#include "update.h"
#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <curl/curl.h>

#ifdef _WIN32
#include <windows.h>
#include <winsvc.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__) && !defined(__ANDROID__)
#include <linux/fs.h>
#include <sys/syscall.h>
#endif
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#endif

#define FP_UPDATE_SERVICE "fastp2p"
#define FP_UPDATE_DOWNLOAD_LIMIT (128ull * 1024ull * 1024ull)
#ifndef _WIN32
#define FP_UPDATE_TEMP_PREFIX "/tmp/.fastp2p-download-"
#define FP_UPDATE_TEMP_FILE "/package"
#endif

/* Android hands the library a writable directory; everywhere else the package is
 * staged beside the executable. */
static char update_stage_dir[1024];
void fp_update_set_dir(const char *dir) {
    snprintf(update_stage_dir, sizeof(update_stage_dir), "%s", dir ? dir : "");
}
void fp_update_discard(const char *path) {
    if (!path || !*path)
        return;
    remove(path);
#ifndef _WIN32
    if (!strncmp(path, FP_UPDATE_TEMP_PREFIX, sizeof(FP_UPDATE_TEMP_PREFIX) - 1)) {
        size_t length = strlen(path);
        if (length < 128 && length >= sizeof(FP_UPDATE_TEMP_FILE) &&
            !strcmp(path + length - (sizeof(FP_UPDATE_TEMP_FILE) - 1), FP_UPDATE_TEMP_FILE)) {
            char directory[128];
            size_t end = length - (sizeof(FP_UPDATE_TEMP_FILE) - 1);
            memcpy(directory, path, end);
            directory[end] = 0;
            rmdir(directory);
        }
    }
#endif
}

static void set_error(char *error, size_t length, const char *text) {
    if (error && length)
        snprintf(error, length, "%s", text);
}
static void update_hex(const unsigned char *digest, unsigned length, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < length; ++i) {
        out[i * 2] = digits[digest[i] >> 4];
        out[i * 2 + 1] = digits[digest[i] & 15];
    }
    out[length * 2] = 0;
}

struct sink {
    FILE *file;
    EVP_MD_CTX *digest;
    uint64_t written;
};
static size_t sink_write(char *data, size_t size, size_t count, void *user) {
    struct sink *sink = (struct sink *)user;
    size_t length = size * count;
    if (!length)
        return 0;
    if (sink->written + length > FP_UPDATE_DOWNLOAD_LIMIT)
        return 0; /* aborts the transfer */
    if (fwrite(data, 1, length, sink->file) != length)
        return 0;
    EVP_DigestUpdate(sink->digest, data, length);
    sink->written += length;
    return length;
}

CURLcode fp_tls_set_ca(CURL *curl, const char *file, const char *pem) {
    if (pem) {
        struct curl_blob certificate = {(void *)pem, strlen(pem), CURL_BLOB_COPY};
        return curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &certificate);
    }
    return file && *file ? curl_easy_setopt(curl, CURLOPT_CAINFO, file) : CURLE_OK;
}

int fp_update_download(const char *url, const char *ca, const char *ca_pem,
                       const struct curl_slist *resolve, const char *dest,
                       const char *expect_sha, uint64_t expect_size,
                       char *error, size_t error_length) {
    if (!url || !*url || !dest || !expect_sha || strlen(expect_sha) != 64) {
        set_error(error, error_length, "invalid update request");
        return -1;
    }
    FILE *file = fopen(dest, "wb");
    if (!file) {
        set_error(error, error_length, "cannot create the staging file");
        return -1;
    }
    EVP_MD_CTX *digest = EVP_MD_CTX_new();
    CURL *curl = curl_easy_init();
    if (!digest || !curl) {
        if (digest)
            EVP_MD_CTX_free(digest);
        if (curl)
            curl_easy_cleanup(curl);
        fclose(file);
        remove(dest);
        set_error(error, error_length, "cannot start the download");
        return -1;
    }
    EVP_DigestInit_ex(digest, EVP_sha256(), NULL);
    struct sink sink = {.file = file, .digest = digest, .written = 0};
    char failure[CURL_ERROR_SIZE];
    failure[0] = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, sink_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sink);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, failure);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 15000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 300000L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_2);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    CURLcode result = fp_tls_set_ca(curl, ca, ca_pem);
    if (result == CURLE_OK)
        result = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    int close_error = fclose(file);

    if (result != CURLE_OK) {
        EVP_MD_CTX_free(digest);
        remove(dest);
        set_error(error, error_length, failure[0] ? failure : curl_easy_strerror(result));
        return -1;
    }
    if (status != 200) {
        EVP_MD_CTX_free(digest);
        remove(dest);
        set_error(error, error_length, "the gateway refused the download");
        return -1;
    }
    if (close_error) {
        EVP_MD_CTX_free(digest);
        remove(dest);
        set_error(error, error_length, "cannot finish writing the staging file");
        return -1;
    }
    unsigned char raw[EVP_MAX_MD_SIZE];
    unsigned raw_length = 0;
    EVP_DigestFinal_ex(digest, raw, &raw_length);
    EVP_MD_CTX_free(digest);
    char got[65];
    update_hex(raw, raw_length, got);
    if (strcmp(got, expect_sha)) {
        remove(dest);
        set_error(error, error_length, "package digest does not match");
        return -1;
    }
    if (expect_size && sink.written != expect_size) {
        remove(dest);
        set_error(error, error_length, "package size does not match");
        return -1;
    }
    return 0;
}

static int is_fastp2p_version(const char *output) {
    if (strncmp(output, "fastp2p ", 8))
        return 0;
    const char *version = output + 8;
    size_t length = strspn(version, "0123456789.");
    return length > 0 && !strncmp(version + length, " ABI ", 5) &&
           version[length + 5] >= '0' && version[length + 5] <= '9';
}

#ifdef _WIN32
static int wide(const char *text, wchar_t *out, size_t count) {
    return MultiByteToWideChar(CP_UTF8, 0, text, -1, out, (int)count) ? 0 : -1;
}
int fp_update_own_path(char *out, size_t length) {
    wchar_t path[4096];
    DWORD used = GetModuleFileNameW(NULL, path, 4096);
    if (!used || used >= 4096)
        return -1;
    if (!WideCharToMultiByte(CP_UTF8, 0, path, -1, out, (int)length, NULL, NULL))
        return -1;
    return 0;
}
int fp_update_stage_path(char *out, size_t length) {
    char own[4096];
    if (fp_update_own_path(own, sizeof(own)))
        return -1;
    char *slash = strrchr(own, '\\');
    if (!slash)
        slash = strrchr(own, '/');
    if (!slash)
        return -1;
    slash[1] = 0;
    snprintf(out, length, "%s.fastp2p-update-%lu.exe", own, (unsigned long)GetCurrentProcessId());
    return 0;
}
static int service_state(SC_HANDLE service, DWORD *state) {
    SERVICE_STATUS status;
    if (!QueryServiceStatus(service, &status))
        return -1;
    *state = status.dwCurrentState;
    return 0;
}
static int probe_executable(const wchar_t *path) {
    SECURITY_ATTRIBUTES inheritable = {.nLength = sizeof(inheritable), .bInheritHandle = TRUE};
    HANDLE input, output;
    if (!CreatePipe(&input, &output, &inheritable, 0))
        return -1;
    wchar_t command[4200];
    STARTUPINFOW startup = {.cb = sizeof(startup), .dwFlags = STARTF_USESTDHANDLES,
                            .hStdOutput = output, .hStdError = output};
    PROCESS_INFORMATION process;
    int ok = 0;
    if (SetHandleInformation(input, HANDLE_FLAG_INHERIT, 0) &&
        swprintf(command, 4200, L"\"%ls\" --version", path) > 0 &&
        CreateProcessW(path, command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL,
                       &startup, &process)) {
        DWORD code = 1, available = 0, read = 0;
        char version[128];
        if (WaitForSingleObject(process.hProcess, 5000) != WAIT_OBJECT_0) {
            TerminateProcess(process.hProcess, 1);
        } else if (GetExitCodeProcess(process.hProcess, &code) && code == 0 &&
                   PeekNamedPipe(input, NULL, 0, NULL, &available, NULL) && available &&
                   ReadFile(input, version, available < sizeof(version) ? available : sizeof(version) - 1,
                            &read, NULL)) {
            version[read] = 0;
            ok = is_fastp2p_version(version);
        }
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    CloseHandle(output);
    CloseHandle(input);
    return ok ? 0 : -1;
}

static int stop_service(SC_HANDLE service) {
    SERVICE_STATUS ignored;
    ControlService(service, SERVICE_CONTROL_STOP, &ignored);
    for (int i = 0; i < 60; ++i) {
        DWORD state;
        if (service_state(service, &state))
            return -1;
        if (state == SERVICE_STOPPED)
            return 0;
        Sleep(500);
    }
    return -1;
}

static int start_service(SC_HANDLE service) {
    if (!StartServiceW(service, 0, NULL))
        return -1;
    for (int i = 0; i < 60; ++i) {
        DWORD state;
        if (service_state(service, &state) || state == SERVICE_STOPPED)
            return -1;
        if (state == SERVICE_RUNNING) {
            Sleep(1000);
            return service_state(service, &state) || state != SERVICE_RUNNING ? -1 : 0;
        }
        Sleep(500);
    }
    return -1;
}

int fp_update_replace_file(const wchar_t *source, const wchar_t *target) {
    /* SERVICE_STOPPED may be reported before the outgoing process has released
     * its mapped executable. A single rename can therefore fail even after a
     * successful stop. Keep the replacement and backup intact while waiting. */
    for (int attempt = 0; attempt < 100; ++attempt) {
        if (MoveFileExW(source, target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            return 0;
        DWORD error = GetLastError();
        if (error != ERROR_SHARING_VIOLATION && error != ERROR_ACCESS_DENIED)
            return -1;
        Sleep(100);
    }
    return -1;
}

int fp_update_swap(const char *staged, const char *target, const char *service) {
    wchar_t wide_staged[4096], wide_target[4096], wide_service[256];
    if (wide(staged, wide_staged, 4096) || wide(target, wide_target, 4096) ||
        wide(service, wide_service, 256))
        return -1;
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE handle = manager ? OpenServiceW(manager, wide_service, SERVICE_STOP | SERVICE_START |
                                              SERVICE_QUERY_STATUS) : NULL;
    int ok = 0;
    wchar_t previous[4200], replacement[4200], retired[4200];
    if (handle && swprintf(previous, 4200, L"%ls.old", wide_target) > 0 &&
        swprintf(replacement, 4200, L"%ls.new", wide_staged) > 0 && !stop_service(handle)) {
        /* The helper is running the staged image. Use a separate copy for the
         * replacement so the running file never has to be moved. */
        int replaced = CopyFileW(wide_target, previous, FALSE) &&
                       CopyFileW(wide_staged, replacement, FALSE) &&
                       !fp_update_replace_file(replacement, wide_target);
        if (replaced && !start_service(handle)) {
            ok = 1;
            /* Retire only AFTER committing the new service. Its runtime can
             * retry removal once this helper and any scanner release files. */
            if(swprintf(retired,4200,L"%ls.old",wide_staged)>0 &&
               !fp_update_replace_file(previous,retired))DeleteFileW(retired);
            else if(!DeleteFileW(previous))
                fputs("fastp2p: previous executable cleanup deferred\n",stderr);
        } else if (!replaced || (!stop_service(handle) &&
                   !fp_update_replace_file(previous, wide_target))) {
            (void)start_service(handle);
        }
        DeleteFileW(replacement);
    }
    if (handle)
        CloseServiceHandle(handle);
    if (manager)
        CloseServiceHandle(manager);
    if (ok)
        DeleteFileW(wide_staged);
    return ok ? 0 : -1;
}
int fp_update_apply(const char *staged, char *error, size_t error_length) {
    char own[4096];
    if (fp_update_own_path(own, sizeof(own))) {
        set_error(error, error_length, "cannot locate the installed executable");
        return -1;
    }
    wchar_t wide_staged[4096], wide_self[4096];
    if (wide(staged, wide_staged, 4096) || wide(own, wide_self, 4096)) {
        set_error(error, error_length, "cannot prepare the update");
        return -1;
    }
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE service = manager ? OpenServiceW(manager, L"" FP_UPDATE_SERVICE, SERVICE_QUERY_STATUS) : NULL;
    SERVICE_STATUS_PROCESS status;
    DWORD used;
    int managed = service && QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                     (BYTE *)&status, sizeof(status), &used) && status.dwProcessId == GetCurrentProcessId();
    if (service)
        CloseServiceHandle(service);
    if (manager)
        CloseServiceHandle(manager);
    if (!managed) {
        set_error(error, error_length, "Windows remote upgrade requires the fastp2p service");
        return -1;
    }
    if (probe_executable(wide_staged)) {
        set_error(error, error_length, "package cannot run as a fastp2p executable");
        return -1;
    }
    /* The running image cannot be overwritten, so a detached copy of the new
     * build performs the swap once this service has stopped. */
    wchar_t command[12500];
    if (swprintf(command, 12500, L"\"%ls\" --apply-update \"%ls\" \"%ls\" \"%ls\"",
                 wide_staged, wide_staged, wide_self, L"" FP_UPDATE_SERVICE) < 0) {
        set_error(error, error_length, "update helper command is too long");
        return -1;
    }
    STARTUPINFOW startup;
    PROCESS_INFORMATION information;
    memset(&startup, 0, sizeof(startup));
    startup.cb = sizeof(startup);
    memset(&information, 0, sizeof(information));
    if (!CreateProcessW(NULL, command, NULL, NULL, FALSE,
                        DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP, NULL, NULL,
                        &startup, &information)) {
        set_error(error, error_length, "cannot start the update helper");
        return -1;
    }
    CloseHandle(information.hThread);
    CloseHandle(information.hProcess);
    return 0;
}
int fp_update_run_pending(char *const argv[]) { (void)argv; return 0; }
void fp_update_cleanup(void) {
    char own[4096];wchar_t directory[4096],pattern[4200];
    if(fp_update_own_path(own,sizeof(own)) || wide(own,directory,4096))return;
    wchar_t *slash=wcsrchr(directory,L'\\');if(!slash)slash=wcsrchr(directory,L'/');
    if(!slash)return;
    slash[1]=0;
    if(swprintf(pattern,4200,L"%ls.fastp2p-update-*.exe*",directory)<0)return;
    WIN32_FIND_DATAW entry;HANDLE search=FindFirstFileW(pattern,&entry);
    if(search==INVALID_HANDLE_VALUE)return;
    do {
        if(entry.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))continue;
        const wchar_t *name=entry.cFileName,*digits=name+16;wchar_t *end;
        if(wcsncmp(name,L".fastp2p-update-",16) || *digits<L'0' || *digits>L'9')continue;
        errno=0;unsigned long pid=wcstoul(digits,&end,10);
        if(errno || !pid || (wcscmp(end,L".exe") && wcscmp(end,L".exe.old") && wcscmp(end,L".exe.new")))continue;
        HANDLE process=OpenProcess(SYNCHRONIZE,FALSE,(DWORD)pid);
        if(process){DWORD state=WaitForSingleObject(process,0);CloseHandle(process);if(state!=WAIT_OBJECT_0)continue;}
        else if(GetLastError()!=ERROR_INVALID_PARAMETER)continue; /* access denied means possibly active */
        wchar_t path[4200];
        if(swprintf(path,4200,L"%ls%ls",directory,name)>0)DeleteFileW(path);
    }while(FindNextFileW(search,&entry));
    FindClose(search);
}
#else
int fp_update_own_path(char *out, size_t length) {
#ifdef __APPLE__
    char buffer[4096];
    uint32_t size = sizeof(buffer);
    if (_NSGetExecutablePath(buffer, &size))
        return -1;
    char resolved[4096];
    if (!realpath(buffer, resolved))
        return -1;
    snprintf(out, length, "%s", resolved);
    return 0;
#else
    ssize_t used = readlink("/proc/self/exe", out, length - 1);
    if (used <= 0 || (size_t)used >= length - 1)
        return -1;
    out[used] = 0;
    return 0;
#endif
}
int fp_update_stage_path(char *out, size_t length) {
#ifdef __ANDROID__
    if (!*update_stage_dir)
        return -1;
    snprintf(out, length, "%s/fastp2p-update.apk", update_stage_dir);
    return 0;
#else
    char directory[128];
    snprintf(directory, sizeof(directory), FP_UPDATE_TEMP_PREFIX "%ld-XXXXXX", (long)getpid());
    if (!mkdtemp(directory))
        return -1;
    int written = snprintf(out, length, "%s" FP_UPDATE_TEMP_FILE, directory);
    if (written >= 0 && (size_t)written < length)
        return 0;
    rmdir(directory);
    errno = ENAMETOOLONG;
    return -1;
#endif
}
int fp_update_swap(const char *staged, const char *target, const char *service) {
    (void)service;
    if (chmod(staged, 0755))
        return -1;
    return rename(staged, target) ? -1 : 0;
}
static void update_error(char *error, size_t length, const char *action, int code) {
    char detail[160];
    snprintf(detail, sizeof(detail), "%s: %s", action, strerror(code));
    set_error(error, length, detail);
}

static struct {
    char target[4096];
    char rollback[4240];
} pending_update;
static int probe_executable(const char *path) {
    int output[2];
    if (pipe(output))
        return -1;
    if (fcntl(output[0], F_SETFL, O_NONBLOCK) < 0) {
        close(output[0]);
        close(output[1]);
        return -1;
    }
    pid_t child = fork();
    if (!child) {
        close(output[0]);
        if (dup2(output[1], STDOUT_FILENO) < 0)
            _exit(127);
        if (output[1] != STDOUT_FILENO)
            close(output[1]);
        char *const arguments[] = {(char *)path, "--version", NULL};
        execv(path, arguments);
        _exit(127);
    }
    close(output[1]);
    int ok = 0;
    if (child > 0) {
        int status;
        for (int i = 0; i < 100; ++i) {
            pid_t result = waitpid(child, &status, WNOHANG);
            if (result == child) {
                char version[128];
                ssize_t length = read(output[0], version, sizeof(version) - 1);
                if (length > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                    version[length] = 0;
                    ok = is_fastp2p_version(version);
                }
                child = -1;
                break;
            }
            if (result < 0 && errno != EINTR) {
                child = -1;
                break;
            }
            const struct timespec delay = {.tv_nsec = 50000000};
            nanosleep(&delay, NULL);
        }
        if (child > 0) {
            kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        }
    }
    close(output[0]);
    return ok ? 0 : -1;
}

static int sync_image(int fd) {
    int result = fchmod(fd, 0755) || fsync(fd);
    int saved = errno;
    if (close(fd) && !result)
        return -1;
    if (result)
        errno = saved;
    return result ? -1 : 0;
}

static int copy_image(const char *source, int output) {
    int input = open(source, O_RDONLY | O_CLOEXEC);
    if (input < 0)
        return -1;
    char buffer[65536];
    int result = 0;
    for (;;) {
        ssize_t count = read(input, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            result = count < 0 ? -1 : 0;
            break;
        }
        ssize_t offset = 0;
        while (offset < count) {
            ssize_t written = write(output, buffer + offset, (size_t)(count - offset));
            if (written < 0 && errno == EINTR)
                continue;
            if (written <= 0) {
                if (!written)
                    errno = EIO;
                result = -1;
                break;
            }
            offset += written;
        }
        if (result)
            break;
    }
    int saved = errno;
    close(input);
    errno = saved;
    return result;
}

static int prepare_executable(const char *own, const char *staged, char *adjacent, size_t length) {
    const char *slash = strrchr(own, '/');
    if (!slash) {
        errno = EINVAL;
        return -1;
    }
    int written = snprintf(adjacent, length, "%.*s/.fastp2p-update-%ld-XXXXXX",
                           (int)(slash - own), own, (long)getpid());
    if (written < 0 || (size_t)written >= length) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int output = mkstemp(adjacent);
    if (output < 0)
        return -1;
    if (!rename(staged, adjacent)) {
        close(output);
        output = open(adjacent, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    } else if (errno != EXDEV || copy_image(staged, output)) {
        int saved = errno;
        close(output);
        unlink(adjacent);
        errno = saved;
        return -1;
    }
    if (output < 0 || sync_image(output)) {
        int saved = errno;
        unlink(adjacent);
        errno = saved;
        return -1;
    }
    return 0;
}

static int backup_executable(const char *source, const char *backup) {
    if (!link(source, backup))
        return 0;
    int fd = open(backup, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (copy_image(source, fd)) {
        int saved = errno;
        close(fd);
        errno = saved;
    } else if (!sync_image(fd)) {
        return 0;
    }
    int saved = errno;
    unlink(backup);
    errno = saved;
    return -1;
}

static int exchange_executables(const char *own, const char *staged) {
#if defined(SYS_renameat2) && defined(RENAME_EXCHANGE)
    return (int)syscall(SYS_renameat2, AT_FDCWD, staged, AT_FDCWD, own, RENAME_EXCHANGE);
#elif defined(__APPLE__) && defined(RENAME_SWAP)
    return renamex_np(staged, own, RENAME_SWAP);
#else
    (void)own;
    (void)staged;
    errno = ENOSYS;
    return -1;
#endif
}

/* Keep the install path populated across interruption and all error paths. */
int fp_update_swap_files(const char *own, const char *staged, const char *previous,
                         char *rollback, size_t rollback_length, char *error,
                         size_t error_length) {
    char backup[4240];
    int written = snprintf(backup, sizeof(backup), "%s.backup", staged);
    if (written < 0 || (size_t)written >= sizeof(backup) || !rollback ||
        rollback_length <= (size_t)written || rollback_length <= strlen(previous)) {
        set_error(error, error_length, "update path is too long");
        return -1;
    }
    rollback[0] = 0;
    const char *retired = staged;
    if (exchange_executables(own, staged)) {
        /* Some filesystems and kernels cannot exchange entries. A hard link
         * preserves the old inode without reserving a second image. A copy is
         * required only if the filesystem also rejects the hard link. */
        if (backup_executable(own, backup)) {
            update_error(error, error_length, "cannot save the previous build", errno);
            return -1;
        }
        if (rename(staged, own)) {
            int saved = errno;
            unlink(backup);
            update_error(error, error_length, "cannot install the new build", saved);
            return -1;
        }
        retired = backup;
    }
    const char *kept = rename(retired, previous) ? retired : previous;
    snprintf(rollback, rollback_length, "%s", kept);
    return 0;
}

int fp_update_apply(const char *staged, char *error, size_t error_length) {
    if (pending_update.target[0]) {
        set_error(error, error_length, "an update is already pending");
        return -1;
    }
    char own[4096], adjacent[4200], previous[4200];
    if (fp_update_own_path(own, sizeof(own))) {
        set_error(error, error_length, "cannot locate the running executable");
        return -1;
    }
    if (prepare_executable(own, staged, adjacent, sizeof(adjacent))) {
        update_error(error, error_length, "cannot prepare the replacement in the install directory", errno);
        return -1;
    }
    fp_update_discard(staged);
    /* /tmp can be mounted noexec. Only execute the verified image after moving
     * it to the filesystem from which the client will actually run. */
    if (probe_executable(adjacent)) {
        unlink(adjacent);
        set_error(error, error_length, "package cannot run as a fastp2p executable");
        return -1;
    }
    snprintf(previous, sizeof(previous), "%s.old", own);
    if (fp_update_swap_files(own, adjacent, previous, pending_update.rollback,
                             sizeof(pending_update.rollback), error, error_length)) {
        unlink(adjacent);
        return -1;
    }
    snprintf(pending_update.target, sizeof(pending_update.target), "%s", own);
    /* Flush the directory entries before the running process gives up the old
     * image. Some POSIX filesystems do not support syncing a directory. */
    char *slash = strrchr(own, '/');
    slash[1] = 0;
    int directory = open(own, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory >= 0) {
        fsync(directory);
        close(directory);
    }
    return 0;
}

int fp_update_run_pending(char *const argv[]) {
    if (!pending_update.target[0])
        return 0;
    char target[sizeof(pending_update.target)], rollback[sizeof(pending_update.rollback)];
    memcpy(target, pending_update.target, sizeof(target));
    memcpy(rollback, pending_update.rollback, sizeof(rollback));
    pending_update.target[0] = 0;
    execv(target, argv);
    fprintf(stderr, "fastp2p update start failed: %s\n", strerror(errno));
    if (rename(rollback, target)) {
        fprintf(stderr, "fastp2p update rollback failed: %s\n", strerror(errno));
        execv(rollback, argv);
        return -1;
    }
    execv(target, argv);
    fprintf(stderr, "fastp2p previous executable could not restart: %s\n", strerror(errno));
    return -1;
}
void fp_update_cleanup(void) {
#ifndef __ANDROID__
    if (pending_update.target[0])
        return;
    char own[4096],previous[4200],directory[4096];
    if(fp_update_own_path(own,sizeof(own)))return;
    snprintf(previous,sizeof(previous),"%s.old",own);
    struct stat metadata;
    if(!lstat(previous,&metadata) && S_ISREG(metadata.st_mode))unlink(previous);
    snprintf(directory,sizeof(directory),"%s",own);
    char *slash=strrchr(directory,'/');if(!slash)return;
    slash[1]=0;
    DIR *scan=opendir(directory);if(!scan)return;
    struct dirent *entry;
    while((entry=readdir(scan))){
        if(strncmp(entry->d_name,".fastp2p-update-",16))continue;
        const char *digits=entry->d_name+16;char *end;
        if(*digits<'0' || *digits>'9')continue;
        errno=0;unsigned long pid=strtoul(digits,&end,10);
        if (errno || !pid || pid > INT_MAX)
            continue;
        if (*end == '-') {
            ++end;
            size_t suffix = strspn(end, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
            if (suffix != 6)
                continue;
            end += suffix;
        }
        if (*end && strcmp(end, ".backup"))
            continue;
        if(!kill((pid_t)pid,0) || errno!=ESRCH)continue;
        char path[4400];
        if(snprintf(path,sizeof(path),"%s%s",directory,entry->d_name)>=(int)sizeof(path))continue;
        if(!lstat(path,&metadata) && S_ISREG(metadata.st_mode))unlink(path);
    }
    closedir(scan);
#endif
}
#endif
