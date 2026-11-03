#include "update.h"
#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <curl/curl.h>

#ifdef _WIN32
#include <windows.h>
#include <winsvc.h>
#else
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#endif

#define FP_UPDATE_SERVICE "fastp2p"
#define FP_UPDATE_DOWNLOAD_LIMIT (128ull * 1024ull * 1024ull)

/* Android hands the library a writable directory; everywhere else the package is
 * staged beside the executable. */
static char update_stage_dir[1024];
void fp_update_set_dir(const char *dir) {
    snprintf(update_stage_dir, sizeof(update_stage_dir), "%s", dir ? dir : "");
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

int fp_update_download(const char *url, const char *ca, const char *dest,
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
    if (ca && *ca)
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca);

    CURLcode result = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    fclose(file);

    if (result != CURLE_OK) {
        EVP_MD_CTX_free(digest);
        remove(dest);
        set_error(error, error_length, failure[0] ? failure : "download failed");
        return -1;
    }
    if (status != 200) {
        EVP_MD_CTX_free(digest);
        remove(dest);
        set_error(error, error_length, "the gateway refused the download");
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
int fp_update_swap(const char *staged, const char *target, const char *service) {
    wchar_t wide_staged[4096], wide_target[4096], wide_service[256];
    if (wide(staged, wide_staged, 4096) || wide(target, wide_target, 4096) ||
        wide(service, wide_service, 256))
        return -1;
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE handle = manager ? OpenServiceW(manager, wide_service, SERVICE_STOP | SERVICE_START |
                                              SERVICE_QUERY_STATUS) : NULL;
    /* Give the outgoing service time to release the image before replacing it. */
    if (handle) {
        for (int i = 0; i < 60; ++i) {
            DWORD state = 0;
            if (service_state(handle, &state) || state == SERVICE_STOPPED)
                break;
            SERVICE_STATUS ignored;
            ControlService(handle, SERVICE_CONTROL_STOP, &ignored);
            Sleep(500);
        }
    }
    int ok = CopyFileW(wide_staged, wide_target, FALSE) != 0;
    if (ok && handle)
        StartServiceW(handle, 0, NULL);
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
    /* The running image cannot be overwritten, so a detached copy of the new
     * build performs the swap once this service has stopped. */
    wchar_t command[8192];
    swprintf(command, 8192, L"\"%ls\" --apply-update \"%ls\" \"%ls\" \"%ls\"",
             wide_staged, wide_staged, wide_self, L"" FP_UPDATE_SERVICE);
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
    char own[4096];
    if (fp_update_own_path(own, sizeof(own)))
        return -1;
    char *slash = strrchr(own, '/');
    if (!slash)
        return -1;
    slash[1] = 0;
    snprintf(out, length, "%s.fastp2p-update-%ld", own, (long)getpid());
    return 0;
#endif
}
int fp_update_swap(const char *staged, const char *target, const char *service) {
    (void)service;
    if (chmod(staged, 0755))
        return -1;
    return rename(staged, target) ? -1 : 0;
}
int fp_update_apply(const char *staged, char *error, size_t error_length) {
    char own[4096];
    if (fp_update_own_path(own, sizeof(own))) {
        set_error(error, error_length, "cannot locate the installed executable");
        return -1;
    }
    if (chmod(staged, 0755)) {
        set_error(error, error_length, "cannot make the new build executable");
        return -1;
    }
    /* Keep the previous build until the replacement is in place. */
    char previous[4200];
    snprintf(previous, sizeof(previous), "%s.old", own);
    remove(previous);
    if (rename(own, previous)) {
        set_error(error, error_length, "cannot move the current build aside");
        return -1;
    }
    if (rename(staged, own)) {
        rename(previous, own);
        set_error(error, error_length, "cannot install the new build");
        return -1;
    }
    /* Re-exec so the process keeps running the same command line under whatever
     * supervisor started it, without a visible restart. */
    char command[4096];
    FILE *cmdline = fopen("/proc/self/cmdline", "rb");
    size_t used = 0;
    if (cmdline) {
        used = fread(command, 1, sizeof(command) - 1, cmdline);
        fclose(cmdline);
    }
    if (used < 2) {
        /* No command line to reuse: ask the supervisor to restart us. */
        return 0;
    }
    command[used] = 0;
    char *argv[64];
    int argc = 0;
    for (size_t i = 0; i < used && argc < 63;) {
        argv[argc++] = command + i;
        i += strlen(command + i) + 1;
    }
    argv[argc] = NULL;
    execv(own, argv);
    /* execv only returns on failure; the supervisor will restart the service. */
    set_error(error, error_length, "the new build could not be started");
    return 0;
}
#endif
