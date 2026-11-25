#include "install.h"
#include "identity_file.h"
#include "log_rotation.h"
#include "platform.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <windows.h>
static HANDLE stop_event;
/* Set by the service control handler; the run loop reads it through
 * fastp2p_runtime_stopping. The named event alone is not enough because a stop
 * can arrive while the client is still starting up. */
static volatile int stop_requested;
/* The runtime log is the only diagnostic an installed node keeps, and these
 * devices can have very little flash. Bound it to one file: when it reaches
 * three quarters of a megabyte, keep only the newest half. The copy uses one
 * fixed 16 KiB buffer, so rotation does not scale with device memory. */
#define FP_LOG_ROTATE_AT (768u * 1024u)
#define FP_LOG_KEEP (512u * 1024u)
static WCHAR runtime_log_path[4096];

static int rotate_log(void) {
    if (!runtime_log_path[0])
        return 0;
    fflush(stdout);
    fflush(stderr);
    /* The streams hold the old log open, so release them before the file is
     * replaced, then attach them to the trimmed file. */
    _wfreopen(L"NUL", L"w", stdout);
    _wfreopen(L"NUL", L"w", stderr);
    int fresh = fp_log_trim_wide(runtime_log_path, FP_LOG_ROTATE_AT, FP_LOG_KEEP);
    if (fresh < 0)
        runtime_log_path[0] = 0; /* do not retry a log that cannot be rewritten */
    if (fresh > 0)
        _close(fresh);
    if (!runtime_log_path[0]) {
        _wfreopen(L"NUL", L"w", stdout);
        _wfreopen(L"NUL", L"w", stderr);
        return -1;
    }
    if (!_wfreopen(runtime_log_path, L"ab", stdout) ||
        !_wfreopen(runtime_log_path, L"ab", stderr)) {
        runtime_log_path[0] = 0;
        return -1;
    }
    return fresh < 0 ? -1 : fresh;
}

int fastp2p_runtime_prepare(const char *profile) { (void)profile; return 0; }
static int wide(const char *text, WCHAR out[4096]) {
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, out, 4096) ? 0 : -1;
}
static void event_name(const char *profile, WCHAR out[80]) {
    uint64_t value = UINT64_C(14695981039346656037);
    for (const unsigned char *p = (const unsigned char *)profile; *p; ++p) {
        unsigned c = *p == '/' ? '\\' : *p;
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        value = (value ^ c) * UINT64_C(1099511628211);
    }
    swprintf(out, 80, L"Local\\fastp2p-stop-%016llx", (unsigned long long)value);
}
int fastp2p_runtime_begin(const char *profile, int background) {
    if (!profile) return 0;
    WCHAR name[80]; event_name(profile, name);
    SetLastError(ERROR_SUCCESS);
    stop_event = CreateEventW(NULL, TRUE, FALSE, name);
    if (!stop_event) return -1;
    if (GetLastError() == ERROR_ALREADY_EXISTS) { CloseHandle(stop_event); stop_event = NULL; return -1; }
    /* A service STOP may arrive before this event exists. Keep the in-process
     * request; configuration reloads must not clear a real SCM shutdown either. */
    if (background) {
        WCHAR path[4096];
        char machine[4096];
        if (!fastp2p_service_profile(machine) && !strcmp(profile, machine)) {
            if (fastp2p_windows_log(path)) return -1;
        } else {
            char log[4096];
            if (snprintf(log, sizeof(log), "%s.log", profile) >= (int)sizeof(log) || wide(log, path))
                return -1;
        }
        if (!_wfreopen(path, L"ab", stdout) || !_wfreopen(path, L"ab", stderr)) return -1;
        if (wcslen(path) < 4096) {
            wcscpy(runtime_log_path, path);
            /* A log left behind by a previous run may already be over the cap. */
            (void)rotate_log();
        }
    }
    return 0;
}
int fastp2p_runtime_stopping(void) {
    if (stop_requested) return 1;
    return stop_event && WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0;
}
void fastp2p_runtime_request_stop(void) {
    stop_requested = 1;
    if (stop_event) SetEvent(stop_event);
}
void fastp2p_runtime_end(void) { if (stop_event) { CloseHandle(stop_event); stop_event = NULL; } }
int fastp2p_stop_installed(const char *profile) {
    WCHAR name[80]; event_name(profile, name);
    HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
    if (!event) return GetLastError() == ERROR_FILE_NOT_FOUND ? 0 : -1;
    int ok = SetEvent(event) != 0; CloseHandle(event); return ok ? 0 : -1;
}
int fastp2p_remove_autostart(const char *profile) {
    if (fastp2p_stop_installed(profile)) return -1;
    WCHAR name[80]; event_name(profile, name);
    /* Closing our handle lets disappearance mean the old runtime released its
     * event; retaining it here would keep the named event alive ourselves. */
    for (int attempt = 0; ; ++attempt) {
        HANDLE old = OpenEventW(SYNCHRONIZE, FALSE, name);
        if (!old) {
            if (GetLastError() != ERROR_FILE_NOT_FOUND) return -1;
            break;
        }
        CloseHandle(old);
        if (attempt == 300) return -1;
        Sleep(100);
    }
    HKEY key;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                                0, KEY_SET_VALUE, &key);
    if (result == ERROR_FILE_NOT_FOUND) return 0;
    if (result != ERROR_SUCCESS) return -1;
    result = RegDeleteValueW(key, L"fastp2p"); RegCloseKey(key);
    return result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND ? 0 : -1;
}
int fastp2p_enable_autostart(const char *profile, const char *ca) {
    (void)ca;
    WCHAR signal[80]; event_name(profile, signal);
    HANDLE previous = OpenEventW(EVENT_MODIFY_STATE, FALSE, signal);
    if (previous) { SetEvent(previous); CloseHandle(previous); Sleep(500); }
    const char *home = getenv("LOCALAPPDATA");
    if (!home) return -1;
    char target[4096];
    if (snprintf(target, sizeof(target), "%s/fastp2p/fastp2p.exe", home) >= (int)sizeof(target) ||
        fastp2p_private_parents(target)) return -1;
    WCHAR source[4096], destination[4096], config[4096];
    DWORD length = GetModuleFileNameW(NULL, source, 4096);
    if (!length || length >= 4096 || wide(target, destination) || wide(profile, config)) return -1;
    for (WCHAR *p = destination; *p; ++p) if (*p == L'/') *p = L'\\';
    if (_wcsicmp(source, destination)) {
        int copied = 0;
        for (int attempt = 0; attempt < 30; ++attempt) {
            if (CopyFileW(source, destination, FALSE)) { copied = 1; break; }
            Sleep(100);
        }
        if (!copied) return -1;
    }
    WCHAR command[8500];
    if (swprintf(command, 8500, L"\"%ls\" run --config \"%ls\" --background", destination, config) < 0) return -1;
    HKEY key;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
                        NULL, 0, KEY_SET_VALUE, NULL, &key, NULL) != ERROR_SUCCESS) return -1;
    LONG result = RegSetValueExW(key, L"fastp2p", 0, REG_SZ, (const BYTE *)command,
                                 (DWORD)((wcslen(command) + 1) * sizeof(WCHAR)));
    RegCloseKey(key);
    if (result != ERROR_SUCCESS) return -1;
    STARTUPINFOW startup = {.cb = sizeof(startup)};
    PROCESS_INFORMATION process = {0};
    if (!CreateProcessW(destination, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process)) return -1;
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    return 0;
}
#else
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
static int root_owned_profile(const char *profile) {
    struct stat metadata;
    if (lstat(profile, &metadata) || !S_ISREG(metadata.st_mode) || metadata.st_uid ||
        metadata.st_nlink != 1 || (metadata.st_mode & 0077))
        return 0;
    char path[4096];
#ifdef __APPLE__
    /* /etc is Apple's system symlink to /private/etc. */
    profile = "/private" FASTP2P_SYSTEM_PROFILE;
#endif
    if (snprintf(path, sizeof(path), "%s", profile) >= (int)sizeof(path))
        return 0;
    char *slash;
    while ((slash = strrchr(path, '/')) && slash != path) {
        *slash = 0;
        if (lstat(path, &metadata) || !S_ISDIR(metadata.st_mode) || metadata.st_uid ||
            (metadata.st_mode & 0022))
            return 0;
    }
    return 1;
}
int fastp2p_runtime_prepare(const char *profile) {
    return profile && !strcmp(profile, FASTP2P_SYSTEM_PROFILE) &&
           (geteuid() || !root_owned_profile(profile)) ? -1 : 0;
}

static int open_log_directory(void) {
    int fd = open(FASTP2P_LOG_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat metadata;
    if (fd >= 0 && (fstat(fd, &metadata) || metadata.st_uid || (metadata.st_mode & 0077))) {
        close(fd);
        return -1;
    }
    return fd;
}

/* One file, newest half kept, fixed-size buffer: see src/log_rotation.c. */
#define FP_LOG_ROTATE_AT (768u * 1024u)
#define FP_LOG_KEEP (512u * 1024u)
static char runtime_log_path[4096];

static int rotate_log(void) {
    if (!runtime_log_path[0])
        return 0;
    fflush(stdout);
    fflush(stderr);
    int fresh = fp_log_trim(runtime_log_path, FP_LOG_ROTATE_AT, FP_LOG_KEEP);
    if (fresh <= 0)
        return fresh;
    /* stdout and stderr follow the renamed inode, so one file stays on disk. */
    if (dup2(fresh, STDOUT_FILENO) < 0 || dup2(fresh, STDERR_FILENO) < 0) {
        close(fresh);
        return -1;
    }
    if (fresh != STDOUT_FILENO && fresh != STDERR_FILENO)
        close(fresh);
    return 1;
}

int fastp2p_runtime_begin(const char *profile, int background) {
    if (!background || !profile || strcmp(profile, FASTP2P_SYSTEM_PROFILE))
        return 0;
    if (mkdir(FASTP2P_LOG_DIR, 0700) && errno != EEXIST)
        return -1;
    int directory = open_log_directory();
    if (directory < 0)
        return -1;
    int log = openat(directory, "fastp2p.log",
                     O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    close(directory);
    if (log < 0)
        return -1;
    struct stat metadata;
    int failed = fstat(log, &metadata) || !S_ISREG(metadata.st_mode) ||
                 metadata.st_uid || metadata.st_nlink != 1 || (metadata.st_mode & 0077);
    if (!failed) {
        fflush(stdout);
        fflush(stderr);
        failed = dup2(log, STDOUT_FILENO) < 0 || dup2(log, STDERR_FILENO) < 0;
    }
    if (log != STDOUT_FILENO && log != STDERR_FILENO)
        close(log);
    if (failed)
        return -1;
    snprintf(runtime_log_path, sizeof(runtime_log_path), "%s", FASTP2P_LOG_FILE);
    /* A log left behind by a previous run may already be over the cap. */
    (void)rotate_log();
    return 0;
}
int fastp2p_runtime_stopping(void) { return 0; }
void fastp2p_runtime_request_stop(void) {}
void fastp2p_runtime_end(void) {}
int fastp2p_stop_installed(const char *profile) {
    (void)profile;
    /* The manager is driven directly. Stopping must not depend on a helper file
     * beside the binary: an upgraded node may not have one any more, and a node
     * installed by this build never gets one. */
    return fastp2p_service_stop();
}
int fastp2p_remove_autostart(const char *profile) {
    return fastp2p_stop_installed(profile);
}

static int unlink_managed(const char *path) {
    return unlink(path) && errno != ENOENT ? -1 : 0;
}

static int protected_directory(const char *path) {
    struct stat st;
    if (lstat(path, &st))
        return errno == ENOENT ? 0 : -1;
    return S_ISDIR(st.st_mode) && !st.st_uid && !(st.st_mode & 0022) ? 1 : -1;
}

static int remove_profile(void) {
    const char *directory_path = "/etc/fastp2p";
    int exists = protected_directory(directory_path);
    if (exists <= 0) return exists;
    DIR *directory = opendir(directory_path);
    if (!directory) return -1;
    int failed = 0;
    struct dirent *entry;
    for (;;) {
        errno = 0;
        entry = readdir(directory);
        if (!entry) {
            failed |= errno != 0;
            break;
        }
        const char *name = entry->d_name;
        const char prefix[] = "config.conf.ca.";
        size_t length = sizeof(prefix) - 1;
        int certificate = strlen(name) == length + 68 && !strncmp(name, prefix, length) &&
            strspn(name + length, "0123456789abcdef") == 64 && !strcmp(name + length + 64, ".pem");
        if (certificate || !strcmp(name, "config.conf") || !strcmp(name, "config.conf.previous") ||
            !strcmp(name, "config.conf.identity"))
            failed |= unlinkat(dirfd(directory), name, 0) && errno != ENOENT;
    }
    closedir(directory);
    (void)rmdir(directory_path);
    return failed ? -1 : 0;
}

static int delete_installation(int keep_config) {
    if (protected_directory(FASTP2P_SYSTEM_DIR) < 0)
        return -1;
    if (!keep_config && remove_profile())
        return -1;
    int log = open_log_directory();
    if (log >= 0) {
        (void)unlinkat(log, "fastp2p.log", 0);
        (void)unlinkat(log, "fastp2p.log.rotate", 0);
        close(log);
        (void)rmdir(FASTP2P_LOG_DIR);
    }
    if (unlink_managed(FASTP2P_SYSTEM_BINARY ".old") ||
        unlink_managed(FASTP2P_SYSTEM_BINARY))
        return -1;
    /* Releases before this one kept a management script here. An upgraded node still
     * has it; it must not survive the uninstall that replaced its job. */
    if (unlink_managed(FASTP2P_SYSTEM_DIR "/fastp2p-service"))
        return -1;
#ifdef __linux__
    char target[4096];
    ssize_t used = readlink("/usr/local/bin/fastp2p", target, sizeof(target) - 1);
    if (used >= 0) {
        target[used] = 0;
        if (!strcmp(target, FASTP2P_SYSTEM_BINARY) &&
            unlink_managed("/usr/local/bin/fastp2p"))
            return -1;
    }
#endif
    (void)rmdir(FASTP2P_SYSTEM_DIR);
    puts(keep_config ? "fastp2p removed; configuration retained." :
                       "fastp2p service and client configuration removed.");
    return 0;
}

int fastp2p_posix_uninstall(int keep_config) {
    if (geteuid()) return -1;
    /* One lock for every platform: two uninstalls at once would race on the unit and
     * on the profile. The manager teardown and the file removal are separate steps,
     * so a half-finished uninstall still leaves a truthful error behind. */
    const char *lock = "/var/run/fastp2p-install.lock";
    if (mkdir(lock, 0700)) return -1;
    int result = fastp2p_service_remove() || delete_installation(keep_config);
    return rmdir(lock) ? -1 : result;
}

int fastp2p_enable_autostart(const char *profile, const char *ca) {
    (void)profile;
    (void)ca;
    return -1;
}
#endif

void fastp2p_runtime_tick(void) {
    /* A check is a single stat, and rotating at 768 KiB leaves room for any
     * burst that can arrive between two checks, so the file never reaches the
     * 1 MiB cap. */
    static uint64_t next;
    uint64_t now = op_monotonic_ns();
    if (next && now < next)
        return;
    next = now + UINT64_C(500000000);
    (void)rotate_log();
}
