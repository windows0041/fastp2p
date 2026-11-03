#include "install.h"
#include "identity_file.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
static HANDLE stop_event;
/* Set by the service control handler; the run loop reads it through
 * fastp2p_runtime_stopping. The named event alone is not enough because a stop
 * can arrive while the client is still starting up. */
static volatile int stop_requested;
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
    stop_requested = 0;
    if (background) {
        DWORD owners[2];
        if (GetConsoleProcessList(owners, 2) == 1) ShowWindow(GetConsoleWindow(), SW_HIDE);
        char log[4096];
        if (snprintf(log, sizeof(log), "%s.log", profile) >= (int)sizeof(log)) return -1;
        WCHAR path[4096]; if (wide(log, path)) return -1;
        if (!_wfreopen(path, L"ab", stdout) || !_wfreopen(path, L"ab", stderr)) return -1;
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
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
int fastp2p_runtime_begin(const char *profile, int background) { (void)profile; (void)background; return 0; }
int fastp2p_runtime_stopping(void) { return 0; }
void fastp2p_runtime_request_stop(void) {}
void fastp2p_runtime_end(void) {}
static int execute(char *const arguments[]) {
    pid_t child = fork();
    if (child < 0) return -1;
    if (!child) { execv(arguments[0], arguments); _exit(127); }
    int status;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}
int fastp2p_stop_installed(const char *profile) {
    (void)profile;
#ifdef __APPLE__
    char service[80]; snprintf(service, sizeof(service), "gui/%lu/top.fastp2p", (unsigned long)getuid());
    char *const stop[] = {"/bin/launchctl", "bootout", service, NULL}; return execute(stop);
#else
    char *const stop[] = {"/usr/bin/systemctl", "stop", "fastp2p-client.service", NULL}; return execute(stop);
#endif
}
static int copy_binary(const char *target) {
    char source[4096];
#ifdef __APPLE__
    uint32_t capacity = sizeof(source);
    if (_NSGetExecutablePath(source, &capacity)) return -1;
#else
    ssize_t length = readlink("/proc/self/exe", source, sizeof(source) - 1);
    if (length <= 0) return -1;
    source[length] = 0;
#endif
    struct stat a, b;
    if (stat(source, &a)) return -1;
    if (!stat(target, &b) && a.st_dev == b.st_dev && a.st_ino == b.st_ino) return 0;
    if (fastp2p_private_parents(target)) return -1;
    char temporary[4096];
    if (snprintf(temporary, sizeof(temporary), "%s.new.%lu", target, (unsigned long)getpid()) >= (int)sizeof(temporary)) return -1;
    int input = open(source, O_RDONLY | O_CLOEXEC), output = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0755);
    if (input < 0 || output < 0) { if (input >= 0) close(input); if (output >= 0) close(output); return -1; }
    char buffer[65536]; ssize_t length_read; int ok = 1;
    while ((length_read = read(input, buffer, sizeof(buffer))) > 0) {
        size_t used = 0;
        while (used < (size_t)length_read) {
            ssize_t count = write(output, buffer + used, (size_t)length_read - used);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { ok = 0; break; }
            used += (size_t)count;
        }
        if (!ok) break;
    }
    if (length_read < 0 || fsync(output) || fchmod(output, 0755)) ok = 0;
    close(input); if (close(output)) ok = 0;
    if (ok && rename(temporary, target)) ok = 0;
    if (!ok) unlink(temporary);
    return ok ? 0 : -1;
}
int fastp2p_enable_autostart(const char *profile, const char *ca) {
#ifdef __APPLE__
    (void)profile; (void)ca;
    /* The same executable/profile runs under launchd; installation stays per-user. */
    const char *home = getenv("HOME");
    if (!home || strchr(home, '<') || strchr(home, '&') || strchr(profile, '<') || strchr(profile, '&')) return -1;
    char target[4096], plist[4096], domain[64], text[12000];
    if (snprintf(target, sizeof(target), "%s/Library/Application Support/fastp2p/fastp2p", home) >= (int)sizeof(target) ||
        snprintf(plist, sizeof(plist), "%s/Library/LaunchAgents/top.fastp2p.plist", home) >= (int)sizeof(plist) || copy_binary(target)) return -1;
    int size = snprintf(text, sizeof(text), "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>Label</key><string>top.fastp2p</string><key>ProgramArguments</key><array><string>%s</string><string>run</string><string>--config</string><string>%s</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>", target, profile);
    if (size < 0 || size >= (int)sizeof(text) || fastp2p_private_parents(plist)) return -1;
    FILE *file = fopen(plist, "wb");
    if (!file) return -1;
    int ok = fwrite(text, 1, (size_t)size, file) == (size_t)size;
    if (fclose(file)) ok = 0;
    if (!ok) return -1;
    snprintf(domain, sizeof(domain), "gui/%lu", (unsigned long)getuid());
    char *const unload[] = {"/bin/launchctl", "bootout", domain, plist, NULL};
    (void)execute(unload);
    char *const load[] = {"/bin/launchctl", "bootstrap", domain, plist, NULL};
    return execute(load);
#else
    if (geteuid() || strcmp(profile, "/etc/fastp2p/client.json")) return -1;
    struct passwd *user = getpwnam("fastp2p");
    if (!user) {
        char *const add[] = {"/usr/sbin/useradd", "--system", "--user-group", "--home-dir", "/var/lib/fastp2p",
                             "--shell", "/usr/sbin/nologin", "fastp2p", NULL};
        if (execute(add)) return -1;
        user = getpwnam("fastp2p");
    }
    if (!user || strcmp(user->pw_dir, "/var/lib/fastp2p") || copy_binary("/usr/local/bin/fastp2p")) return -1;
    if (chown("/etc/fastp2p", 0, user->pw_gid) || chmod("/etc/fastp2p", 0750) ||
        chown(profile, 0, user->pw_gid) || chmod(profile, 0640) ||
        (ca && (chown(ca, 0, user->pw_gid) || chmod(ca, 0640)))) return -1;
    const char *unit = "[Unit]\nDescription=fastp2p client\nAfter=network-online.target\nWants=network-online.target\n[Service]\nUser=fastp2p\nGroup=fastp2p\nExecStart=/usr/local/bin/fastp2p run --config /etc/fastp2p/client.json\nRestart=on-failure\nRestartSec=3\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nStateDirectory=fastp2p\nStateDirectoryMode=0700\n[Install]\nWantedBy=multi-user.target\n";
    FILE *file = fopen("/etc/systemd/system/fastp2p-client.service", "wb");
    if (!file) return -1;
    int ok = fwrite(unit, 1, strlen(unit), file) == strlen(unit);
    if (fclose(file)) ok = 0;
    if (!ok) return -1;
    char *const reload[] = {"/usr/bin/systemctl", "daemon-reload", NULL};
    char *const enable[] = {"/usr/bin/systemctl", "enable", "fastp2p-client.service", NULL};
    char *const restart[] = {"/usr/bin/systemctl", "restart", "fastp2p-client.service", NULL};
    return execute(reload) || execute(enable) || execute(restart) ? -1 : 0;
#endif
}
#endif
