#include "firewall.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>
#else
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define FP_FIREWALL_RULE_PREFIX "FastP2P"

static int append(char *out, size_t length, const char *text) {
    size_t used = strlen(out);
    if (!length || used >= length - 1)
        return -1;
    int written = snprintf(out + used, length - used, "%s%s", used ? "\n" : "", text);
    return written < 0 ? -1 : 0;
}

/* The macOS application firewall is configured per binary, so the commands need this
 * executable's own path. */
static int current_executable(char *out, size_t length) {
    if (!out || !length)
        return -1;
#if defined(_WIN32)
    wchar_t wide[512];
    DWORD used = GetModuleFileNameW(NULL, wide, ARRAYSIZE(wide));
    if (!used || used >= ARRAYSIZE(wide))
        return -1;
    size_t i = 0;
    for (; i + 1 < used && i + 1 < length; ++i)
        out[i] = (char)wide[i];
    out[i] = 0;
    return 0;
#elif defined(__APPLE__)
    uint32_t size = (uint32_t)length;
    return _NSGetExecutablePath(out, &size) == 0 ? 0 : -1;
#else
    ssize_t used = readlink("/proc/self/exe", out, length - 1);
    if (used <= 0)
        return -1;
    out[used] = 0;
    return 0;
#endif
}

int fp_firewall_commands(unsigned port, int udp, const char *tun, char *out, size_t length) {
    if (!out || !length)
        return -1;
    out[0] = 0;
    char line[256];
#if defined(_WIN32)
    /* A fixed name per protocol keeps repeated starts from stacking rules; netsh has no
     * replace, so the rule is deleted before it is added again. The overlay interface is
     * separate: it carries nothing but packets this client wrote into the TUN. */
    snprintf(line, sizeof(line),
             "C:\\Windows\\System32\\netsh.exe advfirewall firewall delete rule name=\"FastP2P TCP %u\"", port);
    if (append(out, length, line))
        return -1;
    snprintf(line, sizeof(line),
             "C:\\Windows\\System32\\netsh.exe advfirewall firewall add rule name=\"FastP2P TCP %u\" dir=in action=allow "
             "protocol=TCP localport=%u profile=any enable=yes", port, port);
    if (append(out, length, line))
        return -1;
    if (udp) {
        snprintf(line, sizeof(line),
                 "C:\\Windows\\System32\\netsh.exe advfirewall firewall delete rule name=\"FastP2P UDP %u\"", port);
        if (append(out, length, line))
            return -1;
        snprintf(line, sizeof(line),
                 "C:\\Windows\\System32\\netsh.exe advfirewall firewall add rule name=\"FastP2P UDP %u\" dir=in action=allow "
                 "protocol=UDP localport=%u profile=any enable=yes", port, port);
        if (append(out, length, line))
            return -1;
    }
    if (tun && *tun) {
        /* The name carries the interface so two overlays never share a rule. */
        snprintf(line, sizeof(line),
                 "C:\\Windows\\System32\\netsh.exe advfirewall firewall delete rule name=\"FastP2P overlay (%s)\"", tun);
        if (append(out, length, line))
            return -1;
        snprintf(line, sizeof(line),
                 "C:\\Windows\\System32\\netsh.exe advfirewall firewall add rule name=\"FastP2P overlay (%s)\" dir=in "
                 "action=allow interface=\"%s\" profile=any enable=yes", tun, tun);
        if (append(out, length, line))
            return -1;
    }
#elif defined(__APPLE__)
    /* macOS filters per application rather than per port; the sanctioned way to allow a
     * binary is the application firewall's unblock list. */
    (void)port;
    (void)udp;
    (void)tun;
    char executable[512];
    if (current_executable(executable, sizeof(executable)))
        return -1;
    snprintf(line, sizeof(line),
             "/usr/libexec/ApplicationFirewall/socketfilterfw --add \"%s\"", executable);
    if (append(out, length, line))
        return -1;
    snprintf(line, sizeof(line),
             "/usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp \"%s\"", executable);
    if (append(out, length, line))
        return -1;
#elif defined(__ANDROID__)
    /* The Android client runs inside a VPN service; the host firewall is not the gate,
     * but a rooted device that runs its own netfilter wants the port opened too. */
    snprintf(line, sizeof(line),
             "su -c 'iptables -C INPUT -p tcp --dport %u -j ACCEPT || "
             "iptables -I INPUT -p tcp --dport %u -j ACCEPT'", port, port);
    if (append(out, length, line))
        return -1;
    if (udp) {
        snprintf(line, sizeof(line),
                 "su -c 'iptables -C INPUT -p udp --dport %u -j ACCEPT || "
                 "iptables -I INPUT -p udp --dport %u -j ACCEPT'", port, port);
        if (append(out, length, line))
            return -1;
    }
    if (tun && *tun) {
        snprintf(line, sizeof(line),
                 "su -c 'iptables -C INPUT -i %s -j ACCEPT || "
                 "iptables -I INPUT -i %s -j ACCEPT'", tun, tun);
        if (append(out, length, line))
            return -1;
    }
#else
    /* netfilter: -C makes the insert idempotent, so a restart does not add a rule per
     * start. Both families are opened because the listener binds both. */
    enum { kFamilies = 2 };
    static const char *const tools[kFamilies] = {"iptables", "ip6tables"};
    for (int family = 0; family < kFamilies; ++family) {
        char candidate[64];
        snprintf(candidate, sizeof(candidate), "/usr/sbin/%s", tools[family]);
        if (access(candidate, X_OK)) {
            snprintf(candidate, sizeof(candidate), "/sbin/%s", tools[family]);
            if (access(candidate, X_OK))
                continue;
        }
        snprintf(line, sizeof(line),
                 "iptables -C INPUT -p tcp --dport %u -j ACCEPT 2>/dev/null || "
                 "iptables -I INPUT -p tcp --dport %u -j ACCEPT", port, port);
        if (family)
            snprintf(line, sizeof(line),
                     "ip6tables -C INPUT -p tcp --dport %u -j ACCEPT 2>/dev/null || "
                     "ip6tables -I INPUT -p tcp --dport %u -j ACCEPT", port, port);
        if (append(out, length, line))
            return -1;
        if (udp) {
            snprintf(line, sizeof(line),
                     "iptables -C INPUT -p udp --dport %u -j ACCEPT 2>/dev/null || "
                     "iptables -I INPUT -p udp --dport %u -j ACCEPT", port, port);
            if (family)
                snprintf(line, sizeof(line),
                         "ip6tables -C INPUT -p udp --dport %u -j ACCEPT 2>/dev/null || "
                         "ip6tables -I INPUT -p udp --dport %u -j ACCEPT", port, port);
            if (append(out, length, line))
                return -1;
        }
    }
    if (tun && *tun) {
        snprintf(line, sizeof(line),
                 "iptables -C INPUT -i %s -j ACCEPT 2>/dev/null || "
                 "iptables -I INPUT -i %s -j ACCEPT", tun, tun);
        if (append(out, length, line))
            return -1;
    }
#endif
    return 0;
}

#if !defined(_WIN32)
/* Run one shell command, returning its exit status (or -1). Shelling out keeps the rules
 * in the host's own tool rather than reimplementing netfilter or netsh calls. */
static int run_shell(const char *command) {
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (!child) {
        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0)
        if (errno != EINTR)
            return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
#else
/* Start the program named at the beginning of the command line directly. A service has
 * no console and no shell, and routing netsh through cmd.exe only adds a quoting layer
 * that fails differently from an interactive run. */
static int run_command_wide(const wchar_t *command) {
    wchar_t buffer[1024];
    _snwprintf(buffer, ARRAYSIZE(buffer), L"%s", command);
    buffer[ARRAYSIZE(buffer) - 1] = 0;
    STARTUPINFOW startup = {0};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION process = {0};
    if (!CreateProcessW(NULL, buffer, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL,
                        &startup, &process))
        return -1;
    WaitForSingleObject(process.hProcess, 15000);
    DWORD code = 1;
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return (int)code;
}
#endif

int fp_firewall_open(unsigned port, int udp, const char *tun, char *detail,
                     size_t detail_length) {
    if (detail && detail_length)
        detail[0] = 0;
    if (!port)
        return FP_FIREWALL_ABSENT;
    char commands[2048];
    if (fp_firewall_commands(port, udp, tun, commands, sizeof(commands)))
        return FP_FIREWALL_ABSENT;
#if defined(_WIN32)
    if (strstr(commands, "netsh") == NULL)
        return FP_FIREWALL_ABSENT;
#elif defined(__APPLE__)
    if (access("/usr/libexec/ApplicationFirewall/socketfilterfw", X_OK))
        return FP_FIREWALL_ABSENT;
#elif defined(__ANDROID__)
    if (access("/system/bin/su", X_OK) && access("/system/xbin/su", X_OK))
        return FP_FIREWALL_ABSENT;
#else
    if (access("/usr/sbin/iptables", X_OK) && access("/sbin/iptables", X_OK))
        return FP_FIREWALL_ABSENT;
#endif
    /* A host without an IPv6 filter table, a missing capability for one family, or an
     * interface that does not exist yet all make single rules fail while the IPv4 port
     * is open. Counting any failure as "closed" hid a working rule behind a refusal, so
     * the result reports what actually happened: all rules in place, some refused, or
     * nothing at all. */
    unsigned ran = 0, done = 0, failed = 0;
    int first_failure = 0;
    char scratch[2048];
    size_t used = 0;
    while (commands[used]) {
        size_t end = used;
        while (commands[end] && commands[end] != '\n')
            ++end;
        size_t span = end - used;
        if (span >= sizeof(scratch))
            break;
        memcpy(scratch, commands + used, span);
        scratch[span] = 0;
        used = commands[end] ? end + 1 : end;
#if defined(_WIN32)
        wchar_t wide[1024];
        size_t i = 0;
        for (; i + 1 < span && i + 1 < ARRAYSIZE(wide); ++i)
            wide[i] = (wchar_t)(unsigned char)scratch[i];
        wide[i] = 0;
        int status = run_command_wide(wide);
#else
        int status = run_shell(scratch);
#endif
        ++ran;
        if (status == 0) {
            ++done;
        } else {
            if (!first_failure)
                first_failure = status;
            ++failed;
        }
    }
    if (!ran)
        return FP_FIREWALL_ABSENT;
    if (detail && detail_length) {
        const char *how =
#if defined(_WIN32)
            "netsh";
#elif defined(__APPLE__)
            "application firewall";
#elif defined(__ANDROID__)
            "su iptables";
#else
            "iptables";
#endif
        if (!failed)
            snprintf(detail, detail_length, "allowed (%s)", how);
        else if (done)
            snprintf(detail, detail_length, "allowed (%s, %u rule(s) refused, first rc %d)", how,
                     failed, first_failure);
        else
            snprintf(detail, detail_length, "refused (%s, rc %d)", how, first_failure);
    }
    if (!done)
        return FP_FIREWALL_DENIED;
    return FP_FIREWALL_OK;
}
