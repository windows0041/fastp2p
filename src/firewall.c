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

#if defined(__ANDROID__)
/* Magisk and friends put su where they like: /system/bin/su, /system/xbin/su, /sbin/su,
 * /product/bin/su and /debug_assert/system/bin/su are all in the wild, and the app's PATH
 * does not necessarily contain the directory. Probing the known places and then naming the
 * binary in full is what makes the rule reach the device at all. */
static const char *android_su(void) {
    static const char *const candidates[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/product/bin/su",
        "/debug_assert/system/bin/su", "/su/bin/su"};
    for (size_t i = 0; i < sizeof(candidates) / sizeof(*candidates); ++i)
        if (!access(candidates[i], X_OK))
            return candidates[i];
    return NULL;
}
#endif

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
    /* One idempotent pass: remove only our own leftovers, then create what is missing.
     * A restart that changes nothing must not touch the policy at all - a delete-and-add
     * cycle on every start churns the rule store and wakes products that watch the
     * firewall, which then re-ask their own whitelist questions because they saw a change
     * they cannot attribute. */
    {
        char udp_want[48] = "";
        if (udp)
            snprintf(udp_want, sizeof(udp_want), ",'FastP2P UDP %u'", port);
        const char *protocols = udp ? "'TCP','UDP'" : "'TCP'";
        char script[1024];
        snprintf(script, sizeof(script),
                 "powershell.exe -NoProfile -NonInteractive -Command \""
                 "$want=@('FastP2P TCP %u'%s); "
                 "Get-NetFirewallRule -DisplayName 'FastP2P *' -ErrorAction SilentlyContinue | "
                 "Where-Object { $want -notcontains $_.DisplayName -and "
                 "$_.DisplayName -notlike 'FastP2P overlay*' } | "
                 "Remove-NetFirewallRule -ErrorAction SilentlyContinue; "
                 "foreach ($p in @(%s)) { $n='FastP2P ' + $p + ' %u'; "
                 "if (-not (Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)) { "
                 "New-NetFirewallRule -DisplayName $n -Direction Inbound -Protocol $p "
                 "-LocalPort %u -Action Allow -Profile Any | Out-Null } }\" || exit /b 1",
                 port, udp_want, protocols, port, port);
        if (append(out, length, script))
            return -1;
    }
    if (tun && *tun) {
        char script[512];
        snprintf(script, sizeof(script),
                 "powershell.exe -NoProfile -NonInteractive -Command \""
                 "if (-not (Get-NetFirewallRule -DisplayName 'FastP2P overlay (%s)' "
                 "-ErrorAction SilentlyContinue)) { New-NetFirewallRule "
                 "-DisplayName 'FastP2P overlay (%s)' -Direction Inbound "
                 "-InterfaceAlias '%s' -Action Allow -Profile Any | Out-Null }\" || exit /b 1",
                 tun, tun, tun);
        if (append(out, length, script))
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
    const char *su = android_su();
    if (!su)
        return -1;
    snprintf(line, sizeof(line),
             "%s -c 'iptables -C INPUT -p tcp --dport %u -j ACCEPT || "
             "iptables -I INPUT -p tcp --dport %u -j ACCEPT'", su, port, port);
    if (append(out, length, line))
        return -1;
    if (udp) {
        snprintf(line, sizeof(line),
                 "%s -c 'iptables -C INPUT -p udp --dport %u -j ACCEPT || "
                 "iptables -I INPUT -p udp --dport %u -j ACCEPT'", su, port, port);
        if (append(out, length, line))
            return -1;
    }
    if (tun && *tun) {
        snprintf(line, sizeof(line),
                 "%s -c 'iptables -C INPUT -i %s -j ACCEPT || "
                 "iptables -I INPUT -i %s -j ACCEPT'", su, tun, tun);
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
/* netsh parses its own command line, and the quoting that survives an interactive
 * prompt does not survive CreateProcessW: every rule came back with status 1 while the
 * same text ran fine from a script. A temporary batch file is the representation both
 * sides agree on, and a service has no shell to build one itself. */
static int run_command_blob(const char *commands) {
    wchar_t directory[MAX_PATH];
    DWORD used = GetTempPathW(ARRAYSIZE(directory), directory);
    if (!used || used >= ARRAYSIZE(directory))
        return -1;
    wchar_t path[MAX_PATH];
    _snwprintf(path, ARRAYSIZE(path), L"%sfastp2p-firewall-%lu.cmd", directory,
               (unsigned long)GetCurrentProcessId());
    path[ARRAYSIZE(path) - 1] = 0;
    FILE *file = _wfopen(path, L"wb");
    if (!file)
        return -1;
    fputs("@echo off\r\n", file);
    fputs(commands, file);
    fputs("\r\n", file);
    fclose(file);
    wchar_t line[MAX_PATH + 16];
    _snwprintf(line, ARRAYSIZE(line), L"cmd.exe /c \"%s\"", path);
    line[ARRAYSIZE(line) - 1] = 0;
    STARTUPINFOW startup = {0};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION process = {0};
    int status = -1;
    if (CreateProcessW(NULL, line, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL,
                       &startup, &process)) {
        WaitForSingleObject(process.hProcess, 20000);
        DWORD code = 1;
        GetExitCodeProcess(process.hProcess, &code);
        status = (int)code;
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    _wremove(path);
    return status;
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
    /* The Windows rules go through PowerShell now, so look for that; checking for netsh
     * made a working opener report "no rule tool on this host" and never run. */
    if (strstr(commands, "powershell.exe") == NULL)
        return FP_FIREWALL_ABSENT;
#elif defined(__APPLE__)
    if (access("/usr/libexec/ApplicationFirewall/socketfilterfw", X_OK))
        return FP_FIREWALL_ABSENT;
#elif defined(__ANDROID__)
    if (!android_su())
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
        int status = run_command_blob(scratch);
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
