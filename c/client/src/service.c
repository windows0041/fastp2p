/* Windows service support.
 *
 * A double-clicked installer cannot create a service without elevation, and a
 * process started by the service manager is killed unless it reports its status,
 * so both halves live here: the installation side that registers the service and
 * the runtime side that answers the controls.
 */
#include "install.h"
#include "identity_file.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <accctrl.h>
#include <aclapi.h>

#define SERVICE_TITLE L"fastp2p"

static SERVICE_STATUS_HANDLE status_handle;
static int (*service_loop)(int, char **);
static int service_argc;
static char **service_argv;
static char service_profile[4096];

static int wide(const char *text, WCHAR out[4096]) {
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, out, 4096) ? 0 : -1;
}

static void report(DWORD state, DWORD exit_code) {
    if (!status_handle)
        return;
    SERVICE_STATUS status = {0};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwWin32ExitCode = exit_code;
    status.dwWaitHint = state == SERVICE_RUNNING ? 0 : 30000;
    if (state == SERVICE_RUNNING)
        status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(status_handle, &status);
}

static DWORD WINAPI control(DWORD code, DWORD event, void *data, void *context) {
    (void)event;
    (void)data;
    (void)context;
    if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN) {
        report(SERVICE_STOP_PENDING, 0);
        /* The named event is what the run loop already watches. */
        fastp2p_stop_installed(service_profile);
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

static void WINAPI service_main(DWORD argc, LPWSTR *argv) {
    (void)argc;
    (void)argv;
    status_handle = RegisterServiceCtrlHandlerExW(SERVICE_TITLE, control, NULL);
    if (!status_handle)
        return;
    report(SERVICE_START_PENDING, 0);
    report(SERVICE_RUNNING, 0);
    int code = service_loop(service_argc, service_argv);
    report(SERVICE_STOPPED, (DWORD)code);
}

int fastp2p_service_supported(void) { return 1; }

void fastp2p_install_pause(void) {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    if (input == INVALID_HANDLE_VALUE || input == NULL) return;
    DWORD mode = 0;
    if (!GetConsoleMode(input, &mode)) return; /* no console to hold open */
    fputs("Press Enter to close.\n", stdout);
    fflush(stdout);
    char ignored[8];
    (void)!fgets(ignored, sizeof(ignored), stdin);
}

int fastp2p_service_dispatch(const char *profile, int argc, char **argv,
                             int (*loop)(int, char **)) {
    if (!loop || !profile)
        return -1;
    snprintf(service_profile, sizeof(service_profile), "%s", profile);
    service_loop = loop;
    service_argc = argc;
    service_argv = argv;
    SERVICE_TABLE_ENTRYW table[] = {{(LPWSTR)SERVICE_TITLE, service_main}, {NULL, NULL}};
    /* Fails when not started by the service manager, which is the right answer. */
    return StartServiceCtrlDispatcherW(table) ? 0 : -1;
}

int fastp2p_service_installed(void) {
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!manager)
        return 0;
    SC_HANDLE service = OpenServiceW(manager, SERVICE_TITLE, SERVICE_QUERY_STATUS);
    int found = service != NULL;
    if (service)
        CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return found;
}

/* Copy this executable where the service can always find it and register it. */
static void restrict_directory(const char *file) {
    char directory[4096];
    if (!file || snprintf(directory, sizeof(directory), "%s", file) >= (int)sizeof(directory))
        return;
    char *slash = strrchr(directory, '/');
    char *other = strrchr(directory, '\\');
    if (other && (!slash || other > slash)) slash = other;
    if (!slash) return;
    *slash = 0;
    WCHAR wide_directory[4096];
    if (wide(directory, wide_directory)) return;
    EXPLICIT_ACCESSW entries[2] = {0};
    for (int i = 0; i < 2; ++i) {
        entries[i].grfAccessPermissions = GENERIC_ALL;
        entries[i].grfAccessMode = SET_ACCESS;
        entries[i].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    }
    SID_IDENTIFIER_AUTHORITY system_authority = SECURITY_NT_AUTHORITY;
    PSID system_sid = NULL, admins_sid = NULL;
    if (!AllocateAndInitializeSid(&system_authority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0,
                                  &system_sid) ||
        !AllocateAndInitializeSid(&system_authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0, &admins_sid)) {
        if (system_sid) FreeSid(system_sid);
        return;
    }
    entries[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entries[0].Trustee.ptstrName = (LPWSTR)system_sid;
    entries[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entries[1].Trustee.ptstrName = (LPWSTR)admins_sid;
    PACL acl = NULL;
    if (SetEntriesInAclW(2, entries, NULL, &acl) == ERROR_SUCCESS && acl) {
        SetNamedSecurityInfoW(wide_directory, SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL,
                              acl, NULL);
        LocalFree(acl);
    }
    FreeSid(system_sid);
    FreeSid(admins_sid);
}

/* Create the machine profile directory and lock it down before anything is
 * written into it, so the key is never briefly readable by other users. */
int fastp2p_service_prepare(const char *profile) {
    if (!profile || fastp2p_private_parents(profile))
        return -1;
    restrict_directory(profile);
    return 0;
}

int fastp2p_service_install(const char *profile, const char *ca) {
    (void)ca;
    fastp2p_service_prepare(profile);
    WCHAR source[4096], target[4096], config[4096];
    DWORD length = GetModuleFileNameW(NULL, source, 4096);
    if (!length || length >= 4096)
        return -1;
    const char *program_files = getenv("ProgramFiles");
    if (!program_files || !*program_files)
        return -1;
    char text[4096];
    if (snprintf(text, sizeof(text), "%s/fastp2p/fastp2p.exe", program_files) >= (int)sizeof(text))
        return -1;
    if (fastp2p_private_parents(text) || wide(text, target) || wide(profile, config))
        return -1;
    for (WCHAR *p = target; *p; ++p)
        if (*p == L'/')
            *p = L'\\';
    if (_wcsicmp(source, target)) {
        int copied = 0;
        for (int attempt = 0; attempt < 30; ++attempt) {
            if (CopyFileW(source, target, FALSE)) {
                copied = 1;
                break;
            }
            Sleep(100);
        }
        if (!copied)
            return -1;
    }
    WCHAR command[8500];
    /* --background sends the run loop's output to the profile log; a service has
     * no console to write to. */
    if (swprintf(command, 8500, L"\"%ls\" service --config \"%ls\" --background", target, config) < 0)
        return -1;

    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!manager)
        return -1;
    SC_HANDLE service = CreateServiceW(manager, SERVICE_TITLE, SERVICE_TITLE, SERVICE_ALL_ACCESS,
                                       SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                                       SERVICE_ERROR_NORMAL, command, NULL, NULL, NULL, NULL, NULL);
    if (!service && GetLastError() == ERROR_SERVICE_EXISTS)
        service = OpenServiceW(manager, SERVICE_TITLE, SERVICE_ALL_ACCESS);
    if (!service) {
        CloseServiceHandle(manager);
        return -1;
    }
    /* An update must repoint the command line without disturbing the start type. */
    ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, command,
                         NULL, NULL, NULL, NULL, NULL, SERVICE_TITLE);
    SERVICE_DESCRIPTIONW description = {L"fastp2p client; keeps the overlay running at boot."};
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &description);
    /* Restart on failure so a crash does not need someone to log in. */
    SC_ACTION actions[3] = {{SC_ACTION_RESTART, 5000},
                            {SC_ACTION_RESTART, 10000},
                            {SC_ACTION_RESTART, 30000}};
    SERVICE_FAILURE_ACTIONSA failure = {0};
    failure.dwResetPeriod = 86400;
    failure.cActions = 3;
    failure.lpsaActions = actions;
    ChangeServiceConfig2A(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failure);
    int started = StartServiceW(service, 0, NULL) != 0 || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return started ? 0 : -1;
}

int fastp2p_service_remove(void) {
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!manager)
        return -1;
    SC_HANDLE service = OpenServiceW(manager, SERVICE_TITLE, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(manager);
        return GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST ? 0 : -1;
    }
    SERVICE_STATUS status = {0};
    if (ControlService(service, SERVICE_CONTROL_STOP, &status))
        for (int i = 0; i < 50 && status.dwCurrentState != SERVICE_STOPPED; ++i) {
            Sleep(100);
            if (!QueryServiceStatus(service, &status))
                break;
        }
    int removed = DeleteService(service) != 0;
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return removed ? 0 : -1;
}

int fastp2p_service_elevated(void) {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return 0;
    TOKEN_ELEVATION elevation = {0};
    DWORD size = sizeof(elevation);
    int elevated = GetTokenInformation(token, TokenElevation, &elevation, size, &size) &&
                   elevation.TokenIsElevated;
    CloseHandle(token);
    return elevated;
}

/* Ask Windows for the rights the installation needs, then exit; the elevated copy
 * repeats the work with the same command line. */
int fastp2p_service_elevate(const char *arguments) {
    WCHAR self[4096], wide_arguments[4096];
    DWORD length = GetModuleFileNameW(NULL, self, 4096);
    if (!length || length >= 4096)
        return -1;
    if (arguments && *arguments) {
        if (wide(arguments, wide_arguments))
            return -1;
    } else {
        wide_arguments[0] = 0;
    }
    HINSTANCE result = ShellExecuteW(NULL, L"runas", self,
                                     *wide_arguments ? wide_arguments : NULL, NULL, SW_SHOWNORMAL);
    return (INT_PTR)result > 32 ? 0 : -1;
}

#else /* POSIX: services are installed by the platform scripts, not this binary. */

int fastp2p_service_supported(void) { return 0; }
void fastp2p_install_pause(void) {}
int fastp2p_service_dispatch(const char *profile, int argc, char **argv,
                             int (*loop)(int, char **)) {
    (void)profile;
    (void)argc;
    (void)argv;
    (void)loop;
    return -1;
}
int fastp2p_service_installed(void) { return 0; }
int fastp2p_service_prepare(const char *profile) {
    (void)profile;
    return -1;
}
int fastp2p_service_install(const char *profile, const char *ca) {
    (void)profile;
    (void)ca;
    return -1;
}
int fastp2p_service_remove(void) { return -1; }
int fastp2p_service_elevated(void) { return 1; }
int fastp2p_service_elevate(const char *arguments) {
    (void)arguments;
    return -1;
}

#endif
