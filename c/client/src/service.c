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

#ifdef FASTP2P_SERVICE_TEST
#define SERVICE_TITLE L"fastp2p-installer-ci"
#else
#define SERVICE_TITLE L"fastp2p"
#endif

static SERVICE_STATUS_HANDLE status_handle;
static DWORD status_checkpoint;
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
    if (state == SERVICE_STOPPED && exit_code) {
        /* A non-zero result is the client's own, not a Win32 error code. */
        status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        status.dwServiceSpecificExitCode = exit_code;
    } else {
        status.dwWin32ExitCode = exit_code;
    }
    status.dwWaitHint = state == SERVICE_RUNNING ? 0 : 30000;
    status.dwCheckPoint = state == SERVICE_RUNNING ? 0 : ++status_checkpoint;
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
        /* The flag is set in-process as well: the named event does not exist yet
         * while the client is still starting up. */
        fastp2p_runtime_request_stop();
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
/* Anything short of a verified SYSTEM/Administrators-only directory leaves the
 * machine-scope DPAPI secret readable by local users, so a failure here has to
 * stop the install rather than be papered over. */
static int restrict_directory(const char *file) {
    char directory[4096];
    if (!file || snprintf(directory, sizeof(directory), "%s", file) >= (int)sizeof(directory))
        return -1;
    char *slash = strrchr(directory, '/');
    char *other = strrchr(directory, '\\');
    if (other && (!slash || other > slash)) slash = other;
    if (!slash) return -1;
    *slash = 0;
    WCHAR wide_directory[4096];
    if (wide(directory, wide_directory)) return -1;
    EXPLICIT_ACCESSW entries[2] = {0};
    for (int i = 0; i < 2; ++i) {
        entries[i].grfAccessPermissions = GENERIC_ALL;
        entries[i].grfAccessMode = SET_ACCESS;
        entries[i].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    }
    SID_IDENTIFIER_AUTHORITY system_authority = SECURITY_NT_AUTHORITY;
    PSID system_sid = NULL, admins_sid = NULL;
    int rv = -1;
    if (!AllocateAndInitializeSid(&system_authority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0,
                                  &system_sid) ||
        !AllocateAndInitializeSid(&system_authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0, &admins_sid))
        goto done;
    entries[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entries[0].Trustee.ptstrName = (LPWSTR)system_sid;
    entries[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entries[1].Trustee.ptstrName = (LPWSTR)admins_sid;
    PACL acl = NULL;
    if (SetEntriesInAclW(2, entries, NULL, &acl) != ERROR_SUCCESS || !acl)
        goto done;
    /* The directory may have been pre-created by another user, whose implicit
     * WRITE_DAC as owner would undo this, so the owner is set as well. */
    if(SetNamedSecurityInfoW(wide_directory, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, admins_sid, NULL,
                             NULL, NULL)!=ERROR_SUCCESS) {
        LocalFree(acl);goto done;
    }
    if (SetNamedSecurityInfoW(wide_directory, SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL,
                              acl, NULL) != ERROR_SUCCESS) {
        LocalFree(acl);
        goto done;
    }
    LocalFree(acl);
    rv = 0;
done:
    if (system_sid) FreeSid(system_sid);
    if (admins_sid) FreeSid(admins_sid);
    return rv;
}

/* Create the machine profile directory and lock it down before anything is
 * written into it, so the key is never briefly readable by other users. */
int fastp2p_service_prepare(const char *profile) {
    if (!profile || fastp2p_private_parents(profile))
        return -1;
    return restrict_directory(profile);
}

int fastp2p_service_install(const char *profile, const char *ca) {
    (void)ca;
    if (fastp2p_service_prepare(profile))
        return -1;
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
        /* A running service holds its image open for reading only, so it has to
         * be stopped before the file can be replaced. */
        char temporary[4096];
        if (snprintf(temporary, sizeof(temporary), "%s.new", text) >= (int)sizeof(temporary))
            return -1;
        WCHAR wide_temporary[4096];
        if (wide(temporary, wide_temporary))
            return -1;
        for (WCHAR *p = wide_temporary; *p; ++p)
            if (*p == L'/')
                *p = L'\\';
        int copied = 0;
        for (int attempt = 0; attempt < 30; ++attempt) {
            if (CopyFileW(source, wide_temporary, FALSE)) {
                copied = 1;
                break;
            }
            Sleep(100);
        }
        if (!copied)
            return -1;
        /* Swap it in, retrying: the old image is released once the service stops. */
        int replaced = 0;
        for (int attempt = 0; attempt < 100; ++attempt) {
            if (MoveFileExW(wide_temporary, target, MOVEFILE_REPLACE_EXISTING)) {
                replaced = 1;
                break;
            }
            Sleep(100);
        }
        if (!replaced) {
            DeleteFileW(wide_temporary);
            return -1;
        }
    }
    WCHAR command[8500];
    /* --background sends the run loop's output to the profile log; a service has
     * no console to write to. */
    if (swprintf(command, 8500, L"\"%ls\" service --config \"%ls\" --background", target, config) < 0)
        return -1;

    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!manager)
        return -1;
    SC_HANDLE service = NULL;
    for (int attempt = 0; attempt < 100; ++attempt) {
        service = CreateServiceW(manager, SERVICE_TITLE, SERVICE_TITLE, SERVICE_ALL_ACCESS,
                                  SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                                  SERVICE_ERROR_NORMAL, command, NULL, NULL, NULL, NULL, NULL);
        if (service || GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE) break;
        Sleep(100);
    }
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
    /* Boot-time DNS/network failures return a service-specific error through
     * report(STOPPED). They need the same recovery as a crashed process. */
    SERVICE_FAILURE_ACTIONS_FLAG failure_flag = {TRUE};
    ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &failure_flag);
    int started = StartServiceW(service, 0, NULL) != 0 || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
    /* SCM accepts StartService before the client has actually initialized. */
    int stable=0;
    for(int attempt=0;started && stable<30 && attempt<100;attempt++){
        SERVICE_STATUS status;
        if(!QueryServiceStatus(service,&status) || status.dwCurrentState==SERVICE_STOPPED){started=0;break;}
        stable=status.dwCurrentState==SERVICE_RUNNING?stable+1:0;
        Sleep(100);
    }
    if(stable<30)started=0;
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return started ? 0 : -1;
}

static int delete_previous_image(const WCHAR *path) {
    for(int attempt=0;attempt<50;attempt++){
        if(DeleteFileW(path))return 0;
        DWORD error=GetLastError();
        if(error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND)return 0;
        if(error!=ERROR_SHARING_VIOLATION && error!=ERROR_ACCESS_DENIED)return -1;
        Sleep(100);
    }
    return -1;
}
static int same_image(const WCHAR *a,const WCHAR *b) {
    HANDLE first=CreateFileW(a,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);
    if(first==INVALID_HANDLE_VALUE)return -1;
    HANDLE second=CreateFileW(b,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);
    if(second==INVALID_HANDLE_VALUE){
        DWORD error=GetLastError();CloseHandle(first);
        return error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND?0:-1;
    }
    BY_HANDLE_FILE_INFORMATION x,y;
    int result=GetFileInformationByHandle(first,&x) && GetFileInformationByHandle(second,&y)?
        x.dwVolumeSerialNumber==y.dwVolumeSerialNumber && x.nFileIndexHigh==y.nFileIndexHigh && x.nFileIndexLow==y.nFileIndexLow:-1;
    CloseHandle(first);CloseHandle(second);return result;
}
int fastp2p_service_cleanup_previous(void) {
    const char *program_files=getenv("ProgramFiles"),*local=getenv("LOCALAPPDATA");
    char text[4096];WCHAR target[4096],self[4096],legacy[4096],previous[4200];
    if(!program_files || snprintf(text,sizeof(text),"%s/fastp2p/fastp2p.exe",program_files)>=(int)sizeof(text) || wide(text,target))return -1;
    for(WCHAR *p=target;*p;p++)if(*p==L'/')*p=L'\\';
    DWORD length=GetModuleFileNameW(NULL,self,4096);
    if(!length || length>=4096)return -1;
    int pending=0;
    if(swprintf(previous,4200,L"%ls.old",target)<0 || delete_previous_image(previous))pending=1;
    if(local && snprintf(text,sizeof(text),"%s/fastp2p/fastp2p.exe",local)<(int)sizeof(text) && !wide(text,legacy)){
        for(WCHAR *p=legacy;*p;p++)if(*p==L'/')*p=L'\\';
        WCHAR resolved[4096],installed[4096],running[4096];
        DWORD a=GetFullPathNameW(legacy,4096,resolved,NULL),b=GetFullPathNameW(target,4096,installed,NULL),
              c=GetFullPathNameW(self,4096,running,NULL);
        if(!a || a>=4096 || !b || b>=4096 || !c || c>=4096)return -1;
        /* Never erase the replacement or an installer executing in-place. */
        if(_wcsicmp(resolved,installed) && _wcsicmp(resolved,running)){
            int installed_alias=same_image(target,legacy),installer_alias=same_image(self,legacy);
            if(installed_alias<0 || installer_alias<0)return -1;
            if(installed_alias || installer_alias)return pending?-1:0;
            if(delete_previous_image(legacy))pending=1;
            if(swprintf(previous,4200,L"%ls.old",legacy)<0 || delete_previous_image(previous))pending=1;
        }
    }
    return pending?-1:0;
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
    SERVICE_STATUS_PROCESS status = {0}; DWORD used = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)&status, sizeof(status), &used)) {
        CloseServiceHandle(service); CloseServiceHandle(manager); return -1;
    }
    HANDLE process = status.dwProcessId ? OpenProcess(SYNCHRONIZE, FALSE, status.dwProcessId) : NULL;
    SERVICE_STATUS ignored;
    if (status.dwCurrentState != SERVICE_STOPPED) ControlService(service, SERVICE_CONTROL_STOP, &ignored);
    int stopped = status.dwCurrentState == SERVICE_STOPPED;
    for (int i = 0; !stopped && i < 300; ++i) {
        Sleep(100);
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)&status, sizeof(status), &used)) break;
        /* START_PENDING does not accept STOP. Retry once the SCM reports that
         * the service can accept it, rather than leaving it running on reinstall. */
        if (status.dwCurrentState != SERVICE_STOPPED && (status.dwControlsAccepted & SERVICE_ACCEPT_STOP))
            ControlService(service, SERVICE_CONTROL_STOP, &ignored);
        if (!process && status.dwProcessId) process=OpenProcess(SYNCHRONIZE,FALSE,status.dwProcessId);
        stopped = status.dwCurrentState == SERVICE_STOPPED;
    }
    if (stopped && process) stopped = WaitForSingleObject(process, 10000) == WAIT_OBJECT_0;
    if (process) CloseHandle(process);
    int removed = stopped && DeleteService(service) != 0;
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return removed ? 0 : -1;
}

/* Deletes the profile directory's contents and the installed copy, best effort.
 * Returns non-zero when something is left behind. */
int fastp2p_service_purge(void) {
    int leftover = 0;
    char profile[4096];
    if (fastp2p_service_profile(profile))
        return 1;
    char directory[4096];
    if (snprintf(directory, sizeof(directory), "%s", profile) >= (int)sizeof(directory))
        return 1;
    char *slash = strrchr(directory, '/');
    if (!slash)
        return 1;
    *slash = 0;

    WCHAR pattern[4096];
    char joined[4200];
    if (snprintf(joined, sizeof(joined), "%s/*", directory) < (int)sizeof(joined) &&
        !wide(joined, pattern)) {
        WIN32_FIND_DATAW entry;
        HANDLE search = FindFirstFileW(pattern, &entry);
        if (search != INVALID_HANDLE_VALUE) {
            do {
                if (!wcscmp(entry.cFileName, L".") || !wcscmp(entry.cFileName, L".."))
                    continue;
                WCHAR victim[4096];
                if (snprintf(joined, sizeof(joined), "%s/%ls", directory, entry.cFileName) >=
                    (int)sizeof(joined))
                    continue;
                if (wide(joined, victim) || (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                    continue;
                if (!DeleteFileW(victim) && GetLastError() != ERROR_FILE_NOT_FOUND)
                    leftover = 1;
            } while (FindNextFileW(search, &entry));
            FindClose(search);
        }
    }
    WCHAR wide_directory[4096];
    if (!wide(directory, wide_directory))
        RemoveDirectoryW(wide_directory);

    const char *program_files = getenv("ProgramFiles");
    if (program_files && *program_files) {
        char installed[4096];
        if (snprintf(installed, sizeof(installed), "%s/fastp2p/fastp2p.exe", program_files) <
            (int)sizeof(installed)) {
            WCHAR wide_installed[4096];
            if (!wide(installed, wide_installed)) {
                /* Never schedule this fixed pathname for deletion at reboot:
                 * a subsequent reinstall could already put a new EXE there. */
                if (!DeleteFileW(wide_installed) && GetLastError() != ERROR_FILE_NOT_FOUND) {
                    leftover = 1;
                }
            }
        }
        char installed_directory[4096];
        if (snprintf(installed_directory, sizeof(installed_directory), "%s/fastp2p", program_files) <
            (int)sizeof(installed_directory)) {
            WCHAR wide_installed_directory[4096];
            if (!wide(installed_directory, wide_installed_directory))
                RemoveDirectoryW(wide_installed_directory);
        }
    }
    return leftover;
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
    /* POSIX installs are laid down by the platform unit files; nothing to lock. */
    (void)profile;
    return 0;
}
int fastp2p_service_install(const char *profile, const char *ca) {
    (void)profile;
    (void)ca;
    return -1;
}
int fastp2p_service_remove(void) { return -1; }
int fastp2p_service_cleanup_previous(void) { return 0; }
int fastp2p_service_purge(void) {
    char profile[4096];
    if (!fastp2p_service_profile(profile))
        remove(profile);
    return 0;
}
/* Deletes the profile directory's contents and the installed copy, best effort.
 * Returns non-zero when something is left behind. */
int fastp2p_service_elevated(void) { return 1; }
int fastp2p_service_elevate(const char *arguments) {
    (void)arguments;
    return -1;
}

#endif
