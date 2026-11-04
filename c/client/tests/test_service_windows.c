/* Real SCM lifecycle, isolated from the user's fastp2p service and directories. */
#include "install.h"
#include <windows.h>
#include <shlobj.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static volatile LONG stopping;
void fastp2p_runtime_request_stop(void) { InterlockedExchange(&stopping, 1); }
int fastp2p_service_profile(char path[4096]) { (void)path; return -1; } /* purge is never used */
int fastp2p_private_parents(const char *path) {
    WCHAR wide[4096];
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wide, 4096)) return -1;
    WCHAR *slash = wcsrchr(wide, L'/'), *backslash = wcsrchr(wide, L'\\');
    if (backslash && (!slash || backslash > slash)) slash = backslash;
    if (!slash) return -1;
    *slash = 0;
    int status = SHCreateDirectoryExW(NULL, wide, NULL);
    return status == ERROR_SUCCESS || status == ERROR_ALREADY_EXISTS ? 0 : -1;
}
static int loop(int argc, char **argv) {
    (void)argc;
    char marker[4096]; snprintf(marker, sizeof(marker), "%s.ready", argv[3]);
    FILE *file = fopen(marker, "wb"); if (!file) return 1;
    fputs("ready", file); fclose(file);
    while (!InterlockedCompareExchange(&stopping, 0, 0)) Sleep(10);
    /* Reporting STOPPED happens before process teardown; removal must also wait
     * for the image handle to close, tested by replacing it immediately below. */
    Sleep(400);
    return 0;
}
static DWORD WINAPI close_service_later(void *service) {
    Sleep(400); CloseServiceHandle((SC_HANDLE)service); return 0;
}
int main(int argc, char **argv) {
    if (argc >= 4 && !strcmp(argv[1], "service"))
        return fastp2p_service_dispatch(argv[3], argc, argv, loop) ? 1 : 0;
    assert(fastp2p_service_elevated());
    assert(!fastp2p_service_installed()); /* test-only name; never delete an existing service */
    char temp[4096], root[4096], profile[4096], marker[4096], installed[4096];
    assert(GetTempPathA(sizeof(temp), temp));
    snprintf(root, sizeof(root), "%sfastp2p-service-ci-%lu", temp, (unsigned long)GetCurrentProcessId());
    assert(CreateDirectoryA(root, NULL));
    assert(SetEnvironmentVariableA("ProgramFiles", root));
    snprintf(profile, sizeof(profile), "%s/config/client.dat", root);
    assert(!fastp2p_service_prepare(profile));
    FILE *file = fopen(profile, "wb"); assert(file); fputs("identity-fixture", file); fclose(file);
    snprintf(marker, sizeof(marker), "%s.ready", profile);
    snprintf(installed, sizeof(installed), "%s/fastp2p/fastp2p.exe", root);
    for (int pass = 0; pass < 2; ++pass) {
        assert(!fastp2p_service_install(profile, NULL));
        int ready = 0;
        for (int i = 0; i < 100; ++i) {
            if (GetFileAttributesA(marker) != INVALID_FILE_ATTRIBUTES) { ready = 1; break; }
            Sleep(50);
        }
        assert(ready && fastp2p_service_installed());
        SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT); assert(scm);
        SC_HANDLE held = OpenServiceW(scm, L"fastp2p-installer-ci", SERVICE_QUERY_STATUS); assert(held);
        assert(!fastp2p_service_remove());
        HANDLE thread = CreateThread(NULL, 0, close_service_later, held, 0, NULL); assert(thread);
        /* An open service handle delays deletion. New registration must retry. */
        assert(!fastp2p_service_install(profile, NULL));
        assert(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0);
        CloseHandle(thread); CloseServiceHandle(scm);
        assert(!fastp2p_service_remove());
        file = fopen(profile, "rb"); assert(file);
        char saved[32] = {0}; assert(fread(saved, 1, sizeof(saved)-1, file) == 16); fclose(file);
        assert(!strcmp(saved, "identity-fixture"));
        assert(DeleteFileA(installed)); /* old process has really released the executable */
        DeleteFileA(marker);
    }
    assert(!fastp2p_service_remove());
    DeleteFileA(profile);
    char directory[4096]; snprintf(directory, sizeof(directory), "%s/config", root); RemoveDirectoryA(directory);
    snprintf(directory, sizeof(directory), "%s/fastp2p", root); RemoveDirectoryA(directory);
    assert(RemoveDirectoryA(root));
    puts("Windows service uninstall/reinstall waits for process exit and delayed SCM deletion; identity retained");
    return 0;
}
