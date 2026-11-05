#include "update.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

static DWORD WINAPI release_image(void *handle) {
    Sleep(350);
    CloseHandle((HANDLE)handle);
    return 0;
}

static void fixture(const wchar_t *path) {
    HANDLE file=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,0,NULL);assert(file!=INVALID_HANDLE_VALUE);
    DWORD count;assert(WriteFile(file,"keep",4,&count,NULL) && count==4);CloseHandle(file);
}
static void cleanup_child(const wchar_t *image) {
    wchar_t command[4200];assert(swprintf(command,4200,L"\"%ls\" --cleanup-fixture",image)>0);
    STARTUPINFOW startup={.cb=sizeof(startup)};PROCESS_INFORMATION process;
    assert(CreateProcessW(image,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&startup,&process));
    assert(WaitForSingleObject(process.hProcess,10000)==WAIT_OBJECT_0);
    DWORD code;assert(GetExitCodeProcess(process.hProcess,&code) && !code);
    CloseHandle(process.hThread);CloseHandle(process.hProcess);
}
int main(int argc,char **argv) {
    if(argc==2 && !strcmp(argv[1],"--cleanup-fixture")){fp_update_cleanup();return 0;}
    wchar_t directory[MAX_PATH], source[MAX_PATH], target[MAX_PATH];
    assert(GetTempPathW(MAX_PATH, directory));
    assert(GetTempFileNameW(directory, L"fpS", 0, source));
    assert(GetTempFileNameW(directory, L"fpT", 0, target));
    HANDLE replacement = CreateFileW(source, GENERIC_WRITE, 0, NULL, TRUNCATE_EXISTING, 0, NULL);
    assert(replacement != INVALID_HANDLE_VALUE);
    DWORD count;
    assert(WriteFile(replacement, "new", 3, &count, NULL) && count == 3);
    CloseHandle(replacement);
    /* A stopped service can still hold a handle without FILE_SHARE_DELETE. */
    HANDLE old_image = CreateFileW(target, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
    assert(old_image != INVALID_HANDLE_VALUE);
    assert(!MoveFileExW(source, target, MOVEFILE_REPLACE_EXISTING));
    HANDLE thread = CreateThread(NULL, 0, release_image, old_image, 0, NULL);
    assert(thread);
    assert(!fp_update_replace_file(source, target));
    assert(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0);
    CloseHandle(thread);
    HANDLE installed = CreateFileW(target, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    char data[4] = {0};
    assert(installed != INVALID_HANDLE_VALUE);
    assert(ReadFile(installed, data, sizeof(data), &count, NULL) && count == 3);
    assert(!strcmp(data, "new"));
    CloseHandle(installed);
    assert(GetFileAttributesW(source) == INVALID_FILE_ATTRIBUTES);
    /* A missing source is a real failure, not a reason to wait ten seconds. */
    ULONGLONG started = GetTickCount64();
    assert(fp_update_replace_file(source, target));
    assert(GetTickCount64() - started < 2000);
    assert(DeleteFileW(target));
    /* The cleanup runs from a copied test binary in its own temporary folder,
     * never the build directory or the user's actual client installation. */
    wchar_t root[MAX_PATH],image[4096],self[4096],old[MAX_PATH],active[MAX_PATH],locked[MAX_PATH],keep[MAX_PATH],folder[MAX_PATH];
    assert(GetTempFileNameW(directory,L"fpC",0,root) && DeleteFileW(root) && CreateDirectoryW(root,NULL));
    assert(GetModuleFileNameW(NULL,self,4096));
    swprintf(image,4096,L"%ls\\cleanup-test.exe",root);assert(CopyFileW(self,image,TRUE));
    swprintf(old,MAX_PATH,L"%ls\\.fastp2p-update-2147483647.exe.old",root);fixture(old);
    swprintf(active,MAX_PATH,L"%ls\\.fastp2p-update-%lu.exe",root,(unsigned long)GetCurrentProcessId());fixture(active);
    swprintf(locked,MAX_PATH,L"%ls\\.fastp2p-update-2147483643.exe",root);fixture(locked);
    swprintf(keep,MAX_PATH,L"%ls\\.fastp2p-update-2147483647.exe.keep",root);fixture(keep);
    swprintf(folder,MAX_PATH,L"%ls\\.fastp2p-update-2147483639.exe",root);assert(CreateDirectoryW(folder,NULL));
    image[4095]=0;
    HANDLE held=CreateFileW(locked,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);assert(held!=INVALID_HANDLE_VALUE);
    cleanup_child(image);
    assert(GetFileAttributesW(old)==INVALID_FILE_ATTRIBUTES);
    assert(GetFileAttributesW(active)!=INVALID_FILE_ATTRIBUTES && GetFileAttributesW(locked)!=INVALID_FILE_ATTRIBUTES);
    assert(GetFileAttributesW(keep)!=INVALID_FILE_ATTRIBUTES && GetFileAttributesW(folder)!=INVALID_FILE_ATTRIBUTES &&
           (GetFileAttributesW(folder)&FILE_ATTRIBUTE_DIRECTORY));
    CloseHandle(held);cleanup_child(image);
    assert(GetFileAttributesW(locked)==INVALID_FILE_ATTRIBUTES);
    assert(DeleteFileW(active) && DeleteFileW(keep) && RemoveDirectoryW(folder));
    assert(DeleteFileW(image) && RemoveDirectoryW(root));
    puts("Windows update waits for the old image and preserves real errors");
    return 0;
}
