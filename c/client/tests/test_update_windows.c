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

int main(void) {
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
    HANDLE image = CreateFileW(target, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
    assert(image != INVALID_HANDLE_VALUE);
    assert(!MoveFileExW(source, target, MOVEFILE_REPLACE_EXISTING));
    HANDLE thread = CreateThread(NULL, 0, release_image, image, 0, NULL);
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
    puts("Windows update waits for the old image and preserves real errors");
    return 0;
}
