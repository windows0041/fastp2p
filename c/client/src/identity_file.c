#include "identity_file.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define close _close
#define read _read
#define write _write
#else
#include <unistd.h>
#endif

#ifdef _WIN32
static int wide(const char *text, WCHAR out[4096]) {
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, out, 4096) ? 0 : -1;
}
#endif
static int directory(const char *path) {
#ifdef _WIN32
    WCHAR name[4096];
    if (wide(path, name))
        return -1;
    if (!CreateDirectoryW(name, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        return -1;
    DWORD attributes = GetFileAttributesW(name);
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) &&
           !(attributes & FILE_ATTRIBUTE_REPARSE_POINT) ? 0 : -1;
#else
    struct stat status;
    if (mkdir(path, 0700) && errno != EEXIST)
        return -1;
    return !lstat(path, &status) && S_ISDIR(status.st_mode) ? 0 : -1;
#endif
}
static int open_file(const char *path, int create) {
#ifdef _WIN32
    WCHAR name[4096];
    if (wide(path, name))
        return -1;
    DWORD attributes = GetFileAttributesW(name);
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        errno = EINVAL;
        return -1;
    }
    return _wopen(name, _O_BINARY | _O_NOINHERIT |
                        (create ? _O_WRONLY | _O_CREAT | _O_EXCL : _O_RDONLY), _S_IREAD | _S_IWRITE);
#else
    return open(path, O_CLOEXEC | O_NOFOLLOW | (create ? O_WRONLY | O_CREAT | O_EXCL : O_RDONLY), 0600);
#endif
}
int op_cli_identity(op2p_client *client, const char *file, const char *config,
                     const char *host, unsigned port) {
    const char *identity = op2p_client_device_id(client);
    if (!*identity)
        return 0;
    char path[4096];
    int length;
    if (file && *file)
        length = snprintf(path, sizeof(path), "%s", file);
    else if (config && *config)
        length = snprintf(path, sizeof(path), "%s.identity", config);
    else {
#ifdef _WIN32
        const char *home = getenv("LOCALAPPDATA");
        if (!home || !*home)
            return -1;
        length = snprintf(path, sizeof(path), "%s/openp2p-c/%s-%u.identity", home, host, port);
#else
        const char *state = getenv("XDG_STATE_HOME"), *home = getenv("HOME");
        if (state && *state)
            length = snprintf(path, sizeof(path), "%s/openp2p-c/%s-%u.identity", state, host, port);
        else if (home && *home)
            length = snprintf(path, sizeof(path), "%s/.local/state/openp2p-c/%s-%u.identity", home, host, port);
        else
            return -1;
#endif
    }
    if (length < 1 || (size_t)length >= sizeof(path))
        return -1;
    for (char *p = path + 1; *p; ++p) {
        if (*p != '/' && *p != '\\')
            continue;
#ifdef _WIN32
        if (p == path + 2 && path[1] == ':')
            continue;
#endif
        char separator = *p; *p = 0;
        int rv = directory(path);
        *p = separator;
        if (rv)
            return -1;
    }
    int fd = open_file(path, 1);
    if (fd >= 0) {
        char data[33];
        memcpy(data, identity, 32); data[32] = '\n';
        int ok = write(fd, data, 33) == 33;
#ifdef _WIN32
        if (ok) ok = !_commit(fd);
#else
        if (ok) ok = !fsync(fd);
#endif
        if (close(fd)) ok = 0;
        return ok ? 0 : -1;
    }
    if (errno != EEXIST)
        return -1;
    for (int attempt = 0; attempt < 10; ++attempt) {
        fd = open_file(path, 0);
        if (fd < 0)
            return -1;
#ifdef _WIN32
        struct _stat64 status;
        int regular = !_fstat64(fd, &status) && (status.st_mode & _S_IFREG);
#else
        struct stat status;
        int regular = !fstat(fd, &status) && S_ISREG(status.st_mode);
#endif
        char data[35];
        int count = regular ? (int)read(fd, data, 34) : -1;
        close(fd);
        if (count == 32 || (count == 33 && data[32] == '\n')) {
            data[32] = 0;
            return op2p_client_set_identity(client, data);
        }
        if (count != 0)
            return -1;
#ifdef _WIN32
        Sleep(50);
#else
        struct timespec delay = {.tv_nsec = 50000000};
        nanosleep(&delay, NULL);
#endif
    }
    return -1;
}
