#include "log_rotation.h"
#include <stdio.h>
#include <string.h>

/* Small enough for an embedded device, large enough that rotation is rare. */
#define FP_LOG_CHUNK 16384

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <windows.h>

static int copy_tail(int source, long long start, int target) {
    char buffer[FP_LOG_CHUNK];
    if (_lseeki64(source, start, SEEK_SET) < 0)
        return -1;
    int first = 1, read_count;
    while ((read_count = _read(source, buffer, sizeof(buffer))) > 0) {
        int offset = 0;
        if (first) {
            /* Drop the partial line the kept window starts in. */
            const char *newline = memchr(buffer, '\n', (size_t)read_count);
            if (!newline)
                continue;
            offset = (int)(newline - buffer) + 1;
            first = 0;
        }
        if (_write(target, buffer + offset, (size_t)(read_count - offset)) !=
            read_count - offset)
            return -1;
    }
    return read_count < 0 ? -1 : 0;
}

int fp_log_trim_wide(const wchar_t *path, uint64_t rotate_at, uint64_t keep) {
    if (!path || !*path || !rotate_at)
        return -1;
    struct _stat64 metadata;
    if (_wstat64(path, &metadata))
        return 0; /* No log yet: nothing to bound. */
    if (metadata.st_size < (__int64)rotate_at)
        return 0;
    if (keep > rotate_at)
        keep = rotate_at;
    long long start = (uint64_t)metadata.st_size > keep ? (long long)((uint64_t)metadata.st_size - keep) : 0;
    wchar_t temporary[4096];
    if (swprintf(temporary, 4096, L"%ls.rotate", path) < 0)
        return -1;
    _wunlink(temporary);
    int source = _wopen(path, _O_RDONLY | _O_BINARY);
    if (source < 0)
        return -1;
    int target = _wopen(temporary, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, _S_IREAD | _S_IWRITE);
    if (target < 0) {
        _close(source);
        return -1;
    }
    int failed = copy_tail(source, start, target);
    _close(source);
    if (_close(target))
        failed = 1;
    if (!failed && !MoveFileExW(temporary, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        failed = 1;
    if (failed) {
        _wunlink(temporary);
        return -1;
    }
    return _wopen(path, _O_WRONLY | _O_APPEND | _O_BINARY);
}
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static int copy_tail(int source, off_t start, int target) {
    char buffer[FP_LOG_CHUNK];
    if (lseek(source, start, SEEK_SET) < 0)
        return -1;
    int first = 1;
    ssize_t read_count;
    while ((read_count = read(source, buffer, sizeof(buffer))) > 0) {
        ssize_t offset = 0;
        if (first) {
            /* Drop the partial line the kept window starts in. */
            const char *newline = memchr(buffer, '\n', (size_t)read_count);
            if (!newline)
                continue;
            offset = (ssize_t)(newline - buffer) + 1;
            first = 0;
        }
        if (write(target, buffer + offset, (size_t)(read_count - offset)) !=
            read_count - offset)
            return -1;
    }
    return read_count < 0 ? -1 : 0;
}

int fp_log_trim(const char *path, uint64_t rotate_at, uint64_t keep) {
    if (!path || !*path || !rotate_at)
        return -1;
    struct stat metadata;
    if (stat(path, &metadata))
        return errno == ENOENT ? 0 : -1; /* No log yet: nothing to bound. */
    if (!S_ISREG(metadata.st_mode) || metadata.st_size < (off_t)rotate_at)
        return 0;
    if (keep > rotate_at)
        keep = rotate_at;
    off_t start = (uint64_t)metadata.st_size > keep ? (off_t)((uint64_t)metadata.st_size - keep) : 0;
    char temporary[4096];
    if (snprintf(temporary, sizeof(temporary), "%s.rotate", path) >= (int)sizeof(temporary))
        return -1;
    (void)unlink(temporary);
    int source = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (source < 0)
        return -1;
    int target = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (target < 0) {
        close(source);
        return -1;
    }
    int failed = copy_tail(source, start, target);
    close(source);
    if (close(target))
        failed = 1;
    /* The rename replaces the old inode atomically; the caller then points its
     * streams at the descriptor returned below. */
    if (!failed && rename(temporary, path))
        failed = 1;
    if (failed) {
        unlink(temporary);
        return -1;
    }
    return open(path, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
}
#endif
