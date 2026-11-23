/* The runtime log must stay inside one file of bounded size, without ever
 * buffering the whole log: these cases check the trimming primitive directly. */
#include "log_rotation.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#define LINE 40

static void make_directory(char *out, size_t size) {
#ifdef _WIN32
    char base[MAX_PATH];
    GetTempPathA(MAX_PATH, base);
    snprintf(out, size, "%sfastp2p-log-test-%lu", base, (unsigned long)GetCurrentProcessId());
    _mkdir(out);
#else
    snprintf(out, size, "/tmp/fastp2p-log-test-%ld", (long)getpid());
    mkdir(out, 0700);
#endif
}

static void fill(const char *path, int lines) {
    FILE *file = fopen(path, "wb");
    assert(file);
    for (int i = 0; i < lines; ++i) {
        char text[LINE];
        int written = snprintf(text, sizeof(text), "line %05d ", i);
        memset(text + written, '.', (size_t)(LINE - 1 - written));
        text[LINE - 1] = '\n';
        assert(fwrite(text, 1, LINE, file) == LINE);
    }
    assert(!fclose(file));
}

static int trim(const char *path, unsigned long long rotate_at, unsigned long long keep) {
#ifdef _WIN32
    wchar_t wide[1024];
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wide, 1024))
        return -2;
    return fp_log_trim_wide(wide, rotate_at, keep);
#else
    return fp_log_trim(path, rotate_at, keep);
#endif
}

static unsigned char *slurp(const char *path, size_t *length) {
    FILE *file = fopen(path, "rb");
    if (!file)
        return NULL;
    assert(!fseek(file, 0, SEEK_END));
    long size = ftell(file);
    assert(size >= 0 && !fseek(file, 0, SEEK_SET));
    unsigned char *data = malloc((size_t)size + 1);
    assert(data);
    assert(fread(data, 1, (size_t)size, file) == (size_t)size);
    data[size] = 0;
    *length = (size_t)size;
    assert(!fclose(file));
    return data;
}

int main(void) {
    char directory[512], path[600], temporary[640];
    make_directory(directory, sizeof(directory));
    snprintf(path, sizeof(path), "%s/runtime.log", directory);
    snprintf(temporary, sizeof(temporary), "%s.rotate", path);

    /* Nothing to do for a missing or small log. */
    assert(trim(path, 2048, 1024) == 0);
    fill(path, 40);
    size_t before = 0;
    unsigned char *original = slurp(path, &before);
    assert(original && before == 40 * LINE);
    assert(trim(path, 2048, 1024) == 0);

    /* Over the threshold: keep the newest bytes, on a line boundary, and hand
     * back a descriptor that appends to the trimmed file. */
    int fd = trim(path, 1024, 512);
    assert(fd > 0);
    size_t kept = 0, after_append = 0;
    unsigned char *trimmed = slurp(path, &kept);
    assert(trimmed);
    assert(kept > 0 && kept <= 512);
    assert(kept <= before);
    assert(!memcmp(trimmed, original + (before - kept), kept));
    assert(trimmed[0] == 'l' && trimmed[kept - 1] == '\n');
#ifndef _WIN32
    struct stat metadata;
    assert(!stat(path, &metadata));
    assert(!(metadata.st_mode & 0077));
    assert(metadata.st_size == (off_t)kept);
#endif
    /* The trimmed file is the one the returned descriptor appends to. */
    assert(write(fd, "line 99999 appended\n", 20) == 20);
#ifdef _WIN32
    _close(fd);
#else
    close(fd);
#endif
    free(trimmed);
    trimmed = slurp(path, &after_append);
    assert(trimmed && after_append > kept);
    assert(!memcmp(trimmed, original + (before - kept), kept));
    assert(!memcmp(trimmed + kept, "line 99999 appended\n", 20));
    free(trimmed);

    /* Repeated growth stays bounded instead of growing without limit. */
    for (int round = 0; round < 12; ++round) {
        FILE *file = fopen(path, "ab");
        assert(file);
        for (int i = 0; i < 40; ++i) {
            char text[LINE];
            int written = snprintf(text, sizeof(text), "round %02d %02d ", round, i);
            memset(text + written, '.', (size_t)(LINE - 1 - written));
            text[LINE - 1] = '\n';
            assert(fwrite(text, 1, LINE, file) == LINE);
        }
        assert(!fclose(file));
        int again = trim(path, 1024, 512);
        if (again > 0) {
#ifdef _WIN32
            _close(again);
#else
            close(again);
#endif
        } else {
            assert(again == 0);
        }
        size_t size = 0;
        unsigned char *current = slurp(path, &size);
        assert(current);
        assert(size <= 1024 + LINE);
        assert(current[size - 1] == '\n');
        free(current);
    }

    /* Only the active log remains: no rotation debris. */
    assert(!fopen(temporary, "rb"));

#ifndef _WIN32
    /* A symlinked log is refused and its target is left alone. */
    char link[600], target[600];
    snprintf(link, sizeof(link), "%s/link.log", directory);
    snprintf(target, sizeof(target), "%s/target.log", directory);
    fill(target, 60);
    unlink(link);
    assert(!symlink(target, link));
    assert(trim(link, 1024, 512) <= 0);
    size_t untouched = 0;
    unsigned char *content = slurp(target, &untouched);
    assert(content && untouched == 60 * LINE);
    free(content);
#endif

    free(original);
    return 0;
}
