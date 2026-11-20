/* Exercise the POSIX update precheck and swap strategies without restarting. */
#include "update.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int write_file(const char *path, const char *text) {
    FILE *file = fopen(path, "wb");
    if (!file)
        return -1;
    size_t length = strlen(text);
    int ok = fwrite(text, 1, length, file) == length && !fclose(file);
    return ok ? 0 : -1;
}

static int read_matches(const char *path, const char *text) {
    char buffer[64] = {0};
    FILE *file = fopen(path, "rb");
    if (!file)
        return 0;
    size_t used = fread(buffer, 1, sizeof(buffer) - 1, file);
    fclose(file);
    return used == strlen(text) && !strcmp(buffer, text);
}

/* The swap must move directory entries, not data: the installed image is
 * replaced in place, the previous one survives under its rolled-over name, and
 * a failed swap leaves the installed image untouched. */
static void swap_strategies(void) {
    char base[] = "/tmp/fp-update-XXXXXX";
    assert(mkdtemp(base));
    char own[512], staged[512], previous[640], rollback[640], error[256];
    snprintf(own, sizeof(own), "%s/fastp2p", base);
    snprintf(staged, sizeof(staged), "%s/.fastp2p-update-1", base);
    snprintf(previous, sizeof(previous), "%s.old", own);

    assert(!write_file(own, "old-image"));
    assert(!write_file(staged, "new-image"));
    assert(!fp_update_swap_files(own, staged, previous, rollback, sizeof(rollback), error,
                                 sizeof(error)));
    assert(read_matches(own, "new-image"));
    assert(rollback[0] && read_matches(rollback, "old-image"));

    /* A missing package is refused and the installed image still runs. */
    unlink(staged);
    assert(fp_update_swap_files(own, staged, previous, rollback, sizeof(rollback), error,
                                sizeof(error)));
    assert(read_matches(own, "new-image"));
    assert(error[0]);

    /* A leftover name from an earlier attempt must not block the swap. */
    unlink(previous);
    unlink(staged);
    assert(!write_file(staged, "third-image"));
    assert(!write_file(previous, "stale-image"));
    assert(!fp_update_swap_files(own, staged, previous, rollback, sizeof(rollback), error,
                                 sizeof(error)));
    assert(read_matches(own, "third-image"));
    assert(rollback[0] && read_matches(rollback, "new-image"));

    char command[512];
    snprintf(command, sizeof(command), "rm -rf '%s'", base);
    assert(!system(command));
}

/* The precheck runs while the client is online, so it has to reject the cases
 * that would otherwise fail silently after the service has stopped. */
static void precheck(void) {
    char self[4096], directory[4096], error[256], adjacent[4200];
    assert(!fp_update_own_path(self, sizeof(self)));
    snprintf(directory, sizeof(directory), "%s", self);
    char *slash = strrchr(directory, '/');
    assert(slash);
    slash[1] = 0;

    snprintf(adjacent, sizeof(adjacent), "%s.fastp2p-update-test", directory);
    assert(!write_file(adjacent, "package"));
    assert(!fp_update_precheck(adjacent, error, sizeof(error)));
    unlink(adjacent);

    /* Nothing to install. */
    memset(error, 0, sizeof(error));
    assert(fp_update_precheck(adjacent, error, sizeof(error)));
    assert(error[0]);

#ifdef __linux__
    /* A package on another filesystem can never be renamed into place. */
    struct stat here, there;
    if (!stat(directory, &here) && !stat("/dev/shm", &there) && here.st_dev != there.st_dev) {
        char foreign[4200];
        snprintf(foreign, sizeof(foreign), "/dev/shm/fp-update-cross-%ld", (long)getpid());
        if (!write_file(foreign, "package")) {
            memset(error, 0, sizeof(error));
            assert(fp_update_precheck(foreign, error, sizeof(error)));
            assert(strstr(error, "different filesystem") != NULL);
            unlink(foreign);
        }
    }
#endif
}

int main(void) {
    swap_strategies();
    precheck();
    puts("POSIX update precheck and swap strategies passed");
    return 0;
}
