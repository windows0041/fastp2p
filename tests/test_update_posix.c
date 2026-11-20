/* Exercise the POSIX update precheck and swap strategies without restarting. */
#include "update.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int write_file(const char *path, const char *text) {
    FILE *file = fopen(path, "wb");
    if (!file)
        return -1;
    size_t length = strlen(text);
    int ok = fwrite(text, 1, length, file) == length;
    if (fclose(file))
        ok = 0;
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

    unlink(previous);
    unlink(staged);
    unlink(own);
    assert(!rmdir(base));
}

static void run_install(const char *installed, const char *package, int expected) {
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        char *argv[] = {(char *)installed, "--update-fixture", (char *)package, NULL};
        execv(installed, argv);
        _exit(127);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == expected);
}

static void restart_from_staged_package(void) {
    char base[] = "/tmp/fp-update-install-XXXXXX";
    assert(mkdtemp(base));
    char self[4096], installed[512], previous[520], package[512], original_package[512];
    assert(!fp_update_own_path(self, sizeof(self)));
    snprintf(installed, sizeof(installed), "%s/installed", base);
    snprintf(previous, sizeof(previous), "%s.old", installed);
    FILE *in = fopen(self, "rb"), *out = fopen(installed, "wb");
    assert(in && out);
    char data[65536];
    size_t bytes;
    while ((bytes = fread(data, 1, sizeof(data), in)) > 0)
        assert(fwrite(data, 1, bytes, out) == bytes);
    assert(!ferror(in) && !fclose(in) && !fclose(out) && !chmod(installed, 0755));

    assert(!fp_update_stage_path(original_package, sizeof(original_package)));
    assert(!strncmp(original_package, "/tmp/", 5));
    assert(!write_file(original_package, "not an executable"));
    run_install(installed, original_package, 42);
    assert(access(installed, X_OK) == 0 && access(previous, F_OK) != 0);
    assert(access(original_package, F_OK) != 0);

    assert(!fp_update_stage_path(package, sizeof(package)));
    char foreign[] = "/dev/shm/fp-update-package-XXXXXX";
#ifdef __linux__
    struct stat local, shared;
    if (!stat(base, &local) && !stat("/dev/shm", &shared) && local.st_dev != shared.st_dev) {
        int fd = mkstemp(foreign);
        if (fd >= 0) {
            close(fd);
            fp_update_discard(package);
            snprintf(package, sizeof(package), "%s", foreign);
        }
    }
#else
    (void)foreign;
#endif
    assert(!write_file(package, "#!/bin/sh\n"
        "if [ \"$1\" = \"--version\" ]; then echo 'fastp2p 2.0.31 ABI 1'; exit 0; fi\n"
        "exit 23\n"));
    run_install(installed, package, 23);
    assert(access(previous, X_OK) == 0 && access(package, F_OK) != 0);
    assert(!unlink(previous) && !unlink(installed) && !rmdir(base));
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "--update-fixture")) {
        char error[256];
        if (fp_update_apply(argv[2], error, sizeof(error))) {
            fp_update_discard(argv[2]);
            return 42;
        }
        return fp_update_run_pending(argv) ? 43 : 44;
    }
    swap_strategies();
    restart_from_staged_package();
    puts("POSIX atomic update and restart passed");
    return 0;
}
