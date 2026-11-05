#ifndef FASTP2P_UPDATE_H
#define FASTP2P_UPDATE_H
#include <stddef.h>
#include <stdint.h>

/* Self-update support. The gateway hosts the packages and pushes an order over
 * the authenticated control channel; the client verifies the digest before it
 * touches its own executable. */

/* Downloads url into dest while hashing it, and fails unless the digest and the
 * byte count match what the gateway announced. Returns 0 on success. */
int fp_update_download(const char *url, const char *ca, const char *dest,
                       const char *expect_sha, uint64_t expect_size,
                       char *error, size_t error_length);

/* Path of the running executable, written into out. Returns 0 on success. */
int fp_update_own_path(char *out, size_t length);

/* Android cannot replace its own package, so the app tells the library where to
 * stage downloads instead. Ignored on other platforms. */
void fp_update_set_dir(const char *dir);

/* Path to stage a download into: same directory as the executable so the final
 * rename is atomic. Returns 0 on success. */
int fp_update_stage_path(char *out, size_t length);

/* Replaces the running executable with staged and arranges the restart.
 * On Windows a detached helper is spawned immediately. On POSIX the package is
 * only recorded here; call fp_update_run_pending once the event loop has exited
 * so the swap happens after a clean shutdown.
 * Returns 0 when the caller should stop. */
int fp_update_apply(const char *staged, char *error, size_t error_length);

/* POSIX: performs a deferred install. Does not return on success. A no-op when
 * nothing is pending or on Windows. */
int fp_update_run_pending(char *const argv[]);

/* CLI maintenance after a verified, stable startup. Removes only retired
 * images and staging files belonging to exited updater processes. */
void fp_update_cleanup(void);

/* Detached-helper entry point: waits for the old image to be released, installs
 * staged over target, then restarts the service. */
int fp_update_swap(const char *staged, const char *target, const char *service);

#ifdef _WIN32
#include <wchar.h>
/* Internal Windows helper: wait for a stopped process to release its image. */
int fp_update_replace_file(const wchar_t *source, const wchar_t *target);
#endif

#endif
