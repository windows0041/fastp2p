#ifndef FASTP2P_LOG_ROTATION_H
#define FASTP2P_LOG_ROTATION_H
#include <stdint.h>
#ifdef _WIN32
#include <wchar.h>
#endif

/* Bound a runtime log without buffering it in memory: once `path` reaches
 * `rotate_at` bytes, replace it with its newest `keep` bytes, starting on a
 * line boundary. The caller keeps writing to the returned descriptor.
 *
 * Returns an open append descriptor for the trimmed file (the caller owns it),
 * 0 when nothing needed to be done, or -1 when the log could not be rewritten.
 * The copy uses one fixed 16 KiB buffer, so small devices never need memory
 * proportional to the log size. */
int fp_log_trim(const char *path, uint64_t rotate_at, uint64_t keep);
#ifdef _WIN32
int fp_log_trim_wide(const wchar_t *path, uint64_t rotate_at, uint64_t keep);
#endif
#endif
