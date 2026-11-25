#ifndef FASTP2P_SERVICE_UNIT_H
#define FASTP2P_SERVICE_UNIT_H

#include <stddef.h>

/* Unit rendering for the POSIX service managers.
 *
 * The client registers itself: there is no helper script beside the executable any
 * more, so the exact text handed to systemd, procd, OpenRC or launchd is the part
 * that breaks silently when a path or an option changes. Everything here is pure -
 * it takes the installed binary and the profile path and returns text - so the
 * content is covered by tests/test_service_unit.c instead of only by an install on
 * a real host. */

enum {
    FP_SERVICE_NONE = 0,
    FP_SERVICE_SYSTEMD,
    FP_SERVICE_PROCD,
    FP_SERVICE_OPENRC,
    FP_SERVICE_LAUNCHD,
};

/* "systemd" | "procd" | "openrc" | "launchd" -> kind, anything else -> NONE. */
int fp_service_kind(const char *name);
const char *fp_service_name(int kind);

/* Where the manager expects the unit. NULL for an unknown kind. */
const char *fp_service_unit_path(int kind);

/* The unit/plist text, malloc'd. NULL for an unknown kind or on allocation
 * failure; the caller frees it. */
char *fp_service_unit_text(int kind, const char *binary, const char *profile);

#endif
