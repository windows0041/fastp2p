#ifndef FASTP2P_FIREWALL_H
#define FASTP2P_FIREWALL_H

#include <stddef.h>

/* Host firewall helpers.
 *
 * The peer listener and the overlay interface carry traffic no connection opened from
 * this side: a symmetric NAT test, a hole-punch probe from a peer, or a packet written
 * into the TUN for this node's own overlay address. Every desktop firewall drops that
 * by default, and each platform needs a different command to allow it, so the client
 * asks here once per start and reports what happened.
 *
 * All calls are best effort: they never fail the client, and they are idempotent - a
 * fixed rule name is replaced instead of accumulated when the port changes. */

enum {
    FP_FIREWALL_OK = 0,      /* the host now allows the traffic */
    FP_FIREWALL_ABSENT,      /* no firewall tool found on this host */
    FP_FIREWALL_DENIED,      /* the tool refused: not root, policy, Android sandbox */
};

/* Hole punching listens on a port the operating system picks, so a rule that names the
 * service port blocks every punch packet that arrives. Linux has no way to allow a
 * program on the input path (the owner match only exists on output), so the client keeps
 * its punch sockets inside this range and the firewall allows exactly the range. Windows
 * gets both a range rule and a program rule; macOS filters per binary already. */
#define FP_PUNCH_PORT_FIRST 40000
#define FP_PUNCH_PORT_LAST 40999

/* Render the commands the current platform would run. Exposed for tests: the exact
 * arguments are the part that breaks silently when a port or a rule name changes. */
int fp_firewall_commands(unsigned port, int udp, const char *tun,
                         char *out, size_t length);

/* Allow inbound peer traffic on `port` (TCP always, UDP when `udp`), then the overlay
 * interface when `tun` is not NULL. Writes a short human-readable note into
 * `detail` so the caller can log it once. */
int fp_firewall_open(unsigned port, int udp, const char *tun,
                     char *detail, size_t detail_length);

#endif
