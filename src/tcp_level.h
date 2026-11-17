#ifndef FASTP2P_TCP_LEVEL_H
#define FASTP2P_TCP_LEVEL_H
#include "platform.h"
#include <json-c/json.h>
#include <stddef.h>
#include <stdint.h>

/* TCP NAT filtering probe.
 *
 * STUN's CHANGE-REQUEST does not exist for TCP, so the filter is measured with a
 * real callback SYN: this side dials out from a local port (which creates the
 * mapping) and keeps listening on that same port, while a probe server answers
 * with the mapping and then opens a new connection to it - first from another
 * source port on the same address, then from its other public address.
 *
 *   both callbacks accepted -> 1 (nothing outside the tuple is filtered)
 *   only the same-address   -> 2 (address restricted)
 *   neither                 -> 3 (port restricted)
 *   0                        -> no verdict
 *
 * A per-destination mapping makes the answer 4 regardless; that is decided by the
 * caller, which already measures the mapping. */
typedef struct {
    int phase; /* 0 idle, 1 connecting, 2 greeting, 3 probing, 4 done */
    op_addr server;    /* resolved when the probe starts */
    char host[254];    /* configured text, resolved in start() */
    uint16_t server_port;
    op_socket listener, dialer;
    uint16_t local_port;
    uint64_t deadline;
    char line[96];
    size_t used;
    int accepted;
    int same_port, other_ip; /* 1 = the server reported that callback succeeded */
    int answered;            /* the server returned a verdict line */
    int attempt;             /* one retry with a fresh local port */
    int level;
} fp_tcp_level;

/* Parses {"Probe": "host:port"} - a single probe server, optional. */
int fp_tcp_level_configure(fp_tcp_level *state, const char *text);
void fp_tcp_level_start(fp_tcp_level *state);
void fp_tcp_level_step(fp_tcp_level *state, uint64_t now);
void fp_tcp_level_close(fp_tcp_level *state);
#endif
