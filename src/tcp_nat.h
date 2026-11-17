#ifndef FASTP2P_TCP_NAT_H
#define FASTP2P_TCP_NAT_H
#include "platform.h"
#include <json-c/json.h>

/* These are mapping observations, never a claim about inbound filtering. */
enum { FP_NAT_STABLE = 1, FP_NAT_DEPENDENT = 2, FP_NAT_UNKNOWN = 314 };
#define FP_TCP_STUN_MAX 4
#define FP_TCP_PROBE_MAX (2 + FP_TCP_STUN_MAX)
typedef struct {
    char host[254];
    uint16_t port;
} fp_stun_server;
typedef struct {
    op_addr address;
    int stun;
} fp_tcp_probe_target;
/* One family's TCP mapping discovery. DUALSTACK-SPEC §3/§4: the identical
 * sequence runs once per family, against that family's gateway probe ports, so
 * the IPv4 slot holds exactly the values the old single-family state did. */
typedef struct {
    unsigned target_count, index, samples, destinations;
    unsigned collected, collected_ips;
    unsigned type;
    fp_tcp_probe_target targets[FP_TCP_PROBE_MAX];
    op_addr mapped[FP_TCP_PROBE_MAX];
    /* Destination endpoints sampled in this cycle, for the distinct-IP count. */
    op_addr target_used[FP_TCP_PROBE_MAX];
    op_socket fd, held[FP_TCP_PROBE_MAX];
    uint16_t source_port;
    int phase, prepared;
    uint64_t deadline, next_cycle;
    uint8_t request[20], response[1024];
    size_t sent, request_length, received;
} fp_tcp_family;
typedef struct {
    fp_stun_server servers[FP_TCP_STUN_MAX];
    unsigned server_count;
    fp_tcp_family family[OP_FAM_COUNT];
} fp_tcp_nat;

void fp_tcp_nat_init(fp_tcp_nat *state);
/* Parse only; DNS is resolved at client start, never in the step loop. */
int fp_tcp_nat_configure(fp_tcp_nat *state, json_object *servers);
/* Start the probe set for every family in `families` that has a resolved
 * gateway endpoint of that family. IPv4 keeps the historical target list
 * (gateway 27180/27181 first, then configured STUN servers); IPv6 uses the
 * gateway's own probe ports. A v4-only gateway prepares one v4 family. */
void fp_tcp_nat_prepare(fp_tcp_nat *state, const op_addr gateway[OP_FAM_COUNT], int families);
/* Returns a FAM_* bitmap of the families that completed a fresh observation. */
int fp_tcp_nat_step(fp_tcp_nat *state, uint64_t now);
void fp_tcp_nat_close(fp_tcp_nat *state);
/* -1 malformed, 0 incomplete, 1 complete. Exposed only to internal tests. */
int fp_tcp_stun_response(const uint8_t *data, size_t length, const uint8_t transaction[12],
                         struct sockaddr_in *mapped);
/* V3 echoes "addr:port" for IPv4 and "[addr]:port" for IPv6 (SPEC §3). */
int fp_tcp_echo_response(const uint8_t *data, size_t length, op_addr *mapped);
#endif
