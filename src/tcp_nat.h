#ifndef FASTP2P_TCP_NAT_H
#define FASTP2P_TCP_NAT_H
#include "platform.h"
#include <json-c/json.h>

/* These are mapping observations, never a claim about inbound filtering. */
enum { FP_NAT_STABLE = 1, FP_NAT_DEPENDENT = 2, FP_NAT_UNKNOWN = 314 };
/* FP_TCP_MAP_UNPREDICTABLE says "my mapping moves per destination and no constant
 * step was measurable, but the port I just measured is where my allocator is now".
 * It exists so the other side can aim its spray at a recent observation instead of
 * at the port the gateway measured minutes ago, which on a monotone allocator is
 * thousands of ports behind. Older peers reject the value and keep treating the
 * peer as unknown, which is exactly what they do today. */
enum { FP_TCP_MAP_NONE, FP_TCP_MAP_STABLE, FP_TCP_MAP_INCREMENT, FP_TCP_MAP_DECREMENT,
       FP_TCP_MAP_UNPREDICTABLE };
#define FP_TCP_STUN_MAX 32
#define FP_TCP_PROBE_MAX (2 + FP_TCP_STUN_MAX)
typedef struct {
    char host[254];
    uint16_t port;
} fp_stun_server;
typedef struct {
    op_addr address;
    int stun;
} fp_tcp_probe_target;
/* How many probes may be in flight at once. Each one costs a TCP handshake to a different
 * witness, and the batch is what a witness list needs: six in parallel finish in the time
 * one used to take, without ever blocking the step loop that also drives the control
 * channel. */
#define FP_TCP_PROBE_SLOTS 6
/* One in-flight probe: the same four stages the single-socket probe ran, per slot. */
typedef struct {
    op_socket fd;
    int target;                 /* index into targets[], -1 when the slot is free */
    int phase;                  /* 2 connecting, 3 sending, 4 receiving */
    uint8_t request[20];
    uint8_t response[1024];
    size_t request_length, sent, received;
    uint64_t deadline;
} fp_tcp_slot;
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
    op_addr source;
    uint16_t source_port;
    /* Every probe binds a fresh local port: with one destination per probe the
     * differences between the observed ports are the allocator's own step. */
    int fresh_source;
    int phase, prepared;
    uint64_t next_cycle;
    /* Witness names are resolved one per step call, spaced out: a lookup blocks this
     * single-threaded loop, and the loop also carries the control channel. prepared stays 0
     * until the walk is done, so the probe ladder never starts on a half-built target list.
     * resolve_cost is how long the last lookup took, which widens the spacing. */
    int resolving;
    unsigned resolve_index, resolved;
    uint64_t next_resolve_at, resolve_cost;
    /* Parallel probing. Results are kept per target and appended in target order when the
     * batch ends, so neither the verdict nor the step calculation depends on the order the
     * replies happen to arrive in. inflight/peak_inflight are also the observable a test
     * uses to prove the probes really do overlap. */
    fp_tcp_slot slots[FP_TCP_PROBE_SLOTS];
    unsigned next_target, inflight, peak_inflight, held_count;
    op_addr cycle_mapped[FP_TCP_PROBE_MAX];
    unsigned char cycle_ok[FP_TCP_PROBE_MAX];
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
/* Optional tunnel samples reuse the exact source of the first gateway echo. */
fp_tcp_family *fp_tcp_punch_sample_start(const fp_tcp_family *catalog, const op_addr *source,
                                       const op_addr *first_mapping);
/* 0 while running, 1 on completion. Ports come from the last successful sample. */
int fp_tcp_punch_sample_step(fp_tcp_family *sample, uint64_t now, unsigned *mapping, uint16_t *port);
void fp_tcp_punch_sample_free(fp_tcp_family *sample);
/* Allocation sampling: the same destination probed from a fresh local port each
 * time. A destination-dependent (NAT4) peer's next allocation is predicted from
 * the step between those samples, which is what the punching side dials. */
fp_tcp_family *fp_tcp_alloc_sample_start(const op_addr *gateway, unsigned count);
/* 0 while running, 1 on completion; step 0 means no constant step was seen. */
int fp_tcp_alloc_sample_step(fp_tcp_family *sample, uint64_t now, int *step, uint16_t *port);
/* -1 no usable sample, 0 no constant step, 1 constant step found. */
int fp_tcp_alloc_delta(const op_addr *mapped, unsigned count, int *step, uint16_t *port);
/* -1 malformed, 0 incomplete, 1 complete. Exposed only to internal tests. */
int fp_tcp_stun_response(const uint8_t *data, size_t length, const uint8_t transaction[12],
                         struct sockaddr_in *mapped);
/* V3 echoes "addr:port" for IPv4 and "[addr]:port" for IPv6 (SPEC §3). */
int fp_tcp_echo_response(const uint8_t *data, size_t length, op_addr *mapped);
#endif
