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
       FP_TCP_MAP_UNPREDICTABLE, FP_TCP_MAP_DRIFT, FP_TCP_MAP_PBA_BLOCK };
typedef struct {
    int kind;
    uint8_t addr_only_dep;
    uint8_t confidence;
    uint16_t base_port;
    int32_t step;
    int16_t err_lo;
    int16_t err_hi;
    uint16_t block_lo;
    uint16_t block_hi;
    uint16_t block_size;
} fp_tcp_port_model;
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
/* One witness lookup. Injectable so a test can make it slow: the whole point of the worker
 * below is that a slow lookup costs the step loop nothing. */
typedef int (*fp_tcp_resolve_fn)(const char *host, uint16_t port, op_addr *out);
/* The resolver is one worker thread with an input and an output queue. Opaque here so the
 * platform's thread types stay out of this header. */
typedef struct fp_tcp_resolver fp_tcp_resolver;
#define FP_TCP_RESOLVE_QUEUE 32
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
    /* Witness names are resolved by one worker thread, because a single lookup can block for
     * the resolver's whole timeout and this loop also carries the control channel. prepared
     * stays 0 until every name of the current list has an answer. awaiting counts the names
     * still with the worker; resolving is the fallback walk used when no worker runs. */
    int resolving;
    unsigned resolve_index, resolved, awaiting;
    uint64_t next_resolve_at, resolve_cost;
    /* Parallel probing. Results are kept per target and appended in target order when the
     * batch ends, so neither the verdict nor the step calculation depends on the order the
     * replies happen to arrive in. inflight/peak_inflight are also the observable a test
     * uses to prove the probes really do overlap. */
    fp_tcp_slot slots[FP_TCP_PROBE_SLOTS];
    unsigned next_target, inflight, peak_inflight, held_count;
    op_addr cycle_mapped[FP_TCP_PROBE_MAX];
    unsigned char cycle_ok[FP_TCP_PROBE_MAX];
    uint64_t measured_at;
    uint64_t slot_timeout_ns;
    int sequential;
    uint8_t addr_only_dep;
} fp_tcp_family;
typedef struct {
    fp_stun_server servers[FP_TCP_STUN_MAX];
    unsigned server_count;
    fp_tcp_family family[OP_FAM_COUNT];
    /* The resolver worker, started with the first prepare and stopped by close. A platform
     * that cannot start one leaves this NULL and the families fall back to the incremental
     * walk, so a lookup is never lost - only its cost moves into the loop. */
    fp_tcp_resolver *resolver;
    fp_tcp_resolve_fn resolve;   /* NULL keeps the platform lookup */
    int inline_resolution;       /* tests only: exercise the fallback walk */
    /* How long the step call took. A tick that blocks and a session the gateway closes are
     * the same story told from two sides, and only the client can put a number on its half:
     * the peak and the count of slow calls go into the log next to a disconnect. */
    uint64_t step_last_ns, step_max_ns;
    unsigned step_slow;
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
/* Four-stage waterfall classifier (stable, constant step, monotone drift, PBA block). */
int fp_tcp_classify_ports(const uint16_t *ports, size_t n, uint8_t addr_only_dep,
                          fp_tcp_port_model *out);
/* Fresh parallel probe across each distinct mapped public IP (blade) seen in catalog. */
fp_tcp_family *fp_tcp_blade_sample_start(const fp_tcp_family *catalog, unsigned max_blades);
/* 0 while running, 1 on completion. */
int fp_tcp_blade_sample_step(fp_tcp_family *sample, uint64_t now);
/* Harvest any partial responses and close all held sockets on an early deadline. */
void fp_tcp_blade_sample_finish(fp_tcp_family *sample, uint64_t now);
/* -1 malformed, 0 incomplete, 1 complete. Exposed only to internal tests. */
int fp_tcp_stun_response(const uint8_t *data, size_t length, const uint8_t transaction[12],
                         struct sockaddr_in *mapped);
/* V3 echoes "addr:port" for IPv4 and "[addr]:port" for IPv6 (SPEC §3). */
int fp_tcp_echo_response(const uint8_t *data, size_t length, op_addr *mapped);
/* Test hooks: replace the lookup the worker performs, force the fallback walk, and ask
 * whether a worker is running. Production calls none of them. */
void fp_tcp_nat_set_resolver(fp_tcp_nat *state, fp_tcp_resolve_fn resolve);
void fp_tcp_nat_set_inline_resolution(fp_tcp_nat *state, int on);
int fp_tcp_nat_resolver_running(const fp_tcp_nat *state);
/* Step timing for the log: the latest call, the longest since the last reset, and how many
 * calls exceeded FP_TCP_STEP_SLOW_NS. Any pointer may be NULL. */
void fp_tcp_nat_step_stats(const fp_tcp_nat *state, uint64_t *last_ns, uint64_t *max_ns,
                           unsigned *slow);
/* Clears the peak and the counter, so one stall produces one log line. */
void fp_tcp_nat_step_stats_reset(fp_tcp_nat *state);
#define FP_TCP_STEP_SLOW_NS (200 * UINT64_C(1000000))
#endif
