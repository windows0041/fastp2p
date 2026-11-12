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
    struct sockaddr_in address;
    int stun;
} fp_tcp_probe_target;
typedef struct {
    fp_stun_server servers[FP_TCP_STUN_MAX];
    unsigned server_count, target_count, index, samples, destinations;
    unsigned collected, collected_ips;
    unsigned type;
    fp_tcp_probe_target targets[FP_TCP_PROBE_MAX];
    struct sockaddr_in mapped[FP_TCP_PROBE_MAX];
    uint32_t sample_ips[FP_TCP_PROBE_MAX];
    op_socket fd, held[FP_TCP_PROBE_MAX];
    uint16_t source_port;
    int phase, prepared;
    uint64_t deadline, next_cycle;
    uint8_t request[20], response[1024];
    size_t sent, request_length, received;
} fp_tcp_nat;

void fp_tcp_nat_init(fp_tcp_nat *state);
/* Parse only; DNS is resolved at client start, never in the step loop. */
int fp_tcp_nat_configure(fp_tcp_nat *state, json_object *servers);
void fp_tcp_nat_prepare(fp_tcp_nat *state, const struct sockaddr_in *gateway);
/* Returns 1 when a fresh observation is ready to report. Never blocks. */
int fp_tcp_nat_step(fp_tcp_nat *state, uint64_t now);
void fp_tcp_nat_close(fp_tcp_nat *state);
/* -1 malformed, 0 incomplete, 1 complete. Exposed only to internal tests. */
int fp_tcp_stun_response(const uint8_t *data, size_t length, const uint8_t transaction[12],
                         struct sockaddr_in *mapped);
int fp_tcp_echo_response(const uint8_t *data, size_t length, struct sockaddr_in *mapped);
#endif
