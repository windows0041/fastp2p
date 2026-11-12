#include "tcp_nat.h"
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SECOND UINT64_C(1000000000)
static uint16_t be16(const uint8_t *p) { return (uint16_t)((unsigned)p[0] << 8 | p[1]); }
static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3]; }

int fp_tcp_stun_response(const uint8_t *p, size_t n, const uint8_t tid[12], struct sockaddr_in *out) {
    if (n < 20) return 0;
    size_t body = be16(p + 2);
    if (be16(p) != 0x0101 || be32(p + 4) != 0x2112a442 || memcmp(p + 8, tid, 12) ||
        (body & 3) || body > 1004) return -1;
    if (n < 20 + body) return 0;
    struct sockaddr_in mapped = {0}, plain = {0};
    int found = 0, plain_found = 0;
    for (size_t at = 20; at < 20 + body;) {
        if (20 + body - at < 4) return -1;
        unsigned type = be16(p + at), size = be16(p + at + 2);
        at += 4;
        size_t padded = ((size_t)size + 3) & ~(size_t)3;
        if (padded > 20 + body - at) return -1;
        if (type == 0x0020 || type == 0x0001) {
            if (size < 4 || p[at] != 0) return -1;
            if (p[at + 1] == 1) {
                if (size != 8) return -1;
                uint16_t port = be16(p + at + 2);
                uint32_t ip = be32(p + at + 4);
                if (type == 0x0020) { port ^= 0x2112; ip ^= 0x2112a442; }
                if (!port || !ip || ip == UINT32_MAX || (ip >> 28) == 14) return -1;
                struct sockaddr_in value = {.sin_family = AF_INET, .sin_port = htons(port),
                                             .sin_addr = {.s_addr = htonl(ip)}};
                if (type == 0x0020) {
                    if (found && (mapped.sin_port != value.sin_port || mapped.sin_addr.s_addr != value.sin_addr.s_addr)) return -1;
                    mapped = value; found = 1;
                } else { plain = value; plain_found = 1; }
            } else if (p[at + 1] != 2 || size != 20) return -1;
        }
        at += padded;
    }
    if (!found && !plain_found) return -1;
    *out = found ? mapped : plain;
    return 1;
}

void fp_tcp_nat_init(fp_tcp_nat *s) {
    memset(s, 0, sizeof(*s));
    s->fd = -1; s->type = FP_NAT_UNKNOWN;
    for (unsigned i = 0; i < FP_TCP_PROBE_MAX; ++i) s->held[i] = -1;
}
int fp_tcp_nat_configure(fp_tcp_nat *s, json_object *servers) {
    if (!servers) return 0;
    if (!json_object_is_type(servers, json_type_array) || json_object_array_length(servers) > FP_TCP_STUN_MAX) return -1;
    fp_stun_server parsed[FP_TCP_STUN_MAX] = {0};
    unsigned count = (unsigned)json_object_array_length(servers);
    for (unsigned i = 0; i < count; ++i) {
        json_object *entry = json_object_array_get_idx(servers, i);
        if (!json_object_is_type(entry, json_type_string)) return -1;
        const char *text = json_object_get_string(entry), *colon = strrchr(text, ':');
        size_t length = colon ? (size_t)(colon - text) : strlen(text);
        if (!length || length >= sizeof(parsed[i].host) || strlen(text) != (size_t)json_object_get_string_len(entry)) return -1;
        for (size_t k = 0; k < length; ++k) {
            unsigned char c = (unsigned char)text[k];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '-')) return -1;
        }
        unsigned port = 3478;
        if (colon) {
            if (!colon[1]) return -1;
            port = 0;
            for (const char *p = colon + 1; *p; ++p) {
                if (*p < '0' || *p > '9' || port > 6553) return -1;
                port = port * 10 + (unsigned)(*p - '0');
            }
            if (!port || port > 65535) return -1;
        }
        memcpy(parsed[i].host, text, length); parsed[i].port = (uint16_t)port;
    }
    memcpy(s->servers, parsed, sizeof(parsed)); s->server_count = count;
    return 0;
}
void fp_tcp_nat_close(fp_tcp_nat *s) {
    if (s->fd >= 0) op_close(s->fd);
    s->fd = -1;
    for (unsigned i = 0; i < FP_TCP_PROBE_MAX; ++i) {
        if (s->held[i] >= 0) op_close(s->held[i]);
        s->held[i] = -1;
    }
    s->phase = s->prepared = 0;
}
void fp_tcp_nat_prepare(fp_tcp_nat *s, const struct sockaddr_in *gateway) {
    fp_tcp_nat_close(s);
    s->target_count = 2; s->type = FP_NAT_UNKNOWN;
    s->samples = s->destinations = 0;
    for (unsigned i = 0; i < 2; ++i) {
        s->targets[i] = (fp_tcp_probe_target){.address = *gateway};
        s->targets[i].address.sin_port = htons((uint16_t)(27180 + i));
    }
    for (unsigned i = 0; i < s->server_count; ++i) {
        struct addrinfo hints = {0}, *addresses = NULL;
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(s->servers[i].host, NULL, &hints, &addresses)) continue;
        struct sockaddr_in address = *(struct sockaddr_in *)addresses->ai_addr;
        freeaddrinfo(addresses);
        address.sin_port = htons(s->servers[i].port);
        int duplicate = 0;
        for (unsigned k = 0; k < s->target_count; ++k)
            if (s->targets[k].address.sin_addr.s_addr == address.sin_addr.s_addr &&
                s->targets[k].address.sin_port == address.sin_port) duplicate = 1;
        if (!duplicate) s->targets[s->target_count++] = (fp_tcp_probe_target){.address = address, .stun = 1};
    }
    s->next_cycle = 0; s->prepared = 1;
}
static int connected(op_socket fd) {
    op_pollfd poll = {.fd = fd, .events = POLLOUT};
    int ready = op_poll(&poll, 1, 0);
    if (ready <= 0) return ready;
    int error = 0; op_socklen length = sizeof(error);
    if (op_getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) || error) return -1;
    return 1;
}
static void next_target(fp_tcp_nat *s, const struct sockaddr_in *mapped) {
    if (mapped) {
        int known_ip = 0;
        for (unsigned i = 0; i < s->collected; ++i)
            if (s->sample_ips[i] == s->targets[s->index].address.sin_addr.s_addr) known_ip = 1;
        if (!known_ip) ++s->collected_ips;
        s->sample_ips[s->collected] = s->targets[s->index].address.sin_addr.s_addr;
        s->mapped[s->collected++] = *mapped;
    }
    /* Keep the bound source port owned for the entire batch, including when
     * another endpoint times out. Connections use distinct remote tuples. */
    s->held[s->index++] = s->fd; s->fd = -1;
    s->phase = 1;
}
int fp_tcp_echo_response(const uint8_t *p, size_t n, struct sockaddr_in *out) {
    const uint8_t *end = memchr(p, '\n', n);
    if (!end) return n < 95 ? 0 : -1;
    char text[96], ip[INET_ADDRSTRLEN]; unsigned port = 0;
    size_t length = (size_t)(end - p);
    if (length >= sizeof(text) || memchr(p, 0, length)) return -1;
    memcpy(text, p, length); text[length] = 0;
    char *colon = strchr(text, ':');
    if (!colon || colon == text || (size_t)(colon - text) >= sizeof(ip) || !colon[1]) return -1;
    memcpy(ip, text, (size_t)(colon - text)); ip[colon - text] = 0;
    for (const char *digit = colon + 1; *digit; ++digit) {
        if (*digit < '0' || *digit > '9' || port > 6553) return -1;
        port = port * 10 + (unsigned)(*digit - '0');
    }
    if (!port || port > 65535) return -1;
    *out = (struct sockaddr_in){.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    return inet_pton(AF_INET, ip, &out->sin_addr) == 1 && out->sin_addr.s_addr ? 1 : -1;
}
int fp_tcp_nat_step(fp_tcp_nat *s, uint64_t now) {
    if (!s->prepared) return 0;
    if (!s->phase) {
        if (now < s->next_cycle) return 0;
        s->phase = 1; s->index = s->collected = s->collected_ips = 0; s->source_port = 0;
    }
    if (s->index == s->target_count) {
        s->samples = s->collected; s->destinations = s->collected_ips;
        s->type = FP_NAT_UNKNOWN;
        if (s->samples >= 2) {
            s->type = FP_NAT_STABLE;
            for (unsigned i = 1; i < s->samples; ++i)
                if (s->mapped[i].sin_addr.s_addr != s->mapped[0].sin_addr.s_addr ||
                    s->mapped[i].sin_port != s->mapped[0].sin_port) s->type = FP_NAT_DEPENDENT;
        }
        for (unsigned i = 0; i < FP_TCP_PROBE_MAX; ++i) {
            if (s->held[i] >= 0) op_close(s->held[i]);
            s->held[i] = -1;
        }
        s->phase = 0; s->next_cycle = now + (s->type == FP_NAT_UNKNOWN ? 30 : 600) * SECOND;
        return 1;
    }
    if (s->phase == 1) {
        s->fd = op_socket_open(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in bind = {.sin_family = AF_INET, .sin_port = htons(s->source_port)};
        if (s->fd < 0 || op_reuse_socket(s->fd) || op_bind(s->fd, (struct sockaddr *)&bind, sizeof(bind))) {
            next_target(s, NULL); return 0;
        }
        op_socklen length = sizeof(bind);
        if (op_getsockname(s->fd, (struct sockaddr *)&bind, &length)) { next_target(s, NULL); return 0; }
        s->source_port = ntohs(bind.sin_port);
        memset(s->request, 0, sizeof(s->request));
        if (s->targets[s->index].stun) {
            s->request[1] = 1; s->request[4] = 0x21; s->request[5] = 0x12;
            s->request[6] = 0xa4; s->request[7] = 0x42;
            if (RAND_bytes(s->request + 8, 12) != 1) { next_target(s, NULL); return 0; }
            s->request_length = 20;
        } else { s->request[0] = '2'; s->request_length = 1; }
        s->sent = s->received = 0; s->deadline = now + 2 * SECOND; s->phase = 2;
        if (op_connect(s->fd, (struct sockaddr *)&s->targets[s->index].address, sizeof(bind)) && errno != EINPROGRESS)
            next_target(s, NULL);
        return 0;
    }
    if (now >= s->deadline) { next_target(s, NULL); return 0; }
    if (s->phase == 2) {
        int ready = connected(s->fd);
        if (ready < 0) { next_target(s, NULL); return 0; }
        if (!ready) return 0;
        s->phase = 3;
    }
    if (s->phase == 3) {
        op_ssize sent = op_send(s->fd, s->request + s->sent, s->request_length - s->sent, MSG_NOSIGNAL);
        if (sent > 0) s->sent += (size_t)sent;
        else if (!sent || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) { next_target(s, NULL); return 0; }
        if (s->sent != s->request_length) return 0;
        s->phase = 4;
    }
    op_ssize received = op_recv(s->fd, s->response + s->received, sizeof(s->response) - s->received, MSG_DONTWAIT);
    if (received > 0) s->received += (size_t)received;
    else if (!received || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) { next_target(s, NULL); return 0; }
    struct sockaddr_in mapped;
    int parsed = s->targets[s->index].stun ? fp_tcp_stun_response(s->response, s->received, s->request + 8, &mapped)
                                          : fp_tcp_echo_response(s->response, s->received, &mapped);
    if (parsed || s->received == sizeof(s->response)) next_target(s, parsed > 0 ? &mapped : NULL);
    return 0;
}
