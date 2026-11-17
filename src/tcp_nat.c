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

/* Every v6 socket we bind explicitly is v6-only. Linux defaults to
 * bindv6only=0, where a "::" listener occupies the same port in the IPv4 space
 * and would collide with the sibling v4 listener on the very same port. */
static void v6_only(op_socket fd, int family) {
    if (family != OP_FAM_V6) return;
    int one = 1;
    op_setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
}

static void family_close(fp_tcp_family *k) {
    if (k->fd >= 0) op_close(k->fd);
    k->fd = -1;
    for (unsigned i = 0; i < FP_TCP_PROBE_MAX; ++i) {
        if (k->held[i] >= 0) op_close(k->held[i]);
        k->held[i] = -1;
    }
    k->phase = 0;
    k->prepared = 0;
}
void fp_tcp_nat_init(fp_tcp_nat *s) {
    memset(s, 0, sizeof(*s));
    for (int f = 0; f < OP_FAM_COUNT; ++f) {
        fp_tcp_family *k = &s->family[f];
        k->fd = -1;
        k->type = FP_NAT_UNKNOWN;
        for (unsigned i = 0; i < FP_TCP_PROBE_MAX; ++i) k->held[i] = -1;
    }
}
/* The server list is family-independent configuration text; resolution happens
 * in fp_tcp_nat_prepare, where the family's gateway address is known. */
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
    for (int f = 0; f < OP_FAM_COUNT; ++f)
        family_close(&s->family[f]);
}
/* One family's target list: the two gateway probe ports of that family, plus
 * the configured STUN servers for IPv4 only (their text syntax is v4). */
static void family_prepare(fp_tcp_family *k, const op_addr *gateway, int index,
                           const fp_stun_server *servers, unsigned count) {
    k->samples = k->destinations = 0;
    k->next_cycle = 0;
    k->type = FP_NAT_UNKNOWN;
    k->prepared = 0;
    k->target_count = 0;
    if (!gateway || !gateway->len || op_family_index(op_addr_family(gateway)) != index)
        return;
    for (unsigned i = 0; i < 2; ++i) {
        memset(&k->targets[i], 0, sizeof(k->targets[i]));
        op_addr_copy(&k->targets[i].address, gateway);
        op_addr_set_port(&k->targets[i].address, (uint16_t)(27180 + i));
        k->targets[i].stun = 0;
    }
    k->target_count = 2;
    if (index == OP_FAM_V4) {
        for (unsigned i = 0; i < count && k->target_count < FP_TCP_PROBE_MAX; ++i) {
            struct addrinfo hints = {0}, *addresses = NULL;
            hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(servers[i].host, NULL, &hints, &addresses)) continue;
            op_addr resolved;
            memset(&resolved, 0, sizeof(resolved));
            resolved.len = (op_socklen)addresses->ai_addrlen;
            if (resolved.len > (op_socklen)sizeof(resolved.u.storage))
                resolved.len = (op_socklen)sizeof(resolved.u.storage);
            memcpy(&resolved.u.storage, addresses->ai_addr, resolved.len);
            freeaddrinfo(addresses);
            op_addr_set_port(&resolved, servers[i].port);
            int duplicate = 0;
            for (unsigned q = 0; q < k->target_count; ++q)
                if (op_addr_equal(&resolved, &k->targets[q].address) &&
                    op_addr_port(&resolved) == op_addr_port(&k->targets[q].address))
                    duplicate = 1;
            if (!duplicate)
                k->targets[k->target_count++] =
                    (fp_tcp_probe_target){.address = resolved, .stun = 1};
        }
    }
    k->prepared = 1;
}
void fp_tcp_nat_prepare(fp_tcp_nat *s, const op_addr gateway[OP_FAM_COUNT], int families) {
    fp_tcp_nat_close(s);
    for (int f = 0; f < OP_FAM_COUNT; ++f) {
        fp_tcp_family *k = &s->family[f];
        if (!(families & (1 << f)))
            continue;
        family_prepare(k, &gateway[f], f, s->servers, s->server_count);
    }
}
static int connected(op_socket fd) {
    op_pollfd poll = {.fd = fd, .events = POLLOUT};
    int ready = op_poll(&poll, 1, 0);
    if (ready <= 0) return ready;
    int error = 0; op_socklen length = sizeof(error);
    if (op_getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) || error) return -1;
    return 1;
}
static void next_target(fp_tcp_family *k, const op_addr *mapped) {
    if (mapped) {
        int known_ip = 0;
        for (unsigned i = 0; i < k->collected; ++i)
            if (op_addr_equal(&k->target_used[i], &k->targets[k->index].address)) known_ip = 1;
        if (!known_ip) ++k->collected_ips;
        k->target_used[k->collected] = k->targets[k->index].address;
        k->mapped[k->collected++] = *mapped;
    }
    /* Keep the bound source port owned for the entire batch, including when
     * another endpoint times out. Connections use distinct remote tuples. */
    k->held[k->index++] = k->fd; k->fd = -1;
    k->phase = 1;
}
int fp_tcp_echo_response(const uint8_t *p, size_t n, op_addr *out) {
    const uint8_t *end = memchr(p, '\n', n);
    if (!end) return n < 95 ? 0 : -1;
    size_t length = (size_t)(end - p);
    if (length >= 96 || memchr(p, 0, length)) return -1;
    char text[96], address[INET6_ADDRSTRLEN + 1];
    memcpy(text, p, length); text[length] = 0;
    const char *ip, *port_text;
    if (text[0] == '[') {
        /* SPEC §3 probeV3: an IPv6 echo record is bracketed so the address and
         * port boundary is unambiguous. */
        const char *close = strchr(text, ']');
        if (!close || close == text + 1 || close[1] != ':') return -1;
        size_t used = (size_t)(close - text - 1);
        if (used >= sizeof(address)) return -1;
        memcpy(address, text + 1, used); address[used] = 0;
        ip = address;
        port_text = close + 2;
    } else {
        const char *colon = strchr(text, ':');
        if (!colon || colon == text) return -1;
        size_t used = (size_t)(colon - text);
        if (used >= sizeof(address)) return -1;
        memcpy(address, text, used); address[used] = 0;
        ip = address;
        port_text = colon + 1;
    }
    unsigned port = 0;
    if (!*port_text) return -1;
    for (const char *digit = port_text; *digit; ++digit) {
        if (*digit < '0' || *digit > '9' || port > 6553) return -1;
        port = port * 10 + (unsigned)(*digit - '0');
    }
    if (!port || port > 65535) return -1;
    op_addr parsed;
    if (op_addr_from_text(&parsed, ip, (uint16_t)port)) return -1;
    if (op_addr_family(&parsed) == AF_INET) {
        if (!parsed.u.in.sin_addr.s_addr) return -1; /* the old 0.0.0.0 rejection */
    } else {
        static const uint8_t unspecified[16] = {0};
        if (!memcmp(parsed.u.in6.sin6_addr.s6_addr, unspecified, sizeof(unspecified))) return -1;
    }
    *out = parsed;
    return 1;
}
/* One request/reply step of a family's TCP mapping discovery. The sequence is
 * the old single-family one (bound source port held for the whole batch, one
 * marker byte per probe, quiet-period boundary for legacy echoes), just
 * repeated for the second family. */
static int family_step(fp_tcp_family *k, int family, uint64_t now) {
    if (!k->prepared) return 0;
    if (!k->phase) {
        if (now < k->next_cycle) return 0;
        k->phase = 1; k->index = k->collected = k->collected_ips = 0; k->source_port = 0;
    }
    if (k->index == k->target_count) {
        k->samples = k->collected; k->destinations = k->collected_ips;
        k->type = FP_NAT_UNKNOWN;
        if (k->samples >= 2) {
            k->type = FP_NAT_STABLE;
            for (unsigned i = 1; i < k->samples; ++i)
                if (op_addr_port(&k->mapped[i]) != op_addr_port(&k->mapped[0]) ||
                    !op_addr_equal(&k->mapped[i], &k->mapped[0])) k->type = FP_NAT_DEPENDENT;
        }
        for (unsigned i = 0; i < FP_TCP_PROBE_MAX; ++i) {
            if (k->held[i] >= 0) op_close(k->held[i]);
            k->held[i] = -1;
        }
        k->phase = 0; k->next_cycle = now + (k->type == FP_NAT_UNKNOWN ? 30 : 600) * SECOND;
        return 1;
    }
    if (k->phase == 1) {
        op_addr bind_to;
        memset(&bind_to, 0, sizeof(bind_to));
        if (op_addr_from_text(&bind_to, family == OP_FAM_V6 ? "::" : "0.0.0.0", k->source_port)) {
            next_target(k, NULL);
            return 0;
        }
        k->fd = op_socket_open(op_index_family(family), SOCK_STREAM, 0);
        v6_only(k->fd, family);
        if (k->fd < 0 || op_reuse_socket(k->fd) || op_bind(k->fd, &bind_to.u.sa, bind_to.len)) {
            if (k->fd >= 0) { op_close(k->fd); k->fd = -1; }
            next_target(k, NULL); return 0;
        }
        op_addr bound;
        if (op_addr_socketname(k->fd, &bound)) { next_target(k, NULL); return 0; }
        k->source_port = op_addr_port(&bound);
        memset(k->request, 0, sizeof(k->request));
        if (k->targets[k->index].stun) {
            k->request[1] = 1; k->request[4] = 0x21; k->request[5] = 0x12;
            k->request[6] = 0xa4; k->request[7] = 0x42;
            if (RAND_bytes(k->request + 8, 12) != 1) { next_target(k, NULL); return 0; }
            k->request_length = 20;
        } else { k->request[0] = '2'; k->request_length = 1; }
        k->sent = k->received = 0; k->deadline = now + 2 * SECOND; k->phase = 2;
        if (op_connect(k->fd, &k->targets[k->index].address.u.sa,
                       k->targets[k->index].address.len) && errno != EINPROGRESS)
            next_target(k, NULL);
        return 0;
    }
    if (now >= k->deadline) { next_target(k, NULL); return 0; }
    if (k->phase == 2) {
        int ready = connected(k->fd);
        if (ready < 0) { next_target(k, NULL); return 0; }
        if (!ready) return 0;
        k->phase = 3;
    }
    if (k->phase == 3) {
        op_ssize sent = op_send(k->fd, k->request + k->sent, k->request_length - k->sent, MSG_NOSIGNAL);
        if (sent > 0) k->sent += (size_t)sent;
        else if (!sent || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) { next_target(k, NULL); return 0; }
        if (k->sent != k->request_length) return 0;
        k->phase = 4;
    }
    op_ssize received = op_recv(k->fd, k->response + k->received, sizeof(k->response) - k->received, MSG_DONTWAIT);
    if (received > 0) k->received += (size_t)received;
    else if (!received || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) { next_target(k, NULL); return 0; }
    op_addr mapped;
    memset(&mapped, 0, sizeof(mapped));
    int parsed;
    if (k->targets[k->index].stun) {
        struct sockaddr_in mapped4;
        memset(&mapped4, 0, sizeof(mapped4));
        parsed = fp_tcp_stun_response(k->response, k->received, k->request + 8, &mapped4);
        if (parsed > 0) {
            memset(&mapped, 0, sizeof(mapped));
            mapped.u.in = mapped4;
            mapped.len = (op_socklen)sizeof(mapped4);
        }
    } else {
        op_addr echo;
        parsed = fp_tcp_echo_response(k->response, k->received, &echo);
        /* A probe only samples its own family; an echo of the other family (or
         * of a legacy gateway with different framing) is not a sample. */
        if (parsed > 0 && op_family_index(op_addr_family(&echo)) != family) parsed = -1;
        if (parsed > 0) mapped = echo;
    }
    if (parsed || k->received == sizeof(k->response)) next_target(k, parsed > 0 ? &mapped : NULL);
    return 0;
}
int fp_tcp_nat_step(fp_tcp_nat *s, uint64_t now) {
    int done = 0;
    for (int f = 0; f < OP_FAM_COUNT; ++f)
        if (family_step(&s->family[f], f, now)) done |= 1 << f;
    return done;
}
