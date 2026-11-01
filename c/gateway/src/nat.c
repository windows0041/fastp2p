#include "gateway.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int bound(const char *ip, unsigned port, int udp) {
    int fd = socket(AF_INET, (udp ? SOCK_DGRAM : SOCK_STREAM) | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1 || bind(fd, (struct sockaddr *)&a, sizeof(a)) ||
        (!udp && listen(fd, 64))) {
        close(fd);
        return -1;
    }
    return fd;
}
void gw_nat_stop(struct nat_state *s) {
    for (int i = 0; i < 4; ++i)
        if (s->udp[i] >= 0) {
            close(s->udp[i]);
            s->udp[i] = -1;
        }
    for (int i = 0; i < 2; ++i)
        if (s->tcp[i] >= 0) {
            close(s->tcp[i]);
            s->tcp[i] = -1;
        }
    for (int i = 0; i < GW_MAX_PROBES; ++i)
        if (s->probes[i].fd >= 0) {
            close(s->probes[i].fd);
            s->probes[i].fd = -1;
        }
}
int gw_nat_start(struct nat_state *s, const char *ip) {
    memset(s, 0, sizeof(*s));
    for (int i = 0; i < 4; ++i)
        s->udp[i] = -1;
    for (int i = 0; i < 2; ++i)
        s->tcp[i] = -1;
    for (int i = 0; i < GW_MAX_PROBES; ++i)
        s->probes[i].fd = -1;
    for (int i = 0; i < 4; ++i)
        if ((s->udp[i] = bound(ip, 27180 + (unsigned)i, 1)) < 0)
            goto error;
    for (int i = 0; i < 2; ++i)
        if ((s->tcp[i] = bound(ip, 27180 + (unsigned)i, 0)) < 0)
            goto error;
    return 0;
error:
    gw_nat_stop(s);
    return -1;
}
static void udp_step(struct nat_state *s, int fd) {
    for (int attempt = 0; attempt < 128; ++attempt) {
        unsigned char packet[4096];
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        ssize_t n = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr *)&peer, &plen);
        if (n < 0)
            break;
        /* Bound aggregate work and amplification; only answer the observed IP. */
        if (++s->packets > 10000 || n < 8 || plen != sizeof(peer) || peer.sin_family != AF_INET ||
            gw_u32(packet) != (uint32_t)(n - 8) || gw_u16(packet + 4) != 2 ||
            gw_u16(packet + 6) > 1)
            continue;
        json_object *request = NULL;
        if (n != 12 || memcmp(packet + 8, "null", 4)) {
            request = gw_json(packet + 8, (size_t)n - 8);
            if (!request || !json_object_is_type(request, json_type_object)) {
                if (request)
                    json_object_put(request);
                continue;
            }
        }
        unsigned sub = gw_u16(packet + 6);
        if (sub == 1) {
            uint64_t port = gw_integer(request, "echoPort");
            if (!port || port > 65535) {
                if (request)
                    json_object_put(request);
                continue;
            }
            peer.sin_port = htons((uint16_t)port);
        }
        if (request)
            json_object_put(request);
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
        json_object *j = json_object_new_object();
        gw_js(j, "IP", ip);
        gw_ju(j, "port", ntohs(peer.sin_port));
        gw_ju(j, "isPublicIP", 0);
        const char *text = json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN);
        size_t length = strlen(text);
        unsigned char response[256];
        gw_put32(response, (uint32_t)length);
        gw_put16(response + 4, 2);
        gw_put16(response + 6, (uint16_t)sub);
        memcpy(response + 8, text, length);
        sendto(fd, response, length + 8, MSG_NOSIGNAL, (struct sockaddr *)&peer, sizeof(peer));
        json_object_put(j);
    }
}
void gw_nat_step(struct nat_state *s) {
    uint64_t now = gw_mono_ms();
    if (s->second != now / 1000) {
        s->second = now / 1000;
        s->packets = 0;
    }
    for (int i = 0; i < 4; ++i)
        udp_step(s, s->udp[i]);
    for (int i = 0; i < 2; ++i)
        for (int attempt = 0; attempt < 32; ++attempt) {
            struct sockaddr_in peer;
            socklen_t n = sizeof(peer);
            int fd = accept4(s->tcp[i], (struct sockaddr *)&peer, &n, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (fd < 0)
                break;
            int slot = 0;
            while (slot < GW_MAX_PROBES && s->probes[slot].fd >= 0)
                ++slot;
            if (slot == GW_MAX_PROBES) {
                close(fd);
                continue;
            }
            s->probes[slot] = (struct probe){.fd = fd, .peer = peer, .deadline = now + 5000};
        }
    for (int i = 0; i < GW_MAX_PROBES; ++i) {
        struct probe *p = &s->probes[i];
        if (p->fd < 0)
            continue;
        int failed = now > p->deadline;
        if (!failed && p->length == p->offset) {
            unsigned char data[1024];
            ssize_t n = recv(p->fd, data, sizeof(data), 0);
            if (n > 0) {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &p->peer.sin_addr, ip, sizeof(ip));
                p->offset = 0;
                p->length = (size_t)snprintf(p->output, sizeof(p->output), "%s:%u", ip,
                                             ntohs(p->peer.sin_port));
                p->deadline = now + 5000;
            } else if (n == 0 ||
                       (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
                failed = 1;
        }
        if (!failed && p->offset < p->length) {
            ssize_t n = send(p->fd, p->output + p->offset, p->length - p->offset, MSG_NOSIGNAL);
            if (n > 0)
                p->offset += (size_t)n;
            else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                failed = 1;
        }
        if (failed) {
            close(p->fd);
            p->fd = -1;
        }
    }
}
