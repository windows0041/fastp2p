#include "tcp_level.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 0
#endif

/* Deadlines share the client clock, which counts nanoseconds (client.c: MS is one
 * millisecond), so every wait below is converted explicitly. */
#define FP_NS_PER_MS UINT64_C(1000000)
#define FP_TCP_LEVEL_CONNECT 3000 /* ms for the control connection */
#define FP_TCP_LEVEL_PROBE 10000  /* ms: the server probes the callbacks one after another */

/* Temporary tracing: FASTP2P_TCP_LEVEL_DEBUG=1 shows each transition. */
static int tracing(void) {
    static int cached = -1;
    if (cached < 0)
        cached = getenv("FASTP2P_TCP_LEVEL_DEBUG") != NULL;
    return cached;
}
#define TRACE(...)                                                                     \
    do {                                                                               \
        if (tracing()) {                                                               \
            fprintf(stderr, "tcp-level: " __VA_ARGS__);                                \
            fputc(10, stderr);                                                         \
        }                                                                              \
    } while (0)

static void reset(fp_tcp_level *state) {
    state->phase = 0;
    state->used = 0;
    state->accepted = 0;
    state->same_port = 0;
    state->other_ip = 0;
    state->answered = 0;
    state->level = 0;
}

void fp_tcp_level_close(fp_tcp_level *state) {
    if (state->listener >= 0)
        op_close(state->listener);
    if (state->dialer >= 0)
        op_close(state->dialer);
    state->listener = -1;
    state->dialer = -1;
}

static int shareable(op_socket fd) {
    int on = 1;
    op_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#if defined(SO_REUSEPORT)
    if (SO_REUSEPORT && op_setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)))
        return -1;
#endif
    return 0;
}

int fp_tcp_level_configure(fp_tcp_level *state, const char *text) {
    memset(state, 0, sizeof(*state));
    state->listener = -1;
    state->dialer = -1;
    if (!text || !*text)
        return 0;
    char host[254];
    const char *colon = strrchr(text, ':');
    uint16_t port = 0;
    if (colon) {
        size_t length = (size_t)(colon - text);
        if (length == 0 || length >= sizeof(host))
            return -1;
        memcpy(host, text, length);
        host[length] = 0;
        port = (uint16_t)strtoul(colon + 1, NULL, 10);
    } else {
        if (strlen(text) >= sizeof(host))
            return -1;
        snprintf(host, sizeof(host), "%s", text);
        port = 3479;
    }
    if (!port)
        return -1;
    snprintf(state->host, sizeof(state->host), "%s", host);
    state->server_port = port;
    return 1;
}

void fp_tcp_level_start(fp_tcp_level *state) {
    if (state->phase)
        return;
    reset(state);
    /* Resolve now: a hostname is normal here, and doing it at config time made
     * every client wait on DNS during startup. A failure just disables the probe. */
    struct addrinfo hints, *found = NULL, *cursor, *pick = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char service[8];
    snprintf(service, sizeof(service), "%u", (unsigned)state->server_port);
    if (getaddrinfo(state->host, service, &hints, &found) || !found) {
        TRACE("cannot resolve %s", state->host);
        state->phase = 4;
        return;
    }
    for (cursor = found; cursor; cursor = cursor->ai_next)
        if (cursor->ai_family == AF_INET) {
            pick = cursor;
            break;
        }
    for (cursor = found; !pick && cursor; cursor = cursor->ai_next)
        if (cursor->ai_family == AF_INET6)
            pick = cursor;
    if (!pick || pick->ai_addrlen > sizeof(state->server.u)) {
        freeaddrinfo(found);
        state->phase = 4;
        return;
    }
    memset(&state->server, 0, sizeof(state->server));
    memcpy(&state->server.u.sa, pick->ai_addr, pick->ai_addrlen);
    state->server.len = pick->ai_addrlen;
    freeaddrinfo(found);

    int family = op_addr_family(&state->server);
    state->dialer = op_socket_open(family, SOCK_STREAM, 0);
    if (state->dialer < 0 || shareable(state->dialer)) {
        fp_tcp_level_close(state);
        state->phase = 4;
        return;
    }
    /* Non-blocking connect; completion is the first thing step() waits for. The
     * listener is created only after this succeeds - putting it on the same port
     * beforehand lets the kernel steer the SYN-ACK to the listener and the
     * connect then never completes. */
    if (op_connect(state->dialer, &state->server.u.sa, state->server.len) &&
        errno != EINPROGRESS) {
        TRACE("connect failed errno=%d", errno);
        fp_tcp_level_close(state);
        state->phase = 4;
        return;
    }
    state->phase = 1;
    state->deadline = 0;
}

/* Opens the listener on the port the outbound connection already occupies, so an
 * inbound SYN for the NAT mapping can actually be accepted. */
static int listen_here(fp_tcp_level *state) {
    op_addr local;
    if (op_addr_socketname(state->dialer, &local))
        return -1;
    state->local_port = op_addr_port(&local);
    int family = op_addr_family(&local);
    op_addr any;
    memset(&any, 0, sizeof(any));
    any.u.sa.sa_family = (unsigned short)family;
    any.len = family == AF_INET6 ? sizeof(any.u.in6) : sizeof(any.u.in);
    op_addr_set_port(&any, state->local_port);
    state->listener = op_socket_open(family, SOCK_STREAM, 0);
    if (state->listener < 0 || shareable(state->listener))
        return -1;
    if (op_bind(state->listener, &any.u.sa, any.len)) {
        TRACE("bind failed on port %u errno=%d", (unsigned)state->local_port, errno);
        return -1;
    }
    if (op_listen(state->listener, 4)) {
        TRACE("listen failed on port %u errno=%d", (unsigned)state->local_port, errno);
        return -1;
    }
    return 0;
}

static int read_line(fp_tcp_level *state) {
    char chunk[64];
    ssize_t received = recv(state->dialer, chunk, sizeof(chunk), MSG_DONTWAIT);
    if (received <= 0)
        return 0;
    if (state->used + (size_t)received >= sizeof(state->line))
        return -1;
    memcpy(state->line + state->used, chunk, (size_t)received);
    state->used += (size_t)received;
    state->line[state->used] = 0;
    return strchr(state->line, '\n') ? 1 : 0;
}

static void verdict(fp_tcp_level *state) {
    if (!state->answered)
        state->level = 0;
    else if (state->same_port && state->other_ip)
        state->level = 1;
    else if (state->same_port)
        state->level = 2;
    else
        state->level = 3;
}

/* One retry with a fresh local port: the port the kernel hands to connect() can be
 * unusable for the co-located listener (another service may hold it), and that is a
 * reason to try again rather than to report "no verdict". */
static void retry_or_finish(fp_tcp_level *state) {
    fp_tcp_level_close(state);
    if (state->attempt < 1) {
        state->attempt++;
        TRACE("retrying with a fresh port");
        state->phase = 0;
        fp_tcp_level_start(state);
        return;
    }
    state->phase = 4;
}
static void finish(fp_tcp_level *state) {
    verdict(state);
    TRACE("verdict level=%d answered=%d same_port=%d other_ip=%d accepted=%d", state->level,
          state->answered, state->same_port, state->other_ip, state->accepted);
    fp_tcp_level_close(state);
    state->phase = 4;
}

void fp_tcp_level_step(fp_tcp_level *state, uint64_t now) {
    if (state->phase == 0 || state->phase >= 4)
        return;
    if (!state->deadline)
        state->deadline = now + (uint64_t)FP_TCP_LEVEL_CONNECT * FP_NS_PER_MS;

    if (state->phase == 1) {
        op_pollfd item = {.fd = state->dialer, .events = POLLOUT, .revents = 0};
        int ready = op_poll(&item, 1, 0);
        if (ready <= 0) {
            if (now > state->deadline) {
                TRACE("connect timed out (revents=%d)", item.revents);
                retry_or_finish(state);
            }
            return;
        }
        int error = 0;
        op_socklen length = sizeof(error);
        if (op_getsockopt(state->dialer, SOL_SOCKET, SO_ERROR, &error, &length) || error) {
            TRACE("connect error %d", error);
            retry_or_finish(state);
            return;
        }
        if (listen_here(state)) {
            retry_or_finish(state);
            return;
        }
        TRACE("connected, listening on %u", (unsigned)state->local_port);
        state->phase = 2;
        state->deadline = now + (uint64_t)FP_TCP_LEVEL_CONNECT * FP_NS_PER_MS;
        return;
    }

    if (state->phase == 2) {
        int line = read_line(state);
        if (line < 0) {
            fp_tcp_level_close(state);
            state->phase = 4;
            return;
        }
        if (line > 0 && !strncmp(state->line, "mapped", 6)) {
            static const char request[] = "probe\n";
            if (send(state->dialer, request, sizeof(request) - 1, MSG_DONTWAIT) <= 0) {
                fp_tcp_level_close(state);
                state->phase = 4;
                return;
            }
            TRACE("greeting %s", state->line);
            state->phase = 3;
            state->used = 0;
            state->line[0] = 0;
            state->deadline = now + (uint64_t)FP_TCP_LEVEL_PROBE * FP_NS_PER_MS;
            return;
        }
        if (now > state->deadline) {
            TRACE("no greeting, deadline hit");
            retry_or_finish(state);
        }
        return;
    }

    /* phase 3: collect the inbound SYNs the NAT let through, plus the server's
     * report of which callbacks it managed to establish. */
    for (;;) {
        op_addr from;
        memset(&from, 0, sizeof(from));
        op_socket peer = op_accept(state->listener, &from.u.sa, &from.len);
        if (peer < 0)
            break;
        op_close(peer);
        ++state->accepted;
        TRACE("accepted callback %d", state->accepted);
    }
    int line = read_line(state);
    if (line < 0) {
        fp_tcp_level_close(state);
        state->phase = 4;
        return;
    }
    if (line > 0 && strstr(state->line, "same-port=")) {
        state->same_port = strstr(state->line, "same-port=1") != NULL;
        state->other_ip = strstr(state->line, "other-ip=1") != NULL;
        state->answered = 1;
        finish(state);
        return;
    }
    if (now > state->deadline)
        finish(state);
}
