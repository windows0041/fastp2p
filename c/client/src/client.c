#include "openp2p.h"
#include "wire.h"
#include "quic.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <curl/curl.h>
#include <openssl/rand.h>
#include <pthread.h>

#define NT 32
#define NA 64
#define NO 256
#define NP 16
#define NS UINT64_C(1000000000)
#define MS UINT64_C(1000000)
#define COMPAT_VERSION "3.25.11"
enum tunnel_state {
    T_FREE,
    T_NAT_CONNECT,
    T_NAT_READ,
    T_NAT_UDP,
    T_REPLY,
    T_TIME,
    T_TCP_CONNECT,
    T_HANDSHAKE,
    T_ACTIVE,
    T_PUNCH,
    T_UNDERLAY,
    T_QUIC,
    T_DIRECT
};
typedef struct {
    int state, fd, listen_fd, alternate_fd, server, initiator, transport, notified;
    uint64_t id, peer_id, deadline, at, last_rx, last_hb, punch_next;
    char peer[32], ip[INET_ADDRSTRLEN], mode[16], probe[96];
    uint16_t local_port, mapped_port, remote_port;
    size_t probe_len;
    op_buffer rx, tx, alternate_rx;
    opq *quic;
} tunnel;
typedef struct {
    int used, local, fd, udp, transport, tunnel_index, synced;
    uint64_t id, key, retry, ready_at;
    char name[64], peer[32], destination[256], bind_ip[INET_ADDRSTRLEN];
    uint16_t port, dst_port;
} app;
typedef struct {
    int used, fd, udp, connected, local_udp, app_index, tunnel_index, waiting, peer_closed;
    uint64_t id, activity, deadline;
    struct sockaddr_in source;
    op_buffer tx, early;
} overlay;
typedef struct {
    int fd;
    uint64_t deadline;
    struct sockaddr_in peer;
    op_buffer rx;
} pending;
struct op2p_client {
    char host[256], ca[4096], node[32], ip[INET_ADDRSTRLEN], local_ip[INET_ADDRSTRLEN];
    char error[192], path[640];
    uint16_t port, public_port;
    uint64_t token, node_id, reconnect_at, last_rx, heartbeat_at, heartbeat_sent;
    int64_t clock_delta;
    op2p_state state;
    int running, stopping, in_callback, stepping, report_ok, login_ok, reconnect_attempt;
    int listener, nat_fd, nat_phase, nat_type;
    uint16_t nat_port;
    uint64_t nat_deadline;
    struct sockaddr_in gateway;
    CURLM *multi;
    CURL *ws;
    struct curl_slist *resolve;
    curl_socket_t ws_socket;
    int ws_connected;
    size_t ws_remaining;
    op_buffer ws_rx, ws_tx;
    op2p_event_fn callback;
    void *user;
    tunnel tunnels[NT];
    app apps[NA];
    overlay overlays[NO];
    pending pending[NP];
};
static void connect_gateway(op2p_client *);
static void control_message(op2p_client *, uint16_t, uint16_t, const uint8_t *, size_t);
static void close_tunnel(op2p_client *, int, const char *);
static void close_overlay(op2p_client *, int, int);
static void tunnel_message(op2p_client *, int, uint16_t, const uint8_t *, size_t);
static void synchronize_app(op2p_client *, int);
static uint64_t mono(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * NS + (uint64_t)t.tv_nsec;
}
static uint64_t wall(void) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (uint64_t)t.tv_sec * NS + (uint64_t)t.tv_nsec;
}
static uint64_t random_id(void) {
    uint64_t v = 0;
    while (!v)
        if (RAND_bytes((unsigned char *)&v, sizeof(v)) != 1)
            abort();
    return v;
}
static int valid_node(const char *s) {
    if (!s || strlen(s) < 8 || strlen(s) > 31)
        return 0;
    for (; *s; ++s)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9') ||
              *s == '_' || *s == '-'))
            return 0;
    return 1;
}
static int copy_string(char *dst, size_t cap, const char *src) {
    if (!src || strlen(src) >= cap)
        return -1;
    memcpy(dst, src, strlen(src) + 1);
    return 0;
}
static void emit(op2p_client *c, op2p_event_type type, uint64_t id, int code, const char *message) {
    if (type == OP2P_EVENT_ERROR)
        snprintf(c->error, sizeof(c->error), "%s", message);
    if (c->callback) {
        op2p_event e = {sizeof(e), type, c->state, id, code, message};
        c->in_callback = 1;
        c->callback(c, &e, c->user);
        c->in_callback = 0;
    }
}
static void set_state(op2p_client *c, op2p_state s, const char *msg) {
    if (c->state != s) {
        c->state = s;
        emit(c, OP2P_EVENT_STATE, 0, 0, msg);
    }
}
static int resolve4(const char *host, uint16_t port, struct sockaddr_in *out) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res))
        return -1;
    memcpy(out, res->ai_addr, sizeof(*out));
    out->sin_port = htons(port);
    freeaddrinfo(res);
    return 0;
}
static int socket_bound(int udp, const char *ip, uint16_t port, int reuse) {
    int fd = socket(AF_INET, (udp ? SOCK_DGRAM : SOCK_STREAM) | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int one = 1;
    if (reuse && (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) ||
                  setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)))) {
        close(fd);
        return -1;
    }
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, ip ? ip : "0.0.0.0", &a.sin_addr) != 1 ||
        bind(fd, (struct sockaddr *)&a, sizeof(a))) {
        close(fd);
        return -1;
    }
    if (!udp) {
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    }
    return fd;
}
static uint16_t socket_port(int fd) {
    struct sockaddr_in a;
    socklen_t n = sizeof(a);
    return getsockname(fd, (struct sockaddr *)&a, &n) ? 0 : ntohs(a.sin_port);
}
static int connect_ready(int fd) {
    struct pollfd p = {.fd = fd, .events = POLLOUT};
    if (poll(&p, 1, 0) <= 0)
        return 0;
    int error = 0;
    socklen_t n = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &n) || error) {
        errno = error;
        return -1;
    }
    return 1;
}
static int flush(int fd, op_buffer *b) {
    for (int i = 0; i < 32 && op_buffer_size(b); ++i) {
        ssize_t n = send(fd, b->data + b->offset, op_buffer_size(b), MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0)
            op_buffer_consume(b, (size_t)n);
        else if (n < 0 && errno == EINTR)
            continue;
        else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
        else
            return -1;
    }
    return 0;
}
static int read_socket(int fd, op_buffer *b, size_t limit) {
    uint8_t data[16384];
    for (int i = 0; i < 16; ++i) {
        ssize_t n = recv(fd, data, sizeof(data), MSG_DONTWAIT);
        if (n > 0) {
            if (op_buffer_add(b, data, (size_t)n, limit))
                return -1;
        } else if (n == 0)
            return -1;
        else if (errno == EINTR)
            continue;
        else if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        else
            return -1;
    }
    return 0;
}
static int ws_frame(op2p_client *c, uint16_t main, uint16_t sub, const void *data, size_t len) {
    if (!c->ws || !c->running)
        return -1;
    if (op_frame_add(&c->ws_tx, main, sub, data, len))
        return -1;
    return 0;
}
static int ws_json(op2p_client *c, uint16_t main, uint16_t sub, json_object *obj) {
    const char *s = obj ? json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN) : "null";
    return ws_frame(c, main, sub, s, strlen(s));
}
static int push(op2p_client *c, const char *peer, uint16_t sub, json_object *obj) {
    op_buffer b = {0};
    uint8_t header[16];
    op_put64(header, c->node_id);
    op_put64(header + 8, op_node_id(peer));
    const char *s = obj ? json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN) : "null";
    int rv = op_buffer_add(&b, header, 16, OP_FRAME_LIMIT) ||
             op_buffer_add(&b, s, strlen(s), OP_FRAME_LIMIT);
    if (!rv)
        rv = ws_frame(c, 3, sub, b.data, b.len);
    op_buffer_clear(&b);
    return rv;
}
static int tframe(tunnel *t, uint16_t sub, const void *data, size_t len) {
    return op_frame_add(&t->tx, 4, sub, data, len);
}
static int tjson(tunnel *t, uint16_t sub, json_object *obj) {
    const char *s = obj ? json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN) : "null";
    return tframe(t, sub, s, strlen(s));
}
static int tunnel_by_id(op2p_client *c, uint64_t id) {
    for (int i = 0; i < NT; ++i)
        if (c->tunnels[i].state && c->tunnels[i].id == id)
            return i;
    return -1;
}
static int active_tunnel(op2p_client *c, const char *peer, int transport) {
    for (int i = 0; i < NT; ++i)
        if (c->tunnels[i].state == T_ACTIVE && c->tunnels[i].transport == transport &&
            !strcmp(c->tunnels[i].peer, peer))
            return i;
    return -1;
}
static void close_overlay(op2p_client *c, int index, int notify) {
    overlay *o = &c->overlays[index];
    if (!o->used)
        return;
    if (notify && c->tunnels[o->tunnel_index].state == T_ACTIVE) {
        json_object *j = json_object_new_object();
        op_ju(j, "id", o->id);
        tjson(&c->tunnels[o->tunnel_index], 8, j);
        json_object_put(j);
    }
    if (o->fd >= 0 && !o->local_udp)
        close(o->fd);
    op_buffer_clear(&o->tx);
    op_buffer_clear(&o->early);
    memset(o, 0, sizeof(*o));
    o->fd = -1;
}
static void close_tunnel(op2p_client *c, int index, const char *reason) {
    tunnel *t = &c->tunnels[index];
    if (!t->state)
        return;
    char message[192];
    if (reason) {
        snprintf(message, sizeof(message), "%s", reason);
        reason = message;
    }
    uint64_t id = t->id;
    t->state = T_FREE;
    for (int i = 0; i < NO; ++i)
        if (c->overlays[i].used && c->overlays[i].tunnel_index == index)
            close_overlay(c, i, 0);
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used && c->apps[i].tunnel_index == index) {
            c->apps[i].tunnel_index = -1;
            c->apps[i].synced = 0;
            c->apps[i].retry = mono() + 2 * NS;
            if (!c->apps[i].local)
                memset(&c->apps[i], 0, sizeof(c->apps[i]));
        }
    if (t->quic)
        opq_free(t->quic);
    if (t->fd >= 0)
        close(t->fd);
    if (t->listen_fd >= 0)
        close(t->listen_fd);
    if (t->alternate_fd >= 0)
        close(t->alternate_fd);
    op_buffer_clear(&t->rx);
    op_buffer_clear(&t->tx);
    op_buffer_clear(&t->alternate_rx);
    memset(t, 0, sizeof(*t));
    t->fd = t->listen_fd = t->alternate_fd = -1;
    if (reason)
        emit(c, OP2P_EVENT_ERROR, id, OP2P_EIO, reason);
}
static int new_tunnel(op2p_client *c, const char *peer, uint64_t id, int transport, int initiator) {
    for (int i = 0; i < NT; ++i)
        if (!c->tunnels[i].state) {
            tunnel *t = &c->tunnels[i];
            memset(t, 0, sizeof(*t));
            t->fd = t->listen_fd = t->alternate_fd = -1;
            t->state = T_REPLY;
            t->id = id;
            t->peer_id = op_node_id(peer);
            strcpy(t->peer, peer);
            t->transport = transport;
            t->initiator = initiator;
            t->deadline = mono() + 15 * NS;
            return i;
        }
    emit(c, OP2P_EVENT_ERROR, 0, OP2P_ELIMIT, "tunnel limit reached");
    return -1;
}
static int udp_packet(int fd, const struct sockaddr_in *peer, uint16_t main, uint16_t sub,
                      json_object *j) {
    op_buffer b = {0};
    const char *s = j ? json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN) : "null";
    int rv = op_frame_add(&b, main, sub, s, strlen(s));
    if (!rv)
        rv = sendto(fd, b.data, b.len, MSG_DONTWAIT, (const struct sockaddr *)peer,
                    sizeof(*peer)) != (ssize_t)b.len;
    op_buffer_clear(&b);
    return rv ? -1 : 0;
}
static int start_probe(op2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    if (t->fd >= 0)
        close(t->fd);
    t->fd = socket_bound(t->transport == OP2P_TRANSPORT_QUIC, c->local_ip, 0, 1);
    if (t->fd < 0)
        return -1;
    t->local_port = socket_port(t->fd);
    t->deadline = mono() + 5 * NS;
    struct sockaddr_in peer = c->gateway;
    peer.sin_port = htons(27180);
    if (t->transport == OP2P_TRANSPORT_QUIC) {
        t->state = T_NAT_UDP;
        return udp_packet(t->fd, &peer, 2, 0, NULL);
    }
    t->state = T_NAT_CONNECT;
    if (connect(t->fd, (struct sockaddr *)&peer, sizeof(peer)) && errno != EINPROGRESS)
        return -1;
    return 0;
}
static void probe_complete(op2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    json_object *j = json_object_new_object();
    op_js(j, "from", c->node);
    op_js(j, "fromIP", c->ip);
    op_js(j, "version", COMPAT_VERSION);
    op_ju(j, "natType", (uint64_t)c->nat_type);
    op_ju(j, "coneNatPort", t->mapped_port);
    op_ju(j, "id", t->id);
    if (t->initiator) {
        op_ju(j, "token", c->token);
        op_js(j, "linkMode", t->mode);
        op_ju(j, "isServer", 1);
        op_js(j, "underlayProtocol", t->transport == OP2P_TRANSPORT_QUIC ? "quic" : "tcp");
        push(c, t->peer, 1, j);
        t->state = T_REPLY;
        t->deadline = mono() + 12 * NS;
    } else {
        uint64_t ts = (uint64_t)((int64_t)wall() - c->clock_delta) + 3 * NS;
        op_js(j, "to", t->peer);
        op_ju(j, "punchts", ts);
        push(c, t->peer, 2, j);
        t->at = mono() + 3 * NS;
        t->state = T_TIME;
        t->deadline = t->at + 10 * NS;
        if (!strcmp(t->mode, "tcp4") || !strcmp(t->mode, "intranet") || !strcmp(t->mode, "udp4"))
            t->at = mono();
    }
    json_object_put(j);
    if (t->transport == OP2P_TRANSPORT_TCP) {
        if (t->fd >= 0)
            close(t->fd);
        t->fd = -1;
        if (!strcmp(t->mode, "tcppunch")) {
            t->listen_fd = socket_bound(0, c->local_ip, t->local_port, 1);
            if (t->listen_fd < 0 || listen(t->listen_fd, 4))
                close_tunnel(c, index, "TCP punch listener failed");
        }
    }
}
static void start_underlay(op2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(t->remote_port)};
    if (inet_pton(AF_INET, t->ip, &peer.sin_addr) != 1) {
        close_tunnel(c, index, "invalid peer address");
        return;
    }
    t->deadline = mono() + 10 * NS;
    if (t->transport == OP2P_TRANSPORT_QUIC) {
        if (!t->server && !t->notified) {
            t->state = T_UNDERLAY;
            return;
        }
        t->quic = opq_new(t->fd, (struct sockaddr *)&peer, sizeof(peer), t->server);
        if (!t->quic) {
            close_tunnel(c, index, "QUIC initialization failed");
            return;
        }
        t->state = T_QUIC;
        if (t->server)
            push(c, t->peer, 8, NULL);
        else {
            uint8_t id[8];
            op_put64(id, t->id);
            tframe(t, 2, id, 8);
        }
        return;
    }
    if (strcmp(t->mode, "tcppunch")) {
        if (t->server) {
            t->state = T_DIRECT;
            push(c, t->peer, 8, NULL);
            return;
        }
        if (!t->notified) {
            t->state = T_UNDERLAY;
            return;
        }
    }
    t->fd = socket_bound(0, c->local_ip, !strcmp(t->mode, "tcppunch") ? t->local_port : 0, 1);
    if (t->fd < 0 ||
        (connect(t->fd, (struct sockaddr *)&peer, sizeof(peer)) && errno != EINPROGRESS)) {
        if (t->listen_fd < 0) {
            close_tunnel(c, index, "TCP peer connection failed");
            return;
        }
        if (t->fd >= 0)
            close(t->fd);
        t->fd = -1;
    }
    t->state = T_TCP_CONNECT;
}
static void tunnel_active(op2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    t->state = T_ACTIVE;
    t->last_rx = t->last_hb = mono();
    if (t->listen_fd >= 0)
        close(t->listen_fd);
    if (t->alternate_fd >= 0)
        close(t->alternate_fd);
    t->listen_fd = t->alternate_fd = -1;
    op_buffer_clear(&t->alternate_rx);
    emit(c, OP2P_EVENT_TUNNEL, t->id, 0,
         t->transport == OP2P_TRANSPORT_TCP ? "TCP tunnel connected" : "QUIC tunnel connected");
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used && c->apps[i].local && !strcmp(c->apps[i].peer, t->peer) &&
            c->apps[i].transport == t->transport) {
            c->apps[i].tunnel_index = index;
            c->apps[i].synced = 0;
            synchronize_app(c, i);
        }
}
static void synchronize_app(op2p_client *c, int index) {
    app *a = &c->apps[index];
    if (a->synced || a->tunnel_index < 0 || c->tunnels[a->tunnel_index].state != T_ACTIVE)
        return;
    tunnel *t = &c->tunnels[a->tunnel_index];
    json_object *j = json_object_new_object();
    op_ju(j, "appID", a->id);
    op_ju(j, "appKey", a->key);
    push(c, a->peer, 13, j);
    op_js(j, "from", c->node);
    op_js(j, "node", c->node);
    op_ju(j, "tunnelID", t->id);
    op_ju(j, "tunnelNum", 2);
    op_ju(j, "srcPort", a->port);
    push(c, a->peer, 18, j);
    json_object_put(j);
    a->synced = 1;
    a->ready_at = mono() + 200 * MS;
    emit(c, OP2P_EVENT_FORWARD, a->id, 0, "forward attached to tunnel");
}
static int overlay_slot(op2p_client *c) {
    for (int i = 0; i < NO; ++i)
        if (!c->overlays[i].used) {
            overlay *o = &c->overlays[i];
            memset(o, 0, sizeof(*o));
            o->fd = -1;
            o->used = 1;
            o->activity = mono();
            o->deadline = o->activity + 5 * NS;
            return i;
        }
    emit(c, OP2P_EVENT_ERROR, 0, OP2P_ELIMIT, "overlay connection limit reached");
    return -1;
}
static int overlay_data(op2p_client *c, int oi, const uint8_t *data, size_t len) {
    overlay *o = &c->overlays[oi];
    app *a = &c->apps[o->app_index];
    uint8_t encrypted[4096 + 32 + 8];
    size_t n = 0;
    if (len > 4096 || op_crypt(1, a->key, data, len, encrypted + 8, sizeof(encrypted) - 8, &n))
        return -1;
    op_put64(encrypted, o->id);
    o->activity = mono();
    return tframe(&c->tunnels[o->tunnel_index], 9, encrypted, n + 8);
}
static void request_overlay(op2p_client *c, int oi) {
    overlay *o = &c->overlays[oi];
    app *a = &c->apps[o->app_index];
    json_object *j = json_object_new_object();
    op_ju(j, "id", o->id);
    op_ju(j, "token", c->token);
    op_ju(j, "appID", a->id);
    op_js(j, "dstIP", a->destination);
    op_ju(j, "dstPort", a->dst_port);
    op_js(j, "protocol", a->udp ? "udp" : "tcp");
    tjson(&c->tunnels[o->tunnel_index], 6, j);
    json_object_put(j);
    o->waiting = 1;
    o->deadline = mono() + 5 * NS;
}
static void report_apps(op2p_client *c) {
    json_object *root = json_object_new_object(), *list = json_object_new_array();
    for (int i = 0; i < NA; ++i) {
        app *a = &c->apps[i];
        if (!a->used || !a->local)
            continue;
        json_object *j = json_object_new_object();
        op_js(j, "appName", a->name);
        op_js(j, "protocol", a->udp ? "udp" : "tcp");
        op_js(j, "peerNode", a->peer);
        op_js(j, "dstHost", a->destination);
        op_ju(j, "dstPort", a->dst_port);
        op_ju(j, "srcPort", a->port);
        op_ju(j, "enabled", 1);
        op_ju(j, "isActive", a->tunnel_index >= 0 && c->tunnels[a->tunnel_index].state == T_ACTIVE);
        op_js(j, "linkMode", a->transport == OP2P_TRANSPORT_QUIC ? "udppunch" : "ipv4");
        json_object_array_add(list, j);
    }
    json_object_object_add(root, "Apps", list);
    ws_json(c, 6, 3, root);
    json_object_put(root);
}
static void control_message(op2p_client *c, uint16_t main, uint16_t sub, const uint8_t *data,
                            size_t len) {
    c->last_rx = mono();
    if (main == 1) {
        if (len != 8) {
            emit(c, OP2P_EVENT_ERROR, 0, OP2P_EIO, "invalid gateway heartbeat");
            return;
        }
        uint64_t now = wall();
        uint64_t server = op_u64(data);
        if (c->heartbeat_sent && now >= c->heartbeat_sent && now - c->heartbeat_sent < 3 * NS &&
            now <= INT64_MAX && server <= INT64_MAX) {
            int64_t delta =
                (int64_t)(c->heartbeat_sent + (now - c->heartbeat_sent) / 2) - (int64_t)server;
            if (delta >= -(int64_t)(86400 * NS) && delta <= (int64_t)(86400 * NS))
                c->clock_delta = delta;
        }
        emit(c, OP2P_EVENT_HEARTBEAT, 0, 0, "gateway heartbeat received");
        return;
    }
    uint64_t sender = 0;
    if (main == 3 && (sub == 1 || sub == 2 || sub == 8 || sub == 13 || sub == 18)) {
        if (len < 16 || op_u64(data + 8) != c->node_id)
            return;
        sender = op_u64(data);
        data += 16;
        len -= 16;
    }
    if (main == 3 && sub == 8) {
        for (int i = 0; i < NT; ++i)
            if (c->tunnels[i].state && c->tunnels[i].peer_id == sender)
                c->tunnels[i].notified = 1;
        return;
    }
    if (main == 3 && sub == 7) {
        report_apps(c);
        return;
    }
    json_object *j = op_json(data, len);
    if (!j || !json_object_is_type(j, json_type_object)) {
        if (j)
            json_object_put(j);
        return;
    }
    if (main == 0) {
        if (op_integer(j, "error") || op_integer(j, "token") != c->token) {
            emit(c, OP2P_EVENT_ERROR, 0, OP2P_EIO, "gateway rejected login");
            c->stopping = 1;
        } else {
            c->login_ok = 1;
            if (c->report_ok)
                set_state(c, OP2P_ONLINE, "gateway authenticated");
        }
    } else if (main == 6 && sub == 7) {
        c->report_ok = 1;
        if (c->login_ok)
            set_state(c, OP2P_ONLINE, "gateway authenticated");
    } else if (main == 3 && sub == 1) {
        const char *from = op_string(j, "from"), *mode = op_string(j, "linkMode");
        uint64_t id = op_integer(j, "id"), port = op_integer(j, "coneNatPort");
        struct in_addr peer_ip;
        int udp = !strcmp(mode, "udppunch") || !strcmp(mode, "udp4");
        if (valid_node(from) && sender == op_node_id(from) && op_integer(j, "token") == c->token &&
            id && tunnel_by_id(c, id) < 0 && port > 0 && port <= 65535 &&
            inet_pton(AF_INET, op_string(j, "fromIP"), &peer_ip) == 1 &&
            (!strcmp(mode, "tcppunch") || !strcmp(mode, "tcp4") || !strcmp(mode, "intranet") ||
             udp)) {
            int ti = new_tunnel(c, from, id, udp ? OP2P_TRANSPORT_QUIC : OP2P_TRANSPORT_TCP, 0);
            if (ti >= 0) {
                tunnel *t = &c->tunnels[ti];
                strcpy(t->mode, mode);
                strcpy(t->ip, op_string(j, "fromIP"));
                t->remote_port = (uint16_t)port;
                t->server = op_integer(j, "isServer") != 0;
                if (udp && !strcmp(mode, "udp4") && t->server)
                    close_tunnel(c, ti, "direct UDP listener is not supported; use UDP punching");
                else if (!udp && strcmp(mode, "tcppunch")) {
                    t->local_port = t->mapped_port = c->public_port;
                    probe_complete(c, ti);
                } else if (start_probe(c, ti))
                    close_tunnel(c, ti, "NAT probe could not start");
            }
        } else
            emit(c, OP2P_EVENT_ERROR, id, OP2P_EINVAL, "peer connection request rejected");
    } else if (main == 3 && sub == 2) {
        int ti = tunnel_by_id(c, op_integer(j, "id"));
        if (ti >= 0) {
            tunnel *t = &c->tunnels[ti];
            uint64_t port = op_integer(j, "coneNatPort");
            struct in_addr ip;
            if (t->state == T_REPLY && sender == t->peer_id &&
                !strcmp(t->peer, op_string(j, "from")) && !op_integer(j, "error") && port > 0 &&
                port <= 65535 && inet_pton(AF_INET, op_string(j, "fromIP"), &ip) == 1) {
                strcpy(t->ip, op_string(j, "fromIP"));
                t->remote_port = (uint16_t)port;
                uint64_t ts = op_integer(j, "punchts"), local = wall();
                uint64_t difference = ts >= local ? ts - local : local - ts;
                if (ts > INT64_MAX || local > INT64_MAX || difference > 2 * 86400 * NS) {
                    close_tunnel(c, ti, "peer sent an invalid punch timestamp");
                    json_object_put(j);
                    return;
                }
                int64_t delay = ((int64_t)ts - (int64_t)local) + c->clock_delta;
                if (delay < 0)
                    delay = 0;
                if (delay > (int64_t)(3 * NS))
                    delay = (int64_t)(3 * NS);
                t->at = mono() + (uint64_t)delay;
                t->deadline = t->at + 10 * NS;
                t->state = T_TIME;
            } else if (t->state == T_REPLY)
                close_tunnel(c, ti, "peer rejected connection or sent an invalid response");
        }
    } else if (main == 3 && sub == 18) {
        int ti = tunnel_by_id(c, op_integer(j, "tunnelID"));
        uint64_t aid = op_integer(j, "appID");
        if (ti >= 0 && aid && c->tunnels[ti].peer_id == sender && !op_integer(j, "relayTunnelID")) {
            int ai = -1;
            for (int i = 0; i < NA; ++i)
                if (c->apps[i].used && c->apps[i].id == aid && !c->apps[i].local &&
                    !strcmp(c->apps[i].peer, c->tunnels[ti].peer)) {
                    ai = i;
                    break;
                }
            if (ai < 0)
                for (int i = 0; i < NA; ++i)
                    if (!c->apps[i].used) {
                        ai = i;
                        break;
                    }
            if (ai >= 0) {
                app *a = &c->apps[ai];
                memset(a, 0, sizeof(*a));
                a->used = 1;
                a->fd = -1;
                a->id = aid;
                a->key = op_integer(j, "appKey");
                a->tunnel_index = ti;
                strcpy(a->peer, c->tunnels[ti].peer);
            }
        }
    } else if (main == 3 && sub == 7)
        report_apps(c);
    else if (main == 3 && sub == 9) {
        uint64_t src = op_integer(j, "srcPort"), dst = op_integer(j, "dstPort");
        if (src && src <= 65535 && dst && dst <= 65535) {
            op2p_forward f = {.struct_size = sizeof(f),
                              .name = op_string(j, "appName"),
                              .local_port = (uint16_t)src,
                              .peer_node = op_string(j, "peerNode"),
                              .destination_host = op_string(j, "dstHost"),
                              .destination_port = (uint16_t)dst,
                              .protocol = op_string(j, "protocol"),
                              .transport = (op_integer(j, "punchPriority") & 2)
                                               ? OP2P_TRANSPORT_TCP
                                               : OP2P_TRANSPORT_QUIC};
            int rv = op2p_client_add_forward(c, &f, NULL);
            if (rv)
                emit(c, OP2P_EVENT_ERROR, 0, rv, "could not add gateway forwarding rule");
        }
    }
    json_object_put(j);
}
static void tunnel_message(op2p_client *c, int ti, uint16_t sub, const uint8_t *data, size_t len) {
    tunnel *t = &c->tunnels[ti];
    t->last_rx = mono();
    if (t->state == T_HANDSHAKE || t->state == T_QUIC) {
        if (t->server && sub == 2 && len == 8 && op_u64(data) == t->id) {
            tframe(t, 3, data, len);
            tunnel_active(c, ti);
        } else if (!t->server && sub == 3)
            tunnel_active(c, ti);
        else
            close_tunnel(c, ti, "invalid tunnel handshake");
        return;
    }
    if (t->state != T_ACTIVE)
        return;
    if (sub == 4) {
        uint8_t id[8];
        op_put64(id, c->node_id);
        tframe(t, 5, id, 8);
        return;
    }
    if (sub == 5)
        return;
    if (sub == 9) {
        if (len < 8 || len > 4096 + 32 + 8)
            return;
        for (int i = 0; i < NO; ++i) {
            overlay *o = &c->overlays[i];
            if (!o->used || o->id != op_u64(data) || o->tunnel_index != ti)
                continue;
            uint8_t plain[4096 + 64];
            size_t n = 0;
            if (op_crypt(0, c->apps[o->app_index].key, data + 8, len - 8, plain, sizeof(plain),
                         &n)) {
                close_overlay(c, i, 1);
                return;
            }
            o->activity = mono();
            if (o->udp) {
                ssize_t sent = o->local_udp
                                   ? sendto(o->fd, plain, n, MSG_DONTWAIT,
                                            (struct sockaddr *)&o->source, sizeof(o->source))
                                   : send(o->fd, plain, n, MSG_DONTWAIT | MSG_NOSIGNAL);
                if (sent != (ssize_t)n)
                    close_overlay(c, i, 1);
            } else if (op_buffer_add(&o->tx, plain, n, OP_QUEUE_LIMIT))
                close_overlay(c, i, 1);
            return;
        }
        return;
    }
    if (sub == 7 && len >= 8) {
        uint64_t aid = op_u64(data);
        /* The Go wire ACK identifies the application, not the overlay. Release
         * all pending connections for that application on this tunnel. */
        for (int i = 0; i < NO; ++i)
            if (c->overlays[i].used && c->overlays[i].tunnel_index == ti &&
                c->apps[c->overlays[i].app_index].id == aid)
                c->overlays[i].waiting = 0;
        return;
    }
    json_object *j = op_json(data, len);
    if (!j)
        return;
    uint64_t id = op_integer(j, "id");
    if (sub == 8) {
        for (int i = 0; i < NO; ++i)
            if (c->overlays[i].used && c->overlays[i].id == id &&
                c->overlays[i].tunnel_index == ti) {
                overlay *o = &c->overlays[i];
                if (!o->udp && op_buffer_size(&o->tx)) {
                    /* A disconnect can follow the final data frame in the same
                     * read. Preserve those bytes until the local TCP write drains. */
                    o->peer_closed = 1;
                    o->waiting = 0;
                    o->deadline = mono() + 30 * NS;
                } else
                    close_overlay(c, i, 0);
            }
    } else if (sub == 6 && id && op_integer(j, "token") == c->token &&
               !op_integer(j, "relayTunnelID")) {
        uint64_t aid = op_integer(j, "appID"), port = op_integer(j, "dstPort");
        int ai = -1, duplicate = 0;
        for (int i = 0; i < NO; ++i)
            if (c->overlays[i].used && c->overlays[i].id == id && c->overlays[i].tunnel_index == ti)
                duplicate = 1;
        for (int i = 0; i < NA; ++i)
            if (c->apps[i].used && c->apps[i].id == aid && c->apps[i].tunnel_index == ti &&
                !c->apps[i].local) {
                ai = i;
                break;
            }
        const char *proto = op_string(j, "protocol"), *host = op_string(j, "dstIP");
        if (!duplicate && ai >= 0 && port > 0 && port <= 65535 && strlen(host) < 256 &&
            (!strcmp(proto, "tcp") || !strcmp(proto, "udp"))) {
            struct sockaddr_in peer;
            int oi = overlay_slot(c);
            if (oi >= 0) {
                overlay *o = &c->overlays[oi];
                o->id = id;
                o->app_index = ai;
                o->tunnel_index = ti;
                o->udp = !strcmp(proto, "udp");
                if (resolve4(host, (uint16_t)port, &peer) ||
                    (o->fd = socket_bound(o->udp, NULL, 0, 0)) < 0 ||
                    (connect(o->fd, (struct sockaddr *)&peer, sizeof(peer)) &&
                     errno != EINPROGRESS))
                    close_overlay(c, oi, 1);
                else if (o->udp) {
                    o->connected = 1;
                    uint8_t ack[12];
                    op_put64(ack, aid);
                    memcpy(ack + 8, "null", 4);
                    tframe(t, 7, ack, sizeof(ack));
                }
            }
        }
    }
    json_object_put(j);
}
static void read_tunnel_frames(op2p_client *c, int ti) {
    tunnel *t = &c->tunnels[ti];
    for (int i = 0; i < 64 && t->state; ++i) {
        uint16_t main, sub;
        uint8_t *body = NULL;
        size_t len;
        int rv = op_frame_take(&t->rx, &main, &sub, &body, &len);
        if (rv < 0) {
            close_tunnel(c, ti, "invalid or oversized peer frame");
            break;
        }
        if (!rv)
            break;
        if (main == 4)
            tunnel_message(c, ti, sub, body, len);
        free(body);
    }
}
static void accept_punch(op2p_client *c, int ti) {
    tunnel *t = &c->tunnels[ti];
    if (t->listen_fd < 0 || (t->state != T_TCP_CONNECT && t->state != T_HANDSHAKE))
        return;
    struct sockaddr_in peer;
    socklen_t length = sizeof(peer);
    int fd = accept4(t->listen_fd, (struct sockaddr *)&peer, &length, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0)
        return;
    struct in_addr expected;
    inet_pton(AF_INET, t->ip, &expected);
    if (peer.sin_addr.s_addr != expected.s_addr || ntohs(peer.sin_port) != t->remote_port) {
        close(fd);
        return;
    }
    if (!t->server && t->state == T_TCP_CONNECT) {
        if (t->fd >= 0)
            close(t->fd);
        t->fd = fd;
        t->state = T_HANDSHAKE;
        close(t->listen_fd);
        t->listen_fd = -1;
        uint8_t id[8];
        op_put64(id, t->id);
        tframe(t, 2, id, 8);
    } else if (t->server && t->alternate_fd < 0)
        t->alternate_fd = fd;
    else
        close(fd);
}
static void read_alternate(op2p_client *c, int ti) {
    tunnel *t = &c->tunnels[ti];
    if (t->alternate_fd < 0)
        return;
    int bad = read_socket(t->alternate_fd, &t->alternate_rx, 4096);
    uint16_t main, sub;
    uint8_t *body = NULL;
    size_t len;
    int rv = bad ? 0 : op_frame_take(&t->alternate_rx, &main, &sub, &body, &len);
    if (rv > 0 && main == 4 && sub == 2 && len == 8 && op_u64(body) == t->id) {
        if (t->fd >= 0)
            close(t->fd);
        t->fd = t->alternate_fd;
        t->alternate_fd = -1;
        op_buffer_clear(&t->rx);
        t->rx = t->alternate_rx;
        memset(&t->alternate_rx, 0, sizeof(t->alternate_rx));
        tframe(t, 3, body, len);
        tunnel_active(c, ti);
    } else if (bad || rv) {
        close(t->alternate_fd);
        t->alternate_fd = -1;
        op_buffer_clear(&t->alternate_rx);
    }
    free(body);
}
static void tick_tunnel(op2p_client *c, int ti, uint64_t now) {
    tunnel *t = &c->tunnels[ti];
    if (!t->state)
        return;
    if (t->state != T_ACTIVE && now > t->deadline) {
        close_tunnel(c, ti, "tunnel establishment timed out");
        return;
    }
    if (t->state == T_NAT_CONNECT) {
        int rv = connect_ready(t->fd);
        if (rv < 0) {
            close_tunnel(c, ti, "TCP NAT connection failed");
            return;
        }
        if (rv > 0) {
            if (send(t->fd, "1", 1, MSG_NOSIGNAL) != 1) {
                close_tunnel(c, ti, "TCP NAT marker failed");
                return;
            }
            t->state = T_NAT_READ;
        }
    }
    if (t->state == T_NAT_READ) {
        ssize_t n =
            recv(t->fd, t->probe + t->probe_len, sizeof(t->probe) - 1 - t->probe_len, MSG_DONTWAIT);
        if (n > 0) {
            t->probe_len += (size_t)n;
            t->probe[t->probe_len] = 0;
            t->last_rx = now;
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            close_tunnel(c, ti, "TCP NAT response failed");
            return;
        }
        if (t->probe_len && now - t->last_rx >= 20 * MS) {
            char ip[INET_ADDRSTRLEN], extra;
            unsigned port;
            if (sscanf(t->probe, "%15[0-9.]:%u%c", ip, &port, &extra) != 2 || !port ||
                port > 65535) {
                close_tunnel(c, ti, "invalid TCP NAT response");
                return;
            }
            struct in_addr address;
            if (inet_pton(AF_INET, ip, &address) != 1) {
                close_tunnel(c, ti, "invalid TCP NAT address");
                return;
            }
            strcpy(c->ip, ip);
            t->mapped_port = (uint16_t)port;
            probe_complete(c, ti);
        }
    }
    if (t->state == T_NAT_UDP) {
        uint8_t data[1024];
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        ssize_t n =
            recvfrom(t->fd, data, sizeof(data), MSG_DONTWAIT, (struct sockaddr *)&from, &flen);
        if (n >= 8 && from.sin_addr.s_addr == c->gateway.sin_addr.s_addr &&
            from.sin_port == htons(27180) && op_u16(data + 4) == 2 &&
            op_u32(data) == (uint32_t)(n - 8)) {
            json_object *j = op_json(data + 8, (size_t)n - 8);
            uint64_t port = op_integer(j, "port");
            if (j)
                json_object_put(j);
            if (port > 0 && port <= 65535) {
                t->mapped_port = (uint16_t)port;
                probe_complete(c, ti);
            }
        }
    }
    if (t->state == T_TIME && now >= t->at) {
        if (t->transport == OP2P_TRANSPORT_QUIC && !strcmp(t->mode, "udppunch")) {
            t->state = T_PUNCH;
            t->punch_next = 0;
        } else
            start_underlay(c, ti);
    }
    if (t->state == T_PUNCH) {
        struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(t->remote_port)};
        inet_pton(AF_INET, t->ip, &peer.sin_addr);
        json_object *j = json_object_new_object();
        op_ju(j, "id", t->id);
        if (now >= t->punch_next) {
            udp_packet(t->fd, &peer, 4, 0, j);
            t->punch_next = now + 200 * MS;
        }
        for (int k = 0; k < 8 && t->state == T_PUNCH; ++k) {
            uint8_t data[1024];
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            ssize_t n =
                recvfrom(t->fd, data, sizeof(data), MSG_DONTWAIT, (struct sockaddr *)&from, &flen);
            if (n < 0)
                break;
            if (n < 8 || op_u32(data) != (uint32_t)(n - 8) || op_u16(data + 4) != 4 ||
                op_u16(data + 6) > 1 || from.sin_addr.s_addr != peer.sin_addr.s_addr)
                continue;
            json_object *r = op_json(data + 8, (size_t)n - 8);
            uint64_t id = op_integer(r, "id");
            if (r)
                json_object_put(r);
            if (id != t->id)
                continue;
            t->remote_port = ntohs(from.sin_port);
            peer = from;
            udp_packet(t->fd, &peer, 4, 1, j);
            if (op_u16(data + 6) == 1)
                start_underlay(c, ti);
        }
        json_object_put(j);
    }
    if (t->state == T_UNDERLAY && t->notified)
        start_underlay(c, ti);
    if (t->state == T_TCP_CONNECT) {
        int rv = t->fd >= 0 ? connect_ready(t->fd) : 0;
        if (rv < 0) {
            if (t->listen_fd < 0) {
                close_tunnel(c, ti, "TCP simultaneous connection failed");
                return;
            }
            close(t->fd);
            t->fd = -1;
        }
        if (rv > 0) {
            t->state = T_HANDSHAKE;
            if (!t->server) {
                if (t->listen_fd >= 0)
                    close(t->listen_fd);
                t->listen_fd = -1;
                uint8_t id[8];
                op_put64(id, t->id);
                tframe(t, 2, id, 8);
            }
        }
    }
    accept_punch(c, ti);
    if (t->quic) {
        if (opq_step(t->quic)) {
            close_tunnel(c, ti, opq_error(t->quic));
            return;
        }
        if (op_buffer_size(&t->tx) && opq_pending(t->quic) < OP_QUEUE_LIMIT / 2) {
            size_t n = op_buffer_size(&t->tx);
            if (opq_write(t->quic, t->tx.data + t->tx.offset, n)) {
                close_tunnel(c, ti, "QUIC write queue full");
                return;
            }
            op_buffer_consume(&t->tx, n);
        }
        uint8_t bytes[16384];
        size_t n;
        while ((n = opq_read(t->quic, bytes, sizeof(bytes))))
            if (op_buffer_add(&t->rx, bytes, n, OP_QUEUE_LIMIT)) {
                close_tunnel(c, ti, "peer receive queue full");
                return;
            }
        read_tunnel_frames(c, ti);
    } else if ((t->state == T_HANDSHAKE || t->state == T_ACTIVE) && t->fd >= 0) {
        if (flush(t->fd, &t->tx) || read_socket(t->fd, &t->rx, OP_QUEUE_LIMIT)) {
            if (t->listen_fd < 0) {
                close_tunnel(c, ti, "TCP tunnel closed");
                return;
            }
            close(t->fd);
            t->fd = -1;
            op_buffer_clear(&t->rx);
        } else
            read_tunnel_frames(c, ti);
    }
    if (t->state && t->state != T_ACTIVE)
        read_alternate(c, ti);
    if (t->state == T_ACTIVE) {
        if (now >= t->last_rx && now - t->last_rx > 30 * NS) {
            close_tunnel(c, ti, "peer heartbeat timed out");
            return;
        }
        if (now >= t->last_hb && now - t->last_hb >= 10 * NS) {
            tframe(t, 4, NULL, 0);
            t->last_hb = now;
        }
    }
}
static void tick_accept(op2p_client *c, uint64_t now) {
    for (int k = 0; k < 8; ++k) {
        struct sockaddr_in peer;
        socklen_t len = sizeof(peer);
        int fd = accept4(c->listener, (struct sockaddr *)&peer, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0)
            break;
        int i;
        for (i = 0; i < NP; ++i)
            if (c->pending[i].fd < 0)
                break;
        if (i == NP)
            close(fd);
        else {
            c->pending[i].fd = fd;
            c->pending[i].peer = peer;
            c->pending[i].deadline = now + 3 * NS;
        }
    }
    for (int i = 0; i < NP; ++i) {
        pending *p = &c->pending[i];
        if (p->fd < 0)
            continue;
        int remove = now > p->deadline || read_socket(p->fd, &p->rx, 4096);
        uint16_t main, sub;
        uint8_t *body = NULL;
        size_t len;
        int rv = remove ? 0 : op_frame_take(&p->rx, &main, &sub, &body, &len);
        if (rv < 0)
            remove = 1;
        if (rv > 0) {
            int ti = main == 4 && sub == 2 && len == 8 ? tunnel_by_id(c, op_u64(body)) : -1;
            if (ti >= 0) {
                tunnel *t = &c->tunnels[ti];
                struct in_addr ip;
                inet_pton(AF_INET, t->ip, &ip);
                if (t->state == T_DIRECT && t->server && ip.s_addr == p->peer.sin_addr.s_addr) {
                    t->fd = p->fd;
                    p->fd = -1;
                    tframe(t, 3, body, len);
                    tunnel_active(c, ti);
                    if (op_buffer_size(&p->rx))
                        op_buffer_add(&t->rx, p->rx.data + p->rx.offset, op_buffer_size(&p->rx),
                                      OP_QUEUE_LIMIT);
                }
            }
            free(body);
            remove = 1;
        }
        if (remove) {
            if (p->fd >= 0)
                close(p->fd);
            p->fd = -1;
            op_buffer_clear(&p->rx);
        }
    }
}
static void tick_overlays(op2p_client *c, uint64_t now) {
    for (int i = 0; i < NO; ++i) {
        overlay *o = &c->overlays[i];
        if (!o->used)
            continue;
        if (c->tunnels[o->tunnel_index].state != T_ACTIVE ||
            ((!o->connected || o->waiting || o->peer_closed) && now > o->deadline) ||
            (o->udp && now >= o->activity && now - o->activity > 300 * NS)) {
            close_overlay(c, i, 1);
            continue;
        }
        if (!o->connected) {
            int rv = connect_ready(o->fd);
            if (rv < 0) {
                close_overlay(c, i, 1);
                continue;
            }
            if (!rv)
                continue;
            o->connected = 1;
            uint8_t ack[12];
            op_put64(ack, c->apps[o->app_index].id);
            memcpy(ack + 8, "null", 4);
            tframe(&c->tunnels[o->tunnel_index], 7, ack, sizeof(ack));
        }
        if (o->waiting)
            continue;
        while (op_buffer_size(&o->early) >= 2) {
            size_t len = op_u16(o->early.data + o->early.offset);
            if (op_buffer_size(&o->early) < len + 2 ||
                overlay_data(c, i, o->early.data + o->early.offset + 2, len)) {
                close_overlay(c, i, 1);
                break;
            }
            op_buffer_consume(&o->early, len + 2);
        }
        if (!o->used)
            continue;
        if (o->local_udp)
            continue;
        if (!o->udp && flush(o->fd, &o->tx)) {
            close_overlay(c, i, 1);
            continue;
        }
        if (o->peer_closed) {
            if (!op_buffer_size(&o->tx))
                close_overlay(c, i, 0);
            continue;
        }
        tunnel *t = &c->tunnels[o->tunnel_index];
        if (op_buffer_size(&t->tx) > OP_QUEUE_LIMIT / 2 ||
            (t->quic && opq_pending(t->quic) > OP_QUEUE_LIMIT / 2))
            continue;
        for (int k = 0; k < 8; ++k) {
            uint8_t data[4096];
            ssize_t n = recv(o->fd, data, sizeof(data), MSG_DONTWAIT);
            if (n > 0 || (n == 0 && o->udp)) {
                if (overlay_data(c, i, data, (size_t)n)) {
                    close_overlay(c, i, 1);
                    break;
                }
            } else if (!n) {
                close_overlay(c, i, 1);
                break;
            } else if (errno == EINTR)
                continue;
            else if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            else {
                close_overlay(c, i, 1);
                break;
            }
        }
    }
}
static void tick_apps(op2p_client *c, uint64_t now) {
    for (int i = 0; i < NA; ++i) {
        app *a = &c->apps[i];
        if (!a->used || !a->local)
            continue;
        if (a->tunnel_index < 0 && now >= a->retry && c->state == OP2P_ONLINE) {
            int ti = active_tunnel(c, a->peer, a->transport);
            if (ti >= 0) {
                a->tunnel_index = ti;
                synchronize_app(c, i);
            } else {
                int in_progress = 0;
                for (int k = 0; k < NT; ++k)
                    if (c->tunnels[k].state && c->tunnels[k].transport == a->transport &&
                        !strcmp(c->tunnels[k].peer, a->peer))
                        in_progress = 1;
                if (!in_progress) {
                    ti = new_tunnel(c, a->peer, random_id(), a->transport, 1);
                    if (ti >= 0) {
                        tunnel *t = &c->tunnels[ti];
                        strcpy(t->mode,
                               a->transport == OP2P_TRANSPORT_TCP ? "tcppunch" : "udppunch");
                        json_object *j = json_object_new_object();
                        op_ju(j, "token", c->token);
                        op_js(j, "peerNode", a->peer);
                        ws_json(c, 7, 0, j);
                        json_object_put(j);
                        if (start_probe(c, ti))
                            close_tunnel(c, ti, "NAT probe could not start");
                    }
                }
                a->retry = now + 2 * NS;
            }
        }
        if (a->tunnel_index < 0 || !a->synced || now < a->ready_at)
            continue;
        if (!a->udp) {
            for (int k = 0; k < 4; ++k) {
                int fd = accept4(a->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (fd < 0)
                    break;
                int oi = overlay_slot(c);
                if (oi < 0) {
                    close(fd);
                    break;
                }
                overlay *o = &c->overlays[oi];
                o->fd = fd;
                o->id = random_id();
                o->app_index = i;
                o->tunnel_index = a->tunnel_index;
                o->connected = 1;
                request_overlay(c, oi);
            }
        } else {
            for (int k = 0; k < 8; ++k) {
                uint8_t data[4097];
                struct sockaddr_in from;
                socklen_t flen = sizeof(from);
                ssize_t n = recvfrom(a->fd, data, sizeof(data), MSG_DONTWAIT,
                                     (struct sockaddr *)&from, &flen);
                if (n < 0)
                    break;
                if (n > 4096) {
                    emit(c, OP2P_EVENT_ERROR, a->id, OP2P_ELIMIT,
                         "UDP application datagram exceeds 4096 bytes");
                    continue;
                }
                int oi = -1;
                for (int q = 0; q < NO; ++q)
                    if (c->overlays[q].used && c->overlays[q].local_udp &&
                        c->overlays[q].app_index == i &&
                        c->overlays[q].source.sin_addr.s_addr == from.sin_addr.s_addr &&
                        c->overlays[q].source.sin_port == from.sin_port) {
                        oi = q;
                        break;
                    }
                if (oi < 0) {
                    oi = overlay_slot(c);
                    if (oi < 0)
                        break;
                    overlay *o = &c->overlays[oi];
                    o->fd = a->fd;
                    o->local_udp = o->udp = o->connected = 1;
                    o->source = from;
                    o->id = random_id();
                    o->app_index = i;
                    o->tunnel_index = a->tunnel_index;
                    request_overlay(c, oi);
                }
                overlay *o = &c->overlays[oi];
                if (o->waiting) {
                    uint8_t packet[4098];
                    op_put16(packet, (uint16_t)n);
                    memcpy(packet + 2, data, (size_t)n);
                    if (op_buffer_add(&o->early, packet, (size_t)n + 2, 65536))
                        close_overlay(c, oi, 1);
                } else if (overlay_data(c, oi, data, (size_t)n))
                    close_overlay(c, oi, 1);
            }
        }
    }
}
static void send_heartbeat(op2p_client *c) {
    c->heartbeat_sent = wall();
    c->heartbeat_at = mono();
    ws_json(c, 1, 0, NULL);
}
static pthread_once_t curl_once = PTHREAD_ONCE_INIT;
static CURLcode curl_initialization;
static void initialize_curl(void) {
    curl_initialization = curl_global_init(CURL_GLOBAL_DEFAULT);
}
static void close_gateway(op2p_client *c) {
    if (c->ws) {
        curl_multi_remove_handle(c->multi, c->ws);
        curl_easy_cleanup(c->ws);
        c->ws = NULL;
    }
    if (c->resolve) {
        curl_slist_free_all(c->resolve);
        c->resolve = NULL;
    }
    c->ws_connected = 0;
    c->ws_socket = CURL_SOCKET_BAD;
    c->ws_remaining = 0;
    c->login_ok = c->report_ok = 0;
    op_buffer_clear(&c->ws_rx);
    op_buffer_clear(&c->ws_tx);
    for (int i = 0; i < NT; ++i)
        close_tunnel(c, i, NULL);
    if (c->running && !c->stopping) {
        unsigned shift = c->reconnect_attempt < 5 ? (unsigned)c->reconnect_attempt++ : 5;
        c->reconnect_at = mono() + ((uint64_t)1 << shift) * NS;
        set_state(c, OP2P_RECONNECTING, "gateway disconnected; retry scheduled");
    }
}
static void gateway_failed(op2p_client *c) {
    emit(c, OP2P_EVENT_ERROR, 0, OP2P_EIO,
         "WSS connection failed: check gateway address, CA, certificate hostname and token");
    close_gateway(c);
}
static void connect_gateway(op2p_client *c) {
    c->ws = curl_easy_init();
    if (!c->ws) {
        gateway_failed(c);
        return;
    }
    snprintf(c->path, sizeof(c->path),
             "wss://%s:%u/api/v1/login?node=%s&token=%" PRIu64
             "&version=%s&nattype=%d&sharebandwidth=0",
             c->host, c->port, c->node, c->token, COMPAT_VERSION, c->nat_type);
    char address[INET_ADDRSTRLEN], resolve[320];
    inet_ntop(AF_INET, &c->gateway.sin_addr, address, sizeof(address));
    snprintf(resolve, sizeof(resolve), "%s:%u:%s", c->host, c->port, address);
    c->resolve = curl_slist_append(NULL, resolve);
    if (!c->resolve) {
        gateway_failed(c);
        return;
    }
#define SETOPT(option, value)                                                                      \
    do {                                                                                           \
        if (curl_easy_setopt(c->ws, (option), (value)) != CURLE_OK) {                              \
            gateway_failed(c);                                                                     \
            return;                                                                                \
        }                                                                                          \
    } while (0)
    SETOPT(CURLOPT_URL, c->path);
    SETOPT(CURLOPT_RESOLVE, c->resolve);
    SETOPT(CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    SETOPT(CURLOPT_CONNECT_ONLY, 2L);
    SETOPT(CURLOPT_CONNECTTIMEOUT_MS, 10000L);
    SETOPT(CURLOPT_NOSIGNAL, 1L);
    SETOPT(CURLOPT_PROXY, "");
    SETOPT(CURLOPT_SSL_VERIFYPEER, 1L);
    SETOPT(CURLOPT_SSL_VERIFYHOST, 2L);
    SETOPT(CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_2);
    SETOPT(CURLOPT_PROTOCOLS_STR, "wss");
    if (c->ca[0])
        SETOPT(CURLOPT_CAINFO, c->ca);
#undef SETOPT
    if (curl_multi_add_handle(c->multi, c->ws) != CURLM_OK)
        gateway_failed(c);
}
static void service_gateway(op2p_client *c) {
    int active = 0;
    if (curl_multi_perform(c->multi, &active) != CURLM_OK) {
        gateway_failed(c);
        return;
    }
    int remaining;
    CURLMsg *message;
    while ((message = curl_multi_info_read(c->multi, &remaining))) {
        if (message->msg != CURLMSG_DONE || message->easy_handle != c->ws)
            continue;
        if (message->data.result != CURLE_OK ||
            curl_easy_getinfo(c->ws, CURLINFO_ACTIVESOCKET, &c->ws_socket) != CURLE_OK ||
            c->ws_socket == CURL_SOCKET_BAD) {
            gateway_failed(c);
            return;
        }
        c->ws_connected = 1;
        c->last_rx = mono();
        char *ip = NULL;
        if (curl_easy_getinfo(c->ws, CURLINFO_LOCAL_IP, &ip) == CURLE_OK && ip &&
            strlen(ip) < sizeof(c->local_ip))
            strcpy(c->local_ip, ip);
        json_object *j = json_object_new_object();
        op_js(j, "os", "linux-c");
        op_js(j, "version", COMPAT_VERSION);
        op_js(j, "lanIP", c->local_ip);
        op_ju(j, "publicIPPort", c->public_port);
        ws_json(c, 6, 0, j);
        json_object_put(j);
        send_heartbeat(c);
    }
    if (!c->ws || !c->ws_connected)
        return;
    for (int i = 0; i < 16 && op_buffer_size(&c->ws_tx); ++i) {
        size_t available = op_buffer_size(&c->ws_tx);
        const uint8_t *p = c->ws_tx.data + c->ws_tx.offset;
        int first = c->ws_remaining == 0;
        if (first) {
            if (available < 8 || op_u32(p) > OP_FRAME_LIMIT || available < 8 + op_u32(p)) {
                gateway_failed(c);
                return;
            }
            c->ws_remaining = 8 + op_u32(p);
        }
        size_t sent = 0;
        CURLcode rv =
            curl_ws_send(c->ws, p, c->ws_remaining, &sent, first ? (curl_off_t)c->ws_remaining : 0,
                         CURLWS_BINARY | CURLWS_OFFSET);
        if (sent > c->ws_remaining) {
            gateway_failed(c);
            return;
        }
        c->ws_remaining -= sent;
        op_buffer_consume(&c->ws_tx, sent);
        if (rv == CURLE_AGAIN)
            break;
        if (rv != CURLE_OK) {
            gateway_failed(c);
            return;
        }
        if (!sent)
            break;
    }
    for (int i = 0; i < 32; ++i) {
        uint8_t bytes[16384];
        size_t received = 0;
        const struct curl_ws_frame *meta = NULL;
        CURLcode rv = curl_ws_recv(c->ws, bytes, sizeof(bytes), &received, &meta);
        if (rv == CURLE_AGAIN)
            break;
        if (rv != CURLE_OK || !meta || (meta->flags & CURLWS_CLOSE)) {
            close_gateway(c);
            return;
        }
        if (meta->flags & (CURLWS_PING | CURLWS_PONG))
            continue;
        if (!(meta->flags & CURLWS_BINARY) ||
            op_buffer_add(&c->ws_rx, bytes, received, OP_FRAME_LIMIT + 8)) {
            gateway_failed(c);
            return;
        }
        if (!meta->bytesleft && !(meta->flags & CURLWS_CONT)) {
            uint16_t main, sub;
            uint8_t *body = NULL;
            size_t length;
            int result = op_frame_take(&c->ws_rx, &main, &sub, &body, &length);
            if (result != 1 || op_buffer_size(&c->ws_rx)) {
                free(body);
                gateway_failed(c);
                return;
            }
            control_message(c, main, sub, body, length);
            free(body);
            if (c->stopping)
                break;
        }
    }
}
static void tick_nat(op2p_client *c, uint64_t now) {
    if (c->nat_fd < 0)
        return;
    uint8_t data[1024];
    struct sockaddr_in from;
    socklen_t flen = sizeof(from);
    ssize_t n =
        recvfrom(c->nat_fd, data, sizeof(data), MSG_DONTWAIT, (struct sockaddr *)&from, &flen);
    uint16_t expected = (uint16_t)(27179 + c->nat_phase);
    int finish = 0;
    if (n >= 8 && from.sin_addr.s_addr == c->gateway.sin_addr.s_addr &&
        from.sin_port == htons(expected) && op_u16(data + 4) == 2 &&
        op_u32(data) == (uint32_t)(n - 8)) {
        json_object *j = op_json(data + 8, (size_t)n - 8);
        uint64_t port = op_integer(j, "port");
        struct in_addr ip;
        if (port > 0 && port <= 65535 && inet_pton(AF_INET, op_string(j, "IP"), &ip) == 1) {
            strcpy(c->ip, op_string(j, "IP"));
            if (c->nat_phase == 1) {
                c->nat_port = (uint16_t)port;
                c->nat_phase = 2;
                c->nat_deadline = now + 2 * NS;
                struct sockaddr_in peer = c->gateway;
                peer.sin_port = htons(27181);
                udp_packet(c->nat_fd, &peer, 2, 0, NULL);
            } else {
                c->nat_type = c->nat_port == port ? 1 : 2;
                finish = 1;
            }
        }
        if (j)
            json_object_put(j);
    }
    if (now > c->nat_deadline) {
        c->nat_type = 314;
        finish = 1;
        emit(c, OP2P_EVENT_ERROR, 0, OP2P_EIO,
             "UDP NAT discovery unavailable; TCP transport can still be attempted");
    }
    if (finish) {
        close(c->nat_fd);
        c->nat_fd = -1;
        connect_gateway(c);
    }
}
uint32_t op2p_abi_version(void) {
    return OP2P_ABI_VERSION;
}
const char *op2p_version(void) {
    return OP2P_VERSION;
}
int op2p_client_create(const op2p_config *cfg, op2p_client **out) {
    if (!out)
        return OP2P_EINVAL;
    *out = NULL;
    if (!cfg || cfg->struct_size < sizeof(*cfg) || cfg->abi_version != OP2P_ABI_VERSION ||
        !valid_node(cfg->node) || !cfg->token || !cfg->gateway_host || !*cfg->gateway_host)
        return OP2P_EINVAL;
    op2p_client *c = calloc(1, sizeof(*c));
    if (!c)
        return OP2P_ENOMEM;
    if (copy_string(c->host, sizeof(c->host), cfg->gateway_host) ||
        copy_string(c->node, sizeof(c->node), cfg->node) ||
        (cfg->ca_file && copy_string(c->ca, sizeof(c->ca), cfg->ca_file))) {
        free(c);
        return OP2P_EINVAL;
    }
    for (const char *p = c->host; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
              *p == '.' || *p == '-' || *p == '_')) {
            free(c);
            return OP2P_EINVAL;
        }
    c->port = cfg->gateway_port ? cfg->gateway_port : 27183;
    c->public_port = cfg->public_port;
    c->token = cfg->token;
    c->node_id = op_node_id(c->node);
    c->callback = cfg->on_event;
    c->user = cfg->user;
    c->listener = c->nat_fd = -1;
    strcpy(c->ip, "0.0.0.0");
    strcpy(c->local_ip, "0.0.0.0");
    for (int i = 0; i < NT; ++i)
        c->tunnels[i].fd = c->tunnels[i].listen_fd = c->tunnels[i].alternate_fd = -1;
    for (int i = 0; i < NA; ++i) {
        c->apps[i].fd = -1;
        c->apps[i].tunnel_index = -1;
    }
    for (int i = 0; i < NP; ++i)
        c->pending[i].fd = -1;
    *out = c;
    return OP2P_OK;
}
int op2p_client_add_forward(op2p_client *c, const op2p_forward *f, uint64_t *id) {
    if (!c || !f || f->struct_size < sizeof(*f) || c->in_callback || !valid_node(f->peer_node) ||
        !strcmp(f->peer_node, c->node) || !f->local_port || !f->destination_port ||
        !f->destination_host || !*f->destination_host || !f->protocol ||
        (strcmp(f->protocol, "tcp") && strcmp(f->protocol, "udp")) ||
        (f->transport != OP2P_TRANSPORT_TCP && f->transport != OP2P_TRANSPORT_QUIC))
        return OP2P_EINVAL;
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used && c->apps[i].local && c->apps[i].port == f->local_port &&
            c->apps[i].udp == !strcmp(f->protocol, "udp"))
            return OP2P_ESTATE;
    for (int i = 0; i < NA; ++i)
        if (!c->apps[i].used) {
            app *a = &c->apps[i];
            memset(a, 0, sizeof(*a));
            a->fd = -1;
            a->tunnel_index = -1;
            if (copy_string(a->peer, sizeof(a->peer), f->peer_node) ||
                copy_string(a->destination, sizeof(a->destination), f->destination_host) ||
                copy_string(a->bind_ip, sizeof(a->bind_ip),
                            f->bind_ip ? f->bind_ip : "127.0.0.1") ||
                copy_string(a->name, sizeof(a->name), f->name ? f->name : "forward"))
                return OP2P_EINVAL;
            struct in_addr check;
            if (inet_pton(AF_INET, a->bind_ip, &check) != 1)
                return OP2P_EINVAL;
            a->id = random_id();
            a->key = random_id();
            a->port = f->local_port;
            a->dst_port = f->destination_port;
            a->udp = !strcmp(f->protocol, "udp");
            a->transport = f->transport;
            a->local = a->used = 1;
            a->fd = socket_bound(a->udp, a->bind_ip, a->port, 0);
            if (a->fd < 0 || (!a->udp && listen(a->fd, 64))) {
                if (a->fd >= 0)
                    close(a->fd);
                a->used = 0;
                return OP2P_EIO;
            }
            if (id)
                *id = a->id;
            return OP2P_OK;
        }
    return OP2P_ELIMIT;
}
int op2p_client_start(op2p_client *c) {
    if (!c || c->in_callback || c->running || c->multi)
        return OP2P_ESTATE;
    pthread_once(&curl_once, initialize_curl);
    if (curl_initialization != CURLE_OK)
        return OP2P_EIO;
    if (resolve4(c->host, c->port, &c->gateway)) {
        emit(c, OP2P_EVENT_ERROR, 0, OP2P_EIO, "gateway DNS resolution failed");
        return OP2P_EIO;
    }
    c->listener = socket_bound(0, NULL, c->public_port, 1);
    if (c->listener < 0 || listen(c->listener, 32)) {
        if (c->listener >= 0)
            close(c->listener);
        c->listener = -1;
        return OP2P_EIO;
    }
    c->public_port = socket_port(c->listener);
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used && c->apps[i].local && c->apps[i].fd < 0) {
            app *a = &c->apps[i];
            a->fd = socket_bound(a->udp, a->bind_ip, a->port, 0);
            if (a->fd < 0 || (!a->udp && listen(a->fd, 64))) {
                op2p_client_stop(c);
                return OP2P_EIO;
            }
        }
    c->multi = curl_multi_init();
    if (!c->multi) {
        op2p_client_stop(c);
        return OP2P_EIO;
    }
    c->running = 1;
    c->stopping = 0;
    c->reconnect_at = 0;
    c->nat_type = 314;
    set_state(c, OP2P_CONNECTING, "discovering NAT and connecting to gateway");
    c->nat_fd = socket_bound(1, NULL, 0, 0);
    c->nat_phase = 1;
    c->nat_deadline = mono() + 2 * NS;
    struct sockaddr_in peer = c->gateway;
    peer.sin_port = htons(27180);
    if (c->nat_fd < 0)
        connect_gateway(c);
    else
        udp_packet(c->nat_fd, &peer, 2, 0, NULL);
    return OP2P_OK;
}
int op2p_client_step(op2p_client *c, unsigned wait_ms) {
    if (!c || !c->running || c->in_callback || c->stepping)
        return OP2P_ESTATE;
    c->stepping = 1;
    if (c->stopping) {
        c->stepping = 0;
        return op2p_client_stop(c);
    }
    uint64_t now = mono();
    tick_nat(c, now);
    if (!c->ws && c->nat_fd < 0 && c->reconnect_at && now >= c->reconnect_at) {
        c->reconnect_at = 0;
        connect_gateway(c);
    }
    if (c->ws && c->login_ok && now - c->heartbeat_at >= 15 * NS)
        send_heartbeat(c);
    if (c->ws && c->login_ok && now - c->last_rx > 45 * NS)
        close_gateway(c);
    service_gateway(c);
    tick_accept(c, now);
    for (int i = 0; i < NT; ++i)
        tick_tunnel(c, i, now);
    tick_apps(c, now);
    tick_overlays(c, now);
    if (wait_ms > 10)
        wait_ms = 10;
    if (wait_ms) {
        struct curl_waitfd extra = {0};
        unsigned count = 0;
        if (c->ws_connected) {
            extra.fd = c->ws_socket;
            extra.events = CURL_WAIT_POLLIN;
            if (op_buffer_size(&c->ws_tx))
                extra.events |= CURL_WAIT_POLLOUT;
            count = 1;
        }
        int events;
        curl_multi_poll(c->multi, &extra, count, (int)wait_ms, &events);
        service_gateway(c);
    }
    c->stepping = 0;
    if (c->stopping)
        return op2p_client_stop(c);
    return OP2P_OK;
}
int op2p_client_stop(op2p_client *c) {
    if (!c)
        return OP2P_EINVAL;
    if (c->in_callback || c->stepping) {
        c->stopping = 1;
        return OP2P_OK;
    }
    c->stopping = 1;
    c->running = 0;
    for (int i = 0; i < NT; ++i)
        close_tunnel(c, i, NULL);
    for (int i = 0; i < NP; ++i) {
        if (c->pending[i].fd >= 0)
            close(c->pending[i].fd);
        c->pending[i].fd = -1;
        op_buffer_clear(&c->pending[i].rx);
    }
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used && c->apps[i].local && c->apps[i].fd >= 0) {
            close(c->apps[i].fd);
            c->apps[i].fd = -1;
        }
    if (c->listener >= 0)
        close(c->listener);
    c->listener = -1;
    if (c->nat_fd >= 0)
        close(c->nat_fd);
    c->nat_fd = -1;
    close_gateway(c);
    if (c->multi) {
        curl_multi_cleanup(c->multi);
        c->multi = NULL;
    }
    c->ws = NULL;
    op_buffer_clear(&c->ws_rx);
    op_buffer_clear(&c->ws_tx);
    c->login_ok = c->report_ok = 0;
    set_state(c, OP2P_STOPPED, "client stopped");
    return OP2P_OK;
}
void op2p_client_destroy(op2p_client *c) {
    if (!c || c->in_callback || c->stepping)
        return;
    op2p_client_stop(c);
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used && c->apps[i].local && c->apps[i].fd >= 0)
            close(c->apps[i].fd);
    OPENSSL_cleanse(c, sizeof(*c));
    free(c);
}
op2p_state op2p_client_state(const op2p_client *c) {
    return c ? c->state : OP2P_STOPPED;
}
const char *op2p_client_last_error(const op2p_client *c) {
    return c ? c->error : "invalid client";
}
