#include "platform.h"
#include "fastp2p.h"
#include "wire.h"
#include "quic.h"
#include "socks.h"
#include "secure.h"
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>
#include <openssl/rand.h>

#define NT 32
#define NA 64
#define NO 256
#define NP 16
#define NPK 32
#define NRL 32
/* Sessions this node is willing to relay for at once. */
#define RELAY_SESSION_LIMIT 4
#define NS UINT64_C(1000000000)
#define MS UINT64_C(1000000)
#define WIRE_VERSION FASTP2P_VERSION
#define WIRE_PROTOCOL "fastp2p2"
/* Tunnel frames.  Frames carrying application data or application control are
 * sealed with the session keys; handshake, keepalive and relay joining are
 * plaintext because they precede, or are handled outside, the session. */
enum {
    TUN_HELLO = 2,
    TUN_HELLO_ACK = 3,
    TUN_KEEPALIVE = 4,
    TUN_KEEPALIVE_ACK = 5,
    TUN_OPEN = 6,
    TUN_OPEN_ACK = 7,
    TUN_CLOSE = 8,
    TUN_DATA = 9,
    TUN_RELAY_JOIN = 10,
    TUN_RELAY_READY = 11,
    TUN_CERT_BIND = 12
};
/* Control-plane push sub-codes between two clients. */
enum {
    PUSH_CONNECT = 1,
    PUSH_CONNECT_REPLY = 2,
    PUSH_APPS = 7,
    PUSH_READY = 8,
    PUSH_RULE = 9,
    PUSH_SESSION = 13,
    PUSH_SESSION_ACK = 14,
    PUSH_ONLINE = 15
};
enum { S_NONE, S_HANDSHAKE, S_TUNNEL, S_ACK, S_STREAM, S_UDP, S_CLOSING, S_FLOW };
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
    int state, server, initiator, transport, notified;
    op_socket fd, listen_fd, alternate_fd;
    uint64_t id, peer_id, deadline, at, last_rx, last_hb, punch_next;
    uint64_t active_at;
    char peer[32], ip[INET_ADDRSTRLEN], mode[16], probe[96];
    uint16_t local_port, mapped_port, remote_port;
    size_t probe_len;
    op_buffer rx, tx, alternate_rx;
    opq *quic;
    /* One encrypted session per tunnel.  The initiator creates the session and
     * its secret; the responder installs both from the gateway push. */
    uint64_t session;
    uint8_t secret[FP_SESSION_SECRET];
    int has_secret, keyed, key_acked, relay_wait, session_owner;
    int lan;
    fp_crypto crypto;
    /* Relay role: forward this tunnel's application frames to a paired tunnel. */
    int relay_link;
    int relay_ready;
    char relay_peer[32];
    int cert_sent, cert_checked;
} tunnel;
typedef struct {
    int used, local, udp, transport, tunnel_index, synced, socks;
    op_socket fd;
    uint64_t id, retry, ready_at;
    char name[64], peer[32], destination[256], bind_ip[INET_ADDRSTRLEN];
    char socks_user[256], socks_password[256];
    uint16_t port, dst_port;
    int attempts, relay_wanted, relay_requested;
    uint64_t peer_nat, link_deadline;
    /* Relays that already failed for this rule; the gateway is asked to skip
     * them so one unreachable candidate cannot pin the link forever. */
    char relay_failed[4][32];
    int relay_failed_count;
    char peer_lan[INET_ADDRSTRLEN];
    /* The session belongs to the rule so the secret survives a failed punch and
     * can be reused when the same link falls back to a relay. */
    uint64_t session;
    uint8_t secret[FP_SESSION_SECRET];
    int has_session;
} app;
typedef struct {
    int used, udp, connected, local_udp, app_index, tunnel_index, waiting, peer_closed;
    op_socket fd;
    uint64_t id, activity, deadline;
    struct sockaddr_in source;
    op_buffer tx, early, socks_rx;
    int socks_state, socks_exit;
    op_socket socks_udp;
    uint64_t socks_parent;
    op_socks socks;
    struct sockaddr_in socks_peer;
} overlay;
typedef struct {
    op_socket fd;
    uint64_t deadline;
    struct sockaddr_in peer;
    op_buffer rx;
} pending;
/* A session secret received from the initiating peer before its tunnel is
 * usable.  Pending entries expire so a failed punch cannot leak state. */
typedef struct {
    int used, transport;
    uint64_t session, peer_id, deadline;
    uint8_t secret[FP_SESSION_SECRET];
    char relay[32];
} pending_key;
/* Relay bookkeeping: two tunnels joined with the same session are spliced
 * together and forward each other's application frames verbatim. */
typedef struct {
    int used;
    uint64_t session, peer_a, peer_b, deadline;
    int ta, tb;
} relay_link;
struct fastp2p_client {
    char host[256], ca[4096], node[32], ip[INET_ADDRSTRLEN], local_ip[INET_ADDRSTRLEN];
    char error[192], path[2048], hostname[256], device_id[33];
    int automatic_node;
    uint16_t port, public_port;
    uint64_t token, node_id, reconnect_at, last_rx, heartbeat_at, heartbeat_sent;
    int64_t clock_delta;
    fastp2p_state state;
    int running, stopping, in_callback, stepping, report_ok, login_ok, reconnect_attempt;
    int nat_phase, nat_type;
    int force_relay; /* FASTP2P_FORCE_RELAY diagnostic switch */
    op_socket listener, nat_fd;
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
    fastp2p_event_fn callback;
    void *user;
    tunnel tunnels[NT];
    app apps[NA];
    overlay overlays[NO];
    pending pending[NP];
    pending_key keys[NPK];
    relay_link relays[NRL];
};
static void connect_gateway(fastp2p_client *);
static void control_message(fastp2p_client *, uint16_t, uint16_t, const uint8_t *, size_t);
static void close_tunnel(fastp2p_client *, int, const char *);
static void release_relay(fastp2p_client *, int);
static void bind_pending_key(fastp2p_client *, int);
static void relay_join(fastp2p_client *, int);
static void session_ready(fastp2p_client *, int);
static void probe_complete(fastp2p_client *, int);
static void close_overlay(fastp2p_client *, int, int);
static void tunnel_message(fastp2p_client *, int, uint16_t, const uint8_t *, size_t);
static void socks_failure(fastp2p_client *, int, unsigned);
static void overlay_ack(fastp2p_client *, int, unsigned);
static void socks_udp_reply(fastp2p_client *, int, const uint8_t *, size_t);
static void socks_acknowledged(fastp2p_client *, int, json_object *);
static uint64_t mono(void) {
    return op_monotonic_ns();
}
static uint64_t wall(void) {
    return op_wall_ns();
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
static int private_address(uint32_t be) {
    uint32_t a = ntohl(be);
    if ((a & 0xFF000000u) == 0x0A000000u)
        return 1; /* 10/8 */
    if ((a & 0xFFF00000u) == 0xAC100000u)
        return 1; /* 172.16/12 */
    if ((a & 0xFFFF0000u) == 0xC0A80000u)
        return 1; /* 192.168/16 */
    return 0;
}
/* A LAN punch is possible when both ends hold a private address for each other.
 * Punching the gateway-mapped address instead needs NAT hairpin support, which
 * is exactly what fails on a flat site behind one router. */
static int lan_punch_possible(const fastp2p_client *c, const app *a) {
    struct in_addr peer, local;
    if (!a->peer_lan[0] || inet_pton(AF_INET, a->peer_lan, &peer) != 1)
        return 0;
    if (inet_pton(AF_INET, c->local_ip, &local) != 1)
        return 0;
    return private_address(peer.s_addr) && private_address(local.s_addr);
}
static size_t node_base(char out[32], const char *hostname) {
    size_t used = 0;
    for (const unsigned char *p = (const unsigned char *)hostname; *p && used < 31; ++p) {
        unsigned value = *p;
        out[used++] = ((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
                       (value >= '0' && value <= '9') || value == '_' || value == '-') ? (char)value : '-';
    }
    if (!used) {
        memcpy(out, "node", 4);
        used = 4;
    }
    out[used] = 0;
    return used;
}
static void automatic_candidate(fastp2p_client *c) {
    size_t used = node_base(c->node, c->hostname), i = 0;
    while (used < 8) {
        unsigned char digit = (unsigned char)c->device_id[i++];
        c->node[used++] = (char)('0' + (digit >= 'a' ? digit - 'a' + 10 : digit - '0') % 10);
    }
    c->node[used] = 0;
    c->node_id = op_node_id(c->node);
}
int fastp2p_client_set_identity(fastp2p_client *c, const char *identity) {
    if (!c || !c->automatic_node || c->running || c->in_callback || !identity || strlen(identity) != 32)
        return FASTP2P_EINVAL;
    for (const char *p = identity; *p; ++p)
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')))
            return FASTP2P_EINVAL;
    memcpy(c->device_id, identity, 33);
    automatic_candidate(c);
    return FASTP2P_OK;
}
const char *fastp2p_client_device_id(const fastp2p_client *c) {
    return c ? c->device_id : "";
}
const char *fastp2p_client_node(const fastp2p_client *c) {
    return c ? c->node : "";
}
static int copy_string(char *dst, size_t cap, const char *src) {
    if (!src || strlen(src) >= cap)
        return -1;
    memcpy(dst, src, strlen(src) + 1);
    return 0;
}
static void emit(fastp2p_client *c, fastp2p_event_type type, uint64_t id, int code, const char *message) {
    if (type == FASTP2P_EVENT_ERROR)
        snprintf(c->error, sizeof(c->error), "%s", message);
    if (c->callback) {
        fastp2p_event e = {sizeof(e), type, c->state, id, code, message};
        c->in_callback = 1;
        c->callback(c, &e, c->user);
        c->in_callback = 0;
    }
}
static void set_state(fastp2p_client *c, fastp2p_state s, const char *msg) {
    if (c->state != s) {
        c->state = s;
        emit(c, FASTP2P_EVENT_STATE, 0, 0, msg);
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
static op_socket socket_bound(int udp, const char *ip, uint16_t port, int reuse) {
    op_socket fd = op_socket_open(AF_INET, (udp ? SOCK_DGRAM : SOCK_STREAM), 0);
    if (fd < 0)
        return -1;
    int one = 1;
    if (reuse && op_reuse_socket(fd)) {
        op_close(fd);
        return -1;
    }
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, ip ? ip : "0.0.0.0", &a.sin_addr) != 1 ||
        op_bind(fd, (struct sockaddr *)&a, sizeof(a))) {
        op_close(fd);
        return -1;
    }
    if (!udp) {
        op_setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        op_setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    }
    return fd;
}
static uint16_t socket_port(op_socket fd) {
    struct sockaddr_in a;
    op_socklen n = sizeof(a);
    return op_getsockname(fd, (struct sockaddr *)&a, &n) ? 0 : ntohs(a.sin_port);
}
static int connect_ready(op_socket fd) {
    op_pollfd p = {.fd = fd, .events = POLLOUT};
    int polled = op_poll(&p, 1, 0);
    if (polled <= 0)
        return polled;
    int error = 0;
    op_socklen n = sizeof(error);
    if (op_getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &n) || error) {
        errno = error;
        return -1;
    }
    return 1;
}
static int flush(op_socket fd, op_buffer *b) {
    for (int i = 0; i < 32 && op_buffer_size(b); ++i) {
        op_ssize n =
            op_send(fd, b->data + b->offset, op_buffer_size(b), MSG_DONTWAIT | MSG_NOSIGNAL);
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
static int read_socket(op_socket fd, op_buffer *b, size_t limit) {
    uint8_t data[16384];
    for (int i = 0; i < 16; ++i) {
        op_ssize n = op_recv(fd, data, sizeof(data), MSG_DONTWAIT);
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
static int ws_frame(fastp2p_client *c, uint16_t main, uint16_t sub, const void *data, size_t len) {
    if (!c->ws || !c->running)
        return -1;
    if (op_frame_add(&c->ws_tx, main, sub, data, len))
        return -1;
    return 0;
}
static int ws_json(fastp2p_client *c, uint16_t main, uint16_t sub, json_object *obj) {
    const char *s = obj ? json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN) : "null";
    return ws_frame(c, main, sub, s, strlen(s));
}
static int push(fastp2p_client *c, const char *peer, uint16_t sub, json_object *obj) {
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
static int tseal(fastp2p_client *c, tunnel *t, uint16_t sub, const void *data, size_t len);
static int tjson_sealed(fastp2p_client *c, tunnel *t, uint16_t sub, json_object *obj) {
    const char *s = obj ? json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN) : "null";
    return tseal(c, t, sub, s, strlen(s));
}
static int tunnel_by_id(fastp2p_client *c, uint64_t id) {
    for (int i = 0; i < NT; ++i)
        if (c->tunnels[i].state && c->tunnels[i].id == id)
            return i;
    return -1;
}
/* A tunnel is only usable for application traffic once its session is ready on
 * both sides.  Treating an active but unkeyed tunnel as usable is what makes an
 * application wait forever on a link that will never carry a frame. */
static int tunnel_ready(const tunnel *t) {
    if (t->state != T_ACTIVE)
        return 0;
    if (t->relay_wait || t->relay_link >= 0 || t->relay_ready)
        return t->relay_ready;
    return t->keyed && t->key_acked;
}
static int active_tunnel(fastp2p_client *c, const char *peer, int transport) {
    for (int i = 0; i < NT; ++i)
        if (tunnel_ready(&c->tunnels[i]) && c->tunnels[i].transport == transport &&
            !strcmp(c->tunnels[i].peer, peer))
            return i;
    return -1;
}
static void close_overlay(fastp2p_client *c, int index, int notify) {
    overlay *o = &c->overlays[index];
    if (!o->used)
        return;
    if (c->running && !c->stopping && (o->socks_state == S_TUNNEL || o->socks_state == S_ACK)) {
        socks_failure(c, index, 1);
        return;
    }
    if (notify && o->tunnel_index >= 0 && c->tunnels[o->tunnel_index].state == T_ACTIVE) {
        json_object *j = json_object_new_object();
        op_ju(j, "id", o->id);
        tjson_sealed(c, &c->tunnels[o->tunnel_index], TUN_CLOSE, j);
        json_object_put(j);
    }
    if (o->socks_state == S_UDP) {
        uint64_t parent = o->id;
        for (int i = 0; i < NO; ++i)
            if (c->overlays[i].used && c->overlays[i].socks_parent == parent)
                close_overlay(c, i, 1);
    }
    if (o->socks_udp >= 0)
        op_close(o->socks_udp);
    if (o->fd >= 0 && !o->local_udp)
        op_close(o->fd);
    op_buffer_clear(&o->tx);
    op_buffer_clear(&o->early);
    if (o->socks_rx.data)
        OPENSSL_cleanse(o->socks_rx.data, o->socks_rx.len);
    op_buffer_clear(&o->socks_rx);
    memset(o, 0, sizeof(*o));
    o->fd = o->socks_udp = -1;
}
static void release_relay(fastp2p_client *c, int index) {
    for (int i = 0; i < NRL; ++i) {
        relay_link *r = &c->relays[i];
        if (!r->used || (r->ta != index && r->tb != index))
            continue;
        int other = r->ta == index ? r->tb : r->ta;
        memset(r, 0, sizeof(*r));
        if (other >= 0 && other < NT && c->tunnels[other].state) {
            c->tunnels[other].relay_link = -1;
            c->tunnels[other].relay_ready = 0;
            close_tunnel(c, other, "relay peer disconnected");
        }
    }
}
/* Half-open relay joins would otherwise hold a slot forever: a client that
 * asked to relay and never got a partner leaks one entry per attempt, and the
 * table is what bounds how many sessions this node can relay. */
static void tick_relays(fastp2p_client *c, uint64_t now) {
    for (int i = 0; i < NRL; ++i) {
        relay_link *r = &c->relays[i];
        if (!r->used || (r->ta >= 0 && r->tb >= 0) || now <= r->deadline)
            continue;
        int side = r->ta >= 0 ? r->ta : r->tb;
        memset(r, 0, sizeof(*r));
        if (side >= 0 && side < NT && c->tunnels[side].state) {
            c->tunnels[side].relay_link = -1;
            c->tunnels[side].relay_ready = 0;
            close_tunnel(c, side, "relay join timed out");
        }
    }
}
static void close_tunnel(fastp2p_client *c, int index, const char *reason) {
    tunnel *t = &c->tunnels[index];
    if (!t->state)
        return;
    char message[192];
    if (reason) {
        snprintf(message, sizeof(message), "%s", reason);
        reason = message;
    }
    uint64_t id = t->id;
    char failed_relay[32];
    failed_relay[0] = 0;
    /* Remember a relay hop that never carried an application session so the
     * next offer skips it; a hop that served traffic is not held against it. */
    if (t->relay_wait && t->peer[0])
        copy_string(failed_relay, sizeof(failed_relay), t->peer);
    t->state = T_FREE;
    for (int i = 0; i < NO; ++i)
        if (c->overlays[i].used && c->overlays[i].tunnel_index == index)
            close_overlay(c, i, 0);
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used && c->apps[i].tunnel_index == index) {
            int was_synced = c->apps[i].synced;
            c->apps[i].tunnel_index = -1;
            c->apps[i].synced = 0;
            c->apps[i].link_deadline = 0;
            c->apps[i].retry = mono() + 2 * NS;
            if (failed_relay[0] && c->apps[i].local && !was_synced) {
                app *a = &c->apps[i];
                int known = 0;
                for (int k = 0; k < a->relay_failed_count; ++k)
                    if (!strcmp(a->relay_failed[k], failed_relay))
                        known = 1;
                if (!known && a->relay_failed_count < 4)
                    copy_string(a->relay_failed[a->relay_failed_count++], 32, failed_relay);
            }
            if (!c->apps[i].local)
                memset(&c->apps[i], 0, sizeof(c->apps[i]));
        }
    if (t->relay_link >= 0)
        release_relay(c, index);
    if (t->quic)
        opq_free(t->quic);
    if (t->fd >= 0)
        op_close(t->fd);
    if (t->listen_fd >= 0)
        op_close(t->listen_fd);
    if (t->alternate_fd >= 0)
        op_close(t->alternate_fd);
    op_buffer_clear(&t->rx);
    op_buffer_clear(&t->tx);
    op_buffer_clear(&t->alternate_rx);
    fp_crypto_clear(&t->crypto);
    OPENSSL_cleanse(t->secret, sizeof(t->secret));
    memset(t, 0, sizeof(*t));
    t->fd = t->listen_fd = t->alternate_fd = -1;
    t->relay_link = -1;
    if (reason)
        emit(c, FASTP2P_EVENT_ERROR, id, FASTP2P_EIO, reason);
}
static int hex_value(char ch) {
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return -1;
}
static int secret_from_hex(const char *text, uint8_t out[FP_SESSION_SECRET]) {
    if (!text || strlen(text) != FP_SESSION_SECRET * 2)
        return -1;
    for (unsigned i = 0; i < FP_SESSION_SECRET; ++i) {
        int hi = hex_value(text[i * 2]), lo = hex_value(text[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}
static void secret_to_hex(const uint8_t *secret, char out[FP_SESSION_SECRET * 2 + 1]) {
    for (unsigned i = 0; i < FP_SESSION_SECRET; ++i)
        snprintf(out + i * 2, 3, "%02x", secret[i]);
}
static void push_session_to(fastp2p_client *c, const char *peer, uint64_t session,
                            const uint8_t *secret, const char *relay, int transport) {
    char hex[FP_SESSION_SECRET * 2 + 1];
    json_object *j = json_object_new_object();
    secret_to_hex(secret, hex);
    /* "peer" names the sender so the receiver can validate the push against the
     * node it punched, and can address its acknowledgement back. */
    op_js(j, "peer", c->node);
    op_ju(j, "session", session);
    op_js(j, "secret", hex);
    op_js(j, "transport", transport == FASTP2P_TRANSPORT_TCP ? "tcp" : "quic");
    if (relay && *relay)
        op_js(j, "relay", relay);
    push(c, peer, PUSH_SESSION, j);
    json_object_put(j);
    OPENSSL_cleanse(hex, sizeof(hex));
}
static void push_session(fastp2p_client *c, tunnel *t, const char *relay) {
    push_session_to(c, t->peer, t->session, t->secret, relay, t->transport);
}
static void push_session_ack(fastp2p_client *c, const char *peer, uint64_t session) {
    json_object *j = json_object_new_object();
    op_js(j, "peer", peer);
    op_ju(j, "session", session);
    push(c, peer, PUSH_SESSION_ACK, j);
    json_object_put(j);
}
static int new_tunnel(fastp2p_client *c, const char *peer, uint64_t id, int transport, int initiator) {
    if (!strcmp(peer, c->node))
        return -1;
    for (int i = 0; i < NT; ++i)
        if (!c->tunnels[i].state) {
            tunnel *t = &c->tunnels[i];
            memset(t, 0, sizeof(*t));
            t->fd = t->listen_fd = t->alternate_fd = -1;
            t->relay_link = -1;
            t->state = T_REPLY;
            t->id = id;
            t->peer_id = op_node_id(peer);
            strcpy(t->peer, peer);
            t->transport = transport;
            t->initiator = initiator;
            t->deadline = mono() + 15 * NS;
            if (initiator) {
                /* The side that opens the tunnel owns the session secret. */
                t->session = random_id();
                fp_random(t->secret, sizeof(t->secret));
                t->has_secret = t->session_owner = 1;
                if (fp_crypto_init(&t->crypto, t->secret, t->session, c->node_id, t->peer_id, 1)) {
                    t->state = T_FREE;
                    return -1;
                }
                t->keyed = 1;
            }
            return i;
        }
    emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_ELIMIT, "tunnel limit reached");
    return -1;
}
static int udp_packet(op_socket fd, const struct sockaddr_in *peer, uint16_t main, uint16_t sub,
                      json_object *j) {
    op_buffer b = {0};
    const char *s = j ? json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN) : "null";
    int rv = op_frame_add(&b, main, sub, s, strlen(s));
    if (!rv)
        rv = op_sendto(fd, b.data, b.len, MSG_DONTWAIT, (const struct sockaddr *)peer,
                       sizeof(*peer)) != (op_ssize)b.len;
    op_buffer_clear(&b);
    return rv ? -1 : 0;
}
static int start_probe(fastp2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    if (t->fd >= 0)
        op_close(t->fd);
    t->fd = socket_bound(t->transport == FASTP2P_TRANSPORT_QUIC, c->local_ip, 0, 1);
    if (t->fd < 0)
        return -1;
    t->local_port = socket_port(t->fd);
    t->deadline = mono() + 5 * NS;
    if (t->lan) {
        /* Both peers have a private address for each other, so the gateway's
         * mapped address is not needed: exchange local ports and punch on the
         * LAN.  Going through the public address instead would need NAT
         * hairpin support, which is what made these links fail. */
        t->mapped_port = t->local_port;
        probe_complete(c, index);
        return 0;
    }
    struct sockaddr_in peer = c->gateway;
    peer.sin_port = htons(27180);
    if (t->transport == FASTP2P_TRANSPORT_QUIC) {
        t->state = T_NAT_UDP;
        return udp_packet(t->fd, &peer, 2, 0, NULL);
    }
    t->state = T_NAT_CONNECT;
    if (op_connect(t->fd, (struct sockaddr *)&peer, sizeof(peer)) && errno != EINPROGRESS)
        return -1;
    return 0;
}
static void probe_complete(fastp2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    json_object *j = json_object_new_object();
    op_js(j, "from", c->node);
    /* On a LAN punch the peers exchange private addresses and local ports; the
     * gateway-observed address is only meaningful when a NAT is in between. */
    op_js(j, "fromIP", t->lan ? c->local_ip : c->ip);
    op_js(j, "version", WIRE_VERSION);
    op_ju(j, "natType", (uint64_t)c->nat_type);
    op_ju(j, "coneNatPort", t->lan ? t->local_port : t->mapped_port);
    op_ju(j, "id", t->id);
    if (t->initiator) {
        op_js(j, "linkMode", t->mode);
        op_ju(j, "isServer", 1);
        op_ju(j, "lan", t->lan ? 1 : 0);
        op_js(j, "underlayProtocol", t->transport == FASTP2P_TRANSPORT_QUIC ? "quic" : "tcp");
        push(c, t->peer, PUSH_CONNECT, j);
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
    if (t->transport == FASTP2P_TRANSPORT_TCP) {
        if (t->fd >= 0)
            op_close(t->fd);
        t->fd = -1;
        if (!strcmp(t->mode, "tcppunch")) {
            t->listen_fd = socket_bound(0, c->local_ip, t->local_port, 1);
            if (t->listen_fd < 0 || op_listen(t->listen_fd, 4))
                close_tunnel(c, index, "TCP punch listener failed");
        }
    }
}
static void start_underlay(fastp2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(t->remote_port)};
    if (inet_pton(AF_INET, t->ip, &peer.sin_addr) != 1) {
        close_tunnel(c, index, "invalid peer address");
        return;
    }
    t->deadline = mono() + 10 * NS;
    if (t->transport == FASTP2P_TRANSPORT_QUIC) {
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
        (op_connect(t->fd, (struct sockaddr *)&peer, sizeof(peer)) && errno != EINPROGRESS)) {
        if (t->listen_fd < 0) {
            close_tunnel(c, index, "TCP peer connection failed");
            return;
        }
        if (t->fd >= 0)
            op_close(t->fd);
        t->fd = -1;
    }
    t->state = T_TCP_CONNECT;
}
static void session_ready(fastp2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    int relayed = t->relay_link >= 0 || t->relay_wait || t->relay_ready;
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used && c->apps[i].local && c->apps[i].tunnel_index == index &&
            !c->apps[i].synced) {
            c->apps[i].synced = 1;
            c->apps[i].link_deadline = 0;
            c->apps[i].ready_at = mono() + 100 * MS;
            c->apps[i].relay_requested = 0;
            /* attempts is deliberately not reset here: a tunnel that completes
             * the key exchange and then dies must not restart the direct-punch
             * ladder, or a pair that cannot punch never reaches the relay. */
            emit(c, FASTP2P_EVENT_FORWARD, c->apps[i].id, 0,
                 relayed ? "forward attached to relay" : "forward attached to tunnel");
        }
}
static void bind_pending_key(fastp2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    if (t->keyed || t->session_owner)
        return;
    /* Retries leave several keys queued for the same peer; the newest one is
     * the session the current tunnel belongs to.  Binding an older key derives
     * a different pair of keys and every frame then fails authentication. */
    pending_key *best = NULL;
    for (int i = 0; i < NPK; ++i) {
        pending_key *k = &c->keys[i];
        if (!k->used || k->peer_id != t->peer_id || k->transport != t->transport || k->relay[0])
            continue;
        if (!best || k->deadline >= best->deadline)
            best = k;
    }
    if (!best)
        return;
    pending_key *k = best;
    t->session = k->session;
    memcpy(t->secret, k->secret, sizeof(t->secret));
    if (fp_crypto_init(&t->crypto, t->secret, t->session, t->peer_id, c->node_id, 0)) {
        close_tunnel(c, index, "session key derivation failed");
        return;
    }
    /* A second unkeyed tunnel to the same peer and transport is a leftover
     * attempt.  Leaving it open lets the peer talk to a tunnel that will never
     * be keyed, so retire it as soon as the live session is known. */
    for (int i = 0; i < NT; ++i)
        if (i != index && c->tunnels[i].state == T_ACTIVE && !c->tunnels[i].keyed &&
            c->tunnels[i].peer_id == t->peer_id && c->tunnels[i].transport == t->transport)
            close_tunnel(c, i, "superseded by a newer session");
    t->keyed = 1;
    OPENSSL_cleanse(k->secret, sizeof(k->secret));
    memset(k, 0, sizeof(*k));
    push_session_ack(c, t->peer, t->session);
    session_ready(c, index);
}
static void relay_join(fastp2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    uint8_t frame[32];
    op_put64(frame, t->session);
    op_put64(frame + 8, op_node_id(t->relay_peer));
    fp_join_proof(c->token, t->session, op_node_id(t->relay_peer), frame + 16);
    tframe(t, TUN_RELAY_JOIN, frame, sizeof(frame));
}
static int app_tunnel(fastp2p_client *c, app *a, const char *peer, int transport) {
    int ti = new_tunnel(c, peer, random_id(), transport, 1);
    if (ti < 0)
        return -1;
    tunnel *t = &c->tunnels[ti];
    if (a->has_session) {
        fp_crypto_clear(&t->crypto);
        t->session = a->session;
        memcpy(t->secret, a->secret, FP_SESSION_SECRET);
        if (fp_crypto_init(&t->crypto, t->secret, t->session, c->node_id, t->peer_id, 1)) {
            close_tunnel(c, ti, "session key derivation failed");
            return -1;
        }
    } else {
        a->session = t->session;
        memcpy(a->secret, t->secret, FP_SESSION_SECRET);
        a->has_session = 1;
    }
    t->keyed = 1;
    t->session_owner = 1;
    return ti;
}
static int relay_tunnel(fastp2p_client *c, app *a, const char *relay, const char *peer, int owner) {
    int ti = new_tunnel(c, relay, random_id(), a->transport, 1);
    if (ti < 0)
        return -1;
    tunnel *t = &c->tunnels[ti];
    fp_crypto_clear(&t->crypto);
    t->session = a->session;
    memcpy(t->secret, a->secret, FP_SESSION_SECRET);
    t->has_secret = 1;
    t->session_owner = owner;
    copy_string(t->relay_peer, sizeof(t->relay_peer), peer);
    uint64_t initiator = owner ? c->node_id : op_node_id(peer);
    uint64_t responder = owner ? op_node_id(peer) : c->node_id;
    if (fp_crypto_init(&t->crypto, t->secret, t->session, initiator, responder, owner)) {
        close_tunnel(c, ti, "session key derivation failed");
        return -1;
    }
    t->keyed = 1;
    t->relay_wait = 1;
    return ti;
}
static void start_punch(fastp2p_client *c, int ti) {
    tunnel *t = &c->tunnels[ti];
    strcpy(t->mode, t->transport == FASTP2P_TRANSPORT_TCP ? "tcppunch" : "udppunch");
    json_object *j = json_object_new_object();
    op_js(j, "peerNode", t->peer);
    ws_json(c, 7, 0, j);
    json_object_put(j);
    if (start_probe(c, ti))
        close_tunnel(c, ti, "NAT probe could not start");
}
/* The initiating peer delivered the session secret.  For a direct tunnel the
 * secret is bound to the tunnel it punched; for a relayed link we punch the
 * relay ourselves and join the session there. */
static void session_receive(fastp2p_client *c, uint64_t peer_id, const char *peer, uint64_t session,
                            const uint8_t *secret, const char *relay, int transport) {
    int slot = -1;
    for (int i = 0; i < NPK; ++i)
        if (c->keys[i].used && c->keys[i].session == session && c->keys[i].peer_id == peer_id) {
            slot = i;
            break;
        }
    if (slot < 0)
        for (int i = 0; i < NPK; ++i)
            if (!c->keys[i].used) {
                slot = i;
                break;
            }
    if (slot < 0) {
        emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_ELIMIT, "too many pending sessions");
        return;
    }
    pending_key *k = &c->keys[slot];
    memset(k, 0, sizeof(*k));
    k->used = 1;
    k->session = session;
    k->peer_id = peer_id;
    k->transport = transport;
    k->deadline = mono() + 30 * NS;
    memcpy(k->secret, secret, FP_SESSION_SECRET);
    /* A newer session for the same peer and transport supersedes any key still
     * waiting from a failed attempt. */
    for (int i = 0; i < NPK; ++i) {
        pending_key *old = &c->keys[i];
        if (old == k || !old->used || old->peer_id != peer_id || old->transport != transport)
            continue;
        OPENSSL_cleanse(old->secret, sizeof(old->secret));
        memset(old, 0, sizeof(*old));
    }
    if (relay && *relay) {
        if (!valid_node(relay)) {
            memset(k, 0, sizeof(*k));
            return;
        }
        app probe = {0};
        probe.transport = transport;
        probe.session = session;
        memcpy(probe.secret, secret, FP_SESSION_SECRET);
        probe.has_session = 1;
        strcpy(probe.peer, peer);
        int ti = relay_tunnel(c, &probe, relay, peer, 0);
        if (ti < 0)
            memset(k, 0, sizeof(*k));
        else
            start_punch(c, ti);
        return;
    }
    /* Bind to the most recently established matching tunnel: an older unkeyed
     * tunnel belongs to an attempt that is already being replaced. */
    int newest = -1;
    for (int i = 0; i < NT; ++i)
        if (c->tunnels[i].state == T_ACTIVE && c->tunnels[i].peer_id == peer_id &&
            c->tunnels[i].transport == transport && !c->tunnels[i].keyed &&
            (newest < 0 || c->tunnels[i].active_at >= c->tunnels[newest].active_at))
            newest = i;
    if (newest >= 0)
        bind_pending_key(c, newest);
}
static void tunnel_active(fastp2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    t->state = T_ACTIVE;
    t->last_rx = t->last_hb = t->active_at = mono();
    if (t->listen_fd >= 0)
        op_close(t->listen_fd);
    if (t->alternate_fd >= 0)
        op_close(t->alternate_fd);
    t->listen_fd = t->alternate_fd = -1;
    op_buffer_clear(&t->alternate_rx);
    emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0,
         t->transport == FASTP2P_TRANSPORT_TCP ? "TCP tunnel connected" : "QUIC tunnel connected");
    if (t->relay_wait) {
        /* Join the relay, and (on the side that owns the session) tell the far
         * endpoint which relay to punch so it can join the same session. */
        relay_join(c, index);
        if (t->session_owner)
            push_session_to(c, t->relay_peer, t->session, t->secret, t->peer, t->transport);
        return;
    }
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used && c->apps[i].local && !strcmp(c->apps[i].peer, t->peer) &&
            c->apps[i].transport == t->transport) {
            c->apps[i].tunnel_index = index;
            c->apps[i].link_deadline = mono() + 20 * NS;
        }
    if (t->session_owner)
        push_session(c, t, NULL);
    else
        bind_pending_key(c, index);
}
static int overlay_slot(fastp2p_client *c) {
    for (int i = 0; i < NO; ++i)
        if (!c->overlays[i].used) {
            overlay *o = &c->overlays[i];
            memset(o, 0, sizeof(*o));
            o->fd = o->socks_udp = -1;
            o->app_index = o->tunnel_index = -1;
            o->used = 1;
            o->activity = mono();
            o->deadline = o->activity + 5 * NS;
            return i;
        }
    emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_ELIMIT, "overlay connection limit reached");
    return -1;
}
static int overlay_data(fastp2p_client *c, int oi, const uint8_t *data, size_t len) {
    overlay *o = &c->overlays[oi];
    uint8_t payload[8 + 4096];
    if (len > 4096 || o->tunnel_index < 0)
        return -1;
    op_put64(payload, o->id);
    memcpy(payload + 8, data, len);
    o->activity = mono();
    return tseal(c, &c->tunnels[o->tunnel_index], TUN_DATA, payload, len + 8);
}
static void request_overlay(fastp2p_client *c, int oi) {
    overlay *o = &c->overlays[oi];
    app *a = &c->apps[o->app_index];
    json_object *j = json_object_new_object();
    op_ju(j, "id", o->id);
    op_js(j, "dstIP", a->socks ? o->socks.host : a->destination);
    op_ju(j, "dstPort", a->socks ? o->socks.port : a->dst_port);
    op_js(j, "protocol", o->udp ? "udp" : "tcp");
    if (a->socks)
        op_ju(j, "socks5", 1);
    const char *text = json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN);
    int rv = tseal(c, &c->tunnels[o->tunnel_index], TUN_OPEN, text, strlen(text));
    json_object_put(j);
    if (rv) {
        close_overlay(c, oi, 1);
        return;
    }
    o->waiting = 1;
    o->deadline = mono() + (a->socks ? 15 : 5) * NS;
}
static void socks_failure(fastp2p_client *c, int oi, unsigned status) {
    overlay *o = &c->overlays[oi];
    if (o->socks_state == S_FLOW) {
        close_overlay(c, oi, 1);
        return;
    }
    if (o->socks_state == S_ACK && o->tunnel_index >= 0 &&
        c->tunnels[o->tunnel_index].state == T_ACTIVE) {
        json_object *j = json_object_new_object();
        op_ju(j, "id", o->id);
        tjson_sealed(c, &c->tunnels[o->tunnel_index], TUN_CLOSE, j);
        json_object_put(j);
    }
    uint8_t reply[10];
    op_socks_reply(reply, status, NULL, 0);
    if (op_buffer_add(&o->tx, reply, sizeof(reply), OP_QUEUE_LIMIT)) {
        o->socks_state = S_CLOSING;
        close_overlay(c, oi, 0);
        return;
    }
    o->socks_state = S_CLOSING;
    o->deadline = mono() + NS;
}
static void overlay_ack(fastp2p_client *c, int oi, unsigned status) {
    overlay *o = &c->overlays[oi];
    if (!o->socks_exit) {
        if (status)
            return;
        json_object *ack = json_object_new_object();
        op_ju(ack, "id", o->id);
        tjson_sealed(c, &c->tunnels[o->tunnel_index], TUN_OPEN_ACK, ack);
        json_object_put(ack);
        return;
    }
    struct sockaddr_in local = {0};
    op_socklen length = sizeof(local);
    if (o->fd >= 0)
        op_getsockname(o->fd, (struct sockaddr *)&local, &length);
    char ip[INET_ADDRSTRLEN], remote[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip));
    inet_ntop(AF_INET, &o->source.sin_addr, remote, sizeof(remote));
    json_object *j = json_object_new_object();
    op_ju(j, "id", o->id);
    op_ju(j, "reply", status);
    op_js(j, "boundIP", ip);
    op_ju(j, "boundPort", ntohs(local.sin_port));
    op_js(j, "remoteIP", remote);
    tjson_sealed(c, &c->tunnels[o->tunnel_index], TUN_OPEN_ACK, j);
    json_object_put(j);
}
static void socks_acknowledged(fastp2p_client *c, int oi, json_object *ack) {
    overlay *o = &c->overlays[oi];
    if (!ack || !json_object_is_type(ack, json_type_object)) {
        emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, "SOCKS5 exit requires a compatible fastp2p client");
        socks_failure(c, oi, 7);
        return;
    }
    if (op_integer(ack, "id") != o->id)
        return;
    uint64_t status = op_integer(ack, "reply"), port = op_integer(ack, "boundPort");
    struct in_addr address;
    if (!op_get(ack, "reply") || status > 8 || port > 65535 ||
        inet_pton(AF_INET, op_string(ack, "boundIP"), &address) != 1) {
        socks_failure(c, oi, 1);
        return;
    }
    if (status) {
        socks_failure(c, oi, (unsigned)status);
        return;
    }
    o->waiting = 0;
    if (o->socks_state == S_FLOW) {
        if (inet_pton(AF_INET, op_string(ack, "remoteIP"), &o->socks_peer.sin_addr) != 1)
            close_overlay(c, oi, 1);
        return;
    }
    uint8_t reply[10];
    op_socks_reply(reply, 0, (const uint8_t *)&address, (uint16_t)port);
    if (op_buffer_add(&o->tx, reply, sizeof(reply), OP_QUEUE_LIMIT)) {
        close_overlay(c, oi, 1);
        return;
    }
    o->socks_state = S_STREAM;
}
static overlay *socks_parent(fastp2p_client *c, uint64_t id) {
    for (int i = 0; i < NO; ++i)
        if (c->overlays[i].used && c->overlays[i].id == id && c->overlays[i].socks_state == S_UDP)
            return &c->overlays[i];
    return NULL;
}
static void socks_udp_reply(fastp2p_client *c, int oi, const uint8_t *data, size_t len) {
    overlay *o = &c->overlays[oi], *parent = socks_parent(c, o->socks_parent);
    if (!parent || o->waiting || len > 4096)
        return;
    uint8_t packet[4106] = {0, 0, 0, 1};
    memcpy(packet + 4, &o->socks_peer.sin_addr, 4);
    packet[8] = (uint8_t)(o->socks.port >> 8);
    packet[9] = (uint8_t)o->socks.port;
    memcpy(packet + 10, data, len);
    op_sendto(parent->socks_udp, packet, len + 10, MSG_DONTWAIT,
              (struct sockaddr *)&parent->socks_peer, sizeof(parent->socks_peer));
}
static void tick_socks_udp(fastp2p_client *c, int index) {
    overlay *parent = &c->overlays[index];
    app *a = &c->apps[parent->app_index];
    for (int k = 0; k < 8; ++k) {
        uint8_t packet[4360];
        struct sockaddr_in from;
        op_socklen flen = sizeof(from);
        op_ssize n = op_recvfrom(parent->socks_udp, packet, sizeof(packet), MSG_DONTWAIT,
                                 (struct sockaddr *)&from, &flen);
        if (n < 0)
            break;
        if (flen != sizeof(from) || from.sin_addr.s_addr != parent->source.sin_addr.s_addr ||
            (parent->socks_peer.sin_port && from.sin_port != parent->socks_peer.sin_port) ||
            n < 4 || packet[0] || packet[1] || packet[2])
            continue;
        char host[256];
        uint16_t port;
        int header = op_socks_address(packet + 3, (size_t)n - 3, host, &port);
        if (header <= 0 || !port || (size_t)n - 3 - (size_t)header > 4096 || a->tunnel_index < 0 ||
            !a->synced || mono() < a->ready_at)
            continue;
        parent->socks_peer = from;
        int oi = -1, flows = 0;
        for (int i = 0; i < NO; ++i)
            if (c->overlays[i].used && c->overlays[i].socks_parent == parent->id) {
                ++flows;
                if (c->overlays[i].socks.port == port && !strcmp(c->overlays[i].socks.host, host))
                    oi = i;
            }
        if (oi < 0) {
            if (flows >= 32 || (oi = overlay_slot(c)) < 0)
                continue;
            overlay *o = &c->overlays[oi];
            o->fd = parent->socks_udp;
            o->udp = o->local_udp = o->connected = 1;
            o->socks_state = S_FLOW;
            o->socks_parent = parent->id;
            o->id = random_id();
            o->app_index = parent->app_index;
            o->tunnel_index = a->tunnel_index;
            strcpy(o->socks.host, host);
            o->socks.port = port;
            request_overlay(c, oi);
        }
        overlay *o = &c->overlays[oi];
        size_t length = (size_t)n - 3 - (size_t)header;
        const uint8_t *data = packet + 3 + header;
        if (o->waiting) {
            uint8_t early[4098];
            op_put16(early, (uint16_t)length);
            memcpy(early + 2, data, length);
            if (op_buffer_add(&o->early, early, length + 2, 65536))
                close_overlay(c, oi, 1);
        } else if (overlay_data(c, oi, data, length))
            close_overlay(c, oi, 1);
    }
}
static void tick_socks(fastp2p_client *c, uint64_t now) {
    for (int i = 0; i < NO; ++i) {
        overlay *o = &c->overlays[i];
        if (!o->used || !o->socks_state || o->socks_state == S_STREAM || o->socks_state == S_FLOW)
            continue;
        if (flush(o->fd, &o->tx)) {
            close_overlay(c, i, 0);
            continue;
        }
        if (o->socks_state == S_CLOSING) {
            if (!op_buffer_size(&o->tx) || now > o->deadline)
                close_overlay(c, i, 0);
            continue;
        }
        app *a = &c->apps[o->app_index];
        if (o->socks_state == S_UDP) {
            uint8_t byte;
            op_ssize n = op_recv(o->fd, &byte, 1, MSG_DONTWAIT);
            if (n >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                close_overlay(c, i, 1);
                continue;
            }
            tick_socks_udp(c, i);
            continue;
        }
        if (now > o->deadline) {
            socks_failure(c, i, 4);
            continue;
        }
        if (o->socks_state == S_TUNNEL) {
            if (a->tunnel_index >= 0 && a->synced && now >= a->ready_at) {
                o->tunnel_index = a->tunnel_index;
                o->socks_state = S_ACK;
                request_overlay(c, i);
            }
            continue;
        }
        if (o->socks_state == S_ACK)
            continue;
        if (read_socket(o->fd, &o->socks_rx, 65536)) {
            close_overlay(c, i, 0);
            continue;
        }
        for (int step = 0; step < 3 && o->socks_state == S_HANDSHAKE; ++step) {
            uint8_t reply[10];
            size_t used, length;
            int rv = op_socks_step(&o->socks,
                                   o->socks_rx.data ? o->socks_rx.data + o->socks_rx.offset : NULL,
                                   op_buffer_size(&o->socks_rx), &used, a->socks_user,
                                   a->socks_password, reply, &length);
            if (length && op_buffer_add(&o->tx, reply, length, OP_QUEUE_LIMIT)) {
                close_overlay(c, i, 0);
                break;
            }
            if (used) {
                OPENSSL_cleanse(o->socks_rx.data + o->socks_rx.offset, used);
                op_buffer_consume(&o->socks_rx, used);
            }
            if (rv < 0) {
                o->socks_state = S_CLOSING;
                o->deadline = now + NS;
                break;
            }
            if (!rv)
                break;
            if (rv != 2)
                continue;
            if (o->socks.command == 1) {
                o->socks_state = S_TUNNEL;
                o->deadline = now + 45 * NS;
                break;
            }
            struct in_addr requested;
            if (inet_pton(AF_INET, o->socks.host, &requested) != 1 ||
                (requested.s_addr && requested.s_addr != o->source.sin_addr.s_addr)) {
                socks_failure(c, i, 2);
                break;
            }
            struct sockaddr_in local;
            op_socklen flen = sizeof(local);
            if (op_getsockname(o->fd, (struct sockaddr *)&local, &flen)) {
                socks_failure(c, i, 1);
                break;
            }
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip));
            o->socks_udp = socket_bound(1, ip, 0, 0);
            if (o->socks_udp < 0) {
                socks_failure(c, i, 1);
                break;
            }
            o->socks_peer = o->source;
            o->socks_peer.sin_port = htons(o->socks.port);
            op_socks_reply(reply, 0, (const uint8_t *)&local.sin_addr, socket_port(o->socks_udp));
            if (op_buffer_add(&o->tx, reply, 10, OP_QUEUE_LIMIT)) {
                close_overlay(c, i, 0);
                break;
            }
            op_buffer_clear(&o->socks_rx);
            o->socks_state = S_UDP;
        }
    }
}
static void report_apps(fastp2p_client *c) {
    json_object *root = json_object_new_object(), *list = json_object_new_array();
    for (int i = 0; i < NA; ++i) {
        app *a = &c->apps[i];
        if (!a->used || !a->local)
            continue;
        json_object *j = json_object_new_object();
        op_js(j, "appName", a->name);
        op_js(j, "protocol", a->socks ? "socks5" : (a->udp ? "udp" : "tcp"));
        op_js(j, "peerNode", a->peer);
        op_js(j, "dstHost", a->destination);
        op_ju(j, "dstPort", a->dst_port);
        op_ju(j, "srcPort", a->port);
        op_ju(j, "enabled", 1);
        op_ju(j, "isActive", a->tunnel_index >= 0 && c->tunnels[a->tunnel_index].state == T_ACTIVE);
        op_js(j, "linkMode", a->transport == FASTP2P_TRANSPORT_QUIC ? "udppunch" : "ipv4");
        json_object_array_add(list, j);
    }
    json_object_object_add(root, "Apps", list);
    ws_json(c, 6, 3, root);
    json_object_put(root);
}
static void control_message(fastp2p_client *c, uint16_t main, uint16_t sub, const uint8_t *data,
                            size_t len) {
    c->last_rx = mono();
    if (main == 1) {
        if (len != 8) {
            emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, "invalid gateway heartbeat");
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
        emit(c, FASTP2P_EVENT_HEARTBEAT, 0, 0, "gateway heartbeat received");
        return;
    }
    uint64_t sender = 0;
    if (main == 3 &&
        (sub == PUSH_CONNECT || sub == PUSH_CONNECT_REPLY || sub == PUSH_READY ||
         sub == PUSH_SESSION || sub == PUSH_SESSION_ACK)) {
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
        if (strcmp(op_string(j, "protocol"), WIRE_PROTOCOL) || op_integer(j, "error") || op_integer(j, "token") != c->token) {
            emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, "gateway rejected login");
            c->stopping = 1;
        } else {
            if (c->automatic_node) {
                const char *assigned = op_string(j, "node");
                if (!valid_node(assigned)) {
                    emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, "gateway returned an invalid node name");
                    c->stopping = 1;
                    json_object_put(j);
                    return;
                }
                strcpy(c->node, assigned);
                c->node_id = op_node_id(c->node);
                char message[64];
                snprintf(message, sizeof(message), "node name: %s", c->node);
                emit(c, FASTP2P_EVENT_STATE, c->node_id, 0, message);
            }
            c->login_ok = 1;
            if (c->report_ok)
                set_state(c, FASTP2P_ONLINE, "gateway authenticated");
        }
    } else if (main == 3 && sub == 0) {
        /* The gateway answers every push with its own result frame.  Surface it
         * so a rejected push is visible instead of silently dropped. */
        uint64_t error = op_integer(j, "error");
        if (error)
            emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO,
                 op_string(j, "detail") ? op_string(j, "detail") : "gateway rejected a push");
    } else if (main == 6 && sub == 7) {
        c->report_ok = 1;
        if (c->login_ok)
            set_state(c, FASTP2P_ONLINE, "gateway authenticated");
    } else if (main == 3 && sub == 1) {
        const char *from = op_string(j, "from"), *mode = op_string(j, "linkMode");
        uint64_t id = op_integer(j, "id"), port = op_integer(j, "coneNatPort");
        struct in_addr peer_ip;
        int udp = !strcmp(mode, "udppunch") || !strcmp(mode, "udp4");
        if (valid_node(from) && sender == op_node_id(from) && id && tunnel_by_id(c, id) < 0 &&
            port > 0 && port <= 65535 &&
            inet_pton(AF_INET, op_string(j, "fromIP"), &peer_ip) == 1 &&
            (!strcmp(mode, "tcppunch") || !strcmp(mode, "tcp4") || !strcmp(mode, "intranet") ||
             udp)) {
            int ti = new_tunnel(c, from, id, udp ? FASTP2P_TRANSPORT_QUIC : FASTP2P_TRANSPORT_TCP, 0);
            if (ti >= 0) {
                tunnel *t = &c->tunnels[ti];
                strcpy(t->mode, mode);
                strcpy(t->ip, op_string(j, "fromIP"));
                t->remote_port = (uint16_t)port;
                t->server = op_integer(j, "isServer") != 0;
                t->lan = op_integer(j, "lan") != 0;
                if (udp && !strcmp(mode, "udp4") && t->server)
                    close_tunnel(c, ti, "direct UDP listener is not supported; use UDP punching");
                else if (!udp && strcmp(mode, "tcppunch")) {
                    t->local_port = t->mapped_port = c->public_port;
                    probe_complete(c, ti);
                } else if (start_probe(c, ti))
                    close_tunnel(c, ti, "NAT probe could not start");
            }
        } else
            emit(c, FASTP2P_EVENT_ERROR, id, FASTP2P_EINVAL, "peer connection request rejected");
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
    } else if (main == 3 && sub == PUSH_SESSION) {
        uint64_t session = op_integer(j, "session");
        const char *peer = op_string(j, "peer"), *relay = op_string(j, "relay");
        const char *transport = op_string(j, "transport");
        uint8_t secret[FP_SESSION_SECRET];
        int ok = session && valid_node(peer) && sender == op_node_id(peer) &&
                 !secret_from_hex(op_string(j, "secret"), secret);
        if (ok) {
            int quic = !transport || strcmp(transport, "tcp");
            session_receive(c, sender, peer, session, secret,
                            relay && *relay ? relay : NULL,
                            quic ? FASTP2P_TRANSPORT_QUIC : FASTP2P_TRANSPORT_TCP);
        } else {
            emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EINVAL, "invalid session key");
        }
        OPENSSL_cleanse(secret, sizeof(secret));
    } else if (main == 3 && sub == PUSH_SESSION_ACK) {
        uint64_t session = op_integer(j, "session");
        for (int i = 0; i < NT; ++i) {
            tunnel *t = &c->tunnels[i];
            if (t->state != T_ACTIVE || !t->session_owner || t->session != session)
                continue;
            uint64_t peer =
                t->relay_wait || t->relay_ready ? op_node_id(t->relay_peer) : t->peer_id;
            if (peer != sender)
                continue;
            t->key_acked = 1;
            session_ready(c, i);
        }
    } else if (main == 5 && sub == 1) {
        /* Relay offer for the rule that asked for one. */
        const char *relay = op_string(j, "relay");
        if (!relay || !*relay || !valid_node(relay))
            emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, "no relay node available");
        for (int i = 0; i < NA; ++i) {
            app *a = &c->apps[i];
            if (!a->used || !a->local || !a->relay_requested || a->synced)
                continue;
            a->relay_requested = 0;
            if (!relay || !*relay || !valid_node(relay))
                continue;
            int ti = relay_tunnel(c, a, relay, a->peer, 1);
            if (ti < 0)
                continue;
            a->tunnel_index = ti;
            a->link_deadline = mono() + 20 * NS;
            a->relay_wanted = 0;
            start_punch(c, ti);
        }
    } else if (main == 7 && sub == 1) {
        const char *peer = op_string(j, "peerNode"), *lan = op_string(j, "lanIP");
        struct in_addr lan_address;
        if (valid_node(peer))
            for (int i = 0; i < NA; ++i)
                if (c->apps[i].used && !strcmp(c->apps[i].peer, peer)) {
                    c->apps[i].peer_nat = op_integer(j, "natType");
                    if (lan && inet_pton(AF_INET, lan, &lan_address) == 1)
                        copy_string(c->apps[i].peer_lan, sizeof(c->apps[i].peer_lan), lan);
                }
    } else if (main == 3 && sub == 7)
        report_apps(c);
    else if (main == 3 && sub == 9) {
        uint64_t src = op_integer(j, "srcPort"), dst = op_integer(j, "dstPort");
        if (src && src <= 65535 && dst && dst <= 65535) {
            fastp2p_forward f = {.struct_size = sizeof(f),
                              .name = op_string(j, "appName"),
                              .local_port = (uint16_t)src,
                              .peer_node = op_string(j, "peerNode"),
                              .destination_host = op_string(j, "dstHost"),
                              .destination_port = (uint16_t)dst,
                              .protocol = op_string(j, "protocol"),
                              .transport = (op_integer(j, "punchPriority") & 2)
                                               ? FASTP2P_TRANSPORT_TCP
                                               : FASTP2P_TRANSPORT_QUIC};
            int rv = fastp2p_client_add_forward(c, &f, NULL);
            if (rv)
                emit(c, FASTP2P_EVENT_ERROR, 0, rv, "could not add gateway forwarding rule");
        }
    }
    json_object_put(j);
}
/* Seal one application frame into the tunnel.  Every frame that carries
 * application data or application control is authenticated and encrypted with
 * the session keys, so a relay hop only ever sees opaque bytes. */
static int tseal(fastp2p_client *c, tunnel *t, uint16_t sub, const void *data, size_t len) {
    uint8_t buffer[8 + 4096 + 256 + 2 * FP_TAG + 8];
    size_t written = 0;
    (void)c;
    if (!t->keyed || len > sizeof(buffer) - 32)
        return -1;
    if (fp_seal(&t->crypto, sub, 0, data, len, buffer, sizeof(buffer), &written))
        return -1;
    return tframe(t, sub, buffer, written);
}
/* Returns 0 on success, 1 when the frame is a duplicate and must be ignored,
 * and -1 when the tunnel must be closed. */
static int topen(fastp2p_client *c, int ti, uint16_t sub, const uint8_t *data, size_t len,
                 uint8_t *out, size_t capacity, size_t *written) {
    tunnel *t = &c->tunnels[ti];
    if (!t->keyed) {
        close_tunnel(c, ti, "peer sent application data before the session was ready");
        return -1;
    }
    int rv = fp_open(&t->crypto, sub, 0, data, len, out, capacity, written);
    if (rv == -1)
        return 1;
    if (rv) {
        if (getenv("FP_DEBUG_KEYS"))
            fprintf(stderr, "auth fail ti=%d sub=%u len=%zu rxmax=%llu\n", ti, sub, len,
                    (unsigned long long)t->crypto.rx_max);
        close_tunnel(c, ti, "tunnel authentication failed");
        return -1;
    }
    return 0;
}
/* Relay side: pair two tunnels that joined with the same session. */
static void relay_receive(fastp2p_client *c, int ti, const uint8_t *data, size_t len) {
    tunnel *t = &c->tunnels[ti];
    if (len != 32 || t->relay_link >= 0) {
        close_tunnel(c, ti, "invalid relay join");
        return;
    }
    uint64_t session = op_u64(data), peer = op_u64(data + 8);
    uint8_t proof[16];
    fp_join_proof(c->token, session, peer, proof);
    if (!fp_equal(proof, data + 16, 16) || peer == t->peer_id) {
        emit(c, FASTP2P_EVENT_ERROR, t->id, FASTP2P_EINVAL, "relay join rejected");
        close_tunnel(c, ti, "relay join rejected");
        return;
    }
    int link = -1;
    for (int i = 0; i < NRL; ++i)
        if (c->relays[i].used && c->relays[i].session == session) {
            link = i;
            break;
        }
    if (link < 0) {
        /* Cap how many sessions this node relays.  A client that also runs its
         * own applications has one event loop, and past this point its own
         * tunnels start missing heartbeats.  Refusing the join makes the
         * endpoint exclude this node and ask for a different relay. */
        int active = 0;
        for (int i = 0; i < NRL; ++i)
            if (c->relays[i].used)
                ++active;
        if (active >= RELAY_SESSION_LIMIT) {
            emit(c, FASTP2P_EVENT_ERROR, t->id, FASTP2P_ELIMIT, "relay busy");
            close_tunnel(c, ti, "relay busy");
            return;
        }
        for (int i = 0; i < NRL; ++i)
            if (!c->relays[i].used) {
                link = i;
                break;
            }
    }
    if (link < 0) {
        close_tunnel(c, ti, "relay table full");
        return;
    }
    relay_link *r = &c->relays[link];
    if (!r->used) {
        memset(r, 0, sizeof(*r));
        r->used = 1;
        r->session = session;
        r->ta = r->tb = -1;
        r->deadline = mono() + 30 * NS;
    }
    if (r->ta < 0) {
        r->ta = ti;
        r->peer_a = t->peer_id;
    } else if (r->tb < 0) {
        r->tb = ti;
        r->peer_b = t->peer_id;
    } else {
        close_tunnel(c, ti, "relay session already paired");
        return;
    }
    t->relay_link = link;
    if (r->ta >= 0 && r->tb >= 0) {
        tunnel *a = &c->tunnels[r->ta], *b = &c->tunnels[r->tb];
        uint8_t frame[8];
        a->relay_ready = b->relay_ready = 1;
        op_put64(frame, session);
        tframe(a, TUN_RELAY_READY, frame, sizeof(frame));
        tframe(b, TUN_RELAY_READY, frame, sizeof(frame));
        emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, "relay session paired");
    }
}
static void tunnel_message(fastp2p_client *c, int ti, uint16_t sub, const uint8_t *data,
                           size_t len) {
    tunnel *t = &c->tunnels[ti];
    t->last_rx = mono();
    if (t->state == T_HANDSHAKE || t->state == T_QUIC) {
        if (t->server && sub == TUN_HELLO && len == 8 && op_u64(data) == t->id) {
            tframe(t, TUN_HELLO_ACK, data, len);
            tunnel_active(c, ti);
        } else if (!t->server && sub == TUN_HELLO_ACK)
            tunnel_active(c, ti);
        else
            close_tunnel(c, ti, "invalid tunnel handshake");
        return;
    }
    if (t->state != T_ACTIVE)
        return;
    if (sub == TUN_RELAY_JOIN) {
        relay_receive(c, ti, data, len);
        return;
    }
    if (sub == TUN_RELAY_READY) {
        if (len != 8 || op_u64(data) != t->session) {
            close_tunnel(c, ti, "invalid relay ready");
            return;
        }
        t->relay_ready = 1;
        if (t->session_owner)
            session_ready(c, ti);
        else
            push_session_ack(c, t->relay_peer, t->session);
        return;
    }
    if (sub == TUN_CERT_BIND) {
        uint8_t digest[32], own[32];
        size_t n = 0;
        if (topen(c, ti, sub, data, len, digest, sizeof(digest), &n) || n != 32)
            return;
        if (opq_identity_digest(own) || !fp_equal(own, digest, sizeof(digest))) {
            close_tunnel(c, ti, "peer saw a different QUIC certificate");
            return;
        }
        t->cert_checked = 1;
        return;
    }
    if (sub == TUN_KEEPALIVE) {
        uint8_t id[8];
        op_put64(id, c->node_id);
        tframe(t, TUN_KEEPALIVE_ACK, id, sizeof(id));
        return;
    }
    if (sub == TUN_KEEPALIVE_ACK)
        return;
    /* Acting as a relay hop: pass application frames through untouched. */
    if (t->relay_link >= 0 && t->relay_ready) {
        if (sub != TUN_OPEN && sub != TUN_OPEN_ACK && sub != TUN_CLOSE && sub != TUN_DATA)
            return;
        relay_link *r = &c->relays[t->relay_link];
        int other = r->ta == ti ? r->tb : r->ta;
        if (other < 0 || other >= NT || c->tunnels[other].state != T_ACTIVE ||
            tframe(&c->tunnels[other], sub, data, len))
            close_tunnel(c, ti, "relay forwarding failed");
        return;
    }
    uint8_t plain[4096 + 256];
    size_t n = 0;
    int rv = topen(c, ti, sub, data, len, plain, sizeof(plain), &n);
    if (rv)
        return;
    if (sub == TUN_DATA) {
        if (n < 8)
            return;
        uint64_t id = op_u64(plain);
        for (int i = 0; i < NO; ++i) {
            overlay *o = &c->overlays[i];
            if (!o->used || o->id != id || o->tunnel_index != ti)
                continue;
            const uint8_t *payload = plain + 8;
            size_t length = n - 8;
            o->activity = mono();
            if (o->socks_parent) {
                socks_udp_reply(c, i, payload, length);
            } else if (o->udp) {
                op_ssize sent =
                    o->local_udp ? op_sendto(o->fd, payload, length, MSG_DONTWAIT,
                                             (struct sockaddr *)&o->source, sizeof(o->source))
                                 : op_send(o->fd, payload, length, MSG_DONTWAIT | MSG_NOSIGNAL);
                if (sent != (op_ssize)length)
                    close_overlay(c, i, 1);
            } else if (op_buffer_add(&o->tx, payload, length, OP_QUEUE_LIMIT)) {
                close_overlay(c, i, 1);
            }
            return;
        }
        return;
    }
    json_object *j = op_json(plain, n);
    if (!j)
        return;
    uint64_t id = op_integer(j, "id");
    if (sub == TUN_CLOSE) {
        for (int i = 0; i < NO; ++i)
            if (c->overlays[i].used && c->overlays[i].id == id &&
                c->overlays[i].tunnel_index == ti) {
                overlay *o = &c->overlays[i];
                if (o->socks_state == S_ACK) {
                    socks_failure(c, i, 5);
                    continue;
                }
                if (!o->udp && op_buffer_size(&o->tx)) {
                    /* A disconnect can follow the final data frame in the same
                     * read. Preserve those bytes until the local TCP write drains. */
                    o->peer_closed = 1;
                    o->waiting = 0;
                    o->deadline = mono() + 30 * NS;
                } else
                    close_overlay(c, i, 0);
            }
    } else if (sub == TUN_OPEN_ACK) {
        for (int i = 0; i < NO; ++i)
            if (c->overlays[i].used && c->overlays[i].id == id &&
                c->overlays[i].tunnel_index == ti) {
                overlay *o = &c->overlays[i];
                int socks = o->app_index >= 0 && c->apps[o->app_index].socks;
                if (socks)
                    socks_acknowledged(c, i, j);
                else
                    o->waiting = 0;
                break;
            }
    } else if (sub == TUN_OPEN) {
        const char *proto = op_string(j, "protocol"), *host = op_string(j, "dstIP");
        uint64_t port = op_integer(j, "dstPort");
        int duplicate = 0;
        for (int i = 0; i < NO; ++i)
            if (c->overlays[i].used && c->overlays[i].id == id && c->overlays[i].tunnel_index == ti)
                duplicate = 1;
        if (!duplicate && id && port > 0 && port <= 65535 && host && strlen(host) < 256 &&
            (!strcmp(proto, "tcp") || !strcmp(proto, "udp"))) {
            struct sockaddr_in peer;
            int oi = overlay_slot(c);
            if (oi >= 0) {
                overlay *o = &c->overlays[oi];
                o->id = id;
                o->app_index = -1;
                o->tunnel_index = ti;
                o->udp = !strcmp(proto, "udp");
                o->socks_exit = op_integer(j, "socks5") == 1;
                if (resolve4(host, (uint16_t)port, &peer)) {
                    overlay_ack(c, oi, 4);
                    close_overlay(c, oi, 0);
                    json_object_put(j);
                    return;
                }
                o->source = peer;
                if ((o->fd = socket_bound(o->udp, NULL, 0, 0)) < 0 ||
                    (op_connect(o->fd, (struct sockaddr *)&peer, sizeof(peer)) &&
                     errno != EINPROGRESS)) {
                    overlay_ack(c, oi, 5);
                    close_overlay(c, oi, 1);
                } else if (o->udp) {
                    o->connected = 1;
                    overlay_ack(c, oi, 0);
                }
            }
        }
    }
    json_object_put(j);
}
static void read_tunnel_frames(fastp2p_client *c, int ti) {
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
static void accept_punch(fastp2p_client *c, int ti) {
    tunnel *t = &c->tunnels[ti];
    if (t->listen_fd < 0 || (t->state != T_TCP_CONNECT && t->state != T_HANDSHAKE))
        return;
    struct sockaddr_in peer;
    op_socklen length = sizeof(peer);
    op_socket fd = op_accept(t->listen_fd, (struct sockaddr *)&peer, &length);
    if (fd < 0)
        return;
    struct in_addr expected;
    inet_pton(AF_INET, t->ip, &expected);
    if (peer.sin_addr.s_addr != expected.s_addr || ntohs(peer.sin_port) != t->remote_port) {
        op_close(fd);
        return;
    }
    if (!t->server && t->state == T_TCP_CONNECT) {
        if (t->fd >= 0)
            op_close(t->fd);
        t->fd = fd;
        t->state = T_HANDSHAKE;
        op_close(t->listen_fd);
        t->listen_fd = -1;
        uint8_t id[8];
        op_put64(id, t->id);
        tframe(t, 2, id, 8);
    } else if (t->server && t->alternate_fd < 0)
        t->alternate_fd = fd;
    else
        op_close(fd);
}
static void read_alternate(fastp2p_client *c, int ti) {
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
            op_close(t->fd);
        t->fd = t->alternate_fd;
        t->alternate_fd = -1;
        op_buffer_clear(&t->rx);
        t->rx = t->alternate_rx;
        memset(&t->alternate_rx, 0, sizeof(t->alternate_rx));
        tframe(t, 3, body, len);
        tunnel_active(c, ti);
    } else if (bad || rv) {
        op_close(t->alternate_fd);
        t->alternate_fd = -1;
        op_buffer_clear(&t->alternate_rx);
    }
    free(body);
}
static void tick_tunnel(fastp2p_client *c, int ti, uint64_t now) {
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
            if (op_send(t->fd, "1", 1, MSG_NOSIGNAL) != 1) {
                close_tunnel(c, ti, "TCP NAT marker failed");
                return;
            }
            t->state = T_NAT_READ;
        }
    }
    if (t->state == T_NAT_READ) {
        op_ssize n = op_recv(t->fd, t->probe + t->probe_len, sizeof(t->probe) - 1 - t->probe_len,
                             MSG_DONTWAIT);
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
        op_socklen flen = sizeof(from);
        op_ssize n =
            op_recvfrom(t->fd, data, sizeof(data), MSG_DONTWAIT, (struct sockaddr *)&from, &flen);
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
        if (t->transport == FASTP2P_TRANSPORT_QUIC && !strcmp(t->mode, "udppunch")) {
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
            op_socklen flen = sizeof(from);
            op_ssize n = op_recvfrom(t->fd, data, sizeof(data), MSG_DONTWAIT,
                                     (struct sockaddr *)&from, &flen);
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
            op_close(t->fd);
            t->fd = -1;
        }
        if (rv > 0) {
            t->state = T_HANDSHAKE;
            if (!t->server) {
                if (t->listen_fd >= 0)
                    op_close(t->listen_fd);
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
        /* Confirm the exact certificate the QUIC peer presented.  A direct
         * tunnel is the only case where both endpoints hold the session keys;
         * on a relay hop the QUIC peer is the relay, which forwards frames
         * without being able to open them. */
        if (!t->cert_sent && t->keyed && (t->key_acked || !t->session_owner) &&
            t->relay_link < 0 && !t->relay_wait) {
            uint8_t digest[32];
            if (!opq_peer_digest(t->quic, digest) && !tseal(c, t, TUN_CERT_BIND, digest, 32))
                t->cert_sent = 1;
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
            op_close(t->fd);
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
            tframe(t, TUN_KEEPALIVE, NULL, 0);
            t->last_hb = now;
        }
        /* A link that stays up for a minute has proven the path: clear the
         * failure counters so a later drop retries the direct punch first. */
        if (t->active_at && now >= t->active_at && now - t->active_at >= 60 * NS) {
            for (int i = 0; i < NA; ++i)
                if (c->apps[i].used && c->apps[i].local && c->apps[i].tunnel_index == ti) {
                    c->apps[i].attempts = 0;
                    c->apps[i].relay_failed_count = 0;
                }
            t->active_at = 0;
        }
    }
}
static void tick_accept(fastp2p_client *c, uint64_t now) {
    for (int k = 0; k < 8; ++k) {
        struct sockaddr_in peer;
        op_socklen len = sizeof(peer);
        op_socket fd = op_accept(c->listener, (struct sockaddr *)&peer, &len);
        if (fd < 0)
            break;
        int i;
        for (i = 0; i < NP; ++i)
            if (c->pending[i].fd < 0)
                break;
        if (i == NP)
            op_close(fd);
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
                op_close(p->fd);
            p->fd = -1;
            op_buffer_clear(&p->rx);
        }
    }
}
static void tick_overlays(fastp2p_client *c, uint64_t now) {
    for (int i = 0; i < NO; ++i) {
        overlay *o = &c->overlays[i];
        if (!o->used)
            continue;
        if (o->socks_state && o->socks_state != S_STREAM && o->socks_state != S_FLOW)
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
                overlay_ack(c, i, 5);
                close_overlay(c, i, 1);
                continue;
            }
            if (!rv)
                continue;
            o->connected = 1;
            overlay_ack(c, i, 0);
        }
        if (o->waiting)
            continue;
        if (o->socks_state == S_STREAM && op_buffer_size(&o->socks_rx)) {
            size_t length = op_buffer_size(&o->socks_rx);
            if (length > 4096)
                length = 4096;
            if (overlay_data(c, i, o->socks_rx.data + o->socks_rx.offset, length)) {
                close_overlay(c, i, 1);
                continue;
            }
            op_buffer_consume(&o->socks_rx, length);
            if (op_buffer_size(&o->socks_rx))
                continue;
            op_buffer_clear(&o->socks_rx);
        }
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
            op_ssize n = op_recv(o->fd, data, sizeof(data), MSG_DONTWAIT);
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
static void tick_apps(fastp2p_client *c, uint64_t now) {
    for (int i = 0; i < NA; ++i) {
        app *a = &c->apps[i];
        if (!a->used || !a->local)
            continue;
        if (a->socks) {
            for (int k = 0; k < 4; ++k) {
                struct sockaddr_in from;
                op_socklen length = sizeof(from);
                op_socket fd = op_accept(a->fd, (struct sockaddr *)&from, &length);
                if (fd < 0)
                    break;
                int oi = overlay_slot(c);
                if (oi < 0) {
                    op_close(fd);
                    break;
                }
                overlay *o = &c->overlays[oi];
                o->fd = fd;
                o->connected = 1;
                o->id = random_id();
                o->app_index = i;
                o->source = from;
                o->socks_state = S_HANDSHAKE;
                o->socks.state = SOCKS_GREETING;
                o->deadline = now + 10 * NS;
            }
        }
        /* A link that never finishes its session is not usable: retire it so the
         * retry ladder can move on (and eventually escalate to a relay). */
        if (a->tunnel_index >= 0 && !a->synced && a->link_deadline && now > a->link_deadline) {
            int dead = a->tunnel_index;
            a->link_deadline = 0;
            a->tunnel_index = -1;
            a->retry = now;
            if (c->tunnels[dead].state)
                close_tunnel(c, dead, "link did not become ready");
        }
        if (a->tunnel_index < 0 && now >= a->retry && c->state == FASTP2P_ONLINE) {
            int ti = active_tunnel(c, a->peer, a->transport);
            if (ti >= 0) {
                a->tunnel_index = ti;
                a->link_deadline = mono() + 20 * NS;
                if (c->tunnels[ti].key_acked)
                    session_ready(c, ti);
            } else if (a->relay_requested) {
                /* Waiting for the gateway to name a relay node. */
            } else {
                int in_progress = 0;
                for (int k = 0; k < NT; ++k)
                    if (c->tunnels[k].state && c->tunnels[k].transport == a->transport &&
                        (!strcmp(c->tunnels[k].peer, a->peer) ||
                         (c->tunnels[k].relay_wait && !strcmp(c->tunnels[k].relay_peer, a->peer))))
                        in_progress = 1;
                if (!in_progress) {
                    /* Two failed punches, symmetric NAT on both sides, or an
                     * explicit diagnostic request means a direct path is not
                     * reachable: ask the gateway for a relay.  A reachable LAN
                     * address is tried first, because it needs no NAT support
                     * at all and stays direct. */
                    if (lan_punch_possible(c, a) && a->attempts < 2 && !c->force_relay) {
                        ++a->attempts;
                        ti = app_tunnel(c, a, a->peer, a->transport);
                        if (ti >= 0) {
                            c->tunnels[ti].lan = 1;
                            start_punch(c, ti);
                        }
                    } else if (a->attempts >= 2 || c->force_relay ||
                        (c->nat_type == 2 && a->peer_nat == 2)) {
                        a->relay_requested = 1;
                        json_object *j = json_object_new_object();
                        op_js(j, "peerNode", a->peer);
                        if (a->relay_failed_count) {
                            json_object *skip = json_object_new_array();
                            for (int k = 0; k < a->relay_failed_count; ++k)
                                json_object_array_add(skip, json_object_new_string(a->relay_failed[k]));
                            json_object_object_add(j, "exclude", skip);
                        }
                        ws_json(c, 5, 0, j);
                        json_object_put(j);
                    } else {
                        ++a->attempts;
                        ti = app_tunnel(c, a, a->peer, a->transport);
                        if (ti >= 0)
                            start_punch(c, ti);
                    }
                }
            }
            a->retry = now + 2 * NS;
        }
        if (a->tunnel_index < 0 || !a->synced || now < a->ready_at)
            continue;
        if (a->socks)
            continue;
        if (!a->udp) {
            for (int k = 0; k < 4; ++k) {
                op_socket fd = op_accept(a->fd, NULL, NULL);
                if (fd < 0)
                    break;
                int oi = overlay_slot(c);
                if (oi < 0) {
                    op_close(fd);
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
                op_socklen flen = sizeof(from);
                op_ssize n = op_recvfrom(a->fd, data, sizeof(data), MSG_DONTWAIT,
                                         (struct sockaddr *)&from, &flen);
                if (n < 0)
                    break;
                if (n > 4096) {
                    emit(c, FASTP2P_EVENT_ERROR, a->id, FASTP2P_ELIMIT,
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
static void send_heartbeat(fastp2p_client *c) {
    c->heartbeat_sent = wall();
    c->heartbeat_at = mono();
    ws_json(c, 1, 0, NULL);
}
static op_once curl_once = OP_ONCE_INIT;
static CURLcode curl_initialization;
static void initialize_curl(void) {
    curl_initialization = curl_global_init(CURL_GLOBAL_DEFAULT);
}
static void close_gateway(fastp2p_client *c) {
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
        set_state(c, FASTP2P_RECONNECTING, "gateway disconnected; retry scheduled");
    }
}
static void gateway_failed(fastp2p_client *c) {
    emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO,
         "WSS connection failed: check gateway address, CA, certificate hostname and token");
    close_gateway(c);
}
static void connect_gateway(fastp2p_client *c) {
    c->ws = curl_easy_init();
    if (!c->ws) {
        gateway_failed(c);
        return;
    }
    snprintf(c->path, sizeof(c->path),
             "wss://%s:%u/api/v1/login?node=%s&token=%" PRIu64
             "&protocol=" WIRE_PROTOCOL "&version=%s&nattype=%d&sharebandwidth=0",
             c->host, c->port, c->node, c->token, WIRE_VERSION, c->nat_type);
    if (c->automatic_node) {
        char hostname[32];
        node_base(hostname, c->hostname);
        size_t used = strlen(c->path);
        snprintf(c->path + used, sizeof(c->path) - used, "&autonode=1&deviceid=%s&hostname=%s",
                 c->device_id, hostname);
    }
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
#ifdef _WIN32
    if (c->ca[0])
        SETOPT(CURLOPT_SSL_OPTIONS, (long)CURLSSLOPT_REVOKE_BEST_EFFORT);
#endif
#undef SETOPT
    if (curl_multi_add_handle(c->multi, c->ws) != CURLM_OK)
        gateway_failed(c);
}
static void service_gateway(fastp2p_client *c) {
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
        op_js(j, "os", FASTP2P_PLATFORM_OS);
        op_js(j, "hostname", c->hostname);
        op_js(j, "version", WIRE_VERSION);
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
static void tick_nat(fastp2p_client *c, uint64_t now) {
    if (c->nat_fd < 0)
        return;
    uint8_t data[1024];
    struct sockaddr_in from;
    op_socklen flen = sizeof(from);
    op_ssize n =
        op_recvfrom(c->nat_fd, data, sizeof(data), MSG_DONTWAIT, (struct sockaddr *)&from, &flen);
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
        emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO,
             "UDP NAT discovery unavailable; TCP transport can still be attempted");
    }
    if (finish) {
        op_close(c->nat_fd);
        c->nat_fd = -1;
        connect_gateway(c);
    }
}
uint32_t fastp2p_abi_version(void) {
    return FASTP2P_ABI_VERSION;
}
const char *fastp2p_version(void) {
    return FASTP2P_VERSION;
}
int fastp2p_client_create(const fastp2p_config *cfg, fastp2p_client **out) {
    if (!out)
        return FASTP2P_EINVAL;
    *out = NULL;
    if (op_platform_init())
        return FASTP2P_EIO;
    if (!cfg || cfg->struct_size < sizeof(*cfg) || cfg->abi_version != FASTP2P_ABI_VERSION ||
        (cfg->node && *cfg->node && !valid_node(cfg->node)) || !cfg->token || !cfg->gateway_host || !*cfg->gateway_host)
        return FASTP2P_EINVAL;
    fastp2p_client *c = calloc(1, sizeof(*c));
    if (!c)
        return FASTP2P_ENOMEM;
    if (copy_string(c->host, sizeof(c->host), cfg->gateway_host) ||
        (cfg->node && copy_string(c->node, sizeof(c->node), cfg->node)) ||
        (cfg->ca_file && copy_string(c->ca, sizeof(c->ca), cfg->ca_file))) {
        free(c);
        return FASTP2P_EINVAL;
    }
    for (const char *p = c->host; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
              *p == '.' || *p == '-' || *p == '_')) {
            free(c);
            return FASTP2P_EINVAL;
        }
    c->port = cfg->gateway_port ? cfg->gateway_port : 27183;
    c->public_port = cfg->public_port;
    c->token = cfg->token;
    if (op_hostname(c->hostname, sizeof(c->hostname)))
        strcpy(c->hostname, "node");
    c->automatic_node = !cfg->node || !*cfg->node;
    if (c->automatic_node) {
        unsigned char bytes[16];
        if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
            free(c);
            return FASTP2P_EIO;
        }
        for (unsigned i = 0; i < sizeof(bytes); ++i)
            snprintf(c->device_id + i * 2, 3, "%02x", bytes[i]);
        automatic_candidate(c);
    }
    c->node_id = op_node_id(c->node);
    c->callback = cfg->on_event;
    c->user = cfg->user;
    c->listener = c->nat_fd = -1;
    c->force_relay = getenv("FASTP2P_FORCE_RELAY") != NULL;
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
    return FASTP2P_OK;
}
int fastp2p_client_add_forward(fastp2p_client *c, const fastp2p_forward *f, uint64_t *id) {
    if (!c || !f || f->struct_size < sizeof(*f) || c->in_callback || !valid_node(f->peer_node) ||
        ((!c->automatic_node || c->login_ok) && !strcmp(f->peer_node, c->node)) || !f->local_port || !f->destination_port ||
        !f->destination_host || !*f->destination_host || !f->protocol ||
        (strcmp(f->protocol, "tcp") && strcmp(f->protocol, "udp")) ||
        (f->transport != FASTP2P_TRANSPORT_TCP && f->transport != FASTP2P_TRANSPORT_QUIC))
        return FASTP2P_EINVAL;
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used && c->apps[i].local && c->apps[i].port == f->local_port &&
            c->apps[i].udp == !strcmp(f->protocol, "udp"))
            return FASTP2P_ESTATE;
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
                return FASTP2P_EINVAL;
            struct in_addr check;
            if (inet_pton(AF_INET, a->bind_ip, &check) != 1)
                return FASTP2P_EINVAL;
            a->id = random_id();
            a->session = random_id();
            fp_random(a->secret, sizeof(a->secret));
            a->has_session = 1;
            a->port = f->local_port;
            a->dst_port = f->destination_port;
            a->udp = !strcmp(f->protocol, "udp");
            a->transport = f->transport;
            a->local = a->used = 1;
            a->fd = socket_bound(a->udp, a->bind_ip, a->port, 0);
            if (a->fd < 0 || (!a->udp && op_listen(a->fd, 64))) {
                if (a->fd >= 0)
                    op_close(a->fd);
                a->used = 0;
                return FASTP2P_EIO;
            }
            if (id)
                *id = a->id;
            return FASTP2P_OK;
        }
    return FASTP2P_ELIMIT;
}
int fastp2p_client_add_socks5(fastp2p_client *c, const fastp2p_socks5 *p, uint64_t *id) {
    if (!p || p->struct_size < sizeof(*p))
        return FASTP2P_EINVAL;
    const char *user = p->username ? p->username : "", *password = p->password ? p->password : "";
    if (strlen(user) > 255 || strlen(password) > 255 || (!*user != !*password))
        return FASTP2P_EINVAL;
    fastp2p_forward f = {.struct_size = sizeof(f),
                      .name = p->name ? p->name : "socks5",
                      .bind_ip = p->bind_ip,
                      .local_port = p->local_port,
                      .peer_node = p->peer_node,
                      .destination_host = "127.0.0.1",
                      .destination_port = 1,
                      .protocol = "tcp",
                      .transport = p->transport};
    uint64_t aid;
    int rv = fastp2p_client_add_forward(c, &f, &aid);
    if (rv)
        return rv;
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used && c->apps[i].id == aid) {
            app *a = &c->apps[i];
            a->socks = 1;
            a->destination[0] = 0;
            a->dst_port = 0;
            strcpy(a->socks_user, user);
            strcpy(a->socks_password, password);
            break;
        }
    if (id)
        *id = aid;
    return FASTP2P_OK;
}
int fastp2p_client_start(fastp2p_client *c) {
    if (!c || c->in_callback || c->running || c->multi)
        return FASTP2P_ESTATE;
    op_once_run(&curl_once, initialize_curl);
    if (curl_initialization != CURLE_OK)
        return FASTP2P_EIO;
    if (resolve4(c->host, c->port, &c->gateway)) {
        emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, "gateway DNS resolution failed");
        return FASTP2P_EIO;
    }
    c->listener = socket_bound(0, NULL, c->public_port, 1);
    if (c->listener < 0 || op_listen(c->listener, 32)) {
        if (c->listener >= 0)
            op_close(c->listener);
        c->listener = -1;
        return FASTP2P_EIO;
    }
    c->public_port = socket_port(c->listener);
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used && c->apps[i].local && c->apps[i].fd < 0) {
            app *a = &c->apps[i];
            a->fd = socket_bound(a->udp, a->bind_ip, a->port, 0);
            if (a->fd < 0 || (!a->udp && op_listen(a->fd, 64))) {
                fastp2p_client_stop(c);
                return FASTP2P_EIO;
            }
        }
    c->multi = curl_multi_init();
    if (!c->multi) {
        fastp2p_client_stop(c);
        return FASTP2P_EIO;
    }
    c->running = 1;
    c->stopping = 0;
    c->reconnect_at = 0;
    c->nat_type = 314;
    set_state(c, FASTP2P_CONNECTING, "discovering NAT and connecting to gateway");
    c->nat_fd = socket_bound(1, NULL, 0, 0);
    c->nat_phase = 1;
    c->nat_deadline = mono() + 2 * NS;
    struct sockaddr_in peer = c->gateway;
    peer.sin_port = htons(27180);
    if (c->nat_fd < 0)
        connect_gateway(c);
    else
        udp_packet(c->nat_fd, &peer, 2, 0, NULL);
    return FASTP2P_OK;
}
int fastp2p_client_step(fastp2p_client *c, unsigned wait_ms) {
    if (!c || !c->running || c->in_callback || c->stepping)
        return FASTP2P_ESTATE;
    c->stepping = 1;
    if (c->stopping) {
        c->stepping = 0;
        return fastp2p_client_stop(c);
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
    tick_relays(c, now);
    tick_apps(c, now);
    tick_socks(c, now);
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
        return fastp2p_client_stop(c);
    return FASTP2P_OK;
}
int fastp2p_client_stop(fastp2p_client *c) {
    if (!c)
        return FASTP2P_EINVAL;
    if (c->in_callback || c->stepping) {
        c->stopping = 1;
        return FASTP2P_OK;
    }
    c->stopping = 1;
    c->running = 0;
    for (int i = 0; i < NT; ++i)
        close_tunnel(c, i, NULL);
    for (int i = 0; i < NO; ++i)
        if (c->overlays[i].used)
            close_overlay(c, i, 0);
    for (int i = 0; i < NP; ++i) {
        if (c->pending[i].fd >= 0)
            op_close(c->pending[i].fd);
        c->pending[i].fd = -1;
        op_buffer_clear(&c->pending[i].rx);
    }
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used && c->apps[i].local && c->apps[i].fd >= 0) {
            op_close(c->apps[i].fd);
            c->apps[i].fd = -1;
        }
    if (c->listener >= 0)
        op_close(c->listener);
    c->listener = -1;
    if (c->nat_fd >= 0)
        op_close(c->nat_fd);
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
    set_state(c, FASTP2P_STOPPED, "client stopped");
    return FASTP2P_OK;
}
void fastp2p_client_destroy(fastp2p_client *c) {
    if (!c || c->in_callback || c->stepping)
        return;
    fastp2p_client_stop(c);
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used && c->apps[i].local && c->apps[i].fd >= 0)
            op_close(c->apps[i].fd);
    OPENSSL_cleanse(c, sizeof(*c));
    free(c);
}
fastp2p_state fastp2p_client_state(const fastp2p_client *c) {
    return c ? c->state : FASTP2P_STOPPED;
}
const char *fastp2p_client_last_error(const fastp2p_client *c) {
    return c ? c->error : "invalid client";
}
