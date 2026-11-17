#include "platform.h"
#include "fastp2p.h"
#include "update.h"
#include "wire.h"
#include "quic.h"
#include "socks.h"
#include "stun.h"
#include "tcp_level.h"
#include "secure.h"
#include "tcp_nat.h"
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
#define SYM_WINDOW_MAX 50
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
/* Address-family bitmaps (SPEC §1). The gateway uses the same two values, so
 * these numbers are protocol, not local policy. */
enum { FAM_V4 = 1, FAM_V6 = 2, FAM_BOTH = 3 };
enum tunnel_state {
    T_FREE,
    /* While any address-family mapping probe is outstanding the tunnel sits in
     * this one state; the per-family probe machines carry the old
     * T_NAT_CONNECT/READ/UDP detail. */
    T_PROBE,
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
/* One address-family mapping probe. A dual-stack client runs the identical
 * sequence once per family, against the gateway's address of that family
 * (SPEC §2); a v4-only client keeps exactly one, which is the old behaviour.
 * The socket in `fd` is the source port the mapping was measured from, so it
 * doubles as the LAN/punch socket of that family until the tunnel adopts it. */
enum { PROBE_FREE = 0, PROBE_CONNECT, PROBE_READ, PROBE_UDP, PROBE_DONE };
typedef struct {
    int state;
    op_socket fd;
    uint16_t local_port, mapped_port;
    char mapped_ip[OP_ADDR_TEXT];
    char response[96];
    size_t response_len;
    uint64_t last_rx;
    /* Advisory families (anything but the primary one) get their own, shorter
     * budget so an unreachable v6 probe cannot hold up the v4 answer. */
    uint64_t deadline;
} nat_probe;
/* Per-family NAT classification state. Running the old single probe sequence
 * once per family is what keeps the IPv4 run byte-identical while letting IPv6
 * be measured the same way (SPEC §2/§4). */
typedef struct {
    int phase, type;
    op_socket fd, fd2;
    uint16_t port, port2, second;
    uint64_t deadline;
    /* A probe can be lost while the gateway is busy accepting a burst of
     * reconnections, so an undetermined result is retried instead of being
     * reported as "unknown" on the first timeout. */
    int retries;
} nat_discovery;
typedef struct {
    int phase; /* 0 idle, 1 plain, 2 change-port, 3 change-ip, 4 done */
    int server, count;
    op_addr addr[FP_STUN_MAX_SERVERS];
    op_socket fd;
    uint8_t tid[FP_STUN_NONCE];
    uint64_t deadline;
    op_addr mapped;  /* first mapping observed; the rest must match to be cone */
    int mapped_seen;
    int mapped_same; /* every server reported the same mapping */
    int port_changed, ip_changed;
    /* Only a reply from a different source shows a server honours the request;
     * a server advertising OTHER-ADDRESS also declares it implements change-ip.
     * Without either, a missing reply is not evidence of filtering. */
    int port_supported, ip_supported;
    int has_alternate; /* some server advertised its alternate address */
    int level; /* 0 = STUN produced no verdict */
    /* 1 when the server reported exactly the address we sent from, i.e. the path
     * has no NAT translation and the level describes the host firewall. */
    int no_nat;
    /* One retransmission per phase: a single lost datagram (common right after
     * startup, while DNS and routing settle) must not throw away the mapping and
     * turn a measurable NAT into "unknown". */
    int retried;
} nat_stun;
typedef struct {
    int state, server, initiator, transport, notified;
    int tcp_v2;
    unsigned tcp_attempts;
    uint64_t tcp_attempt_deadline, tcp_retry_at;
    op_socket fd, listen_fd, alternate_fd;
    uint64_t id, peer_id, deadline, at, last_rx, last_hb, punch_next, punch_started;
    /* Peer's predicted mapping window: base port, direction and width. A
     * symmetric peer changes port per destination, so the peer tells us
     * where its next mapping is likely to land and we spray that range. */
    uint16_t sym_base, sym_count;
    int sym_up, sym_sprayed;
    uint64_t active_at;
    /* Endpoint text is canonical address text (no brackets, no %scope) in
     * whichever family it was learned, so an IPv6 peer no longer truncates into
     * a 16-byte IPv4 buffer. `ip`/`mapped_ip` name the active family; the
     * per-family arrays carry both, because a dual-stack negotiation publishes
     * both and the punch may still have to fall back from one to the other. */
    char peer[32], ip[OP_ADDR_TEXT], mapped_ip[OP_ADDR_TEXT], mode[16], probe[96];
    size_t probe_len;
    /* Peer endpoints and our own mapping observations, by family (SPEC §5). */
    char peer_text[OP_FAM_COUNT][OP_ADDR_TEXT], mapped_text[OP_FAM_COUNT][OP_ADDR_TEXT];
    uint16_t remote_ports[OP_FAM_COUNT], mapped_ports[OP_FAM_COUNT];
    /* 1 when the peer gave us a usable endpoint of that family. */
    int peer_ready[OP_FAM_COUNT];
    uint64_t peer_families; /* peer families bitmap (SPEC §1), 0 = unknown */
    nat_probe probes[OP_FAM_COUNT];
    /* `family` is the one this tunnel punches in; `fallback_family` is the one
     * to retry when it times out (SPEC §5: a shared v6 is tried first, because
     * it usually has no NAT at all, and IPv4 is the path an old peer can always
     * answer). -1 means no alternative. `family_switched` bounds the retry to
     * one, so a broken pair cannot ping-pong. */
    int family, fallback_family, family_switched;
    uint16_t local_port, mapped_port, remote_port;
    /* The remote endpoint actually punched toward, with its family. Rebuilt
     * from peer_text/remote_ports whenever the family is chosen, so connect,
     * accept comparison and the QUIC context all agree on one tuple. */
    op_addr peer_addr;
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
    char name[64], peer[32], destination[256], bind_ip[OP_ADDR_TEXT];
    char socks_user[256], socks_password[256];
    uint16_t port, dst_port;
    int attempts, relay_wanted, relay_requested;
    int lan_tried; /* the LAN punch was already attempted for this rule */
    int no_relay;  /* operator disabled relay fallback for this rule */
    /* Operator-chosen relay for this rule; empty means automatic. */
    char relay_node[32];
    uint64_t peer_nat, peer_tcp_nat, link_deadline;
    /* Relays that already failed for this rule; the gateway is asked to skip
     * them so one unreachable candidate cannot pin the link forever. */
    struct {
        char node[32];
        uint64_t until;
    } relay_failed[4];
    int relay_failed_count;
    /* The peer's own local address, per family (SPEC §5: same-LAN detection
     * compares within a family). lanIP stays IPv4 as before; lanIP6 is only
     * filled when the peer reports one, so an old peer looks LAN-less exactly
     * as it did before. */
    char peer_lan[OP_ADDR_TEXT], peer_lan6[OP_ADDR_TEXT];
    uint64_t peer_families, peer_nat6, peer_tcp_nat6;
    /* The current attempt's session; relay offers create a fresh session. */
    uint64_t session;
    uint8_t secret[FP_SESSION_SECRET];
    int has_session;
} app;
typedef struct {
    int used, udp, connected, local_udp, app_index, tunnel_index, waiting, peer_closed;
    int read_eof, peer_eof, write_shutdown;
    op_socket fd;
    uint64_t id, activity, deadline;
    /* Endpoints carry their family: an overlay that reaches a v6 destination or
     * a v6 SOCKS client must not be flattened into an IPv4-only sockaddr. */
    op_addr source;
    op_buffer tx, early, socks_rx;
    int socks_state, socks_exit;
    op_socket socks_udp;
    uint64_t socks_parent;
    op_socks socks;
    op_addr socks_peer;
} overlay;
typedef struct {
    op_socket fd;
    uint64_t deadline;
    op_addr peer;
    op_buffer rx;
} pending;
/* A session secret received from the initiating peer before its tunnel is
 * usable.  Pending entries expire so a failed punch cannot leak state. */
typedef struct {
    int used, transport;
    uint64_t session, peer_id, tunnel_id, deadline;
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
    char host[256], ca[4096], node[32];
    char error[192], path[2048], hostname[256], device_id[33];
    int automatic_node;
    uint16_t port, public_port;
    uint64_t token, node_id, reconnect_at, last_rx, heartbeat_at, heartbeat_sent;
    int64_t clock_delta;
    fastp2p_state state;
    int running, stopping, in_callback, stepping, report_ok, login_ok, reconnect_attempt;
    /* NAT classification is per family (DUALSTACK-SPEC §2/§4). Index 0 holds
     * exactly the values the old single fields carried, so a v4-only run
     * reports and logs byte-identical numbers. */
    nat_discovery nat[OP_FAM_COUNT];
    /* Post-login inbound-filtering refinement; IPv4 only, because the console
     * reports NAT levels for IPv4 alone (IPv6 normally has no NAT to classify). */
    /* Optional public STUN servers, resolved at start (FP_STUN_MAX_SERVERS). */
    char stun_host[FP_STUN_MAX_SERVERS][254];
    uint16_t stun_port[FP_STUN_MAX_SERVERS];
    int stun_count;
    nat_stun stun;
    fp_tcp_level tcp_level;
    int tcp_level_reported; /* the TCP verdict was already announced */
    /* 1 once every family we decided to probe has finished (or timed out), so
     * the login goes out with a complete picture rather than half-way. */
    int nat_settled;
    fp_tcp_nat tcp_nat;
    int force_relay; /* FASTP2P_FORCE_RELAY diagnostic switch */
    int nat_override; /* FASTP2P_NAT_TYPE diagnostic switch, 0 = use the probe */
    /* Curl writes the detailed TLS reason here; the short error code alone
     * cannot say whether the handshake was refused, reset, or rejected. */
    char curl_error[CURL_ERROR_SIZE];
    /* The direct-punch listener, one per family: an IPv6 peer connects our v6
     * listener, an IPv4 peer the v4 one. A v4-only run opens only the v4
     * listener, as before. public_port stays the configured hint; the bound
     * ports are recorded per family because they can differ. */
    op_socket listener[OP_FAM_COUNT];
    uint16_t listener_port[OP_FAM_COUNT];
    /* Public observations, one per family, in canonical text. Index 0 is what
     * the old `ip`/`local_ip` fields held; an unset entry is an empty string,
     * never a stale 0.0.0.0 that a later bind would trust. */
    char ip[OP_FAM_COUNT][OP_ADDR_TEXT], local_ip[OP_FAM_COUNT][OP_ADDR_TEXT];
    /* Local source address of the WSS control connection, with its family: the
     * old code copied CURLINFO_LOCAL_IP into a 16-byte IPv4 buffer, so a v6
     * connection silently kept "0.0.0.0" and every socket bound to the reported
     * source address went out the wrong interface. */
    op_addr control_local;
    /* Every address the gateway hostname resolved to. The control connection
     * uses `gateway` (the preferred one); probes and CURLOPT_RESOLVE use all. */
    op_addr gateway, gateway_addr[OP_FAM_COUNT];
    int gateway_families; /* bitmap: 1 = v4, 2 = v6 */
    int families_wanted;  /* what we publish: observed ∩ configured intent */
    CURLM *multi;
    CURL *ws;
    struct curl_slist *resolve;
    curl_socket_t ws_socket;
    int ws_connected;
    int gateway_tcp_probe_v2, gateway_tcp_probe_v3;
    size_t ws_remaining;
    op_buffer ws_rx, ws_tx;
    fastp2p_event_fn callback;
    fastp2p_config_handler config_handler;
    void *config_user;
    int validate_only;
    void *user;
    tunnel tunnels[NT];
    app apps[NA];
    overlay overlays[NO];
    pending pending[NP];
    pending_key keys[NPK];
    relay_link relays[NRL];
};
static void connect_gateway(fastp2p_client *);
static int nat_level(const fastp2p_client *);
static int tcp_nat_level(const fastp2p_client *);
static int refresh_families(fastp2p_client *);
static void control_message(fastp2p_client *, uint16_t, uint16_t, const uint8_t *, size_t);
static void close_tunnel(fastp2p_client *, int, const char *);
static void release_relay(fastp2p_client *, int);
static void bind_pending_key(fastp2p_client *, int);
static void relay_join(fastp2p_client *, int);
static void session_ready(fastp2p_client *, int);
static void probe_complete(fastp2p_client *, int);
static int tcp_punch_listen(fastp2p_client *, int);
static void report_client(fastp2p_client *);
static void report_nat(fastp2p_client *);
static void tick_nat(fastp2p_client *, uint64_t);
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
/* Families bitmap helpers (SPEC §1). `nat` is IPv4-only in the old sense; the
 * per-family helpers below are what makes a v6 measurement possible without
 * changing any v4 number. */
static int family_bit(int index) { return index == OP_FAM_V4 ? FAM_V4 : FAM_V6; }
static int family_index(unsigned bit) { return bit == FAM_V6 ? OP_FAM_V6 : OP_FAM_V4; }
/* The one required family: IPv4 whenever it is available (the historical path),
 * otherwise IPv6. A v4-only run therefore treats IPv4 exactly as before and a
 * v6-only gateway still has one family whose failure is fatal rather than
 * advisory. */
static int primary_family(const fastp2p_client *c) {
    return family_index((c->families_wanted & FAM_V4) ? FAM_V4 : FAM_V6);
}
/* 1 when this client intends to probe/publish `index` (SPEC §1). The default is
 * IPv4-only, so a dual-stack hostname does not silently add v6 latency to a
 * previously working v4 link. */
static int family_wanted(const fastp2p_client *c, int index) {
    return (c->families_wanted & family_bit(index)) ? 1 : 0;
}
/* 1 when `text` is a canonical literal of exactly family `index`. Empty or
 * unparseable text is never present, so an old peer never appears v6-capable. */
static int address_of_family(const char *text, int index) {
    op_addr scratch;
    return text && *text && !op_addr_from_text(&scratch, text, 0) &&
           op_family_index(op_addr_family(&scratch)) == index;
}
/* Writes canonical text for `index`, or clears the slot when there is nothing
 * of that family to say. Keeping a slot empty rather than 0.0.0.0 is what stops
 * a later bind from going out with a bogus source address. */
static void address_text_out(char out[OP_ADDR_TEXT], const char *text, int index) {
    if (!address_of_family(text, index)) {
        out[0] = 0;
        return;
    }
    snprintf(out, OP_ADDR_TEXT, "%s", text);
}
/* Copy bounded endpoint text between fields that may live in the same object;
 * memmove makes the source/destination overlap a non-issue. */
static void address_copy(char out[OP_ADDR_TEXT], const char *text) {
    if (!text) {
        out[0] = 0;
        return;
    }
    size_t length = strlen(text);
    if (length >= OP_ADDR_TEXT)
        length = OP_ADDR_TEXT - 1;
    if (length)
        memmove(out, text, length);
    out[length] = 0;
}
/* A gateway host is either a name we may look up, or a literal address of
 * either family. Colons belong to IPv6 literals, so a host holding one is only
 * accepted when it really parses as one (SPEC §7). The old check rejected every
 * colon, which made "::1" and "2001:db8::1" unusable as ServerHost. */
static int valid_gateway_host(const char *host) {
    int colons = 0;
    for (const char *p = host; *p; ++p) {
        unsigned char c = (unsigned char)*p;
        if (c == ':') {
            ++colons;
            continue;
        }
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '-' || c == '_'))
            return 0;
    }
    if (!colons)
        return 1;
    /* Only an IPv6 literal may carry colons, and it must be complete: no
     * brackets (URL syntax, not address text) and no embedded scope. */
    op_addr scratch;
    if (strchr(host, '[') || strchr(host, '%'))
        return 0;
    return op_addr_from_text(&scratch, host, 0) == 0 && op_addr_family(&scratch) == AF_INET6;
}
/* A LAN punch is possible when both ends hold a private address for each other
 * **in the same family** (SPEC §5). Comparing a v4 self-report against a v6
 * peer report would claim a LAN path that does not exist. The IPv4 pair is
 * checked first so the historical decision is unchanged whenever v4 exists. */
static int lan_punch_possible(const fastp2p_client *c, const app *a) {
    for (int index = 0; index < OP_FAM_COUNT; ++index) {
        const char *peer_text = index == OP_FAM_V4 ? a->peer_lan : a->peer_lan6;
        op_addr peer, local;
        if (!address_of_family(peer_text, index) ||
            !address_of_family(c->local_ip[index], index) ||
            op_addr_from_text(&peer, peer_text, 0) ||
            op_addr_from_text(&local, c->local_ip[index], 0))
            continue;
        if (op_addr_private(&peer) && op_addr_private(&local))
            return 1;
    }
    return 0;
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
/* Resolve a host to **every** family it has. `want` is a FAM_* bitmap. Returns
 * the bitmap of families actually resolved; out/per_family carry the answers.
 *
 * Each family is asked for explicitly instead of issuing one AF_UNSPEC query:
 * resolvers and NSS paths that answer A but drop AAAA for a combined request
 * are common enough that a single query silently made a v6-capable host look
 * IPv4-only, which in turn disabled its v6 listeners and probes. */
static int resolve_any_families(const char *host, uint16_t port, int want, op_addr *out,
                                op_addr per_family[OP_FAM_COUNT]) {
    (void)want;
    int found = 0;
    op_addr collected[OP_FAM_COUNT];
    memset(collected, 0, sizeof(collected));
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = op_index_family(family);
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host, NULL, &hints, &res))
            continue;
        for (struct addrinfo *p = res; p; p = p->ai_next) {
            if (!p->ai_addr || p->ai_addrlen < sizeof(struct sockaddr))
                continue;
            if (p->ai_family != op_index_family(family))
                continue;
            op_addr a;
            memset(&a, 0, sizeof(a));
            a.len = (op_socklen)p->ai_addrlen;
            if (a.len > (op_socklen)sizeof(a.u.storage))
                a.len = (op_socklen)sizeof(a.u.storage);
            memcpy(&a.u.storage, p->ai_addr, a.len);
            op_addr_normalize(&a); /* a v4-mapped answer is one peer, in one family */
            if (op_family_index(op_addr_family(&a)) != family)
                continue;
            op_addr_set_port(&a, port);
            collected[family] = a;
            found |= family_bit(family);
            break;
        }
        freeaddrinfo(res);
    }
    if (!found)
        return 0;
    /* The preferred answer keeps the historical default: the old code asked for
     * AF_INET only, so a v4 answer wins unless there is nothing else. That leaves
     * a v4-capable gateway reachable exactly as before while letting a v6-only
     * host resolve at all. */
    int preferred = collected[OP_FAM_V4].len ? OP_FAM_V4 : OP_FAM_V6;
    if (out)
        op_addr_copy(out, &collected[preferred]);
    if (per_family)
        memcpy(per_family, collected, sizeof(collected));
    return found;
}
static int resolve_any(const char *host, uint16_t port, op_addr *out) {
    return resolve_any_families(host, port, 0, out, NULL) ? 0 : -1;
}
/* Bind an endpoint of the family the literal implies. A v4 literal binds the
 * IPv4 any address, a v6 literal the IPv6 one, and an empty one keeps the
 * historical IPv4 any-address default, so behaviour is unchanged unless the
 * caller actually hands over an IPv6 text. */
static op_socket socket_bound_addr(int udp, const op_addr *a, uint16_t port, int reuse) {
    op_addr bind_to;
    memset(&bind_to, 0, sizeof(bind_to));
    if (!a || !a->len) {
        if (op_addr_from_text(&bind_to, "0.0.0.0", port))
            return -1;
        a = &bind_to;
    }
    bind_to = *a;
    op_addr_set_port(&bind_to, port);
    op_socket fd = op_socket_open(op_addr_family(&bind_to), (udp ? SOCK_DGRAM : SOCK_STREAM), 0);
    if (fd < 0)
        return -1;
    int one = 1;
    /* An explicit v6 endpoint must not reserve the same port in the IPv4 space:
     * a dual-stack run binds one listener per family on the same port, and the
     * Linux default (bindv6only=0) would make the v6 socket fail the v4 bind. */
    if (op_addr_family(&bind_to) == AF_INET6)
        op_setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    if (reuse && op_reuse_socket(fd)) {
        op_close(fd);
        return -1;
    }
    if (op_bind(fd, &bind_to.u.sa, bind_to.len)) {
        op_close(fd);
        return -1;
    }
    if (!udp) {
        op_setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        op_setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    }
    return fd;
}
static op_socket socket_bound(int udp, const char *ip, uint16_t port, int reuse) {
    op_addr a;
    memset(&a, 0, sizeof(a));
    if (ip && *ip && op_addr_from_text(&a, ip, port))
        return -1;
    return socket_bound_addr(udp, a.len ? &a : NULL, port, reuse);
}
static uint16_t socket_port(op_socket fd) {
    op_addr a;
    return op_addr_socketname(fd, &a) ? 0 : op_addr_port(&a);
}
static int socket_family(op_socket fd) {
    op_addr a;
    return op_addr_socketname(fd, &a) ? -1 : op_family_index(op_addr_family(&a));
}
/* Source text to bind a family-specific socket on. A family whose control
 * connection was not that family (dual-stack host reached over IPv4) has no
 * learned v6 local address, so the v6 wildcard is used instead of silently
 * asking socket_bound for an IPv4 socket. The v4 default is unchanged. */
static const char *source_text(const fastp2p_client *c, int family) {
    if (family == OP_FAM_V6)
        return c->local_ip[OP_FAM_V6][0] ? c->local_ip[OP_FAM_V6] : "::";
    return c->local_ip[OP_FAM_V4];
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
/* Mapping behaviour, reported to peers through the login query. 1 and 2 keep
 * their historical meaning so older peers still read the value correctly. */
enum { NAT_UNKNOWN = 314, NAT_CONE = 1, NAT_HARD_SYM = 2, NAT_EASY_SYM_INC = 3,
       NAT_EASY_SYM_DEC = 4 };
/* A symmetric NAT is the only case where a direct punch is hopeless between two
 * peers, so both the relay decision and the gateway's candidate filter use it. */
static int nat_is_hard_sym(uint64_t nat) { return nat == NAT_HARD_SYM; }
static uint64_t local_transport_nat(const fastp2p_client *c, int transport) {
    /* Index 0 is the old single value: a v4-only run reports and decides
     * exactly as before. */
    return transport == FASTP2P_TRANSPORT_TCP ? c->tcp_nat.family[OP_FAM_V4].type
                                              : (uint64_t)c->nat[OP_FAM_V4].type;
}
static uint64_t peer_transport_nat(const app *a) {
    return a->transport == FASTP2P_TRANSPORT_TCP ? a->peer_tcp_nat : a->peer_nat;
}
int fp_client_tcp_nat_config(fastp2p_client *c, json_object *servers) {
    return fp_tcp_nat_configure(&c->tcp_nat, servers) ? FASTP2P_EINVAL : FASTP2P_OK;
}
/* Two cone NATs open their filters on the first packet either side sends, so the
 * first moments decide the outcome: send densely for half a second, then fall
 * back to a steady cadence that keeps the mapping alive for the rest of the
 * window. */
static uint64_t punch_interval(uint64_t elapsed) {
    return elapsed < 500 * MS ? 50 * MS : 200 * MS;
}
/* Rounds of direct punching worth spending before asking for a relay.  Two is
 * the historical budget; when either side maps a fresh port per destination with
 * no pattern, the second round cannot help, so only one is spent. */
static int direct_rounds_allowed(int hard_self, int hard_peer) {
    return hard_self || hard_peer ? 1 : 2;
}
/* Ports to hit when the peer's mapping shifts with every destination.  Returns
 * the first port of the window; the caller walks the span in one direction.
 * Zero span means the peer has no predictable mapping, or the window would run
 * off the end of the port range, so only its observed port is worth a packet. */
static uint16_t sym_window_span(uint16_t observed, int up, uint16_t count) {
    if (!count)
        return 0;
    /* Stop at the end of the range instead of wrapping onto unrelated ports. */
    uint32_t room = up ? 65535u - (uint32_t)observed
                       : (observed > 1 ? (uint32_t)observed - 1 : 0);
    return (uint16_t)(room < count ? room : count);
}
static uint16_t sym_window_base(uint16_t observed, int up, uint16_t count) {
    if (!sym_window_span(observed, up, count))
        return observed;
    /* Both directions start next to the observed mapping: the caller walks up or
     * down from here, so the window always covers the ports closest to it. */
    return (uint16_t)(up ? observed + 1 : observed - 1);
}
/* Cap the window so a peer cannot make us send an unbounded burst. */
static uint16_t sym_window_cap(uint16_t requested) {
    return requested > SYM_WINDOW_MAX ? SYM_WINDOW_MAX : requested;
}
/* Decide the mapping behaviour from observed mapped ports.  The first two come
 * from the same local socket talking to two different destinations, which is
 * what separates endpoint-independent mapping (cone) from per-destination
 * mapping (symmetric).  The third is the same probe from a second local port:
 * a small step in one direction means the next mapping can be predicted. */
static int nat_classify(uint16_t first, uint16_t second, uint16_t third) {
    if (first == second)
        return NAT_CONE;
    if (!third)
        return NAT_HARD_SYM;
    if (third == first)
        return NAT_CONE;
    if (third > first && third - first <= 100)
        return NAT_EASY_SYM_INC;
    if (first > third && first - third <= 100)
        return NAT_EASY_SYM_DEC;
    return NAT_HARD_SYM;
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
    if (t->relay_link >= 0)
        return 0; /* A middle hop never owns an application session. */
    if (t->relay_wait)
        return t->keyed && t->relay_ready;
    return t->keyed && t->key_acked &&
           (t->transport != FASTP2P_TRANSPORT_QUIC || t->cert_checked);
}
static int active_tunnel(fastp2p_client *c, const char *peer, int transport) {
    for (int i = 0; i < NT; ++i)
        if (tunnel_ready(&c->tunnels[i]) && c->tunnels[i].transport == transport &&
            !strcmp(c->tunnels[i].relay_wait ? c->tunnels[i].relay_peer : c->tunnels[i].peer, peer))
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
                int k = 0;
                while (k < a->relay_failed_count && strcmp(a->relay_failed[k].node, failed_relay))
                    ++k;
                if (k < 4) {
                    if (k == a->relay_failed_count)
                        ++a->relay_failed_count;
                    copy_string(a->relay_failed[k].node, sizeof(a->relay_failed[k].node), failed_relay);
                    a->relay_failed[k].until = mono() + 30 * NS;
                }
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
    for (int p = 0; p < OP_FAM_COUNT; ++p)
        t->probes[p].fd = -1;
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
                            const uint8_t *secret, const char *relay, int transport,
                            uint64_t tunnel_id) {
    char hex[FP_SESSION_SECRET * 2 + 1];
    json_object *j = json_object_new_object();
    secret_to_hex(secret, hex);
    /* "peer" names the sender so the receiver can validate the push against the
     * node it punched, and can address its acknowledgement back. */
    op_js(j, "peer", c->node);
    op_ju(j, "session", session);
    op_js(j, "secret", hex);
    op_js(j, "transport", transport == FASTP2P_TRANSPORT_TCP ? "tcp" : "quic");
    /* NAT ports can change and retries can reuse ports. Only the identifier
     * confirmed by the tunnel handshake identifies this connection. */
    op_ju(j, "tunnelID", tunnel_id);
    if (relay && *relay)
        op_js(j, "relay", relay);
    push(c, peer, PUSH_SESSION, j);
    json_object_put(j);
    OPENSSL_cleanse(hex, sizeof(hex));
}
static void push_session(fastp2p_client *c, tunnel *t, const char *relay) {
    push_session_to(c, t->peer, t->session, t->secret, relay, t->transport, t->id);
}
static void push_session_ack(fastp2p_client *c, const char *peer, uint64_t session,
                             uint64_t tunnel_id) {
    json_object *j = json_object_new_object();
    op_js(j, "peer", peer);
    op_ju(j, "session", session);
    op_ju(j, "tunnelID", tunnel_id);
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
            /* Zero is a valid descriptor: every probe slot must start closed or
             * the first probe would close whatever owns fd 0. */
            for (int p = 0; p < OP_FAM_COUNT; ++p)
                t->probes[p].fd = -1;
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
static int udp_packet(op_socket fd, const op_addr *peer, uint16_t main, uint16_t sub,
                      json_object *j) {
    op_buffer b = {0};
    const char *s = j ? json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN) : "null";
    int rv = op_frame_add(&b, main, sub, s, strlen(s));
    if (!rv)
        rv = op_sendto(fd, b.data, b.len, MSG_DONTWAIT, &peer->u.sa, peer->len) != (op_ssize)b.len;
    op_buffer_clear(&b);
    return rv ? -1 : 0;
}
/* 1 when the gateway itself can be probed over that family: it resolved an
 * address of it, and the probe port set is reachable there. Nothing in the
 * client opens a v6 probe against a v4-only gateway, so the old single-family
 * sequence is exactly what a v4 gateway still sees. */
static int gateway_has(const fastp2p_client *c, int index) {
    return c->gateway_families & family_bit(index) ? 1 : 0;
}
/* Close a probe socket without disturbing whichever socket the tunnel is
 * currently punching with (t->fd owns the active family's socket). */
static void probe_socket_close(tunnel *t) {
    for (int index = 0; index < OP_FAM_COUNT; ++index)
        if (t->probes[index].fd >= 0) {
            op_close(t->probes[index].fd);
            t->probes[index].fd = -1;
        }
}
static int probe_running(const tunnel *t) {
    for (int index = 0; index < OP_FAM_COUNT; ++index)
        if (t->probes[index].state && t->probes[index].state != PROBE_DONE)
            return 1;
    return 0;
}
/* 1 when the peer published a usable endpoint of `family` and we can answer it
 * in that family too — our side needs either a mapping observation or, for a
 * LAN punch, a local address of the same family. */
static int family_usable(const fastp2p_client *c, const tunnel *t, int family) {
    if (family < 0 || family >= OP_FAM_COUNT)
        return 0;
    if (!t->peer_ready[family] || !address_of_family(t->peer_text[family], family))
        return 0;
    if (t->lan)
        return address_of_family(c->local_ip[family], family);
    return t->mapped_ports[family] && address_of_family(t->mapped_text[family], family);
}
/* Which family to punch in (SPEC §5): a shared IPv6 is tried first because it
 * usually has no NAT in front of it at all, and IPv4 stays the compatibility
 * path an old peer can always answer. An old peer never publishes a v6
 * endpoint, so a mixed pair never leaves the v4 path here. */
static int choose_punch_family(const fastp2p_client *c, const tunnel *t) {
    if (family_usable(c, t, OP_FAM_V6))
        return OP_FAM_V6;
    if (family_usable(c, t, OP_FAM_V4))
        return OP_FAM_V4;
    return -1;
}
/* The family to fall back to if the chosen one does not connect. */
static int punch_fallback(const fastp2p_client *c, const tunnel *t, int family) {
    int other = family == OP_FAM_V6 ? OP_FAM_V4 : OP_FAM_V6;
    return family_usable(c, t, other) ? other : -1;
}
/* Point the tunnel at `family`: active endpoints, the remote tuple and the
 * socket to punch with. For QUIC the probe socket of that family becomes the
 * punch socket (one UDP socket keeps the mapping the peer was told about); the
 * other family's socket is handed to the fallback slot so a timeout can switch
 * without another round of negotiation. */
static int use_punch_family(fastp2p_client *c, int index, int family) {
    tunnel *t = &c->tunnels[index];
    if (!family_usable(c, t, family))
        return -1;
    op_addr peer;
    if (op_addr_from_text(&peer, t->peer_text[family], t->remote_ports[family]))
        return -1;
    int other = family == OP_FAM_V6 ? OP_FAM_V4 : OP_FAM_V6;
    t->family = family;
    t->fallback_family = punch_fallback(c, t, family);
    address_copy(t->ip, t->peer_text[family]);
    address_copy(t->mapped_ip, t->mapped_text[family]);
    t->remote_port = t->remote_ports[family];
    t->mapped_port = t->mapped_ports[family];
    op_addr_copy(&t->peer_addr, &peer);
    if (t->transport != FASTP2P_TRANSPORT_QUIC)
        return 0;
    if (t->probes[family].fd >= 0 && socket_family(t->probes[family].fd) == family) {
        if (t->fd >= 0 && t->fd != t->probes[family].fd)
            op_close(t->fd);
        t->fd = t->probes[family].fd;
        t->probes[family].fd = -1; /* t->fd owns the punch socket now */
    } else if (t->probes[family].fd >= 0) {
        /* A socket of the wrong family can never carry this punch; drop it so a
         * v6 socket is not mistaken for the v4 path (or vice versa). */
        op_close(t->probes[family].fd);
        t->probes[family].fd = -1;
    } else if (t->probes[other].fd >= 0 && t->fd == t->probes[other].fd) {
        /* Switching back after a v6 attempt: the v4 socket is still in the
         * other slot, untouched, so simply take it over. */
        t->fd = t->probes[other].fd;
        t->probes[other].fd = -1;
    }
    if (t->fd < 0) {
        t->fd = socket_bound(1, source_text(c, family), t->local_port, 1);
        if (t->fd < 0)
            return -1;
    }
    t->local_port = socket_port(t->fd);
    return 0;
}
/* Record one endpoint a peer published (SPEC §5). `text` is canonical, so a
 * v4-only peer only ever fills the v4 slot and every historical decision (the
 * active `ip`/`remote_port`, the punch target) sees the same values it did
 * before. A v6 endpoint is remembered alongside and only becomes active when
 * `use_punch_family` chooses it. */
static int tunnel_learn_peer(tunnel *t, const char *text, uint64_t port) {
    op_addr peer;
    if (!text || !*text || !port || port > 65535 ||
        op_addr_from_text(&peer, text, (uint16_t)port))
        return -1;
    int family = op_family_index(op_addr_family(&peer));
    if (family < 0)
        return -1;
    snprintf(t->peer_text[family], OP_ADDR_TEXT, "%s", text);
    t->remote_ports[family] = (uint16_t)port;
    t->peer_ready[family] = 1;
    if (!t->peer_addr.len) {
        op_addr_copy(&t->peer_addr, &peer);
        address_copy(t->ip, text);
        t->remote_port = (uint16_t)port;
        t->family = family;
    }
    return 0;
}
static int start_probe(fastp2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    for (int i = 0; i < OP_FAM_COUNT; ++i) {
        if (t->probes[i].fd >= 0 && t->probes[i].fd != t->fd)
            op_close(t->probes[i].fd);
        t->probes[i].state = PROBE_FREE;
        t->probes[i].fd = -1;
        t->probes[i].mapped_ip[0] = 0;
        t->probes[i].response_len = 0;
        t->mapped_ports[i] = 0;
        t->mapped_text[i][0] = 0;
    }
    if (t->lan) {
        if (t->fd >= 0)
            op_close(t->fd);
        /* Both peers have a private address for each other, so the gateway's
         * mapped address is not needed: exchange local ports and punch on the
         * LAN.  Going through the public address instead would need NAT
         * hairpin support, which is what made these links fail. The LAN socket
         * is opened in whichever family the two ends actually share, falling
         * back to IPv4 when only IPv4 is in common — the old behaviour. */
        int family = family_wanted(c, OP_FAM_V6) &&
                             address_of_family(c->local_ip[OP_FAM_V6], OP_FAM_V6) &&
                             t->peer_ready[OP_FAM_V6]
                         ? OP_FAM_V6
                         : OP_FAM_V4;
        t->fd = socket_bound(t->transport == FASTP2P_TRANSPORT_QUIC, c->local_ip[family], 0, 1);
        if (t->fd < 0)
            return -1;
        t->family = family;
        t->local_port = socket_port(t->fd);
        t->mapped_port = t->local_port;
        t->mapped_ports[family] = t->local_port;
        probe_complete(c, index);
        return 0;
    }
    if (t->fd >= 0) {
        op_close(t->fd);
        t->fd = -1;
    }
    t->deadline = mono() + 5 * NS;
    /* One probe set per family the gateway can actually be reached in. On an
     * IPv4-only gateway (or an IPv4-resolving hostname) this is a single v4
     * probe: the same socket, the same 2/0 to port 27180, byte-identical to the
     * old sequence. */
    int started = 0;
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        if (!family_wanted(c, family) || !gateway_has(c, family))
            continue;
        op_socket fd =
            socket_bound(t->transport == FASTP2P_TRANSPORT_QUIC, c->local_ip[family], 0, 1);
        if (fd < 0)
            continue;
        t->probes[family].fd = fd;
        t->probes[family].local_port = socket_port(fd);
        t->probes[family].response_len = 0;
        t->probes[family].last_rx = mono();
        t->probes[family].deadline = mono() + (family == OP_FAM_V4 ? 5 * NS : 2 * NS);
        op_addr peer = c->gateway_addr[family];
        op_addr_set_port(&peer, 27180);
        if (t->transport == FASTP2P_TRANSPORT_QUIC) {
            t->probes[family].state = PROBE_UDP;
            if (udp_packet(fd, &peer, 2, 0, NULL)) {
                op_close(fd);
                t->probes[family].fd = -1;
                t->probes[family].state = PROBE_FREE;
                continue;
            }
        } else {
            t->probes[family].state = PROBE_CONNECT;
            if (op_connect(fd, &peer.u.sa, peer.len) && errno != EINPROGRESS) {
                op_close(fd);
                t->probes[family].fd = -1;
                t->probes[family].state = PROBE_FREE;
                continue;
            }
        }
        ++started;
    }
    if (!started)
        return -1;
    t->state = T_PROBE;
    return 0;
}
/* One round of the per-family mapping probes a tunnel is waiting on. Returns 1
 * when the negotiation has been published, -1 when the tunnel was closed, 0
 * while still waiting.
 *
 * The IPv4 probe keeps the old exchange and the old five-second budget
 * untouched. The IPv6 probe runs the same exchange against the gateway's v6
 * address but on a shorter budget and as an **advisory** measurement: if v6 is
 * unreachable (a gateway that resolves AAAA but filters UDP v6), the tunnel
 * still goes out on the IPv4 answer at the same moment it would have in the old
 * build, so a broken v6 path can never make a previously working link slower
 * or fail. */
static int probe_round(fastp2p_client *c, int index, uint64_t now) {
    tunnel *t = &c->tunnels[index];
    int pending = 0, answered = 0;
    int required = primary_family(c);
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        nat_probe *p = &t->probes[family];
        if (p->state == PROBE_FREE)
            continue;
        if (p->state == PROBE_DONE) {
            ++answered;
            continue;
        }
        if (p->fd < 0) {
            p->state = PROBE_FREE;
            continue;
        }
        int expired = family == required ? now > t->deadline : now > p->deadline;
        if (expired) {
            if (family == required) {
                close_tunnel(c, index, "peer NAT mapping discovery timed out");
                return -1;
            }
            p->state = PROBE_FREE; /* advisory only: drop it and keep going */
            continue;
        }
        ++pending;
        if (p->state == PROBE_CONNECT) {
            int rv = connect_ready(p->fd);
            if (rv < 0) {
                if (family == required) {
                    close_tunnel(c, index, "TCP NAT connection failed");
                    return -1;
                }
                op_close(p->fd);
                p->fd = -1;
                p->state = PROBE_FREE;
                --pending;
                continue;
            }
            if (rv > 0) {
                const char marker = c->gateway_tcp_probe_v2 || c->gateway_tcp_probe_v3 ? '2' : '1';
                if (op_send(p->fd, &marker, 1, MSG_NOSIGNAL) != 1) {
                    if (family == required) {
                        close_tunnel(c, index, "TCP NAT marker failed");
                        return -1;
                    }
                    op_close(p->fd);
                    p->fd = -1;
                    p->state = PROBE_FREE;
                    --pending;
                    continue;
                }
                p->state = PROBE_READ;
                p->last_rx = now;
            }
            continue;
        }
        if (p->state == PROBE_READ) {
            op_ssize n = op_recv(p->fd, p->response + p->response_len,
                                 sizeof(p->response) - 1 - p->response_len, MSG_DONTWAIT);
            if (n > 0) {
                p->response_len += (size_t)n;
                p->response[p->response_len] = 0;
                p->last_rx = now;
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                if (family == required) {
                    close_tunnel(c, index, "TCP NAT response failed");
                    return -1;
                }
                op_close(p->fd);
                p->fd = -1;
                p->state = PROBE_FREE;
                --pending;
                continue;
            }
            /* A V3 gateway delimits the echo record with a newline, and the v6
             * form is bracketed ("[addr]:port"). A V2 gateway also delimits it;
             * only a legacy gateway needs the old quiet-period boundary, where
             * a split arrival must not be read as a complete shorter port. */
            int delimited = c->gateway_tcp_probe_v2 || c->gateway_tcp_probe_v3;
            if (p->response_len && (delimited || now - p->last_rx >= 20 * MS)) {
                op_addr mapped;
                size_t length = p->response_len;
                if (!delimited)
                    p->response[length++] = '\n';
                int parsed = fp_tcp_echo_response((uint8_t *)p->response, length, &mapped);
                if (parsed < 0) {
                    if (family == required) {
                        close_tunnel(c, index, "invalid TCP NAT response");
                        return -1;
                    }
                    op_close(p->fd);
                    p->fd = -1;
                    p->state = PROBE_FREE;
                    --pending;
                    continue;
                }
                if (parsed > 0 && op_family_index(op_addr_family(&mapped)) == family) {
                    op_addr_text(&mapped, p->mapped_ip, sizeof(p->mapped_ip));
                    p->mapped_port = op_addr_port(&mapped);
                    p->state = PROBE_DONE;
                    ++answered;
                    /* This probe finished inside this round: do not let it count
                     * as still pending, so a v4-only tunnel publishes on the
                     * same step the old code did. */
                    --pending;
                }
            }
            continue;
        }
        if (p->state == PROBE_UDP) {
            uint8_t data[1024];
            op_addr from;
            memset(&from, 0, sizeof(from));
            from.len = (op_socklen)sizeof(from.u.storage);
            op_ssize n = op_recvfrom(p->fd, data, sizeof(data), MSG_DONTWAIT, &from.u.sa, &from.len);
            if (n < 8)
                continue;
            op_addr expect = c->gateway_addr[family];
            op_addr_set_port(&expect, 27180);
            if (op_u16(data + 4) != 2 || op_u32(data) != (uint32_t)(n - 8) ||
                !op_address_equal(&from.u.sa, from.len, &expect.u.sa, expect.len))
                continue;
            json_object *j = op_json(data + 8, (size_t)n - 8);
            uint64_t port = op_integer(j, "port");
            const char *text = op_string(j, "IP");
            /* SPEC §2: the response field names are unchanged and now carry an
             * observed source of either family. Only accept an answer of the
             * family this probe socket speaks; a stray other-family reply must
             * not be mistaken for a mapping of the wrong interface. */
            if (port > 0 && port <= 65535 && address_of_family(text, family)) {
                snprintf(p->mapped_ip, sizeof(p->mapped_ip), "%s", text);
                p->mapped_port = (uint16_t)port;
                p->state = PROBE_DONE;
                ++answered;
                --pending;
            }
            if (j)
                json_object_put(j);
            continue;
        }
    }
    if (!answered || pending)
        return 0;
    /* Adopt the answers, then choose which family this tunnel will punch in
     * before publishing, so the negotiation carries one consistent pair. */
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        if (t->probes[family].state != PROBE_DONE)
            continue;
        t->mapped_ports[family] = t->probes[family].mapped_port;
        address_copy(t->mapped_text[family], t->probes[family].mapped_ip);
    }
    int adopt = primary_family(c);
    if (!t->probes[adopt].mapped_port) {
        int other = adopt == OP_FAM_V4 ? OP_FAM_V6 : OP_FAM_V4;
        if (t->probes[other].mapped_port)
            adopt = other;
    }
    t->family = adopt;
    t->local_port = t->probes[adopt].local_port;
    t->mapped_port = t->probes[adopt].mapped_port;
    address_copy(t->mapped_ip, t->probes[adopt].mapped_ip);
    probe_complete(c, index);
    return 1;
}
static void probe_complete(fastp2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    /* Listen on the port this client is about to advertise. The TCP punch used to
     * create the listener lazily, only after a dial failed, so for a short window
     * the published endpoint - exactly what a LAN peer dials - had nothing behind
     * it, and the two ends ended up chasing different ports. */
    if (t->transport == FASTP2P_TRANSPORT_TCP && tcp_punch_listen(c, index))
        return;
    json_object *j = json_object_new_object();
    op_js(j, "from", c->node);
    /* On a LAN punch the peers exchange private addresses and local ports; the
     * gateway-observed address is only meaningful when a NAT is in between.
     * fromIP/coneNatPort stay strictly the IPv4 observation (SPEC §5): an old
     * peer reads only these two and must see exactly what the old build
     * published. fromIP6/coneNatPort6 are new fields an old peer ignores, and
     * they are only sent when this client actually measured an IPv6 mapping. */
    op_js(j, "fromIP", t->lan ? c->local_ip[OP_FAM_V4]
                              : t->mapped_text[OP_FAM_V4][0] ? t->mapped_text[OP_FAM_V4]
                                                             : c->ip[OP_FAM_V4]);
    op_js(j, "version", WIRE_VERSION);
    op_ju(j, "natType", local_transport_nat(c, t->transport));
    op_ju(j, "udpNatType", (uint64_t)c->nat[OP_FAM_V4].type);
    op_ju(j, "tcpNatType", c->tcp_nat.family[OP_FAM_V4].type);
    if (t->tcp_v2) op_ju(j, "tcpPunchV2", 1);
    /* Each family publishes independently: only the pair that was actually
     * measured is written, so a v6 LAN port can never ride in the v4 fields an
     * old peer reads (SPEC §5). */
    op_ju(j, "coneNatPort", t->mapped_ports[OP_FAM_V4]);
    if (t->mapped_ports[OP_FAM_V6]) {
        op_js(j, "fromIP6",
              t->lan ? c->local_ip[OP_FAM_V6] : t->mapped_text[OP_FAM_V6]);
        op_ju(j, "coneNatPort6", t->mapped_ports[OP_FAM_V6]);
    }
    /* A LAN punch must hand the peer the port this client actually listens on:
     * coneNatPort is the NAT mapping, which is a different port and is not open on
     * the private address. New fields only, so a peer that does not understand
     * them keeps using the public pair it already knows. */
    if (t->lan) {
        op_js(j, "fromIPLan", c->local_ip[OP_FAM_V4]);
        op_ju(j, "lanPort", t->local_port);
        char note[128];
        snprintf(note, sizeof(note), "LAN punch advertising %s:%u (mapped port %u)",
                 c->local_ip[OP_FAM_V4], (unsigned)t->local_port,
                 (unsigned)t->mapped_ports[OP_FAM_V4]);
        emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, note);
    }
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
        int family = t->family >= 0 ? t->family : OP_FAM_V4;
        /* Our mapping moves with every destination we contact, so tell the peer
         * where the next one is likely to land and let it spray that window. */
        if (t->transport == FASTP2P_TRANSPORT_QUIC &&
            (c->nat[family].type == NAT_EASY_SYM_INC || c->nat[family].type == NAT_EASY_SYM_DEC)) {
            op_ju(j, "symBase", t->mapped_port);
            op_ju(j, "symCount", SYM_WINDOW_MAX);
            op_ju(j, "symUp", c->nat[family].type == NAT_EASY_SYM_INC ? 1 : 0);
        }
        push(c, t->peer, 2, j);
        t->at = mono() + 3 * NS;
        t->state = T_TIME;
        t->deadline = t->at + 10 * NS;
        if (!strcmp(t->mode, "tcp4") || !strcmp(t->mode, "intranet") || !strcmp(t->mode, "udp4"))
            t->at = mono();
    }
    json_object_put(j);
    if (t->transport == FASTP2P_TRANSPORT_TCP) {
        /* The TCP probe connections are finished: a TCP punch re-binds the
         * source port it observed, so they are closed here, LAN included. */
        probe_socket_close(t);
        if (t->fd >= 0) {
            op_close(t->fd);
            t->fd = -1;
        }
        if (!strcmp(t->mode, "tcppunch") && !t->tcp_v2) {
            t->listen_fd = socket_bound(0, c->local_ip[t->family >= 0 ? t->family : OP_FAM_V4],
                                        t->local_port, 1);
            if (t->listen_fd < 0 || op_listen(t->listen_fd, 4))
                close_tunnel(c, index, "TCP punch listener failed");
        }
    }
}
static int tcp_punch_listen(fastp2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    if (t->listen_fd >= 0) return 0;
    t->listen_fd = socket_bound(0, c->local_ip[t->family >= 0 ? t->family : OP_FAM_V4],
                                t->local_port, 1);
    if (t->listen_fd < 0 || op_listen(t->listen_fd, 4)) {
        close_tunnel(c, index, "TCP punch fallback listener failed");
        return -1;
    }
    emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, "TCP punch fallback listening on the mapped source port");
    return 0;
}
static void tcp_punch_failed(fastp2p_client *c, int index, uint64_t now) {
    tunnel *t = &c->tunnels[index];
    {
        char note[128];
        int saved = errno;
        snprintf(note, sizeof(note), "TCP punch attempt %u failed: %s (listener %s)",
                 t->tcp_attempts, saved ? strerror(saved) : "unknown",
                 t->listen_fd >= 0 ? "up" : "down");
        emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, note);
    }
    if (t->fd >= 0) op_close(t->fd);
    t->fd = -1;
    unsigned limit = t->initiator ? 1 : 5;
    if (t->tcp_attempts >= limit) {
        t->tcp_retry_at = 0;
        (void)tcp_punch_listen(c, index);
    } else t->tcp_retry_at = now + (50 + random_id() % 151) * MS;
}
static void tcp_punch_dial(fastp2p_client *c, int index, uint64_t now) {
    tunnel *t = &c->tunnels[index];
    if (!t->peer_addr.len) {
        close_tunnel(c, index, "invalid TCP punch peer address");
        return;
    }
    ++t->tcp_attempts;
    t->tcp_retry_at = 0;
    t->tcp_attempt_deadline = now + 3 * NS;
    t->fd = socket_bound(0, c->local_ip[t->family >= 0 ? t->family : OP_FAM_V4], t->local_port, 1);
    /* Name the address actually dialled: the old wording claimed "the mapped
     * source port" even on a LAN punch, which made a failed direct attempt
     * impossible to tell apart from a NAT problem. */
    char target[OP_ADDR_TEXT] = "?", local[OP_ADDR_TEXT] = "?";
    op_addr shown = t->peer_addr; /* a copy: the tunnel's own address must not change */
    op_addr_text(&shown, target, sizeof(target));
    int family_index = t->family >= 0 ? t->family : OP_FAM_V4;
    if (c->local_ip[family_index])
        snprintf(local, sizeof(local), "%s", c->local_ip[family_index]);
    char message[192];
    snprintf(message, sizeof(message), "TCP punch connect attempt %u to %s from %s:%u%s",
             t->tcp_attempts, target, local, (unsigned)t->local_port, t->lan ? " (LAN)" : "");
    emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, message);
    if (t->fd < 0 || (op_connect(t->fd, &t->peer_addr.u.sa, t->peer_addr.len) && errno != EINPROGRESS)) {
        /* Record why the dial did not even start: refused, unreachable and a full
         * queue look identical in the retry log otherwise. */
        char note[128];
        int saved = errno;
        snprintf(note, sizeof(note), "TCP punch dial to %s failed: %s", target,
                 saved ? strerror(saved) : "socket unavailable");
        emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, note);
        tcp_punch_failed(c, index, now);
    }
}
static void start_underlay(fastp2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    if (!t->peer_addr.len) {
        close_tunnel(c, index, "invalid peer address");
        return;
    }
    t->deadline = mono() + 10 * NS;
    if (t->tcp_v2) {
        /* Both dial first. The initiator then listens while its peer keeps
         * retrying. Protocol client/server and session ownership never change
         * merely because the successful socket was accepted instead of dialed. */
        uint64_t now = mono();
        t->deadline = now + 15 * NS;
        t->state = T_TCP_CONNECT;
        tcp_punch_dial(c, index, now);
        return;
    }
    if (t->transport == FASTP2P_TRANSPORT_QUIC) {
        if (!t->server && !t->notified) {
            t->state = T_UNDERLAY;
            return;
        }
        t->quic = opq_new(t->fd, &t->peer_addr.u.sa, t->peer_addr.len, t->server);
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
    if (!strcmp(t->mode, "tcppunch") && tcp_punch_listen(c, index)) return;
    t->fd = socket_bound(0, c->local_ip[t->family >= 0 ? t->family : OP_FAM_V4],
                         !strcmp(t->mode, "tcppunch") ? t->local_port : 0, 1);
    if (t->fd < 0 ||
        (op_connect(t->fd, &t->peer_addr.u.sa, t->peer_addr.len) && errno != EINPROGRESS)) {
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
    if (!tunnel_ready(t))
        return;
    int relayed = t->relay_wait;
    const char *peer = relayed ? t->relay_peer : t->peer;
    for (int i = 0; i < NA; ++i) {
        app *a = &c->apps[i];
        if (a->used && a->local && !strcmp(a->peer, peer) && a->transport == t->transport) {
            if (a->synced && a->tunnel_index >= 0 && tunnel_ready(&c->tunnels[a->tunnel_index]))
                continue; /* Keep existing overlays on their authenticated session. */
            a->tunnel_index = index;
            a->synced = 1;
            a->link_deadline = 0;
            a->ready_at = mono() + 100 * MS;
            a->relay_requested = 0;
            /* attempts is deliberately not reset here: a tunnel that completes
             * the key exchange and then dies must not restart the direct-punch
             * ladder, or a pair that cannot punch never reaches the relay. */
            emit(c, FASTP2P_EVENT_FORWARD, c->apps[i].id, 0,
                 relayed ? "forward attached to relay" : "forward attached to tunnel");
        }
    }
}
static void bind_pending_key(fastp2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    if (t->keyed || t->session_owner)
        return;
    pending_key *best = NULL;
    for (int i = 0; i < NPK; ++i) {
        pending_key *k = &c->keys[i];
        if (!k->used || k->peer_id != t->peer_id || k->transport != t->transport ||
            k->relay[0] || k->tunnel_id != t->id || k->deadline <= mono())
            continue;
        best = k;
        break;
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
    t->keyed = t->key_acked = 1;
    OPENSSL_cleanse(k->secret, sizeof(k->secret));
    memset(k, 0, sizeof(*k));
    push_session_ack(c, t->peer, t->session, t->id);
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
    /* A retry must not reset AEAD counters under a previously used key. */
    a->session = t->session;
    memcpy(a->secret, t->secret, FP_SESSION_SECRET);
    a->has_session = 1;
    a->tunnel_index = ti;
    a->link_deadline = 0; /* Underlay states have their own deadlines. */
    a->synced = 0;
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
    t->tcp_v2 = t->transport == FASTP2P_TRANSPORT_TCP;
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
                            const uint8_t *secret, const char *relay, int transport,
                            uint64_t tunnel_id) {
    int direct = -1;
    if (!relay || !*relay) {
        direct = tunnel_id ? tunnel_by_id(c, tunnel_id) : -1;
        if (direct < 0)
            return; /* An expired attempt must not replace a live session. */
        tunnel *t = &c->tunnels[direct];
        if (t->peer_id != peer_id || t->transport != transport || t->session_owner ||
            t->relay_wait || t->relay_link >= 0)
            return;
        if (t->keyed) {
            if (t->session == session && fp_equal(t->secret, secret, FP_SESSION_SECRET))
                push_session_ack(c, peer, session, tunnel_id);
            return; /* Duplicate delivery must not reset sequence numbers. */
        }
    } else {
        for (int i = 0; i < NT; ++i) {
            tunnel *t = &c->tunnels[i];
            if (t->state && t->relay_wait && !t->session_owner && t->session == session &&
                t->transport == transport && !strcmp(t->peer, relay) &&
                !strcmp(t->relay_peer, peer)) {
                if (t->relay_ready && fp_equal(t->secret, secret, FP_SESSION_SECRET))
                    push_session_ack(c, peer, session, 0);
                return;
            }
        }
    }
    int slot = -1;
    for (int i = 0; i < NPK; ++i)
        if (c->keys[i].used && c->keys[i].tunnel_id == tunnel_id &&
            c->keys[i].transport == transport && c->keys[i].peer_id == peer_id &&
            !strcmp(c->keys[i].relay, relay ? relay : "")) {
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
    if (k->used && (k->session != session || !fp_equal(k->secret, secret, FP_SESSION_SECRET)))
        return; /* One immutable key per connection, including before HELLO. */
    memset(k, 0, sizeof(*k));
    k->used = 1;
    k->session = session;
    k->peer_id = peer_id;
    k->transport = transport;
    k->tunnel_id = tunnel_id;
    k->deadline = mono() + 30 * NS;
    memcpy(k->secret, secret, FP_SESSION_SECRET);
    if (relay && *relay) {
        if (!valid_node(relay)) {
            memset(k, 0, sizeof(*k));
            return;
        }
        copy_string(k->relay, sizeof(k->relay), relay);
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
        OPENSSL_cleanse(k->secret, sizeof(k->secret));
        memset(k, 0, sizeof(*k));
        return;
    }
    if (c->tunnels[direct].state == T_ACTIVE)
        bind_pending_key(c, direct);
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
            push_session_to(c, t->relay_peer, t->session, t->secret, t->peer, t->transport,
                            0);
        return;
    }
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used && c->apps[i].local && c->apps[i].tunnel_index == index) {
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
    op_addr local;
    memset(&local, 0, sizeof(local));
    if (o->fd >= 0)
        op_addr_socketname(o->fd, &local);
    if (!local.len)
        op_addr_from_text(&local, "0.0.0.0", 0); /* the old all-zero answer */
    char ip[OP_ADDR_TEXT], remote[OP_ADDR_TEXT];
    if (op_addr_text(&local, ip, sizeof(ip)))
        snprintf(ip, sizeof(ip), "%s", "0.0.0.0");
    if (op_addr_text(&o->source, remote, sizeof(remote)))
        snprintf(remote, sizeof(remote), "%s", "0.0.0.0");
    json_object *j = json_object_new_object();
    op_ju(j, "id", o->id);
    op_ju(j, "reply", status);
    op_js(j, "boundIP", ip);
    op_ju(j, "boundPort", op_addr_port(&local));
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
    op_addr address;
    /* The local SOCKS5 entry answers with a 4-byte IPv4 endpoint (socks.c is
     * still v4-only), so an exit that reports a v6 binding cannot be relayed to
     * this listener and fails the same way a malformed answer did. */
    if (!op_get(ack, "reply") || status > 8 || port > 65535 ||
        op_addr_from_text(&address, op_string(ack, "boundIP"), (uint16_t)port) ||
        op_addr_family(&address) != AF_INET) {
        socks_failure(c, oi, 1);
        return;
    }
    if (status) {
        socks_failure(c, oi, (unsigned)status);
        return;
    }
    o->waiting = 0;
    if (o->socks_state == S_FLOW) {
        op_addr remote;
        if (op_addr_from_text(&remote, op_string(ack, "remoteIP"), 0) ||
            op_addr_family(&remote) != AF_INET)
            close_overlay(c, oi, 1);
        else
            op_addr_copy(&o->socks_peer, &remote);
        return;
    }
    uint8_t reply[10];
    op_socks_reply(reply, 0, (const uint8_t *)&address.u.in.sin_addr, (uint16_t)port);
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
    if (!parent || o->waiting || len > 4096 || !parent->socks_peer.len ||
        op_addr_family(&o->socks_peer) != AF_INET)
        return;
    uint8_t packet[4106] = {0, 0, 0, 1};
    memcpy(packet + 4, &o->socks_peer.u.in.sin_addr, 4);
    packet[8] = (uint8_t)(o->socks.port >> 8);
    packet[9] = (uint8_t)o->socks.port;
    memcpy(packet + 10, data, len);
    op_sendto(parent->socks_udp, packet, len + 10, MSG_DONTWAIT, &parent->socks_peer.u.sa,
              parent->socks_peer.len);
}
static void tick_socks_udp(fastp2p_client *c, int index) {
    overlay *parent = &c->overlays[index];
    app *a = &c->apps[parent->app_index];
    for (int k = 0; k < 8; ++k) {
        uint8_t packet[4360];
        op_addr from;
        memset(&from, 0, sizeof(from));
        from.len = (op_socklen)sizeof(from.u.storage);
        op_ssize n = op_recvfrom(parent->socks_udp, packet, sizeof(packet), MSG_DONTWAIT,
                                 &from.u.sa, &from.len);
        if (n < 0)
            break;
        op_addr_normalize(&from);
        if (!op_addr_equal(&from, &parent->source) ||
            (op_addr_port(&parent->socks_peer) &&
             op_addr_port(&from) != op_addr_port(&parent->socks_peer)) ||
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
            op_addr requested;
            /* The old check accepted INADDR_ANY and otherwise required the
             * request to name this client's own source address. The local
             * SOCKS5 entry is still IPv4-only (socks.c), so anything else is
             * the same protocol error as before. */
            if (op_addr_from_text(&requested, o->socks.host, 0) ||
                op_addr_family(&requested) != AF_INET ||
                (!op_addr_equal(&requested, &o->source) &&
                 strcmp(o->socks.host, "0.0.0.0"))) {
                socks_failure(c, i, 2);
                break;
            }
            op_addr local;
            memset(&local, 0, sizeof(local));
            if (op_addr_socketname(o->fd, &local) || op_addr_family(&local) != AF_INET) {
                socks_failure(c, i, 1);
                break;
            }
            char ip[OP_ADDR_TEXT];
            if (op_addr_text(&local, ip, sizeof(ip))) {
                socks_failure(c, i, 1);
                break;
            }
            o->socks_udp = socket_bound(1, ip, 0, 0);
            if (o->socks_udp < 0) {
                socks_failure(c, i, 1);
                break;
            }
            op_addr_copy(&o->socks_peer, &o->source);
            op_addr_set_port(&o->socks_peer, o->socks.port);
            op_socks_reply(reply, 0, (const uint8_t *)&local.u.in.sin_addr,
                           socket_port(o->socks_udp));
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
        if (a->relay_node[0])
            op_js(j, "relayNode", a->relay_node);
        op_ju(j, "isActive", a->tunnel_index >= 0 && c->tunnels[a->tunnel_index].state == T_ACTIVE);
        op_js(j, "linkMode", a->transport == FASTP2P_TRANSPORT_QUIC ? "udppunch" : "ipv4");
        json_object_array_add(list, j);
    }
    json_object_object_add(root, "Apps", list);
    ws_json(c, 6, 3, root);
    json_object_put(root);
}
static int rule_protocol(fastp2p_client *c, int index, const char *protocol) {
    app *a = &c->apps[index];
    if (!strcmp(protocol, "socks5"))
        return a->socks;
    if (!strcmp(protocol, "udp"))
        return a->udp && !a->socks;
    return !a->udp && !a->socks;
}
static void remove_rule(fastp2p_client *c, int index) {
    app *a = &c->apps[index];
    for (int i = 0; i < NO; ++i)
        if (c->overlays[i].used && c->overlays[i].app_index == index)
            close_overlay(c, i, 0);
    if (a->tunnel_index >= 0)
        close_tunnel(c, a->tunnel_index, "rule removed");
    if (a->fd >= 0)
        op_close(a->fd);
    memset(a, 0, sizeof(*a));
    a->fd = -1;
    a->tunnel_index = -1;
}
static void apply_rule(fastp2p_client *c, json_object *j) {
    uint64_t src = op_integer(j, "srcPort"), dst = op_integer(j, "dstPort");
    int transport_tcp = (op_integer(j, "punchPriority") & 2) != 0;
    const char *protocol = op_string(j, "protocol");
    /* Re-applying a rule (edit, re-enable, or a fresh RULE_SYNC) replaces the
     * one with the same identity rather than being rejected as a duplicate. */
    if (src && src <= 65535 && *protocol)
        for (int i = 0; i < NA; ++i)
            if (c->apps[i].used && c->apps[i].local && c->apps[i].port == src &&
                rule_protocol(c, i, protocol)) {
                remove_rule(c, i);
                break;
            }
    if (src && src <= 65535 && !strcmp(protocol, "socks5")) {
            /* A SOCKS5 exit has no fixed destination: the target is chosen by each
             * client request and resolved at the peer. The console still picks the
             * local entry port, so honour it here instead of requiring dstPort. */
            const char *user = op_string(j, "Username"), *password = op_string(j, "Password");
            const char *bind = op_string(j, "whitelist");
            fastp2p_socks5 proxy = {.struct_size = sizeof(proxy),
                                   .name = op_string(j, "appName"),
                                   .bind_ip = *bind ? bind : "127.0.0.1",
                                   .local_port = (uint16_t)src,
                                   .peer_node = op_string(j, "peerNode"),
                                   .transport = transport_tcp ? FASTP2P_TRANSPORT_TCP
                                                              : FASTP2P_TRANSPORT_QUIC,
                                   .username = *user ? user : NULL,
                                   .password = *password ? password : NULL};
            if (!*user != !*password) {
                emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EINVAL,
                     "SOCKS5 needs both a username and a password, or neither");
            } else {
                uint64_t id = 0;
                int rv = fastp2p_client_add_socks5(c, &proxy, &id);
                if (rv)
                    emit(c, FASTP2P_EVENT_ERROR, 0, rv, "could not add SOCKS5 forwarding rule");
                else {
                    /* add_socks5 predates named relays, so apply the console's
                     * choice to the app it just created rather than widening the
                     * public ABI. */
                    const char *relay = op_string(j, "relayNode");
                    /* Accept both spellings: the console sends NoRelay, while a rule
                     * stored without a descriptor keeps the key as written by hand. */
                    int no_relay = op_integer(j, "NoRelay") != 0 || op_integer(j, "noRelay") != 0;
                    for (int i = 0; i < NA; ++i)
                        if (c->apps[i].used && c->apps[i].id == id) {
                            if (*relay && valid_node(relay))
                                copy_string(c->apps[i].relay_node,
                                            sizeof(c->apps[i].relay_node), relay);
                            c->apps[i].no_relay = no_relay;
                            break;
                        }
                }
            }
        } else if (src && src <= 65535 && dst && dst <= 65535) {
            fastp2p_forward f = {.struct_size = sizeof(f),
                              .name = op_string(j, "appName"),
                              .local_port = (uint16_t)src,
                              .peer_node = op_string(j, "peerNode"),
                              .destination_host = op_string(j, "dstHost"),
                              .destination_port = (uint16_t)dst,
                              .protocol = op_string(j, "protocol"),
                              .transport = transport_tcp ? FASTP2P_TRANSPORT_TCP
                                                          : FASTP2P_TRANSPORT_QUIC,
                              .relay_node = op_string(j, "relayNode")};
            int rv = fastp2p_client_add_forward(c, &f, NULL);
            if (rv)
                emit(c, FASTP2P_EVENT_ERROR, 0, rv, "could not add gateway forwarding rule");
        }
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
            c->gateway_tcp_probe_v2 = op_integer(j, "tcpProbeV2") == 1;
            /* SPEC §3: only a V3 gateway brackets an IPv6 echo record; without
             * it this client keeps the legacy v4-only echo parsing. */
            c->gateway_tcp_probe_v3 = op_integer(j, "tcpProbeV3") == 1;
            /* A working login means the earlier failures were transient; without
             * this the backoff would stay at its maximum for the rest of the run. */
            c->reconnect_attempt = 0;
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
        uint64_t port6 = op_integer(j, "coneNatPort6");
        const char *peer_text = op_string(j, "fromIP");
        const char *peer_text6 = op_string(j, "fromIP6");
        op_addr peer_ip;
        /* SPEC §5: the two families are independent fields. Accept the request
         * when *either* measured endpoint is usable, so a v6-only peer (which
         * has nothing valid for the v4 fields an old peer reads) is no longer
         * rejected by the IPv4-only check. */
        int v4_ok = port > 0 && port <= 65535 &&
                    !op_addr_from_text(&peer_ip, peer_text, (uint16_t)port) &&
                    op_family_index(op_addr_family(&peer_ip)) == OP_FAM_V4;
        int v6_ok = port6 > 0 && port6 <= 65535 &&
                    !op_addr_from_text(&peer_ip, peer_text6, (uint16_t)port6) &&
                    op_family_index(op_addr_family(&peer_ip)) == OP_FAM_V6;
        int udp = !strcmp(mode, "udppunch") || !strcmp(mode, "udp4");
        if (valid_node(from) && sender == op_node_id(from) && id && tunnel_by_id(c, id) < 0 &&
            (v4_ok || v6_ok) &&
            (!strcmp(mode, "tcppunch") || !strcmp(mode, "tcp4") || !strcmp(mode, "intranet") ||
             udp)) {
            /* A peer may open a relay hop while our direct session with it is
             * carrying traffic. Handshake IDs isolate the two connections. */
            int ti = new_tunnel(c, from, id, udp ? FASTP2P_TRANSPORT_QUIC : FASTP2P_TRANSPORT_TCP, 0);
            if (ti >= 0) {
                tunnel *t = &c->tunnels[ti];
                strcpy(t->mode, mode);
                t->tcp_v2 = !strcmp(mode, "tcppunch") && op_integer(j, "tcpPunchV2") == 1;
                if (v4_ok)
                    tunnel_learn_peer(t, peer_text, port);
                if (v6_ok)
                    tunnel_learn_peer(t, peer_text6, port6);
                t->server = op_integer(j, "isServer") != 0;
                t->lan = op_integer(j, "lan") != 0;
                if (t->lan) {
                    /* The peer's private endpoint: its listening port, not the NAT
                     * mapping it published for the public path. */
                    const char *lan_text = op_string(j, "fromIPLan");
                    uint64_t lan_port = op_integer(j, "lanPort");
                    op_addr lan_address;
                    if (lan_text && *lan_text && lan_port > 0 && lan_port <= 65535 &&
                        !op_addr_from_text(&lan_address, lan_text, (uint16_t)lan_port) &&
                        op_family_index(op_addr_family(&lan_address)) == OP_FAM_V4)
                        tunnel_learn_peer(t, lan_text, (uint16_t)lan_port);
                    char note[128];
                    snprintf(note, sizeof(note), "LAN punch target %s:%llu",
                             lan_text, (unsigned long long)lan_port);
                    emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, note);
                }
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
            uint64_t port6 = op_integer(j, "coneNatPort6");
            const char *peer_text = op_string(j, "fromIP");
            const char *peer_text6 = op_string(j, "fromIP6");
            op_addr ip;
            int v4_ok = port > 0 && port <= 65535 &&
                        !op_addr_from_text(&ip, peer_text, (uint16_t)port) &&
                        op_family_index(op_addr_family(&ip)) == OP_FAM_V4;
            int v6_ok = port6 > 0 && port6 <= 65535 &&
                        !op_addr_from_text(&ip, peer_text6, (uint16_t)port6) &&
                        op_family_index(op_addr_family(&ip)) == OP_FAM_V6;
            if (t->state == T_REPLY && sender == t->peer_id &&
                !strcmp(t->peer, op_string(j, "from")) && !op_integer(j, "error") &&
                (v4_ok || v6_ok)) {
                if (v4_ok)
                    tunnel_learn_peer(t, peer_text, port);
                if (v6_ok)
                    tunnel_learn_peer(t, peer_text6, port6);
                t->tcp_v2 = t->tcp_v2 && op_integer(j, "tcpPunchV2") == 1;
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
                /* A symmetric peer's port shifts per destination; remember the
                 * window it advertised so the punch can cover it. */
                uint64_t base = op_integer(j, "symBase"), count = op_integer(j, "symCount");
                if (base > 0 && base <= 65535) {
                    t->sym_base = (uint16_t)base;
                    t->sym_count = sym_window_cap((uint16_t)count);
                    t->sym_up = op_integer(j, "symUp") ? 1 : 0;
                }
            } else if (t->state == T_REPLY)
                close_tunnel(c, ti, "peer rejected connection or sent an invalid response");
        }
    } else if (main == 3 && sub == PUSH_SESSION) {
        uint64_t session = op_integer(j, "session");
        const char *peer = op_string(j, "peer"), *relay = op_string(j, "relay");
        const char *transport = op_string(j, "transport");
        uint8_t secret[FP_SESSION_SECRET];
        int ok = session && valid_node(peer) && sender == op_node_id(peer) &&
                 (!strcmp(transport, "tcp") || !strcmp(transport, "quic")) &&
                 !secret_from_hex(op_string(j, "secret"), secret);
        if (ok) {
            int quic = !transport || strcmp(transport, "tcp");
            session_receive(c, sender, peer, session, secret,
                            relay && *relay ? relay : NULL,
                            quic ? FASTP2P_TRANSPORT_QUIC : FASTP2P_TRANSPORT_TCP,
                            op_integer(j, "tunnelID"));
        } else {
            emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EINVAL, "invalid session key");
        }
        OPENSSL_cleanse(secret, sizeof(secret));
    } else if (main == 3 && sub == PUSH_SESSION_ACK) {
        uint64_t session = op_integer(j, "session");
        uint64_t tunnel_id = op_integer(j, "tunnelID");
        for (int i = 0; i < NT; ++i) {
            tunnel *t = &c->tunnels[i];
            if (t->state != T_ACTIVE || !t->session_owner || t->session != session)
                continue;
            uint64_t peer =
                t->relay_wait || t->relay_ready ? op_node_id(t->relay_peer) : t->peer_id;
            if (peer != sender || (!(t->relay_wait || t->relay_ready) &&
                                   (!tunnel_id || t->id != tunnel_id)))
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
        /* SPEC §4: the gateway's 7/1 answer carries the family bitmap and the
         * parallel v6 levels. It has no separate v6 LAN column; `IPv6` is the
         * address observed for the peer, so it is used as the v6 LAN endpoint
         * only when it is a private (ULA) address. A global v6 is a public
         * mapping and is handled by the normal v6 punch path instead. */
        const char *lan6 = op_string(j, "lanIP6");
        if (!lan6 || !*lan6) {
            const char *observed = op_string(j, "IPv6");
            op_addr check;
            if (observed && *observed && !op_addr_from_text(&check, observed, 0) &&
                op_family_index(op_addr_family(&check)) == OP_FAM_V6 &&
                op_addr_private(&check))
                lan6 = observed;
        }
        if (valid_node(peer))
            for (int i = 0; i < NA; ++i)
                if (c->apps[i].used && !strcmp(c->apps[i].peer, peer)) {
                    c->apps[i].peer_nat = op_integer(j, "natType");
                    uint64_t tcp = op_integer(j, "tcpNatType");
                    c->apps[i].peer_tcp_nat = tcp == FP_NAT_STABLE || tcp == FP_NAT_DEPENDENT ? tcp : FP_NAT_UNKNOWN;
                    uint64_t tcp6 = op_integer(j, "tcpNatType6");
                    c->apps[i].peer_tcp_nat6 = tcp6 == FP_NAT_STABLE || tcp6 == FP_NAT_DEPENDENT
                                                  ? tcp6
                                                  : FP_NAT_UNKNOWN;
                    c->apps[i].peer_nat6 = op_integer(j, "udpNatType6");
                    c->apps[i].peer_families = op_integer(j, "families");
                    if (lan && inet_pton(AF_INET, lan, &lan_address) == 1)
                        copy_string(c->apps[i].peer_lan, sizeof(c->apps[i].peer_lan), lan);
                    if (lan6 && *lan6) {
                        op_addr parsed;
                        if (!op_addr_from_text(&parsed, lan6, 0) &&
                            op_family_index(op_addr_family(&parsed)) == OP_FAM_V6)
                            copy_string(c->apps[i].peer_lan6, sizeof(c->apps[i].peer_lan6),
                                        lan6);
                    }
                    /* The peer's private address only arrives with this answer, long
                     * after the rule was created and possibly after a WAN punch or a
                     * relay link was already chosen. A LAN link is cheaper and does not
                     * depend on the relay, so drop a link that is still not ready and
                     * let the app loop re-decide with the LAN path available. A link
                     * that already carries traffic is left alone. */
                    /* Only after a direct attempt has actually failed: switching
                     * earlier preempts the punch that would have succeeded, and in a
                     * two-node topology there is no relay to fall back to. */
                    if (c->apps[i].peer_lan[0] && !c->apps[i].lan_tried &&
                        c->apps[i].attempts >= 1 && lan_punch_possible(c, &c->apps[i])) {
                        int index = c->apps[i].tunnel_index;
                        if (index >= 0 && c->tunnels[index].state &&
                            !c->tunnels[index].lan && !tunnel_ready(&c->tunnels[index]))
                            close_tunnel(c, index, "peer LAN address reachable; trying a direct LAN punch");
                        c->apps[i].tunnel_index = -1;
                        /* The LAN branch needs an unspent round budget; it is taken at
                         * most once because lan_tried is set when the punch starts. */
                        c->apps[i].attempts = 0;
                        c->apps[i].retry = mono();
                    }
                }
    } else if (main == 3 && sub == 7)
        report_apps(c);
    else if (main == 3 && sub == 16) {
        /* RULE_SYNC: the gateway is the source of truth. Drop every local rule
         * first, then rebuild exactly the enabled set it persisted. */
        json_object *rules = op_get(j, "Rules");
        for (int i = 0; i < NA; ++i)
            if (c->apps[i].used && c->apps[i].local)
                remove_rule(c, i);
        if (rules && json_object_is_type(rules, json_type_array))
            for (size_t k = 0; k < json_object_array_length(rules); ++k) {
                json_object *rule = json_object_array_get_idx(rules, k);
                if (json_object_is_type(rule, json_type_object))
                    apply_rule(c, rule);
            }
    } else if (main == 3 && sub == 17) {
        /* RULE_REMOVE: a rule was disabled, deleted, or had its key changed. */
        const char *protocol = op_string(j, "protocol");
        uint64_t port = op_integer(j, "srcPort");
        for (int i = 0; i < NA; ++i)
            if (c->apps[i].used && c->apps[i].local && c->apps[i].port == port &&
                rule_protocol(c, i, protocol)) {
                remove_rule(c, i);
                break;
            }
    } else if (main == 3 && sub == 19) {
        json_object *fields=op_get(j,"fields");uint64_t revision=op_integer(j,"revision");
        int result=FASTP2P_EINVAL;
        if(c->login_ok && c->report_ok && revision && json_object_is_type(fields,json_type_object) && c->config_handler) {
            c->in_callback=1;
            result=c->config_handler(json_object_to_json_string_ext(fields,JSON_C_TO_STRING_PLAIN),revision,c->config_user);
            c->in_callback=0;
        }
        json_object *ack=json_object_new_object();
        json_object_object_add(ack,"revision",json_object_new_uint64(revision));
        json_object_object_add(ack,"error",json_object_new_int(result<0));
        json_object_object_add(ack,"state",json_object_new_string(result<0?"failed":result?"saved":"applied"));
        ws_json(c,6,8,ack);json_object_put(ack);
        if(result<0)emit(c,FASTP2P_EVENT_ERROR,revision,result,"gateway configuration rejected or could not be saved");
    } else if (main == 3 && sub == 18) {
        /* UPDATE: the operator asked for this node to be upgraded. Download,
         * verify, then hand over to the new build. */
        const char *url = op_string(j, "url"), *sha = op_string(j, "sha256");
        const char *version = op_string(j, "version");
        uint64_t size = op_integer(j, "size");
        if (!*url || strlen(sha) != 64) {
            emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EINVAL, "invalid upgrade order");
        } else {
            char staged[4200], error[256], message[192];
            snprintf(staged, sizeof(staged), "%s", "");
            snprintf(message, sizeof(message), "downloading build %s", *version ? version : "update");
            emit(c, FASTP2P_EVENT_STATE, 0, 0, message);
            if (fp_update_stage_path(staged, sizeof(staged))) {
                emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, "cannot locate the install directory");
            } else if (fp_update_download(url, c->ca, staged, sha, size, error, sizeof(error))) {
                emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, error);
#ifdef __ANDROID__
            } else {
                /* Android cannot replace its own package: hand the verified APK
                 * to the app, which asks the user to confirm the install. */
                char ready[4300];
                snprintf(ready, sizeof(ready), "update-ready:%s", staged);
                emit(c, FASTP2P_EVENT_STATE, 0, 0, ready);
            }
#else
            } else if (fp_update_apply(staged, error, sizeof(error))) {
                remove(staged);
                emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, error);
            } else {
                emit(c, FASTP2P_EVENT_STATE, 0, 0, "installing the new build");
                /* Ask for a normal stop: the run loop then reports a clean exit,
                 * so a Windows service manager does not treat it as a failure and
                 * race the updater by restarting the old image. */
                c->stopping = 1;
            }
#endif
        }
    } else if (main == 3 && sub == 9) {
        apply_rule(c, j);
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
        } else if (!t->server && sub == TUN_HELLO_ACK && len == 8 && op_u64(data) == t->id)
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
        if (!t->relay_wait || t->relay_link >= 0 || len != 8 || op_u64(data) != t->session) {
            close_tunnel(c, ti, "invalid relay ready");
            return;
        }
        t->relay_ready = 1;
        if (!t->session_owner)
            push_session_ack(c, t->relay_peer, t->session, 0);
        session_ready(c, ti);
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
        session_ready(c, ti);
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
                                             &o->source.u.sa, o->source.len)
                                 : op_send(o->fd, payload, length, MSG_DONTWAIT | MSG_NOSIGNAL);
                if (sent != (op_ssize)length)
                    close_overlay(c, i, 1);
            } else if (o->peer_eof || op_buffer_add(&o->tx, payload, length, OP_QUEUE_LIMIT)) {
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
                if (!o->udp && op_integer(j, "writeEOF") == 1) {
                    /* EOF is directional. Deliver all earlier DATA before
                     * shutdown(SHUT_WR), while continuing to forward replies. */
                    o->peer_eof = 1;
                    o->activity = mono();
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
            op_addr peer;
            int oi = overlay_slot(c);
            if (oi >= 0) {
                overlay *o = &c->overlays[oi];
                o->id = id;
                o->app_index = -1;
                o->tunnel_index = ti;
                o->udp = !strcmp(proto, "udp");
                o->socks_exit = op_integer(j, "socks5") == 1;
                /* SPEC §8: a v6/domain destination resolves through the same
                 * helper as everything else and the exit socket binds the
                 * destination's own family. v4 keeps the historical any-address
                 * bind. */
                if (resolve_any(host, (uint16_t)port, &peer)) {
                    overlay_ack(c, oi, 4);
                    close_overlay(c, oi, 0);
                    json_object_put(j);
                    return;
                }
                o->source = peer;
                int family = op_family_index(op_addr_family(&peer));
                if ((o->fd = socket_bound(o->udp, family == OP_FAM_V6 ? "::" : NULL, 0, 0)) < 0 ||
                    (op_connect(o->fd, &peer.u.sa, peer.len) && errno != EINPROGRESS)) {
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
    op_addr peer;
    memset(&peer, 0, sizeof(peer));
    peer.len = (op_socklen)sizeof(peer.u.storage);
    op_socket fd = op_accept(t->listen_fd, &peer.u.sa, &peer.len);
    if (fd < 0)
        return;
    op_addr_normalize(&peer);
    op_addr expected;
    if (op_addr_from_text(&expected, t->ip, 0) || !op_addr_equal(&peer, &expected) ||
        op_addr_port(&peer) != t->remote_port) {
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
    if (t->state == T_PROBE) {
        if (!probe_running(t)) {
            close_tunnel(c, ti, "NAT probe could not start");
            return;
        }
        if (probe_round(c, ti, now) < 0)
            return;
        if (!t->state)
            return;
    }
    if (t->state == T_TIME && now >= t->at) {
        /* Pick the family and point the tunnel at that exact tuple. A direct
         * request (tcp4/intranet/udp4) has no mapping observation to choose
         * from; it keeps the historical text target learned from the peer. */
        int family = choose_punch_family(c, t);
        if (family < 0)
            family = t->family;
        if (family >= 0 && family < OP_FAM_COUNT && use_punch_family(c, ti, family) == 0) {
            /* Ready: peer_addr, mapping and (for QUIC) the punch socket agree. */
        } else if (!t->peer_addr.len &&
                   op_addr_from_text(&t->peer_addr, t->ip, t->remote_port)) {
            close_tunnel(c, ti, "invalid peer address");
            return;
        }
        if (t->transport == FASTP2P_TRANSPORT_QUIC && !strcmp(t->mode, "udppunch")) {
            int f = t->family >= 0 && t->family < OP_FAM_COUNT ? t->family : OP_FAM_V4;
            if (t->fd < 0 && t->probes[f].fd >= 0) {
                t->fd = t->probes[f].fd;
                t->probes[f].fd = -1;
            }
            if (t->fd < 0)
                t->fd = socket_bound(1, c->local_ip[f], t->local_port, 1);
            if (t->fd < 0 || !t->peer_addr.len) {
                close_tunnel(c, ti, "UDP punch socket unavailable");
                return;
            }
            t->state = T_PUNCH;
            t->punch_next = 0;
            t->punch_started = now;
        } else
            start_underlay(c, ti);
    }
    if (t->state == T_PUNCH) {
        op_addr peer = t->peer_addr;
        op_addr_set_port(&peer, t->remote_port);
        json_object *j = json_object_new_object();
        op_ju(j, "id", t->id);
        if (now >= t->punch_next) {
            udp_packet(t->fd, &peer, 4, 0, j);
            /* A symmetric peer maps a fresh port per destination, so the port it
             * reported is only the start of a window. Spray the rest of it once,
             * early, when the peer's filters are most likely to still be open. */
            if (t->sym_count && !t->sym_sprayed) {
                t->sym_sprayed = 1;
                uint16_t start = sym_window_base(t->sym_base, t->sym_up, t->sym_count);
                uint16_t span = sym_window_span(t->sym_base, t->sym_up, t->sym_count);
                for (uint16_t k = 0; k < span; ++k) {
                    op_addr candidate = peer;
                    uint16_t port = t->sym_up ? (uint16_t)(start + k) : (uint16_t)(start - k);
                    if (!port)
                        continue;
                    op_addr_set_port(&candidate, port);
                    udp_packet(t->fd, &candidate, 4, 0, j);
                }
            }
            t->punch_next = now + punch_interval(now - t->punch_started);
        }
        for (int k = 0; k < 8 && t->state == T_PUNCH; ++k) {
            uint8_t data[1024];
            op_addr from;
            memset(&from, 0, sizeof(from));
            from.len = (op_socklen)sizeof(from.u.storage);
            op_ssize n =
                op_recvfrom(t->fd, data, sizeof(data), MSG_DONTWAIT, &from.u.sa, &from.len);
            if (n < 0)
                break;
            op_addr_normalize(&from);
            if (n < 8 || op_u32(data) != (uint32_t)(n - 8) || op_u16(data + 4) != 4 ||
                op_u16(data + 6) > 1 || !op_addr_equal(&from, &peer))
                continue;
            json_object *r = op_json(data + 8, (size_t)n - 8);
            uint64_t id = op_integer(r, "id");
            if (r)
                json_object_put(r);
            if (id != t->id)
                continue;
            t->remote_port = op_addr_port(&from);
            op_addr_copy(&peer, &from);
            udp_packet(t->fd, &peer, 4, 1, j);
            if (op_u16(data + 6) == 1)
                start_underlay(c, ti);
        }
        json_object_put(j);
    }
    if (t->state == T_UNDERLAY && t->notified)
        start_underlay(c, ti);
    if (t->state == T_TCP_CONNECT) {
        if (t->state && t->tcp_v2 && t->fd < 0 && t->tcp_retry_at && now >= t->tcp_retry_at)
            tcp_punch_dial(c, ti, now);
        if (!t->state) return;
        /* Completion first, deadline second: a connect that finishes as the window
         * closes must count as success. */
        int rv = t->fd >= 0 ? connect_ready(t->fd) : 0;
        if (rv == 0 && t->tcp_v2 && t->fd >= 0 && now >= t->tcp_attempt_deadline) {
            errno = ETIMEDOUT;
            tcp_punch_failed(c, ti, now);
            if (!t->state) return;
        }
        if (rv < 0) {
            if (t->tcp_v2) {
                tcp_punch_failed(c, ti, now);
                if (!t->state) return;
            } else if (t->listen_fd < 0) {
                close_tunnel(c, ti, "TCP simultaneous connection failed");
                return;
            } else {
                op_close(t->fd);
                t->fd = -1;
            }
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
        if (t->state == T_ACTIVE && !t->cert_sent && t->keyed &&
            (t->key_acked || !t->session_owner) &&
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
            if (t->listen_fd < 0 || t->tcp_v2) {
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
        op_socket fd = -1;
        op_addr peer;
        memset(&peer, 0, sizeof(peer));
        /* A v4-only run opens only listener[0], so this loop is the old single
         * accept in that case; a v6 listener is simply never created. */
        for (int family = 0; family < OP_FAM_COUNT && fd < 0; ++family) {
            if (c->listener[family] < 0)
                continue;
            peer.len = (op_socklen)sizeof(peer.u.storage);
            fd = op_accept(c->listener[family], &peer.u.sa, &peer.len);
        }
        if (fd < 0)
            break;
        op_addr_normalize(&peer);
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
                op_addr expected;
                if (t->state == T_DIRECT && t->server && !op_addr_from_text(&expected, t->ip, 0) &&
                    op_addr_equal(&expected, &p->peer)) {
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
            ((o->read_eof || o->peer_eof) && now >= o->activity && now - o->activity > 300 * NS) ||
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
        if (o->peer_eof && !op_buffer_size(&o->tx) && !o->write_shutdown) {
            if (op_shutdown_write(o->fd)) { close_overlay(c, i, 1); continue; }
            o->write_shutdown = 1;
        }
        if (o->read_eof) {
            if (o->write_shutdown) close_overlay(c, i, 0);
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
                o->read_eof = 1;
                o->activity = now;
                json_object *eof = json_object_new_object();
                op_ju(eof, "id", o->id); op_ju(eof, "writeEOF", 1);
                int failed = tjson_sealed(c, t, TUN_CLOSE, eof);
                json_object_put(eof);
                if (failed) close_overlay(c, i, 1);
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
        if (a->relay_requested && a->link_deadline && now > a->link_deadline) {
            a->relay_requested = 0;
            a->link_deadline = 0;
            a->retry = now;
        }
        if (a->socks) {
            for (int k = 0; k < 4; ++k) {
                op_addr from;
                memset(&from, 0, sizeof(from));
                from.len = (op_socklen)sizeof(from.u.storage);
                op_socket fd = op_accept(a->fd, &from.u.sa, &from.len);
                if (fd < 0)
                    break;
                op_addr_normalize(&from);
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
                session_ready(c, ti);
            } else if (a->relay_requested) {
                /* Waiting for the gateway to name a relay node. */
            } else {
                int in_progress = 0;
                for (int k = 0; k < NA; ++k)
                    if (k != i && c->apps[k].used && c->apps[k].local &&
                        c->apps[k].relay_requested && c->apps[k].transport == a->transport &&
                        !strcmp(c->apps[k].peer, a->peer))
                        in_progress = 1;
                for (int k = 0; k < NT; ++k)
                    if (c->tunnels[k].state && c->tunnels[k].relay_link < 0 &&
                        c->tunnels[k].transport == a->transport &&
                        (!strcmp(c->tunnels[k].peer, a->peer) ||
                         (c->tunnels[k].relay_wait && !strcmp(c->tunnels[k].relay_peer, a->peer))))
                        in_progress = 1;
                if (!in_progress) {
                    /* Two failed punches, symmetric NAT on both sides, or an
                     * explicit diagnostic request means a direct path is not
                     * reachable: ask the gateway for a relay.  A reachable LAN
                     * address is tried first, because it needs no NAT support
                     * at all and stays direct. */
                    /* One side maps a different port per destination with no
                     * pattern, so no amount of sending or spraying finds it.
                     * Skip the punch ladder entirely: the first round is worth
                     * trying for the LAN case, then go straight to the relay. */
                    int rounds = direct_rounds_allowed(
                        nat_is_hard_sym(local_transport_nat(c, a->transport)),
                        nat_is_hard_sym(peer_transport_nat(a)));
                    if (lan_punch_possible(c, a) && !a->lan_tried && a->attempts < rounds && !c->force_relay) {
                        ++a->attempts;
                        ti = app_tunnel(c, a, a->peer, a->transport);
                        if (ti >= 0) {
                            c->tunnels[ti].lan = 1;
                            a->lan_tried = 1;
                            start_punch(c, ti);
                        }
                    } else if (a->relay_node[0] || a->attempts >= 2 || c->force_relay ||
                        (nat_is_hard_sym(local_transport_nat(c, a->transport)) &&
                         nat_is_hard_sym(peer_transport_nat(a)))) {
                        /* Direct attempts may already have sealed certificate
                         * frames. Never restart counters with that same key. */
                        a->session = random_id();
                        fp_random(a->secret, sizeof(a->secret));
                        a->has_session = 1;
                        a->link_deadline = now + 20 * NS;
                        if (a->relay_node[0]) {
                            /* The rule named its relay, so skip the offer and
                             * punch that node directly. */
                            int relay_index = relay_tunnel(c, a, a->relay_node, a->peer, 1);
                            if (relay_index >= 0)
                                start_punch(c, relay_index);
                        } else {
                            a->relay_requested = 1;
                            emit(c, FASTP2P_EVENT_TUNNEL, 0, 0,
                                 "relay requested from the gateway after a failed direct attempt");
                            json_object *j = json_object_new_object();
                            op_js(j, "peerNode", a->peer);
                            op_js(j, "underlayProtocol", a->transport == FASTP2P_TRANSPORT_TCP ? "tcp" : "quic");
                            for (int k = 0; k < a->relay_failed_count;) {
                                if (now >= a->relay_failed[k].until)
                                    a->relay_failed[k] = a->relay_failed[--a->relay_failed_count];
                                else
                                    ++k;
                            }
                            if (a->relay_failed_count) {
                                json_object *skip = json_object_new_array();
                                for (int k = 0; k < a->relay_failed_count; ++k)
                                    json_object_array_add(skip, json_object_new_string(a->relay_failed[k].node));
                                json_object_object_add(j, "exclude", skip);
                            }
                            if (a->no_relay) {
                                /* The operator disabled the relay for this rule, so do
                                 * not ask for one: the session stays direct or fails
                                 * with a clear reason instead of landing on a relay the
                                 * operator does not want (for example one behind the
                                 * same NAT, which cannot hairpin). */
                                emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO,
                                     "relay disabled for this rule; staying direct");
                                a->relay_requested = 0;
                            } else {
                                ws_json(c, 5, 0, j);
                                json_object_put(j);
                            }
                        }
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
        if (a->tunnel_index < 0 || !a->synced ||
            !tunnel_ready(&c->tunnels[a->tunnel_index]) || now < a->ready_at)
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
                op_addr from;
                memset(&from, 0, sizeof(from));
                from.len = (op_socklen)sizeof(from.u.storage);
                op_ssize n = op_recvfrom(a->fd, data, sizeof(data), MSG_DONTWAIT, &from.u.sa,
                                         &from.len);
                if (n < 0)
                    break;
                op_addr_normalize(&from);
                if (n > 4096) {
                    emit(c, FASTP2P_EVENT_ERROR, a->id, FASTP2P_ELIMIT,
                         "UDP application datagram exceeds 4096 bytes");
                    continue;
                }
                int oi = -1;
                for (int q = 0; q < NO; ++q)
                    if (c->overlays[q].used && c->overlays[q].local_udp &&
                        c->overlays[q].app_index == i &&
                        op_addr_equal(&c->overlays[q].source, &from) &&
                        op_addr_port(&c->overlays[q].source) == op_addr_port(&from)) {
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
/* SPEC §1/§4: the family bitmap and the parallel v6 levels ride on both the
 * registration frame (6/0) and the refresh frame (6/9). IPv4 fields keep their
 * historical names and values; a v4-only run reports families=1 and the v6
 * slots stay at their sentinel values, exactly as an old client read them. */
static void report_families(const fastp2p_client *c, json_object *j) {
    op_ju(j, "families", (uint64_t)c->families_wanted);
    op_ju(j, "hasIPv6", family_wanted(c, OP_FAM_V6) ? 1 : 0);
    if (family_wanted(c, OP_FAM_V6) && address_of_family(c->ip[OP_FAM_V6], OP_FAM_V6))
        op_js(j, "IPv6", c->ip[OP_FAM_V6]);
    op_ju(j, "udpNatType6", (uint64_t)c->nat[OP_FAM_V6].type);
    op_ju(j, "tcpNatType6", c->tcp_nat.family[OP_FAM_V6].type);
    op_ju(j, "tcpNatSamples6", c->tcp_nat.family[OP_FAM_V6].samples);
    op_ju(j, "tcpNatDestinationIPs6", c->tcp_nat.family[OP_FAM_V6].destinations);
}
static void report_client(fastp2p_client *c) {
    json_object *j = json_object_new_object();
    op_js(j, "os", FASTP2P_PLATFORM_OS);
    op_js(j, "hostname", c->hostname);
    op_js(j, "version", WIRE_VERSION);
    op_js(j, "lanIP", c->local_ip[OP_FAM_V4]);
    op_ju(j, "publicIPPort", c->public_port);
    op_ju(j, "configPush", c->config_handler != NULL);
    op_ju(j, "udpNatType", (uint64_t)c->nat[OP_FAM_V4].type);
    op_ju(j, "tcpNatType", c->tcp_nat.family[OP_FAM_V4].type);
    op_ju(j, "tcpNatSamples", c->tcp_nat.family[OP_FAM_V4].samples);
    op_ju(j, "tcpNatDestinationIPs", c->tcp_nat.family[OP_FAM_V4].destinations);
    op_ju(j, "natLevel", (uint64_t)nat_level(c));
    op_ju(j, "tcpNatLevel", (uint64_t)tcp_nat_level(c));
    report_families(c, j);
    ws_json(c, 6, 0, j);
    json_object_put(j);
}
static void report_nat(fastp2p_client *c) {
    json_object *j = json_object_new_object();
    op_ju(j, "udpNatType", (uint64_t)c->nat[OP_FAM_V4].type);
    op_ju(j, "tcpNatType", c->tcp_nat.family[OP_FAM_V4].type);
    op_ju(j, "tcpNatSamples", c->tcp_nat.family[OP_FAM_V4].samples);
    op_ju(j, "tcpNatDestinationIPs", c->tcp_nat.family[OP_FAM_V4].destinations);
    op_ju(j, "natLevel", (uint64_t)nat_level(c));
    op_ju(j, "tcpNatLevel", (uint64_t)tcp_nat_level(c));
    report_families(c, j);
    /* NAT refresh must not replay gateway rules or managed configuration. */
    ws_json(c, 6, 9, j); /* 6/8 is reserved for managed configuration ACKs. */
    json_object_put(j);
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
    c->gateway_tcp_probe_v2 = 0;
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
/* Same failure, but carrying the library's own reason. The generic message above
 * cannot distinguish an unreachable host from an unreadable CA or a hostname
 * mismatch, which is exactly what a reported failure usually needs. */
static void gateway_failed_curl(fastp2p_client *c, CURLcode rv) {
    char message[448];
    if (c->curl_error[0])
        snprintf(message, sizeof(message), "WSS connection failed: %s (curl %d): %s",
                 curl_easy_strerror(rv), (int)rv, c->curl_error);
    else
        snprintf(message, sizeof(message), "WSS connection failed: %s (curl %d)",
                 curl_easy_strerror(rv), (int)rv);
    emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, message);
    close_gateway(c);
}
static void connect_gateway(fastp2p_client *c) {
    c->ws = curl_easy_init();
    if (!c->ws) {
        gateway_failed(c);
        return;
    }
    /* The reachable set can change between attempts (a service that started
     * before IPv6 came up, a family that lost its route), and the login query
     * is what tells the gateway which families this node speaks. */
    refresh_families(c);
    /* SPEC §7: a v6 literal host must be bracketed in the URL authority, while
     * a plain name or v4 literal is unchanged. */
    char urlhost[300];
    int literal6 = strchr(c->host, ':') != NULL;
    if (literal6)
        snprintf(urlhost, sizeof(urlhost), "[%s]", c->host);
    else
        snprintf(urlhost, sizeof(urlhost), "%s", c->host);
    snprintf(c->path, sizeof(c->path),
             "wss://%s:%u/api/v1/login?node=%s&token=%" PRIu64
             "&protocol=" WIRE_PROTOCOL
             "&version=%s&nattype=%d&tcpnattype=%u&families=%d&sharebandwidth=0",
             urlhost, c->port, c->node, c->token, WIRE_VERSION, c->nat[OP_FAM_V4].type,
             c->tcp_nat.family[OP_FAM_V4].type, c->families_wanted);
    if (c->automatic_node) {
        char hostname[32];
        node_base(hostname, c->hostname);
        size_t used = strlen(c->path);
        snprintf(c->path + used, sizeof(c->path) - used, "&autonode=1&deviceid=%s&hostname=%s",
                 c->device_id, hostname);
    }
    /* One pinned answer per *usable* family, v4 first so the preferred family
     * keeps the historical order (SPEC §7). A family this host cannot route to
     * is deliberately left out: pinning it would let curl start the connection
     * on an address that will never answer and burn the whole connect timeout
     * before it falls back, which is exactly what happens on a host that
     * resolves AAAA but has no working IPv6 uplink. */
    c->resolve = NULL;
    char hostpart[300];
    if (literal6)
        snprintf(hostpart, sizeof(hostpart), "[%s]", c->host);
    else
        snprintf(hostpart, sizeof(hostpart), "%s", c->host);
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        if (!c->gateway_addr[family].len || !family_wanted(c, family))
            continue;
        char text[OP_ADDR_TEXT], resolve[400];
        if (op_addr_text(&c->gateway_addr[family], text, sizeof(text)))
            continue;
        if (family == OP_FAM_V4)
            snprintf(resolve, sizeof(resolve), "%s:%u:%s", hostpart, c->port, text);
        else
            snprintf(resolve, sizeof(resolve), "%s:%u:[%s]", hostpart, c->port, text);
        struct curl_slist *next = curl_slist_append(c->resolve, resolve);
        if (!next) {
            curl_slist_free_all(c->resolve);
            c->resolve = NULL;
            gateway_failed(c);
            return;
        }
        c->resolve = next;
    }
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
    c->curl_error[0] = 0;
    SETOPT(CURLOPT_ERRORBUFFER, c->curl_error);
    SETOPT(CURLOPT_URL, c->path);
    SETOPT(CURLOPT_RESOLVE, c->resolve);
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
        if (message->data.result != CURLE_OK) {
            gateway_failed_curl(c, message->data.result);
            return;
        }
        if (curl_easy_getinfo(c->ws, CURLINFO_ACTIVESOCKET, &c->ws_socket) != CURLE_OK ||
            c->ws_socket == CURL_SOCKET_BAD) {
            gateway_failed(c);
            return;
        }
        c->ws_connected = 1;
        c->last_rx = mono();
        char *ip = NULL;
        if (curl_easy_getinfo(c->ws, CURLINFO_LOCAL_IP, &ip) == CURLE_OK && ip) {
            op_addr local;
            if (!op_addr_from_text(&local, ip, 0)) {
                op_addr_copy(&c->control_local, &local);
                int index = op_family_index(op_addr_family(&local));
                if (index >= 0)
                    address_text_out(c->local_ip[index], ip, index);
            }
        }
        report_client(c);
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
            gateway_failed_curl(c, rv);
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
        if (rv != CURLE_OK) {
            gateway_failed_curl(c, rv);
            return;
        }
        if (!meta || (meta->flags & CURLWS_CLOSE)) {
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
/* Close whatever sockets one family's discovery still owns. The classification
 * already lives in `type`, so nothing else has to survive the close. */
static void nat_discovery_close(nat_discovery *n) {
    if (n->fd >= 0)
        op_close(n->fd);
    n->fd = -1;
    if (n->fd2 >= 0)
        op_close(n->fd2);
    n->fd2 = -1;
}
/* One request/reply step of a family's UDP NAT discovery. This is the old
 * single-family sequence, unchanged: 2/0 to 27180, 2/0 to 27181, then a second
 * local port to 27180. Running it once per family keeps every IPv4 number and
 * timeout exactly what it was. */
static void tick_nat_family(fastp2p_client *c, int family, uint64_t now) {
    nat_discovery *n = &c->nat[family];
    if (n->fd < 0)
        return;
    uint8_t data[1024];
    op_addr from, expect;
    memset(&from, 0, sizeof(from));
    from.len = (op_socklen)sizeof(from.u.storage);
    /* Phase 3 reads from the second socket; phases 1 and 2 share the first. */
    op_socket fd = n->phase == 3 && n->fd2 >= 0 ? n->fd2 : n->fd;
    op_ssize received =
        op_recvfrom(fd, data, sizeof(data), MSG_DONTWAIT, &from.u.sa, &from.len);
    uint16_t expected = n->phase == 3 ? 27180 : (uint16_t)(27179 + n->phase);
    expect = c->gateway_addr[family];
    op_addr_set_port(&expect, expected);
    int finish = 0;
    if (received >= 8 && op_address_equal(&from.u.sa, from.len, &expect.u.sa, expect.len) &&
        op_u16(data + 4) == 2 && op_u32(data) == (uint32_t)(received - 8)) {
        json_object *j = op_json(data + 8, (size_t)received - 8);
        uint64_t port = op_integer(j, "port");
        const char *text = op_string(j, "IP");
        if (port > 0 && port <= 65535 && address_of_family(text, family)) {
            /* Index 0 is exactly what the old `ip` field held. */
            snprintf(c->ip[family], OP_ADDR_TEXT, "%s", text);
            if (n->phase == 1) {
                n->port = (uint16_t)port;
                n->phase = 2;
                n->deadline = now + 2 * NS;
                op_addr peer = c->gateway_addr[family];
                op_addr_set_port(&peer, 27181);
                udp_packet(n->fd, &peer, 2, 0, NULL);
            } else if (n->phase == 2) {
                n->second = (uint16_t)port;
                if (n->port == port) {
                    /* Same mapping for a different destination: the NAT keeps
                     * the port, so a punch from any address reaches us. */
                    n->type = NAT_CONE;
                    finish = 1;
                } else {
                    /* Different mapping: symmetric.  Probe from a second local
                     * port to see whether the next mapping is predictable. */
                    n->fd2 = socket_bound(1, family == OP_FAM_V4 ? NULL : "::", 0, 0);
                    if (n->fd2 < 0) {
                        n->type = NAT_HARD_SYM;
                        finish = 1;
                    } else {
                        n->phase = 3;
                        n->deadline = now + 2 * NS;
                        op_addr peer = c->gateway_addr[family];
                        op_addr_set_port(&peer, 27180);
                        udp_packet(n->fd2, &peer, 2, 0, NULL);
                    }
                }
            } else {
                n->port2 = (uint16_t)port;
                n->type = nat_classify(n->port, n->second, n->port2);
                finish = 1;
            }
        }
        if (j)
            json_object_put(j);
    }
    if (now > n->deadline) {
        /* Retry once from a fresh socket before declaring the mapping unknown:
         * a probe lost while the gateway is busy with a burst of reconnections
         * says nothing about the NAT. */
        if (n->retries < 2) {
            ++n->retries;
            nat_discovery_close(n);
            n->phase = 1;
            n->fd = socket_bound(1, family == OP_FAM_V4 ? NULL : "::", 0, 0);
            if (n->fd >= 0) {
                n->deadline = now + 2 * NS;
                op_addr peer = c->gateway_addr[family];
                op_addr_set_port(&peer, 27180);
                udp_packet(n->fd, &peer, 2, 0, NULL);
                return;
            }
        }
        n->type = NAT_UNKNOWN;
        finish = 1;
        /* One diagnostic per run, exactly as the old single-family discovery
         * produced, even when v6 was the only family probed. */
        if (family == OP_FAM_V4 || !(c->gateway_families & FAM_V4))
            emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO,
                 "UDP NAT discovery unavailable; TCP transport can still be attempted");
    }
    if (!finish)
        return;
    if (family == OP_FAM_V4 && c->nat_override)
        n->type = c->nat_override;
    nat_discovery_close(n);
}
/* --- Public STUN probe ---------------------------------------------------
 * One socket carries every request, so all servers observe the same mapping;
 * that is what makes the cone/symmetric comparison meaningful. Per server we
 * send a plain request first (it yields the mapping and proves reachability),
 * then the same request with CHANGE-REQUEST asking for another port, then for
 * another address. A reply that arrives from a *different* source than the one
 * we addressed is the evidence the NAT's filter let a stranger through. */
/* Built-in probe servers: every node measures its NAT the same way without any
 * per-machine configuration. Both are still overridable, and `[]` / "" disables
 * the corresponding probe for an operator who does not want it to leave the host. */
#define FP_DEFAULT_STUN_SERVERS "stun.fastp2p.top:3478"
/* TCP filtering needs a callback probe server; same host, dedicated port. */
#define FP_DEFAULT_TCP_NAT_PROBE "stun.fastp2p.top:3479"

int fp_client_tcp_level_config(fastp2p_client *c, json_object *probe) {
    if (!c)
        return FASTP2P_OK;
    if (probe) {
        if (!json_object_is_type(probe, json_type_string))
            return FASTP2P_EINVAL;
        const char *text = json_object_get_string(probe);
        if (!*text) /* an empty string is an explicit opt-out */
            return fp_tcp_level_configure(&c->tcp_level, NULL) < 0 ? FASTP2P_EINVAL
                                                                  : FASTP2P_OK;
        return fp_tcp_level_configure(&c->tcp_level, text) < 0 ? FASTP2P_EINVAL : FASTP2P_OK;
    }
    /* No key: fall back to the built-in probe server so a node measures its TCP
     * filtering without any per-machine configuration. Resolution happens when the
     * probe starts, so a host without DNS to that name simply skips it. */
    if (fp_tcp_level_configure(&c->tcp_level, FP_DEFAULT_TCP_NAT_PROBE) < 0)
        fp_tcp_level_configure(&c->tcp_level, NULL);
    return FASTP2P_OK;
}/* Parses one "host:port" entry into slot `count`. Returns 0 on success. */
static int stun_entry(fastp2p_client *c, const char *text, int count) {
    size_t length = strlen(text);
    if (!length || length >= sizeof(c->stun_host[0]))
        return -1;
    uint64_t port = 3478;
    size_t host_length = length;
    /* "host:port"; a bracketed or bare v6 literal keeps its colons. */
    const char *colon = strrchr(text, ':');
    if (colon && !strchr(text, '[') && strchr(text, ':') == colon) {
        uint64_t parsed = 0;
        if (!*++colon)
            return -1;
        for (const char *p = colon; *p; ++p) {
            if (*p < '0' || *p > '9')
                return -1;
            parsed = parsed * 10 + (uint64_t)(*p - '0');
            if (parsed > 65535)
                return -1;
        }
        if (!parsed)
            return -1;
        port = parsed;
        host_length = (size_t)(colon - 1 - text);
    }
    if (!host_length || host_length >= sizeof(c->stun_host[0]))
        return -1;
    memcpy(c->stun_host[count], text, host_length);
    c->stun_host[count][host_length] = 0;
    /* A bracketed v6 literal is written [addr] on the wire of the config. */
    if (c->stun_host[count][0] == '[') {
        size_t inner = strlen(c->stun_host[count]);
        if (inner < 3 || c->stun_host[count][inner - 1] != ']')
            return -1;
        memmove(c->stun_host[count], c->stun_host[count] + 1, inner - 2);
        c->stun_host[count][inner - 2] = 0;
    }
    c->stun_port[count] = (uint16_t)port;
    return 0;
}int fp_client_stun_config(fastp2p_client *c, json_object *servers) {
    if (!c)
        return FASTP2P_OK;
    /* No key at all falls back to the built-in server, so a node measures its NAT
     * without any per-machine configuration. An empty array is an explicit opt-out
     * for operators who do not want the client to contact anything. */
    if (!servers) {
        if (stun_entry(c, FP_DEFAULT_STUN_SERVERS, 0))
            return FASTP2P_EINVAL;
        c->stun_count = 1;
        return FASTP2P_OK;
    }
    if (!json_object_is_type(servers, json_type_array) ||
        json_object_array_length(servers) > FP_STUN_MAX_SERVERS)
        return FASTP2P_EINVAL;
    int count = 0;
    for (size_t i = 0; i < json_object_array_length(servers); ++i) {
        json_object *item = json_object_array_get_idx(servers, i);
        if (!json_object_is_type(item, json_type_string))
            return FASTP2P_EINVAL;
        if (stun_entry(c, json_object_get_string(item), count))
            return FASTP2P_EINVAL;
        ++count;
    }
    c->stun_count = count;
    return FASTP2P_OK;
}

/* Same IP, ignoring the port: the STUN filtering test asks whether the peer
 * address changed at all, which is independent of the port it changed to. */
static int same_ip(const op_addr *a, const op_addr *b) {
    op_addr x = *a, y = *b;
    op_addr_normalize(&x);
    op_addr_normalize(&y);
    if (op_addr_family(&x) != op_addr_family(&y))
        return 0;
    if (op_addr_family(&x) == AF_INET)
        return x.u.in.sin_addr.s_addr == y.u.in.sin_addr.s_addr;
    if (op_addr_family(&x) == AF_INET6)
        return !memcmp(&x.u.in6.sin6_addr, &y.u.in6.sin6_addr, sizeof(x.u.in6.sin6_addr));
    return 0;
}
static void nat_stun_send(fastp2p_client *c) {
    nat_stun *s = &c->stun;
    if (s->server >= s->count || s->fd < 0)
        return;
    for (int i = 0; i < FP_STUN_NONCE; ++i)
        s->tid[i] = (uint8_t)random_id();
    uint8_t request[64];
    size_t length = fp_stun_request(request, sizeof(request), s->tid, s->phase == 3,
                                    s->phase == 2);
    if (length)
        (void)op_sendto(s->fd, request, length, MSG_DONTWAIT, &s->addr[s->server].u.sa,
                        s->addr[s->server].len);
    s->deadline = mono() + 1200 * MS;
}
static void nat_stun_finish(fastp2p_client *c) {
    nat_stun *s = &c->stun;
    /* Read the local endpoint before closing: when the server reports exactly the
     * address we sent from, there is no NAT in the path at all, and calling that
     * a full-cone NAT would be wrong. */
    if (s->fd >= 0 && s->mapped_seen && !s->no_nat) {
        op_addr local;
        memset(&local, 0, sizeof(local));
        if (!op_addr_socketname(s->fd, &local) &&
            op_addr_family(&local) == op_addr_family(&s->mapped) &&
            op_addr_port(&local) == op_addr_port(&s->mapped) && same_ip(&local, &s->mapped))
            s->no_nat = 1;
    }
    if (s->fd >= 0)
        op_close(s->fd);
    s->fd = -1;
    s->phase = 4;
    /* Same mapping from every destination -> cone; anything else is a
     * per-destination mapping, which is symmetric by definition.
     *
     * The cone variants are only separated when the servers actually proved
     * they implement the filtering extension: a reply from a different source,
     * or an advertised OTHER-ADDRESS. Otherwise a missing reply is just as
     * likely to mean "server ignored the attribute", and reporting NAT3 there
     * would turn a full-cone network into a false "port restricted". */
    int port_evidence = s->port_supported || s->has_alternate;
    int ip_evidence = s->ip_supported || s->has_alternate;
    if (!s->mapped_seen)
        s->level = 0;
    else if (s->no_nat)
        /* No translation, so the "levels" describe the host firewall instead:
         * reachable from elsewhere is an open internet host, and a path that
         * answers nothing is a symmetric UDP firewall (RFC 3489 §5). */
        s->level = (s->port_changed || s->ip_changed) ? 6 : (port_evidence ? 7 : 0);
    else if (!s->mapped_same)
        s->level = 4;
    else if (s->ip_changed)
        s->level = 1;
    else if (s->port_changed)
        /* Another port got through, so not port-restricted. Whether a stranger
         * address would also be accepted is only known if one was probed. */
        s->level = ip_evidence ? 2 : 5;
    else
        s->level = port_evidence ? 3 : 5;
    {
        char message[176];
        snprintf(message, sizeof(message),
                 "STUN NAT level: %d (mapping %s, other port %s, other address %s; "
                 "server honours change-request: port %s, address %s)",
                 s->level, s->mapped_same ? "stable" : "per-destination",
                 s->port_changed ? "answered" : "filtered",
                 s->ip_changed ? "answered" : "filtered", port_evidence ? "yes" : "unknown",
                 ip_evidence ? "yes" : "unknown");
        emit(c, FASTP2P_EVENT_TUNNEL, 0, 0, message);
    }
    if (c->ws && c->login_ok)
        report_nat(c);
}
static void nat_stun_start(fastp2p_client *c) {
    nat_stun *s = &c->stun;
    if (s->phase || !c->stun_count || !c->ws || !c->login_ok)
        return;
    if (c->nat[OP_FAM_V4].type != NAT_CONE && c->nat[OP_FAM_V4].type != NAT_UNKNOWN)
        return; /* symmetric is already NAT4, no stranger test needed */
    int resolved = 0;
    for (int i = 0; i < c->stun_count; ++i) {
        op_addr address;
        if (resolve_any(c->stun_host[i], c->stun_port[i], &address))
            continue;
        s->addr[resolved++] = address;
    }
    if (!resolved) {
        s->phase = 4;
        return;
    }
    s->count = resolved;
    s->server = 0;
    s->phase = 1;
    /* Assume cone until a server reports a different mapping. */
    s->mapped_same = 1;
    s->retried = 0;
    s->fd = socket_bound(1, NULL, 0, 0);
    if (s->fd < 0) {
        s->phase = 4;
        return;
    }
    nat_stun_send(c);
}
static void nat_stun_step(fastp2p_client *c, uint64_t now) {
    nat_stun *s = &c->stun;
    if (s->phase == 0 || s->phase >= 4)
        return;
    if (s->fd >= 0) {
        uint8_t data[1024];
        op_addr from;
        memset(&from, 0, sizeof(from));
        from.len = (op_socklen)sizeof(from.u.storage);
        op_ssize received =
            op_recvfrom(s->fd, data, sizeof(data), MSG_DONTWAIT, &from.u.sa, &from.len);
        if (received > 0) {
            fp_stun_mapped mapped;
            if (fp_stun_response(data, (size_t)received, s->tid, &mapped) && mapped.valid) {
                if (mapped.has_alternate) {
                    /* The server told us where it would answer from, which is a
                     * declaration that change-ip is implemented - so a missing
                     * reply later is our NAT dropping it, not a missing feature. */
                    s->has_alternate = 1;
                    s->ip_supported = 1;
                }
                if (s->phase == 1) {
                    if (!s->mapped_seen) {
                        op_addr_copy(&s->mapped, &mapped.address);
                        s->mapped_seen = 1;
                    /* A symmetric NAT changes the mapped *port* per destination,
                     * so the comparison has to include it - op_addr_equal
                     * deliberately compares endpoints without the port. */
                    } else if (!same_ip(&mapped.address, &s->mapped) ||
                               op_addr_port(&mapped.address) != op_addr_port(&s->mapped)) {
                        s->mapped_same = 0;
                    }
                }
                /* The reply's source is the evidence, not the payload. Address and
                 * port are judged separately: a CHANGE-REQUEST answer may come
                 * from another address, another port, or both. */
                if (op_addr_family(&from) == op_addr_family(&s->addr[s->server])) {
                    if (op_addr_port(&from) != op_addr_port(&s->addr[s->server])) {
                        s->port_changed = 1;
                        s->port_supported = 1;
                    }
                    if (!same_ip(&from, &s->addr[s->server])) {
                        s->ip_changed = 1;
                        s->ip_supported = 1;
                    }
                }
                /* Advance to the next variant, and to the next server once this
                 * one has answered all three: the cross-server comparison is
                 * what separates cone from symmetric. */
                ++s->phase;
                if (s->phase > 3) {
                    ++s->server;
                    s->phase = 1;
                }
                if (s->server >= s->count) {
                    nat_stun_finish(c);
                    return;
                }
                s->retried = 0;
                nat_stun_send(c);
                return;
            }
        }
    }
    if (now < s->deadline)
        return;
    /* Retry this phase once before reading anything into its silence: at startup
     * the first datagram is the one most likely to be lost, and losing it would
     * cost the mapping that the whole verdict depends on. */
    /* The mapping phase gets two retries: everything else is derived from it, and a
     * NAT that has just seen a new client can drop the first couple of datagrams
     * while it creates the state. A filtered reply is still information, so the
     * other phases only try once more. */
    if (s->retried < (s->phase == 1 ? 2 : 1)) {
        ++s->retried;
        nat_stun_send(c);
        return;
    }
    /* Move on: a missing reply is itself information (that variant was filtered
     * out), and the next server or phase may still answer. */
    ++s->phase;
    s->retried = 0;
    if (s->phase > 3) {
        ++s->server;
        s->phase = 1;
    }
    if (s->server >= s->count) {
        nat_stun_finish(c);
        return;
    }
    nat_stun_send(c);
}
/* NAT level in the four-step convention, derived from the mapping result plus the
 * inbound-filtering refinement. 5 means "cone, but the filtering test could not be
 * completed" (no second node to answer from a foreign address): claiming NAT1 or
 * NAT2 there would be a guess, so it is reported as its own value. */
/* TCP level: the mapping settles symmetric, the callback probe settles the cones. */
static int tcp_nat_level(const fastp2p_client *c) {
    if (c->tcp_nat.family[OP_FAM_V4].type == FP_NAT_DEPENDENT)
        return 4;
    if (c->tcp_level.level >= 1 && c->tcp_level.level <= 3)
        return c->tcp_level.level;
    return 0; /* mapping measured, filtering not */
}
static int nat_level(const fastp2p_client *c) {
    const nat_discovery *n = &c->nat[OP_FAM_V4];
    if (n->type == NAT_UNKNOWN)
        return 0;
    if (n->type != NAT_CONE)
        return 4;
    /* An external STUN observer settles it without needing a second node. Levels
     * 6 and 7 mean "no NAT in the path": 6 is an open host, 7 a symmetric UDP
     * firewall, and both are decided from the local-versus-mapped comparison. */
    if (c->stun.level >= 1 && c->stun.level <= 7)
        return c->stun.level;
    /* Without a STUN verdict the mapping still proves "cone", but which
     * cone variant it is stays unmeasured rather than guessed. */
    return 5;
}
/* 1 when this host can originate traffic of `family` toward the gateway. A
 * connect() on a bare UDP socket makes the kernel pick a source address and
 * fails with ENETUNREACH/EHOSTUNREACH when the family has no working path.
 * A successful connect is not enough on its own: a host with an IPv6 default
 * route but no global address still "succeeds", because the kernel picks a
 * link-local source that can never reach a global destination. Such a family is
 * reported unusable here, otherwise every v6 attempt would hang until timeout. */
static int local_family_routable(const op_addr *gateway, int family) {
    if (!gateway || !gateway->len || op_family_index(op_addr_family(gateway)) != family)
        return 0;
    op_socket fd = op_socket_open(op_index_family(family), SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    int usable = op_connect(fd, &gateway->u.sa, gateway->len) == 0;
    if (usable) {
        op_addr local;
        if (op_addr_socketname(fd, &local) == 0) {
            char text[OP_ADDR_TEXT];
            if (!op_addr_text(&local, text, sizeof(text))) {
                /* :: and fe80::/10 cannot carry traffic to a global peer. */
                if (!strncmp(text, "fe80", 4) || !strncmp(text, "::", 2))
                    usable = 0;
            }
        }
    } else if (errno == EINPROGRESS) {
        usable = 0; /* no source was selected, so there is no usable path */
    }
    op_close(fd);
    return usable;
}
/* Recompute which families this host can actually use toward the gateway. Called
 * at start and again before every connection attempt: a service that starts
 * before IPv6 is usable would otherwise advertise IPv4-only for its whole
 * lifetime, and a host that loses a family would keep claiming it. */
static int refresh_families(fastp2p_client *c) {
    int wanted = 0;
    for (int family = 0; family < OP_FAM_COUNT; ++family)
        if ((c->gateway_families & family_bit(family)) &&
            local_family_routable(&c->gateway_addr[family], family))
            wanted |= family_bit(family);
    if (!wanted)
        /* Nothing verified: keep the family the name resolved to so the client
         * still attempts the historical path instead of refusing to run. */
        wanted = (c->gateway_families & FAM_V4) ? FAM_V4 : FAM_V6;
    c->families_wanted = wanted;
    return wanted;
}
static void tick_nat(fastp2p_client *c, uint64_t now) {
    /* v4 is driven first so its socket work is identical to the old build; a
     * family that has not been started (fd < 0) is simply not counted. */
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        int was_running = c->nat[family].fd >= 0;
        if (was_running)
            tick_nat_family(c, family, now);
        /* An advisory family that finishes after the login went out publishes its
         * result over 6/9 rather than holding the connection back. Without this
         * the operator would wait for a full v6 probe timeout just to learn that
         * v4 was already ready. */
        if (was_running && c->nat[family].fd < 0 && c->ws && c->login_ok &&
            (family != primary_family(c) || c->nat_settled))
            report_nat(c);
    }
    if (c->nat_settled)
        return;
    /* Only the primary family's *first* probe window gates the login: a retry
     * runs afterwards and publishes its result over 6/9, so a blocked UDP probe
     * costs the historical two seconds and never six. */
    const nat_discovery *primary = &c->nat[primary_family(c)];
    if (primary->fd >= 0 && !primary->retries)
        return;
    c->nat_settled = 1;
    connect_gateway(c);
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
    /* SPEC §7: a gateway host may now be an IPv6 literal; every other character
     * still has to be a name character, so the old rejection of odd hosts is
     * unchanged. */
    if (!valid_gateway_host(c->host)) {
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
    /* fds start closed: calloc leaves 0, which is a valid descriptor. */
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        c->listener[family] = -1;
        c->listener_port[family] = 0;
        c->nat[family].fd = c->nat[family].fd2 = -1;
        c->nat[family].phase = 0;
    }
    fp_tcp_nat_init(&c->tcp_nat);
    c->tcp_level.listener = c->tcp_level.dialer = -1;
    c->force_relay = getenv("FASTP2P_FORCE_RELAY") != NULL;
    /* Diagnostic only: pretend the probe classified us differently, so the punch
     * ladder and the port window can be exercised without a matching NAT. */
    c->nat_override = 0;
    const char *nat_override = getenv("FASTP2P_NAT_TYPE");
    if (nat_override && *nat_override) {
        long value = strtol(nat_override, NULL, 10);
        if (value == NAT_CONE || value == NAT_HARD_SYM || value == NAT_EASY_SYM_INC ||
            value == NAT_EASY_SYM_DEC)
            c->nat_override = (int)value;
    }
    /* Index 0 keeps the old default text; an unset v6 slot stays empty so a
     * later bind never trusts a bogus address. */
    snprintf(c->ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", "0.0.0.0");
    snprintf(c->local_ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", "0.0.0.0");
    for (int i = 0; i < NT; ++i) {
        c->tunnels[i].fd = c->tunnels[i].listen_fd = c->tunnels[i].alternate_fd = -1;
        for (int p = 0; p < OP_FAM_COUNT; ++p)
            c->tunnels[i].probes[p].fd = -1;
    }
    for (int i = 0; i < NA; ++i) {
        c->apps[i].fd = -1;
        c->apps[i].tunnel_index = -1;
    }
    for (int i = 0; i < NP; ++i)
        c->pending[i].fd = -1;
    *out = c;
    return FASTP2P_OK;
}
void fp_client_validation_mode(fastp2p_client *c) { if(c)c->validate_only=1; }
int fastp2p_client_set_config_handler(fastp2p_client *c,fastp2p_config_handler handler,void *user) {
    if(!c || c->running || c->in_callback)return FASTP2P_ESTATE;
    c->config_handler=handler;c->config_user=user;return FASTP2P_OK;
}
int fastp2p_client_add_forward(fastp2p_client *c, const fastp2p_forward *f, uint64_t *id) {
    /* relay_node is appended to the struct, so callers built against the
     * earlier layout stay valid and simply have no opinion on the relay. */
    if (!c || !f || f->struct_size < offsetof(fastp2p_forward, relay_node) ||
        c->in_callback || !valid_node(f->peer_node) ||
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
                (f->struct_size >= sizeof(*f) && f->relay_node && *f->relay_node &&
                 (!valid_node(f->relay_node) ||
                  copy_string(a->relay_node, sizeof(a->relay_node), f->relay_node))) ||
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
            a->fd = c->validate_only ? -1 : socket_bound(a->udp, a->bind_ip, a->port, 0);
            if(c->validate_only) {if(id)*id=a->id;return FASTP2P_OK;}
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
    if (!p || p->struct_size < offsetof(fastp2p_socks5,relay_node))
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
                      .transport = p->transport,
                      .relay_node = p->struct_size >= sizeof(*p) ? p->relay_node : NULL};
    uint64_t aid;
    int rv = fastp2p_client_add_forward(c, &f, &aid);
    if (rv)
        return rv;
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used && c->apps[i].id == aid) {
            app *a = &c->apps[i];
            a->socks = 1;
            a->no_relay = p->struct_size >= sizeof(*p) ? (p->no_relay != 0) : 0;
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
    /* SPEC §7: resolve both families. Probe every family this host can actually
     * reach the gateway on, so a dual-stack pair can negotiate v6, but keep the
     * historical v4 preference for the login and the reply address. */
    int found = resolve_any_families(c->host, c->port, FAM_BOTH, &c->gateway, c->gateway_addr);
    if (!found) {
        emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, "gateway DNS resolution failed");
        return FASTP2P_EIO;
    }
    c->gateway_families = found;
    refresh_families(c);
    {
        /* One line that says why the client speaks the families it does. Without
         * it a v4-only decision (no AAAA, no v6 route, a blocked probe) is
         * indistinguishable in the log from a build that never had IPv6. */
        char message[128];
        snprintf(message, sizeof(message), "address families: resolved=%s%s wanted=%s%s",
                 (found & FAM_V4) ? "IPv4" : "", (found & FAM_V6) ? "+IPv6" : "",
                 (c->families_wanted & FAM_V4) ? "IPv4" : "",
                 (c->families_wanted & FAM_V6) ? "+IPv6" : "");
        emit(c, FASTP2P_EVENT_TUNNEL, 0, 0, message);
    }
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        if (!family_wanted(c, family))
            continue;
        op_socket fd =
            socket_bound(0, family == OP_FAM_V4 ? NULL : "::", c->public_port, 1);
        if (fd < 0 || op_listen(fd, 32)) {
            if (fd >= 0)
                op_close(fd);
            for (int other = 0; other < OP_FAM_COUNT; ++other)
                if (c->listener[other] >= 0) {
                    op_close(c->listener[other]);
                    c->listener[other] = -1;
                }
            return FASTP2P_EIO;
        }
        c->listener[family] = fd;
        c->listener_port[family] = socket_port(fd);
    }
    c->public_port = socket_port(c->listener[primary_family(c)]);
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
    fp_tcp_nat_prepare(&c->tcp_nat, c->gateway_addr, c->families_wanted);
    c->stopping = 0;
    c->reconnect_at = 0;
    c->nat_settled = 0;
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        c->nat[family].type = NAT_UNKNOWN;
        c->nat[family].phase = 0;
        c->nat[family].retries = 0;
        /* The diagnostic override is a forced value, so it must be visible from
         * the first login rather than only after a probe (which now retries). */
        if (family == OP_FAM_V4 && c->nat_override)
            c->nat[family].type = c->nat_override;
        nat_discovery_close(&c->nat[family]);
    }
    set_state(c, FASTP2P_CONNECTING, "discovering NAT and connecting to gateway");
    /* One discovery per family we mean to publish, each the old sequence. A
     * v4-only run opens exactly one v4 socket, as before. */
    int probing = 0;
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        if (!family_wanted(c, family) || !gateway_has(c, family))
            continue;
        nat_discovery *n = &c->nat[family];
        n->fd = socket_bound(1, family == OP_FAM_V4 ? NULL : "::", 0, 0);
        if (n->fd < 0)
            continue;
        n->phase = 1;
        n->deadline = mono() + 2 * NS;
        op_addr peer = c->gateway_addr[family];
        op_addr_set_port(&peer, 27180);
        /* A send failure is not fatal here: the deadline reports it, exactly as
         * the old single-family discovery did. */
        (void)udp_packet(n->fd, &peer, 2, 0, NULL);
        ++probing;
    }
    c->nat_settled = probing ? 0 : 1;
    if (!probing)
        connect_gateway(c);
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
    int tcp_done = fp_tcp_nat_step(&c->tcp_nat, now);
    if (tcp_done) {
        /* One line per family that finished a fresh observation, so the log
         * reads the same as before for a v4-only client and gains a v6 line
         * only when v6 was actually probed. */
        for (int family = 0; family < OP_FAM_COUNT; ++family) {
            const fp_tcp_family *f = &c->tcp_nat.family[family];
            if (!(tcp_done & family_bit(family)) || !f->collected)
                continue;
            char message[160];
            snprintf(message, sizeof(message),
                     "TCP NAT mapping (%s): %s; samples=%u destinationIPs=%u; filtering untested",
                     family == OP_FAM_V4 ? "IPv4" : "IPv6",
                     f->type == FP_NAT_STABLE ? "stable" :
                     f->type == FP_NAT_DEPENDENT ? "destination-dependent" : "unknown",
                     f->samples, f->destinations);
            emit(c, FASTP2P_EVENT_TUNNEL, 0, 0, message);
        }
        if (c->ws_connected)
            report_nat(c);
    }
    if (!c->ws && c->nat_settled && c->reconnect_at && now >= c->reconnect_at) {
        c->reconnect_at = 0;
        connect_gateway(c);
    }
    if (c->ws && c->login_ok && now - c->heartbeat_at >= 15 * NS)
        send_heartbeat(c);
    if (c->ws && c->login_ok && now - c->last_rx > 45 * NS)
        close_gateway(c);
    service_gateway(c);
    /* The STUN refinement starts once the control connection is authenticated: its
     * result is reported over 6/9, so it never delays the login itself. */
    nat_stun_start(c);
    nat_stun_step(c, now);
    /* TCP filtering probe: same window, verdict arrives asynchronously. */
    /* server.len is only known after the probe resolves its server, so the ports
     * configured text is what says a probe is wanted. */
    if (c->tcp_level.phase == 0 && c->tcp_level.server_port && c->ws && c->login_ok)
        fp_tcp_level_start(&c->tcp_level);
    fp_tcp_level_step(&c->tcp_level, now);
    /* Announce the outcome once, including "no verdict": the console has to be
     * able to tell a measured level from a probe that simply got no answer, and
     * a silent probe looks identical to one that has not run yet. */
    if (c->tcp_level.phase >= 4 && !c->tcp_level_reported) {
        char message[128];
        snprintf(message, sizeof(message),
                 "TCP NAT level: %d (callbacks accepted=%d same-port=%d other-ip=%d)",
                 c->tcp_level.level, c->tcp_level.accepted, c->tcp_level.same_port,
                 c->tcp_level.other_ip);
        emit(c, FASTP2P_EVENT_TUNNEL, 0, 0, message);
        c->tcp_level_reported = 1;
        if (c->ws && c->login_ok)
            report_nat(c);
    }
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
    fp_tcp_nat_close(&c->tcp_nat);
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
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        if (c->listener[family] >= 0)
            op_close(c->listener[family]);
        c->listener[family] = -1;
        c->listener_port[family] = 0;
        nat_discovery_close(&c->nat[family]);
        c->nat[family].phase = 0;
    }
    c->nat_settled = 0;
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
