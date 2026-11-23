#include "platform.h"
#include "fastp2p.h"
#include "update.h"
#include "wire.h"
#include "quic.h"
#include "port_mapping.h"
#include "socks.h"
#include "stun.h"
#include "tcp_level.h"
#include "secure.h"
#include "sdwan.h"
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
#define TCP_PREDICT_PORTS 4
#define NS UINT64_C(1000000000)
#define MS UINT64_C(1000000)
#define PEER_PORT_MIN 1024u
#define PEER_PORT_COUNT (9999u - PEER_PORT_MIN + 1u)
#define TCP_DIRECT_WAIT (10 * NS)
/* Simultaneous open: both sides must be in SYN_SENT at the same instant, so a
 * refused dial is retried quickly and for the whole window rather than once.
 * A carrier NAT refuses in ~5 ms, so the retry interval is short; the jitter
 * keeps two peers from retrying in lockstep and missing each other. */
/* The two sides play different roles. The initiator dials a few times, which opens
 * its mapping and its filter for the peer, and then listens on the same port: a
 * peer behind a port-restricted carrier NAT can only reach a listener that has
 * already sent it something. The responder keeps dialling for the whole window,
 * because those dials are what the initiator's now-open filter lets through.
 * Dialling forever on both sides is worse than useless: a carrier NAT answers an
 * unknown 5-tuple with a reset, and that reset tears the peer's socket down just
 * as it was about to cross. */
#define TCP_PUNCH_ATTEMPTS 4u
#define TCP_PUNCH_ATTEMPTS_RESPONDER 400u
#define TCP_PUNCH_RETRY_MS 20u
#define TCP_PUNCH_RETRY_JITTER_MS 60u
/* Per-attempt wait for a non-blocking connect; a dropped dial must not eat the
 * whole retry budget the way a 3 s deadline would. */
#define TCP_PUNCH_ATTEMPT_MS 250u
/* How far a TCP dial walks around the port the peer reported: a carrier NAT picks
 * the mapping for a new destination out of a pool, so the reachable port is close
 * to, but not equal to, the one reported for a different destination. */
#define TCP_PUNCH_SCAN 0
/* How often an active tunnel proves it is still there. */
#define TCP_KEEPALIVE_MS 3000u
#define UDP_DIRECT_WAIT (5 * NS)
#define NAT_FILTER_RETRY (30 * NS)
#define NAT_FILTER_REFRESH (600 * NS)
#define NAT_FILTER_MAX_AGE (1200 * NS)
/* A peer whose mapping moves with every destination still allocates the next
 * port somewhere near the one it last reported. When the sample says only "it
 * moved a lot" - no direction, no step - the punch offers the peer a window
 * centred on that observation instead of guessing one side of it: a directional
 * guess is wrong half the time and wastes the entire burst. Every port in the
 * window is a real datagram, so this is also the cap a peer may ask for. */
#define SYM_WINDOW_HARD 128
#define UDP_MAPPING_PROBE_PORT 27180
#define UDP_MAPPING_SAMPLES 4
#define UDP_MAPPING_SAMPLE_WAIT (250 * MS)
/* Repeat the spray once. The repeat reuses the same destination ports, so it
 * does not multiply NAT mappings; it buys two things instead: a punch timestamp
 * that is a few hundred milliseconds off still lands inside an open filter, and
 * each side's own burst advances its allocator, so a mapping that moved into the
 * window after the first round can still be caught. */
#define SYM_SPRAY_ROUNDS 2
#define SYM_SPRAY_GAP (400 * MS)
#define UDP_PUNCH_READY_WAIT (1500 * MS)
#define UDP_PUNCH_ACK_WINDOW (2 * NS)
#define UDP_PUNCH_EXTRA_SOCKETS 7
#define UDP_PUNCH_CLIENT_EXTRA_SOCKETS 16
#define UDP_PUNCH_EXTRA_WINDOW 4
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
    TUN_CERT_BIND = 12,
    TUN_SDWAN_IPV4 = 13
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
/* Address-family bitmaps (SPEC 搂1). The gateway uses the same two values, so
 * these numbers are protocol, not local policy. */
enum { FAM_V4 = 1, FAM_V6 = 2, FAM_BOTH = 3 };
enum tunnel_state {
    T_FREE,
    /* While any address-family mapping probe is outstanding the tunnel sits in
     * this one state; the per-family probe machines carry the old
     * T_NAT_CONNECT/READ/UDP detail. */
    T_PROBE,
    T_TCP_SAMPLE,
    T_NAT_CONNECT,
    T_NAT_READ,
    T_NAT_UDP,
    T_REPLY,
    T_TIME,
    T_TCP_CONNECT,
    T_TCP_DIRECT_CONNECT,
    T_TCP_DIRECT_ACK,
    T_HANDSHAKE,
    T_ACTIVE,
    T_PUNCH,
    T_UNDERLAY,
    T_UDP_DIRECT,
    T_QUIC,
    T_DIRECT
};
enum { TCP_PREDICT_NONE, TCP_PREDICT_OPEN, TCP_PREDICT_DIAL, TCP_PREDICT_PAIR };
enum { UDP_PUNCH_LEGACY, UDP_PUNCH_SEND, UDP_PUNCH_RECEIVE };
/* One address-family mapping probe. A dual-stack client runs the identical
 * sequence once per family, against the gateway's address of that family
 * (SPEC 搂2); a v4-only client keeps exactly one, which is the old behaviour.
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
    /* A socket borrowed from the shared UDP listener: it must never be closed
     * here, because the peer listener owns it for the rest of the run. */
    int borrowed;
    int sample_udp_ports;
    uint16_t udp_ports[UDP_MAPPING_SAMPLES];
    uint32_t udp_ips[UDP_MAPPING_SAMPLES];
} nat_probe;
/* Per-family NAT classification state. Running the old single probe sequence
 * once per family is what keeps the IPv4 run byte-identical while letting IPv6
 * be measured the same way (SPEC 搂2/搂4). */
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
    int phase; /* 0 idle, 1 plain, 2 change-port, 3 change-ip */
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
    /* 1 when the server reported exactly the address we sent from, i.e. the path
     * has no NAT translation and the level describes the host firewall. */
    int no_nat;
    /* One retransmission per phase: a single lost datagram (common right after
     * startup, while DNS and routing settle) must not throw away the mapping and
     * turn a measurable NAT into "unknown". */
    int retried;
    /* The probe borrowed the peer listener socket: its mapping is the port the
     * operator forwards, and that socket has to stay open when the probe ends. */
    int shared;
} nat_stun;
typedef struct {
    int level;
    uint64_t measured_at, next_at;
} nat_filter;
typedef struct {
    int state, server, initiator, transport, notified;
    int tcp_v2, tcp_punch_immediate;
    uint16_t tcp_direct_port, udp_direct_port, udp_reverse_port, udp_reverse_port6;
    int skip_udp_direct, udp_reverse6_retry, udp_reverse6_supported;
    unsigned tcp_attempts;
    uint64_t tcp_attempt_deadline, tcp_retry_at;
    fp_tcp_family *tcp_sample;
    unsigned tcp_mapping, peer_tcp_mapping;
    uint16_t tcp_last_port, peer_tcp_last_port;
    /* How far the dial has walked around the port the peer reported. A carrier NAT
     * allocates the mapping for a new destination from a pool, so the port that is
     * reachable from this side is near, but not equal to, the reported one. */
    int tcp_scan;
    int peer_tcp_pair, tcp_predict_role, tcp_predict_ready, tcp_predict_ready_sent;
    int tcp_peer_ip_verified;
    uint64_t tcp_predict_wait, tcp_predict_until;
    unsigned tcp_candidate_count;
    uint16_t tcp_candidate_ports[1 + TCP_PREDICT_PORTS];
    op_socket tcp_candidates[1 + TCP_PREDICT_PORTS];
    op_socket fd, listen_fd, alternate_fd;
    uint64_t id, peer_id, deadline, at, last_rx, last_hb, punch_next, punch_started;
    uint64_t last_session_push, silent_logged, last_payload, active_since;
    /* Peer's predicted mapping window: base port, direction and width. A
     * symmetric peer changes port per destination, so the peer tells us
     * where its next mapping is likely to land and we spray that range.
     * `sym_split` marks a window centred on `sym_base` (direction unknown,
     * used for a peer with an unpredictable step); otherwise the window starts
     * one port past `sym_base` and walks in the `sym_up` direction. */
    uint16_t sym_base, sym_count, sym_alt_base;
    int sym_up, sym_sprayed, sym_split;
    uint64_t sym_spray_at;
    int udp_punch_order, udp_punch_kind, udp_punch_role, udp_punch_ready;
    int udp_dual_punch, udp_peer_cone;
    unsigned udp_candidate_count;
    op_socket udp_candidates[UDP_PUNCH_EXTRA_SOCKETS];
    uint64_t udp_punch_ack_until;
    uint64_t active_at;
    /* Endpoint text is canonical address text (no brackets, no %scope) in
     * whichever family it was learned, so an IPv6 peer no longer truncates into
     * a 16-byte IPv4 buffer. `ip`/`mapped_ip` name the active family; the
     * per-family arrays carry both, because a dual-stack negotiation publishes
     * both and the punch may still have to fall back from one to the other. */
    char peer[32], ip[OP_ADDR_TEXT], mapped_ip[OP_ADDR_TEXT], mode[16], probe[96];
    size_t probe_len;
    /* Peer endpoints and our own mapping observations, by family (SPEC 搂5). */
    char peer_text[OP_FAM_COUNT][OP_ADDR_TEXT], mapped_text[OP_FAM_COUNT][OP_ADDR_TEXT];
    uint16_t remote_ports[OP_FAM_COUNT], mapped_ports[OP_FAM_COUNT];
    /* 1 when the peer gave us a usable endpoint of that family. */
    int peer_ready[OP_FAM_COUNT];
    nat_probe probes[OP_FAM_COUNT];
    int family, ipv4_only, attempted_ipv6;
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
    int used, local, udp, transport, tunnel_index, synced, socks, sdwan;
    op_socket fd;
    uint64_t id, retry, ready_at;
    char name[64], peer[32], destination[256], bind_ip[OP_ADDR_TEXT];
    char socks_user[256], socks_password[256];
    uint16_t port, dst_port;
    int attempts, relay_wanted, relay_requested;
    int lan_tried, udp_direct_tried, udp_reverse6_retry, ipv4_retry;
    int no_relay;  /* operator disabled relay fallback for this rule */
    /* Operator-chosen relay for this rule; empty means automatic. */
    char relay_node[32];
    uint64_t link_deadline;
    /* Relays that already failed for this rule; the gateway is asked to skip
     * them so one unreachable candidate cannot pin the link forever. */
    struct {
        char node[32];
        uint64_t until;
    } relay_failed[4];
    int relay_failed_count;
    /* The peer's own local address, per family (SPEC 搂5: same-LAN detection
     * compares within a family). lanIP stays IPv4 as before; lanIP6 is only
     * filled when the peer reports one, so an old peer looks LAN-less exactly
     * as it did before. */
    char peer_lan[OP_ADDR_TEXT], peer_lan6[OP_ADDR_TEXT];
    uint32_t peer_observed_ipv4;
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
    const char *ca_pem, *tls_host;
    char error[192], path[2048], hostname[256], device_id[33];
    int automatic_node;
    uint16_t port, public_port, requested_public_port;
    int auto_port_mapping;
    fp_port_mapping *port_mapping;
    fp_mapped_ports mapped_listener;
    uint64_t port_mapping_wait_until;
    uint64_t token, node_id, reconnect_at, last_rx, heartbeat_at, heartbeat_sent;
    int64_t clock_delta;
    fastp2p_state state;
    int running, stopping, in_callback, stepping, report_ok, login_ok, reconnect_attempt;
    /* NAT classification is per family (DUALSTACK-SPEC 搂2/搂4). Index 0 holds
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
    nat_filter udp_filter, tcp_filter;
    /* 1 once every family we decided to probe has finished (or timed out), so
     * the login goes out with a complete picture rather than half-way. */
    int nat_settled;
    fp_tcp_nat tcp_nat;
    int force_relay; /* FASTP2P_FORCE_RELAY diagnostic switch */
    int nat_override; /* FASTP2P_NAT_TYPE diagnostic switch, 0 = use the probe */
    /* Curl writes the detailed TLS reason here; the short error code alone
     * cannot say whether the handshake was refused, reset, or rejected. */
    char curl_error[CURL_ERROR_SIZE];
    /* Peer listeners share public_port across both transports and families. */
    op_socket listener[OP_FAM_COUNT], udp_listener[OP_FAM_COUNT];
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
    /* Which family to offer first when both resolve, and how many attempts in a row
     * have failed: a route that completes the TCP handshake and then stays silent
     * never lets curl fall through, so the order has to move by itself. */
    /* Both families were resolved for this connection, which is what makes a
     * switch worth trying: the family bitmap above only describes reachability. */
    int gateway_dual;
    /* 1 while the TCP peer listener is closed so the probe can own the port, and when
     * that last happened: a probe that keeps failing must not close the listener on
     * every 30 s retry. */
    int tcp_relisten;
    uint64_t tcp_handoff_at;
    int gateway_prefer_v6;
    unsigned gateway_failures;
    int families_wanted;  /* what we publish: observed 鈭?configured intent */
    CURLM *multi;
    CURL *ws;
    struct curl_slist *resolve;
    curl_socket_t ws_socket;
    int ws_connected;
    uint64_t upgrade_stop_at;
    int gateway_tcp_probe_v2, gateway_tcp_probe_v3;
    size_t ws_remaining;
    op_buffer ws_rx, ws_tx;
    fastp2p_event_fn callback;
    fastp2p_config_handler config_handler;
    void *config_user;
    fastp2p_restart_handler restart_handler;
    void *restart_user;
    int validate_only;
    void *user;
    fp_sdwan *sdwan;
    uint64_t sdwan_report_at;
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
static int nat_filter_level(const nat_filter *filter, uint64_t now);
static int addr_text_set(const char *text);
static int local_is_public(const char *text);
static void report_nat(fastp2p_client *);
static int nat_stun_input(fastp2p_client *, const uint8_t *, size_t, const op_addr *, uint64_t);
static int family_usable(const fastp2p_client *, const tunnel *, int);
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
/* Families bitmap helpers (SPEC 搂1). `nat` is IPv4-only in the old sense; the
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
/* 1 when this client intends to probe/publish `index` (SPEC 搂1). The default is
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
 * accepted when it really parses as one (SPEC 搂7). The old check rejected every
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
static uint32_t observed_ipv4(const op_addr *address) {
    if (op_addr_family(address) != AF_INET || !op_addr_routable(address))
        return 0;
    return ntohl(address->u.in.sin_addr.s_addr);
}
static uint32_t public_ipv4(const op_addr *address) {
    uint32_t ip = observed_ipv4(address);
    /* Shared carrier space can also be observed by a privately hosted gateway. */
    return (ip & 0xffc00000u) == 0x64400000u ? 0 : ip;
}

/* Different egress IPv4 observations, including shared carrier addresses,
 * rule out a LAN attempt between sites. A private gateway or an IPv6-only
 * peer can lack a comparable observation.
 * The LAN candidates still need private addresses in the same family. */
static int lan_punch_possible(const fastp2p_client *c, const app *a) {
    op_addr local_observed;
    if (a->peer_observed_ipv4 && !op_addr_from_text(&local_observed, c->ip[OP_FAM_V4], 0)) {
        uint32_t local_ip = observed_ipv4(&local_observed);
        if (local_ip && local_ip != a->peer_observed_ipv4)
            return 0;
    }
    for (int index = 0; index < OP_FAM_COUNT; ++index) {
        const char *peer_text = index == OP_FAM_V4 ? a->peer_lan : a->peer_lan6;
        op_addr peer, local;
        if (!address_of_family(peer_text, index) ||
            !address_of_family(c->local_ip[index], index) ||
            op_addr_from_text(&peer, peer_text, 0) ||
            op_addr_from_text(&local, c->local_ip[index], 0))
            continue;
        if (op_addr_private(&peer) && op_addr_private(&local)) {
            /* Only a peer on *our* subnet is reachable without a route between
             * the two LANs. Treating any two private addresses as neighbours
             * wastes a whole punch round on an address nothing can answer. */
            if (peer.u.in.sin_family == AF_INET && local.u.in.sin_family == AF_INET &&
                memcmp(&peer.u.in.sin_addr, &local.u.in.sin_addr, 3))
                continue;
            return 1;
        }
    }
    return 0;
}
/* A peer this host can reach without a NAT in between: loopback or a private
 * address. Such a peer dials our listener, which is the opposite of what a
 * carrier-NAT peer needs, so the two cases must not share one strategy. */
static int peer_is_local(const op_addr *a) {
    if (!a || !a->len)
        return 0;
    if (op_addr_private(a))
        return 1;
    op_addr x = *a;
    op_addr_normalize(&x);
    if (x.u.sa.sa_family == AF_INET)
        return (ntohl(x.u.in.sin_addr.s_addr) >> 24) == 127;
    if (x.u.sa.sa_family == AF_INET6) {
        const uint8_t *b = x.u.in6.sin6_addr.s6_addr;
        for (int i = 0; i < 15; ++i)
            if (b[i])
                return 0;
        return b[15] == 1;
    }
    return 0;
}/* A peer may publish an address that is actually ours: both nodes can egress the
 * same carrier NAT, or the peer's probe can leave through our line. Dialling it
 * only reaches our own NAT, which has no hairpin, so fall back to the address the
 * gateway observed for that peer. */
static const char *punch_peer_text(const fastp2p_client *c, const char *peer, const char *text,
                                   char *out, size_t length) {
    if (!text || !*text || !c->ip[OP_FAM_V4][0] || strcmp(text, c->ip[OP_FAM_V4]))
        return text;
    for (int i = 0; i < NA; ++i) {
        const app *a = &c->apps[i];
        if (!a->used || !a->peer_observed_ipv4 || (peer && strcmp(a->peer, peer)))
            continue;
        uint32_t ip = a->peer_observed_ipv4;
        snprintf(out, length, "%u.%u.%u.%u", (unsigned)(ip >> 24), (unsigned)((ip >> 16) & 255),
                 (unsigned)((ip >> 8) & 255), (unsigned)(ip & 255));
        return out;
    }
    return text;
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
enum { BIND_DEFAULT, BIND_REUSE_PORT, BIND_PEER_LISTENER };
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
    /* The peer listener must have this port to itself. On POSIX, REUSEADDR
     * alone still allows restart when previous connections are in TIME_WAIT. */
#ifdef _WIN32
    int listener_option = SO_EXCLUSIVEADDRUSE;
#else
    int listener_option = udp ? 0 : SO_REUSEADDR;
#endif
    if ((reuse == BIND_REUSE_PORT && op_reuse_socket(fd)) ||
        (reuse == BIND_PEER_LISTENER && listener_option &&
         op_setsockopt(fd, SOL_SOCKET, listener_option, &one, sizeof(one)))) {
        op_close(fd);
        return -1;
    }
    if (op_bind(fd, &bind_to.u.sa, bind_to.len)) {
        int error = errno;
        op_close(fd);
        errno = error;
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
static void close_peer_listeners(op_socket listeners[OP_FAM_COUNT]) {
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        if (listeners[family] >= 0)
            op_close(listeners[family]);
        listeners[family] = -1;
    }
}

static int bind_peer_listeners(fastp2p_client *c, uint16_t port, int udp) {
    op_socket *listeners = udp ? c->udp_listener : c->listener;
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        /* The peer listener is about the data plane, not the control connection: a host
         * whose gateway is only reachable over IPv6 still has peers arriving over
         * IPv4; skipping that listener made the IPv4 callback fail and the TCP
         * verdict read port-restricted. IPv4 is always attempted, IPv6 only when
         * the family is usable. */
        if (family == OP_FAM_V6 && !family_wanted(c, OP_FAM_V6))
            continue;
        listeners[family] = socket_bound(udp, family == OP_FAM_V4 ? NULL : "::",
                                         port, BIND_PEER_LISTENER);
        if (listeners[family] < 0 || (!udp && op_listen(listeners[family], 32))) {
            int error = errno;
            close_peer_listeners(listeners);
            return error;
        }
    }
    return 0;
}

static int has_udp_listener(const fastp2p_client *c) {
    return c->udp_listener[OP_FAM_V4] >= 0 || c->udp_listener[OP_FAM_V6] >= 0;
}

static int start_peer_listeners(fastp2p_client *c) {
    c->public_port = c->requested_public_port;
    if (c->public_port) {
        int error = bind_peer_listeners(c, c->public_port, 0);
        if (!error) {
            if (bind_peer_listeners(c, c->public_port, 1))
                emit(c, FASTP2P_EVENT_TUNNEL, 0, 0, "Configured UDP peer port unavailable; using UDP punching");
            return 0;
        }
        if (error != EADDRINUSE && error != EACCES)
            return error;
        emit(c, FASTP2P_EVENT_TUNNEL, 0, 0, "Configured TCP peer port unavailable; choosing another port");
        c->public_port = 0;
    }
    const char *identity = c->device_id[0] ? c->device_id : c->node;
    unsigned first = (unsigned)(op_node_id(identity) % PEER_PORT_COUNT);
    for (unsigned offset = 0; offset < PEER_PORT_COUNT; ++offset) {
        uint16_t port = (uint16_t)(PEER_PORT_MIN + (first + offset) % PEER_PORT_COUNT);
        int error = bind_peer_listeners(c, port, 0);
        if (!error) {
            error = bind_peer_listeners(c, port, 1);
            if (!error) {
                c->public_port = port;
                return 0;
            }
            close_peer_listeners(c->listener);
        }
        if (error != EADDRINUSE && error != EACCES)
            return error;
    }
    return EADDRINUSE;
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
static uint64_t local_transport_nat(const fastp2p_client *c, int transport) {
    /* Index 0 is the old single value: a v4-only run reports and decides
     * exactly as before. */
    return transport == FASTP2P_TRANSPORT_TCP ? c->tcp_nat.family[OP_FAM_V4].type
                                              : (uint64_t)c->nat[OP_FAM_V4].type;
}
/* Built-in probe servers: every node measures its NAT the same way without any
 * per-machine configuration. Each is still overridable, and `[]` / "" disables the
 * corresponding probe for an operator who does not want it to leave the host.
 *
 * The UDP entry pairs a nearby server with the project's own: the filter verdict
 * needs an answer from a *different address*, so one unreachable probe would leave
 * the level unmeasured rather than merely slow. */
#define FP_DEFAULT_STUN_SERVERS "stun.miwifi.com:3478"
#define FP_DEFAULT_STUN_SERVERS_ALT "stun.fastp2p.top:3478"
/* TCP filtering needs a callback probe server; the project's own host, dedicated
 * port. It answers a plain-text "mapped <ip> <port>" line, not STUN. */
#define FP_DEFAULT_TCP_NAT_PROBE "stun.fastp2p.top:3479"
/* TCP mapping needs two destinations on *different addresses*: the gateway's own
 * probe ports are one address, so a mapping that depends on the destination could
 * otherwise never be told apart from a stable one, and the port prediction that
 * symmetric-to-symmetric punching relies on would never enable. */
#define FP_DEFAULT_TCP_MAPPING_SERVERS "stun.fastp2p.top:3478"
#define FP_DEFAULT_TCP_MAPPING_SERVERS_ALT "stun.nextcloud.com:443"

int fp_client_tcp_nat_config(fastp2p_client *c, json_object *servers) {
    if (servers)
        return fp_tcp_nat_configure(&c->tcp_nat, servers) ? FASTP2P_EINVAL : FASTP2P_OK;
    /* No key at all falls back to the two built-in destinations. An empty array is
     * an explicit opt-out, so a hermetic deployment still gets no external traffic. */
    json_object *fallback = json_object_new_array();
    if (!fallback)
        return FASTP2P_EIO;
    json_object_array_add(fallback, json_object_new_string(FP_DEFAULT_TCP_MAPPING_SERVERS));
    json_object_array_add(fallback, json_object_new_string(FP_DEFAULT_TCP_MAPPING_SERVERS_ALT));
    int configured = fp_tcp_nat_configure(&c->tcp_nat, fallback);
    json_object_put(fallback);
    return configured ? FASTP2P_EINVAL : FASTP2P_OK;
}
/* Two cone NATs open their filters on the first packet either side sends, so the
 * first moments decide the outcome: send densely for half a second, then fall
 * back to a steady cadence that keeps the mapping alive for the rest of the
 * window. */
static uint64_t punch_interval(uint64_t elapsed) {
    return elapsed < 500 * MS ? 50 * MS : 200 * MS;
}
/* Each public round gets a fresh mapping and a new prediction window. */
enum { PUBLIC_PUNCH_ROUNDS = 2 };
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
/* A hard-symmetric peer offers no direction to walk in, so it gets a window
 * centred on its observation and both edges are clamped to the port range.
 * The observed port itself stays out of the span: it is already punched
 * explicitly, and repeating it would spend two of the capped slots on one port. */
static int sym_split_window(uint16_t observed, uint16_t count, uint16_t *low, uint16_t *high) {
    if (count < 2 || !low || !high)
        return 0;
    uint32_t below = observed > 1 ? (uint32_t)observed - 1 : 0;
    uint32_t above = 65535u - (uint32_t)observed;
    uint32_t half = (uint32_t)count / 2;
    if (below > half)
        below = half;
    if (above > half)
        above = half;
    if (!below && !above)
        return 0;
    *low = (uint16_t)((uint32_t)observed - below);
    *high = (uint16_t)((uint32_t)observed + above);
    return 1;
}
/* Centred windows are wider than directional ones, because the same burst now
 * has to cover both sides of the observation. */
static uint16_t sym_window_hard_cap(uint16_t requested) {
    return requested > SYM_WINDOW_HARD ? SYM_WINDOW_HARD : requested;
}
/* Which window, if any, this mapping behaviour lets us offer a peer.
 * 0 = none: a cone or unclassified mapping is already reachable at the port it
 * published, so a window would only add traffic. 1 = directional: the step is
 * small, so walking away from the observation in the measured direction lands on
 * the next mapping. 2 = centred: the step is unpredictable, so cover both
 * sides and let the peer's allocator fall where it may. */
static int sym_window_kind(int nat_type) {
    if (nat_type == NAT_EASY_SYM_INC || nat_type == NAT_EASY_SYM_DEC)
        return 1;
    if (nat_type == NAT_HARD_SYM)
        return 2;
    return 0;
}
/* Require two close observations in each of two well-separated ranges, all
 * on the same external address. The replies can arrive in any order. */
static uint16_t udp_alternate_mapping(const nat_probe *p) {
    uint16_t base = p->udp_ports[0], low = UINT16_MAX, high = 0;
    int nearby = 0;
    if (!base)
        return 0;
    for (int i = 1; i < UDP_MAPPING_SAMPLES; ++i) {
        uint16_t port = p->udp_ports[i];
        int gap = abs((int)port - base);
        if (!port || p->udp_ips[i] != p->udp_ips[0])
            return 0;
        if (gap <= SYM_WINDOW_MAX) {
            if (port == base)
                return 0;
            ++nearby;
        } else if (gap >= 2 * SYM_WINDOW_HARD) {
            if (port < low)
                low = port;
            if (port > high)
                high = port;
        } else {
            return 0;
        }
    }
    return nearby == 1 && high > low && high - low <= SYM_WINDOW_MAX ? high : 0;
}
/* Read a peer's advertised window. Kept in one place because both the request
 * and the reply carry it, and an old peer sends neither. A window that cannot
 * describe at least two ports is dropped rather than half-honoured. */
static void learn_sym_window(tunnel *t, json_object *j) {
    uint64_t base = op_integer(j, "symBase"), count = op_integer(j, "symCount");
    uint64_t alt = op_integer(j, "symAltBase");
    t->sym_alt_base = 0;
    int split = op_integer(j, "symSplit") == 1;
    uint16_t width = 0;
    if (base && base <= 65535 && count)
        width = split ? sym_window_hard_cap(count > 65535 ? 65535 : (uint16_t)count)
                      : sym_window_cap(count > 65535 ? 65535 : (uint16_t)count);
    if (width < 2) {
        t->sym_base = t->sym_count = 0;
        t->sym_split = 0;
        return;
    }
    t->sym_base = (uint16_t)base;
    t->sym_count = width;
    t->sym_split = split;
    t->sym_up = op_integer(j, "symUp") ? 1 : 0;
    if (split && width >= 4 && base == op_integer(j, "coneNatPort") &&
        alt && alt <= UINT16_MAX && abs((int)alt - (int)base) >= 2 * SYM_WINDOW_HARD)
        t->sym_alt_base = (uint16_t)alt;
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
static void close_tcp_candidates(tunnel *t) {
    for (unsigned i = 0; i < t->tcp_candidate_count; ++i)
        if (t->tcp_candidates[i] >= 0)
            op_close(t->tcp_candidates[i]);
    t->tcp_candidate_count = 0;
}
static void close_udp_candidates(tunnel *t) {
    for (unsigned i = 0; i < t->udp_candidate_count; ++i)
        if (t->udp_candidates[i] >= 0)
            op_close(t->udp_candidates[i]);
    t->udp_candidate_count = 0;
}
/* t->fd owns the active punch socket after a probe socket is adopted. */
static void probe_close(nat_probe *p) {
    if (p->fd >= 0 && !p->borrowed)
        op_close(p->fd);
    p->fd = -1;
}
static void probe_socket_close(tunnel *t) {
    for (int index = 0; index < OP_FAM_COUNT; ++index) {
        op_socket fd = t->probes[index].fd;
        if (fd >= 0 && fd != t->fd && !t->probes[index].borrowed)
            op_close(fd);
        t->probes[index].fd = -1;
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
            if (reason && c->apps[i].local && t->initiator && !t->lan && !t->relay_wait && !was_synced) {
                app *a = &c->apps[i];
                int reverse6 = t->attempted_ipv6 && t->udp_direct_port && t->udp_reverse_port6 &&
                               t->udp_reverse6_supported && !t->udp_reverse6_retry;
                int fallback = !reverse6 && t->attempted_ipv6 && !a->ipv4_retry &&
                               family_usable(c, t, OP_FAM_V4);
                a->udp_reverse6_retry = reverse6;
                if (reverse6) {
                    emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, "IPv6 direct attempt failed; trying reverse UDP dialing");
                } else if (fallback) {
                    a->ipv4_retry = 1;
                    a->udp_direct_tried = 0;
                    emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, "IPv6 direct attempt failed; retrying over IPv4");
                } else if (t->udp_direct_port) {
                    a->udp_direct_tried = 1;
                }
                /* Listener attempts do not spend the ordinary punch rounds. */
                if ((reverse6 || fallback || t->udp_direct_port) && a->attempts > 0)
                    --a->attempts;
            }
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
    probe_socket_close(t);
    if (t->fd >= 0)
        op_close(t->fd);
    if (t->listen_fd >= 0)
        op_close(t->listen_fd);
    if (t->alternate_fd >= 0)
        op_close(t->alternate_fd);
    close_tcp_candidates(t);
    close_udp_candidates(t);
    fp_tcp_punch_sample_free(t->tcp_sample);
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
            {
                /* Every tunnel object starts in T_REPLY; without this line a tunnel that
                 * never progresses cannot be told apart from one nobody created. */
                char born[200];
                snprintf(born, sizeof(born), "tunnel created: peer %s (%s, %s) id %llu state %d",
                         peer, initiator ? "initiator" : "responder",
                         transport == FASTP2P_TRANSPORT_QUIC ? "quic" : "tcp",
                         (unsigned long long)id, (int)t->state);
                emit(c, FASTP2P_EVENT_TUNNEL, id, 0, born);
            }
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
static int probe_running(const tunnel *t) {
    for (int index = 0; index < OP_FAM_COUNT; ++index)
        if (t->probes[index].state && t->probes[index].state != PROBE_DONE)
            return 1;
    return 0;
}
/* 1 when the peer published a usable endpoint of `family` and we can answer it
 * in that family too 鈥?our side needs either a mapping observation or, for a
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
/* Which family to punch in (SPEC 搂5): a shared IPv6 is tried first because it
 * usually has no NAT in front of it at all, and IPv4 stays the compatibility
 * path an old peer can always answer. An old peer never publishes a v6
 * endpoint, so a mixed pair never leaves the v4 path here. */
static int choose_punch_family(const fastp2p_client *c, const tunnel *t) {
    if (!t->ipv4_only && family_usable(c, t, OP_FAM_V6))
        return OP_FAM_V6;
    if (family_usable(c, t, OP_FAM_V4))
        return OP_FAM_V4;
    return -1;
}
/* Point the tunnel at `family`: active endpoints, the remote tuple and the
 * socket to punch with. For QUIC the probe socket of that family becomes the
 * punch socket and keeps the mapping that was advertised to the peer. */
static int use_punch_family(fastp2p_client *c, int index, int family) {
    tunnel *t = &c->tunnels[index];
    if (!family_usable(c, t, family))
        return -1;
    op_addr peer;
    if (op_addr_from_text(&peer, t->peer_text[family], t->remote_ports[family]))
        return -1;
    t->family = family;
    t->attempted_ipv6 = family == OP_FAM_V6;
    address_copy(t->ip, t->peer_text[family]);
    address_copy(t->mapped_ip, t->mapped_text[family]);
    t->remote_port = t->remote_ports[family];
    t->mapped_port = t->mapped_ports[family];
    op_addr_copy(&t->peer_addr, &peer);
    if (t->transport != FASTP2P_TRANSPORT_QUIC) {
        if (t->probes[family].local_port)
            t->local_port = t->probes[family].local_port;
        if (t->listen_fd >= 0 && (socket_family(t->listen_fd) != family ||
                                 socket_port(t->listen_fd) != t->local_port)) {
            op_close(t->listen_fd);
            t->listen_fd = -1;
        }
        return strcmp(t->mode, "tcppunch") ? 0 : tcp_punch_listen(c, index);
    }
    if (t->probes[family].fd >= 0) {
        if (t->fd >= 0 && t->fd != t->probes[family].fd)
            op_close(t->fd);
        t->fd = t->probes[family].fd;
        t->probes[family].fd = -1; /* t->fd owns the punch socket now */
    }
    if (t->fd >= 0 && socket_family(t->fd) != family) {
        op_close(t->fd);
        t->fd = -1;
    }
    if (t->fd < 0) {
        t->fd = socket_bound(1, source_text(c, family), t->local_port, 1);
        if (t->fd < 0)
            return -1;
    }
    t->local_port = socket_port(t->fd);
    return 0;
}
/* Record one endpoint a peer published (SPEC 搂5). `text` is canonical, so a
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
/* No gateway mapping probe answered, but a host without translation peers on its
 * business port: its own address and that port are the mapping, and answering the
 * peer with them keeps a no-relay link alive instead of falling through to the
 * relay. Returns 1 when the mapping was adopted and the peer can be answered. */
static int probe_fallback_mapping(fastp2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    if (nat_filter_level(&c->udp_filter, mono()) < 6 || !c->public_port)
        return 0;
    int family = family_wanted(c, OP_FAM_V4) && c->ip[OP_FAM_V4][0]
                     ? OP_FAM_V4
                     : family_wanted(c, OP_FAM_V6) && c->ip[OP_FAM_V6][0] ? OP_FAM_V6 : -1;
    if (family < 0)
        return 0;
    /* The business port cannot be bound twice - the listener owns it exclusively -
     * so borrow that socket the way the STUN exchange already does. Its mapping is
     * the port peers know, which is exactly what the answer needs. */
    op_socket fd = c->udp_listener[family];
    if (fd < 0)
        return 0;
    int borrowed = 1;
    t->probes[family] = (nat_probe){.fd = fd};
    t->probes[family].borrowed = borrowed;
    t->probes[family].local_port = socket_port(fd);
    t->fd = -1;
    t->family = family;
    t->local_port = t->probes[family].local_port;
    t->mapped_port = t->local_port;
    t->mapped_ports[family] = t->local_port;
    /* c->ip can still be 0.0.0.0 when the control plane never learned this
     * address; the STUN exchange measured it independently, so publish that
     * instead of answering the peer with an unusable address. */
    const char *mapped_ip = c->ip[family];
    char stun_text[OP_ADDR_TEXT] = "";
    if (!addr_text_set(mapped_ip) || !address_of_family(mapped_ip, family)) {
        if (!c->stun.mapped_seen ||
            op_family_index(op_addr_family(&c->stun.mapped)) != family)
            return 0;
        if (op_addr_text(&c->stun.mapped, stun_text, sizeof(stun_text)) ||
            !address_of_family(stun_text, family))
            return 0;
        mapped_ip = stun_text;
    }
    snprintf(t->mapped_text[family], OP_ADDR_TEXT, "%s", mapped_ip);
    char note[176];
    snprintf(note, sizeof(note),
             "no gateway mapping probe; answering with the business port %u (no translation)",
             (unsigned)t->local_port);
    emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, note);
    probe_complete(c, index);
    return 1;
}

static int start_probe(fastp2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    probe_socket_close(t);
    for (int i = 0; i < OP_FAM_COUNT; ++i) {
        t->probes[i] = (nat_probe){.fd = -1};
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
         * back to IPv4 when only IPv4 is in common 鈥?the old behaviour. */
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
        if ((t->ipv4_only && family != OP_FAM_V4) || !family_wanted(c, family) || !gateway_has(c, family))
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
        op_addr_set_port(&peer, UDP_MAPPING_PROBE_PORT);
        if (t->transport == FASTP2P_TRANSPORT_QUIC) {
            t->probes[family].state = PROBE_UDP;
            if (udp_packet(fd, &peer, 2, 0, NULL)) {
                op_close(fd);
                t->probes[family].fd = -1;
                t->probes[family].state = PROBE_FREE;
                continue;
            }
            if (family == OP_FAM_V4 && !t->relay_wait && sym_window_kind(c->nat[family].type)) {
                t->probes[family].sample_udp_ports = 1;
                for (uint16_t i = 1; i < UDP_MAPPING_SAMPLES; ++i) {
                    op_addr_set_port(&peer, (uint16_t)(UDP_MAPPING_PROBE_PORT + i));
                    udp_packet(fd, &peer, 2, 0, NULL);
                }
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
    if (!started) {
        if (probe_fallback_mapping(c, index))
            return 0;
        return -1;
    }
    t->state = T_PROBE;
    return 0;
}
static void read_udp_mapping(fastp2p_client *c, nat_probe *p, int family, uint64_t now) {
    int count = p->sample_udp_ports ? UDP_MAPPING_SAMPLES : 1;
    for (int i = 0; i < count; ++i) {
        uint8_t data[1024];
        op_addr from = {0};
        from.len = (op_socklen)sizeof(from.u.storage);
        op_ssize n = op_recvfrom(p->fd, data, sizeof(data), MSG_DONTWAIT, &from.u.sa, &from.len);
        if (n < 0)
            break;
        int slot = (int)op_addr_port(&from) - UDP_MAPPING_PROBE_PORT;
        if (n < 8 || slot < 0 || slot >= count || p->udp_ports[slot] ||
            op_u16(data + 4) != 2 || op_u16(data + 6) != 0 ||
            op_u32(data) != (uint32_t)(n - 8) || !op_addr_equal(&from, &c->gateway_addr[family]))
            continue;
        json_object *j = op_json(data + 8, (size_t)n - 8);
        uint64_t port = op_integer(j, "port");
        op_addr mapped;
        if (port && port <= UINT16_MAX &&
            !op_addr_from_text(&mapped, op_string(j, "IP"), (uint16_t)port) &&
            op_addr_family(&mapped) == op_index_family(family)) {
            p->udp_ports[slot] = (uint16_t)port;
            if (family == OP_FAM_V4)
                p->udp_ips[slot] = mapped.u.in.sin_addr.s_addr;
            if (!slot) {
                p->mapped_port = (uint16_t)port;
                op_addr_text(&mapped, p->mapped_ip, sizeof(p->mapped_ip));
                p->last_rx = now;
            }
        }
        if (j)
            json_object_put(j);
    }
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
        uint64_t probe_deadline = family == required ? t->deadline : p->deadline;
        if (now > probe_deadline) {
            if (family == required) {
                if (probe_fallback_mapping(c, index))
                    return 1;
                close_tunnel(c, index, "peer NAT mapping discovery timed out");
                return -1;
            }
            probe_close(p);
            p->fd = -1;
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
                probe_close(p);
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
                    probe_close(p);
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
                probe_close(p);
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
                    probe_close(p);
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
            read_udp_mapping(c, p, family, now);
            if (p->mapped_port &&
                (!p->sample_udp_ports || (p->udp_ports[1] && p->udp_ports[2] && p->udp_ports[3]) ||
                 now - p->last_rx >= UDP_MAPPING_SAMPLE_WAIT ||
                 now + UDP_MAPPING_SAMPLE_WAIT >= probe_deadline)) {
                p->state = PROBE_DONE;
                ++answered;
                --pending;
            }
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
    if (adopt == OP_FAM_V4 && !t->lan && !t->relay_wait && t->tcp_punch_immediate &&
        (t->initiator || t->peer_tcp_mapping) && (c->gateway_tcp_probe_v2 || c->gateway_tcp_probe_v3)) {
        op_addr source, mapped, bind_address;
        if (!op_addr_socketname(t->probes[adopt].fd, &source) &&
            !op_addr_from_text(&bind_address, source_text(c, adopt), 0) &&
            op_addr_equal(&source, &bind_address) &&
            !op_addr_from_text(&mapped, t->mapped_ip, t->mapped_port))
            t->tcp_sample = fp_tcp_punch_sample_start(&c->tcp_nat.family[adopt], &source, &mapped);
        if (t->tcp_sample) {
            t->state = T_TCP_SAMPLE;
            t->deadline = now + 2 * NS;
            return 0;
        }
    }
    probe_complete(c, index);
    return 1;
}
static uint16_t tcp_predict_next_port(unsigned mapping, uint16_t last_port) {
    if (mapping == FP_TCP_MAP_INCREMENT && last_port && last_port < UINT16_MAX)
        return (uint16_t)(last_port + 1);
    if (mapping == FP_TCP_MAP_DECREMENT && last_port > 1)
        return (uint16_t)(last_port - 1);
    return 0;
}
static void learn_tcp_mapping(tunnel *t, json_object *j) {
    uint64_t mapping = op_integer(j, "tcpPunchMap");
    uint64_t port = op_integer(j, "tcpPunchLastPort");
    if (t->tcp_punch_immediate && mapping >= FP_TCP_MAP_STABLE && mapping <= FP_TCP_MAP_DECREMENT &&
        port > 0 && port <= 65535) {
        t->peer_tcp_mapping = (unsigned)mapping;
        t->peer_tcp_last_port = (uint16_t)port;
        t->peer_tcp_pair = op_integer(j, "tcpPunchPair") == 1;
    }
}
/* Offer the peer a window to spray when our own mapping shifts per destination.
 * Both roles publish it: the responder used to be the only one, which left a
 * symmetric peer that happened to open the connection with no window at all and
 * therefore no way to be reached. A cone mapping publishes nothing, because the
 * port it already published is the port it will answer on. */
static int announce_sym_window(fastp2p_client *c, tunnel *t, json_object *j, int family) {
    if (t->transport != FASTP2P_TRANSPORT_QUIC || t->lan || t->relay_wait || !t->mapped_port)
        return 0;
    int index = family >= 0 && family < OP_FAM_COUNT ? family : OP_FAM_V4;
    int kind = sym_window_kind(c->nat[index].type);
    if (!kind)
        return 0;
    uint16_t alternate = index == OP_FAM_V4 ? udp_alternate_mapping(&t->probes[index]) : 0;
    if (alternate) {
        kind = 2;
        op_ju(j, "symAltBase", alternate);
    }
    op_ju(j, "symBase", t->mapped_port);
    if (kind == 1) {
        op_ju(j, "symCount", SYM_WINDOW_MAX);
        op_ju(j, "symUp", c->nat[index].type == NAT_EASY_SYM_INC ? 1 : 0);
    } else {
        /* No direction and no step to rely on: centre the window instead. */
        op_ju(j, "symCount", SYM_WINDOW_HARD);
        op_ju(j, "symUp", 1);
        op_ju(j, "symSplit", 1);
    }
    return kind;
}
/* Only peers that exchanged compatible IPv4 windows use the ordered punch.
 * The less predictable side receives. With two predictable sides, the node
 * answering the control-plane request receives. Both derive the same roles. */
static int ordered_udp_role(const fastp2p_client *c, const tunnel *t) {
    if (t->lan || t->relay_wait || t->udp_direct_port || strcmp(t->mode, "udppunch") ||
        t->family != OP_FAM_V4 || choose_punch_family(c, t) != OP_FAM_V4)
        return UDP_PUNCH_LEGACY;
    if (t->udp_dual_punch) {
        /* The cone must open its address/port filter before the symmetric
         * side creates its mapping to the cone's stable public endpoint. */
        if (t->sym_alt_base && t->sym_base == t->remote_ports[OP_FAM_V4] &&
            c->nat[OP_FAM_V4].type == NAT_CONE)
            return UDP_PUNCH_RECEIVE;
        if (t->udp_punch_kind == 2 && t->udp_peer_cone && !t->sym_count &&
            udp_alternate_mapping(&t->probes[OP_FAM_V4]))
            return UDP_PUNCH_SEND;
    }
    if (!t->udp_punch_order || !t->udp_punch_kind || !t->sym_count ||
        t->sym_base != t->remote_ports[OP_FAM_V4] || (t->udp_punch_kind == 2 && t->sym_split))
        return UDP_PUNCH_LEGACY;
    int receiver = t->udp_punch_kind == 2 || (!t->sym_split && !t->initiator);
    return receiver ? UDP_PUNCH_RECEIVE : UDP_PUNCH_SEND;
}

/* The allocated port is valid on the router's WAN address. An outer NAT
 * can expose a different address and may not forward that port. */
static uint16_t public_mapping_port(const char *observed_ip, uint16_t port, uint32_t wan) {
    op_addr probe;
    if (!port || !wan || op_addr_from_text(&probe, observed_ip, 0) ||
        public_ipv4(&probe) != ntohl(wan))
        return 0;
    return port;
}

static void report_port_mapping(const fastp2p_client *c, json_object *j) {
    const char *ip = c->ip[OP_FAM_V4];
    uint16_t tcp = public_mapping_port(ip, c->mapped_listener.tcp, c->mapped_listener.tcp_wan);
    uint16_t udp = public_mapping_port(ip, c->mapped_listener.udp, c->mapped_listener.udp_wan);
    op_js(j, "mappedIPv4", tcp || udp ? ip : "");
    op_ju(j, "mappedTCPPort", tcp);
    op_ju(j, "mappedUDPPort", udp);
}

/* Advertise the shared listener only when the IPv6 probe retained its
 * interface address and port. A translated IPv6 mapping would not establish
 * whether the listener is reachable at the same port. */
static uint16_t ipv6_udp_listener_port(const fastp2p_client *c, const tunnel *t) {
    op_addr mapped, local;
    if (c->udp_listener[OP_FAM_V6] < 0 || !t->mapped_ports[OP_FAM_V6] ||
        t->mapped_ports[OP_FAM_V6] != t->probes[OP_FAM_V6].local_port ||
        op_addr_from_text(&mapped, t->mapped_text[OP_FAM_V6], 0) ||
        op_addr_family(&mapped) != AF_INET6 ||
        op_addr_from_text(&local, c->local_ip[OP_FAM_V6], 0) ||
        !op_addr_routable(&mapped) || !op_addr_equal(&mapped, &local))
        return 0;
    return c->public_port;
}

static void probe_complete(fastp2p_client *c, int index) {
    tunnel *t = &c->tunnels[index];
    /* Listen on the port this client is about to advertise. The TCP punch used to
     * create the listener lazily, only after a dial failed, so for a short window
     * the published endpoint - exactly what a LAN peer dials - had nothing behind
     * it, and the two ends ended up chasing different ports. */
    if (!strcmp(t->mode, "tcppunch") && tcp_punch_listen(c, index))
        return;
    json_object *j = json_object_new_object();
    op_js(j, "from", c->node);
    /* On a LAN punch the peers exchange private addresses and local ports; the
     * gateway-observed address is only meaningful when a NAT is in between.
     * fromIP/coneNatPort stay strictly the IPv4 observation (SPEC 搂5): an old
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
    if (t->tcp_punch_immediate) op_ju(j, "tcpPunchImmediate", 1);
    if (t->tcp_mapping) {
        op_ju(j, "tcpPunchMap", t->tcp_mapping);
        op_ju(j, "tcpPunchLastPort", t->tcp_last_port);
        if (tcp_predict_next_port(t->tcp_mapping, t->tcp_last_port))
            op_ju(j, "tcpPunchPair", 1);
    }
    /* Each family publishes independently: only the pair that was actually
     * measured is written, so a v6 LAN port can never ride in the v4 fields an
     * old peer reads (SPEC 搂5). */
    /* A host whose mapping is its own address has no translation, so the business
     * port *is* the public port. Publishing 0 there - which is what happens when
     * the gateway mapping probe is unreachable - leaves the peer with no port to
     * dial, so it punches blindly and ends up on the relay. */
    int no_translation = nat_filter_level(&c->udp_filter, mono()) >= 6;
    op_ju(j, "coneNatPort", t->mapped_ports[OP_FAM_V4]
                              ? t->mapped_ports[OP_FAM_V4]
                              : (no_translation ? c->public_port : 0));
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
    t->udp_punch_kind = announce_sym_window(c, t, j, t->family);
    if (t->initiator) {
        op_js(j, "linkMode", t->mode);
        /* Peers that understand the shared listener advertise its port in
         * their reply. Other peers proceed with the existing punch. */
        if (t->tcp_punch_immediate && c->public_port)
            op_ju(j, "tcpDirect", 1);
        if (t->transport == FASTP2P_TRANSPORT_QUIC && !t->skip_udp_direct &&
            !t->relay_wait && has_udp_listener(c)) {
            op_ju(j, "udpDirect", 1);
            if (!t->lan && !strcmp(t->mode, "udppunch")) {
                t->udp_reverse_port = public_mapping_port(t->mapped_text[OP_FAM_V4],
                                                          c->mapped_listener.udp, c->mapped_listener.udp_wan);
                t->udp_reverse_port6 = ipv6_udp_listener_port(c, t);
            }
            if (t->udp_reverse_port)
                op_ju(j, "udpReversePort", t->udp_reverse_port);
            if (t->udp_reverse_port6) {
                op_ju(j, "udpReversePort6", t->udp_reverse_port6);
                if (t->udp_reverse6_retry)
                    op_ju(j, "udpReverse6", 1);
            }
        }
        op_ju(j, "isServer", 1);
        op_ju(j, "lan", t->lan ? 1 : 0);
        op_js(j, "underlayProtocol", t->transport == FASTP2P_TRANSPORT_QUIC ? "quic" : "tcp");
        t->udp_punch_order = t->udp_punch_kind && t->family == OP_FAM_V4 &&
                             !strcmp(t->mode, "udppunch");
        if (t->udp_punch_order)
            op_ju(j, "udpPunchOrder", 1);
        if (t->transport == FASTP2P_TRANSPORT_QUIC && !t->lan && !t->relay_wait &&
            t->mapped_ports[OP_FAM_V4] && !strcmp(t->mode, "udppunch"))
            op_ju(j, "udpPunchDual", 1);
        push(c, t->peer, PUSH_CONNECT, j);
        {
            /* Prove the offer left this host: without it a silent T_REPLY timeout
             * cannot be told apart from a push the gateway never delivered. */
            char sent[180];
            snprintf(sent, sizeof(sent), "connect request sent to %s (mode %s, family %d, tunnel %llu)",
                     t->peer, t->mode, t->family, (unsigned long long)t->id);
            emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, sent);
        }
        t->state = T_REPLY;
        t->deadline = mono() + 12 * NS;
    } else {
        uint64_t ts = (uint64_t)((int64_t)wall() - c->clock_delta) + 3 * NS;
        op_js(j, "to", t->peer);
        op_ju(j, "punchts", ts);
        uint16_t reverse_port = 0;
        int family = choose_punch_family(c, t);
        {
            /* Which family the responder picked and why: a host whose own v6 mapping
             * was never measured must not answer on a v6 endpoint the peer cannot
             * reach, and without these numbers the choice is invisible. */
            char pick[240];
            snprintf(pick, sizeof(pick),
                     "punch family %d (v4 usable=%d mapped=%u/%s, v6 usable=%d mapped=%u/%s, ipv4_only=%d, reverse6=%u)",
                     family, family_usable(c, t, OP_FAM_V4), (unsigned)t->mapped_ports[OP_FAM_V4],
                     t->mapped_text[OP_FAM_V4], family_usable(c, t, OP_FAM_V6),
                     (unsigned)t->mapped_ports[OP_FAM_V6], t->mapped_text[OP_FAM_V6], t->ipv4_only,
                     (unsigned)t->udp_reverse_port6);
            emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, pick);
        }
        if (!t->lan && family == OP_FAM_V4) {
            const char *ip = t->mapped_text[OP_FAM_V4];
            uint16_t mapped_tcp = public_mapping_port(ip, c->mapped_listener.tcp, c->mapped_listener.tcp_wan);
            if (t->tcp_direct_port && mapped_tcp)
                t->tcp_direct_port = mapped_tcp;
            else if (t->tcp_direct_port && (t->lan || peer_is_local(&t->peer_addr)))
                /* A peer on the same host or LAN reaches the listener this client
                 * keeps for it, so that port is the one to publish. Swapping in the
                 * probe mapping here is what stopped the two local test clients from
                 * ever finding each other. */
                t->tcp_direct_port = c->public_port;
            else if (t->tcp_direct_port && t->mapped_port)
                /* Without UPnP the only port the peer can reach is the one the
                 * carrier NAT actually allocated: a CGNAT rewrites the source
                 * port, so advertising the local listener port gives the peer a
                 * port that was never open. t->mapped_port is what the gateway's
                 * probe observed for the very socket this punch will use. */
                t->tcp_direct_port = t->mapped_port;
            uint16_t mapped_udp = public_mapping_port(ip, c->mapped_listener.udp, c->mapped_listener.udp_wan);
            if (t->udp_direct_port && mapped_udp) {
                t->udp_direct_port = mapped_udp;
            } else {
                reverse_port = t->udp_reverse_port;
            }
        } else if (!t->lan && family == OP_FAM_V6 && t->udp_reverse_port6) {
            op_ju(j, "udpReverse6Cap", 1);
            if (t->udp_reverse6_retry || !t->udp_direct_port || c->udp_listener[OP_FAM_V6] < 0)
                reverse_port = t->udp_reverse_port6;
        }
        if (reverse_port) {
            t->server = 0;
            t->udp_direct_port = reverse_port;
            op_ju(j, family == OP_FAM_V6 ? "udpReverse6" : "udpReverse", 1);
            emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, family == OP_FAM_V6
                ? "Dialing the initiator's IPv6 UDP listener" : "Dialing the initiator's mapped UDP listener");
        }
        if (t->tcp_direct_port)
            op_ju(j, "tcpDirectPort", t->tcp_direct_port);
        if (t->udp_direct_port && !reverse_port)
            op_ju(j, "udpDirectPort", t->udp_direct_port);
        t->udp_punch_role = ordered_udp_role(c, t);
        if (t->udp_punch_role) {
            op_ju(j, "udpPunchOrder", 1);
            if (t->udp_dual_punch)
                op_ju(j, "udpPunchDual", 1);
        }
        push(c, t->peer, 2, j);
        /* Give the initiator a short window to dial the shared listener.
         * Immediate punch resumes after that window, or starts right away
         * when the peer did not request a direct attempt. */
        uint64_t delay = reverse_port ? 100 * MS : t->tcp_direct_port ? TCP_DIRECT_WAIT
                         : t->tcp_punch_immediate || t->udp_punch_role ? 0 : 3 * NS;
        t->at = mono() + delay;
        t->state = t->udp_direct_port && !reverse_port ? T_UDP_DIRECT : T_TIME;
        t->deadline = t->udp_direct_port ? mono() + UDP_DIRECT_WAIT + 2 * NS : t->at + 10 * NS;
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
/* Interleave the walk so the reported port is tried first and the window grows
 * evenly on both sides: 0, +1, -1, +2, -2, ... */
static uint16_t tcp_scan_port(uint16_t base, int step) {
    int delta = (step + 1) / 2;
    if (step > 0 && (step & 1) == 0)
        delta = -delta;
    int port = (int)base + delta;
    if (port < 1)
        port += 65535;
    if (port > 65535)
        port -= 65535;
    return (uint16_t)port;
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
    /* Keep dialling for the whole window instead of giving up after one attempt.
     * Simultaneous open needs both sides in SYN_SENT at the same moment: a
     * refused dial comes back in a few milliseconds, so a retry is nearly free,
     * while switching to listen-only throws away the mapping that lets the peer
     * in. Measured across two carrier NATs: one side crossed on its first try,
     * the other needed ten. */
    unsigned limit = TCP_PUNCH_ATTEMPTS_RESPONDER;
    if (t->tcp_scan < TCP_PUNCH_SCAN)
        ++t->tcp_scan;
    if (t->tcp_attempts >= limit) {
        t->tcp_retry_at = 0;
        (void)tcp_punch_listen(c, index);
    } else t->tcp_retry_at = now + (TCP_PUNCH_RETRY_MS + random_id() % TCP_PUNCH_RETRY_JITTER_MS) * MS;
}

static void tcp_punch_dial(fastp2p_client *c, int index, uint64_t now) {
    tunnel *t = &c->tunnels[index];
    if (!t->peer_addr.len) {
        close_tunnel(c, index, "invalid TCP punch peer address");
        return;
    }
    /* A peer may publish an address that is ours (both nodes can egress the same
     * carrier NAT). Dialling it reaches our own NAT, which has no hairpin, so swap in
     * the address the gateway observed and, while that answer is still missing, skip
     * the round instead of burning the budget on ourselves. */
    {
        int index_family = t->family >= 0 ? t->family : OP_FAM_V4;
        char substitute[OP_ADDR_TEXT];
        const char *chosen = punch_peer_text(c, t->peer, t->peer_text[index_family], substitute,
                                             sizeof(substitute));
        if (chosen && strcmp(chosen, t->peer_text[index_family]) &&
            !op_addr_from_text(&t->peer_addr, chosen, t->remote_ports[index_family]))
            snprintf(t->peer_text[index_family], OP_ADDR_TEXT, "%s", chosen);
        else if (c->ip[OP_FAM_V4][0] && !strcmp(t->peer_text[index_family], c->ip[OP_FAM_V4])) {
            /* Ask the gateway who the peer really is, then retry. */
            json_object *ask = json_object_new_object();
            op_js(ask, "peerNode", t->peer);
            ws_json(c, 7, 0, ask);
            json_object_put(ask);
            t->tcp_retry_at = now + 300 * MS;
            return;
        }
    }
    ++t->tcp_attempts;
    t->tcp_retry_at = 0;
    /* Walk a small window around the port the peer reported: the mapping a carrier
     * NAT allocates for *this* destination is close to, but not necessarily equal
     * to, the port it observed towards another one. Attempt zero keeps the reported
     * port, so a pair that works today is unaffected. */
    {
        int walk_family = t->family >= 0 ? t->family : OP_FAM_V4;
        uint16_t reported = t->remote_ports[walk_family];
        if (reported && t->tcp_scan)
            op_addr_set_port(&t->peer_addr, tcp_scan_port(reported, t->tcp_scan));
    }
    /* A refused dial returns at once, but a silently dropped one would spend the
     * whole window on a single attempt. Bound it so the retry budget survives. */
    t->tcp_attempt_deadline = now + TCP_PUNCH_ATTEMPT_MS * MS;
    /* The v1 punch has no initiator role to answer with: both ends keep their
     * listener and both dial, so the port must not be taken away from them. */
    if (!t->tcp_v2) {
        /* Historical scheme, unchanged. */
    } else if (!t->initiator && peer_is_local(&t->peer_addr)) {
        /* The v2 punch does have one. A peer on the same host or LAN is reached by
         * dialling our listener, so the responder parks there and lets the
         * initiator's connection arrive instead of fighting it for the port. */
        if (t->fd >= 0) {
            op_close(t->fd);
            t->fd = -1;
        }
        if (t->listen_fd < 0 && tcp_punch_listen(c, index)) {
            close_tunnel(c, index, "TCP punch listener failed");
            return;
        }
        t->tcp_attempts = TCP_PUNCH_ATTEMPTS_RESPONDER;
        t->tcp_retry_at = 0;
        return;
    }
    /* Everything else dials, and on v2 the dial has to own the port: a carrier NAT
     * only admits the answer while a mapping is alive, and nothing stays mapped for
     * a port this process is not sending from. The listener and any earlier attempt
     * socket are closed for that, which is also why the "unknown" bind failures
     * disappeared once the port was released here. */
    if (t->tcp_v2 && t->listen_fd >= 0) {
        op_close(t->listen_fd);
        t->listen_fd = -1;
    }
    if (t->tcp_v2 && t->fd >= 0) {
        op_close(t->fd);
        t->fd = -1;
    }
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
    /* Name the port dialled and the port this side advertises: with a cone mapping
     * the peer can only reach us at the advertised port, so the two have to be the
     * mapping and the local port of the very same socket. */
    snprintf(message, sizeof(message),
             "TCP punch connect attempt %u to %s:%u from %s:%u adv=%u%s", t->tcp_attempts,
             target, (unsigned)op_addr_port(&shown), local, (unsigned)t->local_port,
             (unsigned)t->mapped_port, t->lan ? " (LAN)" : "");
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
static int tcp_mapping_moves(unsigned mapping) {
    return mapping == FP_TCP_MAP_INCREMENT || mapping == FP_TCP_MAP_DECREMENT;
}
static void tcp_candidate_connected(tunnel *t, op_socket fd, uint64_t now) {
    close_tcp_candidates(t);
    op_close(t->listen_fd);
    t->listen_fd = -1;
t->fd = fd;
    t->state = T_HANDSHAKE;
    t->deadline = now + 10 * NS;
    if (!t->server) {
        uint8_t id[8];
        op_put64(id, t->id);
        tframe(t, 2, id, 8);
    }
}
static int tcp_predict_add_candidate(fastp2p_client *c, tunnel *t, uint16_t port) {
    op_socket fd = socket_bound(0, source_text(c, OP_FAM_V4), t->local_port, 1);
    if (fd < 0)
        return -1;
    op_addr candidate = t->peer_addr;
    op_addr_set_port(&candidate, port);
    if (op_connect(fd, &candidate.u.sa, candidate.len) && errno != EINPROGRESS) {
        op_close(fd);
        return 0;
    }
    unsigned slot = t->tcp_candidate_count++;
    t->tcp_candidates[slot] = fd;
    t->tcp_candidate_ports[slot] = port;
    return 1;
}
static int tcp_send_prediction_ready(fastp2p_client *c, const tunnel *t) {
    json_object *j = json_object_new_object();
    op_ju(j, "id", t->id);
    op_ju(j, "tcpPredictReady", 1);
    int rv = push(c, t->peer, PUSH_READY, j);
    json_object_put(j);
    return rv;
}
static void tcp_predict_open(fastp2p_client *c, tunnel *t, uint64_t now) {
    int direction = t->peer_tcp_mapping == FP_TCP_MAP_INCREMENT ? 1 : -1;
    /* Some destination-dependent NATs still reuse the observed port for a
     * particular peer. Open that tuple alongside the predicted ones. */
    for (int i = 0; i <= TCP_PREDICT_PORTS; ++i) {
        int port = i ? t->peer_tcp_last_port + direction * i : t->remote_port;
        if (port <= 0 || port > 65535)
            break;
        if (i && port == t->remote_port)
            continue;
        if (tcp_predict_add_candidate(c, t, (uint16_t)port) < 0)
            break;
    }
    if (!t->tcp_candidate_count) {
        t->tcp_predict_wait = now;
        return;
    }
    /* Keep the SYN-SENT sockets for simultaneous open. The existing listener
     * also covers candidates whose connection attempt has already ended. */
    tcp_send_prediction_ready(c, t);
    t->tcp_predict_until = now + 4 * NS;
    emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, "TCP NAT prediction opened a bounded port window");
}
static void tcp_predict_pair(fastp2p_client *c, tunnel *t, uint64_t now) {
    if (!t->tcp_predict_ready_sent) {
        if (tcp_send_prediction_ready(c, t)) {
            t->tcp_predict_wait = now;
            return;
        }
        t->tcp_predict_ready_sent = 1;
    }
    if (!t->tcp_predict_ready)
        return;
    /* A second destination could consume our next translated port. Each
     * side therefore sends a SYN to exactly one peer endpoint per round. */
    uint16_t port = tcp_predict_next_port(t->peer_tcp_mapping, t->peer_tcp_last_port);
    if (tcp_predict_add_candidate(c, t, port) <= 0) {
        t->tcp_predict_wait = now;
        return;
    }
    t->tcp_predict_until = now + 4 * NS;
    emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, "TCP NAT prediction dialing a single endpoint for simultaneous open");
}
static void tcp_predict_tick(fastp2p_client *c, int index, uint64_t now) {
    tunnel *t = &c->tunnels[index];
    if (!t->tcp_candidate_count && t->tcp_peer_ip_verified && now < t->tcp_predict_wait) {
        if (t->tcp_predict_role == TCP_PREDICT_OPEN)
            tcp_predict_open(c, t, now);
        else if (t->tcp_predict_role == TCP_PREDICT_PAIR)
            tcp_predict_pair(c, t, now);
    }
    if (t->tcp_candidate_count) {
        for (unsigned i = 0; i < t->tcp_candidate_count; ++i) {
            op_socket fd = t->tcp_candidates[i];
            if (fd < 0)
                continue;
            int ready = connect_ready(fd);
            if (ready)
                t->tcp_candidates[i] = -1;
            if (ready > 0) {
                tcp_candidate_connected(t, fd, now);
                return;
            }
            if (ready < 0)
                op_close(fd);
        }
        return;
    }
    if (t->tcp_predict_role == TCP_PREDICT_DIAL && t->tcp_predict_ready) {
        t->tcp_predict_role = TCP_PREDICT_NONE;
        t->tcp_predict_until = now + 4 * NS;
        emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, "TCP NAT prediction peer ready; dialing from sampled port");
        tcp_punch_dial(c, index, now);
        return;
    }
    if (now >= t->tcp_predict_wait) {
        t->tcp_predict_role = TCP_PREDICT_NONE;
        tcp_punch_dial(c, index, now);
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
        /* Long enough for the port walk to cover its window: a refused dial costs
         * a few milliseconds, so the budget is spent on breadth, not on waiting. */
        t->deadline = now + 30 * NS;
        uint16_t direct_port = t->tcp_direct_port;
        t->tcp_direct_port = 0;
        if (t->initiator && direct_port) {
            op_addr endpoint = t->peer_addr;
            op_addr_set_port(&endpoint, direct_port);
            int family = op_family_index(op_addr_family(&endpoint));
            t->fd = socket_bound(0, source_text(c, family), 0, BIND_DEFAULT);
            if (t->fd >= 0) {
                if (!op_connect(t->fd, &endpoint.u.sa, endpoint.len) || errno == EINPROGRESS) {
                    t->state = T_TCP_DIRECT_CONNECT;
                    t->tcp_attempt_deadline = now + TCP_DIRECT_WAIT;
                    return;
                }
                op_close(t->fd);
                t->fd = -1;
            }
        }
        t->state = T_TCP_CONNECT;
        if (t->family == OP_FAM_V4) {
            if (t->tcp_mapping == FP_TCP_MAP_STABLE && tcp_mapping_moves(t->peer_tcp_mapping))
                t->tcp_predict_role = TCP_PREDICT_OPEN;
            else if (tcp_mapping_moves(t->tcp_mapping) && t->peer_tcp_mapping == FP_TCP_MAP_STABLE)
                t->tcp_predict_role = TCP_PREDICT_DIAL;
            else if (t->peer_tcp_pair && tcp_predict_next_port(t->tcp_mapping, t->tcp_last_port) &&
                     tcp_predict_next_port(t->peer_tcp_mapping, t->peer_tcp_last_port))
                t->tcp_predict_role = TCP_PREDICT_PAIR;
        }
        if (t->tcp_predict_role) {
            t->tcp_predict_wait = now + (t->tcp_predict_role == TCP_PREDICT_OPEN ? 1 : 2) * NS;
            if (t->tcp_predict_role != TCP_PREDICT_DIAL) {
                /* Verify the destination IPv4 independently of peer input. */
                json_object *j = json_object_new_object();
                op_js(j, "peerNode", t->peer);
                ws_json(c, 7, 0, j);
                json_object_put(j);
            }
            return;
        }
        tcp_punch_dial(c, index, now);
        return;
    }
    if (t->transport == FASTP2P_TRANSPORT_QUIC) {
        if (!t->server && !t->notified) {
            t->state = T_UNDERLAY;
            return;
        }
        t->quic = opq_new(t->fd, &t->peer_addr.u.sa, t->peer_addr.len, t->server, c->tls_host);
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
            const char *message = a->sdwan
                ? (relayed ? "SD-WAN peer attached to relay" : "SD-WAN peer attached to direct tunnel")
                : (relayed ? "forward attached to relay" : "forward attached to tunnel");
            emit(c, FASTP2P_EVENT_FORWARD, a->id, 0, message);
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
    t->skip_udp_direct = a->udp_direct_tried;
    t->udp_reverse6_retry = a->udp_reverse6_retry;
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
    t->tcp_punch_immediate = t->tcp_v2;
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
    /* Never cleared: active_at is reset once the link proves stable, and the
     * idle refresh needs the tunnel's real age. */
    t->active_since = mono();
    t->last_session_push = mono();
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
    c->tunnels[o->tunnel_index].last_payload = mono();
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
    uint8_t reply[OP_SOCKS_MAX_REPLY];
    size_t length = op_socks_reply(reply, status, NULL);
    if (op_buffer_add(&o->tx, reply, length, OP_QUEUE_LIMIT)) {
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
    if (!op_get(ack, "reply") || status > 8 || port > UINT16_MAX) {
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
        if (op_addr_from_text(&remote, op_string(ack, "remoteIP"), o->socks.port))
            close_overlay(c, oi, 1);
        else
            op_addr_copy(&o->socks_peer, &remote);
        return;
    }
    op_addr address;
    if (op_addr_from_text(&address, op_string(ack, "boundIP"), (uint16_t)port)) {
        socks_failure(c, oi, 1);
        return;
    }
    uint8_t reply[OP_SOCKS_MAX_REPLY];
    size_t length = op_socks_reply(reply, 0, &address);
    if (op_buffer_add(&o->tx, reply, length, OP_QUEUE_LIMIT)) {
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
    if (!parent || o->waiting || len > 4096 || !parent->socks_peer.len || !o->socks_peer.len)
        return;
    uint8_t packet[4096 + OP_SOCKS_MAX_REPLY];
    size_t header = op_socks_reply(packet, 0, &o->socks_peer);
    packet[0] = 0;
    memcpy(packet + header, data, len);
    op_sendto(parent->socks_udp, packet, len + header, MSG_DONTWAIT, &parent->socks_peer.u.sa,
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
            uint8_t reply[OP_SOCKS_MAX_REPLY];
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
            /* The association accepts only datagrams from the TCP peer.
             * An unspecified request leaves its UDP endpoint to be learned. */
            if (op_addr_from_text(&requested, o->socks.host, 0) ||
                (!op_addr_equal(&requested, &o->source) &&
                 strcmp(o->socks.host, "0.0.0.0") && strcmp(o->socks.host, "::"))) {
                socks_failure(c, i, 2);
                break;
            }
            op_addr local;
            memset(&local, 0, sizeof(local));
            if (op_addr_socketname(o->fd, &local)) {
                socks_failure(c, i, 1);
                break;
            }
            o->socks_udp = socket_bound_addr(1, &local, 0, 0);
            if (o->socks_udp < 0) {
                socks_failure(c, i, 1);
                break;
            }
            op_addr_copy(&o->socks_peer, &o->source);
            op_addr_set_port(&o->socks_peer, o->socks.port);
            op_addr_set_port(&local, socket_port(o->socks_udp));
            length = op_socks_reply(reply, 0, &local);
            if (op_buffer_add(&o->tx, reply, length, OP_QUEUE_LIMIT)) {
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
        if (!a->used || !a->local || a->sdwan)
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
        const tunnel *link = a->tunnel_index >= 0 ? &c->tunnels[a->tunnel_index] : NULL;
        int ready = a->synced && link && tunnel_ready(link);
        op_ju(j, "isActive", ready);
        op_ju(j, "linkReady", ready);
        if (ready)
            op_js(j, "linkMode", link->relay_wait ? "relay" : link->mode);
        json_object_array_add(list, j);
    }
    json_object_object_add(root, "Apps", list);
    ws_json(c, 6, 3, root);
    json_object_put(root);
}
static void report_sdwan(fastp2p_client *c, uint64_t now) {
    fp_sdwan *state = c->sdwan;
    if (!fp_sdwan_active(state) || c->state != FASTP2P_ONLINE || now < c->sdwan_report_at)
        return;
    c->sdwan_report_at = now + 5 * NS;
    json_object *root = json_object_new_object(), *links = json_object_new_array();
    op_js(root, "mode", state->central ? "central" : "mesh");
    if (state->central)
        op_js(root, "center", state->center);
    json_object_object_add(root, "links", links);
    for (unsigned i = 0; i < state->peer_count; ++i) {
        int index = state->peers[i].app_index;
        if (index < 0)
            continue;
        const app *a = &c->apps[index];
        const tunnel *t = a->tunnel_index >= 0 ? &c->tunnels[a->tunnel_index] : NULL;
        json_object *link = json_object_new_object();
        op_js(link, "peer", a->peer);
        if (a->synced && t && tunnel_ready(t)) {
            op_js(link, "state", t->relay_wait ? "relay" : "direct");
            if (t->relay_wait)
                op_js(link, "relay", t->peer);
            else if (t->family >= 0)
                op_ju(link, "family", t->family == OP_FAM_V6 ? 6 : 4);
        } else
            op_js(link, "state", "connecting");
        json_object_array_add(links, link);
    }
    ws_json(c, 6, 11, root);
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
    const char *bind_ip = op_string(j, "whitelist");
    json_object *bind_field;
    op_addr bind_address;
    if (json_object_object_get_ex(j, "whitelist", &bind_field) &&
        (!json_object_is_type(bind_field, json_type_string) ||
         strlen(bind_ip) != (size_t)json_object_get_string_len(bind_field) ||
         (*bind_ip && op_addr_from_text(&bind_address, bind_ip, 0)))) {
        emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EINVAL, "invalid forwarding listen address");
        return;
    }
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
            fastp2p_socks5 proxy = {.struct_size = sizeof(proxy),
                                   .name = op_string(j, "appName"),
                                   .bind_ip = *bind_ip ? bind_ip : NULL,
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
                    int no_relay = op_flag(j, "NoRelay") || op_flag(j, "noRelay");
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
                              .bind_ip = *bind_ip ? bind_ip : NULL,
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

static void rename_peer(fastp2p_client *c, const char *old_name, const char *name) {
    if (!valid_node(old_name) || !valid_node(name) || !strcmp(old_name, name))
        return;
    for (int i = 0; i < NT; ++i) {
        tunnel *t = &c->tunnels[i];
        if (t->state && (!strcmp(t->peer, old_name) || !strcmp(t->relay_peer, old_name)))
            close_tunnel(c, i, NULL);
    }
    for (int i = 0; i < NA; ++i) {
        app *a = &c->apps[i];
        if (!a->used || !a->local)
            continue;
        int peer = !strcmp(a->peer, old_name);
        int relay = !strcmp(a->relay_node, old_name);
        if (peer)
            strcpy(a->peer, name);
        if (relay)
            strcpy(a->relay_node, name);
        if (peer || relay) {
            a->attempts = 0;
            a->lan_tried = 0;
            a->udp_direct_tried = 0;
            a->udp_reverse6_retry = 0;
            a->ipv4_retry = 0;
            a->relay_requested = 0;
            a->relay_failed_count = 0;
            a->retry = 0;
        }
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
        if (main == 3 && sub == PUSH_CONNECT) {
            /* The receiving side of the same offer: its presence or absence decides
             * whether the gateway delivered the push or the peer ignored it. */
            char got[180];
            snprintf(got, sizeof(got), "connect request received from id %llu (%u bytes)",
                     (unsigned long long)sender, (unsigned)len);
            emit(c, FASTP2P_EVENT_TUNNEL, 0, 0, got);
        }
    }
    if (main == 3 && sub == PUSH_READY) {
        json_object *ready = op_json(data, len);
        int prediction = op_integer(ready, "tcpPredictReady") == 1;
        int udp_prepared = op_integer(ready, "udpPunchReady") == 1;
        if (prediction || udp_prepared) {
            int ti = tunnel_by_id(c, op_integer(ready, "id"));
            if (ti >= 0 && c->tunnels[ti].peer_id == sender) {
                tunnel *t = &c->tunnels[ti];
                if (prediction && (t->state == T_TIME || t->state == T_TCP_CONNECT))
                    t->tcp_predict_ready = 1;
                if (udp_prepared && t->udp_punch_role == UDP_PUNCH_SEND &&
                    (t->state == T_TIME || t->state == T_PUNCH))
                    t->udp_punch_ready = 1;
            }
        }
        if (ready)
            json_object_put(ready);
        if (prediction || udp_prepared)
            return;
        for (int i = 0; i < NT; ++i)
            if (c->tunnels[i].state && c->tunnels[i].peer_id == sender)
                c->tunnels[i].notified = 1;
        return;
    }
    if (main == 3 && sub == 7) {
        report_apps(c);
        return;
    }
    if (main == 3 && sub == 11) {
        if (c->login_ok && c->report_ok && !c->stopping && c->restart_handler) {
            c->in_callback = 1;
            c->restart_handler(c->restart_user);
            c->in_callback = 0;
        }
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
            if (c->automatic_node || op_integer(j, "nodeRename") == 1) {
                const char *assigned = op_string(j, "node");
                if (!valid_node(assigned)) {
                    emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, "gateway returned an invalid node name");
                    c->stopping = 1;
                    json_object_put(j);
                    return;
                }
                if (c->automatic_node || strcmp(c->node, assigned)) {
                    strcpy(c->node, assigned);
                    c->node_id = op_node_id(c->node);
                    char message[64];
                    snprintf(message, sizeof(message), "node name: %s", c->node);
                    emit(c, FASTP2P_EVENT_STATE, c->node_id, 0, message);
                }
            }
            c->login_ok = 1;
            c->gateway_failures = 0;
            c->gateway_tcp_probe_v2 = op_integer(j, "tcpProbeV2") == 1;
            /* SPEC 搂3: only a V3 gateway brackets an IPv6 echo record; without
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
        /* SPEC 搂5: the two families are independent fields. Accept the request
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
                t->tcp_punch_immediate = t->tcp_v2 && op_integer(j, "tcpPunchImmediate") == 1;
                if (t->tcp_punch_immediate && op_integer(j, "tcpDirect") == 1)
                    t->tcp_direct_port = c->public_port;
                if (!strcmp(mode, "udppunch") && op_integer(j, "udpDirect") == 1 && has_udp_listener(c))
                    t->udp_direct_port = c->public_port;
                uint64_t reverse_port = op_integer(j, "udpReversePort");
                if (!strcmp(mode, "udppunch") && op_integer(j, "udpDirect") == 1 &&
                    !op_integer(j, "lan") && v4_ok && reverse_port <= UINT16_MAX &&
                    !op_addr_from_text(&peer_ip, peer_text, 0) && public_ipv4(&peer_ip))
                    t->udp_reverse_port = (uint16_t)reverse_port;
                uint64_t reverse6_port = op_integer(j, "udpReversePort6");
                if (!strcmp(mode, "udppunch") && op_integer(j, "udpDirect") == 1 &&
                    !op_integer(j, "lan") && v6_ok && reverse6_port && reverse6_port <= UINT16_MAX &&
                    !op_addr_from_text(&peer_ip, peer_text6, 0) && op_addr_routable(&peer_ip)) {
                    t->udp_reverse_port6 = (uint16_t)reverse6_port;
                    t->udp_reverse6_retry = op_integer(j, "udpReverse6") == 1;
                }
                t->udp_punch_order = op_integer(j, "udpPunchOrder") == 1;
                t->udp_dual_punch = op_integer(j, "udpPunchDual") == 1;
                t->udp_peer_cone = op_integer(j, "udpNatType") == NAT_CONE;
                learn_tcp_mapping(t, j);
                learn_sym_window(t, j);
                {
                    char punch_text[OP_ADDR_TEXT];
                    if (v4_ok)
                        tunnel_learn_peer(t, punch_peer_text(c, t->peer, peer_text, punch_text,
                                                             sizeof(punch_text)), port);
                    if (v6_ok)
                        tunnel_learn_peer(t, peer_text6, port6);
                }
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
                if (!strcmp(mode, "udp4") && t->server)
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
            int v6_ok = !t->ipv4_only && port6 > 0 && port6 <= 65535 &&
                        !op_addr_from_text(&ip, peer_text6, (uint16_t)port6) &&
                        op_family_index(op_addr_family(&ip)) == OP_FAM_V6;
            if (t->state == T_REPLY && sender == t->peer_id &&
                !strcmp(t->peer, op_string(j, "from")) && !op_integer(j, "error") &&
                (v4_ok || v6_ok)) {
                {
                    char punch_text[OP_ADDR_TEXT];
                    if (v4_ok)
                        tunnel_learn_peer(t, punch_peer_text(c, t->peer, peer_text, punch_text,
                                                             sizeof(punch_text)), port);
                    if (v6_ok)
                        tunnel_learn_peer(t, peer_text6, port6);
                }
                t->tcp_v2 = t->tcp_v2 && op_integer(j, "tcpPunchV2") == 1;
                t->tcp_punch_immediate = t->tcp_v2 && op_integer(j, "tcpPunchImmediate") == 1;
                uint64_t direct_port = op_integer(j, "tcpDirectPort");
                if (t->tcp_punch_immediate && direct_port <= UINT16_MAX)
                    t->tcp_direct_port = (uint16_t)direct_port;
                uint64_t udp_port = op_integer(j, "udpDirectPort");
                if (t->transport == FASTP2P_TRANSPORT_QUIC && !t->skip_udp_direct && !t->relay_wait &&
                    udp_port <= UINT16_MAX)
                    t->udp_direct_port = (uint16_t)udp_port;
                learn_tcp_mapping(t, j);
                learn_sym_window(t, j);
                int family = choose_punch_family(c, t);
                t->udp_reverse6_supported = family == OP_FAM_V6 && t->udp_reverse_port6 &&
                                            op_integer(j, "udpReverse6Cap") == 1;
                uint16_t reverse = 0;
                if (t->udp_reverse6_supported && op_integer(j, "udpReverse6") == 1) {
                    reverse = t->udp_reverse_port6;
                    t->udp_reverse6_retry = 1;
                } else if (family == OP_FAM_V4 && op_integer(j, "udpReverse") == 1) {
                    reverse = t->udp_reverse_port;
                }
                if (reverse) {
                    t->server = 1;
                    t->family = family;
                    t->attempted_ipv6 = family == OP_FAM_V6;
                    t->udp_direct_port = reverse;
                    t->state = T_UDP_DIRECT;
                    t->deadline = mono() + UDP_DIRECT_WAIT + 2 * NS;
                    emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, family == OP_FAM_V6
                        ? "Waiting on the IPv6 UDP listener for reverse dialing"
                        : "Waiting on the mapped UDP listener for reverse dialing");
                    json_object_put(j);
                    return;
                }
                t->udp_dual_punch = op_integer(j, "udpPunchDual") == 1;
                t->udp_peer_cone = op_integer(j, "udpNatType") == NAT_CONE;
                if (op_integer(j, "udpPunchOrder") == 1)
                    t->udp_punch_role = ordered_udp_role(c, t);
                int64_t delay = 0;
                if (!t->tcp_punch_immediate && !t->udp_punch_role) {
                    uint64_t ts = op_integer(j, "punchts"), local = wall();
                    uint64_t difference = ts >= local ? ts - local : local - ts;
                    if (ts > INT64_MAX || local > INT64_MAX || difference > 2 * 86400 * NS) {
                        close_tunnel(c, ti, "peer sent an invalid punch timestamp");
                        json_object_put(j);
                        return;
                    }
                    delay = ((int64_t)ts - (int64_t)local) + c->clock_delta;
                    if (delay < 0)
                        delay = 0;
                    if (delay > (int64_t)(3 * NS))
                        delay = (int64_t)(3 * NS);
                }
                t->at = mono() + (t->udp_direct_port ? 0 : (uint64_t)delay);
                t->deadline = t->at + 10 * NS;
                {
                    /* Say how long the punch waits and what the deadline is: a tunnel that
                     * sits in T_TIME until its deadline is indistinguishable from one that
                     * never got here without these two numbers. */
                    char when[200];
                    snprintf(when, sizeof(when),
                             "punch scheduled for %s in %llu ms (delay %lld ms, at+deadline %llu ms)",
                             t->peer, (unsigned long long)((t->at - mono()) / NS),
                             (long long)(delay / NS),
                             (unsigned long long)((t->deadline - mono()) / NS));
                    emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, when);
                }
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
        const char *canonical = op_string(j, "canonicalNode");
        if (valid_node(canonical)) {
            rename_peer(c, peer, canonical);
            peer = canonical;
        }
        op_addr gateway_ip;
        int has_gateway_ipv4 = !op_addr_from_text(&gateway_ip, op_string(j, "IPv4"), 0) &&
                               op_addr_family(&gateway_ip) == AF_INET;
        if (valid_node(peer) && has_gateway_ipv4)
            for (int i = 0; i < NT; ++i) {
                tunnel *t = &c->tunnels[i];
                if (t->state == T_TCP_CONNECT &&
                    (t->tcp_predict_role == TCP_PREDICT_OPEN || t->tcp_predict_role == TCP_PREDICT_PAIR) &&
                    !strcmp(t->peer, peer) && op_addr_equal(&gateway_ip, &t->peer_addr))
                    t->tcp_peer_ip_verified = 1;
            }
        /* SPEC 搂4: the gateway's 7/1 answer carries the family bitmap and the
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
                    c->apps[i].peer_observed_ipv4 = has_gateway_ipv4 ? observed_ipv4(&gateway_ip) : 0;
                    address_text_out(c->apps[i].peer_lan, lan, OP_FAM_V4);
                    address_text_out(c->apps[i].peer_lan6, lan6, OP_FAM_V6);
                }
    } else if (main == 3 && sub == 21 && c->login_ok)
        rename_peer(c, op_string(j, "oldName"), op_string(j, "name"));
    else if (main == 3 && sub == 7)
        report_apps(c);
    else if (main == 3 && sub == 16) {
        /* RULE_SYNC: the gateway is the source of truth. Drop every local rule
         * first, then rebuild exactly the enabled set it persisted. */
        json_object *rules = op_get(j, "Rules");
        for (int i = 0; i < NA; ++i)
            if (c->apps[i].used && c->apps[i].local && !c->apps[i].sdwan)
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
        if(result<0){
            /* The handler's reason lives in the CLI layer, so publish the code and the
             * revision: EINVAL means the payload was refused, EIO that it could not be
             * written, and the revision says whether the gateway retried the same one. */
            char message[192];
            snprintf(message,sizeof(message),
                     "gateway configuration rejected or could not be saved (code %d, revision %llu, login=%d report=%d handler=%d)",
                     result,(unsigned long long)revision,(int)(c->login_ok!=0),(int)(c->report_ok!=0),(int)(c->config_handler!=NULL));
            emit(c,FASTP2P_EVENT_ERROR,revision,result,message);
        }
    } else if (main == 3 && sub == 18) {
        /* UPDATE: the operator asked for this node to be upgraded. Download,
         * verify, then hand over to the new build. */
        const char *url = op_string(j, "url"), *sha = op_string(j, "sha256");
        const char *version = op_string(j, "version");
        uint64_t size = op_integer(j, "size"), upgrade = op_integer(j, "upgradeId");
        const char *failure = NULL;
        if (c->stopping || c->upgrade_stop_at) {
            failure = "an update is already pending";
        } else if (!*url || strlen(sha) != 64) {
            failure = "invalid upgrade order";
            emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EINVAL, "invalid upgrade order");
        } else {
            char staged[4200], error[256], message[192];
            snprintf(staged, sizeof(staged), "%s", "");
            snprintf(message, sizeof(message), "downloading build %s", *version ? version : "update");
            emit(c, FASTP2P_EVENT_STATE, 0, 0, message);
            if (fp_update_stage_path(staged, sizeof(staged))) {
                failure = "cannot prepare the download directory";
                emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, failure);
            } else if (fp_update_download(url, c->ca, c->ca_pem, c->tls_host ? c->resolve : NULL,
                                          staged, sha, size, error, sizeof(error))) {
                emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, error);
                failure = "cannot download or verify the update package";
                fp_update_discard(staged);
#ifdef __ANDROID__
            } else {
                /* Hand the verified APK to the Android install flow. */
                char ready[4300];
                snprintf(ready, sizeof(ready), "update-ready:%s", staged);
                emit(c, FASTP2P_EVENT_STATE, 0, 0, ready);
            }
#else
            } else if (fp_update_apply(staged, error, sizeof(error))) {
                fp_update_discard(staged);
                emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, error);
                failure = c->error;
            } else {
                emit(c, FASTP2P_EVENT_STATE, 0, 0, "installing the new build");
                /* Ask for a normal stop: the run loop then reports a clean exit,
                 * so a Windows service manager does not treat it as a failure and
                 * race the updater by restarting the old image. */
                c->upgrade_stop_at = mono() + 500 * MS;
            }
#endif
        }
        if (upgrade) {
            json_object *result = json_object_new_object();
            op_ju(result, "upgradeId", upgrade);
            op_js(result, "state", failure ? "failed" : "accepted");
            if (failure)
                op_js(result, "detail", failure);
            ws_json(c, 6, 10, result);
            json_object_put(result);
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
static void sdwan_send(fastp2p_client *c, int owner, const uint8_t *packet, size_t length) {
    const fp_sdwan *state = c->sdwan;
    if (state->central && state->center_index != FP_SDWAN_LOCAL)
        owner = state->center_index;
    if (owner < 0 || state->peers[owner].app_index < 0)
        return;
    const app *a = &c->apps[state->peers[owner].app_index];
    if (a->synced && a->tunnel_index >= 0 && tunnel_ready(&c->tunnels[a->tunnel_index]))
        (void)tseal(c, &c->tunnels[a->tunnel_index], TUN_SDWAN_IPV4, packet, length);
}

static void sdwan_receive(fastp2p_client *c, const tunnel *t, uint8_t *packet, size_t length) {
    fp_sdwan *state = c->sdwan;
    uint32_t source, destination;
    if (fp_sdwan_ipv4(packet, length, &source, &destination))
        return;
    int from = fp_sdwan_owner(state, source), to = fp_sdwan_owner(state, destination);
    if (from < 0 || to == FP_SDWAN_NO_ROUTE)
        return;
    int hub = state->central && state->center_index == FP_SDWAN_LOCAL;
    int incoming = state->central && !hub ? state->center_index : from;
    const char *peer = t->relay_wait ? t->relay_peer : t->peer;
    if (incoming < 0 || state->peers[incoming].app_index < 0 ||
        strcmp(peer, c->apps[state->peers[incoming].app_index].peer))
        return;
    if (to == FP_SDWAN_LOCAL) {
        fp_sdwan_write(state, packet, length);
        return;
    }
    if (!hub || from == to || packet[8] <= 1)
        return;
    --packet[8];
    /* Route between authenticated branches without passing through the host's IP stack. */
    packet[10] = packet[11] = 0;
    unsigned sum = 0;
    for (unsigned i = 0; i < (unsigned)(packet[0] & 15) * 4; i += 2)
        sum += ((unsigned)packet[i] << 8) | packet[i + 1];
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    packet[10] = (uint8_t)(~sum >> 8);
    packet[11] = (uint8_t)~sum;
    sdwan_send(c, to, packet, length);
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
    /* Sealed frames only: a keepalive is plaintext, so this timestamp really means
     * the rule was carrying traffic, which is what decides an idle re-punch. */
    t->last_payload = mono();
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
        /* A hello means the peer's socket is live in both directions, whichever side
         * we were told we are: during a punch both ends dial, so both can be the one
         * that receives it. Requiring the server role here left the two ends each
         * waiting for the other's acknowledgement and tearing the tunnel down with
         * "invalid tunnel handshake". */
        if (sub == TUN_HELLO && len == 8 && op_u64(data) == t->id) {
            tframe(t, TUN_HELLO_ACK, data, len);
            if (t->udp_direct_port)
                emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, "UDP peer listener accepted connection");
            tunnel_active(c, ti);
        } else if (sub == TUN_HELLO_ACK && len == 8 && op_u64(data) == t->id) {
            if (t->udp_direct_port)
                emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, "UDP peer listener connected");
            tunnel_active(c, ti);
        } else if (sub == 4 && len == 8 && op_u64(data) == t->id) {
            /* An older build confirmed a completed dial with this frame. It names
             * this tunnel and nothing else, so it can arrive just after the socket
             * is adopted; ignoring it keeps a mixed-version pair from tearing the
             * tunnel down over a frame that carries no state this side still needs. */
        } else
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
    /* A plaintext hello or acknowledgement can land after this side is already
     * active: during a punch both ends answer the peer's hello, so the second
     * answer arrives once the tunnel is up. It carries only the tunnel id and is
     * never sealed, so opening it as data would fail the session. */
    if ((sub == TUN_HELLO || sub == TUN_HELLO_ACK) && len == 8 && op_u64(data) == t->id)
        return;
    /* Acting as a relay hop: pass application frames through untouched. */
    if (t->relay_link >= 0 && t->relay_ready) {
        if (sub != TUN_OPEN && sub != TUN_OPEN_ACK && sub != TUN_CLOSE &&
            sub != TUN_DATA && sub != TUN_SDWAN_IPV4)
            return;
        relay_link *r = &c->relays[t->relay_link];
        int other = r->ta == ti ? r->tb : r->ta;
        if (other < 0 || other >= NT || c->tunnels[other].state != T_ACTIVE ||
            tframe(&c->tunnels[other], sub, data, len))
            close_tunnel(c, ti, "relay forwarding failed");
        return;
    }
    if (sub == TUN_SDWAN_IPV4 && (!fp_sdwan_active(c->sdwan) || !tunnel_ready(t)))
        return;
    uint8_t plain[4096 + 256];
    size_t n = 0;
    int rv = topen(c, ti, sub, data, len, plain, sizeof(plain), &n);
    if (rv)
        return;
    if (sub == TUN_SDWAN_IPV4) {
        sdwan_receive(c, t, plain, n);
        return;
    }
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
                /* SPEC 搂8: a v6/domain destination resolves through the same
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
    if (t->tcp_predict_role == TCP_PREDICT_OPEN || t->tcp_predict_role == TCP_PREDICT_PAIR) {
        if (op_addr_equal(&peer, &t->peer_addr))
            for (unsigned i = 0; i < t->tcp_candidate_count; ++i)
                if (op_addr_port(&peer) == t->tcp_candidate_ports[i]) {
                    tcp_candidate_connected(t, fd, mono());
                    return;
                }
        op_close(fd);
        return;
    }
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
    /* The dialler announces itself with the hello (2/0); a confirming peer uses 4/2.
     * Both identify the same tunnel the same way, and either one proves this
     * accepted socket is the punched connection and not a stray probe. Waiting only
     * for 4/2 left every simultaneous open with a live socket that the handshake
     * never adopted, so the tunnel died on the first missing heartbeat. */
    int announce = (main == 4 && sub == 2) || (main == 2 && sub == 0);
    if (rv > 0 && announce && len == 8 && op_u64(body) == t->id) {
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
static void tick_tcp_direct(fastp2p_client *c, int ti, uint64_t now) {
    tunnel *t = &c->tunnels[ti];
    if (now < t->tcp_attempt_deadline) {
        if (t->state == T_TCP_DIRECT_CONNECT) {
            int ready = connect_ready(t->fd);
            if (!ready)
                return;
            if (ready > 0) {
                uint8_t id[8];
                op_put64(id, t->id);
                if (!tframe(t, 2, id, sizeof(id)))
                    t->state = T_TCP_DIRECT_ACK;
            }
        }
        if (t->state == T_TCP_DIRECT_ACK && !flush(t->fd, &t->tx) &&
            !read_socket(t->fd, &t->rx, 4096)) {
            uint16_t main, sub;
            uint8_t *body = NULL;
            size_t length;
            int frame = op_frame_take(&t->rx, &main, &sub, &body, &length);
            if (!frame)
                return;
            int acknowledged = frame > 0 && main == 4 && sub == 3 && length == 8 &&
                               op_u64(body) == t->id;
            free(body);
            if (acknowledged) {
                emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, "TCP peer listener connected");
                tunnel_active(c, ti);
                return;
            }
        }
    }
    op_close(t->fd);
    t->fd = -1;
    op_buffer_clear(&t->rx);
    op_buffer_clear(&t->tx);
    start_underlay(c, ti);
}

static void send_udp_centered(op_socket fd, op_addr peer, json_object *message,
                              uint16_t base, uint16_t count, int closest_first) {
    uint16_t low, high;
    if (!sym_split_window(base, count, &low, &high))
        return;
    if (closest_first) {
        /* The receiver's extra sockets cover the first few new mappings
         * we allocate. Try the closest destinations before the edges. */
        for (int offset = 1; offset <= count / 2; ++offset) {
            int ports[] = {base + offset, base - offset};
            for (unsigned i = 0; i < 2; ++i) {
                if (ports[i] < low || ports[i] > high)
                    continue;
                op_addr_set_port(&peer, (uint16_t)ports[i]);
                udp_packet(fd, &peer, 4, 0, message);
            }
        }
        return;
    }
    for (uint32_t port = low; port <= high; ++port) {
        if (port == base)
            continue;
        op_addr_set_port(&peer, (uint16_t)port);
        udp_packet(fd, &peer, 4, 0, message);
    }
}

static void send_udp_punch_window(const tunnel *t, op_socket fd, op_addr peer,
                                  json_object *message, uint16_t count) {
    if (t->sym_split) {
        int closest_first = t->udp_punch_role == UDP_PUNCH_SEND;
        if (t->sym_alt_base && t->family == OP_FAM_V4 && count >= 4) {
            /* Reserve part of the existing burst for the second window. Its
             * centre also counts against the budget. */
            uint16_t alternate_count = (uint16_t)((count / 2) & ~1u);
            op_addr_set_port(&peer, t->sym_alt_base);
            udp_packet(fd, &peer, 4, 0, message);
            send_udp_centered(fd, peer, message, t->sym_alt_base, (uint16_t)(alternate_count - 2),
                              closest_first);
            count = (uint16_t)(count - alternate_count);
        }
        send_udp_centered(fd, peer, message, t->sym_base, count, closest_first);
        return;
    }
    uint16_t start = sym_window_base(t->sym_base, t->sym_up, count);
    uint16_t span = sym_window_span(t->sym_base, t->sym_up, count);
    for (uint16_t i = 0; i < span; ++i) {
        op_addr_set_port(&peer, (uint16_t)(t->sym_up ? start + i : start - i));
        udp_packet(fd, &peer, 4, 0, message);
    }
}

static void open_udp_candidates(fastp2p_client *c, tunnel *t) {
    unsigned in_use = 0;
    for (int i = 0; i < NT; ++i)
        in_use += c->tunnels[i].udp_candidate_count;
    while (t->udp_candidate_count < UDP_PUNCH_EXTRA_SOCKETS && in_use < UDP_PUNCH_CLIENT_EXTRA_SOCKETS) {
        op_socket fd = socket_bound(1, source_text(c, OP_FAM_V4), 0, 0);
        if (fd < 0)
            break;
        t->udp_candidates[t->udp_candidate_count++] = fd;
        ++in_use;
    }
}

static void read_udp_punch(fastp2p_client *c, int ti, op_addr peer, json_object *message, uint64_t now) {
    tunnel *t = &c->tunnels[ti];
    for (unsigned slot = 0; slot <= t->udp_candidate_count; ++slot) {
        op_socket fd = slot ? t->udp_candidates[slot - 1] : t->fd;
        for (int k = 0; k < 8; ++k) {
            uint8_t data[1024];
            op_addr from = {0};
            from.len = (op_socklen)sizeof(from.u.storage);
            op_ssize n = op_recvfrom(fd, data, sizeof(data), MSG_DONTWAIT, &from.u.sa, &from.len);
            if (n < 0)
                break;
            op_addr_normalize(&from);
            if (n < 8 || op_u32(data) != (uint32_t)(n - 8) || op_u16(data + 4) != 4 ||
                !op_addr_equal(&from, &peer))
                continue;
            uint16_t sub = op_u16(data + 6);
            if (sub > 1 || (t->udp_punch_role == UDP_PUNCH_SEND && sub != 1) ||
                (t->udp_punch_role == UDP_PUNCH_RECEIVE && sub != 0))
                continue;
            json_object *reply = op_json(data + 8, (size_t)n - 8);
            uint64_t id = op_integer(reply, "id");
            if (reply)
                json_object_put(reply);
            if (id != t->id)
                continue;

            if (slot) {
                op_close(t->fd);
    t->fd = -1;
                t->udp_candidates[slot - 1] = -1;
                t->local_port = socket_port(fd);
                emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, "UDP punch selected another local socket");
            }
            close_udp_candidates(t);
            t->remote_port = op_addr_port(&from);
            op_addr_copy(&t->peer_addr, &from);
            udp_packet(fd, &from, 4, 1, message);
            if (t->udp_punch_role == UDP_PUNCH_RECEIVE) {
                t->udp_punch_ack_until = now + UDP_PUNCH_ACK_WINDOW;
                t->punch_next = now + 50 * MS;
            }
            if (sub == 1 || t->udp_punch_role == UDP_PUNCH_RECEIVE) {
                start_underlay(c, ti);
                return;
            }
        }
    }
}

static void tick_udp_punch(fastp2p_client *c, int ti, uint64_t now) {
    tunnel *t = &c->tunnels[ti];
    if (t->udp_punch_role == UDP_PUNCH_SEND && !t->udp_punch_ready &&
        now - t->punch_started < UDP_PUNCH_READY_WAIT)
        return;
    op_addr peer = t->peer_addr;
    json_object *message = json_object_new_object();
    op_ju(message, "id", t->id);
    int first = !t->punch_next;
    if (now >= t->punch_next) {
        int burst = t->sym_count && t->sym_sprayed < SYM_SPRAY_ROUNDS && now >= t->sym_spray_at;
        /* Sending to the observed port first can spend the very next mapping
         * that a peer with a predictable allocator expects us to use. */
        int predict_first = burst && t->udp_punch_role && !t->sym_split;
        if (!predict_first)
            udp_packet(t->fd, &peer, 4, 0, message);
        if (burst) {
            ++t->sym_sprayed;
            t->sym_spray_at = now + SYM_SPRAY_GAP;
            send_udp_punch_window(t, t->fd, peer, message, t->sym_count);
            if (first && t->udp_punch_role == UDP_PUNCH_RECEIVE && t->udp_punch_kind == 2)
                open_udp_candidates(c, t);
            uint16_t count = t->sym_count < UDP_PUNCH_EXTRA_WINDOW ? t->sym_count : UDP_PUNCH_EXTRA_WINDOW;
            for (unsigned i = 0; i < t->udp_candidate_count; ++i) {
                send_udp_punch_window(t, t->udp_candidates[i], peer, message, count);
                udp_packet(t->udp_candidates[i], &peer, 4, 0, message);
            }
        }
        if (predict_first)
            udp_packet(t->fd, &peer, 4, 0, message);
        t->punch_next = now + punch_interval(now - t->punch_started);
        if (first && t->udp_punch_role == UDP_PUNCH_RECEIVE) {
            op_ju(message, "udpPunchReady", 1);
            push(c, t->peer, PUSH_READY, message);
            json_object_object_del(message, "udpPunchReady");
            emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, "UDP punch receiver prepared");
        } else if (first && t->udp_punch_role == UDP_PUNCH_SEND) {
            emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, "UDP punch sender started");
        }
    }
    read_udp_punch(c, ti, peer, message, now);
    json_object_put(message);
}

static void tick_tunnel(fastp2p_client *c, int ti, uint64_t now) {
    tunnel *t = &c->tunnels[ti];
    if (!t->state)
        return;
    if (t->state == T_TCP_SAMPLE &&
        (now >= t->deadline || fp_tcp_punch_sample_step(t->tcp_sample, now, &t->tcp_mapping, &t->tcp_last_port))) {
        fp_tcp_punch_sample_free(t->tcp_sample);
        t->tcp_sample = NULL;
        probe_complete(c, ti);
        if (!t->state)
            return;
    }
    if (t->state != T_ACTIVE && now > t->deadline) {
        /* A mapping probe that never answered leaves the peer without a reply; the
         * fallback keeps a no-relay link alive instead of timing the tunnel out. */
        if (probe_fallback_mapping(c, ti))
            return;
        /* Name the peer: several tunnels run at once and the bare message made it
         * impossible to tell which one timed out. */
        char why[160];
        snprintf(why, sizeof(why), "tunnel establishment timed out (peer %s, mode %s, state %d)",
                 t->peer, t->mode, (int)t->state);
        close_tunnel(c, ti, why);
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
        if (!family_usable(c, t, family)) {
            /* Nothing to aim at: say which half is missing, otherwise the tunnel just
             * sits in T_TIME until its deadline and the log names only the timeout. */
            char why[240];
            snprintf(why, sizeof(why),
                     "no usable punch endpoint for %s (family=%d mapped v4=%u/%s v6=%u/%s peer v4=%s/%d v6=%s/%d)",
                     t->peer, family, (unsigned)t->mapped_ports[OP_FAM_V4], t->mapped_text[OP_FAM_V4],
                     (unsigned)t->mapped_ports[OP_FAM_V6], t->mapped_text[OP_FAM_V6],
                     t->peer_text[OP_FAM_V4], (int)t->peer_ready[OP_FAM_V4],
                     t->peer_text[OP_FAM_V6], (int)t->peer_ready[OP_FAM_V6]);
            emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, why);
        }
        if (family_usable(c, t, family)) {
            if (use_punch_family(c, ti, family)) {
                close_tunnel(c, ti, "could not prepare the peer address family");
                return;
            }
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
            if (!t->server && t->udp_direct_port) {
                uint8_t id[OPQ_DIRECT_ID_LEN];
                op_put64(id, t->id);
                op_addr_set_port(&t->peer_addr, t->udp_direct_port);
                t->quic = opq_dial_listener(t->fd, &t->peer_addr.u.sa, t->peer_addr.len, id, c->tls_host);
                t->state = T_QUIC;
                t->deadline = now + UDP_DIRECT_WAIT;
                if (!t->quic || tframe(t, TUN_HELLO, id, sizeof(id))) {
                    close_tunnel(c, ti, "UDP peer listener dial could not start");
                    return;
                }
            } else {
                t->state = T_PUNCH;
                t->punch_next = 0;
                t->punch_started = now;
            }
        } else
            start_underlay(c, ti);
    }
    if (t->state == T_TCP_DIRECT_CONNECT || t->state == T_TCP_DIRECT_ACK) {
        tick_tcp_direct(c, ti, now);
        return;
    }
    if (t->state == T_PUNCH)
        tick_udp_punch(c, ti, now);
    if (t->state == T_UNDERLAY && t->notified)
        start_underlay(c, ti);
    /* The chosen receiver retransmits its reply until the sender's QUIC
     * handshake confirms that the reply reached the winning endpoint. */
    if (now < t->udp_punch_ack_until && now >= t->punch_next &&
        (t->state == T_UNDERLAY || (t->state == T_QUIC && !opq_ready(t->quic)))) {
        json_object *reply = json_object_new_object();
        op_ju(reply, "id", t->id);
        udp_packet(t->fd, &t->peer_addr, 4, 1, reply);
        json_object_put(reply);
        t->punch_next = now + 100 * MS;
    }
    if (t->state == T_TCP_CONNECT && t->tcp_predict_until && now >= t->tcp_predict_until) {
        /* The predicted port can miss even when the original mapped endpoint
         * works. Use the rest of the original budget for the standard punch. */
        close_tcp_candidates(t);
        if (t->fd >= 0)
            op_close(t->fd);
        t->fd = -1;
        t->tcp_predict_until = 0;
        t->tcp_predict_role = TCP_PREDICT_NONE;
        t->tcp_attempts = 0;
        emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, "TCP NAT prediction timed out; trying the observed endpoint");
        tcp_punch_dial(c, ti, now);
    }
    if (t->state == T_TCP_CONNECT && t->tcp_predict_role)
        tcp_predict_tick(c, ti, now);
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
            }
            /* This socket completed a dial, so it is live in both directions: say so
             * with the hello, which is what a peer adopts a parked socket on. */
            uint8_t id[8];
            op_put64(id, t->id);
            tframe(t, TUN_HELLO, id, sizeof(id));
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

        /* Three seconds, not ten: a punched socket is only kept alive by traffic,
         * and both carrier NATs drop a silent TCP mapping well before the
         * heartbeat timeout would notice. The link then looks established while
         * nothing crosses it, which is what a rule hitting its deadline after an
         * idle period is really seeing. */
        if (now >= t->last_hb && now - t->last_hb >= TCP_KEEPALIVE_MS * MS) {
            tframe(t, TUN_KEEPALIVE, NULL, 0);
            t->last_hb = now;
            if (now >= t->last_rx && now - t->last_rx >= 15 * NS &&
                (!t->silent_logged || now - t->silent_logged >= 15 * NS)) {
                char note[96];
                snprintf(note, sizeof(note), "peer silent for %llus; keepalive sent",
                         (unsigned long long)((now - t->last_rx) / NS));
                emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, note);
                t->silent_logged = now;
            }
        }
        /* The first session push can land while the peer is still finishing its own
         * handshake, and a peer that drops it never becomes ready: the rule then
         * gives up at its deadline and abandons a tunnel that is already carrying
         * traffic, which is why a working link kept disappearing after ~20 s. Push
         * again until the rule that owns this tunnel reports the session; the
         * session and secret are the same values, so a peer that already has them
         * simply re-keys to the same state. */
        if (t->session_owner && t->relay_link < 0 &&
            now >= t->last_session_push && now - t->last_session_push >= 2 * NS) {
            int pending = 0;
            for (int i = 0; i < NA; ++i)
                if (c->apps[i].used && c->apps[i].local && c->apps[i].tunnel_index == ti &&
                    !c->apps[i].synced)
                    pending = 1;
            if (pending) {
                push_session(c, t, NULL);
                t->last_session_push = now;
            }
        }
        /* A link that stays up for a minute has proven the path: clear the
         * failure counters so a later drop retries the direct punch first. */
        if (t->active_at && now >= t->active_at && now - t->active_at >= 60 * NS) {
            for (int i = 0; i < NA; ++i)
                if (c->apps[i].used && c->apps[i].local && c->apps[i].tunnel_index == ti) {
                    c->apps[i].attempts = 0;
                    c->apps[i].lan_tried = 0;
                    c->apps[i].udp_direct_tried = 0;
                    c->apps[i].udp_reverse6_retry = 0;
                    c->apps[i].ipv4_retry = 0;
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
                int family = op_family_index(op_addr_family(&p->peer));
                int waiting = t->state == T_TIME && t->tcp_direct_port && family >= 0 &&
                              t->peer_ready[family];
                const char *wanted = waiting ? t->peer_text[family] : t->ip;
                if ((waiting || t->state == T_DIRECT) && t->server &&
                    !op_addr_from_text(&expected, wanted, 0) &&
                    op_addr_equal(&expected, &p->peer)) {
                    t->fd = p->fd;
                    p->fd = -1;
                    if (tframe(t, 3, body, len))
                        close_tunnel(c, ti, "TCP handshake acknowledgement could not be queued");
                    else {
                        if (waiting)
                            emit(c, FASTP2P_EVENT_TUNNEL, t->id, 0, "TCP peer listener accepted connection");
                        tunnel_active(c, ti);
                        if (op_buffer_size(&p->rx))
                            op_buffer_add(&t->rx, p->rx.data + p->rx.offset, op_buffer_size(&p->rx),
                                          OP_QUEUE_LIMIT);
                    }
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
static void dispatch_udp_listener(fastp2p_client *c, int family, const op_addr *peer,
                                   const uint8_t *packet, size_t length, uint64_t now) {
    if (!length || !(packet[0] & 0x40))
        return;
    uint8_t id[OPQ_DIRECT_ID_LEN];
    int initial = opq_initial_tunnel_id(packet, length, id);
    /* Each dial uses its own UDP source socket. The receiving side owns the
     * shared listener and dispatches established connections by source tuple. */
    for (int i = 0; i < NT; ++i) {
        tunnel *t = &c->tunnels[i];
        if (!t->quic || !t->server || !t->udp_direct_port || t->family != family ||
            !op_address_equal(&t->peer_addr.u.sa, t->peer_addr.len, &peer->u.sa, peer->len))
            continue;
        if ((!initial || op_u64(id) == t->id) && opq_receive(t->quic, packet, length))
            close_tunnel(c, i, opq_error(t->quic));
        return;
    }
    if (!initial)
        return;
    int index = tunnel_by_id(c, op_u64(id));
    if (index < 0)
        return;
    tunnel *t = &c->tunnels[index];
    op_addr expected;
    if (t->state != T_UDP_DIRECT || !t->server || !t->peer_ready[family] || now >= t->deadline ||
        (t->initiator && t->udp_reverse6_retry && family != OP_FAM_V6) ||
        op_addr_from_text(&expected, t->peer_text[family], 0) || !op_addr_equal(&expected, peer))
        return;
    opq *q = opq_accept_listener(c->udp_listener[family], &peer->u.sa, peer->len);
    if (!q)
        return;
    if (opq_receive(q, packet, length)) {
        opq_free(q);
        return;
    }
    probe_socket_close(t);
    if (t->fd >= 0)
        op_close(t->fd);
    t->fd = -1;
    t->quic = q;
    t->family = family;
    t->remote_port = op_addr_port(peer);
    op_addr_copy(&t->peer_addr, peer);
    t->state = T_QUIC;
}
static void tick_port_mapping(fastp2p_client *c) {
    if (!c->port_mapping)
        return;
    fp_mapped_ports previous = c->mapped_listener;
    c->mapped_listener = fp_port_mapping_read(c->port_mapping);
    if (previous.udp != c->mapped_listener.udp || previous.tcp != c->mapped_listener.tcp) {
        char message[125];
        snprintf(message, sizeof(message), "Router port mapping for local port %u: TCP %u, UDP %u",
                 (unsigned)c->public_port, (unsigned)c->mapped_listener.tcp, (unsigned)c->mapped_listener.udp);
        emit(c, FASTP2P_EVENT_TUNNEL, 0, 0, message);
    }
    if (c->ws_connected && c->login_ok &&
        (previous.tcp != c->mapped_listener.tcp || previous.udp != c->mapped_listener.udp ||
         previous.tcp_wan != c->mapped_listener.tcp_wan || previous.udp_wan != c->mapped_listener.udp_wan))
        report_nat(c);
}

static void tick_udp_listeners(fastp2p_client *c, uint64_t now) {
    uint8_t packet[65536];
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        if (c->udp_listener[family] < 0)
            continue;
        for (int i = 0; i < 64; ++i) {
            op_addr peer = {0};
            peer.len = (op_socklen)sizeof(peer.u.storage);
            op_ssize length = op_recvfrom(c->udp_listener[family], packet, sizeof(packet),
                                          MSG_DONTWAIT, &peer.u.sa, &peer.len);
            if (length < 0)
                break;
            op_addr_normalize(&peer);
            /* The probe borrows this socket when a listener owns public_port,
             * so its replies arrive here: hand them over before the punch
             * dispatcher treats them as an unknown datagram and drops them. */
            if (family == OP_FAM_V4 && c->stun.phase && c->stun.shared &&
                nat_stun_input(c, packet, (size_t)length, &peer, now))
                continue;
            dispatch_udp_listener(c, family, &peer, packet, (size_t)length, now);
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
         * retry ladder can move on (and eventually escalate to a relay). A link
         * whose transport is already active is a different case: the punched
         * socket is carrying the peer's traffic, and dropping it at this deadline
         * is what the peer sees as a heartbeat timeout. Give the session exchange
         * more time instead, and let the tunnel's own heartbeat decide when it is
         * really gone. */
        if (a->tunnel_index >= 0 && !a->synced && a->link_deadline && now > a->link_deadline) {
            int index = a->tunnel_index;
            if (c->tunnels[index].state == T_ACTIVE) {
                a->link_deadline = now + 20 * NS;
                bind_pending_key(c, index);
            } else {
                a->link_deadline = 0;
                a->tunnel_index = -1;
                a->retry = now;
                if (c->tunnels[index].state)
                    close_tunnel(c, index, "link did not become ready");
            }
        }
        if (a->tunnel_index < 0 && now >= a->retry && c->state == FASTP2P_ONLINE) {
            int ti = active_tunnel(c, a->peer, a->transport);
            if (ti >= 0) {
                a->tunnel_index = ti;
                a->link_deadline = mono() + 20 * NS;
                session_ready(c, ti);
            } else if (a->relay_requested ||
                       (a->transport == FASTP2P_TRANSPORT_QUIC && now < c->port_mapping_wait_until &&
                        !c->mapped_listener.udp && !a->attempts && !a->relay_node[0] && !c->force_relay)) {
                /* Let the router respond before choosing the first direct QUIC path. */
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
                    if (!a->udp_reverse6_retry && lan_punch_possible(c, a) && !a->lan_tried && !c->force_relay) {
                        ti = app_tunnel(c, a, a->peer, a->transport);
                        if (ti >= 0) {
                            c->tunnels[ti].lan = 1;
                            a->lan_tried = 1;
                            start_punch(c, ti);
                        }
                    } else if (a->relay_node[0] || a->attempts >= PUBLIC_PUNCH_ROUNDS || c->force_relay) {
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
                            char relay_message[160];
                            snprintf(relay_message, sizeof(relay_message),
                                     "relay requested from the gateway after a failed direct attempt (peer %s, protocol %s)",
                                     a->peer, a->transport == FASTP2P_TRANSPORT_TCP ? "tcp" : "quic");
                            emit(c, FASTP2P_EVENT_TUNNEL, 0, 0, relay_message);
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
                            }
                            json_object_put(j);
                        }
                    } else {
                        ti = app_tunnel(c, a, a->peer, a->transport);
                        if (ti >= 0) {
                            ++a->attempts;
                            c->tunnels[ti].ipv4_only = a->ipv4_retry;
                            start_punch(c, ti);
                        }
                    }
                }
            }
            a->retry = now + 2 * NS;
        }
        if (a->tunnel_index < 0 || !a->synced ||
            !tunnel_ready(&c->tunnels[a->tunnel_index]) || now < a->ready_at)
            continue;
        if (a->socks || a->sdwan)
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
/* SPEC 搂1/搂4: the family bitmap and the parallel v6 levels ride on both the
 * registration frame (6/0) and the refresh frame (6/9). IPv4 fields keep their
 * historical names and values; a v4-only run reports families=1 and the v6
 * slots stay at their sentinel values, exactly as an old client read them. */
static void report_families(const fastp2p_client *c, json_object *j) {
    op_ju(j, "families", (uint64_t)c->families_wanted);
    if (family_wanted(c, OP_FAM_V4) &&
        strcmp(c->ip[OP_FAM_V4], "0.0.0.0") && address_of_family(c->ip[OP_FAM_V4], OP_FAM_V4))
        op_js(j, "IPv4", c->ip[OP_FAM_V4]);
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
    op_ju(j, "publicUDP", has_udp_listener(c));
    report_port_mapping(c, j);
    op_ju(j, "configPush", c->config_handler != NULL);
#ifdef __linux__
    op_ju(j, "sdwanPush", c->config_handler != NULL);
    op_ju(j, "sdwanTopology", c->config_handler != NULL);
#elif defined(_WIN32)
    int sdwan_supported = c->config_handler && !fp_sdwan_check();
    op_ju(j, "sdwanPush", sdwan_supported);
    op_ju(j, "sdwanTopology", sdwan_supported);
#endif
    op_ju(j, "restart", c->restart_handler != NULL);
    op_ju(j, "udpNatType", (uint64_t)c->nat[OP_FAM_V4].type);
    op_ju(j, "tcpNatType", c->tcp_nat.family[OP_FAM_V4].type);
    op_ju(j, "tcpNatSamples", c->tcp_nat.family[OP_FAM_V4].samples);
    op_ju(j, "tcpNatDestinationIPs", c->tcp_nat.family[OP_FAM_V4].destinations);
    op_ju(j, "natLevel", (uint64_t)nat_level(c));
    op_ju(j, "tcpNatLevel", (uint64_t)tcp_nat_level(c));
    report_families(c, j);
    /* The refresh frame carries the addresses too: the login happens before the
     * IPv4 mapping is known, so without this a host whose NIC is public keeps an
     * empty public address in the registry forever. */
    op_js(j, "IPv4", addr_text_set(c->ip[OP_FAM_V4])
                       ? c->ip[OP_FAM_V4]
                       : (local_is_public(c->local_ip[OP_FAM_V4]) ? c->local_ip[OP_FAM_V4] : ""));
    op_js(j, "lanIP", c->local_ip[OP_FAM_V4]);
    ws_json(c, 6, 0, j);
    json_object_put(j);
}
/* A host whose NIC carries the public address has a public "LAN" address: report it
 * as the public one too, so the registry shows the same value in both fields instead
 * of an empty public address waiting for a mapping that does not exist. */
/* The client seeds both v4 slots with "0.0.0.0" at init, so a non-empty check alone
 * reports a bogus address: nothing learns the real value and "is this our own address"
 * can never match. Treat the placeholder as unset everywhere. */
static int addr_text_set(const char *text) {
    return text && text[0] && strcmp(text, "0.0.0.0");
}
static int local_is_public(const char *text) {
    struct in_addr address;
    if (!text || !*text || inet_pton(AF_INET, text, &address) != 1)
        return 0;
    uint32_t value = ntohl(address.s_addr);
    unsigned first = value >> 24, second = (value >> 16) & 0xff;
    if (!first || first == 10 || first == 127 || first >= 224)
        return 0;
    if (first == 172 && second >= 16 && second <= 31)
        return 0;
    if (first == 192 && second == 168)
        return 0;
    if (first == 169 && second == 254)
        return 0;
    if (first == 100 && second >= 64 && second <= 127)
        return 0;
    return 1;
}
static void report_nat(fastp2p_client *c) {
    json_object *j = json_object_new_object();
    report_port_mapping(c, j);
    op_ju(j, "udpNatType", (uint64_t)c->nat[OP_FAM_V4].type);
    op_ju(j, "tcpNatType", c->tcp_nat.family[OP_FAM_V4].type);
    op_ju(j, "tcpNatSamples", c->tcp_nat.family[OP_FAM_V4].samples);
    op_ju(j, "tcpNatDestinationIPs", c->tcp_nat.family[OP_FAM_V4].destinations);
    op_ju(j, "natLevel", (uint64_t)nat_level(c));
    op_ju(j, "tcpNatLevel", (uint64_t)tcp_nat_level(c));
    report_families(c, j);
    /* NAT refresh must not replay gateway rules or managed configuration. */
    op_js(j, "IPv4", addr_text_set(c->ip[OP_FAM_V4])
                       ? c->ip[OP_FAM_V4]
                       : (local_is_public(c->local_ip[OP_FAM_V4]) ? c->local_ip[OP_FAM_V4] : ""));
    op_js(j, "lanIP", c->local_ip[OP_FAM_V4]);
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
static void gateway_retry_next_family(fastp2p_client *c) {
    if (++c->gateway_failures < 2)
        return;
    c->gateway_failures = 0;
    if (c->gateway_dual)
        c->gateway_prefer_v6 = !c->gateway_prefer_v6;
}
static void gateway_failed(fastp2p_client *c) {
    /* The generic text below cannot tell a rejected option from a missing CA, and a
     * platform-specific setup failure looks identical to a refused connection. */
    {
        char detail[224];
        snprintf(detail, sizeof(detail), "WSS setup failed: host=%s port=%u ca=%s resolve=%s",
                 c->tls_host ? c->tls_host : c->host, (unsigned)c->port,
                 c->ca[0] || c->ca_pem ? "set" : "builtin", c->resolve ? "pinned" : "none");
        emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, detail);
    }
    gateway_retry_next_family(c);
    emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO,
         "WSS connection failed: check gateway address, CA, certificate hostname and token");
    close_gateway(c);
}
/* Same failure, but carrying the library's own reason. The generic message above
 * cannot distinguish an unreachable host from an unreadable CA or a hostname
 * mismatch, which is exactly what a reported failure usually needs. */
static void gateway_failed_curl(fastp2p_client *c, CURLcode rv) {
    gateway_retry_next_family(c);
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
    /* SPEC 搂7: a v6 literal host must be bracketed in the URL authority, while
     * a plain name or v4 literal is unchanged. */
    char urlhost[300];
    const char *tls_host = c->tls_host ? c->tls_host : c->host;
    if (strchr(tls_host, ':'))
        snprintf(urlhost, sizeof(urlhost), "[%s]", tls_host);
    else
        snprintf(urlhost, sizeof(urlhost), "%s", tls_host);
    snprintf(c->path, sizeof(c->path),
             "wss://%s:%u/api/v1/login?node=%s&token=%" PRIu64
             "&protocol=" WIRE_PROTOCOL
             "&version=%s&nattype=%d&tcpnattype=%u&families=%d&sharebandwidth=0&nodeRename=1",
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
     * keeps the historical order (SPEC 搂7). A family this host cannot route to
     * is deliberately left out: pinning it would let curl start the connection
     * on an address that will never answer and burn the whole connect timeout
     * before it falls back, which is exactly what happens on a host that
     * resolves AAAA but has no working IPv6 uplink. */
    c->resolve = NULL;
    char addresses[OP_FAM_COUNT][OP_ADDR_TEXT] = {{0}};
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        if (!c->gateway_addr[family].len || !family_wanted(c, family))
            continue;
        if (op_addr_text(&c->gateway_addr[family], addresses[family], sizeof(addresses[family])))
            addresses[family][0] = 0;
    }
    int ipv4 = addresses[OP_FAM_V4][0] != 0, ipv6 = addresses[OP_FAM_V6][0] != 0;
    if (ipv4 || ipv6) {
        char entry[512];
        /* The preferred family goes first. A route that answers the TCP handshake and
         * then goes silent never lets curl fall through to the second address, so the
         * order comes from the retry counter and not from the resolution order. */
        c->gateway_dual = ipv4 && ipv6;
    int v6_first = ipv6 && (!ipv4 || c->gateway_prefer_v6);
        int length = v6_first
                          ? snprintf(entry, sizeof(entry), "%s:%u:[%s]%s%s", urlhost, c->port,
                                     addresses[OP_FAM_V6], ipv4 ? "," : "", addresses[OP_FAM_V4])
                          : snprintf(entry, sizeof(entry), "%s:%u:%s%s%s%s%s", urlhost, c->port,
                                     addresses[OP_FAM_V4], ipv4 && ipv6 ? "," : "",
                                     ipv6 ? "[" : "", addresses[OP_FAM_V6], ipv6 ? "]" : "");
        if (length > 0 && (size_t)length < sizeof(entry))
            c->resolve = curl_slist_append(NULL, entry);
    /* Which endpoint the control connection actually dials, and which families the
     * resolver offered: a failure here is otherwise indistinguishable from a
     * rejected handshake in the log. */
    {
        char message[320];
        /* Never echo the login URL: it carries the install token, and one of the
         * release tests asserts the token never appears in client output. */
        snprintf(message, sizeof(message), "gateway dial: %s:%u (v4=%s v6=%s)",
                 urlhost, c->port, addresses[OP_FAM_V4], addresses[OP_FAM_V6]);
        emit(c, FASTP2P_EVENT_TUNNEL, 0, 0, message);
    }
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
    if (fp_tls_set_ca(c->ws, c->ca, c->ca_pem) != CURLE_OK) {
        gateway_failed(c);
        return;
    }
#ifdef _WIN32
    if (c->ca[0] || c->ca_pem)
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
/* Built-in probe servers are defined with fp_client_tcp_nat_config above. */

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
    /* No key at all falls back to the built-in servers, so a node measures its NAT
     * without any per-machine configuration. An empty array is an explicit opt-out
     * for operators who do not want the client to contact anything. */
    if (!servers) {
        if (stun_entry(c, FP_DEFAULT_STUN_SERVERS, 0) ||
            stun_entry(c, FP_DEFAULT_STUN_SERVERS_ALT, 1))
            return FASTP2P_EINVAL;
        c->stun_count = 2;
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
static void nat_filter_record(nat_filter *filter, int level, uint64_t now) {
    filter->level = level;
    filter->measured_at = level ? now : 0;
    filter->next_at = now + (level ? NAT_FILTER_REFRESH : NAT_FILTER_RETRY);
}
static int nat_filter_level(const nat_filter *filter, uint64_t now) {
    return now - filter->measured_at < NAT_FILTER_MAX_AGE ? filter->level : 0;
}
/* A listening socket is bound to the wildcard address, so its own endpoint says
 * nothing about which address the outside world sees. Treat that as unknown rather
 * than as a difference: the port is still the evidence this comparison needs. */
static int addr_is_unspecified(const op_addr *a) {
    op_addr copy = *a;
    op_addr_normalize(&copy);
    if (op_addr_family(&copy) == AF_INET)
        return copy.u.in.sin_addr.s_addr == 0;
    if (op_addr_family(&copy) == AF_INET6) {
        static const uint8_t zero[16] = {0};
        return !memcmp(&copy.u.in6.sin6_addr, zero, sizeof(zero));
    }
    return 0;
}
/* A listening socket is wildcard-bound, so the address half of "did anything get
 * translated" has to come from the interface addresses the client already knows.
 * Comparing only the port would call a port-preserving NAT "no NAT" and mislabel a
 * filtered private host as an open one. */
static int mapped_is_local_address(const fastp2p_client *c, const op_addr *mapped) {
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        const char *text = c->local_ip[family];
        if (!text[0])
            continue;
        op_addr local;
        if (op_addr_from_text(&local, text, 0))
            continue;
        if (op_addr_family(&local) != op_addr_family(mapped))
            continue;
        if (same_ip(&local, mapped))
            return 1;
    }
    return 0;
}
static void nat_stun_finish(fastp2p_client *c, uint64_t now) {
    nat_stun *s = &c->stun;
    /* Read the local endpoint before closing: when the server reports exactly the
     * address we sent from, there is no NAT in the path at all, and calling that
     * a full-cone NAT would be wrong. */
    char local_text[OP_ADDR_TEXT] = "", mapped_text[OP_ADDR_TEXT] = "";
    if (s->fd >= 0 && s->mapped_seen && !s->no_nat) {
        op_addr local;
        op_addr_text(&s->mapped, mapped_text, sizeof(mapped_text));
        memset(&local, 0, sizeof(local));
        if (!op_addr_socketname(s->fd, &local) &&
            op_addr_family(&local) == op_addr_family(&s->mapped) &&
            op_addr_port(&local) == op_addr_port(&s->mapped) &&
            (addr_is_unspecified(&local) ? mapped_is_local_address(c, &s->mapped)
                                          : same_ip(&local, &s->mapped)))
            s->no_nat = 1;
        op_addr_text(&local, local_text, sizeof(local_text));
    }
    if (s->fd >= 0 && !s->shared)
        op_close(s->fd);
    s->shared = 0;
    s->fd = -1;
    s->phase = 0;
    /* Same mapping from every destination -> cone; anything else is a
     * per-destination mapping, which is symmetric by definition.
     *
     * The cone variants are only separated when the servers actually proved
     * they implement the filtering extension: a reply from a different source,
     * or an advertised OTHER-ADDRESS. Otherwise a missing reply is just as
     * likely to mean "server ignored the attribute", and reporting NAT3 there
     * would turn a full-cone network into a false "port restricted". */
    int port_evidence = s->port_supported;
    int ip_evidence = s->ip_supported;
    int level;
    if (!s->mapped_seen)
        level = 0;
    else if (s->no_nat)
        /* No translation, so the "levels" describe the host firewall instead:
         * reachable from elsewhere is an open internet host, and a path that
         * answers nothing is a symmetric UDP firewall (RFC 3489 搂5). */
        level = (s->port_changed || s->ip_changed) ? 6 : (port_evidence ? 7 : 0);
    else if (!s->mapped_same)
        level = 4;
    else if (s->ip_changed)
        level = 1;
    else if (s->port_changed)
        /* Another port got through, so not port-restricted. Whether a stranger
         * address would also be accepted is only known if one was probed. */
        level = ip_evidence ? 2 : 5;
    else
        level = port_evidence ? 3 : 5;
    /* The mapping probe is the only other writer of c->ip, and it never runs in a
     * family the gateway is unreachable in - on a host whose IPv4 gateway route is
     * filtered, c->ip stayed 0.0.0.0 and every tunnel answer published that as the
     * address to dial. STUN measured the same mapping independently: keep it. */
    if (s->mapped_seen && addr_text_set(c->ip[OP_FAM_V4]) == 0) {
        char observed[OP_ADDR_TEXT];
        if (!op_addr_text(&s->mapped, observed, sizeof(observed)) &&
            address_of_family(observed, OP_FAM_V4))
            snprintf(c->ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", observed);
    }
    nat_filter_record(&c->udp_filter, level == 5 ? 0 : level, now);
    /* The registry only learns the level when it is told: a login before the probe
     * finishes carries the previous value, so publish the verdict as soon as there
     * is one. Otherwise a host that is open reads as unknown until its next login. */
    if (c->ws && c->login_ok)
        report_nat(c);
    {
        char message[320];
        snprintf(message, sizeof(message),
"STUN NAT level: %d (mapping %s, other port %s, other address %s; "
                 "server honours change-request: port %s, address %s; "
                 "local %s mapped %s no_nat %d)",
                 level, !s->mapped_seen ? "unmeasured" : s->mapped_same ? "stable" : "per-destination",
                 s->port_changed ? "answered" : "no reply",
                 s->ip_changed ? "answered" : "no reply", port_evidence ? "yes" : "unknown",
                 ip_evidence ? "yes" : "unknown",
                 local_text, mapped_text, s->no_nat);
        emit(c, FASTP2P_EVENT_TUNNEL, 0, 0, message);
    }
    if (c->ws && c->login_ok)
        report_nat(c);
}
static void nat_stun_start(fastp2p_client *c, uint64_t now) {
    nat_stun *s = &c->stun;
    if (s->phase || !c->stun_count || !c->ws || !c->login_ok ||
        /* The probe measures this host's IPv4 mapping, which the STUN servers
         * answer independently of the address family the control connection uses:
         * tying it to the gateway family skipped the measurement on a v6-only path
         * and reported an open host as "unknown". A host without IPv4 simply gets
         * no reply, which leaves the verdict undetermined as before. */
        now < c->udp_filter.next_at)
        return;
    if (c->nat[OP_FAM_V4].type != NAT_CONE && c->nat[OP_FAM_V4].type != NAT_UNKNOWN)
        return; /* symmetric is already NAT4, no stranger test needed */
    *s = (nat_stun){.fd = -1, .mapped_same = 1};
    int resolved = 0;
    for (int i = 0; i < c->stun_count; ++i) {
        op_addr address;
        if (!(resolve_any_families(c->stun_host[i], c->stun_port[i], FAM_V4, &address, NULL) & FAM_V4))
            continue;
        s->addr[resolved++] = address;
    }
    if (!resolved) {
        nat_stun_finish(c, mono());
        return;
    }
    s->count = resolved;
    /* Now that a server address exists, ask the kernel which source address it
     * would use towards it: with an IPv6-only control path local_ip[v4] is
     * otherwise empty and the open-host comparison has nothing to compare. */
    if (!addr_text_set(c->local_ip[OP_FAM_V4])) {
        op_socket probe = socket_bound(1, NULL, 0, 0);
        if (probe >= 0) {
            if (!op_connect(probe, &s->addr[0].u.sa, s->addr[0].len)) {
                op_addr source;
                memset(&source, 0, sizeof(source));
                if (!op_addr_socketname(probe, &source) && op_addr_family(&source) == AF_INET)
                    op_addr_text(&source, c->local_ip[OP_FAM_V4], sizeof(c->local_ip[OP_FAM_V4]));
            }
            op_close(probe);
        }
    }
    s->server = 0;
    s->phase = 1;
    /* A listener on public_port already owns the mapping the operator forwards, so
     * probe from that socket: classifying an ephemeral port would describe a port no
     * firewall rule can name, and the verdict would be about the wrong mapping. */
    if (c->udp_listener[OP_FAM_V4] >= 0) {
        s->fd = c->udp_listener[OP_FAM_V4];
        s->shared = 1;
    } else {
        s->fd = socket_bound(1, NULL, 0, 0);
    }
    if (s->fd < 0) {
        nat_stun_finish(c, mono());
        return;
    }
    nat_stun_send(c);
}
/* A reply is handed in by whoever owns the socket: the probe reads its own socket
 * when it has one, and the peer listener passes replies over when the probe borrowed
 * it, which is the case whenever a listener owns public_port. Returns 1 when the
 * datagram was a matching reply. */
static int nat_stun_input(fastp2p_client *c, const uint8_t *data, size_t length,
                          const op_addr *from, uint64_t now) {
    nat_stun *s = &c->stun;
    fp_stun_mapped mapped;
    if (!fp_stun_response(data, length, s->tid, &mapped) || !mapped.valid)
        return 0;
    if (s->phase == 1) {
        if (mapped.has_alternate && op_addr_family(&mapped.alternate) == AF_INET) {
            /* Only the address or port actually offered by the server can be
             * used to interpret a missing filtering reply. */
            s->ip_supported |= !same_ip(&mapped.alternate, &s->addr[s->server]);
            s->port_supported |= op_addr_port(&mapped.alternate) != op_addr_port(&s->addr[s->server]);
        }
        if (!s->mapped_seen) {
            op_addr_copy(&s->mapped, &mapped.address);
            s->mapped_seen = 1;
            /* A symmetric NAT changes the mapped *port* per destination, so the
             * comparison has to include it - op_addr_equal deliberately compares
             * endpoints without the port. */
        } else if (!same_ip(&mapped.address, &s->mapped) ||
                   op_addr_port(&mapped.address) != op_addr_port(&s->mapped)) {
            s->mapped_same = 0;
        }
    }
    /* The reply's source is the evidence, not the payload. Address and port are
     * judged separately: a CHANGE-REQUEST answer may come from another address,
     * another port, or both. */
    if (s->phase != 1 && op_addr_family(from) == op_addr_family(&s->addr[s->server])) {
        if (op_addr_port(from) != op_addr_port(&s->addr[s->server])) {
            s->port_changed = 1;
            s->port_supported = 1;
        }
        if (!same_ip(from, &s->addr[s->server])) {
            s->ip_changed = 1;
            s->ip_supported = 1;
        }
    }
    /* Advance to the next variant, and to the next server once this one has
     * answered all three: the cross-server comparison is what separates cone from
     * symmetric. */
    ++s->phase;
    if (s->phase > 3) {
        ++s->server;
        s->phase = 1;
    }
    if (s->server >= s->count) {
        nat_stun_finish(c, now);
        return 1;
    }
    s->retried = 0;
    nat_stun_send(c);
    return 1;
}
static void nat_stun_step(fastp2p_client *c, uint64_t now) {
    nat_stun *s = &c->stun;
    if (!s->phase)
        return;
    if (s->fd >= 0 && !s->shared) {
        uint8_t data[1024];
        op_addr from;
        memset(&from, 0, sizeof(from));
        from.len = (op_socklen)sizeof(from.u.storage);
        op_ssize received =
            op_recvfrom(s->fd, data, sizeof(data), MSG_DONTWAIT, &from.u.sa, &from.len);
        if (received > 0 && nat_stun_input(c, data, (size_t)received, &from, now))
            return;
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
    s->retried = 0;
    /* A server that missed the initial binding cannot measure filtering. */
    if (s->phase == 1 || s->phase == 3) {
        ++s->server;
        s->phase = 1;
    } else
        ++s->phase;
    if (s->server >= s->count) {
        nat_stun_finish(c, now);
        return;
    }
    nat_stun_send(c);
}
/* NAT level combines the mapping and filtering observations. 5 denotes a
 * cone-shaped mapping whose filtering has yet to be measured. */
/* TCP level: the mapping settles symmetric, the callback probe settles the cones. */
static int tcp_nat_level(const fastp2p_client *c) {
    const fp_tcp_family *k = &c->tcp_nat.family[OP_FAM_V4];
    if (k->type == FP_NAT_DEPENDENT)
        return 4;
    /* Nothing is translated means there is no filtering level to describe either.
     * The same evidence the UDP path uses settles it - the mapped address equals one
     * of our interface addresses - and unlike the callback probe it does not depend
     * on a server that dials back, which a plain STUN server never does. */
    if (k->type == FP_NAT_STABLE && k->samples && mapped_is_local_address(c, &k->mapped[0]))
        return 6;
    /* The TCP mapping probe needs a reachable echo server. When it never got a
     * sample - the IPv4 rendezvous is unreachable from this host - the UDP verdict
     * still says whether the interface itself is translated, and TCP shares it. */
    /* The UDP verdict describes the same interface: no translation at all (6) or
     * no translation with a filtering firewall (7) both mean TCP shares that path
     * and its "level" would describe a firewall rule, not a NAT mapping. */
    int udp_level = nat_filter_level(&c->udp_filter, mono());
    if (udp_level == 6 || udp_level == 7)
        return udp_level;
    return nat_filter_level(&c->tcp_filter, mono());
}
static int nat_level(const fastp2p_client *c) {
    const nat_discovery *n = &c->nat[OP_FAM_V4];
    if (n->type == NAT_UNKNOWN) {
        /* The gateway probe only settles the mapping when its IPv4 rendezvous is
         * reachable. A host on an IPv6-only path, or behind a carrier that drops
         * that route, still has a measurable translation: STUN reports the same
         * mapping from an outside observer, including "no translation at all" for
         * a host whose NIC carries the public address. Reporting "unknown" there
         * hid a perfectly open host, so fall back to the STUN verdict. */
        return nat_filter_level(&c->udp_filter, mono());
    }
    if (n->type != NAT_CONE)
        return 4;
    /* An external STUN observer settles it without needing a second node. Levels
     * 6 and 7 mean "no NAT in the path": 6 is an open host, 7 a symmetric UDP
     * firewall, and both are decided from the local-versus-mapped comparison. */
    int level = nat_filter_level(&c->udp_filter, mono());
    if (level)
        return level;
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
static int local_family_routable(const op_addr *gateway, int family, char source[OP_ADDR_TEXT]) {
    source[0] = 0;
    if (!gateway || !gateway->len || op_family_index(op_addr_family(gateway)) != family)
        return 0;
    op_socket fd = op_socket_open(op_index_family(family), SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    int usable = op_connect(fd, &gateway->u.sa, gateway->len) == 0;
    if (usable) {
        op_addr local;
        usable = !op_addr_socketname(fd, &local) && !op_addr_text(&local, source, OP_ADDR_TEXT);
        if (usable && family == OP_FAM_V6)
            usable = !IN6_IS_ADDR_LINKLOCAL(&local.u.in6.sin6_addr) &&
                     !IN6_IS_ADDR_UNSPECIFIED(&local.u.in6.sin6_addr);
        else if (usable)
            usable = local.u.in.sin_addr.s_addr != 0;
    }
    op_close(fd);
    if (!usable)
        source[0] = 0;
    return usable;
}
/* Recompute which families this host can actually use toward the gateway. Called
 * at start and again before every connection attempt: a service that starts
 * before IPv6 is usable would otherwise advertise IPv4-only for its whole
 * lifetime, and a host that loses a family would keep claiming it. */
static int refresh_families(fastp2p_client *c) {
    /* A public destination per family, used only for a route lookup (connect() on a
     * UDP socket sends nothing). This is what a data-plane peer would need, and it
     * is deliberately not the gateway: publishing the gateway-reachable set made a
     * host whose IPv4 gateway route is filtered advertise IPv6 only, so every
     * IPv4 peer had no family in common and fell back to the relay. */
    static const char *probe_text[OP_FAM_COUNT] = {"8.8.8.8:53", "[2001:4860:4860::8888]:53"};
    int wanted = 0;
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        if (local_family_routable(&c->gateway_addr[family], family, c->local_ip[family])) {
            wanted |= family_bit(family);
            continue;
        }
        op_addr probe;
        memset(&probe, 0, sizeof(probe));
        if (op_addr_from_text(&probe, probe_text[family], 53) == 0 &&
            local_family_routable(&probe, family, c->local_ip[family]))
            wanted |= family_bit(family);
    }
    if (!wanted)
        /* Nothing verified at all: keep the family the name resolved to so the
         * client still attempts the historical path instead of refusing to run. */
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
    /* SPEC 搂7: a gateway host may now be an IPv6 literal; every other character
     * still has to be a name character, so the old rejection of odd hosts is
     * unchanged. */
    if (!valid_gateway_host(c->host)) {
        free(c);
        return FASTP2P_EINVAL;
    }
    c->port = cfg->gateway_port ? cfg->gateway_port : 27183;
    c->public_port = c->requested_public_port = cfg->public_port;
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
        c->listener[family] = c->udp_listener[family] = -1;
        c->nat[family].fd = c->nat[family].fd2 = -1;
        c->nat[family].phase = 0;
    }
    fp_tcp_nat_init(&c->tcp_nat);
    c->stun.fd = -1;
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
void fp_client_set_ca_pem(fastp2p_client *c, const char *pem) { c->ca_pem = pem; }

void fp_client_set_auto_port_mapping(fastp2p_client *c, int enabled) { c->auto_port_mapping = enabled; }

void fp_client_set_tls_alias(fastp2p_client *c, const char *hostname, const char *pem) {
    c->tls_host = hostname;
    c->ca_pem = pem;
}
int fastp2p_client_set_config_handler(fastp2p_client *c,fastp2p_config_handler handler,void *user) {
    if(!c || c->running || c->in_callback)return FASTP2P_ESTATE;
    c->config_handler=handler;c->config_user=user;return FASTP2P_OK;
}
int fastp2p_client_set_restart_handler(fastp2p_client *c, fastp2p_restart_handler handler, void *user) {
    if (!c || c->running || c->in_callback)
        return FASTP2P_ESTATE;
    c->restart_handler = handler;
    c->restart_user = user;
    return FASTP2P_OK;
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
            op_addr bind_address;
            if (op_addr_from_text(&bind_address, a->bind_ip, f->local_port))
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
            a->fd = c->validate_only ? -1 : socket_bound_addr(a->udp, &bind_address, a->port, 0);
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
int fp_client_sdwan_config(fastp2p_client *c, json_object *config) {
#if defined(__linux__) || defined(_WIN32)
    fp_sdwan *state = malloc(sizeof(*state));
    if (!state)
        return FASTP2P_EIO;
    if (fp_sdwan_parse(state, config)) {
        free(state);
        return FASTP2P_EINVAL;
    }
    unsigned available = 0;
    for (int i = 0; i < NA; ++i)
        available += !c->apps[i].used;
    if (state->central && !strcmp(state->center, c->node))
        state->center_index = FP_SDWAN_LOCAL;
    for (unsigned i = 0; i < state->peer_count; ++i) {
        const char *peer = state->peers[i].node;
        if (!valid_node(peer) || !strcmp(c->node, peer)) {
            free(state);
            return FASTP2P_EINVAL;
        }
        if (state->central && !strcmp(state->center, peer))
            state->center_index = (int)i;
    }
    unsigned needed = !state->central || state->center_index == FP_SDWAN_LOCAL ? state->peer_count :
                      state->center_index >= 0 ? 1 : 0;
    if (needed > available ||
        (state->central && state->center[0] && state->center_index == FP_SDWAN_NO_ROUTE)) {
        free(state);
        return FASTP2P_EINVAL;
    }
    int slot = 0;
    for (unsigned i = 0; i < state->peer_count; ++i) {
        if (state->central && state->center_index != FP_SDWAN_LOCAL && state->center_index != (int)i)
            continue;
        while (c->apps[slot].used)
            ++slot;
        fp_sdwan_peer *peer = &state->peers[i];
        peer->app_index = slot;
        app *a = &c->apps[slot++];
        *a = (app){.used = 1, .local = 1, .sdwan = 1, .fd = -1, .tunnel_index = -1,
                   .transport = FASTP2P_TRANSPORT_QUIC, .id = random_id()};
        strcpy(a->peer, peer->node);
    }
    c->sdwan = state;
    return FASTP2P_OK;
#else
    (void)c;
    (void)config;
    return FASTP2P_EINVAL;
#endif
}

int fastp2p_client_attach_sdwan_tun(fastp2p_client *c, int fd) {
    if (!c || c->in_callback || c->running)
        return FASTP2P_ESTATE;
    return fp_sdwan_attach(c->sdwan, fd) ? FASTP2P_EINVAL : FASTP2P_OK;
}

static void tick_sdwan(fastp2p_client *c) {
    fp_sdwan *state = c->sdwan;
    if (!fp_sdwan_active(state))
        return;
    for (int i = 0; i < 32; ++i) {
        uint8_t packet[FP_SDWAN_MTU];
        int length = fp_sdwan_read(state, packet);
        if (length <= 0)
            break;
        uint32_t source, destination;
        if (fp_sdwan_ipv4(packet, (size_t)length, &source, &destination) ||
            fp_sdwan_owner(state, source) != FP_SDWAN_LOCAL)
            continue;
        int owner = fp_sdwan_owner(state, destination);
        if (owner < 0)
            continue;
        sdwan_send(c, owner, packet, (size_t)length);
    }
}

int fastp2p_client_start(fastp2p_client *c) {
    if (!c || c->in_callback || c->running || c->multi)
        return FASTP2P_ESTATE;
    op_once_run(&curl_once, initialize_curl);
    if (curl_initialization != CURLE_OK)
        return FASTP2P_EIO;
    /* SPEC 搂7: resolve both families. Probe every family this host can actually
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
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used && c->apps[i].local && !c->apps[i].sdwan && c->apps[i].fd < 0) {
            app *a = &c->apps[i];
            a->fd = socket_bound(a->udp, a->bind_ip, a->port, 0);
            if (a->fd < 0 || (!a->udp && op_listen(a->fd, 64))) {
                fastp2p_client_stop(c);
                return FASTP2P_EIO;
            }
        }
    int listener_error = start_peer_listeners(c);
    if (listener_error) {
        char message[160];
        if (c->public_port)
            snprintf(message, sizeof(message), "Cannot listen on configured TCP peer port %u: %s",
                     (unsigned)c->public_port, strerror(listener_error));
        else
            snprintf(message, sizeof(message), "Cannot listen on a TCP peer port in 1024鈥?999: %s",
                     strerror(listener_error));
        emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, message);
        fastp2p_client_stop(c);
        return FASTP2P_EIO;
    }
    char peer_port_message[64];
    snprintf(peer_port_message, sizeof(peer_port_message), "%s peer listener port: %u",
             has_udp_listener(c) ? "TCP/UDP" : "TCP", (unsigned)c->public_port);
    emit(c, FASTP2P_EVENT_TUNNEL, 0, 0, peer_port_message);
    c->multi = curl_multi_init();
    if (!c->multi) {
        fastp2p_client_stop(c);
        return FASTP2P_EIO;
    }
    if (c->sdwan) {
        const char *error = fp_sdwan_start(c->sdwan);
        if (error) {
            emit(c, FASTP2P_EVENT_ERROR, 0, FASTP2P_EIO, error);
            fastp2p_client_stop(c);
            return FASTP2P_EIO;
        }
        emit(c, FASTP2P_EVENT_TUNNEL, 0, 0, "SD-WAN TUN interface ready");
    }
    c->running = 1;
    if (c->auto_port_mapping && !c->validate_only)
        c->port_mapping = fp_port_mapping_start(c->listener[OP_FAM_V4] >= 0 ? c->public_port : 0,
                                                c->udp_listener[OP_FAM_V4] >= 0 ? c->public_port : 0);
    if (c->port_mapping && c->udp_listener[OP_FAM_V4] >= 0)
        c->port_mapping_wait_until = mono() + 4 * NS;
    fp_tcp_nat_prepare(&c->tcp_nat, c->gateway_addr, c->families_wanted);
    c->stopping = 0;
    c->reconnect_at = 0;
    c->nat_settled = 0;
    snprintf(c->ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", "0.0.0.0");
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
    if (c->upgrade_stop_at &&
        (!op_buffer_size(&c->ws_tx) || mono() >= c->upgrade_stop_at)) {
        c->upgrade_stop_at = 0;
        c->stopping = 1;
    }
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
    /* Start and refresh the filter measurements after login. */
    nat_stun_start(c, now);
    nat_stun_step(c, now);
    /* TCP filtering probe: same window, verdict arrives asynchronously. */
    /* server.len is only known after the probe resolves its server, so the ports
     * configured text is what says a probe is wanted. */
    if (!c->tcp_level.phase && c->tcp_level.server_port && c->ws && c->login_ok &&
        now >= c->tcp_filter.next_at) {
        c->tcp_level.attempt = 0;
        /* The probe has to originate from the business port: only that mapping is
         * named by an operator firewall rule, so a callback to any other port is
         * dropped and the verdict would describe a port nobody can open. Release
         * the TCP listener for the probe window and rebuild it below. */
        c->tcp_relisten = 0;
        if (c->public_port && c->listener[OP_FAM_V4] >= 0 &&
            now - c->tcp_handoff_at >= NAT_FILTER_REFRESH) {
            close_peer_listeners(c->listener);
            c->tcp_relisten = 1;
            c->tcp_handoff_at = now;
        }
    c->tcp_level.fixed_port = (uint16_t)c->public_port;
        fp_tcp_level_start(&c->tcp_level);
    }
    fp_tcp_level_step(&c->tcp_level, now);
    if (c->tcp_level.phase == 4) {
        char message[128];
        snprintf(message, sizeof(message),
                 "TCP NAT level: %d (callbacks accepted=%d same-port=%d other-ip=%d)",
                 c->tcp_level.level, c->tcp_level.accepted, c->tcp_level.same_port,
                 c->tcp_level.other_ip);
        emit(c, FASTP2P_EVENT_TUNNEL, 0, 0, message);
        nat_filter_record(&c->tcp_filter, c->tcp_level.level, mono());
        if (c->tcp_relisten) {
            c->tcp_relisten = 0;
            if (bind_peer_listeners(c, c->public_port, 0))
                emit(c, FASTP2P_EVENT_TUNNEL, 0, 0,
                     "TCP peer listener could not be restored after the probe");
        }
        c->tcp_level.phase = 0;
        if (c->ws && c->login_ok)
            report_nat(c);
    }
    tick_accept(c, now);
    tick_port_mapping(c);
    tick_udp_listeners(c, now);
    for (int i = 0; i < NT; ++i)
        tick_tunnel(c, i, now);
    tick_relays(c, now);
    tick_apps(c, now);
    tick_sdwan(c);
    report_sdwan(c, now);
    tick_socks(c, now);
    tick_overlays(c, now);
    if (wait_ms > 10)
        wait_ms = 10;
    if (wait_ms) {
        struct curl_waitfd extra[2] = {{0}};
        unsigned count = 0;
        if (c->ws_connected) {
            extra[count].fd = c->ws_socket;
            extra[count].events = CURL_WAIT_POLLIN;
            if (op_buffer_size(&c->ws_tx))
                extra[count].events |= CURL_WAIT_POLLOUT;
            ++count;
        }
        if (c->sdwan && c->sdwan->fd >= 0)
            extra[count++] = (struct curl_waitfd){.fd = (curl_socket_t)c->sdwan->fd, .events = CURL_WAIT_POLLIN};
        int events;
        curl_multi_poll(c->multi, extra, count, (int)wait_ms, &events);
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
    if (c->sdwan)
        fp_sdwan_stop(c->sdwan);
    fp_port_mapping_stop(c->port_mapping);
    c->port_mapping = NULL;
    c->mapped_listener = (fp_mapped_ports){0};
    c->port_mapping_wait_until = 0;
    fp_tcp_nat_close(&c->tcp_nat);
    if (c->stun.fd >= 0)
        op_close(c->stun.fd);
    c->stun = (nat_stun){.fd = -1};
    fp_tcp_level_close(&c->tcp_level);
    c->tcp_level.phase = 0;
    c->udp_filter = c->tcp_filter = (nat_filter){0};
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
    close_peer_listeners(c->listener);
    close_peer_listeners(c->udp_listener);
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
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
    free(c->sdwan);
    OPENSSL_cleanse(c, sizeof(*c));
    free(c);
}
fastp2p_state fastp2p_client_state(const fastp2p_client *c) {
    return c ? c->state : FASTP2P_STOPPED;
}
uint16_t fastp2p_client_public_port(const fastp2p_client *c) {
    return c && c->running ? c->public_port : 0;
}
const char *fastp2p_client_last_error(const fastp2p_client *c) {
    return c ? c->error : "invalid client";
}
