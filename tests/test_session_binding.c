/* Exercise the private state machine with reordered control-plane delivery.
 * Including it here keeps the production C ABI unchanged. */
#define fp_sdwan_write capture_sdwan_write
#include "../src/client.c"
#undef fp_sdwan_write
#include <assert.h>

static uint8_t sdwan_packet[FP_SDWAN_MTU];
static size_t sdwan_packet_size;

void capture_sdwan_write(fp_sdwan *state, const uint8_t *packet, size_t length) {
    assert(fp_sdwan_active(state));
    assert(length <= sizeof(sdwan_packet));
    memcpy(sdwan_packet, packet, length);
    sdwan_packet_size = length;
}

static fastp2p_client *fixture(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    strcpy(c->node, "receiver-node");
    c->node_id = op_node_id(c->node);
    return c;
}
static void dispose(fastp2p_client *c) {
    for (int i = 0; i < NT; ++i)
        if (c->tunnels[i].state)
            close_tunnel(c, i, NULL);
    op_buffer_clear(&c->ws_tx);
    free(c);
}
static int receiver(fastp2p_client *c, uint64_t id, uint16_t local_port, int active) {
    int ti = new_tunnel(c, "sender-node", id, FASTP2P_TRANSPORT_QUIC, 0);
    assert(ti >= 0);
    c->tunnels[ti].state = active ? T_ACTIVE : T_QUIC;
    c->tunnels[ti].local_port = local_port;
    return ti;
}
static void deliver(fastp2p_client *c, uint16_t sub, json_object *j) {
    op_buffer b = {0};
    uint8_t header[16];
    op_put64(header, op_node_id("sender-node"));
    op_put64(header + 8, c->node_id);
    const char *body = json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN);
    assert(!op_buffer_add(&b, header, 16, OP_FRAME_LIMIT));
    assert(!op_buffer_add(&b, body, strlen(body), OP_FRAME_LIMIT));
    control_message(c, 3, sub, b.data, b.len);
    op_buffer_clear(&b);
}
static void key(fastp2p_client *c, uint64_t id, uint64_t session, uint16_t mapped_port,
                const uint8_t secret[FP_SESSION_SECRET]) {
    json_object *j = json_object_new_object();
    char hex[FP_SESSION_SECRET * 2 + 1];
    secret_to_hex(secret, hex);
    op_js(j, "peer", "sender-node");
    op_js(j, "transport", "quic");
    op_js(j, "secret", hex);
    op_ju(j, "session", session);
    op_ju(j, "tunnelID", id);
    op_ju(j, "peerPort", mapped_port);
    deliver(c, PUSH_SESSION, j);
    json_object_put(j);
}
static void exact_connection(void) {
    fastp2p_client *c = fixture();
    uint8_t secret[FP_SESSION_SECRET] = {1};
    int old = receiver(c, 100, 41000, 1);
    int live = receiver(c, UINT64_C(0xfedcba9876543210), 42000, 1);
    /* NAT maps live:42000 to :41000, coincidentally an older attempt's port. */
    key(c, c->tunnels[live].id, 999, 41000, secret);
    assert(!c->tunnels[old].keyed);
    assert(c->tunnels[live].keyed && c->tunnels[live].session == 999);
    fp_crypto sender;
    assert(!fp_crypto_init(&sender, secret, 999, op_node_id("sender-node"), c->node_id, 1));
    uint8_t sealed[80], plain[80];
    size_t n, size;
    assert(!fp_seal(&sender, TUN_CERT_BIND, 0, secret, 32, sealed, sizeof(sealed), &n));
    assert(!fp_open(&c->tunnels[live].crypto, TUN_CERT_BIND, 0, sealed, n, plain, sizeof(plain), &size));
    assert(size == 32 && !memcmp(plain, secret, size));
    dispose(c);
}

static void reordered_and_duplicate_keys(void) {
    fastp2p_client *c = fixture();
    uint8_t secret[FP_SESSION_SECRET] = {2}, other[FP_SESSION_SECRET] = {3};
    int old = receiver(c, 100, 41000, 1);
    int live = receiver(c, 200, 42000, 0);
    key(c, 200, 999, 62000, secret); /* key before HELLO_ACK */
    key(c, 200, 111, 42000, other);  /* conflicting push before HELLO_ACK */
    key(c, 100, 888, 42000, other);  /* delayed old attempt, misleading port */
    assert(c->tunnels[old].session == 888);
    assert(!c->tunnels[live].keyed);
    tunnel_active(c, live);
    assert(c->tunnels[live].session == 999 && c->tunnels[live].keyed);

    uint8_t sealed[80], plain[80];
    size_t n, size;
    fp_crypto sender;
    assert(!fp_crypto_init(&sender, secret, 999, op_node_id("sender-node"), c->node_id, 1));
    assert(!fp_seal(&sender, TUN_DATA, 0, "data", 4, sealed, sizeof(sealed), &n));
    assert(!fp_open(&c->tunnels[live].crypto, TUN_DATA, 0, sealed, n, plain, sizeof(plain), &size));
    assert(!fp_seal(&c->tunnels[live].crypto, TUN_DATA, 0, "reply", 5, plain, sizeof(plain), &size));
    key(c, 200, 999, 62000, secret); /* identical push is idempotent */
    key(c, 200, 111, 42000, other);  /* conflicting push cannot rekey */
    assert(c->tunnels[live].session == 999 && c->tunnels[live].crypto.tx_seq == 1);
    assert(fp_open(&c->tunnels[live].crypto, TUN_DATA, 0, sealed, n, plain, sizeof(plain), &size) == -1);
    key(c, 0, 222, 42000, other);   /* no identifier: never guess by port */
    key(c, 300, 333, 42000, other); /* unknown/expired identifier */
    assert(c->tunnels[live].session == 999);
    dispose(c);
}

static void acknowledgement_and_certificate(void) {
    fastp2p_client *c = fixture();
    int ti = new_tunnel(c, "sender-node", 200, FASTP2P_TRANSPORT_QUIC, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    t->state = T_ACTIVE;
    app *a = &c->apps[0];
    a->used = a->local = 1;
    a->tunnel_index = ti;
    strcpy(a->peer, "sender-node");
    a->transport = FASTP2P_TRANSPORT_QUIC;
    json_object *j = json_object_new_object();
    op_ju(j, "session", t->session);
    op_ju(j, "tunnelID", 100);
    deliver(c, PUSH_SESSION_ACK, j);
    assert(!t->key_acked && !a->synced);
    op_ju(j, "tunnelID", 200);
    deliver(c, PUSH_SESSION_ACK, j);
    json_object_put(j);
    assert(t->key_acked && !a->synced && !tunnel_ready(t));

    uint8_t digest[32], sealed[80];
    size_t n;
    fp_crypto peer;
    assert(!opq_identity_digest(digest));
    assert(!fp_crypto_init(&peer, t->secret, t->session, c->node_id, t->peer_id, 0));
    assert(!fp_seal(&peer, TUN_CERT_BIND, 0, digest, sizeof(digest), sealed, sizeof(sealed), &n));
    tunnel_message(c, ti, TUN_CERT_BIND, sealed, n);
    assert(t->cert_checked && a->synced && tunnel_ready(t));
    dispose(c);
}

static void retries_use_fresh_keys(void) {
    fastp2p_client *c = fixture();
    app a = {0};
    int first = app_tunnel(c, &a, "sender-node", FASTP2P_TRANSPORT_QUIC);
    assert(first >= 0);
    uint64_t previous = a.session;
    uint8_t secret[FP_SESSION_SECRET];
    memcpy(secret, a.secret, sizeof(secret));
    close_tunnel(c, first, NULL);
    assert(app_tunnel(c, &a, "sender-node", FASTP2P_TRANSPORT_QUIC) >= 0);
    assert(a.session != previous && memcmp(secret, a.secret, sizeof(secret)));
    dispose(c);
}

static void sdwan_ingress_reaches_active_adapter(void) {
    fastp2p_client *c = fixture();
    int ti = receiver(c, 200, 42000, 1);
    uint8_t secret[FP_SESSION_SECRET] = {4};
    key(c, 200, 999, 62000, secret);
    c->tunnels[ti].key_acked = 1;
    c->tunnels[ti].cert_checked = 1;
    assert(tunnel_ready(&c->tunnels[ti]));
    strcpy(c->apps[0].peer, "sender-node");

    fp_sdwan sdwan = {
        .fd = -1,
        .peer_count = 1,
        .peers = {{.app_index = 0}},
        .route_count = 2,
        .routes = {{.network = 0x0a030214, .bits = 32, .owner = 0},
                   {.network = 0x0a03020a, .bits = 32, .owner = FP_SDWAN_LOCAL}}
    };
    c->sdwan = &sdwan;
    const uint8_t packet[28] = {
        0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 10, 3, 2, 20, 10, 3, 2, 10
    };
    fp_crypto peer;
    assert(!fp_crypto_init(&peer, secret, 999, c->tunnels[ti].peer_id, c->node_id, 1));
    uint8_t sealed[80];
    size_t n;
    assert(!fp_seal(&peer, TUN_SDWAN_IPV4, 0, packet, sizeof(packet), sealed, sizeof(sealed), &n));
    sdwan_packet_size = 0;
    tunnel_message(c, ti, TUN_SDWAN_IPV4, sealed, n);
    assert(!sdwan_packet_size);

#ifdef _WIN32
    /* An active Wintun session has no POSIX file descriptor. */
    sdwan.windows = (struct fp_sdwan_windows *)(void *)&sdwan;
#else
    sdwan.fd = 0;
#endif
    assert(!fp_seal(&peer, TUN_SDWAN_IPV4, 0, packet, sizeof(packet), sealed, sizeof(sealed), &n));
    tunnel_message(c, ti, TUN_SDWAN_IPV4, sealed, n);
    assert(sdwan_packet_size == sizeof(packet) && !memcmp(sdwan_packet, packet, sizeof(packet)));
    c->sdwan = NULL;
    dispose(c);
}

static void relay_cannot_steal_direct_rule(void) {
    fastp2p_client *c = fixture();
    int direct = new_tunnel(c, "sender-node", 200, FASTP2P_TRANSPORT_TCP, 1);
    assert(direct >= 0);
    c->tunnels[direct].state = T_ACTIVE;
    c->tunnels[direct].key_acked = 1;
    app *a = &c->apps[0];
    a->used = a->local = a->synced = 1;
    a->transport = FASTP2P_TRANSPORT_TCP;
    a->tunnel_index = direct;
    strcpy(a->peer, "sender-node");
    /* The same endpoint opens another hop because we relay for a third node. */
    int hop = new_tunnel(c, "sender-node", 300, FASTP2P_TRANSPORT_TCP, 0);
    assert(hop >= 0);
    tunnel_active(c, hop);
    assert(a->tunnel_index == direct && a->synced);
    c->tunnels[hop].relay_link = 0;
    c->tunnels[hop].relay_ready = 1;
    assert(active_tunnel(c, "sender-node", FASTP2P_TRANSPORT_TCP) == direct);
    close_tunnel(c, direct, NULL);
    assert(active_tunnel(c, "sender-node", FASTP2P_TRANSPORT_TCP) == -1);
    dispose(c);
}

static void relay_endpoint_shares_only_with_the_logical_peer(void) {
    fastp2p_client *c = fixture();
    app session = {0};
    session.session = 999; session.transport = FASTP2P_TRANSPORT_TCP;
    int ti = relay_tunnel(c, &session, "relay-node", "sender-node", 1);
    assert(ti >= 0);
    c->tunnels[ti].state = T_ACTIVE;
    c->tunnels[ti].relay_ready = 1;
    for (int i = 0; i < 2; ++i) {
        app *a = &c->apps[i];
        a->used = a->local = 1;
        a->tunnel_index = -1;
        a->transport = FASTP2P_TRANSPORT_TCP;
        strcpy(a->peer, "sender-node");
    }
    session_ready(c, ti);
    assert(c->apps[0].synced && c->apps[1].synced);
    assert(c->apps[0].tunnel_index == ti && c->apps[1].tunnel_index == ti);
    assert(active_tunnel(c, "sender-node", FASTP2P_TRANSPORT_TCP) == ti);
    assert(active_tunnel(c, "relay-node", FASTP2P_TRANSPORT_TCP) == -1);
    dispose(c);
}
static void relay_requests_are_shared_and_expire(void) {
    fastp2p_client *c = fixture();
    c->state = FASTP2P_ONLINE; c->force_relay = c->running = 1;
    c->ws = (CURL *)(uintptr_t)1; /* ws_frame only queues bytes in this test. */
    for (int i = 0; i < 6; ++i) {
        app *a = &c->apps[i];
        a->used = a->local = 1; a->tunnel_index = a->fd = -1;
        a->transport = i < 3 ? FASTP2P_TRANSPORT_TCP : FASTP2P_TRANSPORT_QUIC;
        strcpy(a->peer, "sender-node");
    }
    tick_apps(c, mono());
    int count = 0;
    uint16_t main, sub; uint8_t *body; size_t size;
    while (op_frame_take(&c->ws_tx, &main, &sub, &body, &size) > 0) {
        assert(main == 5 && sub == 0); ++count; free(body);
    }
    assert(count == 2); /* One request for each logical peer/transport pair. */
    c->state = 0;
    for (int i = 0; i < 6; ++i) c->apps[i].link_deadline = mono() - 1;
    tick_apps(c, mono());
    for (int i = 0; i < 6; ++i) assert(!c->apps[i].relay_requested);
    c->ws = NULL;
    dispose(c);
}

static void failed_relay_can_be_reselected(void) {
    fastp2p_client *c = fixture();
    c->state = FASTP2P_ONLINE; c->force_relay = c->running = 1;
    c->ws = (CURL *)(uintptr_t)1;
    app *a = &c->apps[0];
    a->used = a->local = 1;
    a->fd = -1;
    a->transport = FASTP2P_TRANSPORT_TCP;
    strcpy(a->peer, "sender-node");
    int ti = relay_tunnel(c, a, "relay-node", a->peer, 1);
    assert(ti >= 0);
    a->tunnel_index = ti;
    close_tunnel(c, ti, NULL);

    uint64_t now = a->retry;
    tick_apps(c, now);
    uint16_t main, sub;
    uint8_t *body;
    size_t length;
    assert(op_frame_take(&c->ws_tx, &main, &sub, &body, &length) > 0);
    assert(main == 5 && sub == 0);
    json_object *request = op_json(body, length);
    json_object *exclude = op_get(request, "exclude");
    assert(exclude && !strcmp(json_object_get_string(json_object_array_get_idx(exclude, 0)), "relay-node"));
    json_object_put(request);
    free(body);

    tick_apps(c, now + 32 * NS);
    assert(op_frame_take(&c->ws_tx, &main, &sub, &body, &length) > 0);
    assert(main == 5 && sub == 0);
    request = op_json(body, length);
    assert(request && !op_get(request, "exclude"));
    json_object_put(request);
    free(body);
    c->ws = NULL;
    dispose(c);
}

static void expired_nat_probes_release_sockets(void) {
    fastp2p_client *c = fixture();
    c->families_wanted = FAM_V4 | FAM_V6;
    uint64_t now = mono();
    for (int advisory_first = 0; advisory_first < 2; ++advisory_first) {
        int index = new_tunnel(c, "sender-node", UINT64_C(41000) + advisory_first,
                               FASTP2P_TRANSPORT_QUIC, 0);
        assert(index >= 0);
        tunnel *t = &c->tunnels[index];
        op_socket primary = socket_bound(1, "127.0.0.1", 0, BIND_DEFAULT);
        op_socket advisory = socket_bound(1, "127.0.0.1", 0, BIND_DEFAULT);
        assert(primary >= 0 && advisory >= 0);
        t->state = T_PROBE;
        t->deadline = advisory_first ? now + NS : now - 1;
        t->probes[OP_FAM_V4] = (nat_probe){.fd = primary, .state = PROBE_UDP};
        t->probes[OP_FAM_V6] = (nat_probe){.fd = advisory, .state = PROBE_UDP, .deadline = now - 1};
        op_addr bound;
        if (advisory_first) {
            assert(probe_round(c, index, now) == 0);
            assert(op_addr_socketname(advisory, &bound));
            assert(!op_addr_socketname(primary, &bound));
            t->deadline = now - 1;
        }
        assert(probe_round(c, index, now) == -1);
        assert(op_addr_socketname(primary, &bound));
        assert(op_addr_socketname(advisory, &bound));
    }
    dispose(c);
}

static void rule_churn_reclaims_only_unused_tunnels(void) {
    fastp2p_client *c = fixture();
    uint64_t now = 100 * NS;
    for (int i = 0; i < NT; ++i) {
        int index = new_tunnel(c, "sender-node", (uint64_t)i + 1, FASTP2P_TRANSPORT_TCP, 1);
        assert(index == i);
        c->tunnels[i].state = T_ACTIVE;
    }
    for (int i = 0; i < 5; ++i)
        c->tunnels[i].detached_at = NS;
    c->tunnels[0].last_payload = now - NS;
    c->tunnels[1].relay_link = 0;
    c->tunnels[2].initiator = 0;
    c->apps[0].used = 1;
    c->apps[0].tunnel_index = 3;
    c->overlays[0].used = 1;
    c->overlays[0].app_index = -1; /* also protect incoming connections */
    c->overlays[0].tunnel_index = 4;
    c->tunnels[5].detached_at = now - NS;
    assert(reserve_tunnel_slot(c, now) == -1);
    c->tunnels[5].detached_at = 2 * NS;
    /* Detached but not acknowledged by the peer: still not reclaimable. */
    assert(reserve_tunnel_slot(c, now) == -1);
    c->tunnels[5].released = 1;
    /* An acknowledged relay session is still not ours to drop. */
    c->tunnels[6].detached_at = 2 * NS;
    c->tunnels[6].released = 1;
    c->tunnels[6].relay_wait = 1;
    assert(reserve_tunnel_slot(c, now) == 5);
    assert(c->tunnels[5].state == T_FREE);
    assert(c->tunnels[6].state == T_ACTIVE);
    for (int i = 0; i < 5; ++i)
        assert(c->tunnels[i].state == T_ACTIVE);
    c->overlays[0].used = 0;
    dispose(c);
}

static void release_request_requires_an_unused_tunnel(void) {
    fastp2p_client *c = fixture();
    int ti = new_tunnel(c, "sender-node", 700, FASTP2P_TRANSPORT_TCP, 1);
    assert(ti == 0);
    tunnel *t = &c->tunnels[ti];
    t->state = T_ACTIVE;
    t->detached_at = NS;
    uint8_t frame[8];
    op_put64(frame, t->id);
    op_buffer_clear(&t->tx);
    /* No local user: the request is acknowledged, but only the ACK releases. */
    tunnel_message(c, ti, TUN_RELEASE, frame, 8);
    assert(!t->released);
    assert(op_buffer_size(&t->tx) == 16); /* 8-byte frame header + tunnel id */
    op_buffer_clear(&t->tx);
    /* An incoming connection still uses it: no acknowledgement. */
    c->overlays[0].used = 1;
    c->overlays[0].app_index = -1;
    c->overlays[0].tunnel_index = ti;
    tunnel_message(c, ti, TUN_RELEASE, frame, 8);
    assert(!op_buffer_size(&t->tx));
    c->overlays[0].used = 0;
    /* A relay hop must never authorise a release: the session belongs to the
     * two endpoints, not to the node carrying it. */
    t->relay_link = 0;
    tunnel_message(c, ti, TUN_RELEASE, frame, 8);
    assert(!op_buffer_size(&t->tx));
    t->relay_link = -1;
    /* The peer's acknowledgement marks it reclaimable. */
    op_put64(frame, t->id);
    tunnel_message(c, ti, TUN_RELEASE_ACK, frame, 8);
    assert(t->released);
    dispose(c);
}

static int free_tcp_port(void) {
    op_socket fd = socket_bound(0, "127.0.0.1", 0, BIND_DEFAULT);
    assert(fd >= 0);
    int port = socket_port(fd);
    op_close(fd);
    return port;
}

static int port_open(int port) {
    op_addr address;
    assert(!op_addr_from_text(&address, "127.0.0.1", (uint16_t)port));
    op_socket fd = op_socket_open(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;
    int open = 0;
    if (!op_connect(fd, &address.u.sa, address.len) || errno == EINPROGRESS) {
        for (int i = 0; i < 200; ++i) {
            int rv = connect_ready(fd);
            if (rv > 0) {
                open = 1;
                break;
            }
            if (rv < 0)
                break;
            op_sleep_ms(1);
        }
    }
    op_close(fd);
    return open;
}

static void rule_json(char *out, size_t size, const char *bind_ip, int port) {
    snprintf(out, size,
             "{\"network\":{\"Node\":\"config-node\",\"ServerHost\":\"127.0.0.1\","
             "\"ServerPort\":27183,\"Token\":\"1\"},\"apps\":["
             "{\"AppName\":\"a\",\"BindIP\":\"%s\",\"SrcPort\":%d,"
             "\"PeerNode\":\"peer-node\",\"DstHost\":\"127.0.0.1\",\"DstPort\":22,"
             "\"Protocol\":\"tcp\",\"UnderlayProtocol\":\"tcp\"}],\"socks5\":[]}",
             bind_ip, port);
}

static const char *app_bind_text(const app *a, char *out, size_t size) {
    op_addr bound = {0};
    if (a->fd < 0 || op_addr_socketname(a->fd, &bound) || op_addr_text(&bound, out, size))
        return "(unbound)";
    return out;
}

/* Changing the bind address keeps the port, so the old socket must be released
 * before the new one can bind. The update has to succeed, and an aborted update
 * has to put the previous listener back. */
static void rule_update_changes_bind_address(void) {
    int port = free_tcp_port();
    char narrow[1200], wide[1200], text[OP_ADDR_TEXT];
    rule_json(narrow, sizeof(narrow), "127.0.0.1", port);
    rule_json(wide, sizeof(wide), "0.0.0.0", port);
    fastp2p_client *c = NULL;
    assert(!fastp2p_client_create_json(narrow, NULL, NULL, NULL, NULL, &c));
    c->running = 1;
    int index = -1;
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used)
            index = i;
    assert(index >= 0);
    assert(!strcmp(app_bind_text(&c->apps[index], text, sizeof(text)), "127.0.0.1"));
    assert(port_open(port));

    /* Widen the listener: the same port is held by the running rule, so on a
     * platform that refuses the overlapping bind the old socket is released
     * first. Windows accepts the pair, in which case nothing is vacated. */
    fp_rule_update *update = NULL;
    assert(!fp_client_rules_prepare(c, wide, &update));
    int widened_vacated = update->vacated_count;
    assert(widened_vacated <= 1);
    fp_client_rules_commit(update);
    index = -1;
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used)
            index = i;
    assert(index >= 0);
    assert(!strcmp(app_bind_text(&c->apps[index], text, sizeof(text)), "0.0.0.0"));
    assert(socket_port(c->apps[index].fd) == port && port_open(port));

    /* Narrow it again, then abort: the wide listener must be restored. A
     * specific address cannot be bound over a wildcard listener on any
     * platform, so this direction always exercises the release path. */
    fp_rule_update *aborted = NULL;
    assert(!fp_client_rules_prepare(c, narrow, &aborted));
    assert(aborted->vacated_count <= 1);
    assert(widened_vacated + aborted->vacated_count <= 2);
    fp_client_rules_abort(aborted);
    index = -1;
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used)
            index = i;
    assert(index >= 0);
    assert(!strcmp(app_bind_text(&c->apps[index], text, sizeof(text)), "0.0.0.0"));
    assert(port_open(port));

    /* The rollback path itself, independent of platform bind semantics: a
     * released listener is bound again when the update is abandoned. */
    fp_rule_update *rollback = NULL;
    assert(!fp_client_rules_prepare(c, wide, &rollback));
    index = -1;
    for (int i = 0; i < NA; ++i)
        if (c->apps[i].used)
            index = i;
    assert(index >= 0);
    vacate_listener(rollback, index);
    assert(c->apps[index].fd < 0);
    fp_client_rules_abort(rollback);
    assert(c->apps[index].fd >= 0);
    assert(!strcmp(app_bind_text(&c->apps[index], text, sizeof(text)), "0.0.0.0"));
    assert(port_open(port));

    /* A port owned by another process is not ours to vacate: the update fails
     * and the running listener keeps working. */
    op_socket foreign = socket_bound(0, "127.0.0.1", 0, BIND_DEFAULT);
    assert(foreign >= 0);
    int foreign_port = socket_port(foreign);
    assert(!op_listen(foreign, 4));
    char blocked[1200];
    rule_json(blocked, sizeof(blocked), "127.0.0.1", foreign_port);
    fp_rule_update *rejected = NULL;
    assert(fp_client_rules_prepare(c, blocked, &rejected) < 0);
    assert(!rejected);
    assert(port_open(port));
    op_close(foreign);
    fastp2p_client_destroy(c);
}

/* The business-port fallback belongs to the mapping-probe stage only, and the
 * borrowed listener must change owner exactly once. */
static void mapping_fallback_only_adopts_while_probing(void) {
    fastp2p_client *c = fixture();
    c->public_port = 5555;
    c->families_wanted = FAM_V4;
    strcpy(c->ip[OP_FAM_V4], "203.0.113.5");
    nat_filter_record(&c->udp_filter, 6, mono());
    op_socket listener = socket_bound(1, "127.0.0.1", 0, BIND_DEFAULT);
    assert(listener >= 0);
    c->udp_listener[OP_FAM_V4] = listener;
    int ti = new_tunnel(c, "sender-node", 910, FASTP2P_TRANSPORT_QUIC, 1);
    assert(ti == 0);
    tunnel *t = &c->tunnels[ti];
    strcpy(t->mode, "udppunch");
    t->state = T_TIME;
    /* A published negotiation is no longer a mapping probe: adopt nothing. */
    assert(!probe_fallback_mapping(c, ti));
    assert(c->udp_listener[OP_FAM_V4] == listener);
    assert(t->fd < 0);
    /* While the mapping is still being measured the business port is adopted. */
    t->state = T_PROBE;
    assert(probe_fallback_mapping(c, ti));
    assert(t->mapped_ports[OP_FAM_V4] == (uint16_t)socket_port(listener));
    assert(t->probes[OP_FAM_V4].borrowed);
    /* Punching from it hands ownership to the tunnel; the listener keeps no fd. */
    strcpy(t->peer_text[OP_FAM_V4], "203.0.113.9");
    t->remote_ports[OP_FAM_V4] = 6000;
    t->peer_ready[OP_FAM_V4] = 1;
    assert(!use_punch_family(c, ti, OP_FAM_V4));
    assert(c->udp_listener[OP_FAM_V4] < 0);
    assert(t->fd == listener && t->probes[OP_FAM_V4].fd < 0);
    dispose(c);
}

/* A completed measurement in the other family outlives the preferred family. */
static void answered_family_survives_primary_failure(void) {
    fastp2p_client *c = fixture();
    c->families_wanted = FAM_V4 | FAM_V6;
    int ti = new_tunnel(c, "sender-node", 920, FASTP2P_TRANSPORT_QUIC, 1);
    assert(ti == 0);
    tunnel *t = &c->tunnels[ti];
    t->state = T_PROBE;
    t->probes[OP_FAM_V6] = (nat_probe){.fd = -1, .state = PROBE_DONE, .mapped_port = 41000};
    assert(!required_family_failed(c, ti, OP_FAM_V4, "probe failed"));
    assert(t->state == T_PROBE);
    /* Without the other answer the same failure still ends the tunnel. */
    t->probes[OP_FAM_V6].state = PROBE_FREE;
    assert(required_family_failed(c, ti, OP_FAM_V4, "probe failed"));
    assert(t->state == T_FREE);
    dispose(c);
}

/* Expired pending keys must not occupy the table forever. */
static void expired_pending_keys_are_reclaimed(void) {
    fastp2p_client *c = fixture();
    uint8_t secret[FP_SESSION_SECRET] = {4};
    int ti = new_tunnel(c, "sender-node", 900, FASTP2P_TRANSPORT_QUIC, 0);
    assert(ti == 0);
    c->tunnels[ti].state = T_QUIC;
    for (int i = 0; i < NPK; ++i) {
        c->keys[i].used = 1;
        c->keys[i].session = (uint64_t)i + 1;
        c->keys[i].deadline = mono() - 1;
    }
    key(c, 900, 4242, 42000, secret);
    int found = 0;
    for (int i = 0; i < NPK; ++i)
        if (c->keys[i].used && c->keys[i].session == 4242)
            found = 1;
    assert(found);
    dispose(c);
}

int main(void) {
    assert(!op_platform_init());
    mapping_fallback_only_adopts_while_probing();
    answered_family_survives_primary_failure();
    expired_pending_keys_are_reclaimed();
    rule_churn_reclaims_only_unused_tunnels();
    release_request_requires_an_unused_tunnel();
    rule_update_changes_bind_address();
    expired_nat_probes_release_sockets();
    relay_cannot_steal_direct_rule();
    relay_endpoint_shares_only_with_the_logical_peer();
    relay_requests_are_shared_and_expire();
    failed_relay_can_be_reselected();
    exact_connection();
    reordered_and_duplicate_keys();
    acknowledgement_and_certificate();
    retries_use_fresh_keys();
    sdwan_ingress_reaches_active_adapter();
    puts("Connection IDs, reordered keys, duplicate delivery, ACK/certificate gates, fresh retry "
         "keys, SD-WAN ingress, tunnel release handshake and listener migration passed");
    return 0;
}
