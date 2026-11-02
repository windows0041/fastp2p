/* Exercise the private state machine with reordered control-plane delivery.
 * Including it here keeps the production C ABI unchanged. */
#include "../src/client.c"
#include <assert.h>

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

int main(void) {
    relay_cannot_steal_direct_rule();
    relay_endpoint_shares_only_with_the_logical_peer();
    relay_requests_are_shared_and_expire();
    exact_connection();
    reordered_and_duplicate_keys();
    acknowledgement_and_certificate();
    retries_use_fresh_keys();
    puts("Connection IDs, reordered keys, duplicate delivery, ACK/certificate gates and fresh retry keys passed");
    return 0;
}
