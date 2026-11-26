/* Check NAT decisions and exercise punch handoff on loopback sockets. */
#include "../src/client.c"
#include <assert.h>

static op_socket bound_port(uint16_t *port) {
    op_socket fd=socket_bound(0,"127.0.0.1",0,1);assert(fd>=0);*port=socket_port(fd);assert(*port);return fd;
}
static void tcp_retry(void) {
    fastp2p_client *c=calloc(1,sizeof(*c));assert(c);strcpy(c->local_ip[OP_FAM_V4],"127.0.0.1");
    uint16_t remote,local;op_socket endpoint=bound_port(&remote),reserve=bound_port(&local);op_close(reserve);
    /* A loopback peer is reached the other way round: the initiator dials and the
     * responder parks on its listener, so the dialling side is the one under test
     * here. */
    int ti=new_tunnel(c,"retry-target",100,FASTP2P_TRANSPORT_TCP,1);assert(ti>=0);
    tunnel *t=&c->tunnels[ti];strcpy(t->ip,"127.0.0.1");strcpy(t->mode,"tcppunch");
    t->local_port=local;t->remote_port=remote;t->tcp_v2=1;t->server=0;
    assert(!op_addr_from_text(&t->peer_addr,"127.0.0.1",remote));
    /* BSD may leave the first connect pending until the production 3-second
     * attempt deadline instead of reporting an immediate loopback refusal. */
    start_underlay(c,ti);uint64_t until=mono()+12*NS;int listening=0;
    while(t->state==T_TCP_CONNECT && mono()<until){
        if(t->tcp_attempts>=2 && !listening){assert(!op_listen(endpoint,4));listening=1;}
        tick_tunnel(c,ti,mono());op_sleep_ms(2);
    }
    assert(listening && t->state==T_HANDSHAKE && t->tcp_attempts>=2 && t->tcp_attempts<=8);
    struct sockaddr_in peer;op_socklen length=sizeof(peer);op_socket accepted=op_accept(endpoint,(struct sockaddr *)&peer,&length);
    assert(accepted>=0 && ntohs(peer.sin_port)==local);
    /* Transport establishment does not bypass session authentication. */
    assert(!tunnel_ready(t));op_close(accepted);close_tunnel(c,ti,NULL);op_close(endpoint);

    endpoint=bound_port(&remote);reserve=bound_port(&local);op_close(reserve);
    ti=new_tunnel(c,"fallback-peer",101,FASTP2P_TRANSPORT_TCP,1);assert(ti>=0);t=&c->tunnels[ti];
    strcpy(t->ip,"127.0.0.1");strcpy(t->mode,"tcppunch");t->local_port=local;t->remote_port=remote;t->tcp_v2=1;
    assert(!op_addr_from_text(&t->peer_addr,"127.0.0.1",remote));
    start_underlay(c,ti);until=mono()+6*NS;
    while(t->state==T_TCP_CONNECT && t->listen_fd<0 && t->tcp_attempts<3 && mono()<until){
        tick_tunnel(c,ti,mono());op_sleep_ms(2);
    }
    /* Simultaneous open needs both peers in SYN_SENT at the same moment, so a
     * refused dial is retried instead of switching to listen after one try. */
    assert(t->tcp_attempts>=2 && t->listen_fd<0 && t->session_owner);
    /* The listen fallback still exists, but only once the retry budget is spent. */
    t->tcp_attempts=TCP_PUNCH_ATTEMPTS_RESPONDER;
    until=mono()+2*NS;
    while(t->listen_fd<0 && mono()<until){tick_tunnel(c,ti,mono());op_sleep_ms(2);}
    assert(t->listen_fd>=0 && t->fd<0);
    assert(!t->tcp_retry_at && !tunnel_ready(t));close_tunnel(c,ti,NULL);op_close(endpoint);free(c);
}
/* The port window is what reaches a symmetric (NAT4) peer, whose mapping for us
 * differs from the one it reported, so it must advance exactly on silent dials
 * and reset as soon as the peer's NAT answers. */
static void tcp_punch_walks_ports_when_silent(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    c->node_id = op_node_id("local-node");
    int ti = new_tunnel(c, "remote-node", 321, FASTP2P_TRANSPORT_TCP, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    strcpy(t->mode, "tcppunch");
    t->tcp_v2 = 1;
    t->state = T_TCP_CONNECT;
    assert(tcp_scan_port(40000, 0) == 40000);
    assert(tcp_scan_port(40000, 1) == 40001);
    assert(tcp_scan_port(40000, 2) == 39999);
    assert(tcp_scan_port(40000, 3) == 40002);
    assert(tcp_scan_port(40000, 4) == 39998);
    assert(tcp_scan_port(1, 2) == 65535);  /* the window wraps inside the range */
    assert(tcp_scan_port(65535, 1) == 1);
    /* A silently dropped dial walks the window; a refused one resets it. */
    errno = ETIMEDOUT;
    tcp_punch_failed(c, ti, mono());
    assert(t->tcp_scan == 1 && t->tcp_timeouts == 1);
    tcp_punch_failed(c, ti, mono());
    assert(t->tcp_scan == 2 && t->tcp_timeouts == 2);
    errno = ECONNREFUSED;
    tcp_punch_failed(c, ti, mono());
    assert(t->tcp_scan == 0 && t->tcp_timeouts == 0);
    /* The window wraps instead of sticking on its last port. */
    t->tcp_scan = TCP_PUNCH_SCAN;
    errno = ETIMEDOUT;
    tcp_punch_failed(c, ti, mono());
    assert(t->tcp_scan == 0);
    close_tunnel(c, ti, NULL);
    free(c);
}
static void tcp_punch_scheduling(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    c->node_id = op_node_id("local-node");
    for (int immediate = 0; immediate <= 1; ++immediate) {
        int ti = new_tunnel(c, "remote-node", 123, FASTP2P_TRANSPORT_TCP, 1);
        assert(ti >= 0);
        tunnel *t = &c->tunnels[ti];
        t->state = T_REPLY;
        t->tcp_v2 = t->tcp_punch_immediate = 1;

        json_object *reply = json_object_new_object();
        op_js(reply, "from", "remote-node");
        op_js(reply, "fromIP", "127.0.0.1");
        op_ju(reply, "coneNatPort", 12345);
        op_ju(reply, "id", 123);
        op_ju(reply, "tcpPunchV2", 1);
        /* A window on the reply must be recorded by the same code path the
         * request uses, so the opener can be sprayed as well as the answerer. */
        op_ju(reply, "symBase", 12345);
        op_ju(reply, "symCount", SYM_WINDOW_MAX);
        op_ju(reply, "symUp", 1);
        if (immediate)
            op_ju(reply, "tcpPunchImmediate", 1); /* no shared clock needed */
        else
            op_ju(reply, "punchts", wall() + 3 * NS);
        const char *body = json_object_to_json_string_ext(reply, JSON_C_TO_STRING_PLAIN);
        uint8_t packet[256];
        size_t length = strlen(body);
        assert(length <= sizeof(packet) - 16);
        op_put64(packet, op_node_id("remote-node"));
        op_put64(packet + 8, c->node_id);
        memcpy(packet + 16, body, length);
        uint64_t before = mono();
        control_message(c, 3, 2, packet, length + 16);
        assert(t->state == T_TIME && t->tcp_v2 && t->tcp_punch_immediate == immediate);
        assert(t->sym_base == 12345 && t->sym_count == SYM_WINDOW_MAX && t->sym_up && !t->sym_split);
        assert(immediate ? t->at <= mono() : t->at >= before + 2 * NS);
        json_object_put(reply);
        close_tunnel(c, ti, NULL);
    }
    free(c);
}
static void quic_uses_punch_endpoint(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    int ti = new_tunnel(c, "quic-peer", 124, FASTP2P_TRANSPORT_QUIC, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    op_socket advertised = socket_bound(1, "127.0.0.1", 0, 0);
    op_socket confirmed = socket_bound(1, "127.0.0.1", 0, 0);
    t->fd = socket_bound(1, "127.0.0.1", 0, 0);
    assert(advertised >= 0 && confirmed >= 0 && t->fd >= 0);
    op_addr local;
    assert(!op_addr_socketname(t->fd, &local));
    assert(!op_addr_socketname(advertised, &t->peer_addr));
    t->remote_port = op_addr_port(&t->peer_addr);
    t->state = T_PUNCH;
    t->punch_next = t->deadline = mono() + 5 * NS;

    /* The peer replies from a different port than the gateway observed. */
    json_object *ack = json_object_new_object();
    op_ju(ack, "id", t->id);
    assert(!udp_packet(confirmed, &local, 4, 1, ack));
    json_object_put(ack);
    uint64_t until = mono() + NS;
    while (t->state == T_PUNCH && mono() < until) {
        tick_tunnel(c, ti, mono());
        op_sleep_ms(2);
    }
    assert(t->state == T_UNDERLAY && t->remote_port == socket_port(confirmed));

    /* The QUIC client starts when the peer is ready. Inspect its first UDP
     * datagrams on the confirmed socket, skipping the punch reply. */
    t->notified = 1;
    int received_initial = 0;
    until = mono() + NS;
    while (!received_initial && mono() < until) {
        tick_tunnel(c, ti, mono());
        uint8_t packet[1500];
        op_ssize size = op_recv(confirmed, packet, sizeof(packet), MSG_DONTWAIT);
        received_initial = size >= 1200 && (packet[0] & 0x80);
        op_sleep_ms(2);
    }
    assert(received_initial);
    close_tunnel(c, ti, NULL);
    op_close(advertised);
    op_close(confirmed);
    free(c);
}
static void lan_punch_public_ipv4(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    strcpy(c->local_ip[OP_FAM_V4], "172.16.12.192");
    strcpy(c->local_ip[OP_FAM_V6], "fd00::10");
    strcpy(c->ip[OP_FAM_V4], "198.51.100.10");

    app *a = &c->apps[0];
    strcpy(a->peer, "mobile-peer");
    a->used = a->local = 1;
    a->transport = FASTP2P_TRANSPORT_QUIC;
    a->attempts = 1;
    a->retry = NS;
    int ti = new_tunnel(c, a->peer, 125, a->transport, 1);
    assert(ti >= 0);
    a->tunnel_index = ti;
    c->tunnels[ti].state = T_TIME;

    const char different[] = "{\"peerNode\":\"mobile-peer\",\"IPv4\":\"203.0.113.10\","
                             "\"lanIP\":\"172.16.12.193\",\"lanIP6\":\"fd00::11\"}";
    control_message(c, 7, 1, (const uint8_t *)different, sizeof(different) - 1);
    assert(!lan_punch_possible(c, a));
    assert(a->attempts == 1 && a->retry == NS);
    assert(a->tunnel_index == ti && c->tunnels[ti].state == T_TIME);

    /* A shared-carrier address is comparable, including against a public one. */
    strcpy(c->ip[OP_FAM_V4], "100.64.0.10");
    assert(!lan_punch_possible(c, a));
    const char carrier[] = "{\"peerNode\":\"mobile-peer\",\"IPv4\":\"100.65.0.11\","
                            "\"lanIP\":\"172.16.12.193\"}";
    control_message(c, 7, 1, (const uint8_t *)carrier, sizeof(carrier) - 1);
    assert(!lan_punch_possible(c, a));
    strcpy(c->ip[OP_FAM_V4], "198.51.100.10");
    assert(!lan_punch_possible(c, a));
    strcpy(c->ip[OP_FAM_V4], "100.65.0.11");
    assert(lan_punch_possible(c, a));
    /* Private addresses alone are not comparable across sites. */
    strcpy(c->ip[OP_FAM_V4], "192.168.1.10");
    assert(lan_punch_possible(c, a));
    strcpy(c->ip[OP_FAM_V4], "198.51.100.10");

    const char shared[] = "{\"peerNode\":\"mobile-peer\",\"IPv4\":\"198.51.100.10\","
                          "\"lanIP\":\"172.16.12.193\"}";
    control_message(c, 7, 1, (const uint8_t *)shared, sizeof(shared) - 1);
    assert(lan_punch_possible(c, a));
    assert(a->attempts == 1 && a->tunnel_index == ti && c->tunnels[ti].state == T_TIME);

    const char ipv6_only[] = "{\"peerNode\":\"mobile-peer\",\"lanIP6\":\"fd00::11\"}";
    control_message(c, 7, 1, (const uint8_t *)ipv6_only, sizeof(ipv6_only) - 1);
    assert(!a->peer_lan[0] && lan_punch_possible(c, a));
    close_tunnel(c, ti, NULL);
    free(c);
}

/* The spray only helps if the datagram is addressed to the port the peer's next
 * mapping actually landed on, so the burst has to cover exactly the announced
 * window and nothing else. Consecutive loopback sockets stand in for a peer
 * whose mapping moves by one port per destination; each one that lies inside the
 * window must receive a punch datagram, and a port outside it must not. */
/* Generous against a loopback round trip, short enough to stay a unit test. */
#define SPRAY_WAIT (200 * MS)
/* Loopback delivery is not synchronous on every kernel: Linux queues the
 * datagram during sendto, while macOS hands it to the interface and delivers it
 * on the receive path some moments later. A single non-blocking pass therefore
 * misses a packet that is already in flight, so wait for the first arrival and
 * give the caller a bounded budget to prove that nothing arrives at all. */
static int drain(op_socket fd, uint64_t budget) {
    int seen = 0;
    uint64_t until = mono() + budget;
    for (;;) {
        uint8_t buffer[1024];
        while (op_recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT) > 0)
            ++seen;
        if (seen || mono() >= until)
            break;
        op_sleep_ms(2);
    }
    return seen;
}

static void peer_listener_port_conflict(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    c->families_wanted = FAM_V4;
    for (int family = 0; family < OP_FAM_COUNT; ++family)
        c->listener[family] = c->udp_listener[family] = -1;
    op_socket occupied = socket_bound(0, "0.0.0.0", 0, BIND_PEER_LISTENER);
    assert(occupied >= 0 && !op_listen(occupied, 1));
    uint16_t requested = socket_port(occupied);
    c->requested_public_port = requested;
    assert(!start_peer_listeners(c));
    assert(c->public_port >= PEER_PORT_MIN && c->public_port < PEER_PORT_MIN + PEER_PORT_COUNT);
    assert(c->public_port != requested && c->requested_public_port == requested);
    assert(socket_port(c->listener[OP_FAM_V4]) == c->public_port);
    assert(socket_port(c->udp_listener[OP_FAM_V4]) == c->public_port);
    close_peer_listeners(c->listener);
    close_peer_listeners(c->udp_listener);
    op_close(occupied);
    assert(!start_peer_listeners(c));
    assert(c->public_port == requested);
    close_peer_listeners(c->listener);
    close_peer_listeners(c->udp_listener);
    occupied = socket_bound(1, "0.0.0.0", requested, BIND_PEER_LISTENER);
    assert(occupied >= 0);
    assert(!start_peer_listeners(c));
    assert(socket_port(c->listener[OP_FAM_V4]) == requested);
    assert(!has_udp_listener(c));
    close_peer_listeners(c->listener);
    op_close(occupied);
    free(c);
}

/* The receiving side sprays from a local socket array: every socket carries its own
 * external mapping towards a destination-dependent NAT, so sixteen of them offer the
 * peer sixteen ports to hit. The whole client caps the array so a pair of punching
 * tunnels cannot open an unbounded number of descriptors. */
/* The ladder describes one path. A laptop that moves from Wi-Fi to a mobile network, or
 * a carrier that re-NATs a node, invalidates the mapping, the filter levels, the TCP
 * mapping and the remembered punch ports in one go - and the relay budget grew to four
 * direct rounds so a symmetric pair has time to find a predictable step. */
static void nat_remeasure_follows_the_path(void) {
    assert(PUBLIC_PUNCH_ROUNDS == 4);
    fastp2p_client c = {0};
    snprintf(c.ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", "203.0.113.7");
    nat_filter_record(&c.udp_filter, 3, NS);
    nat_filter_record(&c.tcp_filter, 2, NS);
    c.punch_ports[0].port = 40000;
    snprintf(c.punch_ports[0].peer, sizeof(c.punch_ports[0].peer), "%s", "peer-a");
    c.ws_connected = 1;
    c.path_recheck_at = UINT64_MAX; /* only a path change may trigger below */

    /* First observation is recorded; nothing is measured again. */
    watch_network_path(&c, 10 * NS);
    assert(!strcmp(c.path_public, "203.0.113.7"));
    assert(!c.tcp_nat_reprepare);
    /* Same path: no work at all. */
    watch_network_path(&c, 11 * NS);
    assert(!c.tcp_nat_reprepare);

    /* The gateway now sees another address: every measurement belongs to the old path. */
    snprintf(c.ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", "198.51.100.9");
    watch_network_path(&c, 20 * NS);
    assert(c.tcp_nat_reprepare);
    assert(c.udp_filter.level == 0 && c.tcp_filter.level == 0);
    assert(c.punch_ports[0].port == 0 && !c.punch_ports[0].peer[0]);
    assert(!strcmp(c.path_public, "198.51.100.9"));

    /* A second change inside the settle window is ignored (a flapping carrier). */
    c.tcp_nat_reprepare = 0;
    snprintf(c.ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", "203.0.113.8");
    watch_network_path(&c, 21 * NS);
    assert(!c.tcp_nat_reprepare);
    assert(!strcmp(c.path_public, "198.51.100.9"));

    /* The source address of the control connection changing is enough on its own. */
    op_addr local;
    assert(!op_addr_from_text(&local, "192.168.60.22", 1234));
    c.control_local = local;
    watch_network_path(&c, 40 * NS);
    assert(c.tcp_nat_reprepare);
    assert(!strcmp(c.path_local, "192.168.60.22"));

    /* Nothing is measured while the control connection is down. */
    fastp2p_client offline = {0};
    snprintf(offline.ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", "203.0.113.7");
    watch_network_path(&offline, NS);
    snprintf(offline.ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", "203.0.113.99");
    offline.path_recheck_at = UINT64_MAX;
    watch_network_path(&offline, 2 * NS);
    assert(!offline.tcp_nat_reprepare);
    /* ...and it measures once the connection is back. */
    offline.ws_connected = 1;
    watch_network_path(&offline, 40 * NS);
    assert(offline.tcp_nat_reprepare);
}
/* A zero-initialised client has descriptor 0 in every slot, and closing slot 0 closes
 * whatever really holds it. fastp2p_client_create() marks them all closed; these tests
 * build the struct by hand, so they do the same. */
static void probe_fds_closed(fastp2p_client *c) {
    for (int family = 0; family < OP_FAM_COUNT; ++family) {
        c->nat[family].fd = c->nat[family].fd2 = -1;
        c->tcp_nat.family[family].fd = -1;
    }
    c->stun.fd = -1;
    c->tcp_level.listener = c->tcp_level.dialer = -1;
}
/* The mapping ladder borrows the peer-port listener when one exists: the mapping an
 * operator has to open is that one, and classifying an ephemeral port described a port
 * no firewall rule can name. Borrowing must never close it - every QUIC connection
 * accepted on the shared listener dies with that fd, and nothing rebuilds it until the
 * next start - and the ladder has to fall back to its own socket when no listener
 * exists. */
static void mapping_probe_borrows_the_peer_port(void) {
    fastp2p_client c = {0};
    snprintf(c.local_ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", "127.0.0.1");
    assert(!op_addr_from_text(&c.gateway_addr[OP_FAM_V4], "127.0.0.1", 27180));
    op_socket listener = socket_bound(1, "127.0.0.1", 0, 0);
    assert(listener >= 0);
    c.udp_listener[OP_FAM_V4] = listener;
    probe_fds_closed(&c);

    assert(nat_discovery_open(&c, OP_FAM_V4) == 1);
    assert(c.nat[OP_FAM_V4].fd == listener && c.nat[OP_FAM_V4].shared);
    /* Finishing the ladder leaves the peer port open and records that the verdict
     * describes it. */
    c.nat[OP_FAM_V4].type = NAT_CONE;
    nat_discovery_finish(&c, OP_FAM_V4);
    assert(!c.nat[OP_FAM_V4].shared && c.nat[OP_FAM_V4].fd < 0);
    assert(c.nat[OP_FAM_V4].measured_shared);
    op_addr check;
    assert(!op_addr_socketname(listener, &check)); /* still open */

    /* Without a listener the ladder owns its socket, and closing it is correct. */
    c.udp_listener[OP_FAM_V4] = -1;
    assert(nat_discovery_open(&c, OP_FAM_V4) == 1);
    op_socket owned = c.nat[OP_FAM_V4].fd;
    assert(owned >= 0 && !c.nat[OP_FAM_V4].shared);
    nat_discovery_finish(&c, OP_FAM_V4);
    assert(op_addr_socketname(owned, &check)); /* closed by the ladder */
    assert(!c.nat[OP_FAM_V4].measured_shared);
    op_close(listener);
}

/* A ladder answer arrives on the borrowed listener, not on a socket the probe reads, so
 * it has to be recognised there; without that the classification never advances on a
 * host that owns the peer port. */
static void mapping_reply_comes_through_the_listener(void) {
    fastp2p_client c = {0};
    snprintf(c.local_ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", "127.0.0.1");
    assert(!op_addr_from_text(&c.gateway_addr[OP_FAM_V4], "127.0.0.1", 27180));
    c.udp_listener[OP_FAM_V4] = socket_bound(1, "127.0.0.1", 0, 0);
    assert(c.udp_listener[OP_FAM_V4] >= 0);
    probe_fds_closed(&c);
    assert(nat_discovery_open(&c, OP_FAM_V4) == 1);

    const char *body = "{\"IP\":\"198.51.100.7\",\"port\":12345}";
    size_t body_length = strlen(body);
    uint8_t packet[256];
    op_put32(packet, (uint32_t)body_length);
    op_put16(packet + 4, 2);
    op_put16(packet + 6, 0);
    memcpy(packet + 8, body, body_length);
    op_addr from;
    assert(!op_addr_from_text(&from, "127.0.0.1", 27180));
    /* Phase 1 answer: the ladder moves to its second destination on the same socket. */
    assert(nat_discovery_reply(&c, OP_FAM_V4, packet, 8 + body_length, &from, 5 * NS));
    assert(c.nat[OP_FAM_V4].phase == 2);
    assert(c.nat[OP_FAM_V4].fd == c.udp_listener[OP_FAM_V4]);
    assert(c.nat[OP_FAM_V4].shared);
    /* The same datagram in phase 2 comes from the wrong port: not our answer. */
    assert(!nat_discovery_reply(&c, OP_FAM_V4, packet, 8 + body_length, &from, 6 * NS));
    nat_discovery_close(&c.nat[OP_FAM_V4]);
    op_close(c.udp_listener[OP_FAM_V4]);
}

/* Sharing the peer port with a hop that is punching perturbs the port sequence a
 * per-destination NAT is judged on, so the re-measurement waits for a quiet moment. */
static void remeasure_waits_for_the_punch(void) {
    fastp2p_client c = {0};
    snprintf(c.local_ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", "127.0.0.1");
    assert(!op_addr_from_text(&c.gateway_addr[OP_FAM_V4], "127.0.0.1", 27180));
    c.families_wanted = c.gateway_families = FAM_V4;
    probe_fds_closed(&c);
    int ti = new_tunnel(&c, "peer-punching", 7, FASTP2P_TRANSPORT_QUIC, 1);
    assert(ti >= 0);
    c.tunnels[ti].state = T_PUNCH;
    assert(nat_remeasure(&c) == 1); /* deferred */
    assert(!c.nat[OP_FAM_V4].phase);
    c.tunnels[ti].state = T_ACTIVE;
    assert(nat_remeasure(&c) == 0);
    assert(c.nat[OP_FAM_V4].phase == 1);
    nat_discovery_close(&c.nat[OP_FAM_V4]);
    close_tunnel(&c, ti, NULL);
}
/* --- second destination address ------------------------------------------------ */

/* These cases need no server socket. The ladder's question is a plain BINDING request,
 * its transaction id is visible in this translation unit, and the answer is handed to
 * nat_discovery_reply() as the socket loop would. The second address is only a
 * *destination*: binding one would fail on macOS, where lo0 carries 127.0.0.1 alone. */

/* A BINDING success carrying MAPPED-ADDRESS, the only attribute the parser needs.
 * `ip` is the public address the server reports, which is what the endpoint comparison
 * looks at besides the port. */
static size_t mapped_answer_at(const uint8_t transaction[FP_STUN_NONCE], uint16_t port,
                               const uint8_t ip[4], uint8_t *out) {
    memset(out, 0, 32);
    out[0] = 0x01; /* BINDING success */
    out[1] = 0x01;
    out[2] = 0x00; /* one MAPPED-ADDRESS attribute: 4-byte header + 8-byte value */
    out[3] = 0x0c;
    out[4] = 0x21; /* magic cookie */
    out[5] = 0x12;
    out[6] = 0xa4;
    out[7] = 0x42;
    memcpy(out + 8, transaction, FP_STUN_NONCE);
    out[20] = 0x00; /* MAPPED-ADDRESS */
    out[21] = 0x01;
    out[22] = 0x00;
    out[23] = 0x08;
    out[24] = 0x00; /* reserved, family IPv4 */
    out[25] = 0x01;
    out[26] = (uint8_t)(port >> 8);
    out[27] = (uint8_t)(port & 0xff);
    memcpy(out + 28, ip, 4);
    return 32;
}

/* The usual witness address, which matches the one the gateway reported. */
static size_t mapped_answer(const uint8_t transaction[FP_STUN_NONCE], uint16_t port,
                            uint8_t *out) {
    static const uint8_t ip[4] = {198, 51, 100, 7};
    return mapped_answer_at(transaction, port, ip, out);
}

/* One gateway answer, as the ladder sees it. */
static void feed_mapping_answer(fastp2p_client *c, uint16_t from_port, uint16_t mapped,
                                uint64_t now) {
    char body[64];
    int body_length = snprintf(body, sizeof(body), "{\"IP\":\"198.51.100.7\",\"port\":%u}",
                               (unsigned)mapped);
    assert(body_length > 0);
    uint8_t packet[128];
    op_put32(packet, (uint32_t)body_length);
    op_put16(packet + 4, 2);
    op_put16(packet + 6, 0);
    memcpy(packet + 8, body, (size_t)body_length);
    op_addr from;
    assert(!op_addr_from_text(&from, "127.0.0.1", from_port));
    assert(nat_discovery_reply(c, OP_FAM_V4, packet, 8 + (size_t)body_length, &from, now));
}

/* Drives the ladder to the point where it asks a second destination address. */
static void start_second_address_question(fastp2p_client *c, uint16_t mapped_port) {
    snprintf(c->local_ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", "127.0.0.1");
    assert(!op_addr_from_text(&c->gateway_addr[OP_FAM_V4], "127.0.0.1", 27180));
    probe_fds_closed(c);
    c->udp_listener[OP_FAM_V4] = -1;
    snprintf(c->stun_host[0], sizeof(c->stun_host[0]), "%s", "127.0.0.2");
    c->stun_port[0] = 3478;
    c->stun_count = 1;
    assert(nat_discovery_open(c, OP_FAM_V4) == 1);
    feed_mapping_answer(c, 27180, mapped_port, 1 * NS);
    assert(c->nat[OP_FAM_V4].phase == 2);
    feed_mapping_answer(c, 27181, mapped_port, 2 * NS); /* same port: cone so far */
    assert(c->nat[OP_FAM_V4].dep_phase == 1);
    /* The cone verdict is published at once: the question refines it and must not hold
     * the login back. This is also the state the login gate lets through - socket open,
     * no retry, a question pending. */
    assert(c->nat[OP_FAM_V4].type == NAT_CONE);
    assert(c->nat[OP_FAM_V4].fd >= 0 && !c->nat[OP_FAM_V4].retries);
}

static void answer_second_address_at(fastp2p_client *c, uint16_t port, const uint8_t ip[4],
                                     uint64_t now) {
    uint8_t answer[32];
    size_t length = mapped_answer_at(c->nat[OP_FAM_V4].dep_tid, port, ip, answer);
    op_addr from;
    assert(!op_addr_from_text(&from, "127.0.0.2", 3478));
    assert(nat_discovery_reply(c, OP_FAM_V4, answer, length, &from, now));
}

static void answer_second_address(fastp2p_client *c, uint16_t port, uint64_t now) {
    static const uint8_t ip[4] = {198, 51, 100, 7};
    answer_second_address_at(c, port, ip, now);
}

/* A gateway inside our own network reports the LAN mapping, which is not the mapping an
 * internet peer would reach. Asking a public server about it would call every
 * LAN-deployed node symmetric, so the ladder keeps the cone verdict and says nothing. */
static void private_gateway_address_is_not_comparable(void) {
    fastp2p_client c = {0};
    snprintf(c.local_ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", "127.0.0.1");
    assert(!op_addr_from_text(&c.gateway_addr[OP_FAM_V4], "127.0.0.1", 27180));
    probe_fds_closed(&c);
    c.udp_listener[OP_FAM_V4] = -1;
    snprintf(c.stun_host[0], sizeof(c.stun_host[0]), "%s", "127.0.0.2");
    c.stun_port[0] = 3478;
    c.stun_count = 1;
    assert(nat_discovery_open(&c, OP_FAM_V4) == 1);
    /* The gateway answers with a private mapping, as a LAN gateway does. */
    char body[] = "{\"IP\":\"192.168.60.4\",\"port\":35000}";
    uint8_t packet[128];
    op_put32(packet, (uint32_t)(sizeof(body) - 1));
    op_put16(packet + 4, 2);
    op_put16(packet + 6, 0);
    memcpy(packet + 8, body, sizeof(body) - 1);
    op_addr from;
    assert(!op_addr_from_text(&from, "127.0.0.1", 27180));
    assert(nat_discovery_reply(&c, OP_FAM_V4, packet, 8 + sizeof(body) - 1, &from, 1 * NS));
    assert(c.nat[OP_FAM_V4].phase == 2);
    assert(!op_addr_from_text(&from, "127.0.0.1", 27181));
    assert(nat_discovery_reply(&c, OP_FAM_V4, packet, 8 + sizeof(body) - 1, &from, 2 * NS));
    /* No question, cone verdict, nothing recorded. */
    assert(c.nat[OP_FAM_V4].dep_phase == 0);
    assert(c.nat[OP_FAM_V4].type == NAT_CONE);
    assert(c.nat[OP_FAM_V4].addr_dep == -1);
    assert(c.nat[OP_FAM_V4].fd < 0);
    /* The predicate itself: private ranges in, public out. */
    op_addr probe;
    assert(!op_addr_from_text(&probe, "10.1.2.3", 1) && address_not_translated(&probe));
    assert(!op_addr_from_text(&probe, "172.20.0.1", 1) && address_not_translated(&probe));
    assert(!op_addr_from_text(&probe, "172.32.0.1", 1) && !address_not_translated(&probe));
    assert(!op_addr_from_text(&probe, "192.168.1.1", 1) && address_not_translated(&probe));
    assert(!op_addr_from_text(&probe, "127.0.0.1", 1) && address_not_translated(&probe));
    assert(!op_addr_from_text(&probe, "169.254.1.1", 1) && address_not_translated(&probe));
    assert(!op_addr_from_text(&probe, "120.231.127.124", 1) && !address_not_translated(&probe));
    assert(!op_addr_from_text(&probe, "fd00::1", 1) && address_not_translated(&probe));
    assert(!op_addr_from_text(&probe, "2409:8a55::1", 1) && !address_not_translated(&probe));
}
/* A server the project runs itself is the better witness than a public one: the default
 * list leads with stun.miwifi.com, so the choice has to be made on the name, not the
 * order. A gateway configured by address matches no name. */
static void self_hosted_stun_is_preferred(void) {
    assert(host_under("stun.fastp2p.top", "fastp2p.top"));
    assert(host_under("fastp2p.top", "fastp2p.top"));
    assert(host_under("a.b.fastp2p.top", "fastp2p.top"));
    /* A shared suffix without the dot is a different domain. */
    assert(!host_under("evilfastp2p.top", "fastp2p.top"));
    assert(!host_under("stun.miwifi.com", "fastp2p.top"));
    assert(!host_under("stun.fastp2p.top", "139.199.4.226"));
    assert(!host_under("", "fastp2p.top"));
    assert(!host_under("stun.fastp2p.top", ""));
}

/* Every gateway probe port is on one address, so a NAT that keys its mapping on the
 * destination *address* looks like a cone until a peer elsewhere punches at a port that
 * was never published. One outside answer settles it, and its verdict must win. */
static void mapping_follows_the_destination_address(void) {
    fastp2p_client c = {0};
    start_second_address_question(&c, 35000);
    answer_second_address(&c, 45123, 3 * NS); /* a different mapping */
    assert(c.nat[OP_FAM_V4].type == NAT_HARD_SYM);
    assert(c.nat[OP_FAM_V4].addr_dep == 1);
    assert(c.nat[OP_FAM_V4].fd < 0); /* ladder finished, nothing left open */
}

/* An answer that matches the gateway's mapping confirms the cone and records that the
 * verdict covers a second address too. */
static void mapping_stays_a_cone_across_addresses(void) {
    fastp2p_client c = {0};
    start_second_address_question(&c, 35000);
    answer_second_address(&c, 35000, 3 * NS); /* the mapping the gateway already saw */
    assert(c.nat[OP_FAM_V4].type == NAT_CONE);
    assert(c.nat[OP_FAM_V4].addr_dep == 0);
    assert(c.nat[OP_FAM_V4].fd < 0);
}

/* Same port, another public address: the port is predictable but the endpoint a peer
 * elsewhere must dial is not, because that peer's packets arrive on an address our
 * mapping was never created on. Still destination-dependent. */
static void mapping_depends_on_the_address_only(void) {
    fastp2p_client c = {0};
    start_second_address_question(&c, 35000); /* the gateway saw 198.51.100.7:35000 */
    static const uint8_t other_ip[4] = {203, 0, 113, 9};
    answer_second_address_at(&c, 35000, other_ip, 3 * NS);
    assert(c.nat[OP_FAM_V4].type == NAT_HARD_SYM);
    assert(c.nat[OP_FAM_V4].addr_dep == 1);
    assert(c.nat[OP_FAM_V4].fd < 0);
}

/* A third party that does not answer says nothing about the NAT, so the cone verdict
 * stays - a silent server must not turn a working mapping into a symmetric one. */
static void unanswered_second_address_keeps_the_cone(void) {
    fastp2p_client c = {0};
    start_second_address_question(&c, 35000);
    tick_nat_family(&c, OP_FAM_V4, 2 * NS + 700 * MS); /* first deadline: retry */
    assert(c.nat[OP_FAM_V4].dep_phase == 1 && c.nat[OP_FAM_V4].dep_attempt == 1);
    tick_nat_family(&c, OP_FAM_V4, 2 * NS + 1400 * MS); /* second: give up quietly */
    assert(c.nat[OP_FAM_V4].dep_phase == 0);
    assert(c.nat[OP_FAM_V4].type == NAT_CONE);
    assert(c.nat[OP_FAM_V4].addr_dep == -1);
    assert(c.nat[OP_FAM_V4].fd < 0);
}

static void udp_array_width_and_ceiling(void) {
    assert(UDP_PUNCH_ARRAY == 16);
    fastp2p_client c = {0};
    snprintf(c.local_ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", "127.0.0.1");
    int ti[4], opened = 0;
    for (int i = 0; i < 4; ++i) {
        ti[i] = new_tunnel(&c, "peer-node-array", (uint64_t)(i + 1), FASTP2P_TRANSPORT_QUIC, 1);
        assert(ti[i] >= 0);
        tunnel *t = &c.tunnels[ti[i]];
        t->family = OP_FAM_V4;
        t->udp_punch_kind = 2; /* centred window: the receiver opens the array */
        t->udp_punch_role = UDP_PUNCH_RECEIVE;
        t->sym_count = SYM_WINDOW_HARD;
        open_udp_candidates(&c, t);
        opened += (int)t->udp_candidate_count;
    }
    /* Three concurrent tunnels fill the per-client ceiling (3 x 16 = 48) and the fourth
     * gets none: the array is bounded per client, not per tunnel. */
    assert(opened == UDP_PUNCH_CLIENT_ARRAY);
    assert(c.tunnels[ti[0]].udp_candidate_count == UDP_PUNCH_ARRAY);
    assert(c.tunnels[ti[2]].udp_candidate_count == UDP_PUNCH_ARRAY);
    assert(c.tunnels[ti[3]].udp_candidate_count == 0);
    for (int i = 0; i < 4; ++i) {
        close_udp_candidates(&c.tunnels[ti[i]]);
        assert(c.tunnels[ti[i]].udp_candidate_count == 0);
        close_tunnel(&c, ti[i], NULL);
    }
}
static void udp_punch_uses_winning_socket(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    strcpy(c->local_ip[OP_FAM_V4], "127.0.0.1");
    int ti = new_tunnel(c, "regular-node", 503, FASTP2P_TRANSPORT_QUIC, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    op_socket peer = socket_bound(1, "127.0.0.1", 0, 0);
    t->fd = socket_bound(1, "127.0.0.1", 0, 0);
    assert(peer >= 0 && t->fd >= 0);
    assert(!op_addr_socketname(peer, &t->peer_addr));
    t->state = T_PUNCH;
    t->udp_punch_role = UDP_PUNCH_RECEIVE;
    t->udp_punch_kind = 2;
    t->sym_base = t->remote_port = socket_port(peer);
    t->sym_count = SYM_WINDOW_MAX;
    t->sym_up = 1;
    t->punch_started = mono();
    t->deadline = t->punch_started + 5 * NS;
    /* The extra sockets are opened on the first tick, but a host under port
     * pressure can refuse one: retry a few ticks before insisting on all of them
     * (this failed once on a macOS arm64 runner while every other platform
     * passed). */
    for (int attempt = 0; attempt < 24 && t->udp_candidate_count < UDP_PUNCH_ARRAY; ++attempt) {
        tick_tunnel(c, ti, t->punch_started);
        op_sleep_ms(2);
    }
    assert(t->udp_candidate_count == UDP_PUNCH_ARRAY);
    assert(drain(peer, SPRAY_WAIT));

    op_socket winner = t->udp_candidates[1], primary = t->fd, other = t->udp_candidates[0];
    op_addr local;
    assert(!op_addr_socketname(winner, &local));
    json_object *probe = json_object_new_object();
    op_ju(probe, "id", t->id + 1);
    assert(!udp_packet(peer, &local, 4, 0, probe));
    tick_tunnel(c, ti, mono());
    assert(t->state == T_PUNCH && t->fd == primary);
    op_ju(probe, "id", t->id);
    assert(!udp_packet(peer, &local, 4, 0, probe));
    json_object_put(probe);
    uint64_t until = mono() + NS;
    while (t->state == T_PUNCH && mono() < until) {
        tick_tunnel(c, ti, mono());
        op_sleep_ms(2);
    }
    assert(t->state == T_UNDERLAY && t->fd == winner && !t->udp_candidate_count);
    assert(t->local_port == op_addr_port(&local) && t->remote_port == socket_port(peer));
    assert(op_addr_socketname(primary, &local) && op_addr_socketname(other, &local));
    assert(drain(peer, SPRAY_WAIT));
    tick_tunnel(c, ti, t->punch_next);
    assert(drain(peer, SPRAY_WAIT));
    close_tunnel(c, ti, NULL);
    assert(op_addr_socketname(winner, &local));
    op_close(peer);
    free(c);
}
static void sym_spray_ports(void) {
    for (int attempt = 0; attempt < 8; ++attempt) {
        op_socket peer[3] = {-1, -1, -1};
        uint16_t port[3] = {0, 0, 0};
        peer[0] = socket_bound(1, "127.0.0.1", 0, 0);
        if (peer[0] < 0)
            return;
        port[0] = socket_port(peer[0]);
        int complete = port[0] + 2 <= 65535;
        for (int i = 1; complete && i < 3; ++i) {
            port[i] = (uint16_t)(port[0] + i);
            peer[i] = socket_bound(1, "127.0.0.1", port[i], 0);
            complete = peer[i] >= 0;
        }
        if (!complete) {
            /* The kernel handed out a port whose neighbours are busy. Retry. */
            for (int i = 0; i < 3; ++i)
                if (peer[i] >= 0)
                    op_close(peer[i]);
            continue;
        }
        /* One extra socket just outside the window: it must stay silent. */
        op_socket outside = port[0] + 3 <= 65535
                                ? socket_bound(1, "127.0.0.1", (uint16_t)(port[0] + 3), 0)
                                : -1;
        fastp2p_client *c = calloc(1, sizeof(*c));
        assert(c);

        /* Centred window: the direction is unknown, so both neighbours are hit. */
        int ti = new_tunnel(c, "sym-peer", 501, FASTP2P_TRANSPORT_QUIC, 1);
        assert(ti >= 0);
        tunnel *t = &c->tunnels[ti];
        t->fd = socket_bound(1, "127.0.0.1", 0, 0);
        assert(t->fd >= 0);
        assert(!op_addr_from_text(&t->peer_addr, "127.0.0.1", port[1]));
        t->remote_port = port[1];
        t->sym_base = port[1];
        t->sym_count = 2; /* one port either side */
        t->sym_split = 1;
        t->state = T_PUNCH;
        t->punch_started = t->punch_next = t->sym_spray_at = 0;
        t->deadline = mono() + 5 * NS;
        tick_tunnel(c, ti, mono());
        assert(drain(peer[0], SPRAY_WAIT) >= 1);
        assert(drain(peer[1], SPRAY_WAIT) >= 1);
        assert(drain(peer[2], SPRAY_WAIT) >= 1);
        if (outside >= 0)
            assert(drain(outside, SPRAY_WAIT) == 0);
        close_tunnel(c, ti, NULL);

        /* Directional window: unchanged behaviour, walks up from the mapping. */
        ti = new_tunnel(c, "easy-peer", 502, FASTP2P_TRANSPORT_QUIC, 1);
        assert(ti >= 0);
        t = &c->tunnels[ti];
        t->fd = socket_bound(1, "127.0.0.1", 0, 0);
        assert(t->fd >= 0);
        assert(!op_addr_from_text(&t->peer_addr, "127.0.0.1", port[0]));
        t->remote_port = port[0];
        t->sym_base = port[0];
        t->sym_count = 2;
        t->sym_up = 1;
        t->sym_split = 0;
        t->state = T_PUNCH;
        t->punch_started = t->punch_next = t->sym_spray_at = 0;
        t->deadline = mono() + 5 * NS;
        tick_tunnel(c, ti, mono());
        assert(drain(peer[0], SPRAY_WAIT) >= 1); /* the explicit punch target */
        assert(drain(peer[1], SPRAY_WAIT) >= 1 && drain(peer[2], SPRAY_WAIT) >= 1);
        if (outside >= 0)
            assert(drain(outside, SPRAY_WAIT) == 0);
        close_tunnel(c, ti, NULL);

        for (int i = 0; i < 3; ++i)
            op_close(peer[i]);
        if (outside >= 0)
            op_close(outside);
        free(c);
        return;
    }
}
/* A symmetric peer is unreachable at the port it published, because the punch
 * reaches it from a different local port and therefore a different mapping.
 * What it publishes instead is a window to spray. These checks pin the shape of
 * that window: directional and narrow when the step is measurable, centred and
 * wider when it is not, and nothing at all for a mapping that does not move. */
/* The offer has to survive the round trip. It did not: the responder never built one,
 * the initiator never stored it, and the role read our own class instead of the peer's,
 * so a cone initiator facing a symmetric peer fell back to one packet at a port that NAT
 * never maps to us - NAT1 vs NAT4 could not punch. */
/* The announced address and the address a peer's packets arrive from can differ inside a
 * carrier pool: 223.104.85.219 answered a peer that had announced .223, and an exact host
 * match dropped every packet. IPv4 compares within one /24; IPv6 stays strict. */
static void punch_accepts_the_carrier_pool(void) {
    op_addr from, peer;
    assert(!op_addr_from_text(&from, "223.104.85.219", 42814));
    assert(!op_addr_from_text(&peer, "223.104.85.223", 57390));
    assert(peer_host_matches(&from, &peer));
    /* Same host still matches, another /24 does not. */
    assert(!op_addr_from_text(&from, "223.104.85.223", 1) ? peer_host_matches(&from, &peer) : 0);
    assert(!op_addr_from_text(&from, "223.104.86.219", 1) ? !peer_host_matches(&from, &peer) : 0);
    assert(!op_addr_from_text(&from, "120.231.127.124", 1) ? !peer_host_matches(&from, &peer) : 0);
    /* IPv6 is never relaxed. */
    assert(!op_addr_from_text(&from, "2409:895a:f1d5:ca7e::1", 1));
    assert(!op_addr_from_text(&peer, "2409:895a:f1d5:ca7e::2", 1));
    assert(!peer_host_matches(&from, &peer));
}
static void window_offer_decides_the_role(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    snprintf(c->local_ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", "127.0.0.1");
    c->families_wanted = c->gateway_families = FAM_V4;
    int ti = new_tunnel(c, "peer", 81, FASTP2P_TRANSPORT_QUIC, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    snprintf(t->mode, sizeof(t->mode), "%s", "udppunch");
    t->family = OP_FAM_V4;
    t->mapped_port = 40000;
    t->mapped_ports[OP_FAM_V4] = 40000;
    t->remote_ports[OP_FAM_V4] = 41000;
    t->peer_ready[OP_FAM_V4] = 1;
    snprintf(t->peer_text[OP_FAM_V4], OP_ADDR_TEXT, "%s", "203.0.113.9");
    snprintf(t->mapped_text[OP_FAM_V4], OP_ADDR_TEXT, "%s", "198.51.100.7");
    c->nat[OP_FAM_V4].type = NAT_CONE;

    /* The peer's request carries udpPunchOrder together with its window. */
    t->udp_punch_order = 1;
    /* A directional window from a symmetric peer: the cone side must spray it. */
    json_object *offer = json_tokener_parse(
        "{\"symBase\":41000,\"symCount\":50,\"symUp\":1,\"udpNatType\":3}");
    learn_sym_window(t, offer);
    json_object_put(offer);
    assert(t->udp_peer_kind == 1);
    assert(t->sym_base == 41000 && t->sym_count == SYM_WINDOW_MAX);
    assert(ordered_udp_role(c, t) == UDP_PUNCH_SEND);

    /* A centred window is sprayed the same way: the side without a window of its own
     * always sends. */
    offer = json_tokener_parse(
        "{\"symBase\":41000,\"symCount\":128,\"symSplit\":1,\"udpNatType\":2}");
    learn_sym_window(t, offer);
    json_object_put(offer);
    assert(t->udp_peer_kind == 2);
    assert(ordered_udp_role(c, t) == UDP_PUNCH_SEND);

    /* When only we published a window, we are the side that waits to be found. */
    t->udp_punch_kind = 1;
    t->udp_punch_order = 1;
    offer = json_tokener_parse("{\"udpNatType\":1}");
    learn_sym_window(t, offer);
    json_object_put(offer);
    assert(t->udp_peer_kind == 0);
    assert(ordered_udp_role(c, t) == UDP_PUNCH_RECEIVE);
    /* Both windows, ours predictable and theirs centred: we do the walking. */
    t->udp_punch_kind = 1;
    t->udp_peer_kind = 2;
    t->sym_base = t->remote_ports[OP_FAM_V4];
    t->sym_count = SYM_WINDOW_HARD;
    t->sym_split = 1;
    assert(ordered_udp_role(c, t) == UDP_PUNCH_SEND);
    t->udp_punch_kind = 0;

    /* No offer at all keeps the legacy single-endpoint punch. */
    offer = json_tokener_parse("{\"udpNatType\":1}");
    learn_sym_window(t, offer);
    json_object_put(offer);
    assert(t->udp_peer_kind == 0 && !t->sym_count);
    assert(ordered_udp_role(c, t) == UDP_PUNCH_LEGACY);
    close_tunnel(c, ti, NULL);
    free(c);
}

static void sym_window_wire(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    int ti = new_tunnel(c, "peer", 77, FASTP2P_TRANSPORT_QUIC, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    t->mapped_port = 40000;
    json_object *j = json_object_new_object();

    /* A cone mapping answers at the port it published: no window, no burst. */
    c->nat[OP_FAM_V4].type = NAT_CONE;
    announce_sym_window(c, t, j, OP_FAM_V4);
    assert(!op_integer(j, "symBase") && !op_integer(j, "symCount"));

    /* Measurable step: keep the historical directional window unchanged. */
    c->nat[OP_FAM_V4].type = NAT_EASY_SYM_INC;
    announce_sym_window(c, t, j, OP_FAM_V4);
    assert(op_integer(j, "symBase") == 40000);
    assert(op_integer(j, "symCount") == SYM_WINDOW_MAX);
    assert(op_integer(j, "symUp") == 1 && !op_integer(j, "symSplit"));
    c->nat[OP_FAM_V4].type = NAT_EASY_SYM_DEC;
    json_object_put(j);
    j = json_object_new_object();
    announce_sym_window(c, t, j, OP_FAM_V4);
    assert(op_integer(j, "symBase") == 40000 && op_integer(j, "symUp") == 0);
    assert(op_integer(j, "symCount") == SYM_WINDOW_MAX);

    /* Unpredictable step: the direction is unknown, so both sides are covered
     * and the wider cap applies. */
    c->nat[OP_FAM_V4].type = NAT_HARD_SYM;
    json_object_put(j);
    j = json_object_new_object();
    announce_sym_window(c, t, j, OP_FAM_V4);
    assert(op_integer(j, "symBase") == 40000);
    assert(op_integer(j, "symCount") == SYM_WINDOW_HARD);
    assert(op_integer(j, "symSplit") == 1);

    /* Unmeasured and LAN/relay punches stay silent: nothing is shifted there. */
    c->nat[OP_FAM_V4].type = NAT_UNKNOWN;
    json_object_put(j);
    j = json_object_new_object();
    announce_sym_window(c, t, j, OP_FAM_V4);
    assert(!op_integer(j, "symCount"));
    c->nat[OP_FAM_V4].type = NAT_HARD_SYM;
    t->lan = 1;
    json_object_put(j);
    j = json_object_new_object();
    announce_sym_window(c, t, j, OP_FAM_V4);
    assert(!op_integer(j, "symCount"));
    t->lan = 0;
    t->relay_wait = 1;
    json_object_put(j);
    j = json_object_new_object();
    announce_sym_window(c, t, j, OP_FAM_V4);
    assert(!op_integer(j, "symCount"));
    t->relay_wait = 0;
    /* Only the QUIC punch sprays; the TCP punch uses port prediction. */
    t->transport = FASTP2P_TRANSPORT_TCP;
    json_object_put(j);
    j = json_object_new_object();
    announce_sym_window(c, t, j, OP_FAM_V4);
    assert(!op_integer(j, "symCount"));
    /* With no measured mapping there is no window origin to publish. */
    t->transport = FASTP2P_TRANSPORT_QUIC;
    t->mapped_port = 0;
    json_object_put(j);
    j = json_object_new_object();
    announce_sym_window(c, t, j, OP_FAM_V4);
    assert(!op_integer(j, "symCount"));
    json_object_put(j);
    close_tunnel(c, ti, NULL);

    /* Reading a peer's window: capped by the kind it declared, and dropped when
     * it cannot describe two ports. */
    fastp2p_client *reader = calloc(1, sizeof(*reader));
    assert(reader);
    ti = new_tunnel(reader, "peer", 78, FASTP2P_TRANSPORT_QUIC, 1);
    assert(ti >= 0);
    tunnel *r = &reader->tunnels[ti];
    json_object *easy = json_object_new_object();
    op_ju(easy, "symBase", 40000);
    op_ju(easy, "symCount", 5000);
    learn_sym_window(r, easy);
    assert(r->sym_base == 40000 && r->sym_count == SYM_WINDOW_MAX && !r->sym_split);
    json_object_put(easy);
    json_object *hard = json_object_new_object();
    op_ju(hard, "symBase", 40000);
    op_ju(hard, "symCount", 5000);
    op_ju(hard, "symSplit", 1);
    op_ju(hard, "symUp", 0);
    learn_sym_window(r, hard);
    assert(r->sym_base == 40000 && r->sym_count == SYM_WINDOW_HARD && r->sym_split);
    json_object_put(hard);
    r->sym_base = r->sym_count = 0;
    r->sym_split = 0;
    json_object *tiny = json_object_new_object();
    op_ju(tiny, "symBase", 40000);
    op_ju(tiny, "symCount", 1);
    learn_sym_window(r, tiny);
    assert(!r->sym_count && !r->sym_base);
    json_object_put(tiny);
    json_object *out_of_range = json_object_new_object();
    op_ju(out_of_range, "symBase", 70000);
    op_ju(out_of_range, "symCount", SYM_WINDOW_MAX);
    learn_sym_window(r, out_of_range);
    assert(!r->sym_count);
    json_object_put(out_of_range);
    close_tunnel(reader, ti, NULL);
    free(reader);
    free(c);
}
static void udp_dual_window_wire(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    int ti = new_tunnel(c, "regular-node", 504, FASTP2P_TRANSPORT_QUIC, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    strcpy(t->mode, "udppunch");
    nat_probe *p = &t->probes[OP_FAM_V4];
    const uint16_t samples[] = {15692, 45660, 15694, 45661};
    for (unsigned i = 0; i < UDP_MAPPING_SAMPLES; ++i) {
        p->udp_ports[i] = samples[i];
        p->udp_ips[i] = 1;
    }
    assert(udp_alternate_mapping(p) == 45661);
    p->udp_ips[2] = 2;
    assert(!udp_alternate_mapping(p));
    p->udp_ips[2] = 1;
    p->udp_ports[3] = 0;
    assert(!udp_alternate_mapping(p));
    p->udp_ports[3] = samples[3];

    t->mapped_ports[OP_FAM_V4] = t->mapped_port = samples[0];
    strcpy(t->mapped_text[OP_FAM_V4], "198.51.100.10");
    assert(!tunnel_learn_peer(t, "198.51.100.20", 31000));
    t->udp_dual_punch = t->udp_peer_cone = 1;
    c->nat[OP_FAM_V4].type = NAT_EASY_SYM_INC;
    json_object *j = json_object_new_object();
    op_ju(j, "coneNatPort", samples[0]);
    t->udp_punch_kind = announce_sym_window(c, t, j, OP_FAM_V4);
    assert(t->udp_punch_kind == 2 && op_integer(j, "symAltBase") == 45661);
    assert(op_integer(j, "symBase") == samples[0] && op_integer(j, "symCount") == SYM_WINDOW_HARD);
    assert(ordered_udp_role(c, t) == UDP_PUNCH_SEND);

    c->nat[OP_FAM_V4].type = NAT_CONE;
    t->udp_punch_kind = 0;
    assert(!tunnel_learn_peer(t, "198.51.100.20", samples[0]));
    learn_sym_window(t, j);
    assert(t->sym_alt_base == 45661 && ordered_udp_role(c, t) == UDP_PUNCH_RECEIVE);
    t->udp_dual_punch = 0;
    assert(ordered_udp_role(c, t) == UDP_PUNCH_LEGACY);
    op_ju(j, "symAltBase", 65536);
    learn_sym_window(t, j);
    assert(!t->sym_alt_base && t->sym_count == SYM_WINDOW_HARD);
    json_object_put(j);
    close_tunnel(c, ti, NULL);
    free(c);
}

static void udp_dual_window_packets(void) {
    op_socket base = socket_bound(1, "127.0.0.1", 0, 0);
    assert(base >= 0);
    uint16_t first = socket_port(base);
    uint16_t alternate_start = first < 32768 ? 50000 : 12000;
    op_socket second = -1, neighbor = -1;
    for (int i = 0; i < 16; ++i) {
        uint16_t port = (uint16_t)(alternate_start + 2 * i);
        second = socket_bound(1, "127.0.0.1", port, 0);
        if (second < 0)
            continue;
        neighbor = socket_bound(1, "127.0.0.1", (uint16_t)(port + 1), 0);
        if (neighbor >= 0)
            break;
        op_close(second);
    }
    assert(neighbor >= 0);
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    int ti = new_tunnel(c, "regular-node", 505, FASTP2P_TRANSPORT_QUIC, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    t->fd = socket_bound(1, "127.0.0.1", 0, 0);
    assert(t->fd >= 0);
    assert(!op_addr_socketname(base, &t->peer_addr));
    t->state = T_PUNCH;
    t->sym_split = 1;
    t->sym_base = t->remote_port = first;
    t->sym_alt_base = socket_port(second);
    t->sym_count = 8;
    t->udp_punch_role = UDP_PUNCH_RECEIVE;
    tick_udp_punch(c, ti, mono());
    assert(drain(second, SPRAY_WAIT) == 1);
    assert(drain(neighbor, SPRAY_WAIT) == 1);

    /* The symmetric peer answers from the alternate window, not its
     * initially advertised source port. Keep the tuple that actually worked. */
    op_addr local;
    assert(!op_addr_socketname(t->fd, &local));
    json_object *reply = json_object_new_object();
    op_ju(reply, "id", t->id);
    assert(!udp_packet(neighbor, &local, 4, 0, reply));
    json_object_put(reply);
    uint64_t until = mono() + NS;
    while (t->state == T_PUNCH && mono() < until) {
        tick_udp_punch(c, ti, mono());
        op_sleep_ms(2);
    }
    assert(t->state == T_UNDERLAY && t->remote_port == socket_port(neighbor));
    assert(op_addr_port(&t->peer_addr) == t->remote_port);
    assert(drain(neighbor, SPRAY_WAIT));
    close_tunnel(c, ti, NULL);
    op_buffer_clear(&c->ws_tx);
    free(c);
    op_close(neighbor);
    op_close(second);
    op_close(base);
}

static void deliver_control(fastp2p_client *from, fastp2p_client *to) {
    uint16_t main, sub;
    uint8_t *body;
    size_t length;
    int result;
    while ((result = op_frame_take(&from->ws_tx, &main, &sub, &body, &length)) == 1) {
        control_message(to, main, sub, body, length);
        free(body);
    }
    assert(!result);
}

static void ipv6_reverse_quic(void) {
    op_socket listeners[] = {socket_bound(1, "::1", 0, 0), socket_bound(1, "::1", 0, 0)};
    if (listeners[0] < 0 || listeners[1] < 0) {
        for (int i = 0; i < 2; ++i)
            if (listeners[i] >= 0)
                op_close(listeners[i]);
        return; /* IPv6 can be disabled by the local test runner. */
    }
    fastp2p_client *router = calloc(1, sizeof(*router)), *phone = calloc(1, sizeof(*phone));
    assert(router && phone);
    fastp2p_client *peers[] = {router, phone};
    const char *names[] = {"reverse-router", "reverse-phone"};
    const char *public_ips[] = {"2409:8a55::1", "2409:895a::1"};
    for (int i = 0; i < 2; ++i) {
        fastp2p_client *c = peers[i];
        strcpy(c->node, names[i]);
        c->node_id = op_node_id(c->node);
        c->ws = (struct lws *)c; /* Route the framed control messages in memory. */
        c->running = 1;
        c->families_wanted = c->gateway_families = FAM_V6;
        strcpy(c->local_ip[OP_FAM_V6], "::1");
        assert(!op_addr_from_text(&c->gateway_addr[OP_FAM_V6], "::1", 0));
        c->udp_listener[OP_FAM_V4] = -1;
        c->udp_listener[OP_FAM_V6] = listeners[i];
        c->public_port = socket_port(listeners[i]);
    }
    app *rule = &router->apps[0];
    rule->used = rule->local = rule->socks = 1;
    rule->transport = FASTP2P_TRANSPORT_QUIC;
    strcpy(rule->peer, phone->node);
    for (int retry = 0; retry < 2; ++retry) {
        int opening = app_tunnel(router, rule, phone->node, FASTP2P_TRANSPORT_QUIC);
        assert(opening >= 0);
        tunnel *out = &router->tunnels[opening];
        assert(out->udp_reverse6_retry == retry);
        ++rule->attempts;
        strcpy(out->mode, "udppunch");
        strcpy(router->local_ip[OP_FAM_V6], public_ips[0]);
        strcpy(out->mapped_text[OP_FAM_V6], public_ips[0]);
        out->mapped_ports[OP_FAM_V6] = out->probes[OP_FAM_V6].local_port = 45678;
        assert(ipv6_udp_listener_port(router, out) == router->public_port);
        ++out->mapped_ports[OP_FAM_V6];
        assert(!ipv6_udp_listener_port(router, out));
        --out->mapped_ports[OP_FAM_V6];
        probe_complete(router, opening);
        deliver_control(router, phone);
        int answering = tunnel_by_id(phone, out->id);
        assert(answering >= 0);
        tunnel *in = &phone->tunnels[answering];
        assert(in->udp_reverse6_retry == retry && in->udp_reverse_port6 == router->public_port);
        strcpy(in->mapped_text[OP_FAM_V6], public_ips[1]);
        in->mapped_ports[OP_FAM_V6] = in->probes[OP_FAM_V6].local_port;
        probe_complete(phone, answering);
        deliver_control(phone, router);

        if (!retry) {
            assert(out->udp_reverse6_supported && out->state == T_TIME);
            assert(out->udp_direct_port == phone->public_port && in->state == T_UDP_DIRECT);
            out->attempted_ipv6 = 1;
            close_tunnel(router, opening, "test forward IPv6 timeout");
            close_tunnel(phone, answering, NULL);
            assert(rule->udp_reverse6_retry && !rule->ipv4_retry && !rule->attempts);
            continue;
        }
        assert(out->state == T_UDP_DIRECT && out->server && out->attempted_ipv6);
        assert(in->state == T_TIME && !in->server && in->udp_direct_port == router->public_port);
        /* Public addresses exercise the negotiation gate. The in-process
         * transport uses loopback IPv6 with the very same negotiated ports. */
        strcpy(in->peer_text[OP_FAM_V6], "::1");
        strcpy(out->peer_text[OP_FAM_V6], "::1");
        uint64_t until = mono() + 5 * NS;
        while ((!tunnel_ready(out) || !tunnel_ready(in)) && mono() < until) {
            uint64_t now = mono();
            tick_udp_listeners(router, now);
            tick_tunnel(router, opening, now);
            tick_tunnel(phone, answering, now);
            deliver_control(router, phone);
            deliver_control(phone, router);
            op_sleep_ms(2);
        }
        assert(tunnel_ready(out) && tunnel_ready(in));
        assert(in->family == OP_FAM_V6 && op_addr_port(&in->peer_addr) == router->public_port);
        assert(out->cert_checked && in->cert_checked && out->session == in->session);
        close_tunnel(router, opening, NULL);
        close_tunnel(phone, answering, NULL);
    }
    for (int i = 0; i < 2; ++i) {
        op_close(listeners[i]);
        op_buffer_clear(&peers[i]->ws_tx);
        free(peers[i]);
    }
}

static void public_round_budget(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    c->state = FASTP2P_ONLINE;
    c->families_wanted = c->gateway_families = FAM_V4 | FAM_V6;
    assert(!op_addr_from_text(&c->gateway_addr[OP_FAM_V4], "127.0.0.1", 0));
    assert(!op_addr_from_text(&c->gateway_addr[OP_FAM_V6], "::1", 0));
    c->nat[OP_FAM_V4].type = NAT_HARD_SYM;
    strcpy(c->ip[OP_FAM_V4], "198.51.100.10");
    strcpy(c->local_ip[OP_FAM_V4], "127.0.0.1");
    app *a = &c->apps[0];
    a->used = a->local = 1;
    a->fd = a->tunnel_index = -1;
    a->transport = FASTP2P_TRANSPORT_QUIC;
    strcpy(a->peer, "remote-node");
    tick_apps(c, mono());
    int ti = a->tunnel_index;
    assert(ti >= 0 && a->attempts == 1);
    tunnel *t = &c->tunnels[ti];
    uint64_t first = t->id;
    strcpy(t->mapped_text[OP_FAM_V4], "198.51.100.10");
    t->mapped_ports[OP_FAM_V4] = 12345;
    assert(!tunnel_learn_peer(t, "198.51.100.10", 23456));
    t->state = T_PUNCH;
    t->attempted_ipv6 = 1;
    t->deadline = 0;
    tick_tunnel(c, ti, mono());
    assert(a->ipv4_retry && !a->attempts && a->tunnel_index < 0);

    a->retry = 0;
    tick_apps(c, mono());
    ti = a->tunnel_index;
    assert(ti >= 0 && a->attempts == 1);
    t = &c->tunnels[ti];
    assert(t->id != first && t->ipv4_only && t->probes[OP_FAM_V6].fd < 0);
    strcpy(c->local_ip[OP_FAM_V4], "192.168.1.1");
    const char lookup[] = "{\"peerNode\":\"remote-node\",\"IPv4\":\"198.51.100.10\","
                          "\"lanIP\":\"192.168.1.2\",\"natType\":2}";
    control_message(c, 7, 1, (const uint8_t *)lookup, sizeof(lookup) - 1);
    assert(lan_punch_possible(c, a) && a->attempts == 1 && a->tunnel_index == ti);
    close_tunnel(c, ti, "test public failure");
    a->retry = 0;
    tick_apps(c, mono());
    assert(a->lan_tried && a->attempts == 1);
    if (a->tunnel_index >= 0) {
        assert(c->tunnels[a->tunnel_index].lan);
        c->tunnels[a->tunnel_index].udp_direct_port = 12345;
        close_tunnel(c, a->tunnel_index, "test LAN failure");
    }
    assert(a->lan_tried && !a->udp_direct_tried && a->attempts == 1);

    strcpy(c->local_ip[OP_FAM_V4], "127.0.0.1");
    a->retry = 0;
    tick_apps(c, mono());
    assert(a->tunnel_index >= 0 && a->attempts == 2 && !a->relay_requested);
    assert(c->tunnels[a->tunnel_index].ipv4_only && !c->tunnels[a->tunnel_index].lan);
    close_tunnel(c, a->tunnel_index, "test second public failure");
    control_message(c, 7, 1, (const uint8_t *)lookup, sizeof(lookup) - 1);
    /* The relay is asked for only after PUBLIC_PUNCH_ROUNDS direct rounds; the loop
     * follows the constant so raising the budget does not silently change the ladder. */
    for (unsigned rounds = 2; rounds < PUBLIC_PUNCH_ROUNDS; ++rounds) {
        a->retry = 0;
        tick_apps(c, mono());
        assert(!a->relay_requested);
        assert(a->tunnel_index >= 0 && a->attempts == (int)(rounds + 1));
        close_tunnel(c, a->tunnel_index, "test extra public round");
        control_message(c, 7, 1, (const uint8_t *)lookup, sizeof(lookup) - 1);
    }
    a->retry = 0;
    tick_apps(c, mono());
    assert(a->relay_requested && a->attempts == PUBLIC_PUNCH_ROUNDS);
    op_buffer_clear(&c->ws_tx);
    free(c);
}

static char captured[256];
static void capture_event(fastp2p_client *client, const fastp2p_event *event, void *user) {
    (void)client;
    (void)user;
    snprintf(captured, sizeof(captured), "%s", event->message ? event->message : "");
}
/* A rule that refuses the relay used to re-enter the relay branch on every retry:
 * it asked the gateway, was refused again, and never punched again. It must
 * restart the direct rounds instead of filling the log every two seconds. */
static void relay_disabled_restarts_direct_rounds(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    c->state = FASTP2P_ONLINE;
    c->node_id = op_node_id("local-node");
    c->callback = capture_event;
    app *a = &c->apps[0];
    a->used = a->local = 1;
    a->no_relay = 1;
    a->attempts = PUBLIC_PUNCH_ROUNDS;
    a->transport = FASTP2P_TRANSPORT_TCP;
    a->tunnel_index = -1;
    a->retry = 0;
    strcpy(a->peer, "remote-node");
    a->port = 1234;
    a->dst_port = 22;
    captured[0] = 0;
    tick_apps(c, mono());
    assert(strstr(captured, "relay is disabled for this rule") != NULL);
    assert(a->attempts <= 1); /* a fresh direct round was started, not another relay request */
    assert(!a->relay_requested);
    for (int i = 0; i < NT; ++i)
        if (c->tunnels[i].state)
            close_tunnel(c, i, NULL);
    free(c);
}
/* A peer that reports a destination-dependent mapping gets the filter spray and
 * a parked listener; the listener must own the port after the spray sockets. */
static void dependent_peer_sprays_and_parks(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    c->node_id = op_node_id("local-node");
    strcpy(c->local_ip[OP_FAM_V4], "127.0.0.1");
    int ti = new_tunnel(c, "remote-node", 77, FASTP2P_TRANSPORT_TCP, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    strcpy(t->mode, "tcppunch");
    t->tcp_v2 = 1;
    t->state = T_TCP_CONNECT;
    t->peer_tcp_dependent = 1;
    t->family = OP_FAM_V4;
    assert(!op_addr_from_text(&t->peer_addr, "127.0.0.1", 9));
    t->remote_ports[OP_FAM_V4] = 9;
    op_socket local = socket_bound(0, "127.0.0.1", 0, 1);
    assert(local >= 0);
    t->local_port = socket_port(local);
    op_close(local);
    t->tcp_attempts = TCP_PUNCH_STALE_ATTEMPTS;
    t->tcp_timeouts = TCP_PUNCH_STALE_ATTEMPTS - 1;
    errno = ETIMEDOUT;
    tcp_punch_failed(c, ti, mono());
    assert(t->state == T_TCP_CONNECT && t->listen_fd >= 0 && !t->tcp_retry_at);
    close_tunnel(c, ti, NULL);
    free(c);
}
/* A minute of direct attempts without a tunnel pauses the ladder for ten seconds
 * instead of hammering the same unresponsive mapping. */
static void direct_attempts_pause_after_a_minute(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    c->state = FASTP2P_ONLINE;
    c->node_id = op_node_id("local-node");
    c->callback = capture_event;
    app *a = &c->apps[0];
    a->used = a->local = 1;
    a->transport = FASTP2P_TRANSPORT_TCP;
    a->tunnel_index = -1;
    a->retry = 0;
    strcpy(a->peer, "remote-node");
    a->port = 1234;
    a->dst_port = 22;
    a->punch_since = mono() - 61 * NS;
    captured[0] = 0;
    uint64_t before = mono();
    tick_apps(c, mono());
    assert(strstr(captured, "pausing 10 s") != NULL);
    assert(a->retry >= before + 9 * NS);
    assert(a->attempts == 0); /* no new round started during the pause */
    for (int i = 0; i < NT; ++i)
        if (c->tunnels[i].state)
            close_tunnel(c, i, NULL);
    free(c);
}
/* Allocation samples: the step between consecutive allocations of a symmetric
 * NAT is what the peer's prediction is built from. */
static void alloc_step_detection(void) {
    op_addr mapped[4];
    int step = 0;
    uint16_t port = 0;
    for (unsigned i = 0; i < 3; ++i)
        assert(!op_addr_from_text(&mapped[i], "36.140.165.200", (uint16_t)(5000 + i + 1)));
    assert(fp_tcp_alloc_delta(mapped, 3, &step, &port) == 1 && step == 1 && port == 5003);
    assert(!op_addr_from_text(&mapped[0], "36.140.165.200", 100));
    assert(!op_addr_from_text(&mapped[1], "36.140.165.200", 108));
    assert(!op_addr_from_text(&mapped[2], "36.140.165.200", 116));
    assert(fp_tcp_alloc_delta(mapped, 3, &step, &port) == 1 && step == 8 && port == 116);
    assert(!op_addr_from_text(&mapped[0], "36.140.165.200", 40000));
    assert(!op_addr_from_text(&mapped[1], "36.140.165.200", 39999));
    assert(!op_addr_from_text(&mapped[2], "36.140.165.200", 39998));
    assert(fp_tcp_alloc_delta(mapped, 3, &step, &port) == 1 && step == -1 && port == 39998);
    /* A random allocator has no constant difference; a constant one, however
     * large the jump, is still predictable. */
    assert(!op_addr_from_text(&mapped[0], "36.140.165.200", 1000));
    assert(!op_addr_from_text(&mapped[1], "36.140.165.200", 2000));
    assert(!op_addr_from_text(&mapped[2], "36.140.165.200", 1200));
    assert(fp_tcp_alloc_delta(mapped, 3, &step, &port) == 0);
    assert(!op_addr_from_text(&mapped[1], "36.140.165.200", 2000));
    assert(!op_addr_from_text(&mapped[2], "36.140.165.200", 3000));
    assert(fp_tcp_alloc_delta(mapped, 3, &step, &port) == 1 && step == 1000 && port == 3000);
    assert(fp_tcp_alloc_delta(mapped, 2, &step, &port) == -1);
    /* The prediction follows the measured step, not a fixed +-1. */
    assert(tcp_predict_next_port(FP_TCP_MAP_INCREMENT, 116, 8) == 124);
    assert(tcp_predict_next_port(FP_TCP_MAP_DECREMENT, 124, -8) == 116);
    assert(tcp_predict_next_port(FP_TCP_MAP_NONE, 116, 0) == 0);
    assert(tcp_predict_next_port(FP_TCP_MAP_INCREMENT, 65535, 8) == 0);
}
/* A destination-dependent peer with a measured step parks after a few dials and
 * listens for the rest of the peer's own window. */
static void dependent_peer_parks_quickly(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    c->node_id = op_node_id("local-node");
    strcpy(c->local_ip[OP_FAM_V4], "127.0.0.1");
    int ti = new_tunnel(c, "remote-node", 78, FASTP2P_TRANSPORT_TCP, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    strcpy(t->mode, "tcppunch");
    t->tcp_v2 = 1;
    t->state = T_TCP_CONNECT;
    t->peer_tcp_dependent = 1;
    t->peer_tcp_step = 8;
    t->peer_tcp_last_port = 30000;
    t->family = OP_FAM_V4;
    assert(!op_addr_from_text(&t->peer_addr, "127.0.0.1", 30001));
    t->remote_ports[OP_FAM_V4] = 30001;
    op_socket local = socket_bound(0, "127.0.0.1", 0, 1);
    assert(local >= 0);
    t->local_port = socket_port(local);
    op_close(local);
    t->tcp_attempts = TCP_PUNCH_QUICK_ATTEMPTS;
    t->tcp_timeouts = TCP_PUNCH_QUICK_ATTEMPTS - 1;
    t->deadline = mono() + 5 * NS;
    errno = ETIMEDOUT;
    uint64_t before = mono();
    tcp_punch_failed(c, ti, before);
    assert(t->state == T_TCP_CONNECT && t->listen_fd >= 0); /* parked, not closed */
    assert(t->deadline >= before + 25 * NS);               /* keeps listening */
    close_tunnel(c, ti, NULL);
    free(c);
}
/* A peer with a stable mapping has one reachable port: the dial must keep the
 * reported one instead of walking (which would also change the peer's own source
 * mapping when its NAT is destination-dependent). A moving peer still walks. */
static void stable_peer_keeps_the_reported_port(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    c->node_id = op_node_id("local-node");
    strcpy(c->local_ip[OP_FAM_V4], "127.0.0.1");
    int ti = new_tunnel(c, "remote-node", 79, FASTP2P_TRANSPORT_TCP, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    strcpy(t->mode, "tcppunch");
    t->tcp_v2 = 1;
    t->state = T_TCP_CONNECT;
    t->family = OP_FAM_V4;
    t->peer_tcp_mapping = FP_TCP_MAP_STABLE;
    t->remote_ports[OP_FAM_V4] = 41000;
    assert(!op_addr_from_text(&t->peer_addr, "127.0.0.1", 41000));
    op_socket local = socket_bound(0, "127.0.0.1", 0, 1);
    assert(local >= 0);
    t->local_port = socket_port(local);
    op_close(local);

    assert(tcp_peer_kind(t) == TCP_PEER_STABLE);
    t->tcp_scan = 3;
    tcp_punch_dial(c, ti, mono());
    assert(op_addr_port(&t->peer_addr) == 41000); /* no walk for a stable peer */

    t->peer_tcp_mapping = FP_TCP_MAP_INCREMENT;
    assert(tcp_peer_kind(t) == TCP_PEER_MOVES);
    t->tcp_scan = 3;
    tcp_punch_dial(c, ti, mono());
    assert(op_addr_port(&t->peer_addr) == tcp_scan_port(41000, 3)); /* a moving peer walks */

    t->peer_tcp_mapping = 0;
    assert(tcp_peer_kind(t) == TCP_PEER_UNKNOWN);
    t->peer_tcp_dependent = 1;
    assert(tcp_peer_kind(t) == TCP_PEER_MOVES); /* the peer's NAT type wins over its map field */
    close_tunnel(c, ti, NULL);
    free(c);
}
/* A stable peer that stays silent has a stale report: the round ends after a few
 * dials so the ladder can measure a fresh mapping, instead of walking for 11 s. */
static void stable_peer_ends_the_round_early(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    c->node_id = op_node_id("local-node");
    strcpy(c->local_ip[OP_FAM_V4], "127.0.0.1");
    int ti = new_tunnel(c, "remote-node", 80, FASTP2P_TRANSPORT_TCP, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    strcpy(t->mode, "tcppunch");
    t->tcp_v2 = 1;
    t->state = T_TCP_CONNECT;
    t->family = OP_FAM_V4;
    t->peer_tcp_mapping = FP_TCP_MAP_STABLE;
    t->remote_ports[OP_FAM_V4] = 41001;
    assert(!op_addr_from_text(&t->peer_addr, "127.0.0.1", 41001));
    op_socket local = socket_bound(0, "127.0.0.1", 0, 1);
    assert(local >= 0);
    t->local_port = socket_port(local);
    op_close(local);
    t->tcp_attempts = TCP_PUNCH_STABLE_ATTEMPTS;
    t->tcp_timeouts = TCP_PUNCH_STABLE_ATTEMPTS - 1;
    errno = ETIMEDOUT;
    tcp_punch_failed(c, ti, mono());
    assert(!t->state); /* closed: a fresh mapping, not another walk */
    free(c);
}
/* A responder never runs the per-tunnel sample, so it must still publish its
 * client-wide classification: otherwise a stable endpoint stays silent and the
 * peer walks neighbour ports for nothing. */
static void responder_publishes_a_stable_mapping(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    c->node_id = op_node_id("local-node");
    int ti = new_tunnel(c, "remote-node", 91, FASTP2P_TRANSPORT_TCP, 0);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    t->tcp_punch_immediate = 1;
    t->mapped_port = 40000;

    json_object *j = json_object_new_object();
    c->tcp_nat.family[OP_FAM_V4].type = FP_NAT_DEPENDENT;
    publish_tcp_mapping(c, t, j);
    assert(!op_integer(j, "tcpPunchMap")); /* nothing measured: nothing to say */
    json_object_put(j);

    /* The same dependent client, but this tunnel did measure a port. Publishing it
     * with the "no step" marker is what lets the peer aim its spray at where our
     * allocator is now instead of at the port the gateway measured long ago. */
    t->tcp_last_port = 61531;
    j = json_object_new_object();
    publish_tcp_mapping(c, t, j);
    assert(op_integer(j, "tcpPunchMap") == FP_TCP_MAP_UNPREDICTABLE);
    assert(op_integer(j, "tcpPunchLastPort") == 61531);
    assert(!op_integer(j, "tcpPunchStep"));
    json_object_put(j);
    t->tcp_last_port = 0;

    c->tcp_nat.family[OP_FAM_V4].type = FP_NAT_STABLE;
    j = json_object_new_object();
    publish_tcp_mapping(c, t, j);
    assert(op_integer(j, "tcpPunchMap") == FP_TCP_MAP_STABLE);
    assert(op_integer(j, "tcpPunchLastPort") == 40000);
    json_object_put(j);

    /* A tunnel that did sample keeps its own result and step. */
    t->tcp_mapping = FP_TCP_MAP_INCREMENT;
    t->tcp_last_port = 41000;
    t->tcp_step = 8;
    j = json_object_new_object();
    publish_tcp_mapping(c, t, j);
    assert(op_integer(j, "tcpPunchMap") == FP_TCP_MAP_INCREMENT);
    assert(op_integer(j, "tcpPunchLastPort") == 41000);
    assert(op_integer(j, "tcpPunchStep") == 8);
    json_object_put(j);

    /* A QUIC tunnel has no TCP mapping to publish. */
    int qi = new_tunnel(c, "remote-node", 92, FASTP2P_TRANSPORT_QUIC, 1);
    assert(qi >= 0);
    c->tunnels[qi].mapped_port = 40001;
    j = json_object_new_object();
    publish_tcp_mapping(c, &c->tunnels[qi], j);
    assert(!op_integer(j, "tcpPunchMap"));
    json_object_put(j);

    /* What the other side does with the marker: accept the port, never mistake it
     * for a predictable step. */
    json_object *learned = json_object_new_object();
    op_ju(learned, "tcpPunchMap", FP_TCP_MAP_UNPREDICTABLE);
    op_ju(learned, "tcpPunchLastPort", 61531);
    learn_tcp_mapping(t, learned);
    assert(t->peer_tcp_mapping == FP_TCP_MAP_UNPREDICTABLE);
    assert(t->peer_tcp_last_port == 61531);
    assert(tcp_peer_kind(t) == TCP_PEER_MOVES);
    assert(tcp_peer_unpredictable(t) == 1);
    assert(!tcp_predict_next_port(t->peer_tcp_mapping, t->peer_tcp_last_port, 0));
    json_object_put(learned);
    close_tunnel(c, qi, NULL);
    close_tunnel(c, ti, NULL);
    free(c);
}
/* The opener has to aim at where the symmetric side's allocator is *now*. A phone
 * CGNAT hands ports out monotonically (measured on the live pair: 61307, 61341,
 * 61381 ... +10..40 per connection), so a window centred on the port it measured
 * towards the gateway (50566 there) lands thousands of ports behind, and a
 * symmetric window spends half of its SYNs on ports the allocator already passed. */
static void spray_aims_ahead_of_an_unpredictable_peer(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    int ti = new_tunnel(c, "remote-node", 94, FASTP2P_TRANSPORT_TCP, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    snprintf(t->mode, sizeof(t->mode), "%s", "tcppunch");
    t->tcp_v2 = 1;
    t->family = OP_FAM_V4;
    t->remote_ports[OP_FAM_V4] = 50566; /* measured towards the gateway */
    t->remote_port = 50566;
    assert(!op_addr_from_text(&t->peer_addr, "203.0.113.9", 50566));
    const char *override = getenv("FASTP2P_TCP_SPRAY");
    int operator_width = override && *override;

    /* Nothing published by the peer: the advertised port is all there is, and the
     * window stays the historical symmetric one. */
    int low = 0, high = 0;
    assert(tcp_spray_base(t, OP_FAM_V4) == 50566);
    tcp_spray_window(t, 50566, &low, &high);
    if (!operator_width)
        assert(low == 50566 - (int)TCP_PUNCH_SPRAY && high == 50566 + (int)TCP_PUNCH_SPRAY);

    /* The peer published its own last observation: aim there, not at 50566, and
     * bias the window forward. */
    t->peer_tcp_mapping = FP_TCP_MAP_UNPREDICTABLE;
    t->peer_tcp_last_port = 61531;
    assert(tcp_peer_kind(t) == TCP_PEER_MOVES);
    assert(tcp_spray_base(t, OP_FAM_V4) == 61531);
    tcp_spray_window(t, 61531, &low, &high);
    if (!operator_width) {
        assert(high - 61531 == (int)TCP_PUNCH_SPRAY_WIDE);
        assert(61531 - low == (int)TCP_PUNCH_SPRAY_WIDE / 8);
        assert(TCP_PUNCH_SPRAY_WIDE > TCP_PUNCH_SPRAY);
    }
    /* A port we already know is not sprayed again. */
    assert(low < 61531 && high > 61531);

    /* A measured step still wins: that path predicts the exact next port. */
    t->peer_tcp_mapping = FP_TCP_MAP_INCREMENT;
    t->peer_tcp_step = 8;
    assert(tcp_predict_next_port(t->peer_tcp_mapping, t->peer_tcp_last_port, t->peer_tcp_step) ==
           61539);
    close_tunnel(c, ti, NULL);
    free(c);
}
/* Mixed pairs get a division of labour; equal or unknown types keep both dialling,
 * and a role the gateway assigned is never overridden. */
static void punch_role_follows_both_nat_types(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    int ti = new_tunnel(c, "remote-node", 93, FASTP2P_TRANSPORT_TCP, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];

    c->tcp_nat.family[OP_FAM_V4].type = FP_NAT_STABLE;
    t->peer_tcp_dependent = 1;
    assert(punch_role_decide(c, t) == TCP_PUNCH_OPENER);

    c->tcp_nat.family[OP_FAM_V4].type = FP_NAT_DEPENDENT;
    t->peer_tcp_dependent = 0;
    t->peer_tcp_mapping = FP_TCP_MAP_STABLE;
    assert(punch_role_decide(c, t) == TCP_PUNCH_DIALER);

    /* Two stable endpoints dial each other as before. */
    c->tcp_nat.family[OP_FAM_V4].type = FP_NAT_STABLE;
    assert(punch_role_decide(c, t) == TCP_PUNCH_AUTO);

    /* The gateway's assignment wins over the local guess. */
    t->punch_role = TCP_PUNCH_OPENER;
    c->tcp_nat.family[OP_FAM_V4].type = FP_NAT_DEPENDENT;
    assert(punch_role_decide(c, t) == TCP_PUNCH_OPENER);

    t->punch_role = TCP_PUNCH_AUTO;
    t->peer_tcp_mapping = 0;
    t->peer_tcp_dependent = 0;
    c->tcp_nat.family[OP_FAM_V4].type = 0; /* unknown */
    assert(punch_role_decide(c, t) == TCP_PUNCH_AUTO);
    close_tunnel(c, ti, NULL);
    free(c);
}
/* The dialer's local port is remembered per peer, not per rule: a pure responder
 * (the rule lives on the other node) has no app to hold it. */
static void punch_port_memory_is_per_peer(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    c->node_id = op_node_id("local-node");
    assert(punch_port_get(c, "peer-a") == 0);
    punch_port_note(c, "peer-a", 40000);
    assert(punch_port_get(c, "peer-a") == 40000);
    assert(punch_port_get(c, "peer-b") == 0);
    punch_port_note(c, "peer-b", 41000);
    assert(punch_port_get(c, "peer-a") == 40000 && punch_port_get(c, "peer-b") == 41000);

    /* A new tunnel towards that peer picks the remembered port up, in either role and
     * on either transport: the pin is what keeps the advertised mapping valid, and a
     * fresh socket every round moved it away while the peer kept dialling it. */
    int ti = new_tunnel(c, "peer-a", 94, FASTP2P_TRANSPORT_TCP, 0);
    assert(ti >= 0 && c->tunnels[ti].prefer_local_port == 40000);
    close_tunnel(c, ti, NULL);
    int qi = new_tunnel(c, "peer-a", 95, FASTP2P_TRANSPORT_QUIC, 1);
    assert(qi >= 0 && c->tunnels[qi].prefer_local_port == 40000);
    close_tunnel(c, qi, NULL);

    /* After the rotation window the port is dropped so a hopeless one is abandoned. */
    for (unsigned i = 0; i < TCP_DIALER_PORT_ROUNDS; ++i)
        punch_port_note(c, "peer-a", (uint16_t)(40000 + i));
    assert(punch_port_get(c, "peer-a") == 0);
    free(c);
}
/* The whole round trip: a dialler round ends, and the next tunnel towards the same
 * peer asks its probe for the same local port. */
static void dialer_port_survives_the_round(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    c->node_id = op_node_id("local-node");
    /* The port is recorded when the probe binds it, so this is the moment a round
     * hands its port to the next one. */
    punch_port_note(c, "peer-p", 39851);
    assert(punch_port_get(c, "peer-p") == 39851);
    int t2 = new_tunnel(c, "peer-p", 97, FASTP2P_TRANSPORT_TCP, 1);
    assert(t2 >= 0);
    assert(c->tunnels[t2].prefer_local_port == 39851);
    close_tunnel(c, t2, NULL);
    free(c);
}
/* A peer that publishes IPv6 must not drag a host without any IPv6 address into
 * dialling it: the kernel answers EAFNOSUPPORT and the whole window is lost. */
static void v6_is_skipped_when_the_host_has_no_v6(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    int ti = new_tunnel(c, "peer-v6", 98, FASTP2P_TRANSPORT_TCP, 0);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    strcpy(t->peer_text[OP_FAM_V4], "198.51.100.9");
    strcpy(t->peer_text[OP_FAM_V6], "2409:895a:f363:b139:b814:b5ff:fe8b:c238");
    strcpy(t->mapped_text[OP_FAM_V4], "172.16.12.192");
    strcpy(t->mapped_text[OP_FAM_V6], "2409:895a:f363::1");
    t->peer_ready[OP_FAM_V4] = t->peer_ready[OP_FAM_V6] = 1;
    t->mapped_ports[OP_FAM_V4] = 40000;
    t->mapped_ports[OP_FAM_V6] = 40001;
    /* A host that has its own v6 address prefers it, as before. */
    strcpy(c->local_ip[OP_FAM_V6], "2409:895a:f363::2");
    assert(choose_punch_family(c, t) == OP_FAM_V6);
    /* Without one, the same tunnel must not keep the v6 choice. */
    c->local_ip[OP_FAM_V6][0] = 0;
    assert(family_usable(c, t, OP_FAM_V6) == 0);
    assert(choose_punch_family(c, t) == OP_FAM_V4);
    close_tunnel(c, ti, NULL);
    free(c);
}
/* The family the target address belongs to wins over a stale choice: dialling a
 * v4 target from a v6 source fails every attempt with EAFNOSUPPORT. */
static void punch_target_family_wins(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    strcpy(c->local_ip[OP_FAM_V4], "192.0.2.10");
    int ti = new_tunnel(c, "peer-fam", 99, FASTP2P_TRANSPORT_TCP, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    strcpy(t->peer_text[OP_FAM_V4], "198.51.100.9");
    strcpy(t->mapped_text[OP_FAM_V4], "192.0.2.10");
    t->peer_ready[OP_FAM_V4] = 1;
    t->mapped_ports[OP_FAM_V4] = 41000;
    t->family = OP_FAM_V6;                       /* stale choice from the answer */
    assert(!op_addr_from_text(&t->peer_addr, "198.51.100.9", 41000));
    assert(punch_realign_family(c, ti) == 0);
    assert(t->family == OP_FAM_V4);
    assert(op_family_index(op_addr_family(&t->peer_addr)) == OP_FAM_V4);

    /* A target in a family this host has no address for ends the round, even when
     * the tunnel's own family already matches it. */
    assert(!op_addr_from_text(&t->peer_addr, "2409:895a:f363::9", 42000));
    t->family = OP_FAM_V4;
    assert(punch_realign_family(c, ti) == -1);
    int ti2 = new_tunnel(c, "peer-fam2", 199, FASTP2P_TRANSPORT_TCP, 0);
    assert(ti2 >= 0);
    tunnel *v6 = &c->tunnels[ti2];
    assert(!op_addr_from_text(&v6->peer_addr, "2409:895a:f363::9", 42000));
    v6->family = OP_FAM_V6;
    assert(punch_realign_family(c, ti2) == -1);
    free(c);
}
/* A port-preserving mapping is pinned; any other mapping rotates every round,
 * because pinning it only repeats the same miss. */
static void only_a_preserving_mapping_is_pinned(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    assert(punch_port_worth_keeping(34191, 34191));
    assert(!punch_port_worth_keeping(26025, 38563));
    assert(!punch_port_worth_keeping(0, 38563));
    punch_port_note(c, "peer-k", 34191);
    assert(punch_port_get(c, "peer-k") == 34191);
    punch_port_forget(c, "peer-k");
    assert(punch_port_get(c, "peer-k") == 0);
    int ti = new_tunnel(c, "peer-k", 100, FASTP2P_TRANSPORT_TCP, 1);
    assert(ti >= 0 && c->tunnels[ti].prefer_local_port == 0);
    close_tunnel(c, ti, NULL);
    free(c);
}
/* Even with no measured mapping in the target's family the source must be switched:
 * otherwise every dial keeps failing on the family mismatch. */
static void target_family_switch_needs_no_mapping(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    strcpy(c->local_ip[OP_FAM_V4], "192.0.2.10");
    int ti = new_tunnel(c, "peer-sw", 200, FASTP2P_TRANSPORT_TCP, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    assert(!op_addr_from_text(&t->peer_addr, "198.51.100.9", 41000));
    t->family = OP_FAM_V6;
    assert(punch_realign_family(c, ti) == 0);
    assert(t->family == OP_FAM_V4);
    free(c);
}
/* A central section must give the hub one rule slot per peer, and the transport the
 * operator asked for must reach the rules it creates. */
static void sdwan_section_builds_rules(void) {
    struct { const char *mode, *center, *node, *transport; unsigned slots; int tcp; } cases[] = {
        {"mesh", "", "xrwgxserver", "quic", 2, 0},
        {"central", "xrwgxserver", "xrwgxserver", "quic", 2, 0},   /* this node is the hub */
        {"central", "redmibook", "xrwgxserver", "udp", 1, 0},      /* a peer is the hub */
        {"mesh", "", "xrwgxserver", "tcp", 2, 1},
    };
    for (unsigned k = 0; k < sizeof(cases) / sizeof(cases[0]); ++k) {
        fastp2p_client *c = calloc(1, sizeof(*c));
        assert(c);
        snprintf(c->node, sizeof(c->node), "%s", cases[k].node);
        char text[640];
        snprintf(text, sizeof(text),
                 "{\"Mode\":\"%s\",\"Center\":\"%s\",\"Transport\":\"%s\","
                 "\"Subnet\":\"10.3.2.0/24\",\"Address\":\"10.3.2.30\",\"Peers\":["
                 "{\"Node\":\"redmibook\",\"Address\":\"10.3.2.10\"},"
                 "{\"Node\":\"ubuntu06\",\"Address\":\"10.3.2.20\"}]}",
                 cases[k].mode, cases[k].center, cases[k].transport);
        json_object *cfg = json_tokener_parse(text);
        assert(cfg);
#if defined(__linux__) || defined(_WIN32)
        assert(fp_client_sdwan_config(c, cfg) == FASTP2P_OK);
#else
        /* SD-WAN needs a TUN device, so the section is refused on this platform; the
         * parse itself still has to accept the document. */
        assert(fp_client_sdwan_config(c, cfg) == FASTP2P_EINVAL);
        json_object_put(cfg);
        free(c);
        continue;
#endif
        json_object_put(cfg);
        assert(c->sdwan && c->sdwan->peer_count == 2);
        assert(c->sdwan->transport == (cases[k].tcp ? FASTP2P_TRANSPORT_TCP : FASTP2P_TRANSPORT_QUIC));
        assert(!c->sdwan->no_relay);
        unsigned assigned = 0;
        int slot = -1;
        for (unsigned i = 0; i < c->sdwan->peer_count; ++i) {
            if (c->sdwan->peers[i].app_index < 0)
                continue;
            ++assigned;
            slot = c->sdwan->peers[i].app_index;
        }
        assert(assigned == cases[k].slots);
        if (slot >= 0) {
            assert(c->apps[slot].sdwan && c->apps[slot].used);
            assert(c->apps[slot].transport ==
                   (cases[k].tcp ? FASTP2P_TRANSPORT_TCP : FASTP2P_TRANSPORT_QUIC));
        }
        fp_sdwan_stop(c->sdwan);
        free(c->sdwan);
        c->sdwan = NULL;
        free(c);
    }
    /* "Relay": "forbid" must reach the rules the section creates: the branches then keep
     * retrying direct rounds instead of asking the gateway for a relay node. */
    {
        fastp2p_client *c = calloc(1, sizeof(*c));
        assert(c);
        snprintf(c->node, sizeof(c->node), "%s", "xrwgxserver");
        char text[512];
        snprintf(text, sizeof(text),
                 "{\"Mode\":\"mesh\",\"Relay\":\"forbid\",\"Subnet\":\"10.3.2.0/24\","
                 "\"Address\":\"10.3.2.30\",\"Peers\":[{\"Node\":\"redmibook\","
                 "\"Address\":\"10.3.2.10\"}]}");
        json_object *cfg = json_tokener_parse(text);
        assert(cfg);
#if defined(__linux__) || defined(_WIN32)
        assert(fp_client_sdwan_config(c, cfg) == FASTP2P_OK);
        assert(c->sdwan->no_relay == 1);
        assert(c->sdwan->peers[0].app_index >= 0);
        assert(c->apps[c->sdwan->peers[0].app_index].no_relay == 1);
        fp_sdwan_stop(c->sdwan);
        free(c->sdwan);
        c->sdwan = NULL;
#else
        assert(fp_client_sdwan_config(c, cfg) == FASTP2P_EINVAL);
#endif
        json_object_put(cfg);
        free(c);
    }
}
/* Pinning keeps the advertised external port valid. A cone NAT that rewrites the port
 * (external != local) still rewrites it the same way every time, so rotating there
 * published a new port every round while the peer kept dialling the old one. */
static void a_stable_mapping_pins_the_local_port_even_when_rewritten(void) {
    assert(punch_port_keep(52840, 52840, 0));   /* port-preserving */
    assert(punch_port_keep(28482, 52840, 1));   /* stable mapping, rewritten port */
    assert(!punch_port_keep(28482, 52840, 0));  /* moves per destination: rotate */
    assert(!punch_port_keep(0, 52840, 1));      /* unmapped: nothing to pin */
}
/* The dialler's source-port array is the only mechanism that answers "which of our
 * external ports will the peer's filter admit": N local ports, N external ports,
 * and the cone side's spray only has to cover one of them. The width doubles after
 * every spent rotation, so a round that keeps missing spends progressively more
 * SYNs instead of repeating the same lottery. */
static void tcp_array_width_escalates(void) {
    /* The ladder with the built-in ceiling: 64 -> 128 -> 256 -> 512, then it stays. */
    assert(tcp_array_next_width(0, TCP_PUNCH_ARRAY_LIMIT) == TCP_PUNCH_ARRAY);
    assert(tcp_array_next_width(TCP_PUNCH_ARRAY, TCP_PUNCH_ARRAY_LIMIT) == 128);
    assert(tcp_array_next_width(128, TCP_PUNCH_ARRAY_LIMIT) == 256);
    assert(tcp_array_next_width(256, TCP_PUNCH_ARRAY_LIMIT) == 512);
    assert(tcp_array_next_width(512, TCP_PUNCH_ARRAY_LIMIT) == 512);
    /* A lowered ceiling applies at once instead of starting at the default. */
    assert(tcp_array_next_width(0, 16) == 16);
    assert(tcp_array_next_width(16, 16) == 16);
    assert(tcp_array_next_width(0, 0) == 0);
    /* FASTP2P_TCP_ARRAY moves the ceiling only; the ladder still starts below it. */
    unsigned ceiling = tcp_array_config_width();
    assert(ceiling >= 1 && ceiling <= TCP_PUNCH_ARRAY_LIMIT);
    const char *override = getenv("FASTP2P_TCP_ARRAY");
    if (!override || !*override)
        assert(ceiling == TCP_PUNCH_ARRAY_LIMIT);
    assert(tcp_array_next_width(0, ceiling) ==
           (ceiling < TCP_PUNCH_ARRAY ? ceiling : TCP_PUNCH_ARRAY));
    /* The per-client ceiling is a descriptor budget large enough for one full array. */
    assert(TCP_ARRAY_CLIENT_LIMIT >= TCP_PUNCH_ARRAY_LIMIT);
}
static void dialer_array_uses_many_source_ports(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    snprintf(c->local_ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", "127.0.0.1");
    uint16_t remote = 0;
    op_socket endpoint = bound_port(&remote);
    assert(!op_listen(endpoint, 8));
    int ti = new_tunnel(c, "array-target", 90210, FASTP2P_TRANSPORT_TCP, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    snprintf(t->mode, sizeof(t->mode), "%s", "tcppunch");
    t->tcp_v2 = 1;
    t->family = OP_FAM_V4;
    t->state = T_TCP_CONNECT;
    t->deadline = mono() + 5 * NS;
    t->punch_role = TCP_PUNCH_DIALER;
    /* The peer published one stable endpoint: exactly the case the array is for. */
    t->peer_tcp_mapping = FP_TCP_MAP_STABLE;
    t->remote_ports[OP_FAM_V4] = t->remote_port = remote;
    assert(!op_addr_from_text(&t->peer_addr, "127.0.0.1", remote));
    tcp_punch_dial(c, ti, mono());
    assert(t->array_count >= 2);
    assert(t->array_width == tcp_array_next_width(0, tcp_array_config_width()));
    assert(c->tcp_array_used == t->array_count);
    assert(t->fd < 0); /* the attempt is the array, not a single dial */
    uint64_t until = mono() + 3 * NS;
    while (t->state == T_TCP_CONNECT && mono() < until) {
        tick_tunnel(c, ti, mono());
        op_sleep_ms(2);
    }
    /* One of the source ports connected; the rest of the rotation is gone and the
     * client-wide descriptor budget is returned. */
    assert(t->state == T_HANDSHAKE && t->fd >= 0);
    assert(t->array == NULL && t->array_count == 0 && c->tcp_array_used == 0);
    op_addr peer;
    memset(&peer, 0, sizeof(peer));
    op_socket accepted = -1;
    for (int attempt = 0; attempt < 50 && accepted < 0; ++attempt) {
        peer.len = (op_socklen)sizeof(peer.u.storage);
        accepted = op_accept(endpoint, &peer.u.sa, &peer.len);
        if (accepted < 0)
            op_sleep_ms(2);
    }
    assert(accepted >= 0);
    op_close(accepted);
    close_tunnel(c, ti, NULL);
    assert(c->tcp_array_used == 0);
    free(c);
    op_close(endpoint);
}
static void dialer_array_leaves_undiallable_peers_alone(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    snprintf(c->local_ip[OP_FAM_V4], OP_ADDR_TEXT, "%s", "127.0.0.1");
    uint16_t remote = 0;
    op_socket endpoint = bound_port(&remote);
    assert(!op_listen(endpoint, 8));
    int ti = new_tunnel(c, "array-target", 90211, FASTP2P_TRANSPORT_TCP, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    snprintf(t->mode, sizeof(t->mode), "%s", "tcppunch");
    t->tcp_v2 = 1;
    t->family = OP_FAM_V4;
    t->state = T_TCP_CONNECT;
    t->deadline = mono() + 5 * NS;
    t->punch_role = TCP_PUNCH_AUTO;
    /* A peer whose mapping moves per destination cannot be dialled on any fixed
     * port, so a fleet of source ports buys nothing: the destination axis is the
     * one missing there. */
    t->peer_tcp_mapping = FP_TCP_MAP_INCREMENT;
    t->remote_ports[OP_FAM_V4] = t->remote_port = remote;
    assert(!op_addr_from_text(&t->peer_addr, "127.0.0.1", remote));
    tcp_punch_dial(c, ti, mono());
    assert(t->array == NULL && t->array_count == 0 && c->tcp_array_used == 0);
    /* The opener's job is the opposite (open our own filter and listen), so it must
     * not build a fleet of dialling sockets either. */
    if (t->fd >= 0) {
        op_close(t->fd);
        t->fd = -1;
    }
    t->punch_role = TCP_PUNCH_OPENER;
    t->peer_tcp_mapping = FP_TCP_MAP_STABLE;
    t->tcp_attempts = 0;
    tcp_punch_dial(c, ti, mono());
    assert(t->array == NULL && c->tcp_array_used == 0);
    close_tunnel(c, ti, NULL);
    free(c);
    op_close(endpoint);
}
/* A host behind a default-deny firewall only has its business port open, so a dial
 * to the peer's advertised mapping dies at that firewall. The published business port
 * therefore wins over every number derived from a mapping. */
static void dial_target_prefers_the_peer_business_port(void) {
    fastp2p_client *c = calloc(1, sizeof(*c));
    assert(c);
    int ti = new_tunnel(c, "remote-node", 95, FASTP2P_TRANSPORT_TCP, 1);
    assert(ti >= 0);
    tunnel *t = &c->tunnels[ti];
    t->family = OP_FAM_V4;
    t->remote_ports[OP_FAM_V4] = 33575; /* the mapping measured towards the gateway */
    assert(!op_addr_from_text(&t->peer_addr, "203.0.113.9", 33575));
    assert(tcp_dial_target(t) == 33575);
    /* Once the peer names its business port, nothing else is dialled. */
    t->peer_direct_port = 1510;
    assert(tcp_dial_target(t) == 1510);
    close_tunnel(c, ti, NULL);
    free(c);
}
int main(void) {
    assert(!op_platform_init());
    punch_role_follows_both_nat_types();
    v6_is_skipped_when_the_host_has_no_v6();
    punch_target_family_wins();
    only_a_preserving_mapping_is_pinned();
    a_stable_mapping_pins_the_local_port_even_when_rewritten();
    sdwan_section_builds_rules();
    target_family_switch_needs_no_mapping();
    punch_port_memory_is_per_peer();
    dialer_port_survives_the_round();
    responder_publishes_a_stable_mapping();
    stable_peer_keeps_the_reported_port();
    stable_peer_ends_the_round_early();
    alloc_step_detection();
    dependent_peer_parks_quickly();
    relay_disabled_restarts_direct_rounds();
    dependent_peer_sprays_and_parks();
    direct_attempts_pause_after_a_minute();
    tcp_retry();
    tcp_punch_walks_ports_when_silent();
    tcp_punch_scheduling();
    quic_uses_punch_endpoint();
    peer_listener_port_conflict();
    nat_remeasure_follows_the_path();
    mapping_probe_borrows_the_peer_port();
    mapping_reply_comes_through_the_listener();
    remeasure_waits_for_the_punch();
    self_hosted_stun_is_preferred();
    private_gateway_address_is_not_comparable();
    mapping_follows_the_destination_address();
    mapping_stays_a_cone_across_addresses();
    mapping_depends_on_the_address_only();
    unanswered_second_address_keeps_the_cone();
    udp_array_width_and_ceiling();
    udp_punch_uses_winning_socket();
    lan_punch_public_ipv4();
    public_round_budget();
    /* Built-in probe defaults. Two destinations each, because the UDP filter test
     * needs a second *address* to answer and the TCP mapping test cannot classify a
     * destination-dependent mapping from the gateway's single probe address. */
    {
        fastp2p_client probes = {0};
        assert(fp_client_tcp_nat_config(&probes, NULL) == FASTP2P_OK);
        assert(probes.tcp_nat.server_count == 2);
        assert(!strcmp(probes.tcp_nat.servers[0].host, "stun.fastp2p.top"));
        assert(probes.tcp_nat.servers[0].port == 3478);
        assert(!strcmp(probes.tcp_nat.servers[1].host, "stun.nextcloud.com"));
        assert(probes.tcp_nat.servers[1].port == 443);
        assert(fp_client_stun_config(&probes, NULL) == FASTP2P_OK);
        assert(probes.stun_count == 2);
        assert(!strcmp(probes.stun_host[0], "stun.miwifi.com") && probes.stun_port[0] == 3478);
        assert(!strcmp(probes.stun_host[1], "stun.fastp2p.top") && probes.stun_port[1] == 3478);
        /* An explicit empty array still opts out of leaving the host. */
        json_object *none = json_object_new_array();
        assert(none);
        assert(fp_client_tcp_nat_config(&probes, none) == FASTP2P_OK);
        assert(probes.tcp_nat.server_count == 0);
        assert(fp_client_stun_config(&probes, none) == FASTP2P_OK);
        assert(probes.stun_count == 0);
        json_object_put(none);
    }
    /* Dense start: the first half second decides a cone-to-cone punch. */
    assert(punch_interval(0) == 50 * MS);
    assert(punch_interval(499 * MS) == 50 * MS);
    assert(punch_interval(500 * MS) == 200 * MS);
    assert(punch_interval(9 * NS) == 200 * MS);

    /* Mapping classification. */
    /* NAT1..NAT4 come from the mapping result plus the public STUN verdict.
     * A symmetric mapping is NAT4 whatever STUN would say, and a cone mapping is
     * only NAT1 when a *different address* actually answered. */
    fastp2p_client levels = {0};
    levels.nat[OP_FAM_V4].type = NAT_UNKNOWN;
    assert(nat_level(&levels) == 0);
    levels.nat[OP_FAM_V4].type = NAT_CONE;
    assert(nat_level(&levels) == 5); /* cone, but nothing measured the filter */
    nat_filter_record(&levels.udp_filter, 1, mono());
    assert(nat_level(&levels) == 1); /* another address answered */
    nat_filter_record(&levels.udp_filter, 2, mono());
    assert(nat_level(&levels) == 2); /* only another port answered */
    nat_filter_record(&levels.udp_filter, 3, mono());
    assert(nat_level(&levels) == 3); /* nothing outside the tuple answered */
    for (int symmetric = NAT_HARD_SYM; symmetric <= NAT_EASY_SYM_DEC; ++symmetric) {
        levels.nat[OP_FAM_V4].type = symmetric;
        nat_filter_record(&levels.udp_filter, 1, mono());
        assert(nat_level(&levels) == 4); /* mapping decides; STUN is moot */
    }
    /* 6 and 7 mean there is no NAT: the mapping is our own address, so the
     * level describes the host firewall rather than a translation. */
    levels.nat[OP_FAM_V4].type = NAT_CONE;
    nat_filter_record(&levels.udp_filter, 6, mono());
    assert(nat_level(&levels) == 6);
    nat_filter_record(&levels.udp_filter, 7, mono());
    assert(nat_level(&levels) == 7);
    levels.udp_filter = (nat_filter){0};
    levels.nat[OP_FAM_V4].type = NAT_CONE;
    assert(nat_level(&levels) == 5); /* STUN unreachable: stay undetermined */
    nat_filter filters = {0};
    nat_filter_record(&filters, 0, NS);
    assert(nat_filter_level(&filters, NS) == 0 && filters.next_at == NS + NAT_FILTER_RETRY);
    nat_filter_record(&filters, 3, 2 * NS);
    assert(filters.next_at == 2 * NS + NAT_FILTER_REFRESH);
    assert(nat_filter_level(&filters, filters.next_at) == 3);
    assert(nat_filter_level(&filters, 2 * NS + NAT_FILTER_MAX_AGE) == 0);
    uint64_t refresh = filters.next_at;
    nat_filter_record(&filters, 0, refresh);
    assert(nat_filter_level(&filters, refresh) == 0 && filters.next_at == refresh + NAT_FILTER_RETRY);
    nat_filter_record(&levels.udp_filter, 3, mono());
    nat_filter_record(&levels.tcp_filter, 2, mono());
    assert(nat_level(&levels) == 3 && tcp_nat_level(&levels) == 2);
    nat_filter_record(&levels.udp_filter, 0, mono());
    nat_filter_record(&levels.tcp_filter, 0, mono());
    assert(nat_level(&levels) == 5 && tcp_nat_level(&levels) == 0);

    assert(nat_classify(40000, 40000, 0) == NAT_CONE);    assert(nat_classify(40000, 40001, 0) == NAT_HARD_SYM);
    assert(nat_classify(40000, 40001, 40000) == NAT_CONE);
    assert(nat_classify(40000, 41000, 40005) == NAT_EASY_SYM_INC);
    assert(nat_classify(40000, 41000, 39995) == NAT_EASY_SYM_DEC);
    assert(nat_classify(40000, 41000, 40101) == NAT_HARD_SYM);
    assert(nat_classify(40000, 41000, 39899) == NAT_HARD_SYM);

    /* A peer with no window leaves only its observed port worth a packet. */
    assert(sym_window_cap(0) == 0);
    assert(sym_window_base(40000, 0, 0) == 40000);

    /* Window cap keeps a peer from asking for an unbounded burst. */
    assert(sym_window_cap(200) == SYM_WINDOW_MAX);
    assert(sym_window_cap(SYM_WINDOW_MAX) == SYM_WINDOW_MAX);

    /* Incrementing window starts just above the observed port, and stops at
     * the end of the range instead of wrapping onto unrelated ports. */
    assert(sym_window_span(65530, 1, 50) == 5);
    assert(sym_window_base(65530, 1, 50) == 65531);
    /* Decrementing never reaches port 0. */
    assert(sym_window_span(1, 0, 50) == 0);
    assert(sym_window_base(1, 0, 50) == 1);
    assert(sym_window_span(20, 0, 50) == 19);
    /* Downward window starts at observed-1 and walks down, so it covers the
     * ports nearest the observed mapping rather than a span below it. */
    assert(sym_window_base(20, 0, 50) == 19);
    assert(sym_window_base(40000, 0, 50) == 39999);
    /* Decrementing window starts count ports below it, never below 1. */
    assert(sym_window_base(40000, 1, 50) == 40001);

    /* Which mapping behaviours get a window at all. */
    assert(sym_window_kind(NAT_CONE) == 0);
    assert(sym_window_kind(NAT_UNKNOWN) == 0);
    assert(sym_window_kind(NAT_EASY_SYM_INC) == 1);
    assert(sym_window_kind(NAT_EASY_SYM_DEC) == 1);
    assert(sym_window_kind(NAT_HARD_SYM) == 2);

    /* A centred window is capped wider than a directional one, because it has
     * to cover both sides of the observation. */
    assert(sym_window_hard_cap(200) == SYM_WINDOW_HARD);
    assert(sym_window_hard_cap(SYM_WINDOW_HARD + 1) == SYM_WINDOW_HARD);
    assert(sym_window_hard_cap(0) == 0);
    assert(sym_window_hard_cap(2) == 2);

    /* The centred window straddles the observation and skips the observed port,
     * which is punched explicitly. */
    uint16_t low = 0, high = 0;
    assert(sym_split_window(40000, SYM_WINDOW_HARD, &low, &high));
    assert(low == 40000 - SYM_WINDOW_HARD / 2 && high == 40000 + SYM_WINDOW_HARD / 2);
    assert(sym_split_window(40000, 2, &low, &high) && low == 39999 && high == 40001);
    /* Edges clamp to the port range instead of wrapping around. */
    assert(sym_split_window(1, SYM_WINDOW_HARD, &low, &high) && low == 1);
    assert(high == 1 + SYM_WINDOW_HARD / 2);
    assert(sym_split_window(65535, SYM_WINDOW_HARD, &low, &high) && high == 65535);
    assert(low == 65535 - SYM_WINDOW_HARD / 2);
    assert(sym_split_window(1, 2, &low, &high) && low == 1 && high == 2);
    assert(sym_split_window(65535, 2, &low, &high) && low == 65534 && high == 65535);
    /* One port is not a window: the caller drops it instead of half-spraying. */
    assert(!sym_split_window(40000, 1, &low, &high));
    assert(!sym_split_window(40000, SYM_WINDOW_HARD, NULL, &high));

    /* A destination-dependent peer is reached by covering a random slice of the port
     * range each round. The slice must stay bounded (no 2048-port march) and must move,
     * otherwise every round retries the same ports. */
    {
        unsigned smallest = 65535, largest = 0, first = tcp_sweep_chunk();
        int moved = 0;
        for (int i = 0; i < 200; ++i) {
            unsigned chunk = tcp_sweep_chunk();
            if (chunk < smallest) smallest = chunk;
            if (chunk > largest) largest = chunk;
            if (chunk != first) moved = 1;
        }
        assert(moved);
        assert(smallest >= TCP_SWEEP_MIN);
        const char *override = getenv("FASTP2P_TCP_SWEEP");
        if (!override || !*override) assert(largest <= TCP_SWEEP_MAX);
    }
    punch_accepts_the_carrier_pool();
    window_offer_decides_the_role();
    sym_window_wire();
    sym_spray_ports();
    udp_dual_window_wire();
    udp_dual_window_packets();
    ipv6_reverse_quic();
    tcp_array_width_escalates();
    dialer_array_uses_many_source_ports();
    dialer_array_leaves_undiallable_peers_alone();
    spray_aims_ahead_of_an_unpredictable_peer();
    dial_target_prefers_the_peer_business_port();
    return 0;
}
