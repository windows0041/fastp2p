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
    tick_tunnel(c, ti, t->punch_started);
    assert(t->udp_candidate_count == UDP_PUNCH_EXTRA_SOCKETS);
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
    a->retry = 0;
    tick_apps(c, mono());
    assert(a->relay_requested && a->attempts == 2);
    op_buffer_clear(&c->ws_tx);
    free(c);
}

int main(void) {
    assert(!op_platform_init());
    tcp_retry();
    tcp_punch_scheduling();
    quic_uses_punch_endpoint();
    peer_listener_port_conflict();
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

    sym_window_wire();
    sym_spray_ports();
    udp_dual_window_wire();
    udp_dual_window_packets();
    ipv6_reverse_quic();
    return 0;
}
