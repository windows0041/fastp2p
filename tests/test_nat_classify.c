/* Check NAT decisions and exercise punch handoff on loopback sockets. */
#include "../src/client.c"
#include <assert.h>

static op_socket bound_port(uint16_t *port) {
    op_socket fd=socket_bound(0,"127.0.0.1",0,1);assert(fd>=0);*port=socket_port(fd);assert(*port);return fd;
}
static void tcp_retry(void) {
    fastp2p_client *c=calloc(1,sizeof(*c));assert(c);strcpy(c->local_ip[OP_FAM_V4],"127.0.0.1");
    uint16_t remote,local;op_socket endpoint=bound_port(&remote),reserve=bound_port(&local);op_close(reserve);
    int ti=new_tunnel(c,"retry-target",100,FASTP2P_TRANSPORT_TCP,0);assert(ti>=0);
    tunnel *t=&c->tunnels[ti];strcpy(t->ip,"127.0.0.1");strcpy(t->mode,"tcppunch");
    t->local_port=local;t->remote_port=remote;t->tcp_v2=1;t->server=1;
    assert(!op_addr_from_text(&t->peer_addr,"127.0.0.1",remote));
    /* BSD may leave the first connect pending until the production 3-second
     * attempt deadline instead of reporting an immediate loopback refusal. */
    start_underlay(c,ti);uint64_t until=mono()+12*NS;int listening=0;
    while(t->state==T_TCP_CONNECT && mono()<until){
        if(t->tcp_attempts>=2 && !listening){assert(!op_listen(endpoint,4));listening=1;}
        tick_tunnel(c,ti,mono());op_sleep_ms(2);
    }
    assert(listening && t->state==T_HANDSHAKE && t->tcp_attempts>=2 && t->tcp_attempts<=5 && t->server==1);
    struct sockaddr_in peer;op_socklen length=sizeof(peer);op_socket accepted=op_accept(endpoint,(struct sockaddr *)&peer,&length);
    assert(accepted>=0 && ntohs(peer.sin_port)==local);
    /* Transport establishment does not bypass session authentication. */
    assert(!tunnel_ready(t));op_close(accepted);close_tunnel(c,ti,NULL);op_close(endpoint);

    endpoint=bound_port(&remote);reserve=bound_port(&local);op_close(reserve);
    ti=new_tunnel(c,"fallback-peer",101,FASTP2P_TRANSPORT_TCP,1);assert(ti>=0);t=&c->tunnels[ti];
    strcpy(t->ip,"127.0.0.1");strcpy(t->mode,"tcppunch");t->local_port=local;t->remote_port=remote;t->tcp_v2=1;
    assert(!op_addr_from_text(&t->peer_addr,"127.0.0.1",remote));
    start_underlay(c,ti);until=mono()+6*NS;
    while(t->state==T_TCP_CONNECT && t->listen_fd<0 && mono()<until){tick_tunnel(c,ti,mono());op_sleep_ms(2);}
    assert(t->state==T_TCP_CONNECT && t->listen_fd>=0 && t->fd<0 && t->tcp_attempts==1 && t->session_owner);
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

    /* No public observation is available through a private gateway. */
    strcpy(c->ip[OP_FAM_V4], "100.64.0.10");
    assert(lan_punch_possible(c, a));
    strcpy(c->ip[OP_FAM_V4], "198.51.100.10");

    const char shared[] = "{\"peerNode\":\"mobile-peer\",\"IPv4\":\"198.51.100.10\","
                          "\"lanIP\":\"172.16.12.193\"}";
    control_message(c, 7, 1, (const uint8_t *)shared, sizeof(shared) - 1);
    assert(lan_punch_possible(c, a));
    assert(a->attempts == 0 && a->tunnel_index == -1 && !c->tunnels[ti].state);

    const char ipv6_only[] = "{\"peerNode\":\"mobile-peer\",\"lanIP6\":\"fd00::11\"}";
    control_message(c, 7, 1, (const uint8_t *)ipv6_only, sizeof(ipv6_only) - 1);
    assert(!a->peer_lan[0] && lan_punch_possible(c, a));
    free(c);
}

int main(void) {
    assert(!op_platform_init());
    tcp_retry();
    tcp_punch_scheduling();
    quic_uses_punch_endpoint();
    lan_punch_public_ipv4();
    /* A difficult UDP mapping must never suppress a stable or unknown TCP path. */
    fastp2p_client client={0};client.nat[OP_FAM_V4].type=NAT_HARD_SYM;client.tcp_nat.family[OP_FAM_V4].type=FP_NAT_STABLE;
    app rule={.transport=FASTP2P_TRANSPORT_TCP,.peer_nat=NAT_HARD_SYM,.peer_tcp_nat=FP_NAT_STABLE};
    assert(local_transport_nat(&client,rule.transport)==FP_NAT_STABLE);
    assert(peer_transport_nat(&rule)==FP_NAT_STABLE);
    assert(direct_rounds_allowed(nat_is_hard_sym(local_transport_nat(&client,rule.transport)),
                                nat_is_hard_sym(peer_transport_nat(&rule)))==2);
    client.tcp_nat.family[OP_FAM_V4].type=FP_NAT_UNKNOWN;rule.peer_tcp_nat=FP_NAT_UNKNOWN;
    assert(!nat_is_hard_sym(local_transport_nat(&client,rule.transport)) && !nat_is_hard_sym(peer_transport_nat(&rule)));
    rule.transport=FASTP2P_TRANSPORT_QUIC;
    assert(local_transport_nat(&client,rule.transport)==NAT_HARD_SYM && peer_transport_nat(&rule)==NAT_HARD_SYM);
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
    nat_filter_record(&filters, 0, filters.next_at);
    assert(nat_filter_level(&filters, filters.next_at) == 3);
    assert(nat_filter_level(&filters, 2 * NS + NAT_FILTER_MAX_AGE) == 0);

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

    /* Punch ladder budget: a hard symmetric side wastes the second round. */
    assert(direct_rounds_allowed(0, 0) == 2);
    assert(direct_rounds_allowed(1, 0) == 1);
    assert(direct_rounds_allowed(0, 1) == 1);
    assert(direct_rounds_allowed(1, 1) == 1);
    assert(direct_rounds_allowed(nat_is_hard_sym(NAT_CONE),
                                 nat_is_hard_sym(NAT_EASY_SYM_INC)) == 2);
    assert(direct_rounds_allowed(nat_is_hard_sym(NAT_EASY_SYM_DEC),
                                 nat_is_hard_sym(NAT_HARD_SYM)) == 1);

    /* Only the hard symmetric value feeds the relay decision. */
    assert(nat_is_hard_sym(NAT_HARD_SYM));
    assert(!nat_is_hard_sym(NAT_CONE));
    assert(!nat_is_hard_sym(NAT_EASY_SYM_INC));
    assert(!nat_is_hard_sym(NAT_EASY_SYM_DEC));
    assert(!nat_is_hard_sym(NAT_UNKNOWN));
    return 0;
}
