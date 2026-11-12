/* The punch cadence, mapping classification and symmetric window are pure
 * decisions, so they can be checked without a socket. */
#include "../src/client.c"
#include <assert.h>

static op_socket bound_port(uint16_t *port) {
    op_socket fd=socket_bound(0,"127.0.0.1",0,1);assert(fd>=0);*port=socket_port(fd);assert(*port);return fd;
}
static void tcp_retry(void) {
    fastp2p_client *c=calloc(1,sizeof(*c));assert(c);strcpy(c->local_ip,"127.0.0.1");
    uint16_t remote,local;op_socket endpoint=bound_port(&remote),reserve=bound_port(&local);op_close(reserve);
    int ti=new_tunnel(c,"retry-target",100,FASTP2P_TRANSPORT_TCP,0);assert(ti>=0);
    tunnel *t=&c->tunnels[ti];strcpy(t->ip,"127.0.0.1");strcpy(t->mode,"tcppunch");
    t->local_port=local;t->remote_port=remote;t->tcp_v2=1;t->server=1;
    start_underlay(c,ti);uint64_t until=mono()+3*NS;int listening=0;
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
    start_underlay(c,ti);until=mono()+3*NS;
    while(t->state==T_TCP_CONNECT && t->listen_fd<0 && mono()<until){tick_tunnel(c,ti,mono());op_sleep_ms(2);}
    assert(t->state==T_TCP_CONNECT && t->listen_fd>=0 && t->fd<0 && t->tcp_attempts==1 && t->session_owner);
    assert(!t->tcp_retry_at && !tunnel_ready(t));close_tunnel(c,ti,NULL);op_close(endpoint);free(c);
}
int main(void) {
    assert(!op_platform_init());tcp_retry();
    /* A difficult UDP mapping must never suppress a stable or unknown TCP path. */
    fastp2p_client client={0};client.nat_type=NAT_HARD_SYM;client.tcp_nat.type=FP_NAT_STABLE;
    app rule={.transport=FASTP2P_TRANSPORT_TCP,.peer_nat=NAT_HARD_SYM,.peer_tcp_nat=FP_NAT_STABLE};
    assert(local_transport_nat(&client,rule.transport)==FP_NAT_STABLE);
    assert(peer_transport_nat(&rule)==FP_NAT_STABLE);
    assert(direct_rounds_allowed(nat_is_hard_sym(local_transport_nat(&client,rule.transport)),
                                nat_is_hard_sym(peer_transport_nat(&rule)))==2);
    client.tcp_nat.type=FP_NAT_UNKNOWN;rule.peer_tcp_nat=FP_NAT_UNKNOWN;
    assert(!nat_is_hard_sym(local_transport_nat(&client,rule.transport)) && !nat_is_hard_sym(peer_transport_nat(&rule)));
    rule.transport=FASTP2P_TRANSPORT_QUIC;
    assert(local_transport_nat(&client,rule.transport)==NAT_HARD_SYM && peer_transport_nat(&rule)==NAT_HARD_SYM);
    /* Dense start: the first half second decides a cone-to-cone punch. */
    assert(punch_interval(0) == 50 * MS);
    assert(punch_interval(499 * MS) == 50 * MS);
    assert(punch_interval(500 * MS) == 200 * MS);
    assert(punch_interval(9 * NS) == 200 * MS);

    /* Mapping classification. */
    assert(nat_classify(40000, 40000, 0) == NAT_CONE);
    assert(nat_classify(40000, 40001, 0) == NAT_HARD_SYM);
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
