#include "tcp_nat.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void put16(uint8_t *p, unsigned n) { p[0]=(uint8_t)(n>>8);p[1]=(uint8_t)n; }
static void put32(uint8_t *p, uint32_t n) { p[0]=(uint8_t)(n>>24);p[1]=(uint8_t)(n>>16);p[2]=(uint8_t)(n>>8);p[3]=(uint8_t)n; }
static void stun_packet(uint8_t p[32], const uint8_t tid[12]) {
    memset(p,0,32);put16(p,0x0101);put16(p+2,12);put32(p+4,0x2112a442);memcpy(p+8,tid,12);
    put16(p+20,0x0020);put16(p+22,8);p[25]=1;put16(p+26,45678^0x2112);put32(p+28,0xcb007107^0x2112a442);
}
static void parser(void) {
    uint8_t tid[12]={1,2,3,4,5,6,7,8,9,10,11,12},p[32];stun_packet(p,tid);
    struct sockaddr_in mapped;
    for(size_t n=0;n<sizeof(p);++n)assert(!fp_tcp_stun_response(p,n,tid,&mapped));
    assert(fp_tcp_stun_response(p,sizeof(p),tid,&mapped)==1);
    assert(ntohs(mapped.sin_port)==45678 && ntohl(mapped.sin_addr.s_addr)==0xcb007107);
    p[8]^=1;assert(fp_tcp_stun_response(p,sizeof(p),tid,&mapped)==-1);p[8]^=1;
    p[4]^=1;assert(fp_tcp_stun_response(p,sizeof(p),tid,&mapped)==-1);p[4]^=1;
    put16(p+2,13);assert(fp_tcp_stun_response(p,sizeof(p),tid,&mapped)==-1);
    put16(p+2,1024);assert(fp_tcp_stun_response(p,sizeof(p),tid,&mapped)==-1);
    stun_packet(p,tid);put16(p+22,20);assert(fp_tcp_stun_response(p,sizeof(p),tid,&mapped)==-1);
    stun_packet(p,tid);put16(p+26,0x2112);assert(fp_tcp_stun_response(p,sizeof(p),tid,&mapped)==-1);
    stun_packet(p,tid);put16(p+20,0x0001);put16(p+26,12345);put32(p+28,0xc0000201);
    assert(fp_tcp_stun_response(p,sizeof(p),tid,&mapped)==1 && ntohs(mapped.sin_port)==12345);
    const char *echo="203.0.113.7:45678\n";
    op_addr echo_mapped;
    for(size_t n=0;n<strlen(echo);++n)assert(!fp_tcp_echo_response((const uint8_t *)echo,n,&echo_mapped));
    assert(fp_tcp_echo_response((const uint8_t *)echo,strlen(echo),&echo_mapped)==1 &&
           op_addr_family(&echo_mapped)==AF_INET && op_addr_port(&echo_mapped)==45678);
    const char *invalid[]={"203.0.113.7:+1\n","203.0.113.7:65536\n","203.0.113.7:99999999999999999999\n",
        "203.0.113.7:1 extra\n","203.0.113.7:0\n","0.0.0.0:1234\n"};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i)
        assert(fp_tcp_echo_response((const uint8_t *)invalid[i],strlen(invalid[i]),&echo_mapped)==-1);
    /* SPEC §3 probeV3: the IPv6 form is bracketed and carries a v6 endpoint. */
    const char *echo6="[2001:db8::1]:45678\n";
    assert(fp_tcp_echo_response((const uint8_t *)echo6,strlen(echo6),&echo_mapped)==1 &&
           op_addr_family(&echo_mapped)==AF_INET6 && op_addr_port(&echo_mapped)==45678);
    const char *invalid6[]={"[]:1\n","[::1]1\n","[::]:1\n","[2001:db8::1]:0\n"};
    for(unsigned i=0;i<sizeof(invalid6)/sizeof(invalid6[0]);++i)
        assert(fp_tcp_echo_response((const uint8_t *)invalid6[i],strlen(invalid6[i]),&echo_mapped)==-1);
}
static void config(void) {
    fp_tcp_nat state;fp_tcp_nat_init(&state);
    const char *valid="[\"stun.example.org:3478\",\"127.0.0.1:49152\"]";
    json_object *j=json_tokener_parse(valid);assert(j && !fp_tcp_nat_configure(&state,j));json_object_put(j);
    assert(state.server_count==2 && state.servers[1].port==49152);
    const char *invalid[]={"{}","[1]","[\"host:0\"]","[\"host:65536\"]","[\"host:-1\"]",
        "[\"host:999999999999999999\"]","[\"tcp://host:3478\"]","[\"[::1]:3478\"]",
        "[\"x\\u0000.example\"]"};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i){
        j=json_tokener_parse(invalid[i]);assert(j && fp_tcp_nat_configure(&state,j)==-1);json_object_put(j);
        assert(state.server_count==2 && !strcmp(state.servers[0].host,"stun.example.org"));
    }
    /* One more witness than the cap is refused, whatever the cap happens to be: the
     * list is a measurement aid, and an unbounded one would turn the probe cycle into
     * an unbounded number of held sockets. */
    {
        json_object *many=json_object_new_array();
        for(unsigned i=0;i<=FP_TCP_STUN_MAX;++i){
            char entry[40];
            snprintf(entry,sizeof(entry),"w%u.example.org:3478",i);
            json_object_array_add(many,json_object_new_string(entry));
        }
        assert(fp_tcp_nat_configure(&state,many)==-1);
        json_object_put(many);
        assert(state.server_count==2 && !strcmp(state.servers[0].host,"stun.example.org"));
    }
    fp_tcp_nat_close(&state);fp_tcp_nat_close(&state);
}
static void real_echo(int changed,int malformed) {
    /* Every observation lives in the per-family slot; this test drives the v4
     * one, which has to keep the exact values the single-family state produced. */
    fp_tcp_nat state;fp_tcp_nat_init(&state);
    state.family[OP_FAM_V4].prepared=1;state.family[OP_FAM_V4].target_count=2;
    op_socket listeners[2],peers[2]={-1,-1};unsigned phase[2]={0};uint16_t ports[2]={0};
    for(unsigned i=0;i<2;++i){
        listeners[i]=op_socket_open(AF_INET,SOCK_STREAM,0);assert(listeners[i]>=0);
        struct sockaddr_in addr={.sin_family=AF_INET,.sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};
        assert(!op_bind(listeners[i],(struct sockaddr *)&addr,sizeof(addr)) && !op_listen(listeners[i],4));
        op_socklen length=sizeof(addr);assert(!op_getsockname(listeners[i],(struct sockaddr *)&addr,&length));
        memset(&state.family[OP_FAM_V4].targets[i].address,0,sizeof(op_addr));
        memcpy(&state.family[OP_FAM_V4].targets[i].address.u.storage,&addr,sizeof(addr));
        state.family[OP_FAM_V4].targets[i].address.len=(op_socklen)sizeof(addr);
        state.family[OP_FAM_V4].targets[i].stun=0;
    }
    uint64_t deadline=op_monotonic_ns()+UINT64_C(5000000000);int done=0;
    while(op_monotonic_ns()<deadline && !done){
        done=fp_tcp_nat_step(&state,op_monotonic_ns());
        for(unsigned i=0;i<2;++i){
            if(peers[i]<0){
                struct sockaddr_in peer;op_socklen length=sizeof(peer);
                peers[i]=op_accept(listeners[i],(struct sockaddr *)&peer,&length);
                if(peers[i]>=0)ports[i]=ntohs(peer.sin_port);
            }
            if(peers[i]<0)continue;
            if(!phase[i]){
                char marker;
                if(op_recv(peers[i],&marker,1,MSG_DONTWAIT)==1){
                    assert(marker=='2');
                    const char *prefix=changed&&i?"203.0.113.8:":"203.0.113.7:";
                    assert(op_send(peers[i],prefix,strlen(prefix),MSG_NOSIGNAL)==(op_ssize)strlen(prefix));
                    phase[i]=1;
                }
            }else if(phase[i]<10){
                ++phase[i]; /* The address prefix alone must not complete a sample. */
            }else if(phase[i]==10){
                const char *tail=malformed&&i?"not-a-port\n":"45678\n";
                assert(op_send(peers[i],tail,strlen(tail),MSG_NOSIGNAL)==(op_ssize)strlen(tail));
                ++phase[i];
            }
        }
        op_sleep_ms(2);
    }
    assert(done && ports[0] && ports[0]==ports[1]);
    assert(done & 1u); /* bit0 is IPv4 (DUALSTACK-SPEC §1) */
    const fp_tcp_family *v4=&state.family[OP_FAM_V4];
    assert(v4->samples==(malformed?1u:2u) && v4->destinations==1);
    assert(v4->type==(malformed?FP_NAT_UNKNOWN:changed?FP_NAT_DEPENDENT:FP_NAT_STABLE));
    assert(!fp_tcp_nat_step(&state,op_monotonic_ns()));
    fp_tcp_nat_close(&state);
    for(unsigned i=0;i<2;++i){if(peers[i]>=0)op_close(peers[i]);op_close(listeners[i]);}
}
/* A gateway on our own network is not a mapping destination: its two probe ports were
 * always first in the target list, and counting them turned every self-hosted deployment
 * into a destination-dependent ("NAT4") TCP node. */
static void private_gateway_is_not_a_destination(void) {
    fp_tcp_nat state;
    fp_tcp_nat_init(&state);
    state.servers[0] = (fp_stun_server){.host = "203.0.113.10", .port = 3478};
    state.servers[1] = (fp_stun_server){.host = "198.51.100.20", .port = 3478};
    state.server_count = 2;
    op_addr gateway[OP_FAM_COUNT];
    memset(gateway, 0, sizeof(gateway));
    int families = 1 << OP_FAM_V4;

    /* A private gateway: only the two public servers remain, both routable. */
    assert(!op_addr_from_text(&gateway[OP_FAM_V4], "192.168.60.4", 27183));
    fp_tcp_nat_prepare(&state, gateway, families);
    const fp_tcp_family *k = &state.family[OP_FAM_V4];
    assert(k->prepared && k->target_count == 2);
    for (unsigned i = 0; i < k->target_count; ++i) {
        assert(k->targets[i].stun);
        assert(op_addr_routable(&k->targets[i].address));
    }
    fp_tcp_nat_close(&state);

    /* One destination cannot show whether the mapping follows the destination. */
    fp_tcp_nat_init(&state);
    state.servers[0] = (fp_stun_server){.host = "203.0.113.10", .port = 3478};
    state.server_count = 1;
    fp_tcp_nat_prepare(&state, gateway, families);
    assert(!state.family[OP_FAM_V4].prepared);
    assert(state.family[OP_FAM_V4].target_count == 1);
    assert(state.family[OP_FAM_V4].type == FP_NAT_UNKNOWN);
    fp_tcp_nat_close(&state);

    /* A routable gateway keeps the historical list: its two ports first. */
    fp_tcp_nat_init(&state);
    state.servers[0] = (fp_stun_server){.host = "203.0.113.10", .port = 3478};
    state.server_count = 1;
    assert(!op_addr_from_text(&gateway[OP_FAM_V4], "139.199.4.226", 27183));
    fp_tcp_nat_prepare(&state, gateway, families);
    const fp_tcp_family *public_targets = &state.family[OP_FAM_V4];
    assert(public_targets->prepared && public_targets->target_count == 3);
    assert(!public_targets->targets[0].stun && !public_targets->targets[1].stun);
    assert(op_addr_port(&public_targets->targets[0].address) == 27180);
    assert(op_addr_port(&public_targets->targets[1].address) == 27181);
    fp_tcp_nat_close(&state);
}

int main(void) {
    assert(!op_platform_init());parser();private_gateway_is_not_a_destination();config();real_echo(0,0);real_echo(1,0);real_echo(0,1);
    puts("TCP STUN framing, transaction validation, configuration, fragmented echo, same-port sampling and separate mapping results passed");
    return 0;
}
