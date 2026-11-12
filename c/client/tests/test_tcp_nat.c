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
    for(size_t n=0;n<strlen(echo);++n)assert(!fp_tcp_echo_response((const uint8_t *)echo,n,&mapped));
    assert(fp_tcp_echo_response((const uint8_t *)echo,strlen(echo),&mapped)==1 && ntohs(mapped.sin_port)==45678);
    const char *invalid[]={"203.0.113.7:+1\n","203.0.113.7:65536\n","203.0.113.7:99999999999999999999\n",
        "203.0.113.7:1 extra\n","203.0.113.7:0\n","0.0.0.0:1234\n"};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i)
        assert(fp_tcp_echo_response((const uint8_t *)invalid[i],strlen(invalid[i]),&mapped)==-1);
}
static void config(void) {
    fp_tcp_nat state;fp_tcp_nat_init(&state);
    const char *valid="[\"stun.example.org:3478\",\"127.0.0.1:49152\"]";
    json_object *j=json_tokener_parse(valid);assert(j && !fp_tcp_nat_configure(&state,j));json_object_put(j);
    assert(state.server_count==2 && state.servers[1].port==49152);
    const char *invalid[]={"{}","[1]","[\"host:0\"]","[\"host:65536\"]","[\"host:-1\"]",
        "[\"host:999999999999999999\"]","[\"tcp://host:3478\"]","[\"[::1]:3478\"]",
        "[\"x\\u0000.example\"]","[\"a\",\"b\",\"c\",\"d\",\"e\"]"};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i){
        j=json_tokener_parse(invalid[i]);assert(j && fp_tcp_nat_configure(&state,j)==-1);json_object_put(j);
        assert(state.server_count==2 && !strcmp(state.servers[0].host,"stun.example.org"));
    }
    fp_tcp_nat_close(&state);fp_tcp_nat_close(&state);
}
static void real_echo(int changed,int malformed) {
    fp_tcp_nat state;fp_tcp_nat_init(&state);state.prepared=1;state.target_count=2;
    op_socket listeners[2],peers[2]={-1,-1};unsigned phase[2]={0};uint16_t ports[2]={0};
    for(unsigned i=0;i<2;++i){
        listeners[i]=op_socket_open(AF_INET,SOCK_STREAM,0);assert(listeners[i]>=0);
        struct sockaddr_in addr={.sin_family=AF_INET,.sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};
        assert(!op_bind(listeners[i],(struct sockaddr *)&addr,sizeof(addr)) && !op_listen(listeners[i],4));
        op_socklen length=sizeof(addr);assert(!op_getsockname(listeners[i],(struct sockaddr *)&addr,&length));
        state.targets[i].address=addr;
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
    assert(state.samples==(malformed?1u:2u) && state.destinations==1);
    assert(state.type==(malformed?FP_NAT_UNKNOWN:changed?FP_NAT_DEPENDENT:FP_NAT_STABLE));
    assert(!fp_tcp_nat_step(&state,op_monotonic_ns()));
    fp_tcp_nat_close(&state);
    for(unsigned i=0;i<2;++i){if(peers[i]>=0)op_close(peers[i]);op_close(listeners[i]);}
}
int main(void) {
    assert(!op_platform_init());parser();config();real_echo(0,0);real_echo(1,0);real_echo(0,1);
    puts("TCP STUN framing, transaction validation, configuration, fragmented echo, same-port sampling and separate mapping results passed");
    return 0;
}
