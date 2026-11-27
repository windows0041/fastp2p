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
/* Drive the witness list to completion. With the resolver worker running that means stepping
 * until every name has an answer; on the fallback path the clock also has to move past the
 * throttle window between calls. */
static void walk_witness_list(fp_tcp_nat *state) {
    uint64_t now = op_monotonic_ns();
    for (unsigned i = 0; i < 400; ++i) {
        const fp_tcp_family *k = &state->family[OP_FAM_V4];
        if (!k->resolving && !k->awaiting)
            break;
        now += UINT64_C(300000000);
        fp_tcp_nat_step(state, now);
        op_sleep_ms(2);
    }
    assert(!state->family[OP_FAM_V4].resolving);
    assert(!state->family[OP_FAM_V4].awaiting);
}

/* The worker is what keeps the loop free; a platform that cannot start one falls back to the
 * walk above, which is why the incremental tests below force that path. */
static void resolver_worker_starts_by_default(void) {
    fp_tcp_nat state;
    fp_tcp_nat_init(&state);
    assert(!fp_tcp_nat_resolver_running(&state));
    op_addr gateway[OP_FAM_COUNT];
    memset(gateway, 0, sizeof(gateway));
    assert(!op_addr_from_text(&gateway[OP_FAM_V4], "139.199.4.226", 27183));
    fp_tcp_nat_prepare(&state, gateway, 1 << OP_FAM_V4);
    assert(fp_tcp_nat_resolver_running(&state));
    fp_tcp_nat_close(&state);
    assert(!fp_tcp_nat_resolver_running(&state));
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
    walk_witness_list(&state);
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
    walk_witness_list(&state);
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
    walk_witness_list(&state);
    const fp_tcp_family *public_targets = &state.family[OP_FAM_V4];
    assert(public_targets->prepared && public_targets->target_count == 3);
    assert(!public_targets->targets[0].stun && !public_targets->targets[1].stun);
    assert(op_addr_port(&public_targets->targets[0].address) == 27180);
    assert(op_addr_port(&public_targets->targets[1].address) == 27181);
    fp_tcp_nat_close(&state);
}

/* ---- parallel probing ------------------------------------------------------------
 * The probe used to run one socket at a time. These tests drive a batch of targets on
 * loopback and check the two things that make the parallel version correct: the probes must
 * really overlap, and the samples must still be recorded in target order whatever order the
 * answers arrive in. */

/* Answer one probe: the plain-text echo, or a STUN binding success carrying the same
 * transaction id the request used. Returns 0 while the probe has not been answered yet. */
static unsigned serve_probe(op_socket peer, unsigned index, int stun, int vary) {
    if (!stun) {
        char marker;
        if (op_recv(peer, &marker, 1, MSG_DONTWAIT) != 1) return 0;
        assert(marker == '2');
        char line[64];
        int n = snprintf(line, sizeof(line), "203.0.113.7:%u\n", 45678u + (vary ? index : 0));
        assert(op_send(peer, line, (size_t)n, MSG_NOSIGNAL) == (op_ssize)n);
        return 1;
    }
    uint8_t request[20];
    size_t got = 0;
    while (got < sizeof(request)) {
        op_ssize r = op_recv(peer, request + got, sizeof(request) - got, MSG_DONTWAIT);
        if (r <= 0) return 0;
        got += (size_t)r;
    }
    uint8_t response[32];
    stun_packet(response, request + 8);
    put16(response + 26, (45678u + (vary ? index : 0)) ^ 0x2112);
    assert(op_send(peer, response, sizeof(response), MSG_NOSIGNAL) == (op_ssize)sizeof(response));
    return 1;
}

/* One full cycle against `count` loopback targets, each answering with its own index.
 * `dead` (>= 0) turns that target into a closed port so the batch has to survive a refusal.
 * Returns 1 when the cycle completed. */
static int run_probe_cycle(fp_tcp_nat *state, unsigned count, int stun, int dead, int vary) {
    enum { MAX = 16 };
    assert(count <= MAX);
    fp_tcp_family *k = &state->family[OP_FAM_V4];
    k->prepared = 1;
    k->target_count = count;
    op_socket listeners[MAX], peers[MAX];
    unsigned served[MAX];
    for (unsigned i = 0; i < MAX; ++i) { listeners[i] = -1; peers[i] = -1; served[i] = 0; }
    for (unsigned i = 0; i < count; ++i) {
        op_socket l = op_socket_open(AF_INET, SOCK_STREAM, 0);
        assert(l >= 0);
        struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)}};
        assert(!op_bind(l, (struct sockaddr *)&addr, sizeof(addr)) && !op_listen(l, 16));
        op_socklen length = sizeof(addr);
        assert(!op_getsockname(l, (struct sockaddr *)&addr, &length));
        memset(&k->targets[i].address, 0, sizeof(op_addr));
        memcpy(&k->targets[i].address.u.storage, &addr, sizeof(addr));
        k->targets[i].address.len = (op_socklen)sizeof(addr);
        k->targets[i].stun = stun;
        if ((int)i == dead) { op_close(l); continue; } /* nothing listens: the connect fails */
        listeners[i] = l;
    }
    uint64_t deadline = op_monotonic_ns() + UINT64_C(5000000000);
    int done = 0;
    while (op_monotonic_ns() < deadline && !done) {
        done = fp_tcp_nat_step(state, op_monotonic_ns());
        for (unsigned i = 0; i < count; ++i) {
            if (listeners[i] < 0) continue;
            if (peers[i] < 0) {
                struct sockaddr_in peer;
                op_socklen length = sizeof(peer);
                peers[i] = op_accept(listeners[i], (struct sockaddr *)&peer, &length);
            }
            if (peers[i] >= 0 && !served[i] && serve_probe(peers[i], i, stun, vary)) served[i] = 1;
        }
        op_sleep_ms(2);
    }
    for (unsigned i = 0; i < MAX; ++i) {
        if (peers[i] >= 0) op_close(peers[i]);
        if (listeners[i] >= 0) op_close(listeners[i]);
    }
    return done;
}

/* Six STUN probes at the same time: the batch must not wait for one answer before starting
 * the next probe. `peak_inflight` is the high-water mark the probe loop keeps, so this is
 * the concurrency itself, not a proxy for it. */
static void six_probes_at_once(void) {
    fp_tcp_nat state;
    fp_tcp_nat_init(&state);
    assert(run_probe_cycle(&state, FP_TCP_PROBE_SLOTS, 1, -1, 0));
    const fp_tcp_family *k = &state.family[OP_FAM_V4];
    assert(k->peak_inflight == FP_TCP_PROBE_SLOTS);
    assert(k->samples == FP_TCP_PROBE_SLOTS && k->destinations == 1);
    assert(k->type == FP_NAT_STABLE);
    fp_tcp_nat_close(&state);
}

/* Answers arrive in whatever order the sockets finish, but the samples have to stay in
 * target order: the step calculation reads mapped[i] - mapped[i-1]. */
static void samples_keep_target_order(void) {
    fp_tcp_nat state;
    fp_tcp_nat_init(&state);
    assert(run_probe_cycle(&state, FP_TCP_PROBE_SLOTS, 1, -1, 1));
    const fp_tcp_family *k = &state.family[OP_FAM_V4];
    assert(k->samples == FP_TCP_PROBE_SLOTS);
    for (unsigned i = 0; i < k->samples; ++i)
        assert(op_addr_port(&k->mapped[i]) == 45678u + i);
    /* Six distinct ports on one address: destination-dependent, and the batch order did not
     * turn that into six separate destinations. */
    assert(k->type == FP_NAT_DEPENDENT && k->destinations == 1);
    fp_tcp_nat_close(&state);
}

/* A refused target must not stall the batch: the other five still complete within a single
 * slot deadline. The bound is one deadline, not one per target - a Windows connect to a
 * closed port is refused later than a Linux one, so the interesting property is that the
 * batch is deadline-bounded rather than serialized behind the dead target. */
static void one_failed_target_still_completes_the_batch(void) {
    fp_tcp_nat state;
    fp_tcp_nat_init(&state);
    uint64_t started = op_monotonic_ns();
    assert(run_probe_cycle(&state, FP_TCP_PROBE_SLOTS, 1, 2, 0));
    uint64_t elapsed = op_monotonic_ns() - started;
    const fp_tcp_family *k = &state.family[OP_FAM_V4];
    assert(k->samples == FP_TCP_PROBE_SLOTS - 1 && k->destinations == 1);
    assert(k->type == FP_NAT_STABLE);
    assert(elapsed < UINT64_C(2500000000)); /* one 2 s slot deadline plus slack, not six */
    fp_tcp_nat_close(&state);
}

/* Resolving a witness list must not happen inside one call: a blocked step loop stops
 * feeding the control channel, which is how a node with ten configured witnesses ended up
 * being disconnected a second after every login. One name per step, spaced out, and the
 * ladder waits for the whole list. */
static void witness_resolution_is_spread_over_the_step_loop(void) {
    fp_tcp_nat state;
    fp_tcp_nat_init(&state);
    fp_tcp_nat_set_inline_resolution(&state, 1);
    for (unsigned i = 0; i < 8; ++i) {
        snprintf(state.servers[i].host, sizeof(state.servers[i].host), "127.0.0.%u", i + 1);
        state.servers[i].port = 3478;
    }
    state.server_count = 8;
    op_addr gateway[OP_FAM_COUNT];
    memset(gateway, 0, sizeof(gateway));
    assert(!op_addr_from_text(&gateway[OP_FAM_V4], "139.199.4.226", 27183));
    fp_tcp_nat_prepare(&state, gateway, 1 << OP_FAM_V4);
    const fp_tcp_family *k = &state.family[OP_FAM_V4];
    /* Nothing resolved synchronously: only the gateway's own two ports are ready. */
    assert(k->prepared == 0 && k->resolving == 1 && k->resolved == 0 && k->target_count == 2);
    uint64_t now = op_monotonic_ns();
    fp_tcp_nat_step(&state, now);
    assert(k->resolved == 1);
    /* A second call inside the throttle window resolves nothing. */
    fp_tcp_nat_step(&state, now);
    assert(k->resolved == 1 && k->target_count == 3);
    for (unsigned i = 1; i < 8; ++i) {
        now += UINT64_C(300000000); /* past the 200 ms spacing */
        fp_tcp_nat_step(&state, now);
        assert(k->resolved == i + 1);
        assert(k->target_count == 2 + i + 1);
    }
    assert(k->resolving == 0 && k->prepared == 1 && k->target_count == 10);
    fp_tcp_nat_close(&state);
}

/* A name that cannot be resolved is skipped; the rest of the list still forms the target
 * set. "127.0.0.256" is not an address, so it fails without touching the network. */
static void unresolvable_witness_is_skipped(void) {
    fp_tcp_nat state;
    fp_tcp_nat_init(&state);
    fp_tcp_nat_set_inline_resolution(&state, 1);
    state.servers[0] = (fp_stun_server){.host = "127.0.0.1", .port = 3478};
    state.servers[1] = (fp_stun_server){.host = "127.0.0.256", .port = 3478};
    state.servers[2] = (fp_stun_server){.host = "127.0.0.2", .port = 3478};
    state.server_count = 3;
    op_addr gateway[OP_FAM_COUNT];
    memset(gateway, 0, sizeof(gateway));
    assert(!op_addr_from_text(&gateway[OP_FAM_V4], "139.199.4.226", 27183));
    fp_tcp_nat_prepare(&state, gateway, 1 << OP_FAM_V4);
    walk_witness_list(&state);
    const fp_tcp_family *k = &state.family[OP_FAM_V4];
    assert(k->resolved == 3 && k->prepared == 1);
    assert(k->target_count == 4); /* two gateway ports + the two resolvable witnesses */
    fp_tcp_nat_close(&state);
}

/* The walk keeps the configured order and drops a name that resolves to an address already
 * in the list, so the final target list is the one the old synchronous version built. */
static void witness_walk_keeps_order_and_drops_duplicates(void) {
    fp_tcp_nat state;
    fp_tcp_nat_init(&state);
    fp_tcp_nat_set_inline_resolution(&state, 1);
    state.servers[0] = (fp_stun_server){.host = "127.0.0.2", .port = 3478};
    state.servers[1] = (fp_stun_server){.host = "127.0.0.1", .port = 3478};
    state.servers[2] = (fp_stun_server){.host = "127.0.0.2", .port = 3478};
    state.server_count = 3;
    op_addr gateway[OP_FAM_COUNT];
    memset(gateway, 0, sizeof(gateway));
    assert(!op_addr_from_text(&gateway[OP_FAM_V4], "139.199.4.226", 27183));
    fp_tcp_nat_prepare(&state, gateway, 1 << OP_FAM_V4);
    walk_witness_list(&state);
    const fp_tcp_family *k = &state.family[OP_FAM_V4];
    assert(k->target_count == 4 && k->resolved == 3);
    assert(op_addr_port(&k->targets[0].address) == 27180 && !k->targets[0].stun);
    assert(op_addr_port(&k->targets[1].address) == 27181 && !k->targets[1].stun);
    assert(k->targets[2].stun && k->targets[3].stun);
    char text[OP_ADDR_TEXT];
    assert(!op_addr_text(&k->targets[2].address, text, sizeof(text)) && !strcmp(text, "127.0.0.2"));
    assert(!op_addr_text(&k->targets[3].address, text, sizeof(text)) && !strcmp(text, "127.0.0.1"));
    fp_tcp_nat_close(&state);
}

/* A fake lookup that answers instantly but not uniquely: names w1..w3 map to .11, .12, .11,
 * so the ordering and de-duplication rules are exercised through the worker path. */
static int fake_resolve(const char *host, uint16_t port, op_addr *out) {
    unsigned last = (unsigned)(host[strlen(host) - 1] - '0');
    char text[32];
    snprintf(text, sizeof(text), "203.0.113.%u", 10 + (last == 3 ? 1 : last));
    return op_addr_from_text(out, text, port) ? -1 : 0;
}

/* The answer to the field failure: a lookup that takes seconds must cost the step loop
 * nothing. The fake resolver sleeps two seconds; prepare and every step call are timed. */
static int slow_resolve(const char *host, uint16_t port, op_addr *out) {
    (void)host;
    op_sleep_ms(2000);
    return op_addr_from_text(out, "203.0.113.77", port) ? -1 : 0;
}

static void slow_resolver_does_not_block_the_step_loop(void) {
    fp_tcp_nat state;
    fp_tcp_nat_init(&state);
    fp_tcp_nat_set_resolver(&state, slow_resolve);
    state.servers[0] = (fp_stun_server){.host = "slow.example", .port = 3478};
    state.server_count = 1;
    op_addr gateway[OP_FAM_COUNT];
    memset(gateway, 0, sizeof(gateway));
    assert(!op_addr_from_text(&gateway[OP_FAM_V4], "139.199.4.226", 27183));
    uint64_t started = op_monotonic_ns();
    fp_tcp_nat_prepare(&state, gateway, 1 << OP_FAM_V4);
    /* prepare only queues the name; it must not wait for the lookup */
    assert(op_monotonic_ns() - started < UINT64_C(50000000));
    assert(fp_tcp_nat_resolver_running(&state));
    const fp_tcp_family *k = &state.family[OP_FAM_V4];
    assert(k->prepared == 0 && k->awaiting == 1);
    uint64_t worst = 0, now = op_monotonic_ns();
    uint64_t deadline = started + UINT64_C(8000000000);
    while (op_monotonic_ns() < deadline && !k->prepared) {
        uint64_t t0 = op_monotonic_ns();
        now += UINT64_C(1000000);
        fp_tcp_nat_step(&state, now);
        uint64_t spent = op_monotonic_ns() - t0;
        if (spent > worst) worst = spent;
        op_sleep_ms(5);
    }
    assert(k->prepared == 1 && k->awaiting == 0 && k->resolved == 1);
    /* The whole point: no single step call waited for the two second lookup. */
    assert(worst < UINT64_C(50000000));
    printf("slow resolver: worst step %.3f ms while one lookup slept 2000 ms\n", (double)worst * 1e-6);
    assert(k->target_count == 3);
    /* Shutdown waits for the lookup in flight, not for the queue to be walked. */
    uint64_t closing = op_monotonic_ns();
    fp_tcp_nat_close(&state);
    assert(op_monotonic_ns() - closing < UINT64_C(4000000000));
}

/* Answers arrive in the order the names were queued, and a name that resolves to an address
 * already in the list is dropped - the same rules the synchronous version applied. */
static void resolver_answers_keep_order_and_drop_duplicates(void) {
    fp_tcp_nat state;
    fp_tcp_nat_init(&state);
    fp_tcp_nat_set_resolver(&state, fake_resolve);
    state.servers[0] = (fp_stun_server){.host = "w1", .port = 3478};
    state.servers[1] = (fp_stun_server){.host = "w2", .port = 3478};
    state.servers[2] = (fp_stun_server){.host = "w3", .port = 3478};
    state.server_count = 3;
    op_addr gateway[OP_FAM_COUNT];
    memset(gateway, 0, sizeof(gateway));
    assert(!op_addr_from_text(&gateway[OP_FAM_V4], "139.199.4.226", 27183));
    fp_tcp_nat_prepare(&state, gateway, 1 << OP_FAM_V4);
    assert(fp_tcp_nat_resolver_running(&state));
    walk_witness_list(&state);
    const fp_tcp_family *k = &state.family[OP_FAM_V4];
    assert(k->resolved == 3 && k->prepared == 1 && k->target_count == 4);
    char text[OP_ADDR_TEXT];
    assert(!op_addr_text(&k->targets[2].address, text, sizeof(text)) && !strcmp(text, "203.0.113.11"));
    assert(!op_addr_text(&k->targets[3].address, text, sizeof(text)) && !strcmp(text, "203.0.113.12"));
    fp_tcp_nat_close(&state);
}

/* A reconfigure (pushed configuration, changed path) runs inside the step loop, so it must not
 * wait for the lookup the worker is in the middle of: the old worker is orphaned and reclaims
 * itself, the new list gets a fresh one. */
static void reconfigure_does_not_wait_for_a_lookup(void) {
    fp_tcp_nat state;
    fp_tcp_nat_init(&state);
    fp_tcp_nat_set_resolver(&state, slow_resolve);
    state.servers[0] = (fp_stun_server){.host = "slowname", .port = 3478};
    state.server_count = 1;
    op_addr gateway[OP_FAM_COUNT];
    memset(gateway, 0, sizeof(gateway));
    assert(!op_addr_from_text(&gateway[OP_FAM_V4], "139.199.4.226", 27183));
    fp_tcp_nat_prepare(&state, gateway, 1 << OP_FAM_V4);
    op_sleep_ms(200); /* let the worker pick the name up and start the slow lookup */
    uint64_t started = op_monotonic_ns();
    fp_tcp_nat_prepare(&state, gateway, 1 << OP_FAM_V4);
    uint64_t spent = op_monotonic_ns() - started;
    printf("reconfigure with a lookup in flight: %.3f ms\n", (double)spent * 1e-6);
    assert(spent < UINT64_C(50000000));
    assert(fp_tcp_nat_resolver_running(&state));
    fp_tcp_nat_close(&state);
}

/* The step timing is what a disconnect line is read against, so it has to record a slow call
 * and clear the peak without losing the last value. Forcing the fallback walk with an injected
 * slow resolver puts the 300 ms lookup inside the step call on purpose. */
static int slow_step_resolve(const char *host, uint16_t port, op_addr *out) {
    (void)host;
    op_sleep_ms(300);
    return op_addr_from_text(out, "203.0.113.9", port) ? -1 : 0;
}

static void step_stats_record_a_slow_step(void) {
    fp_tcp_nat state;
    fp_tcp_nat_init(&state);
    fp_tcp_nat_set_resolver(&state, slow_step_resolve);
    fp_tcp_nat_set_inline_resolution(&state, 1);
    state.servers[0] = (fp_stun_server){.host = "slowstep", .port = 3478};
    state.server_count = 1;
    op_addr gateway[OP_FAM_COUNT];
    memset(gateway, 0, sizeof(gateway));
    assert(!op_addr_from_text(&gateway[OP_FAM_V4], "139.199.4.226", 27183));
    fp_tcp_nat_prepare(&state, gateway, 1 << OP_FAM_V4);
    uint64_t last = 1, max = 1;
    unsigned slow = 1;
    fp_tcp_nat_step_stats(&state, &last, &max, &slow);
    assert(last == 0 && max == 0 && slow == 0);
    fp_tcp_nat_step(&state, op_monotonic_ns()); /* resolves one name inline: ~300 ms */
    fp_tcp_nat_step_stats(&state, &last, &max, &slow);
    printf("step stats: last %.1f ms, max %.1f ms, slow=%u\n", (double)last * 1e-6,
           (double)max * 1e-6, slow);
    assert(last > FP_TCP_STEP_SLOW_NS && max >= last && slow == 1);
    fp_tcp_nat_step_stats_reset(&state);
    fp_tcp_nat_step_stats(&state, &last, &max, &slow);
    assert(max == 0 && slow == 0);
    /* The peak is cleared, the latest observation is not: it describes the last call. */
    assert(last > FP_TCP_STEP_SLOW_NS);
    fp_tcp_nat_close(&state);
}

int main(void) {
    assert(!op_platform_init());parser();private_gateway_is_not_a_destination();config();real_echo(0,0);real_echo(1,0);real_echo(0,1);
    six_probes_at_once();samples_keep_target_order();one_failed_target_still_completes_the_batch();
    resolver_worker_starts_by_default();resolver_answers_keep_order_and_drop_duplicates();
    slow_resolver_does_not_block_the_step_loop();reconfigure_does_not_wait_for_a_lookup();
    step_stats_record_a_slow_step();
    witness_resolution_is_spread_over_the_step_loop();unresolvable_witness_is_skipped();
    witness_walk_keeps_order_and_drops_duplicates();
    puts("TCP STUN framing, transaction validation, configuration, fragmented echo, same-port sampling, "
         "separate mapping results, six parallel probes, a resolver worker that never blocks the loop, "
         "an incremental fallback walk and step timing stats passed");
    return 0;
}
