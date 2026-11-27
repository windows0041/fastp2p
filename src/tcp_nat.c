#include "tcp_nat.h"
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <process.h>
#endif

#define SECOND UINT64_C(1000000000)
#define PUNCH_SAMPLE_TIMEOUT UINT64_C(450000000)
/* Spacing between two witness lookups in the fallback walk. Long enough that several
 * resolutions cannot pile up into one stalled tick, short enough that ten witnesses are
 * ready in about two seconds. The worker below does not use it: it resolves back to back. */
#define TCP_RESOLVE_INTERVAL (200 * SECOND / 1000)
/* How often the worker looks for work. A lookup happens seconds apart, so a poll is cheaper
 * than a condition variable and keeps the platform surface to a thread and a lock. */
#define RESOLVE_POLL_MS 10

/* --- one resolver thread ---------------------------------------------------------------
 * getaddrinfo is the only call in this file that can block for as long as the resolver's
 * timeout - seconds, when the resolver is unreachable. It used to run inside the loop that
 * also carries the control channel: ten witnesses meant ten lookups, a stalled loop, and a
 * gateway that closed the session. Now one worker does the lookups and the loop only pushes
 * names and drains answers, taking the lock with a try-lock it never waits on. */
typedef struct {
    char host[254];
    uint16_t port;
} fp_tcp_resolve_job;
typedef struct {
    op_addr address;
    uint16_t port;
    int ok;
} fp_tcp_resolve_answer;
struct fp_tcp_resolver {
#ifdef _WIN32
    HANDLE thread;
    SRWLOCK lock;
#else
    pthread_t thread;
    pthread_mutex_t lock;
#endif
    int started, stopping, orphan;
    fp_tcp_resolve_fn resolve;
    fp_tcp_resolve_job jobs[FP_TCP_RESOLVE_QUEUE];
    unsigned job_head, job_count;
    fp_tcp_resolve_answer answers[FP_TCP_RESOLVE_QUEUE];
    unsigned answer_head, answer_count;
};

static void resolver_lock(fp_tcp_resolver *r) {
#ifdef _WIN32
    AcquireSRWLockExclusive(&r->lock);
#else
    pthread_mutex_lock(&r->lock);
#endif
}
static void resolver_unlock(fp_tcp_resolver *r) {
#ifdef _WIN32
    ReleaseSRWLockExclusive(&r->lock);
#else
    pthread_mutex_unlock(&r->lock);
#endif
}
/* A try-lock: the step loop must never wait for the worker, so a busy lock simply means the
 * answers are drained on a later call. */
static int resolver_trylock(fp_tcp_resolver *r) {
#ifdef _WIN32
    return TryAcquireSRWLockExclusive(&r->lock) ? 1 : 0;
#else
    return pthread_mutex_trylock(&r->lock) ? 0 : 1;
#endif
}
/* The default lookup. WSAStartup is the client's job (op_platform_init) and has already run
 * by the time a probe is prepared. */
static int platform_resolve(const char *host, uint16_t port, op_addr *out) {
    struct addrinfo hints = {0}, *addresses = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &addresses) || !addresses)
        return -1;
    memset(out, 0, sizeof(*out));
    out->len = (op_socklen)addresses->ai_addrlen;
    if (out->len > (op_socklen)sizeof(out->u.storage))
        out->len = (op_socklen)sizeof(out->u.storage);
    memcpy(&out->u.storage, addresses->ai_addr, out->len);
    freeaddrinfo(addresses);
    op_addr_set_port(out, port);
    return 0;
}
#ifdef _WIN32
static unsigned __stdcall resolver_worker(void *arg) {
#else
static void *resolver_worker(void *arg) {
#endif
    fp_tcp_resolver *r = arg;
    for (;;) {
        char host[254];
        uint16_t port = 0;
        int have = 0, stop = 0;
        resolver_lock(r);
        if (r->job_count) {
            memcpy(host, r->jobs[r->job_head].host, sizeof(host));
            port = r->jobs[r->job_head].port;
            r->job_head = (r->job_head + 1) % FP_TCP_RESOLVE_QUEUE;
            --r->job_count;
            have = 1;
        }
        stop = r->stopping;
        resolver_unlock(r);
        if (!have) {
            if (stop) break;
            op_sleep_ms(RESOLVE_POLL_MS);
            continue;
        }
        fp_tcp_resolve_answer answer;
        memset(&answer, 0, sizeof(answer));
        answer.port = port;
        answer.ok = r->resolve && !r->resolve(host, port, &answer.address);
        resolver_lock(r);
        if (r->answer_count < FP_TCP_RESOLVE_QUEUE) {
            r->answers[(r->answer_head + r->answer_count) % FP_TCP_RESOLVE_QUEUE] = answer;
            ++r->answer_count;
        }
        resolver_unlock(r);
    }
    /* The owner let this struct go on a reconfigure: reclaim it here, because nothing else
     * may touch it once the reference is dropped. */
    resolver_lock(r);
    int orphan = r->orphan;
    resolver_unlock(r);
    if (orphan) {
#ifndef _WIN32
        pthread_mutex_destroy(&r->lock);
#endif
        free(r);
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}
static int resolver_start(fp_tcp_nat *s) {
    if (s->resolver)
        return 1;
    fp_tcp_resolver *r = calloc(1, sizeof(*r));
    if (!r)
        return 0;
    r->resolve = s->resolve ? s->resolve : platform_resolve;
#ifdef _WIN32
    InitializeSRWLock(&r->lock);
    r->thread = (HANDLE)_beginthreadex(NULL, 0, resolver_worker, r, 0, NULL);
    if (!r->thread) {
        free(r);
        return 0;
    }
#else
    if (pthread_mutex_init(&r->lock, NULL)) {
        free(r);
        return 0;
    }
    if (pthread_create(&r->thread, NULL, resolver_worker, r)) {
        pthread_mutex_destroy(&r->lock);
        free(r);
        return 0;
    }
#endif
    r->started = 1;
    s->resolver = r;
    return 1;
}
static void resolver_stop(fp_tcp_nat *s, int wait) {
    fp_tcp_resolver *r = s->resolver;
    if (!r)
        return;
    resolver_lock(r);
    r->stopping = 1;
    /* wait == 0 is the reconfigure path: this call runs inside the step loop, so it must not
     * wait for the lookup the worker is in the middle of. The worker owns the struct from here
     * and frees it when it exits. */
    if (!wait)
        r->orphan = 1;
    resolver_unlock(r);
    s->resolver = NULL;
    if (!wait) {
#ifdef _WIN32
        CloseHandle(r->thread);
#else
        pthread_detach(r->thread);
#endif
        return;
    }
    /* Shutdown waits for the worker, which is that poll plus the lookup it is inside - at
     * worst one resolver timeout, and this is the only place in the file that waits at all. */
#ifdef _WIN32
    WaitForSingleObject(r->thread, INFINITE);
    CloseHandle(r->thread);
#else
    pthread_join(r->thread, NULL);
    pthread_mutex_destroy(&r->lock);
#endif
    free(r);
}
/* Queue every name of the list. False means "no worker, or the queue would not take them":
 * the caller falls back to the incremental walk and nothing is lost. */
static int resolver_submit(fp_tcp_nat *s, const fp_stun_server *servers, unsigned count) {
    fp_tcp_resolver *r = s->resolver;
    if (!r || count > FP_TCP_RESOLVE_QUEUE)
        return 0;
    if (!resolver_trylock(r))
        return 0;
    int room = r->job_count + count <= FP_TCP_RESOLVE_QUEUE;
    for (unsigned i = 0; room && i < count; ++i) {
        unsigned slot = (r->job_head + r->job_count) % FP_TCP_RESOLVE_QUEUE;
        snprintf(r->jobs[slot].host, sizeof(r->jobs[slot].host), "%s", servers[i].host);
        r->jobs[slot].port = servers[i].port;
        ++r->job_count;
    }
    resolver_unlock(r);
    return room;
}
static unsigned resolver_drain(fp_tcp_nat *s, fp_tcp_resolve_answer *out, unsigned max) {
    fp_tcp_resolver *r = s->resolver;
    if (!r || !max)
        return 0;
    if (!resolver_trylock(r))
        return 0;
    unsigned n = 0;
    while (n < max && r->answer_count) {
        out[n].address = r->answers[r->answer_head].address;
        out[n].port = r->answers[r->answer_head].port;
        out[n].ok = r->answers[r->answer_head].ok;
        ++n;
        r->answer_head = (r->answer_head + 1) % FP_TCP_RESOLVE_QUEUE;
        --r->answer_count;
    }
    resolver_unlock(r);
    return n;
}
void fp_tcp_nat_set_resolver(fp_tcp_nat *s, fp_tcp_resolve_fn resolve) {
    if (s)
        s->resolve = resolve;
}
void fp_tcp_nat_set_inline_resolution(fp_tcp_nat *s, int on) {
    if (s)
        s->inline_resolution = on;
}
int fp_tcp_nat_resolver_running(const fp_tcp_nat *s) {
    return s && s->resolver && s->resolver->started;
}
static uint16_t be16(const uint8_t *p) { return (uint16_t)((unsigned)p[0] << 8 | p[1]); }
static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3]; }

int fp_tcp_stun_response(const uint8_t *p, size_t n, const uint8_t tid[12], struct sockaddr_in *out) {
    if (n < 20) return 0;
    size_t body = be16(p + 2);
    if (be16(p) != 0x0101 || be32(p + 4) != 0x2112a442 || memcmp(p + 8, tid, 12) ||
        (body & 3) || body > 1004) return -1;
    if (n < 20 + body) return 0;
    struct sockaddr_in mapped = {0}, plain = {0};
    int found = 0, plain_found = 0;
    for (size_t at = 20; at < 20 + body;) {
        if (20 + body - at < 4) return -1;
        unsigned type = be16(p + at), size = be16(p + at + 2);
        at += 4;
        size_t padded = ((size_t)size + 3) & ~(size_t)3;
        if (padded > 20 + body - at) return -1;
        if (type == 0x0020 || type == 0x0001) {
            if (size < 4 || p[at] != 0) return -1;
            if (p[at + 1] == 1) {
                if (size != 8) return -1;
                uint16_t port = be16(p + at + 2);
                uint32_t ip = be32(p + at + 4);
                if (type == 0x0020) { port ^= 0x2112; ip ^= 0x2112a442; }
                if (!port || !ip || ip == UINT32_MAX || (ip >> 28) == 14) return -1;
                struct sockaddr_in value = {.sin_family = AF_INET, .sin_port = htons(port),
                                             .sin_addr = {.s_addr = htonl(ip)}};
                if (type == 0x0020) {
                    if (found && (mapped.sin_port != value.sin_port || mapped.sin_addr.s_addr != value.sin_addr.s_addr)) return -1;
                    mapped = value; found = 1;
                } else { plain = value; plain_found = 1; }
            } else if (p[at + 1] != 2 || size != 20) return -1;
        }
        at += padded;
    }
    if (!found && !plain_found) return -1;
    *out = found ? mapped : plain;
    return 1;
}

/* Every v6 socket we bind explicitly is v6-only. Linux defaults to
 * bindv6only=0, where a "::" listener occupies the same port in the IPv4 space
 * and would collide with the sibling v4 listener on the very same port. */
static void v6_only(op_socket fd, int family) {
    if (family != OP_FAM_V6) return;
    int one = 1;
    op_setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
}

static void family_close(fp_tcp_family *k) {
    if (k->fd >= 0) op_close(k->fd);
    k->fd = -1;
    for (unsigned i = 0; i < FP_TCP_PROBE_MAX; ++i) {
        if (k->held[i] >= 0) op_close(k->held[i]);
        k->held[i] = -1;
    }
    k->held_count = 0;
    for (unsigned i = 0; i < FP_TCP_PROBE_SLOTS; ++i) {
        if (k->slots[i].fd >= 0) op_close(k->slots[i].fd);
        k->slots[i].fd = -1;
        k->slots[i].target = -1;
        k->slots[i].phase = 0;
    }
    k->inflight = 0;
    k->phase = 0;
    k->resolving = 0;
    k->awaiting = 0;
    k->prepared = 0;
}
void fp_tcp_nat_init(fp_tcp_nat *s) {
    memset(s, 0, sizeof(*s));
    for (int f = 0; f < OP_FAM_COUNT; ++f) {
        fp_tcp_family *k = &s->family[f];
        k->fd = -1;
        k->type = FP_NAT_UNKNOWN;
        for (unsigned i = 0; i < FP_TCP_PROBE_MAX; ++i) k->held[i] = -1;
        for (unsigned i = 0; i < FP_TCP_PROBE_SLOTS; ++i) {
            k->slots[i].fd = -1;
            k->slots[i].target = -1;
        }
    }
}
/* The server list is family-independent configuration text; resolution happens
 * in fp_tcp_nat_prepare, where the family's gateway address is known. */
int fp_tcp_nat_configure(fp_tcp_nat *s, json_object *servers) {
    if (!servers) return 0;
    if (!json_object_is_type(servers, json_type_array) || json_object_array_length(servers) > FP_TCP_STUN_MAX) return -1;
    fp_stun_server parsed[FP_TCP_STUN_MAX] = {0};
    unsigned count = (unsigned)json_object_array_length(servers);
    for (unsigned i = 0; i < count; ++i) {
        json_object *entry = json_object_array_get_idx(servers, i);
        if (!json_object_is_type(entry, json_type_string)) return -1;
        const char *text = json_object_get_string(entry), *colon = strrchr(text, ':');
        size_t length = colon ? (size_t)(colon - text) : strlen(text);
        if (!length || length >= sizeof(parsed[i].host) || strlen(text) != (size_t)json_object_get_string_len(entry)) return -1;
        for (size_t k = 0; k < length; ++k) {
            unsigned char c = (unsigned char)text[k];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '-')) return -1;
        }
        unsigned port = 3478;
        if (colon) {
            if (!colon[1]) return -1;
            port = 0;
            for (const char *p = colon + 1; *p; ++p) {
                if (*p < '0' || *p > '9' || port > 6553) return -1;
                port = port * 10 + (unsigned)(*p - '0');
            }
            if (!port || port > 65535) return -1;
        }
        memcpy(parsed[i].host, text, length); parsed[i].port = (uint16_t)port;
    }
    memcpy(s->servers, parsed, sizeof(parsed)); s->server_count = count;
    return 0;
}
void fp_tcp_nat_close(fp_tcp_nat *s) {
    s->step_last_ns = s->step_max_ns = 0;
    s->step_slow = 0;
    resolver_stop(s, 1);
    for (int f = 0; f < OP_FAM_COUNT; ++f)
        family_close(&s->family[f]);
}
/* One family's target list: the two gateway probe ports of that family, plus the configured
 * STUN servers for IPv4 only (their text syntax is v4).
 *
 * The gateway's own two ports need no name resolution, so they are ready at once. The
 * configured witnesses are not: resolving a list of foreign names is the one blocking call
 * left in this file, and it runs inside the loop that also drives the control channel. Ten
 * names resolved back to back kept that loop busy for seconds, the gateway stopped seeing
 * heartbeats and closed the session - a reconnect loop that looked like the node being
 * kicked. The list is therefore walked one name per step call (see family_resolve_step);
 * prepared stays 0 until the walk is done. */
static void family_begin(fp_tcp_family *k, const op_addr *gateway, int index,
                         const fp_stun_server *servers, unsigned count, int have_worker) {
    k->samples = k->destinations = 0;
    k->next_cycle = 0;
    k->type = FP_NAT_UNKNOWN;
    k->prepared = 0;
    k->target_count = 0;
    k->resolving = 0;
    k->awaiting = 0;
    k->resolve_index = k->resolved = 0;
    k->next_resolve_at = 0;
    k->resolve_cost = 0;
    if (!gateway || !gateway->len || op_family_index(op_addr_family(gateway)) != index)
        return;
    /* Only a destination the NAT actually translates says anything about the mapping.
     * A gateway on our own network answers with our untranslated address, and counting
     * it here made every self-hosted deployment look destination-dependent. */
    if (op_addr_routable(gateway)) {
        for (unsigned i = 0; i < 2; ++i) {
            memset(&k->targets[i], 0, sizeof(k->targets[i]));
            op_addr_copy(&k->targets[i].address, gateway);
            op_addr_set_port(&k->targets[i].address, (uint16_t)(27180 + i));
            k->targets[i].stun = 0;
        }
        k->target_count = 2;
    }
    if (index == OP_FAM_V4 && count) {
        /* With a worker the answers arrive on their own; without one the walk below takes
         * over. Either way the ladder waits until every name has an answer. */
        if (have_worker)
            k->awaiting = count;
        else
            k->resolving = 1;
        return;
    }
    /* One destination cannot tell whether the mapping follows the destination, so an
     * unanswerable question stays unmeasured instead of being guessed. */
    if (k->target_count >= 2)
        k->prepared = 1;
}
/* Append one resolved witness, keeping the configured order and dropping an address that is
 * already in the list. */
static void family_add_target(fp_tcp_family *k, const op_addr *address, uint16_t port) {
    op_addr resolved = *address;
    op_addr_set_port(&resolved, port);
    for (unsigned q = 0; q < k->target_count; ++q)
        if (op_addr_equal(&resolved, &k->targets[q].address) &&
            op_addr_port(&resolved) == op_addr_port(&k->targets[q].address))
            return;
    if (k->target_count < FP_TCP_PROBE_MAX)
        k->targets[k->target_count++] = (fp_tcp_probe_target){.address = resolved, .stun = 1};
}
/* Take the worker's answers in the order they were queued, which is the order the names were
 * submitted, so the target list keeps the configured order. */
static void family_apply_answers(fp_tcp_family *k, const fp_tcp_resolve_answer *batch, unsigned n) {
    for (unsigned i = 0; i < n && k->awaiting; ++i) {
        if (batch[i].ok)
            family_add_target(k, &batch[i].address, batch[i].port);
        ++k->resolved;
        --k->awaiting;
    }
    if (!k->awaiting && !k->resolving && k->target_count >= 2)
        k->prepared = 1;
}
/* Fallback: no worker could be started, so resolve one name per step call, spaced out. The
 * spacing widens to whatever the last lookup took, which keeps a slow resolver's share of
 * the loop bounded instead of letting it take the whole call. */
static void family_resolve_step(fp_tcp_family *k, int index, const fp_stun_server *servers,
                                unsigned count, uint64_t now, fp_tcp_resolve_fn resolve) {
    if (!k->resolving || now < k->next_resolve_at)
        return;
    if (k->resolve_index < count) {
        const fp_stun_server *server = &servers[k->resolve_index++];
        uint64_t started = op_monotonic_ns();
        op_addr resolved;
        memset(&resolved, 0, sizeof(resolved));
        if (!resolve(server->host, server->port, &resolved))
            family_add_target(k, &resolved, server->port);
        ++k->resolved;
        k->resolve_cost = op_monotonic_ns() - started;
        uint64_t wait = k->resolve_cost > TCP_RESOLVE_INTERVAL ? k->resolve_cost : TCP_RESOLVE_INTERVAL;
        k->next_resolve_at = now + wait;
    }
    if (k->resolve_index >= count)
        k->resolving = 0;
    if (!k->resolving && k->target_count >= 2)
        k->prepared = 1;
}
void fp_tcp_nat_prepare(fp_tcp_nat *s, const op_addr gateway[OP_FAM_COUNT], int families) {
    resolver_stop(s, 0); /* a reconfigure happens in the loop: never wait for a lookup */
    for (int f = 0; f < OP_FAM_COUNT; ++f) family_close(&s->family[f]);
    /* One worker for the client, started here because this is where the names to resolve
     * arrive. A platform that cannot give one leaves resolver NULL and every family uses the
     * fallback walk. */
    if (!s->inline_resolution && !resolver_start(s))
        s->resolver = NULL;
    for (int f = 0; f < OP_FAM_COUNT; ++f) {
        fp_tcp_family *k = &s->family[f];
        if (!(families & (1 << f)))
            continue;
        family_begin(k, &gateway[f], f, s->servers, s->server_count, s->resolver != NULL);
        if (f == OP_FAM_V4 && k->awaiting && !resolver_submit(s, s->servers, s->server_count)) {
            /* The queue would not take them: walk instead, so no name is lost. */
            k->awaiting = 0;
            k->resolving = 1;
        }
    }
}
static int connected(op_socket fd) {
    op_pollfd poll = {.fd = fd, .events = POLLOUT};
    int ready = op_poll(&poll, 1, 0);
    if (ready <= 0) return ready;
    int error = 0; op_socklen length = sizeof(error);
    if (op_getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) || error) return -1;
    return 1;
}
static fp_tcp_slot *slot_free(fp_tcp_family *k) {
    for (unsigned i = 0; i < FP_TCP_PROBE_SLOTS; ++i)
        if (k->slots[i].target < 0) return &k->slots[i];
    return NULL;
}
/* Retire a slot. The descriptor is kept, not closed: every probe in a batch has to leave
 * from the same local port for the comparison across destinations to mean anything, and a
 * closed socket would let the port go and the next bind pick a different one. */
static void slot_release(fp_tcp_family *k, fp_tcp_slot *s) {
    if (s->fd >= 0) {
        if (k->held_count < FP_TCP_PROBE_MAX)
            k->held[k->held_count++] = s->fd;
        else
            op_close(s->fd);
    }
    s->fd = -1;
    s->target = -1;
    s->phase = 0;
    if (k->inflight) --k->inflight;
    ++k->index;
}
/* Start one probe for the next target that has not been tried yet. */
static void slot_launch(fp_tcp_family *k, int family, uint64_t now) {
    fp_tcp_slot *s = slot_free(k);
    if (!s || k->next_target >= k->target_count) return;
    unsigned index = k->next_target++;
    op_addr bind_to;
    memset(&bind_to, 0, sizeof(bind_to));
    if (k->source.len) {
        /* A punch sample dials from the endpoint the punch will use. */
        bind_to = k->source;
    } else if (!k->fresh_source && k->source_port) {
        /* The rest of the batch reuses the port the first probe was given. */
        if (op_addr_from_text(&bind_to, family == OP_FAM_V6 ? "::" : "0.0.0.0", k->source_port))
            return;
    } else if (op_addr_from_text(&bind_to, family == OP_FAM_V6 ? "::" : "0.0.0.0", 0)) {
        return;
    }
    s->fd = op_socket_open(op_index_family(family), SOCK_STREAM, 0);
    v6_only(s->fd, family);
    if (s->fd < 0 || op_reuse_socket(s->fd) || op_bind(s->fd, &bind_to.u.sa, bind_to.len)) {
        if (s->fd >= 0) { op_close(s->fd); s->fd = -1; }
        return;
    }
    if (!k->source.len && !k->fresh_source && !k->source_port) {
        op_addr bound;
        if (!op_addr_socketname(s->fd, &bound)) k->source_port = op_addr_port(&bound);
    }
    memset(s->request, 0, sizeof(s->request));
    if (k->targets[index].stun) {
        s->request[1] = 1; s->request[4] = 0x21; s->request[5] = 0x12;
        s->request[6] = 0xa4; s->request[7] = 0x42;
        if (RAND_bytes(s->request + 8, 12) != 1) { op_close(s->fd); s->fd = -1; return; }
        s->request_length = 20;
    } else {
        s->request[0] = '2';
        s->request_length = 1;
    }
    s->sent = s->received = 0;
    s->deadline = now + (k->source.len ? PUNCH_SAMPLE_TIMEOUT : 2 * SECOND);
    s->target = (int)index;
    s->phase = 2;
    ++k->inflight;
    if (k->inflight > k->peak_inflight) k->peak_inflight = k->inflight;
    if (op_connect(s->fd, &k->targets[index].address.u.sa,
                   k->targets[index].address.len) && errno != EINPROGRESS)
        slot_release(k, s);
}
/* Advance one slot as far as it can go without blocking; record its answer under its own
 * target index so arrival order cannot reorder the samples. */
static void slot_step(fp_tcp_family *k, int family, fp_tcp_slot *s, uint64_t now) {
    if (s->target < 0) return;
    unsigned index = (unsigned)s->target;
    if (now >= s->deadline) { slot_release(k, s); return; }
    if (s->phase == 2) {
        int ready = connected(s->fd);
        if (ready < 0) { slot_release(k, s); return; }
        if (!ready) return;
        s->phase = 3;
    }
    if (s->phase == 3) {
        op_ssize sent = op_send(s->fd, s->request + s->sent, s->request_length - s->sent, MSG_NOSIGNAL);
        if (sent > 0) s->sent += (size_t)sent;
        else if (!sent || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) { slot_release(k, s); return; }
        if (s->sent != s->request_length) return;
        s->phase = 4;
    }
    op_ssize received = op_recv(s->fd, s->response + s->received, sizeof(s->response) - s->received, MSG_DONTWAIT);
    if (received > 0) s->received += (size_t)received;
    else if (!received || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) { slot_release(k, s); return; }
    op_addr mapped;
    memset(&mapped, 0, sizeof(mapped));
    int parsed;
    if (k->targets[index].stun) {
        struct sockaddr_in mapped4;
        memset(&mapped4, 0, sizeof(mapped4));
        parsed = fp_tcp_stun_response(s->response, s->received, s->request + 8, &mapped4);
        if (parsed > 0) {
            memset(&mapped, 0, sizeof(mapped));
            mapped.u.in = mapped4;
            mapped.len = (op_socklen)sizeof(mapped4);
        }
    } else {
        op_addr echo;
        parsed = fp_tcp_echo_response(s->response, s->received, &echo);
        /* A probe only samples its own family; an echo of the other family (or
         * of a legacy gateway with different framing) is not a sample. */
        if (parsed > 0 && op_family_index(op_addr_family(&echo)) != family) parsed = -1;
        if (parsed > 0) mapped = echo;
    }
    if (parsed || s->received == sizeof(s->response)) {
        if (parsed > 0) {
            k->cycle_mapped[index] = mapped;
            k->cycle_ok[index] = 1;
        }
        slot_release(k, s);
    }
}
/* Append the batch's answers in target order and publish the verdict. */
static void cycle_finish(fp_tcp_family *k, uint64_t now) {
    for (unsigned i = 0; i < k->target_count; ++i) {
        if (!k->cycle_ok[i]) continue;
        int known_ip = 0;
        for (unsigned q = 0; q < k->collected; ++q)
            if (op_addr_equal(&k->target_used[q], &k->targets[i].address)) known_ip = 1;
        if (!known_ip) ++k->collected_ips;
        k->target_used[k->collected] = k->targets[i].address;
        k->mapped[k->collected++] = k->cycle_mapped[i];
    }
    k->samples = k->collected;
    k->destinations = k->collected_ips;
    k->type = FP_NAT_UNKNOWN;
    if (k->samples >= 2) {
        k->type = FP_NAT_STABLE;
        for (unsigned i = 1; i < k->samples; ++i)
            if (op_addr_port(&k->mapped[i]) != op_addr_port(&k->mapped[0]) ||
                !op_addr_equal(&k->mapped[i], &k->mapped[0])) k->type = FP_NAT_DEPENDENT;
    }
    for (unsigned i = 0; i < FP_TCP_PROBE_MAX; ++i) {
        if (k->held[i] >= 0) op_close(k->held[i]);
        k->held[i] = -1;
    }
    k->held_count = 0;
    for (unsigned i = 0; i < FP_TCP_PROBE_SLOTS; ++i) {
        if (k->slots[i].fd >= 0) op_close(k->slots[i].fd);
        k->slots[i].fd = -1;
        k->slots[i].target = -1;
        k->slots[i].phase = 0;
    }
    k->inflight = 0;
    k->phase = 0;
    k->next_cycle = now + (k->type == FP_NAT_UNKNOWN ? 30 : 600) * SECOND;
}
int fp_tcp_echo_response(const uint8_t *p, size_t n, op_addr *out) {
    const uint8_t *end = memchr(p, '\n', n);
    if (!end) return n < 95 ? 0 : -1;
    size_t length = (size_t)(end - p);
    if (length >= 96 || memchr(p, 0, length)) return -1;
    char text[96], address[INET6_ADDRSTRLEN + 1];
    memcpy(text, p, length); text[length] = 0;
    const char *ip, *port_text;
    if (text[0] == '[') {
        /* SPEC §3 probeV3: an IPv6 echo record is bracketed so the address and
         * port boundary is unambiguous. */
        const char *close = strchr(text, ']');
        if (!close || close == text + 1 || close[1] != ':') return -1;
        size_t used = (size_t)(close - text - 1);
        if (used >= sizeof(address)) return -1;
        memcpy(address, text + 1, used); address[used] = 0;
        ip = address;
        port_text = close + 2;
    } else {
        const char *colon = strchr(text, ':');
        if (!colon || colon == text) return -1;
        size_t used = (size_t)(colon - text);
        if (used >= sizeof(address)) return -1;
        memcpy(address, text, used); address[used] = 0;
        ip = address;
        port_text = colon + 1;
    }
    unsigned port = 0;
    if (!*port_text) return -1;
    for (const char *digit = port_text; *digit; ++digit) {
        if (*digit < '0' || *digit > '9' || port > 6553) return -1;
        port = port * 10 + (unsigned)(*digit - '0');
    }
    if (!port || port > 65535) return -1;
    op_addr parsed;
    if (op_addr_from_text(&parsed, ip, (uint16_t)port)) return -1;
    if (op_addr_family(&parsed) == AF_INET) {
        if (!parsed.u.in.sin_addr.s_addr) return -1; /* the old 0.0.0.0 rejection */
    } else {
        static const uint8_t unspecified[16] = {0};
        if (!memcmp(parsed.u.in6.sin6_addr.s6_addr, unspecified, sizeof(unspecified))) return -1;
    }
    *out = parsed;
    return 1;
}
/* One request/reply step of a family's TCP mapping discovery. The sequence of stages is
 * the old single-socket one (bound source port held for the whole batch, one marker byte
 * per probe, quiet-period boundary for legacy echoes); what changed is that up to
 * FP_TCP_PROBE_SLOTS probes run at the same time, each on its own target, so a witness
 * list costs one round trip per batch instead of one per destination. Nothing here blocks:
 * every socket is non-blocking and a slot advances at most one stage per call. */
static int family_step(fp_tcp_family *k, int family, uint64_t now) {
    if (!k->prepared) return 0;
    if (!k->phase) {
        if (now < k->next_cycle) return 0;
        k->phase = 1;
        k->index = k->collected = k->collected_ips = 0;
        k->source_port = 0;
        k->next_target = k->inflight = k->peak_inflight = k->held_count = 0;
        memset(k->cycle_ok, 0, sizeof(k->cycle_ok));
    }
    while (k->next_target < k->target_count && slot_free(k)) slot_launch(k, family, now);
    for (unsigned i = 0; i < FP_TCP_PROBE_SLOTS; ++i) slot_step(k, family, &k->slots[i], now);
    while (k->next_target < k->target_count && slot_free(k)) slot_launch(k, family, now);
    if (k->next_target == k->target_count && k->inflight == 0) {
        cycle_finish(k, now);
        return 1;
    }
    return 0;
}
int fp_tcp_nat_step(fp_tcp_nat *s, uint64_t now) {
    /* Answers first: the worker has been resolving in parallel with everything else, and the
     * drain is a try-lock plus a bounded copy, so this call never waits for it. */
    uint64_t entered = op_monotonic_ns();
    fp_tcp_resolve_answer batch[FP_TCP_RESOLVE_QUEUE];
    unsigned answered = resolver_drain(s, batch, FP_TCP_RESOLVE_QUEUE);
    if (answered)
        family_apply_answers(&s->family[OP_FAM_V4], batch, answered);
    int done = 0;
    for (int f = 0; f < OP_FAM_COUNT; ++f) {
        /* The fallback walk still resolves at most one name per call, and the probe ladder
         * only runs once the family is prepared. */
        family_resolve_step(&s->family[f], f, s->servers, s->server_count, now,
                            s->resolve ? s->resolve : platform_resolve);
        if (family_step(&s->family[f], f, now)) done |= 1 << f;
    }
    /* What the caller needs to correlate a stalled tick with a closed session. Two clock
     * reads per step are nothing next to a socket operation. */
    uint64_t spent = op_monotonic_ns() - entered;
    s->step_last_ns = spent;
    if (spent > s->step_max_ns)
        s->step_max_ns = spent;
    if (spent > FP_TCP_STEP_SLOW_NS)
        ++s->step_slow;
    return done;
}
void fp_tcp_nat_step_stats(const fp_tcp_nat *s, uint64_t *last_ns, uint64_t *max_ns,
                           unsigned *slow) {
    if (last_ns)
        *last_ns = s ? s->step_last_ns : 0;
    if (max_ns)
        *max_ns = s ? s->step_max_ns : 0;
    if (slow)
        *slow = s ? s->step_slow : 0;
}
void fp_tcp_nat_step_stats_reset(fp_tcp_nat *s) {
    if (!s)
        return;
    s->step_max_ns = 0;
    s->step_slow = 0;
}

fp_tcp_family *fp_tcp_punch_sample_start(const fp_tcp_family *catalog, const op_addr *source,
                                       const op_addr *first_mapping) {
    if (catalog->target_count < 3)
        return NULL;
    /* Sample distinct destination IPs. The first result came from 27180. */
    fp_tcp_probe_target targets[FP_TCP_PROBE_MAX];
    unsigned count = 0;
    for (unsigned i = 1; i < catalog->target_count; ++i) {
        const fp_tcp_probe_target *target = &catalog->targets[i];
        int duplicate = op_addr_equal(&target->address, &catalog->targets[0].address);
        for (unsigned j = 0; j < count; ++j)
            duplicate |= op_addr_equal(&target->address, &targets[j].address);
        if (!duplicate)
            targets[count++] = *target;
    }
    if (count < 2)
        return NULL;
    fp_tcp_family *sample = calloc(1, sizeof(*sample));
    if (!sample)
        return NULL;
    sample->source = *source;
    sample->source_port = op_addr_port(source);
    sample->fd = -1;
    for (unsigned i = 0; i < FP_TCP_PROBE_MAX; ++i)
        sample->held[i] = -1;
    for (unsigned i = 0; i < FP_TCP_PROBE_SLOTS; ++i) {
        sample->slots[i].fd = -1;
        sample->slots[i].target = -1;
    }
    memcpy(sample->targets, targets, count * sizeof(targets[0]));
    sample->target_count = count;
    sample->target_used[0] = catalog->targets[0].address;
    sample->mapped[0] = *first_mapping;
    sample->collected = sample->collected_ips = 1;
    sample->prepared = sample->phase = 1;
    return sample;
}

int fp_tcp_punch_sample_step(fp_tcp_family *sample, uint64_t now, unsigned *mapping, uint16_t *port) {
    if (!family_step(sample, OP_FAM_V4, now))
        return 0;
    if (sample->destinations < 3)
        return 1;
    int step = (int)op_addr_port(&sample->mapped[1]) - op_addr_port(&sample->mapped[0]);
    if (step < -1 || step > 1)
        return 1;
    for (unsigned i = 1; i < sample->samples; ++i) {
        if (!op_addr_equal(&sample->mapped[i], &sample->mapped[0]) ||
            (int)op_addr_port(&sample->mapped[i]) - op_addr_port(&sample->mapped[i - 1]) != step)
            return 1;
    }
    *mapping = step == 0 ? FP_TCP_MAP_STABLE : step > 0 ? FP_TCP_MAP_INCREMENT : FP_TCP_MAP_DECREMENT;
    *port = op_addr_port(&sample->mapped[sample->samples - 1]);
    return 1;
}

int fp_tcp_alloc_delta(const op_addr *mapped, unsigned count, int *step, uint16_t *port) {
    *step = 0;
    if (count < 3 || !mapped)
        return -1;
    *port = op_addr_port(&mapped[count - 1]);
    int delta = (int)op_addr_port(&mapped[1]) - (int)op_addr_port(&mapped[0]);
    if (delta == 0 || delta > 4096 || delta < -4096)
        return 0;
    for (unsigned i = 2; i < count; ++i)
        if ((int)op_addr_port(&mapped[i]) - (int)op_addr_port(&mapped[i - 1]) != delta)
            return 0;
    *step = delta;
    return 1;
}

fp_tcp_family *fp_tcp_alloc_sample_start(const op_addr *gateway, unsigned count) {
    if (!gateway || !gateway->len || count < 3 || count > FP_TCP_PROBE_MAX)
        return NULL;
    fp_tcp_family *sample = calloc(1, sizeof(*sample));
    if (!sample)
        return NULL;
    sample->fd = -1;
    for (unsigned i = 0; i < FP_TCP_PROBE_MAX; ++i)
        sample->held[i] = -1;
    for (unsigned i = 0; i < FP_TCP_PROBE_SLOTS; ++i) {
        sample->slots[i].fd = -1;
        sample->slots[i].target = -1;
    }
    sample->fresh_source = 1;
    for (unsigned i = 0; i < count; ++i) {
        sample->targets[i].address = *gateway;
        op_addr_set_port(&sample->targets[i].address, 27180);
        sample->targets[i].stun = 0;
    }
    sample->target_count = count;
    sample->prepared = sample->phase = 1;
    return sample;
}

int fp_tcp_alloc_sample_step(fp_tcp_family *sample, uint64_t now, int *step, uint16_t *port) {
    *step = 0;
    if (!family_step(sample, OP_FAM_V4, now))
        return 0;
    if (sample->samples >= 3)
        fp_tcp_alloc_delta(sample->mapped, sample->samples, step, port);
    return 1;
}

void fp_tcp_punch_sample_free(fp_tcp_family *sample) {
    if (sample) {
        family_close(sample);
        free(sample);
    }
}
