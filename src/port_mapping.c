#include "platform.h"
#include "port_mapping.h"

#include <curl/curl.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <natpmp.h>
#include <openssl/rand.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <process.h>
#endif

#define LEASE_SECONDS 300u
#define RETRY_SECONDS 30u
#define NS_PER_SECOND UINT64_C(1000000000)
#define IGD_NO_SUCH_MAPPING 714

enum { MAPPING_NONE, MAPPING_IGD, MAPPING_PMP };
enum { MAP_TCP, MAP_UDP, MAP_COUNT };

typedef struct {
    uint16_t internal, external;
    int backend;
    uint32_t renew, expires, wan;
} lease;

struct fp_port_mapping {
#ifdef _WIN32
    HANDLE thread;
    SRWLOCK lock;
#else
    pthread_t thread;
    pthread_mutex_t lock;
#endif
    atomic_int stopping;
    uint16_t internal[MAP_COUNT];
    lease published[MAP_COUNT];
};

typedef struct {
    fp_port_mapping *owner;
    natpmp_t pmp;
    struct UPNPUrls urls;
    struct IGDdatas igd;
    char local[OP_ADDR_TEXT], description[40];
    lease ports[MAP_COUNT];
} mapper;

static uint32_t seconds_now(void) {
    return (uint32_t)(op_monotonic_ns() / NS_PER_SECOND);
}

static void lock_mapping(fp_port_mapping *m) {
#ifdef _WIN32
    AcquireSRWLockExclusive(&m->lock);
#else
    pthread_mutex_lock(&m->lock);
#endif
}

static void unlock_mapping(fp_port_mapping *m) {
#ifdef _WIN32
    ReleaseSRWLockExclusive(&m->lock);
#else
    pthread_mutex_unlock(&m->lock);
#endif
}

static int router_url(const char *text, uint32_t gateway) {
    CURLU *url = curl_url();
    if (!url || !text) {
        curl_url_cleanup(url);
        return 0;
    }
    char *host = NULL, *scheme = NULL;
    struct in_addr ip;
    int valid = !curl_url_set(url, CURLUPART_URL, text, CURLU_DISALLOW_USER) &&
                !curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) && !strcmp(scheme, "http") &&
                !curl_url_get(url, CURLUPART_HOST, &host, 0) &&
                inet_pton(AF_INET, host, &ip) == 1 && ip.s_addr == gateway;
    curl_free(host);
    curl_free(scheme);
    curl_url_cleanup(url);
    return valid;
}

static void discover_igd(mapper *m) {
    static const char *const types[] = {
        "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1", NULL
    };
    struct UPNPDev *devices = upnpDiscoverDevices(types, 800, m->local, NULL, 0, 0, 1, NULL, 0);
    for (struct UPNPDev *d = devices; d && !atomic_load(&m->owner->stopping); d = d->pNext) {
        if (!router_url(d->descURL, m->pmp.gateway))
            continue;
        char local[OP_ADDR_TEXT] = {0};
        if (UPNP_GetIGDFromUrl(d->descURL, &m->urls, &m->igd, local, sizeof(local)) &&
            !strcmp(local, m->local) && router_url(m->urls.controlURL, m->pmp.gateway) &&
            (!strcmp(m->igd.first.servicetype, "urn:schemas-upnp-org:service:WANIPConnection:1") ||
             !strcmp(m->igd.first.servicetype, "urn:schemas-upnp-org:service:WANIPConnection:2") ||
             !strcmp(m->igd.first.servicetype, "urn:schemas-upnp-org:service:WANPPPConnection:1")))
            break;
        FreeUPNPUrls(&m->urls);
    }
    freeUPNPDevlist(devices);
}

static int pmp_reply(mapper *m, natpmpresp_t *reply, int deleting) {
    uint64_t deadline = op_monotonic_ns() + (deleting ? NS_PER_SECOND / 3 : NS_PER_SECOND);
    do {
        int result = readnatpmpresponseorretry(&m->pmp, reply);
        if (result != NATPMP_TRYAGAIN)
            return result;
        op_pollfd wait = {.fd = m->pmp.s, .events = POLLIN};
        op_poll(&wait, 1, 50);
    } while (op_monotonic_ns() < deadline);
    return -1;
}

static int pmp_mapping(mapper *m, int index, uint16_t port, uint32_t duration, lease *value) {
    natpmpresp_t reply = {0};
    int protocol = index == MAP_TCP ? NATPMP_PROTOCOL_TCP : NATPMP_PROTOCOL_UDP;
    if (sendnewportmappingrequest(&m->pmp, protocol, value->internal, port, duration) < 0 ||
        pmp_reply(m, &reply, !duration) || reply.type != protocol ||
        reply.pnu.newportmapping.privateport != value->internal)
        return -1;
    if (!duration)
        return reply.pnu.newportmapping.lifetime ? -1 : 0;
    uint32_t lifetime = reply.pnu.newportmapping.lifetime;
    if (!lifetime || !reply.pnu.newportmapping.mappedpublicport)
        return -1;
    value->external = reply.pnu.newportmapping.mappedpublicport;
    return (int)(lifetime > LEASE_SECONDS ? LEASE_SECONDS : lifetime);
}

static const char *protocol_name(int index) { return index == MAP_TCP ? "TCP" : "UDP"; }

/* 0 means this process owns the entry, 714 means the port is free. */
static int igd_mapping_owner(mapper *m, int index, const char *external, const char *internal,
                             char *duration) {
    char client[16] = {0}, port[6] = {0}, desc[80] = {0};
    int rc = UPNP_GetSpecificPortMappingEntry(m->urls.controlURL, m->igd.first.servicetype,
                                               external, protocol_name(index), NULL,
                                               client, port, desc, NULL, duration);
    return !rc && (strcmp(client, m->local) || strcmp(port, internal) || strcmp(desc, m->description))
               ? -1 : rc;
}

static int igd_lease_seconds(mapper *m, int index, const char *external, const char *internal) {
    char duration[16] = {0}, *end;
    if (!igd_mapping_owner(m, index, external, internal, duration)) {
        unsigned long seconds = strtoul(duration, &end, 10);
        if (!*end && seconds && seconds < LEASE_SECONDS)
            return (int)seconds;
    }
    return LEASE_SECONDS;
}

static int igd_mapping(mapper *m, int index, lease *value, int deleting) {
    const char *type = m->igd.first.servicetype, *proto = protocol_name(index);
    char internal[6], external[6], duration[12];
    snprintf(internal, sizeof(internal), "%u", (unsigned)value->internal);
    snprintf(external, sizeof(external), "%u", (unsigned)value->external);
    snprintf(duration, sizeof(duration), "%u", LEASE_SECONDS);
    if (value->external) {
        int owner = igd_mapping_owner(m, index, external, internal, NULL);
        if (deleting)
            return owner ? -1 : UPNP_DeletePortMapping(m->urls.controlURL, type, external, proto, NULL);
        if (owner && owner != IGD_NO_SUCH_MAPPING)
            return -1;
    } else {
        char assigned[6] = {0};
        if (!UPNP_AddAnyPortMapping(m->urls.controlURL, type, "0", internal, m->local,
                                    m->description, proto, NULL, duration, assigned)) {
            char *end;
            unsigned long port = strtoul(assigned, &end, 10);
            if (!*end && port && port <= UINT16_MAX) {
                value->external = (uint16_t)port;
                return igd_lease_seconds(m, index, assigned, internal);
            }
            return -1;
        }
        if (atomic_load(&m->owner->stopping) ||
            igd_mapping_owner(m, index, internal, internal, NULL) != IGD_NO_SUCH_MAPPING)
            return -1;
        memcpy(external, internal, sizeof(external));
    }
    if (UPNP_AddPortMapping(m->urls.controlURL, type, external, internal, m->local,
                            m->description, proto, NULL, duration))
        return -1;
    value->external = (uint16_t)strtoul(external, NULL, 10);
    return igd_lease_seconds(m, index, external, internal);
}

static uint32_t wan_address(mapper *m, int backend) {
    if (backend == MAPPING_PMP) {
        natpmpresp_t reply = {0};
        return sendpublicaddressrequest(&m->pmp) >= 0 && !pmp_reply(m, &reply, 0) &&
                       reply.type == NATPMP_RESPTYPE_PUBLICADDRESS ? reply.pnu.publicaddress.addr.s_addr : 0;
    }
    struct in_addr ip = {0};
    char text[16] = {0};
    if (!UPNP_GetExternalIPAddress(m->urls.controlURL, m->igd.first.servicetype, text))
        inet_pton(AF_INET, text, &ip);
    return ip.s_addr;
}

static void update_lease(mapper *m, int index, uint32_t now) {
    lease *value = &m->ports[index];
    if (!value->internal || now < value->renew)
        return;
    if (now >= value->expires) {
        value->backend = MAPPING_NONE;
        value->external = 0;
    }
    int duration = -1;
    if (m->urls.controlURL && value->backend != MAPPING_PMP && !atomic_load(&m->owner->stopping)) {
        duration = igd_mapping(m, index, value, 0);
        if (duration > 0)
            value->backend = MAPPING_IGD;
    }
    if (duration < 0 && value->backend != MAPPING_IGD && !atomic_load(&m->owner->stopping)) {
        duration = pmp_mapping(m, index, value->external, LEASE_SECONDS, value);
        if (duration < 0 && !value->external && !atomic_load(&m->owner->stopping))
            duration = pmp_mapping(m, index, value->internal, LEASE_SECONDS, value);
        if (duration > 0)
            value->backend = MAPPING_PMP;
    }
    value->renew = now + RETRY_SECONDS;
    if (duration > 0) {
        uint32_t seconds = (uint32_t)duration;
        value->expires = now + seconds;
        value->renew = now + (seconds >= 5 ? seconds - seconds / 5 : 1);
        if (!atomic_load(&m->owner->stopping))
            value->wan = wan_address(m, value->backend);
    }
    lock_mapping(m->owner);
    m->owner->published[index] = *value;
    unlock_mapping(m->owner);
}

static void run_mapping(fp_port_mapping *owner) {
    mapper m = {.owner = owner};
    int rc = initnatpmp(&m.pmp, 0, 0);
    op_addr local;
    if (rc || op_addr_socketname(m.pmp.s, &local) || op_addr_family(&local) != AF_INET ||
        op_addr_text(&local, m.local, sizeof(m.local)))
        goto done;
    uint32_t ip = ntohl(local.u.in.sin_addr.s_addr);
    if (!op_addr_private(&local) && (ip & UINT32_C(0xffc00000)) != UINT32_C(0x64400000) &&
        (ip & UINT32_C(0xffff0000)) != UINT32_C(0xa9fe0000))
        goto done;
    unsigned char suffix[8];
    if (RAND_bytes(suffix, sizeof(suffix)) != 1)
        goto done;
    memcpy(m.description, "FastP2P-", 8);
    for (size_t i = 0; i < sizeof(suffix); ++i)
        snprintf(m.description + 8 + i * 2, 3, "%02x", (unsigned)suffix[i]);
    for (int i = 0; i < MAP_COUNT; ++i)
        m.ports[i].internal = owner->internal[i];
    uint32_t next_discovery = 0;
    while (!atomic_load(&owner->stopping)) {
        uint32_t now = seconds_now();
        if (!m.urls.controlURL && !m.ports[MAP_TCP].external && !m.ports[MAP_UDP].external &&
            now >= next_discovery) {
            discover_igd(&m);
            next_discovery = now + RETRY_SECONDS;
        }
        for (int i = 0; i < MAP_COUNT && !atomic_load(&owner->stopping); ++i)
            update_lease(&m, i, seconds_now());
        op_sleep_ms(100);
    }
    for (int i = 0; i < MAP_COUNT; ++i) {
        lease *value = &m.ports[i];
        if (value->backend == MAPPING_IGD)
            igd_mapping(&m, i, value, 1);
        else if (value->backend == MAPPING_PMP)
            pmp_mapping(&m, i, value->external, 0, value);
    }
    FreeUPNPUrls(&m.urls);
done:
    if (m.pmp.s >= 0)
        closenatpmp(&m.pmp);
}

#ifdef _WIN32
static unsigned __stdcall mapping_thread(void *arg) { run_mapping(arg); return 0; }
#else
static void *mapping_thread(void *arg) { run_mapping(arg); return NULL; }
#endif

fp_port_mapping *fp_port_mapping_start(uint16_t tcp_port, uint16_t udp_port) {
    if (!tcp_port && !udp_port)
        return NULL;
    fp_port_mapping *m = calloc(1, sizeof(*m));
    if (!m)
        return NULL;
    atomic_init(&m->stopping, 0);
    m->internal[MAP_TCP] = tcp_port;
    m->internal[MAP_UDP] = udp_port;
#ifdef _WIN32
    InitializeSRWLock(&m->lock);
    m->thread = (HANDLE)_beginthreadex(NULL, 0, mapping_thread, m, 0, NULL);
    if (m->thread)
        return m;
#else
    if (!pthread_mutex_init(&m->lock, NULL)) {
        if (!pthread_create(&m->thread, NULL, mapping_thread, m))
            return m;
        pthread_mutex_destroy(&m->lock);
    }
#endif
    free(m);
    return NULL;
}

fp_mapped_ports fp_port_mapping_read(fp_port_mapping *m) {
    fp_mapped_ports ports = {0};
    if (!m)
        return ports;
    uint32_t now = seconds_now();
    lock_mapping(m);
    if (now < m->published[MAP_TCP].expires) {
        ports.tcp = m->published[MAP_TCP].external;
        ports.tcp_wan = m->published[MAP_TCP].wan;
    }
    if (now < m->published[MAP_UDP].expires) {
        ports.udp = m->published[MAP_UDP].external;
        ports.udp_wan = m->published[MAP_UDP].wan;
    }
    unlock_mapping(m);
    return ports;
}

void fp_port_mapping_stop(fp_port_mapping *m) {
    if (!m)
        return;
    atomic_store(&m->stopping, 1);
#ifdef _WIN32
    WaitForSingleObject(m->thread, INFINITE);
    CloseHandle(m->thread);
#else
    pthread_join(m->thread, NULL);
    pthread_mutex_destroy(&m->lock);
#endif
    free(m);
}
