#include "platform.h"
#include "port_mapping.h"

#include <curl/curl.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpreplyparse.h>
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
#define LEASE_RETRY_SECONDS 30u
#define DISCOVERY_RETRY_SECONDS 300u
#define NS_PER_SECOND UINT64_C(1000000000)
#define NS_PER_MS UINT64_C(1000000)
#define SSDP_TIMEOUT_MS 1000
#define HTTP_TIMEOUT_MS 1000
#define STOP_TIMEOUT_MS 2000
#define IGD_RESPONSE_LIMIT (128 * 1024)
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
    uint64_t stop_deadline;
    uint16_t internal[MAP_COUNT];
    lease published[MAP_COUNT];
};

typedef struct {
    fp_port_mapping *owner;
    natpmp_t pmp;
    struct UPNPUrls urls;
    struct IGDdatas igd;
    CURL *http;
    char *response;
    size_t response_len;
    uint64_t cleanup_deadline;
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

static int remaining_ms(uint64_t deadline) {
    uint64_t now = op_monotonic_ns();
    return now < deadline ? (int)((deadline - now + NS_PER_MS - 1) / NS_PER_MS) : 0;
}

static int request_timeout(const mapper *m, int limit) {
    if (!m->cleanup_deadline)
        return atomic_load(&m->owner->stopping) ? 0 : limit;
    int remaining = remaining_ms(m->cleanup_deadline);
    return remaining < limit ? remaining : limit;
}

static size_t router_response(char *data, size_t size, size_t count, void *arg) {
    mapper *m = arg;
    size_t bytes = size * count;
    if (bytes > IGD_RESPONSE_LIMIT - m->response_len)
        return 0;
    memcpy(m->response + m->response_len, data, bytes);
    m->response_len += bytes;
    return bytes;
}

/* Keep the entire HTTP transaction within the deadline even if the router
 * sends a partial response. Only the validated, local gateway can be dialed. */
static long router_http(mapper *m, const char *url, const char *body, const char *action) {
    long timeout = request_timeout(m, HTTP_TIMEOUT_MS);
    if (!timeout)
        return 0;
    struct curl_slist *headers = NULL;
    if (body) {
        headers = curl_slist_append(NULL, "Content-Type: text/xml; charset=\"utf-8\"");
        struct curl_slist *next = headers ? curl_slist_append(headers, action) : NULL;
        if (!next) {
            curl_slist_free_all(headers);
            return 0;
        }
        headers = next;
    }
    m->response_len = 0;
    curl_easy_reset(m->http);
    curl_easy_setopt(m->http, CURLOPT_URL, url);
    curl_easy_setopt(m->http, CURLOPT_PROTOCOLS_STR, "http");
    curl_easy_setopt(m->http, CURLOPT_PROXY, "");
    curl_easy_setopt(m->http, CURLOPT_INTERFACE, m->local);
    curl_easy_setopt(m->http, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(m->http, CURLOPT_TIMEOUT_MS, timeout);
    curl_easy_setopt(m->http, CURLOPT_WRITEFUNCTION, router_response);
    curl_easy_setopt(m->http, CURLOPT_WRITEDATA, m);
    if (body) {
        curl_easy_setopt(m->http, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(m->http, CURLOPT_POSTFIELDS, body);
    }
    long status = 0;
    if (curl_easy_perform(m->http) == CURLE_OK)
        curl_easy_getinfo(m->http, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers);
    return status;
}

static int load_igd(mapper *m, const char *location) {
    long status = router_http(m, location, NULL, NULL);
    if (status < 200 || status >= 300 || !m->response_len)
        return 0;
    memset(&m->igd, 0, sizeof(m->igd));
    parserootdesc(m->response, (int)m->response_len, &m->igd);
    const char *type = m->igd.first.servicetype;
    if (strcmp(type, "urn:schemas-upnp-org:service:WANIPConnection:1") &&
        strcmp(type, "urn:schemas-upnp-org:service:WANIPConnection:2") &&
        strcmp(type, "urn:schemas-upnp-org:service:WANPPPConnection:1"))
        return 0;
    GetUPNPUrls(&m->urls, &m->igd, location, 0);
    if (router_url(m->urls.controlURL, m->pmp.gateway))
        return 1;
    FreeUPNPUrls(&m->urls);
    return 0;
}

static const char *ssdp_location(char *packet) {
    char *line = strchr(packet, '\n');
    if (!line || line - packet < 12 || strncmp(packet, "HTTP/1.", 7) ||
        strncmp(packet + 8, " 200", 4) || !strchr(" \r\n", packet[12]))
        return NULL;
    while (*++line && *line != '\r' && *line != '\n') {
        char *end = strchr(line, '\n');
        if (!end)
            break;
        if (end - line > 9 && curl_strnequal(line, "Location:", 9)) {
            line += 9;
            while (*line == ' ' || *line == '\t')
                ++line;
            while (end > line && (end[-1] == '\r' || end[-1] == ' ' || end[-1] == '\t'))
                --end;
            *end = 0;
            return line;
        }
        line = end;
    }
    return NULL;
}

static void discover_igd(mapper *m, const op_addr *local) {
    static const char *const types[] = {
        "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
    };
    op_socket fd = op_socket_open(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return;
    op_addr source = *local, group;
    op_addr_set_port(&source, 0);
    if (op_bind(fd, &source.u.sa, source.len) ||
        op_setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &source.u.in.sin_addr, sizeof(source.u.in.sin_addr)) ||
        op_addr_from_text(&group, "239.255.255.250", 1900)) {
        op_close(fd);
        return;
    }
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); ++i) {
        char request[256];
        int length = snprintf(request, sizeof(request), "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: %s\r\n\r\n", types[i]);
        op_sendto(fd, request, (size_t)length, 0, &group.u.sa, group.len);
    }
    uint64_t deadline = op_monotonic_ns() + SSDP_TIMEOUT_MS * NS_PER_MS;
    int remaining;
    while (!atomic_load(&m->owner->stopping) && (remaining = remaining_ms(deadline)) > 0) {
        op_pollfd wait = {.fd = fd, .events = POLLIN};
        int ready = op_poll(&wait, 1, remaining < 50 ? remaining : 50);
        if (ready < 0)
            break;
        if (!ready)
            continue;
        char packet[2048];
        op_addr from = {.len = sizeof(from.u.storage)};
        op_ssize length = op_recvfrom(fd, packet, sizeof(packet) - 1, 0, &from.u.sa, &from.len);
        if (length <= 0 || from.u.sa.sa_family != AF_INET || from.u.in.sin_addr.s_addr != m->pmp.gateway)
            continue;
        packet[length] = 0;
        const char *location = ssdp_location(packet);
        if (location && router_url(location, m->pmp.gateway) && load_igd(m, location))
            break;
    }
    op_close(fd);
}

static int pmp_reply(mapper *m, natpmpresp_t *reply, int deleting) {
    /* The request is already on the wire. Give its reply a bounded chance to
     * arrive so a lease acquired just as stop was requested can be deleted. */
    uint64_t deadline = op_monotonic_ns() + (deleting ? 333 : 1000) * NS_PER_MS;
    if (m->cleanup_deadline && m->cleanup_deadline < deadline)
        deadline = m->cleanup_deadline;
    int remaining;
    do {
        int result = readnatpmpresponseorretry(&m->pmp, reply);
        if (result != NATPMP_TRYAGAIN)
            return result;
        op_pollfd wait = {.fd = m->pmp.s, .events = POLLIN};
        remaining = remaining_ms(deadline);
        if (remaining > 0)
            op_poll(&wait, 1, remaining < 50 ? remaining : 50);
    } while (remaining_ms(deadline) > 0);
    return -1;
}

static int pmp_mapping(mapper *m, int index, uint16_t port, uint32_t duration, lease *value) {
    natpmpresp_t reply = {0};
    int protocol = index == MAP_TCP ? NATPMP_PROTOCOL_TCP : NATPMP_PROTOCOL_UDP;
    if (!request_timeout(m, 1000) ||
        sendnewportmappingrequest(&m->pmp, protocol, value->internal, port, duration) < 0 ||
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

static unsigned igd_number(struct NameValueParserData *reply, const char *field) {
    const char *text = GetValueFromNameValueList(reply, field);
    if (!text || *text < '0' || *text > '9')
        return 0;
    char *end;
    unsigned long number = strtoul(text, &end, 10);
    return !*end && number <= UINT16_MAX ? (unsigned)number : 0;
}

static int igd_command(mapper *m, const char *name, const char *args, struct NameValueParserData *reply) {
    const char *type = m->igd.first.servicetype;
    char action[160], body[960];
    snprintf(action, sizeof(action), "SOAPAction: \"%s#%s\"", type, name);
    snprintf(body, sizeof(body),
             "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
             "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>"
             "<u:%s xmlns:u=\"%s\">%s</u:%s></s:Body></s:Envelope>", name, type, args, name);
    long status = router_http(m, m->urls.controlURL, body, action);
    if (!status)
        return -1;
    ParseNameValue(m->response, (int)m->response_len, reply);
    unsigned error = igd_number(reply, "errorCode");
    if (error)
        return (int)error;
    return status >= 200 && status < 300 ? 0 : -1;
}

static void igd_key(char out[128], int index, uint16_t external) {
    snprintf(out, 128, "<NewRemoteHost></NewRemoteHost><NewExternalPort>%u</NewExternalPort>"
             "<NewProtocol>%s</NewProtocol>", (unsigned)external, protocol_name(index));
}

/* 0 means this process owns the entry, 714 means the port is free. */
static int igd_mapping_owner(mapper *m, const char *key, uint16_t internal, unsigned *duration) {
    struct NameValueParserData reply = {0};
    int rc = igd_command(m, "GetSpecificPortMappingEntry", key, &reply);
    if (!rc) {
        const char *client = GetValueFromNameValueList(&reply, "NewInternalClient");
        const char *description = GetValueFromNameValueList(&reply, "NewPortMappingDescription");
        if (!client || strcmp(client, m->local) || !description || strcmp(description, m->description) ||
            igd_number(&reply, "NewInternalPort") != internal)
            rc = -1;
        else if (duration)
            *duration = igd_number(&reply, "NewLeaseDuration");
    }
    ClearNameValueList(&reply);
    return rc;
}

static int add_igd_mapping(mapper *m, int index, uint16_t external, lease *value) {
    char key[128], args[420];
    igd_key(key, index, external);
    snprintf(args, sizeof(args), "%s<NewInternalPort>%u</NewInternalPort>"
             "<NewInternalClient>%s</NewInternalClient><NewEnabled>1</NewEnabled>"
             "<NewPortMappingDescription>%s</NewPortMappingDescription>"
             "<NewLeaseDuration>%u</NewLeaseDuration>", key, (unsigned)value->internal,
             m->local, m->description, LEASE_SECONDS);
    struct NameValueParserData reply = {0};
    int rc = igd_command(m, external ? "AddPortMapping" : "AddAnyPortMapping", args, &reply);
    if (!external)
        external = (uint16_t)igd_number(&reply, "NewReservedPort");
    ClearNameValueList(&reply);
    if (rc || !external)
        return -1;
    value->external = external;
    igd_key(key, index, external);
    unsigned duration = 0;
    igd_mapping_owner(m, key, value->internal, &duration);
    return (int)(duration && duration < LEASE_SECONDS ? duration : LEASE_SECONDS);
}

static int igd_mapping(mapper *m, int index, lease *value, int deleting) {
    char key[128];
    if (value->external) {
        igd_key(key, index, value->external);
        int owner = igd_mapping_owner(m, key, value->internal, NULL);
        if (deleting) {
            if (owner)
                return -1;
            struct NameValueParserData reply = {0};
            int rc = igd_command(m, "DeletePortMapping", key, &reply);
            ClearNameValueList(&reply);
            return rc;
        }
        if (owner && owner != IGD_NO_SUCH_MAPPING)
            return -1;
        return add_igd_mapping(m, index, value->external, value);
    }
    if (!strcmp(m->igd.first.servicetype, "urn:schemas-upnp-org:service:WANIPConnection:2")) {
        int duration = add_igd_mapping(m, index, 0, value);
        if (duration > 0)
            return duration;
    }
    igd_key(key, index, value->internal);
    if (igd_mapping_owner(m, key, value->internal, NULL) != IGD_NO_SUCH_MAPPING)
        return -1;
    return add_igd_mapping(m, index, value->internal, value);
}

static uint32_t wan_address(mapper *m, int backend) {
    if (backend == MAPPING_PMP) {
        natpmpresp_t reply = {0};
        return request_timeout(m, 1000) && sendpublicaddressrequest(&m->pmp) >= 0 && !pmp_reply(m, &reply, 0) &&
                       reply.type == NATPMP_RESPTYPE_PUBLICADDRESS ? reply.pnu.publicaddress.addr.s_addr : 0;
    }
    struct in_addr ip = {0};
    struct NameValueParserData reply = {0};
    if (!igd_command(m, "GetExternalIPAddress", "", &reply)) {
        const char *text = GetValueFromNameValueList(&reply, "NewExternalIPAddress");
        if (text)
            inet_pton(AF_INET, text, &ip);
    }
    ClearNameValueList(&reply);
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
    value->renew = now + LEASE_RETRY_SECONDS;
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
    m.response = malloc(IGD_RESPONSE_LIMIT);
    if (m.response)
        m.http = curl_easy_init();
    uint32_t next_discovery = 0;
    while (!atomic_load(&owner->stopping)) {
        uint32_t now = seconds_now();
        if (m.http && !m.urls.controlURL && !m.ports[MAP_TCP].external && !m.ports[MAP_UDP].external &&
            now >= next_discovery) {
            discover_igd(&m, &local);
            next_discovery = seconds_now() + DISCOVERY_RETRY_SECONDS;
        }
        for (int i = 0; i < MAP_COUNT && !atomic_load(&owner->stopping); ++i)
            update_lease(&m, i, seconds_now());
        if (!atomic_load(&owner->stopping))
            op_sleep_ms(100);
    }
    m.cleanup_deadline = owner->stop_deadline; /* Published before stopping. */
    for (int i = 0; i < MAP_COUNT; ++i) {
        lease *value = &m.ports[i];
        if (value->backend == MAPPING_IGD)
            igd_mapping(&m, i, value, 1);
        else if (value->backend == MAPPING_PMP)
            pmp_mapping(&m, i, value->external, 0, value);
    }
    FreeUPNPUrls(&m.urls);
    curl_easy_cleanup(m.http);
    free(m.response);
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
    m->stop_deadline = op_monotonic_ns() + STOP_TIMEOUT_MS * NS_PER_MS;
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
