#ifndef FASTP2P_GATEWAY_H
#define FASTP2P_GATEWAY_H
#include "protocol.h"
#include "store.h"
#include <libwebsockets.h>
#include <netinet/in.h>
#define GW_MAX_NODES 256
#define GW_MAX_PROBES 128
#define GW_HTTP_LIMIT (64u * 1024u)
#define GW_QUEUE_LIMIT (4u * 1024u * 1024u)
#define GW_TOTAL_QUEUED (64u * 1024u * 1024u)
struct packet {
    struct packet *next;
    size_t length, offset;
    unsigned char data[];
};
struct connection {
    struct lws *wsi;
    int slot, registered, closing;
    char node[32], ip[64], ipv6[128], os[128], mac[128], lan[64], version[64];
    uint64_t id, last_rx, relay_time, active_wall;
    uint64_t last_seen_wall, next_store;
    char hostname[256];
    unsigned nat, bandwidth, has_ipv4, has_upnp, public_port, major;
    struct packet *head, *tail;
    size_t queued, count;
    unsigned char *rx;
    size_t rx_length, rx_capacity;
    /* HTTP transactions share the protocol allocation, never the WS role. */
    char uri[256];
    int post, deleting, authorized, status, headers_sent, handled;
    uint64_t auth_generation;
    unsigned char *request, *response;
    const char *response_type;
    size_t request_length, response_length, response_offset;
    uint64_t deadline, relay_log_ms;
    struct connection *request_node, *pending_http;
};
struct probe {
    int fd;
    struct sockaddr_in peer;
    uint64_t deadline;
    char output[128];
    size_t length, offset;
};
struct nat_state {
    int udp[4], tcp[2];
    struct probe probes[GW_MAX_PROBES];
    uint64_t second;
    unsigned packets;
};
struct gateway {
    struct lws_context *context;
    struct lws_vhost *ws_vhost, *api_vhost;
    /* A second WSS listener, typically 443: mobile carriers reset TLS to
     * non-standard ports, so the same gateway is reachable on both. */
    struct lws_vhost *ws_alt_vhost;
    unsigned alt_ws_port;
    lws_sorted_usec_list_t tick;
    struct connection *nodes[GW_MAX_NODES];
    uint64_t grants[GW_MAX_NODES][GW_MAX_NODES];
    size_t queued, rx_allocated;
    unsigned max_nodes, timeout, ws_port, api_port, run_seconds;
    char bind[64], api_bind[64];
    const char *cert, *key, *user, *password;
    char secret[2048];
    struct gw_admin admin;
    uint64_t auth_generation;
    uint64_t token;
    int reset_admin;
    uint64_t started_ms;
    sqlite3 *db;
    const char *database;
    const char *public_host, *enrollment_ca_file;
    char enrollment_ca[16385];
    struct nat_state nat;
};
int gw_nat_start(struct nat_state *state, const char *bind);
void gw_nat_step(struct nat_state *state);
void gw_nat_stop(struct nat_state *state);
#endif
