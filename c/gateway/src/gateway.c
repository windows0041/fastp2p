#include "gateway.h"
#include "web_assets.h"
#include "enrollment.h"
#include "linux_installer.h"
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

static struct gateway g;
static volatile sig_atomic_t stopping;
static pid_t release_sync_pid;
static pid_t release_cleanup_pid;
static time_t release_cleanup_at;
static int start_release_worker(int cleanup_only);
static void upload_unlock(struct connection *c);
static int send_json(struct connection *,uint16_t,uint16_t,json_object *);
static int push_config(struct connection *node) {
    if(!node||!node->config_supported)return 0;
    json_object *config=gw_store_config(g.db,node->node);
    if(!config)return -1;
    int result=gw_integer(config,"revision")?send_json(node,3,19,config):0;
    json_object_put(config);return result;
}
static const char *release_sync_status = "idle";
static void signal_stop(int signal) {
    (void)signal;
    stopping = 1;
}
static void http_reply(struct connection *c, int status, const void *data, size_t len);
static void http_error(struct connection *c, int status, unsigned code, const char *detail);
static void upload_abort(struct connection *c);
static int query(struct lws *wsi, const char *name, char *out, size_t capacity);
static unsigned query_integer(struct lws *wsi, const char *name, unsigned limit, unsigned fallback);

static struct connection *find_node(uint64_t id) {
    for (unsigned i = 0; i < g.max_nodes; ++i)
        if (g.nodes[i] && g.nodes[i]->id == id && !g.nodes[i]->closing)
            return g.nodes[i];
    return NULL;
}
static void close_node(struct connection *c) {
    if (!c || c->closing)
        return;
    c->closing = 1;
    lws_set_timeout(c->wsi, PENDING_TIMEOUT_CLOSE_SEND, LWS_TO_KILL_ASYNC);
}
static void unregister_node(struct connection *c) {
    if (!c || !c->registered)
        return;
    if (c->slot >= 0 && c->slot < GW_MAX_NODES && g.nodes[c->slot] == c) {
        if (gw_store_save(g.db, c, 0))
            fputs("Cannot persist disconnected node\n", stderr);
        g.nodes[c->slot] = NULL;
        memset(g.grants[c->slot], 0, sizeof(g.grants[c->slot]));
        for (unsigned i = 0; i < g.max_nodes; ++i)
            g.grants[i][c->slot] = 0;
    }
    c->registered = 0;
    if (c->pending_http) {
        struct connection *http = c->pending_http;
        c->pending_http = NULL;
        http->request_node = NULL;
        http_error(http, 503, 1, "device disconnected");
    }
}
static int enqueue(struct connection *c, uint16_t main, uint16_t sub, const void *body,
                   size_t length) {
    if (!c || !c->registered || c->closing || length > GW_FRAME_LIMIT)
        return -1;
    size_t size = length + 8;
    if (c->count >= 64 || size > GW_QUEUE_LIMIT - c->queued) {
        /* This connection is the one falling behind, so it is the one to drop. */
        close_node(c);
        return -1;
    }
    if (size > GW_TOTAL_QUEUED - g.queued) {
        /* The budget is shared: closing a node here would let one sender knock
         * unrelated peers offline, so the frame is dropped instead. */
        return -1;
    }
    struct packet *p = malloc(sizeof(*p) + LWS_PRE + size);
    if (!p) {
        close_node(c);
        return -1;
    }
    *p = (struct packet){.length = size};
    unsigned char *data = p->data + LWS_PRE;
    gw_put32(data, (uint32_t)length);
    gw_put16(data + 4, main);
    gw_put16(data + 6, sub);
    if (length)
        memcpy(data + 8, body, length);
    if (c->tail)
        c->tail->next = p;
    else
        c->head = p;
    c->tail = p;
    ++c->count;
    c->queued += size;
    g.queued += size;
    lws_callback_on_writable(c->wsi);
    return 0;
}
static int send_json(struct connection *c, uint16_t main, uint16_t sub, json_object *j) {
    size_t length;
    char *text = gw_json_text(j, &length);
    if (!text)
        return -1;
    int result = enqueue(c, main, sub, text, length);
    free(text);
    return result;
}
static void send_push_result(struct connection *c, unsigned error, const char *detail) {
    json_object *j = json_object_new_object();
    gw_ju(j, "error", error);
    gw_js(j, "detail", detail);
    send_json(c, 3, 0, j);
    json_object_put(j);
}
static void grant(struct connection *from, struct connection *to) {
    uint64_t until = gw_mono_ms() + 60000;
    g.grants[from->slot][to->slot] = until;
    g.grants[to->slot][from->slot] = until;
}
static unsigned major_version(const char *text) {
    unsigned n = 0;
    for (int i = 0; i < 4 && text[i] >= '0' && text[i] <= '9'; ++i)
        n = n * 10 + (unsigned)(text[i] - '0');
    return n;
}
static void copy_field(char *out, size_t size, json_object *j, const char *name) {
    snprintf(out, size, "%s", gw_string(j, name));
}
static int nat_fields(struct connection *c, json_object *j) {
    const char *keys[] = {"udpNatType", "tcpNatType", "tcpNatSamples", "tcpNatDestinationIPs"};
    unsigned *values[] = {&c->nat, &c->tcp_nat, &c->tcp_nat_samples, &c->tcp_nat_ips};
    for (unsigned i = 0; i < 4; ++i) {
        json_object *v = gw_get(j, keys[i]);
        if (!v) continue;
        if (!json_object_is_type(v, json_type_int) || json_object_get_int64(v) < 0) return -1;
        uint64_t n = json_object_get_uint64(v);
        if ((i == 0 && n != 1 && n != 2 && n != 3 && n != 4 && n != 314) ||
            (i == 1 && n != 1 && n != 2 && n != 314) || (i >= 2 && n > 6)) return -1;
        *values[i] = (unsigned)n;
    }
    return c->tcp_nat_ips > c->tcp_nat_samples ? -1 : 0;
}
static int dispatch(struct connection *c, uint16_t main, uint16_t sub, const unsigned char *data,
                    size_t len) {
    if (main == 1) {
        unsigned char ts[8];
        gw_put64(ts, gw_wall_ns());
        return enqueue(c, 1, 0, ts, 8);
    }
    if (main == 3) {
        if (len < 16)
            return -1;
        uint64_t from = gw_u64(data), to = gw_u64(data + 8);
        if (from != c->id) {
            send_push_result(c, 1, "sender mismatch");
            return 0;
        }
        /* 1 connect request, 2 connect reply, 8 peer ready, 13 session key,
         * 14 session key ack.  Everything else is not a client-to-client push. */
        if (!(sub == 1 || sub == 2 || sub == 8 || sub == 13 || sub == 14)) {
            send_push_result(c, 1, "unsupported push");
            return 0;
        }
        struct connection *target = find_node(to);
        if (!target) {
            send_push_result(c, 1, "peer offline");
            return 0;
        }
        if (sub == 1) {
            /* A connect request may only claim the sender's own node name; the
             * gateway has already authenticated this connection, so no secret
             * needs to travel with the request. */
            json_object *request = gw_json(data + 16, len - 16);
            int valid = request && !strcmp(gw_string(request, "from"), c->node);
            if (request)
                json_object_put(request);
            if (!valid) {
                send_push_result(c, 1, "push denied");
                return 0;
            }
            grant(c, target);
        } else if (sub != 13 && sub != 14 && g.grants[c->slot][target->slot] <= gw_mono_ms()) {
            send_push_result(c, 1, "push denied");
            return 0;
        }
        int result = enqueue(target, 3, sub, data, len);
        send_push_result(c, result ? 1 : 0, result ? "peer backpressure" : "push accepted");
        return 0;
    }
    json_object *j = gw_json(data, len);
    if (!j || !json_object_is_type(j, json_type_object)) {
        if (j)
            json_object_put(j);
        return -1;
    }
    if (main == 0) {
        if (gw_integer(j, "error")) {
            json_object_put(j);
            return -1;
        }
    } else if (main == 6 && sub == 9) {
        if (nat_fields(c, j) || gw_store_save(g.db, c, 1)) {
            json_object_put(j); return -1;
        }
    } else if (main == 6 && sub == 0) {
        if (nat_fields(c, j)) { json_object_put(j); return -1; }
        copy_field(c->os, sizeof(c->os), j, "os");
        copy_field(c->mac, sizeof(c->mac), j, "mac");
        copy_field(c->lan, sizeof(c->lan), j, "lanIP");
        copy_field(c->ipv6, sizeof(c->ipv6), j, "IPv6");
        copy_field(c->version, sizeof(c->version), j, "version");
        copy_field(c->hostname, sizeof(c->hostname), j, "hostname");
        c->has_ipv4 = (unsigned)(gw_integer(j, "hasIPv4") != 0);
        c->has_upnp = (unsigned)(gw_integer(j, "hasUPNPorNATPMP") != 0);
        uint64_t port = gw_integer(j, "publicIPPort");
        if (port > 65535) {
            json_object_put(j);
            return -1;
        }
        c->public_port = (unsigned)port;
        c->config_supported = gw_integer(j,"configPush") != 0;
        c->major = major_version(c->version);
        if (gw_store_save(g.db, c, 1)) {
            json_object_put(j);
            return -1;
        }
        json_object *ack = json_object_new_object();
        send_json(c, 6, 7, ack);
        json_object_put(ack);
        /* Restore persisted rules on (re)connection, but only for nodes the
         * console has taken ownership of. A node that has never had a stored
         * rule keeps whatever its local config file defines. */
        if(c->config_supported) {
            if(gw_store_config_rules(g.db,c->node)||push_config(c)) {
                json_object_put(j);return -1;
            }
        }
        json_object *stored = !c->config_supported && gw_store_rule_managed(g.db, c->node)
                                  ? gw_store_rules(g.db, c->node) : NULL;
        if (stored) {
            json_object *sync = json_object_new_object(), *rules = json_object_new_array();
            for (size_t i = 0; i < json_object_array_length(stored); ++i) {
                json_object *entry = json_object_array_get_idx(stored, i);
                if (!gw_integer(entry, "enabled"))
                    continue;
                json_object *rule = gw_get(entry, "rule");
                if (rule) {
                    json_object_get(rule);
                    json_object_array_add(rules, rule);
                }
            }
            json_object_object_add(sync, "Rules", rules);
            send_json(c, 3, 16, sync); /* RULE_SYNC */
            json_object_put(sync);
            json_object_put(stored);
        }
        json_object *online = json_object_new_object();
        gw_js(online, "node", c->node);
        for (unsigned i = 0; i < g.max_nodes; ++i)
            if (g.nodes[i])
                send_json(g.nodes[i], 3, 15, online);
        json_object_put(online);
    } else if (main == 6 && sub == 8) {
        if(c->config_supported && gw_store_config_ack(g.db,c->node,gw_integer(j,"revision"),gw_string(j,"state"))) {
            json_object_put(j);return -1;
        }
    } else if (main == 6 && sub == 3 && c->pending_http) {
        struct connection *http = c->pending_http;
        c->pending_http = NULL;
        http->request_node = NULL;
        http_reply(http, 200, data, len);
    } else if (main == 7 && sub == 0) {
        json_object *response = json_object_new_object();
        const char *name = gw_string(j, "peerNode");
        struct connection *target = gw_node_valid(name) ? find_node(gw_node_id(name)) : NULL;
        if (target) {
            grant(c, target);
            gw_ju(response, "online", 1);
            gw_js(response, "peerNode", target->node);
            gw_js(response, "version", target->version);
            gw_js(response, "IPv4", target->ip);
            gw_js(response, "lanIP", target->lan);
            gw_ju(response, "natType", target->nat);
            gw_ju(response, "udpNatType", target->nat);
            gw_ju(response, "tcpNatType", target->tcp_nat);
            gw_ju(response, "hasIPv4", target->has_ipv4);
            gw_ju(response, "hasUPNPorNATPMP", target->has_upnp);
            gw_js(response, "IPv6", target->ipv6);
        } else
            gw_ju(response, "online", 0);
        send_json(c, 7, 1, response);
        json_object_put(response);
    } else if (main == 5 && sub == 0) {
        /* Relay offer.  Prefer a node that is neither endpoint, is not behind a
         * symmetric NAT, runs the same protocol major, and served a relay least
         * recently, so no single node carries every relayed session. */
        const char *name = gw_string(j, "peerNode");
        struct connection *peer = gw_node_valid(name) ? find_node(gw_node_id(name)) : NULL;
        int tcp_relay = !strcmp(gw_string(j, "underlayProtocol"), "tcp");
        json_object *exclude = gw_get(j, "exclude");
        struct connection *relay = NULL;
        /* Rank candidates by how likely they are to be reachable: a node on a
         * different public address than the peer does not need hairpin NAT, an
         * endpoint-independent mapping (nat 1) beats an unknown one, a larger
         * shared bandwidth beats a smaller one, and the least recently used
         * relay breaks ties so no single node carries every session. */
#define RELAY_RANK(n) \
    (((n)->ip[0] && peer && peer->ip[0] && !strcmp((n)->ip, peer->ip)) ? 0u : 1u)
        unsigned seen = 0, skip_self = 0, skip_peer = 0, skip_nat = 0, skip_major = 0,
                 skip_exclude = 0;
        for (unsigned i = 0; i < g.max_nodes; ++i) {
            struct connection *n = g.nodes[i];
            if (!n || n->closing)
                continue;
            ++seen;
            if (n->slot == c->slot) {
                ++skip_self;
                continue;
            }
            if (peer && n->slot == peer->slot) {
                ++skip_peer;
                continue;
            }
            /* nat 1 is endpoint-independent; 2, 3 and 4 are symmetric in
             * different flavours and cannot accept an unsolicited peer.
             * Unknown (314) stays eligible: it usually means probing failed. */
            unsigned candidate_nat = tcp_relay ? n->tcp_nat : n->nat;
            if (candidate_nat == 2 || candidate_nat == 3 || candidate_nat == 4) {
                ++skip_nat;
                continue;
            }
            if (n->major != c->major) {
                ++skip_major;
                continue;
            }
            /* A candidate that already failed for this rule is skipped so one
             * unreachable node cannot pin the link to a dead relay. */
            int rejected = 0;
            if (exclude && json_object_is_type(exclude, json_type_array))
                for (size_t k = 0; k < json_object_array_length(exclude); ++k) {
                    json_object *item = json_object_array_get_idx(exclude, k);
                    if (item && json_object_is_type(item, json_type_string) &&
                        !strcmp(n->node, json_object_get_string(item)))
                        rejected = 1;
                }
            if (rejected) {
                ++skip_exclude;
                continue;
            }
            if (!relay)
                relay = n;
            else {
                unsigned rank = RELAY_RANK(n), best = RELAY_RANK(relay);
                unsigned quality = (tcp_relay ? n->tcp_nat : n->nat) == 1 ? 1u : 0u;
                unsigned best_quality = (tcp_relay ? relay->tcp_nat : relay->nat) == 1 ? 1u : 0u;
                if (rank != best)
                    relay = rank > best ? n : relay;
                else if (quality != best_quality)
                    relay = quality > best_quality ? n : relay;
                else if (n->bandwidth != relay->bandwidth)
                    relay = n->bandwidth > relay->bandwidth ? n : relay;
                else if (n->relay_time < relay->relay_time)
                    relay = n;
            }
        }
        /* An empty offer is otherwise indistinguishable from a busy gateway, so
         * report the pool and the reason each node was passed over.  Repeated
         * failures are rate limited; a successful choice is always recorded. */
        uint64_t now_ms = gw_mono_ms();
        if (now_ms - c->relay_log_ms >= 5000) {
            printf("{\"event\":\"relay-select\",\"from\":\"%s\",\"peer\":\"%s\","
                   "\"connected\":%u,\"skipped\":{\"self\":%u,\"peer\":%u,\"symmetric\":%u,"
                   "\"major\":%u,\"excluded\":%u},\"relay\":\"%s\",\"relayNat\":%u,"
                   "\"relayBandwidth\":%u}\n",
                   c->node, peer ? peer->node : "", seen, skip_self, skip_peer, skip_nat, skip_major,
                   skip_exclude, relay ? relay->node : "", relay ? relay->nat : 0,
                   relay ? relay->bandwidth : 0);
            fflush(stdout);
            c->relay_log_ms = now_ms;
        }
        json_object *response = json_object_new_object();
        gw_js(response, "relay", relay ? relay->node : "");
        gw_ju(response, "error", relay ? 0 : 1);
        if (relay)
            relay->relay_time = gw_mono_ms();
        send_json(c, 5, 1, response);
        json_object_put(response);
    }
    json_object_put(j);
    return 0;
}
static int receive_ws(struct connection *c, const void *data, size_t len) {
    if (!lws_frame_is_binary(c->wsi) || c->rx_length > GW_FRAME_LIMIT + 8 ||
        len > GW_FRAME_LIMIT + 8 - c->rx_length)
        return -1;
    if (c->rx_length + len > c->rx_capacity) {
        size_t capacity = c->rx_capacity ? c->rx_capacity * 2 : 16384;
        if (capacity < c->rx_length + len)
            capacity = c->rx_length + len;
        if (capacity > GW_FRAME_LIMIT + 8)
            capacity = GW_FRAME_LIMIT + 8;
        if (capacity - c->rx_capacity > GW_TOTAL_QUEUED - g.rx_allocated)
            return -1;
        unsigned char *p = realloc(c->rx, capacity);
        if (!p)
            return -1;
        g.rx_allocated += capacity - c->rx_capacity;
        c->rx = p;
        c->rx_capacity = capacity;
    }
    if (len)
        memcpy(c->rx + c->rx_length, data, len);
    c->rx_length += len;
    c->last_rx = gw_mono_ms();
    c->active_wall = gw_wall_ns();
    if (!lws_is_final_fragment(c->wsi) || lws_remaining_packet_payload(c->wsi))
        return 0;
    size_t offset = 0;
    while (offset < c->rx_length) {
        if (c->rx_length - offset < 8)
            return -1;
        unsigned char *p = c->rx + offset;
        size_t length = gw_u32(p);
        uint16_t main = gw_u16(p + 4), sub = gw_u16(p + 6);
        if (length > GW_FRAME_LIMIT || length > c->rx_length - offset - 8 || main > 8 ||
            dispatch(c, main, sub, p + 8, length))
            return -1;
        offset += 8 + length;
    }
    c->rx_length = 0;
    return 0;
}
static int write_ws(struct connection *c) {
    if (c->closing)
        return -1;
    struct packet *p = c->head;
    if (!p)
        return 0;
    size_t length = p->length - p->offset;
    if (length > 16384)
        length = 16384;
    enum lws_write_protocol flags = p->offset ? LWS_WRITE_CONTINUATION : LWS_WRITE_BINARY;
    if (p->offset + length < p->length)
        flags = (enum lws_write_protocol)(flags | LWS_WRITE_NO_FIN);
    int n = lws_write(c->wsi, p->data + LWS_PRE + p->offset, length, flags);
    if (n < (int)length)
        return -1;
    p->offset += length;
    if (p->offset == p->length) {
        c->head = p->next;
        if (!c->head)
            c->tail = NULL;
        c->queued -= p->length;
        g.queued -= p->length;
        --c->count;
        free(p);
    }
    if (c->head)
        lws_callback_on_writable(c->wsi);
    return 0;
}
static void clear_http(struct connection *c) {
    /* TLS rejection and pre-upgrade failures can close before user allocation. */
    if (!c)
        return;
    if (c->request_node && c->request_node->pending_http == c)
        c->request_node->pending_http = NULL;
    c->request_node = NULL;
    free(c->request);
    if (c->response)
        g.queued -= c->response_length;
    free(c->response);
    c->request = c->response = NULL;
    c->request_length = c->response_length = c->response_offset = 0;
    c->headers_sent = c->handled = 0;
    c->response_type = NULL;
    c->deadline = 0;
    c->put = 0;
    if (c->upload || c->upload_digest || *c->upload_tmp)
        upload_abort(c);
}
static void http_reply(struct connection *c, int status, const void *data, size_t len) {
    upload_unlock(c);
    if (c->handled || len > GW_FRAME_LIMIT)
        return;
    if (len > GW_TOTAL_QUEUED - g.queued) {
        lws_set_timeout(c->wsi, PENDING_TIMEOUT_CLOSE_SEND, LWS_TO_KILL_ASYNC);
        return;
    }
    c->response = malloc(LWS_PRE + len + 1);
    if (!c->response) {
        lws_set_timeout(c->wsi, PENDING_TIMEOUT_CLOSE_SEND, LWS_TO_KILL_ASYNC);
        return;
    }
    if (len)
        memcpy(c->response + LWS_PRE, data, len);
    c->status = status;
    c->response_length = len;
    g.queued += len;
    c->handled = 1;
    lws_callback_on_writable(c->wsi);
}
static void http_json(struct connection *c, int status, json_object *j) {
    const char *text = json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN);
    http_reply(c, status, text, strlen(text));
}
static void http_error(struct connection *c, int status, unsigned code, const char *detail) {
    json_object *j = json_object_new_object();
    gw_ju(j, "error", code);
    gw_js(j, "detail", detail);
    http_json(c, status, j);
    json_object_put(j);
}
static void capabilities(json_object *node) {
    /* Rules live in the gateway database, so listing, adding, editing, toggling
     * and deleting work whether or not the node is online. Changes are applied
     * immediately when connected, and on the next connection otherwise. */
    json_object *caps = json_object_new_object();
    json_object_object_add(caps, "readApps", json_object_new_boolean(1));
    json_object_object_add(caps, "addForward", json_object_new_boolean(1));
    json_object_object_add(caps, "editForward", json_object_new_boolean(1));
    json_object_object_add(caps, "switchForward", json_object_new_boolean(1));
    struct connection *live=find_node(gw_node_id(gw_string(node,"name")));
    json_object_object_add(caps,"configPush",json_object_new_boolean(live&&live->config_supported));
    json_object_object_add(node, "capabilities", caps);
}
static json_object *devices(void) {
    json_object *root = json_object_new_object(), *nodes = json_object_new_array();
    json_object_object_add(root, "nodes", nodes);
    for (unsigned i = 0; i < g.max_nodes; ++i) {
        struct connection *n = g.nodes[i];
        if (!n || n->closing)
            continue;
        json_object *j = json_object_new_object();
        char number[32], date[64];
        snprintf(number, sizeof(number), "%" PRIu64, n->id);
        gw_js(j, "id", number);
        gw_js(j, "name", n->node);
        gw_js(j, "ip", n->ip);
        gw_js(j, "ipv6", n->ipv6);
        snprintf(number, sizeof(number), "%u", n->nat);
        gw_js(j, "natType", number);
        gw_ju(j, "udpNatType", n->nat);
        gw_ju(j, "tcpNatType", n->tcp_nat);
        gw_ju(j, "tcpNatSamples", n->tcp_nat_samples);
        gw_ju(j, "tcpNatDestinationIPs", n->tcp_nat_ips);
        snprintf(number, sizeof(number), "%u", n->bandwidth);
        gw_js(j, "bandwidth", number);
        gw_js(j, "lanip", n->lan);
        gw_js(j, "mac", n->mac);
        gw_js(j, "os", n->os);
        gw_js(j, "version", n->version);
        gw_ju(j, "isActive", 1);
        gw_js(j, "hostname", n->hostname);
        capabilities(j);
        json_object_object_add(j, "isUpdate", json_object_new_boolean(1));
        time_t timestamp = (time_t)(n->active_wall / 1000000000);
        struct tm utc;
        gmtime_r(&timestamp, &utc);
        strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%SZ", &utc);
        gw_js(j, "activetime", date);
        json_object_array_add(nodes, j);
    }
    return root;
}
/* Per-source-IP budget for the login endpoint. Returns non-zero when the request
 * must be rejected before the expensive password hash runs. The table is small
 * and bounded: a busy public gateway cannot be made to allocate without limit. */
static struct login_attempt *login_slot(uint32_t address) {
    /* Mix the address so sequential sources do not all land in one slot. */
    uint32_t hash = address ^ (address >> 16) ^ (address >> 8);
    unsigned index = hash % GW_LOGIN_SLOTS;
    for (unsigned i = 0; i < GW_LOGIN_SLOTS; ++i) {
        struct login_attempt *entry = &g.logins[(index + i) % GW_LOGIN_SLOTS];
        if (entry->address == address || !entry->address)
            return entry;
    }
    /* All slots are taken: evict the oldest window. */
    struct login_attempt *oldest = &g.logins[index];
    for (unsigned i = 1; i < GW_LOGIN_SLOTS; ++i)
        if (g.logins[i].window_start < oldest->window_start)
            oldest = &g.logins[i];
    return oldest;
}
static int login_limited(struct connection *c, uint32_t *out_address) {
    struct sockaddr_in peer;
    socklen_t length = sizeof(peer);
    if (getpeername(lws_get_socket_fd(c->wsi), (struct sockaddr *)&peer, &length) ||
        peer.sin_family != AF_INET)
        return 0; /* no usable address: fall through to credentials as before */
    *out_address = peer.sin_addr.s_addr;
    uint64_t now = gw_mono_ms();
    struct login_attempt *entry = login_slot(peer.sin_addr.s_addr);
    if (entry->address != peer.sin_addr.s_addr) {
        memset(entry, 0, sizeof(*entry));
        entry->address = peer.sin_addr.s_addr;
    }
    if (entry->locked_until && now < entry->locked_until)
        return 1;
    if (entry->locked_until) { /* lock expired: start clean */
        entry->locked_until = 0;
        entry->attempts = entry->failures = 0;
    }
    if (now - entry->window_start >= GW_LOGIN_WINDOW_MS) {
        entry->window_start = now;
        entry->attempts = 0;
    }
    if (entry->attempts >= GW_LOGIN_MAX_ATTEMPTS)
        return 1;
    ++entry->attempts;
    return 0;
}
static void login_result(uint32_t address, int success) {
    if (!address)
        return;
    struct login_attempt *entry = login_slot(address);
    if (entry->address != address)
        return;
    if (success) {
        memset(entry, 0, sizeof(*entry));
        return;
    }
    if (++entry->failures >= GW_LOGIN_FAIL_LOCK)
        entry->locked_until = gw_mono_ms() + GW_LOGIN_LOCK_MS;
}

/* --- Client upgrade packages ---------------------------------------------
 * Binaries are hosted by the gateway so a node never has to reach the public
 * internet to update. Metadata lives in SQLite; files are content addressed. */
static void update_path(char *out, size_t length, const char *filename) {
    snprintf(out, length, "%s/%s", g.update_dir, filename);
}
static int update_dir_ready(void) {
    return mkdir(g.update_dir, 0700) == 0 || errno == EEXIST ? 0 : -1;
}
static void update_hex(const unsigned char *digest, unsigned length, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < length; ++i) {
        out[i * 2] = digits[digest[i] >> 4];
        out[i * 2 + 1] = digits[digest[i] & 15];
    }
    out[length * 2] = 0;
}
static void upload_abort(struct connection *c) {
    upload_unlock(c);
    if (c->upload)
        fclose(c->upload);
    if (c->upload_digest)
        EVP_MD_CTX_free((EVP_MD_CTX *)c->upload_digest);
    if (*c->upload_tmp)
        unlink(c->upload_tmp);
    c->upload = NULL;
    c->upload_digest = NULL;
    c->upload_size = 0;
    c->upload_tmp[0] = 0;
}
static void upload_unlock(struct connection *c) {
    if (c->upload_cache_lock) {
        close(c->upload_cache_lock-1);
        c->upload_cache_lock=0;
    }
}
static int upload_lock(struct connection *c) {
    char path[700];snprintf(path,sizeof(path),"%s/.release.lock",g.update_dir);
    int descriptor=open(path,O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);
    if(descriptor<0) return -1;
    if(flock(descriptor,LOCK_EX|LOCK_NB)) { close(descriptor);return -1; }
    c->upload_cache_lock=descriptor+1;return 0;
}
static int package_format_matches(FILE *file, const char *platform) {
    unsigned char magic[4];
    if (fseek(file, 0, SEEK_SET) || fread(magic, 1, sizeof(magic), file) != sizeof(magic))
        return 0;
    if (!strcmp(platform, "windows"))
        return magic[0] == 'M' && magic[1] == 'Z';
    if (!strcmp(platform, "linux"))
        return !memcmp(magic, "\177ELF", 4);
    if (!strcmp(platform, "android"))
        return !memcmp(magic, "PK\003\004", 4);
    /* Mach-O (32/64-bit) and universal binaries, in either byte order. */
    uint32_t value = ((uint32_t)magic[0] << 24) | ((uint32_t)magic[1] << 16) |
                     ((uint32_t)magic[2] << 8) | magic[3];
    return value == 0xfeedface || value == 0xcefaedfe || value == 0xfeedfacf ||
           value == 0xcffaedfe || value == 0xcafebabe || value == 0xbebafeca ||
           value == 0xcafebabf || value == 0xbfbafeca;
}
/* Compares dotted numeric versions; returns <0, 0 or >0. */
static int version_compare(const char *left, const char *right) {
    for (;;) {
        unsigned long a = 0, b = 0;
        while (*left >= '0' && *left <= '9')
            a = a * 10 + (unsigned long)(*left++ - '0');
        while (*right >= '0' && *right <= '9')
            b = b * 10 + (unsigned long)(*right++ - '0');
        if (a != b)
            return a < b ? -1 : 1;
        if (!*left && !*right)
            return 0;
        if (*left && *left != '.')
            return -1;
        if (*right && *right != '.')
            return 1;
        if (*left == '.')
            ++left;
        if (*right == '.')
            ++right;
        if (!*left && !*right)
            return 0;
    }
}

/* A single downloader selects the newest available package for each CPU.
 * Old generic manual packages are classified from their ELF header, never run. */
static int linux_installer_packages(const char *wanted,struct gw_linux_package out[GW_LINUX_ARCH_COUNT],size_t *count) {
    struct gw_linux_package selected[GW_LINUX_ARCH_COUNT]={0};
    json_object *list=gw_store_updates(g.db);
    if(!list)return -1;
    for(size_t i=0;i<json_object_array_length(list);i++){
        json_object *row=json_object_array_get_idx(list,i);
        const char *platform=gw_string(row,"platform"),*version=gw_string(row,"version");
        if(strcmp(platform,"linux") && strncmp(platform,"linux-",6))continue;
        if((*wanted && strcmp(wanted,version)) || !gw_store_package_key_valid(platform,version))continue;
        const char *arch=platform+6;char sha[65],filename[260];uint64_t size=0;
        if(gw_store_update_find(g.db,platform,version,sha,filename,&size))continue;
        if(!strcmp(platform,"linux")){
            char path[700];update_path(path,sizeof(path),filename);
            arch=gw_linux_payload_arch(path);
            if(!arch)continue;
        }
        for(size_t k=0;k<GW_LINUX_ARCH_COUNT;k++){
            if(strcmp(arch,gw_linux_arches[k]))continue;
            struct gw_linux_package *p=selected+k;
            int comparison=version_compare(version,p->version);
            if(p->arch && (comparison<0 || (!comparison && strcmp(p->platform,"linux"))))break;
            p->arch=gw_linux_arches[k];p->size=size;
            snprintf(p->platform,sizeof(p->platform),"%s",platform);
            snprintf(p->version,sizeof(p->version),"%s",version);
            snprintf(p->sha,sizeof(p->sha),"%s",sha);
            break;
        }
    }
    json_object_put(list);*count=0;
    for(size_t k=0;k<GW_LINUX_ARCH_COUNT;k++)if(selected[k].arch){
        if(gw_store_package_lease(g.db,selected[k].platform,selected[k].version,(uint64_t)time(NULL)+600))return -1;
        out[(*count)++]=selected[k];
    }
    return 0;
}

/* Maps the OS string a client reports onto an update platform name. */
static const char *platform_for_os(const char *os) {
    size_t length = os ? strlen(os) : 0;
    if (length < 2 || strcmp(os + length - 2, "-c"))
        return NULL;
    if (!strncmp(os, "windows", 7))
        return "windows";
    if (!strncmp(os, "linux", 5))
        return "linux";
    if (!strncmp(os, "android", 7))
        return "android";
    if (!strncmp(os, "darwin", 6))
        return "macos";
    return NULL;
}
static const char *package_platform(const char *os, const char *base, char variant[16]) {
    if (!base || (strcmp(base, "linux") && strcmp(base, "macos")))
        return base;
    size_t length = strlen(os);
    const char *prefix = !strcmp(base, "linux") ? "linux-" : "darwin-";
    size_t prefix_length = strlen(prefix);
    if (length > prefix_length + 2 && !strncmp(os, prefix, prefix_length)) {
        int arch = (int)(length - prefix_length - 2);
        if (snprintf(variant, 16, "%s-%.*s", base, arch, os + prefix_length) < 16 &&
            gw_store_package_key_valid(variant, "1"))
            return variant;
    }
    return base;
}

static const char *find_node_package(struct connection *node, const char *version,
                                     char sha[65], char filename[260], uint64_t *size,
                                     char variant[16]) {
    const char *base = platform_for_os(node->os);
    const char *platform = package_platform(node->os, base, variant);
    if (platform && !gw_store_update_find(g.db, platform, version, sha, filename, size))
        return platform;
    if (base && platform != base && !gw_store_update_find(g.db, base, version, sha, filename, size))
        return base;
    return NULL;
}
/* Sends one upgrade order to a connected node. Returns 0 when it was queued. */
static int push_update(struct connection *node, const char *version) {
    char sha[65], filename[260], variant[16];
    uint64_t size = 0;
    const char *platform = find_node_package(node, version, sha, filename, &size, variant);
    if (!platform)
        return 1;
    if (gw_store_package_lease(g.db,platform,version,(uint64_t)time(NULL)+600))
        return 1;
    json_object *j = json_object_new_object();
    gw_js(j, "version", version);
    gw_js(j, "sha256", sha);
    gw_ju(j, "size", size);
    gw_js(j, "platform", platform);
    char url[640];
    unsigned port = lws_get_vhost(node->wsi) == g.ws_alt_vhost ? g.alt_ws_port : g.ws_port;
    snprintf(url, sizeof(url),
             "https://%s:%u/api/v1/update/download?platform=%s&version=%s&token=%" PRIu64,
             g.public_host, port, platform, version, g.token);
    gw_js(j, "url", url);
    int rv = send_json(node, 3, 18, j);
    json_object_put(j);
    return rv ? 1 : 0;
}

static void poll_release_sync(void) {
    int status;
    time_t now=time(NULL);
    if (release_sync_pid) {
        pid_t result=waitpid(release_sync_pid,&status,WNOHANG);
        if (result==release_sync_pid || (result<0 && errno==ECHILD)) {
            release_sync_pid=0;
            release_sync_status=result>0 && WIFEXITED(status) && !WEXITSTATUS(status)?"complete":"failed";
            release_cleanup_at=now+60;
        }
    }
    if (release_cleanup_pid) {
        pid_t result=waitpid(release_cleanup_pid,&status,WNOHANG);
        if(result==release_cleanup_pid || (result<0 && errno==ECHILD)) release_cleanup_pid=0;
    }
    if (!release_cleanup_at) release_cleanup_at=now+60;
    if (!release_sync_pid && !release_cleanup_pid && now>=release_cleanup_at) {
        release_cleanup_at=now+60;
        char version[32];gw_store_release_version(g.db,version);
        if(*version) (void)start_release_worker(1);
    }
}

static int start_release_worker(int cleanup_only) {
    char worker[4096];
    ssize_t size = readlink("/proc/self/exe", worker, sizeof(worker) - 1);
    if (size <= 0 || (size_t)size >= sizeof(worker) - 1)
        return -1;
    worker[size] = 0;
    char *name = strrchr(worker, '/');
    const char script[] = "/fastp2p-sync-releases.py";
    if (!name || (size_t)(name - worker) + sizeof(script) > sizeof(worker))
        return -1;
    strcpy(name, script);
    if (access(worker, R_OK) || access("/usr/bin/python3", X_OK))
        return -1;
    const char *repository = getenv("FASTP2P_RELEASE_REPOSITORY");
    if (!repository || !*repository)
        repository = "windows0041/fastp2p";
    long limit = sysconf(_SC_OPEN_MAX);
    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (!child) {
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) || getppid() != parent)
            _exit(1);
        for (int fd = 3; fd < limit; ++fd)
            close(fd);
        if(cleanup_only)
            execl("/usr/bin/python3","python3",worker,"--database",g.database,"--cleanup-only",(char *)NULL);
        else
            execl("/usr/bin/python3", "python3", worker, "--database", g.database,
                  "--repository", repository, (char *)NULL);
        _exit(127);
    }
    if(cleanup_only) release_cleanup_pid=child;
    else { release_sync_pid=child;release_sync_status="running"; }
    return 0;
}

static void handle_http(struct connection *c) {
    if (c->handled || c->request_node)
        return;
    int download = !c->post && !c->put && !c->deleting &&
                   !strcmp(c->uri, "/api/v1/update/download");
    if (!download && lws_get_vhost(c->wsi) != g.api_vhost) {
        http_error(c, 404, 1, "not found");
        return;
    }
    if (!c->put && !c->deleting && !strcmp(c->uri, "/api/v1/releases/sync")) {
        if (!c->authorized || c->auth_generation != g.auth_generation) {
            http_error(c, 401, 1, "unauthorized");
            return;
        }
        poll_release_sync();
        if (c->post && !release_sync_pid && start_release_worker(0)) {
            http_error(c, 503, 1, "release sync requires the installed sync script and Python 3");
            return;
        }
        char version[32];
        gw_store_release_version(g.db, version);
        json_object *reply = json_object_new_object();
        gw_js(reply, "status", release_sync_status);
        gw_js(reply, "version", version);
        http_json(c, c->post ? 202 : 200, reply);
        json_object_put(reply);
        return;
    }
    if (!c->post) {
        for (size_t i = 0; i < sizeof(web_assets) / sizeof(web_assets[0]); ++i) {
            const struct web_asset *asset = &web_assets[i];
            if (!strcmp(c->uri, asset->path) || (i == 0 && !strcmp(c->uri, "/index.html"))) {
                c->response_type = asset->type;
                http_reply(c, 200, asset->data, asset->length);
                return;
            }
        }
    }
    if (c->put && !strcmp(c->uri, "/api/v1/update")) {
        /* Finalise the streamed upload begun in LWS_CALLBACK_HTTP. */
        if (!c->upload) {
            http_error(c, 400, 1, "no upload in progress");
            return;
        }
        if (c->auth_generation != g.auth_generation) {
            upload_abort(c);
            http_error(c, 401, 1, "unauthorized");
            return;
        }
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned digest_length = 0;
        if (fflush(c->upload) ||
            EVP_DigestFinal_ex((EVP_MD_CTX *)c->upload_digest, digest, &digest_length) != 1) {
            upload_abort(c);
            http_error(c, 500, 1, "cannot finalise upload");
            return;
        }
        if (!package_format_matches(c->upload, c->upload_platform)) {
            upload_abort(c);
            http_error(c, 400, 1, "package does not match the selected platform");
            return;
        }
        if (upload_lock(c)) {
            upload_abort(c);
            http_error(c,409,1,"package publication is busy; retry shortly");
            return;
        }
        int close_error = fclose(c->upload);
        c->upload = NULL;
        if (close_error) {
            upload_abort(c);
            http_error(c, 500, 1, "cannot close staged upload");
            return;
        }
        EVP_MD_CTX_free((EVP_MD_CTX *)c->upload_digest);
        c->upload_digest = NULL;
        char sha[65];
        update_hex(digest, digest_length, sha);
        char filename[160], final_path[700], staged[640];
        snprintf(filename, sizeof(filename), "%s-%s-%s", c->upload_platform, c->upload_version, sha);
        update_path(final_path, sizeof(final_path), filename);
        snprintf(staged, sizeof(staged), "%s", c->upload_tmp);
        c->upload_tmp[0] = 0;
        /* Re-uploading the same version with different content leaves the old
         * file behind unless it is removed after the row is replaced. */
        char previous_file[260] = "", previous_sha[65];
        uint64_t previous_size = 0;
        int had_previous =
            gw_store_update_find(g.db, c->upload_platform, c->upload_version,
                                 previous_sha, previous_file, &previous_size) == 0;
        if (rename(staged, final_path)) {
            unlink(staged);
            http_error(c, 503, 1, "cannot store package");
            return;
        }
        if (gw_store_update_put(g.db, c->upload_platform, c->upload_version, sha,
                                c->upload_size, filename)) {
            if (!had_previous || strcmp(previous_file, filename))
                unlink(final_path);
            http_error(c, 503, 1, "cannot record package");
            return;
        }
        if (had_previous && *previous_file && strncmp(previous_file, "github-", 7) &&
            strcmp(previous_file, filename)) {
            char previous_path[700];
            update_path(previous_path, sizeof(previous_path), previous_file);
            unlink(previous_path);
        }
        json_object *j = json_object_new_object();
        gw_js(j, "platform", c->upload_platform);
        gw_js(j, "version", c->upload_version);
        gw_js(j, "sha256", sha);
        gw_ju(j, "size", c->upload_size);
        gw_ju(j, "error", 0);
        http_json(c, 200, j);
        json_object_put(j);
        return;
    }
    if (!c->post && !c->put && !strcmp(c->uri, "/api/v1/updates")) {
        if (!c->authorized || c->auth_generation != g.auth_generation) {
            http_error(c, 401, 1, "unauthorized");
            return;
        }
        json_object *list = gw_store_updates(g.db);
        if (!list) {
            http_error(c, 503, 1, "update storage unavailable");
            return;
        }
        json_object *root = json_object_new_object();
        json_object_object_add(root, "updates", list);
        http_json(c, 200, root);
        json_object_put(root);
        return;
    }
    int installer = !c->post && !c->put && !c->deleting && !strcmp(c->uri, "/api/v1/update/install");
    if (download || installer) {
        /* The client presents the shared install token, the same secret it uses
         * to authenticate the WebSocket, so no extra credential is introduced. */
        char platform[16], version[32]="", token[32], auth[128];
        if (query(c->wsi, "platform=", platform, sizeof(platform))) {
            http_error(c, 400, 1, "platform is required");
            return;
        }
        int has_version=!query(c->wsi,"version=",version,sizeof(version));
        int is_linux=!strcmp(platform,"linux") || !strncmp(platform,"linux-",6);
        uint64_t supplied = 0;
        int header=lws_hdr_copy(c->wsi,auth,sizeof(auth),WSI_TOKEN_HTTP_AUTHORIZATION);
        int install_auth=header>8 && !strncmp(auth,"FastP2P ",8) && fastp2p_install_key_valid(auth+8) &&
                         !gw_decimal(auth+8,&supplied) && supplied==g.token;
        if (installer ? (!c->authorized || c->auth_generation != g.auth_generation) :
            (!install_auth && (query(c->wsi, "token=", token, sizeof(token)) || gw_decimal(token, &supplied) ||
             supplied != g.token))) {
            http_error(c, 401, 1, "unauthorized");
            return;
        }
        if(installer && is_linux){
            if(!gw_store_package_key_valid(platform,has_version?version:"1")){
                http_error(c,400,1,"invalid platform or version");return;
            }
            struct gw_linux_package packages[GW_LINUX_ARCH_COUNT];size_t count=0;
            if(linux_installer_packages(has_version?version:"",packages,&count)){
                http_error(c,503,1,"cannot prepare package manifest; retry after synchronization");return;
            }
            if(!count){http_error(c,404,1,"no supported Linux packages found");return;}
            char generated[700],headers[256];
            if(gw_linux_installer(g.update_dir,g.public_host,g.ws_port,g.enrollment_ca,packages,count,generated)){
                http_error(c,503,1,"cannot prepare Linux installer; retry after synchronization");return;
            }
            snprintf(headers,sizeof(headers),"Content-Disposition: attachment; filename=\"fastp2p-%" PRIu64 "\"\r\nCache-Control: no-store\r\n",g.token);
            if(lws_serve_http_file(c->wsi,generated,"application/octet-stream",headers,(int)strlen(headers))<0)
                http_error(c,503,1,"cannot serve Linux installer");
            return;
        }
        if(!has_version){http_error(c,400,1,"version is required");return;}
        char sha[65], filename[260], path[700];
        uint64_t size = 0;
        if (gw_store_update_find(g.db, platform, version, sha, filename, &size)) {
            http_error(c, 404, 1, "package not found");
            return;
        }
        if (gw_store_package_lease(g.db,platform,version,(uint64_t)time(NULL)+600)) {
            http_error(c,503,1,"package changed during cleanup; retry the download");
            return;
        }
        update_path(path, sizeof(path), filename);
        char headers[256] = "";
        if (installer) {
            const char *extension = !strcmp(platform, "windows") ? ".exe" :
                                    !strcmp(platform, "android") ? ".apk" : "";
            snprintf(headers, sizeof(headers),
                     "Content-Disposition: attachment; filename=\"fastp2p-%s-v%s-%" PRIu64 "%s\"\r\n"
                     "Cache-Control: no-store\r\n", platform, version, g.token, extension);
        }
        if (lws_serve_http_file(c->wsi, path, "application/octet-stream", headers, (int)strlen(headers)) < 0) {
            http_error(c, 503, 1, "cannot serve package");
            return;
        }
        return;
    }
    if (c->post && !strcmp(c->uri, "/api/v1/upgrades")) {
        /* Batch upgrade: every connected node whose version is behind the newest
         * package for its platform, or an explicit target version. */
        if (!c->authorized || c->auth_generation != g.auth_generation) {
            http_error(c, 401, 1, "unauthorized");
            return;
        }
        json_object *body = gw_json(c->request, c->request_length);
        char wanted[32];
        wanted[0] = 0;
        if (body && json_object_is_type(body, json_type_object))
            snprintf(wanted, sizeof(wanted), "%s", gw_string(body, "version"));
        if (body)
            json_object_put(body);
        json_object *available = gw_store_updates(g.db);
        if (!available) {
            http_error(c, 503, 1, "update storage unavailable");
            return;
        }
        json_object *queued = json_object_new_array();
        json_object *skipped = json_object_new_array();
        for (unsigned i = 0; i < g.max_nodes; ++i) {
            struct connection *node = g.nodes[i];
            if (!node)
                continue;
            const char *platform = platform_for_os(node->os);
            if (!platform)
                continue;
            char variant[16];
            const char *architecture = package_platform(node->os, platform, variant);
            const char *target_version = *wanted ? wanted : NULL;
            if (!target_version)
                for (size_t k = 0; k < json_object_array_length(available); ++k) {
                    json_object *row = json_object_array_get_idx(available, k);
                    const char *candidate = gw_string(row, "platform"), *version = gw_string(row, "version");
                    /* Old Linux/macOS clients report no architecture. Include
                     * the family only to explain why they need a manual first
                     * upgrade; never select an arbitrary architecture's file. */
                    int unknown_arch = architecture == platform &&
                        (!strcmp(platform, "linux") || !strcmp(platform, "macos"));
                    if ((!strcmp(platform, candidate) || !strcmp(architecture, candidate) ||
                         (unknown_arch && !strncmp(candidate, platform, strlen(platform)) &&
                          candidate[strlen(platform)] == '-')) &&
                        (!target_version || version_compare(version, target_version) > 0))
                        target_version = version;
                }
            if (!target_version || version_compare(node->version, target_version) >= 0)
                continue;
            char sha[65], filename[260], package_variant[16];
            uint64_t size = 0;
            const char *reason = NULL;
            if (!find_node_package(node, target_version, sha, filename, &size, package_variant))
                reason = architecture == platform && (!strcmp(platform, "linux") || !strcmp(platform, "macos"))
                    ? "architecture_not_reported" : "package_unavailable";
            else if (push_update(node, target_version))
                reason = "dispatch_failed";
            json_object *item = json_object_new_object();
            gw_js(item, "node", node->node);
            gw_js(item, "from", node->version);
            gw_js(item, "to", target_version);
            if (reason) {
                gw_js(item, "reason", reason);
                json_object_array_add(skipped, item);
            } else {
                json_object_array_add(queued, item);
            }
        }
        json_object_put(available);
        json_object *root = json_object_new_object();
        gw_ju(root, "error", 0);
        json_object_object_add(root, "queued", queued);
        json_object_object_add(root, "skipped", skipped);
        http_json(c, 200, root);
        json_object_put(root);
        return;
    }
    if (!c->post && !strcmp(c->uri, "/healthz")) {
        http_reply(c, 200,
                   "{\"status\":\"ok\",\"implementation\":\"c\",\"version\":\"" GW_VERSION "\"}",
                   strlen("{\"status\":\"ok\",\"implementation\":\"c\",\"version\":"
                          "\"" GW_VERSION "\"}"));
        return;
    }
    if (c->post && !strcmp(c->uri, "/api/v1/user/login")) {
        /* Reject before the expensive PBKDF2 verification when this source has
         * used up its budget or is serving a lockout. */
        uint32_t address = 0;
        if (login_limited(c, &address)) {
            http_error(c, 429, 9, "too many login attempts");
            return;
        }
        json_object *j = gw_json(c->request, c->request_length);
        if (!j || !json_object_is_type(j, json_type_object)) {
            if (j)
                json_object_put(j);
            login_result(address, 0);
            http_error(c, 400, 1, "invalid JSON");
            return;
        }
        int valid = gw_secret_equal(gw_string(j, "user"), g.user) &&
                    gw_admin_verify(&g.admin, gw_string(j, "password"));
        if (j)
            json_object_put(j);
        login_result(address, valid);
        if (!valid) {
            http_error(c, 401, 1, "invalid credentials");
            return;
        }
        char *jwt = gw_jwt_issue(g.user, g.token, g.secret, gw_wall_ns() / 1000000000);
        if (!jwt) {
            http_error(c, 500, 1, "internal error");
            return;
        }
        j = json_object_new_object();
        char number[32];
        snprintf(number, sizeof(number), "%" PRIu64, g.token);
        gw_js(j, "token", jwt);
        gw_js(j, "installToken", number);
        json_object *preset = json_object_new_object();
        gw_js(preset, "host", g.public_host); gw_ju(preset, "port", g.ws_port);
        gw_js(preset, "ca", g.enrollment_ca); json_object_object_add(j, "gateway", preset);
        gw_ju(j, "error", 0);
        http_json(c, 200, j);
        json_object_put(j);
        free(jwt);
        return;
    }
    if (!c->authorized || c->auth_generation != g.auth_generation) {
        http_error(c, 401, 1, "unauthorized");
        return;
    }
    if (c->post && !strcmp(c->uri, "/api/v1/user/account")) {
        json_object *j = gw_json(c->request, c->request_length);
        if (!j || !json_object_is_type(j, json_type_object)) {
            if (j) json_object_put(j);
            http_error(c, 400, 1, "invalid JSON"); return;
        }
        if (!json_object_is_type(gw_get(j, "user"), json_type_string) ||
            !json_object_is_type(gw_get(j, "currentPassword"), json_type_string) ||
            !json_object_is_type(gw_get(j, "newPassword"), json_type_string)) {
            json_object_put(j); http_error(c, 400, 1, "invalid account settings"); return;
        }
        const char *user = gw_string(j, "user"), *password = gw_string(j, "newPassword");
        if (strlen(user) != (size_t)json_object_get_string_len(gw_get(j, "user")) ||
            strlen(password) != (size_t)json_object_get_string_len(gw_get(j, "newPassword")) ||
            strlen(gw_string(j, "currentPassword")) != (size_t)json_object_get_string_len(gw_get(j, "currentPassword"))) {
            json_object_put(j); http_error(c, 400, 1, "invalid account settings"); return;
        }
        struct gw_admin next;
        if (!gw_admin_verify(&g.admin, gw_string(j, "currentPassword"))) {
            json_object_put(j); http_error(c, 403, 1, "current password incorrect"); return;
        }
        if (strlen(password) < 8 || gw_admin_make(&next, user, password)) {
            json_object_put(j); http_error(c, 400, 1, "invalid account settings"); return;
        }
        json_object_put(j);
        if (gw_store_admin_write(g.db, &next)) {
            OPENSSL_cleanse(&next, sizeof(next));
            http_error(c, 503, 1, "account storage unavailable"); return;
        }
        g.admin = next; OPENSSL_cleanse(&next, sizeof(next));
        g.user = g.admin.user;
        snprintf(g.secret, sizeof(g.secret), "%s", g.admin.secret);
        ++g.auth_generation;
        http_error(c, 200, 0, "account updated; sign in again"); return;
    }
    if (c->deleting) {
        const char *prefix = "/api/v1/nodes/";
        const char *name = c->uri + strlen(prefix);
        if (strncmp(c->uri, prefix, strlen(prefix)) || !gw_node_valid(name)) {
            http_error(c, 404, 1, "not found"); return;
        }
        if (find_node(gw_node_id(name))) {
            http_error(c, 409, 1, "node is online"); return;
        }
        int result = gw_store_delete_offline(g.db, name);
        if (result == 0) http_error(c, 200, 0, "offline node deleted");
        else if (result == 1) http_error(c, 404, 1, "node not found");
        else if (result == 2) http_error(c, 409, 1, "node is online");
        else http_error(c, 503, 1, "node storage unavailable");
        return;
    }
    if (!c->post && !strcmp(c->uri, "/api/v1/status")) {
        unsigned count = 0;
        for (unsigned i = 0; i < g.max_nodes; ++i)
            if (g.nodes[i] && !g.nodes[i]->closing)
                ++count;
        json_object *j = json_object_new_object();
        gw_js(j, "implementation", "c");
        gw_js(j, "version", GW_VERSION);
        gw_js(j, "user", g.user);
        uint64_t total = 0;
        if (gw_store_count(g.db, &total)) {
            json_object_put(j);
            http_error(c, 503, 1, "node storage unavailable");
            return;
        }
        gw_ju(j, "totalNodes", total);
        gw_js(j, "nodeStorage", "sqlite");
        gw_ju(j, "online", count);
        gw_ju(j, "capacity", g.max_nodes);
        gw_ju(j, "uptimeSeconds", (gw_mono_ms() - g.started_ms) / 1000);
        gw_ju(j, "queuedBytes", g.queued);
        gw_ju(j, "queueLimitBytes", GW_TOTAL_QUEUED);
        gw_ju(j, "wssPort", g.ws_port);
        gw_ju(j, "apiPort", g.api_port);
        gw_ju(j, "heartbeatTimeout", g.timeout);
        http_json(c, 200, j);
        json_object_put(j);
        return;
    }
    if (!c->post && !strcmp(c->uri, "/api/v1/devices")) {
        json_object *j = devices();
        http_json(c, 200, j);
        json_object_put(j);
        return;
    }
    if (!c->post && !strcmp(c->uri, "/api/v1/nodes")) {
        char search[256];
        if (query(c->wsi, "search=", search, sizeof(search)))
            search[0] = 0;
        unsigned limit = query_integer(c->wsi, "limit=", 256, 100);
        unsigned offset = query_integer(c->wsi, "offset=", 2147483647u, 0);
        if (!limit) {
            http_error(c, 400, 1, "invalid page size");
            return;
        }
        json_object *j = gw_store_list(g.db, search, limit, offset);
        if (!j) {
            http_error(c, 503, 1, "node storage unavailable");
            return;
        }
        json_object *nodes = gw_get(j, "nodes");
        for (size_t i = 0; i < json_object_array_length(nodes); ++i) {
            json_object *node = json_object_array_get_idx(nodes, i);
            uint64_t id = 0;
            struct connection *live = !gw_decimal(gw_string(node, "id"), &id) ? find_node(id) : NULL;
            gw_ju(node, "isActive", live && !strcmp(live->node, gw_string(node, "name")) ? 1 : 0);
            capabilities(node);
        }
        http_json(c, 200, j);
        json_object_put(j);
        return;
    }
    const char *prefix = "/api/v1/device/";
    size_t prefix_len = strlen(prefix);
    if (strncmp(c->uri, prefix, prefix_len)) {
        http_error(c, 404, 1, "not found");
        return;
    }
    const char *start = c->uri + prefix_len, *end = strchr(start, '/');
    char name[32];
    size_t length = end ? (size_t)(end - start) : strlen(start);
    if (!end || length >= sizeof(name)) {
        http_error(c, 404, 1, "not found");
        return;
    }
    memcpy(name, start, length);
    name[length] = 0;
    if (!gw_node_valid(name)) {
        http_error(c, 400, 1, "invalid node name");
        return;
    }
    /* The database is the source of truth. A node does not have to be online
     * for its rules to be listed, added, edited or removed; the change is simply
     * queued by being stored and applied on the client's next connection. */
    struct connection *target = find_node(gw_node_id(name));

    if(!strcmp(end,"/config")) {
        if(c->post) {
            if(target&&!target->config_supported) {http_error(c,501,1,"client does not support configuration updates");return;}
            json_object *body=gw_json(c->request,c->request_length);
            json_object *fields=body?gw_get(body,"fields"):NULL;
            if(!json_object_is_type(fields,json_type_object)||gw_store_config_put(g.db,name,fields)) {
                if(body)json_object_put(body);
                http_error(c,400,1,"invalid configuration fields");return;
            }
            json_object_put(body);
            if(push_config(target)) {http_error(c,503,1,"configuration queued; node busy");return;}
        } else if(c->put||c->deleting) {http_error(c,405,1,"method not allowed");return;}
        json_object *config=gw_store_config(g.db,name);
        if(!config) {http_error(c,503,1,"configuration storage unavailable");return;}
        http_json(c,200,config);json_object_put(config);return;
    }

    if (!c->post && !strcmp(end, "/apps")) {
        json_object *list = gw_store_rules(g.db, name);
        if (!list) {
            http_error(c, 503, 1, "rule storage unavailable");
            return;
        }
        /* Flatten the stored payloads into the shape the console already reads. */
        json_object *apps = json_object_new_array();
        for (size_t i = 0; i < json_object_array_length(list); ++i) {
            json_object *entry = json_object_array_get_idx(list, i);
            json_object *rule = gw_get(entry, "rule");
            if (!rule)
                continue;
            json_object_get(rule);
            json_object_object_del(rule,"_config");
            if (!gw_get(rule, "enabled"))
                gw_ju(rule, "enabled", gw_integer(entry, "enabled"));
            if (!strcmp(gw_string(rule, "protocol"), "socks5")) {
                /* Never send a stored SOCKS5 password back to the browser; tell
                 * it whether one exists so editing can require re-entry. */
                int has = *gw_string(rule, "Password") != 0;
                json_object_object_del(rule, "Password");
                gw_ju(rule, "hasPassword", (uint64_t)has);
            }
            json_object_object_add(rule, "isActive",
                json_object_new_int(target && gw_integer(entry, "enabled") ? 1 : 0));
            json_object_array_add(apps, rule);
        }
        json_object_put(list);
        json_object *root = json_object_new_object();
        json_object_object_add(root, "Apps", apps);
        http_json(c, 200, root);
        json_object_put(root);
        return;
    }
    if (!c->post && !strcmp(end, "/restart")) {
        if (!target || send_json(target, 3, 11, NULL))
            http_error(c, 503, 1, "device unavailable");
        else
            http_reply(c, 200, "{\"error\":0}", 11);
        return;
    }
    if (c->post && !strcmp(end, "/upgrade")) {
        /* Manual, operator-initiated upgrade of one node. */
        json_object *j = gw_json(c->request, c->request_length);
        if (!j || !json_object_is_type(j, json_type_object)) {
            if (j)
                json_object_put(j);
            http_error(c, 400, 1, "invalid JSON");
            return;
        }
        char version[32];
        snprintf(version, sizeof(version), "%s", gw_string(j, "version"));
        json_object_put(j);
        if (!*version) {
            http_error(c, 400, 1, "version is required");
            return;
        }
        if (!target) {
            http_error(c, 503, 1, "device offline");
            return;
        }
        char sha[65], filename[260], variant[16];
        uint64_t size = 0;
        if (!find_node_package(target, version, sha, filename, &size, variant)) {
            http_error(c, 404, 1, "no package for this platform and version");
            return;
        }
        if (push_update(target, version)) {
            http_error(c, 503, 1, "device unavailable");
            return;
        }
        json_object *reply = json_object_new_object();
        gw_ju(reply, "error", 0);
        gw_js(reply, "version", version);
        gw_js(reply, "sha256", sha);
        gw_ju(reply, "size", size);
        http_json(c, 200, reply);
        json_object_put(reply);
        return;
    }
    if (c->post && (!strcmp(end, "/app") || !strcmp(end, "/switchapp"))) {
        json_object *j = gw_json(c->request, c->request_length);
        if (!j || !json_object_is_type(j, json_type_object)) {
            if (j)
                json_object_put(j);
            http_error(c, 400, 1, "invalid JSON");
            return;
        }
        /* Copy the identity strings out of the request before it is released:
         * they point into the JSON object, which is freed below. */
        char protocol[16], old_protocol[16];
        snprintf(protocol, sizeof(protocol), "%s", gw_string(j, "protocol"));
        snprintf(old_protocol, sizeof(old_protocol), "%s", gw_string(j, "protocol0"));
        uint64_t src = gw_integer(j, "srcPort");
        uint64_t old_port = gw_integer(j, "srcPort0");
        int switching = !strcmp(end, "/switchapp");

        /* switchapp only toggles an existing rule. */
        if (switching) {
            int enabled = gw_integer(j, "enabled") ? 1 : 0;
            json_object_put(j);
            if (!*protocol || !src || src > 65535 ||
                gw_store_rule_set_enabled(g.db, name, protocol, (unsigned)src, enabled)) {
                http_error(c, 404, 1, "rule not found");
                return;
            }
            if (target && !target->config_supported) {
                if (!enabled) {
                    json_object *remove = json_object_new_object();
                    gw_js(remove, "protocol", protocol);
                    gw_ju(remove, "srcPort", src);
                    send_json(target, 3, 17, remove); /* RULE_REMOVE */
                    json_object_put(remove);
                } else {
                    json_object *list = gw_store_rules(g.db, name);
                    if (list)
                        for (size_t i = 0; i < json_object_array_length(list); ++i) {
                            json_object *entry = json_object_array_get_idx(list, i);
                            if (!strcmp(gw_string(entry, "protocol"), protocol) &&
                                gw_integer(entry, "srcPort") == src) {
                                send_json(target, 3, 9, gw_get(entry, "rule")); /* RULE_APPLY */
                                break;
                            }
                        }
                    if (list)
                        json_object_put(list);
                }
            }
            if(gw_store_config_rules(g.db,name)||push_config(target)) {http_error(c,503,1,"configuration storage unavailable");return;}
            http_reply(c, 200, "", 0);
            return;
        }

        /* /app with srcPort=0 removes the rule identified by protocol0/srcPort0. */
        if (!src) {
            json_object_put(j);
            if (!*old_protocol || !old_port || old_port > 65535 ||
                gw_store_rule_delete(g.db, name, old_protocol, (unsigned)old_port)) {
                http_error(c, 404, 1, "rule not found");
                return;
            }
            if (target && !target->config_supported) {
                json_object *remove = json_object_new_object();
                gw_js(remove, "protocol", old_protocol);
                gw_ju(remove, "srcPort", old_port);
                send_json(target, 3, 17, remove);
                json_object_put(remove);
            }
            if(gw_store_config_rules(g.db,name)||push_config(target)) {http_error(c,503,1,"configuration storage unavailable");return;}
            http_reply(c, 200, "", 0);
            return;
        }
        if (src > 65535 || !*protocol ||
            (strcmp(protocol, "tcp") && strcmp(protocol, "udp") && strcmp(protocol, "socks5"))) {
            json_object_put(j);
            http_error(c, 400, 1, "invalid rule");
            return;
        }

        /* Editing carries the identity of the old rule; remove that key first. */
        int edited = *old_protocol && old_port;
        if (edited && !strcmp(protocol, "socks5") && gw_integer(j, "keepPassword")) {
            /* The browser never receives a stored password. When the user leaves
             * the field blank while editing an authenticated proxy, keep the old
             * credentials rather than silently turning authentication off. */
            json_object *stored = gw_store_rules(g.db, name);
            if (stored) {
                for (size_t i = 0; i < json_object_array_length(stored); ++i) {
                    json_object *entry = json_object_array_get_idx(stored, i);
                    if (strcmp(gw_string(entry, "protocol"), old_protocol) ||
                        gw_integer(entry, "srcPort") != old_port)
                        continue;
                    json_object *old = gw_get(entry, "rule");
                    if (old) {
                        gw_js(j, "Username", gw_string(old, "Username"));
                        gw_js(j, "Password", gw_string(old, "Password"));
                    }
                    break;
                }
                json_object_put(stored);
            }
        }
        if (edited) {
            if (gw_store_rule_delete(g.db, name, old_protocol, (unsigned)old_port)) {
                json_object_put(j);
                http_error(c, 404, 1, "rule not found");
                return;
            }
            if (target && !target->config_supported) {
                json_object *remove = json_object_new_object();
                gw_js(remove, "protocol", old_protocol);
                gw_ju(remove, "srcPort", old_port);
                send_json(target, 3, 17, remove);
                json_object_put(remove);
            }
        }
        /* Normalise the identity fields before storing the payload verbatim.
         * Copy the protocol first: re-adding the key frees the string the JSON
         * object owned, and the pointer would dangle. */
        char protocol_copy[16];
        snprintf(protocol_copy, sizeof(protocol_copy), "%s", protocol);
        gw_js(j, "protocol", protocol_copy);
        gw_ju(j, "srcPort", src);
        const char *payload = json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN);
        int rv = gw_store_rule_put(g.db, name, protocol_copy, (unsigned)src, payload, 1);
        if (target && !target->config_supported && !rv)
            send_json(target, 3, 9, j); /* RULE_APPLY */
        json_object_put(j);
        if (rv) {
            http_error(c, 503, 1, "rule storage unavailable");
            return;
        }
        if(gw_store_config_rules(g.db,name)||push_config(target)) {http_error(c,503,1,"configuration storage unavailable");return;}
        http_reply(c, 200, "", 0);
        return;
    }
    http_error(c, 404, 1, "not found");
}

static int write_http(struct connection *c) {
    if (!c->handled)
        return 0;
    if (!c->headers_sent) {
        unsigned char buffer[LWS_PRE + 1024], *start = buffer + LWS_PRE, *p = start,
                                              *end = buffer + sizeof(buffer);
        if (lws_add_http_common_headers(c->wsi, (unsigned)c->status,
                                        c->response_type ? c->response_type
                                                         : "application/json; charset=utf-8",
                                        (lws_filepos_t)c->response_length, &p, end) ||
            lws_add_http_header_by_name(c->wsi, (unsigned char *)"cache-control:",
                                        (unsigned char *)"no-store", 8, &p, end) ||
            lws_add_http_header_by_name(c->wsi, (unsigned char *)"x-content-type-options:",
                                        (unsigned char *)"nosniff", 7, &p, end) ||
            lws_add_http_header_by_name(
                c->wsi, (unsigned char *)"content-security-policy:",
                (unsigned char *)"default-src 'none'; script-src 'self'; style-src 'self'; img-src "
                                 "'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; "
                                 "frame-ancestors 'none'",
                (int)strlen("default-src 'none'; script-src 'self'; style-src 'self'; img-src "
                            "'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; "
                            "frame-ancestors 'none'"),
                &p, end) ||
            lws_add_http_header_by_name(c->wsi, (unsigned char *)"referrer-policy:",
                                        (unsigned char *)"no-referrer", 11, &p, end) ||
            lws_add_http_header_by_name(
                c->wsi, (unsigned char *)"x-frame-options:", (unsigned char *)"DENY", 4, &p, end) ||
            lws_finalize_write_http_header(c->wsi, start, &p, end))
            return -1;
        c->headers_sent = 1;
        if (!c->response_length)
            return lws_http_transaction_completed(c->wsi) ? -1 : 0;
        lws_callback_on_writable(c->wsi);
        return 0;
    }
    size_t n = c->response_length - c->response_offset;
    if (n > 16384)
        n = 16384;
    enum lws_write_protocol flags =
        c->response_offset + n == c->response_length ? LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP;
    int written = lws_write(c->wsi, c->response + LWS_PRE + c->response_offset, n, flags);
    if (written < (int)n)
        return -1;
    c->response_offset += n;
    if (c->response_offset == c->response_length)
        return lws_http_transaction_completed(c->wsi) ? -1 : 0;
    lws_callback_on_writable(c->wsi);
    return 0;
}
static int query(struct lws *wsi, const char *name, char *out, size_t capacity) {
    char buffer[1024];
    const char *p = lws_get_urlarg_by_name(wsi, name, buffer, sizeof(buffer));
    if (!p) {
        *out = 0;
        return -1;
    }
    if (strlen(p) >= capacity)
        return -1;
    snprintf(out, capacity, "%s", p);
    return 0;
}
static unsigned query_integer(struct lws *wsi, const char *name, unsigned limit,
                              unsigned fallback) {
    char buffer[32];
    uint64_t n;
    return query(wsi, name, buffer, sizeof(buffer)) || gw_decimal(buffer, &n) || n > limit
               ? fallback
               : (unsigned)n;
}
static int login_status(struct lws *wsi) {
    char uri[256], node[32], token[32];
    uint64_t value;
    if (lws_get_vhost(wsi) != g.ws_vhost && lws_get_vhost(wsi) != g.ws_alt_vhost)
        return 404;
    if (lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_GET_URI) < 0 ||
        (strcmp(uri, "/api/v1/login") && strcmp(uri, "/fastp2p/v1/login")))
        return 404;
    char protocol[32];
    if (query(wsi, "protocol=", protocol, sizeof(protocol)) || strcmp(protocol, "fastp2p2"))
        return 426;
    if (query(wsi, "node=", node, sizeof(node)) || !gw_node_valid(node))
        return 400;
    if (query(wsi, "token=", token, sizeof(token)) || gw_decimal(token, &value) || value != g.token)
        return 401;
    int automatic = query_integer(wsi, "autonode=", 1, 0) != 0;
    int automatic_known = 0;
    if (automatic) {
        char device[33], hostname[256];
        if (query(wsi, "deviceid=", device, sizeof(device)) || !gw_device_valid(device) ||
            query(wsi, "hostname=", hostname, sizeof(hostname)) || !*hostname)
            return 400;
        size_t length = strlen(hostname);
        if (length > 31)
            return 400;
        char padded[32];
        strcpy(padded, hostname);
        while (length < 8) padded[length++] = '0';
        padded[length] = 0;
        if (!gw_node_valid(padded))
            return 400;
        automatic_known = gw_store_resolve(g.db, device, node);
        if (automatic_known < 0)
            return 503;
    } else {
        int status = gw_store_manual_status(g.db, node);
        if (status)
            return status > 0 ? 409 : 503;
    }
    struct connection *existing = find_node(gw_node_id(node));
    if (automatic && !automatic_known)
        existing = NULL;
    if (existing && strcmp(existing->node, node))
        return 409;
    if (!existing) {
        unsigned i = 0;
        while (i < g.max_nodes && g.nodes[i])
            ++i;
        if (i == g.max_nodes)
            return 503;
    }
    return 0;
}
static int establish(struct lws *wsi, struct connection *c) {
    if (login_status(wsi))
        return -1;
    memset(c, 0, sizeof(*c));
    c->wsi = wsi;
    c->slot = -1;
    if (query(wsi, "node=", c->node, sizeof(c->node)))
        return -1;
    char requested[32], device[33];
    strcpy(requested, c->node);
    int automatic = query_integer(wsi, "autonode=", 1, 0) != 0;
    device[0] = 0;
    if (automatic && (query(wsi, "deviceid=", device, sizeof(device)) ||
                      query(wsi, "hostname=", c->hostname, sizeof(c->hostname))))
        return -1;
    if (gw_store_claim(g.db, requested, c->hostname, device, automatic, c->node))
        return -1;
    c->id = gw_node_id(c->node);
    struct connection *previous = find_node(c->id);
    if (previous) {
        unregister_node(previous);
        close_node(previous);
    }
    unsigned slot = 0;
    while (slot < g.max_nodes && g.nodes[slot])
        ++slot;
    if (slot == g.max_nodes)
        return -1;
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    if (getpeername(lws_get_socket_fd(wsi), (struct sockaddr *)&peer, &plen) ||
        peer.sin_family != AF_INET || !inet_ntop(AF_INET, &peer.sin_addr, c->ip, sizeof(c->ip)))
        return -1;
    query(wsi, "version=", c->version, sizeof(c->version));
    query(wsi, "ipv6=", c->ipv6, sizeof(c->ipv6));
    c->major = major_version(c->version);
    c->nat = query_integer(wsi, "nattype=", 314, 314);
    c->tcp_nat = query_integer(wsi, "tcpnattype=", 314, 314);
    if (c->tcp_nat != 1 && c->tcp_nat != 2) c->tcp_nat = 314;
    c->bandwidth = query_integer(wsi, "sharebandwidth=", 1000000, 0);
    c->slot = (int)slot;
    c->registered = 1;
    c->last_rx = gw_mono_ms();
    c->active_wall = gw_wall_ns();
    c->last_seen_wall = c->active_wall;
    c->next_store = c->last_rx + 30000;
    g.nodes[slot] = c;
    if (gw_store_save(g.db, c, 1)) {
        unregister_node(c);
        return -1;
    }
    json_object *login = json_object_new_object();
    gw_ju(login, "tcpProbeV2", 1);
    gw_js(login, "user", g.user);
    gw_js(login, "node", c->node);
    gw_js(login, "protocol", "fastp2p2");
    gw_ju(login, "token", g.token);
    gw_ju(login, "ts", gw_wall_ns() / 1000000000);
    gw_ju(login, "error", 0);
    int result = send_json(c, 0, 0, login);
    json_object_put(login);
    return result;
}
static int callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in,
                    size_t len) {
    struct connection *c = user;
    switch (reason) {
    case LWS_CALLBACK_HTTP_CONFIRM_UPGRADE: {
        int status = login_status(wsi);
        if (status) {
            lws_return_http_status(wsi, (unsigned)status, NULL);
            return 1;
        }
        return 0;
    }
    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
        return login_status(wsi) ? 1 : 0;
    case LWS_CALLBACK_ESTABLISHED:
        return establish(wsi, c);
    case LWS_CALLBACK_RECEIVE: {
        if (c && c->registered)
            c->last_seen_wall = gw_wall_ns();
        int result = c && c->registered && !c->closing ? receive_ws(c, in, len) : -1;
        if (result && c) {
            c->closing = 1;
            unregister_node(c);
        }
        return result;
    }
    case LWS_CALLBACK_SERVER_WRITEABLE:
        return write_ws(c);
    case LWS_CALLBACK_CLOSED:
        if (!c)
            break;
        unregister_node(c);
        while (c->head) {
            struct packet *p = c->head;
            c->head = p->next;
            g.queued -= p->length;
            free(p);
        }
        c->tail = NULL;
        c->queued = c->count = 0;
        g.rx_allocated -= c->rx_capacity;
        free(c->rx);
        c->rx = NULL;
        c->rx_capacity = c->rx_length = 0;
        break;
    case LWS_CALLBACK_HTTP: {
        if (!c)
            return -1;
        clear_http(c);
        c->wsi = wsi;
        if (len >= sizeof(c->uri)) {
            http_error(c, 414, 1, "URI too long");
            return 0;
        }
        memcpy(c->uri, in, len);
        c->uri[len] = 0;
        char *method_uri = NULL;
        int method_length = 0;
        int method = lws_http_get_uri_and_method(wsi, &method_uri, &method_length);
        if (lws_get_vhost(wsi) != g.api_vhost &&
            (method != LWSHUMETH_GET || strcmp(c->uri, "/api/v1/update/download"))) {
            http_error(c, 404, 1, "not found");
            return 0;
        }
        int is_upload = method == LWSHUMETH_PUT && !strcmp(c->uri, "/api/v1/update");
        if (method != LWSHUMETH_GET && method != LWSHUMETH_POST && !is_upload &&
            !(method == LWSHUMETH_DELETE && !strncmp(c->uri, "/api/v1/nodes/", 14))) {
            http_error(c, 405, 1, "method not allowed");
            return 0;
        }
        c->post = method == LWSHUMETH_POST;
        c->deleting = method == LWSHUMETH_DELETE;
        char auth[8192];
        int n = lws_hdr_copy(wsi, auth, sizeof(auth), WSI_TOKEN_HTTP_AUTHORIZATION);
        c->authorized =
            n > 0 && gw_jwt_verify(auth, g.user, g.token, g.secret, gw_wall_ns() / 1000000000);
        c->auth_generation = g.auth_generation;
        if (is_upload) {
            /* Stream the package to a temporary file; it is far larger than the
             * in-memory HTTP body limit. */
            c->put = 1;
            if (!c->authorized || c->auth_generation != g.auth_generation) {
                http_error(c, 401, 1, "unauthorized");
                return 0;
            }
            char platform[16], version[32], length[32];
            if (query(wsi, "platform=", platform, sizeof(platform)) ||
                query(wsi, "version=", version, sizeof(version)) ||
                !gw_store_update_key_valid(platform, version)) {
                http_error(c, 400, 1, "invalid platform or version");
                return 0;
            }
            uint64_t declared = 0;
            if (lws_hdr_copy(wsi, length, sizeof(length), WSI_TOKEN_HTTP_CONTENT_LENGTH) > 0 &&
                (gw_decimal(length, &declared) || declared > GW_UPLOAD_LIMIT)) {
                http_error(c, 413, 1, "package too large");
                return 0;
            }
            if (update_dir_ready()) {
                http_error(c, 503, 1, "update storage unavailable");
                return 0;
            }
            snprintf(c->upload_platform, sizeof(c->upload_platform), "%s", platform);
            snprintf(c->upload_version, sizeof(c->upload_version), "%s", version);
            snprintf(c->upload_tmp, sizeof(c->upload_tmp), "%s/.upload-XXXXXX", g.update_dir);
            int fd = mkstemp(c->upload_tmp);
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            if (fd < 0 || !ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
                if (fd >= 0) {
                    close(fd);
                    unlink(c->upload_tmp);
                }
                if (ctx)
                    EVP_MD_CTX_free(ctx);
                c->upload_tmp[0] = 0;
                http_error(c, 503, 1, "cannot stage upload");
                return 0;
            }
            fchmod(fd, 0600);
            c->upload = fdopen(fd, "w+b");
            if (!c->upload) {
                close(fd);
                EVP_MD_CTX_free(ctx);
                unlink(c->upload_tmp);
                c->upload_tmp[0] = 0;
                http_error(c, 503, 1, "cannot stage upload");
                return 0;
            }
            c->upload_digest = ctx;
            c->upload_size = 0;
            return 0;
        }
        if (c->post) {
            if (strcmp(c->uri, "/api/v1/user/login") && !c->authorized) {
                http_error(c, 401, 1, "unauthorized");
                return 0;
            }
            char length[32];
            uint64_t size;
            int has_length =
                lws_hdr_copy(wsi, length, sizeof(length), WSI_TOKEN_HTTP_CONTENT_LENGTH) > 0;
            if (has_length && (gw_decimal(length, &size) || size > GW_HTTP_LIMIT)) {
                http_error(c, 413, 1, "request too large");
                return 0;
            }
            if ((has_length && size == 0) ||
                (!has_length && !lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_TRANSFER_ENCODING)))
                handle_http(c);
            return 0;
        }
        handle_http(c);
        return 0;
    }
    case LWS_CALLBACK_HTTP_BODY:
        if (c->handled)
            return 0;
        if (c->upload) {
            if (c->upload_size + len > GW_UPLOAD_LIMIT) {
                upload_abort(c);
                http_error(c, 413, 1, "package too large");
                return 0;
            }
            if (len) {
                if (fwrite(in, 1, len, c->upload) != len) {
                    upload_abort(c);
                    http_error(c, 500, 1, "cannot write upload");
                    return 0;
                }
                EVP_DigestUpdate((EVP_MD_CTX *)c->upload_digest, in, len);
                c->upload_size += len;
            }
            return 0;
        }
        if (len > GW_HTTP_LIMIT - c->request_length) {
            http_error(c, 413, 1, "request too large");
            return 0;
        }
        if (len) {
            unsigned char *p = realloc(c->request, c->request_length + len);
            if (!p)
                return -1;
            c->request = p;
            memcpy(p + c->request_length, in, len);
            c->request_length += len;
        }
        return 0;
    case LWS_CALLBACK_HTTP_BODY_COMPLETION:
        handle_http(c);
        return 0;
    case LWS_CALLBACK_HTTP_WRITEABLE:
        return write_http(c);
    case LWS_CALLBACK_HTTP_FILE_COMPLETION:
        /* An upgrade package finished streaming; close the transaction so the
         * connection can serve another request. */
        return lws_http_transaction_completed(wsi) ? -1 : 0;
    case LWS_CALLBACK_CLOSED_HTTP:
    case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
        clear_http(c);
        break;
    default:
        break;
    }
    return 0;
}
static const struct lws_protocols protocols[] = {
    {.name = "http",
     .callback = callback,
     .per_session_data_size = sizeof(struct connection),
     .rx_buffer_size = 16384,
     .tx_packet_size = 16384},
    {.name = "fastp2p",
     .callback = callback,
     .per_session_data_size = sizeof(struct connection),
     .rx_buffer_size = 16384,
     .tx_packet_size = 16384},
    {0}};
static void tick(lws_sorted_usec_list_t *sul) {
    poll_release_sync();
    (void)sul;
    gw_nat_step(&g.nat);
    uint64_t now = gw_mono_ms();
    for (unsigned i = 0; i < g.max_nodes; ++i) {
        struct connection *c = g.nodes[i];
        if (!c)
            continue;
        if (now >= c->next_store) {
            c->next_store = now + 30000;
            if (gw_store_save(g.db, c, 1))
                fputs("Cannot persist node heartbeat\n", stderr);
        }
        if (now - c->last_rx > (uint64_t)g.timeout * 1000)
            close_node(c);
        if (c->pending_http && now > c->pending_http->deadline) {
            struct connection *http = c->pending_http;
            c->pending_http = NULL;
            http->request_node = NULL;
            http_error(http, 504, 9, "timeout");
        }
    }
    lws_sul_schedule(g.context, 0, &g.tick, tick, 10000);
}
static void usage(void) {
    puts("fastp2p-gateway --cert FILE --key FILE [--bind IP] [--apibind IP]\n"
         "  [--port 27183] [--altwss 443] [--apiport 10008] [--database FILE]\n"
         "  [--max-clients 256] [--heartbeat-timeout 40] [--run-seconds N]\n"
         "  [--reset-admin] (stop the gateway before resetting its account)\n"
         "Set FASTP2P_USER, FASTP2P_PASSWORD and a 16-digit FASTP2P_TOKEN.\n"
         "Default bind: 127.0.0.1. NAT ports: TCP 27180-27181, UDP 27180-27183.");
}
static int options(int argc, char **argv) {
    g.max_nodes = GW_MAX_NODES;
    g.timeout = 40;
    g.ws_port = 27183;
    g.api_port = 10008;
    g.database = getenv("FASTP2P_DATABASE");
    g.public_host = getenv("FASTP2P_PUBLIC_HOST");
    g.enrollment_ca_file = getenv("FASTP2P_CA_FILE");
    if (!g.database)
        g.database = "nodes.sqlite3";
    snprintf(g.bind, sizeof(g.bind), "127.0.0.1");
    g.cert = getenv("FASTP2P_TLS_CERT");
    if (!g.cert)
        g.cert = "api.crt";
    g.key = getenv("FASTP2P_TLS_KEY");
    if (!g.key)
        g.key = "api.key";
    static const struct option opts[] = {{"cert", required_argument, 0, 'c'},
                                         {"key", required_argument, 0, 'k'},
                                         {"bind", required_argument, 0, 'b'},
                                         {"apibind", required_argument, 0, 'a'},
                                         {"port", required_argument, 0, 'p'},
                                         {"apiport", required_argument, 0, 'q'},
                                         {"altwss", required_argument, 0, 'x'},
                                         {"max-clients", required_argument, 0, 'm'},
                                         {"heartbeat-timeout", required_argument, 0, 't'},
                                         {"run-seconds", required_argument, 0, 'r'},
                                         {"database", required_argument, 0, 'd'},
                                         {"public-host", required_argument, 0, 'H'},
                                         {"enrollment-ca", required_argument, 0, 'C'},
                                         {"reset-admin", no_argument, 0, 'R'},
                                         {"version", no_argument, 0, 'v'},
                                         {"help", no_argument, 0, 'h'},
                                         {0}};
    int option;
    uint64_t value;
    while ((option = getopt_long_only(argc, argv, "", opts, NULL)) != -1) {
        switch (option) {
        case 'c':
            g.cert = optarg;
            break;
        case 'k':
            g.key = optarg;
            break;
        case 'b':
            if (strlen(optarg) >= sizeof(g.bind))
                return -1;
            strcpy(g.bind, optarg);
            break;
        case 'a':
            if (strlen(optarg) >= sizeof(g.api_bind))
                return -1;
            strcpy(g.api_bind, optarg);
            break;
        case 'd':
            g.database = optarg;
            break;
        case 'H': g.public_host = optarg; break;
        case 'C': g.enrollment_ca_file = optarg; break;
        case 'R': g.reset_admin = 1; break;
        case 'v':
            printf("fastp2p-gateway %s\n", GW_VERSION);
            return 1;
        case 'h':
            usage();
            return 1;
        case 'p':
        case 'q':
        case 'x':
        case 'm':
        case 't':
        case 'r':
            if (gw_decimal(optarg, &value) || value > 86400 || !value)
                return -1;
            if (option == 'p' || option == 'q' || option == 'x') {
                if (value > 65535)
                    return -1;
                if (option == 'p')
                    g.ws_port = (unsigned)value;
                else if (option == 'q')
                    g.api_port = (unsigned)value;
                else
                    g.alt_ws_port = (unsigned)value;
            } else if (option == 'm') {
                if (value > GW_MAX_NODES)
                    return -1;
                g.max_nodes = (unsigned)value;
            } else if (option == 't') {
                if (value < 5)
                    return -1;
                g.timeout = (unsigned)value;
            } else
                g.run_seconds = (unsigned)value;
            break;
        default:
            return -1;
        }
    }
    if (optind != argc || g.ws_port == g.api_port ||
        (g.alt_ws_port && (g.alt_ws_port == g.ws_port || g.alt_ws_port == g.api_port)) ||
        !*g.database)
        return -1;
    if (!*g.api_bind)
        strcpy(g.api_bind, g.bind);
    /* Upgrade packages sit beside the database so one backup captures both. */
    {
        const char *slash = strrchr(g.database, '/');
        if (slash) {
            size_t length = (size_t)(slash - g.database);
            if (length > sizeof(g.update_dir) - 16)
                return -1;
            snprintf(g.update_dir, sizeof(g.update_dir), "%.*s/updates", (int)length, g.database);
        } else {
            snprintf(g.update_dir, sizeof(g.update_dir), "updates");
        }
    }
    struct in_addr address;
    if (inet_pton(AF_INET, g.bind, &address) != 1 || inet_pton(AF_INET, g.api_bind, &address) != 1)
        return -1;
    g.user = getenv("FASTP2P_USER");
    g.password = getenv("FASTP2P_PASSWORD");
    if (!g.user || !*g.user || strlen(g.user) > 256 || !g.password || !*g.password ||
        strlen(g.password) > 1024)
        return -1;
    const char *token = getenv("FASTP2P_TOKEN");
    if (!fastp2p_install_key_valid(token) || gw_decimal(token, &g.token))
        return -1;
    if (!g.token)
        return -1;
    if (!g.public_host || !*g.public_host)
        g.public_host = strcmp(g.bind, "0.0.0.0") ? g.bind : "127.0.0.1";
    if (!fastp2p_enrollment_host_valid(g.public_host))
        return -1;
    /* Kept across the call because the global below points at it. */
    static char automatic_ca[4096];
    if (!g.enrollment_ca_file) {
        const char *slash = strrchr(g.cert, '/');
        size_t length = slash ? (size_t)(slash - g.cert + 1) : 0;
        if (length + 7 >= sizeof(automatic_ca)) return -1;
        memcpy(automatic_ca, g.cert, length); memcpy(automatic_ca + length, "ca.crt", 7);
        if (!access(automatic_ca, R_OK)) g.enrollment_ca_file = automatic_ca;
    }
    if (g.enrollment_ca_file) {
        FILE *file = fopen(g.enrollment_ca_file, "rb");
        if (!file) return -1;
        size_t length = fread(g.enrollment_ca, 1, sizeof(g.enrollment_ca), file);
        int bad = ferror(file) || !length || length >= sizeof(g.enrollment_ca);
        fclose(file);
        if (bad) return -1;
        g.enrollment_ca[length] = 0;
    }
    char *profile = fastp2p_enrollment_encode(g.public_host, g.ws_port, g.token, g.enrollment_ca);
    if (!profile) return -1;
    OPENSSL_cleanse(profile, strlen(profile)); free(profile);
    return 0;
}
int main(int argc, char **argv) {
    int parsed = options(argc, argv);
    if (parsed) {
        if (parsed < 0) {
            fputs("Invalid gateway configuration; check credentials, options and "
                  "database path\n",
                  stderr);
            usage();
        }
        return parsed < 0 ? 2 : 0;
    }
    signal(SIGINT, signal_stop);
    signal(SIGTERM, signal_stop);
    signal(SIGPIPE, SIG_IGN);
    lws_set_log_level(LLL_ERR | LLL_WARN, NULL);
    umask(0077);
    if (gw_store_open(&g.db, g.database)) {
        fputs("Cannot open node SQLite database\n", stderr);
return 1;
    }
    int admin_status = gw_store_admin_read(g.db, &g.admin);
    if (admin_status == 1 || g.reset_admin) {
        admin_status = gw_admin_make(&g.admin, g.user, g.password) ? -1 : gw_store_admin_write(g.db, &g.admin);
    }
    if (admin_status) {
        fputs("Cannot initialize gateway account\n", stderr);
sqlite3_close(g.db); return 1;
    }
    g.user = g.admin.user;
    snprintf(g.secret, sizeof(g.secret), "%s", g.admin.secret);
    g.auth_generation = 1;
    if (g.reset_admin) {
        puts("Gateway account reset from FASTP2P_USER and FASTP2P_PASSWORD");
sqlite3_close(g.db); return 0;
    }
    if (gw_nat_start(&g.nat, g.bind)) {
        fputs("Cannot bind NAT ports\n", stderr);
sqlite3_close(g.db);
        return 1;
    }
    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS | LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
                   LWS_SERVER_OPTION_DISABLE_IPV6;
    info.uid = -1;
    info.gid = -1;
    info.fd_limit_per_thread = 1024;
    info.max_http_header_data = 8192;
    info.max_http_header_pool = 256;
    info.timeout_secs = 10;
    g.context = lws_create_context(&info);
    if (!g.context) {
        fputs("Cannot initialize TLS service\n", stderr);
        goto failed;
    }
    memset(&info, 0, sizeof(info));
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT | LWS_SERVER_OPTION_DISABLE_IPV6;
    info.protocols = protocols;
    info.ssl_cert_filepath = g.cert;
    info.ssl_private_key_filepath = g.key;
    info.alpn = "http/1.1";
    info.uid = -1;
    info.gid = -1;
    info.ssl_options_set =
        SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_COMPRESSION;
    info.iface = g.bind;
    info.port = (int)g.ws_port;
    info.vhost_name = "fastp2p-wss";
    g.ws_vhost = lws_create_vhost(g.context, &info);
    g.ws_alt_vhost = NULL;
    if (g.alt_ws_port) {
        info.iface = g.bind;
        info.port = (int)g.alt_ws_port;
        info.vhost_name = "fastp2p-wss-alt";
        g.ws_alt_vhost = lws_create_vhost(g.context, &info);
        if (!g.ws_alt_vhost) {
            fputs("Cannot bind the alternate WSS port\n", stderr);
            goto failed;
        }
    }
    info.iface = g.api_bind;
    info.port = (int)g.api_port;
    info.vhost_name = "fastp2p-api";
    g.api_vhost = lws_create_vhost(g.context, &info);
    if (!g.ws_vhost || !g.api_vhost) {
        fputs("Cannot load TLS certificate/key or bind HTTPS/WSS ports\n", stderr);
        goto failed;
    }
    g.started_ms = gw_mono_ms();
    printf("{\"event\":\"ready\",\"version\":\"%s\",\"wss\":%u,\"wssAlt\":%u,"
           "\"api\":%u}\n", GW_VERSION, g.ws_port, g.alt_ws_port, g.api_port);
    fflush(stdout);
    lws_sul_schedule(g.context, 0, &g.tick, tick, 10000);
    uint64_t end = g.run_seconds ? gw_mono_ms() + (uint64_t)g.run_seconds * 1000 : 0;
    int result = 0;
    while (!stopping && (!end || gw_mono_ms() < end))
        if (lws_service(g.context, 0) < 0) {
            result = 1;
            break;
        }
    if (release_sync_pid) {
        kill(release_sync_pid, SIGTERM);
        while (waitpid(release_sync_pid, NULL, 0) < 0 && errno == EINTR) {}
    }
    if (release_cleanup_pid) {
        kill(release_cleanup_pid,SIGTERM);
        while(waitpid(release_cleanup_pid,NULL,0)<0 && errno==EINTR) {}
    }
    lws_sul_cancel(&g.tick);
    lws_context_destroy(g.context);
    gw_nat_stop(&g.nat);
    sqlite3_close(g.db);
    OPENSSL_cleanse(g.secret, sizeof(g.secret));
    return result;
failed:
    if (g.context)
        lws_context_destroy(g.context);
    gw_nat_stop(&g.nat);
    sqlite3_close(g.db);
    OPENSSL_cleanse(g.secret, sizeof(g.secret));
    return 1;
}
