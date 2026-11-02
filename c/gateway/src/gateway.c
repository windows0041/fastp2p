#include "gateway.h"
#include "web_assets.h"
#include "enrollment.h"
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/stat.h>

static struct gateway g;
static volatile sig_atomic_t stopping;
static void signal_stop(int signal) {
    (void)signal;
    stopping = 1;
}
static void http_reply(struct connection *c, int status, const void *data, size_t len);
static void http_error(struct connection *c, int status, unsigned code, const char *detail);
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
    if (c->count >= 64 || size > GW_QUEUE_LIMIT - c->queued || size > GW_TOTAL_QUEUED - g.queued) {
        close_node(c);
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
    } else if (main == 6 && sub == 0) {
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
        c->major = major_version(c->version);
        if (gw_store_save(g.db, c, 1)) {
            json_object_put(j);
            return -1;
        }
        json_object *ack = json_object_new_object();
        send_json(c, 6, 7, ack);
        json_object_put(ack);
        json_object *online = json_object_new_object();
        gw_js(online, "node", c->node);
        for (unsigned i = 0; i < g.max_nodes; ++i)
            if (g.nodes[i])
                send_json(g.nodes[i], 3, 15, online);
        json_object_put(online);
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
        json_object *exclude = gw_get(j, "exclude");
        struct connection *relay = NULL;
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
            if (n->nat == 2) {
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
            if (!relay || n->relay_time < relay->relay_time)
                relay = n;
        }
        /* An empty offer is otherwise indistinguishable from a busy gateway, so
         * report the pool and the reason each node was passed over.  Repeated
         * failures are rate limited; a successful choice is always recorded. */
        uint64_t now_ms = gw_mono_ms();
        if (relay || now_ms - c->relay_log_ms >= 5000) {
            printf("{\"event\":\"relay-select\",\"from\":\"%s\",\"peer\":\"%s\","
                   "\"connected\":%u,\"skipped\":{\"self\":%u,\"peer\":%u,\"symmetric\":%u,"
                   "\"major\":%u,\"excluded\":%u},\"relay\":\"%s\"}\n",
                   c->node, peer ? peer->node : "", seen, skip_self, skip_peer, skip_nat, skip_major,
                   skip_exclude, relay ? relay->node : "");
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
}
static void http_reply(struct connection *c, int status, const void *data, size_t len) {
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
    const char *os = gw_string(node, "os");
    size_t length = strlen(os);
    int c_client = length >= 2 && !strcmp(os + length - 2, "-c");
    int active = gw_integer(node, "isActive") != 0;
    json_object *caps = json_object_new_object();
    json_object_object_add(caps, "readApps", json_object_new_boolean(active));
    json_object_object_add(caps, "addForward", json_object_new_boolean(active));
    json_object_object_add(caps, "editForward", json_object_new_boolean(active && !c_client));
    json_object_object_add(caps, "switchForward", json_object_new_boolean(active && !c_client));
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
static void handle_http(struct connection *c) {
    if (c->handled || c->request_node)
        return;
    if (lws_get_vhost(c->wsi) != g.api_vhost) {
        http_error(c, 404, 1, "not found");
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
    if (!c->post && !strcmp(c->uri, "/healthz")) {
        http_reply(c, 200,
                   "{\"status\":\"ok\",\"implementation\":\"c\",\"version\":\"" GW_VERSION "\"}",
                   strlen("{\"status\":\"ok\",\"implementation\":\"c\",\"version\":"
                          "\"" GW_VERSION "\"}"));
        return;
    }
    if (c->post && !strcmp(c->uri, "/api/v1/user/login")) {
        json_object *j = gw_json(c->request, c->request_length);
        if (!j || !json_object_is_type(j, json_type_object)) {
            if (j)
                json_object_put(j);
            http_error(c, 400, 1, "invalid JSON");
            return;
        }
        int valid = gw_secret_equal(gw_string(j, "user"), g.user) &&
                    gw_admin_verify(&g.admin, gw_string(j, "password"));
        if (j)
            json_object_put(j);
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
    if (!end || (size_t)(end - start) >= sizeof(name)) {
        http_error(c, 404, 1, "not found");
        return;
    }
    memcpy(name, start, (size_t)(end - start));
    name[end - start] = 0;
    struct connection *target = gw_node_valid(name) ? find_node(gw_node_id(name)) : NULL;
    if (!target) {
        http_error(c, 200, 1, "device offline");
        return;
    }
    if (!c->post && !strcmp(end, "/apps")) {
        if (target->pending_http) {
            http_error(c, 409, 10, "request already pending");
            return;
        }
        if (send_json(target, 3, 7, NULL)) {
            http_error(c, 503, 1, "device unavailable");
            return;
        }
        target->pending_http = c;
        c->request_node = target;
        c->deadline = gw_mono_ms() + 10000;
        lws_set_timeout(c->wsi, PENDING_TIMEOUT_HTTP_CONTENT, 15);
        return;
    }
    if (!c->post && !strcmp(end, "/restart")) {
        if (send_json(target, 3, 11, NULL))
            http_error(c, 503, 1, "device unavailable");
        else
            http_reply(c, 200, "{\"error\":0}", 11);
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
        size_t os_len = strlen(target->os);
        int c_client = os_len >= 2 && !strcmp(target->os + os_len - 2, "-c");
        if (c_client && (!strcmp(end, "/switchapp") || gw_integer(j, "srcPort0") ||
                         *gw_string(j, "protocol0"))) {
            json_object_put(j);
            http_error(c, 501, 1, "this client supports querying and adding rules only");
            return;
        }
        int result = send_json(target, 3, !strcmp(end, "/app") ? 9 : 10, j);
        json_object_put(j);
        if (result)
            http_error(c, 503, 1, "device unavailable");
        else
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
    if (lws_get_vhost(wsi) != g.ws_vhost)
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
        if (method != LWSHUMETH_GET && method != LWSHUMETH_POST &&
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
         "  [--port 27183] [--apiport 10008] [--database FILE]\n"
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
        case 'm':
        case 't':
        case 'r':
            if (gw_decimal(optarg, &value) || value > 86400 || !value)
                return -1;
            if (option == 'p' || option == 'q') {
                if (value > 65535)
                    return -1;
                if (option == 'p')
                    g.ws_port = (unsigned)value;
                else
                    g.api_port = (unsigned)value;
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
    if (optind != argc || g.ws_port == g.api_port || !*g.database)
        return -1;
    if (!*g.api_bind)
        strcpy(g.api_bind, g.bind);
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
    char automatic_ca[4096];
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
    info.iface = g.api_bind;
    info.port = (int)g.api_port;
    info.vhost_name = "fastp2p-api";
    g.api_vhost = lws_create_vhost(g.context, &info);
    if (!g.ws_vhost || !g.api_vhost) {
        fputs("Cannot load TLS certificate/key or bind HTTPS/WSS ports\n", stderr);
        goto failed;
    }
    g.started_ms = gw_mono_ms();
    printf("{\"event\":\"ready\",\"version\":\"%s\",\"wss\":%u,\"api\":%u}\n", GW_VERSION,
           g.ws_port, g.api_port);
    fflush(stdout);
    lws_sul_schedule(g.context, 0, &g.tick, tick, 10000);
    uint64_t end = g.run_seconds ? gw_mono_ms() + (uint64_t)g.run_seconds * 1000 : 0;
    int result = 0;
    while (!stopping && (!end || gw_mono_ms() < end))
        if (lws_service(g.context, 0) < 0) {
            result = 1;
            break;
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
