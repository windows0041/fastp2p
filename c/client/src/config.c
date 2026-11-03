#include "fastp2p.h"
#include "update.h"
#include "wire.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int decimal_token(const char *s, uint64_t *value) {
    if (!s || !*s)
        return FASTP2P_EINVAL;
    for (const char *p = s; *p; ++p)
        if (*p < '0' || *p > '9')
            return FASTP2P_EINVAL;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || *end || !v)
        return FASTP2P_EINVAL;
    *value = (uint64_t)v;
    return FASTP2P_OK;
}
int fastp2p_client_create_json(const char *text, const char *token_text, const char *ca,
                            fastp2p_event_fn callback, void *user, fastp2p_client **out) {
    if (!out)
        return FASTP2P_EINVAL;
    *out = NULL;
    if (!text)
        return FASTP2P_EINVAL;
    json_object *root = op_json(text, strlen(text));
    if (!root || !json_object_is_type(root, json_type_object)) {
        if (root)
            json_object_put(root);
        return FASTP2P_EINVAL;
    }
    json_object *network = op_get(root, "network");
    if (network && !json_object_is_type(network, json_type_object)) {
        json_object_put(root);
        return FASTP2P_EINVAL;
    }
    const char *network_strings[] = {"Node", "ServerHost", "DeviceID"};
    for (size_t i = 0; i < sizeof(network_strings) / sizeof(network_strings[0]); ++i) {
        json_object *value = op_get(network, network_strings[i]);
        if (value && (!json_object_is_type(value, json_type_string) ||
                      (size_t)json_object_get_string_len(value) != strlen(json_object_get_string(value)))) {
            json_object_put(root);
            return FASTP2P_EINVAL;
        }
    }
    uint64_t token = op_integer(network, "Token"), port = op_integer(network, "ServerPort"),
             public_port = op_integer(network, "PublicIPPort");
    int rv = FASTP2P_OK;
    if (token_text)
        rv = decimal_token(token_text, &token);
    else if (json_object_is_type(op_get(network, "Token"), json_type_string))
        rv = decimal_token(op_string(network, "Token"), &token);
    if (rv || port > 65535 || public_port > 65535) {
        json_object_put(root);
        return FASTP2P_EINVAL;
    }
    const char *host = op_string(network, "ServerHost");
    const char *ca_file = ca ? ca : op_string(root, "CACertFile");
    json_object *automatic = op_get(network, "AutoNode");
    if (automatic && !json_object_is_type(automatic, json_type_boolean)) {
        json_object_put(root);
        return FASTP2P_EINVAL;
    }
    fastp2p_config cfg = {.struct_size = sizeof(cfg),
                       .abi_version = FASTP2P_ABI_VERSION,
                       .gateway_host = *host ? host : "127.0.0.1",
                       .gateway_port = (uint16_t)port,
                       .node = automatic && json_object_get_boolean(automatic) ? NULL : op_string(network, "Node"),
                       .token = token,
                       .ca_file = *ca_file ? ca_file : NULL,
                       .public_port = (uint16_t)public_port,
                       .on_event = callback,
                       .user = user};
    rv = fastp2p_client_create(&cfg, out);
    /* Android cannot replace its own package, so the embedding app names a
     * writable directory here for staging a downloaded upgrade. */
    const char *update_dir = op_string(root, "UpdateDir");
    if (*update_dir)
        fp_update_set_dir(update_dir);
    const char *device = op_string(network, "DeviceID");
    if (!rv && *device)
        rv = fastp2p_client_set_identity(*out, device);
    json_object *apps = op_get(root, "apps");
    if (!rv && apps && !json_object_is_type(apps, json_type_array))
        rv = FASTP2P_EINVAL;
    for (size_t i = 0; !rv && apps && i < json_object_array_length(apps); ++i) {
        json_object *a = json_object_array_get_idx(apps, i);
        json_object *enabled = op_get(a, "Enabled");
        /* JSON true is the natural spelling, and op_integer reads it as 0, which
         * would silently disable the rule. */
        if (enabled && !(json_object_is_type(enabled, json_type_boolean)
                             ? json_object_get_boolean(enabled)
                             : json_object_get_int64(enabled) != 0))
            continue;
        uint64_t local = op_integer(a, "SrcPort"), dst = op_integer(a, "DstPort");
        const char *transport = op_string(a, "UnderlayProtocol"), *bind_ip = op_string(a, "BindIP");
        if (!local || local > 65535 || !dst || dst > 65535 ||
            (*transport && strcmp(transport, "tcp") && strcmp(transport, "quic"))) {
            rv = FASTP2P_EINVAL;
            break;
        }
        fastp2p_forward f = {.struct_size = sizeof(f),
                          .name = op_string(a, "AppName"),
                          .bind_ip = *bind_ip ? bind_ip : NULL,
                          .local_port = (uint16_t)local,
                          .peer_node = op_string(a, "PeerNode"),
                          .destination_host = op_string(a, "DstHost"),
                          .destination_port = (uint16_t)dst,
                          .protocol = op_string(a, "Protocol"),
                          .transport = (*transport ? !strcmp(transport, "tcp")
                                                   : (op_integer(a, "PunchPriority") & 2) != 0)
                                           ? FASTP2P_TRANSPORT_TCP
                                           : FASTP2P_TRANSPORT_QUIC,
                          .relay_node = op_string(a, "RelayNode")};
        rv = fastp2p_client_add_forward(*out, &f, NULL);
    }
    json_object *proxies = op_get(root, "socks5");
    if (!rv && proxies && !json_object_is_type(proxies, json_type_array))
        rv = FASTP2P_EINVAL;
    for (size_t i = 0; !rv && proxies && i < json_object_array_length(proxies); ++i) {
        json_object *p = json_object_array_get_idx(proxies, i);
        if (!json_object_is_type(p, json_type_object)) {
            rv = FASTP2P_EINVAL;
            break;
        }
        const char *string_fields[] = {"Name",     "PeerNode", "BindIP",     "UnderlayProtocol",
                                       "Username", "Password", "PasswordEnv"};
        for (size_t q = 0; q < sizeof(string_fields) / sizeof(string_fields[0]); ++q) {
            json_object *v = op_get(p, string_fields[q]);
            if (v && (!json_object_is_type(v, json_type_string) ||
                      (size_t)json_object_get_string_len(v) != strlen(json_object_get_string(v)))) {
                rv = FASTP2P_EINVAL;
                break;
            }
        }
        if (rv)
            break;
        if (op_get(p, "Enabled") && !json_object_get_boolean(op_get(p, "Enabled")))
            continue;
        const char *transport = op_string(p, "UnderlayProtocol"), *bind_ip = op_string(p, "BindIP");
        uint64_t port = op_integer(p, "SrcPort");
        if (!port || port > 65535 ||
            (*transport && strcmp(transport, "tcp") && strcmp(transport, "quic"))) {
            rv = FASTP2P_EINVAL;
            break;
        }
        const char *password = op_string(p, "Password"), *variable = op_string(p, "PasswordEnv");
        if (*variable) {
            password = getenv(variable);
            if (!password || !*password) {
                rv = FASTP2P_EINVAL;
                break;
            }
        }
        fastp2p_socks5 proxy = {.struct_size = sizeof(proxy),
                             .name = op_string(p, "Name"),
                             .bind_ip = *bind_ip ? bind_ip : NULL,
                             .local_port = (uint16_t)port,
                             .peer_node = op_string(p, "PeerNode"),
                             .transport = !strcmp(transport, "tcp") ? FASTP2P_TRANSPORT_TCP
                                                                    : FASTP2P_TRANSPORT_QUIC,
                             .username = op_string(p, "Username"),
                             .password = password};
        rv = fastp2p_client_add_socks5(*out, &proxy, NULL);
    }
    json_object_put(root);
    if (rv && *out) {
        fastp2p_client_destroy(*out);
        *out = NULL;
    }
    return rv;
}
