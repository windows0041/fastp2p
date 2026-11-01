#ifndef OPENP2P_H
#define OPENP2P_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define OP2P_ABI_VERSION 1u
#define OP2P_VERSION "0.3.0"
#if defined(_WIN32) && !defined(OP2P_STATIC)
#if defined(OP2P_BUILDING_LIBRARY)
#define OP2P_API __declspec(dllexport)
#else
#define OP2P_API __declspec(dllimport)
#endif
#elif defined(__GNUC__)
#define OP2P_API __attribute__((visibility("default")))
#else
#define OP2P_API
#endif
typedef struct op2p_client op2p_client;
typedef enum {
    OP2P_OK = 0,
    OP2P_EINVAL = -1,
    OP2P_ENOMEM = -2,
    OP2P_ESTATE = -3,
    OP2P_EIO = -4,
    OP2P_ELIMIT = -5
} op2p_result;
typedef enum { OP2P_STOPPED, OP2P_CONNECTING, OP2P_ONLINE, OP2P_RECONNECTING } op2p_state;
typedef enum {
    OP2P_EVENT_STATE,
    OP2P_EVENT_ERROR,
    OP2P_EVENT_TUNNEL,
    OP2P_EVENT_FORWARD,
    OP2P_EVENT_HEARTBEAT
} op2p_event_type;
typedef enum { OP2P_TRANSPORT_TCP = 1, OP2P_TRANSPORT_QUIC = 2 } op2p_transport;
typedef struct {
    size_t struct_size;
    op2p_event_type type;
    op2p_state state;
    uint64_t id;
    int code;
    const char *message; /* Borrowed, valid only during the callback. No secrets. */
} op2p_event;
typedef void (*op2p_event_fn)(op2p_client *, const op2p_event *, void *user);
typedef struct {
    size_t struct_size;
    uint32_t abi_version;
    const char *gateway_host;
    uint16_t gateway_port; /* zero = 27183 */
    const char *node;      /* 8..31 ASCII letters, digits, underscore or hyphen */
    uint64_t token;
    const char *ca_file;  /* NULL = system roots; chain + hostname always verified */
    uint16_t public_port; /* Optional direct TCP listener, zero = ephemeral */
    op2p_event_fn on_event;
    void *user;
} op2p_config;
typedef struct {
    size_t struct_size;
    const char *name;
    const char *bind_ip; /* NULL = 127.0.0.1; explicit address to expose a port */
    uint16_t local_port;
    const char *peer_node;
    const char *destination_host;
    uint16_t destination_port;
    const char *protocol;     /* tcp or udp */
    op2p_transport transport; /* TCP punch or UDP punch + QUIC */
} op2p_forward;

typedef struct {
    size_t struct_size;
    const char *name;
    const char *bind_ip; /* NULL = 127.0.0.1 */
    uint16_t local_port;
    const char *peer_node; /* Exit node must run C client >= 0.3.0. */
    op2p_transport transport;
    const char *username; /* NULL/empty and password empty = no authentication. */
    const char *password; /* If supplied, both strings must be 1..255 bytes. */
} op2p_socks5;

/* All functions for an instance are called on one owning thread. No worker
 * threads are created. Strings are copied by create/add_forward. Event callbacks
 * may request stop, but must not reenter step, destroy, or change forwards.
 * struct_size + abi_version permit extending the API without exposing internals. */
OP2P_API int op2p_client_create(const op2p_config *config, op2p_client **out);
/* Parse the same UTF-8 configuration as the CLI. Override strings may be NULL.
 * Token is decimal text to preserve all 64 bits through mobile language bindings. */
OP2P_API int op2p_client_create_json(const char *json_utf8, const char *token_override,
                                     const char *ca_override, op2p_event_fn on_event, void *user,
                                     op2p_client **out);
OP2P_API int op2p_client_add_forward(op2p_client *client, const op2p_forward *forward,
                                     uint64_t *id);
/* RFC 1928 CONNECT / UDP ASSOCIATE, RFC 1929 optional authentication.
 * Targets: IPv4 or DNS names resolved at the exit. BIND/IPv6/UDP fragments rejected.
 * Strings copied; listener lifetime matches add_forward. Existing ABI 1 is preserved. */
OP2P_API int op2p_client_add_socks5(op2p_client *client, const op2p_socks5 *proxy, uint64_t *id);
OP2P_API int op2p_client_start(op2p_client *client);
/* Service once, waiting at most min(max_wait_ms, 10) milliseconds for WSS events.
 * Call repeatedly while running. Network/peer errors are reported via events;
 * reconnect is automatic. A zero wait is nonblocking. */
OP2P_API int op2p_client_step(op2p_client *client, unsigned max_wait_ms);
OP2P_API int op2p_client_stop(op2p_client *client);
OP2P_API void op2p_client_destroy(op2p_client *client);
OP2P_API op2p_state op2p_client_state(const op2p_client *client);
OP2P_API const char *op2p_client_last_error(const op2p_client *client);
OP2P_API uint32_t op2p_abi_version(void);
OP2P_API const char *op2p_version(void);
#ifdef __cplusplus
}
#endif
#endif
