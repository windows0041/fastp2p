#ifndef FASTP2P_H
#define FASTP2P_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define FASTP2P_ABI_VERSION 1u
#define FASTP2P_VERSION "1.0.1"
#if defined(_WIN32) && !defined(FASTP2P_STATIC)
#if defined(FASTP2P_BUILDING_LIBRARY)
#define FASTP2P_API __declspec(dllexport)
#else
#define FASTP2P_API __declspec(dllimport)
#endif
#elif defined(__GNUC__)
#define FASTP2P_API __attribute__((visibility("default")))
#else
#define FASTP2P_API
#endif
typedef struct fastp2p_client fastp2p_client;
typedef enum {
    FASTP2P_OK = 0,
    FASTP2P_EINVAL = -1,
    FASTP2P_ENOMEM = -2,
    FASTP2P_ESTATE = -3,
    FASTP2P_EIO = -4,
    FASTP2P_ELIMIT = -5
} fastp2p_result;
typedef enum { FASTP2P_STOPPED, FASTP2P_CONNECTING, FASTP2P_ONLINE, FASTP2P_RECONNECTING } fastp2p_state;
typedef enum {
    FASTP2P_EVENT_STATE,
    FASTP2P_EVENT_ERROR,
    FASTP2P_EVENT_TUNNEL,
    FASTP2P_EVENT_FORWARD,
    FASTP2P_EVENT_HEARTBEAT
} fastp2p_event_type;
typedef enum { FASTP2P_TRANSPORT_TCP = 1, FASTP2P_TRANSPORT_QUIC = 2 } fastp2p_transport;
typedef struct {
    size_t struct_size;
    fastp2p_event_type type;
    fastp2p_state state;
    uint64_t id;
    int code;
    const char *message; /* Borrowed, valid only during the callback. No secrets. */
} fastp2p_event;
typedef void (*fastp2p_event_fn)(fastp2p_client *, const fastp2p_event *, void *user);
typedef struct {
    size_t struct_size;
    uint32_t abi_version;
    const char *gateway_host;
    uint16_t gateway_port; /* zero = 27183 */
    const char *node;      /* 8..31 ASCII; NULL/empty = hostname-based automatic name */
    uint64_t token;
    const char *ca_file;  /* NULL = system roots; chain + hostname always verified */
    uint16_t public_port; /* Optional direct TCP listener, zero = ephemeral */
    fastp2p_event_fn on_event;
    void *user;
} fastp2p_config;

/* Automatic identity: persist the returned 32 lowercase hex digits in the host
 * application's private configuration, then set them before start on later runs.
 * A new C gateway assigns a unique name and returns it during authentication.
 * No file-system writes are performed by the C library itself. */
FASTP2P_API int fastp2p_client_set_identity(fastp2p_client *, const char *device_id);
/* Borrowed strings, valid until destroy; node contents can change on login. */
FASTP2P_API const char *fastp2p_client_device_id(const fastp2p_client *);
FASTP2P_API const char *fastp2p_client_node(const fastp2p_client *);
typedef struct {
    size_t struct_size;
    const char *name;
    const char *bind_ip; /* NULL = 127.0.0.1; explicit address to expose a port */
    uint16_t local_port;
    const char *peer_node;
    const char *destination_host;
    uint16_t destination_port;
    const char *protocol;     /* tcp or udp */
    fastp2p_transport transport; /* TCP punch or UDP punch + QUIC */
} fastp2p_forward;

typedef struct {
    size_t struct_size;
    const char *name;
    const char *bind_ip; /* NULL = 127.0.0.1 */
    uint16_t local_port;
    const char *peer_node; /* Exit node must run fastp2p 1.x. */
    fastp2p_transport transport;
    const char *username; /* NULL/empty and password empty = no authentication. */
    const char *password; /* If supplied, both strings must be 1..255 bytes. */
} fastp2p_socks5;

/* All functions for an instance are called on one owning thread. No worker
 * threads are created. Strings are copied by create/add_forward. Event callbacks
 * may request stop, but must not reenter step, destroy, or change forwards.
 * struct_size + abi_version permit extending the API without exposing internals. */
FASTP2P_API int fastp2p_client_create(const fastp2p_config *config, fastp2p_client **out);
/* Parse the same UTF-8 configuration as the CLI. Override strings may be NULL.
 * Token is decimal text to preserve all 64 bits through mobile language bindings. */
FASTP2P_API int fastp2p_client_create_json(const char *json_utf8, const char *token_override,
                                     const char *ca_override, fastp2p_event_fn on_event, void *user,
                                     fastp2p_client **out);
FASTP2P_API int fastp2p_client_add_forward(fastp2p_client *client, const fastp2p_forward *forward,
                                     uint64_t *id);
/* RFC 1928 CONNECT / UDP ASSOCIATE, RFC 1929 optional authentication.
 * Targets: IPv4 or DNS names resolved at the exit. BIND/IPv6/UDP fragments rejected.
 * Strings copied; listener lifetime matches add_forward. Existing ABI 1 is preserved. */
FASTP2P_API int fastp2p_client_add_socks5(fastp2p_client *client, const fastp2p_socks5 *proxy, uint64_t *id);
FASTP2P_API int fastp2p_client_start(fastp2p_client *client);
/* Service once, waiting at most min(max_wait_ms, 10) milliseconds for WSS events.
 * Call repeatedly while running. Network/peer errors are reported via events;
 * reconnect is automatic. A zero wait is nonblocking. */
FASTP2P_API int fastp2p_client_step(fastp2p_client *client, unsigned max_wait_ms);
FASTP2P_API int fastp2p_client_stop(fastp2p_client *client);
FASTP2P_API void fastp2p_client_destroy(fastp2p_client *client);
FASTP2P_API fastp2p_state fastp2p_client_state(const fastp2p_client *client);
FASTP2P_API const char *fastp2p_client_last_error(const fastp2p_client *client);
FASTP2P_API uint32_t fastp2p_abi_version(void);
FASTP2P_API const char *fastp2p_version(void);
#ifdef __cplusplus
}
#endif
#endif
