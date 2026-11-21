#ifndef FASTP2P_SDWAN_H
#define FASTP2P_SDWAN_H

#include <json-c/json.h>
#include <stdint.h>
#include <stddef.h>

#define FP_SDWAN_MTU 1280
#define FP_SDWAN_LOCAL (-1)
#define FP_SDWAN_NO_ROUTE (-2)
#define FP_SDWAN_MAX_PEERS 32
#define FP_SDWAN_MAX_ROUTES 128

typedef struct {
    uint32_t network;
    unsigned bits;
    int owner;
} fp_sdwan_route;

typedef struct {
    char node[32];
    int app_index;
} fp_sdwan_peer;

typedef struct {
    int fd;
#ifdef _WIN32
    struct fp_sdwan_windows *windows;
    char error[160];
#endif
    int central, center_index;
    char center[32];
    uint32_t address;
    fp_sdwan_peer peers[FP_SDWAN_MAX_PEERS];
    unsigned peer_count;
    fp_sdwan_route routes[FP_SDWAN_MAX_ROUTES];
    unsigned route_count;
} fp_sdwan;

/* Returns 0 on success; callers allocate the optional configuration. */
int fp_sdwan_parse(fp_sdwan *state, json_object *config);
int fp_sdwan_owner(const fp_sdwan *state, uint32_t address);
int fp_sdwan_ipv4(const uint8_t *packet, size_t length, uint32_t *source, uint32_t *destination);

static inline int fp_sdwan_active(const fp_sdwan *state) {
#ifdef _WIN32
    return state && state->windows;
#else
    return state && state->fd >= 0;
#endif
}

const char *fp_sdwan_check(void);
const char *fp_sdwan_start(fp_sdwan *state);
int fp_sdwan_attach(fp_sdwan *state, int fd);
void fp_sdwan_stop(fp_sdwan *state);
int fp_sdwan_read(fp_sdwan *state, uint8_t packet[FP_SDWAN_MTU]);
void fp_sdwan_write(fp_sdwan *state, const uint8_t *packet, size_t length);

#endif
