#include "sdwan.h"
#include "platform.h"
#include <string.h>

static uint32_t prefix_mask(unsigned bits) {
    return bits ? UINT32_MAX << (32 - bits) : 0;
}

static int unicast(uint32_t address) {
    return address >= UINT32_C(0x01000000) && (address >> 24) != 127 &&
           (address >> 16) != UINT32_C(0xa9fe) && address < UINT32_C(0xe0000000);
}

static int parse_address(const char *text, uint32_t *address) {
    op_addr parsed;
    if (op_addr_from_text(&parsed, text, 0) || op_addr_family(&parsed) != AF_INET)
        return -1;
    *address = ntohl(parsed.u.in.sin_addr.s_addr);
    return unicast(*address) ? 0 : -1;
}

static int parse_prefix(const char *text, uint32_t *network, unsigned *width) {
    const char *slash = strchr(text, '/');
    char address[16];
    if (!slash || slash == text || (size_t)(slash - text) >= sizeof(address))
        return -1;
    size_t length = (size_t)(slash - text);
    memcpy(address, text, length);
    address[length] = '\0';
    const char *bits = slash + 1;
    if (*bits < '1' || *bits > '9')
        return -1;
    unsigned value = (unsigned)(*bits++ - '0');
    if (*bits >= '0' && *bits <= '9')
        value = 10 * value + (unsigned)(*bits++ - '0');
    if (*bits || value > 32 || parse_address(address, network) || (*network & ~prefix_mask(value)))
        return -1;
    *width = value;
    return 0;
}

static const char *string_value(json_object *value) {
    if (!json_object_is_type(value, json_type_string))
        return NULL;
    const char *text = json_object_get_string(value);
    return strlen(text) == (size_t)json_object_get_string_len(value) ? text : NULL;
}

static const char *get_string(json_object *object, const char *field) {
    json_object *value;
    return json_object_object_get_ex(object, field, &value) ? string_value(value) : NULL;
}

static int add_route(fp_sdwan *state, uint32_t network, unsigned bits, int owner) {
    for (unsigned i = 0; i < state->route_count; ++i)
        if (state->routes[i].network == network && state->routes[i].bits == bits)
            return -1;
    if (state->route_count == FP_SDWAN_MAX_ROUTES)
        return -1;
    state->routes[state->route_count++] = (fp_sdwan_route){network, bits, owner};
    return 0;
}

static int add_routes(fp_sdwan *state, json_object *object, const char *field, int owner,
                      uint32_t subnet, unsigned subnet_bits) {
    json_object *routes;
    if (!json_object_object_get_ex(object, field, &routes))
        return 0;
    if (!json_object_is_type(routes, json_type_array) ||
        json_object_array_length(routes) > FP_SDWAN_MAX_ROUTES)
        return -1;
    for (size_t i = 0; i < json_object_array_length(routes); ++i) {
        const char *text = string_value(json_object_array_get_idx(routes, i));
        uint32_t network;
        unsigned bits;
        if (!text || parse_prefix(text, &network, &bits))
            return -1;
        uint32_t common = prefix_mask(bits < subnet_bits ? bits : subnet_bits);
        if ((network & common) == (subnet & common) || add_route(state, network, bits, owner))
            return -1;
    }
    return 0;
}

static int virtual_address(const char *text, uint32_t subnet, unsigned bits, uint32_t *address) {
    uint32_t mask = prefix_mask(bits);
    return !text || parse_address(text, address) || (*address & mask) != subnet ||
           *address == subnet || *address == (subnet | ~mask) ? -1 : 0;
}

int fp_sdwan_parse(fp_sdwan *state, json_object *config) {
    *state = (fp_sdwan){.fd = -1};
    if (!json_object_is_type(config, json_type_object))
        return -1;
    json_object *value, *peers;
    const char *pool = "10.3.2.0/24";
    uint32_t subnet;
    unsigned bits;
    if (json_object_object_get_ex(config, "Subnet", &value))
        pool = string_value(value);
    if (!pool || parse_prefix(pool, &subnet, &bits) || bits > 30 ||
        virtual_address(get_string(config, "Address"), subnet, bits, &state->address) ||
        !json_object_object_get_ex(config, "Peers", &peers) ||
        !json_object_is_type(peers, json_type_array) || !json_object_array_length(peers) ||
        json_object_array_length(peers) > FP_SDWAN_MAX_PEERS)
        return -1;
    if (add_route(state, state->address, 32, FP_SDWAN_LOCAL) ||
        add_routes(state, config, "LocalRoutes", FP_SDWAN_LOCAL, subnet, bits))
        return -1;
    for (size_t i = 0; i < json_object_array_length(peers); ++i) {
        json_object *peer = json_object_array_get_idx(peers, i);
        if (!json_object_is_type(peer, json_type_object))
            return -1;
        const char *name = get_string(peer, "Node");
        uint32_t address;
        if (!name || !*name || strlen(name) >= sizeof(state->peers[0].node) ||
            virtual_address(get_string(peer, "Address"), subnet, bits, &address) ||
            add_route(state, address, 32, (int)i) ||
            add_routes(state, peer, "Routes", (int)i, subnet, bits))
            return -1;
        for (size_t j = 0; j < i; ++j)
            if (!strcmp(state->peers[j].node, name))
                return -1;
        strcpy(state->peers[i].node, name);
    }
    state->peer_count = (unsigned)json_object_array_length(peers);
    return 0;
}

int fp_sdwan_owner(const fp_sdwan *state, uint32_t address) {
    unsigned longest = 0;
    int owner = FP_SDWAN_NO_ROUTE;
    for (unsigned i = 0; i < state->route_count; ++i) {
        const fp_sdwan_route *route = &state->routes[i];
        if (route->bits > longest && (address & prefix_mask(route->bits)) == route->network) {
            longest = route->bits;
            owner = route->owner;
        }
    }
    return owner;
}

static uint32_t ip_word(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

int fp_sdwan_ipv4(const uint8_t *packet, size_t length, uint32_t *source, uint32_t *destination) {
    if (length < 20 || length > FP_SDWAN_MTU || packet[0] >> 4 != 4 ||
        (packet[0] & 15) < 5 || (size_t)(packet[0] & 15) * 4 > length ||
        ((size_t)packet[2] << 8 | packet[3]) != length)
        return -1;
    *source = ip_word(packet + 12);
    *destination = ip_word(packet + 16);
    return unicast(*source) && unicast(*destination) ? 0 : -1;
}

#if defined(__linux__) && !defined(__ANDROID__)
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define TUN_NAME "fastp2p0"
extern char **environ;

static const char *ip_command(void) {
    static const char *const paths[] = {"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i)
        if (!access(paths[i], X_OK))
            return paths[i];
    return NULL;
}

static int run_ip(const char *path, char *const *arguments) {
    pid_t process;
    if (posix_spawn(&process, path, NULL, NULL, arguments, environ))
        return -1;
    int status;
    while (waitpid(process, &status, 0) < 0)
        if (errno != EINTR)
            return -1;
    return !WIFEXITED(status) || WEXITSTATUS(status) ? -1 : 0;
}

static int open_tun(const char *name) {
    int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct ifreq request = {0};
    request.ifr_flags = (short)(IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL);
    if (name)
        strcpy(request.ifr_name, name);
    if (ioctl(fd, TUNSETIFF, &request)) {
        close(fd);
        return -1;
    }
    return fd;
}

const char *fp_sdwan_check(void) {
    if (!ip_command())
        return "SD-WAN requires iproute2 (ip)";
    if (access("/dev/net/tun", R_OK | W_OK))
        return "SD-WAN requires /dev/net/tun and the Linux TUN driver";
    int fd = open_tun(NULL);
    if (fd < 0)
        return "SD-WAN cannot create a TUN interface; check the kernel driver and CAP_NET_ADMIN";
    close(fd);
    return NULL;
}

static void cidr(char text[19], uint32_t address, unsigned bits) {
    snprintf(text, 19, "%u.%u.%u.%u/%u", (unsigned)(address >> 24),
             (unsigned)((address >> 16) & 255), (unsigned)((address >> 8) & 255),
             (unsigned)(address & 255), bits);
}

const char *fp_sdwan_start(fp_sdwan *state) {
    const char *ip = ip_command();
    if (!ip)
        return "SD-WAN requires iproute2 (ip)";
    state->fd = open_tun(TUN_NAME);
    if (state->fd < 0)
        return "SD-WAN cannot create fastp2p0; check /dev/net/tun, CAP_NET_ADMIN and the interface name";
    char address[19], mtu[8];
    cidr(address, state->address, 32);
    snprintf(mtu, sizeof(mtu), "%u", FP_SDWAN_MTU);
    char *link[] = {"ip", "link", "set", "dev", TUN_NAME, "mtu", mtu, "up", NULL};
    char *assign[] = {"ip", "-4", "address", "add", address, "dev", TUN_NAME, NULL};
    if (run_ip(ip, link) || run_ip(ip, assign)) {
        fp_sdwan_stop(state);
        return "SD-WAN could not configure fastp2p0";
    }
    for (unsigned i = 0; i < state->route_count; ++i) {
        const fp_sdwan_route *route = &state->routes[i];
        if (route->owner < 0)
            continue;
        cidr(address, route->network, route->bits);
        char *add[] = {"ip", "-4", "route", "add", address, "dev", TUN_NAME, "proto", "static", NULL};
        if (run_ip(ip, add)) {
            fp_sdwan_stop(state);
            return "SD-WAN route installation failed; check for an existing route";
        }
    }
    return NULL;
}

void fp_sdwan_stop(fp_sdwan *state) {
    if (state->fd >= 0)
        close(state->fd);
    state->fd = -1;
}

int fp_sdwan_read(fp_sdwan *state, uint8_t packet[FP_SDWAN_MTU]) {
    return (int)read(state->fd, packet, FP_SDWAN_MTU);
}

void fp_sdwan_write(fp_sdwan *state, const uint8_t *packet, size_t length) {
    (void)write(state->fd, packet, length);
}
#elif defined(__ANDROID__)
#include <fcntl.h>
#include <unistd.h>
const char *fp_sdwan_check(void) {
    return "Android SD-WAN requires a TUN supplied by the app";
}
const char *fp_sdwan_start(fp_sdwan *state) {
    return state->fd >= 0 ? NULL : fp_sdwan_check();
}
void fp_sdwan_stop(fp_sdwan *state) {
    if (state->fd >= 0)
        close(state->fd);
    state->fd = -1;
}
int fp_sdwan_read(fp_sdwan *state, uint8_t packet[FP_SDWAN_MTU]) {
    return (int)read(state->fd, packet, FP_SDWAN_MTU);
}
void fp_sdwan_write(fp_sdwan *state, const uint8_t *packet, size_t length) {
    (void)write(state->fd, packet, length);
}
#elif !defined(_WIN32)
const char *fp_sdwan_check(void) {
    return "SD-WAN TUN is unavailable on this platform";
}
const char *fp_sdwan_start(fp_sdwan *state) {
    (void)state;
    return fp_sdwan_check();
}
void fp_sdwan_stop(fp_sdwan *state) { (void)state; }
int fp_sdwan_read(fp_sdwan *state, uint8_t packet[FP_SDWAN_MTU]) {
    (void)state;
    (void)packet;
    return -1;
}
void fp_sdwan_write(fp_sdwan *state, const uint8_t *packet, size_t length) {
    (void)state;
    (void)packet;
    (void)length;
}
#endif

int fp_sdwan_attach(fp_sdwan *state, int fd) {
#ifdef __ANDROID__
    if (!state || state->fd >= 0 || fd < 0)
        return -1;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK))
        return -1;
    state->fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    return state->fd >= 0 ? 0 : -1;
#else
    (void)state;
    (void)fd;
    return -1;
#endif
}
