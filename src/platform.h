#ifndef FASTP2P_PLATFORM_H
#define FASTP2P_PLATFORM_H
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#if defined(__ANDROID__)
#define FASTP2P_PLATFORM_OS "android-c"
#elif defined(_WIN32)
#define FASTP2P_PLATFORM_OS "windows-c"
#elif defined(__APPLE__)
#if defined(__aarch64__) || defined(__arm64__)
#define FASTP2P_PLATFORM_OS "darwin-arm64-c"
#else
#define FASTP2P_PLATFORM_OS "darwin-x86_64-c"
#endif
#else
#if defined(__x86_64__)
#define FASTP2P_PLATFORM_OS "linux-x86_64-c"
#elif defined(__aarch64__)
#define FASTP2P_PLATFORM_OS "linux-aarch64-c"
#elif defined(__arm__) && defined(__ARM_ARCH) && __ARM_ARCH >= 7
#define FASTP2P_PLATFORM_OS "linux-armv7-c"
#elif defined(__i386__)
#define FASTP2P_PLATFORM_OS "linux-i686-c"
#elif defined(__riscv) && __riscv_xlen == 64
#define FASTP2P_PLATFORM_OS "linux-riscv64-c"
#elif defined(__s390x__)
#define FASTP2P_PLATFORM_OS "linux-s390x-c"
#elif defined(__powerpc64__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define FASTP2P_PLATFORM_OS "linux-ppc64le-c"
#elif (defined(__mips64) || defined(__mips64__)) && defined(__MIPSEL__)
#define FASTP2P_PLATFORM_OS "linux-mips64el-c"
#else
#define FASTP2P_PLATFORM_OS "linux-c"
#endif
#endif
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <basetsd.h>
typedef SSIZE_T op_ssize;
typedef int op_socklen;
typedef WSAPOLLFD op_pollfd;
typedef INIT_ONCE op_once;
#define OP_ONCE_INIT INIT_ONCE_STATIC_INIT
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
typedef ssize_t op_ssize;
typedef socklen_t op_socklen;
typedef struct pollfd op_pollfd;
typedef pthread_once_t op_once;
#define OP_ONCE_INIT PTHREAD_ONCE_INIT
#endif
typedef intptr_t op_socket;
#define OP_INVALID_SOCKET ((op_socket) - 1)
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
/* One endpoint of either family. The socket calls below already take a sockaddr
 * plus its real length, so dual-stack work is a text/address concern, not a
 * socket-API concern: every address the client stores becomes an op_addr or its
 * canonical text, and lengths travel with it instead of being assumed. */
typedef struct {
    union {
        struct sockaddr sa;
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
        struct sockaddr_storage storage;
    } u;
    op_socklen len;
} op_addr;
#define OP_ADDR_TEXT 46 /* fits IPv6 text; also fits IPv4 text */
#define OP_FAM_V4 0
#define OP_FAM_V6 1
#define OP_FAM_COUNT 2
/* 0 = IPv4, 1 = IPv6, -1 = not a supported family. */
int op_family_index(int family);
int op_index_family(int index);
/* Fills the endpoint from canonical text (no brackets), inferring the family.
 * Port is host order. Returns 0 on success. */
int op_addr_from_text(op_addr *out, const char *text, uint16_t port);
/* Canonical text, no brackets; URL callers add them for IPv6. */
int op_addr_text(const op_addr *a, char *out, size_t capacity);
int op_addr_family(const op_addr *a);
uint16_t op_addr_port(const op_addr *a);
void op_addr_set_port(op_addr *a, uint16_t port);
void op_addr_copy(op_addr *dst, const op_addr *src);
/* Same endpoint ignoring the port. */
int op_addr_equal(const op_addr *a, const op_addr *b);
/* Collapses an IPv4-mapped IPv6 endpoint into IPv4 so a dual-stack listener
 * cannot present one peer as two different ones. */
void op_addr_normalize(op_addr *a);
/* 1 when a peer could reach this address over the internet: IPv4 global
 * unicast, or IPv6 global/ULA. Loopback, unspecified, link-local and the other
 * IPv4-special ranges give 0. */
int op_addr_routable(const op_addr *a);
/* 1 for loopback or a site-local range (RFC 1918, fe80::/10, fc00::/7): a peer
 * holding one of these is reachable without punching through a NAT. */
int op_addr_private(const op_addr *a);
/* Local and remote endpoints of a socket, normalized. These replace the old
 * habit of reading the family-independent port alone: a socket that connected
 * over IPv6 reports its IPv6 source, which the text field must be able to hold. */
int op_addr_socketname(op_socket fd, op_addr *out);
int op_addr_peername(op_socket fd, op_addr *out);
int op_platform_init(void);
int op_hostname(char *out, size_t capacity);
void op_once_run(op_once *once, void (*function)(void));
uint64_t op_monotonic_ns(void);
uint64_t op_wall_ns(void);
void op_sleep_ms(unsigned milliseconds);
op_socket op_socket_open(int family, int type, int protocol);
op_socket op_accept(op_socket fd, struct sockaddr *address, op_socklen *length);
int op_close(op_socket fd);
int op_shutdown_write(op_socket fd);
int op_bind(op_socket fd, const struct sockaddr *address, op_socklen length);
int op_connect(op_socket fd, const struct sockaddr *address, op_socklen length);
int op_listen(op_socket fd, int backlog);
int op_getsockname(op_socket fd, struct sockaddr *address, op_socklen *length);
int op_getpeername(op_socket fd, struct sockaddr *address, op_socklen *length);
int op_setsockopt(op_socket fd, int level, int option, const void *value, op_socklen length);
int op_getsockopt(op_socket fd, int level, int option, void *value, op_socklen *length);
int op_reuse_socket(op_socket fd);
int op_address_equal(const struct sockaddr *a, op_socklen alen, const struct sockaddr *b,
                     op_socklen blen);
int op_poll(op_pollfd *fds, unsigned count, int timeout);
op_ssize op_send(op_socket fd, const void *data, size_t length, int flags);
op_ssize op_recv(op_socket fd, void *data, size_t length, int flags);
op_ssize op_sendto(op_socket fd, const void *data, size_t length, int flags,
                   const struct sockaddr *peer, op_socklen peer_length);
op_ssize op_recvfrom(op_socket fd, void *data, size_t length, int flags, struct sockaddr *peer,
                     op_socklen *peer_length);
#endif
