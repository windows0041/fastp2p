#ifndef OP2P_PLATFORM_H
#define OP2P_PLATFORM_H
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#if defined(__ANDROID__)
#define OP2P_PLATFORM_OS "android-c"
#elif defined(_WIN32)
#define OP2P_PLATFORM_OS "windows-c"
#elif defined(__APPLE__)
#define OP2P_PLATFORM_OS "darwin-c"
#else
#define OP2P_PLATFORM_OS "linux-c"
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
int op_platform_init(void);
int op_hostname(char *out, size_t capacity);
void op_once_run(op_once *once, void (*function)(void));
uint64_t op_monotonic_ns(void);
uint64_t op_wall_ns(void);
void op_sleep_ms(unsigned milliseconds);
op_socket op_socket_open(int family, int type, int protocol);
op_socket op_accept(op_socket fd, struct sockaddr *address, op_socklen *length);
int op_close(op_socket fd);
int op_bind(op_socket fd, const struct sockaddr *address, op_socklen length);
int op_connect(op_socket fd, const struct sockaddr *address, op_socklen length);
int op_listen(op_socket fd, int backlog);
int op_getsockname(op_socket fd, struct sockaddr *address, op_socklen *length);
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
