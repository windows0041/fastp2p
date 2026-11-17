#include "platform.h"
#include <limits.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <mstcpip.h>
#include <mswsock.h>
#endif
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif
#ifdef _WIN32
static int socket_error(void) {
    switch (WSAGetLastError()) {
    case WSAEWOULDBLOCK:
        errno = EAGAIN;
        break;
    case WSAEINPROGRESS:
    case WSAEALREADY:
        errno = EINPROGRESS;
        break;
    case WSAEINTR:
        errno = EINTR;
        break;
    case WSAECONNREFUSED:
        errno = ECONNREFUSED;
        break;
    case WSAECONNRESET:
        errno = ECONNRESET;
        break;
    case WSAECONNABORTED:
        errno = ECONNABORTED;
        break;
    case WSAETIMEDOUT:
        errno = ETIMEDOUT;
        break;
    case WSAEADDRINUSE:
        errno = EADDRINUSE;
        break;
    case WSAENETUNREACH:
        errno = ENETUNREACH;
        break;
    case WSAEHOSTUNREACH:
        errno = EHOSTUNREACH;
        break;
    case WSAENOTCONN:
        errno = ENOTCONN;
        break;
    default:
        errno = EIO;
        break;
    }
    return -1;
}
struct once_call {
    void (*function)(void);
};
static BOOL CALLBACK once_callback(PINIT_ONCE once, PVOID value, PVOID *context) {
    (void)once;
    (void)context;
    ((struct once_call *)value)->function();
    return TRUE;
}
void op_once_run(op_once *once, void (*function)(void)) {
    struct once_call call = {function};
    InitOnceExecuteOnce(once, once_callback, &call, NULL);
}
static op_once startup_once = OP_ONCE_INIT;
static int startup_error;
static void startup(void) {
    WSADATA data;
    startup_error = WSAStartup(MAKEWORD(2, 2), &data);
}
int op_platform_init(void) {
    op_once_run(&startup_once, startup);
    return startup_error ? -1 : 0;
}
static int nonblocking(op_socket fd) {
    u_long enabled = 1;
    return ioctlsocket((SOCKET)fd, FIONBIO, &enabled) ? socket_error() : 0;
}
#else
void op_once_run(op_once *once, void (*function)(void)) {
    pthread_once(once, function);
}
int op_platform_init(void) {
    return 0;
}
static int nonblocking(op_socket fd) {
    if (fcntl((int)fd, F_SETFL, fcntl((int)fd, F_GETFL, 0) | O_NONBLOCK) < 0 ||
        fcntl((int)fd, F_SETFD, FD_CLOEXEC) < 0)
        return -1;
#ifdef SO_NOSIGPIPE
    int one = 1;
    if (setsockopt((int)fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)))
        return -1;
#endif
    return 0;
}
#endif
int op_hostname(char *out, size_t capacity) {
    if (!out || capacity < 2 || capacity > INT_MAX)
        return -1;
#ifdef _WIN32
    WCHAR name[256];
    DWORD size = sizeof(name) / sizeof(name[0]);
    if (!GetComputerNameExW(ComputerNameDnsHostname, name, &size) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name, -1, out, (int)capacity,
                             NULL, NULL))
        return -1;
#else
    if (gethostname(out, capacity - 1))
        return -1;
    out[capacity - 1] = 0;
#endif
    return *out ? 0 : -1;
}
uint64_t op_monotonic_ns(void) {
#ifdef _WIN32
    LARGE_INTEGER counter, frequency;
    QueryPerformanceCounter(&counter);
    QueryPerformanceFrequency(&frequency);
    return (uint64_t)(counter.QuadPart / frequency.QuadPart) * UINT64_C(1000000000) +
           (uint64_t)((counter.QuadPart % frequency.QuadPart) * UINT64_C(1000000000) /
                      (uint64_t)frequency.QuadPart);
#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
#endif
}
uint64_t op_wall_ns(void) {
#ifdef _WIN32
    FILETIME ft;
    ULARGE_INTEGER value;
    GetSystemTimePreciseAsFileTime(&ft);
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return (value.QuadPart - UINT64_C(116444736000000000)) * 100;
#else
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
#endif
}
op_socket op_socket_open(int family, int type, int protocol) {
#ifdef _WIN32
    SOCKET native = WSASocketW(family, type, protocol, NULL, 0,
                               WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if (native == INVALID_SOCKET) {
        socket_error();
        return OP_INVALID_SOCKET;
    }
    op_socket fd = (op_socket)native;
    if (type == SOCK_DGRAM) {
        BOOL disabled = FALSE;
        DWORD returned = 0;
        WSAIoctl(native, SIO_UDP_CONNRESET, &disabled, sizeof(disabled), NULL, 0, &returned, NULL,
                 NULL);
    }
#else
    op_socket fd = socket(family, type, protocol);
    if (fd < 0)
        return OP_INVALID_SOCKET;
#endif
    if (nonblocking(fd)) {
        op_close(fd);
        return OP_INVALID_SOCKET;
    }
    return fd;
}
op_socket op_accept(op_socket fd, struct sockaddr *address, op_socklen *length) {
#ifdef _WIN32
    SOCKET native = accept((SOCKET)fd, address, length);
    if (native == INVALID_SOCKET) {
        socket_error();
        return OP_INVALID_SOCKET;
    }
    op_socket child = (op_socket)native;
    SetHandleInformation((HANDLE)native, HANDLE_FLAG_INHERIT, 0);
#else
    op_socket child = accept((int)fd, address, length);
    if (child < 0)
        return OP_INVALID_SOCKET;
#endif
    if (nonblocking(child)) {
        op_close(child);
        return OP_INVALID_SOCKET;
    }
    return child;
}
int op_close(op_socket fd) {
#ifdef _WIN32
    return closesocket((SOCKET)fd) ? socket_error() : 0;
#else
    return close((int)fd);
#endif
}
int op_bind(op_socket fd, const struct sockaddr *address, op_socklen length) {
#ifdef _WIN32
    return bind((SOCKET)fd, address, length) ? socket_error() : 0;
#else
    return bind((int)fd, address, length);
#endif
}
int op_connect(op_socket fd, const struct sockaddr *address, op_socklen length) {
#ifdef _WIN32
    if (!connect((SOCKET)fd, address, length))
        return 0;
    int rv = socket_error();
    if (errno == EAGAIN)
        errno = EINPROGRESS;
    return rv;
#else
    return connect((int)fd, address, length);
#endif
}
int op_listen(op_socket fd, int backlog) {
#ifdef _WIN32
    return listen((SOCKET)fd, backlog) ? socket_error() : 0;
#else
    return listen((int)fd, backlog);
#endif
}
int op_getsockname(op_socket fd, struct sockaddr *address, op_socklen *length) {
#ifdef _WIN32
    return getsockname((SOCKET)fd, address, length) ? socket_error() : 0;
#else
    return getsockname((int)fd, address, length);
#endif
}
int op_getpeername(op_socket fd, struct sockaddr *address, op_socklen *length) {
#ifdef _WIN32
    return getpeername((SOCKET)fd, address, length) ? socket_error() : 0;
#else
    return getpeername((int)fd, address, length);
#endif
}
int op_setsockopt(op_socket fd, int level, int option, const void *value, op_socklen length) {
#ifdef _WIN32
    return setsockopt((SOCKET)fd, level, option, (const char *)value, length) ? socket_error() : 0;
#else
    return setsockopt((int)fd, level, option, value, length);
#endif
}
int op_getsockopt(op_socket fd, int level, int option, void *value, op_socklen *length) {
#ifdef _WIN32
    if (getsockopt((SOCKET)fd, level, option, (char *)value, length))
        return socket_error();
    if (level == SOL_SOCKET && option == SO_ERROR && *(int *)value) {
        WSASetLastError(*(int *)value);
        socket_error();
        *(int *)value = errno;
    }
    return 0;
#else
    return getsockopt((int)fd, level, option, value, length);
#endif
}
int op_shutdown_write(op_socket fd) {
#ifdef _WIN32
    return shutdown((SOCKET)fd, SD_SEND) ? socket_error() : 0;
#else
    return shutdown((int)fd, SHUT_WR);
#endif
}
int op_reuse_socket(op_socket fd) {
    int one = 1;
    if (op_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
        return -1;
#if defined(SO_REUSEPORT) && !defined(_WIN32)
    if (op_setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)))
        return -1;
#endif
    return 0;
}
int op_address_equal(const struct sockaddr *a, op_socklen alen, const struct sockaddr *b,
                     op_socklen blen) {
    if (!a || !b || alen < (op_socklen)sizeof(struct sockaddr) ||
        blen < (op_socklen)sizeof(struct sockaddr) || a->sa_family != b->sa_family)
        return 0;
    if (a->sa_family == AF_INET && alen >= (op_socklen)sizeof(struct sockaddr_in) &&
        blen >= (op_socklen)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *x = (const struct sockaddr_in *)a,
                                 *y = (const struct sockaddr_in *)b;
        return x->sin_port == y->sin_port && x->sin_addr.s_addr == y->sin_addr.s_addr;
    }
    if (a->sa_family == AF_INET6 && alen >= (op_socklen)sizeof(struct sockaddr_in6) &&
        blen >= (op_socklen)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *x = (const struct sockaddr_in6 *)a,
                                  *y = (const struct sockaddr_in6 *)b;
        return x->sin6_port == y->sin6_port && x->sin6_scope_id == y->sin6_scope_id &&
               !memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(x->sin6_addr));
    }
    return 0;
}
int op_family_index(int family) {
    if (family == AF_INET)
        return OP_FAM_V4;
    if (family == AF_INET6)
        return OP_FAM_V6;
    return -1;
}
int op_index_family(int index) {
    return index == OP_FAM_V4 ? AF_INET : index == OP_FAM_V6 ? AF_INET6 : AF_UNSPEC;
}
int op_addr_from_text(op_addr *out, const char *text, uint16_t port) {
    if (!out || !text || !*text)
        return -1;
    memset(out, 0, sizeof(*out));
    if (inet_pton(AF_INET, text, &out->u.in.sin_addr) == 1) {
        out->u.in.sin_family = AF_INET;
        out->u.in.sin_port = htons(port);
        out->len = (op_socklen)sizeof(out->u.in);
        return 0;
    }
    if (inet_pton(AF_INET6, text, &out->u.in6.sin6_addr) == 1) {
        out->u.in6.sin6_family = AF_INET6;
        out->u.in6.sin6_port = htons(port);
        out->len = (op_socklen)sizeof(out->u.in6);
        /* An IPv4-mapped literal carries no scope; normalize keeps both views
         * of the same endpoint comparing equal. */
        return 0;
    }
    return -1;
}
int op_addr_text(const op_addr *a, char *out, size_t capacity) {
    if (!a || !out || capacity < 5)
        return -1;
    if (a->u.sa.sa_family == AF_INET && a->len >= (op_socklen)sizeof(a->u.in))
        return inet_ntop(AF_INET, &a->u.in.sin_addr, out, (op_socklen)capacity) ? 0 : -1;
    if (a->u.sa.sa_family == AF_INET6 && a->len >= (op_socklen)sizeof(a->u.in6))
        return inet_ntop(AF_INET6, &a->u.in6.sin6_addr, out, (op_socklen)capacity) ? 0 : -1;
    return -1;
}
int op_addr_family(const op_addr *a) { return a ? a->u.sa.sa_family : AF_UNSPEC; }
uint16_t op_addr_port(const op_addr *a) {
    if (!a)
        return 0;
    if (a->u.sa.sa_family == AF_INET)
        return ntohs(a->u.in.sin_port);
    if (a->u.sa.sa_family == AF_INET6)
        return ntohs(a->u.in6.sin6_port);
    return 0;
}
void op_addr_set_port(op_addr *a, uint16_t port) {
    if (!a)
        return;
    if (a->u.sa.sa_family == AF_INET)
        a->u.in.sin_port = htons(port);
    else if (a->u.sa.sa_family == AF_INET6)
        a->u.in6.sin6_port = htons(port);
}
void op_addr_copy(op_addr *dst, const op_addr *src) {
    if (dst && src)
        *dst = *src;
}
void op_addr_normalize(op_addr *a) {
    if (!a || a->u.sa.sa_family != AF_INET6 || a->len < (op_socklen)sizeof(a->u.in6))
        return;
    const uint8_t *bytes = a->u.in6.sin6_addr.s6_addr;
    int mapped = 1;
    for (int i = 0; i < 10; ++i)
        if (bytes[i])
            mapped = 0;
    if (!mapped || bytes[10] != 0xff || bytes[11] != 0xff)
        return; /* only ::ffff/a.b.c.d collapses; ::1 and others never match */
    uint8_t v4[4] = {bytes[12], bytes[13], bytes[14], bytes[15]};
    uint16_t port = a->u.in6.sin6_port; /* network order; preserved as-is */
    memset(a, 0, sizeof(*a));
    a->u.in.sin_family = AF_INET;
    memcpy(&a->u.in.sin_addr, v4, sizeof(v4));
    a->u.in.sin_port = port;
    a->len = (op_socklen)sizeof(a->u.in);
}
int op_addr_equal(const op_addr *a, const op_addr *b) {
    if (!a || !b)
        return 0;
    op_addr x = *a, y = *b;
    op_addr_normalize(&x);
    op_addr_normalize(&y);
    if (x.u.sa.sa_family != y.u.sa.sa_family)
        return 0;
    if (x.u.sa.sa_family == AF_INET)
        return x.u.in.sin_addr.s_addr == y.u.in.sin_addr.s_addr;
    if (x.u.sa.sa_family == AF_INET6)
        return !memcmp(&x.u.in6.sin6_addr, &y.u.in6.sin6_addr, sizeof(x.u.in6.sin6_addr)) &&
               x.u.in6.sin6_scope_id == y.u.in6.sin6_scope_id;
    return 0;
}
int op_addr_routable(const op_addr *a) {
    if (!a)
        return 0;
    op_addr x = *a;
    op_addr_normalize(&x);
    if (x.u.sa.sa_family == AF_INET) {
        uint32_t v = ntohl(x.u.in.sin_addr.s_addr);
        /* Reject 0/8, loopback, link-local 169.254/16, site ranges and
         * multicast/reserved; CGNAT 100.64/10 stays routable because a
         * carrier peer behind it is still reachable through its mapping. */
        if (op_addr_private(&x))
            return 0;
        if (v < 0x01000000u)
            return 0;
        if ((v & 0xFF000000u) == 0x7F000000u)
            return 0;
        if ((v & 0xFFFF0000u) == 0xA9FE0000u)
            return 0;
        if ((v >> 28) >= 0xEu)
            return 0;
        return 1;
    }
    if (x.u.sa.sa_family == AF_INET6) {
        const uint8_t *b = x.u.in6.sin6_addr.s6_addr;
        static const uint8_t zero[15] = {0};
        if (!memcmp(b, zero, sizeof(zero)))
            return 0; /* :: and ::1 are not globally reachable */
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80)
            return 0; /* fe80::/10 link-local */
        return (b[0] & 0x2Fu) == 0x20u; /* 2000::/3 global unicast */
    }
    return 0;
}
int op_addr_private(const op_addr *a) {
    if (!a)
        return 0;
    op_addr x = *a;
    op_addr_normalize(&x);
    if (x.u.sa.sa_family == AF_INET) {
        uint32_t v = ntohl(x.u.in.sin_addr.s_addr);
        return (v & 0xFF000000u) == 0x0A000000u || (v & 0xFFF00000u) == 0xAC100000u ||
               (v & 0xFFFF0000u) == 0xC0A80000u;
    }
    if (x.u.sa.sa_family == AF_INET6) {
        const uint8_t *b = x.u.in6.sin6_addr.s6_addr;
        return (b[0] & 0xFE) == 0xFC /* fc00::/7 ULA */ || b[0] == 0xFE && (b[1] & 0xC0) == 0x80;
    }
    return 0;
}
static int op_addr_socket(op_socket fd, int peer, op_addr *out) {
    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    out->len = (op_socklen)sizeof(out->u.storage);
    int rv = peer ? op_getpeername(fd, &out->u.sa, &out->len)
                  : op_getsockname(fd, &out->u.sa, &out->len);
    if (rv || (out->len < (op_socklen)sizeof(struct sockaddr)) ||
        (op_family_index(out->u.sa.sa_family) < 0))
        return -1;
    op_addr_normalize(out);
    return 0;
}
int op_addr_socketname(op_socket fd, op_addr *out) { return op_addr_socket(fd, 0, out); }
int op_addr_peername(op_socket fd, op_addr *out) { return op_addr_socket(fd, 1, out); }
int op_poll(op_pollfd *fds, unsigned count, int timeout) {
#ifdef _WIN32
    if (!count) {
        Sleep((DWORD)(timeout < 0 ? 0 : timeout));
        return 0;
    }
    int n = WSAPoll(fds, count, timeout);
    return n == SOCKET_ERROR ? socket_error() : n;
#else
    return poll(fds, count, timeout);
#endif
}
void op_sleep_ms(unsigned ms) {
    op_poll(NULL, 0, (int)ms);
}
op_ssize op_send(op_socket fd, const void *data, size_t length, int flags) {
    if (length > INT_MAX) {
        errno = EMSGSIZE;
        return -1;
    }
#ifdef _WIN32
    int n = send((SOCKET)fd, data, (int)length, flags);
    return n == SOCKET_ERROR ? socket_error() : n;
#else
    return send((int)fd, data, length, flags);
#endif
}
op_ssize op_recv(op_socket fd, void *data, size_t length, int flags) {
    if (length > INT_MAX) {
        errno = EMSGSIZE;
        return -1;
    }
#ifdef _WIN32
    int n = recv((SOCKET)fd, data, (int)length, flags);
    return n == SOCKET_ERROR ? socket_error() : n;
#else
    return recv((int)fd, data, length, flags);
#endif
}
op_ssize op_sendto(op_socket fd, const void *data, size_t length, int flags,
                   const struct sockaddr *peer, op_socklen peer_length) {
    if (length > INT_MAX) {
        errno = EMSGSIZE;
        return -1;
    }
#ifdef _WIN32
    int n = sendto((SOCKET)fd, data, (int)length, flags, peer, peer_length);
    return n == SOCKET_ERROR ? socket_error() : n;
#else
    return sendto((int)fd, data, length, flags, peer, peer_length);
#endif
}
op_ssize op_recvfrom(op_socket fd, void *data, size_t length, int flags, struct sockaddr *peer,
                     op_socklen *peer_length) {
    if (length > INT_MAX) {
        errno = EMSGSIZE;
        return -1;
    }
#ifdef _WIN32
    int n = recvfrom((SOCKET)fd, data, (int)length, flags, peer, peer_length);
    return n == SOCKET_ERROR ? socket_error() : n;
#else
    return recvfrom((int)fd, data, length, flags, peer, peer_length);
#endif
}
