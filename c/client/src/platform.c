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
