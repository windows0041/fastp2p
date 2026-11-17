#include "platform.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static op_addr addr(const char *text, uint16_t port) {
    op_addr a;
    assert(!op_addr_from_text(&a, text, port));
    return a;
}

int main(void) {
    assert(!op_platform_init());
    char hostname[256];
    assert(!op_hostname(hostname, sizeof(hostname)) && *hostname);
    assert(op_hostname(hostname, 1));
    struct sockaddr_in a, b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0xff, sizeof(b));
    a.sin_family = b.sin_family = AF_INET;
    a.sin_port = b.sin_port = htons(22001);
    a.sin_addr.s_addr = b.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(op_address_equal((struct sockaddr *)&a, sizeof(a), (struct sockaddr *)&b, sizeof(b)));
    b.sin_port = htons(22002);
    assert(!op_address_equal((struct sockaddr *)&a, sizeof(a), (struct sockaddr *)&b, sizeof(b)));
    assert(!op_address_equal((struct sockaddr *)&a, 1, (struct sockaddr *)&a, sizeof(a)));
    op_socket fd = op_socket_open(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    a.sin_port = 0;
    assert(!op_bind(fd, (struct sockaddr *)&a, sizeof(a)));
    char data[16];
    assert(op_recvfrom(fd, data, sizeof(data), 0, NULL, NULL) < 0);
    assert(errno == EAGAIN || errno == EWOULDBLOCK);
    uint64_t before = op_monotonic_ns();
    op_sleep_ms(3);
    assert(op_monotonic_ns() > before);
    assert(!op_close(fd));

    /* Address primitives: text in either family, normalization, and the range
     * tests that later decide punching versus a same-side local reach. */
    op_addr v4 = addr("192.0.2.7", 27183);
    assert(op_addr_family(&v4) == AF_INET && op_addr_port(&v4) == 27183);
    op_addr v6 = addr("2001:db8::1", 0);
    assert(op_addr_family(&v6) == AF_INET6 && op_addr_port(&v6) == 0);
    op_addr rejected;
    assert(op_addr_from_text(&rejected, "[::1]", 0));  /* brackets are URL syntax */
    assert(op_addr_from_text(&rejected, "host.example", 0)); /* not an address */
    char text[OP_ADDR_TEXT];
    assert(!op_addr_text(&v6, text, sizeof(text)) && !strcmp(text, "2001:db8::1"));
    assert(op_addr_text(&v6, text, 8)); /* a too-small buffer must fail outright */

    /* One peer behind a dual-stack listener must not look like two peers. */
    op_addr mapped = addr("::ffff:192.0.2.7", 27183);
    op_addr_normalize(&mapped);
    assert(op_addr_family(&mapped) == AF_INET && op_addr_port(&mapped) == 27183);
    assert(op_addr_equal(&mapped, &v4));
    assert(!op_addr_equal(&v4, &v6));
    op_addr same = v6;
    op_addr_set_port(&same, 1);
    assert(op_addr_equal(&same, &v6)); /* endpoint equality ignores the port */

    /* Range classification per family. */
    assert(op_addr_routable(&v4) && op_addr_routable(&v6));
    assert(!op_addr_private(&v4));
    op_addr loop4 = addr("127.0.0.1", 0), lan4 = addr("192.168.1.10", 0),
            cgnat = addr("100.64.0.9", 0), ll4 = addr("169.254.8.8", 0);
    assert(!op_addr_routable(&loop4) && !op_addr_private(&loop4));
    assert(op_addr_private(&lan4) && !op_addr_routable(&lan4));
    assert(op_addr_routable(&cgnat)); /* carrier NAT is still peer-reachable */
    assert(!op_addr_routable(&ll4));
    op_addr loop6 = addr("::1", 0), link6 = addr("fe80::abcd", 0), ula = addr("fd12::1", 0);
    assert(!op_addr_routable(&loop6) && !op_addr_private(&loop6));
    assert(!op_addr_routable(&link6) && op_addr_private(&link6));
    assert(!op_addr_routable(&ula) && op_addr_private(&ula));

    /* A socket reports both endpoints with the family it actually used. This
     * replaces the old habit of extracting only the port into a 16-byte IPv4
     * text buffer, which silently kept "0.0.0.0" on an IPv6 connection. */
    op_addr target = addr("::1", 0);
    op_socket listener = op_socket_open(AF_INET6, SOCK_STREAM, 0);
    int usable = listener >= 0 && !op_reuse_socket(listener) &&
                 (op_addr_set_port(&target, 0),
                  !op_bind(listener, &target.u.sa, target.len)) && !op_listen(listener, 4);
    if (usable) {
        assert(!op_addr_socketname(listener, &target)); /* now carries the real port */
        assert(op_addr_family(&target) == AF_INET6 && op_addr_port(&target));
        assert(op_addr_equal(&target, &loop6));
        op_addr unused;
        assert(op_addr_peername(listener, &unused)); /* not connected yet: fail */
        op_socket dialer = op_socket_open(AF_INET6, SOCK_STREAM, 0);
        assert(dialer >= 0);
        op_addr dialed = target;
        assert(op_connect(dialer, &dialed.u.sa, dialed.len) &&
               (errno == EINPROGRESS || errno == EAGAIN || errno == EISCONN));
        op_pollfd connected = {.fd = dialer, .events = POLLOUT};
        assert(op_poll(&connected, 1, 2000) == 1);
        int error = 0;
        op_socklen n = sizeof(error);
        assert(!op_getsockopt(dialer, SOL_SOCKET, SO_ERROR, &error, &n) && !error);
        op_addr child_addr;
        op_socket child = OP_INVALID_SOCKET;
        for (int attempt = 0; attempt < 100 && child < 0; ++attempt) {
            op_pollfd incoming = {.fd = listener, .events = POLLIN};
            if (op_poll(&incoming, 1, 100) == 1) {
                child_addr.len = (op_socklen)sizeof(child_addr.u.storage);
                child = op_accept(listener, &child_addr.u.sa, &child_addr.len);
            }
        }
        assert(child >= 0);
        assert(op_addr_family(&child_addr) == AF_INET6);
        op_addr dialer_local;
        assert(!op_addr_socketname(dialer, &dialer_local));
        assert(op_addr_equal(&child_addr, &dialer_local)); /* same peer, both views */
        op_addr child_peer;
        assert(!op_addr_peername(child, &child_peer));
        assert(op_addr_port(&child_peer) == op_addr_port(&dialer_local));
        op_addr child_local;
        assert(!op_addr_socketname(child, &child_local));
        assert(op_addr_equal(&child_local, &target));
        op_close(child);
        op_close(dialer);
    } else {
        puts("skipping IPv6 loopback socket checks (no bindable ::1 here)");
    }
    if (listener >= 0)
        op_close(listener);
    puts("Address identity, family primitives, ranges and clock passed");
    return 0;
}
