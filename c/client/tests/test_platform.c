#include "platform.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    assert(!op_platform_init());
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
    puts("Address identity, nonblocking socket and monotonic clock passed");
    return 0;
}
