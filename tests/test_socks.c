#include "socks.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    assert(!op_platform_init());
    uint8_t out[OP_SOCKS_MAX_REPLY];
    size_t used, len;
    op_socks s = {.state = SOCKS_GREETING};
    const uint8_t greeting[] = {5, 2, 0, 2};
    for (size_t n = 0; n < sizeof(greeting); ++n)
        assert(op_socks_step(&s, greeting, n, &used, "", "", out, &len) == 0 && !used && !len);
    assert(op_socks_step(&s, greeting, 4, &used, "", "", out, &len) == 1 && used == 4 && len == 2 &&
           out[1] == 0);
    const uint8_t request[] = {5, 1, 0, 3, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 1, 187};
    for (size_t n = 0; n < sizeof(request); ++n)
        assert(op_socks_step(&s, request, n, &used, "", "", out, &len) == 0);
    assert(op_socks_step(&s, request, sizeof(request), &used, "", "", out, &len) == 2);
    assert(!strcmp(s.host, "localhost") && s.port == 443 && used == sizeof(request));
    s.state = SOCKS_GREETING;
    assert(op_socks_step(&s, greeting, 4, &used, "alice", "secret", out, &len) == 1 && out[1] == 2);
    uint8_t auth[] = {1, 5, 'a', 'l', 'i', 'c', 'e', 6, 's', 'e', 'c', 'r', 'e', 't'};
    for (size_t n = 0; n < sizeof(auth); ++n)
        assert(op_socks_step(&s, auth, n, &used, "alice", "secret", out, &len) == 0);
    assert(op_socks_step(&s, auth, sizeof(auth), &used, "alice", "secret", out, &len) == 1 &&
           out[1] == 0);
    s.state = SOCKS_AUTH;
    auth[4] = 0;
    assert(op_socks_step(&s, auth, sizeof(auth), &used, "alice", "secret", out, &len) == -1 &&
           out[1] == 1);
    const uint8_t bad_domain[] = {5, 1, 0, 3, 3, 'a', 0, 'b', 0, 80};
    s.state = SOCKS_REQUEST;
    assert(op_socks_step(&s, bad_domain, sizeof(bad_domain), &used, "", "", out, &len) == -1 &&
           out[1] == 8);
    uint8_t unsupported[] = {5, 2, 0, 1, 127, 0, 0, 1, 0, 80};
    assert(op_socks_step(&s, unsupported, 10, &used, "", "", out, &len) == -1 && out[1] == 7);
    unsupported[1] = 1;
    unsupported[3] = 5;
    assert(op_socks_step(&s, unsupported, 10, &used, "", "", out, &len) == -1 && out[1] == 8);
    op_addr ip;
    assert(!op_addr_from_text(&ip, "127.0.0.1", 1080));
    assert(op_socks_reply(out, 0, &ip) == 10);
    assert(!memcmp(out, (uint8_t[]){5, 0, 0, 1, 127, 0, 0, 1, 4, 56}, 10));
    const uint8_t ipv6[22] = {5, 1, 0, 4, 0x20, 1, 0x0d, 0xb8, [19] = 1, 1, 187};
    s.state = SOCKS_REQUEST;
    for (size_t n = 0; n < sizeof(ipv6); ++n)
        assert(op_socks_step(&s, ipv6, n, &used, "", "", out, &len) == 0);
    assert(op_socks_step(&s, ipv6, sizeof(ipv6), &used, "", "", out, &len) == 2);
    assert(used == sizeof(ipv6) && s.port == 443 && !strcmp(s.host, "2001:db8::1"));
    assert(!op_addr_from_text(&ip, s.host, s.port));
    assert(op_socks_reply(out, 0, &ip) == sizeof(ipv6));
    assert(out[0] == 5 && out[1] == 0 && !memcmp(out + 2, ipv6 + 2, sizeof(ipv6) - 2));
    puts("SOCKS5 incremental greeting, authentication, addressing and rejection checks passed");
}
