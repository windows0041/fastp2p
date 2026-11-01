#include "socks.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    uint8_t out[10];
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
    unsupported[3] = 4;
    assert(op_socks_step(&s, unsupported, 10, &used, "", "", out, &len) == -1 && out[1] == 8);
    const uint8_t ip[] = {127, 0, 0, 1};
    op_socks_reply(out, 0, ip, 1080);
    assert(!memcmp(out, (uint8_t[]){5, 0, 0, 1, 127, 0, 0, 1, 4, 56}, 10));
    puts("SOCKS5 incremental greeting, authentication, addressing and rejection checks passed");
}
