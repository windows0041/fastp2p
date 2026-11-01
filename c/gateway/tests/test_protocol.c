#include "protocol.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned char data[8];
    gw_put64(data, UINT64_MAX);
    assert(gw_u64(data) == UINT64_MAX);
    uint64_t n;
    assert(!gw_decimal("18446744073709551615", &n) && n == UINT64_MAX);
    assert(gw_decimal("18446744073709551616", &n) && gw_decimal("-1", &n));
    const char *text = "{\"token\":18446744073709551615}";
    json_object *j = gw_json(text, strlen(text));
    assert(j && gw_integer(j, "token") == UINT64_MAX);
    json_object_put(j);
    text = "{\"token\":18446744073709551616}";
    assert(!gw_json(text, strlen(text)));
    assert(!gw_json("{}{}", 4) && !gw_json("{", 1));
    assert(gw_node_valid("test-node-1") && !gw_node_valid("short"));
    /* Go crc64.ISO check value. */
    assert(gw_node_id("123456789") == UINT64_C(0xb90956c775a41001));
    uint64_t now = 1700000000, token = UINT64_MAX;
    uint64_t code = gw_totp(token, now);
    assert(code == UINT64_C(15768002713671294198)); /* Go totp reference */
    assert(code && gw_token_valid(code, token, now) && gw_token_valid(code, token, now + 30));
    assert(gw_token_valid(token, token, now) && !gw_token_valid(0, token, now) &&
           !gw_token_valid(code, token, now + 90));
    char *jwt = gw_jwt_issue("test-user", token, "test-secret", now);
    assert(jwt);
    assert(gw_jwt_verify(jwt, "test-user", token, "test-secret", now + 1));
    assert(!gw_jwt_verify(jwt, "test-user", token, "wrong-secret", now + 1));
    assert(!gw_jwt_verify(jwt, "other-user", token, "test-secret", now + 1));
    assert(!gw_jwt_verify(jwt, "test-user", token, "test-secret", now + 86400));
    jwt[10] = jwt[10] == 'A' ? 'B' : 'A';
    assert(!gw_jwt_verify(jwt, "test-user", token, "test-secret", now));
    free(jwt);
    puts("Wire, uint64, CRC64, TOTP and JWT checks passed");
    return 0;
}
