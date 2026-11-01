#include "protocol.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    const char unicode[] =
        "{\"appName\":\"浏览器测试转发\",\"protocol\":\"tcp\",\"srcPort\":24567,\"peerNode\":\"web-"
        "go-node\",\"dstHost\":\"127.0.0.1\",\"dstPort\":80,\"punchPriority\":3}";
    json_object *utf = gw_json(unicode, sizeof(unicode) - 1);
    assert(utf);
    size_t wire_len;
    char *wire_text = gw_json_text(utf, &wire_len);
    assert(wire_text && strstr(wire_text, "\\u6d4f"));
    for (size_t i = 0; i < wire_len; ++i)
        assert((unsigned char)wire_text[i] < 128);
    json_tokener *legacy = json_tokener_new();
    json_tokener_set_flags(legacy, JSON_TOKENER_STRICT);
    json_object *decoded = json_tokener_parse_ex(legacy, wire_text, (int)wire_len);
    assert(decoded && !strcmp(gw_string(decoded, "appName"), "浏览器测试转发"));
    json_object_put(decoded);
    json_tokener_free(legacy);
    free(wire_text);
    json_object_put(utf);
    const char *valid[] = {"{\"x\":\"\xc3\xa9\"}", "{\"x\":\"\xf0\x9f\x94\x92\"}"};
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
        utf = gw_json(valid[i], strlen(valid[i]));
        assert(utf);
        json_object_put(utf);
    }
    const char *invalid[] = {
        "{\"x\":\"\x80\"}",         "{\"x\":\"\xc0\xaf\"}",         "{\"x\":\"\xe0\x80\x80\"}",
        "{\"x\":\"\xed\xa0\x80\"}", "{\"x\":\"\xf4\x90\x80\x80\"}", "{\"x\":\"\xc2\"}",
        "{\"x\":\"\xf0\x9f\"}"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        assert(!gw_json(invalid[i], strlen(invalid[i])));
    const char *syntax[] = {"{\"x\":\"\\\xc3\xa9\"}", "{\"x\":\xc3\xa9}",
                            "{\"x\":\"\xe4\xb8\xad\"}{}", "{\"x\":\"a\n\xe4\xb8\xad\"}"};
    for (size_t i = 0; i < sizeof(syntax) / sizeof(syntax[0]); ++i)
        assert(!gw_json(syntax[i], strlen(syntax[i])));
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
