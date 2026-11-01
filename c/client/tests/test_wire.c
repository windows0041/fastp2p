#include "wire.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    op_buffer wire = {0}, rx = {0};
    const uint8_t expected[] = {8, 0, 0, 0, 4, 0, 2, 0, 255, 254, 253, 252, 251, 250, 249, 248};
    assert(!op_frame_add(&wire, 4, 2, expected + 8, 8));
    assert(wire.len == sizeof(expected) && !memcmp(wire.data, expected, sizeof(expected)));
    for (size_t i = 0; i < sizeof(expected); ++i) {
        assert(!op_buffer_add(&rx, expected + i, 1, OP_FRAME_LIMIT + 8));
        uint8_t *body = NULL;
        uint16_t main = 99, sub = 99;
        size_t len = 0;
        int result = op_frame_take(&rx, &main, &sub, &body, &len);
        if (i + 1 < sizeof(expected))
            assert(result == 0);
        else {
            assert(result == 1 && main == 4 && sub == 2 && len == 8 &&
                   !memcmp(body, expected + 8, 8));
            free(body);
        }
    }
    uint8_t invalid[8] = {255, 255, 255, 255, 4, 0, 0, 0};
    assert(!op_buffer_add(&rx, invalid, sizeof(invalid), OP_FRAME_LIMIT + 8));
    uint8_t *body = NULL;
    uint16_t main, sub;
    size_t len;
    assert(op_frame_take(&rx, &main, &sub, &body, &len) == -1);
    op_buffer_clear(&rx);
    /* More than one frame per read, and a partial following header. */
    assert(!op_buffer_add(&rx, expected, sizeof(expected), OP_FRAME_LIMIT + 8));
    assert(!op_buffer_add(&rx, expected, sizeof(expected), OP_FRAME_LIMIT + 8));
    for (int i = 0; i < 2; ++i) {
        assert(op_frame_take(&rx, &main, &sub, &body, &len) == 1);
        free(body);
    }
    assert(!op_buffer_size(&rx));
    const char *json = "{\"id\":18446744073709551615,\"token\":9007199254740993}";
    json_object *j = op_json(json, strlen(json));
    assert(j && op_integer(j, "id") == UINT64_MAX &&
           op_integer(j, "token") == UINT64_C(9007199254740993));
    json_object_put(j);
    const char *overflow = "{\"token\":18446744073709551616}";
    assert(!op_json(overflow, strlen(overflow)));
    assert(!op_json("{\"id\":1}garbage", 15));
    assert(!op_json("{\"id\":", 6));
    /* Deterministic malformed stream exercise under ASan/UBSan. */
    uint32_t seed = 12345;
    for (int i = 0; i < 10000; ++i) {
        uint8_t bytes[64];
        for (size_t k = 0; k < sizeof(bytes); ++k) {
            seed = seed * 1664525u + 1013904223u;
            bytes[k] = (uint8_t)(seed >> 24);
        }
        assert(!op_buffer_add(&rx, bytes, sizeof(bytes), OP_FRAME_LIMIT + 8));
        int rv = op_frame_take(&rx, &main, &sub, &body, &len);
        if (rv == 1)
            free(body);
        op_buffer_clear(&rx);
    }
    op_buffer_clear(&wire);
    puts("wire framing, uint64 JSON and malformed input checks passed");
    return 0;
}
