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
    /* Direct encoding preserves aliasing across both growth and compaction. */
    uint8_t seed_bytes[8192];
    for(size_t i=0;i<sizeof(seed_bytes);i++)seed_bytes[i]=(uint8_t)(i^(i>>8));
    assert(!op_buffer_add(&rx,seed_bytes,4096,OP_QUEUE_LIMIT));
    assert(!op_frame_add(&rx,4,9,rx.data,4096));
    op_buffer_consume(&rx,4096);
    assert(op_frame_take(&rx,&main,&sub,&body,&len)==1 && len==4096 && !memcmp(body,seed_bytes,len));
    free(body);op_buffer_clear(&rx);
    assert(!op_buffer_add(&rx,seed_bytes,sizeof(seed_bytes),sizeof(seed_bytes)));
    op_buffer_consume(&rx,4096);
    assert(!op_frame_add(&rx,4,9,rx.data,4096));
    assert(!memcmp(rx.data+rx.offset,seed_bytes+4096,4096));
    op_buffer_consume(&rx,4096);
    assert(op_frame_take(&rx,&main,&sub,&body,&len)==1 && len==4096 && !memcmp(body,seed_bytes,len));
    free(body);op_buffer_clear(&rx);
    assert(!op_frame_add(&rx,4,9,NULL,0));
    size_t queued=op_buffer_size(&rx);
    assert(op_frame_add(&rx,4,9,NULL,1)==-1 && op_buffer_size(&rx)==queued);
    assert(op_frame_add(&rx,4,9,seed_bytes,SIZE_MAX)==-1 && op_buffer_size(&rx)==queued);
    assert(op_frame_take(&rx,&main,&sub,&body,&len)==1 && !len);free(body);
    /* Refuse a whole frame atomically when the queue has room for only its header. */
    uint8_t *full=calloc(1,OP_QUEUE_LIMIT);assert(full);
    assert(!op_buffer_add(&rx,full,OP_QUEUE_LIMIT-8,OP_QUEUE_LIMIT));
    assert(op_frame_add(&rx,4,9,seed_bytes,1)==-1 && op_buffer_size(&rx)==OP_QUEUE_LIMIT-8);
    assert(!op_frame_add(&rx,4,9,NULL,0) && op_buffer_size(&rx)==OP_QUEUE_LIMIT);
    free(full);op_buffer_clear(&rx);
    assert(!op_buffer_add(&rx,seed_bytes,8,8) && rx.capacity<=8);
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
    const char *unicode="{\"name\":\"\xe4\xb8\xad\xe6\x96\x87\"}";
    j=op_json(unicode,strlen(unicode));
    assert(j&&!strcmp(op_string(j,"name"),"\xe4\xb8\xad\xe6\x96\x87"));json_object_put(j);
    const char *bad_utf8="{\"name\":\"\xff\"}",*bad_control="{\"name\":\"line\nfeed\"}";
    assert(!op_json(bad_utf8,strlen(bad_utf8)));
    assert(!op_json(bad_control,strlen(bad_control)));
    const char *invalid_utf8[]={"{\"x\":\"\xc0\xaf\"}","{\"x\":\"\xe0\x80\x80\"}",
        "{\"x\":\"\xed\xa0\x80\"}","{\"x\":\"\xf4\x90\x80\x80\"}","{\"x\":\"\xc2\"}"};
    for(unsigned i=0;i<sizeof(invalid_utf8)/sizeof(invalid_utf8[0]);++i)
        assert(!op_json(invalid_utf8[i],strlen(invalid_utf8[i])));
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
