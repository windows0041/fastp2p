#include "wire.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
uint16_t op_u16(const void *p) {
    const uint8_t *b = p;
    return (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
}
uint32_t op_u32(const void *p) {
    const uint8_t *b = p;
    return (uint32_t)op_u16(b) | ((uint32_t)op_u16(b + 2) << 16);
}
uint64_t op_u64(const void *p) {
    const uint8_t *b = p;
    return (uint64_t)op_u32(b) | ((uint64_t)op_u32(b + 4) << 32);
}
void op_put16(void *p, uint16_t v) {
    uint8_t *b = p;
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
}
void op_put32(void *p, uint32_t v) {
    uint8_t *b = p;
    op_put16(b, (uint16_t)v);
    op_put16(b + 2, (uint16_t)(v >> 16));
}
void op_put64(void *p, uint64_t v) {
    uint8_t *b = p;
    op_put32(b, (uint32_t)v);
    op_put32(b + 4, (uint32_t)(v >> 32));
}
uint64_t op_node_id(const char *s) {
    uint64_t crc = UINT64_MAX;
    while (*s) {
        crc ^= (uint8_t)*s++;
        for (int i = 0; i < 8; ++i)
            crc = (crc >> 1) ^ ((crc & 1) ? UINT64_C(0xd800000000000000) : 0);
    }
    return ~crc;
}
size_t op_buffer_size(const op_buffer *b) {
    return b->len - b->offset;
}
int op_buffer_add(op_buffer *b, const void *data, size_t len, size_t limit) {
    if (len && !data)
        return -1;
    size_t old = op_buffer_size(b);
    if (old > limit || len > limit - old)
        return -1;
    if (b->offset && (b->capacity - b->len < len || b->offset > b->capacity / 2)) {
        memmove(b->data, b->data + b->offset, old);
        b->len = old;
        b->offset = 0;
    }
    if (b->capacity - b->len < len) {
        size_t cap = b->len + len;
        if (cap < 4096)
            cap = 4096;
        if (cap < limit / 2)
            cap *= 2;
        uint8_t *p = realloc(b->data, cap);
        if (!p)
            return -1;
        b->data = p;
        b->capacity = cap;
    }
    if (len)
        memcpy(b->data + b->len, data, len);
    b->len += len;
    return 0;
}
void op_buffer_consume(op_buffer *b, size_t len) {
    if (len >= op_buffer_size(b))
        b->offset = b->len = 0;
    else
        b->offset += len;
}
void op_buffer_clear(op_buffer *b) {
    free(b->data);
    memset(b, 0, sizeof(*b));
}
int op_frame_add(op_buffer *b, uint16_t main, uint16_t sub, const void *data, size_t len) {
    if (len > OP_FRAME_LIMIT || op_buffer_size(b) > OP_QUEUE_LIMIT - 8 - len)
        return -1;
    if (len && !data)
        return -1;
    uint8_t *frame = malloc(8 + len);
    if (!frame)
        return -1;
    op_put32(frame, (uint32_t)len);
    op_put16(frame + 4, main);
    op_put16(frame + 6, sub);
    if (len)
        memcpy(frame + 8, data, len);
    int rv = op_buffer_add(b, frame, 8 + len, OP_QUEUE_LIMIT);
    free(frame);
    return rv;
}
int op_frame_take(op_buffer *b, uint16_t *main, uint16_t *sub, uint8_t **body, size_t *len) {
    size_t n = op_buffer_size(b);
    if (n < 8)
        return 0;
    const uint8_t *p = b->data + b->offset;
    size_t length = op_u32(p);
    if (length > OP_FRAME_LIMIT || op_u16(p + 4) > 8)
        return -1;
    if (n < length + 8)
        return 0;
    uint8_t *copy = malloc(length + 1);
    if (!copy)
        return -1;
    memcpy(copy, p + 8, length);
    copy[length] = 0;
    *main = op_u16(p + 4);
    *sub = op_u16(p + 6);
    *len = length;
    *body = copy;
    op_buffer_consume(b, length + 8);
    return 1;
}
json_object *op_json(const void *data, size_t len) {
    if (len > OP_FRAME_LIMIT || len > INT_MAX)
        return NULL;
    json_tokener *t = json_tokener_new();
    if (!t)
        return NULL;
    json_tokener_set_flags(t, JSON_TOKENER_STRICT);
    errno = 0;
    json_object *o = json_tokener_parse_ex(t, data, (int)len);
    int range_error = errno == ERANGE;
    if (range_error || json_tokener_get_error(t) != json_tokener_success ||
        json_tokener_get_parse_end(t) != len) {
        if (o)
            json_object_put(o);
        o = NULL;
    }
    json_tokener_free(t);
    return o;
}
json_object *op_get(json_object *o, const char *name) {
    json_object *v = NULL;
    if (o)
        json_object_object_get_ex(o, name, &v);
    return v;
}
const char *op_string(json_object *o, const char *name) {
    json_object *v = op_get(o, name);
    return v && json_object_is_type(v, json_type_string) ? json_object_get_string(v) : "";
}
uint64_t op_integer(json_object *o, const char *name) {
    json_object *v = op_get(o, name);
    return v && json_object_is_type(v, json_type_int) ? json_object_get_uint64(v) : 0;
}
void op_js(json_object *o, const char *name, const char *s) {
    json_object_object_add(o, name, json_object_new_string(s ? s : ""));
}
void op_ju(json_object *o, const char *name, uint64_t v) {
    json_object_object_add(o, name, json_object_new_uint64(v));
}
