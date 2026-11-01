#include "protocol.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

uint16_t gw_u16(const void *p) {
    const uint8_t *b = p;
    return (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
}
uint32_t gw_u32(const void *p) {
    const uint8_t *b = p;
    return (uint32_t)gw_u16(b) | ((uint32_t)gw_u16(b + 2) << 16);
}
uint64_t gw_u64(const void *p) {
    const uint8_t *b = p;
    return (uint64_t)gw_u32(b) | ((uint64_t)gw_u32(b + 4) << 32);
}
void gw_put16(void *p, uint16_t v) {
    uint8_t *b = p;
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
}
void gw_put32(void *p, uint32_t v) {
    uint8_t *b = p;
    gw_put16(b, (uint16_t)v);
    gw_put16(b + 2, (uint16_t)(v >> 16));
}
void gw_put64(void *p, uint64_t v) {
    uint8_t *b = p;
    gw_put32(b, (uint32_t)v);
    gw_put32(b + 4, (uint32_t)(v >> 32));
}
uint64_t gw_node_id(const char *text) {
    uint64_t crc = UINT64_MAX;
    for (; *text; ++text) {
        crc ^= (uint8_t)*text;
        for (int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ ((crc & 1) ? UINT64_C(0xd800000000000000) : 0);
    }
    return ~crc;
}
uint64_t gw_mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
uint64_t gw_wall_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
int gw_decimal(const char *text, uint64_t *out) {
    if (!text || !*text || !out)
        return -1;
    for (const char *p = text; *p; ++p)
        if (*p < '0' || *p > '9')
            return -1;
    errno = 0;
    char *end;
    unsigned long long v = strtoull(text, &end, 10);
    if (errno || *end)
        return -1;
    *out = (uint64_t)v;
    return 0;
}
int gw_node_valid(const char *text) {
    size_t n = text ? strlen(text) : 0;
    if (n < 8 || n > 31)
        return 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)text[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-'))
            return 0;
    }
    return 1;
}
json_object *gw_json(const void *data, size_t len) {
    if (!data || !len || len > GW_FRAME_LIMIT || len > INT_MAX)
        return NULL;
    json_tokener *tok = json_tokener_new();
    if (!tok)
        return NULL;
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    errno = 0;
    json_object *j = json_tokener_parse_ex(tok, data, (int)len);
    size_t used = json_tokener_get_parse_end(tok);
    if (json_tokener_get_error(tok) != json_tokener_success || errno == ERANGE) {
        if (j)
            json_object_put(j);
        j = NULL;
    }
    if (j) {
        const unsigned char *p = data;
        for (size_t i = used; i < len; ++i)
            if (p[i] != ' ' && p[i] != '\t' && p[i] != '\n' && p[i] != '\r') {
                json_object_put(j);
                j = NULL;
                break;
            }
    }
    json_tokener_free(tok);
    return j;
}
json_object *gw_get(json_object *j, const char *name) {
    json_object *v = NULL;
    if (j && json_object_is_type(j, json_type_object))
        json_object_object_get_ex(j, name, &v);
    return v;
}
const char *gw_string(json_object *j, const char *name) {
    json_object *v = gw_get(j, name);
    if (!v || !json_object_is_type(v, json_type_string))
        return "";
    const char *text = json_object_get_string(v);
    return strlen(text) == (size_t)json_object_get_string_len(v) ? text : "";
}
uint64_t gw_integer(json_object *j, const char *name) {
    json_object *v = gw_get(j, name);
    if (!v || !json_object_is_type(v, json_type_int) || json_object_get_int64(v) < 0)
        return 0;
    return json_object_get_uint64(v);
}
void gw_js(json_object *j, const char *name, const char *text) {
    json_object_object_add(j, name, json_object_new_string(text ? text : ""));
}
void gw_ju(json_object *j, const char *name, uint64_t value) {
    json_object_object_add(j, name, json_object_new_uint64(value));
}
