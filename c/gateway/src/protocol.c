#include "protocol.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
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
static int utf8_valid(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len;) {
        unsigned lead = data[i++], remaining;
        uint32_t value, minimum;
        if (lead < 0x80)
            continue;
        if (lead >= 0xc2 && lead <= 0xdf) {
            remaining = 1;
            value = lead & 0x1f;
            minimum = 0x80;
        } else if (lead >= 0xe0 && lead <= 0xef) {
            remaining = 2;
            value = lead & 0x0f;
            minimum = 0x800;
        } else if (lead >= 0xf0 && lead <= 0xf4) {
            remaining = 3;
            value = lead & 7;
            minimum = 0x10000;
        } else
            return 0;
        if (remaining > len - i)
            return 0;
        while (remaining--) {
            unsigned next = data[i++];
            if ((next & 0xc0) != 0x80)
                return 0;
            value = (value << 6) | (next & 0x3f);
        }
        if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
            return 0;
    }
    return 1;
}
static char *json_ascii(const unsigned char *data, size_t len, size_t *length) {
    char *out = malloc(len * 3 + 1);
    if (!out)
        return NULL;
    size_t used = 0;
    int quoted = 0, escaped = 0;
    for (size_t i = 0; i < len;) {
        unsigned c = data[i++];
        if (c < 0x80) {
            out[used++] = (char)c;
            if (quoted) {
                if (escaped)
                    escaped = 0;
                else if (c == '\\')
                    escaped = 1;
                else if (c == '"')
                    quoted = 0;
            } else if (c == '"')
                quoted = 1;
            continue;
        }
        /* Non-ASCII is legal only as an unescaped character inside a string. */
        if (!quoted || escaped) {
            free(out);
            return NULL;
        }
        unsigned remaining = c < 0xe0 ? 1 : c < 0xf0 ? 2 : 3;
        uint32_t value = c & (remaining == 1 ? 0x1f : remaining == 2 ? 0x0f : 7);
        while (remaining--)
            value = (value << 6) | (data[i++] & 0x3f);
        if (value <= 0xffff)
            used += (size_t)sprintf(out + used, "\\u%04x", (unsigned)value);
        else {
            value -= 0x10000;
            used += (size_t)sprintf(out + used, "\\u%04x\\u%04x", 0xd800u + (value >> 10),
                                    0xdc00u + (value & 0x3ff));
        }
    }
    out[used] = 0;
    *length = used;
    return out;
}
char *gw_json_text(json_object *value, size_t *length) {
    const char *text =
        value ? json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN) : "null";
    *length = strlen(text);
    if (*length > GW_FRAME_LIMIT || !utf8_valid((const unsigned char *)text, *length))
        return NULL;
    for (size_t i = 0; i < *length; ++i)
        if ((unsigned char)text[i] >= 0x80)
            return json_ascii((const unsigned char *)text, *length, length);
    return strdup(text);
}
json_object *gw_json(const void *data, size_t len) {
    if (!data || !len || len > GW_FRAME_LIMIT || len > INT_MAX)
        return NULL;
    if (!utf8_valid(data, len))
        return NULL;
    const unsigned char *input = data;
    /* json-c 0.16 accepts literal controls in strings even with STRICT. */
    int quoted = 0, escaped = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned c = input[i];
        if (quoted) {
            if (c < 0x20)
                return NULL;
            if (escaped)
                escaped = 0;
            else if (c == '\\')
                escaped = 1;
            else if (c == '"')
                quoted = 0;
        } else if (c == '"')
            quoted = 1;
    }
    size_t input_len = len;
    char *normalized = NULL;
    for (size_t i = 0; i < len; ++i)
        if (input[i] >= 0x80) {
            normalized = json_ascii(data, len, &input_len);
            if (!normalized)
                return NULL;
            input = (const unsigned char *)normalized;
            break;
        }
    json_tokener *tok = json_tokener_new();
    if (!tok) {
        free(normalized);
        return NULL;
    }
    /* Distro json-c strict parsing may treat signed UTF-8 bytes as controls.
     * Validate raw UTF-8, then use equivalent JSON escapes, keeping STRICT. */
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT);
    errno = 0;
    json_object *j = json_tokener_parse_ex(tok, (const char *)input, (int)input_len);
    size_t used = json_tokener_get_parse_end(tok);
    if (json_tokener_get_error(tok) != json_tokener_success || errno == ERANGE) {
        if (j)
            json_object_put(j);
        j = NULL;
    }
    if (j) {
        const unsigned char *p = input;
        for (size_t i = used; i < input_len; ++i)
            if (p[i] != ' ' && p[i] != '\t' && p[i] != '\n' && p[i] != '\r') {
                json_object_put(j);
                j = NULL;
                break;
            }
    }
    json_tokener_free(tok);
    free(normalized);
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
