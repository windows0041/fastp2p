#ifndef FASTP2P_WIRE_H
#define FASTP2P_WIRE_H
#include <stddef.h>
#include <stdint.h>
#include <json-c/json.h>
#define OP_FRAME_LIMIT (1024u * 1024u)
#define OP_QUEUE_LIMIT (4u * 1024u * 1024u)
typedef struct {
    uint8_t *data;
    size_t len, offset, capacity;
} op_buffer;
uint16_t op_u16(const void *p);
uint32_t op_u32(const void *p);
uint64_t op_u64(const void *p);
void op_put16(void *p, uint16_t value);
void op_put32(void *p, uint32_t value);
void op_put64(void *p, uint64_t value);
uint64_t op_node_id(const char *name);
int op_buffer_add(op_buffer *b, const void *data, size_t len, size_t limit);
void op_buffer_consume(op_buffer *b, size_t len);
void op_buffer_clear(op_buffer *b);
size_t op_buffer_size(const op_buffer *b);
int op_frame_add(op_buffer *b, uint16_t main, uint16_t sub, const void *data, size_t len);
/* 1: complete frame, 0: incomplete, -1: invalid. Caller frees *body. */
int op_frame_take(op_buffer *b, uint16_t *main, uint16_t *sub, uint8_t **body, size_t *len);
json_object *op_json(const void *data, size_t len);
json_object *op_get(json_object *obj, const char *name);
const char *op_string(json_object *obj, const char *name);
uint64_t op_integer(json_object *obj, const char *name);
void op_js(json_object *obj, const char *name, const char *value);
void op_ju(json_object *obj, const char *name, uint64_t value);
/* Existing wire format: repeated LE uint64 key, fixed IV, AES-128-CBC/PKCS#7. */
int op_crypt(int encrypt, uint64_t key, const uint8_t *in, size_t len, uint8_t *out,
             size_t capacity, size_t *written);
#endif
