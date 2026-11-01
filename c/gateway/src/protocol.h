#ifndef OP2P_GATEWAY_PROTOCOL_H
#define OP2P_GATEWAY_PROTOCOL_H
#include <json-c/json.h>
#include <stddef.h>
#include <stdint.h>
#define GW_VERSION "0.2.0"
#define GW_FRAME_LIMIT (1024u * 1024u)
uint16_t gw_u16(const void *p);
uint32_t gw_u32(const void *p);
uint64_t gw_u64(const void *p);
void gw_put16(void *p, uint16_t v);
void gw_put32(void *p, uint32_t v);
void gw_put64(void *p, uint64_t v);
uint64_t gw_node_id(const char *text);
uint64_t gw_mono_ms(void);
uint64_t gw_wall_ns(void);
int gw_decimal(const char *text, uint64_t *out);
int gw_node_valid(const char *text);
json_object *gw_json(const void *data, size_t len);
char *gw_json_text(json_object *value, size_t *length);
json_object *gw_get(json_object *j, const char *name);
const char *gw_string(json_object *j, const char *name);
uint64_t gw_integer(json_object *j, const char *name);
void gw_js(json_object *j, const char *name, const char *text);
void gw_ju(json_object *j, const char *name, uint64_t value);
uint64_t gw_totp(uint64_t token, uint64_t timestamp);
int gw_token_valid(uint64_t code, uint64_t token, uint64_t timestamp);
char *gw_jwt_issue(const char *user, uint64_t token, const char *secret, uint64_t now);
int gw_jwt_verify(const char *text, const char *user, uint64_t token, const char *secret,
                  uint64_t now);
int gw_secret_equal(const char *a, const char *b);
#endif
