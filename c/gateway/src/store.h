#ifndef OP2P_STORE_H
#define OP2P_STORE_H
#include <sqlite3.h>
#include <json-c/json.h>
#include <stdint.h>
struct connection;
int gw_store_open(sqlite3 **db, const char *path);
/* 0 = claimed; 1 = conflicting explicit name; -1 = storage failure. */
int gw_store_claim(sqlite3 *db, const char *requested, const char *hostname,
                   const char *device, int automatic, char assigned[32]);
int gw_store_save(sqlite3 *db, const struct connection *node, int online);
int gw_store_count(sqlite3 *db, uint64_t *count);
json_object *gw_store_list(sqlite3 *db, const char *search, unsigned limit, unsigned offset);
int gw_device_valid(const char *device);
int gw_store_manual_status(sqlite3 *db, const char *name);
int gw_store_resolve(sqlite3 *db, const char *device, char name[32]);
#endif
