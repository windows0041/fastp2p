#ifndef FASTP2P_STORE_H
#define FASTP2P_STORE_H
#include <sqlite3.h>
#include <json-c/json.h>
#include <stdint.h>
struct connection;
struct gw_admin {
    char user[257], secret[65];
    unsigned char salt[16], hash[32];
    unsigned iterations;
};
int gw_admin_make(struct gw_admin *admin, const char *user, const char *password);
int gw_admin_verify(const struct gw_admin *admin, const char *password);
int gw_store_admin_read(sqlite3 *db, struct gw_admin *admin);
int gw_store_admin_write(sqlite3 *db, const struct gw_admin *admin);
/* 0 deleted, 1 absent, 2 online, -1 storage failure. */
int gw_store_delete_offline(sqlite3 *db, const char *name);
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

/* Persistent per-node forwarding / SOCKS5 rules. The payload is the complete
 * rule JSON as sent by the console; the gateway stores it verbatim so adding a
 * field later does not require a schema change. Rules are keyed by the pair the
 * console already uses: (protocol, srcPort). */
int gw_store_rule_put(sqlite3 *db, const char *node, const char *protocol,
                      unsigned src_port, const char *payload, int enabled);
int gw_store_rule_delete(sqlite3 *db, const char *node, const char *protocol,
                         unsigned src_port);
int gw_store_rule_set_enabled(sqlite3 *db, const char *node, const char *protocol,
                              unsigned src_port, int enabled);
/* Returns a JSON array of {protocol, srcPort, enabled, payload} objects, or NULL
 * on failure. The caller owns the returned reference. */
json_object *gw_store_rules(sqlite3 *db, const char *node);
/* A node becomes gateway-managed the first time the console writes a rule for
 * it. That fact survives deleting the last rule, so a restart does not silently
 * fall back to rules from a local config file. */
int gw_store_rule_managed(sqlite3 *db, const char *node);
#endif
