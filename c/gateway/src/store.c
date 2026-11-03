#include "gateway.h"
#include <inttypes.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define APP_ID 0x46503250
#define PREVIOUS_APP_ID 0x4f503250
static int sql(sqlite3 *db, const char *text) {
    return sqlite3_exec(db, text, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}
static int scalar(sqlite3 *db, const char *text, sqlite3_int64 *value) {
    sqlite3_stmt *statement = NULL;
    int ok = sqlite3_prepare_v2(db, text, -1, &statement, NULL) == SQLITE_OK &&
             sqlite3_step(statement) == SQLITE_ROW;
    if (ok)
        *value = sqlite3_column_int64(statement, 0);
    sqlite3_finalize(statement);
    return ok ? 0 : -1;
}
int gw_store_open(sqlite3 **out, const char *path) {
    *out = NULL;
    sqlite3 *db = NULL;
    if (!path || !*path || sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                                                     SQLITE_OPEN_NOMUTEX, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_busy_timeout(db, 50);
    sqlite3_int64 app = 0, version = 0, tables = 0;
    if (scalar(db, "PRAGMA application_id", &app) || scalar(db, "PRAGMA user_version", &version) ||
        scalar(db, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'", &tables) ||
        (app != APP_ID && app != PREVIOUS_APP_ID && (app != 0 || tables != 0)) || version > 3)
        goto fail;
    /* One event-loop writer; rollback journaling also supports simple offline backups. */
    if (sql(db, "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;") ||
        sql(db, "BEGIN IMMEDIATE;"
                "CREATE TABLE IF NOT EXISTS nodes("
                "name TEXT PRIMARY KEY CHECK(length(name) BETWEEN 8 AND 31 AND name NOT GLOB '*[^a-zA-Z0-9_-]*'),"
                "node_id TEXT NOT NULL UNIQUE, device_id TEXT UNIQUE, hostname TEXT NOT NULL DEFAULT '',"
                "ip TEXT NOT NULL DEFAULT '', ipv6 TEXT NOT NULL DEFAULT '', lanip TEXT NOT NULL DEFAULT '',"
                "mac TEXT NOT NULL DEFAULT '', os TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '',"
                "nat INTEGER NOT NULL DEFAULT 314, bandwidth INTEGER NOT NULL DEFAULT 0,"
                "first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, last_offline INTEGER NOT NULL DEFAULT 0,"
                "online INTEGER NOT NULL DEFAULT 0 CHECK(online IN(0,1)));"
                "CREATE INDEX IF NOT EXISTS nodes_order ON nodes(online DESC, name);"
                "CREATE TABLE IF NOT EXISTS admin(id INTEGER PRIMARY KEY CHECK(id=1),username TEXT NOT NULL,"
                "salt BLOB NOT NULL CHECK(length(salt)=16),password_hash BLOB NOT NULL CHECK(length(password_hash)=32),"
                "iterations INTEGER NOT NULL,jwt_secret TEXT NOT NULL CHECK(length(jwt_secret)=64));"
                "CREATE TABLE IF NOT EXISTS rules("
                "node TEXT NOT NULL,protocol TEXT NOT NULL,src_port INTEGER NOT NULL,"
                "payload TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN(0,1)),"
                "PRIMARY KEY(node,protocol,src_port),"
                "FOREIGN KEY(node) REFERENCES nodes(name) ON DELETE CASCADE);"
                "CREATE TABLE IF NOT EXISTS rule_nodes(node TEXT PRIMARY KEY);"
                "PRAGMA application_id=1179660880; PRAGMA user_version=3;"
                "UPDATE nodes SET online=0; COMMIT;"))
        goto fail;
    *out = db;
    return 0;
fail:
    if (db)
        sqlite3_close(db);
    return -1;
}
int gw_device_valid(const char *text) {
    if (!text || strlen(text) != 32)
        return 0;
    for (; *text; ++text)
        if (!((*text >= '0' && *text <= '9') || (*text >= 'a' && *text <= 'f')))
            return 0;
    return 1;
}
int gw_store_delete_offline(sqlite3 *db, const char *name) {
    sqlite3_stmt *s = NULL;
    if (!gw_node_valid(name) || sqlite3_prepare_v2(db, "DELETE FROM nodes WHERE name=? AND online=0", -1, &s, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(s, 1, name, -1, SQLITE_TRANSIENT);
    int ok = sqlite3_step(s) == SQLITE_DONE, changed = sqlite3_changes(db);
    sqlite3_finalize(s);
    if (!ok) return -1;
    if (changed) return 0;
    if (sqlite3_prepare_v2(db, "SELECT online FROM nodes WHERE name=?", -1, &s, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(s, 1, name, -1, SQLITE_TRANSIENT);
    int row = sqlite3_step(s);
    sqlite3_finalize(s);
    return row == SQLITE_ROW ? 2 : row == SQLITE_DONE ? 1 : -1;
}
int gw_store_manual_status(sqlite3 *db, const char *name) {
    sqlite3_stmt *statement = NULL;
    char id[32];
    snprintf(id, sizeof(id), "%" PRIu64, gw_node_id(name));
    if (sqlite3_prepare_v2(db, "SELECT name,device_id FROM nodes WHERE name=? OR node_id=?",
                          -1, &statement, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(statement, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, id, -1, SQLITE_TRANSIENT);
    int result = sqlite3_step(statement), status = 0;
    if (result == SQLITE_ROW)
        status = strcmp((const char *)sqlite3_column_text(statement, 0), name) ||
                 sqlite3_column_type(statement, 1) != SQLITE_NULL;
    else if (result != SQLITE_DONE)
        status = -1;
    sqlite3_finalize(statement);
    return status;
}
int gw_store_resolve(sqlite3 *db, const char *device, char name[32]) {
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(db, "SELECT name FROM nodes WHERE device_id=?", -1, &statement, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(statement, 1, device, -1, SQLITE_TRANSIENT);
    int result = sqlite3_step(statement), found = result == SQLITE_ROW;
    if (found)
        snprintf(name, 32, "%s", (const char *)sqlite3_column_text(statement, 0));
    sqlite3_finalize(statement);
    return found ? 1 : result == SQLITE_DONE ? 0 : -1;
}
static int digit(char *out) {
    unsigned char value;
    do {
        if (RAND_bytes(&value, 1) != 1)
            return -1;
    } while (value >= 250);
    *out = (char)('0' + value % 10);
    return 0;
}
static int candidate(const char *hostname, int collision, char out[32]) {
    size_t used = 0, maximum = collision ? 20 : 31;
    for (const unsigned char *p = (const unsigned char *)hostname; *p && used < maximum; ++p) {
        unsigned c = *p;
        out[used++] = ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '_' || c == '-') ? (char)c : '-';
    }
    if (!used) {
        memcpy(out, "node", 4);
        used = 4;
    }
    if (collision) {
        out[used++] = '-';
        for (int i = 0; i < 10; ++i)
            if (digit(&out[used++]))
                return -1;
    }
    while (used < 8)
        if (digit(&out[used++]))
            return -1;
    out[used] = 0;
    return 0;
}
int gw_store_claim(sqlite3 *db, const char *requested, const char *hostname,
                   const char *device, int automatic, char assigned[32]) {
    if (!db || !hostname || strlen(hostname) > 255 ||
        (automatic ? !gw_device_valid(device) : !gw_node_valid(requested)))
        return -1;
    if (sql(db, "BEGIN IMMEDIATE"))
        return -1;
    sqlite3_stmt *statement = NULL;
    const char *lookup = automatic ? "SELECT name FROM nodes WHERE device_id=?" :
                                     "SELECT device_id FROM nodes WHERE name=?";
    if (sqlite3_prepare_v2(db, lookup, -1, &statement, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(statement, 1, automatic ? device : requested, -1, SQLITE_TRANSIENT);
    int result = sqlite3_step(statement);
    if (result == SQLITE_ROW) {
        if (!automatic && sqlite3_column_type(statement, 0) != SQLITE_NULL) {
            sqlite3_finalize(statement);
            sql(db, "ROLLBACK");
            return 1;
        }
        snprintf(assigned, 32, "%s", automatic ? (const char *)sqlite3_column_text(statement, 0) : requested);
        sqlite3_finalize(statement);
        if (sql(db, "COMMIT")) {
            sql(db, "ROLLBACK");
            return -1;
        }
        return 0;
    }
    sqlite3_finalize(statement);
    statement = NULL;
    if (result != SQLITE_DONE)
        goto fail;
    for (int attempt = 0; attempt < (automatic ? 128 : 1); ++attempt) {
        if (automatic) {
            if (candidate(hostname, attempt != 0, assigned))
                goto fail;
        } else
            snprintf(assigned, 32, "%s", requested);
        char id[32];
        snprintf(id, sizeof(id), "%" PRIu64, gw_node_id(assigned));
        if (sqlite3_prepare_v2(db, "INSERT INTO nodes(name,node_id,device_id,hostname,first_seen,last_seen) VALUES(?,?,?,?,?,?)",
                              -1, &statement, NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_text(statement, 1, assigned, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, id, -1, SQLITE_TRANSIENT);
        if (automatic)
            sqlite3_bind_text(statement, 3, device, -1, SQLITE_TRANSIENT);
        else
            sqlite3_bind_null(statement, 3);
        sqlite3_bind_text(statement, 4, hostname, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(statement, 5, (sqlite3_int64)time(NULL));
        sqlite3_bind_int64(statement, 6, (sqlite3_int64)time(NULL));
        result = sqlite3_step(statement);
        sqlite3_finalize(statement);
        statement = NULL;
        if (result == SQLITE_DONE) {
            if (sql(db, "COMMIT"))
                goto fail;
            return 0;
        }
        if (result != SQLITE_CONSTRAINT)
            goto fail;
    }
    sql(db, "ROLLBACK");
    return 1;
fail:
    sqlite3_finalize(statement);
    sql(db, "ROLLBACK");
    return -1;
}
int gw_store_save(sqlite3 *db, const struct connection *node, int online) {
    sqlite3_stmt *statement = NULL;
    const char *text = "UPDATE nodes SET ip=?,ipv6=?,lanip=CASE WHEN ?<>'' THEN ? ELSE lanip END,"
                       "mac=CASE WHEN ?<>'' THEN ? ELSE mac END,os=CASE WHEN ?<>'' THEN ? ELSE os END,"
                       "version=CASE WHEN ?<>'' THEN ? ELSE version END,"
                       "hostname=CASE WHEN ?<>'' THEN ? ELSE hostname END,nat=?,bandwidth=?,last_seen=?,"
                       "online=?,last_offline=CASE WHEN ?=0 THEN ? ELSE last_offline END WHERE name=?";
    if (sqlite3_prepare_v2(db, text, -1, &statement, NULL) != SQLITE_OK)
        return -1;
    int parameter = 1;
    sqlite3_bind_text(statement, parameter++, node->ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, parameter++, node->ipv6, -1, SQLITE_TRANSIENT);
    const char *fields[] = {node->lan, node->mac, node->os, node->version, node->hostname};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
        sqlite3_bind_text(statement, parameter++, fields[i], -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, parameter++, fields[i], -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_int(statement, parameter++, (int)node->nat);
    sqlite3_bind_int(statement, parameter++, (int)node->bandwidth);
    sqlite3_bind_int64(statement, parameter++, (sqlite3_int64)(node->last_seen_wall / 1000000000));
    sqlite3_bind_int(statement, parameter++, online);
    sqlite3_bind_int(statement, parameter++, online);
    sqlite3_bind_int64(statement, parameter++, (sqlite3_int64)time(NULL));
    sqlite3_bind_text(statement, parameter++, node->node, -1, SQLITE_TRANSIENT);
    int ok = sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(db) == 1;
    sqlite3_finalize(statement);
    return ok ? 0 : -1;
}
int gw_store_count(sqlite3 *db, uint64_t *count) {
    sqlite3_int64 value = 0;
    if (scalar(db, "SELECT count(*) FROM nodes", &value))
        return -1;
    *count = (uint64_t)value;
    return 0;
}
static void date(json_object *object, const char *key, sqlite3_int64 value) {
    char buffer[32] = "";
    time_t timestamp = (time_t)value;
    struct tm utc;
    if (value && gmtime_r(&timestamp, &utc))
        strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &utc);
    gw_js(object, key, buffer);
}
json_object *gw_store_list(sqlite3 *db, const char *search, unsigned limit, unsigned offset) {
    if (!search || strlen(search) > 255 || !limit || limit > 256)
        return NULL;
    char pattern[514];
    size_t used = 0;
    pattern[used++] = '%';
    for (const char *p = search; *p; ++p) {
        if (*p == '%' || *p == '_' || *p == '\\')
            pattern[used++] = '\\';
        pattern[used++] = *p;
    }
    pattern[used++] = '%'; pattern[used] = 0;
    const char *where = " WHERE name LIKE ?1 ESCAPE '\\' OR hostname LIKE ?1 ESCAPE '\\' OR ip LIKE ?1 ESCAPE '\\' OR lanip LIKE ?1 ESCAPE '\\' OR os LIKE ?1 ESCAPE '\\'";
    char query[1024];
    sqlite3_stmt *statement = NULL;
    snprintf(query, sizeof(query), "SELECT count(*) FROM nodes%s", where);
    if (sqlite3_prepare_v2(db, query, -1, &statement, NULL) != SQLITE_OK)
        return NULL;
    sqlite3_bind_text(statement, 1, pattern, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return NULL;
    }
    uint64_t total = (uint64_t)sqlite3_column_int64(statement, 0);
    sqlite3_finalize(statement);
    statement = NULL;
    snprintf(query, sizeof(query), "SELECT name,node_id,hostname,ip,ipv6,lanip,mac,os,version,nat,bandwidth,first_seen,last_seen,last_offline,online FROM nodes%s ORDER BY online DESC,name LIMIT ?2 OFFSET ?3", where);
    if (sqlite3_prepare_v2(db, query, -1, &statement, NULL) != SQLITE_OK)
        return NULL;
    sqlite3_bind_text(statement, 1, pattern, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 2, (int)limit);
    sqlite3_bind_int64(statement, 3, (sqlite3_int64)offset);
    json_object *root = json_object_new_object(), *nodes = json_object_new_array();
    json_object_object_add(root, "nodes", nodes);
    gw_ju(root, "total", total); gw_ju(root, "offset", offset); gw_ju(root, "limit", limit);
    int result;
    while ((result = sqlite3_step(statement)) == SQLITE_ROW) {
        json_object *node = json_object_new_object();
        const char *keys[] = {"name", "id", "hostname", "ip", "ipv6", "lanip", "mac", "os", "version"};
        for (int i = 0; i < 9; ++i)
            gw_js(node, keys[i], (const char *)sqlite3_column_text(statement, i));
        char number[32];
        snprintf(number, sizeof(number), "%d", sqlite3_column_int(statement, 9)); gw_js(node, "natType", number);
        snprintf(number, sizeof(number), "%d", sqlite3_column_int(statement, 10)); gw_js(node, "bandwidth", number);
        date(node, "firstSeen", sqlite3_column_int64(statement, 11));
        date(node, "lastSeen", sqlite3_column_int64(statement, 12));
        date(node, "lastOffline", sqlite3_column_int64(statement, 13));
        date(node, "activetime", sqlite3_column_int64(statement, 12));
        gw_ju(node, "isActive", (uint64_t)sqlite3_column_int(statement, 14));
        json_object_array_add(nodes, node);
    }
    sqlite3_finalize(statement);
    if (result != SQLITE_DONE) {
        json_object_put(root);
        return NULL;
    }
    return root;
}

/* --- Persistent per-node rules -------------------------------------------
 * The gateway is the source of truth. It stores the console's rule JSON
 * verbatim; only the identity fields (node, protocol, port) and the enabled
 * flag are normalised into columns so editing and toggling are unambiguous. */
static int rule_identity(const char *node, const char *protocol, unsigned src_port) {
    return !gw_node_valid(node) || !protocol ||
           (strcmp(protocol, "tcp") && strcmp(protocol, "udp") && strcmp(protocol, "socks5")) ||
           !src_port || src_port > 65535;
}
int gw_store_rule_put(sqlite3 *db, const char *node, const char *protocol,
                      unsigned src_port, const char *payload, int enabled) {
    if (rule_identity(node, protocol, src_port) || !payload || !*payload)
        return -1;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO rules(node,protocol,src_port,payload,enabled) VALUES(?1,?2,?3,?4,?5) "
        "ON CONFLICT(node,protocol,src_port) DO UPDATE SET payload=excluded.payload,"
        "enabled=excluded.enabled", -1, &s, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(s, 1, node, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, protocol, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 3, (int)src_port);
    sqlite3_bind_text(s, 4, payload, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 5, enabled ? 1 : 0);
    int ok = sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s);
    if (!ok)
        return -1;
    /* Remember that this node's rules are owned by the gateway, even if every
     * rule is later removed. */
    sqlite3_stmt *marker = NULL;
    if (sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO rule_nodes(node) VALUES(?1)",
                           -1, &marker, NULL) == SQLITE_OK) {
        sqlite3_bind_text(marker, 1, node, -1, SQLITE_TRANSIENT);
        sqlite3_step(marker);
        sqlite3_finalize(marker);
    }
    return 0;
}
int gw_store_rule_managed(sqlite3 *db, const char *node) {
    if (!gw_node_valid(node))
        return 0;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM rule_nodes WHERE node=?1", -1, &s, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(s, 1, node, -1, SQLITE_TRANSIENT);
    int managed = sqlite3_step(s) == SQLITE_ROW;
    sqlite3_finalize(s);
    return managed;
}
int gw_store_rule_delete(sqlite3 *db, const char *node, const char *protocol,
                         unsigned src_port) {
    if (rule_identity(node, protocol, src_port))
        return -1;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "DELETE FROM rules WHERE node=?1 AND protocol=?2 AND src_port=?3",
                           -1, &s, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(s, 1, node, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, protocol, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 3, (int)src_port);
    int ok = sqlite3_step(s) == SQLITE_DONE && sqlite3_changes(db) > 0;
    sqlite3_finalize(s);
    return ok ? 0 : -1;
}
int gw_store_rule_set_enabled(sqlite3 *db, const char *node, const char *protocol,
                              unsigned src_port, int enabled) {
    if (rule_identity(node, protocol, src_port))
        return -1;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "UPDATE rules SET enabled=?4 WHERE node=?1 AND protocol=?2 "
                           "AND src_port=?3", -1, &s, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(s, 1, node, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, protocol, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 3, (int)src_port);
    sqlite3_bind_int(s, 4, enabled ? 1 : 0);
    int ok = sqlite3_step(s) == SQLITE_DONE && sqlite3_changes(db) > 0;
    sqlite3_finalize(s);
    return ok ? 0 : -1;
}
json_object *gw_store_rules(sqlite3 *db, const char *node) {
    if (!gw_node_valid(node))
        return NULL;
    json_object *list = json_object_new_array();
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT protocol,src_port,payload,enabled FROM rules "
                           "WHERE node=?1 ORDER BY protocol,src_port", -1, &s, NULL) != SQLITE_OK) {
        json_object_put(list);
        return NULL;
    }
    sqlite3_bind_text(s, 1, node, -1, SQLITE_TRANSIENT);
    int result;
    while ((result = sqlite3_step(s)) == SQLITE_ROW) {
        json_object *rule = json_object_new_object();
        gw_js(rule, "protocol", (const char *)sqlite3_column_text(s, 0));
        gw_ju(rule, "srcPort", (uint64_t)sqlite3_column_int(s, 1));
        gw_ju(rule, "enabled", (uint64_t)sqlite3_column_int(s, 3));
        /* Embed the stored JSON as an object so the client can apply it directly. */
        json_object *payload = json_tokener_parse((const char *)sqlite3_column_text(s, 2));
        json_object_object_add(rule, "rule", payload ? payload : json_object_new_object());
        json_object_array_add(list, rule);
    }
    sqlite3_finalize(s);
    if (result != SQLITE_DONE) {
        json_object_put(list);
        return NULL;
    }
    return list;
}
