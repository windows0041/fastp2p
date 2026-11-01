#include "gateway.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char path[] = "/tmp/fastp2p-store-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0); close(fd);
    sqlite3 *db;
    assert(!gw_store_open(&db, path));
    struct gw_admin admin, restored;
    assert(gw_store_admin_read(db, &admin) == 1);
    assert(!gw_admin_make(&admin, "custom-admin", "private-unit-test-password"));
    assert(gw_admin_verify(&admin, "private-unit-test-password"));
    assert(!gw_admin_verify(&admin, "wrong-password"));
    assert(!gw_store_admin_write(db, &admin) && !gw_store_admin_read(db, &restored));
    assert(!memcmp(&admin, &restored, sizeof(admin)));
    const char *first = "11111111111111111111111111111111";
    char name[32], second[32], original[32];
    assert(!gw_store_claim(db, "ignored", "pc", first, 1, name));
    assert(strlen(name) == 8 && !strncmp(name, "pc", 2));
    for (int i = 2; i < 8; ++i) assert(name[i] >= '0' && name[i] <= '9');
    strcpy(original, name);
    assert(!gw_store_claim(db, "ignored", "new-host", first, 1, name) && !strcmp(name, original));
    assert(!gw_store_claim(db, "ignored", "pc", "22222222222222222222222222222222", 1, second));
    assert(strcmp(name, second));
    assert(!gw_store_claim(db, "ignored", "host-one", "33333333333333333333333333333333", 1, name));
    assert(!strcmp(name, "host-one"));
    assert(!gw_store_claim(db, "ignored", "host-one", "44444444444444444444444444444444", 1, second));
    assert(!strncmp(second, "host-one-", 9) && strlen(second) == 19);
    assert(gw_store_manual_status(db, "host-one") == 1);
    assert(gw_store_claim(db, "host-one", "", "", 0, second) == 1);
    assert(!gw_store_claim(db, "legacy-node", "", "", 0, name));
    assert(!gw_store_manual_status(db, "legacy-node"));
    assert(!gw_store_claim(db, "legacy-node", "", "", 0, second));
    assert(!strcmp(name, second));
    struct connection connection = {0};
    strcpy(connection.node, name); strcpy(connection.ip, "192.0.2.44");
    strcpy(connection.os, "linux-c"); strcpy(connection.hostname, "unit-host");
    strcpy(connection.lan, "127.0.0.1");
    connection.last_seen_wall = gw_wall_ns();
    assert(!gw_store_save(db, &connection, 1));
    assert(gw_store_delete_offline(db, name) == 2);
    json_object *list = gw_store_list(db, "legacy", 100, 0);
    assert(list && gw_integer(list, "total") == 1);
    json_object *node = json_object_array_get_idx(gw_get(list, "nodes"), 0);
    assert(gw_integer(node, "isActive") == 1 && !strcmp(gw_string(node, "hostname"), "unit-host"));
    json_object_put(list);
    assert(!gw_store_save(db, &connection, 0));
    assert(!gw_store_save(db, &connection, 1));
    sqlite3_close(db);
    assert(!gw_store_open(&db, path));
    assert(gw_store_resolve(db, first, name) == 1 && !strcmp(name, original));
    list = gw_store_list(db, "legacy", 100, 0);
    node = json_object_array_get_idx(gw_get(list, "nodes"), 0);
    assert(gw_integer(node, "isActive") == 0 && *gw_string(node, "firstSeen") && *gw_string(node, "lastSeen"));
    json_object_put(list);
    list = gw_store_list(db, "%' OR 1=1 --", 100, 0);
    assert(list && !gw_integer(list, "total")); json_object_put(list);
    for (unsigned i = 10; i < 110; ++i) {
        char identity[33]; snprintf(identity, sizeof(identity), "%032x", i);
        assert(!gw_store_claim(db, "ignored", "same-host", identity, 1, name));
        assert(gw_node_valid(name));
    }
    uint64_t total;
    assert(!gw_store_count(db, &total) && total == 105);
    list = gw_store_list(db, "same-host", 5, 5);
    assert(list && gw_integer(list, "total") == 100 && json_object_array_length(gw_get(list, "nodes")) == 5);
    json_object_put(list);
    assert(gw_store_delete_offline(db, "no-such-node") == 1);
    assert(!gw_store_delete_offline(db, "legacy-node"));
    assert(gw_store_delete_offline(db, "legacy-node") == 1);
    assert(!sqlite3_exec(db, "PRAGMA application_id=1330655824; PRAGMA user_version=1", NULL, NULL, NULL));
    sqlite3_close(db);
    assert(!gw_store_open(&db, path));
    sqlite3_stmt *statement;
    assert(!sqlite3_prepare_v2(db, "PRAGMA application_id", -1, &statement, NULL));
    assert(sqlite3_step(statement) == SQLITE_ROW && sqlite3_column_int(statement, 0) == 1179660880);
    sqlite3_finalize(statement);
    assert(!gw_store_count(db, &total) && total == 104);
    assert(!gw_store_admin_read(db, &restored) && gw_admin_verify(&restored, "private-unit-test-password"));
    sqlite3_close(db); unlink(path);
    puts("SQLite identity uniqueness, numeric padding, offline persistence, search and pagination passed");
    return 0;
}
