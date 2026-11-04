#include "gateway.h"
#include "config_merge.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void) {
    char path[]="/tmp/fastp2p-config-store-XXXXXX";int fd=mkstemp(path);assert(fd>=0);close(fd);
    sqlite3 *db=NULL;assert(!gw_store_open(&db,path));
    json_object *a=json_tokener_parse("{\"nested\":{\"keep\":1,\"change\":2},\"array\":[1,2],\"local\":true}"),
                *b=json_tokener_parse("{\"nested\":{\"change\":3},\"array\":[4],\"null\":null}"),*merged=NULL;
    assert(!fp_config_merge(a,b,&merged));
    assert(gw_integer(gw_get(merged,"nested"),"keep")==1&&gw_integer(gw_get(merged,"nested"),"change")==3);
    assert(json_object_array_length(gw_get(merged,"array"))==1&&json_object_get_boolean(gw_get(merged,"local")));
    assert(gw_integer(gw_get(a,"nested"),"change")==2);json_object_put(merged);
    assert(!gw_store_config_put(db,"config-store-node",a));
    assert(!gw_store_config_put(db,"config-store-node",b));
    json_object *stored=gw_store_config(db,"config-store-node");assert(gw_integer(stored,"revision")==2);
    assert(gw_integer(gw_get(gw_get(stored,"fields"),"nested"),"keep")==1);json_object_put(stored);
    assert(!gw_store_config_ack(db,"config-store-node",2,"applied"));
    assert(!gw_store_config_ack(db,"config-store-node",1,"failed")); /* stale ACK cannot replace new status */
    stored=gw_store_config(db,"config-store-node");assert(!strcmp(gw_string(stored,"state"),"applied"));json_object_put(stored);
    json_object *rules=json_tokener_parse("{\"apps\":[{\"AppName\":\"ssh\",\"Protocol\":\"tcp\",\"SrcPort\":23322,\"PeerNode\":\"test-peer-node\",\"DstHost\":\"localhost\",\"DstPort\":22,\"custom\":{\"keep\":42}}]}");
    assert(!gw_store_config_put(db,"config-store-node",rules));assert(!gw_store_config_rules(db,"config-store-node"));
    stored=gw_store_config(db,"config-store-node");
    json_object *entry=json_object_array_get_idx(gw_get(gw_get(stored,"fields"),"apps"),0);
    assert(gw_integer(gw_get(entry,"custom"),"keep")==42);json_object_put(stored);
    json_object *bad=json_tokener_parse("{\"apps\":[{\"SrcPort\":1,\"Protocol\":\"invalid\"}]}");
    assert(gw_store_config_put(db,"config-store-node",bad)==-1);
    stored=gw_store_rules(db,"config-store-node");assert(json_object_array_length(stored)==1);json_object_put(stored);
    json_object_put(a);json_object_put(b);json_object_put(rules);json_object_put(bad);sqlite3_close(db);
    assert(!gw_store_open(&db,path));stored=gw_store_config(db,"config-store-node");assert(gw_integer(stored,"revision")>=3);
    json_object_put(stored);sqlite3_close(db);unlink(path);
    puts("Recursive key merge, arrays, unknown fields, transactional rules and stale ACK protection passed");return 0;
}
