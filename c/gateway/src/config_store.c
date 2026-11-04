#include "gateway.h"
#include "config_merge.h"
#include <string.h>

/* Translate the existing rule console and file configuration into one desired
 * state. Keep original descriptors so future/unknown keys survive round trips. */
static const char *names[][2]={{"PeerNode","peerNode"},{"BindIP","whitelist"},
 {"DstHost","dstHost"},{"DstPort","dstPort"},{"SrcPort","srcPort"},
 {"RelayNode","relayNode"},{"Username","Username"},{"Password","Password"}};
static void copy(json_object *to,const char *key,json_object *from,const char *source) {
    json_object *value=gw_get(from,source);if(value)json_object_object_add(to,key,json_object_get(value));
}
static int replace_rules(sqlite3 *db,const char *node,json_object *fields) {
    const char *arrays[]={"apps","socks5"};
    for(unsigned type=0;type<2;++type) {
        json_object *array=NULL;if(!json_object_object_get_ex(fields,arrays[type],&array))continue;
        if(!json_object_is_type(array,json_type_array)||json_object_array_length(array)>256)return -1;
        sqlite3_stmt *statement=NULL;
        const char *sql=type?"DELETE FROM rules WHERE node=? AND protocol='socks5'":
                            "DELETE FROM rules WHERE node=? AND protocol IN('tcp','udp')";
        if(sqlite3_prepare_v2(db,sql,-1,&statement,NULL)!=SQLITE_OK)return -1;
        sqlite3_bind_text(statement,1,node,-1,SQLITE_TRANSIENT);
        int ok=sqlite3_step(statement)==SQLITE_DONE;sqlite3_finalize(statement);if(!ok)return -1;
        for(size_t i=0;i<json_object_array_length(array);++i) {
            json_object *entry=json_object_array_get_idx(array,i);
            if(!json_object_is_type(entry,json_type_object))return -1;
            const char *protocol=type?"socks5":gw_string(entry,"Protocol");
            uint64_t port=gw_integer(entry,"SrcPort");
            if(!port||port>65535||(!type&&strcmp(protocol,"tcp")&&strcmp(protocol,"udp")))return -1;
            json_object *rule=json_object_new_object();
            json_object_object_add(rule,"_config",json_object_get(entry));
            copy(rule,"appName",entry,type?"Name":"AppName");gw_js(rule,"protocol",protocol);
            for(unsigned k=0;k<sizeof(names)/sizeof(names[0]);++k)copy(rule,names[k][1],entry,names[k][0]);
            gw_ju(rule,"punchPriority",!strcmp(gw_string(entry,"UnderlayProtocol"),"tcp")?2:0);
            json_object *enabled=NULL;int on=!json_object_object_get_ex(entry,"Enabled",&enabled)||json_object_get_boolean(enabled);
            int result=gw_store_rule_put(db,node,protocol,(unsigned)port,
                json_object_to_json_string_ext(rule,JSON_C_TO_STRING_PLAIN),on);
            json_object_put(rule);if(result)return -1;
        }
        sqlite3_stmt *mark=NULL;
        if(sqlite3_prepare_v2(db,"INSERT OR IGNORE INTO rule_nodes VALUES(?)",-1,&mark,NULL)!=SQLITE_OK)return -1;
        sqlite3_bind_text(mark,1,node,-1,SQLITE_TRANSIENT);
        ok=sqlite3_step(mark)==SQLITE_DONE;sqlite3_finalize(mark);if(!ok)return -1;
    }
    return 0;
}
json_object *gw_store_config(sqlite3 *db,const char *node) {
    if(!gw_node_valid(node))return NULL;
    sqlite3_stmt *statement=NULL;
    if(sqlite3_prepare_v2(db,"SELECT fields,revision,state,ack_revision FROM node_configs WHERE node=?",-1,&statement,NULL)!=SQLITE_OK)return NULL;
    sqlite3_bind_text(statement,1,node,-1,SQLITE_TRANSIENT);
    json_object *root=json_object_new_object(),*fields=NULL;
    int status=sqlite3_step(statement);
    if(status==SQLITE_ROW) {
        fields=json_tokener_parse((const char *)sqlite3_column_text(statement,0));
        gw_ju(root,"revision",(uint64_t)sqlite3_column_int64(statement,1));
        gw_js(root,"state",(const char *)sqlite3_column_text(statement,2));
        gw_ju(root,"ackRevision",(uint64_t)sqlite3_column_int64(statement,3));
    } else if(status==SQLITE_DONE) {fields=json_object_new_object();gw_ju(root,"revision",0);gw_js(root,"state","none");}
    sqlite3_finalize(statement);
    if(!json_object_is_type(fields,json_type_object)) {if(fields)json_object_put(fields);json_object_put(root);return NULL;}
    json_object_object_add(root,"fields",fields);gw_ju(root,"error",0);return root;
}
int gw_store_config_put(sqlite3 *db,const char *node,json_object *fields) {
    if(!gw_node_valid(node)||!json_object_is_type(fields,json_type_object))return -1;
    json_object *forbidden=NULL;
    if(json_object_object_get_ex(fields,"_fastp2pManaged",&forbidden))return -1;
    if(sqlite3_exec(db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)return -1;
    json_object *old=gw_store_config(db,node),*next=NULL;int result=-1;
    if(!old||fp_config_merge(gw_get(old,"fields"),fields,&next))goto done;
    const char *text=json_object_to_json_string_ext(next,JSON_C_TO_STRING_PLAIN);
    if(strlen(text)>65536||replace_rules(db,node,fields))goto done;
    sqlite3_stmt *statement=NULL;
    if(sqlite3_prepare_v2(db,"INSERT INTO node_configs VALUES(?1,?2,1,'queued',0) ON CONFLICT(node) "
        "DO UPDATE SET fields=excluded.fields,revision=revision+1,state='queued'",-1,&statement,NULL)!=SQLITE_OK)goto done;
    sqlite3_bind_text(statement,1,node,-1,SQLITE_TRANSIENT);sqlite3_bind_text(statement,2,text,-1,SQLITE_TRANSIENT);
    int ok=sqlite3_step(statement)==SQLITE_DONE;sqlite3_finalize(statement);
    if(ok&&sqlite3_exec(db,"COMMIT",NULL,NULL,NULL)==SQLITE_OK)result=0;
done:
    if(result)sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);
    if(old)json_object_put(old);
    if(next)json_object_put(next);
    return result;
}
int gw_store_config_ack(sqlite3 *db,const char *node,uint64_t revision,const char *state) {
    if(!gw_node_valid(node)||!state||(strcmp(state,"applied")&&strcmp(state,"saved")&&strcmp(state,"failed")))return -1;
    sqlite3_stmt *statement=NULL;
    if(sqlite3_prepare_v2(db,"UPDATE node_configs SET state=?,ack_revision=? WHERE node=? AND revision=?",-1,&statement,NULL)!=SQLITE_OK)return -1;
    sqlite3_bind_text(statement,1,state,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(statement,2,(sqlite3_int64)revision);
    sqlite3_bind_text(statement,3,node,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(statement,4,(sqlite3_int64)revision);
    int result=sqlite3_step(statement)==SQLITE_DONE;sqlite3_finalize(statement);return result?0:-1;
}
int gw_store_config_rules(sqlite3 *db,const char *node) {
    if(!gw_store_rule_managed(db,node))return 0;
    json_object *list=gw_store_rules(db,node),*fields=json_object_new_object();
    json_object *apps=json_object_new_array(),*socks=json_object_new_array();
    json_object_object_add(fields,"apps",apps);json_object_object_add(fields,"socks5",socks);
    if(!list) {json_object_put(fields);return -1;}
    for(size_t i=0;i<json_object_array_length(list);++i) {
        json_object *row=json_object_array_get_idx(list,i),*rule=gw_get(row,"rule"),*entry=NULL;
        int proxy=!strcmp(gw_string(row,"protocol"),"socks5");
        json_object *original=gw_get(rule,"_config");
        if(!original||json_object_deep_copy(original,&entry,NULL))entry=json_object_new_object();
        copy(entry,proxy?"Name":"AppName",rule,"appName");
        for(unsigned k=0;k<sizeof(names)/sizeof(names[0]);++k)copy(entry,names[k][0],rule,names[k][1]);
        if(!proxy)gw_js(entry,"Protocol",gw_string(row,"protocol"));
        gw_js(entry,"UnderlayProtocol",(gw_integer(rule,"punchPriority")&2)?"tcp":"quic");
        json_object_object_add(entry,"Enabled",json_object_new_boolean(gw_integer(row,"enabled")!=0));
        json_object_array_add(proxy?socks:apps,entry);
    }
    json_object_put(list);
    json_object *old=gw_store_config(db,node),*merged=NULL;int result=-1;
    if(old&&!fp_config_merge(gw_get(old,"fields"),fields,&merged)) {
        result=json_object_equal(merged,gw_get(old,"fields"))?0:gw_store_config_put(db,node,fields);
    }
    if(old)json_object_put(old);
    if(merged)json_object_put(merged);
    json_object_put(fields);return result;
}
