/* CLI host adapter: the reusable C library never owns filesystem policy. */
#include "config_sync.h"
#include "config_internal.h"
#include "config_merge.h"
#include "install.h"
#include "platform.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define META "_fastp2pManaged"
static struct {
    char path[4096],previous[4096],digest[65];
    json_object *active,*rollback;
    uint64_t revision,deadline,reload_at;
    int machine,pending,reload,online;
} sync_state;
static json_object *get(json_object *root,const char *key) {
    json_object *value=NULL;if(root)json_object_object_get_ex(root,key,&value);return value;
}
static uint64_t integer(json_object *root,const char *key) {
    json_object *v=get(root,key);return json_object_is_type(v,json_type_int)?json_object_get_uint64(v):0;
}
static const char *string(json_object *root,const char *key) {
    json_object *v=get(root,key);return json_object_is_type(v,json_type_string)?json_object_get_string(v):"";
}
static json_object *metadata(json_object *root) {
    json_object *value=get(root,META);
    if(!json_object_is_type(value,json_type_object)) {
        value=json_object_new_object();json_object_object_add(root,META,value);
    }
    return value;
}
static int save(const char *path,json_object *root) {
    const char *text=json_object_to_json_string_ext(root,JSON_C_TO_STRING_PLAIN);
    return sync_state.machine?fastp2p_profile_write_machine(path,text):fastp2p_profile_write(path,text);
}
static void digest(const char *text,char out[65]) {
    unsigned char bytes[32];unsigned length=0;
    if(!EVP_Digest(text,strlen(text),bytes,&length,EVP_sha256(),NULL)||length!=32) {out[0]=0;return;}
    for(unsigned i=0;i<32;++i)snprintf(out+2*i,3,"%02x",bytes[i]);
}
static int rollback(void) {
    if(!sync_state.pending||!sync_state.rollback)return 0;
    json_object *root=NULL;if(json_object_deep_copy(sync_state.rollback,&root,NULL))return 0;
    json_object *meta=metadata(root);
    json_object_object_add(meta,"pending",json_object_new_boolean(0));
    json_object_object_add(meta,"rejectedRevision",json_object_new_uint64(sync_state.revision));
    json_object_object_add(meta,"rejectedDigest",json_object_new_string(sync_state.digest));
    int result=save(sync_state.path,root);json_object_put(root);
    if(result) {fputs("Cannot restore the previous configuration.\n",stderr);return 0;}
    sync_state.pending=sync_state.reload=0;
    json_object_put(sync_state.rollback);sync_state.rollback=NULL;
    fputs("Gateway configuration could not start; restored previous configuration.\n",stderr);
    return 1;
}
static int receive(const char *fields,uint64_t revision,void *user) {
    (void)user;
    if(!sync_state.path[0]||!sync_state.active||sync_state.reload||strlen(fields)>65536)return FASTP2P_ESTATE;
    json_object *patch=json_tokener_parse(fields),*current=fastp2p_profile_read(sync_state.path),*next=NULL;
    int result=FASTP2P_EINVAL;char hash[65];digest(fields,hash);
    json_object *forbidden=NULL;
    if(!patch||!current||!*hash||json_object_object_get_ex(patch,META,&forbidden)) {
        fputs("Cannot read a valid current profile or accept reserved configuration fields.\n",stderr);goto done;
    }
    json_object *meta=get(current,META);
    if(integer(meta,"rejectedRevision")==revision&&!strcmp(string(meta,"rejectedDigest"),hash))goto done;
    if(fp_config_merge(current,patch,&next))goto done;
    if(get(next,"product")&&strcmp(string(next,"product"),"fastp2p"))goto done;
    result=fp_config_validate_json(json_object_to_json_string_ext(next,JSON_C_TO_STRING_PLAIN));
    if(result) {fprintf(stderr,"Gateway configuration validation failed (%d).\n",result);goto done;}
    if(json_object_equal(next,sync_state.active)) {result=0;goto done;}
    if(save(sync_state.previous,current)) {result=FASTP2P_EIO;goto done;}
    meta=metadata(next);
    json_object_object_add(meta,"revision",json_object_new_uint64(revision));
    json_object_object_add(meta,"digest",json_object_new_string(hash));
    json_object_object_add(meta,"pending",json_object_new_boolean(1));
    json_object_object_del(meta,"rejectedRevision");json_object_object_del(meta,"rejectedDigest");
    if(save(sync_state.path,next)) {result=FASTP2P_EIO;goto done;}
    if(sync_state.rollback)json_object_put(sync_state.rollback);
    sync_state.rollback=json_object_get(current);sync_state.revision=revision;
    snprintf(sync_state.digest,sizeof(sync_state.digest),"%s",hash);
    sync_state.pending=sync_state.reload=1;sync_state.online=0;
    sync_state.reload_at=op_monotonic_ns()+UINT64_C(200000000);
    sync_state.deadline=op_monotonic_ns()+UINT64_C(25000000000);
    result=1;
done:
    if(patch)json_object_put(patch);
    if(current)json_object_put(current);
    if(next)json_object_put(next);
    return result;
}
int fp_config_sync_bind(fastp2p_client *client,const char *path,json_object *active) {
    if(!path||strlen(path)>=sizeof(sync_state.path)-10)return 0;
    if(sync_state.path[0]&&strcmp(sync_state.path,path))fp_config_sync_close();
    snprintf(sync_state.path,sizeof(sync_state.path),"%s",path);
    snprintf(sync_state.previous,sizeof(sync_state.previous),"%s.previous",path);
    char machine[4096];sync_state.machine=fastp2p_service_supported()&&!fastp2p_service_profile(machine)&&!strcmp(machine,path);
#ifdef _WIN32
    const char *program_data=getenv("ProgramData");
    if(program_data&&snprintf(machine,sizeof(machine),"%s/fastp2p/client.dat",program_data)<(int)sizeof(machine)&&!strcmp(machine,path))
        sync_state.machine=1; /* in-place upgrade before the installer migrates it */
#endif
    if(sync_state.active)json_object_put(sync_state.active);
    sync_state.active=json_object_get(active);sync_state.online=0;sync_state.reload=0;
    json_object *meta=get(active,META);
    if(json_object_get_boolean(get(meta,"pending"))) {
        if(!sync_state.rollback)sync_state.rollback=fastp2p_profile_read(sync_state.previous);
        sync_state.pending=1;sync_state.revision=integer(meta,"revision");
        snprintf(sync_state.digest,sizeof(sync_state.digest),"%s",string(meta,"digest"));
        sync_state.deadline=op_monotonic_ns()+UINT64_C(25000000000);
    }
    /* Old Linux units keep /etc read-only. Preserve their legacy rule protocol
     * until the installer migrates them to the writable config directory. */
    return client&&fastp2p_profile_writable(path)?fastp2p_client_set_config_handler(client,receive,NULL):0;
}
void fp_config_sync_online(void) {
    sync_state.online=1;
    if(!sync_state.pending||!sync_state.active||sync_state.reload)return;
    json_object *meta=metadata(sync_state.active);
    json_object_object_add(meta,"pending",json_object_new_boolean(0));
    if(save(sync_state.path,sync_state.active))fputs("Cannot save configuration completion marker.\n",stderr);
    sync_state.pending=0;
    if(sync_state.rollback)json_object_put(sync_state.rollback);
    sync_state.rollback=NULL;
}
int fp_config_sync_tick(void) {
    uint64_t now=op_monotonic_ns();
    if(sync_state.reload&&now>=sync_state.reload_at)return 1;
    if(sync_state.pending&&!sync_state.online&&now>=sync_state.deadline)return rollback();
    return 0;
}
int fp_config_sync_failed(void) { return rollback(); }
void fp_config_sync_close(void) {
    if(sync_state.active)json_object_put(sync_state.active);
    if(sync_state.rollback)json_object_put(sync_state.rollback);
    memset(&sync_state,0,sizeof(sync_state));
}
