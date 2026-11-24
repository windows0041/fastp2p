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
        value = json_object_new_object();
        if (!value)
            return NULL;
        if (json_object_object_add(root, META, value)) {
            json_object_put(value);
            return NULL;
        }
    }
    return value;
}
static int save(const char *path,json_object *root) {
    /* Indented JSON: the operator reads and edits this file, and the parser
     * does not care about whitespace. */
    char *text=fp_profile_pretty(root);
    if(!text)return -1;
    int result=sync_state.machine?fastp2p_profile_write_machine(path,text):fastp2p_profile_write(path,text);
    free(text);
    return result;
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
    /* Do not remember the revision as rejected: the reason it failed to start may have
     * been a network error, and a remembered rejection blocks the identical retry for
     * good - the gateway keeps sending the same revision until it is accepted. */
    json_object_object_del(meta,"rejectedRevision");
    json_object_object_del(meta,"rejectedDigest");
    int result=save(sync_state.path,root);json_object_put(root);
    if(result) {fputs("Cannot restore the previous configuration.\n",stderr);return 0;}
    sync_state.pending=sync_state.reload=0;
    json_object_put(sync_state.rollback);sync_state.rollback=NULL;
    fputs("Gateway configuration could not start; restored previous configuration.\n",stderr);
    return 1;
}
static int rule_field(const char *key) {
    return !strcmp(key, "apps") || !strcmp(key, "socks5");
}
static int unchanged_outside_rules(json_object *a, json_object *b) {
    json_object_object_foreach(a, key, value) {
        json_object *other;
        if (!rule_field(key) && strcmp(key, META) &&
            (!json_object_object_get_ex(b, key, &other) || !json_object_equal(value, other)))
            return 0;
    }
    return 1;
}
static int update_metadata(json_object *root, uint64_t revision, const char *hash, int pending) {
    json_object *meta = metadata(root);
    if (!meta)
        return -1;
    json_object *values[] = {json_object_new_uint64(revision), json_object_new_string(hash),
                             json_object_new_boolean(pending)};
    const char *keys[] = {"revision", "digest", "pending"};
    int failed = 0;
    for (size_t i = 0; i < sizeof(values) / sizeof(*values); ++i) {
        if (!values[i] || json_object_object_add(meta, keys[i], values[i])) {
            if (values[i]) json_object_put(values[i]);
            failed = 1;
        }
    }
    json_object_object_del(meta, "rejectedRevision");
    json_object_object_del(meta, "rejectedDigest");
    return failed ? -1 : 0;
}
static int receive(const char *fields,uint64_t revision,void *user) {
    fastp2p_client *client = user;
    if(!sync_state.path[0]||!sync_state.active||sync_state.reload||strlen(fields)>65536)return FASTP2P_ESTATE;
    json_object *patch=json_tokener_parse(fields),*current=fastp2p_profile_read(sync_state.path),*next=NULL;
    fp_rule_update *rules = NULL;
    int result=FASTP2P_EINVAL;char hash[65];digest(fields,hash);
    json_object *forbidden=NULL;
    if(!patch||!current||!*hash||json_object_object_get_ex(patch,META,&forbidden)) {
        fputs("Cannot read a valid current profile or accept reserved configuration fields.\n",stderr);goto done;
    }
    json_object *meta=get(current,META);
    if(integer(meta,"rejectedRevision")==revision&&!strcmp(string(meta,"rejectedDigest"),hash)) {
        fputs("This revision was already rejected by the running configuration.\n",stderr);
        goto done;
    }
    if(fp_config_merge(current,patch,&next)) {fputs("Gateway configuration could not be merged.\n",stderr);goto done;}
    json_object *product=NULL;
    if(json_object_object_get_ex(next,"product",&product)&&
       (!json_object_is_type(product,json_type_string)||strcmp(json_object_get_string(product),"fastp2p"))) {
        fputs("Gateway configuration product mismatch.\n",stderr);goto done;
    }
    if(json_object_equal(next,sync_state.active)) {result=0;goto done;}
    const char *text = json_object_to_json_string_ext(next, JSON_C_TO_STRING_PLAIN);
    json_object *field;
    int has_rules = json_object_object_get_ex(patch, "apps", &field) ||
                    json_object_object_get_ex(patch, "socks5", &field);
    /* The gateway can include other, unchanged fields in its full snapshot.
     * Compare against the file just read, not the startup snapshot: an operator
     * edit made while the client runs must not demote a rules-only push to a
     * full reload that drops every tunnel. */
    if (has_rules && !sync_state.pending && unchanged_outside_rules(next, current) &&
        unchanged_outside_rules(current, next)) {
        result = fp_client_rules_prepare(client, text, &rules);
        if (result) {
            fprintf(stderr, "Gateway rules could not be prepared (%d); keeping current rules.\n", result);
            goto done;
        }
        if (update_metadata(next, revision, hash, 0) || save(sync_state.path, next)) {
            fputs("Gateway rules could not be saved; keeping current rules.\n", stderr);
            result = FASTP2P_EIO;
            goto done;
        }
        /* All fallible work is done. No step can run between save and commit. */
        fp_client_rules_commit(rules);
        rules = NULL;
        json_object_put(sync_state.active);
        sync_state.active = json_object_get(next);
        result = FASTP2P_OK;
        goto done;
    }
    /* Non-rule changes still reload the entire instance. */
    result=fp_config_validate_json(text);
    if(result) {fprintf(stderr,"Gateway configuration validation failed (%d).\n",result);goto done;}
    if (update_metadata(next, revision, hash, 1)) {result=FASTP2P_ENOMEM;goto done;}
    if(save(sync_state.previous,current) || save(sync_state.path,next)) {result=FASTP2P_EIO;goto done;}
    if(sync_state.rollback)json_object_put(sync_state.rollback);
    sync_state.rollback=json_object_get(current);sync_state.revision=revision;
    snprintf(sync_state.digest,sizeof(sync_state.digest),"%s",hash);
    sync_state.pending=sync_state.reload=1;sync_state.online=0;
    sync_state.reload_at=op_monotonic_ns()+UINT64_C(200000000);
    sync_state.deadline=op_monotonic_ns()+UINT64_C(25000000000);
    result=1;
done:
    if (rules) fp_client_rules_abort(rules);
    if(patch)json_object_put(patch);
    if(current)json_object_put(current);
    if(next)json_object_put(next);
    return result;
}
/* Write the node name the gateway assigned into the profile, once. The name is only
 * known after login, so a document parsed before that carries the hostname instead -
 * and every decision that compares the assigned name with a configuration value
 * (which node is the SD-WAN hub, which peer a rule slot belongs to) is then wrong.
 * Persisting it here makes the next parse - including the validator that runs on every
 * pushed document - start from the right name. */
int fp_config_sync_persist_node(const char *node) {
    if (!sync_state.path[0] || !node || !*node)
        return -1;
    FILE *file = fopen(sync_state.path, "rb");
    if (!file)
        return -1;
    char buffer[1 << 20];
    size_t length = fread(buffer, 1, sizeof(buffer) - 1, file);
    fclose(file);
    buffer[length] = 0;
    json_object *root = json_tokener_parse(buffer);
    if (!root || !json_object_is_type(root, json_type_object)) {
        if (root)
            json_object_put(root);
        return -1;
    }
    json_object *network = NULL;
    if (!json_object_object_get_ex(root, "network", &network) ||
        !json_object_is_type(network, json_type_object)) {
        network = json_object_new_object();
        if (!network || json_object_object_add(root, "network", network)) {
            json_object_put(root);
            return -1;
        }
    }
    const char *current = string(network, "Node");
    int automatic = json_object_get_boolean(get(network, "AutoNode")) != 0;
    if (!automatic && !strcmp(current, node)) {
        json_object_put(root);
        return 0;
    }
    json_object_object_add(network, "Node", json_object_new_string(node));
    json_object_object_add(network, "AutoNode", json_object_new_boolean(0));
    int saved = save(sync_state.path, root);
    json_object_put(root);
    return saved;
}

int fp_config_sync_bind(fastp2p_client *client,const char *path,json_object *active) {
    if(!path||strlen(path)>=sizeof(sync_state.path)-10)return 0;
    if(sync_state.path[0]&&strcmp(sync_state.path,path))fp_config_sync_close();
    snprintf(sync_state.path,sizeof(sync_state.path),"%s",path);
    snprintf(sync_state.previous,sizeof(sync_state.previous),"%s.previous",path);
    char machine[4096];sync_state.machine=fastp2p_service_supported()&&!fastp2p_service_profile(machine)&&!strcmp(machine,path);
    if(sync_state.active)json_object_put(sync_state.active);
    sync_state.active=json_object_get(active);sync_state.online=0;sync_state.reload=0;
    json_object *meta=get(active,META);
    /* A "rejected" marker only describes the run that rejected it: the reason may have
     * been a network failure, and leaving it on disk blocks the identical revision for
     * good, because the gateway keeps resending it until it is accepted. */
    if(meta&&(integer(meta,"rejectedRevision")||*string(meta,"rejectedDigest"))) {
        json_object_object_del(meta,"rejectedRevision");
        json_object_object_del(meta,"rejectedDigest");
        if(save(path,active))fputs("Cannot clear the stale configuration rejection.\n",stderr);
        else fputs("Cleared a stale configuration rejection marker.\n",stderr);
    }
    if(json_object_get_boolean(get(meta,"pending"))) {
        if(!sync_state.rollback)sync_state.rollback=fastp2p_profile_read(sync_state.previous);
        sync_state.pending=1;sync_state.revision=integer(meta,"revision");
        snprintf(sync_state.digest,sizeof(sync_state.digest),"%s",string(meta,"digest"));
        sync_state.deadline=op_monotonic_ns()+UINT64_C(25000000000);
    }
    if(!client)return 0;
    if(!fastp2p_profile_writable(path)) {
        fputs("Profile is not writable; managed configuration pushes are disabled.\n",stderr);
        return 0;
    }
    return fastp2p_client_set_config_handler(client, receive, client);
}
void fp_config_sync_online(uint16_t public_port) {
    sync_state.online=1;
    if(!sync_state.active||sync_state.reload)return;
    json_object *network=get(sync_state.active,"network");
    /* Installed clients keep their first successfully reported port for the
     * firewall rule. Re-read before adding it so an operator edit wins. */
    json_object *current=NULL;
    if(public_port && !integer(network,"PublicIPPort") &&
       !strcmp(string(sync_state.active,"product"),"fastp2p") &&
       fastp2p_profile_writable(sync_state.path)) {
        current=fastp2p_profile_read(sync_state.path);
        if(current && json_object_equal(current,sync_state.active) &&
           json_object_is_type(network,json_type_object) &&
           json_object_is_type(get(current,"network"),json_type_object)) {
            json_object_object_add(get(current,"network"),"PublicIPPort",json_object_new_int(public_port));
            if(save(sync_state.path,current))
                fputs("Cannot save the selected TCP peer port.\n",stderr);
            else
                json_object_object_add(network,"PublicIPPort",json_object_new_int(public_port));
        }
        if(current)json_object_put(current);
    }
    if(!sync_state.pending)return;
    json_object_object_add(metadata(sync_state.active),"pending",json_object_new_boolean(0));
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
