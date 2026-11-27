/* CLI host adapter: the reusable C library never owns filesystem policy. */
#include "config_sync.h"
#include "config_internal.h"
#include "config_merge.h"
#include "install.h"
#include "platform.h"
#include <openssl/evp.h>
#include <errno.h>
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
/* network subkeys the running client can adopt without being rebuilt. TCPSTUNServers is
 * included: its parser only stores text, and the step loop resolves the destinations on
 * its next tick, so a pushed change never blocks the control channel. */
static int hot_network_field(const char *key) {
    return !strcmp(key, "UDPSTUNServers") || !strcmp(key, "TCPSTUNServers") ||
           !strcmp(key, "TCPNatProbe") || !strcmp(key, "AutoPortMapping");
}
/* Everything the running client can pick up in place: the rules, the overlay section and
 * a handful of per-machine probes. The remaining fields describe the connection itself
 * (gateway endpoint, token, node identity, certificate, listener port), so a change
 * there still has to rebuild the instance. Comparing in both directions catches a key
 * that one side has and the other does not. */
static int unchanged_outside_hot(json_object *a, json_object *b) {
    json_object_object_foreach(a, key, value) {
        json_object *other = NULL;
        if (!strcmp(key, META))
            continue;
        if (!strcmp(key, "network")) {
            /* Inside network only the hot subkeys may differ. */
            if (!json_object_is_type(value, json_type_object))
                return 0;
            json_object_object_get_ex(b, key, &other);
            json_object_object_foreach(value, name, item) {
                json_object *theirs = NULL;
                if (hot_network_field(name))
                    continue;
                if (!json_object_is_type(other, json_type_object) ||
                    !json_object_object_get_ex(other, name, &theirs) ||
                    !json_object_equal(item, theirs))
                    return 0;
            }
            continue;
        }
        if (rule_field(key) || !strcmp(key, "sdwan"))
            continue;
        if (!json_object_object_get_ex(b, key, &other) || !json_object_equal(value, other))
            return 0;
    }
    return 1;
}
/* How many entries a witness list holds after the merge: the number an oversized list shows up
 * as in the applied-configuration line below. */
static unsigned list_count(json_object *network, const char *key) {
    json_object *list = get(network, key);
    return list && json_object_is_type(list, json_type_array)
               ? (unsigned)json_object_array_length(list) : 0;
}
/* One line per applied push. A push that only touched hot knobs is applied in place and keeps
 * the session; anything else reloads the instance. Which of the two happened, how big the
 * document was and how many witnesses it asked for are what a reconnect loop has to be read
 * against. */
static void log_applied(fastp2p_client *client, uint64_t revision, size_t bytes, int hot,
                        json_object *next) {
    if (!client)
        return;
    json_object *network = get(next, "network");
    char note[192];
    snprintf(note, sizeof(note), "config: applied revision=%llu bytes=%llu hot=%d udp=%u tcp=%u",
             (unsigned long long)revision, (unsigned long long)bytes, hot,
             list_count(network, "UDPSTUNServers"), list_count(network, "TCPSTUNServers"));
    fp_client_event(client, note);
}
/* A profile that could not be written used to be silent here while the acknowledgement still
 * said "applied": the gateway then stopped resending the revision and the node kept running the
 * old settings - on Android, where the private directory is not always writable by the service,
 * that is exactly what happened. The failure is named once (last path component only) and the
 * caller turns it into a failed acknowledgement. */
static void log_save_failure(fastp2p_client *client, const char *path, int error) {
    const char *leaf = path ? path : "";
    const char *slash = strrchr(leaf, '/');
#ifdef _WIN32
    const char *backslash = strrchr(leaf, '\\');
    if (!slash || (backslash && backslash > slash))
        slash = backslash;
#endif
    char note[192];
    snprintf(note, sizeof(note), "config: save failed errno=%d path=%s", error,
             slash ? slash + 1 : leaf);
    fprintf(stderr, "%s\n", note);
    fp_client_event(client, note);
}
/* The verdict of the document check, right where it happens: "the push arrived and nothing
 * followed" has to be readable as either a refusal or a bug in the path. */
static void log_validate(fastp2p_client *client, uint64_t revision, int result) {
    char note[128];
    snprintf(note, sizeof(note), "config: validate result=%d revision=%llu", result,
             (unsigned long long)revision);
    fprintf(stderr, "%s\n", note);
    fp_client_event(client, note);
}
static json_object *section(json_object *root, const char *key) {    json_object *value = NULL;
    if (root)
        json_object_object_get_ex(root, key, &value);
    return value;
}
/* True when both are absent, or both present and equal. */
static int section_equal(json_object *a, json_object *b, const char *key) {
    json_object *left = section(a, key), *right = section(b, key);
    if (!left || !right)
        return left == right;
    return json_object_equal(left, right) ? 1 : 0;
}
/* Adopt the probe servers and the router-mapping switch. Each setter only retargets the
 * next measurement (no sockets are opened here), so applying them cannot leave the
 * client half-converted; the mapping worker itself is started or stopped by the step
 * loop, because joining its thread inside this callback would stall the event loop.
 * Only fields that really changed are touched, so a routine push does no work at all. */
static void apply_runtime_knobs(fastp2p_client *client, json_object *next, json_object *active) {
    json_object *network = section(next, "network"), *running = section(active, "network");
    if (!section_equal(network, running, "UDPSTUNServers") &&
        fp_client_stun_config(client, section(network, "UDPSTUNServers")))
        fputs("Gateway UDP STUN servers were refused; keeping the old ones.\n", stderr);
    if (!section_equal(network, running, "TCPSTUNServers") &&
        fp_client_tcp_nat_reconfigure(client, section(network, "TCPSTUNServers")))
        fputs("Gateway TCP STUN servers were refused; keeping the old ones.\n", stderr);
    if (!section_equal(network, running, "TCPNatProbe") &&
        fp_client_tcp_level_config(client, section(network, "TCPNatProbe")))
        fputs("Gateway TCP probe server was refused; keeping the old one.\n", stderr);
    int mapping = json_object_get_boolean(section(network, "AutoPortMapping"));
    if (mapping != json_object_get_boolean(section(running, "AutoPortMapping")))
        fp_client_set_auto_port_mapping(client, mapping);
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
    {
        /* Entry record. A push that arrives and then leaves no line is indistinguishable from
         * one that never arrived, which is how a node kept the old settings while the console
         * showed the new list. bytes is the payload as sent, before any merge. */
        char note[192];
        snprintf(note, sizeof(note), "config: push received revision=%llu bytes=%llu",
                 (unsigned long long)revision, (unsigned long long)strlen(fields));
        fprintf(stderr, "%s\n", note);
        fp_client_event(client, note);
    }
    if(!sync_state.path[0]||!sync_state.active||sync_state.reload||strlen(fields)>65536) {
        /* The branch that used to be silent: a client whose sync never bound - no profile path,
         * or a profile that could not be read - drops every push right here. */
        char note[192];
        snprintf(note, sizeof(note), "config: push dropped (%s) revision=%llu",
                 !sync_state.path[0] ? "no profile path" :
                 !sync_state.active ? "no running profile" :
                 sync_state.reload ? "reload pending" : "payload too large",
                 (unsigned long long)revision);
        fprintf(stderr, "%s\n", note);
        fp_client_event(client, note);
        return FASTP2P_ESTATE;
    }
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
    const char *text = json_object_to_json_string_ext(next, JSON_C_TO_STRING_PLAIN);
    if(json_object_equal(next,sync_state.active)) {
        /* Nothing to do, but say so: a push that produces no line at all was indistinguishable
         * from a platform where the profile cannot be written. */
        char note[192];
        snprintf(note, sizeof(note),
                 "config: push ignored (identical to running state) revision=%llu",
                 (unsigned long long)revision);
        fprintf(stderr, "%s\n", note);
        fp_client_event(client, note);
        log_applied(client, revision, strlen(text), 1, next);
        result=0;
        goto done;
    }
    /* A push that only touches what the running client can adopt is applied in place:
     * the rules, the overlay section, the probe servers and the router-mapping switch.
     * The gate compares against the file just read, so an operator edit does not demote
     * a hot push to a full reload; what is actually re-applied is decided against
     * sync_state.active, which is what runs today. */
    int hot = sync_state.online && !sync_state.pending &&
              unchanged_outside_hot(next, current) && unchanged_outside_hot(current, next);
    json_object *next_sdwan = section(next, "sdwan");
    int has_sdwan = next_sdwan && json_object_is_type(next_sdwan, json_type_object);
    int sdwan_changed = has_sdwan && !section_equal(next, sync_state.active, "sdwan");
    int rules_changed = !section_equal(next, sync_state.active, "apps") ||
                        !section_equal(next, sync_state.active, "socks5");
    if (hot) {
        /* Validate the whole document before adopting any part of it: a field the parser
         * refuses must not leave the running client half-converted. */
        result = fp_config_validate_json(text);
        log_validate(client, revision, result);
        if (result) {
            fprintf(stderr, "Gateway configuration validation failed (%d).\n", result);
            goto done;
        }
        apply_runtime_knobs(client, next, sync_state.active);
        if (rules_changed) {
            result = fp_client_rules_prepare(client, text, &rules);
            if (result) {
                fprintf(stderr, "Gateway rules could not be prepared (%d); keeping current rules.\n", result);
                goto done;
            }
        }
        if (sdwan_changed) {
            char detail[96] = "";
            if (fp_client_sdwan_reconfigure(client, next_sdwan, detail, sizeof(detail))) {
                /* The section was refused: take the reload path, which reports the
                 * rejection the way every other configuration error is reported. */
                fprintf(stderr, "Gateway SD-WAN section was refused; reloading the instance instead.\n");
                goto reload;
            }
        }
        /* The running client has the pushed settings from here on: the probe servers, the
         * mapping switch, the rules and the overlay section were all handed over above. The
         * acknowledgement and the log say that before persistence is attempted, because a
         * profile that cannot be written is a durability problem, not an application one - and
         * reporting it as "applied" is what let the gateway stop resending a revision the node
         * was only running in memory. */
        if (rules) {
            fp_client_rules_commit(rules);
            rules = NULL;
        }
        log_applied(client, revision, strlen(text), 1, next);
        if (update_metadata(next, revision, hash, 0) || save(sync_state.path, next)) {
            int error = errno;
            log_save_failure(client, sync_state.path, error);
            /* Nothing is remembered as applied: the next push of this revision re-applies it,
             * which is idempotent, and the gateway is told the truth. */
            result = FASTP2P_EIO;
            goto done;
        }
        /* All fallible work is done. No step can run between save and commit. */
        json_object_put(sync_state.active);
        sync_state.active = json_object_get(next);
        sync_state.revision = revision;
        snprintf(sync_state.digest, sizeof(sync_state.digest), "%s", hash);
        fprintf(stderr, "Gateway configuration applied in place (rules=%d, sdwan=%d).\n",
                rules_changed, sdwan_changed);
        result = FASTP2P_OK;
        goto done;
    }
reload:
    /* A new gateway endpoint, token, node identity, certificate or listener port still
     * needs a fresh instance, so those reload the whole client. */
    result=fp_config_validate_json(text);
    log_validate(client, revision, result);
    if(result) {fprintf(stderr,"Gateway configuration validation failed (%d).\n",result);goto done;}
    if (update_metadata(next, revision, hash, 1)) {result=FASTP2P_ENOMEM;goto done;}
    if(save(sync_state.previous,current) || save(sync_state.path,next)) {
        int error = errno;
        log_save_failure(client, sync_state.path, error);
        result=FASTP2P_EIO;
        goto done;
    }
    if(sync_state.rollback)json_object_put(sync_state.rollback);
    sync_state.rollback=json_object_get(current);sync_state.revision=revision;
    snprintf(sync_state.digest,sizeof(sync_state.digest),"%s",hash);
    sync_state.pending=sync_state.reload=1;sync_state.online=0;
    sync_state.reload_at=op_monotonic_ns()+UINT64_C(200000000);
    sync_state.deadline=op_monotonic_ns()+UINT64_C(25000000000);
    log_applied(client, revision, strlen(text), 0, next);
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
    /* Read through the same helper the writer below uses: a machine-scope Windows
     * profile is "FPD1" + DPAPI, so a raw fopen + JSON parse only ever saw
     * ciphertext there and the assigned name was never persisted.  The helper also
     * keeps the 1 MiB bound this function used to duplicate on the stack. */
    json_object *root = fastp2p_profile_read(sync_state.path);
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
    const char *current = string(network, "NodeHint");
    if (!strcmp(current, node)) {
        json_object_put(root);
        return 0;
    }
    /* A hint, not a claim: the profile keeps logging in automatically (the gateway
     * resolves the name from the device) while local code comparing names - the SD-WAN
     * centre above all - starts from the name the gateway actually assigns. */
    json_object_object_add(network, "NodeHint", json_object_new_string(node));
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
