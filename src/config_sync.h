#ifndef FASTP2P_CONFIG_SYNC_H
#define FASTP2P_CONFIG_SYNC_H
#include "fastp2p.h"
#include <json-c/json.h>
#define FP_CONFIG_RELOAD 75
/* The configuration layer lives in its own translation unit, but what it decides belongs in
 * the client's event log: a push applied in place and a push that forced a reload are the two
 * halves of a reconnect loop. */
void fp_client_event(fastp2p_client *client, const char *message);
/* The state word the client acknowledges with. It has to say "failed" whenever the pushed
 * configuration did not take effect: the gateway stops resending a revision it saw accepted, so
 * a false "applied" leaves a node running settings nobody can see. */
static inline const char *fp_config_ack_state(int result) {
    return result < 0 ? "failed" : result ? "saved" : "applied";
}
int fp_config_sync_persist_node(const char *node);
int fp_config_sync_bind(fastp2p_client *,const char *path,json_object *active);
void fp_config_sync_online(uint16_t public_port);
int fp_config_sync_tick(void);
int fp_config_sync_failed(void);
void fp_config_sync_close(void);
#endif
