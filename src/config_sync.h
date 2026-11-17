#ifndef FASTP2P_CONFIG_SYNC_H
#define FASTP2P_CONFIG_SYNC_H
#include "fastp2p.h"
#include <json-c/json.h>
#define FP_CONFIG_RELOAD 75
int fp_config_sync_bind(fastp2p_client *,const char *path,json_object *active);
void fp_config_sync_online(void);
int fp_config_sync_tick(void);
int fp_config_sync_failed(void);
void fp_config_sync_close(void);
#endif
