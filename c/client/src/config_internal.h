#ifndef FASTP2P_CONFIG_INTERNAL_H
#define FASTP2P_CONFIG_INTERNAL_H
#include "fastp2p.h"
#include <json-c/json.h>
int fp_client_tcp_nat_config(fastp2p_client *client, json_object *servers);
void fp_client_validation_mode(fastp2p_client *client);
int fp_config_validate_json(const char *json);
#endif
