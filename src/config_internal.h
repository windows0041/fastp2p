#ifndef FASTP2P_CONFIG_INTERNAL_H
#define FASTP2P_CONFIG_INTERNAL_H
#include "fastp2p.h"
#include <json-c/json.h>
int fp_client_tcp_nat_config(fastp2p_client *client, json_object *servers);
/* Public STUN servers used to classify the NAT (network.UDPSTUNServers). */
int fp_client_stun_config(fastp2p_client *client, json_object *servers);
/* TCP filtering probe server (network.TCPNatProbe), empty disables it. */
int fp_client_tcp_level_config(fastp2p_client *client, json_object *probe);
int fp_client_sdwan_config(fastp2p_client *client, json_object *config);
/* The PEM lives in static storage for the lifetime of the client. */
void fp_client_set_ca_pem(fastp2p_client *client, const char *pem);
void fp_client_set_tls_alias(fastp2p_client *client, const char *hostname, const char *pem);
void fp_client_set_auto_port_mapping(fastp2p_client *client, int enabled);
void fp_client_validation_mode(fastp2p_client *client);
int fp_config_validate_json(const char *json);
#endif
