#ifndef FASTP2P_PORT_MAPPING_H
#define FASTP2P_PORT_MAPPING_H
#include <stdint.h>

typedef struct fp_port_mapping fp_port_mapping;

typedef struct {
    uint16_t tcp, udp;
    uint32_t tcp_wan, udp_wan; /* network byte order */
} fp_mapped_ports;

fp_port_mapping *fp_port_mapping_start(uint16_t tcp_port, uint16_t udp_port);
fp_mapped_ports fp_port_mapping_read(fp_port_mapping *mapping);
void fp_port_mapping_stop(fp_port_mapping *mapping);
#endif
