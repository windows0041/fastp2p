#ifndef FASTP2P_ENROLLMENT_H
#define FASTP2P_ENROLLMENT_H
#include <json-c/json.h>
#include <stdint.h>
#define FASTP2P_INSTALL_TOKEN_LIMIT 32768u
/* Installation tokens carry their gateway address, access key and public CA.
 * They are credentials, supplied through a trusted administrator channel. */
char *fastp2p_enrollment_encode(const char *host, unsigned port, uint64_t key, const char *ca);
json_object *fastp2p_enrollment_decode(const char *token);
int fastp2p_enrollment_host_valid(const char *host);
#endif
