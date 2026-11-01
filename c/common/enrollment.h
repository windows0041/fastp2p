#ifndef FASTP2P_ENROLLMENT_H
#define FASTP2P_ENROLLMENT_H
#include <json-c/json.h>
#include <stdint.h>
#define FASTP2P_INSTALL_TOKEN_LIMIT 32768u
/* Internal enrollment envelopes validate a public gateway identity and key.
 * User-facing installation accepts only a 16-digit access key. */
char *fastp2p_enrollment_encode(const char *host, unsigned port, uint64_t key, const char *ca);
json_object *fastp2p_enrollment_decode(const char *token);
int fastp2p_enrollment_host_valid(const char *host);
int fastp2p_install_key_valid(const char *key);
#endif
