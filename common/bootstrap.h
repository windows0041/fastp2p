#ifndef FASTP2P_BOOTSTRAP_H
#define FASTP2P_BOOTSTRAP_H
/* Public gateway identity compiled into a gateway-specific distribution. */
const char *fastp2p_default_gateway(void);
const char *fastp2p_builtin_ca(const char *host, unsigned port);
const char *fastp2p_builtin_ca_hash(void);
const char *fastp2p_builtin_tls_host(const char *host, unsigned port);
const char *fastp2p_builtin_tls_ca(void);
#endif
