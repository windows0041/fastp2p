#include "bootstrap.h"
#include "bootstrap_profile.h"
#include <string.h>

const char *fastp2p_default_gateway(void) { return (const char *)fastp2p_bootstrap_profile; }

const char *fastp2p_builtin_ca(const char *host, unsigned port) {
    return fastp2p_bootstrap_ca[0] && port == fastp2p_bootstrap_port && !strcmp(host, fastp2p_bootstrap_host)
               ? fastp2p_bootstrap_ca : NULL;
}

const char *fastp2p_builtin_ca_hash(void) { return fastp2p_bootstrap_ca_hash; }

const char *fastp2p_builtin_tls_host(const char *host, unsigned port) {
    return fastp2p_bootstrap_tls_host[0] && port == fastp2p_bootstrap_port &&
                   !strcmp(host, fastp2p_bootstrap_host)
               ? fastp2p_bootstrap_tls_host : NULL;
}

const char *fastp2p_builtin_tls_ca(void) { return fastp2p_bootstrap_tls_ca; }
