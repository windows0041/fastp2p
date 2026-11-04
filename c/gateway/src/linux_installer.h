#ifndef FASTP2P_LINUX_INSTALLER_H
#define FASTP2P_LINUX_INSTALLER_H
#include <stdint.h>
/* Produce an immutable, token-free shell installer containing the verified ELF. */
int gw_linux_installer(const char *directory, const char *payload, const char *sha,
                       uint64_t size, char path[700]);
#endif
