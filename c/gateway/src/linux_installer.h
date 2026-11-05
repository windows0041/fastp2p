#ifndef FASTP2P_LINUX_INSTALLER_H
#define FASTP2P_LINUX_INSTALLER_H
#include <stdint.h>
#include <stddef.h>
#define GW_LINUX_ARCH_COUNT 8
extern const char *const gw_linux_arches[GW_LINUX_ARCH_COUNT];
struct gw_linux_package {
    const char *arch;
    char platform[16],version[32],sha[65];
    uint64_t size;
};
/* Classify an old, unqualified manual Linux package without executing it. */
const char *gw_linux_payload_arch(const char *path);
/* Immutable token-free downloader: architecture-specific ELFs remain on gateway. */
int gw_linux_installer(const char *directory,const char *host,unsigned port,const char *ca,
                       const struct gw_linux_package *packages,size_t count,char path[700]);
#endif
