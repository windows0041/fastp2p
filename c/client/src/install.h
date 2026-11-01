#ifndef FASTP2P_INSTALL_H
#define FASTP2P_INSTALL_H
#include <json-c/json.h>
int fastp2p_install_command(int argc, char **argv);
int fastp2p_default_profile(char out[4096]);
json_object *fastp2p_profile_read(const char *path);
int fastp2p_profile_write(const char *path, const char *text);
int fastp2p_runtime_begin(const char *profile, int background);
int fastp2p_runtime_stopping(void);
void fastp2p_runtime_end(void);
int fastp2p_enable_autostart(const char *profile, const char *ca);
int fastp2p_stop_installed(const char *profile);
#endif
