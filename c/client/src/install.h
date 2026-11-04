#ifndef FASTP2P_INSTALL_H
#define FASTP2P_INSTALL_H
#include <json-c/json.h>
int fastp2p_install_command(int argc, char **argv);
int fastp2p_uninstall_command(int argc, char **argv);
int fastp2p_default_profile(char out[4096]);
/* Machine-wide profile, used when the client runs as a Windows service and the
 * per-user location is not readable by the account the service runs under. */
int fastp2p_service_profile(char out[4096]);
json_object *fastp2p_profile_read(const char *path);
int fastp2p_profile_write(const char *path, const char *text);
int fastp2p_profile_write_machine(const char *path, const char *text);
/* The double-clicked installer: takes the key from the file name. */
int fastp2p_service_install_token(const char *token);
void fastp2p_install_note(const char *text);
/* Double-clicked installer UI: a progress terminal plus a result dialog. */
void fastp2p_installer_ui_begin(void);
void fastp2p_install_step(const char *text);
int fastp2p_installer_ui_result(int ok, const char *title, const char *detail);
/* Returns 0 and fills out with 16 digits when the name carries an install key. */
int fastp2p_name_token(const char *path, char out[17]);
int fastp2p_runtime_begin(const char *profile, int background);
int fastp2p_runtime_prepare(const char *profile);
int fastp2p_runtime_stopping(void);
void fastp2p_runtime_request_stop(void);
void fastp2p_runtime_end(void);
int fastp2p_enable_autostart(const char *profile, const char *ca);
/* Stop and unregister this installation while retaining its private profile. */
int fastp2p_remove_autostart(const char *profile);
int fastp2p_linux_uninstall(int keep_config);
int fastp2p_stop_installed(const char *profile);
/* Windows service plumbing; the POSIX builds answer "unsupported". */
int fastp2p_service_supported(void);
int fastp2p_service_dispatch(const char *profile, int argc, char **argv,
                             int (*loop)(int, char **));
int fastp2p_service_installed(void);
int fastp2p_service_prepare(const char *profile);
int fastp2p_service_install(const char *profile, const char *ca);
int fastp2p_service_remove(void);
/* Removes the stored profile, its certificates and the installed copy. */
int fastp2p_service_purge(void);
int fastp2p_service_elevated(void);
int fastp2p_service_elevate(const char *arguments);
#endif
