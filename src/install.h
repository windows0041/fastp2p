#ifndef FASTP2P_INSTALL_H
#define FASTP2P_INSTALL_H
#include <json-c/json.h>
#include <stddef.h>
int fastp2p_install_command(int argc, char **argv);
int fastp2p_uninstall_command(int argc, char **argv);
int fastp2p_default_profile(char out[4096]);
/* Machine-wide profile, used when the client runs as a Windows service and the
 * per-user location is not readable by the account the service runs under. */
int fastp2p_service_profile(char out[4096]);
#ifndef _WIN32
#define FASTP2P_SYSTEM_DIR "/usr/local/fastp2p"
#define FASTP2P_SYSTEM_BINARY FASTP2P_SYSTEM_DIR "/fastp2p"
#define FASTP2P_SYSTEM_PROFILE "/etc/fastp2p/config.conf"
#define FASTP2P_LOG_DIR "/tmp/fastp2p"
#define FASTP2P_LOG_FILE FASTP2P_LOG_DIR "/fastp2p.log"
int fastp2p_posix_uninstall(int keep_config);
/* Native service management. The unit text is rendered by src/service_unit.c and the
 * manager tools are driven directly, so no helper script has to sit beside the
 * binary: registration, teardown and the stop path all live in the client. */
int fastp2p_service_stop(void);
#endif
json_object *fastp2p_profile_read(const char *path);
int fastp2p_profile_write(const char *path, const char *text);
int fastp2p_profile_write_machine(const char *path, const char *text);
int fastp2p_profile_writable(const char *path);
/* Indented JSON for a profile file, so an operator can read it. The caller
 * frees the text; formatting never changes what the profile means. */
char *fp_profile_pretty(json_object *root);
/* Rewrite an existing profile with that formatting; 0 on success. */
int fastp2p_format_profile(const char *path);
int fastp2p_profile_relocate(const char *source,const char *destination);
/* The double-clicked installer: takes the key from the file name. */
int fastp2p_service_install_token(const char *token);
void fastp2p_install_note(const char *text);
/* Attach foreground CLI commands to their shell without creating a console.
 * Service/background/update-helper invocations stay detached. */
void fastp2p_console_prepare(int argc, char **argv);
/* Double-clicked installer UI: a progress terminal plus a result dialog. */
void fastp2p_installer_ui_begin(void);
void fastp2p_install_step(const char *text);
int fastp2p_installer_ui_result(int ok, const char *title, const char *detail);
/* Returns 0 and fills out with 16 digits when the name carries an install key. */
int fastp2p_name_token(const char *path, char out[17]);
int fastp2p_runtime_begin(const char *profile, int background);
/* Cheap, rate-limited housekeeping for the runtime log (size cap and rotation). */
void fastp2p_runtime_tick(void);
int fastp2p_runtime_prepare(const char *profile);
int fastp2p_runtime_stopping(void);
void fastp2p_runtime_request_stop(void);
void fastp2p_runtime_end(void);
int fastp2p_enable_autostart(const char *profile, const char *ca);
/* Stop and unregister this installation while retaining its private profile. */
int fastp2p_remove_autostart(const char *profile);
int fastp2p_stop_installed(const char *profile);
/* Windows service plumbing; the POSIX builds answer "unsupported". */
int fastp2p_service_supported(void);
int fastp2p_service_dispatch(const char *profile, int argc, char **argv,
                             int (*loop)(int, char **));
int fastp2p_service_installed(void);
int fastp2p_service_prepare(const char *profile);
#ifdef _WIN32
int fastp2p_windows_log(wchar_t path[4096]);
#endif
int fastp2p_service_install(const char *profile, const char *ca);
int fastp2p_service_remove(void);
/* After the replacement service is healthy, remove only known old images. */
int fastp2p_service_cleanup_previous(void);
/* Removes the stored profile, its certificates and the installed copy. */
int fastp2p_service_purge(void);
int fastp2p_service_elevated(void);
int fastp2p_service_elevate(const char *arguments);
#endif
