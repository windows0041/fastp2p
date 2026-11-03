#include "install.h"
#include "fastp2p.h"
#include "enrollment.h"
#include "identity_file.h"
#include "platform.h"
#include "bootstrap.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <io.h>
#include <process.h>
#define close _close
#define write _write
#define getpid _getpid
#else
#include <unistd.h>
#endif

#ifdef _WIN32
static int wide(const char *text, WCHAR out[4096]) {
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, out, 4096) ? 0 : -1;
}
#endif
int fastp2p_default_profile(char out[4096]) {
    const char *base;
    int size;
#ifdef _WIN32
    base = getenv("LOCALAPPDATA");
    size = base ? snprintf(out, 4096, "%s/fastp2p/client.dat", base) : -1;
#elif defined(__APPLE__)
    base = getenv("HOME");
    size = base ? snprintf(out, 4096, "%s/Library/Application Support/fastp2p/client.json", base) : -1;
#else
    base = getenv("XDG_CONFIG_HOME");
    if (geteuid() == 0) size = snprintf(out, 4096, "/etc/fastp2p/client.json");
    else if (base && *base) size = snprintf(out, 4096, "%s/fastp2p/client.json", base);
    else { base = getenv("HOME"); size = base ? snprintf(out, 4096, "%s/.config/fastp2p/client.json", base) : -1; }
#endif
    return size > 0 && size < 4096 ? 0 : -1;
}
#ifdef _WIN32
/* The service runs as LocalSystem, which cannot read a per-user profile, so a
 * machine install keeps its own copy under ProgramData. */
int fastp2p_service_profile(char out[4096]) {
    const char *base = getenv("ProgramData");
    if (!base || !*base) return -1;
    int size = snprintf(out, 4096, "%s/fastp2p/client.dat", base);
    return size > 0 && size < 4096 ? 0 : -1;
}
#else
int fastp2p_service_profile(char out[4096]) {
    int size = snprintf(out, 4096, "/etc/fastp2p/client.json");
    return size > 0 && size < 4096 ? 0 : -1;
}
#endif
static unsigned char *read_file(const char *path, size_t maximum, size_t *length) {
#ifdef _WIN32
    WCHAR name[4096];
    if (wide(path, name)) return NULL;
    DWORD attributes = GetFileAttributesW(name);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return NULL;
    FILE *file = _wfopen(name, L"rb");
#else
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    FILE *file = fd >= 0 ? fdopen(fd, "rb") : NULL;
    if (fd >= 0 && !file) close(fd);
#endif
    if (!file) return NULL;
    unsigned char *data = malloc(maximum + 2);
    if (!data) { fclose(file); return NULL; }
    size_t size = fread(data, 1, maximum + 1, file);
    int ok = !ferror(file) && size && size <= maximum;
    fclose(file);
    if (!ok) { free(data); return NULL; }
    data[size] = 0; *length = size;
    return data;
}
json_object *fastp2p_profile_read(const char *path) {
    size_t length;
    unsigned char *data = read_file(path, 1048576, &length);
    if (!data) return NULL;
#ifdef _WIN32
    if (length > 4 && !memcmp(data, "FPD1", 4)) {
        DATA_BLOB input = {(DWORD)(length - 4), data + 4}, output = {0};
        if (!CryptUnprotectData(&input, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &output)) {
            OPENSSL_cleanse(data, length); free(data); return NULL;
        }
        OPENSSL_cleanse(data, length); free(data);
        data = malloc((size_t)output.cbData + 1);
        if (!data) { SecureZeroMemory(output.pbData, output.cbData); LocalFree(output.pbData); return NULL; }
        length = output.cbData; memcpy(data, output.pbData, length); data[length] = 0;
        SecureZeroMemory(output.pbData, output.cbData); LocalFree(output.pbData);
    }
#endif
    json_object *root = memchr(data, 0, length) ? NULL : json_tokener_parse((const char *)data);
    OPENSSL_cleanse(data, length); free(data);
    if (root && !json_object_is_type(root, json_type_object)) { json_object_put(root); root = NULL; }
    return root;
}
static int write_private(const char *path, const unsigned char *data, size_t length) {
    if (fastp2p_private_parents(path)) return -1;
    char temporary[4096];
    int size = snprintf(temporary, sizeof(temporary), "%s.tmp.%lu", path, (unsigned long)getpid());
    if (size < 0 || (size_t)size >= sizeof(temporary)) return -1;
#ifdef _WIN32
    WCHAR target[4096], name[4096];
    if (wide(path, target) || wide(temporary, name)) return -1;
    DWORD attributes = GetFileAttributesW(target);
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return -1;
    int fd = _wopen(name, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY | _O_NOINHERIT, _S_IREAD | _S_IWRITE);
#else
    struct stat status;
    if (!lstat(path, &status) && !S_ISREG(status.st_mode)) return -1;
    int fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
#endif
    if (fd < 0) return -1;
    size_t used = 0;
    while (used < length) {
        int count = (int)write(fd, data + used, (unsigned)(length - used));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        used += (size_t)count;
    }
#ifdef _WIN32
    int ok = used == length && !_commit(fd);
    if (close(fd)) ok = 0;
    if (ok) ok = MoveFileExW(name, target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
    if (!ok) DeleteFileW(name);
#else
    int ok = used == length && !fsync(fd);
    if (close(fd)) ok = 0;
    if (ok) ok = !rename(temporary, path);
    if (!ok) unlink(temporary);
#endif
    return ok ? 0 : -1;
}
static int ensure_ca(const char *path, const char *ca) {
#ifdef _WIN32
    WCHAR name[4096]; if (wide(path, name)) return -1;
    DWORD attributes = GetFileAttributesW(name);
    int exists = attributes != INVALID_FILE_ATTRIBUTES;
    if (!exists && GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND) return -1;
#else
    struct stat status;
    int exists = !lstat(path, &status);
    if (!exists && errno != ENOENT) return -1;
#endif
    if (exists) {
        size_t length = 0;
        unsigned char *data = read_file(path, 16384, &length);
        int ok = data && length == strlen(ca) && !memcmp(data, ca, length);
        free(data);
        return ok ? 0 : -1;
    }
    return write_private(path, (const unsigned char *)ca, strlen(ca));
}
#ifdef _WIN32
static int protect_and_write(const char *path, const char *text, DWORD scope) {
    DATA_BLOB input = {(DWORD)strlen(text), (BYTE *)text}, output = {0};
    if (!CryptProtectData(&input, L"fastp2p client profile", NULL, NULL, NULL,
                          CRYPTPROTECT_UI_FORBIDDEN | scope, &output)) return -1;
    unsigned char *data = malloc((size_t)output.cbData + 4);
    if (!data) { LocalFree(output.pbData); return -1; }
    memcpy(data, "FPD1", 4); memcpy(data + 4, output.pbData, output.cbData);
    int result = write_private(path, data, (size_t)output.cbData + 4);
    OPENSSL_cleanse(data, (size_t)output.cbData + 4); free(data);
    SecureZeroMemory(output.pbData, output.cbData); LocalFree(output.pbData);
    return result;
}
/* Bound to the machine instead of the user, so the service account can read it.
 * The file still sits in a directory only administrators may open. */
int fastp2p_profile_write_machine(const char *path, const char *text) {
    return protect_and_write(path, text, CRYPTPROTECT_LOCAL_MACHINE);
}
#else
int fastp2p_profile_write_machine(const char *path, const char *text) {
    return fastp2p_profile_write(path, text);
}
#endif
int fastp2p_profile_write(const char *path, const char *text) {
#ifdef _WIN32
    DATA_BLOB input = {(DWORD)strlen(text), (BYTE *)text}, output = {0};
    if (!CryptProtectData(&input, L"fastp2p client profile", NULL, NULL, NULL,
                          CRYPTPROTECT_UI_FORBIDDEN, &output)) return -1;
    unsigned char *data = malloc((size_t)output.cbData + 4);
    if (!data) { LocalFree(output.pbData); return -1; }
    memcpy(data, "FPD1", 4); memcpy(data + 4, output.pbData, output.cbData);
    int result = write_private(path, data, (size_t)output.cbData + 4);
    OPENSSL_cleanse(data, (size_t)output.cbData + 4); free(data);
    SecureZeroMemory(output.pbData, output.cbData); LocalFree(output.pbData);
    return result;
#else
    return write_private(path, (const unsigned char *)text, strlen(text));
#endif
}
typedef struct { int online, failed; char node[32]; } verification;
static void verified(fastp2p_client *client, const fastp2p_event *event, void *context) {
    verification *result = context;
    if (event->type == FASTP2P_EVENT_ERROR && strstr(event->message, "WSS connection failed")) result->failed = 1;
    if (event->state == FASTP2P_ONLINE) {
        result->online = 1;
        snprintf(result->node, sizeof(result->node), "%s", fastp2p_client_node(client));
    }
}
static const char *field(json_object *root, const char *key) {
    json_object *value = NULL;
    return json_object_object_get_ex(root, key, &value) ? json_object_get_string(value) : "";
}
static int install_token(const char *token, const char *token_file, const char *profile,
                         const char *node, int no_service, int machine) {
    if (!token && !token_file) token = getenv("FASTP2P_INSTALL_TOKEN");
    unsigned char *owned = NULL;
    if (token_file && !token) {
        size_t length;
        owned = read_file(token_file, FASTP2P_INSTALL_TOKEN_LIMIT, &length);
        if (owned) {
            while (length && (owned[length - 1] == '\n' || owned[length - 1] == '\r')) owned[--length] = 0;
            token = (const char *)owned;
        }
    }
    char *expanded = NULL;
    if (fastp2p_install_key_valid(token)) {
        const char *preset = fastp2p_default_gateway();
        const char *override = getenv("FASTP2P_BOOTSTRAP_FILE");
        unsigned char *data = NULL;
        if (override && *override) { size_t length; data = read_file(override, FASTP2P_INSTALL_TOKEN_LIMIT, &length); preset = (const char *)data; }
        json_object *gateway = preset ? json_tokener_parse(preset) : NULL;
        json_object *port = NULL;
        if (gateway && json_object_is_type(gateway, json_type_object) &&
            json_object_object_get_ex(gateway, "port", &port) && json_object_is_type(port, json_type_int) &&
            json_object_get_int64(port) >= 1 && json_object_get_int64(port) <= 65535)
            expanded = fastp2p_enrollment_encode(field(gateway, "host"), (unsigned)json_object_get_int64(port),
                                                (uint64_t)strtoull(token, NULL, 10), field(gateway, "ca"));
        if (gateway) json_object_put(gateway);
        free(data);
    }
    json_object *enrollment = expanded ? fastp2p_enrollment_decode(expanded) : NULL;
    if (expanded) { OPENSSL_cleanse(expanded, strlen(expanded)); free(expanded); }
    if (owned) { OPENSSL_cleanse(owned, strlen((char *)owned)); free(owned); }
    if (!enrollment) { fputs("Invalid installation token or public gateway preset. Copy the 16-digit token from the gateway console.\n", stderr); return 2; }
    char default_path[4096], ca_path[4096], identity[33];
    if (!profile) {
        int failed = machine ? fastp2p_service_profile(default_path) : fastp2p_default_profile(default_path);
        if (failed) { json_object_put(enrollment); return 2; }
        profile = default_path;
    }
    if (machine && fastp2p_service_prepare(profile)) { json_object_put(enrollment); return 1; }
    const char *ca = field(enrollment, "ca");
    int custom_ca = *ca != 0;
    unsigned char digest[32]; unsigned digest_length;
    char fingerprint[65];
    if (!EVP_Digest(ca, strlen(ca), digest, &digest_length, EVP_sha256(), NULL)) { json_object_put(enrollment); return 1; }
    for (unsigned i = 0; i < 32; ++i) snprintf(fingerprint + 2*i, 3, "%02x", digest[i]);
    int size = snprintf(ca_path, sizeof(ca_path), "%s.ca.%s.pem", profile, fingerprint);
    if (size < 0 || (size_t)size >= sizeof(ca_path)) { json_object_put(enrollment); return 2; }
    json_object *previous = fastp2p_profile_read(profile), *root = json_object_new_object();
    json_object *old_network = NULL;
    if (previous) json_object_object_get_ex(previous, "network", &old_network);
    if (previous && strcmp(field(previous, "product"), "fastp2p")) {
        json_object_put(previous); json_object_put(root); json_object_put(enrollment);
        fputs("Refusing to replace an unrelated configuration file.\n", stderr); return 2;
    }
    if (!node && old_network && *field(old_network, "Node")) node = field(old_network, "Node");
    unsigned char bytes[16];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) { json_object_put(root); json_object_put(enrollment); if (previous) json_object_put(previous); return 1; }
    for (unsigned i = 0; i < sizeof(bytes); ++i) snprintf(identity + 2*i, 3, "%02x", bytes[i]);
    if (old_network && strlen(field(old_network, "DeviceID")) == 32) strcpy(identity, field(old_network, "DeviceID"));
    if (*ca && ensure_ca(ca_path, ca)) goto fail;
    json_object *network = json_object_new_object();
    json_object_object_add(root, "network", network);
    json_object_object_add(root, "product", json_object_new_string("fastp2p"));
    json_object_object_add(network, "ServerHost", json_object_new_string(field(enrollment, "host")));
    json_object *port = NULL; json_object_object_get_ex(enrollment, "port", &port);
    json_object_object_add(network, "ServerPort", json_object_new_int(json_object_get_int(port)));
    json_object_object_add(network, "Token", json_object_new_string(field(enrollment, "key")));
    json_object_object_add(network, "AutoNode", json_object_new_boolean(!node || !*node));
    if (node && *node) json_object_object_add(network, "Node", json_object_new_string(node));
    else json_object_object_add(network, "DeviceID", json_object_new_string(identity));
    if (*ca) json_object_object_add(root, "CACertFile", json_object_new_string(ca_path));
    fastp2p_client *client = NULL;
    verification result = {0};
    if (fastp2p_client_create_json(json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN),
                                  NULL, NULL, verified, &result, &client)) goto fail;
    int started = !fastp2p_client_start(client);
    uint64_t deadline = op_monotonic_ns() + UINT64_C(25000000000);
    while (started && !result.online && !result.failed && op_monotonic_ns() < deadline && fastp2p_client_state(client) != FASTP2P_STOPPED)
        if (fastp2p_client_step(client, 10)) break;
    fastp2p_client_destroy(client);
    if (!result.online) { fputs("Gateway certificate, hostname or installation key could not be verified.\n", stderr); goto fail; }
    const char *arrays[] = {"apps", "socks5"};
    for (unsigned i = 0; i < 2; ++i) {
        json_object *value = NULL;
        if (previous && json_object_object_get_ex(previous, arrays[i], &value))
            json_object_object_add(root, arrays[i], json_object_get(value));
    }
    const char *plain = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    if ((machine ? fastp2p_profile_write_machine(profile, plain)
                 : fastp2p_profile_write(profile, plain))) goto fail;
    json_object_put(root); json_object_put(enrollment); if (previous) json_object_put(previous);
    if (!no_service) {
        int installed = machine ? fastp2p_service_install(profile, custom_ca ? ca_path : NULL)
                                : fastp2p_enable_autostart(profile, custom_ca ? ca_path : NULL);
        if (installed) {
            fputs("Gateway verified and profile saved; automatic startup could not be installed.\n", stderr);
            return 1;
        }
    }
    printf("fastp2p installed; gateway identity verified; node=%s\n", result.node);
    return 0;
fail:
    json_object_put(root); json_object_put(enrollment); if (previous) json_object_put(previous);
    return 1;
}

int fastp2p_install_command(int argc, char **argv) {
    const char *token = NULL, *token_file = NULL, *profile = NULL, *node = NULL;
    int no_service = 0, machine = 0;
    for (int i = 2; i < argc; ++i) {
        if (!strcmp(argv[i], "--no-service")) { no_service = 1; continue; }
        if (!strcmp(argv[i], "--service")) { machine = 1; continue; }
        if (i + 1 >= argc) return 2;
        const char *name = argv[i], *value = argv[++i];
        if (!strcmp(name, "--token")) token = value;
        else if (!strcmp(name, "--token-file")) token_file = value;
        else if (!strcmp(name, "--config")) profile = value;
        else if (!strcmp(name, "--node")) node = value;
        else return 2;
    }
    return install_token(token, token_file, profile, node, no_service, machine);
}
/* A 16-digit run in the file name is the key; that is what makes the download a
 * single double-clickable file rather than a package plus a separate token. */
int fastp2p_name_token(const char *path, char out[17]) {
    const char *name = path ? path : "";
    for (const char *p = name; *p; ++p)
        if (*p == '/' || *p == '\\') name = p + 1;
    const char *start = NULL;
    int run = 0;
    for (const char *p = name;; ++p) {
        if (*p >= '0' && *p <= '9') {
            if (!run) start = p;
            ++run;
        } else {
            if (run == 16) {
                memcpy(out, start, 16);
                out[16] = 0;
                return fastp2p_install_key_valid(out) ? 0 : -1;
            }
            run = 0;
        }
        if (!*p) break;
    }
    return -1;
}
int fastp2p_service_install_token(const char *token) {
    if (!fastp2p_service_supported() || !token || !*token) return 2;
    /* Creating a service needs rights a plain double-click does not have. */
    if (!fastp2p_service_elevated()) return fastp2p_service_elevate(NULL) == 0 ? 0 : 1;
    char profile[4096];
    if (fastp2p_service_profile(profile)) return 1;
    return install_token(token, NULL, profile, NULL, 0, 1) ? 1 : 0;
}
