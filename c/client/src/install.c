#include "install.h"
#include "fastp2p.h"
#include "enrollment.h"
#include "identity_file.h"
#include "platform.h"
#include "bootstrap.h"
#include "config_internal.h"
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
    size = base ? snprintf(out, 4096, "%s/fastp2p/config/fastp2p.conf", base) : -1;
#elif defined(__APPLE__)
    base = getenv("HOME");
    size = base ? snprintf(out, 4096, "%s/Library/Application Support/fastp2p/client.json", base) : -1;
#else
    base = getenv("XDG_CONFIG_HOME");
    if (geteuid() == 0) size = snprintf(out, 4096, "/var/lib/fastp2p/config/fastp2p.conf");
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
    int size = snprintf(out, 4096, "%s/fastp2p/config/fastp2p.conf", base);
    return size > 0 && size < 4096 ? 0 : -1;
}
#else
int fastp2p_service_profile(char out[4096]) {
    int size = snprintf(out, 4096, "/var/lib/fastp2p/config/fastp2p.conf");
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
int fastp2p_profile_writable(const char *path) {
    char parent[4096];
    if(!path||snprintf(parent,sizeof(parent),"%s",path)>=(int)sizeof(parent))return 0;
#ifdef _WIN32
    char probe[4096];WCHAR wide_probe[4096],wide_path[4096];
    if(wide(path,wide_path))return 0;
    DWORD attributes=GetFileAttributesW(wide_path);
    if(attributes==INVALID_FILE_ATTRIBUTES||(attributes&(FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_REPARSE_POINT)))return 0;
    if(snprintf(probe,sizeof(probe),"%s.probe.%lu",path,(unsigned long)getpid())>=(int)sizeof(probe)||wide(probe,wide_probe))return 0;
    HANDLE file=CreateFileW(wide_probe,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE,NULL);
    if(file==INVALID_HANDLE_VALUE)return 0;
    CloseHandle(file);return 1;
#else
    char *slash=strrchr(parent,'/');
    if(slash) {*slash=0;if(!*parent)strcpy(parent,"/");}else strcpy(parent,".");
    return access(parent,W_OK|X_OK)==0;
#endif
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
int fastp2p_profile_relocate(const char *source,const char *destination) {
    json_object *root=fastp2p_profile_read(source),*value=NULL;
    int result=-1;
    if(!root||!json_object_object_get_ex(root,"product",&value)||!json_object_is_type(value,json_type_string)||
       strcmp(json_object_get_string(value),"fastp2p")||
       fp_config_validate_json(json_object_to_json_string_ext(root,JSON_C_TO_STRING_PLAIN)))goto done;
    if(json_object_object_get_ex(root,"CACertFile",&value)&&json_object_is_type(value,json_type_string)&&*json_object_get_string(value)) {
        size_t length=0;unsigned char *ca=read_file(json_object_get_string(value),16384,&length);
        unsigned char hash[32];unsigned count=0;char fingerprint[65],path[4096];
        if(!ca)goto done;
        if(!EVP_Digest(ca,length,hash,&count,EVP_sha256(),NULL)||count!=32) {free(ca);goto done;}
        for(unsigned i=0;i<32;++i)snprintf(fingerprint+2*i,3,"%02x",hash[i]);
        int size=snprintf(path,sizeof(path),"%s.ca.%s.pem",destination,fingerprint);
        int failed=size<0||size>=(int)sizeof(path)||memchr(ca,0,length)||ensure_ca(path,(const char *)ca);
        free(ca);if(failed)goto done;
        json_object_object_add(root,"CACertFile",json_object_new_string(path));
    }
    const char *text=json_object_to_json_string_ext(root,JSON_C_TO_STRING_PLAIN);
#ifdef _WIN32
    char machine[4096];
    result=!fastp2p_service_profile(machine)&&!strcmp(machine,destination)?fastp2p_profile_write_machine(destination,text):fastp2p_profile_write(destination,text);
#else
    result=fastp2p_profile_write(destination,text);
#endif
done:
    if(root)json_object_put(root);
    return result;
}
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
    const char *text = root && json_object_is_type(root,json_type_object) && json_object_object_get_ex(root,key,&value)
                           ? json_object_get_string(value) : NULL;
    return text ? text : "";
}
/* The installer runs in its own console, which closes the moment it exits, so a
 * failure would otherwise leave no trace at all. */
void fastp2p_install_note(const char *text) {
    /* Written beside the machine profile, which the installer has already locked
     * to SYSTEM and administrators. A shared temp directory would let another
     * user aim this append at a file of their choosing. */
    char profile[4096], path[4096];
    if (fastp2p_service_profile(profile)) return;
    char *slash = strrchr(profile, '/');
    if (!slash) return;
    *slash = 0;
    if (snprintf(path, sizeof(path), "%s/install.log", profile) >= (int)sizeof(path)) return;
#ifdef _WIN32
    WCHAR wide_path[4096];
    if (wide(path, wide_path)) return;
    FILE *log = _wfopen(wide_path, L"a");
#else
    FILE *log = fopen(path, "a");
#endif
    if (!log) return;
    fprintf(log, "%s\n", text);
    fclose(log);
}
static int install_token(const char *token, const char *token_file, const char *profile,
                         const char *node, int no_service, int machine) {
    if (machine) fastp2p_install_step("[1/5] 正在读取文件名中的安装密钥并准备环境…");
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
        /* Only the double-clicked machine install (machine=1) is driven by a
         * file name a user can choose, where it must trust the compiled-in preset
         * rather than an inherited environment variable. An explicit CLI install
         * --token/--token-file legitimately uses FASTP2P_BOOTSTRAP_FILE to target a
         * test or private gateway, so the override stays available there even when
         * the shell happens to be elevated. */
        if (machine && override && *override) override = NULL;
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
#ifdef _WIN32
    char legacy_profile[4096]="";
#endif
    /* Never silently replace an existing unreadable identity. */
    if (!previous) {
#ifdef _WIN32
        WCHAR existing[4096];
        int exists = !wide(profile, existing) && GetFileAttributesW(existing) != INVALID_FILE_ATTRIBUTES;
#else
        struct stat existing;
        int exists = !lstat(profile, &existing);
#endif
        if (exists) {
            fputs("Existing profile cannot be read; repair it before reinstalling.\n", stderr);
            json_object_put(root); json_object_put(enrollment); return 1;
        }
    }
#ifdef _WIN32
    if (!previous) {
        char expected[4096], candidate[4096];
        int managed = !(machine ? fastp2p_service_profile(expected) : fastp2p_default_profile(expected)) && !strcmp(profile, expected);
        const char *bases[] = {machine ? getenv("ProgramData") : getenv("LOCALAPPDATA"),
                               machine ? getenv("LOCALAPPDATA") : NULL,machine ? getenv("LOCALAPPDATA") : NULL};
        for (unsigned i = 0; managed && !previous && i < 3; ++i) {
            if (!bases[i] || !*bases[i]) continue;
            if (snprintf(candidate, sizeof(candidate),i==1?"%s/fastp2p/config/fastp2p.conf":"%s/fastp2p/client.dat",bases[i]) >= (int)sizeof(candidate)) continue;
            if(!strcmp(candidate,profile))continue;
            WCHAR old_path[4096];
            if (wide(candidate, old_path) || GetFileAttributesW(old_path) == INVALID_FILE_ATTRIBUTES) continue;
            previous = fastp2p_profile_read(candidate);
            if (!previous) {
                fputs("Legacy profile cannot be decrypted; refusing identity loss.\n", stderr);
                json_object_put(root); json_object_put(enrollment); return 1;
            }
            snprintf(legacy_profile,sizeof(legacy_profile),"%s",candidate);
        }
    }
#endif
    json_object *old_network = NULL;
    if (previous) json_object_object_get_ex(previous, "network", &old_network);
    if (previous && strcmp(field(previous, "product"), "fastp2p")) {
        json_object_put(previous); json_object_put(root); json_object_put(enrollment);
        fputs("Refusing to replace an unrelated configuration file.\n", stderr); return 2;
    }
    json_object *old_automatic = NULL;
    int automatic = old_network && json_object_object_get_ex(old_network,"AutoNode",&old_automatic) &&
                    json_object_is_type(old_automatic,json_type_boolean) && json_object_get_boolean(old_automatic);
    if (!node && !automatic && old_network && *field(old_network, "Node")) node = field(old_network, "Node");
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
    json_object_object_add(network, "DeviceID", json_object_new_string(identity));
    if (*ca) json_object_object_add(root, "CACertFile", json_object_new_string(ca_path));
    fastp2p_client *client = NULL;
    verification result = {0};
    if (machine) fastp2p_install_step("[2/5] 正在连接网关并校验证书与密钥（最多 25 秒）…");
    if (fastp2p_client_create_json(json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN),
                                  NULL, NULL, verified, &result, &client)) goto fail;
    int started = !fastp2p_client_start(client);
    uint64_t deadline = op_monotonic_ns() + UINT64_C(25000000000);
    while (started && !result.online && !result.failed && op_monotonic_ns() < deadline && fastp2p_client_state(client) != FASTP2P_STOPPED)
        if (fastp2p_client_step(client, 10)) break;
    fastp2p_client_destroy(client);
    if (!result.online) {
        fputs("Gateway certificate, hostname or installation key could not be verified.\n", stderr);
        fastp2p_install_note("failed: the gateway could not be verified (network, certificate or token)");
        goto fail;
    }
    /* Keep forwarding rules and user settings, but only after verification:
     * running a second copy of the old listeners would conflict with the service. */
    if (previous) {
        json_object *saved = NULL, *saved_network = NULL;
        if (json_object_deep_copy(previous, &saved, NULL)) goto fail;
        if (!json_object_object_get_ex(saved, "network", &saved_network) ||
            !json_object_is_type(saved_network, json_type_object)) {
            saved_network = json_object_new_object();
            json_object_object_add(saved, "network", saved_network);
        }
        const char *keys[] = {"ServerHost", "ServerPort", "Token", "AutoNode", "Node", "DeviceID"};
        for (unsigned i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
            json_object *value = NULL;
            if (json_object_object_get_ex(network, keys[i], &value))
                json_object_object_add(saved_network, keys[i], json_object_get(value));
            else json_object_object_del(saved_network, keys[i]);
        }
        json_object *value = NULL;
        if (json_object_object_get_ex(root, "CACertFile", &value))
            json_object_object_add(saved, "CACertFile", json_object_get(value));
        else json_object_object_del(saved, "CACertFile");
        json_object_put(root); root = saved;
    }
    if(fp_config_validate_json(json_object_to_json_string_ext(root,JSON_C_TO_STRING_PLAIN))) {
        fputs("Existing forwarding or network settings are invalid; previous service retained.\n",stderr);goto fail;
    }
#ifdef _WIN32
    if(*legacy_profile) {
        char backup[4096];
        if(snprintf(backup,sizeof(backup),"%s.migrated",profile)>=(int)sizeof(backup))goto fail;
        const char *old=json_object_to_json_string_ext(previous,JSON_C_TO_STRING_PLAIN);
        if(machine?fastp2p_profile_write_machine(backup,old):fastp2p_profile_write(backup,old))goto fail;
    }
#endif
    /* Use the new installer's uninstall command: old releases do not understand
     * --keep-config and may delete the identity or schedule the new EXE for
     * deletion at reboot. Verify first so a bad token leaves the old service. */
    if (!no_service) {
        if (machine) fastp2p_install_step("正在探测并卸载旧服务，保留节点身份与配置…");
#ifdef _WIN32
        if (machine) {
            char *remove[] = {"fastp2p", "uninstall", "--keep-config", NULL};
            if (fastp2p_uninstall_command(3, remove)) goto fail;
        } else {
            if(*legacy_profile&&fastp2p_remove_autostart(legacy_profile))goto fail;
            if(fastp2p_remove_autostart(profile))goto fail;
        }
#else
        if (fastp2p_remove_autostart(profile)) goto fail;
#endif
    }
    if (machine) fastp2p_install_step("[3/5] 网关校验通过，正在写入加密配置…");
    const char *plain = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    if ((machine ? fastp2p_profile_write_machine(profile, plain)
                 : fastp2p_profile_write(profile, plain))) goto fail;
    json_object_put(root); json_object_put(enrollment); if (previous) json_object_put(previous);
    if (!no_service) {
        if (machine) fastp2p_install_step("[4/5] 正在注册 Windows 服务并设为开机自启…");
        int installed = machine ? fastp2p_service_install(profile, custom_ca ? ca_path : NULL)
                                : fastp2p_enable_autostart(profile, custom_ca ? ca_path : NULL);
        if (installed) {
            fputs("Gateway verified and profile saved; automatic startup could not be installed.\n", stderr);
            return 1;
        }
        if(machine && fastp2p_service_cleanup_previous())
            fastp2p_install_note("installed; previous executable cleanup deferred because a file is in use");
    }
#ifdef _WIN32
    if(*legacy_profile) {
        WCHAR old_path[4096];
        if(!wide(legacy_profile,old_path)&&!DeleteFileW(old_path))
            fastp2p_install_note("installed; legacy profile cleanup deferred");
    }
#endif
    printf("fastp2p installed; gateway identity verified; node=%s\n", result.node);
    if (machine) {
        char done[160];
        snprintf(done, sizeof(done), "[5/5] 安装完成，节点名：%s", result.node);
        fastp2p_install_step(done);
    }
    fastp2p_install_note("installed");
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

int fastp2p_uninstall_command(int argc, char **argv) {
    int keep = argc == 3 && !strcmp(argv[2], "--keep-config");
    if (argc != 2 && !keep) return 2;
    char profile[4096];
#ifdef _WIN32
    if (!fastp2p_service_elevated())
        return fastp2p_service_elevate(keep ? "uninstall --keep-config" : "uninstall") ? 1 : 0;
    if (fastp2p_service_profile(profile) || fastp2p_service_remove()) return 1;
    char user_profile[4096];
    if (!fastp2p_default_profile(user_profile) && fastp2p_remove_autostart(user_profile)) return 1;
    const char *home=getenv("LOCALAPPDATA");
    if(home&&snprintf(user_profile,sizeof(user_profile),"%s/fastp2p/client.dat",home)<(int)sizeof(user_profile)&&
       fastp2p_remove_autostart(user_profile))return 1;
    if (!keep && fastp2p_service_purge()) {
        fputs("fastp2p removed; an in-use file may need removal after this process exits.\n", stderr);
    }
#elif defined(__linux__)
    if (geteuid()) { fputs("Run fastp2p uninstall as root.\n", stderr); return 1; }
    (void)profile;
    return fastp2p_linux_uninstall(keep) ? 1 : 0;
#else
    fputs("This platform does not provide the system uninstall command.\n", stderr); return 2;
#endif
    puts(keep ? "Previous fastp2p service removed; configuration retained for reinstall."
              : "fastp2p service and client configuration removed.");
    return 0;
}
/* A 16-digit run in the file name is the key; that is what makes the download a
 * single double-clickable file rather than a package plus a separate token. */
int fastp2p_name_token(const char *path, char out[17]) {
    const char *name = path ? path : "";
    for (const char *p = name; *p; ++p)
        if (*p == '/' || *p == '\\') name = p + 1;
    const char *start = NULL;
    int run = 0, saw_candidate = 0;
    for (const char *p = name;; ++p) {
        if (*p >= '0' && *p <= '9') {
            if (!run) start = p;
            ++run;
        } else {
            /* Keep looking: a name can carry a build stamp as well as the key. */
            if (run == 16) {
                memcpy(out, start, 16);
                out[16] = 0;
                if (fastp2p_install_key_valid(out)) return 0;
                saw_candidate = 1;
            }
            run = 0;
        }
        if (!*p) break;
    }
    return saw_candidate ? -2 : -1;
}
int fastp2p_service_install_token(const char *token) {
    if (!fastp2p_service_supported() || !token || !*token) return 2;
    /* Creating a service needs rights a plain double-click does not have. The
     * elevated copy repeats this work, so report the hand-off rather than a
     * result this process never saw. */
    if (!fastp2p_service_elevated()) return fastp2p_service_elevate(NULL) == 0 ? 3 : 1;
    /* The elevated copy gets its own progress terminal. */
    fastp2p_installer_ui_begin();
    char profile[4096];
    if (fastp2p_service_profile(profile)) {
        fastp2p_installer_ui_result(0, "fastp2p 安装失败",
            "无法定位系统配置目录（%ProgramData%）。\n请确认以管理员身份运行。");
        return 1;
    }
    int rv = install_token(token, NULL, profile, NULL, 0, 1);
    if (rv == 0) {
        fastp2p_installer_ui_result(1, "fastp2p 安装完成",
            "安装成功！\n\n服务已注册为开机自启，并会在异常退出时自动重启。\n"
            "可在「服务」中查看 fastp2p，或用 sc query fastp2p 查询状态。");
    } else {
        fastp2p_installer_ui_result(0, "fastp2p 安装失败",
            "安装未能完成。\n\n常见原因：\n"
            "· 无法连接网关（网络不通或网关证书校验失败）\n"
            "· 文件名中的 16 位安装密钥不正确\n"
            "· C:\\ProgramData\\fastp2p 权限异常\n\n"
            "详细信息已写入 %ProgramData%\\fastp2p\\config\\install.log。");
    }
    return rv ? 1 : 0;
}
