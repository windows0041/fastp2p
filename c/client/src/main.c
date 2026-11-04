#include "fastp2p.h"
#include "identity_file.h"
#include "install.h"
#include "config_sync.h"
#include "notices.h"
#include "update.h"
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>

static volatile sig_atomic_t interrupted;
static int was_online;
static void signal_stop(int sig) {
    (void)sig;
    interrupted = 1;
}
static void event(fastp2p_client *c, const fastp2p_event *e, void *user) {
    (void)c;
    (void)user;
    static const char *types[] = {"state", "error", "tunnel", "forward", "heartbeat"};
    if (e->state == FASTP2P_ONLINE && e->type == FASTP2P_EVENT_STATE) {
        was_online = 1;
        fp_config_sync_online();
    }
    json_object *j = json_object_new_object();
    json_object_object_add(j, "event", json_object_new_string(types[e->type]));
    json_object_object_add(j, "state", json_object_new_int(e->state));
    json_object_object_add(j, "id", json_object_new_uint64(e->id));
    json_object_object_add(j, "code", json_object_new_int(e->code));
    json_object_object_add(j, "message", json_object_new_string(e->message));
    puts(json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN));
    fflush(stdout);
    json_object_put(j);
}
static json_object *field(json_object *j, const char *name) {
    json_object *v = NULL;
    if (j)
        json_object_object_get_ex(j, name, &v);
    return v;
}
static const char *string(json_object *j, const char *name) {
    json_object *v = field(j, name);
    return v && json_object_is_type(v, json_type_string) ? json_object_get_string(v) : NULL;
}
static uint64_t number(json_object *j, const char *name) {
    json_object *v = field(j, name);
    return v && json_object_is_type(v, json_type_int) ? json_object_get_uint64(v) : 0;
}
static int integer(const char *s, uint64_t *value) {
    if (!s || !*s)
        return -1;
    for (const char *p = s; *p; ++p)
        if (*p < '0' || *p > '9')
            return -1;
    errno = 0;
    char *end;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || *end)
        return -1;
    *value = (uint64_t)v;
    return 0;
}
static void usage(void) {
    puts("fastp2p install --token 16_DIGITS [--no-service] [--service] [--config FILE]\n"
         "fastp2p uninstall [--keep-config]   (removes service; keep-config prepares a reinstall)\n"
         "fastp2p service --config FILE   (started by the Windows service manager)\n"
         "fastp2p install --token-file FILE [--no-service] [--config FILE]\n"
         "fastp2p run [--config FILE]\n"
         "fastp2p stop [--config FILE]\n"
         "fastp2p --config FILE [--serverhost HOST] [--node NAME] [--cacert FILE]\n"
         "          [--port WSS_PORT] [--publicipport PORT] [--run-seconds N]\n"
         "          [--identity-file FILE] (omitting --node uses this host's name)\n"
         "FASTP2P_TOKEN overrides network.Token in the JSON configuration.\n"
         "--version prints the C library and ABI version; --licenses prints complete notices.");
}
static int client_main(int argc, char **argv) {
    optind = 1;
    was_online = 0;
    char **original_argv = argv;
    if (argc == 2 && !strcmp(argv[1], "--licenses")) {
        return fwrite(fastp2p_notices, 1, sizeof(fastp2p_notices), stdout) == sizeof(fastp2p_notices) ? 0 : 1;
    }
    if (argc > 1 && !strcmp(argv[1], "install")) return fastp2p_install_command(argc, argv);
    if (argc == 5 && !strcmp(argv[1], "--apply-update")) {
        /* Detached helper spawned by a self-update: installs the staged build
         * over the target and restarts the service. */
        return fp_update_swap(argv[2], argv[3], argv[4]) ? 1 : 0;
    }
    if (argc > 1 && !strcmp(argv[1], "stop")) {
        char profile[4096]; const char *path = NULL;
        if (argc == 4 && !strcmp(argv[2], "--config")) path = argv[3];
        else if (argc != 2) return 2;
        if (!path) { if (fastp2p_default_profile(profile)) return 2; path = profile; }
        return fastp2p_stop_installed(path) ? 1 : 0;
    }
    if (argc > 1 && !strcmp(argv[1], "run")) { --argc; ++argv; }
    const char *config_file = NULL, *host = NULL, *node = NULL, *ca = NULL;
    const char *identity_file = NULL;
    int explicit_node = 0;
    int background = 0;
    char default_profile[4096];
    uint64_t port = 0, public_port = 0, run_seconds = 0;
    static const struct option options[] = {{"config", required_argument, 0, 'c'},
                                            {"serverhost", required_argument, 0, 's'},
                                            {"node", required_argument, 0, 'n'},
                                            {"identity-file", required_argument, 0, 'i'},
                                            {"background", no_argument, 0, 'b'},
                                            {"cacert", required_argument, 0, 'a'},
                                            {"port", required_argument, 0, 'p'},
                                            {"publicipport", required_argument, 0, 'P'},
                                            {"run-seconds", required_argument, 0, 'r'},
                                            {"version", no_argument, 0, 'v'},
                                            {"help", no_argument, 0, 'h'},
                                            {0, 0, 0, 0}};
    int opt;
    while ((opt = getopt_long_only(argc, argv, "", options, NULL)) != -1) {
        switch (opt) {
        case 'b': background = 1; break;
        case 'c':
            config_file = optarg;
            break;
        case 's':
            host = optarg;
            break;
        case 'n':
            node = optarg;
            explicit_node = 1;
            break;
        case 'i':
            identity_file = optarg;
            break;
        case 'a':
            ca = optarg;
            break;
        case 'p':
            if (integer(optarg, &port) || !port || port > 65535)
                return 2;
            break;
        case 'P':
            if (integer(optarg, &public_port) || public_port > 65535)
                return 2;
            break;
        case 'r':
            if (integer(optarg, &run_seconds) || run_seconds > 86400 * 365)
                return 2;
            break;
        case 'v':
            printf("fastp2p %s ABI %u\n", fastp2p_version(), fastp2p_abi_version());
            return 0;
        case 'h':
            usage();
            return 0;
        default:
            usage();
            return 2;
        }
    }
    if (optind != argc) {
        usage();
        return 2;
    }
    errno = 0;
    if (!config_file && !host && !getenv("FASTP2P_TOKEN")) {
        if (fastp2p_default_profile(default_profile)) return 2;
        config_file = default_profile;
    }
    if (fastp2p_runtime_prepare(config_file)) {
        fputs("Cannot use the managed service account.\n", stderr); return 1;
    }
    json_object *root = config_file ? fastp2p_profile_read(config_file) : json_object_new_object();
    if (errno == ERANGE || !root || !json_object_is_type(root, json_type_object)) {
        fputs("Invalid JSON configuration\n", stderr);
        if (root)
            json_object_put(root);
        return 2;
    }
    json_object *network = field(root, "network");
    uint64_t token = number(network, "Token");
    const char *env = getenv("FASTP2P_TOKEN");
    /* Explicit CLI/environment overrides are for foreground/debug embedding;
     * only file-driven sessions can truthfully acknowledge managed reloads. */
    int managed_config = config_file && !host && !node && !ca && !port && !public_port && !env;
    if (env && integer(env, &token)) {
        fputs("Invalid FASTP2P_TOKEN\n", stderr);
        json_object_put(root);
        return 2;
    }
    if (!host)
        host = string(network, "ServerHost");
    if (!node)
        node = string(network, "Node");
    if (!ca)
        ca = string(root, "CACertFile");
    if (!port)
        port = number(network, "ServerPort");
    if (!public_port)
        public_port = number(network, "PublicIPPort");
    if (port > 65535 || public_port > 65535) {
        json_object_put(root);
        return 2;
    }
    /* CLI and JNI use the same factory, including SOCKS5 and Enabled semantics. */
    if (!network || !json_object_is_type(network, json_type_object)) {
        network = json_object_new_object();
        json_object_object_add(root, "network", network);
    }
    if (host)
        json_object_object_add(network, "ServerHost", json_object_new_string(host));
    if (node)
        json_object_object_add(network, "Node", json_object_new_string(node));
    if (explicit_node)
        json_object_object_add(network, "AutoNode", json_object_new_boolean(!*node));
    if (port)
        json_object_object_add(network, "ServerPort", json_object_new_uint64(port));
    if (public_port)
        json_object_object_add(network, "PublicIPPort", json_object_new_uint64(public_port));
    /* Override strings may refer to root; copy CA before replacing any field. */
    fastp2p_client *client = NULL;
    fp_config_sync_bind(NULL,managed_config?config_file:NULL,root);
    int rv = fastp2p_client_create_json(json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN),
                                     env, ca, event, NULL, &client);
    if (rv) {
        fputs("Invalid client configuration (network, forward or SOCKS5 rule)\n", stderr);
        json_object_put(root);
        return 2;
    }
    fp_config_sync_bind(client,managed_config?config_file:NULL,root);
    const char *configured_identity = string(network, "DeviceID");
    const char *effective_host = string(network, "ServerHost");
    if ((!configured_identity || !*configured_identity) &&
        op_cli_identity(client, identity_file, config_file,
                        effective_host && *effective_host ? effective_host : "127.0.0.1",
                        port ? (unsigned)port : 27183)) {
        fputs("Cannot read or save automatic node identity; check --identity-file and directory permissions\n", stderr);
        fastp2p_client_destroy(client);
        json_object_put(root);
        return 2;
    }
    signal(SIGINT, signal_stop);
    if (fastp2p_runtime_begin(config_file, background)) {
        fastp2p_client_destroy(client); json_object_put(root); return 1;
    }
    signal(SIGTERM, signal_stop);
    rv = fastp2p_client_start(client);
    if (rv)
        goto done;
    time_t deadline = run_seconds ? time(NULL) + (time_t)run_seconds : 0;
    while (!interrupted && !fastp2p_runtime_stopping() && (!deadline || time(NULL) < deadline) &&
           fastp2p_client_state(client) != FASTP2P_STOPPED) {
        rv = fastp2p_client_step(client, 10);
        if (rv)
            break;
        if (fp_config_sync_tick()) {rv=FP_CONFIG_RELOAD;break;}
    }
    if (!was_online && !interrupted && rv != FP_CONFIG_RELOAD)
        rv = FASTP2P_EIO;
done:
    if (rv && rv != FP_CONFIG_RELOAD)
        fprintf(stderr, "Client failed (%d): %s\n", rv, fastp2p_client_last_error(client));
    fastp2p_client_destroy(client);
    /* Install a verified upgrade package only after a clean shutdown: the run
     * loop then returns success, so a service manager sees a normal stop instead
     * of a failure it would answer with a restart of the old image. */
    fastp2p_runtime_end();
    if (fp_update_run_pending(original_argv))
        rv = FASTP2P_EIO;
    json_object_put(root);
    return rv == FP_CONFIG_RELOAD ? rv : rv ? 1 : 0;
}
static int client_loop(int argc,char **argv) {
    int result;
    do {
        result=client_main(argc,argv);
        if(result && result!=FP_CONFIG_RELOAD && !interrupted && fp_config_sync_failed())result=FP_CONFIG_RELOAD;
    } while(result==FP_CONFIG_RELOAD && !interrupted && !fastp2p_runtime_stopping());
    fp_config_sync_close();return result==FP_CONFIG_RELOAD?0:result;
}

int main(int argc, char **argv) {
#if !defined(_WIN32)
    if (argc == 1 || (argc == 2 && !strcmp(argv[1], "--no-service"))) {
        char token[17];
        if (fastp2p_name_token(argv[0], token) == 0) {
            char *install[] = {argv[0], "install", "--token", token,
                               argc == 2 ? argv[1] : NULL, NULL};
            return fastp2p_install_command(argc + 3, install);
        }
    }
#endif
#ifdef _WIN32
    /* Started from Explorer: no arguments. The key travels in the file name. */
    if (argc == 1) {
        char token[17];
        int named = fastp2p_name_token(argv[0], token);
        if (named == -2)
            fastp2p_installer_ui_result(0, "fastp2p 安装失败",
                "文件名里有一串 16 位数字，但不是有效的安装密钥。\n\n"
                "请确认文件名包含网关控制台提供的 16 位数字（不以 0 开头），且没有被改名工具改动。");
        if (named == 0) {
            /* Unelevated: hand off to the system UAC prompt and exit silently. The
             * elevated copy shows the progress terminal and the result dialog. */
            int rv = fastp2p_service_install_token(token);
            if (rv == 1)
                fputs("fastp2p could not request administrator approval.\n", stderr);
            return rv == 3 ? 0 : rv;
        }
    }
#endif
    if (argc > 1 && !strcmp(argv[1], "uninstall")) {
        return fastp2p_uninstall_command(argc, argv);
    }
    if (argc > 1 && !strcmp(argv[1], "service")) {
        /* Started by the service manager; --config names the profile the installer wrote. */
        char profile[4096];
        const char *path = NULL;
        for (int i = 2; i + 1 < argc; ++i)
            if (!strcmp(argv[i], "--config"))
                path = argv[i + 1];
        if (!path) {
            if (fastp2p_service_profile(profile))
                return 2;
            path = profile;
        }
        /* Drop the keyword so the rest reads like "run --config FILE". */
        return fastp2p_service_dispatch(path, argc - 1, argv + 1, client_loop);
    }
    return client_loop(argc, argv);
}
