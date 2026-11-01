#include "openp2p.h"
#include "identity_file.h"
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
static void event(op2p_client *c, const op2p_event *e, void *user) {
    (void)c;
    (void)user;
    static const char *types[] = {"state", "error", "tunnel", "forward", "heartbeat"};
    if (e->state == OP2P_ONLINE)
        was_online = 1;
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
    puts("openp2p-c --config FILE [--serverhost HOST] [--node NAME] [--cacert FILE]\n"
         "          [--port WSS_PORT] [--publicipport PORT] [--run-seconds N]\n"
         "          [--identity-file FILE] (omitting --node uses this host's name)\n"
         "OPENP2P_TOKEN overrides network.Token in the JSON configuration.\n"
         "--version prints the C library and ABI version.");
}
int main(int argc, char **argv) {
    const char *config_file = NULL, *host = NULL, *node = NULL, *ca = NULL;
    const char *identity_file = NULL;
    int explicit_node = 0;
    uint64_t port = 0, public_port = 0, run_seconds = 0;
    static const struct option options[] = {{"config", required_argument, 0, 'c'},
                                            {"serverhost", required_argument, 0, 's'},
                                            {"node", required_argument, 0, 'n'},
                                            {"identity-file", required_argument, 0, 'i'},
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
            printf("openp2p-c %s ABI %u\n", op2p_version(), op2p_abi_version());
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
    json_object *root = config_file ? json_object_from_file(config_file) : json_object_new_object();
    if (errno == ERANGE || !root || !json_object_is_type(root, json_type_object)) {
        fputs("Invalid JSON configuration\n", stderr);
        if (root)
            json_object_put(root);
        return 2;
    }
    json_object *network = field(root, "network");
    uint64_t token = number(network, "Token");
    const char *env = getenv("OPENP2P_TOKEN");
    if (env && integer(env, &token)) {
        fputs("Invalid OPENP2P_TOKEN\n", stderr);
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
    op2p_client *client = NULL;
    int rv = op2p_client_create_json(json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN),
                                     env, ca, event, NULL, &client);
    if (rv) {
        fputs("Invalid client configuration (network, forward or SOCKS5 rule)\n", stderr);
        json_object_put(root);
        return 2;
    }
    const char *configured_identity = string(network, "DeviceID");
    const char *effective_host = string(network, "ServerHost");
    if ((!configured_identity || !*configured_identity) &&
        op_cli_identity(client, identity_file, config_file,
                        effective_host && *effective_host ? effective_host : "127.0.0.1",
                        port ? (unsigned)port : 27183)) {
        fputs("Cannot read or save automatic node identity; check --identity-file and directory permissions\n", stderr);
        op2p_client_destroy(client);
        json_object_put(root);
        return 2;
    }
    signal(SIGINT, signal_stop);
    signal(SIGTERM, signal_stop);
    rv = op2p_client_start(client);
    if (rv)
        goto done;
    time_t deadline = run_seconds ? time(NULL) + (time_t)run_seconds : 0;
    while (!interrupted && (!deadline || time(NULL) < deadline) &&
           op2p_client_state(client) != OP2P_STOPPED) {
        rv = op2p_client_step(client, 10);
        if (rv)
            break;
    }
    if (!was_online && !interrupted)
        rv = OP2P_EIO;
done:
    if (rv)
        fprintf(stderr, "Client failed (%d): %s\n", rv, op2p_client_last_error(client));
    op2p_client_destroy(client);
    json_object_put(root);
    return rv ? 1 : 0;
}
