#include <fastp2p.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static volatile sig_atomic_t stopping;
static void stop(int signal_number) {
    (void)signal_number;
    stopping = 1;
}
static void event(fastp2p_client *client, const fastp2p_event *e, void *user) {
    (void)client;
    (void)user;
    printf("event=%d state=%d: %s\n", e->type, e->state, e->message);
}
int main(int argc, char **argv) {
    if (argc != 4) {
        fputs("Usage: example-embed GATEWAY NODE CA_FILE\nSet FASTP2P_TOKEN before running.\n",
              stderr);
        return 2;
    }
    const char *text = getenv("FASTP2P_TOKEN");
    if (!text || !*text)
        return 2;
    for (const char *p = text; *p; ++p)
        if (*p < '0' || *p > '9')
            return 2;
    char *end = NULL;
    errno = 0;
    uint64_t token = strtoull(text, &end, 10);
    if (errno || *end || !token)
        return 2;
    fastp2p_config config = {.struct_size = sizeof(config),
                          .abi_version = FASTP2P_ABI_VERSION,
                          .gateway_host = argv[1],
                          .node = argv[2],
                          .token = token,
                          .ca_file = argv[3],
                          .on_event = event};
    fastp2p_client *client = NULL;
    int result = fastp2p_client_create(&config, &client);
    if (result)
        return 1;
    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    result = fastp2p_client_start(client);
    while (!result && !stopping && fastp2p_client_state(client) != FASTP2P_STOPPED)
        result = fastp2p_client_step(client, 10);
    fastp2p_client_destroy(client);
    return result ? 1 : 0;
}
