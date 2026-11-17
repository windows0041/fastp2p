#include "fastp2p.h"
#include <assert.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#endif
#include <stdio.h>
#include <string.h>

static int callback_count;
static void stop_from_callback(fastp2p_client *c, const fastp2p_event *e, void *user) {
    (void)user;
    if (e->type == FASTP2P_EVENT_STATE && e->state == FASTP2P_CONNECTING) {
        ++callback_count;
        assert(fastp2p_client_step(c, 0) == FASTP2P_ESTATE);
        assert(fastp2p_client_stop(c) == FASTP2P_OK);
    }
}
static int fd_count(void) {
#ifdef _WIN32
    DWORD n;
    assert(GetProcessHandleCount(GetCurrentProcess(), &n));
    return (int)n;
#else
#ifdef __APPLE__
    DIR *d = opendir("/dev/fd");
#else
    DIR *d = opendir("/proc/self/fd");
#endif
    assert(d);
    int n = 0;
    struct dirent *entry;
    while ((entry = readdir(d)))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
            ++n;
    closedir(d);
    return n;
#endif
}
int main(void) {
    assert(fastp2p_abi_version() == 1 && !strcmp(fastp2p_version(), FASTP2P_VERSION));
    fastp2p_client *c = (void *)1;
    assert(fastp2p_client_create(NULL, &c) == FASTP2P_EINVAL && !c);
    fastp2p_config cfg = {.struct_size = sizeof(cfg),
                       .abi_version = 1,
                       .gateway_host = "127.0.0.1",
                       .node = "c-api-selftest",
                       .token = UINT64_MAX,
                       .on_event = stop_from_callback};
    cfg.abi_version = 99;
    assert(fastp2p_client_create(&cfg, &c) == FASTP2P_EINVAL);
    cfg.abi_version = 1;
    cfg.struct_size = 1;
    assert(fastp2p_client_create(&cfg, &c) == FASTP2P_EINVAL);
    cfg.struct_size = sizeof(cfg);
    cfg.node = NULL;
    assert(fastp2p_client_create(&cfg, &c) == FASTP2P_OK);
    assert(strlen(fastp2p_client_node(c)) >= 8 && strlen(fastp2p_client_node(c)) <= 31);
    assert(strlen(fastp2p_client_device_id(c)) == 32);
    assert(fastp2p_client_set_identity(c, "not-valid") == FASTP2P_EINVAL);
    assert(fastp2p_client_set_identity(c, "1234567890abcdef1234567890abcdef") == FASTP2P_OK);
    assert(!strcmp(fastp2p_client_device_id(c), "1234567890abcdef1234567890abcdef"));
    fastp2p_client_destroy(c);
    cfg.node = "c-api-selftest";
    assert(fastp2p_client_create(&cfg, &c) == FASTP2P_OK);
    assert(fastp2p_client_state(c) == FASTP2P_STOPPED);
    assert(fastp2p_client_step(c, 0) == FASTP2P_ESTATE);
    fastp2p_forward f = {.struct_size = sizeof(f),
                      .local_port = 0,
                      .peer_node = "other-client",
                      .destination_host = "127.0.0.1",
                      .destination_port = 22,
                      .protocol = "tcp",
                      .transport = FASTP2P_TRANSPORT_TCP};
    assert(fastp2p_client_add_forward(c, &f, NULL) == FASTP2P_EINVAL);
    fastp2p_client_destroy(c);
    /* Prime TLS process caches before checking repeated lifecycle FD ownership. */
    for (int i = 0; i < 20; ++i) {
        assert(fastp2p_client_create(&cfg, &c) == FASTP2P_OK);
        assert(fastp2p_client_start(c) == FASTP2P_OK);
        assert(fastp2p_client_step(c, 0) == FASTP2P_OK);
        assert(fastp2p_client_state(c) == FASTP2P_STOPPED);
        assert(fastp2p_client_stop(c) == FASTP2P_OK);
        fastp2p_client_destroy(c);
    }
    int before = fd_count();
    for (int i = 0; i < 20; ++i) {
        assert(fastp2p_client_create(&cfg, &c) == FASTP2P_OK);
        assert(fastp2p_client_start(c) == FASTP2P_OK);
        assert(fastp2p_client_step(c, 0) == FASTP2P_OK);
        fastp2p_client_destroy(c);
    }
    int after = fd_count();
    fprintf(stderr, "callback_count=%d fds_before=%d fds_after=%d\n", callback_count, before,
            after);
    assert(callback_count == 40 && after == before);
    const char *json = "{\"network\":{\"Node\":\"json-api-test\",\"Token\":18446744073709551615}}";
    assert(fastp2p_client_create_json(json, NULL, NULL, NULL, NULL, &c) == FASTP2P_OK);
    fastp2p_client_destroy(c);
    assert(fastp2p_client_create_json(json, "18446744073709551616", NULL, NULL, NULL, &c) ==
               FASTP2P_EINVAL &&
           !c);
    assert(fastp2p_client_create_json("{}", "1", NULL, NULL, NULL, &c) == FASTP2P_OK);
    assert(strlen(fastp2p_client_node(c)) >= 8 && strlen(fastp2p_client_device_id(c)) == 32);
    fastp2p_client_destroy(c);
    assert(fastp2p_client_create_json("{\"network\":{\"Node\":\"short\"}}", "1", NULL, NULL, NULL, &c) == FASTP2P_EINVAL && !c);
    assert(fastp2p_client_create_json("{", NULL, NULL, NULL, NULL, &c) == FASTP2P_EINVAL && !c);
    assert(fastp2p_client_create(&cfg, &c) == FASTP2P_OK);
    fastp2p_socks5 p = {.struct_size = sizeof(p),
                     .peer_node = "exit-client",
                     .local_port = 0,
                     .transport = FASTP2P_TRANSPORT_QUIC};
    assert(fastp2p_client_add_socks5(c, &p, NULL) == FASTP2P_EINVAL);
    p.local_port = 1080;
    p.username = "user";
    assert(fastp2p_client_add_socks5(c, &p, NULL) == FASTP2P_EINVAL);
    p.username = NULL;
    p.transport = 0;
    assert(fastp2p_client_add_socks5(c, &p, NULL) == FASTP2P_EINVAL);
    fastp2p_client_destroy(c);
    assert(fastp2p_client_create_json(
               "{\"network\":{\"Node\":\"json-api-test\",\"Token\":1},\"socks5\":{}}", NULL, NULL,
               NULL, NULL, &c) == FASTP2P_EINVAL &&
           !c);
    puts("ABI validation, callback stop and repeated lifecycle FD checks passed");
    return 0;
}
