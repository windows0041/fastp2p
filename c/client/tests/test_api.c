#include "openp2p.h"
#include <assert.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#endif
#include <stdio.h>
#include <string.h>

static int callback_count;
static void stop_from_callback(op2p_client *c, const op2p_event *e, void *user) {
    (void)user;
    if (e->type == OP2P_EVENT_STATE && e->state == OP2P_CONNECTING) {
        ++callback_count;
        assert(op2p_client_step(c, 0) == OP2P_ESTATE);
        assert(op2p_client_stop(c) == OP2P_OK);
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
    assert(op2p_abi_version() == 1 && !strcmp(op2p_version(), OP2P_VERSION));
    op2p_client *c = (void *)1;
    assert(op2p_client_create(NULL, &c) == OP2P_EINVAL && !c);
    op2p_config cfg = {.struct_size = sizeof(cfg),
                       .abi_version = 1,
                       .gateway_host = "127.0.0.1",
                       .node = "c-api-selftest",
                       .token = UINT64_MAX,
                       .on_event = stop_from_callback};
    cfg.abi_version = 99;
    assert(op2p_client_create(&cfg, &c) == OP2P_EINVAL);
    cfg.abi_version = 1;
    cfg.struct_size = 1;
    assert(op2p_client_create(&cfg, &c) == OP2P_EINVAL);
    cfg.struct_size = sizeof(cfg);
    assert(op2p_client_create(&cfg, &c) == OP2P_OK);
    assert(op2p_client_state(c) == OP2P_STOPPED);
    assert(op2p_client_step(c, 0) == OP2P_ESTATE);
    op2p_forward f = {.struct_size = sizeof(f),
                      .local_port = 0,
                      .peer_node = "other-client",
                      .destination_host = "127.0.0.1",
                      .destination_port = 22,
                      .protocol = "tcp",
                      .transport = OP2P_TRANSPORT_TCP};
    assert(op2p_client_add_forward(c, &f, NULL) == OP2P_EINVAL);
    op2p_client_destroy(c);
    /* Prime TLS process caches before checking repeated lifecycle FD ownership. */
    for (int i = 0; i < 20; ++i) {
        assert(op2p_client_create(&cfg, &c) == OP2P_OK);
        assert(op2p_client_start(c) == OP2P_OK);
        assert(op2p_client_step(c, 0) == OP2P_OK);
        assert(op2p_client_state(c) == OP2P_STOPPED);
        assert(op2p_client_stop(c) == OP2P_OK);
        op2p_client_destroy(c);
    }
    int before = fd_count();
    for (int i = 0; i < 20; ++i) {
        assert(op2p_client_create(&cfg, &c) == OP2P_OK);
        assert(op2p_client_start(c) == OP2P_OK);
        assert(op2p_client_step(c, 0) == OP2P_OK);
        op2p_client_destroy(c);
    }
    int after = fd_count();
    fprintf(stderr, "callback_count=%d fds_before=%d fds_after=%d\n", callback_count, before,
            after);
    assert(callback_count == 40 && after == before);
    const char *json = "{\"network\":{\"Node\":\"json-api-test\",\"Token\":18446744073709551615}}";
    assert(op2p_client_create_json(json, NULL, NULL, NULL, NULL, &c) == OP2P_OK);
    op2p_client_destroy(c);
    assert(op2p_client_create_json(json, "18446744073709551616", NULL, NULL, NULL, &c) ==
               OP2P_EINVAL &&
           !c);
    assert(op2p_client_create_json("{}", "1", NULL, NULL, NULL, &c) == OP2P_EINVAL && !c);
    assert(op2p_client_create_json("{", NULL, NULL, NULL, NULL, &c) == OP2P_EINVAL && !c);
    assert(op2p_client_create(&cfg, &c) == OP2P_OK);
    op2p_socks5 p = {.struct_size = sizeof(p),
                     .peer_node = "exit-client",
                     .local_port = 0,
                     .transport = OP2P_TRANSPORT_QUIC};
    assert(op2p_client_add_socks5(c, &p, NULL) == OP2P_EINVAL);
    p.local_port = 1080;
    p.username = "user";
    assert(op2p_client_add_socks5(c, &p, NULL) == OP2P_EINVAL);
    p.username = NULL;
    p.transport = 0;
    assert(op2p_client_add_socks5(c, &p, NULL) == OP2P_EINVAL);
    op2p_client_destroy(c);
    assert(op2p_client_create_json(
               "{\"network\":{\"Node\":\"json-api-test\",\"Token\":1},\"socks5\":{}}", NULL, NULL,
               NULL, NULL, &c) == OP2P_EINVAL &&
           !c);
    puts("ABI validation, callback stop and repeated lifecycle FD checks passed");
    return 0;
}
