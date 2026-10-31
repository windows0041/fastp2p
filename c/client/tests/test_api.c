#include "openp2p.h"
#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
    DIR *d = opendir("/proc/self/fd");
    assert(d);
    int n = 0;
    struct dirent *entry;
    while ((entry = readdir(d)))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
            ++n;
    closedir(d);
    return n;
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
    if (after != before) {
        for (int fd = 3; fd < 80; ++fd) {
            char path[64], target[256];
            snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
            ssize_t count = readlink(path, target, sizeof(target) - 1);
            if (count > 0) {
                target[count] = 0;
                fprintf(stderr, "fd=%d target=%s\n", fd, target);
            }
            struct sockaddr_storage a;
            socklen_t n = sizeof(a);
            if (!getsockname(fd, (struct sockaddr *)&a, &n))
                fprintf(stderr, "fd=%d family=%d port=%u\n", fd, a.ss_family,
                        a.ss_family == AF_INET ? ntohs(((struct sockaddr_in *)&a)->sin_port) : 0);
        }
    }
    assert(callback_count == 40 && after == before);
    puts("ABI validation, callback stop and repeated lifecycle FD checks passed");
    return 0;
}
