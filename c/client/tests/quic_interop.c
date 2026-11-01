#include "platform.h"
#include "quic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/version.h>

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--dependencies")) {
        const ngtcp2_info *info = ngtcp2_version(0);
        printf("ngtcp2 header=%s runtime=%s settings_version=%d settings_size=%zu\n",
               NGTCP2_VERSION, info->version_str, NGTCP2_SETTINGS_VERSION, sizeof(ngtcp2_settings));
        return info->version_num == NGTCP2_VERSION_NUM ? 0 : 1;
    }
    if (argc != 5) {
        fprintf(stderr, "usage: quic-interop client|server IP PORT LOCAL_PORT\n");
        return 2;
    }
    if (op_platform_init())
        return 2;
    int server = !strcmp(argv[1], "server");
    op_socket fd = op_socket_open(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local = {.sin_family = AF_INET,
                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
                                .sin_port = htons((uint16_t)atoi(argv[4]))};
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons((uint16_t)atoi(argv[3]))};
    if (fd < 0 || inet_pton(AF_INET, argv[2], &peer.sin_addr) != 1 ||
        op_bind(fd, (struct sockaddr *)&local, sizeof(local)))
        return 2;
    op_socklen length = sizeof(local);
    op_getsockname(fd, (struct sockaddr *)&local, &length);
    printf("UDP_PORT=%u\n", ntohs(local.sin_port));
    fflush(stdout);
    opq *q = opq_new(fd, (struct sockaddr *)&peer, sizeof(peer), server);
    if (!q) {
        fprintf(stderr, "QUIC initialization failed\n");
        op_close(fd);
        return 1;
    }
    /* One real OpenP2P frame containing a tunnel ID, echoed verbatim. */
    uint8_t expected[] = {8, 0, 0, 0, 4, 0, 2, 0, 255, 254, 253, 252, 251, 250, 249, 248};
    if (!server && opq_write(q, expected, sizeof(expected)))
        return 1;
    uint8_t received[sizeof(expected)];
    size_t used = 0;
    time_t deadline = time(NULL) + 12;
    int success = 0;
    while (time(NULL) < deadline) {
        if (opq_step(q)) {
            fprintf(stderr, "%s\n", opq_error(q));
            break;
        }
        used += opq_read(q, received + used, sizeof(received) - used);
        if (used == sizeof(expected)) {
            if (memcmp(received, expected, sizeof(expected)))
                break;
            if (server) {
                opq_write(q, received, used);
                for (int i = 0; i < 100; ++i) {
                    if (opq_step(q))
                        break;
                    op_sleep_ms(1);
                }
            }
            success = 1;
            break;
        }
        op_pollfd pollfd = {.fd = fd, .events = POLLIN};
        op_poll(&pollfd, 1, 2);
    }
    if (success)
        puts("QUIC_INTEROP_OK ALPN=openp2pv1 frame_bytes=16");
    opq_free(q);
    op_close(fd);
    return success ? 0 : 1;
}
