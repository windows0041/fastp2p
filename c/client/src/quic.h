#ifndef OP2P_QUIC_H
#define OP2P_QUIC_H
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/* One ordered bidirectional stream, ALPN openp2pv1. The caller owns the UDP
 * descriptor and must keep it bound for the lifetime of this object. Peer
 * certificates follow the existing Go peer transport's self-signed policy;
 * gateway TLS trust is a separate, verified connection. */
typedef struct opq opq;
opq *opq_new(int fd, const struct sockaddr *peer, socklen_t peer_len, int server);
int opq_step(opq *q);
int opq_write(opq *q, const void *data, size_t length);
size_t opq_read(opq *q, void *data, size_t capacity);
size_t opq_pending(const opq *q);
int opq_ready(const opq *q);
const char *opq_error(const opq *q);
void opq_free(opq *q);
#endif
