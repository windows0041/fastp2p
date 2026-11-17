#include "platform.h"
#ifndef FASTP2P_QUIC_H
#define FASTP2P_QUIC_H
#include <stddef.h>
#include <stdint.h>

/* One ordered bidirectional stream, ALPN fastp2pv2. The caller owns the UDP
 * descriptor and must keep it bound for the lifetime of this object.  Each
 * process presents one self-signed EC certificate; TLS proves the peer holds
 * the key it presented, and the tunnel confirms the exact certificate through
 * an end-to-end check after the handshake. */
typedef struct opq opq;
opq *opq_new(op_socket fd, const struct sockaddr *peer, op_socklen peer_len, int server);
int opq_step(opq *q);
int opq_write(opq *q, const void *data, size_t length);
size_t opq_read(opq *q, void *data, size_t capacity);
size_t opq_pending(const opq *q);
int opq_ready(const opq *q);
/* SHA-256 of the certificate the peer presented, and of this process identity. */
int opq_peer_digest(opq *q, uint8_t out[32]);
int opq_identity_digest(uint8_t out[32]);
const char *opq_error(const opq *q);
void opq_free(opq *q);
#endif
