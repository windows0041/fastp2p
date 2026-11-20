#ifndef FASTP2P_SOCKS_H
#define FASTP2P_SOCKS_H
#include <stddef.h>
#include <stdint.h>
#include "platform.h"
#define OP_SOCKS_MAX_REPLY 22
enum { SOCKS_GREETING = 1, SOCKS_AUTH, SOCKS_REQUEST, SOCKS_TARGET };
typedef struct {
    int state, command;
    char host[256];
    uint16_t port;
} op_socks;
/* Incremental handshake: 0=incomplete, 1=progress, 2=target, -1=reply then close. */
int op_socks_step(op_socks *s, const uint8_t *data, size_t len, size_t *consumed,
                  const char *username, const char *password, uint8_t reply[OP_SOCKS_MAX_REPLY], size_t *reply_len);
/* Address starts at ATYP; 0=incomplete, -1=invalid, otherwise encoded length. */
int op_socks_address(const uint8_t *data, size_t len, char host[256], uint16_t *port);
/* Encode a reply and return its length (10 or 22 bytes). */
size_t op_socks_reply(uint8_t reply[OP_SOCKS_MAX_REPLY], unsigned status, const op_addr *address);
#endif
