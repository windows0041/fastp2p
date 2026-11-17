#ifndef FASTP2P_STUN_H
#define FASTP2P_STUN_H
#include "platform.h"
#include <stddef.h>
#include <stdint.h>

/* Minimal STUN (RFC 5389) client pieces plus the RFC 3489 CHANGE-REQUEST
 * attribute. Only what NAT classification needs: ask a server for our mapped
 * address, and ask it to answer from a different address or port so the inbound
 * filter of the NAT in front of us becomes observable. */
#define FP_STUN_MAGIC 0x2112A442u
#define FP_STUN_MAX_SERVERS 4
#define FP_STUN_NONCE 12

/* Mapped endpoint a server reported for us. */
typedef struct {
    op_addr address;
    int valid;
    /* RFC 5780 OTHER-ADDRESS: the server's alternate address, which it uses to
     * answer change-ip requests. A server that advertises one is declaring that
     * it implements the NAT-behaviour extension, so a missing reply to our
     * change-ip probe becomes evidence of filtering rather than of an
     * unsupported attribute. */
    op_addr alternate;
    int has_alternate;
} fp_stun_mapped;

/* Builds a BINDING request. change_ip/change_port set CHANGE-REQUEST so a
 * compliant server answers from another address / port. Returns length, 0 on
 * bad arguments. */
size_t fp_stun_request(uint8_t *out, size_t capacity, const uint8_t transaction[FP_STUN_NONCE],
                       int change_ip, int change_port);

/* Parses a BINDING success response. Returns 1 on success (mapped filled),
 * 0 when the bytes are not a valid response for this transaction. */
int fp_stun_response(const uint8_t *data, size_t length, const uint8_t transaction[FP_STUN_NONCE],
                     fp_stun_mapped *mapped);
#endif
