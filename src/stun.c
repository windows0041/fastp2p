#include "stun.h"
#include <stdio.h>
#include <string.h>

/* Wire layout: 20-byte header (type, length, magic cookie, 12-byte transaction),
 * then attributes of 4-byte aligned TLV. Values are big-endian. */
#define HEADER 20
#define BINDING_REQUEST 0x0001
#define BINDING_SUCCESS 0x0101
#define ATTR_MAPPED_ADDRESS 0x0001
#define ATTR_CHANGE_REQUEST 0x0003
#define ATTR_XOR_MAPPED_ADDRESS 0x0020
#define ATTR_OTHER_ADDRESS 0x802C

static void put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}
static void put32(uint8_t *p, uint32_t v) {
    put16(p, (uint16_t)(v >> 16));
    put16(p + 2, (uint16_t)v);
}
static uint16_t get16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }
static uint32_t get32(const uint8_t *p) {
    return ((uint32_t)get16(p) << 16) | get16(p + 2);
}

size_t fp_stun_request(uint8_t *out, size_t capacity, const uint8_t transaction[FP_STUN_NONCE],
                       int change_ip, int change_port) {
    if (!out || !transaction || capacity < HEADER + 8)
        return 0;
    /* One attribute: CHANGE-REQUEST carries two flag bits. A plain request (both
     * flags clear) is still sent as a request without the attribute, because old
     * servers reject unknown zero attributes. */
    int with_change = change_ip || change_port;
    size_t length = with_change ? 8 : 0;
    memset(out, 0, HEADER + length);
    put16(out, BINDING_REQUEST);
    put16(out + 2, (uint16_t)length);
    put32(out + 4, FP_STUN_MAGIC);
    memcpy(out + 8, transaction, FP_STUN_NONCE);
    if (with_change) {
        uint8_t *attr = out + HEADER;
        put16(attr, ATTR_CHANGE_REQUEST);
        put16(attr + 2, 4);
        /* 0x04 = change IP, 0x02 = change port (RFC 3489 §18.2). */
        uint32_t flags = 0;
        if (change_ip)
            flags |= 0x04u;
        if (change_port)
            flags |= 0x02u;
        put32(attr + 4, flags);
    }
    return HEADER + length;
}

/* Reads MAPPED-ADDRESS or XOR-MAPPED-ADDRESS into `address`. */
static int decode_address(const uint8_t *value, size_t length, int xored, op_addr *address) {
    if (length < 4)
        return -1;
    unsigned family = value[1];
    uint16_t port = get16(value + 2);
    if (xored)
        port = (uint16_t)(port ^ (uint16_t)(FP_STUN_MAGIC >> 16));
    const uint8_t *raw = value + 4;
    if (family == 0x01) {
        if (length < 8)
            return -1;
        uint8_t v4[4];
        if (xored) {
            uint8_t cookie[4];
            put32(cookie, FP_STUN_MAGIC);
            for (int i = 0; i < 4; ++i)
                v4[i] = (uint8_t)(raw[i] ^ cookie[i]);
        } else {
            memcpy(v4, raw, 4);
        }
        char text[OP_ADDR_TEXT];
        snprintf(text, sizeof(text), "%u.%u.%u.%u", v4[0], v4[1], v4[2], v4[3]);
        return op_addr_from_text(address, text, port);
    }
    if (family == 0x02) {
        if (length < 20)
            return -1;
        uint8_t v6[16];
        for (int i = 0; i < 16; ++i)
            v6[i] = raw[i];
        if (xored) {
            /* The key is magic cookie followed by the transaction ID; the caller
             * handed us a value that still needs it, so read it from the packet
             * header at parse time instead (see fp_stun_response). */
            return -1;
        }
        memset(address, 0, sizeof(*address));
        address->u.in6.sin6_family = AF_INET6;
        address->len = (op_socklen)sizeof(address->u.in6);
        memcpy(&address->u.in6.sin6_addr, v6, sizeof(v6));
        address->u.in6.sin6_port = htons(port);
        return 0;
    }
    return -1;
}

int fp_stun_response(const uint8_t *data, size_t length, const uint8_t transaction[FP_STUN_NONCE],
                     fp_stun_mapped *mapped) {
    if (!data || !transaction || !mapped || length < HEADER)
        return 0;
    if (get16(data) != BINDING_SUCCESS || get32(data + 4) != FP_STUN_MAGIC)
        return 0;
    if (memcmp(data + 8, transaction, FP_STUN_NONCE))
        return 0;
    size_t body = get16(data + 2);
    if (body + HEADER > length)
        return 0;
    memset(mapped, 0, sizeof(*mapped));
    fp_stun_mapped xored = {0};
    size_t offset = HEADER;
    while (offset + 4 <= HEADER + body) {
        uint16_t type = get16(data + offset);
        size_t size = get16(data + offset + 2);
        const uint8_t *value = data + offset + 4;
        if (offset + 4 + size > HEADER + body)
            break;
        if (type == ATTR_MAPPED_ADDRESS && !mapped->valid)
            mapped->valid = decode_address(value, size, 0, &mapped->address) == 0;
        if (type == ATTR_OTHER_ADDRESS && !mapped->has_alternate)
            mapped->has_alternate = decode_address(value, size, 0, &mapped->alternate) == 0;
        if (type == ATTR_XOR_MAPPED_ADDRESS && !xored.valid) {
            /* XOR-MAPPED-ADDRESS v4 is the common case; v6 needs the transaction
             * as part of the mask, which decode_address cannot see. */
            if (size >= 8 && value[1] == 0x01) {
                uint16_t port = (uint16_t)(get16(value + 2) ^ (uint16_t)(FP_STUN_MAGIC >> 16));
                uint8_t cookie[4], v4[4];
                put32(cookie, FP_STUN_MAGIC);
                for (int i = 0; i < 4; ++i)
                    v4[i] = (uint8_t)(value[4 + i] ^ cookie[i]);
                char text[OP_ADDR_TEXT];
                snprintf(text, sizeof(text), "%u.%u.%u.%u", v4[0], v4[1], v4[2], v4[3]);
                xored.valid = op_addr_from_text(&xored.address, text, port) == 0;
            }
        }
        offset += 4 + ((size + 3) & ~(size_t)3);
    }
    if (xored.valid) {
        /* The obfuscated attribute is authoritative for the mapping, but the
         * alternate address was parsed separately and must survive. */
        op_addr alternate = mapped->alternate;
        int has_alternate = mapped->has_alternate;
        *mapped = xored;
        mapped->alternate = alternate;
        mapped->has_alternate = has_alternate;
    }
    return mapped->valid;
}

