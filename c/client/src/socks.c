#include "socks.h"
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>

void op_socks_reply(uint8_t out[10], unsigned status, const uint8_t ip[4], uint16_t port) {
    memset(out, 0, 10);
    out[0] = 5;
    out[1] = (uint8_t)status;
    out[3] = 1;
    if (ip)
        memcpy(out + 4, ip, 4);
    out[8] = (uint8_t)(port >> 8);
    out[9] = (uint8_t)port;
}
int op_socks_address(const uint8_t *p, size_t n, char host[256], uint16_t *port) {
    if (!n)
        return 0;
    size_t end;
    if (p[0] == 1) {
        end = 5;
        if (n < end + 2)
            return 0;
        snprintf(host, 256, "%u.%u.%u.%u", p[1], p[2], p[3], p[4]);
    } else if (p[0] == 3) {
        if (n < 2)
            return 0;
        if (!p[1])
            return -1;
        end = 2 + p[1];
        if (n < end + 2)
            return 0;
        for (size_t i = 2; i < end; ++i)
            if (p[i] <= 32 || p[i] >= 127 || p[i] == ':' || p[i] == '/' || p[i] == '\\')
                return -1;
        memcpy(host, p + 2, p[1]);
        host[p[1]] = 0;
    } else
        return -1;
    *port = (uint16_t)((unsigned)p[end] << 8 | p[end + 1]);
    return (int)(end + 2);
}
int op_socks_step(op_socks *s, const uint8_t *p, size_t n, size_t *used, const char *user,
                  const char *password, uint8_t out[10], size_t *out_len) {
    *used = *out_len = 0;
    if (s->state == SOCKS_GREETING) {
        if (n < 2)
            return 0;
        if (p[0] != 5 || !p[1])
            return -1;
        if (n < (size_t)p[1] + 2)
            return 0;
        unsigned method = *user ? 2 : 0;
        int found = 0;
        for (unsigned i = 0; i < p[1]; ++i)
            if (p[i + 2] == method)
                found = 1;
        out[0] = 5;
        out[1] = found ? (uint8_t)method : 255;
        *out_len = 2;
        *used = (size_t)p[1] + 2;
        s->state = method ? SOCKS_AUTH : SOCKS_REQUEST;
        return found ? 1 : -1;
    }
    if (s->state == SOCKS_AUTH) {
        if (n < 2)
            return 0;
        if (p[0] != 1 || !p[1])
            return -1;
        size_t ulen = p[1], plen_offset = 2 + ulen;
        if (n <= plen_offset)
            return 0;
        size_t plen = p[plen_offset], total = plen_offset + 1 + plen;
        if (n < total)
            return 0;
        int ok = plen && strlen(user) == ulen && strlen(password) == plen &&
                 !CRYPTO_memcmp(p + 2, user, ulen) &&
                 !CRYPTO_memcmp(p + plen_offset + 1, password, plen);
        out[0] = 1;
        out[1] = ok ? 0 : 1;
        *out_len = 2;
        *used = total;
        s->state = SOCKS_REQUEST;
        return ok ? 1 : -1;
    }
    if (s->state == SOCKS_REQUEST) {
        if (n < 4)
            return 0;
        unsigned failure = 0;
        if (p[0] != 5 || p[2])
            failure = 1;
        else if (p[1] != 1 && p[1] != 3)
            failure = 7;
        else {
            int length = op_socks_address(p + 3, n - 3, s->host, &s->port);
            if (!length)
                return 0;
            if (length < 0)
                failure = 8;
            else if (p[1] == 1 && !s->port)
                failure = 1;
            else {
                s->command = p[1];
                s->state = SOCKS_TARGET;
                *used = 3 + (size_t)length;
                return 2;
            }
        }
        op_socks_reply(out, failure, NULL, 0);
        *out_len = 10;
        return -1;
    }
    return -1;
}
