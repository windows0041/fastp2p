#include "secure.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Sealed tunnel body: [u64 big-endian sequence][ciphertext][16-byte tag].
 * The sequence is public; it selects the nonce and drives replay detection.
 * Only a valid tag lets the receiver advance its window. */
#define SEAL_HEADER 8

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v = (v << 8) | p[i];
    return v;
}
void fp_random(void *out, size_t len) {
    if (len > 2147483647u || RAND_bytes(out, (int)len) != 1)
        abort();
}
int fp_equal(const void *a, const void *b, size_t len) {
    return CRYPTO_memcmp(a, b, len) == 0;
}
static int hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                       uint8_t out[32]) {
    unsigned length = 0;
    if (!HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &length) || length != 32)
        return -1;
    return 0;
}
/* RFC 5869 extract, then one 32-byte expand block (T(1) only, info <= 64). */
static int hkdf(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                const char *info, uint8_t out[32]) {
    uint8_t prk[32], block[65];
    size_t info_len = strlen(info);
    if (info_len > 64)
        return -1;
    if (hmac_sha256(salt, salt_len, ikm, ikm_len, prk))
        return -1;
    memcpy(block, info, info_len);
    block[info_len] = 1;
    int rv = hmac_sha256(prk, sizeof(prk), block, info_len + 1, out);
    OPENSSL_cleanse(prk, sizeof(prk));
    OPENSSL_cleanse(block, sizeof(block));
    return rv;
}
int fp_crypto_init(fp_crypto *c, const uint8_t secret[FP_SESSION_SECRET], uint64_t session,
                   uint64_t initiator_id, uint64_t responder_id, int local_initiator) {
    uint8_t salt[24], a2b[32], b2a[32];
    memset(c, 0, sizeof(*c));
    if (!secret)
        return -1;
    put64(salt, session);
    put64(salt + 8, initiator_id);
    put64(salt + 16, responder_id);
    int rv = hkdf(salt, sizeof(salt), secret, FP_SESSION_SECRET, "fastp2p2 a2b", a2b);
    if (!rv)
        rv = hkdf(salt, sizeof(salt), secret, FP_SESSION_SECRET, "fastp2p2 b2a", b2a);
    if (!rv) {
        memcpy(c->tx, local_initiator ? a2b : b2a, 32);
        memcpy(c->rx, local_initiator ? b2a : a2b, 32);
    }
    if (getenv("FP_DEBUG_KEYS"))
        fprintf(stderr, "crypto session=%016llx init=%016llx resp=%016llx local=%d\n",
                (unsigned long long)session, (unsigned long long)initiator_id,
                (unsigned long long)responder_id, local_initiator);
    OPENSSL_cleanse(a2b, sizeof(a2b));
    OPENSSL_cleanse(b2a, sizeof(b2a));
    return rv;
}
void fp_crypto_clear(fp_crypto *c) {
    if (c)
        OPENSSL_cleanse(c, sizeof(*c));
}
static void make_aad(uint8_t aad[FP_AAD], uint16_t sub, uint64_t overlay) {
    aad[0] = (uint8_t)(sub >> 8);
    aad[1] = (uint8_t)sub;
    put64(aad + 2, overlay);
}
static int gcm(int encrypt, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad,
               const uint8_t *in, size_t len, uint8_t *out, uint8_t tag[FP_TAG]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, tail = 0, ok = 0;
    if (!ctx || len > 2147483647u)
        goto done;
    if (!EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL, encrypt) ||
        !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) ||
        !EVP_CipherInit_ex(ctx, NULL, NULL, key, nonce, encrypt))
        goto done;
    if (!EVP_CipherUpdate(ctx, NULL, &n, aad, FP_AAD) ||
        !EVP_CipherUpdate(ctx, out, &n, in, (int)len))
        goto done;
    if (encrypt) {
        if (!EVP_CipherFinal_ex(ctx, out + n, &tail) ||
            !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, FP_TAG, tag))
            goto done;
    } else if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, FP_TAG, (void *)tag) ||
               !EVP_CipherFinal_ex(ctx, out + n, &tail)) {
        goto done;
    }
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}
static int replay_ok(const fp_crypto *c, uint64_t seq) {
    if (!c->rx_started || seq > c->rx_max)
        return 1;
    uint64_t delta = c->rx_max - seq;
    return delta < 64 && !(c->rx_seen & (UINT64_C(1) << delta));
}
static void replay_mark(fp_crypto *c, uint64_t seq) {
    if (!c->rx_started) {
        c->rx_started = 1;
        c->rx_max = seq;
        c->rx_seen = 1;
        return;
    }
    if (seq > c->rx_max) {
        uint64_t shift = seq - c->rx_max;
        c->rx_seen = shift >= 64 ? 0 : c->rx_seen << shift;
        c->rx_seen |= 1;
        c->rx_max = seq;
    } else {
        c->rx_seen |= UINT64_C(1) << (c->rx_max - seq);
    }
}
int fp_seal(fp_crypto *c, uint16_t sub, uint64_t overlay, const void *in, size_t len, uint8_t *out,
            size_t capacity, size_t *written) {
    uint8_t nonce[12] = {0}, aad[FP_AAD];
    if (!c || c->broken || c->tx_seq == UINT64_MAX || capacity < len + SEAL_HEADER + FP_TAG)
        return -1;
    put64(out, c->tx_seq);
    put64(nonce + 4, c->tx_seq);
    make_aad(aad, sub, overlay);
    if (gcm(1, c->tx, nonce, aad, in, len, out + SEAL_HEADER, out + SEAL_HEADER + len)) {
        c->broken = 1;
        return -1;
    }
    ++c->tx_seq;
    *written = len + SEAL_HEADER + FP_TAG;
    return 0;
}
/* Returns 0 on success, -1 for a duplicate/stale frame (drop it), and -2 when
 * authentication fails (the tunnel must be torn down). */
int fp_open(fp_crypto *c, uint16_t sub, uint64_t overlay, const void *in, size_t len, uint8_t *out,
            size_t capacity, size_t *written) {
    uint8_t nonce[12] = {0}, aad[FP_AAD];
    if (!c || c->broken || len < SEAL_HEADER + FP_TAG)
        return -2;
    const uint8_t *p = in;
    size_t body = len - SEAL_HEADER - FP_TAG;
    if (capacity < body)
        return -2;
    uint64_t seq = get64(p);
    if (!replay_ok(c, seq))
        return -1;
    put64(nonce + 4, seq);
    make_aad(aad, sub, overlay);
    if (gcm(0, c->rx, nonce, aad, p + SEAL_HEADER, body, out, (uint8_t *)p + len - FP_TAG)) {
        /* GCM releases plaintext before the tag is checked; never let a caller
         * observe unauthenticated bytes. */
        OPENSSL_cleanse(out, body);
        c->broken = 1;
        return -2;
    }
    replay_mark(c, seq);
    *written = body;
    return 0;
}
void fp_join_proof(const uint64_t token, uint64_t session, uint64_t peer, uint8_t out[16]) {
    uint8_t key[32], message[16], digest[32], token_bytes[8];
    put64(token_bytes, token);
    static const char relay_salt[] = "fastp2p2 relay";
    if (hkdf((const uint8_t *)relay_salt, sizeof(relay_salt) - 1, token_bytes, sizeof(token_bytes),
             "join proof",
             key)) {
        memset(out, 0, 16);
        return;
    }
    put64(message, session);
    put64(message + 8, peer);
    if (hmac_sha256(key, sizeof(key), message, sizeof(message), digest))
        memset(out, 0, 16);
    else
        memcpy(out, digest, 16);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(digest, sizeof(digest));
}
