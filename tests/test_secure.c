#include "secure.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint8_t secret[FP_SESSION_SECRET];
static const uint64_t initiator = UINT64_C(0x1122334455667788);
static const uint64_t responder = UINT64_C(0x8877665544332211);
static const uint64_t session = UINT64_C(0xdeadbeefcafef00d);

int main(void) {
    fp_crypto a, b;
    for (size_t i = 0; i < sizeof(secret); ++i)
        secret[i] = (uint8_t)(i * 7 + 3);
    assert(!fp_crypto_init(&a, secret, session, initiator, responder, 1));
    assert(!fp_crypto_init(&b, secret, session, initiator, responder, 0));

    const char *text = "{\"id\":7,\"dstIP\":\"10.0.0.1\",\"dstPort\":22}";
    uint8_t sealed[512], plain[512];
    size_t sealed_len = 0, plain_len = 0;

    /* Initiator to responder. */
    assert(!fp_seal(&a, 6, 42, text, strlen(text), sealed, sizeof(sealed), &sealed_len));
    assert(sealed_len == strlen(text) + 24);
    assert(!fp_open(&b, 6, 42, sealed, sealed_len, plain, sizeof(plain), &plain_len));
    assert(plain_len == strlen(text) && !memcmp(plain, text, plain_len));

    /* The same ciphertext replayed is rejected without breaking the session. */
    assert(fp_open(&b, 6, 42, sealed, sealed_len, plain, sizeof(plain), &plain_len) == -1);
    assert(!fp_seal(&a, 6, 43, "next", 4, sealed, sizeof(sealed), &sealed_len));
    assert(!fp_open(&b, 6, 43, sealed, sealed_len, plain, sizeof(plain), &plain_len));

    /* A different frame type or overlay is a different AAD. */
    assert(!fp_seal(&a, 9, 1, "payload", 7, sealed, sizeof(sealed), &sealed_len));
    assert(fp_open(&b, 6, 1, sealed, sealed_len, plain, sizeof(plain), &plain_len) == -2);
    fp_crypto_init(&b, secret, session, initiator, responder, 0);
    assert(fp_open(&b, 9, 2, sealed, sealed_len, plain, sizeof(plain), &plain_len) == -2);

    /* Tampering is fatal for the receiver and never yields plaintext. */
    fp_crypto_init(&b, secret, session, initiator, responder, 0);
    assert(!fp_seal(&a, 9, 1, "payload", 7, sealed, sizeof(sealed), &sealed_len));
    sealed[12] ^= 0x01;
    memset(plain, 0, sizeof(plain));
    assert(fp_open(&b, 9, 1, sealed, sealed_len, plain, sizeof(plain), &plain_len) == -2);
    assert(!plain[0] && !plain[1]);
    assert(b.broken);

    /* Truncated and oversized inputs are refused. */
    fp_crypto_init(&b, secret, session, initiator, responder, 0);
    assert(fp_open(&b, 9, 1, sealed, 10, plain, sizeof(plain), &plain_len) == -2);
    assert(fp_seal(&a, 9, 1, plain, 500, sealed, 64, &sealed_len) == -1);

    /* The reverse direction uses the other key and its own sequence space. */
    assert(!fp_seal(&b, 9, 5, "back", 4, sealed, sizeof(sealed), &sealed_len));
    assert(!fp_open(&a, 9, 5, sealed, sealed_len, plain, sizeof(plain), &plain_len));
    assert(plain_len == 4 && !memcmp(plain, "back", 4));

    /* Out-of-order delivery inside the replay window still succeeds. */
    fp_crypto_init(&a, secret, session, initiator, responder, 1);
    fp_crypto_init(&b, secret, session, initiator, responder, 0);
    uint8_t frames[4][512];
    size_t lengths[4];
    for (int i = 0; i < 4; ++i)
        assert(!fp_seal(&a, 9, 1, "x", 1, frames[i], sizeof(frames[i]), &lengths[i]));
    for (int i = 3; i >= 0; --i)
        assert(!fp_open(&b, 9, 1, frames[i], lengths[i], plain, sizeof(plain), &plain_len));
    /* A frame older than the window is dropped. */
    assert(fp_open(&b, 9, 1, frames[0], lengths[0], plain, sizeof(plain), &plain_len) == -1);

    /* A different secret or a different peer pair yields unrelated keys. */
    uint8_t other[FP_SESSION_SECRET];
    memcpy(other, secret, sizeof(other));
    other[0] ^= 0xff;
    fp_crypto_init(&a, other, session, initiator, responder, 1);
    fp_crypto_init(&b, secret, session, initiator, responder, 0);
    assert(!fp_seal(&a, 9, 1, "x", 1, sealed, sizeof(sealed), &sealed_len));
    assert(fp_open(&b, 9, 1, sealed, sealed_len, plain, sizeof(plain), &plain_len) == -2);
    fp_crypto_init(&a, secret, session, initiator, responder + 1, 1);
    fp_crypto_init(&b, secret, session, initiator, responder, 0);
    assert(!fp_seal(&a, 9, 1, "x", 1, sealed, sizeof(sealed), &sealed_len));
    assert(fp_open(&b, 9, 1, sealed, sealed_len, plain, sizeof(plain), &plain_len) == -2);

    /* Relay join proofs are bound to the session, the peer and the token. */
    uint8_t p1[16], p2[16], p3[16];
    fp_join_proof(UINT64_C(1234567890123456), session, initiator, p1);
    fp_join_proof(UINT64_C(1234567890123456), session, initiator, p2);
    fp_join_proof(UINT64_C(1234567890123456), session, responder, p3);
    assert(fp_equal(p1, p2, 16) && !fp_equal(p1, p3, 16));
    fp_join_proof(UINT64_C(1234567890123457), session, initiator, p2);
    assert(!fp_equal(p1, p2, 16));

    fp_crypto_clear(&a);
    fp_crypto_clear(&b);
    puts("session key derivation, AEAD sealing, replay window and join proofs passed");
    return 0;
}
