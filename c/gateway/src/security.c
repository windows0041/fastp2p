#include "protocol.h"
#include <inttypes.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int gw_secret_equal(const char *a, const char *b) {
    size_t n = strlen(a);
    return n == strlen(b) && CRYPTO_memcmp(a, b, n) == 0;
}
uint64_t gw_totp(uint64_t token, uint64_t ts) {
    uint8_t key[8], step[8], digest[32];
    unsigned length = 0;
    gw_put64(key, token);
    gw_put64(step, ts / 30);
    if (!HMAC(EVP_sha256(), key, 8, step, 8, digest, &length) || length != 32)
        return 0;
    return gw_u64(digest);
}
int gw_token_valid(uint64_t code, uint64_t token, uint64_t ts) {
    return code &&
           (code == token || code == gw_totp(token, ts) ||
            code == gw_totp(token, ts >= 30 ? ts - 30 : 0) || code == gw_totp(token, ts + 30));
}
static char *b64(const void *data, size_t length) {
    if (length > 8192)
        return NULL;
    size_t n = 4 * ((length + 2) / 3);
    char *out = malloc(n + 1);
    if (!out)
        return NULL;
    EVP_EncodeBlock((unsigned char *)out, data, (int)length);
    for (size_t i = 0; i < n; ++i) {
        if (out[i] == '+')
            out[i] = '-';
        else if (out[i] == '/')
            out[i] = '_';
    }
    while (n && out[n - 1] == '=')
        --n;
    out[n] = 0;
    return out;
}
static json_object *unb64_json(const char *text, size_t length) {
    if (!length || length > 4096 || length % 4 == 1)
        return NULL;
    size_t padded = (length + 3) / 4 * 4;
    char in[4100];
    uint8_t out[4100];
    for (size_t i = 0; i < length; ++i) {
        char c = text[i];
        if (c == '-')
            c = '+';
        else if (c == '_')
            c = '/';
        else if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))
            return NULL;
        in[i] = c;
    }
    for (size_t i = length; i < padded; ++i)
        in[i] = '=';
    in[padded] = 0;
    int n = EVP_DecodeBlock(out, (unsigned char *)in, (int)padded);
    if (n < 0)
        return NULL;
    return gw_json(out, (size_t)n - (padded - length));
}
static char *signature(const char *data, size_t n, const char *secret) {
    unsigned length = 0;
    uint8_t hash[32];
    if (!HMAC(EVP_sha256(), secret, (int)strlen(secret), (const uint8_t *)data, n, hash, &length) ||
        length != 32)
        return NULL;
    return b64(hash, 32);
}
char *gw_jwt_issue(const char *user, uint64_t token, const char *secret, uint64_t now) {
    char number[32];
    snprintf(number, sizeof(number), "%" PRIu64, token);
    json_object *j = json_object_new_object();
    if (!j)
        return NULL;
    gw_js(j, "user", user);
    gw_js(j, "installToken", number);
    gw_js(j, "iss", "fastp2p.cn");
    gw_ju(j, "iat", now);
    gw_ju(j, "exp", now + 86400);
    const char *text = json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN);
    char *body = b64(text, strlen(text));
    json_object_put(j);
    if (!body)
        return NULL;
    const char *head = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    size_t n = strlen(head) + 1 + strlen(body);
    char *result = malloc(n + 1 + 43 + 1);
    if (!result) {
        free(body);
        return NULL;
    }
    snprintf(result, n + 1, "%s.%s", head, body);
    free(body);
    char *sig = signature(result, n, secret);
    if (!sig) {
        free(result);
        return NULL;
    }
    result[n] = '.';
    memcpy(result + n + 1, sig, 44);
    free(sig);
    return result;
}
int gw_jwt_verify(const char *text, const char *user, uint64_t token, const char *secret,
                  uint64_t now) {
    if (!text || strlen(text) > 8192)
        return 0;
    if (!strncmp(text, "Bearer ", 7))
        text += 7;
    const char *dot = strchr(text, '.'), *last = dot ? strchr(dot + 1, '.') : NULL;
    if (!dot || !last || strchr(last + 1, '.') || strlen(last + 1) != 43)
        return 0;
    char *sig = signature(text, (size_t)(last - text), secret);
    if (!sig)
        return 0;
    int ok = gw_secret_equal(sig, last + 1);
    free(sig);
    if (!ok)
        return 0;
    json_object *head = unb64_json(text, (size_t)(dot - text));
    json_object *claims = unb64_json(dot + 1, (size_t)(last - dot - 1));
    uint64_t installation = 0;
    ok = head && claims && !strcmp(gw_string(head, "alg"), "HS256") &&
         gw_secret_equal(gw_string(claims, "user"), user) &&
         !strcmp(gw_string(claims, "iss"), "fastp2p.cn") &&
         !gw_decimal(gw_string(claims, "installToken"), &installation) && installation == token &&
         gw_integer(claims, "exp") > now && gw_integer(claims, "nbf") <= now &&
         gw_integer(claims, "iat") <= now + 30;
    if (head)
        json_object_put(head);
    if (claims)
        json_object_put(claims);
    return ok;
}
