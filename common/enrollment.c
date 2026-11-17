#include "enrollment.h"
#include <errno.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int fastp2p_install_key_valid(const char *key) {
    if (!key || strlen(key) != 16 || key[0] < '1' || key[0] > '9') return 0;
    for (const char *p = key; *p; ++p) if (*p < '0' || *p > '9') return 0;
    return 1;
}

int fastp2p_enrollment_host_valid(const char *host) {
    size_t length = host ? strlen(host) : 0;
    if (!length || length > 253 || host[0] == '.' || host[0] == '-')
        return 0;
    for (const unsigned char *p = (const unsigned char *)host; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '-' || *p == '.' || *p == '_'))
            return 0;
    return 1;
}
static const char *string(json_object *root, const char *key) {
    json_object *value = NULL;
    if (!json_object_object_get_ex(root, key, &value) || !json_object_is_type(value, json_type_string))
        return NULL;
    const char *text = json_object_get_string(value);
    return text && strlen(text) == (size_t)json_object_get_string_len(value) ? text : NULL;
}
static int valid(json_object *root) {
    if (!root || !json_object_is_type(root, json_type_object))
        return 0;
    json_object *version = NULL, *port = NULL;
    const char *host = string(root, "host"), *key = string(root, "key"), *ca = string(root, "ca");
    if (!json_object_object_get_ex(root, "v", &version) || !json_object_is_type(version, json_type_int) ||
        json_object_get_int64(version) != 1 || !json_object_object_get_ex(root, "port", &port) ||
        !json_object_is_type(port, json_type_int) || json_object_get_int64(port) < 1 ||
        json_object_get_int64(port) > 65535 || !fastp2p_enrollment_host_valid(host) ||
        !fastp2p_install_key_valid(key) || !ca || strlen(ca) > 16384)
        return 0;
    for (const char *p = key; *p; ++p)
        if (*p < '0' || *p > '9')
            return 0;
    errno = 0;
    unsigned long long number = strtoull(key, NULL, 10);
    if (errno || !number)
        return 0;
    if (*ca) {
        if (strstr(ca, "PRIVATE KEY") || !strstr(ca, "-----BEGIN CERTIFICATE-----"))
            return 0;
        BIO *input = BIO_new_mem_buf(ca, -1);
        X509 *certificate = input ? PEM_read_bio_X509(input, NULL, NULL, NULL) : NULL;
        int ok = certificate != NULL;
        X509_free(certificate);
        BIO_free(input);
        if (!ok)
            return 0;
    }
    return 1;
}
char *fastp2p_enrollment_encode(const char *host, unsigned port, uint64_t key, const char *ca) {
    if (!host || !ca)
        return NULL;
    json_object *root = json_object_new_object();
    char number[32]; snprintf(number, sizeof(number), "%" PRIu64, key);
    json_object_object_add(root, "v", json_object_new_int(1));
    json_object_object_add(root, "host", json_object_new_string(host));
    json_object_object_add(root, "port", json_object_new_int64(port));
    json_object_object_add(root, "key", json_object_new_string(number));
    json_object_object_add(root, "ca", json_object_new_string(ca));
    if (!valid(root)) {
        json_object_put(root);
        return NULL;
    }
    const char *text = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    size_t length = strlen(text), encoded = 4 * ((length + 2) / 3);
    char *out = encoded + 5 <= FASTP2P_INSTALL_TOKEN_LIMIT ? malloc(encoded + 5) : NULL;
    if (out) {
        memcpy(out, "FP1.", 4);
        EVP_EncodeBlock((unsigned char *)out + 4, (const unsigned char *)text, (int)length);
        for (size_t i = 4; i < encoded + 4; ++i) {
            if (out[i] == '+') out[i] = '-';
            if (out[i] == '/') out[i] = '_';
        }
        while (encoded && out[encoded + 3] == '=') --encoded;
        out[encoded + 4] = 0;
    }
    json_object_put(root);
    return out;
}
json_object *fastp2p_enrollment_decode(const char *token) {
    size_t length = token ? strlen(token) : 0;
    if (length < 8 || length > FASTP2P_INSTALL_TOKEN_LIMIT || strncmp(token, "FP1.", 4))
        return NULL;
    token += 4; length -= 4;
    if (length % 4 == 1)
        return NULL;
    size_t padded = (length + 3) / 4 * 4;
    char *input = malloc(padded + 1);
    unsigned char *decoded = malloc(padded + 1);
    if (!input || !decoded) { free(input); free(decoded); return NULL; }
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)token[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) {
            free(input); free(decoded); return NULL;
        }
        input[i] = c == '-' ? '+' : c == '_' ? '/' : (char)c;
    }
    memset(input + length, '=', padded - length); input[padded] = 0;
    int size = EVP_DecodeBlock(decoded, (const unsigned char *)input, (int)padded);
    free(input);
    if (size <= 0) { free(decoded); return NULL; }
    size -= (int)(padded - length);
    json_tokener *parser = json_tokener_new();
    if (!parser) { free(decoded); return NULL; }
    json_tokener_set_flags(parser, JSON_TOKENER_STRICT);
    json_object *root = json_tokener_parse_ex(parser, (const char *)decoded, size);
    int ok = json_tokener_get_error(parser) == json_tokener_success &&
             json_tokener_get_parse_end(parser) == (size_t)size && valid(root);
    json_tokener_free(parser);
    OPENSSL_cleanse(decoded, padded + 1); free(decoded);
    if (!ok) { if (root) json_object_put(root); return NULL; }
    return root;
}
