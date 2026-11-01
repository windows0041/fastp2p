#include "platform.h"
/* ngtcp2 integration follows ngtcp2's MIT-licensed public examples.
 * See THIRD_PARTY.md for their copyright and license. */
#include "quic.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#define QLIMIT (4u * 1024u * 1024u)
struct qchunk {
    struct qchunk *next;
    uint64_t offset;
    size_t len, sent;
    uint8_t data[];
};
struct opq {
    ngtcp2_crypto_conn_ref ref;
    ngtcp2_conn *conn;
    SSL_CTX *tls_context;
    SSL *tls;
    ngtcp2_crypto_ossl_ctx *native_tls;
    op_socket fd;
    int server, failed, ready;
    int64_t stream;
    struct sockaddr_storage local, peer;
    op_socklen local_len, peer_len;
    struct qchunk *head, *tail;
    uint64_t next_offset;
    size_t pending, rxlen, rxcap;
    uint8_t *rx;
    uint8_t blocked_packet[1500];
    size_t blocked_len;
    char error[160];
};
static uint64_t now_ns(void) {
    return op_monotonic_ns();
}
static int fail(opq *q, const char *message, int code) {
    snprintf(q->error, sizeof(q->error), "%s: %s", message,
             code ? ngtcp2_strerror(code) : strerror(errno));
    q->failed = 1;
    return -1;
}
static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *ref) {
    return ((opq *)ref->user_data)->conn;
}
static int qrandom(uint8_t *data, size_t len) {
    return len > INT_MAX || RAND_bytes(data, (int)len) != 1 ? -1 : 0;
}
static void random_bytes(uint8_t *dst, size_t len, const ngtcp2_rand_ctx *ctx) {
    (void)ctx;
    /* GnuTLS uses the OS CSPRNG; an unavailable RNG is fatal, never predictable. */
    if (qrandom(dst, len))
        abort();
}
static int new_cid(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token, size_t len, void *user) {
    (void)conn;
    (void)user;
    cid->datalen = len;
    if (qrandom(cid->data, len) || qrandom(token, NGTCP2_STATELESS_RESET_TOKENLEN))
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}
static int handshake_done(ngtcp2_conn *conn, void *user) {
    (void)conn;
    ((opq *)user)->ready = 1;
    return 0;
}
static int receive_stream(ngtcp2_conn *conn, uint32_t flags, int64_t sid, uint64_t offset,
                          const uint8_t *data, size_t len, void *user, void *stream_user) {
    opq *q = user;
    (void)offset;
    (void)stream_user;
    if (sid != 0 || (flags & NGTCP2_STREAM_DATA_FLAG_0RTT) || len > QLIMIT - q->rxlen)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    q->stream = sid;
    if (q->rxlen + len > q->rxcap) {
        size_t cap = q->rxlen + len;
        uint8_t *p = realloc(q->rx, cap);
        if (!p)
            return NGTCP2_ERR_CALLBACK_FAILURE;
        q->rx = p;
        q->rxcap = cap;
    }
    if (len)
        memcpy(q->rx + q->rxlen, data, len);
    q->rxlen += len;
    /* Flow-control credit is returned from opq_read once the tunnel has taken
     * the bytes, so a slow consumer backpressures the peer instead of tripping
     * the buffer limit and tearing the tunnel down. */
    (void)conn;
    return 0;
}
static int acknowledged(ngtcp2_conn *conn, int64_t sid, uint64_t offset, uint64_t len, void *user,
                        void *stream_user) {
    opq *q = user;
    (void)conn;
    (void)sid;
    (void)stream_user;
    while (q->head && q->head->offset + q->head->len <= offset + len) {
        struct qchunk *p = q->head;
        q->head = p->next;
        q->pending -= p->len;
        free(p);
    }
    if (!q->head)
        q->tail = NULL;
    return 0;
}
/* One self-signed identity per process.  The key is EC P-256 so generating it
 * costs microseconds rather than the ~100 ms an RSA-2048 keygen takes, and it
 * satisfies the default OpenSSL security level.  The certificate is only a
 * transport credential: a self-signed certificate cannot be validated by a CA,
 * so peers confirm the exact certificate they saw through the sealed tunnel
 * (TUN_CERT_BIND) instead of trusting the TLS layer for identity. */
typedef struct {
    int ready, failed;
    uint8_t digest[32];
    EVP_PKEY *key;
    X509 *cert;
} fp_identity;
static fp_identity identity;
static op_once identity_once = OP_ONCE_INIT;
static void identity_init(void) {
    EVP_PKEY_CTX *generator = NULL;
    BIGNUM *serial = NULL;
    uint8_t bytes[16];
    unsigned length = 0;
    if (qrandom(bytes, sizeof(bytes)))
        goto done;
    generator = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    identity.cert = X509_new();
    if (!generator || !identity.cert || EVP_PKEY_keygen_init(generator) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(generator, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(generator, &identity.key) <= 0 || !X509_set_version(identity.cert, 2))
        goto done;
    serial = BN_bin2bn(bytes, sizeof(bytes), NULL);
    if (!serial || !BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(identity.cert)) ||
        !X509_gmtime_adj(X509_getm_notBefore(identity.cert), -60) ||
        !X509_gmtime_adj(X509_getm_notAfter(identity.cert), 7 * 86400) ||
        !X509_set_pubkey(identity.cert, identity.key))
        goto done;
    X509_NAME *name = X509_get_subject_name(identity.cert);
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"fastp2p", -1,
                                    -1, 0) ||
        !X509_set_issuer_name(identity.cert, name) ||
        !X509_sign(identity.cert, identity.key, EVP_sha256()) ||
        !X509_digest(identity.cert, EVP_sha256(), identity.digest, &length) || length != 32)
        goto done;
    identity.ready = 1;
done:
    BN_free(serial);
    EVP_PKEY_CTX_free(generator);
    if (!identity.ready) {
        X509_free(identity.cert);
        EVP_PKEY_free(identity.key);
        identity.cert = NULL;
        identity.key = NULL;
        identity.failed = 1;
    }
}
static fp_identity *get_identity(void) {
    op_once_run(&identity_once, identity_init);
    return identity.ready ? &identity : NULL;
}
/* Any certificate is accepted here: identity is confirmed end to end after the
 * handshake, and a CA chain says nothing about a peer that generated its key at
 * start-up.  TLS still proves the peer holds the key it presented. */
static int accept_any_certificate(int preverify_ok, X509_STORE_CTX *ctx) {
    (void)preverify_ok;
    (void)ctx;
    return 1;
}
static int select_alpn(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *argument) {
    (void)ssl;
    (void)argument;
    static const unsigned char protocol[] = "\x09" "fastp2pv2";
    unsigned char *selected = NULL;
    if (SSL_select_next_proto(&selected, outlen, protocol, sizeof(protocol) - 1, in, inlen) !=
        OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    *out = selected;
    return SSL_TLSEXT_ERR_OK;
}
static int init_conn(opq *q, const ngtcp2_pkt_hd *first) {
    ngtcp2_callbacks cb = {
        .client_initial = ngtcp2_crypto_client_initial_cb,
        .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
        .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
        .handshake_completed = handshake_done,
        .recv_stream_data = receive_stream,
        .acked_stream_data_offset = acknowledged,
        .encrypt = ngtcp2_crypto_encrypt_cb,
        .decrypt = ngtcp2_crypto_decrypt_cb,
        .hp_mask = ngtcp2_crypto_hp_mask_cb,
        .recv_retry = ngtcp2_crypto_recv_retry_cb,
        .rand = random_bytes,
        .get_new_connection_id = new_cid,
        .update_key = ngtcp2_crypto_update_key_cb,
        .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
        .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
    };
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_cid dcid, scid;
    ngtcp2_path path = {{(struct sockaddr *)&q->local, q->local_len},
                        {(struct sockaddr *)&q->peer, q->peer_len},
                        NULL};
    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_ns();
    settings.no_pmtud = 1;
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi = 1;
    params.initial_max_stream_data_bidi_local = QLIMIT;
    params.initial_max_stream_data_bidi_remote = QLIMIT;
    params.initial_max_data = QLIMIT;
    params.max_idle_timeout = 60 * NGTCP2_SECONDS;
    scid.datalen = 16;
    if (qrandom(scid.data, scid.datalen))
        return -1;
    int rv;
    if (q->server) {
        dcid = first->scid;
        params.original_dcid = first->dcid;
        params.original_dcid_present = 1;
        rv = ngtcp2_conn_server_new(&q->conn, &dcid, &scid, &path, first->version, &cb, &settings,
                                    &params, NULL, q);
    } else {
        dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
        if (qrandom(dcid.data, dcid.datalen))
            return -1;
        rv = ngtcp2_conn_client_new(&q->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, &cb,
                                    &settings, &params, NULL, q);
    }
    if (rv)
        return fail(q, "QUIC connection", rv);
    ngtcp2_conn_set_tls_native_handle(q->conn, q->native_tls);
    return 0;
}
opq *opq_new(op_socket fd, const struct sockaddr *peer, op_socklen peer_len, int server) {
    if ((size_t)peer_len > sizeof(struct sockaddr_storage))
        return NULL;
    opq *q = calloc(1, sizeof(*q));
    if (!q)
        return NULL;
    q->fd = fd;
    q->server = server;
    q->stream = -1;
    q->peer_len = peer_len;
    memcpy(&q->peer, peer, peer_len);
    q->local_len = sizeof(q->local);
    q->ref.get_conn = get_conn;
    q->ref.user_data = q;
    if (op_getsockname(fd, (struct sockaddr *)&q->local, &q->local_len))
        goto error;
    fp_identity *id = get_identity();
    if (!id)
        goto error;
    q->tls_context = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (!q->tls_context || !SSL_CTX_set_min_proto_version(q->tls_context, TLS1_3_VERSION))
        goto error;
    /* Both sides present the process identity and accept any certificate here;
     * the peer's exact certificate is confirmed after the handshake through the
     * sealed tunnel, which is authenticated by the gateway-delivered secret. */
    SSL_CTX_set_verify(q->tls_context, SSL_VERIFY_PEER, accept_any_certificate);
    if (SSL_CTX_use_certificate(q->tls_context, id->cert) != 1 ||
        SSL_CTX_use_PrivateKey(q->tls_context, id->key) != 1)
        goto error;
    if (server)
        SSL_CTX_set_alpn_select_cb(q->tls_context, select_alpn, NULL);
    q->tls = SSL_new(q->tls_context);
    if (!q->tls || ngtcp2_crypto_ossl_ctx_new(&q->native_tls, q->tls))
        goto error;
    SSL_set_app_data(q->tls, &q->ref);
    if (server) {
        SSL_set_accept_state(q->tls);
        if (ngtcp2_crypto_ossl_configure_server_session(q->tls))
            goto error;
    } else {
        SSL_set_connect_state(q->tls);
        static const unsigned char alpn[] = "\x09" "fastp2pv2";
        if (SSL_set_alpn_protos(q->tls, alpn, sizeof(alpn) - 1) ||
            ngtcp2_crypto_ossl_configure_client_session(q->tls))
            goto error;
    }
    if (!server && init_conn(q, NULL))
        goto error;
    return q;
error:
    opq_free(q);
    return NULL;
}
static int send_packet(opq *q, const uint8_t *data, size_t len) {
    op_ssize n;
    do {
        n = op_sendto(q->fd, data, len, MSG_DONTWAIT, (struct sockaddr *)&q->peer, q->peer_len);
    } while (n < 0 && errno == EINTR);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return 1;
    if (n != (op_ssize)len)
        return fail(q, "QUIC send", 0);
    return 0;
}
int opq_step(opq *q) {
    if (!q || q->failed)
        return -1;
    uint8_t packet[65536];
    for (int i = 0; i < 64; ++i) {
        struct sockaddr_storage peer;
        op_socklen plen = sizeof(peer);
        op_ssize n = op_recvfrom(q->fd, packet, sizeof(packet), MSG_DONTWAIT,
                                 (struct sockaddr *)&peer, &plen);
        if (n < 0) {
            if (errno == EINTR) {
                --i;
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            return fail(q, "QUIC receive", 0);
        }
        /* BSD adds sin_len; sockaddr padding is not an address identity. */
        if (!op_address_equal((struct sockaddr *)&peer, plen, (struct sockaddr *)&q->peer,
                              q->peer_len))
            continue;
        /* Stray FastP2P UDP punch markers may still arrive after handoff. */
        if (!n || !(packet[0] & 0x40))
            continue;
        if (!q->conn) {
            ngtcp2_pkt_hd first;
            if (ngtcp2_pkt_decode_hd_long(&first, packet, (size_t)n) < 0 ||
                first.type != NGTCP2_PKT_INITIAL)
                continue;
            if (init_conn(q, &first))
                return -1;
        }
        ngtcp2_path path = {{(struct sockaddr *)&q->local, q->local_len},
                            {(struct sockaddr *)&q->peer, q->peer_len},
                            NULL};
        ngtcp2_pkt_info pi = {0};
        int rv = ngtcp2_conn_read_pkt(q->conn, &path, &pi, packet, (size_t)n, now_ns());
        if (rv)
            return fail(q, "QUIC packet", rv);
    }
    if (!q->conn)
        return 0;
    uint64_t now = now_ns();
    if (ngtcp2_conn_get_expiry(q->conn) <= now) {
        int rv = ngtcp2_conn_handle_expiry(q->conn, now);
        if (rv)
            return fail(q, "QUIC timer", rv);
    }
    if (!q->server && q->stream == -1 && q->ready)
        (void)ngtcp2_conn_open_bidi_stream(q->conn, &q->stream, NULL);
    if (q->blocked_len) {
        int rv = send_packet(q, q->blocked_packet, q->blocked_len);
        if (rv)
            return rv < 0 ? -1 : 0;
        q->blocked_len = 0;
    }
    for (int i = 0; i < 32; ++i) {
        struct qchunk *p = q->head;
        while (p && p->sent == p->len)
            p = p->next;
        ngtcp2_vec vec = {NULL, 0};
        if (p) {
            vec.base = p->data + p->sent;
            vec.len = p->len - p->sent;
        }
        ngtcp2_path_storage path;
        ngtcp2_path_storage_zero(&path);
        ngtcp2_pkt_info pi = {0};
        ngtcp2_ssize accepted = -1;
        int64_t sid = p && q->stream >= 0 ? q->stream : -1;
        ngtcp2_ssize n = ngtcp2_conn_writev_stream(q->conn, &path.path, &pi, q->blocked_packet,
                                                   sizeof(q->blocked_packet), &accepted, 0, sid,
                                                   &vec, sid >= 0 ? 1 : 0, now_ns());
        if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED)
            break;
        if (n < 0)
            return fail(q, "QUIC stream", (int)n);
        if (accepted > 0 && p)
            p->sent += (size_t)accepted;
        if (!n)
            break;
        int rv = send_packet(q, q->blocked_packet, (size_t)n);
        if (rv < 0)
            return -1;
        if (rv > 0) {
            q->blocked_len = (size_t)n;
            break;
        }
    }
    return 0;
}
int opq_write(opq *q, const void *data, size_t len) {
    if (!q || q->failed || len > QLIMIT - q->pending)
        return -1;
    if (!len)
        return 0;
    struct qchunk *p = malloc(sizeof(*p) + len);
    if (!p)
        return -1;
    p->next = NULL;
    p->offset = q->next_offset;
    p->len = len;
    p->sent = 0;
    memcpy(p->data, data, len);
    if (q->tail)
        q->tail->next = p;
    else
        q->head = p;
    q->tail = p;
    q->pending += len;
    q->next_offset += len;
    return 0;
}
size_t opq_read(opq *q, void *data, size_t cap) {
    size_t n = q->rxlen < cap ? q->rxlen : cap;
    if (n) {
        memcpy(data, q->rx, n);
        memmove(q->rx, q->rx + n, q->rxlen - n);
        q->rxlen -= n;
        if (q->conn && q->stream >= 0) {
            ngtcp2_conn_extend_max_stream_offset(q->conn, q->stream, n);
            ngtcp2_conn_extend_max_offset(q->conn, n);
        }
    }
    return n;
}
size_t opq_pending(const opq *q) {
    return q->pending;
}
int opq_ready(const opq *q) {
    return q && q->ready;
}
int opq_peer_digest(opq *q, uint8_t out[32]) {
    if (!q || !q->tls || q->failed)
        return -1;
    X509 *certificate = SSL_get1_peer_certificate(q->tls);
    if (!certificate)
        return -1;
    unsigned length = 0;
    int rv = X509_digest(certificate, EVP_sha256(), out, &length) && length == 32 ? 0 : -1;
    X509_free(certificate);
    return rv;
}
int opq_identity_digest(uint8_t out[32]) {
    fp_identity *id = get_identity();
    if (!id)
        return -1;
    memcpy(out, id->digest, 32);
    return 0;
}
const char *opq_error(const opq *q) {
    return q ? q->error : "QUIC initialization failed";
}
void opq_free(opq *q) {
    if (!q)
        return;
    if (q->conn)
        ngtcp2_conn_del(q->conn);
    if (q->tls) {
        SSL_set_app_data(q->tls, NULL);
        SSL_free(q->tls);
    }
    if (q->native_tls)
        ngtcp2_crypto_ossl_ctx_del(q->native_tls);
    if (q->tls_context)
        SSL_CTX_free(q->tls_context);
    while (q->head) {
        struct qchunk *p = q->head;
        q->head = p->next;
        free(p);
    }
    free(q->rx);
    free(q);
}
