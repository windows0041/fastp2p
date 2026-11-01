#include "platform.h"
/* ngtcp2 / GnuTLS integration follows ngtcp2's MIT-licensed public examples.
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
#ifdef OP2P_QUIC_OPENSSL
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#else
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#endif

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
#ifdef OP2P_QUIC_OPENSSL
    SSL_CTX *tls_context;
    SSL *tls;
    ngtcp2_crypto_ossl_ctx *native_tls;
#else
    gnutls_session_t tls;
    gnutls_certificate_credentials_t cred;
#endif
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
static uint64_t now_ns(void) { return op_monotonic_ns(); }
static int fail(opq *q, const char *message, int code) {
    snprintf(q->error, sizeof(q->error), "%s: %s", message,
             code ? ngtcp2_strerror(code) : strerror(errno));
    q->failed = 1;
    return -1;
}
static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *ref) {
    return ((opq *)ref->user_data)->conn;
}
static int qrandom(uint8_t *data,size_t len) {
#ifdef OP2P_QUIC_OPENSSL
    return len>INT_MAX || RAND_bytes(data,(int)len)!=1 ? -1:0;
#else
    return gnutls_rnd(GNUTLS_RND_RANDOM,data,len);
#endif
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
    ngtcp2_conn_extend_max_stream_offset(conn, sid, len);
    ngtcp2_conn_extend_max_offset(conn, len);
    /* FIN means the only transport stream is closed. Drain already received
     * bytes first; idle/peer closure is handled by the enclosing tunnel. */
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
#ifdef OP2P_QUIC_OPENSSL
static int make_certificate(opq *q) {
    EVP_PKEY_CTX *generator=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,NULL);
    EVP_PKEY *key=NULL; X509 *certificate=X509_new(); BIGNUM *serial=NULL;
    uint8_t bytes[16]; int result=-1;
    if(!generator || !certificate || qrandom(bytes,sizeof(bytes))) goto done;
    serial=BN_bin2bn(bytes,sizeof(bytes),NULL);
    if(!serial || EVP_PKEY_keygen_init(generator)<=0 ||
       EVP_PKEY_CTX_set_rsa_keygen_bits(generator,2048)<=0 || EVP_PKEY_keygen(generator,&key)<=0 ||
       !X509_set_version(certificate,2) || !BN_to_ASN1_INTEGER(serial,X509_get_serialNumber(certificate)) ||
       !X509_gmtime_adj(X509_getm_notBefore(certificate),-60) ||
       !X509_gmtime_adj(X509_getm_notAfter(certificate),86400) ||
       !X509_set_pubkey(certificate,key)) goto done;
    X509_NAME *name=X509_get_subject_name(certificate);
    if(!X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(const unsigned char *)"openp2p",-1,-1,0) ||
       !X509_set_issuer_name(certificate,name) || !X509_sign(certificate,key,EVP_sha256()) ||
       SSL_CTX_use_certificate(q->tls_context,certificate)!=1 || SSL_CTX_use_PrivateKey(q->tls_context,key)!=1) goto done;
    result=0;
done:
    BN_free(serial); X509_free(certificate); EVP_PKEY_free(key); EVP_PKEY_CTX_free(generator);
    return result;
}
static int select_alpn(SSL *ssl,const unsigned char **out,unsigned char *outlen,
                        const unsigned char *in,unsigned int inlen,void *argument) {
    (void)ssl; (void)argument;
    static const unsigned char protocol[]="\x09openp2pv1";
    unsigned char *selected=NULL;
    if(SSL_select_next_proto(&selected,outlen,protocol,sizeof(protocol)-1,in,inlen)!=OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    *out=selected; return SSL_TLSEXT_ERR_OK;
}
#else
static int make_certificate(opq *q) {
    gnutls_x509_privkey_t key = NULL;
    gnutls_x509_crt_t crt = NULL;
    uint8_t serial[16];
    int rv = -1;
    if (gnutls_x509_privkey_init(&key) || gnutls_x509_crt_init(&crt))
        goto end;
    if (gnutls_x509_privkey_generate(key, GNUTLS_PK_RSA, 2048, 0) ||
        gnutls_rnd(GNUTLS_RND_RANDOM, serial, sizeof(serial)) ||
        gnutls_x509_crt_set_version(crt, 3) ||
        gnutls_x509_crt_set_serial(crt, serial, sizeof(serial)) ||
        gnutls_x509_crt_set_activation_time(crt, time(NULL) - 60) ||
        gnutls_x509_crt_set_expiration_time(crt, time(NULL) + 86400) ||
        gnutls_x509_crt_set_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME, 0, "openp2p", 7) ||
        gnutls_x509_crt_set_key(crt, key) ||
        gnutls_x509_crt_sign2(crt, crt, key, GNUTLS_DIG_SHA256, 0) ||
        gnutls_certificate_set_x509_key(q->cred, &crt, 1, key))
        goto end;
    rv = 0;
end:
    if (crt)
        gnutls_x509_crt_deinit(crt);
    if (key)
        gnutls_x509_privkey_deinit(key);
    return rv;
}
#endif
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
#ifdef OP2P_QUIC_OPENSSL
    ngtcp2_conn_set_tls_native_handle(q->conn, q->native_tls);
#else
    ngtcp2_conn_set_tls_native_handle(q->conn, q->tls);
#endif
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
#ifdef OP2P_QUIC_OPENSSL
    q->tls_context=SSL_CTX_new(server?TLS_server_method():TLS_client_method());
    if(!q->tls_context || !SSL_CTX_set_min_proto_version(q->tls_context,TLS1_3_VERSION)) goto error;
    /* Existing Go peers use temporary self-signed 1024-bit certificates.
     * This compatibility policy is confined to P2P; WSS verifies CA and SAN. */
    SSL_CTX_set_verify(q->tls_context,SSL_VERIFY_NONE,NULL);
    if(!server) SSL_CTX_set_security_level(q->tls_context,1);
    if(server) { if(make_certificate(q)) goto error; SSL_CTX_set_alpn_select_cb(q->tls_context,select_alpn,NULL); }
    q->tls=SSL_new(q->tls_context);
    if(!q->tls || ngtcp2_crypto_ossl_ctx_new(&q->native_tls,q->tls)) goto error;
    SSL_set_app_data(q->tls,&q->ref);
    if(server) {
        SSL_set_accept_state(q->tls);
        if(ngtcp2_crypto_ossl_configure_server_session(q->tls)) goto error;
    } else {
        SSL_set_connect_state(q->tls);
        static const unsigned char alpn[]="\x09openp2pv1";
        if(SSL_set_alpn_protos(q->tls,alpn,sizeof(alpn)-1) || ngtcp2_crypto_ossl_configure_client_session(q->tls)) goto error;
    }
#else
    if(gnutls_certificate_allocate_credentials(&q->cred)) goto error;
    if (server && make_certificate(q))
        goto error;
    if (gnutls_init(&q->tls,
                    (server ? GNUTLS_SERVER : GNUTLS_CLIENT) | GNUTLS_NO_END_OF_EARLY_DATA))
        goto error;
    if ((server ? ngtcp2_crypto_gnutls_configure_server_session(q->tls)
                : ngtcp2_crypto_gnutls_configure_client_session(q->tls)))
        goto error;
    if (gnutls_priority_set_direct(
            q->tls, "NORMAL:-VERS-ALL:+VERS-TLS1.3:%DISABLE_TLS13_COMPAT_MODE", NULL))
        goto error;
    gnutls_session_set_ptr(q->tls, &q->ref);
    if (gnutls_credentials_set(q->tls, GNUTLS_CRD_CERTIFICATE, q->cred))
        goto error;
    gnutls_datum_t alpn = {(unsigned char *)"openp2pv1", 9};
    if (gnutls_alpn_set_protocols(q->tls, &alpn, 1, GNUTLS_ALPN_MANDATORY))
        goto error;
#endif
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
        op_ssize n =
            op_recvfrom(q->fd, packet, sizeof(packet), MSG_DONTWAIT, (struct sockaddr *)&peer, &plen);
        if (n < 0) {
            if (errno == EINTR) {
                --i;
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            return fail(q, "QUIC receive", 0);
        }
        if (plen != q->peer_len || memcmp(&peer, &q->peer, plen))
            continue;
        /* Stray OpenP2P UDP punch markers may still arrive after handoff. */
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
    }
    return n;
}
size_t opq_pending(const opq *q) {
    return q->pending;
}
int opq_ready(const opq *q) {
    return q && q->ready;
}
const char *opq_error(const opq *q) {
    return q ? q->error : "QUIC initialization failed";
}
void opq_free(opq *q) {
    if (!q)
        return;
    if (q->conn)
        ngtcp2_conn_del(q->conn);
#ifdef OP2P_QUIC_OPENSSL
    if(q->tls) { SSL_set_app_data(q->tls,NULL); SSL_free(q->tls); }
    if(q->native_tls) ngtcp2_crypto_ossl_ctx_del(q->native_tls);
    if(q->tls_context) SSL_CTX_free(q->tls_context);
#else
    if (q->tls) gnutls_deinit(q->tls);
    if (q->cred) gnutls_certificate_free_credentials(q->cred);
#endif
    while (q->head) {
        struct qchunk *p = q->head;
        q->head = p->next;
        free(p);
    }
    free(q->rx);
    free(q);
}
