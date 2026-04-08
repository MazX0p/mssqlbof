/*
 * tls_openssl.c — Linux test-only TLS implementation.
 *
 * SQL Server's TLS handshake is unusual: TLS records during the handshake
 * are wrapped inside TDS PRELOGIN packets (type 0x12), then after the
 * handshake completes, behavior depends on the negotiated encryption mode:
 *
 *   ENCRYPT_REQ  → all subsequent TDS packets are inside TLS records (full session)
 *   ENCRYPT_OFF  → only LOGIN7 is encrypted; TLS layer is torn down after
 *   ENCRYPT_NOT_SUP → no TLS at all (server hardened off)
 *
 * We bridge OpenSSL with the SQL Server quirk by using a pair of memory BIOs:
 * one to feed ciphertext that OpenSSL produces (so we can wrap it in TDS) and
 * one to receive ciphertext we read from the network (so OpenSSL can decrypt).
 *
 * This file is ONLY compiled into the Linux test .so, never into Windows BOFs.
 * The Windows production path uses tls_schannel.c.
 */

#ifdef TDS_LINUX_TEST
#include "tds_internal.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdlib.h>
#include <string.h>

struct tds_tls {
    SSL_CTX *ctx;
    SSL     *ssl;
    BIO     *rbio;   /* network -> OpenSSL */
    BIO     *wbio;   /* OpenSSL -> network */
    int      handshake_done;
};

/* Push raw data from OpenSSL's wbio into the network as a TDS PRELOGIN packet.
 * Used during the handshake phase. */
static int pump_out_handshake(struct tds_conn *c) {
    char buf[4096];
    int n;
    while ((n = BIO_read(c->tls->wbio, buf, sizeof(buf))) > 0) {
        /* Wrap as TDS PRELOGIN packet — type 0x12 */
        uint8_t pkt[4096 + TDS_HEADER_SIZE];
        tds_header_t *h = (tds_header_t*)pkt;
        h->type      = TDS_TYPE_PRELOGIN;
        h->status    = TDS_STATUS_EOM;
        h->length    = htons((uint16_t)(n + TDS_HEADER_SIZE));
        h->spid      = 0;
        h->packet_id = c->packet_id++;
        h->window    = 0;
        memcpy(pkt + TDS_HEADER_SIZE, buf, n);
        if (tds_raw_send(c, pkt, n + TDS_HEADER_SIZE) != TDS_OK)
            return TDS_ERR_NETWORK;
    }
    return TDS_OK;
}

/* Read one TDS packet from the wire and feed its payload into rbio. */
static int pump_in_handshake(struct tds_conn *c) {
    uint8_t hdr[TDS_HEADER_SIZE];
    if (tds_raw_recv(c, hdr, TDS_HEADER_SIZE) != TDS_OK) return TDS_ERR_NETWORK;
    tds_header_t *h = (tds_header_t*)hdr;
    uint16_t total = ntohs(h->length);
    if (total < TDS_HEADER_SIZE) return TDS_ERR_PROTOCOL;
    size_t plen = total - TDS_HEADER_SIZE;
    uint8_t buf[4096];
    if (plen > sizeof(buf)) return TDS_ERR_PROTOCOL;
    if (tds_raw_recv(c, buf, plen) != TDS_OK) return TDS_ERR_NETWORK;
    BIO_write(c->tls->rbio, buf, (int)plen);
    return TDS_OK;
}

int tds_tls_init(struct tds_conn *c, const wchar_t *host) {
    (void)host;
    static int initialized = 0;
    if (!initialized) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        initialized = 1;
    }

    struct tds_tls *t = (struct tds_tls*)calloc(1, sizeof(*t));
    if (!t) return TDS_ERR_ALLOC;

    t->ctx = SSL_CTX_new(TLS_client_method());
    if (!t->ctx) { free(t); return TDS_ERR_TLS; }
    SSL_CTX_set_min_proto_version(t->ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(t->ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_security_level(t->ctx, 0);  /* allow self-signed weak certs */

    t->ssl = SSL_new(t->ctx);
    t->rbio = BIO_new(BIO_s_mem());
    t->wbio = BIO_new(BIO_s_mem());
    if (!t->ssl || !t->rbio || !t->wbio) {
        if (t->ssl) SSL_free(t->ssl);
        if (t->rbio) BIO_free(t->rbio);
        if (t->wbio) BIO_free(t->wbio);
        SSL_CTX_free(t->ctx);
        free(t);
        return TDS_ERR_ALLOC;
    }
    SSL_set_bio(t->ssl, t->rbio, t->wbio);
    SSL_set_connect_state(t->ssl);

    c->tls = t;
    return TDS_OK;
}

int tds_tls_handshake(struct tds_conn *c) {
    if (!c->tls) return TDS_ERR_TLS;
    for (;;) {
        int rc = SSL_do_handshake(c->tls->ssl);
        if (rc == 1) {
            c->tls->handshake_done = 1;
            /* Drain any final ciphertext to wire */
            if (pump_out_handshake(c) != TDS_OK) return TDS_ERR_NETWORK;
            return TDS_OK;
        }
        int err = SSL_get_error(c->tls->ssl, rc);
        if (err == SSL_ERROR_WANT_READ) {
            if (pump_out_handshake(c) != TDS_OK) return TDS_ERR_NETWORK;
            if (pump_in_handshake(c)  != TDS_OK) return TDS_ERR_NETWORK;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            if (pump_out_handshake(c) != TDS_OK) return TDS_ERR_NETWORK;
        } else {
            unsigned long e = ERR_get_error();
            char buf[256];
            ERR_error_string_n(e, buf, sizeof(buf));
            tds_set_error_a(c, "TLS handshake failed: %s", buf);
            return TDS_ERR_TLS;
        }
    }
}

/* Post-handshake send. In login phase the ciphertext is wrapped in TDS
 * PRELOGIN packets (per FreeTDS / [MS-TDS]). After login completes,
 * if full-session TLS is in effect we send raw TLS records. */
int tds_tls_send(struct tds_conn *c, const uint8_t *data, size_t len) {
    if (!c->tls || !c->tls->handshake_done) return tds_raw_send(c, data, len);
    int n = SSL_write(c->tls->ssl, data, (int)len);
    if (n <= 0) {
        tds_set_error_a(c, "SSL_write failed");
        return TDS_ERR_TLS;
    }
    /* Drain ciphertext from wbio and ship it. Wrap in TDS PRELOGIN packets
     * during the handshake, send raw TLS records afterward. */
    char buf[8192];
    int got;
    while ((got = BIO_read(c->tls->wbio, buf, sizeof(buf))) > 0) {
        if (c->tls_send_state == TDS_TLS_STATE_HANDSHAKE) {
            uint8_t pkt[8192 + TDS_HEADER_SIZE];
            tds_header_t *h = (tds_header_t*)pkt;
            h->type      = TDS_TYPE_PRELOGIN;
            h->status    = TDS_STATUS_EOM;
            h->length    = htons((uint16_t)(got + TDS_HEADER_SIZE));
            h->spid      = 0;
            h->packet_id = c->packet_id++;
            h->window    = 0;
            memcpy(pkt + TDS_HEADER_SIZE, buf, got);
            if (tds_raw_send(c, pkt, got + TDS_HEADER_SIZE) != TDS_OK)
                return TDS_ERR_NETWORK;
        } else {
            if (tds_raw_send(c, (const uint8_t*)buf, (size_t)got) != TDS_OK)
                return TDS_ERR_NETWORK;
        }
    }
    return TDS_OK;
}

/* Helper: feed more ciphertext into rbio. */
static int feed_rbio(struct tds_conn *c) {
    if (c->tls_recv_state == TDS_TLS_STATE_HANDSHAKE) {
        uint8_t hdr[TDS_HEADER_SIZE];
        if (tds_raw_recv(c, hdr, TDS_HEADER_SIZE) != TDS_OK) return TDS_ERR_NETWORK;
        tds_header_t *h = (tds_header_t*)hdr;
        uint16_t total = ntohs(h->length);
        if (total < TDS_HEADER_SIZE) return TDS_ERR_PROTOCOL;
        size_t plen = total - TDS_HEADER_SIZE;
        uint8_t pbuf[8192];
        if (plen > sizeof(pbuf)) return TDS_ERR_PROTOCOL;
        if (tds_raw_recv(c, pbuf, plen) != TDS_OK) return TDS_ERR_NETWORK;
        BIO_write(c->tls->rbio, pbuf, (int)plen);
    } else {
        uint8_t buf[8192];
        int r = recv(c->sock, buf, sizeof(buf), 0);
        if (r <= 0) return TDS_ERR_NETWORK;
        BIO_write(c->tls->rbio, buf, r);
    }
    return TDS_OK;
}

int tds_tls_recv(struct tds_conn *c, uint8_t *out, size_t want) {
    if (!c->tls || !c->tls->handshake_done) return tds_raw_recv(c, out, want);
    size_t got = 0;
    while (got < want) {
        int n = SSL_read(c->tls->ssl, out + got, (int)(want - got));
        if (n > 0) {
            got += (size_t)n;
            continue;
        }
        int err = SSL_get_error(c->tls->ssl, n);
        if (err == SSL_ERROR_WANT_READ) {
            int rc = feed_rbio(c);
            if (rc != TDS_OK) {
                tds_set_error_a(c, "feed_rbio failed during TLS read");
                return rc;
            }
        } else {
            unsigned long e = ERR_get_error();
            char sbuf[256];
            ERR_error_string_n(e, sbuf, sizeof(sbuf));
            tds_set_error_a(c, "SSL_read err=%d ssl_err=%s rc=%d", err, sbuf, n);
            return TDS_ERR_TLS;
        }
    }
    return TDS_OK;
}

void tds_tls_free(struct tds_conn *c) {
    if (!c || !c->tls) return;
    SSL_free(c->tls->ssl);
    /* rbio and wbio freed with SSL */
    SSL_CTX_free(c->tls->ctx);
    free(c->tls);
    c->tls = NULL;
}

#endif /* TDS_LINUX_TEST */
