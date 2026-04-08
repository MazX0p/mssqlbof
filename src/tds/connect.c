/*
 * tds_connect / tds_close — top-level orchestration.
 *
 * Production path (Windows BOF build):
 *   socket → PRELOGIN → optional Schannel TLS → LOGIN7+SSPI → ready
 *
 * Linux test path (TDS_LINUX_TEST):
 *   socket → PRELOGIN → optional OpenSSL TLS → LOGIN7+SQL-auth → ready
 *
 * The test escapes tds_test_send_prelogin / tds_test_get_negotiated_encryption
 * let the pytest harness drive each step in isolation, which is essential for
 * iterating on the protocol layer without a full login working yet.
 */

#include "tds_internal.h"

#ifdef _WIN32
  #include "../common/dynimports.h"
  #define X_calloc(n,s)  MSVCRT$calloc(n,s)
  #define X_free(p)      MSVCRT$free(p)
  #define X_memset(d,v,n) MSVCRT$memset(d,v,n)
  #define X_wcslen(s)    MSVCRT$wcslen(s)
#else
  #include <stdlib.h>
  #include <string.h>
  #include <wchar.h>
  #define X_calloc(n,s)  calloc(n,s)
  #define X_free(p)      free(p)
  #define X_memset(d,v,n) memset(d,v,n)
  #define X_wcslen(s)    wcslen(s)
#endif

/* Convert wide host to ASCII for getaddrinfo. Truncates to 255 chars. */
static void wide_to_ascii(const wchar_t *in, char *out, size_t outlen) {
    size_t i = 0;
    if (!in) { out[0] = 0; return; }
    for (; i < outlen - 1 && in[i]; ++i) out[i] = (char)in[i];
    out[i] = 0;
}

int tds_connect(const wchar_t *host, uint16_t port,
                const wchar_t *instance, const wchar_t *database,
                tds_conn_t **out) {
    return tds_connect_ex(host, port, instance, database, NULL, out);
}

static void copy_wide(const wchar_t *src, wchar_t *dst, size_t dstlen) {
    size_t i = 0;
    if (!src) { dst[0] = 0; return; }
    for (; i < dstlen - 1 && src[i]; ++i) dst[i] = src[i];
    dst[i] = 0;
}

int tds_connect_ex(const wchar_t *host, uint16_t port,
                   const wchar_t *instance, const wchar_t *database,
                   const tds_auth_t *auth, tds_conn_t **out) {
    (void)instance; /* named instances handled later via SQL Browser */
    if (!host || !out) return TDS_ERR_ARG;

    struct tds_conn *c = (struct tds_conn*)X_calloc(1, sizeof(*c));
    if (!c) return TDS_ERR_ALLOC;
    c->sock = TDS_INVALID_SOCK;

    /* Default auth mode: SSPI current token */
    c->auth_mode = auth ? auth->mode : TDS_AUTH_SSPI_CURRENT;
    if (auth) {
        copy_wide(auth->user,   c->auth_user,   128);
        copy_wide(auth->pass,   c->auth_pass,   128);
        copy_wide(auth->domain, c->auth_domain, 64);
        /* copy hex hash string (ASCII) for PTH */
        if (auth->hash) {
            size_t i = 0;
            for (; i < sizeof(c->auth_hash) - 1 && auth->hash[i]; ++i)
                c->auth_hash[i] = auth->hash[i];
            c->auth_hash[i] = 0;
        }
    }

    char host_ascii[256];
    wide_to_ascii(host, host_ascii, sizeof(host_ascii));

    /* Stash host + port for later SSPI SPN construction */
    {
        size_t i = 0;
        for (; i < 255 && host[i]; ++i) c->target_host[i] = host[i];
        c->target_host[i] = 0;
        c->target_port = port;
    }

    /* Always hand back the conn so the caller can read tds_last_error and
     * then call tds_close — even on a partial-failure path. */
    *out = c;

    int rc = tds_socket_open(c, host_ascii, port);
    if (rc != TDS_OK) return rc;

    rc = tds_prelogin_exchange(c);
    if (rc != TDS_OK) return rc;

    /* TLS handshake if any encryption negotiated */
    int do_tls = (c->negotiated_encryption == TDS_ENCRYPT_REQ ||
                  c->negotiated_encryption == TDS_ENCRYPT_ON  ||
                  c->negotiated_encryption == TDS_ENCRYPT_OFF);
    if (do_tls) {
        rc = tds_tls_init(c, host);
        if (rc != TDS_OK) return rc;
        c->tls_send_state = TDS_TLS_STATE_HANDSHAKE;
        c->tls_recv_state = TDS_TLS_STATE_HANDSHAKE;
        c->tls_active = 1;
        rc = tds_tls_handshake(c);
        if (rc != TDS_OK) return rc;
        /* Post-handshake: client sends encrypted LOGIN7 as raw TLS app data,
         * server responds with PLAINTEXT TDS TABULAR (login-only encryption
         * is asymmetric on SQL Server's default config). */
        c->tls_send_state = TDS_TLS_STATE_RAW_TLS;
        c->tls_recv_state = TDS_TLS_STATE_NONE;
    }

    /* LOGIN7 (encrypted via raw TLS records on send path) */
    rc = tds_login7_send(c, database);
    if (rc != TDS_OK) return rc;

    /* Read login response — plaintext TDS TABULAR */
    struct tds_result *r = tds_result_new(c);
    if (!r) return TDS_ERR_ALLOC;
    rc = tds_parse_response(c, r);
    tds_result_free(r);
    if (rc != TDS_OK) return rc;

#ifndef TDS_LINUX_TEST
    /* Multi-leg SSPI pump: while the server hands us a TDS_TOK_SSPI 0xED
     * continuation, run another ISC step and ship the resulting token in a
     * TDS_TYPE_SSPI (0x11) packet, then re-parse the response. Bounded to
     * 8 legs to defend against a runaway server. */
    /* After the first LOGIN7 is sent encrypted, SQL Server's asymmetric
     * login-only TLS quirk means subsequent SSPI continuation packets must
     * be sent PLAINTEXT — the server only decrypts the initial LOGIN7. */
    if (c->tls_send_state != TDS_TLS_STATE_NONE) {
        c->tls_send_state = TDS_TLS_STATE_NONE;
    }
    int legs = 0;
    while (c->sspi_in_buf && c->sspi_in_len > 0 && legs < 8) {
        uint8_t *out_tok = NULL;
        size_t   out_len = 0;
        int      done    = 0;
        int      owned_by_heap = 0;  /* ntlm_pth result is heap, must free */

        if (c->auth_mode == TDS_AUTH_NTLM_HASH) {
            /* Manual NTLMv2: parse Type 2, build Type 3 via PTH. */
            uint8_t nt[16];
            if (ntlm_pth_parse_hash(c->auth_hash, nt) != 0) {
                X_free(c->sspi_in_buf); c->sspi_in_buf = NULL; c->sspi_in_len = 0;
                tds_set_error_a(c, "invalid --hash value");
                return TDS_ERR_AUTH;
            }
            int b_rc = ntlm_pth_build_type3(c->sspi_in_buf, c->sspi_in_len,
                                            nt, c->auth_user, c->auth_domain,
                                            c->target_host,
                                            &out_tok, &out_len);
            X_free(c->sspi_in_buf); c->sspi_in_buf = NULL; c->sspi_in_len = 0;
            if (b_rc != 0 || !out_tok || out_len == 0) {
                tds_set_error_a(c, "NTLMv2 PTH Type3 build failed");
                return TDS_ERR_AUTH;
            }
            owned_by_heap = 1;
            done = 1;  /* Type 3 is the last leg */
        } else {
            int s_rc = tds_sspi_step(c, c->sspi_in_buf, c->sspi_in_len,
                                     &out_tok, &out_len, &done);
            X_free(c->sspi_in_buf); c->sspi_in_buf = NULL; c->sspi_in_len = 0;
            if (s_rc != TDS_OK) return s_rc;
        }

        if (out_tok && out_len > 0) {
            int p_rc = tds_packet_send(c, TDS_TYPE_SSPI, out_tok, out_len);
            if (owned_by_heap) X_free(out_tok);
            if (p_rc != TDS_OK) return p_rc;
        }
        if (done && (!c->sspi_in_buf)) {
            struct tds_result *r2 = tds_result_new(c);
            if (!r2) return TDS_ERR_ALLOC;
            rc = tds_parse_response(c, r2);
            tds_result_free(r2);
            if (rc != TDS_OK) return rc;
            break;
        }

        struct tds_result *r2 = tds_result_new(c);
        if (!r2) return TDS_ERR_ALLOC;
        rc = tds_parse_response(c, r2);
        tds_result_free(r2);
        if (rc != TDS_OK) return rc;
        legs++;
    }
    /* Whether we used SSPI or not, drop SSPI handles after login. */
    tds_sspi_free(c);
#endif

    /* After LOGIN7 ack, drop TLS entirely for login-only mode */
    if (do_tls) {
        c->tls_send_state = TDS_TLS_STATE_NONE;
        c->tls_recv_state = TDS_TLS_STATE_NONE;
        c->tls_active = 0;
        tds_tls_free(c);
    }
    return TDS_OK;
}

void tds_close(tds_conn_t *c) {
    if (!c) return;
    if (c->active_result) {
        tds_result_free(c->active_result);
        c->active_result = NULL;
    }
    if (c->sspi_in_buf) { X_free(c->sspi_in_buf); c->sspi_in_buf = NULL; }
    tds_tls_free(c);
    tds_socket_close(c);
    X_free(c);
}

const wchar_t *tds_last_error(tds_conn_t *c) {
    return c ? c->last_error : NULL;
}

#ifdef TDS_LINUX_TEST
int tds_test_send_prelogin(tds_conn_t *c) {
    if (!c) return TDS_ERR_ARG;
    return tds_prelogin_exchange(c);
}

int tds_test_get_negotiated_encryption(tds_conn_t *c) {
    if (!c) return -1;
    return (int)c->negotiated_encryption;
}

/* Open a raw socket only — for unit tests that drive the protocol step-by-step. */
int tds_test_open_socket(const wchar_t *host, uint16_t port, tds_conn_t **out) {
    if (!host || !out) return TDS_ERR_ARG;
    struct tds_conn *c = (struct tds_conn*)X_calloc(1, sizeof(*c));
    if (!c) return TDS_ERR_ALLOC;
    c->sock = TDS_INVALID_SOCK;
    char host_ascii[256];
    wide_to_ascii(host, host_ascii, sizeof(host_ascii));
    int rc = tds_socket_open(c, host_ascii, port);
    if (rc != TDS_OK) { X_free(c); return rc; }
    *out = c;
    return TDS_OK;
}
#endif

/* tls_*, sspi_*, sqlbatch_*, tokens, types, result are in their own .c files */
