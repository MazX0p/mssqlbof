/*
 * tls_schannel.c — Windows production TLS via Schannel.
 *
 * Mirrors the OpenSSL Linux stub state machine:
 *
 *   Handshake phase: TLS records exchanged via InitializeSecurityContextW.
 *     Outbound tokens are wrapped in TDS PRELOGIN (0x12) packets.
 *     Inbound bytes are read by unwrapping TDS PRELOGIN packet payloads.
 *
 *   Post-handshake: TLS records sent raw on the wire (no TDS wrapping)
 *     for the LOGIN7 transaction. EncryptMessage produces ciphertext records
 *     containing one plaintext TDS packet each. DecryptMessage consumes
 *     ciphertext from a sliding network buffer and yields plaintext.
 *
 * Self-signed certs: SCH_CRED_MANUAL_CRED_VALIDATION + we skip validation
 * by passing ISC_REQ_MANUAL_CRED_VALIDATION and ignoring the result.
 *
 * Reference: [MS-TDS] §8.5, Microsoft "Using Schannel" sample, FreeTDS
 * `gnutls.c` and `openssl.c` for the wrapping choreography.
 */

#ifndef TDS_LINUX_TEST
#include "tds_internal.h"
#include "../common/dynimports.h"

#define ISC_REQ_REPLAY_DETECT     0x00000004
#define ISC_REQ_SEQUENCE_DETECT   0x00000008
#define ISC_REQ_CONFIDENTIALITY   0x00000010
#define ISC_REQ_ALLOCATE_MEMORY   0x00000100
#define ISC_REQ_STREAM            0x00008000
#define ISC_REQ_MANUAL_CRED_VALIDATION 0x00080000
#define ISC_REQ_USE_SUPPLIED_CREDS 0x00000080

#define SECBUFFER_VERSION         0
#define SECBUFFER_EMPTY           0
#define SECBUFFER_DATA            1
#define SECBUFFER_TOKEN           2
#define SECBUFFER_STREAM_HEADER   7
#define SECBUFFER_STREAM_TRAILER  6
#define SECBUFFER_EXTRA           5
#define SECBUFFER_ALERT           17

#define SECPKG_ATTR_STREAM_SIZES  4

#ifndef SP_PROT_TLS1_2_CLIENT
#define SP_PROT_TLS1_2_CLIENT     0x00000800
#endif
#ifndef SCH_CRED_NO_DEFAULT_CREDS
#define SCH_CRED_NO_DEFAULT_CREDS 0x00000010
#endif
#ifndef SCH_CRED_MANUAL_CRED_VALIDATION
#define SCH_CRED_MANUAL_CRED_VALIDATION 0x00000008
#endif
#ifndef UNISP_NAME_W
#define UNISP_NAME_W L"Microsoft Unified Security Protocol Provider"
#endif

typedef struct {
    DWORD cbHeader;
    DWORD cbTrailer;
    DWORD cbMaximumMessage;
    DWORD cBuffers;
    DWORD cbBlockSize;
} SecPkgContext_StreamSizes_local;

#define SCHANNEL_NETBUF_CAP   (32 * 1024)

struct tds_tls {
    CredHandle  hCred;
    CtxtHandle  hCtxt;
    int         have_cred;
    int         have_ctxt;
    int         handshake_done;
    SecPkgContext_StreamSizes_local sizes;

    /* Inbound network buffer: ciphertext awaiting decrypt. */
    uint8_t     net_buf[SCHANNEL_NETBUF_CAP];
    size_t      net_len;

    /* Decrypted plaintext queue: filled by DecryptMessage, drained by tds_tls_recv. */
    uint8_t     plain_buf[SCHANNEL_NETBUF_CAP];
    size_t      plain_len;
    size_t      plain_pos;
};

/* ---- helpers ---- */

/* Send a buffer wrapped in a TDS PRELOGIN packet (handshake phase). */
static int send_handshake_token(struct tds_conn *c, const uint8_t *buf, size_t len) {
    uint8_t pkt[8192 + TDS_HEADER_SIZE];
    if (len + TDS_HEADER_SIZE > sizeof(pkt)) return TDS_ERR_PROTOCOL;
    tds_header_t *h = (tds_header_t*)pkt;
    h->type      = TDS_TYPE_PRELOGIN;
    h->status    = TDS_STATUS_EOM;
    h->length    = WS2_32$htons((uint16_t)(len + TDS_HEADER_SIZE));
    h->spid      = 0;
    h->packet_id = c->packet_id++;
    h->window    = 0;
    MSVCRT$memcpy(pkt + TDS_HEADER_SIZE, buf, len);
    return tds_raw_send(c, pkt, len + TDS_HEADER_SIZE);
}

/* Read one TDS PRELOGIN packet's payload into c->tls->net_buf. */
static int read_handshake_payload(struct tds_conn *c) {
    uint8_t hdr[TDS_HEADER_SIZE];
    int rc = tds_raw_recv(c, hdr, TDS_HEADER_SIZE);
    if (rc != TDS_OK) return rc;
    tds_header_t *h = (tds_header_t*)hdr;
    uint16_t total = WS2_32$ntohs(h->length);
    if (total < TDS_HEADER_SIZE) return TDS_ERR_PROTOCOL;
    size_t plen = total - TDS_HEADER_SIZE;
    if (c->tls->net_len + plen > sizeof(c->tls->net_buf)) return TDS_ERR_PROTOCOL;
    rc = tds_raw_recv(c, c->tls->net_buf + c->tls->net_len, plen);
    if (rc != TDS_OK) return rc;
    c->tls->net_len += plen;
    return TDS_OK;
}

int tds_tls_init(struct tds_conn *c, const wchar_t *host) {
    (void)host;
    struct tds_tls *t = (struct tds_tls*)MSVCRT$calloc(1, sizeof(*t));
    if (!t) return TDS_ERR_ALLOC;

    SCHANNEL_CRED cred;
    MSVCRT$memset(&cred, 0, sizeof(cred));
    cred.dwVersion             = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    cred.dwFlags               = SCH_CRED_NO_DEFAULT_CREDS |
                                 SCH_CRED_MANUAL_CRED_VALIDATION;

    SECURITY_STATUS ss = SECUR32$AcquireCredentialsHandleW(
        NULL, (SEC_WCHAR*)UNISP_NAME_W, SECPKG_CRED_OUTBOUND,
        NULL, &cred, NULL, NULL, &t->hCred, NULL);
    if (ss != SEC_E_OK) {
        tds_set_error_a(c, "AcquireCredentialsHandleW failed: 0x%lx", (unsigned long)ss);
        MSVCRT$free(t);
        return TDS_ERR_TLS;
    }
    t->have_cred = 1;
    c->tls = t;
    return TDS_OK;
}

int tds_tls_handshake(struct tds_conn *c) {
    struct tds_tls *t = c->tls;
    if (!t) return TDS_ERR_TLS;

    SecBufferDesc out_desc;
    SecBuffer     out_buf;
    SecBufferDesc in_desc;
    SecBuffer     in_bufs[2];

    DWORD flags_in = ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT |
                     ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
                     ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION;
    DWORD flags_out = 0;

    /* First call: produce ClientHello, no input buffer. */
    out_buf.BufferType = SECBUFFER_TOKEN;
    out_buf.cbBuffer   = 0;
    out_buf.pvBuffer   = NULL;
    out_desc.ulVersion = SECBUFFER_VERSION;
    out_desc.cBuffers  = 1;
    out_desc.pBuffers  = &out_buf;

    SECURITY_STATUS ss = SECUR32$InitializeSecurityContextW(
        &t->hCred, NULL, (SEC_WCHAR*)L"sql",
        flags_in, 0, 0,
        NULL, 0, &t->hCtxt,
        &out_desc, &flags_out, NULL);

    if (ss != SEC_I_CONTINUE_NEEDED && ss != SEC_E_OK) {
        tds_set_error_a(c, "ISC initial failed: 0x%lx", (unsigned long)ss);
        return TDS_ERR_TLS;
    }
    t->have_ctxt = 1;

    if (out_buf.cbBuffer > 0 && out_buf.pvBuffer) {
        int rc = send_handshake_token(c, (uint8_t*)out_buf.pvBuffer, out_buf.cbBuffer);
        SECUR32$FreeContextBuffer(out_buf.pvBuffer);
        if (rc != TDS_OK) return rc;
    }

    /* Loop: read response, feed to ISC, send any output token, repeat. */
    while (ss == SEC_I_CONTINUE_NEEDED) {
        if (read_handshake_payload(c) != TDS_OK) {
            tds_set_error_a(c, "Schannel: read handshake payload failed");
            return TDS_ERR_NETWORK;
        }

        in_bufs[0].BufferType = SECBUFFER_TOKEN;
        in_bufs[0].cbBuffer   = (unsigned long)t->net_len;
        in_bufs[0].pvBuffer   = t->net_buf;
        in_bufs[1].BufferType = SECBUFFER_EMPTY;
        in_bufs[1].cbBuffer   = 0;
        in_bufs[1].pvBuffer   = NULL;
        in_desc.ulVersion = SECBUFFER_VERSION;
        in_desc.cBuffers  = 2;
        in_desc.pBuffers  = in_bufs;

        out_buf.BufferType = SECBUFFER_TOKEN;
        out_buf.cbBuffer   = 0;
        out_buf.pvBuffer   = NULL;

        ss = SECUR32$InitializeSecurityContextW(
            &t->hCred, &t->hCtxt, (SEC_WCHAR*)L"sql",
            flags_in, 0, 0,
            &in_desc, 0, NULL,
            &out_desc, &flags_out, NULL);

        if (ss == SEC_E_INCOMPLETE_MESSAGE) {
            /* Need more bytes — keep current net_buf and read another packet */
            continue;
        }

        if (out_buf.cbBuffer > 0 && out_buf.pvBuffer) {
            int rc = send_handshake_token(c, (uint8_t*)out_buf.pvBuffer, out_buf.cbBuffer);
            SECUR32$FreeContextBuffer(out_buf.pvBuffer);
            if (rc != TDS_OK) return rc;
        }

        if (ss == SEC_E_OK) {
            /* Handshake complete. Check for leftover bytes. */
            if (in_bufs[1].BufferType == SECBUFFER_EXTRA && in_bufs[1].cbBuffer > 0) {
                size_t off = t->net_len - in_bufs[1].cbBuffer;
                MSVCRT$memcpy(t->net_buf, t->net_buf + off, in_bufs[1].cbBuffer);
                t->net_len = in_bufs[1].cbBuffer;
            } else {
                t->net_len = 0;
            }
            t->handshake_done = 1;
            break;
        }

        if (ss != SEC_I_CONTINUE_NEEDED && ss != SEC_E_INCOMPLETE_MESSAGE) {
            tds_set_error_a(c, "Schannel handshake failed: 0x%lx", (unsigned long)ss);
            return TDS_ERR_TLS;
        }

        /* Consume processed bytes from net_buf, keep extras */
        if (in_bufs[1].BufferType == SECBUFFER_EXTRA && in_bufs[1].cbBuffer > 0) {
            size_t off = t->net_len - in_bufs[1].cbBuffer;
            MSVCRT$memcpy(t->net_buf, t->net_buf + off, in_bufs[1].cbBuffer);
            t->net_len = in_bufs[1].cbBuffer;
        } else {
            t->net_len = 0;
        }
    }

    /* Query stream sizes */
    SECUR32$QueryContextAttributesW(&t->hCtxt, SECPKG_ATTR_STREAM_SIZES, &t->sizes);
    return TDS_OK;
}

int tds_tls_send(struct tds_conn *c, const uint8_t *data, size_t len) {
    struct tds_tls *t = c->tls;
    if (!t || !t->handshake_done) return tds_raw_send(c, data, len);

    /* Encrypt one record at a time, max plaintext = sizes.cbMaximumMessage. */
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > t->sizes.cbMaximumMessage) chunk = t->sizes.cbMaximumMessage;

        size_t bsize = (size_t)t->sizes.cbHeader + chunk + (size_t)t->sizes.cbTrailer;
        uint8_t *buf = (uint8_t*)MSVCRT$malloc(bsize);
        if (!buf) return TDS_ERR_ALLOC;

        MSVCRT$memcpy(buf + t->sizes.cbHeader, data + off, chunk);

        SecBuffer bufs[4];
        bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
        bufs[0].cbBuffer   = t->sizes.cbHeader;
        bufs[0].pvBuffer   = buf;
        bufs[1].BufferType = SECBUFFER_DATA;
        bufs[1].cbBuffer   = (unsigned long)chunk;
        bufs[1].pvBuffer   = buf + t->sizes.cbHeader;
        bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
        bufs[2].cbBuffer   = t->sizes.cbTrailer;
        bufs[2].pvBuffer   = buf + t->sizes.cbHeader + chunk;
        bufs[3].BufferType = SECBUFFER_EMPTY;
        bufs[3].cbBuffer   = 0;
        bufs[3].pvBuffer   = NULL;

        SecBufferDesc desc;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers  = 4;
        desc.pBuffers  = bufs;

        SECURITY_STATUS ss = SECUR32$EncryptMessage(&t->hCtxt, 0, &desc, 0);
        if (ss != SEC_E_OK) {
            MSVCRT$free(buf);
            tds_set_error_a(c, "EncryptMessage failed: 0x%lx", (unsigned long)ss);
            return TDS_ERR_TLS;
        }

        size_t total_out = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
        int rc = tds_raw_send(c, buf, total_out);
        MSVCRT$free(buf);
        if (rc != TDS_OK) return rc;

        off += chunk;
    }
    return TDS_OK;
}

/* Try to decrypt one record from net_buf into plain_buf. Returns:
 *   1  = produced plaintext (plain_buf updated)
 *   0  = need more bytes
 *  <0  = error
 */
static int try_decrypt_one(struct tds_conn *c) {
    struct tds_tls *t = c->tls;
    if (t->net_len == 0) return 0;

    SecBuffer bufs[4];
    bufs[0].BufferType = SECBUFFER_DATA;
    bufs[0].cbBuffer   = (unsigned long)t->net_len;
    bufs[0].pvBuffer   = t->net_buf;
    bufs[1].BufferType = SECBUFFER_EMPTY;
    bufs[1].cbBuffer   = 0;
    bufs[1].pvBuffer   = NULL;
    bufs[2].BufferType = SECBUFFER_EMPTY;
    bufs[2].cbBuffer   = 0;
    bufs[2].pvBuffer   = NULL;
    bufs[3].BufferType = SECBUFFER_EMPTY;
    bufs[3].cbBuffer   = 0;
    bufs[3].pvBuffer   = NULL;

    SecBufferDesc desc;
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers  = 4;
    desc.pBuffers  = bufs;

    SECURITY_STATUS ss = SECUR32$DecryptMessage(&t->hCtxt, &desc, 0, NULL);
    if (ss == SEC_E_INCOMPLETE_MESSAGE) return 0;
    if (ss != SEC_E_OK) {
        tds_set_error_a(c, "DecryptMessage failed: 0x%lx", (unsigned long)ss);
        return TDS_ERR_TLS;
    }

    /* Find data + extra buffers */
    SecBuffer *data_buf = NULL;
    SecBuffer *extra_buf = NULL;
    for (int i = 0; i < 4; ++i) {
        if (bufs[i].BufferType == SECBUFFER_DATA && !data_buf) data_buf = &bufs[i];
        if (bufs[i].BufferType == SECBUFFER_EXTRA) extra_buf = &bufs[i];
    }
    if (!data_buf) return TDS_ERR_TLS;

    /* Append plaintext to plain_buf */
    if (t->plain_len + data_buf->cbBuffer > sizeof(t->plain_buf)) return TDS_ERR_PROTOCOL;
    MSVCRT$memcpy(t->plain_buf + t->plain_len, data_buf->pvBuffer, data_buf->cbBuffer);
    t->plain_len += data_buf->cbBuffer;

    /* Move extras to start of net_buf */
    if (extra_buf && extra_buf->cbBuffer > 0) {
        MSVCRT$memcpy(t->net_buf, extra_buf->pvBuffer, extra_buf->cbBuffer);
        t->net_len = extra_buf->cbBuffer;
    } else {
        t->net_len = 0;
    }
    return 1;
}

int tds_tls_recv(struct tds_conn *c, uint8_t *out, size_t want) {
    struct tds_tls *t = c->tls;
    if (!t || !t->handshake_done) return tds_raw_recv(c, out, want);

    size_t got = 0;
    while (got < want) {
        /* Drain plaintext */
        if (t->plain_pos < t->plain_len) {
            size_t avail = t->plain_len - t->plain_pos;
            size_t need = want - got;
            size_t take = avail < need ? avail : need;
            MSVCRT$memcpy(out + got, t->plain_buf + t->plain_pos, take);
            t->plain_pos += take;
            got += take;
            if (t->plain_pos == t->plain_len) {
                t->plain_pos = 0;
                t->plain_len = 0;
            }
            continue;
        }

        /* Try to decrypt what we have */
        int rc = try_decrypt_one(c);
        if (rc < 0) return rc;
        if (rc == 1) continue;

        /* Need more network bytes */
        if (t->net_len >= sizeof(t->net_buf)) {
            tds_set_error_a(c, "Schannel: net_buf full, no progress");
            return TDS_ERR_PROTOCOL;
        }
        int n = WS2_32$recv(c->sock, (char*)(t->net_buf + t->net_len),
                            (int)(sizeof(t->net_buf) - t->net_len), 0);
        if (n <= 0) {
            tds_set_error_a(c, "Schannel: recv failed");
            return TDS_ERR_NETWORK;
        }
        t->net_len += (size_t)n;
    }
    return TDS_OK;
}

void tds_tls_free(struct tds_conn *c) {
    if (!c || !c->tls) return;
    if (c->tls->have_ctxt) SECUR32$DeleteSecurityContext(&c->tls->hCtxt);
    if (c->tls->have_cred) SECUR32$FreeCredentialsHandle(&c->tls->hCred);
    MSVCRT$free(c->tls);
    c->tls = NULL;
}

#endif /* !TDS_LINUX_TEST */
