/*
 * PRELOGIN packet — [MS-TDS] §2.2.6.5
 *
 * Layout:
 *   Option table (variable, terminated by 0xFF):
 *     For each option:
 *       1 byte  token (TDS_PL_*)
 *       2 bytes offset (big-endian, from start of option table)
 *       2 bytes length (big-endian)
 *     Then 1 byte 0xFF terminator
 *   Option data (variable, referenced by offsets above)
 *
 * Options we send:
 *   VERSION   (6 bytes : 4-byte version + 2-byte sub-build)
 *   ENCRYPT   (1 byte  : ENCRYPT_OFF — server may upgrade)
 *   INSTOPT   (variable, NUL-terminated, empty for default instance)
 *   THREADID  (4 bytes : client TID, we use 0)
 *   MARS      (1 byte  : 0)
 *
 * Server response options we read:
 *   VERSION   (6 bytes)
 *   ENCRYPT   (1 byte) — the negotiated value
 *   INSTOPT   (1 byte success/fail)
 *   THREADID  (echo)
 *   MARS      (1 byte)
 */

#include "tds_internal.h"

#ifdef _WIN32
  #include "../common/dynimports.h"
  #define X_memcpy MSVCRT$memcpy
  #define X_memset MSVCRT$memset
  #define X_strlen MSVCRT$strlen
#else
  #include <string.h>
  #define X_memcpy memcpy
  #define X_memset memset
  #define X_strlen strlen
#endif

/* Helper: append one option's table entry. Returns the data offset to fill in. */
static uint16_t pl_emit_option(uint8_t *table, size_t *table_pos,
                               uint8_t token, uint16_t data_off, uint16_t data_len) {
    table[(*table_pos)++] = token;
    table[(*table_pos)++] = (uint8_t)(data_off >> 8);
    table[(*table_pos)++] = (uint8_t)(data_off & 0xff);
    table[(*table_pos)++] = (uint8_t)(data_len >> 8);
    table[(*table_pos)++] = (uint8_t)(data_len & 0xff);
    return data_off + data_len;
}

int tds_prelogin_exchange(struct tds_conn *c) {
    uint8_t pkt[256];
    X_memset(pkt, 0, sizeof(pkt));

    /* Option table — 5 options × 5 bytes + 1 terminator = 26 bytes */
    const uint16_t table_bytes = 5 * 5 + 1;

    /* Compute option data offsets relative to start of payload */
    const uint16_t off_version  = table_bytes;        /* 26 */
    const uint16_t len_version  = 6;
    const uint16_t off_encrypt  = off_version + len_version;
    const uint16_t len_encrypt  = 1;
    const uint16_t off_instopt  = off_encrypt + len_encrypt;
    const uint16_t len_instopt  = 1;                  /* empty NUL-terminated */
    const uint16_t off_threadid = off_instopt + len_instopt;
    const uint16_t len_threadid = 4;
    const uint16_t off_mars     = off_threadid + len_threadid;
    const uint16_t len_mars     = 1;
    const uint16_t total        = off_mars + len_mars;

    /* Emit option table */
    size_t pos = 0;
    pl_emit_option(pkt, &pos, TDS_PL_VERSION,  off_version,  len_version);
    pl_emit_option(pkt, &pos, TDS_PL_ENCRYPT,  off_encrypt,  len_encrypt);
    pl_emit_option(pkt, &pos, TDS_PL_INSTOPT,  off_instopt,  len_instopt);
    pl_emit_option(pkt, &pos, TDS_PL_THREADID, off_threadid, len_threadid);
    pl_emit_option(pkt, &pos, TDS_PL_MARS,     off_mars,     len_mars);
    pkt[pos++] = TDS_PL_TERMINATOR;

    /* Emit option data — VERSION: 9.0.0.0 sub_build 0 */
    pkt[off_version + 0] = 9;
    pkt[off_version + 1] = 0;
    pkt[off_version + 2] = 0;
    pkt[off_version + 3] = 0;
    pkt[off_version + 4] = 0;
    pkt[off_version + 5] = 0;

    /* ENCRYPT: client says OFF; server decides */
    pkt[off_encrypt] = TDS_ENCRYPT_OFF;

    /* INSTOPT: empty NUL */
    pkt[off_instopt] = 0;

    /* THREADID: 0 */
    pkt[off_threadid + 0] = 0;
    pkt[off_threadid + 1] = 0;
    pkt[off_threadid + 2] = 0;
    pkt[off_threadid + 3] = 0;

    /* MARS off */
    pkt[off_mars] = 0;

    /* Send PRELOGIN */
    int rc = tds_packet_send(c, TDS_TYPE_PRELOGIN, pkt, total);
    if (rc != TDS_OK) return rc;

    /* Receive PRELOGIN response */
    rc = tds_packet_recv(c);
    if (rc != TDS_OK) return rc;

    /* Parse server's option table to find ENCRYPT */
    uint8_t *r = c->rx_buf;
    size_t   rlen = c->rx_len;
    if (rlen < 1) {
        tds_set_error_a(c, "short PRELOGIN response");
        return TDS_ERR_PROTOCOL;
    }

    size_t i = 0;
    c->negotiated_encryption = TDS_ENCRYPT_NOT_SUP;
    while (i + 1 <= rlen) {
        uint8_t token = r[i++];
        if (token == TDS_PL_TERMINATOR) break;
        if (i + 4 > rlen) {
            tds_set_error_a(c, "truncated PRELOGIN option");
            return TDS_ERR_PROTOCOL;
        }
        uint16_t off = ((uint16_t)r[i] << 8) | r[i+1];
        uint16_t len = ((uint16_t)r[i+2] << 8) | r[i+3];
        i += 4;
        if ((size_t)off + (size_t)len > rlen) {
            tds_set_error_a(c, "PRELOGIN option points past buffer");
            return TDS_ERR_PROTOCOL;
        }
        if (token == TDS_PL_ENCRYPT && len >= 1) {
            c->negotiated_encryption = r[off];
        }
        if (token == TDS_PL_VERSION && len >= 6) {
            c->server_version[0] = r[off + 0];
            c->server_version[1] = r[off + 1];
            c->server_version[2] = r[off + 2];
            c->server_version[3] = r[off + 3];
        }
    }

    /* Decide TLS posture for the rest of the session */
    if (c->negotiated_encryption == TDS_ENCRYPT_REQ ||
        c->negotiated_encryption == TDS_ENCRYPT_ON) {
        c->tls_login_only = 0;   /* full session TLS */
    } else if (c->negotiated_encryption == TDS_ENCRYPT_OFF) {
        c->tls_login_only = 1;   /* TLS only for LOGIN7, then plaintext */
    } else {
        /* NOT_SUP — plaintext throughout */
        c->tls_login_only = 0;
    }

    return TDS_OK;
}
