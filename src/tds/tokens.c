/*
 * Token-stream parser — [MS-TDS] §2.2.7
 *
 * Reads all packets of a server response into one growable buffer (using EOM
 * status flag to detect end), then walks the token stream once. Each token
 * type updates either the current tds_result_t (COLMETADATA, ROW, NBCROW),
 * the connection's last_error (ERROR), or is consumed silently (INFO,
 * ENVCHANGE, LOGINACK, DONE*, ORDER).
 *
 * v1 supports the columns we actually need from sys.* views and the
 * introspection bundle. Anything beyond that bails with TDS_ERR_PROTOCOL
 * and the column type printed for diagnosability.
 */

#include "tds_internal.h"
#include <stdarg.h>

#ifdef _WIN32
  #include "../common/dynimports.h"
  #define X_malloc(n)  MSVCRT$malloc(n)
  #define X_realloc(p,n) MSVCRT$realloc(p,n)
  #define X_free(p)    MSVCRT$free(p)
  #define X_memcpy(d,s,n) MSVCRT$memcpy(d,s,n)
  #define X_memset(d,v,n) MSVCRT$memset(d,v,n)
#else
  #include <stdlib.h>
  #include <string.h>
  #include <wchar.h>
  #define X_malloc(n)  malloc(n)
  #define X_realloc(p,n) realloc(p,n)
  #define X_free(p)    free(p)
  #define X_memcpy(d,s,n) memcpy(d,s,n)
  #define X_memset(d,v,n) memset(d,v,n)
#endif

/* Read all packets of a response into a single growable buffer */
static int slurp_response(struct tds_conn *c, uint8_t **out_buf, size_t *out_len) {
    uint8_t *buf = NULL;
    size_t   cap = 0, len = 0;

    for (;;) {
        int rc = tds_packet_recv(c);
        if (rc != TDS_OK) { X_free(buf); return rc; }

        if (len + c->rx_len > cap) {
            cap = (len + c->rx_len) * 2;
            uint8_t *nb = (uint8_t*)X_realloc(buf, cap);
            if (!nb) { X_free(buf); return TDS_ERR_ALLOC; }
            buf = nb;
        }
        X_memcpy(buf + len, c->rx_buf, c->rx_len);
        len += c->rx_len;

        /* Honor the TDS EOM flag from the packet header — if the server
         * marked this packet as end-of-message, we MUST stop reading.
         * Critical for SSPI continuation responses which contain only a
         * 0xED token and NO DONE token: without this break we'd loop
         * forever waiting for a DONE that never comes. */
        if (c->rx_status & TDS_STATUS_EOM) break;

        /* Legacy heuristic: also stop if the buffer ends with a clean DONE.
         * Use a heuristic: if the last token in the stream is a DONE-family
         * token with DONE_MORE clear, we're done. Otherwise read another. */
        /* Simpler: check if the last token in the buffer is DONE/DONEPROC/
         * DONEINPROC with bit 0 (DONE_MORE) clear. */
        if (len >= 13) {
            uint8_t tok = buf[len - 13];
            if (tok == TDS_TOK_DONE || tok == TDS_TOK_DONEPROC || tok == TDS_TOK_DONEINPROC) {
                uint16_t status = (uint16_t)buf[len-12] | ((uint16_t)buf[len-11] << 8);
                if (!(status & 0x0001)) break;  /* DONE_MORE not set */
            }
        }
        /* Safety: cap at 4MB */
        if (len > 4 * 1024 * 1024) break;
    }
    *out_buf = buf;
    *out_len = len;
    return TDS_OK;
}

/* Fixed-length size for "fixed-length type" tokens (no length bytes follow) */
static int fixed_type_size(uint8_t t) {
    switch (t) {
        case TDS_DT_NULL:      return 0;
        case TDS_DT_INT1:      return 1;
        case TDS_DT_BIT:       return 1;
        case TDS_DT_INT2:      return 2;
        case TDS_DT_INT4:      return 4;
        case TDS_DT_INT8:      return 8;
        case TDS_DT_DATETIM4:  return 4;
        case TDS_DT_DATETIME:  return 8;
        case TDS_DT_FLT4:      return 4;
        case TDS_DT_FLT8:      return 8;
        case TDS_DT_MONEY4:    return 4;
        case TDS_DT_MONEY:     return 8;
        default:               return -1;
    }
}

/* Returns 1 if this type uses a 1-byte length prefix in metadata */
static int is_byte_len_type(uint8_t t) {
    switch (t) {
        case TDS_DT_GUID: case TDS_DT_INTN: case TDS_DT_BITN:
        case TDS_DT_DECIMALN: case TDS_DT_NUMERICN: case TDS_DT_FLTN:
        case TDS_DT_MONEYN: case TDS_DT_DATETIMN:
        case TDS_DT_DATEN: case TDS_DT_TIMEN: case TDS_DT_DATETIME2N:
        case TDS_DT_DATETIMEOFFSN:
        case TDS_DT_CHAR: case TDS_DT_VARCHAR:
        case TDS_DT_BINARY: case TDS_DT_VARBINARY:
            return 1;
        default: return 0;
    }
}

/* Returns 1 if this type uses a USHORT length prefix in metadata + collation */
static int is_ushort_len_char_type(uint8_t t) {
    switch (t) {
        case TDS_DT_BIGCHAR: case TDS_DT_BIGVARCHAR:
        case TDS_DT_NCHAR:   case TDS_DT_NVARCHAR:
            return 1;
        default: return 0;
    }
}

static int is_ushort_len_bin_type(uint8_t t) {
    return (t == TDS_DT_BIGBINARY || t == TDS_DT_BIGVARBINARY);
}

static int is_long_len_type(uint8_t t) {
    return (t == TDS_DT_TEXT || t == TDS_DT_NTEXT || t == TDS_DT_IMAGE);
}

/* Decode COLMETADATA: count + per-column metadata.
 * Returns number of bytes consumed from p. */
static int parse_colmetadata(const uint8_t *p, size_t plen,
                             struct tds_result *r, size_t *out_consumed) {
    if (plen < 2) return TDS_ERR_PROTOCOL;
    uint16_t n = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    size_t off = 2;

    /* 0xFFFF means no metadata (rare) */
    if (n == 0xFFFF) {
        r->n_cols = 0;
        *out_consumed = off;
        return TDS_OK;
    }

    if (n > TDS_MAX_COLS) return TDS_ERR_PROTOCOL;
    r->n_cols = n;

    for (uint16_t i = 0; i < n; ++i) {
        if (off + 6 > plen) return TDS_ERR_PROTOCOL;
        tds_col_t *col = &r->cols[i];
        X_memset(col, 0, sizeof(*col));
        col->user_type = (uint32_t)p[off] | ((uint32_t)p[off+1] << 8) | ((uint32_t)p[off+2] << 16) | ((uint32_t)p[off+3] << 24);
        off += 4;
        col->flags = (uint16_t)p[off] | ((uint16_t)p[off+1] << 8);
        off += 2;
        if (off >= plen) return TDS_ERR_PROTOCOL;
        col->type = p[off++];

        int fs = fixed_type_size(col->type);
        if (fs >= 0) {
            col->type_size = (uint32_t)fs;
        } else if (is_byte_len_type(col->type)) {
            if (off >= plen) return TDS_ERR_PROTOCOL;
            col->type_size = p[off++];
            /* DECIMAL/NUMERIC have additional precision+scale */
            if (col->type == TDS_DT_DECIMALN || col->type == TDS_DT_NUMERICN) {
                if (off + 2 > plen) return TDS_ERR_PROTOCOL;
                col->precision = p[off++];
                col->scale = p[off++];
            }
            /* DATETIME2/TIME/DATETIMEOFFSET have a scale byte instead */
            if (col->type == TDS_DT_TIMEN || col->type == TDS_DT_DATETIME2N || col->type == TDS_DT_DATETIMEOFFSN) {
                /* the byte we just read was actually scale */
                col->scale = (uint8_t)col->type_size;
                col->type_size = 0;
            }
        } else if (is_ushort_len_char_type(col->type)) {
            if (off + 2 > plen) return TDS_ERR_PROTOCOL;
            col->type_size = (uint32_t)p[off] | ((uint32_t)p[off+1] << 8);
            off += 2;
            /* 5-byte collation */
            if (off + 5 > plen) return TDS_ERR_PROTOCOL;
            off += 5;
        } else if (is_ushort_len_bin_type(col->type)) {
            if (off + 2 > plen) return TDS_ERR_PROTOCOL;
            col->type_size = (uint32_t)p[off] | ((uint32_t)p[off+1] << 8);
            off += 2;
        } else if (is_long_len_type(col->type)) {
            if (off + 4 > plen) return TDS_ERR_PROTOCOL;
            col->type_size = (uint32_t)p[off] | ((uint32_t)p[off+1] << 8) | ((uint32_t)p[off+2] << 16) | ((uint32_t)p[off+3] << 24);
            off += 4;
            if (col->type == TDS_DT_TEXT || col->type == TDS_DT_NTEXT) {
                if (off + 5 > plen) return TDS_ERR_PROTOCOL;
                off += 5;  /* collation */
            }
            /* table name as US_VARCHAR (1 USHORT count + N parts of USHORT-len + chars) */
            if (off + 2 > plen) return TDS_ERR_PROTOCOL;
            uint16_t parts = (uint16_t)p[off] | ((uint16_t)p[off+1] << 8); off += 2;
            for (int pi = 0; pi < parts; ++pi) {
                if (off + 2 > plen) return TDS_ERR_PROTOCOL;
                uint16_t plen2 = (uint16_t)p[off] | ((uint16_t)p[off+1] << 8); off += 2;
                if (off + plen2 * 2 > plen) return TDS_ERR_PROTOCOL;
                off += plen2 * 2;
            }
        } else {
            /* unsupported type */
            return TDS_ERR_PROTOCOL;
        }

        /* Column name: 1-byte len + UTF-16LE chars */
        if (off >= plen) return TDS_ERR_PROTOCOL;
        col->name_len = p[off++];
        if (off + col->name_len * 2 > plen) return TDS_ERR_PROTOCOL;
        for (int j = 0; j < col->name_len && j < 128; ++j) {
            col->name[j] = (wchar_t)p[off + j*2] | ((wchar_t)p[off + j*2 + 1] << 8);
        }
        col->name[col->name_len < 128 ? col->name_len : 128] = 0;
        off += col->name_len * 2;
    }
    *out_consumed = off;
    return TDS_OK;
}

/* Read one cell's variable length prefix and data into a heap allocation.
 * Returns bytes consumed and stores cell. Caller owns cell->data. */
static int parse_cell(const uint8_t *p, size_t plen, const tds_col_t *col,
                      tds_cell_t *cell, size_t *out_consumed) {
    cell->data = NULL; cell->len = 0; cell->is_null = 0;
    size_t off = 0;
    int fs = fixed_type_size(col->type);
    if (fs >= 0) {
        if (off + (size_t)fs > plen) return TDS_ERR_PROTOCOL;
        cell->len = fs;
        cell->data = (uint8_t*)X_malloc(fs ? fs : 1);
        if (!cell->data) return TDS_ERR_ALLOC;
        X_memcpy(cell->data, p, fs);
        off += fs;
    } else if (is_byte_len_type(col->type)) {
        if (off + 1 > plen) return TDS_ERR_PROTOCOL;
        uint8_t l = p[off++];
        if (l == 0 || (l == 0xFF && (col->type == TDS_DT_INTN || col->type == TDS_DT_BITN ||
                                      col->type == TDS_DT_FLTN || col->type == TDS_DT_MONEYN ||
                                      col->type == TDS_DT_DATETIMN || col->type == TDS_DT_GUID ||
                                      col->type == TDS_DT_DECIMALN || col->type == TDS_DT_NUMERICN))) {
            cell->is_null = 1;
        } else {
            if (off + l > plen) return TDS_ERR_PROTOCOL;
            cell->len = l;
            cell->data = (uint8_t*)X_malloc(l ? l : 1);
            if (!cell->data) return TDS_ERR_ALLOC;
            X_memcpy(cell->data, p + off, l);
            off += l;
        }
    } else if (is_ushort_len_char_type(col->type) || is_ushort_len_bin_type(col->type)) {
        if (off + 2 > plen) return TDS_ERR_PROTOCOL;
        uint16_t l = (uint16_t)p[off] | ((uint16_t)p[off+1] << 8); off += 2;
        if (l == 0xFFFF) {
            cell->is_null = 1;
        } else {
            if (off + l > plen) return TDS_ERR_PROTOCOL;
            cell->len = l;
            cell->data = (uint8_t*)X_malloc(l ? l : 1);
            if (!cell->data) return TDS_ERR_ALLOC;
            X_memcpy(cell->data, p + off, l);
            off += l;
        }
    } else if (is_long_len_type(col->type)) {
        /* TEXT/NTEXT/IMAGE: 1-byte text pointer length, then ptr+ts+data
         * (or 0 = NULL) */
        if (off + 1 > plen) return TDS_ERR_PROTOCOL;
        uint8_t tplen = p[off++];
        if (tplen == 0) {
            cell->is_null = 1;
        } else {
            if (off + tplen + 8 + 4 > plen) return TDS_ERR_PROTOCOL;
            off += tplen;  /* skip ptr */
            off += 8;      /* skip timestamp */
            uint32_t dlen = (uint32_t)p[off] | ((uint32_t)p[off+1] << 8) |
                            ((uint32_t)p[off+2] << 16) | ((uint32_t)p[off+3] << 24);
            off += 4;
            if (off + dlen > plen) return TDS_ERR_PROTOCOL;
            cell->len = (int)dlen;
            cell->data = (uint8_t*)X_malloc(dlen ? dlen : 1);
            if (!cell->data) return TDS_ERR_ALLOC;
            X_memcpy(cell->data, p + off, dlen);
            off += dlen;
        }
    } else {
        return TDS_ERR_PROTOCOL;
    }
    *out_consumed = off;
    return TDS_OK;
}

static int append_row(struct tds_result *r, const uint8_t *p, size_t plen,
                      int is_nbc, size_t *out_consumed) {
    size_t off = 0;
    int *null_bits = NULL;

    if (is_nbc) {
        size_t bm_bytes = (r->n_cols + 7) / 8;
        if (off + bm_bytes > plen) return TDS_ERR_PROTOCOL;
        null_bits = (int*)X_malloc(sizeof(int) * r->n_cols);
        if (!null_bits) return TDS_ERR_ALLOC;
        for (int i = 0; i < r->n_cols; ++i) {
            null_bits[i] = (p[off + i/8] >> (i % 8)) & 1;
        }
        off += bm_bytes;
    }

    struct tds_row_node *rn = (struct tds_row_node*)X_malloc(sizeof(*rn));
    if (!rn) { X_free(null_bits); return TDS_ERR_ALLOC; }
    X_memset(rn, 0, sizeof(*rn));

    for (int i = 0; i < r->n_cols; ++i) {
        if (null_bits && null_bits[i]) {
            rn->cells[i].is_null = 1;
            continue;
        }
        size_t cn;
        int rc = parse_cell(p + off, plen - off, &r->cols[i], &rn->cells[i], &cn);
        if (rc != TDS_OK) {
            for (int k = 0; k < i; ++k) X_free(rn->cells[k].data);
            X_free(rn);
            X_free(null_bits);
            return rc;
        }
        off += cn;
    }

    rn->next = NULL;
    if (!r->row_head) {
        r->row_head = rn;
        r->row_tail = rn;
    } else {
        r->row_tail->next = rn;
        r->row_tail = rn;
    }

    X_free(null_bits);
    *out_consumed = off;
    return TDS_OK;
}

/* Parse an ERROR or INFO token: store message in conn->last_error */
static int parse_error_or_info(struct tds_conn *c, const uint8_t *p, size_t plen,
                               int is_error, size_t *out_consumed) {
    if (plen < 2) return TDS_ERR_PROTOCOL;
    uint16_t total = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    if (2 + total > plen) return TDS_ERR_PROTOCOL;
    /* number(4) state(1) class(1) MsgText: USHORT-len + UTF-16 chars */
    if (total < 8) return TDS_ERR_PROTOCOL;
    size_t off = 2 + 4 + 1 + 1;  /* number + state + class */
    if (off + 2 > 2 + total) return TDS_ERR_PROTOCOL;
    uint16_t mlen = (uint16_t)p[off] | ((uint16_t)p[off+1] << 8); off += 2;
    if (off + mlen * 2 > 2 + total) return TDS_ERR_PROTOCOL;
    if (is_error) {
        size_t i = 0;
        for (; i < (sizeof(c->last_error)/sizeof(wchar_t)) - 1 && i < mlen; ++i) {
            c->last_error[i] = (wchar_t)p[off + i*2] | ((wchar_t)p[off + i*2 + 1] << 8);
        }
        c->last_error[i] = 0;
    }
    *out_consumed = 2 + total;
    return TDS_OK;
}

int tds_parse_response(struct tds_conn *c, struct tds_result *r) {
    uint8_t *buf = NULL;
    size_t   blen = 0;
    int rc = slurp_response(c, &buf, &blen);
    if (rc != TDS_OK) return rc;

    size_t off = 0;
    int saw_error = 0;
    while (off < blen) {
        uint8_t tok = buf[off++];
        size_t consumed = 0;
        switch (tok) {
            case TDS_TOK_COLMETADATA:
                rc = parse_colmetadata(buf + off, blen - off, r, &consumed);
                if (rc != TDS_OK) goto cleanup;
                off += consumed;
                break;
            case TDS_TOK_ROW:
                rc = append_row(r, buf + off, blen - off, 0, &consumed);
                if (rc != TDS_OK) goto cleanup;
                off += consumed;
                break;
            case TDS_TOK_NBCROW:
                rc = append_row(r, buf + off, blen - off, 1, &consumed);
                if (rc != TDS_OK) goto cleanup;
                off += consumed;
                break;
            case TDS_TOK_DONE:
            case TDS_TOK_DONEPROC:
            case TDS_TOK_DONEINPROC:
                if (off + 12 > blen) { rc = TDS_ERR_PROTOCOL; goto cleanup; }
                off += 12;  /* status(2) curcmd(2) rowcount(8) */
                break;
            case TDS_TOK_ENVCHANGE: {
                if (off + 2 > blen) { rc = TDS_ERR_PROTOCOL; goto cleanup; }
                uint16_t l = (uint16_t)buf[off] | ((uint16_t)buf[off+1] << 8);
                off += 2 + l;
                break;
            }
            case TDS_TOK_INFO:
                rc = parse_error_or_info(c, buf + off, blen - off, 0, &consumed);
                if (rc != TDS_OK) goto cleanup;
                off += consumed;
                break;
            case TDS_TOK_ERROR:
                rc = parse_error_or_info(c, buf + off, blen - off, 1, &consumed);
                if (rc != TDS_OK) goto cleanup;
                off += consumed;
                saw_error = 1;
                break;
            case TDS_TOK_LOGINACK: {
                if (off + 2 > blen) { rc = TDS_ERR_PROTOCOL; goto cleanup; }
                uint16_t l = (uint16_t)buf[off] | ((uint16_t)buf[off+1] << 8);
                off += 2 + l;
                break;
            }
            case TDS_TOK_ORDER: {
                if (off + 2 > blen) { rc = TDS_ERR_PROTOCOL; goto cleanup; }
                uint16_t l = (uint16_t)buf[off] | ((uint16_t)buf[off+1] << 8);
                off += 2 + l;
                break;
            }
            case TDS_TOK_RETURNSTATUS:
                if (off + 4 > blen) { rc = TDS_ERR_PROTOCOL; goto cleanup; }
                off += 4;
                break;
            case TDS_TOK_RETURNVALUE: {
                /* Skip — not used in v1 */
                if (off + 4 > blen) { rc = TDS_ERR_PROTOCOL; goto cleanup; }
                /* parameter ord(2) + name (1+chars) + status(1) + UserType(4) +
                   Flags(2) + TYPE_INFO + TYPE_VARBYTE — we don't need this for SELECT */
                /* Punt: bail with protocol error so we know we need to add it. */
                rc = TDS_ERR_PROTOCOL;
                goto cleanup;
            }
            case TDS_TOK_SSPI: {
                /* SSPI continuation: 2-byte length + raw token bytes.
                 * Stash on conn so connect.c can pump the next leg. */
                if (off + 2 > blen) { rc = TDS_ERR_PROTOCOL; goto cleanup; }
                uint16_t l = (uint16_t)buf[off] | ((uint16_t)buf[off+1] << 8);
                off += 2;
                if (off + l > blen) { rc = TDS_ERR_PROTOCOL; goto cleanup; }
                if (c->sspi_in_buf) { X_free(c->sspi_in_buf); c->sspi_in_buf = NULL; }
                c->sspi_in_buf = (uint8_t*)X_malloc(l);
                if (!c->sspi_in_buf) { rc = TDS_ERR_ALLOC; goto cleanup; }
                X_memcpy(c->sspi_in_buf, buf + off, l);
                c->sspi_in_len = l;
                off += l;
                break;
            }
            default:
                tds_set_error_a(c, "unknown TDS token: 0x%02x at offset %zu", tok, off-1);
                rc = TDS_ERR_PROTOCOL;
                goto cleanup;
        }
    }

    rc = saw_error ? TDS_ERR_SERVER : TDS_OK;
cleanup:
    X_free(buf);
    return rc;
}
