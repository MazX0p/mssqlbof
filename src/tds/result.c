/*
 * tds_result_t pull-model iterator + tds_query orchestrator.
 *
 * tds_query: send SQLBatch, parse the response into the result, return.
 * tds_result_next_row: advance the iterator, copy the current row's cells
 *                      into r->row, return 1 / 0 / <0.
 * tds_result_get_*: read fields from the current row.
 * tds_result_free: walk the row chain, free everything.
 */

#include "tds_internal.h"

#ifdef _WIN32
  #include "../common/dynimports.h"
  #define X_calloc(n,s) MSVCRT$calloc(n,s)
  #define X_free(p)     MSVCRT$free(p)
  #define X_memset(d,v,n) MSVCRT$memset(d,v,n)
  #define X_memcpy(d,s,n) MSVCRT$memcpy(d,s,n)
#else
  #include <stdlib.h>
  #include <string.h>
  #include <wchar.h>
  #define X_calloc(n,s) calloc(n,s)
  #define X_free(p)     free(p)
  #define X_memset(d,v,n) memset(d,v,n)
  #define X_memcpy(d,s,n) memcpy(d,s,n)
#endif

struct tds_result *tds_result_new(struct tds_conn *c) {
    struct tds_result *r = (struct tds_result*)X_calloc(1, sizeof(*r));
    if (r) r->conn = c;
    return r;
}

int tds_query(tds_conn_t *c, const wchar_t *sql, tds_result_t **out) {
    if (!c || !sql || !out) return TDS_ERR_ARG;

    /* Free any previous active result */
    if (c->active_result) {
        tds_result_free(c->active_result);
        c->active_result = NULL;
    }

    int rc = tds_sqlbatch_send(c, sql);
    if (rc != TDS_OK) return rc;

    struct tds_result *r = tds_result_new(c);
    if (!r) return TDS_ERR_ALLOC;

    rc = tds_parse_response(c, r);
    if (rc != TDS_OK && rc != TDS_ERR_SERVER) {
        tds_result_free(r);
        return rc;
    }

    c->active_result = r;
    *out = r;
    /* If saw_error, last_error is populated. Caller can decide. */
    return rc;  /* TDS_OK or TDS_ERR_SERVER */
}

int tds_result_next_row(tds_result_t *r) {
    if (!r) return TDS_ERR_ARG;
    if (!r->row_cur) {
        r->row_cur = r->row_head;
    } else {
        r->row_cur = r->row_cur->next;
    }
    if (!r->row_cur) {
        r->eof = 1;
        return 0;
    }
    /* Copy cells into r->row[] */
    for (int i = 0; i < r->n_cols; ++i) {
        r->row[i] = r->row_cur->cells[i];
    }
    r->have_row = 1;
    return 1;
}

int tds_result_get_col_count(tds_result_t *r) {
    return r ? r->n_cols : 0;
}

const wchar_t *tds_result_get_col_name(tds_result_t *r, int col) {
    if (!r || col < 0 || col >= r->n_cols) return L"";
    return r->cols[col].name;
}

int tds_result_is_null(tds_result_t *r, int col) {
    if (!r || col < 0 || col >= r->n_cols) return 1;
    return r->row[col].is_null;
}

int tds_result_get_i64(tds_result_t *r, int col, int64_t *out) {
    if (!r || col < 0 || col >= r->n_cols || !out) return TDS_ERR_ARG;
    if (r->row[col].is_null) { *out = 0; return TDS_OK; }
    const tds_col_t *c = &r->cols[col];
    const uint8_t *p = r->row[col].data;
    int len = r->row[col].len;
    switch (c->type) {
        case TDS_DT_INT1: *out = (int8_t)p[0]; return TDS_OK;
        case TDS_DT_BIT:  *out = p[0] ? 1 : 0; return TDS_OK;
        case TDS_DT_INT2: *out = (int16_t)((uint16_t)p[0] | ((uint16_t)p[1]<<8)); return TDS_OK;
        case TDS_DT_INT4: *out = (int32_t)((uint32_t)p[0] | ((uint32_t)p[1]<<8) |
                                           ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24)); return TDS_OK;
        case TDS_DT_INT8: {
            uint64_t v = 0;
            for (int i = 0; i < 8; ++i) v |= ((uint64_t)p[i] << (i*8));
            *out = (int64_t)v; return TDS_OK;
        }
        case TDS_DT_INTN: {
            if (len == 1) { *out = (int8_t)p[0]; return TDS_OK; }
            if (len == 2) { *out = (int16_t)((uint16_t)p[0] | ((uint16_t)p[1]<<8)); return TDS_OK; }
            if (len == 4) { *out = (int32_t)((uint32_t)p[0] | ((uint32_t)p[1]<<8) |
                                              ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24)); return TDS_OK; }
            if (len == 8) {
                uint64_t v = 0;
                for (int i = 0; i < 8; ++i) v |= ((uint64_t)p[i] << (i*8));
                *out = (int64_t)v; return TDS_OK;
            }
            return TDS_ERR_PROTOCOL;
        }
        case TDS_DT_BITN: *out = (len > 0 && p[0]) ? 1 : 0; return TDS_OK;
        default: return TDS_ERR_PROTOCOL;
    }
}

/* Format hex */
static void hex_byte(uint8_t b, wchar_t *out) {
    static const wchar_t H[] = L"0123456789abcdef";
    out[0] = H[b >> 4];
    out[1] = H[b & 0x0f];
}

int tds_result_get_str(tds_result_t *r, int col, wchar_t *buf, size_t buflen) {
    if (!r || col < 0 || col >= r->n_cols || !buf || buflen == 0) return TDS_ERR_ARG;
    if (r->row[col].is_null) { buf[0] = 0; return TDS_OK; }
    const tds_col_t *c = &r->cols[col];
    const uint8_t *p = r->row[col].data;
    int len = r->row[col].len;
    size_t out = 0;

    switch (c->type) {
        case TDS_DT_NCHAR: case TDS_DT_NVARCHAR: case TDS_DT_NTEXT: {
            int chars = len / 2;
            for (int i = 0; i < chars && out < buflen - 1; ++i) {
                buf[out++] = (wchar_t)p[i*2] | ((wchar_t)p[i*2 + 1] << 8);
            }
            buf[out] = 0;
            return TDS_OK;
        }
        case TDS_DT_BIGCHAR: case TDS_DT_BIGVARCHAR: case TDS_DT_CHAR: case TDS_DT_VARCHAR:
        case TDS_DT_TEXT: {
            for (int i = 0; i < len && out < buflen - 1; ++i) buf[out++] = (wchar_t)p[i];
            buf[out] = 0;
            return TDS_OK;
        }
        case TDS_DT_INT1: case TDS_DT_INT2: case TDS_DT_INT4: case TDS_DT_INT8:
        case TDS_DT_INTN: case TDS_DT_BIT: case TDS_DT_BITN: {
            int64_t v = 0;
            int rc = tds_result_get_i64(r, col, &v);
            if (rc != TDS_OK) return rc;
            /* manual int -> wide */
            wchar_t tmp[32]; int ti = 0; int neg = 0;
            uint64_t u;
            if (v < 0) { neg = 1; u = (uint64_t)(-v); } else u = (uint64_t)v;
            if (u == 0) tmp[ti++] = L'0';
            while (u > 0) { tmp[ti++] = L'0' + (u % 10); u /= 10; }
            if (neg) tmp[ti++] = L'-';
            while (ti > 0 && out < buflen - 1) buf[out++] = tmp[--ti];
            buf[out] = 0;
            return TDS_OK;
        }
        case TDS_DT_GUID: {
            /* 16 bytes -> "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" */
            if (len != 16 || buflen < 37) return TDS_ERR_ARG;
            int order[] = {3,2,1,0,-1,5,4,-1,7,6,-1,8,9,-1,10,11,12,13,14,15};
            for (int i = 0; i < 20 && out < buflen - 2; ++i) {
                if (order[i] < 0) { buf[out++] = L'-'; }
                else { hex_byte(p[order[i]], buf + out); out += 2; }
            }
            buf[out] = 0;
            return TDS_OK;
        }
        case TDS_DT_BIGVARBINARY: case TDS_DT_BIGBINARY:
        case TDS_DT_VARBINARY: case TDS_DT_BINARY: case TDS_DT_IMAGE: {
            for (int i = 0; i < len && out < buflen - 3; ++i) {
                hex_byte(p[i], buf + out);
                out += 2;
            }
            buf[out] = 0;
            return TDS_OK;
        }
        default: {
            const wchar_t *u = L"<unsupported>";
            for (int i = 0; u[i] && out < buflen - 1; ++i) buf[out++] = u[i];
            buf[out] = 0;
            return TDS_OK;
        }
    }
}

void tds_result_free(tds_result_t *r) {
    if (!r) return;
    /* If this result is referenced by its owning connection, clear the
     * back-pointer so the next tds_query doesn't double-free. */
    if (r->conn && r->conn->active_result == r) {
        r->conn->active_result = NULL;
    }
    struct tds_row_node *n = r->row_head;
    while (n) {
        struct tds_row_node *next = n->next;
        for (int i = 0; i < TDS_MAX_COLS; ++i) {
            if (n->cells[i].data) X_free(n->cells[i].data);
        }
        X_free(n);
        n = next;
    }
    X_free(r);
}
