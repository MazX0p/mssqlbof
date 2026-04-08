#ifndef MSSQLBOF_TDS_H
#define MSSQLBOF_TDS_H

/*
 * MSSQLBOF — TDS 7.4 protocol public API.
 *
 * The entire BOF suite consumes the protocol layer through the ~10 functions
 * below. The protocol layer is pure C and unit-tested on Linux against a
 * Dockerized SQL Server. On Windows it links Schannel + Secur32 for TLS and
 * SSPI/Negotiate. On Linux it falls back to OpenSSL + SQL auth (test only).
 */

#include <stdint.h>
#include <stddef.h>
#include <wchar.h>

#define TDS_OK              0
#define TDS_ERR_NETWORK    -1
#define TDS_ERR_TLS        -2
#define TDS_ERR_AUTH       -3
#define TDS_ERR_PROTOCOL   -4
#define TDS_ERR_SERVER     -5  /* server-side ERROR token */
#define TDS_ERR_ALLOC      -6
#define TDS_ERR_ARG        -7
#define TDS_ERR_TIMEOUT    -8

typedef struct tds_conn   tds_conn_t;
typedef struct tds_result tds_result_t;

/* Authentication modes */
#define TDS_AUTH_SSPI_CURRENT  0  /* default: current beacon thread token */
#define TDS_AUTH_SSPI_EXPLICIT 1  /* NTLM with explicit user/domain/pass  */
#define TDS_AUTH_SQL           2  /* SQL auth username/password           */
#define TDS_AUTH_NTLM_HASH     3  /* pass-the-hash via manual NTLMv2      */

typedef struct tds_auth {
    int            mode;
    const wchar_t *user;     /* for NTLM + SQL */
    const wchar_t *pass;     /* for NTLM + SQL */
    const wchar_t *domain;   /* for NTLM */
    const char    *hash;     /* 32-char hex NT hash (or "LM:NT") for PTH */
} tds_auth_t;

/*
 * Connect to a SQL Server. On Windows this performs PRELOGIN, optional TLS,
 * LOGIN7 with SSPI/Negotiate using the current thread token. On Linux test
 * builds, falls back to SQL auth using TDS_TEST_USER / TDS_TEST_PASS.
 *
 *   host     - server hostname or IP (UTF-16)
 *   port     - TCP port, typically 1433
 *   instance - named instance (NULL for default)
 *   database - initial DB (NULL for login default)
 *   out      - receives the new connection handle on success
 */
int  tds_connect(const wchar_t *host,
                 uint16_t       port,
                 const wchar_t *instance,
                 const wchar_t *database,
                 tds_conn_t   **out);

/* Like tds_connect but with explicit auth config. NULL auth means
 * TDS_AUTH_SSPI_CURRENT (same as tds_connect). */
int  tds_connect_ex(const wchar_t    *host,
                    uint16_t          port,
                    const wchar_t    *instance,
                    const wchar_t    *database,
                    const tds_auth_t *auth,
                    tds_conn_t      **out);

/*
 * Run a single T-SQL batch. The result handle iterates rows in pull mode.
 * The caller must free the result with tds_result_free before issuing
 * another query on the same connection.
 */
int  tds_query(tds_conn_t    *c,
               const wchar_t *sql,
               tds_result_t **out);

/* Pull-model row iteration. Returns 1 on row, 0 on end-of-rows, <0 on error. */
int            tds_result_next_row     (tds_result_t *r);
int            tds_result_get_col_count(tds_result_t *r);
const wchar_t *tds_result_get_col_name (tds_result_t *r, int col);
int            tds_result_get_str      (tds_result_t *r, int col, wchar_t *buf, size_t buflen);
int            tds_result_get_i64      (tds_result_t *r, int col, int64_t *out);
int            tds_result_is_null      (tds_result_t *r, int col);

void  tds_result_free(tds_result_t *r);
void  tds_close      (tds_conn_t   *c);

const wchar_t *tds_last_error(tds_conn_t *c);

/* Test-only escape hatches. Compiled into the Linux .so for pytest. */
#ifdef TDS_LINUX_TEST
size_t   tds_test_header_size(void);
uint8_t  tds_test_next_packet_id(uint8_t cur);
int      tds_test_open_socket(const wchar_t *host, uint16_t port, tds_conn_t **out);
int      tds_test_send_prelogin(tds_conn_t *c);
int      tds_test_get_negotiated_encryption(tds_conn_t *c);
#endif

#endif
