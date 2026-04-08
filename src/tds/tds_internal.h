#ifndef MSSQLBOF_TDS_INTERNAL_H
#define MSSQLBOF_TDS_INTERNAL_H

#include "tds.h"
#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #define SECURITY_WIN32
  #include <sspi.h>
  #include <schannel.h>
  typedef SOCKET tds_socket_t;
  #define TDS_INVALID_SOCK INVALID_SOCKET
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <errno.h>
  typedef int tds_socket_t;
  #define TDS_INVALID_SOCK (-1)
#endif

/* TDS packet types — [MS-TDS] §2.2.3.1.1 */
#define TDS_TYPE_SQLBATCH    0x01
#define TDS_TYPE_LOGIN7      0x10
#define TDS_TYPE_RPC         0x03
#define TDS_TYPE_TABULAR     0x04
#define TDS_TYPE_PRELOGIN    0x12
#define TDS_TYPE_SSPI        0x11

/* Packet status flags */
#define TDS_STATUS_NORMAL        0x00
#define TDS_STATUS_EOM           0x01
#define TDS_STATUS_IGNORE        0x02
#define TDS_STATUS_RESETCONN     0x08
#define TDS_STATUS_RESETCONN_SK  0x10

/* PRELOGIN option tokens — [MS-TDS] §2.2.6.5 */
#define TDS_PL_VERSION    0x00
#define TDS_PL_ENCRYPT    0x01
#define TDS_PL_INSTOPT    0x02
#define TDS_PL_THREADID   0x03
#define TDS_PL_MARS       0x04
#define TDS_PL_TRACEID    0x05
#define TDS_PL_FEDAUTH    0x06
#define TDS_PL_NONCEOPT   0x07
#define TDS_PL_TERMINATOR 0xFF

/* PRELOGIN encryption negotiation values */
#define TDS_ENCRYPT_OFF      0x00  /* client wants off, server may upgrade */
#define TDS_ENCRYPT_ON       0x01  /* client wants on,  server must accept */
#define TDS_ENCRYPT_NOT_SUP  0x02  /* peer does not support encryption */
#define TDS_ENCRYPT_REQ      0x03  /* peer requires encryption */
#define TDS_ENCRYPT_CLI_CERT 0x80  /* client cert flag, ORed with above */

/* TDS data stream tokens — [MS-TDS] §2.2.7 */
#define TDS_TOK_ALTMETADATA  0x88
#define TDS_TOK_ALTROW       0xD3
#define TDS_TOK_COLMETADATA  0x81
#define TDS_TOK_COLINFO      0xA5
#define TDS_TOK_DONE         0xFD
#define TDS_TOK_DONEPROC     0xFE
#define TDS_TOK_DONEINPROC   0xFF
#define TDS_TOK_ENVCHANGE    0xE3
#define TDS_TOK_ERROR        0xAA
#define TDS_TOK_INFO         0xAB
#define TDS_TOK_LOGINACK     0xAD
#define TDS_TOK_NBCROW       0xD2
#define TDS_TOK_OFFSET       0x78
#define TDS_TOK_ORDER        0xA9
#define TDS_TOK_RETURNSTATUS 0x79
#define TDS_TOK_RETURNVALUE  0xAC
#define TDS_TOK_ROW          0xD1
#define TDS_TOK_TABNAME      0xA4
#define TDS_TOK_SSPI         0xED  /* SSPI continuation token, [MS-TDS] §2.2.7.21 */

/* TDS data type tokens — [MS-TDS] §2.2.5.4.1 / §2.2.5.5.1 */
#define TDS_DT_NULL          0x1F
#define TDS_DT_INT1          0x30
#define TDS_DT_BIT           0x32
#define TDS_DT_INT2          0x34
#define TDS_DT_INT4          0x38
#define TDS_DT_DATETIM4      0x3A
#define TDS_DT_FLT4          0x3B
#define TDS_DT_MONEY         0x3C
#define TDS_DT_DATETIME      0x3D
#define TDS_DT_FLT8          0x3E
#define TDS_DT_MONEY4        0x7A
#define TDS_DT_INT8          0x7F
#define TDS_DT_GUID          0x24
#define TDS_DT_INTN          0x26
#define TDS_DT_BITN          0x68
#define TDS_DT_DECIMALN      0x6A
#define TDS_DT_NUMERICN      0x6C
#define TDS_DT_FLTN          0x6D
#define TDS_DT_MONEYN        0x6E
#define TDS_DT_DATETIMN      0x6F
#define TDS_DT_DATEN         0x28
#define TDS_DT_TIMEN         0x29
#define TDS_DT_DATETIME2N    0x2A
#define TDS_DT_DATETIMEOFFSN 0x2B
#define TDS_DT_CHAR          0x2F
#define TDS_DT_VARCHAR       0x27
#define TDS_DT_BINARY        0x2D
#define TDS_DT_VARBINARY     0x25
#define TDS_DT_BIGVARBINARY  0xA5
#define TDS_DT_BIGVARCHAR    0xA7
#define TDS_DT_BIGBINARY     0xAD
#define TDS_DT_BIGCHAR       0xAF
#define TDS_DT_NVARCHAR      0xE7
#define TDS_DT_NCHAR         0xEF
#define TDS_DT_XML           0xF1
#define TDS_DT_UDT           0xF0
#define TDS_DT_TEXT          0x23
#define TDS_DT_IMAGE         0x22
#define TDS_DT_NTEXT         0x63
#define TDS_DT_SSVARIANT     0x62

/* Packet header — 8 bytes, fields are network byte order */
#pragma pack(push, 1)
typedef struct {
    uint8_t  type;
    uint8_t  status;
    uint16_t length;
    uint16_t spid;
    uint8_t  packet_id;
    uint8_t  window;
} tds_header_t;
#pragma pack(pop)

#define TDS_HEADER_SIZE          8
#define TDS_DEFAULT_PACKET_SIZE  4096
#define TDS_MAX_PACKET_SIZE      32767

/* Forward decls for column metadata + row buffer */
typedef struct {
    uint32_t  user_type;
    uint16_t  flags;
    uint8_t   type;          /* TDS_DT_* */
    uint32_t  type_size;     /* declared length for variable types, else 0 */
    uint8_t   precision;
    uint8_t   scale;
    uint16_t  collation_lcid;
    uint8_t   collation_flags;
    uint8_t   collation_charset;
    uint8_t   collation_sortid;
    wchar_t   name[129];
    uint8_t   name_len;
} tds_col_t;

#define TDS_MAX_COLS 256

typedef struct {
    int       len;
    int       is_null;
    uint8_t  *data;       /* heap, owned */
} tds_cell_t;

struct tds_row_node {
    tds_cell_t           cells[TDS_MAX_COLS];
    struct tds_row_node *next;
};

struct tds_result {
    struct tds_conn *conn;
    int       n_cols;
    tds_col_t cols[TDS_MAX_COLS];
    tds_cell_t row[TDS_MAX_COLS];   /* current row for the iterator */
    int       have_row;
    int       eof;
    int       error;
    struct tds_row_node *row_head;
    struct tds_row_node *row_tail;
    struct tds_row_node *row_cur;   /* iterator position */
};

/* TLS state — opaque to most code, defined in tls_*.c */
typedef struct tds_tls tds_tls_t;

/* TLS state machine for the asymmetric SQL Server quirk:
 *   NONE       — plain TDS, no TLS layer
 *   HANDSHAKE  — TLS records wrapped in TDS PRELOGIN packets (handshake only)
 *   RAW_TLS    — TLS application data records sent raw on the wire
 */
#define TDS_TLS_STATE_NONE      0
#define TDS_TLS_STATE_HANDSHAKE 1
#define TDS_TLS_STATE_RAW_TLS   2

struct tds_conn {
    tds_socket_t sock;
    uint8_t      packet_id;
    uint8_t      negotiated_encryption;
    int          tls_send_state;      /* TDS_TLS_STATE_* — applies to outbound */
    int          tls_recv_state;      /* TDS_TLS_STATE_* — applies to inbound */
    int          tls_login_only;      /* 1 = TLS only during login phase */
    int          tls_active;          /* legacy, set when any TLS state is non-NONE */
    tds_tls_t   *tls;
    wchar_t      last_error[512];
    /* Read buffer for current incoming packet payload */
    uint8_t      rx_buf[TDS_MAX_PACKET_SIZE];
    size_t       rx_len;
    size_t       rx_pos;
    uint8_t      rx_status;          /* status byte from last packet header (EOM=0x01) */
    /* Connection metadata captured from server */
    uint8_t      server_version[4];
    wchar_t      server_name[129];
    /* Target host (used to build MSSQLSvc SPN for SSPI) */
    wchar_t      target_host[256];
    uint16_t     target_port;
    /* Auth config stashed from tds_connect_ex and consumed by login7 */
    int          auth_mode;
    wchar_t      auth_user[128];
    wchar_t      auth_pass[128];
    wchar_t      auth_domain[64];
    /* NTLM hash for pass-the-hash (32-char hex). Empty if unused. */
    char         auth_hash[64];
    /* SSPI continuation buffer captured from server's TDS_TOK_SSPI 0xED.
     * Heap-allocated via MSVCRT$malloc, freed in tds_close. */
    uint8_t     *sspi_in_buf;
    size_t       sspi_in_len;
    /* Active result, for cleanup on close */
    struct tds_result *active_result;
};

/* ---- internal API exposed across .c files ---- */

/* packet.c */
int  tds_socket_open (struct tds_conn *c, const char *host, uint16_t port);
void tds_socket_close(struct tds_conn *c);
int  tds_packet_send (struct tds_conn *c, uint8_t type, const uint8_t *payload, size_t len);
int  tds_packet_recv (struct tds_conn *c);   /* fills c->rx_buf, c->rx_len */
int  tds_raw_send    (struct tds_conn *c, const uint8_t *data, size_t len);
int  tds_raw_recv    (struct tds_conn *c, uint8_t *out, size_t want);

/* prelogin.c */
int  tds_prelogin_exchange(struct tds_conn *c);

/* tls_*.c */
int  tds_tls_init     (struct tds_conn *c, const wchar_t *host);
int  tds_tls_handshake(struct tds_conn *c);
int  tds_tls_send     (struct tds_conn *c, const uint8_t *data, size_t len);
int  tds_tls_recv     (struct tds_conn *c, uint8_t *out, size_t want);
void tds_tls_free     (struct tds_conn *c);

/* login7.c */
int  tds_login7_send(struct tds_conn *c, const wchar_t *database);

/* sspi.c / sspi_stub.c */
int  tds_sspi_init       (struct tds_conn *c, const wchar_t *target_spn);
/* Explicit NTLM credentials. If user/domain/pass are all NULL, falls back
 * to current thread token (same as tds_sspi_init). */
int  tds_sspi_init_explicit(struct tds_conn *c,
                            const wchar_t   *user,
                            const wchar_t   *domain,
                            const wchar_t   *pass);
int  tds_sspi_step       (struct tds_conn *c, const uint8_t *in_token, size_t in_len,
                          uint8_t **out_token, size_t *out_len, int *done);
void tds_sspi_free       (struct tds_conn *c);
/* Linux test stub uses these instead of SSPI */
int  tds_sql_auth_credentials(const wchar_t **user, const wchar_t **pass);

/* ntlm_pth.c — manual NTLMv2 for pass-the-hash */
int  ntlm_pth_parse_hash(const char *in, uint8_t out[16]);
int  ntlm_pth_build_type1(uint8_t *out, size_t outlen);
int  ntlm_pth_build_type3(const uint8_t *type2, size_t type2_len,
                          const uint8_t nt_hash[16],
                          const wchar_t *user, const wchar_t *domain,
                          const wchar_t *workstation,
                          uint8_t **out_buf, size_t *out_len);

/* sqlbatch.c */
int  tds_sqlbatch_send(struct tds_conn *c, const wchar_t *sql);

/* tokens.c */
int  tds_parse_response(struct tds_conn *c, struct tds_result *r);
int  tds_consume_done  (struct tds_conn *c);

/* result.c */
struct tds_result *tds_result_new (struct tds_conn *c);
void               tds_result_clear_row(struct tds_result *r);

/* types.c */
int  tds_decode_col_metadata(const uint8_t *p, size_t plen, tds_col_t *col, size_t *consumed);
int  tds_decode_cell        (const uint8_t *p, size_t plen, const tds_col_t *col,
                             tds_cell_t *cell, size_t *consumed);
int  tds_format_cell        (const tds_col_t *col, const tds_cell_t *cell,
                             wchar_t *out, size_t outlen);

/* internal helpers */
void tds_set_error  (struct tds_conn *c, const wchar_t *fmt, ...);
void tds_set_error_a(struct tds_conn *c, const char *fmt, ...);

#endif
