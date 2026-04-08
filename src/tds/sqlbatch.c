/*
 * SQLBatch (0x01) request — [MS-TDS] §2.2.1.7
 *
 * In TDS 7.4 the SQLBatch payload is preceded by an ALL_HEADERS structure
 * containing at least a transaction descriptor header. Then the SQL text
 * in UTF-16LE. No null terminator.
 *
 * ALL_HEADERS layout:
 *   4 bytes  total length (including this field itself)
 *   per header:
 *     4 bytes  header length (including this field)
 *     2 bytes  header type
 *     header data
 *
 * Transaction descriptor header (type 0x0002):
 *   8 bytes  transaction descriptor (0)
 *   4 bytes  outstanding request count (1)
 */

#include "tds_internal.h"

#ifdef _WIN32
  #include "../common/dynimports.h"
  #define X_memset MSVCRT$memset
  #define X_wcslen MSVCRT$wcslen
#else
  #include <string.h>
  #include <wchar.h>
  #include <stdlib.h>
  #define X_memset memset
  #define X_wcslen wcslen
#endif

int tds_sqlbatch_send(struct tds_conn *c, const wchar_t *sql) {
    if (!sql) return TDS_ERR_ARG;
    size_t sql_chars = X_wcslen(sql);
    size_t pktlen = 22 + sql_chars * 2;
    if (pktlen > TDS_MAX_PACKET_SIZE) return TDS_ERR_PROTOCOL;

#ifdef _WIN32
    uint8_t *pkt = (uint8_t*)MSVCRT$malloc(pktlen);
#else
    uint8_t *pkt = (uint8_t*)malloc(pktlen);
#endif
    if (!pkt) return TDS_ERR_ALLOC;
    X_memset(pkt, 0, pktlen);

    /* ALL_HEADERS = 4 + (4 + 2 + 12) = 22 bytes */
    uint32_t total_headers = 22;
    pkt[0] = (uint8_t)(total_headers       & 0xff);
    pkt[1] = (uint8_t)((total_headers >> 8) & 0xff);
    pkt[2] = (uint8_t)((total_headers >> 16) & 0xff);
    pkt[3] = (uint8_t)((total_headers >> 24) & 0xff);

    /* Transaction descriptor header */
    uint32_t hdr_len = 18;
    pkt[4] = (uint8_t)(hdr_len & 0xff);
    pkt[5] = (uint8_t)((hdr_len >> 8) & 0xff);
    pkt[6] = (uint8_t)((hdr_len >> 16) & 0xff);
    pkt[7] = (uint8_t)((hdr_len >> 24) & 0xff);
    pkt[8]  = 0x02;  /* TX descriptor type */
    pkt[9]  = 0x00;
    /* 8 bytes TX descriptor = 0 */
    X_memset(pkt + 10, 0, 8);
    /* 4 bytes outstanding requests = 1 */
    pkt[18] = 0x01; pkt[19] = 0x00; pkt[20] = 0x00; pkt[21] = 0x00;

    /* SQL text in UTF-16LE */
    size_t pos = 22;
    for (size_t i = 0; i < sql_chars; ++i) {
        uint16_t cp = (uint16_t)(sql[i] & 0xFFFF);
        pkt[pos++] = (uint8_t)(cp & 0xff);
        pkt[pos++] = (uint8_t)(cp >> 8);
    }

    int rc = tds_packet_send(c, TDS_TYPE_SQLBATCH, pkt, pos);
#ifdef _WIN32
    MSVCRT$free(pkt);
#else
    free(pkt);
#endif
    return rc;
}
