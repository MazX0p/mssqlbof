/*
 * LOGIN7 packet — [MS-TDS] §2.2.6.4
 *
 * Layout:
 *   Fixed header (36 bytes):
 *     4   length            (entire packet)
 *     4   TDS version       (0x74000004 = TDS 7.4)
 *     4   packet size       (4096)
 *     4   client program version
 *     4   client PID
 *     4   connection ID     (0)
 *     1   option flags 1
 *     1   option flags 2    (bit 7 = fIntSecurity, set for SSPI)
 *     1   type flags
 *     1   option flags 3
 *     4   client time zone
 *     4   client LCID
 *
 *   Offset/length table (58 bytes for the standard 14 entries):
 *     For each variable section: 2-byte offset (from start of LOGIN7) + 2-byte length-in-chars
 *     Order: hostname, username, password, appname, servername, extension(unused, 0),
 *            cltintname, language, database, clientid(6 bytes raw), sspi, atchdbfile,
 *            changepassword, sspilong(4 bytes)
 *
 *   Then the variable data section with all UTF-16LE strings.
 *
 * Password is "obfuscated" with nibble-swap + XOR 0xA5 per byte (per spec).
 */

#include "tds_internal.h"

#ifdef _WIN32
  #include "../common/dynimports.h"
  #define X_memset MSVCRT$memset
  #define X_memcpy MSVCRT$memcpy
  #define X_wcslen MSVCRT$wcslen
#else
  #include <string.h>
  #include <wchar.h>
  #include <stdlib.h>
  #define X_memset memset
  #define X_memcpy memcpy
  #define X_wcslen wcslen
#endif

/* Convert UCS-2/wchar to UTF-16LE buffer (pure C, no Windows API).
 * Linux wchar_t is 32-bit; we truncate to BMP. Returns chars written. */
static size_t wide_to_utf16le(const wchar_t *in, uint8_t *out) {
    size_t n = 0;
    if (!in) return 0;
    for (; in[n]; ++n) {
        uint16_t cp = (uint16_t)(in[n] & 0xFFFF);
        out[n*2 + 0] = (uint8_t)(cp & 0xff);
        out[n*2 + 1] = (uint8_t)(cp >> 8);
    }
    return n;
}

static void password_obfuscate(uint8_t *buf, size_t bytes) {
    for (size_t i = 0; i < bytes; ++i) {
        uint8_t b = buf[i];
        buf[i] = (uint8_t)(((b >> 4) | (b << 4)) ^ 0xA5);
    }
}

/* Append a wide string at append_pos (in bytes), returns new pos.
 * out_offset/out_chars are filled into the offset/length table fields. */
static size_t append_wide(uint8_t *pkt, size_t *append_pos,
                          const wchar_t *s, uint16_t *out_offset, uint16_t *out_chars,
                          int obfuscate) {
    size_t off = *append_pos;
    size_t n = wide_to_utf16le(s ? s : L"", pkt + off);
    if (obfuscate) password_obfuscate(pkt + off, n * 2);
    *out_offset = (uint16_t)off;
    *out_chars  = (uint16_t)n;
    *append_pos = off + n * 2;
    return *append_pos;
}

int tds_login7_send(struct tds_conn *c, const wchar_t *database) {
    /* Use malloc + manual zero instead of calloc — calloc was causing
     * COFFLoader to crash on SRV02 for reasons I don't yet understand. */
#ifdef _WIN32
    uint8_t *pkt = (uint8_t*)MSVCRT$malloc(16384);
#else
    uint8_t *pkt = (uint8_t*)malloc(16384);
#endif
    if (!pkt) return TDS_ERR_ALLOC;
    X_memset(pkt, 0, 16384);

    const wchar_t *user = NULL, *pass = NULL;
    uint8_t *sspi_token = NULL;
    size_t   sspi_len = 0;
    int      use_sspi = 0;

#ifdef TDS_LINUX_TEST
    tds_sql_auth_credentials(&user, &pass);
#else
    /* Dispatch on c->auth_mode set by tds_connect_ex.
     *   TDS_AUTH_SSPI_CURRENT  — Negotiate with NULL creds (thread token)
     *   TDS_AUTH_SSPI_EXPLICIT — NTLM with explicit user/domain/pass
     *   TDS_AUTH_SQL           — SQL auth, user/pass embedded in LOGIN7
     */
    if (c->auth_mode == TDS_AUTH_SQL) {
        user = c->auth_user;
        pass = c->auth_pass;
        use_sspi = 0;
    } else if (c->auth_mode == TDS_AUTH_NTLM_HASH) {
        /* Manual NTLMv2: build Type 1 NEGOTIATE ourselves, skip SSPI. */
        static uint8_t type1_buf[48];
        int n = ntlm_pth_build_type1(type1_buf, sizeof(type1_buf));
        if (n < 0) { MSVCRT$free(pkt); return TDS_ERR_AUTH; }
        sspi_token = type1_buf;
        sspi_len   = (size_t)n;
        use_sspi   = 1;
    } else {
        int sspi_done = 0;
        int rc_sspi;
        if (c->auth_mode == TDS_AUTH_SSPI_EXPLICIT) {
            rc_sspi = tds_sspi_init_explicit(c, c->auth_user, c->auth_domain, c->auth_pass);
        } else {
            rc_sspi = tds_sspi_init(c, c->target_host);
        }
        if (rc_sspi != TDS_OK) return rc_sspi;
        rc_sspi = tds_sspi_step(c, NULL, 0, &sspi_token, &sspi_len, &sspi_done);
        if (rc_sspi != TDS_OK || !sspi_token || sspi_len == 0) {
            tds_sspi_free(c);
            return TDS_ERR_AUTH;
        }
        use_sspi = 1;
    }
#endif

    const size_t hdr_size      = 36;
    const size_t offtbl_size   = 58;   /* 14 entries × 4 bytes + 6-byte ClientID + 4-byte SSPILong */
    const size_t var_start     = hdr_size + offtbl_size;

    size_t pos = var_start;

    /* Offset/length table layout */
    uint16_t off_hostname, len_hostname;
    uint16_t off_user,     len_user;
    uint16_t off_pass,     len_pass;
    uint16_t off_appname,  len_appname;
    uint16_t off_servername, len_servername;
    uint16_t off_unused,   len_unused = 0;
    uint16_t off_cltintname, len_cltintname;
    uint16_t off_language, len_language;
    uint16_t off_database, len_database;
    uint16_t off_sspi, len_sspi;
    uint16_t off_atchdb, len_atchdb;
    uint16_t off_chgpw, len_chgpw;

    append_wide(pkt, &pos, L"client",       &off_hostname,   &len_hostname,   0);
    append_wide(pkt, &pos, user,            &off_user,       &len_user,       0);
    append_wide(pkt, &pos, pass,            &off_pass,       &len_pass,       1);
    append_wide(pkt, &pos, L"mssqlbof",     &off_appname,    &len_appname,    0);
    append_wide(pkt, &pos, L"",             &off_servername, &len_servername, 0);
    off_unused = (uint16_t)pos;
    append_wide(pkt, &pos, L"mssqlbof",     &off_cltintname, &len_cltintname, 0);
    append_wide(pkt, &pos, L"",             &off_language,   &len_language,   0);
    append_wide(pkt, &pos, database ? database : L"", &off_database, &len_database, 0);

    /* SSPI option: populated only for Windows SSPI builds. */
    off_sspi = (uint16_t)pos;
    if (use_sspi && sspi_token && sspi_len > 0) {
        if (pos + sspi_len > 16384 - 256) {
#ifdef _WIN32
            MSVCRT$free(pkt);
#else
            free(pkt);
#endif
            return TDS_ERR_PROTOCOL;
        }
#ifdef _WIN32
        MSVCRT$memcpy(pkt + pos, sspi_token, sspi_len);
#else
        memcpy(pkt + pos, sspi_token, sspi_len);
#endif
        pos += sspi_len;
        len_sspi = (uint16_t)sspi_len;
    } else {
        len_sspi = 0;
    }
    append_wide(pkt, &pos, L"", &off_atchdb, &len_atchdb, 0);
    append_wide(pkt, &pos, L"", &off_chgpw,  &len_chgpw,  0);

    size_t total = pos;
    if (total > 16384) {
#ifdef _WIN32
        MSVCRT$free(pkt);
#else
        free(pkt);
#endif
        return TDS_ERR_PROTOCOL;
    }

    /* ---- Fixed header ---- */
    uint32_t *u32 = (uint32_t*)pkt;
    u32[0] = (uint32_t)total;          /* Length */
    u32[1] = 0x74000004;               /* TDS 7.4 */
    u32[2] = 4096;                     /* PacketSize */
    u32[3] = 0x07000000;               /* ClientProgVer */
    u32[4] = 1234;                     /* ClientPID */
    u32[5] = 0;                        /* ConnectionID */
    pkt[24] = 0x00;                    /* OptionFlags1 */
    pkt[25] = use_sspi ? 0x80 : 0x00;  /* OptionFlags2: bit 7 = fIntSecurity for SSPI */
    pkt[26] = 0x00;                    /* TypeFlags: SQL_DFLT */
    pkt[27] = 0x00;                    /* OptionFlags3 */
    u32[7]  = 0;                       /* ClientTimezone */
    u32[8]  = 0x00000409;              /* ClientLCID = en-US */

    /* ---- Offset/length table @ offset 36 ---- */
    uint8_t *t = pkt + hdr_size;
    #define PUT16(buf, off, v) do { (buf)[(off)+0] = (uint8_t)((v)&0xff); (buf)[(off)+1] = (uint8_t)(((v)>>8)&0xff); } while(0)
    PUT16(t,  0, off_hostname);    PUT16(t,  2, len_hostname);
    PUT16(t,  4, off_user);        PUT16(t,  6, len_user);
    PUT16(t,  8, off_pass);        PUT16(t, 10, len_pass);
    PUT16(t, 12, off_appname);     PUT16(t, 14, len_appname);
    PUT16(t, 16, off_servername);  PUT16(t, 18, len_servername);
    PUT16(t, 20, off_unused);      PUT16(t, 22, len_unused);
    PUT16(t, 24, off_cltintname);  PUT16(t, 26, len_cltintname);
    PUT16(t, 28, off_language);    PUT16(t, 30, len_language);
    PUT16(t, 32, off_database);    PUT16(t, 34, len_database);
    /* ClientID 6 raw bytes */
    t[36] = 0x00; t[37] = 0x50; t[38] = 0x56;
    t[39] = 0x00; t[40] = 0x00; t[41] = 0x01;
    PUT16(t, 42, off_sspi);        PUT16(t, 44, len_sspi);
    PUT16(t, 46, off_atchdb);      PUT16(t, 48, len_atchdb);
    PUT16(t, 50, off_chgpw);       PUT16(t, 52, len_chgpw);
    /* SSPILong 4 bytes (used when SSPI > 64K — we set 0) */
    t[54] = t[55] = t[56] = t[57] = 0;
    #undef PUT16

    int send_rc = tds_packet_send(c, TDS_TYPE_LOGIN7, pkt, total);
#ifdef _WIN32
    MSVCRT$free(pkt);
#else
    free(pkt);
#endif
    return send_rc;
}

#ifdef TDS_LINUX_TEST
/* SQL auth fallback for the Linux test path. Picked up from env vars so the
 * test fixtures can override per case. */
int tds_sql_auth_credentials(const wchar_t **user, const wchar_t **pass) {
    static wchar_t u[64];
    static wchar_t p[64];
    const char *eu = getenv("TDS_TEST_USER");
    const char *ep = getenv("TDS_TEST_PASS");
    if (!eu) eu = "sa";
    if (!ep) ep = "TestP@ss123!";
    size_t i;
    for (i = 0; i < 63 && eu[i]; ++i) u[i] = (wchar_t)(unsigned char)eu[i]; u[i] = 0;
    for (i = 0; i < 63 && ep[i]; ++i) p[i] = (wchar_t)(unsigned char)ep[i]; p[i] = 0;
    *user = u; *pass = p;
    return TDS_OK;
}
#endif
