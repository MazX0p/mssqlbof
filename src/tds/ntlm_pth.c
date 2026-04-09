/*
 * ntlm_pth.c — manual NTLMv2 Pass-The-Hash for SQL Server LOGIN7.
 *
 * SSPI cannot accept an NT hash directly (it only takes plaintext passwords
 * or current thread tokens). To support PTH cleanly without patching lsass,
 * we roll our own NTLMSSP message building and signing here.
 *
 * Flow:
 *   1. ntlm_pth_build_type1   → 40-byte NEGOTIATE_MESSAGE. Goes into the
 *                                SSPI field of the first LOGIN7 packet.
 *   2. ntlm_pth_build_type3   → AUTHENTICATE_MESSAGE. Built from the
 *                                server's CHALLENGE_MESSAGE (Type 2) which
 *                                arrives in the TDS_TOK_SSPI 0xED response.
 *                                Sent in a TDS_TYPE_SSPI (0x11) packet.
 *
 * NTLMv2 computation (MS-NLMP §3.3.2):
 *   NTLMv2Hash   = HMAC_MD5(NTHash, UPPER(user) || domain)      // UTF-16LE
 *   temp         = 0x01 0x01 0x00 0x00  (header)
 *                  0x00 0x00 0x00 0x00  (reserved)
 *                  timestamp(8 LE)
 *                  clientChallenge(8)
 *                  0x00 0x00 0x00 0x00  (reserved)
 *                  targetInfo(N)        (from server Type 2 message)
 *                  0x00 0x00 0x00 0x00  (EOL)
 *   NTProofStr   = HMAC_MD5(NTLMv2Hash, serverChallenge || temp)
 *   NTLMv2Resp   = NTProofStr || temp
 *
 * HMAC-MD5 is done via BCrypt (bcrypt.dll) so we don't need our own
 * crypto.
 */

#ifndef TDS_LINUX_TEST

#include "tds_internal.h"
#include "../common/dynimports.h"

#define NTLMSSP_NEGOTIATE_UNICODE              0x00000001
#define NTLMSSP_REQUEST_TARGET                 0x00000004
#define NTLMSSP_NEGOTIATE_SIGN                 0x00000010
#define NTLMSSP_NEGOTIATE_NTLM                 0x00000200
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN          0x00008000
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSEC  0x00080000
#define NTLMSSP_NEGOTIATE_TARGET_INFO          0x00800000
#define NTLMSSP_NEGOTIATE_VERSION              0x02000000
#define NTLMSSP_NEGOTIATE_128                  0x20000000
#define NTLMSSP_NEGOTIATE_KEY_EXCH             0x40000000
#define NTLMSSP_NEGOTIATE_56                   0x80000000

/* Match Impacket's flag set exactly — SQL Server validates the flags. */
#define NTLMSSP_FLAGS (0xa2880205u)

static const uint8_t NTLMSSP_SIG[8] = { 'N','T','L','M','S','S','P',0 };

/* ---- small utils ---- */

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

/* Accepts "aabbcc..." or "AABBCC..." and optional leading "LM:NT" where
 * only NT half (32 chars) matters. Writes 16 bytes to out. Returns 0 on
 * success. */
int ntlm_pth_parse_hash(const char *in, uint8_t out[16]) {
    if (!in) return -1;
    /* If looks like LM:NT (65 chars, colon at pos 32) */
    const char *p = in;
    size_t len = 0; while (p[len]) ++len;
    if (len == 65 && p[32] == ':') p += 33;  /* skip LM:... */
    else if (len != 32)              return -1;
    for (int i = 0; i < 16; ++i) {
        int hi = hex_nibble(p[i*2]);
        int lo = hex_nibble(p[i*2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* UTF-16LE encode — out must have room for 2*len bytes. Returns bytes written. */
static size_t utf16le_from_wide(const wchar_t *s, uint8_t *out) {
    size_t n = 0;
    if (!s) return 0;
    for (size_t i = 0; s[i]; ++i) {
        uint16_t cp = (uint16_t)(s[i] & 0xFFFF);
        out[n++] = (uint8_t)(cp & 0xff);
        out[n++] = (uint8_t)(cp >> 8);
    }
    return n;
}

static size_t wide_len(const wchar_t *s) {
    if (!s) return 0;
    size_t n = 0; while (s[n]) ++n; return n;
}

static void towupper_buf(uint8_t *buf, size_t bytes) {
    /* Upper-case ASCII letters in a UTF-16LE buffer. */
    for (size_t i = 0; i + 1 < bytes; i += 2) {
        if (buf[i+1] == 0 && buf[i] >= 'a' && buf[i] <= 'z') {
            buf[i] -= 32;
        }
    }
}

/* ---- HMAC-MD5 via BCrypt ---- */

static int hmac_md5(const uint8_t *key, size_t keylen,
                    const uint8_t *data, size_t datalen,
                    uint8_t out[16]) {
    void *hAlg = NULL, *hHash = NULL;
    NTSTATUS_BC s;

    s = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, L"MD5", NULL,
                                           BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (s < 0) return -1;
    s = BCRYPT$BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key,
                                (ULONG)keylen, 0);
    if (s < 0) { BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0); return -1; }
    s = BCRYPT$BCryptHashData(hHash, (PUCHAR)data, (ULONG)datalen, 0);
    if (s < 0) goto fail;
    s = BCRYPT$BCryptFinishHash(hHash, out, 16, 0);
    if (s < 0) goto fail;

    BCRYPT$BCryptDestroyHash(hHash);
    BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return 0;
fail:
    BCRYPT$BCryptDestroyHash(hHash);
    BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return -1;
}

/* ---- Type 1 (NEGOTIATE) ---- */

/* Returns bytes written into out (caller sized; 48 is enough). */
int ntlm_pth_build_type1(uint8_t *out, size_t outlen) {
    if (outlen < 40) return -1;
    MSVCRT$memset(out, 0, 40);
    MSVCRT$memcpy(out + 0, NTLMSSP_SIG, 8);               /* signature */
    out[8] = 0x01;                                         /* message type */
    /* NegotiateFlags @12, little-endian */
    uint32_t fl = NTLMSSP_FLAGS;
    out[12] = (uint8_t)(fl & 0xff);
    out[13] = (uint8_t)((fl >> 8) & 0xff);
    out[14] = (uint8_t)((fl >> 16) & 0xff);
    out[15] = (uint8_t)((fl >> 24) & 0xff);
    /* DomainNameFields @16 (len=0, maxlen=0, offset=40) */
    out[16] = 0; out[17] = 0; out[18] = 0; out[19] = 0;
    out[20] = 40; out[21] = 0; out[22] = 0; out[23] = 0;
    /* WorkstationFields @24 (len=0, maxlen=0, offset=40) */
    out[24] = 0; out[25] = 0; out[26] = 0; out[27] = 0;
    out[28] = 40; out[29] = 0; out[30] = 0; out[31] = 0;
    /* Version @32 (8 bytes) — Windows 10 marker */
    out[32] = 0x0a; out[33] = 0x00; out[34] = 0x63; out[35] = 0x45;
    out[36] = 0x00; out[37] = 0x00; out[38] = 0x00; out[39] = 0x0f;
    return 40;
}

/* ---- Type 2 parsing ---- */

typedef struct {
    uint8_t        server_challenge[8];
    const uint8_t *target_info;
    size_t         target_info_len;
} ntlm_type2_t;

static int parse_type2(const uint8_t *p, size_t plen, ntlm_type2_t *t2) {
    if (plen < 48) return -1;
    if (MSVCRT$memcmp(p, NTLMSSP_SIG, 8) != 0) return -1;
    if (p[8] != 0x02) return -1;
    /* ServerChallenge @24, 8 bytes */
    MSVCRT$memcpy(t2->server_challenge, p + 24, 8);
    /* TargetInfoFields @40: len(2) maxlen(2) offset(4) */
    uint16_t ti_len = (uint16_t)p[40] | ((uint16_t)p[41] << 8);
    uint32_t ti_off = (uint32_t)p[44] | ((uint32_t)p[45] << 8) |
                      ((uint32_t)p[46] << 16) | ((uint32_t)p[47] << 24);
    if (ti_off + ti_len > plen) return -1;
    t2->target_info = (ti_len && ti_off) ? (p + ti_off) : NULL;
    t2->target_info_len = ti_len;
    return 0;
}

/* ---- Type 3 (AUTHENTICATE) ---- */

int ntlm_pth_build_type3(const uint8_t *type2, size_t type2_len,
                         const uint8_t nt_hash[16],
                         const wchar_t *user,
                         const wchar_t *domain,
                         const wchar_t *workstation,
                         uint8_t **out_buf, size_t *out_len) {
    ntlm_type2_t t2;
    if (parse_type2(type2, type2_len, &t2) != 0) return -1;

    /* 1. NTLMv2 hash = HMAC_MD5(nt_hash, UPPER(user) || domain)  — UTF-16LE */
    size_t ulen = wide_len(user);
    size_t dlen = wide_len(domain);
    uint8_t *ud = (uint8_t*)MSVCRT$malloc((ulen + dlen) * 2 + 2);
    if (!ud) return -1;
    size_t upos = utf16le_from_wide(user, ud);
    towupper_buf(ud, upos);
    size_t dpos = utf16le_from_wide(domain, ud + upos);
    (void)dpos;

    uint8_t ntlmv2_hash[16];
    if (hmac_md5(nt_hash, 16, ud, upos + dpos, ntlmv2_hash) != 0) {
        MSVCRT$free(ud);
        return -1;
    }
    MSVCRT$free(ud);

    /* 2. temp = header(4) resv(4) ts(8) cc(8) resv(4) targetInfo(N) eol(4) */
    size_t temp_len = 4 + 4 + 8 + 8 + 4 + t2.target_info_len + 4;
    uint8_t *temp = (uint8_t*)MSVCRT$malloc(temp_len);
    if (!temp) return -1;
    MSVCRT$memset(temp, 0, temp_len);
    temp[0] = 0x01; temp[1] = 0x01;
    /* timestamp: 100-ns intervals since 1601 = FILETIME */
    FILETIME ft; KERNEL32$GetSystemTimeAsFileTime(&ft);
    temp[8]  = (uint8_t)(ft.dwLowDateTime        & 0xff);
    temp[9]  = (uint8_t)((ft.dwLowDateTime >>  8) & 0xff);
    temp[10] = (uint8_t)((ft.dwLowDateTime >> 16) & 0xff);
    temp[11] = (uint8_t)((ft.dwLowDateTime >> 24) & 0xff);
    temp[12] = (uint8_t)(ft.dwHighDateTime        & 0xff);
    temp[13] = (uint8_t)((ft.dwHighDateTime >>  8) & 0xff);
    temp[14] = (uint8_t)((ft.dwHighDateTime >> 16) & 0xff);
    temp[15] = (uint8_t)((ft.dwHighDateTime >> 24) & 0xff);
    /* client challenge: 8 bytes of quasi-random — reuse timestamp low bits */
    for (int i = 0; i < 8; ++i) temp[16 + i] = temp[8 + ((i * 3) % 8)] ^ (uint8_t)(i * 37);
    /* target info */
    if (t2.target_info_len && t2.target_info) {
        MSVCRT$memcpy(temp + 28, t2.target_info, t2.target_info_len);
    }
    /* trailing 4-byte EOL already zeroed by memset */

    /* 3. NTProofStr = HMAC_MD5(ntlmv2_hash, serverChallenge || temp) */
    uint8_t *cct = (uint8_t*)MSVCRT$malloc(8 + temp_len);
    if (!cct) { MSVCRT$free(temp); return -1; }
    MSVCRT$memcpy(cct, t2.server_challenge, 8);
    MSVCRT$memcpy(cct + 8, temp, temp_len);
    uint8_t nt_proof[16];
    if (hmac_md5(ntlmv2_hash, 16, cct, 8 + temp_len, nt_proof) != 0) {
        MSVCRT$free(cct); MSVCRT$free(temp); return -1;
    }
    MSVCRT$free(cct);

    /* 4. NTLMv2 response = NTProofStr || temp */
    size_t nt_resp_len = 16 + temp_len;
    uint8_t *nt_resp = (uint8_t*)MSVCRT$malloc(nt_resp_len);
    if (!nt_resp) { MSVCRT$free(temp); return -1; }
    MSVCRT$memcpy(nt_resp, nt_proof, 16);
    MSVCRT$memcpy(nt_resp + 16, temp, temp_len);

    /* LMv2Response = HMAC_MD5(NTLMv2Hash, serverChallenge||clientChallenge) || clientChallenge
     * (24 bytes total). Must be computed BEFORE freeing temp since clientChallenge
     * lives at temp[16..23]. */
    uint8_t lmv2[24];
    {
        uint8_t ccinput[16];
        MSVCRT$memcpy(ccinput, t2.server_challenge, 8);
        MSVCRT$memcpy(ccinput + 8, temp + 16, 8);  /* clientChallenge from temp[16..23] */
        if (hmac_md5(ntlmv2_hash, 16, ccinput, 16, lmv2) != 0) {
            MSVCRT$free(temp); MSVCRT$free(nt_resp); return -1;
        }
        MSVCRT$memcpy(lmv2 + 16, temp + 16, 8);
    }
    MSVCRT$free(temp);

    /* 5. Build AUTHENTICATE_MESSAGE */
    size_t wlen = wide_len(workstation);
    size_t domain_b = dlen * 2;
    size_t user_b   = ulen * 2;
    size_t wsb      = wlen * 2;
    size_t lm_resp_len = 24;
    size_t hdr = 88;  /* fixed header including MIC */
    size_t payload_off = hdr;
    size_t dom_off = payload_off;
    size_t user_off = dom_off + domain_b;
    size_t ws_off   = user_off + user_b;
    size_t lm_off   = ws_off   + wsb;
    size_t nt_off   = lm_off   + lm_resp_len;
    size_t total    = nt_off   + nt_resp_len;

    uint8_t *a = (uint8_t*)MSVCRT$malloc(total);
    if (!a) { MSVCRT$free(nt_resp); return -1; }
    MSVCRT$memset(a, 0, total);

    MSVCRT$memcpy(a, NTLMSSP_SIG, 8);
    a[8] = 0x03;  /* message type */

    #define PUT_FIELD(off, len, maxlen, payload_off) do { \
        a[(off)+0] = (uint8_t)((len)       & 0xff); \
        a[(off)+1] = (uint8_t)((len)  >> 8 & 0xff); \
        a[(off)+2] = (uint8_t)((maxlen)    & 0xff); \
        a[(off)+3] = (uint8_t)((maxlen)>> 8 & 0xff); \
        a[(off)+4] = (uint8_t)((payload_off)      & 0xff); \
        a[(off)+5] = (uint8_t)((payload_off) >> 8 & 0xff); \
        a[(off)+6] = (uint8_t)((payload_off) >>16 & 0xff); \
        a[(off)+7] = (uint8_t)((payload_off) >>24 & 0xff); \
    } while (0)

    PUT_FIELD(12, lm_resp_len,  lm_resp_len,  lm_off);    /* LmChallengeResponse */
    PUT_FIELD(20, nt_resp_len,  nt_resp_len,  nt_off);    /* NtChallengeResponse */
    PUT_FIELD(28, domain_b,     domain_b,     dom_off);   /* DomainName */
    PUT_FIELD(36, user_b,       user_b,       user_off);  /* UserName */
    PUT_FIELD(44, wsb,          wsb,          ws_off);    /* Workstation */
    PUT_FIELD(52, 0,            0,            total);     /* EncryptedRandomSessionKey */

    /* NegotiateFlags @60 */
    uint32_t fl = NTLMSSP_FLAGS;
    a[60] = (uint8_t)(fl & 0xff);
    a[61] = (uint8_t)((fl >> 8) & 0xff);
    a[62] = (uint8_t)((fl >> 16) & 0xff);
    a[63] = (uint8_t)((fl >> 24) & 0xff);

    /* Version @64 (8 bytes) — Windows 10 marker */
    a[64] = 0x0a; a[65] = 0x00; a[66] = 0x63; a[67] = 0x45;
    a[68] = 0x00; a[69] = 0x00; a[70] = 0x00; a[71] = 0x0f;

    /* MIC @72 (16 bytes) — zero'd out (no challenge commitment in temp) */
    /* payload: domain, user, workstation, lm(24 zeros), nt_resp */
    utf16le_from_wide(domain,      a + dom_off);
    utf16le_from_wide(user,        a + user_off);
    utf16le_from_wide(workstation, a + ws_off);
    MSVCRT$memcpy(a + lm_off, lmv2, 24);
    MSVCRT$memcpy(a + nt_off, nt_resp, nt_resp_len);
    MSVCRT$free(nt_resp);

    *out_buf = a;
    *out_len = total;
    return 0;
}

#endif /* !TDS_LINUX_TEST */
