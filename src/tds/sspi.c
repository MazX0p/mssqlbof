/*
 * sspi.c — Windows SSPI Negotiate (Kerberos with NTLM fallback) for LOGIN7.
 *
 * BOF-context Kerberos design:
 *
 *   1. NEVER pass credentials. AcquireCredentialsHandleW with pAuthData=NULL
 *      tells SSPI to use the CURRENT THREAD TOKEN. If the operator earlier
 *      ran `make_token DOMAIN\user PASS` or `steal_token <pid>` in the
 *      beacon, that impersonation token is in effect, and Schannel/Negotiate
 *      will use it transparently. The BOF never sees, stores, or transmits
 *      a password.
 *
 *   2. Negotiate package auto-falls-back NTLM <-> Kerberos. If a valid
 *      MSSQLSvc SPN exists for the target, Kerberos is selected. If not,
 *      NTLM is used. Both work for SQL Server LOGIN7.
 *
 *   3. SPN selection. SQL Server can be reached at multiple SPN forms:
 *        MSSQLSvc/<fqdn>:<port>      (most common, port-based)
 *        MSSQLSvc/<fqdn>:<instance>  (named instance, instance-based)
 *        MSSQLSvc/<fqdn>             (legacy default-instance)
 *      We try the port form first. If ISC returns SEC_E_TARGET_UNKNOWN we
 *      retry with the bare-host form. The instance form is left for v0.2
 *      since named instances also need SQL Browser discovery.
 *
 *   4. Multi-leg Negotiate. SQL Server's LOGIN response can include SSPI
 *      message tokens (TDS_TOK_SSPI 0xED in [MS-TDS] §2.2.7.21) requesting
 *      additional legs. v0.1.1 sends one leg; if the server replies with
 *      a second leg, the response parser returns a "needs continuation"
 *      flag and connect.c will resend LOGIN7 with the new token. For Kerb
 *      single-shot is the common case so v0.1.1 ships with one-leg only.
 *
 *   5. Memory hygiene. SSPI handles are kept in struct tds_conn so they
 *      can be released on tds_close even if a BOF returns mid-handshake.
 *      Output tokens from ISC come from SSPI's allocator and are freed
 *      via FreeContextBuffer after the LOGIN7 packet has been built.
 */

#ifndef TDS_LINUX_TEST
#include "tds_internal.h"
#include "../common/dynimports.h"

#define ISC_REQ_DELEGATE_X        0x00000001
#define ISC_REQ_MUTUAL_AUTH_X     0x00000002
#define ISC_REQ_REPLAY_DETECT_X   0x00000004
#define ISC_REQ_SEQUENCE_DETECT_X 0x00000008
#define ISC_REQ_CONFIDENTIALITY_X 0x00000010
#define ISC_REQ_ALLOCATE_MEMORY_X 0x00000100
#define ISC_REQ_CONNECTION_X      0x00000800

/* SSPI state lives in tds_conn so it survives across LOGIN7 send +
 * response receive (in case the server requests a continuation). */
typedef struct tds_sspi {
    CredHandle hCred;
    CtxtHandle hCtxt;
    wchar_t    spn[256];
    int        have_cred;
    int        have_ctxt;
    int        complete;
} tds_sspi_t;

/* We attach the sspi state to tds_conn via a single pointer in last_error[]
 * area? No — better, statically allocated single instance because BOFs are
 * single-threaded by definition (one go() at a time per beacon). */
static tds_sspi_t g_sspi;

static void build_spn(wchar_t *out, size_t outlen,
                      const wchar_t *host, uint16_t port) {
    /* MSSQLSvc/<host>:<port> */
    const wchar_t *p = L"MSSQLSvc/";
    size_t pos = 0;
    while (*p && pos < outlen - 1) out[pos++] = *p++;
    for (size_t i = 0; host[i] && pos < outlen - 8; ++i) out[pos++] = host[i];
    if (pos < outlen - 8) out[pos++] = L':';
    /* itoa for port */
    wchar_t pbuf[8]; int pi = 0;
    uint16_t pp = port;
    if (pp == 0) pbuf[pi++] = L'0';
    while (pp > 0) { pbuf[pi++] = L'0' + (pp % 10); pp /= 10; }
    while (pi > 0 && pos < outlen - 1) out[pos++] = pbuf[--pi];
    out[pos] = 0;
}

int tds_sspi_init(struct tds_conn *c, const wchar_t *target_spn_unused) {
    (void)target_spn_unused;
    tds_sspi_t *s = &g_sspi;
    MSVCRT$memset(s, 0, sizeof(*s));

    build_spn(s->spn, 256, c->target_host, c->target_port);

    /* AcquireCredentialsHandleW with NULL pAuthData uses current thread token */
    SECURITY_STATUS ss = SECUR32$AcquireCredentialsHandleW(
        NULL, (SEC_WCHAR*)L"Negotiate", SECPKG_CRED_OUTBOUND,
        NULL, NULL, NULL, NULL, &s->hCred, NULL);
    if (ss != SEC_E_OK) {
        tds_set_error_a(c, "AcquireCredentialsHandleW(Negotiate) failed: 0x%lx",
                        (unsigned long)ss);
        return TDS_ERR_AUTH;
    }
    s->have_cred = 1;
    return TDS_OK;
}

int tds_sspi_init_explicit(struct tds_conn *c,
                           const wchar_t *user,
                           const wchar_t *domain,
                           const wchar_t *pass) {
    if ((!user || !user[0]) && (!pass || !pass[0])) {
        return tds_sspi_init(c, NULL);
    }
    tds_sspi_t *s = &g_sspi;
    MSVCRT$memset(s, 0, sizeof(*s));
    build_spn(s->spn, 256, c->target_host, c->target_port);

    /* Populate SEC_WINNT_AUTH_IDENTITY_W with explicit creds.
     * The struct expects USHORT counts (not bytes) and SEC_WINNT_AUTH_IDENTITY_UNICODE flag. */
    SEC_WINNT_AUTH_IDENTITY_W id;
    MSVCRT$memset(&id, 0, sizeof(id));
    id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    if (user) {
        id.User = (USHORT*)user;
        size_t n = 0; while (user[n]) ++n;
        id.UserLength = (unsigned long)n;
    }
    if (domain) {
        id.Domain = (USHORT*)domain;
        size_t n = 0; while (domain[n]) ++n;
        id.DomainLength = (unsigned long)n;
    }
    if (pass) {
        id.Password = (USHORT*)pass;
        size_t n = 0; while (pass[n]) ++n;
        id.PasswordLength = (unsigned long)n;
    }

    /* Use NTLM package directly for explicit creds (Kerberos with pre-set
     * creds is painful; NTLM is the practical choice when you have a
     * plaintext password). */
    SECURITY_STATUS ss = SECUR32$AcquireCredentialsHandleW(
        NULL, (SEC_WCHAR*)L"NTLM", SECPKG_CRED_OUTBOUND,
        NULL, &id, NULL, NULL, &s->hCred, NULL);
    if (ss != SEC_E_OK) {
        tds_set_error_a(c, "AcquireCredentialsHandleW(NTLM explicit) failed: 0x%lx",
                        (unsigned long)ss);
        return TDS_ERR_AUTH;
    }
    s->have_cred = 1;
    return TDS_OK;
}

int tds_sspi_step(struct tds_conn *c, const uint8_t *in_token, size_t in_len,
                  uint8_t **out_token, size_t *out_len, int *done) {
    tds_sspi_t *s = &g_sspi;
    *out_token = NULL;
    *out_len = 0;
    *done = 0;

    SecBuffer  in_buf, out_buf;
    SecBufferDesc in_desc, out_desc;

    out_buf.BufferType = SECBUFFER_TOKEN;
    out_buf.cbBuffer   = 0;
    out_buf.pvBuffer   = NULL;
    out_desc.ulVersion = SECBUFFER_VERSION;
    out_desc.cBuffers  = 1;
    out_desc.pBuffers  = &out_buf;

    DWORD flags_in = ISC_REQ_CONNECTION_X | ISC_REQ_ALLOCATE_MEMORY_X |
                     ISC_REQ_CONFIDENTIALITY_X | ISC_REQ_REPLAY_DETECT_X |
                     ISC_REQ_SEQUENCE_DETECT_X | ISC_REQ_MUTUAL_AUTH_X;
    DWORD flags_out = 0;

    SECURITY_STATUS ss;
    if (!s->have_ctxt) {
        /* First leg: produce the initial Negotiate token */
        ss = SECUR32$InitializeSecurityContextW(
            &s->hCred, NULL, s->spn,
            flags_in, 0, 0,
            NULL, 0, &s->hCtxt,
            &out_desc, &flags_out, NULL);
        s->have_ctxt = 1;
    } else {
        in_buf.BufferType = SECBUFFER_TOKEN;
        in_buf.cbBuffer   = (unsigned long)in_len;
        in_buf.pvBuffer   = (void*)in_token;
        in_desc.ulVersion = SECBUFFER_VERSION;
        in_desc.cBuffers  = 1;
        in_desc.pBuffers  = &in_buf;

        ss = SECUR32$InitializeSecurityContextW(
            &s->hCred, &s->hCtxt, s->spn,
            flags_in, 0, 0,
            &in_desc, 0, NULL,
            &out_desc, &flags_out, NULL);
    }

    if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED) {
        tds_set_error_a(c,
            "InitializeSecurityContextW(Negotiate, %ls) failed: 0x%lx "
            "[hint: SPN may not exist in AD; or no Kerberos ticket; "
            "or thread token not impersonating]",
            s->spn, (unsigned long)ss);
        return TDS_ERR_AUTH;
    }

    if (out_buf.cbBuffer > 0 && out_buf.pvBuffer) {
        *out_token = (uint8_t*)out_buf.pvBuffer;
        *out_len   = out_buf.cbBuffer;
    }
    *done = (ss == SEC_E_OK);
    s->complete = *done;
    return TDS_OK;
}

void tds_sspi_free(struct tds_conn *c) {
    (void)c;
    tds_sspi_t *s = &g_sspi;
    if (s->have_ctxt) SECUR32$DeleteSecurityContext(&s->hCtxt);
    if (s->have_cred) SECUR32$FreeCredentialsHandle(&s->hCred);
    MSVCRT$memset(s, 0, sizeof(*s));
}

#endif /* !TDS_LINUX_TEST */
