/*
 * mssql_query — arbitrary T-SQL passthrough.
 *
 * Usage:
 *   mssql_query <host> "<sql>"
 *   mssql_query SQL01 "SELECT name FROM sys.databases"
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
    const char *sql  = bof_args_str_pos(&a, 1);
    int port = bof_args_int_flag(&a, "--port", 1433);

    if (!host || !sql) {
        BeaconPrintf(CALLBACK_ERROR, "[!] usage: mssql_query <host> \"<sql>\"");
        return;
    }

    wchar_t whost[256];
    ascii_to_wide(host, whost, 256);

    wchar_t *wsql = (wchar_t*)MSVCRT$malloc(4096 * sizeof(wchar_t));
    if (!wsql) { BeaconPrintf(CALLBACK_ERROR, "[!] oom"); return; }
    ascii_to_wide(sql, wsql, 4096);

    tds_conn_t *c = NULL;
    int rc = tds_connect(whost, (uint16_t)port, NULL, NULL, &c);
    if (rc != TDS_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] connect failed (%d)", rc);
        MSVCRT$free(wsql);
        if (c) tds_close(c);
        return;
    }

    tds_result_t *r = NULL;
    rc = tds_query(c, wsql, &r);
    MSVCRT$free(wsql);
    if (rc != TDS_OK || !r) {
        BeaconPrintf(CALLBACK_ERROR, "[!] query failed (%d): %ls", rc, tds_last_error(c));
        if (r) tds_result_free(r);
        tds_close(c);
        return;
    }

    int n = tds_result_get_col_count(r);
    wchar_t *line = (wchar_t*)MSVCRT$malloc(4096 * sizeof(wchar_t));
    wchar_t *cell = (wchar_t*)MSVCRT$malloc(1024 * sizeof(wchar_t));
    if (!line || !cell) {
        if (line) MSVCRT$free(line);
        if (cell) MSVCRT$free(cell);
        tds_result_free(r);
        tds_close(c);
        return;
    }

    /* Header */
    size_t pos = 0;
    line[0] = 0;
    for (int i = 0; i < n && pos < 4000; ++i) {
        const wchar_t *cn = tds_result_get_col_name(r, i);
        for (int j = 0; cn[j] && pos < 4000; ++j) line[pos++] = cn[j];
        if (i + 1 < n && pos < 4000) line[pos++] = L'\t';
    }
    line[pos] = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "%ls", line);

    int rows = 0;
    while (tds_result_next_row(r) == 1) {
        pos = 0;
        line[0] = 0;
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

    MSVCRT$free(line);
    MSVCRT$free(cell);
    tds_result_free(r);
    tds_close(c);
}
