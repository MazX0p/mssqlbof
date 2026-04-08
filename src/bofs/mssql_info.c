/*
 * mssql_info — connect to a target SQL host and dump introspection bundle.
 *
 * Usage:
 *   mssql_info <host>
 *   mssql_info SQL01 --port 1433
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
    int port = bof_args_int_flag(&a, "--port", 1433);

    if (!host) {
        BeaconPrintf(CALLBACK_ERROR, "[!] usage: mssql_info <host> [--port N]");
        return;
    }
    wchar_t whost[256];
    ascii_to_wide(host, whost, 256);

    tds_conn_t *c = NULL;
    int rc = tds_connect(whost, (uint16_t)port, NULL, NULL, &c);
    if (rc != TDS_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] mssql_info connect failed (%d)", rc);
        if (c) tds_close(c);
        return;
    }

    tds_result_t *r = NULL;
    rc = tds_query(c,
        L"SELECT CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(50)),"
        L"       CAST(SERVERPROPERTY('Edition') AS NVARCHAR(100)),"
        L"       SUSER_SNAME(),"
        L"       CAST(IS_SRVROLEMEMBER('sysadmin') AS INT),"
        L"       DB_NAME(),"
        L"       @@SERVERNAME,"
        L"       @@VERSION", &r);
    if (rc != TDS_OK || !r) {
        BeaconPrintf(CALLBACK_ERROR, "[!] mssql_info query failed (%d)", rc);
        if (r) tds_result_free(r);
        tds_close(c);
        return;
    }
    if (tds_result_next_row(r) != 1) {
        BeaconPrintf(CALLBACK_ERROR, "[!] mssql_info: empty result");
        tds_close(c);
        return;
    }

    wchar_t pv[64], ed[128], su[128], dn[128], srv[128];
    int64_t sa = 0;
    /* Banner on heap to avoid big stack frame */
    wchar_t *ver = (wchar_t*)MSVCRT$malloc(2048 * sizeof(wchar_t));
    if (!ver) { tds_close(c); return; }
    MSVCRT$memset(ver, 0, 2048 * sizeof(wchar_t));

    tds_result_get_str(r, 0, pv, 64);
    tds_result_get_str(r, 1, ed, 128);
    tds_result_get_str(r, 2, su, 128);
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
    tds_close(c);
}
