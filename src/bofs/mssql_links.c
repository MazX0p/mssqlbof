/*
 * mssql_links — single-hop linked-server enumeration.
 *
 * v0.1.0 lab note: Windows BOF execution shows intermittent heap-state
 * crashes that need proper WinDbg analysis (see ROADMAP v0.1.1).
 * The TDS protocol library this BOF wraps is fully Linux-tested
 * against live SQL 2019 + 2022 (10/10 PASS).
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
    int json = bof_args_bool_flag(&a, "--json");
    (void)json;

    if (!host) {
        BeaconPrintf(CALLBACK_ERROR, "[!] usage: mssql_links <host> [--port N] [--json]");
        return;
    }
    wchar_t whost[256];
    ascii_to_wide(host, whost, 256);

    tds_conn_t *c = NULL;
    int rc = tds_connect(whost, (uint16_t)port, NULL, NULL, &c);
    if (rc != TDS_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] mssql_links connect failed (%d)", rc);
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
        BeaconPrintf(CALLBACK_ERROR, "[!] mssql_links query failed (%d)", rc);
        if (r) tds_result_free(r);
        tds_close(c);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Linked servers reachable from this host:");
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
        BeaconPrintf(CALLBACK_OUTPUT, " - %ls (%ls / %ls -> %ls) rpc_out=%d data_access=%d",
                     name, product, provider, src, (int)rpc_out, (int)data_access);
        ++n;
    }
    if (n == 0) BeaconPrintf(CALLBACK_OUTPUT, " (no linked servers configured)");
    BeaconPrintf(CALLBACK_OUTPUT, "Total: %d", n);
    tds_close(c);
}
