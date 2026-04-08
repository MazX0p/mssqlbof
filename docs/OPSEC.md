# MSSQLBOF — OPSEC notes

Per-command on-wire and in-memory footprint. Read this before running any of these in an engagement.

## Universal characteristics

Every BOF in this suite, except `mssql_find`, makes a TDS connection from the beacon process to a SQL Server target. That connection has the following uniform footprint:

**In-process**
- `secur32.dll`, `schannel.dll`, `ws2_32.dll` loaded into beacon (most already present in any beacon process)
- **NOT loaded:** `msodbcsql17.dll`, `msodbcsql18.dll`, `sqloledb.dll`, `sqlncli.dll`, `mscoree.dll`, `clr.dll`, `mscorlib.ni.dll`. **This is the differentiator.** Every other BOF that talks to SQL pulls one of these.
- No CLR, no PowerShell engine, no Python interpreter, no Lua VM
- No new threads — single-threaded synchronous protocol over the calling thread's existing stack

**On-wire**
- TCP to target SQL port (default 1433)
- TDS 7.4 PRELOGIN exchange (~50 bytes each direction)
- TLS 1.2 handshake wrapped in TDS PRELOGIN packets (~2 KB each direction, ~5 round trips)
- Encrypted LOGIN7 packet (varies, ~200 bytes plaintext)
- LOGIN response (plaintext TDS TABULAR in default login-only encryption mode)
- Then plaintext TDS for queries/responses

**Server-side**
- SQL audit event 33205 (`AUDIT_LOGIN`) if `Logon` audit specification is on. Default off in most boxes.
- Client process name on the beacon host is whatever process the beacon is injected into — `notepad.exe`, `svchost.exe`, etc. Telemetry that filters by "known SQL clients" (`sqlcmd.exe`, `ssms.exe`, `dotnet.exe`) will not match.
- Source port is whatever the beacon's ephemeral port allocation produces. Same as any other TCP connection.

**The single noisiest tell** is point 3: SQL audit + EDR network telemetry will see "process X on host Y connected to SQL Server", and X may not match the org's known SQL clients. If the org uses application allow-listing for SQL traffic, this will get flagged. There is no clean fix at the BOF level — this is a beacon-host tradeoff.

## Per-command details

### `mssql_find`

**On-wire:** one LDAP search to a Domain Controller on TCP/389 with filter `(servicePrincipalName=MSSQLSvc/*)`. No TDS connection at all.

**In-process:** loads `wldap32.dll` (usually already loaded by anything that touches AD).

**Server-side (DC):**
- LDAP query auditing event 1644 if enabled. The filter shape (`MSSQLSvc/*`) is unusual enough to be a soft IOC, but `setspn -Q` produces the same query for legitimate admin use.

**Detection:** low. If you only run one BOF on an engagement, this is the safest one.

### `mssql_info`

**On-wire:** one TDS connection to target SQL host, runs a single fixed introspection batch:
```sql
SELECT SERVERPROPERTY('ProductVersion'), SERVERPROPERTY('Edition'),
       SERVERPROPERTY('IsClustered'), SUSER_SNAME(),
       IS_SRVROLEMEMBER('sysadmin'), ORIGINAL_LOGIN(), DB_NAME(),
       (SELECT value_in_use FROM sys.configurations WHERE name='xp_cmdshell'),
       @@SERVERNAME, @@VERSION
```

**Server-side:**
- Login audit event 33205 if enabled
- The `sys.configurations` read is visible in `sys.dm_exec_query_stats` cache for ~minutes

**Detection:** low. The query shape is identical to what management tools run on first connect.

### `mssql_query`

**On-wire:** one TDS connection + arbitrary T-SQL. Whatever you send, the server logs it in default trace if enabled and `set statistics` if a profile is on.

**Server-side:**
- Statement appears in `sys.dm_exec_query_stats`
- Heavy queries show up in `sys.dm_exec_sessions` and Activity Monitor

**Detection:** depends entirely on what you query. `SELECT @@version` is invisible. `SELECT * FROM HumanResources.Employee` will get you fired.

### `mssql_links`

**On-wire:** one TDS connection + a `sys.servers` query. v0.1 is single-hop only — does not actually traverse the graph. v0.1.1 will recurse via OPENQUERY.

**Server-side:**
- One `sys.servers` SELECT in default trace
- v0.1.1 recursive walker will issue nested OPENQUERY calls visible in `sys.dm_exec_sessions` as nested logins under the linked server's auth context

**Detection:** low for v0.1. Medium for v0.1.1 — recursive linked-server walks are unusual sysadmin activity.

### `mssql_exec`

**The loud one.** Documented loudly so operators don't deploy this without thinking.

**On-wire:** TDS connection + `sp_configure`/`RECONFIGURE` calls + `EXEC xp_cmdshell '<cmd>'` + (optional) restore `sp_configure` calls.

**Server-side:**
- `sp_configure` calls are **logged in the default trace**, which is on by default in every SQL Server install. `xp_cmdshell` enable/disable events are visible to anyone running `sp_readtraces`.
- The `xp_cmdshell` invocation itself spawns a child process: `sqlservr.exe → cmd.exe → <your command>`. **Every EDR catches this process tree.** It's the most-detected SQL execution primitive.
- Auto-restore (the default) issues a second `sp_configure` to revert state, doubling the trace footprint but leaving the box clean for the next admin who looks.
- `--no-restore` halves the noise but leaves `xp_cmdshell` enabled — visible to any subsequent `SELECT * FROM sys.configurations` from a defender.

**Detection:** HIGH. Use `--method auto` for now (xp_cmdshell only). The `--method clr` (load assembly) and `--method agent` (SQL Agent job) options are v0.1.1 deliverables and are quieter.

**Operator advice:** `mssql_exec` is a "loud but reliable" primitive. If you only need recon, use `mssql_query` instead. If you need code exec, prefer the v0.1.1 CLR method when available.

### `mssql_impersonate`

**On-wire:** TDS connection + `EXECUTE AS LOGIN = '...'; <user-sql>; REVERT;`

**Server-side:**
- `EXECUTE AS` generates audit event 33205 (`AUDIT_LOGIN`) under the impersonated login
- `REVERT` generates audit event 33206
- If audit is off, both are invisible
- The `--discover` mode runs a `sys.server_permissions` SELECT that's visible in default trace

**Detection:** low if audit is off, medium if on. The "discover then impersonate sa" pattern is a known privesc IOC.

## Defender perspective (what to look for)

If you're on the defensive side and reading this, here's what would catch each command in our suite:

| Detection | What it catches |
|---|---|
| LDAP query auditing for `(servicePrincipalName=MSSQLSvc/*)` from non-admin hosts | `mssql_find` |
| SQL audit `AUDIT_LOGIN` from process names not matching `{sqlcmd, ssms, dotnet, ...}` | every other command |
| Default trace `sp_configure xp_cmdshell` events outside change-window | `mssql_exec` |
| Process tree `sqlservr.exe → cmd.exe` | `mssql_exec` (the loudest signal) |
| SQL audit `EXECUTE AS LOGIN` events outside known service-account flows | `mssql_impersonate` |

The hard one for defenders is that none of these BOFs leave a Windows-process-loaded-DLL signature like the .NET / ODBC tools do — there's no `msodbcsql.dll` to alert on. The signal moves to the SQL server side.
