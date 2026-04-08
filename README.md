# mssqlbof



A Beacon Object File suite for Microsoft SQL Server that speaks TDS 7.4 on the wire itself, in C. No `msodbcsql.dll`, no `sqloledb.dll`, no .NET CLR, no PowerShell. One COFF per arch, loads into every beacon that honors the canonical Beacon API.

<img width="3198" height="1180" alt="image" src="https://github.com/user-attachments/assets/6f538d2b-bdca-48fc-a0c0-0dab3057685f" />



## Why

SQL Server shows up on nearly every engagement. The two tools people reach for are `SQLRecon` / `PowerUpSQL` (CLR + PowerShell) and whatever wraps `sqlcmd.exe`. Both leave `mscoree.dll`, PowerShell AMSI events, or a full copy of the Microsoft ODBC driver sitting in beacon memory. None of that is necessary: TDS is just framed bytes over TCP with a Schannel handshake in front, and every BOF-capable beacon already has `ws2_32`, `secur32`, `schannel`, and `bcrypt` loaded.

So `mssqlbof` implements TDS by hand, in C, and plugs directly into whatever SSPI or BCrypt primitives the operator needs for the target. Beacon loads one ~48 KB object, runs SQL, unloads. Nothing else enters the process.

## Compatibility

| C2 | x64 | x86 |
|---|---|---|
| Cobalt Strike | yes | yes |
| Havoc | yes | yes |
| Sliver | yes | yes |
| BruteRatel | yes | yes |
| Nighthawk | yes | yes |
| Outflank Stage1 | yes | yes |
| AdaptixC2 | yes | yes |
| Metasploit `execute_bof` | yes | yes |
| PoshC2 | yes | yes |

One object file per architecture. `mssql.x64.o` is the same binary on every framework — we only use the canonical Beacon API (`BeaconPrintf`, `BeaconDataExtract`, etc.) and the `<LIB>$<fn>` dynamic import pattern COFF loaders resolve at runtime.

## Quickstart

```bash
apt install gcc-mingw-w64 libssl-dev
make
```

Produces `build/mssql.x64.o` and `build/mssql.x86.o`. Drop on the team server, load with your C2's BOF runner.

## Actions

Everything goes through one object file with `--action <verb>`:

```
--action find                                   LDAP enum of MSSQLSvc SPNs in the current forest
--action info     --host <sql>                  server/version/current user/sysadmin/db
--action query    --host <sql> --sql "..."      arbitrary T-SQL, multi-row, multi-resultset
--action links    --host <sql>                  linked-server enumeration (single hop)
--action exec     --host <sql> --cmd "..."      xp_cmdshell with auto enable + restore
--action impersonate --host <sql> --discover    list logins you can EXECUTE AS
--action impersonate --host <sql> --login X --sql "..."
                                                run T-SQL as X via EXECUTE AS LOGIN
--action privesc  --host <sql>                  six-section privesc surface enumeration
--action coerce   --host <sql> --to "\\listener\x"
                                                xp_dirtree SMB auth coercion
--action passwords --host <sql>                 dump sys.linked_logins + sys.credentials
--action chain    --host <sql> --via LINK --sql "..."
                                                EXEC (...) AT [LinkedServer]
```

`--action find` runs without a host — it talks to the operator's DC via LDAP.

## Authentication

Four modes. Every mode is verified end-to-end against SQL Server 2019 in both COFFLoader and Adaptix C2 on a real domain.

```
--auth sspi                                     (default) current beacon thread token
                                                Kerberos if SPN exists, NTLM otherwise.
                                                Honors make_token / steal_token.

--auth ntlm --domain D --user U --pass P        explicit NTLM plaintext.
                                                Drives SSPI NTLM package, multi-leg.

--auth ntlm --domain D --user U --hash <NT>     pass-the-hash.
                                                Hand-rolled NTLMv2 (see below).
                                                No SSPI, no lsass, no make_token.

--auth sql  --user U --pass P                   SQL authentication.
```

`--hash` takes a 32-char hex NT hash or the `LM:NT` form that `secretsdump` emits.

### Why the hash mode is not just `SSPI + SEC_WINNT_AUTH_IDENTITY`

`AcquireCredentialsHandleW(NULL, "NTLM", ...)` only accepts plaintext passwords in the credential identity structure. The NTLM provider derives the NT hash internally. Feeding it a hash requires patching lsass (what Mimikatz `sekurlsa::pth` does) or running the beacon under a sacrificial process that was already pre-authenticated.

The alternative — the one we took — is to skip SSPI for PTH entirely and generate the NTLMSSP messages ourselves. `src/tds/ntlm_pth.c` builds a Type 1 NEGOTIATE, parses the server's Type 2 CHALLENGE out of the TDS 0xED token, runs the NTLMv2 math with `bcrypt.dll`'s HMAC-MD5 provider, and writes a Type 3 AUTHENTICATE that SQL Server happily passes to the DC.

The first cut failed with `error 18452: login is from an untrusted domain`. Capturing Impacket's working auth on the wire next to ours narrowed it down fast: we were sending 24 zeros for the LMv2 response and the full 0xe288... Windows negotiate flag soup. Matching Impacket's LMv2 computation and its smaller 0xa2880205 flag set (no `KEY_EXCH`, no `SIGN`, no `ALWAYS_SIGN`) made the server accept the hash. Write-up in [`docs/BLOG.md`](docs/BLOG.md).

## Privesc for `--action exec`

```
--impersonate auto          (default) try EXECUTE AS LOGIN, then TRUSTWORTHY hop
--impersonate login         EXECUTE AS LOGIN via an IMPERSONATE grant
--impersonate trustworthy   hop through dbo of a sysadmin-owned TRUSTWORTHY db
--impersonate none          fail if not sysadmin
```

`privesc` enumerates the surface before you pick a method: sysadmin membership, IMPERSONATE grants (with the target login's sysadmin status), TRUSTWORTHY databases owned by a sysadmin (with your access), linked servers, server-level permissions, and `xp_cmdshell` state.

## Build

```
apt install gcc-mingw-w64 libssl-dev
make                    # cross-compile BOFs to x64 + x86
make tds                # Linux shared library of the TDS core (for fuzzing / tests)
```

The Linux shared library shares every TDS source file with the Windows build; only `tls_schannel.c` / `sspi.c` / `ntlm_pth.c` swap out for their OpenSSL / stub equivalents.

Nothing calls libc or Win32 directly. Every external symbol goes through the `<LIB>$<fn>` dynamic import convention in `src/common/dynimports.h`. Verify with:

```
x86_64-w64-mingw32-objdump -t build/mssql.x64.o | grep UND
```

Only `MSVCRT$*`, `WS2_32$*`, `SECUR32$*`, `BCRYPT$*`, `CRYPT32$*`, `SCHANNEL$*`, `WLDAP32$*`, `KERNEL32$*`, `ADVAPI32$*`, and `__imp_Beacon*` should show up. No `msodbcsql.dll`. No `sqloledb.dll`. No `mscoree.dll`.

## OPSEC

| Action | Extra DLLs beyond beacon baseline | Server-side trace | Notes |
|---|---|---|---|
| `find` | `wldap32` | DC event 1644 (rare) | LDAP only, no SQL touched |
| `info` / `query` / `links` / `privesc` / `passwords` | `secur32` or `bcrypt`, `schannel`, `ws2_32` | SQL audit 33205 if enabled | Pure TDS, no ODBC fingerprint |
| `exec` | same | `xp_cmdshell` + `sp_configure` in default trace | Loud. Use `--impersonate` from a low-priv login to avoid landing as NT SERVICE |
| `impersonate` | same | `EXECUTE AS` audit 33205 + 33206 | |
| `coerce` | same | `xp_dirtree` attempt logged | Point it at `responder` / `ntlmrelayx` |
| `chain` | same | `EXEC AT` logged on the linked server target | Pivot primitive |

Everything TLS is real Schannel (not a stub) with the SQL Server PRELOGIN-wrap quirk handled: the handshake runs inside TDS PRELOGIN type 0x12 packets, then LOGIN7 goes out as raw TLS application data, and the server answers that first login packet in plaintext. Multi-leg SSPI continuations also go plaintext — if you encrypt them with TLS, SRV02 just closes the socket.

## Protocol notes

`docs/PROTOCOL.md` has the TDS deep dive: packet framing, PRELOGIN option stream, LOGIN7 password obfuscation, ALL_HEADERS on SQLBatch, the token stream grammar (COLMETADATA / ROW / NBCROW / DONE / LOGINACK / ENVCHANGE / 0xED SSPI continuation), the TLS handshake quirk, and the multi-leg NTLM pump.

`docs/BLOG.md` is the narrative version — the actual debugging journey, with wire captures, of getting PTH working.

## Status

`v0.1.2` — multi-auth, PTH, 11 actions, lab-verified.

- Four auth modes working: sspi, ntlm-plaintext, ntlm-hash (PTH), sql
- Unified dispatch BOF (`mssql.x64.o`) with 11 actions
- Four privesc methods for `exec`: login, trustworthy, auto, none
- Multi-leg SSPI continuation with TDS EOM handling
- Pass-the-hash via hand-rolled NTLMv2 + BCrypt
- Full end-to-end verification: 38-case COFF sweep + Adaptix C2 sweep on a domain-joined SQL Server 2019

Known edge cases:
- Single-hop linked-server walker only; recursive nested `OPENQUERY` chain is v0.2.
- The first SQLBatch after a multi-leg SSPI login drops data on the floor. A primer SELECT in `do_connect` drains it — side effect is the `[*] connected as ...` line every action logs. Root cause is in the post-LOGINACK read path and will get a proper fix in v0.2.

## Credits

- [`Cobalt-Strike/bof_template`](https://github.com/Cobalt-Strike/bof_template) for the canonical Beacon API surface this project hews to exactly.
- [`TrustedSec/COFFLoader`](https://github.com/trustedsec/COFFLoader) for an independent loader to test against.
- `impacket`'s `ntlm.py` and `mssqlclient.py` — the reference we diffed against when chasing the NTLMv2 flag soup.
- `[MS-TDS]` and `[MS-NLMP]` — the specs that all this hand-rolling follows.
- `AI` — help and documntation 

## License

MIT.
