# MSSQLBOF — Roadmap

## v0.1.2 — multi-auth + PTH (current)

- ✅ Real Schannel TLS with SQL Server PRELOGIN-wrap quirk
- ✅ SSPI Negotiate (current-token Kerberos / NTLM)
- ✅ Multi-leg SSPI continuation via `TDS_TOK_SSPI` 0xED handler + TDS EOM flag
- ✅ Explicit NTLM plaintext auth (`--auth ntlm --user --pass`)
- ✅ **Pass-the-hash** (`--auth ntlm --hash <NT>`) via hand-rolled NTLMv2 +
  BCrypt HMAC-MD5 — no SSPI, no lsass touching, no make_token
- ✅ SQL authentication (`--auth sql`)
- ✅ Unified `mssql.x64.o` with 11 actions
- ✅ Four privesc methods for `exec`: login, trustworthy, auto, none
- ✅ New actions: `privesc`, `coerce`, `passwords`, `chain`
- ✅ End-to-end verified SRV03 → SRV02 via COFFLoader + Adaptix C2
- ⚠️  Single-hop linked-server walker
- ⚠️  First-query-after-multi-leg-login column corruption (workaround: primer query in do_connect)

## v0.1.0 — initial release

- ✅ TDS 7.4 protocol library, ~2000 lines pure C
- ✅ Linux test harness against live SQL 2019 + 2022 (Docker)
- ✅ 10/10 protocol tests passing
- ✅ Six BOFs cross-compiled to x64 + x86 COFFs
- ✅ Unified arg parser, table + JSON output
- ⚠️  Schannel TLS = stub on Windows; Linux OpenSSL stub validates protocol
- ⚠️  Single-hop `mssql_links` only

## v0.1.1 — Windows TLS + recursive links

Target: 2-3 weeks after v0.1.0.

- [ ] **Real Schannel TLS implementation** in `tls_schannel.c`
  - Mirror the OpenSSL state machine: `AcquireCredentialsHandleW(UNISP_NAME_W, ...)`, `InitializeSecurityContextW` loop, `EncryptMessage`/`DecryptMessage`
  - TLS 1.2 minimum, manual cert validation off by default, `--verify-cert` flag
  - Validate against lab SQL Server 2019 + 2022 + Azure SQL DB
- [ ] **Real SSPI Negotiate** in `sspi.c` for Kerberos auth via current beacon thread token
  - `MSSQLSvc/<host>:<port>` and `MSSQLSvc/<host>:<instance>` SPN attempt
  - Honors `make_token` / `steal_token` from beacon
- [ ] **Recursive `mssql_links`** with cycle detection
  - Indented ASCII tree output (the README screenshot)
  - JSON edge list (BloodHound-ingestible)
- [ ] **Adaptix C2 command file** (`adaptix/mssqlbof.json`)
- [ ] **Cobalt Strike `.cna` aggressor** registration with help text per command

## v0.2.0 — quieter exec primitives + cross-forest

Target: 4-6 weeks after v0.1.0.

- [ ] **CLR assembly exec method** for `mssql_exec` (`--method clr`) — much quieter than xp_cmdshell
- [ ] **SQL Agent job exec method** (`--method agent`) — alternative quiet path
- [ ] **OLE automation exec method** (`--method ole`)
- [ ] **Cross-forest Kerberos** for `mssql_*` against trusted-forest SQL hosts
- [ ] **Coerced authentication primitive** (`mssql_coerce`) — `xp_dirtree`/`xp_fileexist` to attacker SMB listener
- [ ] **Password spray BOF** (`mssql_spray`) for SQL auth across discovered hosts

## v0.3.0 — Azure & advanced

Target: 8-10 weeks.

- [ ] **Azure SQL DB support** — Entra ID auth via cached PRT, AAD app token
- [ ] **MARS support** for concurrent result sets
- [ ] **RPC packet type** for parameterized queries (avoids string concat)
- [ ] **Database content search BOF** (`mssql_search`) — regex over text columns for credentials/PII

## v0.4.0 — graph + integration

Target: 12+ weeks.

- [ ] **BloodHound ingestor** for `mssql_links --json` output
- [ ] **Built-in detection guide** for blue teamers
- [ ] **Conference talk submission**: DEF CON Demo Labs, BSides anywhere

## Backlog (no committed version)

- Linked-server graph visualization (graphviz output)
- TDS protocol fuzzer for defender testing
- TDS proxy mode for MitM scenarios
- ssl pinning detection bypass via cert override
- Encrypted channel for `xp_cmdshell` output to bypass NIDS

## Anti-roadmap (will not do)

These are out of scope and asked-about often enough to need a "no":

- **GUI client** — this is a BOF suite, not an IDE
- **MySQL/PostgreSQL/Oracle support** — different protocols, different repo
- **Vendoring `msodbcsql.dll`** — defeats the entire point of the project
- **Aggressive privesc primitives** that don't have a clean OPSEC story
