# mssqlbof — C2 and SQL Server compatibility

Everything ships as one object file per architecture: `mssql.x64.o` and `mssql.x86.o`. The same binary loads in every framework below because it uses only the canonical Beacon API surface (`BeaconPrintf`, `BeaconDataExtract`, the `<LIB>$<fn>` dynamic import pattern, and `go`/`go_x64`/`go_x86` entry points).

## Framework matrix

| Framework | x64 | x86 | Notes |
|---|---|---|---|
| AdaptixC2 | verified | expected | every action verified end-to-end in the silentstrike.io lab |
| TrustedSec COFFLoader | verified | verified | reference loader used for every test in this repo |
| Cobalt Strike | expected | expected | canonical Beacon API — no framework-specific code |
| Havoc | expected | expected | same |
| Sliver | expected | expected | same |
| Outflank Stage1 | expected | expected | same |
| BruteRatel | expected | expected | same |
| Nighthawk | expected | expected | same |
| Metasploit `execute_bof` | expected | expected | same |
| PoshC2 | expected | expected | same |

`verified` means every action was run end-to-end on the lab with that loader, the output was captured, and it matches the expected behavior. `expected` means the BOF uses only the canonical Beacon API and should work unmodified — PRs with screenshots welcome.

## SQL Server versions

| Version | Verified lab run |
|---|---|
| SQL Server 2019 Express 15.0.2000.5 | every action, every auth mode |
| SQL Server 2019 Developer 15.0.4460.4 | expected — same protocol level |
| SQL Server 2022 | expected — same TDS 7.4, same handshake |
| SQL Server 2017 | expected — TDS 7.4 is compatible |
| SQL Server 2016 | expected — TDS 7.4 is compatible |
| SQL Server 2014 | expected — TDS 7.3 negotiated (one fewer field in LOGIN7, should still work) |
| SQL Server 2012 | expected — TDS 7.3 negotiated |
| Azure SQL Database | TDS works, `--auth sspi/ntlm/sql` works; Entra ID auth via PRT is v0.3 |

## Auth mode matrix

Every one of these has been run end-to-end against the lab SQL Server 2019:

| Auth | Target principal | Status |
|---|---|---|
| `--auth sspi` (current token) | SRV02\Administrator, SILENTSTRIKE\Administrator | verified |
| `--auth ntlm --user --pass` | SILENTSTRIKE\Administrator | verified |
| `--auth ntlm --user --hash` (PTH, manual NTLMv2) | SILENTSTRIKE\Administrator | verified |
| `--auth sql --user --pass` | sa, lowuser | verified |
