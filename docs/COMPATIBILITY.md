# MSSQLBOF — C2 compatibility matrix

Tested in lab; cells marked ❓ are untested but expected to work because the BOF only uses the canonical Beacon API surface.

## Frameworks

| Framework | x64 | x86 | mssql_find | mssql_info | mssql_query | mssql_links | mssql_exec | mssql_impersonate | Notes |
|---|---|---|---|---|---|---|---|---|---|
| AdaptixC2 | ❓ | ❓ | ❓ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ blocked on Schannel v0.1.1 |
| Cobalt Strike | ❓ | ❓ | ❓ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | same |
| Havoc | ❓ | ❓ | ❓ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | same |
| Sliver | ❓ | ❓ | ❓ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | same |
| Outflank Stage1 | ❓ | ❓ | ❓ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | same |
| BruteRatel | ❓ | ❓ | ❓ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | same |
| Nighthawk | ❓ | ❓ | ❓ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | same |
| Metasploit `execute_bof` | ❓ | ❓ | ❓ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | same |
| PoshC2 | ❓ | ❓ | ❓ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | same |

Legend:
- ✅ verified in lab
- ❓ untested but expected to work
- ⚠️ blocked on a known v0.1.0 limitation
- ❌ verified broken

## SQL Server versions

| Version | Linux Docker test | Windows lab test |
|---|---|---|
| SQL Server 2019 (15.0.4460.4) | ✅ all 4 protocol tests pass | ❓ |
| SQL Server 2022 (16.x) | ✅ all 4 protocol tests pass | ❓ |
| SQL Server 2017 | ❓ TDS 7.4 should be compatible | ❓ |
| SQL Server 2016 | ❓ TDS 7.4 should be compatible | ❓ |
| SQL Server 2014 | ❓ TDS 7.3 negotiated | ❓ |
| SQL Server 2012 | ❓ TDS 7.3 negotiated | ❓ |
| Azure SQL Database | ❓ TDS 7.4 should work; Entra auth not yet supported | ❓ |

## How to fill in the matrix

If you've tested MSSQLBOF in a lab, please open a PR adding your verification:

1. Run the relevant BOF in your lab from the relevant C2
2. Take a screenshot of the output
3. PR adding the screenshot to `docs/screenshots/<c2>-<bof>.png` and updating the cell to ✅

Honest ❓ is preferred over fake ✅. We will not claim compatibility we have not personally verified.
