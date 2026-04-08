# MSSQLBOF — TDS protocol implementation notes

This document explains how MSSQLBOF speaks the TDS 7.4 protocol from a beacon, with no ODBC/OLEDB driver loaded into the process. It's both a code map for contributors and a write-up for anyone curious how `sys.databases` rows make it back from a SQL Server through ~2000 lines of pure C.

## TDS at a glance

TDS (Tabular Data Stream) is Microsoft's SQL Server wire protocol. The current version is 7.4 (SQL Server 2012+). The relevant spec is [`[MS-TDS]`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/) — about 280 pages.

Every TDS message is wrapped in an 8-byte header:

```
+--------+--------+--------+--------+
|  type  | status |     length      |
+--------+--------+--------+--------+
|       spid      | pkt_id | window |
+--------+--------+--------+--------+
```

- **type** (1 byte): packet kind. `0x12` PRELOGIN, `0x10` LOGIN7, `0x01` SQLBatch, `0x03` RPC, `0x04` TabularResult.
- **status** (1 byte): bit 0 = EOM (last packet of message), bit 1 = ignore.
- **length** (2 bytes BE): total packet size including header. Max 32767.
- **spid** (2 bytes BE): server process id; client sends 0.
- **packet_id** (1 byte): wraps 0x00 → 0xff for the connection lifetime.
- **window** (1 byte): 0.

The fixed layout is `src/tds/tds_internal.h:tds_header_t`. Our framing code lives in `src/tds/packet.c` — that's the only file that touches the socket.

## The login dance

A successful TDS login is a four-stage handshake:

1. **PRELOGIN** — client sends a list of options (version, encryption, instance name, MARS), server replies with its version and the negotiated encryption byte.
2. **TLS handshake** — if either side asked for encryption, perform a TLS handshake. **TLS records during the handshake are wrapped inside TDS PRELOGIN packets** (type `0x12`). This is the SQL Server quirk — every other implementation gets it wrong on the first try.
3. **LOGIN7** — sends client metadata, target database, and either SSPI Negotiate token (Windows auth) or username+password (SQL auth). The LOGIN7 packet is encrypted via the just-negotiated TLS.
4. **LOGIN response** — server replies with `LOGINACK` + `ENVCHANGE` tokens, optional `ERROR` token if login failed, then `DONE`. **In login-only encryption mode (the SQL Server default), the response comes back PLAINTEXT, not encrypted.** This asymmetry is critical and is the second pitfall.

After step 4, in login-only mode, the TLS layer is torn down. In full-session mode (`Force Encryption = Yes`), TLS persists through the connection lifetime.

### The TLS framing quirk, in detail

The PRELOGIN packet is sent in plain TDS framing. After both sides agree to encrypt, the client begins a TLS handshake — but instead of sending TLS records directly on the TCP socket, **each TLS record's bytes are wrapped in a TDS PRELOGIN packet body**. The server unwraps them, feeds them to its TLS implementation, and replies the same way.

After the handshake completes, SQL Server switches to a different scheme:
- **Outbound encrypted LOGIN7**: client sends raw TLS application data records on the TCP socket, NOT wrapped in TDS packets
- **Inbound LOGIN response**: server sends plaintext TDS TABULAR (`0x04`) packets, NOT encrypted at all
- **After LOGIN7 ack**: TLS layer is torn down entirely; both sides communicate plaintext TDS packets

This three-state asymmetry is encoded in our state machine:

```c
#define TDS_TLS_STATE_NONE      0
#define TDS_TLS_STATE_HANDSHAKE 1   /* TLS records inside TDS PRELOGIN packets */
#define TDS_TLS_STATE_RAW_TLS   2   /* TLS records sent raw on the wire */
```

`tds_send_state` and `tds_recv_state` are tracked independently because the directions can transition at different times. See `src/tds/connect.c` for the state transitions.

## Why we wrote our own TLS layer twice

For Linux unit tests we use OpenSSL with memory BIOs — OpenSSL takes plaintext bytes, produces ciphertext records, and we wrap them in TDS PRELOGIN packets manually during the handshake phase. After handshake, we drain ciphertext from OpenSSL and send raw. See `src/tds/tls_openssl.c` (~250 lines).

For Windows production builds we use Schannel via the SSPI surface — `AcquireCredentialsHandleW` for the credentials, `InitializeSecurityContextW` for the handshake loop, `EncryptMessage`/`DecryptMessage` for post-handshake records. Same TLS-record-inside-TDS-PRELOGIN-packet plumbing, different API. See `src/tds/tls_schannel.c`. **Currently a stub in v0.1.0** — the OpenSSL Linux test path proves the protocol mechanics are correct, and the Schannel fill-in is a v0.1.1 deliverable.

## Token-stream parsing

After LOGIN7 ack, every server response is a stream of tokens. The token bytes we care about:

| Token | Hex | Meaning |
|---|---|---|
| `COLMETADATA` | `0x81` | Column metadata for the upcoming rows |
| `ROW` | `0xD1` | One row of cell data |
| `NBCROW` | `0xD2` | Like `ROW` but with a leading null bitmap |
| `DONE` | `0xFD` | End of a result set |
| `DONEPROC` | `0xFE` | End of a stored procedure |
| `DONEINPROC` | `0xFF` | End of a batch within a procedure |
| `ENVCHANGE` | `0xE3` | Environment change (e.g., default DB switched) |
| `ERROR` | `0xAA` | Server-side error |
| `INFO` | `0xAB` | Informational message |
| `LOGINACK` | `0xAD` | Login acknowledgment |
| `ORDER` | `0xA9` | Order columns |
| `RETURNSTATUS` | `0x79` | Return status from a procedure |

Our parser (`src/tds/tokens.c`) reads all packets of a response into a single growable buffer (using the `DONE_MORE` bit to detect when the server is done emitting), then walks the byte stream once and dispatches to per-token handlers. Buffer-then-walk trades a bit of memory for radically simpler parser code — recon queries return at most a few thousand rows, so the buffer cap at 4 MB is fine.

The parser is **defensive**: every token's length field is bounds-checked against the buffer. A short read in `COLMETADATA` returns `TDS_ERR_PROTOCOL` immediately rather than reading past the buffer. **This matters because BOFs run in the beacon's address space; a parser overflow is a dead beacon.**

## Data type decoding

TDS has three categories of types in COLMETADATA:

- **Fixed-length** (INT1, INT2, INT4, INT8, BIT, MONEY, DATETIME, FLT4, FLT8): no extra metadata. Cell data is N bytes.
- **Byte-length** (INTN, BITN, FLTN, GUID, etc.): metadata has a 1-byte declared max length. Cell data has a 1-byte actual length, with `0xFF` meaning NULL.
- **USHORT-length char/binary** (BIGCHAR, BIGVARCHAR, NCHAR, NVARCHAR, BIGBINARY, BIGVARBINARY): metadata has a 2-byte max length and (for char types) a 5-byte collation. Cell data has a 2-byte actual length, with `0xFFFF` meaning NULL.
- **Long-length** (TEXT, NTEXT, IMAGE): 4-byte length, plus a text pointer header before the data, plus a 5-byte collation for char types, plus a US_VARCHAR table name.

Decoding lives in `src/tds/tokens.c:parse_cell` and the `tds_result_get_*` family in `src/tds/result.c`. We support enough types to drive `sys.databases`, `sys.servers`, `sys.server_principals`, `sys.configurations`, and the introspection bundle in `mssql_info`. Unsupported types (`SQL_VARIANT`, `XML`, geography) decode to a `<unsupported>` placeholder.

## Pull-model row iteration

The result struct holds the column metadata + a linked list of rows that the parser produced. The iterator walks the list:

```c
tds_result_t *r;
tds_query(c, L"SELECT name FROM sys.databases", &r);
while (tds_result_next_row(r) == 1) {
    wchar_t name[128];
    tds_result_get_str(r, 0, name, 128);
    BeaconPrintf(CALLBACK_OUTPUT, "%ls", name);
}
tds_result_free(r);
```

Pull-model with no callbacks is the right choice for BOFs: easier to reason about, easier to test on Linux, easier for contributors to understand. Trade-off: all rows of a query are buffered before iteration begins. For our recon queries (tens to thousands of rows max), this is the right trade.

## Memory and process discipline

BOFs run inside the beacon process, so leaks compound forever:

- Every `m_malloc` is paired with an `m_free` on every exit path — success and error
- The `tds_close` cleanup walks the row chain and frees everything
- All allocations go through dynamically resolved `MSVCRT$malloc` so the COFF loader handles them — no static buffers, no `.bss` writable data, no globals
- Token parser uses fixed-size on-stack buffers where possible
- Output is streamed via `BeaconPrintf(CALLBACK_OUTPUT, ...)` row by row, not buffered then dumped at the end

## Wire-level test against live SQL

The Linux test harness (`tests/`) drives the TDS library against `mcr.microsoft.com/mssql/server:2019-latest` and `:2022-latest` containers. Tests cover packet framing, PRELOGIN both encryption modes, full TLS handshake via OpenSSL, LOGIN7 with SQL auth, SQLBatch, the major data types, multi-row iteration, NULL handling.

```bash
make tds && make test
```

```
test_tds_header_layout                       PASS
test_packet_id_rollover                      PASS
test_prelogin_against_live_sql[2019]         PASS
test_prelogin_against_live_sql[2022]         PASS
test_connect_and_select_one[2019]            PASS  → SELECT 1 = 1
test_connect_and_select_one[2022]            PASS
test_select_version[2019]                    PASS  → @@VERSION banner
test_select_version[2022]                    PASS
test_select_databases[2019]                  PASS  → master/tempdb/model/msdb
test_select_databases[2022]                  PASS
```

10/10 against both server versions, on every PR, before any Windows build is even attempted. The architectural choice that makes this project actually shippable is **isolating the TDS protocol layer as a Linux-buildable .so**. Every protocol bug found here is a bug not found at 2 AM in a beacon.

## Reading the code

Order to read, easiest to hardest:

1. `src/tds/tds.h` — public API, ~10 functions
2. `src/tds/packet.c` — socket + TDS framing, dual Linux/Windows
3. `src/tds/prelogin.c` — option table builder/parser
4. `src/tds/tls_openssl.c` — Linux TLS with the SQL Server quirk
5. `src/tds/login7.c` — LOGIN7 packet builder
6. `src/tds/sqlbatch.c` — SQLBatch with ALL_HEADERS
7. `src/tds/tokens.c` — the token-stream parser (longest file)
8. `src/tds/result.c` — pull-model iterator
9. `src/tds/connect.c` — orchestration

Then look at any one BOF (e.g., `src/bofs/mssql_info.c`) to see how thin the BOF shims are once the protocol layer exists.
