/*
 * mssql_hello — sanity-check BOF.
 *
 * Validates the cross-compile path, dynamic-import resolution, and the
 * Beacon API surface before any TDS code is involved. Loaded in any C2's
 * COFF loader (CS, Havoc, Sliver, MSF, Adaptix), it should print:
 *   "MSSQLBOF hello (x64 build)"
 *
 * Build:
 *   make BOFS=mssql_hello
 *
 * Run via Adaptix CLI:
 *   inline-execute build/mssql_hello.x64.o go
 */

#include <winsock2.h>
#include <windows.h>
#include "../bof_compat/beacon.h"
#include "../common/dynimports.h"

void go(char *args, int alen) {
    (void)args; (void)alen;
    BeaconPrintf(CALLBACK_OUTPUT,
                 "MSSQLBOF hello (%s build) — beacon api ok",
                 sizeof(void*) == 8 ? "x64" : "x86");
}
