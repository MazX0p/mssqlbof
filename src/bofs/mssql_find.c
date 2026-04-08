/*
 * mssql_find — enumerate MSSQLSvc SPNs in the current domain via LDAP.
 *
 * Pure LDAP, no TDS connection. Loads wldap32.dll.
 *
 * Usage:
 *   mssql_find                 (current domain, table output)
 *   mssql_find --json          (machine-parseable)
 *   mssql_find --domain corp.local
 */

#include <winsock2.h>
#include <windows.h>
#include "../bof_compat/beacon.h"
#include "../common/dynimports.h"
#include "../common/args.h"

void go(char *args, int alen) {
    bof_args_t a;
    bof_args_init(&a, args, alen);
    int json = bof_args_bool_flag(&a, "--json");
    const char *domain = bof_args_str_flag(&a, "--domain", NULL);
    (void)domain;  /* domain selection deferred — use rootDSE for now */

    /* For v0.1 we use rootDSE to discover the domain naming context, then
     * search (servicePrincipalName=MSSQLSvc/*). All bind via current creds. */
    /* ldap_initW with NULL doesn't always discover the DC. Try the
     * domain FQDN if --domain is set, otherwise let it use the configured
     * DC via DC locator (works when host is domain-joined). */
    void *ld = WLDAP32$ldap_initW(NULL, 389);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[!] mssql_find: ldap_initW failed (err=%u)",
                     KERNEL32$GetLastError());
        return;
    }
    ULONG ver = 3;
    WLDAP32$ldap_set_option(ld, 0x11 /*LDAP_OPT_PROTOCOL_VERSION*/, &ver);

    ULONG bind_rc = WLDAP32$ldap_bind_sW(ld, NULL, NULL, 0x0486 /*LDAP_AUTH_NEGOTIATE*/);
    if (bind_rc != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] mssql_find: ldap_bind_sW failed (rc=0x%x)", bind_rc);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    /* Read defaultNamingContext from rootDSE */
    wchar_t *attrs[] = { L"defaultNamingContext", NULL };
    void *res = NULL;
    ULONG rc1 = WLDAP32$ldap_search_sW(ld, (wchar_t*)L"", 0 /*BASE*/, L"(objectClass=*)",
                                       attrs, 0, &res);
    if (rc1 != 0 || !res) {
        BeaconPrintf(CALLBACK_ERROR, "[!] mssql_find: rootDSE search failed (rc=0x%x)", rc1);
        WLDAP32$ldap_unbind(ld);
        return;
    }
    void *entry = WLDAP32$ldap_first_entry(ld, res);
    if (!entry) {
        BeaconPrintf(CALLBACK_ERROR, "[!] mssql_find: empty rootDSE");
        WLDAP32$ldap_msgfree(res);
        WLDAP32$ldap_unbind(ld);
        return;
    }
    wchar_t **dnc = WLDAP32$ldap_get_valuesW(ld, entry, L"defaultNamingContext");
    wchar_t base[256] = {0};
    if (dnc && dnc[0]) {
        for (int i = 0; i < 255 && dnc[0][i]; ++i) base[i] = dnc[0][i];
    }
    if (dnc) WLDAP32$ldap_value_freeW(dnc);
    WLDAP32$ldap_msgfree(res);

    /* Search for MSSQLSvc SPNs */
    wchar_t *attrs2[] = { L"servicePrincipalName", L"sAMAccountName", NULL };
    res = NULL;
    BeaconPrintf(CALLBACK_OUTPUT, "[*] base=%ls", base);
    ULONG rc2 = WLDAP32$ldap_search_sW(ld, base, 2 /*SUBTREE*/,
                               L"(servicePrincipalName=MSSQLSvc/*)",
                               attrs2, 0, &res);
    if (rc2 != 0 || !res) {
        BeaconPrintf(CALLBACK_ERROR, "[!] mssql_find: SPN search failed (rc=0x%x)", rc2);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    if (json) BeaconPrintf(CALLBACK_OUTPUT, "[");
    else      BeaconPrintf(CALLBACK_OUTPUT, "%-40ls %-20ls", L"SPN", L"Account");

    int first = 1;
    for (entry = WLDAP32$ldap_first_entry(ld, res); entry;
         entry = WLDAP32$ldap_next_entry(ld, entry)) {
        wchar_t **spns  = WLDAP32$ldap_get_valuesW(ld, entry, L"servicePrincipalName");
        wchar_t **names = WLDAP32$ldap_get_valuesW(ld, entry, L"sAMAccountName");
        const wchar_t *acct = (names && names[0]) ? names[0] : L"?";
        if (spns) {
            for (int i = 0; spns[i]; ++i) {
                /* Filter again — entry may have non-MSSQL SPNs too */
                const wchar_t *s = spns[i];
                if (s[0] != L'M' || s[1] != L'S' || s[2] != L'S' ||
                    s[3] != L'Q' || s[4] != L'L' || s[5] != L'S' || s[6] != L'v' ||
                    s[7] != L'c' || s[8] != L'/') continue;
                if (json) {
                    BeaconPrintf(CALLBACK_OUTPUT, "%s{\"spn\":\"%ls\",\"account\":\"%ls\"}",
                                 first ? "" : ",", s, acct);
                    first = 0;
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "%-40ls %-20ls", s, acct);
                }
            }
            WLDAP32$ldap_value_freeW(spns);
        }
        if (names) WLDAP32$ldap_value_freeW(names);
    }
    if (json) BeaconPrintf(CALLBACK_OUTPUT, "]");

    WLDAP32$ldap_msgfree(res);
    WLDAP32$ldap_unbind(ld);
}
