#ifndef MSSQLBOF_DYNIMPORTS_H
#define MSSQLBOF_DYNIMPORTS_H

/*
 * Dynamic imports for CRT, Win32, Schannel, SSPI, Winsock, LDAP.
 *
 * BOF loaders resolve symbols of the form LIBRARY$function at load time.
 * Never call libc / Win32 directly — always go through these declarations
 * so that the COFF loader (CS, Havoc, Sliver, MSF, etc.) can resolve them.
 */

/* winsock2 must precede windows.h */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <schannel.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <winldap.h>

/* ---- MSVCRT ---- */
DECLSPEC_IMPORT void * __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void * __cdecl MSVCRT$calloc(size_t, size_t);
DECLSPEC_IMPORT void * __cdecl MSVCRT$realloc(void *, size_t);
DECLSPEC_IMPORT void   __cdecl MSVCRT$free(void *);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memcpy(void *, const void *, size_t);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memset(void *, int, size_t);
DECLSPEC_IMPORT int    __cdecl MSVCRT$memcmp(const void *, const void *, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char *);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$wcslen(const wchar_t *);
DECLSPEC_IMPORT int    __cdecl MSVCRT$_snprintf(char *, size_t, const char *, ...);
DECLSPEC_IMPORT int    __cdecl MSVCRT$_vsnprintf(char *, size_t, const char *, va_list);
DECLSPEC_IMPORT int    __cdecl MSVCRT$_snwprintf(wchar_t *, size_t, const wchar_t *, ...);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strncpy(char *, const char *, size_t);
DECLSPEC_IMPORT wchar_t * __cdecl MSVCRT$wcsncpy(wchar_t *, const wchar_t *, size_t);
DECLSPEC_IMPORT int    __cdecl MSVCRT$strcmp(const char *, const char *);
DECLSPEC_IMPORT int    __cdecl MSVCRT$_stricmp(const char *, const char *);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strchr(const char *, int);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strstr(const char *, const char *);
DECLSPEC_IMPORT long   __cdecl MSVCRT$strtol(const char *, char **, int);

/* ---- KERNEL32 ---- */
DECLSPEC_IMPORT void  WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT void  WINAPI KERNEL32$SetLastError(DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$FormatMessageA(DWORD, LPCVOID, DWORD, DWORD, LPSTR, DWORD, va_list*);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$FormatMessageW(DWORD, LPCVOID, DWORD, DWORD, LPWSTR, DWORD, va_list*);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetCurrentThreadId(void);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT int   WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int   WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);

/* ---- WS2_32 (Winsock) ---- */
DECLSPEC_IMPORT int    WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
DECLSPEC_IMPORT int    WSAAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT int    WSAAPI WS2_32$WSAGetLastError(void);
DECLSPEC_IMPORT SOCKET WSAAPI WS2_32$socket(int, int, int);
DECLSPEC_IMPORT int    WSAAPI WS2_32$connect(SOCKET, const struct sockaddr*, int);
DECLSPEC_IMPORT int    WSAAPI WS2_32$send(SOCKET, const char*, int, int);
DECLSPEC_IMPORT int    WSAAPI WS2_32$recv(SOCKET, char*, int, int);
DECLSPEC_IMPORT int    WSAAPI WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT int    WSAAPI WS2_32$getaddrinfo(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
DECLSPEC_IMPORT void   WSAAPI WS2_32$freeaddrinfo(PADDRINFOA);
DECLSPEC_IMPORT u_short WSAAPI WS2_32$htons(u_short);
DECLSPEC_IMPORT u_short WSAAPI WS2_32$ntohs(u_short);
DECLSPEC_IMPORT u_long  WSAAPI WS2_32$htonl(u_long);
DECLSPEC_IMPORT u_long  WSAAPI WS2_32$ntohl(u_long);
DECLSPEC_IMPORT int     WSAAPI WS2_32$setsockopt(SOCKET, int, int, const char*, int);

/* ---- SECUR32 (SSPI Negotiate) ---- */
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY SECUR32$AcquireCredentialsHandleW(
    SEC_WCHAR*, SEC_WCHAR*, ULONG, void*, void*, SEC_GET_KEY_FN, void*, PCredHandle, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY SECUR32$InitializeSecurityContextW(
    PCredHandle, PCtxtHandle, SEC_WCHAR*, ULONG, ULONG, ULONG,
    PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY SECUR32$DeleteSecurityContext(PCtxtHandle);
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY SECUR32$FreeCredentialsHandle(PCredHandle);
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY SECUR32$FreeContextBuffer(PVOID);
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY SECUR32$QueryContextAttributesW(PCtxtHandle, ULONG, PVOID);
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY SECUR32$EncryptMessage(PCtxtHandle, ULONG, PSecBufferDesc, ULONG);
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY SECUR32$DecryptMessage(PCtxtHandle, PSecBufferDesc, ULONG, PULONG);
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY SECUR32$ApplyControlToken(PCtxtHandle, PSecBufferDesc);

/* ---- WLDAP32 (used by mssql_find) ---- */
DECLSPEC_IMPORT void* __cdecl WLDAP32$ldap_initW(const wchar_t*, ULONG);
DECLSPEC_IMPORT ULONG __cdecl WLDAP32$ldap_bind_sW(void*, const wchar_t*, const wchar_t*, ULONG);
DECLSPEC_IMPORT ULONG __cdecl WLDAP32$ldap_search_sW(void*, const wchar_t*, ULONG, const wchar_t*, wchar_t**, ULONG, void**);
DECLSPEC_IMPORT ULONG __cdecl WLDAP32$ldap_unbind(void*);
DECLSPEC_IMPORT void* __cdecl WLDAP32$ldap_first_entry(void*, void*);
DECLSPEC_IMPORT void* __cdecl WLDAP32$ldap_next_entry(void*, void*);
DECLSPEC_IMPORT wchar_t** __cdecl WLDAP32$ldap_get_valuesW(void*, void*, const wchar_t*);
DECLSPEC_IMPORT ULONG __cdecl WLDAP32$ldap_value_freeW(wchar_t**);
DECLSPEC_IMPORT ULONG __cdecl WLDAP32$ldap_msgfree(void*);
DECLSPEC_IMPORT ULONG __cdecl WLDAP32$ldap_set_option(void*, int, void*);
DECLSPEC_IMPORT ULONG __cdecl WLDAP32$ldap_get_optionW(void*, int, void*);

/* ---- BCRYPT (for manual NTLMv2 PTH) ---- */
typedef LONG NTSTATUS_BC;
#define BCRYPT_ALG_HANDLE_HMAC_FLAG 0x00000008
DECLSPEC_IMPORT NTSTATUS_BC WINAPI BCRYPT$BCryptOpenAlgorithmProvider(void**, const wchar_t*, const wchar_t*, ULONG);
DECLSPEC_IMPORT NTSTATUS_BC WINAPI BCRYPT$BCryptCloseAlgorithmProvider(void*, ULONG);
DECLSPEC_IMPORT NTSTATUS_BC WINAPI BCRYPT$BCryptCreateHash(void*, void**, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS_BC WINAPI BCRYPT$BCryptHashData(void*, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS_BC WINAPI BCRYPT$BCryptFinishHash(void*, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS_BC WINAPI BCRYPT$BCryptDestroyHash(void*);
DECLSPEC_IMPORT void WINAPI KERNEL32$GetSystemTimeAsFileTime(FILETIME*);

/* convenience aliases used by all source files */
#define m_malloc    MSVCRT$malloc
#define m_calloc    MSVCRT$calloc
#define m_free      MSVCRT$free
#define m_memcpy    MSVCRT$memcpy
#define m_memset    MSVCRT$memset
#define m_memcmp    MSVCRT$memcmp
#define m_strlen    MSVCRT$strlen
#define m_wcslen    MSVCRT$wcslen
#define m_snprintf  MSVCRT$_snprintf
#define m_snwprintf MSVCRT$_snwprintf

#endif
