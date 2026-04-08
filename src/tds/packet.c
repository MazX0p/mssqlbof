/*
 * TDS packet framing — send/recv with chunked payloads.
 *
 * On Linux (TDS_LINUX_TEST) this uses POSIX sockets directly via libc.
 * On Windows (BOF build) this uses Winsock through dynamic imports.
 *
 * The goal of this file is to be the ONLY place that touches the socket
 * directly. TLS, SSPI, SQLBatch, and tokens all go through tds_packet_send /
 * tds_packet_recv (or tds_raw_send / tds_raw_recv during the TLS handshake
 * inside the PRELOGIN packet).
 */

#include "tds_internal.h"
#include <stdarg.h>

#ifdef _WIN32
  #include "../common/dynimports.h"
  #define X_send(s,b,l,f)         WS2_32$send(s,(const char*)(b),(int)(l),f)
  #define X_recv(s,b,l,f)         WS2_32$recv(s,(char*)(b),(int)(l),f)
  #define X_close(s)              WS2_32$closesocket(s)
  #define X_socket(d,t,p)         WS2_32$socket(d,t,p)
  #define X_connect(s,a,l)        WS2_32$connect(s,a,l)
  #define X_getaddrinfo(h,p,h2,r) WS2_32$getaddrinfo(h,p,h2,r)
  #define X_freeaddrinfo(r)       WS2_32$freeaddrinfo(r)
  #define X_htons(x)              WS2_32$htons(x)
  #define X_ntohs(x)              WS2_32$ntohs(x)
  #define X_memcpy(d,s,n)         MSVCRT$memcpy(d,s,n)
  #define X_memset(d,v,n)         MSVCRT$memset(d,v,n)
  #define X_snprintf              MSVCRT$_snprintf
  #define X_snwprintf             MSVCRT$_snwprintf
  #define X_wcslen                MSVCRT$wcslen
  #define X_malloc(n)             MSVCRT$malloc(n)
  #define X_free(p)               MSVCRT$free(p)
#else
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <unistd.h>
  #include <wchar.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <netinet/tcp.h>
  #include <errno.h>
  #define X_send(s,b,l,f)         send(s,b,l,f)
  #define X_recv(s,b,l,f)         recv(s,b,l,f)
  #define X_close(s)              close(s)
  #define X_socket(d,t,p)         socket(d,t,p)
  #define X_connect(s,a,l)        connect(s,a,l)
  #define X_getaddrinfo(h,p,h2,r) getaddrinfo(h,p,h2,r)
  #define X_freeaddrinfo(r)       freeaddrinfo(r)
  #define X_htons(x)              htons(x)
  #define X_ntohs(x)              ntohs(x)
  #define X_memcpy(d,s,n)         memcpy(d,s,n)
  #define X_memset(d,v,n)         memset(d,v,n)
  #define X_snprintf              snprintf
  #define X_snwprintf             swprintf
  #define X_wcslen                wcslen
  #define X_malloc(n)             malloc(n)
  #define X_free(p)               free(p)
#endif

void tds_set_error_a(struct tds_conn *c, const char *fmt, ...) {
    if (!c) return;
    char tmp[512];
    va_list ap;
    va_start(ap, fmt);
#ifdef _WIN32
    MSVCRT$_vsnprintf(tmp, sizeof(tmp), fmt, ap);
#else
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
#endif
    va_end(ap);
    tmp[sizeof(tmp)-1] = 0;
    size_t i = 0;
    for (; i < sizeof(c->last_error)/sizeof(wchar_t) - 1 && tmp[i]; ++i)
        c->last_error[i] = (wchar_t)(unsigned char)tmp[i];
    c->last_error[i] = 0;
}

void tds_set_error(struct tds_conn *c, const wchar_t *fmt, ...) {
    if (!c) return;
    /* Simple copy — full wide printf is overkill for what we need. */
#ifdef _WIN32
    size_t i = 0;
    for (; i < sizeof(c->last_error)/sizeof(wchar_t) - 1 && fmt[i]; ++i)
        c->last_error[i] = fmt[i];
    c->last_error[i] = 0;
#else
    va_list ap;
    va_start(ap, fmt);
    vswprintf(c->last_error, sizeof(c->last_error)/sizeof(wchar_t), fmt, ap);
    va_end(ap);
#endif
}

int tds_socket_open(struct tds_conn *c, const char *host, uint16_t port) {
#ifdef _WIN32
    WSADATA wsa;
    int wsa_rc = WS2_32$WSAStartup(0x0202, &wsa);
    if (wsa_rc != 0) {
        tds_set_error_a(c, "WSAStartup failed (rc=%d)", wsa_rc);
        return TDS_ERR_NETWORK;
    }
#endif
    char portstr[8];
    X_snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);

    struct addrinfo hints;
    X_memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *res = NULL;
    int gai_rc = X_getaddrinfo(host, portstr, &hints, &res);
    if (gai_rc != 0 || !res) {
        /* Manual error string build — printf %s with mingw + MSVCRT
         * dynamic import has been unreliable in our test runs. */
        char ebuf[256];
        const char *prefix = "getaddrinfo failed for host=[";
        size_t pos = 0;
        for (size_t i = 0; prefix[i] && pos < 255; ++i) ebuf[pos++] = prefix[i];
        for (size_t i = 0; host && host[i] && pos < 240; ++i) ebuf[pos++] = host[i];
        const char *suffix = "] gai_rc=";
        for (size_t i = 0; suffix[i] && pos < 250; ++i) ebuf[pos++] = suffix[i];
        /* int to ascii */
        char nbuf[16]; int ni = 0; int v = gai_rc;
        if (v < 0) { ebuf[pos++] = '-'; v = -v; }
        if (v == 0) nbuf[ni++] = '0';
        while (v > 0) { nbuf[ni++] = '0' + (v % 10); v /= 10; }
        while (ni > 0 && pos < 254) ebuf[pos++] = nbuf[--ni];
        ebuf[pos] = 0;
        /* Copy to last_error as wchar */
        size_t k = 0;
        for (; k < sizeof(c->last_error)/sizeof(wchar_t) - 1 && ebuf[k]; ++k)
            c->last_error[k] = (wchar_t)(unsigned char)ebuf[k];
        c->last_error[k] = 0;
        return TDS_ERR_NETWORK;
    }

    tds_socket_t s = X_socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == TDS_INVALID_SOCK) {
        X_freeaddrinfo(res);
        tds_set_error_a(c, "socket() failed");
        return TDS_ERR_NETWORK;
    }

    if (X_connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
        X_close(s);
        X_freeaddrinfo(res);
        tds_set_error_a(c, "connect() failed");
        return TDS_ERR_NETWORK;
    }
    X_freeaddrinfo(res);

    /* Disable Nagle + set a recv timeout so a hung login doesn't deadlock
     * the BOF process. 15-second recv timeout = reasonable upper bound for
     * any single TDS packet. */
    int one = 1;
#ifdef _WIN32
    WS2_32$setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof(one));
    DWORD timeo = 15000;  /* ms */
    WS2_32$setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeo, sizeof(timeo));
    WS2_32$setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeo, sizeof(timeo));
#else
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    struct timeval tv = { .tv_sec = 15, .tv_usec = 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    c->sock      = s;
    c->packet_id = 0;
    c->rx_len    = 0;
    c->rx_pos    = 0;
    return TDS_OK;
}

void tds_socket_close(struct tds_conn *c) {
    if (c && c->sock != TDS_INVALID_SOCK) {
        X_close(c->sock);
        c->sock = TDS_INVALID_SOCK;
#ifdef _WIN32
        WS2_32$WSACleanup();
#endif
    }
}

int tds_raw_send(struct tds_conn *c, const uint8_t *data, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = X_send(c->sock, data + off, (int)(len - off), 0);
        if (n <= 0) {
            tds_set_error_a(c, "send() failed");
            return TDS_ERR_NETWORK;
        }
        off += (size_t)n;
    }
    return TDS_OK;
}

int tds_raw_recv(struct tds_conn *c, uint8_t *out, size_t want) {
    size_t got = 0;
    while (got < want) {
        int n = X_recv(c->sock, out + got, (int)(want - got), 0);
        if (n <= 0) {
            tds_set_error_a(c, "recv() failed or eof");
            return TDS_ERR_NETWORK;
        }
        got += (size_t)n;
    }
    return TDS_OK;
}

int tds_packet_send(struct tds_conn *c, uint8_t type, const uint8_t *payload, size_t len) {
    /* For v1 we always emit a single packet (EOM=1). Chunked send for >4K
     * payloads can be added later when LOGIN7 SSPI tokens grow.
     *
     * IMPORTANT: cannot use a 32 KB stack buffer here — that crosses x64
     * Windows guard pages without __chkstk probing and crashes BOF loaders.
     * Heap-allocate instead. */
    if (len + TDS_HEADER_SIZE > TDS_MAX_PACKET_SIZE) return TDS_ERR_PROTOCOL;

    size_t total = len + TDS_HEADER_SIZE;
    uint8_t *buf = (uint8_t*)X_malloc(total);
    if (!buf) return TDS_ERR_ALLOC;

    tds_header_t *h = (tds_header_t*)buf;
    h->type      = type;
    h->status    = TDS_STATUS_EOM;
    h->length    = X_htons((uint16_t)total);
    h->spid      = 0;
    h->packet_id = c->packet_id++;
    h->window    = 0;
    if (len) X_memcpy(buf + TDS_HEADER_SIZE, payload, len);

    int rc;
    if (c->tls_send_state != TDS_TLS_STATE_NONE) {
        rc = tds_tls_send(c, buf, total);
    } else {
        rc = tds_raw_send(c, buf, total);
    }
    X_free(buf);
    return rc;
}

int tds_packet_recv(struct tds_conn *c) {
    uint8_t hdr[TDS_HEADER_SIZE];
    int rc;

    if (c->tls_recv_state != TDS_TLS_STATE_NONE) {
        rc = tds_tls_recv(c, hdr, TDS_HEADER_SIZE);
    } else {
        rc = tds_raw_recv(c, hdr, TDS_HEADER_SIZE);
    }
    if (rc != TDS_OK) return rc;

    tds_header_t *h = (tds_header_t*)hdr;
    c->rx_status = h->status;
    uint16_t total = X_ntohs(h->length);
    if (total < TDS_HEADER_SIZE || total > TDS_MAX_PACKET_SIZE) {
        tds_set_error_a(c, "bad packet length in TDS header");
        return TDS_ERR_PROTOCOL;
    }
    size_t payload = (size_t)(total - TDS_HEADER_SIZE);

    if (c->tls_recv_state != TDS_TLS_STATE_NONE) {
        rc = tds_tls_recv(c, c->rx_buf, payload);
    } else {
        rc = tds_raw_recv(c, c->rx_buf, payload);
    }
    if (rc != TDS_OK) return rc;

    c->rx_len = payload;
    c->rx_pos = 0;
    return TDS_OK;
}

#ifdef TDS_LINUX_TEST
size_t  tds_test_header_size(void)             { return sizeof(tds_header_t); }
uint8_t tds_test_next_packet_id(uint8_t cur)   { return (uint8_t)(cur + 1); }
#endif
