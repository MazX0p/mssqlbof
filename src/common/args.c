/*
 * args.c — minimal argv-style parser for BOF command lines.
 *
 * Convention: the C2 .cna / Adaptix command file packs ONE null-terminated
 * string containing the entire command line, joined with spaces. The BOF
 * uses BeaconDataParse + BeaconDataExtract to fetch it, then bof_args_init
 * tokenizes it in place (mutates the buffer) into argv-style tokens.
 *
 * Tokens are split on whitespace. Quoted strings (single or double) are
 * preserved as one token (quotes stripped). No escape handling — keep it
 * simple, the operator can re-quote if needed.
 *
 * Flag lookup uses linear scan — there are at most ~5 flags per BOF, so
 * O(N) is fine and removes the need for a hash table.
 */

#include "args.h"

#ifdef _WIN32
  #include <windows.h>
  #include "dynimports.h"
  #define X_strcmp(a,b)  MSVCRT$strcmp(a,b)
  #define X_stricmp(a,b) MSVCRT$_stricmp(a,b)
  #define X_strtol(s,e,b) MSVCRT$strtol(s,e,b)
#else
  #include <string.h>
  #include <stdlib.h>
  #define X_strcmp(a,b)  strcmp(a,b)
  #define X_stricmp(a,b) strcasecmp(a,b)
  #define X_strtol(s,e,b) strtol(s,e,b)
#endif

static int is_ws(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

/* The raw beacon args buffer is exactly `alen` bytes with no terminator,
 * so we cannot tokenize in place. We allocate a NUL-terminated copy via
 * dynamic-imported malloc and stash the pointer in a->raw_owned (caller
 * must free via bof_args_free). For the lifetime of go() this is fine. */

int bof_args_init(bof_args_t *a, const char *raw, int rlen) {
    a->raw = raw;
    a->rlen = rlen;
    a->n_tok = 0;
    if (!raw || rlen <= 0) return 1;

#ifdef _WIN32
    char *buf = (char*)MSVCRT$malloc(rlen + 1);
    if (!buf) return 0;
    MSVCRT$memcpy(buf, raw, rlen);
#else
    char *buf = (char*)malloc(rlen + 1);
    if (!buf) return 0;
    memcpy(buf, raw, rlen);
#endif
    buf[rlen] = 0;
    a->owned = buf;

    char *p = buf;
    char *end = p + rlen;
    while (p < end && a->n_tok < 32) {
        while (p < end && is_ws(*p)) ++p;
        if (p >= end || *p == 0) break;
        char quote = 0;
        if (*p == '"' || *p == '\'') { quote = *p; ++p; }
        a->tok[a->n_tok++] = p;
        if (quote) {
            while (p < end && *p && *p != quote) ++p;
        } else {
            while (p < end && *p && !is_ws(*p)) ++p;
        }
        if (p < end) { *p = 0; ++p; }
    }
    return 1;
}

/* Skip flag pairs to find the Nth POSITIONAL token. */
const char *bof_args_str_pos(bof_args_t *a, int pos) {
    int seen = 0;
    for (int i = 0; i < a->n_tok; ++i) {
        const char *t = a->tok[i];
        if (t[0] == '-' && t[1] == '-') {
            /* skip flag and (if not bool) its value */
            ++i;
            continue;
        }
        if (seen == pos) return t;
        ++seen;
    }
    return NULL;
}

const char *bof_args_str_flag(bof_args_t *a, const char *name, const char *dflt) {
    for (int i = 0; i < a->n_tok - 1; ++i) {
        if (X_strcmp(a->tok[i], name) == 0) return a->tok[i + 1];
    }
    return dflt;
}

/* Like bof_args_str_flag, but for flags whose value is free-form text that
 * the caller's shell/C2 may have split on whitespace. Joins every token
 * after `name` until the next "--flag" token or end-of-args with a space
 * separator. Mutates the backing buffer (patches inter-token NULs to
 * spaces) so the returned pointer remains stable. Used by --sql and --cmd
 * which regularly contain spaces and need to survive a C2 that strips
 * outer quotes before passing param_data to the BOF. */
const char *bof_args_str_flag_tail(bof_args_t *a, const char *name, const char *dflt) {
    int i;
    for (i = 0; i < a->n_tok; ++i) {
        if (X_strcmp(a->tok[i], name) == 0) break;
    }
    if (i >= a->n_tok - 1) return dflt;
    int start = i + 1;
    int end = start;
    while (end < a->n_tok) {
        const char *t = a->tok[end];
        if (t[0] == '-' && t[1] == '-') break;
        ++end;
    }
    if (end == start) return dflt;
    /* Patch any NULs between tok[start] and the end of tok[end-1] into
     * spaces so the memory reads as one contiguous string. We walk from
     * the first byte of tok[start] to the last byte before tok[end]
     * (or end of buffer if end == n_tok) and fix any zero we find. */
    char *first = (char*)a->tok[start];
    char *last_end;
    if (end < a->n_tok) {
        last_end = (char*)a->tok[end];  /* stop before the next flag token */
        /* step back past any trailing NULs that came from token termination */
        if (last_end > first) last_end--;
    } else {
        /* walk to the end of the owned buffer */
        last_end = a->owned + a->rlen;
    }
    for (char *p = first; p < last_end; ++p) {
        if (*p == 0) *p = ' ';
    }
    return first;
}

int bof_args_bool_flag(bof_args_t *a, const char *name) {
    for (int i = 0; i < a->n_tok; ++i) {
        if (X_strcmp(a->tok[i], name) == 0) return 1;
    }
    return 0;
}

int bof_args_int_flag(bof_args_t *a, const char *name, int dflt) {
    const char *s = bof_args_str_flag(a, name, NULL);
    if (!s) return dflt;
    return (int)X_strtol(s, NULL, 10);
}

void bof_args_free(bof_args_t *a) {
    if (!a || !a->owned) return;
#ifdef _WIN32
    MSVCRT$free(a->owned);
#else
    free(a->owned);
#endif
    a->owned = NULL;
}
