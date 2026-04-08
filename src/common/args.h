#ifndef MSSQLBOF_ARGS_H
#define MSSQLBOF_ARGS_H

#include <stdint.h>

/* Lightweight wrapper around BeaconDataParse + BeaconDataExtract for the
 * BOF arg convention used by every command:
 *
 *   <verb> <required_positional> [--flag value] [--flag value] [--bool-flag]
 *
 * Usage in a BOF:
 *
 *   bof_args_t a;
 *   if (!bof_args_init(&a, args, length)) { error; return; }
 *   const char *target = bof_args_str_pos(&a, 0);              // target host
 *   const char *via    = bof_args_str_flag(&a, "--via", NULL); // optional
 *   int json           = bof_args_bool_flag(&a, "--json");
 *
 * The parser assumes args were packed with BeaconDataParse on the C2 side.
 */

typedef struct {
    const char  *raw;
    int          rlen;
    int          n_tok;
    char        *owned;     /* heap copy of raw, owns the tok pointers */
    const char  *tok[32];   /* pointers into owned, NUL-terminated */
} bof_args_t;

int          bof_args_init      (bof_args_t *a, const char *raw, int rlen);
void         bof_args_free      (bof_args_t *a);
const char  *bof_args_str_pos   (bof_args_t *a, int pos);
const char  *bof_args_str_flag  (bof_args_t *a, const char *name, const char *dflt);
/* Free-form text that may contain spaces: consumes tokens from after
 * `name` until the next --flag or end of args, joined with spaces.
 * Use for --sql / --cmd where the C2 may strip outer quotes. */
const char  *bof_args_str_flag_tail(bof_args_t *a, const char *name, const char *dflt);
int          bof_args_bool_flag (bof_args_t *a, const char *name);
int          bof_args_int_flag  (bof_args_t *a, const char *name, int dflt);

#endif
