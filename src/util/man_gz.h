/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Tier 4 of src/util/man.c's own troff-engine plan: gzip decompression
 * for `.gz` man pages (RFC 1952's container format, wrapping RFC
 * 1951's own DEFLATE compressed-data format). A private header of its
 * own rather than folded into src/internal/util.h's flat function
 * list -- same reasoning src/util/tablist.h's own header comment gives
 * for expand(1p)/unexpand(1p)'s shared -t grammar: this is real,
 * substantial logic (a whole compression algorithm) with exactly one
 * caller (src/util/man.c) today, kept in its own translation unit so
 * that already-2800-line file doesn't grow by another thousand, not
 * because two *different* utilities share it the way tablist.h's
 * grammar is shared.
 *
 * See src/util/man_gz.c's own header comment for the algorithm itself
 * and every deliberate simplification.
 *
 * This internal header, like the public C library headers, must use the
 * implementation-reserved namespace for its guard so it cannot collide
 * with user code.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#ifndef _NTLIBC_UTIL_MAN_GZ_H
#define _NTLIBC_UTIL_MAN_GZ_H

#include <stddef.h>

/* True iff `data`'s first two bytes are gzip's own magic number (RFC
 * 1952 SS2.3.1, 0x1f 0x8b) -- a candidate man page is treated as
 * gzip-compressed by this magic OR by a literal ".gz" name (see
 * src/util/man.c's own man_read_page()), matching how a real gzip(1)
 * itself decides, since a compressed page need not be named ".gz" to
 * actually be compressed. `len` < 2 is never a match. */
int man_looks_gzipped(const char *data, size_t len);

/* Decompresses one RFC 1952 gzip member -- `in`/`inlen` starting at
 * the magic number -- into a fresh malloc'd buffer.
 *
 * On success returns 1 with *out and *outlen set: an owned buffer the
 * caller must free(), same contract as src/util/man.c's own
 * man_read_file(). On any malformed input returns 0, *out and *outlen
 * left untouched, and *errmsg pointing at a static (never malloc'd,
 * never to be freed, safe to printf directly) diagnostic string.
 *
 * Only the FIRST gzip member of `in` is decompressed -- a documented
 * simplification. RFC 1952 permits concatenating several independent
 * members back to back in one stream, but every real man page on a
 * real system is the product of one "gzip -9 page.1" invocation, one
 * member, so this is not a real-world gap. */
int man_gunzip(const char *in, size_t inlen, char **out, size_t *outlen, const char **errmsg);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
