/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <iconv.h>: codeset conversion. See src/misc/iconv.c.
 *
 * Only UTF-8 and UTF-16LE are supported (all four combinations,
 * including self-to-self as a validating copy) -- POSIX leaves supported
 * codesets implementation-defined, and these are the two spicule already
 * converts between internally for every ntdll call. Anything else fails
 * with (iconv_t)-1/EINVAL. Names are matched case-insensitively, ignoring
 * '-'/'_'; "UCS-2LE" is deliberately not accepted as a UTF-16LE spelling
 * since this converter emits surrogate pairs UCS-2 cannot represent.
 */
#ifndef _ICONV_H
#define _ICONV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <allocation_tokens.h>
#include <ownership.h>

#define __NEED_size_t

#include <bits/alltypes.h>

typedef void *iconv_t;

tokdef iconv_opened
	dynamic_storage
	implemented_by(heap_allocated)
	sentinel_exclude(-1);

withtok(iconv_opened)
iconv_t iconv_open(const char *, const char *);
size_t  iconv(iconv_t, char **__restrict, size_t *__restrict,
              char **__restrict, size_t *__restrict);
int     iconv_close(iconv_t consume(iconv_opened));

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
