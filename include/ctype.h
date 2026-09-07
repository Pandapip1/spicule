/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef	_CTYPE_H
#define	_CTYPE_H

#include <features.h>

/* POSIX requires locale_t here unconditionally, unlike locale.h's own
 * feature-test gating of newlocale() et al. */
#define __NEED_locale_t

#include <bits/alltypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Pure arithmetic on `(unsigned)c`: no locale read, errno, or state, hence
 * __attribute__((__pure__)).
 *
 * Deliberately ASCII-only for c in 0x80-0xff. spicule's char* strings are
 * UTF-8, where a lone byte in that range is always a continuation or lead
 * byte, never a complete character -- so "false" is the correct answer, not
 * a limitation. A decoded code point (e.g. "é") is what iswalpha() is for. */
int   isalnum(int) __attribute__((__pure__));
int   isalpha(int) __attribute__((__pure__));
int   isblank(int) __attribute__((__pure__));
int   iscntrl(int) __attribute__((__pure__));
int   isdigit(int) __attribute__((__pure__));
int   isgraph(int) __attribute__((__pure__));
int   islower(int) __attribute__((__pure__));
int   isprint(int) __attribute__((__pure__));
int   ispunct(int) __attribute__((__pure__));
int   isspace(int) __attribute__((__pure__));
int   isupper(int) __attribute__((__pure__));
int   isxdigit(int) __attribute__((__pure__));
int   tolower(int) __attribute__((__pure__));
int   toupper(int) __attribute__((__pure__));

/* spicule's locale.c accepts only "C"/"POSIX", so each _l function is
 * equivalent to its non-_l sibling and ignores its locale_t argument
 * (same precedent as strcasecmp_l() in strings.h). Still __pure__ since
 * the ignored argument is never dereferenced. */
int   isalnum_l(int, locale_t) __attribute__((__pure__));
int   isalpha_l(int, locale_t) __attribute__((__pure__));
int   isblank_l(int, locale_t) __attribute__((__pure__));
int   iscntrl_l(int, locale_t) __attribute__((__pure__));
int   isdigit_l(int, locale_t) __attribute__((__pure__));
int   isgraph_l(int, locale_t) __attribute__((__pure__));
int   islower_l(int, locale_t) __attribute__((__pure__));
int   isprint_l(int, locale_t) __attribute__((__pure__));
int   ispunct_l(int, locale_t) __attribute__((__pure__));
int   isspace_l(int, locale_t) __attribute__((__pure__));
int   isupper_l(int, locale_t) __attribute__((__pure__));
int   isxdigit_l(int, locale_t) __attribute__((__pure__));
int   tolower_l(int, locale_t) __attribute__((__pure__));
int   toupper_l(int, locale_t) __attribute__((__pure__));

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int   isascii(int) __attribute__((__pure__));
int   toascii(int) __attribute__((__pure__));
#define _tolower(a) ((a)|0x20)
#define _toupper(a) ((a)&0x5f)
#endif

#ifdef __cplusplus
}
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
