/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef	_LOCALE_H
#define	_LOCALE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#ifdef __cplusplus
#define NULL 0L
#else
#define NULL ((void*)0)
#endif

#define LC_CTYPE    0
#define LC_NUMERIC  1
#define LC_TIME     2
#define LC_COLLATE  3
#define LC_MONETARY 4
#define LC_MESSAGES 5
#define LC_ALL      6

struct lconv {
	char *decimal_point;
	char *thousands_sep;
	char *grouping;

	char *int_curr_symbol;
	char *currency_symbol;
	char *mon_decimal_point;
	char *mon_thousands_sep;
	char *mon_grouping;
	char *positive_sign;
	char *negative_sign;
	char int_frac_digits;
	char frac_digits;
	char p_cs_precedes;
	char p_sep_by_space;
	char n_cs_precedes;
	char n_sep_by_space;
	char p_sign_posn;
	char n_sign_posn;
	char int_p_cs_precedes;
	char int_p_sep_by_space;
	char int_n_cs_precedes;
	char int_n_sep_by_space;
	char int_p_sign_posn;
	char int_n_sign_posn;
};

char  *setlocale (int, const char *);
struct lconv *localeconv(void) __attribute__((returns_nonnull));

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)

#define __NEED_locale_t

#include <ownership.h>

#include <bits/alltypes.h>

#define LC_GLOBAL_LOCALE ((locale_t)-1)

#define LC_CTYPE_MASK    (1<<LC_CTYPE)
#define LC_NUMERIC_MASK  (1<<LC_NUMERIC)
#define LC_TIME_MASK     (1<<LC_TIME)
#define LC_COLLATE_MASK  (1<<LC_COLLATE)
#define LC_MONETARY_MASK (1<<LC_MONETARY)
#define LC_MESSAGES_MASK (1<<LC_MESSAGES)
#define LC_ALL_MASK      0x7fffffff

/* locale_t tracked the same way DIR* is (dirent.h): a real acquire/
 * release token pair, not a bespoke special case. locale_opened has no
 * implemented_by(...) because ntlibc's own locale implementation hands
 * out one immutable static object for every request (src/misc/locale.c,
 * test/posix-locale.c's own audit) -- there is no further, more-primitive
 * family for freelocale() to route a release through today. That is a
 * fact about the CURRENT implementation, not a reason to leave the type
 * untracked: AllocationLifetimeChecker.cpp's checkEndFunction trusts a
 * terminal family's own consume(...) site as the release, the same way
 * it already trusts consume(...) at every CALL site regardless of the
 * callee's body (including an opaque external declaration with no body
 * to inspect at all) -- it only re-derives release from the body for a
 * family that names a further one via implemented_by(...), where that is
 * a real, checkable promise (see closedir()/catclose()/iconv_close()).
 * If a future locale implementation ever backs locale_t with real
 * per-locale storage, adding implemented_by(...) here is the only change
 * needed: the existing consume(locale_opened) below would then also
 * start proving freelocale() actually releases that storage, with no
 * further annotation changes. */
tokdef locale_opened
	dynamic_storage
	sentinel_exclude(-1);

withtok(locale_opened)
locale_t duplocale(locale_t);
void freelocale(locale_t consume(locale_opened));
withtok(locale_opened)
locale_t newlocale(int, const char *, locale_t);
locale_t uselocale(locale_t);

#endif

#ifdef __cplusplus
}
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
