/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <locale.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>

/* ntlibc supports exactly one locale, "C".  locale_t is an opaque
 * pointer; we hand out the address of one static object for it. */
struct __locale_struct { int dummy; };
static struct __locale_struct __c_locale; // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision

/* Tagged struct rather than an output-pointer parameter: writing
 * through an out-param would just reintroduce the "writes through a
 * pointer argument" disqualifier this split exists to remove. */
struct setlocale_result { char *value; int bad_cat; };

static struct setlocale_result setlocale_compute(int cat, const char *name) __attribute__((__pure__));
static struct setlocale_result setlocale_compute(int cat, const char *name)
{
	struct setlocale_result r = { 0, 0 };
	if (cat < 0 || cat > LC_ALL) { r.bad_cat = 1; return r; }
	if (!name) { r.value = (char *)"C"; return r; }
	if (!*name || !strcmp(name, "C") || !strcmp(name, "POSIX")) {
		r.value = (char *)"C";
		return r;
	}
	/* setlocale(LC_ALL, "C;C;C;...") style composite names */
	if (cat == LC_ALL && !strncmp(name, "C;", 2)) r.value = (char *)"C";
	return r;
}

char *setlocale(int cat, const char *name)
{
	struct setlocale_result r = setlocale_compute(cat, name);
	if (r.bad_cat) errno = EINVAL;
	return r.value;
}

static struct lconv __posix_lconv = { // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision
	.decimal_point = (char *)".",
	.thousands_sep = (char *)"",
	.grouping = (char *)"",
	.int_curr_symbol = (char *)"",
	.currency_symbol = (char *)"",
	.mon_decimal_point = (char *)"",
	.mon_thousands_sep = (char *)"",
	.mon_grouping = (char *)"",
	.positive_sign = (char *)"",
	.negative_sign = (char *)"",
	/* "not available", per the pages for each of these members: they
	 * are `char`, and CHAR_MAX -- not the literal 127 -- is the value
	 * that means that, because CHAR_MAX itself is what's implementation
	 * -defined (limits.h): 127 on a signed-char target, 255 where plain
	 * char is unsigned (this project's aarch64 target). */
	.int_frac_digits = CHAR_MAX,
	.frac_digits = CHAR_MAX,
	.p_cs_precedes = CHAR_MAX,
	.p_sep_by_space = CHAR_MAX,
	.n_cs_precedes = CHAR_MAX,
	.n_sep_by_space = CHAR_MAX,
	.p_sign_posn = CHAR_MAX,
	.n_sign_posn = CHAR_MAX,
	.int_p_cs_precedes = CHAR_MAX,
	.int_p_sep_by_space = CHAR_MAX,
	.int_n_cs_precedes = CHAR_MAX,
	.int_n_sep_by_space = CHAR_MAX,
	.int_p_sign_posn = CHAR_MAX,
	.int_n_sign_posn = CHAR_MAX,
};

struct lconv *localeconv(void)
{
	return &__posix_lconv;
}

/* &__c_locale is a fixed address (one static object, never moved), so
 * returning it is a constant pointer value, not a read of mutable
 * state -- the same reasoning as strerror()'s pointer into its own
 * fixed message table (string.h). */
struct newlocale_result { locale_t value; int err; };

static struct newlocale_result newlocale_compute(int mask, const char *name) __attribute__((__pure__));
static struct newlocale_result newlocale_compute(int mask, const char *name)
{
	struct newlocale_result r = { 0, 0 };
	/* newlocale.html ERRORS, *shall fail* (not "may fail"):
	 *   "[EINVAL] The category_mask contains a bit that does not
	 *    correspond to a valid category."
	 * DESCRIPTION defines the valid bits as "a bitwise-inclusive OR of
	 * the symbolic constants LC_CTYPE_MASK, ... LC_MESSAGES_MASK, or any
	 * of the implementation-defined mask values defined in <locale.h>".
	 *
	 * <locale.h> defines those six AND LC_ALL_MASK, which is 0x7fffffff
	 * -- so under that wording every bit 0..30 belongs to a mask value
	 * this implementation defines, and only bit 31 (the sign bit) can be
	 * rejected without also rejecting LC_ALL_MASK itself.  Hence the test
	 * is against ~LC_ALL_MASK rather than against the OR of the six.
	 *
	 * Being C-locale-only is not an excuse for skipping this: validating
	 * a bitmask needs no locale data at all, and *shall fail* makes it
	 * part of the contract a caller relies on to detect its own bad
	 * argument. */
	if (mask & ~LC_ALL_MASK) { r.err = EINVAL; return r; }
	if (name && *name && strcmp(name, "C") && strcmp(name, "POSIX")) { // NOLINT(bugprone-suspicious-string-compare) -- nonzero from both calls intentionally means neither locale name matches
		r.err = ENOENT;
		return r;
	}
	r.value = &__c_locale;
	return r;
}

withtok(locale_opened)
locale_t newlocale(int mask, const char *name, locale_t base)
{
	(void)base;
	struct newlocale_result r = newlocale_compute(mask, name);
	if (r.err) errno = r.err;
	return r.value;
}

/* Correctly a no-op: every locale_t in this implementation names the one
 * immutable static object below, never a real allocation (see
 * include/locale.h's tokdef comment for why consume(locale_opened) is
 * still sound here). */
void freelocale(locale_t l consume(locale_opened))
{
	(void)l;
}

withtok(locale_opened)
locale_t duplocale(locale_t l)
{
	(void)l;
	return &__c_locale;
}

/* uselocale.html RETURN VALUE, verbatim: "Upon successful completion,
 * the uselocale() function shall return a handle for the thread-local
 * locale that was in use as the current locale for the calling thread on
 * entry to the function, or LC_GLOBAL_LOCALE if no thread-local locale
 * was in use."
 *
 * This used to be `{ (void)l; return &__c_locale; }`, which stored
 * nothing -- so "no thread-local locale was in use" was true on entry to
 * every call ever made, LC_GLOBAL_LOCALE was the required answer every
 * time, and the function returned a locale handle instead.
 *
 * That matters more than an unused constant being wrong, which is why it
 * is a defect and freelocale()'s no-op is not.  `uselocale(0) ==
 * LC_GLOBAL_LOCALE` is THE documented way for a program to ask whether it
 * is on the global locale, and the old code answered "no" when the truth
 * was always "yes".  The standard save/restore idiom
 *
 *     locale_t old = uselocale(my_locale);  ... ;  uselocale(old);
 *
 * could therefore not distinguish "I was on the global locale, put me
 * back on it" from "I was on some locale object, put me back on that":
 * it silently did the wrong one rather than failing.
 *
 * Note the fix is NOT "return LC_GLOBAL_LOCALE unconditionally".  Once
 * uselocale(loc) has been called a thread-local locale IS in use, and a
 * subsequent query must report it -- which
 * test_uselocale_install_and_uninstall() asserts.  One word of state
 * satisfies both that and the "nothing installed yet" case.
 *
 * The state is a plain static rather than thread-local because this
 * library has no threads to make it local to; if that changes, this is
 * the declaration that has to change with it. */
static locale_t current_locale = LC_GLOBAL_LOCALE;

locale_t uselocale(locale_t l)
{
	locale_t prev = current_locale;
	/* "If the newloc argument is (locale_t)0, the current locale shall
	 * not be changed" -- a pure query. */
	if (l) current_locale = l;
	return prev;
}

// NOLINTEND(misc-include-cleaner)
