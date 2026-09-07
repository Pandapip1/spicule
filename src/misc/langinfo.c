/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * nl_langinfo(), nl_langinfo_l() -- nl_langinfo.html.
 *
 * DESCRIPTION: "The nl_langinfo() and nl_langinfo_l() functions shall
 * return a pointer to a string containing information relevant to the
 * particular language or cultural area defined in the current locale, or
 * in the locale represented by locale, respectively (see
 * <langinfo.h>)."
 *
 * RETURN VALUE: "In a locale where langinfo data is not defined, these
 * functions shall return a pointer to the corresponding string in the
 * POSIX locale. In all locales, these functions shall return a pointer
 * to an empty string if item contains an invalid setting."  And: "The
 * application shall not modify the string returned."
 *
 * ERRORS: "No errors are defined."  Nothing here sets errno.
 *
 * spicule has exactly one locale, "C" (src/misc/locale.c), so the first
 * of those two sentences is the whole of the locale story: every item
 * answers with its POSIX-locale string and there is no second answer to
 * choose between.  That is why nl_langinfo_l() ignores its locale_t
 * rather than dispatching on it -- not because the argument is
 * unimplemented, but because every handle newlocale()/duplocale() can
 * hand out here denotes the same immutable C locale, so dispatching
 * could not produce a different string.  If a second locale is ever
 * added, this is the function that has to grow a table per locale.
 *
 * "The behavior is undefined if the locale argument to nl_langinfo_l()
 * is the special locale object LC_GLOBAL_LOCALE or is not a valid locale
 * object handle."  Undefined is not "diagnosed": this deliberately does
 * NOT validate the handle, because a caller must not come to rely on a
 * check the standard does not require and a future implementation might
 * not be able to make.  It also never dereferences it, so a bad handle
 * is inert rather than fatal here.
 *
 * "The nl_langinfo() function need not be thread-safe" -- and by
 * RATIONALE nl_langinfo_l() must be.  Every string returned below is a
 * string literal or a pointer into a const table or into localeconv()'s
 * static struct; nothing is copied into a shared buffer, so both forms
 * are re-entrant here and the distinction never arises.
 *
 * Where each POSIX-locale value comes from, since agreement with the
 * rest of the library is the property that matters:
 *
 *  - The day and month names are src/time/names.c's four const arrays,
 *    the same objects strftime()'s %A/%a/%B/%b print, so %A and
 *    nl_langinfo(DAY_1+wday) cannot disagree.
 *  - D_T_FMT/D_FMT/T_FMT/T_FMT_AMPM/AM_STR/PM_STR are the format
 *    strings src/time/strftime.c open-codes for %c/%x/%X/%r/%p,
 *    transcribed here as the format that reproduces that output.  They
 *    are strftime.html's C-locale list.
 *  - RADIXCHAR and THOUSEP are localeconv()'s decimal_point and
 *    thousands_sep, read live rather than duplicated.
 *  - CODESET is "UTF-8", the only encoding this library has
 *    (src/internal/utf.c).  The name is implementation-defined.
 *  - CRNCYSTR is "" because the local currency symbol is the empty
 *    string, which langinfo.h.html permits explicitly: "If the local
 *    currency symbol is the empty string, implementations may return
 *    the empty string ("")."
 *  - The five era and alternative-digit items are "" because the POSIX
 *    locale defines no era and no alternative digits.
 *  - YESEXPR and NOEXPR are "^[yY]" and "^[nN]": extended regular
 *    expressions <regex.h> here compiles and matches.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <langinfo.h>
#include <locale.h>

/* src/time/names.c.  Declared here rather than by including
 * src/time/time_impl.h: no .c file in this tree reaches across a src/
 * subdirectory for a header, and these four declarators are stable
 * enough that repeating them is cheaper than starting that habit.  A
 * divergence would be a link-time type error under any checker, and the
 * live cross-check in test/posix-msgcat.c compares every one of these
 * strings against what strftime() prints. */
extern const char *const __spicule_day_name[7]; // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision
extern const char *const __spicule_day_name_abbr[7]; // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision
extern const char *const __spicule_month_name[12]; // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision
extern const char *const __spicule_month_name_abbr[12]; // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision

char *nl_langinfo(nl_item item)
{
	switch (item) {
	case CODESET:      return (char *)"UTF-8";

	case D_T_FMT:      return (char *)"%a %b %e %H:%M:%S %Y";
	case D_FMT:        return (char *)"%m/%d/%y";
	case T_FMT:        return (char *)"%H:%M:%S";
	case T_FMT_AMPM:   return (char *)"%I:%M:%S %p";
	case AM_STR:       return (char *)"AM";
	case PM_STR:       return (char *)"PM";

	case ERA:
	case ERA_D_FMT:
	case ERA_D_T_FMT:
	case ERA_T_FMT:
	case ALT_DIGITS:   return (char *)"";

	case RADIXCHAR:    return localeconv()->decimal_point;
	case THOUSEP:      return localeconv()->thousands_sep;

	case YESEXPR:      return (char *)"^[yY]";
	case NOEXPR:       return (char *)"^[nN]";

	case CRNCYSTR:     return (char *)"";
	default: break;
	}

	if (item >= DAY_1 && item <= DAY_7)
		return (char *)__spicule_day_name[item - DAY_1];
	if (item >= ABDAY_1 && item <= ABDAY_7)
		return (char *)__spicule_day_name_abbr[item - ABDAY_1];
	if (item >= MON_1 && item <= MON_12)
		return (char *)__spicule_month_name[item - MON_1];
	if (item >= ABMON_1 && item <= ABMON_12)
		return (char *)__spicule_month_name_abbr[item - ABMON_1];

	/* "these functions shall return a pointer to an empty string if
	 * item contains an invalid setting" -- an empty string, never a
	 * null pointer, and never errno. */
	return (char *)"";
}

char *nl_langinfo_l(nl_item item, locale_t locale)
{
	(void)locale;
	return nl_langinfo(item);
}

// NOLINTEND(misc-include-cleaner)
