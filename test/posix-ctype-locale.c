/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Coverage fences for the `_l` locale-argument variants of <ctype.h>
 * and <wctype.h>.  POSIX.1-2017 (IEEE Std 1003.1-2017, The Open Group
 * Base Specifications Issue 7, 2018 Edition), served at
 * https://pubs.opengroup.org/onlinepubs/9699919799/ ; clause text read
 * from Ubuntu's manpages-posix-dev 2017a-2, which reprints that
 * edition verbatim (pubs.opengroup.org is unreachable from here).
 *
 * ==================== the gap, and why it is a real one ==============
 *
 * The same name-level cross-index behind test/posix-pthread.c finds 30
 * `_l` names with no mention anywhere in the test/ tree:
 *
 *   <ctype.h>   isalnum_l is not in the list -- see below --
 *               isalpha_l isblank_l iscntrl_l isdigit_l isgraph_l
 *               islower_l isprint_l ispunct_l isspace_l isupper_l
 *               isxdigit_l tolower_l toupper_l
 *   <wctype.h>  iswalpha_l iswblank_l iswcntrl_l iswctype_l iswdigit_l
 *               iswgraph_l iswlower_l iswprint_l iswpunct_l iswspace_l
 *               iswupper_l iswxdigit_l towctrans_l towlower_l
 *               towupper_l wctrans_l wctype_l
 *
 * This is NOT the "spicule is C-locale-only, so a locale argument has
 * nothing to select" case, and that distinction is the whole finding.
 * The per-locale API is present and implemented here: include/locale.h
 * declares newlocale/duplocale/freelocale/uselocale and defines
 * LC_GLOBAL_LOCALE and the LC_*_MASK set, and test/posix-locale.c
 * already audits all four clause by clause.  test/posix-strings.c:99
 * exercises strcasecmp_l() and strncasecmp_l(), which take exactly the
 * locale_t these functions take.  So the type exists, the objects that
 * inhabit it exist, and two `_l` functions over that type already work.
 * What is missing is the <ctype.h>/<wctype.h> half of the same family:
 * `grep '_l(' include/ctype.h include/wctype.h` returns nothing.
 *
 * That makes these mandatory-and-cheap rather than optional: the
 * pages are marked CX (POSIX extensions to the ISO C standard) and are
 * base in this edition, and in a C-locale-only implementation each one
 * is its non-_l sibling with an ignored argument -- exactly what
 * src/misc/locale.c already does for strcasecmp_l.
 *
 * ==================== what a caller observes today ===================
 *
 * <ctype.h> and <wctype.h> both exist and include cleanly, so unlike
 * the absent-header fences elsewhere in this tree these do not stop at
 * the preprocessor: they get an implicit declaration (a warning under
 * this tcc, not an error) and then die at link with "unresolved
 * reference to 'isalpha_l'".  Failing to produce the probe binary is
 * what tools/test-policy.py measures, so that is UNIMPL -- an absent
 * interface -- and not BUG, which would assert a present interface
 * giving a wrong answer.  --pedantic decides it, not this comment.
 *
 * ==================== isalnum_l/iswalnum_l, added later ==============
 *
 * isalnum_l and iswalnum_l did not appear in the gap list above because
 * those two identifiers already occurred in the test/ tree -- at
 * test/posix-headers.c:173, in prose, not in an assertion.  The index
 * over-reports coverage by construction (it is a name match, not a
 * call-site audit), and that gap was real: tools/lint-unreferenced.sh's
 * undefined-symbol scan (which does check call sites) found both
 * functions genuinely unreferenced by any test.  Real assertions for
 * both now live inline in posix_ctype_locale_isalpha_l_family() and
 * posix_ctype_locale_iswalpha_l_family() below, next to their isalpha_l/
 * iswalpha_l siblings, rather than in a family of their own -- there is
 * nothing about isalnum_l()/iswalnum_l() that needs a separate fence.
 *
 * The RELATED gap that is already fenced, and must not be confused with
 * this one: test/posix-headers.c's `ctype_h_defines_locale_t` island
 * fences the fact that <ctype.h> and <wctype.h> are the two headers on
 * the locale_t mandate list that do not request the type (they omit
 * __NEED_locale_t), so a translation unit including either alone cannot
 * name the argument these functions take.  That fence's own comment
 * says it "claims nothing about those functions"; this file is the
 * other half.  The two are ordered, not duplicates -- nothing here can
 * be DECLARED until that one is fixed.
 *
 * One stale premise, recorded rather than repeated: that comment
 * attributes the gap to "test/POSIX-GAP-ACCOUNTING.md", which c2cac99
 * deleted.  The gap is real; the citation no longer resolves.
 */

#include <stdio.h>

#include "test-policy.h"

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; \
	printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* ==================================================================
 * <ctype.h> classification, per locale --
 * .../functions/isalpha.html and the sibling isXXX pages
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_ctype_locale_isalpha_l_family)
#include <ctype.h>
#include <locale.h>

static void test_posix_ctype_locale_isalpha_l_family(void)
{
	locale_t loc = newlocale(LC_ALL_MASK, "C", (locale_t)0);

	CHECK(loc != (locale_t)0);
	if (loc == (locale_t)0)
		return;

	/* isalpha.html: "The isalpha() and isalpha_l() functions shall
	 * test whether c is a character of class alpha in the current
	 * locale, or in the locale represented by locale, respectively."
	 * In the POSIX locale the class memberships are fixed by XBD 7.3.1
	 * ("LC_CTYPE"), so each of these is decidable, not a preference.
	 * The uniform requirement across the family -- "shall return
	 * non-zero if c is [in the class]; otherwise, it shall return 0"
	 * -- is what the != 0 / == 0 pattern below asserts. */
	CHECK(isalpha_l('a', loc) != 0);
	CHECK(isalpha_l('Z', loc) != 0);
	CHECK(isalpha_l('0', loc) == 0);
	CHECK(isalpha_l(' ', loc) == 0);

	/* isalnum.html: "test whether c is a character of class alpha or
	 * digit in the current locale, or in the locale represented by
	 * locale, respectively." -- alpha OR digit, nothing else. */
	CHECK(isalnum_l('a', loc) != 0);
	CHECK(isalnum_l('Z', loc) != 0);
	CHECK(isalnum_l('7', loc) != 0);
	CHECK(isalnum_l(' ', loc) == 0);
	CHECK(isalnum_l('!', loc) == 0);

	CHECK(isdigit_l('7', loc) != 0);
	CHECK(isdigit_l('a', loc) == 0);

	CHECK(isxdigit_l('f', loc) != 0);
	CHECK(isxdigit_l('F', loc) != 0);
	CHECK(isxdigit_l('g', loc) == 0);

	CHECK(islower_l('a', loc) != 0);
	CHECK(islower_l('A', loc) == 0);
	CHECK(isupper_l('A', loc) != 0);
	CHECK(isupper_l('a', loc) == 0);

	CHECK(isspace_l(' ', loc) != 0);
	CHECK(isspace_l('\t', loc) != 0);
	CHECK(isspace_l('\n', loc) != 0);
	CHECK(isspace_l('a', loc) == 0);

	/* isblank.html: in the POSIX locale the blank class is exactly
	 * <space> and <tab>. */
	CHECK(isblank_l(' ', loc) != 0);
	CHECK(isblank_l('\t', loc) != 0);
	CHECK(isblank_l('\n', loc) == 0);

	CHECK(iscntrl_l('\n', loc) != 0);
	CHECK(iscntrl_l('a', loc) == 0);

	/* isprint.html: "any printing character, including <space>";
	 * isgraph.html: "any printing character, except <space>". */
	CHECK(isprint_l(' ', loc) != 0);
	CHECK(isgraph_l(' ', loc) == 0);
	CHECK(isprint_l('a', loc) != 0);
	CHECK(isgraph_l('a', loc) != 0);
	CHECK(isprint_l('\n', loc) == 0);

	CHECK(ispunct_l('!', loc) != 0);
	CHECK(ispunct_l('a', loc) == 0);
	CHECK(ispunct_l(' ', loc) == 0);

	/* The `_l` answer must agree with the current-locale answer while
	 * the current locale is the same one: that agreement is what makes
	 * the locale argument meaningful rather than decorative. */
	CHECK((isalpha_l('a', loc) != 0) == (isalpha('a') != 0));
	CHECK((ispunct_l('!', loc) != 0) == (ispunct('!') != 0));
	CHECK((isalnum_l('a', loc) != 0) == (isalnum('a') != 0));

	freelocale(loc);
}
#endif

#if SPICULE_TEST(PASS, posix_ctype_locale_tolower_l)
#include <ctype.h>
#include <locale.h>

static void test_posix_ctype_locale_tolower_l(void)
{
	locale_t loc = newlocale(LC_ALL_MASK, "POSIX", (locale_t)0);

	CHECK(loc != (locale_t)0);
	if (loc == (locale_t)0)
		return;

	/* tolower.html: "If the argument of tolower() or tolower_l()
	 * represents an uppercase letter, and there exists a
	 * corresponding lowercase letter as defined by character type
	 * information in the current locale or in the locale represented
	 * by locale, respectively ... the result shall be the
	 * corresponding lowercase letter.  All other arguments in the
	 * domain are returned unchanged." */
	CHECK(tolower_l('A', loc) == 'a');
	CHECK(tolower_l('Z', loc) == 'z');
	CHECK(tolower_l('a', loc) == 'a');
	CHECK(tolower_l('0', loc) == '0');
	CHECK(tolower_l('!', loc) == '!');

	/* toupper.html, the mirror clause. */
	CHECK(toupper_l('a', loc) == 'A');
	CHECK(toupper_l('z', loc) == 'Z');
	CHECK(toupper_l('A', loc) == 'A');
	CHECK(toupper_l('9', loc) == '9');

	/* "have as a domain a type int, the value of which is
	 * representable as an unsigned char or the value of EOF" -- EOF is
	 * in the domain and must come back unchanged. */
	CHECK(tolower_l(EOF, loc) == EOF);
	CHECK(toupper_l(EOF, loc) == EOF);

	/* Round-trip agreement with the current-locale form. */
	CHECK(tolower_l('Q', loc) == tolower('Q'));
	CHECK(toupper_l('q', loc) == toupper('q'));

	freelocale(loc);
}
#endif

/* ==================================================================
 * <wctype.h> classification and mapping, per locale --
 * .../functions/iswalpha.html, towlower.html, wctype.html,
 * iswctype.html, wctrans.html, towctrans.html
 * ================================================================== */

#if SPICULE_TEST(PASS, posix_ctype_locale_iswalpha_l_family)
#include <wctype.h>
#include <locale.h>

static void test_posix_ctype_locale_iswalpha_l_family(void)
{
	locale_t loc = newlocale(LC_ALL_MASK, "C", (locale_t)0);

	CHECK(loc != (locale_t)0);
	if (loc == (locale_t)0)
		return;

	/* iswalpha.html: "The iswalpha() and iswalpha_l() functions shall
	 * test whether wc is a wide-character code representing a
	 * character of class alpha in the current locale, or in the locale
	 * represented by locale, respectively."  Same POSIX-locale class
	 * memberships as the byte functions, over wide-character codes. */
	CHECK(iswalpha_l(L'a', loc) != 0);
	CHECK(iswalpha_l(L'0', loc) == 0);

	/* iswalnum.html: alpha OR digit, mirroring isalnum_l() above one
	 * character width up. */
	CHECK(iswalnum_l(L'a', loc) != 0);
	CHECK(iswalnum_l(L'7', loc) != 0);
	CHECK(iswalnum_l(L' ', loc) == 0);
	CHECK(iswalnum_l(L'!', loc) == 0);

	CHECK(iswdigit_l(L'7', loc) != 0);
	CHECK(iswdigit_l(L'a', loc) == 0);
	CHECK(iswxdigit_l(L'F', loc) != 0);
	CHECK(iswxdigit_l(L'g', loc) == 0);
	CHECK(iswlower_l(L'a', loc) != 0);
	CHECK(iswupper_l(L'A', loc) != 0);
	CHECK(iswspace_l(L' ', loc) != 0);
	CHECK(iswspace_l(L'a', loc) == 0);
	CHECK(iswblank_l(L'\t', loc) != 0);
	CHECK(iswblank_l(L'\n', loc) == 0);
	CHECK(iswcntrl_l(L'\n', loc) != 0);
	CHECK(iswcntrl_l(L'a', loc) == 0);
	CHECK(iswprint_l(L' ', loc) != 0);
	CHECK(iswgraph_l(L' ', loc) == 0);
	CHECK(iswpunct_l(L'!', loc) != 0);
	CHECK(iswpunct_l(L'a', loc) == 0);

	/* Every one of these pages carries the same WEOF clause: the
	 * argument's domain is "a wide-character code corresponding to a
	 * valid character in the locale used by the function, or the value
	 * of WEOF", and WEOF is in no class. */
	CHECK(iswalpha_l(WEOF, loc) == 0);
	CHECK(iswalnum_l(WEOF, loc) == 0);
	CHECK(iswdigit_l(WEOF, loc) == 0);
	CHECK(iswspace_l(WEOF, loc) == 0);

	freelocale(loc);
}
#endif

#if SPICULE_TEST(PASS, posix_ctype_locale_towlower_l)
#include <wctype.h>
#include <locale.h>

static void test_posix_ctype_locale_towlower_l(void)
{
	locale_t loc = newlocale(LC_ALL_MASK, "C", (locale_t)0);

	CHECK(loc != (locale_t)0);
	if (loc == (locale_t)0)
		return;

	/* towlower.html: "If the argument of towlower() or towlower_l()
	 * represents an uppercase wide-character code ... the result shall
	 * be the corresponding lowercase wide-character code.  All other
	 * arguments in the domain are returned unchanged." */
	CHECK(towlower_l(L'A', loc) == L'a');
	CHECK(towlower_l(L'a', loc) == L'a');
	CHECK(towlower_l(L'0', loc) == L'0');
	CHECK(towupper_l(L'a', loc) == L'A');
	CHECK(towupper_l(L'A', loc) == L'A');
	CHECK(towupper_l(L'!', loc) == L'!');

	/* "or the value of WEOF" is in the domain, and unchanged. */
	CHECK(towlower_l(WEOF, loc) == WEOF);
	CHECK(towupper_l(WEOF, loc) == WEOF);

	freelocale(loc);
}
#endif

#if SPICULE_TEST(PASS, posix_ctype_locale_wctype_l_iswctype_l)
#include <wctype.h>
#include <locale.h>

static void test_posix_ctype_locale_wctype_l_iswctype_l(void)
{
	locale_t loc = newlocale(LC_ALL_MASK, "C", (locale_t)0);
	wctype_t alpha, digit, bogus;

	CHECK(loc != (locale_t)0);
	if (loc == (locale_t)0)
		return;

	/* wctype.html: "The following character class names shall be
	 * defined in all locales: alnum alpha blank cntrl digit graph
	 * lower print punct space upper xdigit."  RETURN VALUE: "Upon
	 * successful completion ... shall return a value of type wctype_t
	 * that can be used in calls to iswctype() and iswctype_l() ...
	 * Otherwise, they shall return (wctype_t)0." */
	alpha = wctype_l("alpha", loc);
	digit = wctype_l("digit", loc);
	CHECK(alpha != (wctype_t)0);
	CHECK(digit != (wctype_t)0);

	bogus = wctype_l("no-such-class", loc);
	CHECK(bogus == (wctype_t)0);

	/* iswctype.html: "The iswctype() and iswctype_l() functions shall
	 * determine whether the wide-character code wc has the character
	 * class charclass, returning true or false ... shall return
	 * non-zero (true) if and only if wc has the property described by
	 * charclass." */
	CHECK(iswctype_l(L'a', alpha, loc) != 0);
	CHECK(iswctype_l(L'0', alpha, loc) == 0);
	CHECK(iswctype_l(L'0', digit, loc) != 0);
	CHECK(iswctype_l(L'a', digit, loc) == 0);

	/* The class handle must agree with the dedicated predicate for
	 * the same locale -- otherwise one of the two is wrong. */
	CHECK((iswctype_l(L'a', alpha, loc) != 0)
	      == (iswalpha_l(L'a', loc) != 0));

	freelocale(loc);
}
#endif

#if SPICULE_TEST(PASS, posix_ctype_locale_wctrans_l_towctrans_l)
#include <wctype.h>
#include <locale.h>

static void test_posix_ctype_locale_wctrans_l_towctrans_l(void)
{
	locale_t loc = newlocale(LC_ALL_MASK, "C", (locale_t)0);
	wctrans_t down, up, bogus;

	CHECK(loc != (locale_t)0);
	if (loc == (locale_t)0)
		return;

	/* wctrans.html: "The following character mapping names are defined
	 * in all locales: tolower and toupper."  RETURN VALUE: "shall
	 * return a value of type wctrans_t that can be used ... in calls
	 * to towctrans() and towctrans_l().  Otherwise, they shall return
	 * (wctrans_t)0". */
	down = wctrans_l("tolower", loc);
	up = wctrans_l("toupper", loc);
	CHECK(down != (wctrans_t)0);
	CHECK(up != (wctrans_t)0);

	bogus = wctrans_l("no-such-mapping", loc);
	CHECK(bogus == (wctrans_t)0);

	/* towctrans.html: "shall transliterate the wide-character code wc
	 * using the mapping described by desc" -- and the two named
	 * mappings must be the ones towlower_l()/towupper_l() perform. */
	CHECK(towctrans_l(L'A', down, loc) == L'a');
	CHECK(towctrans_l(L'a', down, loc) == L'a');
	CHECK(towctrans_l(L'a', up, loc) == L'A');
	CHECK(towctrans_l(L'A', up, loc) == L'A');
	CHECK(towctrans_l(L'A', down, loc) == towlower_l(L'A', loc));
	CHECK(towctrans_l(L'a', up, loc) == towupper_l(L'a', loc));

	/* "If the value of desc is zero, towctrans() and towctrans_l()
	 * shall return the value of wc." */
	CHECK(towctrans_l(L'A', (wctrans_t)0, loc) == L'A');

	freelocale(loc);
}
#endif

int main(void)
{
	/* Every case here is still fenced out of the normal build (see
	 * test-policy.h: SPICULE_TEST() is 0 outside tools/test-policy.py's
	 * per-case probe), but `grep '_l(' include/ctype.h include/wctype.h`
	 * no longer returns nothing: include/ctype.h and include/wctype.h
	 * now declare the whole isalnum_l() ... wctrans_l() family (see
	 * their own banners), each one forwarding to its non-_l sibling
	 * (the src/ctype/ sources). tools/test-policy.py --pedantic re-decides each
	 * case independently; that is what turned every fence above from
	 * UNIMPL to PASS. */
	if (!fails) printf("posix-ctype-locale: all tests passed\n");
	return fails != 0;
}
