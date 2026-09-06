/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of the sixteen <wctype.h>
 * functions test/POSIX-GAP-ACCOUNTING.md lists as implemented but never
 * clause-audited:
 *
 *   iswalnum iswalpha iswblank iswcntrl iswctype iswdigit iswgraph
 *   iswlower iswprint iswpunct iswspace iswupper iswxdigit
 *   towctrans towlower towupper
 *
 * test/posix-wchar.c already calls fourteen of these (it gained a short
 * <wctype.h> block when that header landed, 2026-08-23), but that block
 * is a smoke test: a dozen single-character spot checks plus WEOF and a
 * lone surrogate.  It is not a clause audit, and it does not touch the
 * one relation these sixteen pages actually specify against each other
 * -- iswctype.html's APPLICATION USAGE equivalence table.  This file
 * does the pages.  Nothing in test/posix-wchar.c is moved or removed;
 * the two files overlap the way a smoke test and an audit are supposed
 * to.
 *
 * Spec pages consulted (https://pubs.opengroup.org/onlinepubs/9699919799/):
 *   functions/iswalnum.html   functions/iswalpha.html
 *   functions/iswblank.html   functions/iswcntrl.html
 *   functions/iswctype.html   functions/iswdigit.html
 *   functions/iswgraph.html   functions/iswlower.html
 *   functions/iswprint.html   functions/iswpunct.html
 *   functions/iswspace.html   functions/iswupper.html
 *   functions/iswxdigit.html  functions/towctrans.html
 *   functions/towlower.html   functions/towupper.html
 *   functions/wctype.html     functions/wctrans.html
 *   basedefs/wctype.h.html    basedefs/V1_chap07.html#tag_07_03_01
 *
 * ==================== what the domain actually is =====================
 *
 * All thirteen isw* pages carry the same domain sentence: "The wc
 * argument is a wint_t, the value of which the application shall ensure
 * is a wide-character code corresponding to a valid character in the
 * locale used by the function, or equal to the value of the macro WEOF.
 * If the argument has any other value, the behavior is undefined."
 * towlower.html/towupper.html say the same with "representable as a
 * wchar_t" added.
 *
 * The locale used by the function is always the POSIX locale here
 * (src/misc/locale.c's setlocale() accepts no other name), and XBD
 * 7.3.1 LC_CTYPE defines that locale's character set as the portable
 * character set.  So the *defined* domain of every function below is
 * exactly U+0000..U+007F plus WEOF -- 129 values -- and that is what
 * test_domain_*() sweeps.  Every wint_t outside it, including all of
 * 0x80-0xffff and every value above WCHAR_MAX, is undefined by the
 * spec and nothing here may assert a required answer for one.
 *
 * include/wctype.h's own banner nevertheless *commits* to an answer for
 * the whole undefined region (0 from every classification function, the
 * argument unchanged from every conversion function, no special-casing
 * of surrogate halves).  That commitment is asserted below too, in
 * test_documented_extension(), clearly separated and labelled: it is
 * ntlibc's promise to its callers, not POSIX's requirement, and if it
 * ever changes this file should record the change rather than pretend
 * the spec forbade it.
 *
 * ==================== the equivalence table ===========================
 *
 * iswctype.html's APPLICATION USAGE states twelve equivalences --
 * `iswalnum(wc)` is `iswctype(wc, wctype("alnum"))`, and so on for all
 * twelve standard class names.  That is the one cross-function
 * requirement in this header, and it is the one with a real failure
 * mode here: src/ctype/wctype.c hands out a 1-based index into a
 * twelve-entry `classes[]` array and src/ctype/iswctype.c consumes it
 * with a hand-written twelve-case switch.  Two lists, kept in step by
 * nothing but sitting near each other.  Transposing any two entries in
 * either would leave both files compiling, every existing test in
 * test/posix-wchar.c passing (its only iswctype() checks use "digit"),
 * and iswctype(wc, wctype("alpha")) quietly answering iswblank().
 * test_iswctype_equivalence_table() asserts all twelve equivalences
 * across the whole defined domain.
 */
#include <wctype.h>
#include <wchar.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* XBD 7.3.1 LC_CTYPE, POSIX locale: class membership by enumeration,
 * over the portable character set only.  Same oracles as
 * test/posix-ctype.c's, and deliberately so -- these are the *spec's*
 * class definitions, not a restatement of either implementation, and
 * the isw* family is required to classify identically to the is*
 * family in a locale whose character set is the portable one. */
#define UPPER "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define LOWER "abcdefghijklmnopqrstuvwxyz"
#define DIGIT "0123456789"
#define PUNCT "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
#define ALPHA UPPER LOWER
#define ALNUM ALPHA DIGIT
#define GRAPH ALNUM PUNCT
#define PRINT GRAPH " "
#define SPACE " \t\n\v\f\r"
#define BLANK " \t"
#define XDIGIT DIGIT "ABCDEF" "abcdef"

static int in_set(const char *members, wint_t wc)
{
	const char *p;
	if (wc > 0x7f) return 0;
	for (p = members; *p; p++)
		if ((wint_t)(unsigned char)*p == wc) return 1;
	return 0;
}

/* cntrl needs a numeric oracle: it contains U+0000, which no C string
 * literal can carry.  XBD 7.3.1, POSIX locale: 0x00-0x1f and 0x7f. */
static int cntrl_oracle(wint_t wc) { return wc <= 0x1f || wc == 0x7f; }

/* One class's oracle, selected by the same name POSIX gives it.  Used
 * both by the per-function sweeps and by the equivalence table, so the
 * two cannot drift apart. */
static int class_oracle(const char *name, wint_t wc)
{
	if (!strcmp(name, "alnum"))  return in_set(ALNUM, wc);
	if (!strcmp(name, "alpha"))  return in_set(ALPHA, wc);
	if (!strcmp(name, "blank"))  return in_set(BLANK, wc);
	if (!strcmp(name, "cntrl"))  return wc <= 0x7f && cntrl_oracle(wc);
	if (!strcmp(name, "digit"))  return in_set(DIGIT, wc);
	if (!strcmp(name, "graph"))  return in_set(GRAPH, wc);
	if (!strcmp(name, "lower"))  return in_set(LOWER, wc);
	if (!strcmp(name, "print"))  return in_set(PRINT, wc);
	if (!strcmp(name, "punct"))  return in_set(PUNCT, wc);
	if (!strcmp(name, "space"))  return in_set(SPACE, wc);
	if (!strcmp(name, "upper"))  return in_set(UPPER, wc);
	if (!strcmp(name, "xdigit")) return in_set(XDIGIT, wc);
	fails++; printf("FAIL %s:%d: unknown class %s\n", __FILE__, __LINE__, name);
	return 0;
}

/* Sweep one classification function over the whole defined domain --
 * U+0000..U+007F plus WEOF -- against the enumerated oracle.
 * iswalnum.html et al. RETURN VALUE: "shall return non-zero if wc is
 * ...; otherwise, they shall return 0", so the true side is tested as
 * `!!f(wc)`, never `f(wc) == 1`. */
static void sweep(const char *fname, int (*f)(wint_t), const char *cls)
{
	wint_t wc;
	/* the domain sentence names WEOF explicitly; it is not a character,
	 * so it is in no class */
	if (!!f(WEOF) != 0) { fails++; printf("FAIL %s:%d: %s(WEOF) must be 0\n", __FILE__, __LINE__, fname); }
	for (wc = 0; wc <= 0x7f; wc++) {
		int want = class_oracle(cls, wc);
		if (!!f(wc) != want) {
			fails++;
			printf("FAIL %s:%d: %s(U+%04X) returned %d, want %s\n",
			    __FILE__, __LINE__, fname, (unsigned)wc, f(wc), want ? "non-zero" : "0");
		}
	}
}

/* --------------------------------------------------------------------
 * The thirteen isw* classification pages.  Each has the identical three
 * clauses -- DESCRIPTION class membership "in the current locale",
 * DESCRIPTION domain, RETURN VALUE non-zero/0 -- and ERRORS: "No errors
 * are defined."  sweep() asserts the first three; test_no_errors_
 * defined() asserts the fourth for all thirteen at once.
 * ------------------------------------------------------------------ */
static void test_iswalpha(void)   { sweep("iswalpha", iswalpha, "alpha");
	CHECK(iswalpha(L'A') != 0); CHECK(iswalpha(L'z') != 0); CHECK(iswalpha(L'0') == 0); }
static void test_iswupper(void)   { sweep("iswupper", iswupper, "upper");
	CHECK(iswupper(L'A') != 0); CHECK(iswupper(L'a') == 0); }
static void test_iswlower(void)   { sweep("iswlower", iswlower, "lower");
	CHECK(iswlower(L'a') != 0); CHECK(iswlower(L'A') == 0); }
static void test_iswdigit(void)   { sweep("iswdigit", iswdigit, "digit");
	/* iswdigit.html: XBD 7.3.1 fixes class digit as exactly 0-9 in
	 * every locale; the adjacent code points are the interesting ones */
	CHECK(iswdigit(L'0') != 0); CHECK(iswdigit(L'9') != 0);
	CHECK(iswdigit(0x2f) == 0); CHECK(iswdigit(0x3a) == 0); }
static void test_iswalnum(void)
{
	wint_t wc;
	sweep("iswalnum", iswalnum, "alnum");
	/* iswalnum.html DESCRIPTION: "of class alpha or digit" -- the union
	 * this page states, over the whole defined domain */
	for (wc = 0; wc <= 0x7f; wc++)
		CHECK(!!iswalnum(wc) == (!!iswalpha(wc) || !!iswdigit(wc)));
	CHECK(!!iswalnum(WEOF) == (!!iswalpha(WEOF) || !!iswdigit(WEOF)));
}
static void test_iswxdigit(void)  { sweep("iswxdigit", iswxdigit, "xdigit");
	CHECK(iswxdigit(L'f') != 0); CHECK(iswxdigit(L'F') != 0);
	CHECK(iswxdigit(L'g') == 0); CHECK(iswxdigit(L'G') == 0); }
static void test_iswspace(void)   { sweep("iswspace", iswspace, "space");
	/* XBD 7.3.1's six, each by name */
	CHECK(iswspace(L' ') != 0); CHECK(iswspace(L'\t') != 0);
	CHECK(iswspace(L'\n') != 0); CHECK(iswspace(L'\v') != 0);
	CHECK(iswspace(L'\f') != 0); CHECK(iswspace(L'\r') != 0);
	CHECK(iswspace(L'\b') == 0); }
static void test_iswblank(void)   { sweep("iswblank", iswblank, "blank");
	CHECK(iswblank(L' ') != 0); CHECK(iswblank(L'\t') != 0);
	/* blank is a strict subset of space */
	CHECK(iswblank(L'\n') == 0 && iswspace(L'\n') != 0); }
static void test_iswcntrl(void)
{
	wint_t wc;
	sweep("iswcntrl", iswcntrl, "cntrl");
	/* U+0000 is in the domain and is a control character; it is also
	 * the one class member no string literal can carry */
	CHECK(iswcntrl(0) != 0);
	CHECK(iswcntrl(0x1f) != 0);
	CHECK(iswcntrl(0x20) == 0);
	CHECK(iswcntrl(0x7f) != 0);
	/* XBD 7.3.1: cntrl and print are disjoint */
	for (wc = 0; wc <= 0x7f; wc++)
		CHECK(!(iswcntrl(wc) && iswprint(wc)));
}
static void test_iswprint(void)   { sweep("iswprint", iswprint, "print");
	CHECK(iswprint(L' ') != 0); CHECK(iswprint(0x7e) != 0);
	CHECK(iswprint(0x7f) == 0); CHECK(iswprint(0x1f) == 0); }
static void test_iswgraph(void)
{
	wint_t wc;
	sweep("iswgraph", iswgraph, "graph");
	/* graph is print minus <space> */
	CHECK(iswgraph(L' ') == 0 && iswprint(L' ') != 0);
	for (wc = 0; wc <= 0x7f; wc++)
		CHECK(!!iswgraph(wc) == (iswprint(wc) && wc != L' '));
}
static void test_iswpunct(void)
{
	wint_t wc;
	sweep("iswpunct", iswpunct, "punct");
	CHECK(iswpunct(L'.') != 0); CHECK(iswpunct(L'~') != 0);
	CHECK(iswpunct(L'a') == 0); CHECK(iswpunct(L'0') == 0);
	CHECK(iswpunct(L' ') == 0);
	/* XBD 7.3.1's stated relation, as a cross-check on the enumeration */
	for (wc = 0; wc <= 0x7f; wc++)
		CHECK(!!iswpunct(wc) == (iswgraph(wc) && !iswalnum(wc)));
}

/* --------------------------------------------------------------------
 * iswctype / wctype -- iswctype.html, wctype.html
 *
 * wctype.html RETURN VALUE: "shall return a value of type wctype_t that
 * can be used ... in subsequent calls to iswctype() ... shall return
 * (wctype_t)0 if the given character class name is not valid".
 * iswctype.html RETURN VALUE: "shall return non-zero (true) if and only
 * if wc has the property described by charclass", and (CX) "If
 * charclass is (wctype_t)0, these functions shall return 0."
 * ------------------------------------------------------------------ */
static const char *const std_classes[] = {
	"alnum", "alpha", "blank", "cntrl", "digit", "graph",
	"lower", "print", "punct", "space", "upper", "xdigit"
};

static void test_wctype(void)
{
	size_t i;
	/* iswctype.html APPLICATION USAGE: the twelve names "are reserved
	 * for the standard character classes"; wctype.html requires a
	 * usable, non-zero value for each of them in every locale. */
	for (i = 0; i < sizeof std_classes / sizeof std_classes[0]; i++)
		CHECK(wctype(std_classes[i]) != (wctype_t)0);
	/* "shall return (wctype_t)0 if the given character class name is
	 * not valid for the current locale" */
	CHECK(wctype("vowel") == (wctype_t)0);
	CHECK(wctype("") == (wctype_t)0);
	CHECK(wctype("ALNUM") == (wctype_t)0);   /* names are case-sensitive */
	CHECK(wctype("alnum ") == (wctype_t)0);
	/* distinct classes must get distinct handles, or the equivalence
	 * table below could not hold for all twelve at once */
	for (i = 1; i < sizeof std_classes / sizeof std_classes[0]; i++)
		CHECK(wctype(std_classes[i]) != wctype(std_classes[i - 1]));
	/* wctype.html: repeated calls with the same name in the same locale
	 * give a value usable interchangeably */
	CHECK(wctype("digit") == wctype("digit"));
}

static void test_iswctype(void)
{
	wctype_t digit = wctype("digit");
	wint_t wc;

	CHECK(iswctype(L'5', digit) != 0);
	CHECK(iswctype(L'x', digit) == 0);
	/* CX: "If charclass is (wctype_t)0, these functions shall return 0."
	 * -- including for a wc that is in every other class. */
	CHECK(iswctype(L'5', (wctype_t)0) == 0);
	CHECK(iswctype(L'a', (wctype_t)0) == 0);
	CHECK(iswctype(WEOF, (wctype_t)0) == 0);
	CHECK(iswctype(L'5', wctype("not-a-real-class")) == 0);
	/* the domain sentence names WEOF; it is in no class */
	for (wc = 0; wc < 12; wc++)
		CHECK(iswctype(WEOF, wctype(std_classes[wc])) == 0);
}

/* iswctype.html APPLICATION USAGE's equivalence table, all twelve rows,
 * across the whole defined domain.  See the file banner for why this is
 * the assertion that matters most in this header. */
static void test_iswctype_equivalence_table(void)
{
	static int (*const fns[12])(wint_t) = {
		iswalnum, iswalpha, iswblank, iswcntrl, iswdigit, iswgraph,
		iswlower, iswprint, iswpunct, iswspace, iswupper, iswxdigit
	};
	size_t i;
	wint_t wc;

	for (i = 0; i < 12; i++) {
		wctype_t cls = wctype(std_classes[i]);
		CHECK(cls != (wctype_t)0);
		for (wc = 0; wc <= 0x7f; wc++) {
			if (!!iswctype(wc, cls) != !!fns[i](wc)) {
				fails++;
				printf("FAIL %s:%d: iswctype(U+%04X, wctype(\"%s\")) "
				    "disagrees with the isw%s() it must equal\n",
				    __FILE__, __LINE__, (unsigned)wc, std_classes[i], std_classes[i]);
			}
			/* and both must equal the spec's own class definition */
			if (!!iswctype(wc, cls) != class_oracle(std_classes[i], wc)) {
				fails++;
				printf("FAIL %s:%d: iswctype(U+%04X, wctype(\"%s\")) "
				    "disagrees with XBD 7.3.1\n",
				    __FILE__, __LINE__, (unsigned)wc, std_classes[i]);
			}
		}
		CHECK(!!iswctype(WEOF, cls) == !!fns[i](WEOF));
	}
}

/* --------------------------------------------------------------------
 * towlower / towupper -- towlower.html, towupper.html
 *
 * towlower.html DESCRIPTION: "If the argument ... represents an
 * uppercase wide-character code, and there exists a corresponding
 * lowercase wide-character code as defined by character type
 * information in the current locale (category LC_CTYPE), the result
 * shall be the corresponding lowercase wide-character code.  All other
 * arguments in the domain are returned unchanged."  RETURN VALUE says
 * the same as a return contract.  towupper.html is the mirror image.
 * ERRORS: "No errors are defined."
 * ------------------------------------------------------------------ */
static void test_towlower(void)
{
	wint_t wc;
	for (wc = 0; wc <= 0x7f; wc++) {
		/* the POSIX locale's toupper/tolower mapping is exactly the
		 * 26 A-Z <-> a-z pairs (XBD 7.3.1 LC_CTYPE toupper/tolower) */
		wint_t want = in_set(UPPER, wc) ? wc + 32 : wc;
		if (towlower(wc) != want) {
			fails++;
			printf("FAIL %s:%d: towlower(U+%04X) = U+%04X, want U+%04X\n",
			    __FILE__, __LINE__, (unsigned)wc, (unsigned)towlower(wc), (unsigned)want);
		}
	}
	/* "All other arguments in the domain are returned unchanged" --
	 * WEOF is named by the domain sentence and is not cased */
	CHECK(towlower(WEOF) == WEOF);
	CHECK(towlower(L'A') == L'a');
	CHECK(towlower(L'a') == L'a');   /* already lowercase: unchanged */
	CHECK(towlower(L'5') == L'5');
}

static void test_towupper(void)
{
	wint_t wc;
	for (wc = 0; wc <= 0x7f; wc++) {
		wint_t want = in_set(LOWER, wc) ? wc - 32 : wc;
		if (towupper(wc) != want) {
			fails++;
			printf("FAIL %s:%d: towupper(U+%04X) = U+%04X, want U+%04X\n",
			    __FILE__, __LINE__, (unsigned)wc, (unsigned)towupper(wc), (unsigned)want);
		}
	}
	CHECK(towupper(WEOF) == WEOF);
	CHECK(towupper(L'a') == L'A');
	CHECK(towupper(L'A') == L'A');
	CHECK(towupper(L'5') == L'5');
	/* the two mappings are inverses on the cased range */
	for (wc = 0; wc <= 0x7f; wc++) {
		if (in_set(UPPER, wc)) CHECK(towupper(towlower(wc)) == wc);
		if (in_set(LOWER, wc)) CHECK(towlower(towupper(wc)) == wc);
	}
}

/* --------------------------------------------------------------------
 * towctrans / wctrans -- towctrans.html, wctrans.html
 *
 * wctrans.html: "the following character mapping names are defined in
 * all locales: tolower toupper", and it "shall return 0 ... if the
 * given character mapping name is not valid for the current locale".
 * towctrans.html RETURN VALUE: "If successful ... shall return the
 * mapped value of wc using the mapping described by desc.  Otherwise,
 * they shall return wc unchanged."  APPLICATION USAGE states the two
 * equivalences towlower(wc) == towctrans(wc, wctrans("tolower")) and
 * towupper(wc) == towctrans(wc, wctrans("toupper")), asserted below
 * over the whole defined domain.
 * ------------------------------------------------------------------ */
static void test_wctrans(void)
{
	CHECK(wctrans("tolower") != (wctrans_t)0);
	CHECK(wctrans("toupper") != (wctrans_t)0);
	CHECK(wctrans("tolower") != wctrans("toupper"));
	CHECK(wctrans("tolower") == wctrans("tolower"));
	/* "shall return 0 ... if the given character mapping name is not
	 * valid for the current locale" */
	CHECK(wctrans("totitle") == (wctrans_t)0);
	CHECK(wctrans("") == (wctrans_t)0);
	CHECK(wctrans("TOLOWER") == (wctrans_t)0);
}

static void test_towctrans(void)
{
	wctrans_t lower = wctrans("tolower");
	wctrans_t upper = wctrans("toupper");
	wint_t wc;

	/* towctrans.html APPLICATION USAGE, both equivalences, whole domain */
	for (wc = 0; wc <= 0x7f; wc++) {
		CHECK(towctrans(wc, lower) == towlower(wc));
		CHECK(towctrans(wc, upper) == towupper(wc));
	}
	CHECK(towctrans(WEOF, lower) == WEOF);
	CHECK(towctrans(WEOF, upper) == WEOF);

	/* "If the value of desc is invalid ... the result is unspecified" --
	 * so the *value* is not asserted.  What is asserted is the RETURN
	 * VALUE fallback POSIX does state: "Otherwise, they shall return wc
	 * unchanged", which is the only defined answer left when no mapping
	 * was applied.  src/ctype/towctrans.c documents choosing exactly
	 * that for desc == 0 rather than leaving it undefined. */
	CHECK(towctrans(L'A', (wctrans_t)0) == L'A');
	CHECK(towctrans(L'a', wctrans("no-such-mapping")) == L'a');
}

/* --------------------------------------------------------------------
 * ERRORS, all thirteen isw* pages and both tow* pages: "No errors are
 * defined."  towctrans.html is the one exception in this header -- it
 * has a *may fail* [EINVAL] for an invalid descriptor, and an
 * APPLICATION USAGE note telling callers to zero errno first -- so it
 * is excluded from the sentinel sweep and handled in its own comment
 * above.
 * ------------------------------------------------------------------ */
static void test_no_errors_defined(void)
{
	wint_t wc;
	errno = 0x5eed;
	for (wc = 0; wc <= 0x7f; wc++) {
		(void)iswalnum(wc); (void)iswalpha(wc); (void)iswblank(wc);
		(void)iswcntrl(wc); (void)iswdigit(wc); (void)iswgraph(wc);
		(void)iswlower(wc); (void)iswprint(wc); (void)iswpunct(wc);
		(void)iswspace(wc); (void)iswupper(wc); (void)iswxdigit(wc);
		(void)iswctype(wc, wctype("alpha"));
		(void)towlower(wc); (void)towupper(wc);
	}
	(void)iswalnum(WEOF); (void)towlower(WEOF); (void)towupper(WEOF);
	CHECK(errno == 0x5eed);
}

/* --------------------------------------------------------------------
 * ntlibc's documented extension beyond the spec's domain.
 *
 * Everything asserted here is UNDEFINED per every page's domain
 * sentence -- POSIX requires nothing at all of it.  It is asserted
 * because include/wctype.h's banner commits to it in writing that a
 * lone surrogate half (0xd800-0xdfff) and any code point past the BMP
 * a 16-bit wchar_t can hold (past 0xffff) get a defined answer rather
 * than being special-cased: every classification function returns 0
 * (false) and every conversion function returns the argument
 * unchanged.  A libc that promises its callers a defined answer for
 * that undefined region owes them a test of that promise; what it
 * does not owe is a claim that POSIX demanded it, hence this section
 * being separate and labelled.
 *
 * This does NOT cover ordinary BMP code points past 0x7f (Latin-1,
 * Greek, Hebrew, Hiragana, ...): since 5da2d7f8 ("Replace ASCII-only
 * wctype classification with real Unicode 15.0.0"), include/wctype.h
 * documents those as classified from the real Unicode Character
 * Database, not blanket-false -- this file used to assert the old
 * ASCII-only contract for them, which that commit intentionally
 * dropped without updating this stale assertion (it updated
 * test/posix-wchar.c's real-Unicode coverage instead, which is where
 * per-character classification of that range is actually exercised;
 * see test_iswalpha_family() there for the same Latin-1/Greek/
 * Hebrew/Hiragana examples this array used to assume were all false).
 *
 * This is also the ASan-relevant half: a classification family
 * implemented as a table indexed by wc would read outside it here, and
 * tools/asan-build.sh runs every test that links natively.
 * ------------------------------------------------------------------ */
static void test_documented_extension(void)
{
	static const wint_t outside[] = {
		0xd800, 0xdbff, 0xdc00, 0xdfff,             /* lone surrogates */
		0x10000, 0x10ffff, 0x7fffffff, 0xfffffffeu  /* above wchar_t */
	};
	size_t i;

	for (i = 0; i < sizeof outside / sizeof outside[0]; i++) {
		wint_t wc = outside[i];
		CHECK(iswalnum(wc) == 0);
		CHECK(iswalpha(wc) == 0);
		CHECK(iswblank(wc) == 0);
		CHECK(iswcntrl(wc) == 0);
		CHECK(iswdigit(wc) == 0);
		CHECK(iswgraph(wc) == 0);
		CHECK(iswlower(wc) == 0);
		CHECK(iswprint(wc) == 0);
		CHECK(iswpunct(wc) == 0);
		CHECK(iswspace(wc) == 0);
		CHECK(iswupper(wc) == 0);
		CHECK(iswxdigit(wc) == 0);
		CHECK(iswctype(wc, wctype("alpha")) == 0);
		CHECK(towlower(wc) == wc);
		CHECK(towupper(wc) == wc);
		CHECK(towctrans(wc, wctrans("tolower")) == wc);
		CHECK(towctrans(wc, wctrans("toupper")) == wc);
	}
}

int main(void)
{
	test_iswalpha();
	test_iswupper();
	test_iswlower();
	test_iswdigit();
	test_iswalnum();
	test_iswxdigit();
	test_iswspace();
	test_iswblank();
	test_iswcntrl();
	test_iswprint();
	test_iswgraph();
	test_iswpunct();

	test_wctype();
	test_iswctype();
	test_iswctype_equivalence_table();

	test_towlower();
	test_towupper();
	test_wctrans();
	test_towctrans();

	test_no_errors_defined();
	test_documented_extension();

	if (fails) { printf("posix-wctype: failures: %d\n", fails); return 1; }
	printf("posix-wctype: all ok\n");
	return 0;
}
