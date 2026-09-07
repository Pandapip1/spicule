/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of the twelve <ctype.h>
 * classification functions:
 *
 *   isalnum isalpha isblank iscntrl isdigit isgraph
 *   islower isprint ispunct isspace isupper isxdigit
 *
 * Why a new file rather than more assertions in test/ctype.c: that file
 * is a *consistency* test.  It builds one oracle out of C range
 * expressions (`c >= 'A' && c <= 'Z'`, `c >= 0x20 && c < 0x7f`, ...) and
 * checks all sixteen ctype entry points against it at once.  That is
 * useful, but it is not a clause audit of twelve separate spec pages,
 * and test/POSIX-COVERAGE.md's priority-4 pass audited the `is*` family
 * "as a group" in exactly the same shape: it cites isascii/toascii/
 * tolower/toupper/_tolower/_toupper by name and never opens the twelve
 * individual pages.  A group audit whose oracle is written in the same
 * idiom as the implementation is precisely where an individual page's
 * requirement can hide -- so every oracle below is instead an explicit
 * *enumeration* of the characters XBD 7.3.1 LC_CTYPE puts in that class
 * in the POSIX locale, written out character by character, sharing no
 * arithmetic with the src/ctype/ sources at all.
 *
 * Spec pages consulted (https://pubs.opengroup.org/onlinepubs/9699919799/):
 *   functions/isalnum.html   functions/isalpha.html
 *   functions/isblank.html   functions/iscntrl.html
 *   functions/isdigit.html   functions/isgraph.html
 *   functions/islower.html   functions/isprint.html
 *   functions/ispunct.html   functions/isspace.html
 *   functions/isupper.html   functions/isxdigit.html
 *   basedefs/ctype.h.html    basedefs/V1_chap07.html#tag_07_03_01
 *
 * ==================== the three clauses every page has ================
 *
 * All twelve pages have the identical three-clause shape; each section
 * below cites it once and then asserts it over the whole domain:
 *
 *  (1) DESCRIPTION, class membership: "shall test whether c is a
 *      character of class <name> in the current locale".  The current
 *      locale here is always the POSIX locale -- src/misc/locale.c's
 *      setlocale() accepts no other name -- so XBD 7.3.1 LC_CTYPE's
 *      POSIX-locale class definitions are the oracle, quoted in each
 *      section's comment and enumerated in its `members` string.
 *
 *  (2) DESCRIPTION, domain: "The c argument is an int, the value of
 *      which the application shall ensure is representable as an
 *      unsigned char or equal to the value of the macro EOF.  If the
 *      argument has any other value, the behavior is undefined."  So
 *      the domain is exactly {EOF} U [0, UCHAR_MAX], and each section
 *      sweeps all 257 of those values -- both edges included, EOF
 *      called out separately because it is the one non-unsigned-char
 *      member and the one every real caller passes (getchar()).
 *
 *  (3) RETURN VALUE: "shall return non-zero if c is <class>; otherwise
 *      ... 0."  Note *non-zero*, not 1: every assertion below tests
 *      `!!f(c) == expected`, never `f(c) == 1`, so an implementation
 *      returning any other true value still passes.  The 0 side is
 *      asserted exactly, because 0 is specified exactly.
 *
 *  ERRORS on all twelve pages: "No errors are defined."  Asserted once,
 *  in test_no_errors_defined(): errno is set to a sentinel, the whole
 *  domain is swept through all twelve functions, and errno must still
 *  hold the sentinel afterwards.
 *
 * ==================== the out-of-domain probe =========================
 *
 * Clause (2) makes any other argument value *undefined*, so nothing
 * below asserts what these functions return for one.  test_out_of_
 * domain_probe() nevertheless *calls* all twelve across INT_MIN,
 * INT_MAX and the values just outside [EOF, UCHAR_MAX], deliberately
 * discarding the results.  That is not a conformance assertion; it is
 * an ASan assertion.  The classic implementation of this family is a
 * 257-entry table indexed by `c + 1`, and the classic bug is that an
 * out-of-domain argument indexes outside it -- a silent
 * heap/global-buffer-overflow that no return-value check can see.  Under
 * `make asan` (tools/asan-build.sh builds every test that links) that
 * probe is what would catch it.  spicule's src/ctype/ sources are pure
 * arithmetic on `(unsigned)c` with no table at all, so the probe passes
 * by construction today; it exists so that it would stop being true the
 * moment someone "optimizes" this family into a lookup table.
 */
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* XBD 7.3.1 LC_CTYPE, POSIX locale: the classes below are defined by
 * enumeration, and only over the portable character set -- no byte in
 * 0x80-0xff belongs to any class in this locale, which is why every
 * oracle here is a plain "is this byte in this literal set" test and
 * why the sweep asserts false for all of 0x80-0xff. */
static int in_set(const char *members, int c)
{
	const char *p;
	if (c < 0 || c > UCHAR_MAX) return 0;
	for (p = members; *p; p++)
		if ((unsigned char)*p == (unsigned char)c) return 1;
	return 0;
}

/* Sweep one classification function across the entire domain
 * {EOF} U [0, UCHAR_MAX] -- clause (2) -- comparing !!f(c) against the
 * enumerated oracle -- clause (3).  `name` only appears in failure
 * output. */
static void sweep(const char *name, int (*f)(int), const char *members)
{
	int c;
	/* clause (2): EOF is in the domain, and is not a member of any
	 * class (it is not a character at all). */
	if (!!f(EOF) != 0) { fails++; printf("FAIL %s:%d: %s(EOF) must be 0\n", __FILE__, __LINE__, name); }
	for (c = 0; c <= UCHAR_MAX; c++) {
		int want = in_set(members, c);
		if (!!f(c) != want) {
			fails++;
			printf("FAIL %s:%d: %s(%d) returned %d, want %s\n",
			    __FILE__, __LINE__, name, c, f(c), want ? "non-zero" : "0");
		}
	}
}

/* The twelve POSIX-locale class enumerations, straight out of XBD 7.3.1
 * LC_CTYPE.  Written as literals, character by character, sharing no
 * expression with the src/ctype/ sources. */
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
/* cntrl: XBD 7.3.1 -- in the POSIX locale, the NUL character, the
 * alert/backspace/tab/newline/vertical-tab/form-feed/carriage-return
 * characters and the rest of 0x00-0x1f, plus DEL (0x7f).  NUL cannot
 * appear inside a C string literal, so this one class gets a numeric
 * oracle and its own sweep rather than an enumeration string; the
 * oracle is still a closed literal range written out here, not a
 * rewrite of src/ctype/iscntrl.c's expression. */
static int cntrl_oracle(int c)
{
	return (c >= 0x00 && c <= 0x1f) || c == 0x7f;
}

static void sweep_cntrl(void)
{
	int c;
	if (!!iscntrl(EOF) != 0) { fails++; printf("FAIL %s:%d: iscntrl(EOF) must be 0\n", __FILE__, __LINE__); }
	for (c = 0; c <= UCHAR_MAX; c++) {
		int want = cntrl_oracle(c);
		if (!!iscntrl(c) != want) {
			fails++;
			printf("FAIL %s:%d: iscntrl(%d) returned %d, want %s\n",
			    __FILE__, __LINE__, c, iscntrl(c), want ? "non-zero" : "0");
		}
	}
}

/* --------------------------------------------------------------------
 * isalpha -- isalpha.html
 * DESCRIPTION: "shall test whether c is a character of class alpha in
 * the current locale".  XBD 7.3.1 LC_CTYPE, POSIX locale: class alpha
 * is exactly the 26 uppercase plus 26 lowercase letters of the portable
 * character set.
 * ------------------------------------------------------------------ */
static void test_isalpha(void)
{
	sweep("isalpha", isalpha, ALPHA);
	/* the two spot clauses worth naming separately: both domain edges */
	CHECK(isalpha(0) == 0);
	CHECK(isalpha(UCHAR_MAX) == 0);
	CHECK(isalpha(EOF) == 0);
	CHECK(isalpha('A') != 0);
	CHECK(isalpha('z') != 0);
}

/* --------------------------------------------------------------------
 * isupper / islower -- isupper.html, islower.html
 * "class upper" / "class lower".  In the POSIX locale these are exactly
 * A-Z and a-z; in particular no byte in 0x80-0xff is either, which the
 * sweep asserts for all 128 of them.
 * ------------------------------------------------------------------ */
static void test_isupper(void)
{
	sweep("isupper", isupper, UPPER);
	CHECK(isupper('A') != 0);
	CHECK(isupper('Z') != 0);
	CHECK(isupper('a') == 0);
	CHECK(isupper(EOF) == 0);
}

static void test_islower(void)
{
	sweep("islower", islower, LOWER);
	CHECK(islower('a') != 0);
	CHECK(islower('z') != 0);
	CHECK(islower('A') == 0);
	CHECK(islower(EOF) == 0);
}

/* --------------------------------------------------------------------
 * isdigit -- isdigit.html
 * "class digit".  XBD 7.3.1: in *every* locale, class digit is exactly
 * the ten characters 0-9 and nothing else ("only the digits ... shall be
 * included") -- the one class whose membership is locale-independent.
 * ------------------------------------------------------------------ */
static void test_isdigit(void)
{
	sweep("isdigit", isdigit, DIGIT);
	CHECK(isdigit('0') != 0);
	CHECK(isdigit('9') != 0);
	CHECK(isdigit('/') == 0);   /* '0' - 1 */
	CHECK(isdigit(':') == 0);   /* '9' + 1 */
	CHECK(isdigit(EOF) == 0);
}

/* --------------------------------------------------------------------
 * isalnum -- isalnum.html
 * DESCRIPTION: "shall test whether c is a character of class alpha or
 * digit in the current locale".  Asserted both ways: against the
 * enumeration, and as the stated union (a page-specific clause the
 * other eleven do not have).
 * ------------------------------------------------------------------ */
static void test_isalnum(void)
{
	int c;
	sweep("isalnum", isalnum, ALNUM);
	/* "of class alpha or digit" -- the union, stated by this page */
	for (c = EOF; c <= UCHAR_MAX; c++)
		CHECK(!!isalnum(c) == (!!isalpha(c) || !!isdigit(c)));
}

/* --------------------------------------------------------------------
 * isxdigit -- isxdigit.html
 * DESCRIPTION: "shall test whether c is a hexadecimal digit".  XBD
 * 7.3.1: class xdigit is 0-9 A-F a-f in every locale.
 * ------------------------------------------------------------------ */
static void test_isxdigit(void)
{
	sweep("isxdigit", isxdigit, XDIGIT);
	CHECK(isxdigit('f') != 0);
	CHECK(isxdigit('F') != 0);
	CHECK(isxdigit('g') == 0);
	CHECK(isxdigit('G') == 0);
	CHECK(isxdigit(EOF) == 0);
}

/* --------------------------------------------------------------------
 * isspace -- isspace.html
 * DESCRIPTION: "shall test whether c is a character of class space".
 * XBD 7.3.1, POSIX locale: <space>, <form-feed>, <newline>,
 * <carriage-return>, <tab>, <vertical-tab> -- exactly six, no more.
 * ------------------------------------------------------------------ */
static void test_isspace(void)
{
	sweep("isspace", isspace, SPACE);
	CHECK(isspace(' ') != 0);
	CHECK(isspace('\t') != 0);
	CHECK(isspace('\n') != 0);
	CHECK(isspace('\v') != 0);
	CHECK(isspace('\f') != 0);
	CHECK(isspace('\r') != 0);
	/* not space: the two control characters bracketing the \t-\r run */
	CHECK(isspace('\b') == 0);
	CHECK(isspace(0x0e) == 0);
	CHECK(isspace(EOF) == 0);
}

/* --------------------------------------------------------------------
 * isblank -- isblank.html
 * DESCRIPTION: "shall test whether c is a character of class blank".
 * XBD 7.3.1, POSIX locale: "<space> and <tab> shall be included".
 * ------------------------------------------------------------------ */
static void test_isblank(void)
{
	sweep("isblank", isblank, BLANK);
	CHECK(isblank(' ') != 0);
	CHECK(isblank('\t') != 0);
	/* blank is a strict subset of space: newline is space, not blank */
	CHECK(isblank('\n') == 0 && isspace('\n') != 0);
	CHECK(isblank(EOF) == 0);
}

/* --------------------------------------------------------------------
 * iscntrl -- iscntrl.html
 * DESCRIPTION: "shall test whether c is a character of class cntrl".
 * XBD 7.3.1, POSIX locale: the control characters, and no character of
 * class print may be in it.
 * ------------------------------------------------------------------ */
static void test_iscntrl(void)
{
	int c;
	sweep_cntrl();
	/* NUL: in the domain (representable as unsigned char), a control
	 * character, and the one class member no C string literal can carry
	 * -- so it is asserted on its own rather than through the sweep's
	 * enumeration. */
	CHECK(iscntrl(0) != 0);
	CHECK(iscntrl(0x1f) != 0);
	CHECK(iscntrl(0x20) == 0);
	CHECK(iscntrl(0x7f) != 0);
	CHECK(iscntrl(EOF) == 0);
	/* XBD 7.3.1: cntrl and print are disjoint */
	for (c = 0; c <= UCHAR_MAX; c++)
		CHECK(!(iscntrl(c) && isprint(c)));
}

/* --------------------------------------------------------------------
 * isprint / isgraph -- isprint.html, isgraph.html
 * isprint.html DESCRIPTION: "shall test whether c is a character of
 * class print"; isgraph.html: "class graph".  XBD 7.3.1: print is
 * alnum + punct + <space>; graph is alnum + punct, i.e. print without
 * <space>.  Both relations are asserted, not just the enumerations.
 * ------------------------------------------------------------------ */
static void test_isprint(void)
{
	sweep("isprint", isprint, PRINT);
	CHECK(isprint(' ') != 0);
	CHECK(isprint(0x7e) != 0);
	CHECK(isprint(0x7f) == 0);
	CHECK(isprint(0x1f) == 0);
	CHECK(isprint(EOF) == 0);
}

static void test_isgraph(void)
{
	int c;
	sweep("isgraph", isgraph, GRAPH);
	CHECK(isgraph('!') != 0);
	CHECK(isgraph(0x7e) != 0);
	/* isgraph.html: "class graph" excludes <space>, which is print */
	CHECK(isgraph(' ') == 0 && isprint(' ') != 0);
	CHECK(isgraph(EOF) == 0);
	/* graph == print minus <space>, over the whole domain */
	for (c = 0; c <= UCHAR_MAX; c++)
		CHECK(!!isgraph(c) == (isprint(c) && c != ' '));
}

/* --------------------------------------------------------------------
 * ispunct -- ispunct.html
 * DESCRIPTION: "shall test whether c is a character of class punct".
 * XBD 7.3.1, POSIX locale: every printable character that is neither
 * <space> nor a member of alpha or digit -- enumerated below rather
 * than derived, so a defect in isalnum()/isgraph() cannot cancel out
 * against a matching defect here.
 * ------------------------------------------------------------------ */
static void test_ispunct(void)
{
	int c;
	sweep("ispunct", ispunct, PUNCT);
	CHECK(ispunct('!') != 0);
	CHECK(ispunct('~') != 0);
	CHECK(ispunct('a') == 0);
	CHECK(ispunct('0') == 0);
	CHECK(ispunct(' ') == 0);
	CHECK(ispunct(EOF) == 0);
	/* XBD 7.3.1's stated relation, as a cross-check on the enumeration */
	for (c = 0; c <= UCHAR_MAX; c++)
		CHECK(!!ispunct(c) == (isgraph(c) && !isalnum(c)));
}

/* --------------------------------------------------------------------
 * ERRORS, all twelve pages: "No errors are defined."
 * A conforming implementation therefore must not set errno; sweep the
 * whole domain through all twelve and confirm the sentinel survives.
 * ------------------------------------------------------------------ */
static void test_no_errors_defined(void)
{
	int c;
	errno = 0x5eed;
	for (c = EOF; c <= UCHAR_MAX; c++) {
		(void)isalnum(c); (void)isalpha(c); (void)isblank(c);
		(void)iscntrl(c); (void)isdigit(c); (void)isgraph(c);
		(void)islower(c); (void)isprint(c); (void)ispunct(c);
		(void)isspace(c); (void)isupper(c); (void)isxdigit(c);
	}
	CHECK(errno == 0x5eed);
}

/* --------------------------------------------------------------------
 * !!! DO NOT DELETE THIS TEST BECAUSE IT ASSERTS NOTHING. !!!
 *
 * Out-of-domain probe.  It deliberately asserts nothing about the
 * values these calls return, because isalnum.html and its eleven
 * siblings all say the same thing about them: "If the argument has any
 * other value, the behavior is undefined."  There is no correct answer
 * to assert.
 *
 * What it checks is not a return value, it is a memory access.  The
 * classic implementation of this family is a 257-entry table indexed by
 * `c + 1`, and the classic bug is that an out-of-domain argument
 * indexes outside it: a silent global- or heap-buffer-overflow that no
 * return-value assertion anywhere can see, precisely because the return
 * value is undefined for exactly those arguments.  `make asan`
 * (tools/asan-build.sh builds and runs every test that links natively,
 * under ASan + UBSan) is the checker here; this function is only the
 * thing that hands ASan the arguments.
 *
 * Verified out-of-band, 2026-08-24, that ASan does catch that shape
 * given exactly this argument list: a stand-in
 *
 *     static const unsigned char tbl[257];
 *     static int isalpha_tbl(int c) { return tbl[c + 1]; }
 *
 * handed the `probes[]` array below dies with "AddressSanitizer: SEGV"
 * inside isalpha_tbl on the first out-of-domain value.  spicule's
 * src/ctype/ sources are pure arithmetic on `(unsigned)c` with no table at
 * all, so this passes by construction today -- and that is exactly why
 * it must stay: it exists to stop being true the moment someone
 * "optimizes" this family into a lookup table.
 *
 * It is called from main() like every other test in this file.
 * ------------------------------------------------------------------ */
static void test_out_of_domain_probe(void)
{
	static const int probes[] = {
		INT_MIN, INT_MIN + 1, -1000, EOF - 1, /* below the domain */
		UCHAR_MAX + 1, 0x100, 0xffff, 0x10000, INT_MAX - 1, INT_MAX
	};
	size_t i;
	int sink = 0;
	for (i = 0; i < sizeof probes / sizeof probes[0]; i++) {
		int c = probes[i];
		sink += isalnum(c) + isalpha(c) + isblank(c) + iscntrl(c);
		sink += isdigit(c) + isgraph(c) + islower(c) + isprint(c);
		sink += ispunct(c) + isspace(c) + isupper(c) + isxdigit(c);
	}
	/* The sum is deliberately unasserted -- every term is undefined.
	 * Consuming it keeps the calls from being optimized away, which is
	 * the entire point of the probe. */
	CHECK(sink == sink);
}

int main(void)
{
	test_isalpha();
	test_isupper();
	test_islower();
	test_isdigit();
	test_isalnum();
	test_isxdigit();
	test_isspace();
	test_isblank();
	test_iscntrl();
	test_isprint();
	test_isgraph();
	test_ispunct();
	test_no_errors_defined();
	test_out_of_domain_probe();

	if (fails) { printf("posix-ctype: failures: %d\n", fails); return 1; }
	printf("posix-ctype: all ok\n");
	return 0;
}
