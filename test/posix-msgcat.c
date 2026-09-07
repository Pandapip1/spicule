/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of four headers of the
 * locale/message-handling family, none of which spicule had when this
 * file was written:
 *
 *   <langinfo.h>   nl_langinfo, nl_langinfo_l      IMPLEMENTED 2026-08-25
 *   <nl_types.h>   catopen, catgets, catclose      IMPLEMENTED 2026-08-25
 *   <monetary.h>   strfmon, strfmon_l              IMPLEMENTED 2026-08-25
 *   <iconv.h>      iconv_open, iconv, iconv_close  IMPLEMENTED 2026-08-25
 *
 * STATUS, and read the rest of this banner in its light. Everything below
 * the next heading was written and measured on 2026-08-25 against a tree
 * in which all four were absent, and is kept verbatim -- a record of what
 * was checked is worth more than one edited to agree with today. All four
 * headers are now implemented (include/{langinfo,nl_types,monetary,
 * iconv}.h and the matching sources in src/misc/), so the six cases
 * covering them are un-fenced and run, plus one new case,
 * test_catgets_reads_a_catalogue(),
 * since the original could only watch catopen() fail on a machine with no
 * catalogues installed. Sentences below saying "the four" or "does not
 * exist" describe the 2026-08-25 tree; a *fenced* case's own claim of
 * that kind was rewritten in the same commit as its implementation.
 *
 * Spec pages consulted (https://pubs.opengroup.org/onlinepubs/9699919799/):
 *   basedefs/langinfo.h.html    functions/nl_langinfo.html
 *   basedefs/nl_types.h.html    functions/catopen.html
 *   functions/catgets.html      functions/catclose.html
 *   basedefs/monetary.h.html    functions/strfmon.html
 *   basedefs/iconv.h.html       functions/iconv_open.html
 *   functions/iconv.html        functions/iconv_close.html
 *   functions/strftime.html     functions/localeconv.html
 *   basedefs/limits.h.html
 *
 * Every passage in double quotes below is verbatim from IEEE Std
 * 1003.1-2017 / The Open Group Base Specifications Issue 7, 2018
 * Edition; the only liberty taken is whitespace (runs of spaces
 * collapsed, wrapped lines rejoined).  Two limitations are stated once
 * here rather than repeated at each site:
 *
 *  - The rendering this audit worked from drops the standard's margin
 *    markers, so [XSI]/[CX]/[OB] option shading is not visible on any
 *    page.  No option marker is guessed anywhere in this file.  Where
 *    option status matters it is taken from this repo's own
 *    test/POSIX-GAP-ACCOUNTING.md, which counts all eleven functions
 *    below as POSIX **base**, and is cited as such rather than quoted.
 *  - XBD Chapter 7 (Locale), which fixes the POSIX locale's value for
 *    each langinfo item, is not a manual page and is not among the
 *    pages consulted.  Where this file states a POSIX-locale item value
 *    that no consulted page gives -- YESEXPR and NOEXPR -- it says so
 *    at the site and does not put the value in quotation marks.
 *
 * ============ the absence, as verified on 2026-08-25 =================
 *
 * An absence is a claim, and a grep that finds nothing is evidence only
 * if the same grep finds something when there is something to find.  So
 * each command below is run twice: once on a header and a function this
 * tree demonstrably HAS, and once on the four it does not.  Run
 * 2026-08-25 against this tree, not inherited from an older audit.
 *
 * POSITIVE CONTROLS -- the pattern works:
 *
 *   $ grep -rn 'wctype' include/ src/ | wc -l
 *   41
 *   $ grep -rn 'localeconv' include/ src/
 *   include/locale.h:56:struct lconv *localeconv(void);
 *   src/misc/locale.c:51:struct lconv *localeconv(void)
 *
 * THE FOUR -- the same pattern, nothing:
 *
 *   $ grep -rnc 'langinfo\|nl_types\|monetary\.h\|iconv\|nl_langinfo\|
 *       catopen\|catgets\|catclose\|strfmon\|nl_item\|nl_catd'
 *       include/ src/ arch/ crt/ | grep -v ':0$'
 *   (no output; grep exit status 1)
 *
 * And the same control on the headers themselves, in one command so the
 * hits and the misses are visibly from the same run:
 *
 *   $ find include -name 'wctype.h' -o -name 'locale.h' \
 *       -o -name 'langinfo.h' -o -name 'iconv.h'
 *   include/wctype.h
 *   include/locale.h
 *
 * `find include -name '*.h' | wc -l` is 67 today; two of the four names
 * asked for come back, two do not.  <nl_types.h> and <monetary.h> were
 * checked the same way and are likewise absent.
 *
 * COUNTS, and what is being counted -- three different numbers that
 * disagree, so each is named:
 *
 *   4    absent headers (the subject of this file)
 *   11   absent function interfaces (2 + 3 + 2 + 3).  Counted per
 *        function name, which is not the same as per page:
 *        nl_langinfo.html declares two of them and strfmon.html two,
 *        while iconv's three have a page each.
 *   6    `#if 0` blocks defining a test function in this file -- NOT
 *        one per header.  <langinfo.h> gets three, because its header
 *        page's constant list, nl_langinfo() and nl_langinfo_l() are
 *        three separate clauses with three different acceptance
 *        criteria; the other three headers get one each.  A seventh
 *        `#if 0` in main() holds the six call sites and defines no
 *        function.
 *   55   langinfo item constants, counted from the table in
 *        langinfo.h.html and enumerated at
 *        test_langinfo_h_item_constants below.
 *
 * Plus every type and constant the four headers carry -- nl_item,
 * nl_catd, iconv_t, NL_SETD, NL_CAT_LOCALE -- none of which appears in
 * the grep above.
 *
 * ==================== what the two ledgers already say ===============
 *
 * Checked both, both ways, because they are keyed differently:
 * POSIX-COVERAGE.md by test function, POSIX-GAP-ACCOUNTING.md by
 * subject, so neither search alone answers "is this recorded".  Both
 * greps were run BEFORE this file's own ledger section was appended --
 * re-running the first one now finds that section too, which is the
 * point rather than a defect in the record.
 *
 *   $ grep -n 'langinfo\|nl_types\|monetary\|iconv\|catopen\|catgets\|
 *       catclose\|strfmon\|nl_item\|nl_catd\|message catalog\|codeset'
 *       test/POSIX-COVERAGE.md
 *   exactly two hits, neither about these headers:
 *     ... "the non-monetary grouping character" ...   (printf, unrelated)
 *     | fork | message catalogs, semaphores, ... | N/A -- ...
 *
 *   $ ... the same pattern over test/POSIX-GAP-ACCOUNTING.md
 *   "### Locale and message catalogues (11)", four rows under it (one
 *   per group, with an interface count, an option column and a
 *   sentence of triage), and four entries in the base-absence table:
 *   nl_types.h 3, iconv.h 3, monetary.h 2, langinfo.h 2.
 *
 *   (Line numbers deliberately not recorded: both files move under
 *   other branches, and a stale line number reads as a checked fact.)
 *
 * So: **the subject is recorded and the clauses are not.**
 * POSIX-GAP-ACCOUNTING.md carries all four as subjects with interface
 * counts and a sentence of triage each, and names no test function,
 * cites no page and quotes no clause.  POSIX-COVERAGE.md carries
 * nothing at all -- its only touch on the subject is fork()'s row,
 * which lists "message catalogs" among the facilities a fork() clause
 * has no object for and refers out to the gap accounting.  That row is
 * about a fork() clause, not about <nl_types.h>, and nothing in this
 * file contradicts it.
 *
 * What this file adds on top of what was already recorded: the clause
 * text itself, per-header fenced tests, and the first rows for these
 * four headers in the test-function-keyed ledger.
 *
 * ==================== the classification, and why ====================
 *
 * All four are **UNIMPL**, in this project's "I chose not to" sense --
 * and specifically UNIMPL *not declined*.  The difference from
 * test/posix-stropts.c, which is the file this one is modelled on,
 * matters, because the two look alike from outside and are not:
 *
 *   <stropts.h>   DECLINED.  POSIX deleted it in Issue 8; the header is
 *                 nothing but STREAMS machinery NT has no subsystem
 *                 for; and its ioctl() prototype conflicts with one
 *                 this tree already ships.  Shipping it would move a
 *                 compile failure to a link failure and fix nothing.
 *
 *   these four    NOT declined.  All eleven functions are current in
 *                 POSIX.1-2017 and are counted POSIX base by this
 *                 repo's own POSIX-GAP-ACCOUNTING.md.  None needs
 *                 anything NT cannot do.  The strongest platform
 *                 dependency on any of the twelve pages consulted is
 *                 catopen()'s pathname resolution and its FD_CLOEXEC
 *                 requirement, and spicule implements and audits both;
 *                 everything else is computation over memory.  Three of
 *                 the four are table lookup and string formatting over data
 *                 this tree already holds; the fourth (<nl_types.h>) is
 *                 explicitly permitted by the standard to fail for want
 *                 of an installed catalogue, and its callers are
 *                 written to keep working when it does.
 *
 * The counter-argument considered and rejected: "spicule is
 * C-locale-only -- src/misc/locale.c's setlocale() accepts no other
 * name -- so a locale-data accessor has nothing to accessorise; call it
 * N/A."  N/A in this ledger requires a *mechanism* that keeps the
 * clause from applying, and there is none here.  nl_langinfo.html's
 * RETURN VALUE is written for exactly this implementation: "In a locale
 * where langinfo data is not defined, these functions shall return a
 * pointer to the corresponding string in the POSIX locale."  Being
 * C-locale-only is the case the clause names, not an exemption from it.
 * It makes these functions easy, not inapplicable.
 *
 * ==================== what a caller observes today ===================
 *
 * The same thing for all four, and it is the first thing that happens
 * rather than the last: **the translation unit does not compile.**  Not
 * a link failure, not a degraded run-time answer -- `#include
 * <langinfo.h>` does not resolve.  test/libc-test-expected.txt records
 * this happening to real code in the corpus this project already runs:
 *
 *   clocale_mbfuncs   unbuildable  clocale_mbfuncs.c:7: error: include
 *                                  file 'langinfo.h' not found
 *   mbc               unbuildable  mbc.c:6: error: ... 'langinfo.h' ...
 *   iconv_open        unbuildable  iconv_open.c:3: error: include file
 *                                  'iconv.h' not found
 *   iconv-roundtrips  unbuildable  iconv-roundtrips.c:3: ... 'iconv.h' ...
 *
 * and one case where the absence reaches past the callers that name it:
 *
 *   fgetwc-buffering  unverifiable  builds and links ..., but opens with
 *                                   libc-test's t_setutf8(), which needs
 *                                   nl_langinfo(CODESET); no <langinfo.h>
 *                                   on this target ...
 *
 * <langinfo.h> declares two functions, and
 * test/LIBC-TEST-MAP.generated.md measures it as the highest-density
 * header lever in that whole corpus: 3 tests naming it, 3 unblocked by
 * it alone, 2 absent interfaces, 1.50 tests per interface -- ahead of
 * every other absent header, including pthread.h (0.33) and
 * semaphore.h (0.90).  <iconv.h> is 2/2/3 = 0.67.  <nl_types.h> and
 * <monetary.h> unblock nothing in that corpus and do not appear in its
 * table at all; that is recorded here too, because it is the honest
 * half of the picture -- they are cheap and base, not urgent.
 *
 * ==================== what each one would be built on =================
 *
 * test/POSIX-HEADER-INVENTORY.md has a one-line note per header, and
 * every claim taken from it below is attributed and dated rather than
 * repeated as fact.  That file's own banner calls itself "draft,
 * produced by an audit agent", says it compared against "include/
 * (`find include -name '*.h'`, 41 headers) as of this audit", and was
 * last touched by 1b82187 (2026-08-24).  `find include -name '*.h' |
 * wc -l` is 67 today, so the tree it measured is not this one: its
 * notes are a decaying measurement, not a standing description.  Each
 * was re-checked here against the files it names.  Two of the four are
 * right; two need correcting, and the corrections are the sharpest part
 * of this finding.  Every "already in the tree" claim below is followed
 * by the grep that shows it, because an assumption about what
 * localeconv() usually holds is not evidence about what this one holds.
 *
 * <langinfo.h> -- the inventory says nl_langinfo() "reads out of the
 *   same locale data locale.h (present) already has; thin wrapper".
 *   Thin, yes.  "The same locale data", no: the item set is spread over
 *   three source files and localeconv() is the smallest of the three.
 *   The header page's own Category column is what makes this checkable,
 *   because it says which setlocale() category each item belongs to:
 *
 *     LC_NUMERIC  RADIXCHAR, THOUSEP        src/misc/locale.c
 *                                           __posix_lconv .decimal_point
 *                                           and .thousands_sep
 *     LC_MONETARY CRNCYSTR                  src/misc/locale.c
 *                                           .currency_symbol with
 *                                           .p_cs_precedes/.n_cs_precedes
 *     LC_TIME     DAY_1..7, ABDAY_1..7,     src/time/names.c -- the four
 *                 MON_1..12, ABMON_1..12    const arrays strftime() uses
 *     LC_TIME     D_T_FMT, D_FMT, T_FMT,    src/time/strftime.c -- NOT
 *                 T_FMT_AMPM, AM_STR,       stored as strings at all;
 *                 PM_STR                    open-coded into the %c, %x,
 *                                           %X, %r and %p cases
 *     LC_TIME     ERA, ERA_D_FMT,           nowhere -- and nothing to
 *                 ERA_D_T_FMT, ERA_T_FMT,   store: the POSIX locale
 *                 ALT_DIGITS                defines no era and no
 *                                           alternative digits
 *     LC_CTYPE    CODESET                   src/stdlib/mbrtowc.c -- the
 *                                           UTF-8 decoder and
 *                                           __ctype_get_mb_cur_max()
 *     LC_MESSAGES YESEXPR, NOEXPR           nowhere; two string literals
 *                                           with a working regcomp() in
 *                                           src/regex/regex.c waiting
 *                                           for them
 *
 *   The evidence for each row of that table, rather than an assumption
 *   about what a locale.c usually contains:
 *
 *     $ grep -n 'decimal_point\|thousands_sep\|currency_symbol\|
 *         p_cs_precedes\|frac_digits' src/misc/locale.c
 *     25: .decimal_point = (char *)".",
 *     26: .thousands_sep = (char *)"",
 *     29: .currency_symbol = (char *)"",
 *     30: .mon_decimal_point = (char *)"",
 *     31: .mon_thousands_sep = (char *)"",
 *     35: .int_frac_digits = 127,
 *     36: .frac_digits = 127,
 *     37: .p_cs_precedes = 127,
 *     43: .int_p_cs_precedes = 127,
 *
 *     $ grep -n '__spicule_day_name\|__spicule_month_name' src/time/names.c
 *     5:  const char *const __spicule_day_name[7] = {
 *     8:  const char *const __spicule_day_name_abbr[7] = {
 *     11: const char *const __spicule_month_name[12] = {
 *     15: const char *const __spicule_month_name_abbr[12] = {
 *
 *     $ grep -n "case 'c':\|case 'x':\|case 'X':\|case 'r':\|case 'p':"
 *         src/time/strftime.c
 *     55:  case 'c':
 *     83:  case 'p': PUT_STR(tm->tm_hour < 12 ? "AM" : "PM"); break;
 *     84:  case 'r':
 *     111: case 'x':
 *     116: case 'X':
 *
 *   Note what the last two show and the inventory's one-liner does not:
 *   the day and month names are addressable data, but the four
 *   composite formats are *switch cases*, not strings -- there is no
 *   D_T_FMT in this tree to return a pointer to, only code that behaves
 *   as if there were.  (Note also that locale.c writes the literal 127
 *   rather than CHAR_MAX; the two coincide on both targets, and
 *   test/posix-misc.c already asserts the CHAR_MAX spelling live.)
 *
 *   The arithmetic, counted off the page's table so it can be checked:
 *   55 items in all.  49 are LC_TIME -- 38 names (DAY_1..7, ABDAY_1..7,
 *   MON_1..12, ABMON_1..12), 6 formats and affixes (D_T_FMT, D_FMT,
 *   T_FMT, T_FMT_AMPM, AM_STR, PM_STR), and 5 era/alternative-digit
 *   items (ERA, ERA_D_FMT, ERA_D_T_FMT, ERA_T_FMT, ALT_DIGITS).  The
 *   remaining 6 are 2 LC_NUMERIC, 1 LC_MONETARY, 1 LC_CTYPE and 2
 *   LC_MESSAGES.  49 + 2 + 1 + 1 + 2 = 55.
 *
 *   48 of the 55 are already in this tree under other names: the 44
 *   non-era LC_TIME items, the 2 LC_NUMERIC fields, CRNCYSTR's source
 *   fields, and the codeset.  Of the 7 that are not, 5 have nothing to
 *   store (the POSIX locale defines no era and no alternative digits)
 *   and 2 are string literals.  And 44 of those 48 are LC_TIME items
 *   localeconv() has never held -- which is the half of the inventory's
 *   one-liner that does not survive the re-check.
 *
 *   The work is one const table plus the decision to give strftime's
 *   four composite formats a name.  Still small, still no NT dependency
 *   anywhere in it.
 *
 *   The standard itself draws the same map, from the other side.
 *   langinfo.h.html APPLICATION USAGE: "Wherever possible, users are
 *   advised to use functions compatible with those in the ISO C
 *   standard to access items of langinfo data. In particular, the
 *   strftime() function should be used to access date and time
 *   information defined in category LC_TIME. The localeconv() function
 *   should be used to access information corresponding to RADIXCHAR,
 *   THOUSEP, and CRNCYSTR."  Both of those functions are implemented
 *   and audited here.  The live tests below are that paragraph, run.
 *
 * <nl_types.h> -- inventory: "trivial to stub against a fixed 'no
 *   catalogs installed' behavior, which POSIX explicitly permits".
 *   Re-checked and correct; see the fence for the clauses that make it
 *   so.  A conforming implementation on a system with no catalogues is
 *   a few dozen lines over getenv() (NLSPATH), open()/read()/close(),
 *   and the LC_MESSAGES category src/misc/locale.c already accepts.
 *   All of those are present in this tree, and so -- already -- are the
 *   <limits.h> constants that bound a catalogue; see
 *   test_message_catalogue_limits_exist_without_the_header.
 *
 * <monetary.h> -- inventory: "locale-driven formatting on top of the
 *   locale.c this tree already has; low value, easy".  Re-checked and
 *   correct, with the low-value half worth stating precisely rather
 *   than as an impression: in the POSIX locale every LC_MONETARY member
 *   of struct lconv is the "not available" value, which
 *   test_lc_numeric_and_lc_monetary_data_without_an_accessor asserts
 *   live.  That is an argument about priority.  It is not an argument
 *   about applicability -- see the fence.
 *
 * <iconv.h> -- inventory: "src/internal/utf.c already implements UTF
 *   conversions internally; ... mostly a stable-name wrapper around
 *   that plus a small codeset table".  Re-checked, and this is the note
 *   most out of date.  src/internal/utf.c is whole-string:
 *   __utf8_to_utf16() mallocs, converts everything, returns -- true
 *   whether the conversion underneath is ntdll's RtlUTF8ToUnicodeN /
 *   RtlUnicodeToUTF8N (as it was) or the in-tree hand-rolled codec
 *   utf.c carries now (as it is; see tools/ntdll.def's history for why).
 *   Either way it has none of iconv()'s shape -- no conversion
 *   descriptor, no incremental pointer advance, no resumable state, no
 *   partial-output case.
 *
 *   The evidence for both halves of that, from the two files:
 *
 *     $ grep -n '^static int utf\|__malloc(' src/internal/utf.c
 *     60: static int utf8_to_utf16n(WCHAR *dst, ULONG dstbytes, ULONG *written,
 *     116: static int utf16_to_utf8n(char *dst, ULONG dstbytes, ULONG *written,
 *     179: w = __malloc(allocation);
 *     227: char *s = __malloc(cap);
 *
 *     $ grep -n 'EILSEQ\|size_t)-2\|__opaque' src/stdlib/mbrtowc.c
 *     26: int mbsinit(const mbstate_t *st) { return !st ||
 *           (!st->__opaque1 && !st->__opaque2); }
 *     40: if (st->__opaque2) {       /- a pending low surrogate -/
 *     45: if (!n) return (size_t)-2;
 *     47: if (st->__opaque1) {
 *
 *   ntdll calls and a malloc on one side; resumable per-call state on
 *   the other.
 *
 *   src/stdlib/mbrtowc.c has all four, in pure C with no ntdll
 *   dependency.  mbrtowc()/wcrtomb() are a stateful, incremental
 *   UTF-8 <-> UTF-16 converter carrying partial sequences and pending
 *   surrogates in mbstate_t, and their failure returns line up with
 *   iconv()'s three *shall fail* conditions one for one:
 *
 *     (size_t)-1 with errno EILSEQ      [EILSEQ]
 *     (size_t)-2 (incomplete input)     [EINVAL]
 *     the caller's own space check      [E2BIG]
 *
 *   test_codeset_is_utf8_and_the_converter_exists asserts all of that
 *   live, today.  So iconv() here is a descriptor allocation, a small
 *   codeset alias table, and a loop over a converter that already
 *   exists and already works on every leg including the native asan
 *   build -- which the utf.c route would not.
 *
 * ==================== what this file therefore does ==================
 *
 * Six live test functions, each showing a piece of langinfo/monetary/
 * iconv data that is already in this tree and already reachable
 * *through some other interface*, so that the fences below claim a
 * missing accessor rather than missing data.  Then six fenced test
 * functions -- three for <langinfo.h>, one each for the other three
 * headers, per the count above -- carrying the assertions that would
 * run the day each is implemented.
 */
/* newlocale()/LC_ALL_MASK are feature-test gated in include/locale.h;
 * same define most other tests in test/ already carry for the same reason
 * (see test/posix-glob.c's comment on this exact define). */
#define _GNU_SOURCE
#include <locale.h>
#include <time.h>
#include <limits.h>
#include <regex.h>
#include <wchar.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <langinfo.h>
#include <nl_types.h>
#include <monetary.h>
#include <iconv.h>
#include "test-policy.h"

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* --------------------------------------------------------------------
 * LIVE.  The LC_TIME half of the langinfo item set, reached through
 * strftime() because there is no nl_langinfo() to reach it through.
 *
 * This is the test langinfo.h.html's APPLICATION USAGE describes:
 * "the strftime() function should be used to access date and time
 * information defined in category LC_TIME".
 *
 * strftime.html fixes what those items are in this locale.  Verbatim,
 * under "In the C or POSIX locale, the E and O modifiers are ignored
 * and the replacement strings for the following specifiers are:"
 *
 *   "%a The first three characters of %A."
 *   "%A One of Sunday, Monday, ..., Saturday."
 *   "%b The first three characters of %B."
 *   "%B One of January, February, ..., December."
 *   "%c Equivalent to %a %b %e %T %Y."
 *   "%p One of AM or PM."
 *   "%r Equivalent to %I:%M:%S %p."
 *   "%x Equivalent to %m/%d/%y."
 *   "%X Equivalent to %T."
 *
 * and from the conversion table, "T Replaced by the time (%H:%M:%S)."
 * Those four composites are D_T_FMT, T_FMT_AMPM, D_FMT and T_FMT --
 * nl_langinfo.html's own EXAMPLES section is the round trip:
 * "strftime (datestring, sizeof(datestring), nl_langinfo (D_T_FMT), tm);"
 *
 * Every one of those strings is already in this library.  The day and
 * month names are src/time/names.c's four const arrays; the four
 * composite formats are open-coded in src/time/strftime.c's %c, %x, %X
 * and %r cases.  What is missing is only the name to ask for them by.
 *
 * The assertions are two-sided on purpose: each composite is compared
 * both against the literal the C locale produces and against the
 * expansion of the format string nl_langinfo() would have to return, so
 * a future divergence between strftime's open-coded %c and a table
 * D_T_FMT is caught from either direction.
 *
 * Safe in all three legs: strftime() is fed a fully initialised struct
 * tm and no timezone-dependent specifier (%Z/%z) is used, so nothing
 * here depends on the environment.  test/posix-time.c already asserts
 * strftime output this way.
 * ------------------------------------------------------------------ */
static void test_lc_time_data_is_present_without_an_accessor(void)
{
	/* Sunday 2 January 2000, 03:04:05 -- wday 0 and mon 0 so the
	 * DAY_1/ABDAY_1/MON_1/ABMON_1 entries are the ones selected. */
	struct tm tm;
	char a[64], b[64];

	memset(&tm, 0, sizeof tm);
	tm.tm_sec = 5; tm.tm_min = 4; tm.tm_hour = 3;
	tm.tm_mday = 2; tm.tm_mon = 0; tm.tm_year = 100;
	tm.tm_wday = 0; tm.tm_yday = 1; tm.tm_isdst = 0;

	/* DAY_1 / ABDAY_1 / MON_1 / ABMON_1 / AM_STR */
	CHECK(strftime(a, sizeof a, "%A", &tm) && !strcmp(a, "Sunday"));
	CHECK(strftime(a, sizeof a, "%a", &tm) && !strcmp(a, "Sun"));
	CHECK(strftime(a, sizeof a, "%B", &tm) && !strcmp(a, "January"));
	CHECK(strftime(a, sizeof a, "%b", &tm) && !strcmp(a, "Jan"));
	CHECK(strftime(a, sizeof a, "%p", &tm) && !strcmp(a, "AM"));

	/* PM_STR: same struct, afternoon. */
	tm.tm_hour = 15;
	CHECK(strftime(a, sizeof a, "%p", &tm) && !strcmp(a, "PM"));
	tm.tm_hour = 3;

	/* D_T_FMT -- "%c Equivalent to %a %b %e %T %Y." */
	CHECK(strftime(a, sizeof a, "%c", &tm) != 0);
	CHECK(strftime(b, sizeof b, "%a %b %e %T %Y", &tm) != 0);
	CHECK(!strcmp(a, "Sun Jan  2 03:04:05 2000"));
	CHECK(!strcmp(a, b));

	/* D_FMT -- "%x Equivalent to %m/%d/%y." */
	CHECK(strftime(a, sizeof a, "%x", &tm) != 0);
	CHECK(strftime(b, sizeof b, "%m/%d/%y", &tm) != 0);
	CHECK(!strcmp(a, "01/02/00"));
	CHECK(!strcmp(a, b));

	/* T_FMT -- "%X Equivalent to %T." */
	CHECK(strftime(a, sizeof a, "%X", &tm) != 0);
	CHECK(strftime(b, sizeof b, "%T", &tm) != 0);
	CHECK(!strcmp(a, "03:04:05"));
	CHECK(!strcmp(a, b));

	/* T_FMT_AMPM -- "%r Equivalent to %I:%M:%S %p." */
	CHECK(strftime(a, sizeof a, "%r", &tm) != 0);
	CHECK(strftime(b, sizeof b, "%I:%M:%S %p", &tm) != 0);
	CHECK(!strcmp(a, "03:04:05 AM"));
	CHECK(!strcmp(a, b));
}

/* --------------------------------------------------------------------
 * LIVE.  RADIXCHAR, THOUSEP and CRNCYSTR -- the three langinfo items
 * that really are localeconv() fields -- and the LC_MONETARY block
 * strfmon() would be driven by, reached through localeconv() because
 * there is no nl_langinfo() and no strfmon().
 *
 * This is the other half of langinfo.h.html's APPLICATION USAGE: "The
 * localeconv() function should be used to access information
 * corresponding to RADIXCHAR, THOUSEP, and CRNCYSTR."
 *
 * localeconv.html DESCRIPTION: "The members of the structure with type
 * char * are pointers to strings, any of which (except decimal_point)
 * can point to "", to indicate that the value is not available in the
 * current locale or is of zero length. The members with type char are
 * non-negative numbers, any of which can be {CHAR_MAX} to indicate that
 * the value is not available in the current locale."
 *
 * Every LC_MONETARY member here is that "not available" value.  Two
 * consequences, both recorded rather than glossed:
 *
 *  - It is the finding for <monetary.h>, stated as data: strfmon()
 *    here would have an empty currency symbol, no grouping and no
 *    frac_digits to read.  Low value.
 *  - langinfo.h.html attaches a condition to CRNCYSTR that this tree
 *    already satisfies: "If the locale's values for p_cs_precedes and
 *    n_cs_precedes do not match, the value of nl_langinfo(CRNCYSTR)
 *    and nl_langinfo_l(CRNCYSTR,loc) is unspecified."  They match here
 *    (both {CHAR_MAX}), so CRNCYSTR would have a defined answer --
 *    which the last assertion below pins down.
 *
 * Safe in all three legs: test/posix-misc.c's test_locale() already
 * asserts the {CHAR_MAX} members and the non-empty decimal_point.
 * ------------------------------------------------------------------ */
static void test_lc_numeric_and_lc_monetary_data_without_an_accessor(void)
{
	struct lconv *lc = localeconv();

	CHECK(lc != NULL);
	if (!lc) return;

	/* RADIXCHAR, THOUSEP */
	CHECK(!strcmp(lc->decimal_point, "."));
	CHECK(!strcmp(lc->thousands_sep, ""));
	CHECK(!strcmp(lc->grouping, ""));

	/* CRNCYSTR's source, and everything strfmon() would read */
	CHECK(!strcmp(lc->currency_symbol, ""));
	CHECK(!strcmp(lc->int_curr_symbol, ""));
	CHECK(!strcmp(lc->mon_decimal_point, ""));
	CHECK(!strcmp(lc->mon_thousands_sep, ""));
	CHECK(!strcmp(lc->mon_grouping, ""));
	CHECK(!strcmp(lc->positive_sign, ""));
	CHECK(!strcmp(lc->negative_sign, ""));
	CHECK(lc->frac_digits == CHAR_MAX);
	CHECK(lc->int_frac_digits == CHAR_MAX);
	CHECK(lc->p_sep_by_space == CHAR_MAX && lc->n_sep_by_space == CHAR_MAX);
	CHECK(lc->p_sign_posn == CHAR_MAX && lc->n_sign_posn == CHAR_MAX);

	/* The CRNCYSTR precondition: the two must agree for the item to
	 * have a specified value at all. */
	CHECK(lc->p_cs_precedes == lc->n_cs_precedes);
	CHECK(lc->p_cs_precedes == CHAR_MAX);
}

/* --------------------------------------------------------------------
 * LIVE.  YESEXPR and NOEXPR -- the two items whose consumer, not whose
 * data, is the interesting half.
 *
 * langinfo.h.html gives their meaning as "Affirmative response
 * expression" and "Negative response expression", both in category
 * LC_MESSAGES.  They are the only langinfo items that are not a string
 * to print but a string to *compile*: the specified use is
 *
 *     regcomp(&re, nl_langinfo(YESEXPR), REG_EXTENDED);
 *     if (regexec(&re, answer, 0, NULL, 0) == 0) ...
 *
 * Their POSIX-locale values are fixed by XBD Chapter 7, which is not
 * among the pages this audit consulted; they are given below as this
 * audit's reading and deliberately not quoted.  Nothing in this test
 * depends on that reading being exact -- what it asserts is that
 * spicule's regcomp()/regexec() handle expressions of that shape, i.e.
 * that the *consumer* of these two items works here today.
 *
 * That is the shape of this file's whole finding in miniature, which is
 * why it gets an assertion of its own: src/regex/regex.c is present and
 * audited (POSIX-COVERAGE.md group E), so the idiom above is blocked
 * not on a facility but on a name for two string literals.
 *
 * Safe in all three legs: anchor plus bracket expression, both inside
 * the subset test/posix-glob.c already asserts live.
 * ------------------------------------------------------------------ */
static void test_yesexpr_noexpr_have_a_working_consumer(void)
{
	regex_t yes, no;

	CHECK(regcomp(&yes, "^[yY]", REG_EXTENDED) == 0);
	CHECK(regcomp(&no, "^[nN]", REG_EXTENDED) == 0);

	CHECK(regexec(&yes, "yes", 0, NULL, 0) == 0);
	CHECK(regexec(&yes, "Y", 0, NULL, 0) == 0);
	CHECK(regexec(&yes, "no", 0, NULL, 0) == REG_NOMATCH);

	CHECK(regexec(&no, "no", 0, NULL, 0) == 0);
	CHECK(regexec(&no, "N", 0, NULL, 0) == 0);
	CHECK(regexec(&no, "yes", 0, NULL, 0) == REG_NOMATCH);

	regfree(&yes);
	regfree(&no);
}

/* --------------------------------------------------------------------
 * LIVE.  CODESET, and the converter <iconv.h> would wrap.
 *
 * langinfo.h.html gives CODESET as "Codeset name.", category LC_CTYPE.
 * It is what libc-test's t_setutf8() asks for, and its absence is why
 * test/libc-test-expected.txt marks `fgetwc-buffering` unverifiable on
 * this target.  spicule has exactly one answer to give -- src/internal/
 * utf.c's banner: "UTF-8 is the library's only character encoding: that
 * is what every char* a program hands in or gets back is" -- and no way
 * to give it.
 *
 * The assertions below establish that answer from outside, through the
 * multibyte layer, and in the same pass establish the three conditions
 * iconv.html makes *shall fail*:
 *
 *   MB_CUR_MAX == 4                       UTF-8's maximum sequence
 *   a 3-byte sequence decodes to U+4E2D   the encoding really is UTF-8
 *   (size_t)-1 with errno EILSEQ          iconv's "[EILSEQ] Input
 *                                         conversion stopped due to an
 *                                         input byte that does not
 *                                         belong to the input codeset."
 *   (size_t)-2 on a truncated sequence    iconv's "[EINVAL] Input
 *                                         conversion stopped due to an
 *                                         incomplete character or shift
 *                                         sequence at the end of the
 *                                         input buffer."
 *
 * Safe in all three legs: src/stdlib/mbrtowc.c is pure C (no ntdll),
 * and test/posix-wchar.c already asserts these exact returns live.
 * ------------------------------------------------------------------ */
static void test_codeset_is_utf8_and_the_converter_exists(void)
{
	mbstate_t st;
	wchar_t wc = 0;
	char buf[8];

	CHECK(MB_CUR_MAX == 4);

	memset(&st, 0, sizeof st);
	CHECK(mbrtowc(&wc, "\xe4\xb8\xad", 3, &st) == 3);	/* U+4E2D */
	CHECK(wc == 0x4e2d);
	CHECK(mbsinit(&st));

	/* and back out again -- the round trip iconv() would perform */
	memset(&st, 0, sizeof st);
	CHECK(wcrtomb(buf, (wchar_t)0x4e2d, &st) == 3);
	CHECK((unsigned char)buf[0] == 0xe4 && (unsigned char)buf[1] == 0xb8
	      && (unsigned char)buf[2] == 0xad);

	/* iconv's [EILSEQ]: a byte belonging to no UTF-8 sequence */
	memset(&st, 0, sizeof st);
	errno = 0;
	CHECK(mbrtowc(&wc, "\xff", 1, &st) == (size_t)-1);
	CHECK(errno == EILSEQ);

	/* iconv's [EINVAL]: an incomplete sequence at the end of input */
	memset(&st, 0, sizeof st);
	CHECK(mbrtowc(&wc, "\xe4\xb8", 2, &st) == (size_t)-2);
}

/* --------------------------------------------------------------------
 * LIVE.  LC_MESSAGES -- the category catopen() is specified against.
 *
 * catopen.html DESCRIPTION: "If the value of the oflag argument is 0,
 * the LANG environment variable is used to locate the catalog without
 * regard to the LC_MESSAGES category. If the oflag argument is
 * NL_CAT_LOCALE, the LC_MESSAGES category is used to locate the message
 * catalog".  src/misc/locale.c accepts LC_MESSAGES like every other
 * category, so the one piece of locale state a catalogue opener would
 * consult is already here and already answers "C".
 *
 * Asserted because it forecloses the "there is no LC_MESSAGES on this
 * target" version of the N/A argument, and because the rest of
 * catopen() is getenv() and open(), both present and audited elsewhere.
 * ------------------------------------------------------------------ */
static void test_lc_messages_category_exists(void)
{
	char *r = setlocale(LC_MESSAGES, "C");
	CHECK(r != NULL && !strcmp(r, "C"));

	r = setlocale(LC_MESSAGES, "POSIX");
	CHECK(r != NULL && !strcmp(r, "C"));

	r = setlocale(LC_MESSAGES, NULL);
	CHECK(r != NULL && !strcmp(r, "C"));
}

/* --------------------------------------------------------------------
 * LIVE.  The message-catalogue limits, which this tree already defines.
 *
 * limits.h.html "Other Invariant Values" -- "The <limits.h> header
 * shall define the following symbolic constants:" -- includes
 * "{NL_MSGMAX} Maximum message number. Minimum Acceptable Value:
 * 32 767", "{NL_SETMAX} Maximum set number. Minimum Acceptable Value:
 * 255", and "{NL_TEXTMAX} Maximum number of bytes in a message string.
 * Minimum Acceptable Value: {_POSIX2_LINE_MAX}".  All three are the
 * bounds on the msg_id, set_id and message string of catgets(), and
 * all three were added to include/limits.h by the group U sweep.
 *
 * So the arithmetic that describes a message catalogue is already in
 * this tree, and the interface that would make it mean anything is
 * not.  That is a sharper statement of the <nl_types.h> gap than any
 * prose, and it is why this runs rather than sitting in a comment: if
 * a later change removes these, the claim at the fence stops being
 * true and this test says so.
 * ------------------------------------------------------------------ */
static void test_message_catalogue_limits_exist_without_the_header(void)
{
	CHECK(NL_MSGMAX >= 32767);
	CHECK(NL_SETMAX >= 255);
	CHECK(NL_TEXTMAX >= _POSIX2_LINE_MAX);
}

/* ===================================================================
 * <langinfo.h> -- basedefs/langinfo.h.html
 * =================================================================== */

/* IMPLEMENTED (2026-08-25).  <langinfo.h> exists; see include/langinfo.h
   and src/misc/langinfo.c.  This case used to be fenced UNIMPL and read
   as a description of an absence; it now runs.

   langinfo.h.html DESCRIPTION, in full and verbatim for the four
   sentences that matter:

     "The <langinfo.h> header shall define the symbolic constants
      used to identify items of langinfo data (see nl_langinfo())."
     "The <langinfo.h> header shall define the locale_t type as
      described in <locale.h>."
     "The <langinfo.h> header shall define the nl_item type as
      described in <nl_types.h>."
     "The <langinfo.h> header shall define the following symbolic
      constants with type nl_item. The entries under Category
      indicate in which setlocale() category each item is defined."

   The table those last two sentences introduce has fifty-five entries,
   enumerated from the page rather than from memory, and they are
   exactly the array below: 49 LC_TIME + 2 LC_NUMERIC + 1 LC_MONETARY +
   1 LC_CTYPE + 2 LC_MESSAGES = 55.  The count is spelled out because a
   count is the easiest thing in an audit to get wrong.

   The values are implementation-defined; include/langinfo.h assigns
   them as a dense 0..54 range in the page's table order.  This test
   does not assert any value -- only that all fifty-five names exist,
   are pairwise distinct, and are answerable.

   ERA, ERA_D_FMT, ERA_D_T_FMT, ERA_T_FMT and ALT_DIGITS are
   deliberately included rather than omitted: the POSIX locale defines
   no era and no alternative digits, and an implementation with nothing
   to say still has to define the constant and answer for it.  Same
   reasoning group U applied to O_TTY_INIT.

   The data behind these names mostly predates them, which was the
   original finding and is still worth recording: of the 49 LC_TIME
   entries, 38 names are src/time/names.c's four const arrays and 6
   formats and affixes were open-coded in src/time/strftime.c's
   %c/%x/%X/%r/%p cases; the 2 LC_NUMERIC entries and the 1 LC_MONETARY
   entry are fields of src/misc/locale.c's __posix_lconv; the 1 LC_CTYPE
   entry is UTF-8; the 2 LC_MESSAGES entries are two literals with a
   working regcomp() behind them.  What was added was the naming, not
   the data -- which is why the four sibling tests that reach the same
   values through strftime(), localeconv(), regcomp() and mbrtowc()
   still run alongside this one and must keep agreeing with it. */
static void test_langinfo_h_item_constants(void)
{
	nl_item items[] = {
		CODESET,
		D_T_FMT, D_FMT, T_FMT, T_FMT_AMPM, AM_STR, PM_STR,
		DAY_1, DAY_2, DAY_3, DAY_4, DAY_5, DAY_6, DAY_7,
		ABDAY_1, ABDAY_2, ABDAY_3, ABDAY_4, ABDAY_5, ABDAY_6, ABDAY_7,
		MON_1, MON_2, MON_3, MON_4, MON_5, MON_6,
		MON_7, MON_8, MON_9, MON_10, MON_11, MON_12,
		ABMON_1, ABMON_2, ABMON_3, ABMON_4, ABMON_5, ABMON_6,
		ABMON_7, ABMON_8, ABMON_9, ABMON_10, ABMON_11, ABMON_12,
		ERA, ERA_D_FMT, ERA_D_T_FMT, ERA_T_FMT, ALT_DIGITS,
		RADIXCHAR, THOUSEP,
		YESEXPR, NOEXPR,
		CRNCYSTR
	};
	size_t i;

	CHECK(sizeof items / sizeof items[0] == 55);

	/* Every constant must exist, be distinct, and be answerable.
	 * "Answerable" is the half a bare #define would not give:
	 * nl_langinfo.html says an empty string comes back only "if item
	 * contains an invalid setting", and an item on this table is
	 * valid by being on it -- so a null pointer is never a legal
	 * answer for any of them. */
	for (i = 0; i < sizeof items / sizeof items[0]; i++) {
		size_t j;
		CHECK(nl_langinfo(items[i]) != NULL);
		for (j = 0; j < i; j++)
			CHECK(items[i] != items[j]);
	}

	/* The POSIX locale defines no era and no alternative digits. */
	CHECK(!strcmp(nl_langinfo(ERA), ""));
	CHECK(!strcmp(nl_langinfo(ERA_D_FMT), ""));
	CHECK(!strcmp(nl_langinfo(ERA_D_T_FMT), ""));
	CHECK(!strcmp(nl_langinfo(ERA_T_FMT), ""));
	CHECK(!strcmp(nl_langinfo(ALT_DIGITS), ""));
}

/* IMPLEMENTED (2026-08-25).  nl_langinfo() -- nl_langinfo.html.
   src/misc/langinfo.c.

   SYNOPSIS, verbatim:
     #include <langinfo.h>
     char *nl_langinfo(nl_item item);
     char *nl_langinfo_l(nl_item item, locale_t locale);

   DESCRIPTION: "The nl_langinfo() and nl_langinfo_l() functions
   shall return a pointer to a string containing information
   relevant to the particular language or cultural area defined
   in the current locale, or in the locale represented by locale,
   respectively (see <langinfo.h>)."

   RETURN VALUE: "In a locale where langinfo data is not defined,
   these functions shall return a pointer to the corresponding
   string in the POSIX locale. In all locales, these functions
   shall return a pointer to an empty string if item contains an
   invalid setting."  And: "The application shall not modify the
   string returned."

   ERRORS: "No errors are defined."  So nothing below inspects
   errno -- there is nothing for it to inspect.

   Where each expected value comes from, since this matters more
   than the code:

    - The four composites and the day/month/AM/PM strings are
      strftime.html's C-or-POSIX-locale list, quoted at
      test_lc_time_data_is_present_without_an_accessor above, and
      each is also asserted live there through strftime().
    - RADIXCHAR and THOUSEP are localeconv()'s decimal_point and
      thousands_sep, asserted live in
      test_lc_numeric_and_lc_monetary_data_without_an_accessor.
    - CRNCYSTR is "" because the local currency symbol is the
      empty string, which langinfo.h.html permits explicitly:
      "If the local currency symbol is the empty string,
      implementations may return the empty string ("")."
    - CODESET is "UTF-8" because that is the only encoding this
      library has (src/internal/utf.c's banner); the *name* is
      implementation-defined, and this test fixes spicule's choice
      rather than quoting a requirement.
    - YESEXPR and NOEXPR come from XBD Chapter 7, which this
      audit did not have; see the note at
      test_yesexpr_noexpr_have_a_working_consumer.  They are
      asserted here as spicule's chosen answer, not as a quoted one.

   So this case is not a guess about what the answers would be.  It is
   the same set of answers this file already checks through other
   interfaces, asked for by their POSIX names -- and the cross-check
   against strftime() at the end is what makes that a test rather than
   a restatement. */
static void test_nl_langinfo_posix_locale_values(void)
{
	CHECK(!strcmp(nl_langinfo(CODESET), "UTF-8"));

	CHECK(!strcmp(nl_langinfo(D_T_FMT), "%a %b %e %H:%M:%S %Y"));
	CHECK(!strcmp(nl_langinfo(D_FMT), "%m/%d/%y"));
	CHECK(!strcmp(nl_langinfo(T_FMT), "%H:%M:%S"));
	CHECK(!strcmp(nl_langinfo(T_FMT_AMPM), "%I:%M:%S %p"));
	CHECK(!strcmp(nl_langinfo(AM_STR), "AM"));
	CHECK(!strcmp(nl_langinfo(PM_STR), "PM"));

	CHECK(!strcmp(nl_langinfo(DAY_1), "Sunday"));
	CHECK(!strcmp(nl_langinfo(DAY_7), "Saturday"));
	CHECK(!strcmp(nl_langinfo(ABDAY_1), "Sun"));
	CHECK(!strcmp(nl_langinfo(ABDAY_7), "Sat"));
	CHECK(!strcmp(nl_langinfo(MON_1), "January"));
	CHECK(!strcmp(nl_langinfo(MON_12), "December"));
	CHECK(!strcmp(nl_langinfo(ABMON_1), "Jan"));
	CHECK(!strcmp(nl_langinfo(ABMON_12), "Dec"));

	CHECK(!strcmp(nl_langinfo(RADIXCHAR), "."));
	CHECK(!strcmp(nl_langinfo(THOUSEP), ""));
	CHECK(!strcmp(nl_langinfo(YESEXPR), "^[yY]"));
	CHECK(!strcmp(nl_langinfo(NOEXPR), "^[nN]"));
	CHECK(!strcmp(nl_langinfo(CRNCYSTR), ""));

	/* "an invalid setting": an empty string, never a null. */
	CHECK(nl_langinfo((nl_item)-1) != NULL);
	CHECK(!strcmp(nl_langinfo((nl_item)-1), ""));

	/* The day and month tables must agree with the ones strftime() is
	 * already using, item for item -- strftime.html defines %A as
	 * "One of Sunday, Monday, ..., Saturday." and %a as "The first
	 * three characters of %A.", which is the same table
	 * nl_langinfo(DAY_n)/nl_langinfo(ABDAY_n) must report.
	 * test_lc_time_data_is_present_without_an_accessor asserts the
	 * strftime half of this today. */
	{
		struct tm tm;
		char buf[64];
		int i;

		memset(&tm, 0, sizeof tm);
		tm.tm_mday = 1; tm.tm_year = 100;
		for (i = 0; i < 7; i++) {
			tm.tm_wday = i;
			CHECK(strftime(buf, sizeof buf, "%A", &tm) != 0);
			CHECK(!strcmp(buf, nl_langinfo(DAY_1 + i)));
			CHECK(strftime(buf, sizeof buf, "%a", &tm) != 0);
			CHECK(!strcmp(buf, nl_langinfo(ABDAY_1 + i)));
		}
		tm.tm_wday = 0;
		for (i = 0; i < 12; i++) {
			tm.tm_mon = i;
			CHECK(strftime(buf, sizeof buf, "%B", &tm) != 0);
			CHECK(!strcmp(buf, nl_langinfo(MON_1 + i)));
			CHECK(strftime(buf, sizeof buf, "%b", &tm) != 0);
			CHECK(!strcmp(buf, nl_langinfo(ABMON_1 + i)));
		}
	}
}

/* IMPLEMENTED (2026-08-25).  nl_langinfo_l() -- nl_langinfo.html, the
   locale_t form.  src/misc/langinfo.c.

   Recorded as a case of its own rather than folded into the one above
   because its acceptance criterion is different and strictly larger:
   it takes a locale_t and must answer out of *that* locale rather than
   the current one.  This tree has the whole locale-object API to hand
   it -- newlocale(), duplocale(), freelocale(), uselocale() and
   LC_GLOBAL_LOCALE, all in src/misc/locale.c and audited in
   test/posix-locale.c -- and every handle it can produce is the same
   immutable C locale, so the two forms' answers must coincide.  That
   coincidence is what the assertions below check, and it is also why
   this was the cheaper of the two to implement, not the harder one.
   src/misc/langinfo.c states the same thing from the other side: it
   ignores the locale_t because there is only one locale to dispatch
   to, and says so rather than implying a dispatch it does not do.

   LC_GLOBAL_LOCALE is deliberately NOT passed, and saying so is
   the point of mentioning it: "The behavior is undefined if the
   locale argument to nl_langinfo_l() is the special locale object
   LC_GLOBAL_LOCALE or is not a valid locale object handle."  The
   implementation must not "helpfully" accept it, and a test must not
   require that it does.

   One clause this case deliberately does not test, because it cannot
   be tested here and pretending otherwise would be worse than
   recording it: "The nl_langinfo() function need not be thread-safe"
   -- and, by RATIONALE, nl_langinfo_l() must be.  spicule has no
   threads (pthread.h is a recorded absence), so there is no second
   thread to observe the difference from.  It is noted because the
   buffer choice is constrained by a clause no test here will catch;
   src/misc/langinfo.c satisfies it by returning only literals and
   pointers into const tables, never a shared buffer. */
static void test_nl_langinfo_l(void)
{
	locale_t loc = newlocale(LC_ALL_MASK, "C", (locale_t)0);

	CHECK(loc != (locale_t)0);
	if (loc == (locale_t)0) return;

	CHECK(!strcmp(nl_langinfo_l(CODESET, loc), "UTF-8"));
	CHECK(!strcmp(nl_langinfo_l(D_T_FMT, loc), "%a %b %e %H:%M:%S %Y"));
	CHECK(!strcmp(nl_langinfo_l(DAY_1, loc), "Sunday"));
	CHECK(!strcmp(nl_langinfo_l(RADIXCHAR, loc), "."));
	CHECK(!strcmp(nl_langinfo_l(YESEXPR, loc), "^[yY]"));

	/* Only one locale exists here, so the two forms must agree. */
	CHECK(!strcmp(nl_langinfo_l(D_FMT, loc), nl_langinfo(D_FMT)));
	CHECK(!strcmp(nl_langinfo_l(ABMON_12, loc), nl_langinfo(ABMON_12)));

	/* "an invalid setting" behaves the same way through either form. */
	CHECK(!strcmp(nl_langinfo_l((nl_item)-1, loc), ""));

	freelocale(loc);
}

/* ===================================================================
 * <nl_types.h> -- basedefs/nl_types.h.html, functions/catopen.html,
 * functions/catgets.html, functions/catclose.html
 * =================================================================== */

/* IMPLEMENTED (2026-08-25).  <nl_types.h> and the message-catalogue
   trio exist; see include/nl_types.h and src/misc/catgets.c.

   nl_types.h.html DESCRIPTION requires, verbatim: "The <nl_types.h>
   header shall define at least the following types:" -- nl_catd, "Used
   by the message catalog functions catopen(), catgets(), and
   catclose() to identify a catalog descriptor.", and nl_item, "Used by
   nl_langinfo() to identify items of langinfo data. Values of objects
   of type nl_item are defined in <langinfo.h>." -- then "The
   <nl_types.h> header shall define at least the following symbolic
   constants:", NL_SETD and NL_CAT_LOCALE, and then the three
   prototypes:

       int       catclose(nl_catd);
       char     *catgets(nl_catd, int, int, const char *);
       nl_catd   catopen(const char *, int);

   nl_item is required by BOTH this header and <langinfo.h> ("shall
   define the nl_item type as described in <nl_types.h>"), so the two
   were coupled and are satisfied together: both typedefs live in
   bits/alltypes.h behind __NEED_ guards and neither header defines
   them itself.

   WHAT THIS CASE CAN AND CANNOT REACH.  POSIX designed this interface
   so that an implementation with no catalogues installed is still
   conforming and -- more to the point -- so that an application using
   it still works on one:

     - catopen.html's ENOENT ("The message catalog does not exist or
       the name argument points to an empty string.") is under "The
       catopen() function may fail if:".  Every listed condition is a
       *may fail*.  Failing for want of a catalogue is legal.
     - catgets.html DESCRIPTION: "The s argument points to a default
       message string which shall be returned by catgets() if it
       cannot retrieve the identified message."  RETURN VALUE: "If the
       call is unsuccessful for any reason, s shall be returned and
       errno shall be set to indicate the error."  So the program's
       own compiled-in default string is what comes back, and the
       caller is correct without a catalogue.
     - catclose.html RETURN VALUE: "Upon successful completion,
       catclose() shall return 0; otherwise, -1 shall be returned, and
       errno set to indicate the error."

   There is no gencat in this tree, so nothing installs a catalogue
   and this case exercises only the no-catalogue path.  That is why
   test_catgets_reads_a_catalogue() below exists: it writes a
   catalogue byte by byte and reads it back, so the parser, the two
   binary searches and the not-in-catalogue path are all covered by
   something rather than by the observation that a lookup failed.
   Without it this case would pass on a tree where catopen() was a
   one-line `return (nl_catd)-1`, which is exactly the outcome the
   fence it replaces was warning about.

   The assertions below are shaped by two clauses that forbid the
   obvious shortcuts.  They do not assert a value for NL_SETD: "The
   value of NL_SETD is implementation-defined."  And they do not call
   catgets() on a failed descriptor, however tempting that is as a way
   to check the default-string contract without a catalogue: "The
   results are undefined if catd is not a value returned by catopen()
   for a message catalog still open in the process." */
static void test_nl_types_h_catalogue_access(void)
{
	static const char deflt[] = "compiled-in default";
	nl_catd cd;
	int set_id = NL_SETD;

	/* NL_CAT_LOCALE is defined by its role rather than its value:
	 * the oflag that makes catalogue selection follow LC_MESSAGES
	 * rather than LANG.  Only its existence is assertable. */
	cd = catopen("posix-msgcat-no-such-catalog", NL_CAT_LOCALE);

	if (cd == (nl_catd)-1) {
		/* Permitted, and the expected outcome on this platform.
		 * The *shall* here is only that errno was set. */
		CHECK(errno != 0);
	} else {
		/* If a catalogue did open, the message ids below are not
		 * in it, so catgets() must hand back the pointer it was
		 * given -- "s shall be returned", i.e. that pointer, not
		 * a copy of it. */
		char *m = catgets(cd, set_id, 1, deflt);
		CHECK(m == deflt);
		m = catgets(cd, NL_SETMAX, NL_MSGMAX, deflt);
		CHECK(m == deflt);
		CHECK(catclose(cd) == 0);
	}

	/* "the name argument points to an empty string" -- again a
	 * *may fail*, so the assertion is on the contract either way:
	 * a descriptor that opens must close. */
	errno = 0;
	cd = catopen("", NL_CAT_LOCALE);
	if (cd == (nl_catd)-1)
		CHECK(errno != 0);
	else
		CHECK(catclose(cd) == 0);

	/* oflag 0 selects LANG rather than LC_MESSAGES; both spellings
	 * must be accepted arguments. */
	cd = catopen("posix-msgcat-no-such-catalog", 0);
	if (cd != (nl_catd)-1)
		CHECK(catclose(cd) == 0);
}

/* -------------------------------------------------------------------
 * catgets() against a catalogue that actually exists.
 *
 * The case above can only ever watch catopen() fail, because nothing
 * installs a message catalogue on this platform and there is no gencat
 * in this tree to build one.  A test that only watches a lookup fail
 * cannot tell a working implementation from `return (nl_catd)-1;`, so
 * this one builds a catalogue itself, in the byte format
 * src/misc/catgets.c documents and reads, and then asks for messages
 * out of it through the public interface.
 *
 * That format is not POSIX's: POSIX standardises gencat's *source*
 * text and says nothing about the compiled bytes, so the layout is
 * spicule's choice (it is musl's, so that catalogues are portable
 * between the two).  This test therefore fixes an implementation
 * detail on purpose, and is the one place in this file that does.  If
 * the format is ever changed, this is what has to change with it --
 * which is the point: the alternative is a reader nothing exercises.
 *
 * What is asserted here is entirely POSIX, though:
 *   - "If the identified message is retrieved successfully, catgets()
 *     shall return a pointer to an internal buffer area containing the
 *     null-terminated message string."
 *   - "If the call is unsuccessful for any reason, s shall be returned
 *     and errno shall be set to indicate the error." -- s, the pointer
 *     the caller passed, and "[ENOMSG] The message identified by
 *     set_id and msg_id is not in the message catalog."
 *   - "Upon successful completion, catclose() shall return 0".
 *   - catopen.html: "If name contains a '/', then name specifies a
 *     pathname for the message catalog." -- which is how this
 *     catalogue is reached without touching NLSPATH.
 * ------------------------------------------------------------------- */
static void put32(unsigned char *p, unsigned long v)
{
	p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)v;
}

static void test_catgets_reads_a_catalogue(void)
{
	/* Two sets: set 1 with messages 1 and 5, set 3 with message 2.
	 * Ids are deliberately non-contiguous and the sets are in
	 * ascending order, which is what the reader's binary searches
	 * require and what a generator has to produce. */
	static const char *const strs[3] = { "first", "fifth", "second-set" };
	unsigned char cat[256];
	size_t hdr = 20, nsets = 2, nmsgs = 3;
	size_t setoff = 0, msgoff = nsets * 12, stroff = msgoff + nmsgs * 12;
	size_t pool = stroff, i, off, total;
	unsigned char *m = cat;
	const char deflt[] = "compiled-in default";
	char path[] = "posix-msgcat-tmp.cat";
	char rel[64];
	nl_catd cd;
	FILE *f;
	char *got;

	memset(cat, 0, sizeof cat);

	/* set records: set_id, message count, first message index */
	put32(m + hdr + setoff + 0, 1);  put32(m + hdr + setoff + 4, 2);
	put32(m + hdr + setoff + 8, 0);
	put32(m + hdr + setoff + 12, 3); put32(m + hdr + setoff + 16, 1);
	put32(m + hdr + setoff + 20, 2);

	/* message records: msg_id, length, offset into the string pool */
	off = 0;
	{
		static const int ids[3] = { 1, 5, 2 };
		for (i = 0; i < 3; i++) {
			size_t l = strlen(strs[i]);
			put32(m + hdr + msgoff + i * 12 + 0, (unsigned long)ids[i]);
			put32(m + hdr + msgoff + i * 12 + 4, (unsigned long)l);
			put32(m + hdr + msgoff + i * 12 + 8, (unsigned long)off);
			memcpy(m + hdr + pool + off, strs[i], l + 1);
			off += l + 1;
		}
	}
	total = hdr + stroff + off;

	put32(m + 0, 0xff88ff89UL);
	put32(m + 4, (unsigned long)nsets);
	put32(m + 8, (unsigned long)(total - hdr));
	put32(m + 12, (unsigned long)msgoff);
	put32(m + 16, (unsigned long)stroff);

	f = fopen(path, "wb");
	CHECK(f != NULL);
	if (!f) return;
	CHECK(fwrite(cat, 1, total, f) == total);
	CHECK(fclose(f) == 0);

	/* A name with a '/' is a pathname, so this reaches the file just
	 * written without depending on NLSPATH or on the working
	 * directory being on any search path. */
	snprintf(rel, sizeof rel, "./%s", path);
	cd = catopen(rel, NL_CAT_LOCALE);
	CHECK(cd != (nl_catd)-1);
	if (cd != (nl_catd)-1) {
		got = catgets(cd, 1, 1, deflt);
		CHECK(got != deflt);
		CHECK(!strcmp(got, "first"));

		got = catgets(cd, 1, 5, deflt);
		CHECK(!strcmp(got, "fifth"));

		got = catgets(cd, 3, 2, deflt);
		CHECK(!strcmp(got, "second-set"));

		/* Not in the catalogue: "s shall be returned" -- that
		 * pointer, not a copy -- "and errno shall be set". */
		errno = 0;
		got = catgets(cd, 1, 2, deflt);
		CHECK(got == deflt);
		CHECK(errno == ENOMSG);

		errno = 0;
		got = catgets(cd, 2, 1, deflt);
		CHECK(got == deflt);
		CHECK(errno == ENOMSG);

		CHECK(catclose(cd) == 0);
	}

	/* A file that is not a catalogue must not open as one. */
	f = fopen(path, "wb");
	CHECK(f != NULL);
	if (f) {
		CHECK(fwrite("not a catalogue at all", 1, 22, f) == 22);
		CHECK(fclose(f) == 0);
		errno = 0;
		cd = catopen(rel, NL_CAT_LOCALE);
		CHECK(cd == (nl_catd)-1);
		CHECK(errno != 0);
		if (cd != (nl_catd)-1) catclose(cd);
	}

	remove(path);
}

/* ===================================================================
 * <monetary.h> -- basedefs/monetary.h.html, functions/strfmon.html
 * =================================================================== */

/* IMPLEMENTED (2026-08-25).  <monetary.h>, strfmon() and strfmon_l()
   exist; see include/monetary.h and src/misc/strfmon.c.

   monetary.h.html DESCRIPTION, verbatim: "The <monetary.h> header
   shall define the locale_t type as described in <locale.h>.",
   "The <monetary.h> header shall define the size_t type as
   described in <stddef.h>.", "The <monetary.h> header shall
   define the ssize_t type as described in <sys/types.h>." -- and
   the two prototypes:

       ssize_t  strfmon(char *restrict, size_t, const char *restrict, ...);
       ssize_t  strfmon_l(char *restrict, size_t, locale_t,
                    const char *restrict, ...);

   strfmon.html DESCRIPTION: "The strfmon() function shall place
   characters into the array pointed to by s as controlled by the
   string pointed to by format. No more than maxsize bytes are
   placed into the array."  A conversion specification is "A '%'
   character", "Optional flags", "Optional field width", "Optional
   left precision", "Optional right precision", "A required
   conversion specifier character that determines the conversion to
   be performed".  And: "The strfmon_l() function shall be
   equivalent to the strfmon() function, except that the locale data
   used is from the locale represented by locale."

   RETURN VALUE: "If the total number of resulting bytes including
   the terminating null byte is not more than maxsize, these
   functions shall return the number of bytes placed into the
   array pointed to by s, not including the terminating NUL
   character. Otherwise, -1 shall be returned, the contents of the
   array are unspecified, and errno shall be set to indicate the
   error."  ERRORS, *shall fail*: "[E2BIG] Conversion stopped due
   to lack of space in the buffer."

   WHY THE ASSERTIONS ARE ABOUT MECHANICS AND NOT ABOUT MONEY.  "The
   LC_MONETARY category of the current locale affects the behavior of
   this function including the monetary radix character ..., the
   grouping separator, the currency symbols, and formats" -- and this
   library's entire LC_MONETARY block is the "not available" value,
   which test_lc_numeric_and_lc_monetary_data_without_an_accessor
   asserts live.  So %n and %i here differ from each other, and from a
   plain "%.2f", by very little.

   Everything the page specifies *other* than the field values is
   locale-independent mechanics, and all of it is testable in the C
   locale: the "=f" numeric fill character, the '^'
   grouping-suppression flag, the '+' and '(' negative-style flags,
   '!' suppressing the currency symbol, '-' left justification ("This
   flag shall be ignored unless a field width ... is specified"), the
   field width, the left precision "#n" ("This option causes an amount
   to be formatted as if it has the number of digits specified by n"),
   the right precision ".p" ("If the value of the right precision p is
   0, no radix character appears. ... The amount being formatted is
   rounded to the specified number of digits prior to formatting"),
   the "%%" rule ("Convert to a '%'; no argument is converted. The
   entire conversion specification shall be %%.") and the [E2BIG]
   truncation rule.  Those are what is asserted below, because those
   are what can actually be wrong here.  Where the page leaves the
   exact spelling open -- the '(' style interacts with the alignment
   padding described under Left Precision, which this test does not
   request -- the assertion is structural rather than a literal
   comparison.

   WHERE THIS TEST IS DELIBERATELY SILENT.  src/misc/strfmon.c has to
   choose a fallback everywhere the POSIX locale says "not available"
   -- the radix character, the default right precision, the negative
   sign, symbol placement -- and those choices are spicule's, not the
   standard's.  This file asserts a value for exactly one of them (the
   default right precision, implicitly, via "%n" of 1234.567 still
   containing "1234"), and states the rest as the source's business.
   It also does NOT assert the alignment clause "any characters
   appearing before or after the number ... are padded as necessary
   with <space> characters to make their positive and negative formats
   an equal length", which src/misc/strfmon.c records as an
   implemented-narrowly shortfall.  That is a known gap, named in the
   source, not something this test overlooked. */
static void test_strfmon_posix_locale(void)
{
	char buf[64];
	ssize_t n;

	/* "%%" is a literal '%'; plain characters "are simply copied to
	 * the output stream". */
	n = strfmon(buf, sizeof buf, "a%%b");
	CHECK(n == 3 && !strcmp(buf, "a%b"));

	/* The C locale has no currency symbol and no grouping, so the
	 * national format is the number itself. */
	n = strfmon(buf, sizeof buf, "%n", 1234.567);
	CHECK(n > 0 && strstr(buf, "1234") != NULL);

	/* Right precision: rounded before formatting, and p == 0 means
	 * no radix character at all.  frac_digits is {CHAR_MAX} ("not
	 * available") here, so this is the only thing that can fix the
	 * number of decimals in this locale. */
	n = strfmon(buf, sizeof buf, "%.0n", 1234.567);
	CHECK(n == 4 && !strcmp(buf, "1235"));

	/* Field width, and the '-' flag's "padded to the right". */
	n = strfmon(buf, sizeof buf, "%10.0n", 42.0);
	CHECK(n == 10 && !strcmp(buf, "        42"));
	n = strfmon(buf, sizeof buf, "%-10.0n|", 42.0);
	CHECK(n == 11 && !strcmp(buf, "42        |"));

	/* The negative sign, which is the one LC_MONETARY fallback in
	 * src/misc/strfmon.c that would be dangerous to get wrong.  The
	 * POSIX locale's negative_sign is "" (localeconv() above asserts
	 * exactly that), so honouring it literally would render -42 as
	 * "42" -- a plausible wrong answer a caller cannot detect.  A
	 * '-' is substituted instead, and that substitution is asserted
	 * here rather than left to the '(' case below, which suppresses
	 * the sign string entirely and so cannot see it.  positive_sign
	 * IS honoured as empty, which the "42" case pins down. */
	n = strfmon(buf, sizeof buf, "%.0n", -42.0);
	CHECK(n == 3 && !strcmp(buf, "-42"));
	n = strfmon(buf, sizeof buf, "%.2n", -0.5);
	CHECK(n == 5 && !strcmp(buf, "-0.50"));
	n = strfmon(buf, sizeof buf, "%10.0n", -42.0);
	CHECK(n == 10 && !strcmp(buf, "       -42"));

	/* "If '(' is specified, negative amounts are enclosed within
	 * parentheses." */
	n = strfmon(buf, sizeof buf, "%(.0n", -42.0);
	CHECK(n > 0);
	CHECK(strchr(buf, '(') != NULL && strchr(buf, ')') != NULL);
	CHECK(strstr(buf, "42") != NULL);
	CHECK(strchr(buf, '-') == NULL);

	/* [E2BIG]: the result including the terminating null exceeds
	 * maxsize.  The array contents are then unspecified, so nothing
	 * is asserted about buf. */
	errno = 0;
	n = strfmon(buf, 4, "%.0n", 123456.0);
	CHECK(n == -1);
	CHECK(errno == E2BIG);

	/* strfmon_l() over the only locale this library has must agree.
	 * LC_GLOBAL_LOCALE is deliberately not passed: "The behavior is
	 * undefined if the locale argument to strfmon_l() is the special
	 * locale object LC_GLOBAL_LOCALE or is not a valid locale object
	 * handle." */
	{
		locale_t loc = newlocale(LC_ALL_MASK, "C", (locale_t)0);
		char lbuf[64];
		CHECK(loc != (locale_t)0);
		if (loc != (locale_t)0) {
			CHECK(strfmon_l(lbuf, sizeof lbuf, loc, "%.0n", 42.0) == 2);
			CHECK(!strcmp(lbuf, "42"));
			freelocale(loc);
		}
	}
}

#if SPICULE_TEST(PASS, posix_msgcat_strfmon_alignment_pads_to_equal_length) /* strfmon() pads the positive
    left-precision format to the length of the negative one.

	strfmon.html, under Left Precision, verbatim: "To ensure
	alignment, any characters appearing before or after the number in
	the formatted output such as currency or sign symbols are padded
	as necessary with <space> characters to make their positive and
	negative formats an equal length."

	The alignment sentence occurs under the Left Precision section and
	applies when #n is present.  The old BUG fixture omitted #n and was
	therefore testing an unrequired behavior; ordinary %.0n is correctly
	unpadded.  These corrected calls use #2 and require the automatic
	equalisation when no field width is given.  In this locale the
	currency symbol and the positive sign
	are both the empty string and the negative sign falls back to
	"-" (src/misc/strfmon.c explains why it does not honour the
	POSIX locale's empty negative_sign literally), so the two formats
	differ by exactly the one byte of that '-' -- or by the two bytes
	of "()" under the '(' flag.  Everything else on the page is
	implemented; see test_strfmon_posix_locale() above, which passes.

	Fenced rather than left as a comment in src/misc/strfmon.c, which
	is where it started.  A comment is not checked and a fence is: two
	fence comments in this tree were found stale tonight, each written
	accurately and each rotted when the thing it described changed
	underneath it.  A BUG fence asserts that the gap is real today AND
	trips when it closes, which a note to a reader who may never
	arrive does not.

	Observed today: compiles, runs, and the lengths differ. */
static void test_strfmon_alignment_pads_to_equal_length(void)
{
	char pos[64], neg[64];

	/* The default '+' style.  positive_sign is "" and the negative
	 * sign is one byte, so the positive format must be padded by one
	 * <space> to match. */
	CHECK(strfmon(pos, sizeof pos, "%#2.0n", 42.0) > 0);
	CHECK(strfmon(neg, sizeof neg, "%#2.0n", -42.0) > 0);
	CHECK(strlen(pos) == strlen(neg));

	/* The '(' style.  "If '(' is specified, negative amounts are
	 * enclosed within parentheses." -- two bytes to match, not one,
	 * which is why this is asserted separately rather than inferred
	 * from the case above. */
	CHECK(strfmon(pos, sizeof pos, "%(#2.0n", 42.0) > 0);
	CHECK(strfmon(neg, sizeof neg, "%(#2.0n", -42.0) > 0);
	CHECK(strlen(pos) == strlen(neg));

	/* The recourse, asserted so the fence cannot be over-read: with a
	 * field width both formats already occupy the same columns, and
	 * that half works today. */
	CHECK(strfmon(pos, sizeof pos, "%10.0n", 42.0) == 10);
	CHECK(strfmon(neg, sizeof neg, "%10.0n", -42.0) == 10);
}
#endif

/* ===================================================================
 * <iconv.h> -- basedefs/iconv.h.html, functions/iconv_open.html,
 * functions/iconv.html, functions/iconv_close.html
 * =================================================================== */

/* IMPLEMENTED (2026-08-25).  <iconv.h> and the three codeset-
   conversion functions exist; see include/iconv.h and
   src/misc/iconv.c.  This was the last of the four headers this file
   audits.

   iconv.h.html DESCRIPTION, verbatim: "The <iconv.h> header shall
   define the following types:" -- iconv_t, "Identifies the
   conversion from one codeset to another.", and size_t -- then
   the three prototypes:

       size_t  iconv(iconv_t, char **restrict, size_t *restrict,
                   char **restrict, size_t *restrict);
       int     iconv_close(iconv_t);
       iconv_t iconv_open(const char *, const char *);

   iconv.html DESCRIPTION: "The iconv() function shall convert the
   sequence of characters from one codeset, in the array specified
   by inbuf, into a sequence of corresponding characters in
   another codeset, in the array specified by outbuf."  The three
   stop conditions, verbatim: "If a sequence of input bytes does
   not form a valid character in the specified codeset, conversion
   shall stop after the previous successfully converted character.
   If the input buffer ends with an incomplete character or shift
   sequence, conversion shall stop after the previous successfully
   converted bytes. If the output buffer is not large enough to
   hold the entire converted input, conversion shall stop just
   prior to the input bytes that would cause the output buffer to
   overflow."  And: "The variable pointed to by inbuf shall be
   updated to point to the byte following the last byte
   successfully used in the conversion."

   RETURN VALUE: "The iconv() function shall update the variables
   pointed to by the arguments to reflect the extent of the
   conversion and return the number of non-identical conversions
   performed."  ERRORS, *shall fail*: "[EILSEQ] Input conversion
   stopped due to an input byte that does not belong to the input
   codeset.", "[E2BIG] Input conversion stopped due to lack of
   space in the output buffer.", "[EINVAL] Input conversion
   stopped due to an incomplete character or shift sequence at the
   end of the input buffer."

   iconv_open.html: "Settings of fromcode and tocode and their
   permitted combinations are implementation-defined." -- so the
   particular codeset names below are spicule's choice, not a
   requirement, and this comment says which is which.  RETURN VALUE:
   "Otherwise, iconv_open() shall return (iconv_t)-1 and set errno
   to indicate the error."  iconv_close.html RETURN VALUE: "Upon
   successful completion, 0 shall be returned; otherwise, -1 shall
   be returned and errno set to indicate the error."

   WHAT IT IS BUILT ON, and one correction worth keeping.
   test/POSIX-HEADER-INVENTORY.md pointed at src/internal/utf.c.
   Re-checked 2026-08-25, that was the wrong file and
   src/misc/iconv.c does not use it: utf.c converts whole strings (via
   ntdll's RtlUTF8ToUnicodeN / RtlUnicodeToUTF8N at the time, an
   in-tree hand-rolled codec since -- see tools/ntdll.def's history)
   and mallocs its result, so it has no conversion descriptor, no
   incremental pointer advance, no resumable state and no
   partial-output case -- none of the four things the clauses above
   are about.  The decoder and encoder used here are written out in
   pure C instead, which also keeps this working identically on the
   native asan build.

   The three assertions that carry the most weight are the ones about
   where the pointers are LEFT, not about what came out: after EILSEQ,
   after EINVAL and after E2BIG the input pointer must sit AT the
   character that could not be converted, never past it.  That is what
   makes a resumed call correct, and it is the property a converter
   that merely returns the right bytes can still get wrong.

   The conversion exercised is UTF-8 <-> UTF-16LE because that is
   what this library already performs internally for every path it
   hands to ntdll, and the one a caller on this platform most
   needs a portable name for. */
static void test_iconv_open_convert_close(void)
{
	char in[] = "A\xe4\xb8\xad";	/* 'A', then U+4E2D */
	char out[16];
	char *ip, *op;
	size_t il, ol, r;
	iconv_t cd;

	cd = iconv_open("UTF-16LE", "UTF-8");
	CHECK(cd != (iconv_t)-1);
	if (cd == (iconv_t)-1) return;

	ip = in; il = 4; op = out; ol = sizeof out;
	r = iconv(cd, &ip, &il, &op, &ol);
	CHECK(r != (size_t)-1);
	CHECK(r == 0);			/* no non-identical conversions */
	CHECK(il == 0);			/* "the value pointed to by
					 * inbytesleft shall be 0" */
	CHECK((size_t)(op - out) == 4);	/* two UTF-16 code units */
	CHECK(ol == sizeof out - 4);
	CHECK((unsigned char)out[0] == 'A' && (unsigned char)out[1] == 0x00);
	CHECK((unsigned char)out[2] == 0x2d && (unsigned char)out[3] == 0x4e);

	/* [EILSEQ].  "conversion shall stop after the previous
	 * successfully converted character" -- there is none, so the
	 * pointers must be left AT the offending byte, not past it. */
	{
		char bad[] = "\xff";
		ip = bad; il = 1; op = out; ol = sizeof out;
		errno = 0;
		CHECK(iconv(cd, &ip, &il, &op, &ol) == (size_t)-1);
		CHECK(errno == EILSEQ);
		CHECK(ip == bad && il == 1);
	}

	/* [EINVAL]: "the input buffer ends with an incomplete character
	 * or shift sequence". */
	{
		char part[] = "\xe4\xb8";
		ip = part; il = 2; op = out; ol = sizeof out;
		errno = 0;
		CHECK(iconv(cd, &ip, &il, &op, &ol) == (size_t)-1);
		CHECK(errno == EINVAL);
	}

	/* [E2BIG]: "conversion shall stop just prior to the input bytes
	 * that would cause the output buffer to overflow" -- the 'A'
	 * fits in two output bytes, U+4E2D does not. */
	{
		ip = in; il = 4; op = out; ol = 2;
		errno = 0;
		CHECK(iconv(cd, &ip, &il, &op, &ol) == (size_t)-1);
		CHECK(errno == E2BIG);
		CHECK(il == 3);
		CHECK(ip == in + 1);
	}

	/* "the conversion descriptor cd is placed into its initial shift
	 * state by a call for which inbuf is a null pointer".  UTF-8 and
	 * UTF-16LE are not state-dependent, so nothing is emitted; the
	 * call must still succeed. */
	op = out; ol = sizeof out;
	CHECK(iconv(cd, NULL, NULL, &op, &ol) != (size_t)-1);

	CHECK(iconv_close(cd) == 0);

	/* A conversion no implementation is required to support, and
	 * this one would not: "[EINVAL] The conversion specified by
	 * fromcode and tocode is not supported by the implementation."
	 * (a *may fail*, so the -1 is the assertable half). */
	errno = 0;
	CHECK(iconv_open("NO-SUCH-CODESET", "UTF-8") == (iconv_t)-1);

	/* The round trip, which is what libc-test's iconv-roundtrips
	 * wants. */
	{
		iconv_t back = iconv_open("UTF-8", "UTF-16LE");
		char again[16];
		CHECK(back != (iconv_t)-1);
		if (back != (iconv_t)-1) {
			ip = out; il = 4; op = again; ol = sizeof again;
			CHECK(iconv(back, &ip, &il, &op, &ol) != (size_t)-1);
			CHECK((size_t)(op - again) == 4);
			CHECK(!memcmp(again, in, 4));
			CHECK(iconv_close(back) == 0);
		}
	}
}

int main(void)
{
	test_lc_time_data_is_present_without_an_accessor();
	test_lc_numeric_and_lc_monetary_data_without_an_accessor();
	test_yesexpr_noexpr_have_a_working_consumer();
	test_codeset_is_utf8_and_the_converter_exists();
	test_lc_messages_category_exists();
	test_message_catalogue_limits_exist_without_the_header();

	/* The call sites of the six fenced tests above.  Each is guarded
	 * with its own case id, for the same reason test/posix-stropts.c
	 * guards test_stropts_header_exists()'s call -- the function lives
	 * inside the fence, so the call has to as well.  Each case's
	 * argument is at the fence over its definition and is not
	 * repeated here. */
	test_langinfo_h_item_constants();
	test_nl_langinfo_posix_locale_values();
	test_nl_langinfo_l();
	test_nl_types_h_catalogue_access();
	test_catgets_reads_a_catalogue();
	test_strfmon_posix_locale();
#if SPICULE_TEST(PASS, posix_msgcat_strfmon_alignment_pads_to_equal_length) /* BUG: see the fence over test_strfmon_alignment_pads_to_equal_length(). */
	test_strfmon_alignment_pads_to_equal_length();
#endif
	test_iconv_open_convert_close();

	if (fails) { printf("posix-msgcat: failures: %d\n", fails); return 1; }
	printf("posix-msgcat: all ok\n");
	return 0;
}
