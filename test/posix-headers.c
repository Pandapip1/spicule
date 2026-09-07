/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * XBD header-content conformance, for the clauses that can only be
 * tested in ISOLATION -- audit group U; see test/POSIX-COVERAGE.md,
 * "XBD header contents -- the macros no ledger counts (group U)".
 *
 * THE RULE THIS FILE EXISTS FOR: a header-content fence must fail the
 * way a consumer fails.  Where an XBD clause is about what ONE header
 * supplies ON ITS OWN, the test needs a translation unit that includes
 * only that header -- otherwise the instrument fights the file it lives
 * in.  <fcntl.h>'s SEEK_* clause is the worked example: <stdio.h> and
 * <unistd.h> both define SEEK_SET, so in any ordinary test file the
 * clause is untestable and the best available fence degrades into a
 * runtime assertion about a recorded flag.  A real consumer meets this
 * as a COMPILE error in a single-header translation unit, and that is
 * what the fence here reproduces.  Where a clause is only about a name
 * existing SOMEWHERE, an existing test file is the right home and this
 * file is the wrong one.
 *
 * STRUCTURE, which is what makes the next such clause cheap: the top of
 * the file is a sequence of small TU-shaped "islands".  Each island
 * includes exactly the header its clause is about and nothing else, and
 * carries the test for that clause immediately after the #include, so
 * the test is compiled with only that header in scope.  Islands are
 * ordered so no earlier one can supply a name a later one probes.
 * Everything below the last island may include anything it likes.
 *
 * Because an island must not pull in <stdio.h>, the assertion helper is
 * forward-declared here and defined at the bottom of the file.
 */

#include "test-policy.h"

static void u_check(int cond, const char *expr, int line);
#define UCHECK(c) u_check((c), #c, __LINE__)

/* ================= island: <fcntl.h>, alone ====================== */
#include <fcntl.h>

static void test_fcntl_h_defines_seek_whence(void)
{
	struct flock fl;

	/* "as described in <stdio.h>": three distinct values ... */
	UCHECK(SEEK_SET != SEEK_CUR);
	UCHECK(SEEK_CUR != SEEK_END);
	UCHECK(SEEK_SET != SEEK_END);

	/* ... usable as l_whence, which is what the sentence is for. */
	fl.l_whence = SEEK_SET;
	UCHECK(fl.l_whence == SEEK_SET);
	fl.l_whence = SEEK_CUR;
	UCHECK(fl.l_whence == SEEK_CUR);
	fl.l_whence = SEEK_END;
	UCHECK(fl.l_whence == SEEK_END);
}

/* ================= island: <tar.h>, alone ======================== */
#include <tar.h>

static void test_tar_h_constants(void)
{
	/* "TMAGIC ... Used in the magic field in the ustar header block,
	 * INCLUDING the trailing null byte"; "TMAGLEN 6 ... Length in
	 * octets of the magic field." */
	UCHECK(sizeof TMAGIC == (unsigned)TMAGLEN);
	UCHECK(TMAGIC[0] == 'u' && TMAGIC[1] == 's' && TMAGIC[2] == 't');
	UCHECK(TMAGIC[3] == 'a' && TMAGIC[4] == 'r' && TMAGIC[5] == '\0');

	/* "TVERSION "00" ... EXCLUDING the trailing null byte";
	 * "TVERSLEN 2". */
	UCHECK(sizeof TVERSION - 1 == (unsigned)TVERSLEN);
	UCHECK(TVERSION[0] == '0' && TVERSION[1] == '0');

	/* Typeflag field definitions -- the values are the archive
	 * format's own bytes, so they are exact, not floors. */
	UCHECK(REGTYPE == '0');
	UCHECK(AREGTYPE == '\0');
	UCHECK(LNKTYPE == '1');
	UCHECK(SYMTYPE == '2');
	UCHECK(CHRTYPE == '3');
	UCHECK(BLKTYPE == '4');
	UCHECK(DIRTYPE == '5');
	UCHECK(FIFOTYPE == '6');
	UCHECK(CONTTYPE == '7');

	/* Mode field bit definitions (octal). */
	UCHECK(TSUID == 04000);
	UCHECK(TSGID == 02000);
	UCHECK(TSVTX == 01000);		/* [XSI] */
	UCHECK(TUREAD == 00400);
	UCHECK(TUWRITE == 00200);
	UCHECK(TUEXEC == 00100);
	UCHECK(TGREAD == 00040);
	UCHECK(TGWRITE == 00020);
	UCHECK(TGEXEC == 00010);
	UCHECK(TOREAD == 00004);
	UCHECK(TOWRITE == 00002);
	UCHECK(TOEXEC == 00001);
}

/* ================= island: <cpio.h>, alone ======================= */
#include <cpio.h>

static void test_cpio_h_constants(void)
{
	UCHECK(C_IRUSR == 0000400);
	UCHECK(C_IWUSR == 0000200);
	UCHECK(C_IXUSR == 0000100);
	UCHECK(C_IRGRP == 0000040);
	UCHECK(C_IWGRP == 0000020);
	UCHECK(C_IXGRP == 0000010);
	UCHECK(C_IROTH == 0000004);
	UCHECK(C_IWOTH == 0000002);
	UCHECK(C_IXOTH == 0000001);
	UCHECK(C_ISUID == 0004000);
	UCHECK(C_ISGID == 0002000);
	UCHECK(C_ISVTX == 0001000);
	UCHECK(C_ISDIR == 0040000);
	UCHECK(C_ISFIFO == 0010000);
	UCHECK(C_ISREG == 0100000);
	UCHECK(C_ISBLK == 0060000);
	UCHECK(C_ISCHR == 0020000);
	UCHECK(C_ISCTG == 0110000);
	UCHECK(C_ISLNK == 0120000);
	UCHECK(C_ISSOCK == 0140000);

	/* "shall define the following symbolic constant as a string:
	 * MAGIC "070707"" -- six digits plus the terminating null. */
	UCHECK(sizeof MAGIC == 7);
	UCHECK(MAGIC[0] == '0' && MAGIC[1] == '7' && MAGIC[2] == '0');
	UCHECK(MAGIC[3] == '7' && MAGIC[4] == '0' && MAGIC[5] == '7');
}

/* ================= island: <sched.h>, alone ====================== */
#include <sched.h>

static void test_sched_h_defines_sched_param(void)
{
	struct sched_param sp;

	/* "shall include at least the following member: int
	 * sched_priority Process or thread execution scheduling
	 * priority." */
	sp.sched_priority = 0;
	UCHECK(sp.sched_priority == 0);
	sp.sched_priority = 7;
	UCHECK(sp.sched_priority == 7);
	UCHECK(sizeof sp >= sizeof(int));
}

/* ============= island: <ctype.h>, alone ========================== */
#include <ctype.h>

#if SPICULE_TEST(PASS, posix_headers_ctype_h_defines_locale_t) /* Was UNIMPL: <ctype.h> did not define locale_t.
	 * basedefs/ctype.h.html: "The <ctype.h> header shall define the
	 * locale_t type as described in <locale.h>."  It is an
	 * unconditional sentence about a type, and it is what lets a
	 * translation unit that includes only <ctype.h> name the argument
	 * the _l family takes.
	 *
	 * Mechanism: bits/alltypes.h gates locale_t behind
	 * __NEED_locale_t, and exactly five headers ask for it --
	 * include/locale.h, include/string.h, include/strings.h,
	 * include/wchar.h and include/time.h.  include/ctype.h and
	 * include/wctype.h are the two headers on the mandate list that do
	 * not, so a TU including either alone cannot name the type at all.
	 * Probed on this tree: `#include <ctype.h>` followed by
	 * `locale_t g;` compiles as an implicit int, while the same two
	 * lines against <locale.h>, <wchar.h> or <string.h> are clean.
	 *
	 * This is separate from the absence of the isalnum_l()/iswalnum_l()
	 * families, which test/POSIX-GAP-ACCOUNTING.md already records as a
	 * gap: exposing the type is one __NEED_locale_t line per header and
	 * claims nothing about those functions.
	 *
	 * It also fills a hole in group U's own sweep, which reported that
	 * of the 68 "shall define T as described in <Y>" sentences the only
	 * failure was <signal.h>/pthread_t -- these two were not among the
	 * ones probed.
	 *
	 * Fixed: include/ctype.h now requests __NEED_locale_t
	 * unconditionally (see its own banner comment for the citation)
	 * and includes bits/alltypes.h to get it, alongside declaring the
	 * isalnum_l() ... toupper_l() family that gives the type
	 * something to be the argument of. */
static void test_ctype_h_defines_locale_t(void)
{
	locale_t l = (locale_t)0;

	UCHECK(sizeof l == sizeof(void *));
	UCHECK(l == (locale_t)0);
}
#endif

/* ============= island: <wctype.h>, alone ========================= */
#include <wctype.h>

#if SPICULE_TEST(PASS, posix_headers_wctype_h_defines_locale_t) /* Was UNIMPL: <wctype.h> did not define locale_t either.
	 * basedefs/wctype.h.html lists the types the header shall define --
	 * wint_t, wctrans_t, wctype_t, and locale_t "As described in
	 * <locale.h>".  include/wctype.h asked bits/alltypes.h only for
	 * __NEED_wint_t and __NEED_wctype_t.  Same mechanism, same
	 * one-line fix, as the <ctype.h> island above; kept as its own
	 * island because the clause is about what this header supplies on
	 * its own.
	 *
	 * Fixed: include/wctype.h now requests __NEED_locale_t too,
	 * alongside declaring the iswalnum_l() ... wctrans_l() family. */
static void test_wctype_h_defines_locale_t(void)
{
	locale_t l = (locale_t)0;

	UCHECK(sizeof l == sizeof(void *));
	UCHECK(l == (locale_t)0);
}
#endif

/* ============ end of the islands; anything goes below ============ */
#include <stdio.h>

static int fails;

static void u_check(int cond, const char *expr, int line)
{
	if (!cond) {
		fails++;
		printf("FAIL %s:%d: %s\n", __FILE__, line, expr);
	}
}

int main(void)
{
	/* Un-fencing a clause here takes TWO edits, not one: removing the
	 * #if 0 around the test AND adding its call below.  The definition
	 * alone compiles and never runs -- which for a header-constants
	 * test is easy to miss, because most of what these assert is
	 * checked by the compiler anyway and the binary still says "all
	 * tests passed".  Found the hard way: two mutations to <tar.h>'s
	 * values went undetected until the calls were added.
	 *
	 * u_check() is referenced by the still-fenced tests only, so it is
	 * touched here to keep it honest while any remain. */
	u_check(1, "posix-headers harness is live", __LINE__);

	test_fcntl_h_defines_seek_whence();
	test_tar_h_constants();
	test_cpio_h_constants();
	test_sched_h_defines_sched_param();

	if (!fails) printf("posix-headers: all tests passed\n");
	return fails != 0;
}
