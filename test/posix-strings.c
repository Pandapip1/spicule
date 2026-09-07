/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of the small, never-audited
 * headers <strings.h>, the XSI additions to <ctype.h>, <assert.h>,
 * <utime.h>, and <endian.h> (not a POSIX header at all -- see below).
 * Each block cites the page it was checked against under
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/<name>.html
 * (or .../basedefs/<header>.html for header-level requirements).
 *
 * strcasecmp/strncasecmp and ffs already have sanity coverage in
 * test/string.c and an ordering-sign check in test/posix-string.c;
 * this file adds the clauses those did not reach: strcasecmp's
 * unsigned-char/bytes->=0x80 behavior and a full ffs() bit sweep.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <utime.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <signal.h>
#include <endian.h>
#include <assert.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

extern char **environ;

/* Internal: spawn a program as a child, return its pid (see
 * src/process/spawn.c).  fork() needs RtlCloneUserProcess, which stock
 * Wine lacks; declared locally as test/misc.c does, rather than
 * widening include/. */
int __spawn(const char *path, char *const argv[], char *const envp[]);

/* ============================== strings.h ============================== */

/* strcasecmp.html DESCRIPTION: "use the current locale to determine the
 * case of the characters"; for the POSIX locale (the only one spicule's
 * LC_CTYPE ever is -- src/ctype/is*.c classify by fixed ASCII ranges,
 * never consulting a locale object) "these functions shall behave as
 * if the strings had been converted to lowercase and then a byte
 * comparison performed."  spicule's tolower() only maps 'A'-'Z'
 * (src/ctype/tolower.c: isupper() is `(unsigned)c-'A' < 26`), so bytes
 * >= 0x80 are never touched by the case fold and fall straight through
 * to a byte comparison.  strcasecmp() casts to `const unsigned char *`
 * before comparing, so that comparison -- and the sign of the return
 * value, which RETURN VALUE ties to "greater than, equal to, or less
 * than" on the (lowercased) strings -- must treat 0x80-0xff as large
 * positive values, not as negative `char`s.  This is the one bug class
 * a `char`-typed rewrite of strcasecmp commonly introduces, so it is
 * swept deliberately rather than spot-checked. */
static void test_strcasecmp_high_bytes(void)
{
	unsigned i;
	for (i = 0x80; i <= 0xff; i++) {
		char a[2], b[2];
		a[0] = (char)i; a[1] = 0;
		b[0] = (char)0x7f; b[1] = 0;
		/* every byte >= 0x80 must compare as unsigned-char greater
		 * than 0x7f -- a signed-char bug would report these as
		 * negative, i.e. *less* than 0x7f */
		CHECK(strcasecmp(a, b) > 0);
		CHECK(strncasecmp(a, b, 1) > 0);
	}
	/* ordering among high bytes themselves must follow unsigned value,
	 * and since none of them get case-folded (no 'A'-'Z'/'a'-'z'
	 * mapping applies), the comparison is a plain unsigned-char one */
	CHECK(strcasecmp("\x80", "\xff") < 0);
	CHECK(strcasecmp("\xff", "\x80") > 0);
	CHECK(strcasecmp("\x80", "\x80") == 0);
	/* mixed: a high byte against a foldable ASCII letter is still a
	 * plain unsigned-char comparison since only the letter folds */
	CHECK(strcasecmp("\xff", "A") > 0 && strcasecmp("\xff", "a") > 0);
	CHECK(strncasecmp("\xff", "A", 1) > 0);
}

/* strcasecmp.html RETURN VALUE: sign reflects the comparison of the
 * *lowercased* strings, not the raw bytes -- exercised here with
 * mixed-case strings that would compare the other way if the fold did
 * not happen (raw "B" < "a" as unsigned char, 0x42 < 0x61) but must
 * fold to "b" > "a". */
static void test_strcasecmp_folds_before_comparing(void)
{
	CHECK(strcmp("B", "a") < 0);          /* sanity: raw bytes disagree */
	CHECK(strcasecmp("B", "a") > 0);      /* folded: 'b' > 'a' */
	CHECK(strncasecmp("B", "a", 1) > 0);
	CHECK(strcasecmp("b", "A") > 0);
	CHECK(strcasecmp_l("B", "a", (locale_t)0) > 0);
	CHECK(strncasecmp_l("B", "a", 1, (locale_t)0) > 0);
}

/* ffs.html DESCRIPTION/RETURN VALUE: "find the first bit set (beginning
 * with the least significant bit) ... Bits are numbered starting at
 * one (the least significant bit) ... If i is 0, then ffs() shall
 * return 0."  Every bit position is swept, not sampled -- ffs's whole
 * contract is a per-bit-position table. */
static void test_ffs_every_bit(void)
{
	int bit;
	CHECK(ffs(0) == 0);
	for (bit = 0; bit < (int)sizeof(int) * CHAR_BIT - 1; bit++) {
		CHECK(ffs(1 << bit) == bit + 1);
		/* setting every bit above `bit` too must not change the
		 * answer: ffs() finds the *least* significant set bit */
		CHECK(ffs((int)(~0u << bit)) == bit + 1);
	}
	/* the sign bit (INT_MIN, bit 31 on a 32-bit int): ffs takes int
	 * but the standard's bit numbering does not exempt the sign bit */
	CHECK(ffs(INT_MIN) == (int)sizeof(int) * CHAR_BIT);
	CHECK(ffs(-1) == 1); /* all bits set: LSB wins */
}

/* strings.h.html: legacy bcmp/bcopy/bzero/index/rindex were removed
 * from POSIX.1-2017's <strings.h> (present through SUSv3, gone in
 * Issue 7 / SUSv4).  spicule still ships them (src/string/bcmp.c etc.),
 * gated in include/strings.h behind "not _POSIX_SOURCE and not
 * _XOPEN_SOURCE>=700", i.e. exposed as a non-standard extension, not
 * claimed as base conformance.  Confirmed present and functioning here
 * as an extension; test/string.c already sanity-covers them and the
 * ledger records the removal, so this is not re-duplicated in depth. */
static void test_legacy_extensions_present(void)
{
	char buf[4] = "abc";
	CHECK(bcmp("abc", "abc", 3) == 0);
	CHECK(bcmp("abc", "abd", 3) != 0);
	bcopy("xyz", buf, 3); CHECK(!memcmp(buf, "xyz", 3));
	bzero(buf, 3); CHECK(!memcmp(buf, "\0\0\0", 3));
	{
		/* compare against strchr/strrchr on the *same* buffer --
		 * two separate string-literal calls are not guaranteed to
		 * share storage, so comparing across two literals would
		 * not actually test index()/rindex()'s search behavior */
		char s[] = "hello";
		CHECK(index(s, 'l') == strchr(s, 'l'));
		CHECK(rindex(s, 'l') == strrchr(s, 'l'));
	}
}

/* ============================== ctype.h (XSI) ============================== */

/* isalpha.html APPLICATION USAGE / isascii.html, toascii.html
 * DESCRIPTION: unlike the other is-x/to-x classifiers, whose argument
 * "shall be representable as an unsigned char or ... EOF" (UB
 * otherwise -- test/ctype.c and test/posix-misc.c cover that family),
 * "isascii() is defined on all integer values" and toascii() "shall
 * return the value (c & 0x7f)" for any int c.  That asymmetry is
 * exercised here with values well outside unsigned-char/EOF range:
 * negative values other than EOF, and values >= 256. */
static void test_isascii_toascii_defined_for_all_ints(void)
{
	static const int vals[] = {
		0, 1, 127, 128, 255, 256, 257, 1000, 65536,
		-1, -2, -128, -129, -256, -1000, INT_MAX, INT_MIN
	};
	unsigned i;
	for (i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
		int c = vals[i];
		/* isascii.html RETURN VALUE: non-zero iff 0 <= c <= 0177 */
		int want_ascii = (c >= 0 && c <= 0177);
		CHECK(!!isascii(c) == want_ascii);
		/* toascii.html RETURN VALUE: "the value (c & 0x7f)",
		 * exactly, for every int -- including negative c, where
		 * the bitwise-and is on the int's representation */
		CHECK(toascii(c) == (c & 0x7f));
	}
}

/* _toascii/_tolower legacy macros (basedefs/ctype.h.html declares
 * `int _toupper(int); int _tolower(int);` with no behavioral
 * description of their own on that page; functions/_toupper.html
 * supplies it: "_toupper() ... shall be equivalent to toupper() except
 * that the application shall ensure that the argument c is a
 * lowercase letter" -- and symmetrically for _tolower()/uppercase.
 * Only the in-contract inputs are asserted; behavior outside them is
 * unspecified by the application-usage contract, not by spicule, so
 * nothing is asserted there. */
static void test_underscore_tolower_toupper(void)
{
	int c;
	for (c = 'a'; c <= 'z'; c++) CHECK(_toupper(c) == toupper(c));
	for (c = 'A'; c <= 'Z'; c++) CHECK(_tolower(c) == tolower(c));
}

/* ============================== assert.h ============================== */

/* assert.html DESCRIPTION: "Forcing a definition of the name NDEBUG,
 * either from the compiler command line or with the preprocessor
 * control statement #define NDEBUG ahead of the #include <assert.h>
 * statement, shall stop assertions from being compiled into the
 * program" -- and per include/assert.h, that decision is remade by
 * every #include <assert.h>, not fixed once per translation unit (the
 * header #undefs and redefines the assert() macro each time,
 * conditioned on NDEBUG's state *at that point*).  A single TU can
 * therefore have assert() active, then inactive, then active again.
 * Proved directly: the same TU re-includes <assert.h> after toggling
 * NDEBUG and checks, via a side effect inside the asserted expression,
 * whether it was evaluated at all -- an inactive assert() must not
 * evaluate its argument, since it expands to (void)0. */
static int ndebug_side_effect;

static void test_assert_active_before_ndebug(void)
{
	ndebug_side_effect = 0;
	assert((ndebug_side_effect = 1, 1));
	CHECK(ndebug_side_effect == 1); /* assert() evaluated its argument */
}

#define NDEBUG
#include <assert.h>	/* re-include: NDEBUG is now defined */

static void test_assert_inactive_under_ndebug(void)
{
	ndebug_side_effect = 0;
	assert((ndebug_side_effect = 1, 1));
	CHECK(ndebug_side_effect == 0); /* assert() compiled to (void)0 */
}

#undef NDEBUG
#include <assert.h>	/* re-include again: NDEBUG undefined once more */

static void test_assert_active_after_ndebug_undef(void)
{
	ndebug_side_effect = 0;
	assert((ndebug_side_effect = 1, 1));
	CHECK(ndebug_side_effect == 1); /* active again in the same TU */
}

/* assert.html DESCRIPTION: on failure, "information about the
 * particular call that failed ... shall include the text of the
 * argument, the name of the source file, the source file line number,
 * and the name of the enclosing function" written to stderr, and the
 * process is terminated via abort() (assert() "shall be equivalent to
 * ... abort()").  Needs an observed child: redirect the child's stderr
 * through a pipe (__assert_fail's fflush(0) guarantees the buffered
 * text is written before abort() tears the process down), let the
 * assertion fire, then have the parent read the pipe back and check
 * every element the clause promises is present. */

/* Records the physical source line of the assert() call into the very
 * file __assert_fail() is about to write to, using the *same*
 * preprocessor __LINE__ expansion point as the assert() call right
 * next to it on one line -- so "expected-line:N" and whatever line
 * number __assert_fail() actually prints come from independent
 * __LINE__ evaluations of the identical source position, with no
 * manually-counted offset to get wrong. */
#define ASSERT_MARK_THEN_FIRE(cond) do { fprintf(stderr, "expected-line:%d\n", __LINE__); assert(cond); } while (0)

static void child_assert_marker(void)
{
	ASSERT_MARK_THEN_FIRE(0 == 1); /* deliberately false: "0 == 1" must appear verbatim */
}

/* Captures the child's stderr through a real pipe rather than a named
 * file: __spawn only carries real OS handles across into the child
 * (fds 0-2 by the STARTF_USESTDHANDLES contract src/process/spawn.c
 * documents, or on this project's native-ASan test harness, "only
 * descriptors 0-2, real host fds, survive the trip" per
 * fuzz/ntstubs.c's process-spawning comment -- either way, a *named
 * file* the child writes is not guaranteed visible to the parent, but
 * an inherited fd 2 is). */
static void test_assert_message_and_death(const char *self)
{
	char *argv[3];
	int pid, status;
	int p[2];
	int saved_stderr;
	char msg[512];
	ssize_t n;
	char linebuf[32];
	int expected_line;
	const char *q;

	CHECK(pipe(p) == 0);
	saved_stderr = dup(2);
	CHECK(saved_stderr >= 0);
	CHECK(dup2(p[1], 2) == 2);
	close(p[1]);

	argv[0] = (char *)self;
	argv[1] = (char *)"--posix-strings-assert-child";
	argv[2] = 0;
	pid = __spawn(self, argv, environ);

	dup2(saved_stderr, 2);	/* restore our own stderr before anything else prints */
	close(saved_stderr);

	if (pid < 0) {
		printf("note: cannot spawn \"%s\" (errno %d); assert() message/death child test skipped\n", self, errno);
		close(p[0]);
		return;
	}
	CHECK(waitpid(pid, &status, 0) == pid);
	/* abort()'s contract (abort.html) is "SIGABRT-shaped death": either
	 * killed by SIGABRT, or (SIGABRT ignored/blocked in some
	 * environment) a nonzero exit -- same relaxed check test/misc.c
	 * and test/posix-alloc.c use for the same reason. */
	CHECK(WIFSIGNALED(status) ? WTERMSIG(status) == SIGABRT
	                           : (WIFEXITED(status) && WEXITSTATUS(status) != 0));

	/* the child (and every fd 2 handle onto the pipe's write end
	 * except our own already-closed one) is gone, so read() drains
	 * whatever was written and then returns 0 (EOF) rather than
	 * blocking.  On a target where fd inheritance across __spawn does
	 * not reach a real OS-level descriptor table (this project's
	 * native ASan test harness forks the real host process directly,
	 * bypassing spicule's own handle layer entirely for that step --
	 * see fuzz/ntstubs.c's RtlCreateUserProcess comment), nothing
	 * arrives here even though the child ran and died correctly, as
	 * just confirmed above; skip only the message-content assertions
	 * in that case rather than failing on an environment limitation
	 * neither this test nor the library controls. */
	n = read(p[0], msg, sizeof(msg) - 1);
	close(p[0]);
	if (n <= 0) {
		printf("note: child's stderr was not observed through the inherited pipe in this environment; assert() message-format check skipped (SIGABRT death was already verified above)\n");
		return;
	}
	msg[n] = 0;

	CHECK(strstr(msg, "0 == 1") != 0);              /* text of the argument */
	CHECK(strstr(msg, "posix-strings.c") != 0);      /* source file name */
	CHECK(strstr(msg, "child_assert_marker") != 0);  /* enclosing function */
	/* "expected-line:N" was written by the same macro invocation that
	 * fires the assert() (see ASSERT_MARK_THEN_FIRE), so N is the
	 * physical source line of the assert() call, independent of the
	 * line number __assert_fail() itself reports; they must match. */
	q = strstr(msg, "expected-line:");
	CHECK(q != 0);
	expected_line = q ? atoi(q + strlen("expected-line:")) : -1;
	CHECK(expected_line > 0);
	sprintf(linebuf, "%d", expected_line);
	/* search only *after* our own "expected-line:N" note, so this
	 * finds N in __assert_fail()'s own "(file: func: line)" text, not
	 * an accidental match against the note itself */
	CHECK(expected_line > 0 && q != 0 &&
	      strstr(q + strlen("expected-line:") + strlen(linebuf), linebuf) != 0);
}

/* basedefs/assert.h.html DESCRIPTION: "The assert() macro shall be
 * implemented as a macro, not as a function.  If the macro definition
 * is suppressed in order to access an actual function, the behavior is
 * undefined."  A compile-time requirement, so it is checked at compile
 * time -- there is no runtime observation that can distinguish the two
 * once the translation unit is built.  This sits after the NDEBUG
 * toggling above deliberately: the final state of that sequence is
 * "NDEBUG undefined, <assert.h> re-included", so this also pins that
 * the last re-include really did put the macro back. */
#ifndef assert
#error "assert() must be a macro (basedefs/assert.h.html DESCRIPTION)"
#endif

/* basedefs/assert.h.html lists exactly one thing the header "shall
 * define": the assert() macro.  static_assert is *not* in it -- it is
 * an ISO C11 addition (N1570 7.2p3), and POSIX.1-2017's <assert.h> is
 * aligned with C99, whose __STDC_VERSION__ is 199901L.  spicule gates
 * `#define static_assert _Static_assert` on
 * `__STDC_VERSION__ >= 201112L` (include/assert.h), so under this
 * project's own build flags (-std=c99, configure's CFLAGS_C99FSE) the
 * macro must be absent: defining it anyway would put a non-reserved
 * identifier into the user's namespace that neither C99 nor
 * POSIX.1-2017 permits this header to claim.  Checked at compile time
 * for the same reason as the assert()-is-a-macro check above; the
 * runtime function below asserts the same condition through the
 * preprocessor so the check is visible in the pass/fail count too. */
static void test_assert_h_defines_only_assert(void)
{
#if __STDC_VERSION__ >= 201112L
	/* C11 or later: static_assert is required, and must be usable
	 * both at block scope and with the _Static_assert semantics. */
	CHECK(1);
	static_assert(sizeof(char) == 1, "C11 static_assert must work when the header defines it");
#else
	/* C99 (this project's build): the header must not define it. */
#	ifdef static_assert
	CHECK(!"static_assert must not be defined under -std=c99 (basedefs/assert.h.html defines only assert())");
#	else
	CHECK(1);
#	endif
#endif
}

/* assert.html DESCRIPTION: assert() "shall expand to a void
 * expression" -- an *expression*, not a statement, so it must be
 * usable anywhere a void expression is (as a comma operand, as a
 * for-loop clause, as the second/third operand of ?:), and its value
 * must be of type void, so casting it to (void) has to compile.  Both
 * the active and the NDEBUG-suppressed forms have to satisfy this;
 * NDEBUG is undefined at this point in the TU, so this exercises the
 * active form, and test_assert_inactive_under_ndebug() above already
 * evaluated the `(void)0` form as an expression in the same position.
 * Nothing here can fail at runtime if it compiled at all -- that is
 * the point; the CHECK() records that the shapes were accepted. */
static void test_assert_is_a_void_expression(void)
{
	int n = 0;
	/* as a comma operand */
	(void)(assert(1), 0);
	/* explicitly cast to void: only valid if it has type void */
	(void)assert(1);
	/* as a for-loop expression clause */
	for (n = 0; n < 3; assert(n >= 0), n++)
		;
	CHECK(n == 3);
	/* as an operand of ?: alongside another void expression */
	n ? assert(1) : (void)0;
	CHECK(n == 3);
}

/* ============================== utime.h ============================== */

/* utime.html DESCRIPTION/RETURN VALUE: full happy-path round trip via
 * stat() is already exercised in test/unistd.c (utimensat/utime/
 * futimens/futimesat, UTIME_NOW/UTIME_OMIT, ENOENT).  Not duplicated
 * here; this adds the one clause that pass did not check: "Upon
 * successful completion, 0 shall be returned" (return value, not just
 * the side effect on stat()), and the times==NULL "current time"
 * path's return value likewise. */
#define UTIME_FILE "posix-strings-utime.tmp"

static void test_utime_return_value(void)
{
	int fd;
	struct utimbuf ub;

	unlink(UTIME_FILE);
	fd = open(UTIME_FILE, O_CREAT | O_WRONLY, 0644);
	CHECK(fd >= 0);
	if (fd >= 0) close(fd);

	ub.actime = 1000000000;
	ub.modtime = 1100000000;
	CHECK(utime(UTIME_FILE, &ub) == 0);   /* RETURN VALUE: 0 on success */

	CHECK(utime(UTIME_FILE, 0) == 0);     /* times==NULL: current time, still 0 */

	/* ERRORS [ENOENT]: "A component of path does not name an existing
	 * file" -- -1 and errno set, matching RETURN VALUE's contract for
	 * the failure path */
	errno = 0;
	CHECK(utime("posix-strings-utime-does-not-exist.tmp", &ub) == -1);
	CHECK(errno == ENOENT);

	unlink(UTIME_FILE);
}

/* utime.html DESCRIPTION: "If times is a null pointer, the access and
 * modification times of the file shall be set to the current time."
 * test_utime_return_value() above only checks that call's return
 * value; test/unistd.c's "back to roughly now" case exercises the
 * current-time side effect through utimensat(..., NULL, 0), not
 * through utime(path, NULL), which is a separate entry point
 * (src/stat/utimensat.c's utime() forwards its own NULL, it does not
 * synthesize a timespec pair).  Checked here directly: set both times
 * to a value far in the past, then let utime(path, NULL) reset them,
 * and require *both* to land in a window around the current time. */
static void test_utime_null_sets_current_time(void)
{
	struct utimbuf ub;
	struct stat st;
	time_t before, after;
	int fd;

	unlink(UTIME_FILE);
	fd = open(UTIME_FILE, O_CREAT | O_WRONLY, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;
	close(fd);

	ub.actime = 1000000000;   /* 2001-09-09 */
	ub.modtime = 1000000000;
	CHECK(utime(UTIME_FILE, &ub) == 0);
	CHECK(stat(UTIME_FILE, &st) == 0);
	CHECK(st.st_atime == 1000000000 && st.st_mtime == 1000000000);

	before = time(0);
	CHECK(utime(UTIME_FILE, 0) == 0);
	after = time(0);
	CHECK(stat(UTIME_FILE, &st) == 0);
	/* "the current time" -- bracketed by readings taken either side of
	 * the call, with a second of slack each way for the coarse
	 * (~15.6ms tick, but 1s-resolution time_t) NT clock and for the
	 * two clocks not being read at the same instant. */
	CHECK(st.st_atime >= before - 1 && st.st_atime <= after + 1);
	CHECK(st.st_mtime >= before - 1 && st.st_mtime <= after + 1);

	unlink(UTIME_FILE);
}

/* utime.html DESCRIPTION: "Upon successful completion, utime() shall
 * mark the last file status change timestamp for update."  That is the
 * st_ctime/st_ctim field (sys_stat.h.html), which spicule reads from
 * FILE_BASIC_INFORMATION.ChangeTime (src/stat/stat.c).  Distinct from
 * the access/modification times the call is setting: setting those to
 * a 2001 value must *not* drag the status-change time backwards with
 * them, and the status-change time must actually advance across the
 * call.  Compared at full struct-timespec resolution after a short
 * sleep, so this needs no whole-second tick to pass; 100ms is well
 * past NT's ~15.6ms system clock granularity. */
static void test_utime_marks_ctime(void)
{
	struct utimbuf ub;
	struct stat before, after;
	struct timespec nap;
	int fd;

	unlink(UTIME_FILE);
	fd = open(UTIME_FILE, O_CREAT | O_WRONLY, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;
	close(fd);

	CHECK(stat(UTIME_FILE, &before) == 0);

	nap.tv_sec = 0;
	nap.tv_nsec = 100000000L;	/* 100ms */
	nanosleep(&nap, 0);

	ub.actime = 1000000000;
	ub.modtime = 1000000000;
	CHECK(utime(UTIME_FILE, &ub) == 0);
	CHECK(stat(UTIME_FILE, &after) == 0);

	/* the times utime() was asked to set did land ... */
	CHECK(after.st_atime == 1000000000 && after.st_mtime == 1000000000);
	/* ... and the status-change time was marked for update, i.e. it
	 * moved forward rather than following them into 2001 */
	CHECK(after.st_ctim.tv_sec > before.st_ctim.tv_sec
	   || (after.st_ctim.tv_sec == before.st_ctim.tv_sec
	    && after.st_ctim.tv_nsec > before.st_ctim.tv_nsec));

	unlink(UTIME_FILE);
}

/* utime.html ERRORS.  Of the seven "shall fail" codes, three are
 * observable here and four are not:
 *
 *   [ENOENT] "A component of path does not name an existing file or
 *   path is an empty string."  The missing-file half is already
 *   checked in test_utime_return_value() above; the empty-string half
 *   is checked below.
 *
 *   [ENOTDIR] has two halves.  The trailing-slash half ("the path
 *   argument contains at least one non-<slash> character and ends
 *   with one or more trailing <slash> characters and the last
 *   pathname component names an existing file that is neither a
 *   directory nor a symbolic link to a directory") passes: it goes
 *   through reject_if_not_dir() in src/internal/path.c, the shared
 *   re-check added for test/posix-unistd.c's
 *   test_access_trailing_slash_enotdir().  The path-prefix half does
 *   not -- see the fenced BUG below.
 *
 *   [ENAMETOOLONG] -- see the fenced BUG below.
 *
 * Not observable, and not fenced as separate no-op tests because the
 * reason is a property of the platform rather than of utime():
 * [EACCES] and [EPERM] both need a second security principal to be
 * denied *as* -- spicule models exactly one user (geteuid() is the
 * token-derived current uid; see include/sys/resource.h's PRIO_USER note), so
 * every caller is always the owner with full access; [EROFS] needs a
 * read-only file system, which the test harness has no way to mount;
 * [ELOOP] needs a symbolic-link loop, and no symbolic link can be
 * created in this environment.  ON THE WINE LEG THE PRIVILEGE IS NOT
 * THE BLOCKER, which this comment used to say it was: stock Wine below
 * 10.19 answers FSCTL_SET_REPARSE_POINT with STATUS_NOT_SUPPORTED
 * (0xc00000bb), which src/internal/errno.c:82-84 renders as ENOSYS, and
 * SeCreateSymbolicLinkPrivilege is never consulted at all.  Whether the
 * privilege is the blocker on GENUINE Windows without Developer Mode is
 * UNCERTAIN and untested.  Full account: test/posix-unreferenced.c's test_fchmodat_eloop() fence, which is the
 * canonical account and is not duplicated here. */
static void test_utime_errors(void)
{
	struct utimbuf ub;
	int fd;

	ub.actime = 1000000000;
	ub.modtime = 1000000000;

	unlink(UTIME_FILE);
	fd = open(UTIME_FILE, O_CREAT | O_WRONLY, 0644);
	CHECK(fd >= 0);
	if (fd >= 0) close(fd);

	/* [ENOTDIR], trailing-slash half: passes */
	errno = 0;
	CHECK(utime(UTIME_FILE "/", &ub) == -1);
	CHECK(errno == ENOTDIR);

	/* [ENOENT]: "path is an empty string" */
	errno = 0;
	CHECK(utime("", &ub) == -1);
	CHECK(errno == ENOENT);

	unlink(UTIME_FILE);
}

/* utime.html ERRORS [ENOTDIR] (shall fail): "A component of the path
 * prefix names an existing file that is neither a directory nor a
 * symbolic link to a directory."
 *
 * spicule used to report ENOENT here, not ENOTDIR, and not only from
 * utime(): open(), stat(), access(), unlink(), mkdir() and
 * utimensat() all gave ENOENT for the identical shape ("<existing
 * regular file>/below"), because this is one defect in the shared
 * path layer (src/internal/path.c), not seven.
 *
 * Mechanism: NT's object manager does not distinguish "a directory in
 * the path prefix does not exist" from "a component of the path
 * prefix exists but is a file" -- it answers both with
 * STATUS_OBJECT_PATH_NOT_FOUND, which src/internal/errno.c maps to
 * ENOENT (correctly, for the first of those two cases).  POSIX
 * requires the two to be told apart, so src/internal/path.c's
 * reject_if_prefix_not_dir() tells them apart itself, with the same
 * handle-less NtQueryAttributesFile() disambiguation that
 * reject_if_not_dir() next to it already did for the
 * *trailing-slash* half of the same [ENOTDIR] clause. */
static void test_utime_enotdir_path_prefix(void)
{
	struct utimbuf ub;
	int fd;

	ub.actime = 1000000000;
	ub.modtime = 1000000000;

	unlink(UTIME_FILE);
	fd = open(UTIME_FILE, O_CREAT | O_WRONLY, 0644);
	CHECK(fd >= 0);
	if (fd >= 0) close(fd);

	errno = 0;
	CHECK(utime(UTIME_FILE "/below", &ub) == -1);
	CHECK(errno == ENOTDIR);

	unlink(UTIME_FILE);
}

/* utime.html ERRORS [ENAMETOOLONG] (shall fail): "The length of a
 * component of a pathname is longer than {NAME_MAX}."  (The
 * {PATH_MAX} form of the same code is only "may fail"; the 40000-byte
 * single component below is longer than either, so the *shall*-fail
 * clause is the one that applies.)
 *
 * spicule used to report ENOENT: open(), stat(), access(), unlink(),
 * mkdir() and utimensat() all gave ENOENT for a 40000-character name.
 * chdir() was the sole exception, and it was the exception precisely
 * because it does not rely on the shared layer for this --
 * src/unistd/chdir.c hands its own hand-built UNICODE_STRING to
 * RtlSetCurrentDirectory_U() and carries its own explicit `n >
 * __US_MAX_WCHARS -> ENAMETOOLONG` check (still needed there for that
 * reason, and still pinned by test/unistd.c).  Coverage of that one
 * caller is why the gap in every other caller went unnoticed.
 *
 * Mechanism: src/internal/path.c's __ntpath() used to funnel every
 * RtlDosPathNameToNtPathName_U_WithStatus() failure other than
 * STATUS_NO_MEMORY into a single `errno = ENOENT`.  The very same
 * length test chdir.c performs existed in path.c too -- but only in
 * the relative-to-a-dirfd branch of __ntpath_at() (the `n >
 * __US_MAX_WCHARS` check), which an AT_FDCWD or absolute path never
 * reaches, since __ntpath_at() forwards both straight to __ntpath().
 * It is now in __ntpath() as well, which fixes every caller at once,
 * alongside a STATUS_NAME_TOO_LONG -> ENAMETOOLONG mapping for the
 * name that only overflows once resolved against the cwd. */
static void test_utime_enametoolong(void)
{
	struct utimbuf ub;
	char *big;

	ub.actime = 1000000000;
	ub.modtime = 1000000000;

	big = malloc(40001);
	CHECK(big != 0);
	if (!big) return;
	memset(big, 'x', 40000);
	big[40000] = 0;
	errno = 0;
	CHECK(utime(big, &ub) == -1);
	CHECK(errno == ENAMETOOLONG);
	free(big);
}

/* ============================== endian.h ============================== */

/* endian.h is not part of POSIX.1-2017: no functions/endian.h.html or
 * basedefs/endian.h.html page exists (verified: the basedefs URL
 * 404s), and it is absent from the base-definitions header index. It
 * is a glibc/BSD extension spicule ships for source compatibility;
 * gated behind _GNU_SOURCE/_BSD_SOURCE in include/endian.h. Recorded
 * as an extension, tested only for internal self-consistency:
 * __BYTE_ORDER names a real endianness, and the byte-swap helpers
 * actually swap. */
static void test_endian_internal_consistency(void)
{
	CHECK(__BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __BIG_ENDIAN);
	CHECK(BYTE_ORDER == __BYTE_ORDER);
	CHECK(htobe16(0x0102) == be16toh(0x0102)); /* both directions of the same swap */
	CHECK(htobe16(0x0102) == 0x0201);
	CHECK(htobe32(0x01020304) == 0x04030201u);
	CHECK((uint64_t)htobe64(0x0102030405060708ULL) == 0x0807060504030201ULL);
	/* le helpers are identity on this (little-endian-only) target */
	CHECK(htole16(0x0102) == 0x0102);
	CHECK(htole32(0x01020304) == 0x01020304u);
	CHECK(le16toh(0x0102) == 0x0102);
	/* htobe/be16toh must be inverses of each other */
	CHECK(be16toh(htobe16(0xabcd)) == 0xabcd);
	CHECK(be32toh(htobe32(0xdeadbeefu)) == 0xdeadbeefu);
}

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "--posix-strings-assert-child")) {
		child_assert_marker();
		return 0; /* unreachable if assert() fired as required */
	}

	test_strcasecmp_high_bytes();
	test_strcasecmp_folds_before_comparing();
	test_ffs_every_bit();
	test_legacy_extensions_present();
	test_isascii_toascii_defined_for_all_ints();
	test_underscore_tolower_toupper();
	test_assert_active_before_ndebug();
	test_assert_inactive_under_ndebug();
	test_assert_active_after_ndebug_undef();
	test_assert_message_and_death(argv[0]);
	test_assert_h_defines_only_assert();
	test_assert_is_a_void_expression();
	test_utime_return_value();
	test_utime_null_sets_current_time();
	test_utime_marks_ctime();
	test_utime_errors();
	test_utime_enotdir_path_prefix();
	test_utime_enametoolong();
	test_endian_internal_consistency();

	if (!fails) printf("posix-strings: all tests passed\n");
	return fails != 0;
}
