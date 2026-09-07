/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 conformance pass over dirent.h, ctype.h,
 * locale.h, libgen.h, setjmp.h and getopt(), companion to the pass over
 * string.h/strings.h in test/posix-string.c.  Existing ad-hoc coverage in
 * test/dirent.c, test/ctype.c, test/getopt.c and test/misc.c is not
 * duplicated here except where a specific clause from the spec page
 * wasn't actually being exercised; each assertion below cites the clause
 * it checks.  See test/posix-coverage/misc.md for the full ledger.
 */
#define _GNU_SOURCE
#include "test-policy.h"
#include <dirent.h>
#include <ctype.h>
#include <stdio.h>
#include <locale.h>
#include <libgen.h>
#include <setjmp.h>
#include <signal.h>
#include <getopt.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

static int fails;
static void wr(const char *s) { const char *e = s; while (*e) e++; write(2, s, e - s); }
static void wrnum(long n) { char b[24]; int i = 23; b[i] = 0; if (n < 0) { wr("-"); n = -n; } do b[--i] = '0' + (int)(n % 10); while (n /= 10); wr(b + i); }
#define CHECK(x) do { if (!(x)) { fails++; wr(__FILE__ ":"); wrnum(__LINE__); wr(": FAIL: " #x "\n"); } } while (0)

/* ------------------------------------------------------------------ *
 * dirent.h
 *
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/opendir.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/readdir.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/rewinddir.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/seekdir.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/closedir.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/dirfd.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/scandir.html
 * ------------------------------------------------------------------ */

static void touch(const char *p)
{
	int fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0) { fails++; wr("touch failed\n"); return; }
	close(fd);
}

static void test_dirent(void)
{
	char tmpl[] = "posix_misc_dir.XXXXXX";
	char *dir, path[128];
	DIR *dp;
	struct dirent ent, *d, *r;
	int fd, n;

	dir = mkdtemp(tmpl);
	CHECK(dir != NULL);
	if (!dir) return;

	strcpy(path, dir); strcat(path, "/a");
	touch(path);

	/* opendir.html DESCRIPTION: "positioned at the first entry." */
	dp = opendir(dir);
	CHECK(dp != NULL);
	if (!dp) { rmdir(dir); return; }

	/* readdir.html DESCRIPTION: applications should set errno to 0
	 * before calling readdir(); it is unchanged when the call succeeds
	 * or when it returns NULL at end-of-directory (RETURN VALUE: "a
	 * null pointer shall be returned and errno is not changed"). */
	errno = 0;
	d = readdir(dp);
	CHECK(d != NULL && errno == 0);

	/* readdir_r: *result gets `entry`'s address on success, and the
	 * struct/return contract is a return value (0/errnum), not errno
	 * (readdir.html RETURN VALUE, readdir_r paragraph).  The first
	 * readdir() above already consumed "." (dp is positioned at "..");
	 * count the remaining entries through readdir_r(). */
	n = 0;
	for (;;) {
		int rc = readdir_r(dp, &ent, &r);
		CHECK(rc == 0);
		if (!r) break;
		n++;
		if (n > 100) { fails++; wr("readdir_r: runaway loop\n"); break; }
	}
	/* readdir_r.html/readdir.html: "*result shall have the value NULL"
	 * at end of directory. */
	CHECK(r == NULL);
	CHECK(n == 2);   /* "..", "a" (the leading "." was already consumed) */

	/* rewinddir.html RETURN VALUE: "shall not return a value" (void).
	 * DESCRIPTION: resets to the beginning of the stream -- after
	 * running it dry above, a fresh pass sees every entry again, from
	 * "." onward.  (Whether a file added or removed *after* opendir()/
	 * rewinddir() shows up is explicitly left unspecified by
	 * readdir.html DESCRIPTION, so that is not asserted here -- see
	 * test/posix-coverage/misc.md for what was observed when trying.
	 * That observation -- rewinddir()+readdir() on the same handle not
	 * seeing a file created since the last opendir()/rewinddir(), even
	 * though a *fresh* opendir() on the same path does -- was only ever
	 * run under Wine's NtQueryDirectoryFile, not real Windows. Since
	 * POSIX leaves this unspecified either way it is not a bug however
	 * it comes out; confirming it is genuine NT directory-handle
	 * enumeration-cache behaviour, rather than an artifact of Wine's own
	 * reimplementation of NtQueryDirectoryFile, needs this exact
	 * sequence -- opendir(dir); readdir() to exhaust it; create a new
	 * file in dir from a second handle/process; rewinddir(); readdir()
	 * again and check whether the new name appears -- run on this
	 * test's actual x86_64-win32 .exe under real Windows (any version;
	 * this is NTFS/NTDLL-level behaviour, not Wine-specific
	 * emulation), which no environment available to this suite
	 * provides.) */
	rewinddir(dp);
	n = 0;
	{
		int seen_dot = 0, seen_a = 0;
		while ((d = readdir(dp))) {
			n++;
			if (!strcmp(d->d_name, ".")) seen_dot = 1;
			if (!strcmp(d->d_name, "a")) seen_a = 1;
		}
		CHECK(seen_dot && seen_a && n == 3);
	}

	/* seekdir.html/telldir.html: seekdir(dp, telldir(dp)) right after a
	 * rewind is a no-op -- the very next readdir() gives the same first
	 * entry either way. */
	{
		char name1[256];
		long mark;
		rewinddir(dp);
		mark = telldir(dp);
		seekdir(dp, mark);
		CHECK(telldir(dp) == mark);
		d = readdir(dp);
		CHECK(d != NULL);
		strcpy(name1, d ? d->d_name : "");
		rewinddir(dp);
		d = readdir(dp);
		CHECK(d != NULL && !strcmp(d->d_name, name1));
	}

	/* dirfd.html RETURN VALUE: "a file descriptor for the stream
	 * pointed to by dirp" -- usable with fstat-family calls, i.e. it is
	 * a real, valid fd, not just a nonnegative token. */
	fd = dirfd(dp);
	CHECK(fd >= 0);
	CHECK(fcntl(fd, F_GETFD) != -1);

	closedir(dp);

	/* fdopendir.html ERRORS: "[ENOTDIR] The fd argument does not refer
	 * to a directory." -- pass an fd open on a plain file. */
	strcpy(path, dir); strcat(path, "/a");
	fd = open(path, O_RDONLY);
	CHECK(fd >= 0);
	if (fd >= 0) {
		errno = 0;
		CHECK(fdopendir(fd) == NULL && errno == ENOTDIR);
		close(fd);
	}

	/* opendir.html ERRORS: "[ENOTDIR] A component of dirname names an
	 * existing file that is neither a directory..." */
	strcpy(path, dir); strcat(path, "/a");
	errno = 0;
	CHECK(opendir(path) == NULL && errno == ENOTDIR);

	/* opendir.html ERRORS: "[ENOENT] A component of dirname does not
	 * name an existing directory or dirname is an empty string." */
	strcpy(path, dir); strcat(path, "/does-not-exist");
	errno = 0;
	CHECK(opendir(path) == NULL && errno == ENOENT);
	errno = 0;
	CHECK(opendir("") == NULL && errno == ENOENT);

	/* closedir.html RETURN VALUE: 0 on success. */
	dp = opendir(dir);
	CHECK(dp != NULL);
	if (dp) CHECK(closedir(dp) == 0);

	/* Clean up. */
	strcpy(path, dir); strcat(path, "/a"); unlink(path);
	rmdir(dir);
}

/* d_type / DT_* are NOT in POSIX.1-2017: opendir.html/readdir.html only
 * mandate d_ino and d_name in "struct dirent" -- verified by reading
 * both pages end to end, neither mentions d_type or any DT_* constant.
 * It is a BSD/GNU extension (include/dirent.h gates DT_* and
 * _DIRENT_HAVE_D_TYPE the same way glibc does), documented e.g. at
 * https://man7.org/linux/man-pages/man3/readdir.3.html under "d_type":
 * "not specified in POSIX.1... available on most BSD systems... on
 * Linux". Tested here as an extension against its own documented
 * contract, not folded into the POSIX table above. spicule's NT backend
 * (src/dirent/nt/plat_dirent.c's dtype_from_attrs(), formerly
 * dirent_internal.h's __dirent_dtype()) only ever returns DT_LNK
 * (reparse points), DT_DIR or DT_REG -- DT_FIFO/DT_CHR/DT_BLK/DT_SOCK/
 * DT_WHT/DT_UNKNOWN are simply unreachable through NTFS directory
 * enumeration, so only DT_REG/DT_DIR are checked below. */
static void test_dtype(void)
{
	char tmpl[] = "posix_misc_dtype.XXXXXX";
	char *dir, path[128], subpath[160];
	DIR *dp;
	struct dirent *d;
	int reg_ok = 0, dir_ok = 0;

	dir = mkdtemp(tmpl);
	CHECK(dir != NULL);
	if (!dir) return;

	strcpy(path, dir); strcat(path, "/f");
	touch(path);
	strcpy(subpath, dir); strcat(subpath, "/d");
	CHECK(mkdir(subpath, 0755) == 0);

	dp = opendir(dir);
	CHECK(dp != NULL);
	if (dp) {
		while ((d = readdir(dp))) {
			if (!strcmp(d->d_name, "f")) {
				CHECK(d->d_type == DT_REG);
				reg_ok = 1;
			} else if (!strcmp(d->d_name, "d")) {
				CHECK(d->d_type == DT_DIR);
				dir_ok = 1;
			} else {
				/* "." and ".." are directories too. */
				CHECK(d->d_type == DT_DIR);
			}
		}
		closedir(dp);
	}
	CHECK(reg_ok && dir_ok);

	unlink(path);
	rmdir(subpath);
	rmdir(dir);
}

/* readdir()'s [EOVERFLOW] is fenced N/A below, and the fence's premise
 * is a set of type widths.  A width is exactly the kind of premise that
 * can stop being true in a commit that never looks at this file, so it
 * is asserted at compile time here rather than only described in prose:
 * if either of these ever fails, the fence below is wrong and the build
 * says so instead of the fence quietly lying.
 *
 * What has to hold, per field of struct dirent that readdir() fills
 * (src/dirent/readdir.c's make_real()):
 *
 *   d_ino = (ino_t)fi->FileId.  NT's FileId in
 *     FILE_ID_BOTH_DIR_INFORMATION is 64-bit, so ino_t must be at least
 *     64-bit for the assignment to be exact.
 *
 *   d_off = dp->tell.  Note this is NOT 64-bit, contrary to what this
 *     fence used to claim: dp->tell is declared `long`
 *     (src/dirent/dirent_internal.h:52), which is 32 bits on BOTH
 *     targets -- i386, and x86_64 because Windows is LLP64.  The old
 *     text said "both are 64-bit already", which was simply wrong about
 *     this field.  The conclusion survives because the error was in the
 *     conservative direction: a 32-bit counter WIDENING into a 64-bit
 *     off_t cannot overflow it.  What the assertion below pins is that
 *     relationship -- off_t at least as wide as dp->tell -- rather than
 *     a specific width for either. */
/* C99 build (-std=c99), so no static_assert: the negative-array idiom
 * instead, which fails at compile time exactly the same way. */
typedef char eoverflow_fence_needs_64bit_ino_t[sizeof(ino_t) >= 8 ? 1 : -1];
typedef char eoverflow_fence_needs_off_t_at_least_as_wide_as_long[sizeof(off_t) >= sizeof(long) ? 1 : -1];

#if SPICULE_TEST(NA, posix_misc_readdir_eoverflow) /* N/A: readdir.html/readdir_r.html ERRORS, the "shall fail"
       * (mandatory-when-triggered, not optional) list: "[EOVERFLOW]
       * One of the values in the structure to be returned cannot be
       * represented correctly." Checked against the live spec page
       * (not the ledger, which lumped this in with the optional "may
       * fail" list -- it is not).
       *
       * Neither field readdir() fills can hold a value its type cannot
       * represent, so the triggering condition is unreachable -- not
       * merely hard to arrange.  d_ino takes NT's 64-bit FileId into a
       * 64-bit ino_t, exactly; d_off takes the 32-bit `long` dp->tell
       * counter into a 64-bit off_t, a widening.  Both relationships
       * are pinned by the static assertions above, so this fence
       * cannot outlive its premise.
       *
       * Not arch-conditional, despite what
       * test/verification-coverage-accounting.md's C5 row supposed:
       * ino_t and off_t are not defined per-arch at all.  Both come
       * from the SHARED include/alltypes.h.in (`TYPEDEF _Int64 off_t;`,
       * `TYPEDEF unsigned _Int64 ino_t;`), and arch/i386 and
       * arch/x86_64 contribute only the _Int64 macro, which both define
       * identically as `long long`.  There is no i386-narrows-off_t
       * path to worry about; the assertions above cover the case
       * anyway. */
static void test_readdir_eoverflow(void)
{
	DIR *dp = opendir(".");
	struct dirent *d;

	CHECK(dp != NULL);
	if (!dp) return;
	errno = 0;
	d = readdir(dp);
	/* what the clause requires, once a value truly does not fit: */
	CHECK(d == NULL && errno == EOVERFLOW);
	closedir(dp);
}
#endif

#if SPICULE_TEST(NA, posix_misc_readdir_enoent_position) /* N/A: readdir.html/readdir_r.html ERRORS, the "may fail"
       * (optional) list: "[ENOENT] The current position of the
       * directory stream is invalid." POSIX "may fail" conditions are
       * explicitly optional -- a conformant implementation need not
       * detect or report them at all (base definitions, "may fail"
       * introductory text: these are conditions an implementation MAY
       * support detecting, not conditions it must). spicule's
       * seekdir()/telldir() positions are plain dp->tell values fed
       * back into a linear NtQueryDirectoryFile restart-scan count
       * (src/dirent/seekdir.c); there is no encoding of "invalid"
       * distinct from "past the current end", which readdir() already
       * handles as ordinary end-of-directory (NULL, errno unchanged)
       * per the DESCRIPTION -- not ENOENT. Implementing ENOENT
       * detection here would mean inventing an out-of-band "invalid"
       * marker with no NT concept behind it, purely to satisfy an
       * optional clause; not done. */
static void test_readdir_enoent_position(void)
{
	DIR *dp = opendir(".");
	struct dirent *d;

	CHECK(dp != NULL);
	if (!dp) return;
	seekdir(dp, 999999L); /* an invalid/unreachable position */
	errno = 0;
	d = readdir(dp);
	CHECK(d == NULL && errno == ENOENT);
	closedir(dp);
}
#endif

/* ------------------------------------------------------------------ *
 * ctype.h
 *
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/isalnum.html
 *
 * "The c argument is an int, the value of which the application shall
 * ensure is representable as an unsigned char or equal to the value of
 * the macro EOF. If the argument has any other value, the behavior is
 * undefined."  test/ctype.c already checks every unsigned-char value
 * plus EOF against the expected classification/case-mapping; what it
 * does not check is the specific "negative char promoted to int" trap
 * this clause exists to warn about, and that plain char in this
 * environment is signed (so the trap is real and not vacuous here).
 * ------------------------------------------------------------------ */

static void test_ctype(void)
{
	char c = (char)0x80;    /* char with the top bit set */
	int i;

	/* Confirm plain char is signed on this target: this is exactly the
	 * "argument not representable as unsigned char" trap the clause
	 * above warns about -- ctype functions must not be called with a
	 * bare negative char, and this is why. */
	CHECK(c < 0);

	/* isalpha((unsigned char)c) / isalpha((int)(unsigned char)c) is the
	 * correct, defined call; confirm it does not crash and gives a
	 * stable, self-consistent answer across the full unsigned-char
	 * domain plus EOF (test/ctype.c already asserts the *value* against
	 * the classification tables; this just confirms EOF specifically,
	 * called out by name in the clause, behaves as "false for every
	 * is*() classifier"). */
	CHECK(isalnum(EOF) == 0 && isalpha(EOF) == 0 && isdigit(EOF) == 0);
	CHECK(isspace(EOF) == 0 && iscntrl(EOF) == 0 && isprint(EOF) == 0);
	CHECK(isupper(EOF) == 0 && islower(EOF) == 0 && ispunct(EOF) == 0);
	CHECK(isgraph(EOF) == 0 && isxdigit(EOF) == 0 && isblank(EOF) == 0);
	/* toupper/tolower on a value with no defined mapping (EOF, or any
	 * unsigned-char value with no case pair) return it unchanged:
	 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/toupper.html
	 * "if the argument is not lowercase, it is returned unchanged." */
	CHECK(toupper(EOF) == EOF && tolower(EOF) == EOF);
	for (i = 0; i < 256; i++)
		if (!isupper(i)) CHECK(tolower(i) == i || (i >= 'A' && i <= 'Z'));
	for (i = 0; i < 256; i++)
		if (!islower(i)) CHECK(toupper(i) == i || (i >= 'a' && i <= 'z'));
}

/* ------------------------------------------------------------------ *
 * locale.h
 *
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/setlocale.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/localeconv.html
 *
 * test/misc.c and test/getopt.c already check the "C"/"POSIX"/NULL/
 * unsupported-name and decimal_point/thousands_sep/frac_digits cases.
 * What's added here: the exact CHAR_MAX (not a hardcoded 127) contract
 * for the "not available in this locale" char members
 * (localeconv.html DESCRIPTION: "the value is not available ... any of
 * which can be {CHAR_MAX}"), and that decimal_point is the one string
 * member the C locale may NOT leave empty (ISO C: it must be non-empty
 * in every locale).
 * ------------------------------------------------------------------ */

static void test_locale(void)
{
	struct lconv *lc = localeconv();

	CHECK(lc != NULL);
	if (!lc) return;
	CHECK(*lc->decimal_point != 0);
	CHECK(lc->frac_digits == CHAR_MAX);
	CHECK(lc->int_frac_digits == CHAR_MAX);
	CHECK(lc->p_cs_precedes == CHAR_MAX && lc->n_cs_precedes == CHAR_MAX);
	CHECK(lc->p_sign_posn == CHAR_MAX && lc->n_sign_posn == CHAR_MAX);

	/* setlocale.html RETURN VALUE: "A null pointer shall be returned
	 * and the global locale shall not be changed" on an unsupported
	 * name -- confirm the *global state*, not just the return value:
	 * a later NULL query still reports "C". */
	CHECK(setlocale(LC_ALL, "bogus_XX") == NULL);
	CHECK(!strcmp(setlocale(LC_ALL, NULL), "C"));

	/* setlocale.html: composite LC_ALL name form other than the plain
	 * category names, still resolving to "C" is an spicule-specific
	 * shortcut (see src/misc/locale.c), not a POSIX requirement -- not
	 * asserted here as a spec clause.  Every individual category
	 * accepts "C"/"POSIX"/NULL (setlocale.html DESCRIPTION lists all of
	 * LC_COLLATE/CTYPE/MONETARY/NUMERIC/TIME/MESSAGES). */
	CHECK(!strcmp(setlocale(LC_COLLATE, "C"), "C"));
	CHECK(!strcmp(setlocale(LC_MONETARY, "POSIX"), "C"));
	CHECK(!strcmp(setlocale(LC_TIME, "C"), "C"));
	CHECK(!strcmp(setlocale(LC_MESSAGES, "C"), "C"));
}

/* ------------------------------------------------------------------ *
 * libgen.h
 *
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/basename.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/dirname.html
 *
 * The EXAMPLES table from basename.html (dirname's outputs are given in
 * the same table).  Both functions may modify the argument -- pass a
 * writable copy each time (basename.html DESCRIPTION: "may modify the
 * string pointed to by path").  spicule's Windows drive-letter handling
 * is an extension POSIX does not describe: asserted separately below,
 * not mixed into the POSIX table.
 * ------------------------------------------------------------------ */

static void check_pair(const char *in, const char *wantbase, const char *wantdir)
{
	char buf[64];
	const char *r;

	strcpy(buf, in);
	r = basename(buf);
	if (strcmp(r, wantbase)) {
		fails++;
		wr("FAIL basename(\""); wr(in); wr("\") = \""); wr(r); wr("\", want \""); wr(wantbase); wr("\"\n");
	}
	strcpy(buf, in);
	r = dirname(buf);
	if (strcmp(r, wantdir)) {
		fails++;
		wr("FAIL dirname(\""); wr(in); wr("\") = \""); wr(r); wr("\", want \""); wr(wantdir); wr("\"\n");
	}
}

static void test_libgen(void)
{
	/* basename.html EXAMPLES table, verbatim. "//" is documented as
	 * "/" or "//" (ambiguous by design) -- not asserted. */
	check_pair("usr", "usr", ".");
	check_pair("usr/", "usr", ".");
	check_pair("", ".", ".");
	check_pair("/", "/", "/");
	check_pair("///", "/", "/");
	check_pair("/usr/", "usr", "/");
	check_pair("/usr/lib", "lib", "/usr");
	check_pair("//usr//lib//", "lib", "//usr");
	check_pair("/home//dwc//test", "test", "/home//dwc");

	/* spicule extension, not POSIX: Windows drive-letter prefixes are
	 * kept with the directory half and never treated as part of the
	 * basename. */
	check_pair("C:\\x\\y", "y", "C:\\x");
	check_pair("C:\\", "\\", "C:\\");
	check_pair("C:/foo", "foo", "C:/");
	check_pair("C:foo", "foo", "C:");
}

/* ------------------------------------------------------------------ *
 * setjmp.h
 *
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/setjmp.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/longjmp.html
 *
 * test/misc.c already covers: setjmp returns 0 direct / nonzero via
 * longjmp, longjmp(env,0) yields 1, multiple returns through the same
 * buffer, nesting, and crossing several stack frames / a 100-deep
 * recursion.  Added here: the exact "yields the value specified by
 * val" clause for a handful of nonzero values (not just spot-checked
 * once), volatile-preservation phrased as the spec phrases it (objects
 * *not* volatile-qualified and changed between setjmp/longjmp are
 * unspecified -- so the test only asserts about a volatile), and
 * sigsetjmp/siglongjmp (not exercised anywhere else in the suite).
 * ------------------------------------------------------------------ */

static jmp_buf jb;
static sigjmp_buf sjb;

static void test_setjmp(void)
{
	volatile int v;
	int r, i;

	/* longjmp.html RETURN VALUE: "execution continues as if the
	 * corresponding invocation of setjmp() had just returned the value
	 * specified by val" -- for several distinct nonzero values. */
	for (i = 1; i <= 5; i++) {
		r = setjmp(jb);
		if (r == 0) longjmp(jb, i);
		CHECK(r == i);
	}
	/* val==0 special case, restated per longjmp.html RETURN VALUE:
	 * "shall not cause setjmp() to return 0; if val is 0, setjmp()
	 * shall return 1." */
	r = setjmp(jb);
	if (r == 0) longjmp(jb, 0);
	CHECK(r == 1);

	/* longjmp.html DESCRIPTION: values of automatic objects that ARE
	 * volatile-qualified and were changed between setjmp() and
	 * longjmp() ARE preserved (this is the converse of the
	 * "unspecified for non-volatile" clause: it only disclaims
	 * non-volatile objects, implying volatile ones are well-defined). */
	v = 1;
	r = setjmp(jb);
	if (r == 0) {
		v = 42;
		longjmp(jb, 1);
	}
	CHECK(v == 42);

	/* sigsetjmp/siglongjmp: same value contract as plain setjmp/longjmp. */
	r = sigsetjmp(sjb, 1);
	if (r == 0) siglongjmp(sjb, 7);
	CHECK(r == 7);
	r = sigsetjmp(sjb, 0);
	if (r == 0) siglongjmp(sjb, 0);
	CHECK(r == 1);
	{
		sigset_t one, cur;
		sigemptyset(&one);
		sigaddset(&one, SIGUSR1);
		CHECK(sigprocmask(SIG_UNBLOCK, &one, NULL) == 0);
		r = sigsetjmp(sjb, 1);
		if (r == 0) {
			CHECK(sigprocmask(SIG_BLOCK, &one, NULL) == 0);
			siglongjmp(sjb, 1);
		}
		CHECK(sigprocmask(SIG_BLOCK, NULL, &cur) == 0);
		CHECK(sigismember(&cur, SIGUSR1) == 0);

		r = sigsetjmp(sjb, 0);
		if (r == 0) {
			CHECK(sigprocmask(SIG_BLOCK, &one, NULL) == 0);
			siglongjmp(sjb, 1);
		}
		CHECK(sigprocmask(SIG_BLOCK, NULL, &cur) == 0);
		CHECK(sigismember(&cur, SIGUSR1) == 1);
		CHECK(sigprocmask(SIG_UNBLOCK, &one, NULL) == 0);
	}

	/* _setjmp/_longjmp (XSI, obsolescent).
	 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/_longjmp.html
	 * DESCRIPTION: they "shall be equivalent to longjmp() and setjmp(),
	 * respectively, with the additional restriction that _longjmp() and
	 * _setjmp() shall not manipulate the signal mask"; RETURN VALUE
	 * defers to longjmp/setjmp; ERRORS: "No errors are defined."  These
	 * two had no assertion anywhere in the test/ tree before this
	 * (test/POSIX-GAP-ACCOUNTING.md's <setjmp.h> pair), even though
	 * src/setjmp/{i386,x86_64}/setjmp.S and longjmp.S both export the
	 * underscored names as aliases of the plain ones.
	 *
	 * Unlike sigsetjmp()/siglongjmp() above, these entry points do not
	 * save or restore the signal mask. */
	for (i = 1; i <= 5; i++) {
		r = _setjmp(jb);
		if (r == 0) _longjmp(jb, i);
		CHECK(r == i);
	}
	r = _setjmp(jb);
	if (r == 0) _longjmp(jb, 0);
	CHECK(r == 1);

	/* The mask really is untouched across the pair. */
	{
		sigset_t before, after;
		sigemptyset(&before);
		sigaddset(&before, SIGUSR1);
		CHECK(sigprocmask(SIG_SETMASK, &before, NULL) == 0);
		r = _setjmp(jb);
		if (r == 0) {
			sigset_t none;
			sigemptyset(&none);
			CHECK(sigprocmask(SIG_SETMASK, &none, NULL) == 0);
			_longjmp(jb, 3);
		}
		CHECK(r == 3);
		CHECK(sigprocmask(SIG_BLOCK, NULL, &after) == 0);
		CHECK(sigismember(&after, SIGUSR1) == 0);
		sigemptyset(&before);
		CHECK(sigprocmask(SIG_SETMASK, &before, NULL) == 0);
	}
}

/* ------------------------------------------------------------------ *
 * getopt() (unistd.h)
 *
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/getopt.html
 *
 * test/getopt.c already covers: basic short-opt parsing, clustering,
 * required-argument attachment, permutation, "--" termination, and the
 * unknown-option / missing-argument cases both with and without a
 * leading ':'.  Added here: opterr suppressing messages independent of
 * the ':' mechanism (opterr.html: "if opterr is nonzero ... getopt()
 * shall print a diagnostic message"), and optind/argv left exactly at
 * "--"'s position per the clause quoted below.
 * ------------------------------------------------------------------ */

static void test_getopt(void)
{
	char *av1[] = { "prog", "--", "-a", 0 };
	int c;

	/* getopt.html DESCRIPTION: "--" argument "shall be discarded... and
	 * -1 shall be returned"; optind is left pointing one past it, at
	 * the first operand. */
	optind = 1;
	c = getopt(3, av1, "a");
	CHECK(c == -1);
	CHECK(optind == 2);
	CHECK(!strcmp(av1[optind], "-a"));

	/* opterr controls whether getopt() writes anything to stderr for an
	 * unknown option; this cannot be captured portably here (stderr may
	 * be redirected by run-tests.py), so only the return-value contract
	 * (independent of opterr) is asserted: an unknown option still
	 * yields '?' and sets optopt regardless of opterr. */
	{
		char *av2[] = { "prog", "-z", 0 };
		optind = 1;
		opterr = 0;
		c = getopt(2, av2, "a");
		CHECK(c == '?' && optopt == 'z');
		opterr = 1;
	}
}

int main(void)
{
	test_dirent();
	test_dtype();
	test_ctype();
	test_locale();
	test_libgen();
	test_setjmp();
	test_getopt();

	if (fails) { wr("posix-misc: failures: "); wrnum(fails); wr("\n"); return 1; }
	wr("posix-misc: all ok\n");
	return 0;
}
