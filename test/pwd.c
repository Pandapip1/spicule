/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of <pwd.h>
 * (pwd.h.html, getpwnam.html, getpwuid.html, getpwent.html) against
 * src/misc/pwd.c.  See that file's header comment for the design:
 * spicule has exactly one uid (getuid()/geteuid() always agree, per
 * src/unistd/ids.c and test/posix-unistd.c's own coverage of that),
 * and this file checks that getpwuid()/getpwnam() answer honestly for
 * that one user and refuse cleanly for anyone else.
 *
 * Every test below is written against `have_user`, not against "does
 * Wine set %USERNAME%": src/misc/pwd.c's whole design is "refuse
 * cleanly rather than fabricate" when the current user's name is not
 * in the environment, and this file's own native (non-Wine) `make
 * asan` run is a real instance of exactly that -- fuzz/ntstubs.c's
 * process shim deliberately starts environ empty (see its own
 * comment, "the test harness's own, arbitrary environment" -- it is
 * kept out on purpose so native tests are deterministic), so
 * %USERNAME%/%USER% are genuinely unset there.  Both branches are
 * therefore exercised for real by this one test binary depending on
 * which harness runs it, rather than one of them being dead code.
 */
/* setenv()/unsetenv()/mkdtemp() are gated behind a feature-test macro
 * in this project's own headers (Makefile's CFLAGS_ALL comment:
 * "_ALL_SOURCE ... is for the library itself, not for programs" -- a
 * consuming TU opts in itself, same as test/posix-time.c/test/posix-
 * unistd.c already do); needed by this file's pre-existing NT-side
 * setenv() use below and, now, by the Linux-side fixture tests this
 * pass adds further down. */
#define _GNU_SOURCE
#include <pwd.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* This whole file, up to the #else below, audits src/misc/nt/pwd.c's
 * single-user-synthesis <pwd.h> (the file this file's own header
 * comment already describes) -- accurate for NT, but no longer for
 * Linux now that src/misc/linux/pwd.c gives Linux a REAL, file-backed
 * <pwd.h> (see that file's own header for why the split happened).
 * Every assertion below assumes "the database has at most one entry,
 * known only through %USERNAME%/%USER%", which is simply false against
 * a real /etc/passwd -- getuid()+1, for instance, is routinely a real
 * second user on any real multi-account Linux host. Rather than adapt
 * each assertion individually (most of them would stop asserting
 * anything meaningful once the one-entry premise is gone), this is
 * gated out entirely on Linux and replaced, in the #else branch, with
 * a real audit of src/misc/linux/pwd.c's own actual behavior. */
#ifndef __linux__

/* Mirrors src/misc/pwd.c's current_name(): whether this process's
 * environment lets the library know who "the current user" is at
 * all. */
static int have_user(void)
{
	const char *n = getenv("USERNAME");
	if (!n || !*n) n = getenv("USER");
	return n && *n;
}

/* pwd.h.html: "at least" pw_name/pw_uid/pw_gid/pw_dir/pw_shell, and
 * getpwuid.html DESCRIPTION: search by uid.  getuid()==geteuid()
 * always here (test/posix-unistd.c), so getuid() is the only uid that
 * can ever have an entry -- when the name behind it is knowable at
 * all (see have_user() above). */
static void test_getpwuid_current(void)
{
	struct passwd *pw;

	errno = 0;
	pw = getpwuid(getuid());
	if (!have_user()) {
		/* getpwuid.html RETURN VALUE: "If the requested entry was
		 * not found, errno shall not be changed." -- the honest
		 * answer when the name is unknowable is "not found", same
		 * as for any other uid. */
		CHECK(pw == NULL);
		CHECK(errno == 0);
		return;
	}
	CHECK(pw != NULL);
	if (!pw) return;
	CHECK(pw->pw_uid == getuid());
	CHECK(pw->pw_gid == getgid());
	CHECK(pw->pw_name != NULL && pw->pw_name[0] != '\0');
	CHECK(pw->pw_dir != NULL && pw->pw_dir[0] != '\0');
	CHECK(pw->pw_shell != NULL && pw->pw_shell[0] != '\0');
}

/* getpwuid.html RETURN VALUE: "If the requested entry was not found,
 * errno shall not be changed." spicule has exactly one uid, so any
 * other value is "not found" by definition, regardless of
 * have_user(). */
static void test_getpwuid_other_not_found(void)
{
	struct passwd *pw;

	errno = 12345;
	pw = getpwuid(getuid() + 1);
	CHECK(pw == NULL);
	CHECK(errno == 12345);
}

/* getpwnam.html DESCRIPTION: search by name.  Round-trip:
 * getpwnam(getpwuid(getuid())->pw_name) must be the same record --
 * both are sourced from src/misc/pwd.c's current_name(), so a mismatch
 * here would be a real bug, not just a design gap. */
static void test_getpwnam_current_and_roundtrip(void)
{
	struct passwd *by_uid, *by_name;
	char namebuf[256];

	by_uid = getpwuid(getuid());
	if (!have_user()) {
		CHECK(by_uid == NULL);
		/* nothing to round-trip without a name */
		return;
	}
	CHECK(by_uid != NULL);
	if (!by_uid) return;
	/* g_pw is static storage, reused by the next getpwnam() call --
	 * snapshot the name first. */
	strcpy(namebuf, by_uid->pw_name);

	errno = 0;
	by_name = getpwnam(namebuf);
	CHECK(by_name != NULL);
	CHECK(errno == 0);
	if (!by_name) return;
	CHECK(strcmp(by_name->pw_name, namebuf) == 0);
	CHECK(by_name->pw_uid == getuid());
	CHECK(by_name->pw_gid == getgid());
}

static void test_getpwnam_other_not_found(void)
{
	struct passwd *pw;

	errno = 12345;
	pw = getpwnam("definitely-not-a-real-spicule-user-xyz");
	CHECK(pw == NULL);
	CHECK(errno == 12345);
}

/* getpwuid_r/getpwnam_r (Thread-Safe Functions option): "shall return
 * zero" on success or clean not-found; error number returned directly,
 * not via errno; *result set to NULL on both error and not-found. */
static void test_getpwuid_r_success(void)
{
	struct passwd pw, *result = (struct passwd *)0x1;
	char buf[512];
	int r;

	r = getpwuid_r(getuid(), &pw, buf, sizeof buf, &result);
	CHECK(r == 0);
	if (!have_user()) {
		CHECK(result == NULL);
		return;
	}
	CHECK(result == &pw);
	CHECK(pw.pw_uid == getuid());
	CHECK(pw.pw_gid == getgid());
	CHECK(pw.pw_name != NULL && pw.pw_name[0] != '\0');
	CHECK(pw.pw_dir != NULL && pw.pw_dir[0] != '\0');
	CHECK(pw.pw_shell != NULL && pw.pw_shell[0] != '\0');
}

static void test_getpwuid_r_not_found(void)
{
	struct passwd pw, *result = (struct passwd *)0x1;
	char buf[512];
	int r;

	r = getpwuid_r(getuid() + 1, &pw, buf, sizeof buf, &result);
	CHECK(r == 0);
	CHECK(result == NULL);
}

/* ERANGE: "Insufficient storage was supplied via buffer and bufsize."
 * Only observable when there is a record to try to pack in the first
 * place -- without have_user(), getpwuid_r() reports "not found"
 * before it ever looks at bufsize, exactly like getpwuid_r_not_found
 * above. */
static void test_getpwuid_r_erange(void)
{
	struct passwd pw, *result = (struct passwd *)0x1;
	char buf[1];
	int r;

	r = getpwuid_r(getuid(), &pw, buf, sizeof buf, &result);
	if (!have_user()) {
		CHECK(r == 0);
		CHECK(result == NULL);
		return;
	}
	CHECK(r == ERANGE);
	CHECK(result == NULL);
}

static void test_getpwnam_r_success_and_not_found(void)
{
	struct passwd pw, *result;
	char buf[512];
	char namebuf[256];
	int r;

	if (!have_user()) {
		result = (struct passwd *)0x1;
		r = getpwnam_r("whoever", &pw, buf, sizeof buf, &result);
		CHECK(r == 0);
		CHECK(result == NULL);
		return;
	}

	result = (struct passwd *)0x1;
	r = getpwuid_r(getuid(), &pw, buf, sizeof buf, &result);
	CHECK(r == 0 && result == &pw);
	if (r != 0 || !result) return;
	strcpy(namebuf, pw.pw_name);

	result = (struct passwd *)0x1;
	r = getpwnam_r(namebuf, &pw, buf, sizeof buf, &result);
	CHECK(r == 0);
	CHECK(result == &pw);
	CHECK(pw.pw_uid == getuid());

	result = (struct passwd *)0x1;
	r = getpwnam_r("definitely-not-a-real-spicule-user-xyz", &pw, buf, sizeof buf, &result);
	CHECK(r == 0);
	CHECK(result == NULL);
}

static void test_getpwnam_r_erange(void)
{
	struct passwd pw, *result = (struct passwd *)0x1;
	char buf[1];
	char namebuf[256];
	struct passwd *cur;

	if (!have_user()) {
		result = (struct passwd *)0x1;
		CHECK(getpwnam_r("whoever", &pw, buf, sizeof buf, &result) == 0);
		CHECK(result == NULL);
		return;
	}

	cur = getpwuid(getuid());
	CHECK(cur != NULL);
	if (!cur) return;
	strcpy(namebuf, cur->pw_name);

	result = (struct passwd *)0x1;
	CHECK(getpwnam_r(namebuf, &pw, buf, sizeof buf, &result) == ERANGE);
	CHECK(result == NULL);
}

/* getpwent.html: XSI, but implementable here -- spicule's "database"
 * genuinely has one entry when the current user's name is knowable,
 * and none at all otherwise.  setpwent() rewinds; the first
 * getpwent() yields the one entry (or immediate end-of-file without
 * have_user()); the next call always hits end-of-file (NULL, errno
 * unchanged); setpwent() rewinds again. */
static void test_getpwent_one_entry_then_eof(void)
{
	struct passwd *pw;

	setpwent();
	errno = 0;
	pw = getpwent();
	if (have_user()) {
		CHECK(pw != NULL);
		if (pw) CHECK(pw->pw_uid == getuid());
	} else {
		CHECK(pw == NULL);
		CHECK(errno == 0);
	}

	errno = 0;
	pw = getpwent();
	CHECK(pw == NULL);
	CHECK(errno == 0);

	setpwent();
	pw = getpwent();
	CHECK((pw != NULL) == have_user());
	endpwent();
}

/* The motivating case: "~" (current user, no name after the tilde)
 * expansion, the way glob(3)/gnulib's glob.c resolves it --
 * look up the current login name via getpwnam() and use pw_dir as the
 * expansion, then confirm that directory is real and usable, not just
 * a non-NULL string.  Only meaningful when have_user() -- without a
 * name there is nothing glob.c could look up either, and it declines
 * the same way getpwnam() does here (NULL, not a fabricated guess). */
static void test_tilde_expansion_current_user(void)
{
	struct passwd *me, *pw;
	struct stat st;

	me = getpwuid(getuid());
	if (!have_user()) {
		CHECK(me == NULL);
		printf("note: %%USERNAME%%/%%USER%% unset in this harness -- '~' is correctly left unexpandable\n");
		return;
	}
	CHECK(me != NULL);
	if (!me) return;
	pw = getpwnam(me->pw_name);
	CHECK(pw != NULL);
	if (!pw) return;
	CHECK(pw->pw_dir != NULL && pw->pw_dir[0] != '\0');
	CHECK(stat(pw->pw_dir, &st) == 0);
	CHECK(S_ISDIR(st.st_mode));
}


/* ==== clauses the successor-queue <pwd.h> audit added ==================== */

/* getpwuid.html DESCRIPTION: "The getpwuid() function shall search the
 * user database for an entry with a matching uid." RETURN VALUE: "A
 * null pointer shall be returned if the requested entry is not found
 * ... If the requested entry was not found, errno shall not be
 * changed."
 *
 * The existing not-found tests use getuid()+1, which is adjacent to the
 * one uid that does exist. This uses a uid that could not plausibly be
 * anything on any system, to pin that the answer is a real lookup
 * rather than a fabricated entry handed out for any argument -- the
 * failure mode a degenerate one-entry database is most at risk of. */
static void test_getpwuid_absurd_uid(void)
{
	errno = 12345;
	CHECK(getpwuid((uid_t)0x7ffffffe) == NULL);
	CHECK(errno == 12345);
	errno = 12345;
	CHECK(getpwnam("no-such-user-could-ever-be-called-this") == NULL);
	CHECK(errno == 12345);
}

/* getpwnam.html RETURN VALUE: "The getpwnam_r() function shall return
 * zero on success or if the requested entry was not found and no error
 * has occurred", with "a null pointer ... at the location pointed to
 * by result". Not-found is *not* an error for the _r form -- returning
 * non-zero for it would be the defect. Checked here on a uid that
 * certainly does not exist, complementing the existing getuid()+1
 * test. */
static void test_getpwuid_r_absurd_uid(void)
{
	struct passwd pw;
	struct passwd *result = (struct passwd *)0x1;	/* poisoned sentinel */
	char buf[512];

	CHECK(getpwuid_r((uid_t)0x7ffffffe, &pw, buf, sizeof buf, &result) == 0);
	CHECK(result == NULL);
	result = (struct passwd *)0x1;
	CHECK(getpwnam_r("no-such-user-could-ever-be-called-this", &pw, buf, sizeof buf, &result) == 0);
	CHECK(result == NULL);
}

/* setpwent.html DESCRIPTION: "The setpwent() function shall rewind the
 * user database so that the next getpwent() call returns the first
 * entry"; endpwent.html: "The endpwent() function shall close the user
 * database." getpwent.html: "If the database is not already open,
 * getpwent() shall open it and return ... the first entry."
 *
 * So endpwent() followed by getpwent() must re-yield the first entry,
 * not stay at end-of-file. test_getpwent_one_entry_then_eof() calls
 * endpwent() only as its last statement and never reads after it, so
 * this path was never exercised.
 *
 * setpwent.html/endpwent.html also both say the function "shall not
 * change the setting of errno if successful", which nothing checked. */
static void test_pwent_reopen_and_errno(void)
{
	struct passwd *pw;

	setpwent();
	(void)getpwent();
	(void)getpwent();		/* at end-of-file now */
	CHECK(getpwent() == NULL);

	endpwent();			/* closes the database ... */
	pw = getpwent();		/* ... so this must reopen it */
	CHECK((pw != NULL) == have_user());

	errno = 12345;
	setpwent();
	CHECK(errno == 12345);
	errno = 12345;
	endpwent();
	CHECK(errno == 12345);
}

/* getpwnam.html ERRORS, [ERANGE]: "Insufficient storage was supplied
 * via buffer and bufsize to contain the data to be referenced by the
 * resulting passwd structure." The existing ERANGE tests use a
 * one-byte buffer, which cannot tell a correct size computation from
 * one that simply rejects anything small. This pins the boundary: a
 * buffer one byte short of what the record needs must fail, and one of
 * exactly that size must succeed. The needed size is derived the same
 * way src/misc/pwd.c does -- the three strings plus their terminators
 * -- rather than guessed. */
static void test_getpwuid_r_erange_boundary(void)
{
	struct passwd pw;
	struct passwd *result;
	char buf[9000];
	size_t need;
	const char *dir, *shell;

	if (!have_user()) {
		printf("note: no user name knowable -- skipping the ERANGE boundary (getpwuid_r() answers \"not found\" before it ever sizes a buffer)\n");
		return;
	}
	result = NULL;
	CHECK(getpwuid_r(getuid(), &pw, buf, sizeof buf, &result) == 0);
	CHECK(result == &pw);
	if (result != &pw) return;
	dir = pw.pw_dir;
	shell = pw.pw_shell;
	need = strlen(pw.pw_name) + 1 + strlen(dir) + 1 + strlen(shell) + 1;

	result = (struct passwd *)0x1;
	CHECK(getpwuid_r(getuid(), &pw, buf, need - 1, &result) == ERANGE);
	CHECK(result == NULL);
	result = NULL;
	CHECK(getpwuid_r(getuid(), &pw, buf, need, &result) == 0);
	CHECK(result == &pw);
}

/* pwd.h.html: "The <pwd.h> header shall define the struct passwd
 * structure ... pw_name, pw_uid, pw_gid, pw_dir, pw_shell." Note the
 * fetched POSIX.1-2017 text lists exactly those five -- pw_passwd and
 * pw_gecos are *not* required, so omitting them is conformant rather
 * than a gap. The existing tests read all five; this records the
 * cross-function consistency the header implies, and that pw_name
 * agrees with getlogin(), which src/misc/pwd.c's current_name() is a
 * private copy of. */
static void test_pw_name_matches_getlogin(void)
{
	struct passwd *pw;
	char *login;

	if (!have_user()) return;
	pw = getpwuid(getuid());
	CHECK(pw != NULL);
	login = getlogin();
	CHECK(login != NULL);
	if (pw && login) CHECK(strcmp(pw->pw_name, login) == 0);
}

static void test_getpwuid_erange_not_in_its_errno_list(void)
{
	static char big[9000];
	struct passwd *pw;
	char *saved_username = getenv("USERNAME");
	char *saved_user = getenv("USER");
	char keep_username[256], keep_user[256];
	int had_username = saved_username != NULL, had_user = saved_user != NULL;

	if (had_username) { strncpy(keep_username, saved_username, sizeof keep_username - 1); keep_username[sizeof keep_username - 1] = 0; }
	if (had_user) { strncpy(keep_user, saved_user, sizeof keep_user - 1); keep_user[sizeof keep_user - 1] = 0; }

	memset(big, 'x', sizeof big - 1);
	big[sizeof big - 1] = 0;
	CHECK(setenv("USERNAME", big, 1) == 0);

	/* The clause, not one particular remedy for it.
	 *
	 * The fence this replaces asserted `getpwuid(getuid()) == NULL`,
	 * because it had in mind the fix of treating an internal-buffer
	 * overflow as "not found".  The fix actually taken grows the buffer,
	 * so the call now SUCCEEDS and returns the real record -- which is
	 * also conforming, and better, since the user does exist.  Asserting
	 * NULL would have pinned the weaker of the two remedies and would
	 * fail against the stronger one.
	 *
	 * What getpwuid.html actually requires is that [ERANGE] -- which is
	 * listed only for getpwuid_r()/getpwnam_r(), where it describes a
	 * caller-supplied buffer -- never comes out of the non-_r form, and
	 * that "if the requested entry was not found, errno shall not be
	 * changed".  So: never ERANGE, and whichever answer is given must be
	 * self-consistent. */
	errno = 0;
	pw = getpwuid(getuid());
	CHECK(errno != ERANGE);
	if (pw) {
		/* if it succeeded it must have succeeded honestly */
		CHECK(pw->pw_name != NULL);
		CHECK(pw->pw_name && !strcmp(pw->pw_name, big));
	} else {
		/* "not found" leaves errno untouched */
		CHECK(errno == 0);
	}

	if (had_username) setenv("USERNAME", keep_username, 1); else unsetenv("USERNAME");
	if (had_user) setenv("USER", keep_user, 1); else unsetenv("USER");
}

int main(void)
{
	printf("note: have_user() = %s\n", have_user() ? "true" : "false");
	test_getpwuid_absurd_uid();
	test_getpwuid_erange_not_in_its_errno_list();
	test_getpwuid_r_absurd_uid();
	test_pwent_reopen_and_errno();
	test_getpwuid_r_erange_boundary();
	test_pw_name_matches_getlogin();

	test_getpwuid_current();
	test_getpwuid_other_not_found();
	test_getpwnam_current_and_roundtrip();
	test_getpwnam_other_not_found();
	test_getpwuid_r_success();
	test_getpwuid_r_not_found();
	test_getpwuid_r_erange();
	test_getpwnam_r_success_and_not_found();
	test_getpwnam_r_erange();
	test_getpwent_one_entry_then_eof();
	test_tilde_expansion_current_user();

	if (!fails) printf("pwd: all tests passed\n");
	return fails != 0;
}

#else /* __linux__ */

/* ====================================================================
 * Linux: a real audit of src/misc/linux/pwd.c's file-backed <pwd.h> --
 * getpwnam()/getpwuid()/getpwent()/setpwent()/endpwent() (and the _r
 * forms) against a genuine /etc/passwd, gated by a genuine
 * /etc/nsswitch.conf. Two tiers:
 *
 *   1. A handful of facts asserted against THIS HOST's real
 *      /etc/passwd, never mutated -- the same strategy test/posix-
 *      netdb.c's own getservbyname test already uses for /etc/
 *      services' "http" entry: root at uid 0 is exactly as universal a
 *      fact about a real POSIX system's user database as "http" is
 *      about its service database, and there is no standard way to
 *      point a real getpwnam() at anything else (glibc offers no
 *      configurable base directory either -- see src/internal/
 *      nss_paths.h's own banner).
 *   2. Everything else -- multi-entry enumeration, the ERANGE
 *      boundary, nsswitch.conf gating -- against a hermetic fixture
 *      tree this file builds itself in a fresh mkdtemp() directory,
 *      pointed to via this pass's own disclosed testability env-var
 *      seam (SPICULE_TEST_PASSWD_PATH/SPICULE_TEST_NSSWITCH_PATH, see
 *      src/internal/nss_paths.h), so none of it depends on this host's
 *      real user database having any particular shape.
 * ==================================================================== */

/* fixture_write(): create/replace a small text file with exactly
 * `content`, no fdopen()/buffering games -- these fixtures are a few
 * lines each. */
static void fixture_write(const char *path, const char *content)
{
	FILE *f = fopen(path, "w");
	CHECK(f != NULL);
	if (!f) return;
	CHECK(fputs(content, f) >= 0);
	fclose(f);
}

/* ---- tier 1: real /etc/passwd, read-only ---- */

static void test_linux_root_exists_by_uid(void)
{
	struct passwd *pw = getpwuid(0);
	CHECK(pw != NULL);
	if (!pw) return;
	CHECK(pw->pw_name != NULL && strcmp(pw->pw_name, "root") == 0);
	CHECK(pw->pw_dir != NULL && pw->pw_dir[0] == '/');
	CHECK(pw->pw_shell != NULL && pw->pw_shell[0] != '\0');
}

static void test_linux_root_exists_by_name(void)
{
	struct passwd *pw = getpwnam("root");
	CHECK(pw != NULL);
	if (pw) CHECK(pw->pw_uid == 0);
}

static void test_linux_absurd_lookups_not_found(void)
{
	errno = 12345;
	CHECK(getpwnam("no-such-user-could-ever-be-called-this-xyz") == NULL);
	CHECK(errno == 12345);
	errno = 12345;
	CHECK(getpwuid((uid_t)0x7ffffffe) == NULL);
	CHECK(errno == 12345);
}

static void test_linux_getpwent_reaches_root(void)
{
	struct passwd *pw;
	int i, saw_root = 0;

	setpwent();
	/* A real /etc/passwd is never anywhere near this long; the bound
	 * exists only so a real bug (an enumeration that never reaches
	 * end-of-file) fails this test instead of hanging the suite. */
	for (i = 0; i < 100000; i++) {
		pw = getpwent();
		if (!pw) break;
		if (pw->pw_uid == 0) saw_root = 1;
	}
	CHECK(saw_root);
	endpwent();
}

/* ---- tier 2: a hermetic fixture tree ---- */

#define FIX_PASSWD "fx-passwd"
#define FIX_NSSWITCH "fx-nsswitch.conf"

static void fixture_env_set(void)
{
	CHECK(setenv("SPICULE_TEST_PASSWD_PATH", FIX_PASSWD, 1) == 0);
	CHECK(setenv("SPICULE_TEST_NSSWITCH_PATH", FIX_NSSWITCH, 1) == 0);
}

static void fixture_env_clear(void)
{
	unsetenv("SPICULE_TEST_PASSWD_PATH");
	unsetenv("SPICULE_TEST_NSSWITCH_PATH");
}

/* getpwnam.html DESCRIPTION/RETURN VALUE, getpwuid.html DESCRIPTION,
 * against a small, fully-controlled two-entry database. */
static void test_linux_fixture_lookup(void)
{
	fixture_write(FIX_PASSWD,
		"alice:x:5001:5001:Alice Example:/home/alice:/bin/ash\n"
		"bob:x:5002:5002:Bob Example:/home/bob:/bin/bsh\n");
	fixture_write(FIX_NSSWITCH, "passwd: files\ngroup: files\nhosts: files dns\n");
	fixture_env_set();

	{
		struct passwd *pw = getpwnam("alice");
		CHECK(pw != NULL);
		if (pw) {
			CHECK(pw->pw_uid == 5001);
			CHECK(pw->pw_gid == 5001);
			CHECK(strcmp(pw->pw_dir, "/home/alice") == 0);
			CHECK(strcmp(pw->pw_shell, "/bin/ash") == 0);
		}
	}
	{
		struct passwd *pw = getpwuid(5002);
		CHECK(pw != NULL);
		if (pw) CHECK(strcmp(pw->pw_name, "bob") == 0);
	}
	CHECK(getpwnam("carol") == NULL);

	fixture_env_clear();
}

/* getpwent.html sequential access against the same two-entry fixture:
 * both entries in order, then a stable end-of-file, then a rewind. */
static void test_linux_fixture_getpwent_sequence(void)
{
	struct passwd *pw;

	fixture_write(FIX_PASSWD,
		"alice:x:5001:5001:Alice Example:/home/alice:/bin/ash\n"
		"bob:x:5002:5002:Bob Example:/home/bob:/bin/bsh\n");
	fixture_write(FIX_NSSWITCH, "passwd: files\n");
	fixture_env_set();

	setpwent();
	pw = getpwent();
	CHECK(pw != NULL && strcmp(pw->pw_name, "alice") == 0);
	pw = getpwent();
	CHECK(pw != NULL && strcmp(pw->pw_name, "bob") == 0);
	errno = 0;
	pw = getpwent();
	CHECK(pw == NULL);
	CHECK(errno == 0);

	setpwent();
	pw = getpwent();
	CHECK(pw != NULL && strcmp(pw->pw_name, "alice") == 0);
	endpwent();

	fixture_env_clear();
}

/* getpwnam.html ERRORS [ERANGE], boundary-pinned exactly like this
 * project's own dlfcn/grp tests do -- one byte short of what
 * fill_from_fields() (src/misc/linux/pwd.c) needs must fail, and
 * exactly that many bytes must succeed. */
static void test_linux_fixture_erange_boundary(void)
{
	struct passwd pw, *result;
	char buf[512];
	size_t need;

	fixture_write(FIX_PASSWD, "carol:x:5003:5003:Carol Example:/home/carol:/bin/csh\n");
	fixture_write(FIX_NSSWITCH, "passwd: files\n");
	fixture_env_set();

	need = strlen("carol") + 1 + strlen("/home/carol") + 1 + strlen("/bin/csh") + 1;

	result = (struct passwd *)0x1;
	CHECK(getpwnam_r("carol", &pw, buf, need - 1, &result) == ERANGE);
	CHECK(result == NULL);

	result = NULL;
	CHECK(getpwnam_r("carol", &pw, buf, need, &result) == 0);
	CHECK(result == &pw);
	if (result == &pw) {
		CHECK(pw.pw_uid == 5003);
		CHECK(strcmp(pw.pw_shell, "/bin/csh") == 0);
	}

	fixture_env_clear();
}

/* getpwuid.html ERRORS [ERANGE], same boundary-pinning style as
 * test_linux_fixture_erange_boundary() above but through getpwuid_r()
 * rather than getpwnam_r() -- the two share fill_from_fields() in
 * src/misc/linux/pwd.c but reach it through different scan_passwd()
 * match modes (MATCH_UID vs MATCH_NAME), so this exercises the uid path
 * for real rather than assuming the two are interchangeable. */
static void test_linux_fixture_erange_boundary_uid(void)
{
	struct passwd pw, *result;
	char buf[512];
	size_t need;

	fixture_write(FIX_PASSWD, "frank:x:5006:5006:Frank Example:/home/frank:/bin/fsh\n");
	fixture_write(FIX_NSSWITCH, "passwd: files\n");
	fixture_env_set();

	need = strlen("frank") + 1 + strlen("/home/frank") + 1 + strlen("/bin/fsh") + 1;

	result = (struct passwd *)0x1;
	CHECK(getpwuid_r(5006, &pw, buf, need - 1, &result) == ERANGE);
	CHECK(result == NULL);

	result = NULL;
	CHECK(getpwuid_r(5006, &pw, buf, need, &result) == 0);
	CHECK(result == &pw);
	if (result == &pw) {
		CHECK(strcmp(pw.pw_name, "frank") == 0);
		CHECK(pw.pw_gid == 5006);
		CHECK(strcmp(pw.pw_shell, "/bin/fsh") == 0);
	}

	result = (struct passwd *)0x1;
	CHECK(getpwuid_r(59999, &pw, buf, sizeof buf, &result) == 0);
	CHECK(result == NULL);

	fixture_env_clear();
}

/* This project's own nsswitch.conf gating: an admin who configures
 * "passwd" with no service this library implements gets an honest
 * "not found" for a user that genuinely IS in /etc/passwd -- the
 * backend was turned off, not silently ignored (src/misc/linux/pwd.c's
 * own header comment states this as the intended behavior). */
static void test_linux_fixture_nsswitch_disables_files(void)
{
	struct passwd *pw;

	fixture_write(FIX_PASSWD, "dave:x:5004:5004:Dave Example:/home/dave:/bin/dsh\n");
	fixture_write(FIX_NSSWITCH, "passwd: some_unimplemented_service\n");
	fixture_env_set();

	errno = 0;
	pw = getpwnam("dave");
	CHECK(pw == NULL);
	CHECK(errno == 0);

	fixture_env_clear();
}

/* A missing nsswitch.conf falls back to this project's own documented
 * default order for "passwd" -- "files" (src/internal/nsswitch.h's own
 * banner) -- so the fixture /etc/passwd is still consulted even with
 * no nsswitch.conf fixture in place at all. */
static void test_linux_fixture_missing_nsswitch_defaults_to_files(void)
{
	struct passwd *pw;

	fixture_write(FIX_PASSWD, "erin:x:5005:5005:Erin Example:/home/erin:/bin/esh\n");
	CHECK(setenv("SPICULE_TEST_PASSWD_PATH", FIX_PASSWD, 1) == 0);
	CHECK(setenv("SPICULE_TEST_NSSWITCH_PATH", "fx-nsswitch-does-not-exist", 1) == 0);

	pw = getpwnam("erin");
	CHECK(pw != NULL);
	if (pw) CHECK(pw->pw_uid == 5005);

	fixture_env_clear();
}

int main(void)
{
	char tmpl[] = "posixpwd-XXXXXX";
	char *dir = mkdtemp(tmpl);

	CHECK(dir == tmpl);
	if (dir) CHECK(chdir(dir) == 0);

	test_linux_root_exists_by_uid();
	test_linux_root_exists_by_name();
	test_linux_absurd_lookups_not_found();
	test_linux_getpwent_reaches_root();

	test_linux_fixture_lookup();
	test_linux_fixture_getpwent_sequence();
	test_linux_fixture_erange_boundary();
	test_linux_fixture_erange_boundary_uid();
	test_linux_fixture_nsswitch_disables_files();
	test_linux_fixture_missing_nsswitch_defaults_to_files();

	if (!fails) printf("pwd: all tests passed\n");
	return fails != 0;
}

#endif /* __linux__ */
