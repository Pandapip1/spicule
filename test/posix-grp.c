/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of four headers:
 * <grp.h>, <sys/utsname.h>, <sys/times.h>, <sys/uio.h>. One file,
 * since none of the four is large on its own -- same reasoning as
 * test/posix-sysmisc.c bundling several small headers together. Every
 * assertion cites the clause of
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/<name>.html
 * or .../basedefs/<header>.html it checks. The same three-fence
 * convention as test/posix-sysmisc.c/test/posix-dl.c is available for a
 * real, permanent gap:
 *
 *   #if 0 / * N/A: <requirement + citation + why NT can't> * /
 *
 * but this file no longer carries one. Its single fence held
 * readv()/writev()'s cross-thread atomicity requirement (XSH 2.9.7) and
 * came out when src/misc/uio.c stopped transferring a vector one area
 * at a time; the long comment left where it stood records both what the
 * clause needed and why nothing in this file can assert it directly.
 *
 * <grp.h> mirrors test/pwd.c's own structure and its have_user() gate:
 * src/misc/grp.c's one group is only knowable when %USERNAME%/%USER%
 * is set, and spicule's own native `make asan` harness (fuzz/ntstubs.c)
 * deliberately starts with an empty environ, so both branches are
 * exercised for real depending on which harness runs this file.
 */
/* setenv()/unsetenv()/clock_gettime()/CLOCK_MONOTONIC/wait4() further
 * down this file are all gated behind a feature-test macro in this
 * project's own headers (see Makefile's CFLAGS_ALL comment: "_ALL_
 * SOURCE ... is for the library itself, not for programs" -- a
 * consuming TU must opt in itself, the same as test/posix-time.c/
 * test/posix-unistd.c already do). A tcc/Wine build apparently never
 * exercised this gap (tcc's own default visibility must differ from
 * clang -std=c99's); only a native clang toolchain build of this file
 * catches it, and it is a pre-existing gap, not introduced by anything
 * below. */
#define _GNU_SOURCE
#include "test-policy.h"
#include <grp.h>
#include <sys/utsname.h>
#include <sys/times.h>
#include <sys/uio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <stdint.h>

static int fails;
/* Assertion groups this run could not exercise at all; see main(). */
static int unverified;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static const char *self;

/* __spawn(): the same internal re-exec primitive test/posix-signal.c
 * and test/posix-alloc.c already use to get a real child process in
 * both the Wine `make check` harness and the native `make asan` one
 * -- not declared in any public header, so declared locally here too. */
int __spawn(const char *path, char *const argv[], char *const envp[]);
extern char **environ;

/* ================================================================== *
 * <grp.h>: grp.h.html, getgrnam.html, getgrgid.html, getgrent.html,
 * mirroring test/pwd.c's audit of <pwd.h> one gid deep.
 * ================================================================== */

/* Everything from here to the matching #else below audits
 * src/misc/nt/grp.c's single-group-synthesis <grp.h> -- see test/
 * pwd.c's own matching comment for why this no longer holds on Linux
 * now that src/misc/linux/grp.c gives Linux a real, file-backed
 * <grp.h>, and why this is gated out wholesale rather than adapted
 * assertion-by-assertion. */
#ifndef __linux__

/* Mirrors src/misc/grp.c's current_name() / test/pwd.c's have_user(). */
static int have_group(void)
{
	const char *n = getenv("USERNAME");
	if (!n || !*n) n = getenv("USER");
	return n && *n;
}

/* grp.h.html: "at least" gr_name/gr_gid/gr_mem. getgid()==getegid()
 * always here (src/unistd/ids.c, test/posix-unistd.c), so getgid() is
 * the only gid that can ever have an entry -- when the name behind it
 * is knowable at all (have_group() above). */
static void test_getgrgid_current(void)
{
	struct group *gr;

	errno = 0;
	gr = getgrgid(getgid());
	if (!have_group()) {
		/* getgrgid.html RETURN VALUE: "If the requested entry was
		 * not found, errno shall not be changed." */
		CHECK(gr == NULL);
		CHECK(errno == 0);
		return;
	}
	CHECK(gr != NULL);
	if (!gr) return;
	CHECK(gr->gr_gid == getgid());
	CHECK(gr->gr_name != NULL && gr->gr_name[0] != '\0');
	/* grp.h.html: gr_mem is "a null-terminated array of character
	 * pointers to member names". src/misc/grp.c's design: the one
	 * user this library has genuinely is a member of its own one
	 * group, so gr_mem == {gr_name, NULL}. */
	CHECK(gr->gr_mem != NULL);
	if (gr->gr_mem) {
		CHECK(gr->gr_mem[0] != NULL && strcmp(gr->gr_mem[0], gr->gr_name) == 0);
		CHECK(gr->gr_mem[1] == NULL);
	}
}

static void test_getgrgid_other_not_found(void)
{
	struct group *gr;

	errno = 12345;
	gr = getgrgid(getgid() + 1);
	CHECK(gr == NULL);
	CHECK(errno == 12345);
}

/* getgrnam.html DESCRIPTION: search by name. Round-trip:
 * getgrnam(getgrgid(getgid())->gr_name) must be the same record. */
static void test_getgrnam_current_and_roundtrip(void)
{
	struct group *by_gid, *by_name;
	char namebuf[256];

	by_gid = getgrgid(getgid());
	if (!have_group()) {
		CHECK(by_gid == NULL);
		return;
	}
	CHECK(by_gid != NULL);
	if (!by_gid) return;
	strcpy(namebuf, by_gid->gr_name);   /* g_gr is static storage, reused below */

	errno = 0;
	by_name = getgrnam(namebuf);
	CHECK(by_name != NULL);
	CHECK(errno == 0);
	if (!by_name) return;
	CHECK(strcmp(by_name->gr_name, namebuf) == 0);
	CHECK(by_name->gr_gid == getgid());
}

static void test_getgrnam_other_not_found(void)
{
	struct group *gr;

	errno = 12345;
	gr = getgrnam("definitely-not-a-real-spicule-group-xyz");
	CHECK(gr == NULL);
	CHECK(errno == 12345);
}

/* getgrgid_r/getgrnam_r (Thread-Safe Functions option): "shall return
 * zero" on success or clean not-found; error number returned directly,
 * not via errno; *result NULL on both error and not-found. */
static void test_getgrgid_r_success(void)
{
	struct group gr, *result = (struct group *)0x1;
	char buf[512];
	int r;

	r = getgrgid_r(getgid(), &gr, buf, sizeof buf, &result);
	CHECK(r == 0);
	if (!have_group()) {
		CHECK(result == NULL);
		return;
	}
	CHECK(result == &gr);
	CHECK(gr.gr_gid == getgid());
	CHECK(gr.gr_name != NULL && gr.gr_name[0] != '\0');
	CHECK(gr.gr_mem != NULL && gr.gr_mem[0] != NULL && gr.gr_mem[1] == NULL);
}

static void test_getgrgid_r_not_found(void)
{
	struct group gr, *result = (struct group *)0x1;
	char buf[512];
	int r;

	r = getgrgid_r(getgid() + 1, &gr, buf, sizeof buf, &result);
	CHECK(r == 0);
	CHECK(result == NULL);
}

/* ERANGE: "Insufficient storage was supplied via buffer and bufsize."
 * Only observable when there is a record to try to pack; without
 * have_group(), getgrgid_r() reports "not found" first. */
static void test_getgrgid_r_erange(void)
{
	struct group gr, *result = (struct group *)0x1;
	char buf[1];
	int r;

	r = getgrgid_r(getgid(), &gr, buf, sizeof buf, &result);
	if (!have_group()) {
		CHECK(r == 0);
		CHECK(result == NULL);
		return;
	}
	CHECK(r == ERANGE);
	CHECK(result == NULL);
}

static void test_getgrnam_r_success_and_not_found(void)
{
	struct group gr, *result;
	char buf[512];
	char namebuf[256];
	int r;

	if (!have_group()) {
		result = (struct group *)0x1;
		r = getgrnam_r("whoever", &gr, buf, sizeof buf, &result);
		CHECK(r == 0);
		CHECK(result == NULL);
		return;
	}

	result = (struct group *)0x1;
	r = getgrgid_r(getgid(), &gr, buf, sizeof buf, &result);
	CHECK(r == 0 && result == &gr);
	if (r != 0 || !result) return;
	strcpy(namebuf, gr.gr_name);

	result = (struct group *)0x1;
	r = getgrnam_r(namebuf, &gr, buf, sizeof buf, &result);
	CHECK(r == 0);
	CHECK(result == &gr);
	CHECK(gr.gr_gid == getgid());

	result = (struct group *)0x1;
	r = getgrnam_r("definitely-not-a-real-spicule-group-xyz", &gr, buf, sizeof buf, &result);
	CHECK(r == 0);
	CHECK(result == NULL);
}

static void test_getgrnam_r_erange(void)
{
	struct group gr, *result = (struct group *)0x1;
	char buf[1];
	char namebuf[256];
	struct group *cur;

	if (!have_group()) {
		result = (struct group *)0x1;
		CHECK(getgrnam_r("whoever", &gr, buf, sizeof buf, &result) == 0);
		CHECK(result == NULL);
		return;
	}

	cur = getgrgid(getgid());
	CHECK(cur != NULL);
	if (!cur) return;
	strcpy(namebuf, cur->gr_name);

	result = (struct group *)0x1;
	CHECK(getgrnam_r(namebuf, &gr, buf, sizeof buf, &result) == ERANGE);
	CHECK(result == NULL);
}

/* getgrent.html: XSI, but implementable here -- one entry when
 * have_group(), none otherwise. setpwent()/getgrent()/endgrent()
 * mirror test/pwd.c's getpwent() coverage exactly. */
static void test_getgrent_one_entry_then_eof(void)
{
	struct group *gr;

	setgrent();
	errno = 0;
	gr = getgrent();
	if (have_group()) {
		CHECK(gr != NULL);
		if (gr) CHECK(gr->gr_gid == getgid());
	} else {
		CHECK(gr == NULL);
		CHECK(errno == 0);
	}

	errno = 0;
	gr = getgrent();
	CHECK(gr == NULL);
	CHECK(errno == 0);

	setgrent();
	gr = getgrent();
	CHECK((gr != NULL) == have_group());
	endgrent();
}

/* Consistency checks the task brief calls out explicitly: gr_gid
 * against getgid(), and getgrnam(getgrgid(getgid())->gr_name)
 * round-tripping back to the same gid. */
static void test_consistency(void)
{
	struct group *by_gid, *by_name;

	by_gid = getgrgid(getgid());
	if (!have_group()) { CHECK(by_gid == NULL); return; }
	CHECK(by_gid != NULL);
	if (!by_gid) return;
	CHECK(by_gid->gr_gid == getgid());

	by_name = getgrnam(by_gid->gr_name);
	CHECK(by_name != NULL);
	if (!by_name) return;
	CHECK(by_name->gr_gid == getgid());
}

/* ================================================================== *
 * <sys/utsname.h>: uname.html, sys_utsname.h.html.
 * ================================================================== */


/* ==== clauses the successor-queue <grp.h> audit added ==================== */

/* getgrgid.html RETURN VALUE: "A null pointer shall be returned if the
 * requested entry is not found ... If the requested entry was not
 * found, errno shall not be changed." The existing not-found tests use
 * getgid()+1, adjacent to the one gid that does exist; this uses a gid
 * that could not plausibly be anything, to pin that the answer is a
 * real lookup rather than an entry fabricated for any argument. */
static void test_getgrgid_absurd_gid(void)
{
	errno = 12345;
	CHECK(getgrgid((gid_t)0x7ffffffe) == NULL);
	CHECK(errno == 12345);
	errno = 12345;
	CHECK(getgrnam("no-such-group-could-ever-be-called-this") == NULL);
	CHECK(errno == 12345);
}

/* getgrnam.html RETURN VALUE: "The getgrnam_r() function shall return
 * zero on success or if the requested entry was not found and no error
 * has occurred", with a null pointer stored through result. Not-found
 * is not an error for the _r form. */
static void test_getgrgid_r_absurd_gid(void)
{
	struct group gr;
	struct group *result = (struct group *)0x1;
	char buf[512];

	CHECK(getgrgid_r((gid_t)0x7ffffffe, &gr, buf, sizeof buf, &result) == 0);
	CHECK(result == NULL);
	result = (struct group *)0x1;
	CHECK(getgrnam_r("no-such-group-could-ever-be-called-this", &gr, buf, sizeof buf, &result) == 0);
	CHECK(result == NULL);
}

/* setgrent.html: "shall rewind the group database"; endgrent.html:
 * "shall close the group database"; getgrent.html: "If the database is
 * not already open, getgrent() shall open it and return ... the first
 * entry." So endgrent() followed by getgrent() must re-yield the first
 * entry rather than stay at end-of-file --
 * test_getgrent_one_entry_then_eof() calls endgrent() only as its last
 * statement and never reads after it. Both pages also state the
 * function "shall not change the setting of errno if successful". */
static void test_grent_reopen_and_errno(void)
{
	struct group *gr;

	setgrent();
	(void)getgrent();
	(void)getgrent();
	CHECK(getgrent() == NULL);

	endgrent();
	gr = getgrent();
	CHECK((gr != NULL) == have_group());

	errno = 12345;
	setgrent();
	CHECK(errno == 12345);
	errno = 12345;
	endgrent();
	CHECK(errno == 12345);
}

/* grp.h.html: struct group's gr_mem is a "Pointer to a null-terminated
 * array of character pointers to member names". The array lives inside
 * the caller's buffer for the _r forms, so it has to be carved out at a
 * correctly aligned offset -- src/misc/grp.c pads for that, and the
 * padding is charged to the size it demands, but nothing ever handed it
 * a deliberately misaligned buffer to prove either half. Also pins
 * ERANGE's boundary (one byte short must fail, exactly enough must
 * succeed) rather than only the one-byte case the existing test uses,
 * which cannot tell a correct size computation from a blanket refusal. */
static void test_getgrgid_r_alignment_and_erange_boundary(void)
{
	static char raw[512];
	char *misaligned = raw + 1;
	struct group gr;
	struct group *result;

	result = (struct group *)0x1;
	CHECK(getgrgid_r(getgid(), &gr, misaligned, sizeof raw - 1, &result) == 0);
	if (!have_group()) {
		CHECK(result == NULL);
		printf("note: no group name knowable -- gr_mem alignment and the ERANGE boundary are unreachable (getgrgid_r() answers \"not found\" before it sizes anything)\n");
		return;
	}
	CHECK(result == &gr);
	if (result != &gr) return;
	/* "a null-terminated array of character pointers", correctly
	 * aligned even though the buffer it was carved from was not. */
	CHECK(((size_t)(char *)gr.gr_mem % sizeof(char *)) == 0);
	CHECK(gr.gr_mem[0] != NULL);
	CHECK(gr.gr_mem[1] == NULL);

	/* ERANGE boundary. Walk the size down until it stops fitting,
	 * rather than recomputing src/misc/grp.c's packing here: what the
	 * clause requires is that there *is* a boundary and that one more
	 * byte is enough, not any particular number. */
	{
		size_t hi = sizeof raw - 1, lo;
		while (hi > 1) {
			result = (struct group *)0x1;
			if (getgrgid_r(getgid(), &gr, misaligned, hi - 1, &result) == ERANGE) break;
			hi--;
		}
		CHECK(hi > 1);			/* a boundary exists */
		lo = hi - 1;
		result = (struct group *)0x1;
		CHECK(getgrgid_r(getgid(), &gr, misaligned, lo, &result) == ERANGE);
		CHECK(result == NULL);		/* "*result shall be a null pointer ... on error" */
		result = NULL;
		CHECK(getgrgid_r(getgid(), &gr, misaligned, hi, &result) == 0);
		CHECK(result == &gr);		/* one more byte is enough */
	}
}

static void test_getgrgid_erange_not_in_its_errno_list(void)
{
	static char big[400];
	struct group *gr;
	char *saved_username = getenv("USERNAME");
	char *saved_user = getenv("USER");
	char keep_username[256], keep_user[256];
	int had_username = saved_username != NULL, had_user = saved_user != NULL;

	if (had_username) { strncpy(keep_username, saved_username, sizeof keep_username - 1); keep_username[sizeof keep_username - 1] = 0; }
	if (had_user) { strncpy(keep_user, saved_user, sizeof keep_user - 1); keep_user[sizeof keep_user - 1] = 0; }

	memset(big, 'x', sizeof big - 1);
	big[sizeof big - 1] = 0;
	CHECK(setenv("USERNAME", big, 1) == 0);

	/* The clause, not one particular remedy for it -- see the matching
	 * note in test/pwd.c.  The fix taken grows the internal buffer, so
	 * the call now succeeds and returns the real record instead of
	 * reporting a group that exists as "not found"; asserting NULL here
	 * would pin the weaker remedy.  What getgrgid.html requires is that
	 * [ERANGE] (listed only for the _r forms, where it describes a
	 * caller-supplied buffer) never escapes the non-_r form, and that a
	 * "not found" answer leaves errno unchanged. */
	errno = 0;
	gr = getgrgid(getgid());
	CHECK(errno != ERANGE);
	if (gr) {
		CHECK(gr->gr_name != NULL);
		CHECK(gr->gr_name && !strcmp(gr->gr_name, big));
	} else {
		CHECK(errno == 0);
	}

	if (had_username) setenv("USERNAME", keep_username, 1); else unsetenv("USERNAME");
	if (had_user) setenv("USER", keep_user, 1); else unsetenv("USER");
}

#else /* __linux__ */

/* ====================================================================
 * Linux: a real audit of src/misc/linux/grp.c's file-backed <grp.h> --
 * mirrors test/pwd.c's own Linux tier-1/tier-2 split one gid deep
 * (real, read-only facts about this host's actual /etc/group; a
 * hermetic fixture tree for everything else). See that file's own
 * banner for the reasoning this does not repeat.
 * ==================================================================== */

static void fixture_write(const char *path, const char *content)
{
	FILE *f = fopen(path, "w");
	CHECK(f != NULL);
	if (!f) return;
	CHECK(fputs(content, f) >= 0);
	fclose(f);
}

/* gid 0 is "root" (or, on a handful of real distros, an equivalent
 * name like "wheel" for gid 0 -- but root's OWN primary group is
 * always gid 0 on every mainstream Linux distribution, so gid 0
 * resolving to SOME real entry is the safe, universal fact to check,
 * the same class of check test/pwd.c's own test_linux_root_exists_by_
 * uid() makes for uid 0). */
static void test_linux_gid0_exists(void)
{
	struct group *gr = getgrgid(0);
	CHECK(gr != NULL);
	if (!gr) return;
	CHECK(gr->gr_name != NULL && gr->gr_name[0] != '\0');
	CHECK(gr->gr_mem != NULL);
}

static void test_linux_absurd_lookups_not_found(void)
{
	errno = 12345;
	CHECK(getgrnam("no-such-group-could-ever-be-called-this-xyz") == NULL);
	CHECK(errno == 12345);
	errno = 12345;
	CHECK(getgrgid((gid_t)0x7ffffffe) == NULL);
	CHECK(errno == 12345);
}

static void test_linux_getgrent_reaches_gid0(void)
{
	struct group *gr;
	int i, saw = 0;

	setgrent();
	for (i = 0; i < 100000; i++) {
		gr = getgrent();
		if (!gr) break;
		if (gr->gr_gid == 0) saw = 1;
	}
	CHECK(saw);
	endgrent();
}

#define FIX_GROUP "fx-group"
#define FIX_NSSWITCH "fx-nsswitch.conf"

static void fixture_env_set(void)
{
	CHECK(setenv("SPICULE_TEST_GROUP_PATH", FIX_GROUP, 1) == 0);
	CHECK(setenv("SPICULE_TEST_NSSWITCH_PATH", FIX_NSSWITCH, 1) == 0);
}

static void fixture_env_clear(void)
{
	unsetenv("SPICULE_TEST_GROUP_PATH");
	unsetenv("SPICULE_TEST_NSSWITCH_PATH");
}

/* getgrnam.html/getgrgid.html DESCRIPTION, and gr_mem's own "array of
 * pointers ... terminated by a null pointer" shape, against a small
 * fully-controlled fixture -- one group with two members, one with
 * none at all (gr_mem must still be a valid {NULL} array, not NULL
 * itself, exactly like src/misc/linux/grp.c's own header documents). */
static void test_linux_fixture_lookup(void)
{
	fixture_write(FIX_GROUP,
		"devs:x:6001:alice,bob\n"
		"lonely:x:6002:\n");
	fixture_write(FIX_NSSWITCH, "group: files\npasswd: files\nhosts: files dns\n");
	fixture_env_set();

	{
		struct group *gr = getgrnam("devs");
		CHECK(gr != NULL);
		if (gr) {
			CHECK(gr->gr_gid == 6001);
			CHECK(gr->gr_mem != NULL);
			CHECK(gr->gr_mem[0] != NULL && strcmp(gr->gr_mem[0], "alice") == 0);
			CHECK(gr->gr_mem[1] != NULL && strcmp(gr->gr_mem[1], "bob") == 0);
			CHECK(gr->gr_mem[2] == NULL);
		}
	}
	{
		struct group *gr = getgrgid(6002);
		CHECK(gr != NULL);
		if (gr) {
			CHECK(strcmp(gr->gr_name, "lonely") == 0);
			CHECK(gr->gr_mem != NULL);
			CHECK(gr->gr_mem[0] == NULL);
		}
	}
	CHECK(getgrnam("nope") == NULL);

	fixture_env_clear();
}

static void test_linux_fixture_getgrent_sequence(void)
{
	struct group *gr;

	fixture_write(FIX_GROUP, "devs:x:6001:alice,bob\nlonely:x:6002:\n");
	fixture_write(FIX_NSSWITCH, "group: files\n");
	fixture_env_set();

	setgrent();
	gr = getgrent();
	CHECK(gr != NULL && strcmp(gr->gr_name, "devs") == 0);
	gr = getgrent();
	CHECK(gr != NULL && strcmp(gr->gr_name, "lonely") == 0);
	errno = 0;
	gr = getgrent();
	CHECK(gr == NULL);
	CHECK(errno == 0);

	setgrent();
	gr = getgrent();
	CHECK(gr != NULL && strcmp(gr->gr_name, "devs") == 0);
	endgrent();

	fixture_env_clear();
}

/* getgrnam.html ERRORS [ERANGE], the same boundary-pinning style as
 * test/pwd.c's identical test -- one byte short of what
 * fill_from_fields() (src/misc/linux/grp.c) needs must fail, exactly
 * that many bytes must succeed, including the member pointer array and
 * its pointer-alignment padding. */
static void test_linux_fixture_erange_boundary(void)
{
	struct group gr, *result;
	char buf[512];
	size_t need, namelen, pad, memberbytes;

	fixture_write(FIX_GROUP, "carol:x:6003:dan,erin\n");
	fixture_write(FIX_NSSWITCH, "group: files\n");
	fixture_env_set();

	/* Mirrors src/misc/linux/grp.c's fill_from_fields() layout
	 * computation exactly (name, then a pointer-aligned (nmem+1)
	 * pointer array, then the member bytes) so this test pins the
	 * real boundary rather than a guessed one. */
	namelen = strlen("carol") + 1;
	pad = (sizeof(char *) - ((uintptr_t)(buf + namelen) % sizeof(char *))) % sizeof(char *);
	memberbytes = strlen("dan,erin") + 1;
	need = namelen + pad + 3 * sizeof(char *) + memberbytes;

	result = (struct group *)0x1;
	CHECK(getgrnam_r("carol", &gr, buf, need - 1, &result) == ERANGE);
	CHECK(result == NULL);

	result = NULL;
	CHECK(getgrnam_r("carol", &gr, buf, need, &result) == 0);
	CHECK(result == &gr);
	if (result == &gr) {
		CHECK(gr.gr_gid == 6003);
		CHECK(gr.gr_mem[0] != NULL && strcmp(gr.gr_mem[0], "dan") == 0);
		CHECK(gr.gr_mem[1] != NULL && strcmp(gr.gr_mem[1], "erin") == 0);
		CHECK(gr.gr_mem[2] == NULL);
	}

	fixture_env_clear();
}

/* getgrgid.html ERRORS [ERANGE], same boundary-pinning style as
 * test_linux_fixture_erange_boundary() above but through getgrgid_r()
 * rather than getgrnam_r() -- the two share fill_from_fields() in
 * src/misc/linux/grp.c but reach it through different scan_group() match
 * modes (MATCH_GID vs MATCH_NAME), so this exercises the gid path for
 * real rather than assuming the two are interchangeable. */
static void test_linux_fixture_erange_boundary_gid(void)
{
	struct group gr, *result;
	char buf[512];
	size_t need, namelen, pad, memberbytes;

	fixture_write(FIX_GROUP, "frank:x:6006:gwen,hal\n");
	fixture_write(FIX_NSSWITCH, "group: files\n");
	fixture_env_set();

	namelen = strlen("frank") + 1;
	pad = (sizeof(char *) - ((uintptr_t)(buf + namelen) % sizeof(char *))) % sizeof(char *);
	memberbytes = strlen("gwen,hal") + 1;
	need = namelen + pad + 3 * sizeof(char *) + memberbytes;

	result = (struct group *)0x1;
	CHECK(getgrgid_r(6006, &gr, buf, need - 1, &result) == ERANGE);
	CHECK(result == NULL);

	result = NULL;
	CHECK(getgrgid_r(6006, &gr, buf, need, &result) == 0);
	CHECK(result == &gr);
	if (result == &gr) {
		CHECK(strcmp(gr.gr_name, "frank") == 0);
		CHECK(gr.gr_mem[0] != NULL && strcmp(gr.gr_mem[0], "gwen") == 0);
		CHECK(gr.gr_mem[1] != NULL && strcmp(gr.gr_mem[1], "hal") == 0);
		CHECK(gr.gr_mem[2] == NULL);
	}

	result = (struct group *)0x1;
	CHECK(getgrgid_r(69999, &gr, buf, sizeof buf, &result) == 0);
	CHECK(result == NULL);

	fixture_env_clear();
}

static void test_linux_fixture_nsswitch_disables_files(void)
{
	struct group *gr;

	fixture_write(FIX_GROUP, "dave:x:6004:\n");
	fixture_write(FIX_NSSWITCH, "group: some_unimplemented_service\n");
	fixture_env_set();

	errno = 0;
	gr = getgrnam("dave");
	CHECK(gr == NULL);
	CHECK(errno == 0);

	fixture_env_clear();
}

static void test_linux_fixture_missing_nsswitch_defaults_to_files(void)
{
	struct group *gr;

	fixture_write(FIX_GROUP, "erin:x:6005:\n");
	CHECK(setenv("SPICULE_TEST_GROUP_PATH", FIX_GROUP, 1) == 0);
	CHECK(setenv("SPICULE_TEST_NSSWITCH_PATH", "fx-nsswitch-does-not-exist", 1) == 0);

	gr = getgrnam("erin");
	CHECK(gr != NULL);
	if (gr) CHECK(gr->gr_gid == 6005);

	fixture_env_clear();
}

#endif /* __linux__ */

static void test_uname(void)
{
	struct utsname u;
	char host[256];

	memset(&u, 0, sizeof u);
	/* uname.html RETURN VALUE: "a non-negative value shall be
	 * returned" on success. */
	CHECK(uname(&u) >= 0);

	/* DESCRIPTION: "shall return a string naming the current system
	 * in ... sysname" -- format is implementation-defined
	 * (RATIONALE: "The format of each member is
	 * implementation-defined"). src/misc/uname.c's choice is the
	 * literal string NT itself uses (%OS%). */
	CHECK(strcmp(u.sysname, "Windows_NT") == 0);

	/* DESCRIPTION: "nodename shall contain the name of this node
	 * within an implementation-defined communications network" --
	 * src/misc/uname.c reuses gethostname() for this, so the two
	 * must agree exactly. */
	CHECK(gethostname(host, sizeof host) == 0);
	CHECK(strcmp(u.nodename, host) == 0);

	/* "The arrays release and version shall further identify the
	 * operating system." Format is implementation-defined; checked
	 * against the RtlGetVersion()-sourced shape src/misc/uname.c
	 * documents (major.minor, and "Build N"). */
	CHECK(u.release[0] != '\0');
	CHECK(strchr(u.release, '.') != NULL);
	CHECK(strncmp(u.version, "Build ", 6) == 0);

	/* "The array machine shall contain a name that identifies the
	 * hardware that the system is running on" -- here, the arch this
	 * binary was actually compiled for (src/misc/uname.c's
	 * documented WOW64 reasoning: the running process's own
	 * bitness, not the kernel's). */
#if defined(__x86_64__)
	CHECK(strcmp(u.machine, "x86_64") == 0);
#elif defined(__i386__)
	CHECK(strcmp(u.machine, "i686") == 0);
#endif

	/* uname.html ERRORS: "No errors are defined." -- a NULL argument
	 * is therefore not a POSIX-mandated case; src/misc/uname.c still
	 * refuses it cleanly rather than crash, exercised here as a
	 * plain implemented-behavior check, not a spec citation. */
	errno = 0;
	CHECK(uname(NULL) == -1);
}

/* ================================================================== *
 * <sys/times.h>: times.html.
 * ================================================================== */

/* Same _SC_CLK_TCK-based tick math src/misc/times.c uses internally,
 * reimplemented independently here (not shared code) so this test does
 * not just echo the same formula back at itself. */
static clock_t timeval_to_clockticks(const struct timeval *tv)
{
	long tck = sysconf(_SC_CLK_TCK);
	return (clock_t)((long long)tv->tv_sec * tck + (long long)tv->tv_usec * tck / 1000000);
}

/* Burn real user CPU until NT has actually charged this process at
 * least `want` more clock ticks of it, and report how many it got.
 *
 * A fixed iteration count cannot do this job, and both callers below
 * used to try.  The amount of user time a fixed loop
 * earns depends on the machine it lands on, while the thing being
 * asserted -- "> 0 ticks" -- is a threshold, not a proportion.  On a
 * GitHub-hosted Windows Server 2025 x86_64 runner the child-side loop
 * fell under that threshold and the assertion failed, while the
 * identical source passed on the slower i386 and kernel32 legs of the
 * same run.
 *
 * A fixed 20,000,000-iteration loop is not a safe margin: re-measuring
 * it, three runs in a row on one machine, gives 3, 2 and 1 ticks --
 * nowhere near enough headroom to be a reliable floor above the
 * "> 0 ticks" threshold being asserted.
 *
 * Why the floor is so easy to miss: NT does not accumulate process CPU
 * time, it *samples* it.  The clock ISR charges one tick to whichever
 * thread is on-CPU at the interrupt (ReactOS ntoskrnl/ke/time.c,
 * KeUpdateRunTime(): `Thread->UserTime++`), and ProcessTimes reports
 * that count scaled by KeMaximumIncrement -- 15.625ms on x64.  So
 * UserTime only ever takes the values 0, 15.625ms, 31.25ms, ...  A
 * burn measured at ~10ms of CPU is therefore charged *zero* whenever it
 * happens not to span a clock interrupt, which is roughly a third of
 * the time.  MSDN says the same thing by pointing at
 * QueryProcessCycleTime for anyone who wants real resolution
 * (GetProcessTimes, Remarks).
 *
 * So: loop until the reading itself says the work landed.  The caller
 * gets a number it can assert on and, crucially, a distinguishable
 * failure -- -1 means "this process never accumulated the time", which
 * is a fact about the burn, not about whichever reader the caller is
 * actually testing.
 *
 * The return type is `long`, not clock_t, on purpose.  The failure
 * sentinel is -1 and every caller tests it with `< want`; that is only
 * safe while clock_t is signed, which here it happens to be
 * (include/alltypes.h.in: `TYPEDEF _Int64 clock_t`).  Were it ever
 * unsigned, `(clock_t)-1` would be a huge positive value and every
 * timeout would silently satisfy the check instead of failing it --
 * precisely the vacuous pass this helper exists to prevent, reached
 * through a typedef this file does not control.  A signed return type
 * makes the sentinel safe by construction rather than by coincidence.
 *
 * Two wall-clock bounds, not one, and they mean different things.  User
 * time accrues only while this process is actually on a CPU, so on a
 * contended machine -- tools/gate.sh runs several stages at once, and
 * hosted CI runners are routinely oversubscribed -- the same confirmed
 * ticks can take arbitrarily longer in wall-clock terms.  A single
 * bound tight enough to catch a dead counter is therefore also tight
 * enough to fire spuriously under load, which would trade a visible
 * flake for a rarer and much more confusing one.
 *
 *   BURN_STALL_LIMIT_SEC  no ticks charged *at all* while spinning
 *                         continuously for this long.  Contention
 *                         cannot produce that: 30s of wall clock
 *                         without a single 15.625ms tick is under a
 *                         0.06% share of one CPU.  That is a counter
 *                         that is not being charged, and it is
 *                         reported as the real failure it is.
 *   BURN_WALL_LIMIT_SEC   total, for a counter that does advance but
 *                         pathologically slowly.  200ms of confirmed
 *                         CPU inside 90s tolerates roughly a 450x
 *                         oversubscription before firing, against a
 *                         realistic worst case of maybe 8x, and two
 *                         such bounds still fit inside the
 *                         windows-test job's 20-minute timeout.  Its
 *                         message names machine load explicitly, so a
 *                         reader who hits it is sent to look at the
 *                         runner rather than at times().
 *
 * The accumulator is volatile and its final value is stored to a
 * volatile object at file scope, so no conforming compiler may delete
 * the loop: a burn that got optimised away is the same vacuous-pass
 * trap this helper exists to close, wearing a different hat. */
static volatile double burn_sink;

#define BURN_STALL_LIMIT_SEC 30
#define BURN_WALL_LIMIT_SEC  90

static long burn_user_ticks(long want)
{
	struct timespec t0, last, now;
	struct tms t;
	clock_t start;
	long got = 0;
	volatile double x = 0;
	long i;

	if (clock_gettime(CLOCK_MONOTONIC, &t0) < 0) return -1;
	last = t0;
	if (times(&t) == (clock_t)-1) return -1;
	start = t.tms_utime;

	for (;;) {
		for (i = 0; i < 5000000L; i++) x += (double)i;
		burn_sink = x;
		if (times(&t) == (clock_t)-1) return -1;
		if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
		if ((long)(t.tms_utime - start) > got) {
			got = (long)(t.tms_utime - start);
			last = now;
		}
		if (got >= want) return got;
		if (now.tv_sec - last.tv_sec > BURN_STALL_LIMIT_SEC) {
			printf("note: tms_utime has not advanced at all in %d wall "
			       "seconds of continuous spinning (%ld of %ld ticks). "
			       "That is under a 0.06%% share of one CPU, which no "
			       "amount of contention explains -- not parallel test "
			       "stages, not an oversubscribed CI runner. The "
			       "user-time counter is not being charged at all\n",
			       BURN_STALL_LIMIT_SEC, got, want);
			return -1;
		}
		if (now.tv_sec - t0.tv_sec > BURN_WALL_LIMIT_SEC) {
			printf("note: only %ld of %ld user ticks in %d wall seconds. "
			       "The counter is advancing, so this process is simply "
			       "getting very little CPU -- suspect contention on this "
			       "machine (parallel test stages, an oversubscribed CI "
			       "runner) before suspecting times()\n",
			       got, want, BURN_WALL_LIMIT_SEC);
			return -1;
		}
	}
}

/* How much user time each side burns before asserting it was charged.
 * 20 ticks is 200ms at _SC_CLK_TCK 100, i.e. ~13 of Windows' 15.625ms
 * accounting quanta -- a wide margin over the 1-tick floor being
 * asserted, and still small enough that both burns together cost this
 * suite well under a second on any machine that accounts at all.
 *
 * The two floors are deliberately DIFFERENT numbers.  When both sides
 * burned BURN_TICKS, the parent's own user time and the child's
 * confirmed floor were the same value by construction, so
 * `tms_cutime > 0` could not distinguish "the child's time was
 * accumulated" from "the parent's own time was reported back" -- and
 * under Wine it is the latter (see test_times_children()).  The
 * printed note below shows both numbers, so a reader can see at a
 * glance which process the total actually came from. */
#define BURN_TICKS       20
#define BURN_CHILD_TICKS 31

static void test_times_self(void)
{
	struct rusage ru_before;
	struct tms t;
	clock_t r;
	clock_t utime_ticks, stime_ticks;
	long burned;

	/* Burn real user CPU until the reading itself confirms it landed,
	 * so the assertions below are non-zero on any platform that tracks
	 * process times at all.  Without a burn the whole function was
	 * vacuous: a test process that has done almost nothing reports
	 * tms_utime == 0 and ru_utime == 0, so `t.tms_utime >= utime_ticks`
	 * was 0 >= 0 and passed identically if times() and getrusage() had
	 * both written nothing.  With a *fixed-size* burn it was merely
	 * fragile instead -- see burn_user_ticks()'s comment. */
	burned = burn_user_ticks(BURN_TICKS);
	/* Distinct from the assertions below on purpose: this one says the
	 * burn never happened, which is a fact about this loop and says
	 * nothing at all about times() or getrusage(). */
	CHECK(burned >= BURN_TICKS);
	if (burned < BURN_TICKS) {
		printf("note: could not accumulate %d ticks of user time "
		       "(burn_user_ticks() printed why just above); the "
		       "tms_utime/ru_utime assertions below cannot mean "
		       "anything and are skipped\n", BURN_TICKS);
		return;
	}

	memset(&ru_before, 0xff, sizeof ru_before);
	CHECK(getrusage(RUSAGE_SELF, &ru_before) == 0);

	memset(&t, 0xff, sizeof t);
	r = times(&t);
	/* times.html RETURN VALUE: "(clock_t)-1 shall be returned" only
	 * on failure; this call cannot fail (no children waited on yet,
	 * no overflow reachable in a test run). */
	CHECK(r != (clock_t)-1);

	/* DESCRIPTION: "tms_utime ... is the CPU time charged for the
	 * execution of user instructions of the calling process" / same
	 * for tms_stime and the system. src/misc/resource.c's
	 * getrusage(RUSAGE_SELF) reads the identical
	 * NtQueryInformationProcess(ProcessTimes) source a few
	 * instructions earlier in this function, so times()'s answer can
	 * only have grown since -- never gone backwards. */
	utime_ticks = timeval_to_clockticks(&ru_before.ru_utime);
	stime_ticks = timeval_to_clockticks(&ru_before.ru_stime);
	/* The field is genuinely tracked, not merely zero: after the burn
	 * above it must have advanced past zero.  This is the assertion
	 * that makes the cross-check below mean something -- 0 >= 0 does
	 * not distinguish "charged correctly" from "never populated". */
	CHECK(utime_ticks > 0);
	CHECK(t.tms_utime > 0);
	CHECK(t.tms_utime >= utime_ticks);
	CHECK(t.tms_stime >= stime_ticks);
	/* And not off by some wildly different order of magnitude either
	 * -- generous (5s) bound so this cannot flake under slow CI. */
	CHECK(t.tms_utime - utime_ticks < 500);
	CHECK(t.tms_stime - stime_ticks < 500);
}

/* times.html DESCRIPTION: "The times of a terminated child process
 * shall be included in the tms_cutime and tms_cstime elements of the
 * parent when wait() ... returns the process ID of this terminated
 * child." src/process/wait.c accumulates exactly this total for
 * getrusage(RUSAGE_CHILDREN) already; src/misc/times.c reads the same
 * accumulator, so the two must report identical values after the same
 * reap -- the exact cross-check the task brief calls for. */
static void test_times_children(void)
{
	char *argv[3];
	pid_t pid;
	int status;
	struct rusage ru_children, ru_child;
	int child_times_real = 1;
	struct tms t;

	argv[0] = (char *)self; argv[1] = (char *)"--times-child"; argv[2] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid < 0) { printf("note: cannot spawn \"%s\"; times() child test skipped\n", self); return; }
	memset(&ru_child, 0xff, sizeof ru_child);
	CHECK(wait4(pid, &status, 0, &ru_child) == pid);
	CHECK(WIFEXITED(status));
	if (WIFEXITED(status) && WEXITSTATUS(status) == 3) {
		/* The child said its own user-time accounting never moved.
		 * Every assertion below would then be measuring that, not the
		 * parent-side accumulator they name, so say which one broke
		 * and stop rather than reporting a misattributed failure. */
		fails++;
		printf("FAIL %s:%d: --times-child never accumulated its user time; "
		       "the tms_cutime/RUSAGE_CHILDREN assertions cannot be "
		       "evaluated\n", __FILE__, __LINE__);
		return;
	}
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/* Both destinations are poisoned first, so "the reader returned
	 * success without writing the field" is a failure here and not an
	 * accidental match at zero. */
	memset(&ru_children, 0xff, sizeof ru_children);
	CHECK(getrusage(RUSAGE_CHILDREN, &ru_children) == 0);
	memset(&t, 0xff, sizeof t);
	CHECK(times(&t) != (clock_t)-1);

	CHECK(t.tms_cutime >= 0 && t.tms_cstime >= 0);

	/* The assertion that makes the cross-check below mean anything.
	 * Two readers of one accumulator (src/process/wait.c's
	 * children_utime100ns/children_ktime100ns) agreeing at zero agree
	 * whether or not either reader works and whether or not wait.c ever
	 * accumulated anything -- and zero is exactly what an unpopulated
	 * accumulator reads as.  The "--times-child" role in main() burns
	 * real CPU precisely so this is not zero, and -- since it exited 0
	 * above -- has already confirmed against its own tms_utime that NT
	 * charged it at least BURN_TICKS of user time.  So a zero here is
	 * necessarily src/process/wait.c's fill_child_rusage() failing to
	 * record time that demonstrably exists, and not a fast machine: the
	 * child would have exited 3 in that case, handled above.
	 *
	 * tms_cstime is deliberately not held to > 0: a child that only
	 * spins in user code need not be charged any system time at all,
	 * and it measures 0 here.
	 *
	 * Not held natively.  tools/asan-build.sh compiles this suite
	 * against fuzz/ntstubs.c, whose NtQueryInformationProcess answers
	 * ProcessTimes for this process only and returns
	 * STATUS_NOT_IMPLEMENTED for any child handle ("if (f) return
	 * STATUS_NOT_IMPLEMENTED;  /-* only this process's own times *-/").
	 * fill_child_rusage() bails on that status, so the accumulator is
	 * legitimately zero there and no assertion could tell that apart
	 * from a real accounting failure.  Saying so out loud rather than
	 * dropping the check silently: a run that did not test the clause
	 * should not read like one that did. */
#ifdef _WIN32
	/* Does this platform report a *child's* process times at all?
	 *
	 * The check costs nothing extra: the child just reaped confirmed,
	 * against its own times(), that NT charged it at least
	 * BURN_CHILD_TICKS of user time before it exited, and wait4()'s
	 * struct rusage is documented as that one child's usage.  So on a
	 * platform that answers the question at all it cannot come back
	 * below the floor the child itself watched land.
	 *
	 * Under Wine it does, because Wine's NtQueryInformationProcess()
	 * ignores the handle for this info class and hands back the
	 * *calling* process's times, with its own FIXME saying so
	 * (dlls/ntdll/unix/process.c, `case ProcessTimes:` -- "FIXME:
	 * user/kernel times only work for current process"; UserTime and
	 * KernelTime come from the host times(), and the handle is used
	 * only for CreateTime/ExitTime).
	 *
	 * READ THIS BEFORE TRUSTING A GREEN `make check`: under Wine --
	 * which is `make check`, the asan leg, and every local run -- the
	 * two assertions below are satisfied by the *parent's* own user
	 * time, burned by test_times_self() a few lines earlier, and not
	 * by the child's at all.  Only the windows-test CI legs test the
	 * clause these assertions name.  That is exactly how this group
	 * came to look correct while measuring the wrong process: while
	 * both sides burned the same BURN_TICKS, the parent's own total
	 * and the child's confirmed floor were the same number by
	 * construction, and no assertion over them could tell the two
	 * apart.  The floors are different constants now, and this probe
	 * refuses to let the run report a pass it did not earn.
	 *
	 * Detected by measuring, not by asking which platform this is, so
	 * it needs no version test and cannot go stale when Wine fixes it.
	 * rc=77 (tools/run-tests.py: UNVERIFIED) rather than a silent skip:
	 * a run that could not check the clause must not read like one
	 * that did. */
	if (timeval_to_clockticks(&ru_child.ru_utime) < BURN_CHILD_TICKS) {
		printf("SKIP posix-grp child CPU-time floors: this platform does "
		       "not report a child's process times. The child confirmed "
		       ">= %d user ticks against its own times() and exited 0, "
		       "yet wait4() reports %ld ticks for it (and the parent's "
		       "own burn was %d ticks -- if the totals below match that "
		       "instead, they are the parent's). Wine substitutes the "
		       "calling process's times here (dlls/ntdll/unix/process.c, "
		       "case ProcessTimes, \"FIXME: user/kernel times only work "
		       "for current process\"); the real-Windows legs are the "
		       "oracle for this clause\n",
		       BURN_CHILD_TICKS,
		       (long)timeval_to_clockticks(&ru_child.ru_utime), BURN_TICKS);
		unverified++;
		child_times_real = 0;
	}
	/* Only the two floors are withheld.  The cross-check below is a
	 * different claim -- that times() and getrusage() are two readers
	 * of one accumulator and cannot disagree -- and it stays honest
	 * whatever that accumulator was filled from, so it still runs. */
	if (child_times_real) {
	CHECK(t.tms_cutime > 0);
	CHECK(timeval_to_clockticks(&ru_children.ru_utime) > 0);
	/* Printed unconditionally: a future failure of the two assertions
	 * above should not need a rebuild to say by how much.  Both floors
	 * are shown because they are different numbers on purpose -- a
	 * total that matches the parent's burn rather than the child's is
	 * the substitution described above. */
	printf("note: reaped child charged tms_cutime=%ld ticks, "
	       "RUSAGE_CHILDREN ru_utime=%ld ticks (that child alone: %ld "
	       "ticks, confirmed >= %d; the parent's own burn was %d)\n",
	       (long)t.tms_cutime,
	       (long)timeval_to_clockticks(&ru_children.ru_utime),
	       (long)timeval_to_clockticks(&ru_child.ru_utime),
	       BURN_CHILD_TICKS, BURN_TICKS);
	}
#else
	printf("note: child CPU-time totals not held to > 0 in the native build "
	       "(fuzz/ntstubs.c's ProcessTimes is not implemented for a child "
	       "handle, so the accumulator is legitimately 0); the "
	       "tms_cutime/getrusage cross-check below therefore agrees "
	       "vacuously here\n");
#endif

	CHECK(t.tms_cutime == timeval_to_clockticks(&ru_children.ru_utime));
	CHECK(t.tms_cstime == timeval_to_clockticks(&ru_children.ru_stime));
}

/* Return value: "elapsed real time, in clock ticks, since an
 * arbitrary point in the past ... This point does not change from one
 * invocation of times() within the process to another." Checked by
 * calling twice and requiring the second reading not to have gone
 * backwards. */
static void test_times_monotonic(void)
{
	clock_t a, b;

	a = times(NULL);
	CHECK(a != (clock_t)-1);
	b = times(NULL);
	CHECK(b != (clock_t)-1);
	CHECK(b >= a);
}

/* EOVERFLOW ("The return value would overflow the range of clock_t")
 * is real per the spec but not practically triggerable in a finite
 * test run (it requires clock_t itself to wrap, i.e. the process
 * living past clock_t's max tick count) -- not fenced UNIMPL/N-A since
 * it is not a gap in this implementation, just untestable within a
 * test suite's lifetime. */

/* ================================================================== *
 * <sys/uio.h>: readv.html, writev.html, sys_uio.h.html.
 * ================================================================== */

static void test_readv_writev_roundtrip(void)
{
	char path[] = "t-uio-roundtrip.tmp";
	int fd;
	struct iovec wiov[3];
	struct iovec riov[3];
	char w0[5] = "Hello", w1[7] = ", ntl!", w2[4] = "bc!";
	char r0[5], r1[7], r2[4];
	ssize_t n;

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;

	/* writev.html DESCRIPTION: "gather output data from the iovcnt
	 * buffers ... always write a complete area before proceeding to
	 * the next." */
	wiov[0].iov_base = w0; wiov[0].iov_len = sizeof w0;
	wiov[1].iov_base = w1; wiov[1].iov_len = sizeof w1;
	wiov[2].iov_base = w2; wiov[2].iov_len = sizeof w2;
	n = writev(fd, wiov, 3);
	CHECK(n == (ssize_t)(sizeof w0 + sizeof w1 + sizeof w2));

	CHECK(lseek(fd, 0, SEEK_SET) == 0);

	/* readv.html DESCRIPTION: "place the input data into the iovcnt
	 * buffers ... always fill an area completely before proceeding
	 * to the next." */
	riov[0].iov_base = r0; riov[0].iov_len = sizeof r0;
	riov[1].iov_base = r1; riov[1].iov_len = sizeof r1;
	riov[2].iov_base = r2; riov[2].iov_len = sizeof r2;
	n = readv(fd, riov, 3);
	CHECK(n == (ssize_t)(sizeof r0 + sizeof r1 + sizeof r2));
	CHECK(memcmp(r0, w0, sizeof w0) == 0);
	CHECK(memcmp(r1, w1, sizeof w1) == 0);
	CHECK(memcmp(r2, w2, sizeof w2) == 0);

	close(fd);
	unlink(path);
}

/* sys_uio.h.html DESCRIPTION: struct iovec "shall include at least"
 * iov_base (void *) and iov_len (size_t). */
static void test_iovec_members(void)
{
	struct iovec v;
	char c;

	v.iov_base = &c;
	v.iov_len = 1;
	CHECK(v.iov_base == &c);
	CHECK(v.iov_len == 1);
}

/* readv.html/writev.html ERRORS: "may fail" with [EINVAL] if "iovcnt
 * ... was less than or equal to 0, or greater than {IOV_MAX}."
 * src/misc/uio.c always enforces this (not merely "may"). */
static void test_iovcnt_range(void)
{
	struct iovec iov[1];
	char c;
	int fd;

	iov[0].iov_base = &c; iov[0].iov_len = 1;
	fd = open("t-uio-range.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);

	errno = 0;
	CHECK(readv(fd, iov, 0) == -1);
	CHECK(errno == EINVAL);
	errno = 0;
	CHECK(writev(fd, iov, 0) == -1);
	CHECK(errno == EINVAL);

	errno = 0;
	CHECK(readv(fd, iov, -1) == -1);
	CHECK(errno == EINVAL);

	errno = 0;
	CHECK(readv(fd, iov, IOV_MAX + 1) == -1);
	CHECK(errno == EINVAL);
	errno = 0;
	CHECK(writev(fd, iov, IOV_MAX + 1) == -1);
	CHECK(errno == EINVAL);

	if (fd >= 0) { close(fd); unlink("t-uio-range.tmp"); }
}

/* readv.html/writev.html ERRORS: "shall fail" with [EINVAL] if "the
 * sum of the iov_len values in the iov array overflowed an ssize_t";
 * writev.html DESCRIPTION adds "no data shall be transferred." Two
 * huge lengths that individually fit in size_t but overflow SSIZE_MAX
 * when summed -- src/misc/uio.c's check_iov() rejects this before
 * touching either buffer, so bogus iov_base pointers are safe here. */
static void test_iov_len_overflow(void)
{
	struct iovec iov[2];
	int fd;
	off_t before, after;

	iov[0].iov_base = (void *)1; iov[0].iov_len = (size_t)SSIZE_MAX - 1;
	iov[1].iov_base = (void *)1; iov[1].iov_len = (size_t)SSIZE_MAX - 1;

	fd = open("t-uio-overflow.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;

	before = lseek(fd, 0, SEEK_CUR);
	errno = 0;
	CHECK(writev(fd, iov, 2) == -1);
	CHECK(errno == EINVAL);
	after = lseek(fd, 0, SEEK_CUR);
	CHECK(before == after);   /* "no data shall be transferred" */

	errno = 0;
	CHECK(readv(fd, iov, 2) == -1);
	CHECK(errno == EINVAL);

	close(fd);
	unlink("t-uio-overflow.tmp");
}

/* writev.html DESCRIPTION: "If fildes refers to a regular file and
 * all of the iov_len members ... are 0, writev() shall return 0 and
 * have no other effect." */
static void test_writev_all_zero(void)
{
	struct iovec iov[2];
	int fd;
	off_t before, after;

	iov[0].iov_base = NULL; iov[0].iov_len = 0;
	iov[1].iov_base = NULL; iov[1].iov_len = 0;

	fd = open("t-uio-zero.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;

	before = lseek(fd, 0, SEEK_CUR);
	CHECK(writev(fd, iov, 2) == 0);
	after = lseek(fd, 0, SEEK_CUR);
	CHECK(before == after);

	close(fd);
	unlink("t-uio-zero.tmp");
}

/* XSH 2.9.7 "Thread Interactions with Regular File Operations"
 * (functions/V2_chap02.html#tag_15_09_07) -- this is XSH chapter 2,
 * not XBD.  Verbatim: "All of
 * the following functions shall be atomic with respect to each other in
 * the effects specified in POSIX.1-2017 when they operate on regular
 * files or symbolic links", followed by a table of 39 functions that
 * includes read(), write(), readv() and writev(), and then: "If two
 * threads each call one of these functions, each call shall either see
 * all of the specified effects of the other call, or none of them."
 *
 * This was fenced UNIMPL for as long as src/misc/uio.c looped over
 * read()/write() one iovec at a time, since a loop of separate
 * transfers can be caught halfway through.  It no longer loops: the
 * vector is gathered into a single buffer and moved by a single
 * read()/write(), so readv() and writev() now have exactly the
 * atomicity read() and write() have.  That is the whole of what the
 * clause asks, because what it requires is that the four be atomic
 * *with respect to each other*, not that any of them be atomic in some
 * absolute sense.  The fence went with the loop.
 *
 * NO ASSERTION REPLACES THE FENCE, and the reason is about
 * observability rather than about conformance.  Single-threaded, on a
 * regular file, a gathered transfer and a loop of per-area transfers
 * are indistinguishable through POSIX: same bytes, same order, same
 * return value, same errno, same st_size -- including under
 * RLIMIT_FSIZE, where write() clamps to the room left and both shapes
 * report the same short count.  The difference exists only to a flow of
 * control running *during* the call, and spicule exposes no way to make
 * one: there is no <pthread.h> in the tree.
 *
 * That is not the same as the clause being inapplicable here, which is
 * why this is not recorded N/A.  fork()/__spawn() do give a second
 * process sharing one NT file object through an inherited handle
 * (src/process/spawn.c marks non-cloexec handles OBJ_INHERIT), which is
 * this platform's shape of a shared open file description and is
 * exactly the clause's precondition.  What cannot be built is a *test*:
 * one racing a spawned child would prove non-atomicity if it ever
 * caught a torn transfer, and prove nothing whatever when it did not,
 * and a test whose passing carries no information is a flake with a
 * verdict attached.  times()'s tms_utime magnitude is left unasserted
 * above for the same reason.
 *
 * What is asserted instead is the half that is deterministic, and it is
 * the half a successor is most likely to break: the gather itself. */

/* A vector too large for src/misc/uio.c's stack gather buffer -- the
 * path that file's one allocation lives on -- must still round-trip
 * whole and in order, and must do so across read boundaries that do not
 * line up with the write boundaries, so that a gather or a scatter run
 * out of order shows up as a mismatch instead of cancelling itself out.
 * readv.html/writev.html DESCRIPTION: "always fill/write a complete
 * area before proceeding to the next." */
static void test_readv_writev_gathered(void)
{
	enum { AREA = 3072, WHOLE = 3 * AREA };
	/* Static rather than automatic: the point of the library holding
	 * the whole vector for the caller is that the caller need not, and
	 * a test that puts 12 KiB on the stack to check that would be
	 * arguing against itself. */
	static char w[3][AREA];
	static char r[WHOLE + 1];
	struct iovec iov[4];
	int fd;
	size_t i;

	for (i = 0; i < AREA; i++) {
		w[0][i] = (char)('a' + i % 26);
		w[1][i] = (char)('A' + i % 26);
		w[2][i] = (char)('0' + i % 10);
	}

	fd = open("t-uio-gather.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;

	/* The zero-length area in the middle is not decoration: it is the
	 * one whose iov_base a gather must never dereference. */
	iov[0].iov_base = w[0]; iov[0].iov_len = AREA;
	iov[1].iov_base = NULL; iov[1].iov_len = 0;
	iov[2].iov_base = w[1]; iov[2].iov_len = AREA;
	iov[3].iov_base = w[2]; iov[3].iov_len = AREA;
	CHECK(writev(fd, iov, 4) == (ssize_t)WHOLE);

	CHECK(lseek(fd, 0, SEEK_SET) == 0);
	memset(r, '#', sizeof r);
	iov[0].iov_base = r;        iov[0].iov_len = 1;
	iov[1].iov_base = r + 1;    iov[1].iov_len = 5000;
	iov[2].iov_base = NULL;     iov[2].iov_len = 0;
	iov[3].iov_base = r + 5001; iov[3].iov_len = WHOLE - 5001;
	CHECK(readv(fd, iov, 4) == (ssize_t)WHOLE);

	CHECK(memcmp(r, w[0], AREA) == 0);
	CHECK(memcmp(r + AREA, w[1], AREA) == 0);
	CHECK(memcmp(r + 2 * AREA, w[2], AREA) == 0);
	CHECK(r[WHOLE] == '#');   /* nothing landed past the data */

	close(fd);
	unlink("t-uio-gather.tmp");
}

/* ================================================================== */

int main(int argc, char **argv)
{
	self = argv[0];
	if (argc > 1 && !strcmp(argv[1], "--times-child")) {
		/* Burn real CPU until NT confirms it charged this process at
		 * least BURN_TICKS of user time, then exit cleanly so
		 * waitpid() reaps a real, queryable exit status.
		 *
		 * Exiting 0 is this child's assertion that the time it is
		 * about to be accounted for genuinely exists.  That is what
		 * lets test_times_children() read a zero in the parent as a
		 * parent-side accounting bug instead of "the runner was fast
		 * today": the two are different failures with different fixes,
		 * and a fixed-size burn cannot tell them apart.  Exit 3 says
		 * the burn is what failed. */
		if (burn_user_ticks(BURN_CHILD_TICKS) < BURN_CHILD_TICKS) {
			printf("posix-grp: --times-child could not accumulate %d "
			       "ticks of its own user time (burn_user_ticks() "
			       "printed why just above)\n", BURN_CHILD_TICKS);
			return 3;
		}
		return 0;
	}

#ifndef __linux__
	printf("note: have_group() = %s\n", have_group() ? "true" : "false");

	test_getgrgid_current();
	test_getgrgid_other_not_found();
	test_getgrnam_current_and_roundtrip();
	test_getgrnam_other_not_found();
	test_getgrgid_r_success();
	test_getgrgid_r_not_found();
	test_getgrgid_r_erange();
	test_getgrnam_r_success_and_not_found();
	test_getgrnam_r_erange();
	test_getgrent_one_entry_then_eof();
	test_consistency();
	test_getgrgid_absurd_gid();
	test_getgrgid_r_absurd_gid();
	test_grent_reopen_and_errno();
	test_getgrgid_r_alignment_and_erange_boundary();

	test_getgrgid_erange_not_in_its_errno_list();
#else
	test_linux_gid0_exists();
	test_linux_absurd_lookups_not_found();
	test_linux_getgrent_reaches_gid0();
	test_linux_fixture_lookup();
	test_linux_fixture_getgrent_sequence();
	test_linux_fixture_erange_boundary();
	test_linux_fixture_erange_boundary_gid();
	test_linux_fixture_nsswitch_disables_files();
	test_linux_fixture_missing_nsswitch_defaults_to_files();
#endif
	test_uname();

	test_times_self();
	test_times_children();
	test_times_monotonic();

	test_readv_writev_roundtrip();
	test_iovec_members();
	test_iovcnt_range();
	test_iov_len_overflow();
	test_writev_all_zero();
	test_readv_writev_gathered();

	if (fails) { printf("posix-grp: failures: %d\n", fails); return 1; }
	if (unverified) {
		printf("posix-grp: %d assertion group(s) unverified in this "
		       "environment (see SKIP lines above); no failures in "
		       "what did run\n", unverified);
		return 77;
	}
	printf("posix-grp: all tests passed\n");
	return 0;
}
