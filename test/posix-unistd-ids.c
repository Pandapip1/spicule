/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of the <unistd.h> identity,
 * process-group, session, scheduling and host-name interfaces --
 * test/POSIX-GAP-ACCOUNTING.md's "Implemented, not clause-audited
 * (357)" first row, worked here for the two families that row's
 * predecessor sweep only ever gave a *first assertion* to:
 *
 *   src/unistd/ids.c    getuid geteuid getgid getegid getgroups
 *                       setuid seteuid setgid setegid setreuid setregid
 *                       getpgrp getpgid setpgid setpgrp setsid getsid
 *                       chown fchown lchown fchownat
 *   src/unistd/sleep.c  alarm pause
 *   src/unistd/gethostname.c  gethostname
 *   src/misc/resource.c nice  (audited here, with the rest of
 *                       <unistd.h>, but implemented beside
 *                       getpriority()/setpriority() so that the one
 *                       nice value has one owner)
 *
 * The distinction this file exists to draw, and the reason the earlier
 * sweep's "N/A -- one user, one session" is *not* repeated wholesale:
 * a degenerate identity model makes an *effect* unobservable, and that
 * is a fair N/A.  It does not make an *argument check* unobservable.
 * Every page below carries shall-fail [EINVAL]/[EPERM]/[EBADF]/[ESRCH]
 * clauses that constrain what the call may do with a bad argument no
 * matter how many users the platform has, and those are what this file
 * asserts.  Where the implementation answers "success" to a request it
 * demonstrably did not carry out, that is fenced BUG; where the effect
 * itself has nothing on NT to attach to, N/A with the mechanism named.
 *
 * Fence vocabulary is test/posix-termios.c's:
 *   #if 0 / * BUG: ... * /     spec violation, probed, not fixed here
 *   #if 0 / * UNIMPL: ... * /  genuinely not implemented
 *   #if 0 / * N/A: ... * /     a real NT mechanism makes it inapplicable
 *
 * Oracle: almost none of these functions makes an NT call -- the
 * exceptions are gethostname() (a getenv), alarm() (an NT waitable
 * timer, whose APC is what delivers SIGALRM) and the fd lookups they
 * *should* be making and do not.  Wine is therefore a sound oracle for
 * essentially all of it -- what is being measured is spicule's own C,
 * not NT's behaviour -- and for the one part that is NT's behaviour,
 * the timer, Wine's NtCreateTimer/NtSetTimer were measured to queue
 * and deliver the APC the same way the documented NT ones do.
 */
#define _GNU_SOURCE
#include "test-policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <sys/resource.h>	/* getpriority(), for the nice() cross-check */
#include <sys/stat.h>
#include <sys/wait.h>

static int fails;
static int unverified;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

extern char **environ;
/* Internal: spawn a program as a child and return its pid
 * (src/process/spawn.c).  fork() needs RtlCloneUserProcess, which stock
 * wine lacks, so this is how this suite gets a real child at all --
 * test/misc.c and test/exec.c use it the same way.  Needed here because
 * setpgid()'s [ESRCH] clause is about the *caller's own* children, and
 * nothing else in this file can produce one to point it at. */
int __spawn(const char *path, char *const argv[], char *const envp[]);

/* ============================================================
 * getuid / geteuid / getgid / getegid
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/getuid.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/geteuid.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgid.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/getegid.html
 * ============================================================ */

/* All four pages carry the identical RETURN VALUE and ERRORS text:
 * getuid.html RETURN VALUE "The getuid() function shall always be
 * successful and no return value is reserved to indicate the error."
 * ERRORS "No errors are defined."  There is no invalid return value and
 * no argument, so the whole testable content of these four pages is
 * (a) they return, (b) they do not disturb errno, and (c) they are
 * stable across calls -- an id that changed under a caller who never
 * asked for a change would break every "compare against getuid()"
 * idiom in the library (src/misc/pwd.c, src/stat/stat.c). */
static void test_getid_always_successful(void)
{
	uid_t u, eu;
	gid_t g, eg;

	errno = 0;
	u = getuid(); eu = geteuid(); g = getgid(); eg = getegid();
	CHECK(errno == 0);		/* "No errors are defined." */

	/* stable: a second call answers the same thing */
	CHECK(getuid() == u);
	CHECK(geteuid() == eu);
	CHECK(getgid() == g);
	CHECK(getegid() == eg);

	/* getuid.html DESCRIPTION: "shall return the real user ID of the
	 * calling process" -- a real uid_t value, not the (uid_t)-1 that
	 * chown.html reserves for "do not change". */
	CHECK(u != (uid_t)-1);
	CHECK(eu != (uid_t)-1);
	CHECK(g != (gid_t)-1);
	CHECK(eg != (gid_t)-1);
	/* 1000 is detect_uid()'s no-error fallback.  Every real NT token
	 * user SID maps elsewhere, so observing it means token detection did
	 * not run successfully and would leave the old bug indistinguishable. */
	CHECK(u != (uid_t)1000);

	/* N/A: geteuid.html's real-vs-effective distinction.  NT has no
	 * set-user-ID bit and no saved set-user-ID -- an NT process's
	 * token is not switched by executing a file -- so nothing on this
	 * platform can ever make the effective id differ from the real
	 * one.  src/unistd/ids.c derives both user IDs from the same token.
	 * That the two agree is asserted (test/posix-unistd.c's
	 * test_access_real_effective_uid_identical() already leans on it);
	 * that they *can* differ is unconstructible, not unimplemented. */
	CHECK(u == eu);
	CHECK(g == eg);

#ifdef __linux__
	/* fuzz/ntstubs.c supplies a local SAM SID ending in RID 4242.  This
	 * independent fixture distinguishes the token/RID mapping from the
	 * old hardcoded 1000 while exercising Cygwin's local 0x30000 range. */
	CHECK(u == (uid_t)(0x30000u + 4242u));
#endif
}

/* ============================================================
 * getgroups
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgroups.html
 * ============================================================ */
static void test_getgroups(void)
{
	gid_t list[NGROUPS_MAX + 1];
	int n, i;

	/* DESCRIPTION: "If gidsetsize is 0, getgroups() shall return the
	 * number of group IDs that it would otherwise return without
	 * modifying the array pointed to by grouplist." */
	memset(list, 0x5a, sizeof list);
	errno = 0;
	n = getgroups(0, list);
	CHECK(n >= 0);
	for (i = 0; i < (int)(sizeof list / sizeof list[0]); i++)
		CHECK(list[i] == (gid_t)0x5a5a5a5a);	/* array untouched */

	/* RETURN VALUE: "the number of supplementary group IDs shall be
	 * returned"; DESCRIPTION: "If the effective group ID of the process
	 * is returned with the supplementary group IDs, the value returned
	 * shall always be greater than or equal to one and less than or
	 * equal to the value of {NGROUPS_MAX}+1." */
	CHECK(n >= 1 && n <= NGROUPS_MAX + 1);

	/* DESCRIPTION: "The actual number of group IDs stored in the array
	 * shall be returned", and with room for all of them the same count
	 * must come back. */
	memset(list, 0x5a, sizeof list);
	errno = 0;
	CHECK(getgroups(NGROUPS_MAX, list) == n);
	CHECK(errno == 0);

	/* DESCRIPTION: "It is implementation-defined whether getgroups()
	 * also returns the effective group ID in the grouplist array." --
	 * so the *contents* are latitude.  What is not latitude is that the
	 * first n entries were actually written: "The values of array
	 * entries with indices greater than or equal to the value returned
	 * are undefined" says nothing about the ones below it. */
	for (i = 0; i < n; i++)
		CHECK(list[i] != (gid_t)0x5a5a5a5a);

	/* src/unistd/ids.c answers a single group equal to getegid(); that
	 * is the implementation-defined choice the clause above permits,
	 * and it must at least be self-consistent. */
	if (n == 1) CHECK(list[0] == getegid());

	/* getgroups.html ERRORS: "The getgroups() function *shall* fail
	 * if: [EINVAL] The gidsetsize argument is non-zero and less than
	 * the number of group IDs that would have been returned."  -1 is
	 * non-zero and is less than the 1 this implementation returns, so
	 * the clause applies exactly and it is a shall-fail, not a
	 * may-fail.  The array must come back untouched with it: a call
	 * that returns -1 stored no group IDs, and a caller that trusts a
	 * "1 group ID stored" answer for a buffer nothing was written to
	 * reads uninitialised memory. */
	memset(list, 0x5a, sizeof list);
	errno = 0;
	CHECK(getgroups(-1, list) == -1 && errno == EINVAL);
	for (i = 0; i < (int)(sizeof list / sizeof list[0]); i++)
		CHECK(list[i] == (gid_t)0x5a5a5a5a);

	/* [EINVAL] for a *positive* gidsetsize smaller than the count is
	 * unconstructible here rather than unimplemented, so there is no
	 * assertion for it.  The count is 1, and the smallest positive
	 * gidsetsize is 1, so no positive value is ever "less than the
	 * number of group IDs that would have been returned".  A one-group
	 * process cannot exhibit that error, on any implementation --
	 * src/unistd/ids.c still spells the comparison against the count
	 * rather than against zero, so the check does not become wrong if
	 * that count ever grows. */
}

/* ============================================================
 * setuid / seteuid / setgid / setegid / setreuid / setregid
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/setuid.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/seteuid.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/setgid.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/setegid.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/setreuid.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/setregid.html
 * ============================================================ */
static void test_setid_family(void)
{
	uid_t u = getuid();
	gid_t g = getgid();

	/* setuid.html DESCRIPTION: "If the process does not have
	 * appropriate privileges, but uid is equal to the real user ID or
	 * the saved set-user-ID, setuid() shall set the effective user ID
	 * to uid"; RETURN VALUE "Upon successful completion, 0 shall be
	 * returned."  Setting an id to the value it already has is the one
	 * request this platform can honestly grant, and it must succeed. */
	CHECK(setuid(u) == 0);
	CHECK(seteuid(u) == 0);
	CHECK(setgid(g) == 0);
	CHECK(setegid(g) == 0);

	/* setreuid.html DESCRIPTION: "If ruid or euid is -1, the
	 * corresponding effective or real user ID of the current process
	 * shall be left unchanged" -- the no-op call, which must succeed
	 * and change nothing. */
	CHECK(setreuid((uid_t)-1, (uid_t)-1) == 0);
	CHECK(setregid((gid_t)-1, (gid_t)-1) == 0);
	CHECK(setreuid(u, u) == 0);
	CHECK(setregid(g, g) == 0);

	/* setuid.html RETURN VALUE, read the other way: a *successful*
	 * setuid() has set the effective user ID to uid, so geteuid() must
	 * agree with what was just asked for.  After the identity calls
	 * above -- all of which asked for the id already in force -- the
	 * getters must still answer that id. */
	CHECK(getuid() == u && geteuid() == u);
	CHECK(getgid() == g && getegid() == g);

	/* setuid.html DESCRIPTION: "The setuid() function shall not affect
	 * the supplementary group list in any way", and setgid.html: "Any
	 * supplementary group IDs of the calling process shall remain
	 * unchanged."  Observable here through getgroups(). */
	{
		gid_t before[NGROUPS_MAX + 1], after[NGROUPS_MAX + 1];
		int nb = getgroups(NGROUPS_MAX, before);
		CHECK(setuid(u) == 0);
		CHECK(setgid(g) == 0);
		CHECK(getgroups(NGROUPS_MAX, after) == nb);
		if (nb > 0) CHECK(!memcmp(before, after, (size_t)nb * sizeof(gid_t)));
	}

	/* setuid.html ERRORS: "The setuid() function *shall* fail, return
	 * -1, and set errno to the corresponding value if one or more of
	 * the following are true: ... [EPERM] The process does not have
	 * appropriate privileges and uid does not match the real user ID
	 * or the saved set-user-ID."  seteuid.html, setgid.html and
	 * setegid.html carry the identical clause for their own id, and
	 * setreuid.html/setregid.html carry the equivalent one ("[EPERM]
	 * The current process does not have appropriate privileges, and
	 * ... an attempt was made to change the effective user ID to a
	 * value other than the real user ID or the saved set-user-ID").
	 *
	 * sysconf(_SC_SAVED_IDS) is -1 on this platform
	 * (src/unistd/sysconf.c), so there is no saved set-user-ID to
	 * match either, and uid 0 is not this token-derived user ID -- the
	 * clause's precondition holds exactly.
	 *
	 * "One user, so the *effect* is unobservable" is a sound argument
	 * for the success path.  It is not an argument for reporting
	 * success to setuid(0): that answer is a claim the caller acts on
	 * -- every privilege-dropping idiom in Unix software is
	 * `if (setuid(pw->pw_uid) != 0) abort();`, and an answer of 0
	 * turns "refuse to run unprivileged" into "run believing the drop
	 * happened".  src/unistd/ids.c's set_one_id() therefore refuses
	 * any id that is not the one identity this library has. */
	errno = 0; CHECK(setuid(0) == -1 && errno == EPERM);
	errno = 0; CHECK(seteuid(0) == -1 && errno == EPERM);
	errno = 0; CHECK(setgid(0) == -1 && errno == EPERM);
	errno = 0; CHECK(setegid(0) == -1 && errno == EPERM);
	errno = 0; CHECK(setreuid(0, 0) == -1 && errno == EPERM);
	errno = 0; CHECK(setregid(0, 0) == -1 && errno == EPERM);

	/* setuid.html ERRORS: "[EINVAL] The value of the uid argument is
	 * invalid and not supported by the implementation" -- also a
	 * shall-fail, and the seteuid/setgid/setegid pages plus
	 * setreuid.html/setregid.html ("[EINVAL] The value of the ruid or
	 * euid argument is invalid or out-of-range") say the same.
	 *
	 * (uid_t)-1 is the reserved "unchanged" marker for setreuid() and
	 * is not an assumable ID for the one-argument calls.  Other values
	 * in the upper half are valid because trusted-domain offsets use
	 * that range. */
	errno = 0; CHECK(setuid((uid_t)-1) == -1 && errno == EINVAL);
	errno = 0; CHECK(setgid((gid_t)-1) == -1 && errno == EINVAL);
}

#if defined(__linux__) && !defined(_SPICULE_NATIVE_BUILD)
/* ============================================================
 * setresuid / setresgid / getresuid / getresgid (Linux backend)
 * https://man7.org/linux/man-pages/man2/setresuid.2.html
 *
 * _GNU_SOURCE-only, and real only on native Linux (src/unistd/linux/
 * plat_ids.c) -- see include/unistd.h's own updated comment: NT's
 * single-fixed-identity reasoning stays true there, so these four are
 * still undefined-ok on that build. Guarded out of both the NT/Wine
 * build (__linux__ undefined there) and the native-ASan harness
 * (_SPICULE_NATIVE_BUILD, which links only the NT backend against
 * fuzz/ntstubs.c and so has no real definition of any of these four --
 * see tools/asan-build.sh's own "other platform" skip rule for every
 * Linux-backend source file under src/.
 * ============================================================ */
static void test_res_ids(void)
{
	uid_t ru, eu, su;
	gid_t rg, eg, sg;

	CHECK(getresuid(&ru, &eu, &su) == 0);
	CHECK(getresgid(&rg, &eg, &sg) == 0);
	/* This process never called setuid()/setresuid() before now, so
	 * the real/effective/saved triple the kernel reports agrees with
	 * plain getuid()/getgid() -- both real on this backend (see
	 * src/unistd/linux/plat_unistd.c's __plat_detect_uid()/
	 * __plat_detect_gid()). */
	CHECK(ru == getuid() && eu == getuid() && su == getuid());
	CHECK(rg == getgid() && eg == getgid() && sg == getgid());

	/* Every argument (uid_t)-1 changes nothing -- real Linux semantics,
	 * the same "leave alone" marker setreuid() already documents for
	 * its own two arguments -- and needs no privilege, so this
	 * exercises the syscall's real success path even when the test
	 * harness itself runs unprivileged. */
	CHECK(setresuid((uid_t)-1, (uid_t)-1, (uid_t)-1) == 0);
	CHECK(setresgid((gid_t)-1, (gid_t)-1, (gid_t)-1) == 0);
	/* getuid()/getgid() still agree afterward: setresuid()/setresgid()
	 * on success invalidate src/unistd/ids.c's own cache
	 * (__ids_creds_cache_invalidate()), so this also proves that
	 * invalidation does not desync the two from the real kernel id. */
	CHECK(getuid() == ru);
	CHECK(getgid() == rg);

	/* An unprivileged process may not set an id it does not already
	 * hold to something else. */
	if (ru != 0) {
		errno = 0;
		CHECK(setresuid(0, ru, ru) == -1);
		CHECK(errno == EPERM);
	}
}

/* ============================================================
 * euidaccess / eaccess (Linux backend)
 * https://man7.org/linux/man-pages/man3/euidaccess.3.html
 * ============================================================ */
static void test_euidaccess(void)
{
	char tmpl[] = "posixeuidacc-XXXXXX";
	int fd;

	fd = mkstemp(tmpl);
	CHECK(fd >= 0);
	if (fd >= 0) close(fd);

	CHECK(chmod(tmpl, 0644) == 0);
	CHECK(euidaccess(tmpl, F_OK) == 0);
	CHECK(euidaccess(tmpl, R_OK) == 0);
	CHECK(eaccess(tmpl, R_OK) == 0);

	if (getuid() != 0) {
		/* Root bypasses every permission bit, so this half only holds
		 * for an unprivileged test run -- the common case, and the
		 * one this whole function (the EFFECTIVE-id check) exists to
		 * prove. */
		CHECK(chmod(tmpl, 0000) == 0);
		errno = 0;
		CHECK(euidaccess(tmpl, R_OK) == -1);
		CHECK(errno == EACCES);
		chmod(tmpl, 0644);
	}
	unlink(tmpl);

	errno = 0;
	CHECK(euidaccess("/no/such/path/at/all/spicule-test", F_OK) == -1);
	CHECK(errno == ENOENT);
}
#endif

/* ============================================================
 * getpgrp / getpgid / getsid / setpgid / setpgrp / setsid
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpgrp.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpgid.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/getsid.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/setpgid.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/setpgrp.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/setsid.html
 * ============================================================ */
static void test_process_group_and_session(const char *exe)
{
	pid_t self = getpid();

	/* getpgrp.html RETURN VALUE: "The getpgrp() function shall always
	 * be successful and no return value is reserved to indicate an
	 * error."  ERRORS: "No errors are defined." */
	errno = 0;
	CHECK(getpgrp() > 0);
	CHECK(errno == 0);

	/* getpgid.html DESCRIPTION: "If pid is equal to 0, getpgid() shall
	 * return the process group ID of the calling process" -- so
	 * getpgid(0) and getpgrp() must be the same number, and so must
	 * getpgid(getpid()). */
	CHECK(getpgid(0) == getpgrp());
	CHECK(getpgid(self) == getpgrp());

	/* getsid.html DESCRIPTION: "If pid is (pid_t)0, it specifies the
	 * calling process."  Same identity for the session getter. */
	CHECK(getsid(0) == getsid(self));

	/* RETURN VALUE on both pages: a process group ID, with (pid_t)-1
	 * reserved for the error return -- so a successful answer is never
	 * -1. */
	CHECK(getpgid(0) != (pid_t)-1);
	CHECK(getsid(0) != (pid_t)-1);

	/* setpgid.html DESCRIPTION: "As a special case, if pid is 0, the
	 * process ID of the calling process shall be used.  Also, if pgid
	 * is 0, the process ID of the indicated process shall be used."
	 * RETURN VALUE: "Upon successful completion, setpgid() shall
	 * return 0."  Joining the group the process is already in is the
	 * request this platform can grant. */
	CHECK(setpgid(0, getpgrp()) == 0);
	CHECK(setpgid(self, getpgrp()) == 0);

	/* getpgid.html ERRORS: "The getpgid() function *shall* fail if:
	 * ... [ESRCH] There is no process with a process ID equal to
	 * pid."  getsid.html carries the identical shall-fail clause.
	 * The clause is about the existence of a *process*, so a
	 * one-session platform is bound by it like any other; both
	 * getters resolve pid through src/unistd/ids.c's pid_exists()
	 * (the child table of src/process/children.c, then an
	 * NtOpenProcess by CLIENT_ID) rather than discarding it. */
	errno = 0;
	CHECK(getpgid(999999) == (pid_t)-1 && errno == ESRCH);
	errno = 0;
	CHECK(getsid(999999) == (pid_t)-1 && errno == ESRCH);

	/* A negative pid names no process either; kill() reports ESRCH
	 * for one (src/signal/signal.c) and these agree. */
	errno = 0;
	CHECK(getpgid(-2) == (pid_t)-1 && errno == ESRCH);
	errno = 0;
	CHECK(getsid(-2) == (pid_t)-1 && errno == ESRCH);

	/* ...and the pids that *do* name a process still answer, with
	 * errno untouched: a check that fails everything would satisfy
	 * the four assertions above and violate getpgid.html's "If pid is
	 * equal to 0 ..." and RETURN VALUE, which the next four pin from
	 * the other side. */
	errno = 0;
	CHECK(getpgid(0) == getpgrp() && errno == 0);
	CHECK(getpgid(self) == getpgrp() && errno == 0);
	CHECK(getsid(0) != (pid_t)-1 && errno == 0);
	CHECK(getsid(self) == getsid(0) && errno == 0);

	/* setpgid.html ERRORS, both shall-fail:
	 *   "[EINVAL] The value of the pgid argument is less than 0, or is
	 *    not a value supported by the implementation."
	 *   "[ESRCH] The value of the pid argument does not match the
	 *    process ID of the calling process or of a child process of
	 *    the calling process."
	 *
	 * Neither needs a process-group model.  [EINVAL] is a range check
	 * on a signed value.  [ESRCH] is a *narrower* question than the
	 * getpgid()/getsid() clause above -- "the calling process or ... a
	 * child process of the calling process", not "there is no process
	 * with a process ID equal to pid" -- so src/unistd/ids.c answers it
	 * from the child table (src/process/children.c) alone rather than
	 * from the pid_exists() those two use, and setpgid() therefore
	 * makes no NT call for any argument.  999999 is the unallocated pid
	 * the getters are probed with above; for them it fails because
	 * nothing has that pid, for setpgid() it would fail even if
	 * something did.
	 *
	 * The order the two are checked in is itself specified: pgid 0
	 * means "the process ID of the indicated process", so there is no
	 * pgid to judge until pid is known to indicate a process of the
	 * caller's -- setpgid(999999, 0) is [ESRCH], not an [EINVAL] about
	 * a pgid that was never resolved. */
	errno = 0;
	CHECK(setpgid(0, -1) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(setpgid(999999, 0) == -1 && errno == ESRCH);

	/* The other half of the [ESRCH] clause, which the two assertions
	 * above cannot reach: a real child of this process must be
	 * *accepted*, and must stop being accepted once wait() has
	 * collected it (a reaped child is no longer a child process of the
	 * calling process).  Without this pair, a setpgid() that accepted
	 * nothing but the caller itself would satisfy everything asserted
	 * so far while breaking the one call every job-control parent makes
	 * -- setpgid(child, pgid) from the parent side of a fork.
	 *
	 * Spawning is a note-and-skip rather than a failure: what it probes
	 * is an additional case, and the clause assertions above do not
	 * depend on a child existing. */
	{
		char *av[3];
		int pid, status;

		av[0] = (char *)exe;
		av[1] = (char *)"--child";
		av[2] = NULL;
		pid = __spawn(exe, av, environ);
		if (pid < 0) {
			printf("note: cannot spawn \"%s\" (errno %d); setpgid()'s child clause not probed\n",
			       exe, errno);
		} else {
			errno = 0;
			CHECK(setpgid(pid, getpgrp()) == 0 && errno == 0);
			/* ...and the pgid range check applies to a child too */
			errno = 0;
			CHECK(setpgid(pid, -1) == -1 && errno == EINVAL);
			CHECK(waitpid(pid, &status, 0) == pid);
			errno = 0;
			CHECK(setpgid(pid, getpgrp()) == -1 && errno == ESRCH);
		}
	}

	/* setsid.html DESCRIPTION: "The setsid() function shall create a
	 * new session, if the calling process is not a process group
	 * leader.  Upon return the calling process shall be the session
	 * leader of this new session ... The process group ID of the
	 * calling process shall be set equal to the process ID of the
	 * calling process."  RETURN VALUE: "the value of the new process
	 * group ID of the calling process."  ERRORS: "[EPERM] The calling
	 * process is already a process group leader".
	 *
	 * Read together those make a state machine with one transition,
	 * and this is the whole of it: a process is born into a group it
	 * does not lead -- src/unistd/ids.c starts the process group id at
	 * 1, a number no pid can be, so `pgid == getpid()` is false at
	 * startup by construction -- so the first call succeeds and leaves
	 * pgid == pid, and the second must fail.
	 *
	 * This runs before the self-consistency checks below rather than
	 * after them for that reason: the transition can be spent only
	 * once per process, and setpgrp() first would spend it, its one
	 * specified effect being to make the caller a group leader, which
	 * is precisely [EPERM]'s precondition.  (setpgrp()'s *effect* is
	 * therefore asserted from the other end, in test/posix-unistd.c's
	 * test_id_session_stubs, whose process has not been made a session
	 * leader by the time it gets there.) */
	CHECK(setsid() == getpid());
	CHECK(getpgrp() == getpid());
	CHECK(getsid(0) == getpgrp());
	errno = 0;
	CHECK(setsid() == (pid_t)-1 && errno == EPERM);
	/* ... and a call that failed changed nothing. */
	CHECK(getpgrp() == getpid() && getsid(0) == getpid());

	/* setpgrp.html DESCRIPTION: "If the calling process is not already
	 * a session leader, setpgrp() sets the process group ID of the
	 * calling process to the process ID of the calling process."
	 * RETURN VALUE: "Upon completion, setpgrp() shall return the
	 * process group ID."  ERRORS: "No errors are defined."
	 *
	 * The setsid() above made this process a session leader, so the
	 * conditional effect is a no-op here and what is left to check is
	 * the return: the process group ID -- which that same setsid() has
	 * made equal to the process ID -- and that it is the same number
	 * getpgrp() reports afterwards, with errno untouched. */
	errno = 0;
	CHECK(setpgrp() == getpid());
	CHECK(setpgrp() == getpgrp());
	CHECK(errno == 0);

	/* N/A, with the mechanism: setpgid()'s [EACCES] ("the child
	 * process has successfully executed one of the exec functions")
	 * and its two remaining [EPERM] clauses, and the [EPERM] clauses
	 * of getpgid()/getsid() ("not in the same session as the calling
	 * process").  All four presuppose a second process in a
	 * *different* session or process group from the caller, and that a
	 * process can *name* it.  Neither is constructible.  The group and
	 * session ids src/unistd/ids.c keeps are per-process bookkeeping
	 * with no registry behind them -- nothing there can report another
	 * process's group or session (getpgid()/getsid() ignore their pid,
	 * the fence above) -- and NT has no session or process-group object
	 * for src/process/spawn.c to put a child into a different one of:
	 * a console process group is the nearest construct and cannot be
	 * joined (src/process/posix_spawn.c's banner).  Making setsid()
	 * real did not change that; it added a transition the *caller* can
	 * observe about itself, which is a different thing from a second
	 * process to compare against.  So the *precondition*
	 * of each of those clauses is unconstructible rather than merely
	 * unimplemented, which is what separates them from the [ESRCH] and
	 * [EINVAL] fences above -- those need only a pid range check. */
}

/* ============================================================
 * chown / fchown / lchown / fchownat
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/chown.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/fchown.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/lchown.html
 * ============================================================ */
static void test_chown_family(void)
{
	struct stat before, after;
	int fd;

	fd = open("chf.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(stat("chf.txt", &before) == 0);

	/* chown.html RETURN VALUE: "Upon successful completion, these
	 * functions shall return 0."  DESCRIPTION: "If owner or group is
	 * specified as (uid_t)-1 or (gid_t)-1, respectively, the
	 * corresponding ID of the file shall not be changed."
	 *
	 * The success path is already asserted by test/posix-unistd.c's
	 * test_id_session_stubs(); what is added here is the clause
	 * *pair* that a stub can still be held to -- a successful chown to
	 * the ids the file already has must leave st_uid/st_gid exactly
	 * where they were, and so must the (uid_t)-1 form. */
	CHECK(chown("chf.txt", getuid(), getgid()) == 0);
	CHECK(chown("chf.txt", (uid_t)-1, (gid_t)-1) == 0);
	CHECK(lchown("chf.txt", (uid_t)-1, (gid_t)-1) == 0);
	CHECK(fchown(fd, (uid_t)-1, (gid_t)-1) == 0);
	CHECK(fchownat(AT_FDCWD, "chf.txt", (uid_t)-1, (gid_t)-1, 0) == 0);
	CHECK(stat("chf.txt", &after) == 0);
	CHECK(after.st_uid == before.st_uid && after.st_gid == before.st_gid);

	/* chown.html DESCRIPTION: "If the specified file is a regular
	 * file, one or more of the S_IXUSR, S_IXGRP, or S_IXOTH bits of
	 * the file mode are set, and the process does not have appropriate
	 * privileges, the set-user-ID (S_ISUID) and set-group-ID (S_ISGID)
	 * bits of the file mode shall be cleared upon successful return."
	 *
	 * N/A, with the mechanism: spicule reserves $LXMOD for the execute
	 * permission mapping and does not expose its set-user-ID or
	 * set-group-ID bits; FILE_ATTRIBUTE_READONLY remains the write
	 * mapping.  st_mode can therefore never
	 * come back with S_ISUID set, so "shall be cleared" has nothing to
	 * clear.  Asserted in the only direction that is observable: the
	 * bits are absent before and after. */
	CHECK((before.st_mode & (S_ISUID | S_ISGID)) == 0);
	CHECK((after.st_mode & (S_ISUID | S_ISGID)) == 0);

	CHECK(close(fd) == 0);

	/* chown.html ERRORS, all shall-fail:
	 *   "[ENOENT] A component of path does not name an existing file
	 *    or path is an empty string."
	 *   "[ENOTDIR] A component of the path prefix names an existing
	 *    file that is neither a directory nor a symbolic link to a
	 *    directory ..."
	 * lchown.html repeats both.  fchown.html: "[EBADF] The fildes
	 * argument is not an open file descriptor."  chown.html's
	 * fchownat() section: "[EBADF] The path argument does not specify
	 * an absolute path and the fd argument is neither AT_FDCWD nor a
	 * valid file descriptor open for reading or searching".
	 *
	 * The degenerate-stub argument -- "NT has no uid/gid to set, so
	 * the effect is unobservable" -- is sound about *ownership* and
	 * says nothing about *path resolution*.  chown("does-not-exist",
	 * ...) returning 0 is not a statement about ownership, it is a
	 * statement that the file exists, and it is false: `chown()`
	 * failing with ENOENT is a standard existence probe, and an
	 * installer that chowns a list of files it has just laid down
	 * loses its only report that one of them is missing.  All four
	 * now run their path through __ntpath_at() and open the object
	 * for FILE_READ_ATTRIBUTES, or their descriptor through
	 * __fd_get(); see src/unistd/ids.c's chown_resolve(). */
	errno = 0; CHECK(chown("chown-no-such-file", getuid(), getgid()) == -1 && errno == ENOENT);
	errno = 0; CHECK(chown("", getuid(), getgid()) == -1 && errno == ENOENT);
	errno = 0; CHECK(lchown("chown-no-such-file", getuid(), getgid()) == -1 && errno == ENOENT);
	errno = 0; CHECK(chown("chf.txt/under-a-file", getuid(), getgid()) == -1 && errno == ENOTDIR);
	errno = 0; CHECK(fchown(4096, getuid(), getgid()) == -1 && errno == EBADF);
	errno = 0; CHECK(fchownat(4096, "rel", getuid(), getgid(), 0) == -1 && errno == EBADF);
	errno = 0; CHECK(fchownat(AT_FDCWD, "chown-no-such-file", getuid(), getgid(), 0) == -1 && errno == ENOENT);

	/* fchownat()'s [EINVAL] ("The value of the flag argument is not
	 * valid") is a *may*-fail on chown.html, not a shall-fail, so
	 * accepting an undefined flag bit is permitted here and is not
	 * fenced -- unlike unlinkat(), whose flag masking was a bug and is
	 * fixed (test/posix-unistd.c's test_unlinkat() asserts it), because
	 * unlink.html makes its [EINVAL] a shall-fail and because there the
	 * accepted bit changed what the call *did*.  fchownat() does
	 * nothing either way. */
	CHECK(fchownat(AT_FDCWD, "chf.txt", (uid_t)-1, (gid_t)-1, 0x9999) == 0);

	CHECK(unlink("chf.txt") == 0);

	/* N/A, with the mechanism, for the rest of chown.html's ERRORS:
	 * [EACCES] and [EPERM] need a file whose owner differs from the
	 * caller's effective user ID, which one fixed identity cannot
	 * produce; [EROFS] needs a read-only mount; [ELOOP] needs a
	 * symbolic-link cycle, which src/internal/path.c hands to NT's own
	 * resolver rather than walking itself; [EIO]/[EINTR] are may-fail.
	 * Every one of those is unreachable *before* reaching the stub,
	 * i.e. they would be unreachable even if the four functions were
	 * fully implemented -- which is what distinguishes them from the
	 * fenced clauses above. */
}

/* ============================================================
 * alarm / pause
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/alarm.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/pause.html
 * ============================================================ */
static volatile sig_atomic_t alarm_caught;
static void alarm_catcher(int s) { (void)s; alarm_caught++; }

static void test_alarm(void)
{
	void (*prev)(int);
	unsigned left;

	/* alarm.html ERRORS: "The alarm() function is always successful,
	 * and no return value is reserved to indicate an error."  RETURN
	 * VALUE: "Otherwise, alarm() shall return 0" -- "otherwise" being
	 * "no previous alarm() request with time remaining".  With no
	 * alarm ever set, 0 is the required answer and errno must be
	 * untouched. */
	errno = 0;
	CHECK(alarm(0) == 0);
	CHECK(errno == 0);

	/* alarm.html DESCRIPTION: "The alarm() function shall cause the
	 * system to generate a SIGALRM signal for the process after the
	 * number of realtime seconds specified by seconds have elapsed.
	 * ... If seconds is 0, a pending alarm request, if any, is
	 * canceled."  RETURN VALUE: "If there is a previous alarm()
	 * request with time remaining, alarm() shall return a non-zero
	 * value that is the number of seconds until the previous request
	 * would have generated a SIGALRM signal."
	 *
	 * Schedule far enough out that no plausible scheduling delay could
	 * have expired it, then read the remaining time back and cancel.
	 * The bound is 99..100 rather than == 100 only because the two
	 * calls read the clock separately; the round-*up* alarm() performs
	 * is what stops a request with 99.99 seconds to run reporting the
	 * 0 that means "no request pending". */
	CHECK(alarm(100) == 0);		/* no previous request */
	left = alarm(0);
	CHECK(left >= 99 && left <= 100);
	CHECK(alarm(0) == 0);		/* and now it is cancelled */

	/* A new request replaces the old one and reports what the old one
	 * had left, which is the same RETURN VALUE clause read the other
	 * way round: "a previous alarm() request with time remaining" does
	 * not have to have been cancelled to be reported. */
	CHECK(alarm(100) == 0);
	left = alarm(50);
	CHECK(left >= 99 && left <= 100);
	left = alarm(0);
	CHECK(left >= 49 && left <= 50);

	/* And the signal itself.  src/unistd/sleep.c arms an NT waitable
	 * timer whose expiry queues a user APC that calls SIGALRM's
	 * disposition, and NT runs a queued user APC only while the thread
	 * is in an alertable wait -- so this asserts delivery the one way
	 * it is reachable here, from inside a sleep().  sleep.html RETURN
	 * VALUE: "If sleep() returns due to the delivery of a signal, the
	 * value returned shall be the 'unslept' amount ... in seconds",
	 * which is what makes the early return distinguishable from a
	 * sleep(5) that simply ran its course.
	 *
	 * Not fenced, and deliberately not written with pause(): what is
	 * still out of reach is delivery to a thread that is neither
	 * sleeping nor paused, and that is recorded in
	 * test/POSIX-GAP-ACCOUNTING.md rather than asserted here.
	 *
	 * RETRIED, and reported unverified rather than failed if every
	 * attempt is dropped.  MEASURED on the Wine leg of this tree
	 * (stock Wine 9.0, x86_64): a bare alarm(1) + sleep(5) loses the
	 * SIGALRM outright in about 1 run in 8 on an idle machine and in
	 * roughly 2 of 3 with six of them running at once -- and it is
	 * LOST, not late: the same probe with sleep(30) still reports
	 * nothing caught after the full thirty seconds in the runs that
	 * miss, so no timeout makes it reliable.  Nothing on the spicule
	 * side is timing-dependent (one NtSetTimer with an absolute due
	 * time and an APC routine, then one alertable NtDelayExecution),
	 * so the drop is between wineserver's timer expiry and the APC
	 * reaching the waiting thread.
	 *
	 * The retry is what keeps this a real assertion instead of a
	 * coin-flip: a delivery path that worked would satisfy the FIRST
	 * attempt, and the fallback below reports "not observed" rather
	 * than "passed", so nothing here can go green on an
	 * implementation that never delivers.  Real Windows is the oracle
	 * (.github/workflows/ci.yml runs this suite on Server 2025), and
	 * there the first attempt is expected to carry it. */
	prev = signal(SIGALRM, alarm_catcher);
	CHECK(prev != SIG_ERR);
	{
		int attempt;
		int delivered = 0;
		for (attempt = 0; attempt < 4 && !delivered; attempt++) {
			alarm_caught = 0;
			CHECK(alarm(1) == 0);
			left = sleep(5);
			if (alarm_caught == 1) {
				delivered = 1;
				CHECK(left >= 3 && left <= 5);
				/* the request was spent on its delivery */
				CHECK(alarm(0) == 0);
			} else {
				/* nothing arrived; the request has expired
				 * either way, so there is nothing to cancel */
				CHECK(left == 0);
				CHECK(alarm(0) == 0);
			}
		}
		if (!delivered) {
			printf("SKIP posix-unistd-ids SIGALRM delivery: the timer "
			       "APC was dropped on all %d attempts (see the "
			       "comment above -- measured as a runtime defect, "
			       "not a timeout); alarm()'s arming, reporting and "
			       "cancellation were still checked above\n", attempt);
			unverified++;
		}
	}
	CHECK(signal(SIGALRM, prev) == alarm_catcher);

#if SPICULE_TEST(NA, posix_ids_pause_requires_async_signal_delivery) /* N/A: pause() cannot be called from this suite at all --
	 * calling it deadlocks the run rather than failing it.
	 *
	 * pause.html DESCRIPTION: "The pause() function shall suspend the
	 * calling thread until delivery of a signal whose action is either
	 * to execute a signal-catching function or to terminate the
	 * process."  RETURN VALUE: "there is no successful completion
	 * return value.  A value of -1 shall be returned and errno set to
	 * indicate the error."  ERRORS: "[EINTR] A signal is caught by the
	 * calling process and control is returned from the signal-catching
	 * function."
	 *
	 * Every clause on the page is conditioned on a signal arriving,
	 * and *this* call has no way of arranging one.  src/unistd/sleep.c
	 * implements pause() as an alertable NtDelayExecution with a
	 * maximal (0x7fffffffffffffff) timeout, and exactly one thing in
	 * this library can end it: an alarm() timer's APC, which is why
	 * test_alarm() above can assert SIGALRM delivery into a sleep().
	 * With no alarm pending -- which is the state pause() is called in
	 * here, and the state a pause() that means "wait for something
	 * from outside" is always in -- nothing can alert the wait, because
	 * src/signal/signal.c still raises signals only from within the
	 * raising thread.
	 *
	 * N/A rather than UNIMPL, at the level of *this page*: the errno
	 * and the -1 return are already written correctly for the case
	 * they describe, and what is missing is asynchronous signal
	 * delivery from outside the process, which is a signal.h gap the
	 * ledger records against that header.  This is also the one name in
	 * test/POSIX-GAP-ACCOUNTING.md's original never-asserted 112 that
	 * that sweep could not give an assertion to, for this exact
	 * reason.  It must stay fenced: enabling it hangs `make check`
	 * until the job timeout. */
	{
		int r;
		errno = 0;
		r = pause();
		CHECK(r == -1 && errno == EINTR);
	}
#endif
}

/* ============================================================
 * nice
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/nice.html
 * ============================================================ */
static void test_nice(void)
{
	/* nice.html RETURN VALUE: "Upon successful completion, nice()
	 * shall return the new nice value -{NZERO}.  Otherwise, -1 shall
	 * be returned, the nice value of the process shall not be changed,
	 * and errno shall be set to indicate the error."  APPLICATION
	 * USAGE: "As -1 is a permissible return value in a successful
	 * situation, an application wishing to check for error situations
	 * should set errno to 0, then call nice(), and if it returns -1,
	 * check to see whether errno is non-zero."
	 *
	 * nice(0) adds nothing, so it must succeed and report the current
	 * nice value relative to {NZERO} -- checked here in the errno-0
	 * form the page itself prescribes. */
	errno = 0;
	CHECK(nice(0) != -1 || errno == 0);
	CHECK(errno == 0);

	/* DESCRIPTION: "A maximum nice value of 2*{NZERO}-1 and a minimum
	 * nice value of 0 shall be imposed by the system.  Requests for
	 * values above or below these limits shall result in the nice
	 * value being set to the corresponding limit."  So a successful
	 * return is always in [-{NZERO}, {NZERO}-1], for any incr. */
	errno = 0;
	CHECK(nice(0) >= -NZERO && nice(0) <= NZERO - 1);

	/* DESCRIPTION: "The nice() function shall add the value of incr to
	 * the nice value of the calling process."  RETURN VALUE: "shall
	 * return the new nice value -{NZERO}."
	 *
	 * WATCH THE ORIGIN, because the text this fence used to carry got
	 * it wrong and asserted `nice(5) == 5 - NZERO`: a process starts at
	 * nice value {NZERO} (XBD <limits.h>: "{NZERO} Default process
	 * priority"), so "the new nice value -{NZERO}" after nice(5) is
	 * 5, and subtracting {NZERO} a second time would report a process
	 * pinned at the most favourable priority it can have.  Measured on
	 * glibc/Linux, unprivileged: nice(0)=0, nice(5)=5, a following
	 * nice(0)=5, nice(-5)=-1/EPERM, nice(1000)=19. */
	errno = 0;
	CHECK(nice(5) == 5);
	CHECK(errno == 0);		/* success must not disturb errno */
	CHECK(nice(0) == 5);		/* the previous call stuck */

	/* The value nice() reports is the value getpriority() reports:
	 * src/misc/resource.c keeps one copy of it and nice() is written in
	 * terms of getpriority()/setpriority(), so the two pages cannot
	 * describe this process's priority differently.  <sys/resource.h>
	 * is included for this one assertion; the getpriority()/
	 * setpriority() clauses themselves are audited in
	 * test/posix-sysmisc.c. */
	errno = 0;
	CHECK(getpriority(PRIO_PROCESS, 0) == 5);
	CHECK(errno == 0);

	/* "A maximum nice value of 2*{NZERO}-1 ... shall be imposed by the
	 * system.  Requests for values above ... these limits shall result
	 * in the nice value being set to the corresponding limit" -- so an
	 * absurd incr clamps and succeeds rather than failing or wrapping. */
	errno = 0;
	CHECK(nice(1000) == NZERO - 1);
	CHECK(errno == 0);

	/* ERRORS: "[EPERM] The incr argument is negative and the calling
	 * process does not have appropriate privileges", the page's only
	 * error.  spicule has exactly one user and it is never privileged
	 * (src/unistd/ids.c), so this is decided here rather than asked of
	 * NT -- which, probed, accepts every priority raise including
	 * REALTIME and would leave the clause unreachable.  The test is
	 * therefore live on any host, root or not. */
	errno = 0;
	CHECK(nice(-5) == -1 && errno == EPERM);

	/* RETURN VALUE, failure half: "the nice value of the process shall
	 * not be changed". */
	errno = 0;
	CHECK(nice(0) == NZERO - 1);
	CHECK(errno == 0);
}

/* ============================================================
 * gethostname
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/gethostname.html
 * ============================================================ */
static void test_gethostname(void)
{
	char buf[HOST_NAME_MAX + 1];
	char small[8];
	size_t n;

	/* DESCRIPTION: "The gethostname() function shall return the
	 * standard host name for the current machine. ... The returned
	 * name shall be null-terminated" when namelen is sufficient.
	 * RETURN VALUE: "Upon successful completion, 0 shall be returned."
	 * ERRORS: "No errors are defined." */
	memset(buf, '@', sizeof buf);
	errno = 0;
	CHECK(gethostname(buf, sizeof buf) == 0);
	CHECK(errno == 0);
	n = strlen(buf);
	CHECK(n > 0);
	CHECK(buf[n] == 0);			/* null-terminated */

	/* DESCRIPTION: "Host names are limited to {HOST_NAME_MAX} bytes." */
	CHECK(n <= HOST_NAME_MAX);

	/* A second call must answer the same name -- the "standard host
	 * name for the current machine" is not a per-call choice. */
	{
		char again[HOST_NAME_MAX + 1];
		CHECK(gethostname(again, sizeof again) == 0);
		CHECK(!strcmp(again, buf));
	}

	/* Exactly-fits is the boundary the truncation clause hinges on:
	 * namelen == strlen(name) + 1 is sufficient, so it must succeed
	 * and be null-terminated. */
	if (n + 1 <= sizeof buf) {
		char exact[HOST_NAME_MAX + 1];
		memset(exact, '@', sizeof exact);
		errno = 0;
		CHECK(gethostname(exact, n + 1) == 0);
		CHECK(errno == 0);
		CHECK(!strcmp(exact, buf));
	}

	/* The truncation *does* happen -- what the fence below is about is
	 * only what is reported afterwards.  src/unistd/gethostname.c
	 * memcpy()s namelen bytes before returning -1, so the first
	 * namelen bytes of the name really are in the buffer, which is
	 * what the clause requires; it is unspecified whether the result
	 * is null-terminated, so only the prefix is checked. */
	if (n >= sizeof small) {
		memset(small, '@', sizeof small);
		(void)gethostname(small, 4);
		CHECK(!memcmp(small, buf, 4));
		CHECK(small[4] == '@');		/* nothing written past namelen */
	}

#if SPICULE_TEST(PASS, posix_ids_gethostname_short_buffer_succeeds) /* gethostname() truncates successfully when the buffer is short.
	 * when the name does not fit.
	 *
	 * gethostname.html DESCRIPTION: "The namelen argument shall
	 * specify the size of the array pointed to by the name argument.
	 * The returned name shall be null-terminated, except that if
	 * namelen is an insufficient length to hold the host name, then
	 * the returned name shall be truncated and it is unspecified
	 * whether the returned name is null-terminated."  ERRORS: "No
	 * errors are defined."
	 *
	 * Truncation *is* the specified behaviour for a short buffer, so
	 * it is a successful completion and RETURN VALUE's "Upon
	 * successful completion, 0 shall be returned" applies to it.
	 * src/unistd/gethostname.c:15 instead does
	 *     if (n >= len) { memcpy(name, h, len); errno = ENAMETOOLONG; return -1; }
	 * -- it performs the required truncation and then reports it as a
	 * failure, with an errno the page does not list.  A caller
	 * following the page has no reason to look at the buffer after a
	 * -1 and loses the truncated name it is entitled to.
	 *
	 * Recorded rather than fixed, and worth noting for whoever fixes
	 * it: test/unistd.c:723 currently *pins* the present behaviour
	 * (`CHECK(gethostname(buf, 1) == -1 && errno == ENAMETOOLONG)`),
	 * so that assertion has to change in the same commit.  Several
	 * other libcs return -1/ENAMETOOLONG here too; that is a
	 * historical divergence, not a licence in this page.  Probed on
	 * this tree: gethostname(buf, 4) returns -1 with errno 36
	 * (ENAMETOOLONG) and the four truncated bytes present in buf.
	 * Re-enable when a short namelen is a successful truncation. */
	if (n >= sizeof small) {
		memset(small, '@', sizeof small);
		errno = 0;
		CHECK(gethostname(small, 4) == 0);
		CHECK(errno == 0);
		CHECK(!memcmp(small, buf, 4));
	}
#endif

	/* N/A, with the mechanism: there is no clause left on this page to
	 * reach.  It defines no errors at all, and the host name itself
	 * comes from %COMPUTERNAME% (src/unistd/gethostname.c), which is
	 * NT's own answer to the same question -- there is no second
	 * source to cross-check it against on this platform. */
}

int main(int argc, char **argv)
{
	char tmpl[] = "posixunistdids-XXXXXX";
	char *dir;
	char origcwd[4096];
	static char self[4096];

	/* The --child role.  test_process_group_and_session() spawns this
	 * program to get a real child process of its own (see there); the
	 * child has nothing to check and exits 0.  Handled before the
	 * fixture directory below so a child never creates or removes
	 * one. */
	if (argc > 1 && !strcmp(argv[1], "--child")) return 0;

	CHECK(getcwd(origcwd, sizeof origcwd) == origcwd);

	/* __spawn() resolves a relative path against the *current*
	 * directory and the tests below run from the fixture directory, so
	 * argv[0] is made absolute here, while the original cwd still
	 * applies.  tools/runtests.sh already invokes the exe by absolute
	 * path; the join is for a run by hand. */
	if (argv[0][0] == '/' || argv[0][0] == '\\' ||
	    (argv[0][0] && argv[0][1] == ':'))
		snprintf(self, sizeof self, "%s", argv[0]);
	else
		snprintf(self, sizeof self, "%s/%s", origcwd, argv[0]);

	dir = mkdtemp(tmpl);
	CHECK(dir == tmpl);
	if (!dir) return 1;
	CHECK(chdir(dir) == 0);

	test_getid_always_successful();
	test_getgroups();
	test_setid_family();
#if defined(__linux__) && !defined(_SPICULE_NATIVE_BUILD)
	test_res_ids();
	test_euidaccess();
#endif
	test_process_group_and_session(self);
	test_chown_family();
	test_alarm();
	test_nice();
	test_gethostname();

	CHECK(chdir(origcwd) == 0);
	CHECK(rmdir(dir) == 0);

	if (fails) { printf("posix-unistd-ids: failures: %d\n", fails); return 1; }
	if (unverified) {
		/* Everything that ran passed, but that is not the same claim
		 * as "all tests passed" -- see the SKIP line(s) above for
		 * which assertion groups never ran.  Exit 77 so
		 * tools/run-tests.py reports this in its own bucket instead
		 * of counting it as a pass.  Same convention as
		 * test/posix-tail.c and test/posix-socket.c.
		 *
		 * `unverified` only ever comes from test_alarm()'s SIGALRM-
		 * delivery retry loop above, which is unconditional and unrelated
		 * to this file's one SPICULE_TEST-fenced case.  A
		 * tools/test-policy.py probe recompiles this whole file to
		 * validate that case in isolation, and test_alarm() still runs
		 * alongside it; without this guard, a dropped SIGALRM here (see
		 * test_alarm()'s comment) would report the fenced case's probe
		 * UNRESOLVED too, regardless of that case's own result. */
		printf("posix-unistd-ids: %d assertion group(s) unverified in "
		       "this environment (see SKIP lines above); no failures in "
		       "what did run\n", unverified);
		if (!SPICULE_TEST_POLICY_PROBE) return 77;
	}
	printf("posix-unistd-ids: all tests passed\n");
	return 0;
}
