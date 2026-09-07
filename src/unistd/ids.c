/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)

/* NT has one immutable process identity: the user SID in its primary
 * access token (S-1-5-21-X-Y-Z-RID). A RID alone is not a uid -- a local
 * SAM account and an AD account can share one -- so uid mapping follows
 * Cygwin's scheme: local domain = 0x30000+RID, machine's primary domain =
 * 0x100000+RID, other/trusted domain = 0xfe500000+RID. Which domain a SID
 * belongs to is decided via LSA (NTLIBC_USE_KERNEL32 build) or by
 * comparing USERDOMAIN/COMPUTERNAME (ntdll-only build, no LSA access).
 * Well-known SIDs use Cygwin's fixed mappings; a token query failure
 * falls back to uid 1000, since getuid() has no POSIX error return.
 *
 * Process groups/sessions used to be a hardcoded 1 from every one of
 * getpgrp/getpgid/setpgrp/setsid/getsid. That fiction couldn't model
 * setsid.html's EPERM-on-second-call state machine or setpgrp.html's
 * "no errors defined" contract, so this process's two ids now live in
 * statics. NT has no process-group/session object to hang them on (a
 * console process group is the nearest thing and can't be joined; see
 * posix_spawn.c's banner), so this is per-process bookkeeping: a process
 * that becomes its own group leader also publishes a named event keyed
 * by its pid, letting getpgid(child)/killpg(child_pgid) observe the
 * transition cross-process.
 *
 * The initial value 1 does double duty: POSIX starts a process as a
 * non-leader (so its first setsid() succeeds), and leadership is tested
 * as `pgid == getpid()` rather than a flag -- 1 works because NT pids are
 * multiples of four, so no real process can ever compare equal to it.
 * getpgid() returns the inherited 1 for another live process unless its
 * named event says it has since become a group leader.
 *
 * fork() inherits these statics for free with the rest of the address
 * space, matching fork.html's inheritance rule. __spawn() cannot: its
 * child is a fresh image with fresh statics, so it starts in the
 * born-into group rather than the caller's -- a known divergence from
 * exec.html that would require widening crt1's RuntimeData block to
 * close. */
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "libc.h"
#include "plat_unistd.h"
#include "ownership_stubs.h"

static uid_t cached_uid = (uid_t)-1;
static gid_t cached_gid = (gid_t)-1;

uid_t getuid(void)
{
	/* The primary token is immutable, so caching is safe and also keeps
	 * the ntdll-only environment fallback stable if callers change env. */
	uid_t uid = cached_uid;
	if (uid == (uid_t)-1) cached_uid = uid = __plat_detect_uid();
	return uid;
}
uid_t geteuid(void) { return getuid(); }
/* __plat_detect_gid() is a constant 1000 on NT (no POSIX group identity
 * distinct from the fixed uid model) and a real getgid(2) on Linux;
 * cached the same way and for the same reason as getuid() above. */
gid_t getgid(void)
{
	gid_t gid = cached_gid;
	if (gid == (gid_t)-1) cached_gid = gid = __plat_detect_gid();
	return gid;
}
gid_t getegid(void) { return getgid(); }

/* setresuid()/setresgid() (Linux only) call this to invalidate the cache
 * above after moving the real uid/gid, so getuid()/getgid() stay honest.
 * Unused on NT: nothing there ever changes the token this process runs
 * under. */
void __ids_creds_cache_invalidate(void)
{
	cached_uid = (uid_t)-1;
	cached_gid = (gid_t)-1;
}

/* setuid()/setgid() and kin must EINVAL an unsupported id and EPERM one
 * that isn't ours (setuid.html ERRORS) -- a stub returning 0
 * unconditionally would make privilege-dropping idioms like
 * `if (setuid(pw->pw_uid) != 0) abort();` believe a drop happened when it
 * didn't. sysconf(_SC_SAVED_IDS) is -1, so there's no saved set-user-ID
 * to match either, and EPERM holds for every id but the current one.
 * (uid_t)-1 is setreuid()'s "leave unchanged" marker, not an assumable
 * uid; every other value is supported since Cygwin's trusted-domain
 * offsets legitimately occupy the upper half of the 32-bit space. */
static int id_supported(uid_t id)
{
	return id != (uid_t)-1;
}

static int set_one_id(uid_t id, uid_t self)
{
	if (!id_supported(id)) { errno = EINVAL; return -1; }
	if (id != self) { errno = EPERM; return -1; }
	return 0;
}

/* setreuid.html: -1 for ruid or euid leaves it unchanged, so (uid_t)-1
 * is accepted here even though it's otherwise "unsupported". */
static int set_two_ids(uid_t r, uid_t e, uid_t self)
{
	if (r != (uid_t)-1 && set_one_id(r, self) < 0) return -1;
	if (e != (uid_t)-1 && set_one_id(e, self) < 0) return -1;
	return 0;
}

int setuid(uid_t u) { return set_one_id(u, getuid()); }
int seteuid(uid_t u) { return set_one_id(u, geteuid()); }
int setgid(gid_t g) { return set_one_id((uid_t)g, (uid_t)getgid()); }
int setegid(gid_t g) { return set_one_id((uid_t)g, (uid_t)getegid()); }
int setreuid(uid_t r, uid_t e) { return set_two_ids(r, e, getuid()); }
int setregid(gid_t r, gid_t e) { return set_two_ids((uid_t)r, (uid_t)e, (uid_t)getgid()); }
/* The supplementary group list here is one entry long (the effective
 * gid) -- getgroups.html leaves that implementation-defined, and with
 * one identity there's nothing else to put in it. gidsetsize 0 asks for
 * the count alone without touching grouplist; any other value less than
 * 1 is a shall-fail EINVAL. */
int getgroups(int n, gid_t *g withtok(writable_elements(n)))
{
	const int held = 1;
	if (n != 0 && n < held) { errno = EINVAL; return -1; }
	/* n != 0 is a POSIX caller obligation that g itself is a real,
	 * non-NULL array (gidsetsize 0 is the only NULL-g case); the
	 * writable_elements(n) token above proves the extent once g is
	 * known live, but not liveness itself. */
	if (n != 0) { __ownership_pointer_nonnull(g); g[0] = getegid(); }
	return held;
}
/* The group and session this process is in; see the banner for why they
 * start at 1 and how group-leader transitions are published. */
static pid_t pgid = 1;
static pid_t sid = 1;

static void publish_own_process_group(void) { __plat_pgrp_publish_self(getpid()); }
static int is_process_group_leader(pid_t pid) { return __plat_pgrp_is_leader(pid); }

pid_t getpgrp(void) { return pgid; }

/* getpgid.html/getsid.html: ESRCH if pid names no process. Decided the
 * way kill()/getpriority() already do: pid 0 or our own pid is the
 * caller (answered without an NT call); a pid in the child table
 * (src/process/children.c) is an exited-but-unreaped child, which is
 * still a process by POSIX's reckoning even though NT disagrees on
 * whether its process object can still be opened (see wait.c's
 * reopen-by-pid discussion); anything else goes to the object manager by
 * CLIENT_ID, where only a refusal (not STATUS_ACCESS_DENIED, which means
 * "exists but not ours") means no such process. A negative pid is
 * rejected without an NT call, since sign-extending it into the unsigned
 * CLIENT_ID would ask about the wrong pid. */
static int pid_exists(pid_t p)
{
	if (p == 0 || p == getpid()) return 1;
	if (p < 0) return 0;
	if (__child_find((int)p)) return 1;
	return __plat_process_exists(p);
}

pid_t getpgid(pid_t p)
{
	if (!pid_exists(p)) { errno = ESRCH; return -1; }
	if (p != 0 && p != getpid() && is_process_group_leader(p)) return p;
	return pgid;
}
/* setpgid.html's ESRCH is narrower than pid_exists() above: "does not
 * match the process ID of the calling process or of a child process",
 * not "no such process anywhere" -- an unrelated process's pid must be
 * refused here but answered by getpgid(), so pid_exists() would be wrong
 * to reuse. The narrowing is also what avoids an NT call: "is this my
 * child" is answerable entirely from the child table
 * (src/process/children.c), whose lifetime already matches POSIX's
 * "child process of the calling process" (present from fork()/__spawn()
 * until wait() reaps it). pid 0 is checked first both because it means
 * "the caller" and because __child_find(0) would otherwise match a free
 * slot. Once pid resolves, [EINVAL] is pgid's own range check; the
 * pgid/sid state here only models this process's own setpgrp()/setsid()
 * transitions, so a valid non-negative request is a no-op. */
static int pid_is_self_or_child(pid_t p)
{
	if (p == 0 || p == getpid()) return 1;
	if (p < 0) return 0;
	return __child_find((int)p) != 0;
}

int setpgid(pid_t pid, pid_t group) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	if (!pid_is_self_or_child(pid)) { errno = ESRCH; return -1; }
	if (group < 0) { errno = EINVAL; return -1; }
	return 0;
}
/* setpgrp.html: sets pgid to pid if not already a session leader; "no
 * errors are defined". Only the process-group half is done -- the page's
 * System V reading (also creating a session) is skipped, since that would
 * make setpgrp() a setsid() that can't fail, for an effect the
 * DESCRIPTION doesn't require. */
pid_t setpgrp(void)
{
	pid_t self = getpid();
	if (sid != self) {
		pgid = self;
		publish_own_process_group();
	}
	return pgid;
}

/* setsid.html: creates a new session/group (pgid = sid = pid) unless the
 * caller is already a process group leader (EPERM); "already a leader" is
 * pgid == pid, so a second call fails. "No controlling terminal" isn't
 * modelled -- the console is the only terminal here and nothing
 * distinguishes a controlling one, so there's no state to drop. */
pid_t setsid(void)
{
	pid_t self = getpid();
	if (pgid == self) { errno = EPERM; return -1; }
	sid = pgid = self;
	publish_own_process_group();
	return pgid;
}

pid_t getsid(pid_t p)
{
	if (!pid_exists(p)) { errno = ESRCH; return -1; }
	return sid;
}
/* Whether chown actually sets anything is a per-backend question: NT has
 * no POSIX owner/group (st_uid/st_gid just report this process's own
 * IDs, see the banner), so __plat_chown()/__plat_fchown()'s NT side
 * stays a probe -- ignoring uid/gid but still resolving the path/handle
 * far enough to produce chown.html's shall-fail ENOENT/ENOTDIR/EBADF.
 * Linux's side does a real chown(2)/fchown(2), (uid_t)-1/(gid_t)-1
 * "leave unchanged" included. Both give the front doors below the same
 * "checked out" vs "set now" result, which chown.html never asks this
 * level to distinguish.
 *
 * fchownat()'s EINVAL for an unrecognised flag is a may-fail here (unlike
 * unlinkat()'s); the bits are accepted, and only AT_SYMLINK_NOFOLLOW is
 * read out of them. */
int fchownat(int d, const char *p, uid_t u, gid_t g, int f) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	return __plat_chown(d, p, u, g, f);
}
int chown(const char *p, uid_t u, gid_t g) { return fchownat(AT_FDCWD, p, u, g, 0); }
int lchown(const char *p, uid_t u, gid_t g) { return fchownat(AT_FDCWD, p, u, g, AT_SYMLINK_NOFOLLOW); }
int fchown(int f, uid_t u, gid_t g) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __fd *fd = __fd_get(f);
	if (!fd) return -1;
	return __plat_fchown(fd->h, u, g);
}
int chroot(const char *p) { (void)p; errno = EPERM; return -1; }
int issetugid(void) { return 0; }
char *getlogin(void)
{
	extern char *getenv(const char *);
	char *u = getenv("USERNAME");
	return u ? u : getenv("USER");
}
int getlogin_r(char *buf, size_t n)
{
	char *l = getlogin();
	size_t i;
	if (!l) return ENXIO;
	for (i = 0; l[i] && i + 1 < n; i++) buf[i] = l[i];
	if (l[i]) return ERANGE;
	buf[i] = 0;
	return 0;
}

// NOLINTEND(misc-include-cleaner)
