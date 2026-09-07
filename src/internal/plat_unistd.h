/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform interface for the rest of src/unistd/ -- everything in
 * that directory's POSIX-facing front doors that is not already covered
 * by src/internal/plat_fd.h (close/read/write/lseek/dup).  See
 * src/unistd/nt/plat_unistd.c for the implementation these declare.
 *
 * Same contract as plat_fd.h/plat_mem.h: every function here takes
 * POSIX-shaped arguments and returns a POSIX-shaped result -- errno
 * already set on failure, never a raw NTSTATUS/HANDLE/PVOID for the
 * front door to interpret.  Every NT-specific interpretation step (which
 * status means what, how a reparse point or a token SID is laid out, how
 * an alertable APC is armed) lives entirely inside the backend function's
 * body.  Front-door bookkeeping that is this library's own POSIX-
 * satisfying strategy -- src/unistd/ids.c's pgid/sid statics,
 * src/unistd/sleep.c's alarm_due/alarm_seq generation counter -- is NOT
 * part of this interface and stays in the front door, unchanged.
 */
#ifndef _SPICULE_PLAT_UNISTD_H
#define _SPICULE_PLAT_UNISTD_H

#include <stddef.h>
#include <sys/types.h>
#include "plat_handle.h"

/* ---- src/unistd/sleep.c ------------------------------------------------ */

/* The current time on the same clock alarm() deadlines and
 * __alertable_delay()'s elapsed-time accounting are kept on -- realtime
 * seconds, 100ns ticks since the platform epoch.  Never fails. */
long long __plat_time_now(void);

/* Delivered when the process-wide alarm timer __plat_alarm_arm() armed
 * expires, on the thread that armed it, only while that thread is in an
 * alertable wait -- see sleep.c's banner for exactly what that does and
 * does not reach.  `seq` is whatever __plat_alarm_arm() was called with;
 * the front door uses it to tell a punctual expiry from one already
 * superseded by a later alarm()/alarm(0) (see sleep.c's alarm_apc
 * comment for why that identity check, not the clock, is the only
 * correct test). */
typedef void (*__plat_alarm_fn)(unsigned long seq);

/* Arm the process-wide alarm timer -- created lazily on first use and
 * kept for the life of the process, non-inheritable so fork()'s child
 * can simply forget it (see __plat_alarm_reset_after_fork) -- to call
 * `deliver(seq)` at absolute time `due`.  0 on success, -1 if the timer
 * could not be created or armed (alarm() has nowhere to report that;
 * see its own comment on why the caller treats this the same as "no
 * alarm could be honoured"). */
int __plat_alarm_arm(long long due, unsigned long seq, __plat_alarm_fn deliver);

/* Withdraw a pending request armed by __plat_alarm_arm(), if any.  Never
 * fails: alarm.html gives alarm() no error to report one with, and a
 * timer that was never created has nothing to withdraw. */
void __plat_alarm_cancel(void);

/* fork()'s child side: forget the timer handle without closing it (it
 * was created non-inheritable, so the value was never duplicated into
 * the child and may already name something else there -- see sleep.c's
 * __alarm_reset_after_fork). */
void __plat_alarm_reset_after_fork(void);

/* ---- src/unistd/getpid.c ------------------------------------------------ */

/* getppid(): the process ID this process was created from, or 1 (init's
 * conventional pid) if that cannot be determined -- getppid.html reserves
 * no error return, so a query that fails still has to answer with some
 * pid. */
pid_t __plat_getppid(void);

/* getpid()/gettid(): this process's own pid, and the calling thread's
 * own tid. Both used to read NT's TEB directly in src/unistd/getpid.c's
 * own front door, never behind any plat_* interface at all -- a real
 * gap other Linux-backend work in this tree already documented and
 * left for later (see src/unistd/linux/plat_unistd.c's own banner
 * history). Neither call has a documented failure mode on any backend
 * (getpid.html/gettid(2) both reserve no error return), so neither
 * function here does either. */
pid_t __plat_getpid(void);
pid_t __plat_gettid(void);

/* ---- src/unistd/ftruncate.c --------------------------------------------- */

/* ftruncate(): set the object `h` refers to to exactly `len` bytes,
 * already validated (len >= 0, fildes open for writing, within
 * RLIMIT_FSIZE) by the front door. */
int __plat_ftruncate(__plat_handle_t h, off_t len);

/* ---- src/unistd/fsync.c -------------------------------------------------- */

/* fsync()/fdatasync(): force `h`'s buffered writes out. */
int __plat_fsync(__plat_handle_t h);

/* ---- src/unistd/pipe.c --------------------------------------------------- */

/* pipe()/pipe2(): create the two ends of a fresh anonymous pipe.
 * `inheritable` requests that both handles be inheritable by a child
 * process (i.e. O_CLOEXEC was not requested). */
/* rp/wp required: both real implementations (linux/plat_unistd.c,
 * nt/plat_unistd.c) write `*rp = ...`/`*wp = ...` unconditionally on
 * the success path, with no NULL check of either anywhere. pipe.c's one
 * real call site always passes `&r, &w`, the addresses of its own
 * locals, never NULL. */
int __plat_pipe(__plat_handle_t *rp, __plat_handle_t *wp, int inheritable)
    __attribute__((nonnull(1, 2)));

/* ---- src/unistd/sysconf.c ------------------------------------------------ */

/* _SC_NPROCESSORS_CONF/_SC_NPROCESSORS_ONLN: 1 if the real count cannot
 * be determined -- sysconf() has no error return for a name it does
 * support, so a query that fails still has to answer with a plausible
 * value. */
long __plat_nprocessors(void);

/* _SC_PHYS_PAGES, already expressed in 4096-byte pages regardless of the
 * platform's native page size: -1 if the real count cannot be
 * determined, sysconf()'s "no limit" answer. */
long __plat_phys_pages(void);

/* ---- src/unistd/unlink.c -------------------------------------------------- */

/* unlink()/rmdir()/unlinkat(): remove the directory entry `path` (already
 * validated not to be "."/".." when `isdir`) names, relative to `dirfd`
 * (AT_FDCWD for the current directory). */
int __plat_unlink(int dirfd, const char *path, int isdir);

/* ---- src/unistd/gethostname.c ------------------------------------------- */

/* Fill `buf` (NUL-terminated, up to bufsz bytes; does nothing if bufsz
 * is 0) with this system's own hostname, the way this backend actually
 * knows it: NT has no kernel concept of one at all, so its own answer is
 * the calling process's own COMPUTERNAME environment variable (or
 * "localhost" if unset/unusable) -- the only oracle a plain ntdll-only
 * build has for this; Linux's own uname(2) syscall answers this
 * directly and correctly, kernel-side, with no environment indirection
 * needed at all (the same call src/misc/linux/plat_misc.c's
 * __plat_uname() already makes for the identical field -- see that
 * function's own comment for the raw struct new_utsname layout this one
 * duplicates locally, matching every other Linux backend's own
 * per-file syscall-number copies in this tree). Never fails --
 * gethostname.html's own contract has no error for "the name is
 * unknown", only for a `name` argument the front door (src/unistd/
 * gethostname.c) already validates before calling here. */
void __plat_hostname(char *buf, size_t bufsz);

/* ---- src/unistd/getcwd.c ---------------------------------------------------- */

/* getcwd(): fill `buf` (a caller-owned buffer of at least `bufsz` bytes)
 * with the process's current working directory, already in this
 * library's POSIX-facing form -- UTF-8, forward slashes, NUL-terminated,
 * no trailing slash except at a root -- so the front door (src/unistd/
 * getcwd.c) never has to know how a backend actually names its own
 * current directory. Returns the length written, NOT counting the NUL
 * (matching strlen() of the result, and the length the front door's own
 * malloc-when-buf-is-NULL/ERANGE math is written against), or -1 with
 * errno set (ERANGE if `bufsz` was too small to hold the result plus its
 * NUL, same as getcwd(3)'s own [ERANGE]) on failure. The front door
 * handles the __VFS_ROOT/__VFS_DEV overlay cases itself (portable
 * bookkeeping, see chdir.c's own comment on why that stays there) and
 * only calls this for a real, native directory. */
ssize_t __plat_getcwd(char *buf, size_t bufsz);

/* ---- src/unistd/chdir.c ---------------------------------------------------- */

/* chdir(): set the process's current directory to `path` (UTF-8, POSIX
 * form; only NUL/empty-string rejection happens in the front door).
 * Resolving `path` through the fixed POSIX namespace (src/internal/
 * vfs.c's __vfs_resolve_at()) -- rejecting anything that is not the
 * overlay root/dev directory or a native object, and substituting the
 * native drive-root spelling for a non-native virtual directory -- is
 * this backend's own job, exactly like __plat_open()'s VFS-overlay
 * dance (src/internal/plat_fcntl.h). __vfs_resolve_at()/__vfs_open_dir()
 * themselves are shared, portable-shaped helpers (see their own
 * comments in libc.h) that ANY backend with no native concept of
 * `/dev/null` etc -- NT today, a future UEFI backend most likely --
 * calls the exact same way; only a backend that (like Linux) already
 * has real native devices has no use for them at all.
 *
 * The whole-pathname-component length check (__name_too_long(),
 * src/internal/path.c) also belongs here rather than the front door:
 * it exists only because this call does not otherwise route through
 * that file's usual path-building step (see the NT backend's own
 * __plat_chdir() comment) -- a backend whose native chdir(2) already
 * enforces {NAME_MAX} itself (Linux) needs no equivalent check at all.
 *
 * On success, *vfsout reports what __vfs_resolve_at() decided (so the
 * front door can hand it to __vfs_cwd_set(), portable process-wide
 * bookkeeping that stays in the front door -- see chdir.c) -- __VFS_NONE
 * for a backend with no overlay concept, always. */
/* vfsout required: both real implementations write `*vfsout = ...`
 * unconditionally on the success path, with no NULL check of vfsout
 * itself anywhere. chdir.c's one real call site always passes `&vfs`,
 * the address of its own local, never NULL. path is NOT marked here:
 * neither backend dereferences it directly in this function's own body
 * (linux forwards it straight into a syscall; NT forwards it into
 * __name_too_long()/__utf8_to_utf16(), which already carry their own
 * contracts), so there is nothing at this level for the attribute to
 * describe. */
int __plat_chdir(const char *path, int *vfsout) __attribute__((nonnull(2)));

/* ---- src/unistd/link.c ------------------------------------------------------ */

/* linkat(): create a new directory entry `newpath` (relative to
 * `newdirfd`) for the file `oldpath` (relative to `olddirfd`) already
 * names.  `followsym` is AT_SYMLINK_FOLLOW: link the symlink's target
 * rather than the symlink itself. */
int __plat_link(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int followsym);

/* readlinkat(): read the target of the symbolic link `path` (relative to
 * `dirfd`) into `buf`/`bufsz`, POSIX truncate-silently semantics.
 * Returns the number of bytes placed, or -1(errno).  Ruling out a
 * virtual-fs path (EINVAL: it is one of the fixed POSIX namespace's own
 * entries, never a symlink; ENOENT: it is inside that namespace but
 * absent) is this backend's own job now, exactly like __plat_chdir()'s
 * -- via the same shared __vfs_resolve_at() (src/internal/vfs.c) a
 * future UEFI backend would call too. A backend with no such namespace
 * at all (Linux, which already has real symlinks and a real ENOENT/
 * EINVAL from its own readlinkat(2)) has nothing to rule out and skips
 * this step entirely. Every reparse-point interpretation step (NTFS
 * symlink, junction, WSL symlink) lives here too, unchanged. */
ssize_t __plat_readlink(int dirfd, const char *path, char *buf, size_t bufsz);

/* symlinkat(): create a new symbolic link `linkpath` (relative to
 * `newdirfd`) whose contents are `target`, verbatim (not resolved).
 *
 * target required: the NT backend's own __plat_symlink() reads
 * `target[0]` unconditionally as its very first statement (deciding
 * `relative`), with no NULL check anywhere in its body; every real call
 * site (src/unistd/link.c's symlinkat()) forwards its own target
 * straight through with no check of its own either -- symlink()'s
 * target has no POSIX NULL-tolerance clause, and no real caller in this
 * tree (test/posix-unistd.c, test/posix-statvfs.c, test/posix-tail.c)
 * ever passes anything but a real string literal. */
int __plat_symlink(const char *target, int newdirfd, const char *linkpath)
    __attribute__((nonnull(1)));

/* ---- src/unistd/ids.c ------------------------------------------------------- */

/* getuid(): this process's uid, derived from its primary token's user
 * SID (see ids.c's banner for the whole Cygwin-compatible mapping this
 * implements).  Never fails -- a token that cannot be opened or queried
 * still has to produce some uid, and getuid.html reserves no error
 * return. */
uid_t __plat_detect_uid(void);

/* getgid(): this process's gid.  Same never-fails contract as
 * __plat_detect_uid() above (getgid.html reserves no error return
 * either).  Added alongside the res*id() family (src/unistd/linux/
 * plat_ids.c) so getgid()/getegid() answer a real, live value on a
 * backend that actually has one, exactly the asymmetry
 * __plat_detect_uid() already draws between NT (one fixed identity) and
 * Linux (a real per-process id) -- see ids.c's own getgid()/getegid()
 * for how the two compose. */
gid_t __plat_detect_gid(void);

/* Publish `self` (this process's own, already-known pid) as its own
 * process-group leader: a named, idempotent, cross-process boolean keyed
 * by pid, since NT has no real process-group object to set one on (see
 * ids.c's banner).  Safe to call repeatedly for the same pid; best-effort
 * and silent on failure the same way setpgrp.html's "no errors are
 * defined" already requires of its caller. */
void __plat_pgrp_publish_self(pid_t self);

/* Has `pid` published itself as a process-group leader via
 * __plat_pgrp_publish_self()? */
int __plat_pgrp_is_leader(pid_t pid);

/* Does a process with this pid exist, as far as this process can tell
 * (STATUS_ACCESS_DENIED counts as existing -- the process is there and
 * merely not ours to open)?  Callers handle pid 0/self/known-child
 * themselves first; this is only the "ask the object manager" fallback
 * for everything else. */
int __plat_process_exists(pid_t pid);

/* chown()/lchown()/fchownat(): change `path`'s (relative to `dirfd`,
 * honoring AT_SYMLINK_NOFOLLOW in `flags`) owner/group to `uid`/`gid`
 * ((uid_t)-1/(gid_t)-1 meaning "leave this one alone", exactly chown.html's
 * own sentinel), resolving `path` regardless of whether this backend has
 * anything to change.  NT has no POSIX owner or group at all (see
 * src/unistd/ids.c's banner), so its own implementation ignores
 * uid/gid entirely and is left with exactly the job its former name
 * (__plat_chown_probe) described: resolve `path` and report whether it
 * exists, which is all of chown.html's shall-fail clauses ever asked of
 * a backend with nothing to set.  Linux has real ownership and a real
 * fchownat(2) to set it with, so its own implementation does the whole
 * job for real. */
int __plat_chown(int dirfd, const char *path, uid_t uid, gid_t gid, int flags);

/* fchown(): the fd-taking sibling of __plat_chown() just above, same
 * uid/gid/-1 contract, against an already-resolved handle rather than a
 * path -- exactly the split __plat_chmod()/__plat_chmodat()
 * (src/internal/plat_stat.h) already draw for chmod(). */
int __plat_fchown(__plat_handle_t h, uid_t uid, gid_t gid);

/* ---- src/unistd/getentropy.c ------------------------------------------ */

/* Fill buf[0..buflen) with cryptographically strong random bytes,
 * blocking (once, at most, at process startup on a not-yet-seeded
 * kernel CSPRNG) rather than ever returning fewer bytes than asked for.
 * 0 on success, -1/errno on failure. buflen is never more than 256 here
 * -- src/unistd/getentropy.c's front door enforces getentropy(3)'s own
 * [EIO] limit before calling this. On NT, only compiled in under
 * SPICULE_USE_KERNEL32 (see src/unistd/nt/plat_unistd.c and
 * src/internal/kernel32.h's banner); with no real entropy source
 * reachable from pure ntdll at all, getentropy() itself (this
 * function's front door) reports ENOSYS without it. */
int __plat_getentropy(void *buf, size_t buflen);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
