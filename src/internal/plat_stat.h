/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform interface src/stat/{chmod,lxmod,mkdir,stat,statvfs,
 * utimensat}.c's POSIX-facing front doors call into instead of a raw
 * NtCreateFile/NtOpenFile/NtQueryInformationFile/NtSetInformationFile/
 * NtQueryVolumeInformationFile/NtQueryEaFile/NtSetEaFile/NtQueryObject
 * call.  See src/stat/nt/plat_stat.c for the implementations these
 * declare.
 *
 * Every function here takes POSIX-shaped arguments and returns a
 * POSIX-shaped result -- errno already set on failure, never a raw
 * platform status for the front door to interpret.
 *
 * __plat_chmodat()/__plat_mkdir()/__plat_fstatat()/__plat_statvfs_path()/
 * __plat_set_times_at() all take a raw, UNRESOLVED (dirfd, path) pair
 * now, rather than a `struct __ntpath *` the front door built via
 * __ntpath_at()/__ntpath() itself -- exactly the same relocation
 * src/internal/plat_fcntl.h's __plat_open() already got (see that
 * header's own banner and src/fcntl/open.c's commit ce4763c for the
 * worked example this mirrors). Each backend resolves the raw path
 * however it needs to: the NT backend still calls __ntpath_at()/
 * __ntpath()/__vfs_resolve_at() internally, exactly as before, just
 * moved from the front door into the backend's own function body.
 *
 * __vfs_resolve_at()/__vfs_open_dir() (src/internal/vfs.c) themselves
 * are NOT NT-only and are NOT moved, shortened, or otherwise edited by
 * this relocation: they synthesize the fixed POSIX namespace overlay
 * (/, /dev, /dev/null etc) that any platform with no native concept of
 * those paths needs -- true of a hypothetical future UEFI backend just
 * as much as it is of NT today. Only the ONE genuinely NT-specific
 * piece inside __vfs_resolve_at() (its `can_probe` branch's call to
 * __ntpath_native()/NtQueryAttributesFile, arbitrating whether a real
 * native filesystem object masks the synthetic overlay entry) actually
 * needs NT; the function as a whole stays exactly where it is, declared
 * in src/internal/libc.h alongside every other cross-module helper, and
 * only the CALL SITE moves -- from the front door directly into the NT
 * backend's own function body, the same "portable helper stays shared,
 * only the platform-specific interpretation step that calls it moves
 * into that backend's own file" pattern this whole migration already
 * uses (e.g. mman.c's reservation table staying in the front door while
 * prot_to_page() stays NT-backend-private).
 *
 * A Linux backend needs no resolution step and no overlay at all: real
 * POSIX syscalls already take (dirfd, path) directly, and Linux already
 * has real, native `/dev/null` etc, so its five implementations below
 * call the underlying syscall (fchmodat(2)/mkdirat(2)/statx(2)/
 * statfs(2)/utimensat(2)) close to directly and never call
 * __vfs_resolve_at() at all -- see src/stat/linux/plat_stat.c's own
 * banner.
 *
 * $LXMOD (WSL's NTFS extended attribute persisting a POSIX mode) is
 * this library's own choice of how to remember a mode NT has no native
 * concept of.  __lxmod_create_buffer() (src/stat/lxmod.c) is a portable
 * helper (declared in src/internal/libc.h, shared verbatim by every
 * caller including src/fcntl/nt/plat_fcntl.c's __plat_open()) that the
 * NT backend's own __plat_mkdir() below calls internally when it builds
 * the EA buffer -- exactly where __plat_open() builds its own, and for
 * the same reason: only NT has a $LXMOD EA to write at all. Only the
 * two functions that actually read/write the EA over the wire
 * (NtQueryEaFile/NtSetEaFile) are platform calls and are declared
 * below.
 */
#ifndef _SPICULE_PLAT_STAT_H
#define _SPICULE_PLAT_STAT_H

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include "plat_handle.h"

/* WSL/ntfs3's $LXMOD extended attribute: 1 found (*mode filled), 0
 * absent/invalid (nothing this library can use; not an error). */
int __plat_lxmod_get(__plat_handle_t h, unsigned *mode);
/* Write $LXMOD. 0/-1(errno). */
int __plat_lxmod_set(__plat_handle_t h, unsigned mode);

/* chmod() on an already-open handle: sets FILE_ATTRIBUTE_READONLY to
 * match the aggregate write bits and writes $LXMOD -- see chmod.c's own
 * banner. 0/-1(errno). */
int __plat_chmod(__plat_handle_t h, mode_t mode);
/* fchmodat(): resolves `path` (relative to `dirfd`, spicule's own
 * AT_FDCWD sentinel or an already-open dirfd) to a handle (with the
 * FILE_WRITE_ATTRIBUTES-denied-on-a-read-only-file Wine fallback
 * chmod.c's own comment documents on the NT side), calls
 * __plat_chmod(), and closes it.  `flags` is whatever the front door
 * already validated (AT_SYMLINK_NOFOLLOW or 0 -- see chmod.c's own
 * EINVAL check, which stays in the front door since it needs no path
 * resolution and is not platform-specific). 0/-1(errno). */
int __plat_chmodat(int dirfd, const char *path, int flags, mode_t mode);

/* Pushes `m` (already masked to the low 9 bits by chmod.c's umask())
 * out to the REAL, OS-level file-creation mask, on a platform that has
 * one of its own.  Linux does: a real kernel-level umask(2) syscall
 * exists, and every raw openat(2)/mkdirat(2)/mknodat(2) call this
 * backend's own Linux implementation makes already honors it directly
 * (see src/stat/linux/plat_stat.c's own banner on why those calls pass
 * `mode` UNMASKED and rely on exactly this) -- so calling this here is
 * what makes a caller's umask() actually change a freshly created
 * file's mode on Linux, without this library masking `mode` a second
 * time in userspace on top of what the kernel already does.  NT has no
 * OS-level umask concept of its own: masking already happens once, in
 * userspace, at each front door that needs it, via __umask_get()
 * (src/fcntl/nt/plat_fcntl.c's __plat_open(), this header's own
 * __plat_mkdir() below) -- so NT's implementation is a documented
 * no-op, not a stub waiting to be filled in. */
void __plat_umask_apply(mode_t m);

/* mkdirat(): creates the directory named by `path` (relative to
 * `dirfd`) with mode `mode` -- the RAW, not-yet-umask-applied POSIX
 * mode.  Unlike __plat_open() (which receives an already-umask-applied
 * mode because its front door still builds that value itself), this
 * backend applies umask and builds the $LXMOD EA internally, mirroring
 * exactly where __plat_open() does the identical work on the NT side.
 * Maps NT's name-collision status to EEXIST -- see mkdir.c's own banner
 * on why that status, rather than a type-mismatch one, is what NT
 * actually reports here. 0/-1(errno). */
int __plat_mkdir(int dirfd, const char *path, mode_t mode);

/* mkfifoat()/mknod()/mknodat() (src/stat/chmod.c): create a new
 * filesystem node `path` (relative to `dirfd`) whose type is `mode`'s
 * S_IF* bits and whose permission bits are its low 12 -- mkfifoat()'s
 * own front door ORs in S_IFIFO itself before calling here, so this one
 * function serves both POSIX calls exactly the way Linux's own
 * mknodat(2) serves both (a FIFO is simply mknod() with S_IFIFO and no
 * device).  `dev` is meaningful only for S_IFCHR/S_IFBLK and is passed
 * straight through in whatever encoding the caller built it in: this
 * library exposes no makedev()/major()/minor() of its own (a real gap,
 * not silently worked around here) to construct or decode one in any
 * other form, so a device node with a real major/minor is not
 * constructible through this library today regardless of what this
 * function does with the bits it is handed -- only S_IFIFO (dev always
 * 0) and the unprivileged-EPERM path for S_IFCHR/S_IFBLK are anything
 * this project's own tests exercise.
 *
 * NT has no filesystem node type any of this maps onto (see chmod.c's
 * own comment on mkfifo()/mknod() there), so its own implementation
 * stays the unconditional stub both calls always were -- ENOSYS for a
 * FIFO (mode & S_IFMT == S_IFIFO), EPERM for anything else, decided
 * from `mode` alone so one function can still tell mkfifo()'s [ENOSYS]
 * from mknod()'s [EPERM] apart with no separate entry point.  Linux has
 * a real mknodat(2) and creates the node for real, mode unmasked
 * exactly like __plat_mkdir() above (the real kernel applies its own
 * umask). 0/-1(errno). */
int __plat_mknod(int dirfd, const char *path, mode_t mode, dev_t dev);

/* The guts of stat()/fstat(): fill *st from an open handle of __FD_*
 * type `type` -- see stat.c's own banner for the $LXMOD/compatibility-
 * default mode policy and the synthetic st_dev/st_ino this assigns a
 * pipe/console/char/unknown handle. 0/-1(errno). */
int __plat_fstat(__plat_handle_t h, int type, struct stat *st);
/* fstatat(): resolves `path` (relative to `dirfd`) to a handle (with
 * stat.c's own reparse-tag/permission fallback cascade on the NT side)
 * and calls __plat_fstat(). 0/-1(errno). */
int __plat_fstatat(int dirfd, const char *path, int flags, struct stat *st);

/* fstatvfs() on an already-open handle -- see statvfs.c's own banner
 * for the field-by-field derivation. 0/-1(errno). */
int __plat_statvfs(__plat_handle_t h, struct statvfs *buf);
/* statvfs(): resolves `path` (always relative to the process's own
 * current directory -- POSIX statvfs() takes no dirfd) to a handle and
 * calls __plat_statvfs(). 0/-1(errno). */
int __plat_statvfs_path(const char *path, struct statvfs *buf);

/* futimens() on an already-open handle: the Wine READONLY-clearing
 * workaround utimensat.c's own comment documents lives here.
 * 0/-1(errno). */
int __plat_set_times(__plat_handle_t h, const struct timespec ts[2]);
/* utimensat(): resolves `path` (relative to `dirfd`) to a handle (with
 * the FILE_WRITE_ATTRIBUTES-denied-on-a-read-only-file Wine fallback
 * utimensat.c's own comment documents on the NT side) and calls
 * __plat_set_times(). 0/-1(errno). */
int __plat_set_times_at(int dirfd, const char *path, int flags, const struct timespec ts[2]);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
