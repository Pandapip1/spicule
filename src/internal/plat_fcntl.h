/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform interface src/fcntl/{open,fcntl,fadvise}.c's POSIX-
 * facing front doors call into instead of a raw NtCreateFile/NtLockFile/
 * NtUnlockFile/NtQueryInformationFile/NtSetInformationFile/
 * NtQueryVolumeInformationFile call.  See src/fcntl/nt/plat_fcntl.c for
 * the implementations these declare.
 *
 * Every function here takes POSIX-shaped arguments and returns a
 * POSIX-shaped result -- errno already set on failure, never a raw
 * platform status for the front door to interpret (posix_fallocate()'s
 * own XSI convention -- returning the error NUMBER, not -1/errno -- is
 * the one documented exception below, and is the front door's own
 * adaptation of that result, not a different backend contract).
 *
 * __plat_open() takes a raw, UNRESOLVED (dirfd, path) pair rather than
 * a `struct __ntpath *` -- unlike the rest of this header's history.
 * Path resolution (src/internal/path.c, src/internal/vfs.c) used to be
 * "explicitly out of scope for this migration" (every previous version
 * of this comment said so) because there seemed to be no POSIX-shaped
 * way to describe "a resolved path" to a future backend. There still
 * isn't -- but there does not need to be: __plat_open() below hands the
 * RAW path straight through, and each backend resolves it however it
 * needs to (the NT backend still calls __ntpath_at()/__vfs_resolve_at()
 * internally, exactly as before, just moved from the front door into
 * the backend's own function body -- the same relocation every other
 * NT-specific interpretation step in this migration already got). A
 * Linux backend needs no resolution step at all: openat(2) already
 * takes (dirfd, path) directly, so its __plat_open() is close to a
 * straight pass-through. See src/fcntl/open.c's own banner for what
 * stays in the front door (only the genuinely portable /dev/std*
 * fd-table special case) versus what moved here.
 */
#ifndef _SPICULE_PLAT_FCNTL_H
#define _SPICULE_PLAT_FCNTL_H

#include <sys/types.h>
#include "plat_handle.h"

/* open()/openat(): resolve `path` (relative to `dirfd`, spicule's own
 * AT_FDCWD sentinel or an already-open dirfd) and translate `flags`/
 * `mode` into whatever the backend's native open call needs -- see
 * src/fcntl/open.c's own banner for the access-mode/synchronous/share-
 * mode policy this replaces on the NT side. `mode` is the already-
 * umask-applied creation mode (0 unless O_CREAT is set).
 *
 * *vfsout and *vfsnativeout report spicule's own POSIX-namespace-overlay
 * state (src/internal/libc.h's __VFS_* enum: is this descriptor one of
 * the synthetic `/`, `/dev`, `/dev/null` etc. entries NT needs because
 * it has no native concept of them, and if so does a real native object
 * also exist there) -- purely an NT backend concern (see plat_dirent.h/
 * src/internal/vfs.c for why: real POSIX filesystems, Linux included,
 * already have real `/dev/null` etc, so nothing needs synthesizing). A
 * non-NT backend has nothing to report here: __VFS_NONE/0, always.
 *
 * On success, *out and *typeout are filled (*typeout is __FD_DIR when the
 * result is a directory, 0 otherwise) and 0 is returned.  On failure,
 * -1/errno.
 *
 * out/typeout/vfsout/vfsnativeout are all required. Both real
 * backends (src/fcntl/{nt,linux}/plat_fcntl.c) dereference typeout
 * and out unconditionally along every real success-return path (NT:
 * lines like `*typeout = __FD_DIR; ...; return 0;`; Linux: the
 * statx-derived `*typeout = ...` switch and `*out = ...` before its
 * own `return 0;`), with no NULL check of either pointer anywhere.
 * vfsout/vfsnativeout are dereferenced unconditionally by the NT
 * backend along its own VFS-overlay branches, and left entirely
 * untouched -- not dereferenced at all -- by the Linux backend (see
 * that file's own `(void)vfsout; (void)vfsnativeout;`, since no VFS
 * overlay exists there); either way, no backend ever requires them to
 * be NULL. This function's one real call site, src/fcntl/open.c's own
 * __open_handle(), forwards exactly these four pointers unmodified
 * (`return __plat_open(dirfd, path, flags, mode, out, typeout, vfsout,
 * vfsnativeout);`), and __open_handle() itself already requires all
 * four of its own (see that function's own comment) -- so nothing
 * NULL can ever reach here. path is deliberately left unmarked: it is
 * the one argument __open_handle() explicitly, defensively checks
 * before ever reaching this call (`if (!path) { errno = EFAULT;
 * return -1; }`), a real, load-bearing guard, not decoration. */
int __plat_open(int dirfd, const char *path, int flags, unsigned mode,
                 __plat_handle_t *out, int *typeout, int *vfsout, int *vfsnativeout)
    __attribute__((nonnull(5, 6, 7, 8)));

/* fcntl(F_GETLK): does a lock of the given range/exclusivity conflict
 * with anything already held?  NT has no separate "would this
 * succeed" query -- NtLockFile IS the test, immediately released again
 * on success (see fcntl.c's record_lock()).  0 with *conflicting=0
 * means the probe round-tripped clean (no conflict; the caller reports
 * F_UNLCK); 0 with *conflicting=1 means NT refused with a lock-
 * conflict status (the caller reports l_pid=-1: NT does not expose an
 * owning process for a byte-range lock); -1/errno is a genuine
 * failure, neither of the above.
 *
 * conflicting is required: both backends (src/fcntl/{nt,linux}/
 * plat_fcntl.c) write through it unconditionally on every success
 * path (NT: `*conflicting = 0;` as the very first statement, then
 * possibly `*conflicting = 1;` further down; Linux: `*conflicting =
 * fl.l_type != F_UNLCK_LX;` right after the syscall succeeds), with
 * no NULL check of the pointer itself. Its one real call site,
 * src/fcntl/fcntl.c's own F_GETLK handling inside fcntl() itself,
 * always passes `&conflicting`, a real local's address, never NULL. */
int __plat_lock_probe(__plat_handle_t h, long long off, long long len, int exclusive, int *conflicting)
    __attribute__((nonnull(5)));

/* fcntl(F_SETLK/F_SETLKW): places a byte-range lock over [off,off+len).
 * `wait` nonzero selects F_SETLKW's blocking behaviour. 0/-1(errno). */
int __plat_lock_set(__plat_handle_t h, long long off, long long len, int exclusive, int wait);

/* fcntl(F_SETLK with F_UNLCK): removes a byte-range lock over
 * [off,off+len). 0/-1(errno). */
int __plat_lock_clear(__plat_handle_t h, long long off, long long len);

/* posix_fallocate()'s [EFBIG]: the volume's maximum representable file
 * size -- see fadvise.c's own banner for why this must be computed
 * rather than queried directly (NT reports "no room", never "too big
 * for this file system").  LLONG_MAX on any query failure or a zero-
 * cluster answer: an unrecognised volume must not be treated as having
 * a limit of zero. */
long long __plat_volume_max_file_size(__plat_handle_t h);

/* posix_fallocate()'s current allocation size and logical end-of-file
 * for `h` (FileStandardInformation), which the front door compares
 * against the requested extent to decide what (if anything) needs
 * growing -- see fadvise.c's own comment on why the two are checked
 * separately rather than just against the request. 0/-1(errno).
 *
 * alloc_size/eof are both required: both backends (src/fcntl/{nt,
 * linux}/plat_fcntl.c) write through both unconditionally, back to
 * back, right after their own success check (NT: `*alloc_size =
 * si.AllocationSize; *eof = si.EndOfFile;`; Linux: `*alloc_size =
 * ... stx_blocks ...; *eof = ... stx_size;`), with no NULL check of
 * either pointer. Its one real call site, src/fcntl/fadvise.c's
 * posix_fallocate(), always passes `&alloc_size, &eof`, two real
 * locals' addresses, never NULL. */
int __plat_file_extent(__plat_handle_t h, long long *alloc_size, long long *eof)
    __attribute__((nonnull(2, 3)));

/* posix_fallocate()'s two-step storage reservation for an extent ending
 * at `want`: first the allocation size (only when `grow_alloc` is
 * nonzero -- the front door's own data-loss interlock on when growing
 * the allocation is safe, see fadvise.c's banner, decides this before
 * calling), then the logical end-of-file (only when `want` exceeds
 * `eof`).  Unlike every other function in this header, returns a
 * POSIX ERROR NUMBER directly on failure (0 on success), matching
 * posix_fallocate()'s own XSI return convention -- the error is
 * returned, not signalled via -1/errno. */
int __plat_fallocate(__plat_handle_t h, long long want, long long eof, int grow_alloc);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
