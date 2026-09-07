/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux implementation of src/internal/plat_stat.h -- see that header for
 * the contract each function makes, and src/mman/linux/plat_mem.c's
 * banner for the raw-syscall discipline this file follows.
 *
 * __plat_lxmod_get()/__plat_lxmod_set() are declared by the header but NOT
 * defined here: grep across src/ confirms they are called only from
 * within src/stat/nt/plat_stat.c itself, to read/write WSL's $LXMOD NTFS
 * extended attribute -- a workaround for NT having no native POSIX mode
 * bits at all. A real Linux filesystem already has real mode bits, so
 * there is nothing for a Linux $LXMOD equivalent to do.
 *
 * The five path-taking functions (__plat_chmodat(), __plat_mkdir(),
 * __plat_fstatat(), __plat_statvfs_path(), __plat_set_times_at()) need
 * almost no translation: real Linux syscalls already take (dirfd, path)
 * directly, and this backend never calls __vfs_resolve_at() at all, since
 * Linux already has real, native `/dev/null` etc.
 *
 * __plat_mkdir() passes `mode` straight to mkdirat(2) UNMASKED, mirroring
 * __plat_open()'s Linux implementation: masking it here too would
 * double-mask against the real kernel-level umask spicule's own umask()
 * (src/stat/chmod.c) already pushes out via __plat_umask_apply() below.
 *
 * __plat_chmodat()'s AT_SYMLINK_NOFOLLOW: the raw fchmodat(2) syscall
 * takes NO flags argument at all. This backend tries fchmodat2(2) (Linux
 * 6.6+) when AT_SYMLINK_NOFOLLOW is set, and reports ENOTSUP -- not
 * silently following the symlink -- if the syscall is missing (ENOSYS) on
 * an older kernel, matching what real glibc does.
 *
 * __plat_fstat() uses statx(2) rather than fstat(2)/newfstatat(2)
 * deliberately: unlike the classic kernel `struct stat`, whose raw layout
 * differs between architectures, struct statx is a fixed,
 * architecture-independent ABI. st_mode needs NO translation into
 * spicule's own struct stat, since spicule's S_IF*, S_IR* etc. values are
 * the same standard bits the kernel uses -- unlike NT, which has to
 * synthesize a mode from FILE_ATTRIBUTE_* bits. `type` goes unused here
 * for the same reason: statx(2) already reports the correct type
 * natively.
 *
 * st_dev/st_rdev are assembled from statx's separate major/minor pairs
 * via a simple, documented (not glibc-bit-compatible) packing that only
 * needs to be internally self-consistent.
 *
 * __plat_statvfs() uses fstatfs(2); unlike NT (which reports zero for
 * f_files/f_ffree/f_favail because NTFS's MFT has no fixed inode pool),
 * Linux genuinely has real numbers here.
 *
 * __plat_set_times() is a single utimensat(2) syscall with a NULL
 * pathname (the documented Linux idiom for "operate on this fd
 * directly"), needing no translation of `ts` at all -- dramatically
 * simpler than NT's version, which needs a query/merge round-trip to
 * work around a Wine quirk.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "libc.h"
#include "plat_stat.h"

/* Linux syscall numbers -- aarch64 confirmed against this host's own
 * <sys/syscall.h>; x86_64/i386 confirmed against this host's own
 * /nix/store linux-headers asm/unistd_64.h / asm/unistd_32.h.
 * fchmodat2 is 452 on every arch here -- a recent addition sharing the
 * same cross-arch numbering scheme plat_misc.c's own banner documents
 * for pidfd_open/pidfd_send_signal. */
#if defined(__aarch64__)
#define SYS_fchmod    52
#define SYS_fchmodat  53
#define SYS_fchmodat2 452
#define SYS_mkdirat   34
#define SYS_mknodat   33
#define SYS_statx     291
#define SYS_statfs    43
#define SYS_fstatfs   44
#define SYS_utimensat 88
#define SYS_umask     166
#elif defined(__x86_64__)
#define SYS_fchmod    91
#define SYS_fchmodat  268
#define SYS_fchmodat2 452
#define SYS_mkdirat   258
#define SYS_mknodat   259
#define SYS_statx     332
#define SYS_statfs    137
#define SYS_fstatfs   138
#define SYS_utimensat 280
#define SYS_umask     95
#elif defined(__i386__)
#define SYS_fchmod    94
#define SYS_fchmodat  306
#define SYS_fchmodat2 452
#define SYS_mkdirat   296
#define SYS_mknodat   297
#define SYS_statx     383
#define SYS_statfs    99
#define SYS_fstatfs   100
#define SYS_utimensat 320
#define SYS_umask     60
#else
#error "plat_stat.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

#define AT_EMPTY_PATH_LX     0x1000
#define STATX_BASIC_STATS_LX 0x7ff

/* A minimal 6-argument raw syscall: no host libc in the call path. NOT
 * `extern long syscall(long, ...)`, which resolves to the HOST's real
 * glibc at link time and sets glibc's OWN errno on failure rather than
 * the raw kernel -errno this file's translation requires. Three
 * per-arch bodies, same "own syscall table per file" discipline this
 * tree already uses (see src/dirent/linux/plat_dirent.c's own
 * raw_syscall()): aarch64's `svc #0`, x86_64's `syscall`, i386's
 * register-starved `int $0x80`. */
#if defined(__aarch64__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6) // NOLINT(bugprone-easily-swappable-parameters) -- raw syscall ABI slots are positional and semantically distinct
{
	register long x8 __asm__("x8") = nr;
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = a3;
	register long x3 __asm__("x3") = a4;
	register long x4 __asm__("x4") = a5;
	register long x5 __asm__("x5") = a6;
	__asm__ volatile("svc #0"
		: "+r"(x0)
		: "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
		: "memory", "cc");
	return x0;
}
#elif defined(__x86_64__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long ret;
	register long r10 __asm__("r10") = a4;
	register long r8  __asm__("r8")  = a5;
	register long r9  __asm__("r9")  = a6;
	__asm__ volatile("syscall"
	                 : "=a"(ret)
	                 : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
	                 : "rcx", "r11", "memory");
	return ret;
}
#elif defined(__i386__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long args[7];
	long ret;
	args[0] = nr; args[1] = a1; args[2] = a2; args[3] = a3;
	args[4] = a4; args[5] = a5; args[6] = a6;
	__asm__ volatile(
		"pushl %%ebp\n\t"
		"pushl %%ebx\n\t"
		"movl 4(%%eax), %%ebx\n\t"
		"movl 8(%%eax), %%ecx\n\t"
		"movl 12(%%eax), %%edx\n\t"
		"movl 16(%%eax), %%esi\n\t"
		"movl 20(%%eax), %%edi\n\t"
		"movl 24(%%eax), %%ebp\n\t"
		"movl (%%eax), %%eax\n\t"
		"int $0x80\n\t"
		"popl %%ebx\n\t"
		"popl %%ebp"
		: "=a"(ret)
		: "a"(args)
		: "ecx", "edx", "esi", "edi", "memory", "cc");
	return ret;
}
#else
#error "plat_stat.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

static int unbox(__plat_handle_t h)
{
	return (int)((long)h - 1);
}

/* See src/fcntl/linux/plat_fcntl.c's own resolve_dirfd() -- identical
 * logic, duplicated per this tree's own-syscall-table-per-file
 * discipline. */
static int resolve_dirfd(int dirfd)
{
	struct __fd *f;
	if (dirfd == AT_FDCWD) return AT_FDCWD;
	f = __fd_get(dirfd);
	if (!f) return -1;
	return unbox(f->h);
}

/* The kernel's fixed, architecture-independent struct statx (linux/
 * stat.h) -- see this file's own banner for the field-by-field
 * confirmation against this host's real header. */
struct __lx_statx_timestamp { // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling mirrors the Linux kernel ABI layout
	long long tv_sec;
	unsigned int tv_nsec;
	int __reserved; // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling mirrors the Linux kernel ABI layout
};
struct __lx_statx { // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling mirrors the Linux kernel ABI layout
	unsigned int stx_mask;
	unsigned int stx_blksize;
	unsigned long long stx_attributes;
	unsigned int stx_nlink;
	unsigned int stx_uid;
	unsigned int stx_gid;
	unsigned short stx_mode;
	unsigned short __spare0[1]; // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling mirrors the Linux kernel ABI layout
	unsigned long long stx_ino;
	unsigned long long stx_size;
	unsigned long long stx_blocks;
	unsigned long long stx_attributes_mask;
	struct __lx_statx_timestamp stx_atime;
	struct __lx_statx_timestamp stx_btime;
	struct __lx_statx_timestamp stx_ctime;
	struct __lx_statx_timestamp stx_mtime;
	unsigned int stx_rdev_major;
	unsigned int stx_rdev_minor;
	unsigned int stx_dev_major;
	unsigned int stx_dev_minor;
	unsigned long long stx_mnt_id;
	unsigned int stx_dio_mem_align;
	unsigned int stx_dio_offset_align;
	unsigned long long __spare3[12]; // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling mirrors the Linux kernel ABI layout
};

/* The kernel's raw struct statfs (fstatfs(2)), confirmed field-for-field
 * against this host's own <sys/statfs.h> / asm-generic/statfs.h:
 * identical to glibc's own struct statfs on every 64-bit Linux
 * architecture. i386 genuinely differs, not just in overall struct
 * size: asm-generic/statfs.h's own __statfs_word is __kernel_long_t
 * (`long`, 8 bytes) on every 64-bit arch here, but plain `__u32`
 * (unsigned, 4 bytes) on 32-bit ones -- i386's own C `long` happens to
 * also be 4 bytes wide, so a `long`-typed field would still be the
 * right SIZE there, but the wrong SIGN (the kernel's field is always
 * unsigned): this file only ever reads these fields and immediately
 * casts them to an unsigned type in statfs_to_statvfs() below, so a
 * signed `long` re-interpretation of a value with bit 31 set would
 * sign-extend to a huge, wrong 64-bit value on the cast -- unsigned
 * int on i386 avoids that gap entirely rather than relying on every
 * real-world field value happening to stay under 2^31. */
#if defined(__i386__)
struct __lx_statfs { // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling mirrors the Linux kernel ABI layout
	unsigned int f_type;
	unsigned int f_bsize;
	unsigned int f_blocks;
	unsigned int f_bfree;
	unsigned int f_bavail;
	unsigned int f_files;
	unsigned int f_ffree;
	int f_fsid[2];
	unsigned int f_namelen;
	unsigned int f_frsize;
	unsigned int f_flags;
	unsigned int f_spare[4];
};
#define LX_STATFS_SIZE 64
#else
struct __lx_statfs { // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling mirrors the Linux kernel ABI layout
	long f_type;
	long f_bsize;
	unsigned long f_blocks;
	unsigned long f_bfree;
	unsigned long f_bavail;
	unsigned long f_files;
	unsigned long f_ffree;
	int f_fsid[2];
	long f_namelen;
	long f_frsize;
	long f_flags;
	long f_spare[4];
};
#define LX_STATFS_SIZE 120
#endif
/* Hand-computed from the real field list above (7 __statfs_word fields
 * + f_fsid's 2 ints + 3 more __statfs_word fields + a 4-element
 * __statfs_word spare array, no gaps: every field here is the same
 * width, so there is no alignment padding to account for either way):
 * 120 bytes on the two 64-bit arches (7+3+4=14 fields * 8 bytes = 112,
 * plus f_fsid's 8 bytes = 120), 64 bytes on i386 (14 fields * 4 bytes
 * = 56, plus f_fsid's 8 bytes = 64) -- sanity-checked below rather
 * than trusted by inspection alone, same discipline as
 * src/dirent/linux/plat_dirent.c's own __lx_dirent64 assert. */
_Static_assert(sizeof(struct __lx_statfs) == LX_STATFS_SIZE,
               "__lx_statfs layout mismatch for this architecture");

static dev_t pack_dev(unsigned major, unsigned minor)
{
	/* A simple, internally-consistent (not glibc-bit-compatible)
	 * packing -- see this file's own banner for why bit-for-bit
	 * fidelity to glibc's historical encoding is not needed here. */
	return ((dev_t)major << 20) | (dev_t)minor;
}

int __plat_chmod(__plat_handle_t h, mode_t mode)
{
	long ret = raw_syscall(SYS_fchmod, (long)unbox(h), (long)(mode & 07777), 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* fchmodat2(2) is Linux 6.6+. AT_SYMLINK_NOFOLLOW (0x100) is already the
 * real Linux value spicule's own constant matches, so it passes through
 * with no translation. */
int __plat_chmodat(int dirfd, const char *path, int flags, mode_t mode) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; flags and file mode have distinct roles
{
	int rd = resolve_dirfd(dirfd);
	long ret;

	if (rd == -1 && dirfd != AT_FDCWD) return -1; /* errno already set */

	if (flags & AT_SYMLINK_NOFOLLOW) {
		ret = raw_syscall(SYS_fchmodat2, (long)rd, (long)path,
		                  (long)(mode & 07777), (long)AT_SYMLINK_NOFOLLOW, 0L, 0L);
		if (is_sys_error(ret) && (int)-ret == ENOSYS) {
			/* No fchmodat2(2) on this kernel: the classic fchmodat(2)
			 * syscall has no flags argument at all, so there is no
			 * way to chmod a symlink itself rather than its target --
			 * see this file's own banner for why ENOTSUP, matching
			 * real glibc, is the honest answer here, not silently
			 * following the symlink. */
			errno = ENOTSUP;
			return -1;
		}
		if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
		return 0;
	}

	ret = raw_syscall(SYS_fchmodat, (long)rd, (long)path, (long)(mode & 07777), 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* umask(2) cannot fail -- it always sets the mask and returns the old
 * one -- so there is nothing for this to check or report; its only job
 * is making the new value real at the kernel level too. */
void __plat_umask_apply(mode_t m)
{
	raw_syscall(SYS_umask, (long)(m & 07777), 0L, 0L, 0L, 0L, 0L);
}

/* `mode` arrives RAW (not umask-applied) and is passed straight to
 * mkdirat(2) unmasked -- the real kernel applies the real process umask
 * itself (see this file's banner). */
int __plat_mkdir(int dirfd, const char *path, mode_t mode)
{
	int rd = resolve_dirfd(dirfd);
	long ret;

	if (rd == -1 && dirfd != AT_FDCWD) return -1; /* errno already set */

	ret = raw_syscall(SYS_mkdirat, (long)rd, (long)path, (long)(mode & 07777), 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* mkfifoat()/mknod()/mknodat(): Linux's own mknodat(2) already takes
 * exactly this (dirfd, path, mode, dev) shape, `mode` carrying both the
 * S_IF* node type and the permission bits together, so it needs no
 * translation. `dev` is passed through as given: this library cannot
 * construct a device node with a real major/minor today (no makedev()),
 * so only S_IFIFO and the CAP_MKNOD-gated EPERM path are reachable. */
int __plat_mknod(int dirfd, const char *path, mode_t mode, dev_t dev) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; mode and dev have distinct roles
{
	int rd = resolve_dirfd(dirfd);
	long ret;

	if (rd == -1 && dirfd != AT_FDCWD) return -1; /* errno already set */

	ret = raw_syscall(SYS_mknodat, (long)rd, (long)path, (long)mode, (long)dev, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* Shared by __plat_fstat()/__plat_fstatat(): fills *st from an already-
 * populated struct statx -- see this file's own banner for why st_mode
 * needs no translation and st_dev/st_rdev use pack_dev()'s own
 * documented (not glibc-bit-compatible) packing. */
static void statx_to_stat(const struct __lx_statx *stx, struct stat *st)
{
	memset(st, 0, sizeof *st);
	st->st_dev = pack_dev(stx->stx_dev_major, stx->stx_dev_minor);
	st->st_rdev = pack_dev(stx->stx_rdev_major, stx->stx_rdev_minor);
	st->st_ino = (ino_t)stx->stx_ino;
	st->st_mode = (mode_t)stx->stx_mode;
	st->st_nlink = (nlink_t)stx->stx_nlink;
	st->st_uid = (uid_t)stx->stx_uid;
	st->st_gid = (gid_t)stx->stx_gid;
	st->st_size = (off_t)stx->stx_size;
	st->st_blksize = (blksize_t)stx->stx_blksize;
	st->st_blocks = (blkcnt_t)stx->stx_blocks;
	st->st_atim.tv_sec = (time_t)stx->stx_atime.tv_sec;
	st->st_atim.tv_nsec = (long)stx->stx_atime.tv_nsec;
	st->st_mtim.tv_sec = (time_t)stx->stx_mtime.tv_sec;
	st->st_mtim.tv_nsec = (long)stx->stx_mtime.tv_nsec;
	st->st_ctim.tv_sec = (time_t)stx->stx_ctime.tv_sec;
	st->st_ctim.tv_nsec = (long)stx->stx_ctime.tv_nsec;
}

int __plat_fstat(__plat_handle_t h, int type, struct stat *st)
{
	struct __lx_statx stx;
	long ret;

	(void)type; /* unused -- see this file's own banner */

	memset(&stx, 0, sizeof stx);
	ret = raw_syscall(SYS_statx, (long)unbox(h), (long)"", (long)AT_EMPTY_PATH_LX,
	                 (long)STATX_BASIC_STATS_LX, (long)&stx, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	statx_to_stat(&stx, st);
	return 0;
}

/* `flags` is whatever the front door passed through unvalidated
 * (AT_SYMLINK_NOFOLLOW or 0 -- fstatat()'s only defined flag), and
 * needs no translation: statx(2)'s own AT_SYMLINK_NOFOLLOW is the same
 * 0x100 value. No AT_EMPTY_PATH here (unlike __plat_fstat() above):
 * this call is genuinely path-based, resolving `path` relative to the
 * real `rd` dirfd exactly like the raw syscall expects. */
int __plat_fstatat(int dirfd, const char *path, int flags, struct stat *st)
{
	int rd = resolve_dirfd(dirfd);
	struct __lx_statx stx;
	long ret;

	if (rd == -1 && dirfd != AT_FDCWD) return -1; /* errno already set */

	memset(&stx, 0, sizeof stx);
	ret = raw_syscall(SYS_statx, (long)rd, (long)path,
	                  (long)(flags & AT_SYMLINK_NOFOLLOW), (long)STATX_BASIC_STATS_LX, (long)&stx, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	statx_to_stat(&stx, st);
	return 0;
}

/* Shared by __plat_statvfs()/__plat_statvfs_path(): fills *buf from an
 * already-populated struct statfs -- see this file's own banner for the
 * field-by-field derivation. */
static void statfs_to_statvfs(const struct __lx_statfs *sf, struct statvfs *buf)
{
	memset(buf, 0, sizeof *buf);
	/* f_bsize/f_frsize: on the common Linux file systems (ext4, xfs,
	 * btrfs, tmpfs) the kernel's own f_bsize and f_frsize already
	 * agree, so no scaling of the block counts below is needed the way
	 * glibc's own statvfs() does when they genuinely differ. */
	buf->f_frsize = (unsigned long)(sf->f_frsize ? sf->f_frsize : sf->f_bsize);
	buf->f_bsize = (unsigned long)sf->f_bsize;
	buf->f_blocks = (fsblkcnt_t)sf->f_blocks;
	buf->f_bfree = (fsblkcnt_t)sf->f_bfree;
	buf->f_bavail = (fsblkcnt_t)sf->f_bavail;
	buf->f_files = (fsfilcnt_t)sf->f_files;
	buf->f_ffree = (fsfilcnt_t)sf->f_ffree;
	buf->f_favail = (fsfilcnt_t)sf->f_ffree; /* Linux reports no separate
	                             * privileged-vs-caller inode count,
	                             * same fallback NT's own backend uses
	                             * for f_bfree/f_bavail when only one
	                             * figure is available. */
	buf->f_fsid = (unsigned long)sf->f_fsid[0];
	/* ST_RDONLY/ST_NOSUID (<sys/statvfs.h>) are the same bit values
	 * the kernel's own f_flags uses (<linux/statfs.h> ST_RDONLY==1,
	 * ST_NOSUID==2), so no translation table is needed -- the same
	 * "already matches the ABI" situation plat_mem.c's banner
	 * describes for PROT_/MAP_. */
	buf->f_flag = (unsigned long)sf->f_flags & (ST_RDONLY | ST_NOSUID);
	buf->f_namemax = (unsigned long)sf->f_namelen;
}

int __plat_statvfs(__plat_handle_t h, struct statvfs *buf)
{
	struct __lx_statfs sf;
	long ret;

	memset(&sf, 0, sizeof sf);
	ret = raw_syscall(SYS_fstatfs, (long)unbox(h), (long)&sf, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	statfs_to_statvfs(&sf, buf);
	return 0;
}

/* statfs(2) (nr 43) is the real, path-based counterpart to fstatfs(2)
 * (nr 44) above -- no need to open the file first the way the NT
 * backend must (see src/stat/nt/plat_stat.c's __plat_statvfs_path(),
 * which opens a handle purely to hand it to NtQueryVolumeInformationFile,
 * NT having no path-based volume-information query at all). `path` is
 * always resolved against the process's real current directory when
 * relative -- POSIX statvfs() takes no dirfd, so there is nothing to
 * resolve here the way __plat_fstatat() above resolves one. */
int __plat_statvfs_path(const char *path, struct statvfs *buf)
{
	struct __lx_statfs sf;
	long ret;

	memset(&sf, 0, sizeof sf);
	ret = raw_syscall(SYS_statfs, (long)path, (long)&sf, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	statfs_to_statvfs(&sf, buf);
	return 0;
}

int __plat_set_times(__plat_handle_t h, const struct timespec ts[2])
{
	long ret = raw_syscall(SYS_utimensat, (long)unbox(h), 0L /* NULL path: see banner */,
	                      (long)ts, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* `flags` (AT_SYMLINK_NOFOLLOW or 0) needs no translation -- same value
 * on both sides, as throughout this file. */
int __plat_set_times_at(int dirfd, const char *path, int flags, const struct timespec ts[2])
{
	int rd = resolve_dirfd(dirfd);
	long ret;

	if (rd == -1 && dirfd != AT_FDCWD) return -1; /* errno already set */

	ret = raw_syscall(SYS_utimensat, (long)rd, (long)path, (long)ts,
	                  (long)(flags & AT_SYMLINK_NOFOLLOW), 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

// NOLINTEND(misc-include-cleaner)
