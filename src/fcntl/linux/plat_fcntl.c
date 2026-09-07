/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux implementation of src/internal/plat_fcntl.h -- see that header
 * for the contract each function makes, and src/mman/linux/plat_mem.c's
 * banner for the raw-syscall discipline this file follows.
 *
 * __plat_open() is implemented here, real: plat_fcntl.h hands it a raw,
 * unresolved (dirfd, path) pair, not an already-NT-resolved
 * `struct __ntpath *np`. Most of spicule's own O_* flag values already
 * match the Linux kernel ABI bit-for-bit and pass straight through.
 *
 * THREE do not, and -- unlike this banner used to claim -- the fix is
 * NOT the same on every architecture. spicule's own <fcntl.h> has
 * O_DIRECTORY=0200000/O_NOFOLLOW=0400000/O_DIRECT=040000. A real kernel
 * ABI check (raw openat(2), ENOTDIR-on-a-regular-file vs success-on-a-
 * real-directory for each candidate bit value, not trusted from any
 * header) gives OPPOSITE answers per architecture:
 *   - x86_64/i386: the kernel's real O_DIRECTORY/O_NOFOLLOW/O_DIRECT
 *     ARE 0200000/0400000/040000 -- identical to spicule's own values.
 *     No translation needed; confirmed with a qemu-user pilot (open("/",
 *     O_DIRECTORY) succeeds untranslated, EINVALs when translated).
 *   - aarch64: the kernel's real values are O_DIRECTORY=040000/
 *     O_NOFOLLOW=0100000/O_DIRECT=0200000 -- genuinely different bit
 *     positions from x86_64/i386, confirmed the same way (raw openat(2)
 *     directly, on this host's own real kernel) and matching this
 *     host's own real glibc <fcntl.h>. spicule's values DO need
 *     translating here.
 * A previous fix applied the aarch64 translation unconditionally on
 * every architecture: right for aarch64 (why the native suite never
 * caught it), silently sending the wrong bit to the x86_64/i386 kernel
 * (why a real directory open EINVALs there). The translation now only
 * runs for aarch64.
 *
 * Linux already has real, native `/dev/null` etc, so the VFS-overlay
 * machinery this interface's *vfsout / *vfsnativeout report is never
 * invoked here -- left at whatever the front door already initialized.
 *
 * *typeout cannot be decided from the O_ flags alone: Linux, like NT
 * after its own retry-as-directory dance, allows opening a directory for
 * reading without O_DIRECTORY. A real statx(2) on the freshly opened fd
 * answers this for real.
 *
 * The three lock functions are simpler here than on NT: Linux's
 * fcntl(F_GETLK) IS a native "would this conflict" probe (fills back
 * l_type with F_UNLCK when nothing blocks), where NT has no such query
 * and has to fake one by taking and releasing the lock.
 *
 * __plat_volume_max_file_size() always answers LLONG_MAX here: Linux
 * exposes no per-filesystem "maximum file size" query, and doesn't need
 * one -- the real fallocate(2) syscall __plat_fallocate() calls already
 * validates the request against the live filesystem's actual limit and
 * fails EFBIG itself.
 *
 * __plat_fallocate()'s NT two-step split (grow allocation, then advance
 * EndOfFile) has no Linux equivalent: a single fallocate(2) call over
 * [0, want) both reserves storage and advances size correctly, sparse
 * files included, so `grow_alloc`/`eof` are accepted but unused here.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "libc.h"
#include "plat_fcntl.h"
#include "unsafe_pointer.h"

/* Linux syscall numbers, confirmed against arch/x86/entry/syscalls/
 * syscall_{64,32}.tbl (x86_64/i386) and this host's own headers
 * (aarch64). i386's SYS_fcntl (55, not fcntl64=221) and SYS_ftruncate
 * (93, not ftruncate64=194) are the plain 32-bit-offset syscalls. */
#if defined(__aarch64__)
#define SYS_fcntl     25
#define SYS_fallocate 47
#define SYS_ftruncate 46
#define SYS_statx     291
#define SYS_openat    56
#define SYS_close     57
#elif defined(__x86_64__)
#define SYS_fcntl     72
#define SYS_fallocate 285
#define SYS_ftruncate 77
#define SYS_statx     332
#define SYS_openat    257
#define SYS_close     3
#elif defined(__i386__)
#define SYS_fcntl     55
#define SYS_fallocate 324
#define SYS_ftruncate 93
#define SYS_statx     383
#define SYS_openat    295
#define SYS_close     6
#else
#error "plat_fcntl.c: unsupported architecture"
#endif

#define AT_EMPTY_PATH_LX     0x1000
#define STATX_BASIC_STATS_LX 0x7ff

/* File-type mode-bits, standard POSIX/Linux kernel values. */
#define S_IFMT_LX   0170000
#define S_IFSOCK_LX 0140000
#define S_IFREG_LX  0100000
#define S_IFDIR_LX  0040000
#define S_IFCHR_LX  0020000
#define S_IFIFO_LX  0010000

#if defined(__aarch64__)
/* aarch64's real kernel O_DIRECTORY/O_NOFOLLOW/O_DIRECT values --
 * confirmed against this host's own real <fcntl.h> and a raw openat(2)
 * ENOTDIR/success probe, see this file's own banner. Genuinely
 * different bit positions from spicule's own <fcntl.h>, and from
 * x86_64/i386's real kernel ABI (which need no translation at all). */
#define LX_O_DIRECTORY 040000
#define LX_O_NOFOLLOW  0100000
#define LX_O_DIRECT    0200000

static int to_linux_open_flags(int flags)
{
	int out = flags & ~(O_DIRECTORY | O_NOFOLLOW | O_DIRECT);
	if (flags & O_DIRECTORY) out |= LX_O_DIRECTORY;
	if (flags & O_NOFOLLOW)  out |= LX_O_NOFOLLOW;
	if (flags & O_DIRECT)    out |= LX_O_DIRECT;
	return out;
}
#else
/* x86_64/i386: spicule's own O_DIRECTORY/O_NOFOLLOW/O_DIRECT already
 * match the real kernel ABI bit-for-bit -- no translation. */
static int to_linux_open_flags(int flags) { return flags; }
#endif

/* fcntl(2) lock commands and lock types: confirmed against this host's
 * own <fcntl.h> -- identical across 64-bit Linux architectures. */
#define F_GETLK_LX  5
#define F_SETLK_LX  6
#define F_SETLKW_LX 7
#define F_RDLCK_LX  0
#define F_WRLCK_LX  1
#define F_UNLCK_LX  2

/* A minimal 6-argument raw syscall: `svc #0` directly, no host libc in
 * the call path. NOT `extern long syscall(long, ...)`: that symbol
 * resolves to the HOST's real glibc at link time, which sets glibc's OWN
 * errno on failure rather than the raw kernel -errno this file's
 * translation requires -- and __plat_fallocate() below reads `-ret`
 * directly and compares it to EOPNOTSUPP/ENOSYS to decide whether to
 * degrade to ftruncate(), so under a glibc-wrapped syscall() that
 * degradation path would never trigger even when it should. */
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
/* See crt/linux/crt1.c's own raw_syscall() banner for the full per-arch
 * calling-convention rationale -- duplicated here per this tree's own
 * "own syscall table per file" discipline, not shared. */
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
#endif

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

static int unbox(__plat_handle_t h)
{
	return (int)((long)h - 1);
}

/* See src/unistd/linux/plat_unistd.c's own resolve_dirfd() -- identical
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

/* The kernel's raw 64-bit struct flock (fcntl(2) F_GETLK/F_SETLK/
 * F_SETLKW): confirmed field-for-field against this host's own
 * <fcntl.h> via offsetof()/sizeof() (l_type/l_whence at 0/2, l_start at
 * 8, l_len at 16, l_pid at 24, total size 32) -- identical layout on
 * every 64-bit Linux architecture, no F_GETLK64-style compat split. */
struct __lx_flock { // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling mirrors the Linux kernel ABI layout
	short l_type;
	short l_whence;
	long l_start;
	long l_len;
	int l_pid;
};

/* The kernel's fixed, architecture-independent struct statx -- see
 * src/stat/linux/plat_stat.c's banner for why this layout, unlike the
 * classic kernel struct stat, needs no per-architecture variant. */
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
	// NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling mirrors the Linux kernel ABI layout
	unsigned long long __rest[26]; /* attributes_mask, four timestamps,
	                                * rdev/dev major/minor, mnt_id,
	                                * dio alignment, and the kernel's own
	                                * reserved tail -- 256 bytes total. */
};

int __plat_open(int dirfd, const char *path, int flags, unsigned mode,
                __plat_handle_t *out, int *typeout, int *vfsout, int *vfsnativeout) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; output slots have distinct roles
{
	int rd, fd;
	long ret;
	struct __lx_statx stx;

	/* Never touched: no VFS overlay exists on this backend at all (see
	 * this file's own banner) -- *vfsout and *vfsnativeout stay whatever
	 * the front door (src/fcntl/open.c) already initialized them to. */
	(void)vfsout; (void)vfsnativeout;

	rd = resolve_dirfd(dirfd);
	if (rd == -1 && dirfd != AT_FDCWD) return -1; /* errno already set */

	ret = raw_syscall(SYS_openat, (long)rd, (long)path, (long)to_linux_open_flags(flags), (long)mode, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	fd = (int)ret;

	/* *typeout cannot be decided from the O_ flags alone: Linux, like NT
	 * after its own retry-as-directory dance, allows opening a directory
	 * for reading without O_DIRECTORY. A real statx(2) answers this.
	 *
	 * Unlike the NT backend, __FD_FILE must be reported explicitly here,
	 * not left at 0: this backend has no fd.c-style auto-classification
	 * behind it, so leaving *typeout at 0 would confirmed-the-hard-way
	 * make lseek()'s `f->type != __FD_FILE` check report ESPIPE on an
	 * ordinary regular file. */
	memset(&stx, 0, sizeof stx);
	ret = raw_syscall(SYS_statx, (long)fd, (long)"", (long)AT_EMPTY_PATH_LX,
	                  (long)STATX_BASIC_STATS_LX, (long)&stx, 0L);
	if (is_sys_error(ret)) {
		int e = (int)-ret;
		raw_syscall(SYS_close, (long)fd, 0L, 0L, 0L, 0L, 0L);
		errno = e;
		return -1;
	}
	switch (stx.stx_mode & S_IFMT_LX) {
	case S_IFDIR_LX:  *typeout = __FD_DIR; break;
	case S_IFIFO_LX:  *typeout = __FD_PIPE; break;
	case S_IFCHR_LX:  *typeout = __FD_CHAR; break;
	case S_IFSOCK_LX: *typeout = __FD_SOCKET; break;
	default:          *typeout = __FD_FILE; break; /* S_IFREG, S_IFBLK, or anything else */
	}

	/* __plat_handle_t is an opaque one-word carrier shared with the NT
	 * backend; this backend's real payload is the plain fd number,
	 * boxed +1 so 0 stays free for __PLAT_HANDLE_NULL, never
	 * dereferenced. */
	*out = unsafe_assume_valid_pointer((__plat_handle_t)(long)(fd + 1));
	return 0;
}

int __plat_lock_probe(__plat_handle_t h, long long off, long long len, int exclusive, int *conflicting) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; offset, length, and mode have distinct roles
{
	struct __lx_flock fl;
	long ret;

	fl.l_type = (short)(exclusive ? F_WRLCK_LX : F_RDLCK_LX);
	fl.l_whence = 0; /* SEEK_SET: off/len already arrive absolute -- see
	                  * src/fcntl/fcntl.c's record_lock_range(). */
	fl.l_start = (long)off;
	fl.l_len = (long)len;
	fl.l_pid = 0;

	ret = raw_syscall(SYS_fcntl, (long)unbox(h), (long)F_GETLK_LX, (long)&fl, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	*conflicting = fl.l_type != F_UNLCK_LX;
	return 0;
}

int __plat_lock_set(__plat_handle_t h, long long off, long long len, int exclusive, int wait) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; offset, length, and modes have distinct roles
{
	struct __lx_flock fl;
	long ret;

	fl.l_type = (short)(exclusive ? F_WRLCK_LX : F_RDLCK_LX);
	fl.l_whence = 0;
	fl.l_start = (long)off;
	fl.l_len = (long)len;
	fl.l_pid = 0;

	ret = raw_syscall(SYS_fcntl, (long)unbox(h), (long)(wait ? F_SETLKW_LX : F_SETLK_LX), (long)&fl, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

int __plat_lock_clear(__plat_handle_t h, long long off, long long len) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; offset and length have distinct roles
{
	struct __lx_flock fl;
	long ret;

	fl.l_type = F_UNLCK_LX;
	fl.l_whence = 0;
	fl.l_start = (long)off;
	fl.l_len = (long)len;
	fl.l_pid = 0;

	ret = raw_syscall(SYS_fcntl, (long)unbox(h), (long)F_SETLK_LX, (long)&fl, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

long long __plat_volume_max_file_size(__plat_handle_t h)
{
	(void)h;
	return LLONG_MAX;
}

/* struct __lx_statx/__lx_statx_timestamp: defined once, above, next to
 * __plat_open() (its first reader in this file). Only stx_size/
 * stx_blocks are read below; everything past them collapses into the
 * trailing __spare padding since nothing else is needed here. */
int __plat_file_extent(__plat_handle_t h, long long *alloc_size, long long *eof) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; allocation and EOF outputs have distinct roles
{
	struct __lx_statx stx;
	long ret;

	memset(&stx, 0, sizeof stx);
	ret = raw_syscall(SYS_statx, (long)unbox(h), (long)"", (long)AT_EMPTY_PATH_LX,
	                 (long)STATX_BASIC_STATS_LX, (long)&stx, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	*alloc_size = (long long)stx.stx_blocks * 512; /* stx_blocks is
	                             * always counted in 512-byte units, the
	                             * same convention struct stat's
	                             * st_blocks uses. */
	*eof = (long long)stx.stx_size;
	return 0;
}

int __plat_fallocate(__plat_handle_t h, long long want, long long eof, int grow_alloc) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; requested extent and EOF have distinct roles
{
	int fd = unbox(h);
	long ret;
	(void)grow_alloc; (void)eof;

	ret = raw_syscall(SYS_fallocate, (long)fd, 0L, 0L, (long)want, 0L, 0L);
	if (!is_sys_error(ret)) return 0;

	if (-ret == EOPNOTSUPP || -ret == ENOSYS) {
		/* Some filesystems (FAT, older tmpfs, some network filesystems)
		 * do not implement fallocate(2). Degrade to ftruncate()'s weaker
		 * guarantee -- it still advances EOF but may leave a sparse hole
		 * -- rather than failing a call that would work on ext4/xfs/
		 * btrfs. posix_fallocate.html permits exactly this. */
		if (want > eof) {
			ret = raw_syscall(SYS_ftruncate, (long)fd, (long)want, 0L, 0L, 0L, 0L);
			if (!is_sys_error(ret)) return 0;
		} else {
			return 0; /* nothing to grow; the weaker guarantee is moot */
		}
	}
	return (int)-ret;
}

// NOLINTEND(misc-include-cleaner)
