/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux's __fd_init(), replacing src/internal/fd.c's own (PLATFORM's
 * REPLACED_OBJS override).
 *
 * NT's __fd_init() reads __peb->ProcessParameters for the three standard
 * handles and an optional RuntimeData blob describing every OTHER
 * descriptor a parent chose to hand down across CreateProcess -- both
 * concepts specific to how NT starts a process. A real Linux process
 * instead already HAS descriptors 0/1/2 open and inherits every other
 * still-open, non-close-on-exec descriptor automatically, with the
 * kernel as the only bookkeeping authority for the raw numbers.
 *
 * What IS this library's own job: spicule's own __fds[] table in a
 * freshly exec'd process is a brand new, zeroed array that has never
 * heard of any of these descriptors. A raw descriptor surviving exec is
 * perfectly usable at the syscall level, but every spicule-level
 * operation on it (read()/write()/fcntl()/close()/dup(), which resolve a
 * small integer to a handle by indexing __fds[], never by asking the
 * kernel) returns EBADF until the table knows the slot is occupied.
 * install_inherited() closes that gap by asking the kernel what is
 * really there (fcntl(F_GETFD) as an existence probe, statx(2) via
 * classify_fd() to classify it, fcntl(F_GETFL) for its access mode).
 *
 * One case this file does NOT cover, by design:
 * posix_spawn_file_actions_adddup2() targeting a descriptor above 2 still
 * uses __plat_dup() rather than __plat_dup_to(), because forcing the
 * duplicate's real number to match the target slot would mean dup3(2)
 * closing the PARENT's real descriptor at that number as a side effect,
 * exactly the mutation posix_spawn() promises not to leave behind. The
 * target-fd wiring instead happens in the CHILD, after clone(2) but
 * before execve(2), in __plat_process_spawn()'s own mv[]/dup3 staging
 * loop; by the time this file runs, every such target is already sitting
 * at its real number, indistinguishable from a descriptor the child was
 * simply born with.
 *
 * Classification below reuses src/fcntl/linux/plat_fcntl.c's own
 * statx()-based approach and constants. __handle_type() is this split's
 * Linux half of src/internal/nt/plat_fd_init.c's NT one (a raw
 * NtQueryVolumeInformationFile/NtQueryInformationFile pair there, a
 * single statx(2) here). */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include "libc.h"
#include "unsafe_pointer.h"

#if defined(__aarch64__)
#define SYS_statx 291
#define SYS_fcntl 25
#elif defined(__x86_64__)
#define SYS_statx 332
#define SYS_fcntl 72
#elif defined(__i386__)
#define SYS_statx 383
#define SYS_fcntl 55
#else
#error "plat_fd_init.c: unsupported architecture"
#endif

/* fcntl(2) command numbers: F_GETFD/F_GETFL, unlike a syscall number,
 * have no per-architecture table to get wrong (uapi/asm-generic/fcntl.h). */
#define F_GETFD_LX 1
#define F_GETFL_LX 3
#define FD_CLOEXEC_LX 1

#define AT_EMPTY_PATH_LX     0x1000
#define STATX_BASIC_STATS_LX 0x7ff

#define S_IFMT_LX   0170000
#define S_IFSOCK_LX 0140000
#define S_IFDIR_LX  0040000
#define S_IFCHR_LX  0020000
#define S_IFIFO_LX  0010000

/* Same 6-argument raw syscall trampoline every Linux backend defines for
 * itself (never the host's syscall(2) wrapper -- see plat_mem.c's banner
 * for why that collapses every failure's errno to the wrong value). */
#if defined(__aarch64__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6) // NOLINT(bugprone-easily-swappable-parameters) -- raw syscall ABI slots are positional and semantically distinct
{
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = a3;
	register long x3 __asm__("x3") = a4;
	register long x4 __asm__("x4") = a5;
	register long x5 __asm__("x5") = a6;
	register long x8 __asm__("x8") = nr;
	__asm__ volatile("svc #0"
	                 : "+r"(x0)
	                 : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
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
#endif

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

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
	unsigned long long __rest[26]; // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling mirrors the Linux kernel ABI layout
};

/* Returns __FD_UNKNOWN (never 0) on a closed/invalid fd, matching
 * __handle_type()'s own NT contract: 0 is not a member of the __FD_*
 * enum, so a caller like __fd_install_at() cannot mistake this for
 * "no override, fall through". */
static int classify_fd(int fd)
{
	struct __lx_statx stx;
	long ret;

	memset(&stx, 0, sizeof stx);
	ret = raw_syscall(SYS_statx, (long)fd, (long)"", (long)AT_EMPTY_PATH_LX,
	                  (long)STATX_BASIC_STATS_LX, (long)&stx, 0L);
	if (is_sys_error(ret)) return __FD_UNKNOWN;

	switch (stx.stx_mode & S_IFMT_LX) {
	case S_IFDIR_LX:  return __FD_DIR;
	case S_IFIFO_LX:  return __FD_PIPE;
	case S_IFCHR_LX:  return __FD_CHAR;
	case S_IFSOCK_LX: return __FD_SOCKET;
	default:          return __FD_FILE;
	}
}

/* HANDLE here is always this backend's own boxed (fd + 1) encoding --
 * every caller already holds a __plat_handle_t this backend itself
 * produced, never a raw platform object the way NT's version queries. */
int __handle_type(HANDLE h)
{
	long fd = (long)h - 1;
	if (fd < 0) return __FD_UNKNOWN;
	return classify_fd((int)fd);
}

static void install_std(int fd)
{
	int type = classify_fd(fd);
	if (type == __FD_UNKNOWN) return; /* fd not actually open -- leave the slot empty */

	/* Boxed (fd + 1): __PLAT_HANDLE_NULL is 0, and fd 0/stdin is a real,
	 * valid descriptor that must not collide with "empty slot". O_RDONLY
	 * for fd 0, O_WRONLY for 1/2: write() refuses an O_RDONLY descriptor
	 * and O_RDONLY is 0, so getting this wrong for an inherited
	 * stdout/stderr would silently break writes to it. */
	/* Boxing, not dereference -- see install_inherited()'s own comment
	 * below on the identical +1 HANDLE encoding. */
	__fd_install_at(fd, unsafe_assume_valid_pointer((HANDLE)(long)(fd + 1)),
	                fd == 0 ? O_RDONLY : O_WRONLY, type);
}

/* Every descriptor above 2 that is still open when a freshly exec'd
 * process starts was inherited from whatever spawned it, and the raw
 * number is already correct at the kernel level -- all that is missing
 * is this library's OWN __fds[] entry. Found by probing every candidate
 * slot directly with fcntl(F_GETFD) rather than parsing /proc/self/fd/:
 * a plain probe needs no directory-entry parsing and no procfs mount.
 *
 * fcntl(F_GETFD) answers two questions in one syscall: whether the slot
 * is open at all, and confirms FD_CLOEXEC really is clear (a descriptor
 * with it set would already have been closed by execve() before this
 * ever ran). F_GETFL supplies the access mode/O_APPEND/O_NONBLOCK bits
 * that classify_fd()'s statx(2) cannot. */
static void install_inherited(void)
{
	int fd;
	for (fd = 3; fd < FD_MAX; fd++) {
		long fdflags = raw_syscall(SYS_fcntl, (long)fd, (long)F_GETFD_LX, 0L, 0L, 0L, 0L);
		long flflags;
		unsigned flags;
		int type;

		if (is_sys_error(fdflags)) continue; /* not open */

		type = classify_fd(fd);
		if (type == __FD_UNKNOWN) continue; /* raced closed between the two probes -- leave it out rather than guess */

		flflags = raw_syscall(SYS_fcntl, (long)fd, (long)F_GETFL_LX, 0L, 0L, 0L, 0L);
		flags = is_sys_error(flflags) ? 0 : ((unsigned)flflags & (O_ACCMODE | O_APPEND | O_NONBLOCK));
		if (fdflags & FD_CLOEXEC_LX) flags |= O_CLOEXEC; /* should not happen (see banner) -- recorded faithfully if it somehow does */

		/* This is the same "+1" fd-to-HANDLE boxing __plat_dup_to()
		 * (src/unistd/linux/plat_fd.c), __plat_kill_open()'s box_fd(),
		 * and every other Linux __plat_handle_t producer already use:
		 * HANDLE/__plat_handle_t is void*
		 * only because plat_handle.h commits every backend to one
		 * pointer-sized carrier, never dereferenced on this backend --
		 * the real payload is the plain descriptor number `fd`, which
		 * this loop's own `for (fd = 3; fd < FD_MAX; fd++)` bounds to
		 * a small nonnegative int, boxed +1 so 0 stays free for
		 * __PLAT_HANDLE_NULL. */
		__fd_install_at(fd, unsafe_assume_valid_pointer((HANDLE)(long)(fd + 1)), flags, type);
	}
}

void __fd_init(void)
{
	install_std(0);
	install_std(1);
	install_std(2);
	install_inherited();
}

// NOLINTEND(misc-include-cleaner)
