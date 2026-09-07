/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Unix98 pseudo-terminal allocation for native Linux:
 * posix_openpt()/grantpt()/unlockpt()/ptsname()/ptsname_r().
 * include/stdlib.h's own "undefined-ok" comment on these five says NT
 * has no PTY concept at all (true, and that reasoning stays for NT --
 * the NT console/pipe model is shaped nothing like a Unix98 pty pair);
 * Linux has a completely real, well-defined one, built entirely on
 * /dev/ptmx plus two ioctl(2) requests, so this backend implements all
 * five for real (same NT-reasoning-stays-Linux-gets-real-code split as
 * this tree's own syscall()/setresuid()/euidaccess() precedent).
 *
 * posix_openpt() is a plain open("/dev/ptmx", oflag) -- spicule's own
 * public open() front door (src/fcntl/open.c) already resolves that
 * path through a real openat(2) on this backend (Linux has real native
 * devices, no VFS-overlay resolution needed -- see src/unistd/linux/
 * plat_unistd.c's own banner on the same point), so nothing here needs
 * to reopen or reinterpret it.
 *
 * grantpt() has nothing left to do on a modern Linux: the devpts
 * filesystem itself already sets the slave's ownership/permissions
 * (root:tty, mode 0620 by devpts's own "ptmxmode" default) the instant
 * /dev/ptmx is opened -- there is no separate chown()+chmod() step for
 * this function to perform the way historical SysV PTY allocation
 * needed one. glibc's own grantpt() is, in current versions, exactly
 * this: validate the fd names a real ptmx master (this backend does
 * that via the same TIOCGPTN probe ptsname() needs anyway) and return.
 * This is not a no-op fiction -- it is what grantpt() genuinely reduces
 * to once the kernel does the real work itself.
 *
 * unlockpt() is the one still-genuinely-necessary step: a freshly
 * opened /dev/ptmx master starts LOCKED (devpts refuses to open the
 * slave until unlocked), so ioctl(TIOCSPTLCK, &0) below is a real,
 * required kernel request, not a formality.
 *
 * ptsname()/ptsname_r() ask the kernel which slave number this master
 * was assigned via ioctl(TIOCGPTN), then format "/dev/pts/<n>" -- the
 * real devpts mount path, not a guess: this assumes a standard
 * devpts-mounted /dev/pts, the same assumption every other real PTY
 * consumer on Linux already makes.
 *
 * Raw ioctl(2) syscalls, not this library's own curated public ioctl()
 * front door (include/sys/ioctl.h/src/ioctl/ioctl.c): that front door
 * only ever recognizes FIONREAD/FIONBIO/TIOCGWINSZ (a deliberately
 * small, documented set -- see its own header comment), and
 * TIOCGPTN/TIOCSPTLCK are not among them. Extending that curated front
 * door for two PTY-only requests it was never meant to carry would
 * widen its contract for no other caller's benefit; going straight to
 * the kernel here, the same discipline every other Linux backend file
 * in this tree already follows for its own syscalls, is the smaller
 * and more honest change. `raw_fd()` below reaches into the fd table
 * the same way src/unistd/linux/plat_unistd.c's resolve_dirfd() and
 * src/ioctl/linux/plat_ioctl.c's unbox() both already do, for the same
 * fd+1 encoding (src/unistd/linux/plat_fd.c's own banner).
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include "libc.h"

/* Linux syscall number -- aarch64 confirmed against this host's own
 * <sys/syscall.h>; x86_64/i386 confirmed against this host's own
 * /nix/store linux-headers asm/unistd_64.h / asm/unistd_32.h. */
#if defined(__aarch64__)
#define SYS_ioctl 29
#elif defined(__x86_64__)
#define SYS_ioctl 16
#elif defined(__i386__)
#define SYS_ioctl 54
#else
#error "plat_pty.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

/* TIOCGPTN/TIOCSPTLCK need no per-arch variant: Linux's ioctl(2)
 * request-number encoding (_IOR/_IOW's type+number+size+direction
 * packing, include/uapi/asm-generic/ioctl.h) is the shared "generic"
 * scheme every mainstream arch this tree targets uses identically --
 * unlike the handful of arches (sparc, mips, powerpc, none of them
 * targets here) that define their own incompatible ioctl.h. */
#define TIOCGPTN   0x80045430u  /* _IOR('T', 0x30, unsigned int) */
#define TIOCSPTLCK 0x40045431u  /* _IOW('T', 0x31, int) */

/* A minimal 6-argument raw syscall: no host libc in the call path at
 * all. Three per-arch bodies, same "own syscall table per file"
 * discipline this tree already uses (see src/dirent/linux/
 * plat_dirent.c's own raw_syscall()): aarch64's `svc #0`, x86_64's
 * `syscall`, i386's register-starved `int $0x80`. */
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
#error "plat_pty.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

static int unbox(__plat_handle_t h)
{
	return (int)((long)h - 1);
}

/* -1 with errno=EBADF (from __fd_get()) for an fd this process never
 * opened; spicule's own fd+1 boxing otherwise unwrapped into the raw
 * Linux fd every ioctl(2) below actually needs. */
static int raw_fd(int fd)
{
	struct __fd *f = __fd_get(fd);
	if (!f) return -1;
	return unbox(f->h);
}

int posix_openpt(int oflag)
{
	return open("/dev/ptmx", oflag);
}

int grantpt(int fd)
{
	unsigned n = 0;
	int rfd = raw_fd(fd);
	long ret;
	if (rfd < 0) return -1;
	ret = raw_syscall(SYS_ioctl, (long)rfd, (long)TIOCGPTN, (long)&n, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

int unlockpt(int fd)
{
	int rfd = raw_fd(fd);
	int zero = 0;
	long ret;
	if (rfd < 0) return -1;
	ret = raw_syscall(SYS_ioctl, (long)rfd, (long)TIOCSPTLCK, (long)&zero, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* ptsname_r.html is a GNU extension, not POSIX -- glibc's own contract
 * (0 on success, an errno-shaped int, never -1/errno, on failure; ERANGE
 * when buflen is too small) is what this backend matches, since nothing
 * else defines one. */
int ptsname_r(int fd, char *buf, size_t buflen)
{
	unsigned n = 0;
	int rfd = raw_fd(fd);
	long ret;
	char tmp[32];
	int len;

	if (rfd < 0) return errno;
	ret = raw_syscall(SYS_ioctl, (long)rfd, (long)TIOCGPTN, (long)&n, 0L, 0L, 0L);
	if (is_sys_error(ret)) return (int)-ret;
	len = snprintf(tmp, sizeof tmp, "/dev/pts/%u", n);
	if (len < 0) return EIO;
	if ((size_t)len + 1 > buflen) return ERANGE;
	memcpy(buf, tmp, (size_t)len + 1);
	return 0;
}

static char ptsname_buf[32];

char *ptsname(int fd)
{
	int e = ptsname_r(fd, ptsname_buf, sizeof ptsname_buf);
	if (e) { errno = e; return 0; }
	return ptsname_buf;
}

// NOLINTEND(misc-include-cleaner)
