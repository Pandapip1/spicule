/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Real Linux implementation of every function <termios.h> declares:
 * tcgetattr()/tcsetattr(), tcsendbreak()/tcdrain()/tcflush()/tcflow(),
 * cfgetispeed()/cfsetispeed()/cfgetospeed()/cfsetospeed(), tcgetsid().
 * src/termios/termios.c implements the exact same eleven symbols against
 * an NT console, the only "terminal" that backend has; that file's body
 * is wrapped in `#ifndef __linux__` specifically so this one can define
 * them for real here without a link-time collision (see its own banner)
 * -- Linux has a genuine tty/pty layer under any real terminal fd, so
 * unlike NT there is no console-shadow, no SPICULE_USE_KERNEL32 gate, and
 * no "accepted and stored, never applied" bucket at all: every clause
 * this header describes is backed by a real ioctl(2) on the underlying
 * fd, the same raw-syscall discipline every other src/<module>/linux/
 * plat_<name>.c backend in this tree already follows (see src/mman/linux/plat_mem.c's
 * banner for the fuller rationale, and src/stdlib/linux/plat_pty.c for
 * the closest sibling: same fd+1 unboxing, same "go straight to the
 * kernel rather than widen spicule's own curated ioctl() front door"
 * choice src/ioctl/ioctl.c's own banner already makes explicit -- TCGETS2
 * and friends below are exactly as tty-specific and out of scope for
 * that front door as TIOCGPTN/TIOCSPTLCK already were for plat_pty.c).
 *
 * GATING: no f->type check of any kind. NT's get_console() gates on
 * `f->type != __FD_CONSOLE` because __FD_CONSOLE is the one descriptor
 * shape that structurally IS a console there; Linux has no equivalent
 * shape -- src/internal/linux/plat_fd_init.c folds every character
 * device (a real tty/pty *and* /dev/null, /dev/zero, ...) into the one
 * __FD_CHAR bucket, so a type check here could only ever be a coarse,
 * misleading filter, not a real answer. The real answer already exists
 * for free: issuing TCGETS2/TCSETS2/TCFLSH/TCXONC/TCSBRK/TIOCGSID
 * against a Linux fd that is not a terminal fails ENOTTY straight from
 * the kernel's own ioctl dispatch (ioctl_tty(2)) -- the exact errno
 * termios.html's own ERRORS clause requires, sourced from the real
 * device instead of guessed from fd metadata. __fd_get() below still
 * supplies [[EBADF]] for an fd this process never opened, the one check
 * a real ioctl(2) call cannot make on spicule's own behalf (an unboxed,
 * never-issued fd number does not name a live kernel object at all).
 *
 * THE STRUCT MISMATCH (why this is real translation, not a memcpy):
 * this platform's own <termios.h> already defines c_iflag/c_oflag's and
 * most of c_cflag/c_lflag's bit VALUES identical to Linux's real kernel
 * ABI (confirmed field-for-field against this host's own
 * <asm-generic/termbits.h>/<asm-generic/termbits-common.h>, not
 * assumed) -- IGNBRK..IXOFF, OPOST..FFDLY, CSIZE/CSTOPB/CREAD/PARENB/
 * PARODD/HUPCL/CLOCAL/CRTSCTS, ISIG..IEXTEN all line up bit-for-bit.
 * That is presumably deliberate future-proofing in the public header,
 * not a coincidence, and it is why get()/set() below can assign those
 * fields directly with no bit-shuffling. Three things still cannot be a
 * straight memcpy of the two structs over each other, though:
 *
 *   1. tcflag_t itself is a different WIDTH: this header's tcflag_t is
 *      `unsigned long` (8 bytes on this LP64 host), the kernel's is
 *      `unsigned int` (4 bytes, asm-generic/termbits.h). A same-offset
 *      memcpy between the two structs would misalign every field after
 *      the first. Field-by-field assignment sidesteps this for free
 *      (ordinary C integer conversion, no explicit cast needed) --
 *      exactly why this file does NOT try to overlay struct termios on
 *      struct termios2 the way, say, src/ioctl/linux/plat_ioctl.c's
 *      struct __lx_statx can be read directly: this platform's own
 *      struct termios AND the kernel's differ in shape, not just in the
 *      handful of fields the public struct adds (c_ispeed/c_ospeed).
 *   2. c_cc[] INDICES do not line up past VMIN. This header's own
 *      c_cc[] (include/termios.h) has no VSWTC slot at all -- its
 *      VSTART..VEOL2 sit at indices 7..15, sixteen slots total (NCCS).
 *      The kernel's real c_cc[] (confirmed against
 *      <asm-generic/termbits-common.h>) reserves index 7 for VSWTC (a
 *      SysV line-switch character no BSD-descended API, including this
 *      one, exposes) and only then continues VSTART..VEOL2 at indices
 *      8..16, nineteen slots total (NCCS==19 there). A straight index-
 *      for-index copy would silently hand back the kernel's VSWTC value
 *      as this platform's VSTART, and so on down the array -- exactly
 *      the kind of subtle, silent corruption this project's own
 *      "confirmed against the real header, not assumed" discipline
 *      exists to catch. lx_cc_get()/lx_cc_put() below do the real
 *      remap: indices 0..6 (VINTR..VMIN) 1:1, index 7 (VSWTC) skipped
 *      entirely -- read-only-preserved on the kernel side by tcsetattr()'s
 *      own read-modify-write below, since this header has no slot to
 *      source or sink a value for it -- and indices 7..15 here to the
 *      kernel's 8..16.
 *   3. BAUD RATE is encoded two entirely different ways. This header's
 *      c_ispeed/c_ospeed are already literal bps values (include/
 *      termios.h's own banner: "these are just the bps number itself"),
 *      the *BSD shape. The kernel's classic struct termios has no
 *      ispeed/ospeed fields at all -- baud lives packed into c_cflag's
 *      CBAUD field as a small ENCODED index (B9600 there is the literal
 *      value 13, not 9600) via TCGETS/TCSETS. TCGETS2/TCSETS2/
 *      TCSETSW2/TCSETSF2 (struct termios2, confirmed sizeof==44 and
 *      every member offset against this host's own <asm-generic/
 *      termbits.h> via a throwaway offsetof() oracle, the same
 *      discipline src/ioctl/linux/plat_ioctl.c's struct __lx_statx
 *      banner describes) add real c_ispeed/c_ospeed fields alongside
 *      CBAUD, activated by setting CBAUD's BOTHER bit -- which is
 *      exactly the *BSD-shaped literal-Hz interface this header already
 *      committed to, so this file uses TCGETS2/TCSETS2 exclusively
 *      (never the classic TCGETS/TCSETS) and never needs a CBAUD-index
 *      lookup table at all. set() special-cases c_ispeed==0 (B0, the
 *      one rate POSIX gives extra "drop modem control lines" meaning
 *      to, termios.h.html's own B0 entry: "hang up") by clearing CBAUD
 *      to its literal index-0 encoding instead of setting BOTHER --
 *      both this header's B0 and the kernel's own index 0 already are
 *      the value 0, so this is not a special case in the DATA, only in
 *      which of BOTHER-vs-plain-CBAUD-index gets written.
 *
 * READ-MODIFY-WRITE in tcsetattr(): every kernel-only bit this header
 * has no macro for at all (c_iflag's IUCLC/IMAXBEL/IUTF8, c_oflag's
 * OLCUC, c_lflag's XCASE/ECHOCTL/ECHOPRT/ECHOKE/FLUSHO/PENDIN/EXTPROC,
 * and c_cc[]'s VSWTC slot) is preserved across a tcsetattr() call by
 * fetching the kernel's current full state via TCGETS2 first and only
 * overlaying the fields this header's struct termios actually models,
 * rather than zeroing them just because *t never carried a value for
 * them. include/termios.h simply does not define a name for these bits
 * -- callers of THIS library can never set or inspect them through any
 * public API -- but that is a reason not to let an unrelated
 * tcsetattr() call (disable ECHO, say) silently clobber another
 * program's already-configured ECHOKE/ECHOCTL on the same real
 * terminal. A stub-shaped straight overwrite would do exactly that;
 * this does not. get() correspondingly reads and returns the kernel's
 * REAL iflag/oflag/lflag bits without masking to only this header's own
 * macro set -- those extra bits are real terminal state, harmless to
 * report, and reporting them (rather than laundering them away) is the
 * more honest of the two choices. c_cflag's CBAUD/CBAUDEX bits are the
 * one deliberate exception: masked out of both directions, because this
 * platform's OWN c_cflag namespace defines no bit at all over that
 * range (baud lives in c_ispeed/c_ospeed here, not c_cflag) -- leaving
 * a raw kernel baud-index in c_cflag would be meaningless noise this
 * header's own macros cannot interpret, not real information.
 *
 * tcdrain()/tcflow()/tcsendbreak()/tcflush()/tcgetsid(): each is one
 * real, unconditional ioctl(2), request numbers taken from this host's
 * own <asm-generic/ioctls.h> --
 *   - tcdrain(): ioctl(fd, TCSBRK, 1) -- tty_ioctl(4)'s own documented
 *     meaning for a nonzero TCSBRK argument is "equivalent to
 *     tcdrain()", so this is not an approximation, it is the named
 *     kernel operation.
 *   - tcflow(fd, action): ioctl(fd, TCXONC, action) -- TCOOFF/TCOON/
 *     TCIOFF/TCION (this platform's <termios.h>) already equal the
 *     kernel's own TCOOFF/TCOON/TCIOFF/TCION (0/1/2/3 both places), so
 *     action passes straight through with no translation.
 *   - tcflush(fd, queue): ioctl(fd, TCFLSH, queue) -- likewise
 *     TCIFLUSH/TCOFLUSH/TCIOFLUSH already equal the kernel's own
 *     values (0/1/2 both places, confirmed against
 *     <asm-generic/termbits-common.h>).
 *   - tcsendbreak(fd, duration): duration==0 is ioctl(fd, TCSBRK, 0)
 *     ("send a break of 0.25 to 0.5 seconds", tty_ioctl(4)'s documented
 *     meaning for a zero argument, and termios.html's own duration==0
 *     case verbatim). duration!=0 is ioctl(fd, TCSBRKP, duration) --
 *     the kernel header's own comment on TCSBRKP is literally "Needed
 *     for POSIX tcsendbreak()", and its documented unit (tenths of a
 *     second) is adopted directly as THIS function's own duration unit
 *     rather than inventing a conversion of this library's own: POSIX
 *     leaves a nonzero duration's unit implementation-defined
 *     (tcsendbreak.html), so defining it as "exactly what TCSBRKP
 *     already means" is a real, documented choice, not a guess.
 *   - tcgetsid(fd): ioctl(fd, TIOCGSID, &sid) -- "Return the session ID
 *     of FD", the real kernel answer, not src/unistd/ids.c's fixed
 *     single-session fallback the NT backend uses (this platform has no
 *     controlling-terminal/session concept of its own to fall back to;
 *     Linux's session/controlling-terminal machinery is real).
 *
 * cfgetispeed()/cfgetospeed()/cfsetispeed()/cfsetospeed(): pure struct
 * accessors, no fd and no syscall involved at all -- byte-for-byte the
 * same four one-liners src/termios/termios.c defines, duplicated here
 * rather than shared across translation units, matching every other
 * Linux backend file's own-syscall-table (and, here, own-struct-
 * accessor) discipline documented throughout this tree.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <termios.h>
#include <string.h>
#include <errno.h>
#include "libc.h"

/* Linux syscall numbers -- see src/mman/linux/plat_mem.c's banner for
 * why these are hardcoded rather than pulled from a host header.
 * aarch64's SYS_ioctl==29 is already independently confirmed and reused
 * across this tree (src/stdlib/linux/plat_pty.c, src/ioctl/linux/
 * plat_ioctl.c); x86_64's SYS_ioctl==16 is the fixed, decades-stable
 * entry in arch/x86/entry/syscalls/syscall_64.tbl, the same oracle
 * src/exit/linux/plat_exit.c's own banner cites for its x86_64 numbers;
 * i386's SYS_ioctl==54 is confirmed against this host's own /nix/store
 * linux-headers asm/unistd_32.h and already reused identically in
 * src/stdlib/linux/plat_pty.c and src/ioctl/linux/plat_ioctl.c. */
#if defined(__aarch64__)
#define SYS_ioctl 29
#elif defined(__x86_64__)
#define SYS_ioctl 16
#elif defined(__i386__)
#define SYS_ioctl 54
#else
#error "plat_termios.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

/* A minimal 6-argument raw syscall -- see src/socket/linux/
 * plat_socket.c's banner for the full rationale (glibc's own syscall()
 * wrapper cannot be used: it performs its own errno translation into a
 * different, glibc-owned errno than this library's, src/internal/
 * errno.c) and src/mman/linux/plat_mem.c's for the calling-convention
 * detail (aarch64: x8=nr, x0..x5=args, result/-errno in x0; x86_64:
 * rax=nr, rdi/rsi/rdx/r10/r8/r9=args, result/-errno in rax -- note r10,
 * not rcx, for the 4th argument: the `syscall` instruction itself
 * clobbers rcx; i386: `int $0x80`, eax=nr, ebx/ecx/edx/esi/edi/ebp=args,
 * result/-errno in eax -- register-starved relative to the other two
 * arches (no free register left for a 7th operand), so args are staged
 * through memory the same way src/stdlib/linux/plat_pty.c's own i386
 * raw_syscall() already does). */
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
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6) // NOLINT(bugprone-easily-swappable-parameters) -- raw syscall ABI slots are positional and semantically distinct
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
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6) // NOLINT(bugprone-easily-swappable-parameters) -- raw syscall ABI slots are positional and semantically distinct
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
#error "plat_termios.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

static int unbox(__plat_handle_t h)
{
	return (int)((long)h - 1);
}

/* ioctl(2) request numbers -- confirmed against this host's own
 * <asm-generic/ioctls.h>, not assumed (see this file's own banner). Not
 * in spicule's own public <sys/ioctl.h>: these are all tty-specific
 * (TCGETS2 et al) or the wrong shape for that curated front door
 * (TCSBRKP), exactly the "go straight to the kernel" call
 * src/stdlib/linux/plat_pty.c's own banner already makes for
 * TIOCGPTN/TIOCSPTLCK. */
#define LX_TCGETS2   0x802c542aUL
#define LX_TCSETS2   0x402c542bUL
#define LX_TCSETSW2  0x402c542cUL
#define LX_TCSETSF2  0x402c542dUL
#define LX_TCSBRK    0x5409UL
#define LX_TCXONC    0x540AUL
#define LX_TCFLSH    0x540BUL
#define LX_TCSBRKP   0x5425UL
#define LX_TIOCGSID  0x5429UL

/* c_cflag's CBAUD field (baud-rate index, bits 0-3) plus CBAUDEX/BOTHER
 * (bit 12) -- <asm-generic/termbits.h>'s own CBAUD==0x0000100f already
 * covers both bit groups in one mask. Confirmed not to overlap any bit
 * this platform's own c_cflag defines (CSIZE=0x30, CSTOPB=0x40,
 * CREAD=0x80, PARENB=0x100, PARODD=0x200, HUPCL=0x400, CLOCAL=0x800,
 * CRTSCTS=0x80000000) -- see this file's banner. */
#define LX_CBAUD   0x0000100fUL
#define LX_BOTHER  0x00001000UL

#define LX_NCCS 19

/* The kernel's real struct termios2 (<asm-generic/termbits.h>) --
 * confirmed field-for-field via offsetof()/sizeof() against this host's
 * own header (sizeof==44; c_iflag/c_oflag/c_cflag/c_lflag at 0/4/8/12,
 * c_line at 16, c_cc at 17, c_ispeed at 36, c_ospeed at 40 -- no
 * explicit padding needed in this mirror, since c_cc's tail already
 * lands on a 4-byte boundary), the same offsetof()-oracle discipline
 * src/ioctl/linux/plat_ioctl.c's struct __lx_statx banner describes. */
struct __lx_termios2 { // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling mirrors the Linux kernel ABI layout
	unsigned int c_iflag;
	unsigned int c_oflag;
	unsigned int c_cflag;
	unsigned int c_lflag;
	unsigned char c_line;
	unsigned char c_cc[LX_NCCS];
	unsigned int c_ispeed;
	unsigned int c_ospeed;
};

static int lx_ioctl(int fd, unsigned long req, long arg) // NOLINT(bugprone-easily-swappable-parameters) -- positional syscall ABI slots are positional and semantically distinct
{
	long ret = raw_syscall(SYS_ioctl, (long)fd, (long)req, arg, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* c_cc[] index remap -- see this file's banner, point 2. Kernel indices
 * 0..6 (VINTR..VMIN) map straight across; kernel index 7 (VSWTC) has no
 * counterpart in this header's c_cc[] and is skipped; kernel indices
 * 8..16 (VSTART..VEOL2) map to this header's indices 7..15. */
static void lx_cc_get(cc_t *pub, const unsigned char *kern)
{
	int i;
	for (i = 0; i < 7; i++) pub[i] = kern[i];
	for (i = 7; i < NCCS; i++) pub[i] = kern[i + 1];
}

static void lx_cc_put(unsigned char *kern, const cc_t *pub)
{
	int i;
	for (i = 0; i < 7; i++) kern[i] = pub[i];
	for (i = 7; i < NCCS; i++) kern[i + 1] = pub[i];
}

int tcgetattr(int fd, struct termios *t)
{
	struct __fd *f = __fd_get(fd);
	struct __lx_termios2 kt;

	if (!f) return -1;
	memset(&kt, 0, sizeof kt);
	if (lx_ioctl(unbox(f->h), LX_TCGETS2, (long)&kt) < 0) return -1;

	t->c_iflag = kt.c_iflag;
	t->c_oflag = kt.c_oflag;
	t->c_cflag = kt.c_cflag & ~(tcflag_t)LX_CBAUD; /* see this file's banner: baud lives in c_ispeed/c_ospeed here, not c_cflag */
	t->c_lflag = kt.c_lflag;
	lx_cc_get(t->c_cc, kt.c_cc);
	t->c_ispeed = kt.c_ispeed;
	t->c_ospeed = kt.c_ospeed;
	return 0;
}

int tcsetattr(int fd, int act, const struct termios *t) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __fd *f = __fd_get(fd);
	struct __lx_termios2 kt;
	unsigned long req;

	if (!f) return -1;
	if (act != TCSANOW && act != TCSADRAIN && act != TCSAFLUSH) { errno = EINVAL; return -1; }

	/* Read-modify-write: see this file's banner ("READ-MODIFY-WRITE in
	 * tcsetattr()") for why the kernel's current state is fetched
	 * first rather than building kt from *t alone. */
	memset(&kt, 0, sizeof kt);
	if (lx_ioctl(unbox(f->h), LX_TCGETS2, (long)&kt) < 0) return -1;

	kt.c_iflag = (unsigned int)t->c_iflag;
	kt.c_oflag = (unsigned int)t->c_oflag;
	kt.c_lflag = (unsigned int)t->c_lflag;
	kt.c_cflag = (kt.c_cflag & (unsigned int)LX_CBAUD) | ((unsigned int)t->c_cflag & ~(unsigned int)LX_CBAUD);
	lx_cc_put(kt.c_cc, t->c_cc);

	if (t->c_ispeed == 0) {
		/* B0 ("hang up", termios.h.html): the classic CBAUD index-0
		 * encoding IS zero, so this is a real, deliberate write, not
		 * a no-op -- it forces the field to 0 regardless of whatever
		 * baud was previously configured. */
		kt.c_cflag &= ~(unsigned int)LX_CBAUD;
		kt.c_ispeed = 0;
		kt.c_ospeed = 0;
	} else {
		kt.c_cflag = (kt.c_cflag & ~(unsigned int)LX_CBAUD) | (unsigned int)LX_BOTHER;
		kt.c_ispeed = t->c_ispeed;
		kt.c_ospeed = t->c_ospeed;
	}

	switch (act) {
	case TCSADRAIN: req = LX_TCSETSW2; break;
	case TCSAFLUSH: req = LX_TCSETSF2; break;
	default:        req = LX_TCSETS2;  break; /* TCSANOW, already validated above */
	}
	return lx_ioctl(unbox(f->h), req, (long)&kt);
}

speed_t cfgetispeed(const struct termios *t) { return t->c_ispeed; }
speed_t cfgetospeed(const struct termios *t) { return t->c_ospeed; }

int cfsetispeed(struct termios *t, speed_t s) { t->c_ispeed = s; return 0; }
int cfsetospeed(struct termios *t, speed_t s) { t->c_ospeed = s; return 0; }

int tcflush(int fd, int queue) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __fd *f = __fd_get(fd);
	if (!f) return -1;
	if (queue != TCIFLUSH && queue != TCOFLUSH && queue != TCIOFLUSH) { errno = EINVAL; return -1; }
	return lx_ioctl(unbox(f->h), LX_TCFLSH, (long)queue);
}

int tcdrain(int fd)
{
	struct __fd *f = __fd_get(fd);
	if (!f) return -1;
	return lx_ioctl(unbox(f->h), LX_TCSBRK, 1L);
}

int tcflow(int fd, int action) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __fd *f = __fd_get(fd);
	if (!f) return -1;
	if (action != TCOOFF && action != TCOON && action != TCIOFF && action != TCION) { errno = EINVAL; return -1; }
	return lx_ioctl(unbox(f->h), LX_TCXONC, (long)action);
}

int tcsendbreak(int fd, int duration) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __fd *f = __fd_get(fd);
	if (!f) return -1;
	if (duration == 0) return lx_ioctl(unbox(f->h), LX_TCSBRK, 0L);
	return lx_ioctl(unbox(f->h), LX_TCSBRKP, (long)duration);
}

pid_t tcgetsid(int fd)
{
	struct __fd *f = __fd_get(fd);
	int sid = 0;
	if (!f) return (pid_t)-1;
	if (lx_ioctl(unbox(f->h), LX_TIOCGSID, (long)&sid) < 0) return (pid_t)-1;
	return (pid_t)sid;
}

// NOLINTEND(misc-include-cleaner)
