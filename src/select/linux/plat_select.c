/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux implementation of src/internal/plat_select.h -- see src/mman/
 * linux/plat_mem.c's own banner for the general discipline this file
 * follows too (raw syscall(2), no host libc, -nostdinc against spicule's
 * own headers, aarch64 syscall numbers confirmed against this host's
 * own <sys/syscall.h>).
 *
 * NT has no single primitive that answers "is this descriptor ready"
 * for every descriptor shape at once (see src/select/select.c's own
 * banner at length: a console handle is a real waitable NT object, a
 * pipe needs an explicit FILE_PIPE_LOCAL_INFORMATION query, and a
 * socket needs the raw IOCTL_AFD_SELECT dance), which is exactly why
 * plat_select.h is shaped as a bundle of small, per-descriptor-shape
 * probes plus a separate multi-handle wait. Linux collapses ALL of
 * that into one primitive, poll(2)/ppoll(2), which already answers
 * readable/writable/hung-up for a pipe, a socket, a regular file, or
 * a tty in a single call -- there is no NT-shaped "which kind of
 * object is this" branch to make at all. So every probe below
 * (__plat_pipe_probe, __plat_wait_ready, __plat_socket_probe) is
 * implemented the same way: a zero-timeout poll(fd, POLLIN|POLLOUT, 0)
 * (via ppoll(2) -- aarch64 has no separate poll(2) syscall number at
 * all, only ppoll; confirmed against this host's own <sys/syscall.h>,
 * where SYS_poll is simply undefined), read through revents. The
 * select.c front door's own wait-vs-poll STRATEGY (probe first, sleep
 * only if nothing is ready, cap a pipe/socket-only sleep at
 * POLL_INTERVAL_TICKS) is untouched by this file, exactly as the
 * general contract requires (plat_select.h's own banner) -- only the
 * raw syscalls each step needs are relocated here, even though a
 * native Linux port of select()/poll() would collapse that whole
 * strategy into one ppoll(2) call across every requested descriptor at
 * once; that strategy-level rewrite belongs to select.c/poll.c, not to
 * this backend, and is explicitly out of scope here (see tools/
 * linux-build-misc.sh's own scope note).
 *
 * __plat_handle_t here is a boxed fd, unboxed the same way
 * src/unistd/linux/plat_fd.c's own unbox() does (fd+1) -- the encoding
 * src/internal/libc.h's struct __fd fixes for every backend, not
 * something this file chooses independently: every __plat_handle_t
 * select.c ever hands this file (a pipe end, a socket, a console-
 * analog stdin fd) already went through __fd_install()'s same boxing,
 * whichever backend originally opened it.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>
#include "plat_select.h"

/* aarch64 Linux syscall numbers (confirmed via a throwaway host program
 * printing the SYS_* macros from <sys/syscall.h>, the same oracle
 * technique src/mman/linux/plat_mem.c's banner describes). */
#define SYS_ppoll         73
#define SYS_clock_gettime 113
#define SYS_nanosleep     101

extern long syscall(long number, ...);

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

static int unbox(__plat_handle_t h) { return (int)((long)h - 1); }

/* struct timespec, as the raw clock_gettime(2)/nanosleep(2)/ppoll(2)
 * kernel ABI on a 64-bit-time_t architecture (aarch64 always is one;
 * see src/internal/libc.h's discipline elsewhere) actually lays it
 * out: two 8-byte fields, matching spicule's own <time.h> struct
 * timespec exactly, so no local restatement of the struct is needed --
 * <poll.h> already pulls in <time.h> for struct timespec (ppoll(2)'s
 * timeout argument). */

static long long ticks_to_ns(long long ticks) { return ticks * 100LL; }

int __plat_pipe_probe(__plat_handle_t h, unsigned long *read_avail, unsigned long *write_quota) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; read and write outputs have distinct roles
{
	struct pollfd pfd;
	struct timespec zero;
	long ret;

	pfd.fd = unbox(h);
	pfd.events = POLLIN | POLLOUT;
	pfd.revents = 0;
	zero.tv_sec = 0; zero.tv_nsec = 0;
	ret = syscall(SYS_ppoll, &pfd, 1L, &zero, 0L, 0L);
	if (is_sys_error(ret) || (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))) {
		/* Query failed, or the pipe is disconnected -- select.c's
		 * caller (__fd_probe()) reads a 0 return here as "ready and
		 * hung up" itself (see plat_select.h's own comment), exactly
		 * matching a broken/disconnected pipe's NT reading. */
		return 0;
	}
	/* FIONREAD gives the real byte count for read_avail; write_quota
	 * has no Linux equivalent (a pipe's free capacity is not queryable
	 * as a byte count the way NT's WriteQuotaAvailable is) but the only
	 * thing any caller of this ever does with it is compare it against
	 * 0 (select.c's __fd_probe(): `*canwrite = ... write_quota > 0`),
	 * so poll(2)'s own POLLOUT bit -- which Linux computes correctly
	 * from the pipe's real free space -- answers the same question
	 * directly, with no invented number needed: 1 stands for "some
	 * room", 0 for "full", and nothing here is ever added, subtracted,
	 * or compared for magnitude beyond that boolean. */
	{
		int avail = 0;
		long fionread_ret = syscall(29 /* SYS_ioctl */, (long)pfd.fd, 0x541BL /* FIONREAD */, &avail);
		*read_avail = (is_sys_error(fionread_ret) || avail < 0) ? 0 : (unsigned long)avail;
	}
	*write_quota = (pfd.revents & POLLOUT) ? 1UL : 0UL;
	return 1;
}

int __plat_pipe_wqa_trustworthy(void)
{
	/* wqa_works()'s whole reason to exist (select.c's own banner) is
	 * that NT's WriteQuotaAvailable field is sometimes a hardcoded 0
	 * that carries no signal (wine-9.0) and sometimes a real, populated
	 * quota (wine-10.0+, real Windows) -- indistinguishable without a
	 * positive-control probe. This backend's write_quota above is never
	 * that hardcoded-0 field to begin with: it is poll(2)'s own POLLOUT
	 * bit, which the Linux kernel always computes correctly for a
	 * pipe's real free space. There is no untrustworthy case to detect
	 * here at all -- always trustworthy. */
	return 1;
}

int __plat_wait_ready(__plat_handle_t h)
{
	struct pollfd pfd;
	struct timespec zero;
	long ret;

	pfd.fd = unbox(h);
	pfd.events = POLLIN;
	pfd.revents = 0;
	zero.tv_sec = 0; zero.tv_nsec = 0;
	ret = syscall(SYS_ppoll, &pfd, 1L, &zero, 0L, 0L);
	if (is_sys_error(ret)) return 0;
	return (pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0;
}

/* The identity here: Linux has a real tty layer, nothing is ever
 * classified __FD_CONSOLE (src/unistd/linux/plat_isatty.c), and there
 * is no reader thread standing between a descriptor and its device. */
int __plat_console_ready(__plat_handle_t h) { return __plat_wait_ready(h); }
__plat_handle_t __plat_console_wait(__plat_handle_t h) { return h; }

void __plat_socket_probe(__plat_handle_t h, int *canread, int *canwrite, int *hup) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; readiness outputs have distinct roles
{
	struct pollfd pfd;
	struct timespec zero;
	long ret;

	pfd.fd = unbox(h);
	pfd.events = POLLIN | POLLOUT;
	pfd.revents = 0;
	zero.tv_sec = 0; zero.tv_nsec = 0;
	ret = syscall(SYS_ppoll, &pfd, 1L, &zero, 0L, 0L);
	if (is_sys_error(ret)) {
		/* No honest answer available -- same over-eager "ready and hung
		 * up" stance the NT backend takes when IOCTL_AFD_SELECT itself
		 * fails (see plat_select.h's own comment). */
		*canread = 1; *canwrite = 1; *hup = 1;
		return;
	}
	*canread = (pfd.revents & POLLIN) != 0;
	*canwrite = (pfd.revents & POLLOUT) != 0;
	*hup = (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) != 0;
	if (*hup) { *canread = 1; *canwrite = 1; }
}

void __plat_wait_multiple(const __plat_handle_t *handles, int nhandles, long long wait_ticks, int infinite) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; count and timeout controls have distinct roles
{
	/* select.c's own bound (__fd_wait_or_delay(), src/select/select.c):
	 * up to FD_SETSIZE console-analog handles plus one signal-delivery
	 * eventfd. */
	struct pollfd pfds[FD_SETSIZE + 1];
	struct timespec ts, *tsp;
	int i, n = nhandles;
	long long ns;

	if (n > FD_SETSIZE + 1) n = FD_SETSIZE + 1;
	for (i = 0; i < n; i++) {
		pfds[i].fd = unbox(handles[i]);
		/* select.c hands this a mix of console-analog read-wait
		 * descriptors and the signal-delivery eventfd -- both cases
		 * only ever care about readability, matching NtWaitForMultiple
		 * Objects(WaitAny) waiting for any ONE of them to become
		 * signalled (readable, here) at all. */
		pfds[i].events = POLLIN;
		pfds[i].revents = 0;
	}
	if (infinite) {
		tsp = 0;
	} else {
		ns = ticks_to_ns(wait_ticks);
		ts.tv_sec = (long)(ns / 1000000000LL);
		ts.tv_nsec = (long)(ns % 1000000000LL);
		tsp = &ts;
	}
	syscall(SYS_ppoll, pfds, (long)n, tsp, 0L, 0L);
	/* No return value needed either way -- see plat_select.h's own
	 * comment: neither select() nor poll() distinguishes "woke because
	 * something signalled" from "woke because the budget ran out". */
}

void __plat_delay(long long wait_ticks, int infinite) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; duration and infinite flag have distinct roles
{
	struct timespec ts;

	if (infinite) {
		/* nanosleep(2) has no NULL-means-forever convention either;
		 * NT's own idiom here (an absolute deadline far in the future,
		 * src/select/nt/plat_select.c's own comment) becomes, on
		 * Linux, simply the largest representable relative sleep --
		 * good for effectively forever on any real workload, and
		 * revisited the same way a truly indefinite wait always is
		 * elsewhere in this library (see pause(), src/unistd/sleep.c). */
		ts.tv_sec = 0x7fffffffL;
		ts.tv_nsec = 0;
	} else {
		long long ns = ticks_to_ns(wait_ticks);
		ts.tv_sec = (long)(ns / 1000000000LL);
		ts.tv_nsec = (long)(ns % 1000000000LL);
	}
	syscall(SYS_nanosleep, &ts, 0L);
}

long long __plat_now_100ns(void)
{
	struct timespec ts;
	/* CLOCK_MONOTONIC (1), not CLOCK_REALTIME (0): every caller of this
	 * (select_core()'s elapsed-time accounting across a wait,
	 * src/select/select.c) uses it purely for a same-process interval
	 * measurement, never for a wall-clock value -- a strictly better
	 * choice than the NT backend's NtQuerySystemTime (wall-clock,
	 * plat_select.h's own comment says only that it matches
	 * clock_gettime(CLOCK_REALTIME)'s clock, not that CLOCK_REALTIME is
	 * required), immune to a concurrent wall-clock step or NTP
	 * adjustment corrupting a *remaining budget mid-wait. Documented
	 * here as a deliberate, safe improvement, not a silent behavior
	 * change: the 100ns-tick UNIT this returns is unchanged, only which
	 * clock backs it. */
	syscall(SYS_clock_gettime, 1L /* CLOCK_MONOTONIC */, &ts);
	return (long long)ts.tv_sec * 10000000LL + (long long)ts.tv_nsec / 100LL;
}

// NOLINTEND(misc-include-cleaner)
