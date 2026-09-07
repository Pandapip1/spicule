/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * select()/pselect(): https://pubs.opengroup.org/onlinepubs/9699919799/
 * functions/select.html and .../pselect.html.
 *
 * NT has no single primitive that waits on this library's descriptor
 * shapes the way select() wants to:
 *   - __FD_CONSOLE: an input handle really is a waitable NT object, so
 *     it is waited on directly; output is always ready (writes never
 *     block). Both the peek and the wait go through
 *     __plat_console_ready()/__plat_console_wait() rather than touching
 *     the handle, since a console this library runs the line discipline
 *     for (src/internal/nt/conin.c) answers from that thread's queue
 *     instead.
 *   - __FD_PIPE: the handle is not signalled on data arrival/drain, so
 *     it is polled via NtQueryInformationFile(FilePipeLocalInformation)'s
 *     ReadDataAvailable/WriteQuotaAvailable. wine-9.0 and older hardcode
 *     WriteQuotaAvailable to 0 for every pipe, so wqa_works() below
 *     confirms (via a private pipe) that the field is populated on this
 *     platform before trusting it; otherwise writable defaults to
 *     always-ready.
 *   - __FD_SOCKET: also not signalled, so it is polled by one
 *     zero-timeout IOCTL_AFD_SELECT per pass (__fd_probe() below), but
 *     unlike a pipe gives an honest answer for both directions.
 *   - __FD_FILE/__FD_DIR/__FD_CHAR/__FD_UNKNOWN: always ready, per
 *     select.html DESCRIPTION for regular files, extended here since
 *     nothing in this library ever blocks a read/write to these shapes
 *     past the syscall itself.
 *
 * Each pass probes everything non-blockingly first (__fd_probe(), plus
 * a zero-timeout wait peek per pending console read) and returns
 * immediately if anything is ready. Otherwise it sleeps: if only
 * console reads are outstanding, NtWaitForMultipleObjects waits the
 * full remaining timeout and wakes instantly on input; if a pipe or
 * socket is pending (no waitable object behind either), the sleep is
 * capped at POLL_INTERVAL_TICKS (20ms) and re-probed on that timer --
 * chosen to bound pipe-readiness latency and CPU cost without a
 * busy-loop.
 *
 * Per select.html DESCRIPTION: a NULL timeout blocks indefinitely, a
 * zero timeval polls once without waiting, and a negative/out-of-range
 * timeval/timespec is EINVAL. The timeout object is never written back
 * (POSIX permits but does not require it, matching this library's other
 * timeout-taking calls). The descriptor sets are never modified
 * in-place: a snapshot is taken up front, fresh output sets are built
 * each pass, and only the final result -- including on timeout, when
 * it is all-clear -- is copied back into the caller's sets. exceptfds
 * is always cleared: none of this platform's descriptor shapes has an
 * honest exceptional-condition signal.
 *
 * EINTR (select.html ERRORS) is returned only when a signal is
 * actually CAUGHT during the wait (a real handler runs), tracked by
 * comparing src/signal/signal.c's __sig_caught_count() across the wait
 * -- not merely pending. SA_RESTART does not suppress this; POSIX
 * leaves the interaction implementation-defined and this matches Linux
 * (EINTR always). A signal arriving blocked just sets `pending` and
 * does not interrupt the wait.
 *
 * pselect()'s sigmask is installed/restored atomically around the wait
 * via the same sigprocmask() path used elsewhere. One known race
 * remains: sigprocmask()'s drain of newly-unblocked pending signals
 * happens strictly before select_core() captures its "caught so far"
 * baseline, so a cross-process signal delivered in that narrow window
 * runs its handler correctly but is not reported as EINTR here. Left
 * open rather than silently assumed fixed.
 *
 * select() and poll() (src/select/poll.c) share __fd_probe() and
 * __fd_wait_or_delay() (declared in src/internal/libc.h) but not one
 * outer loop: select's fd_set bit range and poll's pollfd array are
 * different enough shapes that unifying them would cost more code than
 * it saves.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/select.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include "libc.h"
#include "plat_select.h"

/* 20ms, in 100ns units (see file banner for why). */
#define POLL_INTERVAL_TICKS 200000LL

/* Is FILE_PIPE_LOCAL_INFORMATION's WriteQuotaAvailable populated on this
 * platform? A 0 there is ambiguous: "completely full" on an
 * implementation that populates it, or just the field's permanent
 * value on one that doesn't (wine-9.0 and older, hardcoded to 0 for
 * every pipe until fixed in wine-10.0) -- reading the latter as "full"
 * would report every empty pipe unwritable forever.
 *
 * Discriminated with a positive control, cached per process: a private
 * pipe, written to nothing, must report a non-zero quota if the field
 * is populated at all; anything else falls back to always-writable.
 * The probe queries a CLIENT-end handle (src/unistd/pipe.c makes the
 * write end the client end), matching what __fd_probe() will ask about.
 *
 * Returns 1 if the field is usable, 0 if not. */
static int wqa_works(void)
{
	/* -1 = not yet asked.  A benign race here would only repeat the
	 * probe and reach the same answer; this library is single-threaded
	 * regardless (see the banner in src/internal/libc.h). */
	static int cached = -1;

	if (cached < 0) cached = __plat_pipe_wqa_trustworthy();
	return cached;
}

/* See src/internal/libc.h for the contract. */
void __fd_probe(struct __fd *f, int *canread, int *canwrite, int *hup)
{
	*hup = 0;
	switch (f->type) {
	case __FD_PIPE: {
		unsigned long read_avail, write_quota;
		if (!__plat_pipe_probe(f->h, &read_avail, &write_quota)) {
			/* Broken/disconnected: read() would EOF/error and write()
			 * would fail, neither blocking, so both count as ready
			 * (like Linux's hung-up descriptor). Checked ahead of the
			 * WriteQuotaAvailable consult below deliberately: NT does
			 * not reduce a pipe's buffered-bytes count past a peer
			 * disconnect (measured on Server 2025, a still-buffered
			 * pipe reports its full quota free once the reader
			 * closes), so that field alone would wrongly read as room
			 * available. */
			*canread = 1; *canwrite = 1; *hup = 1;
			break;
		}
		*canread = read_avail > 0;
		/* On real NT, WriteQuotaAvailable is write-direction quota
		 * minus bytes currently buffered (measured on Server 2025
		 * build 26100), so it is trustworthy once wqa_works() has
		 * confirmed this platform populates it. This library only
		 * ever creates byte-stream pipes with a 65536 quota
		 * (src/unistd/pipe.c); an inherited message-mode pipe charges
		 * the same per data byte with no per-message overhead
		 * (measured), and an inherited zero-quota pipe reads 0 and is
		 * reported not-writable, the conservative answer for a buffer
		 * that can never accept an unread byte. */
		*canwrite = wqa_works() ? write_quota > 0 : 1;
		break;
	}
	case __FD_CONSOLE:
		/* Read side is resolved by the caller's own console peek and
		 * wait (__plat_console_ready()/__plat_console_wait()), not
		 * here. Output is always ready: writes never block. */
		*canread = 0;
		*canwrite = 1;
		break;
	case __FD_SOCKET:
		/* One non-blocking, zero-timeout IOCTL_AFD_SELECT (==
		 * Wine's IOCTL_AFD_POLL). Close/abort/disconnect counts as
		 * both readable, writable and hup, same as a broken pipe
		 * above. */
		__plat_socket_probe(f->h, canread, canwrite, hup);
		break;
	case __FD_FILE:
	case __FD_DIR:
	case __FD_CHAR:
	case __FD_UNKNOWN:
	default:
		/* select.html DESCRIPTION: regular files always select
		 * ready; extended to __FD_CHAR since nothing here ever
		 * blocks past the syscall itself. __FD_UNKNOWN (a handle
		 * __handle_type() could not classify) gets the same answer
		 * since there is no probe that could apply to it. */
		*canread = 1;
		*canwrite = 1;
		break;
	}
}

/* See src/internal/libc.h for the contract.
 *
 * Also waits on src/signal/sigdelivery.c's per-process "a packet
 * arrived" event when this process has one -- the mechanism behind
 * select()/pselect()'s EINTR path: without it, a cross-process signal
 * would not be noticed until the wait next woke up on its own, up to
 * POLL_INTERVAL_TICKS or the full timeout later (or never, for an
 * infinite console-and-pipe-free wait). Folding it into the same
 * NtWaitForMultipleObjects call costs nothing when unsignalled. */
void __fd_wait_or_delay(__plat_handle_t *console_handles, int ncons, long long wait_ticks, int infinite) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	__plat_handle_t handles[FD_SETSIZE + 1];
	__plat_handle_t sigev = __sig_delivery_event();
	int n = 0, i;

	/* console_handles[] holds the descriptors' own handles; what is
	 * actually waitable for a console read may be something else
	 * entirely once this library runs that console's line discipline
	 * (plat_select.h's __plat_console_wait()). */
	for (i = 0; i < ncons; i++) handles[n++] = __plat_console_wait(console_handles[i]);
	if (sigev) handles[n++] = sigev;

	if (n > 0) {
		__plat_wait_multiple(handles, n, wait_ticks, infinite);
		return;
	}
	__plat_delay(wait_ticks, infinite);
}

/* One poll pass: build fresh output sets from the (unchanging) snapshot
 * *in_r, *in_w and *in_e, probing every requested descriptor without
 * blocking. Console reads still pending after a zero-timeout peek are
 * left in console_h/console_fd for the caller to wait on. *have_poll
 * is set when a requested pipe or socket is still outstanding -- since
 * neither has a waitable NT object, the caller must cap its sleep at
 * POLL_INTERVAL_TICKS rather than wait the full timeout. */
/* in_r/in_w/in_e are deliberately not nonnull: rfds/wfds/efds are
 * genuinely optional per POSIX, and each is only touched behind its
 * own `in_r &&` guard. console_h/console_fd aren't required either,
 * since they are only written/read within a loop bounded by `n`,
 * which may be 0. */
static int poll_pass(int nfds, const fd_set *in_r, const fd_set *in_w, const fd_set *in_e,
                      fd_set *out_r, fd_set *out_w, int *have_poll,
                      __plat_handle_t *console_h, int *console_fd, int *ncons)
    __attribute__((nonnull(5, 6, 7, 10)));
static int poll_pass(int nfds, const fd_set *in_r, const fd_set *in_w, const fd_set *in_e,
                      fd_set *out_r, fd_set *out_w, int *have_poll,
                      __plat_handle_t *console_h, int *console_fd, int *ncons) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int d, total = 0, n = 0, hp = 0;

	FD_ZERO(out_r);
	FD_ZERO(out_w);
	for (d = 0; d < nfds; d++) {
		int wantr = in_r && FD_ISSET(d, in_r);
		int wantw = in_w && FD_ISSET(d, in_w);
		int wante = in_e && FD_ISSET(d, in_e);
		struct __fd *f;
		int cr, cw, hup;

		if (!wantr && !wantw && !wante) continue;
		f = __fd_get(d);  /* already known open: validated before the loop */

		if (f->type == __FD_PIPE || f->type == __FD_SOCKET) {
			/* Neither has a waitable NT object, so both must be
			 * re-probed on a timer -- hence hp. */
			if (wantr || wantw) hp = 1;
			__fd_probe(f, &cr, &cw, &hup);
			if (wantr && cr) { FD_SET(d, out_r); total++; }
			if (wantw && cw) { FD_SET(d, out_w); total++; }
		} else if (f->type == __FD_CONSOLE) {
			if (wantw) { FD_SET(d, out_w); total++; }
			if (wantr) { console_h[n] = f->h; console_fd[n] = d; n++; }
		} else {
			/* __FD_FILE/__FD_DIR/__FD_CHAR/__FD_UNKNOWN: always
			 * ready (see __fd_probe()'s default case). */
			if (wantr) { FD_SET(d, out_r); total++; }
			if (wantw) { FD_SET(d, out_w); total++; }
		}
	}

	/* Zero-timeout peek at every still-pending console read: cheap,
	 * and lets a console that was already signalled before this call
	 * be reported ready without ever sleeping. */
	{
		int i;
		for (i = 0; i < n; i++)
			if (__plat_console_ready(console_h[i])) {
				FD_SET(console_fd[i], out_r);
				total++;
			}
	}

	*have_poll = hp;
	*ncons = n;
	return total;
}

/* The shared core: nfds/timeout range validation is the caller's job;
 * EBADF is checked here, once, before the first poll pass. *remaining
 * is the timeout budget in 100ns ticks, ignored when infinite is set. */
static int select_core(int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds, long long *remaining, int infinite)
{
	fd_set in_r, in_w, in_e, out_r, out_w;
	__plat_handle_t console_h[FD_SETSIZE];
	int console_fd[FD_SETSIZE];
	int d, total, have_poll, ncons;
	/* __sig_caught_count() only advances when a signal-catching
	 * function actually runs, never for SIG_IGN or a still-pending
	 * blocked signal -- see file banner's EINTR note. */
	unsigned long sig_start = __sig_caught_count();

	FD_ZERO(&in_r); FD_ZERO(&in_w); FD_ZERO(&in_e);
	if (rfds) in_r = *rfds;
	if (wfds) in_w = *wfds;
	if (efds) in_e = *efds;

	for (d = 0; d < nfds; d++) {
		if ((rfds && FD_ISSET(d, &in_r)) || (wfds && FD_ISSET(d, &in_w)) || (efds && FD_ISSET(d, &in_e))) {
			if (!__fd_get(d)) return -1;  /* EBADF: not a valid open descriptor */
		}
	}

	for (;;) {
		__sig_drain_pending();
		if (__sig_caught_count() != sig_start) { errno = EINTR; return -1; }
		total = poll_pass(nfds, rfds ? &in_r : 0, wfds ? &in_w : 0, efds ? &in_e : 0,
		                   &out_r, &out_w, &have_poll, console_h, console_fd, &ncons);
		if (total > 0) break;
		if (!infinite && *remaining == 0) break;  /* "to effect a poll": return promptly, nothing ready */

		{
			long long wait_ticks;
			int wait_infinite;
			long long before, after;

			if (infinite) {
				wait_infinite = !have_poll;
				wait_ticks = have_poll ? POLL_INTERVAL_TICKS : 0;
			} else {
				wait_infinite = 0;
				wait_ticks = have_poll && *remaining > POLL_INTERVAL_TICKS ? POLL_INTERVAL_TICKS : *remaining;
			}
			/* Real elapsed time, not wait_ticks: __fd_wait_or_delay()
			 * can return early, woken by sigdelivery.c's wake_event
			 * for a blocked/ignored signal. Charging the full
			 * wait_ticks regardless would let a spurious wakeup
			 * exhaust the whole timeout budget in one step. */
			if (!infinite) before = __plat_now_100ns();
			__fd_wait_or_delay(console_h, ncons, wait_ticks, wait_infinite);
			if (!infinite) {
				long long elapsed;
				after = __plat_now_100ns();
				elapsed = after - before;
				if (elapsed < 0) elapsed = 0;
				if (elapsed > *remaining) elapsed = *remaining;
				*remaining -= elapsed;
			}
		}

		/* __fd_wait_or_delay() also waits on sigdelivery.c's
		 * wake_event, so a cross-process signal wakes this promptly.
		 * The empty lock/unlock rendezvous with the publishing
		 * thread before the drain runs any eligible handler here. */
		__sig_lock();
		__sig_unlock();
		__sig_drain_pending();
		if (__sig_caught_count() != sig_start) { errno = EINTR; return -1; }
	}

	if (rfds) *rfds = out_r;
	if (wfds) *wfds = out_w;
	if (efds) FD_ZERO(efds);
	return total;
}

int select(int nfds, fd_set *__restrict rfds, fd_set *__restrict wfds, fd_set *__restrict efds, struct timeval *__restrict timeout)
{
	long long remaining;
	int infinite;

	if (nfds < 0 || nfds > FD_SETSIZE) { errno = EINVAL; return -1; }
	if (timeout) {
		if (timeout->tv_sec < 0 || timeout->tv_usec < 0 || timeout->tv_usec >= 1000000) { errno = EINVAL; return -1; }
		remaining = __duration_ticks(timeout->tv_sec,
			(long)timeout->tv_usec * 1000L);
		infinite = 0;
	} else {
		remaining = 0;
		infinite = 1;
	}
	return select_core(nfds, rfds, wfds, efds, &remaining, infinite);
}

int pselect(int nfds, fd_set *__restrict rfds, fd_set *__restrict wfds, fd_set *__restrict efds,
            const struct timespec *__restrict timeout, const sigset_t *__restrict sigmask)
{
	long long remaining;
	int infinite, r;
	sigset_t omask;

	if (nfds < 0 || nfds > FD_SETSIZE) { errno = EINVAL; return -1; }
	if (timeout) {
		if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 || timeout->tv_nsec >= 1000000000L) { errno = EINVAL; return -1; }
		remaining = __duration_ticks(timeout->tv_sec, timeout->tv_nsec);
		infinite = 0;
	} else {
		remaining = 0;
		infinite = 1;
	}

	if (sigmask) sigprocmask(SIG_SETMASK, sigmask, &omask);
	r = select_core(nfds, rfds, wfds, efds, &remaining, infinite);
	if (sigmask) sigprocmask(SIG_SETMASK, &omask, 0);
	return r;
}

// NOLINTEND(misc-include-cleaner)
