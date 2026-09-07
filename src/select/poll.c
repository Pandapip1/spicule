/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * poll(): https://pubs.opengroup.org/onlinepubs/9699919799/functions/
 * poll.html.  Shares select.c's per-descriptor readiness probe
 * (__fd_probe()) and wait/sleep primitive (__fd_wait_or_delay()) --
 * see that file's banner for the wait-vs-poll design and 20ms
 * pipe-poll interval. The outer loop is not shared with select's: it
 * walks a caller-supplied pollfd array rather than an fd_set bit
 * range, different enough to not be worth unifying.
 *
 * revents: POLLIN/POLLRDNORM and POLLOUT/POLLWRNORM mirror
 * __fd_probe()'s readable/writable; POLLPRI/POLLRDBAND/POLLWRBAND have
 * no analogue on any descriptor shape here and are never set (POSIX
 * only requires reporting conditions that exist). POLLHUP mirrors
 * __fd_probe()'s *hup (peer gone, or a failed socket probe ioctl,
 * which it deliberately treats as ready-and-hung-up). POLLERR is
 * never set: none of these shapes can report a device error without
 * first surfacing EOF/broken via read()/write() itself. POLLNVAL
 * marks an fd that is not open and counts toward the return value; a
 * negative fd is left at revents==0 and does not count, since
 * DESCRIPTION says such an entry is ignored outright.
 *
 * `timeout` (milliseconds) follows select.c's null/zero timeval
 * distinction one level down: -1 blocks indefinitely, 0 polls without
 * blocking, a positive value bounds the wait and is converted to the
 * same 100ns tick unit select.c's core uses.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <poll.h>
#include <errno.h>
#include "libc.h"
#include "plat_select.h"

#define POLL_INTERVAL_TICKS 200000LL  /* 20ms; see select.c's file banner */

/* pfds is deliberately not nonnull: every dereference is inside the
 * `i < nfds` loop, so poll(NULL, 0, timeout) -- the portable "sleep"
 * idiom -- already works and must not be foreclosed. */
int poll(struct pollfd *pfds, nfds_t nfds, int timeout) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	long long remaining;
	int infinite, total;

	infinite = timeout < 0;
	remaining = infinite ? 0 : (long long)timeout * 10000LL;  /* ms -> 100ns ticks */

	for (;;) {
		__plat_handle_t console_h[FD_MAX];
		int console_idx[FD_MAX];
		int ncons = 0, have_poll = 0;
		nfds_t i;

		total = 0;
		for (i = 0; i < nfds; i++) {
			struct pollfd *p = &pfds[i];
			struct __fd *f;
			int cr, cw, hup;

			p->revents = 0;
			if (p->fd < 0) continue;  /* DESCRIPTION: ignored outright */

			f = __fd_get(p->fd);
			if (!f) { p->revents = POLLNVAL; total++; continue; }

			if (f->type == __FD_PIPE || f->type == __FD_SOCKET) {
				/* No waitable NT object behind either, so both
				 * are re-probed on the POLL_INTERVAL_TICKS timer. */
				have_poll = 1;
				__fd_probe(f, &cr, &cw, &hup);
				if (hup) p->revents = (short)(p->revents | POLLHUP);
				if (cr) p->revents = (short)(p->revents | (p->events & (POLLIN | POLLRDNORM)));
				if (cw && !hup) p->revents = (short)(p->revents | (p->events & (POLLOUT | POLLWRNORM)));
			} else if (f->type == __FD_CONSOLE) {
				p->revents = (short)(p->revents | (p->events & (POLLOUT | POLLWRNORM)));  /* output: always ready */
				if ((p->events & (POLLIN | POLLRDNORM)) && ncons < FD_MAX) {
					console_h[ncons] = f->h;
					console_idx[ncons] = (int)i;
					ncons++;
				}
			} else {
				/* __FD_FILE/__FD_DIR/__FD_CHAR/__FD_UNKNOWN:
				 * always ready, same as select(). */
				p->revents = (short)(p->revents | (p->events & (POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM)));
			}
			if (p->revents) total++;
		}

		/* Zero-timeout peek at every still-pending console read. */
		{
			int k;
			for (k = 0; k < ncons; k++) {
				if (__plat_console_ready(console_h[k])) {
					struct pollfd *p = &pfds[console_idx[k]];
					if (!p->revents) total++;
					p->revents = (short)(p->revents | (p->events & (POLLIN | POLLRDNORM)));
				}
			}
		}

		if (total > 0) break;
		if (!infinite && remaining == 0) break;  /* timeout == 0: poll, nothing ready */

		{
			long long wait_ticks;
			int wait_infinite;

			if (infinite) {
				wait_infinite = !have_poll;
				wait_ticks = have_poll ? POLL_INTERVAL_TICKS : 0;
			} else {
				wait_infinite = 0;
				wait_ticks = have_poll && remaining > POLL_INTERVAL_TICKS ? POLL_INTERVAL_TICKS : remaining;
			}
			__fd_wait_or_delay(console_h, ncons, wait_ticks, wait_infinite);
			if (!infinite) remaining -= wait_ticks;
		}
	}

	return total;
}

// NOLINTEND(misc-include-cleaner)
