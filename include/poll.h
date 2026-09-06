/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * poll(): implemented in src/select/poll.c, sharing its readiness probe
 * and wait-or-sleep primitive with select()/pselect() (see
 * src/select/select.c for the full design writeup).
 */
#ifndef _POLL_H
#define _POLL_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <ownership.h>

typedef unsigned long nfds_t;

struct pollfd {
	int fd;
	short events;
	short revents;
};

/* poll.html DESCRIPTION event/revent bits. Numeric values match musl's
 * (and thus glibc's) so a raw int mask written by one is meaningful to
 * the other -- nothing in POSIX assigns these bit positions, but there
 * is no reason to pick different ones. */
#define POLLIN     0x001
#define POLLPRI    0x002
#define POLLOUT    0x004
#define POLLERR    0x008
#define POLLHUP    0x010
#define POLLNVAL   0x020
#define POLLRDNORM 0x040
#define POLLRDBAND 0x080
#ifndef POLLWRNORM
#define POLLWRNORM 0x100
#endif
#ifndef POLLWRBAND
#define POLLWRBAND 0x200
#endif

async_signal_safe
io_operation
int poll (struct pollfd *, nfds_t, int);

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
