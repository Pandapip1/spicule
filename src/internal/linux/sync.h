/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * struct spicule_linux_sync, promoted out of src/thread/linux/
 * plat_thread.c (where it started as a private, file-scoped type) so
 * that other Linux backends -- named semaphores and stop-events
 * (src/thread/linux/plat_thread.c's own __plat_named_semaphore_*(),
 * src/signal/linux/plat_signal.c's __plat_stop_event_*()) -- can build
 * objects the SAME generic __plat_wait_one()/__plat_event_set()/
 * __plat_semaphore_post() already understand, rather than inventing a
 * second, parallel synchronization primitive. Every field and its
 * meaning is exactly what plat_thread.c's own banner already
 * documents: `futex` is the wait/wake word (a semaphore's count, or an
 * event's zero/nonzero flag), `max` is a semaphore's ceiling (unused
 * for an event), `kind` distinguishes the two so __plat_wait_one() can
 * tell a decrementing P/V wait from a manual-reset non-consuming one.
 *
 * SPICULE_LX_SYNC_INITIALIZING: a third, transient `kind` value used
 * ONLY by __plat_named_mutant_acquire() (plat_thread.c) to make its
 * first-touch lazy initialization of a freshly created (or not-yet-
 * initialized) MAP_SHARED backing file race-free across processes --
 * see that function's own comment for the real, confirmed bug this
 * closes (two processes racing a brand-new mutant file could both
 * observe kind==0 and both plainly, non-atomically write max/futex/
 * kind, and if one write landed after the other had already
 * decremented futex via a real acquire, it silently stomped the count
 * back up, letting both processes believe they held the same supposedly
 * exclusive lock at once). Never a value __plat_wait_one()/
 * __plat_event_set()/__plat_semaphore_post() need to understand: by the
 * time any of those see the object, kind has always already settled to
 * SEMAPHORE or EVENT. */
#ifndef _SPICULE_LINUX_SYNC_H
#define _SPICULE_LINUX_SYNC_H

enum { SPICULE_LX_SYNC_SEMAPHORE = 1, SPICULE_LX_SYNC_EVENT = 2,
       SPICULE_LX_SYNC_INITIALIZING = 3 };

struct spicule_linux_sync {
	int futex;
	int max;
	unsigned char kind;
};

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
