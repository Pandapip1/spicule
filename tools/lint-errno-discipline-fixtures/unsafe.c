/* SPDX-FileCopyrightText: (C) 2026 Gavin John */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "../../include/ownership.h"

requires_thread_token(errno_grounds)
int *__errno_location(void);
#define errno (*__errno_location())

int __set_errno_status(int st);
grants_thread_token(errno_grounds)
int close(int fd);

/* CERT ERR30-C: the cleanup call after the diagnosed failure clobbers
 * errno before it is read. */
int stale_after_cleanup(int fd) {
	if (close(fd) < 0) {
		__set_errno_status(5);
		if (errno == 9) /* errno-discipline-expect */
			return -1;
	}
	return 0;
}

/* No call or assignment on this path could have set errno; this trusts
 * leftover/uninitialized errno state from function entry. */
int unset_origin(void) {
	if (errno == 9) /* errno-discipline-expect */
		return -1;
	return 0;
}

/* Two independent capable calls: the second, undiagnosed close(fd2) runs
 * before the read below, even though the comparison diagnoses the first
 * call's (fd1's) own return value. A thread-scoped fact that only tracks
 * presence/absence per family -- with no per-call identity -- cannot tell
 * "the currently pending call was just diagnosed" apart from "some
 * unrelated, already-superseded call was diagnosed while a newer,
 * undiagnosed one is still pending": that is exactly why the
 * Diagnosed-vs-LastCapable identity check stays on CallSlot's own Stmt*
 * comparison rather than moving onto errno_grounds. This fixture is the
 * adversarial case that comparison exists to catch. */
int stale_diagnosis_of_superseded_call(int fd1, int fd2) {
	int r1 = close(fd1);
	int r2 = close(fd2);
	(void)r2;
	if (r1 < 0) {
		if (errno == 9) /* errno-discipline-expect */
			return -1;
	}
	return 0;
}
