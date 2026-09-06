/* SPDX-FileCopyrightText: (C) 2026 Gavin John */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "../../include/ownership.h"

requires_thread_token(errno_grounds)
int *__errno_location(void);
#define errno (*__errno_location())

int __set_errno_status(int st);
grants_thread_token(errno_grounds)
int close(int fd);
int harmless(void);

/* The read matches the call the code just checked. */
int diagnosed_read(int fd) {
	if (close(fd) < 0) {
		if (errno == 9)
			return -1;
	}
	return 0;
}

/* Copying the diagnosed call's errno into a local is still a read of
 * that same call's errno, not a stale one. */
int copied_out(int fd) {
	if (close(fd) < 0) {
		int saved = errno;
		return saved;
	}
	return 0;
}

/* An unrelated, non-capable call between the diagnosed call and the
 * read does not invalidate the read. */
int survives_unrelated_call(int fd) {
	if (close(fd) < 0) {
		harmless();
		if (errno == 9)
			return -1;
	}
	return 0;
}

/* A direct assignment is its own trusted origin. */
int reset_then_read(void) {
	errno = 0;
	if (errno == 0)
		return 0;
	return -1;
}

/* A capable call happened but its result was never compared for
 * failure: neither of this checker's two proof obligations applies. */
int uncompared_call(int fd) {
	close(fd);
	if (errno == 9)
		return -1;
	return 0;
}

void *malloc(unsigned long);
void free(void *);

/* src/process/spawn_file_actions.c's fa_push() shape: save errno before
 * an unrelated operation that might clobber it (malloc, here), restore
 * it on every exit.  The save itself needs no prior capable call --
 * whatever errno currently holds is being preserved opaquely, not
 * interpreted. */
int save_restore_around_cleanup(void) {
	int e = errno;
	void *p = malloc(8);
	if (!p) {
		errno = e;
		return -1;
	}
	free(p);
	errno = e;
	return 0;
}

/* src/ftw/ftw.c's report() shape: save errno, call something this
 * checker cannot see into (an indirect call, here), and ask only
 * whether errno *changed* from the saved value -- never asserting what
 * any specific call set it to. */
int compare_to_saved_after_unknown_call(int (*fn)(void)) {
	int saved_errno = errno;
	int r = fn();
	if (r == -1 && errno == saved_errno)
		errno = 5;
	return r;
}

void *fopen(const char *path, const char *mode);

/* `if (!fopen(...))` is the idiomatic C null-check for a pointer-
 * returning capable call; it must diagnose that call's failure exactly
 * as `== 0`/`== NULL` already does, not just an explicit comparison. */
int diagnosed_read_pointer_null_check(const char *path) {
	void *f = fopen(path, "r");
	if (!f) {
		if (errno == 9)
			return -1;
	}
	return 0;
}

/* A redundant double-check of the same already-diagnosed call: diagnosing
 * close(fd)'s failure twice in a row must not itself be a violation. This
 * is the fixture the shared thread-scoped errno_grounds fact was checked
 * against before landing it: a Consume-based encoding of "has this call
 * been diagnosed" would report the *second* comparison here (consuming an
 * already-absent fact), which today's checker never does -- it only ever
 * reports at the read site, never at the diagnosing comparison itself.
 * errno_grounds sidesteps this entirely: it is granted Duplicable (an
 * idempotent "some origin exists" fact, never consumed), and the
 * Diagnosed-vs-LastCapable identity comparison this function actually
 * needs stays on CallSlot's own Stmt* identity, unchanged. */
int redundant_double_check(int fd) {
	if (close(fd) < 0) {
		if (errno == 9)
			return -1;
		if (errno == 9)
			return -2;
	}
	return 0;
}

int __set_errno_status(int st);
int open(const char *path, int flags, int mode);

/* src/thread/semaphore.c's sem_open() shape: a comparison earlier in
 * the function diagnosed a *different* capable call (open, here), then
 * this expression calls a second capable call purely for its errno side
 * effect and reads errno back in the very same expression via the comma
 * operator.  Nothing can run between that call and this read, so the
 * fact that some *other*, earlier call is still "under diagnosis" does
 * not matter. */
int comma_after_second_capable_call(const char *path, int mode, long st) {
	int fd = open(path, 0, mode), saved;
	if (fd >= 0) {
		saved = (__set_errno_status((int)st), errno);
		return saved;
	}
	return -1;
}

/* src/process/posix_spawn.c's do_action() shape: same root cause as
 * comma_after_second_capable_call above -- a stale Diagnosed slot left
 * over from a different switch case / call site -- but as two plain
 * statements rather than a comma expression.  `return errno;` hands the
 * value back opaquely immediately after the only call that could have
 * set it in this block, with nothing able to run in between. */
int immediate_return_after_second_capable_call(const char *path, long st) {
	int t = open(path, 0, 0);
	if (t < 0) return errno;
	if (st < 0) {
		__set_errno_status((int)st);
		return errno;
	}
	return 0;
}
