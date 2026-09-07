/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * mesg(1p): "mesg [y|n]" -- controls whether other users are allowed
 * to send messages, via write(1p) or similar, to a terminal device.
 * Bare `mesg` queries the current state without changing it.
 *
 * This library tracks only one real user identity (src/misc/pwd.c),
 * but mesg's traditional mechanism -- toggling the group-write bit on
 * a tty device node -- still has real, honest meaning: the bit is
 * real, chmod() genuinely reads and writes it, and a future
 * multi-session extension would see and honor the same bit unchanged.
 *
 * Per platform (see src/util/termident.h for the full argument):
 *   Linux: __util_find_terminal() resolves the calling terminal to a
 *   real device-node path; chmod() on it is a real syscall, and
 *   S_IWGRP genuinely gates whether another process can open the tty
 *   for writing.
 *   NT: a console is a real terminal but has no filesystem path to
 *   chmod() -- fchmodat() returns EROFS on it and fchmod() is a silent
 *   no-op, so no mechanism here gates writes to it. `mesg` and
 *   `mesg y` honestly report/confirm the only state that has ever been
 *   true (messages are never blocked); `mesg n` asks for enforcement
 *   this library cannot provide and is refused loudly rather than
 *   silently under-honored (same reasoning as src/misc/resource.c's
 *   setrlimit()).
 *
 * EXIT STATUS (mesg(1p)): 0 = receiving messages is allowed, 1 = not
 * allowed, >1 = an error occurred -- this is the resulting *state*,
 * not a plain success/failure code, so `mesg n`'s own successful exit
 * status is 1, not 0.
 */
#include "util.h"
#include "termident.h"
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

int __util_mesg_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	struct term_ident t;
	struct stat st;
	mode_t nm;
	int fd;

	if (argc > 2 || (argc == 2 && strcmp(argv[1], "y") != 0 && strcmp(argv[1], "n") != 0)) {
		__util_diagf("mesg: usage: mesg [y|n]\n");
		return 2;
	}

	fd = __util_find_terminal(&t);
	if (fd < 0) {
		__util_diagf("mesg: not a terminal\n");
		return 2;
	}

	if (argc == 1) {
		if (t.opaque) { printf("is y\n"); return 0; }
		if (stat(t.path, &st) != 0) {
			__util_diagf("mesg: %s: %s\n", t.path, strerror(errno));
			return 2;
		}
		if (st.st_mode & S_IWGRP) { printf("is y\n"); return 0; }
		printf("is n\n");
		return 1;
	}

	if (strcmp(argv[1], "y") == 0) {
		if (t.opaque) return 0; /* already, and always, true -- see header comment */
		/* fstat()/fchmod() on `fd` itself, not stat()/chmod() on
		 * t.path: guarantees the mode bits read and written below are
		 * the same object's, never a path re-resolved to something
		 * else in between. */
		if (fstat(fd, &st) != 0) {
			__util_diagf("mesg: %s: %s\n", t.path, strerror(errno));
			return 2;
		}
		nm = st.st_mode | S_IWGRP;
		if (fchmod(fd, nm) != 0) {
			__util_diagf("mesg: %s: %s\n", t.path, strerror(errno));
			return 2;
		}
		return 0;
	}

	/* argv[1] == "n" */
	if (t.opaque) {
		__util_diagf("mesg: cannot deny messages on this console: "
			"no permission mechanism reaches an NT console handle "
			"(see src/util/mesg.c's own header comment)\n");
		return 2;
	}
	if (fstat(fd, &st) != 0) {
		__util_diagf("mesg: %s: %s\n", t.path, strerror(errno));
		return 2;
	}
	nm = st.st_mode & ~(mode_t)S_IWGRP;
	if (fchmod(fd, nm) != 0) {
		__util_diagf("mesg: %s: %s\n", t.path, strerror(errno));
		return 2;
	}
	return 1;
}
