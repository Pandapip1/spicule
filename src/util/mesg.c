/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * mesg(1p): "mesg [y|n]" -- controls whether other users are allowed
 * to send messages, via write(1p) or similar, to a terminal device.
 * Bare `mesg` queries the current state without changing it.
 *
 * ---- what "other users" honestly means here --------------------------
 *
 * src/misc/pwd.c's own header comment already makes the load-bearing
 * argument this file inherits: ntlibc has exactly one real user
 * identity it can ever honestly report.  mesg's traditional mechanism
 * -- toggling the group-write bit on a tty device node so a *different*
 * real user's write(1p) can or cannot open it for writing -- still has
 * a real, honest meaning even with only one user, though: the bit is
 * real, this library's own chmod() genuinely reads and writes it (on
 * the one platform where it has anywhere real to live), and a future
 * multi-session extension would see and honour exactly the same bit
 * without this file changing at all.  This file does not fabricate a
 * second user to justify that; it implements the real, verifiable
 * mechanism honestly and lets its meaning follow from whatever else is
 * (or is not) on the system.
 *
 * ---- what is real, per platform, and why ------------------------------
 *
 * See src/util/termident.h's own banner for the full argument; the
 * short version:
 *
 *   Linux: __util_find_terminal() (termident.c) resolves the calling
 *   terminal to a real device-node path via fstat()+S_ISCHR() and
 *   readlink("/proc/self/fd/<fd>") -- procfs is the kernel's own,
 *   nothing ntlibc provides.  chmod() on that real path
 *   (src/stat/linux/plat_stat.c) is a real syscall: S_IWGRP genuinely
 *   gates whether a *different* real Linux process (any process, since
 *   this library tracks only one uid, but the OS-level permission bit
 *   itself does not know that) can open the tty for writing.  `mesg y`/
 *   `mesg n` here really do what mesg(1p) has always done.
 *
 *   NT: a console is a real, correctly-identified terminal
 *   (isatty()'s __FD_CONSOLE gate), but has no filesystem path this
 *   library can chmod() at all -- src/stat/chmod.c's fchmodat()
 *   returns EROFS off the synthetic /dev/console object, and
 *   fchmod() on it is a silent no-op.  There is, today, no NT
 *   mechanism this library reaches that gates whether another process
 *   can write to this console -- so nothing here is ever actually
 *   denying receipt of a message.  Per src/misc/resource.c's own
 *   setrlimit() precedent ("accepts a request only when it does not
 *   actually ask for stricter enforcement than the fixed value already
 *   in effect ... asking to genuinely lower it is rejected ... rather
 *   than silently accepted and then not honored"): `mesg` (query) and
 *   `mesg y` both honestly report/confirm the only state that has ever
 *   been true (messages are never blocked) and succeed; `mesg n` asks
 *   for an enforcement this library cannot provide and is refused
 *   loudly (a real, nonzero, diagnosed failure) rather than accepted
 *   and silently not honoured.
 *
 * EXIT STATUS (mesg(1p)): 0 "receiving messages is allowed", 1
 * "receiving messages is not allowed", >1 "an error occurred" -- note
 * this is the resulting *state*, not a plain success/failure code, so
 * `mesg n`'s own successful exit status is 1, not 0.
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
		if (t.opaque) return 0; /* already, and always, true -- see banner */
		/* fstat()/fchmod() on `fd` itself, not stat()/chmod() on the
		 * re-resolved t.path: fd is the exact tty device
		 * __util_find_terminal() already verified, so the mode bits
		 * read here and the ones written below are guaranteed to be
		 * the same object's, never a different device a path lookup
		 * happened to re-resolve to in between. */
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
