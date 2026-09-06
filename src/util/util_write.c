/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Named util_write.c, not write.c: the same tcc-`ar` member-name
 * collision src/util/util_basename.c's header explains in full, this
 * time against src/unistd/write.c (the real write(2) syscall front
 * door) -- confirmed with `find src -name write.c` before choosing the
 * name, per src/internal/util.h's own instruction to check.  The
 * util_ prefix is the whole fix; the exported symbol is still
 * __util_write_main().
 *
 * write(1p): "write user [tty]" -- reads lines from standard input and
 * writes them to another user's terminal.
 *
 * ---- the reality check -------------------------------------------------
 *
 * Real write(1p) sends to a *different* logged-in user's terminal.
 * src/misc/pwd.c's header comment already establishes that ntlibc has
 * exactly one real user identity it can ever honestly report, and this
 * file does not invent a second one to pretend otherwise. What is real
 * and left standing once that is accepted:
 *
 *   - `user` must name the one real user this process actually is
 *     (getpwnam(user) -- src/misc/pwd.c -- succeeds only for that
 *     name).  Any other name is not "logged in" here, honestly,
 *     because there genuinely is no second account: write(1p)'s own
 *     EXIT STATUS ">0 ... user not logged on" is the real, specified
 *     answer for exactly this case, not a cop-out.
 *
 *   - The one real "session" this process can ever honestly claim is
 *     open is its own controlling terminal, resolved by
 *     __util_find_terminal() (src/util/termident.h/.c -- see that
 *     header's own banner for what is real, per platform, and why
 *     isatty() alone is not enough on Linux yet).  So `write
 *     $(whoami)` -- optionally with the matching tty operand -- writes
 *     the message straight into that same real terminal: a genuine,
 *     verifiable "write directly to the target tty device", not a
 *     fabrication, just degenerately with sender and recipient being
 *     the same real session.  Any *other* tty operand is, again
 *     honestly, not a session this process can find -- ">0 user not
 *     logged on" once more, per write.html's own ERRORS wording,
 *     rather than a silent, fake success.
 *
 *   - This is deliberately forward-compatible, not a permanent ceiling:
 *     if this tree later grows a real multi-session registry (a
 *     utmp-equivalent -- none exists anywhere in this tree today,
 *     confirmed via `git log --all --grep=utmp` and a full-tree
 *     `grep -ri utmp` before writing this file), the only change
 *     __util_write_main() would need is a second, wider search before
 *     falling back to "is this my own terminal" -- the core mechanism
 *     (resolve a real target tty, open it, write straight into it)
 *     does not change at all.  Building that registry is explicitly
 *     out of scope for this pass: the self-write case above is the
 *     only session this system can honestly claim exists today, and
 *     write(1p)'s own contract already specifies the correct behaviour
 *     (a real, diagnosed failure) for every other case.
 *
 * mesg(1p) (src/util/mesg.c) is deliberately NOT consulted for the
 * self-write case: mesg gates *other* users' ability to reach a
 * terminal, and the only real recipient here is this same session, so
 * there is no one for it to gate against.
 *
 * Interrupt handling (write.html: "an interrupt character shall cause
 * write to send... EOT... and exit") is out of scope here: this
 * function is a shared __util_write_main() called both as a standalone
 * process and as a shell builtin running in-process (src/internal/
 * util.h's own contract -- never exit()/_exit() from here, see
 * src/util/dd.c's header comment), so it does not install any signal
 * handler of its own either way; an interrupt during the read loop
 * below behaves the same way it would in any other blocking read here
 * (cat(1p) included), and EOF alone -- the common, real way to end an
 * interactive write session -- gets the real "EOT\n" trailer.
 */
#include "util.h"
#include "termident.h"
#include <pwd.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>

static int send_all(int fd, const char *buf, size_t len)
{
	size_t off = 0;
	ssize_t n;
	while (off < len) {
		n = write(fd, buf + off, len - off);
		if (n < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		/* write() returning 0 here (distinct from n < 0 above, already
		 * errno-set by write() itself) is not documented to touch
		 * errno at all; every caller of send_all() below trusts errno
		 * unconditionally after a -1 return, so this path needs its
		 * own explicit reason. */
		if (n == 0) { errno = EIO; return -1; }
		off += (size_t)n;
	}
	return 0;
}

int __util_write_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	const char *user, *ttyop;
	struct passwd *pw;
	struct term_ident t;
	int fd, wfd, opened_real, status = 0;
	time_t now;
	char *timestr;
	char tbuf[64];
	char banner[320];
	char line[2048];
	size_t tlen;

	if (argc < 2 || argc > 3) {
		__util_diagf("write: usage: write user [tty]\n");
		return 1;
	}
	user = argv[1];
	ttyop = argc == 3 ? argv[2] : 0;

	pw = getpwnam(user);
	if (!pw) {
		__util_diagf("write: %s is not logged in\n", user);
		return 1;
	}

	fd = __util_find_terminal(&t);
	if (fd < 0) {
		/* Honest either way: no terminal of ours to send from, and
		 * (per this file's own header comment) the only real
		 * recipient this system could ever name IS our own
		 * terminal -- so "not logged in" is the correct diagnosis
		 * for the recipient too, not just a sender-side problem. */
		__util_diagf("write: %s is not logged in\n", user);
		return 1;
	}

	if (ttyop && strcmp(ttyop, t.shortname) != 0) {
		__util_diagf("write: %s is not logged in on %s\n", user, ttyop);
		return 1;
	}

	if (!t.opaque) {
		wfd = open(t.path, O_WRONLY);
		if (wfd < 0) {
			__util_diagf("write: %s: %s\n", t.path, strerror(errno));
			return 1;
		}
		opened_real = 1;
	} else {
		wfd = fd;
		opened_real = 0;
	}

	now = time(0);
	timestr = ctime(&now);
	tbuf[0] = 0;
	if (timestr) {
		strncpy(tbuf, timestr, sizeof tbuf - 1);
		tbuf[sizeof tbuf - 1] = 0;
		tlen = strlen(tbuf);
		while (tlen && (tbuf[tlen - 1] == '\n' || tbuf[tlen - 1] == '\r')) tbuf[--tlen] = 0;
	}
	snprintf(banner, sizeof banner, "Message from %s (%s) [%s]...\n",
		pw->pw_name, t.shortname, tbuf);

	if (send_all(wfd, banner, strlen(banner)) != 0) {
		__util_diagf("write: %s\n", strerror(errno));
		status = 1;
		goto out;
	}

	while (fgets(line, sizeof line, stdin)) {
		if (send_all(wfd, line, strlen(line)) != 0) {
			__util_diagf("write: %s\n", strerror(errno));
			status = 1;
			goto out;
		}
	}

	send_all(wfd, "EOT\n", 4); /* best-effort trailer; stdin is already
	                            * exhausted either way, nothing left to
	                            * usefully retry against */

out:
	if (opened_real) (void)close(wfd);
	return status;
}
