/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Named util_write.c, not write.c: the same tcc-`ar` member-name
 * collision src/util/util_basename.c's header explains, this time
 * against src/unistd/write.c (the write(2) syscall front door). The
 * util_ prefix is the whole fix; the exported symbol is still
 * __util_write_main().
 *
 * write(1p): "write user [tty]" -- reads lines from standard input and
 * writes them to another user's terminal.
 *
 * ---- what this actually implements --------------------------------------
 *
 * Real write(1p) sends to a *different* logged-in user's terminal, but
 * spicule has exactly one real user identity (src/misc/pwd.c), so there
 * is no second account to invent:
 *
 *   - `user` must name this process's own user (getpwnam(user) --
 *     src/misc/pwd.c). Any other name gets write(1p)'s own specified
 *     ">0 user not logged on" exit status, not a fabricated success.
 *
 *   - The only session this process can find is its own controlling
 *     terminal, resolved by __util_find_terminal() (src/util/
 *     termident.h/.c). So `write $(whoami)` writes straight into that
 *     same terminal -- sender and recipient degenerately the same
 *     session. Any other tty operand likewise gets "not logged on".
 *
 *   - Forward-compatible, not a permanent ceiling: if this tree ever
 *     grows a real multi-session registry (none exists today), only
 *     __util_write_main()'s target-resolution step would need to widen;
 *     the core mechanism (open the real tty, write into it) stays the
 *     same.
 *
 * mesg(1p) is deliberately not consulted here: it gates *other* users
 * reaching a terminal, and the only recipient here is this same session.
 *
 * Interrupt handling (write.html: an interrupt sends EOT and exits) is
 * out of scope: __util_write_main() is shared between a standalone
 * process and an in-process shell builtin (src/internal/util.h's
 * never-exit() contract, see src/util/dd.c), so it installs no signal
 * handler; EOF alone -- the normal way to end a session -- gets the
 * real "EOT\n" trailer.
 */
#include "util.h"
#include "termident.h"
#include "ownership_stubs.h" /* __ownership_string_terminated() */
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
		/* write() returning 0 isn't documented to touch errno; every
		 * caller here trusts errno after a -1 return, so set it explicitly. */
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

	/* ttyop: argv element read through const char * (AggregateElementToken
	 * gap, same idiom as tail.c/head.c/cksum.c). t.shortname: struct field
	 * __util_find_terminal() always NUL-terminates on success. */
	if (ttyop) __ownership_string_terminated(ttyop);
	__ownership_string_terminated(t.shortname);
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
		/* strncpy() only proves extent; the explicit assignment above
		 * is what actually NUL-terminates tbuf. */
		__ownership_string_terminated(tbuf);
		tlen = strlen(tbuf);
		/* KNOWN CHECKER GAP (spicule.ValidPointer on tbuf[tlen-1]/
		 * tbuf[--tlen] below): tlen <= sizeof tbuf - 1 always holds, from
		 * the fixed NUL just written above, but OwnershipChecker.cpp's
		 * trackScanExtent declines to correlate strlen()'s return with a
		 * fixed local array's already-stronger extent, and a manual
		 * __ownership_writable_span/readable_span restatement here is
		 * rejected by spicule.MemoryContract as narrowing an
		 * already-proven-stronger fact. Left open rather than worked
		 * around. */
		while (tlen && (tbuf[tlen - 1] == '\n' || tbuf[tlen - 1] == '\r')) tbuf[--tlen] = 0;
	}
	snprintf(banner, sizeof banner, "Message from %s (%s) [%s]...\n",
		pw->pw_name, t.shortname, tbuf);
	/* snprintf() isn't itself annotated to grant null_terminated, but it
	 * always NUL-terminates a nonzero-size buffer. */
	__ownership_string_terminated(banner);

	if (send_all(wfd, banner, strlen(banner)) != 0) {
		__util_diagf("write: %s\n", strerror(errno));
		status = 1;
		goto out;
	}

	while (fgets(line, sizeof line, stdin)) {
		/* fgets() always NUL-terminates on a non-NULL return. */
		__ownership_string_terminated(line);
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
