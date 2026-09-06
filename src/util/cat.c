/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * cat(1p): `cat [-u] [file...]`
 *
 * DESCRIPTION: reads files in sequence, writes their contents to
 * standard output in the same sequence, byte for byte, with no
 * line-ending translation -- this is the one utility in this tier where
 * "copy" means exactly that.
 *
 * OPERANDS: no file operands means standard input. "-" reads standard
 * input at that point in the sequence, so it can appear anywhere in a
 * mixed operand list rather than only as a synonym for "no operands".
 *
 * OPTIONS: -u ("write bytes without delay as each is read") is accepted
 * as a real no-op: copy_stream() below already writes every block it
 * reads immediately, with no buffering layer above raw read()/write()
 * for -u to disable.
 *
 * EXIT STATUS: diagnose-and-continue across operands, the same shape
 * rm/cp/mv/touch already establish: one unreadable operand does not
 * stop the rest from being copied, and the final exit status is still
 * nonzero.
 *
 * Spec consulted: https://pubs.opengroup.org/onlinepubs/9699919799/utilities/cat.html
 */
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "util.h"
#include "ownership_stubs.h"

/* Copies every byte of `in` to fd 1 (standard output), diagnosing under
 * `label` (the operand text as given, "standard input" for the no-operand
 * and "-" cases) on either a read or a write failure.  Does not close
 * `in`: the caller owns that, since fd 0 (stdin, used for both "-" and
 * the no-operand case) must never be closed by an interior helper that
 * might be called on it more than once in one invocation. */
static int copy_stream(int in, const char *label)
{
	char buf[65536];
	ssize_t n;

	while ((n = read(in, buf, sizeof buf)) > 0) {
		if ((size_t)n > sizeof buf) { errno = EIO; return -1; }
		__ownership_readable_span(buf, (size_t)n);
		size_t off = 0;
		while (off < (size_t)n) {
			ssize_t w = write(STDOUT_FILENO, buf + off, (size_t)n - off);
			if (w <= 0 || (size_t)w > (size_t)n - off) {
				if (w >= 0) errno = EIO;
				__util_diagf("cat: %s: %s\n", label, strerror(errno));
				return -1;
			}
			off += (size_t)w;
		}
	}
	if (n < 0) {
		__util_diagf("cat: %s: %s\n", label, strerror(errno));
		return -1;
	}
	return 0;
}

int __util_cat_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i, had_error = 0;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-u")) continue;  /* real no-op -- see header */
		break;
	}

	if (i >= argc) {
		/* No file operands at all: read standard input once. */
		return copy_stream(STDIN_FILENO, "standard input") < 0 ? 1 : 0;
	}

	for (; i < argc; i++) {
		const char *path = argv[i];
		int fd;

		if (!strcmp(path, "-")) {
			if (copy_stream(STDIN_FILENO, "-") < 0) had_error = 1;
			continue;
		}

		fd = open(path, O_RDONLY);
		if (fd < 0) {
			__util_diagf("cat: %s: %s\n", path, strerror(errno));
			had_error = 1;
			continue;
		}
		if (copy_stream(fd, path) < 0) had_error = 1;
		(void)close(fd);
	}

	return had_error ? 1 : 0;
}
