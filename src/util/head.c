/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * head(1p): `head [-n number] [file...]`
 *
 * DESCRIPTION: "The head utility shall copy its input files to the
 * standard output, ending the output for each file at a designated
 * point."
 *
 * OPTIONS: -n number -- "The first number lines of each input file shall
 * be copied to standard output."  "The number option-argument shall be
 * counted as a positive decimal integer" -- 0 and anything signed or
 * non-numeric is a usage error here, not a silent "print nothing"/
 * "print everything" extension; default is 10 when -n is not given.
 * "If a file contains fewer than number lines, it shall be copied to
 * standard output in its entirety" -- head_one() below stops naturally
 * at end-of-file with no separate short-file check needed for that.
 *
 * The multi-operand `==> file <==` banner is not specified by XCU's own
 * wording at all (head(1p) says nothing about multiple files needing any
 * separator beyond concatenation) -- this follows the GNU/BSD
 * convention every head this project has to interoperate with actually
 * uses: a banner line before each file's output, and (this file's own
 * choice, matching GNU coreutils rather than the sparser historical BSD
 * form) a blank line before every banner after the first, so
 * concatenated outputs are visually separated rather than run together.
 *
 * OPERANDS: "If no file operands are specified, the standard input shall
 * be used."
 *
 * EXIT STATUS: "0 Successful completion." ">0 An error occurred." --
 * diagnose-and-continue across operands, same shape as this project's
 * other utilities.
 *
 * Spec consulted: https://pubs.opengroup.org/onlinepubs/9699919799/utilities/head.html
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "util.h"
#include "ownership_stubs.h"

static int write_all(const char *buf withtok(readable_span(len)), size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t w = write(STDOUT_FILENO, buf + off, len - off);
		if (w < 0) return -1;
		off += (size_t)w;
	}
	return 0;
}

/* Copies the first `n` lines of `fd` to standard output.  Stops reading
 * as soon as the n-th newline has been written -- it does not drain the
 * rest of `fd`, matching every other head(1) this project interoperates
 * with (a pipe's writer may still see the rest of its data refused with
 * EPIPE, exactly as with a real head). */
static int head_one(int fd, long n, const char *label)
{
	char buf[65536];
	ssize_t r;

	while (n > 0 && (r = read(fd, buf, sizeof buf)) > 0) {
		ssize_t i;
		ssize_t seglen = r;

		for (i = 0; i < r; i++) {
			if (buf[i] == '\n') {
				n--;
				if (n == 0) { seglen = i + 1; break; }
			}
		}
		if (write_all(buf, (size_t)seglen) < 0) {
			int saved = errno;
			__util_diagf("head: %s: %s\n", label, strerror(saved));
			return -1;
		}
	}
	if (r < 0) {
		__util_diagf("head: %s: %s\n", label, strerror(errno));
		return -1;
	}
	return 0;
}

int __util_head_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i;
	long n = 10;
	int had_error = 0;
	int first_banner = 1;

	for (i = 1; i < argc; i++) {
		char *a = argv[i];

		if (!strcmp(a, "--")) { i++; break; }
		if (!strcmp(a, "-n")) {
			char *end;
			long v;

			if (i + 1 >= argc) {
				__util_diagf("head: -n: option requires an argument\n");
				return 1;
			}
			v = strtol(argv[++i], &end, 10);
			if (*end || end == argv[i] || v <= 0) {
				__util_diagf("head: %s: invalid number of lines\n", argv[i]);
				return 1;
			}
			n = v;
			continue;
		}
		if (a[0] == '-' && a[1] != 0) {
			__util_diagf("head: invalid option -- '%s'\n", a);
			return 1;
		}
		break;
	}

	if (i >= argc)
		return head_one(STDIN_FILENO, n, "standard input") < 0 ? 1 : 0;

	{
		int noperands = argc - i;

		for (; i < argc; i++) {
			const char *path = argv[i];
			int fd;

			/* path is one of argv's own elements, genuinely
			 * null-terminated by this function's own
			 * elements_withtok(null_terminated, argc) contract on argv --
			 * restated here since that token does not survive the
			 * argv[i] -> const char * read this checker can trace on its
			 * own. */
			__ownership_string_terminated(path);

			if (noperands > 1) {
				printf("%s==> %s <==\n", first_banner ? "" : "\n", path);
				first_banner = 0;
				if (fflush(stdout) < 0) had_error = 1;
			}

			if (!strcmp(path, "-")) {
				if (head_one(STDIN_FILENO, n, "-") < 0) had_error = 1;
				continue;
			}

			fd = open(path, O_RDONLY);
			if (fd < 0) {
				__util_diagf("head: %s: %s\n", path, strerror(errno));
				had_error = 1;
				continue;
			}
			if (head_one(fd, n, path) < 0) had_error = 1;
			(void)close(fd);
		}
	}

	return had_error ? 1 : 0;
}
