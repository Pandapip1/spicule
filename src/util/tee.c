/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * tee(1p): `tee [-ai] [file...]`
 *
 * DESCRIPTION: "The tee utility shall copy standard input to standard
 * output, making a copy in zero or more files.  The tee utility shall
 * not buffer output." -- read/write below moves each block read
 * straight out to every destination with no interior buffering layer
 * that could hold data back, matching "not buffer output" the same way
 * cat's -u note in src/util/cat.c does.
 *
 * OPTIONS:
 *  -a  "Append the output to the files."  Without -a, each file operand
 *      is created or truncated, same as cp's destination-open call.
 *  -i  "Ignore the SIGINT signal."  This is real here, not faked: signal
 *      disposition is a genuine, tested part of this platform (see
 *      src/signal/signal.c's own header), so `signal(SIGINT, SIG_IGN)`
 *      before the copy loop is the whole of what -i asks for -- no
 *      polling loop, no approximation, nothing left refused.
 *
 * OPERANDS: "A pathname of an output file."  Per the spec's own note, a
 * file operand of '-' names a literal file called "-", *not* a second
 * alias for standard output -- unlike cat's OPERANDS clause, tee(1p)'s
 * does not carve out "-" as special, so it is opened just like any other
 * path here.
 *
 * DESCRIPTION continues: "If a write to any successfully opened file
 * operand fails, writes to other successfully opened file operands shall
 * continue, although the tee utility shall eventually exit with a
 * non-zero exit status" -- the diagnose-and-continue shape this project
 * already uses in rm/cp/mv/cat, applied per-destination instead of
 * per-operand: one broken output file does not stop the others from
 * still getting every remaining byte of stdin, and does not stop stdout
 * from getting it either.
 *
 * A file operand that fails to *open* at all is diagnosed and dropped
 * from the destination set before the copy loop starts (mirroring cp's
 * "cannot create" diagnostic in src/util/cp.c) -- there is nothing to
 * "continue" doing to a destination the loop was never able to add.
 *
 * EXIT STATUS: "0 The standard input was successfully copied to all
 * output files." ">0 An error occurred."
 *
 * Spec consulted: https://pubs.opengroup.org/onlinepubs/9699919799/utilities/tee.html
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include "util.h"

int __util_tee_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i;
	int opt_a = 0, opt_i = 0;
	int nfiles = 0;
	int *fds = 0;
	char **paths = 0;
	int had_error = 0;
	char buf[65536];
	ssize_t n;

	for (i = 1; i < argc; i++) {
		char *a = argv[i];
		char *p;

		if (a[0] != '-' || a[1] == 0) break;
		if (!strcmp(a, "--")) { i++; break; }
		for (p = a + 1; *p; p++) {
			if (*p == 'a') { opt_a = 1; continue; }
			if (*p == 'i') { opt_i = 1; continue; }
			__util_diagf("tee: invalid option -- '%c'\n", *p);
			return 1;
		}
	}

	if (opt_i) {
		/* Real signal disposition, not a fake -- see this file's
		 * header.  Failure here (an unsupported signal number, which
		 * SIGINT never is on this platform) would be a build-time
		 * bug, not a runtime condition worth diagnosing to the user. */
		if (signal(SIGINT, SIG_IGN) == SIG_ERR) return 1;
	}

	if (i < argc) {
		int count = argc - i;
		fds = __util_mallocarray((size_t)count, sizeof *fds);
		paths = (char **)__util_mallocarray((size_t)count, sizeof *paths);
		if (!fds || !paths) {
			__util_diagf("tee: out of memory\n");
			free(fds);
			free((void *)paths);
			return 1;
		}
		for (; i < argc; i++) {
			int flags = O_WRONLY | O_CREAT | (opt_a ? O_APPEND : O_TRUNC);
			int fd = open(argv[i], flags, 0666);
			if (fd < 0) {
				__util_diagf("tee: %s: %s\n", argv[i], strerror(errno));
				had_error = 1;
				continue;
			}
			fds[nfiles] = fd;
			paths[nfiles] = argv[i];
			nfiles++;
		}
	}

	while ((n = read(STDIN_FILENO, buf, sizeof buf)) > 0) {
		if ((size_t)n > sizeof buf) { errno = EIO; had_error = 1; break; }
		int j;
		size_t off = 0;

		while (off < (size_t)n) {
			ssize_t w = write(STDOUT_FILENO, buf + off, (size_t)n - off);
			if (w <= 0 || (size_t)w > (size_t)n - off) {
				if (w >= 0) errno = EIO;
				__util_diagf("tee: standard output: %s\n", strerror(errno));
				had_error = 1;
				break;
			}
			off += (size_t)w;
		}

		for (j = 0; j < nfiles; j++) {
			if (fds[j] < 0) continue;  /* already failed; skip, per DESCRIPTION */
			off = 0;
			while (off < (size_t)n) {
				ssize_t w = write(fds[j], buf + off, (size_t)n - off);
				if (w <= 0 || (size_t)w > (size_t)n - off) {
					if (w >= 0) errno = EIO;
					__util_diagf("tee: %s: %s\n", paths[j], strerror(errno));
					had_error = 1;
					(void)close(fds[j]);
					fds[j] = -1;
					break;
				}
				off += (size_t)w;
			}
		}
	}
	if (n < 0) {
		__util_diagf("tee: standard input: %s\n", strerror(errno));
		had_error = 1;
	}

	{
		int j;
		for (j = 0; j < nfiles; j++) {
			if (fds[j] >= 0 && close(fds[j]) < 0) {
				__util_diagf("tee: %s: %s\n", paths[j], strerror(errno));
				had_error = 1;
			}
		}
	}
	free(fds);
	free((void *)paths);

	return had_error ? 1 : 0;
}
