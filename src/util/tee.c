/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * tee(1p): `tee [-ai] [file...]`
 *
 * DESCRIPTION: copies standard input to standard output and to zero or
 * more files, unbuffered -- read/write below moves each block straight
 * out to every destination with no buffering layer that could hold
 * data back, same as cat's -u note in src/util/cat.c.
 *
 * OPTIONS:
 *  -a  Append to the files instead of truncating them.
 *  -i  Ignore SIGINT -- real signal disposition (src/signal/signal.c),
 *      not an approximation.
 *
 * OPERANDS: a file operand of '-' names a literal file called "-", not
 * an alias for standard output -- unlike cat(1p), tee(1p) does not
 * carve out "-" as special.
 *
 * A write failure on one already-open destination diagnoses it and
 * drops it from the set; the rest keep getting every remaining byte of
 * stdin, and the utility exits nonzero at the end. A file operand that
 * fails to *open* at all is diagnosed and dropped before the copy loop
 * starts (mirroring cp's "cannot create" diagnostic).
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
		/* Failure here means an unsupported signal number, which
		 * SIGINT never is on this platform -- a build-time bug, not
		 * something worth diagnosing to the user. */
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
		/* Checker gap (ntlibc.ResourceLeak): each open() below is stored
		 * into fds[nfiles], a heap array indexed at runtime -- the
		 * checker can't correlate that store with the fds[j] loads in
		 * the write-error and final close loops below, so every
		 * descriptor here is reported as never released even when
		 * those loops do close it. */
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
