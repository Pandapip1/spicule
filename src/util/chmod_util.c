/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Named chmod_util.c, not chmod.c -- see src/util/mkdir_util.c's own
 * comment on exactly why (src/stat/chmod.c already owns that basename,
 * and `ar` truncates member names to a bare, path-less basename).
 *
 * chmod(1p): `chmod mode file...`
 *
 * OPERANDS:
 *  mode  "Represents the change to be made to the file mode bits of each
 *         file named by one of the file operands."  Octal or symbolic --
 *         see src/util/modeparse.h for the exact grammar implemented and
 *         its documented gap (X/s/t/permcopy are refused, not
 *         approximated).
 *  file  "A pathname of a file whose file mode bits shall be modified."
 *
 * EXIT STATUS: "0 The utility executed successfully and all requested
 * changes were made." ">0 An error occurred." -- diagnose-and-continue,
 * same shape as this project's other utilities.
 *
 * A symbolic mode's '+'/'-'/'=' are relative to *this file's own current
 * mode bits*, unlike mkdir(1p)/mkfifo(1p)'s -m (which assume a=rwx or
 * a=rw since there is no existing file yet) -- so, unlike those two,
 * this utility has to stat() each file before it can even parse the
 * mode operand for it, and does so once per file rather than once
 * overall.
 *
 * -R (recurse into directories) is a real chmod(1p) option that is not
 * implemented here -- refused with a diagnostic rather than silently
 * walking (or not walking) a tree the caller asked it to.  The single-
 * file, non-recursive form is the one this project's own bootstrap
 * scripts need; -R is a real, tracked gap, not an oversight.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "libc.h"
#include "util.h"
#include "modeparse.h"

enum chmod_fd_result { CHMOD_FD_DONE, CHMOD_FD_FAILED, CHMOD_FD_USAGE_ERROR, CHMOD_FD_UNAVAILABLE };

/* A relative mode ("+w", "-x", ...) is computed from *this file's own
 * current mode bits*, so the stat() that reads those bits and the
 * chmod() that applies the result must see the same filesystem
 * object -- a path re-resolved between the two (an attacker's symlink
 * swapped into a shared directory, most dangerously) would compute
 * the new mode from one file and apply it to another. Pinning both to
 * one fd via fstat()/fchmod() closes that window instead of merely
 * narrowing it. open() still follows a symlink named by `path` itself,
 * matching chmod(1p)'s own "act on the referent" rule; O_NONBLOCK/
 * O_NOCTTY keep opening a FIFO or tty operand from blocking or
 * stealing a controlling terminal. */
static enum chmod_fd_result chmod_by_fd(const char *path, const char *mode_spec, int *fail)
{
	struct stat st;
	mode_t newmode;
	int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOCTTY);

	if (fd < 0) return CHMOD_FD_UNAVAILABLE;
	if (fstat(fd, &st) != 0) {
		__util_diagf("chmod: %s: %s\n", path, strerror(errno));
		(void)close(fd);
		*fail = 1;
		return CHMOD_FD_FAILED;
	}
	/* The who-omitted umask rule (modeparse.h) is chmod(1p)'s own
	 * OPERANDS text, not something mkdir(1p)/mkfifo(1p) add on top of
	 * it -- so a bare `chmod +w file` is exactly as umask-sensitive
	 * here as `mkdir -m +w newdir` is. */
	if (__util_parse_mode("chmod", mode_spec, st.st_mode & 07777,
	                      (mode_t)__umask_get(), &newmode) < 0) {
		(void)close(fd);
		return CHMOD_FD_USAGE_ERROR; /* malformed mode operand: usage error, not per-file */
	}
	if (fchmod(fd, newmode) != 0) {
		__util_diagf("chmod: %s: %s\n", path, strerror(errno));
		(void)close(fd);
		*fail = 1;
		return CHMOD_FD_FAILED;
	}
	(void)close(fd);
	return CHMOD_FD_DONE;
}

int __util_chmod_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i, fail = 0;
	const char *mode_spec;

	if (argc > 1 && !strcmp(argv[1], "-R")) {
		__util_diagf("chmod: -R: not implemented -- see src/util/chmod_util.c\n");
		return 1;
	}
	if (argc < 3) {
		__util_diagf("chmod: missing operand\n");
		return 1;
	}
	mode_spec = argv[1];

	for (i = 2; i < argc; i++) {
		struct stat st;
		mode_t newmode;
		enum chmod_fd_result r = chmod_by_fd(argv[i], mode_spec, &fail);

		if (r == CHMOD_FD_DONE || r == CHMOD_FD_FAILED) continue;
		if (r == CHMOD_FD_USAGE_ERROR) return 1;

		/* CHMOD_FD_UNAVAILABLE: open() itself failed -- a socket, or
		 * a real permission problem (an owner can chmod a file whose
		 * own mode bits deny them read/write, but cannot open() it)
		 * -- neither is the TOCTOU chmod_by_fd() exists to close, so
		 * fall back to the plain stat()+chmod() pair this function
		 * used before it ever tried to open() at all. */
		if (stat(argv[i], &st) != 0) {
			__util_diagf("chmod: %s: %s\n", argv[i], strerror(errno));
			fail = 1;
			continue;
		}
		if (__util_parse_mode("chmod", mode_spec, st.st_mode & 07777,
		                      (mode_t)__umask_get(), &newmode) < 0)
			return 1; /* malformed mode operand: usage error, not per-file */
		if (chmod(argv[i], newmode) != 0) {
			__util_diagf("chmod: %s: %s\n", argv[i], strerror(errno));
			fail = 1;
		}
	}
	return fail;
}

// NOLINTEND(misc-include-cleaner)
