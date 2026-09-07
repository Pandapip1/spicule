/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * file(1p): `file [-dh] [-M file] [-m file] file...` / `file -i [-h] file...`
 *
 * Filename note: this is src/util/util_file.c, not src/util/file.c, to
 * avoid colliding with this library's own src/stdio/file.c in lib/libc.a
 * -- tcc's `-ar` archiver (this project's own $(AR), Makefile) truncates
 * every archive member name to its basename before storing it, so two
 * different file.c anywhere under src/ would silently collide as the
 * same "file.o" archive member (see tools/linkcheck.sh, which exists
 * specifically to catch this class of bug, and src/internal/util.h's
 * own header comment, which documents this exact naming exception
 * alongside mkdir_util.c/chmod_util.c/util_printf.c).  The utility's
 * own name, argv[0] and the standalone executable, all stay "file" --
 * only this source file's own basename changes.
 *
 * ---- SCOPE, verified against the real XCU file(1p) text -----------------
 *
 * POSIX's *mandatory* scope here is much narrower than a full libmagic
 * signature database, and this file deliberately stays inside it:
 *
 *  - OPTIONS: -d ("apply ... default system tests"; "the default if no
 *    -M or -m option is specified") and -h (symlink identification
 *    control) are implemented.  -i ("If a file is a regular file, do
 *    not attempt to classify the type of the file further, but
 *    identify the file as specified in the STDOUT section") is
 *    implemented as: under -i, every regular file -- empty or not --
 *    is reported as plain "regular file", skipping every content peek
 *    including the empty/non-empty distinction; this is the most
 *    literal reading of "do not attempt to classify ... further".
 *  - -M file / -m file (custom position-sensitive test files, in
 *    effect a small magic(5)-style interpreter) are NOT implemented --
 *    refused loudly (nonzero exit, real diagnostic) rather than
 *    silently ignored, this project's standing convention for an
 *    unimplemented option (see e.g. src/util/cp.c's -p/-i refusals).
 *    POSIX's own DESCRIPTION makes -d ("default system tests") the
 *    behaviour "if no -M or -m option is specified" -- i.e. exactly
 *    the mandatory baseline this file targets; -M/-m exist to let a
 *    caller *replace or extend* that baseline with their own test
 *    file, a distinct, open-ended parsing project (a real grammar:
 *    offset/type/value/message lines, position-sensitive and
 *    conditional '>' tests, printf-style messages) that this batch
 *    does not attempt.
 *
 *  - The STDOUT section's format is always `"%s: %s\n", file, type`
 *    (symbolic links: `"%s: %s %s\n", file, type, link-contents`), and
 *    lists exact required strings for: cannot open, block special,
 *    character special, directory, fifo, socket, symbolic link
 *    ("symbolic link to"), regular file, empty regular file, and
 *    "Unknown regular file" -> "data". All of these are implemented
 *    via stat()/lstat() (src/util/test.c's S_IS* pattern) with no
 *    content read at all for the non-regular-file cases.
 *
 *  - For a non-empty regular file, POSIX additionally lists
 *    "position-sensitive tests" that "examine an initial segment of
 *    file" and "make a guess ... The answer is not guaranteed to be
 *    correct" -- i.e. a best-effort content peek, not a certified
 *    result.  This file peeks at most PEEK_MAX bytes and recognizes
 *    only signatures that map directly onto STDOUT's own required
 *    strings, so the peek never grows into an open-ended magic
 *    database:
 *      - ELF ("\x7fELF") or PE ("MZ") magic       -> "executable"
 *      - ar magic ("!<arch>\n")                   -> "archive"
 *      - ustar magic ("ustar" at byte offset 257)  -> "tar archive"
 *      - cpio odc magic ("070707" at offset 0)      -> "cpio archive"
 *      - a "#!" shebang                             -> "commands text"
 *      - otherwise, every peeked byte is a tab, CR, LF or printable
 *        7-bit ASCII byte                           -> "ASCII text"
 *      - anything else (a NUL byte, a non-shebang non-ASCII byte, ...)
 *        -> "data"
 *    Deliberately NOT implemented: POSIX's own "c program text" and
 *    "fortran program text" context-sensitive strings -- distinguishing
 *    a C or FORTRAN source file from any other readable text needs a
 *    real keyword/token scan, exactly the kind of open-ended
 *    content-sensitive test this file avoids by design; such files
 *    are reported as "ASCII text" here instead, which is a legitimate
 *    (if less specific) answer since POSIX's own required-string list
 *    only binds "when applicable" and does not mandate language
 *    detection to be attempted at all.
 *
 *  - "-" as a file operand: STDOUT's own OPERANDS section makes this
 *    implementation-defined ("if a file operand is '-' and the
 *    implementation treats the '-' as meaning standard input"). This
 *    build does: "-" is classified via fstat(STDIN_FILENO) and, for a
 *    regular/peekable case, the same content peek reading from fd 0
 *    directly (there is no seekable path to reopen).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "util.h"
#include "ownership_stubs.h"

#define PEEK_MAX 4096

/* Reads up to `cap` bytes from `fd` into `buf`, looping over short
 * reads the way every other reader in this tree does.  Returns the
 * byte count read (0 on EOF/empty file), or -1 on a real read error. */
static ssize_t peek_read(int fd, unsigned char *buf, size_t cap)
{
	size_t got = 0;
	while (got < cap) {
		ssize_t n = read(fd, buf + got, cap - got);
		if (n < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		if (n == 0) break;
		got += (size_t)n;
	}
	return (ssize_t)got;
}

static int is_text_byte(unsigned char c)
{
	if (c == '\t' || c == '\n' || c == '\r') return 1;
	return c >= 0x20 && c < 0x7f;
}

/* Classifies a content peek already in memory, returning one of the
 * STDOUT strings this file's header documents.  `n` is the number of
 * valid bytes in `buf` (0 for an empty file, handled by the caller
 * before this is reached). */
static const char *classify_peek(const unsigned char *buf, size_t n)
{
	size_t i;

	if (n >= 4 && memcmp(buf, "\x7f""ELF", 4) == 0) return "executable";
	if (n >= 2 && buf[0] == 'M' && buf[1] == 'Z') return "executable";
	if (n >= 8 && memcmp(buf, "!<arch>\n", 8) == 0) return "archive";
	if (n >= 263 && memcmp(buf + 257, "ustar", 5) == 0) return "tar archive";
	if (n >= 6 && memcmp(buf, "070707", 6) == 0) return "cpio archive";
	if (n >= 2 && buf[0] == '#' && buf[1] == '!') return "commands text";

	for (i = 0; i < n; i++)
		if (!is_text_byte(buf[i])) return "data";
	return "ASCII text";
}

/* Peeks at most PEEK_MAX bytes of an already-open regular file (fd
 * positioned at offset 0) and classifies it, closing fd's read position
 * is irrelevant since the caller is done with fd either way. Returns 0
 * and sets *out on success (a static string, never freed), or -1 if
 * the peek read itself failed (a real I/O error, distinct from "file
 * classifies as data"). */
static int classify_fd(int fd, const char **out)
{
	unsigned char buf[PEEK_MAX];
	ssize_t n = peek_read(fd, buf, sizeof buf);
	if (n < 0) return -1;
	*out = classify_peek(buf, (size_t)n);
	return 0;
}

struct file_opts {
	int h; /* -h: report a symlink as itself, don't resolve */
	int i; /* -i: regular files -> plain "regular file", no peek */
};

/* Classifies one already-stat'd (or lstat'd) non-symlink file by
 * st_mode, opening and peeking it if it is a non-empty regular file.
 * `path` is used only to open the file for the content peek; the name
 * printed is always the caller's, not necessarily this one (a resolved
 * symlink target is peeked via this path but printed under the
 * original operand name). */
static const char *classify_stat(const char *path, const struct stat *st, const struct file_opts *o)
{
	if (S_ISDIR(st->st_mode)) return "directory";
	if (S_ISFIFO(st->st_mode)) return "fifo";
	if (S_ISSOCK(st->st_mode)) return "socket";
	if (S_ISBLK(st->st_mode)) return "block special";
	if (S_ISCHR(st->st_mode)) return "character special";
	if (S_ISREG(st->st_mode)) {
		int fd, r;
		const char *type;
		if (o->i) return "regular file";
		if (st->st_size == 0) return "empty";
		fd = open(path, O_RDONLY);
		if (fd < 0) return "cannot open";
		r = classify_fd(fd, &type);
		(void)close(fd);
		return r < 0 ? "cannot open" : type;
	}
	/* No other S_IS* case exists in include/sys/stat.h; this is
	 * unreachable for a file that stat() actually returned, but a
	 * fallback avoids ever printing nothing. */
	return "data";
}

/* Classifies stdin ("-") without a nameable path to (re)open: fstat it,
 * and for the regular/peekable case, read the peek directly from fd 0
 * (there is no seek-and-retry story for a pipe). */
static const char *classify_stdin(const struct file_opts *o)
{
	struct stat st;
	const char *type;

	if (fstat(STDIN_FILENO, &st) < 0) return "cannot open";
	if (S_ISDIR(st.st_mode)) return "directory";
	if (S_ISFIFO(st.st_mode)) return "fifo";
	if (S_ISSOCK(st.st_mode)) return "socket";
	if (S_ISBLK(st.st_mode)) return "block special";
	if (S_ISCHR(st.st_mode)) return "character special";
	if (o->i) return "regular file";
	if (S_ISREG(st.st_mode) && st.st_size == 0) return "empty";
	if (classify_fd(STDIN_FILENO, &type) < 0) return "cannot open";
	return type;
}

/* Processes one operand, printing its STDOUT-format line and returning
 * 0 on a successful classification or -1 for "cannot open"/a stat
 * failure (the caller turns that into a nonzero exit status, without
 * stopping the remaining operands -- the same "diagnose and continue"
 * shape src/util/readlink.c's own header describes). */
static int file_one(const char *path, const struct file_opts *o)
{
	struct stat lst, st;
	char linkbuf[PATH_MAX];
	ssize_t linklen;

	/* path is one of __util_file_main's own argv elements, null-terminated
	 * by its elements_withtok(null_terminated, argc) contract on argv --
	 * restated here since that token does not survive the argv[i] -> const
	 * char * parameter read this checker can trace on its own. */
	__ownership_string_terminated(path);

	if (strcmp(path, "-") == 0) {
		printf("%s: %s\n", path, classify_stdin(o));
		return 0;
	}

	if (lstat(path, &lst) < 0) {
		printf("%s: %s\n", path, "cannot open");
		return -1;
	}

	if (S_ISLNK(lst.st_mode)) {
		if (!o->h && stat(path, &st) == 0) {
			/* "the link shall be resolved and file shall test the
			 * type of file referenced by the symbolic link" --
			 * classify the referent, but always print the
			 * caller's own operand name. */
			printf("%s: %s\n", path, classify_stat(path, &st, o));
			return 0;
		}
		/* Either -h was given, or the link's target does not exist
		 * ("file shall identify the file as a symbolic link, as if
		 * -h had been specified" -- file(1p) DESCRIPTION). Both
		 * paths print the same "symbolic link to <target>" form. */
		linklen = readlink(path, linkbuf, sizeof linkbuf - 1);
		if (linklen < 0) {
			printf("%s: %s\n", path, "cannot open");
			return -1;
		}
		/* linklen <= sizeof linkbuf - 1 is readlink()'s own POSIX
		 * contract on its own third argument ("return value <=
		 * bufsiz"); this vocabulary has no annotation for a return
		 * value bounded by a parameter, so linkbuf[linklen] is left
		 * open as an ntlibc.ValidPointer finding -- a real
		 * checker/vocabulary gap, not a bug here (same gap documented
		 * in src/util/readlink.c's own identical use). */
		linkbuf[linklen] = 0;
		printf("%s: %s %s\n", path, "symbolic link to", linkbuf);
		return 0;
	}

	printf("%s: %s\n", path, classify_stat(path, &lst, o));
	return 0;
}

int __util_file_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	struct file_opts o;
	int i, status = 0;

	o.h = 0;
	o.i = 0;

	for (i = 1; i < argc; i++) {
		char *a = argv[i];
		char *p;

		if (!strcmp(a, "--")) { i++; break; }
		if (a[0] != '-' || a[1] == 0) break;

		p = a + 1;
		while (*p) {
			switch (*p) {
			case 'd': p++; break; /* already the default */
			case 'h': o.h = 1; p++; break;
			case 'i': o.i = 1; p++; break;
			case 'M':
			case 'm':
				__util_diagf("file: -%c: custom test files are not implemented by "
				                "this build -- see src/util/util_file.c's header\n", *p);
				return 2;
			default:
				__util_diagf("file: -%c: invalid option\n", *p);
				return 2;
			}
		}
	}

	if (i >= argc) {
		__util_diagf("file: missing operand\n");
		return 2;
	}

	for (; i < argc; i++)
		if (file_one(argv[i], &o) < 0) status = 1;

	return status;
}
