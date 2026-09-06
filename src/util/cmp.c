/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * cmp(1p): `cmp [-l|-s] file1 file2`, a byte-by-byte comparison. Checked
 * against the real XCU cmp(1p) page
 * (pubs.opengroup.org/onlinepubs/9699919799/utilities/cmp.html), not
 * reconstructed from memory -- citations below point at the exact
 * section each behavior comes from.
 *
 * SYNOPSIS is "cmp [-l|-s] file1 file2": the '|' means -l and -s are
 * mutually exclusive, refused loudly if both are given rather than
 * silently picking one -- the same rule this project applies elsewhere
 * (see uniq(1p)'s -d/-u check in src/util/uniq.c).
 *
 * DEFAULT OUTPUT (STDOUT section): the first time the two files differ,
 * "%s %s differ: char %d, line %d\n" -- a 1-based byte position and a
 * 1-based line number.  The line number is "the number of newlines seen
 * so far, plus one"; see the LINE COUNTING note below for whose stream
 * that count is taken from once the files diverge.
 *
 * -l (OPTIONS/STDOUT): "Write the byte number (decimal) and the
 * differing bytes (octal) for each difference" -- every differing byte
 * up to the length of the shorter file, not just the first, one line
 * each: "%d %o %o\n" (byte number, file1's byte, file2's byte).
 *
 * -s (OPTIONS): "Write nothing to standard output or standard error
 * when files differ; indicate differing files through exit status
 * only."  Content-difference and EOF-length diagnostics are suppressed
 * under -s; a file that cannot even be opened is a different thing --
 * that is not "when files differ", and every other utility in this
 * tree still reports why it could not attempt its work at all (see
 * sort's fopen() diagnostic, src/util/sort.c) -- so -s does not swallow
 * open/read-error diagnostics, only the differ/EOF ones.
 *
 * EOF DIAGNOSTIC (STDERR section): "If the -l option is used and file1
 * and file2 differ in length, or if the -s option is not used and
 * file1 and file2 are identical for the entire length of the shorter
 * file ... 'cmp: EOF on %s%s\n', <name of shorter file>, <additional
 * info>", where "The <additional info> field shall either be null or a
 * string that starts with a <blank> and contains no <newline>
 * characters" and "[s]ome implementations report on the number of
 * lines in this case" -- this implementation takes that explicitly
 * granted license and reports " after byte %llu, in line %llu" as the
 * additional-info field.
 *
 * LINE COUNTING ACROSS A MISMATCH (real, deliberate scope note): once a
 * mismatch is found and -l keeps scanning past it, file1 and file2 can
 * disagree from that point on about where their own newlines fall.
 * POSIX does not say whose newline count the reported line number
 * should track in that case; this implementation always tracks file1's
 * newlines (the first operand, treated as the reference side)
 * throughout the whole comparison, documented here rather than picked
 * silently.
 *
 * EXIT STATUS: "0 The files are identical. 1 The files are different;
 * this includes the case where one file is identical to the first part
 * of the other. >1 An error occurred."
 *
 * Streamed, not loaded into memory: both files are read in fixed-size
 * chunks and compared as they go, so cmp's own memory use does not grow
 * with input size -- unlike e.g. sort(1p), which has to see every line
 * before it can order any of them, cmp never needs more than the
 * current chunk of each file.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "util.h"

#define CMP_CHUNK 65536

struct cmp_file {
	FILE *f;
	int is_stdin;
};

static int cmp_open(struct cmp_file *cf, const char *path)
{
	if (strcmp(path, "-") == 0) {
		cf->f = stdin;
		cf->is_stdin = 1;
		return 1;
	}
	cf->is_stdin = 0;
	cf->f = fopen(path, "rb");
	return cf->f != 0;
}

static void cmp_close(struct cmp_file *cf)
{
	if (cf->f && !cf->is_stdin) (void)fclose(cf->f);
}

int __util_cmp_main(int argc, char **argv)
{
	int opt_l = 0, opt_s = 0;
	int i;
	const char *files[2];
	int nfiles = 0;
	struct cmp_file f1, f2;
	static unsigned char buf1[CMP_CHUNK], buf2[CMP_CHUNK];
	unsigned long long byte_no = 0, line_no = 1;
	int diff_found = 0;

	for (i = 1; i < argc; i++) {
		char *arg = argv[i];
		if (!strcmp(arg, "--")) { i++; break; }
		if (arg[0] != '-' || arg[1] == 0) break;
		if (!strcmp(arg, "-l")) { opt_l = 1; continue; }
		if (!strcmp(arg, "-s")) { opt_s = 1; continue; }
		__util_diagf("cmp: %s: invalid option\n", arg);
		return 2;
	}
	if (opt_l && opt_s) {
		__util_diagf("cmp: -l and -s are mutually exclusive\n");
		return 2;
	}
	for (; i < argc; i++) {
		if (nfiles >= 2) {
			__util_diagf("cmp: extra operand %s\n", argv[i]);
			return 2;
		}
		files[nfiles++] = argv[i];
	}
	if (nfiles != 2) {
		__util_diagf("cmp: usage: cmp [-l|-s] file1 file2\n");
		return 2;
	}

	if (!cmp_open(&f1, files[0])) {
		__util_diagf("cmp: %s: %s\n", files[0], strerror(errno));
		return 2;
	}
	if (!cmp_open(&f2, files[1])) {
		__util_diagf("cmp: %s: %s\n", files[1], strerror(errno));
		cmp_close(&f1);
		return 2;
	}

	for (;;) {
		size_t n1 = fread(buf1, 1, sizeof buf1, f1.f);
		/* f1's errno must be captured here, before f2's fread() runs --
		 * a later call, even a successful one, is not required to
		 * leave errno alone. */
		int errno1 = errno;
		size_t n2 = fread(buf2, 1, sizeof buf2, f2.f);
		int errno2 = errno;
		size_t n = n1 < n2 ? n1 : n2;
		size_t k;

		for (k = 0; k < n; k++) {
			byte_no++;
			if (buf1[k] != buf2[k]) {
				diff_found = 1;
				if (opt_l) {
					if (!opt_s)
						printf("%llu %o %o\n", byte_no,
							(unsigned)buf1[k], (unsigned)buf2[k]);
				} else {
					if (!opt_s)
						printf("%s %s differ: char %llu, line %llu\n",
							files[0], files[1], byte_no, line_no);
					cmp_close(&f1); cmp_close(&f2);
					return 1;
				}
			}
			if (buf1[k] == '\n') line_no++;
		}

		if (n1 < sizeof buf1 || n2 < sizeof buf2) {
			/* At least one stream came up short of a full chunk --
			 * that is EOF only if it was not a real read error, so
			 * ferror() must be checked before treating the short
			 * count as "this file is shorter". */
			int err1 = ferror(f1.f), err2 = ferror(f2.f);
			if (err1 || err2) {
				/* Report whichever file ferror() says actually
				 * failed using THAT file's own errno1/errno2,
				 * captured right after its own fread() -- not the
				 * shared errno, which by now reflects only the
				 * later of the two fread() calls regardless of
				 * which one (or both) really failed. */
				__util_diagf("cmp: %s: %s\n",
					err1 ? files[0] : files[1],
					strerror(err1 ? errno1 : errno2));
				cmp_close(&f1); cmp_close(&f2);
				return 2;
			}
			if (n1 != n2) {
				const char *shorter = n1 < n2 ? files[0] : files[1];
				if (!opt_s)
					__util_diagf("cmp: EOF on %s after byte %llu, in line %llu\n",
						shorter, byte_no, line_no);
				cmp_close(&f1); cmp_close(&f2);
				return 1;
			}
			break; /* both streams ended together: same length */
		}
	}

	cmp_close(&f1); cmp_close(&f2);
	/* diff_found here can only have come from -l's "keep scanning"
	 * path (the non -l branch above already returned on the first
	 * mismatch), and any length mismatch was already reported and
	 * returned above too, so this is exactly "were any bytes, within
	 * the shared length, different". */
	return diff_found ? 1 : 0;
}
