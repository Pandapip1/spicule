/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * comm(1p): `comm [-123] file1 file2`.  Both operands MUST already be
 * sorted (byte/collating order -- this library's only locale is "C",
 * src/misc/locale.c, so that is plain byte value); comm never sorts
 * anything itself and never checks that its inputs are sorted either --
 * a real, documented gotcha this file does not try to paper over by
 * second-guessing the input (see src/util/sort.c or the sort(1p) pipe
 * stage a caller is expected to have already run).
 *
 * OUTPUT: three columns -- lines only in file1, lines only in file2,
 * lines in both -- written as up to three *tab-separated* columns per
 * line, not three separate sections.  Column 1 has no leading tab.
 * Column 2 is preceded by a tab for every column *before* it that is
 * still being shown (0 or 1, i.e. one tab unless -1 suppressed column
 * 1).  Column 3 is preceded by a tab for every column before it that is
 * still shown (0, 1 or 2, i.e. -1 and -2 each drop one leading tab).
 * -1/-2/-3 suppress the corresponding column outright (that line is
 * just not printed at all, not printed with an empty field).
 *
 * MERGE: classic three-way sorted merge -- the cursor that holds the
 * lexicographically smaller of the two current lines always advances;
 * on a tie both advance together and the line goes to column 3.  EOF on
 * one side is handled by treating every remaining line of the other
 * side as if it always compared smaller (so it drains straight to its
 * own only-in-that-file column) -- see the loop below, which is where
 * this batch's "classic place for an off-by-one on which cursor
 * advances" warning actually bites if gotten wrong.
 *
 * EXIT STATUS: "0 All input files were output successfully.  >0 An
 * error occurred." -- the ordinary shape.  Worth stating plainly since
 * it would be easy to assume comm mirrors cmp(1p)/diff(1p)'s "0 same, 1
 * different, 2 trouble" convention; it does not -- comm has no notion
 * of "the files were identical" to report as a distinct exit code, only
 * success-or-error.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "util.h"

static int read_line(FILE *f, char **buf, size_t *cap, size_t *len) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	ssize_t got = getline(buf, cap, f);
	if (got < 0) return -1;
	*len = (size_t)got;
	if (*len && (*buf)[*len - 1] == '\n') (*buf)[--*len] = 0;
	return 0;
}

int __util_comm_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int show1 = 1, show2 = 1, show3 = 1;
	int i;
	const char *paths[2];
	int npaths = 0;
	FILE *f1, *f2;
	char *l1 = 0, *l2 = 0;
	size_t c1 = 0, c2 = 0, n1 = 0, n2 = 0;
	int have1, have2;
	int tabs2, tabs3, t;
	int status = 0;

	for (i = 1; i < argc; i++) {
		char *arg = argv[i];

		if (!strcmp(arg, "--")) { i++; break; }
		if (arg[0] != '-' || arg[1] == 0) break;

		{
			char *p = arg + 1;
			while (*p) {
				if (*p == '1') { show1 = 0; p++; }
				else if (*p == '2') { show2 = 0; p++; }
				else if (*p == '3') { show3 = 0; p++; }
				else {
					__util_diagf("comm: -%c: invalid option\n", *p);
					return 1;
				}
			}
		}
	}

	for (; i < argc; i++) {
		if (npaths >= 2) { __util_diagf("comm: too many operands\n"); return 1; }
		paths[npaths++] = argv[i];
	}
	if (npaths != 2) {
		__util_diagf("comm: usage: comm [-123] file1 file2\n");
		return 1;
	}

	f1 = !strcmp(paths[0], "-") ? stdin : fopen(paths[0], "r");
	if (!f1) {
		int saved = errno;
		__util_diagf("comm: %s: %s\n", paths[0], strerror(saved));
		return 1;
	}
	f2 = !strcmp(paths[1], "-") ? stdin : fopen(paths[1], "r");
	if (!f2) {
		__util_diagf("comm: %s: %s\n", paths[1], strerror(errno));
		/* Cleanup cannot supersede the primary failure to open file2. */
		if (f1 != stdin) (void)fclose(f1);
		return 1;
	}

	tabs2 = show1 ? 1 : 0;
	tabs3 = (show1 ? 1 : 0) + (show2 ? 1 : 0);

	have1 = read_line(f1, &l1, &c1, &n1) == 0;
	have2 = read_line(f2, &l2, &c2, &n2) == 0;

	while (have1 || have2) {
		int cmp;
		if (have1 && have2) {
			size_t n = n1 < n2 ? n1 : n2;
			cmp = 0;
			for (size_t j = 0; j < n; j++) {
				if (l1[j] == l2[j]) continue;
				cmp = (unsigned char)l1[j] < (unsigned char)l2[j] ? -1 : 1;
				break;
			}
			if (!cmp) cmp = n1 < n2 ? -1 : (n1 > n2 ? 1 : 0);
		} else if (have1) {
			cmp = -1;
		} else {
			cmp = 1;
		}

		if (cmp < 0) {
			if (show1) printf("%s\n", l1);
			have1 = read_line(f1, &l1, &c1, &n1) == 0;
		} else if (cmp > 0) {
			if (show2) { for (t = 0; t < tabs2; t++) putchar('\t'); printf("%s\n", l2); }
			have2 = read_line(f2, &l2, &c2, &n2) == 0;
		} else {
			if (show3) { for (t = 0; t < tabs3; t++) putchar('\t'); printf("%s\n", l1); }
			have1 = read_line(f1, &l1, &c1, &n1) == 0;
			have2 = read_line(f2, &l2, &c2, &n2) == 0;
		}
	}

	free(l1);
	free(l2);
	if (f1 != stdin && fclose(f1) != 0) status = 1;
	if (f2 != stdin && fclose(f2) != 0) status = 1;
	if (fflush(stdout) != 0) status = 1;
	return status;
}
