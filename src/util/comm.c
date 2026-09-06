/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * comm(1p): `comm [-123] file1 file2`. Both files must already be
 * sorted in byte order (this library's only locale is "C") -- comm
 * never sorts or checks sortedness itself (see src/util/sort.c).
 *
 * OUTPUT: up to three tab-separated columns per line (only-in-file1,
 * only-in-file2, in-both), not three sections. Column 1 has no
 * leading tab; columns 2 and 3 are preceded by one tab per
 * still-shown column before them. -1/-2/-3 suppress a column
 * outright (the line is not printed, not printed with an empty
 * field).
 *
 * MERGE: classic three-way sorted merge -- the cursor holding the
 * lexicographically smaller line always advances; a tie advances both
 * and goes to column 3. EOF on one side makes every remaining line of
 * the other side compare smaller, draining it to its own column.
 *
 * EXIT STATUS: 0 success, >0 error -- unlike cmp(1p)/diff(1p), comm
 * has no "files differed" exit code, only success-or-error.
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
