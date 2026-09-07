/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * expand(1p): `expand [-t tablist] [file...]` -- replaces every <tab>
 * with the spaces needed to pad to the next tab stop (src/util/
 * tablist.c/.h, shared with src/util/unexpand.c's own -t).  Default tab
 * stops are every 8th column when -t is not given.
 *
 * Backspace is copied through and decrements the column count for tab
 * calculations, floored at one; `col` here is the 1-based column the
 * next character will occupy, so the standard's 0-based "not below
 * zero" is "col not below one".
 *
 * Processed byte-at-a-time (fgetc/fputc) rather than line-buffered: no
 * line-length bound is needed, and `col` already resets on '\n' with
 * nothing else to remember across it.
 *
 * A missing/unreadable file operand is diagnosed and counted as a
 * failure; remaining operands still run (same convention as
 * src/util/cut.c and src/util/rm.c).
 *
 * EXIT STATUS: "0 Successful completion. >0 An error occurred."
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "util.h"
#include "tablist.h"

static void expand_stream(FILE *f, const struct tablist *tl)
{
	long col = 1;
	int c;

	while ((c = fgetc(f)) != EOF) {
		if (c == '\t') {
			long next = __util_tablist_next_stop(tl, col);
			if (!next) { fputc(' ', stdout); col++; }
			else { while (col < next) { fputc(' ', stdout); col++; } }
		} else if (c == '\n') {
			fputc('\n', stdout);
			col = 1;
		} else if (c == '\b') {
			fputc('\b', stdout);
			if (col > 1) col--;
		} else {
			fputc(c, stdout);
			col++;
		}
	}
}

int __util_expand_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	struct tablist tl;
	int have_t = 0;
	int i = 1;
	int had_error = 0;

	for (; i < argc; i++) {
		char *a = argv[i];

		if (a[0] != '-' || a[1] == 0) break;
		if (!strcmp(a, "--")) { i++; break; }
		if (!strcmp(a, "-t") || (a[1] == 't' && a[2])) {
			const char *spec = a[2] ? a + 2 : NULL;
			if (!spec) {
				if (i + 1 >= argc) { fprintf(stderr, "expand: -t: option requires an argument\n"); return 2; }
				spec = argv[++i];
			}
			if (__util_tablist_parse(spec, &tl) < 0) {
				fprintf(stderr, "expand: %s: invalid tablist\n", spec);
				return 2;
			}
			have_t = 1;
			continue;
		}
		fprintf(stderr, "expand: invalid option -- '%s'\n", a);
		return 2;
	}
	if (!have_t) { tl.interval = 8; tl.stops = NULL; tl.nstops = 0; }

	if (i >= argc) {
		expand_stream(stdin, &tl);
	} else {
		for (; i < argc; i++) {
			/* use_stdin, not `f != stdin`, decides the fclose() below --
			 * the checker can't prove opaque pointers unequal, so a
			 * direct comparison makes the fopen() allocation look
			 * conditionally leaked (same idiom as src/util/join.c's
			 * read_all()). */
			int use_stdin = !strcmp(argv[i], "-");
			FILE *f = use_stdin ? stdin : fopen(argv[i], "r");
			if (!f) {
				fprintf(stderr, "expand: %s: %s\n", argv[i], strerror(errno));
				had_error = 1;
				continue;
			}
			expand_stream(f, &tl);
			if (!use_stdin) (void)fclose(f);
		}
	}

	__util_tablist_free(&tl);
	return had_error ? 1 : 0;
}
