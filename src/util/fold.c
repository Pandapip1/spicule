/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * fold(1p): `fold [-bs] [-w width] [file...]` -- wraps each input line
 * so no output line exceeds `width` (default 80) column positions (or
 * bytes, with -b).
 *
 * DESCRIPTION's column-position rules, each implemented literally:
 *   - <tab> advances to the next column n where n modulo 8 equals 1 --
 *     fixed at 8, unlike src/util/expand.c's configurable -t, because
 *     fold(1p) has no -t of its own.
 *   - <backspace> decrements by one, never below zero (this file's
 *     `col` is a 0-based count of columns already used, unlike
 *     src/util/expand.c's 1-based "next column"; see fold_stream()).
 *   - <carriage-return> resets to zero.
 *
 * -b counts width in bytes rather than column positions: every byte
 * counts as exactly one, including tab/backspace/CR, which lose their
 * special column-tracking meaning entirely in this mode.
 *
 * Column (non -b) mode decodes real UTF-8 via this build's mbrtowc()
 * rather than treating each byte as its own column -- see
 * src/util/cut.c's header for why; char_len() below is that same
 * decode-length helper, duplicated rather than shared for the same
 * reason cut.c's copy does. A decoded multi-byte character still
 * counts as exactly one column even when its *display* width is wider
 * (many CJK characters) -- the same simplification a locale-free
 * wc/fold always makes; real East Asian width data is out of scope.
 *
 * -s breaks a line after the last <blank> within the first `width`
 * columns (or bytes), if any -- implemented by remembering the byte
 * offset just past the most recent <blank> in the segment being built,
 * and rewinding to it (re-scanning forward, so tab stops in the
 * remainder are recomputed rather than assumed unaffected by the
 * shift) when the segment would otherwise overflow.
 *
 * A single unit (byte, or decoded character) wider than `width` by
 * itself is still emitted alone on its own output line, rather than
 * looping forever trying to make it fit -- fold(1p) doesn't define
 * this case, and making no progress is worse than the one
 * inevitably-too-wide line this produces.
 *
 * EXIT STATUS: "0 All input files were processed successfully. >0 An
 * error occurred."
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <wchar.h>
#include "util.h"
#include "ownership_stubs.h"

/* See this file's header: identical to src/util/cut.c's char_len(). */
static size_t char_len(const unsigned char *p, size_t avail)
{
	mbstate_t st;
	size_t r;

	if (avail == 0) return 0;
	memset(&st, 0, sizeof st);
	r = mbrtowc(NULL, (const char *)p, avail, &st);
	if (r == (size_t)-1 || r == (size_t)-2) return 1;
	if (r == 0) return 1;
	return r;
}

static void fold_line(const char *line, size_t len, int had_nl, long width, int opt_b, int opt_s)
{
	size_t i = 0, seg_start = 0;
	long col = 0;
	size_t last_blank = (size_t)-1;

	while (i < len) {
		unsigned char c = (unsigned char)line[i];
		size_t clen;
		long newcol;

		if (opt_b) {
			clen = 1;
			newcol = col + 1;
		} else if (c == '\t') {
			clen = 1;
			newcol = (col / 8 + 1) * 8;
		} else if (c == '\b') {
			clen = 1;
			newcol = col > 0 ? col - 1 : 0;
		} else if (c == '\r') {
			clen = 1;
			newcol = 0;
		} else {
			clen = char_len((const unsigned char *)line + i, len - i);
			newcol = col + 1;
		}

		if (newcol > width) {
			if (col == 0) {
				/* Unavoidably oversize on its own; emit it alone
				 * rather than spin -- see this file's header. */
				fwrite(line + i, 1, clen, stdout);
				fputc('\n', stdout);
				i += clen;
				seg_start = i;
				last_blank = (size_t)-1;
				continue;
			}
			if (opt_s && last_blank != (size_t)-1) {
				fwrite(line + seg_start, 1, last_blank - seg_start, stdout);
				fputc('\n', stdout);
				i = last_blank;
			} else {
				fwrite(line + seg_start, 1, i - seg_start, stdout);
				fputc('\n', stdout);
			}
			seg_start = i;
			col = 0;
			last_blank = (size_t)-1;
			continue;
		}

		if (!opt_b && (c == ' ' || c == '\t')) last_blank = i + clen;
		col = newcol;
		i += clen;
	}

	__ownership_readable_span(line + seg_start, len - seg_start);
	fwrite(line + seg_start, 1, len - seg_start, stdout);
	if (had_nl) fputc('\n', stdout);
}

static void fold_stream(FILE *f, long width, int opt_b, int opt_s)
{
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;

	while ((len = getline(&line, &cap, f)) >= 0) {
		int had_nl = (len > 0 && line[len - 1] == '\n');
		size_t n = had_nl ? (size_t)(len - 1) : (size_t)len;
		fold_line(line, n, had_nl, width, opt_b, opt_s);
	}
	free(line);
}

int __util_fold_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int opt_b = 0, opt_s = 0;
	long width = 80;
	int i = 1;
	int had_error = 0;

	for (; i < argc; i++) {
		char *a = argv[i];

		if (a[0] != '-' || a[1] == 0) break;
		if (!strcmp(a, "--")) { i++; break; }
		if (!strcmp(a, "-w") || (a[1] == 'w' && a[2])) {
			const char *arg = a[2] ? a + 2 : NULL;
			char *end;
			if (!arg) {
				if (i + 1 >= argc) { fprintf(stderr, "fold: -w: option requires an argument\n"); return 2; }
				arg = argv[++i];
			}
			width = strtol(arg, &end, 10);
			if (end == arg || *end || width < 1) {
				fprintf(stderr, "fold: %s: invalid width\n", arg);
				return 2;
			}
			continue;
		}
		{
			char *p;
			int recognized = 1;
			for (p = a + 1; *p; p++) {
				if (*p == 'b') opt_b = 1;
				else if (*p == 's') opt_s = 1;
				else { recognized = 0; break; }
			}
			if (recognized) continue;
		}
		fprintf(stderr, "fold: invalid option -- '%s'\n", a);
		return 2;
	}

	if (i >= argc) {
		fold_stream(stdin, width, opt_b, opt_s);
	} else {
		for (; i < argc; i++) {
			FILE *f = !strcmp(argv[i], "-") ? stdin : fopen(argv[i], "r");
			if (!f) {
				fprintf(stderr, "fold: %s: %s\n", argv[i], strerror(errno));
				had_error = 1;
				continue;
			}
			fold_stream(f, width, opt_b, opt_s);
			if (f != stdin) (void)fclose(f);
		}
	}

	return had_error ? 1 : 0;
}
