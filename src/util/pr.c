/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * pr(1p): paginate text files for a line-printer device -- a five-line
 * header (blank, blank, "date pathname Page N", blank, blank; date via
 * strftime("%b %e %H:%M %Y")), a body of `page length` lines (default
 * 66), and a five-line trailer, repeated per page. Page numbering is
 * continuous across every file operand; each operand always starts a
 * fresh page, and every page (including a file's own short last one)
 * is padded with blank filler lines before its trailer -- some real pr
 * implementations leave the truly last page unpadded, this one does
 * not.
 *
 * SCOPE: only the default single-column mode is implemented solidly.
 * Multi-column mode (bare `-column`, `-a`, `-w`'s real effect), `-m`
 * (merge files side by side into columns), `-e`/`-i` (tab expansion),
 * `-s` (XSI column separator), and `+page` need a different, buffering
 * output engine this file does not implement -- all refused with a
 * diagnostic and nonzero exit rather than half-implemented. `-w` is
 * accepted and stored but inert here (it only affects multi-column
 * output).
 *
 * IMPLEMENTED: -h header (replace pathname in header), -l lines (page
 * length), -o offset (indent every output line), -n[char][width]
 * (number text lines, default width 5, default separator <tab>), -t
 * (omit header/trailer), -d (double-space), -F (form-feed page
 * separator instead of the blank-line trailer; -f is a synonym -- this
 * build has no terminal to pause in front of, -f's only real
 * difference), -r (suppress "failed to open" diagnostics; still a
 * nonzero exit).
 *
 * EXIT STATUS: 0 success, >0 error.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include "util.h"

struct pr_opts {
	int page_len;      /* -l, default 66 */
	int offset;        /* -o, default 0 */
	int width;          /* -w, parsed but inert -- see this file's header */
	const char *header; /* -h, 0 = use each file's own pathname */
	int opt_t, opt_d, opt_F, opt_r;
	int opt_n;
	char n_sepchar;
	int n_width;
};

static long g_page_no; /* continuous across every file operand */
static int pr_output_failed;

static void emit_offset(const struct pr_opts *o)
{
	int i;
	for (i = 0; i < o->offset; i++) putchar(' ');
}

/* Every blank output line in the header/trailer/filler machinery is
 * offset+newline, so that pair is folded into one call here. */
static void emit_blank_line(const struct pr_opts *o)
{
	emit_offset(o);
	putchar('\n');
}

static void emit_header(const struct pr_opts *o, const char *fname)
{
	char datebuf[64];
	time_t now = time(0);
	struct tm *tmv = now != (time_t)-1 ? localtime(&now) : 0;

	if (tmv && strftime(datebuf, sizeof datebuf, "%b %e %H:%M %Y", tmv) == 0) {
		datebuf[0] = 0;
		pr_output_failed = 1;
	}
	else datebuf[0] = 0;

	emit_blank_line(o);
	emit_blank_line(o);
	emit_offset(o); printf("%s %s Page %ld\n", datebuf, fname, g_page_no);
	emit_blank_line(o);
	emit_blank_line(o);
}

static void emit_trailer(const struct pr_opts *o)
{
	int i;
	if (o->opt_F) { putchar('\f'); return; }
	for (i = 0; i < 5; i++) emit_blank_line(o);
}

struct prstate {
	const struct pr_opts *o;
	const char *fname;
	long lineno;
	long long lines_on_page;
	int budget;
	int page_open;
};

static int increment_long(long *value, const char *what)
{
	if (*value < 0 || *value >= LONG_MAX) {
		errno = EOVERFLOW;
		__util_diagf("pr: %s exceeds LONG_MAX\n", what);
		return -1;
	}
	*value = (long)((unsigned long)*value + 1UL);
	return 0;
}

static int start_page(struct prstate *st)
{
	if (increment_long(&g_page_no, "page count") < 0) return -1;
	if (!st->o->opt_t) emit_header(st->o, st->fname);
	st->lines_on_page = 0;
	st->page_open = 1;
	return 0;
}

static int page_body_fits(const struct prstate *st)
{
	long long limit = st->o->opt_d ? (long long)INT_MAX - 1 : INT_MAX;

	if (st->lines_on_page < 0 || st->lines_on_page > limit) {
		errno = EOVERFLOW;
		__util_diagf("pr: page line count exceeds its proven bound\n");
		return -1;
	}
	return 0;
}

static void end_page(struct prstate *st)
{
	while (st->lines_on_page < st->budget) {
		emit_blank_line(st->o);
		st->lines_on_page++;
	}
	if (!st->o->opt_t) emit_trailer(st->o);
	st->page_open = 0;
}

static int process_stream(const struct pr_opts *o, FILE *f, const char *fname)
{
	struct prstate st;
	char *line = 0;
	size_t cap = 0;
	int rc = 0, saved_errno = 0;

	/* Shared "record the failure and unwind to cleanup" step for every
	 * failure path below. */
#define PR_FAIL() do { rc = -1; saved_errno = errno; goto done; } while (0)

	st.o = o;
	st.fname = fname;
	st.lineno = 0;
	st.lines_on_page = 0;
	st.page_open = 0;
	st.budget = o->opt_t ? o->page_len : (o->page_len - 10);
	if (st.budget <= 0) {
		__util_diagf("pr: page length %d is too small for a header and trailer\n", o->page_len);
		return -1;
	}

	for (;;) {
		ssize_t n = getline(&line, &cap, f);
		size_t len;
		if (n < 0) break;
		if (increment_long(&st.lineno, "line count") < 0) PR_FAIL();
		len = (size_t)n;
		if (len > 0 && line[len - 1] == '\n') { line[len - 1] = 0; len--; }

		if (!st.page_open || st.lines_on_page >= st.budget) {
			if (st.page_open) end_page(&st);
			if (start_page(&st) < 0) PR_FAIL();
		}
		if (page_body_fits(&st) < 0) PR_FAIL();

		if (o->opt_n) printf("%*ld%c", o->n_width, st.lineno, o->n_sepchar);
		emit_offset(o);
		if (fputs(line, stdout) < 0) pr_output_failed = 1;
		putchar('\n');
		st.lines_on_page++;

		if (o->opt_d) {
			emit_blank_line(o);
			st.lines_on_page++;
		}
	}

done:
	free(line);

	if (st.page_open) end_page(&st);
	if (rc < 0) errno = saved_errno;
	return rc;
#undef PR_FAIL
}

static int process_file(const struct pr_opts *o, const char *path)
{
	FILE *f;
	int rc;
	const char *fname = o->header ? o->header : path;

	if (!strcmp(path, "-")) {
		f = stdin;
		fname = o->header ? o->header : "";
	} else {
		f = fopen(path, "r");
		if (!f) {
			if (!o->opt_r) __util_diagf("pr: %s: %s\n", path, strerror(errno));
			return -1;
		}
	}
	rc = process_stream(o, f, fname);
	if (f != stdin && fclose(f) != 0) rc = -1;
	if (pr_output_failed || fflush(stdout) != 0) rc = -1;
	return rc;
}

static int parse_n_opt(const char *rest, struct pr_opts *o)
{
	o->opt_n = 1;
	o->n_sepchar = '\t';
	o->n_width = 5;
	if (*rest && !(*rest >= '0' && *rest <= '9')) { o->n_sepchar = *rest; rest++; }
	if (*rest) {
		char *end;
		long w = strtol(rest, &end, 10);
		if (*end || w <= 0) return -1;
		o->n_width = (int)w;
	}
	return 0;
}

int __util_pr_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	struct pr_opts o;
	int i = 1;
	int had_error = 0;
	pr_output_failed = 0;

	/* g_page_no is file-scope to avoid threading it through
	 * emit_header()/emit_trailer(), but must be reset on every entry:
	 * as a shell builtin (bi_pr(), src/sh/builtin.c) this can run many
	 * times in one process, and each `pr` invocation restarts at page 1. */
	g_page_no = 0;

	o.page_len = 66;
	o.offset = 0;
	o.width = 72;
	o.header = 0;
	o.opt_t = o.opt_d = o.opt_F = o.opt_r = o.opt_n = 0;
	o.n_sepchar = '\t';
	o.n_width = 5;

	for (; i < argc; i++) {
		char *a = argv[i];

		if (a[0] == '+') {
			__util_diagf("pr: %s: +page is not implemented -- see src/util/pr.c\n", a);
			return 1;
		}
		if (a[0] != '-' || a[1] == 0) break;
		if (!strcmp(a, "--")) { i++; break; }
		if (a[1] >= '0' && a[1] <= '9') {
			__util_diagf("pr: %s: multi-column mode is not implemented -- "
			                "see src/util/pr.c\n", a);
			return 1;
		}
		if (!strcmp(a, "-t")) { o.opt_t = 1; continue; }
		if (!strcmp(a, "-d")) { o.opt_d = 1; continue; }
		if (!strcmp(a, "-F") || !strcmp(a, "-f")) { o.opt_F = 1; continue; }
		if (!strcmp(a, "-r")) { o.opt_r = 1; continue; }
		if (!strcmp(a, "-h")) {
			if (i + 1 >= argc) { __util_diagf("pr: -h: option requires an argument\n"); return 1; }
			o.header = argv[++i];
			continue;
		}
		if (!strcmp(a, "-l")) {
			char *end;
			if (i + 1 >= argc) { __util_diagf("pr: -l: option requires an argument\n"); return 1; }
			o.page_len = (int)strtol(argv[++i], &end, 10);
			if (*end || o.page_len <= 0) { __util_diagf("pr: -l: invalid page length\n"); return 1; }
			continue;
		}
		if (!strcmp(a, "-o")) {
			char *end;
			if (i + 1 >= argc) { __util_diagf("pr: -o: option requires an argument\n"); return 1; }
			o.offset = (int)strtol(argv[++i], &end, 10);
			if (*end || o.offset < 0) { __util_diagf("pr: -o: invalid offset\n"); return 1; }
			continue;
		}
		if (!strcmp(a, "-w")) {
			char *end;
			if (i + 1 >= argc) { __util_diagf("pr: -w: option requires an argument\n"); return 1; }
			o.width = (int)strtol(argv[++i], &end, 10);
			if (*end || o.width <= 0) { __util_diagf("pr: -w: invalid width\n"); return 1; }
			continue;
		}
		if (a[1] == 'n') {
			if (parse_n_opt(a + 2, &o) < 0) {
				__util_diagf("pr: %s: invalid -n argument\n", a);
				return 1;
			}
			continue;
		}
		if (!strcmp(a, "-m")) {
			__util_diagf("pr: -m: merging files side by side is not implemented "
			                "-- see src/util/pr.c\n");
			return 1;
		}
		if (!strcmp(a, "-e") || !strcmp(a, "-i")) {
			__util_diagf("pr: %s: tab expansion is not implemented -- see "
			                "src/util/pr.c\n", a);
			return 1;
		}
		if (!strcmp(a, "-a") || !strcmp(a, "-s")) {
			__util_diagf("pr: %s: is not implemented -- see src/util/pr.c\n", a);
			return 1;
		}
		__util_diagf("pr: %s: invalid option\n", a);
		return 1;
	}

	if (i >= argc) {
		if (process_file(&o, "-") < 0) had_error = 1;
		return had_error ? 1 : 0;
	}

	for (; i < argc; i++)
		if (process_file(&o, argv[i]) < 0) had_error = 1;

	return had_error ? 1 : 0;
}
