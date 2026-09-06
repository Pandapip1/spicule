/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * diff(1p): `diff [-c|-e|-f|-u|-C n|-U n] [-br] file1 file2`. Checked
 * against the real XCU diff(1p) page.
 *
 * OPTIONS MANDATED: exactly -b, -c, -C n, -e, -f, -r, -u, -U n -- all
 * eight, none XSI-tagged. -i/-l/-n/-s/-w are not in that list and are
 * not implemented; an unrecognized flag is a usage error (exit 2), not
 * a no-op. -u/-U are genuinely mandatory, not a GNU-only extension --
 * verified against the page's OPTIONS list, since that folklore may
 * hold for some historical/BSD diff(1)s but not POSIX's own text. -C's
 * n must be a positive integer (>=1); -U's n a non-negative integer
 * (>=0), an asymmetry both enforced below. -c/-e/-f/-u/-C/-U are
 * mutually exclusive (the SYNOPSIS groups them with '|'); more than one
 * is refused.
 *
 * DIRECTORY OPERANDS ARE ALSO MANDATORY, NOT XSI: a plain `diff dir1
 * dir2` (no -r) has real, defined behavior in the OPERANDS section, not
 * gated on -r. -r only controls whether a common subdirectory is
 * *recursed into*; top-level pairing/comparison of two directory
 * operands happens either way.
 *
 * DEFAULT (ed-script-like) FORMAT: each hunk is a header line --
 * "%da%d"/"%dd%d"/"%dc%d" (or "%d,%da%d"/... for a multi-line range) --
 * followed by file1's affected lines each prefixed "< ", a "---\n"
 * separator if both sides have lines, then file2's lines prefixed "> ".
 *
 * -c/-C n and -u/-U n need one real algorithmic feature the prose
 * doesn't spell out: adjacent hunks whose padding (n lines of context)
 * would overlap or touch must be merged into one printed group sharing
 * a contiguous context block, not printed as two blocks with duplicated
 * context. The exact empty-range and multi-hunk-grouping conventions
 * below were confirmed against GNU diffutils 3.12 rather than guessed,
 * since XCU describes the format only in general terms; the substantive
 * format (headers, "***"/"---"/"+++"/"@@" lines, "!"/"+"/"-"/" "
 * prefixes, context width) is the STDOUT section's own text.
 *
 * TIMESTAMPS in -c/-u headers: real file mtimes via stat(), formatted
 * per the STDOUT section's strftime-style descriptions. Fractional
 * seconds are not implemented for either format (the spec calls it
 * optional for -u, silent for -c). A "-" operand (stdin) uses the
 * current time, since it has no real mtime.
 *
 * -e (ed script) and -f (its "alternative form"): the STDOUT section
 * gives -e's shape (a/c/d commands, "." terminates text, hunks ordered
 * end-to-beginning so already-emitted line numbers stay valid) but not
 * every punctuation detail; the RATIONALE section's three -f
 * differences (reverse hunk order, command letter before the range,
 * space- instead of comma-separated ranges) were additionally
 * cross-checked against real diffutils output. A missing trailing
 * newline has no defined -e/-f handling in XCU (unlike -c/-u/default's
 * "\ No newline at end of file" marker); this implementation reports it
 * as a stderr diagnostic once per affected operand and promotes the
 * exit status from 1 to 2 for that case, matching real diffutils: the
 * script printed cannot faithfully reproduce the missing-newline file.
 *
 * -b: trailing whitespace is stripped from each line before comparing,
 * and any nonempty run of spaces/tabs at the same logical position in
 * both lines compares equal regardless of length (lines_equal_b()
 * below). A displayed "shared" context line always uses file1's exact
 * text, since XCU does not say whose copy of a -b-equal-but-not-
 * identical line to show.
 *
 * ALGORITHM: the classic Myers O(ND) trace-storing algorithm
 * (myers_build_ops() below) -- O(ND) time *and* space, not the
 * linear-space divide-and-conquer variant of the same paper. Good
 * enough for realistic shell-utility file sizes; not safe against
 * adversarially-dissimilar multi-gigabyte inputs (D approaching N+M
 * costs O((N+M)^2) memory).
 *
 * Both files are read fully into memory before any comparison starts --
 * unlike cmp(1p) (src/util/cmp.c), diff needs random access to both
 * files' lines to compute an edit script at all.
 *
 * EXIT STATUS: 0 no differences; 1 differences found; >1 an error
 * occurred.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <sys/stat.h>
#include <dirent.h>
#include "util.h"
#include "ownership_stubs.h"

/* ==== line storage ======================================================== */

struct dline { const char *s; size_t len; };

static int read_whole_stream(FILE *f, char **out withtok(heap_allocated),
                             size_t *outlen)
{
	size_t cap = 65536, len = 0;
	char *buf = malloc(cap);
	if (!buf) return 0;
	for (;;) {
		size_t got;
		if (len == cap) {
			size_t newcap;
			char *g;
			if (!__util_array_capacity(cap, cap, 1, 65536, 1, &newcap)) { free(buf); return 0; }
			g = realloc(buf, newcap);
			if (!g) { free(buf); return 0; }
			buf = g; cap = newcap;
		}
		__ownership_writable_span(buf + len, cap - len);
		got = fread(buf + len, 1, cap - len, f);
		len += got;
		if (got == 0) break;
	}
	if (ferror(f)) { free(buf); return 0; }
	*out = buf;
	*outlen = len;
	return 1;
}

static struct dline *dline_grow(struct dline *out, size_t *cap, size_t used)
{
	size_t newcap;
	struct dline *g;
	if (!__util_array_capacity(*cap, used, 1, 256, sizeof *out, &newcap)) return 0;
	g = __util_reallocarray(out, newcap, sizeof *out);
	if (!g) return 0;
	*cap = newcap;
	return g;
}

/* Splits `buf` (length `len`) into lines with the trailing '\n' of each
 * stripped from the stored length (never copied -- every dline points
 * straight into `buf`, so `buf` must outlive the returned array).  If
 * the last "line" has no trailing '\n' at all, *noeol is set and that
 * partial line is still included -- diff still needs to compare and
 * display it, matching real diff's own handling of a missing final
 * newline (see the header comment's -c/-u/default "\ No newline..."
 * marker and the -e/-f stderr diagnostic). */
static struct dline *split_lines(const char *buf, size_t len, size_t *nout, int *noeol)
{
	struct dline *out = 0;
	size_t cap = 0, n = 0;
	size_t i, start = 0;

	*noeol = 0;
	for (i = 0; i < len; i++) {
		if (buf[i] == '\n') {
			if (n >= cap) {
				struct dline *g = dline_grow(out, &cap, n);
				if (!g) { free(out); *nout = 0; return 0; }
				out = g;
			}
			out[n].s = buf + start;
			out[n].len = i - start;
			n++;
			start = i + 1;
		}
	}
	if (start < len) {
		if (n >= cap) {
			struct dline *g = dline_grow(out, &cap, n);
			if (!g) { free(out); *nout = 0; return 0; }
			out = g;
		}
		out[n].s = buf + start;
		out[n].len = len - start;
		n++;
		*noeol = 1;
	}
	*nout = n;
	return out;
}

/* ==== -b comparison ======================================================== */

static int is_blank_byte(unsigned char c) { return c == ' ' || c == '\t'; }

/* -b semantics: trailing blanks on either line never count, and any
 * nonempty run of blanks at the same logical position in both lines
 * compares equal to any other nonempty run there regardless of how
 * many characters make it up on either side. */
static int lines_equal_b(const char *a, size_t alen, const char *b, size_t blen)
{
	size_t ai = 0, bi = 0;

	while (alen > 0 && is_blank_byte((unsigned char)a[alen - 1])) alen--;
	while (blen > 0 && is_blank_byte((unsigned char)b[blen - 1])) blen--;

	for (;;) {
		int ablank = ai < alen && is_blank_byte((unsigned char)a[ai]);
		int bblank = bi < blen && is_blank_byte((unsigned char)b[bi]);
		if (ablank && bblank) {
			while (ai < alen && is_blank_byte((unsigned char)a[ai])) ai++;
			while (bi < blen && is_blank_byte((unsigned char)b[bi])) bi++;
			continue;
		}
		if (ablank != bblank) return 0;
		if (ai >= alen && bi >= blen) return 1;
		if (ai >= alen || bi >= blen) return 0;
		if (a[ai] != b[bi]) return 0;
		ai++; bi++;
	}
}

static int dline_equal(const struct dline *a, const struct dline *b, int bflag)
{
	if (!bflag)
		return a->len == b->len && (a->len == 0 || memcmp(a->s, b->s, a->len) == 0);
	return lines_equal_b(a->s, a->len, b->s, b->len);
}

/* A line at the very end of a file that has no trailing newline is a
 * genuinely different thing from an otherwise-identical line that does
 * have one -- collapsing them into "the same line" would make the
 * resulting hunk list not touch that line at all, silently losing the
 * "no newline at end of file" fact entirely (nothing else in the
 * printed output would ever mention it, since the marker below is only
 * ever emitted for a line that is actually part of a hunk body).
 * Confirmed empirically (not guessed) against real diffutils: `diff`
 * on a one-line file containing "d" with no trailing newline against
 * one containing "d\n" reports them as different (a 1c1 hunk), while
 * two files both containing "d" with no trailing newline at all report
 * no difference -- i.e. two truncated final lines can still match each
 * other by content, but a truncated final line never matches a
 * non-final (or non-truncated-final) line even with identical text. */
static int lines_equal_final(const struct dline *a, long ai, long na, int noeol_a,
	const struct dline *b, long bi, long nb, int noeol_b, int bflag)
{
	int a_trunc = noeol_a && (ai + 1 == na);
	int b_trunc = noeol_b && (bi + 1 == nb);
	if (a_trunc != b_trunc) return 0;
	return dline_equal(&a[ai], &b[bi], bflag);
}

/* ==== Myers O(ND) shortest-edit-script ===================================== */

enum optype { OP_MATCH, OP_DEL, OP_INS };
struct editop { unsigned char type; size_t ai, bi; };

static int editop_push(struct editop **ops withtok(heap_allocated), size_t *cap,
	size_t *n, unsigned char type, size_t ai, size_t bi)
{
	if (*n >= *cap) {
		size_t newcap;
		struct editop *g;
		if (!__util_array_capacity(*cap, *n, 1, 256, sizeof **ops, &newcap)) return 0;
		g = __util_reallocarray(*ops, newcap, sizeof **ops);
		if (!g) return 0;
		*ops = g;
		*cap = newcap;
	}
	(*ops)[*n].type = type;
	(*ops)[*n].ai = ai;
	(*ops)[*n].bi = bi;
	(*n)++;
	return 1;
}

/* The classic trace-storing Myers diff: forward pass finds the shortest
 * edit distance D by growing "snakes" (runs of matching lines) along
 * each diagonal k = x-y, saving the whole V array after each D so the
 * backward pass can reconstruct which diagonal was taken at every step.
 * See this file's header comment for the O(ND) space tradeoff this
 * implies. `ops` comes out in file order (a match/delete/insert per
 * line consumed from whichever file it came from). */
static int myers_build_ops(const struct dline *a, long n, int noeol_a,
	const struct dline *b, long m, int noeol_b,
	int bflag, struct editop **out_ops withtok(heap_allocated), size_t *out_nops)
{
	long max = n + m;
	long vsize, off, d, found_d = -1;
	/* v/trace/saved/vv store edit-graph x-coordinates, which range up to
	 * n (== na, a file's line count) -- these must be the same width as
	 * n/m/x/y (long) themselves.  Storing them as `int` would silently
	 * truncate for a single input file with more than INT_MAX lines,
	 * corrupting the backward pass's reconstructed x/y positions (and,
	 * via editop_push()'s size_t cast of a wrapped-negative x/y, could
	 * turn into an out-of-bounds index into the line arrays). */
	long *v;
	long **trace;
	struct editop *ops = 0;
	size_t opscap = 0, nops = 0;
	long x, y;

	*out_ops = 0;
	*out_nops = 0;
	if (max == 0) return 1;

	off = max;
	vsize = 2 * max + 1;
	v = __util_mallocarray((size_t)vsize, sizeof *v);
	if (!v) return 0;
	trace = __util_mallocarray((size_t)(max + 1), sizeof *trace);
	if (!trace) { free(v); return 0; }
	{
		long i;
		for (i = 0; i <= max; i++) trace[i] = 0;
	}

	v[1 + off] = 0;

	for (d = 0; d <= max; d++) {
		long k;
		long *saved;

		for (k = -d; k <= d; k += 2) {
			long xk, yk;
			if (k == -d || (k != d && v[k - 1 + off] < v[k + 1 + off]))
				xk = v[k + 1 + off];
			else
				xk = v[k - 1 + off] + 1;
			yk = xk - k;
			while (xk < n && yk < m && lines_equal_final(a, xk, n, noeol_a, b, yk, m, noeol_b, bflag)) { xk++; yk++; }
			v[k + off] = xk;
			if (xk >= n && yk >= m) found_d = d;
		}

		saved = __util_mallocarray((size_t)vsize, sizeof *saved);
		if (!saved) {
			free(v);
			for (k = 0; k < d; k++) free(trace[k]);
			free(trace);
			return 0;
		}
		memcpy(saved, v, (size_t)vsize * sizeof *v);
		trace[d] = saved;

		if (found_d >= 0) break;
	}
	free(v);

	x = n; y = m;
	{
		long dd;
		for (dd = found_d; dd >= 1; dd--) {
			long *vv = trace[dd - 1];
			long k = x - y;
			long prev_k, prev_x, prev_y;
			if (k == -dd || (k != dd && vv[k - 1 + off] < vv[k + 1 + off]))
				prev_k = k + 1;
			else
				prev_k = k - 1;
			prev_x = vv[prev_k + off];
			prev_y = prev_x - prev_k;

			while (x > prev_x && y > prev_y) {
				if (!editop_push(&ops, &opscap, &nops, OP_MATCH, (size_t)(x - 1), (size_t)(y - 1)))
					goto oom;
				x--; y--;
			}
			if (x == prev_x) {
				if (!editop_push(&ops, &opscap, &nops, OP_INS, (size_t)x, (size_t)(y - 1)))
					goto oom;
				y--;
			} else {
				if (!editop_push(&ops, &opscap, &nops, OP_DEL, (size_t)(x - 1), (size_t)y))
					goto oom;
				x--;
			}
		}
		while (x > 0 && y > 0 && lines_equal_final(a, x - 1, n, noeol_a, b, y - 1, m, noeol_b, bflag)) {
			if (!editop_push(&ops, &opscap, &nops, OP_MATCH, (size_t)(x - 1), (size_t)(y - 1)))
				goto oom;
			x--; y--;
		}
	}

	{
		long i;
		for (i = 0; i <= found_d; i++) free(trace[i]);
	}
	free(trace);

	/* Backtracking walks from (N,M) to (0,0), so ops[] above was
	 * appended in reverse file order; flip it in place. */
	if (nops) {
		size_t lo = 0, hi = nops - 1;
		while (lo < hi) {
			struct editop t = ops[lo];
			ops[lo] = ops[hi];
			ops[hi] = t;
			lo++; hi--;
		}
	}

	*out_ops = ops;
	*out_nops = nops;
	return 1;

oom:
	free(ops);
	{
		long i;
		for (i = 0; i <= found_d; i++) free(trace[i]);
	}
	free(trace);
	return 0;
}

/* ==== hunks: maximal runs of non-match ops ================================ */

struct hunk { size_t a0, a1, b0, b1; };

static int hunk_push(struct hunk **hunks, size_t *cap, size_t *n,
	size_t a0, size_t a1, size_t b0, size_t b1)
{
	if (*n >= *cap) {
		size_t newcap;
		struct hunk *g;
		if (!__util_array_capacity(*cap, *n, 1, 32, sizeof **hunks, &newcap)) return 0;
		g = __util_reallocarray(*hunks, newcap, sizeof **hunks);
		if (!g) return 0;
		*hunks = g;
		*cap = newcap;
	}
	(*hunks)[*n].a0 = a0; (*hunks)[*n].a1 = a1;
	(*hunks)[*n].b0 = b0; (*hunks)[*n].b1 = b1;
	(*n)++;
	return 1;
}

/* *ok is a real, separate failure signal (not just "hunks came back
 * NULL") because NULL is also the *correct* return for the common
 * "files are identical, zero hunks" case -- nops can be nonzero (every
 * op a MATCH) while genuinely producing no hunks at all, and that must
 * not be mistaken for hunk_push() having failed to allocate. */
static struct hunk *build_hunks(const struct editop *ops, size_t nops, size_t *out_n, int *ok)
{
	struct hunk *hunks = 0;
	size_t cap = 0, n = 0;
	size_t ai = 0, bi = 0;
	size_t hstart_a = 0, hstart_b = 0;
	int in_hunk = 0;
	size_t i;

	*ok = 1;
	for (i = 0; i < nops; i++) {
		const struct editop *op = &ops[i];
		if (op->type == OP_MATCH) {
			if (in_hunk) {
				if (!hunk_push(&hunks, &cap, &n, hstart_a, ai, hstart_b, bi)) { free(hunks); *out_n = 0; *ok = 0; return 0; }
				in_hunk = 0;
			}
			ai++; bi++;
		} else if (op->type == OP_DEL) {
			if (!in_hunk) { hstart_a = ai; hstart_b = bi; in_hunk = 1; }
			ai++;
		} else {
			if (!in_hunk) { hstart_a = ai; hstart_b = bi; in_hunk = 1; }
			bi++;
		}
	}
	if (in_hunk) {
		if (!hunk_push(&hunks, &cap, &n, hstart_a, ai, hstart_b, bi)) { free(hunks); *out_n = 0; *ok = 0; return 0; }
	}
	*out_n = n;
	return hunks;
}

static int line_in_any_hunk_a(const struct hunk *hunks, size_t nh, size_t idx)
{
	size_t i;
	for (i = 0; i < nh; i++) if (idx >= hunks[i].a0 && idx < hunks[i].a1) return 1;
	return 0;
}

static int line_in_any_hunk_b(const struct hunk *hunks, size_t nh, size_t idx)
{
	size_t i;
	for (i = 0; i < nh; i++) if (idx >= hunks[i].b0 && idx < hunks[i].b1) return 1;
	return 0;
}

/* ==== shared range/line printing =========================================== */

/* [r0,r1) 0-based -> the default/-c/-u-header convention: an empty
 * range prints as the bare (0-based) position with no adjustment (this
 * is deliberately the same number a 1-based "insert/delete after this
 * line" reading would give); a single line prints as its 1-based
 * number; anything wider prints as "start,end" (1-based, inclusive),
 * or "start end" if `sep` is a space (that space form is -f's, per
 * this file's header comment on the RATIONALE section). */
static void print_range(FILE *out, size_t r0, size_t r1, char sep)
{
	if (r0 == r1) fprintf(out, "%zu", r0);
	else if (r1 == r0 + 1) fprintf(out, "%zu", r0 + 1);
	else fprintf(out, "%zu%c%zu", r0 + 1, sep, r1);
}

/* Unified format's own convention is different from print_range()'s:
 * "beginning line, count" rather than "start,end", and an empty range
 * is spelled "%zu,0" (not just a bare number) -- confirmed against
 * real diffutils -U0 output on deliberately pure-insert/pure-delete
 * cases (see this file's header comment). */
static void print_unified_range(FILE *out, size_t r0, size_t r1)
{
	size_t count = r1 - r0;
	if (count == 0) fprintf(out, "%zu,0", r0);
	else if (count == 1) fprintf(out, "%zu", r0 + 1);
	else fprintf(out, "%zu,%zu", r0 + 1, count);
}

enum side { SIDE_A, SIDE_B };

static void print_ctxline(FILE *out, const char *prefix, enum side side,
	const struct dline *a, size_t na, int noeol_a,
	const struct dline *b, size_t nb, int noeol_b, size_t idx)
{
	const struct dline *lines = (side == SIDE_A) ? a : b;
	size_t n = (side == SIDE_A) ? na : nb;
	int noeol = (side == SIDE_A) ? noeol_a : noeol_b;

	/* fwrite(), not fprintf("%.*s", (int)len, ...): a dline's length is
	 * size_t and its text is not NUL-terminated (it points straight into
	 * the mmap'd/malloc'd file buffer -- see split_lines()).  A single
	 * input line at or beyond 2 GiB would have its length silently
	 * truncated by a (int) cast, and on wraparound to a *negative* int,
	 * printf's "%.*s" treats a negative precision as "no precision at
	 * all" (C11 7.21.6.1p5) -- i.e. it would print until a stray NUL
	 * byte turns up in the untrimmed buffer, an out-of-bounds read past
	 * the actual line. fwrite()'s count is size_t, so no such truncation
	 * is possible regardless of line length. */
	fputs(prefix, out);
	fwrite(lines[idx].s, 1, lines[idx].len, out);
	fputc('\n', out);
	if (noeol && idx + 1 == n) fprintf(out, "\\ No newline at end of file\n");
}

/* ==== default (ed-script-like) format ====================================== */

static void print_default(FILE *out, const struct hunk *hunks, size_t nh,
	const struct dline *a, size_t na, int noeol_a,
	const struct dline *b, size_t nb, int noeol_b)
{
	size_t i;
	for (i = 0; i < nh; i++) {
		const struct hunk *h = &hunks[i];
		int a_empty = h->a0 == h->a1;
		int b_empty = h->b0 == h->b1;
		char cmd;
		size_t j;

		if (a_empty) cmd = 'a';
		else if (b_empty) cmd = 'd';
		else cmd = 'c';

		print_range(out, h->a0, h->a1, ',');
		fputc(cmd, out);
		print_range(out, h->b0, h->b1, ',');
		fputc('\n', out);

		for (j = h->a0; j < h->a1; j++) print_ctxline(out, "< ", SIDE_A, a, na, noeol_a, b, nb, noeol_b, j);
		if (!a_empty && !b_empty) fprintf(out, "---\n");
		for (j = h->b0; j < h->b1; j++) print_ctxline(out, "> ", SIDE_B, a, na, noeol_a, b, nb, noeol_b, j);
	}
}

/* ==== -e (ed script) and -f (its "alternative form") ======================= */

/* fwrite(), not fprintf("%.*s", (int)len, ...) -- see print_ctxline()'s
 * comment on why a size_t line length truncated to int (and, on a line at
 * or past 2 GiB, wrapped negative) turns "%.*s" into an unbounded,
 * out-of-bounds read of the non-NUL-terminated dline text. */
static void print_line_body(FILE *out, const struct dline *l)
{
	fwrite(l->s, 1, l->len, out);
	fputc('\n', out);
}

static void print_ed(FILE *out, const struct hunk *hunks, size_t nh, const struct dline *b)
{
	size_t i;
	for (i = nh; i > 0; i--) {
		const struct hunk *h = &hunks[i - 1];
		int a_empty = h->a0 == h->a1;
		int b_empty = h->b0 == h->b1;
		size_t j;

		if (b_empty) {
			print_range(out, h->a0, h->a1, ',');
			fprintf(out, "d\n");
			continue;
		}
		if (a_empty) fprintf(out, "%zua\n", h->a0);
		else { print_range(out, h->a0, h->a1, ','); fprintf(out, "c\n"); }
		for (j = h->b0; j < h->b1; j++) print_line_body(out, &b[j]);
		fprintf(out, ".\n");
	}
}

static void print_falt(FILE *out, const struct hunk *hunks, size_t nh, const struct dline *b)
{
	size_t i;
	for (i = 0; i < nh; i++) {
		const struct hunk *h = &hunks[i];
		int a_empty = h->a0 == h->a1;
		int b_empty = h->b0 == h->b1;
		size_t j;

		if (b_empty) {
			fputc('d', out);
			print_range(out, h->a0, h->a1, ' ');
			fputc('\n', out);
			continue;
		}
		if (a_empty) fprintf(out, "a%zu\n", h->a0);
		else { fputc('c', out); print_range(out, h->a0, h->a1, ' '); fputc('\n', out); }
		for (j = h->b0; j < h->b1; j++) print_line_body(out, &b[j]);
		fprintf(out, ".\n");
	}
}

/* ==== -c/-C and -u/-U: hunk grouping by overlapping context ================ */

struct group { size_t hstart, hend; size_t ga0, ga1, gb0, gb1; };

static int group_push(struct group **groups withtok(heap_allocated), size_t *cap,
	size_t *n, size_t hstart, size_t hend, size_t ga0, size_t ga1, size_t gb0,
	size_t gb1)
{
	if (*n >= *cap) {
		size_t newcap;
		struct group *g;
		if (!__util_array_capacity(*cap, *n, 1, 16, sizeof **groups, &newcap)) return 0;
		g = __util_reallocarray(*groups, newcap, sizeof **groups);
		if (!g) return 0;
		*groups = g;
		*cap = newcap;
	}
	(*groups)[*n].hstart = hstart; (*groups)[*n].hend = hend;
	(*groups)[*n].ga0 = ga0; (*groups)[*n].ga1 = ga1;
	(*groups)[*n].gb0 = gb0; (*groups)[*n].gb1 = gb1;
	(*n)++;
	return 1;
}

/* Two hunks are merged into one printed group whenever the padding
 * (`context` lines on each side) that -c/-u would add around them
 * would overlap or touch -- the standard "gap <= 2*context" test. */
static struct group *build_groups(const struct hunk *hunks, size_t nh, size_t context,
	size_t na, size_t nb, size_t *out_ng)
{
	struct group *groups = 0;
	size_t cap = 0, ng = 0;
	size_t i;

	*out_ng = 0;
	if (nh == 0) return 0;

	for (i = 0; i < nh; ) {
		size_t j = i + 1;
		size_t ga0, ga1, gb0, gb1;
		while (j < nh && hunks[j].a0 <= hunks[j - 1].a1 + 2 * context) j++;

		ga0 = hunks[i].a0 > context ? hunks[i].a0 - context : 0;
		gb0 = hunks[i].b0 > context ? hunks[i].b0 - context : 0;
		ga1 = hunks[j - 1].a1 + context; if (ga1 > na) ga1 = na;
		gb1 = hunks[j - 1].b1 + context; if (gb1 > nb) gb1 = nb;

		if (!group_push(&groups, &cap, &ng, i, j, ga0, ga1, gb0, gb1)) { free(groups); *out_ng = 0; return 0; }
		i = j;
	}
	*out_ng = ng;
	return groups;
}

/* One side ("*** file1 ****" block, or "--- file2 ----" block) of one
 * printed context-format group: context lines around/between hunks,
 * plus that side's own "- "/"! "/"+ " lines for each hunk that has any
 * content on this side (a hunk with nothing on this side, e.g. a pure
 * insert on the file1 side, contributes no lines here at all -- just
 * the context around it). */
static void print_context_side(FILE *out, enum side side, const struct group *g, const struct hunk *hunks,
	const struct dline *a, size_t na, int noeol_a, const struct dline *b, size_t nb, int noeol_b)
{
	size_t pos = (side == SIDE_A) ? g->ga0 : g->gb0;
	size_t end = (side == SIDE_A) ? g->ga1 : g->gb1;
	size_t hi;

	for (hi = g->hstart; hi < g->hend; hi++) {
		const struct hunk *h = &hunks[hi];
		int a_empty = h->a0 == h->a1;
		int b_empty = h->b0 == h->b1;
		size_t hs = (side == SIDE_A) ? h->a0 : h->b0;
		size_t he = (side == SIDE_A) ? h->a1 : h->b1;
		const char *prefix;
		size_t j;

		for (; pos < hs; pos++) print_ctxline(out, "  ", side, a, na, noeol_a, b, nb, noeol_b, pos);

		if (side == SIDE_A) {
			if (b_empty) prefix = "- ";
			else if (a_empty) prefix = 0;
			else prefix = "! ";
		} else {
			if (a_empty) prefix = "+ ";
			else if (b_empty) prefix = 0;
			else prefix = "! ";
		}

		if (prefix) for (j = hs; j < he; j++) print_ctxline(out, prefix, side, a, na, noeol_a, b, nb, noeol_b, j);
		pos = he;
	}
	for (; pos < end; pos++) print_ctxline(out, "  ", side, a, na, noeol_a, b, nb, noeol_b, pos);
}

static void print_context_group(FILE *out, const struct group *g, const struct hunk *hunks,
	const struct dline *a, size_t na, int noeol_a, const struct dline *b, size_t nb, int noeol_b)
{
	size_t hi;
	int any_a = 0, any_b = 0;

	for (hi = g->hstart; hi < g->hend; hi++) {
		if (hunks[hi].a0 != hunks[hi].a1) any_a = 1;
		if (hunks[hi].b0 != hunks[hi].b1) any_b = 1;
	}

	fprintf(out, "***************\n");
	fprintf(out, "*** "); print_range(out, g->ga0, g->ga1, ','); fprintf(out, " ****\n");
	if (any_a) print_context_side(out, SIDE_A, g, hunks, a, na, noeol_a, b, nb, noeol_b);
	fprintf(out, "--- "); print_range(out, g->gb0, g->gb1, ','); fprintf(out, " ----\n");
	if (any_b) print_context_side(out, SIDE_B, g, hunks, a, na, noeol_a, b, nb, noeol_b);
}

static void print_unified_group(FILE *out, const struct group *g, const struct hunk *hunks,
	const struct dline *a, size_t na, int noeol_a, const struct dline *b, size_t nb, int noeol_b)
{
	size_t pos_a = g->ga0, pos_b = g->gb0;
	size_t hi;

	fprintf(out, "@@ -"); print_unified_range(out, g->ga0, g->ga1);
	fprintf(out, " +"); print_unified_range(out, g->gb0, g->gb1);
	fprintf(out, " @@\n");

	for (hi = g->hstart; hi < g->hend; hi++) {
		const struct hunk *h = &hunks[hi];
		size_t j;
		for (; pos_a < h->a0; pos_a++, pos_b++)
			print_ctxline(out, " ", SIDE_A, a, na, noeol_a, b, nb, noeol_b, pos_a);
		for (j = h->a0; j < h->a1; j++) print_ctxline(out, "-", SIDE_A, a, na, noeol_a, b, nb, noeol_b, j);
		for (j = h->b0; j < h->b1; j++) print_ctxline(out, "+", SIDE_B, a, na, noeol_a, b, nb, noeol_b, j);
		pos_a = h->a1; pos_b = h->b1;
	}
	for (; pos_a < g->ga1; pos_a++, pos_b++)
		print_ctxline(out, " ", SIDE_A, a, na, noeol_a, b, nb, noeol_b, pos_a);
}

static void format_ctx_timestamp(char *buf, size_t bufsz, time_t t)
{
	struct tm tmv;
	localtime_r(&t, &tmv);
	strftime(buf, bufsz, "%a %b %e %T %Y", &tmv);
}

static void format_unified_timestamp(char *buf, size_t bufsz, time_t t)
{
	struct tm tmv;
	char tz[16];
	localtime_r(&t, &tmv);
	strftime(tz, sizeof tz, "%z", &tmv);
	snprintf(buf, bufsz, "%04d-%02d-%02d %02d:%02d:%02d %s",
		tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
		tmv.tm_hour, tmv.tm_min, tmv.tm_sec, tz);
}

/* ==== two-operand comparison, one output format's worth of dispatch ======== */

enum diff_fmt { FMT_DEFAULT = 0, FMT_CONTEXT, FMT_UNIFIED, FMT_ED, FMT_FALT };

struct diff_opts {
	enum diff_fmt fmt;
	int fmt_set;
	int bflag;
	int rflag;
	long context;
};

static int diff_files(const char *path1, const char *path2, const char *label1, const char *label2,
	const struct diff_opts *opts, FILE *out, int dirmode)
{
	FILE *f1, *f2;
	int is_stdin1 = !strcmp(path1, "-");
	int is_stdin2 = !strcmp(path2, "-");
	char *buf1 = 0, *buf2 = 0;
	size_t len1 = 0, len2 = 0;
	struct dline *a = 0, *b = 0;
	size_t na = 0, nb = 0;
	int noeol_a = 0, noeol_b = 0;
	struct editop *ops = 0;
	size_t nops = 0;
	struct hunk *hunks = 0;
	size_t nh = 0;
	time_t mt1, mt2;
	int result;

	mt1 = mt2 = time(0);

	f1 = is_stdin1 ? stdin : fopen(path1, "rb");
	if (!f1) { __util_diagf("diff: %s: %s\n", path1, strerror(errno)); return 2; }
	f2 = is_stdin2 ? stdin : fopen(path2, "rb");
	if (!f2) {
		__util_diagf("diff: %s: %s\n", path2, strerror(errno));
		if (!is_stdin1) (void)fclose(f1);
		return 2;
	}

	if (!is_stdin1) { struct stat st; if (stat(path1, &st) == 0) mt1 = st.st_mtime; }
	if (!is_stdin2) { struct stat st; if (stat(path2, &st) == 0) mt2 = st.st_mtime; }

	if (!read_whole_stream(f1, &buf1, &len1)) {
		__util_diagf("diff: %s: %s\n", path1, strerror(errno));
		if (!is_stdin1) (void)fclose(f1);
		if (!is_stdin2) (void)fclose(f2);
		return 2;
	}
	if (!is_stdin1) (void)fclose(f1);
	if (!read_whole_stream(f2, &buf2, &len2)) {
		__util_diagf("diff: %s: %s\n", path2, strerror(errno));
		free(buf1);
		if (!is_stdin2) (void)fclose(f2);
		return 2;
	}
	if (!is_stdin2) (void)fclose(f2);

	a = split_lines(buf1, len1, &na, &noeol_a);
	if (len1 && !a) { __util_diagf("diff: out of memory\n"); free(buf1); free(buf2); return 2; }
	b = split_lines(buf2, len2, &nb, &noeol_b);
	if (len2 && !b) { __util_diagf("diff: out of memory\n"); free(a); free(buf1); free(buf2); return 2; }

	if (!myers_build_ops(a, (long)na, noeol_a, b, (long)nb, noeol_b, opts->bflag, &ops, &nops)) {
		__util_diagf("diff: out of memory\n");
		free(a); free(b); free(buf1); free(buf2);
		return 2;
	}
	{
		int hunks_ok;
		hunks = build_hunks(ops, nops, &nh, &hunks_ok);
		free(ops);
		if (!hunks_ok) {
			__util_diagf("diff: out of memory\n");
			free(a); free(b); free(buf1); free(buf2);
			return 2;
		}
	}

	if (nh == 0) {
		free(hunks); free(a); free(b); free(buf1); free(buf2);
		return 0;
	}

	if (dirmode) {
		fprintf(out, "diff");
		if (opts->bflag) fprintf(out, " -b");
		switch (opts->fmt) {
		case FMT_CONTEXT: fprintf(out, " -c"); break;
		case FMT_UNIFIED: fprintf(out, " -u"); break;
		case FMT_ED: fprintf(out, " -e"); break;
		case FMT_FALT: fprintf(out, " -f"); break;
		case FMT_DEFAULT: default: break;
		}
		fprintf(out, " %s %s\n", label1, label2);
	}

	switch (opts->fmt) {
	case FMT_ED:
		print_ed(out, hunks, nh, b);
		break;
	case FMT_FALT:
		print_falt(out, hunks, nh, b);
		break;
	case FMT_CONTEXT: {
		char ts1[64], ts2[64];
		struct group *groups;
		size_t ng, gi;
		format_ctx_timestamp(ts1, sizeof ts1, mt1);
		format_ctx_timestamp(ts2, sizeof ts2, mt2);
		fprintf(out, "*** %s\t%s\n", label1, ts1);
		fprintf(out, "--- %s\t%s\n", label2, ts2);
		groups = build_groups(hunks, nh, (size_t)opts->context, na, nb, &ng);
		for (gi = 0; gi < ng; gi++)
			print_context_group(out, &groups[gi], hunks, a, na, noeol_a, b, nb, noeol_b);
		free(groups);
		break;
	}
	case FMT_UNIFIED: {
		char ts1[64], ts2[64];
		struct group *groups;
		size_t ng, gi;
		format_unified_timestamp(ts1, sizeof ts1, mt1);
		format_unified_timestamp(ts2, sizeof ts2, mt2);
		fprintf(out, "--- %s\t%s\n", label1, ts1);
		fprintf(out, "+++ %s\t%s\n", label2, ts2);
		groups = build_groups(hunks, nh, (size_t)opts->context, na, nb, &ng);
		for (gi = 0; gi < ng; gi++)
			print_unified_group(out, &groups[gi], hunks, a, na, noeol_a, b, nb, noeol_b);
		free(groups);
		break;
	}
	case FMT_DEFAULT:
	default:
		print_default(out, hunks, nh, a, na, noeol_a, b, nb, noeol_b);
		break;
	}

	result = 1;
	if (opts->fmt == FMT_ED || opts->fmt == FMT_FALT) {
		int noeol_diag = 0;
		if (noeol_a && na > 0 && line_in_any_hunk_a(hunks, nh, na - 1)) {
			fflush(out); /* diagnostics must trail the body they explain, not race it */
			__util_diagf("diff: %s: No newline at end of file\n", label1);
			noeol_diag = 1;
		}
		if (noeol_b && nb > 0 && line_in_any_hunk_b(hunks, nh, nb - 1)) {
			fflush(out);
			__util_diagf("diff: %s: No newline at end of file\n", label2);
			noeol_diag = 1;
		}
		/* An ed/-f script has no way to represent "this embedded text
		 * had no trailing newline in its source file" -- the script it
		 * just printed cannot faithfully reproduce that file, which is
		 * a real error, not just "differences were found" (confirmed
		 * against real diffutils: this specific case exits >1, not 1;
		 * see this file's header comment on the -e/-f noeol case). */
		if (noeol_diag) result = 2;
	}

	free(hunks); free(a); free(b); free(buf1); free(buf2);
	return result;
}

/* ==== directory comparison (mandatory: see this file's header comment) ==== */

struct namelist { char **names; size_t n; };

static int namecmp(const void *pa, const void *pb)
{
	const char *const *a = pa;
	const char *const *b = pb;
	return strcmp(*a, *b);
}

static void free_namelist(struct namelist *l)
{
	size_t i;
	for (i = 0; i < l->n; i++) free(l->names[i]);
	free(l->names);
}

static int list_dir_sorted(const char *path, struct namelist *out)
{
	DIR *dp;
	struct dirent *d;
	char **names = 0;
	size_t cap = 0, n = 0;

	out->names = 0; out->n = 0;
	dp = opendir(path);
	if (!dp) return 0;
	while ((d = readdir(dp)) != 0) {
		size_t namelen = strnlen(d->d_name, sizeof d->d_name);
		char *dup;
		if (namelen == sizeof d->d_name) continue;
		if ((namelen == 1 && d->d_name[0] == '.') ||
		    (namelen == 2 && d->d_name[0] == '.' && d->d_name[1] == '.')) continue;
		if (n >= cap) {
			size_t newcap;
			char **g;
			if (!__util_array_capacity(cap, n, 1, 32, sizeof *names, &newcap)) goto fail;
			g = __util_reallocarray(names, newcap, sizeof *names);
			if (!g) goto fail;
			names = g; cap = newcap;
		}
		{
			size_t bytes;
			if (!__util_size_add(namelen, 1, &bytes)) goto fail;
			dup = malloc(bytes);
			if (!dup) goto fail;
			memcpy(dup, d->d_name, bytes);
		}
		names[n++] = dup;
	}
	(void)closedir(dp);
	qsort(names, n, sizeof *names, namecmp);
	out->names = names; out->n = n;
	return 1;

fail:
	{
		size_t i;
		for (i = 0; i < n; i++) free(names[i]);
	}
	free(names);
	(void)closedir(dp);
	return 0;
}

static int diff_dirs(const char *d1, const char *d2, const struct diff_opts *opts, FILE *out)
{
	struct namelist l1, l2;
	size_t i1 = 0, i2 = 0;
	int any_diff = 0, had_error = 0;

	if (!list_dir_sorted(d1, &l1)) { __util_diagf("diff: %s: %s\n", d1, strerror(errno)); return 2; }
	if (!list_dir_sorted(d2, &l2)) { __util_diagf("diff: %s: %s\n", d2, strerror(errno)); free_namelist(&l1); return 2; }

	while (i1 < l1.n || i2 < l2.n) {
		int cmp;
		if (i1 >= l1.n) cmp = 1;
		else if (i2 >= l2.n) cmp = -1;
		else cmp = strcmp(l1.names[i1], l2.names[i2]);

		if (cmp < 0) {
			fprintf(out, "Only in %s: %s\n", d1, l1.names[i1]);
			any_diff = 1;
			i1++;
		} else if (cmp > 0) {
			fprintf(out, "Only in %s: %s\n", d2, l2.names[i2]);
			any_diff = 1;
			i2++;
		} else {
			char p1[PATH_MAX], p2[PATH_MAX];
			struct stat st1, st2;
			int have1, have2;

			snprintf(p1, sizeof p1, "%s/%s", d1, l1.names[i1]);
			snprintf(p2, sizeof p2, "%s/%s", d2, l2.names[i2]);
			have1 = stat(p1, &st1) == 0;
			have2 = have1 && stat(p2, &st2) == 0;

			if (!have1 || !have2) {
				__util_diagf("diff: %s: %s\n", have1 ? p2 : p1, strerror(errno));
				had_error = 1;
			} else if (S_ISDIR(st1.st_mode) && S_ISDIR(st2.st_mode)) {
				if (opts->rflag) {
					int r = diff_dirs(p1, p2, opts, out);
					if (r == 1) any_diff = 1;
					else if (r > 1) had_error = 1;
				} else {
					fprintf(out, "Common subdirectories: %s and %s\n", p1, p2);
				}
			} else if (S_ISDIR(st1.st_mode) || S_ISDIR(st2.st_mode)) {
				/* One is a directory, the other is not: the OPERANDS
				 * section says diff "shall not compare regular files to
				 * directories" but leaves what to report as
				 * implementation-defined; this matches the one
				 * empirically-observed real convention. */
				int a_is_dir = S_ISDIR(st1.st_mode);
				fprintf(out, "File %s is a directory while file %s is a regular file\n",
					a_is_dir ? p1 : p2, a_is_dir ? p2 : p1);
				any_diff = 1;
			} else if (!S_ISREG(st1.st_mode) || !S_ISREG(st2.st_mode)) {
				/* Block/character-special or FIFO: OPERANDS says diff
				 * "shall not compare" these to anything -- skipped
				 * silently, taken literally. */
			} else {
				int r = diff_files(p1, p2, p1, p2, opts, out, 1);
				if (r == 1) any_diff = 1;
				else if (r > 1) had_error = 1;
			}
			i1++; i2++;
		}
	}

	free_namelist(&l1);
	free_namelist(&l2);
	if (had_error) return 2;
	return any_diff ? 1 : 0;
}

/* ==== option parsing / entry point ========================================= */

static int set_fmt(struct diff_opts *opts, enum diff_fmt fmt)
{
	if (opts->fmt_set && opts->fmt != fmt) return 0;
	opts->fmt = fmt;
	opts->fmt_set = 1;
	return 1;
}

int __util_diff_main(int argc, char **argv)
{
	struct diff_opts opts;
	int i;
	const char *files[2];
	int nfiles = 0;
	int is_dash1, is_dash2;
	struct stat st1, st2;
	int have1, have2;

	memset(&opts, 0, sizeof opts);
	opts.context = 3;

	for (i = 1; i < argc; i++) {
		char *arg = argv[i];
		char *p;

		if (!strcmp(arg, "--")) { i++; break; }
		if (arg[0] != '-' || arg[1] == 0) break;

		p = arg + 1;
		while (*p) {
			switch (*p) {
			case 'b': opts.bflag = 1; p++; break;
			case 'r': opts.rflag = 1; p++; break;
			case 'c':
				if (!set_fmt(&opts, FMT_CONTEXT)) goto conflict;
				p++; break;
			case 'e':
				if (!set_fmt(&opts, FMT_ED)) goto conflict;
				p++; break;
			case 'f':
				if (!set_fmt(&opts, FMT_FALT)) goto conflict;
				p++; break;
			case 'u':
				if (!set_fmt(&opts, FMT_UNIFIED)) goto conflict;
				p++; break;
			case 'C': case 'U': {
				const char *val;
				char fmtc = *p;
				char *end;
				long n;
				p++;
				if (*p) val = p;
				else {
					if (++i >= argc) { __util_diagf("diff: -%c: option requires an argument\n", fmtc); return 2; }
					val = argv[i];
				}
				n = strtol(val, &end, 10);
				if (*end || val[0] == 0 || n < (fmtc == 'C' ? 1 : 0)) {
					__util_diagf("diff: -%c: invalid context count %s\n", fmtc, val);
					return 2;
				}
				if (!set_fmt(&opts, fmtc == 'C' ? FMT_CONTEXT : FMT_UNIFIED)) goto conflict;
				opts.context = n;
				p = (char *)"";
				break;
			}
			default:
				__util_diagf("diff: -%c: invalid option\n", *p);
				return 2;
			}
		}
	}

	for (; i < argc; i++) {
		if (nfiles >= 2) { __util_diagf("diff: extra operand %s\n", argv[i]); return 2; }
		files[nfiles++] = argv[i];
	}
	if (nfiles != 2) {
		__util_diagf("diff: usage: diff [-c|-e|-f|-u|-C n|-U n] [-br] file1 file2\n");
		return 2;
	}

	is_dash1 = !strcmp(files[0], "-");
	is_dash2 = !strcmp(files[1], "-");
	have1 = !is_dash1 && stat(files[0], &st1) == 0;
	have2 = !is_dash2 && stat(files[1], &st2) == 0;

	if (have1 && have2 && S_ISDIR(st1.st_mode) && S_ISDIR(st2.st_mode))
		return diff_dirs(files[0], files[1], &opts, stdout);

	if (have1 && have2 && (S_ISDIR(st1.st_mode) != S_ISDIR(st2.st_mode))) {
		/* Exactly one operand is a directory: XCU's OPERANDS section --
		 * "diff shall be applied to the non-directory file and the file
		 * contained in the directory file with a filename that is the
		 * same as the last component of the non-directory file." */
		char resolved[PATH_MAX];
		const char *dirpath, *filepath, *base;
		int dir_is_first = S_ISDIR(st1.st_mode);

		dirpath = dir_is_first ? files[0] : files[1];
		filepath = dir_is_first ? files[1] : files[0];
		base = strrchr(filepath, '/');
		base = base ? base + 1 : filepath;
		snprintf(resolved, sizeof resolved, "%s/%s", dirpath, base);

		if (dir_is_first) return diff_files(resolved, filepath, resolved, filepath, &opts, stdout, 0);
		return diff_files(filepath, resolved, filepath, resolved, &opts, stdout, 0);
	}

	return diff_files(files[0], files[1], files[0], files[1], &opts, stdout, 0);

conflict:
	__util_diagf("diff: -c, -e, -f, -u, -C and -U are mutually exclusive\n");
	return 2;
}
