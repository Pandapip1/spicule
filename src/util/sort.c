/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * sort(1p): `sort [-bdfinru] [-k keydef]... [-t char] [-o output] [-c|-C]
 * [file...]`.
 *
 * DEFAULT KEY: no -k means the whole line is the key, compared
 * byte-by-byte (this library's only locale is "C", src/misc/locale.c).
 *
 * DEFAULT FIELD SPLITTING (-t not given): each run of blanks following a
 * non-blank char is a field separator and is consumed, except leading
 * blanks on the line, which stay part of field 1. This is the opposite
 * of join(1p)'s default (join drops leading blanks); see
 * src/util/join.c's header.
 *
 * -k keydef GRAMMAR: `field_start[type][,field_end[type]]`, both
 * field_start and field_end are `F[.C]` (F,C 1-based; C omitted means
 * "start of field" on field_start, "end of field" on field_end); type is
 * any run of 'b','d','f','i','n','r', all implemented. Any modifier
 * attached anywhere in one -k spec makes that key use only its own
 * attached modifiers (global -b/-d/-f/-i/-n/-r do not leak in).
 * Deliberate simplification: 'b' attached to either endpoint applies to
 * both, rather than tracked per-endpoint as POSIX's literal wording
 * would allow. Omitted field_end runs to the end of the line, not just
 * the end of that field.
 *
 * TIEBREAK: lines that compare equal under the primary key(s) fall back
 * to a whole-line, unfiltered byte comparison (honoring global -r only,
 * not any per-key 'r'), unless -u is given -- in which case such lines
 * are exactly the duplicates -u collapses, and no tiebreak runs. This is
 * why `sort -k1,1 -k2,2n` differs from a naive single-key sort.
 *
 * STABILITY: merge_sort() below is a stable bottom-up merge sort (over
 * qsort()/quicksort) so equal-comparing lines keep their original order;
 * POSIX doesn't require this but scripts rely on it, and stability costs
 * nothing extra here.
 *
 * -c/-C (check, don't sort): only a single input file is allowed. EXIT
 * STATUS is unusual: 0 = sorted (or all input written), 1 = -c found the
 * file unsorted (or -c -u found equal keys), >1 = a real error. Usage/IO
 * errors below always return 2, never 1, to preserve that distinction.
 *
 * -o output: safe to reuse an input filename, because every line is
 * read into memory (read_all_lines() below) before -o is ever opened.
 *
 * -m (merge, assume inputs already sorted) is a real option, deliberately
 * not implemented: refused loudly with a diagnostic rather than silently
 * doing a full sort instead.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include "util.h"
#include "ownership_stubs.h" /* __ownership_pointer_nonnull() */

struct field { size_t start, end; };

struct sort_key {
	int f1, c1;             /* field_start: field number, char pos (both 1-based) */
	int f2, c2;             /* field_end: c2==0 means "last char of field" */
	int has_end;
	int has_mod;
	int mb, md, mf, mi, mn, mr;
};

struct sort_opts {
	int b, d, f, i, n, r, u;
	int have_delim;
	char delim;
	struct sort_key *keys;
	size_t nkeys;
};

struct line {
	char *text withtok(heap_allocated);
	size_t len;
	struct field *fields withtok(heap_allocated);
	size_t nfields;
};

/* ==== field splitting ==================================================== */

/* Not out = realloc(out, ...): on failure realloc() returns NULL without
 * freeing the original block, so assigning straight back would leak it. */
static struct field *fields_grow(struct field *out, size_t *cap)
	__attribute__((nonnull(2)));
withtok(heap_allocated)
static struct field *fields_grow(
	struct field *out consume_if_nonnull_return(heap_allocated), size_t *cap)
{
	size_t newcap;
	struct field *g;
	if (!__util_array_capacity(*cap, *cap, 1, 8, sizeof *out, &newcap)) return 0;
	g = __util_reallocarray(out, newcap, sizeof *out);
	if (!g) return 0;
	*cap = newcap;
	return g;
}

/* Ensures `*out` has room for field index `n`, growing via fields_grow()
 * if not; on failure frees and clears `*out` so callers just propagate
 * a false return. */
static int field_reserve(struct field **out, size_t *cap, size_t n)
	__attribute__((nonnull(1, 2)));
static int field_reserve(struct field **out withtok(heap_allocated), size_t *cap,
                         size_t n)
{
	struct field *g;

	if (n < *cap) return 1;
	g = fields_grow(*out, cap);
	if (!g) { free(*out); *out = 0; return 0; }
	*out = g;
	return 1;
}

static struct field *split_fields(const char *line, size_t len, const struct sort_opts *o, size_t *nout)
	__attribute__((nonnull(1, 3, 4)));
withtok(heap_allocated)
static struct field *split_fields(const char *line, size_t len, const struct sort_opts *o, size_t *nout)
{
	struct field *out;
	size_t cap = 8, n = 0;

	out = __util_mallocarray(cap, sizeof *out);
	if (!out) { *nout = 0; return 0; }

	if (o->have_delim) {
		size_t start = 0, i;
		for (i = 0; i < len + 1; i++) {
			if (i == len || line[i] == o->delim) {
				if (!field_reserve(&out, &cap, n)) { *nout = 0; return 0; }
				out[n].start = start; out[n].end = i; n++;
				start = i + 1;
			}
		}
	} else {
		size_t i = 0, field_start = 0;
		int seen_nb = 0;
		while (i < len) {
			if (isblank((unsigned char)line[i])) {
				if (seen_nb) {
					size_t sep_start = i;
					while (i < len && isblank((unsigned char)line[i])) i++;
					if (!field_reserve(&out, &cap, n)) { *nout = 0; return 0; }
					out[n].start = field_start; out[n].end = sep_start; n++;
					field_start = i;
					seen_nb = 0;
					continue;
				}
				i++;
			} else {
				seen_nb = 1;
				i++;
			}
		}
		if (!field_reserve(&out, &cap, n)) { *nout = 0; return 0; }
		out[n].start = field_start; out[n].end = len; n++;
	}
	*nout = n;
	return out;
}

/* ==== key range resolution ================================================ */

static size_t key_start_off(const char *line withtok(readable_span(len)), size_t len,
                            const struct field *fields, size_t nf,
                            int f, int c, int bflag) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct field fl;
	size_t start;

	/* line is always a struct line's own text field -- see
	 * compare_by_key()'s call site. */
	__ownership_pointer_nonnull(line);
	if (f < 1) f = 1;
	if ((size_t)(f - 1) >= nf) return len;
	/* nf > 0 here; split_fields() never returns a count without a
	 * backing fields array. */
	__ownership_pointer_nonnull(fields);
	/* OPEN LINT FINDING (ntlibc.ValidPointer): fields[f-1].end <= len
	 * always holds, since split_fields() never records an end beyond
	 * the line's len -- but the checker can't correlate a struct field
	 * value against a bound set in a different function, so this stays
	 * open rather than papered over. */
	fl = fields[f - 1];
	start = fl.start;
	if (bflag) while (start < fl.end && isblank((unsigned char)line[start])) start++;
	if (c < 1) c = 1;
	start += (size_t)(c - 1);
	if (start > len) start = len;
	return start;
}

static size_t key_end_off(const char *line withtok(readable_span(len)), size_t len,
                          const struct field *fields, size_t nf,
                          int f, int c, int bflag) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct field fl;
	size_t fstart, end;

	(void)len;
	/* line -- see key_start_off()'s identical note. */
	__ownership_pointer_nonnull(line);
	if (f < 1) f = 1;
	if ((size_t)(f - 1) >= nf) return len;
	/* nf > 0 -- see key_start_off()'s identical fields/nfields note. */
	__ownership_pointer_nonnull(fields);
	/* OPEN LINT FINDING -- see key_start_off()'s identical note above. */
	fl = fields[f - 1];
	fstart = fl.start;
	if (bflag) while (fstart < fl.end && isblank((unsigned char)line[fstart])) fstart++;
	if (c <= 0) return fl.end;
	end = fstart + (size_t)c;
	if (end > fl.end) end = fl.end;
	return end;
}

/* ==== character-level comparison ========================================= */

/* Saturates to LLONG_MAX/LLONG_MIN instead of wrapping on an absurdly
 * long numeric key (30+ digits under -n) -- a wrapped value could come
 * out smaller than a key it should sort after, flipping the order. */
static long long parse_numeric(const char *s, size_t len)
	__attribute__((nonnull(1)));
static long long parse_numeric(const char *s, size_t len)
{
	size_t i = 0;
	int neg = 0;
	long long v = 0;
	int overflowed = 0;

	while (i < len && isblank((unsigned char)s[i])) i++;
	if (i < len && s[i] == '-') { neg = 1; i++; }
	for (; i < len && s[i] >= '0' && s[i] <= '9'; i++) {
		int digit = s[i] - '0';
		if (v > (LLONG_MAX - digit) / 10) { overflowed = 1; break; }
		v = v * 10 + digit;
	}
	if (overflowed) v = LLONG_MAX;
	if (!neg) return v;
	return overflowed ? LLONG_MIN : -v;
}

static int char_passes(unsigned char c, int d, int i) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	if (i && !isprint(c)) return 0;
	if (d && !(isblank(c) || isalnum(c))) return 0;
	return 1;
}

static int compare_range(const char *a, size_t as, size_t ae, const char *b, size_t bs, size_t be, int d, int f, int i, int n) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
	__attribute__((nonnull(1, 4)));
static int compare_range(const char *a, size_t as, size_t ae, const char *b, size_t bs, size_t be, int d, int f, int i, int n) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	if (n) {
		long long va = parse_numeric(a + as, ae - as);
		long long vb = parse_numeric(b + bs, be - bs);
		if (va < vb) return -1;
		if (va > vb) return 1;
		return 0;
	}
	{
		size_t pa = as, pb = bs;
		for (;;) {
			while (pa < ae && !char_passes((unsigned char)a[pa], d, i)) pa++;
			while (pb < be && !char_passes((unsigned char)b[pb], d, i)) pb++;
			if (pa >= ae && pb >= be) return 0;
			if (pa >= ae) return -1;
			if (pb >= be) return 1;
			{
				int ca = (unsigned char)a[pa], cb = (unsigned char)b[pb];
				if (f) { ca = tolower(ca); cb = tolower(cb); }
				if (ca != cb) return ca < cb ? -1 : 1;
			}
			pa++; pb++;
		}
	}
}

static int compare_raw(const struct line *a, const struct line *b)
{
	size_t n = a->len < b->len ? a->len : b->len;
	for (size_t i = 0; i < n; i++)
		if (a->text[i] != b->text[i])
			return (unsigned char)a->text[i] < (unsigned char)b->text[i] ? -1 : 1;
	if (a->len < b->len) return -1;
	if (a->len > b->len) return 1;
	return 0;
}

static int reverse_comparison(int comparison)
{
	if (comparison < 0) return 1;
	if (comparison > 0) return -1;
	return 0;
}

static int compare_by_key(const struct sort_opts *o, const struct sort_key *k, const struct line *a, const struct line *b)
{
	int bflag, dflag, fflag, iflag, nflag, rflag;
	size_t as, ae, bs, be;
	int c;

	/* o/a/b -- see line_compare()'s identical note, one call up. k is
	 * always &o->keys[i] for some i < o->nkeys, never NULL. */
	__ownership_pointer_nonnull(o);
	__ownership_pointer_nonnull(a);
	__ownership_pointer_nonnull(b);
	__ownership_pointer_nonnull(k);
	if (k->has_mod) {
		bflag = k->mb; dflag = k->md; fflag = k->mf;
		iflag = k->mi; nflag = k->mn; rflag = k->mr;
	} else {
		bflag = o->b; dflag = o->d; fflag = o->f;
		iflag = o->i; nflag = o->n; rflag = o->r;
	}

	/* a->text has exactly a->len readable bytes -- see
	 * read_all_lines()'s struct line construction. */
	__ownership_readable_span(a->text, a->len);
	as = key_start_off(a->text, a->len, a->fields, a->nfields, k->f1, k->c1, bflag);
	ae = k->has_end ? key_end_off(a->text, a->len, a->fields, a->nfields, k->f2, k->c2, bflag) : a->len;
	if (ae < as) ae = as;

	__ownership_readable_span(b->text, b->len);
	bs = key_start_off(b->text, b->len, b->fields, b->nfields, k->f1, k->c1, bflag);
	be = k->has_end ? key_end_off(b->text, b->len, b->fields, b->nfields, k->f2, k->c2, bflag) : b->len;
	if (be < bs) be = bs;

	c = compare_range(a->text, as, ae, b->text, bs, be, dflag, fflag, iflag, nflag);
	return rflag ? reverse_comparison(c) : c;
}

static int line_compare(const struct sort_opts *o, const struct line *a, const struct line *b)
{
	int c;

	/* a and b are always &lines[i] within a live lines[] array
	 * (__util_sort_main's nlines/lines invariant), never NULL. */
	__ownership_pointer_nonnull(a);
	__ownership_pointer_nonnull(b);
	if (o->nkeys) {
		size_t i;
		c = 0;
		for (i = 0; i < o->nkeys; i++) {
			c = compare_by_key(o, &o->keys[i], a, b);
			if (c) return c;
		}
	} else {
		size_t as = 0, bs = 0;
		if (o->b) {
			while (as < a->len && isblank((unsigned char)a->text[as])) as++;
			while (bs < b->len && isblank((unsigned char)b->text[bs])) bs++;
		}
		c = compare_range(a->text, as, a->len, b->text, bs, b->len, o->d, o->f, o->i, o->n);
		if (o->r) c = reverse_comparison(c);
	}

	if (c == 0 && !o->u) {
		c = compare_raw(a, b);
		if (o->r) c = reverse_comparison(c);
	}
	return c;
}

/* ==== stable bottom-up merge sort ========================================= */

static void merge_sort(struct line *lines, size_t n, const struct sort_opts *o)
{
	struct line *tmp;
	size_t width;

	if (n < 2) return;
	/* n >= 2 here, and read_all_lines() never leaves nlines nonzero
	 * without a matching heap-allocated lines array. */
	__ownership_pointer_nonnull(lines);
	tmp = __util_mallocarray(n, sizeof *tmp);
	if (!tmp) return; /* input stays in original (still-valid) order */

	for (width = 1; width < n;) {
		size_t i;
		for (i = 0; i < n;) {
			size_t lo = i, mid = n - i < width ? n : i + width;
			size_t hi = n - mid < width ? n : mid + width;
			size_t a = lo, b = mid, k = lo;
			while (a < mid && b < hi) {
				if (line_compare(o, &lines[a], &lines[b]) <= 0) tmp[k++] = lines[a++];
				else tmp[k++] = lines[b++];
			}
			while (a < mid) tmp[k++] = lines[a++];
			while (b < hi) tmp[k++] = lines[b++];
			i = hi;
		}
		for (size_t j = 0; j < n; j++) lines[j] = tmp[j];
		if (width > n / 2) break;
		width *= 2;
	}
	free(tmp);
}

/* ==== -k parsing =========================================================== */

/* Consumes a run of 'b'/'d'/'f'/'i'/'n'/'r' modifier letters at `*pp`
 * (present identically after both field_start and field_end in a -k
 * spec's grammar -- see parse_keydef() below), setting the matching
 * k->m* flag and k->has_mod for each. */
static void parse_key_mods(const char **pp, struct sort_key *k)
{
	const char *p = *pp;
	while (*p && strchr("bdfinr", *p)) {
		k->has_mod = 1;
		switch (*p) { // NOLINT(bugprone-switch-missing-default-case) -- the enclosing strchr guard restricts the modifier to these cases
		case 'b': k->mb = 1; break;
		case 'd': k->md = 1; break;
		case 'f': k->mf = 1; break;
		case 'i': k->mi = 1; break;
		case 'n': k->mn = 1; break;
		case 'r': k->mr = 1; break;
		}
		p++;
	}
	*pp = p;
}

static int parse_keydef(const char *spec, struct sort_key *k)
	__attribute__((nonnull(1)));
static int parse_keydef(const char *spec, struct sort_key *k)
{
	const char *p = spec;
	char *end;
	long v;

	memset(k, 0, sizeof *k);
	if (!isdigit((unsigned char)*p)) return -1;
	v = strtol(p, &end, 10);
	if (v < 1) return -1;
	k->f1 = (int)v;
	p = end;
	/* end is strtol()'s endptr output: never NULL when p was nonnull
	 * (C11 7.22.1.4p8) -- restated at every p = end below. */
	__ownership_pointer_nonnull(p);
	k->c1 = 1;
	if (*p == '.') {
		p++;
		if (!isdigit((unsigned char)*p)) return -1;
		v = strtol(p, &end, 10);
		if (v < 1) return -1;
		k->c1 = (int)v;
		p = end;
		__ownership_pointer_nonnull(p);
	}
	parse_key_mods(&p, k);
	/* parse_key_mods() only advances *pp, never assigns NULL. */
	__ownership_pointer_nonnull(p);
	if (*p == ',') {
		p++;
		if (!isdigit((unsigned char)*p)) return -1;
		v = strtol(p, &end, 10);
		if (v < 1) return -1;
		k->f2 = (int)v;
		p = end;
		__ownership_pointer_nonnull(p);
		k->c2 = 0;
		if (*p == '.') {
			p++;
			if (!isdigit((unsigned char)*p)) return -1;
			v = strtol(p, &end, 10);
			if (v < 0) return -1;
			k->c2 = (int)v;
			p = end;
			__ownership_pointer_nonnull(p);
		}
		parse_key_mods(&p, k);
		/* see the first parse_key_mods() call's identical note above. */
		__ownership_pointer_nonnull(p);
		k->has_end = 1;
	}
	if (*p) return -1;
	return 0;
}

/* ==== input reading ======================================================= */

static int read_all_lines(FILE *f, struct line **out withtok(heap_allocated),
                          size_t *nout, size_t *cap)
{
	char *buf = 0;
	size_t bufcap = 0;
	ssize_t got;

	while ((got = getline(&buf, &bufcap, f)) >= 0) {
		size_t len = (size_t)got;
		char *text;
		if (len && buf[len - 1] == '\n') len--;
		{
			size_t bytes;
			if (!__util_size_add(len, 1, &bytes)) { free(buf); return -1; }
			text = malloc(bytes);
		}
		if (!text) { free(buf); return -1; }
	for (size_t i = 0; i < len; i++) text[i] = buf[i];
		text[len] = 0;
		if (*nout >= *cap) {
			size_t newcap;
			struct line *g;
			if (!__util_array_capacity(*cap, *nout, 1, 64, sizeof **out, &newcap)) {
				free(text); free(buf); return -1;
			}
			g = __util_reallocarray(*out, newcap, sizeof **out);
			if (!g) { free(text); free(buf); return -1; }
			*out = g;
			*cap = newcap;
		}
		(*out)[*nout].text = text;
		(*out)[*nout].len = len;
		(*out)[*nout].fields = 0;
		(*out)[*nout].nfields = 0;
		(*nout)++;
	}
	free(buf);
	return 0;
}

static void free_lines(struct line *lines, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		/* i < n -- see merge_sort()'s identical lines/n note. */
		__ownership_pointer_nonnull(lines);
		free(lines[i].text);
		free(lines[i].fields);
	}
	free(lines);
}

int __util_sort_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	struct sort_opts o;
	struct sort_key keys[64];
	int opt_c = 0, opt_C = 0;
	int i;
	const char *files[256];
	int nfiles = 0;
	const char *outfile = 0;
	struct line *lines = 0;
	size_t nlines = 0, cap = 0;
	size_t li;

	memset(&o, 0, sizeof o);
	o.keys = keys;

	for (i = 1; i < argc; i++) {
		char *arg = argv[i];
		char *p;

		if (!strcmp(arg, "--")) { i++; break; }
		if (arg[0] != '-' || arg[1] == 0) break;

		p = arg + 1;
		while (*p) {
			switch (*p) {
			case 'b': o.b = 1; p++; break;
			case 'd': o.d = 1; p++; break;
			case 'f': o.f = 1; p++; break;
			case 'i': o.i = 1; p++; break;
			case 'n': o.n = 1; p++; break;
			case 'r': o.r = 1; p++; break;
			case 'u': o.u = 1; p++; break;
			case 'c': opt_c = 1; p++; break;
			case 'C': opt_c = 1; opt_C = 1; p++; break;
			case 'm':
				__util_diagf("sort: -m: not implemented -- see src/util/sort.c\n");
				return 2;
			case 'k': {
				const char *val;
				p++;
				if (*p) { val = p; }
				else {
					if (++i >= argc) { __util_diagf("sort: -k: option requires an argument\n"); return 2; }
					val = argv[i];
				}
				/* val is an offset into argv[i]'s bytes, or argv[i]
				 * itself -- never NULL per argv's own
				 * elements_withtok(null_terminated, argc) contract. */
				__ownership_pointer_nonnull(val);
				if (o.nkeys >= sizeof keys / sizeof keys[0]) {
					__util_diagf("sort: too many -k options\n");
					return 2;
				}
				if (parse_keydef(val, &keys[o.nkeys]) < 0) {
					__util_diagf("sort: %s: invalid key definition\n", val);
					return 2;
				}
				o.nkeys++;
				p = (char *)"";
				break;
			}
			case 't': {
				const char *val;
				p++;
				if (*p) { val = p; }
				else {
					if (++i >= argc) { __util_diagf("sort: -t: option requires an argument\n"); return 2; }
					val = argv[i];
				}
				/* val -- see the -k case's identical note above. */
				__ownership_pointer_nonnull(val);
				if (val[0] == 0 || val[1] != 0) {
					__util_diagf("sort: -t: field separator must be exactly one character\n");
					return 2;
				}
				o.delim = val[0];
				o.have_delim = 1;
				p = (char *)"";
				break;
			}
			case 'o': {
				p++;
				if (*p) { outfile = p; }
				else {
					if (++i >= argc) { __util_diagf("sort: -o: option requires an argument\n"); return 2; }
					outfile = argv[i];
				}
				p = (char *)"";
				break;
			}
			default:
				__util_diagf("sort: -%c: invalid option\n", *p);
				return 2;
			}
		}
	}

	for (; i < argc; i++) {
		if (nfiles >= (int)(sizeof files / sizeof files[0])) {
			__util_diagf("sort: too many file operands\n");
			return 2;
		}
		files[nfiles++] = argv[i];
	}

	if (opt_c && nfiles > 1) {
		__util_diagf("sort: -c/-C: only one input file may be given\n");
		return 2;
	}

	/* Read every operand (or stdin) fully into memory before anything
	 * is written -- see this file's header comment on -o. */
	if (nfiles == 0) {
		if (read_all_lines(stdin, &lines, &nlines, &cap) < 0) {
			__util_diagf("sort: out of memory\n");
			free_lines(lines, nlines);
			return 2;
		}
	} else {
		int fi;
		for (fi = 0; fi < nfiles; fi++) {
			FILE *f;
			int is_stdin = !strcmp(files[fi], "-");
			f = is_stdin ? stdin : fopen(files[fi], "r");
			if (!f) {
				int saved = errno;
				__util_diagf("sort: %s: %s\n", files[fi], strerror(saved));
				free_lines(lines, nlines);
				return 2;
			}
			if (read_all_lines(f, &lines, &nlines, &cap) < 0) {
				__util_diagf("sort: out of memory\n");
				/* Allocation failure is primary; closing the input is cleanup. */
				if (!is_stdin) (void)fclose(f);
				free_lines(lines, nlines);
				return 2;
			}
			if (!is_stdin && fclose(f) != 0) {
				free_lines(lines, nlines);
				return 2;
			}
		}
	}

	if (o.nkeys) {
		for (li = 0; li < nlines; li++) {
			/* li < nlines -- see merge_sort()'s identical lines/n note. */
			__ownership_pointer_nonnull(lines);
			lines[li].fields = split_fields(lines[li].text, lines[li].len, &o, &lines[li].nfields);
		}
	}

	if (opt_c) {
		const char *srcname = nfiles ? files[0] : "-";
		int result = 0;
		for (li = 1; li < nlines; li++) {
			__ownership_pointer_nonnull(lines);
			int cmp = line_compare(&o, &lines[li - 1], &lines[li]);
			if (cmp > 0) {
				if (!opt_C)
					__util_diagf("sort: %s: disorder: %s\n", srcname, lines[li].text);
				result = 1;
				break;
			}
			if (cmp == 0 && o.u) {
				if (!opt_C)
					__util_diagf("sort: %s: duplicate key: %s\n", srcname, lines[li].text);
				result = 1;
				break;
			}
		}
		free_lines(lines, nlines);
		return result;
	}

	merge_sort(lines, nlines, &o);

	{
		FILE *outf = stdout;
		size_t write_i, keep = 0;

		if (outfile) {
			outf = fopen(outfile, "w");
			if (!outf) {
				__util_diagf("sort: %s: %s\n", outfile, strerror(errno));
				free_lines(lines, nlines);
				return 2;
			}
		}

		for (write_i = 0; write_i < nlines; write_i++) {
			/* write_i < nlines -- see the o.nkeys loop's identical
			 * lines/nlines note above. */
			__ownership_pointer_nonnull(lines);
			if (o.u && keep > 0 && line_compare(&o, &lines[keep - 1], &lines[write_i]) == 0)
				continue;
			lines[keep++] = lines[write_i];
		}
		for (write_i = 0; write_i < keep; write_i++) {
			/* keep <= nlines, so keep > 0 implies lines is live. */
			__ownership_pointer_nonnull(lines);
			if (fprintf(outf, "%s\n", lines[write_i].text) < 0) {
				/* The output error fixes the result; close only releases outf. */
				if (outfile) (void)fclose(outf);
				free_lines(lines, nlines);
				return 2;
			}
		}

		if (outfile ? fclose(outf) != 0 : fflush(outf) != 0) {
			free_lines(lines, nlines);
			return 2;
		}
	}

	free_lines(lines, nlines);
	return 0;
}
