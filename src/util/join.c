/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * join(1p): `join [-a file_number] [-e string] [-o list] [-t char]
 * [-1 field] [-2 field] file1 file2` -- a relational equijoin on sorted
 * input. Both files MUST already be sorted on their own join field (the
 * same "comm/join don't sort for you" property src/util/comm.c's header
 * spells out; join does not verify sortedness either).
 *
 * DEFAULT FIELD SPLITTING (-t not given) is deliberately NOT the same
 * rule sort(1p)'s default uses (src/util/sort.c's header): join's
 * default is ordinary whitespace tokenization -- runs of blanks collapse
 * to one separator and leading blanks are stripped, never producing an
 * empty field -- unlike sort's "leading separator stays part of field 1".
 *
 * -t char makes every occurrence of char significant (an ordinary
 * single-character split, empty fields allowed between adjacent
 * separators, same as sort's -t). -t also sets the output field
 * separator (default a single space), used to join printed fields on
 * both the default output and an -o list's output.
 *
 * -1 field / -2 field: which field of file1/file2 to join on (default:
 * field 1 of each).
 *
 * DEFAULT OUTPUT (no -o): the join field, then file1's remaining fields,
 * then file2's remaining fields. For a genuinely unpairable line (only
 * relevant with -a) there's no counterpart to draw fields from, so that
 * half of the output just contributes nothing -- never padded with empty
 * placeholders.
 *
 * -o list: "file_number.field" (1 or 2) or "0" for the join field,
 * comma/blank-separated; one or more -o options accumulate. Unlike
 * default output, an -o list is a fixed field layout applied to every
 * output line including unpairable ones, so a file2.N entry on an
 * unpaired file1 line resolves to an empty field (subject to -e)
 * instead of being omitted.
 *
 * -e string: replaces empty output fields in an -o list; scoped to -o's
 * own output construction, no defined effect on default output.
 *
 * -a file_number: also emit a line for each unpairable line of that
 * file (both -a 1 and -a 2 may be given). -v (print only unpairable
 * lines) is a real, related option this file does not implement --
 * refused loudly rather than silently reinterpreted as -a, per this
 * project's "refuse rather than silently ignore" rule (see
 * src/util/touch.c's -d comment).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "util.h"
#include "ownership_stubs.h"

struct field { size_t start, end; };

/* text and fields are each their own heap allocation, released by
 * free_jlines() -- marking them lets AllocationLifetimeChecker see
 * read_all()'s assignments into them as transferring the obligation
 * into the array, not leaking it (same idiom as src/util/od.c's struct
 * instream.cur). */
struct jline {
	char *text withtok(heap_allocated);
	size_t len;
	struct field *fields withtok(heap_allocated);
	size_t nfields;
};

struct outspec { int file; int field; }; /* file: 0, 1 or 2 */

/* Not out = realloc(out, ...): on failure realloc() returns NULL without
 * freeing the original block, so assigning straight back would leak it. */
withtok(heap_allocated)
__attribute__((nonnull(2)))
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

withtok(heap_allocated)
static struct field *split_fields(const char *line, size_t len, int have_delim, char delim, size_t *nout) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct field *out;
	size_t cap = 8, n = 0;

	out = __util_mallocarray(cap, sizeof *out);
	if (!out) { *nout = 0; return 0; }

	if (have_delim) {
		size_t start = 0, i;
		for (i = 0; i < len + 1; i++) {
			if (i == len || line[i] == delim) {
				if (!field_reserve(&out, &cap, n)) { *nout = 0; return 0; }
				out[n].start = start; out[n].end = i; n++;
				start = i + 1;
			}
		}
	} else {
		size_t i = 0;
		while (i < len) {
			size_t start;
			while (i < len && isblank((unsigned char)line[i])) i++;
			if (i >= len) break;
			start = i;
			while (i < len && !isblank((unsigned char)line[i])) i++;
			if (!field_reserve(&out, &cap, n)) { *nout = 0; return 0; }
			out[n].start = start; out[n].end = i; n++;
		}
	}
	*nout = n;
	return out;
}

static void free_jlines(struct jline *l, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		/* l is read_all()'s non-NULL output whenever n > 0 (an empty
		 * input file leaves it NULL, always paired with n == 0). */
		__ownership_pointer_nonnull(l);
		free(l[i].text);
		free(l[i].fields);
	}
	free(l);
}

static int join_output_failed;

static void join_putc(int ch)
{
	if (!join_output_failed && putchar(ch) == EOF) join_output_failed = 1;
}

static void join_write(const char *p, size_t len)
{
	__ownership_readable_span(p, len);
	if (!join_output_failed && fwrite(p, 1, len, stdout) != len)
		join_output_failed = 1;
}

/* use_stdin, not `f != stdin`, decides the fclose() below -- the checker
 * can't prove opaque pointers unequal, so a direct comparison avoids a
 * false conditional-leak finding on read_all()'s fopen() (same idiom as
 * src/util/sed.c's script_buf_append_file()). */
static int read_all_failure(FILE *f, int use_stdin, int error)
{
	/* Closing is cleanup after the read/allocation failure already
	 * happened; restore the primary errno for diagnosis. */
	if (!use_stdin) (void)fclose(f);
	errno = error;
	return -1;
}

/* On failure *out can still hold lines parsed before the failing
 * getline()/malloc()/realloc() call (*nout reflects how many) -- every
 * caller below frees that partial result via free_jlines() rather than
 * treating a negative return as "*out is untouched". */
static int read_all(const char *path, struct jline **out withtok(heap_allocated),
                    size_t *nout, int have_delim, char delim)
{
	FILE *f;
	int use_stdin = !strcmp(path, "-");
	char *buf = 0;
	size_t bufcap = 0, cap = 0;
	ssize_t got;

	f = use_stdin ? stdin : fopen(path, "r");
	if (!f) return -1;

	*out = 0; *nout = 0;
	while ((got = getline(&buf, &bufcap, f)) >= 0) {
		size_t len = (size_t)got;
		char *text;
		if (len && buf[len - 1] == '\n') len--;
		{
			size_t bytes;
			if (!__util_size_add(len, 1, &bytes)) {
				free(buf);
				return read_all_failure(f, use_stdin, EOVERFLOW);
			}
			text = malloc(bytes);
		}
		if (!text) {
			int saved = errno;
			free(buf);
			return read_all_failure(f, use_stdin, saved ? saved : ENOMEM);
		}
	for (size_t i = 0; i < len; i++) text[i] = buf[i];
		text[len] = 0;
		if (*nout >= cap) {
			size_t newcap;
			struct jline *g;
			if (!__util_array_capacity(cap, *nout, 1, 64, sizeof **out, &newcap)) {
				free(text); free(buf);
				return read_all_failure(f, use_stdin, EOVERFLOW);
			}
			g = __util_reallocarray(*out, newcap, sizeof **out);
			if (!g) {
				int saved = errno;
				free(text); free(buf);
				return read_all_failure(f, use_stdin, saved ? saved : ENOMEM);
			}
			*out = g;
			cap = newcap;
		}
		(*out)[*nout].text = text;
		(*out)[*nout].len = len;
		(*out)[*nout].fields = split_fields(text, len, have_delim, delim, &(*out)[*nout].nfields);
		(*nout)++;
	}
	free(buf);
	if (!use_stdin && fclose(f) != 0) return -1;
	return 0;
}

/* Always returns either "" or a real slice of l->text -- never NULL. */
__attribute__((returns_nonnull))
static const char *field_ptr(const struct jline *l, int field1based, size_t *outlen)
{
	if (!l || field1based < 1 || (size_t)(field1based - 1) >= l->nfields) { *outlen = 0; return ""; }
	{
		struct field fl;
		/* l->fields is split_fields()'s non-NULL return whenever
		 * l->nfields > 0 (only OOM leaves it NULL, always paired with
		 * nfields == 0), with at least l->nfields elements live
		 * (field_reserve() never lets nfields exceed tracked capacity) --
		 * restated since neither fact is expressible as a struct-field
		 * invariant in ownership.h's vocabulary. */
		__ownership_pointer_nonnull(l->fields);
		__ownership_readable_span(l->fields, l->nfields * sizeof *l->fields);
		/* OPEN LINT FINDING: still reported as "dereference extent not
		 * proven sufficient" on all arches despite the restatement above
		 * -- same accepted class as src/util/du.c's residual findings;
		 * the guard just above makes this a true fact the extent prover
		 * doesn't close via any annotation this vocabulary offers. */
		fl = l->fields[field1based - 1];
		*outlen = fl.end - fl.start;
		return l->text + fl.start;
	}
}

static int keys_equal(const struct jline *a, int fa, const struct jline *b, int fb)
{
	size_t la, lb;
	const char *pa = field_ptr(a, fa, &la);
	const char *pb = field_ptr(b, fb, &lb);
	if (la != lb) return 0;
	/* field_ptr() returns either "" with *outlen == 0, or a real slice
	 * of a->text/b->text with *outlen its byte count -- restated the
	 * same way join_write() restates this for fwrite(). */
	__ownership_pointer_nonnull(pa);
	__ownership_pointer_nonnull(pb);
	__ownership_readable_span(pa, la);
	__ownership_readable_span(pb, lb);
	for (size_t i = 0; i < la; i++) if (pa[i] != pb[i]) return 0;
	return 1;
}

static int keys_cmp(const struct jline *a, int fa, const struct jline *b, int fb)
{
	size_t la, lb, n;
	const char *pa = field_ptr(a, fa, &la);
	const char *pb = field_ptr(b, fb, &lb);
	n = la < lb ? la : lb;
	for (size_t i = 0; i < n; i++)
		if (pa[i] != pb[i])
			return (unsigned char)pa[i] < (unsigned char)pb[i] ? -1 : 1;
	if (la < lb) return -1;
	if (la > lb) return 1;
	return 0;
}

static void put_field_raw(const char *p, size_t len, const char *empty_repl)
{
	if (len == 0 && empty_repl) {
		/* empty_repl, whenever non-NULL, is -e's own argv element (or a
		 * slice of one), NUL-terminated per __util_join_main's
		 * elements_withtok(null_terminated, argc) contract -- restated
		 * since the checker doesn't trace that through plain
		 * `const char *` parameters. */
		__ownership_string_terminated(empty_repl);
		join_write(empty_repl, strlen(empty_repl));
	}
	else join_write(p, len);
}

/* Default (no -o) output for a matched pair, or an unpaired single line
 * (l2 or l1 NULL): join field, then file1's remaining fields, then
 * file2's -- the absent side contributes no fields (see file header). */
static void print_default(const struct jline *l1, int jf1, const struct jline *l2, int jf2, char outsep) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	size_t klen; const char *kp;
	size_t i;
	int first = 1;

	if (l1) kp = field_ptr(l1, jf1, &klen);
	else kp = field_ptr(l2, jf2, &klen);
	join_write(kp, klen);
	first = 0;

	if (l1) {
		for (i = 1; i <= l1->nfields; i++) {
			size_t flen; const char *fp;
			if ((int)i == jf1) continue;
			fp = field_ptr(l1, (int)i, &flen);
			if (!first) join_putc(outsep);
			join_write(fp, flen);
			first = 0;
		}
	}
	if (l2) {
		for (i = 1; i <= l2->nfields; i++) {
			size_t flen; const char *fp;
			if ((int)i == jf2) continue;
			fp = field_ptr(l2, (int)i, &flen);
			if (!first) join_putc(outsep);
			join_write(fp, flen);
			first = 0;
		}
	}
	join_putc('\n');
}

/* Every call site passes at least one of l1/l2 non-NULL (a matched pair
 * has both; an unpairable line under -a has exactly one), so the file==0
 * branch's fallback below never actually runs with both NULL --
 * clang-analyzer-core.NullDereference flags it anyway since nothing
 * local proves that to a whole-program analyzer; a known, accepted
 * false positive (see __util_join_main() for the three call shapes). */
static void print_o(const struct outspec *specs, size_t nspecs, const struct jline *l1, int jf1,
                     const struct jline *l2, int jf2, char outsep, const char *empty_repl) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	size_t i;
	for (i = 0; i < nspecs; i++) {
		size_t len; const char *p;
		/* specs is parse_o_list()'s non-NULL output whenever nspecs > 0
		 * (left NULL only alongside nspecs == 0). */
		__ownership_pointer_nonnull(specs);
		if (i) join_putc(outsep);
		if (specs[i].file == 0) {
			if (l1) p = field_ptr(l1, jf1, &len);
			else p = field_ptr(l2, jf2, &len);
		} else if (specs[i].file == 1) {
			if (l1) { p = field_ptr(l1, specs[i].field, &len); }
			else { p = ""; len = 0; }
		} else {
			if (l2) { p = field_ptr(l2, specs[i].field, &len); }
			else { p = ""; len = 0; }
		}
		put_field_raw(p, len, empty_repl);
	}
	join_putc('\n');
}

/* val is always -o's own argv-derived argument, never NULL. */
__attribute__((nonnull(1)))
static int parse_o_list(const char *val, struct outspec **specs withtok(heap_allocated),
                        size_t *nspecs, size_t *cap)
{
	const char *p = val;
	while (*p) {
		struct outspec s;
		char *end;
		long v;
		while (*p == ',' || isblank((unsigned char)*p)) p++;
		if (!*p) break;
		if (*p == '0' && (p[1] == 0 || p[1] == ',' || isblank((unsigned char)p[1]))) {
			s.file = 0; s.field = 0; p++;
		} else {
			v = strtol(p, &end, 10);
			if (end == p || (v != 1 && v != 2) || *end != '.') return -1;
			s.file = (int)v;
			p = end + 1;
			v = strtol(p, &end, 10);
			if (end == p || v < 1) return -1;
			s.field = (int)v;
			p = end;
		}
		if (*nspecs >= *cap) {
			size_t newcap;
			struct outspec *g;
			if (!__util_array_capacity(*cap, *nspecs, 1, 16, sizeof **specs, &newcap)) return -1;
			g = __util_reallocarray(*specs, newcap, sizeof **specs);
			if (!g) return -1;
			*specs = g;
			*cap = newcap;
		}
		(*specs)[(*nspecs)++] = s;
	}
	return 0;
}

int __util_join_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int jf1 = 1, jf2 = 1;
	int a1 = 0, a2 = 0;
	int have_delim = 0;
	char delim = ' ';
	char outsep = ' ';
	const char *empty_repl = 0;
	struct outspec *specs = 0;
	size_t nspecs = 0, speccap = 0;
	const char *paths[2];
	int npaths = 0;
	struct jline *L1 = 0, *L2 = 0;
	size_t n1 = 0, n2 = 0;
	int i;
	join_output_failed = 0;

	/* Every error exit below goes through `goto bad;`, not a bare
	 * `return 1;`: -o may already have allocated `specs` by the time a
	 * later option is rejected, and `bad:` is the one place that frees
	 * it regardless of which option failed. */
	for (i = 1; i < argc; i++) {
		char *arg = argv[i];

		if (!strcmp(arg, "--")) { i++; break; }
		if (arg[0] != '-' || arg[1] == 0) break;

		if (!strcmp(arg, "-v")) {
			__util_diagf("join: -v: not implemented -- see src/util/join.c\n");
			goto bad;
		}
		if (!strncmp(arg, "-1", 2)) {
			const char *val; char *end; long v;
			if (arg[2]) val = arg + 2;
			else { if (++i >= argc) { __util_diagf("join: -1: option requires an argument\n"); goto bad; } val = argv[i]; }
			v = strtol(val, &end, 10);
			if (*end || v < 1) { __util_diagf("join: -1: %s: invalid field\n", val); goto bad; }
			jf1 = (int)v;
			continue;
		}
		if (!strncmp(arg, "-2", 2)) {
			const char *val; char *end; long v;
			if (arg[2]) val = arg + 2;
			else { if (++i >= argc) { __util_diagf("join: -2: option requires an argument\n"); goto bad; } val = argv[i]; }
			v = strtol(val, &end, 10);
			if (*end || v < 1) { __util_diagf("join: -2: %s: invalid field\n", val); goto bad; }
			jf2 = (int)v;
			continue;
		}
		if (!strncmp(arg, "-a", 2)) {
			const char *val; char *end; long v;
			if (arg[2]) val = arg + 2;
			else { if (++i >= argc) { __util_diagf("join: -a: option requires an argument\n"); goto bad; } val = argv[i]; }
			v = strtol(val, &end, 10);
			if (*end || (v != 1 && v != 2)) { __util_diagf("join: -a: %s: must be 1 or 2\n", val); goto bad; }
			if (v == 1) a1 = 1; else a2 = 1;
			continue;
		}
		if (!strncmp(arg, "-e", 2)) {
			if (arg[2]) empty_repl = arg + 2;
			else { if (++i >= argc) { __util_diagf("join: -e: option requires an argument\n"); goto bad; } empty_repl = argv[i]; }
			continue;
		}
		if (!strncmp(arg, "-t", 2)) {
			const char *val;
			if (arg[2]) val = arg + 2;
			else { if (++i >= argc) { __util_diagf("join: -t: option requires an argument\n"); goto bad; } val = argv[i]; }
			/* val is an offset into argv[i], or argv[i] itself -- never
			 * NULL per argv's own elements_withtok(null_terminated, argc)
			 * contract. */
			__ownership_pointer_nonnull(val);
			if (val[0] == 0 || val[1] != 0) { __util_diagf("join: -t: field separator must be exactly one character\n"); goto bad; }
			delim = val[0];
			have_delim = 1;
			outsep = val[0];
			continue;
		}
		if (!strncmp(arg, "-o", 2)) {
			const char *val;
			if (arg[2]) val = arg + 2;
			else { if (++i >= argc) { __util_diagf("join: -o: option requires an argument\n"); goto bad; } val = argv[i]; }
			if (parse_o_list(val, &specs, &nspecs, &speccap) < 0) {
				__util_diagf("join: -o: %s: invalid output list\n", val);
				goto bad;
			}
			continue;
		}
		__util_diagf("join: %s: invalid option\n", arg);
		goto bad;
	}

	for (; i < argc; i++) {
		if (npaths >= 2) { __util_diagf("join: too many operands\n"); goto bad; }
		paths[npaths++] = argv[i];
	}
	if (npaths != 2) {
		__util_diagf("join: usage: join [-a n] [-e string] [-o list] [-t char] [-1 f] [-2 f] file1 file2\n");
		goto bad;
	}
	if (!strcmp(paths[0], "-") && !strcmp(paths[1], "-")) {
		__util_diagf("join: file1 and file2 cannot both be standard input\n");
		goto bad;
	}

	if (read_all(paths[0], &L1, &n1, have_delim, delim) < 0) {
		int saved = errno;
		__util_diagf("join: %s: %s\n", paths[0], strerror(saved));
		goto bad;
	}
	if (read_all(paths[1], &L2, &n2, have_delim, delim) < 0) {
		int saved = errno;
		__util_diagf("join: %s: %s\n", paths[1], strerror(saved));
		goto bad;
	}

	{
		size_t i1 = 0, i2 = 0;
		while (i1 < n1 && i2 < n2) {
			int cmp;
			/* L1/L2 are read_all()'s non-NULL output whenever n1/n2 are
			 * nonzero (an empty input file leaves a heap array NULL,
			 * always paired with n == 0); i1 < n1 and i2 < n2 already
			 * hold here, and every index derived from them below stays
			 * within [0, n1) / [0, n2). */
			__ownership_pointer_nonnull(L1);
			__ownership_pointer_nonnull(L2);
			cmp = keys_cmp(&L1[i1], jf1, &L2[i2], jf2);
			if (cmp == 0) {
				size_t g1s = i1, g2s = i2, g1e, g2e, x, y;
				while (i1 < n1 && keys_equal(&L1[i1], jf1, &L1[g1s], jf1)) i1++;
				g1e = i1;
				while (i2 < n2 && keys_equal(&L2[i2], jf2, &L2[g2s], jf2)) i2++;
				g2e = i2;
				for (x = g1s; x < g1e; x++)
					for (y = g2s; y < g2e; y++) {
						if (nspecs) print_o(specs, nspecs, &L1[x], jf1, &L2[y], jf2, outsep, empty_repl);
						else print_default(&L1[x], jf1, &L2[y], jf2, outsep);
					}
			} else if (cmp < 0) {
				if (a1) {
					if (nspecs) print_o(specs, nspecs, &L1[i1], jf1, 0, jf2, outsep, empty_repl);
					else print_default(&L1[i1], jf1, 0, jf2, outsep);
				}
				i1++;
			} else {
				if (a2) {
					if (nspecs) print_o(specs, nspecs, 0, jf1, &L2[i2], jf2, outsep, empty_repl);
					else print_default(0, jf1, &L2[i2], jf2, outsep);
				}
				i2++;
			}
		}
		if (a1) for (; i1 < n1; i1++) {
			if (nspecs) print_o(specs, nspecs, &L1[i1], jf1, 0, jf2, outsep, empty_repl);
			else print_default(&L1[i1], jf1, 0, jf2, outsep);
		}
		if (a2) for (; i2 < n2; i2++) {
			if (nspecs) print_o(specs, nspecs, 0, jf1, &L2[i2], jf2, outsep, empty_repl);
			else print_default(0, jf1, &L2[i2], jf2, outsep);
		}
	}

	free(specs);
	free_jlines(L1, n1);
	free_jlines(L2, n2);
	if (fflush(stdout) != 0) join_output_failed = 1;
	return join_output_failed ? 1 : 0;

	/* Shared error-exit for every `goto bad;` above: L1/L2/n1/n2 are
	 * either still their initial 0 (free_jlines() is then a no-op) or
	 * hold a partial read_all() result, and free_jlines() takes exactly
	 * the count read_all() reported before failing. */
bad:
	free(specs);
	free_jlines(L1, n1);
	free_jlines(L2, n2);
	return 1;
}
