/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * join(1p): `join [-a file_number] [-e string] [-o list] [-t char]
 * [-1 field] [-2 field] file1 file2` -- a relational equijoin on sorted
 * input.  Both files MUST already be sorted on their own join field
 * (the same "comm/join don't sort for you" property src/util/comm.c's
 * header spells out; join does not verify sortedness either).
 *
 * DEFAULT FIELD SPLITTING (-t not given) is deliberately NOT the same
 * rule sort(1p)'s default uses (src/util/sort.c's header) -- this is
 * exactly the "easy to get subtly wrong" trap the batch instructions
 * warned about: "The default input field separators shall be <blank>
 * characters.  In this case, multiple separators shall count as one
 * field separator, and leading separators shall be ignored."  So unlike
 * sort's default (which keeps a line's leading blanks as part of field
 * 1), join's default strips them entirely and never produces an empty
 * field from a run of blanks -- ordinary whitespace tokenization, not
 * sort's "leading separator included in the first field" rule.
 *
 * -t char changes this to "every appearance of char in a line shall be
 * significant" -- an ordinary single-character split with empty fields
 * allowed between adjacent separators, the same as sort's -t.  -t also
 * sets "the default output field separator" (a single <space> when -t
 * is absent) -- used to join every printed field together, on both the
 * default output and an -o list's output.
 *
 * -1 field / -2 field: which field of file1/file2 to join on (default:
 * field 1 of each).
 *
 * DEFAULT OUTPUT (no -o): "the join field, then the remaining fields
 * from file1, then the remaining fields from file2" -- for a genuinely
 * *unpairable* line (only relevant with -a), there is no counterpart
 * line to draw a field count from, so that half of the formula simply
 * contributes nothing: an unpaired file1 line under default output is
 * exactly that line's own fields (join field first, since it already
 * is one of them when the join field is field 1; reordered in front
 * when it is not), never padded with empty placeholders for file2's
 * fields.
 *
 * -o list: "file_number.field" (file_number 1 or 2) or "0" for the join
 * field, comma- or blank-separated, one or more -o options accumulate.
 * "Fields selected by list that do not appear in the input shall be
 * treated as empty output fields" -- this is what makes -o's behaviour
 * on an unpairable line genuinely different from the default-output
 * case above: an -o list is a *fixed* field layout applied to every
 * output line including unpairable ones, so a file2.N entry on an
 * unpaired file1 line resolves to an empty field (subject to -e)
 * instead of just being omitted.
 *
 * -e string: "Replace empty output fields in the list selected by -o
 * with the string string" -- read literally, this is scoped to -o's
 * own output construction (build_o_output() below); it has no defined
 * effect on the default output format, and this file does not invent
 * one for it.
 *
 * -a file_number: also emit a line for each unpairable line of that
 * file (both -a 1 and -a 2 may be given).  -v (print *only* unpairable
 * lines, dropping the default matched output) is a real, related join
 * option this file does not implement -- refused loudly with a
 * diagnostic rather than silently reinterpreted as -a, per this
 * project's "refuse rather than silently ignore" rule (src/util/
 * touch.c's -d comment is the canonical statement of it).
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
 * read_all()'s `(*out)[*nout].text = text;`/`.fields = split_fields(...);`
 * as transferring the obligation into the array, not leaking it (same
 * "assignment into an annotated destination moves the obligation" as
 * src/util/od.c's struct instream.cur). */
struct jline {
	char *text withtok(heap_allocated);
	size_t len;
	struct field *fields withtok(heap_allocated);
	size_t nfields;
};

struct outspec { int file; int field; }; /* file: 0, 1 or 2 */

/* realloc(), not out = realloc(out, ...): on failure realloc() returns
 * NULL without freeing the original block, so assigning straight back
 * into `out` would both lose the data already collected *and* leak that
 * original block -- the classic realloc mistake clang-tidy's bugprone-
 * suspicious-realloc-usage and cppcheck's memleakOnRealloc both flag. */
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

/* Ensures `*out` has room for field index `n`, growing it via
 * fields_grow() first if not; on failure `*out` is freed and cleared so
 * every caller can propagate a single false return without repeating
 * fields_grow()'s own free-on-failure contract at each call site. */
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
		/* l is read_all()'s own non-NULL output whenever n > 0 (only an
		 * empty input file leaves it NULL, and that always pairs with
		 * n == 0, which never enters this loop) -- restated here since
		 * that struct-held-array invariant is not itself expressible in
		 * ownership.h's vocabulary. */
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
 * can't prove opaque pointers unequal, so a direct comparison makes
 * read_all()'s fopen() allocation look conditionally leaked (same idiom as
 * src/util/sed.c's script_buf_append_file()). */
static int read_all_failure(FILE *f, int use_stdin, int error)
{
	/* Closing an input is cleanup after the read/allocation failure.  Check
	 * no further outcome here, but restore the primary errno for diagnosis. */
	if (!use_stdin) (void)fclose(f);
	errno = error;
	return -1;
}

/* On failure this can still leave *out holding whatever lines were
 * successfully parsed before the failing getline()/malloc()/realloc()
 * call (*nout reflects exactly how many) -- every caller below frees
 * that partial result via free_jlines() rather than treating a
 * negative return as "*out is untouched". */
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
		/* l->fields is split_fields()'s own non-NULL return whenever
		 * l->nfields > 0 (only an OOM leaves it NULL, and that always
		 * pairs with nfields == 0), with at least l->nfields elements
		 * live (field_reserve() never lets nfields exceed the array's
		 * own tracked capacity) -- both are struct-field invariants not
		 * themselves expressible in ownership.h's vocabulary, so both
		 * are restated here: nonnull the same way src/util/od.c uses
		 * this axiom for its own struct-held array field, and the
		 * extent via the same __ownership_readable_span() idiom
		 * join_write() already uses for its own field-slice fact. */
		__ownership_pointer_nonnull(l->fields);
		__ownership_readable_span(l->fields, l->nfields * sizeof *l->fields);
		/* The nonnull axiom above closes cleanly, but tools/lint.sh
		 * ownership still reports this index as "dereference extent is
		 * not proven sufficient" on all three arches even with the
		 * readable_span restatement in place: left open, same accepted
		 * class as src/util/du.c's documented residual findings -- a
		 * true fact (field1based - 1 < l->nfields is guarded just above)
		 * the linear/Z3 extent prover does not close via any annotation
		 * this vocabulary offers. */
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
	/* field_ptr() always returns either "" with *outlen == 0, or a real
	 * slice of a->text/b->text with *outlen == that slice's own byte
	 * count -- restated here the same way join_write() restates an
	 * analogous field-slice fact for fwrite(). */
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
		/* empty_repl, whenever non-NULL, is always -e's own argv element
		 * (or a slice of one), genuinely null-terminated by
		 * __util_join_main's elements_withtok(null_terminated, argc)
		 * contract on argv -- restated here since the checker does not
		 * trace that fact through put_field_raw()'s and print_o()'s
		 * plain `const char *` parameters. */
		__ownership_string_terminated(empty_repl);
		join_write(empty_repl, strlen(empty_repl));
	}
	else join_write(p, len);
}

/* Default (no -o) output for a matched pair, or an unpaired single line
 * (l2 or l1 NULL): "the join field, then the remaining fields from
 * file1, then the remaining fields from file2" -- the absent side
 * simply contributes no fields at all (see this file's header). */
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

/* Every call site below passes at least one of l1/l2 non-NULL (a
 * matched pair has both; an unpairable line under -a has exactly one)
 * -- the `l1 ? ... : field_ptr(l2, ...)` fallback in the file==0 branch
 * below is never actually reached with both NULL, even though nothing
 * local to this function proves that to a whole-program static
 * analyzer (clang-analyzer-core.NullDereference flags it here for
 * exactly that reason -- a known, accepted false positive, not a real
 * bug: see this file's __util_join_main() for the three call shapes). */
static void print_o(const struct outspec *specs, size_t nspecs, const struct jline *l1, int jf1,
                     const struct jline *l2, int jf2, char outsep, const char *empty_repl) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	size_t i;
	for (i = 0; i < nspecs; i++) {
		size_t len; const char *p;
		/* specs is parse_o_list()'s own non-NULL output whenever
		 * nspecs > 0 (specs is only ever left NULL alongside nspecs == 0)
		 * -- restated here since that struct-held-array invariant is not
		 * itself expressible in ownership.h's vocabulary. */
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

	/* Every error exit from here down goes through `goto bad;` rather
	 * than a bare `return 1;`, on purpose: -o may already have run (in
	 * any argv position -- options are not required to appear in any
	 * particular order) and left `specs` allocated by the time a *later*
	 * option is rejected, so every error path needs to free it, not just
	 * -o's own.  `bad:` is the one place that does. */
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
			/* val is either an offset into argv[i] or argv[i] itself,
			 * genuinely never NULL by this function's own
			 * elements_withtok(null_terminated, argc) contract on argv --
			 * restated here since the checker does not trace that fact
			 * through the two assignments above. */
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
			/* L1/L2 are read_all()'s own non-NULL output whenever n1/n2
			 * are nonzero (only an empty input file leaves a heap array
			 * NULL, and that always pairs with n == 0) -- i1 < n1 and
			 * i2 < n2 are already established by this loop's own
			 * condition, so both are genuinely nonnull for every index
			 * derived from i1/i2 below (g1s/g1e/g2s/g2e/x/y are all
			 * bounded within [0, n1) / [0, n2)). Restated here since that
			 * struct-held-array invariant is not itself expressible in
			 * ownership.h's vocabulary. */
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

	/* Shared error-exit for every `goto bad;` above -- both those
	 * reached before either read_all() call (L1/L2/n1/n2 still their
	 * initial 0, so free_jlines() on them is a harmless no-op) and the
	 * two read_all() failures themselves (which may leave a *partially*
	 * filled L1 or L2 behind; free_jlines() takes exactly the count
	 * read_all() reported before failing, not a stale full count). */
bad:
	free(specs);
	free_jlines(L1, n1);
	free_jlines(L2, n2);
	return 1;
}
