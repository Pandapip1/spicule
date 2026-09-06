/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * csplit(1p): `csplit [-ks] [-f prefix] [-n number] file arg...` --
 * splits `file` into consecutively-numbered pieces at the boundaries
 * named by each `arg`.
 *
 * OPTIONS:
 *  -f prefix   "Name the created files prefix00, prefix01, ...".
 *              Default "xx".
 *  -k          "Leave previously created files intact [on error].  By
 *              default, csplit shall remove created files if an error
 *              occurs."
 *  -n number   "Use number decimal digits ... The default shall be 2."
 *  -s          "Suppress the output of file size messages" (the plain
 *              "%d\n" byte count this utility writes to stdout after
 *              each piece it creates).
 *
 * ARG GRAMMAR implemented:
 *  line_no          "Create a file from the current line up to (but not
 *                    including) the line number line_no."
 *  /regexp/[offset]  "... up to, but not including, the line that
 *                    results from the evaluation of the regular
 *                    expression with offset, if any, applied."
 *  %regexp%[offset]  "Equivalent to /regexp/[offset], except that no
 *                    file shall be created for the selected section."
 *
 * `regexp` is a BRE (Basic Regular Expression -- this project's own
 * src/regex/regex.c, regcomp() with no REG_EXTENDED), the same flavor
 * grep(1p)/sed(1p) default to, compiled fresh from each `arg` operand
 * against the whole file kept in memory (read_all_lines() below) so a
 * later regexp can search forward from wherever the previous split
 * point left off.
 *
 * NOT implemented, refused loudly rather than silently dropped or
 * half-applied: the `{num}` repeat-count operand ("If it follows a
 * rexp type operand, that operand shall be applied num more times") --
 * a real csplit(1p) feature, but this build stops at a diagnostic
 * whenever a `{...}`-shaped arg is seen, rather than guessing how many
 * of the preceding regexp's matches to silently consume.
 *
 * The implicit final piece -- "the current line up to the end of
 * file", after every explicit `arg` has been applied -- is always
 * created, per every real csplit(1p) implementation, even if it is
 * empty.
 *
 * EXIT STATUS: "0 Successful completion." ">0 An error occurred."
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <regex.h>
#include "util.h"

struct lines {
	char **text;   /* text[i]: malloc'd line i, WITH its trailing '\n' if the input had one */
	size_t *len;
	int n;
};

/* Frees everything a struct lines can own, at any point in its life --
 * fresh-zeroed, fully populated, or (the reason this exists as a
 * separate function rather than being inlined at the one success-path
 * call site) left however read_all_lines() below stopped partway
 * through on an allocation failure: L->n always reflects exactly how
 * many of L->text[]/L->len[]'s slots hold a real, owned line. */
static void free_lines(struct lines *L)
{
	int i;
	for (i = 0; i < L->n; i++) free(L->text[i]);
	free((void *)L->text);
	free(L->len);
	L->text = 0;
	L->len = 0;
	L->n = 0;
}

static int read_all_lines(FILE *f, struct lines *L)
{
	char *buf = 0;
	size_t cap = 0;
	int alloc = 0;

	L->text = 0;
	L->len = 0;
	L->n = 0;
	for (;;) {
		ssize_t got = getline(&buf, &cap, f);
		if (got < 0) break;
		if (L->n >= alloc) {
			if (alloc > INT_MAX / 2) { free(buf); return -1; }
			int newalloc = alloc ? alloc * 2 : 64;
			/* realloc()'s own contract: on success the old block is
			 * gone (freed or moved) regardless of what the caller does
			 * with the return value, so L->text/L->len are committed
			 * to each new pointer the instant it is known good --
			 * never left holding a stale pointer to memory realloc()
			 * has already invalidated while a *second* realloc() (for
			 * the other array) is still pending and might fail. */
			char **nt = (char **)__util_reallocarray((void *)L->text, (size_t)newalloc, sizeof *nt);
			size_t *nl;
			if (!nt) { free(buf); return -1; }
			L->text = nt;
			nl = __util_reallocarray(L->len, (size_t)newalloc, sizeof *nl);
			if (!nl) { free(buf); return -1; }
			L->len = nl;
			alloc = newalloc;
		}
		{
			size_t bytes;
			if (!__util_size_add((size_t)got, 1, &bytes)) { free(buf); return -1; }
			L->text[L->n] = malloc(bytes);
		}
		if (!L->text[L->n]) { free(buf); return -1; }
		memcpy(L->text[L->n], buf, (size_t)got + 1);
		L->len[L->n] = (size_t)got;
		L->n++;
	}
	free(buf);
	return 0;
}

/* Parses "<delim>pattern<delim>[+-]offset" starting at arg[0]==delim;
 * <delim> may appear literally inside pattern as "\<delim>". */
static int extract_delimited(const char *arg, char delim, char *pat, size_t patsz, long *offset)
{
	size_t i = 1, o = 0;
	char *end;

	while (arg[i] && arg[i] != delim) {
		if (arg[i] == '\\' && arg[i + 1]) {
			if (o + 1 < patsz) pat[o++] = arg[i + 1];
			i += 2;
			continue;
		}
		if (o + 1 < patsz) pat[o++] = arg[i];
		i++;
	}
	if (arg[i] != delim) return -1; /* unterminated */
	pat[o] = 0;
	i++;
	*offset = 0;
	if (arg[i]) {
		*offset = strtol(arg + i, &end, 10);
		if (*end) return -1;
	}
	return 0;
}

/* Searches lines[from..n) for the first line regexec() matches;
 * returns its index, or -1 if none matched. */
static int find_match(struct lines *L, int from, const char *pattern)
{
	regex_t re;
	int i, found = -1;

	if (regcomp(&re, pattern, REG_NOSUB) != 0) return -2; /* bad pattern: distinct from "no match" */
	for (i = from; i < L->n; i++) {
		/* regexec() wants a NUL-terminated string; L->text[i] already
		 * is one (read_all_lines() copies getline()'s own NUL). */
		if (regexec(&re, L->text[i], 0, 0, 0) == 0) { found = i; break; }
	}
	regfree(&re);
	return found;
}

static int apply_offset(int base, long offset, int maximum, int *result)
{
	size_t sum;

	if (base < 0 || maximum < base) return 0;
	if (offset < 0) {
		if (offset < -(long)base) return 0;
		*result = (int)((size_t)base - (size_t)(-offset));
		return 1;
	}
	if (!__util_size_add((size_t)base, (size_t)offset, &sum) ||
	    sum > (size_t)maximum) return 0;
	*result = (int)sum;
	return 1;
}

struct created {
	char **names;
	int n, cap;
};

static int remember_created(struct created *c, const char *name)
{
	if (c->n >= c->cap) {
		size_t grown;
		int newcap;
		if (!__util_array_capacity((size_t)c->cap, (size_t)c->n, 1, 16,
		    sizeof *c->names, &grown) || grown > INT_MAX) return -1;
		newcap = (int)grown;
		char **nn = (char **)__util_reallocarray((void *)c->names, (size_t)newcap, sizeof *nn);
		if (!nn) return -1;
		c->names = nn;
		c->cap = newcap;
	}
	c->names[c->n] = strdup(name);
	if (!c->names[c->n]) return -1;
	c->n++;
	return 0;
}

static void cleanup_created(struct created *c, int keep)
{
	int i;
	if (!keep) for (i = 0; i < c->n; i++) (void)unlink(c->names[i]);
	for (i = 0; i < c->n; i++) free(c->names[i]);
	free((void *)c->names);
}

/* Common failure exit for write_piece() below: closes `f` (skipped when
 * `f` is NULL, meaning it was already closed), unlinks the half-written
 * piece, restores `saved` as errno for the diagnostic, and always
 * returns -1 so every call site below can just `return piece_fail(...)`. */
static int piece_fail(FILE *f, const char *name, int saved)
{
	if (f) (void)fclose(f);
	(void)unlink(name);
	errno = saved;
	__util_diagf("csplit: %s: %s\n", name, strerror(saved));
	return -1;
}

/* Writes lines[from..to) to a new piece file, records it, and reports
 * its size unless -s. Returns 0 on success, -1 on a real I/O error. */
static int write_piece(struct lines *L, int from, int to, const char *prefix, int ndigits, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
                        int piece_no, int quiet, struct created *created) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	char name[512];
	FILE *f;
	long size = 0;
	int i, n;

	n = snprintf(name, sizeof name, "%s%0*d", prefix, ndigits, piece_no);
	if (n < 0 || (size_t)n >= sizeof name) {
		if (n >= 0) errno = ENAMETOOLONG;
		return -1;
	}
	f = fopen(name, "wb");
	if (!f) {
		int saved = errno;
		__util_diagf("csplit: %s: %s\n", name, strerror(saved));
		return -1;
	}
	for (i = from; i < to; i++) {
		size_t next_size;
		if (!__util_size_add((size_t)size, L->len[i], &next_size) ||
		    next_size > LONG_MAX)
			return piece_fail(f, name, EFBIG);
		if (fwrite(L->text[i], 1, L->len[i], f) != L->len[i])
			return piece_fail(f, name, errno);
		size = (long)next_size;
	}
	if (fclose(f) < 0) return piece_fail(0, name, errno);
	if (remember_created(created, name) < 0) {
		__util_diagf("csplit: out of memory\n");
		return -1;
	}
	if (!quiet) printf("%ld\n", size);
	return 0;
}

int __util_csplit_main(int argc, char **argv)
{
	int i = 1;
	int opt_k = 0, opt_s = 0;
	const char *prefix = "xx";
	int ndigits = 2;
	const char *filename;
	FILE *f;
	struct lines L;
	struct created created;
	int cur = 0, piece = 0;
	int had_error = 0;

	for (; i < argc; i++) {
		char *a = argv[i];
		if (a[0] != '-' || a[1] == 0) break;
		if (!strcmp(a, "--")) { i++; break; }
		if (!strcmp(a, "-k")) { opt_k = 1; continue; }
		if (!strcmp(a, "-s")) { opt_s = 1; continue; }
		if (!strcmp(a, "-f")) {
			if (i + 1 >= argc) { __util_diagf("csplit: -f: option requires an argument\n"); return 1; }
			prefix = argv[++i];
			continue;
		}
		if (!strcmp(a, "-n")) {
			char *end;
			long v;
			if (i + 1 >= argc) { __util_diagf("csplit: -n: option requires an argument\n"); return 1; }
			v = strtol(argv[++i], &end, 10);
			/* Same cast-before-validate hazard as the line_no operand
			 * below: check the un-narrowed `long` against INT_MAX before
			 * ever casting to `int`, so a digit count too large to be a
			 * real `int` is rejected outright rather than silently
			 * wrapping into some small (or negative) value that then
			 * slips past the `ndigits <= 0` check. */
			if (*end || v <= 0 || v > INT_MAX) { __util_diagf("csplit: -n: invalid digit count\n"); return 1; }
			ndigits = (int)v;
			continue;
		}
		__util_diagf("csplit: %s: invalid option\n", a);
		return 1;
	}

	if (i >= argc) { __util_diagf("csplit: missing file operand\n"); return 1; }
	filename = argv[i++];
	if (i >= argc) { __util_diagf("csplit: missing arg operand\n"); return 1; }

	f = strcmp(filename, "-") == 0 ? stdin : fopen(filename, "rb");
	if (!f) {
		int saved = errno;
		__util_diagf("csplit: %s: %s\n", filename, strerror(saved));
		return 1;
	}
	if (read_all_lines(f, &L) < 0) {
		/* The allocation/read failure is primary; close is cleanup only. */
		if (f != stdin) (void)fclose(f);
		free_lines(&L); /* frees whatever lines were read before the allocation failure */
		__util_diagf("csplit: %s: out of memory reading file\n", filename);
		return 1;
	}
	if (f != stdin && fclose(f) != 0) {
		free_lines(&L);
		__util_diagf("csplit: %s: %s\n", filename, strerror(errno));
		return 1;
	}

	memset(&created, 0, sizeof created);

	for (; i < argc && !had_error; i++) {
		const char *a = argv[i];
		int target;

		if (a[0] == '{') {
			__util_diagf("csplit: %s: the '{num}' repeat operand is not "
			                "implemented -- see src/util/csplit.c\n", a);
			had_error = 1;
			break;
		}
		if (a[0] == '/' || a[0] == '%') {
			char pat[512];
			long offset;
			int m;

			if (extract_delimited(a, a[0], pat, sizeof pat, &offset) < 0) {
				__util_diagf("csplit: %s: unterminated or malformed pattern\n", a);
				had_error = 1;
				break;
			}
			m = find_match(&L, cur, pat);
			if (m == -2) {
				__util_diagf("csplit: %s: invalid regular expression\n", pat);
				had_error = 1;
				break;
			}
			if (m < 0) {
				__util_diagf("csplit: %s: no match\n", pat);
				had_error = 1;
				break;
			}
			if (!apply_offset(m, offset, L.n, &target) || target < cur) {
				__util_diagf("csplit: %s: match plus offset is out of range\n", a);
				had_error = 1;
				break;
			}
			if (a[0] == '/') {
				if (write_piece(&L, cur, target, prefix, ndigits, piece++, opt_s, &created) < 0) {
					had_error = 1;
					break;
				}
			}
			/* '%': "no file shall be created for the selected
			 * section" -- still advances `cur`, no piece number
			 * consumed (piece numbering only counts real files). */
			cur = target;
			continue;
		}
		{
			char *end;
			long lineno, t;
			lineno = strtol(a, &end, 10);
			if (*end || lineno <= 0) {
				__util_diagf("csplit: %s: invalid arg (expected a line number, "
				                "/regexp/[offset], or %%regexp%%[offset])\n", a);
				had_error = 1;
				break;
			}
			/* Validate in `long` BEFORE narrowing to `int`: L.n is an
			 * `int` (bounded well under INT_MAX by read_all_lines()'s own
			 * cap), but `lineno` is a `long`, 64 bits wide on this
			 * project's Linux targets even though `int` stays 32 bits
			 * there. A line number like 4294967301 (2^32+5) is a
			 * perfectly valid `long` -- no strtol() clamp involved at
			 * all -- but truncates to 5 on a naive `(int)lineno`,
			 * silently turning an out-of-range operand into a
			 * plausible-looking small target instead of the "line
			 * number is out of range" diagnostic a real csplit(1p) would
			 * give. Comparing the unnarrowed `t` against `cur`/`L.n`
			 * first (both promoted to `long` for the comparison) means
			 * the cast below only ever runs once t is already known to
			 * fit inside `int`. */
			t = lineno - 1;
			if (t < cur || t > (long)L.n) {
				__util_diagf("csplit: %s: line number is out of range\n", a);
				had_error = 1;
				break;
			}
			target = (int)t;
			if (write_piece(&L, cur, target, prefix, ndigits, piece++, opt_s, &created) < 0) {
				had_error = 1;
				break;
			}
			cur = target;
		}
	}

	if (!had_error) {
		/* The implicit final piece: current line through EOF. */
		if (write_piece(&L, cur, L.n, prefix, ndigits, piece++, opt_s, &created) < 0)
			had_error = 1;
	}

	if (had_error) {
		/* "By default, csplit shall remove created files if an error
		 * occurs" -- -k keeps them instead. */
		cleanup_created(&created, opt_k);
	} else {
		cleanup_created(&created, 1); /* success: never remove */
	}

	free_lines(&L);

	return had_error ? 1 : 0;
}
