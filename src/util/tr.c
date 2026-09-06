/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * tr(1p). XCU's SYNOPSIS is exactly four forms, and every combination
 * this file accepts is one of them -- anything else is refused rather
 * than guessed at:
 *
 *   tr [-c|-C] [-s] string1 string2   translate, optionally squeeze
 *   tr -s [-c|-C] string1             squeeze only
 *   tr -d [-c|-C] string1             delete only
 *   tr -ds [-c|-C] string1 string2    delete, then squeeze
 *
 * __util_tr_main()'s argument-combination check enforces exactly this
 * table: string2 is required with -ds and with plain translate, absent
 * with plain -d, and optional with plain -s.  tr(1p) takes no file
 * operands at all -- input is always standard input, output always
 * standard output -- so this file has none of the sibling utilities'
 * per-operand file loop.
 *
 * ---- string1/string2 grammar (expand_spec() below) ---------------------
 *
 * Both operands share one grammar, expanded once into a plain array of
 * bytes:
 *   - an ordinary character stands for itself;
 *   - \\, \a, \b, \f, \n, \r, \t, \v are the named escapes; \ddd is 1-3
 *     octal digits (0-7).  A backslash followed by anything else is
 *     "unspecified" per the standard -- this build resolves that
 *     leniently, as the literal character after the backslash, rather
 *     than refusing, so a script that over-escapes an ordinary
 *     character (`tr -d '\.'` for a literal dot) still does what it
 *     looks like it does; a lone trailing backslash is likewise its own
 *     literal character;
 *   - c-c is an ascending range (descending is refused, not reversed);
 *   - [:class:] is one of the twelve POSIX named classes, expanded via
 *     this build's own <ctype.h> (alnum/alpha/blank/cntrl/digit/graph/
 *     lower/print/punct/space/upper/xdigit);
 *   - [=c=] is an equivalence class of exactly one character c -- with
 *     no real collation database beyond the POSIX/C locale, "the
 *     characters equivalent to c" is just {c} itself, same simplification
 *     every C-locale-only tr makes;
 *   - [x*n] repeats x n times and is valid only in string2 ("this
 *     expression is used to map multiple characters to one"); using it
 *     in string1 is refused.  n omitted or 0 means "however many are
 *     needed to make string2's expansion as long as string1's" -- at
 *     most one such wildcard per string is supported (a second is
 *     refused rather than guessed at); n with a leading zero is octal,
 *     otherwise decimal, exactly as specified.  n itself is accepted
 *     (not refused) however large the input spells it -- but expand_spec()
 *     never materializes more than one byte past string1's expansion
 *     length's worth of repeats, since nothing downstream -- xtab's
 *     construction, -s's squeeze set -- ever looks at a byte of string2's
 *     expansion past that point or cares how many identical copies of it
 *     exist; a handful of argv bytes spelling out a huge n is refused the
 *     unbounded allocation that a literal reading would otherwise hand
 *     it, with no change to any observable output.
 *
 * If string2's expansion is shorter than string1's (post-complement)
 * one once both are known, "the results are unspecified" per the
 * standard, whose own RATIONALE names the two historical answers -- BSD
 * padded with string2's last character, System V did not -- and tells
 * portable scripts to use [x*n] instead of relying on either.  This
 * build takes the BSD reading (pad with the last character) since a
 * silent short read of the translation table would otherwise leave
 * some of string1's characters not just untranslated but unaccounted
 * for.
 *
 * ---- -c/-C (complement) --------------------------------------------
 *
 * The standard distinguishes -c ("complement of the *values*", ascending
 * binary order) from -C ("complement of the *characters*", ascending
 * *collation* order, over LC_CTYPE's character set) -- a real distinction
 * only where a multi-byte character set and a non-trivial collation
 * order both exist.  This file treats every string1/string2 byte as an
 * opaque value 0-255, with no multi-byte decoding and no collation
 * order beyond plain numeric order (unlike src/util/cut.c and
 * src/util/fold.c, which do have a real UTF-8 decoder to reach for --
 * see either file's header): tr's own "characters" are its unit of
 * translation, and a byte-for-byte translation table has no
 * well-defined meaning once one input byte can be part of a multi-byte
 * sequence spanning several output positions.  So -c and -C are
 * accepted as exact synonyms here, both complementing string1's byte
 * set in ascending numeric order -- a stated scope limit, not a hidden
 * one.
 *
 * ---- which set squeeze (-s) applies to -------------------------------
 *
 * "When the -s option is specified, after any deletions or translations
 * have taken place, repeated sequences of the same character shall be
 * replaced by one occurrence of the same character, if the character is
 * found in the array specified by the last operand." That "last
 * operand" rule is uniform across all three -s-bearing forms: string2
 * when it is present (plain-translate-with-squeeze, and -ds), string1
 * (post-complement) when it is not (-s alone). set1[] below is always
 * string1's array with -c/-C already resolved, so it doubles as both
 * the deletion/translate-position array *and* the squeeze-only array
 * with no separate code path.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "util.h"

/* ==== string1/string2 grammar ============================================ */

static size_t decode_escape(const char *p, unsigned char *out)
{
	/* p[0] == '\\' */
	switch (p[1]) {
	case 0: return 0; /* trailing backslash: caller treats it as literal '\' */
	case 'a': *out = '\a'; return 2;
	case 'b': *out = '\b'; return 2;
	case 'f': *out = '\f'; return 2;
	case 'n': *out = '\n'; return 2;
	case 'r': *out = '\r'; return 2;
	case 't': *out = '\t'; return 2;
	case 'v': *out = '\v'; return 2;
	case '\\': *out = '\\'; return 2;
	default:
		if (p[1] >= '0' && p[1] <= '7') {
			int v = 0, k;
			for (k = 0; k < 3 && p[1 + k] >= '0' && p[1 + k] <= '7'; k++)
				v = v * 8 + (p[1 + k] - '0');
			*out = (unsigned char)v;
			return (size_t)k + 1;
		}
		/* "Unspecified" -- see this file's header for the lenient
		 * choice made here. */
		*out = (unsigned char)p[1];
		return 2;
	}
}

static size_t decode_one_char(const char *p, unsigned char *out)
{
	if (!*p) return 0;
	if (*p == '\\') {
		size_t used = decode_escape(p, out);
		if (used) return used;
		*out = '\\';
		return 1;
	}
	*out = (unsigned char)*p;
	return 1;
}

struct char_class { const char *name; int (*fn)(int); };
static const struct char_class classes[] = {
	{ "alnum", isalnum }, { "alpha", isalpha }, { "blank", isblank },
	{ "cntrl", iscntrl }, { "digit", isdigit }, { "graph", isgraph },
	{ "lower", islower }, { "print", isprint }, { "punct", ispunct },
	{ "space", isspace }, { "upper", isupper }, { "xdigit", isxdigit },
	{ 0, 0 }
};

static int push_byte(unsigned char **buf, size_t *n, size_t *cap, unsigned char b)
{
	if (*n == *cap) {
		size_t newcap;
		unsigned char *tmp;
		if (!__util_array_capacity(*cap, *n, 1, 32, 1, &newcap)) return -1;
		tmp = realloc(*buf, newcap);
		if (!tmp) return -1;
		*buf = tmp;
		*cap = newcap;
	}
	(*buf)[(*n)++] = b;
	return 0;
}

/* Expands one string1/string2 operand per this file's header grammar.
 * `allow_repeat` permits [x*n] (string2 only); `pad_hint` is the length
 * an [x*]/[x*0] wildcard should fill to (string1's own expanded length,
 * meaningless and ignored when there is no wildcard).  Returns 0 and
 * fills *out and *out_n on success, -1 (diagnostic already written) on
 * any grammar violation. */
static int expand_spec(const char *spec, const char *diagname, int allow_repeat, size_t pad_hint,
                        unsigned char **out, size_t *out_n)
{
	unsigned char *buf = NULL;
	size_t n = 0, cap = 0;
	long wildcard_pos = -1;
	unsigned char wildcard_byte = 0;
	const char *p = spec;

#define PUSH(b) do { if (push_byte(&buf, &n, &cap, (b)) < 0) goto oom; } while (0)

	while (*p) {
		unsigned char c;

		if (*p == '[' && p[1] == ':') {
			const char *start = p + 2;
			const char *end = strstr(start, ":]");
			size_t namelen;
			const struct char_class *cl;

			if (!end) goto bad;
			namelen = (size_t)(end - start);
			for (cl = classes; cl->name; cl++)
				if (strlen(cl->name) == namelen && !strncmp(cl->name, start, namelen)) break;
			if (!cl->name) goto bad;
			{
				int v;
				for (v = 0; v < 256; v++) if (cl->fn(v)) PUSH((unsigned char)v);
			}
			p = end + 2;
			continue;
		}
		if (*p == '[' && p[1] == '=') {
			const char *start = p + 2;
			const char *end = strstr(start, "=]");
			if (!end || end - start != 1) goto bad;
			PUSH((unsigned char)start[0]);
			p = end + 2;
			continue;
		}
		if (*p == '[') {
			const char *q = p + 1;
			unsigned char xchar;
			size_t xlen = decode_one_char(q, &xchar);

			if (xlen > 0 && q[xlen] == '*') {
				const char *nstart = q + xlen + 1;
				const char *close = strchr(nstart, ']');
				long count;

				if (!allow_repeat) goto bad;
				if (!close) goto bad;
				if (close == nstart) {
					count = 0;
				} else {
					char *nend;
					int is_octal = (nstart[0] == '0');
					count = strtol(nstart, &nend, is_octal ? 8 : 10);
					if (nend != close || count < 0) goto bad;
				}
				if (count == 0) {
					if (wildcard_pos >= 0) goto bad; /* only one wildcard supported */
					wildcard_pos = (long)n;
					wildcard_byte = xchar;
				} else {
					/* An explicit [x*N] repeats one identical byte, and
					 * __util_tr_main() below only ever reads positions
					 * < pad_hint out of string2's expansion (xtab's
					 * construction indexes s2exp[] by position < set1n,
					 * which is exactly pad_hint here) -- with -s's
					 * squeeze set caring only whether xchar is present
					 * at all, never how many times or where. So once
					 * this buffer already reaches one byte past
					 * pad_hint, further identical copies are
					 * unobservable to every consumer downstream,
					 * including a later [y*]/[y*0] wildcard's own fill
					 * math further down in this function (which only
					 * checks whether n has already reached pad_hint).
					 * Capping what actually gets pushed to that point
					 * is exact, not an approximation -- but it is load-
					 * bearing: N is decimal/octal text, so a string2 of
					 * a few dozen bytes can name a repeat count in the
					 * billions, and pushing that many bytes for real
					 * would let a short, attacker-controlled argv
					 * demand an unbounded allocation. */
					size_t remaining = (pad_hint > n) ? (pad_hint - n) : 0;
					size_t budget = remaining + 1;
					long k, limit = ((size_t)count > budget) ? (long)budget : count;
					for (k = 0; k < limit; k++) PUSH(xchar);
				}
				p = close + 1;
				continue;
			}
			/* Not a recognized bracket construct: '[' is a literal. */
			PUSH((unsigned char)'[');
			p++;
			continue;
		}

		if (*p == '\\') {
			unsigned char v;
			size_t used = decode_escape(p, &v);
			if (!used) { PUSH((unsigned char)'\\'); p++; continue; }
			c = v;
			p += used;
		} else {
			c = (unsigned char)*p;
			p++;
		}

		if (*p == '-' && p[1]) {
			const char *q = p + 1;
			unsigned char c2;
			size_t used2;

			if (*q == '\\') {
				used2 = decode_escape(q, &c2);
				if (!used2) { c2 = '\\'; used2 = 1; }
			} else {
				c2 = (unsigned char)*q;
				used2 = 1;
			}
			if (c2 < c) goto bad; /* descending range: refused, not reversed */
			{
				int v;
				for (v = c; v <= c2; v++) PUSH((unsigned char)v);
			}
			p = q + used2;
			continue;
		}
		PUSH(c);
	}

	if (wildcard_pos >= 0) {
		size_t fill = (pad_hint > n) ? (pad_hint - n) : 0;
		if (fill > 0) {
			size_t need = n + fill;
			if (need > cap) {
				unsigned char *tmp = realloc(buf, need);
				if (!tmp) goto oom;
				buf = tmp;
				cap = need;
			}
			memmove(buf + wildcard_pos + fill, buf + wildcard_pos, n - (size_t)wildcard_pos);
			memset(buf + wildcard_pos, wildcard_byte, fill);
			n += fill;
		}
	}

	*out = buf;
	*out_n = n;
	return 0;

bad:
	fprintf(stderr, "tr: %s: invalid string\n", diagname);
	free(buf);
	return -1;
oom:
	fprintf(stderr, "tr: out of memory\n");
	free(buf);
	return -1;
#undef PUSH
}

/* ==== option parsing and the four SYNOPSIS forms ========================= */

int __util_tr_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int opt_c = 0, opt_d = 0, opt_s = 0;
	int i = 1;
	int nargs;
	const char *string1, *string2;
	unsigned char *s1exp; size_t n1exp;
	unsigned char *set1; size_t set1n;
	unsigned char *s2exp = NULL; size_t n2exp = 0;
	unsigned char xtab[256];
	unsigned char del_in[256];
	unsigned char sq_in[256];
	int v;

	for (; i < argc; i++) {
		char *a = argv[i];
		char *p;

		if (a[0] != '-' || a[1] == 0) break;
		if (!strcmp(a, "--")) { i++; break; }
		for (p = a + 1; *p; p++) {
			if (*p == 'c' || *p == 'C') opt_c = 1;
			else if (*p == 'd') opt_d = 1;
			else if (*p == 's') opt_s = 1;
			else { fprintf(stderr, "tr: invalid option -- '%c'\n", *p); return 2; }
		}
	}

	nargs = argc - i;
	string1 = nargs >= 1 ? argv[i] : NULL;
	string2 = nargs >= 2 ? argv[i + 1] : NULL;
	if (nargs < 1) { fprintf(stderr, "tr: missing operand\n"); return 2; }
	if (nargs > 2) { fprintf(stderr, "tr: extra operand '%s'\n", argv[i + 2]); return 2; }

	if (opt_d) {
		if (opt_s) {
			if (!string2) { fprintf(stderr, "tr: -ds requires both string1 and string2\n"); return 2; }
		} else if (string2) {
			fprintf(stderr, "tr: -d (without -s) takes only string1\n");
			return 2;
		}
	} else if (!string2 && !opt_s) {
		fprintf(stderr, "tr: string2 is required unless -d or -s is given\n");
		return 2;
	}

	if (expand_spec(string1, "string1", 0, 0, &s1exp, &n1exp) < 0) return 2;

	{
		unsigned char in1[256];
		memset(in1, 0, sizeof in1);
		{ size_t k; for (k = 0; k < n1exp; k++) in1[s1exp[k]] = 1; }

		if (opt_c) {
			set1 = malloc(256);
			if (!set1) { fprintf(stderr, "tr: out of memory\n"); free(s1exp); return 1; }
			set1n = 0;
			for (v = 0; v < 256; v++) if (!in1[v]) set1[set1n++] = (unsigned char)v;
			free(s1exp);
		} else {
			set1 = s1exp;
			set1n = n1exp;
		}
	}

	if (string2) {
		if (expand_spec(string2, "string2", 1, set1n, &s2exp, &n2exp) < 0) { free(set1); return 2; }
		if (n2exp == 0) {
			fprintf(stderr, "tr: string2 must not be empty\n");
			free(set1);
			free(s2exp);
			return 2;
		}
	}

	for (v = 0; v < 256; v++) xtab[v] = (unsigned char)v;
	if (!opt_d && string2) {
		size_t k;
		for (k = 0; k < set1n; k++) {
			size_t di = (k < n2exp) ? k : n2exp - 1;
			xtab[set1[k]] = s2exp[di];
		}
	}

	memset(del_in, 0, sizeof del_in);
	if (opt_d) { size_t k; for (k = 0; k < set1n; k++) del_in[set1[k]] = 1; }

	memset(sq_in, 0, sizeof sq_in);
	if (opt_s) {
		const unsigned char *sqset = string2 ? s2exp : set1;
		size_t sqn = string2 ? n2exp : set1n;
		size_t k;
		for (k = 0; k < sqn; k++) sq_in[sqset[k]] = 1;
	}

	free(set1);
	free(s2exp);

	{
		int c;
		int have_last = 0;
		unsigned char last = 0;

		while ((c = getchar()) != EOF) {
			unsigned char b = (unsigned char)c;

			if (opt_d && del_in[b]) continue;
			if (!opt_d) b = xtab[b];
			if (opt_s && sq_in[b]) {
				if (have_last && last == b) continue;
				have_last = 1;
				last = b;
			} else {
				have_last = 0;
			}
			putchar(b);
		}
	}
	return 0;
}
