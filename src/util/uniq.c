/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * uniq(1p): `uniq [-c|-d|-u] [-f fields] [-s chars] [input_file
 * [output_file]]`.  Collapses *adjacent* equal lines only -- like the
 * real utility, it never sorts, so a caller that wants global dedup
 * pipes through sort(1p) first (src/util/sort.c).
 *
 * "-c|-d|-u" is one bracketed alternation in the real SYNOPSIS, read
 * here (as the XCU grouping implies) as genuinely mutually exclusive --
 * giving more than one is a usage error, not a "last one wins" or a
 * "-d and -u combine with -c" GNU-style extension.
 *
 * -f fields: "Ignore the first fields fields on each input line when
 * doing comparisons" -- a field is "the maximal string matched by the
 * basic regular expression [[:blank:]]*[^[:blank:]]*", applied `fields`
 * times to find where comparison starts.  "If a field is not
 * available, ... a null string shall be used" -- skip_prefix() below
 * clamps to the line length rather than erroring, exactly that.
 *
 * -s chars: "Ignore the first chars characters when doing comparisons"
 * -- applied *after* -f's field skip ("the first chars characters after
 * the first fields fields shall be ignored"), same clamp-not-error
 * behaviour if chars overruns what -f already skipped past.
 *
 * Comparison itself, once the prefix is skipped, is exact byte
 * comparison -- XCU's uniq(1p) OPTIONS never mentions case-folding (no
 * -i here, unlike some real implementations' extension), so this file
 * does not implement one.
 *
 * EXIT STATUS: "0 The utility executed successfully.  >0 An error
 * occurred." -- the ordinary shape, no special "found duplicates" code
 * the way sort -c has one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "util.h"

static size_t skip_prefix(const char *line, size_t len, long fields, long chars) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	size_t off = 0;
	long f;

	for (f = 0; f < fields && off < len; f++) {
		while (off < len && isblank((unsigned char)line[off])) off++;
		while (off < len && !isblank((unsigned char)line[off])) off++;
	}
	if (chars > 0) {
		if ((size_t)chars > len - off) off = len;
		else off += (size_t)chars;
	}
	return off;
}

static int lines_equal(const char *a, size_t alen, const char *b, size_t blen, long fields, long chars)
{
	size_t aoff = skip_prefix(a, alen, fields, chars);
	size_t boff = skip_prefix(b, blen, fields, chars);
	size_t ar = alen - aoff, br = blen - boff;

	if (ar != br) return 0;
	for (size_t i = 0; i < ar; i++)
		if (a[aoff + i] != b[boff + i]) return 0;
	return 1;
}

int __util_uniq_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int opt_c = 0, opt_d = 0, opt_u = 0;
	long fields = 0, chars = 0;
	int i;
	const char *infile = 0, *outfile = 0;
	FILE *in = stdin, *out = stdout;
	char *cur = 0, *next = 0;
	size_t curcap = 0, nextcap = 0;
	ssize_t curlen = -1, nextlen;
	long count;
	int status = 0;

	for (i = 1; i < argc; i++) {
		char *arg = argv[i];

		if (!strcmp(arg, "--")) { i++; break; }
		if (arg[0] != '-' || arg[1] == 0) break;

		if (!strcmp(arg, "-c")) { opt_c = 1; continue; }
		if (!strcmp(arg, "-d")) { opt_d = 1; continue; }
		if (!strcmp(arg, "-u")) { opt_u = 1; continue; }
		if (!strcmp(arg, "-f") || !strncmp(arg, "-f", 2)) {
			const char *val;
			char *end;
			if (arg[2]) val = arg + 2;
			else { if (++i >= argc) { __util_diagf("uniq: -f: option requires an argument\n"); return 1; } val = argv[i]; }
			fields = strtol(val, &end, 10);
			if (*end || fields < 0) { __util_diagf("uniq: -f: %s: invalid field count\n", val); return 1; }
			continue;
		}
		if (!strcmp(arg, "-s") || !strncmp(arg, "-s", 2)) {
			const char *val;
			char *end;
			if (arg[2]) val = arg + 2;
			else { if (++i >= argc) { __util_diagf("uniq: -s: option requires an argument\n"); return 1; } val = argv[i]; }
			chars = strtol(val, &end, 10);
			if (*end || chars < 0) { __util_diagf("uniq: -s: %s: invalid character count\n", val); return 1; }
			continue;
		}
		__util_diagf("uniq: %s: invalid option\n", arg);
		return 1;
	}

	if (opt_c + opt_d + opt_u > 1) {
		__util_diagf("uniq: -c, -d and -u are mutually exclusive\n");
		return 1;
	}

	if (i < argc) infile = argv[i++];
	if (i < argc) outfile = argv[i++];
	if (i < argc) {
		__util_diagf("uniq: too many operands\n");
		return 1;
	}

	if (infile && strcmp(infile, "-") != 0) {
		in = fopen(infile, "r");
		if (!in) { __util_diagf("uniq: %s: %s\n", infile, strerror(errno)); return 1; }
	}
	if (outfile && strcmp(outfile, "-") != 0) {
		out = fopen(outfile, "w");
		if (!out) {
			__util_diagf("uniq: %s: %s\n", outfile, strerror(errno));
			/* Output-open failure is primary; input close is cleanup only. */
			if (in != stdin) (void)fclose(in);
			return 1;
		}
	}

	curlen = getline(&cur, &curcap, in);
	if (curlen < 0) { free(cur); free(next); goto done; }
	if (curlen && cur[curlen - 1] == '\n') cur[--curlen] = 0;
	count = 1;

	for (;;) {
		nextlen = getline(&next, &nextcap, in);
		if (nextlen < 0) {
			if ((!opt_d && !opt_u) || (opt_d && count > 1) ||
			    (opt_u && count == 1)) {
				if (opt_c) {
					if (fprintf(out, "%7ld %s\n", count, cur) < 0) status = 1;
				} else if (fprintf(out, "%s\n", cur) < 0) status = 1;
			}
			break;
		}
		if (nextlen && next[nextlen - 1] == '\n') next[--nextlen] = 0;

		if (lines_equal(cur, (size_t)curlen, next, (size_t)nextlen, fields, chars)) {
			count++;
			continue;
		}

		if ((!opt_d && !opt_u) || (opt_d && count > 1) ||
		    (opt_u && count == 1)) {
			if (opt_c) {
				if (fprintf(out, "%7ld %s\n", count, cur) < 0) status = 1;
			} else if (fprintf(out, "%s\n", cur) < 0) status = 1;
		}

		{
			char *tmp = cur; size_t tmpcap = curcap;
			cur = next; curcap = nextcap; curlen = nextlen;
			next = tmp; nextcap = tmpcap;
		}
		count = 1;
	}

	free(cur);
	free(next);
done:
	if (in != stdin && fclose(in) != 0) status = 1;
	if (out != stdout) {
		if (fclose(out) != 0) status = 1;
	} else if (fflush(out) != 0) status = 1;
	return status;
}
