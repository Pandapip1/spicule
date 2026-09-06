/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * cut(1p): `cut -b list [-n] [file...]`, `cut -c list [file...]`, or
 * `cut -f list [-d delim] [-s] [file...]` -- "exactly one of -b, -c or
 * -f" is required (OPTIONS: these three "are mutually exclusive").
 *
 * `list` is XCU cut(1p)'s own range-list grammar, shared verbatim by all
 * three modes: "a comma or <blank>-separated list of numbers and/or
 * number ranges. Numbers ... range: N N'th byte, character or field,
 * counted from 1. N- from Nth to end of line. N-M from Nth to Mth
 * inclusive. -M from first to Mth." parse_list() below builds a plain
 * array of (start, end) pairs (end == RANGE_OPEN for a trailing "N-")
 * and is_selected() does a linear membership scan -- no attempt to
 * merge/sort ranges, since "the selected input shall be written in the
 * order collected" (ascending position order) regardless of how the
 * list itself was written or how many of its ranges overlap a given
 * position, and a linear scan over a handful of ranges per character
 * position is not a real cost for real command lines.
 *
 * -b (bytes) vs -c (characters): this build's mbrtowc() (src/stdlib/
 * mbrtowc.c) really does decode UTF-8 unconditionally -- there is no
 * setlocale() to turn it off, so unlike a build where "the current
 * locale" always means single-byte C, the byte/character distinction
 * here is backed by real multibyte decoding, not just a name. -c
 * therefore counts and slices actual decoded characters (falling back to
 * one raw byte per position on an invalid or incomplete sequence, so a
 * corrupt byte is never silently dropped or allowed to desynchronize the
 * rest of the line); -b counts and slices raw bytes. -n ("do not split a
 * multi-byte character" when a byte-list boundary falls inside one) is
 * refused loudly rather than implemented partially or silently ignored,
 * same "refuse rather than guess" reasoning as src/util/touch.c's -d:
 * -b's contract is exact byte offsets, and rounding those to a character
 * boundary is a second, different feature this file does not implement.
 *
 * -s ("suppress lines with no delimiter") is real and implemented, field
 * mode only -- OPTIONS: "-s Suppress lines with no delimiter characters
 * ... Unless -s is specified, lines with no delimiters shall be passed
 * through unmodified." -d is likewise field-mode only ("Use delim as the
 * field delimiter character instead of the <tab> character"); using
 * either with -b/-c is refused rather than silently ignored.
 *
 * A missing/unreadable file operand is diagnosed and counted as a
 * failure; other operands still run (the file loop below never stops
 * early), matching this project's other multi-operand utilities (see
 * src/util/rm.c).
 *
 * EXIT STATUS: "0 Success. >0 An error occurred." -- 2 for a usage
 * error (bad option, bad list, conflicting flags), 1 for a runtime one
 * (a file that could not be opened), same split src/util/rm.c and
 * src/util/cp.c already use.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <wchar.h>
#include "util.h"
#include "ownership_stubs.h"

#define RANGE_OPEN (-1L)

struct range { long start, end; };

/* spec is never NULL at either call site (both pass the already-validated
 * listspec). */
__attribute__((nonnull(1)))
static int parse_list(const char *spec, struct range **out withtok(heap_allocated),
                      size_t *out_n)
{
	struct range *arr = NULL;
	size_t n = 0, cap = 0;
	const char *p = spec;

	if (!*spec) return -1;

	while (*p) {
		long start, end;
		char *endp;

		while (*p == ',' || *p == ' ' || *p == '\t') p++;
		if (!*p) break;

		if (*p == '-') {
			p++;
			start = 1;
			end = strtol(p, &endp, 10);
			if (endp == p || end < 1) { free(arr); return -1; }
			p = endp;
		} else {
			if (*p < '0' || *p > '9') { free(arr); return -1; }
			start = strtol(p, &endp, 10);
			if (endp == p || start < 1) { free(arr); return -1; }
			p = endp;
			if (*p == '-') {
				p++;
				if (!*p || *p == ',' || *p == ' ' || *p == '\t') {
					end = RANGE_OPEN;
				} else {
					end = strtol(p, &endp, 10);
					if (endp == p || end < start) { free(arr); return -1; }
					p = endp;
				}
			} else {
				end = start;
			}
		}

		if (*p && *p != ',' && *p != ' ' && *p != '\t') { free(arr); return -1; }

		if (n == cap) {
			size_t newcap;
			struct range *tmp;
			if (!__util_array_capacity(cap, n, 1, 8, sizeof *arr, &newcap)) { free(arr); return -1; }
			tmp = __util_reallocarray(arr, newcap, sizeof *arr);
			if (!tmp) { free(arr); return -1; }
			arr = tmp;
			cap = newcap;
		}
		arr[n].start = start;
		arr[n].end = end;
		n++;
	}
	if (n == 0) { free(arr); return -1; }
	*out = arr;
	*out_n = n;
	return 0;
}

/* r is always parse_list()'s own successful `ranges` output, never NULL
 * (parse_list() fails rather than returning n == 0). */
__attribute__((nonnull(1)))
static int is_selected(const struct range *r, size_t n, long pos)
{
	size_t i;
	for (i = 0; i < n; i++)
		if (pos >= r[i].start && (r[i].end == RANGE_OPEN || pos <= r[i].end)) return 1;
	return 0;
}

/* Decoded length, in bytes, of the character (or byte-list fallback
 * unit) starting at `p`, within `avail` bytes -- shared logic with
 * src/util/fold.c's identical (and identically small) helper; see that
 * file's header for why this ten-line function is duplicated rather
 * than given a shared declaration in src/internal/util.h. */
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

static void process_char_mode(FILE *f, const struct range *ranges, size_t nr, int bytemode)
{
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;

	while ((len = getline(&line, &cap, f)) >= 0) {
		int had_nl = (len > 0 && line[len - 1] == '\n');
		size_t ulen = had_nl ? (size_t)(len - 1) : (size_t)len;

		if (bytemode) {
			long pos;
			for (pos = 1; pos <= (long)ulen; pos++)
				if (is_selected(ranges, nr, pos))
					fputc((unsigned char)line[pos - 1], stdout);
		} else {
			size_t off = 0;
			long pos = 1;
			while (off < ulen) {
				size_t clen = char_len((const unsigned char *)line + off, ulen - off);
				if (is_selected(ranges, nr, pos)) {
					/* clen <= ulen - off by char_len()'s own contract
					 * (never more than the `avail` bytes handed to it), so
					 * line+off..line+off+clen stays within [line,
					 * line+ulen] -- same restatement as
					 * process_field_mode()'s analogous fwrite() below. */
					__ownership_readable_span(line + off, clen);
					fwrite(line + off, 1, clen, stdout);
				}
				off += clen;
				pos++;
			}
		}
		if (had_nl) fputc('\n', stdout);
	}
	free(line);
}

static void process_field_mode(FILE *f, const struct range *ranges, size_t nr, char delim, int suppress)
{
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;

	while ((len = getline(&line, &cap, f)) >= 0) {
		int had_nl = (len > 0 && line[len - 1] == '\n');
		size_t ulen = had_nl ? (size_t)(len - 1) : (size_t)len;

		if (!memchr(line, delim, ulen)) {
			if (!suppress) {
				size_t i;
				for (i = 0; i < ulen; i++) fputc((unsigned char)line[i], stdout);
				if (had_nl) fputc('\n', stdout);
			}
			continue;
		}

		{
			long field = 1;
			char *start = line;
			char *end = line + ulen;
			int wrote_any = 0;

			for (;;) {
				char *p = memchr(start, delim, (size_t)(end - start));
				size_t flen = p ? (size_t)(p - start) : (size_t)(end - start);

				if (is_selected(ranges, nr, field)) {
					if (wrote_any) fputc(delim, stdout);
					/* start..start+flen is always within [line, line+ulen]
					 * (flen is p-start or end-start, both bounded by
					 * end-start): true by the cursor arithmetic above, not
					 * traced by the checker across the memchr loop -- same
					 * restatement src/util/join.c's join_write() already
					 * does for its own field-slice fwrite(). */
					__ownership_readable_span(start, flen);
					fwrite(start, 1, flen, stdout);
					wrote_any = 1;
				}
				if (!p) break;
				start = p + 1;
				field++;
			}
			if (had_nl) fputc('\n', stdout);
		}
	}
	free(line);
}

int __util_cut_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int mode = 0; /* 'b', 'c' or 'f' */
	const char *listspec = NULL;
	char delim = '\t';
	int have_delim = 0;
	int opt_s = 0, opt_n = 0;
	int i = 1;
	struct range *ranges;
	size_t nranges;
	int had_error = 0;

	for (; i < argc; i++) {
		char *a = argv[i];

		/* a is one of argv's own elements (i < argc), genuinely never
		 * NULL by this function's own elements_withtok(null_terminated,
		 * argc) contract on argv -- same restatement as src/util/od.c's
		 * option loop. */
		__ownership_pointer_nonnull(a);
		if (a[0] != '-' || a[1] == 0) break;
		if (!strcmp(a, "--")) { i++; break; }

		if (a[1] == 'b' || a[1] == 'c' || a[1] == 'f') {
			if (mode) {
				fprintf(stderr, "cut: only one of -b, -c or -f may be specified\n");
				return 2;
			}
			mode = (unsigned char)a[1];
			if (a[2]) {
				listspec = a + 2;
			} else {
				if (i + 1 >= argc) {
					fprintf(stderr, "cut: -%c: option requires an argument\n", mode);
					return 2;
				}
				listspec = argv[++i];
			}
			continue;
		}
		if (!strcmp(a, "-d") || (a[1] == 'd' && a[2])) {
			const char *arg = a[2] ? a + 2 : NULL;
			if (!arg) {
				if (i + 1 >= argc) { fprintf(stderr, "cut: -d: option requires an argument\n"); return 2; }
				arg = argv[++i];
			}
			if (strlen(arg) != 1) {
				fprintf(stderr, "cut: -d: delimiter must be a single character\n");
				return 2;
			}
			delim = arg[0];
			have_delim = 1;
			continue;
		}
		if (!strcmp(a, "-s")) { opt_s = 1; continue; }
		if (!strcmp(a, "-n")) { opt_n = 1; continue; }
		fprintf(stderr, "cut: invalid option -- '%s'\n", a);
		return 2;
	}

	if (!mode) {
		fprintf(stderr, "cut: you must specify a list of bytes, characters, or fields\n");
		return 2;
	}
	/* Every path above that sets `mode` sets `listspec` in the very
	 * same branch (either to the attached "-f1,3" tail or to the next
	 * argv[] word), so `mode` being nonzero already guarantees
	 * `listspec` is too -- restated here as a direct check, rather
	 * than left as an invariant only this file's control flow proves,
	 * since a static checker reading parse_list()'s own `*spec` cannot
	 * otherwise see the connection between the two variables. */
	if (!listspec) {
		fprintf(stderr, "cut: internal error: no list captured for -%c\n", mode);
		return 2;
	}
	if (mode != 'f' && (have_delim || opt_s)) {
		fprintf(stderr, "cut: -d and -s are only valid with -f\n");
		return 2;
	}
	if (opt_n) {
		/* See this file's header: -n's "round to a character boundary"
		 * behavior is not implemented. */
		fprintf(stderr, "cut: -n: not implemented -- see src/util/cut.c\n");
		return 2;
	}
	if (parse_list(listspec, &ranges, &nranges) < 0) {
		fprintf(stderr, "cut: %s: invalid list\n", listspec);
		return 2;
	}

	if (i >= argc) {
		if (mode == 'f') process_field_mode(stdin, ranges, nranges, delim, opt_s);
		else process_char_mode(stdin, ranges, nranges, mode == 'b');
	} else {
		for (; i < argc; i++) {
			FILE *f;
			/* argv[i] is one of argv's own elements (i < argc), genuinely
			 * null-terminated by this function's own
			 * elements_withtok(null_terminated, argc) contract on argv --
			 * restated here since the checker does not trace that fact
			 * through the two argv[i] uses below. */
			__ownership_string_terminated(argv[i]);
			/* use_stdin, not `f != stdin`, decides the fclose() below --
			 * the checker can't prove opaque pointers unequal, so a direct
			 * comparison makes the fopen() allocation look conditionally
			 * leaked (same idiom as src/util/sed.c's
			 * script_buf_append_file()). */
			int use_stdin = !strcmp(argv[i], "-");
			f = use_stdin ? stdin : fopen(argv[i], "r");
			if (!f) {
				fprintf(stderr, "cut: %s: %s\n", argv[i], strerror(errno));
				had_error = 1;
				continue;
			}
			if (mode == 'f') process_field_mode(f, ranges, nranges, delim, opt_s);
			else process_char_mode(f, ranges, nranges, mode == 'b');
			if (!use_stdin) (void)fclose(f);
		}
	}

	free(ranges);
	return had_error ? 1 : 0;
}
