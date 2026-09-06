/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * split(1p): `split [-l line_count | -b n[k|m]] [-a suffix_length]
 * [file [name]]` -- splits one file into consecutively-named pieces.
 *
 * OPTIONS:
 *  -l line_count  "the number of lines in each resulting file piece"
 *  -b n[k|m]      pieces of n bytes (n*1024 with 'k', n*1,048,576 with
 *                 'm') instead of by line count -- mutually exclusive
 *                 with -l.
 *  -a suffix_length  override the default 2-character suffix width.
 *
 * Default, "[i]f no -l or -b is given ... equivalent to -l 1000".
 *
 * SUFFIX SCHEME: split(1p)'s own base-26 alphabetic suffix -- "aa",
 * "ab", ..., "az", "ba", ... -- implemented by gen_suffix() below as a
 * plain base-26 odometer over suffix_length letter positions, not a
 * decimal-number suffix.  Running out of the 26^suffix_length names
 * available at a given -a width is a real, diagnosed error ("too many
 * output files"), not silent wraparound back to "aa" (which would
 * silently overwrite the first piece with the (26^n+1)-th).
 *
 * OPERANDS: `file` -- "the pathname of the ordinary file to be split.
 * If no input file is given or file is '-', standard input shall be
 * used."  `name` -- "The prefix ... default shall be the character
 * 'x'."
 *
 * EXIT STATUS: "0 Successful completion." ">0 An error occurred."
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "util.h"
#include "ownership_stubs.h"

/* index 0 -> suffix_length copies of 'a', counting up like an odometer
 * with 26 positions per digit; returns -1 once index has run past the
 * 26^suffix_length names a width of suffix_length can spell. */
static int gen_suffix(char *buf, int suflen, long index) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int i;

	if (index < 0) return -1;
	for (i = suflen - 1; i >= 0; i--) { buf[i] = (char)('a' + index % 26); index /= 26; }
	if (index != 0) return -1;
	buf[suflen] = 0;
	return 0;
}

/* Deliberately NOT withtok(file_stream_open): split_by_lines() below
 * rotates through a sequence of these (close the current piece, then
 * call this again for the next one) inside one loop, and the analyzer's
 * loop-widening merges that rotation into a spurious "not freed before
 * function exit" on the very first piece, even though every piece this
 * function ever returns is closed before being replaced or at the
 * function's own final return. Not a real leak; annotating it produced
 * a false finding the checker's loop exploration cannot resolve on its
 * own here. */
static FILE *open_piece(const char *prefix, int suflen, long index, char *namebuf, size_t namebuf_sz)
{
	char suf[32];
	FILE *f;
	int n;

	if (suflen >= (int)sizeof suf) suflen = (int)sizeof suf - 1;
	if (gen_suffix(suf, suflen, index) < 0) {
		__util_diagf("split: too many output files (suffix length %d exhausted)\n", suflen);
		return 0;
	}
	n = snprintf(namebuf, namebuf_sz, "%s%s", prefix, suf);
	if (n < 0 || (size_t)n >= namebuf_sz) {
		if (n >= 0) errno = ENAMETOOLONG;
		return 0;
	}
	f = fopen(namebuf, "wb");
	if (!f) {
		int saved = errno;
		__util_diagf("split: %s: %s\n", namebuf, strerror(saved));
	}
	return f;
}

/* -b n[k|m] */
static int parse_bytecount(const char *s, long *out)
{
	size_t n = strlen(s);
	long mult = 1;
	char buf[32];
	char *end;
	long v;

	if (n == 0) return -1;
	if (s[n - 1] == 'k') { mult = 1024; n--; }
	else if (s[n - 1] == 'm') { mult = 1048576; n--; }
	if (n == 0 || n >= sizeof buf) return -1;
	strncpy(buf, s, n);
	buf[n] = 0;
	v = strtol(buf, &end, 10);
	if (end == buf || *end || v <= 0) return -1;
	if (v > LONG_MAX / mult) return -1;
	*out = v * mult;
	return 0;
}

static int split_by_lines(FILE *in, const char *prefix, int suflen, long lcount) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	char *line = 0;
	size_t linecap = 0;
	long piece = 0;
	long inpiece = 0;
	FILE *out = 0;
	char namebuf[512];
	int had_output = 0;

	for (;;) {
		ssize_t n = getline(&line, &linecap, in);
		if (n < 0) {
			if (ferror(in)) { free(line); return -1; }
			break;
		}
		if (!out || inpiece >= lcount) {
			if (out && fclose(out) != 0) { free(line); return -1; }
			out = open_piece(prefix, suflen, piece++, namebuf, sizeof namebuf);
			if (!out) { free(line); return -1; }
			inpiece = 0;
			had_output = 1;
		}
		__ownership_readable_span(line, (size_t)n);
		if (fwrite(line, 1, (size_t)n, out) != (size_t)n) {
			/* The write failure is primary; close only releases the piece. */
			(void)fclose(out);
			free(line);
			return -1;
		}
		inpiece++;
	}
	free(line);
	/* split(1p) always creates at least one (possibly empty) output
	 * piece, even for a zero-byte input -- matching every real
	 * implementation's behavior for an empty file. */
	if (!had_output) {
		out = open_piece(prefix, suflen, piece, namebuf, sizeof namebuf);
		if (!out) return -1;
	}
	return !out || fclose(out) == 0 ? 0 : -1;
}

static int split_by_bytes(FILE *in, const char *prefix, int suflen, long bcount) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	char *buf = malloc((size_t)bcount);
	long piece = 0;
	char namebuf[512];
	int had_output = 0;

	if (!buf) { __util_diagf("split: out of memory\n"); return -1; }
	for (;;) {
		size_t got = fread(buf, 1, (size_t)bcount, in);
		FILE *out;
		if (got == 0) {
			if (ferror(in)) { free(buf); return -1; }
			break;
		}
		out = open_piece(prefix, suflen, piece++, namebuf, sizeof namebuf);
		if (!out) { free(buf); return -1; }
		{
			size_t i;
			for (i = 0; i < got; i++)
				if (fputc((unsigned char)buf[i], out) == EOF) break;
			if (i != got) {
			/* The write failure is primary; close only releases the piece. */
			(void)fclose(out);
			free(buf);
			return -1;
			}
		}
		if (fclose(out) < 0) { free(buf); return -1; }
		had_output = 1;
		if (got < (size_t)bcount) {
			/* short fread: could be real EOF or a real I/O error mid-read
			 * -- ferror() must be checked before treating it as EOF. */
			if (ferror(in)) { free(buf); return -1; }
			break;
		}
	}
	if (!had_output) {
		FILE *out = open_piece(prefix, suflen, piece, namebuf, sizeof namebuf);
		if (!out) { free(buf); return -1; }
		if (fclose(out) < 0) { free(buf); return -1; }
	}
	free(buf);
	return 0;
}

int __util_split_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i = 1;
	long lcount = -1, bcount = -1;
	int suflen = 2;
	const char *file = "-";
	const char *prefix = "x";
	FILE *in;
	int rc;

	for (; i < argc; i++) {
		char *a = argv[i];
		if (a[0] != '-' || a[1] == 0) break;
		if (!strcmp(a, "--")) { i++; break; }
		if (!strcmp(a, "-l")) {
			char *end;
			if (i + 1 >= argc) { __util_diagf("split: -l: option requires an argument\n"); return 1; }
			lcount = strtol(argv[++i], &end, 10);
			if (*end || lcount <= 0) { __util_diagf("split: -l: invalid line count\n"); return 1; }
			continue;
		}
		if (!strcmp(a, "-b")) {
			if (i + 1 >= argc) { __util_diagf("split: -b: option requires an argument\n"); return 1; }
			i++;
			if (parse_bytecount(argv[i], &bcount) < 0) {
				__util_diagf("split: -b: invalid byte count\n");
				return 1;
			}
			continue;
		}
		if (!strcmp(a, "-a")) {
			char *end;
			if (i + 1 >= argc) { __util_diagf("split: -a: option requires an argument\n"); return 1; }
			suflen = (int)strtol(argv[++i], &end, 10);
			if (*end || suflen <= 0) { __util_diagf("split: -a: invalid suffix length\n"); return 1; }
			continue;
		}
		__util_diagf("split: %s: invalid option\n", a);
		return 1;
	}

	if (lcount > 0 && bcount > 0) {
		__util_diagf("split: -l and -b are mutually exclusive\n");
		return 1;
	}
	if (lcount < 0 && bcount < 0) lcount = 1000; /* split(1p) default */

	if (i < argc) file = argv[i++];
	if (i < argc) prefix = argv[i++];
	if (i < argc) {
		__util_diagf("split: extra operand '%s'\n", argv[i]);
		return 1;
	}

	if (!strcmp(file, "-")) {
		in = stdin;
	} else {
		in = fopen(file, "rb");
		if (!in) {
			__util_diagf("split: %s: %s\n", file, strerror(errno));
			return 1;
		}
	}

	rc = bcount > 0 ? split_by_bytes(in, prefix, suflen, bcount)
	                : split_by_lines(in, prefix, suflen, lcount);

	if (in != stdin && fclose(in) != 0) rc = -1;
	return rc < 0 ? 1 : 0;
}
