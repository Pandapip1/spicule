/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * od(1p): `od [-A base] [-j skip] [-N count] [-t type] [-v] [file...]`
 * -- octal (or hex/decimal/character) dump.
 *
 * SCOPE.  od(1p)'s full -t grammar lets a type letter (a/c/d/f/o/u/x)
 * take a size suffix that is either a letter (C/S/I/L, "the size of a
 * char/short/int/long") or a decimal byte count (1/2/4/8).  This
 * implements the decimal-byte-count form only (`-t x1`, `-t o2`, `-t
 * d4`, `-t u8`, ...) plus `-t c` (which never takes a size) and the
 * traditional argument-less default, which od(1p) itself defines as
 * "as if -t oS had been specified" -- i.e. octal, 2-byte units, taken
 * literally here as `-t o2`.  The C/S/I/L letter-size spelling and `-t
 * a`/`-t f` (named-character and floating-point dumps) are real od(1p)
 * but not implemented: refused loudly (a diagnostic, nonzero exit)
 * rather than silently misinterpreted.  Multi-byte units are decoded in
 * this platform's own native byte order (little-endian on every
 * architecture ntlibc targets -- x86, x86_64, arm64), matching what a
 * real od reading a real binary on this platform is for.
 *
 * -A address_base: d/o/x/n (n: "no offsets shall be output"). od(1p):
 * "If no -A option is specified, the input offset base is unspecified"
 * -- resolved here as octal, od's own traditional default.
 *
 * -j skip / -N count: od(1p)'s own numeric syntax -- a decimal, a
 * leading "0x"/"0X" hexadecimal, or a leading-zero octal value,
 * optionally followed by a single b(*512)/k(*1024)/m(*1048576)
 * multiplier suffix -- implemented by parse_odnum() below.
 *
 * -v: disables the elision below (od(1p) DESCRIPTION: "Without the -v
 * option, any number of groups of output lines, which would be
 * identical to the immediately preceding group of output lines (except
 * for the byte offsets), shall be replaced with a line containing only
 * an <asterisk>" -- implemented literally in od_run() below, comparing
 * each full 16-byte row's raw bytes against the previous one).
 *
 * -t c's escape table, od(1p) verbatim: "'\\', '\\a', '\\b', '\\f',
 * '\\n', '\\r', '\\t', '\\v' shall be written as the corresponding
 * escape sequences ... a NUL shall be written as '\\0'.  Other
 * non-printable characters shall be written as one three-digit octal
 * number for each byte."
 *
 * Multiple file operands are read as one logical concatenated stream
 * (od(1p)'s own behavior, matching cat(1p)) via struct instream below;
 * no operands at all reads standard input.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "util.h"

static int od_output_failed;

#define ROWBYTES 16

/* ---- od(1p)'s own -j/-N numeric syntax -------------------------------- */

/* long long, not long, throughout this file's numeric plumbing (skip/
 * count/offsets/unit values): this platform is LLP64 (arch/x86_64/bits/
 * alltypes.h.in: `long` is 32-bit even on a 64-bit build), so an -N/-j
 * value or a -t x8/o8/d8/u8 unit -- both legitimately up to 64 bits --
 * would silently truncate through a plain `long`. */
static int parse_odnum(const char *s, long long *out)
{
	size_t n = strlen(s);
	long long mult = 1;
	char buf[64];
	char *end;
	long long v;

	if (n == 0) return -1;
	if (s[n - 1] == 'b') { mult = 512; n--; }
	else if (s[n - 1] == 'k') { mult = 1024; n--; }
	else if (s[n - 1] == 'm') { mult = 1048576; n--; }
	if (n == 0 || n >= sizeof buf) return -1;
	strncpy(buf, s, n);
	buf[n] = 0;

	errno = 0;
	v = strtoll(buf, &end, 0); /* base 0: honors od's own 0x/0-prefix rules */
	if (end == buf || *end || errno == ERANGE || v < 0) return -1;
	if (v > LLONG_MAX / mult) return -1;
	*out = v * mult;
	return 0;
}

/* ---- multi-file concatenated input ------------------------------------ */

struct instream {
	char **files;
	int nfiles;
	int idx;      /* nfiles>0: next files[] index to open. nfiles==0: 0
	               * before stdin has been used, 1 after (stdin is only
	               * ever read once, then treated as exhausted). */
	FILE *cur;
	int any_error;
};

static void instream_init(struct instream *is, char **files, int nfiles)
{
	is->files = files;
	is->nfiles = nfiles;
	is->idx = 0;
	is->cur = 0;
	is->any_error = 0;
}

/* Returns bytes read (0 == exhausted every file/stdin). */
static size_t instream_read(struct instream *is, unsigned char *buf, size_t want)
{
	for (;;) {
		size_t got;

		if (!is->cur) {
			if (is->nfiles == 0) {
				if (is->idx != 0) return 0; /* stdin already used once */
				is->cur = stdin;
				is->idx = 1;
			} else {
				if (is->idx >= is->nfiles) return 0;
				is->cur = fopen(is->files[is->idx], "rb");
				if (!is->cur) {
					__util_diagf("od: %s: %s\n", is->files[is->idx], strerror(errno));
					is->any_error = 1;
					is->idx++;
					continue;
				}
				is->idx++;
			}
		}
		got = fread(buf, 1, want, is->cur);
		if (got > 0) return got;
		if (is->cur != stdin && fclose(is->cur) != 0) is->any_error = 1;
		is->cur = 0;
		if (is->nfiles == 0) return 0; /* stdin: nothing more, ever */
		/* else: this file is exhausted, loop around to the next one */
	}
}

/* ---- per-type formatting ----------------------------------------------- */

struct od_opts {
	char abase;   /* 'd', 'o', 'x', 'n' */
	long long skip;
	long long count;   /* -1: unbounded */
	char type;    /* 'x', 'o', 'd', 'u', 'c' */
	int size;     /* 1/2/4/8; unused for 'c' */
	int verbose;
};

static unsigned long long load_unit(const unsigned char *p, int size)
{
	unsigned long long v = 0;
	int i;
	/* Native (little-endian) byte order -- see this file's header. */
	for (i = size - 1; i >= 0; i--) v = (v << 8) | p[i];
	return v;
}

/* Widest decimal rendering (in digits) of an unsigned/unsigned/signed
 * value of `size` bytes -- one column-width table per -t o/u/d, each
 * indexed the same way: size is always 1, 2, 4, or 8. */
static int odigits(int size)
{
	switch (size) {
	case 1: return 3;
	case 2: return 6;
	case 4: return 11;
	default: return 22;
	}
}

static int udigits(int size)
{
	switch (size) {
	case 1: return 3;
	case 2: return 5;
	case 4: return 10;
	default: return 20;
	}
}

static int ddigits(int size)
{
	switch (size) {
	case 1: return 4;
	case 2: return 6;
	case 4: return 11;
	default: return 20;
	}
}

/* od(1p)'s -t c escape table, quoted in full in this file's header. */
static const char *char_field(unsigned char b, char tmp[8])
{
	switch (b) {
	case 0: return "\\0";
	case '\\': return "\\\\";
	case '\a': return "\\a";
	case '\b': return "\\b";
	case '\f': return "\\f";
	case '\n': return "\\n";
	case '\r': return "\\r";
	case '\t': return "\\t";
	case '\v': return "\\v";
	default:
		if (b >= 0x20 && b < 0x7f) { tmp[0] = (char)b; tmp[1] = 0; return tmp; }
		if (snprintf(tmp, 8, "%03o", b) < 0) {
			tmp[0] = 0;
			od_output_failed = 1;
		}
		return tmp;
	}
}

static void print_offset(const struct od_opts *o, unsigned long long off)
{
	switch (o->abase) {
	case 'd': printf("%07llu", off); break;
	case 'x': printf("%06llx", off); break;
	case 'n': return; /* "no offsets shall be output" */
	case 'o': default: printf("%07llo", off); break;
	}
}

static void print_row(const struct od_opts *o, const unsigned char *buf, size_t n)
{
	size_t i;

	if (o->type == 'c') {
		for (i = 0; i < n; i++) {
			char tmp[8];
			printf("%4s", char_field(buf[i], tmp));
		}
		putchar('\n');
		return;
	}

	for (i = 0; i < n; i += (size_t)o->size) {
		/* od(1p): "the last object displayed shall be extended to a
		 * full object by adding zero-valued padding at the end" -- a
		 * trailing count not a multiple of the unit size must not read
		 * `buf` past the `n` bytes this row's read actually filled in
		 * (the rest of `buf` is a stale/uninitialized previous-row
		 * leftover, not real input). */
		size_t avail = n - i;
		unsigned long long v;
		int width;
		if (avail >= (size_t)o->size) {
			v = load_unit(buf + i, o->size);
		} else {
			unsigned char tail[8] = { 0 };
			for (size_t k = 0; k < avail; k++) tail[k] = buf[i + k];
			v = load_unit(tail, o->size);
		}
		switch (o->type) {
		case 'x': width = o->size * 2; printf(" %*llx", width, v); break;
		case 'o': width = odigits(o->size); printf(" %*llo", width, v); break;
		case 'u': width = udigits(o->size); printf(" %*llu", width, v); break;
		case 'd': default: {
			long long sv;
			/* sign-extend from the unit's own size */
			unsigned long long signbit = 1ULL << (o->size * 8 - 1);
			if (o->size < 8 && (v & signbit)) sv = (long long)(v | ~((signbit << 1) - 1));
			else sv = (long long)v;
			width = ddigits(o->size);
			printf(" %*lld", width, sv);
			break;
		}
		}
	}
	putchar('\n');
}

/* Only a full ROWBYTES row can ever be elided (a short final row is
 * trivially "not identical" -- different length -- to any full-length
 * predecessor, so no special-case is needed for it). */
static int od_run(struct instream *is, const struct od_opts *o)
{
	/* prev[] is zero-initialized defensively, not because it is ever
	 * read before being written: every read of it below is gated by
	 * prev_valid (never true until the memcpy() a few lines down has
	 * run at least once) -- cppcheck's uninitvar check does not trace
	 * that multi-term && guard and flags a false positive without this. */
	unsigned char buf[ROWBYTES], prev[ROWBYTES] = { 0 };
	unsigned long long off = 0;
	int prev_valid = 0, prev_full = 0, in_run = 0;
	long long remaining = o->count; /* -1: unbounded */

	if (o->skip > 0) {
		long long left = o->skip;
		unsigned char trash[4096];
		while (left > 0) {
			size_t want = left < (long long)sizeof trash ? (size_t)left : sizeof trash;
			size_t got = instream_read(is, trash, want);
			if (got == 0) break; /* skip past EOF: not an error, per -N's own "missing data isn't an error" spirit */
			left -= (long long)got;
		}
		/* od(1p): the offset column is the byte's real position in the
		 * (concatenated) input, so a -j skip must be reflected in every
		 * offset printed afterward -- including the final "total bytes"
		 * closing line -- not just in which bytes get displayed. `off`
		 * starting at 0 here would print offset 0 for the first
		 * post-skip row even though that row's first byte is actually
		 * o->skip bytes into the input. Use o->skip - left (the bytes
		 * actually consumed above) rather than o->skip itself so a skip
		 * that ran past EOF still reports the true, possibly-shorter,
		 * number of bytes skipped. */
		off = (unsigned long long)(o->skip - left);
	}

	for (;;) {
		size_t want = ROWBYTES;
		size_t got;
		if (remaining >= 0) {
			if (remaining == 0) break;
			if ((long long)want > remaining) want = (size_t)remaining;
		}
		got = instream_read(is, buf, want);
		if (got == 0) break;
		if (remaining >= 0) remaining -= (long long)got;

		int same = got == ROWBYTES;
		for (size_t j = 0; same && j < ROWBYTES; j++)
			if (buf[j] != prev[j]) same = 0;
		if (!o->verbose && prev_valid && prev_full && same) {
			if (!in_run) { printf("*\n"); in_run = 1; }
		} else {
			print_offset(o, off);
			if (o->abase != 'n' && fputc(' ', stdout) == EOF) od_output_failed = 1;
			print_row(o, buf, got);
			in_run = 0;
		}
		for (size_t j = 0; j < got; j++) prev[j] = buf[j];
		prev_valid = 1;
		prev_full = (got == ROWBYTES);
		off += got;
	}

	/* od(1p)'s traditional closing line: the final total offset, with
	 * no data -- what lets a reader see the exact byte count even when
	 * it lands exactly on a row boundary (or was entirely elided). */
	if (o->abase != 'n') {
		print_offset(o, off);
		putchar('\n');
	}
	if (fflush(stdout) != 0) od_output_failed = 1;
	return is->any_error || od_output_failed;
}

/* ---- argument parsing --------------------------------------------------- */

static int parse_type(const char *s, char *type, int *size)
{
	if (!strcmp(s, "c")) { *type = 'c'; *size = 1; return 0; }
	if ((s[0] == 'x' || s[0] == 'o' || s[0] == 'd' || s[0] == 'u') && s[1]) {
		char *end;
		long v = strtol(s + 1, &end, 10);
		if (*end || (v != 1 && v != 2 && v != 4 && v != 8)) return -1;
		*type = s[0];
		*size = (int)v;
		return 0;
	}
	return -1;
}

int __util_od_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	struct od_opts o;
	struct instream is;
	int i = 1;
	char **files;
	int nfiles;
	int status;
	od_output_failed = 0;

	o.abase = 'o';
	o.skip = 0;
	o.count = -1;
	o.type = 'o';
	o.size = 2; /* default: "as if -t oS" */
	o.verbose = 0;

	for (; i < argc; i++) {
		char *a = argv[i];
		if (a[0] != '-' || a[1] == 0) break;
		if (!strcmp(a, "--")) { i++; break; }
		if (!strcmp(a, "-v")) { o.verbose = 1; continue; }
		if (!strcmp(a, "-A")) {
			if (i + 1 >= argc) { __util_diagf("od: -A: option requires an argument\n"); return 1; }
			a = argv[++i];
			if (strlen(a) != 1 || !strchr("doxn", a[0])) {
				__util_diagf("od: -A %s: invalid address base\n", a);
				return 1;
			}
			o.abase = a[0];
			continue;
		}
		if (!strcmp(a, "-j")) {
			if (i + 1 >= argc) { __util_diagf("od: -j: option requires an argument\n"); return 1; }
			i++;
			if (parse_odnum(argv[i], &o.skip) < 0) {
				__util_diagf("od: -j: invalid skip count\n");
				return 1;
			}
			continue;
		}
		if (!strcmp(a, "-N")) {
			if (i + 1 >= argc) { __util_diagf("od: -N: option requires an argument\n"); return 1; }
			i++;
			if (parse_odnum(argv[i], &o.count) < 0) {
				__util_diagf("od: -N: invalid count\n");
				return 1;
			}
			continue;
		}
		if (!strcmp(a, "-t")) {
			if (i + 1 >= argc) { __util_diagf("od: -t: option requires an argument\n"); return 1; }
			i++;
			if (parse_type(argv[i], &o.type, &o.size) < 0) {
				__util_diagf("od: -t: invalid type (this build supports "
				                "x1/x2/x4/x8, o1/o2/o4/o8, d1/d2/d4/d8, u1/u2/u4/u8, c "
				                "-- not the C/S/I/L letter-size spelling, and not -t a/-t f)\n");
				return 1;
			}
			continue;
		}
		__util_diagf("od: %s: invalid option\n", a);
		return 1;
	}

	if (i < argc) {
		files = argv + i;
		nfiles = argc - i;
	} else {
		files = argv;
		nfiles = 0;
	}
	instream_init(&is, files, nfiles);
	status = od_run(&is, &o);
	return status ? 1 : 0;
}
