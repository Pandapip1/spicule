/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * dd(1p): a block-oriented copy utility with its own `operand=value`
 * argument grammar (XCU dd(1p) OPERANDS) instead of `-flag` options --
 * every argv[i] here is parsed as "name=value" or rejected outright.
 *
 * ---- OPERANDS implemented ------------------------------------------------
 *
 *  if=file / of=file   Input/output file; unspecified means standard
 *                       input / standard output, per dd(1p)'s own
 *                       "[i]f no if operand is specified... standard
 *                       input shall be used" wording (and symmetrically
 *                       for of/standard output).
 *  ibs=expr / obs=expr Input/output block size.
 *  bs=expr             "Set the input and output block sizes, superseding
 *                       ibs and obs.  If input blocks read are short ...
 *                       and the sync conversion is not specified, the
 *                       resultant output block ... shall be the same
 *                       size as the corresponding input block."  That
 *                       last clause is a real, specified behavioural
 *                       difference from ibs=/obs=: with bs=, this
 *                       implementation copies each block through as-is
 *                       (dd_copy_direct() below) instead of recombining
 *                       reads into obs-sized writes the way ibs=/obs=
 *                       does (dd_copy_blocked()) -- see either
 *                       function's own comment.
 *  count=n              Copy only n input blocks, then stop.
 *  skip=n / seek=n      Skip n ibs-sized / obs-sized blocks (from the
 *                       beginning of the file) before copying starts.
 *                       "If it is not possible to seek ... dd shall read
 *                       and discard" -- implemented for skip= (input)
 *                       exactly that way when lseek() reports the file is
 *                       not seekable; seek= (output) has no such
 *                       documented fallback and a non-seekable output is
 *                       a real, diagnosed error here instead.
 *  conv=value[,value...] Comma-separated conversions.  Only the cheap,
 *                       commonly-used subset below is implemented; any
 *                       other value is a loud, nonzero-exit refusal
 *                       (never a silent no-op -- the same "an
 *                       unsupported option must not look like it
 *                       worked" rule src/sh/builtin.c's bi_set() and
 *                       src/util/touch.c's -d both already apply):
 *                         notrunc  Do not truncate the output file --
 *                                  open it without O_TRUNC, so data
 *                                  past what this run writes survives
 *                                  (the point of combining it with
 *                                  seek=, to patch part of a file).
 *                         sync     Pad every short input block (a final
 *                                  partial read, or -- with noerror --
 *                                  one a read error cut short) to the
 *                                  full ibs with trailing NUL bytes,
 *                                  rather than passing the short length
 *                                  straight through.
 *                         noerror  Continue past a read error instead of
 *                                  stopping; the block that failed
 *                                  contributes nothing (or, combined
 *                                  with sync, an ibs of NUL bytes) rather
 *                                  than being retried or guessed at.
 *                       ucase/lcase/swab/ascii/ebcdic/block/unblock and
 *                       the rest of chmod(1p)... no, dd(1p)'s own
 *                       conv= alphabet are a documented, deliberate gap:
 *                       character-set and record-format conversions are
 *                       real work this project's own callers (bootstrap
 *                       image copies, mainly) never need, and refusing
 *                       them outright is far safer than a partial,
 *                       silently-wrong implementation of any one of
 *                       them.
 *
 * ---- the block-size grammar (b/k/w suffixes, 'x' multiplication) --------
 *
 * dd(1p): "b: Multiply by 512 ... k: Multiply by 1024 ... w: Multiply by
 * the number of bytes in an integer ... expr1'x'expr2 ... equivalent to
 * expr1*expr2."  parse_dd_num() below implements exactly that: an
 * unsigned decimal integer, an optional single b/k/w suffix, and an
 * optional trailing 'x'-and-another-expression multiplier (recursive, so
 * "2x3x4" parses the same left-to-right way arithmetic reads).  "w"'s
 * "the number of bytes in an integer" is taken as sizeof(int) on this
 * platform (4) rather than the traditional PDP-11-derived "2" some very
 * old dd implementations hardcoded -- the standard's own wording is
 * platform-relative, not a fixed historical constant.
 *
 * ---- the end-of-run summary ----------------------------------------------
 *
 * dd(1p): "Upon receiving SIGINT, dd shall write the following to
 * standard error before exiting: ... total number of complete and
 * partial input and output blocks."  Implemented as a required feature,
 * not a cosmetic afterthought: the summary is written on ordinary
 * completion too (both really are just "the run has stopped copying"),
 * in the "N+P records in / N+P records out" format every historical dd
 * uses.  SIGINT itself is handled by a plain flag (`static volatile
 * sig_atomic_t dd_interrupted`) set from the handler and polled by the
 * copy loop between blocks and after every EINTR -- nothing runs inside
 * the handler except that one assignment, so there is no async-signal-
 * safety question about the fprintf() that prints the summary, which
 * always happens back on the normal call stack, after the loop has
 * actually stopped.  The previous SIGINT disposition is saved and
 * restored before returning (both success and failure paths, and the
 * SIGINT path itself), because __util_dd_main() can run in-process as a
 * shell built-in (src/sh/builtin.c) rather than as its own process --
 * leaving a handler installed after `dd` returns would keep intercepting
 * SIGINT for the rest of the shell's own life, and calling exit()/_exit()
 * from inside the handler (the other common way to implement this) would
 * tear down that whole shell process instead of just this one command,
 * which is exactly the class of mistake src/sh/builtin.c's own header
 * comment warns about for a builtin's effect on its host process.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <inttypes.h>
#include "ownership_stubs.h"
#include "util.h"

static volatile sig_atomic_t dd_interrupted;

static void dd_sigint_handler(int sig)
{
	(void)sig;
	dd_interrupted = 1;
}

/* Overflow-checked multiplication for the uintmax_t arithmetic dd(1p)'s own
 * block-size/skip/seek/count grammar does throughout this file: a bare
 * `a * b` here would silently wrap mod 2^64 on overflow, landing on some
 * arbitrary *nonzero* value that sails straight past a caller's simple
 * `== 0` validation -- the classic "multiply that overflows before the
 * bounds check runs" bug class this function exists to close off, once,
 * for every call site below (parse_dd_num()'s own b/k/w suffix and 'x'
 * multiplier, and dd_position()'s skip/seek-count * block-size). */
static int dd_mul_overflows(uintmax_t a, uintmax_t b, uintmax_t *out)
{
	if (b != 0 && a > UINTMAX_MAX / b) return -1;
	*out = a * b;
	return 0;
}

/* dd(1p)'s block-size expression grammar -- see this file's header. */
// NOLINTNEXTLINE(misc-no-recursion) -- suffix-expression parsing consumes input on every recursive step
static int parse_dd_num(const char *s, uintmax_t *out)
{
	char *end;
	uintmax_t v;

	if (!*s) return -1;
	errno = 0;
	v = strtoumax(s, &end, 10);
	if (end == s) return -1;
	/* strtoumax() itself clamps a literal too big for uintmax_t to
	 * UINTMAX_MAX and sets errno to ERANGE (src/stdlib/strtol.c) rather
	 * than failing outright -- without this check that clamped value
	 * would silently stand in for whatever the caller actually typed. */
	if (v == UINTMAX_MAX && errno == ERANGE) return -1;
	s = end;

	if (*s == 'b') { if (dd_mul_overflows(v, 512, &v) < 0) return -1; s++; }
	else if (*s == 'k') { if (dd_mul_overflows(v, 1024, &v) < 0) return -1; s++; }
	else if (*s == 'w') { if (dd_mul_overflows(v, sizeof(int), &v) < 0) return -1; s++; }

	if (*s == 'x') {
		uintmax_t rhs;
		if (parse_dd_num(s + 1, &rhs) < 0) return -1;
		if (dd_mul_overflows(v, rhs, &v) < 0) return -1;
		*out = v;
		return 0;
	}
	if (*s) return -1; /* trailing garbage */
	*out = v;
	return 0;
}

struct dd_opts {
	const char *if_path, *of_path;
	uintmax_t ibs, obs;
	int bs_mode;
	uintmax_t count;
	int have_count;
	uintmax_t skip, seek;
	int notrunc, sync, noerror;
};

/* conv=value[,value...] -- see this file's header for the implemented
 * subset. *notrunc, *sync, and *noerror are set (never left untouched) on a
 * 0 return; on -1 a diagnostic is already on stderr and the caller must
 * not trust any of the three. */
static int parse_conv(const char *val, int *notrunc, int *sync, int *noerror)
{
	char buf[256];
	char *tok;
	size_t n = strlen(val);

	if (n >= sizeof buf) { __util_diagf("dd: conv=%s: too long\n", val); return -1; }
	__ownership_readable_span(val, n + 1);
	memcpy(buf, val, n + 1);

	*notrunc = *sync = *noerror = 0;
	for (tok = strtok(buf, ","); tok; tok = strtok(0, ",")) {
		if (!strcmp(tok, "notrunc")) *notrunc = 1;
		else if (!strcmp(tok, "sync")) *sync = 1;
		else if (!strcmp(tok, "noerror")) *noerror = 1;
		else {
			__util_diagf("dd: conv=%s: not supported by this build "
			                "-- see src/util/dd.c\n", tok);
			return -1;
		}
	}
	return 0;
}

static int write_all(int fd, const char *buf, size_t n, const char *what)
{
	size_t off = 0;
	while (off < n) {
		__ownership_readable_span(buf + off, n - off);
		ssize_t w = write(fd, buf + off, n - off);
		if (w < 0) {
			if (errno == EINTR) continue;
			__util_diagf("dd: writing '%s': %s\n", what, strerror(errno));
			return -1;
		}
		off += (size_t)w;
	}
	return 0;
}

/* bs= mode: each input block is written straight out at whatever length
 * was actually read -- see this file's header on why this differs from
 * dd_copy_blocked() below. */
static int dd_copy_direct(int ifd, int ofd, const struct dd_opts *o,
	uintmax_t *in_full, uintmax_t *in_partial, uintmax_t *out_full, uintmax_t *out_partial, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
	int *had_error)
{
	char *buf = malloc((size_t)o->ibs);
	uintmax_t blocks = 0;

	if (!buf) { __util_diagf("dd: out of memory\n"); return -1; }

	for (;;) {
		ssize_t n;
		if (o->have_count && blocks >= o->count) break;
		if (dd_interrupted) break;

		n = read(ifd, buf, (size_t)o->ibs);
		if (n < 0) {
			if (errno == EINTR) { if (dd_interrupted) break; continue; }
			__util_diagf("dd: reading '%s': %s\n", o->if_path ? o->if_path : "stdin", strerror(errno));
			if (o->noerror) {
				*in_partial += 1;
				blocks++;
				if (o->sync) {
					memset(buf, 0, (size_t)o->ibs);
					if (write_all(ofd, buf, (size_t)o->ibs, o->of_path ? o->of_path : "stdout") < 0) { *had_error = 1; break; }
					*out_full += 1;
				}
				continue;
			}
			*had_error = 1;
			break;
		}
		if (n == 0) break;
		blocks++;
		if ((uintmax_t)n == o->ibs) (*in_full)++; else (*in_partial)++;
		if (o->sync && (uintmax_t)n < o->ibs) {
			__ownership_writable_span(buf + n,
			                          (size_t)(o->ibs - (uintmax_t)n));
			memset(buf + n, 0, (size_t)(o->ibs - (uintmax_t)n));
			n = (ssize_t)o->ibs;
		}

		if (write_all(ofd, buf, (size_t)n, o->of_path ? o->of_path : "stdout") < 0) { *had_error = 1; break; }
		if ((uintmax_t)n == o->obs) (*out_full)++; else (*out_partial)++;
	}
	free(buf);
	return 0;
}

/* ibs != obs (or both left at their 512 default): reads are recombined
 * into obs-sized writes, carrying a partial output block across
 * multiple reads exactly the way historical dd's own blocking/
 * deblocking behaviour works. */
static int dd_copy_blocked(int ifd, int ofd, const struct dd_opts *o,
	uintmax_t *in_full, uintmax_t *in_partial, uintmax_t *out_full, uintmax_t *out_partial, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
	int *had_error)
{
	char *restrict ibuf = malloc((size_t)o->ibs);
	char *restrict obuf = malloc((size_t)o->obs);
	size_t obuf_used = 0;
	uintmax_t blocks = 0;

	if (!ibuf || !obuf) { free(ibuf); free(obuf); __util_diagf("dd: out of memory\n"); return -1; }

	for (;;) {
		ssize_t n;
		size_t off;
		if (o->have_count && blocks >= o->count) break;
		if (dd_interrupted) break;

		n = read(ifd, ibuf, (size_t)o->ibs);
		if (n < 0) {
			if (errno == EINTR) { if (dd_interrupted) break; continue; }
			__util_diagf("dd: reading '%s': %s\n", o->if_path ? o->if_path : "stdin", strerror(errno));
			if (o->noerror) {
				*in_partial += 1;
				blocks++;
				if (o->sync) { memset(ibuf, 0, (size_t)o->ibs); n = (ssize_t)o->ibs; }
				else continue;
			} else {
				*had_error = 1;
				break;
			}
		} else if (n == 0) {
			break;
		} else {
			blocks++;
			if ((uintmax_t)n == o->ibs) (*in_full)++; else (*in_partial)++;
			if (o->sync && (uintmax_t)n < o->ibs) {
				__ownership_writable_span(ibuf + n,
				                          (size_t)(o->ibs - (uintmax_t)n));
				memset(ibuf + n, 0,
				       (size_t)(o->ibs - (uintmax_t)n));
				n = (ssize_t)o->ibs;
			}
		}

		off = 0;
		while (off < (size_t)n) {
			size_t take = (size_t)o->obs - obuf_used;
			size_t i;
			if (take > (size_t)n - off) take = (size_t)n - off;
			for (i = 0; i < take; i++) obuf[obuf_used + i] = ibuf[off + i];
			obuf_used += take;
			off += take;
			if (obuf_used == (size_t)o->obs) {
				if (write_all(ofd, obuf, (size_t)o->obs, o->of_path ? o->of_path : "stdout") < 0) { *had_error = 1; goto out; }
				(*out_full)++;
				obuf_used = 0;
			}
		}
	}
	if (obuf_used > 0 && !*had_error) {
		if (write_all(ofd, obuf, obuf_used, o->of_path ? o->of_path : "stdout") < 0) *had_error = 1;
		else (*out_partial)++;
	}
out:
	free(ibuf);
	free(obuf);
	return 0;
}

/* Skip n `unit`-sized blocks on `fd` before copying starts.  Tries
 * lseek() first; falls back to read-and-discard only for `is_input`
 * (dd(1p)'s own documented fallback is for skip=, not seek= -- see this
 * file's header). Returns 0 on success, -1 (diagnostic already written)
 * on failure. */
static int dd_position(int fd, uintmax_t n, uintmax_t unit, int is_input, const char *what) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	uintmax_t bytes;

	/* n and unit (skip=/seek= and ibs=/obs=) are each validated on their
	 * own by the caller's parse_dd_num(), but their product never is --
	 * a bare `n * unit` here can wrap mod 2^64 and land on a small (even
	 * zero) byte offset for a skip/seek the user asked to be enormous,
	 * silently copying data that was supposed to be skipped past instead
	 * of failing loudly.  off_t is a signed 64-bit type on this tree
	 * (include/alltypes.h.gen), so the product must also fit INTMAX_MAX
	 * before the `(off_t)bytes` cast below, or that cast itself produces
	 * an implementation-defined (in practice negative) offset. */
	if (dd_mul_overflows(n, unit, &bytes) < 0 || bytes > (uintmax_t)INTMAX_MAX) {
		__util_diagf("dd: %s: %" PRIuMAX " * %" PRIuMAX " overflows\n",
			is_input ? "skip" : "seek", n, unit);
		return -1;
	}
	if (bytes == 0) return 0;
	if (lseek(fd, (off_t)bytes, SEEK_SET) >= 0) return 0;
	if (is_input) {
		char buf[8192];
		uintmax_t left = bytes;
		while (left > 0) {
			size_t chunk = left < sizeof buf ? (size_t)left : sizeof buf;
			ssize_t r = read(fd, buf, chunk);
			if (r < 0) {
				if (errno == EINTR) continue;
				__util_diagf("dd: skip: reading '%s': %s\n", what, strerror(errno));
				return -1;
			}
			if (r == 0) break; /* skip past EOF: nothing left to copy, not an error */
			left -= (uintmax_t)r;
		}
		return 0;
	}
	__util_diagf("dd: seek: '%s' is not seekable: %s\n", what, strerror(errno));
	return -1;
}

int __util_dd_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	struct dd_opts o;
	struct sigaction sa, old_sa;
	int ifd = -1, ofd = -1, i, status = 0, had_error = 0;
	uintmax_t in_full = 0, in_partial = 0, out_full = 0, out_partial = 0;

	memset(&o, 0, sizeof o);
	o.ibs = o.obs = 512;

	for (i = 1; i < argc; i++) {
		char *a = argv[i];
		char *eq;
		size_t klen;
		const char *val;

		klen = strcspn(a, "=");
		if (!a[klen]) {
			__util_diagf("dd: %s: not an operand=value pair\n", a);
			return 2;
		}
		eq = a + klen;
		val = eq + 1;

#define KEYIS(k) (klen == strlen(k) && !strncmp(a, k, klen))
		if (KEYIS("if")) { o.if_path = val; }
		else if (KEYIS("of")) { o.of_path = val; }
		else if (KEYIS("bs")) {
			if (parse_dd_num(val, &o.ibs) < 0 || o.ibs == 0) { __util_diagf("dd: bs=%s: invalid block size\n", val); return 2; }
			o.obs = o.ibs;
			o.bs_mode = 1;
		} else if (KEYIS("ibs")) {
			if (parse_dd_num(val, &o.ibs) < 0 || o.ibs == 0) { __util_diagf("dd: ibs=%s: invalid block size\n", val); return 2; }
		} else if (KEYIS("obs")) {
			if (parse_dd_num(val, &o.obs) < 0 || o.obs == 0) { __util_diagf("dd: obs=%s: invalid block size\n", val); return 2; }
		} else if (KEYIS("count")) {
			if (parse_dd_num(val, &o.count) < 0) { __util_diagf("dd: count=%s: invalid count\n", val); return 2; }
			o.have_count = 1;
		} else if (KEYIS("skip")) {
			if (parse_dd_num(val, &o.skip) < 0) { __util_diagf("dd: skip=%s: invalid count\n", val); return 2; }
		} else if (KEYIS("seek")) {
			if (parse_dd_num(val, &o.seek) < 0) { __util_diagf("dd: seek=%s: invalid count\n", val); return 2; }
		} else if (KEYIS("conv")) {
			if (parse_conv(val, &o.notrunc, &o.sync, &o.noerror) < 0) return 2;
		} else {
			__util_diagf("dd: %.*s=%s: unrecognized operand\n", (int)klen, a, val);
			return 2;
		}
#undef KEYIS
	}

	ifd = o.if_path ? open(o.if_path, O_RDONLY) : 0;
	if (ifd < 0) { __util_diagf("dd: %s: %s\n", o.if_path, strerror(errno)); return 1; }

	if (o.of_path) {
		int oflags = O_WRONLY | O_CREAT | (o.notrunc ? 0 : O_TRUNC);
		ofd = open(o.of_path, oflags, 0666);
	} else {
		ofd = 1;
	}
	if (ofd < 0) { __util_diagf("dd: %s: %s\n", o.of_path, strerror(errno)); if (ifd > 0) (void)close(ifd); return 1; }

	if (dd_position(ifd, o.skip, o.ibs, 1, o.if_path ? o.if_path : "stdin") < 0) { had_error = 1; goto summary; }
	if (dd_position(ofd, o.seek, o.obs, 0, o.of_path ? o.of_path : "stdout") < 0) { had_error = 1; goto summary; }

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = dd_sigint_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0; /* no SA_RESTART: a blocking read() must be interruptible */
	sigaction(SIGINT, &sa, &old_sa);

	if (o.bs_mode)
		dd_copy_direct(ifd, ofd, &o, &in_full, &in_partial, &out_full, &out_partial, &had_error);
	else
		dd_copy_blocked(ifd, ofd, &o, &in_full, &in_partial, &out_full, &out_partial, &had_error);

	sigaction(SIGINT, &old_sa, 0);

summary:
	/* %ju assumes the host libc's own uintmax_t (e.g. "unsigned long" on
	 * an LP64 Linux target), which is not what this tree's own
	 * <stdint.h> defines uintmax_t as (always "unsigned _Int64", i.e.
	 * "unsigned long long") -- see PRIuMAX's own comment in
	 * include/inttypes.h. __util_diagf is the one printf-family function
	 * in this tree that carries an explicit format(printf) attribute
	 * (src/internal/util.h), so it is the one place that mismatch is
	 * checkable, and PRIuMAX is exactly the macro built to name the
	 * matching length modifier instead of the bare, ABI-dependent 'j'. */
	__util_diagf("%" PRIuMAX "+%" PRIuMAX " records in\n%" PRIuMAX "+%" PRIuMAX " records out\n",
		in_full, in_partial, out_full, out_partial);

	if (ifd > 0) (void)close(ifd);
	if (ofd > 1 && close(ofd) < 0) {
		__util_diagf("dd: closing '%s': %s\n", o.of_path ? o.of_path : "stdout", strerror(errno));
		had_error = 1;
	}

	if (dd_interrupted) status = 130; /* 128+SIGINT, this project's own signal-exit-status convention (see test/util-fsops.c and friends) */
	else if (had_error) status = 1;
	return status;
}

// NOLINTEND(misc-include-cleaner)
