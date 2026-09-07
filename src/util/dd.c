/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * dd(1p): a block-oriented copy utility with its own `operand=value`
 * argument grammar (XCU dd(1p) OPERANDS) instead of `-flag` options.
 *
 * Operands:
 *  if=file / of=file    Input/output file; default stdin/stdout.
 *  ibs=expr / obs=expr  Input/output block size.
 *  bs=expr              Sets both ibs and obs, and changes copy strategy:
 *                       with bs=, each block read is written out as-is
 *                       (dd_copy_direct()); with ibs=/obs=, reads are
 *                       recombined into obs-sized writes (dd_copy_blocked()).
 *                       This split is a real behavioral difference dd(1p)
 *                       itself specifies, not an implementation shortcut.
 *  count=n              Copy only n input blocks, then stop.
 *  skip=n / seek=n      Skip n ibs-/obs-sized blocks before copying starts.
 *                       skip= falls back to read-and-discard when the input
 *                       isn't seekable (POSIX-mandated); seek= has no such
 *                       fallback -- a non-seekable output is an error.
 *  conv=value[,...]     Only notrunc/sync/noerror are implemented; any
 *                       other value is a loud, nonzero-exit refusal rather
 *                       than a silent no-op. ucase/lcase/swab/ascii/ebcdic/
 *                       block/unblock are a deliberate gap -- this
 *                       project's own callers never need them.
 *                         notrunc  Open the output file without O_TRUNC.
 *                         sync     Pad every short input block to the full
 *                                  ibs with NUL bytes.
 *                         noerror  Continue past a read error instead of
 *                                  stopping.
 *
 * Block-size grammar: an unsigned decimal, an optional single b/k/w suffix
 * (multiply by 512/1024/sizeof(int)), and an optional trailing 'x'expr
 * multiplier, parsed recursively so "2x3x4" reads left-to-right.
 *
 * On SIGINT or ordinary completion, prints "N+P records in/out" to stderr.
 * The SIGINT handler only sets a flag (no work inside it), and the previous
 * disposition is restored before returning, since __util_dd_main() can run
 * in-process as a shell builtin (src/sh/builtin.c) rather than its own
 * process -- a handler left installed, or an exit() called from inside it,
 * would otherwise outlive this command or tear down the whole shell.
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

/* Overflow-checked multiplication -- a bare a*b could wrap and pass a
 * caller's `== 0` check with a bogus nonzero result. */
static int dd_mul_overflows(uintmax_t a, uintmax_t b, uintmax_t *out)
{
	if (b != 0 && a > UINTMAX_MAX / b) return -1;
	*out = a * b;
	return 0;
}

/* dd(1p)'s block-size expression grammar -- see this file's header. */
// NOLINTNEXTLINE(misc-no-recursion) -- suffix-expression parsing consumes input on every recursive step
static int parse_dd_num(const char *s withtok(null_terminated), uintmax_t *out)
{
	char *end;
	uintmax_t v;

	/* OPEN LINT FINDING (ntlibc.ValidPointer, "dereference extent is not
	 * proven sufficient"): every real caller passes a pointer into a
	 * NUL-terminated argv string (some via `val = eq + 1` after
	 * confirming a[klen] is non-NUL, so val is always at least the
	 * terminator itself), but that fact reaches here through symbolic
	 * pointer arithmetic on an opaque, unsized argv element -- no
	 * existing ownership.h annotation expresses "offset klen+1 into a
	 * null-terminated string of unknown static extent is in bounds",
	 * the same class of gap already accepted in src/util/sort.c and
	 * src/util/join.c. Left open rather than papered over. */
	if (!*s) return -1;
	errno = 0;
	v = strtoumax(s, &end, 10);
	if (end == s) return -1;
	/* strtoumax() clamps an overlong literal to UINTMAX_MAX and sets
	 * ERANGE instead of failing outright; without this check the clamped
	 * value would silently stand in for whatever was actually typed. */
	if (v == UINTMAX_MAX && errno == ERANGE) return -1;
	/* end still points within (or at the terminating NUL of) the same
	 * string s did on entry -- strtoumax()'s endptr contract -- but that
	 * fact does not survive the plain char * variable's own type. */
	__ownership_string_terminated(end);
	s = end;

	if (*s == 'b') { if (dd_mul_overflows(v, 512, &v) < 0) return -1; s++; }
	else if (*s == 'k') { if (dd_mul_overflows(v, 1024, &v) < 0) return -1; s++; }
	else if (*s == 'w') { if (dd_mul_overflows(v, sizeof(int), &v) < 0) return -1; s++; }

	if (*s == 'x') {
		uintmax_t rhs;
		/* s+1 is still inside the same NUL-terminated string s is, but
		 * the pointer-arithmetic expression itself doesn't carry the
		 * token this checker can trace. */
		__ownership_string_terminated(s + 1);
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
 * subset. On 0 return, *notrunc, *sync, and *noerror are all set; on -1
 * a diagnostic is already on stderr and the caller must not trust them. */
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
		/* strtok() always returns either NULL or a NUL-terminated token
		 * carved out of buf (itself NUL-terminated above); that fact
		 * does not survive strtok()'s own unannotated declaration. */
		__ownership_string_terminated(tok);
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

	/* n*unit must also fit INTMAX_MAX (not just UINTMAX_MAX): off_t is a
	 * signed 64-bit type here, so an oversized product would produce a
	 * negative offset once cast below. */
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
	/* PRIuMAX, not %ju: this tree's uintmax_t doesn't match the host
	 * libc's, so the bare 'j' length modifier would be wrong here. */
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
