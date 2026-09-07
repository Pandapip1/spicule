/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The integer conversion family in src/stdlib/strtol.c: strtol, strtoul,
 * strtoll, strtoull, strtoimax, strtoumax.  All six go through one
 * `strtox` worker (parse the magnitude, then apply sign and range), so
 * the interesting bugs are in the base handling (0, 1, 36, 37,
 * negative), the ERANGE saturation, and where endptr lands -- not in six
 * independent parsers.
 *
 * The base is *derived from the input*, not fixed at 10/16: byte 0 of
 * the fuzzer input feeds a base in [-128, 127] (interpreted as int),
 * deliberately including 0 (auto-detect), 1 and 37 (both invalid: C99
 * 7.20.1.4p1 requires base in {0} u [2,36]) and negative values.  The
 * rest of the input is the subject string.
 *
 * An invalid base is undefined behaviour in the *standard*, and glibc
 * exploits that: it was fuzzed here first, and calling glibc's strtoll
 * with an out-of-range base left its endptr flat-out uninitialized
 * (observed: a garbage multi-terabyte offset for input "").  So the host
 * oracle is only ever called with a base of 0 or in [2,36]; an
 * out-of-range base still drives spicule's six functions (which document
 * EINVAL/endptr==nptr for it, src/stdlib/strtol.c's `parse`), just
 * without a host comparison.
 *
 * strtoll/strtoull/strtoimax/strtoumax are compared directly against the
 * host libc's strtoll/strtoull (via fuzz/host_oracle.c, reached with
 * dlsym the same way fuzz_strtod.c does): `long long` is 64 bits under
 * both the host ABI and this target's LLP64 one (LLONG_MAX is
 * 0x7fffffffffffffffLL in both arch/x86_64/bits/limits.h and the host's
 * <limits.h>), and intmax_t/uintmax_t are typedef'd to (unsigned) long
 * long here (include/stdint.h: INTMAX_MAX is INT64_MAX), so all four are
 * genuinely comparable to the host's 64-bit strtoll/strtoull.
 *
 * strtol/strtoul are NOT compared against the host's strtol/strtoul.
 * spicule targets LLP64: `long` is 32 bits (arch/x86_64/bits/limits.h,
 * LONG_MAX 0x7fffffffL), but this is a *native* build, where the host
 * compiler's `long` is 64 bits -- so spicule's strtol saturates at its
 * own 32-bit LONG_MAX while returning a 64-bit `long`, and glibc's
 * saturates at 2^63-1.  That is a header/target mismatch (the same
 * reason test/strto.c skips strtol natively), not a defect, and a naive
 * comparison would be a flood of false findings.  Instead strtol/strtoul
 * are checked for *self-consistency* against strtoll/strtoull: the
 * parse itself (which characters are consumed, where endptr lands) must
 * agree between the 32-bit- and 64-bit-limited wrappers, and the result
 * must equal the 64-bit one saturated to spicule's own LONG_MIN/LONG_MAX
 * (taken from <limits.h> as this harness's own compiler sees it, which
 * -nostdinc/-I arch/$(ARCH) makes spicule's, not the host's).
 */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>

extern long long host_strtoll(const char *, size_t *, int, int *);
extern unsigned long long host_strtoull(const char *, size_t *, int, int *);
extern void oracle_mismatch_i(const char *, const char *, long long, long long);

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	char buf[512];
	int base;
	size_t n;
	char *end;
	size_t hoff;
	int herr;
	long long want_ll, got_ll;
	unsigned long long want_ull, got_ull;
	long got_l;
	unsigned long got_ul;
	intmax_t got_im;
	uintmax_t got_um;

	if (size < 1) return 0;
	base = (int)(signed char)data[0];       /* -128..127, including 0/1/37-and-up */
	data++; size--;

	n = size < sizeof buf - 1 ? size : sizeof buf - 1;
	if (n) memcpy(buf, data, n);
	buf[n] = 0;
	if (n && memchr(buf, 0, n)) return 0;   /* embedded NUL: not one string */

	if (base != 0 && (base < 2 || base > 36)) {
		/* Invalid base: no host comparison (see the file header) -- just
		 * check spicule's own documented contract for it directly. */
		char *e;
		errno = 0;
		if (strtoll(buf, &e, base) != 0 || e != buf)
			oracle_mismatch_i("strtoll(invalid base) result/endptr", buf, 1, 0);
		if (errno != EINVAL)
			oracle_mismatch_i("strtoll(invalid base) errno != EINVAL", buf, errno, EINVAL);
		errno = 0;
		if (strtoul(buf, &e, base) != 0 || e != buf || errno != EINVAL)
			oracle_mismatch_i("strtoul(invalid base) result/endptr/errno", buf, 1, 0);
		return 0;
	}

	/* ---- strtoll / strtoimax: directly against the host -------------- */
	errno = 0;
	got_ll = strtoll(buf, &end, base);
	herr = 0;
	want_ll = host_strtoll(buf, &hoff, base, &herr);
	if (got_ll != want_ll)
		oracle_mismatch_i("strtoll value", buf, got_ll, want_ll);
	if ((size_t)(end - buf) != hoff)
		oracle_mismatch_i("strtoll endptr offset", buf, (long long)(end - buf), (long long)hoff);
	if ((errno == ERANGE) != (herr == ERANGE))
		oracle_mismatch_i("strtoll errno==ERANGE", buf, errno == ERANGE, herr == ERANGE);

	errno = 0;
	got_im = strtoimax(buf, &end, base);
	if ((long long)got_im != got_ll)
		oracle_mismatch_i("strtoimax != strtoll", buf, (long long)got_im, got_ll);
	{
		char *end2;
		strtoll(buf, &end2, base);
		if (end != end2)
			oracle_mismatch_i("strtoimax endptr != strtoll endptr", buf,
			                  (long long)(end - buf), (long long)(end2 - buf));
	}

	/* ---- strtoull / strtoumax: directly against the host -------------- */
	errno = 0;
	got_ull = strtoull(buf, &end, base);
	herr = 0;
	want_ull = host_strtoull(buf, &hoff, base, &herr);
	if (got_ull != want_ull)
		oracle_mismatch_i("strtoull value", buf, (long long)got_ull, (long long)want_ull);
	if ((size_t)(end - buf) != hoff)
		oracle_mismatch_i("strtoull endptr offset", buf, (long long)(end - buf), (long long)hoff);
	if ((errno == ERANGE) != (herr == ERANGE))
		oracle_mismatch_i("strtoull errno==ERANGE", buf, errno == ERANGE, herr == ERANGE);

	got_um = strtoumax(buf, &end, base);
	if ((unsigned long long)got_um != got_ull)
		oracle_mismatch_i("strtoumax != strtoull", buf, (long long)got_um, (long long)got_ull);

	/* ---- strtol/strtoul: self-consistency against strtoll/strtoull,
	 * saturating to spicule's OWN LONG_MIN/LONG_MAX/ULONG_MAX (this
	 * harness's <limits.h> is arch/$(ARCH)'s, per -nostdinc), never the
	 * host's.
	 *
	 * strtox's magnitude v is parsed once per call and compared against
	 * that call's own `lim`; when the 32-bit-limited call does NOT
	 * overflow, v fits in 32 bits, so it can't have overflowed the
	 * 64-bit-limited call either, and both computed plain +-v (signed)
	 * or (0-v)&lim (unsigned) from the same v -- so for the unsigned
	 * case truncating the 64-bit answer to 32 bits has to equal the
	 * 32-bit answer (two's-complement truncation commutes with mod),
	 * and for the signed case the two answers are simply equal.  When
	 * the 32-bit call DOES overflow, its answer is exactly its own
	 * LONG_MAX/LONG_MIN/ULONG_MAX by definition -- so that is compared
	 * against directly instead of against the 64-bit result. --------- */
	{
		char *endl;

		errno = 0;
		got_l = strtol(buf, &endl, base);
		if (errno == ERANGE) {
			long want = got_l < 0 ? LONG_MIN : LONG_MAX;
			if (got_l != want)
				oracle_mismatch_i("strtol ERANGE result != LONG_MIN/LONG_MAX",
				                  buf, (long long)got_l, (long long)want);
		} else if ((long long)got_l != got_ll) {
			oracle_mismatch_i("strtol (no overflow) != strtoll", buf,
			                  (long long)got_l, got_ll);
		}
		if (endl != end)
			oracle_mismatch_i("strtol endptr != strtoll endptr", buf,
			                  (long long)(endl - buf), (long long)(end - buf));
	}
	{
		char *endu;

		errno = 0;
		got_ul = strtoul(buf, &endu, base);
		if (errno == ERANGE) {
			if (got_ul != ULONG_MAX)
				oracle_mismatch_i("strtoul ERANGE result != ULONG_MAX", buf,
				                  (long long)got_ul, (long long)ULONG_MAX);
		} else {
			/* Truncate with the header's own ULONG_MAX mask, not a cast
			 * to `unsigned long`: natively that type is 64 bits (the
			 * compiler's, not the PE target's), so a cast alone does
			 * not reproduce the 32-bit wraparound spicule's strtoul
			 * actually performs (arch/x86_64/bits/limits.h keeps `long`
			 * at 32 bits only in its own macros, not in the type). */
			unsigned long long want = got_ull & (unsigned long long)ULONG_MAX;
			if ((unsigned long long)got_ul != want)
				oracle_mismatch_i("strtoul (no overflow) != strtoull masked to ULONG_MAX",
				                  buf, (long long)got_ul, (long long)want);
		}
		if (endu != end)
			oracle_mismatch_i("strtoul endptr != strtoull endptr", buf,
			                  (long long)(endu - buf), (long long)(end - buf));
	}

	return 0;
}
