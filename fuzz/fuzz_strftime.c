/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * src/time/strftime.c: output-buffer sizing and truncation.  do_strftime
 * writes through the PUT_CH/PUT_STR/PUT_NUM macros, which are supposed
 * to bail out (overflow=1, return 0, leave *s unspecified) the instant
 * `pos + 1 >= max` rather than ever writing at s[max] or beyond -- a
 * classic off-by-one surface, and multi-character emitters (PUT_STR for
 * a day/month name, PUT_NUM for a 4-digit year or a %z offset) are where
 * an off-by-one in the bound tends to hide, not the single-char case.
 *
 * Rather than rely on ASan's redzone to *probabilistically* catch a
 * one-byte overrun (which depends on where malloc happens to place the
 * redzone), the destination here is a fixed-size buffer with a known
 * guard byte placed immediately after it, checked explicitly after every
 * call -- deterministic regardless of allocator layout.  The buffer size
 * itself is also fuzzed, specifically including sizes right at a
 * plausible field width (0, 1, 2, 3, 4, 5) where PUT_CH's `pos + 1 >=
 * max` boundary is likeliest to be off by one.
 *
 * The format string is fuzzed too (bytes 1.. of the input), including
 * unrecognized %<letter> conversions (passed through literally per the
 * file's own header comment) and the composite ones (%c %x %X %D %F %T
 * %R %r), which each expand into several PUT_NUM/PUT_STR calls and so
 * multiply any single off-by-one across the whole write.
 *
 * struct tm fields are also taken from the input (byte 0's bits) rather
 * than fixed, since __num_digits and the %j/%y/%Y paths are handed
 * whatever tm_year/tm_yday/etc. the caller had lying around -- strftime
 * itself clamps tm_wday/tm_mon defensively (see `wday`/`mon` in
 * do_strftime) but does not clamp tm_year, tm_mday, tm_hour, etc., so
 * out-of-range values there are exactly what a real caller with a
 * corrupt or hand-built struct tm would hand it.
 *
 * No host oracle: glibc's strftime honours %E/%O and locale data spicule
 * doesn't implement, so byte-for-byte comparison would be mostly noise;
 * this is a bounds/crash check.
 */
#include <time.h>
#include <string.h>

extern void oracle_mismatch_i(const char *, const char *, long long, long long);

#define GUARD 0x5a

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	char fmt[128];
	size_t flen;
	struct tm tm;
	unsigned char tmseed;
	static const size_t sizes[] = { 0, 1, 2, 3, 4, 5, 8, 16, 32, 64 };
	size_t si;

	if (size < 2) return 0;
	tmseed = data[0];
	data++; size--;

	flen = size < sizeof fmt - 1 ? size : sizeof fmt - 1;
	memcpy(fmt, data, flen);
	fmt[flen] = 0;
	if (memchr(fmt, 0, flen)) return 0;      /* embedded NUL: not one format */

	memset(&tm, 0, sizeof tm);
	tm.tm_sec  = (tmseed & 0x3f) - 8;         /* deliberately allow out-of-range */
	tm.tm_min  = ((tmseed >> 1) & 0x7f) - 16;
	tm.tm_hour = ((tmseed * 3) & 0x3f) - 8;
	tm.tm_mday = ((tmseed * 5) & 0x3f) - 8;
	tm.tm_mon  = ((tmseed * 7) & 0xff) - 64;
	tm.tm_year = (int)((tmseed * 131) - 128) * 3;
	tm.tm_wday = ((tmseed * 11) & 0xff) - 64;
	tm.tm_yday = ((tmseed * 13) & 0x1ff) - 64;
	tm.__tm_gmtoff = ((long)tmseed - 128) * 3600;
	tm.__tm_zone = tmseed & 1 ? "UTC" : "XYZ";

	for (si = 0; si < sizeof sizes / sizeof *sizes; si++) {
		size_t cap = sizes[si];
		char buf[72];
		size_t rc;

		if (cap + 1 > sizeof buf) continue;
		memset(buf, GUARD, sizeof buf);
		rc = strftime(buf, cap, fmt, &tm);

		if ((unsigned char)buf[cap] != GUARD)
			oracle_mismatch_i("strftime wrote past its buffer", fmt,
			                  (long long)(unsigned char)buf[cap], GUARD);

		if (rc == 0) {
			/* POSIX: either max was too small, or the true result really
			 * is the empty string (an empty format, or one made only of
			 * conversions that produce nothing -- there are none here,
			 * so with cap > 0 this branch means "didn't fit"). Contents
			 * of buf are then unspecified, but the guard byte still may
			 * not have been touched, which was just checked above. */
			continue;
		}

		/* Success: rc is strlen(buf), and buf[rc] is the NUL strftime
		 * placed itself -- both must be within the caller's cap, and
		 * nothing past index rc may have been written except that NUL. */
		if (rc >= cap)
			oracle_mismatch_i("strftime returned >= max on success", fmt,
			                  (long long)rc, (long long)cap);
		if (strlen(buf) != rc)
			oracle_mismatch_i("strftime return value != strlen(buf)", fmt,
			                  (long long)rc, (long long)strlen(buf));
	}

	return 0;
}
