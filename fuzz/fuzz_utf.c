/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * src/internal/utf.c, and src/stdlib/mbtowc.c / mbrtowc.c.
 *
 * What is and is not under test here matters, and it changed: utf.c's
 * UTF-8 <-> UTF-16 conversions used to be a thin wrapper around ntdll's
 * RtlUTF8ToUnicodeN and RtlUnicodeToUTF8N, which a native build does not
 * have -- fuzz/ntstubs.c reimplemented them from their documented
 * behaviour just so this harness had something to link against, and this
 * comment used to say (correctly, then) that the harness was not
 * evidence about ntdll's real converter.  utf.c now carries its own
 * from-scratch, platform-independent codec (see its header for why:
 * dropping the ntdll dependency dropped spicule's minimum supported
 * Windows version), so this native build now runs the *exact same*
 * conversion code the PE build does.  fuzz/ntstubs.c's RtlUTF8ToUnicodeN
 * / RtlUnicodeToUTF8N are unreachable from here as a result -- nothing
 * in utf.c calls them any more -- but are kept for other ntstubs.c
 * consumers (its own cmdline_to_argv()).
 *
 * What is still true, and is what this harness actually checks: the
 * buffer arithmetic utf.c performs around the conversion, and the two
 * size claims its allocations rest on --
 *
 *     "UTF-16 is never longer in code units than UTF-8 is in bytes"
 *     "UTF-8 is at most 3 bytes per UTF-16 code unit"
 *
 * -- which are exactly the sort of claim that holds until a malformed
 * input makes the converter substitute something longer.  ASan sees any
 * overrun of the resulting heap blocks directly.
 *
 * mbrtowc/mbtowc are spicule's own decoders and are fuzzed for real.
 */
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <errno.h>
#include "libc.h"

extern void oracle_mismatch_i(const char *, const char *, long long, long long);

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	char s[1024];
	WCHAR w[512];
	size_t n = size < sizeof s - 1 ? size : sizeof s - 1, wlen = 0, i;
	WCHAR *conv;

	if (!n) return 0;
	memcpy(s, data, n);
	s[n] = 0;

	/* ---- UTF-8 in, UTF-16 out --------------------------------------- */
	conv = __utf8_to_utf16(s, &wlen);
	if (conv) {
		/* the claim utf.c allocates on */
		if (wlen > strlen(s))
			oracle_mismatch_i("__utf8_to_utf16 produced more code units than input bytes",
			                  s, (long long)wlen, (long long)strlen(s));
		if (conv[wlen] != 0)
			oracle_mismatch_i("__utf8_to_utf16 result not NUL-terminated", s,
			                  (long long)conv[wlen], 0);

		/* ---- and back again ------------------------------------------ */
		{
			char *back = __utf16_to_utf8(conv, wlen);
			if (back) {
				/* Re-encoding what came out must be stable: converting the
				 * round-tripped string again has to give the same UTF-16. */
				size_t wlen2 = 0;
				WCHAR *again = __utf8_to_utf16(back, &wlen2);
				if (again) {
					if (wlen2 != wlen || memcmp(again, conv, wlen * sizeof(WCHAR)))
						oracle_mismatch_i("UTF-8/UTF-16 round trip is not stable",
						                  back, (long long)wlen2, (long long)wlen);
					free(again);
				}
				free(back);
			}
		}

		/* ---- the bounded form, at every buffer size around the edge --- */
		for (i = 0; i <= 8; i++) {
			size_t cap = wlen * 3 + 1;
			char *buf;
			int rc;
			if (cap < i) continue;
			cap -= i;
			buf = malloc(cap + 1);
			if (!buf) break;
			buf[cap] = 0x5a;
			rc = __utf16_to_utf8_buf(conv, wlen, buf, cap);
			if ((unsigned char)buf[cap] != 0x5a)
				oracle_mismatch_i("__utf16_to_utf8_buf wrote past its buffer", s,
				                  (long long)(unsigned char)buf[cap], 0x5a);
			if (rc >= 0 && (size_t)rc >= cap)
				oracle_mismatch_i("__utf16_to_utf8_buf returned more than it was given",
				                  s, rc, (long long)cap - 1);
			free(buf);
		}
		free(conv);
	}

	/* ---- UTF-16 in (raw bytes reinterpreted), UTF-8 out -------------- */
	{
		size_t units = (n / sizeof(WCHAR));
		char *out;
		if (units > sizeof w / sizeof *w) units = sizeof w / sizeof *w;
		memcpy(w, s, units * sizeof(WCHAR));
		out = __utf16_to_utf8(w, units);
		if (out) {
			if (strlen(out) > units * 3)
				oracle_mismatch_i("__utf16_to_utf8 exceeded 3 bytes per code unit",
				                  s, (long long)strlen(out), (long long)units * 3);
			free(out);
		}
	}

	/* ---- spicule's own multibyte decoders ---------------------------- */
	{
		mbstate_t st;
		const char *p = s;
		size_t left = n;
		wchar_t wc;
		memset(&st, 0, sizeof st);
		while (left) {
			size_t rc = mbrtowc(&wc, p, left, &st);
			if (rc == (size_t)-1 || rc == (size_t)-2) break;
			/* (size_t)-3 is the low half of a surrogate pair, produced from
			 * state and consuming nothing.  wchar_t is 16 bits on the NT
			 * target, so this is a normal return here, not an error. */
			if (rc == (size_t)-3) continue;
			if (rc == 0) rc = 1;
			if (rc > left)
				oracle_mismatch_i("mbrtowc consumed more than it was given", s,
				                  (long long)rc, (long long)left);
			p += rc; left -= rc;
		}
		(void)mbtowc(&wc, s, n);
	}
	return 0;
}
