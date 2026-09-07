/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * UTF-8 is the library's only character encoding: that is what every
 * char* a program hands in or gets back is.  ntdll wants UTF-16, so every
 * path or string that crosses into it goes through the pair of
 * conversions below.
 *
 * These used to call ntdll's RtlUTF8ToUnicodeN/RtlUnicodeToUTF8N rather
 * than reimplement them; that stopped being free once it turned out those
 * two names are the only ntdll exports newer than Windows Vista (NTDLL
 * 6.0) this library imports at all, so relying on them held the whole
 * library's floor at Windows 7 (NTDLL 6.1) -- see tools/ntdll.def and
 * README.md's "Supported Windows versions".  utf8_to_utf16n() and
 * utf16_to_utf8n() below are a from-scratch replacement, so
 * __utf8_to_utf16()/__utf16_to_utf8_buf()/__utf16_to_utf8() no longer
 * import anything to do their job.
 *
 * The two local functions match RtlUTF8ToUnicodeN's/RtlUnicodeToUTF8N's
 * documented contract exactly, since every caller in this file (and,
 * transitively, everything that calls into this file) was written
 * against that contract:
 *
 *   - dst == NULL is a size-query call: nothing is written, *written is
 *     set to the number of bytes the full conversion would need, and the
 *     call cannot fail.
 *   - Otherwise, conversion stops the instant writing the next unit(s)
 *     would exceed dstbytes.  Everything before that point has already
 *     been written, *written is set to that amount, and the function
 *     returns -1.  (Neither caller below inspects a partial *written on
 *     that path -- they discard the output -- but filling as far as it
 *     goes is what the real functions document doing, so this does too.)
 *   - A malformed input is never a hard failure by itself: an invalid
 *     lead byte, a truncated or broken continuation sequence, an
 *     overlong encoding, a UTF-8-encoded surrogate, a codepoint past
 *     U+10FFFF, or an unpaired UTF-16 surrogate all become one U+FFFD
 *     replacement character each, and decoding resumes right after the
 *     shortest invalid subsequence rather than failing outright.  This
 *     is the "maximal subpart" substitution Unicode recommends for
 *     exactly this case, and it is what ntdll's real converters do too --
 *     RtlUTF8ToUnicodeN/RtlUnicodeToUTF8N report it via the informational
 *     STATUS_SOME_NOT_MAPPED rather than any failure NTSTATUS, which is
 *     why neither caller here has ever treated malformed input as an
 *     error on its own; only "the output did not fit" is.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stdlib.h>
#include <string.h>
#include "libc.h"

#define UTF_REPLACEMENT 0xFFFDu

/* See the file banner for the contract.  bytes/units are counted rather
 * than characters throughout, matching RtlUTF8ToUnicodeN's own ULONG
 * byte-count parameters. */
static int utf8_to_utf16n(WCHAR *dst, ULONG dstbytes, ULONG *written,
                           const char *src, ULONG srcbytes)
{
	const unsigned char *s = (const unsigned char *)src, *end = s + srcbytes;
	ULONG out = 0;

	while (s < end) {
		unsigned int cp;
		int extra, i;
		unsigned char c = *s++;

		if (c < 0x80)                { cp = c; extra = 0; }
		else if ((c & 0xe0) == 0xc0) { cp = c & 0x1f; extra = 1; }
		else if ((c & 0xf0) == 0xe0) { cp = c & 0x0f; extra = 2; }
		else if ((c & 0xf8) == 0xf0) { cp = c & 0x07; extra = 3; }
		else                         { cp = UTF_REPLACEMENT; extra = 0; }

		for (i = 0; i < extra; i++) {
			if (s >= end || (*s & 0xc0) != 0x80) {
				cp = UTF_REPLACEMENT;
				extra = -1;
				break;
			}
			cp = (cp << 6) | (*s++ & 0x3f);
		}
		if (extra > 0 &&
		    ((extra == 1 && cp < 0x80) || (extra == 2 && cp < 0x800) ||
		     (extra == 3 && cp < 0x10000) || cp > 0x10FFFF ||
		     (cp >= 0xD800 && cp <= 0xDFFF)))
			cp = UTF_REPLACEMENT; /* overlong, surrogate, or out of range */

		if (cp >= 0x10000) {
			if (dst && out + 2 * sizeof(WCHAR) > dstbytes) {
				if (written) *written = out;
				return -1;
			}
			if (dst) {
				dst[out / sizeof(WCHAR)]     = (WCHAR)(0xD800 + ((cp - 0x10000) >> 10));
				dst[out / sizeof(WCHAR) + 1] = (WCHAR)(0xDC00 + ((cp - 0x10000) & 0x3ff));
			}
			out += 2 * sizeof(WCHAR);
		} else {
			if (dst && out + sizeof(WCHAR) > dstbytes) {
				if (written) *written = out;
				return -1;
			}
			if (dst) dst[out / sizeof(WCHAR)] = (WCHAR)cp;
			out += sizeof(WCHAR);
		}
	}
	if (written) *written = out;
	return 0;
}

/* See the file banner for the contract.  srcbytes, like
 * RtlUnicodeToUTF8N's, is a byte count over src, not a unit count. */
static int utf16_to_utf8n(char *dst, ULONG dstbytes, ULONG *written,
                           const WCHAR *src, ULONG srcbytes)
{
	ULONG i, n = srcbytes / sizeof(WCHAR), out = 0;

	for (i = 0; i < n; i++) {
		unsigned int cp = src[i];
		unsigned char buf[4];
		int len;

		if (cp >= 0xD800 && cp <= 0xDBFF) {
			if (i + 1 < n && src[i + 1] >= 0xDC00 && src[i + 1] <= 0xDFFF)
				cp = 0x10000 + ((cp - 0xD800) << 10) + (src[++i] - 0xDC00);
			else
				cp = UTF_REPLACEMENT; /* high surrogate with no low to pair */
		} else if (cp >= 0xDC00 && cp <= 0xDFFF) {
			cp = UTF_REPLACEMENT; /* low surrogate with no preceding high */
		}

		if (cp < 0x80) {
			len = 1;
			buf[0] = (unsigned char)cp;
		} else if (cp < 0x800) {
			len = 2;
			buf[0] = (unsigned char)(0xc0 | (cp >> 6));
			buf[1] = (unsigned char)(0x80 | (cp & 0x3f));
		} else if (cp < 0x10000) {
			len = 3;
			buf[0] = (unsigned char)(0xe0 | (cp >> 12));
			buf[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3f));
			buf[2] = (unsigned char)(0x80 | (cp & 0x3f));
		} else {
			len = 4;
			buf[0] = (unsigned char)(0xf0 | (cp >> 18));
			buf[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3f));
			buf[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3f));
			buf[3] = (unsigned char)(0x80 | (cp & 0x3f));
		}

		if (dst && out + (ULONG)len > dstbytes) {
			if (written) *written = out;
			return -1;
		}
		if (dst) memcpy(dst + out, buf, (size_t)len);
		out += (ULONG)len;
	}
	if (written) *written = out;
	return 0;
}

withtok(internal_heap_allocated)
WCHAR *__utf8_to_utf16(const char *s, size_t *wlen)
{
	size_t length = strlen(s), allocation;
	ULONG inlen, outlen = 0;
	WCHAR *w;

	/* UTF-16 is never longer in code units than UTF-8 is in bytes. */
	if (!__utf8_to_utf16_allocation(length, &allocation)) {
		errno = EOVERFLOW;
		return 0;
	}
	inlen = (ULONG)length;
	w = __malloc(allocation);
	if (!w) { errno = ENOMEM; return 0; }
	if (inlen) {
		/* Buffer-too-small can't actually happen here given the sizing
		 * claim above, but if it ever did, EILSEQ is what this call site
		 * has always reported for any conversion failure -- unlike
		 * __utf16_to_utf8_buf() below, which has a real, reachable
		 * too-small case and reports it as ERANGE instead. */
		if (utf8_to_utf16n(w, (ULONG)(allocation - sizeof(WCHAR)), &outlen,
		                    s, inlen)) {
			__free(w);
			errno = EILSEQ;
			return 0;
		}
	}
	w[outlen / sizeof(WCHAR)] = 0;
	if (wlen) *wlen = outlen / sizeof(WCHAR);
	return w;
}

int __utf16_to_utf8_buf(const WCHAR *w, size_t n, char *out, size_t outsz)
{
	ULONG outlen = 0;
	size_t input_bytes;

	if (!outsz) { errno = ERANGE; return -1; }
	if (!__utf16_input_bytes(n, &input_bytes) || outsz - 1 > UINT32_MAX) {
		errno = EOVERFLOW;
		return -1;
	}
	if (n) {
		if (utf16_to_utf8n(out, (ULONG)(outsz - 1), &outlen, w,
		                    (ULONG)input_bytes)) {
			errno = ERANGE;
			return -1;
		}
	}
	out[outlen] = 0;
	return (int)outlen;
}

withtok(internal_heap_allocated)
char *__utf16_to_utf8(const WCHAR *w, size_t n)
{
	/* UTF-8 is at most 3 bytes per UTF-16 code unit (4 per surrogate pair,
	 * which is two units). */
	size_t cap;
	if (!__utf16_to_utf8_capacity(n, &cap)) { errno = EOVERFLOW; return 0; }
	char *s = __malloc(cap);
	if (!s) { errno = ENOMEM; return 0; }
	if (__utf16_to_utf8_buf(w, n, s, cap) < 0) { __free(s); return 0; }
	return s;
}

// NOLINTEND(misc-include-cleaner)
