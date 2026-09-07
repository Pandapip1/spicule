/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * src/time/strptime.c: a format-driven parser whose conversion table
 * (read_num, match_name, the %z and composite-expansion cases) is
 * exactly where a freshly extended switch hides an out-of-bounds read or
 * an infinite/quadratic recursion (%c, %D/%x, %F, %r, %R, %T/%X all
 * recurse into parse() with a substituted format).
 *
 * Both axes the parser has -- the format string and the input being
 * matched against it -- need to vary independently, so one fuzzer input
 * is split into two NUL-terminated buffers at the first 0x00 byte:
 * everything before it is the format, everything after is the input. A
 * raw byte stream with no separator gives an empty input and the whole
 * thing as format, which still exercises the parser without wasting a
 * byte on a dedicated length prefix.
 *
 * No host oracle: glibc's strptime accepts locale-dependent names and a
 * superset of conversions (E/O modifiers, %s, week-number fields that DO
 * feed back into tm on some platforms) that spicule's deliberately does
 * not implement, so a differential comparison would be mostly noise.
 * This is a crash/UB/OOB check under ASan+UBSan, plus a couple of
 * invariants strptime's own contract guarantees regardless of locale.
 */
#include <time.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	char fmt[256], input[256];
	size_t i, flen, ilen;
	struct tm tm;
	char *end;

	for (i = 0; i < size && i < sizeof fmt - 1 && data[i]; i++) ;
	flen = i;
	memcpy(fmt, data, flen);
	fmt[flen] = 0;

	if (i < size) i++;                      /* skip the separating NUL */
	ilen = size - i < sizeof input - 1 ? size - i : sizeof input - 1;
	memcpy(input, data + i, ilen);
	input[ilen] = 0;
	if (memchr(input, 0, ilen)) return 0;    /* embedded NUL: not one string */

	memset(&tm, 0xaa, sizeof tm);            /* poison: catch reads of unset fields */
	end = strptime(input, fmt, &tm);
	if (end) {
		/* strptime's contract: the return is always inside, or at the
		 * end of, the input it was given -- never before it and never
		 * past its NUL. */
		if (end < input || end > input + ilen)
			__builtin_trap();
	}

	return 0;
}
