/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * wcsftime(): https://pubs.opengroup.org/onlinepubs/9699919799/functions/wcsftime.html
 * DESCRIPTION, RETURN VALUE -- "equivalent to strftime(), except that
 * ... the argument format is a wide-character string [and] the output
 * ... is a wide-character string", returning "the number of
 * wide-character codes placed into the array" when the result including
 * the terminating null fits in maxsize, and 0 otherwise.
 *
 * WHY THIS IS NOT "strftime() INTO A BUFFER, THEN WIDEN".  That obvious
 * shape has two problems.  strftime()'s bound is a BYTE count and
 * wcsftime()'s is a WIDE-CHARACTER count, and under UTF-8 those differ
 * for any non-ASCII output (%Z with a non-ASCII zone name is the live
 * case here, since src/time/strftime.c takes %Z straight from
 * tm->__tm_zone), so no fixed byte budget corresponds to the caller's
 * maxsize.  Sizing around that means either allocating -- which a
 * function with no error return cannot report the failure of -- or
 * over-allocating 4x on the stack for a caller-chosen maxsize.
 *
 * Instead this walks the wide format itself and calls strftime() once
 * per conversion specifier, which is musl's approach and has three
 * properties worth having: literal characters in the format never go
 * through a conversion at all (they are already wchar_t and are copied
 * as such, so a non-ASCII literal cannot be mangled by a round trip);
 * the wide-character count is exact at every step, so the maxsize test
 * is the one POSIX specifies rather than a byte-count proxy; and the
 * only buffer needed is one big enough for a single expanded specifier,
 * which is a fixed size rather than a function of maxsize.
 *
 * The grammar deliberately mirrors src/time/strftime.c, with one
 * KNOWN GAP rather than an exact match: '%' followed by one character
 * is handed to strftime() as a two-byte format ("%<c>"), so an %E/%O
 * pair never reaches it intact.  strftime() itself DOES fall back %E<x>
 * and %O<x> to plain %<x> (strftime.html: "the behavior shall be as if
 * the unmodified conversion specification were used" when no alternate
 * form exists, which is always true in the C-only locale this target
 * has) -- but only when it sees both characters at once, and this file
 * sends 'E'/'O' alone, one wide character at a time, so strftime()'s
 * fallback never triggers here: it gets "%E" with nothing after it,
 * emits that literally via its `default:` arm, and this file's own
 * loop then emits the following character (the 'C' in "%EC") as an
 * unrelated literal on the next iteration -- the exact bug strftime.c
 * itself used to have, un-fixed here.  Widening this loop to detect
 * E/O and forward two characters at once would close it; that has not
 * been done, so %E/%O are still broken specifically through wcsftime(),
 * unlike through strftime() -- and a trailing '%' at the end of the
 * format is dropped, matching that file's `if (!*f) break;`.
 *
 * A format specifier whose letter is not a single-byte character cannot
 * be spelled in strftime()'s byte format at all.  strftime()'s own
 * answer for an unrecognised specifier is to emit '%' and the character
 * literally, so that is what happens here, with the character emitted
 * as the wchar_t it already is.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <wchar.h>
#include <time.h>
#include <string.h>

/* Room for one expanded conversion specifier.  The largest this
 * library's strftime() can produce is %c (a full date-and-time string,
 * about 25 bytes) or %Z, whose length is that of tm->__tm_zone -- an NT
 * time-zone display name, which the registry caps well under 128
 * characters.  512 is therefore not a guess at a typical size but a
 * bound with an order of magnitude of headroom, and the strftime()
 * return is still checked rather than assumed. */
#define SPEC_MAX 512

size_t wcsftime(wchar_t *__restrict s, size_t n, const wchar_t *__restrict f,
                const struct tm *__restrict tm)
{
	size_t pos = 0;
	char fmt[3], out[SPEC_MAX];

	/* Store one wide character, failing the whole call if it (or the
	 * terminating null that must follow it) would not fit.  POSIX gives
	 * no truncating behaviour: it is all or nothing. */
#define PUT_WC(c) do { if (pos + 1 >= n) return 0; s[pos++] = (wchar_t)(c); } while (0)

	for (; *f; f++) {
		const char *p;
		size_t left, r;
		mbstate_t st;

		if (*f != L'%') { PUT_WC(*f); continue; }
		f++;
		if (!*f) break;			/* trailing '%': dropped, as strftime does */
		if (*f > 0x7f) {		/* not spellable as a byte specifier */
			PUT_WC(L'%');
			PUT_WC(*f);
			continue;
		}
		fmt[0] = '%'; fmt[1] = (char)*f; fmt[2] = 0;
		r = strftime(out, sizeof out, fmt, tm);
		if (!r) {
			/* strftime() answers 0 both for "did not fit" and for an
			 * expansion of length zero, and no specifier this library
			 * implements expands to nothing -- so with SPEC_MAX bytes
			 * this is unreachable in practice.  Handled rather than
			 * asserted because either way there is nothing to append,
			 * and wcsftime() has no return value with which to report
			 * an error that is not "did not fit in maxsize". */
			continue;
		}

		/* Append the expansion, converting bytes to wide characters.
		 * mbrtowc() is used rather than mbstowcs() so the count is
		 * bounded by the caller's maxsize at every unit, and so a
		 * supplementary character -- two wchar_t from four bytes, the
		 * second delivered from state alone as (size_t)-3 -- is
		 * appended as both halves. */
		p = out; left = r;
		memset(&st, 0, sizeof st);
		for (;;) {
			if (!left && mbsinit(&st)) break;
			wchar_t wc = 0;
			size_t used, k = mbrtowc(&wc, p, left, &st);

			if (k == (size_t)-3) used = 0;
			else if (k == 0) used = 1;	/* an embedded null byte */
			else if (k == (size_t)-1 || k == (size_t)-2) return 0;
			else used = k;
			PUT_WC(wc);
			p += used; left -= used;
		}
	}

	if (pos >= n) return 0;
	s[pos] = 0;
	return pos;

#undef PUT_WC
}

// NOLINTEND(misc-include-cleaner)
