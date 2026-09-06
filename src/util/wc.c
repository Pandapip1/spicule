/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * wc(1p): `wc [-c|-m] [-l] [-w] [file...]`
 *
 * DESCRIPTION: "The wc utility shall read one or more input files and,
 * by default, write the number of <newline> characters, words, and
 * bytes contained in each input file to the standard output."  "When any
 * option is specified, wc shall report only the information requested by
 * the specified options" -- but always in the fixed newlines/words/
 * bytes-or-chars column order below, never the order the options were
 * given on the command line.
 *
 * OPTIONS: -l newlines, -w words ("a non-zero-length string of
 * characters delimited by white space" -- classified here with
 * isspace() on each raw byte; every ASCII whitespace character is a
 * single UTF-8 byte and no UTF-8 continuation or lead byte ever falls in
 * isspace()'s range, so this is exact for UTF-8 input regardless of
 * whether -m's multibyte decoding below is in play), -c bytes, -m
 * characters.  SYNOPSIS pairs -c and -m as mutually exclusive
 * (`[-c|-m]`); combining them is a usage error here rather than a silent
 * "last one wins".
 *
 * ---- -m is a real, distinct count here, not -c under another name ----
 *
 * Unlike touch's -d (refused outright, see that file's header) or -u for
 * cat (accepted as a no-op because there is truly nothing left for it to
 * disable), -m has a real multibyte decode path to stand on:
 * src/stdlib/mbrtowc.c is a genuine, stateful UTF-8 decoder, already
 * exercised by this library's own wide-character stdio path
 * (src/stdio/wide.c) and src/misc/langinfo.c's own comment that "UTF-8
 * is the only encoding this library has ever supported" -- there is no
 * locale switch that changes that, so decoding as UTF-8 unconditionally
 * is exactly this platform's own answer to "the current locale", not a
 * shortcut around it.  count_chars() below drives mbrtowc() directly,
 * carrying a partial trailing sequence across successive read() blocks
 * in `carry`, the same "don't assume a decode boundary lines up with a
 * read() boundary" concern src/misc/iconv.c's own stream conversion has
 * to handle.
 *
 * A byte sequence mbrtowc() rejects (return (size_t)-1) is counted as
 * one character and skipped one byte at a time, and a sequence still
 * incomplete at end-of-file is likewise counted one byte at a time --
 * matching common wc practice of never losing count of trailing bytes
 * to an encoding error, at the cost of not distinguishing "malformed" in
 * the character count itself (wc(1p) has no separate diagnostic for
 * that case to report).
 *
 * mbrtowc()'s (size_t)-3 return ("no bytes consumed, wide character
 * produced from state alone") is this decoder's own way of splitting a
 * non-BMP UTF-8 sequence into a UTF-16 surrogate pair (src/stdlib/
 * mbrtowc.c's header comment) -- both halves are one Unicode character,
 * so only the call that actually consumed bytes (the high surrogate)
 * counts; the trailing -3 drain call is not a second character.
 *
 * OPERANDS: "If no file operands are specified, the standard input shall
 * be used."  STDOUT: `"%d %d %d %s\n", <newlines>, <words>, <bytes>,
 * <file>` for the default case, with the -m count replacing <bytes>
 * when -m is given, no pathname printed at all for the implicit-stdin
 * case (matching every wc this project has to interoperate with -- the
 * standard's own format string is silent on that case, since STDOUT
 * describes the per-file line), and a final "total" line, spelled
 * exactly like a pathname, when more than one file operand is given.
 *
 * EXIT STATUS: "0 Successful completion." ">0 An error occurred." --
 * diagnose-and-continue across operands, same shape as this project's
 * other utilities: one unreadable operand does not stop the rest from
 * being counted, and the final exit status is still nonzero.  A failed
 * operand contributes nothing to the totals line, the same as it
 * contributes no line of its own.
 *
 * Spec consulted: https://pubs.opengroup.org/onlinepubs/9699919799/utilities/wc.html
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <wchar.h>
#include <fcntl.h>
#include <unistd.h>
#include "util.h"

struct wc_counts {
	long long lines;
	long long words;
	long long bytes_or_chars;
};

static int add_count(long long *count, long long amount)
{
	if (*count < 0 || amount < 0 ||
	    (unsigned long long)*count >
	        (unsigned long long)LLONG_MAX - (unsigned long long)amount) {
		errno = EOVERFLOW;
		return -1;
	}
	*count = (long long)((unsigned long long)*count +
	                     (unsigned long long)amount);
	return 0;
}

/* Reads all of `fd`, filling `out` with exactly the newline/word/
 * byte-or-character counts count_stream() was asked for (`want_chars`
 * selects mbrtowc()-based character counting for the third field
 * instead of a raw byte count -- see this file's header on why that is
 * a real distinction here).  Returns 0 on success, -1 (with a
 * diagnostic already written) on a read failure partway through. */
static int count_stream(int fd, int want_chars, struct wc_counts *out, const char *label) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	unsigned char buf[65536];
	unsigned char carry[8];
	size_t carry_len = 0;
	mbstate_t mbs;
	int in_word = 0;
	ssize_t n;

	memset(&mbs, 0, sizeof mbs);
	memset(out, 0, sizeof *out);

	while ((n = read(fd, buf, sizeof buf)) > 0) {
		ssize_t i;

		for (i = 0; i < n; i++) {
			unsigned char ch = buf[i];
			if (ch == '\n') out->lines++;
			if (isspace(ch)) {
				in_word = 0;
			} else if (!in_word) {
				in_word = 1;
				out->words++;
			}
		}

		if (!want_chars) {
			out->bytes_or_chars += n;
			continue;
		}

		{
			unsigned char tmp[sizeof buf + sizeof carry];
			size_t tmplen = carry_len;
			size_t pos = 0;

			memcpy(tmp, carry, carry_len);
			memcpy(tmp + carry_len, buf, (size_t)n);
			tmplen += (size_t)n;

			while (pos < tmplen) {
				wchar_t wc;
				size_t r = mbrtowc(&wc, (char *)tmp + pos, tmplen - pos, &mbs);

				if (r == (size_t)-2) {
					/* Incomplete sequence with no more input
					 * yet this read() -- carry the rest to
					 * the next block. */
					break;
				}
				if (r == (size_t)-3) {
					/* Trailing half of a surrogate pair:
					 * already counted on the call that
					 * consumed the encoding's bytes. */
					continue;
				}
				if (r == (size_t)-1) {
					/* Invalid byte: counts as one
					 * character, resync one byte at a
					 * time. */
					out->bytes_or_chars++;
					pos++;
					memset(&mbs, 0, sizeof mbs);
					continue;
				}
				/* r == 0 (embedded NUL, one byte consumed) or
				 * the real byte length of a decoded
				 * character: either way, one character. */
				out->bytes_or_chars++;
				pos += (r == 0) ? 1 : r;
			}

			carry_len = tmplen - pos;
			if (carry_len > sizeof carry) carry_len = sizeof carry; /* cannot happen: max is MB_CUR_MAX-1 */
			memmove(carry, tmp + pos, carry_len);
		}
	}
	if (n < 0) {
		__util_diagf("wc: %s: %s\n", label, strerror(errno));
		return -1;
	}
	if (want_chars && carry_len > 0) {
		/* A sequence still incomplete at EOF: count what is left
		 * one byte at a time rather than silently dropping it. */
		if (add_count(&out->bytes_or_chars, (long long)carry_len) < 0) {
			__util_diagf("wc: %s: %s\n", label, strerror(errno));
			return -1;
		}
	}
	return 0;
}

static void print_counts(const struct wc_counts *c, int want_l, int want_w, int want_bc, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
                          const char *name)
{
	int first = 1;

	if (want_l) { printf("%s%lld", first ? "" : " ", c->lines); first = 0; }
	if (want_w) { printf("%s%lld", first ? "" : " ", c->words); first = 0; }
	if (want_bc) { printf("%s%lld", first ? "" : " ", c->bytes_or_chars); first = 0; }
	if (name) printf("%s%s", first ? "" : " ", name);
	printf("\n");
}

int __util_wc_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i;
	int opt_c = 0, opt_m = 0, opt_l = 0, opt_w = 0;
	int want_l, want_w, want_bc, want_chars;
	int had_error = 0;
	struct wc_counts total;
	int noperands = 0;

	for (i = 1; i < argc; i++) {
		char *a = argv[i];
		char *p;

		if (a[0] != '-' || a[1] == 0) break;
		if (!strcmp(a, "--")) { i++; break; }
		for (p = a + 1; *p; p++) {
			if (*p == 'c') { opt_c = 1; continue; }
			if (*p == 'm') { opt_m = 1; continue; }
			if (*p == 'l') { opt_l = 1; continue; }
			if (*p == 'w') { opt_w = 1; continue; }
			__util_diagf("wc: invalid option -- '%c'\n", *p);
			return 1;
		}
	}
	if (opt_c && opt_m) {
		__util_diagf("wc: -c and -m are mutually exclusive\n");
		return 1;
	}

	if (!opt_c && !opt_m && !opt_l && !opt_w) {
		want_l = want_w = want_bc = 1;
	} else {
		want_l = opt_l;
		want_w = opt_w;
		want_bc = opt_c || opt_m;
	}
	want_chars = opt_m;

	memset(&total, 0, sizeof total);

	if (i >= argc) {
		struct wc_counts c;
		if (count_stream(STDIN_FILENO, want_chars, &c, "standard input") < 0)
			return 1;
		print_counts(&c, want_l, want_w, want_bc, 0);
		return 0;
	}

	noperands = argc - i;

	for (; i < argc; i++) {
		const char *path = argv[i];
		struct wc_counts c;
		int fd;

		if (!strcmp(path, "-")) {
			if (count_stream(STDIN_FILENO, want_chars, &c, "-") < 0) {
				had_error = 1;
				continue;
			}
		} else {
			fd = open(path, O_RDONLY);
			if (fd < 0) {
				__util_diagf("wc: %s: %s\n", path, strerror(errno));
				had_error = 1;
				continue;
			}
			if (count_stream(fd, want_chars, &c, path) < 0) {
				(void)close(fd);
				had_error = 1;
				continue;
			}
			(void)close(fd);
		}
		print_counts(&c, want_l, want_w, want_bc, path);
		if (add_count(&total.lines, c.lines) < 0 ||
		    add_count(&total.words, c.words) < 0 ||
		    add_count(&total.bytes_or_chars, c.bytes_or_chars) < 0) {
			__util_diagf("wc: total: %s\n", strerror(errno));
			return 1;
		}
	}

	if (noperands > 1) print_counts(&total, want_l, want_w, want_bc, "total");

	return had_error ? 1 : 0;
}

// NOLINTEND(misc-include-cleaner)
