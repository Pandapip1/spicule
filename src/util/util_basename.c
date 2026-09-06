/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Named util_basename.c, not basename.c: tools/linkcheck.sh caught that
 * tcc's `ar` truncates a member name to its basename's first 15 bytes
 * (no directory component), so this file and src/misc/basename.c --
 * genuinely different translation units, one the basename(1p) utility,
 * one the basename(3) library function it calls -- would both produce
 * an object literally named basename.o and silently shadow each other
 * inside lib/libc.a.  The util_ prefix is this file's whole fix; the
 * exported symbol stays __util_basename_main() either way.
 *
 * basename(1p).  SYNOPSIS: "basename string [suffix]".  DESCRIPTION: the
 * suffix step, taken literally -- "If the suffix operand is present, is
 * not identical to the characters remaining in string, and is identical
 * to a suffix of the characters remaining in string, the suffix suffix
 * shall be removed from string."  STDOUT: "%s\n".
 *
 * The pathname-component stripping itself is basename() (src/misc/
 * basename.c), not reimplemented here -- but that function's contract is
 * worth stating rather than assuming: it takes a non-const `char *s`,
 * both mutates it in place (trailing separators are overwritten with
 * NUL) and may return `s` itself, a pointer into the middle of it, or a
 * pointer to a static "." for the degenerate cases.  argv[1] is passed
 * straight through -- utility argv strings are this process's own
 * writable memory for its own lifetime, the same assumption every real
 * basename(1) implementation makes, and mutating it is harmless because
 * nothing here reads argv[1] again afterwards.
 */
#include <string.h>
#include <stdio.h>
#include <libgen.h>
#include "util.h"

int __util_basename_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	char *base;
	size_t blen, slen;

	if (argc < 2 || argc > 3) {
		__util_diagf("basename: usage: basename string [suffix]\n");
		return 2;
	}

	base = basename(argv[1]);
	if (argc == 3) {
		const char *suffix = argv[2];
		blen = strlen(base);
		slen = strlen(suffix);
		/* "is not identical to the characters remaining" (slen < blen,
		 * not <=) "and is identical to a suffix of" them. */
		if (slen > 0 && slen < blen && !strcmp(base + (blen - slen), suffix))
			base[blen - slen] = 0;
	}

	if (fputs(base, stdout) < 0 || fputc('\n', stdout) == EOF) return 1;
	return fflush(stdout) == 0 ? 0 : 1;
}
