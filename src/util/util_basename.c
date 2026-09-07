/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Named util_basename.c, not basename.c: tcc's `ar` truncates a member
 * name to its basename's first 15 bytes (see tools/linkcheck.sh), so
 * this file and src/misc/basename.c -- the basename(1p) utility and the
 * basename(3) function it calls, genuinely different translation units
 * -- would both produce an object named basename.o and silently shadow
 * each other in lib/libc.a. The util_ prefix is the whole fix; the
 * exported symbol stays __util_basename_main().
 *
 * basename(1p) SYNOPSIS: "basename string [suffix]". The suffix step,
 * taken literally: "If the suffix operand is present, is not identical
 * to the characters remaining in string, and is identical to a suffix
 * of the characters remaining in string, the suffix shall be removed
 * from string." STDOUT: "%s\n".
 *
 * Pathname stripping itself is basename() (src/misc/basename.c), not
 * reimplemented here. It takes a non-const `char *s`, mutates it in
 * place (trailing separators overwritten with NUL), and may return `s`,
 * a pointer into its middle, or a static "." -- argv[1] is passed
 * straight through since it's this process's own writable memory and
 * nothing here reads it again afterward.
 */
#include <string.h>
#include <stdio.h>
#include <libgen.h>
#include "util.h"
#include "ownership_stubs.h"

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
	/* basename() is an opaque external decl with no ownership contract;
	 * base is a real C string either way (into argv[1], or a static "."). */
	__ownership_string_terminated(base);
	if (argc == 3) {
		const char *suffix = argv[2];
		/* suffix = argv[2]; null-terminated per argv's own contract, but
		 * that token doesn't survive the argv[2] read -- restated. */
		__ownership_string_terminated(suffix);
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
