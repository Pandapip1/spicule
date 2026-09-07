/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * uuencode(1p): reads source_file (or stdin) and writes a uuencoded
 * version to stdout, for uudecode to reverse.
 *
 * SYNOPSIS: `uuencode [-m] [source_file] decode_pathname`.
 *
 * Format: "begin mode decode_pathname\n" header (mode as three octal
 * digits), then the input in 45-byte chunks, each becoming one line: a
 * length character (src/util/uucode.h's UUENC(n)) followed by
 * ceil(n/3)*4 encoded characters. A short final chunk is zero-padded
 * before encoding, but the length prefix -- not the full group -- is
 * what tells uudecode.c's decoder how many bytes are real. A
 * zero-length line ends the data, followed by a literal "end\n".
 *
 * With no source_file there's no real file to fstat() a mode from, so
 * 0644 is used -- the conventional default every historical uuencode
 * falls back to in that case.
 *
 * -m (Base64) is a distinct algorithm this build doesn't implement;
 * refused with a diagnostic and nonzero exit rather than silently
 * falling back to the historical encoding under a flag that promised
 * something else.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include "util.h"
#include "uucode.h"

static void emit_line(const unsigned char *buf, size_t n)
{
	size_t i;

	putchar(UUENC((unsigned)n));
	for (i = 0; i < n; i += 3) {
		unsigned char b0 = buf[i];
		unsigned char b1 = (i + 1 < n) ? buf[i + 1] : 0;
		unsigned char b2 = (i + 2 < n) ? buf[i + 2] : 0;
		int c1 = (b0 >> 2) & 0x3f;
		int c2 = ((b0 << 4) | (b1 >> 4)) & 0x3f;
		int c3 = ((b1 << 2) | (b2 >> 6)) & 0x3f;
		int c4 = b2 & 0x3f;
		putchar(UUENC(c1));
		putchar(UUENC(c2));
		putchar(UUENC(c3));
		putchar(UUENC(c4));
	}
	putchar('\n');
}

int __util_uuencode_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i = 1;
	const char *src_path = 0, *decode_name;
	FILE *in;
	mode_t mode = 0644; /* traditional stdin-source default -- see header */
	unsigned char buf[45];
	size_t n;
	int noperands;
	int status = 0;

	for (; i < argc; i++) {
		if (argv[i][0] != '-' || !argv[i][1]) break;
		if (!strcmp(argv[i], "--")) { i++; break; }
		if (!strcmp(argv[i], "-m")) {
			__util_diagf("uuencode: -m: Base64 encoding is not supported "
			                "by this build -- see src/util/uuencode.c\n");
			return 1;
		}
		__util_diagf("uuencode: %s: invalid option\n", argv[i]);
		return 1;
	}

	noperands = i < argc ? argc - i : 0;
	if (noperands == 1) {
		decode_name = argv[i];
		in = stdin;
	} else if (noperands == 2) {
		/* Checker gap (ntlibc.ResourceLeak): the fclose()s below are
		 * already gated on this same `src_path` (set right here, never
		 * reassigned) rather than on `in != stdin` -- but the checker
		 * can't prove argv[i], i < argc, is non-null, so it still
		 * explores a (real-world impossible) path where src_path reads
		 * back null and reports the fopen() below as never released. */
		src_path = argv[i];
		decode_name = argv[i + 1];
		in = fopen(src_path, "rb");
		if (!in) {
			__util_diagf("uuencode: %s: %s\n", src_path, strerror(errno));
			return 1;
		}
	} else {
		__util_diagf("uuencode: usage: uuencode [-m] [source_file] decode_pathname\n");
		return 1;
	}

	if (src_path) {
		struct stat st;
		if (fstat(fileno(in), &st) == 0) mode = st.st_mode & 0777;
	}

	printf("begin %03o %s\n", (unsigned)mode, decode_name);

	while ((n = fread(buf, 1, sizeof buf, in)) > 0) emit_line(buf, n);
	if (ferror(in)) {
		__util_diagf("uuencode: %s: %s\n", src_path ? src_path : "stdin", strerror(errno));
		/* The input error is primary; close is cleanup only. */
		if (src_path) (void)fclose(in);
		return 1;
	}

	printf("`\nend\n");
	if (src_path && fclose(in) != 0) status = 1;
	if (fflush(stdout) != 0) status = 1;
	return status;
}
