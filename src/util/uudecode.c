/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * uudecode(1p): reads a uuencoded file (or stdin) and recreates the
 * original file, including its mode.
 *
 * SYNOPSIS: `uudecode [-o outfile] [file]` (-o: use outfile instead of
 * the pathname named inside the file).
 *
 * Parsing mirrors src/util/uuencode.c's format exactly: leading lines
 * before "begin mode filename" are skipped -- historical mail transports
 * prepend headers, and uudecode has always tolerated that; no such line
 * at all is a diagnosed error. mode is parsed as octal; filename is the
 * rest of the line after the mode field, so a filename with spaces still
 * reads correctly. Each data line's first character is a length
 * (src/util/uucode.h's UUDEC()); a length of 0 ends the data and must be
 * followed by a line reading "end" -- anything else (including EOF) is a
 * truncated-stream error. Every data character is checked with
 * uu_valid_char() first: anything outside the uuencoding alphabet is a
 * diagnosed error immediately, never decoded into a plausible-looking
 * wrong byte.
 *
 * The output file's mode is chmod()'d after it's fully written, to the
 * octal value from the begin line masked to the permission bits (07777,
 * same mask as src/util/modeparse.h) -- applied even under -o, since -o
 * only changes where the file goes, not what mode it gets.
 *
 * No path sanitization is applied to the header's filename or -o's
 * value; used as given, the same trust model src/util/rm.c's/cp.c's own
 * pathname operands already have.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/stat.h>
#include "util.h"
#include "uucode.h"

static size_t chomp(char *s, size_t n)
{
	while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[--n] = 0;
	return n;
}

/* Shared cleanup for early-exit failure paths below: closes `in` if it
 * came from a real path (not stdin), and always returns 1. Caller has
 * already written the diagnostic. */
static int uudecode_fail_in(const char *in_path, FILE *in)
{
	if (in_path) (void)fclose(in);
	return 1;
}

/* Decodes one data line (`have` bytes, already chomped) into `out`, up to
 * `n` real bytes (uuencode.c's own length prefix, parsed by the caller).
 * Returns 0 on success, -1 (diagnostic already written) on a malformed
 * or truncated line. */
static int decode_line(const char *prog, const char *line, size_t have,
                       unsigned n, FILE *out) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	size_t needed = ((size_t)n + 2) / 3 * 4;
	size_t pos, written = 0;

	if (have < needed) {
		/* size_t here is this tree's "unsigned _Addr", which a bare 'z'
		 * length modifier doesn't name on an LP64 host; __util_diagf has
		 * a real format(printf) attribute (see dd.c's identical fix), so
		 * cast to uintmax_t and use PRIuMAX. */
		__util_diagf("%s: truncated data line (need %" PRIuMAX " characters, got %" PRIuMAX ")\n",
			prog, (uintmax_t)needed, (uintmax_t)have);
		return -1;
	}

	for (pos = 0; pos < needed; pos += 4) {
		char c1 = line[pos], c2 = line[pos + 1], c3 = line[pos + 2], c4 = line[pos + 3];
		unsigned char outbuf[3];
		size_t take;

		if (!uu_valid_char(c1) || !uu_valid_char(c2) || !uu_valid_char(c3) || !uu_valid_char(c4)) {
			__util_diagf("%s: invalid character in uuencoded data\n", prog);
			return -1;
		}
		{
			int d1 = UUDEC(c1), d2 = UUDEC(c2), d3 = UUDEC(c3), d4 = UUDEC(c4);
			outbuf[0] = (unsigned char)(((unsigned)d1 << 2) | (unsigned)d2 >> 4);
			outbuf[1] = (unsigned char)(((unsigned)(d2 & 0xf) << 4) | (unsigned)d3 >> 2);
			outbuf[2] = (unsigned char)(((unsigned)(d3 & 0x3) << 6) | (unsigned)d4);
		}
		take = n - written;
		if (take > 3) take = 3;
		if (fwrite(outbuf, 1, take, out) != take) {
			__util_diagf("%s: write error: %s\n", prog, strerror(errno));
			return -1;
		}
		written += take;
	}
	return 0;
}

int __util_uudecode_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i = 1;
	const char *out_override = 0, *in_path = 0;
	FILE *in, *out;
	char line[1024];
	int found_begin = 0, terminated = 0, status = 0;
	unsigned long mode_val;
	char *p, *end;
	const char *filename, *outname;

	for (; i < argc; i++) {
		if (argv[i][0] != '-' || !argv[i][1]) break;
		if (!strcmp(argv[i], "--")) { i++; break; }
		if (!strcmp(argv[i], "-o")) {
			if (i + 1 >= argc) { __util_diagf("uudecode: -o: option requires an argument\n"); return 1; }
			out_override = argv[++i];
			continue;
		}
		__util_diagf("uudecode: %s: invalid option\n", argv[i]);
		return 1;
	}
	if (i < argc) in_path = argv[i++];
	if (i < argc) { __util_diagf("uudecode: too many operands\n"); return 1; }

	in = in_path ? fopen(in_path, "rb") : stdin;
	if (!in) {
		int saved = errno;
		__util_diagf("uudecode: %s: %s\n", in_path, strerror(saved));
		return 1;
	}

	while (fgets(line, sizeof line, in)) {
		(void)chomp(line, strnlen(line, sizeof line));
		if (!strncmp(line, "begin ", 6)) { found_begin = 1; break; }
	}
	if (!found_begin) {
		__util_diagf("uudecode: %s: no valid \"begin\" line found\n", in_path ? in_path : "stdin");
		return uudecode_fail_in(in_path, in);
	}

	p = line + 6;
	mode_val = strtoul(p, &end, 8);
	if (end == p || *end != ' ') {
		__util_diagf("uudecode: %s: malformed begin line\n", in_path ? in_path : "stdin");
		return uudecode_fail_in(in_path, in);
	}
	while (*end == ' ') end++;
	filename = end;
	if (!*filename) {
		__util_diagf("uudecode: %s: begin line has no filename\n", in_path ? in_path : "stdin");
		return uudecode_fail_in(in_path, in);
	}
	outname = out_override ? out_override : filename;

	out = fopen(outname, "wb");
	if (!out) {
		__util_diagf("uudecode: %s: %s\n", outname, strerror(errno));
		return uudecode_fail_in(in_path, in);
	}

	while (fgets(line, sizeof line, in)) {
		size_t line_len;
		unsigned n;
		line_len = chomp(line, strnlen(line, sizeof line));
		if (!line[0]) continue; /* tolerate a stray blank line between records */
		if (!uu_valid_char(line[0])) {
			__util_diagf("uudecode: %s: invalid length character in data\n", in_path ? in_path : "stdin");
			goto fail;
		}
		n = (unsigned)UUDEC(line[0]);
		if (n == 0) { terminated = 1; break; }
		if (n > 45) {
			__util_diagf("uudecode: %s: data line length %u out of range\n", in_path ? in_path : "stdin", n);
			goto fail;
		}
		if (decode_line("uudecode", line + 1, line_len - 1, n, out) < 0) goto fail;
	}
	if (!terminated) {
		__util_diagf("uudecode: %s: truncated uuencoded stream (no terminator line)\n", in_path ? in_path : "stdin");
		goto fail;
	}
	if (!fgets(line, sizeof line, in)) {
		__util_diagf("uudecode: %s: truncated uuencoded stream (no \"end\" line)\n", in_path ? in_path : "stdin");
		goto fail;
	}
	{
		size_t line_len = chomp(line, strnlen(line, sizeof line));
		if (line_len != 3 || memcmp(line, "end", 3) != 0) {
			__util_diagf("uudecode: %s: missing \"end\" line\n", in_path ? in_path : "stdin");
			goto fail;
		}
	}

	if (fclose(out) < 0) {
		__util_diagf("uudecode: %s: %s\n", outname, strerror(errno));
		return uudecode_fail_in(in_path, in);
	}
	if (in_path && fclose(in) < 0) {
		__util_diagf("uudecode: %s: %s\n", in_path, strerror(errno));
		status = 1;
	}

	if (chmod(outname, (mode_t)(mode_val & 07777)) != 0) {
		__util_diagf("uudecode: %s: chmod: %s\n", outname, strerror(errno));
		status = 1;
	}
	return status;

fail:
	/* Diagnostic already written by the failing step; these closes are
	 * cleanup only. */
	(void)fclose(out);
	if (in_path) (void)fclose(in);
	return 1;
}
