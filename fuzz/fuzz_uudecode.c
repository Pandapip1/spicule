/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * __util_uudecode_main() -- src/util/uudecode.c, uudecode(1p)'s
 * hand-written parser for a classic (non-Base64) uuencoded stream: a
 * "begin mode filename" header, a body of length-prefixed data lines
 * each decoded 4 characters at a time via uu_valid_char()/UUDEC(), a
 * zero-length terminator line, and a mandatory trailing "end" line --
 * plus the chmod() that applies the header's mode bits to the recreated
 * file.
 *
 * Whole input is one file/stdin operand, not tokenized arguments, so
 * there is no separate lexer to fuzz apart from the format parser
 * itself. Every fuzzer byte after the first is written to a file,
 * verbatim, embedded NULs included: uudecode.c reads with fgets() into a
 * fixed 1024-byte line buffer, never assumes a caller-supplied length
 * via strlen(), and chomp()/strnlen() already bound every line access to
 * that buffer regardless of what an embedded NUL does elsewhere.
 *
 * Byte 0 selects whether "-o <fixed path>" is passed. Left off (the
 * majority case), the recreated file's path is *the header's own
 * filename field* -- attacker-controlled and, per uudecode.c's own
 * header comment, not sanitized at all. That's real, in-scope behavior
 * to fuzz, not a harness bug to route around: every open()/fopen()/
 * chmod() here goes through spicule's own I/O, which resolves against
 * fuzz/ntstubs.c's in-process simulated NT volume, not the real host
 * filesystem -- so a header filename like "../../etc/passwd" only ever
 * touches an in-memory tree private to this process. Set, "-o" instead
 * routes the decode through the override path ("-o only replaces where
 * the file goes, not what mode it is supposed to have") -- both code
 * paths matter, so the option bit exists to reach both.
 *
 * INPUT_CAP bytes of the fuzz buffer become the file content; every loop
 * in decode_line()/the data-line loop is bounded by the file's own
 * length, so this is purely an absolute-cost cap, not a runaway-
 * computation one.
 *
 * Only stderr is redirected: every diagnostic path here (no "begin"
 * line, a malformed header, an invalid/truncated data line, a missing
 * "end" line, an unopenable output path) writes via __util_diagf() to
 * stderr, and a malformed stream is the overwhelming common case while
 * fuzzing. This file has no stdout use (read in full), unlike its
 * encode-direction counterpart fuzz_uuencode.c.
 *
 * Checked: a real exit status, never a raw errno or boolean.
 * src/util/uudecode.c's every `return` (read in full) uses exactly 0 or
 * 1 -- uudecode(1p) only distinguishes success from "an error occurred",
 * so 1 is the real upper bound asserted. No exit()/_exit() call anywhere
 * in the file either; libFuzzer's own atexit-based detection is the
 * backstop for that.
 *
 * No oracle beyond that exit-status contract: there is no reference
 * uudecode(1p) this project could differential-test against without this
 * file's own scope narrowings (no Base64 -- that's uuencode(1p)'s -m,
 * refused outright; no "leading mail header" content-sniffing beyond the
 * first line literally starting "begin ") reading as a false mismatch.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../src/internal/util.h"

extern void oracle_mismatch_i(const char *, const char *, long long, long long);

#define ROOT "/tmp/uudecodefz"
#define INPUT_CAP 2048

static void write_file(const char *path, const char *data, size_t len)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return;
	(void)write(fd, data, len);
	close(fd);
}

/* ==== stderr redirection -- see this file's header comment. ============== */

static int redirect_stderr(void)
{
	return freopen(ROOT "/err", "w", stderr) != 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	unsigned opts;
	size_t n;
	int status;
	char *argv[6];
	int argc = 0;
	/* NUL-terminated diagnostic copy for oracle_mismatch_i()'s `in` --
	 * see fuzz_patch.c's identical field for why the raw fuzzer buffer
	 * cannot be handed to it directly (no guaranteed embedded NUL). The
	 * file written below still gets every real byte, embedded NULs
	 * included. */
	char diagbuf[INPUT_CAP + 1];

	if (size < 1) return 0;
	mkdir(ROOT, 0755);

	opts = data[0];
	data++; size--;

	n = size < INPUT_CAP ? size : INPUT_CAP;
	write_file(ROOT "/in", (const char *)data, n);
	memcpy(diagbuf, data, n);
	diagbuf[n] = 0;

	if (!redirect_stderr()) return 0;

	argv[argc++] = (char *)"uudecode";
	if (opts & 0x01) {
		argv[argc++] = (char *)"-o";
		argv[argc++] = (char *)ROOT "/out";
	}
	argv[argc++] = (char *)ROOT "/in";
	argv[argc] = 0;

	status = __util_uudecode_main(argc, argv);
	if (status < 0 || status > 1)
		oracle_mismatch_i("__util_uudecode_main returned outside {0,1}", diagbuf, status, 0);

	fflush(stderr);
	return 0;
}
