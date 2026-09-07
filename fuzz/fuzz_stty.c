/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Fuzzes __util_stty_main()'s (src/util/stty.c) `stty [-a|-g] |
 * operand...` argument parser.
 *
 * Same NUL-delimited tokenized-argv shape as fuzz_expr.c/fuzz_test.c:
 * stty's grammar is a flat operand list with no separate lexer, so
 * every token after the fixed argv[0]="stty" becomes one argv element,
 * and two-token operands (ispeed N, ...) need no special handling. No
 * byte is reserved for invocation shape (unlike fuzz_test.c) since bare
 * `stty`, `-a`/`-g`, and their "may not be combined" rejection all fall
 * out of ordinary tokenization. parse_saved()'s 22-hex-field "saved
 * settings" success path is left to the fuzzer's corpus rather than
 * synthesized here.
 *
 * SAFETY: real fd 0 is forced to /dev/null before __util_stty_main() is
 * ever called. __util_stty_main() hard-codes fd 0 in every
 * tcgetattr(0,...)/tcsetattr(0,...) call, and neither spicule termios
 * backend is actually linked into this build (src/termios/termios.c is
 * __linux__-guarded out, and the Linux backend is skipped by
 * asan-build.sh's file selection) -- so those calls resolve to the
 * host's real, dynamically-linked glibc instead. Unforced, that would
 * (a) mutate a real terminal's settings if real fd 0 happens to be one,
 * and (b) on success write glibc's larger struct termios (NCCS==32)
 * through a pointer declared with spicule's own smaller one (NCCS==16),
 * a real stack buffer overrun. force_stdin_devnull() below reaches the
 * host's syscall(2) directly (fd 0 is real hardware here, not
 * fuzz/ntstubs.c's simulated volume) to dup2() /dev/null onto it once,
 * before any fuzzed argv is processed.
 *
 * With fd 0 pinned to /dev/null, tcgetattr/tcsetattr always fail ENOTTY
 * untouched, and __util_stty_main() has no `return 2` path and returns
 * 0 only right after a successful tcgetattr/tcsetattr -- so the only
 * value it can legitimately return here is 1, which is the oracle
 * below asserts (stty.html itself only requires "0 or nonzero").
 *
 * Separately: src/ioctl/ioctl.c references __plat_tiocgwinsz, which
 * nothing in this build provides, breaking the link of every harness in
 * fuzz/Makefile's HARNESSES list regardless of whether it calls
 * ioctl() -- so this harness cannot actually be linked in this sandbox
 * today either way.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../src/internal/util.h"

extern void oracle_mismatch_i(const char *, const char *, long long, long long);
extern long syscall(long number, ...);

#define CAP_TOKENS 16
#define CAP_SCRATCH 512
#define ROOT "/tmp/sttyfz"

/* x86_64, matching fuzz/ntstubs.c's own SYS_openat=257. */
#define SYS_OPENAT 257
#define SYS_DUP2   33
#define SYS_CLOSE  3

/* Once per process (stty never itself opens/closes/repoints fd 0, only
 * queries/changes its mode). Returns 0 if this could not be arranged,
 * in which case the caller must not call __util_stty_main() this run. */
static int force_stdin_devnull(void)
{
	static int state; /* 0 untried, 1 ok, -1 permanently failed */
	long devnull, dr;

	if (state) return state > 0;

	devnull = syscall(SYS_OPENAT, -100 /* AT_FDCWD */, "/dev/null", 0 /* O_RDONLY */, 0);
	if (devnull < 0) { state = -1; return 0; }
	dr = syscall(SYS_DUP2, devnull, 0);
	syscall(SYS_CLOSE, devnull);
	state = (dr == 0) ? 1 : -1;
	return state > 0;
}

static int redirect_streams(void)
{
	if (!freopen(ROOT "/out", "w", stdout)) return 0;
	if (!freopen(ROOT "/err", "w", stderr)) return 0;
	return 1;
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	char scratch[CAP_SCRATCH];
	char argv0[] = "stty";
	char *argv[CAP_TOKENS + 2];
	int argc = 1;
	size_t si = 0, wi = 0;
	int rc;

	if (!force_stdin_devnull()) return 0;

	mkdir(ROOT, 0755);
	if (!redirect_streams()) return 0;

	argv[0] = argv0;

	while (si < size && argc < CAP_TOKENS + 1 && wi < CAP_SCRATCH - 1) {
		size_t start = wi;

		while (si < size && data[si] != 0 && wi < CAP_SCRATCH - 1)
			scratch[wi++] = (char)data[si++];
		scratch[wi++] = 0;
		argv[argc++] = &scratch[start];

		if (si < size && data[si] == 0) si++;   /* consume the delimiter itself */
	}
	argv[argc] = NULL;

	rc = __util_stty_main(argc, argv);
	fflush(stdout);
	fflush(stderr);
	if (rc != 1)
		oracle_mismatch_i("__util_stty_main returned something other than 1 "
		                  "with stdin forced to /dev/null",
		                  argc > 1 ? argv[argc - 1] : "", rc, 1);

	return 0;
}
