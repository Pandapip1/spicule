/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Proof that an *unmodified* program -- a plain `extern` declaration,
 * an ordinary call site, nothing spicule-specific at the call site at
 * all -- gets $ORIGIN-relative delay loading when built with
 * -Wl,--delay-all, through the linker-generated thunks and
 * __delayLoadHelper2 (crt/delayload2.c), not through
 * include/spicule/delayload.h's hand-authored SPICULE_DELAY_STUB macros
 * (that facility is exercised separately by test/rpath.c). This is the
 * only spicule-specific thing this file contains: the well-known
 * __rpath array rpath.h documents every delay-loading program defining
 * regardless of which of the two mechanisms it uses -- a plain data
 * declaration, not a macro or a wrapper call.
 *
 * Only built and run when `./configure` detected linker support for
 * --delay-all (see configure's "checking whether linker accepts
 * -Wl,--delay-all" and the Makefile's DELAY_ALL-gated rules): the
 * stock TinyCC CI's build-toolchain job checks out does not have this
 * flag, so this test does not exist in that build at all rather than
 * fail to link there.
 *
 * delayall_check (test/delayall-plugin-src/delayall-plugin.c) takes
 * four ints and two doubles and asserts every one, so a thunk that
 * clobbers a register or misaligns the stack corrupts an argument and
 * fails loudly. Called twice: the first call resolves the DLL and the
 * symbol and patches the delay IAT slot; the second call exercises
 * that already-patched slot (see crt/delayload2.c's header comment on
 * why the generated tail-merge stub calls __delayLoadHelper2 on every
 * call regardless, and how the range-check fast path there answers it
 * cheaply).
 */
#ifndef _WIN32
#error "delayall.c is NT-only (exercises the -Wl,--delay-all delay-load path); see crt/delayload2.c"
#endif
#include <stdio.h>

/* $ORIGIN semantics (rpath.h): "." is the image's own directory, where
 * the Makefile places delayall-plugin.dll right alongside this .exe. */
const char *const __rpath[] = { ".", 0 };

/* No SPICULE_DELAY_DLL/SPICULE_DELAY_STUB, no spicule/delayload.h at all --
 * exactly the extern declaration an unmodified program would write for
 * a function it expects to find in some DLL. */
extern int delayall_check(int a, int b, int c, int d, double e, double f);

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

int main(int argc, char **argv)
{
	int r1, r2;

	/* ---- first call: resolves delayall-plugin.dll from $ORIGIN and
	 * delayall_check within it, then patches the delay IAT slot ------ */
	r1 = delayall_check(11, 22, 33, 44, 55.5, 66.25);
	CHECK(r1 == 42);

	/* ---- second call: through the now-patched slot ------------------ */
	r2 = delayall_check(11, 22, 33, 44, 55.5, 66.25);
	CHECK(r2 == 42);

	/* ---- nothing about using this facility disturbs ordinary state -- */
	CHECK(argc >= 1);
	CHECK(argv != 0 && argv[0] != 0);

	if (!fails) printf("PASS\n");
	return fails ? 1 : 0;
}
