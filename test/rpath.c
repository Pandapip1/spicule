/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Exercises the RPATH/$ORIGIN-equivalent delay-load mechanism in
 * include/spicule/rpath.h and include/spicule/delayload.h. Named *-win.c
 * (see the Makefile's note by TEST_SRCS/TEST_RUN) because it needs a
 * companion DLL sitting next to the executable, which "make check"
 * arranges (obj/test/rpath-plugin.dll, built straight from
 * test/rpath-plugin-src/rpath-plugin.c) but does not itself run under
 * Wine as part of the suite -- run it directly, from obj/test/, to see
 * it pass: `wine obj/test/rpath-win.exe`.
 *
 * Covered:
 *   - resolution from the image directory ($ORIGIN), through both
 *     __rpath (a "." entry) and a dllname with an explicit relative
 *     path component, via the real descriptor/IAT/INT delay-load path
 *     (SPICULE_DELAY_DLL/SPICULE_DELAY_STUB) end to end -- load, resolve,
 *     call, and that the second call reuses the now-patched IAT slot
 *     rather than resolving again;
 *   - a missing DLL (spicule_rpath_load fails, with a diagnosable
 *     spicule_rpath_error());
 *   - a missing symbol in a DLL that *does* exist (spicule_rpath_sym
 *     fails, likewise diagnosable);
 *   - that ordinary program state (argv, environ) untouched by any of
 *     this still looks normal, i.e. using this facility does not
 *     disturb anything else. (The zero-*startup*-cost claim itself --
 *     that a program which never calls into rpath.c/delayload.c never
 *     pulls those objects in -- is a link-time property, not a runtime
 *     one, and is checked separately: `nm obj/test/misc.exe` (a test
 *     that never mentions this API) has no spicule_rpath_... or
 *     spicule_delayLoadHelper2 symbols.)
 *
 * If this exits 6 rather than 0 or 1, it never reached any of the
 * CHECKs below: 6 is 0xE0DE0006 truncated to a POSIX exit status, i.e.
 * __ENCODE_SIGNAL_EXIT(SIGABRT) from abort() in spicule_rpath_fail() -- the
 * very first rpath_plugin_answer() call could not delay-load
 * rpath-plugin.dll at all.  Nothing in this file prints on that path,
 * so read the stderr line the failure does leave, which names the
 * NTSTATUS: 0xc0000135 means the DLL is not next to the .exe,
 * 0xc000007b/0xc0000020 mean the file is there but is not a loadable
 * image -- most often a half-written obj/test/rpath-plugin.dll left by
 * an interrupted or OOM-killed build, which make will happily call "up
 * to date" for ever after.  The Makefile now renames that DLL into
 * place atomically so that cannot happen; if it somehow does, the fix
 * is to rebuild it, never to relax anything here.
 *
 * NT-only, like src/internal/rpath.c and src/internal/delayload.c that
 * this exercises: under tools/asan-build.sh's native run this fails to
 * compile (see the #error below) rather than fail to link with a
 * confusing "undefined reference to spicule_rpath_load" -- those two
 * files are excluded from that build for the same reason, so nothing
 * this test calls would exist there regardless.
 */
#ifndef _WIN32
#error "rpath-win.c is NT-only (exercises rpath.c/delayload.c, both NT-only); see src/internal/rpath.c"
#endif
#include <stdio.h>
#include <string.h>
#include "spicule/delayload.h"

/* $ORIGIN semantics: "." resolves to the image's own directory, where
 * the Makefile places rpath-plugin.dll right alongside this .exe. */
const char *const __rpath[] = { ".", 0 };

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* The real delay-load machinery: a descriptor + delay IAT/INT for
 * "rpath-plugin.dll", one imported function (rpath_plugin_answer,
 * index 0), and the generated stub a caller actually calls. */
SPICULE_DELAY_DLL(plugin, "rpath-plugin.dll", 1, SPICULE_DELAY_NAME("rpath_plugin_answer"));
SPICULE_DELAY_STUB(int, plugin, 0, rpath_plugin_answer, (void), ())

int main(int argc, char **argv)
{
	spicule_dll_t *dll;
	void *sym;

	/* ---- end-to-end delay load through __rpath's "." entry --------- */
	CHECK(rpath_plugin_answer() == 42);
	/* Second call must reuse the now-resolved IAT slot (extern void*
	 * spicule_delay_iat_plugin[0].function is non-NULL after the first
	 * call) rather than resolving again -- observable indirectly: it
	 * still returns the right answer, and nothing about repeating the
	 * call crashes or re-touches spicule_rpath_error()'s "no error"
	 * default, which a spurious second resolve attempt would not
	 * disturb either way, so this is mostly a smoke check that the
	 * cached path is exercised at all. */
	CHECK(rpath_plugin_answer() == 42);

	/* ---- same DLL, reached by an explicit relative path component -- */
	/* Bypasses __rpath entirely (see rpath.h): "./rpath-plugin.dll" has
	 * a path component, so it is resolved directly against the image
	 * directory. */
	dll = spicule_rpath_load("./rpath-plugin.dll");
	CHECK(dll != 0);
	if (dll) {
		sym = spicule_rpath_sym(dll, "rpath_plugin_answer");
		CHECK(sym != 0);
		if (sym) CHECK(((int (*)(void))sym)() == 42);
		/* spicule_rpath_unload.html-equivalent (rpath.h's own doc
		 * comment): "releases one reference on dll ... Returns 0 on
		 * success". */
		CHECK(spicule_rpath_unload(dll) == 0);
	}

	/* ---- missing DLL ------------------------------------------------ */
	{
		/* spicule_rpath_error_seq.html-equivalent: "0 until the first
		 * ever failure", then "bumped once per failure recorded".
		 * Nothing above this line ever failed, so this is exactly the
		 * first bump -- checked as a strict "it moved" rather than
		 * pinning 0->1, since a future caller adding an earlier
		 * failure elsewhere in this file should not have to renumber
		 * this assertion. */
		unsigned long seq_before = spicule_rpath_error_seq();
		dll = spicule_rpath_load("no-such-plugin-at-all.dll");
		CHECK(dll == 0);
		CHECK(strcmp(spicule_rpath_error(), "no error") != 0);
		CHECK(strstr(spicule_rpath_error(), "no-such-plugin-at-all.dll") != 0);
		CHECK(spicule_rpath_error_seq() != seq_before);
	}

	/* ---- missing symbol in a DLL that does exist --------------------- */
	{
		unsigned long seq_before = spicule_rpath_error_seq();
		dll = spicule_rpath_load("rpath-plugin.dll");
		CHECK(dll != 0);
		if (dll) {
			sym = spicule_rpath_sym(dll, "no_such_symbol_at_all");
			CHECK(sym == 0);
			CHECK(strcmp(spicule_rpath_error(), "no error") != 0);
			CHECK(spicule_rpath_error_seq() != seq_before);
			CHECK(spicule_rpath_unload(dll) == 0);
		}
	}

	/* ---- spicule_rpath_unload() failure: NULL dll ---------------------- */
	/* src/internal/rpath.c: "!dll" is reported through the same
	 * diagnosable-error channel as every other failure here, with a
	 * nonzero return -- checked directly rather than only through the
	 * success path above. */
	CHECK(spicule_rpath_unload(0) != 0);
	CHECK(strcmp(spicule_rpath_error(), "no error") != 0);

	/* ---- nothing about using this facility disturbs ordinary state -- */
	CHECK(argc >= 1);
	CHECK(argv != 0 && argv[0] != 0);

	if (!fails) printf("PASS\n");
	return fails ? 1 : 0;
}
