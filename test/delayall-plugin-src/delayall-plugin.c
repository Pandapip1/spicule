/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A trivial DLL for test/delayall.c to call through the *linker's own*
 * delay-load thunks (built with -Wl,--delay-all, resolved through
 * __delayLoadHelper2 in crt/delayload2.c) -- as opposed to
 * test/rpath-plugin-src/rpath-plugin.c, which is called through
 * spicule's hand-authored SPICULE_DELAY_STUB macros. Not linked against
 * spicule at all; built directly with `$(CC) -shared`, same as that
 * other plugin.
 *
 * delayall_check() takes four ints and two doubles -- enough to occupy
 * every register-passed argument slot on both targets (the x86_64
 * Microsoft ABI's four RCX/RDX/R8/R9 integer slots, and i386 cdecl's
 * all-on-stack convention, which this also happens to exercise for the
 * two doubles since only four argument slots exist in the x86_64 ABI
 * regardless of type) -- and asserts every one against the exact
 * values test/delayall.c passes, so a delay-load thunk that clobbers a
 * register or misaligns the stack corrupts an argument and fails this
 * check loudly (a wrong return code) instead of silently.
 */
__declspec(dllexport) int delayall_check(int a, int b, int c, int d, double e, double f)
{
	if (a != 11 || b != 22 || c != 33 || d != 44) return 100;
	if (e != 55.5 || f != 66.25) return 200;
	return 42;
}
