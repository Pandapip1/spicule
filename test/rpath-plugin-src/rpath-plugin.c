/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A trivial DLL for test/rpath-win.c to delay-load through
 * spicule_rpath_load()/spicule_rpath_sym() -- not linked against spicule at
 * all, since all rpath-win.c needs from it is one exported, callable
 * function.  Built directly by the Makefile's obj/test/%.dll rule with
 * `$(CC) -shared`, independent of libc.a.
 */
__declspec(dllexport) int rpath_plugin_answer(void)
{
	return 42;
}
