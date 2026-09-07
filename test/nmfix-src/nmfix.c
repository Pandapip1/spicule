/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A tiny, deliberately unlinked object-file fixture for test/util-nm.c:
 * known symbols exercising each of the type letters src/util/nm.c's
 * own header comment documents --
 *
 *   nmfix_global_func       T (global, defined, in .text)
 *   nmfix_local_func        t (local/static, defined, in .text --
 *                              __attribute__((noinline)) so it keeps
 *                              its own symbol-table entry even under
 *                              an optimizing build that would otherwise
 *                              inline a single-call-site static)
 *   nmfix_global_data       D (global, initialized, in .data)
 *   nmfix_global_bss        B (global, uninitialized, in .bss)
 *   nmfix_external_undefined U (referenced but never defined here)
 *
 * Never linked into anything spicule ships -- see the Makefile's own
 * obj/test/nmfix.o rule (`$(CC) ... -c`, no link stage at all) and
 * test/util-nm.c's own header comment for how this fixture is used.
 */

extern int nmfix_external_undefined(int);

int nmfix_global_data = 42;
int nmfix_global_bss;

static __attribute__((noinline)) int nmfix_local_func(int x)
{
	return x + 1;
}

int nmfix_global_func(int x)
{
	nmfix_global_bss = nmfix_local_func(x);
	return nmfix_external_undefined(nmfix_global_bss) + nmfix_global_data;
}
