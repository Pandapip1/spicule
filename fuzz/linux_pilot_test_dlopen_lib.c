/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The trivial target .so tools/linux-build-dlfcn.sh dlopen()s to prove
 * src/dlfcn/linux/plat_dlfcn.c's ELF loader end to end. Built by the
 * HOST's own clang/lld as an ordinary aarch64 shared object (this is
 * the file being loaded, not spicule's own code -- it deliberately
 * does NOT use any spicule header or type, and does not link against
 * spicule, glibc, or anything else: -nodefaultlibs/-nostdlib at build
 * time, so the only two kinds of relocation it can possibly need are
 * exactly the two kinds this pass's loader implements support for:
 *
 *   - R_AARCH64_RELATIVE, from exported_table's function-pointer
 *     initializers (a -fPIC shared object cannot know its own load
 *     address at link time, so these need fixing up at load time --
 *     proves apply_one_reloc()'s R_AARCH64_RELATIVE case).
 *   - R_AARCH64_JUMP_SLOT (or GLOB_DAT), from calling
 *     host_provided_value(), a function this .so never defines --
 *     proves resolve_symref()'s fallthrough to resolve_main_symbol(),
 *     i.e. the "symbol resolution against the static binary" design
 *     (see plat_dlfcn.c's own banner). host_provided_value() is
 *     defined by the test PROGRAM (linux_pilot_test_dlopen.c), not by
 *     this file or by anything this file links against.
 */
int add_one(int x) { return x + 1; }
int call_add_one(int x) { return add_one(x) + 1; }

typedef int (*fnptr)(int);
fnptr exported_table[2] = { add_one, call_add_one };

extern int host_provided_value(void);
int use_host_value(void) { return host_provided_value() + 100; }

int dlso_answer(void) { return 42; }
