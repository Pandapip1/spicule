/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * errno itself -- the one piece of this file every platform needs
 * identically. The NTSTATUS-to-errno mapping (__errno_from_status(),
 * __errno_from_doserror(), __set_errno_status()) used to live in this
 * same file, unconditionally, which meant a Linux build linked in a
 * call to RtlNtStatusToDosError() it could never resolve even though
 * nothing on that platform ever calls the function containing it --
 * one undefined symbol away from every single link, discovered while
 * getting the OPTS suite to build natively. It now lives in
 * src/internal/nt/errno_nt.c, this file's NT-only counterpart, the
 * same PLAT_GLOBS split src/internal/vfs.c already uses for
 * __vfs_resolve_at()/__vfs_open_dir(). Linux needs no equivalent file:
 * every Linux backend in this tree sets errno directly from the raw
 * kernel's own already-POSIX -errno value (see src/mman/linux/
 * plat_mem.c's banner), so there is no status table to translate.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include "libc.h"

/* errno must be a per-thread, modifiable lvalue (C11 7.5p2, POSIX XSH 2.3).
 * spicule has no threads of its own, but the NT programs it links into do,
 * and this shape is part of the library's ABI -- getting it right now is
 * far cheaper than changing it after the fact.
 *
 * Storage is real Windows implicit ("static") thread-local storage: a
 * __thread variable, backed by the PE TLS directory and the per-thread
 * array the loader hangs off TEB.ThreadLocalStoragePointer (gs:0x58 on
 * x86_64, fs:0x2c on i386).  tcc's PE backend (tccpe.c: pe_build_tls();
 * x86_64-gen.c and i386-gen.c: the TCC_TARGET_PE arm of gen_modrm) emits
 * exactly that access pattern, so this works with the bootstrap compiler,
 * not just clang.  The NT loader always processes the TLS directory of the
 * main executable image at process start (confirmed against Wine's
 * dlls/ntdll/loader.c: build_main_module() -> alloc_tls_slot()), which is
 * the only image spicule programs are -- no DLL involvement required.
 *
 * Natively (the ASan/TSan builds under fuzz/ntstubs.c, where there is no
 * real TEB) a plain __thread still works: clang supports it directly on
 * Linux, and __errno_location() just returns the calling thread's copy.
 * Those builds are effectively single-threaded except for tools/tsan-probe.sh,
 * which specifically wants per-thread storage here -- so __thread is
 * correct there too, not merely tolerated. */
static __thread int __errno_val; // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision

int *__errno_location(void)
{
	return &__errno_val;
}

// NOLINTEND(misc-include-cleaner)
