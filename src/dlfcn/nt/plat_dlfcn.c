/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * src/internal/plat_dlfcn.h's NT backend. Built on ntdll's
 * LdrLoadDll()/LdrGetProcedureAddress()/LdrUnloadDll() through
 * include/spicule/rpath.h's wrappers (spicule_rpath_load()/_sym()/
 * _unload()/_error()/_error_seq(), src/internal/rpath.c); NT-specific
 * decisions -- what counts as an absolute path, where $ORIGIN is, the
 * sticky-error bookkeeping -- are made there, not here.
 *
 * `mode` (RTLD_NOW/RTLD_LAZY/RTLD_GLOBAL/RTLD_LOCAL) is accepted but
 * never inspected:
 *   - RTLD_NOW/RTLD_LAZY: LdrLoadDll() always resolves every relocation
 *     before returning, so both are trivially satisfied -- there is
 *     nothing left for RTLD_LAZY to defer.
 *   - RTLD_GLOBAL: also unconditionally what LdrLoadDll() does -- every
 *     mapped module's exports are visible process-wide, with no
 *     per-handle opt-in.
 *   - RTLD_LOCAL: not implementable, not merely unimplemented. dlsym()
 *     already resolves only against one handle's own export table
 *     (RTLD_LOCAL's *direct* promise), but its other half -- keeping
 *     this module's symbols from satisfying a *different*,
 *     later-loaded module's unresolved imports -- would need
 *     reimplementing PE import resolution wholesale, which only
 *     rpath.c/pe.c's ntdll delay-load bootstrap case does today, and
 *     only narrowly. The bit is still accepted, so the common
 *     `RTLD_NOW | RTLD_LOCAL` combination compiles and loads, but it
 *     isolates nothing.
 *
 * A bare (no-slash) `file` is routed through __rpath, the program's own
 * opt-in $ORIGIN-relative search list -- NOT LdrLoadDll's ordinary
 * unqualified-name search (CWD/PATH/system dirs). This is intentional:
 * an ambient, attacker-influenceable search path starting with the CWD
 * is a classic DLL-hijacking vector, and rpath.h already refuses that
 * fallback for delay-load; dlopen() sits on the same primitive and
 * inherits the same protection. A caller that wants the ordinary
 * system search can add an absolute directory to __rpath, or pass a
 * fully-qualified path.
 *
 * Reference counting is not tracked here: LdrLoadDll()/LdrUnloadDll()
 * already refcount each module internally (WINE_MODREF.ldr.LoadCount
 * in Wine's dlls/ntdll/loader.c, the reference implementation of the
 * ntdll ABI this project targets), so two dlopen() calls on the same
 * path already return the identical handle for free.
 *
 * dlopen(NULL, ...) returns __peb->ImageBaseAddress, the main image's
 * own base address -- dlsym() recognises that handle and walks
 * PEB_LDR_DATA's load-order list across every loaded module (the main
 * image, startup DLLs, and later LdrLoadDll modules) instead of just
 * one.
 *
 * NT-only: every function here calls into spicule_rpath_*(), which does
 * not exist in a native build (rpath.c refuses to compile there), so
 * this needs the same #error guard rather than being left simply
 * unimplemented -- tools/asan-build.sh's native run links every
 * compiled object into every test, so a stray undefined reference here
 * would break unrelated tests' native links too. */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#ifndef __has_feature
#define __has_feature(x) 0 /* not clang: never claim a clang-only feature */
#endif
#if !defined(_WIN32) && (defined(_SPICULE_NATIVE_BUILD) || \
                        defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer))
#error "plat_dlfcn.c is NT-only (built on spicule_rpath_*(), which is NT-only itself); see src/internal/rpath.c's comment for why this guard exists"
#endif
#include <stddef.h>
#include <dlfcn.h>
#include <string.h>
#include "libc.h"
#include "plat_dlfcn.h"
#include "spicule/rpath.h"

/* dlclose()'s no-op special case below compares against this rather
 * than hardcoding NULL, so it reads the same way dlopen(NULL, ...)'s
 * own special case does. */
#define MAIN_IMAGE_HANDLE (__peb->ImageBaseAddress)

void *__plat_dlopen(const char *file, int mode)
{
	(void)mode; /* see this file's header comment: every bit is either
	             * already what LdrLoadDll() does, or N/A on NT */

	if (!file)
		return MAIN_IMAGE_HANDLE;

	return spicule_rpath_load(file);
}

/* entry->DllBase below is a disclosed, deliberately unmarked residual:
 * entry is not a parameter of this function at all -- it is
 * CONTAINING_RECORD-computed from `link`, a pointer-arithmetic offset
 * off a live circular list walk -- the same "struct/local-derived
 * pointer, not a parameter" class crt/delayload2.c's own
 * find_mapped_module() comment already established for the identical
 * PEB_LDR_DATA walk shape (InMemoryOrderModuleList there,
 * InLoadOrderModuleList here). Verified sound by hand regardless, for
 * the same reason: PEB_LDR_DATA's own lists are genuinely circular
 * and always populated for any live NT process. */
void *__plat_dlsym(void *__restrict handle,
	const char *__restrict name withtok(null_terminated))
{
	if (handle == MAIN_IMAGE_HANDLE && __peb->Ldr) {
		LIST_ENTRY *head = &__peb->Ldr->InLoadOrderModuleList;
		LIST_ENTRY *link;
		ANSI_STRING symbol;
		size_t len = strlen(name);

		/* ANSI_STRING counts bytes in a USHORT.  Let the ordinary
		 * spicule_rpath_sym() path below record STATUS_NAME_TOO_LONG
		 * instead of wrapping a long name into a different symbol. */
		if (len > 0xffffu)
			return spicule_rpath_sym((spicule_dll_t *)handle, name);
		symbol.Buffer = (char *)name;
		symbol.Length = (USHORT)len;
		symbol.MaximumLength = symbol.Length;
		for (link = head->Flink; link != head; link = link->Flink) {
			LDR_DATA_TABLE_ENTRY *entry =
				(LDR_DATA_TABLE_ENTRY *)((char *)link -
				 offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks));
			PVOID address = 0;
			if (NT_SUCCESS(LdrGetProcedureAddress(entry->DllBase,
					&symbol, 0, &address)))
				return address;
		}
		/* Record the ordinary diagnosable symbol error after the global
		 * search, without recording every module miss along the way. */
	}
	return spicule_rpath_sym((spicule_dll_t *)handle, name);
}

int __plat_dlclose(void *handle)
{
	/* Nothing on NT can sensibly unload the running program's own
	 * image out from under itself; POSIX only ever says an
	 * implementation "may" unload on dlclose(), never must, so
	 * treating this handle as always still open and returning success
	 * is conforming, not a shortcut. */
	if (handle == MAIN_IMAGE_HANDLE)
		return 0;

	return spicule_rpath_unload((spicule_dll_t *)handle) == 0 ? 0 : -1;
}

/* Thin forwards -- see plat_dlfcn.h's own banner for why sticky-backend/
 * single-shot-front-door reconciliation lives in src/dlfcn/dlfcn.c and
 * not here: spicule_rpath_error()/_error_seq() already ARE exactly that
 * sticky-message/monotonic-sequence pair, unchanged since before this
 * split, and other callers of rpath.c (not just dlfcn) already depend
 * on their stickiness. */
const char *__plat_dlerror(void) { return spicule_rpath_error(); }
unsigned long __plat_dlerror_seq(void) { return spicule_rpath_error_seq(); }

// NOLINTEND(misc-include-cleaner)
