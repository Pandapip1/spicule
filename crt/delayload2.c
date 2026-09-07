/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * __delayLoadHelper2(): the real, linker-driven delay-load helper for a
 * tcc built with -Wl,--delay-all. That linker turns every ordinary
 * `extern` call to an imported function into a call through a generated
 * thunk, and every such thunk's first call goes through this exact
 * routine name -- __delayLoadHelper2(descriptor, &iat_slot) -- with no
 * spicule-specific declaration required at the call site, so an
 * unmodified program gets $ORIGIN resolution for free.
 *
 * Lives under crt/, not src/internal/: tinycc's pe_build_delay_imports()
 * only invents the undefined reference to "__delayLoadHelper2" while
 * *writing* the PE image, after tcc has already resolved undefined
 * symbols against archive members -- so a plain `-lc` link never looks
 * inside libc.a for it. This file is instead built to lib/delayload2.o
 * and given to the linker as a plain object alongside crt1.o, the same
 * way crt1.o itself is; the spicule-tcc wrapper adds it automatically
 * whenever it sees --delay-all.
 *
 * The descriptor is RVA-based, not a native pointer: the linker emits a
 * real IMAGE_DELAYLOAD_DESCRIPTOR (PE/COFF spec 4.3) with
 * Attributes.RvaBased = 1, so DllNameRVA/ModuleHandleRVA/
 * ImportAddressTableRVA/ImportNameTableRVA are offsets from
 * __peb->ImageBaseAddress, not pointers -- unlike delayload.h's
 * spicule_delay_descr_t, whose fields are plain native pointers by a
 * separate, unrelated convention. The one exception is what an IAT slot
 * *contains*: always a real absolute pointer, initially the thunk's own
 * address, later the resolved function's. This file tells "still the
 * thunk" from "already resolved" by range-checking the slot's value
 * against the target DLL's mapped image (spicule_pe_dll_range()) rather
 * than remembering the thunk's address, since the generated tail-merge
 * stub calls this helper unconditionally on every call.
 *
 * ntdll itself is delay-loaded too under -Wl,--delay-all (it's a real
 * import), so naively resolving via LdrLoadDll()/LdrGetProcedureAddress()
 * would recurse into itself resolving those very symbols. The fix:
 * symbol resolution never calls LdrGetProcedureAddress. spicule_pe_find_
 * export() hand-parses a module's export directory directly from its
 * mapped image, which works for any already-mapped module including
 * ntdll (mapped by the kernel before the entry point runs).
 * find_mapped_module() below walks the PEB's loader module list first,
 * for exactly that reason; only a module not found there falls through
 * to spicule_rpath_load(), which does call LdrLoadDll -- safe because
 * resolving *that* call's own ntdll.dll import never reaches
 * spicule_rpath_load() (ntdll is always found by the PEB walk first).
 *
 * NT-only, same guard and same reason as rpath.c/delayload.c/pe.c.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(_WIN32) && (defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer))
#error "delayload2.c is NT-only; see the comment above and src/internal/rpath.c"
#endif
#include <string.h>
#include "libc.h"
#include "pe.h"
#include "rtlib.h"
#include "spicule/rpath.h"
#include "unsafe_pointer.h"

/* Real (linker-built) delay-load descriptor, PE/COFF spec 4.3. Every
 * *RVA field is an offset from the image base; see the file header
 * comment for the one field (an IAT slot's contents) that is not. */
typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR { // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling follows the NT ABI
	ULONG Attributes;
	ULONG DllNameRVA;
	ULONG ModuleHandleRVA;
	ULONG ImportAddressTableRVA;
	ULONG ImportNameTableRVA;
	ULONG BoundImportAddressTableRVA;
	ULONG UnloadInformationTableRVA;
	ULONG TimeDateStamp;
} IMAGE_DELAYLOAD_DESCRIPTOR;

/* Case-insensitive (ASCII range only -- every DLL name this ever
 * compares is plain ASCII) compare of a plain (non-allocated) ASCII
 * C string against a UTF-16 buffer of known length `wn`, with no
 * conversion or allocation of any kind: deliberately, since this runs
 * inside the delay-load resolution path itself (see below). */
/* w is nonnull per NT's UNICODE_STRING invariant (Buffer is never NULL
 * for a populated LDR_DATA_TABLE_ENTRY), not derivable from the `i < wn`
 * guard alone -- same reasoning as crt/crt1.c's split_cmdline. */
static int name_eq_ci(const char *ascii, const WCHAR *w, size_t wn)
    __attribute__((nonnull(1, 2)));
static int name_eq_ci(const char *ascii, const WCHAR *w, size_t wn)
{
	size_t i;
	for (i = 0; i < wn; i++) {
		unsigned char ca = (unsigned char)ascii[i];
		WCHAR cb = w[i];
		if (!ca) return 0; /* ascii is shorter than w */
		if (ca >= 'a' && ca <= 'z') ca = (unsigned char)(ca - 0x20);
		if (cb >= 'a' && cb <= 'z') cb = (WCHAR)(cb - 0x20);
		if ((WCHAR)ca != cb) return 0;
	}
	return ascii[wn] == 0; /* same length too */
}

/* Finds `dllname` already mapped into this process by walking the PEB's
 * loader module list.
 *
 * Deliberately does *no* heap allocation: __malloc() ultimately calls
 * RtlAllocateHeap, itself an ntdll import and therefore delay-loaded --
 * and RtlAllocateHeap is typically the very first symbol this program
 * resolves at all (crt1.c allocates before main() runs). If resolving
 * it needed to allocate first, that would recurse forever (confirmed
 * as a real stack overflow under Wine). Comparing without allocating
 * breaks that cycle. */
static void *find_mapped_module(const char *dllname)
{
	PLIST_ENTRY head, cur;

	if (!__peb || !__peb->Ldr) return 0;

	head = &__peb->Ldr->InMemoryOrderModuleList;
	for (cur = head->Flink; cur != head; cur = cur->Flink) {
		/* InMemoryOrderLinks is LDR_DATA_TABLE_ENTRY's *second* LIST_ENTRY
		 * member (nt.h): recover the entry by subtracting that member's
		 * offset, the same pattern CONTAINING_RECORD expands to. */
		LDR_DATA_TABLE_ENTRY *e = (LDR_DATA_TABLE_ENTRY *)
			((unsigned char *)cur - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
		if (name_eq_ci(dllname, e->BaseDllName.Buffer, e->BaseDllName.Length / sizeof(WCHAR)))
			return e->DllBase;
	}
	return 0;
}

void *__delayLoadHelper2(void *vdescr, void **piat)
{
	IMAGE_DELAYLOAD_DESCRIPTOR *descr = (IMAGE_DELAYLOAD_DESCRIPTOR *)vdescr;
	unsigned char *base;
	void **modhandle;
	void **iat;
	ULONG *nametable;
	const char *dllname;
	unsigned long index;
	const char *name;
	void *dll;
	void *proc;
	void *rstart, *rend;

	/* Defensive, fail-loud guard: __peb is always set by crt1.c before
	 * any ntdll call could reach a delay-load stub at all. */
	if (!__peb) spicule_rpath_fail("<spicule>", "__peb not initialized");

	base = (unsigned char *)__peb->ImageBaseAddress;
	modhandle = (void **)(base + descr->ModuleHandleRVA);
	iat = (void **)(base + descr->ImportAddressTableRVA);
	nametable = (ULONG *)(base + descr->ImportNameTableRVA);
	dllname = (const char *)(base + descr->DllNameRVA);

	/* piat is the hand-written delay-load thunk stub's (crt/delayload1.asm)
	 * own argument, computed there as `base + <RVA>` -- the same
	 * computation `iat` just made in C above -- but nothing in this TU
	 * sees that assembly to prove the two share provenance. */
	index = (unsigned long)unsafe_assume_shared_provenance(piat - iat);
	/* Each name-table entry is an RVA to a 2-byte "hint" (unused, always
	 * 0 here) followed by the NUL-terminated import name; skip the hint
	 * the same way the real loader does. */
	name = (const char *)(base + nametable[index]) + sizeof(USHORT);

	dll = *modhandle;

	/* Fast path: already resolved by an earlier call through this same
	 * slot. See the file header comment for why a range check against
	 * the owning DLL's mapped image, not a sentinel compare, is what
	 * distinguishes this from "still holds the thunk's own address". */
	/* *piat and rstart/rend come from two independent sources this
	 * function's own body cannot relate: *piat is whatever a prior
	 * resolution already stored into the IAT slot, while rstart/rend are
	 * spicule_pe_dll_range()'s runtime query of the OWNING dll's mapped
	 * image -- a human-verified PE loader invariant (a resolved IAT slot
	 * always holds an address inside its own DLL's mapping), not
	 * something derivable from this function's local pointer arithmetic. */
	if (dll && spicule_pe_dll_range(dll, &rstart, &rend) &&
	    unsafe_assume_shared_provenance(*piat >= rstart) &&
	    unsafe_assume_shared_provenance(*piat < rend))
		return *piat;

	if (!dll) {
		dll = find_mapped_module(dllname);
		if (!dll) dll = spicule_rpath_load(dllname);
		if (!dll) spicule_rpath_fail(dllname, "<module>");
		*modhandle = dll;
	}

	proc = spicule_pe_find_export(dll, name);
	if (!proc) spicule_rpath_fail(dllname, name);

	*piat = proc;
	return proc;
}

// NOLINTEND(misc-include-cleaner)
