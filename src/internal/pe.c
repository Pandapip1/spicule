/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ntlibc_pe_find_export(): hand-parses an already-mapped PE image's own
 * export directory. See src/internal/pe.h for why this exists (the
 * ntdll delay-import bootstrap problem) and the field layouts used.
 *
 * NT-only for the same reason and by the same guard as rpath.c/
 * delayload2.c: nothing here has a native stand-in, and this is reached
 * only from delayload2.c, which is already excluded from a native
 * ASan/UBSan build.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(_WIN32) && (defined(_NTLIBC_NATIVE_BUILD) || \
                        defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer))
#error "pe.c is NT-only; see src/internal/rpath.c's comment for why this guard exists"
#endif
#include <string.h>
#include "libc.h"
#include "pe.h"

/* Shared by ntlibc_pe_find_export() and ntlibc_pe_dll_range(): validates
 * the DOS/NT headers and returns a pointer to IMAGE_NT_HEADERS, or NULL
 * if `base` is not a valid PE image.
 *
 * nt->Signature below is a disclosed, deliberately unmarked residual:
 * nt is `b + dos->e_lfanew`, a local computed by pointer arithmetic,
 * not a parameter of this function -- b itself is already guarded
 * (`if (!b) return 0;`) and there is no signature for `nonnull` to
 * describe a further-derived local on, the same "struct/local-derived
 * pointer, not a parameter" class this tree's own crt/delayload2.c
 * find_mapped_module() comment already established. Verified sound by
 * hand regardless: b is always a real, already-mapped PE image's base
 * address here (this file's own two real callers pass __peb-derived
 * or loader-walked module bases, never an arbitrary offset), and
 * dos->e_lfanew for any genuine PE image is a small, sane header
 * offset -- nt lands well inside the same mapped image, never NULL. */
static IMAGE_NT_HEADERS *pe_nt_headers(unsigned char *b)
{
	IMAGE_DOS_HEADER *dos;
	IMAGE_NT_HEADERS *nt;

	if (!b) return 0;
	dos = (IMAGE_DOS_HEADER *)b;
	if (dos->e_magic != 0x5A4D /* "MZ" */) return 0;
	nt = (IMAGE_NT_HEADERS *)(b + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
	return nt;
}

int ntlibc_pe_dll_range(void *base, void **start, void **end)
{
	unsigned char *b = (unsigned char *)base;
	IMAGE_NT_HEADERS *nt = pe_nt_headers(b);
	if (!nt) return 0;
	*start = b;
	*end = b + nt->OptionalHeader.SizeOfImage;
	return 1;
}

int ntlibc_pe_tls_directory(void *base, IMAGE_TLS_DIRECTORY **dir)
{
	unsigned char *b = (unsigned char *)base;
	IMAGE_NT_HEADERS *nt = pe_nt_headers(b);
	ULONG rva, size;

	if (!nt) return 0;
	if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_TLS)
		return 0;
	rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
	size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
	if (!rva || size < sizeof(IMAGE_TLS_DIRECTORY)) return 0;
	*dir = (IMAGE_TLS_DIRECTORY *)(b + rva);
	return 1;
}

void *ntlibc_pe_find_export(void *base, const char *name)
{
	unsigned char *b = (unsigned char *)base;
	IMAGE_NT_HEADERS *nt;
	IMAGE_EXPORT_DIRECTORY *exp;
	ULONG exp_rva, exp_size;
	ULONG *functions, *names;
	USHORT *ordinals;
	ULONG i, n;

	if (!name) return 0;
	nt = pe_nt_headers(b);
	if (!nt) return 0;

	if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
		return 0;
	exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	exp_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (!exp_rva || !exp_size) return 0;

	exp = (IMAGE_EXPORT_DIRECTORY *)(b + exp_rva);
	names = (ULONG *)(b + exp->AddressOfNames);
	ordinals = (USHORT *)(b + exp->AddressOfNameOrdinals);
	functions = (ULONG *)(b + exp->AddressOfFunctions);

	n = exp->NumberOfNames;
	for (i = 0; i < n; i++) {
		const char *cand = (const char *)(b + names[i]);
		if (strcmp(cand, name) == 0) {
			USHORT ord = ordinals[i];
			if (ord >= exp->NumberOfFunctions) return 0;
			return b + functions[ord];
			/* Not checking whether functions[ord] lands back inside
			 * [exp_rva, exp_rva+exp_size) (a forwarder RVA, e.g.
			 * "NTDLL.RtlAllocateHeap") -- none of the exports this file
			 * is ever asked to resolve (LdrLoadDll,
			 * LdrGetProcedureAddress, and whatever ntlibc_rpath_load()
			 * itself later imports from ntdll) are forwarders in
			 * practice, and misresolving one would fail loudly the
			 * moment the caller jumps into a string instead of code,
			 * not silently. */
		}
	}
	return 0;
}

// NOLINTEND(misc-include-cleaner)
