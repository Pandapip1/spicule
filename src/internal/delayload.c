/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * spicule_delayLoadHelper2(): the one routine every SPICULE_DELAY_STUB
 * calls the first time its IAT slot is still unresolved. See
 * include/spicule/delayload.h for the descriptor/IAT/INT shapes and why
 * they are not byte-for-byte MSVC's ImgDelayDescr, and
 * include/spicule/rpath.h for the $ORIGIN search this uses to find the
 * DLL.
 *
 * NT-only, for the same reason and by the same (ASan-gated, not a bare
 * _WIN32 check -- see src/internal/rpath.c's longer comment for why) as
 * src/internal/rpath.c: this calls into that file, which is itself
 * excluded from a native ASan/UBSan build's compile, so this file has
 * to fail the same way rather than leave a dangling reference to
 * spicule_rpath_load() et al. in that build's unconditional link. A
 * plain native -fsyntax-only pass is unaffected, same as there.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#ifndef __has_feature
#define __has_feature(x) 0 /* not clang: never claim a clang-only feature */
#endif
#if !defined(_WIN32) && (defined(_SPICULE_NATIVE_BUILD) || \
                        defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer))
#error "delayload.c is NT-only (calls into rpath.c, which is NT-only); see the comment above and src/internal/rpath.c"
#endif
#include "libc.h"
#include "spicule/delayload.h"
#include "unsafe_pointer.h"

void *spicule_delayLoadHelper2(spicule_delay_descr_t *descr, spicule_delay_thunk_t *piat)
{
	unsigned long index;
	spicule_dll_t *dll;
	void *proc;
	const char *name;

	/* Same trick __delayLoadHelper2 uses: which import this call is for
	 * is recovered from *where in the IAT* the caller's slot sits,
	 * rather than being passed separately -- so the descriptor alone
	 * (plus this one slot pointer) is enough, matching the real ABI's
	 * two-argument helper shape. */
	/* piat is the hand-written delay-load thunk stub's own argument,
	 * computed there as `base + <RVA>` (same shape __delayLoadHelper2's
	 * own comment on this identical pattern describes) -- nothing in
	 * this TU sees that assembly to prove it shares provenance with
	 * descr->iat. */
	index = (unsigned long)unsafe_assume_shared_provenance(piat - descr->iat);

	/* *descr->modhandle below is a disclosed, deliberately unmarked
	 * residual, surfaced only after descr's own nonnull mark let this
	 * checker explore further into this function than before (the
	 * "deeper exploration unlocked" effect prior sweeps in this tree
	 * already measured, not a regression): descr->modhandle is a
	 * struct FIELD's own value, distinct from descr itself (already
	 * required, see include/spicule/delayload.h), and `nonnull`
	 * cannot describe a field reached through a parameter, only the
	 * parameter itself. Verified sound by hand regardless: every real
	 * descr this function is ever called with is SPICULE_DELAY_DLL's
	 * own macro-built static (include/spicule/delayload.h), whose own
	 * modhandle field is always `&spicule_delay_mod_##dllvar` -- the
	 * address of a real, file-static variable, never NULL. */
	dll = *descr->modhandle;
	if (!dll) {
		dll = spicule_rpath_load(descr->dllname);
		if (!dll) spicule_rpath_fail(descr->dllname, "<module>");
		*descr->modhandle = dll;
	}

	name = descr->nametable[index].name;
	proc = spicule_rpath_sym(dll, name);
	if (!proc) spicule_rpath_fail(descr->dllname, name);

	piat->function = proc;
	return proc;
}

// NOLINTEND(misc-include-cleaner)
