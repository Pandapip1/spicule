/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <dlfcn.h>: dlopen()/dlsym()/dlclose()/dlerror(), as a thin,
 * platform-agnostic front door over src/internal/plat_dlfcn.h --
 * __plat_dlopen()/_dlsym()/_dlclose()/_dlerror()/_dlerror_seq(), each
 * implemented once per OS backend (src/dlfcn/nt/plat_dlfcn.c over
 * ntdll's LdrLoadDll() family; src/dlfcn/linux/plat_dlfcn.c, a real
 * from-scratch ELF64 loader -- see that file's own banner for the
 * design). Same split as src/stat/chmod.c over plat_stat.h,
 * src/fcntl/open.c over plat_fcntl.h, src/mman/mman.c over plat_mem.h:
 * everything genuinely platform-specific moved into the matching
 * backend, and this file kept small enough that nothing here needs to
 * know which backend it is calling.
 *
 * dlopen()/dlsym()/dlclose() are pure one-line forwards -- every
 * POSIX-facing decision (mode-flag handling, dlopen(NULL, ...)'s
 * process-global handle, search-path/namespace rules, reference
 * counting) is entirely a backend call, since it differs completely
 * between an NT loader with no unload-narrowing primitive and a from-
 * scratch ELF loader that deliberately narrows differently (see
 * plat_dlfcn.c's own banner for the Linux backend's namespace-
 * isolation model). Nothing here is left to be "platform-agnostic
 * about" beyond the four function signatures themselves.
 *
 * dlerror() is the one function with real logic left in this file: its
 * POSIX single-shot contract (dlerror.html DESCRIPTION: "invoking
 * dlerror() a second time, immediately following a prior invocation,
 * shall result in NULL being returned") layered over a backend that is
 * deliberately NOT single-shot -- both backends keep their error state
 * sticky across repeated calls (see plat_dlfcn.h's own banner for why:
 * NT's rpath.c had older callers that already depended on stickiness,
 * and the Linux backend matches that shape on purpose rather than
 * inventing a second contract). The two are reconciled with one extra
 * piece of state entirely local to this file: the seq value
 * (__plat_dlerror_seq(), bumped once per failure recorded by whichever
 * backend is linked in) that was already reported through dlerror().
 * A successful dlopen()/dlsym()/dlclose() call never bumps that
 * counter, so it cannot un-consume an already-reported error --
 * exactly the "unless an intervening call ... returned NULL and set
 * the error condition" exception dlerror.html itself carves out;
 * nothing else in this file needs to special-case a successful call at
 * all.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stddef.h>
#include <dlfcn.h>
#include "plat_dlfcn.h"

void *dlopen(const char *file, int mode)
{
	return __plat_dlopen(file, mode);
}

void *dlsym(void *__restrict handle,
	const char *__restrict name withtok(null_terminated))
{
	return __plat_dlsym(handle, name);
}

int dlclose(void *handle)
{
	return __plat_dlclose(handle);
}

char *dlerror(void)
{
	static unsigned long reported;
	unsigned long cur = __plat_dlerror_seq();

	if (cur == 0 || cur == reported)
		return NULL;

	reported = cur;
	/* __plat_dlerror() owns this buffer (a backend-local static) and
	 * promises it stays valid until the next __plat_dl*() call, the
	 * same lifetime dlerror.html itself specifies for its own return
	 * value ("may be overwritten by a subsequent call"). The const is
	 * dropped only because dlerror()'s prototype is `char *`, not
	 * `const char *` -- POSIX's own signature, not something this file
	 * chose -- and nothing here writes through it. */
	return (char *)__plat_dlerror();
}

// NOLINTEND(misc-include-cleaner)
