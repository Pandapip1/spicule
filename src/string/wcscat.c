/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <wchar.h>
#include "ownership_stubs.h"

withtok(null_terminated)
wchar_t *wcscat(wchar_t *__restrict dest withtok(null_terminated)
	grant(null_terminated),
	const wchar_t *__restrict src withtok(null_terminated))
{
	wcscpy(dest + wcslen(dest), src);
	unsafe_assume_string_terminated(dest);
	return dest;
}

// NOLINTEND(misc-include-cleaner)
