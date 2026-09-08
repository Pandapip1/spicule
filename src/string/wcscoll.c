/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Locale is always C/POSIX (src/misc/locale.c), whose collation order is
 * code-unit order -- i.e. wcscmp()'s ordering. This one-line forward is
 * therefore the complete implementation, not a placeholder awaiting a
 * real collation table.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <wchar.h>
#include <locale.h>

int wcscoll(const wchar_t *l withtok(null_terminated),
	const wchar_t *r withtok(null_terminated))
{
	return wcscmp(l, r);
}

int wcscoll_l(const wchar_t *l withtok(null_terminated),
	const wchar_t *r withtok(null_terminated), locale_t loc)
{
	(void)loc;
	return wcscmp(l, r);
}

// NOLINTEND(misc-include-cleaner)
