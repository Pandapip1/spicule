/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include "ownership_stubs.h"

withtok(null_terminated)
char *strcpy(char *__restrict dest grant(null_terminated),
	const char *__restrict src withtok(null_terminated))
{
	stpcpy(dest, src);
	__ownership_string_terminated(dest);
	return dest;
}

// NOLINTEND(misc-include-cleaner)
