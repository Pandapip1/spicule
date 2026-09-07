/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)

#include "libc.h"
PTEB __teb(void)
{
	PTEB t;
	__asm__ __volatile__("movl %%fs:0x18, %0" : "=r"(t));
	return t;
}

// NOLINTEND(misc-include-cleaner)
