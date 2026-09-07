/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)

/* environ is defined in crt1.c (as the symbol crt1 fills in at startup);
 * this file exists so that src/env has the declaration in one place. */
#include "libc.h"

// NOLINTEND(misc-include-cleaner)
