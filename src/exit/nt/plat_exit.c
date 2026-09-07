/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of src/internal/plat_exit.h -- see that header for
 * the contract.  Was, until this file existed, inline inside
 * src/exit/exit.c's __exit_internal(); nothing changed in substance, only
 * location.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include "libc.h"
#include "plat_exit.h"

_Noreturn void __plat_terminate(int code)
{
	NtTerminateProcess(NtCurrentProcess(), code);
	for (;;) NtTerminateProcess(NtCurrentProcess(), code);
}

// NOLINTEND(misc-include-cleaner)
