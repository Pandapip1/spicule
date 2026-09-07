/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)

#include <stdlib.h>
#include <signal.h>
#include "libc.h"

_Noreturn void abort(void)
{
	__sig_lock();
	__raise_internal(SIGABRT);
	__sig_unlock();
	/* If a handler returned, or SIGABRT was ignored, die anyway -- with
	 * the status a Unix process killed by SIGABRT would have. */
	__exit_internal(__ENCODE_SIGNAL_EXIT(SIGABRT));
}

// NOLINTEND(misc-include-cleaner)
