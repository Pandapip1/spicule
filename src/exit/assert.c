/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

_Noreturn void __assert_fail(const char *expr, const char *file, int line, const char *func)
{
	/* Fatal diagnostics are best-effort: abort is the only outcome and there
	 * is no recovery channel through which a stderr failure could propagate. */
	(void)fprintf(stderr, "Assertion failed: %s (%s: %s: %d)\n", expr, file, func, line);
	(void)fflush(0);
	abort();
}

// NOLINTEND(misc-include-cleaner)
