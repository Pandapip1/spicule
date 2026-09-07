/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>

/* ISO C leaves a zero divisor and MIN/-1 undefined.  Handle both anyway so
 * these small helpers never execute hardware- or language-level undefined
 * arithmetic when called by an unchecked application.  ldiv derives its
 * minimum from the compiler's unsigned-long width: spicule's target header
 * correctly publishes a 32-bit LONG_MIN for LLP64, while the native sanitizer
 * build compiles this same source with a 64-bit C long. */
div_t div(int n, int d) { div_t r; if (!d || (n == INT_MIN && d == -1)) { r.quot = 0; r.rem = n; return r; } r.quot = n / d; r.rem = n % d; return r; }
ldiv_t ldiv(long n, long d) { ldiv_t r; long min = -(long)(~0UL >> 1) - 1L; if (!d || (n == min && d == -1)) { r.quot = 0; r.rem = n; return r; } r.quot = n / d; r.rem = n % d; return r; }
lldiv_t lldiv(long long n, long long d) { lldiv_t r; if (!d || (n == LLONG_MIN && d == -1)) { r.quot = 0; r.rem = n; return r; } r.quot = n / d; r.rem = n % d; return r; }
imaxdiv_t imaxdiv(intmax_t n, intmax_t d) { imaxdiv_t r; if (!d || (n == INTMAX_MIN && d == -1)) { r.quot = 0; r.rem = n; return r; } r.quot = n / d; r.rem = n % d; return r; }

// NOLINTEND(misc-include-cleaner)
