/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
/* spicule targets Windows NT only; under this tcc's -win32 target "long
 * double" is really just "double" (see src/math/ldbl_math.h), so squaring
 * two doubles near DBL_MAX (as hypot(1e300, 1e300) does) overflows the
 * intermediate the same as it would in plain double arithmetic - there
 * is no extra 80-bit exponent range to hide behind here.  So scale by
 * the larger magnitude first (the standard fix): with r = min/max in
 * [0, 1], max*sqrt(1 + r*r) is exact up to the final sqrt rounding and
 * cannot overflow unless the true result itself would. */
#include <math.h>
#include "ldbl_math.h"

long double hypotl(long double x, long double y)
{
	long double ax = fabsl(x), ay = fabsl(y), r;
	/* hypot.html RETURN VALUE: "If x or y is +-Inf, +Inf shall be
	 * returned even if one of x or y is a NaN" -- an infinity outranks
	 * a NaN, so that check must run first, unconditionally, not only
	 * inside the x!=x||y!=y branch below. */
	if (ax == HUGE_VALL || ay == HUGE_VALL) return HUGE_VALL;
	if (x != x || y != y) return x + y;
	if (ax < ay) { long double t = ax; ax = ay; ay = t; }
	if (ax == 0) return 0;
	r = ay / ax;
	return ax * __x87_sqrt(1.0L + r * r);
}

double hypot(double x, double y) { return (double)hypotl(x, y); }
float hypotf(float x, float y) { return (float)hypotl(x, y); }
