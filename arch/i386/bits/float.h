/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#define FLT_EVAL_METHOD 2

/* See the matching comment in arch/x86_64/bits/float.h: this project's
 * tcc builds "long double" as an alias for `double` (sizeof == 8) on
 * the actual NT target, while the mingw-w64/gcc fallback compiler (and
 * a native gcc/clang for `make asan`) gives it the genuine 80-bit x87
 * extended format. __SIZEOF_LONG_DOUBLE__ tells the two apart exactly
 * as src/math/ldbl_math.h's SPICULE_LDBL_EXTENDED does. Before this fix these
 * macros were hardcoded to the 80-bit values even for the tcc/NT
 * build, where they described a range and precision the actual 8-byte
 * object does not have. */
#if defined(__SIZEOF_LONG_DOUBLE__) && __SIZEOF_LONG_DOUBLE__ > 8

#define LDBL_TRUE_MIN 3.6451995318824746025e-4951L
#define LDBL_MIN     3.3621031431120935063e-4932L
#define LDBL_MAX     1.1897314953572317650e+4932L
#define LDBL_EPSILON 1.0842021724855044340e-19L

#define LDBL_MANT_DIG 64
#define LDBL_MIN_EXP (-16381)
#define LDBL_MAX_EXP 16384

#define LDBL_DIG 18
#define LDBL_MIN_10_EXP (-4931)
#define LDBL_MAX_10_EXP 4932

#define DECIMAL_DIG 21

#else /* long double is really just double here -- mirror DBL_* exactly */

#define LDBL_TRUE_MIN 4.94065645841246544177e-324L
#define LDBL_MIN     2.22507385850720138309e-308L
#define LDBL_MAX     1.79769313486231570815e+308L
#define LDBL_EPSILON 2.22044604925031308085e-16L

#define LDBL_MANT_DIG 53
#define LDBL_MIN_EXP (-1021)
#define LDBL_MAX_EXP 1024

#define LDBL_DIG 15
#define LDBL_MIN_10_EXP (-307)
#define LDBL_MAX_10_EXP 308

#define DECIMAL_DIG 17

#endif
