/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * SPICULE_LDBL_EXTENDED: the one macro every piece of `long double`
 * bit-layout code in this tree -- src/math/ldbl_math.h, src/math/
 * fpclassify.c, src/math/frexp.c, src/math/copysign.c, src/math/
 * fabs.c, and (as of the startup canary this header now also serves)
 * src/internal/ldbl_layout_check.c -- tests before trusting any
 * assumption about where `long double`'s sign/exponent/mantissa bits
 * physically sit in memory.
 *
 * C itself guarantees none of that: <float.h>'s constants describe a
 * floating type in an abstract radix/exponent-range/significant-digits
 * model, never a byte layout, and `long double` has no mandated
 * relationship to any specific hardware format at all. This project is
 * built with two compilers that disagree about what `long double` even
 * is on the SAME target:
 *
 *  - tcc's -win32 targets (TCC_TARGET_PE) alias it to plain 8-byte
 *    `double` (matching the MSVC ABI) -- confirmed empirically: this
 *    tcc defines no __*LONG_DOUBLE__ macro at all and reports
 *    sizeof(long double) == 8.
 *  - mingw-w64 gcc (the configure-time dev/test fallback) gives it the
 *    genuine 80-bit x87 extended format, in a 12- (i386) or 16-byte
 *    (x86_64) object.
 *  - A native aarch64 build gives it real IEEE 754 binary128 ("quad"),
 *    always 16 bytes.
 *
 * __SIZEOF_LONG_DOUBLE__ is the one thing every one of those compilers
 * predefines correctly to the TRUE sizeof(long double) for its own
 * ABI (tcc: undefined; gcc/mingw: 12 or 16; a real aarch64 compiler:
 * 16) -- unlike each compiler's own <float.h>, which this tree has
 * already caught being wrong once (see git history: LDBL_MANT_DIG/
 * LDBL_MAX used to be hardcoded to the 80-bit values unconditionally,
 * silently wrong for every tcc-built PE binary). Testing the compiler's
 * own size report, rather than trusting either compiler's <float.h> or
 * assuming a target-name-based answer, is what makes this macro
 * reliable across both toolchains.
 */
#ifndef SPICULE_LDBL_FORMAT_H
#define SPICULE_LDBL_FORMAT_H

#if defined(__SIZEOF_LONG_DOUBLE__) && __SIZEOF_LONG_DOUBLE__ > 8
#define SPICULE_LDBL_EXTENDED 1
#else
#define SPICULE_LDBL_EXTENDED 0
#endif

#endif
