/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Floating point <-> 64-bit integer conversion helpers for tcc.
 *
 * tcc emits calls to __fix*di for every float-to-integer conversion on
 * i386 (it takes the low 32 bits itself when the target is int), and to
 * __fixuns*di / __floatundi* for the unsigned long long cases on both
 * architectures.  The float-to-integer direction is done by picking the
 * IEEE representation apart with unions: a cast here would compile into
 * a call to the very helper being defined.
 */
#include "rtlib.h"
#include "ldbl_format.h"

union fbits { float f; unsigned u; };
union dbits { double d; struct { unsigned lo, hi; } u; };
#if SPICULE_LDBL_EXTENDED
/* x87 extended: 64-bit explicit mantissa, then sign+15-bit exponent. */
union xbits { long double x; struct { unsigned lo, hi; unsigned short se; } u; };
#endif

/* Build a 64-bit value from a 64-bit mantissa `m` scaled by 2^e. */
static unsigned long long scale64(unsigned long long m, int e)
{
	while (e > 0) {
		if (m & 0x8000000000000000uLL) return ~0uLL;  /* saturate */
		m += m;
		e--;
	}
	while (e < 0 && m) { m >>= 1; e++; }
	return m;
}

unsigned long long __fixunssfdi(float a)
{
	union fbits b;
	int exp;
	unsigned long long m;
	b.f = a;
	exp = (int)((b.u >> 23) & 0xff);
	if (!exp || (b.u & 0x80000000u)) return 0;   /* zero, denormal, negative */
	if (exp == 0xff) return ~0uLL;               /* inf/nan: saturate */
	m = (b.u & 0x7fffffu) | 0x800000u;
	return scale64(m, exp - 127 - 23);
}

unsigned long long __fixunsdfdi(double a)
{
	union dbits b;
	int exp;
	unsigned long long m;
	b.d = a;
	exp = (int)((b.u.hi >> 20) & 0x7ff);
	if (!exp || (b.u.hi & 0x80000000u)) return 0;
	if (exp == 0x7ff) return ~0uLL;
	m = ((unsigned long long)((b.u.hi & 0xfffffu) | 0x100000u) << 32) | b.u.lo;
	return scale64(m, exp - 1023 - 52);
}

unsigned long long __fixunsxfdi(long double a)
{
#if SPICULE_LDBL_EXTENDED
	union xbits b;
	int exp;
	unsigned long long m;
	b.x = a;
	exp = b.u.se & 0x7fff;
	if (!exp || (b.u.se & 0x8000)) return 0;
	if (exp == 0x7fff) return ~0uLL;
	m = ((unsigned long long)b.u.hi << 32) | b.u.lo;
	return scale64(m, exp - 16383 - 63);
#else
	/* This tcc's i386 -win32 target aliases long double to double
	 * (MSVC ABI): sizeof(long double) == 8 here, not the 10/12-byte
	 * 80-bit extended layout union xbits above assumes.  Decoding it
	 * as 80-bit storage in that build would read past the object. */
	return __fixunsdfdi((double)a);
#endif
}

static long long signed_magnitude(unsigned long long magnitude, int negative)
{
	/* -2^63 is representable, but casting its magnitude to long long and
	 * then negating evaluates -LLONG_MIN.  Values beyond the signed range
	 * have undefined conversion semantics in C; saturating them also keeps
	 * this toolchain helper itself free of UB and implementation-defined
	 * unsigned-to-signed narrowing. */
	if (magnitude >= 0x8000000000000000uLL)
		return negative ? (-0x7fffffffffffffffLL - 1) : 0x7fffffffffffffffLL;
	return negative ? -(long long)magnitude : (long long)magnitude;
}

long long __fixsfdi(float a)
{
	return a < 0 ? signed_magnitude(__fixunssfdi(-a), 1)
		: signed_magnitude(__fixunssfdi(a), 0);
}

long long __fixdfdi(double a)
{
	return a < 0 ? signed_magnitude(__fixunsdfdi(-a), 1)
		: signed_magnitude(__fixunsdfdi(a), 0);
}

long long __fixxfdi(long double a)
{
	return a < 0 ? signed_magnitude(__fixunsxfdi(-a), 1)
		: signed_magnitude(__fixunsxfdi(a), 0);
}

/* unsigned long long -> floating point.  The signed conversion is native
 * (x87 fild / cvtsi2sd), so lean on it: halve an out-of-range value,
 * convert, double, and patch the dropped bit back in. */

double __floatundidf(unsigned long long a)
{
	if (a <= 0x7fffffffffffffffuLL) return (double)(long long)a;
	return (double)(long long)(a >> 1) * 2.0 + (double)(int)(a & 1uLL);
}

float __floatundisf(unsigned long long a)
{
	if (a <= 0x7fffffffffffffffuLL) return (float)(long long)a;
	return (float)((float)(long long)(a >> 1) * 2.0f);
}

long double __floatundixf(unsigned long long a)
{
	if (a <= 0x7fffffffffffffffuLL) return (long double)(long long)a;
	return (long double)(long long)(a >> 1) * 2.0L + (long double)(int)(a & 1uLL);
}
