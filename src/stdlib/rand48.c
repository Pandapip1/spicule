/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
/* The 48-bit linear congruential family of SVID. */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <features.h>
#include "ownership_stubs.h"

/* drand48.html's process-start initializer is Xi = 0.  This is distinct
 * from srand48(seed), which explicitly installs 0x330e in the low word. */
static unsigned short xsubi_default[3];
static unsigned short a_[3] = { 0xe66d, 0xdeec, 0x5 };
static unsigned short c_ = 0xb;

/* a and x are only guaranteed < 2**48 (lcong48 lets a caller widen a_[2]
 * up to 0xffff), so a*x can in principle overflow uint64_t.  That is
 * harmless: only the low 48 bits, masked out below, are ever used, and
 * modular arithmetic guarantees those are the same whether or not the
 * 64-bit multiply itself wrapped first (48 <= 64). */
__wraps static uint64_t step(unsigned short xi[3])
{
	uint64_t x = (uint64_t)xi[0] | ((uint64_t)xi[1] << 16) | ((uint64_t)xi[2] << 32);
	uint64_t a = (uint64_t)a_[0] | ((uint64_t)a_[1] << 16) | ((uint64_t)a_[2] << 32);
	x = (a * x + c_) & 0xffffffffffffULL;
	xi[0] = (unsigned short)x; xi[1] = (unsigned short)(x >> 16); xi[2] = (unsigned short)(x >> 32);
	return x;
}

double erand48(unsigned short s[3]) { return (double)step(s) / 281474976710656.0; }
double drand48(void) { return erand48(xsubi_default); }
long nrand48(unsigned short s[3]) { return (long)(step(s) >> 17); }
long lrand48(void) { return nrand48(xsubi_default); }
long jrand48(unsigned short s[3]) { return (long)(int32_t)(uint32_t)(step(s) >> 16); }
long mrand48(void) { return jrand48(xsubi_default); }

void srand48(long seed)
{
	xsubi_default[0] = 0x330e;
	xsubi_default[1] = (unsigned short)seed;
	xsubi_default[2] = (unsigned short)((unsigned long)seed >> 16);
	a_[0] = 0xe66d; a_[1] = 0xdeec; a_[2] = 0x5; c_ = 0xb;
}

unsigned short *seed48(unsigned short s[3])
{
	static unsigned short old[3];
	memcpy(old, xsubi_default, sizeof old);
	unsafe_assume_readable_span(s, sizeof old);
	memcpy(xsubi_default, s, sizeof old);
	a_[0] = 0xe66d; a_[1] = 0xdeec; a_[2] = 0x5; c_ = 0xb;
	return old;
}

void lcong48(unsigned short p[7])
{
	unsafe_assume_readable_span(p, 3 * sizeof(unsigned short));
	memcpy(xsubi_default, p, 3 * sizeof(unsigned short));
	unsafe_assume_readable_span(p + 3, 3 * sizeof(unsigned short));
	memcpy(a_, p + 3, 3 * sizeof(unsigned short));
	c_ = p[6];
}
