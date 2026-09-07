/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
/* random/srandom/initstate/setstate: the BSD additive feedback
 * generator (x[i] = x[i-3] + x[i-31]), the same sequence glibc and musl
 * produce for the default 128-byte state. */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <features.h>

static uint32_t init_state[32];   /* 31 words of state + 1 slot */
static uint32_t *x = init_state + 1;
static int n = 31, i = 3, j = 0;

__wraps static long random_step(void);

/* Both LCGs are meant to overflow -- that is the generator, taken
 * modulo 2**32/2**64 by construction, used only to seed the additive
 * generator below. */
__wraps static uint32_t lcg31(uint32_t v) { return (1103515245u * v + 12345u) & 0x7fffffff; }
__wraps static uint64_t lcg64(uint64_t v) { return 6364136223846793005ULL * v + 1; }

static void seed_state(unsigned s)
{
	int k;
	if (n == 0) { x[0] = s; return; }
	i = n == 31 || n == 7 ? 3 : 1;
	j = 0;
	if (n == 31 || n == 7) {
		uint32_t v = s ? s : 1;
		for (k = 0; k < n; k++) { x[k] = v; v = lcg31(v); }
	} else {
		uint64_t v = s ? s : 1;
		for (k = 0; k < n; k++) { x[k] = (uint32_t)(v >> 32); v = lcg64(v); }
	}
	for (k = 0; k < n; k++) {
		int round;
		for (round = 0; round < 10; round++) (void)random_step();
	}
}

static int random_initialised;
static void ensure_init(void)
{
	if (!random_initialised) { random_initialised = 1; seed_state(1); }
}

void srandom(unsigned s) { random_initialised = 1; seed_state(s); }

char *initstate(unsigned s, char *state, size_t size)
{
	char *old;
	ensure_init();
	if (size < 8) return 0;
	x[-1] = (uint32_t)((n << 16) | ((unsigned)i << 8) | (unsigned)j);
	old = (char *)(x - 1);
	if (size < 32) n = 0;
	else if (size < 64) n = 7;
	else if (size < 128) n = 15;
	else if (size < 256) n = 31;
	else n = 63;
	x = (uint32_t *)state + 1;
	seed_state(s);
	x[-1] = (uint32_t)((n << 16) | ((unsigned)i << 8) | (unsigned)j);
	return old;
}

char *setstate(char *state)
{
	char *old;
	ensure_init();
	x[-1] = (uint32_t)((n << 16) | ((unsigned)i << 8) | (unsigned)j);
	old = (char *)(x - 1);
	x = (uint32_t *)state + 1;
	n = (int)(x[-1] >> 16);
	i = (int)((x[-1] >> 8) & 0xff);
	j = (int)(x[-1] & 0xff);
	return old;
}

/* x[i] += x[j] is the additive feedback generator itself (x[i] =
 * x[i-3] + x[i-31] mod 2**32) -- the overflow is the point, not a bug,
 * and matches glibc/musl's sequence exactly because they rely on the
 * same wraparound. */
__wraps static long random_step(void)
{
	uint32_t k;
	if (n == 0) { x[0] = lcg31(x[0]); return (long)x[0]; }
	x[i] += x[j];
	k = x[i] >> 1;
	if (++i == n) i = 0;
	if (++j == n) j = 0;
	return (long)k;
}

__wraps long random(void)
{
	ensure_init();
	return random_step();
}

// NOLINTEND(misc-include-cleaner)
