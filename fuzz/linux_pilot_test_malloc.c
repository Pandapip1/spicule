/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * malloc front-door pilot -- NOT part of spicule, same standing as
 * every other fuzz/linux_pilot_test_*.c file.
 *
 * Exercises the REAL src/malloc/malloc.c front door
 * (malloc/calloc/realloc/free/malloc_usable_size/posix_memalign)
 * against the REAL src/malloc/linux/plat_malloc.c backend -- the
 * segregated free-list, mmap-backed allocator that platform needed
 * from scratch, unlike NT, which already has RtlAllocateHeap to
 * delegate to (src/malloc/nt/plat_malloc.c). The check that matters
 * most here is test_no_aliasing(): 2000 concurrently-live allocations
 * of varying sizes, each carrying its own byte-pattern canary, freed
 * and reallocated out of order and re-verified -- this is what would
 * actually catch a free-list corruption bug (a wrong size-class
 * index, or a `next` pointer written past a chunk's real size), which
 * a plain "does malloc return non-NULL" smoke test would not.
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern int printf(const char *, ...);

static int failures, checks;
#define CHECK(cond, msg) do { \
	checks++; \
	if (!(cond)) { printf("FAIL - %s\n", msg); failures++; } \
} while (0)

static void fill(unsigned char *p, size_t n, unsigned char seed)
{
	size_t i;
	for (i = 0; i < n; i++) p[i] = (unsigned char)(seed + i);
}

static int check_fill(unsigned char *p, size_t n, unsigned char seed)
{
	size_t i;
	for (i = 0; i < n; i++)
		if (p[i] != (unsigned char)(seed + i)) return 0;
	return 1;
}

static void test_basic(void)
{
	void *p = malloc(64);
	CHECK(p != NULL, "malloc(64) succeeds");
	CHECK(((uintptr_t)p & 15) == 0, "malloc(64) returns 16-byte-aligned pointer");
	/* Exactly 64, not merely >= 64: 64 is one of plat_malloc.c's own
	 * size-class boundaries, so this is also a real check that this
	 * binary is actually exercising THIS allocator and not silently
	 * linking against the host's own malloc instead (this script's
	 * link line has no -nostdlib, so that mistake is a real
	 * possibility, not a hypothetical one) -- a host glibc reports 72
	 * for this same call (its own chunk-header rounding), confirmed
	 * empirically while writing this test, not assumed. */
	CHECK(malloc_usable_size(p) == 64, "malloc_usable_size(malloc(64)) is exactly 64 (this allocator's own size class, not glibc's)");
	fill(p, 64, 0x11);
	CHECK(check_fill(p, 64, 0x11), "written bytes read back unchanged");
	free(p);

	p = malloc(0);
	CHECK(p != NULL, "malloc(0) returns a real, freeable pointer");
	free(p);

	p = calloc(16, 4);
	CHECK(p != NULL, "calloc(16,4) succeeds");
	{
		size_t i;
		unsigned char *c = p;
		int allzero = 1;
		for (i = 0; i < 64; i++) if (c[i] != 0) allzero = 0;
		CHECK(allzero, "calloc() zero-fills");
	}
	free(p);
}

static void test_calloc_overflow(void)
{
	void *p = calloc((size_t)-1, 2);
	CHECK(p == NULL, "calloc() overflow is rejected, not silently truncated");
}

static void test_realloc(void)
{
	unsigned char *p = malloc(32);
	fill(p, 32, 0x42);
	p = realloc(p, 512);
	CHECK(p != NULL, "realloc() growing succeeds");
	CHECK(check_fill(p, 32, 0x42), "realloc() growing preserves original content");
	CHECK(malloc_usable_size(p) >= 512, "usable size grew");

	p = realloc(p, 8);
	CHECK(p != NULL, "realloc() shrinking succeeds");
	CHECK(check_fill(p, 8, 0x42), "realloc() shrinking preserves surviving content");
	free(p);

	p = realloc(NULL, 100);
	CHECK(p != NULL, "realloc(NULL, n) behaves as malloc(n)");
	free(p);
}

static void test_large(void)
{
	/* Bigger than the largest size class (32768) -- exercises the
	 * direct-mmap path. */
	size_t n = 200000;
	unsigned char *p = malloc(n);
	CHECK(p != NULL, "large (200000-byte) malloc succeeds");
	CHECK(((uintptr_t)p & 15) == 0, "large allocation is also 16-byte-aligned");
	fill(p, n, 0x77);
	CHECK(check_fill(p, n, 0x77), "large allocation holds its full content without corruption");
	CHECK(malloc_usable_size(p) >= n, "usable size for a large allocation is at least what was requested");
	free(p);
}

static void test_posix_memalign(void)
{
	void *p = NULL;
	int r = posix_memalign(&p, 4096, 100);
	CHECK(r == 0 && p != NULL, "posix_memalign(4096, 100) succeeds");
	CHECK(((uintptr_t)p & 4095) == 0, "posix_memalign() honors the requested alignment");
	fill(p, 100, 0x99);
	CHECK(check_fill(p, 100, 0x99), "posix_memalign() block holds content correctly");
	free(p);
}

#define NLIVE 2000
static unsigned char *ptrs[NLIVE];
static size_t sizes[NLIVE];

static void test_no_aliasing(void)
{
	int i;
	unsigned int seed = 12345;

	for (i = 0; i < NLIVE; i++) {
		seed = seed * 1103515245u + 12345u;
		size_t sz = 1 + (seed % 5000);
		sizes[i] = sz;
		ptrs[i] = malloc(sz);
		if (!ptrs[i]) {
			printf("FAIL - malloc() in aliasing test returned NULL at i=%d\n", i);
			failures++; checks++;
			return;
		}
		fill(ptrs[i], sz, (unsigned char)i);
	}

	for (i = 0; i < NLIVE; i += 3) {
		free(ptrs[i]);
		seed = seed * 1103515245u + 12345u;
		size_t sz = 1 + (seed % 5000);
		sizes[i] = sz;
		ptrs[i] = malloc(sz);
		fill(ptrs[i], sz, (unsigned char)(i + 1));
	}

	{
		int ok = 1;
		for (i = 0; i < NLIVE; i++) {
			unsigned char seedbyte = (unsigned char)((i % 3 == 0) ? i + 1 : i);
			if (!check_fill(ptrs[i], sizes[i], seedbyte)) { ok = 0; break; }
		}
		CHECK(ok, "2000 concurrently-live, interleaved-free/realloc allocations never alias or corrupt each other");
	}

	for (i = 0; i < NLIVE; i++) free(ptrs[i]);
}

int main(void)
{
	test_basic();
	test_calloc_overflow();
	test_realloc();
	test_large();
	test_posix_memalign();
	test_no_aliasing();

	printf("\n%s\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
	return failures ? 1 : 0;
}
