/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The four AddressSanitizer entry points fuzz/ntstubs.c calls, supplied
 * for the build that has no AddressSanitizer in it (SPICULE_SAN_MODE=ubsan,
 * where those four names are simply undefined otherwise).
 *
 * A name-resolution shim, not a replacement allocator: each function
 * forwards to the host libc's, so ntstubs.c gets glibc's malloc rather
 * than ASan's -- no redzones, no quarantine, no LeakSanitizer. Nothing
 * here can put those back.
 *
 * dlsym, not a direct call to malloc(): `malloc` in this link is
 * *spicule's* (src/malloc/malloc.o is in the link and the static linker
 * binds to the definition it can already see), so calling it here would
 * route RtlAllocateHeap back into the allocator implemented in terms of
 * RtlAllocateHeap. An explicit libc.so.6 handle reaches glibc's instead.
 *
 * Compiled against the HOST headers, like host_oracle.c and unlike
 * everything else in this directory -- it has to agree with glibc about
 * size_t and malloc_usable_size, not with spicule.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

static void *libc(void)
{
	static void *h;
	if (!h) {
		h = dlopen("libc.so.6", RTLD_LAZY | RTLD_LOCAL);
		if (!h) { fprintf(stderr, "ubsanshim: %s\n", dlerror()); abort(); }
	}
	return h;
}

static void *sym(const char *n)
{
	void *p = dlsym(libc(), n);
	if (!p) { fprintf(stderr, "ubsanshim: no %s\n", n); abort(); }
	return p;
}

void *__interceptor_malloc(size_t n)
{
	static void *(*f)(size_t);
	if (!f) f = (void *(*)(size_t))sym("malloc");
	return f(n);
}

void __interceptor_free(void *p)
{
	static void (*f)(void *);
	if (!f) f = (void (*)(void *))sym("free");
	f(p);
}

void *__interceptor_realloc(void *p, size_t n)
{
	static void *(*f)(void *, size_t);
	if (!f) f = (void *(*)(void *, size_t))sym("realloc");
	return f(p, n);
}

/* RtlSizeHeap's answer. malloc_usable_size() returns the size of the
 * BUCKET (>= the requested size), where __sanitizer_get_allocated_size()
 * under ASan returns exactly what was asked for -- a real difference,
 * though harmless for its one caller today, spicule's own
 * malloc_usable_size(), whose documented answer IS the bucket size. */
size_t __sanitizer_get_allocated_size(const void *p)
{
	static size_t (*f)(void *);
	if (!f) f = (size_t (*)(void *))sym("malloc_usable_size");
	return f((void *)p);
}

/* __lsan_disable()/__lsan_enable() bracket a region whose allocations
 * LeakSanitizer should not report. fuzz_shparse.c uses them around a
 * deliberately-leaked parse, and libFuzzer's own ExternalFunctions
 * constructor references them too, so without definitions the link fails
 * outright in this mode. No-ops are exactly right: with no
 * LeakSanitizer, there is no leak detection to suspend, so
 * fuzz_shparse's leak fence is simply vacuous here.
 */
void __lsan_disable(void) { }
void __lsan_enable(void) { }
