/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Real, running proof of src/dlfcn/linux/plat_dlfcn.c -- the from-
 * scratch ELF64 loader behind dlopen()/dlsym()/dlclose()/dlerror() on
 * the Linux platform pilot. Built and linked entirely on spicule's OWN
 * startup and library code (tools/linux-build-dlfcn.sh: crt/linux/
 * crt1.c + crt/linux/aarch64/start.S + the real lib/libc.a, -nostdlib
 * -static -no-pie -- no host crt, no host libc), the same discipline
 * tools/linux-build-crt.sh established: this program IS the "running
 * binary" plat_dlfcn.c's resolve_main_symbol() reads back out of
 * /proc/self/exe, so this is also the only realistic way to exercise
 * that path -- a host-crt-linked test (tools/linux-build-malloc.sh's
 * lighter-weight pattern) would be a PIE binary belonging to the HOST's
 * glibc, not the non-PIE, spicule-owned image this design assumes.
 *
 * fuzz/linux_pilot_test_dlopen_lib.c is the target .so this dlopen()s
 * (see that file's own banner for exactly which relocation types this
 * exercises and why). fuzz/linux_pilot_test_dlopen_tlslib.c is a
 * second, deliberately TLS-bearing .so -- it used to prove this pass's
 * documented PT_TLS REFUSAL fired; now that per-object TLS is
 * implemented for aarch64 (see plat_dlfcn.c's own "TLS / per-library
 * thread descriptors" banner), it instead proves the real thing works:
 * a dlopen()'d object's own __thread variable is readable/writable, and
 * two independent dlopen() instances of the SAME .so get two genuinely
 * separate TLS blocks (own TD per library, not aliased), exactly like
 * the non-TLS namespace-isolation proof further down already does for
 * ordinary data.
 *
 * host_provided_value() below is what fuzz/linux_pilot_test_dlopen_
 * lib.c's use_host_value() calls through an unresolved-at-link-time
 * R_AARCH64_JUMP_SLOT relocation -- proving plat_dlfcn.c's "symbol
 * resolution against the static binary" mechanism resolves a real
 * symbol that exists ONLY in this program's own (non-stripped)
 * .symtab, nowhere else.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef int (*fnptr)(int);
typedef int (*fnptr0)(void);

int host_provided_value(void) { return 7; }

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

int main(void)
{
	void *h, *h2, *mh, *bad;
	fnptr0 dlso_answer, dlso_answer2, use_host_value;
	fnptr call_add_one;
	fnptr *table;
	fnptr0 self_host_value;
	char *e;

	/* ---- basic load + symbol resolution + relocation proof ------- */
	h = dlopen("./linux_pilot_test_dlopen_lib.so", RTLD_NOW);
	if (!h) { printf("dlopen failed: %s\n", dlerror()); return 1; }

	dlso_answer = (fnptr0)dlsym(h, "dlso_answer");
	call_add_one = (fnptr)dlsym(h, "call_add_one");
	use_host_value = (fnptr0)dlsym(h, "use_host_value");
	table = (fnptr *)dlsym(h, "exported_table");

	CHECK(dlso_answer && dlso_answer() == 42);
	CHECK(call_add_one && call_add_one(5) == 7);
	/* Proves R_AARCH64_JUMP_SLOT resolution against THIS program's own
	 * symtab (host_provided_value is defined only here, never in the
	 * .so or in any host library -- the .so links against nothing). */
	CHECK(use_host_value && use_host_value() == 107);
	/* Proves R_AARCH64_RELATIVE: exported_table's own two entries are
	 * load-address-relative function pointers, fixed up at dlopen()
	 * time -- calling through them only works if that fixup happened. */
	CHECK(table && table[0] && table[0](10) == 11);
	CHECK(table && table[1] && table[1](10) == 12);

	CHECK(dlclose(h) == 0);

	/* ---- dlopen(NULL, ...) + dlsym: the main image's own symbols -- */
	mh = dlopen(NULL, RTLD_NOW);
	CHECK(mh != NULL);
	self_host_value = (fnptr0)dlsym(mh, "host_provided_value");
	CHECK(self_host_value && self_host_value() == 7);

	/* ---- namespace isolation: two independent instances ----------- */
	h = dlopen("./linux_pilot_test_dlopen_lib.so", RTLD_NOW);
	h2 = dlopen("./linux_pilot_test_dlopen_lib.so", RTLD_NOW);
	CHECK(h && h2);
	CHECK(h != h2); /* no dedup -- see plat_dlfcn.c's own banner */
	dlso_answer = (fnptr0)dlsym(h, "dlso_answer");
	dlso_answer2 = (fnptr0)dlsym(h2, "dlso_answer");
	CHECK(dlso_answer && dlso_answer2);
	CHECK(dlso_answer != dlso_answer2); /* genuinely separate mappings, not aliased */
	CHECK(dlso_answer && dlso_answer() == 42);
	CHECK(dlso_answer2 && dlso_answer2() == 42);
	CHECK(dlclose(h) == 0);
	CHECK(dlclose(h2) == 0);

	/* ---- dlerror(): single-shot front door over a sticky backend -- */
	bad = dlopen("./no-such-file.so", RTLD_NOW);
	CHECK(bad == NULL);
	e = dlerror();
	CHECK(e != NULL && strstr(e, "no-such-file.so") != NULL);
	CHECK(dlerror() == NULL); /* single-shot: NULL immediately after */

	/* ---- PT_TLS: real per-object TLS, not a refusal any more ------ */
	{
		void *t1, *t2;
		fnptr0 bump1, bump2;

		t1 = dlopen("./linux_pilot_test_dlopen_tlslib.so", RTLD_NOW);
		if (!t1) printf("dlopen tlslib failed: %s\n", dlerror());
		CHECK(t1 != NULL);
		bump1 = (fnptr0)dlsym(t1, "bump_tls_counter");
		CHECK(bump1 != NULL);
		CHECK(bump1 && bump1() == 1);
		CHECK(bump1 && bump1() == 2);
		CHECK(bump1 && bump1() == 3);

		/* A second, independent dlopen() of the byte-identical .so gets
		 * its OWN TLS block (own TD per library -- see plat_dlfcn.c's
		 * own TLS banner), not a second reference to the first's: its
		 * counter starts back at 1 even though t1's is already at 3. */
		t2 = dlopen("./linux_pilot_test_dlopen_tlslib.so", RTLD_NOW);
		CHECK(t2 != NULL && t2 != t1);
		bump2 = (fnptr0)dlsym(t2, "bump_tls_counter");
		CHECK(bump2 != NULL);
		CHECK(bump2 && bump2() == 1);
		/* t1's own counter is untouched by t2's calls. */
		CHECK(bump1 && bump1() == 4);

		CHECK(dlclose(t1) == 0);
		CHECK(dlclose(t2) == 0);
	}

	if (fails) {
		printf("%d CHECK(S) FAILED\n", fails);
		return 1;
	}
	printf("ALL DLOPEN TESTS PASS\n");
	return 0;
}
