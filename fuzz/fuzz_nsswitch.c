/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * __nsswitch_order() -- src/netdb/linux/nsswitch.c's real
 * /etc/nsswitch.conf(5) parser, shared by src/netdb/linux/
 * hosts_resolve.c and src/misc/linux/{pwd,grp}.c (src/internal/
 * nsswitch.h has the full contract).
 *
 * src/netdb/linux/ is not part of the library ../tools/asan-build.sh
 * builds for every other harness (this native harness exercises the NT
 * backend through ntstubs.c, and src/netdb/nt/plat_netdb.c never calls
 * __nsswitch_order() at all), so this function is simply absent from
 * that library today. __nsswitch_order() itself has no NT dependency at
 * all (fopen(), fgets(), fclose(), strchr(), strncmp(), tolower(),
 * nothing else -- fopen() reaches ntstubs.c's own simulated in-memory
 * volume the same way every other native fuzz/test binary's file I/O
 * does), so rather than widen asan-build.sh's file selection,
 * fuzz/Makefile compiles the real nsswitch.c once on its own and links
 * the result into this harness alone, the same shape ntstubs.o/
 * host_oracle.o already use. Nothing in nsswitch.c was changed:
 * __nsswitch_order() was already non-static and already declared in
 * src/internal/nsswitch.h, unlike resolv.c's parse_response() (see
 * fuzz_resolv.c's own header for that one).
 *
 * __nsswitch_order() does not take a buffer -- fopen(__NSS_NSSWITCH_PATH(),
 * "r") is baked into it, and there is no lower buffer-taking entry point
 * underneath. src/internal/nss_paths.h's own banner describes the seam
 * that already exists for exactly this: __NSS_NSSWITCH_PATH() expands to
 * __nss_path("SPICULE_TEST_NSSWITCH_PATH", "/etc/nsswitch.conf"), an
 * undocumented env-var override this library's own test fixtures use,
 * with TZ and HOSTALIASES as precedent. This harness uses that same
 * seam: it fwrite()s the fuzz input into a path inside ntstubs.c's own
 * simulated volume, then setenv()s SPICULE_TEST_NSSWITCH_PATH to that
 * path before calling __nsswitch_order().
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nsswitch.h"

extern void oracle_mismatch_i(const char *, const char *, long long, long long);

/* Bigger than NSS_LINE_MAX (512, nsswitch.c's own fgets() buffer): a
 * fuzzer-sized file exercises both ordinary lines and the "one real
 * line split across more than one fgets() call" case nsswitch.c's own
 * comment above its main loop documents as deliberately tolerated. */
#define CAP 2048
#define GUARD 0xC7
#define NCAP 8    /* out[]'s capacity; __nsswitch_order's real callers use 4 */

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	static const char *const dbs[4] = { "hosts", "passwd", "group", "shadow" };
	unsigned char ctl;
	int max, dbidx, r, r2;
	const char *db;
	char content[CAP];
	size_t n, i;
	FILE *f;
	struct {
		unsigned char pre[16];
		enum __nss_service arr[NCAP];
		unsigned char post[16];
	} buf;
	unsigned char *raw = (unsigned char *)&buf;

	if (size < 1) return 0;
	ctl = data[0];
	data++; size--;

	max = ctl % NCAP;                  /* 0..7: always leaves >=1 guard slot */
	dbidx = (ctl >> 3) & 0x03;
	db = dbs[dbidx];

	n = size < CAP ? size : CAP;
	memcpy(content, data, n);

	/* A path inside ntstubs.c's own simulated volume, not a real host
	 * file. "w" truncates, so each call starts the fixture fresh. */
	f = fopen("/fuzz_nsswitch.conf", "w");
	if (!f) return 0;
	if (n && fwrite(content, 1, n, f) != n) { fclose(f); return 0; }
	if (fclose(f) != 0) return 0;

	if (setenv("SPICULE_TEST_NSSWITCH_PATH", "/fuzz_nsswitch.conf", 1) != 0)
		return 0;

	memset(&buf, GUARD, sizeof buf);
	r = __nsswitch_order(db, buf.arr, max);

	if (r < 0 || r > max)
		oracle_mismatch_i("__nsswitch_order returned outside [0, max]",
		                  db, (long long)r, (long long)max);

	/* Every entry actually written must be one of the two services this
	 * library implements -- the enum's only two members -- never some
	 * other value a corrupted write could produce. */
	for (i = 0; i < (size_t)(r < max ? r : max); i++)
		if (buf.arr[i] != __NSS_SVC_FILES && buf.arr[i] != __NSS_SVC_DNS)
			oracle_mismatch_i("__nsswitch_order wrote an unrecognized service value",
			                  db, (long long)buf.arr[i], (long long)i);

	/* Guard bytes on both sides, plus the unused tail of arr[] itself
	 * (indices [max, NCAP)) -- the same "bring your own guard" discipline
	 * fuzz/Makefile's SAN_MODE comment asks for, since ubsan mode has no
	 * shadow memory to catch an out-of-bounds write on its own. */
	for (i = 0; i < sizeof buf.pre; i++)
		if (raw[i] != GUARD)
			oracle_mismatch_i("__nsswitch_order wrote before its output array",
			                  db, (long long)i, GUARD);
	for (i = (size_t)max; i < NCAP; i++) {
		unsigned char *slot = (unsigned char *)&buf.arr[i];
		size_t j;
		for (j = 0; j < sizeof buf.arr[i]; j++)
			if (slot[j] != GUARD) {
				oracle_mismatch_i("__nsswitch_order wrote past its declared max",
				                  db, (long long)i, (long long)max);
				break;
			}
	}
	for (i = 0; i < sizeof buf.post; i++)
		if (raw[16 + NCAP * sizeof(enum __nss_service) + i] != GUARD)
			oracle_mismatch_i("__nsswitch_order wrote after its output array",
			                  db, (long long)i, GUARD);

	/* Determinism: __nsswitch_order carries no state between calls (it
	 * reopens and re-reads the file fresh every time), so parsing the
	 * same fixture twice must agree, both on the count and on the order. */
	{
		enum __nss_service again[NCAP];
		memset(again, GUARD, sizeof again);
		r2 = __nsswitch_order(db, again, max);
		if (r2 != r)
			oracle_mismatch_i("__nsswitch_order is not deterministic (count)",
			                  db, (long long)r2, (long long)r);
		else if (r > 0 && memcmp(again, buf.arr, (size_t)r * sizeof again[0]) != 0)
			oracle_mismatch_i("__nsswitch_order is not deterministic (order)",
			                  db, 0, 0);
	}

	return 0;
}
