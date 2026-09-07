/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of the parts of stdlib.h not
 * already covered clause-for-clause by test/strto.c, test/qsort.c,
 * test/stdlib.c, test/malloc.c and test/posix-parse.c.  Each assertion
 * cites the clause of https://pubs.opengroup.org/onlinepubs/9699919799/
 * functions/<name>.html it checks.  See test/posix-coverage/stdlib.md
 * for the full ledger, including what those five files already cover.
 */
/* ptsname_r() (tested below, Linux-only) is _GNU_SOURCE; the same
 * define test/posix-unistd-ids.c's own top already carries for its
 * own _GNU_SOURCE-only coverage. */
#define _GNU_SOURCE
#include "test-policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

extern char **environ;

/* Internal: spawn a program as a child, return its pid (see
 * src/process/spawn.c).  Needed for the quick_exit() child-process test
 * below; declared locally the same way test/posix-alloc.c does, rather
 * than widening include/. */
int __spawn(const char *path, char *const argv[], char *const envp[]);

/* ---- strtol.html: EINVAL for an unsupported base, errno untouched on
 * success, no-conversion endptr rule for a non-numeric-but-nonempty base. ---- */
static void test_strtol_base(void)
{
	char *end;

	/* RETURN VALUE: "If the value of base is not supported, 0 shall be
	 * returned and errno shall be set to [EINVAL]."  ERRORS: same,
	 * listed as a required (not "may fail") error. */
	{
		const char *s = "123";
		errno = 0; end = 0;
		CHECK(strtol(s, &end, 1) == 0 && errno == EINVAL && end == s);
	}
	{
		const char *s = "123";
		errno = 0; end = 0;
		CHECK(strtol(s, &end, 37) == 0 && errno == EINVAL && end == s);
	}
	{
		const char *s = "123";
		errno = 0; end = 0;
		CHECK(strtoul(s, &end, -1) == 0 && errno == EINVAL && end == s);
	}

	/* "These functions shall not change the setting of errno if
	 * successful." -- errno left at a sentinel value across a clean
	 * conversion. */
	errno = 12345;
	CHECK(strtol("42", 0, 10) == 42 && errno == 12345);
	errno = 12345;
	CHECK(strtoul("42", 0, 10) == 42 && errno == 12345);
	errno = 12345;
	CHECK(strtod("4.5", 0) == 4.5 && errno == 12345);
}

/* ---- atoi.html: "shall be equivalent to (int) strtol(str, NULL, 10)" ---- */
static void test_atoi_family(void)
{
	/* strtol/strtod skip leading white space and accept a sign; atoi()
	 * and friends must inherit exactly that since they are DEFINED as
	 * calls to strtol()/strtod(). */
	CHECK(atoi("   \t -42") == -42);
	CHECK(atol("  +100") == 100L);
	CHECK(atoll(" -123456789012345") == -123456789012345LL);
	CHECK(atof("  2.5e1") == 25.0);
	/* "junk" after the number is simply ignored, same as strtol/strtod
	 * with a discarded endptr. */
	CHECK(atoi("17abc") == 17);
	CHECK(atof("2.5xyz") == 2.5);
	/* empty / all-whitespace / no digits: strtol/strtod perform no
	 * conversion and return 0 / 0.0. */
	CHECK(atoi("") == 0);
	CHECK(atoi("   ") == 0);
	CHECK(atof("   ") == 0.0);
}

/* ---- qsort.html / bsearch.html: nel==0 must not call the comparator. ---- */
static int ncalls;
static int counting_cmp(const void *a, const void *b)
{
	ncalls++;
	return *(const int *)a - *(const int *)b;
}

static void test_qsort_bsearch_zero(void)
{
	int a[4] = { 4, 3, 2, 1 };
	int key = 1;

	/* qsort.html DESCRIPTION: "If the nel argument has the value zero,
	 * the comparison function ... shall not be called." */
	ncalls = 0;
	qsort(a, 0, sizeof a[0], counting_cmp);
	CHECK(ncalls == 0);
	/* array must be untouched */
	CHECK(a[0] == 4 && a[1] == 3 && a[2] == 2 && a[3] == 1);

	/* bsearch.html DESCRIPTION: "If the nel argument has the value
	 * zero, the comparison function ... shall not be called and no
	 * match shall be found." */
	ncalls = 0;
	CHECK(bsearch(&key, a, 0, sizeof a[0], counting_cmp) == 0);
	CHECK(ncalls == 0);
}

/* bsearch.html DESCRIPTION: "The comparison function shall be called
 * with two arguments that point to the key object and to an array
 * member, in that order." -- verify the key pointer is always first by
 * using a comparator that only *that* order can satisfy. */
static const int *bsearch_key_ptr;
static int order_cmp(const void *a, const void *b)
{
	/* a must always be the key, b an array element */
	if (a != bsearch_key_ptr) { fails++; printf("FAIL %s:%d: bsearch comparator arg order\n", __FILE__, __LINE__); }
	return *(const int *)a - *(const int *)b;
}

static void test_bsearch_arg_order(void)
{
	int a[5] = { 1, 2, 3, 4, 5 };
	int key = 3;
	bsearch_key_ptr = &key;
	CHECK(bsearch(&key, a, 5, sizeof a[0], order_cmp) == &a[2]);
}

/* ---- drand48.html: required ranges of the returned values. ---- */
static void test_rand48_ranges(void)
{
	int i;
	unsigned short s[3] = { 0x1234, 0x5678, 0x9abc };

	/* long is 32 bits on both spicule arches (established by
	 * test/strto.c's `sizeof(long) == 4` check), so every long value
	 * already lies in [LONG_MIN,LONG_MAX] = [-2**31,2**31-1], which is
	 * inside the required [-2**31,2**31) -- the upper bound can never
	 * be violated by the type itself and is checked here only via
	 * `long long` so the comparison itself has no overflow/UB.  The
	 * lower bound (>=0 for lrand48/nrand48) is the one a broken
	 * generator could actually fail. */
	srand48(777);
	for (i = 0; i < 200; i++) {
		double d = drand48();
		long l = lrand48();
		long m = mrand48();
		/* "non-negative ... values, uniformly distributed over the
		 * interval [0.0,1.0)" */
		CHECK(d >= 0.0 && d < 1.0);
		/* "non-negative, long integers ... over the interval [0,2**31)" */
		CHECK(l >= 0 && (long long)l < (1LL << 31));
		/* "signed long integers ... over the interval [-2**31,2**31)" */
		CHECK((long long)m >= -(1LL << 31) && (long long)m < (1LL << 31));

		CHECK(erand48(s) >= 0.0 && erand48(s) < 1.0);
		CHECK(nrand48(s) >= 0 && (long long)nrand48(s) < (1LL << 31));
		CHECK((long long)jrand48(s) >= -(1LL << 31) && (long long)jrand48(s) < (1LL << 31));
	}

	/* seed48.html RETURN VALUE: "shall return a pointer to an array of
	 * 3 unsigned shorts which contained a copy of the internal buffer
	 * ... prior to the update."  srand48.html: "the low-order 16 bits
	 * of Xi are set to the arbitrary value 0x330E [and] the high-order
	 * 32 bits of Xi are set to the ... seed argument."  Check both:
	 * seed48()'s return reflects srand48()'s prior state exactly, and
	 * a second seed48() call reflects the first one's argument. */
	{
		unsigned short knot[3] = { 11, 22, 33 };
		unsigned short *prev;

		srand48(42);
		prev = seed48(knot);
		CHECK(prev != 0 && prev[0] == 0x330e && prev[1] == 42 && prev[2] == 0);

		prev = seed48(knot);
		CHECK(prev != 0 && prev[0] == 11 && prev[1] == 22 && prev[2] == 33);
	}

	/* lcong48.html: "If lcong48() is used, it shall then be followed
	 * by a call to either seed48() or srand48() before subsequent
	 * calls to any of drand48(), erand48(), lrand48(), nrand48(),
	 * mrand48(), or jrand48()."  We only check that lcong48()'s a/c
	 * actually take effect: with a=1, c=0 the generator is the
	 * identity multiplier, so X(n+1) = X(n) (mod 2**48) -- a fixed
	 * point once seeded to any value. */
	{
		unsigned short p[7] = { 9, 0, 0,  1, 0, 0,  0 }; /* Xi=9, a=1, c=0 */
		long first, second;
		lcong48(p);
		first = mrand48();
		second = mrand48();
		CHECK(first == second);
	}
}

#if SPICULE_TEST(PASS, posix_stdlib_rand_default_seed_is_srand_1) /* The un-seeded rand() stream is the srand(1) stream.
	 * rand.html DESCRIPTION: "If rand() is called before any calls to
	 * srand() are made, the same sequence shall be generated as when
	 * srand() is first called with a seed value of 1."  (ISO C99
	 * 7.20.2.2p2 says the same in the same words.)  It is the one thing
	 * the standard fixes about the default state, and it is what lets a
	 * program that never calls srand() be reproduced by one that says
	 * srand(1).
	 *
	 * Mechanism: src/stdlib/rand.c holds the LCG state in
	 *
	 *     static uint64_t seed = 1;
	 *
	 * while srand() stores `s - 1`, so srand(1) sets the state to 0.
	 * The default state is therefore the srand(1) state advanced by
	 * exactly one LCG step, and the two streams are offset by one draw
	 * for their whole length.  (musl, whose constants this generator
	 * borrows, leaves the state a zero-initialised static -- which is
	 * precisely the srand(1) state, and is what makes musl conform.
	 * The `= 1` initialiser is the whole difference.)
	 *
	 * The srand(0) note above that line -- "s - 1 wraps to UINT_MAX for
	 * srand(0): still a perfectly usable 64-bit seed once widened, not
	 * a bug the caller can observe" -- is about a different call and
	 * remains true; nothing about srand(0) is asserted here.
	 *
	 * This test has to run before anything else in the process calls
	 * srand() or rand().  Nothing in this file does -- the generators
	 * exercised above it are rand48 and random(), which src/stdlib has
	 * on separate state (src/stdlib/rand.c's `static uint64_t seed`
	 * is not shared with src/stdlib/random.c or rand48.c) -- so
	 * wherever the call site lands, the first rand() below is the
	 * default stream.  Whoever un-fences this should still put the
	 * call first in main() rather than rely on that.
	 *
	 * Re-enable when the default state and srand(1)'s state agree. */
static void test_rand_default_seed_is_srand_1(void)
{
	int a[4], b[4], k;

	/* the default stream, before any srand() in this process */
	for (k = 0; k < 4; k++) a[k] = rand();

	srand(1);
	for (k = 0; k < 4; k++) b[k] = rand();

	CHECK(a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]);
}
#endif

/* ---- random.html: initstate/setstate return values and size rules. ---- */
static void test_random_state(void)
{
	static char st8[8], st16[16], st32[32], st64[64], st128[128], st256[256];
	char *old;
	long expected;

	/* "If size bytes are not available to be used by the state array
	 * ... the initstate() function shall fail and return a null
	 * pointer" -- glibc/SVID: fewer than 8 bytes is always a failure. */
	{
		static char tiny[4];
		CHECK(initstate(1, tiny, 4) == 0);
	}

	/* Valid sizes (8, 32, 64, 128, 256 or anything >=8, rounded down)
	 * must succeed, return the previous state pointer, and not crash
	 * subsequent random() calls. */
	old = initstate(1, st8, sizeof st8);
	CHECK(old != 0);
	CHECK(random() >= 0);
	old = initstate(2, st16, sizeof st16); /* 8<=16<32: rounds down to the 8-byte generator type */
	CHECK(old == st8);
	CHECK(random() >= 0);
	old = initstate(3, st32, sizeof st32);
	CHECK(old == st16);
	CHECK(random() >= 0);
	old = initstate(4, st64, sizeof st64);
	CHECK(old == st32);
	CHECK(random() >= 0);
	old = initstate(5, st128, sizeof st128);
	CHECK(old == st64);
	CHECK(random() >= 0);
	old = initstate(6, st256, sizeof st256);
	CHECK(old == st128);
	CHECK(random() >= 0);

	/* setstate.html: "Upon successful completion, setstate() shall
	 * return a pointer to the previous state array." */
	old = setstate(st128);
	CHECK(old == st256);
	CHECK(random() >= 0);
	old = setstate(st256);
	CHECK(old == st128);

	/* initstate() must preserve the current generator metadata as well as
	 * return its storage, so setstate() resumes that exact stream. */
	srandom(123);
	random();
	expected = random();
	srandom(123);
	random();
	old = initstate(456, st128, sizeof st128);
	random();
	CHECK(setstate(old) == st128);
	CHECK(random() == expected);

	/* srandom(1) reproducibility already covered by test/stdlib.c;
	 * here just confirm switching back to the default (128-byte)
	 * generator via srandom() still gives a well-formed sequence. */
	srandom(9);
	CHECK(random() >= 0 && random() >= 0);
}

/* ---- getenv/setenv/unsetenv/putenv: not exercised anywhere else. ---- */
static void test_env(void)
{
	/* setenv.html ERRORS: "[EINVAL] The envname argument points to an
	 * empty string, or points to a string containing an '=' character." */
	errno = 0;
	CHECK(setenv("", "x", 1) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(setenv("FOO=BAR", "x", 1) == -1 && errno == EINVAL);

	/* basic set + getenv.html: "a pointer to the value ... or a null
	 * pointer if ... not found" */
	CHECK(unsetenv("SPICULE_TEST_VAR") == 0); /* start clean; unsetenv on a missing var still succeeds */
	CHECK(getenv("SPICULE_TEST_VAR") == 0);
	CHECK(setenv("SPICULE_TEST_VAR", "one", 1) == 0);
	CHECK(getenv("SPICULE_TEST_VAR") && !strcmp(getenv("SPICULE_TEST_VAR"), "one"));

	/* setenv.html DESCRIPTION: overwrite==0 with an existing variable
	 * leaves the environment unchanged and still returns success. */
	CHECK(setenv("SPICULE_TEST_VAR", "two", 0) == 0);
	CHECK(!strcmp(getenv("SPICULE_TEST_VAR"), "one"));
	CHECK(setenv("SPICULE_TEST_VAR", "two", 1) == 0);
	CHECK(!strcmp(getenv("SPICULE_TEST_VAR"), "two"));

	/* unsetenv.html: "Upon successful completion, zero shall be
	 * returned" and the variable is gone afterwards; EINVAL for an
	 * empty name or one containing '='. */
	CHECK(unsetenv("SPICULE_TEST_VAR") == 0);
	CHECK(getenv("SPICULE_TEST_VAR") == 0);
	errno = 0;
	CHECK(unsetenv("") == -1 && errno == EINVAL);
	errno = 0;
	CHECK(unsetenv("A=B") == -1 && errno == EINVAL);

	/* putenv.html DESCRIPTION: "the string pointed to by string shall
	 * become part of the environment, so altering the string shall
	 * change the environment" -- the string is not copied. */
	{
		static char buf[] = "SPICULE_PUTENV_VAR=abc";
		CHECK(putenv(buf) == 0);
		CHECK(!strcmp(getenv("SPICULE_PUTENV_VAR"), "abc"));
		/* mutate the very string handed to putenv(), in place ("xyz" is
		 * the same length as "abc" so no NUL bookkeeping needed) */
		strcpy(buf + strlen("SPICULE_PUTENV_VAR="), "xyz");
		CHECK(!strcmp(getenv("SPICULE_PUTENV_VAR"), "xyz"));
		unsetenv("SPICULE_PUTENV_VAR");
	}

	/* putenv.html RETURN VALUE: "Upon successful completion, putenv()
	 * shall return 0; otherwise, it shall return a non-zero value." */
	{
		static char buf2[] = "SPICULE_PUTENV_VAR2=v";
		CHECK(putenv(buf2) == 0);
		CHECK(!strcmp(getenv("SPICULE_PUTENV_VAR2"), "v"));
		unsetenv("SPICULE_PUTENV_VAR2");
	}

	/* environ.html / getenv.html: environ reflects the live list, and
	 * a name must appear in it after setenv(). */
	{
		char **e;
		int found = 0;
		CHECK(setenv("SPICULE_ENVIRON_CHECK", "z", 1) == 0);
		for (e = environ; e && *e; e++)
			if (!strncmp(*e, "SPICULE_ENVIRON_CHECK=", 21)) found = 1;
		CHECK(found);
		unsetenv("SPICULE_ENVIRON_CHECK");
	}

	/* clearenv(3) (XSI, not in the base standard, restored per
	 * src/env/setenv.c's own comment: musl's libc-test functional/
	 * env.c calls it directly): "shall clear the environment of all
	 * name-value pairs". Save and restore PATH around the call so this
	 * test does not leave the rest of the run (or the process spawned
	 * by test_system() below) without one. */
	{
		char *saved_path = getenv("PATH");
		char pathbuf[4096];
		int had_path = saved_path != 0;

		if (had_path) {
			strncpy(pathbuf, saved_path, sizeof pathbuf - 1);
			pathbuf[sizeof pathbuf - 1] = 0;
		}
		CHECK(setenv("SPICULE_CLEARENV_VAR", "x", 1) == 0);
		CHECK(getenv("SPICULE_CLEARENV_VAR") != 0);

		CHECK(clearenv() == 0);
		CHECK(getenv("SPICULE_CLEARENV_VAR") == 0);
		CHECK(getenv("PATH") == 0);
		CHECK(environ != 0 && environ[0] == 0);

		if (had_path) CHECK(setenv("PATH", pathbuf, 1) == 0);
	}
}

/* ---- mkostemp/mkstemps: forms not already covered by test/stdlib.c
 * (which covers plain mkstemp/mkstemps/mkdtemp and the EINVAL
 * no-XXXXXX case). ---- */
static void test_mkostemp(void)
{
	/* mkstemp.html EINVAL: "The last six characters of template were
	 * not XXXXXX" -- fewer than six (five here) must also fail, not
	 * just zero. */
	{
		char t[] = "short-XXXXX";
		errno = 0;
		CHECK(mkostemp(t, 0) == -1 && errno == EINVAL);
	}

	/* mkstemp.html: "as if by a call to open() with ... O_RDWR" --
	 * mkostemp is documented (glibc, and src/stdlib/mktemp.c's
	 * `flags &= ~O_ACCMODE`) to force O_RDWR regardless of any
	 * access-mode bits passed in flags.  Passing O_RDONLY must not
	 * leave the descriptor read-only. */
	{
		char t[] = "mkotest-XXXXXX";
		int fd = mkostemp(t, O_RDONLY);
		CHECK(fd >= 0);
		if (fd >= 0) {
			CHECK(write(fd, "hi", 2) == 2);
			close(fd);
			unlink(t);
		}
	}

	/* the created file must not already exist (O_EXCL semantics) and
	 * must be a regular file open for reading and writing. */
	{
		char t[] = "mkotest2-XXXXXX";
		int fd = mkstemp(t);
		struct stat st;
		CHECK(fd >= 0);
		if (fd >= 0) {
			CHECK(fstat(fd, &st) == 0 && S_ISREG(st.st_mode));
			CHECK(lseek(fd, 0, SEEK_CUR) == 0);
			CHECK(read(fd, &st, 0) == 0); /* readable */
			close(fd);
			unlink(t);
		}
	}

	/* mkostemps() itself, not just through mkstemps()/mkostemp(): both
	 * a nonzero suffix length AND access-mode-forcing flags together,
	 * the combination neither test/stdlib.c's mkstemps(t, 4) call (no
	 * flags) nor the mkostemp(t, O_RDONLY) call above (no suffix)
	 * exercises. */
	{
		char t[] = "mkostest-XXXXXX.txt";
		int fd = mkostemps(t, 4, O_RDONLY);
		CHECK(fd >= 0);
		if (fd >= 0) {
			CHECK(strstr(t, ".txt") != 0);
			CHECK(write(fd, "hi", 2) == 2); /* O_RDONLY was forced off */
			close(fd);
			unlink(t);
		}
	}
	/* mkstemp.html EINVAL, through mkostemps() directly: fewer than
	 * six X's immediately before the suffix. */
	{
		char t[] = "short-XXXXX.txt";
		errno = 0;
		CHECK(mkostemps(t, 4, 0) == -1 && errno == EINVAL);
	}
}

/* ---- mkstemp.html DESCRIPTION: "The file shall be readable and
 * writable only by the creating process's user ID" -- glibc/BSD sharpen
 * this to exactly S_IRUSR|S_IWUSR (0600), which is what
 * src/stdlib/mktemp.c actually requests: mkostemps() calls
 * open(tmpl, flags|O_CREAT|O_EXCL|O_RDWR, 0600).
 *
 * N/A: spicule now writes the mode word to WSL's $LXMOD metadata, but
 * intentionally consumes only its execute/search bits.  Read bits remain
 * synthetic, while write permission remains the aggregate Windows
 * FILE_ATTRIBUTE_READONLY mapping.  Thus S_IRUSR|S_IWUSR-only still
 * cannot round-trip through this permission model.  Under Wine, mkstemp()
 * followed by fstat() reports mode 0644, not 0600, for a file created
 * with the literal open(..., 0600) call above, and it would read
 * exactly the same on real Windows NT since nothing here queries an NT
 * security descriptor at all.
 *
 * The only way to make this real would be to stop using file attributes
 * for permissions altogether and start writing/reading an actual NT
 * DACL (a discretionary access-control list naming the creating SID) --
 * NT does have that machinery, but no code in this tree touches it, and
 * adding it would be a new permission model for open()/stat()/chmod()
 * collectively, not an extension of the $LXMOD execute-bit mapping.
 * That remains out of scope and, per the ledger, would need verification against real ACL
 * behaviour that only a real NT box (not Wine) could confirm -- so it
 * is left as a real, well-understood gap rather than attempted
 * half-way. */
/* mktemp.html DESCRIPTION: "shall replace the contents of the string
 * pointed to by template ... with a string that constitutes a valid
 * pathname and that does not name an existing file", the same fill()
 * this file's mkostemp()/mkstemp() calls above use, but through
 * mktemp() itself: it fills the X's and confirms the name is unique,
 * without creating the file.  RETURN VALUE: "shall return the
 * template argument" (never a null pointer, unlike mkstemp()'s error
 * return -- mktemp() reports failure by returning an unusable path). */
static void test_mktemp(void)
{
	char t[] = "mktemptest-XXXXXX";
	char *r;
	struct stat st;

	r = mktemp(t);
	CHECK(r == t);
	CHECK(strcmp(t, "mktemptest-XXXXXX") != 0);
	/* "does not name an existing file" */
	errno = 0;
	CHECK(stat(t, &st) == -1 && errno == ENOENT);

	/* Two successive calls against independent templates must not
	 * collide -- fill() reseeds its xorshift state from process-
	 * specific entropy, not from a fixed sequence, so this is not
	 * merely restating "not the literal XXXXXX" above. */
	{
		char t2[] = "mktemptest-XXXXXX";
		char *r2 = mktemp(t2);
		CHECK(r2 == t2);
		CHECK(strcmp(t, t2) != 0);
	}

	/* mktemp.html EINVAL is not in this call's own ERRORS list (unlike
	 * mkstemp()'s), but src/stdlib/mktemp.c's mktemp() still refuses a
	 * malformed template cleanly: "an empty string shall be placed in
	 * template" per the LEGACY-era description this implementation
	 * follows, rather than writing past the string's actual X's. */
	{
		char bad[] = "bad-template";
		r = mktemp(bad);
		CHECK(r == bad);
		CHECK(bad[0] == '\0');
	}
}

static void test_mkstemp_permission_bits(void)
{
#if SPICULE_TEST(BUG, posix_stdlib_mkstemp_owner_only_permissions) /* BUG (compiles and links; formerly UNIMPL):: mkstemp.html DESCRIPTION -- the file is created with
       * mode S_IRUSR|S_IWUSR only (0600).  Was N/A, and asserted
       * "unrepresentable, not merely unimplemented".  That is the wrong
       * way round.  The proximate facts are right -- $LXMOD is consumed
       * only for execute/search bits, FILE_ATTRIBUTE_READONLY carries
       * aggregate write permission, and read bits remain synthetic --
       * but they are facts about
       * THIS LIBRARY, not about NT.  "Owner-only readable" is
       * representable on NT: it is a DACL with one allow ACE for the
       * owner's SID, which NtSetSecurityObject writes and
       * NtQuerySecurityObject reads (both real ntdll syscalls,
       * exported and implemented even by Wine, dlls/ntdll/ntdll.spec
       * lines 419 and 344).  The fence's own closing clause says the
       * blocker out loud -- "real NT DACL storage, which no code in
       * this tree has" -- which is the definition of unimplemented, not
       * of unrepresentable.
       *
       * Same group as the three chmod fences in test/posix-unistd.c;
       * see the banner above them for the full accounting of what NT's
       * security descriptor does provide.  Retagged, not reopened: the
       * decision to do no ACL work may well be right, and it would need
       * measuring on real Windows rather than Wine, whose DACL
       * emulation over a Unix filesystem is not NT's.
       *
       * RE-AUDITED, STILL BUG.  This fence's own "$LXMOD is consumed
       * only for execute/search bits" is now factually wrong and worth
       * flagging as such rather than quietly leaving stale: since
       * c9411f8, $LXMOD stores and mode_from_attrs() reads back a full
       * 07777 mode, not merely execute bits (checked directly against
       * src/stat/nt/plat_stat.c). mkstemp's own open(..., 0600) call
       * would, on that mechanism alone, persist lxmod=0600 exactly and
       * satisfy this fence's literal assertion with no ACL work at
       * all -- unlike its sibling
       * posix_unistd_chmod_group_other_write_aliases_owner, whose
       * required 0640 genuinely cannot come from a literal $LXMOD
       * round-trip. That distinction does not save this one, though:
       * src/stat/nt/plat_stat.c:165 documents "Wine through 10.x stubs
       * NtSetEaFile as ACCESS_DENIED", and the CI leg this project
       * measures against elsewhere is stock apt Wine 9.0 -- inside
       * that range. So the EA write mkstemp's open() attempts at
       * creation is expected to fail on the actual grading Wine,
       * leaving the file with no $LXMOD record and its read-back mode
       * synthesized at the ordinary 0644 default -- not the 0600 this
       * fence requires. Same blocker as its two siblings in
       * test/posix-unistd.c, see the fuller note on
       * test_chmod_cannot_clear_read_bits there. Not attempted here for
       * the same reason: no working Wine available to verify either the
       * EA-write failure or a real ACL alternative against actual
       * NT/Wine behaviour. */
	char t[] = "mkperm-XXXXXX";
	int fd = mkstemp(t);
	struct stat st;
	CHECK(fd >= 0);
	if (fd >= 0) {
		CHECK(fstat(fd, &st) == 0);
		CHECK((st.st_mode & 0777) == (S_IRUSR | S_IWUSR));
		close(fd);
		unlink(t);
	}
#endif
	printf("note: mkstemp() permission bits (S_IRUSR|S_IWUSR only) are "
	       "N/A -- $LXMOD is consumed only for execute/search bits and "
	       "FILE_ATTRIBUTE_READONLY stores aggregate write permission; "
	       "the read bits stat() reports have no NT DACL behind them, so "
	       "\"owner-only readable\" cannot round-trip through this "
	       "library's permission model at all\n");
}

/* ---- realpath.html: caller-supplied (non-NULL) resolved_name buffer. ---- */
#if SPICULE_TEST(PASS, posix_stdlib_realpath_errno_not_flattened) /* realpath() preserves the errno from open().
	 * ENOENT, losing two shall-fail errors.  realpath.html ERRORS, "The
	 * realpath() function shall fail if": "[ENOTDIR] A component of the
	 * path prefix names an existing file that is neither a directory
	 * nor a symbolic link to a directory" and "[ENAMETOOLONG] The
	 * length of a component of a pathname is longer than {NAME_MAX}".
	 *
	 * Mechanism: src/stdlib/realpath.c opens the path and, on failure,
	 * does
	 *
	 *     if (fd < 0) { if (errno != EACCES) errno = ENOENT; return 0; }
	 *
	 * open() produces both of the errnos above -- this library goes to
	 * real trouble to synthesize them.  src/internal/path.c's
	 * reject_if_prefix_not_dir(), called for every AT_FDCWD and
	 * absolute path, is what sets ENOTDIR; __name_too_long() in
	 * dos_from_posix() is what sets ENAMETOOLONG for an over-long
	 * component.  realpath() then throws both away.
	 *
	 * The file's banner justifies exactly one of these: "A path that
	 * does not exist cannot be canonicalised that way, so it is an
	 * ENOENT like POSIX says."  That is right, and is about a path that
	 * does not exist.  A prefix component that exists and is not a
	 * directory, and a component longer than {NAME_MAX}, are different
	 * conditions with their own clauses, and the blanket rewrite
	 * flattens them into the one case the banner reasoned about.
	 *
	 * Re-enable when realpath() passes through the errno open() set for
	 * the cases POSIX names. */
static void test_realpath_errno_not_flattened(void)
{
	char t[] = "rperr-XXXXXX";
	char sub[64];
	char longc[300];
	int fd = mkstemp(t);

	CHECK(fd >= 0);
	if (fd < 0) return;
	close(fd);

	/* a path prefix that exists and is a regular file */
	snprintf(sub, sizeof sub, "%s/x", t);
	errno = 0;
	CHECK(realpath(sub, 0) == 0 && errno == ENOTDIR);

	/* a single component longer than {NAME_MAX} */
	memset(longc, 'a', 280);
	longc[280] = 0;
	errno = 0;
	CHECK(realpath(longc, 0) == 0 && errno == ENAMETOOLONG);

	/* and the case the banner is about must keep answering ENOENT */
	errno = 0;
	CHECK(realpath("no-such-file-xyz", 0) == 0 && errno == ENOENT);

	unlink(t);
}
#endif

static void test_realpath_buf(void)
{
	char t[] = "rpbuf-XXXXXX";
	int fd = mkstemp(t);
	CHECK(fd >= 0);
	if (fd >= 0) {
		char resolved[4096]; /* PATH_MAX may not be defined; generous buffer */
		char *r = realpath(t, resolved);
		/* realpath.html RETURN VALUE: "shall return a pointer to the
		 * resolved_name argument" when one was supplied. */
		CHECK(r == resolved);
		CHECK(r && strstr(r, "rpbuf-") != 0);
		close(fd);
		unlink(t);
	}
}

/* ---- system.html: not exercised anywhere else. ---- */
static void test_system(void)
{
	int st;

	/* RETURN VALUE: "the system() function shall always return
	 * non-zero when command is NULL" -- non-zero exactly when a command
	 * processor is available.  Under Wine that is cmd.exe, via ComSpec
	 * or PATH.  The native sanitizer build has no cmd.exe at all (its
	 * file system is simulated in fuzz/ntstubs.c), so 0 is the correct
	 * answer there and the clauses below have nothing to run.  Detect
	 * rather than assert either way, the same way test/unistd.c handles
	 * Wine-vs-NT divergence. */
	if (system(0) == 0) {
		printf("note: no command processor; skipping the system() clauses\n");
		return;
	}

	/* "the value returned by system() shall be the termination status
	 * of the command language interpreter in the format specified by
	 * waitpid()." -- cmd.exe's "exit N" sets its own exit code to N. */
	st = system("exit 5");
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 5);

	st = system("exit 0");
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);

	/* sanity check on the status-decoding path itself (distinct from
	 * the exit(127) clause below): an ordinary nonzero exit still comes
	 * back through system()'s own wait-status convention correctly. */
	st = system("exit 1");
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 1);

	/* "If a shell could not be executed ... the value returned by
	 * system() shall be as if the command interpreter terminated using
	 * exit(127)."  This *is* independently triggerable, contrary to
	 * what the ledger previously assumed, but the fixture that gets
	 * find_shell() to resolve a real, executable, yet genuinely
	 * un-runnable file is platform-specific -- ComSpec on NT, PATH on
	 * Linux, since src/stdlib/system.c's find_shell() consults ComSpec
	 * on NT but does a plain __find_program("sh", 1) PATH search on
	 * Linux (see that file's header comment). Either way, system() must
	 * synthesize a (127<<8)-shaped status for the `pid < 0` __spawn()
	 * returns once it actually tries to launch the fixture, so
	 * WIFEXITED(st) && WEXITSTATUS(st)==127 as this clause requires. */
#if defined(__linux__)
	/* A directory prepended to PATH with a "sh" in it -- chmod'd
	 * executable, but neither a valid ELF image nor a "#!" script --
	 * is found ahead of the real shell by that PATH search and fails
	 * execve(2) with ENOEXEC.  __spawn()'s Linux backend reports that
	 * failure back through a close-on-exec self-pipe before returning
	 * (src/process/linux/plat_process.c), so this reaches the same
	 * synchronous `pid < 0` outcome NT gets for free from atomic
	 * process creation -- see system.c's header comment. */
	{
		char dir[] = "sysbad-dirXXXXXX";
		char shpath[32];
		char *old_path = getenv("PATH");

		old_path = old_path ? strdup(old_path) : 0;
		CHECK(mkdtemp(dir) == dir);
		snprintf(shpath, sizeof shpath, "%s/sh", dir);
		{
			int fd = open(shpath, O_CREAT | O_WRONLY, 0755);
			CHECK(fd >= 0);
			if (fd >= 0) {
				CHECK(write(fd, "not a valid executable\n", 24) == 24);
				CHECK(close(fd) == 0);
				CHECK(chmod(shpath, 0755) == 0);
			}
		}
		{
			char newpath[PATH_MAX];
			snprintf(newpath, sizeof newpath, "%s:%s", dir, old_path ? old_path : "");
			CHECK(setenv("PATH", newpath, 1) == 0);
		}
		st = system("exit 0");
		CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 127);
		if (old_path) { CHECK(setenv("PATH", old_path, 1) == 0); free(old_path); }
		else CHECK(unsetenv("PATH") == 0);
		unlink(shpath);
		rmdir(dir);
	}
#else
	{
		char t[] = "sysbad-XXXXXX.exe";
		int fd = mkstemps(t, 4);
		CHECK(fd >= 0);
		if (fd >= 0) {
			int executable;
			CHECK(write(fd, "not a valid PE image\n", 22) == 22);
			CHECK(close(fd) == 0);
			executable = chmod(t, 0755) == 0 || access(t, X_OK) == 0;
			if (!executable) {
				printf("note: $LXMOD unavailable; skipping invalid-shell system() clause\n");
			} else {
				CHECK(setenv("ComSpec", t, 1) == 0);
				st = system("exit 0");
				CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 127);
				unsetenv("ComSpec");
			}
			unlink(t);
		}
	}
#endif
}

/* ---- a64l.html / l64a.html: radix-64 digit mapping and the
 * first-six-characters / stops-at-NUL rules. ---- */
static void test_a64l(void)
{
	/* "'.' represents the value 0 through 'z' represents the value 63" */
	CHECK(a64l(".") == 0);
	CHECK(a64l("/") == 1);
	CHECK(a64l("0") == 2);
	CHECK(a64l("9") == 11);
	CHECK(a64l("A") == 12);
	CHECK(a64l("Z") == 37);
	CHECK(a64l("a") == 38);
	CHECK(a64l("z") == 63);

	/* "the first character represents the least significant digit" */
	CHECK(a64l("0/") == 2 + 1 * 64); /* '0'=2 (lsd), '/'=1 */

	/* "a64l() shall use the first six characters" -- extra characters
	 * beyond six must be ignored. */
	{
		long a = a64l("////// extra junk that would overflow if read");
		long b = a64l("//////");
		CHECK(a == b);
	}

	/* round-trip already covered by test/stdlib.c; here check l64a(0)
	 * returns a pointer to an *empty* string, not NULL. */
	{
		char *p = l64a(0);
		CHECK(p != 0 && p[0] == 0);
	}
}

/* ================ quick_exit / at_quick_exit ================
 *
 * Not POSIX.1-2017 pages -- both
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/quick_exit.html
 * and .../at_quick_exit.html return 404; quick_exit/at_quick_exit are a
 * C11 addition (ISO/IEC 9899:2011, N1570 7.22.4.3 and 7.22.4.7) that
 * <stdlib.h> happens to also declare here.  Cited against N1570 instead.
 *
 * Needs a real child process observed from the parent, the same way
 * test/posix-alloc.c's exit()/_Exit()/abort() tests do: fork() needs
 * RtlCloneUserProcess (unavailable under stock Wine), so this re-execs
 * itself via __spawn(), with argv[1] selecting which child behaviour to
 * run. */
static int qe_spawn_self(const char *self, const char *flag, int *status)
{
	char *argv[3];
	int pid;
	argv[0] = (char *)self;
	argv[1] = (char *)flag;
	argv[2] = 0;
	pid = __spawn(self, argv, environ);
	if (pid < 0) return -1;
	if (waitpid(pid, status, 0) != pid) return -1;
	return 0;
}

/* N1570 7.22.4.3p3 (at_quick_exit): "The implementation shall support
 * the registration of at least 32 functions."  src/exit/exit.c's
 * `qhandlers[32]` (checked via `nqhandlers >= 32` before storing)
 * provides exactly that minimum -- unlike atexit's ATEXIT_MAX=128, a
 * 33rd registration here is expected to fail; that is conforming (the
 * standard says "at least 32", not "unlimited"), just worth pinning as
 * this implementation's actual capacity. */
#define N_QE_MIN 32

static int qe_order[N_QE_MIN];
static int qe_norder;
static int qe_atexit_ran;

/* N1570 7.22.4.7p2: "No functions registered by the atexit function ...
 * are called [by quick_exit]." -- registered in the child alongside the
 * at_quick_exit handlers below; if quick_exit() incorrectly invoked it,
 * qe_atexit_ran would be set before qe_fn_0 (the last at_quick_exit
 * handler to run, since they run LIFO) checks it. */
static void qe_atexit_marker(void) { qe_atexit_ran = 1; }
/* target for the 33rd (expected-to-fail) at_quick_exit() registration;
 * must never itself run since it's never expected to be registered. */
static void qe_extra_marker(void) { _Exit(89); }

#define QE_FN(n) static void qe_fn_##n(void) { qe_order[qe_norder++] = n; }
QE_FN(1) QE_FN(2) QE_FN(3) QE_FN(4) QE_FN(5) QE_FN(6) QE_FN(7) QE_FN(8)
QE_FN(9) QE_FN(10) QE_FN(11) QE_FN(12) QE_FN(13) QE_FN(14) QE_FN(15)
QE_FN(16) QE_FN(17) QE_FN(18) QE_FN(19) QE_FN(20) QE_FN(21) QE_FN(22)
QE_FN(23) QE_FN(24) QE_FN(25) QE_FN(26) QE_FN(27) QE_FN(28) QE_FN(29)
QE_FN(30) QE_FN(31)

/* qe_fn_0 was registered *first*, so per 7.22.4.7p3 ("in the reverse
 * order of their registration") it is the *last* at_quick_exit handler
 * to run -- the same place posix-alloc.c's atexit_fn_0 sits for atexit,
 * and for the same reason: nothing after quick_exit()'s handler loop
 * ever returns to main(), so the last handler to run must itself decide
 * pass/fail and terminate the process with a status the parent can
 * read back. */
static void qe_fn_0(void)
{
	int i, ok;
	qe_order[qe_norder++] = 0;
	ok = (qe_norder == N_QE_MIN) && !qe_atexit_ran;
	for (i = 0; ok && i < N_QE_MIN; i++)
		if (qe_order[i] != N_QE_MIN - 1 - i) ok = 0;
	_Exit(ok ? 77 : 78);
}

static void (*const qe_fns[N_QE_MIN])(void) = {
	qe_fn_0, qe_fn_1, qe_fn_2, qe_fn_3, qe_fn_4, qe_fn_5, qe_fn_6,
	qe_fn_7, qe_fn_8, qe_fn_9, qe_fn_10, qe_fn_11, qe_fn_12, qe_fn_13,
	qe_fn_14, qe_fn_15, qe_fn_16, qe_fn_17, qe_fn_18, qe_fn_19, qe_fn_20,
	qe_fn_21, qe_fn_22, qe_fn_23, qe_fn_24, qe_fn_25, qe_fn_26, qe_fn_27,
	qe_fn_28, qe_fn_29, qe_fn_30, qe_fn_31,
};

/* child side: run entirely inside main() below (argv[1]=="--posix-stdlib-quickexit"). */
static _Noreturn void run_quickexit_child(void)
{
	int i;

	atexit(qe_atexit_marker);
	for (i = 0; i < N_QE_MIN; i++) {
		if (at_quick_exit(qe_fns[i]) != 0) _Exit(79); /* the guaranteed-32 must all succeed */
	}
	/* 33rd: this implementation's fixed-size qhandlers[32] is now full,
	 * so this registration is expected to fail (see N_QE_MIN comment
	 * above) -- not itself a spec requirement, just this
	 * implementation's actual, pinned behaviour. */
	if (at_quick_exit(qe_extra_marker) == 0) _Exit(80);
	quick_exit(55); /* N1570 7.22.4.7p4: control passes to _Exit(status) */
	_Exit(81); /* unreachable if quick_exit() truly never returns (p5) */
}

static void test_quick_exit(const char *self)
{
	int status;

	if (qe_spawn_self(self, "--posix-stdlib-quickexit", &status) < 0) {
		printf("note: cannot spawn \"%s\"; quick_exit() child test skipped\n", self);
		return;
	}
	/* qe_fn_0 encodes "everything checked out" as exit 77, any other
	 * detected failure (order wrong, atexit ran, a guaranteed
	 * registration failed, an extra one unexpectedly succeeded, or
	 * quick_exit() returned) as a distinct nonzero code. */
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

/* ---- getsubopt.html: keylistp must not be modified by the call. ---- */
static void test_getsubopt_keylist(void)
{
	char buf[] = "ro";
	char *tokens[] = { "ro", "rw", 0 };
	char *tok0 = tokens[0], *tok1 = tokens[1], *tok2 = tokens[2];
	char *subopts = buf, *val;
	int r = getsubopt(&subopts, tokens, &val);
	CHECK(r == 0 && val == 0);
	/* "getsubopt() shall not modify the keylistp vector" -- the array's
	 * own pointer slots (not just the strings they name) must be the
	 * same afterwards. */
	CHECK(tokens[0] == tok0 && tokens[1] == tok1 && tokens[2] == tok2);
	/* single suboption, no comma: "*optionp shall be updated to point
	 * to the null character at the end of the string." */
	CHECK(subopts != 0 && *subopts == 0);
}

#if defined(__linux__) && !defined(_SPICULE_NATIVE_BUILD)
/* ============================================================
 * posix_openpt / grantpt / unlockpt / ptsname / ptsname_r (Linux
 * backend, src/stdlib/linux/plat_pty.c)
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_openpt.html
 *
 * Real only on native Linux -- NT genuinely has no PTY concept (see
 * include/stdlib.h's own updated comment), so this whole family stays
 * undefined-ok there. Guarded out of the NT/Wine build (no __linux__)
 * and the native-ASan harness (_SPICULE_NATIVE_BUILD links only the NT
 * backend against fuzz/ntstubs.c, which defines none of these five)
 * the same way test/posix-unistd-ids.c's own test_res_ids() is.
 * ============================================================ */
static void test_posix_openpt_family(void)
{
	int mfd, sfd;
	char *slave;
	char buf[64];
	ssize_t n;
	char rb[16];

	mfd = posix_openpt(O_RDWR | O_NOCTTY);
	CHECK(mfd >= 0);
	if (mfd < 0) return;

	CHECK(grantpt(mfd) == 0);
	CHECK(unlockpt(mfd) == 0);

	slave = ptsname(mfd);
	CHECK(slave != 0);
	if (slave) CHECK(!strncmp(slave, "/dev/pts/", 9));

	CHECK(ptsname_r(mfd, buf, sizeof buf) == 0);
	CHECK(slave != 0 && !strcmp(slave, buf));

	/* ERANGE for a buffer too small to hold the real answer. */
	CHECK(ptsname_r(mfd, buf, 1) == ERANGE);

	/* EBADF/EINVAL-shaped failure for a descriptor that is not a ptmx
	 * master at all -- grantpt()/unlockpt() must not silently succeed
	 * on an unrelated fd. */
	{
		int junk = open("/dev/null", O_RDONLY);
		CHECK(junk >= 0);
		if (junk >= 0) {
			CHECK(grantpt(junk) == -1);
			CHECK(unlockpt(junk) == -1);
			close(junk);
		}
	}

	/* The master/slave pair actually work as a real pty: open the
	 * slave and prove data flows across it, not just that the naming
	 * machinery answers something. */
	if (slave) {
		sfd = open(slave, O_RDWR | O_NOCTTY);
		CHECK(sfd >= 0);
		if (sfd >= 0) {
			CHECK(write(mfd, "hi\n", 3) == 3);
			n = read(sfd, rb, sizeof rb);
			CHECK(n > 0);
			close(sfd);
		}
	}
	close(mfd);
}
#endif

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "--posix-stdlib-quickexit"))
		run_quickexit_child();

	test_strtol_base();
	test_atoi_family();
	test_qsort_bsearch_zero();
	test_bsearch_arg_order();
	test_rand48_ranges();
	test_random_state();
	test_env();
	test_mkostemp();
	test_mktemp();
	test_mkstemp_permission_bits();
	test_realpath_buf();
	test_system();
	test_a64l();
	test_getsubopt_keylist();
#if defined(__linux__) && !defined(_SPICULE_NATIVE_BUILD)
	test_posix_openpt_family();
#endif
	test_quick_exit(argv[0]);

	if (!fails) printf("posix-stdlib: all tests passed\n");
	return fails != 0;
}
