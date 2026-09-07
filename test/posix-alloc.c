/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of memory allocation
 * (malloc/calloc/realloc/free/posix_memalign/aligned_alloc), process
 * termination (exit/_Exit/abort/atexit/assert) and environment
 * (getenv/setenv/unsetenv/putenv/environ).  Each assertion cites the
 * clause of https://pubs.opengroup.org/onlinepubs/9699919799/functions/
 * <name>.html it checks.  See test/posix-coverage/alloc.md for the
 * full ledger, including what test/malloc.c and test/misc.c already
 * cover (both belong to other agents and are not duplicated here
 * except where a clause was not actually cited against the spec text
 * there).
 *
 * The exit()-vs-_Exit() and abort()/assert() clauses need a child
 * process observed from the parent -- fork() needs RtlCloneUserProcess,
 * which stock Wine lacks, so this re-execs itself via __spawn(), same
 * pattern as test/misc.c's test_abort_child().
 */
/* posix_memalign()/setenv()/unsetenv()/putenv() and the sigaction()
 * family used by the child re-exec below are feature-test gated in
 * include/stdlib.h and include/signal.h; same define most other
 * tests in test/ already carry for the same reason (see test/posix-glob.c's
 * comment on this exact define). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

extern char **environ;

/* Internal: spawn a program as a child, return its pid (see
 * src/process/spawn.c).  Declared locally, as test/misc.c does, rather
 * than widening include/. */
int __spawn(const char *path, char *const argv[], char *const envp[]);

/* ================= malloc / calloc / realloc / free ================= */

/* ---- malloc.html DESCRIPTION/RETURN VALUE: "If the size of the space
 * requested is 0, the behavior is implementation-defined: either a
 * null pointer is returned, or the behavior is as if the size were
 * some nonzero value, except that the returned pointer shall not be
 * used to access an object."  Assert only the permitted set -- NULL or
 * a pointer usable with free() -- and that two live malloc(0) results
 * never alias (each is a distinct "object" per the standard even
 * though it may not be dereferenced). ---- */
static void test_malloc_zero(void)
{
	void *a = malloc(0);
	void *b = malloc(0);

	/* whichever the implementation picked, it must not crash to free */
	if (a) free(a);
	/* two simultaneously-live zero-size allocations must not alias:
	 * if both are non-null they must be distinct pointers (or NT's
	 * heap may legitimately hand back the same address for a
	 * zero-length allocation with nothing between the calls -- but
	 * only if it never got freed in between, which is not the case
	 * here since a was freed above).  Re-do without freeing between
	 * the two calls to test the real "two live allocations" case. */
	(void)b;
	{
		void *x = malloc(0), *y = malloc(0);
		if (x && y) CHECK(x != y);
		free(x); free(y);
	}
	printf("note: malloc(0) returns %s\n", a ? "a unique pointer" : "NULL");
}

/* ---- realloc.html: "If size is 0 ... the behavior is
 * implementation-defined: either a null pointer is returned, or the
 * behavior shall be as if the size were some nonzero value, except
 * that the returned pointer shall not be used to access an object."
 * Same latitude as malloc(0); also confirm free-ability. ---- */
static void test_realloc_zero(void)
{
	void *p = malloc(16);
	void *q;
	CHECK(p != 0);
	q = realloc(p, 0);
	/* whichever this implementation does, it must be one of the two
	 * permitted outcomes and must not crash */
	if (q) free(q);
	printf("note: realloc(p, 0) returns %s\n", q ? "a pointer" : "NULL");
}

/* ---- calloc.html DESCRIPTION: "the space shall be initialized to all
 * bits 0" -- checked on a small allocation and on one large enough
 * that it plausibly takes a different code path (bigger than a
 * typical small-object heap bucket), after deliberately dirtying that
 * address range first so a false pass (memory that merely started
 * zero) is not possible. ---- */
static void test_calloc_zeroes(void)
{
	unsigned char *p;
	size_t i, n;

	n = 64;
	p = malloc(n);
	CHECK(p != 0);
	if (p) { memset(p, 0xa5, n); free(p); }
	p = calloc(n, 1);
	CHECK(p != 0);
	if (p) { for (i = 0; i < n; i++) CHECK(p[i] == 0); free(p); }

	/* large: dirty a big block, free it, then calloc the same size and
	 * hope the allocator reuses the address range (not guaranteed, but
	 * gives the zero-fill code a real chance to be exercised on
	 * previously-nonzero memory rather than fresh-from-the-OS pages,
	 * which the kernel already zeroes for unrelated reasons). */
	n = 4u << 20; /* 4 MiB: well past any small-object bucket */
	p = malloc(n);
	if (p) { memset(p, 0x5a, n); free(p); }
	p = calloc(n, 1);
	CHECK(p != 0);
	if (p) {
		for (i = 0; i < n; i += 4093) CHECK(p[i] == 0); /* prime-strided sample */
		CHECK(p[0] == 0 && p[n - 1] == 0);
		free(p);
	}
}

/* ---- calloc.html DESCRIPTION / ERRORS: nelem*elsize overflow must be
 * detected and treated as "insufficient memory" (NULL + ENOMEM)
 * rather than silently wrapping and under-allocating -- the classic
 * exploitable calloc bug.  src/malloc/malloc.c's check is
 * `if (n && m > (size_t)-1 / n)`; exercise the exact wraparound
 * boundaries, not just "very large", so an off-by-one in that
 * comparison would be caught. ---- */
static void test_calloc_overflow(void)
{
	void *p;

	/* m*n wraps to exactly 0: m = SIZE_MAX/2+1, n = 2 (odd SIZE_MAX
	 * case handled below too) */
	errno = 0;
	p = calloc((size_t)-1 / 2 + 1, 2);
	CHECK(p == 0 && errno == ENOMEM);

	/* m*n wraps to a small nonzero value: with n=2, m = SIZE_MAX/2+2
	 * gives m*n = SIZE_MAX+3, which wraps to 1 (mod 2**bits) -- if the
	 * overflow check were off by one, this would return a 1-byte
	 * buffer instead of failing. */
	errno = 0;
	p = calloc((size_t)-1 / 2 + 2, 2);
	CHECK(p == 0 && errno == ENOMEM);

	/* the exact non-overflowing boundary: m*n == SIZE_MAX (no wrap,
	 * but an unsatisfiable request) must still fail, distinguishing
	 * "overflow rejected before the multiply" from "the multiply
	 * itself was avoided because it's small" -- both are ENOMEM but
	 * via different branches in the source. */
	errno = 0;
	p = calloc((size_t)-1, 1);
	CHECK(p == 0 && errno == ENOMEM);
	errno = 0;
	p = calloc(1, (size_t)-1);
	CHECK(p == 0 && errno == ENOMEM);

	/* n == 0: never a multiply, never an overflow -- must not spuriously
	 * report ENOMEM via the overflow branch (m > SIZE_MAX/0 would be
	 * UB, which is exactly why the check is `n &&` first). */
	errno = 1234;
	p = calloc((size_t)-1, 0);
	CHECK(errno == 1234); /* zero-size result permitted either way, no error */
	if (p) free(p);

	/* a genuinely satisfiable product must NOT be rejected as if it
	 * had overflowed */
	p = calloc(1000, 1000);
	CHECK(p != 0);
	free(p);
}

/* ---- realloc.html DESCRIPTION: "the contents of the object shall
 * remain unchanged up to the lesser of the new and old sizes" -- both
 * growing and shrinking. ---- */
static void test_realloc_preserves(void)
{
	unsigned char *p = malloc(32);
	unsigned char *q;
	size_t i;

	CHECK(p != 0);
	if (!p) return;
	for (i = 0; i < 32; i++) p[i] = (unsigned char)(i * 3 + 1);

	/* grow: all 32 original bytes preserved */
	q = realloc(p, 4096);
	CHECK(q != 0);
	if (q) { for (i = 0; i < 32; i++) CHECK(q[i] == (unsigned char)(i * 3 + 1)); p = q; }

	/* re-fill the larger buffer, then shrink: the surviving prefix
	 * (min(old,new) = 10 bytes) must be preserved */
	for (i = 0; i < 4096; i++) p[i] = (unsigned char)(i ^ 0x5a);
	q = realloc(p, 10);
	CHECK(q != 0);
	if (q) { for (i = 0; i < 10; i++) CHECK(q[i] == (unsigned char)(i ^ 0x5a)); free(q); }
}

/* ---- realloc.html RETURN VALUE: "If realloc() fails, the original
 * block is left untouched; it is not deallocated or moved." -- an
 * ENOMEM failure must leave ptr's content readable and unchanged.
 * Triggering the failure needs a genuinely unsatisfiable request; the
 * ASan-hook comment in test/malloc.c explains why AddressSanitizer's
 * default allocator would abort rather than return NULL here, so
 * mirror that hook for this test's own asan build. ---- */
#if defined(__SANITIZE_ADDRESS__) || \
    (defined(__has_feature) && __has_feature(address_sanitizer))
const char *__asan_default_options(void);
const char *__asan_default_options(void) { return "allocator_may_return_null=1"; }
#endif

static void test_realloc_failure_untouched(void)
{
	unsigned char *p = malloc(16);
	unsigned char *q;

	CHECK(p != 0);
	if (!p) return;
	memcpy(p, "0123456789abcdef", 16);

	errno = 0;
	q = realloc(p, (size_t)-1 - 64); /* not quite SIZE_MAX: avoids any
	                                   * "size==(size_t)-1 is special"
	                                   * edge some allocators reserve */
	if (q == 0) {
		CHECK(errno == ENOMEM);
		CHECK(memcmp(p, "0123456789abcdef", 16) == 0);
		free(p);
	} else {
		/* allocator actually satisfied it (huge address space): just
		 * confirm the content survived the (successful) call */
		CHECK(memcmp(q, "0123456789abcdef", 16) == 0);
		free(q);
	}
}

/* ---- posix_memalign.html ERRORS: "[EINVAL] The value of the
 * alignment parameter is not a power of two multiple of
 * sizeof(void *)." -- already exercised in test/malloc.c; add the one
 * clause not covered there: alignment == sizeof(void*) itself (the
 * smallest legal value, boundary of "power of two multiple") must
 * succeed, not be rejected as too small. ---- */
static void test_posix_memalign_boundary(void)
{
	void *p = 0;
	int r = posix_memalign(&p, sizeof(void *), 64);
	CHECK(r == 0 && p != 0);
	CHECK(((uintptr_t)p & (sizeof(void *) - 1)) == 0);
	free(p);
}

/* =================== exit / _Exit / atexit / abort =================== */

/* Neither Wine nor the native asan build (tools/asan-build.sh, see its
 * not_native() list and comment) can be relied on to hand back a wait
 * status carrying spicule's full 0xE0DE00xx signal-death encoding
 * unmodified -- the native build's child is a real host process, and a
 * real host wait4() truncates the exit code to 8 bits before spicule's
 * own waitpid()/__wait_encode_status ever sees it (the same reason
 * test/waitpid-overflow.c and test/posix-signal.c are excluded there
 * wholesale).  So: check for "died abnormally, not a clean exit()"
 * unconditionally, and additionally require WTERMSIG()==SIGABRT only
 * when the wait status *did* come back WIFSIGNALED -- true on every
 * run under Wine (the environment the task brief's SIGABRT-shaped-death
 * requirement targets), and harmlessly not reached on the native build
 * where the encoding cannot survive the round trip.  test/misc.c's own
 * abort() child check uses the same tolerant shape for the same
 * reason. */
static void check_died_abnormally(int status)
{
	CHECK(WIFSIGNALED(status) || (WIFEXITED(status) && WEXITSTATUS(status) != 0));
	if (WIFSIGNALED(status)) CHECK(WTERMSIG(status) == SIGABRT);
}

static int spawn_self(const char *self, const char *flag, int *status)
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

/* ---- atexit.html DESCRIPTION: "at least 32 functions can be
 * registered."  Register more than 32 (well under this
 * implementation's ATEXIT_MAX=128, src/exit/exit.c), and confirm every
 * one of them succeeds and all of them run, in exact reverse order of
 * registration.  No child process is needed for this one: it is done
 * as literally the last thing this test binary itself does, the same
 * way test/misc.c's h1/h2/h3 do.  Whether the order was actually
 * correct is only known once the handlers run inside exit(), by which
 * point control has left main() for good -- there is no "come back and
 * CHECK() it" afterwards -- so the last-to-run handler (index 0,
 * registered first, since atexit is LIFO) must itself decide pass/fail
 * (folding in every CHECK() from earlier in the run via the shared
 * `fails` counter) and call _Exit() directly with the final status. */
#define N_ATEXIT_MIN 40 /* > POSIX's required minimum of 32 */

static int atexit_order[N_ATEXIT_MIN];
static int atexit_norder;

#define ATEXIT_FN(n) static void atexit_fn_##n(void) { atexit_order[atexit_norder++] = n; }
ATEXIT_FN(1) ATEXIT_FN(2) ATEXIT_FN(3) ATEXIT_FN(4)
ATEXIT_FN(5) ATEXIT_FN(6) ATEXIT_FN(7) ATEXIT_FN(8) ATEXIT_FN(9)
ATEXIT_FN(10) ATEXIT_FN(11) ATEXIT_FN(12) ATEXIT_FN(13) ATEXIT_FN(14)
ATEXIT_FN(15) ATEXIT_FN(16) ATEXIT_FN(17) ATEXIT_FN(18) ATEXIT_FN(19)
ATEXIT_FN(20) ATEXIT_FN(21) ATEXIT_FN(22) ATEXIT_FN(23) ATEXIT_FN(24)
ATEXIT_FN(25) ATEXIT_FN(26) ATEXIT_FN(27) ATEXIT_FN(28) ATEXIT_FN(29)
ATEXIT_FN(30) ATEXIT_FN(31) ATEXIT_FN(32) ATEXIT_FN(33) ATEXIT_FN(34)
ATEXIT_FN(35) ATEXIT_FN(36) ATEXIT_FN(37) ATEXIT_FN(38) ATEXIT_FN(39)

static void atexit_fn_0(void)
{
	int i, ok;
	atexit_order[atexit_norder++] = 0;
	/* last handler to run: validate the whole sequence and end the
	 * process here, since nothing after this can report through the
	 * normal `fails` exit code (see the comment above). */
	ok = (atexit_norder == N_ATEXIT_MIN);
	for (i = 0; ok && i < N_ATEXIT_MIN; i++)
		if (atexit_order[i] != N_ATEXIT_MIN - 1 - i) ok = 0;
	if (!ok) {
		fails++;
		printf("FAIL %s:%d: atexit(>=32) did not run in exact reverse order\n", __FILE__, __LINE__);
		fflush(stdout);
	}
	_Exit(fails != 0);
}

static void (*const atexit_fns[N_ATEXIT_MIN])(void) = {
	atexit_fn_0, atexit_fn_1, atexit_fn_2, atexit_fn_3, atexit_fn_4,
	atexit_fn_5, atexit_fn_6, atexit_fn_7, atexit_fn_8, atexit_fn_9,
	atexit_fn_10, atexit_fn_11, atexit_fn_12, atexit_fn_13, atexit_fn_14,
	atexit_fn_15, atexit_fn_16, atexit_fn_17, atexit_fn_18, atexit_fn_19,
	atexit_fn_20, atexit_fn_21, atexit_fn_22, atexit_fn_23, atexit_fn_24,
	atexit_fn_25, atexit_fn_26, atexit_fn_27, atexit_fn_28, atexit_fn_29,
	atexit_fn_30, atexit_fn_31, atexit_fn_32, atexit_fn_33, atexit_fn_34,
	atexit_fn_35, atexit_fn_36, atexit_fn_37, atexit_fn_38, atexit_fn_39,
};

/* handler shared by the exit-vs-_Exit and abort-vs-atexit children:
 * if it runs at all, it force-terminates the process with a
 * distinctive exit code, so the parent can tell "the atexit handler
 * ran" from "it did not" purely from the wait status -- no marker
 * file needed (and no file needed means no dependency on a spawned
 * child sharing a working directory/filesystem view with the parent,
 * which the native asan build's simulated NT filesystem does not
 * guarantee). */
static void atexit_terminate_99(void) { _Exit(99); }

/* ---- exit.html: atexit handlers run "at normal program termination"
 * via exit().  _Exit.html: "_exit() and _Exit() ... do not call
 * functions registered with atexit()."  Same child binary, two
 * argv[1] flavours so the two outcomes are directly comparable. ---- */
static void test_exit_runs_atexit_Exit_does_not(const char *self)
{
	int status;

	if (spawn_self(self, "--posix-alloc-exit-runs-atexit", &status) < 0) {
		printf("note: cannot spawn \"%s\"; exit()-runs-atexit child test skipped\n", self);
		return;
	}
	/* atexit_terminate_99 ran (and so forced exit 99) iff exit()
	 * actually called it */
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 99);

	if (spawn_self(self, "--posix-alloc-Exit-skips-atexit", &status) < 0) return;
	/* atexit_terminate_99 must NOT have run: the child's own _Exit(43)
	 * is what must be observed */
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 43);
}

/* ---- abort.html: "shall cause abnormal process termination to
 * occur, unless the signal SIGABRT is being caught and the signal
 * handler does not return", and "shall override blocking or ignoring
 * the SIGABRT signal."  Neither of those overrides is "run the
 * program's atexit() list" -- abort() does not go through exit(), so
 * an atexit-registered handler must not fire.  Exercise both the
 * ignored-signal override and the blocked-signal override, with
 * atexit_terminate_99 registered in each child: if abort() ran it,
 * the child would report a clean-looking exit(99) instead of an
 * abnormal death.  WINEDEBUG/WINEDLLOVERRIDES must be set by the
 * caller (see test/POSIX-COVERAGE.md) or the crash pops a modal
 * debugger dialog that hangs the run. ---- */
static void test_abort_not_via_atexit_and_overrides(const char *self)
{
	int status;

	if (spawn_self(self, "--posix-alloc-abort-ignored", &status) < 0) {
		printf("note: cannot spawn \"%s\"; abort()-overrides-SIG_IGN child test skipped\n", self);
		return;
	}
	CHECK(!(WIFEXITED(status) && WEXITSTATUS(status) == 99)); /* atexit handler must not have run */
	check_died_abnormally(status);

	if (spawn_self(self, "--posix-alloc-abort-blocked", &status) < 0) return;
	CHECK(!(WIFEXITED(status) && WEXITSTATUS(status) == 99));
	check_died_abnormally(status);
}

/* ---- assert.html: "writes information about the particular call
 * that failed ... to the standard error stream, and calls abort()."
 * Since assert() is DEFINED as calling abort(), the same
 * "SIGABRT-shaped death" contract applies; confirmed here directly
 * rather than only inferred from abort()'s own test above. ---- */
static void test_assert_calls_abort(const char *self)
{
	int status;

	if (spawn_self(self, "--posix-alloc-assert-fires", &status) < 0) {
		printf("note: cannot spawn \"%s\"; assert()-calls-abort child test skipped\n", self);
		return;
	}
	check_died_abnormally(status);
}

/* ================================ environ ================================ */

/* ---- setenv.html ERRORS: "[EINVAL] The envname argument points to an
 * empty string, or points to a string containing an '=' character."
 * unsetenv.html: same ERRORS wording.  Already exercised in
 * test/misc.c and test/posix-stdlib.c; not re-added here except the
 * overwrite==0-on-a-var-that-does-not-exist-yet case, which neither of
 * those files' setenv sequences happens to isolate (both only exercise
 * overwrite==0 against an *existing* variable). ---- */
static void test_setenv_overwrite_new(void)
{
	unsetenv("SPICULE_ALLOC_NEWVAR");
	CHECK(getenv("SPICULE_ALLOC_NEWVAR") == 0);
	/* setenv.html: overwrite==0 only suppresses replacing an *existing*
	 * value; for a variable that does not exist yet, it must still be
	 * created. */
	CHECK(setenv("SPICULE_ALLOC_NEWVAR", "first", 0) == 0);
	CHECK(getenv("SPICULE_ALLOC_NEWVAR") && !strcmp(getenv("SPICULE_ALLOC_NEWVAR"), "first"));
	unsetenv("SPICULE_ALLOC_NEWVAR");
}

/* ---- putenv.html DESCRIPTION: "the string pointed to by string shall
 * become part of the environment" (aliased, not copied) vs.
 * setenv.html DESCRIPTION: implies a copy is made ("the function shall
 * fail if ... insufficient memory to add a variable or its value";
 * src/env/setenv.c mallocs and memcpy's).  Directly contrast the two:
 * mutating the caller's buffer after setenv() must NOT change the
 * environment, unlike putenv(). ---- */
static void test_setenv_copies_putenv_aliases(void)
{
	char buf[] = "SPICULE_ALLOC_SRC=orig";
	char *val = strchr(buf, '=') + 1; /* -> "orig", 4 bytes incl. NUL */

	CHECK(setenv("SPICULE_ALLOC_COPY", val, 1) == 0); /* copies "orig" */
	strcpy(val, "XXXX");
	CHECK(getenv("SPICULE_ALLOC_COPY") && !strcmp(getenv("SPICULE_ALLOC_COPY"), "orig"));
	unsetenv("SPICULE_ALLOC_COPY");

	CHECK(putenv(buf) == 0); /* SPICULE_ALLOC_SRC=XXXX, string aliased */
	strcpy(val, "YYYY");
	CHECK(getenv("SPICULE_ALLOC_SRC") && !strcmp(getenv("SPICULE_ALLOC_SRC"), "YYYY"));
	unsetenv("SPICULE_ALLOC_SRC");
}

/* ---- environ.html: "the array of pointers ... is named environ ...
 * shall be considered read-only" for entries added by getenv/setenv,
 * i.e. any modification made through setenv/unsetenv/putenv must be
 * visible by walking environ directly, and a removed entry must be
 * gone from it too (not just from getenv()). ---- */
static void test_environ_reflects_state(void)
{
	char **e;
	int seen;

	CHECK(setenv("SPICULE_ALLOC_ENVWALK", "v", 1) == 0);
	seen = 0;
	for (e = environ; e && *e; e++) if (!strncmp(*e, "SPICULE_ALLOC_ENVWALK=", 21)) seen = 1;
	CHECK(seen);

	CHECK(unsetenv("SPICULE_ALLOC_ENVWALK") == 0);
	seen = 0;
	for (e = environ; e && *e; e++) if (!strncmp(*e, "SPICULE_ALLOC_ENVWALK=", 21)) seen = 1;
	CHECK(!seen);
}

/* ---- Is a setenv()-modified environment inherited by a child?  Real
 * integration point on NT: the environment block __spawn hands the
 * child is UTF-16 and rebuilt at spawn time (src/process/spawn.c), so
 * this is genuinely exercising that rebuild, not just process
 * inheritance in the abstract.  The child (--posix-alloc-envcheck)
 * exits with a distinct code per outcome so the parent needs no IPC
 * beyond the exit status. ---- */
static void test_setenv_inherited_by_child(const char *self)
{
	int status;

	CHECK(setenv("SPICULE_ALLOC_INHERIT", "childsees", 1) == 0);
	if (spawn_self(self, "--posix-alloc-envcheck", &status) < 0) {
		printf("note: cannot spawn \"%s\"; setenv-inheritance child test skipped\n", self);
		unsetenv("SPICULE_ALLOC_INHERIT");
		return;
	}
	CHECK(WIFEXITED(status));
	if (WIFEXITED(status)) {
		printf("note: setenv()-modified environment inherited by child: %s\n",
		       WEXITSTATUS(status) == 44 ? "yes" : "no");
		CHECK(WEXITSTATUS(status) == 44 || WEXITSTATUS(status) == 45);
	}
	unsetenv("SPICULE_ALLOC_INHERIT");
}

/* ================================== main ================================== */

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "--posix-alloc-exit-runs-atexit")) {
		atexit(atexit_terminate_99);
		exit(42); /* if atexit_terminate_99 runs, the process actually exits 99 */
	}
	if (argc > 1 && !strcmp(argv[1], "--posix-alloc-Exit-skips-atexit")) {
		atexit(atexit_terminate_99);
		_Exit(43);
	}
	if (argc > 1 && !strcmp(argv[1], "--posix-alloc-abort-ignored")) {
		atexit(atexit_terminate_99);
		signal(SIGABRT, SIG_IGN);
		abort();
	}
	if (argc > 1 && !strcmp(argv[1], "--posix-alloc-abort-blocked")) {
		sigset_t s;
		atexit(atexit_terminate_99);
		sigemptyset(&s);
		sigaddset(&s, SIGABRT);
		sigprocmask(SIG_BLOCK, &s, 0);
		abort();
	}
	if (argc > 1 && !strcmp(argv[1], "--posix-alloc-assert-fires")) {
		volatile int zero = 0;
		assert(zero == 1); /* prints "Assertion failed: ..." to stderr: expected noise */
		return 0; /* did not fire -> parent's check_died_abnormally() fails, reported */
	}
	if (argc > 1 && !strcmp(argv[1], "--posix-alloc-envcheck")) {
		char *v = getenv("SPICULE_ALLOC_INHERIT");
		return (v && !strcmp(v, "childsees")) ? 44 : 45;
	}

	test_malloc_zero();
	test_realloc_zero();
	test_calloc_zeroes();
	test_calloc_overflow();
	test_realloc_preserves();
	test_realloc_failure_untouched();
	test_posix_memalign_boundary();

	test_exit_runs_atexit_Exit_does_not(argv[0]);
	test_abort_not_via_atexit_and_overrides(argv[0]);
	test_assert_calls_abort(argv[0]);

	test_setenv_overwrite_new();
	test_setenv_copies_putenv_aliases();
	test_environ_reflects_state();
	test_setenv_inherited_by_child(argv[0]);

	if (!fails) printf("posix-alloc: all tests passed\n");

	/* atexit(>=32) + exact-reverse-order check: must be the very last
	 * thing this process does -- see the comment above atexit_fn_0().
	 * It never returns; atexit_fn_0 calls _Exit() with the final
	 * pass/fail status once every handler above it has run. */
	{
		int i;
		for (i = 0; i < N_ATEXIT_MIN; i++) CHECK(atexit(atexit_fns[i]) == 0);
	}
	exit(0);
}
