/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of <signal.h> and <sys/wait.h>,
 * checked against https://pubs.opengroup.org/onlinepubs/9699919799/functions/<name>.html
 * (and .../basedefs/signal.h.html, .../basedefs/sys_wait.h.html for the
 * macros/flags). This is *additional* coverage on top of the existing
 * ad-hoc passes in test/misc.c (env/setjmp/signal/abort-in-child) and
 * test/waitpid-overflow.c (wait-status encoding, child-table growth) --
 * read those first; this file does not repeat what they already assert.
 *
 * src/signal/signal.c's header comment is required reading before any of
 * this: signals are self-generated, synchronous CPU exceptions, timer APCs,
 * or packets handled by spicule's delivery thread.  Blocking interfaces use
 * those asynchronous sources without pretending an ordinary instruction can
 * be interrupted in place.
 */
/* kill() and the sigaction()/sigemptyset()/sigprocmask() family are
 * feature-test gated in include/signal.h; same define most other
 * tests in test/ already carry for the same reason (see test/posix-glob.c's
 * comment on this exact define). */
#define _GNU_SOURCE
#include "test-policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/time.h>
#include <limits.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* Native ASan build (tools/asan-build.sh): fuzz/ntstubs.c's
 * RtlAddVectoredExceptionHandler stores nothing and forwards no real
 * hardware fault to it, on purpose -- see the SIGSEGV/SIGFPE tests below
 * for why bridging one in would cost more than it buys here. Reused
 * verbatim from test/malloc.c / test/posix-alloc.c's ASan detection. */
#if defined(_SPICULE_NATIVE_BUILD) || defined(__SANITIZE_ADDRESS__) || \
    (defined(__has_feature) && __has_feature(address_sanitizer))
#define NATIVE_NO_FAULT_BRIDGE 1
#endif

/* Internal: spawn a program as a child, return its pid (see
 * src/process/spawn.c). fork() needs RtlCloneUserProcess, which Wine
 * lacks, so __spawn is used for every child-process test here, same as
 * test/misc.c and test/waitpid-overflow.c. */
int __spawn(const char *path, char *const argv[], char *const envp[]);

/* src/process/wait.c's pure exit-code -> wait-status mapping, exposed
 * (not static) via src/internal/libc.h for exactly this: driving its
 * boundary cases directly instead of only through a spawned process.
 * test/ is not on the -I path for src/internal/, so it is declared
 * locally here, the same way test/posix-errno.c declares
 * __errno_from_status(). __ENCODE_SIGNAL_EXIT's formula is copied by hand
 * from src/internal/libc.h for the same reason. */
int __wait_encode_status(int);
#define ENCODE_SIGNAL_EXIT(sig) ((int)(0xE0DE0000u | ((unsigned)(sig) & 0x7fu)))

/* NtAllocateVirtualMemory()/NtProtectVirtualMemory(), used below to
 * provoke a SIGSEGV on a page that genuinely exists (MEM_COMMIT) but is
 * PAGE_NOACCESS -- the SEGV_ACCERR half of src/signal/signal.c's
 * segv_code(); the existing --fault-segv-siginfo child already covers
 * the SEGV_MAPERR half with a plain unmapped address. Hand-declared,
 * same reasoning as __wait_encode_status()/__errno_from_status() above
 * (test/posix-errno.c) -- test/ is not on the -I path for
 * src/internal/nt.h, and these two calls need real ntdll prototypes,
 * types and constants that are not part of any public <...> header. */
typedef int NTSTATUS;
typedef void *HANDLE;
typedef unsigned long ULONG;
#ifdef __i386__
#define NTAPI __attribute__((stdcall))
#else
#define NTAPI
#endif
#if defined(_WIN64) || defined(__x86_64__)
typedef unsigned long long SIZE_T;
#else
typedef unsigned long SIZE_T;
#endif
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define NtCurrentProcess() ((HANDLE)(size_t)-1)   /* pointer-sized, unlike plain long under LLP64 */
#define MEM_COMMIT   0x00001000
#define MEM_RESERVE  0x00002000
#define PAGE_NOACCESS  0x01
#define PAGE_READWRITE 0x04
NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, void **, unsigned long, SIZE_T *, ULONG, ULONG);
NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE, void **, SIZE_T *, ULONG, ULONG *);

extern char **environ;
static char *self;   /* argv[0], set in main(); used to re-spawn ourselves */

/* ================================================================== *
 * signal.html: signal()
 * ================================================================== */

/* "an attempt is made to catch a signal that cannot be caught" -> SIG_ERR
 * / EINVAL. test/misc.c already checks this for SIGKILL; SIGSTOP is the
 * other signal src/signal/signal.c's sig_valid()-adjacent check refuses
 * (see signal(), sigaction(), sigprocmask() all special-casing it). */
static void dummy_handler(int s) { (void)s; }

static void test_signal_sigstop(void)
{
	errno = 0;
	CHECK(signal(SIGSTOP, dummy_handler) == SIG_ERR && errno == EINVAL);
}

/* sig_atomic_t: signal.html's DESCRIPTION forbids a handler from
 * touching anything other than a volatile sig_atomic_t (plus errno).
 * Because every signal here is delivered synchronously, inside the
 * raise()/kill()/abort() call itself, there is no reordering or
 * partial-write hazard to demonstrate -- but the type still has to
 * exist, be assignable from a handler, and be visible to the caller the
 * moment the delivering call returns. */
static volatile sig_atomic_t atomic_flag;
static void atomic_handler(int s) { atomic_flag = s; }

static void test_sig_atomic_t(void)
{
	sig_atomic_t plain;   /* not required to be volatile outside a handler */
	plain = 5;
	CHECK(plain == 5);

	CHECK(signal(SIGUSR1, atomic_handler) != SIG_ERR);
	atomic_flag = 0;
	CHECK(raise(SIGUSR1) == 0);
	CHECK(atomic_flag == SIGUSR1);   /* observable right after raise() returns */
	CHECK(signal(SIGUSR1, SIG_DFL) == atomic_handler);
}

/* raise.html ERRORS: "[EINVAL] The value of the sig argument is an
 * invalid signal number." test/misc.c already checks raise(0); add the
 * other two boundaries sig_valid() rejects. */
static void test_raise_einval(void)
{
	errno = 0;
	CHECK(raise(-1) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(raise(_NSIG) == -1 && errno == EINVAL);
}

/* ================================================================== *
 * kill.html
 * ================================================================== */

static void test_kill(void)
{
	pid_t pid;
	int status;
	char *argv[3];

	/* ERRORS: "[EINVAL] The value of the sig argument is an invalid or
	 * unsupported signal number." kill(self, sig) routes through
	 * raise()/__raise_internal(), which validates sig. */
	errno = 0;
	CHECK(kill(getpid(), 9999) == -1 && errno == EINVAL);

	/* ERRORS: "[ESRCH] No process or process group can be found
	 * corresponding to that specified by pid." A pid nothing ever
	 * spawned (and NtOpenProcess therefore cannot open) must fail this
	 * way, not merely return a wrong success. */
	errno = 0;
	CHECK(kill((pid_t)0x7ffffffe, SIGTERM) == -1 && errno == ESRCH);

	/* DESCRIPTION: sig==0 is the existence/permission check -- "no
	 * signal is actually sent" -- exercised here against a *real*,
	 * still-running child rather than the caller itself. */
	argv[0] = self; argv[1] = (char *)"--sleep"; argv[2] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid <= 0) { printf("note: cannot spawn self (errno %d); kill() child tests skipped\n", errno); return; }
	CHECK(kill(pid, 0) == 0);   /* exists, not signaled */

	/* DESCRIPTION: pid > 0 sends sig to exactly that process; waitpid
	 * afterwards proves the signal actually reached and ended it (this
	 * is also the sig_status()/WTERMSIG round trip, but from the kill()
	 * side of the contract rather than wait()'s). */
	CHECK(kill(pid, SIGTERM) == 0);
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);

	/* kill(0, sig) after the child is gone: 0 no longer names anything
	 * kill() can open, but see the N/A note in the ledger fragment about
	 * pid==0/pid<-1 process-group targeting -- that path is not what is
	 * being exercised here. */
}

#if SPICULE_TEST(PASS, posix_signal_kill_validates_sig_for_other_pid) /* Fixed: kill() now validates sig before selecting the target path.
	 * and terminates the target with the unvalidated value otherwise.
	 * kill.html ERRORS, shall fail: "[EINVAL] The value of the sig
	 * argument is an invalid or unsupported signal number."  And
	 * DESCRIPTION, on the null signal: "If sig is 0 (the null signal),
	 * error checking is performed but no signal is actually sent" --
	 * the whole design of the page is that a call which fails its
	 * checks delivers nothing.
	 *
	 * Mechanism: src/signal/signal.c's kill() has two arms.  The
	 * self-arm --
	 *
	 *     if (pid == getpid() || pid == 0 || pid == -1) {
	 *             if (!sig) return 0;
	 *             return raise(sig);
	 *     }
	 *
	 * -- reaches sig_valid() through raise()/__raise_internal(), which
	 * is what makes the kill(getpid(), 9999) assertion in test_kill()
	 * above pass.  The remote-pid arm never calls sig_valid() at all.
	 * It opens the target and goes straight to
	 *
	 *     NtTerminateProcess(h, __ENCODE_SIGNAL_EXIT(sig));
	 *
	 * and __ENCODE_SIGNAL_EXIT (src/internal/libc.h) is
	 * `0xE0DE0000 | ((unsigned)sig & 0x7f)` -- it *masks* the number
	 * rather than rejecting it.  So an invalid signal number does not
	 * merely fail to be rejected: the process dies, and the exit status
	 * encodes whatever the low seven bits happened to be.  9999 & 0x7f
	 * is 15, so the parent's waitpid() reports WTERMSIG == SIGTERM for
	 * a signal that was never a signal; kill(pid, -1) masks to 127 and
	 * kills just as cheerfully.
	 *
	 * This is the destructive shape of a missing argument check: a
	 * conforming program that computes a signal number and gets it
	 * wrong is told the kill succeeded, the target is gone, and the
	 * status blames a different signal.
	 *
	 * The fix is to move sig_valid() ahead of the pid dispatch, so both
	 * arms reject before anything is opened or terminated.
	 *
	 * Re-enable when the remote-pid arm validates sig. */
static void test_kill_validates_sig_for_other_pid(void)
{
	pid_t pid;
	int status;
	char *argv[3];

	argv[0] = self; argv[1] = (char *)"--sleep"; argv[2] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid <= 0) { printf("note: cannot spawn self (errno %d); skipped\n", errno); return; }

	errno = 0;
	CHECK(kill(pid, 9999) == -1 && errno == EINVAL);
	CHECK(kill(pid, 0) == 0);	/* nothing was sent: still there */

	errno = 0;
	CHECK(kill(pid, -1) == -1 && errno == EINVAL);
	CHECK(kill(pid, 0) == 0);

	errno = 0;
	CHECK(kill(pid, _NSIG) == -1 && errno == EINVAL);
	CHECK(kill(pid, 0) == 0);

	CHECK(kill(pid, SIGTERM) == 0);
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
}
#endif

/* ================================================================== *
 * sigaction.html
 * ================================================================== */

static void handler_a(int s) { (void)s; }
static void handler_b(int s) { (void)s; }

static void test_sigaction_query_and_einval(void)
{
	struct sigaction sa, old;

	/* DESCRIPTION: "If act is a null pointer, signal handling is
	 * unchanged; thus, the call can be used to enquire about the
	 * current handling of a given signal." */
	CHECK(signal(SIGUSR2, handler_a) != SIG_ERR);
	memset(&old, 0xaa, sizeof old);
	CHECK(sigaction(SIGUSR2, NULL, &old) == 0);
	CHECK(old.sa_handler == handler_a);
	CHECK(signal(SIGUSR2, SIG_DFL) == handler_a);   /* unchanged by the query */

	/* oact may be NULL: must not crash, must not fail. */
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler_b;
	CHECK(sigaction(SIGUSR2, &sa, NULL) == 0);
	CHECK(signal(SIGUSR2, SIG_DFL) == handler_b);

	/* ERRORS: EINVAL for SIGKILL/SIGSTOP, same restriction as signal(). */
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler_a;
	errno = 0;
	CHECK(sigaction(SIGKILL, &sa, NULL) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(sigaction(SIGSTOP, &sa, NULL) == -1 && errno == EINVAL);
}

/* SA_RESETHAND (sigaction.html DESCRIPTION): "the disposition of the
 * signal shall be reset to SIG_DFL ... on entry to the signal handler."
 * Use SIGWINCH: its default action here is "ignore"
 * (src/signal/signal.c: default_action()), so re-delivering it after
 * the reset is safe to observe in-process -- unlike a signal whose
 * default action terminates the process. */
static int resethand_calls;
static void resethand_handler(int s) { (void)s; resethand_calls++; }

static void test_sa_resethand(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = resethand_handler;
	sa.sa_flags = SA_RESETHAND;
	CHECK(sigaction(SIGWINCH, &sa, NULL) == 0);

	resethand_calls = 0;
	CHECK(raise(SIGWINCH) == 0);
	CHECK(resethand_calls == 1);   /* handler ran once */

	CHECK(raise(SIGWINCH) == 0);   /* disposition should now be SIG_DFL (ignore) */
	CHECK(resethand_calls == 1);
	signal(SIGWINCH, SIG_DFL);
}

/* sa_mask / implicit self-mask on entry (sigaction.html DESCRIPTION):
 * "the signal being delivered ... shall be added to [the mask] unless
 * SA_NODEFER is set." i.e. by default a signal is blocked against
 * itself while its own handler runs. */
static int nodefer_self_was_blocked = -1;
static void mask_check_handler(int s)
{
	sigset_t cur;
	sigprocmask(SIG_BLOCK, NULL, &cur);   /* set==NULL: read only, per sigprocmask.html */
	nodefer_self_was_blocked = sigismember(&cur, s);
}

static void test_sigaction_implicit_mask(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = mask_check_handler;   /* SA_NODEFER not set */
	CHECK(sigaction(SIGWINCH, &sa, NULL) == 0);

	nodefer_self_was_blocked = -1;
	CHECK(raise(SIGWINCH) == 0);
	CHECK(nodefer_self_was_blocked == 1);
	signal(SIGWINCH, SIG_DFL);
}

/* ================================================================== *
 * sigemptyset.html / sigaddset.html / sigismember.html
 * ================================================================== */

static void test_sigsetops(void)
{
	sigset_t s;

	/* sigemptyset.html/sigfillset: "No errors are defined." -- always 0. */
	CHECK(sigemptyset(&s) == 0);
	CHECK(sigisemptyset(&s) == 1);
	CHECK(sigfillset(&s) == 0);
	CHECK(sigisemptyset(&s) == 0);

	/* sigaddset.html/sigdelset/sigismember ERRORS: "[EINVAL] The value
	 * of the signo argument is an invalid or unsupported signal
	 * number." for all three boundary shapes sig_valid() rejects. */
	errno = 0; CHECK(sigaddset(&s, 0) == -1 && errno == EINVAL);
	errno = 0; CHECK(sigaddset(&s, -1) == -1 && errno == EINVAL);
	errno = 0; CHECK(sigaddset(&s, _NSIG) == -1 && errno == EINVAL);
	errno = 0; CHECK(sigdelset(&s, 0) == -1 && errno == EINVAL);
	errno = 0; CHECK(sigdelset(&s, _NSIG) == -1 && errno == EINVAL);
	errno = 0; CHECK(sigismember(&s, 0) == -1 && errno == EINVAL);
	errno = 0; CHECK(sigismember(&s, _NSIG) == -1 && errno == EINVAL);

	/* sigismember.html RETURN VALUE: "shall return 1 if the specified
	 * signal is a member ... or 0 if it is not" -- exactly 1 or 0, not
	 * merely truthy/falsy. */
	sigemptyset(&s);
	CHECK(sigismember(&s, SIGTERM) == 0);
	CHECK(sigaddset(&s, SIGTERM) == 0);
	CHECK(sigismember(&s, SIGTERM) == 1);
	CHECK(sigdelset(&s, SIGTERM) == 0);
	CHECK(sigismember(&s, SIGTERM) == 0);

	/* The highest valid signal number (_NSIG - 1) must work too, not
	 * just the low, well-known ones. */
	sigfillset(&s);
	CHECK(sigismember(&s, _NSIG - 1) == 1);
}

/* sigorset(3) (glibc/BSD, not POSIX -- src/signal/signal.c's own
 * comment: "sigorset() would do this in one call" describing the very
 * loop it replaces): "the union of the sets ... is stored in dest".
 * Checked directly, plus its two-sided special cases: ORing with an
 * empty set is a no-op, and ORing with a full set gives a full set. */
static void test_sigorset(void)
{
	sigset_t a, b, dest;

	sigemptyset(&a);
	sigemptyset(&b);
	CHECK(sigaddset(&a, SIGTERM) == 0);
	CHECK(sigaddset(&b, SIGINT) == 0);

	sigemptyset(&dest);
	CHECK(sigorset(&dest, &a, &b) == 0);
	CHECK(sigismember(&dest, SIGTERM) == 1);
	CHECK(sigismember(&dest, SIGINT) == 1);
	CHECK(sigismember(&dest, SIGHUP) == 0);

	/* union with an empty set changes nothing */
	sigemptyset(&b);
	sigemptyset(&dest);
	CHECK(sigorset(&dest, &a, &b) == 0);
	CHECK(sigismember(&dest, SIGTERM) == 1);
	CHECK(sigismember(&dest, SIGINT) == 0);

	/* union with a full set is full */
	sigfillset(&b);
	CHECK(sigorset(&dest, &a, &b) == 0);
	CHECK(sigisemptyset(&dest) == 0);
	CHECK(sigismember(&dest, _NSIG - 1) == 1);
}

/* <signal.h>: "SIGRTMAX A symbolic constant that expands to a positive
 * integer, of type int, that is the highest number of a realtime
 * signal" -- defined here (include/signal.h) as a call through
 * __libc_current_sigrtmax(), the same indirection glibc itself uses so
 * the value can be computed rather than hardcoded. Checked against
 * SIGRTMIN and against sig_valid()'s own upper bound (_NSIG - 1, per
 * sigismember() accepting it above), since those are the two facts a
 * caller building an RT signal set actually relies on. */
static void test_sigrtmax(void)
{
	CHECK(SIGRTMAX == __libc_current_sigrtmax());
	CHECK(SIGRTMAX >= SIGRTMIN);
	CHECK(SIGRTMAX == _NSIG - 1);

	{
		sigset_t s;
		sigemptyset(&s);
		CHECK(sigaddset(&s, SIGRTMAX) == 0);
		CHECK(sigismember(&s, SIGRTMAX) == 1);
	}
}

/* ================================================================== *
 * sigprocmask.html
 * ================================================================== */

static void test_sigprocmask(void)
{
	sigset_t s, old, cur;

	/* ERRORS: "[EINVAL] The value of the how argument is not equal to
	 * one of the defined values [SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK]." */
	sigemptyset(&s);
	errno = 0;
	CHECK(sigprocmask(99, &s, NULL) == -1 && errno == EINVAL);

	/* DESCRIPTION: "If set is a null pointer, the value of ... how is
	 * not significant and the ... signal mask of the thread is
	 * unchanged"; oset, if non-null, still gets the current mask. */
	sigemptyset(&s);
	CHECK(sigprocmask(SIG_SETMASK, &s, NULL) == 0);   /* start from empty */
	CHECK(sigprocmask(SIG_BLOCK, NULL, &old) == 0);
	CHECK(sigisemptyset(&old) == 1);

	/* SIG_SETMASK: "the resulting set shall be the signal set pointed
	 * to by set" -- a full replace, not a union/intersection. */
	sigemptyset(&s);
	sigaddset(&s, SIGUSR1);
	sigaddset(&s, SIGUSR2);
	CHECK(sigprocmask(SIG_SETMASK, &s, NULL) == 0);
	sigprocmask(SIG_BLOCK, NULL, &cur);
	CHECK(sigismember(&cur, SIGUSR1) == 1 && sigismember(&cur, SIGUSR2) == 1);
	sigemptyset(&s);
	sigaddset(&s, SIGTERM);
	CHECK(sigprocmask(SIG_SETMASK, &s, &old) == 0);   /* replaces, not unions */
	CHECK(sigismember(&old, SIGUSR1) == 1);           /* old reported the prior mask */
	sigprocmask(SIG_BLOCK, NULL, &cur);
	CHECK(sigismember(&cur, SIGUSR1) == 0 && sigismember(&cur, SIGTERM) == 1);

	/* DESCRIPTION: "It is not possible to block [SIGKILL, SIGSTOP].
	 * This shall be enforced by the system without causing an error." */
	sigemptyset(&s);
	sigaddset(&s, SIGKILL);
	sigaddset(&s, SIGSTOP);
	CHECK(sigprocmask(SIG_BLOCK, &s, NULL) == 0);   /* no error */
	sigprocmask(SIG_BLOCK, NULL, &cur);
	CHECK(sigismember(&cur, SIGKILL) == 0);
	CHECK(sigismember(&cur, SIGSTOP) == 0);

	/* restore a clean mask for the rest of the file */
	sigemptyset(&s);
	sigprocmask(SIG_SETMASK, &s, NULL);
}

/* sigpending.html DESCRIPTION: "store ... the set of signals ... blocked
 * from delivery ... and ... pending." Complements test/misc.c's "blocked
 * signal becomes pending" check by also confirming pending is empty
 * beforehand and cleared again after delivery. */
#if SPICULE_TEST(PASS, posix_signal_sigign_discards_pending) /* Setting a disposition to SIG_IGN discards an
	 * already-pending signal.  sigaction.html DESCRIPTION: "Setting a
	 * signal action to SIG_IGN for a signal that is pending shall cause
	 * the pending signal to be discarded, whether or not it is
	 * blocked."  And immediately after: "Setting a signal action to
	 * SIG_DFL for a signal that is pending, and whose default action is
	 * to ignore the signal (for example, SIGCHLD), shall cause the
	 * pending signal to be discarded, whether or not it is blocked."
	 *
	 * Mechanism: `pending` is a file-static in src/signal/signal.c with
	 * exactly four references -- its definition, the line in
	 * __raise_internal() that adds to it when the signal is blocked,
	 * the drain loop in sigprocmask(), and sigpending().  Neither
	 * signal() nor sigaction() touches it: they write handlers[],
	 * act_mask[] and act_flags[] and nothing else.  So a signal that
	 * went pending under a block stays pending across any number of
	 * disposition changes.
	 *
	 * The delivery itself is harmless -- __raise_internal() returns
	 * immediately for SIG_IGN -- but the pending set is directly
	 * observable through sigpending(), and it is not merely cosmetic:
	 * setting the disposition back to a real handler before unblocking
	 * resurrects a signal POSIX says was discarded, and the handler
	 * runs.
	 *
	 * Re-enable when signal()/sigaction() clear the pending bit for a
	 * disposition of SIG_IGN, and for SIG_DFL on a signal whose default
	 * action is to ignore (default_action() in the same file already
	 * classifies SIGCHLD/SIGURG/SIGWINCH/SIGCONT that way). */
static void test_sigign_discards_pending(void)
{
	sigset_t s, pend;

	sigemptyset(&s);
	sigaddset(&s, SIGUSR1);
	CHECK(sigprocmask(SIG_BLOCK, &s, NULL) == 0);
	CHECK(raise(SIGUSR1) == 0);
	CHECK(sigpending(&pend) == 0 && sigismember(&pend, SIGUSR1) == 1);

	/* "shall cause the pending signal to be discarded, whether or not
	 * it is blocked" -- it is still blocked here. */
	CHECK(signal(SIGUSR1, SIG_IGN) != SIG_ERR);
	CHECK(sigpending(&pend) == 0);
	CHECK(sigismember(&pend, SIGUSR1) == 0);

	/* and so it must not come back when a handler is reinstated and the
	 * signal unblocked. */
	CHECK(signal(SIGUSR1, dummy_handler) != SIG_ERR);
	CHECK(sigprocmask(SIG_UNBLOCK, &s, NULL) == 0);
	CHECK(sigpending(&pend) == 0 && sigismember(&pend, SIGUSR1) == 0);

	/* the SIG_DFL half, on a signal whose default action is to ignore */
	sigemptyset(&s);
	sigaddset(&s, SIGCHLD);
	CHECK(sigprocmask(SIG_BLOCK, &s, NULL) == 0);
	CHECK(signal(SIGCHLD, dummy_handler) != SIG_ERR);
	CHECK(raise(SIGCHLD) == 0);
	CHECK(sigpending(&pend) == 0 && sigismember(&pend, SIGCHLD) == 1);
	CHECK(signal(SIGCHLD, SIG_DFL) != SIG_ERR);
	CHECK(sigpending(&pend) == 0 && sigismember(&pend, SIGCHLD) == 0);

	CHECK(sigprocmask(SIG_UNBLOCK, &s, NULL) == 0);
	signal(SIGUSR1, SIG_DFL);
}
#endif

static void test_sigpending(void)
{
	sigset_t s, pend;

	sigemptyset(&s);
	CHECK(sigprocmask(SIG_SETMASK, &s, NULL) == 0);
	CHECK(sigpending(&pend) == 0);
	CHECK(sigisemptyset(&pend) == 1);   /* nothing pending with an empty mask */

	sigaddset(&s, SIGUSR1);
	CHECK(sigprocmask(SIG_BLOCK, &s, NULL) == 0);
	CHECK(raise(SIGUSR1) == 0);
	CHECK(sigpending(&pend) == 0 && sigismember(&pend, SIGUSR1) == 1);

	signal(SIGUSR1, dummy_handler);   /* something to deliver into on unblock */
	CHECK(sigprocmask(SIG_UNBLOCK, &s, NULL) == 0);   /* delivers it */
	CHECK(sigpending(&pend) == 0);
	CHECK(sigismember(&pend, SIGUSR1) == 0);   /* no longer pending once delivered */
	signal(SIGUSR1, SIG_DFL);
}

#ifdef _WIN32
struct new_thread_signal_state {
	sigset_t mask;
	sigset_t pending;
	int mask_result;
	int pending_result;
};

static void *capture_new_thread_signal_state(void *argument)
{
	struct new_thread_signal_state *state = argument;
	state->mask_result = pthread_sigmask(SIG_SETMASK, NULL, &state->mask);
	state->pending_result = sigpending(&state->pending);
	return NULL;
}

static void test_new_thread_pending_empty(void)
{
	struct new_thread_signal_state state;
	void (*old_usr1)(int), (*old_usr2)(int);
	sigset_t block, old, pending;
	pthread_t thread;

	/* pthread_create.html: "The signal mask shall be inherited from the
	 * creating thread" but "The set of signals pending for the new thread
	 * shall be empty."  raise() is thread-directed, so signals pending for
	 * this thread must not leak into the new thread's initial state. */
	memset(&state, 0, sizeof state);
	CHECK(sigemptyset(&block) == 0);
	CHECK(sigaddset(&block, SIGUSR1) == 0);
	CHECK(sigaddset(&block, SIGUSR2) == 0);
	CHECK(pthread_sigmask(SIG_BLOCK, &block, &old) == 0);
	CHECK(raise(SIGUSR1) == 0);
	CHECK(raise(SIGUSR2) == 0);
	CHECK(sigpending(&pending) == 0);
	CHECK(sigismember(&pending, SIGUSR1) == 1);
	CHECK(sigismember(&pending, SIGUSR2) == 1);

	CHECK(pthread_create(&thread, NULL, capture_new_thread_signal_state,
	                     &state) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	CHECK(state.mask_result == 0);
	CHECK(state.pending_result == 0);
	CHECK(sigismember(&state.mask, SIGUSR1) == 1);
	CHECK(sigismember(&state.mask, SIGUSR2) == 1);
	CHECK(sigismember(&state.pending, SIGUSR1) == 0);
	CHECK(sigismember(&state.pending, SIGUSR2) == 0);

	/* Discard this thread's two pending signals before restoring its mask,
	 * without disturbing whatever dispositions the caller had installed. */
	old_usr1 = signal(SIGUSR1, SIG_IGN);
	old_usr2 = signal(SIGUSR2, SIG_IGN);
	CHECK(old_usr1 != SIG_ERR);
	CHECK(old_usr2 != SIG_ERR);
	CHECK(pthread_sigmask(SIG_SETMASK, &old, NULL) == 0);
	if (old_usr1 != SIG_ERR) CHECK(signal(SIGUSR1, old_usr1) != SIG_ERR);
	if (old_usr2 != SIG_ERR) CHECK(signal(SIGUSR2, old_usr2) != SIG_ERR);
}
#else
static void test_new_thread_pending_empty(void)
{
	/* The native sanitizer shim deliberately refuses NtCreateThreadEx: it
	 * has no NT thread/APC substrate.  The PE test runs this case under Wine
	 * and real Windows; do not dereference pthread_create()'s untouched
	 * output after that explicit native refusal. */
	puts("note: native sanitizer shim has no NT thread substrate; new-thread signal state skipped");
}
#endif

static volatile sig_atomic_t queued_handler_value;

static void queued_handler(int sig, siginfo_t *info, void *context)
{
	(void)sig;
	(void)context;
	queued_handler_value = info->si_value.sival_int;
}

static void test_realtime_signal_queue(void)
{
	struct sigaction sa;
	struct timespec zero = { 0, 0 };
	struct timespec huge = { LLONG_MAX, 999999999L };
	union sigval value;
	siginfo_t info;
	sigset_t set, pend;
	int sig = SIGRTMIN;

	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = queued_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	CHECK(sigaction(sig, &sa, NULL) == 0);
	sigemptyset(&set);
	sigaddset(&set, sig);
	CHECK(sigprocmask(SIG_BLOCK, &set, NULL) == 0);

	value.sival_int = 11;
	CHECK(sigqueue(getpid(), sig, value) == 0);
	value.sival_int = 22;
	CHECK(sigqueue(getpid(), sig, value) == 0);
	CHECK(sigpending(&pend) == 0 && sigismember(&pend, sig) == 1);
	CHECK(sigwaitinfo(&set, &info) == sig);
	CHECK(info.si_code == SI_QUEUE && info.si_value.sival_int == 11);
	CHECK(sigpending(&pend) == 0 && sigismember(&pend, sig) == 1);
	CHECK(sigwaitinfo(&set, &info) == sig);
	CHECK(info.si_value.sival_int == 22);
	CHECK(sigpending(&pend) == 0 && sigismember(&pend, sig) == 0);

	/* A pending member must be returned immediately even with the largest
	 * valid relative timeout: the conversion to an absolute deadline must
	 * not overflow signed nanoseconds before the queue scan runs. */
	value.sival_int = 33;
	CHECK(sigqueue(getpid(), sig, value) == 0);
	CHECK(sigtimedwait(&set, &info, &huge) == sig);
	CHECK(info.si_value.sival_int == 33);

	errno = 0;
	CHECK(sigtimedwait(&set, &info, &zero) == -1 && errno == EAGAIN);
	CHECK(raise(sig) == 0 && raise(sig) == 0);
	CHECK(sigwait(&set, &sig) == 0 && sig == SIGRTMIN);
	CHECK(sigpending(&pend) == 0 && sigismember(&pend, SIGRTMIN) == 1);
	CHECK(sigwait(&set, &sig) == 0 && sig == SIGRTMIN);

	CHECK(sigprocmask(SIG_UNBLOCK, &set, NULL) == 0);
	queued_handler_value = 0;
	value.sival_int = 37;
	CHECK(sigqueue(getpid(), SIGRTMIN, value) == 0);
	CHECK(queued_handler_value == 37);
	signal(SIGRTMIN, SIG_DFL);
}

static volatile sig_atomic_t sigsuspend_alarm_caught;
static void sigsuspend_alarm_handler(int sig)
{
	(void)sig;
	sigsuspend_alarm_caught = 1;
}

/* sigsuspend.html: atomically install the temporary mask and suspend until
 * a caught signal arrives, then restore the old mask and return -1/EINTR.
 * alarm() supplies a genuinely asynchronous signal to the calling thread;
 * cross-process mask replacement and pending delivery are covered in
 * posix-signal-crossproc.c. */
static void test_sigsuspend_wait(void)
{
	struct sigaction sa, old;
	sigset_t temporary, before, after;

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = sigsuspend_alarm_handler;
	sigemptyset(&sa.sa_mask);
	CHECK(sigaction(SIGALRM, &sa, &old) == 0);
	CHECK(sigprocmask(SIG_SETMASK, NULL, &before) == 0);
	sigemptyset(&temporary);
	sigsuspend_alarm_caught = 0;
	alarm(1);
	errno = 0;
	CHECK(sigsuspend(&temporary) == -1 && errno == EINTR);
	CHECK(sigsuspend_alarm_caught == 1);
	CHECK(sigprocmask(SIG_SETMASK, NULL, &after) == 0);
	CHECK(memcmp(&before, &after, sizeof before) == 0);
	alarm(0);
	CHECK(sigaction(SIGALRM, &old, NULL) == 0);
}

/* ================================================================== *
 * abort.html
 * ================================================================== */

/* abort.html DESCRIPTION: "The abort() function shall override blocking
 * or ignoring [SIGABRT]." test/misc.c's --abort-child already covers
 * the SIG_IGN half; this covers SIG_BLOCK, and separately a caught
 * SIGABRT whose handler returns normally (DESCRIPTION: abnormal
 * termination happens "unless ... the signal handler does not return" --
 * i.e. if it *does* return, termination proceeds anyway). */
static void abort_handler_returns(int s) { (void)s; /* returns normally */ }

static void test_abort_overrides(const char *self)
{
	char *argv[3];
	pid_t pid;
	int status;

	argv[0] = (char *)self; argv[1] = (char *)"--abort-blocked"; argv[2] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid < 0) { printf("note: cannot spawn \"%s\" (errno %d); abort()-override tests skipped\n", self, errno); return; }
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
	CHECK(WCOREDUMP(status));

	argv[1] = (char *)"--abort-caught";
	pid = __spawn(self, argv, environ);
	CHECK(pid > 0);
	if (pid > 0) {
		CHECK(waitpid(pid, &status, 0) == pid);
		CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
	}
}

/* ---- stdio buffers and a terminating signal -----------------------
 *
 * BOTH DIRECTIONS ARE ASSERTED ON PURPOSE.  The rule is an asymmetry
 * and only half of it is a prohibition, so a test that checked one side
 * would stay green through a change that broke the other:
 *
 *   any default-terminate signal   MUST NOT flush   (XSH 2.4.3 ->
 *       _exit(): "Open streams shall not be flushed")
 *   SIGABRT                        MAY flush        (abort.html: "may
 *       include an attempt to effect fclose() on all open streams")
 *
 * The SIGABRT half pins a *permitted choice* this library makes, not a
 * requirement -- an implementation that dropped the buffers on abort()
 * would conform too.  It is pinned so the choice stays visible and a
 * change to it has to be deliberate; src/signal/signal.c records why it
 * is made.  The SIGTERM half is a real conformance assertion.
 *
 * THE MEASUREMENT IS CHECKED BEFORE IT IS TRUSTED.  Both assertions
 * reduce to "how many bytes of the child's buffer reached the file",
 * and a zero can mean two entirely different things: the flush did not
 * happen (what is being tested), or the file never carried anything
 * from the child in the first place (a fact about the build, not about
 * flushing).  That is not hypothetical -- under the native ASan build
 * fuzz/ntstubs.c supplies an in-memory volume rooted at C:\work, and it
 * is PER PROCESS, so nothing a spawned child writes is visible to the
 * parent no matter what happened to the buffer.  On that build the
 * SIGTERM half would pass vacuously and the SIGABRT half would fail
 * spuriously, and only the second of those is loud.
 *
 * So flush_probe_channel_works() runs first: a child that writes the
 * same bytes and flushes them EXPLICITLY, before exiting normally.  If
 * the parent cannot read those back, the apparatus cannot measure
 * anything here and both halves are skipped with a note.  The skip is
 * therefore derived from a measurement rather than from a build-type
 * #ifdef, which also means it disappears by itself if ntstubs ever
 * grows a volume that survives a spawn.
 *
 * The child writes into a FILE on disk rather than a pipe, so the
 * evidence outlives it: the parent reads the file afterwards and the
 * byte count is the whole measurement.  Buffered, never explicitly
 * flushed, and well under BUFSIZ, so nothing can reach the file except
 * through a flush somebody performed. */
#define FLUSHPROBE_TEXT "buffered-and-never-explicitly-flushed"

static int flush_probe_child(int sig)
{
	FILE *f = fopen("flushprobe.tmp", "w");
	if (!f) return 71;
	if (setvbuf(f, 0, _IOFBF, 4096) != 0) return 74;
	if (fputs(FLUSHPROBE_TEXT, f) == EOF) return 75;
	if (sig == 0) {
		/* The control: flush on purpose and leave normally, so the
		 * parent is measuring the file channel and nothing else. */
		if (fflush(f) != 0) return 78;
		if (fclose(f) != 0) return 79;
		return 0;
	}
	if (sig == SIGABRT) abort();
	raise(sig);
	return 76;   /* must not be reached: both dispositions terminate */
}

static long flush_probe_bytes(const char *s, const char *mode, int *status)
{
	char *argv[3];
	char buf[128];
	FILE *f;
	pid_t pid;
	size_t n;

	remove("flushprobe.tmp");
	argv[0] = (char *)s; argv[1] = (char *)mode; argv[2] = NULL;
	pid = __spawn(s, argv, environ);
	if (pid < 0) return -1;
	if (waitpid(pid, status, 0) != pid) return -1;

	f = fopen("flushprobe.tmp", "r");
	if (!f) return 0;            /* never created is "nothing was written" */
	n = fread(buf, 1, sizeof buf, f);
	fclose(f);
	remove("flushprobe.tmp");
	return (long)n;
}

/* Can a child's explicitly-flushed file be read back by the parent in
 * this build at all?  See the section comment: without this, a zero
 * byte count is unreadable. */
static int flush_probe_channel_works(const char *s)
{
	int status = 0;
	long n = flush_probe_bytes(s, "--flush-probe-control", &status);

	if (n == (long)strlen(FLUSHPROBE_TEXT) && WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 1;
	printf("note: a child's flushed file does not reach the parent in this build"
	       " (control wrote %ld of %ld byte(s)); stdio-flush-on-signal checks skipped\n",
	       n < 0 ? 0L : n, (long)strlen(FLUSHPROBE_TEXT));
	return 0;
}

static void test_terminating_signal_does_not_flush_stdio(const char *s)
{
	int status = 0;
	long n = flush_probe_bytes(s, "--flush-probe-term", &status);

	if (n < 0) { CHECK(0 && "spawn/waitpid failed for --flush-probe-term"); return; }
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
	/* The clause. Not "n is small" -- exactly nothing. */
	if (n != 0) printf("    note: %ld byte(s) reached the file\n", n);
	CHECK(n == 0);
}

static void test_abort_flushes_stdio(const char *s)
{
	int status = 0;
	long n = flush_probe_bytes(s, "--flush-probe-abort", &status);

	if (n < 0) { CHECK(0 && "spawn/waitpid failed for --flush-probe-abort"); return; }
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
	/* Positive direction: the permitted flush actually happened, and in
	 * full -- a partial write would mean something other than
	 * __stdio_exit() produced it. */
	if (n != (long)strlen(FLUSHPROBE_TEXT))
		printf("    note: %ld byte(s) reached the file, wanted %ld\n",
		       n, (long)strlen(FLUSHPROBE_TEXT));
	CHECK(n == (long)strlen(FLUSHPROBE_TEXT));
}

/* ================================================================== *
 * psiginfo.html
 * ================================================================== */

static void test_psiginfo(void)
{
	siginfo_t si;

	memset(&si, 0, sizeof si);
	si.si_signo = SIGSEGV;
	si.si_code = SI_USER;

	/* Must exist, be callable with a real siginfo_t, and not crash;
	 * stderr content is not capturable here without extra plumbing, so
	 * only the "does not crash / returns void" half of the contract is
	 * checked directly -- same limitation test_strsignal() already
	 * notes for strsignal()'s unspecified-string cases. */
	psiginfo(&si, "test message");   /* "message: <strsignal text>\n" */
	psiginfo(&si, NULL);             /* just "<strsignal text>\n" */
}

/* ================================================================== *
 * sigaction.html: SA_SIGINFO / sa_sigaction / siginfo_t
 * ================================================================== */

static volatile int sainfo_signo, sainfo_code, sainfo_pid_ok;
static void sainfo_handler(int sig, siginfo_t *si, void *uctx)
{
	(void)uctx;
	sainfo_signo = sig;
	sainfo_code = si->si_code;
	sainfo_pid_ok = (si->si_pid == getpid());
}

static void test_sa_siginfo_raise(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = sainfo_handler;
	sa.sa_flags = SA_SIGINFO;
	CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);

	sainfo_signo = 0;
	CHECK(raise(SIGUSR1) == 0);
	CHECK(sainfo_signo == SIGUSR1);   /* three-arg form actually called */
	CHECK(sainfo_code == SI_USER);    /* signal.h.html: SI_USER "signal sent by kill()" -- raise() is defined in terms of it */
	CHECK(sainfo_pid_ok);             /* si_pid == the sender, here the caller itself */

	signal(SIGUSR1, SIG_DFL);
}

/* signal.h.html siginfo_t DESCRIPTION: for a hardware-fault signal
 * (SIGSEGV/SIGBUS/SIGILL/SIGFPE), si_addr "Address of faulting
 * instruction/memory reference" must be set. exception_handler()
 * (src/signal/signal.c) already has this value on hand --
 * ep->ExceptionRecord->ExceptionInformation[1] for an access
 * violation -- but has nowhere to put it while sa_sigaction is never
 * read at all (same root cause as above). Provoked in a child so a
 * real crash cannot take the suite down with it (see the SIGSEGV/
 * SIGILL/SIGFPE tests below, which use the same __spawn()+waitpid()
 * shape for the same reason). */
static volatile void *sainfo_fault_addr;
static void sainfo_fault_handler(int sig, siginfo_t *si, void *uctx)
{
	(void)uctx;
	sainfo_signo = sig;
	sainfo_fault_addr = si->si_addr;
	_Exit(sainfo_fault_addr != NULL ? 44 : 45);
}

static void test_sa_siginfo_fault_child(const char *self)
{
	char *argv[3];
	pid_t pid;
	int status;

	argv[0] = (char *)self; argv[1] = (char *)"--fault-segv-siginfo"; argv[2] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid < 0) { printf("note: cannot spawn \"%s\"; SA_SIGINFO si_addr child test skipped\n", self); return; }
	CHECK(waitpid(pid, &status, 0) == pid);
#ifdef NATIVE_NO_FAULT_BRIDGE
	/* Same root cause as test_fault_sigsegv() below: there is no real
	 * NT-exception bridge under a native ASan build, so the child (see
	 * "--fault-segv-siginfo" in main()) does not attempt the fault at
	 * all rather than take an uncontrolled wild SEGV. */
	printf("note: native ASan build cannot provoke or forward a real SIGSEGV; SA_SIGINFO si_addr check skipped\n");
#else
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 44);   /* si_addr was non-NULL */
#endif
}

/* ================================================================== *
 * Hardware-fault signals: SIGSEGV / SIGFPE / SIGILL / SIGBUS, via the
 * vectored exception handler (src/signal/signal.c: exception_handler(),
 * installed by __signal_init() with RtlAddVectoredExceptionHandler()).
 * This handler and its EXCEPTION_* -> signal mapping DO exist and ARE
 * wired up -- the ledger's earlier "deliberately not provoked on
 * purpose" note undersold this: the gap was only that nobody had
 * actually provoked one to check. Done here in spawned children
 * (__spawn()+waitpid(), same shape test/posix-alloc.c uses for
 * abort()/assert() deaths) so an uncaught fault cannot take the whole
 * suite down with it.
 * ================================================================== */

/* sigaction.html DESCRIPTION (default disposition table) / signal.h.html
 * basedefs: SIGSEGV/SIGILL/SIGFPE's default action is to terminate the
 * process; sys_wait.h.html: WIFSIGNALED/WTERMSIG must report exactly
 * that signal.  A null-pointer write is a portable, reliable way to
 * provoke EXCEPTION_ACCESS_VIOLATION on both arches this library
 * targets. */
static void test_fault_sigsegv(const char *self)
{
	char *argv[3];
	pid_t pid;
	int status;

	argv[0] = (char *)self; argv[1] = (char *)"--fault-segv"; argv[2] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid < 0) { printf("note: cannot spawn \"%s\"; SIGSEGV fault child test skipped\n", self); return; }
	CHECK(waitpid(pid, &status, 0) == pid);
#ifdef NATIVE_NO_FAULT_BRIDGE
	/* UBSan's own null-pointer-store check reports "*p = 1" as UB and
	 * aborts (a real SIGABRT-shaped death) before the CPU's own page
	 * fault would ever happen, so this child never reaches a genuine
	 * SIGSEGV to test the vectored exception handler against. Bridging
	 * one in even for the cases that would reach real hardware -- some
	 * other test's wild pointer, not this deliberately-provoked one --
	 * would need this file's own global sigaction(SIGSEGV, ...); since
	 * exception_handler() (src/signal/signal.c) always ends the process
	 * one way or another for a SIGSEGV it sees, that would just as
	 * surely swallow a *genuine* ASan-caught memory bug's real SIGSEGV
	 * and turn it into a plain signal-death exit instead of ASan's own
	 * diagnostic report -- the opposite of this build's whole point.
	 * Not attempted; only the spawn/wait mechanics above are exercised
	 * here. This is exercised for real by "make check" under Wine and
	 * CI's windows-test job, where no sanitizer stands in the way. */
	printf("note: native ASan build cannot provoke or forward a real SIGSEGV; signal-identity checks skipped\n");
#else
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
	CHECK(WCOREDUMP(status));   /* src/process/wait.c sig_status(): SIGSEGV is core-dumping */
#endif
}

/* EXCEPTION_ILLEGAL_INSTRUCTION -> SIGILL, via an actual illegal
 * opcode (ud2 on x86/x86_64), not a library-internal shortcut. */
static void test_fault_sigill(const char *self)
{
	char *argv[3];
	pid_t pid;
	int status;

	argv[0] = (char *)self; argv[1] = (char *)"--fault-ill"; argv[2] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid < 0) { printf("note: cannot spawn \"%s\"; SIGILL fault child test skipped\n", self); return; }
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGILL);
	CHECK(WCOREDUMP(status));
}

/* EXCEPTION_INT_DIVIDE_BY_ZERO -> SIGFPE, via a real integer divide
 * (volatile operands so tcc cannot fold it to a compile-time trap or
 * elide it). */
static void test_fault_sigfpe(const char *self)
{
#if defined(__aarch64__)
	/* AArch64 SDIV defines a zero-divisor result as zero; it does not trap,
	 * so there is no EXCEPTION_INT_DIVIDE_BY_ZERO to translate here. */
	(void)self;
	puts("note: AArch64 integer division by zero does not trap; SIGFPE fault check skipped");
#else
	char *argv[3];
	pid_t pid;
	int status;

	argv[0] = (char *)self; argv[1] = (char *)"--fault-fpe"; argv[2] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid < 0) { printf("note: cannot spawn \"%s\"; SIGFPE fault child test skipped\n", self); return; }
	CHECK(waitpid(pid, &status, 0) == pid);
#ifdef NATIVE_NO_FAULT_BRIDGE
	/* Same root cause as test_fault_sigsegv() above: UBSan's own
	 * integer-divide-by-zero check intercepts "a / b" before it ever
	 * traps for real. */
	printf("note: native ASan build cannot provoke or forward a real SIGFPE; signal-identity checks skipped\n");
#else
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGFPE);
	CHECK(WCOREDUMP(status));
#endif
#endif
}

/* sigaction.html DESCRIPTION applies to hardware-generated signals same
 * as self-generated ones: a caught SIGFPE must actually run the
 * installed handler (not silently keep the default terminate action),
 * and "If a signal-catching function returns... normal program
 * execution shall resume" -- here made observable by having the
 * handler itself end the process cleanly, so "the handler ran, with
 * the right signal number, and execution continued long enough to
 * reach _Exit()" is exactly what a distinctive clean exit code proves,
 * without needing to resume the faulting instruction (which
 * EXCEPTION_CONTINUE_EXECUTION really would do for INT_DIVIDE_BY_ZERO,
 * looping forever on the same trap -- not what this clause is about). */
static volatile int fpe_caught_sig;
static void fpe_caught_handler(int s) { fpe_caught_sig = s; _Exit(66); }

/* Exits with si_code as the process's own exit status, so the parent
 * can read the fault subcode straight back out of waitpid()'s status --
 * see the si_code test block below. Every code these tests provoke
 * (SEGV_MAPERR/SEGV_ACCERR/FPE_INTDIV/ILL_ILLOPC) is a small positive
 * int, well inside the 0..255 an exit status can carry. */
static void code_exit_handler(int sig, siginfo_t *si, void *uctx)
{
	(void)sig; (void)uctx;
	_Exit(si->si_code);
}

static void test_fault_sigfpe_caught(const char *self)
{
#if defined(__aarch64__)
	(void)self;
#else
	char *argv[3];
	pid_t pid;
	int status;

	argv[0] = (char *)self; argv[1] = (char *)"--fault-fpe-caught"; argv[2] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid < 0) { printf("note: cannot spawn \"%s\"; caught-SIGFPE fault child test skipped\n", self); return; }
	CHECK(waitpid(pid, &status, 0) == pid);
#ifdef NATIVE_NO_FAULT_BRIDGE
	/* Same root cause again, plus: even setting UBSan's divide check
	 * aside, catching this needs exception_handler() to actually run,
	 * which needs a real fault forwarded to it in the first place --
	 * the same bridge test_fault_sigsegv() explains not building. */
	printf("note: native ASan build cannot provoke or forward a real SIGFPE; caught-signal check skipped\n");
#else
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 66);   /* handler ran and chose to exit cleanly */
#endif
#endif
}

/* ================================================================== *
 * si_code for the hardware-fault signals (signal.h.html siginfo_t
 * DESCRIPTION: si_code is "sigaction.html-specific ... SEGV_MAPERR,
 * SEGV_ACCERR" and friends for SIGSEGV/SIGBUS/SIGILL/SIGFPE) --
 * src/signal/signal.c's exception_handler()/segv_code() now derive a
 * real one instead of the previous blanket SI_KERNEL. Every case here
 * runs the fault-provoking child with a SA_SIGINFO handler that exits
 * with si_code itself as its exit status (valid codes are all small
 * positive integers, well inside 0..255), so the parent's check is
 * just WEXITSTATUS(status) == the expected macro.
 * ================================================================== */

/* SEGV_MAPERR: EXCEPTION_ACCESS_VIOLATION on an address nothing has
 * ever mapped -- same address test_sa_siginfo_fault_child() already
 * uses and already documents as reliably unmapped on both arches. */
static void test_fault_sigsegv_maperr(const char *self)
{
	char *argv[3];
	pid_t pid;
	int status;

	argv[0] = (char *)self; argv[1] = (char *)"--fault-segv-maperr"; argv[2] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid < 0) { printf("note: cannot spawn \"%s\"; SEGV_MAPERR child test skipped\n", self); return; }
	CHECK(waitpid(pid, &status, 0) == pid);
#ifdef NATIVE_NO_FAULT_BRIDGE
	printf("note: native ASan build cannot provoke or forward a real SIGSEGV; SEGV_MAPERR check skipped\n");
#else
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == SEGV_MAPERR);
#endif
}

/* SEGV_ACCERR: EXCEPTION_ACCESS_VIOLATION on a page that genuinely
 * exists (NtAllocateVirtualMemory(MEM_COMMIT)) but whose protection was
 * then set to PAGE_NOACCESS -- src/signal/signal.c's segv_code() must
 * read this back as MEM_COMMIT and answer SEGV_ACCERR, not SEGV_MAPERR. */
static void test_fault_sigsegv_accerr(const char *self)
{
	char *argv[3];
	pid_t pid;
	int status;

	argv[0] = (char *)self; argv[1] = (char *)"--fault-segv-accerr"; argv[2] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid < 0) { printf("note: cannot spawn \"%s\"; SEGV_ACCERR child test skipped\n", self); return; }
	CHECK(waitpid(pid, &status, 0) == pid);
#ifdef NATIVE_NO_FAULT_BRIDGE
	printf("note: native ASan build cannot provoke or forward a real SIGSEGV; SEGV_ACCERR check skipped\n");
#else
	/* exit code 93 would mean the child's own NtAllocateVirtualMemory/
	 * NtProtectVirtualMemory setup failed, not that segv_code() got the
	 * wrong answer -- the WEXITSTATUS(status) == SEGV_ACCERR check below
	 * already fails in either case, since SEGV_ACCERR (2) != 93. */
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == SEGV_ACCERR);
#endif
}

/* FPE_INTDIV: EXCEPTION_INT_DIVIDE_BY_ZERO, same fault test_fault_sigfpe()
 * already provokes, checked for si_code this time instead of just the
 * signal identity. */
static void test_fault_sigfpe_code(const char *self)
{
#if defined(__aarch64__)
	(void)self;
#else
	char *argv[3];
	pid_t pid;
	int status;

	argv[0] = (char *)self; argv[1] = (char *)"--fault-fpe-code"; argv[2] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid < 0) { printf("note: cannot spawn \"%s\"; FPE_INTDIV child test skipped\n", self); return; }
	CHECK(waitpid(pid, &status, 0) == pid);
#ifdef NATIVE_NO_FAULT_BRIDGE
	printf("note: native ASan build cannot provoke or forward a real SIGFPE; FPE_INTDIV check skipped\n");
#else
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == FPE_INTDIV);
#endif
#endif
}

/* ILL_ILLOPC: EXCEPTION_ILLEGAL_INSTRUCTION, same ud2
 * test_fault_sigill() already provokes. Unlike that test, this one
 * needs src/signal/signal.c's own exception_handler() to actually run
 * (it is what computes si_code) -- under NATIVE_NO_FAULT_BRIDGE the
 * child's ud2 still traps for real (nothing dangerous about that, same
 * as test_fault_sigill()), but the *host* kernel delivers the SIGILL
 * directly and simply kills the process, since fuzz/ntstubs.c's
 * RtlAddVectoredExceptionHandler() never forwards anything to
 * exception_handler() (this file's top-of-file comment); si_code is
 * therefore never computed at all, so only the WIFSIGNALED/WTERMSIG
 * shape -- not si_code -- can be checked in that build. */
static void test_fault_sigill_code(const char *self)
{
	char *argv[3];
	pid_t pid;
	int status;

	argv[0] = (char *)self; argv[1] = (char *)"--fault-ill-code"; argv[2] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid < 0) { printf("note: cannot spawn \"%s\"; ILL_ILLOPC child test skipped\n", self); return; }
	CHECK(waitpid(pid, &status, 0) == pid);
#ifdef NATIVE_NO_FAULT_BRIDGE
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGILL);
	printf("note: native ASan build cannot provoke or forward a real SIGILL through exception_handler(); ILL_ILLOPC check skipped\n");
#else
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == ILL_ILLOPC);
#endif
}

#if SPICULE_TEST(NA, posix_signal_fault_sigbus) /* N/A: signal.h.html basedefs / sigaction.html default-disposition
 * table: SIGBUS's default action is to terminate the process, mapped
 * here from EXCEPTION_DATATYPE_MISALIGNMENT (src/signal/signal.c:
 * exception_handler() -- the switch case exists and IS wired to
 * SIGBUS). The gap is not in spicule: on x86 and x86_64, an unaligned
 * scalar load/store simply does not fault in user mode by default --
 * the CPU only raises #AC (-> EXCEPTION_DATATYPE_MISALIGNMENT) when
 * EFLAGS.AC is set *and* CPL==3, and no supported CRT/OS in this
 * project's target (Wine/NT, i386 and x86_64) turns that bit on, nor
 * does this library expose any way for a test to turn it on itself
 * (setting AC via popf from ring 3 works, but the resulting fault is a
 * property of the CPU/OS's alignment-check contract, not something a
 * conformant hosted C program can rely on portably -- and the one other
 * candidate, an unaligned SSE `movaps`, faults as #GP0 ->
 * EXCEPTION_ACCESS_VIOLATION -> SIGSEGV on real hardware, not
 * DATATYPE_MISALIGNMENT). So: the mapping this library provides is
 * real and implemented, but nothing a test can portably execute
 * reaches it -- there is no conformant way to provoke this exact
 * fault, which is what N/A here is about, not "spicule doesn't support
 * it".
 *
 * EXPIRY, stated because this fence is conditional on TWO facts and
 * neither was written down: (1) that EFLAGS.AC is never set on this
 * target, and (2) that the target is x86 or x86_64 at all.  The whole
 * argument above is an argument about the x86 alignment-check
 * contract.  On an architecture where unaligned scalar access traps by
 * configuration rather than by an opt-in flag -- AArch64 with SCTLR_EL1.A
 * set is the obvious case -- provoking the fault becomes ordinary
 * portable C, the clause becomes live, and this fence becomes false.
 * spicule is x86_64 and i386 only today (arch/); re-audit this the day a
 * third arch appears rather than assuming it carried over. */
static void test_fault_sigbus(const char *self)
{
	char *argv[3];
	pid_t pid;
	int status;

	argv[0] = (char *)self; argv[1] = (char *)"--fault-bus"; argv[2] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid < 0) { printf("note: cannot spawn \"%s\"; SIGBUS fault child test skipped\n", self); return; }
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGBUS);
	CHECK(WCOREDUMP(status));
}
#endif

/* ================================================================== *
 * strsignal.html / psignal.html
 * ================================================================== */

static void test_strsignal(void)
{
	int i;
	char *m;

	/* strsignal.html DESCRIPTION: "shall map the signal number in
	 * signum to an implementation-defined string and shall return a
	 * pointer to it." Not NULL, for every valid signal number.
	 * (test/string.c already checks the exact __sigmsgs[] text for a
	 * couple of signals; this checks the contract -- non-NULL,
	 * non-empty, distinct-enough to be useful -- across the whole
	 * range, which it does not.) */
	for (i = 1; i < _NSIG; i++) {
		m = strsignal(i);
		CHECK(m != NULL && m[0] != '\0');
	}

	/* RETURN VALUE: "if signum is not a valid signal number, the return
	 * value is unspecified" -- so only that it does not crash is
	 * checkable, not any particular string. */
	m = strsignal(-1);
	(void)m;
	m = strsignal(_NSIG + 1000);
	(void)m;

	/* psignal() (psignal.html, same page as psiginfo()) has no
	 * implementation in spicule at all -- grep across src/ and include/
	 * finds no psignal symbol or prototype. There is nothing to test;
	 * see the ledger fragment. */
}

/* ================================================================== *
 * sys/wait.h: wait()/waitpid() clauses not already in
 * test/waitpid-overflow.c, plus the status macros via the pure
 * __wait_encode_status() mapping.
 * ================================================================== */

/* wait.html: "[WNOHANG] The waitpid() function shall not suspend
 * execution ... if status is not immediately available for one of the
 * child processes specified by pid" -- returns 0, not -1/ECHILD, for a
 * child that exists but has not exited yet. */
static void test_waitpid_wnohang_running(void)
{
	char *argv[3];
	pid_t pid;
	int status;

	argv[0] = self; argv[1] = (char *)"--sleep"; argv[2] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid <= 0) { printf("note: cannot spawn self (errno %d); WNOHANG test skipped\n", errno); return; }

	status = -12345;
	CHECK(waitpid(pid, &status, WNOHANG) == 0);
	CHECK(status == -12345);   /* not touched when nothing was reaped */

	CHECK(kill(pid, SIGKILL) == 0);
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
	CHECK(!WCOREDUMP(status));   /* SIGKILL is not in sig_status()'s core-dump list */
}

/* wait.html ERRORS (waitpid() only): "[EINVAL] The value of the options
 * argument is not valid." */
static void test_waitpid_einval_options(void)
{
	char *argv[4];
	pid_t pid;
	int status;

	argv[0] = self; argv[1] = (char *)"--child"; argv[2] = (char *)"0"; argv[3] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid <= 0) { printf("note: cannot spawn self (errno %d); EINVAL-options test skipped\n", errno); return; }

	errno = 0;
	CHECK(waitpid(pid, &status, 0xdead0000) == -1 && errno == EINVAL);
	waitpid(pid, &status, 0);   /* reap it regardless, so it is not left a zombie */
}

/* sigaction.html, SA_NOCLDWAIT: a child born while it is set on SIGCHLD
 * must never turn into something wait()/waitpid() can find -- OPTS'
 * sigaction/21-1.c asserts exactly this (fork, exit immediately, parent's
 * wait() must answer [ECHILD]) and was BUG until src/process/children.c's
 * __child_add() started consulting __sigchld_nocldwait().  Restores the
 * default disposition afterward: every other test in this file that
 * spawns and reaps a child runs after this one in main()'s list, and an
 * SA_NOCLDWAIT left set would make every one of them untracked too. */
static void test_sa_nocldwait(void)
{
	struct sigaction sa, old;
	char *argv[4];
	pid_t pid;
	int status;

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = SIG_DFL;
	sa.sa_flags = SA_NOCLDWAIT;
	CHECK(sigaction(SIGCHLD, &sa, &old) == 0);

	argv[0] = self; argv[1] = (char *)"--child"; argv[2] = (char *)"0"; argv[3] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid <= 0) {
		printf("note: cannot spawn self (errno %d); SA_NOCLDWAIT test skipped\n", errno);
		sigaction(SIGCHLD, &old, NULL);
		return;
	}

	/* Give the child a moment to actually run and exit, so a wrong
	 * implementation that merely raced the reap (rather than never
	 * tracking the child at all) is not let off by a lucky timing. */
	{
		struct timeval tv = { 0, 50000 };
		select(0, NULL, NULL, NULL, &tv);
	}

	errno = 0;
	CHECK(waitpid(pid, &status, 0) == -1 && errno == ECHILD);

	sigaction(SIGCHLD, &old, NULL);
}

/* __wait_encode_status(): the exit-code -> wait-status mapping.
 * A signal death is encoded as 0xE0DE00xx (__ENCODE_SIGNAL_EXIT in
 * src/internal/libc.h), chosen precisely so it cannot collide with any
 * of the 256 real exit codes -- unlike the shell-style 128+signo
 * scheme, which conflates exit codes 129..192 with a signal death. */
static void test_wait_encode_status(void)
{
	int i, st;

	/* Every exit code 0..255 round-trips as WIFEXITED with that code,
	 * and is never mistaken for WIFSIGNALED (sys_wait.h.html:
	 * WIFEXITED/WEXITSTATUS/WIFSIGNALED are mutually exclusive). */
	for (i = 0; i < 256; i++) {
		st = __wait_encode_status(i);
		CHECK(WIFEXITED(st) && WEXITSTATUS(st) == i);
		CHECK(!WIFSIGNALED(st));
		CHECK(!WIFSTOPPED(st));   /* this implementation never produces a
		                           * stopped status -- no job control --
		                           * so WIFSTOPPED must never fire here */
	}

	/* A signal death: __ENCODE_SIGNAL_EXIT(sig) decodes as WIFSIGNALED with
	 * that exact WTERMSIG, never WIFEXITED. */
	{
		static const int sigs[] = { SIGHUP, SIGINT, SIGTERM, SIGABRT, SIGSEGV, SIGKILL, _NSIG - 1 };
		size_t n = sizeof sigs / sizeof sigs[0], j;
		for (j = 0; j < n; j++) {
			st = __wait_encode_status(ENCODE_SIGNAL_EXIT(sigs[j]));
			CHECK(WIFSIGNALED(st) && WTERMSIG(st) == sigs[j]);
			CHECK(!WIFEXITED(st));
			CHECK(!WIFSTOPPED(st));
		}
	}

	/* WCOREDUMP (not a POSIX.1-2017 base macro -- see ledger fragment --
	 * but spicule implements it): set for the traditional dumping
	 * signals, clear otherwise. Unit-level version of what
	 * test/waitpid-overflow.c already checks end-to-end through real
	 * processes for SIGTERM/SIGABRT. */
	st = __wait_encode_status(ENCODE_SIGNAL_EXIT(SIGABRT));
	CHECK(WCOREDUMP(st));
	st = __wait_encode_status(ENCODE_SIGNAL_EXIT(SIGTERM));
	CHECK(!WCOREDUMP(st));
	st = __wait_encode_status(ENCODE_SIGNAL_EXIT(SIGKILL));
	CHECK(!WCOREDUMP(st));

	/* The collision case: under a 128+signo scheme, exit codes 129..192
	 * would decode as signal deaths. They must not, for any exit code
	 * 0..255. */
	for (i = 129; i <= 192; i++) {
		st = __wait_encode_status(i);
		CHECK(WIFEXITED(st) && !WIFSIGNALED(st) && WEXITSTATUS(st) == i);
	}
}

/* wait3()/wait4(): not a POSIX.1-2017 base function (wait3.html 404s on
 * the standard site; this is a BSD/historical interface). spicule
 * implements it as an extension (declared under _XOPEN_SOURCE ||
 * _GNU_SOURCE || _BSD_SOURCE in include/sys/wait.h), so it gets a
 * sanity pass rather than a clause audit: it reaps like waitpid() and
 * fills a struct rusage without crashing. */
static void test_wait4_sanity(void)
{
	char *argv[4];
	pid_t pid;
	int status;
	struct rusage ru;

	argv[0] = self; argv[1] = (char *)"--child"; argv[2] = (char *)"7"; argv[3] = NULL;
	pid = __spawn(self, argv, environ);
	if (pid <= 0) { printf("note: cannot spawn self (errno %d); wait4() test skipped\n", errno); return; }

	memset(&ru, 0xaa, sizeof ru);
	CHECK(wait4(pid, &status, 0, &ru) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 7);
	/* ru was at least touched (zeroed or filled by
	 * fill_child_rusage()) -- not left as the 0xaa poison pattern. */
	CHECK(memcmp(&ru, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 8) != 0 || sizeof ru <= 8);
}


/* killpg.html: "If pgrp is greater than 1, killpg(pgrp, sig) shall be
 * equivalent to kill(-pgrp, sig)"; a pgrp of 0 addresses "the process
 * group of the sender".  Under this library's group-of-one model
 * (src/unistd/ids.c, and kill()'s own comment in src/signal/signal.c)
 * the caller is the entire content of its own process group, so
 * killpg(0, 0) is a permission/existence check against the caller and
 * must succeed without delivering anything.  RETURN VALUE / ERRORS:
 * "[EINVAL] The value of the sig argument is an invalid or unsupported
 * signal number."
 *
 * killpg() and sigaltstack() both exist in src/signal/signal.c and link,
 * but were named by no assertion anywhere in the test/ tree before this (see
 * test/POSIX-GAP-ACCOUNTING.md's "implemented, but no assertion
 * anywhere" list).  These run on real Windows in CI too; neither
 * depends on Wine-specific behaviour. */
static void test_killpg(void)
{
	/* sig == 0: "error checking is performed but no signal is
	 * actually sent" (kill.html DESCRIPTION). */
	CHECK(killpg(0, 0) == 0);
	errno = 0;
	CHECK(killpg(0, -1) == -1);
	CHECK(errno == EINVAL);
	errno = 0;
	CHECK(killpg(0, NSIG + 100) == -1);
	CHECK(errno == EINVAL);
}

/* sigaltstack.html: "If ss is a null pointer, the current alternate
 * signal stack shall remain unchanged"; oss, when non-null, receives
 * the current state, whose ss_flags "shall contain SS_DISABLE" when no
 * alternate stack is currently established.  spicule establishes none
 * (there is no alternate-stack delivery on this platform, see this
 * file's banner), so SS_DISABLE is the permanent, correct answer --
 * asserted as such rather than as an aspiration. */
static void test_sigaltstack_disabled(void)
{
	stack_t oss;

	CHECK(sigaltstack(NULL, NULL) == 0);

	memset(&oss, 0xa5, sizeof oss);
	CHECK(sigaltstack(NULL, &oss) == 0);
	CHECK((oss.ss_flags & SS_DISABLE) != 0);
	/* SS_ONSTACK and SS_DISABLE are mutually exclusive states. */
	CHECK((oss.ss_flags & SS_ONSTACK) == 0);

	/* Querying twice must be idempotent -- the first query must not
	 * have established anything. */
	memset(&oss, 0, sizeof oss);
	CHECK(sigaltstack(NULL, &oss) == 0);
	CHECK((oss.ss_flags & SS_DISABLE) != 0);
}

/* sigset.html (XSI, obsolescent) and siginterrupt.html (XSI,
 * obsolescent) -- the five <signal.h> names test/POSIX-GAP-ACCOUNTING.md
 * lists as never asserted anywhere in the test/ tree.
 *
 * Pure library bookkeeping over this file's own signal-mask tables, so
 * Wine is a sound oracle for all of it; nothing here touches the
 * filesystem, a process or a handle.
 *
 * sigset.html RETURN VALUE: sighold()/sigrelse() "shall return 0 upon
 * successful completion; otherwise, -1 shall be returned and errno set";
 * sigset() returns "SIG_HOLD if the signal had been blocked and the
 * signal's previous disposition if it had not been blocked", or SIG_ERR
 * on failure; sigpause() "shall suspend execution of the thread until a
 * signal is received, whereupon it shall return -1 and set errno to
 * [EINTR]".  ERRORS [EINVAL]: "The sig argument is an illegal signal
 * number", for all of them.
 * sigpause() is tested with a signal already pending under the current
 * mask.  Its temporary mask makes that signal eligible atomically, so the
 * test exercises a real delivery and wakeup without a timing race. */
static void hold_handler(int sig) { (void)sig; }

static void test_sighold_sigrelse(void)
{
	sigset_t cur;
	int i, held;

	/* start from a known state */
	sigemptyset(&cur);
	CHECK(sigprocmask(SIG_SETMASK, &cur, NULL) == 0);

	CHECK(sighold(SIGUSR1) == 0);
	CHECK(sigprocmask(SIG_BLOCK, NULL, &cur) == 0);
	CHECK(sigismember(&cur, SIGUSR1) == 1);
	/* only that one signal, not the whole mask */
	CHECK(sigismember(&cur, SIGUSR2) == 0);

	/* idempotent: holding an already-held signal still succeeds */
	CHECK(sighold(SIGUSR1) == 0);

	CHECK(sigrelse(SIGUSR1) == 0);
	CHECK(sigprocmask(SIG_BLOCK, NULL, &cur) == 0);
	CHECK(sigismember(&cur, SIGUSR1) == 0);
	/* releasing an already-released signal still succeeds */
	CHECK(sigrelse(SIGUSR1) == 0);

	/* sigset.html ERRORS lists as shall-fail: "[EINVAL] The sig argument
	 * is an illegal signal number."  Both wrappers build a one-signal
	 * sigset_t and hand it to sigprocmask(), so the only place the bad
	 * argument is ever seen is sigaddset()'s own sig_valid() check --
	 * an empty set is a perfectly legal sigprocmask() argument, so a
	 * dropped sigaddset() failure turns into a silent success rather
	 * than an error.  Both signs of "illegal" are probed: below the
	 * bottom of the range and at NSIG, one past the top. */
	errno = 0;
	CHECK(sighold(-1) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(sighold(NSIG) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(sigrelse(-1) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(sigrelse(NSIG) == -1 && errno == EINVAL);

	/* A rejected call must also have changed nothing: the mask the four
	 * calls above left behind is still the empty one this function
	 * started from, and a valid signal is still held and released after
	 * them -- so the [EINVAL] arm cannot be "achieved" by a wrapper that
	 * refuses everything or that blocks first and reports second. */
	CHECK(sigprocmask(SIG_BLOCK, NULL, &cur) == 0);
	for (i = 1, held = 0; i < NSIG; i++)
		if (sigismember(&cur, i) == 1) held++;
	CHECK(held == 0);
	CHECK(sighold(SIGUSR1) == 0);
	CHECK(sigprocmask(SIG_BLOCK, NULL, &cur) == 0);
	CHECK(sigismember(&cur, SIGUSR1) == 1);
	CHECK(sigrelse(SIGUSR1) == 0);
	CHECK(sigprocmask(SIG_BLOCK, NULL, &cur) == 0);
	CHECK(sigismember(&cur, SIGUSR1) == 0);
}

static void test_sigset(void)
{
	void (*prev)(int);
	sigset_t cur;

	sigemptyset(&cur);
	CHECK(sigprocmask(SIG_SETMASK, &cur, NULL) == 0);
	CHECK(signal(SIGUSR1, SIG_DFL) != SIG_ERR);

	/* "the signal's previous disposition if it had not been blocked" */
	prev = sigset(SIGUSR1, hold_handler);
	CHECK(prev == SIG_DFL);
	prev = sigset(SIGUSR1, SIG_IGN);
	CHECK(prev == hold_handler);
	prev = sigset(SIGUSR1, SIG_DFL);
	CHECK(prev == SIG_IGN);

	/* the disposition really is installed: signal() reads it back */
	CHECK(sigset(SIGUSR1, hold_handler) == SIG_DFL);
	CHECK(signal(SIGUSR1, SIG_DFL) == hold_handler);

	/* [EINVAL] "The sig argument is an illegal signal number", and
	 * "an attempt is made to catch a signal that cannot be caught". */
	errno = 0;
	CHECK(sigset(-1, hold_handler) == SIG_ERR && errno == EINVAL);
	errno = 0;
	CHECK(sigset(NSIG, hold_handler) == SIG_ERR && errno == EINVAL);
	errno = 0;
	CHECK(sigset(SIGKILL, hold_handler) == SIG_ERR && errno == EINVAL);
	errno = 0;
	CHECK(sigset(SIGSTOP, hold_handler) == SIG_ERR && errno == EINVAL);

	/* RETURN VALUE: "Upon successful completion, sigset() shall return
	 * SIG_HOLD if the signal had been blocked and the signal's previous
	 * disposition if it had not been blocked."  The two halves have to
	 * be checked together: the SIG_HOLD return is how a caller learns
	 * that the call also "remove[d] sig from the calling process' signal
	 * mask", so a run that only looked at the return value could not
	 * tell that answer apart from a stale one. */
	CHECK(sighold(SIGUSR1) == 0);
	CHECK(sigset(SIGUSR1, hold_handler) == SIG_HOLD);
	CHECK(sigprocmask(SIG_BLOCK, NULL, &cur) == 0);
	CHECK(sigismember(&cur, SIGUSR1) == 0);	/* "shall remove sig from ... mask" */
	/* and the disposition the SIG_HOLD return replaced the name of was
	 * still installed -- SIG_HOLD is a report about the mask, not a
	 * licence to drop the handler on the floor */
	CHECK(signal(SIGUSR1, SIG_DFL) == hold_handler);

	/* DESCRIPTION: "If func is SIG_HOLD, sig shall be added to the
	 * calling process' signal mask and its disposition shall remain
	 * unchanged."  The same return rule applies, so the first call --
	 * on an unblocked signal -- reports the disposition it left alone,
	 * and the second, now that sig is held, reports SIG_HOLD. */
	CHECK(sigset(SIGUSR1, hold_handler) == SIG_DFL);
	CHECK(sigset(SIGUSR1, SIG_HOLD) == hold_handler);
	CHECK(sigprocmask(SIG_BLOCK, NULL, &cur) == 0);
	CHECK(sigismember(&cur, SIGUSR1) == 1);
	CHECK(sigset(SIGUSR1, SIG_HOLD) == SIG_HOLD);
	CHECK(signal(SIGUSR1, SIG_DFL) == hold_handler);	/* disposition unchanged */

	/* unblocked signal, unblocked afterwards: the mask is not the only
	 * thing sigset() may not disturb -- a plain disposition change on a
	 * signal that was never held must still leave it unheld */
	CHECK(sigrelse(SIGUSR1) == 0);
	CHECK(sigset(SIGUSR1, hold_handler) == SIG_DFL);
	CHECK(sigprocmask(SIG_BLOCK, NULL, &cur) == 0);
	CHECK(sigismember(&cur, SIGUSR1) == 0);

	CHECK(signal(SIGUSR1, SIG_DFL) != SIG_ERR);
}

static void test_sigignore(void)
{
	struct sigaction act;
	sigset_t before, after;

	/* sigignore.html: install SIG_IGN and leave the signal mask alone. */
	sigemptyset(&before);
	sigaddset(&before, SIGUSR1);
	CHECK(sigprocmask(SIG_BLOCK, &before, 0) == 0);
	CHECK(sigignore(SIGUSR1) == 0);
	CHECK(sigaction(SIGUSR1, 0, &act) == 0);
	CHECK(act.sa_handler == SIG_IGN);
	CHECK(sigprocmask(SIG_SETMASK, 0, &after) == 0);
	CHECK(sigismember(&after, SIGUSR1) == 1);
	CHECK(sigprocmask(SIG_UNBLOCK, &before, 0) == 0);

	errno = 0;
	CHECK(sigignore(-1) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(sigignore(SIGKILL) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(sigignore(SIGSTOP) == -1 && errno == EINVAL);
}

static void test_sigpause(void)
{
	sigset_t one;

	/* Hold a real pending signal, then let sigpause() temporarily unblock
	 * it.  The call must deliver that signal and report EINTR. */
	CHECK(signal(SIGUSR1, hold_handler) != SIG_ERR);
	CHECK(sigemptyset(&one) == 0);
	CHECK(sigaddset(&one, SIGUSR1) == 0);
	CHECK(sigprocmask(SIG_BLOCK, &one, NULL) == 0);
	CHECK(raise(SIGUSR1) == 0);
	errno = 0;
	CHECK(sigpause(SIGUSR1) == -1 && errno == EINTR);
	CHECK(sigprocmask(SIG_UNBLOCK, &one, NULL) == 0);
	CHECK(signal(SIGUSR1, SIG_DFL) != SIG_ERR);
}

static void test_siginterrupt(void)
{
	/* siginterrupt.html RETURN VALUE: "Upon successful completion,
	 * siginterrupt() shall return 0".  Both flag values are accepted
	 * for a valid signal. */
	CHECK(siginterrupt(SIGUSR1, 0) == 0);
	CHECK(siginterrupt(SIGUSR1, 1) == 0);
	CHECK(siginterrupt(SIGINT, 1) == 0);

	/* The effect siginterrupt() names -- clearing/setting SA_RESTART --
	 * is N/A here and this file's header already says why: spicule never
	 * suspends a thread mid-call waiting on a signal, so there is no
	 * restart-vs-EINTR decision for the flag to steer.  What is *not*
	 * N/A is the argument check below. */

	/* siginterrupt.html ERRORS lists as shall-fail: "[EINVAL] The sig
	 * argument is not a valid signal number."  That the flag itself is
	 * a documented no-op here does not excuse the argument check: this
	 * is a shall-fail clause about the argument, not about the effect,
	 * so sig goes through src/signal/signal.c's own sig_valid() -- the
	 * one signal(), sigaction(), sighold() and sigrelse() all use.
	 * Both signs of "not valid" are probed, and 0 with them: it is the
	 * one number a plain range check written as `sig < NSIG` would let
	 * through, and kill()'s sig==0 convention gives it a meaning
	 * elsewhere in this header that it does not have here. */
	errno = 0;
	CHECK(siginterrupt(-1, 1) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(siginterrupt(NSIG, 1) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(siginterrupt(0, 1) == -1 && errno == EINVAL);

	/* And the rejection is of the argument, not of everything: a valid
	 * signal still succeeds afterwards, with both flag values, so the
	 * [EINVAL] arm cannot be "achieved" by a stub that fails always.
	 * SIGKILL and SIGSTOP are valid signal numbers and this page lists
	 * no uncatchable-signal error, so -- unlike signal()/sigaction() --
	 * they must be accepted rather than rejected. */
	CHECK(siginterrupt(SIGUSR1, 1) == 0);
	CHECK(siginterrupt(SIGUSR1, 0) == 0);
	CHECK(siginterrupt(SIGKILL, 1) == 0);
	CHECK(siginterrupt(SIGSTOP, 0) == 0);
	CHECK(siginterrupt(NSIG - 1, 1) == 0);
}

/* ==================================================================
 * <signal.h> header content -- the si_code constant table.  Audit
 * group U (XBD header contents); see
 * test/POSIX-COVERAGE.md "XBD header contents (group U)".
 * ================================================================== */

/* signal.h.html DESCRIPTION, immediately after the siginfo_t member
 * list: "[CX] The <signal.h> header shall define the symbolic constants
 * in the Code column of the following table for use as values of
 * si_code".  CX marks an extension to ISO C that POSIX requires, not an
 * option group, so all 40 Code entries are mandatory.  What is asserted
 * is the property a handler depends on -- the codes for one signal are
 * distinct from each other, since si_code is compared for equality --
 * and NOT that spicule ever delivers any particular one: <signal.h>
 * records per code which NT exception status produces it and which
 * nothing does -- six of the eight ILL_* and two of the three BUS_* name
 * conditions NT never reports, and exist so a portable handler can name
 * them, a default branch included. */
static void test_signal_si_code_constants(void)
{
	static const int ill[] = {
		ILL_ILLOPC, ILL_ILLOPN, ILL_ILLADR, ILL_ILLTRP,
		ILL_PRVOPC, ILL_PRVREG, ILL_COPROC, ILL_BADSTK
	};
	static const int fpe[] = {
		FPE_INTDIV, FPE_INTOVF, FPE_FLTDIV, FPE_FLTOVF,
		FPE_FLTUND, FPE_FLTRES, FPE_FLTINV, FPE_FLTSUB
	};
	static const int bus[] = { BUS_ADRALN, BUS_ADRERR, BUS_OBJERR };
	size_t i, j;

	for (i = 0; i < sizeof ill / sizeof ill[0]; i++)
		for (j = i + 1; j < sizeof ill / sizeof ill[0]; j++)
			CHECK(ill[i] != ill[j]);
	for (i = 0; i < sizeof fpe / sizeof fpe[0]; i++)
		for (j = i + 1; j < sizeof fpe / sizeof fpe[0]; j++)
			CHECK(fpe[i] != fpe[j]);
	for (i = 0; i < sizeof bus / sizeof bus[0]; i++)
		for (j = i + 1; j < sizeof bus / sizeof bus[0]; j++)
			CHECK(bus[i] != bus[j]);

	/* A si_code value is assigned into siginfo_t's int si_code, so
	 * each must fit there -- the property that makes the table
	 * usable at all. */
	{
		siginfo_t si;
		si.si_code = ILL_BADSTK;
		CHECK(si.si_code == ILL_BADSTK);
		si.si_code = FPE_FLTSUB;
		CHECK(si.si_code == FPE_FLTSUB);
		si.si_code = BUS_OBJERR;
		CHECK(si.si_code == BUS_OBJERR);
	}
}

int main(int argc, char **argv)
{
	self = argv[0];

	if (argc > 1 && !strcmp(argv[1], "--sleep")) { sleep(30); return 0; }
	if (argc == 3 && !strcmp(argv[1], "--child")) return atoi(argv[2]) & 0xff;
	if (argc > 1 && !strcmp(argv[1], "--flush-probe-control")) return flush_probe_child(0);
	if (argc > 1 && !strcmp(argv[1], "--flush-probe-term")) return flush_probe_child(SIGTERM);
	if (argc > 1 && !strcmp(argv[1], "--flush-probe-abort")) return flush_probe_child(SIGABRT);
	if (argc > 1 && !strcmp(argv[1], "--abort-blocked")) {
		sigset_t s;
		sigemptyset(&s);
		sigaddset(&s, SIGABRT);
		sigprocmask(SIG_BLOCK, &s, NULL);
		abort();
	}
	if (argc > 1 && !strcmp(argv[1], "--abort-caught")) {
		signal(SIGABRT, abort_handler_returns);
		abort();
		_Exit(42);   /* must not be reached: abort() never returns */
	}
	if (argc > 1 && !strcmp(argv[1], "--fault-segv")) {
		int *p = NULL;
		*p = 1;
		_Exit(90);   /* must not be reached */
	}
	if (argc > 1 && !strcmp(argv[1], "--fault-segv-siginfo")) {
#ifdef NATIVE_NO_FAULT_BRIDGE
		/* Unlike --fault-segv's literal NULL write, this address is
		 * only known bad at run time, not a compile-time-recognized
		 * null pointer -- so UBSan's null-pointer-store check (which
		 * intercepts *p=1 for a literal NULL before the real page
		 * fault, see test_fault_sigsegv()) does not catch it, and the
		 * write would reach real hardware and take an uncontrolled
		 * SEGV that ASan's signal handler aborts the whole child on.
		 * There is no NT-exception bridge in this build to test
		 * against anyway (top of file), so skip the write entirely. */
		_Exit(45);
#else
		struct sigaction sa;
		/* A nonzero bad address, unlike --fault-segv's NULL write --
		 * si_addr would be legitimately NULL for a null-pointer fault,
		 * which would make "si_addr != NULL" pass for the wrong
		 * reason. This address is chosen small and unmapped on both
		 * arches this library targets, never reachable from a normal
		 * allocation. */
		int *p = (int *)(size_t)8;

		memset(&sa, 0, sizeof sa);
		sa.sa_sigaction = sainfo_fault_handler;
		sa.sa_flags = SA_SIGINFO;
		sigaction(SIGSEGV, &sa, NULL);
		*p = 1;
		_Exit(90);   /* must not be reached */
#endif
	}
	if (argc > 1 && !strcmp(argv[1], "--fault-ill")) {
#if defined(__i386__) || defined(__x86_64__)
		__asm__ volatile("ud2");
#elif defined(__aarch64__)
		/* Encoding zero is UDF #0, an architecturally undefined instruction. */
		__asm__ volatile(".long 0");
#endif
		_Exit(90);
	}
	if (argc > 1 && !strcmp(argv[1], "--fault-fpe")) {
		volatile int a = 1, b = 0;
		a = a / b;
		_Exit(90);
	}
	if (argc > 1 && !strcmp(argv[1], "--fault-fpe-caught")) {
		volatile int a = 1, b = 0;
		signal(SIGFPE, fpe_caught_handler);
		a = a / b;
		_Exit(91);   /* only reached if the handler did NOT run/exit */
	}
	if (argc > 1 && !strcmp(argv[1], "--fault-segv-maperr")) {
#ifdef NATIVE_NO_FAULT_BRIDGE
		_Exit(45);   /* arbitrary: parent skips the check under this build */
#else
		struct sigaction sa;
		/* Same reliably-unmapped address --fault-segv-siginfo uses above. */
		int *p = (int *)(size_t)8;

		memset(&sa, 0, sizeof sa);
		sa.sa_sigaction = code_exit_handler;
		sa.sa_flags = SA_SIGINFO;
		sigaction(SIGSEGV, &sa, NULL);
		*p = 1;
		_Exit(90);   /* must not be reached */
#endif
	}
	if (argc > 1 && !strcmp(argv[1], "--fault-segv-accerr")) {
#ifdef NATIVE_NO_FAULT_BRIDGE
		_Exit(45);
#else
		struct sigaction sa;
		void *base = NULL;
		SIZE_T size = 4096;
		ULONG oldprot = 0;
		NTSTATUS st;

		memset(&sa, 0, sizeof sa);
		sa.sa_sigaction = code_exit_handler;
		sa.sa_flags = SA_SIGINFO;
		sigaction(SIGSEGV, &sa, NULL);

		/* A real, committed page -- then immediately made PAGE_NOACCESS,
		 * so the write below faults on memory that genuinely exists
		 * (segv_code()'s NtQueryVirtualMemory() must see MEM_COMMIT). */
		st = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!NT_SUCCESS(st) || !base) _Exit(93);   /* setup failed; not what this test checks */
		st = NtProtectVirtualMemory(NtCurrentProcess(), &base, &size, PAGE_NOACCESS, &oldprot);
		if (!NT_SUCCESS(st)) _Exit(93);
		*(volatile int *)base = 1;
		_Exit(90);   /* must not be reached */
#endif
	}
	if (argc > 1 && !strcmp(argv[1], "--fault-fpe-code")) {
#ifdef NATIVE_NO_FAULT_BRIDGE
		_Exit(45);
#else
		volatile int a = 1, b = 0;
		struct sigaction sa;

		memset(&sa, 0, sizeof sa);
		sa.sa_sigaction = code_exit_handler;
		sa.sa_flags = SA_SIGINFO;
		sigaction(SIGFPE, &sa, NULL);
		a = a / b;
		_Exit(91);   /* only reached if the handler did NOT run/exit */
#endif
	}
	if (argc > 1 && !strcmp(argv[1], "--fault-ill-code")) {
		struct sigaction sa;

		memset(&sa, 0, sizeof sa);
		sa.sa_sigaction = code_exit_handler;
		sa.sa_flags = SA_SIGINFO;
		sigaction(SIGILL, &sa, NULL);
#if defined(__i386__) || defined(__x86_64__)
		__asm__ volatile("ud2");
#elif defined(__aarch64__)
		__asm__ volatile(".long 0");
#endif
		_Exit(90);   /* must not be reached */
	}

	test_signal_sigstop();
	test_sig_atomic_t();
	test_raise_einval();
	test_kill();
	test_sigaction_query_and_einval();
	test_sa_resethand();
	test_sigaction_implicit_mask();
	test_sigsetops();
	test_sigorset();
	test_sigrtmax();
	test_sigprocmask();
	test_sigpending();
	test_new_thread_pending_empty();
	test_realtime_signal_queue();
	test_sigsuspend_wait();
	test_abort_overrides(argv[0]);
	if (flush_probe_channel_works(argv[0])) {
		test_terminating_signal_does_not_flush_stdio(argv[0]);
		test_abort_flushes_stdio(argv[0]);
	}
	test_psiginfo();
	test_sa_siginfo_raise();
	test_sa_siginfo_fault_child(argv[0]);
	test_fault_sigsegv(argv[0]);
	test_fault_sigill(argv[0]);
	test_fault_sigfpe(argv[0]);
	test_fault_sigfpe_caught(argv[0]);
	test_fault_sigsegv_maperr(argv[0]);
	test_fault_sigsegv_accerr(argv[0]);
	test_fault_sigfpe_code(argv[0]);
	test_fault_sigill_code(argv[0]);
	test_strsignal();
	test_waitpid_wnohang_running();
	test_waitpid_einval_options();
	test_sa_nocldwait();
	test_wait_encode_status();
	test_wait4_sanity();
	test_killpg();
	test_sigaltstack_disabled();
	test_sighold_sigrelse();
	test_sigset();
	test_sigignore();
	test_sigpause();
	test_siginterrupt();
	test_signal_si_code_constants();

	if (!fails) printf("posix-signal: all tests passed\n");
	return fails != 0;
}
