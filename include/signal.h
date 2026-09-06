/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef _SIGNAL_H
#define _SIGNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <ownership.h>

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)

#ifdef _GNU_SOURCE
#define __ucontext ucontext
#endif

#define __NEED_size_t
#define __NEED_pid_t
#define __NEED_uid_t
#define __NEED_struct_timespec
#define __NEED_pthread_t
#define __NEED_pthread_attr_t
#define __NEED_time_t
#define __NEED_clock_t
#define __NEED_sigset_t

#include <bits/alltypes.h>

#define SIG_BLOCK     0
#define SIG_UNBLOCK   1
#define SIG_SETMASK   2

#define SI_ASYNCNL (-60)
#define SI_TKILL (-6)
#define SI_SIGIO (-5)
#define SI_ASYNCIO (-4)
#define SI_MESGQ (-3)
#define SI_TIMER (-2)
#define SI_QUEUE (-1)
#define SI_USER 0
#define SI_KERNEL 128

/* si_code values for SIGILL/SIGFPE/SIGSEGV/SIGBUS, derived from the NT
 * EXCEPTION_RECORD by src/signal/signal.c's exception_handler(). All
 * POSIX-mandated codes are defined even where NT never produces them
 * (each such macro below says so), since a `switch (si_code)` covering
 * every case must still compile. Numeric values match musl/glibc.
 * SEGV_BNDERR, SEGV_PKUERR, SEGV_MTEAERR, SEGV_MTESERR, BUS_MCEERR_AR
 * and BUS_MCEERR_AO stay out: those are Linux extensions, not POSIX. */
#define ILL_ILLOPC 1   /* EXCEPTION_ILLEGAL_INSTRUCTION */
#define ILL_ILLOPN 2   /* not produced: EXCEPTION_ILLEGAL_INSTRUCTION is
                        * NT's whole vocabulary for an undecodable
                        * instruction -- the EXCEPTION_RECORD carries no
                        * operand or addressing-mode detail to tell
                        * ILL_ILLOPN and ILL_ILLADR from ILL_ILLOPC */
#define ILL_ILLADR 3   /* not produced: as ILL_ILLOPN */
#define ILL_ILLTRP 4   /* not produced: NT has no illegal-trap status;
                        * an int n to an unset IDT gate surfaces as
                        * EXCEPTION_ILLEGAL_INSTRUCTION or a debug
                        * exception, never as a trap-number report */
#define ILL_PRVOPC 5   /* EXCEPTION_PRIV_INSTRUCTION */
#define ILL_PRVREG 6   /* not produced: EXCEPTION_PRIV_INSTRUCTION does
                        * not say whether the privileged thing was the
                        * opcode or a register, so a privileged access
                        * is reported as the opcode case rather than
                        * guessed between the two */
#define ILL_COPROC 7   /* not produced: an x87/SSE coprocessor fault is
                        * an EXCEPTION_FLT_* status on NT, so it arrives
                        * as SIGFPE with an FPE_* code, never as SIGILL */
#define ILL_BADSTK 8   /* not produced: a stack-segment fault is reported
                        * by NT as EXCEPTION_ACCESS_VIOLATION or
                        * EXCEPTION_STACK_OVERFLOW, both SIGSEGV here */

#define FPE_INTDIV 1   /* EXCEPTION_INT_DIVIDE_BY_ZERO */
#define FPE_INTOVF 2   /* EXCEPTION_INT_OVERFLOW */
#define FPE_FLTDIV 3   /* EXCEPTION_FLT_DIVIDE_BY_ZERO */
#define FPE_FLTOVF 4   /* EXCEPTION_FLT_OVERFLOW */
#define FPE_FLTUND 5   /* EXCEPTION_FLT_UNDERFLOW */
#define FPE_FLTRES 6   /* EXCEPTION_FLT_INEXACT_RESULT */
#define FPE_FLTINV 7   /* EXCEPTION_FLT_INVALID_OPERATION */
#define FPE_FLTSUB 8   /* EXCEPTION_ARRAY_BOUNDS_EXCEEDED */

#define SEGV_MAPERR 1  /* EXCEPTION_ACCESS_VIOLATION on unmapped or
                         * reserved-but-uncommitted memory */
#define SEGV_ACCERR 2  /* same exception on a committed page whose protection
                         * denied the access */

#define BUS_ADRALN 1   /* EXCEPTION_DATATYPE_MISALIGNMENT */
#define BUS_ADRERR 2   /* not produced: "nonexistent physical address" is
                        * a bus-level report NT does not make -- the
                        * memory manager turns a mapping it cannot
                        * satisfy into EXCEPTION_ACCESS_VIOLATION, which
                        * is SIGSEGV/SEGV_MAPERR here */
#define BUS_OBJERR 3   /* EXCEPTION_IN_PAGE_ERROR: a mapped object's backing
                        * store could not supply the faulted page */

/* si_code values for SIGCHLD. All six are defined for POSIX conformance
 * though CLD_TRAPPED is never produced: it reports a trace-trap stop,
 * and this library has no ptrace/debugger interface. waitid() produces
 * the other five; CLD_STOPPED/CLD_CONTINUED come from ntlibc's own
 * kill(SIGSTOP/SIGCONT) (NtSuspendProcess/NtResumeProcess), not from an
 * NT notification. Numeric values match musl/glibc. */
#define CLD_EXITED    1
#define CLD_KILLED    2
#define CLD_DUMPED    3
#define CLD_TRAPPED   4
#define CLD_STOPPED   5
#define CLD_CONTINUED 6

typedef struct sigaltstack stack_t;

#define SA_NOCLDSTOP  1
#define SA_NOCLDWAIT  2
#define SA_SIGINFO    4
#define SA_ONSTACK    0x08000000
#define SA_RESTART    0x10000000
#define SA_NODEFER    0x40000000
#define SA_RESETHAND  0x80000000
#define SA_RESTORER   0x04000000

#define MINSIGSTKSZ 2048
#define SIGSTKSZ 8192

#include <bits/sigevent.h>

typedef struct {
	int si_signo, si_errno, si_code;
	union {
		char __pad[128 - 2*sizeof(int) - sizeof(long)];
		struct {
			union {
				struct {
					pid_t si_pid;
					uid_t si_uid;
				} __piduid;
				struct {
					int si_timerid;
					int si_overrun;
				} __timer;
			} __first;
			union {
				union sigval si_value;
				struct {
					int si_status;
					clock_t si_utime, si_stime;
				} __sigchld;
			} __second;
		} __si_common;
		struct {
			void *si_addr;
			short si_addr_lsb;
		} __sigfault;
		struct {
			long si_band;
			int si_fd;
		} __sigpoll;
	} __si_fields;
} siginfo_t;
#define si_pid     __si_fields.__si_common.__first.__piduid.si_pid
#define si_uid     __si_fields.__si_common.__first.__piduid.si_uid
#define si_timerid __si_fields.__si_common.__first.__timer.si_timerid
#define si_overrun __si_fields.__si_common.__first.__timer.si_overrun
#define si_status  __si_fields.__si_common.__second.__sigchld.si_status
#define si_utime   __si_fields.__si_common.__second.__sigchld.si_utime
#define si_stime   __si_fields.__si_common.__second.__sigchld.si_stime
#define si_value   __si_fields.__si_common.__second.si_value
#define si_addr    __si_fields.__sigfault.si_addr
#define si_band    __si_fields.__sigpoll.si_band
#define si_fd      __si_fields.__sigpoll.si_fd

struct sigaction {
	union {
		void (*sa_handler)(int);
		void (*sa_sigaction)(int, siginfo_t *, void *);
	} __sa_handler;
	sigset_t sa_mask;
	int sa_flags;
	void (*sa_restorer)(void);
};
#define sa_handler   __sa_handler.sa_handler
#define sa_sigaction __sa_handler.sa_sigaction

struct sigaltstack {
	void *ss_sp;
	int ss_flags;
	size_t ss_size;
};

int __libc_current_sigrtmin(void);
int __libc_current_sigrtmax(void);

#define SIGRTMIN  (__libc_current_sigrtmin())
#define SIGRTMAX  (__libc_current_sigrtmax())

async_signal_safe
io_operation
int kill(pid_t, int);

/* Every sigset_t-taking function below dereferences its set argument(s)
 * unconditionally, with no NULL check in its implementation. */
async_signal_safe
int sigemptyset(sigset_t *) __attribute__((nonnull(1)));
async_signal_safe
int sigfillset(sigset_t *) __attribute__((nonnull(1)));
async_signal_safe
int sigaddset(sigset_t *, int) __attribute__((nonnull(1)));
async_signal_safe
int sigdelset(sigset_t *, int) __attribute__((nonnull(1)));
async_signal_safe
int sigismember(const sigset_t *, int) __attribute__((nonnull(1)));

async_signal_safe
int sigprocmask(int, const sigset_t *__restrict, sigset_t *__restrict);
async_signal_safe
int sigsuspend(const sigset_t *);
async_signal_safe
int sigaction(int, const struct sigaction *__restrict, struct sigaction *__restrict);
async_signal_safe
int sigpending(sigset_t *) __attribute__((nonnull(1)));
/* sig is deliberately NOT marked: sigwait() guards it with a real
 * `if (sig) *sig = selected;`. */
int sigwait(const sigset_t *__restrict, int *__restrict) __attribute__((nonnull(1)));
int pthread_sigmask(int, const sigset_t *__restrict, sigset_t *__restrict);
/* info is optional: sigwaitinfo() only writes through it behind a real
 * `if (si) *si = ...;` guard. */
int sigwaitinfo(const sigset_t *__restrict, siginfo_t *__restrict) __attribute__((nonnull(1)));
/* timeout is deliberately NOT marked: sigtimedwait() has a real, live
 * NULL check (`if (!timeout || ...) return EINVAL;`). */
int sigtimedwait(const sigset_t *__restrict, siginfo_t *__restrict, const struct timespec *__restrict) __attribute__((nonnull(1)));
async_signal_safe
int sigqueue(pid_t, int, union sigval);

int sigaltstack(const stack_t *__restrict, stack_t *__restrict);

/* pinfo is dereferenced unconditionally; s (the message prefix) is
 * optional -- psignal() itself guards it with `if (s && *s)`. */
void psiginfo(const siginfo_t *, const char *) __attribute__((nonnull(1)));

#endif

#if defined(_XOPEN_SOURCE) || defined(_BSD_SOURCE) || defined(_GNU_SOURCE)
#define NSIG _NSIG
typedef void (*sig_t)(int);
int killpg(pid_t, int);
async_signal_safe
int sigpause(int);
int siginterrupt(int, int);
int sigignore(int);
int sighold(int);
int sigrelse(int);
void (*sigset(int, void (*)(int)))(int);
/* 2 continues the SIG_DFL 0 / SIG_IGN 1 sequence below (same value
 * musl and glibc use); just needs to be distinguishable from those,
 * SIG_ERR, and any real function address. */
#define SIG_HOLD ((void (*)(int)) 2)
#define TRAP_BRKPT 1
#define TRAP_TRACE 2
#define POLL_IN 1
#define POLL_OUT 2
#define POLL_MSG 3
#define POLL_ERR 4
#define POLL_PRI 5
#define POLL_HUP 6
#define SS_ONSTACK    1
#define SS_DISABLE    2
#endif

#if defined(_BSD_SOURCE) || defined(_GNU_SOURCE)
typedef void (*sighandler_t)(int);
void psignal(int, const char *);
/* Same shared sigset_t-family contract as sigemptyset() et al. above;
 * see that comment. */
int sigisemptyset(const sigset_t *) __attribute__((nonnull(1)));
int sigorset (sigset_t *, const sigset_t *, const sigset_t *) __attribute__((nonnull(1, 2, 3)));

#define SA_NOMASK SA_NODEFER
#define SA_ONESHOT SA_RESETHAND
#endif

#define SIG_ERR  ((void (*)(int))-1)
#define SIG_DFL  ((void (*)(int)) 0)
#define SIG_IGN  ((void (*)(int)) 1)

typedef int sig_atomic_t;

async_signal_safe
void (*signal(int, void (*)(int)))(int);
async_signal_safe
io_operation
int raise(int);

#define SIGHUP    1
#define SIGINT    2
#define SIGQUIT   3
#define SIGILL    4
#define SIGTRAP   5
#define SIGABRT   6
#define SIGIOT    SIGABRT
#define SIGBUS    7
#define SIGFPE    8
#define SIGKILL   9
#define SIGUSR1   10
#define SIGSEGV   11
#define SIGUSR2   12
#define SIGPIPE   13
#define SIGALRM   14
#define SIGTERM   15
#define SIGSTKFLT 16
#define SIGCHLD   17
#define SIGCONT   18
#define SIGSTOP   19
#define SIGTSTP   20
#define SIGTTIN   21
#define SIGTTOU   22
#define SIGURG    23
#define SIGXCPU   24
#define SIGXFSZ   25
#define SIGVTALRM 26
#define SIGPROF   27
#define SIGWINCH  28
#define SIGIO     29
#define SIGPOLL   29
#define SIGPWR    30
#define SIGSYS    31
#define SIGUNUSED SIGSYS

#define _NSIG 65

#ifdef __cplusplus
}
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
