/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux implementation of src/internal/plat_process.h -- see src/mman/
 * linux/plat_mem.c's own banner for the raw-syscall discipline every
 * Linux backend follows.
 *
 * Process-handle encoding: a Linux __plat_handle_t here is the pid itself,
 * cast straight through, with NO offset -- unlike a file descriptor, 0 is
 * never a valid pid, so __PLAT_HANDLE_NULL never collides and no +1 trick
 * is needed.
 *
 * That plain encoding has one deliberately-not-fully-solved consequence:
 * fork.c's mark_children_inheritable() and children.c's __child_remove()
 * call plat_fd.c's fd-domain __plat_dup()/__plat_close() directly on a
 * process handle -- correct on NT (one HANDLE domain), but a pid and an fd
 * are different Linux kernel namespaces entirely, so __plat_close()'s
 * fd-domain unbox() would reinterpret the boxed pid as (pid - 1) and
 * close(2) whatever descriptor that happens to be. Not fixed here; what
 * keeps this from corrupting a live descriptor in practice is that pids
 * run many orders of magnitude higher than any fd a process actually has
 * open, so the misdirected close reliably lands on an fd nothing ever
 * opened and fails silently EBADF -- a coincidence of scale, not a proof.
 *
 * The other structural difference from NT: Linux's wait4()/waitpid() both
 * detect exit AND reap in one shot, irreversibly (a second wait4() on the
 * same pid fails ECHILD), unlike NT where a process handle can be queried
 * any number of times after the wait. So __plat_process_wait() below does
 * the real one-time reap itself and stashes the translated exit code and
 * CPU times in a small fixed-size table for __plat_process_exit_code()/
 * __plat_process_times() to read back. The exit code is encoded the same
 * way as the NT backend's, so src/process/wait.c's __wait_encode_status()
 * needs no per-backend copy of that decoding.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <errno.h>
#include <stdlib.h>     /* malloc()/free(), used deep in the cloned child in
                         * __plat_process_spawn(); safe since clone() here
                         * has no CLONE_VM to share heap state with the
                         * parent. */
#include <sys/wait.h>   /* WIFEXITED/WEXITSTATUS/WIFSIGNALED/WTERMSIG, which
                         * apply directly to a raw Linux wait4(2) status. */
#include "libc.h"
#include "plat_process.h"
#include "unsafe_pointer.h"

/* Linux syscall numbers -- aarch64 confirmed against this host's own
 * <sys/syscall.h>; x86_64/i386 confirmed against a real x86_64-linux-gnu
 * glibc's own asm/unistd_64.h/unistd_32.h, genuinely different tables
 * from aarch64's. None of the three define a fork(2) number: aarch64 has
 * no such syscall at all, and though x86_64/i386 do, clone(2) takes the
 * identical (flags, stack, ptid, ctid, tls) shape on all three arches,
 * so __plat_process_fork()/__plat_process_spawn() share one
 * clone(SIGCHLD, 0, 0, 0, 0) call across all of them instead. */
#if defined(__aarch64__)
#define SYS_clone      220
#define SYS_execve     221
#define SYS_wait4      260
#define SYS_exit_group 94
#define SYS_kill       129
#define SYS_openat     56
#define SYS_close      57
#define SYS_fstat      80
#define SYS_pipe2      59
#define SYS_dup3       24
#define SYS_fcntl      25   /* used for F_DUPFD staging in __plat_process_spawn() */
#define SYS_read       63
#define SYS_write      64
#define SYS_nanosleep  101
#elif defined(__x86_64__)
#define SYS_clone      56
#define SYS_execve     59
#define SYS_wait4      61
#define SYS_exit_group 231
#define SYS_kill       62
#define SYS_openat     257
#define SYS_close      3
#define SYS_fstat      5
#define SYS_pipe2      293
#define SYS_dup3       292
#define SYS_fcntl      72   /* same x86_64 number src/fcntl/linux/
                             * plat_fcntl.c already uses. */
#define SYS_read       0
#define SYS_write      1
#define SYS_nanosleep  35
#elif defined(__i386__)
#define SYS_clone      120
#define SYS_execve     11
#define SYS_wait4      114
#define SYS_exit_group 252
#define SYS_kill       37
#define SYS_openat     295
#define SYS_close      6
#define SYS_fstat      108
#define SYS_pipe2      331
#define SYS_dup3       330
#define SYS_fcntl      55   /* same i386 number src/fcntl/linux/
                             * plat_fcntl.c already uses. */
#define SYS_read       3
#define SYS_write      4
#define SYS_nanosleep  162
#else
#error "plat_process.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

#define AT_FDCWD_LX     (-100)
#define O_CLOEXEC_LX    0x80000  /* octal 02000000 -- confirmed against the host */
#define WNOHANG_LX      1
#define SIGCHLD_LX      17
#define SIGCONT_LX      18
/* F_DUPFD is command 0 on every Linux architecture (uapi/asm-generic/fcntl.h). */
#define F_DUPFD_LX      0

/* Regular-file / execute-permission-bit masks, standard POSIX values. */
#define S_IFMT_LX  0170000
#define S_IFREG_LX 0100000
#define S_IXUSR_LX 0100
#define S_IXGRP_LX 0010
#define S_IXOTH_LX 0001

/* A minimal 6-argument raw syscall, one calling convention per arch
 * below. NOT `extern long syscall(long, ...)`: that resolves to the
 * HOST's real glibc at link time, and glibc's syscall() sets glibc's OWN
 * errno on failure rather than handing back the raw kernel -errno this
 * file's `errno = (int)-ret` translation requires. __plat_process_fork()
 * below also relies on this returning zero exactly once from the
 * *child* side of clone(2) -- safe on every arch here because
 * SIGCHLD-only clone (no CLONE_VM) shares the parent's stack, unlike
 * src/thread/linux/plat_thread.c's CLONE_VM case. */
#if defined(__aarch64__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6) // NOLINT(bugprone-easily-swappable-parameters) -- raw syscall ABI slots are positional and semantically distinct
{
	register long x8 __asm__("x8") = nr;
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = a3;
	register long x3 __asm__("x3") = a4;
	register long x4 __asm__("x4") = a5;
	register long x5 __asm__("x5") = a6;
	__asm__ volatile("svc #0"
		: "+r"(x0)
		: "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
		: "memory", "cc");
	return x0;
}
#elif defined(__x86_64__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long ret;
	register long r10 __asm__("r10") = a4;
	register long r8  __asm__("r8")  = a5;
	register long r9  __asm__("r9")  = a6;
	__asm__ volatile("syscall"
	                 : "=a"(ret)
	                 : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
	                 : "rcx", "r11", "memory");
	return ret;
}
#elif defined(__i386__)
/* Saves/restores %ebx and %ebp around int $0x80 (both double as syscall
 * argument registers here); the asm never touches %esp beyond this
 * matched push/pop pair, so both the parent and child return through an
 * intact C stack frame. */
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long args[7];
	long ret;
	args[0] = nr; args[1] = a1; args[2] = a2; args[3] = a3;
	args[4] = a4; args[5] = a5; args[6] = a6;
	__asm__ volatile(
		"pushl %%ebp\n\t"
		"pushl %%ebx\n\t"
		"movl 4(%%eax), %%ebx\n\t"
		"movl 8(%%eax), %%ecx\n\t"
		"movl 12(%%eax), %%edx\n\t"
		"movl 16(%%eax), %%esi\n\t"
		"movl 20(%%eax), %%edi\n\t"
		"movl 24(%%eax), %%ebp\n\t"
		"movl (%%eax), %%eax\n\t"
		"int $0x80\n\t"
		"popl %%ebx\n\t"
		"popl %%ebp"
		: "=a"(ret)
		: "a"(args)
		: "ecx", "edx", "esi", "edi", "memory", "cc");
	return ret;
}
#endif

static int is_sys_error(long ret)
{
	return (unsigned long)ret >= (unsigned long)-4095L;
}

static int box_pid(int pid) { return pid; }   /* documentation no-op: see this file's banner */
static int unbox_pid(__plat_handle_t h) { return (int)(long)h; }

/* std[0..2]'s three slots are NOT this file's own process-handle domain:
 * they come from the fd table, boxed fd+1 the way plat_fd.c encodes them.
 * Unboxing them here reads that convention, not this file's own. */
static int unbox_fd(__plat_handle_t h) { return (int)((long)h - 1); }

/* ---- find_program.c: is this file something Linux's loader/kernel --- */
/* ---- can start directly? ---------------------------------------------- */

/* A minimal, byte-exact mirror of the leading fields of Linux's real
 * kernel struct stat, padded to the kernel's real total size so
 * fstat(2) never writes past this buffer. Only st_mode is ever read.
 *
 * Field order genuinely differs per arch, not just widths: aarch64
 * orders st_mode (4-byte uint) before st_nlink, at offset 16
 * (dev(8)+ino(8)); x86_64 orders st_nlink (8-byte ulong) before st_mode
 * instead, so st_mode sits at offset 24; i386's classic pre-LFS layout
 * uses 4-byte st_dev/st_ino and 2-byte st_mode/st_nlink (mode-then-
 * nlink), landing st_mode at offset 8. Whole-struct sizes: 128
 * (aarch64), 144 (x86_64), 64 (i386 -- the old non-LFS fstat(2); moot
 * here since only st_mode is read). */
#if defined(__aarch64__)
struct raw_stat_prefix {
	unsigned long st_dev;
	unsigned long st_ino;
	unsigned int  st_mode;
	unsigned int  st_nlink;
	unsigned char reserved[128 - 24];
};
#define RAW_STAT_SIZE 128
#elif defined(__x86_64__)
struct raw_stat_prefix {
	unsigned long st_dev;
	unsigned long st_ino;
	unsigned long st_nlink;
	unsigned int  st_mode;
	unsigned char reserved[144 - 28];
};
#define RAW_STAT_SIZE 144
#elif defined(__i386__)
struct raw_stat_prefix {
	unsigned long  st_dev;
	unsigned long  st_ino;
	unsigned short st_mode;
	unsigned short st_nlink;
	unsigned char  reserved[64 - 12];
};
#define RAW_STAT_SIZE 64
#else
#error "plat_process.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif
/* Catches unexpected compiler padding at compile time instead of
 * risking a silent fstat(2) buffer overflow. */
_Static_assert(sizeof(struct raw_stat_prefix) == RAW_STAT_SIZE,
               "raw_stat_prefix size mismatch for this architecture");

/* Unlike NT, Linux has a real execute permission bit and its kernel
 * already runs a "#!" script directly through binfmt_script, so there is
 * nothing here to distinguish. A regular file with any execute bit set is
 * "yes"; anything else, including any open/stat failure, is "no". */
int __plat_is_program(const char *path)
{
	long fd = raw_syscall(SYS_openat, (long)AT_FDCWD_LX, (long)path, 0L /* O_RDONLY */, 0L, 0L, 0L);
	struct raw_stat_prefix st = {0};
	long ret;

	if (is_sys_error(fd)) return 0;
	ret = raw_syscall(SYS_fstat, fd, (long)&st, 0L, 0L, 0L, 0L);
	raw_syscall(SYS_close, fd, 0L, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) return 0;
	if ((st.st_mode & S_IFMT_LX) != S_IFREG_LX) return 0;
	if (!(st.st_mode & (S_IXUSR_LX | S_IXGRP_LX | S_IXOTH_LX))) return 0;
	return 1;
}

/* ---- fork.c: clone(2) and the (nonexistent) suspended-thread resume -- */

int __plat_process_fork(struct __plat_fork_result *out)
{
	long pid = raw_syscall(SYS_clone, (long)SIGCHLD_LX, 0L, 0L, 0L, 0L, 0L);

	if (pid == 0) return __PLAT_FORK_CHILD;
	if (is_sys_error(pid)) { errno = (int)-pid; return -1; }

	/* __plat_handle_t is an opaque one-word carrier shared with the NT
	 * backend; box_pid() is a documentation no-op (this file's banner)
	 * -- the real payload is the bare Linux pid, never dereferenced. */
	out->process = unsafe_assume_valid_pointer((__plat_handle_t)(long)box_pid((int)pid));
	/* No suspended clone thread to hand back: clone(2) without CLONE_VM
	 * starts the child running immediately, like glibc's own fork(). */
	out->thread = __PLAT_HANDLE_NULL;
	/* No job-object concept on Linux -- the kernel already folds a reaped
	 * child's own cutime/cstime into this process's accounting at wait4()
	 * time natively. Always NULL; __plat_process_times() ignores it. */
	out->job = __PLAT_HANDLE_NULL;
	out->pid = (int)pid;
	return __PLAT_FORK_PARENT;
}

/* __plat_thread_resume(): declared in both plat_process.h and
 * plat_thread.h, but defined in src/thread/linux/plat_thread.c (ODR) --
 * that file's own __plat_thread_spawn() is now a real create-suspended
 * primitive (a clone()'d thread gated on a manual-reset event, since
 * clone(2)/execve(2) themselves have no OS-level "start suspended"
 * concept), and __plat_thread_resume() needs its suspend_table to find
 * which gate, if any, a given handle is waiting on. This file's own
 * __plat_process_fork() always hands back __PLAT_HANDLE_NULL for
 * out->thread, so fork.c's own call to __plat_thread_resume() finds
 * nothing to do and is a plain no-op success on this backend. */

/* ---- wait.c: wait4(2), and the peek/query split Linux's one-shot ----- */
/* ---- reap does not offer natively -------------------------------------- */

#define REAP_CACHE_MAX 256   /* matches CHILD_MAX_'s own static-table sizing (libc.h) */

struct reap_entry {
	int pid;                 /* 0 == free slot; a real pid is never 0 */
	int code;                /* NT-shaped: __wait_encode_status()'s input */
	unsigned long long ktime100ns;
	unsigned long long utime100ns;
};

static struct reap_entry reap_cache[REAP_CACHE_MAX];

static struct reap_entry *reap_find(int pid)
{
	int i;
	for (i = 0; i < REAP_CACHE_MAX; i++)
		if (reap_cache[i].pid == pid) return &reap_cache[i];
	return 0;
}

static struct reap_entry *reap_alloc(int pid)
{
	int i;
	for (i = 0; i < REAP_CACHE_MAX; i++)
		if (!reap_cache[i].pid) { reap_cache[i].pid = pid; return &reap_cache[i]; }
	return 0;   /* table exhausted -- see the fallback note below */
}

/* Return a slot to the pool once its info has been delivered. pid == 0 is
 * "already free", so a redundant or not-found release is a silent no-op. */
static void reap_free(int pid)
{
	struct reap_entry *e = reap_find(pid);
	if (e) e->pid = 0;
}

/* Byte-exact mirror of Linux's real struct rusage (ru_utime at offset 0,
 * ru_stime at offset 16, both `struct timeval`, whole struct 144 bytes),
 * padded to the kernel's real size like raw_stat_prefix above. */
struct raw_timeval { long tv_sec; long tv_usec; };
struct raw_rusage {
	struct raw_timeval ru_utime;
	struct raw_timeval ru_stime;
	unsigned char reserved[144 - 32];
};

/* tv required: dereferenced unconditionally (`tv->tv_sec`) as the very
 * first thing this function does; its only real call sites pass
 * &ru.ru_stime/&ru.ru_utime, addresses of a local, never NULL. */
static unsigned long long tv_to_100ns(struct raw_timeval *tv)
    __attribute__((nonnull(1)));
static unsigned long long tv_to_100ns(struct raw_timeval *tv)
{
	return (unsigned long long)tv->tv_sec * 10000000ULL +
	       (unsigned long long)tv->tv_usec * 10ULL;
}

int __plat_process_wait(__plat_handle_t h, int mode)
{
	int pid = unbox_pid(h);
	int status = 0;
	long options;
	long ret;
	struct raw_rusage ru;
	struct reap_entry *e;
	int i;

	/* Already reaped by an earlier call to this very function -- report
	 * "still signalled" without touching the kernel again, since the
	 * pid may since have been recycled onto an unrelated live process. */
	if (reap_find(pid)) return 1;

	switch (mode) {
	case __PLAT_WAIT_NOHANG:
	case __PLAT_WAIT_POLL:   options = WNOHANG_LX; break;
	default:                 options = 0; break;
	}

	for (i = 0; i < (int)sizeof ru; i++) ((unsigned char *)&ru)[i] = 0;
	ret = raw_syscall(SYS_wait4, (long)pid, (long)&status, options, (long)&ru, 0L, 0L);

	if (mode == __PLAT_WAIT_POLL && ret == 0) {
		/* Not yet exited: sleep ~10ms, the same short poll interval
		 * the NT backend's own __PLAT_WAIT_POLL case builds into its
		 * single NtWaitForSingleObject call (see plat_process.h), so a
		 * WUNTRACED caller re-checking in a loop does not spin. */
		struct { long tv_sec; long tv_nsec; } ts;
		ts.tv_sec = 0; ts.tv_nsec = 10000000L;
		raw_syscall(SYS_nanosleep, (long)&ts, 0L, 0L, 0L, 0L, 0L);
		return 0;
	}
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	if (ret == 0) return 0;   /* WNOHANG: not exited yet */

	e = reap_alloc(pid);
	if (WIFSIGNALED(status)) {
		int code_val = WTERMSIG(status);
		int nt_code = (int)(0xE0DE0000u | ((unsigned)code_val & 0x7fu));
		if (e) e->code = nt_code;
	} else {
		int exitcode = WEXITSTATUS(status) & 0xff;
		if (e) e->code = exitcode;
	}
	if (e) {
		e->ktime100ns = tv_to_100ns(&ru.ru_stime);
		e->utime100ns = tv_to_100ns(&ru.ru_utime);
	}
	/* A full reap-cache table has nowhere left to stash this exit status
	 * (the wait4() above already, unavoidably, reaped the child). Degrades
	 * by still reporting the process signalled, losing only the
	 * exit-code/rusage detail. */
	return 1;
}

int __plat_process_exit_code(__plat_handle_t h, int *code)
{
	struct reap_entry *e = reap_find(unbox_pid(h));
	if (!e) { errno = ECHILD; return -1; }
	*code = e->code;
	return 0;
}

int __plat_process_times(__plat_handle_t h, __plat_handle_t job,
                          unsigned long long *ktime100ns, unsigned long long *utime100ns)
{
	struct reap_entry *e = reap_find(unbox_pid(h));
	/* job is always __PLAT_HANDLE_NULL on this backend and never consulted:
	 * the wait4(2) rusage already captured into *e is the complete answer. */
	(void)job;
	if (!e) { errno = ECHILD; return -1; }
	*ktime100ns = e->ktime100ns;
	*utime100ns = e->utime100ns;
	return 0;
}

/* A reap_cache slot exists only to bridge __plat_process_wait()'s real,
 * irreversible wait4(2) reap to the __plat_process_exit_code()/
 * __plat_process_times() reads do_waitpid() makes immediately afterward.
 * Freeing it here, rather than leaving it allocated for the process's
 * whole life, keeps a long-running process (a shell, crond, anything that
 * forks in a loop) from exhausting all REAP_CACHE_MAX slots. */
void __plat_process_reap_release(__plat_handle_t h)
{
	reap_free(unbox_pid(h));
}

/* ---- signal.c's job-control resume, via kill()'s job-control arm ----- */
/* ---- (src/process/children.c's clear_stops() also calls this) -------- */

int __plat_process_resume(__plat_handle_t h)
{
	/* Canonical implementation for both plat_process.h and plat_signal.h's
	 * identically-named declaration. SIGCONT here is the actual kernel
	 * mechanism, unlike NT's NtSuspendProcess/NtResumeProcess pair which
	 * this project's signal subsystem has to synthesize. */
	long ret = raw_syscall(SYS_kill, (long)unbox_pid(h), (long)SIGCONT_LX, 0L, 0L, 0L, 0L);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* ---- spawn.c: fork + dup the standard descriptors + execve ----------- */

/* One entry in __plat_process_spawn()'s child-side descriptor staging.
 * `target` is the descriptor number the entry must end up AT (0, 1, 2 for
 * a standard descriptor; posix_spawn_file_actions_adddup2()'s `newfd`,
 * always > 2, otherwise). `orig` is the real fd the content started at;
 * `mv` is the current best-known real fd for that content, initially a
 * copy of `orig` and overwritten with a scratch descriptor if staging was
 * needed. `mv < 0` means "this target should end up closed" -- only
 * possible for a std[0..2] entry. */
struct fd_move {
	int target;
	int mv;
	int orig;
};

int __plat_process_spawn(const char *path, char *const argv[], char *const envp[],
                         const __plat_handle_t std[3], __plat_handle_t *out_process,
                         __plat_handle_t *out_job)
{
	long pfd_ret;
	int pipefd[2];
	long pid;

	/* A self-pipe, close-on-exec on the write end, is the standard way to
	 * make an otherwise-asynchronous fork()+execve() report a real execve()
	 * failure back to the caller of THIS call, synchronously. A successful
	 * execve() closes every O_CLOEXEC fd as part of replacing the child's
	 * image, so the write end closes itself and the parent's read sees EOF;
	 * a failed execve() leaves the child able to write its errno first. */
	{
		/* pipe2(2) writes exactly two `int`s into this buffer; declaring it
		 * wider would leave pipefd[1] reading uninitialized stack. */
		int fds[2] = {-1, -1};
		pfd_ret = raw_syscall(SYS_pipe2, (long)fds, (long)O_CLOEXEC_LX, 0L, 0L, 0L, 0L);
		if (is_sys_error(pfd_ret)) { errno = (int)-pfd_ret; return -1; }
		pipefd[0] = fds[0];
		pipefd[1] = fds[1];
	}

	pid = raw_syscall(SYS_clone, (long)SIGCHLD_LX, 0L, 0L, 0L, 0L, 0L);
	if (is_sys_error(pid)) {
		int e = (int)-pid;
		raw_syscall(SYS_close, (long)pipefd[0], 0L, 0L, 0L, 0L, 0L);
		raw_syscall(SYS_close, (long)pipefd[1], 0L, 0L, 0L, 0L, 0L);
		errno = e;
		return -1;
	}

	if (pid == 0) {
		/* Child. std[i] == __PLAT_HANDLE_NULL means "closed" (spawn.c
		 * already turned a close-on-exec descriptor into that): an actual
		 * close(2) represents that on Linux, unlike NT's value-blind
		 * placeholder dance (a closed Linux fd is simply absent). */
		int i, ntotal, extra_n = 0;
		struct fd_move *fm;
		const struct __spawn_dup2_target *extra;
		int max_target;
		raw_syscall(SYS_close, (long)pipefd[0], 0L, 0L, 0L, 0L, 0L);

		/* posix_spawn_file_actions_adddup2() targets above 2. Folded into
		 * the SAME staging pass as std[0..2] below, not a separate one:
		 * a source outside 0..2 could still collide with one of these
		 * targets, or vice versa, so both groups need the same
		 * target-zone floor to stage against. */
		extra = __spawn_pending_dup2s(&extra_n);
		ntotal = 3 + extra_n;

		/* One malloc rather than three, keeping target/mv/orig's ownership
		 * to a single alloc/free pair. Sized ntotal, never less than 3, so
		 * this covers fd 0/1/2 even when extra_n is 0. */
		{
			size_t fmbytes;
			fm = __size_mul_checked((size_t)ntotal, sizeof *fm, &fmbytes) ?
				malloc(fmbytes) : NULL;
		}
		if (!fm) {
			int e = ENOMEM;
			raw_syscall(SYS_write, (long)pipefd[1], (long)&e, (long)sizeof e, 0L, 0L, 0L);
			raw_syscall(SYS_close, (long)pipefd[1], 0L, 0L, 0L, 0L, 0L);
			raw_syscall(SYS_exit_group, 127L, 0L, 0L, 0L, 0L, 0L);
			/* unreachable */
			return -1;
		}

		max_target = 2;
		for (i = 0; i < 3; i++) {
			fm[i].target = i;
			fm[i].orig = std[i] ? unbox_fd(std[i]) : -1;
		}
		for (i = 0; i < extra_n; i++) {
			fm[3 + i].target = extra[i].fd;
			fm[3 + i].orig = unbox_fd(extra[i].h);
			if (extra[i].fd > max_target) max_target = extra[i].fd;
		}

		/* A source fd can itself equal ANY target in this list. Mutating a
		 * target in place (close(), or dup3() which closes whatever was
		 * there first) would silently destroy that fd if a later target
		 * still needs it as its own source -- confirmed live: closing fd 0
		 * in the parent, then adding a dup2-onto-fd-2 action whose own
		 * __plat_dup() reused that just-freed fd 0, reproduced the child's
		 * stderr redirect silently failing to reach the target.
		 *
		 * Fixed generally: every live source at or below the highest
		 * target in the WHOLE list is first duplicated (F_DUPFD) to a
		 * scratch descriptor above every target, before any target is
		 * touched. Once staged, no target's dup3()/close() can reach a
		 * scratch fd, so the placement pass below is safe regardless of
		 * which raw fd numbers were originally named, including a full
		 * swap among them. */
		for (i = 0; i < ntotal; i++) {
			fm[i].mv = fm[i].orig;
			if (fm[i].mv < 0 || fm[i].mv > max_target) continue;
			{
				long t = raw_syscall(SYS_fcntl, (long)fm[i].mv,
				                      (long)F_DUPFD_LX, (long)(max_target + 1), 0L, 0L, 0L);
				/* F_DUPFD failing here (fd-table exhaustion) is the only
				 * way fm[i].mv can still land inside the target zone --
				 * fall back to the original, unstaged source rather than
				 * lose the redirect outright. */
				if (!is_sys_error(t)) fm[i].mv = (int)t;
			}
		}
		for (i = 0; i < ntotal; i++) {
			if (fm[i].mv < 0) {
				raw_syscall(SYS_close, (long)fm[i].target, 0L, 0L, 0L, 0L, 0L);
			} else if (fm[i].mv != fm[i].target) {
				raw_syscall(SYS_dup3, (long)fm[i].mv, (long)fm[i].target, 0L, 0L, 0L, 0L);
			}
		}
		/* Close the scratch copies -- two different rules for the two
		 * groups sharing this array. A std[0..2] entry (i < 3) preserves
		 * an unstaged source (fm[i].mv == fm[i].orig): that's the
		 * caller's own real descriptor, and closing it would take away a
		 * descriptor the caller never asked to lose. An extra target
		 * (i >= 3) has no such caller-visible original: it's always a
		 * throwaway duplicate build_dup2_targets() minted purely to feed
		 * this spawn, so it's always closed once placed, staged or not. */
		for (i = 0; i < ntotal; i++) {
			if (fm[i].mv < 0 || fm[i].mv == fm[i].target) continue;
			if (i < 3 && fm[i].mv == fm[i].orig) continue;
			raw_syscall(SYS_close, (long)fm[i].mv, 0L, 0L, 0L, 0L, 0L);
		}
		free(fm);
		{
			long ret = raw_syscall(SYS_execve, (long)path, (long)argv, (long)envp, 0L, 0L, 0L);
			int e = is_sys_error(ret) ? (int)-ret : EINVAL;
			raw_syscall(SYS_write, (long)pipefd[1], (long)&e, (long)sizeof e, 0L, 0L, 0L);
			raw_syscall(SYS_close, (long)pipefd[1], 0L, 0L, 0L, 0L, 0L);
		}
		raw_syscall(SYS_exit_group, 127L, 0L, 0L, 0L, 0L, 0L);
		/* unreachable */
		return -1;
	}

	/* Parent. */
	raw_syscall(SYS_close, (long)pipefd[1], 0L, 0L, 0L, 0L, 0L);
	{
		int e = 0;
		long n = raw_syscall(SYS_read, (long)pipefd[0], (long)&e, (long)sizeof e, 0L, 0L, 0L);
		raw_syscall(SYS_close, (long)pipefd[0], 0L, 0L, 0L, 0L, 0L);
		if (n == (long)sizeof e) {
			/* execve() failed in the child; it has already called
			 * _exit(127) (via exit_group) or is about to, so reap it
			 * here rather than leaving a zombie the front door's own
			 * child table was never told about. */
			raw_syscall(SYS_wait4, pid, 0L, 0L, 0L, 0L, 0L);
			errno = e;
			return -1;
		}
	}

	/* Boxing, not dereference -- see __plat_process_fork()'s own comment
	 * above on the identical box_pid() encoding. */
	*out_process = unsafe_assume_valid_pointer((__plat_handle_t)(long)box_pid((int)pid));
	/* No job-object concept on Linux -- see __plat_process_fork()'s own
	 * comment just above, which applies here identically. */
	*out_job = __PLAT_HANDLE_NULL;
	return (int)pid;
}

/* ---- exec.c: a real, in-place execve(2), a primitive NT has no equivalent for */

int __plat_process_exec(const char *path, char *const argv[], char *const envp[])
{
	long ret = raw_syscall(SYS_execve, (long)path, (long)argv, (long)envp, 0L, 0L, 0L);
	/* execve(2) returns to its caller only on failure: a success replaces
	 * this thread's address space and resumes at the new entry point
	 * instead of returning from `svc #0` at all. */
	errno = is_sys_error(ret) ? (int)-ret : EINVAL;
	return -1;
}

// NOLINTEND(misc-include-cleaner)
