/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform-process interface src/process/{find_program,children,wait,
 * posix_spawn,fork,spawn}.c's POSIX-facing front doors call into instead
 * of RtlCloneUserProcess/RtlCreateUserProcess/NtWaitForSingleObject/
 * NtQueryInformationProcess/NtResumeThread/NtResumeProcess directly.  See
 * src/process/nt/plat_process.c for the implementation these declare.
 *
 * This subsystem's front doors keep more than the pilot's did: the pid
 * table (__children[]/__child_add()/__child_find(), src/internal/libc.h)
 * is this library's own POSIX-bookkeeping strategy, exactly like mman.c's
 * reservation table (src/internal/plat_mem.h) -- shared verbatim by
 * whichever backend is compiled in, not part of this interface.  So is
 * every reset call fork.c makes on the child side after
 * __plat_process_fork() returns (__pthread_reset_after_fork(),
 * __rusage_children_reset(), __mman_reset_after_fork(), ...): those are
 * POSIX-level state a fresh child must not inherit, not anything NT-
 * specific, and their ORDER relative to the platform call is part of
 * fork()'s own contract, not this interface's.
 *
 * A few functions here are coarser than the pilot's per-syscall style,
 * deliberately: __plat_process_spawn() runs the whole parameter-block-
 * build-and-create-process sequence as one call (mirroring
 * __plat_mem_map_file()'s two-step section-then-view dance staying one
 * call), and __plat_process_fork() has to hand back a real tri-state
 * (child / parent / error) because the NTSTATUS that tells "this is the
 * child now" apart from "this is the parent" -- STATUS_PROCESS_CLONED,
 * a SUCCESS-severity status distinct from STATUS_SUCCESS -- only exists
 * inside the call that has the real status in hand; a generic status-to-
 * errno mapping performed afterward could never reconstruct that
 * distinction from a plain 0/-1 result. */
#ifndef _SPICULE_PLAT_PROCESS_H
#define _SPICULE_PLAT_PROCESS_H

#include <stddef.h>
#include <sys/types.h>
#include "plat_handle.h"

/* Is `path` something NT's loader can start, or a script something else
 * (execvp()'s shell fallback) must run instead?  The whole-file sniff
 * (open, check for a cloud-placeholder attribute, read two bytes, close)
 * lives entirely inside the backend; the caller supplies nothing NT-
 * specific and gets back exactly 1 or 0, never an error -- any failure
 * to open/read/classify the file is itself a "no" (see
 * src/process/find_program.c's own banner for why). */
int __plat_is_program(const char *path);

/* fork(): the result of one RtlCloneUserProcess call, which returns
 * TWICE -- once in each process -- and tells them apart by NTSTATUS
 * value, not by any argument.  See this header's banner for why that
 * decision cannot be made anywhere but here. */
struct __plat_fork_result {
	__plat_handle_t process;   /* parent only: the child's process handle */
	__plat_handle_t thread;    /* parent only: the child's (suspended) thread */
	/* parent only: the job the child was placed in before its thread was
	 * ever resumed, or __PLAT_HANDLE_NULL if none (best-effort, see
	 * struct __child's own comment in src/internal/libc.h -- this is the
	 * same field, just not yet filed into the child table). Always
	 * __PLAT_HANDLE_NULL on a backend with no job-object concept
	 * (Linux). */
	__plat_handle_t job;
	int pid;                   /* parent only */
};
#define __PLAT_FORK_CHILD  0   /* this call is returning in the new process */
#define __PLAT_FORK_PARENT 1   /* this call is returning in the parent; *out filled */
/* A negative return is -1, with errno already set -- no process was
 * created, both sides of RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES's
 * caller-side handle marking are the front door's job before and after
 * this call either way (src/process/fork.c), not this interface's. */
/* out required: both real implementations (linux/plat_process.c,
 * nt/plat_process.c) write `out->process = ...;`/`out->pid = ...;`/
 * `out->job = ...;` on their parent-success return path, with no NULL
 * check of out itself anywhere in either body. */
int __plat_process_fork(struct __plat_fork_result *out) __attribute__((nonnull(1)));

/* Resume a thread this backend handed back suspended -- fork()'s cloned
 * thread and spawn()'s new process's initial thread alike.  The result
 * is intentionally not checked by any caller today (neither
 * RtlCloneUserProcess nor RtlCreateUserProcess leaves a plausible reason
 * for a resume on a handle just received from them to fail), so this
 * reports success/failure but nothing currently acts on failure -- kept
 * POSIX-shaped rather than void so that could change without another
 * interface edit. */
int __plat_thread_resume(__plat_handle_t th);

/* How long __plat_process_wait() may block. */
#define __PLAT_WAIT_BLOCK  0   /* wait until the process exits */
#define __PLAT_WAIT_NOHANG 1   /* return immediately either way (WNOHANG) */
#define __PLAT_WAIT_POLL   2   /* a short poll interval -- self-stop markers
                                 * are not handles in any wait set, so a
                                 * WUNTRACED caller has to keep re-checking
                                 * for one instead of blocking past it */

/* Wait for `h`, a child process handle, to become signalled (the process
 * has exited), honoring `mode`.  Returns 1 once signalled, 0 if the
 * chosen mode timed out first (only possible for NOHANG/POLL), or -1
 * with errno set on a genuine wait failure -- STATUS_TIMEOUT is decided
 * here, not left for the front door to infer from a generic mapping. */
int __plat_process_wait(__plat_handle_t h, int mode);

/* The exit code of a process __plat_process_wait() has already reported
 * as signalled.  0/-1(errno); *code is set only on success. */
/* code required: both real implementations write `*code = ...;`
 * (only on the success path -- see this comment's own "set only on
 * success" note above -- but with no NULL check of code itself, so a
 * genuine success call with code == NULL would still crash). */
int __plat_process_exit_code(__plat_handle_t h, int *code) __attribute__((nonnull(2)));

/* Kernel/user CPU time a process has consumed so far, in 100ns NT ticks
 * -- the only granularity NT offers and the one src/process/wait.c and
 * src/misc/resource.c both already convert from/to a timeval themselves.
 * 0/-1(errno); the outputs are left untouched on failure so a best-
 * effort caller can leave an already-zeroed struct rusage alone (see
 * wait.c's fill_child_rusage()).
 *
 * `job` is the job `h` was placed in at creation time
 * (__plat_process_fork()/__plat_process_spawn()'s own job output,
 * carried in struct __child -- see libc.h), or __PLAT_HANDLE_NULL. When
 * it names a real job, the NT backend reads
 * JobObjectBasicAccountingInformation from IT instead of querying `h`
 * directly: that total already includes every process ever assigned to
 * the job, which -- ordinary job-membership inheritance, not anything
 * this library sets up per generation -- is `h` itself and everything
 * `h` went on to spawn before it exited, i.e. exactly the "recursive"
 * half of times.html's tms_cutime/tms_cstime clause that a bare
 * ProcessTimes query on `h` alone cannot see. __PLAT_HANDLE_NULL falls
 * back to that bare query, same as before this parameter existed
 * (job creation is best-effort, src/misc/resource.c's own job for
 * setrlimit() being the precedent) -- and is what a caller with no `h`
 * to have jobbed in the first place (Linux, which ignores `job`
 * entirely, see this file's own banner) always passes. */
/* ktime100ns/utime100ns required, same "written only on success, but
 * with no NULL check" shape as __plat_process_exit_code()'s own code
 * argument just above. */
int __plat_process_times(__plat_handle_t h, __plat_handle_t job,
                          unsigned long long *ktime100ns, unsigned long long *utime100ns)
    __attribute__((nonnull(3, 4)));

/* Tell the backend that `h`'s exit code and times have now been
 * delivered to the caller -- src/process/wait.c's do_waitpid() calls
 * this exactly once per reap, in its `reap:` block, right after both
 * __plat_process_exit_code() and __plat_process_times() have been read
 * (unconditionally: fill_child_rusage() always runs there, whether or
 * not the caller asked for a struct rusage -- see that file's own
 * comment). Neither of those two is ever called again for the same `h`
 * afterward: a WNOWAIT caller's repeat read comes back from
 * src/internal/libc.h's own struct __child.status/.done instead, one
 * layer up, never by re-querying the backend.
 *
 * On NT this is a no-op: NtQueryInformationProcess can answer
 * ProcessBasicInformation/ProcessTimes any number of times for as long
 * as the handle stays open, and __child_remove()'s __plat_close(c->h)
 * already owns the real release. A backend that instead has to stash
 * that answer itself, because reporting it destroyed the only kernel
 * copy (see this header's own banner on NtWaitForSingleObject vs.
 * wait4(2) -- Linux, src/process/linux/plat_process.c) uses this call as
 * the signal that its own stashed copy may finally be freed. */
void __plat_process_reap_release(__plat_handle_t h);

/* Resume a process this library previously suspended through kill()'s
 * job-control path (src/signal/signal.c, out of this interface's
 * scope). */
int __plat_process_resume(__plat_handle_t h);

/* Start `path` as a new process running argv[]/envp[] -- POSIX-shaped,
 * envp already defaulted to __environ by the caller when the original
 * argument was NULL.  `std[0..2]` are the standard-descriptor handles
 * already resolved by the front door's own fd-table lookup
 * (__fd_get(0..2), close-on-exec excluded -- that bookkeeping is the fd
 * table's, not this interface's, exactly like plat_fd.h's own functions
 * take an already-resolved handle rather than an fd); __PLAT_HANDLE_NULL
 * in a slot means "represent this standard descriptor as closed",
 * never "closed" being expressed as a live handle the backend must
 * infer to hide.
 *
 * Everything else __spawn() used to do inline moves here verbatim: path
 * resolution, the UTF-16 command-line and environment-block encoding
 * (Windows command-line quoting is not a POSIX concept, so a non-NT
 * backend would not do any of this at all), the inheritable-descriptor
 * RuntimeData blob, RTL_USER_PROCESS_PARAMETERS, process creation, the
 * specific-NTSTATUS-to-errno decisions (ENOENT/ENOEXEC) that only make
 * sense with the real status in hand rather than reconstructed from a
 * generic mapping afterward, and resuming the new thread.
 *
 * *out_process receives the new process's handle on success -- NOT yet
 * added to the pid/child table, since that bookkeeping is the front
 * door's, same as __plat_mem_map_file() leaves mman.c's reservation
 * table alone.  *out_job receives the job the new process was placed in
 * before its first instruction ran, or __PLAT_HANDLE_NULL (best-effort,
 * same tolerance as the fork side -- see struct __plat_fork_result's own
 * job field just above and __plat_process_times()'s comment on why this
 * exists).  Returns the new pid, or -1 with errno set.
 *
 * std/out_process/out_job required: both real implementations
 * (linux/plat_process.c, nt/plat_process.c) subscript std[0..2]
 * unconditionally (the child-side fd-redirect loop / the
 * StandardInput/Output/Error assignments) and write `*out_process = ...`/
 * `*out_job = ...` unconditionally on their success path, with no NULL
 * check of either output pointer anywhere. spawn.c's __spawn() is the
 * one real call site: std is always `__plat_handle_t std[3];`, the
 * address of its own local array, and out_process/out_job are always
 * `&process`/`&job`, the address of their own locals -- none of the
 * three is ever NULL. path/argv/envp are NOT marked here: this function
 * never dereferences any of them directly itself, only forwards them
 * into functions that already carry their own contracts
 * (build_cmdline()'s own argv, __utf8_to_utf16()'s own path, both
 * required there; build_env_block()'s own envp, deliberately optional
 * there via its own `for (i = 0; envp && envp[i]; ...)` check, matching
 * __spawn()'s own `envp ? envp : __environ` one level up). */
int __plat_process_spawn(const char *path, char *const argv[], char *const envp[],
                          const __plat_handle_t std[3], __plat_handle_t *out_process,
                          __plat_handle_t *out_job)
    __attribute__((nonnull(4, 5, 6)));

/* execve(2), for src/process/exec.c's own execve() ONLY on the one
 * backend that has a real image-replacement primitive to call: Linux.
 * NT's whole reason for this interface's fork()-shaped members above is
 * that no NT call replaces a running process's image in place (see
 * exec.c's own banner) -- so unlike every other function in this file,
 * this one is declared here for symmetry but implemented ONLY by
 * src/process/linux/plat_process.c; the NT backend defines nothing
 * named this, and exec.c's own #if defined(__linux__) around every call
 * to it is what keeps that from ever becoming an undefined-symbol link
 * error on a build that has no definition to offer.
 *
 * Returns only on failure (-1, errno set), the same shape as the raw
 * execve(2) it wraps: a successful call replaces this very process's
 * image and never returns to its caller at all. */
int __plat_process_exec(const char *path, char *const argv[], char *const envp[]);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
