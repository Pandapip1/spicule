/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of src/internal/plat_process.h -- see that header for
 * the contract each function makes.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "libc.h"
#include "plat_process.h"
#include "plat_misc.h"

/* ---- find_program.c: is this file something NT's loader can start? --- */

/* See plat_process.h's own comment on this function, and
 * src/process/find_program.c's file banner for the full accounting of
 * why a content sniff is the right tool and why FILE_OPEN_NO_RECALL and
 * the two RECALL_ON_* checks matter (a cloud-backed placeholder must not
 * be woken merely to look at its first two bytes). */
int __plat_is_program(const char *path)
{
	struct __ntpath np;
	IO_STATUS_BLOCK io;
	FILE_BASIC_INFORMATION bi;
	LARGE_INTEGER off = 0;
	HANDLE h;
	NTSTATUS s;
	unsigned char b[4];

	if (__ntpath_at(AT_FDCWD, path, &np, OBJ_CASE_INSENSITIVE) < 0) return 0;
	s = NtOpenFile(&h, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &np.oa, &io,
	               FILE_SHARE_VALID_FLAGS,
	               FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_OPEN_NO_RECALL);
	__ntpath_free(&np);
	if (!NT_SUCCESS(s)) return 0;

	/* Offline or not-yet-hydrated: do not touch the data. */
	if (NT_SUCCESS(NtQueryInformationFile(h, &io, &bi, sizeof bi, FileBasicInformation)) &&
	    (bi.FileAttributes & (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN |
	                          FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS))) {
		NtClose(h);
		return 0;
	}

	io.Information = 0;
	s = NtReadFile(h, 0, 0, 0, &io, b, sizeof b, &off, 0);
	NtClose(h);
	if (!NT_SUCCESS(s) || io.Information < 2) return 0;
	if ((b[0] == 'M' && b[1] == 'Z') || (b[0] == '#' && b[1] == '!')) return 1;
#ifdef _NTLIBC_NATIVE_BUILD
	/* The sanitizer shim starts copied test images as their native ELF
	 * host binary.  Treat that native image signature exactly as the NT
	 * build treats MZ; this branch cannot enter a PE build. */
	if (io.Information >= 4 && b[0] == 0x7f && b[1] == 'E' &&
	    b[2] == 'L' && b[3] == 'F') return 1;
#endif
	return 0;
}

/* A fresh job for one newly-created (still-suspended) child. Job-membership
 * inheritance means every process this child goes on to spawn, at any
 * depth, automatically becomes a member of the same job, so querying it
 * after the child is reaped already accounts for the child's own CPU time
 * plus everything it spawned -- the recursive half of times.html's
 * tms_cutime/tms_cstime clause.
 *
 * Best-effort: __PLAT_HANDLE_NULL on any failure degrades
 * __plat_process_times() back to a bare per-process ProcessTimes query,
 * never a spawn/fork failure. */
static HANDLE create_child_job(HANDLE process)
{
	OBJECT_ATTRIBUTES oa;
	HANDLE job;

	InitializeObjectAttributes(&oa, 0, 0, 0, 0);
	if (!NT_SUCCESS(NtCreateJobObject(&job, JOB_OBJECT_ALL_ACCESS, &oa)))
		return 0;
	if (!NT_SUCCESS(NtAssignProcessToJobObject(job, process))) {
		NtClose(job);
		return 0;
	}
	return job;
}

/* ---- fork.c: RtlCloneUserProcess and NtResumeThread ------------------- */

int __plat_process_fork(struct __plat_fork_result *out)
{
	RTL_USER_PROCESS_INFORMATION info;
	NTSTATUS st;

	memset(&info, 0, sizeof info);
	info.Length = sizeof info;

	st = RtlCloneUserProcess(RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED | RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES,
	                         0, 0, 0, &info);

	/* STATUS_PROCESS_CLONED is a SUCCESS-severity status distinct from
	 * STATUS_SUCCESS -- the only way RtlCloneUserProcess tells its two
	 * returns apart -- so this has to be tested before NT_SUCCESS(st)
	 * folds it into "success" along with the parent's own STATUS_SUCCESS.
	 * See plat_process.h's banner for why no caller outside this function
	 * can make this decision. */
	if (st == STATUS_PROCESS_CLONED) return __PLAT_FORK_CHILD;
	if (!NT_SUCCESS(st)) return __set_errno_status(st);

	out->process = info.Process;
	out->thread = info.Thread;
	/* Still suspended (CREATE_SUSPENDED above): this is the window
	 * create_child_job()'s own comment describes, before fork.c ever
	 * calls __plat_thread_resume() on out->thread. */
	out->job = create_child_job(info.Process);
	out->pid = (int)(ULONG_PTR)info.ClientId.UniqueProcess;
	return __PLAT_FORK_PARENT;
}

int __plat_thread_resume(__plat_handle_t th)
{
	NTSTATUS st = NtResumeThread(th, 0);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

/* ---- wait.c: NtWaitForSingleObject / NtQueryInformationProcess -------- */

int __plat_process_wait(__plat_handle_t h, int mode)
{
	LARGE_INTEGER timeout;
	LARGE_INTEGER *tp;
	NTSTATUS st;

	switch (mode) {
	case __PLAT_WAIT_NOHANG: timeout = 0; tp = &timeout; break;
	/* 10ms: self-stop markers are not handles in the wait set, so a
	 * WUNTRACED caller has to keep re-checking for one rather than
	 * blocking past it. */
	case __PLAT_WAIT_POLL:   timeout = -100000; tp = &timeout; break;
	default:                 tp = 0; break;
	}
	st = NtWaitForSingleObject(h, 0, tp);
	if (st == STATUS_TIMEOUT) return 0;
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 1;
}

int __plat_process_exit_code(__plat_handle_t h, int *code)
{
	PROCESS_BASIC_INFORMATION pbi;
	NTSTATUS st = NtQueryInformationProcess(h, ProcessBasicInformation, &pbi, sizeof pbi, 0);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	*code = (int)pbi.ExitStatus;
	return 0;
}

int __plat_process_times(__plat_handle_t h, __plat_handle_t job,
                          unsigned long long *ktime100ns, unsigned long long *utime100ns)
{
	KERNEL_USER_TIMES kt;
	NTSTATUS st;

	/* job's own comment (plat_process.h) and create_child_job()'s
	 * (above) explain why this total already includes `h`'s own CPU
	 * time -- `h` is itself a member of `job` -- plus everything `h`
	 * spawned before it exited, which a bare ProcessTimes query on `h`
	 * alone cannot see at all. Tried first, not merged with the
	 * ProcessTimes query below: the job's own accounting already
	 * subsumes `h`'s, so adding both would double-count `h`'s own
	 * share. */
	if (job) {
		JOBOBJECT_BASIC_ACCOUNTING_INFORMATION jai;
		st = NtQueryInformationJobObject(job, JobObjectBasicAccountingInformation,
		                                 &jai, sizeof jai, 0);
		if (NT_SUCCESS(st)) {
			*ktime100ns = (unsigned long long)jai.TotalKernelTime;
			*utime100ns = (unsigned long long)jai.TotalUserTime;
			return 0;
		}
	}

	st = NtQueryInformationProcess(h, ProcessTimes, &kt, sizeof kt, 0);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	*ktime100ns = (unsigned long long)kt.KernelTime;
	*utime100ns = (unsigned long long)kt.UserTime;
	return 0;
}

/* No-op here: see plat_process.h's own comment on this call for why --
 * this backend has nothing to release. `h` stays queryable until
 * __child_remove()'s __plat_close(h) closes it, independent of whether
 * wait.c has read this reap's exit code/times yet. */
void __plat_process_reap_release(__plat_handle_t h)
{
	(void)h;
}

int __plat_process_resume(__plat_handle_t h)
{
	NTSTATUS st = NtResumeProcess(h);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

/* ---- spawn.c: the command line, the environment block, and the ------- */
/* ---- create-process sequence itself ----------------------------------- */

/* Append one argument to a UTF-16 command-line buffer, quoting it if it
 * contains whitespace, a quote, or is empty. */
/* buf/len/cap/arg all required: *cap and *len are read unconditionally
 * (via __array_next_capacity(*cap, *len, ...)) before anything else,
 * and arg[0] is read in the very first statement. Every real call site
 * (build_cmdline()) passes local stack variables' addresses for
 * buf/len/cap, never NULL. */
static int append_arg(WCHAR **buf, size_t *len, size_t *cap, const WCHAR *arg)
    __attribute__((nonnull(1, 2, 3, 4)));
static int append_arg(WCHAR **buf, size_t *len, size_t *cap, const WCHAR *arg)
{
	size_t n = 0, i, extra, nc;
	int need_quote = arg[0] == 0;
	for (i = 0; arg[i]; i++) if (arg[i] == ' ' || arg[i] == '\t' || arg[i] == '"' || arg[i] == '\n' || arg[i] == '\v') need_quote = 1;
	n = i;
	/* worst case: quotes + every char doubled (backslashes) + a space */
	if (!__size_mul_checked(n, 2, &extra) ||
	    !__size_add_checked(extra, 4, &extra) ||
	    !__array_next_capacity(*cap, *len, extra, 32, sizeof(WCHAR), &nc)) {
		errno = E2BIG;
		return -1;
	}
	if (nc != *cap) {
		size_t ncbytes = nc * sizeof(WCHAR); /* proven <= SIZE_MAX by __array_next_capacity's own element_size bound above */
		WCHAR *nb = realloc(*buf, ncbytes);
		if (!nb) { errno = ENOMEM; return -1; }
		*buf = nb; *cap = nc;
	}
	if (*len) (*buf)[(*len)++] = ' ';
	if (!need_quote) {
		for (i = 0; i < n; i++) (*buf)[*len + i] = arg[i];
		*len += n;
		return 0;
	}
	(*buf)[(*len)++] = '"';
	for (i = 0; i < n; i++) {
		size_t nb = 0;
		while (i < n && arg[i] == '\\') { nb++; i++; }
		if (i == n) {
			size_t k; for (k = 0; k < nb * 2; k++) (*buf)[(*len)++] = '\\';
			break;
		} else if (arg[i] == '"') {
			size_t k; for (k = 0; k < nb * 2 + 1; k++) (*buf)[(*len)++] = '\\';
			(*buf)[(*len)++] = arg[i];
		} else {
			size_t k; for (k = 0; k < nb; k++) (*buf)[(*len)++] = '\\';
			(*buf)[(*len)++] = arg[i];
		}
	}
	(*buf)[(*len)++] = '"';
	return 0;
}

/* Append argv[0].  The program name is *not* read back by the rules
 * append_arg encodes for: every parser -- Wine's CommandLineToArgvW,
 * the Microsoft C runtimes, and this library's own crt1.c
 * split_cmdline -- treats it specially.  Backslashes in it are always
 * literal and never escape anything; a quote only turns the
 * "whitespace is literal" state on and off and is otherwise dropped.
 * See src/process/spawn.c's file banner (moved from here) for the full
 * accounting; the encoding itself is unchanged. */
/* Same requirement shape as append_arg() just above. */
static int append_prog(WCHAR **buf, size_t *len, size_t *cap, const WCHAR *arg)
    __attribute__((nonnull(1, 2, 3, 4)));
static int append_prog(WCHAR **buf, size_t *len, size_t *cap, const WCHAR *arg)
{
	size_t n, i, extra, nc;
	int need_quote = arg[0] == 0;
	for (i = 0; arg[i]; i++) {
		if (arg[i] == '"') { errno = EINVAL; return -1; }
		if (arg[i] == ' ' || arg[i] == '\t') need_quote = 1;
	}
	n = i;
	if (!__size_add_checked(n, 4, &extra) ||
	    !__array_next_capacity(*cap, *len, extra, 32, sizeof(WCHAR), &nc)) {
		errno = E2BIG;
		return -1;
	}
	if (nc != *cap) {
		size_t ncbytes = nc * sizeof(WCHAR); /* proven <= SIZE_MAX by __array_next_capacity's own element_size bound above */
		WCHAR *nb = realloc(*buf, ncbytes);
		if (!nb) { errno = ENOMEM; return -1; }
		*buf = nb; *cap = nc;
	}
	/* The growth helper guarantees allocation from the initial zero-capacity
	 * state. Keep that invariant explicit at the use site as a defensive
	 * fallback if its contract ever changes. */
	if (!*buf) { errno = ENOMEM; return -1; }
	if (need_quote) (*buf)[(*len)++] = '"';
	for (i = 0; i < n; i++) (*buf)[*len + i] = arg[i];
	*len += n;
	if (need_quote) (*buf)[(*len)++] = '"';
	return 0;
}

/* argv required: subscripted unconditionally (`argv[i]`) at loop
 * entry, matching every execve-family argv contract this tree already
 * treats as required elsewhere. */
withtok(heap_allocated) __attribute__((nonnull(1)))
static WCHAR *build_cmdline(char *const argv[]);
withtok(heap_allocated) __attribute__((nonnull(1)))
static WCHAR *build_cmdline(char *const argv[])
{
	WCHAR *buf = 0;
	size_t len = 0, cap = 0;
	size_t i;
	for (i = 0; argv[i]; i++) {
		size_t wl;
		WCHAR *w = __utf8_to_utf16(argv[i], &wl);
		int rc;
		if (!w) { errno = ENOMEM; free(buf); return 0; }
		rc = i ? append_arg(&buf, &len, &cap, w) : append_prog(&buf, &len, &cap, w);
		__free(w);
		if (rc < 0) { free(buf); return 0; }   /* errno set by the appender */
	}
	if (!buf) {
		buf = malloc(sizeof(WCHAR));
		if (!buf) { errno = ENOMEM; return 0; }
		buf[0] = 0;
		return buf;
	}
	buf[len] = 0;
	return buf;
}

/* The environment as one UTF-16 block of NAME=VALUE\0 ... \0\0.  See
 * src/process/spawn.c's file banner (moved from here) for why a
 * zero-length entry and an entry with no '=' are both dropped rather
 * than passed on, and why a leading '=' (Windows' own per-drive
 * current-directory shape) is kept. */
withtok(heap_allocated)
static WCHAR *build_env_block(char *const envp[])
{
	size_t cap = 256, len = 0, capbytes = cap * sizeof(WCHAR);
	WCHAR *blk = malloc(capbytes);
	int i;
	if (!blk) return 0;
	for (i = 0; envp && envp[i]; i++) {
		size_t wl, extra, nc;
		WCHAR *w;
		if (!envp[i][0] || !strchr(envp[i], '=')) continue;
		w = __utf8_to_utf16(envp[i], &wl);
		if (!w) { free(blk); return 0; }
		if (!__size_add_checked(wl, 2, &extra) ||
		    !__array_next_capacity(cap, len, extra, 256, sizeof(WCHAR), &nc)) {
			__free(w);
			free(blk);
			errno = E2BIG;
			return 0;
		}
		if (nc != cap) {
			WCHAR *nb;
			size_t ncbytes = nc * sizeof(WCHAR); /* proven <= SIZE_MAX by __array_next_capacity's own element_size bound above */
			nb = realloc(blk, ncbytes);
			if (!nb) { __free(w); free(blk); return 0; }
			blk = nb;
			cap = nc;
		}
		{
			size_t j;
			for (j = 0; j < wl; j++) blk[len + j] = w[j];
		}
		len += wl;
		blk[len++] = 0;
		__free(w);
	}
	blk[len++] = 0;   /* terminating empty string */
	return blk;
}

/* Hands back a real, valid, inheritable, non-NULL, non-pseudo HANDLE to
 * stand in for a *closed* standard descriptor -- see src/process/spawn.c's
 * file banner for why plain 0 and (HANDLE)(LONG_PTR)-1 both fail to come
 * up closed in the child on real Windows. *out receives this process's own
 * copy, which the caller must NtClose() once RtlCreateUserProcess is done
 * with the parameter block. Deliberately does not disturb errno on
 * failure: it would only be clobbered by RtlCreateUserProcess next. */
/* out required: `*out = ...;` is written unconditionally at the end,
 * on every call (this function has no early-return path). */
static HANDLE closed_placeholder(HANDLE *out) __attribute__((nonnull(1)));
static HANDLE closed_placeholder(HANDLE *out)
{
	HANDLE h = 0;
	NTSTATUS st = NtDuplicateObject(NtCurrentProcess(), NtCurrentProcess(), NtCurrentProcess(),
	                                &h, 0, OBJ_INHERIT, DUPLICATE_SAME_ACCESS);
	*out = NT_SUCCESS(st) ? h : 0;
	return *out;
}

int __plat_process_spawn(const char *path, char *const argv[], char *const envp[], // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
                         const __plat_handle_t std[3], __plat_handle_t *out_process,
                         __plat_handle_t *out_job)
{
	struct __ntpath np;
	__plat_handle_t inherited_std[3] = { std[0], std[1], std[2] };
	RTL_USER_PROCESS_PARAMETERS *pp = 0;
	RTL_USER_PROCESS_INFORMATION info;
	UNICODE_STRING imageDos, cmdLine, cur, runtimeUS;
	WCHAR *wcmd = 0, *wenv = 0, *wimage = 0;
	WCHAR curbuf[4096];
	void *runtime = 0;
	size_t runtime_len = 0;
	HANDLE ph[3] = { 0, 0, 0 };
	NTSTATUS st;
	int pid = -1, i;
	ULONG curlen;
	size_t cmdlen;

	if (__ntpath(path, &np, OBJ_CASE_INSENSITIVE) < 0) return -1;

	wimage = __utf8_to_utf16(path, 0);
	if (!wimage) { errno = ENOMEM; goto out; }
	{ size_t k; for (k = 0; wimage[k]; k++) if (wimage[k] == '/') wimage[k] = '\\'; }
	wcmd = build_cmdline(argv);
	if (!wcmd) goto out;   /* errno set by build_cmdline */
	wenv = build_env_block(envp);
	if (!wenv) goto out;   /* errno set by build_env_block */

	/* Everything below goes into a UNICODE_STRING, whose Length is a
	 * USHORT counting *bytes*.  A longer string does not truncate, it
	 * wraps: the child would be handed a random prefix of its own
	 * command line and split that.  So each length is checked against
	 * what the field can hold before it is narrowed. */
	cmdlen = wcslen_(wcmd);
	if (cmdlen > __US_MAX_WCHARS) { errno = E2BIG; goto out; }

	RtlInitUnicodeString(&imageDos, wimage);
	cmdLine.Buffer = wcmd;
	cmdLine.Length = (USHORT)(cmdlen * sizeof(WCHAR));
	cmdLine.MaximumLength = (USHORT)(cmdLine.Length + sizeof(WCHAR));
	curlen = RtlGetCurrentDirectory_U(sizeof curbuf, curbuf);
	/* RtlGetCurrentDirectory_U reports the size it needed when the buffer
	 * was too small, so a long enough directory would leave curlen past
	 * the end of curbuf as well as past a USHORT. */
	if (curlen > sizeof curbuf - sizeof(WCHAR)) { errno = ENAMETOOLONG; goto out; }
	cur.Buffer = curbuf;
	cur.Length = (USHORT)curlen;
	cur.MaximumLength = sizeof curbuf;

	/* The inheritable descriptor table, built *before* the parameters
	 * block so it can be handed to RtlCreateProcessParametersEx as the
	 * RuntimeInfo argument and packed INTO the block, the same way
	 * cmdLine, cur and wenv are.  See src/process/spawn.c's file banner
	 * (moved from here) for why a field set *after* creation to point
	 * outside the block is not safe -- the intermittent parent-address
	 * bug that used to be. */
	runtime = __fd_runtime_data(&runtime_len, inherited_std);
	runtimeUS.Buffer = (PWSTR)runtime;
	runtimeUS.Length = (USHORT)runtime_len;
	runtimeUS.MaximumLength = (USHORT)runtime_len;

	st = RtlCreateProcessParametersEx(&pp, &imageDos, 0, &cur, &cmdLine, wenv, 0, 0, 0,
	                                  runtime ? &runtimeUS : 0,
	                                  RTL_USER_PROC_PARAMS_NORMALIZED);
	if (!NT_SUCCESS(st)) { __set_errno_status(st); goto out; }

	/* Standard handles: HANDLE values stored by *value* in the block,
	 * unlike RuntimeData above -- see src/process/spawn.c's file banner
	 * for the measurements behind closed_placeholder() and why a
	 * close-on-exec standard descriptor never reaches here (the front
	 * door already turned it into __PLAT_HANDLE_NULL before calling
	 * this).  RuntimeData construction can replace a descriptor's handle
	 * while making it inheritable; inherited_std tracks those replacements
	 * so these by-value fields always receive the live handle.
	 *
	 * pp->StandardInput: not expressible via nonnull -- pp is a LOCAL
	 * (`RTL_USER_PROCESS_PARAMETERS *pp = 0;` above), not a parameter of
	 * __plat_process_spawn(), and is already dereferenced safely at this
	 * point only because RtlCreateProcessParametersEx() just succeeded
	 * (the `if (!NT_SUCCESS(st)) {...goto out;}` immediately above sets
	 * *pp on success, per RtlCreateProcessParametersEx's own contract) --
	 * a fact this function's own signature has no way to restate. */
	pp->StandardInput = inherited_std[0] ? inherited_std[0] : closed_placeholder(&ph[0]);
	pp->StandardOutput = inherited_std[1] ? inherited_std[1] : closed_placeholder(&ph[1]);
	pp->StandardError = inherited_std[2] ? inherited_std[2] : closed_placeholder(&ph[2]);
	pp->WindowFlags |= STARTF_USESTDHANDLES;

	memset(&info, 0, sizeof info);
	info.Length = sizeof info;
	st = RtlCreateUserProcess(&np.nt, OBJ_CASE_INSENSITIVE, pp, 0, 0, 0, TRUE, 0, 0, &info);
	/* Whatever closed_placeholder() duplicated was only ever needed to
	 * get a real, non-NULL handle value into *this* process's copy of
	 * the parameter block for RtlCreateUserProcess to copy onward -- this
	 * process's own reference is never used for anything and must not
	 * linger as an inheritable handle for the *next* spawn to pick up by
	 * accident. */
	for (i = 0; i < 3; i++) if (ph[i]) NtClose(ph[i]);
	if (!NT_SUCCESS(st)) {
		/* Decided here, with the real status in hand: a generic
		 * status-to-errno mapping has no vocabulary for "this
		 * particular failure means the child could not be started
		 * because the file is not a valid image" versus any other
		 * reason NtCreateSection(SEC_IMAGE) can fail, and execvp()'s
		 * shell-fallback clause (src/process/exec.c) depends on
		 * telling ENOEXEC apart from every other spawn failure. */
		if (st == STATUS_OBJECT_NAME_NOT_FOUND || st == STATUS_OBJECT_PATH_NOT_FOUND) errno = ENOENT;
		else if (st == STATUS_INVALID_IMAGE_FORMAT || st == STATUS_INVALID_IMAGE_NOT_MZ ||
		         st == STATUS_INVALID_FILE_FOR_SECTION) errno = ENOEXEC;
		else __set_errno_status(st);
		goto out;
	}

	/* Still suspended (RtlCreateUserProcess always hands the initial
	 * thread back that way): create_child_job()'s own comment explains
	 * why this has to happen in this window, before the resume just
	 * below ever lets the child run an instruction. */
	*out_job = create_child_job(info.Process);
	/* src/process/posix_spawn.c's POSIX_SPAWN_SETSCHEDPARAM/
	 * POSIX_SPAWN_SETSCHEDULER, same window, same reason: this is the
	 * last point this library ever has a handle to the child before it
	 * runs its own first instruction. __spawn_pending_priority()'s own
	 * comment (libc.h) explains why this call needs no cross-process
	 * channel the way the sigmask trailer just below does -- best-
	 * effort, like every other caller of __plat_priority_set()
	 * (src/misc/resource.c's own setpriority()): a target this process
	 * has no privilege to raise simply keeps its default priority, and
	 * that failure is not this spawn's to report. */
	{
		int nice_value;
		if (__spawn_pending_priority(&nice_value))
			__plat_priority_set(info.Process, 0, nice_value);
	}
	NtResumeThread(info.Thread, 0);
	NtClose(info.Thread);
	pid = (int)(ULONG_PTR)info.ClientId.UniqueProcess;
	*out_process = info.Process;

out:
	if (pp) RtlDestroyProcessParameters(pp);
	__ntpath_free(&np);
	if (wimage) __free(wimage);
	if (wcmd) free(wcmd);
	if (wenv) free(wenv);
	if (runtime) __free(runtime);
	return pid;
}

// NOLINTEND(misc-include-cleaner)
