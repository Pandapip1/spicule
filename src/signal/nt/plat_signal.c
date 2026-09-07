/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of src/internal/plat_signal.h -- see that header
 * for the contract each function makes and for why several of them
 * necessarily take a raw UNICODE_STRING*.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <errno.h>
#include <signal.h>
#include <string.h>
#include "libc.h"
#include "plat_signal.h"

__plat_handle_t __plat_sigevent_create(int initially_signalled)
{
	OBJECT_ATTRIBUTES oa;
	HANDLE ev;

	InitializeObjectAttributes(&oa, 0, 0, 0, 0);
	if (!NT_SUCCESS(NtCreateEvent(&ev, EVENT_ALL_ACCESS, &oa, SynchronizationEvent,
	                              initially_signalled ? TRUE : FALSE)))
		return __PLAT_HANDLE_NULL;
	return ev;
}

/* __plat_event_set() is declared in this file's header but defined in
 * src/thread/nt/plat_thread.c alongside the other generic sync primitives,
 * to avoid a duplicate ODR definition. */

void __plat_signal_wait(__plat_handle_t wake_event, int has_timeout, long long ticks) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	LARGE_INTEGER t;

	if (wake_event) {
		if (has_timeout) { t = ticks; NtWaitForSingleObject(wake_event, TRUE, &t); }
		else NtWaitForSingleObject(wake_event, TRUE, 0);
		return;
	}
	if (has_timeout) { t = ticks; NtDelayExecution(TRUE, &t); return; }
	{
		LARGE_INTEGER fallback = -1000000; /* 100 ms */
		NtDelayExecution(TRUE, &fallback);
	}
}

__plat_handle_t __plat_signal_pipe_create(const UNICODE_STRING *name)
{
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK io;
	LARGE_INTEGER timeout = -1200000000LL;
	HANDLE pipe;
	NTSTATUS st;

	InitializeObjectAttributes(&oa, (UNICODE_STRING *)name, OBJ_CASE_INSENSITIVE, 0, 0);
	st = NtCreateNamedPipeFile(&pipe,
		GENERIC_READ | GENERIC_WRITE | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
		&oa, &io, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT, FILE_PIPE_MESSAGE_TYPE,
		FILE_PIPE_MESSAGE_MODE, FILE_PIPE_QUEUE_OPERATION, 2, 4096, 4096,
		&timeout);
	return NT_SUCCESS(st) ? pipe : __PLAT_HANDLE_NULL;
}

int __plat_signal_pipe_listen(__plat_handle_t pipe)
{
	IO_STATUS_BLOCK io;
	NTSTATUS st = NtFsControlFile(pipe, 0, 0, 0, &io, FSCTL_PIPE_LISTEN, 0, 0, 0, 0);
	if (st == STATUS_PENDING) { NtWaitForSingleObject(pipe, 0, 0); st = io.Status; }
	/* A sender may already have connected before this thread reaches LISTEN. */
	if (st == STATUS_PIPE_CONNECTED) st = STATUS_SUCCESS;
	return NT_SUCCESS(st);
}

int __plat_signal_pipe_read(__plat_handle_t h, void *buf, size_t len, size_t *received)
{
	IO_STATUS_BLOCK io;
	NTSTATUS st = NtReadFile(h, 0, 0, 0, &io, buf, (ULONG)len, 0, 0);
	if (st == STATUS_PENDING) { NtWaitForSingleObject(h, 0, 0); st = io.Status; }
	if (!NT_SUCCESS(st)) return -1;
	*received = (size_t)io.Information;
	return 0;
}

int __plat_signal_pipe_write(__plat_handle_t h, const void *buf, size_t len, size_t *sent)
{
	IO_STATUS_BLOCK io;
	NTSTATUS st = NtWriteFile(h, 0, 0, 0, &io, buf, (ULONG)len, 0, 0);
	if (st == STATUS_PENDING) { NtWaitForSingleObject(h, 0, 0); st = io.Status; }
	if (!NT_SUCCESS(st)) return -1;
	*sent = (size_t)io.Information;
	return 0;
}

void __plat_signal_backoff(void)
{
	LARGE_INTEGER d = -1000000; /* 100ms, src/unistd/sleep.c's own idiom */
	NtDelayExecution(0, &d);
}

__plat_handle_t __plat_signal_mutant_create(const UNICODE_STRING *name)
{
	OBJECT_ATTRIBUTES oa;
	HANDLE mutant;
	NTSTATUS st;

	InitializeObjectAttributes(&oa, (UNICODE_STRING *)name, OBJ_CASE_INSENSITIVE | OBJ_OPENIF, 0, 0);
	st = NtCreateMutant(&mutant, MUTANT_ALL_ACCESS, &oa, FALSE);
	return NT_SUCCESS(st) ? mutant : __PLAT_HANDLE_NULL;
}

int __plat_wait_acquire(__plat_handle_t h)
{
	NTSTATUS st = NtWaitForSingleObject(h, 0, 0);
	return NT_SUCCESS(st);
}

void __plat_mutant_release(__plat_handle_t h)
{
	NtReleaseMutant(h, 0);
}

int __plat_event_peek(__plat_handle_t ev)
{
	LARGE_INTEGER zero = 0;
	return NtWaitForSingleObject(ev, 0, &zero) == STATUS_SUCCESS;
}

__plat_handle_t __plat_signal_pipe_open(const UNICODE_STRING *name)
{
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK io;
	HANDLE h;
	NTSTATUS st;

	InitializeObjectAttributes(&oa, (UNICODE_STRING *)name, OBJ_CASE_INSENSITIVE, 0, 0);
	st = NtOpenFile(&h, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &oa, &io,
	                FILE_SHARE_READ | FILE_SHARE_WRITE,
	                FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
	return NT_SUCCESS(st) ? h : __PLAT_HANDLE_NULL;
}

int __plat_thread_start(void *entry, void *arg, __plat_handle_t *out)
{
	HANDLE thr;
	NTSTATUS st = NtCreateThreadEx(&thr, THREAD_ALL_ACCESS, 0, NtCurrentProcess(),
	                               entry, arg, 0, 0, 0, 0, 0);
	if (!NT_SUCCESS(st)) return -1;
	*out = thr;
	return 0;
}

__plat_handle_t __plat_stop_event_create(const UNICODE_STRING *name)
{
	OBJECT_ATTRIBUTES oa;
	HANDLE h;
	NTSTATUS st;

	InitializeObjectAttributes(&oa, (UNICODE_STRING *)name, OBJ_CASE_INSENSITIVE | OBJ_OPENIF, 0, 0);
	st = NtCreateEvent(&h, EVENT_ALL_ACCESS, &oa, SynchronizationEvent, FALSE);
	if (!NT_SUCCESS(st)) { __set_errno_status(st); return __PLAT_HANDLE_NULL; }
	return h;
}

int __plat_stop_event_probe(const UNICODE_STRING *name, __plat_handle_t *out, int *already_existed)
{
	OBJECT_ATTRIBUTES oa;
	HANDLE h;
	NTSTATUS st;

	InitializeObjectAttributes(&oa, (UNICODE_STRING *)name, OBJ_CASE_INSENSITIVE | OBJ_OPENIF, 0, 0);
	st = NtCreateEvent(&h, EVENT_ALL_ACCESS, &oa, SynchronizationEvent, FALSE);
	if (!NT_SUCCESS(st)) return -1;
	*out = h;
	*already_existed = (st == (NTSTATUS)STATUS_OBJECT_NAME_EXISTS);
	return 0;
}

int __plat_process_suspend_self(void)
{
	NTSTATUS st = NtSuspendProcess(NtCurrentProcess());
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_process_suspend(__plat_handle_t h)
{
	NTSTATUS st = NtSuspendProcess(h);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

/* __plat_process_resume() is declared in this file's header but defined in
 * src/process/nt/plat_process.c alongside the rest of process lifecycle, to
 * avoid a duplicate ODR definition. */

int __plat_kill_open(pid_t pid, int want_suspend_resume, __plat_handle_t *out) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	OBJECT_ATTRIBUTES oa;
	CLIENT_ID cid;
	ACCESS_MASK want = PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION;
	HANDLE h;
	NTSTATUS st;

	if (want_suspend_resume) want |= PROCESS_SUSPEND_RESUME;
	InitializeObjectAttributes(&oa, 0, 0, 0, 0);
	cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
	cid.UniqueThread = 0;
	st = NtOpenProcess(&h, want, &oa, &cid);
	if (!NT_SUCCESS(st)) {
		errno = st == (NTSTATUS)STATUS_ACCESS_DENIED ? EPERM : ESRCH;
		return -1;
	}
	*out = h;
	return 0;
}

int __plat_kill_terminate(__plat_handle_t h, int exitcode)
{
	NTSTATUS st = NtTerminateProcess(h, exitcode);
	if (!NT_SUCCESS(st) && st != (NTSTATUS)STATUS_PROCESS_IS_TERMINATING)
		return __set_errno_status(st);
	return 0;
}

int __plat_segv_code(void *addr)
{
	MEMORY_BASIC_INFORMATION mbi;
	SIZE_T ret = 0;
	NTSTATUS st;

	memset(&mbi, 0, sizeof mbi);
	st = NtQueryVirtualMemory(NtCurrentProcess(), addr, MemoryBasicInformation, &mbi, sizeof mbi, &ret);
	if (!NT_SUCCESS(st)) return SEGV_MAPERR;
	return mbi.State == MEM_COMMIT ? SEGV_ACCERR : SEGV_MAPERR;
}

/* No real kernel signal disposition exists on NT to synchronize with: every
 * signal reaching __raise_internal() was already synthesized by this
 * library, and each call site already reads handlers[] itself. */
void __plat_sig_sync_kernel(int sig, int ignore)
{
	(void)sig; (void)ignore;
}

/* NT has no real kernel signal to raise, so __exit_internal() always falls
 * through to its own __ENCODE_SIGNAL_EXIT() simulation. */
void __plat_sig_default_terminate(int sig)
{
	(void)sig;
}

/* No catchable cross-process signal exists on NT; children.c's clear_stops()
 * uses this to skip SIGHUP rather than destroy a child that may have caught it. */
int __plat_sig_deliverable_to_other_process(void)
{
	return 0;
}

// NOLINTEND(misc-include-cleaner)
