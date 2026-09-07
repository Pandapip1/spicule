/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of src/internal/plat_fd.h -- see that header for
 * the contract each function makes.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include "libc.h"
#include "plat_fd.h"
#include "conin.h"

int __plat_close(__plat_handle_t h)
{
	NTSTATUS st = NtClose(h);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

ssize_t __plat_read(__plat_handle_t h, void *buf, size_t count)
{
	IO_STATUS_BLOCK io;
	NTSTATUS st;

	/* A console whose line discipline this library runs has exactly one
	 * NtReadFile caller -- the thread in src/internal/nt/conin.c -- and
	 * every other reader takes bytes from its queue instead. */
	if (__conin_owns(h)) return __conin_read(buf, count);

	io.Status = 0; io.Information = 0;
	st = NtReadFile(h, 0, 0, 0, &io, buf, (ULONG)count, 0, 0);
	if (st == STATUS_PENDING) {
		/* The handle was not opened synchronous (inherited from a
		 * parent that opened it overlapped, say): wait for it. */
		NtWaitForSingleObject(h, 0, 0);
		st = io.Status;
	}
	if (st == STATUS_END_OF_FILE || st == STATUS_PIPE_BROKEN || st == STATUS_PIPE_DISCONNECTED) return 0;
	if (st == STATUS_PIPE_EMPTY) { errno = EAGAIN; return -1; }
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return (ssize_t)io.Information;
}

ssize_t __plat_pread(__plat_handle_t h, void *buf, size_t count, off_t off) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	IO_STATUS_BLOCK io;
	LARGE_INTEGER pos = off;
	NTSTATUS st;

	io.Information = 0;
	st = NtReadFile(h, 0, 0, 0, &io, buf, (ULONG)count, &pos, 0);
	if (st == STATUS_PENDING) { NtWaitForSingleObject(h, 0, 0); st = io.Status; }
	if (st == STATUS_END_OF_FILE) return 0;
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return (ssize_t)io.Information;
}

/* write.html [EFBIG]: checked on the FAILURE path, not before the write,
 * to avoid an unconditional NtQueryInformationFile round trip on the
 * hottest path in the library for a condition no successful write can
 * ever satisfy. A query that cannot be answered reports 0, so the caller
 * gets NT's own status translated normally. */
static int start_at_offset_max(__plat_handle_t h, int append)
{
	IO_STATUS_BLOCK io;

	if (append) {
		FILE_STANDARD_INFORMATION si;
		if (!NT_SUCCESS(NtQueryInformationFile(h, &io, &si, sizeof si, FileStandardInformation)))
			return 0;
		return si.EndOfFile >= __OFF_MAX;
	} else {
		FILE_POSITION_INFORMATION pi;
		if (!NT_SUCCESS(NtQueryInformationFile(h, &io, &pi, sizeof pi, FilePositionInformation)))
			return 0;
		return pi.CurrentByteOffset >= __OFF_MAX;
	}
}

ssize_t __plat_write(__plat_handle_t h, const void *buf, size_t count, int append) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	IO_STATUS_BLOCK io;
	LARGE_INTEGER pos, *pp = 0;
	NTSTATUS st;

	if (append) {
		pos = FILE_WRITE_TO_END_OF_FILE;
		pp = &pos;
	}
	io.Status = 0; io.Information = 0;
	st = NtWriteFile(h, 0, 0, 0, &io, buf, (ULONG)count, pp, 0);
	if (st == STATUS_PENDING) { NtWaitForSingleObject(h, 0, 0); st = io.Status; }
	/* Raised here, not by the front door testing errno==EPIPE after the
	 * fact: __errno_from_status()'s generic table also maps OTHER statuses
	 * to EPIPE, and SIGPIPE must not fire for those -- only this call,
	 * with the real status in hand, can tell them apart. */
	if (st == STATUS_PIPE_BROKEN || st == STATUS_PIPE_DISCONNECTED || st == STATUS_PIPE_CLOSING) {
		__sig_lock();
		__raise_internal(SIGPIPE);
		__sig_unlock();
		errno = EPIPE;
		return -1;
	}
	if (!NT_SUCCESS(st)) {
		/* The offset maximum, NOT the process limit: this [EFBIG] is a
		 * property of the open file description, so setrlimit.html's
		 * "SIGXFSZ shall be generated" does not reach it and nothing is
		 * raised here.  (__fsize_exceeded(), the process-limit half,
		 * already ran in the front door before this call.) */
		if (start_at_offset_max(h, append)) { errno = EFBIG; return -1; }
		return __set_errno_status(st);
	}
	return (ssize_t)io.Information;
}

ssize_t __plat_pwrite(__plat_handle_t h, const void *buf, size_t count, off_t off) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	IO_STATUS_BLOCK io;
	LARGE_INTEGER pos = off;
	NTSTATUS st;

	io.Information = 0;
	st = NtWriteFile(h, 0, 0, 0, &io, buf, (ULONG)count, &pos, 0);
	if (st == STATUS_PENDING) { NtWaitForSingleObject(h, 0, 0); st = io.Status; }
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return (ssize_t)io.Information;
}

long long __plat_seek_query(__plat_handle_t h, int at_eof)
{
	IO_STATUS_BLOCK io;
	NTSTATUS st;

	if (at_eof) {
		FILE_STANDARD_INFORMATION si;
		st = NtQueryInformationFile(h, &io, &si, sizeof si, FileStandardInformation);
		if (!NT_SUCCESS(st)) return __set_errno_status(st);
		return si.EndOfFile;
	} else {
		FILE_POSITION_INFORMATION pi;
		st = NtQueryInformationFile(h, &io, &pi, sizeof pi, FilePositionInformation);
		if (!NT_SUCCESS(st)) return __set_errno_status(st);
		return pi.CurrentByteOffset;
	}
}

int __plat_seek_set(__plat_handle_t h, long long target)
{
	IO_STATUS_BLOCK io;
	FILE_POSITION_INFORMATION pi;
	NTSTATUS st;

	pi.CurrentByteOffset = target;
	st = NtSetInformationFile(h, &io, &pi, sizeof pi, FilePositionInformation);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_dup(__plat_handle_t h, int inheritable, __plat_handle_t *out)
{
	NTSTATUS st = NtDuplicateObject(NtCurrentProcess(), h, NtCurrentProcess(), out, 0,
	                                inheritable ? OBJ_INHERIT : 0, DUPLICATE_SAME_ACCESS);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_dup_to(__plat_handle_t h, int newfd, __plat_handle_t old, int inheritable, __plat_handle_t *out)
{
	/* See plat_fd.h's own comment on this function: a HANDLE's numeric
	 * value carries no meaning here, so there is nothing `newfd` could
	 * even ask this backend to do differently. */
	(void)newfd;
	if (__plat_dup(h, inheritable, out) < 0) return -1;
	/* NtDuplicateObject() above has no "replace this target" mode the
	 * way Linux's dup3(2) does, so closing whatever `old` occupied is
	 * this call's own job -- `old != h` guards the adddup2(fd, fd)
	 * shape (plat_fd.h's own comment), where closing it would destroy
	 * the handle just duplicated above rather than a separate one. */
	if (old && old != h) __plat_close(old);
	return 0;
}

void __plat_set_cloexec(__plat_handle_t h, int cloexec)
{
	/* See plat_fd.h's own comment: this backend's inheritance is
	 * entirely __fds[]-table-driven, so this function's only caller
	 * has already achieved the same effect by removing/restoring the
	 * table entry itself -- there is no separate real-object state
	 * left for this to touch. */
	(void)h; (void)cloexec;
}

// NOLINTEND(misc-include-cleaner)
