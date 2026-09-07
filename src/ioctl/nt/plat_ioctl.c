/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of src/internal/plat_ioctl.h -- see that header for
 * the contract each function makes.  Everything here was, until this
 * file existed, inline inside src/ioctl/ioctl.c's fionread_pipe() and
 * fionread_file(); nothing changed in substance, only location and the
 * addition of a POSIX-shaped return (0/-1 with errno set) in place of
 * a raw NTSTATUS.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <limits.h>
#include "libc.h"
#include "plat_ioctl.h"

int __plat_fionread_pipe(__plat_handle_t h, int *out)
{
	IO_STATUS_BLOCK io;
	FILE_PIPE_LOCAL_INFORMATION pli;
	NTSTATUS st = NtQueryInformationFile(h, &io, &pli, sizeof pli, FilePipeLocalInformation);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	*out = pli.ReadDataAvailable > (ULONG)INT_MAX ? INT_MAX
	     : (int)pli.ReadDataAvailable;
	return 0;
}

int __plat_file_eof_and_pos(__plat_handle_t h, long long *eof, long long *pos) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	IO_STATUS_BLOCK io;
	FILE_STANDARD_INFORMATION si;
	FILE_POSITION_INFORMATION pi;
	NTSTATUS st;

	st = NtQueryInformationFile(h, &io, &si, sizeof si, FileStandardInformation);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	st = NtQueryInformationFile(h, &io, &pi, sizeof pi, FilePositionInformation);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	*eof = si.EndOfFile;
	*pos = pi.CurrentByteOffset;
	return 0;
}

// NOLINTEND(misc-include-cleaner)
