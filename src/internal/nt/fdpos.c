/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include "libc.h"

/* pread/pwrite pass an explicit ByteOffset to NtReadFile/NtWriteFile, but
 * our file handles are opened FILE_SYNCHRONOUS_IO_NONALERT, and for such
 * handles the filesystem sets FileObject->CurrentByteOffset to the end of
 * the transfer regardless. POSIX wants the position left alone, so
 * callers save it with __fd_pos_save before the transfer and restore it
 * with __fd_pos_restore afterwards. Not atomic against other threads
 * sharing the fd, but this libc has none. */

int __fd_pos_save(HANDLE h, long long *pos)
{
	IO_STATUS_BLOCK io;
	FILE_POSITION_INFORMATION pi;
	NTSTATUS st;

	st = NtQueryInformationFile(h, &io, &pi, sizeof pi, FilePositionInformation);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	*pos = pi.CurrentByteOffset;
	return 0;
}

void __fd_pos_restore(HANDLE h, long long pos)
{
	IO_STATUS_BLOCK io;
	FILE_POSITION_INFORMATION pi;

	pi.CurrentByteOffset = pos;
	NtSetInformationFile(h, &io, &pi, sizeof pi, FilePositionInformation);
}

// NOLINTEND(misc-include-cleaner)
