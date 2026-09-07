/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of src/internal/plat_dirent.h -- see that header for
 * the contract each function makes.
 *
 * __plat_dir_decode_one() is the NT-specific half of decoding a
 * FILE_ID_BOTH_DIR_INFORMATION record, shared by readdir.c and
 * getdents.c so neither hardcodes the struct itself. The attribute-to-
 * d_type mapping lives here too, since FILE_ATTRIBUTE_* bits mean
 * nothing to any other backend. */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include "libc.h"
#include "plat_dirent.h"

ssize_t __plat_dir_read(__plat_handle_t h, void *buf, size_t bufsize, int restart)
{
	IO_STATUS_BLOCK io;
	NTSTATUS st;

	io.Status = 0; io.Information = 0;
	st = NtQueryDirectoryFile(h, 0, 0, 0, &io, buf, (ULONG)bufsize,
	                          FileIdBothDirectoryInformation, FALSE, 0, restart);
	if (st == STATUS_NO_MORE_FILES) return 0;
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return (ssize_t)io.Information;
}

/* A d_type value from NT's FileAttributes. A reparse point is reported as
 * a symlink regardless of its actual reparse tag (mount points included):
 * a directory listing has no cheap way to tell them apart without opening
 * each one, and DT_LNK is what every other minimal implementation reports
 * for the case anyway. These are dirent.h's own DT_DIR/DT_LNK/DT_REG
 * values, duplicated here rather than pulled from a header. */
#define __NT_DT_REG 8 // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling follows the NT ABI
#define __NT_DT_DIR 4 // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling follows the NT ABI
#define __NT_DT_LNK 10 // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- spelling follows the NT ABI

static unsigned char dtype_from_attrs(ULONG attrs)
{
	if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) return __NT_DT_LNK;
	if (attrs & FILE_ATTRIBUTE_DIRECTORY) return __NT_DT_DIR;
	return __NT_DT_REG;
}

int __plat_dir_decode_one(const void *buf, size_t buflen, size_t *pos, struct __dirent_raw *out)
{
	const FILE_ID_BOTH_DIR_INFORMATION *fi;
	size_t next;

	if (*pos >= buflen) return 0;
	/* `*pos < buflen` above proves this offset is within buf's own real,
	 * NtQueryDirectoryFile-filled extent. */
	fi = (const FILE_ID_BOTH_DIR_INFORMATION *)((const unsigned char *)buf + *pos);

	/* Zeroed up front so bytes of d_name past the NUL terminator are
	 * always zero, never leftover stack/heap content: __utf16_to_utf8_buf()
	 * only ever writes outlen bytes plus one NUL. */
	memset(out, 0, sizeof *out);

	out->ino = (ino_t)fi->FileId;
	out->type = dtype_from_attrs(fi->FileAttributes);
	__utf16_to_utf8_buf(fi->FileName, fi->FileNameLength / sizeof(WCHAR), out->name, sizeof out->name);

	/* NextEntryOffset is 0 on the final record of a batch, so the rest of
	 * the buffer is consumed instead of looping forever on a zero offset. */
	next = fi->NextEntryOffset ? fi->NextEntryOffset : buflen - *pos;
	*pos += next;
	return 1;
}

// NOLINTEND(misc-include-cleaner)
