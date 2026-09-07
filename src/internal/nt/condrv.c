/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The single console-driver call behind src/internal/condrv.h -- see
 * that header for where every field of the request comes from.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stddef.h>
#include <string.h>
#include "libc.h"
#include "condrv.h"

/* The driver connection the loader left in the process parameters. Not
 * cached: a process can end up on a different console (a fresh handle
 * in the same field) without this library being told.
 *
 * The field is also where a caller of CreateProcess puts the
 * CONSOLE_NEW_CONSOLE/CONSOLE_DETACHED_PROCESS sentinels (small
 * negative values, microsoft/terminal dep/Console/ntcon.h), and a
 * process with no console at all leaves it null; neither names a device
 * this call could go to. */
static HANDLE condrv_handle(void)
{
	HANDLE h;

	if (!__peb || !__peb->ProcessParameters) return 0;
	h = __peb->ProcessParameters->ConsoleHandle;
	if ((LONG_PTR)h >= -4 && (LONG_PTR)h <= 0) return 0;
	return h;
}

int __condrv_call(HANDLE client, ULONG api, void *body, ULONG body_size)
{
	HANDLE condrv = condrv_handle();
	/* The header and the descriptor have to be adjacent -- that is the
	 * whole shape of the input list -- so the message is assembled here
	 * and the caller's descriptor is copied in and back out. */
	struct {
		CONSOLE_MSG_HEADER Header;
		unsigned char Body[CONDRV_MAX_DESCRIPTOR];
	} msg;
	CD_USER_DEFINED_IO req;
	IO_STATUS_BLOCK io;
	ULONG nbuf, reqlen;
	NTSTATUS st;

	if (!condrv || body_size > CONDRV_MAX_DESCRIPTOR) return -1;

	/* Both cross the syscall boundary whole -- the request directly,
	 * the message through the pointers in it -- and both have bytes
	 * the assignments below do not reach (the unused output buffer
	 * descriptor, the descriptor space past body_size). */
	memset(&req, 0, sizeof req);
	memset(&msg, 0, sizeof msg);

	msg.Header.ApiNumber = api;
	msg.Header.ApiDescriptorSize = body_size;
	/* body is legitimately NULL for a no-descriptor API, so the copy is
	 * skipped rather than called with a null source and a zero count. */
	if (body_size) memcpy(msg.Body, body, body_size);

	/* The input list is header+descriptor; the output list is the
	 * descriptor alone, and is omitted entirely for an API that has
	 * no descriptor to write back. */
	req.Client = client;
	req.InputCount = 1;
	req.OutputCount = body_size ? 1 : 0;
	req.Buffers[0].Size = (ULONG)sizeof msg.Header + body_size;
	req.Buffers[0].Buffer = &msg;
	req.Buffers[1].Size = body_size;
	req.Buffers[1].Buffer = msg.Body;

	nbuf = req.InputCount + req.OutputCount;
	reqlen = (ULONG)offsetof(CD_USER_DEFINED_IO, Buffers)
	       + nbuf * (ULONG)sizeof(CD_IO_BUFFER);

	io.Status = 0;
	io.Information = 0;
	st = NtDeviceIoControlFile(condrv, 0, 0, 0, &io, IOCTL_CONDRV_ISSUE_USER_IO,
	                           &req, reqlen, 0, 0);
	if (st == STATUS_PENDING) {
		NtWaitForSingleObject(condrv, 0, 0);
		st = io.Status;
	}
	if (!NT_SUCCESS(st)) return -1;
	if (body_size) memcpy(body, msg.Body, body_size);
	return 0;
}
// NOLINTEND(misc-include-cleaner)
