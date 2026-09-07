/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of src/internal/plat_select.h -- see that header
 * for the contract each function makes.  Everything here was, until
 * this file existed, inline inside src/select/select.c and poll.c;
 * nothing changed in substance, only location.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include "libc.h"
#include "plat_select.h"
#include "afd.h"
#include "conin.h"

int __plat_pipe_probe(__plat_handle_t h, unsigned long *read_avail, unsigned long *write_quota) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	IO_STATUS_BLOCK io;
	FILE_PIPE_LOCAL_INFORMATION pli;
	NTSTATUS st = NtQueryInformationFile(h, &io, &pli, sizeof pli, FilePipeLocalInformation);
	if (!NT_SUCCESS(st) || pli.NamedPipeState != FILE_PIPE_CONNECTED_STATE) return 0;
	*read_avail = pli.ReadDataAvailable;
	*write_quota = pli.WriteQuotaAvailable;
	return 1;
}

int __plat_pipe_wqa_trustworthy(void)
{
	HANDLE r, w;
	IO_STATUS_BLOCK io;
	FILE_PIPE_LOCAL_INFORMATION pli;
	NTSTATUS st;
	int ok = 0;

	if (!NT_SUCCESS(__pipe_handles(&r, &w, 0))) return 0;

	/* w is the client end, empty, with a 65536-byte inbound quota. */
	memset(&pli, 0, sizeof pli);
	st = NtQueryInformationFile(w, &io, &pli, sizeof pli, FilePipeLocalInformation);
	if (NT_SUCCESS(st) && pli.WriteQuotaAvailable > 0) ok = 1;

	NtClose(w);
	NtClose(r);
	return ok;
}

int __plat_wait_ready(__plat_handle_t h)
{
	LARGE_INTEGER zero = 0;
	return NtWaitForSingleObject(h, 0, &zero) == STATUS_WAIT_0;
}

int __plat_console_ready(__plat_handle_t h)
{
	if (__conin_owns(h)) return __conin_pending();
	return __plat_wait_ready(h);
}

__plat_handle_t __plat_console_wait(__plat_handle_t h)
{
	if (__conin_owns(h)) return __conin_event();
	return h;
}

void __plat_socket_probe(__plat_handle_t h, int *canread, int *canwrite, int *hup) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	/* `pi` is storage only -- correctly aligned and large enough; every
	 * field is written and read through src/internal/afd.h's
	 * AFD_POLL_REQ_OFF_* and AFD_POLL_H_OFF_* offsets (see that header's
	 * poll banner for why the struct's own layout cannot be trusted
	 * across implementations).  Separate request and reply buffers,
	 * deliberately: IOCTL_AFD_SELECT is METHOD_BUFFERED, so aliasing the
	 * reply onto the request buffer made "nothing fired" read back as
	 * "everything fired" (see select.c's file banner for the full
	 * history of that bug). */
	AFD_POLL_INFO req, rep;
	unsigned long len = __afd_poll_request_size(1);
	uint32_t events;
	NTSTATUS st;

	/* Timeout 0: never wait, just sample. */
	__afd_build_poll_request(&req, 0, 1);
	__afd_poll_set_handle(&req, 0, h, AFD_POLL_READ_BITS | AFD_POLL_WRITE_BITS);

	memset(&rep, 0, sizeof rep);
	st = __afd_ioctl(h, IOCTL_AFD_SELECT, &req, (ULONG)len, &rep, (ULONG)len, 0);
	if (!NT_SUCCESS(st)) {
		/* No honest answer available: the driver refused to tell us.
		 * Report ready-and-hung-up, the same over-eager stance taken
		 * for a pipe's unreadable WriteQuotaAvailable -- see this
		 * header's own comment. */
		*canread = 1; *canwrite = 1; *hup = 1;
		return;
	}

	/* Bounded by the reply's own NumberOfHandles and matched on the
	 * handle, never read as slot 0 unconditionally -- see select.c's
	 * file banner for why that distinction matters. */
	events = __afd_poll_events_for(&rep, 1, h);
	*canread = (events & AFD_POLL_READ_BITS) != 0;
	*canwrite = (events & AFD_POLL_WRITE_BITS) != 0;
	if (events & (AFD_EVENT_CLOSE | AFD_EVENT_ABORT | AFD_EVENT_DISCONNECT)) {
		*canread = 1; *canwrite = 1; *hup = 1;
	}
}

void __plat_wait_multiple(const __plat_handle_t *handles, int nhandles, long long wait_ticks, int infinite) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	LARGE_INTEGER t;
	if (infinite) {
		NtWaitForMultipleObjects((ULONG)nhandles, (HANDLE *)handles, 1 /* WaitAny */, 0, 0);
		return;
	}
	t = -wait_ticks;
	NtWaitForMultipleObjects((ULONG)nhandles, (HANDLE *)handles, 1 /* WaitAny */, 0, &t);
}

void __plat_delay(long long wait_ticks, int infinite) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	LARGE_INTEGER t;
	if (infinite) {
		/* NtDelayExecution has no NULL-means-forever convention; an
		 * absolute deadline far in the future is this library's
		 * existing idiom for "forever" -- see pause() in
		 * src/unistd/sleep.c. */
		LARGE_INTEGER never = 0x7fffffffffffffffLL;
		NtDelayExecution(0, &never);
		return;
	}
	t = -wait_ticks;
	if (!t) t = -1;
	NtDelayExecution(0, &t);
}

long long __plat_now_100ns(void)
{
	LARGE_INTEGER t;
	NtQuerySystemTime(&t);
	return t;
}

// NOLINTEND(misc-include-cleaner)
