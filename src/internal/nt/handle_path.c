/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * __handle_path() -- moved out of src/internal/path.c: this half, unlike
 * the rest of path.c, has a genuinely portable POSIX-shaped meaning ("the
 * path of an already-open descriptor"), called unconditionally from the
 * portable front door (fchmod()'s EACCES retry, fchdir(), exec.c's
 * re-exec by path, realpath.c) rather than gated behind an nt/ directory.
 * That unconditional call used to pull this file's NT-only syscall chain
 * into the native-Linux build even when no test exercised it, so it now
 * has a real Linux counterpart (src/internal/linux/handle_path.c).
 *
 * The DOS path of an open handle: NtQueryObject's ObjectNameInformation
 * gives the full NT name (\Device\HarddiskVolume3\dir\file), and the
 * drive is found by asking each of A: through Z: for its target -- the
 * cheaper route than kernel32's GetFinalPathNameByHandle takes. Returns a
 * malloc'd UTF-8 path.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include "libc.h"

NTSTATUS NTAPI NtOpenSymbolicLinkObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSTATUS NTAPI NtQuerySymbolicLinkObject(HANDLE, PUNICODE_STRING, PULONG);

withtok(internal_heap_allocated)
char *__handle_path(HANDLE h)
{
	char buf[sizeof(OBJECT_NAME_INFORMATION) + 2048 * sizeof(WCHAR)];
	OBJECT_NAME_INFORMATION *oni = (OBJECT_NAME_INFORMATION *)buf;
	ULONG len = 0;
	NTSTATUS st;
	WCHAR drive[7] = { '\\', '?', '?', '\\', 'A', ':', 0 };
	WCHAR target[512];
	UNICODE_STRING us, tus;
	OBJECT_ATTRIBUTES oa;
	int c;

	st = NtQueryObject(h, ObjectNameInformation, oni, sizeof buf, &len);
	if (!NT_SUCCESS(st)) { __set_errno_status(st); return 0; }

	/* Under Wine (and in some other cases) ObjectNameInformation comes back
	 * already in \??\C:\... form instead of \Device\HarddiskVolumeN\...;
	 * such a name is already a drive path, so just strip the \??\ prefix
	 * rather than going through the device/symlink matching below, which
	 * only knows how to match \Device\... names. Every access below is
	 * guarded by `nlen >= 6` first. */
	{
		size_t nlen = oni->Name.Length / sizeof(WCHAR);
		WCHAR *nb = oni->Name.Buffer;
		if (nlen >= 6 && nb[0] == '\\' && nb[1] == '?' && nb[2] == '?' && nb[3] == '\\' &&
		    ((nb[4] >= 'A' && nb[4] <= 'Z') || (nb[4] >= 'a' && nb[4] <= 'z')) && nb[5] == ':') {
			return __utf16_to_utf8(nb + 4, nlen - 4);
		}
	}

	RtlInitUnicodeString(&us, drive);
	InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, 0, 0);
	for (c = 'A'; c <= 'Z'; c++) {
		HANDLE lh;
		ULONG tl;
		size_t i;
		int matches;
		drive[4] = (WCHAR)c;
		us.Length = 6 * sizeof(WCHAR);
		if (!NT_SUCCESS(NtOpenSymbolicLinkObject(&lh, 0x1 /* SYMBOLIC_LINK_QUERY */, &oa))) continue;
		tus.Buffer = target; tus.Length = 0; tus.MaximumLength = sizeof target;
		st = NtQuerySymbolicLinkObject(lh, &tus, &tl);
		NtClose(lh);
		if (!NT_SUCCESS(st)) continue;
		tl = tus.Length / sizeof(WCHAR);
		matches = oni->Name.Length / sizeof(WCHAR) >= tl;
		for (i = 0; i < tl; i++)
			if (oni->Name.Buffer[i] != target[i]) { matches = 0; break; }
		if (matches &&
		    (oni->Name.Length / sizeof(WCHAR) == tl || oni->Name.Buffer[tl] == '\\')) {
			size_t rest = oni->Name.Length / sizeof(WCHAR) - tl;
			size_t units, bytes;
			WCHAR *w;
			char *r;
			if (!__size_add_checked(rest, 3, &units) ||
			    !__size_mul_checked(units, sizeof(WCHAR), &bytes)) return 0;
			w = __malloc(bytes);
			if (!w) return 0;
			w[0] = (WCHAR)c; w[1] = ':';
			for (i = 0; i < rest; i++) w[2 + i] = oni->Name.Buffer[tl + i];
			if (!rest) { w[2] = '\\'; rest = 1; }
			r = __utf16_to_utf8(w, rest + 2);
			__free(w);
			return r;
		}
	}
	/* Not on a drive letter (a pipe, a UNC path): give the NT name. */
	return __utf16_to_utf8(oni->Name.Buffer, oni->Name.Length / sizeof(WCHAR));
}

// NOLINTEND(misc-include-cleaner)
