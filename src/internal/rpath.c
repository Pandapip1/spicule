/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Implementation of the $ORIGIN-relative DLL search declared in
 * include/ntlibc/rpath.h -- see that file for the design, search order
 * and threat model, and include/ntlibc/delayload.h for the delay-load
 * mechanism built on top of it.
 *
 * This file only ever runs code when something calls
 * ntlibc_rpath_load()/_sym() -- which happens only from
 * ntlibc_delayLoadHelper2() (src/internal/delayload.c), which itself
 * only runs on the first call through a generated delay-load stub.
 * Nothing here is reached from crt1.c or any other startup path, so a
 * program that never delay-loads anything never pays for it.
 *
 * The one loading primitive used is LdrLoadDll()/LdrGetProcedureAddress()
 * (both ntdll exports, declared in nt.h) -- the same pair
 * src/signal/signal.c already uses to reach kernel32's
 * SetConsoleCtrlHandler at runtime. Every candidate path handed to
 * LdrLoadDll here is already fully qualified (built from the image
 * directory or an explicit absolute __rpath entry), so the NT loader's
 * own search order -- which does include the current working directory
 * on many configurations -- is never invoked by this file.
 *
 * NT-only, deliberately, but *only* refused at the point something would
 * actually try to link and run it natively: LdrLoadDll()/
 * LdrGetProcedureAddress() have no native (non-Windows) counterpart, so
 * unlike most other files under src/, this one cannot be given a
 * stand-in for tools/asan-build.sh's native run -- fuzz/ntstubs.c
 * answers RtlAllocateHeap and the like precisely because every native
 * ASan/UBSan build links every compiled source file's object into every
 * test unconditionally (see that script's own comment on why an archive
 * would be wrong there), so a stray undefined Ldr* here would break
 * every *other* test's native link too, not just this facility's own.
 * The #error below fires only when both are true: not building for NT
 * (tcc predefines _WIN32 for both win32 targets this library builds
 * for -- confirmed for i386-win32-tcc and x86_64-win32-tcc alike), *and*
 * this is the native compile-and-link, which is the one situation this
 * file cannot survive.
 *
 * THE SECOND HALF IS NOW ASKED DIRECTLY, via -D_NTLIBC_NATIVE_BUILD,
 * which tools/asan-build.sh passes in every mode.  It used to be
 * inferred from AddressSanitizer being active (__SANITIZE_ADDRESS__ for
 * gcc, __has_feature(address_sanitizer) for clang), on the reasoning
 * that asan-build.sh always passes -fsanitize=address.  That stopped
 * being true when that script gained NTLIBC_SAN_MODE=ubsan -- a native
 * build with no ASan in it -- and the proxy failed silently in the worst
 * direction: this file compiled, and then broke the link of every test
 * and every fuzz harness in that mode with an undefined
 * LdrGetProcedureAddress.  A proxy for a fact is worth exactly as long
 * as nothing else can make it false.  The ASan terms are kept as well,
 * so a native build that reaches these files without going through
 * asan-build.sh is still caught. A plain native
 * -fsyntax-only pass (tools/lint.sh's fallback when no mingw-w64 cross
 * compiler is installed) defines neither and is unaffected: nothing in
 * this file needs an actual Ldr* definition to type-check, only to
 * link, so there is nothing to protect there. Where the #error does
 * fire, it fails *compilation*, which is exactly the signal
 * tools/asan-build.sh's mechanical "compile every source file and keep
 * whichever compiles" step already treats as "skip this one" -- the
 * same outcome src/internal/$ARCH/teb.c gets for reading gs:0x30
 * natively, reached here without needing that script (which is out of
 * this change's scope) to name this file specifically.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#ifndef __has_feature
#define __has_feature(x) 0 /* not clang: never claim a clang-only feature */
#endif
#if !defined(_WIN32) && (defined(_NTLIBC_NATIVE_BUILD) || \
                        defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer))
#error "rpath.c is NT-only (LdrLoadDll/LdrGetProcedureAddress have no native stand-in); see the comment above"
#endif
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include "libc.h"
#include "ntlibc/rpath.h"
#include "ownership_stubs.h"

/* ---- the image's own directory ($ORIGIN) ------------------------------ */

/* __progname_full (crt1.c) is the image path as ImagePathName gave it --
 * a native, backslash-separated path.  Return a fresh string so the search
 * iteration that consumes it also has an explicit, finite lifetime. */
withtok(internal_heap_allocated)
static char *image_dir(void)
{
	const char *progname = __progname_full;
	char *dir;
	size_t n, i;

	if (!progname) return NULL; /* caller sees the same as OOM */

	n = strlen(progname);
	for (i = n; i > 0 && progname[i-1] != '\\' && progname[i-1] != '/'; i--) ;
	if (i == 0) {
		/* No separator at all -- nothing sensible to strip; treat the
		 * image as living in "." rather than guessing. */
		dir = __malloc(2);
		if (dir) { dir[0] = '.'; dir[1] = 0; }
		return dir;
	}
	/* i is the index just past the last separator; strip it too, unless
	 * that separator is the one after a bare drive letter ("C:\"),
	 * which has to stay to still name the root directory. */
	if (i > 1 && !(i == 3 && progname[1] == ':')) i--;
	if (i > INT_MAX) return 0;
	{
		size_t bytes;
		if (!__size_add_checked(i, 1, &bytes)) return 0;
		dir = __malloc(bytes);
		if (dir) snprintf(dir, bytes, "%.*s", (int)i, progname);
	}
	return dir;
}

static int is_absolute(const char *p)
{
	if (!p[0]) return 0;
	if (p[0] == '/' || p[0] == '\\') return 1;
	return ((p[0] | 0x20) >= 'a' && (p[0] | 0x20) <= 'z') && p[1] == ':';
}

static int has_path_component(const char *p)
{
	for (; *p; p++)
		if (*p == '/' || *p == '\\') return 1;
	return 0;
}

/* dir "\" tail, with every '/' normalised to '\\'. Malloc'd; NULL on OOM. */
withtok(internal_heap_allocated)
static char *join(const char *dir, const char *tail)
{
	size_t dl = strlen(dir), tl = strlen(tail), i, bytes;
	char *p;
	if (!__size_add_checked(dl, 1, &bytes) ||
	    !__size_add_checked(bytes, tl, &bytes) ||
	    !__size_add_checked(bytes, 1, &bytes)) return 0;
	p = __malloc(bytes);
	if (!p) return 0;
	snprintf(p, bytes, "%s\\%s", dir, tail);
	for (i = 0; i < dl + 1 + tl; i++)
		if (p[i] == '/') p[i] = '\\';
	return p;
}

/* ---- last-failure record ----------------------------------------------- */

static struct rpath_error {
	int valid;
	NTSTATUS status;
	char what[1024];
	unsigned long seq; /* bumped on every set_err(); see ntlibc_rpath_error_seq() */
} last_err;

static void set_err(NTSTATUS st, const char *what)
{
	last_err.valid = 1;
	last_err.status = st;
	last_err.seq++;
	/* Error text is a bounded best-effort record; truncation cannot replace
	 * the NTSTATUS and this void recorder has no failure channel. */
	(void)snprintf(last_err.what, sizeof last_err.what, "%s", what);
}

/* Monotonic counter, bumped once per set_err() (i.e. once per failure
 * recorded here), 0 until the first failure ever happens. This exists
 * purely so a caller layered on top -- dlerror() (src/dlfcn/dlfcn.c) is
 * the only one today -- can tell "this is the same failure I already
 * reported" from "a new failure has happened since", by remembering the
 * seq value it last consumed, without this file's own sticky
 * ntlibc_rpath_error() (which intentionally keeps returning the same
 * string on repeated calls, per its own doc comment and
 * test/posix-dl.c's test_dl_underlying_mechanism()) having to change
 * shape or ever go quiet on its own callers. */
unsigned long ntlibc_rpath_error_seq(void)
{
	return last_err.seq;
}

const char *ntlibc_rpath_error(void)
{
	static char buf[1200];
	const char *reason;

	if (!last_err.valid) return "no error";
	switch (last_err.status) {
	case STATUS_DLL_NOT_FOUND:
	case STATUS_OBJECT_NAME_NOT_FOUND:
		reason = "DLL not found";
		break;
	case STATUS_ENTRYPOINT_NOT_FOUND:
		reason = "symbol not found";
		break;
	case STATUS_INVALID_IMAGE_FORMAT:
	case STATUS_INVALID_IMAGE_NOT_MZ:
	case STATUS_INVALID_IMAGE_WIN_32:
	case STATUS_INVALID_IMAGE_WIN_64:
		reason = "not a valid image for this architecture";
		break;
	case STATUS_NO_MEMORY:
		reason = "out of memory";
		break;
	case STATUS_NAME_TOO_LONG:
		reason = "path too long";
		break;
	default:
		reason = 0;
	}
	/* The accessor must return its bounded diagnostic buffer even if the
	 * descriptive text is truncated; the recorded NTSTATUS remains primary. */
	if (reason)
		(void)snprintf(buf, sizeof buf, "%s: %s (NTSTATUS 0x%08lx)", last_err.what, reason, (unsigned long)last_err.status);
	else
		(void)snprintf(buf, sizeof buf, "%s: NTSTATUS 0x%08lx", last_err.what, (unsigned long)last_err.status);
	return buf;
}

/* ---- loading ------------------------------------------------------------ */

static NTSTATUS try_load(const char *path, PVOID *handle)
{
	WCHAR *w;
	size_t wn;
	UNICODE_STRING us;
	NTSTATUS st;

	w = __utf8_to_utf16(path, &wn);
	if (!w) return STATUS_NO_MEMORY;
	if (wn > __US_MAX_WCHARS) { __free(w); return STATUS_NAME_TOO_LONG; }
	us.Buffer = w;
	us.Length = (USHORT)(wn * sizeof(WCHAR));
	us.MaximumLength = (USHORT)(us.Length + sizeof(WCHAR));
	st = LdrLoadDll(NULL, NULL, &us, handle);
	__free(w);
	return st;
}

ntlibc_dll_t *ntlibc_rpath_load(const char *dllname)
{
	PVOID handle;
	NTSTATUS st;
	char *path;

	if (!dllname || !*dllname) { set_err(STATUS_OBJECT_NAME_NOT_FOUND, ""); return 0; }

	if (has_path_component(dllname)) {
		path = join("", dllname); /* normalises slashes; dir="" leaves a leading '\\' */
		if (path && path[0] == '\\') memmove(path, path + 1, strlen(path));
		if (!path) { set_err(STATUS_NO_MEMORY, dllname); return 0; }
		st = try_load(path, &handle);
		if (!NT_SUCCESS(st)) { set_err(st, path); __free(path); return 0; }
		__free(path);
		return handle;
	}

	{
		const char *const *entry = __rpath;
		struct rpath_error saved_err = last_err;
		int tried = 0;
		for (; entry && *entry; entry++) {
			char *dir;
			char *full;

			tried = 1;
			if (is_absolute(*entry)) {
				size_t n = strlen(*entry) + 1;
				dir = __malloc(n);
				if (dir) memcpy(dir, *entry, n);
			} else {
				char *base = image_dir();
				dir = base ? join(base, *entry) : 0;
				__free(base);
			}
			if (!dir) { set_err(STATUS_NO_MEMORY, dllname); return 0; }
			full = join(dir, dllname);
			__free(dir);
			if (!full) { set_err(STATUS_NO_MEMORY, dllname); return 0; }

			st = try_load(full, &handle);
			if (NT_SUCCESS(st)) {
				__free(full);
				last_err = saved_err;
				return handle;
			}
			set_err(st, full); /* overwritten by a later entry's failure, if any */
			__free(full);
		}
		if (!tried) set_err(STATUS_DLL_NOT_FOUND, dllname);
		return 0;
	}
}

void *ntlibc_rpath_sym(ntlibc_dll_t *dll, const char *symbol)
{
	ANSI_STRING name;
	PVOID proc;
	NTSTATUS st;

	if (!dll || !symbol) { set_err(STATUS_ENTRYPOINT_NOT_FOUND, symbol ? symbol : ""); return 0; }

	name.Buffer = (char *)symbol;
	{
		size_t l = strlen(symbol);
		if (l > 0xffffu) { set_err(STATUS_NAME_TOO_LONG, symbol); return 0; }
		name.Length = name.MaximumLength = (USHORT)l;
	}
	st = LdrGetProcedureAddress(dll, &name, 0, &proc);
	if (!NT_SUCCESS(st)) { set_err(st, symbol); return 0; }
	return proc;
}

/* Symmetrical with ntlibc_rpath_load(): decrements the loader's own
 * LoadCount for `dll` and unloads it once that count reaches zero.
 * LdrUnloadDll() (src/internal/nt.h) already does both the decrement
 * and the conditional unload itself -- confirmed against Wine's
 * dlls/ntdll/loader.c, where LdrLoadDll's callees increment
 * WINE_MODREF.ldr.LoadCount on every load of an already-mapped module
 * (e.g. the `if (LoadCount != -1) LoadCount++` sites around
 * import_dll()/load_dll()) and LdrUnloadDll() itself decrements that
 * same field and only calls free_modref() when it hits zero -- so
 * nothing here needs its own refcount; this is a thin call-and-
 * translate wrapper, the same shape as ntlibc_rpath_sym(). Returns 0
 * on success; on failure returns nonzero and ntlibc_rpath_error()
 * describes why. */
int ntlibc_rpath_unload(ntlibc_dll_t *dll)
{
	NTSTATUS st;

	if (!dll) { set_err(STATUS_INVALID_PARAMETER, ""); return -1; }
	st = LdrUnloadDll(dll);
	if (!NT_SUCCESS(st)) { set_err(st, ""); return -1; }
	return 0;
}

_Noreturn void ntlibc_rpath_fail(const char *dllfile, const char *symbol)
{
	/* This is the final fatal diagnostic; abort is unconditional and a
	 * secondary stderr failure cannot be reported through another channel. */
	(void)fprintf(stderr, "%s: delay-load of %s!%s failed: %s\n",
	        __progname ? __progname : "?", dllfile, symbol, ntlibc_rpath_error());
	abort();
}

// NOLINTEND(misc-include-cleaner)
