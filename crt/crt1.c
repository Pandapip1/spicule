/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Program startup.
 *
 * The kernel enters a new process's first thread at ntdll's
 * RtlUserThreadStart, which reaches the image's entry point -- this
 * file's _start.  tcc's PE linker names _start as the entry when linking
 * with -nostdlib, so nothing has to be said on the command line.
 *
 * _start declares two parameters, and uses neither.  They are captured
 * into __entry_arg0/__entry_arg1 purely so test/entry-arg.c can report
 * what the OS actually handed the entry point; the PEB itself comes from
 * the TEB.  See __libc_start_main below for why -- a Windows-subsystem
 * image's entry point is not reliably passed anything.
 *
 * What a C program expects to have been done by the time main runs, and
 * is done here: argv split out of the one command line string Windows
 * hands a process, the environment block turned into environ, the three
 * standard handles turned into descriptors 0, 1 and 2, and exit arranged
 * so that main's return value becomes the process's exit status.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stdlib.h>
#include <string.h>
#include "libc.h"
#include "rtlib.h"

/* main is always called below with the full three arguments, whichever
 * of the three standard forms the program actually defined. C23 turns
 * the traditional unprototyped `int main();' into an implicit `(void)',
 * which would stop this call from compiling, so the widest prototype is
 * declared instead (mingw-w64 does the same). Passing extra arguments a
 * narrower main ignores is harmless under both ABIs spicule targets:
 * i386 __cdecl (caller pops the stack) and x86_64 Microsoft x64 (caller
 * owns the shadow space) both let a callee read fewer args/registers
 * than were passed for free. C99 5.1.2.2.1 only requires main be
 * callable, not that the declaration match exactly. */
int main(int, char **, char **);

PPEB __peb;
char **environ;
char **__argv;
int __argc;
char *__progname;
char *__progname_full;

/* Splits a Windows command line by the CommandLineToArgvW rules:
 * arguments separated by unquoted spaces/tabs; a quote toggles
 * "in quotes"; 2n backslashes + quote = n backslashes + special quote,
 * 2n+1 = n backslashes + literal quote; "" inside quotes is a literal
 * quote (post-2008 rule). The first argument (program name) is special:
 * backslashes are never escapes, only quotes delimit it. */
/* p is nonnull per NT's own UNICODE_STRING invariant (Buffer is
 * non-NULL whenever Length > 0), not derivable from the `i < n` guards
 * alone. */
static int split_cmdline(const WCHAR *p, size_t n,
                         char ***argvp withtok(internal_heap_allocated))
    __attribute__((nonnull(1, 3)));
static int split_cmdline(const WCHAR *p, size_t n,
                         char ***argvp withtok(internal_heap_allocated))
{
	WCHAR *buf;
	char **argv;
	int argc = 0;
	size_t i = 0, cap = 2, units, bytes;

	if (!__size_add_checked(n, 1, &units) ||
	    !__size_mul_checked(units, sizeof(WCHAR), &bytes)) return -1;
	buf = __malloc(bytes);
	argv = (char **)__malloc(sizeof(char *[2]));

	if (!buf || !argv) return -1;

	/* program name */
	{
		size_t o = 0;
		int inq = 0;
		while (i < n && (p[i] == ' ' || p[i] == '\t')) i++;
		while (i < n) {
			if (p[i] == '"') { inq = !inq; i++; continue; }
			if (!inq && (p[i] == ' ' || p[i] == '\t')) break;
			buf[o++] = p[i++];
		}
		argv[argc++] = __utf16_to_utf8(buf, o);
	}

	for (;;) {
		size_t o = 0;
		int inq = 0;
		while (i < n && (p[i] == ' ' || p[i] == '\t')) i++;
		if (i >= n) break;
		for (;;) {
			if (i >= n) break;
			if (p[i] == '\\') {
				size_t nb = 0;
				while (i < n && p[i] == '\\') { nb++; i++; }
				if (i < n && p[i] == '"') {
					size_t k;
					for (k = 0; k < nb / 2; k++) buf[o++] = '\\';
					if (nb & 1) { buf[o++] = '"'; i++; }
					/* even: the quote is handled by the loop */
				} else {
					size_t k;
					for (k = 0; k < nb; k++) buf[o++] = '\\';
				}
				continue;
			}
			if (p[i] == '"') {
				if (inq && i + 1 < n && p[i+1] == '"') { buf[o++] = '"'; i += 2; continue; }
				inq = !inq; i++;
				continue;
			}
			if (!inq && (p[i] == ' ' || p[i] == '\t')) break;
			buf[o++] = p[i++];
		}
		if ((size_t)argc + 1 >= cap) {
			size_t next;
			char **nv;
			if (!__array_next_capacity(cap, (size_t)argc, 2, 2,
			    sizeof *argv, &next) ||
			    !__size_mul_checked(next, sizeof *argv, &bytes)) return -1;
				nv = (char **)__malloc(bytes);
				if (!nv) return -1;
				memcpy((void *)nv, (const void *)argv, sizeof *argv * (size_t)argc);
				__free((void *)argv);
			argv = nv;
			cap = next;
		}
		argv[argc++] = __utf16_to_utf8(buf, o);
	}
	argv[argc] = 0;
	__free(buf);
	*argvp = argv;
	return argc;
}

/* The environment block is a sequence of NUL-terminated UTF-16 strings
 * ended by an empty one.  Windows keeps some "=C:=C:\dir" entries for
 * per-drive current directories; those are kept too, the way msvcrt and
 * Cygwin keep them, since a child may need them. */
static char **build_environ(const WCHAR *env)
{
	size_t count = 0, i, slots, bytes;
	const WCHAR *p;
	char **ev;

	if (!env) {
		ev = (char **)__malloc(sizeof(char *));
		if (ev) ev[0] = 0;
		return ev;
	}
	for (p = env; *p; p += wcslen_(p) + 1) count++;
	if (!__size_add_checked(count, 1, &slots) ||
	    !__size_mul_checked(slots, sizeof *ev, &bytes)) return 0;
	ev = (char **)__malloc(bytes);
	if (!ev) return 0;
	for (p = env, i = 0; *p; p += wcslen_(p) + 1)
		ev[i++] = __utf16_to_utf8(p, wcslen_(p));
	ev[i] = 0;
	return ev;
}

/* pp->StandardError/pp->CommandLine are dereferenced unchecked below:
 * RTL_USER_PROCESS_PARAMETERS is allocated and populated by the NT
 * loader before any user-mode instruction runs, so pp is exactly as
 * OS-guaranteed non-NULL as __peb itself. */
void __libc_start_main(void)
{
	PRTL_USER_PROCESS_PARAMETERS pp;
	int rc;

	/* The PEB comes out of the TEB, not out of an entry-point argument:
	 * whether that argument even holds the PEB depends on NT's era.
	 * NT 4.0 through Server 2003 call a Subsystem-3 entry point with
	 * NO arguments at all (PPROCESS_START_ROUTINE is DWORD(WINAPI
	 * *)(VOID)); the PEB sits in EBX from the initial thread context
	 * but is never pushed for the callee, so reading "the first
	 * argument" there gets a stale stack slot instead (in practice the
	 * pseudo-handle 0xFFFFFFFE, which faults at address 0xE if
	 * dereferenced as a PEB). Vista and later start threads at
	 * ntdll!RtlUserThreadStart, whose thread parameter genuinely is
	 * the PEB. No Microsoft documentation specifies which, and there
	 * is no reliable runtime test to distinguish a stale slot from a
	 * real PEB pointer -- so the TEB, which every thread has before
	 * any user code runs on any NT version, is read instead.
	 *
	 * __teb() (src/internal/{i386,x86_64}/teb.c) is a two-instruction
	 * read of fs:0x18 / gs:0x30, not an ntdll import -- unlike
	 * RtlGetCurrentPeb(), which under -Wl,--delay-all would be a
	 * delay-load stub whose first resolution needs __peb already set,
	 * a chicken-and-egg deadlock.
	 *
	 * TEB.ProcessEnvironmentBlock is at +0x30 on i386 and +0x60 on
	 * x86_64; nt.h asserts this against ReactOS's own layout tests. */
	__peb = __teb()->ProcessEnvironmentBlock;
	pp = __peb->ProcessParameters;

	/* Checked as early as possible while still able to report why: a
	 * diagnostic needs pp->StandardError, unavailable before the two
	 * lines above. Nothing before this touches a long double, and
	 * __fenv_init() below would be the first thing that does. Writes
	 * directly via NtWriteFile, not stdio, since stdio isn't
	 * initialized yet; STATUS_INVALID_IMAGE_FORMAT is NT's status for
	 * an ABI mismatch, the same category of failure as this one. */
	if (!__verify_ldbl_layout()) {
		static const char msg[] =
			"spicule: long double bit-layout assumption failed at startup\r\n";
		IO_STATUS_BLOCK io;
		if (pp->StandardError)
			NtWriteFile(pp->StandardError, 0, 0, 0, &io, msg,
				sizeof msg - 1, 0, 0);
		NtTerminateProcess(NtCurrentProcess(), STATUS_INVALID_IMAGE_FORMAT);
	}

	__argc = split_cmdline(pp->CommandLine.Buffer, pp->CommandLine.Length / sizeof(WCHAR), &__argv);
	if (__argc < 0) NtTerminateProcess(NtCurrentProcess(), STATUS_NO_MEMORY);
	__progname = __argv[0];
	__progname_full = __utf16_to_utf8(pp->ImagePathName.Buffer, pp->ImagePathName.Length / sizeof(WCHAR));
	__environ = build_environ(pp->Environment);
	if (!__environ) NtTerminateProcess(NtCurrentProcess(), STATUS_NO_MEMORY);

	__fd_init();
	__signal_init();
	__fenv_init();

	rc = main(__argc, __argv, __environ);
	exit(rc);
}

/* Exists to be *measured* by test/entry-arg.c, not used: __libc_start_main
 * never reads it, taking the PEB from the TEB instead (see above). Must
 * never become the source of __peb -- it's the quantity under
 * measurement. */
void *__entry_arg0;

/* Captured alongside __entry_arg0 as a control: nobody claims the entry
 * point takes two arguments, so this confirms the capture reads real
 * incoming machine state rather than a hardcoded answer. */
void *__entry_arg1;

/* Named arg0/arg1, not peb: whether either slot holds a PEB is exactly
 * what is under measurement, not known in advance. */
void _start(void *arg0, void *arg1)
{
	__entry_arg0 = arg0;
	__entry_arg1 = arg1;
	__libc_start_main();
}

// NOLINTEND(misc-include-cleaner)
