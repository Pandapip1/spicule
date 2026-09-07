/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * exit and friends.  The process is ended with NtTerminateProcess rather
 * than RtlExitUserProcess: the latter runs the loader's shutdown, which
 * notifies every loaded DLL and, through kernel32, tells csrss -- none of
 * which a forked child (which has no csrss connection) can survive, and
 * none of which a program with no DLLs but ntdll needs.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stdlib.h>
#include <unistd.h>
#include "libc.h"
#include "plat_exit.h"
#include "plat_signal.h"

/* ATEXIT_CAP_ is in libc.h, shared with sysconf(_SC_ATEXIT_MAX). */
static void (*handlers[ATEXIT_CAP_])(void);
static int nhandlers;
static void (*qhandlers[32])(void);
static int nqhandlers;

int atexit(void (*f)(void))
{
	if (nhandlers >= ATEXIT_CAP_) return -1;
	handlers[nhandlers++] = f;
	return 0;
}

int at_quick_exit(void (*f)(void))
{
	if (nqhandlers >= 32) return -1;
	qhandlers[nqhandlers++] = f;
	return 0;
}

void __funcs_on_exit(void)
{
	while (nhandlers > 0) handlers[--nhandlers]();
}

_Noreturn void __exit_internal(int code)
{
	/* Before the process goes: continue any child kill(pid, SIGSTOP)
	 * left suspended, preceded by a SIGHUP where the platform can
	 * deliver one for real.  exit.html requires both to a newly-
	 * orphaned stopped process group, and every child of ours becomes
	 * one the moment this process ends; src/process/children.c has the
	 * full reasoning, including why the SIGHUP half is per-platform.
	 * Placed in __exit_internal() rather than in exit() so that _exit() and
	 * _Exit() -- and the exec() stand-in, which ends through here --
	 * cannot skip it. */
	__child_resume_stopped();
	/* code encodes "end this process exactly as if by sig's default
	 * action" (__ENCODE_SIGNAL_EXIT(), libc.h) at every call site that
	 * passes one. __plat_sig_default_terminate() raises the real signal
	 * where the platform has one of its own to raise (Linux); see its
	 * plat_signal.h comment for why __plat_terminate() below -- an
	 * ordinary process exit whose status only ENCODES the signal number
	 * -- is the wrong way to end such a process there. A no-op, and
	 * always falls through to __plat_terminate() below, on NT (same
	 * comment), same as before this call existed. */
	if (__IS_SIGNAL_EXIT(code) && (code & 0x7f))
		__plat_sig_default_terminate(code & 0x7f);
	__plat_terminate(code);
}

_Noreturn void _Exit(int code) { __exit_internal(code); }
_Noreturn void _exit(int code) { __exit_internal(code); }

_Noreturn void exit(int code)
{
	__funcs_on_exit();
	__stdio_exit();
	__exit_internal(code);
}

_Noreturn void quick_exit(int code)
{
	while (nqhandlers > 0) qhandlers[--nqhandlers]();
	__exit_internal(code);
}

// NOLINTEND(misc-include-cleaner)
