/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * uname(): this front door's whole job is uname.html's one shall-fail
 * clause -- [EFAULT] for a NULL `u` -- and handing off to __plat_uname()
 * (src/internal/plat_misc.h) for how this backend actually identifies
 * the system.  What follows describes the NT backend's own answer for
 * each field (src/misc/nt/plat_misc.c); Linux's own real uname(2)
 * answers all of them directly instead, see that backend's own comment
 * (src/misc/linux/plat_misc.c) for why nothing here needs reconstructing
 * by hand on that platform. Every NT field is something NT can genuinely
 * answer, nothing invented:
 *
 *   sysname  -- the literal string "Windows_NT".  This is not a guess
 *               dressed up as an OS name: it is the exact string
 *               Windows itself puts in %OS% on every NT-family system
 *               (`cmd /c echo %OS%`), and the same string MSYS2/Cygwin
 *               report from their own uname() for the same reason --
 *               it is the name NT gives itself, not a POSIX-flavoured
 *               fabrication.
 *   nodename -- read straight from the registry:
 *               HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\
 *               ActiveComputerName, value "ComputerName" -- the same
 *               location GetComputerNameW() itself answers from, and
 *               the machine's real name regardless of what the calling
 *               process's own environment says (nt_registry_computername()
 *               below).  NOT src/unistd/gethostname.c's %COMPUTERNAME%
 *               lookup: that reads the *caller's* environment, which a
 *               caller controls (setenv()) and a hand-built envp can
 *               omit entirely -- precisely the defect this fence
 *               recorded ("a value read out of the caller's own
 *               environment is set by the caller, which is ... an
 *               implementation-defined ORACLE, and a wrong one").  Falls
 *               back to gethostname()'s own env-based answer only if the
 *               registry query itself fails (no such environment this
 *               tree has been run in has been found, but a Windows
 *               installation missing this standard key, or an ntdll
 *               stub that has not been taught NtOpenKey/NtQueryValueKey
 *               yet -- see fuzz/ntstubs.c -- both remain possible), so
 *               uname() degrades rather than starts failing outright.
 *   release  -- "%lu.%lu" of RtlGetVersion()'s dwMajorVersion and
 *               dwMinorVersion: NT's own idea of its release number
 *               (10.0 for every Windows 10/11 build; NT has reported
 *               major.minor this way since NT 3.1), read straight from
 *               the OS, not looked up in a table this library would
 *               have to keep current by hand.
 *   version  -- "Build %lu" of dwBuildNumber, the same convention
 *               `winver`/`ver` show a user on the box itself -- the
 *               finer-grained number release.html's DESCRIPTION
 *               distinguishes version from ("further defines... release
 *               of the operating system"), sourced from the same
 *               RtlGetVersion() call as release, not synthesized
 *               separately.
 *   machine  -- a compile-time check of which arch.h this library was
 *               built with (__x86_64__ / __i386__), i.e. the same
 *               binary-compatibility class the running program was
 *               itself just compiled and linked for -- exactly what
 *               uname.html's DESCRIPTION means by "the name of the
 *               hardware type". WOW64 (a 32-bit process on a 64-bit
 *               kernel) reports "i686", not "x86_64": the running
 *               *process* is what a caller checking machine actually
 *               cares about (can it dlopen() a same-arch library?
 *               does a size_t match?), and that is 32-bit regardless
 *               of the underlying kernel's own bitness.
 *
 * A single RtlGetVersion() call, not a cached/env-derived one: it is
 * pure-NTDLL (tools/ntdll.def already exports it; src/internal/nt.h
 * already declares RTL_OSVERSIONINFOW and the prototype -- neither
 * needed adding), always succeeds per its own documentation, and reading
 * it fresh means uname() can never go stale relative to the OS it is
 * actually running under.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/utsname.h>
#include <errno.h>
#include "libc.h"
#include "plat_misc.h"

int uname(struct utsname *u)
{
	if (!u) { errno = EFAULT; return -1; }
	return __plat_uname(u);
}

// NOLINTEND(misc-include-cleaner)
