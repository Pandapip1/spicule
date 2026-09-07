/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform-termination interface src/exit/exit.c's __exit_internal() calls
 * into instead of a raw NtTerminateProcess call.  See src/exit/nt/
 * plat_exit.c for the implementation this declares.
 *
 * There is exactly one function here because there is exactly one raw
 * syscall left in exit.c once __child_resume_stopped() (this library's
 * own exit.html job-control bookkeeping, not NT-specific) is taken out:
 * the unconditional, never-returning process termination itself.
 */
#ifndef _SPICULE_PLAT_EXIT_H
#define _SPICULE_PLAT_EXIT_H

/* End this process immediately with exit status `code`.  Never returns
 * -- retries forever on the vanishingly unlikely chance the first
 * attempt does not immediately end the process, the same defensive loop
 * __exit_internal() had before this call existed. */
_Noreturn void __plat_terminate(int code);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
