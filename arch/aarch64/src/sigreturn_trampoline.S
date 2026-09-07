/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * aarch64's rt_sigaction(2) SA_RESTORER trampoline. Installed as
 * k_restorer by src/signal/linux/plat_signal.c's
 * __plat_sig_install_fault_handlers(), alongside fault_dispatch()
 * installed directly as k_handler.
 *
 * Raw rt_sigaction(2) on aarch64 has no vDSO trampoline (unlike
 * x86_64) and REQUIRES SA_RESTORER: the kernel refuses to build a
 * signal frame otherwise. The kernel calls k_handler with
 * x0/x1/x2 = (sig, &siginfo, &ucontext) and LR (x30) already pointing
 * HERE, so fault_dispatch()'s own `ret` lands on this trampoline
 * automatically with SP still where the kernel's signal frame put it;
 * all this file does is ask the kernel to restore the interrupted
 * context from that same frame.
 *
 * __NR_rt_sigreturn is 139 on aarch64, matching musl's
 * src/signal/aarch64/restore.s, which this is a byte-for-byte port of.
 *
 * Arch-keyed like cancel_trampoline.S, so it's built for every
 * ARCH=aarch64 platform even though rt_sigreturn(2) is Linux-only; the
 * __TINYC__ split below mirrors that file's own tcc accommodation.
 */
.text
.globl __spicule_sigreturn_trampoline
__spicule_sigreturn_trampoline:
#ifdef __TINYC__
	/* tcc's arm64-win32 assembler does not implement SVC. Never reached
	 * on this platform regardless -- nothing on NT installs this. */
1:	b	1b
#else
	mov	x8, #139		// SYS_rt_sigreturn (aarch64)
	svc	#0
2:	b	2b			// unreachable: rt_sigreturn(2) never returns on success
#endif
