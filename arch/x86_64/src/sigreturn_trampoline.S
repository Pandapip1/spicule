/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * x86_64's rt_sigaction(2) SA_RESTORER trampoline -- the x86_64 sibling
 * of arch/aarch64/src/sigreturn_trampoline.S; see that file's banner for
 * the full story. Installed as k_restorer by src/signal/linux/
 * plat_signal.c's __plat_sig_install_fault_handlers()/
 * __plat_sig_install_real_handler(), alongside real_dispatch() installed
 * directly as k_handler.
 *
 * Unlike aarch64, x86_64's rt_sigaction(2) does NOT strictly require
 * SA_RESTORER: the kernel falls back to the vDSO's own
 * __kernel_rt_sigreturn when it's unset. That fallback isn't used here
 * regardless -- plat_signal.c's install path unconditionally sets
 * SA_RESTORER for every arch it supports, so this file exists to make
 * that reference resolve to something real, following the same
 * "no host libc, no assumed runtime helper" discipline every other
 * Linux backend in this tree follows.
 *
 * System V AMD64 ABI: the kernel calls k_handler with rdi/rsi/rdx =
 * (sig, &siginfo, &ucontext) and pushes k_restorer's address as the
 * frame's return address, so real_dispatch()'s own `ret` lands here via
 * ordinary call-stack unwinding. This file just asks the kernel to
 * restore the interrupted context from that same frame.
 *
 * __NR_rt_sigreturn is 15 on x86_64 (unrelated to aarch64's 139),
 * matching musl's src/signal/x86_64/restore.s.
 *
 * `syscall`, not `int $0x80`: the legacy 32-bit entry gate silently
 * truncates the 64-bit register file rt_sigreturn(2) needs to restore.
 * rt_sigreturn(2) takes no argument registers -- the kernel reads
 * everything off the frame `rsp` already points at.
 *
 * Arch-keyed like cancel_trampoline.S, so built for every ARCH=x86_64
 * platform even though rt_sigreturn(2) is Linux-only. No __TINYC__
 * split needed: `syscall` has no tcc-assembler gap like aarch64's
 * SVC/BRK.
 */
.text
.globl __spicule_sigreturn_trampoline
__spicule_sigreturn_trampoline:
	mov	$15, %rax		# SYS_rt_sigreturn (x86_64)
	syscall
1:	jmp	1b			# unreachable: rt_sigreturn(2) never returns on success
