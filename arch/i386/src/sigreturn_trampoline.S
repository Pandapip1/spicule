/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * i386's rt_sigaction(2) SA_RESTORER trampoline -- the i386 sibling of
 * arch/aarch64/src/sigreturn_trampoline.S and arch/x86_64/src/
 * sigreturn_trampoline.S; see the aarch64 file's banner for the full
 * story. Installed as k_restorer by src/signal/linux/plat_signal.c's
 * __plat_sig_install_fault_handlers()/__plat_sig_install_real_handler(),
 * alongside real_dispatch() installed directly as k_handler.
 *
 * cdecl: the kernel calls k_handler with the signal frame it built on
 * this thread's stack, using i386's ordinary cdecl argument-passing
 * convention (sig, &siginfo, &ucontext pushed in that order); its own
 * `ret` lands here. This file just asks the kernel to restore the
 * interrupted context from that same frame.
 *
 * __NR_rt_sigreturn is 173 on i386 (unrelated to aarch64's 139 or
 * x86_64's 15), matching musl's src/signal/i386/restore.s.
 *
 * `int $0x80`, not `sysenter`, for consistency with every other i386
 * raw syscall this tree issues. rt_sigreturn(2) takes no argument
 * registers -- the kernel reads everything off the frame %esp already
 * points at -- so no register marshalling is needed here.
 *
 * Arch-keyed like cancel_trampoline.S, so built for every ARCH=i386
 * platform even though rt_sigreturn(2) is Linux-only. No __TINYC__
 * split needed: `int $0x80` has no tcc-assembler gap like aarch64's
 * SVC/BRK.
 */
.text
.globl __spicule_sigreturn_trampoline
__spicule_sigreturn_trampoline:
	movl	$173, %eax		# SYS_rt_sigreturn (i386)
	int	$0x80
1:	jmp	1b			# unreachable: rt_sigreturn(2) never returns on success
