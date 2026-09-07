/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * i386 sibling of src/thread/linux/aarch64/clone.S -- see that file's
 * own banner for why this trampoline has to be hand-written assembly
 * at all. Same __spicule_linux_clone(fn, stack_top, flags, arg, tls)
 * contract, musl's src/thread/i386/clone.s the direct model, cdecl
 * calling convention (this build's own established i386 convention --
 * see src/signal/i386/altstack.S's own banner, "i386 SysV Linux's own
 * default calling convention for an extern C function is ... cdecl,
 * args on the caller's stack"): all five arguments arrive on the
 * caller's stack at 8/12/16/20/24(%ebp), not in registers.
 *
 * clone(2)'s raw syscall argument ORDER is confirmed against the
 * kernel's own arch/x86/Kconfig and kernel/fork.c source (this is NOT
 * captured by this build's /nix/store linux-headers UAPI headers at
 * all -- those only fix the numeric syscall NUMBER, not which
 * kernel-internal register slot each C parameter maps to; see
 * src/thread/linux/x86_64/clone.S's own banner for the fuller
 * account of why this needed a different oracle than every other
 * syscall in this porting session). `config X86_32` in
 * arch/x86/Kconfig DOES select CLONE_BACKWARDS (unlike X86_64), which
 * makes kernel/fork.c's sys_clone(clone_flags, newsp, parent_tidptr,
 * tls, child_tidptr) the real ordering here -- TLS 4th, child_tidptr
 * 5th, the SAME position aarch64 uses (CONFIG_ARM64 also selects
 * CLONE_BACKWARDS) and the opposite of x86_64's own default ordering.
 *
 * Raw i386 syscall calling convention (arch/x86/entry/entry_32.S,
 * `int $0x80`): %eax = syscall number, %ebx/%ecx/%edx/%esi/%edi = up
 * to 5 arguments (a 6th, when needed, goes in %ebp -- not needed here,
 * clone(2) only takes 5). %ebx/%esi/%edi are also this ABI's own
 * CALLEE-SAVED registers (SysV i386 ABI), so this function must save
 * and restore them around its own use of them as syscall argument
 * registers -- unlike x86_64's %rdi/%rsi/%rdx/%r10/%r8, which are all
 * caller-saved and need no such preservation. SYS_clone=120,
 * SYS_exit=1, both confirmed against this host's own /nix/store
 * linux-headers asm/unistd_32.h.
 *
 *   long __spicule_linux_clone(unsigned (*fn)(void *), void *stack_top,
 *                             long flags, void *arg, void *tls);
 *   8(%ebp)=fn, 12(%ebp)=stack_top, 16(%ebp)=flags, 20(%ebp)=arg,
 *   24(%ebp)=tls
 *
 * Child stack setup mirrors aarch64/x86_64's own clone.S (push {fn,
 * arg} onto the child's own stack before the syscall, retrieve them
 * after it returns in the child) with one extra wrinkle: i386 cdecl
 * expects fn's own single argument already sitting on the stack at
 * the point of `call`, not in a register the way SysV AMD64's `call`
 * would want -- so after popping fn off, this leaves `arg` in place
 * on the stack rather than also popping and re-pushing it, landing
 * %esp exactly where cdecl already wants it. The one-time extra 20 (not
 * 16) -byte reservation below is NOT a mistake: it is what lands %esp
 * at 12-mod-16, rather than 0-mod-16, after the initial align-down, so
 * that popping fn's 4 bytes off in the child (advancing %esp by 4)
 * lands exactly on the 0-mod-16 residue the SysV i386 ABI requires
 * immediately before `call` (the same "%esp+4 aligned to 16 on entry"
 * rule src/signal/i386/altstack.S's own banner documents) -- worked
 * through arithmetically: 0-mod-16 minus 20 bytes is (-20 mod 16) =
 * 12-mod-16; 12 plus the 4-byte pop is 16, i.e. 0-mod-16 again. Only
 * the first 8 of those 20 reserved bytes are ever written to.
 */
	.text
	.globl __spicule_linux_clone
	.type __spicule_linux_clone, @function
__spicule_linux_clone:
	push	%ebp
	mov	%esp, %ebp
	push	%ebx			# callee-saved: this function clobbers
	push	%esi			# it as a syscall argument register
	push	%edi			# below, so it must be restored before
					# returning to the (cdecl) caller

	mov	8(%ebp), %eax		# fn
	mov	12(%ebp), %ecx		# stack_top
	mov	16(%ebp), %ebx		# flags
	mov	20(%ebp), %edx		# arg (temporary home -- %edx becomes
					# parent_tidptr=0 below, after this
					# value has already been stored to the
					# child's own stack)
	mov	24(%ebp), %esi		# tls -- CLONE_BACKWARDS' 4th slot; see
					# this file's own banner

	and	$-16, %ecx		# align stack_top down to 16 bytes...
	sub	$20, %ecx		# ...then reserve 20 bytes -- see this
					# file's own banner for why 20, not 16
	mov	%eax, (%ecx)		# fn
	mov	%edx, 4(%ecx)		# arg

	xor	%edx, %edx		# parent_tidptr -- unused by this port
	xor	%edi, %edi		# child_tidptr -- unused by this port
	mov	$120, %eax		# SYS_clone (i386)
	int	$0x80

	test	%eax, %eax
	jz	1f			# %eax == 0 only in the new child
	# parent: restore the callee-saved regs pushed above, then hand
	# %eax (child pid, or a raw negative -errno on failure) straight
	# back to the C caller, exactly like aarch64/x86_64's own clone.S.
	pop	%edi
	pop	%esi
	pop	%ebx
	pop	%ebp
	ret
1:	# child: NEVER fall through to the parent path above -- see
	# aarch64's clone.S banner for why unwinding into the caller's C
	# frame here would be memory corruption, not merely wrong. %esp is
	# now the child stack pointer this function itself set up above
	# (fn at offset 0, arg at offset 4).
	mov	(%esp), %eax		# %eax = fn
	add	$4, %esp		# %esp -> arg, already cdecl-ready (see
					# this file's own banner) -- no need to
					# pop-then-repush it separately
	call	*%eax			# fn(arg); %eax now holds fn's return value
	mov	%eax, %ebx		# exit code = fn's return value
	mov	$1, %eax		# SYS_exit (this "thread" is its own
					# thread-group leader -- no
					# CLONE_THREAD, see plat_thread.c's
					# banner -- so a plain per-thread exit
					# is also this process's exit)
	int	$0x80
	.size __spicule_linux_clone, . - __spicule_linux_clone
