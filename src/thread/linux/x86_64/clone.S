/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * x86_64 sibling of src/thread/linux/aarch64/clone.S -- see that file's
 * own banner for why this trampoline has to be hand-written assembly at
 * all (clone(2) returns twice; a `ret` in the child would unwind into a
 * C epilogue against a stack pointer that never held the right values).
 * Same __spicule_linux_clone(fn, stack_top, flags, arg, tls) contract,
 * musl's src/thread/x86_64/clone.s the direct model, same SysV AMD64
 * calling convention this whole build already assumes for every other
 * x86_64 C function (System V AMD64 ABI): fn=%rdi, stack_top=%rsi,
 * flags=%rdx, arg=%rcx, tls=%rdi... no -- tls=%r8, the 5th integer
 * argument slot.
 *
 * clone(2)'s own raw syscall argument ORDER genuinely differs from
 * aarch64's: the kernel's kernel/fork.c picks one of several argument
 * orderings per architecture via a Kconfig symbol (CLONE_BACKWARDS/
 * _BACKWARDS2/_BACKWARDS3, or the plain default), and this is NOT
 * something this build's own /nix/store linux-headers UAPI headers
 * capture at all (they only fix the numeric syscall NUMBER, not which
 * kernel-internal register slot each C parameter name maps to) -- so
 * unlike every other syscall number in this porting session, this had
 * to be confirmed against the kernel's own arch/x86/Kconfig and
 * kernel/fork.c source directly: `config X86_64` in arch/x86/Kconfig
 * selects neither CLONE_BACKWARDS nor any of its variants (unlike
 * `config X86_32`, which does -- see src/thread/linux/i386/clone.S's
 * own banner), so x86_64 takes kernel/fork.c's own #else default
 * ordering: sys_clone(clone_flags, newsp, parent_tidptr, child_tidptr,
 * tls) -- TLS LAST, in the 5th argument slot. That is a DIFFERENT
 * position than aarch64's own clone.S uses (aarch64 -- CONFIG_ARM64
 * DOES select CLONE_BACKWARDS -- puts tls 4th and child_tidptr 5th),
 * which is exactly why this file cannot just be aarch64's register
 * numbers renamed: the argument-to-register MAPPING itself is
 * genuinely different here, not merely the register names.
 *
 * Raw x86_64 syscall calling convention (arch/x86/entry/entry_64.S):
 * %rax = syscall number, %rdi/%rsi/%rdx/%r10/%r8/%r9 = up to 6
 * arguments (NOT %rcx for the 4th slot -- the `syscall` instruction
 * itself clobbers %rcx, storing the return address there, so the
 * kernel's own syscall ABI substitutes %r10 in that slot instead of
 * the SysV C calling convention's %rcx). SYS_clone=56, SYS_exit=60,
 * both confirmed against this host's own /nix/store linux-headers
 * asm/unistd_64.h.
 *
 *   long __spicule_linux_clone(unsigned (*fn)(void *), void *stack_top,
 *                             long flags, void *arg, void *tls);
 *   %rdi = fn, %rsi = stack_top, %rdx = flags, %rcx = arg, %r8 = tls
 *
 * Stack-alignment/child-setup technique, return-value contract, and
 * exit(2)-instead-of-exit_group(2) reasoning (this "thread" is its own
 * thread-group leader, no CLONE_THREAD) are all identical to aarch64's
 * clone.S -- see that file's own banner for the fuller account, not
 * repeated here.
 */
	.text
	.global __spicule_linux_clone
	.type __spicule_linux_clone, @function
__spicule_linux_clone:
	andq	$-16, %rsi		# stack pointers must stay 16-byte aligned
	subq	$16, %rsi		# reserve 2 words on the child's own stack
	movq	%rdi, (%rsi)		# fn
	movq	%rcx, 8(%rsi)		# arg
	movq	%rdx, %rdi		# flags (clone(2)'s 1st kernel argument)
	# %rsi already holds the (adjusted) child stack pointer -- clone(2)'s
	# 2nd kernel argument, matches without moving it again.
	xorl	%edx, %edx		# parent_tidptr -- unused by this port
	xorl	%r10d, %r10d		# child_tidptr -- unused by this port
	# %r8 already holds tls (this arch's default, non-BACKWARDS 5th-slot
	# position -- see this file's own banner), passed through unchanged.
	movl	$56, %eax		# SYS_clone (x86_64)
	syscall
	testq	%rax, %rax
	jz	1f			# %rax == 0 only in the new child
	ret				# parent: hand %rax (child pid, or a raw
					# negative -errno on failure) straight
					# back to the C caller
1:	# child: NEVER fall through to `ret` above -- see aarch64's clone.S
	# banner for why unwinding into the caller's C frame here would be
	# memory corruption, not merely wrong.
	popq	%rax			# %rax = fn (matches the push order
					# above: fn stored first at [rsp+0])
	popq	%rdi			# %rdi = arg -- first (and only)
					# integer argument to fn(), SysV AMD64
					# calling convention
	call	*%rax			# fn(arg); %eax now holds fn's return value
	movl	%eax, %edi		# exit code = fn's return value
	movl	$60, %eax		# SYS_exit (this "thread" is its own
					# thread-group leader -- no
					# CLONE_THREAD, see plat_thread.c's
					# banner -- so a plain per-thread exit
					# is also this process's exit)
	syscall
	.size __spicule_linux_clone, . - __spicule_linux_clone
