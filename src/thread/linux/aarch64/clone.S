/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The one piece of __plat_thread_spawn() (src/thread/linux/plat_thread.c,
 * one directory up -- PLAT_ARCH_GLOBS's own src/thread/linux/$(ARCH)/
 * *.[csS] shape, see Makefile's own comment on that glob) that cannot be
 * a raw syscall call from C: clone(2) returns TWICE, once in the
 * calling thread and once in the new one -- exactly like fork(2) --
 * except the new thread's stack pointer becomes the `stack_top`
 * argument below, a fresh mmap()'d region, not a continuation of the
 * calling thread's own stack. A `svc #0` wrapped in an ordinary C
 * function would, in the child, execute that C function's epilogue
 * (restoring saved registers, reading local variables) against a stack
 * pointer that never held any of those values -- real, silent memory
 * corruption, not a crash on the first instruction. Every real libc's
 * clone() (glibc's, musl's) is hand-written assembly for exactly this
 * reason; this is that same shape, musl's src/thread/aarch64/clone.s
 * the direct model. src/thread/linux/x86_64/clone.S and src/thread/
 * linux/i386/clone.S are this file's siblings for the other two arches
 * this tree targets, each following its own arch's calling convention
 * and clone(2) register ABI (see their own banners) but implementing
 * the identical __spicule_linux_clone() contract documented below.
 *
 * Validated standalone, outside this tree, before being wired in here:
 * a byte-identical copy of this trampoline, called from a throwaway
 * host-glibc test program, correctly created a real second kernel
 * thread sharing memory with its parent (verified via a written-then-
 * read shared mmap()), and a plain wait4() only saw it as a joinable
 * child once the SIGCHLD exit-signal bit was added to the flags word
 * passed in from plat_thread.c -- see that file's own banner for why.
 *
 *   long __spicule_linux_clone(unsigned (*fn)(void *), void *stack_top,
 *                             long flags, void *arg, void *tls);
 *   x0 = fn, x1 = stack_top, x2 = flags, x3 = arg, x4 = tls
 *
 *   `tls` is clone(2)'s own tls argument: when `flags` carries
 *   CLONE_SETTLS, the kernel sets the CHILD's TPIDR_EL0 to this value
 *   before it ever runs a single instruction, which is what gives it
 *   real, independent `__thread` storage instead of aliasing the
 *   caller's (see plat_thread.c's __plat_thread_spawn(), the only
 *   caller, for how `tls` is built). A caller that does not want
 *   CLONE_SETTLS at all passes tls=0 with the flag bit clear, same as
 *   before this parameter existed.
 *
 * Returns, in the CALLING thread, whatever the parent's clone(2) branch
 * of the underlying syscall returns: the new thread's pid, or a raw
 * negative -errno (see plat_thread.c's raw_syscall()/is_sys_error() for
 * why this file never routes through the host libc's syscall() wrapper,
 * which would collapse that value away). Never returns to its caller in
 * the CHILD at all: the child instead calls fn(arg) directly and then
 * exits via a raw SYS_exit syscall, whatever fn returns becoming the
 * exit code (truncated to a byte, standard Unix exit-status
 * convention).
 */
	.text
	.global __spicule_linux_clone
	.type __spicule_linux_clone,%function
__spicule_linux_clone:
	and	x1, x1, #-16		// stack pointers must stay 16-byte aligned
	stp	x0, x3, [x1, #-16]!	// push {fn, arg} onto the child's own stack
	mov	x0, x2			// flags (clone(2)'s first kernel argument)
	// x1 already holds the (adjusted) child stack pointer -- clone(2)'s
	// second kernel argument, matches without moving it again.
	mov	x2, #0			// parent_tidptr -- unused by this port
	mov	x3, x4			// tls -- the incoming 5th argument (x4
					// on entry, clobbered above only in the
					// x1/child-stack-pointer computation,
					// never written), passed through
					// unchanged; see this file's own banner
	mov	x4, #0			// child_tidptr -- unused by this port
	mov	x8, #220		// SYS_clone (aarch64; confirmed against
					// this host's own <sys/syscall.h>, same
					// as plat_thread.c's other numbers)
	svc	#0
	cbz	x0, 1f			// x0 == 0 only in the new child
	ret				// parent: hand x0 (child pid, or a raw
					// negative -errno on failure) straight
					// back to the C caller
1:	// child: NEVER fall through to `ret` above -- see this file's
	// banner for why unwinding into the caller's C frame here would be
	// memory corruption, not merely wrong.
	ldp	x1, x0, [sp], #16	// x1 = fn, x0 = arg (matches the push
					// order above: stp stored fn first at
					// [sp+0], arg at [sp+8])
	blr	x1			// fn(arg); x0 now holds fn's return value
	mov	x8, #93			// SYS_exit (this "thread" is its own
					// thread-group leader -- no
					// CLONE_THREAD, see plat_thread.c's
					// banner -- so a plain per-thread exit
					// is also this process's exit)
	svc	#0
	.size __spicule_linux_clone, . - __spicule_linux_clone
