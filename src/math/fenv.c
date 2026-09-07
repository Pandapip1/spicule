/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * See include/fenv.h for why both the x87 status word and (on x86_64
 * only) MXCSR must be consulted: tcc/i386 compiles plain `double`
 * arithmetic to x87 instructions, tcc/x86_64 compiles it to SSE2, and
 * src/math/ldbl_math.h's inline-asm helpers (fsqrt, fsin, fyl2x, ...) are
 * x87 on both arches -- so on x86_64 either unit can be the one that
 * actually raised a given flag.
 *
 * The 28-byte x87 environment image used by fnstenv/fldenv below is
 * the standard 32-bit-protected-mode format (also what x86_64 gets
 * from a bare, non-REX.W fnstenv/fldenv): control word at byte
 * offset 0, status word at offset 4 (its low byte holding exactly the
 * six FE_* exception bits), tag word/instruction pointer/data pointer
 * beyond that, round-tripped opaquely by fegetenv/fesetenv without
 * this file caring what they mean.
 *
 * AArch64 (the #else branch below) has none of this: one floating-
 * point unit, its entire control/status state in two plain 32-bit
 * registers (FPCR/FPSR, read/written by mrs/msr, no memory image at
 * all), and a FE_*-bit layout that does not match FPSR's own bit
 * numbering (see FE_TO_FPSR/FPSR_TO_FE below) -- spicule's own FE_*
 * values stay the fixed, portable ones every arch's caller sees
 * (include/fenv.h's own banner explains why), translated internally
 * here, the same way this file always has been the one place that
 * knows what the public FE_* numbers really mean in hardware terms.
 */
#include <fenv.h>

/* The floating-point environment as it was at program startup, which is
 * what <fenv.h> defines FE_DFL_ENV to mean.  Captured by __fenv_init(),
 * called from crt1 before main -- the only moment at which "at program
 * startup" is still true.
 *
 * dfl_env_ok guards the case of a program that did not come through
 * crt1 at all (a DLL, a bare -nostdlib entry point of its own).  Such a
 * caller gets a capture taken at first use instead, which is strictly
 * better than a hardcoded constant and honestly worse than a startup
 * capture: it is only "the environment when FE_DFL_ENV was first
 * needed".  Nothing better is available without a startup hook.
 *
 * Declared up here, ahead of both arch branches below, since fesetenv()
 * and feholdexcept() in each one reference them -- a file-scope static
 * needs to be in scope at its use, unlike a function prototype the
 * compiler will forward-reference across a whole translation unit. */
static fenv_t dfl_env;
static int dfl_env_ok;

/* Declared here rather than by including src/internal/libc.h, where the
 * matching declaration lives beside __fd_init() and __signal_init():
 * libc.h includes nt.h, which is NT-specific, and this file is also
 * compiled natively by tools/asan-build.sh.  Keep the two in step. */
void __fenv_init(void); // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision

#if defined(__i386__) || defined(__x86_64__)

int feclearexcept(int excepts)
{
	/* Zero-initialised only to keep clang's static analyzer quiet: it
	 * cannot see that the fnstenv/fnstsw/fnstcw/stmxcsr below write
	 * through their pointer operand, so it treats the reads that
	 * follow as garbage values (clang-analyzer-core.Undefined
	 * BinaryOperatorResult; clang-tidy 18 reports it, 21 does not).
	 * The stores overwrite every byte, so these initialisers are dead
	 * in practice -- they are not a correctness fix. Passing the
	 * buffers as "=m" outputs instead would inform the analyzer
	 * properly, but tcc miscompiles that form here (SIGSEGV at
	 * runtime on both arches), so this is the portable option. */
	unsigned char env[28] = { 0 };
	excepts &= FE_ALL_EXCEPT;
	__asm__ __volatile__("fnstenv (%0)" : : "r"(env) : "memory");
	env[4] = (unsigned char)(env[4] & ~excepts);
	__asm__ __volatile__("fldenv (%0)" : : "r"(env) : "memory");
#ifndef __i386__
	{
		unsigned int mxcsr = 0;
		__asm__ __volatile__("stmxcsr (%0)" : : "r"(&mxcsr) : "memory");
		mxcsr &= ~(unsigned int)excepts;
		__asm__ __volatile__("ldmxcsr (%0)" : : "r"(&mxcsr) : "memory");
	}
#endif
	return 0;
}

/* This pokes the sticky exception bits directly (via fldenv/ldmxcsr)
 * rather than performing an operation that actually triggers each
 * exception in hardware. C99 7.6.2.3 permits that -- "the specified
 * exceptions" need only end up "currently set", not be raised through
 * a real computation. It is observationally identical to a real raise
 * as long as every exception stays masked, which they always are here
 * (src/internal never unmasks any, and neither does anything in this
 * file): a masked exception never traps, it only ever sets the sticky
 * flag, exactly what this does directly. If a caller did unmask an
 * exception (there is no API in this header to do so, but the bits
 * are real hardware state, reachable via fegetenv()'s raw env, or
 * from outside this library entirely) and then called this function
 * for that exception, the flag would still end up set correctly, but
 * no SIGFPE would fire the way it would for a genuine trapping
 * operation -- feraiseexcept()'s trap behaviour when unmasked is
 * merely "implementation-defined" per the same clause, and this is
 * the implementation's choice: never synthesize a trap. */
int feraiseexcept(int excepts)
{
	unsigned char env[28] = { 0 };
	excepts &= FE_ALL_EXCEPT;
	__asm__ __volatile__("fnstenv (%0)" : : "r"(env) : "memory");
	env[4] = (unsigned char)(env[4] | excepts);
	__asm__ __volatile__("fldenv (%0)" : : "r"(env) : "memory");
#ifndef __i386__
	{
		unsigned int mxcsr = 0;
		__asm__ __volatile__("stmxcsr (%0)" : : "r"(&mxcsr) : "memory");
		mxcsr |= (unsigned int)excepts;
		__asm__ __volatile__("ldmxcsr (%0)" : : "r"(&mxcsr) : "memory");
	}
#endif
	return 0;
}

int fetestexcept(int excepts)
{
	unsigned short sw = 0;
	excepts &= FE_ALL_EXCEPT;
	__asm__ __volatile__("fnstsw (%0)" : : "r"(&sw) : "memory");
#ifndef __i386__
	{
		unsigned int mxcsr = 0;
		__asm__ __volatile__("stmxcsr (%0)" : : "r"(&mxcsr) : "memory");
		return (int)((sw | mxcsr) & (unsigned int)excepts);
	}
#else
	return sw & excepts;
#endif
}

int fegetround(void)
{
	unsigned short cw = 0;
	__asm__ __volatile__("fnstcw (%0)" : : "r"(&cw) : "memory");
	return cw & 0xc00;
}

int fesetround(int round)
{
	unsigned short cw = 0;
	if (round != FE_TONEAREST && round != FE_DOWNWARD &&
	    round != FE_UPWARD && round != FE_TOWARDZERO)
		return -1;
	__asm__ __volatile__("fnstcw (%0)" : : "r"(&cw) : "memory");
	cw = (unsigned short)((cw & ~0xc00) | round);
	__asm__ __volatile__("fldcw (%0)" : : "r"(&cw) : "memory");
#ifndef __i386__
	{
		unsigned int mxcsr = 0;
		__asm__ __volatile__("stmxcsr (%0)" : : "r"(&mxcsr) : "memory");
		mxcsr = (mxcsr & ~0x6000u) | ((unsigned int)round << 3);
		__asm__ __volatile__("ldmxcsr (%0)" : : "r"(&mxcsr) : "memory");
	}
#endif
	return 0;
}

/* fegetenv.html DESCRIPTION: "The fegetenv() function shall attempt to
 * store the current floating-point environment in the object pointed to
 * by envp."  STORE, not modify.
 *
 * THE FLDENV BELOW IS NOT REDUNDANT -- DO NOT DELETE IT.  It reads as a
 * no-op (load back exactly what was just stored) and it is not: FNSTENV,
 * after saving the environment, MASKS ALL FLOATING-POINT EXCEPTIONS.
 * That is documented behaviour of the instruction, not an erratum
 * (Intel SDM, FSTENV/FNSTENV), and it made this getter silently mask
 * every x87 exception as a side effect -- leaving the caller unable to
 * save and restore an environment, which is the function's entire
 * purpose.  Reloading the just-saved image undoes it.  glibc's x86
 * fegetenv() does exactly this, for exactly this reason; musl's x86_64
 * version has the defect this library inherited from it.
 *
 * Nothing in <fenv.h> can unmask an exception -- feholdexcept() is
 * specified to go the other way -- so this is not observable through the
 * header alone, which is why it survived.  test/posix-math.c's
 * test_fenv_getenv_does_not_modify() reaches the control word with
 * inline asm to see it.
 *
 * STMXCSR has no such side effect and needs no counterpart. */
int fegetenv(fenv_t *envp)
{
	__asm__ __volatile__("fnstenv (%0)" : : "r"(envp->__x87env) : "memory");
	__asm__ __volatile__("fldenv (%0)" : : "r"(envp->__x87env) : "memory");
#ifndef __i386__
	__asm__ __volatile__("stmxcsr (%0)" : : "r"(&envp->__mxcsr) : "memory");
#endif
	return 0;
}

int fesetenv(const fenv_t *envp)
{
	/* Default environment: round-to-nearest, all exceptions masked and
	 * clear, 0x37f/0x1f80 are the values a fresh x87/SSE unit powers up
	 * with (and what feclearexcept/fnclex alone cannot reproduce, since
	 * they leave the control word and rounding mode untouched). */
	if (envp == FE_DFL_ENV) {
		/* <fenv.h>: FE_DFL_ENV "represents the default floating-point
		 * environment (that is, THE ONE INSTALLED AT PROGRAM STARTUP)".
		 *
		 * This used to build an environment around a hardcoded x87
		 * control word of 0x037F -- musl's value, correct for Linux
		 * x86_64, and WRONG HERE.  NT starts a thread with 0x027F.  The
		 * two differ in precision control (bits 8-9): 0x027F is 53-bit
		 * (double), 0x037F is 64-bit (extended).  So every
		 * fesetenv(FE_DFL_ENV), including the one inside
		 * feupdateenv(FE_DFL_ENV), silently WIDENED x87 precision and
		 * changed the double-rounding behaviour of every src/math/ldbl_math.h
		 * helper on both arches, and of all plain `double` arithmetic on
		 * i386 (where tcc emits x87 rather than SSE -- see
		 * include/fenv.h's banner).  Measured startup values on this
		 * target: x87 CW 0x027F, MXCSR 0x1F80.  The MXCSR constant was
		 * right; the control word was not.
		 *
		 * Rather than swapping one hardcoded word for another -- which
		 * would keep the same class of defect and merely move the day it
		 * is wrong -- the startup environment is CAPTURED, by
		 * __fenv_init() from crt1 alongside __fd_init() and
		 * __signal_init().  That is what the clause actually says, and
		 * it cannot go stale against a future Windows, a different
		 * arch, or a host that starts threads differently. */
		if (!dfl_env_ok) __fenv_init();
		__asm__ __volatile__("fldenv (%0)" : : "r"(dfl_env.__x87env) : "memory");
#ifndef __i386__
		__asm__ __volatile__("ldmxcsr (%0)" : : "r"(&dfl_env.__mxcsr) : "memory");
#endif
		return 0;
	}
	__asm__ __volatile__("fldenv (%0)" : : "r"(envp->__x87env) : "memory");
#ifndef __i386__
	__asm__ __volatile__("ldmxcsr (%0)" : : "r"(&envp->__mxcsr) : "memory");
#endif
	return 0;
}

/* feholdexcept.html DESCRIPTION: "shall save the current floating-point
 * environment in the object pointed to by envp, clear the floating-point
 * status flags, and then install a non-stop (continue on floating-point
 * exceptions) mode, if available, for all floating-point exceptions."
 * RETURN VALUE: "shall return zero if and only if non-stop floating-point
 * exception handling was successfully installed."
 *
 * The save and the clear were here; INSTALLING NON-STOP MODE WAS NOT.
 * Neither fegetenv() nor feclearexcept() sets a single mask bit --
 * feclearexcept()'s MXCSR path touches status bits 0-5 and never the
 * mask bits at 7-12 -- and the function returned 0 unconditionally,
 * making the very claim the RETURN VALUE clause conditions on.
 *
 * The x87 half used to LOOK masked, but only by accident: FNSTENV masks
 * all x87 exceptions as a documented side effect (Intel SDM, FSTENV/
 * FNSTENV), so fegetenv() was doing it invisibly.  That accident is
 * being removed in fegetenv() -- it is a defect there, a getter that
 * modifies what it reads -- so relying on it here would turn one fix
 * into another's regression.  Both halves are therefore set EXPLICITLY
 * below and this function no longer depends on any side effect.
 *
 * On x86 non-stop mode is always available: masking is a bit in each
 * unit's control register and cannot fail.  The return is still written
 * as a check of what was actually established rather than a bare
 * `return 0`, because the clause makes success conditional. */
int feholdexcept(fenv_t *envp)
{
	unsigned char env[28] = { 0 };
	/* Zero-initialised for the same reason, and with the same dead-in-
	 * practice status, as the buffers in feclearexcept() above: the
	 * analyzer cannot see that the fnstcw below writes through its
	 * pointer operand, so it treats the read that follows as a garbage
	 * value (clang-analyzer-core.UndefinedBinaryOperatorResult).  The
	 * asm overwrites every byte, so this initialiser never survives to
	 * be read -- it is not a correctness fix, and it is not optional
	 * either: every other local in this file carries it for the same
	 * reason.  Do not remove it as redundant. */
	unsigned short cw = 0;

	(void)fegetenv(envp);
	(void)feclearexcept(FE_ALL_EXCEPT);

	/* x87: set all six exception-mask bits (control word bits 0-5). */
	__asm__ __volatile__("fnstenv (%0)" : : "r"(env) : "memory");
	env[0] = (unsigned char)(env[0] | 0x3f);
	__asm__ __volatile__("fldenv (%0)" : : "r"(env) : "memory");
	__asm__ __volatile__("fnstcw (%0)" : : "r"(&cw) : "memory");
	if ((cw & 0x3f) != 0x3f) return -1;
#ifndef __i386__
	/* SSE: the six mask bits are 7-12, i.e. 0x1f80.  This is the unit
	 * tcc compiles plain `double` arithmetic into on x86_64, so leaving
	 * it alone meant a caller who had unmasked divide-by-zero still took
	 * a hardware exception on the first 1.0/0.0 inside what
	 * feholdexcept() had just reported was a non-stop region. */
	{
		unsigned int mxcsr = 0;
		__asm__ __volatile__("stmxcsr (%0)" : : "r"(&mxcsr) : "memory");
		mxcsr |= 0x1f80u;
		__asm__ __volatile__("ldmxcsr (%0)" : : "r"(&mxcsr) : "memory");
		__asm__ __volatile__("stmxcsr (%0)" : : "r"(&mxcsr) : "memory");
		if ((mxcsr & 0x1f80u) != 0x1f80u) return -1;
	}
#endif
	return 0;
}

#else /* aarch64 and any other non-x86 arch: FPCR/FPSR, no memory image */

/* FE_* (include/fenv.h: 0x01/0x04/0x08/0x10/0x20, the x87 status-word
 * bit positions) do not match FPSR's own numbering (bit 0 invalid, 1
 * divide-by-zero, 2 overflow, 3 underflow, 4 inexact -- no gap) -- see
 * this file's own banner for why the public numbers stay fixed anyway.
 * Translated explicitly both ways rather than via a shift-and-mask
 * trick: the bit orders happen to agree (I,Z,O,U,X in that sequence on
 * both), only the spacing differs, but writing that out loud once here
 * is worth more than a clever formula every future reader has to
 * re-derive. */
static unsigned int fe_to_fpsr_bits(int excepts)
{
	unsigned int r = 0;
	if (excepts & FE_INVALID)   r |= 1u << 0;
	if (excepts & FE_DIVBYZERO) r |= 1u << 1;
	if (excepts & FE_OVERFLOW)  r |= 1u << 2;
	if (excepts & FE_UNDERFLOW) r |= 1u << 3;
	if (excepts & FE_INEXACT)   r |= 1u << 4;
	return r;
}

static int fpsr_bits_to_fe(unsigned int fpsr)
{
	int r = 0;
	if (fpsr & (1u << 0)) r |= FE_INVALID;
	if (fpsr & (1u << 1)) r |= FE_DIVBYZERO;
	if (fpsr & (1u << 2)) r |= FE_OVERFLOW;
	if (fpsr & (1u << 3)) r |= FE_UNDERFLOW;
	if (fpsr & (1u << 4)) r |= FE_INEXACT;
	return r;
}

/* FPCR's RMode field (bits 22-23): 00 nearest, 01 +inf (up), 10 -inf
 * (down), 11 toward zero -- NOT the same 2-bit order the x87 control
 * word/MXCSR use (see include/fenv.h: FE_DOWNWARD=0x400 < FE_UPWARD=
 * 0x800 there; AArch64 numbers +inf before -inf). Translated
 * explicitly for the same reason as the exception bits above. */
static unsigned int fe_round_to_rmode(int round)
{
	switch (round) {
	case FE_UPWARD:     return 1;
	case FE_DOWNWARD:   return 2;
	case FE_TOWARDZERO: return 3;
	default:            return 0; /* FE_TONEAREST */
	}
}

static int rmode_to_fe_round(unsigned int rmode)
{
	switch (rmode & 3u) {
	case 1:  return FE_UPWARD;
	case 2:  return FE_DOWNWARD;
	case 3:  return FE_TOWARDZERO;
	default: return FE_TONEAREST;
	}
}

static unsigned int read_fpcr(void)
{
	unsigned long v;
	__asm__ __volatile__("mrs %0, fpcr" : "=r"(v));
	return (unsigned int)v;
}

static void write_fpcr(unsigned int v)
{
	unsigned long vv = v;
	__asm__ __volatile__("msr fpcr, %0" : : "r"(vv));
}

static unsigned int read_fpsr(void)
{
	unsigned long v;
	__asm__ __volatile__("mrs %0, fpsr" : "=r"(v));
	return (unsigned int)v;
}

static void write_fpsr(unsigned int v)
{
	unsigned long vv = v;
	__asm__ __volatile__("msr fpsr, %0" : : "r"(vv));
}

int feclearexcept(int excepts)
{
	unsigned int fpsr = read_fpsr();
	excepts &= FE_ALL_EXCEPT;
	fpsr &= ~fe_to_fpsr_bits(excepts);
	write_fpsr(fpsr);
	return 0;
}

/* See the x86 branch's own comment above (same clause, same
 * reasoning): pokes the sticky FPSR bits directly rather than
 * triggering a real trap, which C99 7.6.2.3 permits, and which stays
 * observationally identical to a real raise as long as every
 * exception's FPCR trap-enable bit stays clear -- true throughout
 * this library, and true of a fresh AArch64 FPCR by default. */
int feraiseexcept(int excepts)
{
	unsigned int fpsr = read_fpsr();
	excepts &= FE_ALL_EXCEPT;
	fpsr |= fe_to_fpsr_bits(excepts);
	write_fpsr(fpsr);
	return 0;
}

int fetestexcept(int excepts)
{
	excepts &= FE_ALL_EXCEPT;
	return fpsr_bits_to_fe(read_fpsr()) & excepts;
}

int fegetround(void)
{
	return rmode_to_fe_round(read_fpcr() >> 22);
}

int fesetround(int round)
{
	unsigned int fpcr;
	if (round != FE_TONEAREST && round != FE_DOWNWARD &&
	    round != FE_UPWARD && round != FE_TOWARDZERO)
		return -1;
	fpcr = read_fpcr();
	fpcr = (fpcr & ~(3u << 22)) | (fe_round_to_rmode(round) << 22);
	write_fpcr(fpcr);
	return 0;
}

/* No FNSTENV-style side effect to undo here (see the x86 branch's own
 * long comment on why its fegetenv() needs a reload after the store):
 * mrs is a plain register read, it does not touch FPCR/FPSR as a side
 * effect of being read. */
int fegetenv(fenv_t *envp)
{
	envp->__fpcr = read_fpcr();
	envp->__fpsr = read_fpsr();
	return 0;
}

int fesetenv(const fenv_t *envp)
{
	/* See the x86 branch's own long comment on FE_DFL_ENV -- same
	 * clause, same reasoning, same __fenv_init()-captures-the-real-
	 * startup-state fix, just no per-target hardcoded-word history to
	 * recount here: this port never shipped a wrong hardcoded aarch64
	 * default in the first place. */
	if (envp == FE_DFL_ENV) {
		if (!dfl_env_ok) __fenv_init();
		write_fpcr(dfl_env.__fpcr);
		write_fpsr(dfl_env.__fpsr);
		return 0;
	}
	write_fpcr(envp->__fpcr);
	write_fpsr(envp->__fpsr);
	return 0;
}

/* See the x86 branch's own long comment on feholdexcept's actual
 * contract (save + clear + INSTALL NON-STOP MODE, the part that is
 * easy to leave out). Non-stop mode here means clearing FPCR's five
 * trap-enable bits (IOE/DZE/OFE/UFE/IXE at bits 8-12) -- masked is
 * always available on this arch too, so the check below is, like the
 * x86 branch's, a check of what was actually established rather than
 * an unconditional success. */
int feholdexcept(fenv_t *envp)
{
	unsigned int fpcr;

	(void)fegetenv(envp);
	(void)feclearexcept(FE_ALL_EXCEPT);

	fpcr = read_fpcr();
	fpcr &= ~(0x1fu << 8);
	write_fpcr(fpcr);
	if (read_fpcr() & (0x1fu << 8)) return -1;
	return 0;
}

#endif

void __fenv_init(void)
{
	/* Captured exactly, status flags included: the clause says "the one
	 * installed at program startup", not "a cleared version of it".  On
	 * this target the startup status flags are clear anyway, so the
	 * distinction is theoretical -- but copying is what the clause says
	 * and needs no justification, while clearing would. */
	dfl_env_ok = (fegetenv(&dfl_env) == 0);
}

int fegetexceptflag(fexcept_t *flagp, int excepts)
{
	*flagp = (fexcept_t)fetestexcept(excepts);
	return 0;
}

int fesetexceptflag(const fexcept_t *flagp, int excepts)
{
	excepts &= FE_ALL_EXCEPT;
	(void)feclearexcept(~*flagp & excepts);
	(void)feraiseexcept(*flagp & excepts);
	return 0;
}

int feupdateenv(const fenv_t *envp)
{
	int ex = fetestexcept(FE_ALL_EXCEPT);
	(void)fesetenv(envp);
	(void)feraiseexcept(ex);
	return 0;
}
