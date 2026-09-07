/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * 32-bit CAS and fetch-add for PLATFORM=nt ARCH=aarch64, called from the
 * three private compare_exchange()/exchange_add() copies in
 * src/thread/{pthread_cancel,pthread_rwlock,pthread_sync}.c's own
 * aarch64 branch (see each file's existing x86 branch comment for why
 * those copies stay separate rather than sharing a header -- the same
 * reasoning applies here: only the low-level primitive centralizes,
 * each caller's wrapper stays where it is).
 *
 * Those three files' existing x86 branch is real `lock; cmpxchgl`/
 * `lock; xaddl` asm, not __atomic_compare_exchange_n()/__atomic_fetch_
 * add(), because tcc (the only compiler PLATFORM=nt ever builds with)
 * implements neither builtin. The pre-existing #else branch assumed
 * "any other arch is always a real gcc/clang" -- true until this port:
 * PLATFORM=nt ARCH=aarch64 is tcc on aarch64, a combination that did
 * not exist when that assumption was written, and it breaks it
 * (`'__ATOMIC_SEQ_CST' undeclared`, confirmed against the actual
 * pinned arm64-win32-tcc).
 *
 * A hand-written LL/SC loop is real work here, not a mechanical port
 * of the x86 branch, for a second, more severe reason: arm64-win32-tcc
 * 0.9.28rc (2026-08-23 HEAD@69eed4d3) does not implement ANY exclusive-
 * access or LSE atomic mnemonic at all -- LDXR/STXR/LDAXR/STLXR/CLREX/
 * LDAR/STLR/CAS/CASAL/LDADD/LDADDAL/SWP all fail "not implemented",
 * empirically probed one at a time the same way as the float mnemonics
 * src/math/aarch64_math.h's own __TINYC__ branch documents. Unlike
 * that file's fallback (portable C, no asm needed at all), an atomic
 * read-modify-write genuinely has no C-only equivalent: it has to be
 * these specific instructions, encoded here as raw `.word` values
 * since the mnemonics do not parse. Each encoding was NOT hand-derived
 * from memory and trusted blindly -- every one was cross-checked by
 * assembling the real mnemonic for a real target (clang --target=
 * aarch64-linux-gnu, which has a complete, independently-implemented
 * AArch64 encoder) and disassembling the result (GNU objdump -m
 * aarch64, an independently-implemented decoder) to confirm the
 * intended instruction and operands round-trip exactly. `.word` itself
 * is an ordinary, universal assembler directive (unlike the mnemonics
 * it stands in for here) -- tcc accepts it -- so this is real machine
 * code, not a trick specific to tcc's parser.
 *
 * The loop shape (LDAXR, compare, STLXR, CBNZ retry, CLREX on the
 * abandoned-monitor exit path for CAS) is not invented either: it is
 * exactly what clang -O2 -mno-outline-atomics emits for
 * __atomic_compare_exchange_n()/__atomic_fetch_add() with
 * __ATOMIC_SEQ_CST on aarch64 (confirmed by compiling both and reading
 * the disassembly) -- LDAXR (load-acquire-exclusive) paired with STLXR
 * (store-release-exclusive) is the standard, sufficient AArch64
 * encoding of a seq-cst RMW; no separate DMB is needed or added.
 *
 * Register encodings used below (Rt/Rs/Rn 5-bit fields, AAPCS64 W/X
 * numbering): w0 address's low half is never itself touched as a
 * value register (x0 stays the pointer throughout); w1/w2 are the
 * incoming arguments; w3/w4 (cas32) and w2/w3/w4 (xadd32) are scratch,
 * matching the operand encodings in each `.long` comment. TinyCC follows
 * the traditional assembler meaning of `.word` (16 bits), so these 32-bit
 * AArch64 instructions must use `.long` to preserve instruction alignment.
 */
.text

.globl __spicule_aarch64_cas32
__spicule_aarch64_cas32:
	/* x0 = address, w1 = expected old value, w2 = new value.
	 * Returns (w0) the value actually observed in memory, whether or
	 * not the swap took place -- matching the callers' compare_
	 * exchange() contract, itself matching x86 LOCK CMPXCHG's "eax
	 * holds the previous value" behavior. */
1:
	.long	0x885ffc03		/* ldaxr w3, [x0] */
	subs	wzr, w3, w1		/* w3 == w1 (expected)? (CMP alias; see longjmp.S's own comment on why CMP itself is avoided) */
	bne	2f
	.long	0x8804fc02		/* stlxr w4, w2, [x0] */
	cbnz	w4, 1b			/* store-exclusive lost the monitor: retry */
	b	3f
2:
	.long	0xd5033f5f		/* clrex: release the monitor opened by
					 * the ldaxr above, since no stlxr will
					 * follow on this path */
3:
	mov	w0, w3
	ret

.globl __spicule_aarch64_xadd32
__spicule_aarch64_xadd32:
	/* x0 = address, w1 = value to add (may be negative). Returns (w0)
	 * the value in memory BEFORE the add, matching x86 LOCK XADD /
	 * __atomic_fetch_add() semantics. */
1:
	.long	0x885ffc02		/* ldaxr w2, [x0] */
	add	w3, w2, w1
	.long	0x8804fc03		/* stlxr w4, w3, [x0] */
	cbnz	w4, 1b
	mov	w0, w2
	ret
