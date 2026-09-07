/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * unsafe_assume_valid_pointer(expr) -- a source-visible marker for the
 * narrow set of integer-to-pointer conversions that
 * tools/clang/PointerProvenanceChecker.cpp cannot prove (there is no
 * base/len pair, and no pointer derivation at all, anywhere in the
 * translation unit -- the integer crossed in from a raw syscall return
 * value, a kernel-populated out-parameter, hardware fault state, or an
 * ELF-relocation-computed address) but that a human has read and can
 * justify by the real ABI contract at that one call site.
 *
 * This is deliberately NOT the same mechanism as the checker's own
 * NamedException table (PointerProvenanceChecker.cpp's isNamedException).
 * That table lists (file, function) pairs the checker consults; nothing
 * at the actual cast site says a finding there is exempt, or why -- only
 * the checker's own source explains it, out of view of whoever is
 * reading the call site. This marker instead wraps the literal
 * expression being converted, right where the conversion happens, and
 * its own name says plainly what it is: an unverified human assumption,
 * never to be mistaken for a proof. Every real call site using it also
 * carries its own substantive comment stating the concrete invariant
 * that makes the assumption true there -- that comment is the actual
 * justification; this macro only makes the assumption visible and
 * machine-checkable as "present, at this exact expression" instead of
 * silent.
 *
 * Expands to nothing but its own argument outside analysis (a real tcc
 * or clang build never defines __clang_analyzer__): normal builds pay
 * nothing and see no behavior change whatsoever. Under the analyzer,
 * it expands to a GNU statement expression declaring exactly one
 * compiler-generated local, scoped to that single use, carrying the
 * annotation PointerProvenanceChecker.cpp's isUnsafeAssumeValidPointer()
 * looks for on the local that directly initializes -- so applying the
 * marker to one cast can never silence any other cast, including a
 * second, otherwise-identical one written right next to it without the
 * marker (see tools/lint-pointer-provenance-fixtures/unsafe.c's
 * unmarked_cast_still_flagged()).
 */
#ifndef _SPICULE_UNSAFE_POINTER_H
#define _SPICULE_UNSAFE_POINTER_H

#ifdef __clang_analyzer__
#define unsafe_assume_valid_pointer(expr) \
	(__extension__({ \
		__typeof__(expr) __spicule_unsafe_ptr__ \
			__attribute__((annotate("spicule_unsafe_assume_valid_pointer"))) \
			= (expr); \
		__spicule_unsafe_ptr__; \
	}))
#else
#define unsafe_assume_valid_pointer(expr) (expr)
#endif

/* unsafe_assume_shared_provenance(expr) -- the same marker idea as
 * unsafe_assume_valid_pointer() above, for
 * tools/clang/PointerProvenanceChecker.cpp's OTHER provenance check: a
 * pointer subtraction or ordered comparison (`<`, `<=`, `>`, `>=`)
 * between two pointers the checker cannot prove share an allocation or a
 * contract-registered element relation. expr is the whole subtraction or
 * comparison expression, e.g.
 * `unsafe_assume_shared_provenance(p < end)`, not either operand
 * separately -- wrapping only one operand would leave the checker
 * looking at an ordinary, unmarked BinaryOperator.
 *
 * Real uses are the same shape as unsafe_assume_valid_pointer()'s: two
 * pointers a human has read and can justify as the same object or the
 * same contract-registered array by an invariant established somewhere
 * this one expression's own local reasoning cannot see -- a hand-written
 * assembly stub's own address computation, a fixed table another
 * function populated earlier, or a caller contract a function's
 * parameters document but cannot express in C's type system. Every real
 * call site carries its own substantive comment stating that invariant;
 * this macro only makes the assumption visible and machine-checkable,
 * exactly as unsafe_assume_valid_pointer() does -- see that macro's own
 * comment above for the full mechanism (expands to nothing outside the
 * analyzer, and PointerProvenanceChecker.cpp's isUnsafeAssumeShared
 * Provenance()/isMarkerRedundant() give it the identical scoped-to-one-
 * use and redundancy-detection guarantees).
 */
#ifdef __clang_analyzer__
#define unsafe_assume_shared_provenance(expr) \
	(__extension__({ \
		__typeof__(expr) __spicule_unsafe_shared_prov__ \
			__attribute__((annotate("spicule_unsafe_assume_shared_provenance"))) \
			= (expr); \
		__spicule_unsafe_shared_prov__; \
	}))
#else
#define unsafe_assume_shared_provenance(expr) (expr)
#endif

#endif
// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
