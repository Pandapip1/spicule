/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _OWNERSHIP_H
#define _OWNERSHIP_H

/* An opt-in ownership dialect expressed entirely in ordinary C syntax.
 * Token policy belongs to the nominal token typedef; values and operations
 * refer to that policy by name. */
#define __token_type typedef struct { char _tok; }
#define tokdef __token_type
/* Every qualifier/relation macro below exists purely for the benefit of
 * the tools/clang checkers' AST walks (OwnershipChecker, MemoryContractChecker,
 * AllocationLifetimeChecker, and SizeCastChecker's ntlibc.ArrayIndex): none
 * of them is read by any normal compile. GCC parses annotate() but always
 * reports it "ignored" outside its own LTO-streaming consumer, and even
 * clang's own ordinary compiles never look at it -- only clang's static
 * analyzer engine (tools/lint.sh's --analyze-based stages) and the one
 * -fsyntax-only "totality" plugin stage that also needs withtok(...) for
 * null_terminated consult it. __clang_analyzer__ is clang's own predefined
 * macro for exactly the first case, defined whenever "clang --analyze" is
 * running regardless of which -analyzer-checker=... is loaded (the same
 * convention src/mman/mman.c's unsafe_pointer.h and
 * src/thread/pthread_cond.c's lock_requires_held_on_entry()/
 * lock_acquires_for_caller already use for their own, unrelated
 * annotations). tools/lint.sh's stage_totality builds its plugin as a
 * plain PluginASTAction under -fsyntax-only, which never defines
 * __clang_analyzer__, so that one stage also defines
 * NTLIBC_OWNERSHIP_ANALYSIS explicitly on its real-source scan; every
 * other stage that reads one of these annotations always runs under
 * --analyze and needs no extra flag. Emitting the attribute for a plain
 * GCC/clang build (including the "lint (warn)" -Wall -Wextra gate, and
 * tcc, which does not understand __attribute__((annotate(...))) at all)
 * serves no purpose there and is exactly what GCC's own "annotate"
 * warning is complaining about. */
#if defined(__clang_analyzer__) || defined(NTLIBC_OWNERSHIP_ANALYSIS)
#define __ownership_attr(text) __attribute__((annotate(text)))
#else
#define __ownership_attr(text)
#endif
/* Linear tokens are strict by default.  A permissive token remains linear,
 * but may stay behind while other, unlimited tokens on its carrier copy. */
#define l_strict __ownership_attr("qual:l_strict")
#define l_permissive __ownership_attr("qual:l_permissive")
#define l_unlimited __ownership_attr("qual:l_unlimited")
#define implicit_drop __ownership_attr("qual:implicit_drop")
#define dynamic_storage __ownership_attr("qual:dynamic_storage")
#define implemented_by(token_name) \
	__ownership_attr("qual:implemented_by=" #token_name)
#define string_literal __ownership_attr("qual:string_literal")
#define extent_at_least __ownership_attr("qual:extent_at_least")
#define element_extent __ownership_attr("qual:element_extent")
#define disjoint_extent __ownership_attr("qual:disjoint_extent")
#define zero_vacuous __ownership_attr("qual:zero_vacuous")
#define sentinel_exclude(value) \
	__ownership_attr("qual:sentinel_exclude=" #value)
#define blocks_dereference \
	__ownership_attr("qual:blocks_dereference")
/* The two thread-scoped verbs below attach a token operation to a bare
 * function declaration that has no natural parameter or return value to
 * hang a per-value withtok(...)/consume(...)/grant(...)/drop(...)
 * annotation on (e.g. close(), __errno_location()): the fact they track is
 * "one thing per analyzed path/function", not tied to any specific value.
 * There is no concurrency modeling anywhere in this checker suite --
 * "thread-scoped" names the granularity (once per analysis, like a
 * thread-local), not an actual thread.
 *
 * There is no consumes_thread_token/requires_thread_token_absent pair
 * alongside these: the one real design that motivated them (errno_pending,
 * tracking whether the single most-recently-diagnosed capable call is
 * still the most recent one at all) turned out to need per-call identity a
 * family-only key structurally cannot carry -- see
 * tools/clang/ErrnoDisciplineChecker.cpp's own design note on
 * CarrierCapabilityKind/ThreadCapabilityMap for the adversarial case that
 * sank it. Add that pair once a real, sound consumer needs it. */
#define grants_thread_token(token_name) \
	__ownership_attr("grants_thread_token:" #token_name)
#define requires_thread_token(token_name) \
	__ownership_attr("requires_thread_token:" #token_name)
#define withtok(token_name) \
	__ownership_attr("withtok:" #token_name)
#define elements_withtok(token_name, extent_name) \
	__ownership_attr("elements_withtok:" #token_name ":" #extent_name)
#define withhandle(handle_name) \
	__ownership_attr("withhandle:" #handle_name)
#define withouttok(token_name) \
	__ownership_attr("withouttok:" #token_name)
#define consume(token_name) \
	__ownership_attr("consume:" #token_name)
#define consume_any(token_name) \
	__ownership_attr("consume_any:" #token_name)
#define grant(token_name) \
	__ownership_attr("grant:" #token_name)
#define drop(token_name) \
	__ownership_attr("drop:" #token_name)
#define consume_if_nonnull_return(token_name) \
	__ownership_attr("consume_if_nonnull_return:" #token_name)
#define construct(handle_name) \
	__ownership_attr("construct:" #handle_name)
#define destroy(handle_name) \
	__ownership_attr("destroy:" #handle_name)
#define handle(handle_name) \
	__ownership_attr("handle:" #handle_name)
#define static_handle(handle_name) \
	__ownership_attr("static_handle:" #handle_name)
/* A pointer-to-struct parameter whose pointee type carries its own
 * withtok(readable_elements(...))/withtok(writable_elements(...)) field
 * contracts (see include/memory_tokens.h). fields_established is a real,
 * two-sided obligation, not a blind trust of whatever the fields happen
 * to hold: MemoryContractChecker's checkPreCall independently verifies,
 * from the CALLER's own current knowledge, that every one of those field
 * contracts already holds for the argument BEFORE allowing the call --
 * exactly the same "prove it at the call site" discipline withtok(...)
 * Require parameters already get. Only once that is satisfied does
 * checkBeginFunction seed the callee's own reasoning (so a function
 * analyzed on its own, with no visible caller, is not forced to treat an
 * incoming struct's fields as permanently unprovable). Omitting this on
 * a parameter that is actually mutated is always safe -- the checker
 * just treats the incoming fields as unconstrained, as it always did. */
#define fields_established \
	__ownership_attr("fields_established")
/* A bare, function-level marker: this function's return value is a real
 * result, not an advisory one, and must not be silently discarded.
 * tools/clang/FallibleResultChecker.cpp's ntlibc.FallibleResult reads this
 * back off the callee instead of keeping its own hardcoded name list. */
#define fallible \
	__ownership_attr("fallible")
/* Two more bare, function-level markers, both read off the callee's
 * redecls the same way fallible is. They are related but genuinely
 * distinct real-world facts -- not two spellings of the same thing -- so
 * a function can carry either, both, or neither:
 *   - async_signal_safe: this function is on POSIX's own Async-Signal-Safe
 *     Functions table, so it may be called from within a signal handler.
 *     tools/clang/SignalSafetyChecker.cpp's asyncSafe() reads this back
 *     instead of keeping its own hardcoded copy of that POSIX table.
 *     Several members of that table (sigemptyset(), getpid(), umask(),
 *     kill(), sleep(), ...) do no I/O at all, and conversely several real
 *     I/O calls (mmap(), ioctl(), pread(), ...) are NOT on the table
 *     (their libc implementations may take an internal lock), so this is
 *     not implied by, and does not imply, io_operation below.
 *   - io_operation: this function performs I/O or a syscall, which
 *     tools/clang/PurityChecker.cpp's isIoCall() treats as a real,
 *     externally observable side effect that disqualifies
 *     __attribute__((pure)) eligibility. Reads this back instead of
 *     keeping its own hardcoded I/O name list.
 * A function commonly carries both (e.g. read(), write(), open()) since
 * most async-signal-safe calls are themselves I/O, but neither table is a
 * subset of the other -- see the two bullets above. */
#define async_signal_safe \
	__ownership_attr("async_signal_safe")
#define io_operation \
	__ownership_attr("io_operation")

#endif
