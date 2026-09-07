/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Portable wrappers over Clang's Thread Safety Analysis attributes
 * (`-Wthread-safety`): `capability`, `guarded_by`, `pt_guarded_by`,
 * `acquire_capability`, `release_capability`, `requires_capability`, and
 * friends.  This is "guarded-by"/lockset analysis -- it proves that a
 * piece of data is only ever touched while a specific lock is held --
 * which is a different question from the one
 * tools/clang/LockDisciplineChecker.cpp answers (that checker proves the
 * lock itself is acquired, released, waited on, and destroyed correctly;
 * it has no notion of which data a lock protects at all).
 *
 * This is internal-only: spicule's public pthread_mutex_t/pthread_rwlock_t
 * are opaque (include/pthread.h), so there is little to say about them at
 * the public API surface.  The payoff here is spicule's own internal
 * globals and the internal locks (src/internal/libc.h's __sig_lock() and
 * the ntdll PEB lock) that are supposed to guard them -- see the
 * SPICULE_GUARDED_BY() call sites for the specific globals.
 *
 * Every macro below expands to nothing UNLESS BOTH of these hold:
 *
 *   1. the compiler is Clang (tcc and gcc have no such attributes, and
 *      would either choke on or silently ignore them -- this project
 *      does not gamble on "silently ignore"); and
 *   2. SPICULE_LOCKSET_ANALYSIS is defined, which nothing in a real build
 *      ever does -- only tools/lint.sh's `lockset` stage passes
 *      -DSPICULE_LOCKSET_ANALYSIS, alongside -Wthread-safety itself.
 *
 * So a plain `clang -c` build of this tree -- including every other
 * clang-based lint.sh stage, none of which defines
 * SPICULE_LOCKSET_ANALYSIS -- sees precisely the same AST it saw before
 * this file existed: these macros do not merely fail to warn, they fail
 * to emit any attribute at all outside the one stage that asked for them.
 * tcc and gcc never see anything other than empty expansions, ever.
 *
 * The shape (a THREAD_ANNOTATION_ATTRIBUTE__(x) chokepoint, individual
 * macros built on top of it) is the well-known pattern several projects
 * with clang+gcc/MSVC portability constraints use for this same feature
 * (Abseil's thread_annotations.h is the best-known example) -- written
 * here from scratch against spicule's own naming and gating conventions,
 * not copied from any of them.
 */
#ifndef _SPICULE_THREAD_ANNOTATIONS_H
#define _SPICULE_THREAD_ANNOTATIONS_H

#if defined(__clang__) && defined(SPICULE_LOCKSET_ANALYSIS)
#define SPICULE_THREAD_ANNOTATION_ATTRIBUTE__(x) __attribute__((x))
#else
#define SPICULE_THREAD_ANNOTATION_ATTRIBUTE__(x)
#endif

/* Marks a type as a lock: something SPICULE_ACQUIRE()/SPICULE_RELEASE() can
 * be acquired/released on, and SPICULE_GUARDED_BY() can name.  `name` is
 * the capability kind clang's diagnostics print ("mutex" for anything
 * exclusive-only, "role" for shared/reader-writer capabilities). */
#define SPICULE_CAPABILITY(name) \
	SPICULE_THREAD_ANNOTATION_ATTRIBUTE__(capability(name))

/* The data a lock protects.  `lock` must be a capability -- one of the
 * SPICULE_CAPABILITY() tokens below, or a real lock object of such a
 * type. */
#define SPICULE_GUARDED_BY(lock) \
	SPICULE_THREAD_ANNOTATION_ATTRIBUTE__(guarded_by(lock))
#define SPICULE_PT_GUARDED_BY(lock) \
	SPICULE_THREAD_ANNOTATION_ATTRIBUTE__(pt_guarded_by(lock))

/* Applied to the function that acquires/releases `lock` (or, for a
 * try-lock, that reports success/failure of acquiring it). */
#define SPICULE_ACQUIRE(...) \
	SPICULE_THREAD_ANNOTATION_ATTRIBUTE__(acquire_capability(__VA_ARGS__))
#define SPICULE_RELEASE(...) \
	SPICULE_THREAD_ANNOTATION_ATTRIBUTE__(release_capability(__VA_ARGS__))
#define SPICULE_TRY_ACQUIRE(success, ...) \
	SPICULE_THREAD_ANNOTATION_ATTRIBUTE__(try_acquire_capability(success, __VA_ARGS__))

/* Applied to a function that may only be called while `lock` is already
 * held by the caller (as opposed to SPICULE_ACQUIRE(), which is the
 * function that takes the lock in the first place). */
#define SPICULE_REQUIRES(...) \
	SPICULE_THREAD_ANNOTATION_ATTRIBUTE__(requires_capability(__VA_ARGS__))

/* Opts a function's body out of lockset checking entirely -- for the rare
 * function whose locking discipline this analysis cannot express (a
 * fork()-child-side reset that runs single-threaded and so needs no lock
 * at all, say), rather than living with a permanent false positive. */
#define SPICULE_NO_THREAD_SAFETY_ANALYSIS \
	SPICULE_THREAD_ANNOTATION_ATTRIBUTE__(no_thread_safety_analysis)

#if defined(__clang__) && defined(SPICULE_LOCKSET_ANALYSIS)
/* A capability token: an otherwise-inert type that exists only so a
 * SPICULE_GUARDED_BY()/SPICULE_ACQUIRE()/SPICULE_RELEASE() call has an
 * object to name.  One extern object of this type per real internal
 * lock -- see src/internal/libc.h for the tokens this tree declares
 * (__spicule_sig_lock_token, __spicule_peb_lock_token) and the functions
 * that acquire/release each one. */
typedef struct SPICULE_CAPABILITY("mutex") __spicule_lock_capability {
	char __opaque;
} __spicule_lock_capability;
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
