/* This internal header, like the public C library headers, must use the
 * implementation-reserved namespace for its guard and its leaf-axiom
 * declarations so they cannot collide with user code.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _NTLIBC_OWNERSHIP_STUBS_H
#define _NTLIBC_OWNERSHIP_STUBS_H

#include <stddef.h>
#include <string_tokens.h>
#include <memory_tokens.h>

/* These declarations are the leaf axioms used to connect a concrete state
 * transition in a function body to its ownership-token contract.  They are
 * visible only to the static analyzer; ordinary builds erase each proof call
 * and therefore gain neither a runtime dependency nor a private ABI. */
#ifdef __clang_analyzer__


void __ownership_pthread_mutex_initialized(void * grant(pthread_mutex_unlocked));

void __ownership_pthread_mutex_locked(void * consume(pthread_mutex_unlocked) grant(pthread_mutex_locked));

void __ownership_pthread_mutex_unlocked(void * consume(pthread_mutex_locked) grant(pthread_mutex_unlocked));

void __ownership_pthread_mutex_destroyed(void * consume(pthread_mutex_unlocked));

void __ownership_pthread_spin_initialized(void * grant(pthread_spin_unlocked));
void __ownership_pthread_spin_locked(void * consume(pthread_spin_unlocked) grant(pthread_spin_locked));
void __ownership_pthread_spin_unlocked(void * consume(pthread_spin_locked) grant(pthread_spin_unlocked));
void __ownership_pthread_spin_destroyed(void * consume(pthread_spin_unlocked));

void __ownership_pthread_rwlock_initialized(void * grant(pthread_rwlock_unlocked));
void __ownership_pthread_rwlock_read_locked(void *
	consume_any(pthread_rwlock_unlocked) consume_any(pthread_rwlock_shared)
	grant(pthread_rwlock_shared));
void __ownership_pthread_rwlock_write_locked(void *
	consume(pthread_rwlock_unlocked) grant(pthread_rwlock_exclusive));
void __ownership_pthread_rwlock_unlocked(void *
	consume_any(pthread_rwlock_shared) consume_any(pthread_rwlock_exclusive)
	grant(pthread_rwlock_unlocked));
void __ownership_pthread_rwlock_destroyed(void *
	consume(pthread_rwlock_unlocked));

void __ownership_string_terminated(const void * grant(null_terminated));
void __ownership_string_invalidated(void * drop(null_terminated));
void __ownership_readable_span(
	const void *data grant(readable_span(length)), size_t length);
void __ownership_writable_span(
	void *data grant(writable_span(length)), size_t length);
void __ownership_disjoint_span(
	void *first grant(disjoint_span(second, length)), const void *second,
	size_t length);

#else

#define __ownership_pthread_mutex_initialized(object) ((void)0)
#define __ownership_pthread_mutex_locked(object) ((void)0)
#define __ownership_pthread_mutex_unlocked(object) ((void)0)
#define __ownership_pthread_mutex_destroyed(object) ((void)0)
#define __ownership_pthread_spin_initialized(object) ((void)0)
#define __ownership_pthread_spin_locked(object) ((void)0)
#define __ownership_pthread_spin_unlocked(object) ((void)0)
#define __ownership_pthread_spin_destroyed(object) ((void)0)
#define __ownership_pthread_rwlock_initialized(object) ((void)0)
#define __ownership_pthread_rwlock_read_locked(object) ((void)0)
#define __ownership_pthread_rwlock_write_locked(object) ((void)0)
#define __ownership_pthread_rwlock_unlocked(object) ((void)0)
#define __ownership_pthread_rwlock_destroyed(object) ((void)0)
#define __ownership_string_terminated(object) ((void)0)
#define __ownership_string_invalidated(object) ((void)0)
#define __ownership_readable_span(object, length) ((void)0)
#define __ownership_writable_span(object, length) ((void)0)
#define __ownership_disjoint_span(first, second, length) ((void)0)

#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
