/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef _FEATURES_H
#define _FEATURES_H

#if defined(_ALL_SOURCE) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif

#if defined(_DEFAULT_SOURCE) && !defined(_BSD_SOURCE)
#define _BSD_SOURCE 1
#endif

#if !defined(_POSIX_SOURCE) && !defined(_POSIX_C_SOURCE) \
 && !defined(_XOPEN_SOURCE) && !defined(_GNU_SOURCE) \
 && !defined(_BSD_SOURCE) && !defined(__STRICT_ANSI__)
#define _BSD_SOURCE 1
#define _XOPEN_SOURCE 700
#endif

#if __STDC_VERSION__ >= 199901L
#define __restrict restrict
#elif !defined(__GNUC__)
#define __restrict
#endif

#if __STDC_VERSION__ >= 199901L || defined(__cplusplus)
#define __inline inline
#elif !defined(__GNUC__)
#define __inline
#endif

#if __STDC_VERSION__ >= 201112L
#elif defined(__GNUC__)
#define _Noreturn __attribute__((__noreturn__))
#else
#define _Noreturn
#endif

/* __wraps marks a function's wraparound as deliberate (unsigned overflow is
 * modular arithmetic, not UB, so -fsanitize=integer still flags it unless
 * excluded). Only clang has both the attribute and that sanitizer check;
 * gcc warns under -Wattributes on unknown sanitizer names, so the
 * __clang__ guard matters. Internal to the library only. */
#ifdef _SPICULE_INTERNAL
#ifndef __has_attribute
#define __has_attribute(x) 0
#endif
#if defined(__clang__) && __has_attribute(no_sanitize)
#define __wraps __attribute__((no_sanitize("unsigned-integer-overflow", \
                                           "unsigned-shift-base")))
#endif
#ifndef __wraps
#define __wraps
#endif
#endif

#define __REDIR(x,y) __typeof__(x) x __asm__(#y) // NOLINT(bugprone-macro-parentheses) -- x is the redirected declaration's identifier, where an expression-style wrapper is not applicable

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
