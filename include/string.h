/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef	_STRING_H
#define	_STRING_H

#include <features.h>
#include <stdlib.h>
#include <memory_tokens.h>
#include <string_tokens.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
#define NULL 0L
#else
#define NULL ((void*)0)
#endif

#define __NEED_size_t
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)
#define __NEED_locale_t
#endif

#include <bits/alltypes.h>

/* mem/str family dest/src pointers are nonnull per ISO C 7.24, even at
 * size_t count == 0. A few functions below are deliberately left
 * unmarked where they have a real structural escape or haven't been
 * independently verified; called out individually where non-obvious. */
void *memcpy (void *__restrict dest
                  withtok(writable_span(n))
                  withtok(disjoint_span(src, n)),
              const void *__restrict src withtok(readable_span(n)), size_t n)
    __attribute__((nonnull(1, 2)));
void *memmove (void *dest withtok(writable_span(n)),
               const void *src withtok(readable_span(n)), size_t n)
    __attribute__((nonnull(1, 2)));
void *memset (void *dest withtok(writable_span(n)), int c, size_t n)
    __attribute__((nonnull(1)));
int memcmp (const void *vl withtok(readable_span(n)),
            const void *vr withtok(readable_span(n)), size_t n)
    __attribute__((nonnull(1, 2), __pure__));
void *memchr (const void *, int, size_t) __attribute__((nonnull(1), __pure__));

withtok(null_terminated)
char *strcpy (char *__restrict grant(null_terminated),
              const char *__restrict withtok(null_terminated));
char *strncpy (char *__restrict d withtok(writable_span(n)),
              const char *__restrict, size_t n);

withtok(null_terminated)
char *strcat (char *__restrict withtok(null_terminated) grant(null_terminated),
              const char *__restrict withtok(null_terminated));
/* s is deliberately not withtok(null_terminated): it may instead name n
 * readable bytes with no NUL. */
char *strncat (char *__restrict withtok(null_terminated),
              const char *__restrict, size_t)
    __attribute__((nonnull(1, 2)));

int strcmp (const char * withtok(null_terminated), const char * withtok(null_terminated))
    __attribute__((nonnull(1, 2), __pure__));
int strncmp (const char *, const char *, size_t) __attribute__((nonnull(1, 2), __pure__));

/* Forwards to strcmp(); pure holds because this tree supports only the
 * POSIX/C locale, so collation order is always plain byte order. */
int strcoll (const char * withtok(null_terminated), const char * withtok(null_terminated))
    __attribute__((__pure__));
size_t strxfrm (char *__restrict dest withtok(writable_span(n)),
                const char *__restrict withtok(null_terminated), size_t n);

withtok(null_terminated)
char *strchr (const char * withtok(null_terminated), int)
    __attribute__((nonnull(1), __pure__));
withtok(null_terminated)
char *strrchr (const char * withtok(null_terminated), int) __attribute__((__pure__));

/* c/s always dereferenced; unlike strtok_r's s below, there is no NULL
 * convention here. */
size_t strcspn (const char *, const char *) __attribute__((nonnull(1, 2), __pure__));
size_t strspn (const char *, const char *) __attribute__((nonnull(1, 2), __pure__));
char *strpbrk (const char *, const char *) __attribute__((nonnull(1, 2), __pure__));
withtok(null_terminated)
char *strstr (const char * withtok(null_terminated),
              const char * withtok(null_terminated))
    __attribute__((nonnull(1, 2), __pure__));
char *strtok (char *__restrict, const char *__restrict);

size_t strlen (const char * withtok(null_terminated))
    __attribute__((nonnull(1), __pure__));

/* pure is safe only because setlocale() never accepts anything but
 * "C"/"POSIX" here; a real strerror() whose message varies with
 * LC_MESSAGES could not be marked this way. */
withtok(null_terminated)
char *strerror (int) __attribute__((__pure__));

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)
#include <strings.h>
#endif

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)
/* s == NULL is a real, documented convention ("continue from *p"), not
 * an omission; sep and p are always required. */
char *strtok_r (char *__restrict, const char *__restrict, char **__restrict) __attribute__((nonnull(2, 3)));
int strerror_r (int err, char *buf withtok(writable_span(buflen)),
	size_t buflen);
char *stpcpy(char *__restrict, const char *__restrict) __attribute__((nonnull(1, 2)));
char *stpncpy(char *__restrict d withtok(writable_span(n)),
	const char *__restrict, size_t n) __attribute__((nonnull(1, 2)));
/* No nonnull yet: not independently verified for NULL-safety. */
size_t strnlen (const char *, size_t) __attribute__((__pure__));
/* tools/clang/ErrnoDisciplineChecker.cpp's ntlibc.ErrnoDiscipline:
 * src/string/strdup.c's and src/string/strndup.c's only failure return
 * (NULL) comes from malloc() (already errno-capable). */
grants_thread_token(errno_grounds)
withtok(heap_allocated)
withtok(null_terminated)
char *strdup (const char * withtok(null_terminated));
grants_thread_token(errno_grounds)
withtok(heap_allocated)
char *strndup (const char *, size_t);
withtok(null_terminated)
char *strsignal(int) __attribute__((__pure__));
/* strerror_l/strcoll_l ignore loc and forward to strerror()/strcoll();
 * see strerror's comment on why that's safe under this one-locale
 * design. */
withtok(null_terminated)
char *strerror_l (int, locale_t) __attribute__((__pure__));
int strcoll_l (const char * withtok(null_terminated),
               const char * withtok(null_terminated), locale_t)
    __attribute__((__pure__));
size_t strxfrm_l (char *__restrict dest withtok(writable_span(n)),
                  const char *__restrict withtok(null_terminated),
                  size_t n, locale_t);
#endif

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
void *memccpy (void *__restrict, const void *__restrict, int, size_t) __attribute__((nonnull(1, 2)));
#endif

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
/* sep is deliberately left unmarked: when *str is NULL, strsep()
 * returns before sep is ever touched (same "resume here" convention
 * as strtok_r's s above). */
char *strsep(char **, const char *) __attribute__((nonnull(1)));
/* strlcat's destination deliberately lacks withtok(null_terminated): only its
 * first n bytes are searched and it may contain no NUL in that range.  Its
 * source, however, is always traversed to a NUL, including when n is zero. */
size_t strlcat (char *, const char * withtok(null_terminated), size_t);
size_t strlcpy (char *__restrict, const char *__restrict, size_t);
void explicit_bzero (void *, size_t) __attribute__((nonnull(1)));
#endif

#ifdef _GNU_SOURCE
#define	strdupa(x)	strcpy(alloca(strlen(x)+1),x)
int strverscmp (const char *, const char *) __attribute__((nonnull(1, 2), __pure__));
/* returns_nonnull: both return paths are s plus pointer arithmetic
 * that only ever advances forward within the same string. */
withtok(null_terminated)
char *strchrnul(const char * withtok(null_terminated), int)
    __attribute__((nonnull(1), __pure__, returns_nonnull));
withtok(null_terminated)
char *strcasestr(const char * withtok(null_terminated),
                 const char * withtok(null_terminated))
    __attribute__((nonnull(1, 2), __pure__));
void *memmem(const void *, size_t, const void *, size_t) __attribute__((nonnull(1, 3), __pure__));
void *memrchr(const void *, int, size_t) __attribute__((nonnull(1), __pure__));
void *mempcpy(void *dest withtok(writable_span(n))
                  withtok(disjoint_span(src, n)),
              const void *src withtok(readable_span(n)), size_t n);
/* No basename() here: glibc's GNU basename (const, non-modifying) and
 * POSIX's <libgen.h> basename (may modify its argument) conflict, and
 * C23 forbids the old unprototyped compromise. Only <libgen.h>'s
 * POSIX basename exists, following musl's 1.2.5 change. */
#endif

#ifdef __cplusplus
}
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
