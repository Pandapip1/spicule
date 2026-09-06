/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef _STDLIB_H
#define _STDLIB_H

#include <features.h>
#include <allocation_tokens.h>
#include <ownership.h>
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
#define __NEED_wchar_t

#include <bits/alltypes.h>

int atoi (const char *);
long atol (const char *);
long long atoll (const char *);
double atof (const char *);

float strtof (const char *__restrict, char **__restrict endptr_advances);
double strtod (const char *__restrict, char **__restrict endptr_advances);
long double strtold (const char *__restrict, char **__restrict endptr_advances);

long strtol (const char *__restrict, char **__restrict endptr_advances, int);
unsigned long strtoul (const char *__restrict, char **__restrict endptr_advances, int);
long long strtoll (const char *__restrict, char **__restrict endptr_advances, int);
unsigned long long strtoull (const char *__restrict, char **__restrict endptr_advances, int);

int rand (void);
void srand (unsigned);

withtok(heap_allocated)
withtok(writable_span(size))
void *malloc (size_t size);
withtok(heap_allocated)
withtok(writable_span(count * size))
void *calloc (size_t count, size_t size);
withtok(heap_allocated)
withtok(writable_span(size))
void *realloc (void * consume_if_nonnull_return(heap_allocated), size_t size);
void free (void * consume(heap_allocated));
withtok(heap_allocated)
withtok(writable_span(size))
void *aligned_alloc(size_t alignment, size_t size);

async_signal_safe
io_operation
_Noreturn void abort (void);
int atexit (void (*) (void));
io_operation
_Noreturn void exit (int);
async_signal_safe
_Noreturn void _Exit (int);
int at_quick_exit (void (*) (void));
_Noreturn void quick_exit (int);

/* Unlike getenv, setenv()/unsetenv() below deliberately check their own
 * name argument and return EINVAL on NULL, so they are left unmarked --
 * nonnull there would tell the compiler that live guard is dead code. */
withtok(null_terminated)
char *getenv (const char * withtok(null_terminated)) __attribute__((nonnull(1)));

int system (const char *);

void *bsearch (const void *, const void *, size_t, size_t, int (*)(const void *, const void *));
void qsort (void *, size_t, size_t, int (*)(const void *, const void *));

int abs (int) __attribute__((__pure__));
long labs (long) __attribute__((__pure__));
long long llabs (long long) __attribute__((__pure__));

typedef struct { int quot, rem; } div_t;
typedef struct { long quot, rem; } ldiv_t;
typedef struct { long long quot, rem; } lldiv_t;

div_t div (int, int) __attribute__((__pure__));
ldiv_t ldiv (long, long) __attribute__((__pure__));
lldiv_t lldiv (long long, long long) __attribute__((__pure__));

int mblen (const char *, size_t);
int mbtowc (wchar_t *__restrict, const char *__restrict, size_t);
int wctomb (char *, wchar_t);
size_t mbstowcs (wchar_t *__restrict, const char *__restrict, size_t);
size_t wcstombs (char *__restrict, const wchar_t *__restrict, size_t);

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

#define MB_CUR_MAX (__ctype_get_mb_cur_max())
size_t __ctype_get_mb_cur_max(void);

#define RAND_MAX (0x7fffffff)

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)

#define WNOHANG    1
#define WUNTRACED  2

#define WEXITSTATUS(s) (((s) & 0xff00) >> 8)
#define WTERMSIG(s) ((s) & 0x7f)
#define WSTOPSIG(s) WEXITSTATUS(s)
#define WIFEXITED(s) (!WTERMSIG(s))
#define WIFSTOPPED(s) ((short)((((unsigned)(s)&0xffff)*0x10001u)>>8) > 0x7f00)
#define WIFSIGNALED(s) (((s)&0xffff)-1U < 0xffu)

int posix_memalign (void **, size_t, size_t);
int setenv (const char *, const char *, int);
int unsetenv (const char *);
int mkstemp (char *);
int mkostemp (char *, int);
char *mkdtemp (char *);
int getsubopt (char **, char *const *, char **) __attribute__((nonnull(1, 2, 3)));
int rand_r (unsigned *) __attribute__((nonnull(1)));

#endif


#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
withtok(heap_allocated)
char *realpath (const char *__restrict,
	char *__restrict withtok(heap_allocated));
long int random (void);
void srandom (unsigned int);
char *initstate (unsigned int, char *, size_t);
char *setstate (char *);
/* Unlike setenv/unsetenv, putenv does not opt into the defensive
 * EINVAL-on-NULL convention. */
int putenv (char *) __attribute__((nonnull(1)));
int posix_openpt (int);  /* undefined-ok: Unix98 PTY allocation has
	no NT counterpart; grantpt/unlockpt/ptsname[_r] below share this
	reason. Real on Linux (/dev/ptmx plus TIOCGPTN/TIOCSPTLCK). */
int grantpt (int);  /* undefined-ok: see posix_openpt */
int unlockpt (int);  /* undefined-ok: see posix_openpt */
char *ptsname (int);  /* undefined-ok: see posix_openpt */
char *l64a (long);
long a64l (const char *) __attribute__((nonnull(1)));
/* setkey() reads all 64 elements of key unconditionally -- same DES
 * machinery as crypt()/encrypt() in unistd.h. */
void setkey (const char *) __attribute__((nonnull(1)));
double drand48 (void);
double erand48 (unsigned short [3]);
long int lrand48 (void);
long int nrand48 (unsigned short [3]);
long mrand48 (void);
long jrand48 (unsigned short [3]);
void srand48 (long);
unsigned short *seed48 (unsigned short [3]);
void lcong48 (unsigned short [7]);
#endif

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#include <alloca.h>
/* mkstemps()/mkostemps() are deliberately left unmarked: neither
 * dereferences tmpl directly, only forwarding it onward. */
char *mktemp (char *) __attribute__((nonnull(1)));
int mkstemps (char *, int);
int mkostemps (char *, int, int);
withtok(heap_allocated)
void *valloc (size_t);
withtok(heap_allocated)
void *memalign(size_t, size_t);
size_t malloc_usable_size(void *);
/* Real on Linux (/proc/loadavg); undefined-ok on NT, whose process
 * model has no run-queue-length average to report. */
int getloadavg(double *, int);
int clearenv(void);
#define WCOREDUMP(s) ((s) & 0x80)
#define WIFCONTINUED(s) ((s) == 0xffff)
withtok(heap_allocated)
withtok(writable_span(count * size))
void *reallocarray (void * consume_if_nonnull_return(heap_allocated),
                    size_t count, size_t size);
void qsort_r (void *, size_t, size_t, int (*)(const void *, const void *, void *), void *);
#endif

#ifdef _GNU_SOURCE
int ptsname_r(int, char *, size_t);  /* undefined-ok: see posix_openpt */
/* gcvt()'s out is deliberately NOT marked: it is only ever forwarded
 * into sprintf(), never dereferenced by gcvt()'s own body. */
char *ecvt(double, int, int *, int *) __attribute__((nonnull(3, 4)));
char *fcvt(double, int, int *, int *) __attribute__((nonnull(3, 4)));
char *gcvt(double, int, char *);
#endif

#ifdef __cplusplus
}
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
