/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef _STDIO_H
#define _STDIO_H

#include <features.h>
#include <string_tokens.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
#define NULL 0L
#else
#define NULL ((void*)0)
#endif

#define __NEED_FILE
#define __NEED___isoc_va_list
#define __NEED_size_t

#if __STDC_VERSION__ < 201112L
#define __NEED_struct__IO_FILE
#endif

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)
#define __NEED_ssize_t
#define __NEED_off_t
#define __NEED_va_list
#endif

#include <bits/alltypes.h>

#define EOF (-1)

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define _IOFBF 0
#define _IOLBF 1
#define _IONBF 2

#define BUFSIZ 4096
#define FILENAME_MAX 4096
#define FOPEN_MAX 1000
#define TMP_MAX 10000
#define L_tmpnam 20

typedef union _G_fpos64_t {
	char __opaque[16];
	long long __lldata;
	double __align;
} fpos_t;

/* _Nonnull here is not just decoration: src/stdio/file.c defines all
 * three as `&stdin_f`/`&stdout_f`/`&stderr_f` -- the address of a real
 * static object, hence genuinely never null -- but that fact is only
 * visible in file.c's own translation unit; every other TU sees just
 * this extern declaration with no initializer. Without _Nonnull here,
 * Clang's analyzer (having no way to see across TUs) treats each of
 * these as an unconstrained global and explores a spurious "what if
 * this is actually null" path, which is what previously produced
 * tools/clang/ErrnoDisciplineChecker.cpp false positives in every
 * `argv[i]=="-" ? stdin : fopen(argv[i], ...)` loop (src/util/cut.c,
 * awk.c, and others): reaching the `!f` failure branch through stdin's
 * spurious null case, with no real fopen() call anywhere on that path
 * to blame, reads as "errno read with no proven prior call".
 *
 * Restricted to __clang_analyzer__ for the same reason
 * include/ownership.h's own __ownership_attr is: no normal compile --
 * tcc (which does not know this Clang-only qualifier at all), plain
 * clang, or gcc -- reads or benefits from it, so it stays entirely out
 * of their view rather than risk any of them handling a type qualifier
 * they were never meant to see. */
#if defined(__clang_analyzer__)
#define __stdio_stream_nonnull _Nonnull
#else
#define __stdio_stream_nonnull
#endif
extern FILE *__stdio_stream_nonnull const stdin;
extern FILE *__stdio_stream_nonnull const stdout;
extern FILE *__stdio_stream_nonnull const stderr;

#define stdin  (stdin)
#define stdout (stdout)
#define stderr (stderr)

/* Mirrors include/dirent.h's directory_stream_open exactly: DIR* and FILE*
 * are both an opaque, individually-heap-allocated handle that must be
 * released exactly once, so both ride AllocationLifetimeChecker's existing
 * leak-at-exit and double-release proof through this one declarative
 * contract, with no per-type checker code of its own. */
tokdef file_stream_open
	dynamic_storage
	implemented_by(internal_heap_allocated);

/* popen()/pclose() get their own family, implemented_by file_stream_open,
 * rather than sharing file_stream_open directly: every dynamic_storage
 * family in this codebase has exactly one declared terminal freer (see
 * e.g. internal_heap_allocated -> __free, platform_heap_allocated ->
 * __plat_dealloc), and fclose() is already file_stream_open's one -- a
 * second, independently declared consume(file_stream_open) on pclose()
 * would make tools/lint-allocation-lifetime.py's contract validator
 * unable to tell which of the two is the real freer. pclose()'s own body
 * still discharges its argument by calling fclose() on it (see
 * src/stdio/misc.c), one morphism hop down, exactly like any other
 * two-family producer/freer chain (e.g. widget_allocated ->
 * heap_allocated in tools/lint-allocation-lifetime-fixtures/safe.c). */
tokdef piped_stream_open
	dynamic_storage
	implemented_by(file_stream_open);

withtok(file_stream_open)
FILE *fopen(const char *__restrict withtok(null_terminated),
            const char *__restrict withtok(null_terminated));
/* freopen() reuses its own third argument's stream rather than acquiring a
 * fresh one (POSIX: "the original stream will be closed" and the same FILE
 * object is returned on success), so it is neither a file_stream_open
 * producer nor consumer -- the stream's identity does not change hands. */
FILE *freopen(const char *__restrict, const char *__restrict, FILE *__restrict) __attribute__((nonnull(3)));
/* Every stdio function below that takes a FILE * dereferences it
 * unconditionally, matching POSIX's "undefined on a stream that does
 * not designate an open file". fflush() is the deliberate exception:
 * fflush(NULL) is documented to flush every open stream, so its f is
 * left unmarked. */
fallible
int fclose(FILE * consume(file_stream_open)) __attribute__((nonnull(1)));

fallible
int remove(const char *);
/* tools/clang/ErrnoDisciplineChecker.cpp's ntlibc.ErrnoDiscipline:
 * src/stdio/misc.c's rename()/renameat() and both platforms'
 * __plat_rename() set errno on every failure return. */
grants_thread_token(errno_grounds)
fallible
async_signal_safe
io_operation
int rename(const char *, const char *);

int feof(FILE *) __attribute__((nonnull(1)));
int ferror(FILE *) __attribute__((nonnull(1)));
fallible
int fflush(FILE *);
void clearerr(FILE *) __attribute__((nonnull(1)));

fallible
int fseek(FILE *, long, int) __attribute__((nonnull(1)));
long ftell(FILE *) __attribute__((nonnull(1)));
void rewind(FILE *) __attribute__((nonnull(1)));

int fgetpos(FILE *__restrict, fpos_t *__restrict) __attribute__((nonnull(1, 2)));
fallible
int fsetpos(FILE *, const fpos_t *) __attribute__((nonnull(1, 2)));

size_t fread(void *__restrict ptr withtok(writable_span(size * nmemb)),
	size_t size, size_t nmemb, FILE *__restrict stream);
size_t fwrite(const void *__restrict ptr withtok(readable_span(size * nmemb)),
	size_t size, size_t nmemb, FILE *__restrict stream);

int fgetc(FILE *) __attribute__((nonnull(1)));
int getc(FILE *) __attribute__((nonnull(1)));
int getchar(void);
int ungetc(int, FILE *) __attribute__((nonnull(2)));

int fputc(int, FILE *) __attribute__((nonnull(2)));
int putc(int, FILE *) __attribute__((nonnull(2)));
int putchar(int);

char *fgets(char *__restrict, int, FILE *__restrict) __attribute__((nonnull(1, 3)));
#if __STDC_VERSION__ < 201112L
char *gets(char *);
#endif

int fputs(const char *__restrict, FILE *__restrict) __attribute__((nonnull(1, 2)));
int puts(const char * withtok(null_terminated)) __attribute__((nonnull(1)));

/* snprintf/vsnprintf's s is deliberately NOT marked: snprintf(s, 0,
 * fmt, ...) with s == NULL is real, POSIX-documented behaviour, unlike
 * sprintf/vsprintf which always write an unbounded amount and so
 * require s. */
int printf(const char *__restrict, ...) __attribute__((nonnull(1)));
int fprintf(FILE *__restrict, const char *__restrict, ...) __attribute__((nonnull(1, 2)));
int sprintf(char *__restrict, const char *__restrict, ...) __attribute__((nonnull(1, 2)));
int snprintf(char *__restrict, size_t, const char *__restrict, ...) __attribute__((nonnull(3)));

int vprintf(const char *__restrict, __isoc_va_list) __attribute__((nonnull(1)));
int vfprintf(FILE *__restrict, const char *__restrict, __isoc_va_list) __attribute__((nonnull(1, 2)));
int vsprintf(char *__restrict, const char *__restrict, __isoc_va_list) __attribute__((nonnull(1, 2)));
int vsnprintf(char *__restrict, size_t, const char *__restrict, __isoc_va_list) __attribute__((nonnull(3)));

/* f is deliberately left unmarked: fscanf/vfscanf/vscanf only forward
 * it into vfscanf_st(), never dereferencing it directly themselves. */
int scanf(const char *__restrict, ...) __attribute__((nonnull(1)));
int fscanf(FILE *__restrict, const char *__restrict, ...) __attribute__((nonnull(2)));
int sscanf(const char *__restrict, const char *__restrict, ...) __attribute__((nonnull(1, 2)));
int vscanf(const char *__restrict, __isoc_va_list) __attribute__((nonnull(1)));
int vfscanf(FILE *__restrict, const char *__restrict, __isoc_va_list) __attribute__((nonnull(2)));
int vsscanf(const char *__restrict, const char *__restrict, __isoc_va_list) __attribute__((nonnull(1, 2)));

void perror(const char *);

/* buf is genuinely optional: POSIX documents that a null buf gets one
 * allocated. */
int setvbuf(FILE *__restrict, char *__restrict, int, size_t) __attribute__((nonnull(1)));
void setbuf(FILE *__restrict, char *__restrict);

char *tmpnam(char *);
withtok(file_stream_open)
FILE *tmpfile(void);

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)
/* buf is genuinely optional: a null buf gets size bytes allocated. */
FILE *fmemopen(void *__restrict, size_t, const char *__restrict) __attribute__((nonnull(3)));
/* tools/clang/ErrnoDisciplineChecker.cpp's ntlibc.ErrnoDiscipline:
 * src/stdio/mem.c's open_memstream() sets errno on every failure
 * return, either via malloc() (already errno-capable) or its own
 * explicit `errno = EINVAL` for a null bufp/sizep. */
grants_thread_token(errno_grounds)
FILE *open_memstream(char **, size_t *);
withtok(file_stream_open)
FILE *fdopen(int, const char *);
withtok(piped_stream_open)
FILE *popen(const char *, const char *) __attribute__((nonnull(2)));
int pclose(FILE * consume(piped_stream_open)) __attribute__((nonnull(1)));
int fileno(FILE *) __attribute__((nonnull(1)));
int fseeko(FILE *, off_t, int) __attribute__((nonnull(1)));
off_t ftello(FILE *) __attribute__((nonnull(1)));
int dprintf(int, const char *__restrict, ...) __attribute__((nonnull(2)));
int vdprintf(int, const char *__restrict, __isoc_va_list) __attribute__((nonnull(2)));
/* flockfile/ftrylockfile/funlockfile are no-ops: there is no threading
 * here for f to be locked against. */
void flockfile(FILE *);
int ftrylockfile(FILE *);
void funlockfile(FILE *);
int getc_unlocked(FILE *) __attribute__((nonnull(1)));
int getchar_unlocked(void);
int putc_unlocked(int, FILE *) __attribute__((nonnull(2)));
int putchar_unlocked(int);
/* buf/n are deliberately left unmarked: a real, documented EINVAL check
 * covers their nullness, not an omission. */
ssize_t getdelim(char **__restrict, size_t *__restrict, int, FILE *__restrict) __attribute__((nonnull(4)));
ssize_t getline(char **__restrict, size_t *__restrict, FILE *__restrict) __attribute__((nonnull(3)));
grants_thread_token(errno_grounds)
fallible
int renameat(int, const char *, int, const char *);
char *ctermid(char *);
#define L_ctermid 20
#endif


#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)
#define P_tmpdir "/tmp"
withtok(heap_allocated)
char *tempnam(const char *, const char *);
#endif

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
void setlinebuf(FILE *) __attribute__((nonnull(1)));
int asprintf(char **, const char *, ...) __attribute__((nonnull(1, 2)));
int vasprintf(char **, const char *, __isoc_va_list) __attribute__((nonnull(1, 2)));
#endif

#if defined(_LARGEFILE64_SOURCE)
#define tmpfile64 tmpfile
#define fopen64 fopen
#define freopen64 freopen
#define fseeko64 fseeko
#define ftello64 ftello
#define fgetpos64 fgetpos
#define fsetpos64 fsetpos
#define fpos64_t fpos_t
#define off64_t off_t
#endif

#ifdef __cplusplus
}
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
