/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The private shape of FILE, and the helpers shared between the files in
 * src/stdio/.  Nothing here is visible outside this directory: callers
 * only ever see the incomplete struct _IO_FILE that <stdio.h> declares.
 *
 * A FILE owns one buffer that is either full of unread bytes (a "read"
 * buffer, rpos..rend valid) or holding bytes not yet written (a "write"
 * buffer, wpos pending) but never both at once; switching direction
 * flushes or un-reads as fseek would.  A file backed by memory
 * (fmemopen/open_memstream) skips this buffer entirely and is served
 * directly out of the memory block, since there is no fd to be economical
 * about calling into.
 */
#ifndef _NTLIBC_STDIO_IMPL_H
#define _NTLIBC_STDIO_IMPL_H

#include <stdio.h>
#include <sys/types.h>
#include <wchar.h>
#include "libc.h"

struct _IO_FILE {
	int fd;                 /* -1 for a memory-backed FILE */
	unsigned char eof;
	unsigned char err;
	unsigned char bufmode;   /* _IOFBF, _IOLBF, _IONBF */
	unsigned char user_buf;  /* the buffer was given by setvbuf: don't free it */
	unsigned char readable;
	unsigned char writable;
	unsigned char is_mem;    /* fmemopen/open_memstream */
	unsigned char mem_dynamic; /* open_memstream: mem_buf grows and is reported back */
	unsigned char wmem;      /* open_wmemstream: mem_buf holds wchar_t, not bytes */
	unsigned char mem_owned; /* fmemopen(NULL,...): mem_buf is ours, free it at fclose */
	unsigned char mem_append; /* fmemopen(...,"a"): every write goes to the end of
	                          * the contents, not to the file position */
	unsigned char no_close;  /* fclose must not close fd (stdin/out/err) */

	unsigned char *buf withtok(writable_span(bufsz));
	size_t bufsz;
	size_t rpos, rend;       /* unread bytes buf[rpos..rend) */
	size_t wpos;             /* unwritten bytes buf[0..wpos) */

	int unget[8];
	int nunget;

	/* Wide-character side (src/stdio/wide.c).  `wide` is fwide()'s
	 * orientation: <0 byte, 0 undecided, >0 wide.  The two mbstate_t
	 * are the read and write conversion states -- separate, because a
	 * read-write stream can be mid-character in one direction while the
	 * other is at rest, and because this target's 16-bit wchar_t means
	 * the READ state can hold a low surrogate owed to the caller while
	 * the WRITE state holds a high surrogate awaiting its partner (see
	 * src/stdlib/mbrtowc.c).  wunget is ungetwc()'s single pushback
	 * slot: the byte `unget` array above cannot serve, because a wide
	 * character pushed back after conversion has no byte form to put
	 * there and POSIX guarantees only one level of wide pushback. */
	int wide;
	mbstate_t wst_in, wst_out;
	wchar_t wunget;
	int nwunget;

	/* fmemopen / open_memstream */
	unsigned char *mem_buf withtok(writable_span(mem_size));
	size_t mem_size;         /* allocated capacity */
	size_t mem_len;          /* logical length (the string so far) */
	size_t mem_pos;          /* current offset */
	char **mem_out_ptr;      /* open_memstream: where to store mem_buf on flush */
	size_t *mem_out_size;    /* open_memstream: where to store mem_len on flush */

	pid_t pid;               /* >0 if popen()ed: pclose waits for it */

	struct _IO_FILE *next;   /* every open FILE, for __stdio_exit */
};

/* Every FILE * internal helper below is dereferenced unconditionally
 * in its own body, first statement in most cases (src/stdio/file.c,
 * buf.c, wide.c), the same required, non-optional handle as every
 * public stdio function above (include/stdio.h's own comment) --
 * every one of this tree's own call sites already holds a FILE * whose
 * own caller has already validated it, never a fresh, possibly-null
 * value from outside. mode is required too: __fmodeflags's own first
 * statement (`switch (mode[0])`) dereferences it. */
int __fmodeflags(const char *mode) __attribute__((nonnull(1)));

/* Allocate the read/write buffer (lazily: not every FILE ever needs one,
 * e.g. one only ever fwrite()n in chunks bigger than BUFSIZ). */
void __ensure_buf(FILE *f) __attribute__((nonnull(1)));

/* Allocate a FILE around an already-open fd, link it into the open list.
 * withtok(file_stream_open) mirrors src/dirent/opendir.c's alloc_dir(): the
 * internal allocation (__malloc, internal_heap_allocated) is a declared
 * one-hop implementation of file_stream_open, so every public producer that
 * returns __file_new()'s result proves its own withtok(file_stream_open)
 * contract instead of leaving it merely declared. */
withtok(file_stream_open)
FILE *__file_new(int fd, int flags);
/* Unlink from the open list and free the buffers a FILE owns (the fd is
 * the caller's problem). Deliberately NOT consume(file_stream_open):
 * fclose() is file_stream_open's one declared freer (see include/stdio.h's
 * own comment on piped_stream_open for why a family has exactly one), so
 * this internal helper -- shared by fclose() and freopen()'s error paths --
 * leaves releasing the FILE struct itself to its own caller's direct
 * __free() call instead of claiming that release itself. */
void __file_free(FILE *f) __attribute__((nonnull(1)));

/* Flush a pending write buffer to the fd (or memory).  0 or EOF+errno. */
int __fflush_locked(FILE *f) __attribute__((nonnull(1)));
/* Make ready to read: flush any pending write.  0 or EOF+errno. */
int __toread(FILE *f) __attribute__((nonnull(1)));
/* Make ready to write: un-read any buffered-ahead bytes via seek.  0 or EOF+errno. */
int __towrite(FILE *f) __attribute__((nonnull(1)));
/* Refill the read buffer.  Returns bytes available (0 at EOF), or -1 with err set. */
int __fill(FILE *f) __attribute__((nonnull(1)));

/* The raw operations every FILE goes through: fd read/write/seek, or the
 * memory-block equivalent when f->is_mem. */
ssize_t __file_read(FILE *f, void *buf withtok(writable_span(n)), size_t n)
	__attribute__((nonnull(1)));
ssize_t __file_write(FILE *f, const void *buf withtok(readable_span(n)), size_t n)
	__attribute__((nonnull(1)));
long long __file_seek(FILE *f, long long off, int whence) __attribute__((nonnull(1)));

/* One wide character from a stream, reporting how many BYTES it
 * consumed (src/stdio/scanf.c needs that to hand look-ahead back by
 * seeking, which is a byte offset). nbytes is genuinely optional
 * (`if (nbytes) *nbytes = 0;` guards every use of it in
 * src/stdio/wide.c's getwc_core()). */
wint_t __fgetwc_n(FILE *f, int *nbytes) __attribute__((nonnull(1)));

/* The list of every FILE currently open, for __stdio_exit. */
extern FILE *__stdio_files;

/* The core formatter/parser every printf/scanf variant calls into.
 * __vfprintf/__vfwprintf both dereference f unconditionally
 * (`sink.widemem = ... && f->wmem;` / `if (!f->wide) f->wide = 1;`)
 * and forward fmt straight into vfprintf_st(), which itself requires
 * it (src/stdio/printf.c). */
int __vfprintf(FILE *f, const char *fmt, va_list ap) __attribute__((nonnull(1, 2)));
/* __vfscanf/__vfwscanf forward fmt straight into vfscanf_st(), which
 * requires it; f is left unmarked the same way stdio.h's own
 * fscanf/vfscanf/vscanf are (see that header's comment). */
int __vfscanf(FILE *f, const char *fmt, va_list ap) __attribute__((nonnull(2)));
int __vfwprintf(FILE *f, const wchar_t *fmt, va_list ap) __attribute__((nonnull(1, 2)));
int __vfwscanf(FILE *f, const wchar_t *fmt, va_list ap) __attribute__((nonnull(2)));

/* The magnitude of a signed value that might be LLONG_MIN, whose
 * positive counterpart does not fit in any signed type.  -(unsigned long
 * long)sv is undefined for LLONG_MIN when written as a plain unary
 * minus on a signed operand, but is exactly the wanted bit pattern when
 * done on the unsigned value instead: C99 6.2.5p9 makes unsigned
 * negation wrap modulo 2**64.  A one-line __wraps helper keeps that
 * deliberate wraparound to this one expression, rather than blinding
 * every other overflow -fsanitize=unsigned-integer-overflow could catch
 * in the ~250-line callers around it (__vfprintf, __vfscanf). */
__wraps static inline unsigned long long __neg_mag(unsigned long long uv)
{
	return -uv;
}

/* Give a stream byte orientation if it has none yet (fwide.html: "a
 * byte input/output function has been applied to a stream without
 * orientation" makes it byte-oriented).  Called from the byte-level
 * primitives so fwide() reports the truth; deliberately a test rather
 * than an unconditional store so the branch is perfectly predicted. */
static inline void __byte_oriented(FILE *f) __attribute__((nonnull(1)));
static inline void __byte_oriented(FILE *f)
{
	if (!f->wide) f->wide = -1;
}

/* fread/fwrite/fgetc/fputc without the (nonexistent) locking; the public
 * fread etc are these under a name that matches. Each dereferences f
 * unconditionally via __byte_oriented(f) as its own first call, the
 * same required handle as everything else in this file; ptr is left
 * unmarked -- both __fread/__fwrite already return early (`if (!size
 * || !nmemb) return 0;`) before ptr would ever be touched, a real,
 * content-driven escape on the SIZE arguments, but unlike the mem*
 * family's own n == 0 convention there is no established "ptr must
 * still be valid at 0 count" contract for fread/fwrite to rely on
 * instead. */
size_t __fread(void *ptr, size_t size, size_t nmemb, FILE *f) __attribute__((nonnull(4)));
size_t __fwrite(const void *ptr, size_t size, size_t nmemb, FILE *f) __attribute__((nonnull(4)));
int __fgetc(FILE *f) __attribute__((nonnull(1)));
int __fputc(int c, FILE *f) __attribute__((nonnull(2)));

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
