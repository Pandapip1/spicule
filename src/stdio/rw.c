/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Byte- and block-oriented reads and writes: fgetc/fputc and their many
 * aliases, fread/fwrite, fgets/fputs/puts, ungetc, getdelim/getline.
 * There is no locking (see flockfile in file.c), so the plain and
 * _unlocked names are the same function.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- GNU feature-test macro has its specified reserved spelling
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include "ownership_stubs.h"
#include "stdio_impl.h"

int __fgetc(FILE *f)
{
	__byte_oriented(f);
	if (f->nunget) return f->unget[--f->nunget];
	if (!f->readable) { errno = EBADF; f->err = 1; return EOF; }
	if (__toread(f) < 0) return EOF;
	if (f->bufmode == _IONBF) {
		unsigned char c;
		ssize_t n = __file_read(f, &c, 1);
		if (n < 0) { f->err = 1; return EOF; }
		if (n == 0) { f->eof = 1; return EOF; }
		return c;
	}
	if (f->rpos >= f->rend && __fill(f) <= 0) return EOF;
	return f->buf[f->rpos++];
}

int __fputc(int c, FILE *f)
{
	unsigned char ch = (unsigned char)c;
	__byte_oriented(f);
	if (!f->writable) { errno = EBADF; f->err = 1; return EOF; }
	if (__towrite(f) < 0) return EOF;
	if (f->bufmode == _IONBF) {
		ssize_t n = __file_write(f, &ch, 1);
		if (n < 1) { f->err = 1; return EOF; }
		return ch;
	}
	__ensure_buf(f);
	if (!f->buf) { f->err = 1; return EOF; }
	f->buf[f->wpos++] = ch;
	if (f->wpos >= f->bufsz || (f->bufmode == _IOLBF && ch == '\n')) {
		if (__fflush_locked(f) < 0) return EOF;
	}
	return ch;
}

int fgetc(FILE *f) { return __fgetc(f); }
int getc(FILE *f) { return __fgetc(f); }
int getchar(void) { return __fgetc(stdin); }
int getc_unlocked(FILE *f) { return __fgetc(f); }
int getchar_unlocked(void) { return __fgetc(stdin); }

int fputc(int c, FILE *f) { return __fputc(c, f); }
int putc(int c, FILE *f) { return __fputc(c, f); }
int putchar(int c) { return __fputc(c, stdout); }
int putc_unlocked(int c, FILE *f) { return __fputc(c, f); }
int putchar_unlocked(int c) { return __fputc(c, stdout); }

int ungetc(int c, FILE *f)
{
	if (c == EOF || !f->readable) return EOF;
	if (f->nunget >= (int)(sizeof f->unget / sizeof f->unget[0])) return EOF;
	__byte_oriented(f);
	f->unget[f->nunget++] = (unsigned char)c;
	f->eof = 0;
	return (unsigned char)c;
}

size_t __fread(void *ptr withtok(writable_span(size * nmemb)),
	size_t size, size_t nmemb, FILE *f)
{
	size_t total, got = 0;
	unsigned char *p = ptr;

	__byte_oriented(f);
	if (!size || !nmemb) return 0;
	if (nmemb > SIZE_MAX / size) {
		errno = EOVERFLOW;
		f->err = 1;
		return 0;
	}
	total = size * nmemb;
	unsafe_assume_writable_span(ptr, total);
	if (!f->readable) { errno = EBADF; f->err = 1; return 0; }
	while (f->nunget && got < total) p[got++] = (unsigned char)f->unget[--f->nunget];
	if (got < total && __toread(f) < 0) return got / size;
	while (got < total) {
		size_t avail = f->rend - f->rpos;
		if (avail) {
			size_t n = total - got;
			size_t i;
			if (n > avail) n = avail;
			for (i = 0; i < n; i++) p[got + i] = f->buf[f->rpos + i];
			f->rpos += n;
			got += n;
			continue;
		}
		if (total - got >= (f->bufsz ? f->bufsz : BUFSIZ)) {
			ssize_t n = __file_read(f, p + got, total - got);
			if (n < 0) { f->err = 1; break; }
			if (n == 0) { f->eof = 1; break; }
			got += (size_t)n;
			continue;
		}
		if (__fill(f) <= 0) break;
	}
	return got / size;
}

size_t __fwrite(const void *ptr withtok(readable_span(size * nmemb)),
	size_t size, size_t nmemb, FILE *f)
{
	size_t total, put = 0;
	const unsigned char *p = ptr;

	__byte_oriented(f);
	if (!size || !nmemb) return 0;
	if (nmemb > SIZE_MAX / size) {
		errno = EOVERFLOW;
		f->err = 1;
		return 0;
	}
	total = size * nmemb;
	if (!f->writable) { errno = EBADF; f->err = 1; return 0; }
	if (__towrite(f) < 0) return 0;
	while (put < total) {
		size_t room, n;
		__ensure_buf(f);
		if (!f->buf) { f->err = 1; break; }
		if (f->wpos == 0 && total - put >= f->bufsz) {
			unsafe_assume_readable_span(p + put, total - put);
			ssize_t r = __file_write(f, p + put, total - put);
			if (r <= 0) { f->err = 1; break; }
			put += (size_t)r;
			continue;
		}
		room = f->bufsz - f->wpos;
		n = total - put;
		if (n > room) n = room;
		{
			int nl = 0;
			size_t i;
			if (f->bufmode == _IOLBF) {
				size_t k;
				for (k = 0; k < n; k++) if (p[put + k] == '\n') { nl = 1; break; }
			}
			for (i = 0; i < n; i++) f->buf[f->wpos + i] = p[put + i];
			f->wpos += n;
			put += n;
			if (f->wpos >= f->bufsz || nl) {
				if (__fflush_locked(f) < 0) break;
			}
		}
	}
	return put / size;
}

size_t fread(void *__restrict ptr withtok(writable_span(size * nmemb)),
	size_t size, size_t nmemb, FILE *__restrict f) { return __fread(ptr, size, nmemb, f); }
size_t fwrite(const void *__restrict ptr withtok(readable_span(size * nmemb)),
	size_t size, size_t nmemb, FILE *__restrict f) { return __fwrite(ptr, size, nmemb, f); }

char *fgets(char *__restrict s, int n, FILE *__restrict f)
{
	int i = 0, c;
	if (n <= 0) return 0;
	if (!f->readable) { errno = EBADF; f->err = 1; return 0; }
	for (; i < n - 1; ) {
		c = __fgetc(f);
		if (c == EOF) { if (i == 0) return 0; break; }
		s[i++] = (char)c;
		if (c == '\n') break;
	}
	s[i] = 0;
	return s;
}

#if __STDC_VERSION__ < 201112L
char *gets(char *s)
{
	int i = 0, c;
	for (;;) {
		c = __fgetc(stdin);
		if (c == EOF) { if (i == 0) return 0; break; }
		if (c == '\n') break;
		s[i++] = (char)c;
	}
	s[i] = 0;
	return s;
}
#endif

int fputs(const char *__restrict s, FILE *__restrict f)
{
	size_t n = strlen(s);
	return __fwrite(s, 1, n, f) == n ? 0 : EOF;
}

int puts(const char *s withtok(null_terminated))
{
	if (fputs(s, stdout) == EOF) return EOF;
	if (__fputc('\n', stdout) == EOF) return EOF;
	return 0;
}

ssize_t getdelim(char **__restrict buf, size_t *__restrict n, int delim, FILE *__restrict f)
{
	size_t cap, len = 0;
	char *b;
	int c;

	/* clang-tidy 21's unix.Malloc double-counts the one legitimate realloc
	 * in getline()'s inlined call to getdelim() as a double-free; one call
	 * cannot release `*buf` twice.  Suppressed per site so the rest of the
	 * function still gets checked. */
	if (!buf || !n) { errno = EINVAL; return -1; }
	cap = *buf ? *n : 0;
	b = *buf;

	if (!f->readable) { errno = EBADF; f->err = 1; return -1; }
	/* realloc, not malloc: `*buf` non-null with `*n` zero is a legal
	 * caller state, and malloc'ing over it would overwrite -- and so
	 * leak -- the buffer the caller handed us.  realloc(0, n) is
	 * malloc(n), and a failing realloc leaves the caller's block intact,
	 * which is exactly what `*buf` still points at on the error return. */
	if (!b || cap == 0) {
		char *nb = realloc(b, 128); // NOLINT(clang-analyzer-unix.Malloc) -- see the note above getdelim()
		if (!nb) { errno = ENOMEM; return -1; }
		b = nb; cap = 128;
	}
	for (;;) {
		c = __fgetc(f);
		if (c == EOF) {
			if (len == 0) { *buf = b; *n = cap; return -1; }
			break;
		}
		if (len >= cap - 1) {
			size_t nc;
			if (!__array_next_capacity(cap, len, 2, 128, 1, &nc)) {
				*buf = b; *n = cap; errno = ENOMEM; return -1;
			}
			char *nb = realloc(b, nc); // NOLINT(clang-analyzer-unix.Malloc) -- see the note above getdelim()
			if (!nb) { *buf = b; *n = cap; errno = ENOMEM; return -1; }
			b = nb; cap = nc;
		}
		b[len++] = (char)c; // NOLINT(clang-analyzer-unix.Malloc) -- see the note above getdelim()
		if (c == delim) break;
	}
	b[len] = 0;
	*buf = b;
	*n = cap;
	return (ssize_t)len;
}

ssize_t getline(char **__restrict buf, size_t *__restrict n, FILE *__restrict f)
{
	return getdelim(buf, n, '\n', f); // NOLINT(clang-analyzer-unix.Malloc) -- see the note above getdelim()
}

// NOLINTEND(misc-include-cleaner)
