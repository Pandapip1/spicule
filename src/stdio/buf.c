/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * One buffer per FILE, used for reading ahead or writing, never both at
 * once; switching direction flushes a pending write or seeks back over
 * unconsumed read-ahead, the same trick fseek uses.
 *
 * __file_read/__file_write/__file_seek are the one place a fd and a
 * fmemopen/open_memstream block look the same.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- GNU feature-test macro has its specified reserved spelling
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include "ownership_stubs.h"
#include "stdio_impl.h"

ssize_t __file_read(FILE *f, void *buf withtok(writable_span(n)), size_t n)
{
	size_t i;
	if (f->is_mem) {
		size_t avail = f->mem_pos < f->mem_len ? f->mem_len - f->mem_pos : 0;
		if (n > avail) n = avail;
		if (n) {
			const unsigned char *src = f->mem_buf + f->mem_pos;
			for (i = 0; i < n; i++) ((unsigned char *)buf)[i] = src[i];
		}
		f->mem_pos += n;
		return (ssize_t)n;
	}
	if (f->fd < 0) { errno = EBADF; return -1; }
	return read(f->fd, buf, n);
}

/* Publishes an open_memstream()/open_wmemstream() buffer to the caller's
 * pointer and size after fflush()/fclose(). *sizep is min(mem_pos,
 * mem_len), not mem_len alone, so a seek-then-fflush reports the position
 * and not the high-water mark. The min is taken before dividing for the
 * wide case since both operands are byte counts. */
static void mem_publish(FILE *f)
{
	size_t n;

	if (!f->mem_dynamic) return;
	if (f->mem_out_ptr) *f->mem_out_ptr = (char *)f->mem_buf;
	if (!f->mem_out_size) return;
	n = f->mem_pos < f->mem_len ? f->mem_pos : f->mem_len;
	*f->mem_out_size = f->wmem ? n / sizeof(wchar_t) : n;
}

ssize_t __file_write(FILE *f, const void *buf withtok(readable_span(n)), size_t n)
{
	if (f->is_mem) {
		size_t avail;
		size_t need;
		/* mem_* stay byte counts even for open_wmemstream(), so term is
		 * the terminator width (a wide NUL or a byte NUL). */
		size_t term = f->wmem ? sizeof(wchar_t) : 1;
		/* fmemopen append mode resets the position to the end of the
		 * contents before every write, regardless of the last seek. */
		if (f->mem_append) f->mem_pos = f->mem_len;
		if (f->mem_dynamic) {
			if (f->mem_pos > (size_t)LLONG_MAX ||
			    n > (size_t)LLONG_MAX - f->mem_pos) {
				errno = EOVERFLOW;
				return -1;
			}
			need = f->mem_pos + n;
			if (need > SIZE_MAX - term) {
				errno = EOVERFLOW;
				return -1;
			}
			need += term;
			/* spicule's usable object-size range ends at PTRDIFF_MAX: offsets
			 * and differences within an allocated object must remain in the
			 * ABI's signed pointer-difference type.  Reject a larger request
			 * before the geometric growth itself crosses the size_t boundary. */
			if (need > (size_t)PTRDIFF_MAX) {
				errno = ENOMEM;
				return -1;
			}
			if (need > f->mem_size) {
				size_t ns = f->mem_size ? f->mem_size : 128;
				while (ns < need) {
					if (ns > (size_t)PTRDIFF_MAX / 2) { ns = need; break; }
					ns *= 2;
				}
				{
					unsigned char *nb = realloc(f->mem_buf, ns);
					if (!nb) { errno = ENOMEM; return -1; }
					f->mem_buf = nb;
					f->mem_size = ns;
				}
			}
		}
		avail = f->mem_pos < f->mem_size ? f->mem_size - f->mem_pos : 0;
		if (n > avail) n = avail;   /* fmemopen: silently truncate, like a full device */
		if (n) {
			unsigned char *dst = f->mem_buf + f->mem_pos;
			size_t i;
			for (i = 0; i < n; i++) dst[i] = ((const unsigned char *)buf)[i];
		}
		f->mem_pos += n;
		if (f->mem_pos > f->mem_len) f->mem_len = f->mem_pos;
		if (f->mem_len <= f->mem_size && term <= f->mem_size - f->mem_len)
			memset(f->mem_buf + f->mem_len, 0, term);
		mem_publish(f);
		return (ssize_t)n;
	}
	if (f->fd < 0) { errno = EBADF; return -1; }
	return write(f->fd, buf, n);
}

long long __file_seek(FILE *f, long long off, int whence)
{
	if (f->is_mem) {
		long long base, pos;
		switch (whence) {
		case SEEK_SET: base = 0; break;
		case SEEK_CUR:
			if (f->mem_pos > (size_t)LLONG_MAX) { errno = EOVERFLOW; return -1; }
			base = (long long)f->mem_pos;
			break;
		case SEEK_END:
			if (f->mem_len > (size_t)LLONG_MAX) { errno = EOVERFLOW; return -1; }
			base = (long long)f->mem_len;
			break;
		default: errno = EINVAL; return -1;
		}
		if ((off > 0 && base > LLONG_MAX - off) ||
		    (off < 0 && base < LLONG_MIN - off)) {
			errno = EOVERFLOW;
			return -1;
		}
		pos = base + off;
		if (pos < 0) { errno = EINVAL; return -1; }
		/* mem_pos is a size_t: on a target where size_t is narrower than
		 * off_t (i386 is ILP32; off_t stays 64-bit there), a pos that
		 * survived every signed-overflow check above can still be too
		 * wide to store. Catch that here instead of truncating it on the
		 * assignment below -- silent truncation would alias unrelated
		 * requested offsets onto the same wrapped mem_pos. This never
		 * fires where size_t already covers off_t's whole range (every
		 * off_t value is trivially <= SIZE_MAX there). */
		if ((unsigned long long)pos > SIZE_MAX) { errno = EOVERFLOW; return -1; }
		/* A fixed fmemopen() buffer rejects a seek past its size; a
		 * growable open_memstream() one has no such ceiling. */
		if (!f->mem_dynamic && (unsigned long long)pos > f->mem_size) {
			errno = EINVAL;
			return -1;
		}
		f->mem_pos = (size_t)pos;
		return (long long)f->mem_pos;
	}
	if (f->fd < 0) { errno = EBADF; return -1; }
	return lseek(f->fd, off, whence);
}

void __ensure_buf(FILE *f)
{
	size_t sz;
	if (f->buf) return;
	sz = f->bufmode == _IONBF ? 1 : (f->bufsz ? f->bufsz : BUFSIZ);
	f->buf = malloc(sz);
	if (f->buf) { f->bufsz = sz; f->user_buf = 0; }
	else f->bufsz = 0;
}

int __fflush_locked(FILE *f)
{
	size_t off = 0;

	if (f->writable && f->wpos) {
		size_t end = f->wpos;
		unsigned char *pending = f->buf;
		if (end > f->bufsz) { errno = EIO; f->err = 1; f->wpos = 0; return -1; }
		__ownership_readable_span(pending, end);
		while (off < end) {
			ssize_t n = __file_write(f, pending + off, end - off);
			if (n <= 0) { f->err = 1; f->wpos = 0; return -1; }
			if ((size_t)n > end - off) { errno = EIO; f->err = 1; f->wpos = 0; return -1; }
			off += (size_t)n;
		}
	}
	f->wpos = 0;

	/* fflush() on a readable stream must seek the fd back over whatever
	 * __fill() read ahead of what the caller actually consumed; a
	 * memory-backed stream has no separate fd offset to resync. */
	if (f->readable) {
		long long ahead = (long long)(f->rend - f->rpos);
		if (ahead && !f->is_mem) {
			if (__file_seek(f, -ahead, SEEK_CUR) < 0) {
				/* Non-seekable: no underlying offset to resync; the
				 * buffered input remains live. */
				if (errno == ESPIPE) {
					mem_publish(f);
					return 0;
				}
				f->err = 1; return -1;
			}
		}
		f->nunget = 0;
		f->nwunget = 0;
		f->rpos = f->rend = 0;
	}
	/* A seek since the last write may have moved the position that
	 * *sizep is measured against, so this can't be left to the write path. */
	mem_publish(f);
	return 0;
}

int __toread(FILE *f)
{
	if (f->wpos) return __fflush_locked(f);
	return 0;
}

int __towrite(FILE *f)
{
	if (f->rpos < f->rend || f->nunget) {
		long long unread = (long long)(f->rend - f->rpos) + f->nunget;
		f->rpos = f->rend = 0;
		f->nunget = 0;
		f->nwunget = 0;
		if (__file_seek(f, -unread, SEEK_CUR) < 0) { f->err = 1; return -1; }
	}
	return 0;
}

int __fill(FILE *f)
{
	ssize_t n;
	__ensure_buf(f);
	f->rpos = f->rend = 0;
	if (!f->buf) { f->err = 1; return -1; }
	n = __file_read(f, f->buf, f->bufsz);
	if (n < 0) { f->err = 1; return -1; }
	if (n == 0) { f->eof = 1; return 0; }
	f->rend = (size_t)n;
	return (int)n;
}

int fflush(FILE *f)
{
	if (!f) {
		FILE *p;
		int r = 0;
		if (__fflush_locked(stdin) < 0) r = EOF;
		if (__fflush_locked(stdout) < 0) r = EOF;
		if (__fflush_locked(stderr) < 0) r = EOF;
		for (p = __stdio_files; p; p = p->next)
			if (__fflush_locked(p) < 0) r = EOF;
		return r;
	}
	return __fflush_locked(f) < 0 ? EOF : 0;
}

int setvbuf(FILE *__restrict f, char *__restrict buf, int mode, size_t size) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	/* _IOLBF is a real mode, not a synonym for full buffering: rw.c
	 * flushes on '\n' when bufmode == _IOLBF. */
	if (mode != _IOFBF && mode != _IOLBF && mode != _IONBF) {
		errno = EINVAL;
		return -1;
	}
	if (fflush(f) < 0) return -1;
	if (f->buf && !f->user_buf) free(f->buf);
	f->buf = 0;
	f->bufsz = 0;
	f->user_buf = 0;
	f->rpos = f->rend = f->wpos = 0;
	f->bufmode = (unsigned char)mode;
	if (mode == _IONBF) return 0;
	if (buf) {
		f->buf = (unsigned char *)buf;
		f->bufsz = size ? size : BUFSIZ;
		f->user_buf = 1;
		return 0;
	}
	/* No buffer given: remember the size and allocate on first use. */
	f->bufsz = size ? size : BUFSIZ;
	return 0;
}

void setbuf(FILE *__restrict f, char *__restrict buf)
{
	/* ISO C gives this void wrapper no channel for setvbuf() failure. */
	(void)setvbuf(f, buf, buf ? _IOFBF : _IONBF, BUFSIZ);
}

void setlinebuf(FILE *f)
{
	/* BSD's void wrapper likewise cannot propagate setvbuf() failure. */
	(void)setvbuf(f, 0, _IOLBF, 0);
}

// NOLINTEND(misc-include-cleaner)
