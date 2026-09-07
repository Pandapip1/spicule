/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * fmemopen and open_memstream: a FILE with no fd at all, read and
 * written straight out of a block of memory.  __file_read/write/seek
 * in buf.c already know how to talk to one (that is what f->is_mem
 * means to them); all that is done here is setting one up.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <wchar.h>
#include "stdio_impl.h"

FILE *fmemopen(void *__restrict buf, size_t size, const char *__restrict mode)
{
	int flags = __fmodeflags(mode);
	unsigned char *b = buf;
	int owned = 0;
	FILE *f;

	if (flags < 0 || size == 0) { errno = EINVAL; return 0; }
	if (!b) {
		b = malloc(size);
		if (!b) return 0;
		owned = 1;
		b[0] = 0;
	}
	f = malloc(sizeof *f); // NOLINT(cert-fio38-c,misc-non-copyable-objects) -- the stdio implementation allocates its private FILE representation; it does not copy one
	if (!f) { if (owned) free(b); return 0; }
	memset(f, 0, sizeof *f); // NOLINT(cert-fio38-c,misc-non-copyable-objects) -- initializes new private FILE storage before it becomes a stream; no live FILE is copied
	f->fd = -1;
	f->pid = -1;
	f->is_mem = 1;
	f->mem_owned = (unsigned char)owned;
	f->mem_buf = b;
	f->mem_size = size;
	switch (flags & O_ACCMODE) {
	case O_RDONLY: f->readable = 1; f->mem_len = size; break;
	case O_WRONLY: f->writable = 1; f->mem_len = 0; break;
	default: f->readable = f->writable = 1; f->mem_len = mode[0] == 'r' ? size : 0; break;
	}
	if (mode[0] == 'a') {
		size_t l = 0;
		while (l < size && b[l]) l++;
		f->mem_len = l;
		f->mem_pos = l;
		/* Initial position is the first NUL; buf.c's shared write path
		 * resets to mem_len before every write while this is set. */
		f->mem_append = 1;
	}
	f->bufmode = _IOFBF;
	f->next = __stdio_files;
	__stdio_files = f;
	return f;
}

FILE *open_memstream(char **bufp, size_t *sizep)
{
	FILE *f;
	unsigned char *b;

	if (!bufp || !sizep) { errno = EINVAL; return 0; }
	b = malloc(1);
	if (!b) return 0;
	b[0] = 0;
	f = malloc(sizeof *f); // NOLINT(cert-fio38-c,misc-non-copyable-objects) -- the stdio implementation allocates its private FILE representation; it does not copy one
	if (!f) { free(b); return 0; }
	memset(f, 0, sizeof *f); // NOLINT(cert-fio38-c,misc-non-copyable-objects) -- initializes new private FILE storage before it becomes a stream; no live FILE is copied
	f->fd = -1;
	f->pid = -1;
	f->is_mem = 1;
	f->mem_dynamic = 1;
	f->writable = 1;
	f->mem_buf = b;
	f->mem_size = 1;
	f->mem_out_ptr = bufp;
	f->mem_out_size = sizep;
	*bufp = (char *)b;
	*sizep = 0;
	f->bufmode = _IOFBF;
	f->next = __stdio_files;
	__stdio_files = f;
	return f;
}

/* open_memstream()'s wide twin: buffer holds wchar_t, *sizep counts wide
 * characters, and the stream is wide-oriented from creation (a stray
 * byte write would misalign the wchar_t contents). mem_len/mem_pos/
 * mem_size stay byte counts so the growth arithmetic is shared with
 * open_memstream(); only the terminator width and reported size divide.
 * fputwc() (src/stdio/wide.c) writes the wchar_t's own bytes here instead
 * of converting through wcrtomb(). Caller owns and frees the buffer;
 * fclose() does not (mem_owned is for fmemopen(NULL, ...) only). */
FILE *open_wmemstream(wchar_t **bufp, size_t *sizep)
{
	FILE *f;
	wchar_t *b;

	if (!bufp || !sizep) { errno = EINVAL; return 0; }
	b = malloc(sizeof *b);
	if (!b) return 0;
	b[0] = 0;
	f = malloc(sizeof *f); // NOLINT(cert-fio38-c,misc-non-copyable-objects) -- the stdio implementation allocates its private FILE representation; it does not copy one
	if (!f) { free(b); return 0; }
	memset(f, 0, sizeof *f); // NOLINT(cert-fio38-c,misc-non-copyable-objects) -- initializes new private FILE storage before it becomes a stream; no live FILE is copied
	f->fd = -1;
	f->pid = -1;
	f->is_mem = 1;
	f->mem_dynamic = 1;
	f->wmem = 1;
	f->wide = 1;
	f->writable = 1;
	f->mem_buf = (unsigned char *)b;
	f->mem_size = sizeof *b;
	f->mem_out_ptr = (char **)(void *)bufp; // NOLINT(bugprone-casting-through-void) -- the shared stream backend stores the ABI-mandated wchar_t ** output slot in its generic char ** field
	f->mem_out_size = sizep;
	*bufp = b;
	*sizep = 0;
	f->bufmode = _IOFBF;
	f->next = __stdio_files;
	__stdio_files = f;
	return f;
}

// NOLINTEND(misc-include-cleaner)
