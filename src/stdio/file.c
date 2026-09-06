/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * FILE* lifetime: fopen/fdopen/freopen/fclose, the three standard
 * streams, and __stdio_exit, which exit() calls to flush and close
 * whatever is still open.  Every FILE that fopen/fdopen/fmemopen hands
 * out is linked into __stdio_files so __stdio_exit can find it without
 * the caller having to remember to.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- GNU feature-test macro has its specified reserved spelling
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "stdio_impl.h"

FILE *__stdio_files;

static unsigned char stdin_buf[BUFSIZ], stdout_buf[BUFSIZ];

static FILE stdin_f  = { .fd = 0, .bufmode = _IOFBF, .user_buf = 1, .readable = 1, .buf = stdin_buf,  .bufsz = sizeof stdin_buf,  .no_close = 1 }; // NOLINT(cert-fio38-c,misc-non-copyable-objects) -- the stdio implementation owns this backing object; no FILE is copied
static FILE stdout_f = { .fd = 1, .bufmode = _IOLBF, .user_buf = 1, .writable = 1, .buf = stdout_buf, .bufsz = sizeof stdout_buf, .no_close = 1 }; // NOLINT(cert-fio38-c,misc-non-copyable-objects) -- the stdio implementation owns this backing object; no FILE is copied
static FILE stderr_f = { .fd = 2, .bufmode = _IONBF, .writable = 1, .no_close = 1 }; // NOLINT(cert-fio38-c,misc-non-copyable-objects) -- the stdio implementation owns this backing object; no FILE is copied

FILE *const stdin = &stdin_f;
FILE *const stdout = &stdout_f;
FILE *const stderr = &stderr_f;

/* fopen's mode string turned into open()'s flags.  "b" is accepted and
 * ignored (everything here is binary already); "x" (C11) maps to O_EXCL. */
int __fmodeflags(const char *mode)
{
	int flags;
	switch (mode[0]) {
	case 'r': flags = O_RDONLY; break;
	case 'w': flags = O_WRONLY | O_CREAT | O_TRUNC; break;
	case 'a': flags = O_WRONLY | O_CREAT | O_APPEND; break;
	default: errno = EINVAL; return -1;
	}
	mode++;
	for (; *mode; mode++) {
		switch (*mode) {
		case '+': flags = (flags & ~O_ACCMODE) | O_RDWR; break;
		case 'x': flags |= O_EXCL; break;
		case 'b': case 't': break;
		case 'e': flags |= O_CLOEXEC; break;
		default: break;
		}
	}
	return flags;
}

withtok(file_stream_open)
FILE *__file_new(int fd, int flags) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	/* __malloc(), not malloc(): file_stream_open is implemented_by
	 * internal_heap_allocated (see stdio_impl.h), matching
	 * src/dirent/opendir.c's alloc_dir()/__malloc() exactly. __malloc()
	 * does not set errno itself (src/malloc/crt_alloc.c), unlike malloc(),
	 * so that is done here instead to preserve fopen()/fdopen()'s existing
	 * ENOMEM-on-failure contract. */
	FILE *f = __malloc(sizeof *f); // NOLINT(cert-fio38-c,misc-non-copyable-objects) -- the stdio implementation allocates its private FILE representation; it does not copy one
	if (!f) { errno = ENOMEM; return 0; }
	memset(f, 0, sizeof *f); // NOLINT(cert-fio38-c,misc-non-copyable-objects) -- initializes new private FILE storage before it becomes a stream; no live FILE is copied
	f->fd = fd;
	f->pid = -1;
	switch (flags & O_ACCMODE) { // NOLINT(bugprone-switch-missing-default-case) -- parsed stdio modes produce only the three valid access-mode encodings
	case O_RDONLY: f->readable = 1; break;
	case O_WRONLY: f->writable = 1; break;
	case O_RDWR: f->readable = f->writable = 1; break;
	}
	f->bufmode = isatty(fd) ? _IOLBF : _IOFBF;
	f->next = __stdio_files;
	__stdio_files = f;
	return f;
}

void __file_free(FILE *f)
{
	FILE **pp;
	for (pp = &__stdio_files; *pp; pp = &(*pp)->next) {
		if (*pp == f) { *pp = f->next; break; }
	}
	/* buf/mem_buf are separate heap_allocated buffers, not the FILE
	 * struct itself; releasing f's own file_stream_open token is each
	 * caller's own following __free(f) call (see stdio_impl.h). */
	if (f->buf && !f->user_buf) free(f->buf);
	if (f->is_mem && f->mem_owned && f->mem_buf) free(f->mem_buf);
}

withtok(file_stream_open)
FILE *fopen(const char *__restrict path withtok(null_terminated),
	const char *__restrict mode withtok(null_terminated)) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int flags = __fmodeflags(mode);
	int fd;
	FILE *f;
	if (flags < 0) return 0;
	fd = open(path, flags, 0666);
	if (fd < 0) return 0;
	f = __file_new(fd, flags);
	if (!f) { int e = errno; (void)close(fd); errno = e; return 0; }
	return f;
}

withtok(file_stream_open)
FILE *fdopen(int fd, const char *mode)
{
	int flags = __fmodeflags(mode);
	struct __fd *desc = __fd_get(fd);
	FILE *f;
	if (flags < 0) return 0;
	if (!desc) return 0;
	if ((flags & O_APPEND) && (flags & O_ACCMODE) != O_RDONLY) {
		/* fdopen(...,"a") establishes append mode even if the fd was
		 * opened without O_APPEND; seed the position from the current end
		 * so ftello() includes buffered output. Done on the raw fd,
		 * before __file_new() wraps it, rather than via fseek() on the
		 * freshly made f as before: a brand-new FILE* has no buffered
		 * state to flush or re-derive position from, so the two are
		 * equivalent here, and this way a seek failure never has to
		 * unwind a live file_stream_open. */
		desc->flags |= O_APPEND;
		if (lseek(fd, 0, SEEK_END) < 0) return 0;
	}
	f = __file_new(fd, flags);
	if (!f) return 0;
	return f;
}

FILE *freopen(const char *__restrict path, const char *__restrict mode, FILE *__restrict f) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int flags = __fmodeflags(mode);
	int fd, oldfd;

	if (flags < 0) return 0;
	(void)fflush(f);
	oldfd = f->fd;

	if (path) {
		if (f->is_mem) {
			if (f->mem_dynamic && f->mem_buf) free(f->mem_buf);
			f->is_mem = 0; f->mem_buf = 0; f->mem_size = f->mem_len = f->mem_pos = 0;
		} else if (oldfd >= 0) {
			(void)close(oldfd);
		}
		fd = open(path, flags, 0666);
		if (fd < 0) { __file_free(f); __free(f); return 0; }
		f->fd = fd;
	} else {
		/* Reopening the same file with a new mode: just re-derive flags.
		 * f->fd already is oldfd, so there is nothing to reassign. */
		if (oldfd < 0) { __file_free(f); __free(f); return 0; }
	}

	f->readable = f->writable = 0;
	switch (flags & O_ACCMODE) { // NOLINT(bugprone-switch-missing-default-case) -- parsed stdio modes produce only the three valid access-mode encodings
	case O_RDONLY: f->readable = 1; break;
	case O_WRONLY: f->writable = 1; break;
	case O_RDWR: f->readable = f->writable = 1; break;
	}
	f->eof = f->err = 0;
	f->rpos = f->rend = f->wpos = 0;
	f->nunget = 0;
	f->wide = 0;
	memset(&f->wst_in, 0, sizeof f->wst_in);
	memset(&f->wst_out, 0, sizeof f->wst_out);
	f->wunget = 0;
	f->nwunget = 0;
	/* O_APPEND enforces append writes even when this best-effort positioning
	 * cannot seek (for example, on a pipe).  Such streams remain valid. */
	if (flags & O_APPEND)
		(void)fseek(f, 0, SEEK_END); // NOLINT(cert-err33-c) -- O_APPEND, not the current offset, guarantees append semantics
	return f;
}

int fclose(FILE *f consume(file_stream_open))
{
	int r = fflush(f);
	if (!f->is_mem && !f->no_close && f->fd >= 0) {
		if (close(f->fd) < 0) r = EOF;
	}
	if (f->no_close) {
		/* stdin/stdout/stderr are never freed; just reset them.
		 *
		 * This path is a known, accepted ntlibc.AllocationLifetime
		 * finding ("consume function exits without releasing its
		 * argument"), not a real leak: f is one of the three static
		 * FILE objects below, never dynamic storage, so there is
		 * nothing to free.  AllocationLifetimeChecker has no
		 * per-function knowledge of which callers pass a static
		 * instance -- unlike DIR*, which has no such static-instance
		 * exception -- and the project's own consume-obligation
		 * design (see tools/lint-ownership-fixtures/... and
		 * tools/lint-allocation-lifetime-fixtures/bad-contract.c's
		 * broken_destroy) intentionally requires every consume(...)
		 * parameter to be discharged through a further matching
		 * release call on every path, with no header-level escape
		 * hatch for "this specific value is not really owned". Fixing
		 * this without a bespoke per-call exemption in checker C++
		 * (out of scope here) is not possible; consume(file_stream_open)
		 * is kept on fclose() regardless because leaving it off would
		 * make AllocationLifetimeChecker treat every real
		 * fopen()/fclose() pairing across the tree as a leak instead. */
		f->rpos = f->rend = f->wpos = 0;
		f->nunget = 0;
		return r;
	}
	__file_free(f);
	__free(f);
	return r;
}

int fileno(FILE *f)
{
	if (f->is_mem || f->fd < 0) { errno = EBADF; return -1; }
	return f->fd;
}

int feof(FILE *f) { return f->eof != 0; }
int ferror(FILE *f) { return f->err != 0; }
void clearerr(FILE *f) { f->eof = f->err = 0; }

/* flockfile/funlockfile: there is no threading here (libpthread.a is an
 * empty placeholder archive), so a FILE needs no real lock -- these exist
 * only so that programs written against a threaded libc still link. */
void flockfile(FILE *f) { (void)f; }
int ftrylockfile(FILE *f) { (void)f; return 0; }
void funlockfile(FILE *f) { (void)f; }

/* exit() calls this to flush and close everything still open.
 *
 * The re-entrancy guard closes a measured infinite recursion: a flush
 * hitting a broken pipe raises SIGPIPE, whose default terminate action
 * calls back into __stdio_exit() (also reached via the vectored exception
 * handler in src/signal/signal.c), which re-flushes the same undrained
 * stream. On a closed pipe this consumed the stack (EXCEPTION_STACK_OVERFLOW)
 * and clobbered the encoded SIGPIPE exit status, so a crashed process
 * reported exit code 0 instead of 13. The guard covers the whole function,
 * not per-FILE, since a second entry has nothing new to flush that the
 * first isn't already inside of; this deliberately leaves later streams
 * unflushed on that path, which is still closer to POSIX than the crash. */
void __stdio_exit(void)
{
	static int in_progress;
	FILE *f;

	if (in_progress) return;
	in_progress = 1;

	(void)fflush(stdout);
	(void)fflush(stderr);
	for (f = __stdio_files; f; f = f->next)
		(void)fflush(f);
	/* Buffers are not freed and fds not closed: the process is about to
	 * end and NtTerminateProcess reclaims everything at once. Flushing
	 * is the only observable effect that matters. */

	/* Deliberately NOT cleared.  There is no "after" for this function:
	 * every caller is on its way to __exit_internal().  Clearing it would only
	 * re-arm the recursion for a second fatal signal arriving during the
	 * same shutdown. */
}

// NOLINTEND(misc-include-cleaner)
