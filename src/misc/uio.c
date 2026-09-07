/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * readv()/writev(): one transfer, not one per area.
 *
 * XSH 2.9.7 "Thread Interactions with Regular File Operations"
 * (functions/V2_chap02.html#tag_15_09_07) lists read(), write(),
 * readv() and writev() among 39 functions that "shall be atomic with
 * respect to each other in the effects specified in POSIX.1-2017 when
 * they operate on regular files or symbolic links", and adds: "If two
 * threads each call one of these functions, each call shall either see
 * all of the specified effects of the other call, or none of them."
 *
 * The requirement is *relative*: whatever atomicity read() and write()
 * have, readv() and writev() must have the same.  So the whole clause
 * is satisfied by making a readv() literally be a read() and a writev()
 * literally be a write() -- the vector is gathered into one buffer,
 * handed to a single src/unistd/write.c call, and therefore reaches the
 * file as a single NtWriteFile; the read side scatters back out of one
 * NtReadFile.  Every file spicule opens is FILE_SYNCHRONOUS_IO_NONALERT
 * (src/fcntl/open.c), and the NT I/O manager holds the file object's
 * own lock across a synchronous transfer, reading and advancing
 * CurrentByteOffset under it.  That lock lives on the FILE_OBJECT, not
 * on the handle, so it also covers the case that matters here: a second
 * process holding an inherited handle (spawn.c marks non-cloexec
 * handles OBJ_INHERIT, so parent and child share one file object, which
 * is NT's shape of POSIX's shared open file description).
 *
 * The previous implementation looped over read()/write() one iovec at a
 * time and documented the resulting gap as a deliberate divergence,
 * on the grounds that the only atomic primitive NT offers is
 * NtReadFileScatter()/NtWriteFileGather(), which is page-granular --
 * every element must be page-aligned and a whole number of pages, which
 * an arbitrary struct iovec never is.  That is true of *scatter/gather*
 * and irrelevant to atomicity: NT has no need to see the vector at all
 * if the vector has already been flattened.  Copying is the price, and
 * it is one memcpy of data that is about to be copied into the page
 * cache anyway.
 *
 * Rejected on the way here: taking a byte-range lock (NtLockFile, via
 * src/file/flock.c) around the existing loop.  It serialises only
 * against other lock-takers, and plain read()/write() take no locks, so
 * it would not exclude the very calls 2.9.7 names.
 *
 * WHAT THE COPY COSTS, AND WHERE IT IS NOT PAID.  A vector with exactly
 * one non-empty area is passed straight through -- no gather buffer, no
 * copy -- which is the overwhelmingly common shape and is already a
 * single transfer.  Beyond that, a small vector is gathered on the
 * stack so an ordinary writev() never reaches the allocator.  Only a
 * vector too large for that buffer allocates, and if the allocation
 * fails the loop is still there as a fallback: refusing the call with
 * an errno neither readv.html nor writev.html lists would be a worse
 * answer than a transfer that is correct in everything except the
 * atomicity clause.  A caller that cannot spare the bytes it is already
 * holding is not in a position to be helped.
 *
 * What is preserved either way: "always fill/write a complete area
 * before proceeding to the next" (readv.html/writev.html DESCRIPTION),
 * since the gather and the scatter both run iov[0], iov[1], ... in
 * order; and a partial transfer still reports the bytes that really
 * moved, leaving the areas past them untouched.
 *
 * Two checks are made honestly before any I/O happens:
 *
 *   - iovcnt outside [1, IOV_MAX] -> EINVAL (readv.html/writev.html
 *     ERRORS, "may fail"; IOV_MAX from include/limits.h -- basedefs/
 *     sys_uio.h.html: "The symbol {IOV_MAX} defined in <limits.h>
 *     should always be used").
 *   - the sum of iov_len overflowing ssize_t/exceeding SSIZE_MAX ->
 *     EINVAL, "and no data shall be transferred" (writev.html
 *     DESCRIPTION/ERRORS; readv.html ERRORS has the matching EINVAL for
 *     the read side). SSIZE_MAX comes from each arch's own
 *     bits/limits.h via <limits.h>, not assumed to be a fixed width --
 *     see that file's own comment on why ssize_t's range differs per
 *     arch here.
 */
#include <sys/uio.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "ownership_stubs.h"

/* Big enough that a header-plus-payload writev -- the shape this call
 * exists for -- is gathered without touching malloc(), small enough to
 * sit on the stack of a 32-bit process without thought. */
#define GATHER_STACK 2048

/* total required: `*total = sum;` is unconditional on the success
 * path with no guard, and both real call sites (readv()/writev()
 * below) pass &total, never NULL. iov is deliberately NOT marked --
 * `if (!iov) { errno = EFAULT; return -1; }` right below is a real,
 * live guard, not decoration: readv()/writev() forward their own iov
 * here unchecked, so this is where a caller-supplied NULL is actually
 * caught. */
static int check_iov(const struct iovec *iov, int iovcnt, size_t *total)
    __attribute__((nonnull(3)));
static int check_iov(const struct iovec *iov, int iovcnt, size_t *total)
{
	size_t sum = 0;
	int i;

	if (iovcnt <= 0 || iovcnt > IOV_MAX) { errno = EINVAL; return -1; }
	if (!iov) { errno = EFAULT; return -1; }

	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len > (size_t)SSIZE_MAX - sum) { errno = EINVAL; return -1; }
		sum += iov[i].iov_len;
	}
	*total = sum;
	return 0;
}

/* The index of the only area with a non-zero length, or -1 if several
 * carry data.  Called only when the total is non-zero, so a return of
 * -1 really does mean "more than one" and never "none". */
/* iov required: `iov[i].iov_len` is dereferenced unconditionally
 * whenever iovcnt > 0, with no guard of its own -- but both real call
 * sites (readv()/writev() below) reach this only after their own
 * check_iov(iov, ...) call has already returned successfully, which
 * means check_iov()'s own `if (!iov) return -1;` has already ruled
 * out NULL on this exact path. */
static int sole_area(const struct iovec *iov, int iovcnt) __attribute__((nonnull(1)));
static int sole_area(const struct iovec *iov, int iovcnt)
{
	int i, found = -1;

	for (i = 0; i < iovcnt; i++) {
		if (!iov[i].iov_len) continue;
		if (found >= 0) return -1;
		found = i;
	}
	return found;
}

/* The pre-2.9.7 loop, kept for the one path that cannot gather: a
 * vector too large for the stack buffer whose allocation failed.  It
 * is correct in every respect except atomicity. */
/* iov required, same evidence as sole_area() above -- its one real
 * call site (readv() below) reaches it only after check_iov()'s own
 * NULL check has already passed on this exact iov. */
static ssize_t readv_looped(int fd, const struct iovec *iov, int iovcnt)
    __attribute__((nonnull(2)));
static ssize_t readv_looped(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t total = 0;
	int i;

	for (i = 0; i < iovcnt; i++) {
		ssize_t r;
		if (!iov[i].iov_len) continue;
		unsafe_assume_writable_span(iov[i].iov_base, iov[i].iov_len);
		r = read(fd, iov[i].iov_base, iov[i].iov_len);
		if (r < 0) return total ? total : -1;
		total += r;
		if ((size_t)r < iov[i].iov_len) break;   /* short read == EOF */
	}
	return total;
}

/* iov required, same evidence as readv_looped() above. */
static ssize_t writev_looped(int fd, const struct iovec *iov, int iovcnt)
    __attribute__((nonnull(2)));
static ssize_t writev_looped(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t total = 0;
	int i;

	for (i = 0; i < iovcnt; i++) {
		ssize_t w;
		if (!iov[i].iov_len) continue;
		unsafe_assume_readable_span(iov[i].iov_base, iov[i].iov_len);
		w = write(fd, iov[i].iov_base, iov[i].iov_len);
		if (w < 0) return total ? total : -1;
		total += w;
		if ((size_t)w < iov[i].iov_len) break;   /* short write */
	}
	return total;
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
	char stack[GATHER_STACK];
	char *buf;
	size_t total, off = 0, left;
	ssize_t r;
	int i;

	if (check_iov(iov, iovcnt, &total) < 0) return -1;
	/* Every area is zero-length: nothing to read into, and read() is
	 * not called at all -- the same answer the loop gave, and the one
	 * writev()'s "return 0 and have no other effect" clause requires of
	 * its side. */
	if (!total) return 0;
	i = sole_area(iov, iovcnt);
	if (i >= 0) {
		unsafe_assume_writable_span(iov[i].iov_base, iov[i].iov_len);
		return read(fd, iov[i].iov_base, iov[i].iov_len);
	}

	buf = total <= sizeof stack ? stack : malloc(total);
	if (!buf) return readv_looped(fd, iov, iovcnt);

	r = read(fd, buf, total);
	/* Scatter only what arrived, in order, so a short transfer fills
	 * the early areas completely and leaves the later ones untouched.
	 * `left` is bounded by the sum of the lengths, so this cannot walk
	 * past iovcnt; the bound is written out anyway rather than argued. */
	for (left = r > 0 ? (size_t)r : 0, i = 0; left && i < iovcnt; i++) {
		size_t n = iov[i].iov_len < left ? iov[i].iov_len : left;
		if (!n) continue;
		unsafe_assume_writable_span(iov[i].iov_base, n);
		unsafe_assume_readable_span(buf + off, n);
		memcpy(iov[i].iov_base, buf + off, n);
		off += n;
		left -= n;
	}
	/* free() is entitled to leave errno anywhere it likes; the caller
	 * is owed read()'s. */
	if (buf != stack) { int e = errno; free(buf); errno = e; }
	return r;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
	char stack[GATHER_STACK];
	char *buf;
	size_t total, off = 0;
	ssize_t w;
	int i;

	if (check_iov(iov, iovcnt, &total) < 0) return -1;
	/* writev.html DESCRIPTION: "If fildes refers to a regular file and
	 * all of the iov_len members ... are 0, writev() shall return 0 and
	 * have no other effect." */
	if (!total) return 0;
	i = sole_area(iov, iovcnt);
	if (i >= 0) {
		unsafe_assume_readable_span(iov[i].iov_base, iov[i].iov_len);
		return write(fd, iov[i].iov_base, iov[i].iov_len);
	}

	buf = total <= sizeof stack ? stack : malloc(total);
	if (!buf) return writev_looped(fd, iov, iovcnt);

	/* A zero-length area is skipped rather than handed to memcpy(): its
	 * iov_base is allowed to be anything at all, NULL included, and
	 * memcpy() from NULL is undefined even for a length of 0. */
	for (i = 0; i < iovcnt; i++) {
		if (!iov[i].iov_len) continue;
		unsafe_assume_writable_span(buf + off, iov[i].iov_len);
		unsafe_assume_readable_span(iov[i].iov_base, iov[i].iov_len);
		memcpy(buf + off, iov[i].iov_base, iov[i].iov_len);
		off += iov[i].iov_len;
	}
	w = write(fd, buf, total);
	if (buf != stack) { int e = errno; free(buf); errno = e; }
	return w;
}
