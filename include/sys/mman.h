/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <sys/mman.h> -- memory management, implemented in src/mman/mman.c.
 * Supports anonymous mappings and file-backed mappings of REGULAR
 * files only; every other file type (directory, pipe, socket, console)
 * is declined with [ENODEV].
 *
 * This tree targets POSIX Issue 7, which has NO anonymous mapping at
 * all: mmap.html requires fildes to be a valid open descriptor, and
 * MAP_ANONYMOUS/MAP_ANON arrived only in Issue 8. So MAP_ANONYMOUS is
 * shipped here as a documented non-POSIX extension gated behind
 * _BSD_SOURCE/_GNU_SOURCE -- an ungated symbol would let a strictly
 * -D_POSIX_C_SOURCE program see something POSIX doesn't define, and a
 * configure probe that finds it would draw a false conclusion.
 *
 * File-backed MAP_FIXED can only replace a mapping's ENTIRE current
 * extent, never part of one: NtUnmapViewOfSection() drops a whole view
 * with no NT primitive for a partial replacement the way
 * MEM_DECOMMIT+MEM_COMMIT gives the anonymous path. An overlapping
 * partial MAP_FIXED is refused with [ENOMEM] rather than misbehaving.
 *
 * posix_madvise/posix_typed_mem_open/posix_typed_mem_get_info/
 * posix_mem_offset are declared with real, spec-mandated answers, not
 * stubs: posix_madvise() validates advice and otherwise no-ops (advice
 * is optional to act on); the typed-mem functions report ENOENT/EBADF
 * since this implementation ships no typed memory pools, which POSIX
 * allows as a conforming choice; posix_mem_offset() answers from the
 * same mapping registry mmap() maintains.
 *
 * shm_open()/shm_unlink() use regular NTFS-backed files in a private
 * temporary-directory namespace, since mmap() already maps those
 * through NT sections.
 */
#ifndef _SYS_MMAN_H
#define _SYS_MMAN_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <ownership.h>

#define __NEED_size_t
#define __NEED_off_t
#define __NEED_mode_t
#include <bits/alltypes.h>

#define PROT_NONE  0x0
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

/* Exactly one of MAP_SHARED/MAP_PRIVATE must be given. Both are
 * accepted even for an anonymous mapping (where they're otherwise
 * indistinguishable), since the distinction is about the object and a
 * caller naming it correctly shouldn't be punished for it. */
#define MAP_SHARED  0x01
#define MAP_PRIVATE 0x02
#define MAP_FIXED   0x10

#define MAP_FAILED ((void *)-1)

#define MS_ASYNC      0x1
#define MS_INVALIDATE 0x2
#define MS_SYNC       0x4

#define MCL_CURRENT 0x1
#define MCL_FUTURE  0x2

/* The VALUE is defined unconditionally under a reserved-namespace name;
 * only the user-visible SPELLING is gated below. src/mman/mman.c tests
 * this bit on every call regardless of which feature-test macros the
 * translation unit compiling it happens to define -- a feature-test
 * macro gates what a translation unit can SEE, never what the
 * implementation does. (Previously this was gated too, and the ASan
 * build -- the one leg that doesn't define _GNU_SOURCE -- silently
 * treated every anonymous mmap() as a file-backed request against fd
 * -1 and failed EBADF.) */
#define __MAP_ANONYMOUS 0x20

#if defined(_BSD_SOURCE) || defined(_GNU_SOURCE)
/* Not POSIX Issue 7 -- see this header's banner. fildes is ignored
 * when this is set; passing -1 is the convention this implementation
 * expects. */
#define MAP_ANONYMOUS __MAP_ANONYMOUS
#define MAP_ANON      MAP_ANONYMOUS
#endif

io_operation
void *mmap(void *, size_t, int, int, int, off_t);
fallible
io_operation
int munmap(void *, size_t);
fallible
io_operation
int mprotect(void *, size_t, int);
fallible
int msync(void *, size_t, int);
int mlock(const void *, size_t);
int munlock(const void *, size_t);
int mlockall(int);
int munlockall(void);
int shm_open(const char *, int, mode_t);
int shm_unlink(const char *);

#define POSIX_MADV_NORMAL     0
#define POSIX_MADV_SEQUENTIAL 1
#define POSIX_MADV_RANDOM     2
#define POSIX_MADV_WILLNEED   3
#define POSIX_MADV_DONTNEED   4

int posix_madvise(void *, size_t, int);

#define POSIX_TYPED_MEM_ALLOCATE        1
#define POSIX_TYPED_MEM_ALLOCATE_CONTIG 2
#define POSIX_TYPED_MEM_MAP_ALLOCATABLE 3

struct posix_typed_mem_info {
	size_t posix_tmi_length;
};

int posix_typed_mem_open(const char *, int, int);
int posix_typed_mem_get_info(int, struct posix_typed_mem_info *);
int posix_mem_offset(const void *__restrict, size_t, off_t *__restrict,
                      size_t *__restrict, int *__restrict);

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
