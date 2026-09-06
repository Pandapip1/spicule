/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef	_DIRENT_H
#define	_DIRENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <allocation_tokens.h>
#include <ownership.h>
#include <memory_tokens.h>

tokdef directory_stream_open
	dynamic_storage
	implemented_by(internal_heap_allocated);

#define __NEED_ino_t
#define __NEED_off_t
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)
#define __NEED_size_t
#define __NEED_ssize_t
#endif

#include <bits/alltypes.h>

typedef struct __dirstream DIR;

#define _DIRENT_HAVE_D_RECLEN
#define _DIRENT_HAVE_D_OFF
#define _DIRENT_HAVE_D_TYPE

struct dirent {
	ino_t d_ino;
	off_t d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[256];
};

#define d_fileno d_ino

/* dp is undefined unless it designates an open directory stream, per
 * POSIX; nonnull makes that contract compiler-checkable. */
__attribute__((nonnull(1)))
fallible
int            closedir(DIR * consume(directory_stream_open));
withtok(directory_stream_open)
DIR           *fdopendir(int);
withtok(directory_stream_open)
DIR           *opendir(const char *);
struct dirent *readdir(DIR *) __attribute__((nonnull(1)));
int            readdir_r(DIR *__restrict, struct dirent *__restrict, struct dirent **__restrict)
    __attribute__((nonnull(1, 2, 3)));
void           rewinddir(DIR *) __attribute__((nonnull(1)));
int            dirfd(DIR *) __attribute__((nonnull(1)));

/* alphasort/versionsort's nonnull covers a/b themselves; it can't express
 * that *a and *b (one level further in) are also non-NULL, but qsort_r never
 * invokes a comparator outside the array scandir() builds, so that holds
 * by construction. filter/compar are optional and left unmarked. */
int alphasort(const struct dirent **, const struct dirent **)
    __attribute__((nonnull(1, 2)));
int scandir(const char *, struct dirent ***, int (*)(const struct dirent *), int (*)(const struct dirent **, const struct dirent **))
    __attribute__((nonnull(2)));

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
void           seekdir(DIR *, long) __attribute__((nonnull(1)));
long           telldir(DIR *) __attribute__((nonnull(1)));
#endif

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_BLK 6
#define DT_REG 8
#define DT_LNK 10
#define DT_SOCK 12
#define DT_WHT 14
#define IFTODT(x) ((x)>>12 & 017)
#define DTTOIF(x) ((x)<<12)
int getdents(int, struct dirent * withtok(writable_span(size)), size_t size);
#endif

#ifdef _GNU_SOURCE
int versionsort(const struct dirent **, const struct dirent **)
    __attribute__((nonnull(1, 2)));
#endif

#if defined(_LARGEFILE64_SOURCE)
#define dirent64 dirent
#define readdir64 readdir
#define readdir64_r readdir_r
#define scandir64 scandir
#define alphasort64 alphasort
#define versionsort64 versionsort
#define off64_t off_t
#define ino64_t ino_t
#define getdents64 getdents
#endif

#ifdef __cplusplus
}
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
