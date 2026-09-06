/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef	_FCNTL_H
#define	_FCNTL_H

#include <features.h>
#include <ownership.h>

#ifdef __cplusplus
extern "C" {
#endif

#define __NEED_off_t
#define __NEED_pid_t
#define __NEED_mode_t

#ifdef _GNU_SOURCE
#define __NEED_size_t
#define __NEED_ssize_t
#endif

#include <bits/alltypes.h>

/* POSIX requires these here unconditionally so record-locking code can fill
 * in l_whence without also including <stdio.h>. Deliberately spelled the
 * same as <stdio.h>/<unistd.h>'s own definitions rather than guarded: C99
 * 6.10.3p2 makes an identical macro redefinition benign. */
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define O_RDONLY  00
#define O_WRONLY  01
#define O_RDWR    02
#define O_ACCMODE 03

/* POSIX permits O_EXEC and O_SEARCH to share a value. Both get 03, the one
 * bit pattern O_ACCMODE had left over (already open()'s unreachable switch
 * arm), rather than musl's O_PATH approach, which would reclassify existing
 * open(..., O_PATH) callers as execute-only. open() refuses both with
 * EINVAL; only the constants are implemented. */
#define O_EXEC   03
#define O_SEARCH 03

/* Zero, per POSIX's escape hatch allowing O_TTY_INIT to be zero: a freshly
 * opened NT console already comes up in the conforming state (ISIG|ICANON|
 * ECHO), so open() has nothing to set. A console an earlier process left
 * altered is not restored. */
#define O_TTY_INIT 0

#define O_CREAT        0100
#define O_EXCL         0200
#define O_NOCTTY       0400
#define O_TRUNC       01000
#define O_APPEND      02000
#define O_NONBLOCK    04000
#define O_DSYNC      010000
#define O_SYNC     04010000
#define O_RSYNC    04010000
#define O_DIRECTORY 0200000
#define O_NOFOLLOW  0400000
#define O_CLOEXEC  02000000

#define O_ASYNC      020000
#define O_DIRECT     040000
#define O_LARGEFILE 0100000
#define O_NOATIME  01000000
#define O_PATH    010000000
#define O_TMPFILE 020200000
#define O_NDELAY O_NONBLOCK

/* Windows-specific: open in text mode (CRLF translation). Ignored: all
 * files are binary here, the way they are everywhere that is not DOS. */
#define O_BINARY 0
#define O_TEXT 0

#define F_DUPFD  0
#define F_GETFD  1
#define F_SETFD  2
#define F_GETFL  3
#define F_SETFL  4

#define F_SETOWN 8
#define F_GETOWN 9
#define F_SETSIG 10
#define F_GETSIG 11

#define F_GETLK 5
#define F_SETLK 6
#define F_SETLKW 7

#define F_DUPFD_CLOEXEC 1030

#define FD_CLOEXEC 1

#define F_RDLCK 0
#define F_WRLCK 1
#define F_UNLCK 2

#define AT_FDCWD (-100)
#define AT_SYMLINK_NOFOLLOW 0x100
#define AT_REMOVEDIR 0x200
#define AT_SYMLINK_FOLLOW 0x400
#define AT_EACCESS 0x200

struct flock {
	short l_type;
	short l_whence;
	off_t l_start;
	off_t l_len;
	pid_t l_pid;
};

io_operation
int creat(const char *, mode_t);
async_signal_safe
io_operation
int fcntl(int, int, ...);
async_signal_safe
io_operation
int open(const char *, int, ...);
io_operation
int openat(int, const char *, int, ...);

#define POSIX_FADV_NORMAL     0
#define POSIX_FADV_RANDOM     1
#define POSIX_FADV_SEQUENTIAL 2
#define POSIX_FADV_WILLNEED   3
#define POSIX_FADV_DONTNEED   4
#define POSIX_FADV_NOREUSE    5
int posix_fadvise(int, off_t, off_t, int);
int posix_fallocate(int, off_t, off_t);

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)
#define S_ISUID 04000
#define S_ISGID 02000
#define S_ISVTX 01000
#define S_IRUSR 0400
#define S_IWUSR 0200
#define S_IXUSR 0100
#define S_IRWXU 0700
#define S_IRGRP 0040
#define S_IWGRP 0020
#define S_IXGRP 0010
#define S_IRWXG 0070
#define S_IROTH 0004
#define S_IWOTH 0002
#define S_IXOTH 0001
#define S_IRWXO 0007
#endif

#ifdef __cplusplus
}
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
