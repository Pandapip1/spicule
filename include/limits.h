/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef _LIMITS_H
#define _LIMITS_H

#include <features.h>
#include <bits/limits.h>

#define CHAR_BIT 8
#define SCHAR_MIN (-128)
#define SCHAR_MAX 127
#define UCHAR_MAX 255
/* Plain `char`'s signedness is implementation-defined: unsigned on this
 * project's aarch64 target, signed on i386/x86_64. */
#ifdef __CHAR_UNSIGNED__
#define CHAR_MIN 0
#define CHAR_MAX UCHAR_MAX
#else
#define CHAR_MIN (-128)
#define CHAR_MAX 127
#endif
#define SHRT_MIN  (-1-0x7fff)
#define SHRT_MAX  0x7fff
#define USHRT_MAX 0xffff
#define INT_MIN  (-1-0x7fffffff)
#define INT_MAX  0x7fffffff
#define UINT_MAX 0xffffffffU
#define LONG_MIN (-LONG_MAX-1)
#define ULONG_MAX (2UL*LONG_MAX+1)
#define LLONG_MIN (-LLONG_MAX-1)
#define ULLONG_MAX (2ULL*LLONG_MAX+1)

#define MB_LEN_MAX 4

#define PIPE_BUF 4096
#define FILESIZEBITS 64
#define NAME_MAX 255
#define PATH_MAX 4096
#define NGROUPS_MAX 32
#define ARG_MAX 131072
#define IOV_MAX 1024
#define SYMLOOP_MAX 40
#define WORD_BIT 32
/* SSIZE_MAX is defined in bits/limits.h, not derived from LONG_MAX
 * here: long stays 32-bit on both arches under this LLP64 model, which
 * would silently truncate it on x86_64 where ssize_t is 64-bit. */
#define TZNAME_MAX 6
#define TTY_NAME_MAX 32
#define HOST_NAME_MAX 255
#define OPEN_MAX 1024
#define RTSIG_MAX 30
#define SIGQUEUE_MAX 32
#define TIMER_MAX 32
#define MQ_OPEN_MAX 1024
#define MQ_PRIO_MAX 32768
#define AIO_LISTIO_MAX 64
#define AIO_MAX 256
#define AIO_PRIO_DELTA_MAX 0

#define _POSIX_AIO_LISTIO_MAX   2
#define _POSIX_AIO_MAX          1
#define _POSIX_ARG_MAX          4096
#define _POSIX_CHILD_MAX        25
#define _POSIX_CLOCKRES_MIN     20000000
#define _POSIX_DELAYTIMER_MAX   32
#define _POSIX_HOST_NAME_MAX    255
#define _POSIX_LINK_MAX         8
#define _POSIX_LOGIN_NAME_MAX   9
#define _POSIX_MQ_OPEN_MAX      8
#define _POSIX_MQ_PRIO_MAX      32
#define _POSIX_MAX_CANON        255
#define _POSIX_MAX_INPUT        255
#define _POSIX_NAME_MAX         14
#define _POSIX_NGROUPS_MAX      8
#define _POSIX_OPEN_MAX         20
#define _POSIX_PATH_MAX         256
#define _POSIX_PIPE_BUF         512
#define _POSIX_RE_DUP_MAX       255
#define _POSIX_RTSIG_MAX        8
#define _POSIX_SEM_NSEMS_MAX    256
#define _POSIX_SEM_VALUE_MAX    32767
#define _POSIX_SIGQUEUE_MAX     32
#define _POSIX_SSIZE_MAX        32767
#define _POSIX_STREAM_MAX       8
#define _POSIX_SYMLINK_MAX      255
#define _POSIX_SYMLOOP_MAX      8
#define _POSIX_TIMER_MAX        32
#define _POSIX_TTY_NAME_MAX     9
#define _POSIX_TZNAME_MAX       6
#define _POSIX2_BC_BASE_MAX     99
#define _POSIX2_BC_DIM_MAX      2048
#define _POSIX2_BC_SCALE_MAX    99
#define _POSIX2_BC_STRING_MAX   1000
#define _POSIX2_CHARCLASS_NAME_MAX 14
#define _POSIX2_COLL_WEIGHTS_MAX 2
#define _POSIX2_EXPR_NEST_MAX   32
#define _POSIX2_LINE_MAX        2048
#define _POSIX2_RE_DUP_MAX      255

/* The rest of the "Minimum Values" table: EXACT values the standard
 * prints, not floors spicule chooses, so defining them claims nothing
 * about spicule's capabilities -- unlike <unistd.h>'s _POSIX_THREADS,
 * which asserts an option group is actually present. */
#define _POSIX_THREAD_DESTRUCTOR_ITERATIONS 4
#define _POSIX_THREAD_KEYS_MAX  128
#define _POSIX_THREAD_THREADS_MAX 64

/* [XSI]. Defined because spicule compiles -D_XOPEN_SOURCE=700 and
 * already implements readv()/writev()/IOV_MAX. */
#define _XOPEN_IOV_MAX          16
#define _XOPEN_NAME_MAX         255
#define _XOPEN_PATH_MAX         1024

/* "Runtime Increasable Values": unlike the Minimum Values above, each
 * of these is a promise about THIS library (sysconf() may report
 * larger, never smaller). Seven of nine sit at the POSIX floor since
 * there's no larger capability to claim (bc isn't implemented,
 * collation is C-locale only); LINE_MAX and RE_DUP_MAX below are set
 * higher because the floor would understate what this library does. */
#define BC_BASE_MAX             _POSIX2_BC_BASE_MAX
#define BC_DIM_MAX              _POSIX2_BC_DIM_MAX
#define BC_SCALE_MAX            _POSIX2_BC_SCALE_MAX
#define BC_STRING_MAX           _POSIX2_BC_STRING_MAX
#define CHARCLASS_NAME_MAX      _POSIX2_CHARCLASS_NAME_MAX
#define COLL_WEIGHTS_MAX        _POSIX2_COLL_WEIGHTS_MAX
#define EXPR_NEST_MAX           _POSIX2_EXPR_NEST_MAX

/* 4096, not the 2048 floor: matches src/unistd/sysconf.c's
 * _SC_LINE_MAX answer. If one changes, change both. */
#define LINE_MAX                4096

/* 32767, not the 255 floor: matches src/regex/regex.c's DUP_MAX, past
 * which it reports REG_BADBR. If one changes, change both. */
#define RE_DUP_MAX              32767

/* "Other Invariant Values": unlike Runtime Increasable, these cannot
 * grow at run time -- no sysconf() counterpart exists for them. */
#define NL_LANGMAX              14      /* [XSI] */
#define NL_MSGMAX               32767
#define NL_SETMAX               255
#define NL_TEXTMAX              _POSIX2_LINE_MAX

/* NL_ARGMAX bounds n in a "%n$" conversion specification. 9 is the
 * standard's floor; src/stdio/printf.c honours it exactly, refusing an
 * index above it with [EINVAL]. Raising this is a one-constant change
 * there (the format-arg table is NL_ARGMAX entries). */
#define NL_ARGMAX               9

/* [XSI]. Also defined by <sys/resource.h> for the nice() range; same
 * token sequence in both, so the redefinition is benign (C99 6.10.3p2).
 * If one moves, move both. */
#define NZERO                   20

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
