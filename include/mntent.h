/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <mntent.h>: not POSIX (glibc/BSD historical). Every function is pure
 * stdio -- parsing formatted lines through a FILE * the caller already has
 * open -- with nothing OS-specific, except setmntent(): MOUNTED names
 * /proc/mounts, a real Linux pseudo-file, so on NT setmntent(MOUNTED, "r")
 * fails ENOENT cleanly rather than fabricating a mount table.
 */
#ifndef _MNTENT_H
#define _MNTENT_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <stdio.h>

/* Meaningful only on Linux -- see this header's banner. */
#define MOUNTED "/proc/mounts"
#define MNTTAB  "/etc/fstab"

/* mnt_freq/mnt_passno default to 0 when a line omits them -- see
 * src/misc/mntent.c's parser. */
struct mntent {
	char *mnt_fsname;
	char *mnt_dir;
	char *mnt_type;
	char *mnt_opts;
	int mnt_freq;
	int mnt_passno;
};

/* A subset of glibc/BSD's option-name constants; the rest (MNTOPT_QUOTA
 * and similar) would have no meaning without a filesystem driver. */
#define MNTOPT_DEFAULTS "defaults"
#define MNTOPT_RO       "ro"
#define MNTOPT_RW       "rw"
#define MNTOPT_SUID     "suid"
#define MNTOPT_NOSUID   "nosuid"
#define MNTOPT_NOAUTO   "noauto"

withtok(file_stream_open)
FILE *setmntent(const char *, const char *);
struct mntent *getmntent(FILE *);
struct mntent *getmntent_r(FILE *__restrict, struct mntent *__restrict,
                            char *__restrict, int);
int addmntent(FILE *__restrict, const struct mntent *__restrict);
int endmntent(FILE *);
char *hasmntopt(const struct mntent *, const char *);

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
