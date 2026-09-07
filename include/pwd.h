/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <pwd.h>: there is no /etc/passwd on NT, but the process token identifies
 * exactly one current user, whom src/unistd/ids.c maps to a uid via their
 * SAM/AD SID and RID; setuid()/seteuid() can only retain that identity.
 * src/misc/pwd.c fills a struct passwd for that user and cleanly refuses
 * to answer for anyone else, rather than fabricating a record. */
#ifndef _PWD_H
#define _PWD_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#define __NEED_uid_t
#define __NEED_gid_t
#define __NEED_size_t
#include <bits/alltypes.h>

/* pwd.h.html: "at least" these five members. */
struct passwd {
	char *pw_name;
	uid_t pw_uid;
	gid_t pw_gid;
	char *pw_dir;
	char *pw_shell;
};

struct passwd *getpwnam(const char *);
struct passwd *getpwuid(uid_t);
/* name and buffer are deliberately not marked nonnull: name has a real,
 * live NULL check in getpwnam_r(), and buffer is safe when NULL exactly
 * when bufsize is 0. */
int getpwnam_r(const char *, struct passwd *, char *, size_t, struct passwd **)
    __attribute__((nonnull(2, 5)));
int getpwuid_r(uid_t, struct passwd *, char *, size_t, struct passwd **)
    __attribute__((nonnull(2, 5)));

/* XSI; spicule's user database genuinely has exactly one entry, so
 * enumerating it is not a fabrication. */
struct passwd *getpwent(void);
void setpwent(void);
void endpwent(void);

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
