/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * struct __spawn_action -- the one recorded file action.
 *
 * <spawn.h> leaves this struct incomplete (posix_spawn_file_actions_t
 * holds only a pointer to an array of them), so it is private to
 * src/process/: spawn_file_actions.c appends them and posix_spawn.c
 * replays them.  A private header rather than src/internal/libc.h
 * because nothing outside this directory has any business knowing the
 * shape -- the same argument src/wordexp/internal.h makes for itself.
 */
#ifndef SPICULE_SPAWN_INTERNAL_H
#define SPICULE_SPAWN_INTERNAL_H

#include <spawn.h>

enum { __SPAWN_CLOSE = 1, __SPAWN_DUP2, __SPAWN_OPEN };

struct __spawn_action {
	int kind;
	union {
		struct { int fd; } close;
		struct { int fd, newfd; } dup2; /* fd (POSIX's `fildes`) is duplicated onto newfd */
		struct { int fd, oflag; mode_t mode; char *path; } open; /* path: malloc'd copy owned by the object */
	} u;
};

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
