/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef _GETOPT_H
#define _GETOPT_H

#include <string_tokens.h>

#ifdef __cplusplus
extern "C" {
#endif

int getopt(int argc, char *const argv[] elements_withtok(null_terminated, argc), const char *)
    __attribute__((nonnull(2, 3)));
extern char *optarg;
extern int optind, opterr, optopt, optreset;

struct option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
};

/* longopts is deliberately not marked nonnull: getopt_long_only()'s
 * single-character fallback runs fine without one. */
int getopt_long(int argc, char *const *argv elements_withtok(null_terminated, argc),
    const char *, const struct option *, int *)
    __attribute__((nonnull(2, 3)));
int getopt_long_only(int argc, char *const *argv elements_withtok(null_terminated, argc),
    const char *, const struct option *, int *)
    __attribute__((nonnull(2, 3)));

#define no_argument        0
#define required_argument  1
#define optional_argument  2

#ifdef __cplusplus
}
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
