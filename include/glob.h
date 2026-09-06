/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <glob.h>: pathname expansion built on <fnmatch.h>; see src/glob/glob.c.
 *
 * Tilde expansion is deliberately not here: per POSIX, "applications that
 * need tilde and parameter expansion should use wordexp()", so a leading
 * '~' is just an ordinary pattern character. glibc's non-standard
 * GLOB_TILDE is not implemented.
 *
 * Flag/return values must match test/posix-glob.c's own local copies,
 * which it declares independently of this header and calls glob() through.
 */
#ifndef _GLOB_H
#define _GLOB_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <allocation_tokens.h>
#include <ownership.h>

#define __NEED_size_t
#include <bits/alltypes.h>

/* gl_pathv is the one field globfree() releases as a single unit (the
 * pointer array itself, from src/glob/glob.c's finish()); the individual
 * char* entries it holds are a separate, unannotated concern shared with
 * <wordexp.h>'s equally-scoped we_wordv (see that header's own comment,
 * which this one mirrors). Like wordexp(), glob() has no pointer-typed
 * return to hang withtok(...) on -- it returns int and reaches this field
 * only through one level of struct-member access on an out-parameter,
 * which AllocationLifetimeChecker's checkPostCall never turns into a
 * freshly tracked fact at a CALLER's call site (only a producer's own
 * pointer-typed return, or an argument echoed back unchanged, ever does
 * that). This annotation therefore proves glob()'s *own* implementation
 * never leaks or double-transfers gl_pathv on any internal path; it
 * cannot, and does not claim to, prove that a caller of glob()/globfree()
 * always pairs them (see src/wordexp/wordexp.c's emit_field() -- the one
 * real caller of glob()/globfree() in this tree, manually reviewed
 * correct -- and tools/lint-allocation-lifetime-fixtures/safe.c's
 * missing_release_is_not_caught() for the same limit demonstrated
 * generically). */
typedef struct {
	size_t gl_pathc;	/* count of paths matched */
	char **gl_pathv withtok(internal_heap_allocated);	/* list of matched pathnames, NULL-terminated */
	size_t gl_offs;		/* slots to reserve at gl_pathv's front, if GLOB_DOOFFS */
} glob_t;

#define GLOB_APPEND	0x001
#define GLOB_DOOFFS	0x002
#define GLOB_ERR	0x004
#define GLOB_MARK	0x008
#define GLOB_NOCHECK	0x010
#define GLOB_NOESCAPE	0x020
#define GLOB_NOSORT	0x040

#define GLOB_ABORTED	1
#define GLOB_NOMATCH	2
#define GLOB_NOSPACE	3

/* errfunc is deliberately not required: per POSIX, a null errfunc is
 * simply never called. */
int glob(const char *__restrict, int, int (*)(const char *, int), glob_t *__restrict)
    __attribute__((nonnull(1, 4)));
void globfree(glob_t *);

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
