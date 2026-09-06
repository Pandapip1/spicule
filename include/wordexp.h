/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <wordexp.h>: shell word expansion. See src/wordexp/wordexp.c.
 *
 * Command substitution ($(cmd)/`cmd`) runs through ntlibc's own internal
 * POSIX shell (src/sh/) via __sh_cmdsub(): the command list is parsed and
 * executed in-process, with standard output captured and trailing
 * newlines removed. A program that never calls wordexp()/system()/
 * popen() never links any of it. WRDE_NOCMD makes a $(...)/`...` fail
 * with WRDE_CMDSUB rather than running; it never affects arithmetic
 * expansion, which POSIX gives precedence ("$((" is read as arithmetic
 * whenever it parses as one). A substitution using a construct the
 * internal shell has no grammar for (if/while/for/case, functions,
 * aliases) comes back as WRDE_SYNTAX; a command that simply fails or is
 * not found is not an error here, exactly as in any shell.
 *
 * Implemented, none of which needs the shell: tilde expansion, parameter
 * expansion ($VAR/${VAR}, ${#VAR}, the -/+/=/? operators, #/##/%/%%
 * pattern removal), arithmetic expansion, pathname expansion (delegates
 * to <glob.h>), quoting/quote removal, and the WRDE_DOOFFS/APPEND/REUSE
 * bookkeeping flags.
 *
 * Field splitting: unquoted expansion results are split on IFS
 * (<space>/<tab>/<newline> by default); double-quoted results are not
 * split. Per POSIX's empty-field rule, an unquoted expansion of an unset
 * or null parameter produces no field at all, while "$UNSET" still
 * produces the empty field the quotes require.
 *
 * The caller has no positional-parameter context, so $1/${10}/$@/$*
 * expand as an empty parameter list and $# expands to "0"; the shell
 * supplies its own positional parameters through the private
 * __wordexp_sh() entry point instead.
 *
 * wordexp_t's layout and the WRDE_* values must match test/posix-glob.c's
 * own local copies, which it declares independently of this header.
 */
#ifndef _WORDEXP_H
#define _WORDEXP_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <allocation_tokens.h>
#include <ownership.h>

#define __NEED_size_t
#include <bits/alltypes.h>

/* we_wordv is the one field wordfree() releases as a single unit (the
 * pointer array itself, from src/wordexp/wordexp.c's pv_pack()); the
 * individual char* entries it holds are a separate, unannotated concern
 * shared with <glob.h>'s equally untracked gl_pathv (see that header's own
 * comment). Unlike <dirent.h>'s DIR*, wordexp() has no pointer-typed return
 * to hang withtok(...) on -- it returns int and reaches this field only
 * through one level of struct-member access on an out-parameter, which
 * AllocationLifetimeChecker's checkPostCall never turns into a freshly
 * tracked fact at a CALLER's call site (only a producer's own pointer-typed
 * return, or an argument echoed back unchanged, ever does that). This
 * annotation therefore proves wordexp()'s *own* implementation never leaks
 * or double-transfers we_wordv on any internal path; it cannot, and does
 * not claim to, prove that a caller of wordexp()/wordfree() always pairs
 * them (see src/wordexp/wordexp.c's pv_pack() and
 * tools/lint-allocation-lifetime-fixtures/safe.c's
 * missing_release_is_not_caught() for the same limit demonstrated
 * generically). */
typedef struct {
	size_t we_wordc;	/* count of words */
	char **we_wordv withtok(internal_heap_allocated);	/* list of expanded words */
	size_t we_offs;		/* slots to reserve at we_wordv's front, if WRDE_DOOFFS */
} wordexp_t;

#define WRDE_APPEND	0x01
#define WRDE_DOOFFS	0x02
#define WRDE_NOCMD	0x04
#define WRDE_REUSE	0x08
#define WRDE_SHOWERR	0x10
#define WRDE_UNDEF	0x20

#define WRDE_BADCHAR	1
#define WRDE_BADVAL	2
#define WRDE_CMDSUB	3
#define WRDE_NOSPACE	4
#define WRDE_SYNTAX	5

/* wordfree() accepts NULL (and a zeroed wordexp_t) by design. */
int wordexp(const char *__restrict, wordexp_t *__restrict, int)
    __attribute__((nonnull(2)));
void wordfree(wordexp_t *);

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
