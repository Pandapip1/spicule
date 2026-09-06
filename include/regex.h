/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef _REGEX_H
#define _REGEX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <ownership.h>
#include <memory_tokens.h>

#define __NEED_size_t
#define __NEED_regoff_t
#include <bits/alltypes.h>

typedef struct {
	size_t re_nsub;		/* number of parenthesized subexpressions */
	void *__opaque;		/* implementation-private compiled form */
} regex_t;

typedef struct {
	regoff_t rm_so;
	regoff_t rm_eo;
} regmatch_t;

#define REG_EXTENDED	0x01
#define REG_ICASE	0x02
#define REG_NOSUB	0x04
#define REG_NEWLINE	0x08

#define REG_NOTBOL	0x01
#define REG_NOTEOL	0x02

#define REG_NOMATCH	1
#define REG_BADPAT	2
#define REG_ECOLLATE	3
#define REG_ECTYPE	4
#define REG_EESCAPE	5
#define REG_ESUBREG	6
#define REG_EBRACK	7
#define REG_EPAREN	8
#define REG_EBRACE	9
#define REG_BADBR	10
#define REG_ERANGE	11
#define REG_ESPACE	12
#define REG_BADRPT	13

/* regex_t's compiled form (__opaque) is a real resource, but regcomp/
 * regexec/regfree do not fit dirent.h's DIR* (opendir()/closedir()) shape:
 * regcomp returns a status code and populates a caller-owned (often
 * stack-resident) regex_t through an out-parameter, rather than
 * returning the resource itself. AllocationLifetimeChecker's cross-
 * translation-unit tracking keys entirely off a call's own return value
 * being the tracked pointer (checkPostCall reads Call.getReturnValue()),
 * so no dynamic_storage/withtok/consume tokdef -- whatever family it
 * names -- can reach a regcomp() caller compiled in another TU: there is
 * no return-value hook to attach to, and this was confirmed empirically
 * (a __opaque withtok(...) field annotation added no diagnostic for a
 * cross-TU caller that never calls regfree()). construct/destroy/handle
 * below are this codebase's own vocabulary for exactly this call shape
 * -- see sem_init/sem_destroy/sem_wait and pthread_mutex_init/destroy/
 * lock in semaphore.h/pthread.h -- and give real, sound coverage: proven
 * initialize-before-use, no double-regcomp without an intervening
 * regfree, and no use or double-free after regfree. What they do not
 * give, and what nothing in this dialect can for this shape, is a
 * "regfree was called before every function exit" proof. */
int regcomp(regex_t *__restrict construct(regex_compiled), const char *__restrict, int)
    __attribute__((nonnull(1, 2)));
/* pmatch is deliberately not marked nonnull: it is defensively checked,
 * matching POSIX's "nmatch == 0" convention for "no match offsets wanted". */
int regexec(const regex_t *__restrict handle(regex_compiled), const char *__restrict, size_t, regmatch_t *__restrict, int)
    __attribute__((nonnull(1, 2)));
/* preg is unused here -- POSIX permits an implementation to ignore it --
 * and is deliberately left unannotated: regerror's standard calling
 * convention is `regcomp(&re, ...); if (rc) regerror(rc, &re, ...);`,
 * passing a regex_t whose regcomp() call just FAILED, which
 * handle(regex_compiled) would wrongly demand be proven live/compiled.
 * errbuf is only dereferenced when errbuf_size != 0. */
size_t regerror(int errcode, const regex_t *__restrict preg,
	char *__restrict errbuf withtok(writable_span(errbuf_size)),
	size_t errbuf_size);
void regfree(regex_t * destroy(regex_compiled)) __attribute__((nonnull(1)));

#ifdef __cplusplus
}
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
