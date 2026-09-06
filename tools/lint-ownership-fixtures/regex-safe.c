/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#include "../../include/ownership.h"

typedef __SIZE_TYPE__ size_t;

typedef struct {
  size_t re_nsub;
  void *__opaque;
} regex_t;

typedef struct {
  long rm_so, rm_eo;
} regmatch_t;

int regcomp(regex_t *preg construct(regex_compiled), const char *, int);
int regexec(const regex_t *preg handle(regex_compiled), const char *, size_t,
            regmatch_t *, int);
size_t regerror(int, const regex_t *preg, char *, size_t);
void regfree(regex_t *preg destroy(regex_compiled));

/* Standard use: compiled, matched against, then freed exactly once. */
void compile_match_free(void) {
  regex_t re;
  if (regcomp(&re, "a*b", 0) != 0)
    return;
  regexec(&re, "aab", 0, 0, 0);
  regfree(&re);
}

/* A failed compile is never used for matching or freed -- POSIX leaves
 * a failed regex_t's __opaque field unset and regfree() on it undefined,
 * so real callers (see src/util/grep.c and friends) skip both on this
 * path. */
void failed_compile_skips_use_and_free(void) {
  regex_t re;
  if (regcomp(&re, "[", 0) != 0)
    return;
  regfree(&re);
}

/* regerror's preg is deliberately unannotated (see regex.h's own
 * comment): the standard idiom passes a regex_t whose regcomp() call
 * just failed, which is exactly this shape. */
void error_message_after_failed_compile(void) {
  regex_t re;
  int rc = regcomp(&re, "[", 0);
  if (rc != 0) {
    char buf[64];
    regerror(rc, &re, buf, sizeof buf);
  }
}

/* A regex_t received as a borrowed parameter -- the same shape
 * construct-safe.c's lock_via_borrowed_pointer trusts for pthread_mutex_t,
 * since this per-function analysis cannot see the other translation
 * unit's own regcomp() call that established it. */
void match_via_borrowed_pointer(const regex_t *preg, const char *s) {
  regexec(preg, s, 0, 0, 0);
}

/* Recompiling into the same regex_t is safe once the prior compilation
 * was actually freed first -- unlike construct-unsafe.c's
 * initialize_twice, there is no double-construct here because regfree()
 * discharges the lifecycle before the second regcomp(). */
void recompile_after_free(void) {
  regex_t re;
  if (regcomp(&re, "a*b", 0) != 0)
    return;
  regfree(&re);
  if (regcomp(&re, "c*d", 0) != 0)
    return;
  regfree(&re);
}
