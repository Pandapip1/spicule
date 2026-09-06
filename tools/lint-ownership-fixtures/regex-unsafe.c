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
void regfree(regex_t *preg destroy(regex_compiled));

/* A genuinely never-compiled, on-stack regex_t -- real, checkable
 * evidence (see construct-safe.c's own comment on why a borrowed
 * pointer is trusted instead, and construct-unsafe.c's
 * use_uninitialized for the identical shape on mutex_t). */
void match_never_compiled(void) {
  regex_t re;
  regexec(&re, "aab", 0, 0, 0); /* ownership-expect: regex-uninitialized */
}

/* Recompiling the same regex_t without freeing the first compilation is
 * the loop-shaped version of the real leak this coverage exists for --
 * a caller that forgets regfree() and comes back around to regcomp()
 * again on the same object. */
void recompile_without_free(void) {
  regex_t re;
  if (regcomp(&re, "a*b", 0) == 0)
    regcomp(&re, "c*d", 0); /* ownership-expect: regex-recompiled */
}

/* Matching against a freed regex_t. */
void match_after_free(void) {
  regex_t re;
  if (regcomp(&re, "a*b", 0) != 0)
    return;
  regfree(&re);
  regexec(&re, "aab", 0, 0, 0); /* ownership-expect: regex-use-after-free */
}

/* Freeing the same regex_t twice. */
void free_twice(void) {
  regex_t re;
  if (regcomp(&re, "a*b", 0) != 0)
    return;
  regfree(&re);
  regfree(&re); /* ownership-expect: regex-double-free */
}
