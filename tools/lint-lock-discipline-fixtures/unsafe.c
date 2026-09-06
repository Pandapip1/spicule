/* SPDX-FileCopyrightText: (C) 2026 Gavin John */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "../../include/ownership.h"

/* Real, source-visible tokens mirroring include/pthread.h's own
 * pthread_mutex_locked/pthread_mutex_unlocked pair -- see safe.c's own
 * copy of this comment for why this fixture needs its own annotated local
 * prototypes rather than the bare, unannotated ones it used to declare. */
tokdef mutex_unlocked;
tokdef mutex_locked lock_held;

typedef struct mutex mutex_t;
int pthread_mutex_lock(mutex_t * handle(mutex) consume(mutex_unlocked) grant(mutex_locked));
int pthread_mutex_unlock(mutex_t * handle(mutex) consume(mutex_locked) grant(mutex_unlocked));
int pthread_mutex_destroy(mutex_t * destroy(mutex) consume(mutex_unlocked));
int pthread_cond_wait(void *, mutex_t * handle(mutex) withtok(mutex_locked));

int unlocked_release(mutex_t *mutex) {
  return pthread_mutex_unlock(mutex); /* lock-discipline-expect */
}

int missing_release(mutex_t *mutex) {
  if (pthread_mutex_lock(mutex) != 0)
    return -1;
  return 0; /* lock-discipline-expect */
}

int wait_without_lock(void *condition, mutex_t *mutex) {
  return pthread_cond_wait(condition, mutex); /* lock-discipline-expect */
}

int destroy_held(mutex_t *mutex) {
  int result;
  if (pthread_mutex_lock(mutex) != 0)
    return -1;
  result = pthread_mutex_destroy(mutex); /* lock-discipline-expect */
  if (pthread_mutex_unlock(mutex) != 0)
    __builtin_unreachable();
  return result;
}

#define lock_requires_held_on_entry(argument) \
  __attribute__((annotate("ntlibc_lock_requires_held_on_entry:" #argument)))

/* Proves the hand-off exemption safe.c's cond_wait/cond_wait_cleanup
 * fixtures rely on is scoped to the one designated argument
 * (lock_requires_held_on_entry(1) below), not the whole function: a
 * *second*, ordinary mutex this same annotated function leaks must
 * still be reported. If LockDisciplineChecker.cpp's exemption were ever
 * broadened to skip the whole annotated function instead of tagging the
 * one MemRegion the annotation names, this finding would silently
 * vanish along with the real one. */
int cond_wait_with_extra_lock(void *cond, mutex_t *mutex, mutex_t *extra)
    lock_requires_held_on_entry(1);
int cond_wait_with_extra_lock(void *cond, mutex_t *mutex, mutex_t *extra) {
  if (pthread_mutex_lock(extra) != 0)
    return -1;
  return 0; /* lock-discipline-expect */
}

/* Same unlock-then-relock shape as safe.c's annotated cond_wait, and
 * even the same real function name cond_wait once used to match by, but
 * with no lock_requires_held_on_entry annotation on its own declaration:
 * proves the hand-off exemption comes from a real, source-visible
 * attribute the checker reads off the function, not from matching this
 * shape or this name. Without the annotation seeding `mutex` as held on
 * entry, the first unlock below is indistinguishable from releasing a
 * lock nobody ever acquired -- and, symmetrically, the final relock is
 * an ordinary acquisition this (unexempted) function then returns while
 * still holding, its own separate finding. */
int cond_wait(void *cond, mutex_t *mutex, void *absolute) {
  int error = pthread_mutex_unlock(mutex); /* lock-discipline-expect */
  if (error)
    return error;
  return pthread_mutex_lock(mutex); /* lock-discipline-expect */
}
