/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _SEMAPHORE_H
#define _SEMAPHORE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <ownership.h>
#define __NEED_mode_t
#include <bits/alltypes.h>

struct timespec;

typedef struct {
	void *__handle;
	unsigned int __magic;
	unsigned int __named;
} sem_t;

#define SEM_FAILED ((sem_t *)-1)
#define SEM_VALUE_MAX 2147483647

fallible
int sem_init(sem_t *sem construct(semaphore), int, unsigned int);
fallible
int sem_destroy(sem_t *sem destroy(semaphore));
sem_t *sem_open(const char *, int, ...);
fallible
int sem_close(sem_t *);
fallible
int sem_unlink(const char *);
fallible
int sem_wait(sem_t *sem handle(semaphore));
fallible
int sem_trywait(sem_t *sem handle(semaphore));
fallible
int sem_timedwait(sem_t *sem handle(semaphore), const struct timespec *);
fallible
async_signal_safe
int sem_post(sem_t *sem handle(semaphore));
int sem_getvalue(sem_t *sem handle(semaphore), int *);

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
