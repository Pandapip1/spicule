/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * posix_spawnattr_t: the ten getter/setter accessors.
 *
 * These are attribute *storage* and nothing else. No accessor here is
 * required to act on the value -- posix_spawn() is where acting on it is
 * specified, and where this implementation reports what it cannot do
 * (posix_spawn.c). That split is what lets posix_spawnattr_setschedpolicy()
 * exist at all on a scheduler with no POSIX policies: storing and
 * returning a value is a promise this code can keep, so it does; a
 * setter that refused the value instead would be lying the other way,
 * since POSIX gives it no error for "no such policy" here.
 *
 * Each function returns an error number, not errno, and none of them can
 * actually fail: there's no allocation, and the [EINVAL] "attr is
 * invalid" case is a POSIX *may fail* this implementation doesn't take
 * up -- an un-_init()ed posix_spawnattr_t is undefined behavior, not a
 * detectable error.
 *
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawnattr_init.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawnattr_getflags.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawnattr_getpgroup.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawnattr_getsigdefault.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawnattr_getsigmask.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawnattr_getschedparam.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/posix_spawnattr_getschedpolicy.html
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <spawn.h>
#include <string.h>
#include <signal.h>
#include "libc.h"

/* posix_spawnattr_init.html DESCRIPTION: "the resulting spawn
 * attributes object ... contains ... the default values" -- and the
 * default for every attribute this header has is the "do nothing"
 * value: no flags set, so nothing else is even consulted. */
int posix_spawnattr_init(posix_spawnattr_t *a)
{
	memset(a, 0, sizeof *a);
	return 0;
}

/* Nothing is allocated by any setter, so destroy has nothing to
 * release.  It still exists, is still required, and callers must still
 * call it: what it destroys is the caller's licence to keep using the
 * object, not a heap block. */
int posix_spawnattr_destroy(posix_spawnattr_t *a)
{
	(void)a;
	return 0;
}

int posix_spawnattr_getflags(const posix_spawnattr_t *__restrict a, short *__restrict out)
{
	*out = a->__flags;
	return 0;
}

int posix_spawnattr_setflags(posix_spawnattr_t *a, short flags)
{
	a->__flags = flags;
	return 0;
}

int posix_spawnattr_getpgroup(const posix_spawnattr_t *__restrict a, pid_t *__restrict out)
{
	*out = a->__pgroup;
	return 0;
}

int posix_spawnattr_setpgroup(posix_spawnattr_t *a, pid_t pgroup)
{
	a->__pgroup = pgroup;
	return 0;
}

int posix_spawnattr_getsigdefault(const posix_spawnattr_t *__restrict a, sigset_t *__restrict out)
{
	*out = a->__sigdefault;
	return 0;
}

int posix_spawnattr_setsigdefault(posix_spawnattr_t *__restrict a, const sigset_t *__restrict set)
{
	a->__sigdefault = *set;
	return 0;
}

int posix_spawnattr_getsigmask(const posix_spawnattr_t *__restrict a, sigset_t *__restrict out)
{
	*out = a->__sigmask;
	return 0;
}

int posix_spawnattr_setsigmask(posix_spawnattr_t *__restrict a, const sigset_t *__restrict set)
{
	a->__sigmask = *set;
	return 0;
}

int posix_spawnattr_getschedparam(const posix_spawnattr_t *__restrict a,
                                  struct sched_param *__restrict out)
{
	*out = a->__param;
	return 0;
}

int posix_spawnattr_setschedparam(posix_spawnattr_t *__restrict a,
                                  const struct sched_param *__restrict param)
{
	a->__param = *param;
	return 0;
}

int posix_spawnattr_getschedpolicy(const posix_spawnattr_t *__restrict a, int *__restrict out)
{
	*out = a->__policy;
	return 0;
}

int posix_spawnattr_setschedpolicy(posix_spawnattr_t *a, int policy)
{
	a->__policy = policy;
	return 0;
}

// NOLINTEND(misc-include-cleaner)
