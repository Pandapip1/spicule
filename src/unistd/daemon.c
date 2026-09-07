/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * daemon(): the standard BSD/glibc fork()+setsid() idiom (BSD; not in
 * POSIX), built on the existing fork(), setsid(), chdir() and
 * open()+dup2(). DESCRIPTION: fork a child that outlives the caller (the
 * parent _exit(0)s); in the child, setsid() to drop the controlling
 * terminal and become a session/group leader; unless nochdir, chdir("/")
 * so the daemon doesn't pin its starting filesystem; unless noclose,
 * redirect fd 0/1/2 to /dev/null. Returns 0 in the child on success,
 * -1/errno on failure; the parent never returns from daemon() at all. */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include "libc.h"

int daemon(int nochdir, int noclose)
{
	pid_t pid = fork();

	if (pid < 0) return -1;
	if (pid > 0) _exit(0);	/* parent: detach, never returning here */

	/* Child, from here on: unlike the parent branch, this process can
	 * still return a failure to its caller. */
	if (setsid() < 0) return -1;

	if (!nochdir && chdir("/") < 0) return -1;

	if (!noclose) {
		int fd = open("/dev/null", O_RDWR);
		if (fd >= 0) {
			/* dup2(fd, fd) is a documented no-op, so this is
			 * correct even if open() returned 0, 1 or 2. */
			if (dup2(fd, STDIN_FILENO) < 0 ||
			    dup2(fd, STDOUT_FILENO) < 0 ||
			    dup2(fd, STDERR_FILENO) < 0) {
				/* A real leak otherwise: unlike the success path
				 * below, nothing here ever closed fd. */
				if (fd > STDERR_FILENO) (void)close(fd);
				return -1;
			}
			if (fd > STDERR_FILENO) (void)close(fd);
			/* Checker gap (ntlibc.ResourceLeak): when fd IS one of
			 * 0/1/2, dup2(fd, fd) above already retired it as that
			 * standard stream for the rest of the process -- the
			 * checker can't see that aliasing, so it reports fd as
			 * never released. */
		}
		/* open() failing here is not daemon()'s own failure --
		 * glibc's daemon() takes the same view and skips the
		 * redirect silently. */
	}
	return 0;
}

// NOLINTEND(misc-include-cleaner)
