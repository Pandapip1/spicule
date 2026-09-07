/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Test-harness scaffolding for the Linux platform pilot's exit/misc/
 * select/signal extension -- NOT part of spicule; see
 * fuzz/linux_pilot_harness.c's banner for the general shape.
 *
 * src/misc/sched.c and src/misc/resource.c reference a handful of
 * cross-subsystem symbols belonging to subsystems this session does not
 * own; those are stubbed below. getpid()/getppid()/getuid()/geteuid()/
 * getpgrp() get real (not stubbed) one-syscall standins instead, since
 * the real src/unistd implementations are NT-only (__teb(),
 * __plat_getppid(), __plat_detect_uid()) and out of scope here -- this
 * lets sched.c/resource.c's real front doors be exercised end to end.
 */
#include <sys/types.h>
#include <sys/resource.h>
#include "libc.h"

/* Confirmed via a throwaway host program printing <sys/syscall.h>'s
 * SYS_* macros. */
#define SYS_getpid  172
#define SYS_getppid 173
#define SYS_getuid  174

extern long syscall(long number, ...);

/* This test only ever asks about a real, but untracked-by-spicule,
 * foreign pid (its own parent), so "never a known child" is honest. */
struct __child *__child_find(int pid) { (void)pid; return 0; }

void __rusage_children(struct rusage *ru) { if (ru) __builtin_memset(ru, 0, sizeof *ru); }

/* Referenced only on resource.c's RLIMIT_FSIZE-exceeded path, never
 * reachable from any call this test makes -- needed for the linker only. */
int __raise_internal(int sig) { (void)sig; return 0; }

void __mq_fd_closed(int fd) { (void)fd; }

pid_t getpid(void) { return (pid_t)syscall(SYS_getpid); }
pid_t getppid(void) { return (pid_t)syscall(SYS_getppid); }
uid_t getuid(void) { return (uid_t)syscall(SYS_getuid); }
uid_t geteuid(void) { return getuid(); }
/* Never reached (always which==PRIO_PROCESS), but getpriority()/
 * setpriority() reference it regardless. */
pid_t getpgrp(void) { return getpid(); }
