/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * sysconf()/pathconf()/fpathconf()/confstr().
 *
 * <unistd.h> unconditionally lists all 125 _SC_ names as valid, and
 * sysconf.html reserves [EINVAL] for an *invalid* name -- so a
 * `default: EINVAL` that also catches mandated-but-unimplemented names
 * would misreport them as nonexistent. Instead the switch answers all
 * 125: a real value where there is one, else -1 with errno untouched
 * (sysconf.html's own answer for "no limit"). `default: EINVAL` is left
 * for names outside the mandated list entirely.
 *
 * An option answered -1 here must correspondingly be *absent* (no
 * _POSIX_* constant at all, not one set to -1) in <unistd.h> -- the two
 * must not drift.
 */
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include <errno.h>
#include "libc.h"
#include "plat_unistd.h"

long sysconf(int name)
{
	switch (name) {
	/* ---- limits with a real value ---------------------------- */
	case _SC_ARG_MAX: return ARG_MAX;
	case _SC_CHILD_MAX: return CHILD_CAP_LIMIT_;
	case _SC_CLK_TCK: return 100;
	case _SC_NGROUPS_MAX: return NGROUPS_MAX;
	case _SC_OPEN_MAX: return FD_MAX; // NOLINT(bugprone-branch-clone) -- OPEN_MAX and STREAM_MAX are independent POSIX limits even though spicule currently gives both the descriptor-table bound
	case _SC_STREAM_MAX: return FD_MAX;
	case _SC_TZNAME_MAX: return TZNAME_MAX;
	case _SC_VERSION: return _POSIX_VERSION; // NOLINT(bugprone-branch-clone) -- POSIX and POSIX.2 version selectors must remain tied to their distinct standard macros even when this release implements the same revision
	case _SC_2_VERSION: return _POSIX2_VERSION;
	case _SC_XOPEN_VERSION: return _XOPEN_VERSION;
	/* Both names, one number: limits.h.html has {PAGESIZE}
	 * "equivalent to {PAGE_SIZE}", and see include/unistd.h on why
	 * the two selectors are nonetheless distinct here. */
	case _SC_PAGESIZE:
	case _SC_PAGE_SIZE: return 4096;
	case _SC_HOST_NAME_MAX: return HOST_NAME_MAX;
	case _SC_TTY_NAME_MAX: return TTY_NAME_MAX;
	case _SC_SYMLOOP_MAX: return SYMLOOP_MAX;
	case _SC_IOV_MAX: return IOV_MAX;
	case _SC_REALTIME_SIGNALS: return _POSIX_REALTIME_SIGNALS;
	case _SC_RTSIG_MAX: return RTSIG_MAX;
	case _SC_SIGQUEUE_MAX: return SIGQUEUE_MAX;
	case _SC_TIMERS: return _POSIX_TIMERS;
	case _SC_TIMER_MAX: return TIMER_MAX; // NOLINT(bugprone-branch-clone) -- timer-count and delay-timer feature queries are semantically independent despite their current constants comparing equal
	case _SC_DELAYTIMER_MAX: return _POSIX_DELAYTIMER_MAX;
	case _SC_CPUTIME: return _POSIX_CPUTIME; // NOLINT(bugprone-branch-clone) -- these are independent POSIX option queries whose feature macros happen to name the same supported revision
	case _SC_MEMLOCK: return _POSIX_MEMLOCK;
	case _SC_MEMLOCK_RANGE: return _POSIX_MEMLOCK_RANGE;
	case _SC_SEMAPHORES: return _POSIX_SEMAPHORES;
	case _SC_SEM_NSEMS_MAX: return SEM_NSEMS_MAX_;
	case _SC_SEM_VALUE_MAX: return 2147483647L;
	case _SC_MESSAGE_PASSING: return _POSIX_MESSAGE_PASSING;
	case _SC_MQ_OPEN_MAX: return MQ_OPEN_MAX;
	case _SC_MQ_PRIO_MAX: return MQ_PRIO_MAX;
	case _SC_ASYNCHRONOUS_IO: return _POSIX_ASYNCHRONOUS_IO;
	case _SC_AIO_LISTIO_MAX: return AIO_LISTIO_MAX;
	case _SC_AIO_MAX: return AIO_MAX;
	case _SC_AIO_PRIO_DELTA_MAX: return AIO_PRIO_DELTA_MAX;
	case _SC_THREAD_DESTRUCTOR_ITERATIONS: return PTHREAD_DESTRUCTOR_ITERATIONS;
	case _SC_THREAD_KEYS_MAX: return PTHREAD_KEYS_MAX;
	case _SC_THREAD_STACK_MIN: return PTHREAD_STACK_MIN;
	case _SC_THREAD_THREADS_MAX: return PTHREAD_THREADS_MAX;
	/* The <limits.h> Runtime Increasable Values, which that header
	 * documents as the compile-time minimum this library promises;
	 * reporting anything smaller here would break the promise. */
	case _SC_LINE_MAX: return LINE_MAX;
	case _SC_RE_DUP_MAX: return RE_DUP_MAX;
	case _SC_BC_BASE_MAX: return BC_BASE_MAX;
	case _SC_BC_DIM_MAX: return BC_DIM_MAX;
	case _SC_BC_SCALE_MAX: return BC_SCALE_MAX;
	case _SC_BC_STRING_MAX: return BC_STRING_MAX;
	case _SC_COLL_WEIGHTS_MAX: return COLL_WEIGHTS_MAX;
	case _SC_EXPR_NEST_MAX: return EXPR_NEST_MAX;
	/* The atexit() table is a fixed array, so this is exact rather
	 * than a floor; shared with src/exit/exit.c through libc.h so
	 * the two cannot drift. */
	case _SC_ATEXIT_MAX: return ATEXIT_CAP_;

	/* ---- options this library does support -------------------- */
	/* Each of these names an option fully implemented here, so a
	 * positive value is the honest answer even though <unistd.h>
	 * defines no matching _POSIX_* constant for it. */
	case _SC_FSYNC: return _POSIX_VERSION;           /* src/unistd/fsync.c */ // NOLINT(bugprone-branch-clone) -- each selector reports a distinct implemented interface and must remain independently adjustable when feature levels diverge
	case _SC_REGEXP: return _POSIX_VERSION;          /* src/regex/regex.c */
	case _SC_SPAWN: return _POSIX_VERSION;           /* src/process/posix_spawn.c */
	case _SC_MONOTONIC_CLOCK: return _POSIX_VERSION; /* src/time/clock_gettime.c */
	case _SC_SHARED_MEMORY_OBJECTS: return _POSIX_VERSION; /* src/mman/shm.c */
	case _SC_MAPPED_FILES: return _POSIX_MAPPED_FILES;
	case _SC_MEMORY_PROTECTION: return _POSIX_MEMORY_PROTECTION;
	case _SC_THREADS: return _POSIX_THREADS;
	case _SC_THREAD_SAFE_FUNCTIONS: return _POSIX_THREAD_SAFE_FUNCTIONS;
	case _SC_THREAD_ATTR_STACKADDR:
	case _SC_THREAD_ATTR_STACKSIZE: return _POSIX_THREADS;
	case _SC_THREAD_PROCESS_SHARED: return _POSIX_THREADS;
	case _SC_BARRIERS: return _POSIX_BARRIERS;
	case _SC_CLOCK_SELECTION: return _POSIX_CLOCK_SELECTION;
	case _SC_READER_WRITER_LOCKS: return _POSIX_READER_WRITER_LOCKS;
	case _SC_SPIN_LOCKS: return _POSIX_SPIN_LOCKS;
	case _SC_TIMEOUTS: return _POSIX_TIMEOUTS;
	case _SC_XOPEN_UNIX: return _XOPEN_UNIX; // NOLINT(bugprone-branch-clone) -- UNIX and enhanced-I18N are independent XSI option selectors even though their macros currently have the same supported value
	case _SC_XOPEN_ENH_I18N: return _XOPEN_ENH_I18N;

	/* ---- spicule extensions ------------------------------------ */
	case _SC_NPROCESSORS_CONF:
	case _SC_NPROCESSORS_ONLN: return __plat_nprocessors();
	case _SC_PHYS_PAGES: return __plat_phys_pages();

	/* ---- the rest of the mandated list: -1, errno untouched ---- */
	/*
	 * Absent option groups, by what is missing: no prioritized AIO
	 * (_SC_PRIORITIZED_IO); no typed memory objects
	 * (_SC_TYPED_MEMORY_OBJECTS, _SC_XOPEN_SHM); no development
	 * utilities (the _SC_2_* set, including _SC_SHELL -- system()/
	 * popen() run %ComSpec%, not a POSIX shell); declined outright
	 * (_SC_TRACE*, _SC_SPORADIC_SERVER, _SC_PRIORITY_SCHEDULING,
	 * _SC_XOPEN_CRYPT, _SC_ADVISORY_INFO, _SC_IPV6/_SC_RAW_SOCKETS).
	 * _SC_JOB_CONTROL/_SC_SAVED_IDS: NT has no process groups to
	 * stop/resume, and src/unistd/ids.c has no saved-set id.
	 *
	 * The eight programming-model names are declined deliberately:
	 * x86_64-win32 is LLP64 (none of the four fit), and even where
	 * i386-win32 would fit ILP32_OFFBIG, confstr() can't supply the
	 * matching _CS_POSIX_V7_ILP32_OFFBIG_* build flags -- claiming a
	 * model whose flags are unobtainable is worse than declining it.
	 *
	 * _SC_LOGIN_NAME_MAX/_SC_GETPW_R_SIZE_MAX/_SC_GETGR_R_SIZE_MAX are
	 * the "no limit" case, not "no option": src/misc/pwd.c's records
	 * come from unbounded environment strings, so any fixed maximum
	 * here would be a guess; callers grow the buffer on ERANGE instead.
	 */
	case _SC_JOB_CONTROL:
	case _SC_SAVED_IDS:
	case _SC_PRIORITY_SCHEDULING:
	case _SC_PRIORITIZED_IO:
	case _SC_SYNCHRONIZED_IO:
	case _SC_2_C_BIND:
	case _SC_2_C_DEV:
	case _SC_2_FORT_DEV:
	case _SC_2_FORT_RUN:
	case _SC_2_SW_DEV:
	case _SC_2_LOCALEDEF:
	case _SC_2_CHAR_TERM:
	case _SC_2_UPE:
	case _SC_2_PBS:
	case _SC_2_PBS_ACCOUNTING:
	case _SC_2_PBS_CHECKPOINT:
	case _SC_2_PBS_LOCATE:
	case _SC_2_PBS_MESSAGE:
	case _SC_2_PBS_TRACK:
	case _SC_THREAD_PRIORITY_SCHEDULING:
	case _SC_THREAD_PRIO_INHERIT:
	case _SC_THREAD_PRIO_PROTECT:
	case _SC_THREAD_CPUTIME:
	case _SC_THREAD_SPORADIC_SERVER:
	case _SC_THREAD_ROBUST_PRIO_INHERIT:
	case _SC_THREAD_ROBUST_PRIO_PROTECT:
	case _SC_GETGR_R_SIZE_MAX:
	case _SC_GETPW_R_SIZE_MAX:
	case _SC_LOGIN_NAME_MAX:
	case _SC_XOPEN_CRYPT:
	case _SC_XOPEN_SHM:
	case _SC_XOPEN_REALTIME:
	case _SC_XOPEN_REALTIME_THREADS:
	case _SC_XOPEN_STREAMS:
	case _SC_XOPEN_UUCP:
	case _SC_ADVISORY_INFO:
	case _SC_SHELL:
	case _SC_SPORADIC_SERVER:
	case _SC_SS_REPL_MAX:
	case _SC_TYPED_MEMORY_OBJECTS:
	case _SC_TRACE:
	case _SC_TRACE_EVENT_FILTER:
	case _SC_TRACE_EVENT_NAME_MAX:
	case _SC_TRACE_INHERIT:
	case _SC_TRACE_LOG:
	case _SC_TRACE_NAME_MAX:
	case _SC_TRACE_SYS_MAX:
	case _SC_TRACE_USER_EVENT_MAX:
	case _SC_IPV6:
	case _SC_RAW_SOCKETS:
	case _SC_V6_ILP32_OFF32:
	case _SC_V6_ILP32_OFFBIG:
	case _SC_V6_LP64_OFF64:
	case _SC_V6_LPBIG_OFFBIG:
	case _SC_V7_ILP32_OFF32:
	case _SC_V7_ILP32_OFFBIG:
	case _SC_V7_LP64_OFF64:
	case _SC_V7_LPBIG_OFFBIG:
		return -1;

	default:
		errno = EINVAL;
		return -1;
	}
}

/* pathconf()/fpathconf(). Unlike sysconf(), this one may EINVAL a
 * mandated name if it's inapplicable to the file (fpathconf.html: a
 * *may fail*) -- but the name itself must still exist, hence <unistd.h>
 * defines all 21 either way.
 *
 * Nothing here looks at path or fd -- every answer is a property of this
 * library/NT, not the file -- so fpathconf() just forwards, keeping the
 * two entry points in agreement by construction. */
long pathconf(const char *path, int name)
{
	(void)path;
	switch (name) {
	case _PC_LINK_MAX: return 1023;
	case _PC_MAX_CANON: return 255; // NOLINT(bugprone-branch-clone) -- canonical-input, input, and filename limits are distinct pathconf properties that may diverge on another backend
	case _PC_MAX_INPUT: return 255;
	case _PC_NAME_MAX: return NAME_MAX;
	case _PC_PATH_MAX: return PATH_MAX; // NOLINT(bugprone-branch-clone) -- pathname and pipe-buffer limits are independent properties whose current public constants happen to compare equal
	case _PC_PIPE_BUF: return PIPE_BUF;
	case _PC_CHOWN_RESTRICTED: return 1; // NOLINT(bugprone-branch-clone) -- ownership restriction and truncation behavior are independent Boolean path properties
	case _PC_NO_TRUNC: return 1;
	/* Same character _POSIX_VDISABLE names; keep the two equal. */
	case _PC_VDISABLE: return 0;
	case _PC_FILESIZEBITS: return FILESIZEBITS;
	/* NTFS reparse points carry symlinks, and this library's own path
	 * handling is bounded by PATH_MAX, so that is the length of link
	 * content readlink() can actually produce. */
	case _PC_SYMLINK_MAX: return PATH_MAX;
	case _PC_2_SYMLINKS: return 1;
	/* NT keeps every file time as a FILETIME, a count of 100ns ticks,
	 * and that is the resolution utimensat()/futimens() can preserve
	 * (src/stat/utimensat.c) -- not the nanosecond struct timespec can
	 * express. */
	case _PC_TIMESTAMP_RESOLUTION: return 100;

	/* The remaining seven answer "no limit / not supported" (-1, errno
	 * untouched) rather than EINVAL: _PC_ASYNC_IO/_PC_PRIO_IO/
	 * _PC_SYNC_IO are the aio/prioritized-I/O options sysconf() also
	 * declines; _PC_ALLOC_SIZE_MIN and the three _PC_REC_* would need
	 * the volume's cluster geometry per file, which this function
	 * can't produce without opening path. */
	case _PC_ASYNC_IO:
	case _PC_PRIO_IO:
	case _PC_SYNC_IO:
	case _PC_ALLOC_SIZE_MIN:
	case _PC_REC_INCR_XFER_SIZE:
	case _PC_REC_MAX_XFER_SIZE:
	case _PC_REC_MIN_XFER_SIZE:
	case _PC_REC_XFER_ALIGN:
		return -1;

	default: errno = EINVAL; return -1;
	}
}

long fpathconf(int fd, int name) { (void)fd; return pathconf("", name); } // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
int getpagesize(void) { return 4096; }
int getdtablesize(void) { return FD_MAX; }
/* confstr.html: an invalid name returns 0 with EINVAL, not 1 or
 * (size_t)-1. <unistd.h> defines exactly one _CS_* constant (_CS_PATH),
 * so every other name is invalid here.
 *
 * POSIX's other zero case -- a valid name with no configuration-defined
 * value, returning 0 with errno unchanged -- has no name to reach it in
 * this tree; a case wanting it can't just set s to "", since the tail
 * below counts the null it writes and returns 1. */
size_t confstr(int name, char *buf, size_t len)
{
	const char *s;
	size_t i;

	switch (name) {
	case _CS_PATH: s = "/bin:/usr/bin"; break;
	default: errno = EINVAL; return 0;
	}
	for (i = 0; s[i] && i + 1 < len; i++) buf[i] = s[i];
	if (len) buf[i] = 0;
	while (s[i]) i++;
	return i + 1;
}
