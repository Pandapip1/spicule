/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * POSIX semaphores over NT semaphore dispatcher objects. Named semaphore
 * names live in an ordinary file namespace, whose small record names the
 * NT object. unlink() can therefore remove the discoverable name while
 * already-open handles keep the dispatcher object alive.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- strnlen(): bound name validation before path construction
#include <semaphore.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <errno.h>
#include "libc.h"
#include "ownership_stubs.h"
#include "pthread_impl.h"
#include "plat_thread.h"

#define SEM_MAGIC 0x53454d31u
#define NAMED_MAX 64

struct named_sem {
	sem_t sem;
	char *path;
	unsigned refs;
	int linked;
};

static struct named_sem named[NAMED_MAX];
static unsigned object_sequence;
static unsigned unnamed_count;

static int valid(const sem_t *sem)
{
	return sem && sem != SEM_FAILED && sem->__magic == SEM_MAGIC && sem->__handle;
}

static const char *tmpdir(void)
{
	const char *p = getenv("TMPDIR");
	if (!p || !*p) p = getenv("TMP");
	if (!p || !*p) p = getenv("TEMP");
	return p && *p ? p : ".";
}

static int name_char(unsigned char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

withtok(heap_allocated)
static char *sem_path(const char *name)
{
	const char *component, *dir;
	size_t n, d, i, maxdir;
	const size_t prefix = sizeof "/ntlibc-sem/" - 1;
	size_t total;
	char *path;
	if (!name) { errno = EINVAL; return NULL; }
	component = *name == '/' ? name + 1 : name;
	/* A longer name has the same ENAMETOOLONG result whatever follows
	 * NAME_MAX, so do not scan an unbounded rejected suffix. */
	n = strnlen(component, NAME_MAX + 1);
	if (!n) { errno = EINVAL; return NULL; }
	if (n > NAME_MAX) { errno = ENAMETOOLONG; return NULL; }
	for (i = 0; i < n; i++) if (!name_char((unsigned char)component[i])) {
		errno = EINVAL;
		return NULL;
	}
	if (n > (size_t)PATH_MAX - 1 - prefix) {
		errno = ENAMETOOLONG;
		return NULL;
	}
	/* The preceding guard makes computing the exact remaining room
	 * non-wrapping.  Once maxdir + 1 bytes have been examined, the
	 * path is known to be too long and no rejected suffix needs scanning. */
	maxdir = (size_t)PATH_MAX - 1 - prefix - n;
	dir = tmpdir(); d = strnlen(dir, maxdir + 1);
	if (d > maxdir) {
		errno = ENAMETOOLONG;
		return NULL;
	}
	total = d + prefix + n + 1;
	path = malloc(total);
	if (!path) return NULL;
	snprintf(path, total, "%s/ntlibc-sem/%s", dir, component);
	return path;
}

/* Call sites all pass a path built by sem_path(), which always embeds a
 * literal "/ntlibc-sem/" component, so strrchr() can't return NULL here. */
static int ensure_dir(const char *path) __attribute__((nonnull(1)));
static int ensure_dir(const char *path)
{
	char *copy = strdup(path);
	char *slash;
	int saved;
	if (!copy) return -1;
	slash = strrchr(copy, '/');
	*slash = 0;
	if (mkdir(copy, 0777) < 0 && errno != EEXIST) {
		saved = errno; free(copy); errno = saved; return -1;
	}
	free(copy);
	return 0;
}

/* Creating a named semaphore's file and filling it isn't one filesystem
 * operation, so this lock serializes that interval: without it, two
 * sem_open(O_CREAT) callers can race, one creating the empty record while
 * the other reads it, and both abandon the name (fork/1-1.c hits this).
 * The full path, not just the POSIX name, is hashed so processes with
 * different temp namespaces don't unnecessarily share a lock. */
__wraps static unsigned long long path_hash(const char *s)
    __attribute__((nonnull(1)));
__wraps static unsigned long long path_hash(const char *s)
{
	unsigned long long h = 1469598103934665603ULL;
	while (*s) { h ^= (unsigned char)*s++; h *= 1099511628211ULL; }
	return h;
}

static int namespace_lock(const char *path, __plat_handle_t *out)
{
	char name[96];
	unsigned long long hash = path_hash(path);
	int n;

	n = snprintf(name, sizeof name, "\\BaseNamedObjects\\ntlibc.sem.name.%08x%08x",
	         (unsigned)(hash >> 32), (unsigned)hash);
	if (n < 0 || (size_t)n >= sizeof name) {
		if (n >= 0) errno = ENAMETOOLONG;
		return -1;
	}
	return __plat_named_mutant_acquire(name, out);
}

static void namespace_unlock(__plat_handle_t lock)
{
	__plat_named_mutant_release(lock);
}

static struct named_sem *find_path(const char *path)
{
	int i;
	for (i = 0; i < NAMED_MAX; i++)
		if (named[i].path && named[i].linked && !strcmp(named[i].path, path))
			return &named[i];
	return NULL;
}

static struct named_sem *find_sem(sem_t *sem)
{
	int i;
	for (i = 0; i < NAMED_MAX; i++) if (&named[i].sem == sem) return &named[i];
	return NULL;
}

static struct named_sem *free_slot(void)
{
	int i;
	for (i = 0; i < NAMED_MAX; i++) if (!named[i].path) return &named[i];
	return NULL;
}

int sem_init(sem_t *sem construct(semaphore), int pshared, unsigned value) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	__plat_handle_t h;
	(void)pshared;
	if (!sem || value > SEM_VALUE_MAX) { errno = EINVAL; return -1; }
	__plat_fast_lock();
	if (unnamed_count == SEM_NSEMS_MAX_) {
		__plat_fast_unlock();
		errno = ENOSPC;
		return -1;
	}
	unnamed_count++;
	__plat_fast_unlock();
	/* fork() only clones OBJ_INHERIT handles. A process-shared sem_t
	 * stores this handle value in shared memory, and named semaphores
	 * have the same requirement when already open across fork. */
	if (__plat_semaphore_create((long)value, SEM_VALUE_MAX, 1, &h) < 0) {
		__plat_fast_lock();
		unnamed_count--;
		__plat_fast_unlock();
		return -1;
	}
	sem->__handle = h; sem->__magic = SEM_MAGIC; sem->__named = 0;
	return 0;
}

int sem_destroy(sem_t *sem destroy(semaphore))
{
	if (!valid(sem) || sem->__named) { errno = EINVAL; return -1; }
	__plat_sync_close(sem->__handle);
	memset(sem, 0, sizeof *sem);
	__plat_fast_lock();
	unnamed_count--;
	__plat_fast_unlock();
	return 0;
}

sem_t *sem_open(const char *name, int oflag, ...)
{
	char *path, object[96];
	struct named_sem *entry;
	__plat_handle_t h, ns = 0;
	int fd = -1, created = 0, saved, recover = 0, n;
	unsigned value = 0;
	mode_t mode = 0;
	ssize_t got;

	if (oflag & ~(O_CREAT | O_EXCL)) { errno = EINVAL; return SEM_FAILED; }
	if (oflag & O_CREAT) {
		va_list ap;
		va_start(ap, oflag); mode = (mode_t)va_arg(ap, int); value = va_arg(ap, unsigned); va_end(ap);
		if (value > SEM_VALUE_MAX) { errno = EINVAL; return SEM_FAILED; }
	}
	path = sem_path(name);
	if (!path) return SEM_FAILED;
	__plat_fast_lock();
	entry = find_path(path);
	if (entry) {
		if ((oflag & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) {
			__plat_fast_unlock(); free(path); errno = EEXIST; return SEM_FAILED;
		}
		entry->refs++;
		__plat_fast_unlock(); free(path); errno = 0; return &entry->sem;
	}
	__plat_fast_unlock();
	if (ensure_dir(path) < 0) { free(path); return SEM_FAILED; }
	if (namespace_lock(path, &ns) < 0) { free(path); return SEM_FAILED; }
	/* A same-process opener may have populated the cache while this caller
	 * waited for the cross-process publication lock. */
	__plat_fast_lock();
	entry = find_path(path);
	if (entry) {
		if ((oflag & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) {
			__plat_fast_unlock(); namespace_unlock(ns); free(path);
			errno = EEXIST; return SEM_FAILED;
		}
		entry->refs++;
		__plat_fast_unlock(); namespace_unlock(ns); free(path);
		errno = 0; return &entry->sem;
	}
	__plat_fast_unlock();

retry_record:
	created = 0;
	if (oflag & O_CREAT) {
		/* The record is implementation metadata, not the semaphore's
		 * permission object. Keeping it owner-writable is necessary on
		 * this filesystem mapping: clearing owner-write maps to NT's
		 * read-only attribute and would make the POSIX-required
		 * sem_unlink() fail merely because mode was 0444 or 0. */
		(void)mode;
		fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
		if (fd >= 0) created = 1;
		else if (errno == EEXIST && !(oflag & O_EXCL)) fd = open(path, O_RDONLY, 0);
	} else fd = open(path, O_RDONLY, 0);
	if (fd < 0) { saved = errno; goto fail_locked; }
	if (created) {
		int create_result;
		n = snprintf(object, sizeof object, "\\BaseNamedObjects\\ntlibc.sem.%d.%u",
		         (int)getpid(), ++object_sequence);
		if (n < 0 || (size_t)n >= sizeof object) {
			saved = n < 0 ? errno : ENAMETOOLONG;
			(void)close(fd);
			(void)unlink(path);
			goto fail_locked;
		}
		create_result = __plat_named_semaphore_create(object, (long)value, SEM_VALUE_MAX, &h);
		if (create_result < 0 ||
		    write(fd, object, (size_t)n + 1) != (ssize_t)n + 1) {
			/* __plat_named_semaphore_create()'s own contract (src/internal/
			 * plat_thread.h) is 0 on success, negative on failure -- never
			 * positive -- so testing the failure condition directly here
			 * (rather than its logical complement, "== 0", inverted) is
			 * the more precise match for what this is actually asking,
			 * not merely a style preference: it is what lets
			 * tools/clang/ErrnoDisciplineChecker.cpp prove this errno read
			 * reflects create_result's own failure without first having
			 * to rule out a hypothetical positive return this function
			 * never actually produces. */
			saved = create_result < 0 ? errno : EIO;
			(void)close(fd); (void)unlink(path); goto fail_locked;
		}
	} else {
		int open_result;
		got = read(fd, object, sizeof object - 1);
		if (got <= 0) {
			saved = got < 0 ? errno : EIO;
			(void)close(fd);
			/* A creator can die after publishing the record but before
			 * filling it.  O_CREAT without O_EXCL owns recovery while the
			 * namespace lock proves nobody can still be publishing it. */
			if ((oflag & O_CREAT) && !(oflag & O_EXCL) && !recover) {
				recover = 1;
				if (unlink(path) == 0) goto retry_record;
				saved = errno;
			}
			goto fail_locked;
		}
		object[got] = 0;
		open_result = __plat_named_semaphore_open(object, &h);
		if (open_result < 0) {
			(void)close(fd);
			if ((oflag & O_CREAT) && !(oflag & O_EXCL) && !recover &&
			    open_result == -2) {
				recover = 1;
				if (unlink(path) == 0) goto retry_record;
				saved = errno;
			} else {
				if (open_result == -2) errno = ENOENT;
				saved = errno;
			}
			goto fail_locked;
		}
	}
	(void)close(fd);
	__plat_fast_lock();
	entry = free_slot();
	if (!entry) {
		__plat_fast_unlock(); __plat_sync_close(h);
		if (created) (void)unlink(path);
		saved = EMFILE; goto fail_locked;
	}
	entry->sem.__handle = h; entry->sem.__magic = SEM_MAGIC; entry->sem.__named = 1;
	entry->path = path; entry->refs = 1; entry->linked = 1;
	__plat_fast_unlock();
	namespace_unlock(ns);
	errno = 0;
	return &entry->sem;

fail_locked:
	namespace_unlock(ns);
	free(path);
	errno = saved;
	return SEM_FAILED;
}

int sem_close(sem_t *sem)
{
	struct named_sem *entry;
	if (!valid(sem) || !sem->__named) { errno = EINVAL; return -1; }
	__plat_fast_lock();
	entry = find_sem(sem);
	if (!entry || !entry->refs) { __plat_fast_unlock(); errno = EINVAL; return -1; }
	entry->refs--;
	if (!entry->linked && !entry->refs) {
		__plat_sync_close(entry->sem.__handle);
		free(entry->path);
		memset(entry, 0, sizeof *entry);
	}
	__plat_fast_unlock();
	return 0;
}

int sem_unlink(const char *name)
{
	char *path = sem_path(name);
	struct named_sem *entry;
	__plat_handle_t ns = 0;
	int result, saved;
	if (!path) return -1;
	if (ensure_dir(path) < 0) { free(path); return -1; }
	if (namespace_lock(path, &ns) < 0) { free(path); return -1; }
	result = unlink(path); saved = errno;
	if (!result) {
		__plat_fast_lock();
		entry = find_path(path);
		if (entry) {
			entry->linked = 0;
			if (!entry->refs) {
				__plat_sync_close(entry->sem.__handle);
				free(entry->path);
				__ownership_writable_span(entry, sizeof *entry);
				memset(entry, 0, sizeof *entry);
			}
		}
		__plat_fast_unlock();
	}
	namespace_unlock(ns);
	free(path); errno = saved; return result;
}

static int wait_handle(sem_t *sem, long long ticks)
{
	int r;
	if (!valid(sem)) { errno = EINVAL; return -1; }
	r = __plat_wait_one(sem->__handle, 1, 1, ticks);
	if (r == __PLAT_WAIT_OK) return 0;
	if (r == __PLAT_WAIT_TIMEOUT) { errno = EAGAIN; return -1; }
	if (r == __PLAT_WAIT_INTR) { errno = EINTR; return -1; }
	return -1; /* __PLAT_WAIT_ERROR: errno already set */
}

static int restartable_interruption(unsigned long *caught, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
	unsigned long *restarted)
{
	unsigned long now_caught = __sig_thread_caught_count();
	unsigned long now_restarted = __sig_thread_restart_count();
	unsigned long delivered = now_caught - *caught;

	if (!delivered) return 0;
	if (delivered == now_restarted - *restarted) {
		*caught = now_caught;
		*restarted = now_restarted;
		return 1;
	}
	return -1;
}

int sem_trywait(sem_t *sem handle(semaphore))
{
	return wait_handle(sem, 0);
}

int sem_wait(sem_t *sem handle(semaphore))
{
	const long long slice = -500000; /* 50 ms: observe handlers run elsewhere. */
	unsigned long caught;
	unsigned long restarted;
	int r;
	if (!valid(sem)) { errno = EINVAL; return -1; }
	__pthread_testcancel();
	caught = __sig_thread_caught_count();
	restarted = __sig_thread_restart_count();
	for (;;) {
		r = wait_handle(sem, slice);
		__pthread_testcancel();
		/* NT semaphore waits aren't part of cross-process signal delivery,
		 * so pending handlers must be run explicitly before deciding
		 * whether this operation was interrupted. */
		__sig_drain_pending();
		if (!r) return 0;
		if (errno == EINTR) {
			/* A deferred pthread_cancel() also produces a __PLAT_WAIT_INTR
			 * wake with no signal delivered (see pthread_cancel.c's
			 * redirect_async_cancel()); only a genuine signal earns EINTR. */
			if (restartable_interruption(&caught, &restarted) >= 0) continue;
			return -1;
		}
		if (errno != EAGAIN) return -1;
		r = restartable_interruption(&caught, &restarted);
		if (r < 0) { errno = EINTR; return -1; }
	}
}

int sem_timedwait(sem_t *sem handle(semaphore), const struct timespec *abstime)
{
	struct timespec now;
	long long ticks;
	unsigned long caught;
	unsigned long restarted;
	int r;
	__pthread_testcancel();
	if (sem_trywait(sem) == 0) return 0;
	if (errno != EAGAIN) return -1;
	if (!abstime || abstime->tv_nsec < 0 || abstime->tv_nsec >= 1000000000L) {
		errno = EINVAL; return -1;
	}
	caught = __sig_thread_caught_count();
	restarted = __sig_thread_restart_count();
	for (;;) {
		clock_gettime(CLOCK_REALTIME, &now);
		ticks = __timespec_diff_ticks(abstime->tv_sec, abstime->tv_nsec,
			now.tv_sec, now.tv_nsec);
		if (ticks <= 0) { errno = ETIMEDOUT; return -1; }
		if (ticks > 500000) ticks = 500000;
		r = wait_handle(sem, -ticks);
		__pthread_testcancel();
		__sig_drain_pending();
		if (!r) return 0;
		if (errno == EINTR) {
			/* See sem_wait()'s comment on this same check. */
			if (restartable_interruption(&caught, &restarted) >= 0) continue;
			return -1;
		}
		if (errno != EAGAIN) return -1;
		r = restartable_interruption(&caught, &restarted);
		if (r < 0) { errno = EINTR; return -1; }
	}
}

int sem_post(sem_t *sem handle(semaphore))
{
	if (!valid(sem)) { errno = EINVAL; return -1; }
	return __plat_semaphore_post(sem->__handle);
}

int sem_getvalue(sem_t *sem handle(semaphore), int *value)
{
	if (!valid(sem) || !value) { errno = EINVAL; return -1; }
	return __plat_semaphore_getvalue(sem->__handle, value);
}

// NOLINTEND(misc-include-cleaner)
