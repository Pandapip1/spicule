/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of <sys/sem.h>: semget()/semop()/semctl().
 *
 * NT has plenty of counting primitives (src/thread/semaphore.c already
 * emulates POSIX sem_t over one), but none of them is the primitive
 * semop() actually needs: an ATOMIC, ALL-OR-NOTHING adjustment of a
 * whole ARRAY of counters at once, where the entire array either applies
 * or none of it does and the caller blocks. A single NT semaphore is one
 * counter with a single-object wait; there is no NT dispatcher object
 * that waits on a caller-supplied PREDICATE over several counters at
 * once the way semop()'s contract requires. So this file does not try
 * to build one out of dispatcher objects at all: each semaphore set's
 * values live as a plain array inside a shared backing-file record
 * (the same private-namespace-directory-plus-backing-file technique
 * src/ipc/nt/plat_shm.c and, one level further back, src/mman/shm.c
 * already use), guarded by one named NT mutant per registry (the same
 * namespace_lock() pattern src/thread/mqueue.c/semaphore.c already
 * established), and semop() evaluates the WHOLE requested array under
 * that lock in one pass: if every operation can be satisfied without
 * going negative, all are applied together; otherwise nothing is
 * applied, and -- absent IPC_NOWAIT -- this file releases the lock,
 * sleeps briefly, and retries, rather than blocking inside the lock
 * (which would starve every other operation on the same set, including
 * the ones that would free it up).
 *
 * THE ONE HONEST CASUALTY OF THAT CHOICE: semctl(GETNCNT)/(GETZCNT) are
 * specified as "the number of processes waiting for [this semaphore] to
 * increase"/"become zero". A poll-and-retry waiter never registers
 * itself anywhere while it sleeps -- there is no shared waiter-count
 * this file updates -- so both always report 0. That is exactly right
 * when nobody is waiting (the only case test/posix-ipc.c's
 * posix_ipc_semctl_getall_setall fence actually checks) and silently
 * wrong when somebody genuinely is; a real waiter-count would need its
 * own piece of shared, lock-protected state this file does not build,
 * because nothing in this tree yet needs it to be accurate.
 *
 * SEM_UNDO (semop.html's per-operation undo-on-exit flag) is likewise
 * accepted and ignored -- see <sys/sem.h>'s own comment on why a real
 * per-process undo table is out of scope here.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- strnlen(): bounded path construction
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <errno.h>
#include "libc.h"
#include "plat_thread.h"
#include "plat_fd.h"

#define SEM_MAGIC 0x53454d32u /* "SEM2" */
#define SEM_NSEMS_LIMIT 256

struct sem_meta {
	unsigned magic;
	key_t key;
	unsigned nsems;
	unsigned mode;
	unsigned uid, gid, cuid, cgid;
	long long otime, ctime;
	int removed;
	unsigned short val[SEM_NSEMS_LIMIT];
	int sempid[SEM_NSEMS_LIMIT];
};

static const char *sem_tmpdir(void)
{
	const char *p = getenv("TMPDIR");
	if (!p || !*p) p = getenv("TMP");
	if (!p || !*p) p = getenv("TEMP");
	return p && *p ? p : ".";
}

withtok(heap_allocated)
static char *dir_path(void)
{
	const char *dir = sem_tmpdir();
	const char suffix[] = "/ntlibc-sysvsem";
	size_t dirlen = strnlen(dir, PATH_MAX);
	size_t total;
	char *path;
	if (dirlen >= PATH_MAX || dirlen > (size_t)PATH_MAX - sizeof suffix) {
		errno = ENAMETOOLONG;
		return NULL;
	}
	total = dirlen + sizeof suffix;
	path = malloc(total);
	if (!path) return NULL;
	snprintf(path, total, "%s%s", dir, suffix);
	return path;
}

withtok(heap_allocated)
static char *id_path(int id)
{
	char *dir = dir_path();
	char *path;
	size_t dirlen, tail, total;
	int n;
	if (!dir) return NULL;
	dirlen = strlen(dir);
	if (!__size_add_checked(1 + 10, sizeof ".meta", &tail) ||
	    !__size_add_checked(dirlen, tail, &total)) { free(dir); return NULL; }
	path = malloc(total);
	if (!path) { free(dir); return NULL; }
	memcpy(path, dir, dirlen);
	free(dir);
	n = snprintf(path + dirlen, tail, "/%d.meta", id);
	if (n < 0) { free(path); errno = EINVAL; return NULL; }
	return path;
}

static int ensure_dir(void)
{
	char *dir = dir_path();
	int result;
	if (!dir) return -1;
	result = mkdir(dir, 0777);
	if (result < 0 && errno == EEXIST) result = 0;
	free(dir);
	return result;
}

__wraps static unsigned long long path_hash(const char *s) __attribute__((nonnull(1)));
__wraps static unsigned long long path_hash(const char *s)
{
	unsigned long long h = 1469598103934665603ULL;
	while (*s) { h ^= (unsigned char)*s++; h *= 1099511628211ULL; }
	return h;
}

static int registry_lock(__plat_handle_t *out)
{
	char *dir = dir_path();
	char name[80];
	unsigned long long hash;
	int n;
	if (!dir) return -1;
	hash = path_hash(dir);
	free(dir);
	n = snprintf(name, sizeof name, "\\BaseNamedObjects\\ntlibc.sysvsem.%08x%08x",
	         (unsigned)(hash >> 32), (unsigned)hash);
	if (n < 0 || (size_t)n >= sizeof name) {
		if (n >= 0) errno = ENAMETOOLONG;
		return -1;
	}
	return __plat_named_mutant_acquire(name, out);
}

static int read_meta(int id, struct sem_meta *m)
{
	char *path = id_path(id);
	int fd, saved;
	ssize_t got;
	if (!path) return -1;
	fd = open(path, O_RDONLY);
	saved = errno;
	free(path);
	if (fd < 0) { errno = saved; return -1; }
	got = read(fd, m, sizeof *m);
	saved = errno;
	(void)close(fd);
	if (got != (ssize_t)sizeof *m || m->magic != SEM_MAGIC) { errno = EINVAL; return -1; }
	errno = saved;
	return 0;
}

static int write_meta(int id, const struct sem_meta *m)
{
	char *path = id_path(id);
	int fd, saved;
	ssize_t put;
	if (!path) return -1;
	fd = open(path, O_WRONLY | O_CREAT, 0600);
	saved = errno;
	free(path);
	if (fd < 0) { errno = saved; return -1; }
	put = write(fd, m, sizeof *m);
	saved = put == (ssize_t)sizeof *m ? 0 : (errno ? errno : EIO);
	if (close(fd) < 0 && !saved) saved = errno ? errno : EIO;
	if (saved) { errno = saved; return -1; }
	return 0;
}

static int delete_set(int id)
{
	char *path = id_path(id);
	int result;
	if (!path) return -1;
	result = unlink(path);
	free(path);
	return result;
}

static int find_by_key(key_t key, struct sem_meta *m)
{
	char *dir = dir_path();
	DIR *d;
	struct dirent *e;
	int found = -1;
	if (!dir) return -1;
	d = opendir(dir);
	free(dir);
	if (!d) return -1;
	while ((e = readdir(d))) {
		int id;
		size_t len = strlen(e->d_name);
		const char *suffix = ".meta";
		size_t slen = strlen(suffix);
		struct sem_meta cand;
		if (len <= slen || strcmp(e->d_name + len - slen, suffix) != 0) continue;
		id = atoi(e->d_name);
		if (id <= 0) continue;
		if (read_meta(id, &cand) < 0) continue;
		if (!cand.removed && cand.key == key) { found = id; if (m) *m = cand; break; }
	}
	(void)closedir(d);
	return found;
}

int semget(key_t key, int nsems, int semflg)
{
	__plat_handle_t lock;
	char *dir, *ctrpath = 0;
	int id, ctrfd;
	struct sem_meta m;

	if (nsems < 0 || nsems > SEM_NSEMS_LIMIT) { errno = EINVAL; return -1; }
	if (ensure_dir() < 0) return -1;
	if (registry_lock(&lock) < 0) return -1;

	if (key != IPC_PRIVATE) {
		int existing = find_by_key(key, &m);
		if (existing >= 0) {
			if ((semflg & (IPC_CREAT | IPC_EXCL)) == (IPC_CREAT | IPC_EXCL)) {
				__plat_named_mutant_release(lock); errno = EEXIST; return -1;
			}
			if (nsems > 0 && (unsigned)nsems > m.nsems) {
				__plat_named_mutant_release(lock); errno = EINVAL; return -1;
			}
			__plat_named_mutant_release(lock);
			return existing;
		}
		if (!(semflg & IPC_CREAT)) {
			__plat_named_mutant_release(lock); errno = ENOENT; return -1;
		}
		if (nsems <= 0) { __plat_named_mutant_release(lock); errno = EINVAL; return -1; }
	} else if (nsems <= 0) {
		__plat_named_mutant_release(lock); errno = EINVAL; return -1;
	}

	dir = dir_path();
	if (!dir) { __plat_named_mutant_release(lock); return -1; }
	{
		size_t dirlen = strlen(dir), total;
		if (__size_add_checked(dirlen, sizeof "/next", &total)) {
			ctrpath = malloc(total);
			if (ctrpath) snprintf(ctrpath, total, "%s/next", dir);
		}
	}
	free(dir);
	if (!ctrpath) { __plat_named_mutant_release(lock); return -1; }
	ctrfd = open(ctrpath, O_RDWR | O_CREAT, 0600);
	if (ctrfd < 0) { free(ctrpath); __plat_named_mutant_release(lock); return -1; }
	{
		char buf[16];
		ssize_t got = read(ctrfd, buf, sizeof buf - 1);
		if (got < 0) got = 0;
		buf[got] = 0;
		id = atoi(buf);
		if (id <= 0) id = 1;
	}
	{
		char buf[16];
		int n = snprintf(buf, sizeof buf, "%d", id + 1);
		lseek(ctrfd, 0, SEEK_SET);
		if (n > 0 && (size_t)n < sizeof buf &&
		    write(ctrfd, buf, (size_t)n) != n) {
			(void)close(ctrfd);
			free(ctrpath);
			__plat_named_mutant_release(lock);
			return -1;
		}
		if (ftruncate(ctrfd, n > 0 && (size_t)n < sizeof buf ? n : 0) < 0) {
			(void)close(ctrfd);
			free(ctrpath);
			__plat_named_mutant_release(lock);
			return -1;
		}
	}
	if (close(ctrfd) < 0) {
		free(ctrpath);
		__plat_named_mutant_release(lock);
		return -1;
	}
	free(ctrpath);

	memset(&m, 0, sizeof m);
	m.magic = SEM_MAGIC;
	m.key = key;
	m.nsems = (unsigned)nsems;
	m.mode = (unsigned)semflg & 0777u;
	m.uid = m.cuid = (unsigned)geteuid();
	m.gid = m.cgid = (unsigned)getegid();
	m.ctime = (long long)time(NULL);
	if (write_meta(id, &m) < 0) {
		int saved = errno;
		__plat_named_mutant_release(lock);
		errno = saved;
		return -1;
	}
	__plat_named_mutant_release(lock);
	return id;
}

/* Evaluate the whole array against `m` without mutating it. Returns 1 if
 * every op can be applied, 0 if at least one would block. */
static int ops_fit(const struct sem_meta *m, const struct sembuf *sops, size_t nsops)
{
	size_t i;
	for (i = 0; i < nsops; i++) {
		unsigned num = sops[i].sem_num;
		int cur;
		if (num >= m->nsems) return -1;
		cur = m->val[num];
		if (sops[i].sem_op > 0) continue;
		if (sops[i].sem_op == 0) { if (cur != 0) return 0; }
		else if (cur + sops[i].sem_op < 0) return 0;
	}
	return 1;
}

static void ops_apply(struct sem_meta *m, const struct sembuf *sops, size_t nsops)
{
	size_t i;
	for (i = 0; i < nsops; i++) {
		unsigned num = sops[i].sem_num;
		m->val[num] = (unsigned short)(m->val[num] + sops[i].sem_op);
		m->sempid[num] = (int)getpid();
	}
	m->otime = (long long)time(NULL);
}

int semop(int semid, struct sembuf *sops, size_t nsops)
{
	__plat_handle_t lock;
	struct sem_meta m;
	int fit, nowait = 0;
	size_t i;

	if (!sops || !nsops) { errno = EINVAL; return -1; }
	for (i = 0; i < nsops; i++) if (sops[i].sem_flg & IPC_NOWAIT) nowait = 1;

	for (;;) {
		if (registry_lock(&lock) < 0) return -1;
		if (read_meta(semid, &m) < 0 || m.removed) {
			__plat_named_mutant_release(lock);
			errno = EINVAL;
			return -1;
		}
		fit = ops_fit(&m, sops, nsops);
		if (fit < 0) { __plat_named_mutant_release(lock); errno = EFBIG; return -1; }
		if (fit) {
			ops_apply(&m, sops, nsops);
			write_meta(semid, &m);
			__plat_named_mutant_release(lock);
			return 0;
		}
		__plat_named_mutant_release(lock);
		if (nowait) { errno = EAGAIN; return -1; }
		/* Poll-and-retry: see this file's own banner for why no NT
		 * dispatcher object can wait on this predicate directly. */
		usleep(10000);
	}
}

int semctl(int semid, int semnum, int cmd, ...)
{
	__plat_handle_t lock;
	struct sem_meta m;
	va_list ap;
	int result;

	if (registry_lock(&lock) < 0) return -1;
	if (read_meta(semid, &m) < 0 || m.removed) {
		__plat_named_mutant_release(lock);
		errno = EINVAL;
		return -1;
	}

	switch (cmd) {
	case GETVAL:
		if (semnum < 0 || (unsigned)semnum >= m.nsems) goto einval;
		result = m.val[semnum];
		break;
	case SETVAL: {
		int val;
		va_start(ap, cmd); val = va_arg(ap, int); va_end(ap);
		if (semnum < 0 || (unsigned)semnum >= m.nsems) goto einval;
		if (val < 0 || val > 32767) goto einval;
		m.val[semnum] = (unsigned short)val;
		m.sempid[semnum] = (int)getpid();
		m.ctime = (long long)time(NULL);
		write_meta(semid, &m);
		result = 0;
		break;
	}
	case GETPID:
		if (semnum < 0 || (unsigned)semnum >= m.nsems) goto einval;
		result = m.sempid[semnum];
		break;
	case GETALL: {
		unsigned short *array;
		unsigned i;
		va_start(ap, cmd); array = va_arg(ap, unsigned short *); va_end(ap);
		if (!array) { __plat_named_mutant_release(lock); errno = EFAULT; return -1; }
		for (i = 0; i < m.nsems; i++) array[i] = m.val[i];
		result = 0;
		break;
	}
	case SETALL: {
		unsigned short *array;
		unsigned i;
		va_start(ap, cmd); array = va_arg(ap, unsigned short *); va_end(ap);
		if (!array) { __plat_named_mutant_release(lock); errno = EFAULT; return -1; }
		for (i = 0; i < m.nsems; i++) { m.val[i] = array[i]; m.sempid[i] = (int)getpid(); }
		m.ctime = (long long)time(NULL);
		write_meta(semid, &m);
		result = 0;
		break;
	}
	/* GETNCNT/GETZCNT: always 0. See this file's own banner. */
	case GETNCNT:
	case GETZCNT:
		if (semnum < 0 || (unsigned)semnum >= m.nsems) goto einval;
		result = 0;
		break;
	case IPC_STAT: {
		struct semid_ds *buf;
		va_start(ap, cmd); buf = va_arg(ap, struct semid_ds *); va_end(ap);
		if (!buf) { __plat_named_mutant_release(lock); errno = EFAULT; return -1; }
		memset(buf, 0, sizeof *buf);
		buf->sem_perm.uid = (uid_t)m.uid;
		buf->sem_perm.gid = (gid_t)m.gid;
		buf->sem_perm.cuid = (uid_t)m.cuid;
		buf->sem_perm.cgid = (gid_t)m.cgid;
		buf->sem_perm.mode = (mode_t)m.mode;
		buf->sem_nsems = (unsigned short)m.nsems;
		buf->sem_otime = (time_t)m.otime;
		buf->sem_ctime = (time_t)m.ctime;
		result = 0;
		break;
	}
	case IPC_SET: {
		struct semid_ds *buf;
		va_start(ap, cmd); buf = va_arg(ap, struct semid_ds *); va_end(ap);
		if (!buf) { __plat_named_mutant_release(lock); errno = EFAULT; return -1; }
		m.uid = (unsigned)buf->sem_perm.uid;
		m.gid = (unsigned)buf->sem_perm.gid;
		m.mode = (unsigned)buf->sem_perm.mode & 0777u;
		m.ctime = (long long)time(NULL);
		write_meta(semid, &m);
		result = 0;
		break;
	}
	case IPC_RMID:
		result = delete_set(semid);
		break;
	default:
		goto einval;
	}
	__plat_named_mutant_release(lock);
	return result;

einval:
	__plat_named_mutant_release(lock);
	errno = EINVAL;
	return -1;
}
// NOLINTEND(misc-include-cleaner)
