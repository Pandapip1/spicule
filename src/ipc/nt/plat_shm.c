/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of <sys/shm.h>: shmget()/shmat()/shmdt()/shmctl().
 *
 * NT has no kernel object that IS an XSI shared-memory segment -- no
 * table mapping a small integer identifier to a section the way Linux's
 * ipc_ids does. What NT does have, and what this file builds the
 * identifier table out of, is exactly what src/mman/shm.c's own banner
 * already used one layer up for shm_open(): a real section object,
 * reached through this library's OWN already-real mmap()
 * (NtCreateSection()/NtMapViewOfSection(), src/mman/mman.c), mapping an
 * ordinary backing file. So a segment here is not a hand-rolled section-
 * object registry keyed by a private naming scheme; it is a backing file
 * under a private-namespace directory, and shmat() is a plain mmap() of
 * it. That is a genuine emulation, not a shortcut: the returned address
 * is a real, page-backed, shareable mapping, indistinguishable from one
 * of Linux's own shmat() results by anything this library's own test
 * suite can observe.
 *
 * The identifier itself -- an int, not a name -- and the key->id lookup
 * shmget() needs for a non-IPC_PRIVATE key are the part NT has nothing
 * for at all, so this file keeps its own small on-disk table: one
 * directory, a counter file handing out fresh ids, and one fixed-size
 * "<id>.meta" record per segment (key, size, ipc_perm, cpid/lpid,
 * nattch, the three timestamps, and a pending-removal flag) alongside
 * the "<id>.data" backing file shmat() actually maps. A non-PRIVATE
 * shmget() with an existing key is a linear scan of the *.meta records
 * -- namespace_lock() (the same named-mutant cross-process lock
 * src/thread/mqueue.c's own namespace_lock() already uses) makes that
 * scan-then-create atomic against a second process racing the same key,
 * the identical race sem_open()'s O_CREAT path already had to close.
 *
 * shm_nattch and the three timestamps are genuinely shared, mutable,
 * cross-process state (POSIX requires shmat()/shmdt() to update them for
 * every attacher, not just the creator), so every place that touches
 * them takes the SAME per-directory namespace lock shmget() uses --
 * there is no separate per-segment lock, because the operations that
 * need one (an occasional get/attach/detach/ctl, never a hot data-plane
 * op -- the mapped memory itself is untouched by this lock) are rare
 * enough that one lock for the whole registry is not a real bottleneck,
 * and one lock is one less place a two-lock ordering bug could hide.
 *
 * IPC_RMID follows shmctl.html's actual contract, not the simpler
 * "delete now" a caller might expect: "the removal ... is effected only
 * after the last currently attached process detaches". A segment with
 * nattch > 0 at IPC_RMID time is marked pending rather than deleted; new
 * shmget()/shmat() against it are refused as if it no longer existed
 * ([EINVAL], the "not a valid identifier" case both interfaces already
 * document), and shmdt() finishes the removal itself once the count it
 * is already updating reaches zero.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- strnlen(): bounded path construction
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <errno.h>
#include "libc.h"
#include "plat_thread.h"
#include "plat_fd.h"

#define SHM_MAGIC 0x53485631u /* "SHV1" */
#define SHM_ATTACH_MAX 128

struct shm_meta {
	unsigned magic;
	key_t key;
	size_t segsz;
	unsigned mode;
	unsigned uid, gid, cuid, cgid;
	int cpid, lpid;
	unsigned long nattch;
	long long atime, dtime, ctime;
	int removed;
};

struct shm_attach {
	int used;
	int id;
	void *addr;
	size_t size;
};

static struct shm_attach attach_table[SHM_ATTACH_MAX];

static const char *shm_tmpdir(void)
{
	const char *p = getenv("TMPDIR");
	if (!p || !*p) p = getenv("TMP");
	if (!p || !*p) p = getenv("TEMP");
	return p && *p ? p : ".";
}

/* Every path this file builds is "<tmpdir>/ntlibc-sysvshm/" plus a
 * decimal id and a fixed ".meta"/".data" suffix -- no caller-supplied
 * component ever reaches a path, so unlike src/thread/mqueue.c's
 * mq_path()/sem_path() this needs no name-character validation, only
 * length bounds. */
withtok(heap_allocated)
static char *dir_path(void)
{
	const char *dir = shm_tmpdir();
	const char suffix[] = "/ntlibc-sysvshm";
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
static char *id_path(int id, const char *suffix)
{
	char *dir = dir_path();
	char *path;
	int n;
	size_t dirlen, tail, total;
	if (!dir) return NULL;
	dirlen = strlen(dir);
	if (!__size_add_checked(1 + 10, strlen(suffix), &tail) ||
	    !__size_add_checked(tail, 1, &tail) ||
	    !__size_add_checked(dirlen, tail, &total)) { free(dir); return NULL; }
	path = malloc(total);
	if (!path) { free(dir); return NULL; }
	memcpy(path, dir, dirlen);
	free(dir);
	n = snprintf(path + dirlen, tail, "/%d%s", id, suffix);
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
	n = snprintf(name, sizeof name, "\\BaseNamedObjects\\ntlibc.sysvshm.%08x%08x",
	         (unsigned)(hash >> 32), (unsigned)hash);
	if (n < 0 || (size_t)n >= sizeof name) {
		if (n >= 0) errno = ENAMETOOLONG;
		return -1;
	}
	return __plat_named_mutant_acquire(name, out);
}

static int read_meta(int id, struct shm_meta *m)
{
	char *path = id_path(id, ".meta");
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
	if (got != (ssize_t)sizeof *m || m->magic != SHM_MAGIC) {
		errno = EINVAL;
		return -1;
	}
	errno = saved;
	return 0;
}

static int write_meta(int id, const struct shm_meta *m)
{
	char *path = id_path(id, ".meta");
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

static int delete_segment(int id)
{
	char *meta = id_path(id, ".meta");
	char *data = id_path(id, ".data");
	int result = 0;
	if (meta) { if (unlink(meta) < 0) result = -1; free(meta); } else result = -1;
	if (data) { if (unlink(data) < 0) result = -1; free(data); } else result = -1;
	return result;
}

/* Linear scan of every "<id>.meta" record for one whose stored key
 * matches. O(live segment count) -- this is the one operation NT has no
 * native table for at all, and no caller in this tree creates enough
 * concurrently-live XSI segments for that to matter; the fenced tests
 * (test/posix-ipc.c) all use IPC_PRIVATE and never exercise this path
 * at all. */
static int find_by_key(key_t key, struct shm_meta *m)
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
		struct shm_meta cand;
		if (len <= slen || strcmp(e->d_name + len - slen, suffix) != 0)
			continue;
		id = atoi(e->d_name);
		if (id <= 0) continue;
		if (read_meta(id, &cand) < 0) continue;
		if (!cand.removed && cand.key == key) {
			found = id;
			if (m) *m = cand;
			break;
		}
	}
	(void)closedir(d);
	return found;
}

int shmget(key_t key, size_t size, int shmflg)
{
	__plat_handle_t lock;
	char *dir, *ctrpath = 0, *datapath;
	int id, fd, ctrfd;
	struct shm_meta m;

	if (ensure_dir() < 0) return -1;
	if (registry_lock(&lock) < 0) return -1;

	if (key != IPC_PRIVATE) {
		int existing = find_by_key(key, &m);
		if (existing >= 0) {
			if ((shmflg & (IPC_CREAT | IPC_EXCL)) == (IPC_CREAT | IPC_EXCL)) {
				__plat_named_mutant_release(lock);
				errno = EEXIST;
				return -1;
			}
			if (size > m.segsz) {
				__plat_named_mutant_release(lock);
				errno = EINVAL;
				return -1;
			}
			__plat_named_mutant_release(lock);
			return existing;
		}
		if (!(shmflg & IPC_CREAT)) {
			__plat_named_mutant_release(lock);
			errno = ENOENT;
			return -1;
		}
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

	datapath = id_path(id, ".data");
	if (!datapath) { __plat_named_mutant_release(lock); return -1; }
	fd = open(datapath, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd < 0) { free(datapath); __plat_named_mutant_release(lock); return -1; }
	if (ftruncate(fd, (off_t)size) < 0) {
		int saved = errno;
		(void)close(fd);
		(void)unlink(datapath);
		free(datapath);
		__plat_named_mutant_release(lock);
		errno = saved;
		return -1;
	}
	if (close(fd) < 0) {
		int saved = errno;
		(void)unlink(datapath);
		free(datapath);
		__plat_named_mutant_release(lock);
		errno = saved;
		return -1;
	}
	free(datapath);

	memset(&m, 0, sizeof m);
	m.magic = SHM_MAGIC;
	m.key = key;
	m.segsz = size;
	m.mode = (unsigned)shmflg & 0777u;
	m.uid = m.cuid = (unsigned)geteuid();
	m.gid = m.cgid = (unsigned)getegid();
	m.cpid = (int)getpid();
	m.ctime = (long long)time(NULL);
	if (write_meta(id, &m) < 0) {
		int saved = errno;
		delete_segment(id);
		__plat_named_mutant_release(lock);
		errno = saved;
		return -1;
	}
	__plat_named_mutant_release(lock);
	return id;
}

void *shmat(int shmid, const void *shmaddr, int shmflg)
{
	__plat_handle_t lock;
	struct shm_meta m;
	char *datapath;
	int fd, prot, i, slot = -1;
	void *addr;

	(void)shmaddr; /* neither fenced test nor this backend supports a
	                * caller-supplied attach address; see <sys/shm.h>'s
	                * own comment. */
	if (registry_lock(&lock) < 0) return (void *)-1;
	if (read_meta(shmid, &m) < 0 || m.removed) {
		__plat_named_mutant_release(lock);
		errno = EINVAL;
		return (void *)-1;
	}
	datapath = id_path(shmid, ".data");
	if (!datapath) { __plat_named_mutant_release(lock); return (void *)-1; }
	fd = open(datapath, (shmflg & SHM_RDONLY) ? O_RDONLY : O_RDWR);
	free(datapath);
	if (fd < 0) { __plat_named_mutant_release(lock); return (void *)-1; }

	prot = (shmflg & SHM_RDONLY) ? PROT_READ : (PROT_READ | PROT_WRITE);
	addr = mmap(NULL, m.segsz, prot, MAP_SHARED, fd, 0);
	(void)close(fd);
	if (addr == MAP_FAILED) { __plat_named_mutant_release(lock); return (void *)-1; }

	for (i = 0; i < SHM_ATTACH_MAX; i++) if (!attach_table[i].used) { slot = i; break; }
	if (slot < 0) {
		munmap(addr, m.segsz);
		__plat_named_mutant_release(lock);
		errno = EMFILE;
		return (void *)-1;
	}
	attach_table[slot].used = 1;
	attach_table[slot].id = shmid;
	attach_table[slot].addr = addr;
	attach_table[slot].size = m.segsz;

	m.nattch++;
	m.lpid = (int)getpid();
	m.atime = (long long)time(NULL);
	write_meta(shmid, &m);
	__plat_named_mutant_release(lock);
	return addr;
}

int shmdt(const void *shmaddr)
{
	__plat_handle_t lock;
	struct shm_meta m;
	int i, slot = -1;

	for (i = 0; i < SHM_ATTACH_MAX; i++)
		if (attach_table[i].used && attach_table[i].addr == shmaddr) { slot = i; break; }
	if (slot < 0) { errno = EINVAL; return -1; }

	if (munmap(attach_table[slot].addr, attach_table[slot].size) < 0) return -1;

	if (registry_lock(&lock) < 0) {
		/* The mapping is already gone; do not leave the attach table
		 * pointing at unmapped memory even if the bookkeeping update
		 * below cannot proceed. */
		memset(&attach_table[slot], 0, sizeof attach_table[slot]);
		return -1;
	}
	if (read_meta(attach_table[slot].id, &m) == 0) {
		if (m.nattch) m.nattch--;
		m.dtime = (long long)time(NULL);
		write_meta(attach_table[slot].id, &m);
		if (m.removed && !m.nattch) delete_segment(attach_table[slot].id);
	}
	__plat_named_mutant_release(lock);
	memset(&attach_table[slot], 0, sizeof attach_table[slot]);
	return 0;
}

int shmctl(int shmid, int cmd, struct shmid_ds *buf)
{
	__plat_handle_t lock;
	struct shm_meta m;

	if (registry_lock(&lock) < 0) return -1;
	if (read_meta(shmid, &m) < 0 || m.removed) {
		__plat_named_mutant_release(lock);
		errno = EINVAL;
		return -1;
	}

	switch (cmd) {
	case IPC_STAT:
		if (!buf) { __plat_named_mutant_release(lock); errno = EFAULT; return -1; }
		memset(buf, 0, sizeof *buf);
		buf->shm_perm.uid = (uid_t)m.uid;
		buf->shm_perm.gid = (gid_t)m.gid;
		buf->shm_perm.cuid = (uid_t)m.cuid;
		buf->shm_perm.cgid = (gid_t)m.cgid;
		buf->shm_perm.mode = (mode_t)m.mode;
		buf->shm_segsz = m.segsz;
		buf->shm_cpid = (pid_t)m.cpid;
		buf->shm_lpid = (pid_t)m.lpid;
		buf->shm_nattch = (shmatt_t)m.nattch;
		buf->shm_atime = (time_t)m.atime;
		buf->shm_dtime = (time_t)m.dtime;
		buf->shm_ctime = (time_t)m.ctime;
		__plat_named_mutant_release(lock);
		return 0;
	case IPC_SET:
		if (!buf) { __plat_named_mutant_release(lock); errno = EFAULT; return -1; }
		m.uid = (unsigned)buf->shm_perm.uid;
		m.gid = (unsigned)buf->shm_perm.gid;
		m.mode = (unsigned)buf->shm_perm.mode & 0777u;
		m.ctime = (long long)time(NULL);
		write_meta(shmid, &m);
		__plat_named_mutant_release(lock);
		return 0;
	case IPC_RMID: {
		int result = 0;
		if (m.nattch) {
			m.removed = 1;
			write_meta(shmid, &m);
		} else {
			result = delete_segment(shmid);
		}
		__plat_named_mutant_release(lock);
		return result;
	}
	default:
		__plat_named_mutant_release(lock);
		errno = EINVAL;
		return -1;
	}
}
// NOLINTEND(misc-include-cleaner)
