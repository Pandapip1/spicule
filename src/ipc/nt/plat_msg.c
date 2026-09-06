/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of <sys/msg.h>: msgget()/msgsnd()/msgrcv()/msgctl().
 *
 * Same private-namespace-directory-plus-backing-file registry
 * src/ipc/nt/plat_shm.c and src/ipc/nt/plat_sem.c both build (see
 * plat_shm.c's own banner for why NT needs one at all: there is no
 * native table mapping a small integer identifier to an XSI object the
 * way Linux's ipc_ids is). Each queue's whole state -- header plus a
 * fixed table of message slots -- lives in one "<id>.meta" file,
 * guarded by one named NT mutant per registry.
 *
 * WHY THIS IS A POLL LOOP, NOT src/thread/mqueue.c's THREE SEMAPHORES.
 * mqueue.c's mq_receive() always takes whichever message is at the head
 * (highest priority, and only priority ties break by arrival order), so
 * "a message is available" and "MY next receive can proceed" are the
 * same fact -- exactly what a plain counting semaphore represents, and
 * why that file can block on one directly. msgrcv() cannot: a caller
 * with msgtyp > 0 wants a SPECIFIC type, so "the queue is non-empty" and
 * "a message of the type I want is here" are different facts, and a
 * naive semaphore-per-message wait would consume a real permit checking
 * a message it then has to leave in place, desynchronizing the count
 * from the next caller's own equally naive check. Rather than build a
 * second, type-aware signalling mechanism to recover that (a real one
 * would need every sender to know in advance which types the current
 * waiters want), a blocking msgrcv()/msgsnd() call here re-takes the
 * one registry lock and re-examines the slot table on a short interval
 * until its own condition holds -- exactly the same honest trade
 * src/ipc/nt/plat_sem.c's own banner already makes for semop(), and for
 * the identical underlying reason: no single NT dispatcher object waits
 * on a caller-supplied predicate.
 *
 * PER-QUEUE CAPACITY IS FIXED AND SMALL (MSG_MAX_SLOTS messages of up to
 * MSG_SLOT_DATA bytes each, not Linux's dynamic MSGMNB/MSGMAX), because
 * the whole queue -- header, slot metadata AND every message's bytes --
 * is one on-disk record read and rewritten under the lock on every
 * operation; an application that actually needs SysV's real ~16 KiB/
 * queue, ~8 KiB/message ceilings has no such ceiling forced on it by
 * this header, only by this specific backend's chosen record size.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- strnlen(): bounded path construction
#include <sys/ipc.h>
#include <sys/msg.h>
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

#define MSG_MAGIC 0x4d534731u /* "MSG1" */
#define MSG_MAX_SLOTS 64
#define MSG_SLOT_DATA 2048

struct msg_slot {
	int used;
	long mtype;
	unsigned length;
	unsigned long long sequence;
	char data[MSG_SLOT_DATA];
};

struct msg_meta {
	unsigned magic;
	key_t key;
	unsigned mode;
	unsigned uid, gid, cuid, cgid;
	unsigned long qnum;
	unsigned long qbytes;
	unsigned long cbytes;
	int lspid, lrpid;
	long long stime, rtime, ctime;
	unsigned long long sequence;
	int removed;
	struct msg_slot slot[MSG_MAX_SLOTS];
};

static const char *msg_tmpdir(void)
{
	const char *p = getenv("TMPDIR");
	if (!p || !*p) p = getenv("TMP");
	if (!p || !*p) p = getenv("TEMP");
	return p && *p ? p : ".";
}

withtok(heap_allocated)
static char *dir_path(void)
{
	const char *dir = msg_tmpdir();
	const char suffix[] = "/ntlibc-sysvmsg";
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
	n = snprintf(name, sizeof name, "\\BaseNamedObjects\\ntlibc.sysvmsg.%08x%08x",
	         (unsigned)(hash >> 32), (unsigned)hash);
	if (n < 0 || (size_t)n >= sizeof name) {
		if (n >= 0) errno = ENAMETOOLONG;
		return -1;
	}
	return __plat_named_mutant_acquire(name, out);
}

/* struct msg_meta is ~140 KiB (MSG_MAX_SLOTS * (sizeof(struct msg_slot)))
 * -- a heap buffer, not a stack one, for every read/write of it. */
static struct msg_meta *read_meta(int id)
{
	char *path = id_path(id);
	struct msg_meta *m;
	int fd, saved;
	ssize_t got;
	if (!path) return NULL;
	m = malloc(sizeof *m);
	if (!m) { free(path); return NULL; }
	fd = open(path, O_RDONLY);
	saved = errno;
	free(path);
	if (fd < 0) { free(m); errno = saved; return NULL; }
	got = read(fd, m, sizeof *m);
	saved = errno;
	(void)close(fd);
	if (got != (ssize_t)sizeof *m || m->magic != MSG_MAGIC) {
		free(m);
		errno = EINVAL;
		return NULL;
	}
	errno = saved;
	return m;
}

static int write_meta(int id, const struct msg_meta *m)
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

static int delete_queue(int id)
{
	char *path = id_path(id);
	int result;
	if (!path) return -1;
	result = unlink(path);
	free(path);
	return result;
}

static int find_by_key(key_t key)
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
		struct msg_meta *cand;
		if (len <= slen || strcmp(e->d_name + len - slen, suffix) != 0) continue;
		id = atoi(e->d_name);
		if (id <= 0) continue;
		cand = read_meta(id);
		if (!cand) continue;
		if (!cand->removed && cand->key == key) { found = id; free(cand); break; }
		free(cand);
	}
	(void)closedir(d);
	return found;
}

int msgget(key_t key, int msgflg)
{
	__plat_handle_t lock;
	char *dir, *ctrpath = 0;
	int id, ctrfd;
	struct msg_meta m;

	if (ensure_dir() < 0) return -1;
	if (registry_lock(&lock) < 0) return -1;

	if (key != IPC_PRIVATE) {
		int existing = find_by_key(key);
		if (existing >= 0) {
			if ((msgflg & (IPC_CREAT | IPC_EXCL)) == (IPC_CREAT | IPC_EXCL)) {
				__plat_named_mutant_release(lock); errno = EEXIST; return -1;
			}
			__plat_named_mutant_release(lock);
			return existing;
		}
		if (!(msgflg & IPC_CREAT)) {
			__plat_named_mutant_release(lock); errno = ENOENT; return -1;
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

	memset(&m, 0, sizeof m);
	m.magic = MSG_MAGIC;
	m.key = key;
	m.mode = (unsigned)msgflg & 0777u;
	m.uid = m.cuid = (unsigned)geteuid();
	m.gid = m.cgid = (unsigned)getegid();
	m.qbytes = (unsigned long)MSG_MAX_SLOTS * MSG_SLOT_DATA;
	m.ctime = (long long)time(NULL);
	m.sequence = 1;
	if (write_meta(id, &m) < 0) {
		int saved = errno;
		__plat_named_mutant_release(lock);
		errno = saved;
		return -1;
	}
	__plat_named_mutant_release(lock);
	return id;
}

int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg)
{
	const long *typep = msgp;
	__plat_handle_t lock;
	struct msg_meta *m;
	int i, slot;

	if (!msgp) { errno = EFAULT; return -1; }
	if (msgsz > MSG_SLOT_DATA) { errno = EINVAL; return -1; }
	if (*typep < 1) { errno = EINVAL; return -1; }

	for (;;) {
		if (registry_lock(&lock) < 0) return -1;
		m = read_meta(msqid);
		if (!m || m->removed) {
			if (m) free(m);
			__plat_named_mutant_release(lock);
			errno = EINVAL;
			return -1;
		}
		slot = -1;
		for (i = 0; i < MSG_MAX_SLOTS; i++) if (!m->slot[i].used) { slot = i; break; }
		if (slot >= 0) break;
		free(m);
		__plat_named_mutant_release(lock);
		if (msgflg & IPC_NOWAIT) { errno = EAGAIN; return -1; }
		usleep(10000);
	}

	m->slot[slot].used = 1;
	m->slot[slot].mtype = *typep;
	m->slot[slot].length = (unsigned)msgsz;
	m->slot[slot].sequence = m->sequence++;
	if (msgsz) {
		size_t j;
		for (j = 0; j < msgsz; j++)
			m->slot[slot].data[j] = ((const char *)msgp)[sizeof(long) + j];
	}
	m->qnum++;
	m->cbytes += msgsz;
	m->lspid = (int)getpid();
	m->stime = (long long)time(NULL);
	write_meta(msqid, m);
	free(m);
	__plat_named_mutant_release(lock);
	return 0;
}

/* msgtyp selection, msgrcv.html DESCRIPTION: 0 -> first message on the
 * queue; >0 -> first message of that exact type; <0 -> first message
 * whose type is the lowest among those <= |msgtyp|. Arrival order
 * (m->slot[].sequence) breaks ties within whichever rule applies. */
static int select_slot(const struct msg_meta *m, long msgtyp)
{
	int i, best = -1;
	for (i = 0; i < MSG_MAX_SLOTS; i++) {
		const struct msg_slot *s = &m->slot[i];
		if (!s->used) continue;
		if (msgtyp > 0 && s->mtype != msgtyp) continue;
		if (msgtyp < 0 && s->mtype > -msgtyp) continue;
		if (best < 0 || s->sequence < m->slot[best].sequence) best = i;
	}
	return best;
}

ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg)
{
	long *typep = msgp;
	__plat_handle_t lock;
	struct msg_meta *m;
	int slot;
	unsigned len;

	if (!msgp) { errno = EFAULT; return -1; }

	for (;;) {
		if (registry_lock(&lock) < 0) return -1;
		m = read_meta(msqid);
		if (!m || m->removed) {
			if (m) free(m);
			__plat_named_mutant_release(lock);
			errno = EINVAL;
			return -1;
		}
		slot = select_slot(m, msgtyp);
		if (slot >= 0) break;
		free(m);
		__plat_named_mutant_release(lock);
		if (msgflg & IPC_NOWAIT) { errno = ENOMSG; return -1; }
		usleep(10000);
	}

	len = m->slot[slot].length;
	if (len > msgsz) {
		if (!(msgflg & MSG_NOERROR)) {
			free(m);
			__plat_named_mutant_release(lock);
			errno = E2BIG;
			return -1;
		}
		len = (unsigned)msgsz;
	}
	*typep = m->slot[slot].mtype;
	if (len) {
		unsigned j;
		for (j = 0; j < len; j++)
			((char *)msgp)[sizeof(long) + j] = m->slot[slot].data[j];
	}
	memset(&m->slot[slot], 0, sizeof m->slot[slot]);
	if (m->qnum) m->qnum--;
	if (m->cbytes >= len) m->cbytes -= len; else m->cbytes = 0;
	m->lrpid = (int)getpid();
	m->rtime = (long long)time(NULL);
	write_meta(msqid, m);
	free(m);
	__plat_named_mutant_release(lock);
	return (ssize_t)len;
}

int msgctl(int msqid, int cmd, struct msqid_ds *buf)
{
	__plat_handle_t lock;
	struct msg_meta *m;
	int result;

	if (registry_lock(&lock) < 0) return -1;
	m = read_meta(msqid);
	if (!m || m->removed) {
		if (m) free(m);
		__plat_named_mutant_release(lock);
		errno = EINVAL;
		return -1;
	}

	switch (cmd) {
	case IPC_STAT:
		if (!buf) { result = -1; errno = EFAULT; break; }
		memset(buf, 0, sizeof *buf);
		buf->msg_perm.uid = (uid_t)m->uid;
		buf->msg_perm.gid = (gid_t)m->gid;
		buf->msg_perm.cuid = (uid_t)m->cuid;
		buf->msg_perm.cgid = (gid_t)m->cgid;
		buf->msg_perm.mode = (mode_t)m->mode;
		buf->msg_qnum = (msgqnum_t)m->qnum;
		buf->msg_qbytes = (msglen_t)m->qbytes;
		buf->msg_lspid = (pid_t)m->lspid;
		buf->msg_lrpid = (pid_t)m->lrpid;
		buf->msg_stime = (time_t)m->stime;
		buf->msg_rtime = (time_t)m->rtime;
		buf->msg_ctime = (time_t)m->ctime;
		result = 0;
		break;
	case IPC_SET:
		if (!buf) { result = -1; errno = EFAULT; break; }
		m->uid = (unsigned)buf->msg_perm.uid;
		m->gid = (unsigned)buf->msg_perm.gid;
		m->mode = (unsigned)buf->msg_perm.mode & 0777u;
		m->ctime = (long long)time(NULL);
		write_meta(msqid, m);
		result = 0;
		break;
	case IPC_RMID:
		result = delete_queue(msqid);
		break;
	default:
		errno = EINVAL;
		result = -1;
		break;
	}
	free(m);
	__plat_named_mutant_release(lock);
	return result;
}
// NOLINTEND(misc-include-cleaner)
