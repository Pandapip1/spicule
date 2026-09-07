/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * POSIX message queues backed by unlinkable regular files.  Three named NT
 * semaphores per queue generation (state lock, message count, slot count)
 * have their names stored in the file header, so mq_open() can recreate them
 * from the header's authoritative counts if every process closes the queue
 * while its pathname remains.
 *
 * Queue descriptors are ordinary close-on-exec file descriptors plus the
 * semaphore handles in mqds[], giving fork() the right behavior for free.
 * close() calls __mq_fd_closed() so using close(mqdes) instead of
 * mq_close() still can't leave a stale descriptor or notification.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- strnlen(): bound name validation before path construction
#include <mqueue.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <stdint.h>
#include <errno.h>
#include "libc.h"
#include "plat_thread.h"

#define MQ_MAGIC 0x4e544d51u
#define MQ_VERSION 2
#define MQ_MAXMSG_LIMIT 256
#define MQ_MSGSIZE_LIMIT 65536
#define MQ_DEFAULT_MAXMSG 10
#define MQ_DEFAULT_MSGSIZE 8192
#define MQ_DESC_MAGIC 0x4d514431u

struct mq_header {
	unsigned magic;
	unsigned version;
	unsigned maxmsg;
	unsigned msgsize;
	unsigned curmsgs;
	unsigned receive_waiters;
	unsigned long long sequence;
	int notify_active;
	int notify_kind; /* SIGEV_NONE or SIGEV_SIGNAL; mq_notify() rejects SIGEV_THREAD */
	int notify_pid;
	int notify_fd; /* registering descriptor; meaningful for every notify_kind, so it stays outside notify */
	union {
		struct { int signo; union sigval value; } signal;
	} notify;
	char lock_name[112];
	char items_name[112];
	char spaces_name[112];
};

struct mq_slot {
	unsigned used;
	unsigned priority;
	unsigned length;
	unsigned reserved;
	unsigned long long sequence;
};

struct mq_desc {
	unsigned magic;
	__plat_handle_t file;
	__plat_handle_t lock;
	__plat_handle_t items;
	__plat_handle_t spaces;
	unsigned maxmsg;
	unsigned msgsize;
};

static struct mq_desc mqds[FD_MAX];
static unsigned object_sequence;

static const char *mq_tmpdir(void)
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
static char *mq_path(const char *name)
{
	const char *component, *dir;
	size_t namelen, n, d, i, maxdir;
	const size_t prefix = sizeof "/spicule-mq/" - 1;
	size_t total;
	char *path;
	if (!name) { errno = EINVAL; return NULL; }
	/* PATH_MAX bytes already force ENAMETOOLONG; no rejected suffix needs
	 * an unbounded scan.  Derive the component length from this one exact
	 * measurement instead of traversing the same string again. */
	namelen = strnlen(name, PATH_MAX);
	if (namelen >= PATH_MAX) { errno = ENAMETOOLONG; return NULL; }
	if (*name == '/') { component = name + 1; n = namelen - 1; }
	else { component = name; n = namelen; }
	if (!n || (n == 1 && component[0] == '.') ||
	    (n == 2 && component[0] == '.' && component[1] == '.')) {
		errno = EINVAL; return NULL;
	}
	if (n > NAME_MAX) { errno = ENAMETOOLONG; return NULL; }
	for (i = 0; i < n; i++) if (!name_char((unsigned char)component[i])) {
		errno = EINVAL; return NULL;
	}
	if (n > (size_t)PATH_MAX - 1 - prefix) {
		errno = ENAMETOOLONG; return NULL;
	}
	/* The preceding guard makes computing the exact remaining room
	 * non-wrapping.  Once maxdir + 1 bytes have been examined, the
	 * path is known to be too long and no rejected suffix needs scanning. */
	maxdir = (size_t)PATH_MAX - 1 - prefix - n;
	dir = mq_tmpdir(); d = strnlen(dir, maxdir + 1);
	if (d > maxdir) {
		errno = ENAMETOOLONG; return NULL;
	}
	total = d + prefix + n + 1;
	path = malloc(total);
	if (!path) return NULL;
	snprintf(path, total, "%s/spicule-mq/%s", dir, component);
	return path;
}

/* Both call sites pass a path built by mq_path(), which always embeds a
 * literal "/spicule-mq/" component, so strrchr() can never return NULL here. */
static int ensure_dir(const char *path) __attribute__((nonnull(1)));
static int ensure_dir(const char *path)
{
	char *copy = strdup(path), *slash;
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

/* FNV-1a is defined by multiplication modulo 2^64.  The wrap is the hash
 * operation, not an exceptional arithmetic result. */
__wraps static unsigned long long path_hash(const char *s)
    __attribute__((nonnull(1)));
__wraps static unsigned long long path_hash(const char *s)
{
	unsigned long long h = 1469598103934665603ULL;
	while (*s) { h ^= (unsigned char)*s++; h *= 1099511628211ULL; }
	return h;
}

static int create_sem(const char *name, long initial, long maximum, __plat_handle_t *out)
{
	return __plat_named_semaphore_open_or_create(name, initial, maximum, out);
}

static int take(__plat_handle_t h)
{
	int r = __plat_wait_one(h, 0, 0, 0);
	return r == __PLAT_WAIT_OK ? 0 : -1;
}

static void give(__plat_handle_t h)
{
	__plat_semaphore_post(h);
}

static int raw_io(__plat_handle_t h, void *buf, size_t len, off_t off, int write_op) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	unsigned char *p = buf;
	while (len) {
		ssize_t got = __plat_thread_file_io(h, p, len, off, write_op);
		if (got < 0) return -1;
		if (!got) { errno = EIO; return -1; }
		if ((size_t)got > len) { errno = EIO; return -1; }
		p += got;
		off += got;
		len -= (size_t)got;
	}
	return 0;
}

static int raw_read(__plat_handle_t h, void *buf, size_t len, off_t off)
{
	return raw_io(h, buf, len, off, 0);
}

static int raw_write(__plat_handle_t h, const void *buf, size_t len, off_t off)
{
	return raw_io(h, (void *)buf, len, off, 1);
}

static off_t slot_offset(const struct mq_desc *d, unsigned slot)
{
	/* Queue creation/read validation bounds slot to 255 and msgsize to 65536. */
	return (off_t)sizeof(struct mq_header) +
	       (off_t)slot * (off_t)(sizeof(struct mq_slot) + d->msgsize);
}

static struct mq_desc *get_desc(mqd_t mqdes)
{
	struct mq_desc *d;
	if (mqdes < 0 || mqdes >= FD_MAX) { errno = EBADF; return NULL; }
	d = &mqds[mqdes];
	if (d->magic != MQ_DESC_MAGIC || !d->file || !__fds[mqdes].h ||
	    __fds[mqdes].h != d->file) { errno = EBADF; return NULL; }
	return d;
}

static int read_header(struct mq_desc *d, struct mq_header *h)
{
	if (raw_read(d->file, h, sizeof *h, 0) < 0) return -1;
	if (h->magic != MQ_MAGIC || h->version != MQ_VERSION ||
	    h->maxmsg != d->maxmsg || h->msgsize != d->msgsize) {
		errno = EIO; return -1;
	}
	return 0;
}

static int attr_valid(const struct mq_attr *a)
{
	return a && a->mq_maxmsg > 0 && a->mq_maxmsg <= MQ_MAXMSG_LIMIT &&
	       a->mq_msgsize > 0 && a->mq_msgsize <= MQ_MSGSIZE_LIMIT;
}

mqd_t mq_open(const char *name, int oflag, ...)
{
	char *path = NULL;
	char nsname[96];
	unsigned long long hash;
	struct mq_header h;
	struct mq_attr supplied, *attr = NULL;
	struct mq_desc *d;
	__plat_handle_t ns = 0, lock = 0, items = 0, spaces = 0;
	int fd = -1, created = 0, saved = 0, access = oflag & O_ACCMODE, n;
	mode_t mode = 0;
	size_t file_size;

	if (access != O_RDONLY && access != O_WRONLY && access != O_RDWR) {
		errno = EINVAL; return (mqd_t)-1;
	}
	if (oflag & ~(O_ACCMODE | O_CREAT | O_EXCL | O_NONBLOCK)) {
		errno = EINVAL; return (mqd_t)-1;
	}
	if (oflag & O_CREAT) {
		va_list ap;
		va_start(ap, oflag);
		mode = (mode_t)va_arg(ap, int);
		attr = va_arg(ap, struct mq_attr *);
		va_end(ap);
		if (attr) supplied = *attr;
		if (attr && !attr_valid(&supplied)) { errno = EINVAL; return (mqd_t)-1; }
	}
	path = mq_path(name);
	if (!path) return (mqd_t)-1;
	if (ensure_dir(path) < 0) goto fail;
	hash = path_hash(path);
	n = snprintf(nsname, sizeof nsname, "\\BaseNamedObjects\\spicule.mq.name.%08x%08x",
	         (unsigned)(hash >> 32), (unsigned)hash);
	if (n < 0 || (size_t)n >= sizeof nsname) {
		if (n >= 0) errno = ENAMETOOLONG;
		goto fail;
	}
	if (create_sem(nsname, 1, 1, &ns) < 0 || take(ns) < 0) goto fail;

	if (oflag & O_CREAT) {
		(void)mode;
		fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
		if (fd >= 0) created = 1;
		else if (errno == EEXIST && !(oflag & O_EXCL))
			fd = open(path, O_RDWR | O_CLOEXEC, 0);
	} else {
		fd = open(path, O_RDWR | O_CLOEXEC, 0);
	}
	if (fd < 0) goto fail_locked;

	if (created) {
		memset(&h, 0, sizeof h);
		h.magic = MQ_MAGIC;
		h.version = MQ_VERSION;
		h.maxmsg = attr ? (unsigned)supplied.mq_maxmsg : MQ_DEFAULT_MAXMSG;
		h.msgsize = attr ? (unsigned)supplied.mq_msgsize : MQ_DEFAULT_MSGSIZE;
		h.sequence = 1;
		object_sequence++;
		n = snprintf(h.lock_name, sizeof h.lock_name,
		         "\\BaseNamedObjects\\spicule.mq.%d.%u.lock", (int)getpid(), object_sequence);
		if (n < 0 || (size_t)n >= sizeof h.lock_name) {
			if (n >= 0) errno = ENAMETOOLONG;
			goto fail_created;
		}
		n = snprintf(h.items_name, sizeof h.items_name,
		         "\\BaseNamedObjects\\spicule.mq.%d.%u.items", (int)getpid(), object_sequence);
		if (n < 0 || (size_t)n >= sizeof h.items_name) {
			if (n >= 0) errno = ENAMETOOLONG;
			goto fail_created;
		}
		n = snprintf(h.spaces_name, sizeof h.spaces_name,
		         "\\BaseNamedObjects\\spicule.mq.%d.%u.spaces", (int)getpid(), object_sequence);
		if (n < 0 || (size_t)n >= sizeof h.spaces_name) {
			if (n >= 0) errno = ENAMETOOLONG;
			goto fail_created;
		}
		file_size = sizeof h + (size_t)h.maxmsg * (sizeof(struct mq_slot) + h.msgsize);
		if (ftruncate(fd, (off_t)file_size) < 0 || raw_write(__fds[fd].h, &h, sizeof h, 0) < 0)
			goto fail_created;
	} else {
		/* io_failed distinguishes a real I/O failure (errno already set by
		 * raw_read()) from a corrupt/incompatible header: errno isn't
		 * guaranteed 0 on entry, so `if (!errno) errno = EIO` could report
		 * a stale unrelated errno instead. */
		int io_failed = raw_read(__fds[fd].h, &h, sizeof h, 0) < 0;
		if (io_failed || h.magic != MQ_MAGIC || h.version != MQ_VERSION ||
		    !h.maxmsg || h.maxmsg > MQ_MAXMSG_LIMIT ||
		    !h.msgsize || h.msgsize > MQ_MSGSIZE_LIMIT) {
			if (!io_failed) errno = EIO;
			goto fail_fd;
		}
	}

	if (create_sem(h.lock_name, 1, 1, &lock) < 0 || take(lock) < 0) goto fail_fd;
	/* The state lock makes these counts an atomic snapshot when all NT
	 * objects had disappeared and are being reconstructed. */
	if (raw_read(__fds[fd].h, &h, sizeof h, 0) < 0) goto fail_qlocked;
	if (create_sem(h.items_name, (long)h.curmsgs, (long)h.maxmsg, &items) < 0 ||
	    create_sem(h.spaces_name, (long)(h.maxmsg - h.curmsgs), (long)h.maxmsg, &spaces) < 0)
		goto fail_qlocked;
	give(lock);
	give(ns);
	__plat_sync_close(ns);

	d = &mqds[fd];
	memset(d, 0, sizeof *d);
	d->magic = MQ_DESC_MAGIC;
	d->file = __fds[fd].h;
	d->lock = lock;
	d->items = items;
	d->spaces = spaces;
	d->maxmsg = h.maxmsg;
	d->msgsize = h.msgsize;
	__fds[fd].flags = (unsigned)access | (oflag & O_NONBLOCK) | O_CLOEXEC;
	free(path);
	errno = 0;
	return fd;

fail_qlocked:
	give(lock);
fail_fd:
	saved = errno;
	if (fd >= 0) (void)close(fd);
	if (created) (void)unlink(path);
	goto fail_locked_saved;
fail_created:
	saved = errno;
	(void)close(fd);
	(void)unlink(path);
	goto fail_locked_saved;
fail_locked:
	saved = errno;
fail_locked_saved:
	give(ns);
fail:
	if (!saved) saved = errno;
	if (spaces) __plat_sync_close(spaces);
	if (items) __plat_sync_close(items);
	if (lock) __plat_sync_close(lock);
	if (ns) __plat_sync_close(ns);
	free(path);
	errno = saved;
	return (mqd_t)-1;
}

static int wait_count(struct mq_desc *d, __plat_handle_t count, int nonblock,
	const struct timespec *abstime, int timed, int receiver) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct timespec now;
	struct mq_header h;
	/* This semaphore isn't part of cross-process signal delivery's wake set,
	 * so pending signals must be drained on this thread explicitly; the
	 * thread counter avoids a spurious interrupt from an unrelated thread's
	 * handler. */
	unsigned long caught = __sig_thread_caught_count();
	int registered = 0;
	int status = __plat_wait_one(count, 1, 1, 0);
	if (status == __PLAT_WAIT_OK) return 0;
	if (status != __PLAT_WAIT_TIMEOUT && status != __PLAT_WAIT_INTR)
		return -1; /* errno already set by __plat_wait_one */
	__sig_drain_pending();
	if (__sig_thread_caught_count() != caught) { errno = EINTR; return -1; }
	if (nonblock) { errno = EAGAIN; return -1; }
	if (timed && (!abstime || abstime->tv_nsec < 0 || abstime->tv_nsec >= 1000000000L)) {
		errno = EINVAL; return -1;
	}
	if (receiver) {
		if (take(d->lock) < 0) return -1;
		if (read_header(d, &h) < 0) { give(d->lock); return -1; }
		h.receive_waiters++;
		if (raw_write(d->file, &h, sizeof h, 0) < 0) { give(d->lock); return -1; }
		give(d->lock);
		registered = 1;
	}
	for (;;) {
		long long slice;
		__sig_drain_pending();
		if (__sig_thread_caught_count() != caught) { errno = EINTR; break; }
		if (timed) {
			long long ticks;
			clock_gettime(CLOCK_REALTIME, &now);
			ticks = __timespec_diff_ticks(abstime->tv_sec,
				abstime->tv_nsec, now.tv_sec, now.tv_nsec);
			if (ticks <= 0) { errno = ETIMEDOUT; break; }
			if (ticks > 500000) ticks = 500000;
			slice = -ticks;
		} else slice = -500000;
		status = __plat_wait_one(count, 1, 1, slice);
		if (status == __PLAT_WAIT_OK) break;
		if (status != __PLAT_WAIT_TIMEOUT && status != __PLAT_WAIT_INTR) {
			/* errno already set by __plat_wait_one */
			break;
		}
		__sig_drain_pending();
		if (__sig_thread_caught_count() != caught) { errno = EINTR; break; }
	}
	if (registered) {
		int saved = errno;
		if (take(d->lock) == 0) {
			if (read_header(d, &h) == 0 && h.receive_waiters) {
				h.receive_waiters--;
				raw_write(d->file, &h, sizeof h, 0);
			}
			give(d->lock);
		}
		errno = saved;
	}
	return status == __PLAT_WAIT_OK ? 0 : -1;
}

int mq_timedsend(mqd_t mqdes, const char *msg, size_t len, unsigned prio, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
	const struct timespec *abstime)
{
	struct mq_desc *d = get_desc(mqdes);
	struct mq_header h;
	struct mq_slot s;
	unsigned i, free_slot = d ? d->maxmsg : 0;
	int notify = 0, notify_kind = 0, notify_pid = 0, notify_signo = 0;
	union sigval notify_value;
	if (!d) return -1;
	if ((__fds[mqdes].flags & O_ACCMODE) == O_RDONLY) { errno = EBADF; return -1; }
	if (len > d->msgsize) { errno = EMSGSIZE; return -1; }
	if (prio >= MQ_PRIO_MAX) { errno = EINVAL; return -1; }
	if (wait_count(d, d->spaces, (__fds[mqdes].flags & O_NONBLOCK) != 0,
	               abstime, abstime != NULL, 0) < 0) return -1;
	if (take(d->lock) < 0) { give(d->spaces); return -1; }
	if (read_header(d, &h) < 0) goto rollback;
	for (i = 0; i < d->maxmsg; i++) {
		if (raw_read(d->file, &s, sizeof s, slot_offset(d, i)) < 0) goto rollback;
		if (!s.used) { free_slot = i; break; }
	}
	if (free_slot == d->maxmsg) { errno = EIO; goto rollback; }
	memset(&s, 0, sizeof s);
	s.used = 1; s.priority = prio; s.length = (unsigned)len; s.sequence = h.sequence++;
	if (len && raw_write(d->file, msg, len,
	                     slot_offset(d, free_slot) + (off_t)sizeof s) < 0) goto rollback;
	if (raw_write(d->file, &s, sizeof s, slot_offset(d, free_slot)) < 0) goto rollback;
	if (!h.curmsgs && h.notify_active && !h.receive_waiters) {
		notify = 1; notify_kind = h.notify_kind; notify_pid = h.notify_pid;
		if (notify_kind == SIGEV_SIGNAL) {
			notify_signo = h.notify.signal.signo;
			notify_value = h.notify.signal.value;
		}
		h.notify_active = 0;
	}
	h.curmsgs++;
	if (raw_write(d->file, &h, sizeof h, 0) < 0) goto rollback;
	give(d->lock);
	give(d->items);
	if (notify && notify_kind == SIGEV_SIGNAL)
		(void)sigqueue((pid_t)notify_pid, notify_signo, notify_value);
	return 0;
rollback:
	give(d->lock);
	give(d->spaces);
	return -1;
}

int mq_send(mqd_t mqdes, const char *msg, size_t len, unsigned prio)
{
	return mq_timedsend(mqdes, msg, len, prio, NULL);
}

ssize_t mq_timedreceive(mqd_t mqdes, char *msg, size_t len, unsigned *prio,
	const struct timespec *abstime)
{
	struct mq_desc *d = get_desc(mqdes);
	struct mq_header h;
	struct mq_slot s, best;
	unsigned i, selected = d ? d->maxmsg : 0;
	if (!d) return -1;
	if ((__fds[mqdes].flags & O_ACCMODE) == O_WRONLY) { errno = EBADF; return -1; }
	if (len < d->msgsize) { errno = EMSGSIZE; return -1; }
	if (wait_count(d, d->items, (__fds[mqdes].flags & O_NONBLOCK) != 0,
	               abstime, abstime != NULL, 1) < 0) return -1;
	if (take(d->lock) < 0) { give(d->items); return -1; }
	if (read_header(d, &h) < 0) goto rollback;
	memset(&best, 0, sizeof best);
	for (i = 0; i < d->maxmsg; i++) {
		if (raw_read(d->file, &s, sizeof s, slot_offset(d, i)) < 0) goto rollback;
		if (s.used && (selected == d->maxmsg || s.priority > best.priority ||
		    (s.priority == best.priority && s.sequence < best.sequence))) {
			best = s; selected = i;
		}
	}
	if (selected == d->maxmsg || !h.curmsgs || best.length > d->msgsize) {
		errno = EIO; goto rollback;
	}
	if (best.length && raw_read(d->file, msg, best.length,
	                            slot_offset(d, selected) + (off_t)sizeof best) < 0) goto rollback;
	memset(&s, 0, sizeof s);
	if (raw_write(d->file, &s, sizeof s, slot_offset(d, selected)) < 0) goto rollback;
	h.curmsgs--;
	if (raw_write(d->file, &h, sizeof h, 0) < 0) goto rollback;
	give(d->lock);
	give(d->spaces);
	if (prio) *prio = best.priority;
	return (ssize_t)best.length;
rollback:
	give(d->lock);
	give(d->items);
	return -1;
}

ssize_t mq_receive(mqd_t mqdes, char *msg, size_t len, unsigned *prio)
{
	return mq_timedreceive(mqdes, msg, len, prio, NULL);
}

int mq_getattr(mqd_t mqdes, struct mq_attr *attr)
{
	struct mq_desc *d = get_desc(mqdes);
	struct mq_header h;
	if (!d) return -1;
	if (!attr) { errno = EINVAL; return -1; }
	if (take(d->lock) < 0) return -1;
	if (read_header(d, &h) < 0) { give(d->lock); return -1; }
	memset(attr, 0, sizeof *attr);
	/* read_header() preserves creation-time limits before these ABI conversions. */
	attr->mq_flags = (long)(__fds[mqdes].flags & O_NONBLOCK);
	attr->mq_maxmsg = (long)h.maxmsg;
	attr->mq_msgsize = (long)h.msgsize;
	attr->mq_curmsgs = (long)h.curmsgs;
	give(d->lock);
	return 0;
}

int mq_setattr(mqd_t mqdes, const struct mq_attr *attr, struct mq_attr *old)
{
	struct mq_desc *d = get_desc(mqdes);
	if (!d) return -1;
	if (!attr) { errno = EINVAL; return -1; }
	if (old && mq_getattr(mqdes, old) < 0) return -1;
	__fds[mqdes].flags = (__fds[mqdes].flags & ~O_NONBLOCK) |
	                       (attr->mq_flags & O_NONBLOCK);
	return 0;
}

int mq_notify(mqd_t mqdes, const struct sigevent *event)
{
	struct mq_desc *d = get_desc(mqdes);
	struct mq_header h;
	if (!d) return -1;
	if (event && event->sigev_notify != SIGEV_SIGNAL && event->sigev_notify != SIGEV_NONE) {
		errno = EINVAL; return -1;
	}
	if (event && event->sigev_notify == SIGEV_SIGNAL &&
	    (event->sigev_signo < 0 || event->sigev_signo >= _NSIG)) {
		errno = EINVAL; return -1;
	}
	if (take(d->lock) < 0) return -1;
	if (read_header(d, &h) < 0) { give(d->lock); return -1; }
	if (!event) {
		if (h.notify_active && h.notify_pid == (int)getpid()) h.notify_active = 0;
	} else {
		if (h.notify_active) { give(d->lock); errno = EBUSY; return -1; }
		h.notify_active = 1;
		h.notify_kind = event->sigev_notify;
		h.notify_pid = (int)getpid();
		h.notify_fd = mqdes;
		if (event->sigev_notify == SIGEV_SIGNAL) {
			h.notify.signal.signo = event->sigev_signo;
			h.notify.signal.value = event->sigev_value;
		}
	}
	if (raw_write(d->file, &h, sizeof h, 0) < 0) { give(d->lock); return -1; }
	give(d->lock);
	return 0;
}

void __mq_fd_closed(int fd)
{
	struct mq_desc *d;
	struct mq_header h;
	if (fd < 0 || fd >= FD_MAX) return;
	d = &mqds[fd];
	if (d->magic != MQ_DESC_MAGIC || d->file != __fds[fd].h) return;
	if (take(d->lock) == 0) {
		if (read_header(d, &h) == 0 && h.notify_active &&
		    h.notify_pid == (int)getpid() && h.notify_fd == fd) {
			h.notify_active = 0;
			raw_write(d->file, &h, sizeof h, 0);
		}
		give(d->lock);
	}
	__plat_sync_close(d->spaces);
	__plat_sync_close(d->items);
	__plat_sync_close(d->lock);
	memset(d, 0, sizeof *d);
}

void __mq_fd_replaced(int fd, __plat_handle_t handle)
{
	if (fd >= 0 && fd < FD_MAX && mqds[fd].magic == MQ_DESC_MAGIC)
		mqds[fd].file = handle;
}

int mq_close(mqd_t mqdes)
{
	if (!get_desc(mqdes)) return -1;
	return close(mqdes);
}

int mq_unlink(const char *name)
{
	char *path = mq_path(name), nsname[96];
	unsigned long long hash;
	__plat_handle_t ns = 0;
	int result, saved, n;
	if (!path) return -1;
	if (ensure_dir(path) < 0) { free(path); return -1; }
	hash = path_hash(path);
	n = snprintf(nsname, sizeof nsname, "\\BaseNamedObjects\\spicule.mq.name.%08x%08x",
	         (unsigned)(hash >> 32), (unsigned)hash);
	if (n < 0 || (size_t)n >= sizeof nsname) {
		if (n >= 0) errno = ENAMETOOLONG;
		free(path);
		return -1;
	}
	if (create_sem(nsname, 1, 1, &ns) < 0 || take(ns) < 0) {
		saved = errno; if (ns) __plat_sync_close(ns); free(path); errno = saved; return -1;
	}
	result = unlink(path); saved = errno;
	give(ns); __plat_sync_close(ns); free(path); errno = saved;
	return result;
}

// NOLINTEND(misc-include-cleaner)
