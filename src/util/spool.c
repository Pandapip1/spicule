/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * See src/internal/spool.h for what this is and why it lives here,
 * shared rather than duplicated, between src/util/atbatch.c,
 * src/util/atd.c, src/util/crontab.c and src/util/crond.c.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h>
#include <sys/stat.h>
#include "spool.h"

int __spool_home(char *buf, size_t bufsz)
{
	const char *h = getenv("HOME");
	struct passwd *pw;

	if (!h || !*h) {
		pw = getpwuid(getuid());
		h = (pw && pw->pw_dir && *pw->pw_dir) ? pw->pw_dir : 0;
	}
	if (!h) return -1;
	if (strlen(h) + 1 > bufsz) { errno = ENAMETOOLONG; return -1; }
	strcpy(buf, h);
	return 0;
}

/* mkdir()s `path` in place, tolerating EEXIST (a directory left by an
 * earlier run, or created by a racing process -- either is fine, both
 * mean "this level already exists" rather than a real failure). Not
 * a general mkdir -p: it never recurses past one component, because
 * every caller here only ever needs to create exactly one or two
 * levels under an already-existing $HOME (see __spool_dir() below). */
static int mkdir_tolerant(const char *path)
{
	if (mkdir(path, 0700) == 0) return 0;
	return errno == EEXIST ? 0 : -1;
}

int __spool_dir(const char *sub, char *buf, size_t bufsz)
{
	size_t homelen, need;

	if (__spool_home(buf, bufsz) < 0) { errno = ENOENT; return -1; }
	homelen = strlen(buf);
	need = homelen + strlen("/.ntlibc/") + strlen(sub) + 1;
	if (need > bufsz) { errno = ENAMETOOLONG; return -1; }

	strcpy(buf + homelen, "/.ntlibc");
	if (mkdir_tolerant(buf) < 0) return -1;

	strcat(buf, "/");
	strcat(buf, sub);
	if (mkdir_tolerant(buf) < 0) return -1;
	return 0;
}

/* Bounded, not open-ended: a runaway id search would otherwise be an
 * infinite loop against a hostile or corrupted spool directory. 100000
 * consecutive collisions is already far more than any real workload
 * (or this project's own tests) could produce -- it exists to turn a
 * pathological case into a clean ENOSPC-shaped failure instead of a
 * hang. */
#define MAX_ID_ATTEMPTS 100000

withtok(file_stream_open)
FILE *__spool_new_job(const char *dir, char *id_out, size_t id_out_sz,
	char *path_out, size_t path_out_sz)
{
	long id = (long)time(0);
	int attempt;
	int fd;

	for (attempt = 0; attempt < MAX_ID_ATTEMPTS; attempt++, id++) {
		int n = snprintf(path_out, path_out_sz, "%s/%ld.job", dir, id);
		char tmp[NTLIBC_SPOOL_PATH_MAX];

		if (n < 0 || (size_t)n >= path_out_sz) { errno = ENAMETOOLONG; return 0; }
		n = snprintf(tmp, sizeof tmp, "%s.tmp", path_out);
		if (n < 0 || (size_t)n >= sizeof tmp) { errno = ENAMETOOLONG; return 0; }

		fd = open(tmp, O_CREAT | O_EXCL | O_WRONLY, 0600);
		if (fd >= 0) {
			FILE *f = fdopen(fd, "w");
			if (!f) { int e = errno; (void)close(fd); (void)unlink(tmp); errno = e; return 0; }
			if (snprintf(id_out, id_out_sz, "%ld", id) >= (int)id_out_sz) {
				(void)fclose(f);
				(void)unlink(tmp);
				errno = ENAMETOOLONG;
				return 0;
			}
			return f;
		}
		if (errno != EEXIST) return 0;
	}
	errno = ENOSPC;
	return 0;
}

int __spool_publish_job(const char *path)
{
	char tmp[NTLIBC_SPOOL_PATH_MAX];
	int n = snprintf(tmp, sizeof tmp, "%s.tmp", path);

	if (n < 0 || (size_t)n >= sizeof tmp) { errno = ENAMETOOLONG; return -1; }
	return rename(tmp, path);
}

int __spool_job_header(const char *path, time_t *run_at, char *queue, size_t queue_sz)
{
	FILE *f = fopen(path, "r");
	char line[256];
	int have = 0;

	if (!f) return -1;
	if (queue_sz > 0) queue[0] = 0;
	while (fgets(line, sizeof line, f)) {
		if (!strncmp(line, "#run_at ", 8)) {
			*run_at = (time_t)strtoll(line + 8, 0, 10);
			have = 1;
		} else if (!strncmp(line, "#queue ", 7)) {
			size_t l = strcspn(line + 7, "\n");
			if (queue_sz) {
				if (l >= queue_sz) l = queue_sz - 1;
				(void)snprintf(queue, queue_sz, "%.*s", (int)l,
				    line + 7);
			}
		} else if (line[0] != '#') {
			break;
		}
	}
	(void)fclose(f);
	if (!have) errno = ENOENT;
	return have ? 0 : -1;
}

const char *__spool_crontab_path(char *buf, size_t bufsz)
{
	char dir[NTLIBC_SPOOL_PATH_MAX];
	int n;

	if (__spool_dir("crontabs", dir, sizeof dir) < 0) return 0;
	n = snprintf(buf, bufsz, "%s/crontab", dir);
	if (n < 0 || (size_t)n >= bufsz) { errno = ENAMETOOLONG; return 0; }
	return buf;
}
