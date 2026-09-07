/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * atd: the at(1p)/batch(1p) scheduling daemon. Not a POSIX utility
 * (no atd(1p)/atd(8) page), but necessary: at(1p)/batch(1p) only
 * submit jobs to the spool (atbatch.c) and return immediately; atd is
 * what notices a due job and actually runs it.
 *
 * Standalone executable only, never a shell builtin (unlike every
 * other src/util/ utility): atd runs forever by design, so running it
 * in-process would either block the shell forever or require the
 * builtin to fork/spawn a detached shell copy. See bin/atd.c and the
 * deliberate absence of a bi_atd() in src/sh/builtin.c.
 *
 * Backgrounding per platform: on Linux this function is the daemon
 * loop itself, detaching from a controlling terminal via
 * daemonize_if_tty() only when one is attached. NT has no
 * controlling-terminal concept, so that's a no-op there; an NT atd is
 * just an ordinary long-running process someone starts once (see
 * bin/atd.c) -- not a registered Service Control Manager service,
 * which is out of scope here.
 *
 * Poll loop, once per tick (SPICULE_ATD_POLL_MS ms, default 1000 --
 * overridable as a test-speed knob since at/batch have no
 * spec-mandated latency):
 *   1. For each *.job file under the spool whose run_at header is due:
 *      a. queue "b" (batch) jobs defer to next tick if getloadavg()'s
 *         1-minute average is >= BATCH_LOAD_THRESHOLD; NT (no
 *         getloadavg()) always runs immediately instead.
 *      b. otherwise claim it by rename()ing <id>.job to
 *         <id>.job.running (atomic ownership mark), then
 *         posix_spawn() `sh <path>` with output captured to <id>.out
 *         (no mail transport, see atbatch.h). The pid is tracked, not
 *         waited on, so multiple due jobs start without blocking
 *         each other.
 *   2. Reap exited children (waitpid(WNOHANG)), unlinking their
 *      .job.running marker; <id>.out is left for the user to read.
 *   3. Sleep one tick, repeat.
 *
 * Never blocking on a running job means one long at(1p) job can't
 * delay another due job or cron (crond.c, a separate process).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <spawn.h>
#include "util.h"
#include "spool.h"
#include "libc.h" /* __find_program() */
#include "ownership_stubs.h"

/* batch(1p) defers above this 1-minute load average; matches the
 * BSD/GNU atd default (1.5) since POSIX leaves the threshold
 * unspecified. */
#define BATCH_LOAD_THRESHOLD 1.5

static volatile sig_atomic_t g_stop;

static void on_term(int sig)
{
	(void)sig;
	g_stop = 1;
}

/* Linux only: fork()+setsid() daemon(3) idiom, but only if stdin is a
 * tty -- skip it if atd is already started detached (test harness,
 * init system). No-op on NT (no controlling-terminal concept). */
static void daemonize_if_tty(void)
{
#if defined(__linux__)
	if (!isatty(0)) return;
	{
		pid_t pid = fork();
		if (pid < 0) return; /* stay attached rather than fail outright */
		if (pid > 0) _exit(0); /* parent: hand control back to the shell */
	}
	setsid();
	(void)freopen("/dev/null", "r", stdin);
	(void)freopen("/dev/null", "w", stdout);
	(void)freopen("/dev/null", "w", stderr);
#endif
}

struct running_job {
	pid_t pid;
	char running_path[SPICULE_SPOOL_PATH_MAX];
};

#define MAX_RUNNING 128
static struct running_job g_running[MAX_RUNNING];
static int g_nrunning;

static void reap_finished(void)
{
	int i;
	for (i = 0; i < g_nrunning; ) {
		int status;
		pid_t r = waitpid(g_running[i].pid, &status, WNOHANG);
		if (r == g_running[i].pid) {
			if (unlink(g_running[i].running_path) < 0)
				fprintf(stderr, "atd: cannot clean up %s: %s\n",
				        g_running[i].running_path, strerror(errno));
			/* spicule.ValidPointer finding on this swap-with-last
			 * compaction left open; crond.c's identical idiom too. */
			g_running[i] = g_running[g_nrunning - 1];
			g_nrunning--;
			continue;
		}
		i++;
	}
}

/* Spawns `sh running_path`, output captured to `<dir>/<id>.out`.
 * Returns the child pid on success, or -1 if it never started (sh
 * not found, spawn failed) -- caller must unlink running_path itself
 * since there's no waitpid() to trigger reap_finished()'s cleanup. */
static pid_t spawn_job(const char *dir, const char *id, const char *running_path)
{
	extern char **environ;
	posix_spawn_file_actions_t fa;
	char *sh_path;
	char outpath[SPICULE_SPOOL_PATH_MAX];
	char *argv2[3];
	pid_t pid;
	int rc;

	if (snprintf(outpath, sizeof outpath, "%s/%s.out", dir, id) >= (int)sizeof outpath) {
		errno = ENAMETOOLONG;
		return -1;
	}
	unsafe_assume_string_terminated(outpath); /* the snprintf() length check above */
	sh_path = __find_program("sh", 1);
	if (!sh_path) { errno = ENOENT; return -1; }

	if (posix_spawn_file_actions_init(&fa) != 0) { free(sh_path); return -1; }
	(void)posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
	(void)posix_spawn_file_actions_addopen(&fa, 1, outpath, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	(void)posix_spawn_file_actions_adddup2(&fa, 1, 2);

	argv2[0] = sh_path;
	argv2[1] = (char *)running_path;
	argv2[2] = 0;

	rc = posix_spawn(&pid, sh_path, &fa, 0, argv2, environ);
	posix_spawn_file_actions_destroy(&fa);
	free(sh_path);
	if (rc != 0) { errno = rc; return -1; }
	return pid;
}

static void poll_once(const char *dir)
{
	DIR *dp = opendir(dir);
	struct dirent *de;
	time_t now = time(0);

	if (!dp) return;
	while ((de = readdir(dp)) != 0) {
		size_t l;
		char path[SPICULE_SPOOL_PATH_MAX];
		char running[SPICULE_SPOOL_PATH_MAX];
		char id[64];
		time_t run_at;
		char queue[32];
		pid_t pid;

		unsafe_assume_string_terminated(de->d_name); /* POSIX dirent contract */
		l = strlen(de->d_name);
		if (l <= 4 || strcmp(de->d_name + l - 4, ".job")) continue;
		if (l - 4 >= sizeof id) continue;
		memcpy(id, de->d_name, l - 4);
		id[l - 4] = 0;

		if (snprintf(path, sizeof path, "%s/%s.job", dir, id) >= (int)sizeof path) continue;
		if (__spool_job_header(path, &run_at, queue, sizeof queue) < 0) continue;
		unsafe_assume_string_terminated(queue); /* __spool_job_header() contract */
		if (run_at > now) continue;

		if (!strcmp(queue, "b")) {
			double load[1];
			if (getloadavg(load, 1) == 1 && load[0] >= BATCH_LOAD_THRESHOLD)
				continue; /* system busy -- try again next tick */
		}

		if (snprintf(running, sizeof running, "%s/%s.job.running", dir, id) >= (int)sizeof running)
			continue;
		unsafe_assume_string_terminated(running); /* the snprintf() length check above */
		if (rename(path, running) < 0) continue; /* another instance claimed it first */

		if (g_nrunning >= MAX_RUNNING) {
			/* No free slot: rename back so next tick's scan retries it. */
			if (rename(running, path) < 0)
				fprintf(stderr, "atd: cannot re-queue %s: %s\n", id, strerror(errno));
			continue;
		}
		pid = spawn_job(dir, id, running);
		if (pid < 0) {
			if (unlink(running) < 0)
				fprintf(stderr, "atd: cannot clean up %s: %s\n", id, strerror(errno));
			continue;
		}
		g_running[g_nrunning].pid = pid;
		strcpy(g_running[g_nrunning].running_path, running);
		g_nrunning++;
	}
	(void)closedir(dp);
}

int __util_atd_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	char dir[SPICULE_SPOOL_PATH_MAX];
	long poll_ms = 1000;
	const char *env_poll = getenv("SPICULE_ATD_POLL_MS");

	(void)argc; (void)argv;
	if (env_poll && *env_poll) {
		char *end;
		long v = strtol(env_poll, &end, 10);
		if (!*end && v > 0) poll_ms = v;
	}

	if (__spool_dir("atjobs", dir, sizeof dir) < 0) {
		fprintf(stderr, "atd: cannot access job spool: %s\n", strerror(errno));
		return 1;
	}

	signal(SIGTERM, on_term);
	signal(SIGINT, on_term);
	daemonize_if_tty();

	while (!g_stop) {
		struct timespec ts;
		poll_once(dir);
		reap_finished();
		ts.tv_sec = poll_ms / 1000;
		ts.tv_nsec = (poll_ms % 1000) * 1000000L;
		nanosleep(&ts, 0);
	}
	reap_finished();
	return 0;
}
