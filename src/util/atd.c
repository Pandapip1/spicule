/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * atd: the at(1p)/batch(1p) scheduling daemon. Not a POSIX utility --
 * there is no atd(1p)/atd(8) page to check against, the same way
 * src/util/timeout.c is not an XCU utility either -- but real,
 * necessary infrastructure: at(1p)/batch(1p) only *submit* jobs
 * (src/util/atbatch.c writes a job file into the spool and returns
 * immediately); something has to notice a due job and actually run
 * it, and this is that something.
 *
 * WHY A STANDALONE EXECUTABLE, NOT A SHELL BUILTIN
 * ----------------------------------------------------
 * Every other utility in src/util/ is deliberately both a shell
 * builtin (src/sh/builtin.c) and a standalone obj/bin/<name>.exe,
 * because both callers want the *same instantaneous* behaviour: run,
 * produce a result, return. atd is the opposite shape on purpose --
 * it runs forever, outliving the shell invocation that started it by
 * design -- so "run it in-process inside the interactive shell" would
 * either block that shell forever (an obviously wrong builtin) or
 * require the builtin to itself fork/spawn a detached copy of the
 * *shell*, which is not what a builtin is for. This is the same
 * "deliberate exception" shape this project's own POSIX-utilities
 * plan already uses for the builtin-only utilities (alias, cd, ...) --
 * just the mirror image: atd is standalone-only, never a builtin. See
 * bin/atd.c and the deliberate absence of a bi_atd() in
 * src/sh/builtin.c.
 *
 * HOW A REAL BACKGROUND PROCESS IS BUILT ON EACH PLATFORM
 * -------------------------------------------------------------
 * Linux: this function itself IS the daemon loop; whether it also
 * detaches from its controlling terminal (fork()+setsid(), the real
 * daemon(3) idiom) is controlled by whether stdin/stdout/stderr look
 * like a terminal at all -- see daemonize_if_tty() below. NT has no
 * controlling-terminal/session concept to detach from in the same
 * sense, so daemonize_if_tty() is a no-op there; what makes an NT
 * invocation of atd "a background process" is simply that it is
 * spawned once (by whatever starts it -- see bin/atd.c) as an
 * ordinary long-running process, sleeping and polling, the same loop
 * shape as the Linux side. This is deliberately NOT a registered NT
 * service: Service Control Manager integration (a service host,
 * install/uninstall via `sc`, a ServiceMain entry point) is a real,
 * separate undertaking not attempted here -- an ordinary process
 * that a user (or a real service wrapper, should one ever be added)
 * starts once is the honest, working scope.
 *
 * THE POLL LOOP
 * ---------------
 * Once per tick (NTLIBC_ATD_POLL_MS milliseconds, default 1000 --
 * overridable via that environment variable purely as a test-speed
 * knob, documented here rather than left a magic undocumented
 * override: at(1p)/batch(1p) jobs have no spec-mandated latency, so
 * shortening the poll interval for a test is not a spec deviation the
 * way shortening cron's real per-minute granularity would be):
 *
 *   1. List the *.job files under $HOME/.ntlibc/atjobs/ (src/util/spool.h).
 *      For each whose "#run_at" header (src/util/atbatch.h's job file format)
 *      is <= now:
 *        a. If its queue is "b" (batch(1p)'s own queue), consult
 *           getloadavg(); a Linux host that is genuinely busy (1-
 *           minute average >= BATCH_LOAD_THRESHOLD) defers the job to
 *           a later tick, matching batch(1p)'s DESCRIPTION ("run ...
 *           using algorithms ... based on unspecified factors"). A
 *           host getloadavg() cannot answer for at all (NT, always --
 *           see src/stdlib/nt/plat_getloadavg.c) runs the job
 *           immediately instead of inventing a signal that is not
 *           there, which this file states here rather than leaving
 *           implicit in a comparison that happens to always be false.
 *        b. Otherwise, claim the job by rename()ing <id>.job to
 *           <id>.job.running (an atomic, single-syscall "I am the one
 *           executing this" mark -- see spool.h's own rename-publish
 *           idiom, used here in the opposite direction), then
 *           posix_spawn() `sh <path>` with stdin from /dev/null and
 *           stdout+stderr captured to <id>.out (src/util/atbatch.h's
 *           own documented "no mail transport, so capture to a file"
 *           choice). The child's pid is tracked, not waited on
 *           synchronously -- multiple due jobs in one tick all start
 *           without blocking each other or this loop.
 *   2. Reap every previously-spawned child that has since exited
 *      (waitpid(WNOHANG)), and unlink its <id>.job.running marker --
 *      the job is fully finished at that point, with <id>.out left
 *      behind for the user to read.
 *   3. Sleep one tick, repeat.
 *
 * This never blocks on a running job, so one long-running at(1p) job
 * can never delay another due job, or cron (a completely separate
 * process -- see src/util/crond.c) from noticing its own due
 * entries.
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

/* batch(1p) jobs defer while the 1-minute load average is at or above
 * this many runnable processes per core-equivalent -- the same
 * ballpark real BSD/GNU atd implementations default to (historically
 * 1.5, sometimes tunable via `atrun -l`); there is no POSIX-mandated
 * value to cite instead, since batch(1p) itself leaves the threshold
 * entirely to the implementation ("unspecified factors"). */
#define BATCH_LOAD_THRESHOLD 1.5

static volatile sig_atomic_t g_stop;

static void on_term(int sig)
{
	(void)sig;
	g_stop = 1;
}

/* Linux only: detach from a controlling terminal via the real
 * fork()+setsid() daemon(3) idiom, but only when one is actually
 * attached (stdin looks like a tty) -- when atd is already started
 * detached (e.g. by a test harness redirecting stdin, or an init
 * system that already sessioned it), forking again would only lose
 * the parent's ability to see this process's own pid/exit status for
 * no benefit. NT has no controlling-terminal concept to detach from
 * in this sense at all (see this file's own header), so this is a
 * no-op there by construction: NTLIBC_PLATFORM_LINUX guards it. */
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
	char running_path[NTLIBC_SPOOL_PATH_MAX];
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
			g_running[i] = g_running[g_nrunning - 1];
			g_nrunning--;
			continue;
		}
		i++;
	}
}

/* Spawns `sh running_path`, output captured to `<dir>/<id>.out`.
 * Returns the child pid (>= 0) on success, or -1 (errno set) if the
 * job could not even be started (sh not found, or the file actions
 * themselves failed) -- the caller unlinks running_path itself in
 * that case, since there will be no waitpid() to trigger the normal
 * cleanup in reap_finished(). */
static pid_t spawn_job(const char *dir, const char *id, const char *running_path)
{
	extern char **environ;
	posix_spawn_file_actions_t fa;
	char *sh_path;
	char outpath[NTLIBC_SPOOL_PATH_MAX];
	char *argv2[3];
	pid_t pid;
	int rc;

	if (snprintf(outpath, sizeof outpath, "%s/%s.out", dir, id) >= (int)sizeof outpath) {
		errno = ENAMETOOLONG;
		return -1;
	}
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
		size_t l = strlen(de->d_name);
		char path[NTLIBC_SPOOL_PATH_MAX];
		char running[NTLIBC_SPOOL_PATH_MAX];
		char id[64];
		time_t run_at;
		char queue[32];
		pid_t pid;

		if (l <= 4 || strcmp(de->d_name + l - 4, ".job")) continue;
		if (l - 4 >= sizeof id) continue;
		memcpy(id, de->d_name, l - 4);
		id[l - 4] = 0;

		if (snprintf(path, sizeof path, "%s/%s.job", dir, id) >= (int)sizeof path) continue;
		if (__spool_job_header(path, &run_at, queue, sizeof queue) < 0) continue;
		if (run_at > now) continue;

		if (!strcmp(queue, "b")) {
			double load[1];
			if (getloadavg(load, 1) == 1 && load[0] >= BATCH_LOAD_THRESHOLD)
				continue; /* system busy -- try again next tick */
		}

		if (snprintf(running, sizeof running, "%s/%s.job.running", dir, id) >= (int)sizeof running)
			continue;
		if (rename(path, running) < 0) continue; /* another instance claimed it first */

		if (g_nrunning >= MAX_RUNNING) {
			/* Bounded, not silently dropped: leave it claimed but
			 * unstarted for next tick once a slot frees up, rather
			 * than lose track of it. Re-claiming means renaming it
			 * back so the next tick's own is-it-due scan finds it
			 * again. */
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
	char dir[NTLIBC_SPOOL_PATH_MAX];
	long poll_ms = 1000;
	const char *env_poll = getenv("NTLIBC_ATD_POLL_MS");

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
