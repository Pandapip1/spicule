/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * crond: the cron(8) scheduling daemon behind crontab(1p)
 * (src/util/crontab.c). Not itself a POSIX utility -- there is no
 * cron(1p)/crond(8) page in XCU at all, crontab(1p) is the only part
 * of "cron" POSIX actually specifies -- but real, necessary
 * infrastructure for exactly the same reason src/util/atd.c is: a
 * crontab is inert data until something notices its schedule and
 * actually runs the command.
 *
 * STANDALONE ONLY, NEVER A BUILTIN
 * ------------------------------------
 * Same reasoning as src/util/atd.c's own header, restated briefly:
 * crond runs forever, so "run it in-process inside an interactive
 * shell" is not a builtin's job. See bin/crond.c and the deliberate
 * absence of a bi_crond() in src/sh/builtin.c.
 *
 * PARSING crontab(5)'S FIVE TIME FIELDS
 * ------------------------------------------
 * src/util/crontime.c does the real work (ranges/steps/lists/names,
 * the dom-vs-dow OR-not-AND special case); this file's only job is to
 * notice when $HOME/.ntlibc/crontabs/crontab (src/util/spool.h) has
 * changed -- stat()ing its mtime once per poll tick, exactly the way
 * src/util/spool.h's own header documents crond doing it, no lock
 * needed because crontab(1p) always publishes a complete file via
 * rename() -- and re-run src/util/crontime.c's parser over it when it
 * has.
 *
 * MINUTE GRANULARITY IS REAL, NOT A POLLING ARTIFACT
 * -------------------------------------------------------
 * crontab(5)'s finest field is minutes, so a schedule can only ever
 * mean to the wall-clock minute -- this file polls every
 * NTLIBC_CROND_POLL_MS (default 1000ms, the same test-speed-only
 * override src/util/atd.c documents for its own poll interval) but
 * only ever *fires* an entry once per distinct wall-clock minute
 * (tracked via last_fired_minute below, an epoch-seconds-over-60
 * counter): polling faster only shortens how long a due entry can sit
 * unnoticed at the top of a new minute, it never makes an entry fire
 * twice for the same minute or early for one it hasn't reached yet.
 *
 * THE COMMAND FIELD'S "%" CONVENTION
 * ---------------------------------------
 * crontab.html's own INPUT FILES: "A percent-sign character in this
 * field shall be translated to a newline character." The fuller real-
 * world rule -- checked directly against the actual crontab(5) manual
 * page every Vixie-derived cron agrees on, since POSIX's one sentence
 * does not by itself say what a percent-sign *starts* -- is
 * implemented here: the first unescaped '%' ends the command and
 * starts the command's standard input (every '%' after that, still
 * unescaped, becomes a newline within that input); "\%" anywhere
 * unescapes to a literal '%' and never triggers the split. See
 * split_percent() below.
 *
 * OUTPUT
 * --------
 * No mail transport (mailx is out of scope for this whole project
 * pass -- see src/util/atbatch.h's identical note for at(1p)/
 * batch(1p)), so real cron's "mail the job's output to the user" has
 * the same honest fallback here: every run's combined stdout+stderr
 * is appended to $HOME/.ntlibc/crontabs/cron.log, preceded by a
 * header line naming the entry and the time it ran, so a user who
 * wants to know what their crontab has been doing has exactly one
 * place to look.
 */
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <spawn.h>
#include "util.h"
#include "spool.h"
#include "crontime.h"
#include "libc.h" /* __find_program() */

static volatile sig_atomic_t g_stop;
static void on_term(int sig) { (void)sig; g_stop = 1; }

struct cron_entry {
	struct crontime ct;
	char *command; /* raw command field, '%'-split lazily at run time */
};

static struct cron_entry *g_entries;
static int g_nentries;

static void free_entries(void)
{
	int i;
	for (i = 0; i < g_nentries; i++) free(g_entries[i].command);
	free(g_entries);
	g_entries = 0;
	g_nentries = 0;
}

static int grow_entries(struct cron_entry **arr, int *n, int *cap)
{
	if (*n < *cap) return 0;
	{
		size_t newcap;
		struct cron_entry *n2;
		if (!__util_array_capacity((size_t)*cap, (size_t)*n, 1, 8, sizeof **arr, &newcap) ||
		    newcap > (size_t)INT_MAX) return -1;
		n2 = __util_reallocarray(*arr, newcap, sizeof **arr);
		if (!n2) return -1;
		*arr = n2;
		*cap = (int)newcap;
	}
	return 0;
}

static int split_field(const char **pp, char *out, size_t outsz)
{
	const char *p = *pp;
	size_t n;
	while (*p == ' ' || *p == '\t') p++;
	n = strcspn(p, " \t\n");
	if (n == 0 || n >= outsz || n > INT_MAX) return -1;
	if (snprintf(out, outsz, "%.*s", (int)n, p) != (int)n) return -1;
	*pp = p + n;
	return 0;
}

static int looks_like_assignment(const char *p)
{
	if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || *p == '_')) return 0;
	while ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
	       (*p >= '0' && *p <= '9') || *p == '_') p++;
	while (*p == ' ' || *p == '\t') p++;
	return *p == '=';
}

/* Reparses the whole crontab into g_entries/g_nentries. A malformed
 * line is skipped (with a diagnostic to crond's own stderr) rather
 * than aborting the whole reload -- crontab(1p) itself already
 * refuses a bad crontab at install time (src/util/crontab.c), so a
 * bad line here means the file was edited by hand after the fact;
 * running every *other*, valid entry is more useful than silently
 * running none of them. */
static void reload_crontab(const char *path)
{
	FILE *f = fopen(path, "r");
	char line[2048];
	long lineno = 0;
	struct cron_entry *arr = 0;
	int n = 0, cap = 0;

	free_entries();
	if (!f) return; /* no crontab at all -- an empty schedule, not an error */

	while (fgets(line, sizeof line, f)) {
		const char *p = line;
		char fields[5][256];
		struct crontime ct;
		int i, ok = 1;

		lineno++;
		while (*p == ' ' || *p == '\t') p++;
		if (*p == '\n' || *p == 0 || *p == '#') continue;
		if (looks_like_assignment(p)) {
			fprintf(stderr, "crond: %s:%ld: environment assignments are not supported, skipped\n", path, lineno);
			continue;
		}
		for (i = 0; i < 5 && ok; i++)
			if (split_field(&p, fields[i], sizeof fields[i]) < 0) ok = 0;
		if (ok) {
			while (*p == ' ' || *p == '\t') p++;
			if (*p == '\n' || *p == 0) ok = 0;
		}
		if (ok && __crontime_parse(fields[0], fields[1], fields[2], fields[3], fields[4], &ct) < 0)
			ok = 0;
		if (!ok) {
			fprintf(stderr, "crond: %s:%ld: malformed entry, skipped\n", path, lineno);
			continue;
		}
		{
			size_t cmdlen = strcspn(p, "\n"), cmdbytes;
			char *cmd;
			if (!__util_size_add(cmdlen, 1, &cmdbytes)) break;
			cmd = malloc(cmdbytes);
			if (!cmd) break;
			memcpy(cmd, p, cmdlen);
			cmd[cmdlen] = 0;
			if (grow_entries(&arr, &n, &cap) < 0) { free(cmd); break; }
			arr[n].ct = ct;
			arr[n].command = cmd;
			n++;
		}
	}
	(void)fclose(f);
	g_entries = arr;
	g_nentries = n;
}

/* crontab(5)'s '%' convention -- see this file's own header. Splits
 * `raw` into a freshly allocated command string (up to the first
 * unescaped '%', "\%" unescaped to '%') and a freshly allocated
 * stdin-body string (everything after, with each unescaped '%'
 * translated to '\n' and "\%" unescaped to '%'). Either output may be
 * empty but is never NULL, unless allocation itself fails (both left
 * NULL in that case). */
static void split_percent(const char *raw, char **cmd_out, char **stdin_out)
{
	size_t len = strlen(raw), bytes;
	char *cmd, *body;
	size_t ci = 0, bi = 0;
	int in_body = 0;
	size_t i;

	*cmd_out = *stdin_out = 0;
	if (!__util_size_add(len, 1, &bytes)) return;
	cmd = malloc(bytes);
	body = malloc(bytes);
	if (!cmd || !body) { free(cmd); free(body); return; }

	for (i = 0; i < len; i++) {
		if (raw[i] == '\\' && raw[i + 1] == '%') {
			if (in_body) body[bi++] = '%'; else cmd[ci++] = '%';
			i++;
			continue;
		}
		if (raw[i] == '%') {
			if (in_body) body[bi++] = '\n';
			else in_body = 1;
			continue;
		}
		if (in_body) body[bi++] = raw[i]; else cmd[ci++] = raw[i];
	}
	cmd[ci] = 0;
	body[bi] = 0;
	*cmd_out = cmd;
	*stdin_out = body;
}

struct running_job { pid_t pid; char stdin_path[NTLIBC_SPOOL_PATH_MAX]; };
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
			if (unlink(g_running[i].stdin_path) < 0)
				fprintf(stderr, "crond: cannot clean up %s: %s\n",
				        g_running[i].stdin_path, strerror(errno));
			g_running[i] = g_running[g_nrunning - 1];
			g_nrunning--;
			continue;
		}
		i++;
	}
}

/* Runs one due entry: `sh -c command`, standard input from a small
 * temp file holding the '%'-derived stdin body, standard output and
 * standard error appended to cron.log (preceded by a header line
 * this function writes itself, synchronously, before spawning --
 * so two entries firing in the same tick never interleave their
 * headers with each other's output, only their own bodies can race,
 * which real cron's own mail-per-job model has no such guarantee
 * against either). */
static void run_entry(const char *crontabs_dir, const struct cron_entry *e, time_t now)
{
	extern char **environ;
	char *cmd, *stdin_body;
	char logpath[NTLIBC_SPOOL_PATH_MAX];
	char stdin_path[NTLIBC_SPOOL_PATH_MAX];
	FILE *log, *sf;
	char *sh_path;
	posix_spawn_file_actions_t fa;
	char *argv2[4];
	pid_t pid;
	int fd;
	char tbuf[32];
	char *ct;

	split_percent(e->command, &cmd, &stdin_body);
	if (!cmd || !stdin_body) { free(cmd); free(stdin_body); return; }

	if (snprintf(logpath, sizeof logpath, "%s/cron.log", crontabs_dir) >= (int)sizeof logpath) {
		free(cmd); free(stdin_body);
		return;
	}
	ct = ctime_r(&now, tbuf);
	if (ct) ct[strcspn(ct, "\n")] = 0;
	log = fopen(logpath, "a");
	if (log) {
		fprintf(log, "==== %s: %s ====\n", ct ? ct : "?", cmd);
		if (fclose(log) < 0)
			fprintf(stderr, "crond: %s: %s\n", logpath, strerror(errno));
	}

	if (snprintf(stdin_path, sizeof stdin_path, "%s/cron.stdin.XXXXXX", crontabs_dir) >= (int)sizeof stdin_path) {
		free(cmd); free(stdin_body);
		return;
	}
	fd = mkstemp(stdin_path);
	if (fd < 0) { free(cmd); free(stdin_body); return; }
	sf = fdopen(fd, "w");
	if (sf) {
		fputs(stdin_body, sf);
		if (fclose(sf) != 0) { (void)unlink(stdin_path); free(cmd); free(stdin_body); return; }
	} else {
		(void)close(fd);
	}

	sh_path = __find_program("sh", 1);
	if (!sh_path) { (void)unlink(stdin_path); free(cmd); free(stdin_body); return; }

	if (posix_spawn_file_actions_init(&fa) != 0) {
		free(sh_path); (void)unlink(stdin_path); free(cmd); free(stdin_body);
		return;
	}
	(void)posix_spawn_file_actions_addopen(&fa, 0, stdin_path, O_RDONLY, 0);
	(void)posix_spawn_file_actions_addopen(&fa, 1, logpath, O_WRONLY | O_APPEND | O_CREAT, 0600);
	(void)posix_spawn_file_actions_adddup2(&fa, 1, 2);

	argv2[0] = sh_path;
	argv2[1] = (char *)"-c";
	argv2[2] = cmd;
	argv2[3] = 0;

	if (posix_spawn(&pid, sh_path, &fa, 0, argv2, environ) == 0 && g_nrunning < MAX_RUNNING) {
		g_running[g_nrunning].pid = pid;
		strcpy(g_running[g_nrunning].stdin_path, stdin_path);
		g_nrunning++;
	} else {
		(void)unlink(stdin_path);
	}
	posix_spawn_file_actions_destroy(&fa);
	free(sh_path);
	free(cmd);
	free(stdin_body);
}

int __util_crond_main(int argc, char **argv)
{
	char crontabs_dir[NTLIBC_SPOOL_PATH_MAX];
	char path[NTLIBC_SPOOL_PATH_MAX];
	long poll_ms = 1000;
	const char *env_poll = getenv("NTLIBC_CROND_POLL_MS");
	time_t last_mtime = 0;
	long last_fired_minute = -1;
	int have_mtime = 0;

	(void)argc; (void)argv;
	if (env_poll && *env_poll) {
		char *end;
		long v = strtol(env_poll, &end, 10);
		if (!*end && v > 0) poll_ms = v;
	}
	if (__spool_dir("crontabs", crontabs_dir, sizeof crontabs_dir) < 0) {
		fprintf(stderr, "crond: cannot access crontab spool: %s\n", strerror(errno));
		return 1;
	}
	if (!__spool_crontab_path(path, sizeof path)) {
		fprintf(stderr, "crond: cannot access crontab spool: %s\n", strerror(errno));
		return 1;
	}

	signal(SIGTERM, on_term);
	signal(SIGINT, on_term);

	while (!g_stop) {
		struct stat st;
		struct timespec ts;

		if (stat(path, &st) == 0) {
			if (!have_mtime || st.st_mtime != last_mtime) {
				reload_crontab(path);
				last_mtime = st.st_mtime;
				have_mtime = 1;
			}
		} else if (have_mtime) {
			free_entries();
			have_mtime = 0;
		}

		{
			time_t now = time(0);
			long minute = (long)(now / 60);
			if (minute != last_fired_minute) {
				struct tm tmv;
				if (localtime_r(&now, &tmv)) {
					int i;
					for (i = 0; i < g_nentries; i++)
						if (__crontime_matches(&g_entries[i].ct, &tmv))
							run_entry(crontabs_dir, &g_entries[i], now);
				}
				last_fired_minute = minute;
			}
		}

		reap_finished();
		ts.tv_sec = poll_ms / 1000;
		ts.tv_nsec = (poll_ms % 1000) * 1000000L;
		nanosleep(&ts, 0);
	}
	reap_finished();
	free_entries();
	return 0;
}
