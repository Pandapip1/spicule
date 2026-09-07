/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for `at`, `batch`, `crontab`, `atd` and `crond` --
 * the deferred/scheduled-job infrastructure (src/util/at.c,
 * src/util/batch.c, src/util/crontab.c, src/util/atd.c,
 * src/util/crond.c). Same spawn+capture technique as every other
 * test/util-*.c in this tree, but these five are the first utilities
 * in this tree with an effect only observable *later*, out of process,
 * via a second real process (atd/crond) noticing a job is due and
 * running it -- so unlike every other test here, several of these
 * cases spawn a real, long-lived daemon, wait (bounded, polling for a
 * marker file the scheduled job itself writes -- never a fixed sleep
 * racing the daemon), and then terminate it.
 *
 * $HOME is redirected to a scratch directory under this test's own
 * working directory (never the real developer/CI account's actual
 * home) for the whole file: src/util/spool.h's whole job spool hangs
 * off $HOME, so this is what keeps every job file, crontab and log
 * this test creates confined to fixtures tools/run-tests.py's own
 * cleanup already owns, the same reasoning test/util-fsops.c's own
 * header gives for scratch/.
 *
 * crontab -e's editor: this binary re-execs *itself* as the editor.
 * Passing SPICULE_TEST_AS_EDITOR=1 in the environment before spawning
 * makes main() below skip every normal test and instead behave as a
 * trivial, deterministic "editor" -- append one fixed, valid crontab
 * line to argv[1] and exit 0 -- which is exactly what crontab.c's
 * do_edit() needs to drive without requiring a real interactive editor
 * (ed, vi, ...) to exist in the test environment. The same technique
 * test/sh-main.c already uses (this file re-executed as the *shell's*
 * child command via --exit-child/--produce/--cat) for the identical
 * reason: this platform has no external /bin/true-equivalent to build
 * a test around.
 *
 * atd's/crond's own poll interval is sped up for these tests via
 * SPICULE_ATD_POLL_MS/SPICULE_CROND_POLL_MS (both files' own header
 * comments document these as a deliberate test-speed-only knob, not a
 * spec deviation) so the at(1p)/batch(1p) cases stay in the
 * few-seconds range this tree's other tests already stay in. crond's own
 * schedule granularity is genuinely per-minute (crontab(5) has no
 * finer field), so that one case is unavoidably slower -- bounded at
 * "wait until the next real minute boundary plus a short margin", not
 * a fixed sleep, and given its own SLOW_TESTS entry in
 * tools/run-tests.py.
 */
/* usleep()/kill()/setenv()/unsetenv() below are all gated behind
 * _POSIX_SOURCE/_POSIX_C_SOURCE/_XOPEN_SOURCE/_GNU_SOURCE/_BSD_SOURCE
 * in spicule's own headers (include/unistd.h, include/signal.h,
 * include/stdlib.h) -- none of which a plain -std=c99 build defines on
 * its own. Same fix, same reasoning, as test/posix-stdlib.c's own
 * top-of-file _GNU_SOURCE define. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>

extern char **environ;
int __spawn(const char *path, char *const argv[], char *const envp[]);

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static char obj_root[1024];
static char self_exe[1024];

/* Same walk-up-from-argv[0] technique every other test/util-*.c in
 * this tree already uses (test/util-fsops.c's own find_obj_root(),
 * copied rather than shared for the same "independent translation
 * unit, four lines" reason that file gives). */
static int find_obj_root(const char *argv0)
{
	size_t n;
	size_t i;

	if (!argv0 || !*argv0) return -1;
	n = strlen(argv0);
	if (n >= sizeof obj_root || n >= sizeof self_exe) return -1;
	strcpy(obj_root, argv0);
	strcpy(self_exe, argv0);

	for (i = n; i > 0; i--)
		if (obj_root[i - 1] == '/' || obj_root[i - 1] == '\\') break;
	if (i == 0) return -1;
	obj_root[i - 1] = 0; /* strip "/util-atcron.exe" */

	n = strlen(obj_root);
	for (i = n; i > 0; i--)
		if (obj_root[i - 1] == '/' || obj_root[i - 1] == '\\') break;
	if (i == 0) return -1;
	obj_root[i - 1] = 0; /* strip "/test" */

	return 0;
}

static void path_for(char *out, size_t outlen, const char *rel)
{
	char sep = strchr(obj_root, '\\') ? '\\' : '/';
	char relcopy[256];
	size_t i;

	strncpy(relcopy, rel, sizeof relcopy - 1);
	relcopy[sizeof relcopy - 1] = 0;
	if (sep == '\\')
		for (i = 0; relcopy[i]; i++)
			if (relcopy[i] == '/') relcopy[i] = '\\';
	snprintf(out, outlen, "%s%c%s", obj_root, sep, relcopy);
}

#define OUTFILE "util-atcron-out.txt"
#define ERRFILE "util-atcron-err.txt"

/* Runs `path args` with stdout/stderr captured to OUTFILE/ERRFILE and
 * stdin from `infile` (unchanged if NULL) -- the same dup2-around-
 * __spawn() technique test/sh-main.c's own run_sh() uses, extended
 * with the third descriptor since at(1p)/batch(1p)/crontab(1p) all
 * read their job body from standard input. Waits for the child and
 * returns its exit status (or -1 if it could not even be spawned). */
static int run3(const char *path, char *const *args, const char *infile)
{
	int out, err, in = -1;
	int s0 = -1, s1, s2, pid, status;

	out = open(OUTFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	err = open(ERRFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (out < 0 || err < 0) { if (out >= 0) close(out); if (err >= 0) close(err); return -1; }
	if (infile) {
		in = open(infile, O_RDONLY);
		if (in < 0) { close(out); close(err); return -1; }
	}

	s1 = dup(1); s2 = dup(2);
	if (infile) s0 = dup(0);
	dup2(out, 1);
	dup2(err, 2);
	if (infile) dup2(in, 0);
	close(out); close(err);
	if (infile) close(in);

	pid = __spawn(path, args, environ);

	dup2(s1, 1); close(s1);
	dup2(s2, 2); close(s2);
	if (infile) { dup2(s0, 0); close(s0); }

	if (pid < 0) return -1;
	if (waitpid(pid, &status, 0) != pid) return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static int run(const char *path, char *const *args)
{
	return run3(path, args, 0);
}

static int write_file(const char *path, const char *content)
{
	FILE *f = fopen(path, "w");
	if (!f) return -1;
	if (fputs(content, f) == EOF) { fclose(f); return -1; }
	return fclose(f) == 0 ? 0 : -1;
}

static int slurp_into(const char *path, char *buf, size_t buflen)
{
	FILE *f = fopen(path, "rb");
	size_t n;
	if (!f) { buf[0] = 0; return -1; }
	n = fread(buf, 1, buflen - 1, f);
	buf[n] = 0;
	fclose(f);
	return 0;
}

static int err_contains(const char *needle)
{
	char buf[4096];
	slurp_into(ERRFILE, buf, sizeof buf);
	return strstr(buf, needle) != 0;
}

static int out_contains(const char *needle)
{
	char buf[4096];
	slurp_into(OUTFILE, buf, sizeof buf);
	return strstr(buf, needle) != 0;
}

/* Bounded poll for a marker file a scheduled job is expected to
 * create -- real synchronization on the daemon's own observable
 * effect, never a fixed sleep racing it (this file's own header calls
 * this out explicitly). Polls every 100ms up to max_ms; returns 1 if
 * the file appeared, 0 on timeout. */
static int wait_for_file(const char *path, long max_ms)
{
	long waited = 0;
	struct stat st;
	while (waited < max_ms) {
		if (stat(path, &st) == 0) return 1;
		usleep(100000);
		waited += 100;
	}
	return stat(path, &st) == 0;
}

static int spawn_daemon(const char *path)
{
	char *argv[] = { (char *)path, 0 };
	return __spawn(path, argv, environ);
}

static void stop_daemon(int pid)
{
	int status;
	if (pid < 0) return;
	kill(pid, SIGTERM);
	waitpid(pid, &status, 0);
}

static char at_path[1024], batch_path[1024], crontab_path[1024];
static char atd_path[1024], crond_path[1024], sh_path[1024];
static char home_dir[1024];

/* ==== at(1p) + atd ======================================================= */

static int at_remove(const char *id)
{
	char *argv[] = { (char *)"at", (char *)"-r", (char *)id, 0 };
	return run(at_path, argv);
}

static void test_at_dash_t_and_atd_runs_it(void)
{
	time_t now = time(0);
	time_t due = now + 3;
	struct tm *tmv = localtime(&due);
	char tspec[32];
	char marker[1024];
	char job_body[2048];
	int pid;

	CHECK(tmv != 0);
	if (!tmv) return;
	strftime(tspec, sizeof tspec, "%Y%m%d%H%M.%S", tmv);

	snprintf(marker, sizeof marker, "%s/at-marker.txt", home_dir);
	unlink(marker);
	snprintf(job_body, sizeof job_body, "echo atran > '%s'\n", marker);
	CHECK(write_file("at-job-body.txt", job_body) == 0);

	{
		char *argv[] = { (char *)"at", (char *)"-t", tspec, 0 };
		CHECK(run3(at_path, argv, "at-job-body.txt") == 0);
	}
	CHECK(err_contains("job "));

	setenv("SPICULE_ATD_POLL_MS", "200", 1);
	pid = spawn_daemon(atd_path);
	CHECK(pid >= 0);

	CHECK(wait_for_file(marker, 9000));
	{
		char buf[256];
		slurp_into(marker, buf, sizeof buf);
		CHECK(strcmp(buf, "atran\n") == 0);
	}

	/* batch(1p) shares the same atd instance and queue-b load gate --
	 * exercised here while atd is already up, to avoid a second
	 * multi-second daemon-startup wait. */
	{
		char marker2[1024];
		snprintf(marker2, sizeof marker2, "%s/batch-marker.txt", home_dir);
		unlink(marker2);
		{
			char body2[2048];
			snprintf(body2, sizeof body2, "echo batchran > '%s'\n", marker2);
			CHECK(write_file("batch-job-body.txt", body2) == 0);
		}
		{
			char *argv[] = { (char *)"batch", 0 };
			CHECK(run3(batch_path, argv, "batch-job-body.txt") == 0);
		}
		CHECK(err_contains("job "));
		CHECK(wait_for_file(marker2, 9000));
		{
			char buf[256];
			slurp_into(marker2, buf, sizeof buf);
			CHECK(strcmp(buf, "batchran\n") == 0);
		}
	}

	stop_daemon(pid);
}

static void test_at_dash_l_and_dash_r(void)
{
	time_t due = time(0) + 3600; /* an hour out -- never actually due during this test */
	struct tm *tmv = localtime(&due);
	char tspec[32];
	char stdout_buf[4096];

	CHECK(tmv != 0);
	if (!tmv) return;
	strftime(tspec, sizeof tspec, "%Y%m%d%H%M.%S", tmv);
	CHECK(write_file("at-noop-body.txt", "true\n") == 0);

	{
		char *argv[] = { (char *)"at", (char *)"-t", tspec, 0 };
		CHECK(run3(at_path, argv, "at-noop-body.txt") == 0);
	}
	slurp_into(ERRFILE, stdout_buf, sizeof stdout_buf);
	{
		/* "job <id> at ..." -- pull the id out to remove it below. */
		char id[64];
		const char *p = strstr(stdout_buf, "job ");
		CHECK(p != 0);
		if (p) {
			p += 4;
			{
				size_t n = strcspn(p, " ");
				if (n >= sizeof id) n = sizeof id - 1;
				memcpy(id, p, n);
				id[n] = 0;
			}
			{
				char *argv[] = { (char *)"at", (char *)"-l", 0 };
				CHECK(run(at_path, argv) == 0);
				CHECK(out_contains(id));
			}
			CHECK(at_remove(id) == 0);
			CHECK(at_remove(id) != 0); /* already removed */
			CHECK(err_contains("no such job"));
		}
	}
}

/* ==== crontab(1p) ========================================================= */

/* Every crontab(1p) invocation below takes exactly one operand -- fold
 * the repeated "build a 1-operand argv[], run it" shape into one
 * helper; each call site still does its own exit-status/output checks,
 * since those differ from one call to the next. */
static int crontab1(const char *arg)
{
	char *argv[] = { (char *)"crontab", (char *)arg, 0 };
	return run(crontab_path, argv);
}

static void test_crontab_install_list_remove(void)
{
	CHECK(write_file("crontab-src.txt", "0 0 1 1 * echo placeholder\n") == 0);
	CHECK(crontab1("crontab-src.txt") == 0);
	CHECK(crontab1("-l") == 0);
	CHECK(out_contains("echo placeholder"));
	CHECK(crontab1("-r") == 0);
	CHECK(crontab1("-l") != 0);
	CHECK(err_contains("no crontab"));
}

static void test_crontab_rejects_bad_entry(void)
{
	CHECK(write_file("crontab-bad.txt", "not a real crontab line\n") == 0);
	CHECK(crontab1("crontab-bad.txt") != 0);
	/* the previous, valid crontab (if any) must be untouched --
	 * confirmed indirectly: -l still reports "no crontab" since
	 * test_crontab_install_list_remove() above already removed
	 * it and this bad install must not have installed anything
	 * in its place. */
	CHECK(crontab1("-l") != 0);
}

static void test_crontab_dash_e(void)
{
	CHECK(write_file("crontab-src2.txt", "0 0 1 1 * echo first\n") == 0);
	CHECK(crontab1("crontab-src2.txt") == 0);

	setenv("EDITOR", self_exe, 1);
	setenv("SPICULE_TEST_AS_EDITOR", "1", 1);
	CHECK(crontab1("-e") == 0);
	unsetenv("SPICULE_TEST_AS_EDITOR");

	CHECK(crontab1("-l") == 0);
	CHECK(out_contains("echo first"));
	CHECK(out_contains("echo appended-by-test-editor"));

	CHECK(crontab1("-r") == 0);
}

/* ==== crond =============================================================== */

static void test_crond_runs_a_due_entry(void)
{
	time_t now = time(0);
	time_t target = (now / 60 + 1) * 60; /* start of the next real minute */
	long lead_s;
	struct tm *tmv;
	char marker[1024];
	char entry[2048];
	int pid;

	if (target - now < 3) target += 60; /* avoid racing a too-close boundary */
	lead_s = (long)(target - now);
	tmv = localtime(&target);
	CHECK(tmv != 0);
	if (!tmv) return;

	snprintf(marker, sizeof marker, "%s/cron-marker.txt", home_dir);
	unlink(marker);
	snprintf(entry, sizeof entry, "%d %d * * * echo cronran > '%s'\n",
		tmv->tm_min, tmv->tm_hour, marker);
	CHECK(write_file("crontab-timed.txt", entry) == 0);
	CHECK(crontab1("crontab-timed.txt") == 0);

	setenv("SPICULE_CROND_POLL_MS", "500", 1);
	pid = spawn_daemon(crond_path);
	CHECK(pid >= 0);

	CHECK(wait_for_file(marker, (lead_s + 15) * 1000));
	{
		char buf[256];
		slurp_into(marker, buf, sizeof buf);
		CHECK(strcmp(buf, "cronran\n") == 0);
	}

	stop_daemon(pid);
	crontab1("-r");
}

static void cleanup_artifacts(void)
{
	unlink(OUTFILE);
	unlink(ERRFILE);
	unlink("at-job-body.txt");
	unlink("at-noop-body.txt");
	unlink("batch-job-body.txt");
	unlink("crontab-src.txt");
	unlink("crontab-src2.txt");
	unlink("crontab-bad.txt");
	unlink("crontab-timed.txt");
	/* Everything under $HOME/.spicule/{atjobs,crontabs}/ and the scratch home tree
	 * itself: best-effort, not exhaustive -- these are already
	 * confined under this test's own private scratch directory
	 * (never a real developer/CI home), so anything this leaves
	 * behind is cleaned up by tools/run-tests.py's own per-run
	 * temporary-directory teardown regardless. */
}

/* Editor stand-in mode: see this file's own header. Appends one fixed
 * valid crontab(5) line to argv[1] and exits. Never reached unless
 * SPICULE_TEST_AS_EDITOR is set, which only test_crontab_dash_e()
 * above ever sets before spawning this same binary as $EDITOR. */
static int run_as_editor(int argc, char **argv)
{
	FILE *f;
	if (argc < 2) return 1;
	f = fopen(argv[1], "a");
	if (!f) return 1;
	fputs("0 0 1 1 * echo appended-by-test-editor\n", f);
	return fclose(f) == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
	if (getenv("SPICULE_TEST_AS_EDITOR")) return run_as_editor(argc, argv);

	if (find_obj_root(argv[0]) != 0) {
		printf("SKIP util-atcron: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(at_path, sizeof at_path, "bin/at.exe");
	path_for(batch_path, sizeof batch_path, "bin/batch.exe");
	path_for(crontab_path, sizeof crontab_path, "bin/crontab.exe");
	path_for(atd_path, sizeof atd_path, "bin/atd.exe");
	path_for(crond_path, sizeof crond_path, "bin/crond.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(at_path, R_OK) != 0 || access(batch_path, R_OK) != 0 ||
	    access(crontab_path, R_OK) != 0 || access(atd_path, R_OK) != 0 ||
	    access(crond_path, R_OK) != 0 || access(sh_path, R_OK) != 0) {
		printf("SKIP util-atcron: one or more of the five utility binaries or sh is missing\n");
		return 77;
	}

	{
		char *cwd = getcwd(0, 0);
		if (!cwd) { printf("SKIP util-atcron: getcwd failed\n"); return 77; }
		snprintf(home_dir, sizeof home_dir, "%s/scratch-home", cwd);
		free(cwd);
	}
	/* Fresh scratch $HOME in case a previous run was interrupted
	 * before its own cleanup ran -- same reasoning as
	 * test/util-fsops.c's own rmtree_scratch() call before its first
	 * test. Only one level deep is ever created by this file, so a
	 * plain rmdir/mkdir pair (rather than a recursive remove) is
	 * enough -- __spool_dir() (src/util/spool.c) creates the rest
	 * (.spicule/, .spicule/atjobs/, .spicule/crontabs/) itself. */
	rmdir(home_dir);
	if (mkdir(home_dir, 0755) != 0 && errno != EEXIST) {
		printf("SKIP util-atcron: cannot create scratch home (%s)\n", strerror(errno));
		return 77;
	}
	setenv("HOME", home_dir, 1);
	/* sh(1p) needs a real shell to interpret job bodies -- PATH must
	 * include the directory atd/crond will search via
	 * __find_program("sh", 1) (src/util/atd.c's/crond.c's own header
	 * explains why they use a PATH search rather than a fixed path,
	 * matching every other spawning utility in this tree). obj/sh is
	 * a sibling of obj/bin under obj_root. */
	{
		char shdir[1024];
		char newpath[2048];
		const char *oldpath = getenv("PATH");
		char sep = strchr(obj_root, '\\') ? '\\' : '/';
		snprintf(shdir, sizeof shdir, "%s%csh", obj_root, sep);
		snprintf(newpath, sizeof newpath, "%s%c%s", shdir,
			strchr(obj_root, '\\') ? ';' : ':', oldpath ? oldpath : "");
		setenv("PATH", newpath, 1);
	}

	test_at_dash_t_and_atd_runs_it();
	test_at_dash_l_and_dash_r();
	test_crontab_install_list_remove();
	test_crontab_rejects_bad_entry();
	test_crontab_dash_e();
	test_crond_runs_a_due_entry();

	cleanup_artifacts();

	if (fails) { printf("util-atcron: failures: %d\n", fails); return 1; }
	printf("util-atcron: all ok (at, batch, crontab, atd, crond)\n");
	return 0;
}
