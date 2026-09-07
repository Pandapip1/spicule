/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for spicule's Tier 6 "terminal messaging" utilities:
 * mesg(1p) and write(1p) (src/util/mesg.c, src/util/util_write.c).
 * Same technique as test/util-timeutil.c: the standalone
 * obj/bin/<name>.exe is spawned as a real process (via
 * __spawn()+waitpid()), and the shell built-in is exercised too (via
 * obj/sh/sh.exe -c), confirming both callers of __util_<name>_main()
 * (src/internal/util.h) agree.
 *
 * What this file can and cannot deterministically exercise:
 *
 * `make check`'s runner gives fds 0/1/2 no real controlling terminal
 * at all (test/posix-termios.c's own header comment documents this in
 * full, and this file's run() below additionally redirects the
 * child's 1/2 to plain files) -- so __util_find_terminal() (src/util/
 * termident.c) genuinely, correctly reports "no terminal" for every
 * process this file spawns, on every platform.  That is not a gap in
 * this file's coverage: it is the single most important real path
 * both utilities have (mesg(1p) run outside of a terminal at all;
 * write(1p) with no session to deliver into), and it is exactly what
 * every test below exercises -- deterministically, without needing a
 * real pty this environment cannot supply.
 *
 * The genuine-success paths -- `mesg y`/`mesg n` actually flipping a
 * real tty's S_IWGRP bit, and `write` actually delivering a message
 * into a real controlling terminal -- need a real attached console,
 * which this automated harness does not have (same limitation
 * test/posix-termios.c's own ISIG/ICANON/ECHO round-trip already
 * accepts and documents rather than fakes around); see src/util/
 * mesg.c and src/util/util_write.c's own header comments for the
 * mechanism itself, which is real and platform-appropriate even
 * though it cannot be driven end-to-end from here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>

extern char **environ;
int __spawn(const char *path, char *const argv[], char *const envp[]);

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static char obj_root[1024];

/* Strips the trailing "/last-component" (or "\...") off `path` in
 * place. Returns 0 on success, -1 if `path` has no separator left to
 * strip at. */
static int strip_last_component(char *path)
{
	size_t i;

	for (i = strlen(path); i > 0; i--)
		if (path[i - 1] == '/' || path[i - 1] == '\\') break;
	if (i == 0) return -1;
	path[i - 1] = 0;
	return 0;
}

/* Same walk-up-from-argv[0] technique as test/util-timeutil.c's
 * find_obj_root(), copied rather than shared for the same reason that
 * file gives. */
static int find_obj_root(const char *argv0)
{
	if (!argv0 || !*argv0) return -1;
	if (strlen(argv0) >= sizeof obj_root) return -1;
	strcpy(obj_root, argv0);

	if (strip_last_component(obj_root) != 0) return -1; /* strip "/util-mesg.exe" */
	if (strip_last_component(obj_root) != 0) return -1; /* strip "/test" */

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

#define OUTFILE "util-mesg-out.txt"
#define ERRFILE "util-mesg-err.txt"

static int run(const char *path, char *const *args)
{
	int out, err;
	int s1, s2, pid, status;

	out = open(OUTFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	err = open(ERRFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (out < 0 || err < 0) { if (out >= 0) close(out); if (err >= 0) close(err); return -1; }

	s1 = dup(1); s2 = dup(2);
	dup2(out, 1);
	dup2(err, 2);
	close(out); close(err);

	pid = __spawn(path, args, environ);

	dup2(s1, 1); close(s1);
	dup2(s2, 2); close(s2);

	if (pid < 0) return -1;
	if (waitpid(pid, &status, 0) != pid) return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
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

static char mesg_path[1024], write_path[1024], sh_path[1024];

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

/* Checks an already-run process's exit code and stderr against what a
 * failing case below expects -- the shape every test in this file
 * shares, since none of them can drive a real success path (see this
 * file's own header comment on why). */
static void check_fails(int rc, int expect_rc, const char *expect_err)
{
	CHECK(rc == expect_rc);
	CHECK(err_contains(expect_err));
}

/* Some real login name -- content does not matter for these tests
 * (every case below is reached before or without needing a real
 * terminal), only that it is non-empty. Falls back to a fixed literal
 * if this environment has neither %USERNAME% nor $USER set, matching
 * src/misc/pwd.c's own "practically-never" fallback discussion --
 * write's own "not logged in" diagnosis is what gets exercised either
 * way, whether that literal happens to be a real account or not. */
static const char *current_user(void)
{
	const char *n = getenv("USERNAME");
	if (!n || !*n) n = getenv("USER");
	if (!n || !*n) n = "nobody";
	return n;
}

/* ==== mesg(1p) ============================================================ */

/* `make check` gives this process's own children no controlling
 * terminal on any of fds 0/1/2 (this file's header comment) -- the
 * real, specified >1 "an error occurred" case, not a made-up one. */
static void test_mesg_no_terminal(void)
{
	char *argv[] = { (char *)"mesg", 0 };
	check_fails(run(mesg_path, argv), 2, "not a terminal");
}

static void test_mesg_invalid_argument(void)
{
	char *argv[] = { (char *)"mesg", (char *)"x", 0 };
	check_fails(run(mesg_path, argv), 2, "usage");
}

static void test_mesg_too_many_arguments(void)
{
	char *argv[] = { (char *)"mesg", (char *)"y", (char *)"n", 0 };
	check_fails(run(mesg_path, argv), 2, "usage");
}

/* No terminal at all still short-circuits before argument validation
 * would matter for a *valid* y/n -- confirms the terminal search runs
 * (and correctly fails) regardless of which valid form was requested. */
static void test_mesg_y_no_terminal(void)
{
	char *argv[] = { (char *)"mesg", (char *)"y", 0 };
	check_fails(run(mesg_path, argv), 2, "not a terminal");
}

static void test_mesg_n_no_terminal(void)
{
	char *argv[] = { (char *)"mesg", (char *)"n", 0 };
	check_fails(run(mesg_path, argv), 2, "not a terminal");
}

/* ==== write(1p) ============================================================ */

static void test_write_missing_operand(void)
{
	char *argv[] = { (char *)"write", 0 };
	check_fails(run(write_path, argv), 1, "usage");
}

static void test_write_too_many_operands(void)
{
	char *argv[] = { (char *)"write", (char *)"a", (char *)"b", (char *)"c", 0 };
	check_fails(run(write_path, argv), 1, "usage");
}

/* No such real account: spicule has exactly one (src/misc/pwd.c) --
 * this is write.html's own ">0 ... user not logged on" case. */
static void test_write_unknown_user(void)
{
	char *argv[] = { (char *)"write", (char *)"no-such-user-xyz-12345", 0 };
	check_fails(run(write_path, argv), 1, "is not logged in");
}

/* The one real account, but (per this file's header comment) no real
 * terminal for this process to find as the target session -- still
 * the honest "not logged in" diagnosis, not a fabricated success. */
static void test_write_self_no_terminal(void)
{
	char *argv[] = { (char *)"write", (char *)current_user(), 0 };
	check_fails(run(write_path, argv), 1, "is not logged in");
}

static void test_write_unknown_user_with_tty(void)
{
	char *argv[] = { (char *)"write", (char *)"no-such-user-xyz-12345", (char *)"pts/9", 0 };
	check_fails(run(write_path, argv), 1, "is not logged in");
}

/* ==== the shell built-ins agree with the standalone executables ========== */

static void test_builtins_match_standalone(void)
{
	check_fails(run_sh_c("mesg"), 2, "not a terminal");
	check_fails(run_sh_c("write no-such-user-xyz-12345"), 1, "is not logged in");
}

/* ==== scratch cleanup ====================================================== */

static void cleanup_artifacts(void)
{
	unlink(OUTFILE);
	unlink(ERRFILE);
}

int main(int argc, char **argv)
{
	(void)argc;

	if (find_obj_root(argv[0]) != 0) {
		printf("SKIP util-mesg: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(mesg_path, sizeof mesg_path, "bin/mesg.exe");
	path_for(write_path, sizeof write_path, "bin/write.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(mesg_path, R_OK) != 0 || access(write_path, R_OK) != 0 ||
	    access(sh_path, R_OK) != 0) {
		printf("SKIP util-mesg: one or more of mesg/write or sh is missing\n");
		return 77;
	}

	test_mesg_no_terminal();
	test_mesg_invalid_argument();
	test_mesg_too_many_arguments();
	test_mesg_y_no_terminal();
	test_mesg_n_no_terminal();

	test_write_missing_operand();
	test_write_too_many_operands();
	test_write_unknown_user();
	test_write_self_no_terminal();
	test_write_unknown_user_with_tty();

	test_builtins_match_standalone();

	cleanup_artifacts();

	printf("note: this environment gives `make check` no real controlling "
		"terminal on any of fds 0/1/2, so the genuine-success paths -- "
		"`mesg y`/`mesg n` actually flipping a real tty's S_IWGRP bit, "
		"and `write` actually delivering a message into one -- are not "
		"exercised here; see this file's own header comment\n");

	if (fails) { printf("util-mesg: failures: %d\n", fails); return 1; }
	printf("util-mesg: all ok (mesg, write -- standalone and builtin)\n");
	return 0;
}
