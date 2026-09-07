/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for spicule's terminal-control utilities: stty(1p)
 * and tty(1p) (src/util/stty.c, src/util/tty.c). Same technique as
 * test/util-timeutil.c: the standalone obj/bin/<name>.exe is spawned
 * as a real process (via __spawn()+waitpid()), and the shell built-in
 * is exercised too (via obj/sh/sh.exe -c), confirming both callers of
 * __util_<name>_main() (src/internal/util.h) agree.
 *
 * Every case below runs with standard input NOT a terminal --
 * tools/run-tests.py's harness redirects stdin from /dev/null for
 * every test, the same fact test/posix-termios.c's own header comment
 * documents and works around by opening /dev/tty directly. This file
 * does not: stty(1p)/tty(1p) both operate on fd 0 specifically (never
 * an operand of their own -- stty.html's own RATIONALE: "usage of
 * standard input is required"), so there is no fd this file could
 * substitute in instead, and there is no real console reachable at
 * all under the Wine test runner (test/posix-termios.c's own comment)
 * or -- a separate, pre-existing, out-of-scope-here gap -- under a
 * native Linux build, whose own plat_fd_init.c never classifies a
 * real tty/pty as __FD_CONSOLE in the first place (only __FD_CHAR),
 * so isatty()/tcgetattr() are honestly ENOTTY there regardless of what
 * is actually attached to fd 0. Every test here therefore exercises
 * exactly what IS deterministic without a real console:
 *
 *  - tty's whole "not a tty" / exit-1 path (tty.html's own EXIT
 *    STATUS), plus -s and its own usage-error path.
 *  - stty's full argument-parsing/validation logic, which -- by this
 *    file's own src/util/stty.c design (see that file's header
 *    comment) -- runs entirely before the first tcgetattr() call, so
 *    every parse error (unrecognized operand, missing value, invalid
 *    number, -a/-g combined with an operand, a malformed '-g'-style
 *    restore token) is reached and checked the same way whether or
 *    not fd 0 is really a terminal. What is NOT checked here is
 *    whether a *successful* parse's settings are actually applied --
 *    that needs a real console this harness never has, the same
 *    documented gap test/posix-termios.c already carries.
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

/* Same walk-up-from-argv[0] technique as test/util-timeutil.c's
 * find_obj_root(), copied rather than shared for the same reason that
 * file gives. */
static int find_obj_root(const char *argv0)
{
	size_t n;
	char *p;

	if (!argv0 || !*argv0) return -1;
	n = strlen(argv0);
	if (n >= sizeof obj_root) return -1;
	strcpy(obj_root, argv0);

	for (p = obj_root + n; p > obj_root; p--)
		if (p[-1] == '/' || p[-1] == '\\') break;
	if (p == obj_root) return -1;
	p[-1] = 0; /* strip "/util-ttyctl.exe" */

	for (p = obj_root + strlen(obj_root); p > obj_root; p--)
		if (p[-1] == '/' || p[-1] == '\\') break;
	if (p == obj_root) return -1;
	p[-1] = 0; /* strip "/test" */

	return 0;
}

static void path_for(char *out, size_t outlen, const char *rel)
{
	char sep = strchr(obj_root, '\\') ? '\\' : '/';
	char relcopy[256], *p;

	strncpy(relcopy, rel, sizeof relcopy - 1);
	relcopy[sizeof relcopy - 1] = 0;
	if (sep == '\\')
		for (p = relcopy; *p; p++) if (*p == '/') *p = '\\';
	snprintf(out, outlen, "%s%c%s", obj_root, sep, relcopy);
}

#define OUTFILE "util-ttyctl-out.txt"
#define ERRFILE "util-ttyctl-err.txt"

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

static int out_contains(const char *needle)
{
	char buf[4096];
	slurp_into(OUTFILE, buf, sizeof buf);
	return strstr(buf, needle) != 0;
}

static int out_is_empty(void)
{
	char buf[4096];
	slurp_into(OUTFILE, buf, sizeof buf);
	return buf[0] == 0;
}

static char stty_path[1024], tty_path[1024], sh_path[1024];

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

/* ==== tty(1p) ============================================================= */

/* No real console on fd 0 under this harness (this file's header
 * comment): tty.html's own "not a tty" / exit-1 bucket is exactly
 * what every plain invocation below must hit. */
static void test_tty_not_a_tty(void)
{
	char *argv[] = { (char *)"tty", 0 };
	CHECK(run(tty_path, argv) == 1);
	CHECK(out_contains("not a tty"));
}

static void test_tty_silent(void)
{
	char *argv[] = { (char *)"tty", (char *)"-s", 0 };
	CHECK(run(tty_path, argv) == 1);
	CHECK(out_is_empty());
}

static void test_tty_invalid_option(void)
{
	char *argv[] = { (char *)"tty", (char *)"bogus", 0 };
	CHECK(run(tty_path, argv) == 2);
	CHECK(err_contains("invalid option"));
}

/* ==== stty(1p): argument-parsing/validation (see this file's own
 * header comment for why this is what's checkable here) ================= */

/* stty's own ENOTTY failure (this file's header comment): every
 * argument-parsing case below that parses cleanly must reach this same
 * exit-1 "standard input" diagnostic rather than some parse error, so
 * it's checked through one helper instead of being repeated at each
 * call site. */
static void check_reaches_tty_check(char *const *argv)
{
	CHECK(run(stty_path, argv) == 1);
	CHECK(err_contains("standard input"));
}

static void test_stty_bare_not_a_tty(void)
{
	char *argv[] = { (char *)"stty", 0 };
	check_reaches_tty_check(argv);
}

static void test_stty_dash_a_not_a_tty(void)
{
	char *argv[] = { (char *)"stty", (char *)"-a", 0 };
	check_reaches_tty_check(argv);
}

static void test_stty_dash_g_not_a_tty(void)
{
	char *argv[] = { (char *)"stty", (char *)"-g", 0 };
	check_reaches_tty_check(argv);
}

static void test_stty_dash_a_combined_is_usage_error(void)
{
	/* SYNOPSIS's two forms ("stty [-a|-g]" vs "stty operand...") are
	 * mutually exclusive -- this must be refused before ever touching
	 * fd 0, so the diagnostic is the combination error, not "standard
	 * input". */
	char *argv[] = { (char *)"stty", (char *)"-a", (char *)"echo", 0 };
	CHECK(run(stty_path, argv) == 1);
	CHECK(err_contains("may not be combined"));
	CHECK(!err_contains("standard input"));
}

static void test_stty_valid_operand_reaches_tty_check(void)
{
	/* "echo" parses cleanly, so the failure must be the ENOTTY one,
	 * not a parse error -- proves valid operands are actually
	 * recognized rather than every case falling through to the same
	 * generic error. */
	char *argv[] = { (char *)"stty", (char *)"echo", 0 };
	check_reaches_tty_check(argv);
}

static void test_stty_unknown_operand(void)
{
	char *argv[] = { (char *)"stty", (char *)"frobnicate", 0 };
	CHECK(run(stty_path, argv) == 1);
	CHECK(err_contains("invalid argument"));
	CHECK(!err_contains("standard input"));
}

static void test_stty_unknown_charsize(void)
{
	/* cs9 doesn't exist (only cs5..cs8) and isn't a boolean flag or
	 * combination mode either -- must be the same parse-error bucket
	 * as an entirely made-up operand. */
	char *argv[] = { (char *)"stty", (char *)"cs9", 0 };
	CHECK(run(stty_path, argv) == 1);
	CHECK(err_contains("invalid argument"));
}

static void test_stty_ispeed_missing_value(void)
{
	char *argv[] = { (char *)"stty", (char *)"ispeed", 0 };
	CHECK(run(stty_path, argv) == 1);
	CHECK(err_contains("requires an argument"));
}

static void test_stty_ispeed_invalid_value(void)
{
	char *argv[] = { (char *)"stty", (char *)"ispeed", (char *)"notanumber", 0 };
	CHECK(run(stty_path, argv) == 1);
	CHECK(err_contains("invalid speed"));
}

static void test_stty_erase_missing_value(void)
{
	char *argv[] = { (char *)"stty", (char *)"erase", 0 };
	CHECK(run(stty_path, argv) == 1);
	CHECK(err_contains("requires an argument"));
}

static void test_stty_erase_invalid_value(void)
{
	/* Neither a single character, "^-"/"undef", nor a recognized "^c"
	 * pair -- three characters with no leading '^' at all. */
	char *argv[] = { (char *)"stty", (char *)"erase", (char *)"xyz", 0 };
	CHECK(run(stty_path, argv) == 1);
	CHECK(err_contains("invalid control character"));
}

static void test_stty_erase_valid_reaches_tty_check(void)
{
	char *argv[] = { (char *)"stty", (char *)"erase", (char *)"^H", 0 };
	check_reaches_tty_check(argv);
}

static void test_stty_min_out_of_range(void)
{
	/* c_cc[] entries are cc_t (unsigned char): 256 does not fit. */
	char *argv[] = { (char *)"stty", (char *)"min", (char *)"256", 0 };
	CHECK(run(stty_path, argv) == 1);
	CHECK(err_contains("invalid value"));
}

static void test_stty_bare_baud_reaches_tty_check(void)
{
	char *argv[] = { (char *)"stty", (char *)"9600", 0 };
	check_reaches_tty_check(argv);
}

static void test_stty_combination_modes_parse(void)
{
	/* raw, sane, ek, nl, evenp/parity, oddp and their '-' forms all
	 * parse cleanly -- every one below must reach the tty check, not
	 * a parse error, proving parse_operand()'s combination-mode
	 * branches are all actually reachable. */
	static const char *const words[] = {
		"raw", "-raw", "cooked", "sane", "ek", "nl", "-nl",
		"evenp", "parity", "oddp", "-parity", "tabs", "-tabs",
	};
	size_t i;
	for (i = 0; i < sizeof words / sizeof *words; i++) {
		char *argv[] = { (char *)"stty", (char *)words[i], 0 };
		check_reaches_tty_check(argv);
	}
}

/* A syntactically-close-but-wrong '-g'-style token (one field short of
 * this file's own 22-field encoding, src/util/stty.c's header comment)
 * must fall through to the ordinary "unrecognized operand" path, not
 * be silently accepted or crash on the short field count. */
static void test_stty_malformed_saved_settings(void)
{
	char *argv[] = { (char *)"stty",
		(char *)"4b00:5:cd6:8a3b:3:1c:7f:15:4:0:1:0:11:13:1a:0:12:f:17:16:0", 0 };
	CHECK(run(stty_path, argv) == 1);
	CHECK(err_contains("invalid argument"));
}

/* A well-formed 22-field saved-settings token as the sole operand IS
 * recognized (parse_saved() succeeds) -- it must reach tcsetattr()'s
 * own ENOTTY failure, not the generic parse-error path. */
static void test_stty_wellformed_saved_settings_reaches_tty_check(void)
{
	char *argv[] = { (char *)"stty",
		(char *)"4b00:5:cd6:8a3b:3:1c:7f:15:4:0:1:0:11:13:1a:0:12:f:17:16:0:0", 0 };
	check_reaches_tty_check(argv);
	CHECK(!err_contains("invalid argument"));
}

/* ==== the shell built-ins agree with the standalone executables ========== */

static void test_builtins_match_standalone(void)
{
	CHECK(run_sh_c("tty") == 1);
	CHECK(out_contains("not a tty"));

	CHECK(run_sh_c("stty") == 1);
	CHECK(err_contains("standard input"));

	CHECK(run_sh_c("stty frobnicate") == 1);
	CHECK(err_contains("invalid argument"));
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
		printf("SKIP util-ttyctl: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(stty_path, sizeof stty_path, "bin/stty.exe");
	path_for(tty_path, sizeof tty_path, "bin/tty.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(stty_path, R_OK) != 0 || access(tty_path, R_OK) != 0 ||
	    access(sh_path, R_OK) != 0) {
		printf("SKIP util-ttyctl: one or more of stty/tty or sh is missing\n");
		return 77;
	}

	test_tty_not_a_tty();
	test_tty_silent();
	test_tty_invalid_option();

	test_stty_bare_not_a_tty();
	test_stty_dash_a_not_a_tty();
	test_stty_dash_g_not_a_tty();
	test_stty_dash_a_combined_is_usage_error();
	test_stty_valid_operand_reaches_tty_check();
	test_stty_unknown_operand();
	test_stty_unknown_charsize();
	test_stty_ispeed_missing_value();
	test_stty_ispeed_invalid_value();
	test_stty_erase_missing_value();
	test_stty_erase_invalid_value();
	test_stty_erase_valid_reaches_tty_check();
	test_stty_min_out_of_range();
	test_stty_bare_baud_reaches_tty_check();
	test_stty_combination_modes_parse();
	test_stty_malformed_saved_settings();
	test_stty_wellformed_saved_settings_reaches_tty_check();

	test_builtins_match_standalone();

	cleanup_artifacts();

	if (fails) { printf("util-ttyctl: failures: %d\n", fails); return 1; }
	printf("util-ttyctl: all ok (stty, tty -- standalone and builtin)\n");
	return 0;
}
