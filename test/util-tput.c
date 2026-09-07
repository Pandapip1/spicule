/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for spicule's Tier 8 tput(1p) (src/util/tput.c) --
 * same technique as test/util-timeutil.c: the standalone
 * obj/bin/tput.exe is spawned as a real process (via __spawn()+
 * waitpid()), and the shell built-in is exercised too (via
 * obj/sh/sh.exe -c), confirming both callers of __util_tput_main()
 * (src/internal/util.h) agree.
 *
 * Exact expected byte strings below (e.g. xterm's clear ==
 * "\033[H\033[2J") are the same real capability strings src/util/tput.c's
 * own built-in table carries, copied here rather than re-derived --
 * this file is checking the implementation matches its own documented
 * table, not independently re-deriving terminal escape sequences.
 *
 * stdout/stderr are always redirected to a fixed file (never a real
 * tty) by this file's own run() helper below, so every `cols`/`lines`
 * case deterministically takes tput's ioctl(TIOCGWINSZ)-fails fallback
 * to its table's static value -- see src/util/tput.c's own header
 * comment on that ordering -- rather than depending on whatever
 * terminal (if any) actually ran this test binary.
 */
/* setenv()/unsetenv() below are gated behind _POSIX_SOURCE/
 * _POSIX_C_SOURCE/_XOPEN_SOURCE/_GNU_SOURCE/_BSD_SOURCE in spicule's own
 * include/stdlib.h, none of which a plain -std=c99 build defines on its
 * own. Same fix, same reasoning, as test/posix-stdlib.c's own
 * top-of-file _GNU_SOURCE define. */
#define _GNU_SOURCE
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
	p[-1] = 0; /* strip "/util-tput.exe" */

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

#define OUTFILE "util-tput-out.txt"
#define ERRFILE "util-tput-err.txt"

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

static int out_equals(const char *expect)
{
	char buf[4096];
	slurp_into(OUTFILE, buf, sizeof buf);
	return strcmp(buf, expect) == 0;
}

static int err_contains(const char *needle)
{
	char buf[4096];
	slurp_into(ERRFILE, buf, sizeof buf);
	return strstr(buf, needle) != 0;
}

static char tput_path[1024], sh_path[1024];

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

/* The "unspecified" bucket (this file's header comment / tput.html's own
 * "shall not be considered an error condition"): exit 1 and nothing
 * written to stdout. Every case below that lands here -- a terminal
 * missing one particular capability, or $TERM defaulting/blank -- checks
 * exactly this same pair, so it is folded into one helper rather than
 * repeated at each call site. */
static void check_unsupported(char *const *argv)
{
	CHECK(run(tput_path, argv) == 1);
	CHECK(out_equals(""));
}

/* ==== POSIX-mandated operands (clear/init/reset) ========================== */

static void test_clear_xterm(void)
{
	char *argv[] = { (char *)"tput", (char *)"-T", (char *)"xterm", (char *)"clear", 0 };
	CHECK(run(tput_path, argv) == 0);
	CHECK(out_equals("\033[H\033[2J"));
}

static void test_clear_vt100(void)
{
	char *argv[] = { (char *)"tput", (char *)"-T", (char *)"vt100", (char *)"clear", 0 };
	CHECK(run(tput_path, argv) == 0);
	CHECK(out_equals("\033[H\033[J"));
}

/* dumb has no clear sequence -- "unspecified" bucket (exit 1), not an
 * error the way an unknown terminal type or operand is; per tput.html's
 * own "shall not be considered an error condition" for a terminal that
 * lacks the capability, this implementation still distinguishes "ran
 * fine, nothing to write" from a hard failure via exit 1 rather than
 * silently claiming success while writing nothing. */
static void test_clear_dumb_unsupported(void)
{
	char *argv[] = { (char *)"tput", (char *)"-T", (char *)"dumb", (char *)"clear", 0 };
	check_unsupported(argv);
}

static void test_init_reset_always_succeed(void)
{
	char *argv1[] = { (char *)"tput", (char *)"-T", (char *)"xterm", (char *)"init", 0 };
	char *argv2[] = { (char *)"tput", (char *)"-T", (char *)"dumb", (char *)"reset", 0 };
	CHECK(run(tput_path, argv1) == 0);
	CHECK(out_equals(""));
	CHECK(run(tput_path, argv2) == 0);
	CHECK(out_equals(""));
}

/* ==== capname extension: numeric caps (cols/lines) ========================= */

static void test_cols_lines_xterm(void)
{
	char *argv1[] = { (char *)"tput", (char *)"-T", (char *)"xterm", (char *)"cols", 0 };
	char *argv2[] = { (char *)"tput", (char *)"-T", (char *)"xterm", (char *)"lines", 0 };
	CHECK(run(tput_path, argv1) == 0);
	CHECK(out_equals("80"));
	CHECK(run(tput_path, argv2) == 0);
	CHECK(out_equals("24"));
}

/* dumb's table entry defines cols but not lines (this file's header
 * comment / src/util/tput.c's own table -- matches the real terminfo
 * "dumb" entry, which genuinely has no lines# capability). */
static void test_cols_lines_dumb(void)
{
	char *argv1[] = { (char *)"tput", (char *)"-T", (char *)"dumb", (char *)"cols", 0 };
	char *argv2[] = { (char *)"tput", (char *)"-T", (char *)"dumb", (char *)"lines", 0 };
	CHECK(run(tput_path, argv1) == 0);
	CHECK(out_equals("80"));
	check_unsupported(argv2);
}

/* ==== capname extension: string caps ======================================= */

static void test_string_caps_xterm(void)
{
	struct { const char *cap; const char *expect; } cases[] = {
		{ "bold", "\033[1m" },
		{ "smso", "\033[7m" },
		{ "rmso", "\033[27m" },
		{ "smul", "\033[4m" },
		{ "rmul", "\033[24m" },
		{ "rev",  "\033[7m" },
		{ "sgr0", "\033(B\033[m" },
	};
	size_t i;
	for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		char *argv[] = { (char *)"tput", (char *)"-T", (char *)"xterm", (char *)cases[i].cap, 0 };
		CHECK(run(tput_path, argv) == 0);
		CHECK(out_equals(cases[i].expect));
	}
}

static void test_sgr0_differs_by_terminal(void)
{
	char *argv_vt100[] = { (char *)"tput", (char *)"-T", (char *)"vt100", (char *)"sgr0", 0 };
	char *argv_ansi[]  = { (char *)"tput", (char *)"-T", (char *)"ansi",  (char *)"sgr0", 0 };
	CHECK(run(tput_path, argv_vt100) == 0);
	CHECK(out_equals("\033[m\017"));
	CHECK(run(tput_path, argv_ansi) == 0);
	CHECK(out_equals("\033[0;10m"));
}

/* dumb has no string capabilities at all in this table. */
static void test_string_caps_dumb_unsupported(void)
{
	char *argv[] = { (char *)"tput", (char *)"-T", (char *)"dumb", (char *)"bold", 0 };
	check_unsupported(argv);
}

/* ==== capname extension: cup (cursor movement) ============================= */

/* 0-based input, 1-based ANSI output (this file's header comment and
 * src/util/tput.c's own header comment on the %i terminfo operator). */
static void test_cup_xterm(void)
{
	char *argv1[] = { (char *)"tput", (char *)"-T", (char *)"xterm", (char *)"cup", (char *)"0", (char *)"0", 0 };
	char *argv2[] = { (char *)"tput", (char *)"-T", (char *)"xterm", (char *)"cup", (char *)"4", (char *)"9", 0 };
	CHECK(run(tput_path, argv1) == 0);
	CHECK(out_equals("\033[1;1H"));
	CHECK(run(tput_path, argv2) == 0);
	CHECK(out_equals("\033[5;10H"));
}

static void test_cup_dumb_unsupported(void)
{
	char *argv[] = { (char *)"tput", (char *)"-T", (char *)"dumb", (char *)"cup", (char *)"0", (char *)"0", 0 };
	check_unsupported(argv);
}

static void test_cup_missing_operands(void)
{
	char *argv[] = { (char *)"tput", (char *)"-T", (char *)"xterm", (char *)"cup", (char *)"0", 0 };
	CHECK(run(tput_path, argv) == 2);
	CHECK(err_contains("requires row and column"));
}

static void test_cup_invalid_operands(void)
{
	char *argv[] = { (char *)"tput", (char *)"-T", (char *)"xterm", (char *)"cup", (char *)"x", (char *)"0", 0 };
	CHECK(run(tput_path, argv) == 2);
}

/* ==== error paths =========================================================== */

static void test_unknown_terminal_type(void)
{
	char *argv[] = { (char *)"tput", (char *)"-T", (char *)"no-such-terminal-xyz", (char *)"clear", 0 };
	CHECK(run(tput_path, argv) == 3);
	CHECK(err_contains("unknown terminal type"));
}

static void test_unknown_operand(void)
{
	char *argv[] = { (char *)"tput", (char *)"-T", (char *)"xterm", (char *)"not-a-real-capname", 0 };
	CHECK(run(tput_path, argv) == 4);
	CHECK(err_contains("invalid operand"));
}

static void test_missing_operand(void)
{
	char *argv[] = { (char *)"tput", (char *)"-T", (char *)"xterm", 0 };
	CHECK(run(tput_path, argv) == 2);
	CHECK(err_contains("missing operand"));
}

static void test_dash_t_missing_argument(void)
{
	char *argv[] = { (char *)"tput", (char *)"-T", 0 };
	CHECK(run(tput_path, argv) == 2);
	CHECK(err_contains("option requires an argument"));
}

/* -Ttype (no space) is also accepted -- src/util/tput.c's argument
 * scan handles both spellings. */
static void test_dash_t_no_space(void)
{
	char *argv[] = { (char *)"tput", (char *)"-Txterm", (char *)"cols", 0 };
	CHECK(run(tput_path, argv) == 0);
	CHECK(out_equals("80"));
}

/* ==== $TERM environment fallback and default ================================ */

static void test_term_env_used_when_no_dash_t(void)
{
	char *argv[] = { (char *)"tput", (char *)"clear", 0 };
	setenv("TERM", "vt100", 1);
	CHECK(run(tput_path, argv) == 0);
	CHECK(out_equals("\033[H\033[J"));
	unsetenv("TERM");
}

/* This implementation's own documented "unspecified default" is
 * "dumb" (src/util/tput.c's TERM_DEFAULT) when -T is absent and $TERM
 * is unset or null -- dumb has no clear sequence, so this must land in
 * the same "unspecified" (exit 1) bucket test_clear_dumb_unsupported()
 * above checks explicitly for -T dumb. */
static void test_term_default_when_unset(void)
{
	char *argv[] = { (char *)"tput", (char *)"clear", 0 };
	unsetenv("TERM");
	check_unsupported(argv);
}

static void test_term_default_when_empty(void)
{
	char *argv[] = { (char *)"tput", (char *)"clear", 0 };
	setenv("TERM", "", 1);
	check_unsupported(argv);
	unsetenv("TERM");
}

/* -T takes precedence over $TERM (DESCRIPTION quote in src/util/tput.c's
 * header comment). */
static void test_dash_t_overrides_term_env(void)
{
	char *argv[] = { (char *)"tput", (char *)"-T", (char *)"xterm", (char *)"clear", 0 };
	setenv("TERM", "vt100", 1);
	CHECK(run(tput_path, argv) == 0);
	CHECK(out_equals("\033[H\033[2J"));
	unsetenv("TERM");
}

/* ==== the shell built-in agrees with the standalone executable ============= */

static void test_builtin_matches_standalone(void)
{
	CHECK(run_sh_c("tput -T xterm clear") == 0);
	CHECK(out_equals("\033[H\033[2J"));

	CHECK(run_sh_c("tput -T dumb bold") == 1);
	CHECK(out_equals(""));

	CHECK(run_sh_c("tput -T no-such-terminal-xyz clear") == 3);

	CHECK(run_sh_c("tput -T xterm cup 4 9") == 0);
	CHECK(out_equals("\033[5;10H"));
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
		printf("SKIP util-tput: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(tput_path, sizeof tput_path, "bin/tput.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(tput_path, R_OK) != 0 || access(sh_path, R_OK) != 0) {
		printf("SKIP util-tput: tput or sh binary is missing\n");
		return 77;
	}

	test_clear_xterm();
	test_clear_vt100();
	test_clear_dumb_unsupported();
	test_init_reset_always_succeed();

	test_cols_lines_xterm();
	test_cols_lines_dumb();

	test_string_caps_xterm();
	test_sgr0_differs_by_terminal();
	test_string_caps_dumb_unsupported();

	test_cup_xterm();
	test_cup_dumb_unsupported();
	test_cup_missing_operands();
	test_cup_invalid_operands();

	test_unknown_terminal_type();
	test_unknown_operand();
	test_missing_operand();
	test_dash_t_missing_argument();
	test_dash_t_no_space();

	test_term_env_used_when_no_dash_t();
	test_term_default_when_unset();
	test_term_default_when_empty();
	test_dash_t_overrides_term_env();

	test_builtin_matches_standalone();

	cleanup_artifacts();

	if (fails) { printf("util-tput: failures: %d\n", fails); return 1; }
	printf("util-tput: all ok (tput -- standalone and builtin)\n");
	return 0;
}
