/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for ntlibc's first Tier-4 POSIX standard utilities
 * batch: `find`, `xargs`, `expr`, `ls` (XCU find(1p), xargs(1p),
 * expr(1p), ls(1p)).  Same technique as test/util-sortset.c: the
 * standalone obj/bin/<name>.exe is spawned as a real process (via
 * __spawn()+waitpid()), and the shell built-in is exercised too (via
 * obj/sh/sh.exe -c), confirming both callers of __util_<name>_main()
 * (src/internal/util.h) agree.
 *
 * A few choices specific to this file, beyond util-sortset.c's own
 * idiom:
 *
 *  - xargs needs its own standard input, not just captured stdout/
 *    stderr -- run_io() below is run() plus an optional third
 *    redirection, built once and reused for every xargs case rather
 *    than duplicated per test.
 *  - Every case that spawns a *further* child process (find's -exec,
 *    xargs's utility) passes that utility as an already-resolved
 *    absolute path (echo_path/false_path, computed by path_for() the
 *    same way sh_path etc. are) directly in an argv array, never
 *    embedded inside an `sh -c "..."` string -- an NT build's paths
 *    contain backslashes, and nothing about this project's sh parses a
 *    raw backslash-laden path safely inside -c source text (every
 *    existing test file's own run_sh_c() calls only ever embed plain
 *    scratch-relative forward-slash paths, never an executable's own
 *    path). The two builtin-vs-standalone agreement checks that
 *    genuinely need a further child (find -exec, xargs) are therefore
 *    exercised as direct __spawn() calls of the *shell itself* with a
 *    -c argv element built as a real argv string (not re-parsed by a
 *    shell a second time) rather than through run_sh_c()'s convenience
 *    wrapper -- see test_find_exec_builtin_matches_standalone() and
 *    test_xargs_matches_between_builtin_and_standalone().
 *  - This test binary is itself a cross-compiled x86_64-win32 PE image
 *    (same as every other obj/test/NAME.exe here) and this environment has
 *    no working Wine to run it in -- so, as with every prior POSIX-
 *    utility batch's own verification, `make obj/test/util-findls.exe`
 *    (a successful link) is the ceiling this file's own author could
 *    verify directly; the assertions below are written to be correct
 *    and low-fragility for whenever a Wine-capable CI leg does run it.
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

static int find_obj_root(const char *argv0)
{
	size_t n;
	size_t i;

	if (!argv0 || !*argv0) return -1;
	n = strlen(argv0);
	if (n >= sizeof obj_root) return -1;
	strcpy(obj_root, argv0);

	for (i = n; i > 0; i--)
		if (obj_root[i - 1] == '/' || obj_root[i - 1] == '\\') break;
	if (i == 0) return -1;
	obj_root[i - 1] = 0; /* strip "/util-findls.exe" */

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

#define OUTFILE "util-findls-out.txt"
#define ERRFILE "util-findls-err.txt"
#define INFILE  "util-findls-in.txt"

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

static void make_file(const char *path, const char *contents)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return;
	if (contents && *contents) write(fd, contents, strlen(contents));
	close(fd);
}

/* run(), plus stdin fed from `input` (a NUL-terminated string written to
 * INFILE first). */
static int run_io(const char *path, char *const *args, const char *input)
{
	int out, err, in;
	int s0, s1, s2, pid, status;

	out = open(OUTFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	err = open(ERRFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (out < 0 || err < 0) { if (out >= 0) close(out); if (err >= 0) close(err); return -1; }
	make_file(INFILE, input ? input : "");
	in = open(INFILE, O_RDONLY);
	if (in < 0) { close(out); close(err); return -1; }

	s0 = dup(0); s1 = dup(1); s2 = dup(2);
	dup2(in, 0);
	dup2(out, 1);
	dup2(err, 2);
	close(in); close(out); close(err);

	pid = __spawn(path, args, environ);

	dup2(s0, 0); close(s0);
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
	char buf[8192];
	slurp_into(OUTFILE, buf, sizeof buf);
	return strstr(buf, needle) != 0;
}

static int out_equals(const char *expect)
{
	char buf[8192];
	slurp_into(OUTFILE, buf, sizeof buf);
	return strcmp(buf, expect) == 0;
}

/* Checks a run's exit status against `want_status` and its stdout against
 * `want_out` exactly -- the shape shared by nearly every expr/ls -d/xargs
 * test below. */
static void check_status_out_equals(int status, int want_status, const char *want_out)
{
	CHECK(status == want_status);
	CHECK(out_equals(want_out));
}

static char find_path[1024], xargs_path[1024], expr_path[1024], ls_path[1024];
static char echo_path[1024], false_path[1024], sh_path[1024];

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

/* ==== expr(1p) ============================================================ */

static void test_expr_arith(void)
{
	char *a[] = { (char *)"expr", (char *)"3", (char *)"+", (char *)"4", 0 };
	check_status_out_equals(run(expr_path, a), 0, "7\n");
}

/* '*' binds tighter than '+': a naive left-to-right evaluator without
 * real precedence would get 2+3=5, 5*4=20 instead of the correct 14. */
static void test_expr_precedence(void)
{
	char *a[] = { (char *)"expr", (char *)"2", (char *)"+", (char *)"3", (char *)"*", (char *)"4", 0 };
	check_status_out_equals(run(expr_path, a), 0, "14\n");
}

static void test_expr_zero_is_exit_1(void)
{
	char *a[] = { (char *)"expr", (char *)"0", 0 };
	check_status_out_equals(run(expr_path, a), 1, "0\n");
}

static void test_expr_zero_spellings(void)
{
	char *negative[] = { (char *)"expr", (char *)"-000", 0 };
	char *leading[] = { (char *)"expr", (char *)"000000000000000000000", 0 };
	char *large[] = { (char *)"expr", (char *)"999999999999999999999", 0 };
	check_status_out_equals(run(expr_path, negative), 1, "-000\n");
	check_status_out_equals(run(expr_path, leading), 1, "000000000000000000000\n");
	check_status_out_equals(run(expr_path, large), 0, "999999999999999999999\n");
}

static void test_expr_string_compare(void)
{
	char *eq[] = { (char *)"expr", (char *)"foo", (char *)"=", (char *)"foo", 0 };
	char *ne[] = { (char *)"expr", (char *)"foo", (char *)"=", (char *)"bar", 0 };
	check_status_out_equals(run(expr_path, eq), 0, "1\n");
	check_status_out_equals(run(expr_path, ne), 1, "0\n");
}

/* Lexicographic "10" < "9" as strings, but expr must treat both as
 * numeric candidates here and compare 10 > 9 arithmetically. */
static void test_expr_numeric_vs_lexicographic(void)
{
	char *a[] = { (char *)"expr", (char *)"10", (char *)">", (char *)"9", 0 };
	check_status_out_equals(run(expr_path, a), 0, "1\n");
}

static void test_expr_match_length(void)
{
	char *a[] = { (char *)"expr", (char *)"abc123", (char *)":", (char *)"[a-z]*", 0 };
	check_status_out_equals(run(expr_path, a), 0, "3\n");
}

static void test_expr_match_capture(void)
{
	char *a[] = { (char *)"expr", (char *)"abc123", (char *)":", (char *)"\\(a.c\\)", 0 };
	check_status_out_equals(run(expr_path, a), 0, "abc\n");
}

static void test_expr_or_and(void)
{
	char *or1[] = { (char *)"expr", (char *)"", (char *)"|", (char *)"fallback", 0 };
	char *and0[] = { (char *)"expr", (char *)"0", (char *)"&", (char *)"5", 0 };
	check_status_out_equals(run(expr_path, or1), 0, "fallback\n");
	check_status_out_equals(run(expr_path, and0), 1, "0\n");
}

static void test_expr_invalid_is_exit_2(void)
{
	char *a[] = { (char *)"expr", (char *)"(", (char *)"1", 0 };
	CHECK(run(expr_path, a) == 2);
}

/* Regression for a real stack-overflow bug: parse_primary()'s '(' case
 * (src/util/expr.c) recursed back into parse_or() -- and from there
 * straight down through parse_and()/parse_cmp()/parse_add()/parse_mul()/
 * parse_match()/parse_primary() again -- once per '(' operand, with no
 * depth cap of its own, the same recursion-without-a-depth-cap bug class
 * already fixed in src/util/m4.c's eval() (M4_EVAL_MAX_DEPTH) and
 * src/util/awk_parse.c's parser. Since expr(1p) walks argv directly
 * (this file's own header, and expr.c's), a caller need not go through
 * any shell expression-length limit at all -- passing enough separate
 * "(" operands in argv is enough on its own. This builds an argv with
 * more '(' operands than EXPR_MAX_DEPTH (src/util/expr.c) and checks
 * only that expr now fails the expression cleanly (exit 2, "the
 * expression is invalid") instead of dying to a signal (run() folds a
 * signal death into 128+signum, e.g. 139 for SIGSEGV, which is
 * unmistakably not the plain 2 a clean depth-cap error exits with). */
static void test_expr_deep_nesting_does_not_crash(void)
{
	enum { N = 5000 };
	char **argv = malloc((size_t)(2 * N + 3) * sizeof *argv);
	int i, n = 0;

	if (!argv) { fails++; printf("FAIL: out of memory building deep-nesting argv\n"); return; }
	argv[n++] = (char *)"expr";
	for (i = 0; i < N; i++) argv[n++] = (char *)"(";
	argv[n++] = (char *)"1";
	for (i = 0; i < N; i++) argv[n++] = (char *)")";
	argv[n] = 0;

	CHECK(run(expr_path, argv) == 2);
	free(argv);
}

/* Regression for a real silent-wrong-answer bug: is_num_candidate()
 * (src/util/expr.c) accepts any all-digit string as a numeric operand
 * with no length limit, but do_arith() fed that string straight to
 * strtol() without checking errno -- strtol() does not fail on a value
 * too large for `long`, it silently clamps to LONG_MAX and sets
 * errno=ERANGE. Before this was fixed, "expr <30 nines> - 1" silently
 * printed LONG_MAX-1 (a plausible-looking but wrong answer) instead of
 * reporting the literal could not actually be represented; now it's
 * treated as the same "overflow" error the operator-level checks
 * already report for a real `long` overflow. */
static void test_expr_arith_overflow_on_huge_literal(void)
{
	char *a[] = { (char *)"expr", (char *)"999999999999999999999999999999",
		(char *)"-", (char *)"1", 0 };
	CHECK(run(expr_path, a) == 2);
	CHECK(err_contains("overflow"));
}

/* ==== find(1p) ============================================================= */

static void mkscratch_tree(void)
{
	mkdir("scratch", 0755);
	mkdir("scratch/t", 0755);
	mkdir("scratch/t/sub", 0755);
	mkdir("scratch/t/prune_me", 0755);
	make_file("scratch/t/a.txt", "hello\n");
	make_file("scratch/t/b.log", "world\n");
	make_file("scratch/t/sub/c.txt", "nested\n");
	make_file("scratch/t/prune_me/inside.txt", "should not be seen when pruned\n");
}

static void test_find_name(void)
{
	char *a[] = { (char *)"find", (char *)"scratch/t", (char *)"-name", (char *)"*.txt", 0 };
	CHECK(run(find_path, a) == 0);
	CHECK(out_contains("a.txt"));
	CHECK(out_contains("c.txt"));
	CHECK(!out_contains("b.log"));
}

static void test_find_type_d(void)
{
	char *a[] = { (char *)"find", (char *)"scratch/t", (char *)"-type", (char *)"d", 0 };
	CHECK(run(find_path, a) == 0);
	CHECK(out_contains("sub"));
	CHECK(out_contains("prune_me"));
	CHECK(!out_contains("a.txt"));
}

/* -prune: the directory itself is still visited (and matched by
 * -name prune_me), but nothing *inside* it should ever be reported --
 * exercising find.c's own "pruned prefix filter" design (see that
 * file's header comment on why it is not a direct nftw() return code). */
static void test_find_prune(void)
{
	char *a[] = { (char *)"find", (char *)"scratch/t", (char *)"-name", (char *)"prune_me",
	              (char *)"-prune", (char *)"-o", (char *)"-name", (char *)"*.txt", (char *)"-print", 0 };
	CHECK(run(find_path, a) == 0);
	CHECK(!out_contains("inside.txt"));
	CHECK(out_contains("a.txt"));
	CHECK(out_contains("c.txt"));
}

/* '!' (highest precedence) combined with the implicit-AND rule: files
 * that do NOT match *.txt, restricted to plain files. */
static void test_find_not(void)
{
	char *a[] = { (char *)"find", (char *)"scratch/t", (char *)"!", (char *)"-name", (char *)"*.txt",
	              (char *)"-type", (char *)"f", 0 };
	CHECK(run(find_path, a) == 0);
	CHECK(out_contains("b.log"));
	CHECK(!out_contains("a.txt"));
	CHECK(!out_contains("c.txt"));
}

/* Explicit grouping: ( -name a -o -name b ) -a -type f. */
static void test_find_grouping(void)
{
	char *a[] = { (char *)"find", (char *)"scratch/t", (char *)"(", (char *)"-name", (char *)"a.txt",
	              (char *)"-o", (char *)"-name", (char *)"b.log", (char *)")", (char *)"-type", (char *)"f", 0 };
	CHECK(run(find_path, a) == 0);
	CHECK(out_contains("a.txt"));
	CHECK(out_contains("b.log"));
	CHECK(!out_contains("c.txt"));
}

static void test_find_exec_semicolon(void)
{
	char *a[] = { (char *)"find", (char *)"scratch/t", (char *)"-name", (char *)"a.txt",
	              (char *)"-exec", echo_path, (char *)"MATCHED", (char *)"{}", (char *)";", 0 };
	CHECK(run(find_path, a) == 0);
	CHECK(out_contains("MATCHED"));
	CHECK(out_contains("a.txt"));
}

static void test_find_nonexistent_path_is_error(void)
{
	char *a[] = { (char *)"find", (char *)"scratch/t/does-not-exist-xyz", 0 };
	CHECK(run(find_path, a) != 0);
}

/* Exercises find's -exec plumbing (real child spawn) as both the
 * standalone executable and the shell built-in, via a single `sh -c`
 * argv element that sh itself parses only once -- see this file's
 * header comment on why an executable path is never embedded inside a
 * *second* round of shell parsing. */
static void test_find_exec_builtin_matches_standalone(void)
{
	char cmd[1024];
	char *sh_argv[4];
	int standalone_status, builtin_status;
	char standalone_out[512], builtin_out[512];

	{
		char *a[] = { (char *)"find", (char *)"scratch/t", (char *)"-name", (char *)"a.txt",
		              (char *)"-exec", echo_path, (char *)"HIT", (char *)"{}", (char *)";", 0 };
		standalone_status = run(find_path, a);
		slurp_into(OUTFILE, standalone_out, sizeof standalone_out);
	}

	snprintf(cmd, sizeof cmd, "find scratch/t -name a.txt -exec %s HIT \"{}\" \\;", echo_path);
	sh_argv[0] = (char *)"sh"; sh_argv[1] = (char *)"-c"; sh_argv[2] = cmd; sh_argv[3] = 0;
	builtin_status = run(sh_path, sh_argv);
	slurp_into(OUTFILE, builtin_out, sizeof builtin_out);

	CHECK(standalone_status == builtin_status);
	CHECK(!strcmp(standalone_out, builtin_out));
	CHECK(strstr(builtin_out, "HIT") != 0);
}

/* ==== xargs(1p) ============================================================ */

static void test_xargs_basic(void)
{
	char *a[] = { (char *)"xargs", echo_path, 0 };
	check_status_out_equals(run_io(xargs_path, a, "a b c\n"), 0, "a b c\n");
}

/* Quoting per the Guideline grammar: "a b" is one token, distinct from
 * the two bare tokens a and b that -n 1 below splits on. */
static void test_xargs_quoting(void)
{
	char *a[] = { (char *)"xargs", echo_path, 0 };
	check_status_out_equals(run_io(xargs_path, a, "\"a b\" c\n"), 0, "a b c\n");
}

static void test_xargs_dash_n(void)
{
	char *a[] = { (char *)"xargs", (char *)"-n", (char *)"1", echo_path, 0 };
	check_status_out_equals(run_io(xargs_path, a, "a b c\n"), 0, "a\nb\nc\n");
}

/* -I: one invocation per input line, substituting into the template. */
static void test_xargs_dash_I(void)
{
	char *a[] = { (char *)"xargs", (char *)"-I", (char *)"{}", echo_path, (char *)"pre-{}-post", 0 };
	check_status_out_equals(run_io(xargs_path, a, "X\nY\n"), 0, "pre-X-post\npre-Y-post\n");
}

static void test_xargs_nonzero_utility_exit(void)
{
	char *a[] = { (char *)"xargs", false_path, 0 };
	CHECK(run_io(xargs_path, a, "x\n") != 0);
}

static void test_xargs_empty_input_is_a_no_op(void)
{
	char *a[] = { (char *)"xargs", echo_path, 0 };
	check_status_out_equals(run_io(xargs_path, a, ""), 0, "");
}

/* Exercises xargs's real child-spawning path as both the standalone
 * executable and the shell built-in.  Piping stdin *within* one `sh -c`
 * script avoids ever redirecting this test process's own stdin into
 * sh.exe (see run_io()'s own comment on why an executable path is never
 * embedded in a second round of shell parsing -- the same reasoning
 * applies here to not needing run_io() at all: the input is generated
 * inside the script by echo, not fed from outside it). */
static void test_xargs_matches_between_builtin_and_standalone(void)
{
	char cmd[1024];
	char *sh_argv[4];
	int standalone_status, builtin_status;
	char standalone_out[512], builtin_out[512];

	{
		char *a[] = { (char *)"xargs", (char *)"-n", (char *)"1", echo_path, 0 };
		standalone_status = run_io(xargs_path, a, "one two\n");
		slurp_into(OUTFILE, standalone_out, sizeof standalone_out);
	}

	snprintf(cmd, sizeof cmd, "echo one two | xargs -n 1 %s", echo_path);
	sh_argv[0] = (char *)"sh"; sh_argv[1] = (char *)"-c"; sh_argv[2] = cmd; sh_argv[3] = 0;
	builtin_status = run(sh_path, sh_argv);
	slurp_into(OUTFILE, builtin_out, sizeof builtin_out);

	CHECK(standalone_status == builtin_status);
	CHECK(!strcmp(standalone_out, builtin_out));
	CHECK(!strcmp(standalone_out, "one\ntwo\n"));
}

/* ==== ls(1p) ================================================================ */

static void test_ls_default(void)
{
	char *a[] = { (char *)"ls", (char *)"scratch/t", 0 };
	CHECK(run(ls_path, a) == 0);
	CHECK(out_contains("a.txt"));
	CHECK(out_contains("b.log"));
	CHECK(out_contains("sub"));
	CHECK(out_contains("prune_me"));
}

static void test_ls_dash_a(void)
{
	char *a[] = { (char *)"ls", (char *)"-a", (char *)"scratch/t", 0 };
	CHECK(run(ls_path, a) == 0);
	CHECK(out_contains(".\n") || out_contains(".\r\n"));
	CHECK(out_contains("..\n") || out_contains("..\r\n"));
}

static void test_ls_dash_l(void)
{
	char *a[] = { (char *)"ls", (char *)"-l", (char *)"scratch/t", 0 };
	CHECK(run(ls_path, a) == 0);
	CHECK(out_contains("a.txt"));
	CHECK(out_contains("sub"));
}

static void test_ls_dash_R(void)
{
	char *a[] = { (char *)"ls", (char *)"-R", (char *)"scratch/t", 0 };
	CHECK(run(ls_path, a) == 0);
	CHECK(out_contains("c.txt"));
}

/* -d: the operand itself, not its contents. */
static void test_ls_dash_d(void)
{
	char *a[] = { (char *)"ls", (char *)"-d", (char *)"scratch/t", 0 };
	check_status_out_equals(run(ls_path, a), 0, "scratch/t\n");
}

static void test_ls_nonexistent_is_error(void)
{
	char *a[] = { (char *)"ls", (char *)"scratch/t/does-not-exist-xyz", 0 };
	CHECK(run(ls_path, a) != 0);
	CHECK(err_contains("scratch/t/does-not-exist-xyz"));
}

/* ==== the shell built-ins agree with the standalone executables (the
 * cases below need no further child process, so run_sh_c() is safe). */

static void test_builtins_match_standalone(void)
{
	check_status_out_equals(run_sh_c("expr 6 \\* 7"), 0, "42\n");

	CHECK(run_sh_c("find scratch/t -name a.txt") == 0);
	CHECK(out_contains("a.txt"));

	check_status_out_equals(run_sh_c("ls -d scratch/t"), 0, "scratch/t\n");
}

/* ==== scratch directory setup/teardown ===================================== */

static void rmtree_scratch(void)
{
	unlink("scratch/t/a.txt");
	unlink("scratch/t/b.log");
	unlink("scratch/t/sub/c.txt");
	unlink("scratch/t/prune_me/inside.txt");
	rmdir("scratch/t/sub");
	rmdir("scratch/t/prune_me");
	rmdir("scratch/t");
	rmdir("scratch");
}

static void cleanup_artifacts(void)
{
	unlink(OUTFILE);
	unlink(ERRFILE);
	unlink(INFILE);
	rmtree_scratch();
}

int main(int argc, char **argv)
{
	(void)argc;

	if (find_obj_root(argv[0]) != 0) {
		printf("SKIP util-findls: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(find_path, sizeof find_path, "bin/find.exe");
	path_for(xargs_path, sizeof xargs_path, "bin/xargs.exe");
	path_for(expr_path, sizeof expr_path, "bin/expr.exe");
	path_for(ls_path, sizeof ls_path, "bin/ls.exe");
	path_for(echo_path, sizeof echo_path, "bin/echo.exe");
	path_for(false_path, sizeof false_path, "bin/false.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(find_path, R_OK) != 0 || access(xargs_path, R_OK) != 0 ||
	    access(expr_path, R_OK) != 0 || access(ls_path, R_OK) != 0 ||
	    access(echo_path, R_OK) != 0 || access(false_path, R_OK) != 0 ||
	    access(sh_path, R_OK) != 0) {
		printf("SKIP util-findls: one or more of the four utility binaries, echo/false, or sh is missing\n");
		return 77;
	}

	rmtree_scratch();
	mkscratch_tree();

	test_expr_arith();
	test_expr_precedence();
	test_expr_zero_is_exit_1();
	test_expr_zero_spellings();
	test_expr_string_compare();
	test_expr_numeric_vs_lexicographic();
	test_expr_match_length();
	test_expr_match_capture();
	test_expr_or_and();
	test_expr_invalid_is_exit_2();
	test_expr_deep_nesting_does_not_crash();
	test_expr_arith_overflow_on_huge_literal();

	test_find_name();
	test_find_type_d();
	test_find_prune();
	test_find_not();
	test_find_grouping();
	test_find_exec_semicolon();
	test_find_nonexistent_path_is_error();
	test_find_exec_builtin_matches_standalone();

	test_xargs_basic();
	test_xargs_quoting();
	test_xargs_dash_n();
	test_xargs_dash_I();
	test_xargs_nonzero_utility_exit();
	test_xargs_empty_input_is_a_no_op();
	test_xargs_matches_between_builtin_and_standalone();

	test_ls_default();
	test_ls_dash_a();
	test_ls_dash_l();
	test_ls_dash_R();
	test_ls_dash_d();
	test_ls_nonexistent_is_error();

	test_builtins_match_standalone();

	cleanup_artifacts();

	if (fails) { printf("util-findls: failures: %d\n", fails); return 1; }
	printf("util-findls: all ok (find, xargs, expr, ls -- standalone and builtin)\n");
	return 0;
}
