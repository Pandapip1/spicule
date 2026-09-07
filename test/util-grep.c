/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for spicule's grep(1p) -- the first Tier 4 "bigger
 * engine" utility.  Same technique as test/util-sortset.c: the
 * standalone obj/bin/grep.exe is spawned as a real process (via
 * __spawn()+waitpid()), and the shell built-in is exercised too (via
 * obj/sh/sh.exe -c), confirming both callers of __util_grep_main()
 * (src/internal/util.h) agree.
 *
 * A few cases are specifically chosen to catch a subtly-wrong-but-
 * plausible implementation, not just exercise the happy path:
 *  - the ERE test uses `a+` -- a BRE `+` is a literal character, so a
 *    test file that ran an ERE pattern through a BRE-only matcher (or
 *    forgot to pass REG_EXTENDED) would silently get the wrong answer
 *    on ordinary-looking input rather than a compile error.
 *  - the -F test's pattern contains a real regex metacharacter (`.`)
 *    that would match extra, wrong lines if -F were silently ignored
 *    and the pattern were compiled as a regex instead of matched
 *    literally.
 *  - the multiple -e test checks that patterns really OR together
 *    (a line matching only the second -e must still be selected), not
 *    just that giving two -e options doesn't crash.
 *  - the three exit-status cases (0/1/>1) are checked individually,
 *    since scripts depend on grep's exit status distinguishing "no
 *    match" (1) from "a real error" (>1), not just "not success".
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

static int find_obj_root(const char *argv0)
{
	if (!argv0 || !*argv0) return -1;
	if (strlen(argv0) >= sizeof obj_root) return -1;
	strcpy(obj_root, argv0);

	if (strip_last_component(obj_root) != 0) return -1; /* strip "/util-grep.exe" */
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

#define OUTFILE "util-grep-out.txt"
#define ERRFILE "util-grep-err.txt"

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

static void make_file(const char *path, const char *contents)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return;
	if (contents && *contents) write(fd, contents, strlen(contents));
	close(fd);
}

static char grep_path[1024], sh_path[1024];

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

/* Runs grep_path with argv, checking it exited 0 with stdout exactly
 * equal to expect_out -- the shape most tests below share. */
static void check_ok(char *const *argv, const char *expect_out)
{
	CHECK(run(grep_path, argv) == 0);
	CHECK(out_equals(expect_out));
}

/* ==== grep(1p) ============================================================= */

static void test_grep_bre_basic(void)
{
	/* A BRE with a literal-char '+' (BRE has no unescaped '+'): the
	 * line "a+b" must match a bare "a+b" pattern exactly, character
	 * by character. */
	char *argv[] = { (char *)"grep", (char *)"a+b", (char *)"scratch/g1", 0 };
	make_file("scratch/g1", "xa+by\nnope\nzz\n");
	check_ok(argv, "xa+by\n");
}

static void test_grep_dash_v(void)
{
	char *argv[] = { (char *)"grep", (char *)"-v", (char *)"foo", (char *)"scratch/g2", 0 };
	make_file("scratch/g2", "foo\nbar\nfoobar\nbaz\n");
	check_ok(argv, "bar\nbaz\n");
}

static void test_grep_dash_i(void)
{
	char *argv[] = { (char *)"grep", (char *)"-i", (char *)"HELLO", (char *)"scratch/g3", 0 };
	make_file("scratch/g3", "hello world\nHELLO THERE\nnope\n");
	check_ok(argv, "hello world\nHELLO THERE\n");
}

static void test_grep_dash_c(void)
{
	char *argv[] = { (char *)"grep", (char *)"-c", (char *)"a", (char *)"scratch/g4", 0 };
	make_file("scratch/g4", "a\nb\na\na\nb\n");
	check_ok(argv, "3\n");
}

static void test_grep_dash_l(void)
{
	char *argv[] = { (char *)"grep", (char *)"-l", (char *)"needle", (char *)"scratch/g5a", (char *)"scratch/g5b", 0 };
	make_file("scratch/g5a", "needle here\n");
	make_file("scratch/g5b", "nothing\n");
	CHECK(run(grep_path, argv) == 0);
	CHECK(out_contains("scratch/g5a"));
	CHECK(!out_contains("scratch/g5b"));
}

static void test_grep_dash_n(void)
{
	char *argv[] = { (char *)"grep", (char *)"-n", (char *)"b", (char *)"scratch/g6", 0 };
	make_file("scratch/g6", "a\nb\nc\nb\n");
	check_ok(argv, "2:b\n4:b\n");
}

/* ERE-only: `a+` (one-or-more) has no meaning in a BRE, where '+' is a
 * literal character -- this exercises both -E turning the flag on and
 * the underlying matcher actually treating it as ERE. */
static void test_grep_dash_E(void)
{
	char *argv[] = { (char *)"grep", (char *)"-E", (char *)"a+b", (char *)"scratch/g7", 0 };
	make_file("scratch/g7", "aaab\nab\nb\nxab\n");
	check_ok(argv, "aaab\nab\nxab\n");
}

/* -F: the pattern contains a literal '.' that would, as a regex,
 * match any character -- if -F were silently ignored, "a.b" would
 * also match "axb" below, which it must not. */
static void test_grep_dash_F(void)
{
	char *argv[] = { (char *)"grep", (char *)"-F", (char *)"a.b", (char *)"scratch/g8", 0 };
	make_file("scratch/g8", "xa.by\naxb\n");
	check_ok(argv, "xa.by\n");
}

/* Multiple -e: patterns really OR together -- a line matching only
 * the second pattern must still be selected. */
static void test_grep_multiple_e(void)
{
	char *argv[] = { (char *)"grep", (char *)"-e", (char *)"cat", (char *)"-e", (char *)"dog", (char *)"scratch/g9", 0 };
	make_file("scratch/g9", "cat\nfish\ndog\nbird\n");
	check_ok(argv, "cat\ndog\n");
}

static void test_grep_dash_x(void)
{
	char *argv[] = { (char *)"grep", (char *)"-x", (char *)"ab", (char *)"scratch/g10", 0 };
	make_file("scratch/g10", "ab\nxab\nabx\nab\n");
	check_ok(argv, "ab\nab\n");
}

/* -w: "cat" must select a line where it occurs as a whole word, and
 * must NOT select a line where it occurs only as a substring of a
 * longer word ("concatenate") -- the exact case a grep that silently
 * ignored -w (falling back to plain substring matching) would get
 * wrong. */
static void test_grep_dash_w(void)
{
	char *argv[] = { (char *)"grep", (char *)"-w", (char *)"cat", (char *)"scratch/g12", 0 };
	make_file("scratch/g12", "a cat sat\nconcatenate\ncats\nscatter\ncat\n");
	check_ok(argv, "a cat sat\ncat\n");
}

/* -w with -F: the same whole-word requirement applies to a literal
 * (non-regex) pattern too. */
static void test_grep_dash_w_fixed(void)
{
	char *argv[] = { (char *)"grep", (char *)"-w", (char *)"-F", (char *)"cat", (char *)"scratch/g13", 0 };
	make_file("scratch/g13", "concatenate\na cat sat\n");
	check_ok(argv, "a cat sat\n");
}

/* -w must not reject a whole-word match that merely sits next to
 * punctuation (non-word bytes) rather than whitespace. */
static void test_grep_dash_w_punctuation_boundary(void)
{
	char *argv[] = { (char *)"grep", (char *)"-w", (char *)"cat", (char *)"scratch/g14", 0 };
	make_file("scratch/g14", "(cat)\nconcatenate\n");
	check_ok(argv, "(cat)\n");
}

/* Exit status: 0 (matched), 1 (no match), >1 (a real error -- here, a
 * genuinely malformed ERE, an unbalanced '('). */
static void test_grep_exit_status_matched(void)
{
	char *argv[] = { (char *)"grep", (char *)"a", (char *)"scratch/g11", 0 };
	make_file("scratch/g11", "a\n");
	CHECK(run(grep_path, argv) == 0);
}

static void test_grep_exit_status_no_match(void)
{
	char *argv[] = { (char *)"grep", (char *)"zzz", (char *)"scratch/g11", 0 };
	CHECK(run(grep_path, argv) == 1);
}

static void test_grep_exit_status_error(void)
{
	char *argv[] = { (char *)"grep", (char *)"-E", (char *)"a(b", (char *)"scratch/g11", 0 };
	int rc = run(grep_path, argv);
	CHECK(rc > 1);
}

static void test_grep_missing_operand_is_an_error(void)
{
	char *argv[] = { (char *)"grep", 0 };
	int rc = run(grep_path, argv);
	CHECK(rc > 1);
	CHECK(err_contains("pattern"));
}

/* ==== the shell built-in agrees with the standalone executable ========== */

static void test_builtin_matches_standalone(void)
{
	CHECK(run_sh_c("grep foo scratch/g2") == 0);
	CHECK(out_equals("foo\nfoobar\n"));

	CHECK(run_sh_c("grep -v foo scratch/g2") == 0);
	CHECK(out_equals("bar\nbaz\n"));

	CHECK(run_sh_c("grep zzz scratch/g2") == 1);
}

/* ==== scratch directory setup/teardown =================================== */

static void rmtree_scratch(void)
{
	int i;
	char buf[32];
	for (i = 1; i <= 14; i++) {
		snprintf(buf, sizeof buf, "scratch/g%d", i);
		unlink(buf);
	}
	unlink("scratch/g5a"); unlink("scratch/g5b");
	unlink("scratch/.keep");
	rmdir("scratch");
}

static void cleanup_artifacts(void)
{
	unlink(OUTFILE);
	unlink(ERRFILE);
	rmtree_scratch();
}

int main(int argc, char **argv)
{
	(void)argc;

	if (find_obj_root(argv[0]) != 0) {
		printf("SKIP util-grep: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(grep_path, sizeof grep_path, "bin/grep.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(grep_path, R_OK) != 0 || access(sh_path, R_OK) != 0) {
		printf("SKIP util-grep: grep.exe or sh.exe is missing\n");
		return 77;
	}

	rmtree_scratch();
	if (mkdir("scratch", 0755) != 0) {
		printf("SKIP util-grep: cannot create scratch/ (%s)\n", strerror(errno));
		return 77;
	}
	make_file("scratch/.keep", "");

	test_grep_bre_basic();
	test_grep_dash_v();
	test_grep_dash_i();
	test_grep_dash_c();
	test_grep_dash_l();
	test_grep_dash_n();
	test_grep_dash_E();
	test_grep_dash_F();
	test_grep_multiple_e();
	test_grep_dash_x();
	test_grep_dash_w();
	test_grep_dash_w_fixed();
	test_grep_dash_w_punctuation_boundary();
	test_grep_exit_status_matched();
	test_grep_exit_status_no_match();
	test_grep_exit_status_error();
	test_grep_missing_operand_is_an_error();

	test_builtin_matches_standalone();

	cleanup_artifacts();

	if (fails) { printf("util-grep: failures: %d\n", fails); return 1; }
	printf("util-grep: all ok (grep -- standalone and builtin)\n");
	return 0;
}
