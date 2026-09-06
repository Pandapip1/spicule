/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for ntlibc's "bigger engines" POSIX standard
 * utilities: `diff`, `cmp` (XCU diff(1p), cmp(1p)).  Same technique as
 * test/util-sortset.c: the standalone obj/bin/<name>.exe is spawned as
 * a real process (via __spawn()+waitpid()), and the shell built-in is
 * exercised too (via obj/sh/sh.exe -c), confirming both callers of
 * __util_<name>_main() (src/internal/util.h) agree.
 *
 * Several cases here are specifically chosen to catch a subtly-wrong-
 * but-plausible implementation, not just exercise the happy path:
 *  - diff's default-format test checks the exact "NcN"/"NaN"/"NdN"
 *    header shapes and "< "/"> "/"---" body lines for a change, an
 *    append and a delete in the same run, not just "some output
 *    appeared".
 *  - diff's exit-status test checks all three of 0 (identical), 1
 *    (differences found) and 2 (a real error -- nonexistent file), the
 *    three-way distinction sort(1p)'s own -c/-C option deliberately
 *    does NOT use (see src/util/sort.c's header) but diff(1p) does.
 *  - diff -c and -e are each checked for their own real, distinct
 *    format markers ("!"/"***"/"---" for context; the ed "c"/"." shape
 *    for -e), not just "diff -c produced *some* different-looking
 *    output than the default".
 *  - diff -C with a count past INT_MAX (but a perfectly valid, in-range
 *    `long`, e.g. from strtol() on a 64-bit `long`) regression-tests
 *    that opts.context is never narrowed through an `int`: a stray
 *    "(int)n" there used to silently wrap such a count (mod 2^32,
 *    landing back near 0 for the value used below), which would have
 *    turned a "diff the whole file as context" request into the exact
 *    opposite -- context-less hunks -- without ever needing an
 *    actually huge input file to reach.
 *  - cmp's -l test checks the exact octal byte values, not just that
 *    -l produced more than one line.
 *  - cmp's default-vs-prefix test (one file a proper prefix of the
 *    other) exercises the EOF/length-mismatch path specifically, which
 *    is a real, separate code path from a genuine byte mismatch (see
 *    src/util/cmp.c's header comment on the STDERR EOF diagnostic).
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
	obj_root[i - 1] = 0; /* strip "/util-diffcmp.exe" */

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

#define OUTFILE "util-diffcmp-out.txt"
#define ERRFILE "util-diffcmp-err.txt"

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

static char diff_path[1024], cmp_path[1024], sh_path[1024];

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

/* Many cases below run one diff/cmp invocation and check both its exit
 * status and its stdout against an exact expected string -- folded into
 * these two helpers since that shape repeats across both utilities. */
static void check_out(const char *path, char *const *argv, int want_status, const char *expect)
{
	CHECK(run(path, argv) == want_status);
	CHECK(out_equals(expect));
}

static void check_sh_out(const char *cmd, int want_status, const char *expect)
{
	CHECK(run_sh_c(cmd) == want_status);
	CHECK(out_equals(expect));
}

/* ==== diff(1p) ============================================================ */

/* Exercises a change, an append and a delete all in the same default-
 * format run, and checks the exact header/body shapes -- not just that
 * *some* differing output appeared. */
static void test_diff_default_format(void)
{
	char *argv[] = { (char *)"diff", (char *)"scratch/d1", (char *)"scratch/d2", 0 };
	make_file("scratch/d1", "a\nb\nc\nd\ne\n");
	make_file("scratch/d2", "a\nB\nc\nd\ne\nf\n");
	check_out(diff_path, argv, 1, "2c2\n< b\n---\n> B\n5a6\n> f\n");
}

static void test_diff_pure_append_and_delete(void)
{
	char *append_argv[] = { (char *)"diff", (char *)"scratch/g1", (char *)"scratch/g2", 0 };
	char *delete_argv[] = { (char *)"diff", (char *)"scratch/g2", (char *)"scratch/g1", 0 };
	make_file("scratch/g1", "a\nb\nc\n");
	make_file("scratch/g2", "a\nb\nX\nY\nc\n");
	check_out(diff_path, append_argv, 1, "2a3,4\n> X\n> Y\n");
	check_out(diff_path, delete_argv, 1, "3,4d2\n< X\n< Y\n");
}

static void test_diff_identical_is_silent_and_zero(void)
{
	char *argv[] = { (char *)"diff", (char *)"scratch/d1", (char *)"scratch/d1", 0 };
	check_out(diff_path, argv, 0, "");
}

/* -c: real context-format markers ("***"/"---"/"!" for the changed
 * lines), not just "different from the default format". */
static void test_diff_dash_c(void)
{
	char *argv[] = { (char *)"diff", (char *)"-c", (char *)"scratch/d1", (char *)"scratch/d2", 0 };
	CHECK(run(diff_path, argv) == 1);
	CHECK(out_contains("***************\n"));
	CHECK(out_contains("! b\n"));
	CHECK(out_contains("! B\n"));
	CHECK(out_contains("+ f\n"));
}

/* -C with a count that overflows `int` (but not `long`): must saturate to
 * "as much context as the file has", not silently wrap back down to a
 * tiny (or zero) count. 4294967296 is 2^32 -- 0 mod 2^32, so a stray
 * "(int)n" narrowing would turn this into "-C 0" and both hunks would
 * print with no surrounding context at all, and as two separate groups
 * (their gap is bigger than 2*0). With the huge count honored, file1's
 * unchanged lines "a"/"c"/"d"/"e" all appear as one merged context block
 * around both hunks. */
static void test_diff_dash_C_huge_context(void)
{
	char *argv[] = { (char *)"diff", (char *)"-C", (char *)"4294967296",
		(char *)"scratch/d1", (char *)"scratch/d2", 0 };
	CHECK(run(diff_path, argv) == 1);
	CHECK(out_contains("  a\n"));
	CHECK(out_contains("  c\n"));
	CHECK(out_contains("  d\n"));
	CHECK(out_contains("  e\n"));
	CHECK(out_contains("! b\n"));
	CHECK(out_contains("! B\n"));
	CHECK(out_contains("+ f\n"));
}

/* -u: unified format's own real markers ("@@ ... @@", leading "-"/"+"). */
static void test_diff_dash_u(void)
{
	char *argv[] = { (char *)"diff", (char *)"-u", (char *)"scratch/d1", (char *)"scratch/d2", 0 };
	CHECK(run(diff_path, argv) == 1);
	CHECK(out_contains("@@ -1,5 +1,6 @@\n"));
	CHECK(out_contains("-b\n"));
	CHECK(out_contains("+B\n"));
	CHECK(out_contains("+f\n"));
}

/* -e: the ed-script shape (a bare "c"/"." pair, no "< "/"> " markers). */
static void test_diff_dash_e(void)
{
	char *argv[] = { (char *)"diff", (char *)"-e", (char *)"scratch/g1", (char *)"scratch/g2", 0 };
	check_out(diff_path, argv, 1, "2a\nX\nY\n.\n");
}

/* Exit status: 0 identical, 1 differences found, >1 a real error --
 * the three-way distinction diff(1p) actually uses, unlike sort -c/-C's
 * own different exit-status convention (see src/util/sort.c). */
static void test_diff_exit_status(void)
{
	char *same[] = { (char *)"diff", (char *)"scratch/d1", (char *)"scratch/d1", 0 };
	char *differ[] = { (char *)"diff", (char *)"scratch/d1", (char *)"scratch/d2", 0 };
	char *missing[] = { (char *)"diff", (char *)"scratch/d1", (char *)"scratch/does-not-exist", 0 };
	CHECK(run(diff_path, same) == 0);
	CHECK(run(diff_path, differ) == 1);
	CHECK(run(diff_path, missing) > 1);
}

static void test_diff_invalid_option(void)
{
	char *argv[] = { (char *)"diff", (char *)"-Q", (char *)"scratch/d1", (char *)"scratch/d2", 0 };
	CHECK(run(diff_path, argv) != 0);
	CHECK(err_contains("invalid option"));
}

/* -c and -u together are refused, not silently resolved to one of
 * them -- the SYNOPSIS groups them as mutually exclusive (see
 * src/util/diff.c's header comment). */
static void test_diff_conflicting_formats(void)
{
	char *argv[] = { (char *)"diff", (char *)"-c", (char *)"-u", (char *)"scratch/d1", (char *)"scratch/d2", 0 };
	CHECK(run(diff_path, argv) != 0);
	CHECK(err_contains("mutually exclusive"));
}

/* ==== cmp(1p) ============================================================== */

static void test_cmp_default_differ(void)
{
	char *argv[] = { (char *)"cmp", (char *)"scratch/c1", (char *)"scratch/c2", 0 };
	make_file("scratch/c1", "hello world\n");
	make_file("scratch/c2", "hello World\n");
	check_out(cmp_path, argv, 1, "scratch/c1 scratch/c2 differ: char 7, line 1\n");
}

static void test_cmp_identical(void)
{
	char *argv[] = { (char *)"cmp", (char *)"scratch/c1", (char *)"scratch/c1", 0 };
	check_out(cmp_path, argv, 0, "");
}

/* -l: exact byte number (decimal) and both differing bytes (octal),
 * not just "some extra output". "hello world" vs "hello World": byte 7
 * is 'w' (0157 octal) vs 'W' (0127 octal). */
static void test_cmp_dash_l(void)
{
	char *argv[] = { (char *)"cmp", (char *)"-l", (char *)"scratch/c1", (char *)"scratch/c2", 0 };
	check_out(cmp_path, argv, 1, "7 167 127\n");
}

static void test_cmp_dash_s(void)
{
	char *argv[] = { (char *)"cmp", (char *)"-s", (char *)"scratch/c1", (char *)"scratch/c2", 0 };
	CHECK(run(cmp_path, argv) == 1);
	CHECK(out_equals(""));
	{
		char buf[64];
		slurp_into(ERRFILE, buf, sizeof buf);
		CHECK(buf[0] == 0);
	}
}

/* One file is a proper prefix of the other: a real, separate code path
 * from a byte-value mismatch (see src/util/cmp.c's header comment on
 * the STDERR EOF diagnostic). */
static void test_cmp_prefix_eof(void)
{
	char *argv[] = { (char *)"cmp", (char *)"scratch/c3", (char *)"scratch/c4", 0 };
	make_file("scratch/c3", "abc");
	make_file("scratch/c4", "abcdef");
	CHECK(run(cmp_path, argv) == 1);
	CHECK(err_contains("EOF on"));
	CHECK(err_contains("scratch/c3"));
}

static void test_cmp_exit_status_error(void)
{
	char *argv[] = { (char *)"cmp", (char *)"scratch/c1", (char *)"scratch/does-not-exist", 0 };
	CHECK(run(cmp_path, argv) > 1);
}

static void test_cmp_dash_l_dash_s_mutually_exclusive(void)
{
	char *argv[] = { (char *)"cmp", (char *)"-l", (char *)"-s", (char *)"scratch/c1", (char *)"scratch/c2", 0 };
	CHECK(run(cmp_path, argv) != 0);
	CHECK(err_contains("mutually exclusive"));
}

/* ==== the shell built-ins agree with the standalone executables ========== */

static void test_builtins_match_standalone(void)
{
	check_sh_out("diff scratch/d1 scratch/d2", 1, "2c2\n< b\n---\n> B\n5a6\n> f\n");
	check_sh_out("diff scratch/d1 scratch/d1", 0, "");
	check_sh_out("cmp scratch/c1 scratch/c2", 1, "scratch/c1 scratch/c2 differ: char 7, line 1\n");
	check_sh_out("cmp scratch/c1 scratch/c1", 0, "");
}

/* ==== scratch directory setup/teardown =================================== */

static void rmtree_scratch(void)
{
	unlink("scratch/d1"); unlink("scratch/d2");
	unlink("scratch/g1"); unlink("scratch/g2");
	unlink("scratch/c1"); unlink("scratch/c2");
	unlink("scratch/c3"); unlink("scratch/c4");
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
		printf("SKIP util-diffcmp: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(diff_path, sizeof diff_path, "bin/diff.exe");
	path_for(cmp_path, sizeof cmp_path, "bin/cmp.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(diff_path, R_OK) != 0 || access(cmp_path, R_OK) != 0 ||
	    access(sh_path, R_OK) != 0) {
		printf("SKIP util-diffcmp: one or more of the two utility binaries or sh is missing\n");
		return 77;
	}

	rmtree_scratch();
	if (mkdir("scratch", 0755) != 0) {
		printf("SKIP util-diffcmp: cannot create scratch/ (%s)\n", strerror(errno));
		return 77;
	}
	make_file("scratch/.keep", "");

	test_diff_default_format();
	test_diff_pure_append_and_delete();
	test_diff_identical_is_silent_and_zero();
	test_diff_dash_c();
	test_diff_dash_C_huge_context();
	test_diff_dash_u();
	test_diff_dash_e();
	test_diff_exit_status();
	test_diff_invalid_option();
	test_diff_conflicting_formats();

	test_cmp_default_differ();
	test_cmp_identical();
	test_cmp_dash_l();
	test_cmp_dash_s();
	test_cmp_prefix_eof();
	test_cmp_exit_status_error();
	test_cmp_dash_l_dash_s_mutually_exclusive();

	test_builtins_match_standalone();

	cleanup_artifacts();

	if (fails) { printf("util-diffcmp: failures: %d\n", fails); return 1; }
	printf("util-diffcmp: all ok (diff, cmp -- standalone and builtin)\n");
	return 0;
}
