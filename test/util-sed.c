/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for spicule's sed(1p) -- Tier 4's first "bigger
 * engine" utility.  Same technique as test/util-sortset.c: the
 * standalone obj/bin/sed.exe is spawned as a real process (via
 * __spawn()+waitpid()), and the shell built-in is exercised too (via
 * obj/sh/sh.exe -c), confirming both callers of __util_sed_main()
 * (src/internal/util.h) agree.
 *
 * Cases are chosen to catch a subtly-wrong-but-plausible
 * implementation, not just exercise the happy path:
 *  - the numeric-occurrence s/// test uses four identical matches so a
 *    naive "replace all after the first match" or "replace first
 *    match regardless of the count" implementation would both produce
 *    the wrong single output.
 *  - the address-range test spans three of five lines with an
 *    explicit inclusive line-number range, distinguishing a range
 *    implementation from a lucky single-address one.
 *  - the /regex/ address test relies on BRE (not ERE) syntax
 *    ("[0-9]\\{2\\}", the BRE interval escape) actually compiling and
 *    matching, which would fail outright under an accidental
 *    REG_EXTENDED slip.
 *  - the multi -e script test chains two substitutions specifically
 *    to catch a script assembler that drops or misorders later -e
 *    fragments instead of running them in argument order.
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

/* Truncates `s` at its last path separator (in place). Returns -1 if
 * `s` contains no separator at all, leaving `s` untouched. */
static int strip_last_component(char *s)
{
	size_t i;

	for (i = strlen(s); i > 0 && s[i - 1] != '/' && s[i - 1] != '\\'; i--)
		;
	if (i == 0) return -1;
	s[i - 1] = 0;
	return 0;
}

static int find_obj_root(const char *argv0)
{
	if (!argv0 || !*argv0) return -1;
	if (strlen(argv0) >= sizeof obj_root) return -1;
	strcpy(obj_root, argv0);

	if (strip_last_component(obj_root) != 0) return -1; /* strip "/util-sed.exe" */
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

#define OUTFILE "util-sed-out.txt"
#define ERRFILE "util-sed-err.txt"

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
	char buf[8192];
	slurp_into(OUTFILE, buf, sizeof buf);
	return strcmp(buf, expect) == 0;
}

static int out_contains(const char *needle)
{
	char buf[8192];
	slurp_into(OUTFILE, buf, sizeof buf);
	return strstr(buf, needle) != 0;
}

static int err_contains(const char *needle)
{
	char buf[4096];
	slurp_into(ERRFILE, buf, sizeof buf);
	return strstr(buf, needle) != 0;
}

static void make_file(const char *path, const char *contents)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return;
	if (contents && *contents) write(fd, contents, strlen(contents));
	close(fd);
}

static char sed_path[1024], sh_path[1024];

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

/* Runs sed.exe with `argv`, checking it exits 0 and its stdout is
 * exactly `expect` -- the shape shared by nearly every test below. */
static void check_sed(char *const *argv, const char *expect)
{
	CHECK(run(sed_path, argv) == 0);
	CHECK(out_equals(expect));
}

/* ==== s/// ================================================================= */

/* No flags: only the first match on each line is replaced. */
static void test_s_default_first_only(void)
{
	char *argv[] = { (char *)"sed", (char *)"s/o/0/", (char *)"scratch/s1", 0 };
	make_file("scratch/s1", "foo boo\n");
	check_sed(argv, "f0o boo\n");
}

static void test_s_global(void)
{
	char *argv[] = { (char *)"sed", (char *)"s/o/0/g", (char *)"scratch/s1", 0 };
	check_sed(argv, "f00 b00\n");
}

/* Four identical matches: only the 3rd is replaced -- catches an
 * implementation that ignores the occurrence count entirely, or that
 * replaces every match from the 3rd onward without 'g'. */
static void test_s_numeric_occurrence(void)
{
	char *argv[] = { (char *)"sed", (char *)"s/a/X/3", (char *)"scratch/s2", 0 };
	make_file("scratch/s2", "a a a a\n");
	check_sed(argv, "a a X a\n");
}

/* -n plus s///p: only substituted lines are printed, and each exactly
 * once (not the default-output copy AND the p-flag copy both). */
static void test_s_print_flag_with_dash_n(void)
{
	char *argv[] = { (char *)"sed", (char *)"-n", (char *)"s/cat/dog/p", (char *)"scratch/s3", 0 };
	make_file("scratch/s3", "a cat sat\nno match here\nanother cat\n");
	check_sed(argv, "a dog sat\nanother dog\n");
}

/* '&' (whole match) and a backreference together. */
static void test_s_ampersand_and_backref(void)
{
	char *argv[] = { (char *)"sed", (char *)"s/\\(foo\\)bar/[&]-\\1/", (char *)"scratch/s4", 0 };
	make_file("scratch/s4", "foobar\n");
	check_sed(argv, "[foobar]-foo\n");
}

/* ==== addressing ============================================================ */

static void test_addr_line_number(void)
{
	char *argv[] = { (char *)"sed", (char *)"2d", (char *)"scratch/a1", 0 };
	make_file("scratch/a1", "one\ntwo\nthree\n");
	check_sed(argv, "one\nthree\n");
}

static void test_addr_dollar(void)
{
	char *argv[] = { (char *)"sed", (char *)"$d", (char *)"scratch/a1", 0 };
	check_sed(argv, "one\ntwo\n");
}

/* /BRE/ address: XCU's own BRE interval syntax ("\{2\}"), not ERE's
 * unescaped "{2}" -- would fail to compile or fail to match under an
 * accidental REG_EXTENDED slip. */
static void test_addr_regex_bre(void)
{
	char *argv[] = { (char *)"sed", (char *)"-n", (char *)"/[0-9]\\{2\\}/p", (char *)"scratch/a2", 0 };
	make_file("scratch/a2", "id 7\nid 42\nid 9\nid 123\n");
	check_sed(argv, "id 42\nid 123\n");
}

/* Inclusive range 2,4 out of five lines, distinguishing a real range
 * from a single-address (or off-by-one) implementation. */
static void test_addr_range(void)
{
	char *argv[] = { (char *)"sed", (char *)"-n", (char *)"2,4p", (char *)"scratch/a3", 0 };
	make_file("scratch/a3", "1\n2\n3\n4\n5\n");
	check_sed(argv, "2\n3\n4\n");
}

/* Negation: everything EXCEPT the matching line survives. */
static void test_addr_negate(void)
{
	char *argv[] = { (char *)"sed", (char *)"/2/!d", (char *)"scratch/a3", 0 };
	check_sed(argv, "2\n");
}

/* ==== d ===================================================================== */

static void test_delete(void)
{
	char *argv[] = { (char *)"sed", (char *)"/skip/d", (char *)"scratch/d1", 0 };
	make_file("scratch/d1", "keep\nskip this\nkeep too\n");
	check_sed(argv, "keep\nkeep too\n");
}

/* ==== multi-command scripts via -e ========================================== */

static void test_multi_dash_e(void)
{
	char *argv[] = { (char *)"sed", (char *)"-e", (char *)"s/a/b/", (char *)"-e", (char *)"s/b/c/", (char *)"scratch/m1", 0 };
	make_file("scratch/m1", "a\n");
	check_sed(argv, "c\n");
}

/* ==== hold space: h/x/g round-trip ========================================== */

static void test_hold_space_roundtrip(void)
{
	/* Swap each line with the previous one: hold the first line, then
	 * on line 2 exchange pattern and hold space. */
	char *argv[] = { (char *)"sed", (char *)"-n", (char *)"1h;2{x;p}", (char *)"scratch/h1", 0 };
	make_file("scratch/h1", "first\nsecond\n");
	check_sed(argv, "first\n");
}

/* ==== y/// transliteration =================================================== */

static void test_y_translit(void)
{
	char *argv[] = { (char *)"sed", (char *)"y/abc/xyz/", (char *)"scratch/y1", 0 };
	make_file("scratch/y1", "abcabc\n");
	check_sed(argv, "xyzxyz\n");
}

/* ==== a\/i\/c\ text ========================================================= */

static void test_a_i_c_text(void)
{
	char *argv[] = { (char *)"sed", (char *)"2{i\\\nBEFORE\na\\\nAFTER\n}", (char *)"scratch/aic1", 0 };
	make_file("scratch/aic1", "one\ntwo\nthree\n");
	check_sed(argv, "one\nBEFORE\ntwo\nAFTER\nthree\n");
}

static void test_c_text(void)
{
	char *argv[] = { (char *)"sed", (char *)"2c\\\nCHANGED", (char *)"scratch/aic1", 0 };
	check_sed(argv, "one\nCHANGED\nthree\n");
}

/* ==== N/D: the classic multi-line gotcha ==================================== */

/* N joins the next line into the pattern space with an embedded
 * <newline>.  This project's BRE engine (src/regex/regex.c) follows
 * XCU literally: an undefined escape is just its next character with
 * the backslash dropped, NOT GNU sed's "\n means newline" extension --
 * so the only portable way to match the embedded <newline> here is an
 * actual backslash-<newline> pair in the script text itself, which
 * esc_literal() then reduces to one literal <newline> atom.  Collapses
 * each pair of lines into one, joined by a comma. */
static void test_N_join_pairs(void)
{
	char *argv[] = { (char *)"sed", (char *)"N;s/\\\n/,/", (char *)"scratch/nd1", 0 };
	make_file("scratch/nd1", "a\nb\nc\nd\n");
	check_sed(argv, "a,b\nc,d\n");
}

/* ==== b/t branching ========================================================= */

/* Loop via a label + t to strip every run of "xx" in a line, proving
 * both b/t label resolution and t's "only if substituted since the
 * last input line/t" condition. */
static void test_branch_loop(void)
{
	char *argv[] = { (char *)"sed", (char *)":top;s/xx//;t top", (char *)"scratch/b1", 0 };
	make_file("scratch/b1", "axxbxxcxx\n");
	check_sed(argv, "abc\n");
}

/* ==== q ====================================================================== */

static void test_quit(void)
{
	char *argv[] = { (char *)"sed", (char *)"2q", (char *)"scratch/a3", 0 };
	check_sed(argv, "1\n2\n");
}

/* ==== usage error ============================================================ */

static void test_bad_option(void)
{
	char *argv[] = { (char *)"sed", (char *)"-Q", (char *)"scratch/a3", 0 };
	CHECK(run(sed_path, argv) != 0);
	CHECK(err_contains("invalid option"));
}

/* ==== the shell built-in agrees with the standalone executable ============= */

static void test_builtin_matches_standalone(void)
{
	CHECK(run_sh_c("sed 's/a/b/' scratch/m1") == 0);
	CHECK(out_equals("b\n"));

	CHECK(run_sh_c("sed -n '2,4p' scratch/a3") == 0);
	CHECK(out_equals("2\n3\n4\n"));
}

/* ==== scratch directory setup/teardown ====================================== */

static void rmtree_scratch(void)
{
	unlink("scratch/s1"); unlink("scratch/s2"); unlink("scratch/s3"); unlink("scratch/s4");
	unlink("scratch/a1"); unlink("scratch/a2"); unlink("scratch/a3");
	unlink("scratch/d1"); unlink("scratch/m1"); unlink("scratch/h1");
	unlink("scratch/y1"); unlink("scratch/aic1"); unlink("scratch/nd1"); unlink("scratch/b1");
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
		printf("SKIP util-sed: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(sed_path, sizeof sed_path, "bin/sed.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(sed_path, R_OK) != 0 || access(sh_path, R_OK) != 0) {
		printf("SKIP util-sed: sed.exe or sh.exe is missing\n");
		return 77;
	}

	rmtree_scratch();
	if (mkdir("scratch", 0755) != 0) {
		printf("SKIP util-sed: cannot create scratch/ (%s)\n", strerror(errno));
		return 77;
	}
	make_file("scratch/.keep", "");

	test_s_default_first_only();
	test_s_global();
	test_s_numeric_occurrence();
	test_s_print_flag_with_dash_n();
	test_s_ampersand_and_backref();

	test_addr_line_number();
	test_addr_dollar();
	test_addr_regex_bre();
	test_addr_range();
	test_addr_negate();

	test_delete();
	test_multi_dash_e();
	test_hold_space_roundtrip();
	test_y_translit();
	test_a_i_c_text();
	test_c_text();
	test_N_join_pairs();
	test_branch_loop();
	test_quit();
	test_bad_option();

	test_builtin_matches_standalone();

	cleanup_artifacts();

	if (fails) { printf("util-sed: failures: %d\n", fails); return 1; }
	printf("util-sed: all ok (sed -- standalone and builtin)\n");
	return 0;
}
