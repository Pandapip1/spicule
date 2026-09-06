/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for ntlibc's Tier 2 POSIX standard utilities: `cut`,
 * `paste`, `tr`, `expand`, `unexpand`, `fold` (XCU cut(1p), paste(1p),
 * tr(1p), expand(1p), unexpand(1p), fold(1p)).  Same technique as
 * test/util-fsops.c: the standalone obj/bin/<name>.exe is spawned as a
 * real process (via __spawn()+waitpid()), and the shell built-in is
 * exercised too (via obj/sh/sh.exe -c), confirming both callers of
 * __util_<name>_main() (src/internal/util.h) agree.
 *
 * Every one of these six reads standard input or a file operand and
 * writes standard output rather than mutating the filesystem, so unlike
 * util-fsops.c there is no lstat()/access() to check afterwards -- the
 * captured stdout *is* the thing under test.  Deliberate emphasis is on
 * the trickier grammars flagged as the real risk of this batch: cut's
 * range-list ("1,3-5,8-"), tr's bracket expressions and escape/range/
 * complement combinations, and paste's cycling -d list -- not just each
 * utility's trivial happy path.
 *
 * All fixtures live under a scratch subdirectory of the test's own
 * working directory (created fresh in main(), removed again by
 * cleanup_artifacts()) -- see test/sh-main.c's own cleanup_artifacts()
 * for why.
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

/* Same walk-up-from-argv[0] technique as test/util-fsops.c's
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
	p[-1] = 0; /* strip "/util-textfmt.exe" */

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

#define OUTFILE "util-textfmt-out.txt"
#define ERRFILE "util-textfmt-err.txt"
#define INFILE  "util-textfmt-in.txt"

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

/* Same idea as run(), but also feeds `input` to the child's stdin --
 * needed for tr(1p), which XCU defines with no file operand of its
 * own, only standard input. */
static int run_stdin(const char *path, char *const *args, const char *input)
{
	int in, out, err;
	int s0, s1, s2, pid, status;
	FILE *f = fopen(INFILE, "wb");

	if (!f) return -1;
	fwrite(input, 1, strlen(input), f);
	fclose(f);

	in = open(INFILE, O_RDONLY);
	out = open(OUTFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	err = open(ERRFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (in < 0 || out < 0 || err < 0) {
		if (in >= 0) close(in);
		if (out >= 0) close(out);
		if (err >= 0) close(err);
		return -1;
	}

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

static int out_equals(const char *expect)
{
	char buf[4096];
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

static char cut_path[1024], paste_path[1024], tr_path[1024];
static char expand_path[1024], unexpand_path[1024], fold_path[1024], sh_path[1024];

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

/* ==== cut(1p) ============================================================ */

static void test_cut_fields_basic(void)
{
	char *argv[] = { (char *)"cut", (char *)"-f", (char *)"1,3", (char *)"scratch/cutfields", 0 };
	make_file("scratch/cutfields", "a\tb\tc\nd\te\tf\n");
	CHECK(run(cut_path, argv) == 0);
	CHECK(out_equals("a\tc\nd\tf\n"));
}

static void test_cut_range_list(void)
{
	/* "1,3-5,8-" over "abcdefghij" (10 chars): 1, 3,4,5, 8,9,10. */
	char *argv[] = { (char *)"cut", (char *)"-c", (char *)"1,3-5,8-", (char *)"scratch/cutchars", 0 };
	make_file("scratch/cutchars", "abcdefghij\n");
	CHECK(run(cut_path, argv) == 0);
	CHECK(out_equals("acdehij\n"));
}

static void test_cut_dash_d_custom_delim(void)
{
	char *argv[] = { (char *)"cut", (char *)"-d", (char *)",", (char *)"-f", (char *)"2", (char *)"scratch/cutcsv", 0 };
	make_file("scratch/cutcsv", "x,y,z\n1,2,3\n");
	CHECK(run(cut_path, argv) == 0);
	CHECK(out_equals("y\n2\n"));
}

static void test_cut_dash_s_suppresses_no_delim_lines(void)
{
	char *argv[] = { (char *)"cut", (char *)"-d", (char *)":", (char *)"-s", (char *)"-f", (char *)"1", (char *)"scratch/cutnodelim", 0 };
	make_file("scratch/cutnodelim", "a:b\nno-colon-here\nc:d\n");
	CHECK(run(cut_path, argv) == 0);
	CHECK(out_equals("a\nc\n"));
}

static void test_cut_both_b_and_f_is_an_error(void)
{
	char *argv[] = { (char *)"cut", (char *)"-b", (char *)"1", (char *)"-f", (char *)"1", (char *)"scratch/cutfields", 0 };
	CHECK(run(cut_path, argv) != 0);
}

static void test_cut_neither_is_an_error(void)
{
	char *argv[] = { (char *)"cut", (char *)"scratch/cutfields", 0 };
	CHECK(run(cut_path, argv) != 0);
}

static void test_cut_missing_file_is_an_error(void)
{
	char *argv[] = { (char *)"cut", (char *)"-f", (char *)"1", (char *)"scratch/does-not-exist", 0 };
	CHECK(run(cut_path, argv) != 0);
}

/* ==== paste(1p) =========================================================== */

static void test_paste_default_merge(void)
{
	char *argv[] = { (char *)"paste", (char *)"scratch/paste1", (char *)"scratch/paste2", 0 };
	make_file("scratch/paste1", "a\nb\nc\n");
	make_file("scratch/paste2", "1\n2\n");
	CHECK(run(paste_path, argv) == 0);
	/* paste2 is shorter: its third row is an empty field, not a
	 * missing row -- see src/util/paste.c's header. */
	CHECK(out_equals("a\t1\nb\t2\nc\t\n"));
}

static void test_paste_dash_s_serial(void)
{
	char *argv[] = { (char *)"paste", (char *)"-s", (char *)"scratch/paste1", 0 };
	CHECK(run(paste_path, argv) == 0);
	CHECK(out_equals("a\tb\tc\n"));
}

static void test_paste_dash_d_cycling_list(void)
{
	char *argv[] = { (char *)"paste", (char *)"-d", (char *)",:", (char *)"scratch/paste3", (char *)"scratch/paste4", (char *)"scratch/paste5", 0 };
	make_file("scratch/paste3", "1\n2\n");
	make_file("scratch/paste4", "a\nb\n");
	make_file("scratch/paste5", "X\nY\n");
	CHECK(run(paste_path, argv) == 0);
	/* delims cycle ',' then ':' between the three fields of each row. */
	CHECK(out_equals("1,a:X\n2,b:Y\n"));
}

static void test_paste_dash_s_with_escaped_delim(void)
{
	char *argv[] = { (char *)"paste", (char *)"-s", (char *)"-d", (char *)"\\t", (char *)"scratch/paste1", 0 };
	CHECK(run(paste_path, argv) == 0);
	CHECK(out_equals("a\tb\tc\n"));
}

static void test_paste_missing_operand(void)
{
	char *argv[] = { (char *)"paste", 0 };
	CHECK(run(paste_path, argv) != 0);
	CHECK(err_contains("missing operand"));
}

/* ==== tr(1p) ============================================================== */

static void test_tr_translate_classes(void)
{
	char *argv[] = { (char *)"tr", (char *)"[:upper:]", (char *)"[:lower:]", 0 };
	CHECK(run_stdin(tr_path, argv, "Hello World\n") == 0);
	CHECK(out_equals("hello world\n"));
}

static void test_tr_delete(void)
{
	char *argv[] = { (char *)"tr", (char *)"-d", (char *)"aeiou", 0 };
	CHECK(run_stdin(tr_path, argv, "the quick brown fox\n") == 0);
	CHECK(out_equals("th qck brwn fx\n"));
}

static void test_tr_squeeze(void)
{
	char *argv[] = { (char *)"tr", (char *)"-s", (char *)" ", 0 };
	CHECK(run_stdin(tr_path, argv, "a    b   c\n") == 0);
	CHECK(out_equals("a b c\n"));
}

static void test_tr_range_and_repeat(void)
{
	/* a-e -> [x*5]: every one of a..e becomes 'x'. */
	char *argv[] = { (char *)"tr", (char *)"a-e", (char *)"[x*5]", 0 };
	CHECK(run_stdin(tr_path, argv, "abcdef\n") == 0);
	CHECK(out_equals("xxxxxf\n"));
}

static void test_tr_complement_delete(void)
{
	/* -cd digit: delete everything that is NOT a digit. */
	char *argv[] = { (char *)"tr", (char *)"-cd", (char *)"0-9", 0 };
	CHECK(run_stdin(tr_path, argv, "ab12cd34\n") == 0);
	CHECK(out_equals("1234"));
}

static void test_tr_octal_escape(void)
{
	/* \101 is octal for 'A'. */
	char *argv[] = { (char *)"tr", (char *)"\\101", (char *)"Z", 0 };
	CHECK(run_stdin(tr_path, argv, "ABC\n") == 0);
	CHECK(out_equals("ZBC\n"));
}

static void test_tr_delete_without_squeeze_rejects_string2(void)
{
	char *argv[] = { (char *)"tr", (char *)"-d", (char *)"a", (char *)"b", 0 };
	CHECK(run_stdin(tr_path, argv, "abc\n") != 0);
}

static void test_tr_plain_translate_requires_string2(void)
{
	char *argv[] = { (char *)"tr", (char *)"abc", 0 };
	CHECK(run_stdin(tr_path, argv, "abc\n") != 0);
}

static void test_tr_repeat_huge_count_is_bounded(void)
{
	/* [x*N] for a huge, attacker-sized N must not force expand_spec()
	 * to actually materialize N bytes of 'x' -- see src/util/tr.c's
	 * header and the explicit-repeat branch's own comment. string1 is
	 * 2 characters long, so a correct, bounded implementation finishes
	 * instantly no matter how large N's decimal text spells; before
	 * the fix this pushed the literal count of bytes, so a few dozen
	 * bytes of argv could demand gigabytes (or more) of memory for a
	 * two-character string1. */
	char *argv[] = { (char *)"tr", (char *)"ab", (char *)"[x*99999999999999]", 0 };
	CHECK(run_stdin(tr_path, argv, "ab\n") == 0);
	CHECK(out_equals("xx\n"));
}

static void test_tr_repeat_huge_count_preserves_later_positions(void)
{
	/* The cap must still leave every position string1's expansion can
	 * address filled with 'x' -- string1 is 10 characters, so a naive
	 * "only ever keep 1 copy" fix would corrupt positions 1..9 here,
	 * and the trailing "YZ" after the repeat must still be parsed
	 * (just never read back, since it falls past string1's length). */
	char *argv[] = { (char *)"tr", (char *)"abcdefghij", (char *)"[x*999999999999]YZ", 0 };
	CHECK(run_stdin(tr_path, argv, "abcdefghij\n") == 0);
	CHECK(out_equals("xxxxxxxxxx\n"));
}

/* ==== expand(1p) ========================================================== */

static void test_expand_default_tabwidth(void)
{
	char *argv[] = { (char *)"expand", (char *)"scratch/exptab", 0 };
	make_file("scratch/exptab", "a\tb\n");
	CHECK(run(expand_path, argv) == 0);
	/* 'a' at column 1, tab to column 9 -> 7 spaces, then 'b'. */
	CHECK(out_equals("a       b\n"));
}

static void test_expand_dash_t_single_number(void)
{
	char *argv[] = { (char *)"expand", (char *)"-t", (char *)"4", (char *)"scratch/exptab", 0 };
	CHECK(run(expand_path, argv) == 0);
	CHECK(out_equals("a   b\n"));
}

static void test_expand_dash_t_list(void)
{
	char *argv[] = { (char *)"expand", (char *)"-t", (char *)"3,6", (char *)"scratch/expmulti", 0 };
	make_file("scratch/expmulti", "a\tb\tc\n");
	CHECK(run(expand_path, argv) == 0);
	/* 'a' occupies column 1, next position column 2; tab from column 2
	 * lands at the next listed stop > 2, column 3 (one space); 'b' at
	 * column 3, next position 4; tab from column 4 lands at the next
	 * listed stop > 4, column 6 (two spaces); 'c' at column 6. */
	CHECK(out_equals("a b  c\n"));
}

static void test_expand_missing_file_is_an_error(void)
{
	char *argv[] = { (char *)"expand", (char *)"scratch/does-not-exist", 0 };
	CHECK(run(expand_path, argv) != 0);
}

/* ==== unexpand(1p) ======================================================== */

static void test_unexpand_leading_only_by_default(void)
{
	char *argv[] = { (char *)"unexpand", (char *)"scratch/unexp1", 0 };
	/* 8 leading spaces (one full tab stop) followed by two mid-line
	 * spaces that must NOT be touched without -a. */
	make_file("scratch/unexp1", "        a  b\n");
	CHECK(run(unexpand_path, argv) == 0);
	CHECK(out_equals("\ta  b\n"));
}

static void test_unexpand_dash_a_converts_whole_line(void)
{
	char *argv[] = { (char *)"unexpand", (char *)"-a", (char *)"scratch/unexp2", 0 };
	/* "ab" occupies columns 1-2, next position column 3; the run of 6
	 * spaces that follows spans columns 3-8, exactly reaching the next
	 * tab stop (column 9) with nothing left over, so -a's run of >=2
	 * converts cleanly to a single tab with no trailing space. */
	make_file("scratch/unexp2", "ab      cd\n");
	CHECK(run(unexpand_path, argv) == 0);
	CHECK(out_equals("ab\tcd\n"));
}

static void test_unexpand_single_space_not_converted_under_dash_a(void)
{
	char *argv[] = { (char *)"unexpand", (char *)"-a", (char *)"scratch/unexp3", 0 };
	make_file("scratch/unexp3", "a b\n");
	CHECK(run(unexpand_path, argv) == 0);
	CHECK(out_equals("a b\n"));
}

static void test_unexpand_dash_t_implies_whole_line(void)
{
	char *argv[] = { (char *)"unexpand", (char *)"-t", (char *)"4", (char *)"scratch/unexp4", 0 };
	/* Without -a: -t alone still converts the whole line per
	 * unexpand(1p)'s own words -- see src/util/unexpand.c's header.
	 * "a" occupies column 1, next position column 2; the run of 3
	 * spaces spans columns 2-4, exactly reaching the tabstop-4 stop at
	 * column 5 with nothing left over. */
	make_file("scratch/unexp4", "a   b\n");
	CHECK(run(unexpand_path, argv) == 0);
	CHECK(out_equals("a\tb\n"));
}

static void test_unexpand_missing_file_is_an_error(void)
{
	char *argv[] = { (char *)"unexpand", (char *)"scratch/does-not-exist", 0 };
	CHECK(run(unexpand_path, argv) != 0);
}

/* ==== fold(1p) ============================================================ */

static void test_fold_default_width(void)
{
	char *argv[] = { (char *)"fold", (char *)"scratch/fold80", 0 };
	char line[121];
	size_t k;
	for (k = 0; k < 100; k++) line[k] = (char)('a' + (k % 26));
	line[100] = '\n';
	line[101] = 0;
	make_file("scratch/fold80", line);
	CHECK(run(fold_path, argv) == 0);
	{
		char buf[4096];
		slurp_into(OUTFILE, buf, sizeof buf);
		/* 100 chars wrapped at 80: first output line 80 chars + '\n',
		 * second line the remaining 20 chars + '\n' (original had a
		 * trailing newline). */
		CHECK(strlen(buf) == 102); /* 80 + 1 + 20 + 1 */
		CHECK(buf[80] == '\n');
	}
}

static void test_fold_dash_w(void)
{
	char *argv[] = { (char *)"fold", (char *)"-w", (char *)"5", (char *)"scratch/foldw", 0 };
	make_file("scratch/foldw", "abcdefghij\n");
	CHECK(run(fold_path, argv) == 0);
	CHECK(out_equals("abcde\nfghij\n"));
}

static void test_fold_dash_s_breaks_at_blank(void)
{
	char *argv[] = { (char *)"fold", (char *)"-s", (char *)"-w", (char *)"10", (char *)"scratch/folds", 0 };
	make_file("scratch/folds", "hello world foo\n");
	CHECK(run(fold_path, argv) == 0);
	/* "hello worl" (10) would split mid-word "world" without -s;
	 * with -s, break after the last blank within the first 10 columns:
	 * "hello " (6) is kept together with as much of the next word as
	 * fits under the *next* segment's own limit. */
	CHECK(out_equals("hello \nworld foo\n"));
}

static void test_fold_missing_file_is_an_error(void)
{
	char *argv[] = { (char *)"fold", (char *)"scratch/does-not-exist", 0 };
	CHECK(run(fold_path, argv) != 0);
}

/* ==== builtin agreement =================================================== */

static void test_builtins_match_standalone(void)
{
	make_file("scratch/shin1", "a\tb\tc\n");
	CHECK(run_sh_c("cut -f2 scratch/shin1") == 0);
	CHECK(out_equals("b\n"));

	make_file("scratch/shin2", "x\ny\n");
	CHECK(run_sh_c("paste -s scratch/shin2") == 0);
	CHECK(out_equals("x\ty\n"));

	make_file("scratch/shin3", "hello\n");
	CHECK(run_sh_c("tr a-z A-Z < scratch/shin3") == 0);
	CHECK(out_equals("HELLO\n"));

	make_file("scratch/shin4", "a\tb\n");
	CHECK(run_sh_c("expand scratch/shin4") == 0);
	CHECK(out_equals("a       b\n"));

	make_file("scratch/shin5", "        a\n");
	CHECK(run_sh_c("unexpand scratch/shin5") == 0);
	CHECK(out_equals("\ta\n"));

	make_file("scratch/shin6", "abcdefghij\n");
	CHECK(run_sh_c("fold -w 5 scratch/shin6") == 0);
	CHECK(out_equals("abcde\nfghij\n"));
}

/* ==== scratch directory setup/teardown =================================== */

static void rmtree_scratch(void)
{
	unlink("scratch/cutfields");
	unlink("scratch/cutchars");
	unlink("scratch/cutcsv");
	unlink("scratch/cutnodelim");
	unlink("scratch/paste1");
	unlink("scratch/paste2");
	unlink("scratch/paste3");
	unlink("scratch/paste4");
	unlink("scratch/paste5");
	unlink("scratch/exptab");
	unlink("scratch/expmulti");
	unlink("scratch/unexp1");
	unlink("scratch/unexp2");
	unlink("scratch/unexp3");
	unlink("scratch/unexp4");
	unlink("scratch/fold80");
	unlink("scratch/foldw");
	unlink("scratch/folds");
	unlink("scratch/shin1");
	unlink("scratch/shin2");
	unlink("scratch/shin3");
	unlink("scratch/shin4");
	unlink("scratch/shin5");
	unlink("scratch/shin6");
	unlink("scratch/.keep");
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
		printf("SKIP util-textfmt: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(cut_path, sizeof cut_path, "bin/cut.exe");
	path_for(paste_path, sizeof paste_path, "bin/paste.exe");
	path_for(tr_path, sizeof tr_path, "bin/tr.exe");
	path_for(expand_path, sizeof expand_path, "bin/expand.exe");
	path_for(unexpand_path, sizeof unexpand_path, "bin/unexpand.exe");
	path_for(fold_path, sizeof fold_path, "bin/fold.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(cut_path, R_OK) != 0 || access(paste_path, R_OK) != 0 ||
	    access(tr_path, R_OK) != 0 || access(expand_path, R_OK) != 0 ||
	    access(unexpand_path, R_OK) != 0 || access(fold_path, R_OK) != 0 ||
	    access(sh_path, R_OK) != 0) {
		printf("SKIP util-textfmt: one or more of the six utility binaries or sh is missing\n");
		return 77;
	}

	rmtree_scratch();
	if (mkdir("scratch", 0755) != 0) {
		printf("SKIP util-textfmt: cannot create scratch/ (%s)\n", strerror(errno));
		return 77;
	}
	make_file("scratch/.keep", "");

	test_cut_fields_basic();
	test_cut_range_list();
	test_cut_dash_d_custom_delim();
	test_cut_dash_s_suppresses_no_delim_lines();
	test_cut_both_b_and_f_is_an_error();
	test_cut_neither_is_an_error();
	test_cut_missing_file_is_an_error();

	test_paste_default_merge();
	test_paste_dash_s_serial();
	test_paste_dash_d_cycling_list();
	test_paste_dash_s_with_escaped_delim();
	test_paste_missing_operand();

	test_tr_translate_classes();
	test_tr_delete();
	test_tr_squeeze();
	test_tr_range_and_repeat();
	test_tr_complement_delete();
	test_tr_octal_escape();
	test_tr_delete_without_squeeze_rejects_string2();
	test_tr_plain_translate_requires_string2();
	test_tr_repeat_huge_count_is_bounded();
	test_tr_repeat_huge_count_preserves_later_positions();

	test_expand_default_tabwidth();
	test_expand_dash_t_single_number();
	test_expand_dash_t_list();
	test_expand_missing_file_is_an_error();

	test_unexpand_leading_only_by_default();
	test_unexpand_dash_a_converts_whole_line();
	test_unexpand_single_space_not_converted_under_dash_a();
	test_unexpand_dash_t_implies_whole_line();
	test_unexpand_missing_file_is_an_error();

	test_fold_default_width();
	test_fold_dash_w();
	test_fold_dash_s_breaks_at_blank();
	test_fold_missing_file_is_an_error();

	test_builtins_match_standalone();

	cleanup_artifacts();

	if (fails) { printf("util-textfmt: failures: %d\n", fails); return 1; }
	printf("util-textfmt: all ok (cut, paste, tr, expand, unexpand, fold -- standalone and builtin)\n");
	return 0;
}
