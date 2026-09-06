/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for ntlibc's text-formatting/file-splitting POSIX
 * standard utilities: `printf`, `od`, `pr`, `tabs`, `split`, `csplit`
 * (XCU printf(1p), od(1p), pr(1p), tabs(1p), split(1p), csplit(1p)).
 * Same technique as test/util-fsops.c: the standalone obj/bin/<name>.exe
 * is spawned as a real process (via __spawn()+waitpid()), and the shell
 * built-in is exercised too (via obj/sh/sh.exe -c), confirming both
 * callers of __util_<name>_main() (src/internal/util.h) agree; tests
 * that produce files (split, csplit) also verify the actual piece
 * contents, not just the spawned utility's exit status.
 *
 * All fixtures live under a scratch subdirectory of the test's own
 * working directory (created fresh in main(), removed again by
 * cleanup_artifacts()) -- see test/util-fsops.c's own header for why.
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

/* Same walk-up-from-argv[0] technique as test/util-fsops.c's own. */
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
	obj_root[i - 1] = 0; /* strip "/util-format.exe" */

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

#define OUTFILE "util-format-out.txt"
#define ERRFILE "util-format-err.txt"

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

static int out_is(const char *expect)
{
	char buf[8192];
	slurp_into(OUTFILE, buf, sizeof buf);
	return strcmp(buf, expect) == 0;
}

/* Checks a run succeeded (exit 0) with stdout exactly `expect` -- the
 * shape shared by most printf/pr tests below. */
static void check_ok_out_is(int status, const char *expect)
{
	CHECK(status == 0);
	CHECK(out_is(expect));
}

/* Checks a run succeeded (exit 0) with stdout containing `expect` -- the
 * shape shared by most od/tabs tests below. */
static void check_ok_out_contains(int status, const char *expect)
{
	CHECK(status == 0);
	CHECK(out_contains(expect));
}

/* Checks a run was refused outright: nonzero exit, with a diagnostic
 * containing `expect` -- the shape shared by most "not implemented"/
 * "not supported"/invalid-argument tests below. */
static void check_refused(int status, const char *expect)
{
	CHECK(status != 0);
	CHECK(err_contains(expect));
}

/* How many times `needle` occurs in OUTFILE -- used by the od elision
 * test to confirm a repeated row was collapsed to one line, not three. */
static int out_count(const char *needle)
{
	char buf[8192];
	const char *p;
	int n = 0;
	size_t nlen = strlen(needle);

	slurp_into(OUTFILE, buf, sizeof buf);
	for (p = buf; (p = strstr(p, needle)) != 0; p += nlen) n++;
	return n;
}

static void make_file(const char *path, const char *contents, size_t len)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return;
	if (contents && len) write(fd, contents, len);
	close(fd);
}

static char printf_path[1024], od_path[1024], pr_path[1024];
static char tabs_path[1024], split_path[1024], csplit_path[1024], sh_path[1024];

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

/* ==== printf(1p) ========================================================= */

static void test_printf_basic_conversions(void)
{
	char *argv[] = { (char *)"printf", (char *)"%s-%d\n", (char *)"hello", (char *)"42", 0 };
	check_ok_out_is(run(printf_path, argv), "hello-42\n");
}

/* printf(1p): "The format operand shall be reused as often as
 * necessary to satisfy the argument operands." */
static void test_printf_argument_cycling(void)
{
	char *argv[] = { (char *)"printf", (char *)"%s\n", (char *)"a", (char *)"b", (char *)"c", 0 };
	check_ok_out_is(run(printf_path, argv), "a\nb\nc\n");
}

/* Width and precision are deliberately capped at 1000.  In particular,
 * accumulating one more digit after 999 must clamp rather than briefly
 * producing 9999: precision controls writes into a fixed-size digit buffer. */
static void test_printf_large_width_and_precision_are_clamped(void)
{
	struct stat st;
	char *width_argv[] = { (char *)"printf", (char *)"%9999s", (char *)"x", 0 };
	char *prec_argv[] = { (char *)"printf", (char *)"%.9999d", (char *)"1", 0 };

	CHECK(run(printf_path, width_argv) == 0);
	CHECK(stat(OUTFILE, &st) == 0 && st.st_size == 1000);
	CHECK(run(printf_path, prec_argv) == 0);
	CHECK(stat(OUTFILE, &st) == 0 && st.st_size == 1000);
}

/* %b: backslash escapes inside the *argument*, distinct from \-escapes
 * written directly in the format string. The C string "a\\tb" is the
 * four bytes a, backslash, t, b -- exactly what a shell would pass for
 * an unquoted `a\tb` argument. */
static void test_printf_percent_b_expands_escapes(void)
{
	char *argv[] = { (char *)"printf", (char *)"%b\n", (char *)"a\\tb", 0 };
	check_ok_out_is(run(printf_path, argv), "a\tb\n");
}

/* printf(1p) ARGUMENTS: an argument that does not parse as a numeric
 * value under %d is a real, diagnosed error -- not a silent 0. */
static void test_printf_invalid_numeric_argument_is_an_error(void)
{
	char *argv[] = { (char *)"printf", (char *)"%d\n", (char *)"notanumber", 0 };
	CHECK(run(printf_path, argv) != 0);
	CHECK(err_contains("printf:"));
	/* Still produces a coherent (0-valued) line, per the standard's
	 * own "extra conversions ... as if a zero argument" wording,
	 * applied here to a genuinely-invalid argument too. */
	CHECK(out_is("0\n"));
}

static void test_printf_missing_operand(void)
{
	char *argv[] = { (char *)"printf", 0 };
	check_refused(run(printf_path, argv), "missing operand");
}

static void test_printf_builtin_agrees(void)
{
	check_ok_out_is(run_sh_c("printf '%s+%s\\n' foo bar"), "foo+bar\n");
}

/* ==== od(1p) ============================================================= */

static void test_od_default_hex_bytes(void)
{
	char *argv[] = { (char *)"od", (char *)"-A", (char *)"n", (char *)"-t", (char *)"x1",
	                  (char *)"scratch/od_in1", 0 };
	make_file("scratch/od_in1", "AB", 2);
	check_ok_out_contains(run(od_path, argv), " 41 42");
}

static void test_od_dash_t_c_escape_table(void)
{
	char *argv[] = { (char *)"od", (char *)"-A", (char *)"n", (char *)"-t", (char *)"c",
	                  (char *)"scratch/od_in2", 0 };
	make_file("scratch/od_in2", "A\n", 2);
	/* 'A' -> "   A" (4-wide field); '\n' -> "\n" mnemonic, "  \n" (4-wide). */
	check_ok_out_contains(run(od_path, argv), "   A  \\n");
}

/* od(1p): "any number of groups of output lines, which would be
 * identical to the immediately preceding group ... shall be replaced
 * with a line containing only an <asterisk>." */
static void test_od_elides_repeated_rows(void)
{
	char data[48];
	char *argv[] = { (char *)"od", (char *)"-A", (char *)"n", (char *)"-t", (char *)"x1",
	                  (char *)"scratch/od_in3", 0 };
	memset(data, 'a', sizeof data); /* three identical 16-byte rows */
	make_file("scratch/od_in3", data, sizeof data);
	CHECK(run(od_path, argv) == 0);
	CHECK(out_contains("*\n"));
	/* The repeated row's own text appears exactly once, not three times. */
	CHECK(out_count(" 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61") == 1);
}

static void test_od_j_skip_and_N_count(void)
{
	char *argv[] = { (char *)"od", (char *)"-A", (char *)"n", (char *)"-t", (char *)"x1",
	                  (char *)"-j", (char *)"2", (char *)"-N", (char *)"3",
	                  (char *)"scratch/od_in4", 0 };
	make_file("scratch/od_in4", "0123456789", 10);
	check_ok_out_contains(run(od_path, argv), " 32 33 34"); /* skips "01", reads "234" */
}

/* od(1p): the offset column is the byte's real position in the input,
 * so a -j skip must be reflected in every offset printed afterward --
 * `off` was left at 0 across the skip, so the first post-skip row was
 * mislabeled offset 0 instead of the real skip-relative offset. */
static void test_od_j_skip_offset_reflects_skip(void)
{
	char *argv[] = { (char *)"od", (char *)"-A", (char *)"d", (char *)"-t", (char *)"x1",
	                  (char *)"-j", (char *)"4", (char *)"scratch/od_in5", 0 };
	make_file("scratch/od_in5", "0123456789", 10);
	/* First (only) data row starts at byte 4 ("456789"), not byte 0. */
	check_ok_out_contains(run(od_path, argv), "0000004 34 35 36 37 38 39");
	/* Closing total-offset line: 10 bytes total, not 6 (10 - skipped 4). */
	CHECK(out_contains("0000010\n"));
}

static void test_od_invalid_type_is_an_error(void)
{
	char *argv[] = { (char *)"od", (char *)"-t", (char *)"q9", (char *)"scratch/od_in1", 0 };
	check_refused(run(od_path, argv), "od:");
}

static void test_od_builtin_agrees(void)
{
	check_ok_out_contains(run_sh_c("od -A n -t x1 scratch/od_in1"), " 41 42");
}

/* ==== pr(1p) ============================================================= */

/* -t (omit header/trailer) with a small -l makes the page-filling
 * behavior fully deterministic: budget == page_len when -t is given
 * (no header/trailer lines consumed), so 3 real lines + 2 blank filler
 * lines fill out a 5-line page exactly. */
static void test_pr_dash_t_pads_short_page(void)
{
	char *argv[] = { (char *)"pr", (char *)"-t", (char *)"-l", (char *)"5", (char *)"scratch/pr_in1", 0 };
	make_file("scratch/pr_in1", "l1\nl2\nl3\n", 9);
	check_ok_out_is(run(pr_path, argv), "l1\nl2\nl3\n\n\n");
}

static void test_pr_header_contains_name_and_page(void)
{
	char *argv[] = { (char *)"pr", (char *)"-h", (char *)"MYHEADER", (char *)"-l", (char *)"12",
	                  (char *)"scratch/pr_in2", 0 };
	make_file("scratch/pr_in2", "x\n", 2);
	CHECK(run(pr_path, argv) == 0);
	CHECK(out_contains("MYHEADER"));
	CHECK(out_contains("Page 1"));
}

static void test_pr_refuses_column_mode(void)
{
	char *argv[] = { (char *)"pr", (char *)"-3", (char *)"scratch/pr_in1", 0 };
	check_refused(run(pr_path, argv), "not implemented");
}

static void test_pr_refuses_merge(void)
{
	char *argv[] = { (char *)"pr", (char *)"-m", (char *)"scratch/pr_in1", (char *)"scratch/pr_in2", 0 };
	check_refused(run(pr_path, argv), "not implemented");
}

static void test_pr_builtin_agrees(void)
{
	check_ok_out_is(run_sh_c("pr -t -l 5 scratch/pr_in1"), "l1\nl2\nl3\n\n\n");
}

/* ==== tabs(1p) ============================================================ */

static void test_tabs_default_is_dash_8(void)
{
	char *argv[] = { (char *)"tabs", 0 };
	CHECK(run(tabs_path, argv) == 0);
	CHECK(out_contains("\033[3g"));
	CHECK(out_contains("\033H"));
	/* First stop at column 8: TBC, CR, 8 spaces, HTS. */
	CHECK(out_contains("\033[3g\r        \033H"));
}

static void test_tabs_dash_n_interval(void)
{
	char *argv[] = { (char *)"tabs", (char *)"-4", 0 };
	check_ok_out_contains(run(tabs_path, argv), "\033[3g\r    \033H"); /* first stop at column 4 */
}

static void test_tabs_refuses_dash_T(void)
{
	char *argv[] = { (char *)"tabs", (char *)"-T", (char *)"vt100", 0 };
	check_refused(run(tabs_path, argv), "not supported");
}

static void test_tabs_builtin_agrees(void)
{
	check_ok_out_contains(run_sh_c("tabs -4"), "\033[3g\r    \033H");
}

/* ==== split(1p) =========================================================== */

static void test_split_by_lines(void)
{
	char *argv[] = { (char *)"split", (char *)"-l", (char *)"2", (char *)"scratch/split_in1",
	                  (char *)"scratch/sl_", 0 };
	char buf[64];
	make_file("scratch/split_in1", "1\n2\n3\n4\n5\n", 10);
	CHECK(run(split_path, argv) == 0);
	CHECK(slurp_into("scratch/sl_aa", buf, sizeof buf) == 0 && !strcmp(buf, "1\n2\n"));
	CHECK(slurp_into("scratch/sl_ab", buf, sizeof buf) == 0 && !strcmp(buf, "3\n4\n"));
	CHECK(slurp_into("scratch/sl_ac", buf, sizeof buf) == 0 && !strcmp(buf, "5\n"));
}

static void test_split_by_bytes(void)
{
	char *argv[] = { (char *)"split", (char *)"-b", (char *)"3", (char *)"scratch/split_in2",
	                  (char *)"scratch/sb_", 0 };
	char buf[64];
	make_file("scratch/split_in2", "abcdefgh", 8);
	CHECK(run(split_path, argv) == 0);
	CHECK(slurp_into("scratch/sb_aa", buf, sizeof buf) == 0 && !strcmp(buf, "abc"));
	CHECK(slurp_into("scratch/sb_ab", buf, sizeof buf) == 0 && !strcmp(buf, "def"));
	CHECK(slurp_into("scratch/sb_ac", buf, sizeof buf) == 0 && !strcmp(buf, "gh"));
}

static void test_split_mutually_exclusive_l_and_b(void)
{
	char *argv[] = { (char *)"split", (char *)"-l", (char *)"2", (char *)"-b", (char *)"3",
	                  (char *)"scratch/split_in1", 0 };
	check_refused(run(split_path, argv), "mutually exclusive");
}

static void test_split_builtin_agrees(void)
{
	char buf[64];
	unlink("scratch/sh_aa");
	unlink("scratch/sh_ab");
	CHECK(run_sh_c("split -l 1 scratch/split_in1 scratch/sh_") == 0);
	CHECK(slurp_into("scratch/sh_aa", buf, sizeof buf) == 0 && !strcmp(buf, "1\n"));
}

/* ==== csplit(1p) ========================================================== */

static void test_csplit_line_number(void)
{
	char *argv[] = { (char *)"csplit", (char *)"-f", (char *)"scratch/cl_", (char *)"-n", (char *)"2",
	                  (char *)"scratch/csplit_in1", (char *)"3", 0 };
	char buf[64];
	make_file("scratch/csplit_in1", "a\nb\nc\nd\ne\n", 10);
	CHECK(run(csplit_path, argv) == 0);
	CHECK(slurp_into("scratch/cl_00", buf, sizeof buf) == 0 && !strcmp(buf, "a\nb\n"));
	CHECK(slurp_into("scratch/cl_01", buf, sizeof buf) == 0 && !strcmp(buf, "c\nd\ne\n"));
	/* size-report lines (not suppressed: no -s), one per created piece */
	CHECK(out_contains("4\n"));
	CHECK(out_contains("6\n"));
}

static void test_csplit_regex_split(void)
{
	char *argv[] = { (char *)"csplit", (char *)"-s", (char *)"-f", (char *)"scratch/cr_",
	                  (char *)"scratch/csplit_in2", (char *)"/SPLIT/", 0 };
	char buf[64];
	make_file("scratch/csplit_in2", "start\nfoo\nbar\nSPLIT\nbaz\n", 24);
	CHECK(run(csplit_path, argv) == 0);
	CHECK(slurp_into("scratch/cr_00", buf, sizeof buf) == 0 && !strcmp(buf, "start\nfoo\nbar\n"));
	CHECK(slurp_into("scratch/cr_01", buf, sizeof buf) == 0 && !strcmp(buf, "SPLIT\nbaz\n"));
	/* -s: no size-report lines at all. */
	CHECK(out_is(""));
}

static void test_csplit_no_match_is_an_error_and_cleans_up(void)
{
	char *argv[] = { (char *)"csplit", (char *)"-f", (char *)"scratch/cn_",
	                  (char *)"scratch/csplit_in2", (char *)"2", (char *)"/nomatch/", 0 };
	CHECK(run(csplit_path, argv) != 0);
	CHECK(err_contains("no match"));
	/* Without -k, the piece created before the failing arg is removed. */
	CHECK(access("scratch/cn_00", F_OK) != 0);
}

static void test_csplit_dash_k_keeps_partial_output(void)
{
	char *argv[] = { (char *)"csplit", (char *)"-k", (char *)"-f", (char *)"scratch/ck_",
	                  (char *)"scratch/csplit_in2", (char *)"2", (char *)"/nomatch/", 0 };
	char buf[64];
	CHECK(run(csplit_path, argv) != 0);
	CHECK(err_contains("no match"));
	CHECK(access("scratch/ck_00", F_OK) == 0);
	CHECK(slurp_into("scratch/ck_00", buf, sizeof buf) == 0 && !strcmp(buf, "start\n"));
}

static void test_csplit_repeat_operand_refused(void)
{
	char *argv[] = { (char *)"csplit", (char *)"-f", (char *)"scratch/cx_",
	                  (char *)"scratch/csplit_in2", (char *)"/foo/", (char *)"{2}", 0 };
	check_refused(run(csplit_path, argv), "not implemented");
}

/* Regression for a cast-before-validate integer overflow: 4294967301
 * (2^32+5) is a fully valid positive `long` -- no strtol() clamp
 * involved at all -- but on this project's Linux targets, where `long`
 * is 64 bits while `int` stays 32, a naive `(int)lineno` truncated it to
 * 5 before the range check ever ran, silently turning an operand a real
 * csplit(1p) rejects as out of range into what looked like a legitimate
 * split at line 5 of a 5-line file. */
static void test_csplit_huge_line_number_is_rejected(void)
{
	char *argv[] = { (char *)"csplit", (char *)"-f", (char *)"scratch/ov_",
	                  (char *)"scratch/csplit_in3", (char *)"4294967301", 0 };
	make_file("scratch/csplit_in3", "a\nb\nc\nd\ne\n", 10);
	check_refused(run(csplit_path, argv), "out of range");
	CHECK(access("scratch/ov_00", F_OK) != 0);
}

/* Same cast-before-validate hazard, for `-n`'s digit count: a value too
 * large to fit an `int` must be refused outright, not silently wrapped
 * into some small (or negative) count that then slips past the
 * `ndigits <= 0` check. */
static void test_csplit_huge_ndigits_is_rejected(void)
{
	char *argv[] = { (char *)"csplit", (char *)"-f", (char *)"scratch/on_", (char *)"-n", (char *)"4294967297",
	                  (char *)"scratch/csplit_in3", (char *)"3", 0 };
	check_refused(run(csplit_path, argv), "invalid digit count");
}

static void test_csplit_builtin_agrees(void)
{
	char buf[64];
	CHECK(run_sh_c("csplit -s -f scratch/csb_ scratch/csplit_in2 /SPLIT/") == 0);
	CHECK(slurp_into("scratch/csb_00", buf, sizeof buf) == 0 && !strcmp(buf, "start\nfoo\nbar\n"));
}

/* ==== cleanup ============================================================= */

static void rmtree_scratch(void)
{
	unlink("scratch/od_in1"); unlink("scratch/od_in2");
	unlink("scratch/od_in3"); unlink("scratch/od_in4");
	unlink("scratch/od_in5");
	unlink("scratch/pr_in1"); unlink("scratch/pr_in2");
	unlink("scratch/split_in1"); unlink("scratch/split_in2");
	unlink("scratch/sl_aa"); unlink("scratch/sl_ab"); unlink("scratch/sl_ac");
	unlink("scratch/sb_aa"); unlink("scratch/sb_ab"); unlink("scratch/sb_ac");
	unlink("scratch/sh_aa"); unlink("scratch/sh_ab");
	unlink("scratch/csplit_in1"); unlink("scratch/csplit_in2"); unlink("scratch/csplit_in3");
	unlink("scratch/cl_00"); unlink("scratch/cl_01");
	unlink("scratch/cr_00"); unlink("scratch/cr_01");
	unlink("scratch/cn_00"); unlink("scratch/cn_01");
	unlink("scratch/ck_00"); unlink("scratch/ck_01");
	unlink("scratch/cx_00");
	unlink("scratch/ov_00"); unlink("scratch/on_00");
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
		printf("SKIP util-format: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(printf_path, sizeof printf_path, "bin/printf.exe");
	path_for(od_path, sizeof od_path, "bin/od.exe");
	path_for(pr_path, sizeof pr_path, "bin/pr.exe");
	path_for(tabs_path, sizeof tabs_path, "bin/tabs.exe");
	path_for(split_path, sizeof split_path, "bin/split.exe");
	path_for(csplit_path, sizeof csplit_path, "bin/csplit.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(printf_path, R_OK) != 0 || access(od_path, R_OK) != 0 ||
	    access(pr_path, R_OK) != 0 || access(tabs_path, R_OK) != 0 ||
	    access(split_path, R_OK) != 0 || access(csplit_path, R_OK) != 0 ||
	    access(sh_path, R_OK) != 0) {
		printf("SKIP util-format: one or more of the six utility binaries or sh is missing\n");
		return 77;
	}

	rmtree_scratch();
	if (mkdir("scratch", 0755) != 0) {
		printf("SKIP util-format: cannot create scratch/ (%s)\n", strerror(errno));
		return 77;
	}
	make_file("scratch/.keep", "", 0);

	test_printf_basic_conversions();
	test_printf_argument_cycling();
	test_printf_large_width_and_precision_are_clamped();
	test_printf_percent_b_expands_escapes();
	test_printf_invalid_numeric_argument_is_an_error();
	test_printf_missing_operand();
	test_printf_builtin_agrees();

	test_od_default_hex_bytes();
	test_od_dash_t_c_escape_table();
	test_od_elides_repeated_rows();
	test_od_j_skip_and_N_count();
	test_od_j_skip_offset_reflects_skip();
	test_od_invalid_type_is_an_error();

	test_pr_dash_t_pads_short_page();
	test_pr_header_contains_name_and_page();
	test_pr_refuses_column_mode();
	test_pr_refuses_merge();

	test_tabs_default_is_dash_8();
	test_tabs_dash_n_interval();
	test_tabs_refuses_dash_T();

	test_split_by_lines();
	test_split_by_bytes();
	test_split_mutually_exclusive_l_and_b();
	test_split_builtin_agrees();

	test_csplit_line_number();
	test_csplit_regex_split();
	test_csplit_no_match_is_an_error_and_cleans_up();
	test_csplit_dash_k_keeps_partial_output();
	test_csplit_repeat_operand_refused();
	test_csplit_huge_line_number_is_rejected();
	test_csplit_huge_ndigits_is_rejected();

	cleanup_artifacts();

	if (fails) { printf("%d check(s) failed\n", fails); return 1; }
	printf("util-format: all checks passed\n");
	return 0;
}
