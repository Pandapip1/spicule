/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for spicule's sorting/set-operation POSIX standard
 * utilities: `sort`, `uniq`, `comm`, `join`, `tsort` (XCU sort(1p),
 * uniq(1p), comm(1p), join(1p), tsort(1p)).  Same technique as
 * test/util-fsops.c: the standalone obj/bin/<name>.exe is spawned as a
 * real process (via __spawn()+waitpid()), and the shell built-in is
 * exercised too (via obj/sh/sh.exe -c), confirming both callers of
 * __util_<name>_main() (src/internal/util.h) agree.
 *
 * Several cases here are specifically chosen to catch a subtly-wrong-
 * but-plausible implementation, not just exercise the happy path:
 *  - sort's multi-key test uses numeric field values ("2" vs "10")
 *    whose *lexicographic* order is the opposite of their *numeric*
 *    order, so a naive implementation that only honors the first -k (or
 *    that never reaches the second key at all) sorts them backwards.
 *  - sort's -t test additionally depends on the "keys tie -> fall back
 *    to whole-line byte comparison" rule (src/util/sort.c's header),
 *    not just a stable sort leaving input order alone.
 *  - join's -a test exercises unpairable lines from *both* files in the
 *    same run, together with an explicit -o list and -e, so a missing
 *    field (the unpaired side) really does surface as an empty output
 *    field that -e then replaces -- not just an omitted column.
 *  - tsort's cycle test is a real 3-node cycle (a->b->c->a), not just a
 *    malformed-input case, so it specifically exercises the "Kahn's
 *    algorithm stalls with nodes remaining" cycle detection path.
 *  - comm's three columns are each checked individually against a
 *    hand-derived expected merge, not eyeballed together.
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

	if (strip_last_component(obj_root) != 0) return -1; /* strip "/util-sortset.exe" */
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

#define OUTFILE "util-sortset-out.txt"
#define ERRFILE "util-sortset-err.txt"

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

static int out_index_of(const char *needle)
{
	char buf[8192];
	char *p;
	slurp_into(OUTFILE, buf, sizeof buf);
	p = strstr(buf, needle);
	return p ? (int)(p - buf) : -1;
}

static void make_file(const char *path, const char *contents)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return;
	if (contents && *contents) write(fd, contents, strlen(contents));
	close(fd);
}

static char sort_path[1024], uniq_path[1024], comm_path[1024];
static char join_path[1024], tsort_path[1024], sh_path[1024];

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

/* Runs `path` with `args`, checking it exits 0 and its stdout is
 * exactly `expect` -- the shape shared by most single-output tests
 * below. */
static void check_out(const char *path, char *const *args, const char *expect)
{
	CHECK(run(path, args) == 0);
	CHECK(out_equals(expect));
}

/* Runs `path` with `args`, checking it exits nonzero and its stderr
 * contains `needle` -- the shape shared by most error-path tests
 * below. */
static void check_err(const char *path, char *const *args, const char *needle)
{
	CHECK(run(path, args) != 0);
	CHECK(err_contains(needle));
}

/* ==== sort(1p) ============================================================ */

static void test_sort_basic(void)
{
	char *argv[] = { (char *)"sort", (char *)"scratch/s1", 0 };
	make_file("scratch/s1", "banana\napple\ncherry\n");
	check_out(sort_path, argv, "apple\nbanana\ncherry\n");
}

static void test_sort_dash_r(void)
{
	char *argv[] = { (char *)"sort", (char *)"-r", (char *)"scratch/s1", 0 };
	check_out(sort_path, argv, "cherry\nbanana\napple\n");
}

static void test_sort_dash_n(void)
{
	char *argv[] = { (char *)"sort", (char *)"-n", (char *)"scratch/s2", 0 };
	make_file("scratch/s2", "10\n2\n33\n4\n");
	check_out(sort_path, argv, "2\n4\n10\n33\n");
}

/* A numeric key long enough to overflow long long must saturate to
 * "largest possible value" rather than silently wrapping around --
 * a naive `v = v * 10 + digit` accumulator wraps this particular
 * 20-digit value to a large *negative* long long, which would sort it
 * before -3 instead of after 100. */
static void test_sort_dash_n_overflow_saturates(void)
{
	char *argv[] = { (char *)"sort", (char *)"-n", (char *)"scratch/s2b", 0 };
	make_file("scratch/s2b", "100\n5\n91311472887713638272\n42\n7\n-3\n");
	check_out(sort_path, argv, "-3\n5\n7\n42\n100\n91311472887713638272\n");
}

static void test_sort_dash_u(void)
{
	char *argv[] = { (char *)"sort", (char *)"-u", (char *)"scratch/s3", 0 };
	make_file("scratch/s3", "b\na\nb\na\nc\n");
	check_out(sort_path, argv, "a\nb\nc\n");
}

/* Lexicographic order of "2" vs "10" is the *opposite* of their numeric
 * order -- a naive sort that only honors -k1,1 (never reaching the
 * second key) or that treats -k2,2n as plain text would get this
 * backwards. */
static void test_sort_multikey_numeric_tiebreak(void)
{
	char *argv[] = { (char *)"sort", (char *)"-k1,1", (char *)"-k2,2n", (char *)"scratch/s4", 0 };
	make_file("scratch/s4", "a 10\na 2\nb 5\nb 1\n");
	check_out(sort_path, argv, "a 2\na 10\nb 1\nb 5\n");
}

/* -t plus a numeric key that ties (two lines both have field 2 == "2")
 * must fall back to whole-line byte comparison -- "a,2" before "b,2" --
 * exercising src/util/sort.c's documented tiebreak rule specifically. */
static void test_sort_dash_t_and_tiebreak(void)
{
	char *argv[] = { (char *)"sort", (char *)"-t,", (char *)"-k2,2n", (char *)"scratch/s5", 0 };
	make_file("scratch/s5", "b,2\na,10\na,2\n");
	check_out(sort_path, argv, "a,2\nb,2\na,10\n");
}

static void test_sort_dash_c(void)
{
	char *sorted[] = { (char *)"sort", (char *)"-c", (char *)"scratch/s1sorted", 0 };
	char *unsorted[] = { (char *)"sort", (char *)"-c", (char *)"scratch/s1", 0 };
	make_file("scratch/s1sorted", "apple\nbanana\ncherry\n");
	CHECK(run(sort_path, sorted) == 0);
	CHECK(run(sort_path, unsorted) == 1);
	CHECK(err_contains("disorder"));
}

/* -o may equal an input file: the whole input must be read before any
 * truncation happens. */
static void test_sort_dash_o_same_as_input(void)
{
	char *argv[] = { (char *)"sort", (char *)"-o", (char *)"scratch/s6", (char *)"scratch/s6", 0 };
	char buf[256];
	FILE *f;
	make_file("scratch/s6", "z\ny\nx\n");
	CHECK(run(sort_path, argv) == 0);
	f = fopen("scratch/s6", "rb");
	CHECK(f != 0);
	if (f) {
		size_t n = fread(buf, 1, sizeof buf - 1, f);
		buf[n] = 0;
		fclose(f);
		CHECK(!strcmp(buf, "x\ny\nz\n"));
	}
}

static void test_sort_missing_operand_reads_nothing_bad(void)
{
	/* sort with an invalid option is a usage error, not silently
	 * ignored. */
	char *argv[] = { (char *)"sort", (char *)"-Q", (char *)"scratch/s1", 0 };
	check_err(sort_path, argv, "invalid option");
}

/* ==== uniq(1p) ============================================================= */

static void test_uniq_basic(void)
{
	char *argv[] = { (char *)"uniq", (char *)"scratch/u1", 0 };
	make_file("scratch/u1", "a\na\nb\nb\nb\nc\n");
	check_out(uniq_path, argv, "a\nb\nc\n");
}

static void test_uniq_dash_c(void)
{
	char *argv[] = { (char *)"uniq", (char *)"-c", (char *)"scratch/u1", 0 };
	CHECK(run(uniq_path, argv) == 0);
	CHECK(out_contains("2 a"));
	CHECK(out_contains("3 b"));
	CHECK(out_contains("1 c"));
}

static void test_uniq_dash_d(void)
{
	char *argv[] = { (char *)"uniq", (char *)"-d", (char *)"scratch/u1", 0 };
	check_out(uniq_path, argv, "a\nb\n");
}

static void test_uniq_dash_u(void)
{
	char *argv[] = { (char *)"uniq", (char *)"-u", (char *)"scratch/u1", 0 };
	check_out(uniq_path, argv, "c\n");
}

/* -f skips whole fields (blank* nonblank*) before comparing: "x 1
 * apple" and "y 2 apple" differ in their first two fields but must
 * still collapse once those two fields are skipped. */
static void test_uniq_dash_f(void)
{
	char *argv[] = { (char *)"uniq", (char *)"-f", (char *)"2", (char *)"scratch/u2", 0 };
	make_file("scratch/u2", "x 1 apple\ny 2 apple\nz 3 banana\n");
	CHECK(run(uniq_path, argv) == 0);
	CHECK(out_contains("x 1 apple"));
	CHECK(out_contains("z 3 banana"));
	CHECK(!out_contains("y 2 apple"));
}

static void test_uniq_dash_s(void)
{
	char *argv[] = { (char *)"uniq", (char *)"-s", (char *)"2", (char *)"scratch/u3", 0 };
	make_file("scratch/u3", "aaXX\nbbXX\nccYY\n");
	/* first two chars ignored: "XX"=="XX" collapses the first pair,
	 * "YY" differs so the third line stays. */
	check_out(uniq_path, argv, "aaXX\nccYY\n");
}

static void test_uniq_mutually_exclusive(void)
{
	char *argv[] = { (char *)"uniq", (char *)"-d", (char *)"-u", (char *)"scratch/u1", 0 };
	check_err(uniq_path, argv, "mutually exclusive");
}

/* ==== comm(1p) ============================================================= */

static void test_comm_three_columns(void)
{
	char *argv[] = { (char *)"comm", (char *)"scratch/c1", (char *)"scratch/c2", 0 };
	make_file("scratch/c1", "a\nb\nc\nd\n");
	make_file("scratch/c2", "b\nc\ne\n");
	/* Hand-derived merge: a(1-only) b(common) c(common) d(1-only)
	 * e(2-only). */
	check_out(comm_path, argv, "a\n\t\tb\n\t\tc\nd\n\te\n");
}

static void test_comm_dash_1_2(void)
{
	/* -1 -2: suppress both only-in-file columns, leaving just the
	 * common lines, unindented. */
	char *argv[] = { (char *)"comm", (char *)"-1", (char *)"-2", (char *)"scratch/c1", (char *)"scratch/c2", 0 };
	check_out(comm_path, argv, "b\nc\n");
}

static void test_comm_dash_3(void)
{
	/* -3: suppress the common column, leaving only each file's own
	 * unique lines. */
	char *argv[] = { (char *)"comm", (char *)"-3", (char *)"scratch/c1", (char *)"scratch/c2", 0 };
	check_out(comm_path, argv, "a\nd\n\te\n");
}

/* ==== join(1p) ============================================================= */

static void test_join_basic(void)
{
	char *argv[] = { (char *)"join", (char *)"scratch/j1", (char *)"scratch/j2", 0 };
	make_file("scratch/j1", "1 apple\n2 banana\n3 cherry\n");
	make_file("scratch/j2", "2 red\n3 yellow\n4 green\n");
	check_out(join_path, argv, "2 banana red\n3 cherry yellow\n");
}

/* -a on both sides: unpairable lines from file1 AND file2 both appear,
 * each in default output form (no padding for the missing side). */
static void test_join_dash_a_both_sides(void)
{
	char *argv[] = { (char *)"join", (char *)"-a", (char *)"1", (char *)"-a", (char *)"2", (char *)"scratch/j1", (char *)"scratch/j2", 0 };
	check_out(join_path, argv, "1 apple\n2 banana red\n3 cherry yellow\n4 green\n");
}

static void test_join_dash_o(void)
{
	char *argv[] = { (char *)"join", (char *)"-o", (char *)"0,2.2", (char *)"scratch/j1", (char *)"scratch/j2", 0 };
	check_out(join_path, argv, "2 red\n3 yellow\n");
}

/* -a on both sides plus an explicit -o list plus -e: an unpaired line's
 * fields from the *absent* file must resolve to genuinely empty output
 * fields, which -e then replaces -- not just omitted columns. */
static void test_join_dash_a_dash_o_dash_e(void)
{
	char *argv[] = {
		(char *)"join", (char *)"-a", (char *)"1", (char *)"-a", (char *)"2",
		(char *)"-o", (char *)"1.1,1.2,2.2", (char *)"-e", (char *)"NONE",
		(char *)"scratch/j1", (char *)"scratch/j2", 0
	};
	check_out(join_path, argv, "1 apple NONE\n2 banana red\n3 cherry yellow\nNONE NONE green\n");
}

static void test_join_dash_t(void)
{
	char *argv[] = { (char *)"join", (char *)"-t", (char *)",", (char *)"scratch/j3", (char *)"scratch/j4", 0 };
	make_file("scratch/j3", "1,apple\n2,banana\n");
	make_file("scratch/j4", "1,red\n2,green\n");
	check_out(join_path, argv, "1,apple,red\n2,banana,green\n");
}

/* ==== tsort(1p) ============================================================= */

static void test_tsort_valid_order(void)
{
	char *argv[] = { (char *)"tsort", (char *)"scratch/t1", 0 };
	int ia, ib, ic, id;
	make_file("scratch/t1", "a b\na c\nb d\nc d\n");
	CHECK(run(tsort_path, argv) == 0);
	ia = out_index_of("a\n");
	ib = out_index_of("b\n");
	ic = out_index_of("c\n");
	id = out_index_of("d\n");
	CHECK(ia >= 0 && ib >= 0 && ic >= 0 && id >= 0);
	CHECK(ia < ib);
	CHECK(ia < ic);
	CHECK(ib < id);
	CHECK(ic < id);
}

static void test_tsort_cycle_is_an_error(void)
{
	char *argv[] = { (char *)"tsort", (char *)"scratch/t2", 0 };
	make_file("scratch/t2", "a b\nb c\nc a\n");
	check_err(tsort_path, argv, "cycle");
}

static void test_tsort_odd_tokens_is_an_error(void)
{
	char *argv[] = { (char *)"tsort", (char *)"scratch/t3", 0 };
	make_file("scratch/t3", "a b c\n");
	check_err(tsort_path, argv, "odd");
}

/* ==== the shell built-ins agree with the standalone executables ========== */

static void test_builtins_match_standalone(void)
{
	CHECK(run_sh_c("sort scratch/s1") == 0);
	CHECK(out_equals("apple\nbanana\ncherry\n"));

	CHECK(run_sh_c("uniq scratch/u1") == 0);
	CHECK(out_equals("a\nb\nc\n"));

	CHECK(run_sh_c("comm scratch/c1 scratch/c2") == 0);
	CHECK(out_equals("a\n\t\tb\n\t\tc\nd\n\te\n"));

	CHECK(run_sh_c("join scratch/j1 scratch/j2") == 0);
	CHECK(out_equals("2 banana red\n3 cherry yellow\n"));

	CHECK(run_sh_c("tsort scratch/t1") == 0);
	CHECK(out_contains("a\n"));
}

/* ==== scratch directory setup/teardown =================================== */

static void rmtree_scratch(void)
{
	unlink("scratch/s1"); unlink("scratch/s1sorted"); unlink("scratch/s2");
	unlink("scratch/s2b");
	unlink("scratch/s3"); unlink("scratch/s4"); unlink("scratch/s5");
	unlink("scratch/s6");
	unlink("scratch/u1"); unlink("scratch/u2"); unlink("scratch/u3");
	unlink("scratch/c1"); unlink("scratch/c2");
	unlink("scratch/j1"); unlink("scratch/j2"); unlink("scratch/j3"); unlink("scratch/j4");
	unlink("scratch/t1"); unlink("scratch/t2"); unlink("scratch/t3");
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
		printf("SKIP util-sortset: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(sort_path, sizeof sort_path, "bin/sort.exe");
	path_for(uniq_path, sizeof uniq_path, "bin/uniq.exe");
	path_for(comm_path, sizeof comm_path, "bin/comm.exe");
	path_for(join_path, sizeof join_path, "bin/join.exe");
	path_for(tsort_path, sizeof tsort_path, "bin/tsort.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(sort_path, R_OK) != 0 || access(uniq_path, R_OK) != 0 ||
	    access(comm_path, R_OK) != 0 || access(join_path, R_OK) != 0 ||
	    access(tsort_path, R_OK) != 0 || access(sh_path, R_OK) != 0) {
		printf("SKIP util-sortset: one or more of the five utility binaries or sh is missing\n");
		return 77;
	}

	rmtree_scratch();
	if (mkdir("scratch", 0755) != 0) {
		printf("SKIP util-sortset: cannot create scratch/ (%s)\n", strerror(errno));
		return 77;
	}
	make_file("scratch/.keep", "");

	test_sort_basic();
	test_sort_dash_r();
	test_sort_dash_n();
	test_sort_dash_n_overflow_saturates();
	test_sort_dash_u();
	test_sort_multikey_numeric_tiebreak();
	test_sort_dash_t_and_tiebreak();
	test_sort_dash_c();
	test_sort_dash_o_same_as_input();
	test_sort_missing_operand_reads_nothing_bad();

	test_uniq_basic();
	test_uniq_dash_c();
	test_uniq_dash_d();
	test_uniq_dash_u();
	test_uniq_dash_f();
	test_uniq_dash_s();
	test_uniq_mutually_exclusive();

	test_comm_three_columns();
	test_comm_dash_1_2();
	test_comm_dash_3();

	test_join_basic();
	test_join_dash_a_both_sides();
	test_join_dash_o();
	test_join_dash_a_dash_o_dash_e();
	test_join_dash_t();

	test_tsort_valid_order();
	test_tsort_cycle_is_an_error();
	test_tsort_odd_tokens_is_an_error();

	test_builtins_match_standalone();

	cleanup_artifacts();

	if (fails) { printf("util-sortset: failures: %d\n", fails); return 1; }
	printf("util-sortset: all ok (sort, uniq, comm, join, tsort -- standalone and builtin)\n");
	return 0;
}
