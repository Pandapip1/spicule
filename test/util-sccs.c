/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for spicule's Tier 9 SCCS tooling: admin(1p) and
 * enough of get(1p) to round-trip it (src/util/admin.c, src/util/get.c
 * -- see each file's own header comment for exactly what this pair
 * does and does not implement, and why delta(1p) is not part of the
 * round trip at all). Same technique as test/util-tput.c: the
 * standalone obj/bin/<name>.exe is spawned as a real process (via
 * __spawn()+waitpid()), and the shell built-in is exercised too (via
 * obj/sh/sh.exe -c), confirming both callers of __util_admin_main()/
 * __util_get_main() (src/internal/util.h) agree.
 *
 * The core scenario every real SCCS user ultimately cares about is a
 * round trip -- put content in with admin -i, get the same content
 * back out with get -- so that is this file's centerpiece
 * (test_roundtrip_basic() and friends), not just isolated per-flag
 * checks.
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

/* Same walk-up-from-argv[0] technique as test/util-tput.c's
 * find_obj_root(), copied rather than shared for the same reason that
 * file gives. */
static int find_obj_root(const char *argv0)
{
	if (!argv0 || !*argv0) return -1;
	if (strlen(argv0) >= sizeof obj_root) return -1;
	strcpy(obj_root, argv0);

	if (strip_last_component(obj_root) != 0) return -1; /* strip "/util-sccs.exe" */
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

#define OUTFILE "util-sccs-out.txt"
#define ERRFILE "util-sccs-err.txt"
#define INFILE  "util-sccs-in.txt"

/* Same shape as test/util-tput.c's run(), plus optional stdin
 * redirection (needed here for admin -i's "name omitted -> read
 * standard input" case, which none of the other util-*.c black-box
 * tests so far have needed). `in_path` may be 0 for "leave stdin
 * alone" (every case that names its input file directly instead). */
static int run_in(const char *path, char *const *args, const char *in_path)
{
	int out, err, in = -1;
	int s0 = -1, s1, s2, pid, status;

	out = open(OUTFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	err = open(ERRFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (out < 0 || err < 0) { if (out >= 0) close(out); if (err >= 0) close(err); return -1; }
	if (in_path) {
		in = open(in_path, O_RDONLY);
		if (in < 0) { close(out); close(err); return -1; }
	}

	s1 = dup(1); s2 = dup(2);
	dup2(out, 1);
	dup2(err, 2);
	close(out); close(err);
	if (in_path) { s0 = dup(0); dup2(in, 0); close(in); }

	pid = __spawn(path, args, environ);

	dup2(s1, 1); close(s1);
	dup2(s2, 2); close(s2);
	if (in_path) { dup2(s0, 0); close(s0); }

	if (pid < 0) return -1;
	if (waitpid(pid, &status, 0) != pid) return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static int run(const char *path, char *const *args) { return run_in(path, args, 0); }

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

static int file_contains(const char *path, const char *needle)
{
	char buf[8192];
	slurp_into(path, buf, sizeof buf);
	return strstr(buf, needle) != 0;
}

static int file_equals_text(const char *path, const char *expect)
{
	char buf[4096];
	slurp_into(path, buf, sizeof buf);
	return strcmp(buf, expect) == 0;
}

static void write_file(const char *path, const char *content)
{
	FILE *f = fopen(path, "wb");
	if (!f) return;
	fwrite(content, 1, strlen(content), f);
	fclose(f);
}

static char admin_path[1024], get_path[1024], sh_path[1024];

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

/* Runs `path` with `args`, checking it exits with `want_status` and
 * that its stderr contains `needle` -- the shape shared by most usage-
 * and refusal-error tests below. */
static void check_run_err(const char *path, char *const *args, int want_status, const char *needle)
{
	CHECK(run(path, args) == want_status);
	CHECK(err_contains(needle));
}

/* Runs admin then get, checking both succeed -- the fixed prefix shared
 * by every round-trip test below, each of which then goes on to check
 * get's own output differently. */
static void check_roundtrip_ok(char *const *aargv, char *const *gargv)
{
	CHECK(run(admin_path, aargv) == 0);
	CHECK(run(get_path, gargv) == 0);
}

/* ==== admin(1p): usage / refusal paths ===================================== */

static void test_admin_rejects_non_s_name(void)
{
	char *argv[] = { (char *)"admin", (char *)"-i" INFILE, (char *)"util-sccs-not-an-sfile", 0 };
	write_file(INFILE, "one\ntwo\n");
	check_run_err(admin_path, argv, 1, "not an SCCS file name");
	unlink("util-sccs-not-an-sfile");
}

static void test_admin_missing_operand(void)
{
	char *argv[] = { (char *)"admin", (char *)"-i" INFILE, 0 };
	check_run_err(admin_path, argv, 2, "missing operand");
}

static void test_admin_neither_i_nor_n(void)
{
	char *argv[] = { (char *)"admin", (char *)"s.util-sccs-neither", 0 };
	check_run_err(admin_path, argv, 1, "modifying an existing SCCS file is not implemented");
}

static void test_admin_refuses_unimplemented_option(void)
{
	char *argv[] = { (char *)"admin", (char *)"-a", (char *)"someuser", (char *)"s.util-sccs-a", 0 };
	check_run_err(admin_path, argv, 1, "not implemented");
}

/* ==== round trip: admin -i creates, get -p retrieves ======================= */

static void test_roundtrip_basic(void)
{
	char *aargv[] = { (char *)"admin", (char *)"-i" INFILE, (char *)"s.util-sccs-rt1", 0 };
	char *gargv[] = { (char *)"get", (char *)"-p", (char *)"s.util-sccs-rt1", 0 };

	write_file(INFILE, "line one\nline two\nline three\n");
	unlink("s.util-sccs-rt1");

	CHECK(run(admin_path, aargv) == 0);
	CHECK(access("s.util-sccs-rt1", R_OK) == 0);

	CHECK(run(get_path, gargv) == 0);
	CHECK(out_equals("line one\nline two\nline three\n"));
	/* get -p's status line goes to stderr (src/util/get.c's own header
	 * comment on this deliberate choice), not stdout. */
	CHECK(err_contains("1.1"));
	CHECK(err_contains("3 lines"));

	unlink("s.util-sccs-rt1");
}

/* Content with no trailing newline on the last line: admin.c's own
 * header comment on read_lines() documents that every line is written
 * back out newline-terminated regardless, so the retrieved text gains
 * a trailing newline the original lacked -- this test pins that down
 * as the actual, current, documented behaviour rather than leaving it
 * unverified. */
static void test_roundtrip_no_trailing_newline(void)
{
	char *aargv[] = { (char *)"admin", (char *)"-i" INFILE, (char *)"s.util-sccs-rt2", 0 };
	char *gargv[] = { (char *)"get", (char *)"-p", (char *)"s.util-sccs-rt2", 0 };

	write_file(INFILE, "only line, no newline");
	unlink("s.util-sccs-rt2");

	check_roundtrip_ok(aargv, gargv);
	CHECK(out_equals("only line, no newline\n"));

	unlink("s.util-sccs-rt2");
}

/* admin -i with no attached name reads standard input. */
static void test_admin_i_reads_stdin(void)
{
	char *aargv[] = { (char *)"admin", (char *)"-i", (char *)"s.util-sccs-rt3", 0 };
	char *gargv[] = { (char *)"get", (char *)"-p", (char *)"s.util-sccs-rt3", 0 };

	write_file(INFILE, "from stdin\n");
	unlink("s.util-sccs-rt3");

	CHECK(run_in(admin_path, aargv, INFILE) == 0);
	CHECK(run(get_path, gargv) == 0);
	CHECK(out_equals("from stdin\n"));

	unlink("s.util-sccs-rt3");
}

/* admin -n (no -i at all): an empty initial delta. */
static void test_admin_n_empty(void)
{
	char *aargv[] = { (char *)"admin", (char *)"-n", (char *)"s.util-sccs-rt4", 0 };
	char *gargv[] = { (char *)"get", (char *)"-p", (char *)"s.util-sccs-rt4", 0 };

	unlink("s.util-sccs-rt4");
	check_roundtrip_ok(aargv, gargv);
	CHECK(out_equals(""));
	CHECK(err_contains("0 lines"));

	unlink("s.util-sccs-rt4");
}

/* admin refuses to overwrite an existing s.file. */
static void test_admin_refuses_existing(void)
{
	char *aargv[] = { (char *)"admin", (char *)"-i" INFILE, (char *)"s.util-sccs-rt5", 0 };

	write_file(INFILE, "x\n");
	unlink("s.util-sccs-rt5");
	CHECK(run(admin_path, aargv) == 0);
	check_run_err(admin_path, aargv, 1, "file already exists");

	unlink("s.util-sccs-rt5");
}

/* New SCCS files are created read-only, per admin.html's own DESCRIPTION
 * ("New SCCS files shall be given read-only permission mode") quoted in
 * src/util/admin.c's header comment. */
static void test_admin_creates_readonly(void)
{
	char *aargv[] = { (char *)"admin", (char *)"-i" INFILE, (char *)"s.util-sccs-rt6", 0 };
	struct stat st;

	write_file(INFILE, "x\n");
	unlink("s.util-sccs-rt6");
	CHECK(run(admin_path, aargv) == 0);
	CHECK(stat("s.util-sccs-rt6", &st) == 0);
	CHECK((st.st_mode & 0222) == 0);

	chmod("s.util-sccs-rt6", 0644);
	unlink("s.util-sccs-rt6");
}

/* -y's comment and -t's descriptive text really do land in the s.file
 * -- get(1p) never surfaces either back out, so this reads the raw
 * s.file content directly rather than round-tripping through get. */
static void test_admin_y_and_t(void)
{
	char *aargv[] = { (char *)"admin", (char *)"-i" INFILE, (char *)"-tutil-sccs-desc.txt",
		(char *)"-yhello from -y", (char *)"s.util-sccs-rt7", 0 };

	write_file(INFILE, "body\n");
	write_file("util-sccs-desc.txt", "a description\n");
	unlink("s.util-sccs-rt7");

	CHECK(run(admin_path, aargv) == 0);
	CHECK(file_contains("s.util-sccs-rt7", "\001c hello from -y"));
	CHECK(file_contains("s.util-sccs-rt7", "a description"));

	unlink("s.util-sccs-rt7");
	unlink("util-sccs-desc.txt");
}

/* -y omitted entirely synthesizes the real historical SCCS default
 * comment (src/util/admin.c's own header comment). */
static void test_admin_default_comment(void)
{
	char *aargv[] = { (char *)"admin", (char *)"-i" INFILE, (char *)"s.util-sccs-rt8", 0 };

	write_file(INFILE, "x\n");
	unlink("s.util-sccs-rt8");
	CHECK(run(admin_path, aargv) == 0);
	CHECK(file_contains("s.util-sccs-rt8", "\001c date and time created "));

	unlink("s.util-sccs-rt8");
}

/* ==== get(1p): the rest of its own paths =================================== */

static void test_get_without_p_writes_gfile(void)
{
	char *aargv[] = { (char *)"admin", (char *)"-i" INFILE, (char *)"s.util-sccs-rt9", 0 };
	char *gargv[] = { (char *)"get", (char *)"s.util-sccs-rt9", 0 };

	write_file(INFILE, "gfile content\n");
	unlink("s.util-sccs-rt9");
	unlink("util-sccs-rt9");

	check_roundtrip_ok(aargv, gargv);
	/* No -p: the status line goes to stdout instead of stderr. */
	CHECK(out_equals("1.1\n1 lines\n"));
	CHECK(file_equals_text("util-sccs-rt9", "gfile content\n"));

	unlink("s.util-sccs-rt9");
	unlink("util-sccs-rt9");
}

static void test_get_dash_r_matching_sid(void)
{
	char *aargv[] = { (char *)"admin", (char *)"-i" INFILE, (char *)"s.util-sccs-r10", 0 };
	char *gargv[] = { (char *)"get", (char *)"-p", (char *)"-r", (char *)"1.1", (char *)"s.util-sccs-r10", 0 };

	write_file(INFILE, "v\n");
	unlink("s.util-sccs-r10");
	check_roundtrip_ok(aargv, gargv);
	CHECK(out_equals("v\n"));

	unlink("s.util-sccs-r10");
}

static void test_get_dash_r_nonexistent_sid(void)
{
	char *aargv[] = { (char *)"admin", (char *)"-i" INFILE, (char *)"s.util-sccs-r11", 0 };
	char *gargv[] = { (char *)"get", (char *)"-p", (char *)"-r", (char *)"9.9", (char *)"s.util-sccs-r11", 0 };

	write_file(INFILE, "v\n");
	unlink("s.util-sccs-r11");
	CHECK(run(admin_path, aargv) == 0);
	check_run_err(get_path, gargv, 1, "no such delta");

	unlink("s.util-sccs-r11");
}

static void test_get_missing_operand(void)
{
	char *gargv[] = { (char *)"get", 0 };
	check_run_err(get_path, gargv, 1, "missing operand");
}

static void test_get_not_an_sfile(void)
{
	char *gargv[] = { (char *)"get", (char *)"-p", INFILE, 0 };
	write_file(INFILE, "not an s.file\n");
	CHECK(run(get_path, gargv) == 1);

	unlink(INFILE);
}

/* ==== the shell built-ins agree with the standalone executables ============ */

static void test_builtins_match_standalone(void)
{
	unlink("s.util-sccs-bi");
	CHECK(run_sh_c("admin -i" INFILE " s.util-sccs-bi") == 0);
	CHECK(run_sh_c("get -p s.util-sccs-bi") == 0);
	CHECK(out_equals("builtin content\n"));
	unlink("s.util-sccs-bi");
}

/* ==== scratch cleanup ======================================================= */

static void cleanup_artifacts(void)
{
	unlink(OUTFILE);
	unlink(ERRFILE);
	unlink(INFILE);
}

int main(int argc, char **argv)
{
	(void)argc;

	if (find_obj_root(argv[0]) != 0) {
		printf("SKIP util-sccs: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(admin_path, sizeof admin_path, "bin/admin.exe");
	path_for(get_path, sizeof get_path, "bin/get.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(admin_path, R_OK) != 0 || access(get_path, R_OK) != 0 || access(sh_path, R_OK) != 0) {
		printf("SKIP util-sccs: admin, get or sh binary is missing\n");
		return 77;
	}

	write_file(INFILE, "builtin content\n");

	test_admin_rejects_non_s_name();
	test_admin_missing_operand();
	test_admin_neither_i_nor_n();
	test_admin_refuses_unimplemented_option();

	test_roundtrip_basic();
	test_roundtrip_no_trailing_newline();
	test_admin_i_reads_stdin();
	test_admin_n_empty();
	test_admin_refuses_existing();
	test_admin_creates_readonly();
	test_admin_y_and_t();
	test_admin_default_comment();

	test_get_without_p_writes_gfile();
	test_get_dash_r_matching_sid();
	test_get_dash_r_nonexistent_sid();
	test_get_missing_operand();
	test_get_not_an_sfile();

	write_file(INFILE, "builtin content\n");
	test_builtins_match_standalone();

	cleanup_artifacts();

	if (fails) { printf("util-sccs: failures: %d\n", fails); return 1; }
	printf("util-sccs: all ok (admin, get -- standalone and builtin)\n");
	return 0;
}
