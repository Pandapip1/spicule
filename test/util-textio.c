/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for the first batch of spicule's third tier of POSIX
 * standard utilities -- the text I/O tier: `cat`, `echo`, `tee`, `wc`,
 * `head`, `tail` (XCU cat(1p), echo(1p), tee(1p), wc(1p), head(1p),
 * tail(1p)).  Same shape as test/util-fileops.c and test/util-fsops.c
 * (see either file's header): each standalone obj/bin/NAME.exe is spawned
 * as a real process, and the shell built-in is exercised too, through
 * `obj/sh/sh.exe -c`, confirming both callers of __util_*_main()
 * (src/internal/util.h) agree.
 *
 * Unlike util-fileops.c/util-fsops.c, several of these utilities read
 * standard input rather than (or in addition to) file operands, so
 * run() below can redirect a child's stdin from a real file, the same
 * technique test/sh-main.c's run_sh() uses.
 *
 * Every fixture this file creates lives inside one scratch directory
 * (SCRATCH below), named with this process's own pid, torn down
 * unconditionally on the way out -- see test/util-fileops.c's header for
 * why (leaving artifacts behind fails the reuse/SPDX lint stage).
 *
 * Spec pages consulted (https://pubs.opengroup.org/onlinepubs/9699919799/):
 *   utilities/cat.html utilities/echo.html utilities/tee.html
 *   utilities/wc.html utilities/head.html utilities/tail.html
 */
/* usleep()/kill() below are gated behind _POSIX_SOURCE/_POSIX_C_SOURCE/
 * _XOPEN_SOURCE/_GNU_SOURCE/_BSD_SOURCE in spicule's own include/
 * unistd.h and include/signal.h, none of which a plain -std=c99 build
 * defines on its own. Same fix, same reasoning, as test/posix-stdlib.c's
 * own top-of-file _GNU_SOURCE define. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>

extern char **environ;
int __spawn(const char *path, char *const argv[], char *const envp[]);

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* ---- locating obj/bin/{cat,echo,tee,wc,head,tail}.exe and obj/sh/sh.exe
 * -- same walk-up-from-argv[0] technique as test/util-trivial.c's
 * find_obj_root()/path_for(). */
static char obj_root[1024];

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
	p[-1] = 0;                       /* strip "/util-textio.exe" */

	for (p = obj_root + strlen(obj_root); p > obj_root; p--)
		if (p[-1] == '/' || p[-1] == '\\') break;
	if (p == obj_root) return -1;
	p[-1] = 0;                       /* strip "/test" */

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

static char cat_path[1024], echo_path[1024], tee_path[1024];
static char wc_path[1024], head_path[1024], tail_path[1024], sh_path[1024];

/* ---- the scratch directory --------------------------------------------- */

static char scratch[128];

static void raw_rmtree(const char *path)
{
	struct stat st;
	DIR *d;
	struct dirent *de;

	if (lstat(path, &st) < 0) return;
	if (S_ISDIR(st.st_mode)) {
		d = opendir(path);
		if (d) {
			while ((de = readdir(d)) != NULL) {
				char child[600];
				if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
				snprintf(child, sizeof child, "%s/%s", path, de->d_name);
				raw_rmtree(child);
			}
			closedir(d);
		}
		rmdir(path);
	} else {
		unlink(path);
	}
}

static char p1[600], p2[600], p3[600];

static void mkpath(char *out, const char *rel)
{
	snprintf(out, 600, "%s/%s", scratch, rel);
}

/* ---- spawning and capturing, with an optional stdin redirect ---------- */

static char outfile[700], errfile[700];

/* Runs `path` with `args` (args[0] supplied by the caller), stdin from
 * `infile` if non-NULL (unchanged otherwise), stdout/stderr captured to
 * fixed files -- the same dup2()-around-__spawn() technique
 * test/sh-main.c's run_sh() and test/util-fileops.c's run() each use,
 * combined here since this file needs both a redirected stdin (cat/wc/
 * head/tail/tee with no file operand) and captured output. */
static int run(const char *path, char *const *args, const char *infile)
{
	int in = -1, out, err;
	int s0 = -1, s1, s2, pid, status;

	out = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	err = open(errfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (out < 0 || err < 0) { if (out >= 0) close(out); if (err >= 0) close(err); return -1; }
	if (infile) {
		in = open(infile, O_RDONLY);
		if (in < 0) { close(out); close(err); return -1; }
	}

	s1 = dup(1); s2 = dup(2);
	if (in >= 0) { s0 = dup(0); dup2(in, 0); close(in); }
	dup2(out, 1);
	dup2(err, 2);
	close(out); close(err);

	pid = __spawn(path, args, environ);

	if (s0 >= 0) { dup2(s0, 0); close(s0); }
	dup2(s1, 1); close(s1);
	dup2(s2, 2); close(s2);

	if (pid < 0) return -1;
	if (waitpid(pid, &status, 0) != pid) return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static int run_sh_c(const char *cmd, const char *infile)
{
	char *argv[4];
	argv[0] = (char *)"sh"; argv[1] = (char *)"-c"; argv[2] = (char *)cmd; argv[3] = 0;
	return run(sh_path, argv, infile);
}

/* Spawns `path` the same way run() does (stdout/stderr captured to
 * outfile/errfile), but does not wait for it -- for `tail -f`, which
 * has no natural exit, the caller polls its captured output, applies
 * whatever end condition it means to test (kill() a still-running
 * follow of a regular file, or close a pipe's write end to test the
 * documented "input exhausted" exit -- see src/util/tail.c's header),
 * then reaps it itself. `stdin_fd`, if >= 0, is an already-open
 * descriptor (e.g. a pipe's read end) to hand the child as fd 0 rather
 * than a file path -- __spawn() only ever looks at this process's own
 * fd 0/1/2 (src/process/spawn.c), so nothing else this process has
 * open (the pipe's write end included) leaks into the child. */
static int spawn_capturing(const char *path, char *const *args, int stdin_fd)
{
	int out, err;
	int s0 = -1, s1, s2, pid;

	out = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	err = open(errfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (out < 0 || err < 0) { if (out >= 0) close(out); if (err >= 0) close(err); return -1; }

	s1 = dup(1); s2 = dup(2);
	if (stdin_fd >= 0) { s0 = dup(0); dup2(stdin_fd, 0); }
	dup2(out, 1);
	dup2(err, 2);
	close(out); close(err);

	pid = __spawn(path, args, environ);

	if (s0 >= 0) { dup2(s0, 0); close(s0); }
	dup2(s1, 1); close(s1);
	dup2(s2, 2); close(s2);

	return pid;
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

static int out_is(const char *expect)
{
	char buf[4096];
	slurp_into(outfile, buf, sizeof buf);
	return strcmp(buf, expect) == 0;
}

static int out_contains(const char *needle)
{
	char buf[4096];
	slurp_into(outfile, buf, sizeof buf);
	return strstr(buf, needle) != 0;
}

static int err_contains(const char *needle)
{
	char buf[4096];
	slurp_into(errfile, buf, sizeof buf);
	return strstr(buf, needle) != 0;
}

/* Bounded poll for `needle` to show up in a still-running child's
 * captured stdout -- real synchronization on `tail -f`'s own observable
 * effect (same technique, and the same rationale, as
 * test/util-atcron.c's wait_for_file()), never a fixed sleep racing a
 * poll loop whose own interval (src/util/tail.c's TAIL_FOLLOW_POLL_NS)
 * this test has no business assuming. Polls every 50ms up to max_ms. */
static int wait_for_out_contains(const char *needle, long max_ms)
{
	long waited = 0;
	while (waited < max_ms) {
		if (out_contains(needle)) return 1;
		usleep(50000);
		waited += 50;
	}
	return out_contains(needle);
}

static void write_file(const char *path, const char *text)
{
	FILE *f = fopen(path, "wb");
	if (!f) { fails++; printf("FAIL: cannot write %s\n", path); return; }
	fputs(text, f);
	fclose(f);
}

static void append_file(const char *path, const char *text)
{
	FILE *f = fopen(path, "ab");
	if (!f) { fails++; printf("FAIL: cannot append %s\n", path); return; }
	fputs(text, f);
	fclose(f);
}

/* ==== cat(1p) ============================================================ */

static void test_cat_single_file(void)
{
	char *argv[3];

	mkpath(p1, "cat-a.txt");
	write_file(p1, "hello\nworld\n");

	argv[0] = (char *)"cat"; argv[1] = p1; argv[2] = 0;
	CHECK(run(cat_path, argv, 0) == 0);
	CHECK(out_is("hello\nworld\n"));
}

static void test_cat_multiple_files_concat(void)
{
	char *argv[4];

	mkpath(p1, "cat-b.txt");
	mkpath(p2, "cat-c.txt");
	write_file(p1, "AAA\n");
	write_file(p2, "BBB\n");

	argv[0] = (char *)"cat"; argv[1] = p1; argv[2] = p2; argv[3] = 0;
	CHECK(run(cat_path, argv, 0) == 0);
	CHECK(out_is("AAA\nBBB\n"));
}

static void test_cat_stdin_and_dash(void)
{
	char *argv0[2];
	char *argv1[3];

	mkpath(p1, "cat-stdin-src.txt");
	write_file(p1, "from stdin\n");

	/* no operand: reads standard input */
	argv0[0] = (char *)"cat"; argv0[1] = 0;
	CHECK(run(cat_path, argv0, p1) == 0);
	CHECK(out_is("from stdin\n"));

	/* "-" operand: same, spelled explicitly */
	argv1[0] = (char *)"cat"; argv1[1] = (char *)"-"; argv1[2] = 0;
	CHECK(run(cat_path, argv1, p1) == 0);
	CHECK(out_is("from stdin\n"));
}

static void test_cat_missing_operand_diagnoses_and_continues(void)
{
	char *argv[4];

	mkpath(p1, "cat-exists.txt");
	mkpath(p2, "cat-does-not-exist.txt");
	write_file(p1, "still here\n");

	argv[0] = (char *)"cat"; argv[1] = p2; argv[2] = p1; argv[3] = 0;
	CHECK(run(cat_path, argv, 0) != 0);
	CHECK(err_contains("cat:"));
	/* the operand that does exist was still copied */
	CHECK(out_is("still here\n"));
}

/* ==== echo(1p) ============================================================ */

static void test_echo_basic(void)
{
	char *argv[4];
	argv[0] = (char *)"echo"; argv[1] = (char *)"a"; argv[2] = (char *)"b"; argv[3] = 0;
	CHECK(run(echo_path, argv, 0) == 0);
	CHECK(out_is("a b\n"));
}

static void test_echo_no_args(void)
{
	char *argv[2];
	argv[0] = (char *)"echo"; argv[1] = 0;
	CHECK(run(echo_path, argv, 0) == 0);
	CHECK(out_is("\n"));
}

static void test_echo_dash_n_suppresses_newline(void)
{
	char *argv[3];
	argv[0] = (char *)"echo"; argv[1] = (char *)"-n"; argv[2] = 0;
	CHECK(run(echo_path, argv, 0) == 0);
	CHECK(out_is(""));

	{
		char *argv2[4];
		argv2[0] = (char *)"echo"; argv2[1] = (char *)"-n"; argv2[2] = (char *)"hi"; argv2[3] = 0;
		CHECK(run(echo_path, argv2, 0) == 0);
		CHECK(out_is("hi"));   /* no trailing newline */
	}
}

static void test_echo_no_backslash_interpretation(void)
{
	/* This project's echo never interprets backslash escapes -- see
	 * src/util/echo.c's header.  A literal backslash-n must come out
	 * as the two characters '\\' 'n', never a newline. */
	char *argv[3];
	argv[0] = (char *)"echo"; argv[1] = (char *)"a\\nb"; argv[2] = 0;
	CHECK(run(echo_path, argv, 0) == 0);
	CHECK(out_is("a\\nb\n"));
}

/* ==== tee(1p) ============================================================= */

static void test_tee_copies_to_stdout_and_file(void)
{
	char buf[256];
	char *argv[3];

	mkpath(p1, "tee-src.txt");
	mkpath(p2, "tee-out.txt");
	write_file(p1, "teed content\n");

	argv[0] = (char *)"tee"; argv[1] = p2; argv[2] = 0;
	CHECK(run(tee_path, argv, p1) == 0);
	CHECK(out_is("teed content\n"));
	CHECK(slurp_into(p2, buf, sizeof buf) == 0);
	CHECK(strcmp(buf, "teed content\n") == 0);
}

static void test_tee_append(void)
{
	char buf[256];
	char *argv[4];

	mkpath(p1, "tee-src2.txt");
	mkpath(p2, "tee-append.txt");
	write_file(p1, "second\n");
	write_file(p2, "first\n");

	argv[0] = (char *)"tee"; argv[1] = (char *)"-a"; argv[2] = p2; argv[3] = 0;
	CHECK(run(tee_path, argv, p1) == 0);
	CHECK(slurp_into(p2, buf, sizeof buf) == 0);
	CHECK(strcmp(buf, "first\nsecond\n") == 0);
}

static void test_tee_bad_destination_diagnoses_but_stdout_still_works(void)
{
	char *argv[3];

	mkpath(p1, "tee-src3.txt");
	mkpath(p2, "no-such-dir/tee-out.txt");
	write_file(p1, "goes to stdout anyway\n");

	argv[0] = (char *)"tee"; argv[1] = p2; argv[2] = 0;
	CHECK(run(tee_path, argv, p1) != 0);
	CHECK(err_contains("tee:"));
	CHECK(out_is("goes to stdout anyway\n"));
}

static void test_tee_dash_i_is_accepted(void)
{
	/* Unlike rm/cp/mv's -i (refused -- see those files' headers), tee's
	 * -i has a real implementation (signal(SIGINT, SIG_IGN), src/util/
	 * tee.c) -- it must be accepted and behave like a normal copy. */
	char buf[64];
	char *argv[4];

	mkpath(p1, "tee-src4.txt");
	mkpath(p2, "tee-i-out.txt");
	write_file(p1, "ignored sigint\n");

	argv[0] = (char *)"tee"; argv[1] = (char *)"-i"; argv[2] = p2; argv[3] = 0;
	CHECK(run(tee_path, argv, p1) == 0);
	CHECK(out_is("ignored sigint\n"));
	CHECK(slurp_into(p2, buf, sizeof buf) == 0);
	CHECK(strcmp(buf, "ignored sigint\n") == 0);
}

/* ==== wc(1p) ============================================================== */

static void test_wc_default_counts(void)
{
	char *argv[3];

	mkpath(p1, "wc-a.txt");
	write_file(p1, "a b\nc\n");   /* 2 lines, 3 words, 6 bytes */

	argv[0] = (char *)"wc"; argv[1] = p1; argv[2] = 0;
	CHECK(run(wc_path, argv, 0) == 0);
	CHECK(out_contains("2 3 6"));
	CHECK(out_contains(p1));
}

static void test_wc_dash_l_w_c_individually(void)
{
	char *argvl[4], *argvw[4], *argvc[4];
	char expect[700];

	mkpath(p1, "wc-b.txt");
	write_file(p1, "a b\nc\n");   /* 2 lines, 3 words, 6 bytes */

	argvl[0] = (char *)"wc"; argvl[1] = (char *)"-l"; argvl[2] = p1; argvl[3] = 0;
	CHECK(run(wc_path, argvl, 0) == 0);
	snprintf(expect, sizeof expect, "2 %s\n", p1);
	CHECK(out_is(expect));   /* a single requested field, plus the filename */

	argvw[0] = (char *)"wc"; argvw[1] = (char *)"-w"; argvw[2] = p1; argvw[3] = 0;
	CHECK(run(wc_path, argvw, 0) == 0);
	snprintf(expect, sizeof expect, "3 %s\n", p1);
	CHECK(out_is(expect));

	argvc[0] = (char *)"wc"; argvc[1] = (char *)"-c"; argvc[2] = p1; argvc[3] = 0;
	CHECK(run(wc_path, argvc, 0) == 0);
	snprintf(expect, sizeof expect, "6 %s\n", p1);
	CHECK(out_is(expect));
}

static void test_wc_dash_m_real_character_count(void)
{
	/* "e" + U+00E9 (UTF-8 0xC3 0xA9) + "\n": 4 bytes, 3 characters --
	 * see src/util/wc.c's header on why -m is a genuine mbrtowc()-based
	 * decode here rather than an alias for -c. */
	char *argvc[4], *argvm[4];
	char expect[700];

	mkpath(p1, "wc-utf8.txt");
	write_file(p1, "e\xC3\xA9\n");

	argvc[0] = (char *)"wc"; argvc[1] = (char *)"-c"; argvc[2] = p1; argvc[3] = 0;
	CHECK(run(wc_path, argvc, 0) == 0);
	snprintf(expect, sizeof expect, "4 %s\n", p1);
	CHECK(out_is(expect));

	argvm[0] = (char *)"wc"; argvm[1] = (char *)"-m"; argvm[2] = p1; argvm[3] = 0;
	CHECK(run(wc_path, argvm, 0) == 0);
	snprintf(expect, sizeof expect, "3 %s\n", p1);
	CHECK(out_is(expect));
}

static void test_wc_dash_c_and_dash_m_mutually_exclusive(void)
{
	char *argv[4];

	mkpath(p1, "wc-cm.txt");
	write_file(p1, "x\n");

	argv[0] = (char *)"wc"; argv[1] = (char *)"-cm"; argv[2] = p1; argv[3] = 0;
	CHECK(run(wc_path, argv, 0) != 0);
	CHECK(err_contains("wc:"));
}

static void test_wc_multiple_files_total(void)
{
	char *argv[4];

	mkpath(p1, "wc-m1.txt");
	mkpath(p2, "wc-m2.txt");
	write_file(p1, "one\n");        /* 1 line, 1 word, 4 bytes */
	write_file(p2, "two three\n");  /* 1 line, 2 words, 10 bytes */

	argv[0] = (char *)"wc"; argv[1] = p1; argv[2] = p2; argv[3] = 0;
	CHECK(run(wc_path, argv, 0) == 0);
	CHECK(out_contains("1 1 4"));
	CHECK(out_contains("1 2 10"));
	CHECK(out_contains("2 3 14 total"));
}

static void test_wc_missing_file_diagnoses(void)
{
	char *argv[3];

	mkpath(p1, "wc-does-not-exist.txt");
	argv[0] = (char *)"wc"; argv[1] = p1; argv[2] = 0;
	CHECK(run(wc_path, argv, 0) != 0);
	CHECK(err_contains("wc:"));
}

/* ==== head(1p) ============================================================ */

static void build_numbered_lines(const char *path, int n)
{
	FILE *f = fopen(path, "wb");
	int i;
	if (!f) { fails++; return; }
	for (i = 1; i <= n; i++) fprintf(f, "line%d\n", i);
	fclose(f);
}

static void test_head_default_10_lines(void)
{
	char *argv[3];

	mkpath(p1, "head-15.txt");
	build_numbered_lines(p1, 15);

	argv[0] = (char *)"head"; argv[1] = p1; argv[2] = 0;
	CHECK(run(head_path, argv, 0) == 0);
	CHECK(out_is("line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\n"));
}

static void test_head_dash_n(void)
{
	char *argv[5];

	mkpath(p1, "head-5.txt");
	build_numbered_lines(p1, 5);

	argv[0] = (char *)"head"; argv[1] = (char *)"-n"; argv[2] = (char *)"2"; argv[3] = p1; argv[4] = 0;
	CHECK(run(head_path, argv, 0) == 0);
	CHECK(out_is("line1\nline2\n"));
}

static void test_head_fewer_lines_than_n(void)
{
	char *argv[5];

	mkpath(p1, "head-3.txt");
	build_numbered_lines(p1, 3);

	argv[0] = (char *)"head"; argv[1] = (char *)"-n"; argv[2] = (char *)"10"; argv[3] = p1; argv[4] = 0;
	CHECK(run(head_path, argv, 0) == 0);
	CHECK(out_is("line1\nline2\nline3\n"));
}

static void test_head_multiple_files_banner(void)
{
	char *argv[6];

	mkpath(p1, "head-ba.txt");
	mkpath(p2, "head-bb.txt");
	build_numbered_lines(p1, 3);
	build_numbered_lines(p2, 3);

	argv[0] = (char *)"head"; argv[1] = (char *)"-n"; argv[2] = (char *)"1";
	argv[3] = p1; argv[4] = p2; argv[5] = 0;
	CHECK(run(head_path, argv, 0) == 0);
	{
		char expect[1400];
		snprintf(expect, sizeof expect, "==> %s <==\nline1\n\n==> %s <==\nline1\n", p1, p2);
		CHECK(out_is(expect));
	}
}

static void test_head_missing_file_diagnoses(void)
{
	char *argv[3];

	mkpath(p1, "head-does-not-exist.txt");
	argv[0] = (char *)"head"; argv[1] = p1; argv[2] = 0;
	CHECK(run(head_path, argv, 0) != 0);
	CHECK(err_contains("head:"));
}

static void test_head_invalid_n_is_diagnosed(void)
{
	char *argv[4];

	mkpath(p1, "head-n0.txt");
	write_file(p1, "x\n");

	argv[0] = (char *)"head"; argv[1] = (char *)"-n"; argv[2] = (char *)"0"; argv[3] = 0;
	CHECK(run(head_path, argv, 0) != 0);
	CHECK(err_contains("head:"));
}

/* ==== tail(1p) ============================================================ */

static void test_tail_default_last_10_lines(void)
{
	char *argv[3];

	mkpath(p1, "tail-15.txt");
	build_numbered_lines(p1, 15);

	argv[0] = (char *)"tail"; argv[1] = p1; argv[2] = 0;
	CHECK(run(tail_path, argv, 0) == 0);
	CHECK(out_is("line6\nline7\nline8\nline9\nline10\nline11\nline12\nline13\nline14\nline15\n"));
}

static void test_tail_dash_n(void)
{
	char *argv[5];

	mkpath(p1, "tail-5.txt");
	build_numbered_lines(p1, 5);

	argv[0] = (char *)"tail"; argv[1] = (char *)"-n"; argv[2] = (char *)"2"; argv[3] = p1; argv[4] = 0;
	CHECK(run(tail_path, argv, 0) == 0);
	CHECK(out_is("line4\nline5\n"));
}

static void test_tail_fewer_lines_than_n(void)
{
	char *argv[5];

	mkpath(p1, "tail-3.txt");
	build_numbered_lines(p1, 3);

	argv[0] = (char *)"tail"; argv[1] = (char *)"-n"; argv[2] = (char *)"10"; argv[3] = p1; argv[4] = 0;
	CHECK(run(tail_path, argv, 0) == 0);
	CHECK(out_is("line1\nline2\nline3\n"));
}

static void test_tail_plus_n_from_beginning(void)
{
	char *argv[5];

	mkpath(p1, "tail-plus.txt");
	build_numbered_lines(p1, 5);

	argv[0] = (char *)"tail"; argv[1] = (char *)"-n"; argv[2] = (char *)"+3"; argv[3] = p1; argv[4] = 0;
	CHECK(run(tail_path, argv, 0) == 0);
	CHECK(out_is("line3\nline4\nline5\n"));
}

static void test_tail_dash_c(void)
{
	char *argv[5];

	mkpath(p1, "tail-bytes.txt");
	write_file(p1, "abcdef");

	argv[0] = (char *)"tail"; argv[1] = (char *)"-c"; argv[2] = (char *)"3"; argv[3] = p1; argv[4] = 0;
	CHECK(run(tail_path, argv, 0) == 0);
	CHECK(out_is("def"));
}

/* -f on a regular file: never terminates on its own (the file can
 * always grow again), so this drives it the way test/util-atcron.c
 * drives atd/crond -- spawn, poll the observable effect, kill(),
 * reap -- rather than the blocking run() every other test in this file
 * uses. Exercises the size-polling half of src/util/tail.c's
 * tail_follow(): the appended line must show up without the file
 * having been closed and reopened, and SIGTERM must actually end the
 * process rather than leaving it stuck in the poll loop. */
static void test_tail_dash_f_follows_appended_data(void)
{
	char *argv[4];
	int pid, status;

	mkpath(p1, "tail-f.txt");
	write_file(p1, "line1\n");

	argv[0] = (char *)"tail"; argv[1] = (char *)"-f"; argv[2] = p1; argv[3] = 0;
	pid = spawn_capturing(tail_path, argv, -1);
	CHECK(pid >= 0);
	if (pid < 0) return;

	CHECK(wait_for_out_contains("line1\n", 3000));

	append_file(p1, "line2\n");
	CHECK(wait_for_out_contains("line1\nline2\n", 3000));

	kill(pid, SIGTERM);
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);

	CHECK(out_is("line1\nline2\n"));
}

/* -f with no file operand (stdin) reading from a pipe: unlike a
 * regular file, a pipe's write end closing really is the end -- no
 * kill() needed, tail_follow()'s single-non-regular-target branch
 * (src/util/tail.c) reads it in a plain blocking loop and returns the
 * moment read() reports EOF.  This is the "or the input is exhausted
 * in a non-blocking context" exit this file's header describes,
 * exercised end to end: a real child process, a real pipe, a real
 * clean exit(0) with no signal involved. */
static void test_tail_dash_f_pipe_exits_at_eof(void)
{
	char *argv[3];
	int fds[2];
	int pid, status;

	/* O_CLOEXEC on both ends: __spawn() (src/process/spawn.c) inherits
	 * any descriptor this process has open and not close-on-exec into
	 * every child it starts -- real fork+exec semantics, not something
	 * special to fd 0/1/2 (confirmed against both backends: Linux's
	 * clone()+execve() only drops a real FD_CLOEXEC-flagged fd, and NT's
	 * __fd_runtime_data(), src/internal/nt/plat_fd_init.c, explicitly
	 * passes "everything open and not close-on-exec"). A plain pipe(2)
	 * here would leave fds[1] (this write end) inheritable, so *every*
	 * child spawn_capturing() below starts -- tail itself included --
	 * would come up holding its own extra, unintentional copy of the
	 * write end open on fd 0's underlying pipe. That copy keeps the
	 * pipe's read side from ever seeing EOF once this test closes its
	 * own fds[1], because the kernel still sees a live writer: the tail
	 * child's own leaked descriptor. tail_follow()'s pipe branch
	 * (src/util/tail.c) would then block in read() forever, and the
	 * waitpid() below would hang right along with it -- reproduced
	 * live: obj/test/util-textio.exe genuinely never returns without
	 * this fix. Marking the pipe close-on-exec keeps both ends out of
	 * any child's table except the one descriptor spawn_capturing()
	 * explicitly re-homes onto fd 0 (dup2() -- src/unistd/dup.c's
	 * dup_to() -- always clears O_CLOEXEC on its target regardless of
	 * the source, so tail still gets a normal, inheritable stdin). */
	CHECK(pipe2(fds, O_CLOEXEC) == 0);

	argv[0] = (char *)"tail"; argv[1] = (char *)"-f"; argv[2] = 0;
	pid = spawn_capturing(tail_path, argv, fds[0]);
	CHECK(pid >= 0);
	close(fds[0]);
	if (pid < 0) { close(fds[1]); return; }

	CHECK(write(fds[1], "a\nb\n", 4) == 4);
	close(fds[1]);   /* EOF: tail -f on a pipe must now exit on its own */

	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(out_is("a\nb\n"));
}

static void test_tail_multiple_files_banner(void)
{
	char *argv[6];

	mkpath(p1, "tail-ba.txt");
	mkpath(p2, "tail-bb.txt");
	build_numbered_lines(p1, 2);
	build_numbered_lines(p2, 2);

	argv[0] = (char *)"tail"; argv[1] = (char *)"-n"; argv[2] = (char *)"1";
	argv[3] = p1; argv[4] = p2; argv[5] = 0;
	CHECK(run(tail_path, argv, 0) == 0);
	{
		char expect[1400];
		snprintf(expect, sizeof expect, "==> %s <==\nline2\n\n==> %s <==\nline2\n", p1, p2);
		CHECK(out_is(expect));
	}
}

/* ==== the shell built-ins agree with the standalone executables ========= */

static void test_builtins_match_standalone(void)
{
	char cmd[1400];

	mkpath(p1, "bi-src.txt");
	write_file(p1, "one\ntwo\nthree\n");

	sprintf(cmd, "cat '%s'", p1);
	CHECK(run_sh_c(cmd, 0) == 0);
	CHECK(out_is("one\ntwo\nthree\n"));

	CHECK(run_sh_c("echo hi there", 0) == 0);
	CHECK(out_is("hi there\n"));

	/* redirected from a file rather than passed as an operand, so the
	 * expected output has no filename field to account for. */
	sprintf(cmd, "wc -l < '%s'", p1);
	CHECK(run_sh_c(cmd, 0) == 0);
	CHECK(out_is("3\n"));

	sprintf(cmd, "head -n 2 '%s'", p1);
	CHECK(run_sh_c(cmd, 0) == 0);
	CHECK(out_is("one\ntwo\n"));

	sprintf(cmd, "tail -n 2 '%s'", p1);
	CHECK(run_sh_c(cmd, 0) == 0);
	CHECK(out_is("two\nthree\n"));

	mkpath(p3, "bi-tee-out.txt");
	sprintf(cmd, "tee '%s'", p3);
	CHECK(run_sh_c(cmd, p1) == 0);
	CHECK(out_is("one\ntwo\nthree\n"));
	{
		char buf[128];
		CHECK(slurp_into(p3, buf, sizeof buf) == 0);
		CHECK(strcmp(buf, "one\ntwo\nthree\n") == 0);
	}
}

/* ==== main =============================================================== */

int main(int argc, char **argv)
{
	(void)argc;

	if (find_obj_root(argv[0]) != 0) {
		printf("SKIP util-textio: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(cat_path, sizeof cat_path, "bin/cat.exe");
	path_for(echo_path, sizeof echo_path, "bin/echo.exe");
	path_for(tee_path, sizeof tee_path, "bin/tee.exe");
	path_for(wc_path, sizeof wc_path, "bin/wc.exe");
	path_for(head_path, sizeof head_path, "bin/head.exe");
	path_for(tail_path, sizeof tail_path, "bin/tail.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(cat_path, R_OK) != 0 || access(echo_path, R_OK) != 0 ||
	    access(tee_path, R_OK) != 0 || access(wc_path, R_OK) != 0 ||
	    access(head_path, R_OK) != 0 || access(tail_path, R_OK) != 0 ||
	    access(sh_path, R_OK) != 0) {
		printf("SKIP util-textio: one or more of cat/echo/tee/wc/head/tail/sh binaries is missing\n");
		return 77;
	}

	snprintf(scratch, sizeof scratch, "textio-scratch-%ld", (long)getpid());
	raw_rmtree(scratch);   /* in case a previous crashed run left one behind */
	if (mkdir(scratch, 0700) != 0) {
		printf("SKIP util-textio: cannot create scratch directory \"%s\"\n", scratch);
		return 77;
	}
	snprintf(outfile, sizeof outfile, "%s/out.txt", scratch);
	snprintf(errfile, sizeof errfile, "%s/err.txt", scratch);

	test_cat_single_file();
	test_cat_multiple_files_concat();
	test_cat_stdin_and_dash();
	test_cat_missing_operand_diagnoses_and_continues();

	test_echo_basic();
	test_echo_no_args();
	test_echo_dash_n_suppresses_newline();
	test_echo_no_backslash_interpretation();

	test_tee_copies_to_stdout_and_file();
	test_tee_append();
	test_tee_bad_destination_diagnoses_but_stdout_still_works();
	test_tee_dash_i_is_accepted();

	test_wc_default_counts();
	test_wc_dash_l_w_c_individually();
	test_wc_dash_m_real_character_count();
	test_wc_dash_c_and_dash_m_mutually_exclusive();
	test_wc_multiple_files_total();
	test_wc_missing_file_diagnoses();

	test_head_default_10_lines();
	test_head_dash_n();
	test_head_fewer_lines_than_n();
	test_head_multiple_files_banner();
	test_head_missing_file_diagnoses();
	test_head_invalid_n_is_diagnosed();

	test_tail_default_last_10_lines();
	test_tail_dash_n();
	test_tail_fewer_lines_than_n();
	test_tail_plus_n_from_beginning();
	test_tail_dash_c();
	test_tail_dash_f_follows_appended_data();
	test_tail_dash_f_pipe_exits_at_eof();
	test_tail_multiple_files_banner();

	test_builtins_match_standalone();

	raw_rmtree(scratch);

	if (fails) { printf("util-textio: failures: %d\n", fails); return 1; }
	printf("util-textio: all ok (cat, echo, tee, wc, head, tail -- standalone and builtin)\n");
	return 0;
}
