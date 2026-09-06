/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for ntlibc's Tier 4 "bigger engines" POSIX standard
 * utilities: `ed`, `m4` (XCU ed(1p), m4(1p)).  Same technique as
 * test/util-textio.c: the standalone obj/bin/<name>.exe is spawned as a
 * real process (via __spawn()+waitpid()) with stdin redirected from a
 * fixed file (both utilities are fundamentally stream-driven -- ed
 * reads a script of editor commands from stdin, m4 reads macro text
 * from stdin when given no file operand), and the shell built-in is
 * exercised too (via obj/sh/sh.exe -c), confirming both callers of
 * __util_ed_main()/__util_m4_main() (src/internal/util.h) agree.
 *
 * Every fixture this file creates lives inside one scratch directory
 * (SCRATCH below), named with this process's own pid, torn down
 * unconditionally on the way out -- see test/util-fileops.c's header for
 * why (leaving artifacts behind fails the reuse/SPDX lint stage).
 *
 * Spec pages consulted (https://pubs.opengroup.org/onlinepubs/9699919799/):
 *   utilities/ed.html utilities/m4.html
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>

extern char **environ;
int __spawn(const char *path, char *const argv[], char *const envp[]);

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* ---- locating obj/bin/{ed,m4}.exe and obj/sh/sh.exe -- same walk-up-
 * from-argv[0] technique as test/util-textio.c's own find_obj_root()/
 * path_for(). */
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
	obj_root[i - 1] = 0;                       /* strip "/util-edm4.exe" */

	n = strlen(obj_root);
	for (i = n; i > 0; i--)
		if (obj_root[i - 1] == '/' || obj_root[i - 1] == '\\') break;
	if (i == 0) return -1;
	obj_root[i - 1] = 0;                       /* strip "/test" */

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

static char ed_path[1024], m4_path[1024], sh_path[1024];

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

static char p1[600], p2[600];

static void mkpath(char *out, const char *rel)
{
	snprintf(out, 600, "%s/%s", scratch, rel);
}

/* ---- spawning and capturing, with an optional stdin redirect ---------- */

static char outfile[700], errfile[700];

/* Same dup2()-around-__spawn() technique as test/util-textio.c's own
 * run() -- see that file's own comment. */
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
	char buf[8192];
	slurp_into(outfile, buf, sizeof buf);
	return strcmp(buf, expect) == 0;
}

static int out_contains(const char *needle)
{
	char buf[8192];
	slurp_into(outfile, buf, sizeof buf);
	return strstr(buf, needle) != 0;
}

/* Checks a run's exit status was 0 (success) and its stdout was exactly
 * `expect` -- the shape shared by nearly every ed/m4 test below. */
static void check_ok_output(int status, const char *expect)
{
	CHECK(status == 0);
	CHECK(out_is(expect));
}

static void write_file(const char *path, const char *text)
{
	FILE *f = fopen(path, "wb");
	if (!f) { fails++; printf("FAIL: cannot write %s\n", path); return; }
	fputs(text, f);
	fclose(f);
}

static void read_file_into(const char *path, char *buf, size_t buflen)
{
	slurp_into(path, buf, buflen);
}

/* ==== ed(1p) ============================================================== */

/* a/p/q: append two lines, print the buffer, quit. -s suppresses the
 * byte-count that would otherwise appear after e/E/r/w -- irrelevant
 * here since no file operand was given, so ed starts with an empty
 * buffer and no counts are printed at all. */
static void test_ed_append_and_print(void)
{
	char *argv[] = { (char *)"ed", (char *)"-s", 0 };
	mkpath(p1, "ed-script1.txt");
	write_file(p1, "a\nhello\nworld\n.\n1,$p\nq\n");
	check_ok_output(run(ed_path, argv, p1), "hello\nworld\n");
}

/* i inserts BEFORE the addressed line; d deletes; = reports the line
 * number of the addressed line without touching the buffer. */
static void test_ed_insert_delete_linenum(void)
{
	char *argv[] = { (char *)"ed", (char *)"-s", 0 };
	mkpath(p1, "ed-script2.txt");
	write_file(p1, "a\nBBB\nCCC\n.\n1i\nAAA\n.\n$=\n1,$p\nq\n");
	check_ok_output(run(ed_path, argv, p1), "3\nAAA\nBBB\nCCC\n");
}

/* s/// with a numeric line range, plus the trailing `p` suffix to print
 * the affected line immediately, and `g` for "every match on the line". */
static void test_ed_substitute(void)
{
	char *argv[] = { (char *)"ed", (char *)"-s", 0 };
	mkpath(p1, "ed-script3.txt");
	write_file(p1, "a\nfoo bar foo\n.\n1s/foo/baz/g p\nq\n");
	check_ok_output(run(ed_path, argv, p1), "baz bar baz\n");
}

/* g/RE/command-list applies `p` to every line matching "b", in address
 * order -- a real exercise of global-command line marking, not just a
 * single substitution. */
static void test_ed_global_command(void)
{
	char *argv[] = { (char *)"ed", (char *)"-s", 0 };
	mkpath(p1, "ed-script4.txt");
	write_file(p1, "a\napple\nbanana\ncherry\nblueberry\n.\ng/b/p\nq\n");
	check_ok_output(run(ed_path, argv, p1), "banana\nblueberry\n");
}

/* w writes the buffer to a real file; a fresh `ed -s realfile` then r
 * reads it back in -- proves w/r round-trip through the filesystem, not
 * just in-memory state. */
static void test_ed_write_and_read(void)
{
	char *argvw[] = { (char *)"ed", (char *)"-s", 0 };
	char *argvr[] = { (char *)"ed", (char *)"-s", 0 };
	char content[8192];

	mkpath(p1, "ed-script5.txt");
	mkpath(p2, "ed-written.txt");
	write_file(p1, "a\none\ntwo\n.\nw ");
	{
		FILE *f = fopen(p1, "ab");
		fprintf(f, "%s\nq\n", p2);
		fclose(f);
	}
	CHECK(run(ed_path, argvw, p1) == 0);
	read_file_into(p2, content, sizeof content);
	CHECK(strcmp(content, "one\ntwo\n") == 0);

	mkpath(p1, "ed-script5b.txt");
	{
		FILE *f = fopen(p1, "wb");
		fprintf(f, "r %s\n1,$p\nq\n", p2);
		fclose(f);
	}
	CHECK(run(ed_path, argvr, p1) == 0);
	CHECK(out_is("one\ntwo\n"));
}

/* An unrecognized command diagnoses "?" to stdout and returns to command
 * mode -- ed must NOT abort the rest of the script after one bad line,
 * so the trailing `p` after the bad command still has to run. */
static void test_ed_bad_command_continues(void)
{
	char *argv[] = { (char *)"ed", (char *)"-s", 0 };
	mkpath(p1, "ed-script6.txt");
	write_file(p1, "a\nonly line\n.\nZ\n1p\nq\n");
	CHECK(run(ed_path, argv, p1) == 1); /* nonzero: an error occurred during the run */
	CHECK(out_contains("?\n"));
	CHECK(out_contains("only line\n"));
}

/* The shell builtin must agree exactly with the standalone binary. */
static void test_ed_builtin_matches_standalone(void)
{
	char cmd[512];
	mkpath(p1, "ed-script7.txt");
	write_file(p1, "a\nx\ny\nz\n.\n1,$p\nq\n");
	snprintf(cmd, sizeof cmd, "ed -s < %s", p1);
	check_ok_output(run_sh_c(cmd, 0), "x\ny\nz\n");
}

/* ==== m4(1p) ================================================================ */

/* define()/plain macro expansion: a macro with no arguments still
 * expands wherever its bare name appears in the input. */
static void test_m4_define_basic(void)
{
	char *argv[] = { (char *)"m4", 0 };
	mkpath(p1, "m4-1.m4");
	write_file(p1, "define(`GREETING', `hello, world')GREETING\n");
	check_ok_output(run(m4_path, argv, p1), "hello, world\n");
}

/* $1/$2 positional-parameter substitution in a macro's own defining
 * text, with a real two-argument call. */
static void test_m4_define_with_args(void)
{
	char *argv[] = { (char *)"m4", 0 };
	mkpath(p1, "m4-2.m4");
	write_file(p1, "define(`ADD2', `$1 and $2')ADD2(`x', `y')\n");
	check_ok_output(run(m4_path, argv, p1), "x and y\n");
}

/* ifdef()/ifelse(): both branches of ifdef, and ifelse's true/false
 * cases from one script. */
static void test_m4_ifdef_ifelse(void)
{
	char *argv[] = { (char *)"m4", 0 };
	mkpath(p1, "m4-3.m4");
	write_file(p1,
		"define(`X',`1')"
		"ifdef(`X',`defined',`undefined')\n"
		"ifdef(`NOPE',`defined',`undefined')\n"
		"ifelse(`a',`a',`same',`different')\n"
		"ifelse(`a',`b',`same',`different')\n");
	check_ok_output(run(m4_path, argv, p1), "defined\nundefined\nsame\ndifferent\n");
}

/* shift(): drops the first argument and re-quotes each remaining one;
 * combined with a recursive `define`d macro, this is the standard
 * "process a comma list one element at a time" idiom. */
static void test_m4_shift(void)
{
	char *argv[] = { (char *)"m4", 0 };
	mkpath(p1, "m4-4.m4");
	write_file(p1, "define(`REST', `shift($@)')REST(`a',`b',`c')\n");
	check_ok_output(run(m4_path, argv, p1), "b,c\n");
}

/* dnl discards through (and including) the next newline, and nothing
 * else -- text on the following line must survive untouched. */
static void test_m4_dnl(void)
{
	char *argv[] = { (char *)"m4", 0 };
	mkpath(p1, "m4-5.m4");
	write_file(p1, "before dnl this is gone\nafter\n");
	check_ok_output(run(m4_path, argv, p1), "before after\n");
}

/* changequote() switches the active quote characters; text quoted with
 * the OLD delimiters is no longer special once the new ones are active,
 * and the new delimiters themselves now suppress expansion. */
static void test_m4_changequote(void)
{
	char *argv[] = { (char *)"m4", 0 };
	mkpath(p1, "m4-6.m4");
	write_file(p1, "changequote([,])define([X],[1])X [X]\n");
	check_ok_output(run(m4_path, argv, p1), "1 X\n");
}

/* include() splices a whole file's contents into the input stream,
 * itself subject to further macro expansion as it is read. */
static void test_m4_include(void)
{
	char *argv[] = { (char *)"m4", 0 };
	mkpath(p1, "m4-7.m4");
	mkpath(p2, "m4-included.m4");
	write_file(p2, "define(`INC',`included-value')\n");
	{
		FILE *f = fopen(p1, "wb");
		fprintf(f, "include(`%s')INC\n", p2);
		fclose(f);
	}
	check_ok_output(run(m4_path, argv, p1), "\nincluded-value\n");
}

/* divert(1) redirects output into buffer 1 instead of the normal
 * stream; that buffered text only reaches real output once, at true
 * end-of-input, appended after whatever the main stream already wrote --
 * so "first" (never diverted) must appear before "second" (diverted)
 * even though "second" is textually written first in the script. */
static void test_m4_divert(void)
{
	char *argv[] = { (char *)"m4", 0 };
	mkpath(p1, "m4-8.m4");
	write_file(p1, "divert(1)second\ndivert(0)first\n");
	check_ok_output(run(m4_path, argv, p1), "first\nsecond\n");
}

/* len/index/substr/translit: the string builtins, each checked against
 * a hand-derived expected result. */
static void test_m4_string_builtins(void)
{
	char *argv[] = { (char *)"m4", 0 };
	mkpath(p1, "m4-9.m4");
	write_file(p1,
		"len(`hello')\n"
		"index(`hello world', `world')\n"
		"substr(`hello world', 6)\n"
		"substr(`hello world', 0, 5)\n"
		"translit(`hello', `el', `ip')\n");
	check_ok_output(run(m4_path, argv, p1), "5\n6\nworld\nhello\nhippo\n");
}

/* eval(): real arithmetic, including operator precedence (`*` before
 * `+`) and a radix argument. */
static void test_m4_eval(void)
{
	char *argv[] = { (char *)"m4", 0 };
	mkpath(p1, "m4-10.m4");
	write_file(p1, "eval(1+2*3)\nincr(41)\ndecr(1)\neval(255,16)\n");
	check_ok_output(run(m4_path, argv, p1), "7\n42\n0\nff\n");
}

/* Regression for a real stack-overflow bug: eval()'s recursive-descent
 * expression parser recursed once per '(' (ev_primary) and, separately,
 * once per leading unary operator (ev_unary), with no depth cap of its
 * own -- unlike dispatch_macro()'s M4_MAX_DEPTH, which only guards
 * NESTED MACRO CALLS and never sees this recursion at all. A single
 * eval() argument with enough nesting reliably crashed the process
 * (SIGSEGV) before M4_EVAL_MAX_DEPTH was added to src/util/m4.c's
 * ev_primary()/ev_unary(). This doesn't check the (undefined, since the
 * expression is malformed) numeric result -- only that m4 now fails the
 * expression cleanly (a diagnosed, ordinary exit status) instead of
 * dying to a signal (run() folds a signal death into 128+signum, e.g.
 * 139 for SIGSEGV, which is unmistakably not the plain `1` a clean
 * eval() error exits with). */
static void write_eval_bomb(const char *path, const char *prefix, int n, const char *suffix)
{
	FILE *f = fopen(path, "wb");
	int i;
	if (!f) { fails++; printf("FAIL: cannot write %s\n", path); return; }
	fputs("eval(", f);
	for (i = 0; i < n; i++) fputs(prefix, f);
	fputc('1', f);
	for (i = 0; i < n; i++) fputs(suffix, f);
	fputs(")\n", f);
	fclose(f);
}

static void test_m4_eval_deep_parens_does_not_crash(void)
{
	char *argv[] = { (char *)"m4", 0 };
	mkpath(p1, "m4-15.m4");
	write_eval_bomb(p1, "(", 200000, ")");
	CHECK(run(m4_path, argv, p1) == 1);
}

static void test_m4_eval_deep_unary_does_not_crash(void)
{
	char *argv[] = { (char *)"m4", 0 };
	mkpath(p1, "m4-16.m4");
	write_eval_bomb(p1, "-", 500000, "");
	CHECK(run(m4_path, argv, p1) == 1);
}

/* m4wrap(): its text is deferred until true end-of-input, not expanded
 * where the call appears. */
static void test_m4_wrap(void)
{
	char *argv[] = { (char *)"m4", 0 };
	mkpath(p1, "m4-11.m4");
	write_file(p1, "m4wrap(`at the end')main text\n");
	check_ok_output(run(m4_path, argv, p1), "main text\nat the end");
}

/* An unreadable include() is a real, diagnosed error (nonzero exit);
 * sinclude() of the same missing file is silently a no-op. */
static void test_m4_include_error_vs_sinclude(void)
{
	char *argv1[] = { (char *)"m4", 0 };
	char *argv2[] = { (char *)"m4", 0 };
	mkpath(p1, "m4-12.m4");
	write_file(p1, "include(`does-not-exist-anywhere.m4')\n");
	CHECK(run(m4_path, argv1, p1) != 0);

	mkpath(p2, "m4-13.m4");
	write_file(p2, "sinclude(`does-not-exist-anywhere.m4')ok\n");
	check_ok_output(run(m4_path, argv2, p2), "ok\n");
}

/* The shell builtin must agree exactly with the standalone binary. */
static void test_m4_builtin_matches_standalone(void)
{
	char cmd[512];
	mkpath(p1, "m4-14.m4");
	write_file(p1, "define(`N', `42')N squared is eval(N*N)\n");
	snprintf(cmd, sizeof cmd, "m4 < %s", p1);
	check_ok_output(run_sh_c(cmd, 0), "42 squared is 1764\n");
}

/* ==== main =============================================================== */

int main(int argc, char **argv)
{
	(void)argc;

	if (find_obj_root(argv[0]) != 0) {
		printf("SKIP util-edm4: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(ed_path, sizeof ed_path, "bin/ed.exe");
	path_for(m4_path, sizeof m4_path, "bin/m4.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(ed_path, R_OK) != 0 || access(m4_path, R_OK) != 0 ||
	    access(sh_path, R_OK) != 0) {
		printf("SKIP util-edm4: one or more of ed/m4/sh binaries is missing\n");
		return 77;
	}

	snprintf(scratch, sizeof scratch, "edm4-scratch-%ld", (long)getpid());
	raw_rmtree(scratch);   /* in case a previous crashed run left one behind */
	if (mkdir(scratch, 0700) != 0) {
		printf("SKIP util-edm4: cannot create scratch directory \"%s\"\n", scratch);
		return 77;
	}
	snprintf(outfile, sizeof outfile, "%s/out.txt", scratch);
	snprintf(errfile, sizeof errfile, "%s/err.txt", scratch);

	test_ed_append_and_print();
	test_ed_insert_delete_linenum();
	test_ed_substitute();
	test_ed_global_command();
	test_ed_write_and_read();
	test_ed_bad_command_continues();
	test_ed_builtin_matches_standalone();

	test_m4_define_basic();
	test_m4_define_with_args();
	test_m4_ifdef_ifelse();
	test_m4_shift();
	test_m4_dnl();
	test_m4_changequote();
	test_m4_include();
	test_m4_divert();
	test_m4_string_builtins();
	test_m4_eval();
	test_m4_eval_deep_parens_does_not_crash();
	test_m4_eval_deep_unary_does_not_crash();
	test_m4_wrap();
	test_m4_include_error_vs_sinclude();
	test_m4_builtin_matches_standalone();

	raw_rmtree(scratch);

	if (fails) { printf("util-edm4: failures: %d\n", fails); return 1; }
	printf("util-edm4: all ok (ed, m4 -- standalone and builtin)\n");
	return 0;
}
