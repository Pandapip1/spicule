/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for spicule's second tier of POSIX standard utilities:
 * `pwd`, `basename`, `dirname`, `pathchk` (XCU pwd(1p), basename(1p),
 * dirname(1p), pathchk(1p)), and the two non-XCU fellow travelers
 * `readlink` and `realpath` (src/util/readlink.c's own comment explains
 * why they are here).  Same technique as test/util-trivial.c, which
 * covers the first tier (true/false/test): each standalone obj/bin/NAME.exe
 * is spawned as a real process (test/sh-main.c's technique), and each
 * utility's shell built-in is exercised too via `obj/sh/sh.exe -c`, so
 * both callers of __util_*_main() (src/internal/util.h) are checked to
 * agree, not just one of them.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
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

/* Same walk-up-from-argv[0] technique as test/util-trivial.c's
 * find_obj_root() -- see that file's header for why. */
static int find_obj_root(const char *argv0)
{
	if (!argv0 || !*argv0) return -1;
	if (strlen(argv0) >= sizeof obj_root) return -1;
	strcpy(obj_root, argv0);

	if (strip_last_component(obj_root) != 0) return -1; /* strip "/util-pathnames.exe" */
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

#define OUTFILE "util-pathnames-out.txt"
#define ERRFILE "util-pathnames-err.txt"

/* Same shape as test/util-trivial.c's run(): spawns `path` with `args`
 * (argv[0] supplied by the caller), capturing stdout/stderr to fixed
 * files, and returns the exit status (-1 if the child could not even be
 * started). */
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

/* Reads OUTFILE and strips exactly one trailing '\n' -- every one of
 * these utilities writes "%s\n", so comparing against the line without
 * its terminator is the natural check. */
static void out_line(char *buf, size_t buflen)
{
	size_t n;
	slurp_into(OUTFILE, buf, buflen);
	n = strlen(buf);
	if (n && buf[n - 1] == '\n') buf[n - 1] = 0;
}

static int out_is(const char *expect)
{
	char buf[4096];
	out_line(buf, sizeof buf);
	return strcmp(buf, expect) == 0;
}

/* Runs `path` with `args`, checking it exits 0 and its stdout is
 * exactly `expect` -- the shape shared by most single-output tests
 * below. */
static void check_ok_output(const char *path, char *const *args, const char *expect)
{
	CHECK(run(path, args) == 0);
	CHECK(out_is(expect));
}

static char pwd_path[1024], basename_path[1024], dirname_path[1024];
static char pathchk_path[1024], readlink_path[1024], realpath_path[1024];
static char sh_path[1024];

/* ---- pwd(1p) ----------------------------------------------------------- */

static void test_pwd_matches_getcwd(void)
{
	char *cwd = getcwd(0, 0);
	char *argv[] = { (char *)"pwd", 0 };
	CHECK(cwd != 0);
	CHECK(run(pwd_path, argv) == 0);
	CHECK(cwd && out_is(cwd));
	free(cwd);
}

static void test_pwd_accepts_L_and_P(void)
{
	char *argvL[] = { (char *)"pwd", (char *)"-L", 0 };
	char *argvP[] = { (char *)"pwd", (char *)"-P", 0 };
	CHECK(run(pwd_path, argvL) == 0);
	CHECK(run(pwd_path, argvP) == 0);
}

static void test_pwd_rejects_operand(void)
{
	/* pwd(1p) OPERANDS: "None." -- an operand is refused, not silently
	 * ignored. */
	char *argv[] = { (char *)"pwd", (char *)"/tmp", 0 };
	CHECK(run(pwd_path, argv) == 2);
	CHECK(err_contains("pwd:"));
}

/* ---- basename(1p) ------------------------------------------------------- */

static void test_basename_strips_directory(void)
{
	char *argv[] = { (char *)"basename", (char *)"/usr/bin/foo", 0 };
	check_ok_output(basename_path, argv, "foo");
}

static void test_basename_root(void)
{
	char *argv[] = { (char *)"basename", (char *)"/", 0 };
	check_ok_output(basename_path, argv, "/");
}

static void test_basename_strips_suffix(void)
{
	char *argv[] = { (char *)"basename", (char *)"/usr/lib/foo.sh", (char *)".sh", 0 };
	check_ok_output(basename_path, argv, "foo");
}

static void test_basename_suffix_identical_to_whole_is_kept(void)
{
	/* "is not identical to the characters remaining in string" --
	 * removing ".sh" from ".sh" would be the whole string, so it must
	 * NOT be removed. */
	char *argv[] = { (char *)"basename", (char *)".sh", (char *)".sh", 0 };
	check_ok_output(basename_path, argv, ".sh");
}

static void test_basename_bad_argc(void)
{
	char *argv0[] = { (char *)"basename", 0 };
	char *argv3[] = { (char *)"basename", (char *)"a", (char *)"b", (char *)"c", 0 };
	CHECK(run(basename_path, argv0) == 2);
	CHECK(run(basename_path, argv3) == 2);
}

/* ---- dirname(1p) --------------------------------------------------------- */

static void test_dirname_strips_last_component(void)
{
	char *argv[] = { (char *)"dirname", (char *)"/usr/bin/foo", 0 };
	check_ok_output(dirname_path, argv, "/usr/bin");
}

static void test_dirname_no_slash_is_dot(void)
{
	char *argv[] = { (char *)"dirname", (char *)"foo", 0 };
	check_ok_output(dirname_path, argv, ".");
}

static void test_dirname_bad_argc(void)
{
	char *argv[] = { (char *)"dirname", (char *)"a", (char *)"b", 0 };
	CHECK(run(dirname_path, argv) == 2);
}

/* ---- pathchk(1p) --------------------------------------------------------- */

static void test_pathchk_ok(void)
{
	char *argv[] = { (char *)"pathchk", (char *)"a/b/c", 0 };
	CHECK(run(pathchk_path, argv) == 0);
}

static void test_pathchk_long_component(void)
{
	static char comp[300];
	char *argv[3];
	memset(comp, 'a', sizeof comp - 1);
	comp[sizeof comp - 1] = 0;
	argv[0] = (char *)"pathchk"; argv[1] = comp; argv[2] = 0;
	CHECK(run(pathchk_path, argv) == 1);
	CHECK(err_contains("pathchk:"));
}

static void test_pathchk_invalid_byte(void)
{
	/* '?' is one of NT's reserved characters (this file's own
	 * src/util/pathchk.c comment lists the set). */
	char *argv[] = { (char *)"pathchk", (char *)"foo?bar", 0 };
	CHECK(run(pathchk_path, argv) == 1);
}

static void test_pathchk_refuses_p_and_P(void)
{
	char *argvp[] = { (char *)"pathchk", (char *)"-p", (char *)"a", 0 };
	char *argvP[] = { (char *)"pathchk", (char *)"-P", (char *)"a", 0 };
	CHECK(run(pathchk_path, argvp) == 2);
	CHECK(run(pathchk_path, argvP) == 2);
}

static void test_pathchk_missing_operand(void)
{
	char *argv[] = { (char *)"pathchk", 0 };
	CHECK(run(pathchk_path, argv) == 2);
}

/* ---- readlink -------------------------------------------------------- */

#define LINKNAME "util-pathnames-link"
#define LINKTARGET "util-pathnames-target"

static void test_readlink_reads_target(void)
{
	char *argv[] = { (char *)"readlink", (char *)LINKNAME, 0 };

	unlink(LINKNAME);
	if (symlink(LINKTARGET, LINKNAME) != 0) {
		/* Creating a symlink can need a privilege this account does not
		 * have -- skip rather than fail the whole suite over an
		 * environment limitation unrelated to __util_readlink_main(). */
		printf("SKIP readlink-target: symlink() unavailable in this environment\n");
		return;
	}
	CHECK(run(readlink_path, argv) == 0);
	CHECK(out_is(LINKTARGET));
	unlink(LINKNAME);
}

static void test_readlink_non_symlink_fails(void)
{
	char *argv[] = { (char *)"readlink", (char *)OUTFILE, 0 };
	/* OUTFILE always exists by this point (run() just created it) and is
	 * an ordinary file, never a symlink. */
	CHECK(run(readlink_path, argv) != 0);
	CHECK(err_contains("readlink:"));
}

static void test_readlink_missing_operand(void)
{
	char *argv[] = { (char *)"readlink", 0 };
	CHECK(run(readlink_path, argv) == 2);
}

/* ---- realpath ---------------------------------------------------------- */

static void test_realpath_matches_getcwd(void)
{
	char *cwd = getcwd(0, 0);
	char *argv[] = { (char *)"realpath", (char *)".", 0 };
	CHECK(cwd != 0);
	CHECK(run(realpath_path, argv) == 0);
	CHECK(cwd && out_is(cwd));
	free(cwd);
}

static void test_realpath_nonexistent_fails(void)
{
	char *argv[] = { (char *)"realpath", (char *)"util-pathnames-does-not-exist", 0 };
	CHECK(run(realpath_path, argv) != 0);
	CHECK(err_contains("realpath:"));
}

static void test_realpath_missing_operand(void)
{
	char *argv[] = { (char *)"realpath", 0 };
	CHECK(run(realpath_path, argv) == 2);
}

/* ---- the shell built-ins agree with the standalone executables --------- */

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

static void test_builtins_match_standalone(void)
{
	CHECK(run_sh_c("basename /a/b/c") == 0);
	CHECK(out_is("c"));
	CHECK(run_sh_c("dirname /a/b/c") == 0);
	CHECK(out_is("/a/b"));
	CHECK(run_sh_c("pwd") == 0);
	CHECK(run_sh_c("pathchk a/b/c") == 0);
	CHECK(run_sh_c("pathchk -p a") == 2);
	CHECK(run_sh_c("realpath .") == 0);
	CHECK(run_sh_c("readlink") == 2);
}

static void cleanup_artifacts(void)
{
	unlink(OUTFILE);
	unlink(ERRFILE);
	unlink(LINKNAME);
}

int main(int argc, char **argv)
{
	(void)argc;

	if (find_obj_root(argv[0]) != 0) {
		printf("SKIP util-pathnames: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(pwd_path, sizeof pwd_path, "bin/pwd.exe");
	path_for(basename_path, sizeof basename_path, "bin/basename.exe");
	path_for(dirname_path, sizeof dirname_path, "bin/dirname.exe");
	path_for(pathchk_path, sizeof pathchk_path, "bin/pathchk.exe");
	path_for(readlink_path, sizeof readlink_path, "bin/readlink.exe");
	path_for(realpath_path, sizeof realpath_path, "bin/realpath.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(pwd_path, R_OK) != 0 || access(basename_path, R_OK) != 0 ||
	    access(dirname_path, R_OK) != 0 || access(pathchk_path, R_OK) != 0 ||
	    access(readlink_path, R_OK) != 0 || access(realpath_path, R_OK) != 0 ||
	    access(sh_path, R_OK) != 0) {
		printf("SKIP util-pathnames: one or more of pwd/basename/dirname/pathchk/"
		       "readlink/realpath/sh binaries is missing\n");
		return 77;
	}

	test_pwd_matches_getcwd();
	test_pwd_accepts_L_and_P();
	test_pwd_rejects_operand();

	test_basename_strips_directory();
	test_basename_root();
	test_basename_strips_suffix();
	test_basename_suffix_identical_to_whole_is_kept();
	test_basename_bad_argc();

	test_dirname_strips_last_component();
	test_dirname_no_slash_is_dot();
	test_dirname_bad_argc();

	test_pathchk_ok();
	test_pathchk_long_component();
	test_pathchk_invalid_byte();
	test_pathchk_refuses_p_and_P();
	test_pathchk_missing_operand();

	test_readlink_reads_target();
	test_readlink_non_symlink_fails();
	test_readlink_missing_operand();

	test_realpath_matches_getcwd();
	test_realpath_nonexistent_fails();
	test_realpath_missing_operand();

	test_builtins_match_standalone();

	cleanup_artifacts();

	if (fails) { printf("util-pathnames: failures: %d\n", fails); return 1; }
	printf("util-pathnames: all ok (pwd, basename, dirname, pathchk, readlink, "
	       "realpath -- standalone and builtin)\n");
	return 0;
}
