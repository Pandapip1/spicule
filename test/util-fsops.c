/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for spicule's filesystem-mutating POSIX standard
 * utilities: `mkdir`, `rmdir`, `mkfifo`, `ln`, `chmod`, `touch` (XCU
 * mkdir(1p), rmdir(1p), mkfifo(1p), ln(1p), chmod(1p), touch(1p)).  Same
 * technique as test/util-trivial.c: the standalone obj/bin/<name>.exe is
 * spawned as a real process (via __spawn()+waitpid()), and the shell
 * built-in is exercised too (via obj/sh/sh.exe -c), confirming both
 * callers of __util_<name>_main() (src/internal/util.h) agree -- but
 * unlike util-trivial.c's four, every utility here has a real,
 * observable filesystem effect, so each test also checks that effect
 * directly with this tree's own stat()/access()/lstat(), not just the
 * spawned utility's exit status.
 *
 * All fixtures live under a scratch subdirectory of the test's own
 * working directory (created fresh in main(), removed again by
 * cleanup_artifacts()) rather than loose in the repo root -- see
 * test/sh-main.c's own cleanup_artifacts() for why: tools/run-tests.py
 * runs from a private temporary directory, but a developer who runs
 * obj/test/util-fsops.exe directly from the checkout would otherwise
 * leave real files behind that fail the reuse/SPDX lint stage.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>

extern char **environ;
int __spawn(const char *path, char *const argv[], char *const envp[]);

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static char obj_root[1024];

/* Same walk-up-from-argv[0] technique as test/util-trivial.c's
 * find_obj_root(), copied rather than shared since these are two
 * independent translation units and the whole function is four lines. */
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
	obj_root[i - 1] = 0; /* strip "/util-fsops.exe" */

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

#define OUTFILE "util-fsops-out.txt"
#define ERRFILE "util-fsops-err.txt"

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

/* Checks a run was refused outright: nonzero exit, with a diagnostic
 * containing `needle` -- the shape shared by most error-path tests below. */
static void check_refused(int status, const char *needle)
{
	CHECK(status != 0);
	CHECK(err_contains(needle));
}

static char mkdir_path[1024], rmdir_path[1024], mkfifo_path[1024];
static char ln_path[1024], chmod_path[1024], touch_path[1024], sh_path[1024];

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

/* ==== mkdir(1p) ========================================================= */

static void test_mkdir_basic_and_default_mode(void)
{
	char *argv[] = { (char *)"mkdir", (char *)"scratch/d1", 0 };
	struct stat st;

	CHECK(run(mkdir_path, argv) == 0);
	CHECK(stat("scratch/d1", &st) == 0 && S_ISDIR(st.st_mode));
	/* Every child process here starts with the fresh default umask
	 * (022, src/stat/chmod.c) since umask is a per-process variable
	 * with no parent-to-child inheritance implemented -- so a plain
	 * mkdir's mode is deterministically 0777 & ~022. */
	CHECK((st.st_mode & 0777) == 0755);
}

static void test_mkdir_eexist_without_p_is_an_error(void)
{
	char *argv[] = { (char *)"mkdir", (char *)"scratch/d1", 0 };
	check_refused(run(mkdir_path, argv), "mkdir:");
}

static void test_mkdir_dash_p(void)
{
	char *argv[] = { (char *)"mkdir", (char *)"-p", (char *)"scratch/a/b/c", 0 };
	struct stat st;

	CHECK(run(mkdir_path, argv) == 0);
	CHECK(stat("scratch/a", &st) == 0 && S_ISDIR(st.st_mode));
	CHECK(stat("scratch/a/b", &st) == 0 && S_ISDIR(st.st_mode));
	CHECK(stat("scratch/a/b/c", &st) == 0 && S_ISDIR(st.st_mode));
	/* -p's "already existed" exception: re-running must still succeed. */
	CHECK(run(mkdir_path, argv) == 0);
}

static void test_mkdir_dash_m_octal(void)
{
	char *argv[] = { (char *)"mkdir", (char *)"-m", (char *)"700", (char *)"scratch/d2", 0 };
	struct stat st;
	CHECK(run(mkdir_path, argv) == 0);
	CHECK(stat("scratch/d2", &st) == 0 && (st.st_mode & 0777) == 0700);
}

static void test_mkdir_missing_operand(void)
{
	char *argv[] = { (char *)"mkdir", 0 };
	check_refused(run(mkdir_path, argv), "missing operand");
}

/* ==== rmdir(1p) ========================================================= */

static void test_rmdir_basic(void)
{
	/* scratch/d1 already exists here, created (and left behind) by
	 * test_mkdir_basic_and_default_mode() above. */
	char *argv[] = { (char *)"rmdir", (char *)"scratch/d1", 0 };
	CHECK(run(rmdir_path, argv) == 0);
	CHECK(access("scratch/d1", F_OK) != 0);
}

static void test_rmdir_nonexistent_is_an_error(void)
{
	char *argv[] = { (char *)"rmdir", (char *)"scratch/does-not-exist", 0 };
	check_refused(run(rmdir_path, argv), "rmdir:");
}

static void test_rmdir_not_empty_is_an_error(void)
{
	char *argv[] = { (char *)"rmdir", (char *)"scratch/ne1", 0 };
	int fd;
	CHECK(mkdir("scratch/ne1", 0755) == 0);
	fd = open("scratch/ne1/f", O_WRONLY | O_CREAT, 0644);
	CHECK(fd >= 0);
	if (fd >= 0) close(fd);
	CHECK(run(rmdir_path, argv) != 0);
	unlink("scratch/ne1/f");
	rmdir("scratch/ne1");
}

static void test_rmdir_dash_p(void)
{
	/* scratch/.keep (created in main()) guarantees scratch/ itself is
	 * never empty, so the -p ascent below stops at scratch/p1 and does
	 * not touch scratch/ or anything above it. */
	char *argv[] = { (char *)"rmdir", (char *)"-p", (char *)"scratch/p1/p2/p3", 0 };
	CHECK(mkdir("scratch/p1", 0755) == 0);
	CHECK(mkdir("scratch/p1/p2", 0755) == 0);
	CHECK(mkdir("scratch/p1/p2/p3", 0755) == 0);
	CHECK(run(rmdir_path, argv) == 0);
	CHECK(access("scratch/p1/p2/p3", F_OK) != 0);
	CHECK(access("scratch/p1/p2", F_OK) != 0);
	CHECK(access("scratch/p1", F_OK) != 0);
	CHECK(access("scratch", F_OK) == 0);
}

/* ==== mkfifo(1p) ========================================================= */

#if defined(__linux__) && !defined(_SPICULE_NATIVE_BUILD)
/* This tree's mkfifo() (src/stat/chmod.c) is real on Linux -- a genuine
 * mknodat(2) FIFO, src/stat/linux/plat_stat.c's own __plat_mknod() --
 * so the utility must report the real success and leave a real FIFO
 * behind, not the ENOSYS this same test pins on NT (see the #else
 * arm's own comment for why that side stays a stub). */
static void test_mkfifo_reports_the_real_enosys_stub(void)
{
	struct stat st;
	char *argv[] = { (char *)"mkfifo", (char *)"scratch/fifo1", 0 };
	CHECK(run(mkfifo_path, argv) == 0);
	CHECK(stat("scratch/fifo1", &st) == 0 && S_ISFIFO(st.st_mode));
}
#else
static void test_mkfifo_reports_the_real_enosys_stub(void)
{
	/* This tree's mkfifo() (src/stat/chmod.c) is a genuine ENOSYS stub
	 * on this platform -- the utility must propagate that failure
	 * honestly, not fabricate success. */
	char *argv[] = { (char *)"mkfifo", (char *)"scratch/fifo1", 0 };
	CHECK(run(mkfifo_path, argv) != 0);
	CHECK(err_contains("mkfifo:"));
	CHECK(access("scratch/fifo1", F_OK) != 0);
}
#endif

static void test_mkfifo_validates_mode_before_the_enosys_call(void)
{
	char *argv[] = { (char *)"mkfifo", (char *)"-m", (char *)"not-a-mode", (char *)"scratch/fifo2", 0 };
	check_refused(run(mkfifo_path, argv), "invalid mode");
}

static void test_mkfifo_missing_operand(void)
{
	char *argv[] = { (char *)"mkfifo", 0 };
	check_refused(run(mkfifo_path, argv), "missing operand");
}

/* ==== ln(1p) ============================================================= */

static void make_file(const char *path, const char *contents)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return;
	if (contents && *contents) write(fd, contents, strlen(contents));
	close(fd);
}

static void test_ln_hardlink(void)
{
	char *argv[] = { (char *)"ln", (char *)"scratch/src1", (char *)"scratch/hard1", 0 };
	struct stat s1, s2;

	make_file("scratch/src1", "hello");
	CHECK(run(ln_path, argv) == 0);
	CHECK(stat("scratch/hard1", &s1) == 0 && S_ISREG(s1.st_mode));
	CHECK(stat("scratch/src1", &s2) == 0);
	/* A real hard link shares an inode/link count with its source. */
	CHECK(s1.st_nlink >= 2);
}

static void test_ln_existing_target_without_f_is_an_error(void)
{
	char *argv[] = { (char *)"ln", (char *)"scratch/src1", (char *)"scratch/hard1", 0 };
	check_refused(run(ln_path, argv), "ln:");
}

static void test_ln_dash_f_overwrites(void)
{
	char *argv[] = { (char *)"ln", (char *)"-f", (char *)"scratch/src1", (char *)"scratch/hard1", 0 };
	CHECK(run(ln_path, argv) == 0);
}

static void test_ln_dash_s(void)
{
	/* Symbolic links need SeCreateSymbolicLinkPrivilege/developer mode
	 * on NT (src/unistd/link.c's own comment) -- this environment may
	 * or may not have it, so this checks that the outcome is coherent
	 * (a real symlink on success, a real diagnostic on failure)
	 * without asserting which one happens, to avoid a flaky test on a
	 * CI leg without the privilege. */
	char *argv[] = { (char *)"ln", (char *)"-s", (char *)"src1", (char *)"scratch/sym1", 0 };
	int st = run(ln_path, argv);
	if (st == 0) {
		struct stat lst;
		CHECK(lstat("scratch/sym1", &lst) == 0 && S_ISLNK(lst.st_mode));
	} else {
		CHECK(err_contains("ln:"));
	}
}

static void test_ln_directory_target_form(void)
{
	char *argv[] = { (char *)"ln", (char *)"scratch/src1", (char *)"scratch/destdir", 0 };
	struct stat st;
	CHECK(mkdir("scratch/destdir", 0755) == 0);
	CHECK(run(ln_path, argv) == 0);
	CHECK(stat("scratch/destdir/src1", &st) == 0 && S_ISREG(st.st_mode));
}

static void test_ln_missing_operand(void)
{
	char *argv[] = { (char *)"ln", (char *)"scratch/src1", 0 };
	check_refused(run(ln_path, argv), "missing operand");
}

/* ==== chmod(1p) =========================================================== */

static void test_chmod_octal(void)
{
	char *argv[] = { (char *)"chmod", (char *)"600", (char *)"scratch/c1", 0 };
	struct stat st;
	make_file("scratch/c1", "x");
	CHECK(run(chmod_path, argv) == 0);
	CHECK(stat("scratch/c1", &st) == 0 && (st.st_mode & 0777) == 0600);
}

static void test_chmod_symbolic_relative_to_current_mode(void)
{
	char *add[] = { (char *)"chmod", (char *)"u+x", (char *)"scratch/c1", 0 };
	char *sub[] = { (char *)"chmod", (char *)"a-w", (char *)"scratch/c1", 0 };
	struct stat st;

	/* starting mode is 0600 (previous test) */
	CHECK(run(chmod_path, add) == 0);
	CHECK(stat("scratch/c1", &st) == 0 && (st.st_mode & 0777) == 0700);

	CHECK(run(chmod_path, sub) == 0);
	CHECK(stat("scratch/c1", &st) == 0 && (st.st_mode & 0777) == 0500);
}

static void test_chmod_invalid_mode_is_an_error(void)
{
	char *argv[] = { (char *)"chmod", (char *)"999", (char *)"scratch/c1", 0 };
	check_refused(run(chmod_path, argv), "invalid mode");
}

static void test_chmod_nonexistent_file_is_an_error(void)
{
	char *argv[] = { (char *)"chmod", (char *)"600", (char *)"scratch/does-not-exist", 0 };
	check_refused(run(chmod_path, argv), "chmod:");
}

static void test_chmod_missing_operand(void)
{
	char *argv[] = { (char *)"chmod", 0 };
	check_refused(run(chmod_path, argv), "missing operand");
}

/* ==== touch(1p) =========================================================== */

static time_t expected_epoch(int year, int mon, int day, int hh, int mm)
{
	struct tm tmv;
	memset(&tmv, 0, sizeof tmv);
	tmv.tm_year = year - 1900;
	tmv.tm_mon = mon - 1;
	tmv.tm_mday = day;
	tmv.tm_hour = hh;
	tmv.tm_min = mm;
	tmv.tm_isdst = -1;
	return mktime(&tmv);
}

static void test_touch_creates_empty_file(void)
{
	char *argv[] = { (char *)"touch", (char *)"scratch/t1", 0 };
	struct stat st;
	CHECK(access("scratch/t1", F_OK) != 0); /* precondition: does not exist yet */
	CHECK(run(touch_path, argv) == 0);
	CHECK(stat("scratch/t1", &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 0);
}

static void test_touch_dash_t_sets_both_times(void)
{
	char *argv[] = { (char *)"touch", (char *)"-t", (char *)"202001011200", (char *)"scratch/t1", 0 };
	struct stat st;
	time_t want = expected_epoch(2020, 1, 1, 12, 0);

	CHECK(run(touch_path, argv) == 0);
	CHECK(stat("scratch/t1", &st) == 0);
	CHECK(st.st_mtim.tv_sec == want);
	CHECK(st.st_atim.tv_sec == want);
}

static void test_touch_dash_a_leaves_mtime_alone(void)
{
	char *argv[] = { (char *)"touch", (char *)"-a", (char *)"-t", (char *)"202006150830", (char *)"scratch/t1", 0 };
	struct stat st;
	time_t old_mtime, new_atime;

	CHECK(stat("scratch/t1", &st) == 0);
	old_mtime = st.st_mtim.tv_sec;

	CHECK(run(touch_path, argv) == 0);
	CHECK(stat("scratch/t1", &st) == 0);
	new_atime = st.st_atim.tv_sec;
	CHECK(st.st_mtim.tv_sec == old_mtime);         /* -a alone: mtime untouched */
	CHECK(new_atime == expected_epoch(2020, 6, 15, 8, 30));
}

static void test_touch_dash_r(void)
{
	char *set_ref[] = { (char *)"touch", (char *)"-t", (char *)"201501020000", (char *)"scratch/ref", 0 };
	char *use_ref[] = { (char *)"touch", (char *)"-r", (char *)"scratch/ref", (char *)"scratch/t2", 0 };
	struct stat sref, st2;

	CHECK(run(touch_path, set_ref) == 0);
	CHECK(run(touch_path, use_ref) == 0);
	CHECK(stat("scratch/ref", &sref) == 0 && stat("scratch/t2", &st2) == 0);
	CHECK(sref.st_mtim.tv_sec == st2.st_mtim.tv_sec);
	CHECK(sref.st_atim.tv_sec == st2.st_atim.tv_sec);
}

static void test_touch_dash_c_skips_missing_silently(void)
{
	char *argv[] = { (char *)"touch", (char *)"-c", (char *)"scratch/never-created", 0 };
	CHECK(run(touch_path, argv) == 0);
	CHECK(access("scratch/never-created", F_OK) != 0);
	{
		char buf[256];
		slurp_into(ERRFILE, buf, sizeof buf);
		CHECK(buf[0] == 0);
	}
}

static void test_touch_dash_d_is_refused(void)
{
	char *argv[] = { (char *)"touch", (char *)"-d", (char *)"2020-01-01", (char *)"scratch/t1", 0 };
	check_refused(run(touch_path, argv), "not implemented");
}

static void test_touch_bad_dash_t_is_an_error(void)
{
	char *argv[] = { (char *)"touch", (char *)"-t", (char *)"not-a-time", (char *)"scratch/t1", 0 };
	check_refused(run(touch_path, argv), "invalid time");
}

static void test_touch_missing_operand(void)
{
	char *argv[] = { (char *)"touch", 0 };
	check_refused(run(touch_path, argv), "missing operand");
}

/* ==== the shell built-ins agree with the standalone executables ========== */

static void test_builtins_match_standalone(void)
{
	CHECK(run_sh_c("mkdir scratch/shd1") == 0);
	CHECK(access("scratch/shd1", F_OK) == 0);
	CHECK(run_sh_c("rmdir scratch/shd1") == 0);
	CHECK(access("scratch/shd1", F_OK) != 0);

#if defined(__linux__) && !defined(_SPICULE_NATIVE_BUILD)
	CHECK(run_sh_c("mkfifo scratch/shfifo") == 0); /* real FIFO, see above */
	{
		struct stat st;
		CHECK(stat("scratch/shfifo", &st) == 0 && S_ISFIFO(st.st_mode));
	}
#else
	CHECK(run_sh_c("mkfifo scratch/shfifo") != 0); /* ENOSYS, see above */
#endif

	CHECK(run_sh_c("ln scratch/src1 scratch/shhard") == 0);
	CHECK(access("scratch/shhard", F_OK) == 0);

	CHECK(run_sh_c("chmod 640 scratch/src1") == 0);
	{
		struct stat st;
		CHECK(stat("scratch/src1", &st) == 0 && (st.st_mode & 0777) == 0640);
	}

	CHECK(run_sh_c("touch scratch/shtouch") == 0);
	CHECK(access("scratch/shtouch", F_OK) == 0);
}

/* ==== scratch directory setup/teardown =================================== */

static void rmtree_scratch(void)
{
	/* No general recursive-delete helper is needed here: every path
	 * this file ever creates is listed explicitly below, deepest
	 * first, mirroring exactly what the tests above are known to
	 * leave behind if a CHECK() failed partway and skipped its own
	 * inline cleanup. */
	unlink("scratch/destdir/src1");
	rmdir("scratch/destdir");
	unlink("scratch/src1");
	unlink("scratch/hard1");
	unlink("scratch/sym1");
	unlink("scratch/shhard");
	unlink("scratch/c1");
	unlink("scratch/t1");
	unlink("scratch/t2");
	unlink("scratch/ref");
	unlink("scratch/shtouch");
	unlink("scratch/ne1/f");
	rmdir("scratch/ne1");
	rmdir("scratch/p1/p2/p3");
	rmdir("scratch/p1/p2");
	rmdir("scratch/p1");
	rmdir("scratch/a/b/c");
	rmdir("scratch/a/b");
	rmdir("scratch/a");
	rmdir("scratch/d1");
	rmdir("scratch/d2");
	rmdir("scratch/shd1");
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
		printf("SKIP util-fsops: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(mkdir_path, sizeof mkdir_path, "bin/mkdir.exe");
	path_for(rmdir_path, sizeof rmdir_path, "bin/rmdir.exe");
	path_for(mkfifo_path, sizeof mkfifo_path, "bin/mkfifo.exe");
	path_for(ln_path, sizeof ln_path, "bin/ln.exe");
	path_for(chmod_path, sizeof chmod_path, "bin/chmod.exe");
	path_for(touch_path, sizeof touch_path, "bin/touch.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(mkdir_path, R_OK) != 0 || access(rmdir_path, R_OK) != 0 ||
	    access(mkfifo_path, R_OK) != 0 || access(ln_path, R_OK) != 0 ||
	    access(chmod_path, R_OK) != 0 || access(touch_path, R_OK) != 0 ||
	    access(sh_path, R_OK) != 0) {
		printf("SKIP util-fsops: one or more of the six utility binaries or sh is missing\n");
		return 77;
	}

	/* Start from a clean scratch/ in case a previous run was
	 * interrupted before its own cleanup ran. */
	rmtree_scratch();
	if (mkdir("scratch", 0755) != 0) {
		printf("SKIP util-fsops: cannot create scratch/ (%s)\n", strerror(errno));
		return 77;
	}
	make_file("scratch/.keep", "");

	test_mkdir_basic_and_default_mode();
	test_mkdir_eexist_without_p_is_an_error();
	test_mkdir_dash_p();
	test_mkdir_dash_m_octal();
	test_mkdir_missing_operand();

	test_rmdir_basic();
	test_rmdir_nonexistent_is_an_error();
	test_rmdir_not_empty_is_an_error();
	test_rmdir_dash_p();

	test_mkfifo_reports_the_real_enosys_stub();
	test_mkfifo_validates_mode_before_the_enosys_call();
	test_mkfifo_missing_operand();

	test_ln_hardlink();
	test_ln_existing_target_without_f_is_an_error();
	test_ln_dash_f_overwrites();
	test_ln_dash_s();
	test_ln_directory_target_form();
	test_ln_missing_operand();

	test_chmod_octal();
	test_chmod_symbolic_relative_to_current_mode();
	test_chmod_invalid_mode_is_an_error();
	test_chmod_nonexistent_file_is_an_error();
	test_chmod_missing_operand();

	test_touch_creates_empty_file();
	test_touch_dash_t_sets_both_times();
	test_touch_dash_a_leaves_mtime_alone();
	test_touch_dash_r();
	test_touch_dash_c_skips_missing_silently();
	test_touch_dash_d_is_refused();
	test_touch_bad_dash_t_is_an_error();
	test_touch_missing_operand();

	test_builtins_match_standalone();

	cleanup_artifacts();

	if (fails) { printf("util-fsops: failures: %d\n", fails); return 1; }
	printf("util-fsops: all ok (mkdir, rmdir, mkfifo, ln, chmod, touch -- standalone and builtin)\n");
	return 0;
}
