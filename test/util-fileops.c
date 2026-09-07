/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for spicule's `rm`, `cp` and `mv` (XCU rm(1p), cp(1p),
 * mv(1p)) -- the second, higher-risk tier of POSIX standard utilities
 * after test/util-trivial.c's true/false/test.  Same shape as that file
 * (see its header): each standalone obj/bin/NAME.exe is spawned as a real
 * process, and the shell built-in is exercised through `obj/sh/sh.exe
 * -c` too, confirming both callers of __util_*_main() (src/internal/
 * util.h) agree.
 *
 * These three do real, potentially destructive filesystem work, so
 * every fixture this file creates, copies, moves or removes lives
 * inside one scratch directory (SCRATCH below), named with this
 * process's own pid so two runs never collide, and never the repository
 * root or the bare test working directory -- and raw_rmtree() tears the
 * whole thing down again on the way out regardless of how many CHECKs
 * failed, using its own independent opendir()/readdir()/unlink()/
 * rmdir() walk rather than the `rm` utility under test, so a cleanup
 * step never depends on the correctness of the thing being tested (see
 * test/sh-main.c's cleanup_artifacts() for the same "leaving fixtures
 * behind turns the reuse/SPDX lint stage red" reasoning, generalized
 * here from a flat file list to a whole tree).
 *
 * Spec pages consulted (https://pubs.opengroup.org/onlinepubs/9699919799/):
 *   utilities/rm.html utilities/cp.html utilities/mv.html
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

/* ---- locating obj/bin/{rm,cp,mv}.exe and obj/sh/sh.exe ---------------
 * Same walk-up-from-argv[0] technique as test/util-trivial.c's
 * find_obj_root()/path_for(). */
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
	obj_root[i - 1] = 0;                       /* strip "/util-fileops.exe" */

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

static char rm_path[1024], cp_path[1024], mv_path[1024], sh_path[1024];

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

static char p1[600], p2[600], p3[600], p4[600];

static void mkpath(char *out, const char *rel)
{
	snprintf(out, 600, "%s/%s", scratch, rel);
}

/* ---- spawning and capturing (same technique as test/util-trivial.c) -- */

static char outfile[700], errfile[700];

static int run(const char *path, char *const *args)
{
	int out, err;
	int s1, s2, pid, status;

	out = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	err = open(errfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
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

static int run_sh_c(const char *cmd)
{
	char *argv[4];
	argv[0] = (char *)"sh"; argv[1] = (char *)"-c"; argv[2] = (char *)cmd; argv[3] = 0;
	return run(sh_path, argv);
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
	slurp_into(errfile, buf, sizeof buf);
	return strstr(buf, needle) != 0;
}

static void write_file(const char *path, const char *text)
{
	FILE *f = fopen(path, "wb");
	if (!f) { fails++; printf("FAIL: cannot write %s\n", path); return; }
	fputs(text, f);
	fclose(f);
}

static int exists(const char *path)
{
	struct stat st;
	return lstat(path, &st) == 0;
}

static int is_dir(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Checks that a run was refused outright: nonzero exit, a diagnostic
 * naming the utility, and the operation's own target never created. */
static void check_refused(int status, const char *err_prefix, const char *must_not_exist)
{
	CHECK(status != 0);
	CHECK(err_contains(err_prefix));
	CHECK(!exists(must_not_exist));
}

/* Checks the -i "always ask" refusal shared by rm/cp/mv below: exit
 * status 2, with a diagnostic naming the unsupported option. */
static void check_dash_i_refused(int status)
{
	CHECK(status == 2);
	CHECK(err_contains("-i"));
}

/* ==== cp: single-file form ============================================== */

static void test_cp_single_file(void)
{
	char buf[256];
	char *argv[4];

	mkpath(p1, "cp-src.txt");
	mkpath(p2, "cp-dst.txt");
	write_file(p1, "hello from cp\n");

	argv[0] = (char *)"cp"; argv[1] = p1; argv[2] = p2; argv[3] = 0;
	CHECK(run(cp_path, argv) == 0);
	CHECK(slurp_into(p2, buf, sizeof buf) == 0);
	CHECK(strcmp(buf, "hello from cp\n") == 0);
	/* source is untouched */
	CHECK(slurp_into(p1, buf, sizeof buf) == 0);
	CHECK(strcmp(buf, "hello from cp\n") == 0);
}

static void test_cp_nonexistent_source(void)
{
	char *argv[4];

	mkpath(p1, "cp-does-not-exist.txt");
	mkpath(p2, "cp-never-created.txt");

	argv[0] = (char *)"cp"; argv[1] = p1; argv[2] = p2; argv[3] = 0;
	check_refused(run(cp_path, argv), "cp:", p2);
}

static void test_cp_directory_target_form(void)
{
	char buf[256];
	char *argv[5];

	mkpath(p1, "cp-into-dir");
	mkdir(p1, 0700);
	mkpath(p2, "cp-a.txt");
	mkpath(p3, "cp-b.txt");
	write_file(p2, "AAA");
	write_file(p3, "BBB");

	argv[0] = (char *)"cp"; argv[1] = p2; argv[2] = p3; argv[3] = p1; argv[4] = 0;
	CHECK(run(cp_path, argv) == 0);

	mkpath(p4, "cp-into-dir/cp-a.txt");
	CHECK(slurp_into(p4, buf, sizeof buf) == 0);
	CHECK(strcmp(buf, "AAA") == 0);
	mkpath(p4, "cp-into-dir/cp-b.txt");
	CHECK(slurp_into(p4, buf, sizeof buf) == 0);
	CHECK(strcmp(buf, "BBB") == 0);
}

/* ==== cp -R: a real small tree ========================================== */

static void build_tree(const char *root)
{
	char p[600];

	mkdir(root, 0700);
	snprintf(p, sizeof p, "%s/top.txt", root);
	write_file(p, "top\n");
	snprintf(p, sizeof p, "%s/sub", root);
	mkdir(p, 0700);
	snprintf(p, sizeof p, "%s/sub/mid.txt", root);
	write_file(p, "mid\n");
	snprintf(p, sizeof p, "%s/sub/subsub", root);
	mkdir(p, 0700);
	snprintf(p, sizeof p, "%s/sub/subsub/deep.txt", root);
	write_file(p, "deep\n");
}

static void check_tree_at(const char *root)
{
	char p[600], buf[64];

	snprintf(p, sizeof p, "%s/top.txt", root);
	CHECK(slurp_into(p, buf, sizeof buf) == 0 && !strcmp(buf, "top\n"));
	snprintf(p, sizeof p, "%s/sub/mid.txt", root);
	CHECK(slurp_into(p, buf, sizeof buf) == 0 && !strcmp(buf, "mid\n"));
	snprintf(p, sizeof p, "%s/sub/subsub/deep.txt", root);
	CHECK(slurp_into(p, buf, sizeof buf) == 0 && !strcmp(buf, "deep\n"));
}

static void test_cp_recursive_tree(void)
{
	char *argv[5];

	mkpath(p1, "cpr-src");
	mkpath(p2, "cpr-dst");
	build_tree(p1);

	/* destination does not exist yet: it becomes the copy's own root */
	argv[0] = (char *)"cp"; argv[1] = (char *)"-R"; argv[2] = p1; argv[3] = p2; argv[4] = 0;
	CHECK(run(cp_path, argv) == 0);
	check_tree_at(p2);
	/* source is untouched */
	check_tree_at(p1);

	/* without -R, a directory source is refused rather than silently
	 * skipped-but-successful. */
	mkpath(p3, "cpr-dst2");
	argv[0] = (char *)"cp"; argv[1] = p1; argv[2] = p3; argv[3] = 0;
	check_refused(run(cp_path, argv), "cp:", p3);
}

/* Copying a directory into its own subtree must be refused, not run:
 * see src/util/cp.c's path_is_under_or_same() for the unbounded-growth
 * hazard this guards against. A hang or runaway disk usage here would
 * be a far worse failure than a plain nonzero exit, so this is checked
 * even though it cannot, by itself, prove the *absence* of a hang --
 * only that the refusal path is taken instead of starting the walk. */
static void test_cp_refuses_into_own_subtree(void)
{
	char *argv5[5];
	char dst[600];

	mkpath(p1, "cpself-src");
	build_tree(p1);
	snprintf(dst, sizeof dst, "%s/nested", p1);

	argv5[0] = (char *)"cp"; argv5[1] = (char *)"-R"; argv5[2] = p1; argv5[3] = dst; argv5[4] = 0;
	check_refused(run(cp_path, argv5), "cp:", dst);

	/* the exact same path, not just a subdirectory of it */
	argv5[3] = p1;
	CHECK(run(cp_path, argv5) != 0);
	CHECK(err_contains("cp:"));
}

/* ==== rm ================================================================ */

static void test_rm_single_file(void)
{
	char *argv[3];

	mkpath(p1, "rm-me.txt");
	write_file(p1, "gone soon");
	CHECK(exists(p1));

	argv[0] = (char *)"rm"; argv[1] = p1; argv[2] = 0;
	CHECK(run(rm_path, argv) == 0);
	CHECK(!exists(p1));
}

static void test_rm_nonexistent(void)
{
	char *argv3[3];
	char *argv4[4];

	mkpath(p1, "rm-never-existed.txt");

	/* without -f: real diagnostic, nonzero exit */
	argv3[0] = (char *)"rm"; argv3[1] = p1; argv3[2] = 0;
	CHECK(run(rm_path, argv3) != 0);
	CHECK(err_contains("rm:"));

	/* with -f: rm(1p) -- suppressed entirely */
	argv4[0] = (char *)"rm"; argv4[1] = (char *)"-f"; argv4[2] = p1; argv4[3] = 0;
	CHECK(run(rm_path, argv4) == 0);
	CHECK(!err_contains("rm:"));
}

static void test_rm_directory_without_r(void)
{
	char *argv[3];

	mkpath(p1, "rm-dir-no-r");
	mkdir(p1, 0700);

	argv[0] = (char *)"rm"; argv[1] = p1; argv[2] = 0;
	CHECK(run(rm_path, argv) != 0);
	CHECK(err_contains("directory"));
	CHECK(is_dir(p1));       /* untouched */
}

/* The single easiest place in this whole effort to delete the wrong
 * thing: prove the recursive walk removes exactly the tree it was
 * asked to and nothing beside it. */
static void test_rm_recursive_tree(void)
{
	char *argv[4];
	char sibling[600], sibling_file[600], victim[600];

	mkpath(victim, "rmr-victim");
	build_tree(victim);

	mkpath(sibling, "rmr-sibling");
	mkdir(sibling, 0700);
	snprintf(sibling_file, sizeof sibling_file, "%s/untouched.txt", sibling);
	write_file(sibling_file, "must survive\n");

	argv[0] = (char *)"rm"; argv[1] = (char *)"-r"; argv[2] = victim; argv[3] = 0;
	CHECK(run(rm_path, argv) == 0);

	CHECK(!exists(victim));

	{
		char buf[64];
		CHECK(is_dir(sibling));
		CHECK(slurp_into(sibling_file, buf, sizeof buf) == 0);
		CHECK(strcmp(buf, "must survive\n") == 0);
	}
}

/* ==== mv ================================================================= */

static void test_mv_same_volume(void)
{
	char buf[64];
	char *argv[4];

	mkpath(p1, "mv-src.txt");
	mkpath(p2, "mv-dst.txt");
	write_file(p1, "moved\n");

	argv[0] = (char *)"mv"; argv[1] = p1; argv[2] = p2; argv[3] = 0;
	CHECK(run(mv_path, argv) == 0);
	CHECK(!exists(p1));
	CHECK(slurp_into(p2, buf, sizeof buf) == 0);
	CHECK(strcmp(buf, "moved\n") == 0);
}

static void test_mv_directory_target_form(void)
{
	char buf[64];
	char *argv[4];

	mkpath(p1, "mv-into-dir");
	mkdir(p1, 0700);
	mkpath(p2, "mv-c.txt");
	write_file(p2, "CCC");

	argv[0] = (char *)"mv"; argv[1] = p2; argv[2] = p1; argv[3] = 0;
	CHECK(run(mv_path, argv) == 0);
	CHECK(!exists(p2));

	mkpath(p3, "mv-into-dir/mv-c.txt");
	CHECK(slurp_into(p3, buf, sizeof buf) == 0);
	CHECK(strcmp(buf, "CCC") == 0);
}

static void test_mv_nonexistent_source(void)
{
	char *argv[4];

	mkpath(p1, "mv-does-not-exist.txt");
	mkpath(p2, "mv-never-created.txt");

	argv[0] = (char *)"mv"; argv[1] = p1; argv[2] = p2; argv[3] = 0;
	check_refused(run(mv_path, argv), "mv:", p2);
}

/* mv(1p)'s cross-filesystem (EXDEV) fallback: rename() first, a copy-
 * then-remove only when it fails specifically because the two paths are
 * on different volumes (src/util/mv.c). Constructing two genuinely
 * different volumes from inside a portable, sandboxed test process is
 * not generally possible -- there is no guaranteed second writable
 * volume/drive letter to target. This looks for one real environment
 * where spicule's own test infrastructure does produce one (Wine's `Z:`
 * passthrough to the host filesystem root, alongside the `C:`-drive
 * prefix obj/ is normally built under) and exercises the fallback for
 * real when it is present; otherwise it prints why it could not run,
 * without counting that as a failure. */
static void test_mv_cross_filesystem(void)
{
	struct stat a, b;
	char probe_dir[64];

	if (stat(scratch, &a) != 0) return;
	if (stat("Z:\\", &b) != 0 && stat("Z:/", &b) != 0) {
		printf("NOTE util-fileops: no second volume (e.g. Wine's Z:) visible -- "
		       "mv's EXDEV fallback path was not exercised\n");
		return;
	}
	if (b.st_dev == a.st_dev) {
		printf("NOTE util-fileops: Z: reports the same volume as the scratch "
		       "directory here -- mv's EXDEV fallback path was not exercised\n");
		return;
	}

	snprintf(probe_dir, sizeof probe_dir, "Z:\\spicule-fileops-test-%ld", (long)getpid());
	if (mkdir(probe_dir, 0700) != 0) {
		printf("NOTE util-fileops: Z: is not writable here -- mv's EXDEV "
		       "fallback path was not exercised\n");
		return;
	}

	{
		char src[600], dst[600], buf[64];
		char *argv[4];

		mkpath(src, "mv-xdev-src.txt");
		write_file(src, "cross-volume\n");
		snprintf(dst, sizeof dst, "%s\\moved.txt", probe_dir);

		argv[0] = (char *)"mv"; argv[1] = src; argv[2] = dst; argv[3] = 0;
		CHECK(run(mv_path, argv) == 0);
		CHECK(!exists(src));
		CHECK(slurp_into(dst, buf, sizeof buf) == 0);
		CHECK(strcmp(buf, "cross-volume\n") == 0);
	}

	raw_rmtree(probe_dir);
}

/* ==== -i is refused, not silently ignored, for all three ================ */

static void test_dash_i_is_refused(void)
{
	char *argv3[4];
	char *argv4[5];

	mkpath(p1, "dash-i-target.txt");
	write_file(p1, "stays put\n");
	mkpath(p2, "dash-i-target2.txt");

	argv3[0] = (char *)"rm"; argv3[1] = (char *)"-i"; argv3[2] = p1; argv3[3] = 0;
	check_dash_i_refused(run(rm_path, argv3));
	CHECK(exists(p1));   /* refused before doing anything */

	argv4[0] = (char *)"cp"; argv4[1] = (char *)"-i"; argv4[2] = p1; argv4[3] = p2; argv4[4] = 0;
	check_dash_i_refused(run(cp_path, argv4));
	CHECK(!exists(p2));

	argv4[0] = (char *)"mv";
	check_dash_i_refused(run(mv_path, argv4));
	CHECK(exists(p1));   /* not moved */
	CHECK(!exists(p2));
}

/* ==== the shell built-ins agree with the standalone executables ========= */

static void test_builtins_match_standalone(void)
{
	char buf[64];
	char cmd[1400];

	mkpath(p1, "bi-src.txt");
	mkpath(p2, "bi-dst.txt");
	write_file(p1, "via builtin\n");

	sprintf(cmd, "cp '%s' '%s'", p1, p2);
	CHECK(run_sh_c(cmd) == 0);
	CHECK(slurp_into(p2, buf, sizeof buf) == 0);
	CHECK(strcmp(buf, "via builtin\n") == 0);

	mkpath(p3, "bi-mv-dst.txt");
	sprintf(cmd, "mv '%s' '%s'", p2, p3);
	CHECK(run_sh_c(cmd) == 0);
	CHECK(!exists(p2));
	CHECK(slurp_into(p3, buf, sizeof buf) == 0);
	CHECK(strcmp(buf, "via builtin\n") == 0);

	sprintf(cmd, "rm '%s' '%s'", p1, p3);
	CHECK(run_sh_c(cmd) == 0);
	CHECK(!exists(p1));
	CHECK(!exists(p3));

	/* rm -r through the builtin, on a real tree. */
	mkpath(p4, "bi-tree");
	build_tree(p4);
	sprintf(cmd, "rm -r '%s'", p4);
	CHECK(run_sh_c(cmd) == 0);
	CHECK(!exists(p4));
}

/* ==== main =============================================================== */

int main(int argc, char **argv)
{
	(void)argc;

	if (find_obj_root(argv[0]) != 0) {
		printf("SKIP util-fileops: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(rm_path, sizeof rm_path, "bin/rm.exe");
	path_for(cp_path, sizeof cp_path, "bin/cp.exe");
	path_for(mv_path, sizeof mv_path, "bin/mv.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(rm_path, R_OK) != 0 || access(cp_path, R_OK) != 0 ||
	    access(mv_path, R_OK) != 0 || access(sh_path, R_OK) != 0) {
		printf("SKIP util-fileops: one or more of rm/cp/mv/sh binaries is missing\n");
		return 77;
	}

	snprintf(scratch, sizeof scratch, "fileops-scratch-%ld", (long)getpid());
	raw_rmtree(scratch);   /* in case a previous crashed run left one behind */
	if (mkdir(scratch, 0700) != 0) {
		printf("SKIP util-fileops: cannot create scratch directory \"%s\"\n", scratch);
		return 77;
	}
	snprintf(outfile, sizeof outfile, "%s/out.txt", scratch);
	snprintf(errfile, sizeof errfile, "%s/err.txt", scratch);

	test_cp_single_file();
	test_cp_nonexistent_source();
	test_cp_directory_target_form();
	test_cp_recursive_tree();
	test_cp_refuses_into_own_subtree();

	test_rm_single_file();
	test_rm_nonexistent();
	test_rm_directory_without_r();
	test_rm_recursive_tree();

	test_mv_same_volume();
	test_mv_directory_target_form();
	test_mv_nonexistent_source();
	test_mv_cross_filesystem();

	test_dash_i_is_refused();

	test_builtins_match_standalone();

	raw_rmtree(scratch);

	if (fails) { printf("util-fileops: failures: %d\n", fails); return 1; }
	printf("util-fileops: all ok (rm, cp, mv -- standalone and builtin)\n");
	return 0;
}
