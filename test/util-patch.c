/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for ntlibc's patch(1p) (the first Tier-4 "bigger
 * engine" utility).  Same technique as test/util-sortset.c: the
 * standalone obj/bin/patch.exe is spawned as a real process (via
 * __spawn()+waitpid()), and the shell built-in is exercised too (via
 * obj/sh/sh.exe -c), confirming both callers of __util_patch_main()
 * (src/internal/util.h) agree.
 *
 * Every test drives patch via `-i patchfile` rather than piping the
 * patch text over stdin, so no stdout/stdin redirection juggling is
 * needed beyond what run() already does for the *target* file's stderr
 * capture -- the patch input itself is just another file.
 *
 * The four hand-written patch files below (one per diff(1) format this
 * project's src/util/patch.c supports) are each derived, by hand, from
 * the same 5-line ORIG_CONTENT against the same 1-line edit or
 * insertion or deletion, specifically so each format's result can be
 * checked against the same expected string -- see src/util/patch.c's
 * own header comment for the exact format grammars these hand-derive
 * from. */
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

/* Strips the trailing "/last-component" (or "\...") off `path` in
 * place. Returns 0 on success, -1 if `path` has no separator left to
 * strip at. */
static int strip_last_component(char *path)
{
	size_t i;

	for (i = strlen(path); i > 0; i--)
		if (path[i - 1] == '/' || path[i - 1] == '\\') break;
	if (i == 0) return -1;
	path[i - 1] = 0;
	return 0;
}

static int find_obj_root(const char *argv0)
{
	if (!argv0 || !*argv0) return -1;
	if (strlen(argv0) >= sizeof obj_root) return -1;
	strcpy(obj_root, argv0);

	if (strip_last_component(obj_root) != 0) return -1; /* strip "/util-patch.exe" */
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

#define ERRFILE "util-patch-err.txt"

static int run(const char *path, char *const *args)
{
	int err;
	int s2, pid, status;

	err = open(ERRFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (err < 0) return -1;

	s2 = dup(2);
	dup2(err, 2);
	close(err);

	pid = __spawn(path, args, environ);

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

static int file_equals(const char *path, const char *expect)
{
	char buf[4096];
	if (slurp_into(path, buf, sizeof buf) < 0) return 0;
	return strcmp(buf, expect) == 0;
}

static int file_exists_nonempty(const char *path)
{
	struct stat st;
	if (stat(path, &st) != 0) return 0;
	return st.st_size > 0;
}

static void make_file(const char *path, const char *contents)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return;
	if (contents && *contents) write(fd, contents, strlen(contents));
	close(fd);
}

static char patch_path[1024], sh_path[1024];

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

/* Runs patch_path with argv, checking it applied cleanly (exit 0) and
 * left `path` holding exactly `expect` -- the shape most of the
 * per-format tests below share. */
static void check_applied(char *const *argv, const char *path, const char *expect)
{
	CHECK(run(patch_path, argv) == 0);
	CHECK(file_equals(path, expect));
}

/* Runs patch_path with argv, checking it was rejected (exit 1), left
 * `path` holding exactly `expect`, and wrote a non-empty scratch/
 * orig.rej. */
static void check_rejected(char *const *argv, const char *path, const char *expect)
{
	CHECK(run(patch_path, argv) == 1);
	CHECK(file_equals(path, expect));
	CHECK(file_exists_nonempty("scratch/orig.rej"));
}

/* ==== shared fixtures ====================================================== */

#define ORIG_CONTENT "line1\nline2\nline3\nline4\nline5\n"
#define CHANGED_CONTENT "line1\nline2\nLINE3-CHANGED\nline4\nline5\n"

static const char UNIFIED_DIFF[] =
	"--- orig\t2026-01-01\n"
	"+++ orig\t2026-01-01\n"
	"@@ -2,3 +2,3 @@\n"
	" line2\n"
	"-line3\n"
	"+LINE3-CHANGED\n"
	" line4\n";

static const char CONTEXT_DIFF[] =
	"*** orig\t2026-01-01\n"
	"--- orig\t2026-01-01\n"
	"***************\n"
	"*** 4,5 ****\n"
	"  line4\n"
	"- line5\n"
	"--- 4 ----\n"
	"  line4\n";

static const char NORMAL_DIFF[] =
	"2a3\n"
	"> NEWLINE\n";

static const char ED_DIFF[] =
	"1d\n";

static const char REJECT_DIFF[] =
	"--- orig\t2026-01-01\n"
	"+++ orig\t2026-01-01\n"
	"@@ -2,3 +2,3 @@\n"
	" wrongline2\n"
	"-line3\n"
	"+LINE3-CHANGED\n"
	" line4\n";

static const char PSTRIP_DIFF[] =
	"--- a/scratch/pfile\t2026-01-01\n"
	"+++ b/scratch/pfile\t2026-01-01\n"
	"@@ -1,3 +1,3 @@\n"
	" alpha\n"
	"-beta\n"
	"+BETA\n"
	" gamma\n";

/* ==== per-format basic apply ============================================== */

static void test_unified_basic(void)
{
	char *argv[] = { (char *)"patch", (char *)"-i", (char *)"scratch/u.diff", (char *)"scratch/orig", 0 };
	make_file("scratch/orig", ORIG_CONTENT);
	make_file("scratch/u.diff", UNIFIED_DIFF);
	check_applied(argv, "scratch/orig", CHANGED_CONTENT);
}

static void test_context_basic(void)
{
	char *argv[] = { (char *)"patch", (char *)"-i", (char *)"scratch/c.diff", (char *)"scratch/orig", 0 };
	make_file("scratch/orig", ORIG_CONTENT);
	make_file("scratch/c.diff", CONTEXT_DIFF);
	check_applied(argv, "scratch/orig", "line1\nline2\nline3\nline4\n");
}

/* Normal diff format carries no filename of its own -- the file operand
 * is mandatory for it (src/util/patch.c's header comment). */
static void test_normal_basic_requires_operand(void)
{
	char *argv[] = { (char *)"patch", (char *)"-i", (char *)"scratch/n.diff", 0 };
	make_file("scratch/orig", ORIG_CONTENT);
	make_file("scratch/n.diff", NORMAL_DIFF);
	CHECK(run(patch_path, argv) != 0);
	CHECK(err_contains("operand"));
}

static void test_normal_basic(void)
{
	char *argv[] = { (char *)"patch", (char *)"-i", (char *)"scratch/n.diff", (char *)"scratch/orig", 0 };
	make_file("scratch/orig", ORIG_CONTENT);
	make_file("scratch/n.diff", NORMAL_DIFF);
	check_applied(argv, "scratch/orig", "line1\nline2\nNEWLINE\nline3\nline4\nline5\n");
}

static void test_ed_basic(void)
{
	char *argv[] = { (char *)"patch", (char *)"-e", (char *)"-i", (char *)"scratch/e.diff", (char *)"scratch/orig", 0 };
	make_file("scratch/orig", ORIG_CONTENT);
	make_file("scratch/e.diff", ED_DIFF);
	check_applied(argv, "scratch/orig", "line2\nline3\nline4\nline5\n");
}

/* -e cannot be combined with -R (the format's own restriction -- see
 * src/util/patch.c's header comment). */
static void test_ed_reverse_refused(void)
{
	char *argv[] = { (char *)"patch", (char *)"-e", (char *)"-R", (char *)"-i", (char *)"scratch/e.diff", (char *)"scratch/orig", 0 };
	make_file("scratch/orig", ORIG_CONTENT);
	make_file("scratch/e.diff", ED_DIFF);
	CHECK(run(patch_path, argv) != 0);
}

/* ==== -R reverses a unified hunk back to the original ===================== */

static void test_reverse(void)
{
	char *argv[] = { (char *)"patch", (char *)"-R", (char *)"-i", (char *)"scratch/u.diff", (char *)"scratch/orig", 0 };
	make_file("scratch/orig", CHANGED_CONTENT);
	check_applied(argv, "scratch/orig", ORIG_CONTENT);
}

/* ==== -p strips leading pathname components, and with no file operand
 * the stripped "old" name is used because it exists on disk ============= */

static void test_p_strip_no_operand(void)
{
	char *argv[] = { (char *)"patch", (char *)"-p", (char *)"1", (char *)"-i", (char *)"scratch/p.diff", 0 };
	make_file("scratch/pfile", "alpha\nbeta\ngamma\n");
	make_file("scratch/p.diff", PSTRIP_DIFF);
	check_applied(argv, "scratch/pfile", "alpha\nBETA\ngamma\n");
}

/* ==== a hunk whose context matches nowhere is rejected, not applied,
 * and the target file is left byte-for-byte alone ========================= */

static void test_reject_creates_rejfile(void)
{
	char *argv[] = { (char *)"patch", (char *)"-i", (char *)"scratch/r.diff", (char *)"scratch/orig", 0 };
	unlink("scratch/orig.rej");
	make_file("scratch/orig", ORIG_CONTENT);
	make_file("scratch/r.diff", REJECT_DIFF);
	check_rejected(argv, "scratch/orig", ORIG_CONTENT);
}

/* ==== -N: an already-applied hunk is a reject by default, and a silent
 * no-op (still exit 0) with -N ============================================ */

static void test_already_applied_default_rejects(void)
{
	char *argv[] = { (char *)"patch", (char *)"-i", (char *)"scratch/u.diff", (char *)"scratch/orig", 0 };
	unlink("scratch/orig.rej");
	make_file("scratch/orig", CHANGED_CONTENT);
	check_rejected(argv, "scratch/orig", CHANGED_CONTENT);
}

static void test_already_applied_dash_N_is_silent(void)
{
	char *argv[] = { (char *)"patch", (char *)"-N", (char *)"-i", (char *)"scratch/u.diff", (char *)"scratch/orig", 0 };
	make_file("scratch/orig", CHANGED_CONTENT);
	check_applied(argv, "scratch/orig", CHANGED_CONTENT);
}

/* ==== -o writes the patched result elsewhere, leaving the target file
 * completely untouched ====================================================== */

static void test_dash_o_leaves_target_untouched(void)
{
	char *argv[] = { (char *)"patch", (char *)"-o", (char *)"scratch/out.txt", (char *)"-i", (char *)"scratch/u.diff", (char *)"scratch/orig", 0 };
	make_file("scratch/orig", ORIG_CONTENT);
	CHECK(run(patch_path, argv) == 0);
	CHECK(file_equals("scratch/orig", ORIG_CONTENT));
	CHECK(file_equals("scratch/out.txt", CHANGED_CONTENT));
}

/* ==== -b backs up the pre-patch content to <file>.orig ==================== */

static void test_dash_b_backs_up_original(void)
{
	char *argv[] = { (char *)"patch", (char *)"-b", (char *)"-i", (char *)"scratch/u.diff", (char *)"scratch/orig", 0 };
	unlink("scratch/orig.orig");
	make_file("scratch/orig", ORIG_CONTENT);
	CHECK(run(patch_path, argv) == 0);
	CHECK(file_equals("scratch/orig", CHANGED_CONTENT));
	CHECK(file_equals("scratch/orig.orig", ORIG_CONTENT));
}

/* ==== security regressions ================================================= */

/* A pure-insertion hunk (empty old side) whose header names a line far
 * beyond the target file's actual length used to make side_matches()
 * report a trivial "match" at that huge, unbounded position -- with
 * nothing on the old side to compare, its per-item loop never ran, so it
 * never reached the bounds check on `pos`. apply_section() then copied
 * target->v[] up to that position, reading heap memory far past the
 * small backing array (crash, or adjacent heap bytes leaking into the
 * patched output) -- see the pos>target->n check now at the top of
 * side_matches() in src/util/patch.c. This exercises that exact shape
 * (insert-only hunk, absurd old_start, small target) and checks patch
 * still exits cleanly with a fully deterministic result: the fix clamps
 * the search to the file's own bounds, so the insertion lands at EOF
 * instead of reading past it. */
static const char OOB_INSERT_DIFF[] =
	"--- orig\t2026-01-01\n"
	"+++ orig\t2026-01-01\n"
	"@@ -9999,0 +1,1 @@\n"
	"+INJECTED\n";

static void test_oob_insert_line_is_bounded(void)
{
	char *argv[] = { (char *)"patch", (char *)"-i", (char *)"scratch/oob.diff", (char *)"scratch/orig", 0 };
	make_file("scratch/orig", ORIG_CONTENT);
	make_file("scratch/oob.diff", OOB_INSERT_DIFF);
	check_applied(argv, "scratch/orig", ORIG_CONTENT "INJECTED\n");
}

/* A patch header's "+++"/"---" filename is patch content, not something
 * the invoking user typed. Without pick_target_name()'s name_is_unsafe()
 * check, a header naming a path outside the current directory (here,
 * one level up via "..") would have patch happily read and overwrite it
 * -- with no file operand to override the header's own choice of name,
 * exactly the case a crafted/untrusted patch can arrange. Confirm patch
 * now refuses instead of touching anything outside scratch/, and that
 * the traversal target is never created. */
static const char TRAVERSAL_DIFF[] =
	"--- ../patch-traversal-canary\t2026-01-01\n"
	"+++ ../patch-traversal-canary\t2026-01-01\n"
	"@@ -0,0 +1,1 @@\n"
	"+pwned\n";

static void test_header_path_traversal_refused(void)
{
	char *argv[] = { (char *)"patch", (char *)"-i", (char *)"scratch/trav.diff", 0 };
	unlink("patch-traversal-canary");
	make_file("scratch/trav.diff", TRAVERSAL_DIFF);
	CHECK(run(patch_path, argv) == 2);
	CHECK(access("patch-traversal-canary", F_OK) != 0);
	unlink("patch-traversal-canary");
}

/* ==== the shell built-in agrees with the standalone executable =========== */

static void test_builtin_matches_standalone(void)
{
	make_file("scratch/orig", ORIG_CONTENT);
	CHECK(run_sh_c("patch -i scratch/u.diff scratch/orig") == 0);
	CHECK(file_equals("scratch/orig", CHANGED_CONTENT));
}

/* ==== scratch directory setup/teardown =================================== */

static void rmtree_scratch(void)
{
	unlink("scratch/orig"); unlink("scratch/orig.rej"); unlink("scratch/orig.orig");
	unlink("scratch/u.diff"); unlink("scratch/c.diff"); unlink("scratch/n.diff");
	unlink("scratch/e.diff"); unlink("scratch/r.diff"); unlink("scratch/p.diff");
	unlink("scratch/pfile"); unlink("scratch/out.txt");
	unlink("scratch/oob.diff"); unlink("scratch/trav.diff");
	unlink("scratch/.keep");
	rmdir("scratch");
}

static void cleanup_artifacts(void)
{
	unlink(ERRFILE);
	rmtree_scratch();
}

int main(int argc, char **argv)
{
	(void)argc;

	if (find_obj_root(argv[0]) != 0) {
		printf("SKIP util-patch: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(patch_path, sizeof patch_path, "bin/patch.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(patch_path, R_OK) != 0 || access(sh_path, R_OK) != 0) {
		printf("SKIP util-patch: patch or sh binary is missing\n");
		return 77;
	}

	rmtree_scratch();
	if (mkdir("scratch", 0755) != 0) {
		printf("SKIP util-patch: cannot create scratch/ (%s)\n", strerror(errno));
		return 77;
	}
	make_file("scratch/.keep", "");

	test_unified_basic();
	test_context_basic();
	test_normal_basic_requires_operand();
	test_normal_basic();
	test_ed_basic();
	test_ed_reverse_refused();
	test_reverse();
	test_p_strip_no_operand();
	test_reject_creates_rejfile();
	test_already_applied_default_rejects();
	test_already_applied_dash_N_is_silent();
	test_dash_o_leaves_target_untouched();
	test_dash_b_backs_up_original();
	test_oob_insert_line_is_bounded();
	test_header_path_traversal_refused();
	test_builtin_matches_standalone();

	cleanup_artifacts();

	if (fails) { printf("util-patch: failures: %d\n", fails); return 1; }
	printf("util-patch: all ok (patch -- unified/context/normal/ed formats, -R/-p/-N/-o/-b, standalone and builtin)\n");
	return 0;
}
