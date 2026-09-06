/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for ntlibc's Tier 5 "process/environment" utilities:
 * `time` and `timeout` (XCU time(1p); timeout is not XCU-mandatory --
 * see src/util/timeout.c's own header comment). Same technique as
 * test/util-sortset.c: the standalone obj/bin/<name>.exe is spawned as
 * a real process (via __spawn()+waitpid()), and the shell built-in is
 * exercised too (via obj/sh/sh.exe -c), confirming both callers of
 * __util_<name>_main() (src/internal/util.h) agree.
 *
 * `time`'s tests can't check the numeric fields (real wall-clock/CPU
 * time is inherently nondeterministic), so they check exactly what IS
 * deterministic: the three-line "real \nuser \nsys \n" shape and order
 * XCU time(1p)'s -p format pins down (src/util/util_time.c's header
 * comment), and that the exit status is the run utility's own.
 *
 * `timeout`'s tests exercise every exit-status bucket its own header
 * comment documents (124/125/126/127/137/passthrough) and the real
 * escalation logic (-k), not just the trivial "did it eventually
 * return" case:
 *  - the -k-present-but-unneeded case (default TERM kills the child
 *    well inside the grace period) must still report 124, not 137 --
 *    a wrong implementation that reports 137 whenever -k is merely
 *    *present* would pass a naive "did it time out" check but fail
 *    this one specifically.
 *  - the real escalation case uses `-s STOP` as the *initial* signal
 *    deliberately: SIGSTOP does not terminate the child (there is no
 *    `trap` builtin in this shell to make a SIGTERM-ignoring child
 *    otherwise), so the child is still alive when -k's own grace
 *    deadline arrives, forcing the real SIGKILL escalation path (not
 *    just the "child happened to already be gone" path) and pinning
 *    the exit status to 137.
 *  - duration 0 ("disables the associated timeout", GNU Coreutils
 *    manual, quoted in src/util/timeout.c) is checked to actually run
 *    the command to completion rather than firing immediately, which
 *    a naive "0 means immediate deadline" reading would get backwards.
 *
 * Every duration used below is small (0.2s at most, chosen well above
 * this file's own POLL_INTERVAL_NS-equivalent granularity in
 * src/util/timeout.c so a slow CI host cannot flake the boundary) so
 * this file's own runtime stays short even though every test really
 * does wait out a real clock.
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

/* Same walk-up-from-argv[0] technique as test/util-sortset.c's
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
	p[-1] = 0; /* strip "/util-timeutil.exe" */

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

#define OUTFILE "util-timeutil-out.txt"
#define ERRFILE "util-timeutil-err.txt"

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

static int err_index_of(const char *needle)
{
	char buf[4096];
	char *p;
	slurp_into(ERRFILE, buf, sizeof buf);
	p = strstr(buf, needle);
	return p ? (int)(p - buf) : -1;
}

static char time_path[1024], timeout_path[1024], sh_path[1024];
static char true_path[1024], false_path[1024];

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

/* ==== time(1p) ============================================================ */

static void check_timing_report(void)
{
	int ri = err_index_of("real "), ui = err_index_of("user "), si = err_index_of("sys ");
	CHECK(ri >= 0 && ui >= 0 && si >= 0);
	CHECK(ri < ui && ui < si);
}

/* Every operand below that names a *real* command for time/timeout to
 * spawn uses the fully resolved obj/bin/NAME.exe path (true_path, not
 * bare "true"), deliberately: __util_time_main()/__util_timeout_main()
 * always resolve their own utility operand via __find_program()/PATH
 * (see each file's header comment on why -- they never dispatch to a
 * shell builtin in-process), and this test process's own PATH is
 * whatever tools/run-tests.py's harness happens to export, not
 * something this file can assume points at obj/bin at all. A
 * directory-qualified path skips the PATH search entirely
 * (src/process/find_program.c's has_dir()), which is what every such
 * case below relies on instead. The two "command not found" cases
 * below are the deliberate exception -- they need the PATH search to
 * actually run and fail, so they use a bare, nonexistent name instead;
 * see the comment on test_time_command_not_found() for why. */

static void test_time_basic(void)
{
	char *argv[] = { (char *)"time", true_path, 0 };
	CHECK(run(time_path, argv) == 0);
	check_timing_report();
}

/* -p is accepted but, per src/util/util_time.c's header comment, this
 * implementation always emits the -p format regardless -- so this
 * must produce the exact same shape test_time_basic() already checks. */
static void test_time_dash_p(void)
{
	char *argv[] = { (char *)"time", (char *)"-p", true_path, 0 };
	CHECK(run(time_path, argv) == 0);
	check_timing_report();
}

/* The run utility's own exit status must pass through time unchanged
 * -- time itself never fails just because the timed command did. */
static void test_time_propagates_exit_status(void)
{
	char *argv[] = { (char *)"time", false_path, 0 };
	CHECK(run(time_path, argv) == 1);
	check_timing_report();
}

static void test_time_missing_operand(void)
{
	char *argv[] = { (char *)"time", 0 };
	CHECK(run(time_path, argv) == 1);
	CHECK(err_contains("missing operand"));
}

/* Bare (non-slash-qualified) name, deliberately: only a name with no
 * directory part goes through __find_program()'s PATH search, whose
 * own failure (no candidate anywhere on PATH) is what actually
 * produces this "command not found" text (src/util/util_time.c). A
 * slash-qualified path that doesn't exist takes a different path
 * entirely -- __find_program()'s has_dir() branch (src/process/find_
 * program.c) returns it unchecked, so the ENOENT instead surfaces
 * from the __spawn() attempt itself as strerror(ENOENT) ("No such
 * file or directory"), exactly like real bash/GNU coreutils report it
 * (verified directly: `bash -c ./no-such-utility-xyz` and `timeout 2
 * ./no-such-utility-xyz` both say "No such file or directory", while
 * the bare-name form says "command not found") -- so a slash-qualified
 * operand here would not exercise this message at all. */
static void test_time_command_not_found(void)
{
	char *argv[] = { (char *)"time", (char *)"no-such-utility-xyz", 0 };
	CHECK(run(time_path, argv) == 127);
	CHECK(err_contains("command not found"));
}

/* ==== timeout ============================================================= */

static void test_timeout_command_finishes_in_time(void)
{
	char *argv[] = { (char *)"timeout", (char *)"2", true_path, 0 };
	CHECK(run(timeout_path, argv) == 0);
}

static void test_timeout_propagates_exit_status(void)
{
	char *argv[] = { (char *)"timeout", (char *)"2", false_path, 0 };
	CHECK(run(timeout_path, argv) == 1);
}

/* Duration 0 disables the timeout entirely (this file's header
 * comment) -- must run to completion, not fire immediately. */
static void test_timeout_zero_duration_disables(void)
{
	char *argv[] = { (char *)"timeout", (char *)"0", true_path, 0 };
	CHECK(run(timeout_path, argv) == 0);
}

/* No -k: the child outlives the deadline running an unkillable-by-
 * anything-but-force busy loop, gets the default SIGTERM, and (since
 * a plain shell process has no trap installed) actually dies from it
 * -- exit 124, the plain "timed out" bucket. */
static void test_timeout_expires_default_signal(void)
{
	char *argv[] = { (char *)"timeout", (char *)"0.2", sh_path,
		(char *)"-c", (char *)"while :; do :; done", 0 };
	CHECK(run(timeout_path, argv) == 124);
}

/* -s KILL as the *initial* signal: per the man page wording quoted in
 * src/util/timeout.c's header comment, "sent the KILL(9) signal" is
 * 137 regardless of whether SIGKILL was the first signal or an -k
 * escalation. */
static void test_timeout_custom_signal_kill(void)
{
	char *argv[] = { (char *)"timeout", (char *)"-s", (char *)"KILL",
		(char *)"0.2", sh_path, (char *)"-c", (char *)"while :; do :; done", 0 };
	CHECK(run(timeout_path, argv) == 137);
}

/* -k present but not needed: the default TERM signal kills the child
 * well inside the 5s grace period, so this must still be 124, not
 * 137 -- see this file's header comment for why this case matters. */
static void test_timeout_kill_after_not_needed(void)
{
	char *argv[] = { (char *)"timeout", (char *)"-k", (char *)"5",
		(char *)"0.2", sh_path, (char *)"-c", (char *)"while :; do :; done", 0 };
	CHECK(run(timeout_path, argv) == 124);
}

/* Real escalation: -s STOP never terminates the child on its own, so
 * it is still alive when -k's own 0.2s grace deadline arrives, forcing
 * the actual SIGKILL escalation this file's header comment describes.
 * Exit status must be 137, not 124 -- distinguishing this from the
 * "not needed" case immediately above. */
static void test_timeout_kill_after_escalates(void)
{
	char *argv[] = { (char *)"timeout", (char *)"-s", (char *)"STOP",
		(char *)"-k", (char *)"0.2", (char *)"0.2", sh_path,
		(char *)"-c", (char *)"while :; do :; done", 0 };
	CHECK(run(timeout_path, argv) == 137);
}

static void test_timeout_missing_operand(void)
{
	char *argv[] = { (char *)"timeout", 0 };
	CHECK(run(timeout_path, argv) == 125);
	CHECK(err_contains("missing operand"));
}

static void test_timeout_invalid_duration(void)
{
	char *argv[] = { (char *)"timeout", (char *)"notanumber", (char *)"true", 0 };
	CHECK(run(timeout_path, argv) == 125);
	CHECK(err_contains("invalid duration"));
}

/* strtod() (src/stdlib/strtod.c) accepts the C99 "inf"/"infinity"/
 * "nan" spellings, and silently saturates to HUGE_VAL on plain
 * numeric overflow (e.g. "1e400") -- both would previously sail
 * through parse_duration()'s only range check ("v < 0", false for
 * +inf and for NaN alike) and reach deadline_after()'s "(time_t)secs"
 * cast, which is undefined behavior for a non-finite double or one
 * whose integral part doesn't fit time_t (C11 6.3.1.4). All three
 * must now be rejected as a plain invalid duration (125), the same
 * as test_timeout_invalid_duration()'s "notanumber" case, rather than
 * crashing or hanging. */
static void test_timeout_infinite_duration_rejected(void)
{
	char *argv1[] = { (char *)"timeout", (char *)"inf", (char *)"true", 0 };
	CHECK(run(timeout_path, argv1) == 125);
	CHECK(err_contains("invalid duration"));

	{
		char *argv2[] = { (char *)"timeout", (char *)"1e400", (char *)"true", 0 };
		CHECK(run(timeout_path, argv2) == 125);
		CHECK(err_contains("invalid duration"));
	}

	{
		char *argv3[] = { (char *)"timeout", (char *)"nan", (char *)"true", 0 };
		CHECK(run(timeout_path, argv3) == 125);
		CHECK(err_contains("invalid duration"));
	}

	/* A huge but *finite* value, pushed to infinity only by the 'd'
	 * unit multiply inside parse_duration() itself -- exercises the
	 * post-multiply check, not just the pre-multiply strtod() result. */
	{
		char *argv4[] = { (char *)"timeout", (char *)"3e304d", (char *)"true", 0 };
		CHECK(run(timeout_path, argv4) == 125);
		CHECK(err_contains("invalid duration"));
	}

	/* Also exercised via -k's duration, which shares parse_duration(). */
	{
		char *argv5[] = { (char *)"timeout", (char *)"-k", (char *)"inf",
			(char *)"2", (char *)"true", 0 };
		CHECK(run(timeout_path, argv5) == 125);
		CHECK(err_contains("invalid duration"));
	}
}

static void test_timeout_invalid_signal(void)
{
	char *argv[] = { (char *)"timeout", (char *)"-s", (char *)"NOTASIGNAL",
		(char *)"2", (char *)"true", 0 };
	CHECK(run(timeout_path, argv) == 125);
	CHECK(err_contains("invalid signal"));
}

/* Bare name -- see test_time_command_not_found()'s comment above for
 * why a slash-qualified operand would not exercise this message. */
static void test_timeout_command_not_found(void)
{
	char *argv[] = { (char *)"timeout", (char *)"2", (char *)"no-such-utility-xyz", 0 };
	CHECK(run(timeout_path, argv) == 127);
	CHECK(err_contains("command not found"));
}

/* ==== the shell built-ins agree with the standalone executables ========== */

static void test_builtins_match_standalone(void)
{
	/* Single-quoted below for the same reason the block comment above
	 * test_time_basic() gives: bi_time()/bi_timeout() (src/sh/builtin.c)
	 * still resolve their own utility operand via plain PATH search,
	 * not shell-builtin dispatch, so the operand has to be a
	 * directory-qualified path here too -- and single-quoting it
	 * keeps a Windows-style "C:\..." path's backslashes literal
	 * rather than the shell's own escape character. */
	char cmd[2048];

	snprintf(cmd, sizeof cmd, "time '%s'", true_path);
	CHECK(run_sh_c(cmd) == 0);
	check_timing_report();

	snprintf(cmd, sizeof cmd, "timeout 2 '%s'", true_path);
	CHECK(run_sh_c(cmd) == 0);

	snprintf(cmd, sizeof cmd, "timeout 0.2 '%s' -c 'while :; do :; done'", sh_path);
	CHECK(run_sh_c(cmd) == 124);
}

/* ==== scratch cleanup ====================================================== */

static void cleanup_artifacts(void)
{
	unlink(OUTFILE);
	unlink(ERRFILE);
}

int main(int argc, char **argv)
{
	(void)argc;

	if (find_obj_root(argv[0]) != 0) {
		printf("SKIP util-timeutil: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(time_path, sizeof time_path, "bin/time.exe");
	path_for(timeout_path, sizeof timeout_path, "bin/timeout.exe");
	path_for(true_path, sizeof true_path, "bin/true.exe");
	path_for(false_path, sizeof false_path, "bin/false.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(time_path, R_OK) != 0 || access(timeout_path, R_OK) != 0 ||
	    access(true_path, R_OK) != 0 || access(false_path, R_OK) != 0 ||
	    access(sh_path, R_OK) != 0) {
		printf("SKIP util-timeutil: one or more of the two utility binaries, true/false or sh is missing\n");
		return 77;
	}

	test_time_basic();
	test_time_dash_p();
	test_time_propagates_exit_status();
	test_time_missing_operand();
	test_time_command_not_found();

	test_timeout_command_finishes_in_time();
	test_timeout_propagates_exit_status();
	test_timeout_zero_duration_disables();
	test_timeout_expires_default_signal();
	test_timeout_custom_signal_kill();
	test_timeout_kill_after_not_needed();
	test_timeout_kill_after_escalates();
	test_timeout_missing_operand();
	test_timeout_invalid_duration();
	test_timeout_infinite_duration_rejected();
	test_timeout_invalid_signal();
	test_timeout_command_not_found();

	test_builtins_match_standalone();

	cleanup_artifacts();

	if (fails) { printf("util-timeutil: failures: %d\n", fails); return 1; }
	printf("util-timeutil: all ok (time, timeout -- standalone and builtin)\n");
	return 0;
}
