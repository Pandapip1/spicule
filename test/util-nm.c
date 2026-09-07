/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for spicule's nm(1p) (Software Development option
 * tier, this project's own POSIX-utilities plan's final tier). Same
 * technique as test/util-archive.c: the standalone obj/bin/nm.exe is
 * spawned as a real process (via __spawn()+waitpid()), and the shell
 * built-in is exercised too (via obj/sh/sh.exe -c), confirming both
 * callers of __util_nm_main() (src/internal/util.h) agree.
 *
 * The real symbol-table assertions run against obj/test/nmfix.o
 * (test/nmfix-src/nmfix.c, compiled -- never linked -- by the
 * Makefile's own obj/test/nmfix.o rule), a tiny fixture with known,
 * predictable symbols covering every type letter src/util/nm.c's own
 * header comment documents: a global function (T), a local/static
 * function (t), a global initialized data object (D), a global
 * uninitialized bss object (B), and a reference to an external,
 * undefined symbol (U).
 *
 * On PLATFORM=linux (this build's own real CC), nmfix.o is a genuine
 * ELF64 little-endian object, so the full set of assertions below runs
 * for real. On the NT/tcc cross build, the same source compiles to a
 * genuine COFF object instead -- src/util/nm.c deliberately does not
 * read that format (see its own header comment on scope), so this test
 * degrades to checking that nm reports a real, graceful "unrecognized
 * format" diagnostic (nonzero exit, no crash) rather than misparsing
 * it -- this is the same defensive shape test/util-archive.c's
 * own test_file_symlink() uses for a platform capability that may not
 * be present ("no symlink support here; skip quietly"), just applied to
 * an object *format* instead of a filesystem feature.
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

	if (strip_last_component(obj_root) != 0) return -1; /* strip "/util-nm.exe" */
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

#define OUTFILE "util-nm-out.txt"
#define ERRFILE "util-nm-err.txt"

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

static char last_out[16384], last_err[16384];

static void capture(void)
{
	slurp_into(OUTFILE, last_out, sizeof last_out);
	slurp_into(ERRFILE, last_err, sizeof last_err);
}

static int out_contains(const char *needle) { return strstr(last_out, needle) != 0; }
static int err_contains(const char *needle) { return strstr(last_err, needle) != 0; }

static int is_elf64le(const char *path)
{
	unsigned char hdr[20];
	FILE *f = fopen(path, "rb");
	size_t n;
	if (!f) return 0;
	n = fread(hdr, 1, sizeof hdr, f);
	fclose(f);
	return n >= 20 && hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F' &&
	       hdr[4] == 2 /* ELFCLASS64 */ && hdr[5] == 1 /* ELFDATA2LSB */;
}

static char nm_path[1024], sh_path[1024], fixture_path[1024];

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

/* Runs nm and captures its stdout/stderr for the CHECK()s that follow
 * -- every test below needs both, immediately after spawning. */
static int run_capture(const char *path, char *const *args)
{
	int rc = run(path, args);
	capture();
	return rc;
}

/* ==== nm(1p) =============================================================== */

static void test_nm_missing_file(void)
{
	char *argv[] = { (char *)"nm", (char *)"util-nm-missing-xyz.o", 0 };
	int rc = run_capture(nm_path, argv);
	CHECK(rc != 0);
	CHECK(err_contains("nm:"));
}

static void test_nm_invalid_option(void)
{
	char *argv[] = { (char *)"nm", (char *)"--bogus", 0 };
	int rc = run_capture(nm_path, argv);
	CHECK(rc == 2);
	CHECK(err_contains("invalid option"));
}

static void test_nm_non_elf_graceful(void)
{
	/* Any ordinary text file is neither an ar archive nor an ELF64
	 * object -- nm must reject it with a real diagnostic and a
	 * nonzero exit, never crash or print garbage. */
	char *argv[] = { (char *)"nm", (char *)"scratch_nm/not_an_object.txt", 0 };
	int fd;

	mkdir("scratch_nm", 0755);
	fd = open("scratch_nm/not_an_object.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd >= 0) { write(fd, "hello world\n", 12); close(fd); }

	CHECK(run_capture(nm_path, argv) != 0);
	CHECK(err_contains("nm:"));
}

/* Position of `needle` in the last captured stdout, or -1 if absent --
 * used to check the default alphabetical-by-name sort order. */
static long pos_of(const char *needle)
{
	const char *p = strstr(last_out, needle);
	return p ? (long)(p - last_out) : -1;
}

static void test_nm_fixture_default(void)
{
	char *argv[] = { (char *)"nm", fixture_path, 0 };
	int rc = run_capture(nm_path, argv);

	if (!is_elf64le(fixture_path)) {
		/* NT/tcc cross build: nmfix.o is a real COFF object, which
		 * src/util/nm.c deliberately does not parse -- see this
		 * file's own header comment. Confirm the graceful-refusal
		 * path instead of the ELF assertions below. */
		CHECK(rc != 0);
		CHECK(err_contains("nm:"));
		return;
	}

	CHECK(rc == 0);
	CHECK(out_contains("T nmfix_global_func"));
	CHECK(out_contains("t nmfix_local_func"));
	CHECK(out_contains("D nmfix_global_data"));
	CHECK(out_contains("B nmfix_global_bss"));
	CHECK(out_contains("U nmfix_external_undefined"));

	/* Default order is alphabetical by name:
	 * nmfix_external_undefined < nmfix_global_bss < nmfix_global_data
	 * < nmfix_global_func < nmfix_local_func. */
	{
		long p_u = pos_of("nmfix_external_undefined");
		long p_b = pos_of("nmfix_global_bss");
		long p_d = pos_of("nmfix_global_data");
		long p_f = pos_of("nmfix_global_func");
		long p_l = pos_of("nmfix_local_func");
		CHECK(p_u >= 0 && p_b >= 0 && p_d >= 0 && p_f >= 0 && p_l >= 0);
		CHECK(p_u < p_b);
		CHECK(p_b < p_d);
		CHECK(p_d < p_f);
		CHECK(p_f < p_l);
	}

	/* Undefined symbols print a blank value field, not a fabricated
	 * all-zero address. */
	CHECK(!out_contains("0000000000000000 U"));
}

static void test_nm_undefined_only(void)
{
	char *argv[] = { (char *)"nm", (char *)"-u", fixture_path, 0 };
	int rc;
	if (!is_elf64le(fixture_path)) return;

	rc = run_capture(nm_path, argv);
	CHECK(rc == 0);
	CHECK(out_contains("U nmfix_external_undefined"));
	CHECK(!out_contains("nmfix_global_func"));
	CHECK(!out_contains("nmfix_global_data"));
	CHECK(!out_contains("nmfix_global_bss"));
	CHECK(!out_contains("nmfix_local_func"));
}

static void test_nm_external_only(void)
{
	char *argv[] = { (char *)"nm", (char *)"-g", fixture_path, 0 };
	int rc;
	if (!is_elf64le(fixture_path)) return;

	rc = run_capture(nm_path, argv);
	CHECK(rc == 0);
	CHECK(out_contains("nmfix_global_func"));
	CHECK(out_contains("nmfix_global_data"));
	CHECK(out_contains("nmfix_global_bss"));
	CHECK(out_contains("nmfix_external_undefined"));
	/* -g: local/static symbols are excluded entirely. */
	CHECK(!out_contains("nmfix_local_func"));
}

static void test_nm_no_sort_and_value_sort_smoke(void)
{
	char *argv_p[] = { (char *)"nm", (char *)"-p", fixture_path, 0 };
	char *argv_v[] = { (char *)"nm", (char *)"-v", fixture_path, 0 };
	if (!is_elf64le(fixture_path)) return;

	CHECK(run_capture(nm_path, argv_p) == 0);
	CHECK(out_contains("nmfix_global_func"));
	CHECK(out_contains("nmfix_local_func"));

	CHECK(run_capture(nm_path, argv_v) == 0);
	CHECK(out_contains("nmfix_global_data"));
	CHECK(out_contains("nmfix_global_bss"));
}

static void test_nm_builtin(void)
{
	char cmd[512];
	snprintf(cmd, sizeof cmd, "nm %s", fixture_path);
	CHECK(run_sh_c(cmd) == 0);
	capture();
	if (is_elf64le(fixture_path)) {
		CHECK(out_contains("nmfix_global_func"));
		CHECK(out_contains("nmfix_external_undefined"));
	}
}

/* ==== scratch directory setup/teardown ==================================== */

static void cleanup_artifacts(void)
{
	unlink(OUTFILE);
	unlink(ERRFILE);
	unlink("scratch_nm/not_an_object.txt");
	rmdir("scratch_nm");
}

int main(int argc, char **argv)
{
	(void)argc;

	if (find_obj_root(argv[0]) != 0) {
		printf("SKIP util-nm: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(nm_path, sizeof nm_path, "bin/nm.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");
	path_for(fixture_path, sizeof fixture_path, "test/nmfix.o");

	if (access(nm_path, R_OK) != 0 || access(sh_path, R_OK) != 0 ||
	    access(fixture_path, R_OK) != 0) {
		printf("SKIP util-nm: nm.exe, sh.exe, or the nmfix.o fixture is missing\n");
		return 77;
	}

	cleanup_artifacts();

	test_nm_missing_file();
	test_nm_invalid_option();
	test_nm_non_elf_graceful();
	test_nm_fixture_default();
	test_nm_undefined_only();
	test_nm_external_only();
	test_nm_no_sort_and_value_sort_smoke();
	test_nm_builtin();

	cleanup_artifacts();

	if (fails) { printf("util-nm: failures: %d\n", fails); return 1; }
	printf("util-nm: all ok (nm -- standalone and builtin)\n");
	return 0;
}
