/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for ntlibc's data-copying/reporting POSIX standard
 * utilities: `dd`, `df`, `du`, `cksum`, `uuencode`, `uudecode` (XCU
 * dd(1p), df(1p), du(1p), cksum(1p), uuencode(1p), uudecode(1p)).  Same
 * technique as test/util-fsops.c: the standalone obj/bin/<name>.exe is
 * spawned as a real process (via __spawn()+waitpid()), and the shell
 * built-in is exercised too (via obj/sh/sh.exe -c), confirming both
 * callers of __util_<name>_main() (src/internal/util.h) agree.
 *
 * cksum's reference values below are not trusted from the algorithm
 * description alone -- they are real output from a real, independent
 * `cksum(1)` (GNU coreutils, verified against this project's own
 * src/util/cksum.c header comment on empty-input=4294967295 as a sanity
 * anchor): `printf '' | cksum`, `printf 'abc' | cksum`, `printf '123456789'
 * | cksum` and a longer pangram, captured once and hardcoded here so a
 * silent algorithm regression (e.g. accidentally reflecting the
 * polynomial, or picking up zlib's crc32() instead) fails this test
 * immediately instead of only ever producing "some number".
 *
 * uuencode/uudecode round-trips a real binary-ish payload (all 256 byte
 * values, not just printable ASCII) through `uuencode | uudecode -o`,
 * both as standalone processes and through the shell built-ins, and
 * compares the result byte-for-byte against the original -- catching
 * any off-by-one in the 6-bit packing/unpacking that a text-only payload
 * could hide (e.g. a bug that only shows up when a decoded byte's high
 * bit is set).
 *
 * All fixtures live under a scratch subdirectory of the test's own
 * working directory, created fresh in main() and removed again by
 * cleanup_artifacts() -- see test/util-fsops.c's identical reasoning.
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

/* Same walk-up-from-argv[0] technique as test/util-fsops.c's
 * find_obj_root(), copied rather than shared since these are two
 * independent translation units and the whole function is short. */
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
	obj_root[i - 1] = 0; /* strip "/util-datacopy.exe" */

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

#define OUTFILE "util-datacopy-out.txt"
#define ERRFILE "util-datacopy-err.txt"

static int run3(const char *path, char *const *args, int in_fd)
{
	int out, err;
	int s0, s1, s2, pid, status;

	out = open(OUTFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	err = open(ERRFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (out < 0 || err < 0) { if (out >= 0) close(out); if (err >= 0) close(err); return -1; }

	s0 = dup(0); s1 = dup(1); s2 = dup(2);
	if (in_fd >= 0) dup2(in_fd, 0);
	dup2(out, 1);
	dup2(err, 2);
	close(out); close(err);

	pid = __spawn(path, args, environ);

	dup2(s0, 0); close(s0);
	dup2(s1, 1); close(s1);
	dup2(s2, 2); close(s2);

	if (pid < 0) return -1;
	if (waitpid(pid, &status, 0) != pid) return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static int run(const char *path, char *const *args)
{
	return run3(path, args, -1);
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
	char buf[8192];
	slurp_into(ERRFILE, buf, sizeof buf);
	return strstr(buf, needle) != 0;
}

static int out_contains(const char *needle)
{
	char buf[8192];
	slurp_into(OUTFILE, buf, sizeof buf);
	return strstr(buf, needle) != 0;
}

static void make_file(const char *path, const void *contents, size_t n)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return;
	if (contents && n) write(fd, contents, n);
	close(fd);
}

static int copy_file(const char *src, const char *dst)
{
	FILE *fs = fopen(src, "rb"), *fd;
	char buf[4096];
	size_t n;
	int ok = 1;

	if (!fs) return -1;
	fd = fopen(dst, "wb");
	if (!fd) { fclose(fs); return -1; }
	while ((n = fread(buf, 1, sizeof buf, fs)) > 0)
		if (fwrite(buf, 1, n, fd) != n) { ok = 0; break; }
	fclose(fs);
	fclose(fd);
	return ok ? 0 : -1;
}

static int files_equal(const char *a, const char *b)
{
	FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
	int eq = 1;
	if (!fa || !fb) { if (fa) fclose(fa); if (fb) fclose(fb); return 0; }
	for (;;) {
		int ca = fgetc(fa), cb = fgetc(fb);
		if (ca != cb) { eq = 0; break; }
		if (ca == EOF) break;
	}
	fclose(fa); fclose(fb);
	return eq;
}

static char dd_path[1024], df_path[1024], du_path[1024];
static char cksum_path[1024], uuencode_path[1024], uudecode_path[1024], sh_path[1024];

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

/* ==== cksum(1p) =========================================================
 *
 * All four reference values are real `cksum(1)` output, not derived from
 * this project's own implementation -- see this file's header. */

static void test_cksum_empty_stdin(void)
{
	char *argv[] = { (char *)"cksum", 0 };
	int devnull = open("scratch/empty", O_RDONLY);
	CHECK(devnull >= 0);
	CHECK(run3(cksum_path, argv, devnull) == 0);
	if (devnull >= 0) close(devnull);
	CHECK(out_contains("4294967295 0\n"));
}

static void test_cksum_known_values(void)
{
	static const struct { const char *data; const char *expect; } cases[] = {
		{ "abc", "1219131554 3 " },
		{ "123456789", "930766865 9 " },
		{ "The quick brown fox jumps over the lazy dog", "2074844392 43 " },
	};
	size_t i;
	for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		char *argv[] = { (char *)"cksum", (char *)"scratch/cksum-in", 0 };
		make_file("scratch/cksum-in", cases[i].data, strlen(cases[i].data));
		CHECK(run(cksum_path, argv) == 0);
		CHECK(out_contains(cases[i].expect));
	}
	unlink("scratch/cksum-in");
}

static void test_cksum_missing_file_is_an_error(void)
{
	char *argv[] = { (char *)"cksum", (char *)"scratch/does-not-exist", 0 };
	CHECK(run(cksum_path, argv) != 0);
	CHECK(err_contains("cksum:"));
}

/* ==== dd(1p) ============================================================= */

static void test_dd_basic_copy(void)
{
	char *argv[] = { (char *)"dd", (char *)"if=scratch/dd-src", (char *)"of=scratch/dd-dst", (char *)"bs=16", 0 };
	const char data[] = "0123456789abcdefXYZ";
	make_file("scratch/dd-src", data, sizeof data - 1);
	CHECK(run(dd_path, argv) == 0);
	CHECK(files_equal("scratch/dd-src", "scratch/dd-dst"));
	/* dd(1p): the "N+P records in / N+P records out" summary is
	 * required output, not cosmetic -- on stderr regardless of success. */
	CHECK(err_contains("records in"));
	CHECK(err_contains("records out"));
	unlink("scratch/dd-src"); unlink("scratch/dd-dst");
}

static void test_dd_count_limits_input(void)
{
	char *argv[] = { (char *)"dd", (char *)"if=scratch/dd-src2", (char *)"of=scratch/dd-dst2",
	                 (char *)"bs=4", (char *)"count=2", 0 };
	struct stat st;
	make_file("scratch/dd-src2", "AAAABBBBCCCCDDDD", 16);
	CHECK(run(dd_path, argv) == 0);
	CHECK(stat("scratch/dd-dst2", &st) == 0 && st.st_size == 8);
	unlink("scratch/dd-src2"); unlink("scratch/dd-dst2");
}

static void test_dd_skip_and_seek(void)
{
	char *argv[] = { (char *)"dd", (char *)"if=scratch/dd-src3", (char *)"of=scratch/dd-dst3",
	                 (char *)"bs=4", (char *)"skip=1", 0 };
	char buf[16];
	FILE *f;
	make_file("scratch/dd-src3", "AAAABBBBCCCC", 12);
	CHECK(run(dd_path, argv) == 0);
	f = fopen("scratch/dd-dst3", "rb");
	CHECK(f != 0);
	if (f) {
		size_t n = fread(buf, 1, sizeof buf, f);
		CHECK(n == 8 && !memcmp(buf, "BBBBCCCC", 8));
		fclose(f);
	}
	unlink("scratch/dd-src3"); unlink("scratch/dd-dst3");
}

static void test_dd_seek(void)
{
	char *argv[] = { (char *)"dd", (char *)"if=scratch/dd-src6", (char *)"of=scratch/dd-dst6",
	                 (char *)"bs=4", (char *)"seek=2", (char *)"conv=notrunc", 0 };
	char buf[16];
	FILE *f;
	make_file("scratch/dd-dst6", "XXXXXXXXXXXX", 12); /* 3 blocks of 4 */
	make_file("scratch/dd-src6", "AAAA", 4);
	CHECK(run(dd_path, argv) == 0);
	f = fopen("scratch/dd-dst6", "rb");
	CHECK(f != 0);
	if (f) {
		size_t n = fread(buf, 1, sizeof buf, f);
		/* First two blocks (seek=2) left alone, third block overwritten. */
		CHECK(n == 12 && !memcmp(buf, "XXXXXXXXAAAA", 12));
		fclose(f);
	}
	unlink("scratch/dd-src6"); unlink("scratch/dd-dst6");
}

static void test_dd_conv_notrunc_preserves_tail(void)
{
	char *argv[] = { (char *)"dd", (char *)"if=scratch/dd-src4", (char *)"of=scratch/dd-dst4",
	                 (char *)"bs=4", (char *)"conv=notrunc", 0 };
	char buf[16];
	FILE *f;
	make_file("scratch/dd-dst4", "XXXXXXXXXXXXXXXX", 16);
	make_file("scratch/dd-src4", "AAAA", 4);
	CHECK(run(dd_path, argv) == 0);
	f = fopen("scratch/dd-dst4", "rb");
	CHECK(f != 0);
	if (f) {
		size_t n = fread(buf, 1, sizeof buf, f);
		/* First 4 bytes overwritten, the rest untouched -- notrunc's
		 * whole point. */
		CHECK(n == 16 && !memcmp(buf, "AAAAXXXXXXXXXXXX", 16));
		fclose(f);
	}
	unlink("scratch/dd-src4"); unlink("scratch/dd-dst4");
}

static void test_dd_unrecognized_conv_is_refused(void)
{
	char *argv[] = { (char *)"dd", (char *)"if=scratch/dd-src5", (char *)"of=scratch/dd-dst5",
	                 (char *)"conv=ebcdic", 0 };
	make_file("scratch/dd-src5", "AAAA", 4);
	CHECK(run(dd_path, argv) != 0);
	CHECK(err_contains("conv=ebcdic"));
	unlink("scratch/dd-src5");
}

static void test_dd_bad_operand_is_refused(void)
{
	char *argv[] = { (char *)"dd", (char *)"not-an-operand", 0 };
	CHECK(run(dd_path, argv) != 0);
}

/* Regression test for a real integer-overflow bug: parse_dd_num()'s 'k'
 * suffix multiply used to be a bare `v *= 1024` with no overflow check, so
 * a bs= value just past 2^54 silently wrapped mod 2^64 down to a small,
 * unrelated block size (18014398509481985k wrapped to exactly 1024)
 * instead of being rejected -- see src/util/dd.c's dd_mul_overflows(). */
static void test_dd_bs_suffix_overflow_is_refused(void)
{
	char *argv[] = { (char *)"dd", (char *)"if=scratch/dd-src7", (char *)"of=scratch/dd-dst7",
	                 (char *)"bs=18014398509481985k", 0 };
	make_file("scratch/dd-src7", "AAAA", 4);
	CHECK(run(dd_path, argv) != 0);
	CHECK(err_contains("invalid block size"));
	unlink("scratch/dd-src7"); unlink("scratch/dd-dst7");
}

/* Regression test for a real integer-overflow bug: dd_position() used to
 * compute `n * unit` (skip-count times block size) with no overflow check,
 * so skip=2^55 with the default ibs=512 (2^9) wrapped mod 2^64 down to
 * exactly 0 -- silently skipping nothing at all instead of either seeking
 * past the requested (enormous) offset or failing loudly. */
static void test_dd_skip_overflow_is_refused(void)
{
	char *argv[] = { (char *)"dd", (char *)"if=scratch/dd-src8", (char *)"of=scratch/dd-dst8",
	                 (char *)"skip=36028797018963968", 0 };
	make_file("scratch/dd-src8", "AAAABBBBCCCCDDDD", 16);
	CHECK(run(dd_path, argv) != 0);
	CHECK(err_contains("overflows"));
	unlink("scratch/dd-src8"); unlink("scratch/dd-dst8");
}

/* ==== df(1p) ============================================================= */

static void test_df_reports_on_an_operand(void)
{
	char *argv[] = { (char *)"df", (char *)"scratch", 0 };
	CHECK(run(df_path, argv) == 0);
	CHECK(out_contains("Filesystem"));
	CHECK(out_contains("scratch"));
}

static void test_df_dash_k(void)
{
	char *argv[] = { (char *)"df", (char *)"-k", (char *)"scratch", 0 };
	CHECK(run(df_path, argv) == 0);
	CHECK(out_contains("1024-blks"));
}

static void test_df_nonexistent_operand_is_an_error(void)
{
	char *argv[] = { (char *)"df", (char *)"scratch/does-not-exist", 0 };
	CHECK(run(df_path, argv) != 0);
	CHECK(err_contains("df:"));
}

/* ==== du(1p) ============================================================= */

static void test_du_reports_files_and_directories(void)
{
	char *argv_a[] = { (char *)"du", (char *)"-a", (char *)"scratch/dutree", 0 };
	char *argv_plain[] = { (char *)"du", (char *)"scratch/dutree", 0 };
	char *argv_s[] = { (char *)"du", (char *)"-s", (char *)"scratch/dutree", 0 };

	mkdir("scratch/dutree", 0755);
	mkdir("scratch/dutree/sub", 0755);
	make_file("scratch/dutree/f1", "hello world", 11);
	make_file("scratch/dutree/sub/f2", "hi", 2);

	CHECK(run(du_path, argv_a) == 0);
	CHECK(out_contains("scratch/dutree/f1"));
	CHECK(out_contains("scratch/dutree/sub/f2"));
	CHECK(out_contains("scratch/dutree/sub"));
	CHECK(out_contains("scratch/dutree\n") || out_contains("scratch/dutree"));

	/* Without -a: files themselves are not listed, only directories. */
	CHECK(run(du_path, argv_plain) == 0);
	CHECK(!out_contains("scratch/dutree/f1"));
	CHECK(out_contains("scratch/dutree/sub"));

	/* -s: exactly one line of output (the grand total), no children. */
	CHECK(run(du_path, argv_s) == 0);
	CHECK(!out_contains("scratch/dutree/sub"));
	{
		char buf[8192];
		int lines = 0, i;
		slurp_into(OUTFILE, buf, sizeof buf);
		for (i = 0; buf[i]; i++) if (buf[i] == '\n') lines++;
		CHECK(lines == 1);
	}

	unlink("scratch/dutree/f1");
	unlink("scratch/dutree/sub/f2");
	rmdir("scratch/dutree/sub");
	rmdir("scratch/dutree");
}

static void test_du_nonexistent_operand_is_an_error(void)
{
	char *argv[] = { (char *)"du", (char *)"scratch/does-not-exist", 0 };
	CHECK(run(du_path, argv) != 0);
}

/* ==== uuencode(1p) / uudecode(1p) =======================================
 *
 * A real binary-ish payload -- every byte value 0..255 once, not just
 * printable ASCII -- round-tripped through uuencode | uudecode -o and
 * compared byte-for-byte against the original.  See this file's header. */

static void make_binary_payload(const char *path)
{
	unsigned char buf[256];
	int i;
	for (i = 0; i < 256; i++) buf[i] = (unsigned char)i;
	make_file(path, buf, sizeof buf);
}

static void test_uuencode_uudecode_roundtrip_standalone(void)
{
	char *enc_argv[] = { (char *)"uuencode", (char *)"scratch/uu-src", (char *)"payload.bin", 0 };
	char *dec_argv[] = { (char *)"uudecode", (char *)"-o", (char *)"scratch/uu-out", (char *)"scratch/uu-mid", 0 };
	int fd;

	make_binary_payload("scratch/uu-src");

	/* Capture uuencode's stdout into scratch/uu-mid: run() already
	 * redirects stdout to OUTFILE, so just copy OUTFILE into
	 * scratch/uu-mid afterward -- plain fopen()/fread()/fwrite() rather
	 * than shelling out to an external `cp`, which the environment
	 * running this test's .exe is not guaranteed to have on PATH. */
	CHECK(run(uuencode_path, enc_argv) == 0);
	CHECK(copy_file(OUTFILE, "scratch/uu-mid") == 0);
	fd = open("scratch/uu-mid", O_RDONLY);
	CHECK(fd >= 0);
	if (fd >= 0) close(fd);

	CHECK(run(uudecode_path, dec_argv) == 0);
	CHECK(files_equal("scratch/uu-src", "scratch/uu-out"));

	unlink("scratch/uu-src");
	unlink("scratch/uu-mid");
	unlink("scratch/uu-out");
}

static void test_uudecode_truncated_stream_is_an_error(void)
{
	char *dec_argv[] = { (char *)"uudecode", (char *)"-o", (char *)"scratch/uu-bad-out", (char *)"scratch/uu-bad", 0 };
	const char *truncated = "begin 644 whatever\n";
	make_file("scratch/uu-bad", truncated, strlen(truncated));
	CHECK(run(uudecode_path, dec_argv) != 0);
	CHECK(err_contains("uudecode:"));
	unlink("scratch/uu-bad");
	unlink("scratch/uu-bad-out");
}

static void test_uudecode_no_begin_line_is_an_error(void)
{
	char *dec_argv[] = { (char *)"uudecode", (char *)"scratch/uu-nobegin", 0 };
	const char *garbage = "not a uuencoded stream at all\n";
	make_file("scratch/uu-nobegin", garbage, strlen(garbage));
	CHECK(run(uudecode_path, dec_argv) != 0);
	CHECK(err_contains("begin"));
	unlink("scratch/uu-nobegin");
}

static void test_uuencode_header_fields(void)
{
	char *argv[] = { (char *)"uuencode", (char *)"scratch/uu-src2", (char *)"myname.bin", 0 };
	make_file("scratch/uu-src2", "hi", 2);
	CHECK(run(uuencode_path, argv) == 0);
	CHECK(out_contains("begin "));
	CHECK(out_contains("myname.bin"));
	CHECK(out_contains("end\n"));
	unlink("scratch/uu-src2");
}

/* ==== builtin-vs-standalone agreement ==================================== */

static void test_builtins_match_standalone(void)
{
	make_file("scratch/cksum-bi", "abc", 3);
	CHECK(run_sh_c("cksum scratch/cksum-bi") == 0);
	CHECK(out_contains("1219131554 3 "));
	unlink("scratch/cksum-bi");

	CHECK(run_sh_c("df scratch") == 0);
	CHECK(out_contains("Filesystem"));

	mkdir("scratch/dubi", 0755);
	make_file("scratch/dubi/f", "x", 1);
	CHECK(run_sh_c("du -s scratch/dubi") == 0);
	unlink("scratch/dubi/f");
	rmdir("scratch/dubi");

	make_file("scratch/dd-bi-src", "hello", 5);
	CHECK(run_sh_c("dd if=scratch/dd-bi-src of=scratch/dd-bi-dst bs=5") == 0);
	CHECK(files_equal("scratch/dd-bi-src", "scratch/dd-bi-dst"));
	unlink("scratch/dd-bi-src"); unlink("scratch/dd-bi-dst");

	make_file("scratch/uu-bi-src", "roundtrip me", 12);
	CHECK(run_sh_c("uuencode scratch/uu-bi-src bi.bin > scratch/uu-bi-mid") == 0);
	CHECK(run_sh_c("uudecode -o scratch/uu-bi-out scratch/uu-bi-mid") == 0);
	CHECK(files_equal("scratch/uu-bi-src", "scratch/uu-bi-out"));
	unlink("scratch/uu-bi-src"); unlink("scratch/uu-bi-mid"); unlink("scratch/uu-bi-out");
}

/* ==== cleanup ============================================================= */

static void rmtree_scratch(void)
{
	unlink("scratch/empty");
	unlink("scratch/cksum-in");
	unlink("scratch/cksum-bi");
	unlink("scratch/dd-src"); unlink("scratch/dd-dst");
	unlink("scratch/dd-src2"); unlink("scratch/dd-dst2");
	unlink("scratch/dd-src3"); unlink("scratch/dd-dst3");
	unlink("scratch/dd-src6"); unlink("scratch/dd-dst6");
	unlink("scratch/dd-src4"); unlink("scratch/dd-dst4");
	unlink("scratch/dd-src5"); unlink("scratch/dd-dst5");
	unlink("scratch/dd-bi-src"); unlink("scratch/dd-bi-dst");
	unlink("scratch/dutree/sub/f2");
	rmdir("scratch/dutree/sub");
	unlink("scratch/dutree/f1");
	rmdir("scratch/dutree");
	unlink("scratch/dubi/f");
	rmdir("scratch/dubi");
	unlink("scratch/uu-src"); unlink("scratch/uu-mid"); unlink("scratch/uu-out");
	unlink("scratch/uu-src2");
	unlink("scratch/uu-bad"); unlink("scratch/uu-bad-out");
	unlink("scratch/uu-nobegin");
	unlink("scratch/uu-bi-src"); unlink("scratch/uu-bi-mid"); unlink("scratch/uu-bi-out");
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
		printf("SKIP util-datacopy: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(dd_path, sizeof dd_path, "bin/dd.exe");
	path_for(df_path, sizeof df_path, "bin/df.exe");
	path_for(du_path, sizeof du_path, "bin/du.exe");
	path_for(cksum_path, sizeof cksum_path, "bin/cksum.exe");
	path_for(uuencode_path, sizeof uuencode_path, "bin/uuencode.exe");
	path_for(uudecode_path, sizeof uudecode_path, "bin/uudecode.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(dd_path, R_OK) != 0 || access(df_path, R_OK) != 0 ||
	    access(du_path, R_OK) != 0 || access(cksum_path, R_OK) != 0 ||
	    access(uuencode_path, R_OK) != 0 || access(uudecode_path, R_OK) != 0 ||
	    access(sh_path, R_OK) != 0) {
		printf("SKIP util-datacopy: one or more of the six utility binaries or sh is missing\n");
		return 77;
	}

	rmtree_scratch();
	if (mkdir("scratch", 0755) != 0) {
		printf("SKIP util-datacopy: cannot create scratch/ (%s)\n", strerror(errno));
		return 77;
	}
	make_file("scratch/.keep", "", 0);
	make_file("scratch/empty", "", 0);

	test_cksum_empty_stdin();
	test_cksum_known_values();
	test_cksum_missing_file_is_an_error();

	test_dd_basic_copy();
	test_dd_count_limits_input();
	test_dd_skip_and_seek();
	test_dd_seek();
	test_dd_conv_notrunc_preserves_tail();
	test_dd_unrecognized_conv_is_refused();
	test_dd_bad_operand_is_refused();
	test_dd_bs_suffix_overflow_is_refused();
	test_dd_skip_overflow_is_refused();

	test_df_reports_on_an_operand();
	test_df_dash_k();
	test_df_nonexistent_operand_is_an_error();

	test_du_reports_files_and_directories();
	test_du_nonexistent_operand_is_an_error();

	test_uuencode_uudecode_roundtrip_standalone();
	test_uudecode_truncated_stream_is_an_error();
	test_uudecode_no_begin_line_is_an_error();
	test_uuencode_header_fields();

	test_builtins_match_standalone();

	cleanup_artifacts();

	if (fails) { printf("util-datacopy: failures: %d\n", fails); return 1; }
	printf("util-datacopy: all ok (dd, df, du, cksum, uuencode, uudecode -- standalone and builtin)\n");
	return 0;
}
