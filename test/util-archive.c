/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for ntlibc's Tier 4 archive/content-format POSIX
 * standard utilities: `pax`, `file`, `ar` (XCU pax(1p), file(1p),
 * ar(1p)).  Same technique as test/util-sortset.c: the standalone
 * obj/bin/<name>.exe is spawned as a real process (via
 * __spawn()+waitpid()), and the shell built-in is exercised too (via
 * obj/sh/sh.exe -c), confirming both callers of __util_<name>_main()
 * (src/internal/util.h) agree.
 *
 * `ar`'s test is a real round-trip: create a two-member archive,
 * list it, print a member, extract both members and compare their
 * bytes against the originals, then delete one member and confirm it
 * is gone -- not just option-parsing smoke tests.
 *
 * `pax`'s tests round-trip both implemented formats (ustar, the
 * default, and cpio via -x cpio): write an archive from two real
 * files, list it, delete the originals, read/extract the archive and
 * compare the recreated bytes, then separately exercise copy mode
 * (-r -w) into a destination directory and compare bytes there too.
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
	obj_root[i - 1] = 0; /* strip "/util-archive.exe" */

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

#define OUTFILE "util-archive-out.txt"
#define ERRFILE "util-archive-err.txt"

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

static int out_contains(const char *needle)
{
	char buf[8192];
	slurp_into(OUTFILE, buf, sizeof buf);
	return strstr(buf, needle) != 0;
}

static int err_contains(const char *needle)
{
	char buf[8192];
	slurp_into(ERRFILE, buf, sizeof buf);
	return strstr(buf, needle) != 0;
}

static int files_equal(const char *a, const char *b)
{
	char ba[8192], bb[8192];
	if (slurp_into(a, ba, sizeof ba) != 0) return 0;
	if (slurp_into(b, bb, sizeof bb) != 0) return 0;
	return strcmp(ba, bb) == 0;
}

static void make_file(const char *path, const char *contents)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return;
	if (contents && *contents) write(fd, contents, strlen(contents));
	close(fd);
}

static char pax_path[1024], file_path_[1024], ar_path[1024], sh_path[1024];

static int run_sh_c(const char *cmd)
{
	char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, 0 };
	return run(sh_path, argv);
}

/* ==== file(1p) ============================================================ */

/* Every case below runs `file` on one operand, then checks both its exit
 * status and one expected substring of its output -- folded here since
 * every test in this section follows that exact shape. */
static void check_file(char *const *argv, int want_status, const char *needle)
{
	CHECK(run(file_path_, argv) == want_status);
	CHECK(out_contains(needle));
}

static void test_file_empty(void)
{
	char *argv[] = { (char *)"file", (char *)"scratch/fa_empty", 0 };
	make_file("scratch/fa_empty", "");
	check_file(argv, 0, "scratch/fa_empty: empty");
}

static void test_file_text(void)
{
	char *argv[] = { (char *)"file", (char *)"scratch/fa_text", 0 };
	make_file("scratch/fa_text", "hello world\nsecond line\n");
	check_file(argv, 0, "scratch/fa_text: ASCII text");
}

static void test_file_shebang(void)
{
	char *argv[] = { (char *)"file", (char *)"scratch/fa_script", 0 };
	make_file("scratch/fa_script", "#!/bin/sh\necho hi\n");
	check_file(argv, 0, "scratch/fa_script: commands text");
}

static void test_file_directory(void)
{
	char *argv[] = { (char *)"file", (char *)"scratch", 0 };
	check_file(argv, 0, "scratch: directory");
}

static void test_file_missing(void)
{
	char *argv[] = { (char *)"file", (char *)"scratch/fa_missing_xyz", 0 };
	check_file(argv, 1, "cannot open");
}

static void test_file_symlink(void)
{
	char *argv_h[] = { (char *)"file", (char *)"-h", (char *)"scratch/fa_link", 0 };
	char *argv_plain[] = { (char *)"file", (char *)"scratch/fa_link", 0 };

	unlink("scratch/fa_link");
	if (symlink("fa_text", "scratch/fa_link") != 0) return; /* no symlink support here; skip quietly */

	check_file(argv_h, 0, "scratch/fa_link: symbolic link to fa_text");
	check_file(argv_plain, 0, "scratch/fa_link: ASCII text");
}

/* ==== ar(1p) =============================================================== */

static void test_ar_roundtrip(void)
{
	char *create[] = { (char *)"ar", (char *)"rc", (char *)"scratch/artest.a",
	                    (char *)"scratch/arm1.txt", (char *)"scratch/arm2.txt", 0 };
	char *toc[] = { (char *)"ar", (char *)"t", (char *)"scratch/artest.a", 0 };
	char *print1[] = { (char *)"ar", (char *)"p", (char *)"scratch/artest.a", (char *)"arm1.txt", 0 };
	char *extract[] = { (char *)"ar", (char *)"x", (char *)"scratch/artest.a", 0 };
	char *del[] = { (char *)"ar", (char *)"d", (char *)"scratch/artest.a", (char *)"arm1.txt", 0 };
	char *toc2[] = { (char *)"ar", (char *)"t", (char *)"scratch/artest.a", 0 };

	unlink("scratch/artest.a");
	make_file("scratch/arm1.txt", "archive member one\n");
	make_file("scratch/arm2.txt", "archive member two, a bit longer\n");

	CHECK(run(ar_path, create) == 0);

	CHECK(run(ar_path, toc) == 0);
	CHECK(out_contains("arm1.txt"));
	CHECK(out_contains("arm2.txt"));

	CHECK(run(ar_path, print1) == 0);
	CHECK(out_contains("archive member one"));

	unlink("arm1.txt");
	unlink("arm2.txt");
	CHECK(run(ar_path, extract) == 0);
	CHECK(files_equal("arm1.txt", "scratch/arm1.txt"));
	CHECK(files_equal("arm2.txt", "scratch/arm2.txt"));
	unlink("arm1.txt");
	unlink("arm2.txt");

	CHECK(run(ar_path, del) == 0);
	CHECK(run(ar_path, toc2) == 0);
	CHECK(!out_contains("arm1.txt"));
	CHECK(out_contains("arm2.txt"));
}

static void test_ar_builtin(void)
{
	unlink("scratch/artest2.a");
	make_file("scratch/arm3.txt", "builtin archive member\n");
	CHECK(run_sh_c("ar rc scratch/artest2.a scratch/arm3.txt") == 0);
	CHECK(run_sh_c("ar t scratch/artest2.a") == 0);
	CHECK(out_contains("arm3.txt"));
}

/* ==== pax(1p) ============================================================== */

static void test_pax_ustar_roundtrip(void)
{
	char *w[] = { (char *)"pax", (char *)"-w", (char *)"-f", (char *)"scratch/pax1.tar",
	              (char *)"scratch/px1.txt", (char *)"scratch/px2.txt", 0 };
	char *list[] = { (char *)"pax", (char *)"-f", (char *)"scratch/pax1.tar", 0 };
	char *r[] = { (char *)"pax", (char *)"-r", (char *)"-f", (char *)"scratch/pax1.tar", 0 };
	struct stat st;

	unlink("scratch/pax1.tar");
	make_file("scratch/px1.txt", "pax ustar content one\n");
	make_file("scratch/px2.txt", "pax ustar content two, a little longer\n");

	CHECK(run(pax_path, w) == 0);
	CHECK(stat("scratch/pax1.tar", &st) == 0 && st.st_size > 0);

	CHECK(run(pax_path, list) == 0);
	CHECK(out_contains("scratch/px1.txt"));
	CHECK(out_contains("scratch/px2.txt"));

	/* Preserve the originals under different names before extraction
	 * recreates the same paths, so the recreated bytes can still be
	 * compared afterward. */
	rename("scratch/px1.txt", "scratch/px1.orig");
	rename("scratch/px2.txt", "scratch/px2.orig");

	CHECK(run(pax_path, r) == 0);
	CHECK(files_equal("scratch/px1.txt", "scratch/px1.orig"));
	CHECK(files_equal("scratch/px2.txt", "scratch/px2.orig"));
}

static void test_pax_cpio_roundtrip(void)
{
	char *w[] = { (char *)"pax", (char *)"-w", (char *)"-x", (char *)"cpio", (char *)"-f",
	              (char *)"scratch/pax2.cpio", (char *)"scratch/pc1.txt", (char *)"scratch/pc2.txt", 0 };
	char *list[] = { (char *)"pax", (char *)"-f", (char *)"scratch/pax2.cpio", 0 };
	char *r[] = { (char *)"pax", (char *)"-r", (char *)"-f", (char *)"scratch/pax2.cpio", 0 };

	unlink("scratch/pax2.cpio");
	make_file("scratch/pc1.txt", "pax cpio content one\n");
	make_file("scratch/pc2.txt", "pax cpio content two\n");

	CHECK(run(pax_path, w) == 0);

	CHECK(run(pax_path, list) == 0);
	CHECK(out_contains("scratch/pc1.txt"));
	CHECK(out_contains("scratch/pc2.txt"));

	rename("scratch/pc1.txt", "scratch/pc1.orig");
	rename("scratch/pc2.txt", "scratch/pc2.orig");

	CHECK(run(pax_path, r) == 0);
	CHECK(files_equal("scratch/pc1.txt", "scratch/pc1.orig"));
	CHECK(files_equal("scratch/pc2.txt", "scratch/pc2.orig"));
}

static void test_pax_copy_mode(void)
{
	char *cp[] = { (char *)"pax", (char *)"-r", (char *)"-w",
	               (char *)"scratch/py1.txt", (char *)"scratch/py2.txt", (char *)"scratch/paxcopydir", 0 };

	mkdir("scratch/paxcopydir", 0755);
	make_file("scratch/py1.txt", "pax copy mode content one\n");
	make_file("scratch/py2.txt", "pax copy mode content two\n");

	CHECK(run(pax_path, cp) == 0);
	CHECK(files_equal("scratch/paxcopydir/scratch/py1.txt", "scratch/py1.txt"));
	CHECK(files_equal("scratch/paxcopydir/scratch/py2.txt", "scratch/py2.txt"));
}

static void test_pax_builtin(void)
{
	unlink("scratch/pax3.tar");
	make_file("scratch/pb1.txt", "pax builtin content\n");
	CHECK(run_sh_c("pax -w -f scratch/pax3.tar scratch/pb1.txt") == 0);
	CHECK(run_sh_c("pax -f scratch/pax3.tar") == 0);
	CHECK(out_contains("scratch/pb1.txt"));
}

/* ==== pax(1p) extraction-safety regression tests ==========================
 *
 * src/util/pax.c's own name_is_safe()/ensure_parent_dirs() only defend
 * against a *hostile* archive -- one this project's own -w side never
 * produces, since ustar_split_name()/write_cpio_header() only ever emit
 * '/'-separated, non-".."  names. Exercising that defense therefore
 * means hand-building raw ustar member blocks below (pax -w has no way
 * to ask for a traversal-unsafe name, a foreign-linkname hardlink, or a
 * symlink planted ahead of a member that walks through it), the same
 * way test/util-patch.c hand-derives its four diff format fixtures. */

static void ustar_put_oct_raw(unsigned char *field, int width, unsigned long value)
{
	char tmp[24];
	int i;
	snprintf(tmp, sizeof tmp, "%0*lo", width - 1, value);
	for (i = 0; i < width - 1; i++) field[i] = tmp[i];
	field[width - 1] = 0;
}

/* Appends one raw 512-byte ustar header (+ NUL-padded data, if any) to
 * `fd` for a member with the given name/typeflag/linkname -- deliberately
 * bypassing write_ustar_header()'s own name_is_safe()-adjacent
 * refusals, so the member can carry exactly the traversal-unsafe shape
 * this file's tests below need. */
static void write_raw_ustar_member(int fd, const char *name, char typeflag,
                                     const char *linkname, const char *data, size_t datalen)
{
	unsigned char block[512];
	unsigned long sum;
	size_t i, namelen = strlen(name);

	memset(block, 0, sizeof block);
	memcpy(block, name, namelen < 100 ? namelen : 100);
	ustar_put_oct_raw(block + 100, 8, 0644);
	ustar_put_oct_raw(block + 108, 8, 0);
	ustar_put_oct_raw(block + 116, 8, 0);
	ustar_put_oct_raw(block + 124, 12, (unsigned long)datalen);
	ustar_put_oct_raw(block + 136, 12, 0);
	memset(block + 148, ' ', 8);
	block[156] = (unsigned char)typeflag;
	if (linkname) strncpy((char *)block + 157, linkname, 100);
	memcpy(block + 257, "ustar", 6);
	memcpy(block + 263, "00", 2);

	sum = 0;
	for (i = 0; i < sizeof block; i++) sum += block[i];
	{
		char tmp[8];
		snprintf(tmp, sizeof tmp, "%06lo", sum & 0777777UL);
		memcpy(block + 148, tmp, 6);
		block[154] = 0;
		block[155] = ' ';
	}

	write(fd, block, sizeof block);
	if (datalen) {
		size_t pad = (512 - (datalen % 512)) % 512;
		write(fd, data, datalen);
		if (pad) {
			char zero[512];
			memset(zero, 0, sizeof zero);
			write(fd, zero, pad);
		}
	}
}

static void write_ustar_trailer_raw(int fd)
{
	unsigned char zero[1024];
	memset(zero, 0, sizeof zero);
	write(fd, zero, sizeof zero);
}

/* A member name using '\\' (rather than '/') to spell a ".." traversal
 * is exactly what a hostile archive would use to escape the extraction
 * directory on the NT/tcc target, where backslash is a real path
 * separator (see src/internal/nt/path.c); name_is_safe() must catch it
 * on every build, not just that one. Checks the member is refused
 * (exit 1, diagnostic) and nothing is ever created under that literal
 * name. */
static void test_pax_rejects_backslash_traversal(void)
{
	int fd;
	char *r[] = { (char *)"pax", (char *)"-r", (char *)"-f", (char *)"scratch/paxbstrav.tar", 0 };
	struct stat st;

	unlink("scratch/paxbstrav.tar");
	unlink("scratch\\..\\..\\paxbstrav_out.txt");
	fd = open("scratch/paxbstrav.tar", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;
	write_raw_ustar_member(fd, "scratch\\..\\..\\paxbstrav_out.txt", '0', NULL, "x", 1);
	write_ustar_trailer_raw(fd);
	close(fd);

	CHECK(run(pax_path, r) == 1);
	CHECK(err_contains("refusing to extract"));
	CHECK(stat("scratch\\..\\..\\paxbstrav_out.txt", &st) != 0);
}

/* A ustar hardlink member's linkname (typeflag '1') is fed straight to
 * link() as the file to link *from* -- an unchecked "../etc/passwd"-
 * style linkname would alias an arbitrary existing file into the
 * extraction tree the instant this one member is processed, no second
 * member required. Checks the member is refused before link() is ever
 * called (the destination path is never created). */
static void test_pax_hardlink_linkname_traversal_refused(void)
{
	int fd;
	char *r[] = { (char *)"pax", (char *)"-r", (char *)"-f", (char *)"scratch/paxhl.tar", 0 };
	struct stat st;

	unlink("scratch/paxhl.tar");
	unlink("scratch/hltrav.txt");
	fd = open("scratch/paxhl.tar", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;
	write_raw_ustar_member(fd, "scratch/hltrav.txt", '1', "../../etc/passwd", NULL, 0);
	write_ustar_trailer_raw(fd);
	close(fd);

	CHECK(run(pax_path, r) == 1);
	CHECK(err_contains("refusing to extract"));
	CHECK(stat("scratch/hltrav.txt", &st) != 0);
}

/* Both member names here individually pass name_is_safe() (neither is
 * absolute nor contains ".."), but the first is a symlink and the
 * second's name walks through it: "trapdir" -> "scratch", then
 * "trapdir/evil.txt". Without ensure_parent_dirs() refusing to walk
 * through an already-extracted non-directory component, the second
 * member lands as "scratch/evil.txt" via the symlink -- exactly the
 * "extract a symlink, then extract through it" attack. Checks that
 * path never gets created. */
static void test_pax_symlink_component_escape_refused(void)
{
	int fd;
	char *r[] = { (char *)"pax", (char *)"-r", (char *)"-f", (char *)"scratch/paxsym.tar", 0 };
	struct stat st;

	unlink("scratch/paxsym.tar");
	unlink("trapdir");
	unlink("scratch/evil.txt");
	fd = open("scratch/paxsym.tar", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;
	write_raw_ustar_member(fd, "trapdir", '2', "scratch", NULL, 0);
	write_raw_ustar_member(fd, "trapdir/evil.txt", '0', NULL, "pwned", 5);
	write_ustar_trailer_raw(fd);
	close(fd);

	CHECK(run(pax_path, r) == 1);
	CHECK(stat("scratch/evil.txt", &st) != 0);
	unlink("trapdir");
}

/* ==== scratch directory setup/teardown ==================================== */

static void rmtree_scratch(void)
{
	unlink("scratch/fa_empty"); unlink("scratch/fa_text"); unlink("scratch/fa_script");
	unlink("scratch/fa_link"); unlink("scratch/fa_missing_xyz");
	unlink("scratch/artest.a"); unlink("scratch/artest2.a");
	unlink("scratch/arm1.txt"); unlink("scratch/arm2.txt"); unlink("scratch/arm3.txt");
	unlink("arm1.txt"); unlink("arm2.txt");
	unlink("scratch/pax1.tar"); unlink("scratch/pax2.cpio"); unlink("scratch/pax3.tar");
	unlink("scratch/px1.txt"); unlink("scratch/px2.txt");
	unlink("scratch/px1.orig"); unlink("scratch/px2.orig");
	unlink("scratch/pc1.txt"); unlink("scratch/pc2.txt");
	unlink("scratch/pc1.orig"); unlink("scratch/pc2.orig");
	unlink("scratch/py1.txt"); unlink("scratch/py2.txt");
	unlink("scratch/pb1.txt");
	unlink("scratch/paxcopydir/scratch/py1.txt");
	unlink("scratch/paxcopydir/scratch/py2.txt");
	rmdir("scratch/paxcopydir/scratch");
	rmdir("scratch/paxcopydir");
	unlink("scratch/paxbstrav.tar"); unlink("scratch\\..\\..\\paxbstrav_out.txt");
	unlink("scratch/paxhl.tar"); unlink("scratch/hltrav.txt");
	unlink("scratch/paxsym.tar"); unlink("scratch/evil.txt"); unlink("trapdir");
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
		printf("SKIP util-archive: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(pax_path, sizeof pax_path, "bin/pax.exe");
	path_for(file_path_, sizeof file_path_, "bin/file.exe");
	path_for(ar_path, sizeof ar_path, "bin/ar.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(pax_path, R_OK) != 0 || access(file_path_, R_OK) != 0 ||
	    access(ar_path, R_OK) != 0 || access(sh_path, R_OK) != 0) {
		printf("SKIP util-archive: one or more of the three utility binaries or sh is missing\n");
		return 77;
	}

	rmtree_scratch();
	if (mkdir("scratch", 0755) != 0) {
		printf("SKIP util-archive: cannot create scratch/ (%s)\n", strerror(errno));
		return 77;
	}
	make_file("scratch/.keep", "");

	test_file_empty();
	test_file_text();
	test_file_shebang();
	test_file_directory();
	test_file_missing();
	test_file_symlink();

	test_ar_roundtrip();
	test_ar_builtin();

	test_pax_ustar_roundtrip();
	test_pax_cpio_roundtrip();
	test_pax_copy_mode();
	test_pax_builtin();
	test_pax_rejects_backslash_traversal();
	test_pax_hardlink_linkname_traversal_refused();
	test_pax_symlink_component_escape_refused();

	cleanup_artifacts();

	if (fails) { printf("util-archive: failures: %d\n", fails); return 1; }
	printf("util-archive: all ok (pax, file, ar -- standalone and builtin)\n");
	return 0;
}
