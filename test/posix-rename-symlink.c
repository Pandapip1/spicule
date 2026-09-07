/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * rename()/renameat() when a SYMBOLIC LINK is the final component of
 * old or of new.  POSIX.1-2017/2024 rename.html is unambiguous that the
 * link itself is the operand and that a link is a NON-DIRECTORY file
 * whatever it points at; NT classifies by FILE_ATTRIBUTE_DIRECTORY,
 * which a *directory* symlink carries on the link itself.  Those two
 * rules disagree, and this file is the measurement that settles whether
 * the disagreement is observable.
 *
 * Page: https://pubs.opengroup.org/onlinepubs/9699919799/functions/rename.html
 *
 * WHY THIS FILE EXISTS RATHER THAN A FENCE.  c96657c ("rename: reject a
 * directory renamed over a regular file") added a type precheck to
 * src/stdio/misc.c's renameat() and left a note saying the check was
 * imprecise because "NtQueryAttributesFile FOLLOWS reparse points".
 * That premise is false, on three independent lines of evidence:
 *
 *   - Measured: NtQueryAttributesFile on a symlink-to-directory, a
 *     symlink-to-file and a dangling symlink all return SUCCESS with
 *     FILE_ATTRIBUTE_REPARSE_POINT set and the DIRECTORY bit reflecting
 *     the LINK, not the target.
 *   - Documented: GetFileAttributesW Remarks, "Symbolic link behavior --
 *     If the path points to a symbolic link, the function returns
 *     attributes for the symbolic link."
 *   - Corroborated: ReactOS ntoskrnl/io/iomgr/file.c:2382,
 *     IopQueryAttributesFile() -- the shared body of both
 *     NtQueryAttributesFile and NtQueryFullAttributesFile -- sets
 *     OpenPacket.CreateOptions = FILE_OPEN_REPARSE_POINT unconditionally.
 *
 * So non-traversal was never the problem and FILE_OPEN_REPARSE_POINT is
 * not the fix.  The real gap is the REPARSE TAG: renameat() decides
 * "is this a directory" from FILE_ATTRIBUTE_DIRECTORY alone, and
 * src/unistd/link.c's symlinkat() deliberately creates a link to a
 * directory as a directory (FILE_CREATE with FILE_DIRECTORY_FILE), so on
 * NT that bit is SET on the link.  src/stat/stat.c's mode_from_attrs()
 * already knows the correct predicate -- attributes AND tag -- and
 * NtQueryAttributesFile cannot return a tag at all.
 *
 * If the NT premise holds, exactly two of the groups below are predicted
 * to diverge, and it is worth being precise about which, because the
 * others look superficially similar and are NOT predicted to move:
 *
 *   - dir_over_symlink_to_dir: new is a DIRECTORY symlink, so new_isdir
 *     is true and the guard c96657c added is skipped.  MEASURED (see
 *     the forced-fixture group at the end of this file): the rename is
 *     still refused -- NT/Wine will not replace a directory-flavoured
 *     reparse point -- but STATUS_ACCESS_DENIED then reaches the
 *     EISDIR/ENOTEMPTY disambiguation, which sees new_isdir true and
 *     old_isdir true and reports [ENOTEMPTY].  So the tree is NOT
 *     damaged; the defect is a wrong errno, naming a condition ("names
 *     a directory that is not empty") that is not the one present, for
 *     a clause rename.html makes [ENOTDIR].  Milder than a destructive
 *     failure, and still a shall-fail clause answered wrongly.
 *   - symlink_to_dir_over_file: old is a DIRECTORY symlink, so old_isdir
 *     is true, the guard fires, and a call POSIX requires to SUCCEED is
 *     refused [ENOTDIR].
 *
 * The link-to-a-FILE and DANGLING cases are not predicted to move in
 * either direction: symlinkat() creates those with FILE_NON_DIRECTORY_
 * FILE (it guesses "file" whenever the target is not a directory *now*,
 * which includes a target that does not exist), so NT leaves the
 * DIRECTORY bit clear on them and the existing classification already
 * gets the right answer.  They are here as controls -- if they moved
 * too, the explanation would not be the reparse tag.
 *
 * One further group is CONTINGENT rather than predicted:
 * file_over_symlink_to_dir depends on what NT's FileRenameInformationEx
 * does when the destination is a directory reparse point.  If it
 * answers STATUS_ACCESS_DENIED, renameat()'s disambiguation sees
 * new_isdir true and reports [EISDIR] for a call that shall succeed.
 * That is a question about NT's rename, not about its attributes, and
 * this file is also how we find that out.
 *
 * The premise itself is no longer an inference.  MEASURED under Wine
 * 11.16: CreateSymbolicLinkW with SYMBOLIC_LINK_FLAG_DIRECTORY produces
 * a link whose own attributes are 0x00000410 --
 * FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT -- and
 * renameat() then answers [ENOTEMPTY] where rename.html requires
 * [ENOTDIR].  The last group in this file builds exactly that fixture,
 * so the defect is observable in any environment that can make a
 * symbolic link at all, rather than only on the real-Windows legs.
 *
 * ORACLE.  The real-Windows legs remain the authority for the groups
 * built through this library's own symlink(), for the reason
 * test/posix-unistd-links.c gives: a Wine pass is evidence about Wine's
 * reparse-point emulation, not about NTFS.  There is a specific reason
 * those groups are weaker than they look, and it is worth stating so it
 * is not mistaken for a clean pass -- MEASURED under Wine 11.16,
 * src/unistd/link.c's symlinkat() produces a link with attributes
 * 0x00000420 (ARCHIVE | REPARSE_POINT) even when its target IS a
 * directory and it passes FILE_DIRECTORY_FILE, i.e. a FILE-flavoured
 * link; on the Unix side Wine has created a regular file.  Win32's
 * CreateSymbolicLinkW on the same Wine creates a real directory and
 * reports 0x00000410.  So under Wine those groups exercise a
 * file-symlink whatever they asked for, which is precisely the shape
 * the current classification already gets right.  Whether NT honours
 * FILE_DIRECTORY_FILE here (and so whether symlinkat() is itself
 * defective under Wine only, or everywhere) is an open question those
 * legs also answer.  The forced-fixture group below sidesteps it
 * entirely.
 *
 * TWO ENVIRONMENT NOTES, both measured, so neither has to be
 * rediscovered from a confusing run:
 *
 *   - Stock apt Wine 9.0 cannot create a symbolic link at all.  Not a
 *     privilege problem: NtCreateFile for the placeholder returns
 *     SUCCESS and NtFsControlFile(FSCTL_SET_REPARSE_POINT) returns
 *     STATUS_NOT_SUPPORTED (0xc00000bb) -- that FSCTL first shipped in
 *     wine-10.19 -- so src/unistd/link.c's EPERM arm never runs and
 *     symlink() surfaces ENOENT.  Every group here is therefore behind
 *     one probe, and this file exits 77 (unverified) rather than
 *     reporting a vacuous pass.
 *   - Wine 11.16 passes A-F and FAILS exactly three assertions, all of
 *     them consequences of one WINE defect rather than of this library:
 *     renaming a reparse point over an existing regular file returns 0,
 *     destroys the link, leaves the destination's contents untouched,
 *     and leaves two directory entries that both render as the
 *     destination name.  So G's "new is now the link" and readlink()
 *     assertions fail, and main()'s closing rmdir() fails too, because
 *     the duplicate entry cannot be removed by name and the scratch
 *     directory is therefore not empty.  spicule issues exactly one
 *     NtSetInformationFile there and glibc gets the case right, so if
 *     those three fail under a symlink-capable Wine the bug to chase is
 *     Wine's rename of a reparse point, not a regression here.  Note
 *     that the PREDICTED NT divergence in G looks nothing like this: it
 *     is rename() itself returning -1/[ENOTDIR] -- the very first
 *     assertion of that group, not its post-state -- which leaves
 *     both names in place and tears down cleanly.
 *
 * Fence vocabulary is test/posix-termios.c's: BUG / UNIMPL / N/A.  There
 * are deliberately no fences in this file -- the whole point is that the
 * answer is measurable rather than assumable.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
/* Same relative-include idiom test/spawn-stdhandle-attr.c uses: the test
 * pattern rule does not put src/internal on the include path, and this
 * file needs NTSTATUS/UNICODE_STRING/ANSI_STRING and the two Ldr* calls
 * to reach kernel32 without spicule declaring any kernel32 import. */
#include "../src/internal/libc.h"

static int fails;
static int skips;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* Set by main() from a single trial symlink(): non-zero when this run
 * can create symbolic links at all. */
static int have_symlinks;

/* Set when the host is observed renaming a reparse point away without
 * replacing the destination (see test_rename_symlink_to_dir_over_file).
 * It leaves a directory entry that cannot be removed by name, so the
 * closing rmdir() below is reported rather than asserted when it is
 * set -- otherwise a host bug fails a teardown that has nothing to say
 * about this library. */
static int host_reparse_rename_defect;

/* lstat-based type, so a symbolic link reports as one rather than as
 * whatever it resolves to -- every assertion in this file is about the
 * link, so stat() would defeat the purpose. */
enum { T_MISSING, T_LNK, T_DIR, T_REG, T_OTHER };

static int type_of(const char *p)
{
	struct stat st;
	if (lstat(p, &st) != 0) return T_MISSING;
	if (S_ISLNK(st.st_mode)) return T_LNK;
	if (S_ISDIR(st.st_mode)) return T_DIR;
	if (S_ISREG(st.st_mode)) return T_REG;
	return T_OTHER;
}

static int mkfile(const char *p, const char *data)
{
	int fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	size_t n = strlen(data);
	if (fd < 0) return -1;
	if (write(fd, data, n) != (ssize_t)n) { close(fd); return -1; }
	return close(fd);
}

/* Each case builds its fixture in a fresh subdirectory and tears it
 * down, so one case's leftovers can never decide the next one's result
 * -- these cases differ only in the TYPE of an existing name, which is
 * exactly what a stale fixture would corrupt silently. */
static void wipe(const char *d)
{
	char p[64];
	static const char *names[] = { "lnk", "f", "sub", "tgtd", "tgtf", "moved", 0 };
	int i;
	for (i = 0; names[i]; i++) {
		snprintf(p, sizeof p, "%s/%s", d, names[i]);
		if (unlink(p) != 0) rmdir(p);
	}
	rmdir(d);
}

/* ============================================================
 * new's final component is a symbolic link
 * ============================================================ */

/* rename.html ERRORS, shall fail: "[ENOTDIR] ... the old argument names
 * a directory and the new argument names a non-directory file".  With
 * DESCRIPTION's "If either the old or new argument names a symbolic
 * link, rename() shall operate on the symbolic link itself, and shall
 * not resolve the last component of the argument", a symbolic link at
 * new is a non-directory file however it resolves -- so all three
 * shapes below (link to a directory, link to a file, dangling link) are
 * the same shall-fail clause, and the target's type is irrelevant.
 *
 * A is the case that decides the open question.  If NT reports
 * FILE_ATTRIBUTE_DIRECTORY on a directory symlink, renameat()'s
 * new_isdir is true, the guard c96657c added is skipped, and the rename
 * proceeds where POSIX requires ENOTDIR. */
static void test_rename_dir_over_symlink_to_dir(void)
{
	CHECK(mkdir("ra", 0755) == 0);
	CHECK(mkdir("ra/sub", 0755) == 0);
	CHECK(mkdir("ra/tgtd", 0755) == 0);
	CHECK(symlink("tgtd", "ra/lnk") == 0);
	CHECK(type_of("ra/lnk") == T_LNK);

	errno = 0;
	CHECK(rename("ra/sub", "ra/lnk") == -1);
	CHECK(errno == ENOTDIR);

	/* RETURN VALUE: on failure "neither the file named by old nor the
	 * file named by new shall be changed or created".  Asserted
	 * separately from the errno above: a wrong errno is a reporting
	 * defect, but a changed tree is destruction, and the two must not
	 * be able to hide behind one another. */
	CHECK(type_of("ra/sub") == T_DIR);
	CHECK(type_of("ra/lnk") == T_LNK);
	CHECK(type_of("ra/tgtd") == T_DIR);
	wipe("ra");
}

static void test_rename_dir_over_symlink_to_file(void)
{
	CHECK(mkdir("rb", 0755) == 0);
	CHECK(mkdir("rb/sub", 0755) == 0);
	CHECK(mkfile("rb/tgtf", "t") == 0);
	CHECK(symlink("tgtf", "rb/lnk") == 0);
	CHECK(type_of("rb/lnk") == T_LNK);

	errno = 0;
	CHECK(rename("rb/sub", "rb/lnk") == -1);
	CHECK(errno == ENOTDIR);
	CHECK(type_of("rb/sub") == T_DIR);
	CHECK(type_of("rb/lnk") == T_LNK);
	CHECK(type_of("rb/tgtf") == T_REG);
	wipe("rb");
}

/* The dangling case is the one that cannot be explained away as "the
 * implementation resolved the link and answered about the target":
 * there is no target.  A link that resolves to nothing is still an
 * existing non-directory file at new, so the clause still applies. */
static void test_rename_dir_over_dangling_symlink(void)
{
	CHECK(mkdir("rc", 0755) == 0);
	CHECK(mkdir("rc/sub", 0755) == 0);
	CHECK(symlink("no-such-target", "rc/lnk") == 0);
	CHECK(type_of("rc/lnk") == T_LNK);

	errno = 0;
	CHECK(rename("rc/sub", "rc/lnk") == -1);
	CHECK(errno == ENOTDIR);
	CHECK(type_of("rc/sub") == T_DIR);
	CHECK(type_of("rc/lnk") == T_LNK);
	wipe("rc");
}

/* The mirror direction, and the reason [EISDIR] must NOT be reported
 * here: rename.html DESCRIPTION, "If the new argument points to a
 * pathname of a symbolic link, the symbolic link shall be removed."  A
 * link to a directory is not a directory, so a plain file renamed onto
 * it shall SUCCEED, removing the link and leaving its target alone.
 * renameat()'s STATUS_ACCESS_DENIED disambiguation reports EISDIR when
 * new_isdir is true, so this is where a directory-symlink misclassified
 * as a directory turns into a spurious [EISDIR]. */
static void test_rename_file_over_symlink_to_dir(void)
{
	struct stat st;

	CHECK(mkdir("rd", 0755) == 0);
	CHECK(mkfile("rd/f", "payload") == 0);
	CHECK(mkdir("rd/tgtd", 0755) == 0);
	CHECK(symlink("tgtd", "rd/lnk") == 0);
	CHECK(type_of("rd/lnk") == T_LNK);

	errno = 0;
	CHECK(rename("rd/f", "rd/lnk") == 0);
	CHECK(type_of("rd/f") == T_MISSING);
	CHECK(type_of("rd/lnk") == T_REG);
	/* The link's TARGET must survive: the operand was the link. */
	CHECK(type_of("rd/tgtd") == T_DIR);
	CHECK(lstat("rd/lnk", &st) == 0);
	CHECK(st.st_size == 7);
	wipe("rd");
}

static void test_rename_file_over_dangling_symlink(void)
{
	CHECK(mkdir("re", 0755) == 0);
	CHECK(mkfile("re/f", "payload") == 0);
	CHECK(symlink("no-such-target", "re/lnk") == 0);
	CHECK(type_of("re/lnk") == T_LNK);

	errno = 0;
	CHECK(rename("re/f", "re/lnk") == 0);
	CHECK(type_of("re/f") == T_MISSING);
	CHECK(type_of("re/lnk") == T_REG);
	wipe("re");
}

/* ============================================================
 * old's final component is a symbolic link
 * ============================================================ */

/* rename.html DESCRIPTION: "If the old argument points to a pathname of
 * a symbolic link, the symbolic link shall be renamed."  The link moves;
 * its target does not, and the moved name is still a link. */
static void test_rename_symlink_to_new_name(void)
{
	char buf[64];
	ssize_t n;

	CHECK(mkdir("rf", 0755) == 0);
	CHECK(mkdir("rf/tgtd", 0755) == 0);
	CHECK(symlink("tgtd", "rf/lnk") == 0);

	errno = 0;
	CHECK(rename("rf/lnk", "rf/moved") == 0);
	CHECK(type_of("rf/lnk") == T_MISSING);
	CHECK(type_of("rf/moved") == T_LNK);
	CHECK(type_of("rf/tgtd") == T_DIR);
	n = readlink("rf/moved", buf, sizeof buf - 1);
	CHECK(n == 4);
	if (n > 0) { buf[n] = 0; CHECK(strcmp(buf, "tgtd") == 0); }
	wipe("rf");
}

/* The second half of the open question, in the old position.  old is a
 * symbolic link to a directory -- a NON-directory file per POSIX -- and
 * new is an existing regular file, so this is NOT the [ENOTDIR] clause
 * and shall succeed.  renameat() opens old with FILE_OPEN_REPARSE_POINT
 * and so sees the LINK's own attributes; if NT sets
 * FILE_ATTRIBUTE_DIRECTORY there, old_isdir is true, the c96657c guard
 * fires, and a call POSIX requires to succeed is refused [ENOTDIR].
 *
 * The post-state here is also where a WINE defect lands, and the two
 * outcomes have to be told apart rather than lumped together, because
 * one is this library's problem and the other is not:
 *
 *   - the NT divergence this group exists for shows up in the FIRST
 *     assertion -- rename() returns -1/[ENOTDIR] for a call POSIX
 *     requires to succeed.  That stays a hard CHECK.
 *   - Wine's reparse-point rename shows up only AFTER a reported
 *     success: rename() returns 0, the source link is gone, and the
 *     destination still holds its original contents because it was
 *     never replaced.  That is an environment gap, not a conformance
 *     result, so it is reported the way every other environment gap in
 *     this suite is -- a SKIP line and exit 77 -- instead of reddening
 *     a run over a bug in the host.
 *
 * The discrimination is on the exact measured signature, not on a
 * version check, so it stops applying by itself the day Wine fixes it. */
static void test_rename_symlink_to_dir_over_file(void)
{
	char buf[64];
	ssize_t n;

	CHECK(mkdir("rg", 0755) == 0);
	CHECK(mkdir("rg/tgtd", 0755) == 0);
	CHECK(mkfile("rg/f", "hello") == 0);
	CHECK(symlink("tgtd", "rg/lnk") == 0);

	errno = 0;
	/* The assertion that detects the predicted NT divergence. */
	CHECK(rename("rg/lnk", "rg/f") == 0);

	if (type_of("rg/lnk") == T_MISSING && type_of("rg/f") == T_REG &&
	    readlink("rg/f", buf, sizeof buf - 1) < 0) {
		printf("SKIP posix-rename-symlink symlink-over-file post-state "
		       "(host renamed the reparse point away without replacing "
		       "the destination: source gone, destination still a plain "
		       "file -- measured on Wine 11.16, not a defect in this "
		       "library; rename() itself reported success)\n");
		skips++;
		host_reparse_rename_defect = 1;
		wipe("rg");
		return;
	}

	CHECK(type_of("rg/lnk") == T_MISSING);
	CHECK(type_of("rg/f") == T_LNK);
	CHECK(type_of("rg/tgtd") == T_DIR);
	n = readlink("rg/f", buf, sizeof buf - 1);
	CHECK(n == 4);
	if (n > 0) { buf[n] = 0; CHECK(strcmp(buf, "tgtd") == 0); }
	wipe("rg");
}

/* ============================================================
 * The same clause, on a fixture forced to be a DIRECTORY symlink
 * ============================================================ */

/* Everything above builds its links with this library's own symlink(),
 * which is the right thing for a POSIX conformance test -- but see the
 * ORACLE note in the banner: under Wine that yields a FILE-flavoured
 * link whatever the target is, and a file-flavoured link is the shape
 * the current classification already handles correctly.  So those
 * groups cannot, in that environment, reach the defect.
 *
 * This group removes the variable.  It asks Win32 for a link that is
 * unambiguously directory-flavoured -- CreateSymbolicLinkW with
 * SYMBOLIC_LINK_FLAG_DIRECTORY, the documented way to create one, whose
 * result is FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT on
 * the link itself -- and then puts renameat() to exactly the clause the
 * banner names.  The fixture is Win32 rather than POSIX on purpose: the
 * object under test is renameat()'s classification of an object that
 * NT can hold, not this library's ability to create one.
 *
 * Resolved through LdrGetProcedureAddress rather than linked, because
 * spicule declares no kernel32 imports; SYMBOLIC_LINK_FLAG_ALLOW_
 * UNPRIVILEGED_CREATE is included so the call also works under
 * Developer Mode without an elevated token.  If it is unavailable or
 * refused, this group SKIPs and the process reports unverified rather
 * than passing vacuously -- the same contract as the probe in main(). */
static void test_rename_dir_over_forced_directory_symlink(void)
{
	static const WCHAR k32name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l',0 };
	static const WCHAR wlnk[] = { 'r','h','\\','l','n','k',0 };
	static const WCHAR wtgt[] = { 't','g','t','d',0 };
	typedef unsigned char (NTAPI *create_symlink_fn)(const WCHAR *, const WCHAR *, ULONG);
	typedef ULONG (NTAPI *get_attrs_fn)(const WCHAR *);
	create_symlink_fn create_symlink;
	get_attrs_fn get_attrs;
	UNICODE_STRING us;
	ANSI_STRING as;
	void *k32;

	us.Buffer = (WCHAR *)k32name;
	us.Length = (USHORT)(12 * sizeof(WCHAR));
	us.MaximumLength = (USHORT)(13 * sizeof(WCHAR));
	if (!NT_SUCCESS(LdrLoadDll(0, 0, &us, &k32))) {
		printf("SKIP posix-rename-symlink forced-directory-symlink group "
		       "(kernel32.dll would not load)\n");
		skips++;
		return;
	}
	as.Buffer = (char *)"CreateSymbolicLinkW";
	as.Length = 19;
	as.MaximumLength = 20;
	if (!NT_SUCCESS(LdrGetProcedureAddress(k32, &as, 0, (void **)&create_symlink))) {
		printf("SKIP posix-rename-symlink forced-directory-symlink group "
		       "(no CreateSymbolicLinkW export)\n");
		skips++;
		return;
	}

	CHECK(mkdir("rh", 0755) == 0);
	CHECK(mkdir("rh/sub", 0755) == 0);
	CHECK(mkdir("rh/tgtd", 0755) == 0);
	/* 0x1 SYMBOLIC_LINK_FLAG_DIRECTORY, 0x2 ALLOW_UNPRIVILEGED_CREATE */
	if (!create_symlink(wlnk, wtgt, 0x1 | 0x2)) {
		printf("SKIP posix-rename-symlink forced-directory-symlink group "
		       "(CreateSymbolicLinkW refused; needs "
		       "SeCreateSymbolicLinkPrivilege or Developer Mode)\n");
		skips++;
		wipe("rh");
		return;
	}

	/* Prove the fixture really is what this group is about before
	 * asserting anything with it.  A group that silently degraded to a
	 * file-flavoured link would pass for the wrong reason -- which is
	 * exactly the failure mode the groups above have under Wine. */
	CHECK(type_of("rh/lnk") == T_LNK);
	as.Buffer = (char *)"GetFileAttributesW";
	as.Length = 18;
	as.MaximumLength = 19;
	if (NT_SUCCESS(LdrGetProcedureAddress(k32, &as, 0, (void **)&get_attrs))) {
		ULONG a = get_attrs(wlnk);
		printf("note: forced fixture rh/lnk attributes = 0x%08lx\n", (unsigned long)a);
		CHECK(a != 0xffffffffu);
		CHECK((a & 0x400u) != 0);   /* FILE_ATTRIBUTE_REPARSE_POINT */
		CHECK((a & 0x010u) != 0);   /* FILE_ATTRIBUTE_DIRECTORY    */
	} else {
		CHECK(0);
	}

	/* rename.html ERRORS: old names a directory, new names a symbolic
	 * link -- a non-directory file -- so this is [ENOTDIR].  Observed
	 * without the reparse-tag fix: -1 / [ENOTEMPTY] (39), because
	 * new_isdir is true from the DIRECTORY bit, NT refuses the replace
	 * with STATUS_ACCESS_DENIED, and the disambiguation reads that as
	 * "new is a non-empty directory". */
	errno = 0;
	CHECK(rename("rh/sub", "rh/lnk") == -1);
	CHECK(errno == ENOTDIR);

	/* RETURN VALUE: nothing changed or created on failure. */
	CHECK(type_of("rh/sub") == T_DIR);
	CHECK(type_of("rh/lnk") == T_LNK);
	CHECK(type_of("rh/tgtd") == T_DIR);
	wipe("rh");
}

int main(void)
{
	char tmpl[] = "posixrenamesymlink-XXXXXX";
	char *dir = mkdtemp(tmpl);
	char origcwd[4096];

	CHECK(getcwd(origcwd, sizeof origcwd) == origcwd);
	CHECK(dir == tmpl);
	if (!dir) return 1;
	CHECK(chdir(dir) == 0);

	/* One trial creation decides whether ANY group in this file can
	 * run: every case needs a symbolic link to exist before rename()
	 * is called, so there is no half of this file that survives the
	 * probe failing.  Reported as an environment fact -- rename.html
	 * has no error for "this system will not make symbolic links". */
	have_symlinks = (symlink("probe-target", "sl-probe") == 0);
	if (have_symlinks) {
		CHECK(unlink("sl-probe") == 0);

		test_rename_dir_over_symlink_to_dir();
		test_rename_dir_over_symlink_to_file();
		test_rename_dir_over_dangling_symlink();
		test_rename_file_over_symlink_to_dir();
		test_rename_file_over_dangling_symlink();
		test_rename_symlink_to_new_name();
		test_rename_symlink_to_dir_over_file();
		test_rename_dir_over_forced_directory_symlink();
	} else {
		printf("SKIP posix-rename-symlink all groups (no symbolic link can "
		       "be created here: symlink() errno=%d; stock Wine below "
		       "10.19 answers FSCTL_SET_REPARSE_POINT with "
		       "STATUS_NOT_SUPPORTED, and NT needs "
		       "SeCreateSymbolicLinkPrivilege or Developer Mode)\n", errno);
		skips++;
	}

	CHECK(chdir(origcwd) == 0);
	if (host_reparse_rename_defect) {
		if (rmdir(dir) != 0)
			printf("note: scratch directory %s left behind (errno=%d); the "
			       "host defect above leaves an entry that cannot be "
			       "removed by name\n", dir, errno);
	} else {
		CHECK(rmdir(dir) == 0);
	}

	if (fails) return 1;
	if (skips) {
		printf("posix-rename-symlink: no failures, but %d assertion group(s) "
		       "did not run in this environment (see SKIP lines above); "
		       "exiting 77 (unverified) rather than reporting a pass\n", skips);
		return 77;
	}
	printf("posix-rename-symlink: all tests passed\n");
	return 0;
}
