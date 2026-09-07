/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * What makes a file executable, and what makes a PATH candidate the
 * right one.  These are two questions, and this file exists because
 * src/stat/stat.c used to answer both with one filename-suffix test.
 *
 * The suffix rule gave `.exe/.com/.bat/.cmd/.sh` mode 0755 and every
 * other regular file 0644, and src/process/find_program.c gated its
 * PATH search on access(p, X_OK) built on those bits.  Two independent
 * consequences, both reported from the nova-nix full-source-bootstrap
 * chain:
 *
 *   - A suffix-less file could never be executed by PATH search.  A PE
 *     image named `cat` is a perfectly good NT process image, and the
 *     search skipped it -- which broke every execvp of a coreutils name
 *     in their stdenv.
 *
 *   - autoconf's `as_fn_executable_p () { test -f "$1" && test -x "$1"; }`
 *     was unconditionally false for the same binaries, so
 *     AC_PROG_INSTALL could never succeed.  A structural ceiling on an
 *     autoconf build, not a nuisance.
 *
 * The split now in the tree: $LXMOD supplies explicit mode bits, while a
 * metadata-free Windows file receives default execute bits only when stat()
 * validates an executable PE32/PE32+ header.  __is_program() separately
 * recognizes an image or shebang script as a PATH candidate.  PATH requires
 * both answers.
 *
 * The format half keeps an executable-permission data file named `cat`
 * in an early PATH directory from shadowing the real cat.exe later on.
 * A search that stops on the wrong candidate is worse than one that finds
 * nothing, so the shadowing assertions below are load-bearing.
 *
 * The program used as a known-good PE is this test's own image, copied
 * under other names.  argv[0] is the path runtests.sh invoked, which is
 * absolute; a copy of those bytes is a real, runnable NT image, which no
 * synthesized fixture would be.
 */
/* setenv() is feature-test gated in include/stdlib.h; same define most
 * other tests in test/ already carry for the same reason (see
 * test/posix-glob.c's comment on this exact define). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>

extern char **environ;
int __spawn(const char *path, char *const argv[], char *const envp[]);

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

#define RC_ROLE 42

/* rm -rf, for the scratch directory main() makes.  Depth is bounded by
 * what this file creates (two levels), so recursion is fine. */
static void rmtree(const char *path)
{
	DIR *d = opendir(path);
	struct dirent *e;
	char sub[2048];
	if (d) {
		while ((e = readdir(d))) {
			if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
			snprintf(sub, sizeof sub, "%s/%s", path, e->d_name);
			if (unlink(sub) < 0) rmtree(sub);
		}
		closedir(d);
	}
	rmdir(path);
}

/* Copy `src` to `dst` byte for byte.  Returns 0 or -1. */
static int copyfile(const char *src, const char *dst)
{
	char buf[8192];
	int in, out;
	ssize_t n;
	in = open(src, O_RDONLY);
	if (in < 0) return -1;
	out = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (out < 0) { close(in); return -1; }
	while ((n = read(in, buf, sizeof buf)) > 0) {
		if (write(out, buf, (size_t)n) != n) { close(in); close(out); return -1; }
	}
	close(in);
	return close(out) < 0 || n < 0 ? -1 : 0;
}

static int writefile(const char *p, const char *data)
{
	size_t n = strlen(data);
	int fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0) return -1;
	if (n && write(fd, data, n) != (ssize_t)n) { close(fd); return -1; }
	return close(fd);
}

/* Explicit $LXMOD wins; otherwise only a validated PE image defaults to
 * executable.  A filename suffix alone has no permission meaning. */
static int test_mode_bits(const char *self)
{
	struct stat st;

	/* A linker-created PE has no spicule $LXMOD stream.  Its image header,
	 * not its .exe suffix, supplies the default execute bits; the same file
	 * remains executable through a hard-link name with no suffix at all. */
	CHECK(stat(self, &st) == 0 && S_ISREG(st.st_mode));
	CHECK((st.st_mode & 0111) == 0111);
	CHECK(link(self, "xs-pe-no-suffix") == 0);
	CHECK(stat("xs-pe-no-suffix", &st) == 0 && S_ISREG(st.st_mode));
	CHECK((st.st_mode & 0111) == 0111);
	CHECK(access("xs-pe-no-suffix", X_OK) == 0);

	CHECK(writefile("xs-plain.txt", "not a program\n") == 0);
	CHECK(stat("xs-plain.txt", &st) == 0);
	CHECK(S_ISREG(st.st_mode));
	CHECK((st.st_mode & 07777) == 0644);
	errno = 0;
	CHECK(access("xs-plain.txt", X_OK) == -1 && errno == EACCES);

	/* chmod writes $LXMOD and stat/access read the same value back. */
	{
		int r = chmod("xs-plain.txt", 0741);
		if (r < 0) {
			printf("exec-search: N/A ($LXMOD is unavailable on this runtime, errno=%d)\n",
			       errno);
			return 0;
		}
		CHECK(r == 0);
	}
	CHECK(stat("xs-plain.txt", &st) == 0);
	CHECK((st.st_mode & 0111) == 0101);
	CHECK(access("xs-plain.txt", X_OK) == 0);
	CHECK(chmod("xs-plain.txt", 0644) == 0);
	CHECK(stat("xs-plain.txt", &st) == 0);
	CHECK((st.st_mode & 07777) == 0644);

	/* Creation metadata beats the PE-aware compatibility fallback; a suffix
	 * by itself never grants execute permission. */
	CHECK(writefile("xs-plain.exe", "not a program\n") == 0);
	CHECK(stat("xs-plain.exe", &st) == 0);
	CHECK((st.st_mode & 07777) == 0644);

	/* A directory keeps its search bit, which is the same 0111 and is
	 * what a PATH prefix walk needs. */
	CHECK(mkdir("xs-d", 0755) == 0);
	CHECK(stat("xs-d", &st) == 0 && S_ISDIR(st.st_mode));
	CHECK(access("xs-d", X_OK) == 0);

	/* ENOENT still beats EACCES for something that is not there. */
	errno = 0;
	CHECK(access("xs-nothing", X_OK) == -1 && errno == ENOENT);
	return 1;
}

/* ============================================================
 * The PATH search: exec.html DESCRIPTION, "the path prefix for this
 * file is obtained by a search of the directories passed as the
 * environment variable PATH".  The standard does not say the search
 * must consult access(X_OK), and this tree's does not.
 * ============================================================ */

/* Run `name` through execvp() in a child and return its wait status, or
 * -1 if the child could not be started.  A separate process is needed
 * because a *successful* execvp does not return. */
static int execvp_in_child(const char *self, const char *name)
{
	char *av[3];
	int pid, status;
	av[0] = (char *)self;
	av[1] = (char *)name;
	av[2] = 0;
	pid = __spawn(self, av, environ);
	if (pid < 0) return -1;
	if (waitpid(pid, &status, 0) < 0) return -1;
	return status;
}

/* The child role: execvp(argv[1]) and report what happened.  On success
 * this never returns -- the resolved image runs, and being another copy
 * of this same binary it is invoked with "--role-exit" so that it exits
 * RC_ROLE immediately rather than running the whole suite again. */
static int search_child(const char *name)
{
	char *av[3];
	av[0] = (char *)name;
	av[1] = (char *)"--role-exit";
	av[2] = 0;
	errno = 0;
	execvp(name, av);
	/* execvp returned, so it failed.  Report errno, offset so that no
	 * value collides with RC_ROLE or with 0. */
	return 100 + (errno > 100 ? 99 : errno);
}

static void test_path_search(const char *self)
{
	char *oldpath = getenv("PATH");
	char pathbuf[4096];
	char cwd[2048];
	int st;

	CHECK(getcwd(cwd, sizeof cwd) != 0);
	CHECK(mkdir("xs-bin", 0755) == 0);
	CHECK(mkdir("xs-early", 0755) == 0);

	/* A real PE image under a name with no suffix at all -- the case
	 * that could not be reached before, and the one nova-nix worked
	 * around by installing .exe-suffixed copies of every coreutils
	 * name. */
	CHECK(copyfile(self, "xs-bin/xsprog") == 0);
	CHECK(chmod("xs-bin/xsprog", 0755) == 0);

	/* PATH entries are ';'-separated here, not ':' -- an absolute
	 * Windows entry contains a colon (src/process/find_program.c). */
	snprintf(pathbuf, sizeof pathbuf, "%s\\xs-early;%s\\xs-bin", cwd, cwd);
	CHECK(setenv("PATH", pathbuf, 1) == 0);

	/* 1. The suffix-less PE is found and run. */
	st = execvp_in_child(self, "xsprog");
	CHECK(st >= 0 && WIFEXITED(st) && WEXITSTATUS(st) == RC_ROLE);
	if (st >= 0 && WIFEXITED(st) && WEXITSTATUS(st) != RC_ROLE)
		printf("note: suffix-less PE search exited %d (errno would be %d)\n",
		       WEXITSTATUS(st), WEXITSTATUS(st) - 100);

	/* 2. ... and a data file of the same name, in an *earlier* PATH
	 * directory, does not shadow it.  This is the assertion that a
	 * "make X_OK true for everything and leave the search alone" fix
	 * would fail: the search would stop on xs-early/xsprog and the
	 * caller would get [ENOEXEC] for a file they never named. */
	CHECK(writefile("xs-early/xsprog", "#not a program, no shebang\n") == 0);
	CHECK(chmod("xs-early/xsprog", 0755) == 0);
	st = execvp_in_child(self, "xsprog");
	CHECK(st >= 0 && WIFEXITED(st) && WEXITSTATUS(st) == RC_ROLE);

	/* 3. A decoy named exactly what try_dir() appends -- xsprog.exe --
	 * in the earlier directory, still not a program.  try_dir() tries
	 * `name` then `name.exe` within each directory before moving on, so
	 * this is the shadowing case the old suffix rule got wrong: it
	 * would have accepted this text file on its name alone. */
	CHECK(writefile("xs-early/xsprog.exe", "still not a program\n") == 0);
	CHECK(chmod("xs-early/xsprog.exe", 0755) == 0);
	st = execvp_in_child(self, "xsprog");
	CHECK(st >= 0 && WIFEXITED(st) && WEXITSTATUS(st) == RC_ROLE);

	/* 4. A name that matches nothing executable anywhere on PATH is
	 * [ENOENT], not [ENOEXEC] and not a spawn attempt.  exec.html
	 * ERRORS: "[ENOENT] A component of path or file does not name an
	 * existing file". */
	CHECK(writefile("xs-early/xsdata", "just data\n") == 0);
	st = execvp_in_child(self, "xsdata");
	CHECK(st >= 0 && WIFEXITED(st) && WEXITSTATUS(st) == 100 + ENOENT);
	if (st >= 0 && WIFEXITED(st) && WEXITSTATUS(st) != 100 + ENOENT)
		printf("note: execvp(\"xsdata\") gave %d, wanted %d (ENOENT)\n",
		       WEXITSTATUS(st) - 100, ENOENT);

	/* (execvp("") is [ENOENT] too, but that clause and its positive
	 * control already live in test/posix-unistd-exec.c, fixed on main
	 * by b4a9a5b -- not repeated here.)
	 *
	 * 5. A shebang script *is* a candidate the search accepts, even
	 * with no suffix.  exec.html DESCRIPTION requires execvp() to hand
	 * such a file to a command interpreter rather than fail, which is
	 * why the [ENOEXEC] ERRORS entry is scoped "except for execlp() and
	 * execvp()".  The in-process interpreter is now implemented, so pin
	 * both halves together: the search must recognize the shebang and
	 * the fallback must execute the script to its distinctive status. */
	CHECK(writefile("xs-bin/xsscript", "#!/bin/sh\nexit 42\n") == 0);
	CHECK(chmod("xs-bin/xsscript", 0755) == 0);
	st = execvp_in_child(self, "xsscript");
	CHECK(st >= 0 && WIFEXITED(st) && WEXITSTATUS(st) == RC_ROLE);
	if (st >= 0 && WIFEXITED(st) && WEXITSTATUS(st) != RC_ROLE)
		printf("note: execvp(\"xsscript\") exited %d, wanted %d\n",
		       WEXITSTATUS(st), RC_ROLE);

	if (oldpath) setenv("PATH", oldpath, 1);
}

/* ============================================================
 * The path-taking forms are unaffected: they do no search, so a caller
 * who names a file explicitly still reaches __spawn and still gets
 * [ENOEXEC] from RtlCreateUserProcess for a non-image.  This is the
 * "split" holding in the other direction -- granting access(X_OK) does
 * not make execv() pretend a text file is a program.
 * ============================================================ */
static void test_explicit_path_still_enoexec(void)
{
	char *av[2];

	CHECK(writefile("xs-text", "#!/bin/sh\necho hi\n") == 0);
	CHECK(chmod("xs-text", 0755) == 0);
	av[0] = (char *)"xs-text";
	av[1] = 0;

	/* access(X_OK) says yes after chmod writes the execute bits... */
	CHECK(access("xs-text", X_OK) == 0);
	/* ... and execv() still refuses it, because whether NT can start an
	 * image is not a permission question.  exec.html: "[ENOEXEC] The
	 * new process image file has the appropriate access permission but
	 * has an unrecognized format" -- precisely this shape: appropriate
	 * permission, unrecognized format. */
	errno = 0;
	CHECK(execv("./xs-text", av) == -1 && errno == ENOEXEC);
}

int main(int argc, char **argv)
{
	char dir[] = "xsearch-XXXXXX";
	char origcwd[2048];

	if (argc > 1 && !strcmp(argv[1], "--role-exit")) return RC_ROLE;
	if (argc > 1) return search_child(argv[1]);

	if (!getcwd(origcwd, sizeof origcwd)) { printf("FAIL getcwd\n"); return 1; }
	if (!mkdtemp(dir)) { printf("FAIL mkdtemp\n"); return 1; }
	if (chdir(dir) < 0) { printf("FAIL chdir\n"); return 1; }

	if (!test_mode_bits(argv[0])) {
		if (chdir(origcwd) == 0) rmtree(dir);
		return 77;
	}
	test_explicit_path_still_enoexec();
	test_path_search(argv[0]);

	/* Leave nothing behind: runtests.sh gives each test a private
	 * mktemp -d, but this file is also run by hand from obj/test/
	 * during development, and a leftover xsearch-* makes the *next*
	 * run's mkdtemp() collide -- which reads as "FAIL mkdtemp" and
	 * hides every assertion below it.  Observed while writing this. */
	if (chdir(origcwd) < 0) { printf("FAIL chdir back\n"); return 1; }
	rmtree(dir);

	if (!fails) printf("exec-search: all tests passed\n");
	return fails != 0;
}
