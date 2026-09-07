/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of the exec family's ERRORS
 * section -- execl, execle, execlp, execv, execve, execvp, fexecve,
 * seven of the 43 names in test/POSIX-GAP-ACCOUNTING.md's
 * "Implemented, not clause-audited (357)" unistd.h row.
 *
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/exec.html
 * (fexecve() shares that page.)
 *
 * Division of labour with test/exec.c, which already exists and which
 * this file deliberately does not duplicate: that file covers the
 * *success* path -- argv/envp round trips through spawn.c's command
 * line builder, the exec'd image's exit status becoming the caller's,
 * [E2BIG] for an over-long command line, [ENOENT] for a missing
 * program, [EBADF] for fexecve() on a closed descriptor -- and needs a
 * spawn/role harness to do it, because a successful exec never
 * returns.  What is left, and what is here, is the rest of the ERRORS
 * list.  Every call below is one POSIX requires to *fail*, so each can
 * be made in-process: exec.html's "If execution fails, the calling
 * process image remains unchanged" is precisely what makes this file
 * possible, and is itself asserted by the fact that it keeps running.
 *
 * NO fork() ANYWHERE IN THIS FILE, deliberately.  It therefore runs
 * under `make check`'s Wine leg like any ordinary test and needs no
 * "-win" suffix (Makefile's TEST_RUN filters those out).  Adding one
 * fork() would move it to the real-Windows legs and, on stock apt Wine
 * -- which has no RtlCloneUserProcess -- would hang rather than fail.
 *
 * Oracle: mixed.  The empty-string and directory cases below are
 * decided inside spicule (src/process/find_program.c and
 * src/process/spawn.c's own checks), so Wine is sound for them; the
 * [ENOEXEC] answer comes from RtlCreateUserProcess refusing an invalid
 * image, which the real-Windows legs are the authority on.
 */
#define _GNU_SOURCE
#include "test-policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

extern char **environ;

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* A canary the "process image remains unchanged" clause is read off:
 * if any call below unexpectedly succeeded, nothing after it would
 * run, and this counter would not reach its final value. */
static int reached;

/* ============================================================
 * [ENOEXEC]
 * ============================================================ */

/* exec.html ERRORS: "The exec functions, except for execlp() and
 * execvp(), shall fail if: [ENOEXEC] The new process image file has
 * the appropriate access permission but has an unrecognized format."
 *
 * A deliberately truncated image with enough PE header to carry execute
 * permission on a no-$LXMOD Wine filesystem is exactly that case.  It is
 * also the one error on the page that distinguishes the p-forms from the
 * rest. */
static void test_enoexec(void)
{
	char *av[2];
	unsigned char image[90] = { 0 };
	int fd;

	/* Give stat() the minimal PE markers it uses for the no-$LXMOD Wine
	 * compatibility default, but omit the image they describe.  Process
	 * creation must reject this truncated, unrecognized format. */
	image[0] = 'M'; image[1] = 'Z';
	image[0x3c] = 0x40;              /* e_lfanew */
	image[0x40] = 'P'; image[0x41] = 'E';
#ifdef __x86_64__
	image[0x44] = 0x64; image[0x45] = 0x86; /* AMD64 */
	image[0x58] = 0x0b; image[0x59] = 0x02; /* PE32+ */
#else
	image[0x44] = 0x4c; image[0x45] = 0x01; /* i386 */
	image[0x58] = 0x0b; image[0x59] = 0x01; /* PE32 */
#endif
	image[0x54] = 2;                 /* optional-header size */
	image[0x56] = 2;                 /* IMAGE_FILE_EXECUTABLE_IMAGE */
	fd = open("ex-bad-image", O_CREAT | O_WRONLY | O_TRUNC, 0755);
	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(write(fd, image, sizeof image) == (ssize_t)sizeof image);
	CHECK(close(fd) == 0);

	av[0] = (char *)"ex-bad-image";
	av[1] = 0;

	errno = 0;
	CHECK(execv("./ex-bad-image", av) == -1 && errno == ENOEXEC);
	reached++;
	errno = 0;
	CHECK(execve("./ex-bad-image", av, environ) == -1 && errno == ENOEXEC);
	reached++;
	errno = 0;
	CHECK(execl("./ex-bad-image", "ex-bad-image", (char *)0) == -1 && errno == ENOEXEC);
	reached++;
	errno = 0;
	CHECK(execle("./ex-bad-image", "ex-bad-image", (char *)0, environ) == -1 && errno == ENOEXEC);
	reached++;

	/* fexecve() is not in the "except for" list, so it carries the
	 * same [ENOEXEC]. */
	fd = open("ex-bad-image", O_RDONLY);
	CHECK(fd >= 0);
	if (fd >= 0) {
		errno = 0;
		CHECK(fexecve(fd, av, environ) == -1 && errno == ENOEXEC);
		reached++;
		CHECK(close(fd) == 0);
	}

	/* execvp()/execlp() are the two functions this page's [ENOEXEC]
	 * entry excludes -- "The exec functions, *except for execlp() and
	 * execvp()*, shall fail if" -- because for them the clause requires
	 * a command interpreter to run instead:
	 *
	 *   "In the cases where the other members of the exec family of
	 *    functions would fail and set errno to [ENOEXEC], the execlp()
	 *    and execvp() functions shall execute a command interpreter and
	 *    the environment of the executed command shall be as if the
	 *    process invoked the sh utility using execl() as follows:
	 *    execl(<shell path>, arg0, file, arg1, ..., (char *)0);"
	 *
	 * Two BUG fences used to stand here, asserting that both calls
	 * returned -1 where the clause says the shell should run.  They are
	 * gone because the fallback is implemented (src/process/exec.c's
	 * shell_fallback(), over __sh_run_script() in src/sh/script.c).
	 *
	 * They are not replaced by the inverse assertion, because a working
	 * fallback cannot be observed from here: it does not return.  The
	 * interpreter becomes what this process is running, and whatever it
	 * exits with becomes this test's exit status -- so an inline `CHECK(execvp
	 * (...) != -1)` cannot pass, cannot fail, and cannot even reach the
	 * clauses below it.  The observation needs a child process to spend,
	 * and a marker file for it to leave behind; that is exactly what
	 * test/exec-script.c is, and its cases A, B and C cover this clause
	 * for both p-forms, including the argument vector the execl() shape
	 * above specifies.  The rest of this file keeps the half that *is*
	 * observable in-process: the non-p-forms above, which must still
	 * fail with [ENOEXEC] on the very same file. */

	CHECK(unlink("ex-bad-image") == 0);

	/* N/A: "[EINVAL] The new process image file has appropriate
	 * privileges and has a recognized executable binary format, but
	 * the system does not support execution of a file with this
	 * format."  The distinction between [ENOEXEC] and [EINVAL] is
	 * "unrecognized" versus "recognized but unsupported", and
	 * producing the latter means a PE image for a machine type this
	 * host cannot run.  src/internal/pe.c can parse such a header but
	 * nothing here can build one at test time, and a checked-in
	 * foreign binary is not something this suite carries. */
}

/* ============================================================
 * [ENOENT], [ENOTDIR], and the empty string
 * ============================================================ */
static void test_path_errors(void)
{
	char *av[2];
	int fd, r;

	av[0] = (char *)"x";
	av[1] = 0;

	fd = open("ex-plain.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
	CHECK(fd >= 0 && close(fd) == 0);

	/* "[ENOENT] A component of path or file does not name an existing
	 * file or path or file is an empty string." */
	errno = 0;
	CHECK(execv("./ex-no-such-program.exe", av) == -1 && errno == ENOENT);
	reached++;
	errno = 0;
	CHECK(execve("./ex-no-such-program.exe", av, environ) == -1 && errno == ENOENT);
	reached++;
	errno = 0;
	CHECK(execv("", av) == -1 && errno == ENOENT);
	reached++;
	errno = 0;
	CHECK(execl("", "x", (char *)0) == -1 && errno == ENOENT);
	reached++;
	errno = 0;
	CHECK(execle("", "x", (char *)0, environ) == -1 && errno == ENOENT);
	reached++;

	/* The p-forms take the same clause: exec.html's [ENOENT] entry is
	 * under "The exec functions, except for fexecve(), shall fail if",
	 * so execvp() and execlp() are included.  A name with no <slash>
	 * is PATH-searched (DESCRIPTION: "Otherwise, the path prefix for
	 * this file is obtained by a search of the directories passed as
	 * the environment variable PATH"), and a name that is in no PATH
	 * directory does not name an existing file. */
	errno = 0;
	CHECK(execvp("ex-no-such-program-on-path-xyz", av) == -1 && errno == ENOENT);
	reached++;
	errno = 0;
	CHECK(execlp("ex-no-such-program-on-path-xyz", "x", (char *)0) == -1 && errno == ENOENT);
	reached++;

	/* "[ENOTDIR] A component of the new process image file's path
	 * prefix names an existing file that is neither a directory nor a
	 * symbolic link to a directory ..." */
	errno = 0;
	CHECK(execv("ex-plain.txt/prog", av) == -1 && errno == ENOTDIR);
	reached++;
	errno = 0;
	CHECK(execl("ex-plain.txt/prog", "x", (char *)0) == -1 && errno == ENOTDIR);
	reached++;

	/* The same clause reaches the p-forms through their PATH search.
	 * `use_path` in src/process/exec.c's execvpe() is true for "" --
	 * an empty name has no <slash> -- so the empty string has to be
	 * rejected by __find_program() (src/process/find_program.c)
	 * before the PATH loop runs.  It cannot be left to the loop: an
	 * empty name makes try_dir() build `<PATH entry>\`, a directory
	 * name with nothing appended, which `access(p, X_OK)` accepts
	 * (src/unistd/access.c), so execvp("") would resolve to the first
	 * directory in PATH and report whatever spawning a directory
	 * produces rather than [ENOENT]. */
	errno = 0;
	CHECK(execvp("", av) == -1 && errno == ENOENT);
	reached++;
	errno = 0;
	CHECK(execlp("", "x", (char *)0) == -1 && errno == ENOENT);
	reached++;

	/* A directory on PATH is not an executable-file candidate.  The
	 * content-aware search opens candidates with FILE_NON_DIRECTORY_FILE,
	 * so this must be indistinguishable from no matching program.
	 *
	 * The name is put on PATH rather than found there, because the
	 * search is over the Windows PATH (';'-separated, no current
	 * directory implied) and nothing this test can execute is on it.
	 * An empty entry means the current directory, as on Unix -- which
	 * is this test's own temporary directory, since main() chdir()s
	 * into it -- so prepending one is enough.
	 *
	 * What is put there is a directory rather than a text file because
	 * execvp() correctly hands a recognized shebang file to the command
	 * interpreter and would not return to this test. */
	{
		const char *oldpath = getenv("PATH");
		char *saved = oldpath ? strdup(oldpath) : 0;
		CHECK(!oldpath || saved != NULL);

		if (mkdir("ex-onpath.d", 0755) == 0) {
			{
				size_t n = saved ? strlen(saved) : 0;
				char *withdot = malloc(n + 2);
				CHECK(withdot != NULL);
				if (withdot) {
					withdot[0] = ';';   /* leading empty entry == "." */
					memcpy(withdot + 1, saved ? saved : "", n + 1);
					CHECK(setenv("PATH", withdot, 1) == 0);
					free(withdot);
				}
			}

			errno = 0;
			r = execvp("ex-onpath.d", av);
			printf("observed: execvp(\"ex-onpath.d\") = %d, errno=%d "
			       "(want %d ENOENT)\n", r, errno, ENOENT);
			CHECK(r == -1 && errno == ENOENT);
			reached++;
			errno = 0;
			CHECK(execlp("ex-onpath.d", "x", (char *)0) == -1 && errno == ENOENT);
			reached++;

			if (saved) CHECK(setenv("PATH", saved, 1) == 0);
			CHECK(rmdir("ex-onpath.d") == 0);
		} else {
			CHECK(0);   /* could not create the probe directory */
		}
		free(saved);
	}

	CHECK(unlink("ex-plain.txt") == 0);
}

/* ============================================================
 * [EACCES] -- a new process image file that is not a regular file
 * ============================================================ */
static void test_not_a_regular_file(void)
{
	char *av[2];

	av[0] = (char *)"x";
	av[1] = 0;

	CHECK(mkdir("ex-dir", 0755) == 0);

	/* exec.html DESCRIPTION: "The new image shall be constructed from
	 * a regular, executable file called the new process image file."
	 * A directory is not one, so the call must fail -- asserted here
	 * unfenced, with only the errno left to the fence below. */
	errno = 0;
	CHECK(execv("./ex-dir", av) == -1);
	reached++;
	errno = 0;
	CHECK(execve("./ex-dir", av, environ) == -1);
	reached++;

#if SPICULE_TEST(PASS, posix_unistd_exec_directory_reports_eacces) /* Executing a directory reports [EACCES], as exec.html requires.
	 *
	 * exec.html ERRORS: "The exec functions *shall* fail if: ...
	 * [EACCES] The new process image file is not a regular file and
	 * the implementation does not support execution of files of its
	 * type."  NT does not execute directories, so that clause applies
	 * exactly.  [EBADF] appears on the page only under "The fexecve()
	 * function shall fail if", where it is about the *descriptor*
	 * argument -- it is not an errno the path-taking forms may
	 * produce at all, and a caller distinguishing "I passed a bad fd"
	 * from "that path is not executable" is misled by it.
	 *
	 * src/process/exec.c checks S_ISREG before process creation, so the
	 * driver's unrelated status for attempting to execute a directory
	 * cannot leak out as [EBADF]. */
	errno = 0;
	CHECK(execv("./ex-dir", av) == -1 && errno == EACCES);
	errno = 0;
	CHECK(execve("./ex-dir", av, environ) == -1 && errno == EACCES);
#endif

	/* fexecve() on a descriptor open on a directory: exec.html's
	 * fexecve() section says "[EBADF] The fd argument is not a valid
	 * file descriptor open for executing", and a directory descriptor
	 * is not open for executing, so EBADF is the right answer here --
	 * this is the one place on the page where it is.  Asserted rather
	 * than fenced, to pin the distinction the fence above draws. */
	{
		int dfd = open("ex-dir", O_RDONLY | O_DIRECTORY);
		int r;
		CHECK(dfd >= 0);
		if (dfd >= 0) {
			errno = 0;
			r = fexecve(dfd, av, environ);
			printf("observed: fexecve(dirfd) = %d, errno=%d "
			       "(want -1/%d EBADF)\n", r, errno, EBADF);
			CHECK(r == -1 && errno == EBADF);
			reached++;
			CHECK(close(dfd) == 0);
		}
		/* Not an assertion: the fence above records execv()/execve()
		 * over a directory as yielding EBADF, but that figure was
		 * probed under Wine, and Wine reaches the image-section step
		 * by a different route than NT does.  Printing it here costs
		 * one failed spawn and tells the next real-NT log whether the
		 * fence's premise holds there at all.  Neither call can
		 * succeed -- a directory is not a process image -- so this
		 * cannot replace the running process. */
		errno = 0;
		r = execv("./ex-dir", av);
		printf("observed: execv(\"./ex-dir\") = %d, errno=%d "
		       "(fence above claims %d EBADF; %d EACCES is what "
		       "exec.html requires)\n", r, errno, EBADF, EACCES);
	}

	CHECK(rmdir("ex-dir") == 0);

	/* N/A, with the mechanism: "[EACCES] Search permission is denied
	 * for a directory listed in the new process image file's path
	 * prefix, or the new process image file denies execution
	 * permission."  $LXMOD now makes the file-permission branch
	 * reachable and is covered by test/exec-search.c.  One fixed identity
	 * (src/unistd/ids.c) still cannot construct a directory it may not
	 * search, so that branch remains unavailable here.
	 *
	 * N/A: [ELOOP] needs a symbolic-link cycle, handed to NT's own
	 * resolver by src/internal/path.c; [ETXTBSY] and [ENOMEM] are
	 * both may-fail. */
}

/* ============================================================
 * RETURN VALUE, and the clause that lets every call above be made
 * in-process at all
 * ============================================================ */
static void test_failed_exec_leaves_image_unchanged(void)
{
	char *av[2];
	int fd;
	char buf[8];

	av[0] = (char *)"x";
	av[1] = 0;

	/* exec.html RETURN VALUE: "If one of the exec functions returns to
	 * the calling process image, an error has occurred; the return
	 * value shall be -1, and errno shall be set to indicate the
	 * error."  DESCRIPTION: "If execution fails, the calling process
	 * image remains unchanged" (RETURN VALUE, in the same words:
	 * "There shall be no return from a successful exec").
	 *
	 * "Remains unchanged" is checked in the form that actually bit
	 * this tree once: src/process/exec.c's banner records that
	 * execve() used to call __fd_close_all_cloexec() *before* the
	 * spawn, so a failed execv() handed the caller back a process
	 * whose close-on-exec descriptors had already been shut.  An open
	 * FD_CLOEXEC descriptor must survive a failed exec and still be
	 * usable. */
	fd = open("ex-keep.txt", O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(write(fd, "keep", 4) == 4);
	CHECK(fcntl(fd, F_GETFD) & FD_CLOEXEC);

	errno = 0;
	CHECK(execv("./ex-no-such-program.exe", av) == -1 && errno == ENOENT);
	reached++;

	/* still open, still close-on-exec, still readable */
	CHECK(fcntl(fd, F_GETFD) != -1);
	CHECK(fcntl(fd, F_GETFD) & FD_CLOEXEC);
	CHECK(lseek(fd, 0, SEEK_SET) == 0);
	CHECK(read(fd, buf, 4) == 4);
	CHECK(!memcmp(buf, "keep", 4));
	CHECK(close(fd) == 0);
	CHECK(unlink("ex-keep.txt") == 0);

	/* And the environment the failed exec was asked to install did not
	 * take effect on this process: "For those forms not containing an
	 * envp pointer ... the environment for the new process image shall
	 * be taken from the external variable environ in the calling
	 * process" -- exec never writes the caller's own environ. */
	{
		char *envp[2];
		envp[0] = (char *)"SPICULE_EXEC_CLAUSE_PROBE=1";
		envp[1] = 0;
		errno = 0;
		CHECK(execve("./ex-no-such-program.exe", av, envp) == -1 && errno == ENOENT);
		reached++;
		CHECK(getenv("SPICULE_EXEC_CLAUSE_PROBE") == NULL);
		CHECK(environ != NULL && environ[0] != NULL);
	}
}

int main(void)
{
#ifndef _WIN32
	/* tools/asan-build.sh compiles this suite natively, against
	 * fuzz/ntstubs.c rather than against ntdll: its
	 * RtlCreateUserProcess is a real host execve(2), not NT process
	 * creation.  Every clause in this file is about what NT does with
	 * a new process image file -- which errno an invalid image, a
	 * directory or an empty name produces -- so under that build the
	 * subject of the test is not present and a green run would be
	 * evidence about glibc's execve, not about src/process/exec.c.
	 * Measured there: the [ENOEXEC] group all report a different
	 * errno (the host honours the "#!/bin/sh" shebang this file
	 * writes) and `environ` is not the one crt1.c installs.
	 *
	 * Reported as rc=77 "unverified" rather than as a pass, and
	 * rather than as an entry in tools/asan-build.sh's not_native()
	 * table -- the SKIP-plus-77 route needs no change to the runner
	 * and is the mechanism tools/run-tests.py, tools/asan-build.sh and
	 * CI's PowerShell loop all already honour (test/posix-socket.c is
	 * the model).  The PE build under `make check`, and the
	 * real-Windows CI legs, are where these clauses are checked. */
	printf("SKIP posix-unistd-exec (native ASan build: fuzz/ntstubs.c's "
	       "RtlCreateUserProcess is a host execve(2), so there is no NT "
	       "process creation for exec.html's ERRORS clauses to be about)\n");
	printf("posix-unistd-exec: nothing ran here; exiting 77 (unverified)\n");
	return 77;
#else
	char tmpl[] = "posixunistdexec-XXXXXX";
	char *dir = mkdtemp(tmpl);
	char origcwd[4096];

	CHECK(getcwd(origcwd, sizeof origcwd) == origcwd);
	CHECK(dir == tmpl);
	if (!dir) return 1;
	CHECK(chdir(dir) == 0);

	test_enoexec();
	test_path_errors();
	test_not_a_regular_file();
	test_failed_exec_leaves_image_unchanged();

	/* Every call this file makes is one POSIX requires to fail, so
	 * reaching here at all is the "calling process image remains
	 * unchanged" clause holding 23 times over.  The count is asserted
	 * rather than left implicit so that an exec which silently started
	 * *succeeding* -- and therefore never returned -- cannot be
	 * mistaken for a shorter run that passed. */
	CHECK(reached == 23);

	CHECK(chdir(origcwd) == 0);
	CHECK(rmdir(dir) == 0);

	if (!fails) printf("posix-unistd-exec: all tests passed\n");
	return fails != 0;
#endif
}
