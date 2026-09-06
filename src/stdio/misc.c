/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The odds and ends of <stdio.h>: perror, remove/rename, tmpfile and its
 * name-only relatives, and popen/pclose.
 *
 * popen hands the command to cmd.exe /c on Windows (via %ComSpec%, since
 * there is no /bin/sh) and to a PATH-resolved "sh" on Linux, consistent
 * with src/stdlib/system.c and the util atd/crond spawners.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- GNU feature-test macro has its specified reserved spelling
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include "libc.h"
#include "ownership_stubs.h"
#include "stdio_impl.h"
#include "plat_stdio.h"
#include "plat_fd.h"

void perror(const char *s)
{
	int e = errno;
	/* perror() is the diagnostic and returns void; a failure writing stderr
	 * cannot be recursively reported or replace the caller's saved errno. */
	if (s && *s) { (void)fputs(s, stderr); (void)fputs(": ", stderr); }
	(void)fputs(strerror(e), stderr);
	(void)fputc('\n', stderr);
}

int remove(const char *path)
{
	if (unlink(path) == 0) return 0;
	if (errno == EISDIR) return rmdir(path);
	return -1;
}

static int final_dot_component(const char *path)
{
	const char *end = path + strlen(path), *start;
	while (end > path && (end[-1] == '/' || end[-1] == '\\')) end--;
	start = end;
	while (start > path && start[-1] != '/' && start[-1] != '\\') start--;
	return (end - start == 1 && start[0] == '.') ||
	       (end - start == 2 && start[0] == '.' && start[1] == '.');
}

int renameat(int olddirfd, const char *old, int newdirfd, const char *new)
{
	/* POSIX requires EINVAL when old or new names a terminal "." or "..";
	 * everything else is backend-specific and lives in __plat_rename(). */
	if (final_dot_component(old) || final_dot_component(new)) {
		errno = EINVAL;
		return -1;
	}
	return __plat_rename(olddirfd, old, newdirfd, new);
}

int rename(const char *old, const char *new) { return renameat(AT_FDCWD, old, AT_FDCWD, new); }

/* Where a temporary file goes: $TMPDIR/$TMP/$TEMP, in that order, or the
 * current directory if none of them are set. */
static const char *tmpdir(void)
{
	const char *d = getenv("TMPDIR");
	if (!d || !*d) d = getenv("TMP");
	if (!d || !*d) d = getenv("TEMP");
	if (!d || !*d) d = ".";
	return d;
}

withtok(file_stream_open)
FILE *tmpfile(void)
{
	const char *dir = tmpdir();
	char *tmpl;
	int fd;
	FILE *f;
	size_t n = strlen(dir);

	{
		size_t tmplbytes;
		if (n > (size_t)-1 - sizeof "/ntlibcXXXXXX") { errno = ENOMEM; return 0; }
		tmplbytes = n + sizeof "/ntlibcXXXXXX";
		tmpl = malloc(tmplbytes);
		if (!tmpl) return 0;
		snprintf(tmpl, tmplbytes, "%s/ntlibcXXXXXX", dir);
	}
	fd = mkstemp(tmpl);
	if (fd < 0) { free(tmpl); return 0; }
	/* POSIX semantics: unlinked at once, gone the moment it is closed. */
	if (unlink(tmpl) < 0) {
		int e = errno;
		(void)close(fd);
		free(tmpl);
		errno = e;
		return 0;
	}
	free(tmpl);
	f = __file_new(fd, O_RDWR);
	if (!f) { int e = errno; (void)close(fd); errno = e; return 0; }
	return f;
}

/* tmpnam() must NOT create the file (unlike an earlier version of this
 * function, which called mkstemp() and left a zero-byte tmpnam_* file
 * behind on every call, plus [EEXIST] on the documented O_CREAT|O_EXCL
 * use). mktemp() is the same generator without the create; unlike
 * create-close-unlink (what tempnam() below does), it needs no write
 * access to the directory and leaves nothing behind on a mid-window
 * process death. The residual naming/create race is inherent to the
 * interface; the six random characters plus a four-hex-digit call
 * counter make it hard to guess and guarantee TMP_MAX distinct names. */
char *tmpnam(char *s)
{
	static const char hex[] = "0123456789abcdef";
	static char buf[L_tmpnam];
	static unsigned seq;
	char tmpl[] = "tmpnam_0000XXXXXX";
	unsigned n = seq++;
	int e = errno, i;

	for (i = 0; i < 4; i++) tmpl[10 - i] = hex[(n >> (4 * i)) & 15];
	/* mktemp() sets errno to 0 on success, which must not leak to the
	 * caller. The analyzer's "use mkstemp() instead" is the defect this
	 * function was fixed to undo (mkstemp() creates the file; tmpnam()
	 * must not), so it's suppressed here rather than followed. */
	if (!*mktemp(tmpl)) return 0; // NOLINT(clang-analyzer-security.insecureAPI.mktemp) -- see above: mkstemp() is the defect, not the fix
	errno = e;
	if (!s) s = buf;
	__ownership_writable_span(s, sizeof tmpl);
	__ownership_readable_span(tmpl, sizeof tmpl);
	memcpy(s, tmpl, sizeof tmpl);
	return s;
}

withtok(heap_allocated)
char *tempnam(const char *dir, const char *pfx) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	const char *d = dir ? dir : tmpdir();
	size_t n = strlen(d), pn = pfx ? strlen(pfx) : 0, tmplbytes;
	char *tmpl;
	int fd;
	if (!__size_add_checked(n, 1, &tmplbytes) ||
	    !__size_add_checked(tmplbytes, pn, &tmplbytes) ||
	    !__size_add_checked(tmplbytes, sizeof "XXXXXX", &tmplbytes)) return 0;
	tmpl = malloc(tmplbytes);
	if (!tmpl) return 0;
	snprintf(tmpl, tmplbytes, "%s/%sXXXXXX", d, pfx ? pfx : "");
	fd = mkstemp(tmpl);
	if (fd < 0) { free(tmpl); return 0; }
	if (close(fd) < 0 || unlink(tmpl) < 0) {
		int e = errno;
		(void)unlink(tmpl);
		free(tmpl);
		errno = e;
		return 0;
	}
	return tmpl;
}

char *ctermid(char *s)
{
	static char buf[L_ctermid] = "/dev/tty";
	if (s) {
		__ownership_writable_span(s, sizeof "/dev/tty");
		memcpy(s, "/dev/tty", sizeof "/dev/tty");
		return s;
	}
	return buf;
}

withtok(piped_stream_open)
FILE *popen(const char *cmd, const char *mode) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int rw = mode[0] == 'w';
	int fds[2], saved, child_std;
	char *shell;
	char *argv[4];
	int pid;
	FILE *f;

	if (mode[0] != 'r' && mode[0] != 'w') { errno = EINVAL; return 0; }
	if (pipe(fds) < 0) return 0;

	/* Reading: the child's stdout is the pipe's write end.  Writing: the
	 * child's stdin is the pipe's read end.  Either way that fd is
	 * swapped in for the duration of the spawn and put back after. */
	child_std = rw ? 0 : 1;
	saved = dup(child_std);
	if (saved < 0) {
		int e = errno;
		(void)close(fds[0]); (void)close(fds[1]);
		errno = e;
		return 0;
	}
	if (dup2(rw ? fds[0] : fds[1], child_std) < 0) {
		int e = errno;
		(void)close(saved); (void)close(fds[0]); (void)close(fds[1]);
		errno = e;
		return 0;
	}

#if defined(__linux__)
	shell = __find_program("sh", 1);
#else
	{
		const char *comspec = getenv("ComSpec");
		if (!comspec || !*comspec) comspec = "C:\\Windows\\System32\\cmd.exe";
		shell = strdup(comspec);
	}
#endif
	if (!shell) { pid = -1; }
	else {
		argv[0] = shell;
#if defined(__linux__)
		argv[1] = (char *)"-c";
#else
		argv[1] = (char *)"/c";
#endif
		argv[2] = (char *)cmd; argv[3] = 0;
		pid = __spawn(shell, argv, 0);
		free(shell);
	}

	if (dup2(saved, child_std) < 0) {
		int e = errno;
		(void)close(saved);
		(void)close(fds[0]);
		(void)close(fds[1]);
		errno = e;
		return 0;
	}
	(void)close(saved);
	(void)close(rw ? fds[0] : fds[1]);

	if (pid < 0) { (void)close(rw ? fds[1] : fds[0]); return 0; }

	f = __file_new(rw ? fds[1] : fds[0], rw ? O_WRONLY : O_RDONLY);
	if (!f) { int e = errno; (void)close(rw ? fds[1] : fds[0]); errno = e; return 0; }
	f->pid = pid;
	return f;
}

int pclose(FILE *f consume(piped_stream_open))
{
	int status;
	pid_t pid = f->pid;
	(void)fclose(f);
	if (pid < 0) { errno = ECHILD; return -1; }
	if (waitpid(pid, &status, 0) < 0) return -1;
	return status;
}

// NOLINTEND(misc-include-cleaner)
