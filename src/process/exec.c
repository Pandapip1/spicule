/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * exec.
 *
 * No Windows call replaces the running image, so execve cannot do what
 * it does on Unix. What it does instead is start the program as a child,
 * wait for it, and end with its status, so anything watching (a shell
 * running `exec prog`, a parent that will waitpid) sees the process run
 * prog and end when prog ends. The pid changes; nothing else can be
 * helped -- the same approach every from-scratch Unix-on-Windows layer
 * without a kernel personality ends up taking.
 *
 * Linux has the real primitive this fork+wait dance stands in for:
 * execve(2) replaces the process image in place, same pid, no child.
 * __plat_process_exec() is that real syscall, and execve() below calls
 * it directly under #if defined(__linux__) instead of running the
 * emulation; every other function here still funnels through execve(),
 * so that one #ifdef is as far as the real path needs to reach.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include "libc.h"
#include "plat_process.h"

int execve(const char *path, char *const argv[], char *const envp[])
{
#if !defined(__linux__)
	int pid, status;
#endif
	struct stat st;
	if (stat(path, &st) < 0) return -1;
	if (!S_ISREG(st.st_mode) || !(st.st_mode & 0111)) {
		errno = EACCES;
		return -1;
	}
#if defined(__linux__)
	/* The real thing: getpid() after this returns unchanged, unlike the
	 * fork+wait stand-in below. A failed real execve() already leaves
	 * the process image untouched (exec.html's promise for a failed
	 * exec), so there's no cloexec-close or _exit() left to do here on
	 * either path. */
	return __plat_process_exec(path, argv, envp);
#else
	pid = __spawn(path, argv, envp);
	if (pid < 0) return -1;
	/* Past this point exec has "succeeded": the new program is running
	 * and this process only stands in for it. Only now may cloexec
	 * descriptors close -- closing them before the spawn would leave a
	 * failed exec (e.g. ENOENT) with an already-mutated process image,
	 * breaking POSIX's unchanged-on-failure promise.
	 *
	 * The child never needed them closed first: a cloexec handle is
	 * created without OBJ_INHERIT, so RtlCreateUserProcess never copies
	 * it regardless. The close still happens because this process
	 * outlives the spawn -- holding the file open for the child's whole
	 * run would keep a lock or pending delete alive that a real exec
	 * would have released. */
	__fd_close_all_cloexec();
	if (waitpid(pid, &status, 0) < 0) return -1;
	/* End the way _exit() does, not exit(): exec.html says a successful
	 * exec unregisters every atexit()/at_quick_exit()/pthread_atfork()
	 * handler, but this stand-in keeps the address space, so calling
	 * exit() here would run the *caller's* atexit handlers when the
	 * exec'd program finishes -- not cosmetic: GCC's driver registers
	 * delete_temp_files() with atexit() then fork()+execv()s cc1, and a
	 * stand-in that ran it on cc1's exit deleted the driver's own
	 * intermediate .s before "as" could read it.
	 *
	 * Skip the stdio flush for the same reason: glibc's own behavior
	 * (measured, 2.39) is that a printf() with no newline followed by
	 * execl() prints nothing, since the buffer dies with the image. */
	if (WIFEXITED(status)) _exit(WEXITSTATUS(status));
	/* The child died by a signal; this process is standing in for it, so
	 * end the same way and let *our* parent's waitpid see WIFSIGNALED. */
	__exit_internal(__ENCODE_SIGNAL_EXIT(WTERMSIG(status)));
#endif
}

int execv(const char *path, char *const argv[])
{
	return execve(path, argv, __environ);
}

/* exec.html: on [ENOEXEC], execlp()/execvp() must run a command
 * interpreter as if by execl(<shell path>, arg0, file, arg1, ...,
 * (char *)0) -- the page's [ENOEXEC] shall-fail clause explicitly
 * excludes these two, and APPLICATION USAGE requires treating the file
 * as a shell script (required since POSIX.1-2017).
 *
 * The interpreter is this libc's own __sh_run_script() (src/sh/script.c),
 * called as a function rather than spawned as a second image, per the
 * shell's own "reuse rule" design note. Spawning sh as a second image was
 * rejected: resolving it through PATH would give arbitrary code
 * execution to whoever can set PATH for a script the caller chose but
 * never trusted PATH to interpret, and locating an sh.exe beside the
 * running image only holds for `make install`'s own layout.
 *
 * __sh_run_script() is the same exec stand-in with the spawn taken out:
 * it closes cloexec descriptors and calls _exit(), not exit(), in the
 * same order execve() does above. Returns only on failure, like every
 * other exec path here. */
static int shell_fallback(const char *path, char *const argv[], char *const envp[]) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int enoexec = errno;
	char **av;
	size_t n = 0, i, navs, bytes;
	int argc;

	while (argv[n]) n++;
	if (!__size_add_checked(n, 3, &navs) ||
	    !__size_mul_checked(navs, sizeof *av, &bytes)) { errno = enoexec; return -1; }
	av = (char **)malloc(bytes);
	if (!av) { errno = enoexec; return -1; }
	/* arg0, file, arg1, ..., (char *)0 -- the clause's own shape. arg0 is
	 * the caller's, not the shell's path: it's only what the shell
	 * prefixes its diagnostics with, and passing argv[0] through
	 * satisfies both POSIX.1-2017's and -2024's wording for that slot.
	 *
	 * `file` is the *resolved* path, not the argument as given: the
	 * shell would otherwise open a bare name a second time, by different
	 * rules, against a different place than where PATH search found it.
	 *
	 * An empty argv (n == 0) is nonconforming, but must not index
	 * argv[0] here, so the shell gets its own name in that slot. */
	av[0] = n ? argv[0] : (char *)"sh";
	av[1] = (char *)path;
	for (i = 1; i < n; i++) av[i + 1] = argv[i];
	argc = (int)(n ? n : 1) + 1;
	av[argc] = 0;

	/* The interpreter must run with the environment execl() of the shell
	 * would have given it; the engine reads the environment through
	 * __environ (getenv(), wordexp()), so pointing that at envp achieves
	 * it. */
	__environ = (char **)envp;

	/* Past this point the exec has "succeeded" (see execve() above): the
	 * interpreter is committed to. Only now may cloexec descriptors go,
	 * and only _exit() may end it -- atexit handlers and unflushed stdio
	 * died with the image a real exec would have thrown away. */
	__fd_close_all_cloexec();
	_exit(__sh_run_script(argc, av));
	return -1;   /* not reached: _exit() does not return */
}

int execvpe(const char *file, char *const argv[], char *const envp[])
{
	char *full;
	int use_path = !strchr(file, '/') && !strchr(file, '\\');
	int r, e;
	full = __find_program(file, use_path);
	if (!full) { errno = ENOENT; return -1; }
	r = execve(full, argv, envp);
	/* [ENOEXEC] here is NT refusing the file as a process image
	 * (RtlCreateUserProcess: STATUS_INVALID_IMAGE_NOT_MZ or
	 * _FORMAT, mapped to ENOEXEC by spawn.c). Reading it back off errno
	 * matches how exec.html states the condition and needs no second
	 * channel through execve().
	 *
	 * Not gated on use_path: the clause is about which *function* was
	 * called, not how the name resolved, and XCU 2.9.1 gives a <slash>
	 * file argument the same fallback explicitly. */
	if (r == -1 && errno == ENOEXEC) r = shell_fallback(full, argv, envp);
	e = errno;
	free(full);
	errno = e;
	return r;
}

int execvp(const char *file, char *const argv[])
{
	return execvpe(file, argv, __environ);
}

withtok(heap_allocated)
static char **build_argv(const char *arg0, va_list ap, char ***envout)
{
	size_t cap = 8, n = 0, bytes;
	char **v;
	if (!__size_mul_checked(cap, sizeof(char *), &bytes)) return 0;
	v = (char **)malloc(bytes);
	if (!v) return 0;
	v[n++] = (char *)arg0;
	while (v[n-1]) {
		if (n >= cap - 1) {
			size_t nc;
			char **nv;
			size_t growbytes;
			if (!__array_next_capacity(cap, n, 2, 8, sizeof *v, &nc)) {
				free((void *)v); errno = ENOMEM; return 0;
			}
			growbytes = nc * sizeof *v; /* proven <= SIZE_MAX by __array_next_capacity's own element_size bound above */
			nv = (char **)realloc((void *)v, growbytes);
			if (!nv) { free((void *)v); return 0; }
			v = nv;
			cap = nc;
		}
		v[n++] = va_arg(ap, char *);
	}
	if (envout) *envout = va_arg(ap, char **);
	return v;
}

int execl(const char *path, const char *arg0, ...) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	va_list ap; char **v; int r;
	va_start(ap, arg0);
	v = build_argv(arg0, ap, 0);
	va_end(ap);
	if (!v) return -1;
	r = execv(path, v);
	free((void *)v);
	return r;
}

int execle(const char *path, const char *arg0, ...) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	va_list ap; char **v, **env = 0; int r;
	va_start(ap, arg0);
	v = build_argv(arg0, ap, &env);
	va_end(ap);
	if (!v) return -1;
	r = execve(path, v, env);
	free((void *)v);
	return r;
}

int execlp(const char *file, const char *arg0, ...) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	va_list ap; char **v; int r;
	va_start(ap, arg0);
	v = build_argv(arg0, ap, 0);
	va_end(ap);
	if (!v) return -1;
	r = execvp(file, v);
	free((void *)v);
	return r;
}

int fexecve(int fd, char *const argv[], char *const envp[])
{
	char *p;
	struct stat st;
	int r;

	/* exec.html's fexecve()-specific [EBADF] ("fd ... not open for
	 * executing") can't come from execve() below it: a directory
	 * descriptor reaches RtlCreateUserProcess and comes back as an
	 * image-section NTSTATUS about the *file*, not the descriptor
	 * (measured, Windows 11 22621: STATUS_INVALID_FILE_FOR_SECTION on a
	 * directory handle, which spawn.c maps to ENOEXEC, not EBADF). So the
	 * clause is decided here instead, while the descriptor still exists:
	 * not open on a regular file means not "open for executing". A
	 * regular file that isn't executable still falls through to
	 * execve()'s own ENOEXEC. */
	if (fstat(fd, &st) < 0) { errno = EBADF; return -1; }
	if (!S_ISREG(st.st_mode)) { errno = EBADF; return -1; }

	p = __handle_path(__fd_handle(fd));
	if (!p) return -1;
	r = execve(p, argv, envp);
	__free(p);
	return r;
}
