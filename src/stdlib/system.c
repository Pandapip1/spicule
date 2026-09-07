/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * system(): run a command through a command processor and wait for it.
 *
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/system.html
 * ("system") is the contract this follows.  A few of its requirements
 * take real decisions on NT, recorded here rather than left implicit:
 *
 *   - "the shell".  POSIX leaves the interpreter unspecified beyond "an
 *     implementation-defined shell"; on NT there is no /bin/sh, so this
 *     uses %ComSpec% if it names something executable, else "cmd.exe"
 *     resolved through PATH like any other program name (see
 *     __find_program, src/process/find_program.c).  ComSpec is what
 *     cmd.exe itself sets and what a nested cmd.exe consults, and it is
 *     what Windows' own C runtime looks up for the same purpose --
 *     Wine's reimplementation of it, which this design otherwise
 *     follows for the reasons below, does exactly this lookup
 *     (dlls/msvcrt/process.c, _wsystem:
 *     https://github.com/reactos/reactos/blob/master/dll/win32/msvcrt/process.c).
 *     Respecting it rather than hard-coding cmd.exe means a caller who
 *     replaced their shell on purpose gets that shell.
 *
 *     On Linux, the shell is "sh" resolved through __find_program(name,
 *     1) -- a PATH search, not a hard-coded "/bin/sh" -- matching how
 *     src/util/atd.c and src/util/crond.c already resolve the shell they
 *     spawn a job/crontab line through; keeping that the one convention
 *     this project has for "the shell it runs a command through" on
 *     Linux, rather than inventing a second one here, is the point. Not
 *     $SHELL: XBD 8.1 defines that as the invoking user's own preferred
 *     interactive shell, which is not what "an implementation-defined
 *     shell" means here -- a caller whose interactive shell is csh or
 *     fish must still get sh(1p) word-splitting and quoting for the
 *     command string this passes to "-c", exactly as glibc's and musl's
 *     own system() hard-code a shell rather than consulting $SHELL for
 *     the same reason.
 *
 *   - system(NULL) must return non-zero "if a command processor is
 *     available" (POSIX, same page).  That is read literally: the shell
 *     found above must actually exist and be runnable, checked with
 *     access(path, X_OK) for a %ComSpec% value (__find_program does not
 *     check existence for a name with a directory part) and implicitly
 *     by __find_program's own access() check for the "cmd.exe" fallback
 *     on NT, or the "sh" lookup on Linux -- neither platform gives "sh"/
 *     "cmd.exe" a directory part, so both go through that same PATH-loop
 *     access() check every time.
 *
 *   - The return value is a wait status, not an exit code: it comes
 *     straight from waitpid() so WEXITSTATUS/WIFEXITED/WIFSIGNALED work
 *     on it exactly as POSIX requires, and this library's own
 *     src/process/wait.c encode_status is what defines what that status
 *     means (an ordinary exit is (code<<8); a death this library staged
 *     via __ENCODE_SIGNAL_EXIT, or an NT exception with a signal-shaped
 *     meaning, decodes as WIFSIGNALED).
 *
 *   - SIGINT/SIGQUIT are ignored in the caller and SIGCHLD is blocked
 *     for the duration, as POSIX requires.  Ignoring SIGINT/SIGQUIT is
 *     fully meaningful here: this library's signal() really does
 *     suppress delivery of a signal it can raise (the Ctrl-C/Ctrl-Break
 *     path under SPICULE_USE_KERNEL32, or a synchronous raise()).
 *     Blocking SIGCHLD, by contrast, protects against nothing real: per
 *     src/signal/signal.c's header comment, this library never delivers
 *     any signal asynchronously from another thread or process, so there
 *     is no concurrent SIGCHLD delivery for the block to race with in
 *     the first place.  It is still done, both because POSIX asks for it
 *     unconditionally and because it costs nothing and keeps a future,
 *     more concurrent signal implementation from silently breaking this
 *     contract.
 *
 *   - Quoting the command for cmd.exe's "/c" is *not* done through
 *     spawn.c's build_cmdline/append_arg, even though __spawn is used to
 *     start the shell.  append_arg implements the CommandLineToArgvW
 *     quoting convention -- backslash-doubling before a quote or the
 *     argument's end, one wrapping quote pair for anything containing
 *     whitespace -- and cmd.exe does not parse the text after /C with
 *     that convention.  Per Microsoft's own documented algorithm
 *     (https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd,
 *     the /C remarks): cmd looks at the *first* character of what
 *     follows /C; if it is a quote, that quote and the *last* quote
 *     character anywhere in the string are stripped, and everything
 *     between (and, if the "all conditions met" fast path linked above
 *     does not apply, which it will not for anything but a bare
 *     executable name) is passed through byte for byte.  Wine's
 *     _wsystem (linked above) accordingly builds the child's raw command
 *     line by string concatenation -- comspec + L" /c " + cmd -- with no
 *     quoting layer of its own at all.
 *
 *     __spawn only takes an argv array, not a raw command line, and
 *     spawn.c is out of scope for this change, so there is no way to
 *     hand it cmd.exe's tail unquoted the way Wine does.  What *is*
 *     available, and is what this uses, is argv = { shell, "/c", command
 *     }: append_arg leaves "command" completely untouched if it needs no
 *     quoting at all, and otherwise wraps the whole string in exactly
 *     one quote pair with no interior escaping *unless* command itself
 *     contains a literal '"' or ends in one or more '\\'.  For a command
 *     with no embedded quote and no trailing backslash, that wrap-only
 *     encoding is exactly what cmd's "strip the first and last quote"
 *     fallback above undoes, so the shell receives the original bytes.
 *     A command containing an embedded '"' or a trailing '\\' is the one
 *     case this cannot reproduce faithfully -- append_arg's escaping for
 *     those is meaningless to cmd's lexer, which strips only the
 *     outermost quote pair and passes escape backslashes through
 *     literally.  That is a real, narrow gap, documented here rather
 *     than hidden; the alternative (hand-building the raw command line)
 *     needs a raw-cmdline entry point into __spawn that does not exist
 *     and is not this change's to add.
 *
 *     None of this applies on Linux.  __spawn's Linux backend
 *     (__plat_process_spawn, src/process/linux/plat_process.c) hands
 *     argv straight to execve(2) -- there is no intermediate raw command
 *     line for the child to re-lex the way cmd.exe re-lexes the text
 *     after "/C", so argv = { shell, "-c", command, NULL } reaches
 *     sh(1p) as exactly the bytes `command` holds, with no
 *     quoting/escaping layer of any kind in between and no equivalent of
 *     the embedded-quote/trailing-backslash gap above.
 *
 *   - "If a shell could not be executed, the child process shall exit
 *     with a status as if the command interpreter terminated using
 *     exit(127)."  On NT, process creation is atomic -- an invalid or
 *     missing image never produces a process at all, unlike POSIX's
 *     fork()-then-exec() where the child already exists when exec()
 *     discovers the image is bad -- so __spawn() itself fails with
 *     pid < 0 rather than a child later exiting 127.  Linux reaches the
 *     same pid < 0 outcome by a different route: __plat_process_spawn()
 *     there forks and execve()s, but reports a failed execve() back
 *     through a close-on-exec self-pipe before returning to this
 *     caller, so the fork()-then-exec() gap the paragraph above
 *     describes is closed at that layer and __spawn() fails synchronously
 *     here exactly as it does on NT.  That failure is synthesized here
 *     into the (127<<8)-shaped wait status this clause requires
 *     (WIFEXITED true, WEXITSTATUS()==127), the same way a real
 *     fork()+execve() failure is turned into exit(127) by other libcs'
 *     system() implementations.  No errno is preserved for this case:
 *     the clause's contract is a wait status, not -1/errno, so there is
 *     no defined errno to leave behind once the synthesized status takes
 *     that branch.
 */
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include "libc.h"

/* Resolve the shell to run commands through, or 0 (errno set) if none
 * can be found.  See the header comment for why ComSpec, checked with
 * access() ourselves, comes first on NT, and why Linux resolves "sh"
 * through PATH instead of a hard-coded "/bin/sh". */
withtok(heap_allocated)
static char *find_shell(void)
{
#if defined(__linux__)
	return __find_program("sh", 1);
#else
	const char *cs = getenv("ComSpec");
	if (cs && *cs && access(cs, X_OK) == 0) {
		size_t n = strlen(cs) + 1;
		char *r = malloc(n);
		if (r) memcpy(r, cs, n);
		return r;
	}
	return __find_program("cmd.exe", 1);
#endif
}

int system(const char *command)
{
	char *shell = find_shell();
	int status;

	if (!command) {
		int have = shell != 0;
		free(shell);
		return have;
	}

	if (!shell) return -1;   /* errno set by find_shell/__find_program */

	{
		char *argv[4];
		int pid, saved_errno = 0;
		sigset_t chldmask, oldmask;
		void (*old_int)(int);
		void (*old_quit)(int);

		argv[0] = shell;
#if defined(__linux__)
		argv[1] = (char *)"-c";
#else
		argv[1] = (char *)"/c";
#endif
		argv[2] = (char *)command;
		argv[3] = 0;

		old_int = signal(SIGINT, SIG_IGN);
		old_quit = signal(SIGQUIT, SIG_IGN);
		sigemptyset(&chldmask);
		sigaddset(&chldmask, SIGCHLD);
		sigprocmask(SIG_BLOCK, &chldmask, &oldmask);

		pid = __spawn(shell, argv, 0);
		if (pid < 0) {
			/* "as if the command interpreter terminated using
			 * exit(127)" -- see the header comment. */
			status = 127 << 8;
		} else if (waitpid(pid, &status, 0) < 0) {
			saved_errno = errno;
			status = -1;
		}

		sigprocmask(SIG_SETMASK, &oldmask, 0);
		/* Restoration is cleanup after the command status is fixed; a
		 * secondary failure must not overwrite that primary result. */
		(void)signal(SIGQUIT, old_quit);
		(void)signal(SIGINT, old_int);

		if (status == -1) errno = saved_errno;
	}

	free(shell);
	return status;
}
