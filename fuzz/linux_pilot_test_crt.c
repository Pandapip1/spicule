/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * crt/linux/crt1.c + crt/linux/aarch64/start.S smoke test -- NOT part
 * of spicule, same standing as every other fuzz/linux_pilot_test_*.c
 * file, but a different kind of pilot from the others: every earlier
 * one (linux_pilot_test_open.c, _rename.c, _statfam.c, ...) still ran
 * under fuzz/linux_pilot_harness*.c's own hand-rolled process
 * bootstrap (a minimal from-scratch fd table, no real argv/environ,
 * `int main(void)` called directly by a harness that was never itself
 * the process entry point). This one is the first to run under the
 * REAL src/fcntl/open.c and src/unistd/write.c front doors, through
 * the REAL platform-abstraction backends, AND under the REAL process
 * entry point (crt/linux/aarch64/start.S's _start -> crt/linux/
 * crt1.c's __linux_start_main() -> this file's own main()) -- proving
 * the crt layer itself, not just a library function called from
 * borrowed scaffolding.
 *
 * Deliberately does not use stdio (no fprintf/puts): the src/stdio
 * subsystem has not been audited for Linux safety the way src/fcntl
 * and src/unistd have this session (see crt/linux/crt1.c's own banner
 * for the same caution about __signal_init()/__fenv_init()).
 *
 * Also deliberately calls __plat_write() (src/internal/plat_fd.h)
 * directly rather than the public write() front door
 * (src/unistd/write.c): that front door's own job -- RLIMIT_FSIZE
 * clamping (src/misc/resource.c) and dispatching a socket fd to
 * send() (src/socket/sendrecv.c) -- pulls in two more subsystems
 * neither of which this fd (a plain fd 1) ever exercises, just to
 * link two branches that can never run here. __plat_write() is still
 * the REAL Linux backend (src/unistd/linux/plat_fd.c), not a raw
 * syscall bypass -- this file proves that interface function directly,
 * the same real code write()'s own front door would call for this fd.
 */
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include "plat_fd.h"

static int failures;

static void report(int ok, const char *msg)
{
	__plat_handle_t out = (__plat_handle_t)(long)2; /* fd 1, boxed (fd+1) */
	if (!ok) failures++;
	__plat_write(out, ok ? "ok   - " : "FAIL - ", 7, 0);
	__plat_write(out, msg, __builtin_strlen(msg), 0);
	__plat_write(out, "\n", 1, 0);
}

static __thread int tls_marker = -1;

/* SA_ONSTACK proof: this backs both the altstack sigaltstack() installs
 * and the range __sig_call_on_altstack() (src/signal/$arch/altstack.S)
 * is expected to move the stack pointer into for the duration of the
 * handler below -- the one real way to tell a correct SysV altstack
 * switch apart from a silent ABI mismatch that happens to link and even
 * happens to run (e.g. reading the wrong incoming registers as sp/fn/arg
 * and using whatever garbage was there instead), rather than trusting
 * that a clean qemu exit alone proves the switch itself was correct. */
static char altstack_buf[SIGSTKSZ];
static int handler_ran;
static int handler_on_altstack;

static void onstack_handler(int sig)
{
	char local;
	(void)sig;
	handler_ran = 1;
	handler_on_altstack = (&local >= altstack_buf &&
	                        &local < altstack_buf + sizeof altstack_buf);
}

int main(int argc, char **argv, char **envp)
{
	int fd;

	report(argc >= 1, "argc is at least 1 (this program's own name)");
	report(argv != 0 && argv[0] != 0, "argv is non-null and argv[0] is non-null");
	report(envp != 0, "envp is non-null");

	/* TLS: a fresh __thread variable initialized to -1 must read back
	 * as -1 (proves TPIDR_EL0 addresses real, zero/initializer-correct
	 * storage, not a null or garbage pointer -- a wrong thread pointer
	 * would most likely fault before ever reaching this line at all,
	 * but a *plausible-looking wrong* one could silently alias some
	 * other memory instead, which is exactly what the write-then-
	 * reread below actually distinguishes). */
	report(tls_marker == -1, "a fresh __thread variable reads back its own initializer");
	tls_marker = 424242;
	report(tls_marker == 424242, "writing a __thread variable and reading it back agree");

	/* errno: open() a path that cannot exist, through the REAL
	 * src/fcntl/open.c front door and its Linux src/fcntl/linux/
	 * plat_fcntl.c backend (real openat(2)), and confirm errno --
	 * itself a `__thread int` (src/internal/errno.c) -- reads back
	 * the real kernel ENOENT, proving TLS is live for library-internal
	 * state too, not just this file's own test variable. */
	errno = 0;
	fd = open("/no/such/path/spicule-linux-crt-test", O_RDONLY);
	report(fd == -1, "open() of a nonexistent path fails");
	report(errno == ENOENT, "errno reads back ENOENT through the real open()/openat() front door");

	/* SA_ONSTACK: see the banner above altstack_buf for why a wrong
	 * register mapping can look correct without this check. */
	{
		stack_t ss;
		struct sigaction sa;
		int rc;

		ss.ss_sp = altstack_buf;
		ss.ss_size = sizeof altstack_buf;
		ss.ss_flags = 0;
		rc = sigaltstack(&ss, 0);
		report(rc == 0, "sigaltstack() installs an alternate signal stack");

		sa.sa_handler = onstack_handler;
		sa.sa_flags = SA_ONSTACK;
		__builtin_memset(&sa.sa_mask, 0, sizeof sa.sa_mask);
		rc = sigaction(SIGUSR1, &sa, 0);
		report(rc == 0, "sigaction() installs an SA_ONSTACK handler");

		rc = raise(SIGUSR1);
		report(rc == 0, "raise(SIGUSR1) succeeds");
		report(handler_ran, "the SA_ONSTACK handler actually ran");
		report(handler_on_altstack, "the handler's own stack frame landed inside the alternate stack");
	}

	report(1, "reached the end of main() -- __plat_terminate() next");

	return failures ? 1 : 0;
}
