/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The exec family, runnable under Wine (no fork needed): the parent
 * __spawn()s itself in an "--exec-*" role, that child calls execv/execve
 * on itself in an "--argv*" role, and the exec'd image checks what it
 * received.  exec never returns on success and exits with the exec'd
 * program's status, so the parent just inspects the spawned child's exit
 * code.
 *
 * The PATH-searching forms are exercised here too: test_exec_path()
 * calls execvp(), which resolves through __find_program()
 * (src/process/find_program.c) before handing the resolved image to the
 * same __spawn() path execv() uses.
 */
/* wait3()/wait4()/setenv()/clock_gettime() below are all feature-test
 * gated in spicule's own headers (see include/sys/wait.h's own comment on
 * why); test/posix-unistd-exec.c already needs the identical define for
 * the same reason.  Harmless noise under a lenient compiler that never
 * enforced the gate, but a genuine build break under one (clang, here)
 * that treats an implicit declaration as the hard ISO C99 error it is. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/times.h>
#include <time.h>

extern char **environ;
int __spawn(const char *path, char *const argv[], char *const envp[]);

static int fails;
/* Assertion groups this run could not exercise at all; see main(). */
static int unverified;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* Arguments exercising every quoting rule spawn.c's append_arg implements
 * and crt1.c's split_cmdline undoes. */
static const char *const tricky[] = {
	"plain",
	"two words",
	"",
	"say \"hi\"",
	"trailing\\",
	"two\\\\backslashes",
	"\\\"escaped quote",
	"tab\there",
	"c:\\dir with space\\",
	"\"",
	"end\\\\\"",
	0
};

#define RC_ARGV_MISMATCH 7
#define RC_ENV_MISMATCH 8
#define RC_PID_MISMATCH 9
#define RC_EXEC_RETURNED 99
#define RC_OK 0

/* argv[0] values that must survive the trip through spawn.c's command
 * line builder and back out of crt1.c's program-name parser unchanged.
 * The program name is read by different rules from every other argument
 * -- backslashes in it are literal and never escape anything -- so these
 * are the cases that catch it being quoted as if it were an ordinary
 * argument. */
static const char *const argv0_cases[] = {
	"plain",
	"a b\\",             /* a space *and* a trailing backslash */
	"a\\\\b",
	"c:\\dir\\prog.exe",
	"has space",
	"",
	0
};

static char **build_argv(const char *self, const char *role)
{
	static char *v[32];
	int i, n = 0;
	v[n++] = (char *)self;
	v[n++] = (char *)role;
	for (i = 0; tricky[i]; i++) v[n++] = (char *)tricky[i];
	v[n] = 0;
	return v;
}

/* The exec'd image: verify argv (and, for --argv-env, the environment). */
static int argv_child(int argc, char **argv)
{
	int i;
	for (i = 0; tricky[i]; i++) {
		if (i + 2 >= argc || strcmp(argv[i + 2], tricky[i])) {
			printf("child: argv[%d] = \"%s\", wanted \"%s\"\n", i + 2,
			       i + 2 < argc ? argv[i + 2] : "(missing)", tricky[i]);
			return RC_ARGV_MISMATCH;
		}
	}
	if (i + 2 != argc) {
		printf("child: argc %d, wanted %d\n", argc, i + 2);
		return RC_ARGV_MISMATCH;
	}
	if (!strcmp(argv[1], "--argv-env")) {
		const char *v = getenv("SPICULE_TEST_ENV");
		if (!v || strcmp(v, "hello world")) {
			printf("child: SPICULE_TEST_ENV = %s\n", v ? v : "(unset)");
			return RC_ENV_MISMATCH;
		}
		if (getenv("SPICULE_TEST_ABSENT")) return RC_ENV_MISMATCH;
	}
	return 0;
}

/* Spawned with a deliberately odd argv[0]; argv[2] says what it should
 * have come out as. */
static int argv0_child(int argc, char **argv)
{
	if (argc != 3) { printf("child: argc %d, wanted 3\n", argc); return RC_ARGV_MISMATCH; }
	if (strcmp(argv[0], argv[2])) {
		printf("child: argv[0] = \"%s\", wanted \"%s\"\n", argv[0], argv[2]);
		return RC_ARGV_MISMATCH;
	}
	return RC_OK;
}

/* The entries test_empty_env_entry() puts in front of the inherited
 * environment.  The empty one is second, so with the truncating bug
 * everything below it -- including whatever the child needs to start at
 * all -- disappears.  The last two are the pair that has to be told
 * apart: an entry with no '=' at all, which Windows will not accept in
 * an environment block and which spawn.c therefore drops, and one that
 * merely begins with '=', which is Windows' own per-drive
 * current-directory shape and must survive. */
#define ENV_NOEQ_ENTRY "SPICULE_EMPTY_NOEQ"
#define ENV_DRIVE_ENTRY "=Z:=Z:\\spicule-test"
static const char *const envblock_probes[] = {
	"SPICULE_EMPTY_A=1",
	"",                     /* used to terminate the block */
	"SPICULE_EMPTY_B=2",
	ENV_NOEQ_ENTRY,         /* no '=' at all: not representable, dropped */
	"SPICULE_EMPTY_C=3",
	ENV_DRIVE_ENTRY,        /* '=' first, but a real name ("=Z:"): kept */
	0
};

/* Spawned with an envp that contains an empty entry: everything after it
 * must still have arrived. */
static int envblock_child(void)
{
	static const char *const want[][2] = {
		{ "SPICULE_EMPTY_A", "1" },
		{ "SPICULE_EMPTY_B", "2" },
		{ "SPICULE_EMPTY_C", "3" },
		{ 0, 0 }
	};
	int i;
	for (i = 0; want[i][0]; i++) {
		const char *v = getenv(want[i][0]);
		if (!v || strcmp(v, want[i][1])) {
			printf("child: %s = %s, wanted %s\n", want[i][0], v ? v : "(unset)", want[i][1]);
			return RC_ENV_MISMATCH;
		}
	}
	/* An entry with no '=' cannot be part of a Windows environment
	 * block, so it is dropped on the way in: it must name no variable,
	 * and it must not be sitting in environ either. */
	if (getenv(ENV_NOEQ_ENTRY)) {
		printf("child: %s names a variable\n", ENV_NOEQ_ENTRY);
		return RC_ENV_MISMATCH;
	}
	for (i = 0; environ[i]; i++)
		if (!strcmp(environ[i], ENV_NOEQ_ENTRY)) {
			printf("child: \"%s\" was passed through\n", ENV_NOEQ_ENTRY);
			return RC_ENV_MISMATCH;
		}
	/* An entry whose name is empty by a naive reading, because it starts
	 * with '=', is a real Windows entry and must not have been mistaken
	 * for either of the malformed shapes. */
	for (i = 0; environ[i]; i++)
		if (!strcmp(environ[i], ENV_DRIVE_ENTRY)) break;
	if (!environ[i]) {
		printf("child: \"%s\" did not survive the trip\n", ENV_DRIVE_ENTRY);
		return RC_ENV_MISMATCH;
	}
	return RC_OK;
}

/* The exec'd image for the l-forms.  execl()/execle()/execlp() take a
 * literal, fixed argument list rather than a built array, so they get
 * their own small fixed expectation instead of tricky[].
 *
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/exec.html
 * DESCRIPTION: the l-forms' "arguments ... are pointers to
 * null-terminated character strings ... The list of argument strings is
 * terminated by a null pointer." */
#define ARGVL_1 "a"
#define ARGVL_2 "b c"

static int argvl_child(int argc, char **argv)
{
	if (argc != 4) { printf("child: argc %d, wanted 4\n", argc); return RC_ARGV_MISMATCH; }
	if (strcmp(argv[2], ARGVL_1) || strcmp(argv[3], ARGVL_2)) {
		printf("child: argv = \"%s\" \"%s\"\n", argv[2], argv[3]);
		return RC_ARGV_MISMATCH;
	}
	if (!strcmp(argv[1], "--argvl-env")) {
		const char *v = getenv("SPICULE_TEST_ENV");
		if (!v || strcmp(v, "hello world")) {
			printf("child: SPICULE_TEST_ENV = %s\n", v ? v : "(unset)");
			return RC_ENV_MISMATCH;
		}
		/* execle()'s envp replaces the environment outright */
		if (getenv("SPICULE_TEST_ABSENT")) return RC_ENV_MISMATCH;
	}
	return RC_OK;
}

/* Markers for test_exec_drops_exit_handlers(); see there. */
#define STDIO_MARKER   "tmp-exec-stdio-marker"
#define CONTROL_MARKER "tmp-exec-control-marker"
#define RC_ATEXIT_RAN 66

/* Registered by the --exec-atexit role, which must never reach it.  It
 * reports through the exit status rather than through a file because the
 * status is the one channel that crosses a spawn in every environment
 * this test runs in. */
static void atexit_must_not_run(void)
{
	_exit(RC_ATEXIT_RAN);
}

/* The intermediate child: exec self in an --argv role. */
static int exec_child(const char *self, const char *role)
{
	if (!strcmp(role, "--exec-v")) {
		execv(self, build_argv(self, "--argv"));
	} else if (!strcmp(role, "--exec-vp")) {
		/* self contains a slash or is an absolute path: used as-is */
		execvp(self, build_argv(self, "--argv"));
	} else if (!strcmp(role, "--exec-ve")) {
		char *envp[3];
		char sysroot[512];
		const char *sr = getenv("SystemRoot");
		envp[0] = (char *)"SPICULE_TEST_ENV=hello world";
		if (sr) { snprintf(sysroot, sizeof sysroot, "SystemRoot=%s", sr); envp[1] = sysroot; }
		else envp[1] = (char *)"SystemRoot=C:\\Windows";
		envp[2] = 0;
		setenv("SPICULE_TEST_ABSENT", "1", 1);   /* must not leak past an explicit envp */
		execve(self, build_argv(self, "--argv-env"), envp);
	} else if (!strcmp(role, "--exec-exit")) {
		char *v[4];
		v[0] = (char *)self; v[1] = (char *)"--exit"; v[2] = (char *)"200"; v[3] = 0;
		execv(self, v);
	} else if (!strcmp(role, "--exec-missing")) {
		errno = 0;
		if (execv("./no-such-program-here.exe", build_argv(self, "--argv")) != -1) return 1;
		return errno == ENOENT ? 0 : 2;
	} else if (!strcmp(role, "--exec-vpe")) {
		/* execvpe(3) (glibc, not POSIX -- execvp()'s explicit-envp
		 * sibling, the same relationship execve() has to execv()):
		 * self contains a slash or is an absolute path, so this is
		 * used as-is with no PATH search, same as --exec-vp above,
		 * but through execvpe()'s own entry point rather than
		 * through execvp() (which only reaches it indirectly). */
		char *envp[3];
		char sysroot[512];
		const char *sr = getenv("SystemRoot");
		envp[0] = (char *)"SPICULE_TEST_ENV=hello world";
		if (sr) { snprintf(sysroot, sizeof sysroot, "SystemRoot=%s", sr); envp[1] = sysroot; }
		else envp[1] = (char *)"SystemRoot=C:\\Windows";
		envp[2] = 0;
		setenv("SPICULE_TEST_ABSENT", "1", 1);   /* must not leak past an explicit envp */
		execvpe(self, build_argv(self, "--argv-env"), envp);
	} else if (!strcmp(role, "--exec-l")) {
		execl(self, self, "--argvl", ARGVL_1, ARGVL_2, (char *)0);
	} else if (!strcmp(role, "--exec-le")) {
		char *envp[3];
		char sysroot[512];
		const char *sr = getenv("SystemRoot");
		envp[0] = (char *)"SPICULE_TEST_ENV=hello world";
		if (sr) { snprintf(sysroot, sizeof sysroot, "SystemRoot=%s", sr); envp[1] = sysroot; }
		else envp[1] = (char *)"SystemRoot=C:\\Windows";
		envp[2] = 0;
		setenv("SPICULE_TEST_ABSENT", "1", 1);   /* must not leak past an explicit envp */
		execle(self, self, "--argvl-env", ARGVL_1, ARGVL_2, (char *)0, envp);
	} else if (!strcmp(role, "--exec-lp")) {
		/* self contains a slash or is an absolute path: used as-is,
		 * no PATH search -- exec.html only searches "when the file
		 * argument lacks a slash character". */
		execlp(self, self, "--argvl", ARGVL_1, ARGVL_2, (char *)0);
	} else if (!strcmp(role, "--exec-l-exit")) {
		execl(self, self, "--exit", "201", (char *)0);
	} else if (!strcmp(role, "--exec-l-missing")) {
		errno = 0;
		if (execl("./no-such-program-here.exe", "x", (char *)0) != -1) return 1;
		return errno == ENOENT ? 0 : 2;
	} else if (!strcmp(role, "--exec-lp-missing")) {
		errno = 0;
		if (execlp("no-such-program-on-path-xyz", "x", (char *)0) != -1) return 1;
		return errno == ENOENT ? 0 : 2;
	} else if (!strcmp(role, "--exec-f")) {
		/* fexecve.html (folded into exec.html): "the file to be
		 * executed is determined by the file descriptor fd". */
		int fd = open(self, O_RDONLY);
		if (fd < 0) return 3;
		fexecve(fd, build_argv(self, "--argv"), environ);
	} else if (!strcmp(role, "--exec-atexit")) {
		/* Register an exit handler and leave a stream dirty, then
		 * exec.  Neither may survive into the exec'd program's
		 * lifetime; see test_exec_drops_exit_handlers(). */
		FILE *f;
		int fd = open(CONTROL_MARKER, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd < 0) return 4;
		if (write(fd, "1", 1) != 1) return 4;
		if (close(fd)) return 4;
		f = fopen(STDIO_MARKER, "w");
		if (!f) return 4;
		fputs("buffered", f);           /* deliberately not flushed */
		if (atexit(atexit_must_not_run)) return 4;
		execl(self, self, "--exit", "0", (char *)0);
#if defined(__linux__) && !defined(_SPICULE_NATIVE_BUILD)
	} else if (!strcmp(role, "--exec-pid")) {
		/* The real-exec bar, per src/process/exec.c's own banner:
		 * on Linux execve() must replace THIS OS process's image in
		 * place, not fork+wait a new one to stand in for it -- so
		 * this process's own pid, captured right here before the
		 * call, must be the exact pid still running once "--report-
		 * pid" below checks it, not merely a process that happens to
		 * report the same *output*.  A grandchild produced by a
		 * disguised fork+emulate would still print the right
		 * argv/exit status; it would not carry this pid. NT is not
		 * tested here at all: its own exec() correctly does NOT
		 * preserve pid (documented, deliberate -- see that banner),
		 * so this role does not exist on that build. */
		char pidbuf[32];
		snprintf(pidbuf, sizeof pidbuf, "%ld", (long)getpid());
		execl(self, self, "--report-pid", pidbuf, (char *)0);
#endif
	} else if (!strcmp(role, "--exec-f-badfd")) {
		/* [EBADF] "The fd argument is not a valid file descriptor
		 * open for executing." */
		errno = 0;
		if (fexecve(4096, build_argv(self, "--argv"), environ) != -1) return 1;
		return errno == EBADF ? 0 : 2;
	}
	printf("child: exec returned, errno %d\n", errno);
	return RC_EXEC_RETURNED;
}

static int run_role(const char *self, const char *role)
{
	char *argv[3];
	int pid, status = -1;
	argv[0] = (char *)self;
	argv[1] = (char *)role;
	argv[2] = 0;
	fflush(stdout);
	pid = __spawn(self, argv, environ);
	CHECK(pid > 0);
	if (pid <= 0) return -1;
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status));
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int spawn_status(const char *self, char *const av[], char *const ev[])
{
	int pid, status = -1;
	fflush(stdout);
	pid = __spawn(self, av, ev);
	if (pid <= 0) return -1;
	if (waitpid(pid, &status, 0) != pid) return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* A command line longer than a UNICODE_STRING can describe must be
 * refused, not silently cut down to whatever its length wrapped to. */
static void test_cmdline_limit(const char *self)
{
	static const size_t sizes[] = { 1000, 16000, 32000 };
	char *big, lenbuf[32];
	char *av[5];
	size_t i;

	/* Sizes that fit still round trip exactly. */
	for (i = 0; i < sizeof sizes / sizeof *sizes; i++) {
		big = malloc(sizes[i] + 1);
		CHECK(big != 0);
		if (!big) return;
		memset(big, 'x', sizes[i]);
		big[sizes[i]] = 0;
		snprintf(lenbuf, sizeof lenbuf, "%lu", (unsigned long)sizes[i]);
		av[0] = (char *)self; av[1] = (char *)"--arglen";
		av[2] = lenbuf; av[3] = big; av[4] = 0;
		CHECK(spawn_status(self, av, environ) == RC_OK);
		free(big);
	}

	/* Past the limit: a clean E2BIG, and no process started. */
	big = malloc(40001);
	CHECK(big != 0);
	if (!big) return;
	memset(big, 'x', 40000);
	big[40000] = 0;
	snprintf(lenbuf, sizeof lenbuf, "40000");
	av[0] = (char *)self; av[1] = (char *)"--arglen";
	av[2] = lenbuf; av[3] = big; av[4] = 0;
	errno = 0;
	CHECK(__spawn(self, av, environ) == -1);
	CHECK(errno == E2BIG);
	errno = 0;
	CHECK(execv(self, av) == -1);
	CHECK(errno == E2BIG);
	free(big);
}

/* Spawn self in the --envblock role with the given environment and
 * describe what happened in `out`.  Returns the child's exit code, or -1
 * if there was never a child to ask.
 *
 * The description matters more than it looks: "not RC_OK" covers a spawn
 * that was refused, a wait that failed, a child that died before main,
 * and a child that ran and disagreed, and those want different fixes.  A
 * child killed before main carries the low byte of an NT status
 * (0xc0000142 STATUS_DLL_INIT_FAILED -> 0x42, STATUS_DLL_NOT_FOUND ->
 * 0x35), which is distinguishable from this test's own small RC_* codes. */
static int envblock_try(const char *self, char *const ev[], char *out, size_t outlen)
{
	char *av[3];
	int pid, status = -1;

	av[0] = (char *)self; av[1] = (char *)"--envblock"; av[2] = 0;
	fflush(stdout);
	errno = 0;
	pid = __spawn(self, av, ev);
	if (pid <= 0) {
		snprintf(out, outlen, "__spawn refused it, errno %d", errno);
		return -1;
	}
	if (waitpid(pid, &status, 0) != pid) {
		snprintf(out, outlen, "waitpid failed, errno %d", errno);
		return -1;
	}
	if (!WIFEXITED(status)) {
		snprintf(out, outlen, "child did not exit normally, status 0x%08x", (unsigned)status);
		return -1;
	}
	snprintf(out, outlen, "child exited %d (0x%02x)",
	         WEXITSTATUS(status), (unsigned)WEXITSTATUS(status));
	return WEXITSTATUS(status);
}

/* Run only when the real spawn failed.  Spawns once with no probes at
 * all -- which exonerates or implicates everything that is not the
 * environment, since argv[0], the command line and the current directory
 * are identical -- and then once per probe with that one probe left out.
 * The run that behaves differently from the rest names the entry the
 * environment block was rejected for, instead of leaving a bare errno to
 * guess from. */
static void envblock_bisect(const char *self, char **ev, int nprobe, int nenv)
{
	char desc[128];
	char **var = malloc((size_t)(nprobe + nenv + 1) * sizeof *var);
	int skip, i, n;

	if (!var) return;
	for (skip = -1; skip < nprobe; skip++) {
		n = 0;
		for (i = 0; i < nprobe; i++) {
			if (skip == -1 || i == skip) continue;
			var[n++] = ev[i];
		}
		for (i = 0; i < nenv; i++) var[n++] = ev[nprobe + i];
		var[n] = 0;
		envblock_try(self, var, desc, sizeof desc);
		printf("  env-block without %s: %s\n",
		       skip == -1 ? "any probe" :
		       ev[skip][0] ? ev[skip] : "the empty entry",
		       desc);
	}
	free(var);
}

/* An empty envp entry must not cut the environment block short.
 *
 * The probes go in *front* of the whole inherited environment rather
 * than replacing it.  An earlier version of this test handed the child
 * six entries -- the probes and a hand-built SystemRoot -- and nothing
 * else.  That is enough under Wine and was never enough on real NT, and
 * it also hid which of the two problems here was which, so the real
 * environment is passed through: the child gets PATH, SystemRoot,
 * SystemDrive, windir, TEMP and the per-drive "=C:=C:\dir" entries,
 * whatever it actually needs to reach main.
 *
 * The probes still prove the point.  The empty entry is the *second*
 * thing in the block, so if it truncated the block again, everything
 * after it -- all three SPICULE_EMPTY_* variables and the whole inherited
 * environment -- would be gone. */
static void test_empty_env_entry(const char *self)
{
	char desc[128];
	char **ev;
	int i, n = 0, nenv = 0, nprobe = 0;

	for (nprobe = 0; envblock_probes[nprobe]; nprobe++) ;
	for (nenv = 0; environ[nenv]; nenv++) ;
	ev = malloc((size_t)(nprobe + nenv + 1) * sizeof *ev);
	CHECK(ev != 0);
	if (!ev) return;
	for (i = 0; i < nprobe; i++) ev[n++] = (char *)envblock_probes[i];
	for (i = 0; i < nenv; i++) ev[n++] = environ[i];
	ev[n] = 0;

	if (envblock_try(self, ev, desc, sizeof desc) != RC_OK) {
		fails++;
		printf("FAIL %s:%d: env block with an empty entry: %s\n", __FILE__, __LINE__, desc);
		envblock_bisect(self, ev, nprobe, nenv);
	}
	free(ev);
}

/* A failed exec must leave the process image alone -- including the
 * close-on-exec descriptors, which stay the caller's until exec
 * succeeds. */
static void test_failed_exec_keeps_cloexec(const char *self)
{
	char buf[4];
	char *av[2];
	int fd = open(self, O_RDONLY | O_CLOEXEC);

	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(read(fd, buf, 2) == 2);
	CHECK(lseek(fd, 0, SEEK_SET) == 0);

	av[0] = (char *)"./no-such-program-xyz.exe"; av[1] = 0;
	errno = 0;
	CHECK(execv("./no-such-program-xyz.exe", av) == -1);
	CHECK(errno == ENOENT);

	errno = 0;
	CHECK(read(fd, buf, 2) == 2);   /* EBADF before the fix */
	CHECK(errno != EBADF);
	close(fd);
}

/* argv[0] is quoted by the program-name rules, so it comes back byte for
 * byte; the values those rules cannot express are refused outright. */
static void test_argv0_roundtrip(const char *self)
{
	char *av[4];
	int i;

	for (i = 0; argv0_cases[i]; i++) {
		av[0] = (char *)argv0_cases[i];
		av[1] = (char *)"--argv0";
		av[2] = (char *)argv0_cases[i];
		av[3] = 0;
		if (spawn_status(self, av, environ) != RC_OK) {
			fails++;
			printf("FAIL %s:%d: argv[0] \"%s\" did not round trip\n",
			       __FILE__, __LINE__, argv0_cases[i]);
		}
	}

	/* A quote in the program name has no encoding: fail, do not mangle. */
	av[0] = (char *)"a\"b"; av[1] = (char *)"--argv0"; av[2] = av[0]; av[3] = 0;
	errno = 0;
	CHECK(__spawn(self, av, environ) == -1);
	CHECK(errno == EINVAL);
}

/* wait3()/wait4(): same reaping as waitpid(), but with a struct rusage
 * for the child, filled from its NT process times before its handle is
 * closed -- runnable here (no fork()) via the same __spawn()+"--exit"
 * shape run_role() uses. */
/* A whole struct timeval as microseconds, so a "did not go backwards"
 * check is one comparison on the real quantity rather than two
 * independent ones on its halves -- tv_usec on its own wraps at each
 * whole second, which is how the previous form here came to be a
 * disjunction that could not fail. */
static long long timeval_usec(const struct timeval *tv)
{
	return (long long)tv->tv_sec * 1000000 + (long long)tv->tv_usec;
}

/* ---- making the child-CPU-time floor deterministic -----------------
 *
 * The floor asserted below ("the RUSAGE_CHILDREN total is genuinely
 * non-zero, not merely non-decreasing") is a threshold, and NT reports
 * process CPU time only in whole clock-tick quanta -- 15.625ms on x64.
 * It does not accumulate that time, it *samples* it: the clock ISR
 * charges one tick to whichever thread is on-CPU at the interrupt
 * (ReactOS ntoskrnl/ke/time.c, KeUpdateRunTime(): `Thread->UserTime++`
 * / `Thread->KernelTime++`), and ProcessTimes reports the count scaled
 * by KeMaximumIncrement.  So a child that really used 10ms of CPU is
 * charged either one quantum or *zero*, depending on nothing but
 * whether it happened to span an interrupt.
 *
 * test/posix-grp.c's identical floor flaked on exactly that: a
 * real-Windows x86_64 runner charged its child zero, while the slower
 * i386 and kernel32 legs of the same run charged it one and passed.
 * This file's version was written with the same hole and had merely
 * not been unlucky yet -- and its own comment concluded
 * the margin "cannot be widened, only made visible", because the
 * quantity was whatever the previously-reaped `--exit 7` children
 * happened to be charged, which is not under this test's control.
 *
 * It can be widened, by making the quantity be under this test's
 * control: reap a child that does not exit until NT has *confirmed*,
 * against the child's own times(), that it was charged the CPU being
 * asserted.  Then the floor holds by construction on a machine of any
 * speed, rather than holding because this one was slow enough today.
 *
 * Both halves are confirmed, not just the system half, so the user
 * floor below stops being unassertable too.  Each chunk of the loop
 * does both kinds of work: a run of lseek()+write() pairs on a real
 * file, which cannot be served without entering the kernel, and a run
 * of floating-point adds whose result is stored to a volatile object at
 * file scope so no conforming compiler may delete it.  A burn that got
 * optimised away would be the same vacuous pass in a new hat.
 *
 * Bounds: two, because they say different things.  CPU time accrues
 * only while the process is on a CPU, so under contention (gate.sh runs
 * stages concurrently; hosted runners are oversubscribed) the same
 * confirmed ticks take arbitrarily longer in wall-clock terms.  A stall
 * bound catches a counter that is not advancing at all -- 30s of
 * continuous work without a single 15.625ms tick is under a 0.06% CPU
 * share, which no machine load explains -- and a much looser total
 * bound catches one that advances pathologically slowly, saying so in
 * terms of machine load rather than of times().
 *
 * The system half is required only on _WIN32.  fuzz/ntstubs.c reports
 * the whole of CLOCK_PROCESS_CPUTIME_ID as UserTime and leaves
 * KernelTime at 0 (fuzz/ntstubs.c, `case ProcessTimes:`), so natively
 * tms_stime provably never advances and requiring it would spin to the
 * bound for a reason that has nothing to do with this library. */
#define BURN_UTICKS          20
#define BURN_STICKS          5
#define BURN_STALL_LIMIT_SEC 30
#define BURN_WALL_LIMIT_SEC  90
#define BURN_SCRATCH         "t-exec-burn.tmp"

static volatile double burn_sink;

/* 0 on success; -1 having printed which half of the burn failed and
 * why.  Distinguishing that from the parent's assertions is the whole
 * point: "the child was never charged the CPU" and "the parent did not
 * accumulate CPU the child was charged" are different bugs with
 * different fixes, and a fixed-size burn cannot tell them apart. */
static int burn_child_cpu(void)
{
	struct timespec t0, last, now;
	struct tms t;
	clock_t u0, s0;
	long gotu = 0, gots = 0, i;
	volatile double x = 0;
	int fd, want_s;
	char b = 'x';

#ifdef _WIN32
	want_s = BURN_STICKS;
#else
	want_s = 0;
#endif

	fd = open(BURN_SCRATCH, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (fd < 0) {
		printf("exec --burn-cpu: cannot create %s (errno %d); the "
		       "system-time half of the burn needs a real file to "
		       "write to\n", BURN_SCRATCH, errno);
		return -1;
	}
	if (clock_gettime(CLOCK_MONOTONIC, &t0) < 0) goto fail;
	last = t0;
	if (times(&t) == (clock_t)-1) goto fail;
	u0 = t.tms_utime;
	s0 = t.tms_stime;

	for (;;) {
		/* Kernel-mode work: each pair is two unavoidable syscalls, and
		 * the lseek keeps the file one byte long rather than letting
		 * it grow without bound. */
		for (i = 0; i < 500; i++) {
			if (lseek(fd, 0, SEEK_SET) == (off_t)-1) goto fail;
			if (write(fd, &b, 1) != 1) goto fail;
		}
		/* User-mode work. */
		for (i = 0; i < 2000000L; i++) x += (double)i;
		burn_sink = x;

		if (times(&t) == (clock_t)-1) goto fail;
		if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) goto fail;
		if ((long)(t.tms_utime - u0) > gotu) { gotu = (long)(t.tms_utime - u0); last = now; }
		if ((long)(t.tms_stime - s0) > gots) { gots = (long)(t.tms_stime - s0); last = now; }
		if (gotu >= BURN_UTICKS && gots >= want_s) {
			close(fd);
			unlink(BURN_SCRATCH);
			return 0;
		}
		if (now.tv_sec - last.tv_sec > BURN_STALL_LIMIT_SEC) {
			printf("exec --burn-cpu: neither tms_utime nor tms_stime "
			       "advanced in %d wall seconds of continuous work "
			       "(%ld/%ld user, %ld/%ld system ticks). That is under "
			       "a 0.06%% share of one CPU, which no machine load "
			       "explains -- the counters are not being charged\n",
			       BURN_STALL_LIMIT_SEC, gotu, (long)BURN_UTICKS,
			       gots, (long)want_s);
			goto fail;
		}
		if (now.tv_sec - t0.tv_sec > BURN_WALL_LIMIT_SEC) {
			printf("exec --burn-cpu: only %ld/%ld user and %ld/%ld "
			       "system ticks in %d wall seconds. The counters are "
			       "advancing, so this process is getting very little "
			       "CPU -- suspect contention on this machine "
			       "(parallel test stages, an oversubscribed CI runner) "
			       "before suspecting times()\n",
			       gotu, (long)BURN_UTICKS, gots, (long)want_s,
			       BURN_WALL_LIMIT_SEC);
			goto fail;
		}
	}
fail:
	close(fd);
	unlink(BURN_SCRATCH);
	return -1;
}

static void test_wait_rusage(const char *self)
{
	char *argv[4];
	struct rusage ru_before, ru_after, ru_child;
	pid_t pid, r;
	int status;

	memset(&ru_before, 0, sizeof ru_before);
	CHECK(getrusage(RUSAGE_CHILDREN, &ru_before) == 0);

	argv[0] = (char *)self; argv[1] = (char *)"--exit"; argv[2] = (char *)"7"; argv[3] = 0;
	fflush(stdout);
	pid = __spawn(self, argv, environ);
	CHECK(pid > 0);
	status = -1;
	memset(&ru_child, 0xff, sizeof ru_child);
	r = wait4(pid, &status, 0, &ru_child);
	CHECK(r == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 7);
	CHECK(ru_child.ru_utime.tv_sec >= 0 && ru_child.ru_stime.tv_sec >= 0);

	/* getrusage.html DESCRIPTION: RUSAGE_CHILDREN "returns information
	 * about resources utilized by the terminated and waited-for
	 * children of the current process" -- a running total, so it can
	 * only ever grow across a reap, never shrink.
	 *
	 * Two things make that a real check rather than a tautology.
	 * First, the comparison is on the whole timeval (seconds folded
	 * into microseconds): the previous form compared tv_sec and
	 * tv_usec independently and OR'd four clauses together, so
	 * `ru_after.ru_utime.tv_usec >= ru_before.ru_utime.tv_usec` alone
	 * satisfied it -- and with both structs identical, which is what
	 * every field of this total actually is under stock Wine (measured:
	 * NtQueryInformationProcess(ProcessTimes) on an exited child
	 * reports KernelTime == UserTime == 0), 0 >= 0 passed whether or
	 * not getrusage() had done anything at all.  Second, ru_after is
	 * poisoned before the call, so a getrusage() that returns 0 without
	 * writing the struct leaves -1s that are below any legitimate
	 * `before` and the comparison fails.
	 *
	 * What this still cannot distinguish, on a platform that reports
	 * zero child CPU time, is "accumulated correctly" from "accumulated
	 * nothing" -- both totals are legitimately 0 there.  The
	 * windows-test legs are the oracle for that half. */
	memset(&ru_after, 0xff, sizeof ru_after);
	CHECK(getrusage(RUSAGE_CHILDREN, &ru_after) == 0);
	CHECK(timeval_usec(&ru_after.ru_utime) >= timeval_usec(&ru_before.ru_utime));
	CHECK(timeval_usec(&ru_after.ru_stime) >= timeval_usec(&ru_before.ru_stime));
	/* And the total is genuinely non-zero, not merely non-decreasing:
	 * a monotonicity check alone is satisfied by an accumulator that is
	 * never written.
	 *
	 * This used to rest on "every child reaped by now was a whole
	 * process creation, so the system half of the total cannot be zero",
	 * with a measurement under stock Wine standing in for a guarantee.
	 * It is not a guarantee -- see burn_child_cpu()'s banner for why a
	 * child that really used CPU can still be charged none of it -- so
	 * the quantity is made this test's own rather than inherited from
	 * whatever the `--exit 7` children happened to cost.  The child
	 * reaped just below does not exit 0 until NT has confirmed, against
	 * the child's own times(), that it was charged the CPU being
	 * asserted here, and its exit-3 protocol keeps "the child was never
	 * charged" from being misread as "the parent failed to accumulate".
	 *
	 * Not held in the native asan build, for the reason test/posix-grp.c
	 * spells out at length: fuzz/ntstubs.c's ProcessTimes returns
	 * STATUS_NOT_IMPLEMENTED for a child handle, so there the
	 * accumulator is legitimately zero. */
	argv[0] = (char *)self; argv[1] = (char *)"--burn-cpu"; argv[2] = 0;
	fflush(stdout);
	pid = __spawn(self, argv, environ);
	CHECK(pid > 0);
	if (pid <= 0) return;
	status = -1;
	memset(&ru_child, 0xff, sizeof ru_child);
	CHECK(wait4(pid, &status, 0, &ru_child) == pid);
	CHECK(WIFEXITED(status));
	if (WIFEXITED(status) && WEXITSTATUS(status) == 3) {
		/* Counted as a failure and named, rather than skipped: the
		 * assertions below would otherwise be reporting on the burn
		 * and not on the accumulator they name. */
		fails++;
		printf("FAIL %s:%d: --burn-cpu never accumulated its own CPU "
		       "time; the RUSAGE_CHILDREN floors below cannot be "
		       "evaluated\n", __FILE__, __LINE__);
		return;
	}
	CHECK(WEXITSTATUS(status) == 0);

	memset(&ru_after, 0xff, sizeof ru_after);
	CHECK(getrusage(RUSAGE_CHILDREN, &ru_after) == 0);

#ifdef _WIN32
	/* Does this platform report a *child's* process times at all?
	 *
	 * Asking costs nothing extra, because the child just reaped has
	 * already confirmed, against its own times(), that it was charged
	 * at least BURN_UTICKS of user time before exiting.  wait4()'s
	 * struct rusage is documented as that one child's usage, so on a
	 * platform that answers the question at all it cannot come back
	 * below the floor the child itself watched land.  If it does, the
	 * platform is reporting something other than this child, and every
	 * assertion below would be reporting on that substitution rather
	 * than on src/process/wait.c's accumulator.
	 *
	 * That is not hypothetical.  Wine's NtQueryInformationProcess()
	 * ignores the handle for this info class and returns the *calling*
	 * process's times, carrying its own FIXME saying so
	 * (dlls/ntdll/unix/process.c, `case ProcessTimes:` -- "FIXME:
	 * user/kernel times only work for current process"; it fills
	 * UserTime/KernelTime from the host times() and uses the handle
	 * only for CreateTime/ExitTime).  So under Wine this whole group
	 * reads the parent's own CPU, and the `ru_stime > 0` assertion
	 * that used to stand here was passing on exec.exe's own syscall
	 * time: the "measured under stock apt Wine: 0.17s by this point"
	 * that justified it was the parent's number, not any child's.
	 *
	 * Detected by measuring rather than by asking which platform this
	 * is, so it needs no version test and cannot go stale when Wine
	 * fixes it.  rc=77 (tools/run-tests.py: UNVERIFIED) rather than a
	 * silent skip -- a run that could not check the clause must not
	 * read like one that did. */
	{
		long tck = sysconf(_SC_CLK_TCK);
		long long floor_us = tck > 0 ? (long long)BURN_UTICKS * 1000000 / tck : 0;

		if (timeval_usec(&ru_child.ru_utime) < floor_us) {
			printf("SKIP exec RUSAGE_CHILDREN CPU-time floors: this "
			       "platform does not report a child's process times. "
			       "The child confirmed >= %d user ticks (>= %lldus) "
			       "against its own times() and exited 0, yet wait4() "
			       "reports ru_utime=%lldus ru_stime=%lldus for it. "
			       "Wine substitutes the calling process's times here "
			       "(dlls/ntdll/unix/process.c, case ProcessTimes, "
			       "\"FIXME: user/kernel times only work for current "
			       "process\"); the real-Windows legs are the oracle "
			       "for this clause\n",
			       BURN_UTICKS, floor_us,
			       timeval_usec(&ru_child.ru_utime),
			       timeval_usec(&ru_child.ru_stime));
			unverified++;
			return;
		}
	}

	CHECK(timeval_usec(&ru_after.ru_stime) > 0);
	CHECK(timeval_usec(&ru_after.ru_utime) > 0);
	printf("note: RUSAGE_CHILDREN total after the confirmed-burn child: "
	       "ru_stime=%lldus ru_utime=%lldus; that child alone was charged "
	       "ru_utime=%lldus ru_stime=%lldus, having confirmed >= %d user "
	       "and >= %d system ticks against its own times() (NT accounts "
	       "CPU time in ~15625us quanta)\n",
	       timeval_usec(&ru_after.ru_stime), timeval_usec(&ru_after.ru_utime),
	       timeval_usec(&ru_child.ru_utime), timeval_usec(&ru_child.ru_stime),
	       BURN_UTICKS, BURN_STICKS);
#else
	printf("note: RUSAGE_CHILDREN total not held to > 0 natively "
	       "(fuzz/ntstubs.c reports no child process times)\n");
#endif

	/* wait3() is the (-1, ...) shape of the same call; ru == NULL is
	 * also valid, like waitpid().  argv is rebuilt rather than reused:
	 * the confirmed-burn spawn above overwrote it, and a stale argv
	 * would quietly turn this into a second --burn-cpu run, whose exit
	 * status is 0 and not the 7 asserted below. */
	argv[0] = (char *)self; argv[1] = (char *)"--exit"; argv[2] = (char *)"7"; argv[3] = 0;
	fflush(stdout);
	pid = __spawn(self, argv, environ);
	CHECK(pid > 0);
	status = -1;
	r = wait3(&status, 0, 0);
	CHECK(r == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 7);
}

/* exec.html DESCRIPTION: "After a successful call to any of the exec
 * functions, any functions previously registered by the atexit(),
 * at_quick_exit(), or pthread_atfork() functions are no longer
 * registered."
 *
 * On NT there is no image replacement, so execve() stands in for the
 * exec'd program: it spawns it, waits, and ends with its status.  That
 * makes this clause a real hazard rather than a tautology -- the
 * caller's atexit handlers are still sitting in the address space when
 * the exec'd program finishes, and ending with exit() runs them.
 *
 * What that cost, concretely: GCC 4.6.4's driver registers
 * delete_temp_files() with atexit() and then fork()s + execv()s cc1.
 * Every `gcc -c` deleted its own intermediate .s the moment cc1 wrote
 * it, and the "as" step that came next reported the file missing.
 *
 * The stdio half is glibc's rule, not the standard's -- the standard is
 * silent on buffered data across exec.  Measured on glibc 2.39: a
 * printf() with no newline followed by execl() prints nothing, because
 * the buffer dies with the image.  So a stream left dirty here must
 * still be empty on disk afterwards. */
static void test_exec_drops_exit_handlers(const char *self)
{
	struct stat st;
	int rc;

	remove(CONTROL_MARKER);
	remove(STDIO_MARKER);

	rc = run_role(self, "--exec-atexit");
	CHECK(rc == 0);
	if (rc == RC_ATEXIT_RAN)
		printf("FAIL: exec ran the caller's atexit handler\n");
	if (rc != 0) { remove(CONTROL_MARKER); remove(STDIO_MARKER); return; }

	/* Positive control: the role creates CONTROL_MARKER with an
	 * ordinary open/write/close before it execs.  If that is not
	 * visible here, files do not cross a spawn in this environment
	 * (the native sanitizer build backs NtCreateFile with an in-process
	 * simulated volume, fuzz/ntstubs.c) and the stdio half below cannot
	 * be measured -- absence of STDIO_MARKER would prove nothing. */
	if (stat(CONTROL_MARKER, &st) != 0) {
		printf("SKIP exec dirty-stream-across-exec: a file the exec'ing "
		       "child created before exec is not visible to its parent "
		       "here, so an unflushed stream cannot be told apart from "
		       "a file that never crossed the process boundary. The "
		       "atexit half above was still measured, through the exit "
		       "status\n");
		unverified++;
		return;
	}

	CHECK(stat(STDIO_MARKER, &st) == 0);
	if (stat(STDIO_MARKER, &st) == 0) {
		CHECK(st.st_size == 0);
		if (st.st_size != 0)
			printf("FAIL: exec flushed %ld byte(s) a real exec "
			       "would have discarded\n", (long)st.st_size);
	}

	remove(CONTROL_MARKER);
	remove(STDIO_MARKER);
}

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "--exit")) return atoi(argv[2]);
	if (argc > 1 && !strcmp(argv[1], "--burn-cpu")) return burn_child_cpu() == 0 ? 0 : 3;
	if (argc > 1 && !strcmp(argv[1], "--argv0")) return argv0_child(argc, argv);
	if (argc > 1 && !strcmp(argv[1], "--envblock")) return envblock_child();
	if (argc > 1 && !strcmp(argv[1], "--arglen"))
		return argc == 4 && strlen(argv[3]) == (size_t)atol(argv[2]) ? RC_OK : RC_ARGV_MISMATCH;
	if (argc > 1 && (!strcmp(argv[1], "--argv") || !strcmp(argv[1], "--argv-env")))
		return argv_child(argc, argv);
	if (argc > 1 && (!strcmp(argv[1], "--argvl") || !strcmp(argv[1], "--argvl-env")))
		return argvl_child(argc, argv);
#if defined(__linux__) && !defined(_SPICULE_NATIVE_BUILD)
	/* Reached only by the --exec-pid role's own execl() above, in the
	 * SAME OS process if (and only if) that was a real in-place exec:
	 * the pid it captured just before calling execl() is the value now
	 * on the command line. */
	if (argc > 2 && !strcmp(argv[1], "--report-pid"))
		return (long)getpid() == atol(argv[2]) ? RC_OK : RC_PID_MISMATCH;
#endif
	if (argc > 1 && !strncmp(argv[1], "--exec-", 7)) return exec_child(argv[0], argv[1]);

	CHECK(run_role(argv[0], "--exec-v") == 0);
	CHECK(run_role(argv[0], "--exec-vp") == 0);
	CHECK(run_role(argv[0], "--exec-ve") == 0);
	CHECK(run_role(argv[0], "--exec-vpe") == 0);
#if defined(__linux__) && !defined(_SPICULE_NATIVE_BUILD)
	/* src/process/exec.c's real, in-place execve() on Linux: getpid()
	 * must be unchanged across the exec, not merely the exec'd
	 * program's output -- see exec_child()'s own "--exec-pid" comment
	 * for exactly what a regression here would look like (a real pid,
	 * just the WRONG one: a disguised fork+emulate would still pass
	 * every other CHECK in this file). Not run against NT: its own
	 * exec() family correctly does not preserve pid at all (documented
	 * fork+wait stand-in, src/process/exec.c's own banner), so this
	 * property is Linux-only by design. */
	CHECK(run_role(argv[0], "--exec-pid") == RC_OK);
#endif
	/* the exec'd image's exit code is what exec's caller exits with */
	CHECK(run_role(argv[0], "--exec-exit") == 200);
	/* a missing program fails with ENOENT and exec returns */
	CHECK(run_role(argv[0], "--exec-missing") == 0);

	/* exec.html, the l-forms and fexecve -- four names
	 * test/POSIX-GAP-ACCOUNTING.md listed as implemented but never
	 * called from anywhere in the test/ tree, plus fexecve.  Same shape as
	 * the v-forms above: the intermediate child execs itself in an
	 * --argvl role and the exec'd image checks what it received.
	 *
	 * RETURN VALUE: "If one of the exec functions returns to the
	 * calling process image, an error has occurred; the return value
	 * shall be -1, and errno shall be set" -- so a role that reaches
	 * the end of exec_child() reports RC_EXEC_RETURNED and fails here.
	 * DESCRIPTION: "If execution fails, the calling process image
	 * remains unchanged" -- which is what the --*-missing roles below
	 * check, by continuing to run and reporting an errno afterwards. */
	CHECK(run_role(argv[0], "--exec-l") == 0);
	CHECK(run_role(argv[0], "--exec-le") == 0);
	CHECK(run_role(argv[0], "--exec-lp") == 0);
	CHECK(run_role(argv[0], "--exec-f") == 0);
	/* the exec'd image's exit code is what the l-form's caller exits
	 * with, same as for execv above */
	CHECK(run_role(argv[0], "--exec-l-exit") == 201);
	/* [ENOENT] "A component of path or file does not name an existing
	 * file", for both the direct and the PATH-searching l-form */
	CHECK(run_role(argv[0], "--exec-l-missing") == 0);
	CHECK(run_role(argv[0], "--exec-lp-missing") == 0);
	/* [EBADF] "The fd argument is not a valid file descriptor open for
	 * executing." */
	CHECK(run_role(argv[0], "--exec-f-badfd") == 0);

	test_exec_drops_exit_handlers(argv[0]);
	test_empty_env_entry(argv[0]);
	test_failed_exec_keeps_cloexec(argv[0]);
	test_argv0_roundtrip(argv[0]);
	test_wait_rusage(argv[0]);
	/* Last: an execv() that is *meant* to fail with E2BIG will, if the
	 * length check is ever lost, succeed instead -- and a successful
	 * execv never comes back, so anything after it would not run. */
	test_cmdline_limit(argv[0]);

	if (fails) { printf("exec: failures: %d\n", fails); return 1; }
	if (unverified) {
		printf("exec: %d assertion group(s) unverified in this "
		       "environment (see SKIP lines above); no failures in "
		       "what did run\n", unverified);
		return 77;
	}
	printf("exec: all tests passed\n");
	return 0;
}
