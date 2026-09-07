/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Real-Linux-only regression coverage for a confirmed process leak in
 * src/thread/aio.c's background AIO worker.  Not meaningful, and not
 * built, anywhere but PLATFORM=linux -- see this file's own Makefile
 * gating, modeled directly on test/posix-dl-linux.c's identical
 * unconditional-filter-out-then-PLATFORM=linux-re-add pattern (that
 * file's own header comment explains the shape; the reason here is the
 * same class of "this only means anything against one specific native
 * backend").
 *
 * The bug, confirmed by direct reproduction before this fix landed:
 * src/thread/linux/plat_thread.c's own __plat_thread_spawn() clones the
 * AIO worker WITHOUT CLONE_THREAD (that file's own banner explains why,
 * a disclosed scope narrowing, not an oversight) -- so on this backend
 * the worker is a genuinely separate OS process (its own pid/tgid), not
 * a thread of the caller's own thread group. exit()/_exit() end the
 * process via exit_group(2) (src/exit/linux/plat_exit.c), which only
 * tears down threads sharing the CALLING thread's tgid -- the AIO
 * worker's tgid is its own, so it was never touched at all and survived
 * every test process's exit, reparented to init, sitting in aio_worker()'s
 * own unconditional `for (;;)` with no shutdown check. Confirmed via
 * `ps`: the leaked process was even observed still RUNNING (not merely
 * sleeping) minutes later, spinning a full CPU core -- a second, related
 * but separate finding (this Linux backend's __plat_event_create()/
 * __plat_event_set() build a manual-reset event, but aio.c's own
 * worker_wake doorbell needs the auto-reset "SynchronizationEvent"
 * semantics plat_thread.h's own banner documents, so __plat_wait_one()
 * on it stops blocking at all after the first signal) left disclosed
 * here rather than re-fixed: it does not change whether the process
 * leaks, only how much CPU the leaked process burns while orphaned, and
 * fixing it for real means auditing every other __plat_event_*
 * consumer's own assumptions about reset semantics, out of this fix's
 * own scope.
 *
 * The fix (src/thread/aio.c's worker_shutdown/worker_exited/
 * worker_done_event/aio_worker_atexit()): a real shutdown flag
 * aio_worker()'s idle branch checks instead of blocking forever once
 * the queue is empty, and an atexit() hook (portable -- runs before
 * __exit_internal()/__plat_terminate() on every platform, not just this one)
 * that sets the flag, wakes an idle worker, and then genuinely BLOCKS
 * on a second, dedicated event the worker signals right before it
 * actually returns -- so exit() cannot proceed, and exit_group(2)
 * cannot run, while the worker is still alive to be missed by it.
 *
 * This test proves the fix at the process level, not just by reading the
 * code: fork()+execve() test/aio-leak-helper.c (see that file's own
 * header for why a SEPARATE exec()'d process, not AIO calls made
 * directly inside a plain fork()'d child of this test binary -- the
 * latter was tried first and crashes in aio_suspend() for reasons
 * entirely unrelated to, and pre-existing before, this fix, a separate
 * bug this regression test is deliberately not about). The helper
 * submits one real aio_write(), waits for it via aio_suspend(), and
 * exits -- then, once it is reaped, this test scans /proc for any OTHER
 * process whose /proc/<pid>/exe resolves to the HELPER's own binary.
 * Before the fix that scan reliably found the leaked worker (CLONE_VM
 * shares the executable image outright, not merely a copy of argv the
 * way an unrelated process launched from the same shell might); after
 * it, nothing is ever found. A short bounded poll (not a single
 * immediate check) absorbs the real, disclosed, sub-millisecond gap
 * between aio_worker_atexit()'s wait returning (worker_done_event
 * observed set) and the worker's own SYS_exit syscall actually
 * completing (see aarch64/clone.S's own trampoline) -- an inherent
 * scheduling window, not a bug, and small enough that a flaky poll
 * interval would be the wrong fix for it.
 */
#include "test-policy.h"
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static char helper_path_buf[PATH_MAX];

/* obj/test/aio-leak-helper.exe, found next to THIS binary's own real
 * executable -- resolved via /proc/self/exe (a run-from-anywhere
 * convention: a plain "./aio-leak-helper.exe" relative-to-cwd path is
 * not reliable once a test runner starts running things from a temp
 * directory, the same reason test/posix-dl-linux.c's own fixture_dir()
 * exists), NOT by patching argv[0]'s own directory component the way
 * that fixture_dir() does. That distinction matters here specifically:
 * this file compares /proc/<pid>/exe of every OTHER live process
 * against this string byte-for-byte (other_instance_running(), below),
 * and /proc/<pid>/exe always reports the kernel's own fully resolved,
 * symlink-free, absolute path -- an argv[0]-derived path (often
 * relative, e.g. "./obj/test/posix-realtime-linux.exe", and with this
 * project's own out-of-source obj/ layout possibly carrying a "./"
 * component /proc/<pid>/exe's own canonicalization would silently drop)
 * would not byte-match that even when it names the identical file on
 * disk, and DID silently fail to match a real, confirmed leak during
 * this test's own development, before switching to this approach --
 * disclosed here so a future edit does not reintroduce it by "helpfully"
 * switching back to the argv[0] convention. */
static const char *helper_path(void)
{
	static const char name[] = "aio-leak-helper.exe";
	char self[PATH_MAX];
	ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
	const char *slash;
	size_t dirlen;
	if (n <= 0) return name;
	self[n] = 0;
	slash = strrchr(self, '/');
	if (!slash) return name;
	dirlen = (size_t)(slash - self) + 1;
	if (dirlen + sizeof name >= sizeof helper_path_buf) return name;
	memcpy(helper_path_buf, self, dirlen);
	memcpy(helper_path_buf + dirlen, name, sizeof name);
	return helper_path_buf;
}

/* Every OTHER live process (skipping `self` and `child`, and anything
 * whose /proc/<pid>/exe cannot be resolved -- a kernel thread or a
 * process that raced past exit between readdir() and readlink(), never
 * this test's own concern) whose real executable is the helper binary.
 * CLONE_VM (not a plain fork()) is what makes this comparison mean "the
 * AIO worker specifically": a leaked worker shares its parent's
 * executable image outright, not merely a copy of its argv the way an
 * unrelated process might. */
static int other_instance_running(const char *helper_exe, pid_t self, pid_t child)
{
	DIR *proc = opendir("/proc");
	struct dirent *entry;
	int found = 0;
	if (!proc) return -1;
	while ((entry = readdir(proc)) != 0) {
		char link[64], target[PATH_MAX];
		pid_t pid;
		char *end;
		ssize_t n;
		pid = (pid_t)strtol(entry->d_name, &end, 10);
		if (*end != 0 || pid <= 0) continue;
		if (pid == self || pid == child) continue;
		snprintf(link, sizeof link, "/proc/%d/exe", (int)pid);
		n = readlink(link, target, sizeof target - 1);
		if (n <= 0) continue;
		target[n] = 0;
		if (strcmp(target, helper_exe) == 0) { found = 1; break; }
	}
	closedir(proc);
	return found;
}

static void test_no_leaked_worker_process_after_exit(const char *helper_exe)
{
	char path[256];
	pid_t self = getpid();
	pid_t child;
	int status, i, leak;

	snprintf(path, sizeof path, "/tmp/.spicule-posix-realtime-linux-aio-%d.txt",
	         (int)self);

	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		char *args[3];
		args[0] = (char *)helper_exe;
		args[1] = path;
		args[2] = 0;
		execv(helper_exe, args);
		_exit(127); /* execv() itself failed -- helper missing/unbuilt */
	}
	if (child < 0) return;

	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	unlink(path);

	/* Bounded poll, not a single immediate check: see this file's own
	 * header comment on the real, small, disclosed gap between the
	 * fix's own wait returning and the worker's actual exit syscall.
	 * `sleep()` (whole seconds, unconditionally declared in unistd.h)
	 * rather than nanosleep()/usleep(): both of those are only visible
	 * under a _POSIX_C_SOURCE/_XOPEN_SOURCE this file deliberately does
	 * not define (this test build's plain -std=c99 already defines
	 * __STRICT_ANSI__, which turns off features.h's own default
	 * _XOPEN_SOURCE=700 fallback -- confirmed empirically, not assumed).
	 * Three total attempts is enough to absorb that gap many times over
	 * in the success case (the very first, sleep-free check already
	 * passes in practice) while keeping the failure case's own runtime
	 * bounded at a couple of seconds, not unbounded. */
	leak = 0;
	for (i = 0; i < 3; i++) {
		int result = other_instance_running(helper_exe, self, child);
		if (result == 0) { leak = 0; break; }
		leak = result > 0;
		if (i + 1 < 3) sleep(1);
	}
	CHECK(!leak);
}

int main(int argc, char **argv)
{
	const char *helper;
	(void)argc;
	(void)argv;

	helper = helper_path();
	test_no_leaked_worker_process_after_exit(helper);

	if (fails) { printf("posix-realtime-linux: failures: %d\n", fails); return 1; }
	printf("posix-realtime-linux: all ok\n");
	return 0;
}
