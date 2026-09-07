/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * select()/poll() must not report a FULL pipe as writable.
 *
 * src/select/select.c used to hardcode pipe writability to 1, on the
 * recorded ground that NtQueryInformationFile(FilePipeLocalInformation)'s
 * WriteQuotaAvailable "reads back 0 always" and so carried no signal.
 * That was a true observation of wine-9.0 -- whose server hardcodes the
 * field to a literal 0 (fixed upstream in 4cbb92cfb, first shipped in
 * wine-10.0) -- generalised into a claim about the platform this library
 * actually targets, where the field works.  Measured on Windows Server
 * 2025 build 26100: an end's WriteQuotaAvailable is its write-direction
 * quota minus the bytes currently buffered in that direction, tracking
 * live and restored exactly by a drain.
 *
 * WINE CANNOT EXERCISE THIS TEST.  Read that literally before treating a
 * green local run as coverage of anything here:
 *
 *   - under wine-9.0 (what `make check` runs against on the primary
 *     development machine) WriteQuotaAvailable is a hard 0 for every
 *     pipe, so select.c's wqa_works() positive control fails and the
 *     whole consult is disabled -- writability falls back to the old
 *     always-ready answer and the assertions below could not fail; and
 *   - under wine-10.x and current master the field returns the FULL
 *     quota unreduced (server/named_pipe.c's standing FIXME: it still
 *     needs reducing by the buffered count), so a full pipe still reads
 *     as having room and the assertions below still could not fail.
 *
 * Neither Wine can distinguish a fixed select.c from a broken one.  That
 * is why this file carries the -win suffix: it is built everywhere but
 * run only on the real-NT CI legs, which are the sole oracle for it.
 * Note also that those legs are one Windows image wearing three labels
 * (all `runs-on: windows-latest`; the matrix varies only artifact arch),
 * so they are three runs of one platform, not three platforms.
 *
 * WHAT THIS MEASURES THAT THE ORIGINAL RUN COULD NOT.  That run wrote
 * only on the server end, so its client-end column sat at full quota in
 * every cell -- evidence that the client->server direction was never
 * exercised, not that the client end is inert.  spicule's own pipe()
 * makes the READ end the pipe's server and the WRITE end its client
 * (src/unistd/pipe.c), so the end select() actually probes for
 * writability is exactly the end that run left unmeasured.  Everything
 * below writes on that client end, which is why the behavioural
 * assertions here are not a restatement of the existing table but the
 * missing column of it.
 *
 * The byte counts printed are the measurement: filling reports how many
 * bytes the client's write direction accepted before it stopped being
 * writable, which is that end's write quota, and the drain reports that
 * the capacity comes back.  A pipe this library makes always requests
 * 65536 on both directions and there is no public way to ask for
 * another, so there is one stimulus here, not several wearing labels;
 * the `total == REQUESTED_QUOTA` check is what would catch the quota
 * being silently honoured at some other size.
 *
 * That check is also the control that keeps the full-pipe cell from
 * being vacuous.  "select() says not writable" is exactly what a probe
 * that never managed to write anything would also produce, so the fill
 * loop accumulates the actual write() return values and the byte count
 * is asserted, not merely printed: the cell asserts that the pipe was
 * filled AND that it then read as unwritable, which a silent write
 * failure could not fake.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <sys/select.h>

/* The quota src/unistd/pipe.c asks for, on both directions. */
#define REQUESTED_QUOTA 65536

static int fails;
#define CHECK(cond) do { \
	if (!(cond)) { fails++; printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

/* ---------------------------------------------------------------- */
/* ASSERTIONS: the public contract, through pipe()/select()/poll().  */
/* ---------------------------------------------------------------- */

/* Is fd reported writable by select() with a zero timeout? */
static int sel_writable(int fd)
{
	fd_set w;
	struct timeval tv;
	int r;

	FD_ZERO(&w);
	FD_SET(fd, &w);
	tv.tv_sec = 0; tv.tv_usec = 0;
	r = select(fd + 1, 0, &w, 0, &tv);
	if (r < 0) { fails++; printf("FAIL: select errno %d\n", errno); return -1; }
	return FD_ISSET(fd, &w) ? 1 : 0;
}

/* Same question through poll(). */
static int poll_writable(int fd)
{
	struct pollfd p;
	int r;

	p.fd = fd; p.events = POLLOUT; p.revents = 0;
	r = poll(&p, 1, 0);
	if (r < 0) { fails++; printf("FAIL: poll errno %d\n", errno); return -1; }
	return (p.revents & POLLOUT) ? 1 : 0;
}

static void assertions(void)
{
	int fd[2];
	char buf[4096];
	long total = 0;
	int sw, pw;

	memset(buf, 'x', sizeof buf);

	if (pipe(fd) != 0) { fails++; printf("FAIL: pipe errno %d\n", errno); return; }

	/* POSITIVE CONTROL, first and non-negotiable.  A fresh pipe has its
	 * whole write direction free and MUST report writable.  Without
	 * this passing, a later "not writable" would be indistinguishable
	 * from a probe that never worked at all -- which is the exact
	 * confusion (a zero that meant the wrong thing) this whole test
	 * exists to settle. */
	sw = sel_writable(fd[1]);
	pw = poll_writable(fd[1]);
	printf("control  fresh pipe: select=%d poll=%d (both must be 1)\n", sw, pw);
	CHECK(sw == 1);
	CHECK(pw == 1);

	/* Fill it.  Nothing reads, so the bytes stay buffered.  The loop is
	 * bounded by the requested quota and stops the moment the pipe
	 * stops reporting writable, so it cannot block on a full pipe even
	 * if the quota were honoured at some other size. */
	while (total < REQUESTED_QUOTA && sel_writable(fd[1]) == 1) {
		long room = REQUESTED_QUOTA - total;
		ssize_t n = write(fd[1], buf, (size_t)(room < (long)sizeof buf ? room : (long)sizeof buf));
		if (n <= 0) { printf("note: write stopped, n=%ld errno=%d\n", (long)n, errno); break; }
		total += n;
	}
	printf("filled   %ld bytes of a %d-byte requested quota\n", total, REQUESTED_QUOTA);
	/* If this fails the pipe never actually filled and everything after
	 * it is vacuous. */
	CHECK(total == REQUESTED_QUOTA);

	/* THE REGRESSION.  A full pipe must NOT be reported writable: a
	 * write() on it would block, which is exactly what select() exists
	 * to let a caller avoid. */
	sw = sel_writable(fd[1]);
	pw = poll_writable(fd[1]);
	printf("full     pipe: select=%d poll=%d (both must be 0)\n", sw, pw);
	CHECK(sw == 0);
	CHECK(pw == 0);

	/* Drain half.  Writability must come back -- an implementation that
	 * simply answered "never writable" would pass the cell above and
	 * fail this one. */
	{
		long drained = 0;
		while (drained < REQUESTED_QUOTA / 2) {
			ssize_t n = read(fd[0], buf, sizeof buf);
			if (n <= 0) break;
			drained += n;
		}
		printf("drained  %ld bytes\n", drained);
		CHECK(drained > 0);
	}
	sw = sel_writable(fd[1]);
	pw = poll_writable(fd[1]);
	printf("drained  pipe: select=%d poll=%d (both must be 1)\n", sw, pw);
	CHECK(sw == 1);
	CHECK(pw == 1);

	close(fd[0]);
	close(fd[1]);
}

int main(void)
{
	printf("posix-pipe-wquota-win: real NT only; see this file's header for\n"
	       "why no Wine build can exercise it.\n");
	assertions();
	if (fails) { printf("FAILURES: %d\n", fails); return 1; }
	printf("PASS\n");
	return 0;
}
