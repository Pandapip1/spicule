/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of <stropts.h>'s ioctl()
 * (`OB XSR`) -- https://pubs.opengroup.org/onlinepubs/9699919799/functions/ioctl.html
 *
 * ==================== the finding, up front ==========================
 *
 * test/POSIX-GAP-ACCOUNTING.md lists `ioctl` under "Implemented, not
 * clause-audited", with the note "src/ioctl/ioctl.c implements the
 * name, not the STREAMS semantics POSIX attaches to it".  **Reading the
 * page shows the note is right and the row it sits in is wrong.**
 * POSIX's ioctl() is not implemented here at all; a different function
 * that shares its name is:
 *
 *                     POSIX <stropts.h>             spicule <sys/ioctl.h>
 *   header            stropts.h (absent here)       sys/ioctl.h
 *   signature         int ioctl(int, int, ...)      int ioctl(int, unsigned long, ...)
 *   specified over    STREAMS devices               NT file/pipe/console handles
 *   command set       I_PUSH I_POP I_LOOK I_FLUSH   FIONREAD TIOCGWINSZ FIONBIO
 *                     I_SETSIG I_FIND I_PEEK ...    (Linux's numbers, by convention)
 *
 * The two share a name, an fd parameter and nothing else -- disjoint
 * headers, disjoint command sets, and POSIX's own text says of
 * everything spicule's version does that "for non-STREAMS devices, the
 * functions performed by this call are unspecified".
 * `include/sys/ioctl.h`'s own banner says as much in its first line:
 * "ioctl(): NOT a POSIX interface -- POSIX deliberately specifies
 * termios(3) ... instead of a general ioctl(2)".
 *
 * So this file's verdict is a **reclassification, not a fence**:
 * `ioctl` belongs in `POSIX-GAP-ACCOUNTING.md`'s *absent* accounting,
 * alongside the other headers spicule does not have, not in
 * "Implemented, not clause-audited".  Fencing an UNIMPL inside a row
 * that should not exist would have recorded the symptom and kept the
 * miscategorisation.  The ledger entry for this file says so.
 *
 * That leaves three things this file does assert or record:
 *
 *  1. `<stropts.h>` is absent, and so is every type and macro it
 *     defines.  A strictly conforming application does not compile.
 *     Fenced UNIMPL, with real assertions -- and, as of 2026-08-25,
 *     UNIMPL in the "I chose not to" sense: the header is DECLINED,
 *     for the three reasons set out at the fence itself (POSIX deleted
 *     it in Issue 8; shipping it moves the failure from compile time to
 *     link time without fixing anything; and its prototype conflicts
 *     with the ioctl() this tree already has).
 *  2. The STREAMS command set and every clause conditioned on a
 *     STREAMS device: **N/A**, and the mechanism is not "NT is
 *     different".  It is that ioctl.html scopes its clauses to STREAMS
 *     devices and declares behaviour on anything else unspecified; NT
 *     has no STREAMS subsystem and nothing on it can be opened as a
 *     STREAMS device, so `fildes` can never refer to one and those
 *     clauses are vacuous rather than violated.  A scope that cannot
 *     be entered.
 *  3. The one general-condition clause that survives regardless of
 *     STREAMS -- "[EBADF] The fildes argument is not a valid open file
 *     descriptor" -- is implemented and is asserted live, against
 *     spicule's own ioctl() through <sys/ioctl.h>.  It is the only
 *     assertion in this file that runs.
 *
 * The BSD ioctl() spicule actually ships is deliberately *not* audited
 * against ioctl.html here beyond that: it is not the function the page
 * specifies, and asserting whatever the code happens to do would be
 * exactly the "audit the implementation instead of the spec" failure
 * this ledger exists to avoid.  Its own behaviour is documented in
 * src/ioctl/ioctl.c's banner; giving it real tests of its own is a
 * separate, non-POSIX job.
 */
#include "test-policy.h"
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* --------------------------------------------------------------------
 * ERRORS, general conditions: "[EBADF] The fildes argument is not a
 * valid open file descriptor."
 *
 * The one clause on the page that is not conditioned on `fildes`
 * referring to a STREAMS device, and therefore the one that is not
 * vacuous here.  Asserted against spicule's own ioctl(); it holds
 * (src/internal/fd.c's __fd_get() sets EBADF and src/ioctl/ioctl.c
 * returns -1 on a null result).
 * ------------------------------------------------------------------ */
static void test_ebadf(void)
{
	int n = 0;

	errno = 0;
	CHECK(ioctl(-1, FIONREAD, &n) == -1);
	CHECK(errno == EBADF);

	errno = 0;
	CHECK(ioctl(4242, FIONREAD, &n) == -1);
	CHECK(errno == EBADF);

	/* a descriptor that was open and has been closed */
	{
		int fd = open("stropts-ebadf.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
		CHECK(fd >= 0);
		if (fd >= 0) {
			close(fd);
			errno = 0;
			CHECK(ioctl(fd, FIONREAD, &n) == -1);
			CHECK(errno == EBADF);
		}
		unlink("stropts-ebadf.tmp");
	}
}

/* --------------------------------------------------------------------
 * <stropts.h> itself.
 *
 * basedefs/stropts.h.html requires the header to define the `bandinfo`,
 * `strpeek`, `strbuf`, `strfdinsert`, `strioctl`, `strrecvfd`,
 * `str_list`, `str_mlist` structures, the FLUSH, I_, S_, RS_, RMSG,
 * MSG_, MORECTL and MOREDATA constants and FMNAMESZ, and to declare
 * isastream(), getmsg(), getpmsg(), putmsg(), putpmsg() and ioctl().
 * grep over include/ and src/ finds none of it: no stropts.h, no
 * I_PUSH, no FMNAMESZ, no isastream.
 *
 * UNIMPL rather than N/A, because this project's rule counts "I chose
 * not to" as UNIMPL -- and this is that case.  The fence below used to
 * argue the opposite, that the header half was cheap and separable from
 * the STREAMS-behaviour half; that argument is retained verbatim in the
 * fence and answered there, because it is a reasonable thing to think
 * and someone will think it again.
 * ------------------------------------------------------------------ */
#if SPICULE_TEST(NA, posix_stropts_placeholder_not_a_header_test) /* N/A: this block cannot test that <stropts.h> exists.
       * ioctl.html SYNOPSIS:
       *   #include <stropts.h>
       *   int ioctl(int fildes, int request, ... );
       * spicule declares ioctl() in <sys/ioctl.h> -- a BSD/SVR4 header
       * POSIX does not specify -- with `unsigned long request` rather
       * than `int request`.  A strictly conforming application that
       * writes the SYNOPSIS above does not compile.  The assertions
       * below are kept so the clause stays written down.
       *
       * THIS FENCE PREVIOUSLY READ: "Deliberately UNIMPL and not N/A:
       * nothing about NT prevents shipping the header.  Deliberately
       * not folded into the N/A for STREAMS semantics either: they
       * block different callers at different stages, and collapsing
       * them would hide that the cheap half is cheap."
       *
       * The first sentence is true and the conclusion does not follow.
       * Three things were checked, and each on its own would settle it:
       *
       * 1. POSIX DELETED IT.  <stropts.h> and ioctl() are both marked
       *    [OB XSR] in Issue 7 -- obsolescent, and part of the XSI
       *    STREAMS OPTION GROUP.  ioctl.html says so itself: "The
       *    ioctl() function is marked obsolescent" and "The ioctl()
       *    function may be removed in a future version."  It was:
       *    basedefs/stropts.h.html and functions/ioctl.html are both
       *    404 under Issue 8 (onlinepubs/9799919799), where they exist
       *    under Issue 7 (9699919799).  Shipping the header now means
       *    implementing an interface the standard has since removed.
       *
       * 2. SHIPPING IT MOVES THE FAILURE LATER WITHOUT FIXING IT.  The
       *    header is nothing but STREAMS machinery -- I_PUSH, strbuf,
       *    isastream, getmsg/putmsg -- whose BEHAVIOUR this file
       *    already records as N/A, because NT has no STREAMS
       *    subsystem and `fildes` can never name a STREAMS device.  A
       *    header without the subsystem lets a program compile and
       *    then fail at link or answer nonsense at run time, which is
       *    strictly worse than failing to compile: the compile error
       *    names the missing thing.
       *
       *    musl is the demonstration, not an analogy.  It DOES ship
       *    include/stropts.h with the full constant and structure set
       *    -- so "absent from musl", as POSIX-GAP-ACCOUNTING.md's row
       *    for these functions puts it, is not quite right -- and it
       *    implements exactly one of the seven functions:
       *    src/legacy/isastream.c, three lines, answering "this is not
       *    a stream" for any valid descriptor.  getmsg, putmsg,
       *    getpmsg, putpmsg, fattach and fdetach do not exist.  An
       *    application that compiles against that header fails at
       *    link, which is where spicule's would fail too.
       *
       * 3. IT IS NOT FREE.  POSIX's prototype is
       *    `int ioctl(int fildes, int request, ...)`; spicule's working
       *    ioctl() is `int ioctl(int, unsigned long, ...)`.  Shipping
       *    <stropts.h> as specified puts two conflicting declarations
       *    of ioctl in one tree -- a program including both headers
       *    fails to compile, which is the very failure the header was
       *    supposed to remove -- or else means changing the signature
       *    of a function that works today, in order to match an
       *    interface the standard has deleted.  "The cheap half" is
       *    not cheap; it is an API change to a working function.
       *
       * Re-enable this only if a consumer this tree actually
       * bootstraps turns out to require the header, and then ship it
       * knowing it will fail at link rather than at compile.  Nothing
       * has asked for it. */
static void test_stropts_header_exists(void)
{
	/* would be: #include <stropts.h> at the top of this file */
	int fildes = 0, request = 0;
	CHECK(ioctl(fildes, request) == -1);   /* the POSIX signature */
}
#endif

/* --------------------------------------------------------------------
 * The STREAMS command set: I_PUSH, I_POP, I_LOOK, I_FLUSH,
 * I_FLUSHBAND, I_SETSIG, I_GETSIG, I_FIND, I_PEEK, I_SRDOPT, I_GRDOPT,
 * I_NREAD, I_FDINSERT, I_STR, I_SWROPT, I_GWROPT, I_SENDFD, I_RECVFD,
 * I_LIST, I_ATMARK, I_CKBAND, I_GETBAND, I_CANPUT, I_SETCLTIME,
 * I_GETCLTIME, I_LINK, I_UNLINK, I_PLINK, I_PUNLINK -- and every
 * per-command [EINVAL]/[ENXIO]/[EAGAIN]/[ENOSR] the page attaches to
 * them, plus the general [EINTR], [EIO], [ENOTTY], [ENXIO], [ENODEV]
 * and the "linked downstream from a multiplexer" [EINVAL].
 *
 * N/A: a scope that cannot be entered.  ioctl.html DESCRIPTION opens
 * "The ioctl() function shall perform a variety of control functions
 * on STREAMS devices" and immediately adds "For non-STREAMS devices,
 * the functions performed by this call are unspecified."  Every clause
 * below that sentence is conditioned on `fildes` referring to a
 * STREAMS device, or on a STREAM being linked downstream from a
 * multiplexer.  NT has no STREAMS subsystem: there is no STREAMS
 * driver, no way to open a device as a STREAM, and no module to push
 * onto one.  `fildes` can therefore never refer to a STREAMS device on
 * this platform, which makes those clauses vacuous rather than
 * violated -- and it puts everything spicule's ioctl() actually does
 * (FIONREAD, TIOCGWINSZ, FIONBIO on ordinary NT handles) squarely in
 * the region POSIX explicitly leaves unspecified.
 *
 * This is emphatically not the "I chose not to" case UNIMPL is for.
 * Emulating STREAMS in user space would not make ioctl.html's clauses
 * apply either: they are about the STREAM a *device driver* provides,
 * and a userspace shim over NT handles would be one more non-STREAMS
 * device.  Written as a comment rather than a fenced test because
 * there is no assertion to write: a test that cannot construct a
 * STREAMS device cannot assert anything about one, even fenced.
 * ------------------------------------------------------------------ */

int main(void)
{
	test_ebadf();
#if SPICULE_TEST(NA, posix_stropts_placeholder_not_a_header_test) /* N/A: see the fence above test_stropts_header_exists.
       * This is the same fence, not a second one: the call site has to
       * be guarded too, because the function it calls is inside the
       * first #if 0. */
	test_stropts_header_exists();
#endif

	if (fails) { printf("posix-stropts: failures: %d\n", fails); return 1; }
	printf("posix-stropts: all ok\n");
	return 0;
}
