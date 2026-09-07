/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The IOCTL_AFD_SELECT Handles[] *stride*, measured against a real AFD
 * device with more than one handle in the array.
 *
 * *** Why this file exists: a LATENT HAZARD, not a live bug. ***
 *
 * Read the rest of this file with that distinction in front of you,
 * because an earlier framing of this work got it wrong and called the
 * unmeasured stride a defect in shipped code.  It is not.  Nothing
 * this file measures is reachable from select(), poll(), or any other
 * entry point THIS library exposes today.  (Other AFD clients DO reach
 * it -- see the "nobody batches" section below.  The scope of this
 * sentence is spicule, not the wire.)  A passing run here is NOT
 * evidence that the shipped poll path is verified -- that path never
 * executes the code this file exercises.
 *
 * The subject splits three ways, and only the first is settled:
 *
 *   1. The element-0 offset, +16.  GENUINELY CONFIRMED against a real
 *      device.  src/internal/afd.h's poll banner records
 *      AFD_POLL_INFO.Handles at +16 (the AFD driver's own NT 4.0
 *      afd.h, phnt, wepoll, libuv) rather than ReactOS's +24 on
 *      x86_64, and calls it "observed, not merely reasoned": the
 *      ioctl issued with Handles at +24 returns STATUS_INVALID_HANDLE
 *      where the +16 form returns STATUS_SUCCESS.  That observation
 *      is real -- and it is about the *base* of the array.
 *
 *   2. The stride as a contributor to the request *length*.  WEAKLY
 *      exercised.  Real-Windows CI passes issuing 32-byte one-handle
 *      requests on x86_64 (16 header + 1 * 16), so that length is at
 *      least *accepted* by the driver.  Acceptance of a total byte
 *      count is not measurement of an element pitch.
 *
 *   3. The stride as an element *pitch* -- the spacing between
 *      Handles[0] and Handles[1].  Untested against any device when
 *      this file was written, and unreached by spicule's own select().
 *      This is what this file measures, and it is measured now: see
 *      the CI runs cited under "Compaction is observed" below.
 *
 *      Note the wording.  NOT "unreachable in production" -- an
 *      earlier draft said that and it was wrong.  ReactOS's msafd
 *      reaches this path on every select() call; see the next section.
 *      Unreached by *us* and unreachable by *anyone* are different
 *      claims, and only the first one is true.
 *
 * Why (3) is unexercised HERE, stated plainly so nobody has to
 * re-derive it.  src/select/select.c's poll_pass() loops per
 * descriptor and calls __fd_probe() once per fd; src/select/poll.c
 * does the same per pollfd; and __fd_probe()'s __FD_SOCKET case builds
 * __afd_build_poll_request(&req, 0, 1) -- HandleCount is the literal
 * 1.  So a select() over N sockets issues N separate SINGLE-HANDLE
 * ioctls, never one N-handle request.  Handles[1] and beyond are
 * never written, never sent, and never read back by shipped spicule
 * code.  A one-element array cannot exercise a stride at all: element
 * 0 sits at base + 0 * stride for every stride there is.
 *
 * *** But "nobody batches" is NOT why the pitch is latent. ***
 *
 * That was this file's first answer and it was too narrow -- it is a
 * fact about spicule's select(), not about the wire.  Plenty of code
 * does batch.  Read in the ReactOS tree at d610480e: WSPSelect fills
 * one AFD_POLL_INFO with the whole fd_set, sets HandleCount, and
 * issues a SINGLE IOCTL_AFD_SELECT for all of them
 * (dll/win32/msafd/misc/dllmain.c:1305 for the size, :1313 for the
 * ioctl).  The pitch is exercised there on every select() call.
 * Reachability is not what makes a wrong value survive.
 *
 * What makes it survive is CLIENT-SERVER HEADER SHARING, and both
 * halves were checked rather than assumed:
 *
 *   client  dll/win32/msafd/misc/dllmain.c:1305
 *           FIELD_OFFSET(AFD_POLL_INFO, Handles)
 *               + PollInfo->HandleCount * sizeof(AFD_HANDLE)
 *   driver  drivers/network/afd/afd/select.c:76
 *           FIELD_OFFSET(AFD_POLL_INFO, Handles)
 *               + sizeof(AFD_HANDLE) * PollReq->HandleCount
 *
 * The same expression with the operands commuted, from the same
 * declaration: dll/win32/msafd/msafd.h:29 and
 * drivers/network/afd/include/afd.h:23 both include <afd/shared.h>,
 * which resolves to sdk/include/reactos/drivers/afd/shared.h.
 *
 * Client and driver therefore agree at ANY pitch.  Get sizeof
 * (AFD_HANDLE) "wrong" and both sides are wrong identically, every
 * request still parses, and nothing anywhere reports an error.  A
 * shared header does not make the value right; it makes a wrong value
 * SELF-CONSISTENT, and so invisible.
 *
 * The exposed class is the foreign client that hand-rolls the
 * structure from documentation rather than sharing the driver's
 * header: wepoll, libuv, mio -- and this library.  spicule declares its
 * own AFD_POLL_INFO in src/internal/afd.h and computes its own offsets
 * (AFD_POLL_REQ_OFF_HANDLES, AFD_POLL_H_SIZE); there is no shared
 * header and therefore NO SELF-CONSISTENCY SAFETY NET.  For us a wrong
 * pitch is silently wrong in a way it structurally cannot be for
 * msafd, and the symptom is select() and poll() misreporting readiness
 * with no error surfaced anywhere.
 *
 * *** The corollary, which is the real argument for this file. ***
 *
 * A probe written against msafd -- WSAEventSelect, select(), anything
 * going through ws2_32 -- COULD NOT HAVE CAUGHT A PITCH ERROR, for
 * exactly the header-sharing reason above: it would be asking a client
 * that shares the driver's header whether it agrees with the driver,
 * and the answer is yes at every pitch.  Such a probe is
 * self-consistent by construction, the same defect this file's banner
 * already records for test/posix-socket-poll.c's fake_handle() images.
 * The only probe that can discriminate is one that hand-rolls the
 * structure and sends it to the real driver -- which is precisely what
 * this file does, and why it exists rather than being folded into a
 * Winsock-level test.
 *
 * So why write this?  Because the helpers are already general.
 * __afd_build_poll_request(), __afd_poll_set_handle() and
 * __afd_poll_request_size() all take an `nhandles` parameter, and
 * AFD_POLL_REQ_SIZE(n) multiplies by it.  The first person to batch
 * handles -- an obvious optimisation for a select() over many sockets,
 * one ioctl instead of N -- inherits an element pitch that has never
 * touched a driver, silently, with no diagnostic anywhere.  This file
 * is the guard that turns that silence into a failing test on the day
 * it would otherwise become a bug.
 *
 * test/posix-socket-poll.c already builds three-element images and
 * already "checks the stride", but device-free: fake_handle(i) (its
 * :187) is a fabricated 0x11110000+ pointer that never reaches
 * afd.sys, so the file asserts that *our own* parser agrees with *our
 * own* builder and with raw byte offsets we also chose.  It is
 * self-consistent by construction and structurally unable to disagree
 * with any driver; afd.h's own comment admits as much.  Five sources
 * agreeing about a property none of them tested is exactly the shape
 * of error that survives.
 *
 * So: this file issues real, multi-handle IOCTL_AFD_SELECT requests
 * against real \Device\Afd endpoints and asserts on the *identity* of
 * the handle the driver names back, never on a slot index.
 *
 * *** Varying the stimulus, not the observation. ***
 *
 * Three handles all in the same readiness state exercise the array no
 * better than one does -- if every handle is ready, any stride that
 * lands inside the array names *a* ready handle and looks right.  The
 * discrimination comes from the readiness *pattern*.  Eight patterns
 * are run over the same three sockets (test_patterns() below):
 *
 *      none          zero control: no handle named at all
 *      first only    { s0 }        1 ready
 *      middle only   { s1 }        1 ready
 *      last only     { s2 }        1 ready
 *      first+middle  { s0, s1 }    2 ready
 *      first+last    { s0, s2 }    2 ready, a gap in the middle
 *      middle+last   { s1, s2 }    2 ready, starting off slot 0
 *      all three     { s0, s1, s2 }  3 ready
 *
 * *** Which check does the discriminating, and when. ***
 *
 * This must be stated exactly, because the obvious intuition is wrong
 * and was written into an earlier draft of this file.  That draft said
 * "middle only" was the load-bearing pattern -- the one an off-by-one
 * stride cannot fake, because a wrong stride would have to name a
 * socket that is genuinely not ready.  That reasoning silently assumes
 * reply slot i corresponds to request slot i.  It does not.  The reply
 * is COMPACTED (see the next section): the driver appends one entry
 * per handle that actually fired, so a pattern with exactly one ready
 * socket produces a one-entry reply, and that entry sits at
 * base + 0 * stride for EVERY stride there is.  A one-element reply
 * cannot exercise a pitch, for precisely the same reason a one-element
 * request cannot -- which is the whole complaint this file exists to
 * answer.  "Middle only" is not load-bearing; it is blind.
 *
 * Measured, not reasoned: feeding this file's own reader a reply built
 * by a driver using a 24-byte element instead of 16 --
 *
 *      pattern      ready   Information catches   identity catches
 *      first          1           yes                  NO
 *      middle         1           yes                  NO
 *      last           1           yes                  NO
 *      first+middle   2           yes                  yes
 *      first+last     2           yes                  yes
 *      middle+last    2           yes                  yes
 *      all            3           yes                  yes
 *
 * So the two assertions cover different halves and NEITHER is
 * redundant:
 *
 *   - The identity/absence assertions -- "the reply named exactly the
 *     ready set and nothing else" -- discriminate a reply-side pitch
 *     error only when at least TWO handles are ready.  This is why the
 *     multi-ready patterns are the ones that matter, and why all three
 *     two-ready sets are run rather than just one.
 *
 *   - IoStatus.Information catches every case including the
 *     single-ready ones, because it is derived from the compacted
 *     output pointer and so is a byte-count measurement of the element
 *     size in its own right.  For the single-ready patterns it is the
 *     ONLY thing standing between a wrong pitch and a silent pass.
 *     Do not "simplify" it away as implied by the identity checks; it
 *     is not.
 *
 * The single-ready patterns are still run, for two reasons: they are
 * what the Information check discriminates on, and "middle only" is
 * the state the deliberately-wrong REQUEST images in
 * test_wrong_layouts() are sent in, where a wrong request-side base or
 * pitch makes the driver read a handle from the wrong offset.
 *
 * *** Reading the reply: bounded by the reply's own count. ***
 *
 * Real AFD *compacts* its output.  AfdPoll() zeroes NumberOfHandles
 * before its readiness scan, appends one AFD_HANDLE per handle that
 * actually fired, and derives IoStatus.Information from the compacted
 * output pointer -- so zero events completes with
 * Information == offsetof(AFD_POLL_INFO, Handles) == 16, the header
 * alone.  (ReactOS instead reports the caller's uncompacted input
 * count, which is one more place the two disagree.)  IOCTL_AFD_SELECT
 * is METHOD_BUFFERED, so only Information bytes are copied back and
 * everything past them keeps whatever the caller left there.
 *
 * Two consequences, both used below.  The number of entries that may
 * be read is bounded by the reply's NumberOfHandles, never by what was
 * asked for.  And Information itself is a stride measurement in its
 * own right: for a compacted reply of k entries it must be exactly
 * 16 + k * (sizeof(HANDLE) + 8), so a driver using any other element
 * size would be caught by the byte count before the contents were even
 * looked at.
 *
 * *** Compaction is observed, not merely reasoned. ***
 *
 * Stated at the same standard as the +16 offset above, because two
 * exact assertions rest on it -- check_pattern()'s CHECK_EQ on `count`
 * and on Information -- and a premise carrying that much weight should
 * not be the one unsourced sentence in this file.
 *
 * The competing hypothesis is specific: a non-compacting AFD would
 * return the caller's full N-entry array, events zeroed for the
 * handles that did not fire, reporting count == N and
 * Information == 16 + N * H_SIZE for every pattern regardless of how
 * many sockets were ready.  (That is exactly what ReactOS's AfdPoll
 * does -- it reports the caller's uncompacted input count -- so this
 * is not a hypothetical shape, it is a shipping one.)
 *
 * Under that hypothesis CHECK_EQ(count, nready) fails for every
 * pattern whose ready count is not NSOCK: seven of the eight distinct
 * patterns run below, and nine of the ten calls.  The zero control
 * would fail twice over, since entries written at +16 would also
 * destroy the poison its CHECK depends on.  A non-compacting NT could
 * therefore not have produced a green run -- it would have produced a
 * near-total red one.
 *
 * Those assertions have now run against real AFD three times, green on
 * all three windows-test legs each time: CI runs 32911726595 (the
 * six-pattern revision), 32912617219 (eight patterns) and 32913414954,
 * on real Windows build 26100.  So real NT compacts, and this file
 * measured it rather than assuming it.  Wine and the native asan build
 * cannot reach AFD and skip, so they are not evidence either way.
 *
 * *** Poisoning. ***
 *
 * Every reply buffer is filled with 0xAB before every ioctl, and the
 * poison is *read back and asserted non-zero* before the call (see
 * poll_multi()).  A test asserting that a count came back zero cannot
 * otherwise distinguish "the driver wrote zero" from "the driver wrote
 * nothing and the buffer was already zero" -- which is precisely the
 * bug src/select/select.c's banner records, where an aliased buffer
 * made "nothing fired" read back as "everything fired".  Same
 * discipline as test/posix-select-socket.c's `revents = -1` and
 * test/posix-socket-accept.c's poisoned pre-parse.
 *
 * *** Negative controls. ***
 *
 * Two deliberately-wrong wire images are sent to the same device, in
 * the same readiness state (middle only), and must NOT produce the
 * right answer -- see test_wrong_layouts().  One moves the array base
 * to ReactOS's +24; the other keeps the base at +16 and widens the
 * *element* to 24 bytes.  The second isolates the stride from the
 * base, which is the whole point of the file: the existing observation
 * already covers the base.  Without these, "the correct layout worked"
 * is unfalsifiable -- a driver that ignored the array entirely and
 * always named every handle would pass the positive assertions.
 *
 * *** Both ABIs, for coverage -- not because a constant might be wrong. ***
 *
 * The pitch is 16 bytes on x86_64 and 12 on i386, and it is that way
 * *by construction* on both sides: src/internal/afd.h:750 spells it
 * #define AFD_POLL_H_SIZE (sizeof(HANDLE) + 8), the offsets around it
 * derive the same way, and H_SIZE below is (sizeof(void *) + 8) for
 * the same reason.  There is no hardcoded 16 anywhere that could be
 * wrong on i386.  That matches Wine's own afd_poll_params_32.
 *
 * So the i386 leg is run because a measurement that has only ever been
 * taken on one ABI is a measurement on one ABI, not because a constant
 * is suspected there.  Note one consequence, handled in
 * test_wrong_layouts() below: on i386 a HANDLE is 4 bytes, ReactOS's
 * +24 collapses to +16, and the "ReactOS base" negative control stops
 * being a *different* wire image at all.  It is skipped there rather
 * than run as a control that cannot fail, which would be exactly the
 * vacuous-assertion failure this file is written against.
 *
 * *** Environments. ***
 *
 * Same three as test/posix-select-socket.c and test/posix-socket.c: a
 * \Device\Afd endpoint answering real AFD ioctls exists only on real
 * Windows (CI's `windows-test` legs), which is the authority for
 * everything here.  Stock Wine's AFD only wires up handles opened via
 * its own IOCTL_AFD_WINE_CREATE, and the native `make asan` build has
 * no AFD device node at all.  Both fail the capability probe, print
 * one SKIP line and exit 77 -- tools/runtests.sh's and
 * tools/asan-build.sh's third bucket, "ran, verified nothing new".
 * Note that tools/asan-build.sh does NOT filter *-win.c the way the
 * Makefile's TEST_RUN does (see its posix-kill-perm-win entry, which
 * says so explicitly), so this file is deliberately named without the
 * -win suffix: it behaves correctly everywhere rather than relying on
 * a filter only one of the two harnesses applies.
 *
 * *** What counts as an oracle here, and what does not. ***
 *
 * Real NT only.  Two near-misses are worth naming so they are not
 * mistaken for corroboration later:
 *
 *   - CI's three `windows-test` legs are ONE Windows build wearing
 *     three labels.  All three are runs-on: windows-latest; the matrix
 *     varies only the artefact architecture, and the measured OS is
 *     identical across them (build 26100, UBR 33296).  Three green
 *     cells there are one observation, not three.
 *
 *   - ReactOS's own AFD is the implementation under test, not an
 *     independent oracle.  A run of this shape against ReactOS
 *     disagreeing with real NT is diagnostic; agreeing with it is
 *     weak, and must not be cited as confirmation.
 *
 *     That case is now concrete rather than hypothetical.  A parallel
 *     probe of this shape was run BY ANOTHER SESSION against
 *     ReactOS's AFD on amd64 -- the reading below is relayed, not
 *     reproduced here, unlike the msafd/afd.sys source facts above,
 *     which were read directly in the tree at d610480e: two
 *     ready UDP sockets at request slots 1 and 3 of 5, one
 *     multi-handle ioctl, giving Information == 48 (16 + 2 * 16),
 *     HandleCount == 2, reply[0] naming slot 1 at +16 and reply[1]
 *     naming slot 3 at +32, with 0xCC fill surviving from +48.  Pitch
 *     exactly 16, compaction confirmed (input slots 1 and 3 arriving
 *     as output entries 0 and 1), and the two ready slots
 *     deliberately non-adjacent so the reading discriminates rather
 *     than merely being consistent.
 *
 *     That is recorded as a FACT ABOUT REACTOS, not about NT.  It
 *     agrees with this file's real-NT readings, and by the rule
 *     immediately above that agreement is WEAK -- neither
 *     implementation is an independent oracle for the other, and two
 *     implementations reading a shared specification the same way is
 *     the cheapest kind of agreement there is.  The honest summary of
 *     the pair is the one its author gave: no disagreement to report.
 *     Nothing in this file rests on it.
 *
 * For the same reason this banner does not lean on afd.h's tally of
 * "four places where CI sided against ReactOS".  Every one of those
 * four was adjudicated by the same one-handle probe, so invoking the
 * count here would launder a prior into evidence for the very thing
 * the prior could not see.
 *
 * Every C file under test/ is built with -Iarch/$(ARCH)
 * -Iarch/generic -Iobj/include -Iinclude only -- src/internal/ is NOT
 * on the include path -- so every prototype, constant and offset below
 * is declared locally, as the siblings do.  A layout test that
 * included the header it checks would agree with it by construction.
 *
 * (That sentence is spelled "every C file under test/" rather than
 * with the glob, deliberately: the glob puts a slash-star inside a
 * block comment, which is a -Wcomment warning.  The prior draft of
 * this file had exactly that, and it is the same defect that was
 * failing CI's lint(warn) stage on main at ea9619e
 * (src/signal/signal.c:123) -- caught here only because it was
 * checked for, since that stage builds the library and not test/.)
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <signal.h>

static int fails;
static int unverified;

#define CHECK(cond) do { if (!(cond)) { fails++; \
	printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_EQ(got, want, what) do { \
	unsigned long long g_ = (unsigned long long)(got), w_ = (unsigned long long)(want); \
	if (g_ != w_) { fails++; \
		printf("FAIL %s:%d: %s = %llu (0x%llx), want %llu (0x%llx)\n", \
		       __FILE__, __LINE__, (what), g_, g_, w_, w_); } \
} while (0)

/* Distinct from posix-socket.c's 55123 and posix-select-socket.c's
 * 55137: tools/runtests.sh runs tests in parallel, and getsockname()
 * does not exist here (see <sys/socket.h>), so an ephemeral port
 * cannot be discovered and a fixed one in RFC 6335's dynamic range is
 * the same trade-off both siblings make. */
#define TEST_PORT 55141
#define WAIT_MS   5000
#define NSOCK     3

/* ---- src/internal/, re-declared; see the banner ------------------- */

/* HANDLE is PVOID (winnt.h); NTSTATUS is int (src/internal/nt.h). */
void *__fd_handle(int fd);
int __afd_ioctl(void *h, unsigned long code, void *in, unsigned long inlen,
                void *out, unsigned long outlen, void *io_out);

/* IO_STATUS_BLOCK: { union { NTSTATUS Status; PVOID Pointer; };
 *                    ULONG_PTR Information; } -- a pointer-sized union
 * followed by a pointer-sized integer, on both ABIs. */
struct iosb { void *ptr; size_t info; };

/* _AFD_CONTROL_CODE(AFD_SELECT = 9, METHOD_BUFFERED) == 0x00012024;
 * spelled as the literal the way wepoll and libuv spell it. */
#define IOCTL_AFD_SELECT 0x00012024UL

#define STATUS_SUCCESS         0
#define STATUS_INVALID_HANDLE  ((int)0xC0000008)

/* The event bits all four sources agree on. Only receive-side bits are
 * requested: a connected idle socket is always *writable*, so asking
 * for AFD_POLL_SEND would make every handle ready in every pattern and
 * destroy the discrimination this file is built on. */
#define EV_RECEIVE      0x0001u
#define EV_DISCONNECT   0x0008u
#define EV_ABORT        0x0010u
#define EV_LOCAL_CLOSE  0x0020u
#define READ_BITS (EV_RECEIVE | EV_DISCONNECT | EV_ABORT | EV_LOCAL_CLOSE)

/* The layout under test.  size_t throughout, never unsigned long: this
 * target is LLP64, so i * H_SIZE in unsigned long would multiply in 32
 * bits and only then widen. */
#define HSZ              (sizeof(void *))
#define REQ_HANDLE_COUNT ((size_t)8)
#define REQ_HANDLES      ((size_t)16)          /* NOT ReactOS's +24 */
/* H_SIZE MIRRORS src/internal/afd.h's AFD_POLL_H_SIZE RATHER THAN
 * PINNING IT, and that is deliberate even though a reader may expect
 * the opposite from a layout test.  Both are spelled
 * (sizeof(HANDLE) + 8) from the same reasoning, so if AFD_POLL_H_SIZE
 * were changed this constant would follow it silently instead of
 * failing and catching the change.
 *
 * That is correct here because the subject of this file is the WIRE,
 * not the constant.  A test that pinned 16/12 as literals would fail
 * whenever the header changed, whether or not the driver agreed -- it
 * would be testing that nobody edited afd.h, which git already does
 * better.  What this file asserts is that whatever pitch the library
 * believes in, a real AFD driver agrees with it: change
 * AFD_POLL_H_SIZE and the next windows-test leg re-measures the new
 * value against the device and goes red if the device disagrees.
 *
 * Note that NOTHING pins the number: test/posix-socket-poll.c, the
 * device-free sibling, spells its own H_SIZE as (HSZ + 8) too (its
 * :141), so it mirrors the header exactly as this file does and would
 * track the same change just as silently.  Neither test would catch an
 * edit to AFD_POLL_H_SIZE; what this one catches is a real driver
 * disagreeing with whatever value the edit produced, which is the
 * question worth asking about a wire format. */
#define H_SIZE           (HSZ + 8)             /* 16 on x86_64, 12 on i386 */
#define H_EVENTS         HSZ
#define REQ_SIZE(n)      (REQ_HANDLES + (size_t)(n) * H_SIZE)

/* ReactOS's ULONG_PTR Exclusive, for the negative control. */
#define ROS_HANDLES      (HSZ == 8 ? (size_t)24 : (size_t)16)

#define POISON 0xABu
#define MAXBUF 256   /* comfortably over REQ_HANDLES + NSOCK * 24 */

/* Both buffers are declared through this union rather than as bare
 * char arrays: Timeout is a LARGE_INTEGER at +0, and a byte array has
 * no alignment guarantee at all. */
union buf { unsigned char b[MAXBUF]; long long align_ll; void *align_p; };

/* Byte-image readers: the buffer is an NT structure on the wire, so it
 * is decoded byte-wise rather than cast to a struct, which would
 * assume the very layout under test. */
static unsigned long rd32(const unsigned char *p)
{
	return (unsigned long)p[0] | ((unsigned long)p[1] << 8)
	     | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}
static unsigned long long rdptr(const unsigned char *p)
{
	unsigned long long v = 0;
	size_t i;
	for (i = 0; i < HSZ; i++) v |= (unsigned long long)p[i] << (8 * i);
	return v;
}
static void wr32(unsigned char *p, unsigned long v)
{
	p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8);
	p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24);
}
static void wr64(unsigned char *p, unsigned long long v)
{
	wr32(p, (unsigned long)(v & 0xFFFFFFFFULL));
	wr32(p + 4, (unsigned long)(v >> 32));
}
static void wrptr(unsigned char *p, void *h)
{
	unsigned long long v = (unsigned long long)(uintptr_t)h;
	size_t i;
	for (i = 0; i < HSZ; i++) p[i] = (unsigned char)(v >> (8 * i));
}

/* Build an AFD_POLL_INFO request by hand, with the array base and the
 * element stride as *parameters*.  The correct call passes
 * (REQ_HANDLES, H_SIZE); the negative controls pass a wrong base or a
 * wrong stride and nothing else changes, so the two calls are
 * indistinguishable to the driver except in the one respect under
 * test.  Returns the request length. */
static size_t build_req(unsigned char *buf, size_t base, size_t stride,
                        void *const *hs, size_t n, unsigned long events)
{
	size_t len = base + n * stride, i;

	memset(buf, 0, len);
	wr64(buf + 0, 0);                       /* Timeout: never wait */
	wr32(buf + REQ_HANDLE_COUNT, (unsigned long)n);
	wr32(buf + 12, 0);                      /* Unique/Exclusive: always zero.
	                                         * A non-zero Unique would make
	                                         * this poll supersede and cancel
	                                         * another one on the same file
	                                         * object -- see afd.h. */
	for (i = 0; i < n; i++) {
		unsigned char *e = buf + base + i * stride;
		wrptr(e + 0, hs[i]);
		wr32(e + H_EVENTS, events);
		wr32(e + H_EVENTS + 4, 0);      /* Status */
	}
	return len;
}

/* Issue one multi-handle poll.  The reply buffer is separate from the
 * request (aliasing them is what once made "nothing fired" read back
 * as "everything fired" -- src/select/select.c's banner) and is
 * poisoned, with the poison asserted present, before the call.
 *
 * *count and *info receive the reply's own NumberOfHandles and the
 * IoStatus.Information byte count.  Returns the NTSTATUS. */
static int poll_multi(void *dev, void *const *hs, size_t n,
                      size_t base, size_t stride,
                      unsigned char *rep, unsigned long *count, size_t *info)
{
	union buf req;
	struct iosb io;
	size_t len = build_req(req.b, base, stride, hs, n, READ_BITS);
	int st;

	memset(rep, POISON, MAXBUF);
	/* The poison must be *observable* before the call, or a zero
	 * afterwards proves nothing about who wrote it. */
	CHECK(rd32(rep + REQ_HANDLE_COUNT) != 0);

	io.ptr = 0; io.info = (size_t)-1;
	st = __afd_ioctl(dev, IOCTL_AFD_SELECT, req.b, (unsigned long)len,
	                 rep, (unsigned long)len, &io);
	*count = rd32(rep + REQ_HANDLE_COUNT);
	*info = io.info;
	return st;
}

/* The reply is compacted, so entry i names whichever handle fired i-th
 * -- there is no relation between i and the request's slot i.  Every
 * assertion below is therefore about handle *identity*. */
static void *rep_handle(const unsigned char *rep, size_t i)
{
	return (void *)(uintptr_t)rdptr(rep + REQ_HANDLES + i * H_SIZE);
}
static unsigned long rep_events(const unsigned char *rep, size_t i)
{
	return rd32(rep + REQ_HANDLES + i * H_SIZE + H_EVENTS);
}

/* ---- the fixture ------------------------------------------------- */

static int make_loopback_addr(struct sockaddr_in *a)
{
	memset(a, 0, sizeof *a);
	a->sin_family = AF_INET;
	a->sin_port = htons(TEST_PORT);
	a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	return sizeof *a;
}

static int listener = -1;
static int cli[NSOCK], srv[NSOCK];
static void *h[NSOCK];

static int network_probe(void)
{
	struct sockaddr_in addr;
	int s;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		printf("SKIP posix-socket-pollmulti (socket() failed, errno=%d)\n", errno);
		unverified++;
		return -1;
	}
	if (bind(s, (struct sockaddr *)&addr, make_loopback_addr(&addr)) < 0) {
		printf("SKIP posix-socket-pollmulti (bind() failed, errno=%d; "
		       "IOCTL_AFD_BIND on a \\Device\\Afd\\Endpoint handle -- see "
		       "test/posix-socket.c and test/networking-audit.md sec 1)\n", errno);
		close(s);
		unverified++;
		return -1;
	}
	if (listen(s, NSOCK + 1) < 0) {
		printf("SKIP posix-socket-pollmulti (listen() failed, errno=%d)\n", errno);
		close(s);
		unverified++;
		return -1;
	}
	return s;
}

/* Is fd readable right now, according to the library's own one-handle
 * probe?  Used only to *establish* the readiness pattern before each
 * multi-handle measurement, never as the measurement: it goes through
 * select(), which issues its own single-handle ioctl and so cannot
 * exercise a stride at all. */
static int readable_now(int fd, int ms)
{
	fd_set r;
	struct timeval tv;

	FD_ZERO(&r);
	FD_SET(fd, &r);
	tv.tv_sec = ms / 1000;
	tv.tv_usec = (ms % 1000) * 1000;
	return select(fd + 1, &r, 0, 0, &tv) > 0 && FD_ISSET(fd, &r);
}

/* Drive srv[] into exactly the readiness pattern `want` (bit i set ==
 * srv[i] must have data pending), and verify it got there before any
 * measurement is taken.  Returns 0 on success. */
static int set_pattern(unsigned want)
{
	int i, ok = 1;

	for (i = 0; i < NSOCK; i++) {
		int should = (want >> i) & 1;
		int is = readable_now(srv[i], 0);
		if (should && !is) {
			if (send(cli[i], "x", 1, 0) != 1) { ok = 0; continue; }
			is = readable_now(srv[i], WAIT_MS);
		} else if (!should && is) {
			char c;
			while (readable_now(srv[i], 0) && recv(srv[i], &c, 1, 0) == 1)
				;
			is = readable_now(srv[i], 0);
		}
		if (is != should) ok = 0;
	}
	if (!ok) {
		fails++;
		printf("FAIL %s:%d: could not establish readiness pattern 0x%x\n",
		       __FILE__, __LINE__, want);
		return -1;
	}
	return 0;
}

/* Emit the raw reading for one ioctl, whatever the verdict.
 *
 * The "measure:" prefix is tools/run-tests.py's MEASURE_PREFIX: lines
 * carrying it are echoed by the harness even when the test PASSES,
 * where ordinary stdout is suppressed (its report() prints a passing
 * test's output not at all).  That suppression is why an earlier run of
 * this file could only be reported as a verdict -- "PASS", with the
 * measured Information byte counts and handle identities discarded by
 * the harness before anyone could read them.
 *
 * A verdict answers the question that was asked; raw values answer the
 * next one.  The assertions below are exact -- Information must be
 * 16 + k * H_SIZE -- so a PASS *is* the numeric claim and nothing here
 * weakens it.  But the next question about AFD's poll wire format will
 * arrive without these numbers unless they are in the log, and
 * re-deriving them costs a CI run on hardware that only CI has. */
static void measure(const char *kind, const char *name, unsigned want,
                    size_t nready, size_t base, size_t stride,
                    int st, unsigned long count, size_t info,
                    const unsigned char *rep)
{
	unsigned long k;

	/* Information is printed at full width, not through (unsigned):
	 * it is a size_t, poll_multi() seeds it with (size_t)-1 as a
	 * did-not-write sentinel, and truncating that to 32 bits would
	 * report 4294967295 for a value that is not 4294967295.  A raw
	 * reading that has been narrowed is not a raw reading. */
	printf("measure: pollmulti %s=%s want=0x%x nready=%u base=%u stride=%u "
	       "st=0x%08x count=%lu Information=%llu",
	       kind, name, want, (unsigned)nready, (unsigned)base,
	       (unsigned)stride, (unsigned)st, count,
	       (unsigned long long)info);
	/* Bounded by NSOCK as well as by count: on a failed ioctl `count`
	 * is read out of the poison and is not a length. */
	for (k = 0; k < count && k < (unsigned long)NSOCK; k++) {
		void *rh = rep_handle(rep, (size_t)k);
		int j, found = -1;
		for (j = 0; j < NSOCK; j++) if (h[j] == rh) found = j;
		printf(" [%lu]handle=%p events=0x%lx srv=%d",
		       k, rh, rep_events(rep, (size_t)k), found);
	}
	/* The byte at the array base, reported neutrally rather than as
	 * "poison": it IS the surviving poison only when nothing was
	 * copied back (the zero control), and is the first handle byte
	 * whenever an entry was written.  Labelling it "poison"
	 * unconditionally would name a value after a hypothesis about it. */
	printf(" rep[%u]=0x%02x\n", (unsigned)base, rep[base]);
}

/* One pattern, measured with the correct layout. */
static void check_pattern(unsigned want, const char *name)
{
	union buf rep;
	unsigned long count = 0;
	size_t info = 0;
	int st, i;
	unsigned seen = 0;
	size_t nready = 0;

	if (set_pattern(want) < 0) return;
	for (i = 0; i < NSOCK; i++) if ((want >> i) & 1) nready++;

	st = poll_multi(h[0], h, NSOCK, REQ_HANDLES, H_SIZE,
	                rep.b, &count, &info);
	measure("pattern", name, want, nready, REQ_HANDLES, H_SIZE,
	        st, count, info, rep.b);
	if (st != STATUS_SUCCESS) {
		fails++;
		printf("FAIL %s:%d: pattern %s: ioctl st=0x%08x\n",
		       __FILE__, __LINE__, name, (unsigned)st);
		return;
	}

	/* Bounded by the reply's own count, never by what was asked.
	 *
	 * READ A FAILURE OF THIS PAIR AS AN APPARATUS FAILURE FIRST.  This
	 * CHECK and the Information one below both test the *compaction*
	 * premise (see the banner): that AFD returns one entry per handle
	 * that fired rather than the caller's whole array.  A mismatch here
	 * says that premise is unconfirmed on whatever ran it -- NOT that
	 * the element pitch is wrong.  The two questions are independent
	 * and they fail in different shapes:
	 *
	 *   count == NSOCK for every pattern, including the zero control,
	 *   and Information == 16 + NSOCK * H_SIZE throughout
	 *       -> the driver did not compact.  The stride is untested by
	 *          this run, not disproved.  Nothing about the pitch has
	 *          been shown either way.
	 *
	 *   count tracks nready correctly but Information disagrees, or the
	 *   identity loop below names a not-ready handle
	 *       -> compaction held and the pitch itself is in question.
	 *          That is a stride finding.
	 *
	 * Filing the first shape as a stride bug is the mistake this
	 * comment exists to prevent; it is the same reason
	 * flush_probe_channel_works() states what a broken probe looks
	 * like separately from what a broken flush looks like. */
	CHECK_EQ(count, nready, name);
	/* Information is derived from the compacted output pointer, so it
	 * is an independent measurement of the element size -- and for the
	 * single-ready patterns it is the ONLY check that can see a wrong
	 * pitch at all, because a one-entry compacted reply puts that entry
	 * at element 0 whatever the pitch is.  Not redundant with the
	 * identity loop below; see the banner's measured table.  On a
	 * failure, read the disambiguation above the count CHECK first --
	 * this assertion tests compaction and pitch together, and only the
	 * count CHECK separates them. */
	CHECK_EQ(info, REQ_HANDLES + nready * H_SIZE, "IoStatus.Information");
	if (nready == 0) {
		/* The zero control.  Nothing past +16 was copied back, so the
		 * poison must still be there -- which is the same-run evidence
		 * that a zero count means "the driver wrote zero", not "the
		 * driver wrote nothing". */
		CHECK(rep.b[REQ_HANDLES] == POISON);
		printf("  %-12s count=0 Information=%u (header only), poison intact\n",
		       name, (unsigned)info);
		return;
	}
	if (count != nready) return;   /* already charged; do not read past it */

	for (i = 0; (size_t)i < nready; i++) {
		void *rh = rep_handle(rep.b, (size_t)i);
		int j, found = -1;
		for (j = 0; j < NSOCK; j++) if (h[j] == rh) found = j;
		if (found < 0) {
			fails++;
			printf("FAIL %s:%d: pattern %s: reply entry %d names handle %p, "
			       "which is none of the three requested\n",
			       __FILE__, __LINE__, name, i, rh);
			continue;
		}
		if (!((want >> found) & 1)) {
			fails++;
			printf("FAIL %s:%d: pattern %s: reply entry %d names srv[%d], "
			       "which is NOT ready -- a wrong answer, and in production "
			       "an idle socket reported readable\n",
			       __FILE__, __LINE__, name, i, found);
			continue;
		}
		if (seen & (1u << found)) {
			fails++;
			printf("FAIL %s:%d: pattern %s: srv[%d] named twice\n",
			       __FILE__, __LINE__, name, found);
			continue;
		}
		seen |= 1u << found;
		CHECK((rep_events(rep.b, (size_t)i) & EV_RECEIVE) != 0);
	}
	CHECK_EQ(seen, want, name);
	printf("  %-12s count=%lu Information=%u handles=%s\n",
	       name, count, (unsigned)info, seen == want ? "exactly the ready set" : "WRONG");
}

/* Every pattern, over the same three sockets and the same device. */
static void test_patterns(void)
{
	printf("posix-socket-pollmulti: %d-handle IOCTL_AFD_SELECT, "
	       "Handles at +%u stride %u\n",
	       NSOCK, (unsigned)REQ_HANDLES, (unsigned)H_SIZE);
	/* Restated in the log, not just the banner: a green run here says
	 * the multi-handle pitch is right, NOT that the shipped poll path
	 * was exercised.  select()/poll() issue N single-handle ioctls and
	 * never reach this array; see the banner's three-way split. */
	printf("  (latent-hazard guard: shipped select()/poll() issue N "
	       "SINGLE-handle ioctls and never batch; a pass here does not "
	       "verify that path)\n");
	check_pattern(0x0, "none");
	/* 1 ready: the identity assertions are BLIND to a reply-side pitch
	 * error here (compaction puts the single entry at element 0, which
	 * is base + 0 * stride for every stride).  Information is what
	 * discriminates these three -- see the banner's measured table. */
	check_pattern(0x1, "first");
	check_pattern(0x2, "middle");
	check_pattern(0x4, "last");
	/* 2 ready: the smallest replies whose *identity* content depends on
	 * the pitch.  All three two-ready sets are run -- a gap in the
	 * middle, and a set that does not start at slot 0 -- because these
	 * are the ones carrying the absence assertion.
	 *
	 * Hardware status, recorded here rather than only in a report,
	 * following the EXPECT_MEASURE rows in test/sparse-zerodata.c: all
	 * three two-ready patterns were asserted before any of them had
	 * touched a real AFD device.  first+last shipped in the first
	 * revision of this file and was confirmed by CI run 32911726595
	 * (all three windows-test legs).  first+mid and mid+last were added
	 * afterwards, on the strength of the compaction argument above
	 * rather than of a measurement, and were confirmed separately by
	 * CI run 32912617219 -- windows-test x86_64, i386 and
	 * x86_64-kernel32, all three PASS.  Both runs are on real Windows
	 * (build 26100); Wine and the native asan build cannot reach AFD
	 * and skip.  If a pattern is added here, it is unconfirmed until a
	 * windows-test leg has run it, and this comment is where that is
	 * recorded. */
	check_pattern(0x3, "first+mid");
	check_pattern(0x5, "first+last");
	check_pattern(0x6, "mid+last");
	check_pattern(0x7, "all");
	check_pattern(0x5, "first+last-2"); /* re-run: a latch would show here */
	check_pattern(0x0, "none-2");
}

/* The two deliberately-wrong images, sent to the same device in the
 * middle-only state.  Neither may produce the right answer.  A driver
 * that ignored the array and always named everything, or that happened
 * to be tolerant of either error, is caught here and only here. */
static void test_wrong_layouts(void)
{
	struct { size_t base, stride; const char *name; } bad[] = {
		{ 0, 0, "ReactOS base +24" },
		{ 0, 0, "base +16, stride 24" },
	};
	int k;

	bad[0].base = ROS_HANDLES;   bad[0].stride = H_SIZE;
	bad[1].base = REQ_HANDLES;   bad[1].stride = H_SIZE + 8;

	if (set_pattern(0x2) < 0) return;

	for (k = 0; k < 2; k++) {
		union buf rep;
		unsigned long count = 0;
		size_t info = 0;
		int st, right = 0;

		if (bad[k].base == REQ_HANDLES && bad[k].stride == H_SIZE) {
			/* i386: ReactOS's +16 *is* the correct base, so that
			 * control is vacuous there and is not run as one. */
			printf("  control %-22s not distinguishable on this ABI; skipped\n",
			       bad[k].name);
			continue;
		}
		st = poll_multi(h[0], h, NSOCK, bad[k].base, bad[k].stride,
		                rep.b, &count, &info);
		measure("control", bad[k].name, 0x2, 1, bad[k].base,
		        bad[k].stride, st, count, info, rep.b);
		/* "The right answer" is precisely: succeeded, named exactly
		 * one handle, and that handle was srv[1]. */
		if (st == STATUS_SUCCESS && count == 1 && rep_handle(rep.b, 0) == h[1])
			right = 1;
		if (right) {
			fails++;
			printf("FAIL %s:%d: control '%s' produced the CORRECT answer -- "
			       "this device does not discriminate the layout, so the "
			       "positive results above measure nothing\n",
			       __FILE__, __LINE__, bad[k].name);
		} else {
			printf("  control %-22s rejected: st=0x%08x count=%lu Information=%u\n",
			       bad[k].name, (unsigned)st, count, (unsigned)info);
		}
	}
}

int main(void)
{
	struct sockaddr_in peer, addr;
	socklen_t peerlen;
	int i;

	signal(SIGPIPE, SIG_IGN);

	listener = network_probe();
	if (listener < 0) {
		printf("posix-socket-pollmulti: %d assertion group(s) unverified in "
		       "this environment (see SKIP line above); nothing ran\n", unverified);
		return 77;
	}

	for (i = 0; i < NSOCK; i++) { cli[i] = -1; srv[i] = -1; }
	for (i = 0; i < NSOCK; i++) {
		cli[i] = socket(AF_INET, SOCK_STREAM, 0);
		CHECK(cli[i] >= 0);
		if (cli[i] < 0) goto out;
		CHECK(connect(cli[i], (struct sockaddr *)&addr,
		              make_loopback_addr(&addr)) == 0);
		peerlen = sizeof peer;
		srv[i] = accept(listener, (struct sockaddr *)&peer, &peerlen);
		CHECK(srv[i] >= 0);
		if (srv[i] < 0) goto out;
		h[i] = __fd_handle(srv[i]);
		CHECK(h[i] != 0);
		if (!h[i]) goto out;
	}

	/* Three *distinct* handles, or "the reply named the right one" is
	 * not a claim: identical handles would make every pattern pass. */
	CHECK(h[0] != h[1]);
	CHECK(h[1] != h[2]);
	CHECK(h[0] != h[2]);
	if (fails) goto out;

	test_patterns();
	test_wrong_layouts();

out:
	for (i = 0; i < NSOCK; i++) {
		if (srv[i] >= 0) close(srv[i]);
		if (cli[i] >= 0) close(cli[i]);
	}
	close(listener);

	if (fails) { printf("posix-socket-pollmulti: failures: %d\n", fails); return 1; }
	if (unverified) {
		printf("posix-socket-pollmulti: %d assertion group(s) unverified in "
		       "this environment (see SKIP lines above)\n", unverified);
		return 77;
	}
	printf("posix-socket-pollmulti: all ok\n");
	return 0;
}
