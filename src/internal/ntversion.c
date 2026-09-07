/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The NT kernel's own version number, and the one sanctioned way to
 * branch on it.
 *
 * *** Read this before adding a second caller. ***
 *
 * Branching on the OS version is a last resort here, not a habit.  The
 * house rule everywhere else in this library is to ask the system what
 * it supports -- call the thing, and treat the failure status as the
 * answer (src/internal/delayload.c resolves an export or does not;
 * src/stat/mkdir.c distinguishes two NtCreateFile dispositions by the
 * status they return).  Probing stays correct on platforms nobody here
 * has heard of; a version test only stays correct for as long as the
 * table of versions is right, and it silently mis-serves anything not
 * in the table.  Prefer the probe.
 *
 * The narrow case that a probe cannot cover, and that this helper
 * exists for, has all three of these properties:
 *
 *   1. Two NT releases read the *same* request buffer with two
 *      different structure layouts;
 *   2. the buffer carries no discriminator -- no version field, no
 *      length, nothing in the bytes themselves that says which layout
 *      is meant.  Both sides simply have to know; and
 *   3. handing the wrong layout to either one *succeeds*.  There is no
 *      failure status to fall back on, because nothing failed.  The
 *      corruption surfaces later, somewhere else, as a different call's
 *      unrelated-looking error.
 *
 * (3) is what rules probing out.  A probe needs a failure to learn
 * from; when the wrong guess returns success, the only thing left to
 * ask is who you are talking to.
 *
 * The first and, at the time of writing, only instance is the AFD
 * socket-creation extended attribute: NT 4/5's 12-byte
 * AFD_CREATE_PACKET against NT 6+'s 24-byte AFD_OPEN_PACKET.  See
 * src/internal/afd.h's socket-creation banner for that case in full,
 * including why ReactOS's own headers say the two cannot be told apart
 * and their apitest picks by GetVersion() for exactly this reason.
 *
 * Anything that does not meet all three tests should probe instead.
 *
 * ---- where the number comes from -------------------------------------
 *
 * PEB.OSMajorVersion / OSMinorVersion, which the kernel fills in when it
 * maps the PEB, so it costs no system call and cannot fail.  It is also
 * what the reference implementations use for this decision.
 *
 * It reports the *kernel's* version, not the shim-adjusted, manifest-
 * dependent number kernel32's GetVersionEx() hands an unmanifested
 * process (and RtlGetVersion() likewise reports the real one) -- which
 * is the version we want, since the question is always "what does the
 * driver on the other end of this ioctl expect".
 *
 * ReactOS reports its NT 5.2 target here; real Windows reports 6.x or
 * 10.x; Wine reports whatever its winecfg version is set to, and
 * defaults to 10.0.
 *
 * *** This is not spicule's minimum supported Windows version. ***
 * That floor is Windows Vista / NTDLL 6.0, set by the ntdll exports this
 * library imports (tools/ntdll.def); it is a statement about which
 * *imports* must resolve.  tools/lint-minver.sh (`make minver`) is the
 * gate that keeps that floor and the marker README.md declares it under
 * in sync with the actual import list.  A platform can satisfy the
 * import floor while reporting an older kernel version here -- ReactOS
 * does exactly that, targeting NT 5.2 above while still implementing and
 * exporting ntdll names newer than that (see tools/ntdll.def's own
 * header for the current list and the versions behind them).  Nothing in
 * this file may be read as lowering or raising that floor.
 */
#include "libc.h"

/* The version to assume when the PEB cannot supply one.  Two callers
 * see this: `make asan`'s native build, whose fuzz/ntstubs.c PEB is a
 * plain static struct, and any hypothetical use before crt1.c has set
 * __peb.  Assuming the *modern* shape there is the deliberate choice:
 * on this project's real target every wire format under discussion is
 * the NT 6+ one, so an unknown platform behaves exactly as today's
 * verified-green path does, and a missing version can never silently
 * turn a working Windows build into the legacy shape.  A test that
 * wants the legacy shape must ask for it by name, not by arranging for
 * detection to fail. */
#define NT_VERSION_ASSUMED_MAJOR 6u
#define NT_VERSION_ASSUMED_MINOR 1u

/* Cached because the PEB's copy never changes for the life of the
 * process, and because a helper this cheap to call will be called from
 * paths that should not re-read memory to answer a constant.
 *
 * 0 means "not yet read"; any other value is (1u << 31) | major << 16 |
 * minor, so the sentinel is distinguishable from a genuine 0.0.  A race
 * between two threads is benign: both read the same PEB and store the
 * same word, and the store is of a naturally-aligned unsigned. */
static unsigned nt_version_cache;

#define NT_VERSION_VALID 0x80000000u
#define NT_VERSION_PACK(maj, min) (NT_VERSION_VALID | ((maj) << 16) | ((min) & 0xffffu))

/* Bit 30 records that the numbers below it are the assumed fallback
 * rather than something read out of a real PEB.  __nt_os_version()
 * hands that fact back to the caller so a diagnostic can say which it
 * printed; nothing in the library's behaviour depends on it. */
#define NT_VERSION_ASSUMED 0x40000000u

static unsigned nt_version(void)
{
	unsigned v = nt_version_cache;
	unsigned long maj, min;

	if (v) return v;

	if (!__peb || !__peb->OSMajorVersion) {
		/* No PEB, or a PEB whose version field is zero -- which is
		 * not a version any NT kernel reports, so it means the
		 * struct was never filled in. */
		v = NT_VERSION_PACK(NT_VERSION_ASSUMED_MAJOR, NT_VERSION_ASSUMED_MINOR)
		  | NT_VERSION_ASSUMED;
	} else {
		maj = (unsigned long)__peb->OSMajorVersion;
		min = (unsigned long)__peb->OSMinorVersion;
		/* Clamped rather than trusted blindly: these are the only
		 * two fields this file reads, they are the source of a
		 * layout decision, and a major version that did not fit
		 * would wrap into the minor's bits. */
		if (maj > 0x3fffu) maj = 0x3fffu;
		if (min > 0xffffu) min = 0xffffu;
		v = NT_VERSION_PACK((unsigned)maj, (unsigned)min);
	}

	nt_version_cache = v;
	return v;
}

/* See libc.h.  Returns 1 when the numbers came from a real PEB, 0 when
 * they are the assumed fallback; *major and *minor are always set. */
int __nt_os_version(unsigned *major, unsigned *minor) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	unsigned v = nt_version();

	if (major) *major = (v >> 16) & 0x3fffu;
	if (minor) *minor = v & 0xffffu;
	return (v & NT_VERSION_ASSUMED) ? 0 : 1;
}

/* See libc.h.  The comparison is on the (major, minor) pair, not on a
 * flattened number: 6.1 is not "61", and 10.0 must compare above 6.3. */
int __nt_version_at_least(unsigned major, unsigned minor) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	unsigned maj, min;

	__nt_os_version(&maj, &min);
	if (maj != major) return maj > major;
	return min >= minor;
}
