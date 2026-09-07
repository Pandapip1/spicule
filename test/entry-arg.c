/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * What does the operating system actually pass as the first argument to a
 * CUI (Subsystem 3) PE image's entry point?
 *
 * crt/crt1.c read the PEB out of that argument for most of this project's
 * life, on the strength of what ntdll's RtlUserThreadStart does.  It no
 * longer does -- the PEB now comes from the TEB -- which is what turns
 * this file into a measurement rather than a self-check: the CRT no
 * longer has a stake in the answer.  Three implementations may not agree
 * about it:
 *
 *   - Wine forwards it: dlls/ntdll/unix/server.c passes the PEB as `arg'
 *     and BaseThreadInitThunk hands it on to the entry point.
 *   - ReactOS does not: its BaseProcessStartup calls the entry point
 *     through PPROCESS_START_ROUTINE, which is
 *     `DWORD (WINAPI *)(VOID)' -- no arguments at all.  Reading the slot
 *     there is reading whatever the caller happened to leave behind.
 *   - Real Windows is undocumented.  Microsoft's /ENTRY page says only
 *     that "the parameters and return value depend on if the program is a
 *     console application, a windows application or a DLL", and MSVC's
 *     own mainCRTStartup is declared to take nothing.  That is a citation,
 *     not a measurement, which is why this file exists.
 *
 * The only evidence anyone had for real Windows was the *absence of a
 * crash*: our CRT read that slot and CI stayed green.  A pointer that is
 * never dereferenced wrongly is not a pointer that was read.
 *
 *
 * WHAT THIS MEASURES, AND WHAT IT CANNOT
 * --------------------------------------
 * The disagreement above is a *version* axis, not a vendor axis, and this
 * file only ever reads one point on it.  Read the number this test prints,
 * not the sentence "Windows passes the PEB".
 *
 *   - NT 4.0 through Server 2003 enter a new process at
 *     kernel32!BaseProcessStart, reached through BaseProcessStartThunk.
 *     NT 4.0's thunk is instruction-for-instruction identical to ReactOS's
 *     -- `xor ebp,ebp / push eax / push 0x0 / jmp BaseProcessStart' -- and
 *     forwards NO argument to the image entry point.  Measured on NT 4 with
 *     NTSD, the dwords above the entry-point ESP are byte-identical to a
 *     prior dump of the CONTEXT block: stale stack, not pushed arguments.
 *     ReactOS is correct for the target it aims at.
 *   - Vista and later unified on ntdll!RtlUserThreadStart, whose thread
 *     parameter IS the PEB, and which is the caller this CRT was written
 *     against.  ReactOS's own ntdll.spec:1256 marks RtlUserThreadStart
 *     `-version=0x600+', i.e. Vista and up.
 *
 * Our real-Windows CI legs are Server 2025, build 26100 -- and all three
 * of them are ONE Windows build wearing three labels: same runs-on, the
 * matrix varies only the artifact arch, and the build has been measured
 * identical across all three.  26100 is Vista+, so what this test can
 * confirm there is the half that was never in dispute.  It says NOTHING
 * about NT 5.x, and a future reader who takes a green 26100 line as
 * "Windows passes the PEB" has made exactly the generalisation that
 * produced the original ReactOS fault.
 *
 * Wine cannot be pressed into service as the missing cross-check either.
 * `grep BaseProcessStart' across Wine's dlls/ and include/ returns zero
 * hits: Wine implements only the Vista+ shape, so it is structurally
 * incapable of being evidence about NT 5.x.  Running this test under Wine
 * is a check that the *reading mechanism* works, and nothing more; do not
 * add a Wine leg here believing it corroborates a version claim.
 *
 * The value this file does have is that it is a reading rather than an
 * inference, that it would catch outcome 2 (the slot holds something other
 * than the PEB on a platform we thought forwarded it), and that it becomes
 * genuinely informative the day anyone runs spicule on an NT 5.x-era
 * target -- where it should report a raw arg0 that is not the PEB.
 *
 *
 * THE READINGS
 * ------------
 * Three independent readings of the same quantity, all printed raw, with
 * no verdict:
 *
 *   A  __entry_arg0   the raw first argument, captured by _start in
 *                     crt/crt1.c before anything can reinterpret it.
 *   B  TEB+0x30/0x60  TEB.ProcessEnvironmentBlock, reached through
 *                     __teb() (fs:0x18 / gs:0x30 -- NT_TIB.Self, a
 *                     distinct read from the PEB slot).  The offsets are
 *                     static-asserted in src/internal/nt.h; this file
 *                     prints offsetof() so the log records the number the
 *                     binary was built with.
 *   C  PebBaseAddress what the kernel says the process's PEB is, via
 *                     NtQueryInformationProcess(ProcessBasicInformation).
 *                     C is the authority and the positive control: if
 *                     B == C, the reading mechanism works, so A != C is a
 *                     finding about A and not about this test.
 *
 * __entry_arg1 -- the *second* argument slot, which nobody claims is passed
 * -- is captured the same way and printed as a control: see crt/crt1.c.  It
 * is what separates "we read the incoming slot" from "this code always
 * reports the PEB".
 *
 * A is then probed for usability -- is it readable at all, does the word
 * at PEB.ProcessParameters point at something readable -- with
 * NtReadVirtualMemory rather than by dereferencing it, so that a null or
 * garbage A produces a printed line instead of an access violation.
 *
 * Assertions: only on what must hold whatever the answer to the open
 * question is (a TEB exists; B agrees with the kernel's C).  Nothing here
 * asserts anything about A.  A is the measurement.
 */
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include "../src/internal/libc.h"

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* Every line the harness must surface even on a PASS carries this prefix;
 * tools/run-tests.py echoes those lines whatever the outcome, because a
 * measurement that only prints when it fails measures nothing. */
#define M "measure: entry-arg "

#define PTR(p) ((unsigned long long)(uintptr_t)(void *)(p))

/* Read n bytes at p without dereferencing it: a bad p comes back as a
 * status, not as an access violation. */
static int peek(const void *p, void *out, size_t n)
{
	SIZE_T got = 0;
	NTSTATUS st = NtReadVirtualMemory(NtCurrentProcess(), (PVOID)p, out, (SIZE_T)n, &got);
	return NT_SUCCESS(st) && got == n;
}

/* Read one pointer-sized word at byte offset `off' from `base'. */
static int peek_ptr(const void *base, size_t off, void **out)
{
	if (!base) return 0;
	return peek((const char *)base + off, out, sizeof *out);
}

int main(void)
{
	PTEB teb = __teb();
	PPEB teb_peb = 0;
	PPEB kernel_peb = 0;
	PROCESS_BASIC_INFORMATION pbi;
	ULONG retlen = 0;
	NTSTATUS st;
	void *a = __entry_arg0;
	void *a1 = __entry_arg1;
	void *a_params = 0, *a_cmdline = 0;
	int a_readable, a_params_ok = 0, a_cmdline_ok = 0;
	unsigned char probe[1];

	memset(&pbi, 0, sizeof pbi);
	st = NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation,
	                               &pbi, (ULONG)sizeof pbi, &retlen);
	if (NT_SUCCESS(st)) kernel_peb = (PPEB)pbi.PebBaseAddress;
	if (teb) teb_peb = teb->ProcessEnvironmentBlock;

	/* ---- the three readings, raw ---------------------------------- */
	printf(M "target_arch=%s ptr_bits=%d\n",
	       sizeof(void *) == 8 ? "x86_64" : "i386", (int)(8 * sizeof(void *)));
	printf(M "A entry_arg0        = 0x%016llx\n", PTR(a));
	printf(M "  entry_arg1 (ctrl)  = 0x%016llx\n", PTR(a1));
	printf(M "B teb               = 0x%016llx\n", PTR(teb));
	printf(M "B teb_peb           = 0x%016llx  (TEB+0x%02x)\n",
	       PTR(teb_peb), (unsigned)offsetof(TEB, ProcessEnvironmentBlock));
	printf(M "C kernel_peb        = 0x%016llx  (NtQueryInformationProcess st=0x%08lx len=%lu)\n",
	       PTR(kernel_peb), (unsigned long)(ULONG)st, (unsigned long)retlen);
	printf(M "eq A==B             = %d\n", a == (void *)teb_peb);
	printf(M "eq A==C             = %d\n", a == (void *)kernel_peb);
	printf(M "eq B==C             = %d\n", (void *)teb_peb == (void *)kernel_peb);
	/* The control: the second argument slot, read by the same mechanism in
	 * the same call.  If this also equalled the PEB the capture would be
	 * suspect; a differing value is what shows arg0 is a real reading. */
	printf(M "eq arg1==C (ctrl, expect 0) = %d\n", a1 == (void *)kernel_peb);

	/* ---- is A usable as a PEB, or merely equal to one? ------------- */
	a_readable = a && peek(a, probe, sizeof probe);
	if (a_readable) {
		a_params_ok = peek_ptr(a, offsetof(PEB, ProcessParameters), &a_params);
		if (a_params_ok && a_params)
			a_cmdline_ok = peek_ptr(a_params,
			                        offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine)
			                        + offsetof(UNICODE_STRING, Buffer), &a_cmdline);
	}
	printf(M "A readable          = %d\n", a_readable);
	printf(M "A ProcessParameters = 0x%016llx  (read_ok=%d, PEB+0x%02x)\n",
	       PTR(a_params), a_params_ok, (unsigned)offsetof(PEB, ProcessParameters));
	printf(M "A CommandLine.Buffer= 0x%016llx  (read_ok=%d)\n",
	       PTR(a_cmdline), a_cmdline_ok);

	/* ---- what this build is running on ----------------------------- */
	/* Printed from C, the authority, so the version stamp is not itself
	 * conditional on the answer above.  A 26100-only measurement is a
	 * measurement of 26100; ReactOS targets NT 5.2, and this line is what
	 * lets a later reader see which version the log speaks for. */
	if (kernel_peb)
		printf(M "os                  = %lu.%lu build %lu, subsystem %lu (3 = CUI)\n",
		       (unsigned long)kernel_peb->OSMajorVersion,
		       (unsigned long)kernel_peb->OSMinorVersion,
		       (unsigned long)kernel_peb->OSBuildNumber,
		       (unsigned long)kernel_peb->ImageSubsystem);

	/* ---- assertions: only what is true whatever A turns out to be --- */
	CHECK(teb != 0);
	CHECK(NT_SUCCESS(st));
	CHECK(kernel_peb != 0);
	/* The positive control.  If this fails, the TEB read is broken and
	 * nothing above may be read as evidence about A. */
	CHECK((void *)teb_peb == (void *)kernel_peb);

	printf("%s\n", fails ? "FAIL" : "PASS");
	return fails != 0;
}
