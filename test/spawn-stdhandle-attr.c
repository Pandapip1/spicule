/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A measurement, not an assertion: what does a child actually find in
 * PEB->ProcessParameters->StandardInput/Output/Error when the parent
 * writes NULL there, and does an explicit PS_ATTRIBUTE_STD_HANDLE_INFO
 * change the answer?
 *
 * Why this exists.  src/process/spawn.c hands a *closed* standard
 * descriptor a real-but-rejected placeholder handle rather than NULL or
 * INVALID_HANDLE_VALUE, because both sentinels were measured on real
 * Windows to come back to the child as a live, open handle -- i.e. some
 * actor between the parent's write and the child's first instruction
 * replaces whatever the caller wrote, value-blind.  Which actor is not
 * known (see spawn.c's file comment for the full accounting).  The
 * leading candidate is the kernel's own standard-handle duplication
 * inside NtCreateUserProcess, driven by PS_ATTRIBUTE_STD_HANDLE_INFO
 * (phnt, ntpsapi.h:3232 PsAttributeStdHandleInfo, :3364-3390
 * PS_STD_HANDLE_STATE / PS_STD_HANDLE_INFO).
 *
 * The decisive experiment: ntdll's RtlCreateUserProcess (which spawn.c
 * uses, and which Wine's dlls/ntdll/process.c:481 mirrors) passes *no*
 * PsAttributeStdHandleInfo at all, so the child gets whatever the
 * kernel's default state is.  Call NtCreateUserProcess directly instead
 * and supply the attribute explicitly with StdHandleState =
 * PsNeverDuplicate.  If the child then reports NULL where the identical
 * run without the attribute reports a live handle, the candidate is
 * confirmed and the question is closed.
 *
 * Nobody has ever printed the raw value.  Every previous data point is
 * inferred from fcntl(0, F_GETFD) succeeding in a child, which only
 * proves the handle got past install_std()'s guards in
 * src/internal/fd.c -- not what it was.  So the child here prints the
 * raw %p of all three fields, plus ConsoleHandle/ConsoleFlags/
 * WindowFlags, plus NtQueryObject(ObjectTypeInformation) on each
 * non-empty handle so the *kind* of object is on the record too.
 *
 * Variants, all with StandardInput/Output/Error = NULL and
 * STARTF_USESTDHANDLES set:
 *
 *   A  CUI child, no PsAttributeStdHandleInfo   (baseline: what spawn.c
 *                                                effectively gets today)
 *   B  CUI child, StdHandleState=PsNeverDuplicate
 *   C  CUI child, StdHandleState=PsAlwaysDuplicate
 *   D  GUI child, no PsAttributeStdHandleInfo   (subsystem-gating check:
 *                                                PsRequestDuplicate is
 *                                                documented to depend on
 *                                                StdHandleSubsystemType
 *                                                matching the image, so a
 *                                                GUI/CUI split here points
 *                                                at this attribute from a
 *                                                second direction)
 *
 * D's image is this same executable, copied and with the PE optional
 * header's Subsystem field flipped from 3 (CUI) to 2 (GUI) -- cheaper
 * and less divergent than maintaining a separate GUI test binary, and
 * nothing in crt1/libc reads the subsystem.
 *
 * Wine cannot answer this question: nothing in the Wine tree reads
 * PsAttributeStdHandleInfo (include/winternl.h:4131 and :4167 define the
 * enumerator and the PS_ATTRIBUTE_STD_HANDLE_INFO macro, and that is the
 * whole of it), and dlls/ntdll/unix/env.c's create_startup_info (:2170)
 * copies params->hStdInput/hStdOutput/hStdError through by value when the
 * process is created with PROCESS_CREATE_FLAGS_INHERIT_HANDLES, which is
 * what RtlCreateUserProcess(inherit=TRUE) asks for.  So under Wine the
 * caller's value simply survives verbatim and every variant should look
 * the same.  Running it under Wine is a smoke test that the probe itself
 * works; only the real-Windows CI legs carry information.
 *
 * This test never fails.  It prints what it measured and exits 0, or
 * exits 77 ("unverified", see test/posix-socket.c and tools/run-tests.py)
 * if the machinery it needs is unavailable.  Interpreting the numbers is
 * a human job; pre-judging them in an assertion would only turn a
 * surprising result into a red board.
 *
 * The NT process-creation types below are not in src/internal/nt.h --
 * spicule itself has no NtCreateUserProcess caller -- so they are declared
 * here, from phnt (winsiderss/phnt, ntpsapi.h), the same way
 * test/posix-errno.c declares what it needs locally.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../src/internal/libc.h"

/* ---- from phnt ntpsapi.h ------------------------------------------------ */

/* ntpsapi.h:3259-3268 */
#define PS_ATTRIBUTE_NUMBER_MASK  0x0000ffff
#define PS_ATTRIBUTE_THREAD       0x00010000
#define PS_ATTRIBUTE_INPUT        0x00020000
#define PS_ATTRIBUTE_ADDITIVE     0x00040000

/* ntpsapi.h:3222-3241, the numbers this probe uses */
#define PsAttributeParentProcess   0
#define PsAttributeClientId        3
#define PsAttributeImageName       5
#define PsAttributeImageInfo       6
#define PsAttributeStdHandleInfo  10

#define PS_ATTRIBUTE_IMAGE_NAME      (PsAttributeImageName | PS_ATTRIBUTE_INPUT)
#define PS_ATTRIBUTE_CLIENT_ID       (PsAttributeClientId | PS_ATTRIBUTE_THREAD)
#define PS_ATTRIBUTE_IMAGE_INFO      (PsAttributeImageInfo)
#define PS_ATTRIBUTE_STD_HANDLE_INFO (PsAttributeStdHandleInfo | PS_ATTRIBUTE_INPUT)

/* ntpsapi.h:3339-3356 */
typedef struct _PS_ATTRIBUTE {
	ULONG_PTR Attribute;
	SIZE_T Size;
	union { ULONG_PTR Value; PVOID ValuePtr; };
	SIZE_T *ReturnLength;
} PS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[6];
} PS_ATTRIBUTE_LIST;

/* ntpsapi.h:3364-3390.  StdHandleState is a 2-bit field holding a
 * PS_STD_HANDLE_STATE; PseudoHandleMask is 3 bits of PS_STD_*. */
#define PsNeverDuplicate    0
#define PsRequestDuplicate  1
#define PsAlwaysDuplicate   2

typedef struct _PS_STD_HANDLE_INFO {
	ULONG Flags;                    /* StdHandleState:2, PseudoHandleMask:3 */
	ULONG StdHandleSubsystemType;
} PS_STD_HANDLE_INFO;

/* ntpsapi.h:3299-3350 (PS_CREATE_INFO).  Only Size and State are written;
 * the union is left zeroed and its largest arm (SuccessState) sets the
 * size, so the buffer is big enough whatever the kernel writes back. */
typedef struct _PS_CREATE_INFO {
	SIZE_T Size;
	ULONG State;
	union {
		struct { ULONG InitFlags; ULONG AdditionalFileAccess; } InitState;
		struct {
			ULONG OutputFlags;
			HANDLE FileHandle;
			HANDLE SectionHandle;
			uint64_t UserProcessParametersNative;
			ULONG UserProcessParametersWow64;
			ULONG CurrentParameterFlags;
			uint64_t PebAddressNative;
			ULONG PebAddressWow64;
			uint64_t ManifestAddress;
			ULONG ManifestSize;
		} SuccessState;
	} u;
} PS_CREATE_INFO;

#define PsCreateInitialState 0

/* ntpsapi.h:2118, :3618 */
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001

#define THREAD_ALL_ACCESS_ (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)

typedef NTSTATUS (NTAPI *NtCreateUserProcess_t)(
	HANDLE *, HANDLE *, ACCESS_MASK, ACCESS_MASK,
	POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG,
	PRTL_USER_PROCESS_PARAMETERS, PS_CREATE_INFO *, PS_ATTRIBUTE_LIST *);

/* PE optional-header Subsystem values (winnt.h). */
#define SUBSYSTEM_GUI 2
#define SUBSYSTEM_CUI 3

#define CHILD_FLAG "--stdprobe-child"

/* ---- child ------------------------------------------------------------- */

/* NtQueryObject(ObjectTypeInformation) returns an OBJECT_TYPE_INFORMATION
 * whose first field is the type name; nothing after it is needed here, so
 * only the leading UNICODE_STRING is declared (src/internal/nt.h takes the
 * same "only the fields actually read" approach). */
static void type_name(HANDLE h, char *out, size_t outsz)
{
	unsigned char buf[1024];
	UNICODE_STRING *nm = (UNICODE_STRING *)buf;
	ULONG len = 0;
	NTSTATUS st;
	size_t i, n;

	out[0] = 0;
	if (!h || h == (HANDLE)(LONG_PTR)-1) { snprintf(out, outsz, "(none)"); return; }
	memset(buf, 0, sizeof buf);
	st = NtQueryObject(h, ObjectTypeInformation, buf, sizeof buf, &len);
	if (!NT_SUCCESS(st)) { snprintf(out, outsz, "<NtQueryObject 0x%08lx>", (unsigned long)st); return; }
	n = nm->Length / sizeof(WCHAR);
	if (n > outsz - 1) n = outsz - 1;
	/* NT type names are ASCII; anything else is shown as '?' rather than
	 * dragged through a converter this probe does not need. */
	for (i = 0; i < n; i++) {
		WCHAR c = nm->Buffer[i];
		out[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
	}
	out[n] = 0;
}

static int child_report(const char *path)
{
	PRTL_USER_PROCESS_PARAMETERS pp = __peb->ProcessParameters;
	/* Captured before anything else can touch them.  Nothing in spicule
	 * writes these fields -- src/internal/fd.c's __fd_init only reads
	 * them -- but reading them first makes that independent of spicule. */
	HANDLE in = pp->StandardInput, out = pp->StandardOutput, err = pp->StandardError;
	HANDLE con = pp->ConsoleHandle;
	ULONG conflags = pp->ConsoleFlags, winflags = pp->WindowFlags;
	char tin[128], tout[128], terr[128];
	FILE *f;

	type_name(in, tin, sizeof tin);
	type_name(out, tout, sizeof tout);
	type_name(err, terr, sizeof terr);

	f = fopen(path, "w");
	if (!f) return 2;
	fprintf(f, "StandardInput  %p  type=%s\n", (void *)in, tin);
	fprintf(f, "StandardOutput %p  type=%s\n", (void *)out, tout);
	fprintf(f, "StandardError  %p  type=%s\n", (void *)err, terr);
	fprintf(f, "ConsoleHandle  %p\n", (void *)con);
	fprintf(f, "ConsoleFlags   0x%08lx\n", (unsigned long)conflags);
	fprintf(f, "WindowFlags    0x%08lx\n", (unsigned long)winflags);
	fclose(f);
	return 0;
}

/* ---- parent ------------------------------------------------------------ */

static NtCreateUserProcess_t resolve_ncup(void)
{
	UNICODE_STRING dll;
	ANSI_STRING fn;
	PVOID base = 0, proc = 0;

	RtlInitUnicodeString(&dll, L"ntdll.dll");
	if (!NT_SUCCESS(LdrGetDllHandle(NULL, NULL, &dll, &base))) return 0;
	/* RtlInitAnsiString is not among the ntdll imports this project
	 * declares (tools/ntdll.def); the structure is three fields. */
	fn.Buffer = (char *)"NtCreateUserProcess";
	fn.Length = (USHORT)strlen(fn.Buffer);
	fn.MaximumLength = (USHORT)(fn.Length + 1);
	if (!NT_SUCCESS(LdrGetProcedureAddress(base, &fn, 0, &proc))) return 0;
	return (NtCreateUserProcess_t)proc;
}

/* Spawn `image` (a POSIX-ish path) so that it writes its report to
 * `report`, with all three standard-handle fields NULL, optionally
 * supplying PsAttributeStdHandleInfo.  Returns 0, or -1 with a reason
 * printed. */
static int spawn_variant(NtCreateUserProcess_t ncup, const char *label,
                         const char *image, const char *report,
                         int use_attr, ULONG std_state, ULONG subsys)
{
	struct __ntpath np;
	PRTL_USER_PROCESS_PARAMETERS pp = 0;
	UNICODE_STRING imageDos, cmdLine, cur;
	PS_ATTRIBUTE_LIST attr;
	PS_CREATE_INFO ci;
	PS_STD_HANDLE_INFO shi;
	OBJECT_ATTRIBUTES poa, toa;
	CLIENT_ID cid;
	SECTION_IMAGE_INFORMATION sii;
	HANDLE hp = 0, ht = 0;
	WCHAR curbuf[4096], *wcmd = 0, *wimage = 0;
	char cmdbuf[4096];
	NTSTATUS st;
	ULONG curlen, pos = 0;
	int rc = -1;
	FILE *f;
	char line[512];

	if (__ntpath(image, &np, OBJ_CASE_INSENSITIVE) < 0) {
		printf("%s: SKIP (__ntpath(%s) failed)\n", label, image);
		return -1;
	}

	wimage = __utf8_to_utf16(image, 0);
	snprintf(cmdbuf, sizeof cmdbuf, "\"%s\" " CHILD_FLAG " \"%s\"", image, report);
	wcmd = __utf8_to_utf16(cmdbuf, 0);
	if (!wimage || !wcmd) { printf("%s: SKIP (out of memory)\n", label); goto out; }
	{ size_t k; for (k = 0; wimage[k]; k++) if (wimage[k] == '/') wimage[k] = '\\'; }
	{ size_t k; for (k = 0; wcmd[k]; k++) if (wcmd[k] == '/') wcmd[k] = '\\'; }

	RtlInitUnicodeString(&imageDos, wimage);
	RtlInitUnicodeString(&cmdLine, wcmd);
	curlen = RtlGetCurrentDirectory_U(sizeof curbuf, curbuf);
	cur.Buffer = curbuf;
	cur.Length = (USHORT)curlen;
	cur.MaximumLength = sizeof curbuf;

	st = RtlCreateProcessParametersEx(&pp, &imageDos, 0, &cur, &cmdLine,
	                                  __peb->ProcessParameters->Environment,
	                                  0, 0, 0, 0, RTL_USER_PROC_PARAMS_NORMALIZED);
	if (!NT_SUCCESS(st)) { printf("%s: SKIP (RtlCreateProcessParametersEx 0x%08lx)\n", label, (unsigned long)st); goto out; }

	/* The whole point: NULL, exactly as written, with the "these are
	 * mine, do not provide any" flag set. */
	pp->StandardInput = 0;
	pp->StandardOutput = 0;
	pp->StandardError = 0;
	pp->WindowFlags |= STARTF_USESTDHANDLES;

	memset(&attr, 0, sizeof attr);
	attr.Attributes[pos].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	attr.Attributes[pos].Size = np.nt.Length;
	attr.Attributes[pos].ValuePtr = np.nt.Buffer;
	pos++;
	attr.Attributes[pos].Attribute = PS_ATTRIBUTE_CLIENT_ID;
	attr.Attributes[pos].Size = sizeof cid;
	attr.Attributes[pos].ValuePtr = &cid;
	pos++;
	attr.Attributes[pos].Attribute = PS_ATTRIBUTE_IMAGE_INFO;
	attr.Attributes[pos].Size = sizeof sii;
	attr.Attributes[pos].ValuePtr = &sii;
	pos++;
	if (use_attr) {
		memset(&shi, 0, sizeof shi);
		/* StdHandleState occupies the low 2 bits of Flags; the
		 * PseudoHandleMask bits above it are left clear, so this asks
		 * about the state alone. */
		shi.Flags = std_state & 3u;
		shi.StdHandleSubsystemType = subsys;
		attr.Attributes[pos].Attribute = PS_ATTRIBUTE_STD_HANDLE_INFO;
		attr.Attributes[pos].Size = sizeof shi;
		attr.Attributes[pos].ValuePtr = &shi;
		pos++;
	}
	attr.TotalLength = (SIZE_T)((char *)&attr.Attributes[pos] - (char *)&attr);

	memset(&ci, 0, sizeof ci);
	ci.Size = sizeof ci;
	ci.State = PsCreateInitialState;

	memset(&poa, 0, sizeof poa); poa.Length = sizeof poa;
	memset(&toa, 0, sizeof toa); toa.Length = sizeof toa;
	memset(&cid, 0, sizeof cid);
	memset(&sii, 0, sizeof sii);

	st = ncup(&hp, &ht, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS_, &poa, &toa,
	          PROCESS_CREATE_FLAGS_INHERIT_HANDLES, THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
	          pp, &ci, &attr);
	if (!NT_SUCCESS(st)) {
		printf("%s: SKIP (NtCreateUserProcess 0x%08lx, CreateInfo.State=%lu)\n",
		       label, (unsigned long)st, (unsigned long)ci.State);
		goto out;
	}

	NtResumeThread(ht, 0);
	st = NtWaitForSingleObject(hp, FALSE, 0);
	if (!NT_SUCCESS(st)) printf("%s: NOTE (wait 0x%08lx)\n", label, (unsigned long)st);

	f = fopen(report, "r");
	if (!f) { printf("%s: SKIP (child wrote no report)\n", label); goto out; }
	printf("%s:\n", label);
	while (fgets(line, sizeof line, f)) printf("    %s", line);
	fclose(f);
	remove(report);
	rc = 0;
out:
	if (ht) NtClose(ht);
	if (hp) NtClose(hp);
	if (pp) RtlDestroyProcessParameters(pp);
	free(wimage);
	free(wcmd);
	__ntpath_free(&np);
	return rc;
}

/* Copy this executable and flip its PE Subsystem field to GUI.  Returns 0
 * on success.  Subsystem sits at optional-header offset 68 in both PE32
 * and PE32+ (the 4-byte-vs-8-byte ImageBase difference is absorbed by
 * PE32's four extra standard fields), so one offset serves both arches. */
static int make_gui_copy(const char *src, const char *dst)
{
	FILE *in = fopen(src, "rb"), *out = 0;
	unsigned char *buf = 0;
	long sz;
	unsigned lfanew, opt;
	unsigned short sub;
	int rc = -1;

	if (!in) return -1;
	if (fseek(in, 0, SEEK_END) != 0) goto done;
	sz = ftell(in);
	if (sz < 0x200) goto done;
	rewind(in);
	buf = malloc((size_t)sz);
	if (!buf || fread(buf, 1, (size_t)sz, in) != (size_t)sz) goto done;
	memcpy(&lfanew, buf + 0x3c, sizeof lfanew);
	if (lfanew + 24 + 70 > (unsigned)sz) goto done;
	if (memcmp(buf + lfanew, "PE\0\0", 4) != 0) goto done;
	opt = lfanew + 24;
	memcpy(&sub, buf + opt + 68, sizeof sub);
	if (sub != SUBSYSTEM_CUI) goto done;
	sub = SUBSYSTEM_GUI;
	memcpy(buf + opt + 68, &sub, sizeof sub);
	out = fopen(dst, "wb");
	if (!out) goto done;
	if (fwrite(buf, 1, (size_t)sz, out) != (size_t)sz) goto done;
	rc = 0;
done:
	if (in) fclose(in);
	if (out) fclose(out);
	free(buf);
	return rc;
}

int main(int argc, char **argv)
{
	NtCreateUserProcess_t ncup;
	char cwd[4096], report[4200], guiexe[4200];
	int done = 0;

	if (argc >= 3 && strcmp(argv[1], CHILD_FLAG) == 0)
		return child_report(argv[2]);

	ncup = resolve_ncup();
	if (!ncup) {
		printf("SKIP: ntdll exports no NtCreateUserProcess here\n");
		printf("UNVERIFIED: nothing measured\n");
		return 77;
	}
	if (!getcwd(cwd, sizeof cwd)) {
		printf("SKIP: getcwd failed\n");
		printf("UNVERIFIED: nothing measured\n");
		return 77;
	}
	snprintf(report, sizeof report, "%s/stdprobe-report.txt", cwd);
	snprintf(guiexe, sizeof guiexe, "%s/stdprobe-gui.exe", cwd);

	printf("Parent wrote NULL into StandardInput/Output/Error and set\n"
	       "STARTF_USESTDHANDLES; each line below is what the child found.\n\n");

	if (spawn_variant(ncup, "A  CUI, no PsAttributeStdHandleInfo",
	                  __progname_full, report, 0, 0, 0) == 0) done++;
	if (spawn_variant(ncup, "B  CUI, StdHandleState=PsNeverDuplicate",
	                  __progname_full, report, 1, PsNeverDuplicate, SUBSYSTEM_CUI) == 0) done++;
	if (spawn_variant(ncup, "C  CUI, StdHandleState=PsAlwaysDuplicate",
	                  __progname_full, report, 1, PsAlwaysDuplicate, SUBSYSTEM_CUI) == 0) done++;

	if (make_gui_copy(__progname_full, guiexe) == 0) {
		if (spawn_variant(ncup, "D  GUI, no PsAttributeStdHandleInfo",
		                  guiexe, report, 0, 0, 0) == 0) done++;
		remove(guiexe);
	} else {
		printf("D  GUI, no PsAttributeStdHandleInfo: SKIP (could not build a GUI copy)\n");
	}

	printf("\n");
	if (!done) {
		printf("UNVERIFIED: no variant produced a reading\n");
		return 77;
	}
	printf("%d of 4 variants reported.  Raw values only -- read A vs B: if B\n"
	       "shows NULL where A does not, PsAttributeStdHandleInfo is the actor.\n", done);
	return 0;
}
