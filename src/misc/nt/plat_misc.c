/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of src/internal/plat_misc.h -- see that header for
 * the contract each function makes.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include "libc.h"
#include "plat_misc.h"

void __plat_yield(void)
{
	NtYieldExecution();
}

/* out required: written unconditionally (`*out = h;`) on the success
 * path with no NULL check; both real callers below forward their own
 * now-required out with no guard of their own. */
static int open_process(pid_t pid, ACCESS_MASK want, __plat_handle_t *out)
    __attribute__((nonnull(3)));
static int open_process(pid_t pid, ACCESS_MASK want, __plat_handle_t *out) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	OBJECT_ATTRIBUTES oa;
	CLIENT_ID cid;
	HANDLE h;
	NTSTATUS st;

	InitializeObjectAttributes(&oa, 0, 0, 0, 0);
	cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
	cid.UniqueThread = 0;
	st = NtOpenProcess(&h, want, &oa, &cid);
	if (!NT_SUCCESS(st)) return st == (NTSTATUS)STATUS_ACCESS_DENIED ? -2 : -1;
	*out = h;
	return 0;
}

int __plat_process_open_checked(pid_t pid, __plat_handle_t *out)
{
	int r = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION, out);
	if (r == 0) return 0;
	errno = r == -2 ? EPERM : ESRCH;
	return -1;
}

int __plat_process_open(pid_t pid, __plat_handle_t *out)
{
	if (open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION, out) < 0) {
		errno = ESRCH;
		return -1;
	}
	return 0;
}

int __plat_process_alive(__plat_handle_t h)
{
	PROCESS_BASIC_INFORMATION pbi;
	NTSTATUS st = NtQueryInformationProcess(h, ProcessBasicInformation, &pbi, sizeof pbi, 0);
	if (!NT_SUCCESS(st)) { errno = ESRCH; return 0; }
	/* NT may keep a reaped process object openable.  ExitStatus, rather
	 * than openability alone, distinguishes that object from a process
	 * POSIX still considers to exist. */
	if (pbi.ExitStatus != (NTSTATUS)STATUS_PENDING) { errno = ESRCH; return 0; }
	return 1;
}

int __plat_process_times_self(unsigned long long *user100ns, unsigned long long *kernel100ns) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	KERNEL_USER_TIMES kt;
	NTSTATUS st = NtQueryInformationProcess(NtCurrentProcess(), ProcessTimes, &kt, sizeof kt, 0);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	*user100ns = (unsigned long long)kt.UserTime;
	*kernel100ns = (unsigned long long)kt.KernelTime;
	return 0;
}

/* This process's nice<->NT-base-priority mapping: only three priority
 * classes are reachable from an unprivileged caller, and the finer-
 * grained ProcessBasePriority class is STATUS_NOT_IMPLEMENTED on the
 * Wine this project's CI runs against. */
static UCHAR priorityclass_from_nice(int nice)
{
	if (nice <= 0) return PROCESS_PRIOCLASS_NORMAL;
	if (nice < 10) return PROCESS_PRIOCLASS_BELOW_NORMAL;
	return PROCESS_PRIOCLASS_IDLE;
}

static int nice_from_baseprio(int bp)
{
	int nice = 8 - bp;
	if (nice < -NZERO) nice = -NZERO;
	if (nice > NZERO - 1) nice = NZERO - 1;
	return nice;
}

int __plat_priority_get(__plat_handle_t h, int *nice_out)
{
	PROCESS_BASIC_INFORMATION pbi;
	NTSTATUS st = NtQueryInformationProcess(h, ProcessBasicInformation, &pbi, sizeof pbi, 0);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	*nice_out = nice_from_baseprio((int)pbi.BasePriority);
	return 0;
}

int __plat_priority_set(__plat_handle_t h, int foreground, int nice_value) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	PROCESS_PRIORITY_CLASS pc;
	NTSTATUS st;

	pc.Foreground = (BOOLEAN)foreground;
	pc.PriorityClass = priorityclass_from_nice(nice_value);
	st = NtSetInformationProcess(h, ProcessPriorityClass, &pc, sizeof pc);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_priority_set_self(int foreground, int nice_value)
{
	return __plat_priority_set(NtCurrentProcess(), foreground, nice_value);
}

int __plat_write_start_offset(__plat_handle_t h, int append, long long *out)
{
	IO_STATUS_BLOCK io;

	if (append) {
		FILE_STANDARD_INFORMATION si;
		if (!NT_SUCCESS(NtQueryInformationFile(h, &io, &si, sizeof si, FileStandardInformation)))
			return -1;
		*out = si.EndOfFile;
	} else {
		FILE_POSITION_INFORMATION pi;
		if (!NT_SUCCESS(NtQueryInformationFile(h, &io, &pi, sizeof pi, FilePositionInformation)))
			return -1;
		*out = pi.CurrentByteOffset;
	}
	return 0;
}

/* Job object this process lazily creates and assigns itself to the
 * first time setrlimit() needs to reflect a limit onto NT.  See
 * resource.c's own comment on why every failure past this point is
 * absorbed rather than reported. */
static HANDLE job_handle;

static HANDLE ensure_job(void)
{
	OBJECT_ATTRIBUTES oa;
	HANDLE h;

	if (job_handle) return job_handle;
	InitializeObjectAttributes(&oa, 0, 0, 0, 0);
	if (!NT_SUCCESS(NtCreateJobObject(&h, JOB_OBJECT_ALL_ACCESS, &oa)))
		return 0;
	if (!NT_SUCCESS(NtAssignProcessToJobObject(h, NtCurrentProcess()))) {
		NtClose(h);
		return 0;
	}
	job_handle = h;
	return job_handle;
}

void __plat_job_apply_limits(rlim_t nproc_cur, rlim_t cpu_cur, rlim_t as_cur, rlim_t data_cur) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli;
	HANDLE h = ensure_job();

	if (!h) return;
	memset(&eli, 0, sizeof eli);
	if (nproc_cur != RLIM_INFINITY) {
		eli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
		eli.BasicLimitInformation.ActiveProcessLimit = nproc_cur > 0xFFFFFFFFu ? 0xFFFFFFFFu : (ULONG)nproc_cur;
	}
	if (cpu_cur != RLIM_INFINITY) {
		eli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
		eli.BasicLimitInformation.PerProcessUserTimeLimit = (LARGE_INTEGER)(cpu_cur * 10000000ULL);
	}
	if (as_cur != RLIM_INFINITY || data_cur != RLIM_INFINITY) {
		rlim_t lim = as_cur;
		if (data_cur != RLIM_INFINITY && (as_cur == RLIM_INFINITY || data_cur < as_cur))
			lim = data_cur;
		eli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
		eli.ProcessMemoryLimit = (SIZE_T)lim;
	}
	NtSetInformationJobObject(h, JobObjectExtendedLimitInformation, &eli, sizeof eli);
}

/* ======================================================================
 * uname.c: moved verbatim from src/misc/uname.c's own front door -- no
 * behaviour change, only location (see plat_misc.h's own comment and
 * uname.c's own header comment for exactly what each field reports and
 * why: every field is something NT genuinely knows, nothing invented).
 * ====================================================================== */

/* HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName,
 * value "ComputerName" -- the registry location this node's real name
 * lives at, independent of any process's own environment. Returns 0 and
 * fills `out` on success, -1 on any failure; the one caller,
 * __plat_uname() below, falls back to gethostname()'s env-based answer. */
static int nt_registry_computername(char *out, size_t outsz)
{
	/* Spelled as WCHAR-array initializer lists, not L"..." literals: a wide
	 * string literal's element type is the compiler's native wchar_t
	 * (32-bit on a non-Windows-targeting compiler), while src/internal/
	 * nt.h's WCHAR is `unsigned short` -- a real array-element type
	 * mismatch under the native ASan/fuzz build. */
	static const WCHAR keypath[] = {
		'\\','R','e','g','i','s','t','r','y','\\','M','a','c','h','i','n','e','\\',
		'S','Y','S','T','E','M','\\','C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t','\\',
		'C','o','n','t','r','o','l','\\','C','o','m','p','u','t','e','r','N','a','m','e','\\',
		'A','c','t','i','v','e','C','o','m','p','u','t','e','r','N','a','m','e', 0
	};
	static const WCHAR valuename[] = { 'C','o','m','p','u','t','e','r','N','a','m','e', 0 };
	UNICODE_STRING key_us, value_us;
	OBJECT_ATTRIBUTES oa;
	HANDLE khandle;
	NTSTATUS st;
	/* KEY_VALUE_PARTIAL_INFORMATION's Data[1] is a placeholder for a
	 * variable-length trailer; this buffer holds the header plus up to
	 * 256 bytes of value data, generously past any real computer name
	 * (NetBIOS caps it at 15 characters; DNS-style names in this key
	 * have been measured no longer than 63). */
	unsigned char buf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 256];
	PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
	ULONG result_len = 0;
	int n;

	RtlInitUnicodeString(&key_us, keypath);
	RtlInitUnicodeString(&value_us, valuename);
	InitializeObjectAttributes(&oa, &key_us, OBJ_CASE_INSENSITIVE, 0, 0);

	st = NtOpenKey(&khandle, KEY_QUERY_VALUE, &oa);
	if (!NT_SUCCESS(st)) return -1;

	st = NtQueryValueKey(khandle, &value_us, KeyValuePartialInformation,
	    info, sizeof buf, &result_len);
	NtClose(khandle);
	if (!NT_SUCCESS(st)) return -1;
	/* REG_SZ == 1: the type this value has always been measured to be
	 * (GetComputerNameW() itself expects the same); anything else is
	 * not this library's job to reinterpret. */
	if (info->Type != 1 || info->DataLength < sizeof(WCHAR)) return -1;

	n = __utf16_to_utf8_buf((const WCHAR *)info->Data,
	    info->DataLength / sizeof(WCHAR), out, outsz);
	if (n < 0) return -1;
	/* The registry value is not guaranteed NUL-terminated within
	 * DataLength; strip a trailing NUL if present so out is a clean C
	 * string either way. */
	if (n > 0 && out[n - 1] == '\0') n--;
	if ((size_t)n < outsz) out[n] = '\0';
	else if (outsz) out[outsz - 1] = '\0';
	return 0;
}

int __plat_uname(struct utsname *u)
{
	RTL_OSVERSIONINFOW vi;
	int n;

	memset(&vi, 0, sizeof vi);
	vi.dwOSVersionInfoSize = sizeof vi;
	RtlGetVersion(&vi);   /* NTSTATUS return is documented always-success */

	strcpy(u->sysname, "Windows_NT");

	if (nt_registry_computername(u->nodename, sizeof u->nodename) < 0) {
		/* Degraded, not the primary path: see nt_registry_computername()'s
		 * own banner for when this is reached. */
		if (gethostname(u->nodename, sizeof u->nodename) < 0)
			strcpy(u->nodename, "localhost");
	}

	n = snprintf(u->release, sizeof u->release, "%lu.%lu",
	    (unsigned long)vi.dwMajorVersion, (unsigned long)vi.dwMinorVersion);
	if (n < 0) return -1;
	if ((size_t)n >= sizeof u->release) { errno = EOVERFLOW; return -1; }
	n = snprintf(u->version, sizeof u->version, "Build %lu",
	    (unsigned long)vi.dwBuildNumber);
	if (n < 0) return -1;
	if ((size_t)n >= sizeof u->version) { errno = EOVERFLOW; return -1; }

#if defined(__x86_64__)
	strcpy(u->machine, "x86_64");
#elif defined(__i386__)
	strcpy(u->machine, "i686");
#else
	strcpy(u->machine, "unknown");
#endif

	return 0;
}

// NOLINTEND(misc-include-cleaner)
