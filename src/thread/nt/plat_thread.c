/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of src/internal/plat_thread.h -- see that header for
 * the contract each function makes.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <signal.h>
#include <string.h>
#include <errno.h>
#include "libc.h"
#include "plat_thread.h"
#include "plat_fd.h"
#include "pe.h"
#include "unsafe_pointer.h"

/* Shared by every \BaseNamedObjects-rooted object this file creates or
 * opens. `openif` clears OBJ_INHERIT and sets OBJ_OPENIF, for the one
 * caller (the named-mutant lock) that needs create-or-open semantics
 * instead of plain inheritable-by-fork creation. 128 WCHARs comfortably
 * covers every name this subsystem builds (the longest is capped at 112
 * bytes -- mqueue.c's struct mq_header). */
static void build_object_attributes(const char *ascii, OBJECT_ATTRIBUTES *oa,
	UNICODE_STRING *us, WCHAR *wide, size_t cap, int openif) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	size_t i, n = strlen(ascii);
	if (n >= cap) n = cap - 1;
	for (i = 0; i < n; i++) wide[i] = (unsigned char)ascii[i];
	wide[n] = 0;
	if (n > __US_MAX_WCHARS) n = __US_MAX_WCHARS;
	us->Length = (USHORT)(n * sizeof(WCHAR));
	us->MaximumLength = (USHORT)((n + 1) * sizeof(WCHAR));
	us->Buffer = wide;
	InitializeObjectAttributes(oa, us, OBJ_CASE_INSENSITIVE | OBJ_INHERIT, 0, 0);
	if (openif) oa->Attributes = (oa->Attributes & ~OBJ_INHERIT) | OBJ_OPENIF;
}

/* ---- waiting -------------------------------------------------------- */

int __plat_wait_one(__plat_handle_t h, int alertable, int has_timeout, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
	long long relative_ticks)
{
	LARGE_INTEGER timeout, *tp = 0;
	NTSTATUS st;
	if (has_timeout) { timeout = relative_ticks; tp = &timeout; }
	st = NtWaitForSingleObject(h, (BOOLEAN)alertable, tp);
	if (st == STATUS_USER_APC || st == STATUS_ALERTED) return __PLAT_WAIT_INTR;
	if (st == STATUS_TIMEOUT) return __PLAT_WAIT_TIMEOUT;
	if (!NT_SUCCESS(st)) { __set_errno_status(st); return __PLAT_WAIT_ERROR; }
	return __PLAT_WAIT_OK;
}

int __plat_wait_any(__plat_handle_t *handles, unsigned count, int alertable, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
	int has_timeout, long long relative_ticks)
{
	LARGE_INTEGER timeout, *tp = 0;
	NTSTATUS st;
	if (has_timeout) { timeout = relative_ticks; tp = &timeout; }
	st = NtWaitForMultipleObjects((ULONG)count, (HANDLE *)handles,
	                              1 /* WaitAny */, (BOOLEAN)alertable, tp);
	if (st == STATUS_USER_APC || st == STATUS_ALERTED) return __PLAT_WAIT_INTR;
	if (st == STATUS_TIMEOUT) return __PLAT_WAIT_TIMEOUT;
	if (!NT_SUCCESS(st)) { __set_errno_status(st); return __PLAT_WAIT_ERROR; }
	return __PLAT_WAIT_OK;
}

/* ---- events ----------------------------------------------------------- */

int __plat_event_create(__plat_handle_t *out)
{
	OBJECT_ATTRIBUTES attributes;
	NTSTATUS status;
	InitializeObjectAttributes(&attributes, 0, 0, 0, 0);
	status = NtCreateEvent(out, EVENT_ALL_ACCESS, &attributes,
	                       SynchronizationEvent, FALSE);
	if (status == STATUS_NOT_IMPLEMENTED) return -2;
	if (!NT_SUCCESS(status)) return __set_errno_status(status);
	return 0;
}

int __plat_event_set(__plat_handle_t h)
{
	LONG previous;
	NTSTATUS status = NtSetEvent(h, &previous);
	if (!NT_SUCCESS(status)) return __set_errno_status(status);
	return 0;
}

/* ---- unnamed semaphores ------------------------------------------------ */

int __plat_semaphore_create(long initial, long maximum, int inheritable, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
	__plat_handle_t *out)
{
	OBJECT_ATTRIBUTES oa;
	NTSTATUS st;
	InitializeObjectAttributes(&oa, 0, inheritable ? OBJ_INHERIT : 0, 0, 0);
	st = NtCreateSemaphore(out, SEMAPHORE_ALL_ACCESS, &oa, (LONG)initial, (LONG)maximum);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_semaphore_post(__plat_handle_t h)
{
	NTSTATUS st = NtReleaseSemaphore(h, 1, NULL);
	/* [EOVERFLOW] decided here, not reconstructed from a generic errno
	 * afterward: see plat_thread.h's banner and src/unistd/nt/plat_fd.c's
	 * SIGPIPE comment for why this class of decision belongs where the
	 * real status is still in hand. */
	if (st == STATUS_SEMAPHORE_LIMIT_EXCEEDED) { errno = EOVERFLOW; return -1; }
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_semaphore_getvalue(__plat_handle_t h, int *value)
{
	SEMAPHORE_BASIC_INFORMATION info;
	NTSTATUS st = NtQuerySemaphore(h, SemaphoreBasicInformation,
	                               &info, sizeof info, NULL);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	*value = info.CurrentCount;
	return 0;
}

/* ---- named objects ------------------------------------------------------ */

int __plat_named_semaphore_create(const char *name, long initial,
	long maximum, __plat_handle_t *out)
{
	WCHAR wide[128];
	UNICODE_STRING us;
	OBJECT_ATTRIBUTES oa;
	NTSTATUS st;
	build_object_attributes(name, &oa, &us, wide, sizeof wide / sizeof wide[0], 0);
	st = NtCreateSemaphore(out, SEMAPHORE_ALL_ACCESS, &oa, (LONG)initial, (LONG)maximum);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_named_semaphore_open(const char *name, __plat_handle_t *out)
{
	WCHAR wide[128];
	UNICODE_STRING us;
	OBJECT_ATTRIBUTES oa;
	NTSTATUS st;
	build_object_attributes(name, &oa, &us, wide, sizeof wide / sizeof wide[0], 0);
	st = NtOpenSemaphore(out, SEMAPHORE_ALL_ACCESS, &oa);
	if (st == STATUS_OBJECT_NAME_NOT_FOUND) return -2;
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_named_semaphore_open_or_create(const char *name, long initial,
	long maximum, __plat_handle_t *out)
{
	WCHAR wide[128];
	UNICODE_STRING us;
	OBJECT_ATTRIBUTES oa;
	NTSTATUS st;
	build_object_attributes(name, &oa, &us, wide, sizeof wide / sizeof wide[0], 0);
	st = NtCreateSemaphore(out, SEMAPHORE_ALL_ACCESS, &oa, (LONG)initial, (LONG)maximum);
	/* Wine reports an existing named semaphore as the error status
	 * STATUS_OBJECT_NAME_COLLISION rather than NT's informational
	 * STATUS_OBJECT_NAME_EXISTS.  Opening it is the same create-or-open
	 * contract every caller of this function needs. */
	if (st == STATUS_OBJECT_NAME_COLLISION)
		st = NtOpenSemaphore(out, SEMAPHORE_ALL_ACCESS, &oa);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_named_mutant_acquire(const char *name, __plat_handle_t *out)
{
	WCHAR wide[128];
	UNICODE_STRING us;
	OBJECT_ATTRIBUTES oa;
	NTSTATUS st;
	build_object_attributes(name, &oa, &us, wide, sizeof wide / sizeof wide[0], 1);
	st = NtCreateMutant(out, MUTANT_ALL_ACCESS, &oa, FALSE);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	st = NtWaitForSingleObject(*out, FALSE, NULL);
	if (!NT_SUCCESS(st)) {
		NtClose(*out);
		*out = 0;
		return __set_errno_status(st);
	}
	return 0;
}

void __plat_named_mutant_release(__plat_handle_t lock)
{
	NtReleaseMutant(lock, NULL);
	NtClose(lock);
}

/* See plat_thread.h's own __plat_sync_close() banner for why this call
 * exists separately from plat_fd.h's __plat_close() at all: on NT a
 * semaphore/event/named-semaphore handle IS a real NtClose()-able HANDLE
 * like any other, so this backend's implementation is exactly that generic
 * close, unlike Linux's (a real munmap(2) there -- see that backend's own
 * comment). Never called on a named-mutant handle: __plat_named_mutant_
 * release() above already closes those as part of releasing them, and no
 * real call site in this tree calls this on one. */
int __plat_sync_close(__plat_handle_t h)
{
	return __plat_close(h);
}

/* ---- thread lifecycle ---------------------------------------------------- */

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 1u

int __plat_thread_spawn(__plat_thread_entry_t entry, void *arg,
	size_t stack_size, int create_suspended, __plat_handle_t *out)
{
	NTSTATUS status = NtCreateThreadEx(out, THREAD_ALL_ACCESS, 0,
		NtCurrentProcess(), (PVOID)entry, arg,
		create_suspended ? THREAD_CREATE_FLAGS_CREATE_SUSPENDED : 0,
		0, stack_size, stack_size, 0);
	if (status == STATUS_NOT_IMPLEMENTED) return -2;
	if (!NT_SUCCESS(status)) return __set_errno_status(status);
	/* No TLS-block fixup here (e5d0b1d1 put one in this exact spot; see
	 * 6291f1b2 for why it was reverted). It now runs from inside the new
	 * thread itself instead -- __plat_thread_tls_fixup() below, called
	 * from src/thread/pthread.c's thread_entry() -- for reasons that
	 * function's own banner explains in full. */
	return 0;
}

/* See this file's own plat_thread.h declaration for the contract, and the
 * paragraphs below for why this exists and runs where it does.
 *
 * WHAT this rebuilds and WHY: the pinned bootstrap tcc build's PE linker
 * (tccpe.c: pe_build_tls()) always writes IMAGE_TLS_DIRECTORY.Characteristics
 * = 0 -- it never encodes the image's real IMAGE_SCN_ALIGN_* requirement
 * (see test/libc-test-expected.txt's tls_local_exec row). A loader that
 * trusts Characteristics for its automatic per-thread TLS allocation's
 * alignment then hands back an under-aligned block for any `__thread`
 * object whose declared alignment exceeds whatever default
 * Characteristics=0 implies (observed: fine up to a point, but a
 * `__thread` object declared __attribute__((aligned(4096))) ends up short
 * of 4096-byte alignment). Since Characteristics can't be trusted, this
 * doesn't even read it -- it defensively page-aligns the replacement block
 * instead, which trivially satisfies every alignment tcc could plausibly
 * ask for (the widest natural alignment x86_64/i386/arm64 have is a page).
 *
 * WHY the calling thread does this to itself, rather than the thread that
 * spawned it doing it before resuming it (e5d0b1d1's original approach,
 * reverted in 6291f1b2 after real Wine CI showed a confirmed, 16-test-wide
 * SIGSEGV regression): under Wine, NtCreateThreadEx computes the new
 * thread's TEB synchronously in the CREATOR (dlls/ntdll/unix/thread.c's
 * virtual_alloc_teb()), but the new thread only registers that TEB with
 * the wineserver ASYNCHRONOUSLY, via a later init_thread request
 * (dlls/ntdll/unix/server.c's server_init_thread()) -- until that request
 * is processed, the server-side thread object's own `teb` field reads back
 * as 0 (server/thread.c), so NtQueryInformationThread(ThreadBasicInformation)
 * called from the creator right after NtCreateThreadEx returns can report
 * STATUS_SUCCESS with a still-zero TebBaseAddress: exactly the race
 * e5d0b1d1's creator-side TEB fetch hit. A thread reading its OWN TEB
 * (__teb(), a direct %fs/%gs-relative read -- see src/internal/{i386,
 * x86_64,aarch64}/teb.c) has no such race: that pointer is valid the
 * instant the thread starts executing, wineserver registration or not.
 *
 * That still leaves a second, independent problem no amount of creator-side
 * fixing could have solved: Wine's own loader_init() (dlls/ntdll/loader.c)
 * always runs before a new thread reaches any code of its own -- every new
 * thread's initial CPU context is engineered to enter LdrInitializeThunk
 * first, which calls loader_init() and only afterward resumes the context
 * that jumps to the real start routine (see e.g.
 * dlls/ntdll/unix/signal_x86_64.c's new-thread context setup, which points
 * the initial frame at pLdrInitializeThunk, never directly at the
 * caller-requested entry) -- and loader_init() unconditionally calls
 * alloc_thread_tls(), which reallocates and overwrites
 * TEB->ThreadLocalStoragePointer wholesale. A block installed by the
 * creator before the thread ever resumes is exactly the block that call
 * clobbers; real Windows' documented THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH/
 * SKIP_LOADER_INIT flags could dodge that specific call, but only by also
 * skipping this thread's DLL_THREAD_ATTACH notification to every other
 * already-loaded DLL and (for SKIP_LOADER_INIT) this thread's FLS slot
 * allocation -- a real behavioral change on real Windows too, not a
 * Wine-only workaround. Running this fixup from the new thread's own
 * entry point instead needs none of that: it runs strictly AFTER
 * loader_init() has already completed (guaranteed by the ordering above,
 * on Wine and on real Windows alike), so it simply overwrites whatever
 * loader_init() just installed, once, and nothing downstream of it in
 * this thread's lifetime touches the slot again -- no flag, no skipped
 * loader work, no race. */
void __plat_thread_tls_fixup(void)
{
	IMAGE_TLS_DIRECTORY *dir;
	PTEB teb;
	PVOID *slots;
	ULONG index;
	uintptr_t raw_start, raw_end, index_addr;
	size_t raw_size, total_size;
	PVOID block = 0;
	SIZE_T block_size;
	NTSTATUS status;

	if (!ntlibc_pe_tls_directory(__peb->ImageBaseAddress, &dir)) return;
	raw_start = (uintptr_t)dir->StartAddressOfRawData;
	raw_end = (uintptr_t)dir->EndAddressOfRawData;
	index_addr = (uintptr_t)dir->AddressOfIndex;
	if (!index_addr || raw_end < raw_start) return;
	raw_size = (size_t)(raw_end - raw_start);
	/* __size_add_checked, not raw '+': SizeOfZeroFill is untrusted input
	 * from the same compiler-emitted directory as Characteristics. */
	if (!__size_add_checked(raw_size, dir->SizeOfZeroFill, &total_size) ||
	    !total_size) return;

	block_size = total_size;
	status = NtAllocateVirtualMemory(NtCurrentProcess(), &block, 0,
		&block_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) return;
	/* raw_start/index_addr are not integer-derived: pe.h's own comment on
	 * IMAGE_TLS_DIRECTORY explains that this directory's fields are
	 * already-relocated absolute VAs the linker bakes in like any other
	 * global, kept correct across a non-preferred load by an ordinary
	 * base relocation -- reading them back out of the already-relocated,
	 * already-mapped image at __peb->ImageBaseAddress is exactly as valid
	 * as dereferencing any other relocated global pointer in this image. */
	if (raw_size) memcpy(block, unsafe_assume_valid_pointer((const void *)raw_start), raw_size);
	memset((unsigned char *)block + raw_size, 0, dir->SizeOfZeroFill);

	index = *unsafe_assume_valid_pointer((ULONG *)index_addr);
	teb = __teb();
	slots = (PVOID *)teb->ThreadLocalStoragePointer;
	if (!slots) {
		/* Not expected in practice -- by the time this runs, the
		 * platform's own loader has already unconditionally allocated
		 * this array (Wine's alloc_thread_tls(), or real Windows'
		 * equivalent). But that allocation is fallible (its own
		 * out-of-memory case terminates the thread before it ever
		 * reaches here) and its exact conditions belong to someone
		 * else's implementation, not a guarantee this file gets to
		 * assume forever. Building one from scratch, sized to `index`,
		 * is safe here for the same reason it would have been at thread
		 * creation: nothing else on this thread has run yet that could
		 * already depend on a smaller array. */
		size_t slots_bytes;
		PVOID array = 0;
		SIZE_T array_size;
		SIZE_T free_size = 0;
		if (!__size_add_checked((size_t)index, 1, &slots_bytes) ||
		    !__size_mul_checked(slots_bytes, sizeof(PVOID), &slots_bytes)) {
			NtFreeVirtualMemory(NtCurrentProcess(), &block, &free_size, MEM_RELEASE);
			return;
		}
		array_size = slots_bytes;
		status = NtAllocateVirtualMemory(NtCurrentProcess(), &array, 0,
			&array_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) {
			NtFreeVirtualMemory(NtCurrentProcess(), &block, &free_size, MEM_RELEASE);
			return;
		}
		slots = (PVOID *)array;
		teb->ThreadLocalStoragePointer = array;
	}
	/* Deliberately not freeing whatever slots[index] already held: by this
	 * point it is the platform loader's own RtlAllocateHeap() block, not
	 * one of ours, and freeing it through the wrong allocator would
	 * corrupt that heap. It is unused from here on and reclaimed only
	 * when the process exits -- a bounded, one-time leak per spawned
	 * thread, not an accumulating one. */
	slots[index] = block;
}

/* See plat_thread.h's own __plat_thread_close() banner for why this call
 * exists separately from plat_fd.h's __plat_close() at all: on NT a
 * thread handle IS a real NtClose()-able HANDLE like any other, so this
 * backend's implementation is exactly that generic close, unlike
 * Linux's (a real no-op there -- see that backend's own comment). */
int __plat_thread_close(__plat_handle_t h)
{
	return __plat_close(h);
}

/* __plat_thread_resume() is declared in this file's header but defined in
 * src/process/nt/plat_process.c, to avoid a duplicate ODR definition. */

int __plat_thread_suspend(__plat_handle_t h)
{
	ULONG previous;
	NTSTATUS status = NtSuspendThread(h, &previous);
	if (!NT_SUCCESS(status)) return __set_errno_status(status);
	return 0;
}

int __plat_thread_queue_apc(__plat_handle_t h, __plat_apc_fn fn, void *arg1,
	void *arg2)
{
	NTSTATUS status = NtQueueApcThread(h, (PKNORMAL_ROUTINE)fn, arg1, arg2, 0);
	if (!NT_SUCCESS(status)) return __set_errno_status(status);
	return 0;
}

int __plat_thread_redirect_ip(__plat_handle_t h, void *target) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
#if defined(__x86_64__)
	unsigned char storage[0x4d0 + 15];
	const ULONG flags = 0x100001; /* CONTEXT_AMD64 | CONTEXT_CONTROL */
	const size_t flags_offset = 0x30;
	const size_t ip_offset = 0xf8;
#elif defined(__i386__)
	unsigned char storage[0x2cc + 15];
	const ULONG flags = 0x10001; /* CONTEXT_i386 | CONTEXT_CONTROL */
	const size_t flags_offset = 0;
	const size_t ip_offset = 0xb8;
#elif defined(__aarch64__)
	/* ARM64_NT_CONTEXT (winnt.h) offsets confirmed against Wine's
	 * include/winnt.h rather than assumed from the x86 layouts' shape.
	 * Only Pc (0x108) is touched, matching the other two branches' scope. */
	unsigned char storage[0x390 + 15];
	const ULONG flags = 0x400001; /* CONTEXT_ARM64 | CONTEXT_ARM64_CONTROL */
	const size_t flags_offset = 0;
	const size_t ip_offset = 0x108;
#else
# error unsupported architecture
#endif
	unsigned char *context = (unsigned char *)
		(((ULONG_PTR)storage + 15) & ~(ULONG_PTR)15);
	ULONG_PTR ip = (ULONG_PTR)target;
	NTSTATUS status;
	size_t i;

	for (i = 0; i < sizeof storage - 15; i++) context[i] = 0;
	memcpy(context + flags_offset, &flags, sizeof flags);
	status = NtGetContextThread(h, context);
	if (!NT_SUCCESS(status)) return __set_errno_status(status);
	memcpy(context + ip_offset, &ip, sizeof ip);
	status = NtSetContextThread(h, context);
	if (!NT_SUCCESS(status)) return __set_errno_status(status);
	return 0;
}

int __plat_thread_stack_extent(__plat_handle_t h, void **base, size_t *size)
{
	THREAD_BASIC_INFORMATION information;
	PTEB teb;
	NTSTATUS status = NtQueryInformationThread(h, ThreadBasicInformation,
		&information, sizeof information, 0);
	if (!NT_SUCCESS(status)) return __set_errno_status(status);
	teb = information.TebBaseAddress;
	*base = teb->NtTib.StackLimit;
	/* The kernel supplies these as the two numeric bounds of one stack.
	 * Integer subtraction expresses that address-space fact without C's
	 * same-array requirement for pointer subtraction. */
	*size = (size_t)((uintptr_t)teb->NtTib.StackBase -
	                 (uintptr_t)teb->NtTib.StackLimit);
	return 0;
}

__plat_handle_t __plat_thread_duplicate_self(void)
{
	HANDLE handle;
	if (NT_SUCCESS(NtDuplicateObject(NtCurrentProcess(), NtCurrentThread(),
		NtCurrentProcess(), &handle, 0, 0, DUPLICATE_SAME_ACCESS)))
		return handle;
	return NtCurrentThread();
}

__plat_handle_t __plat_thread_current_pseudo(void)
{
	return NtCurrentThread();
}

_Noreturn void __plat_thread_terminate_self(void)
{
	NtTerminateThread(NtCurrentThread(), 0);
	for (;;) NtTerminateThread(NtCurrentThread(), 0);
}

/* The write deliberately bypasses stdio and the fd table: the suspended
 * target may own either one's locks.  Termination likewise goes straight
 * to NT instead of abort()/__exit_internal(), whose signal and child
 * bookkeeping are not async-cancel-safe themselves. */
_Noreturn void __plat_cancel_unsafe_abort(const char *region)
{
	static const char prefix[] =
		"ntlibc: undefined behavior: asynchronous cancellation during ";
	static const char suffix[] = "\r\n";
	IO_STATUS_BLOCK io;
	HANDLE error = 0;
	size_t length = 0;

	if (__peb && __peb->ProcessParameters)
		error = __peb->ProcessParameters->StandardError;
	if (!region) region = "an async-cancel-unsafe operation";
	while (region[length]) length++;
	if (error) {
		NtWriteFile(error, 0, 0, 0, &io, prefix,
			sizeof prefix - 1, 0, 0);
		NtWriteFile(error, 0, 0, 0, &io, region, (ULONG)length, 0, 0);
		NtWriteFile(error, 0, 0, 0, &io, suffix,
			sizeof suffix - 1, 0, 0);
	}
	NtTerminateProcess(NtCurrentProcess(), __ENCODE_SIGNAL_EXIT(SIGABRT));
	for (;;) NtTerminateProcess(NtCurrentProcess(),
		__ENCODE_SIGNAL_EXIT(SIGABRT));
}

void __plat_thread_alertable_yield(void)
{
	LARGE_INTEGER delay = 0;
	NtDelayExecution(TRUE, &delay);
}

long long __plat_query_system_time(void)
{
	LARGE_INTEGER t;
	NtQuerySystemTime(&t);
	return t;
}

/* ---- mqueue.c's queue-file I/O -------------------------------------------- */

ssize_t __plat_thread_file_io(__plat_handle_t h, void *buf, size_t count, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
	off_t off, int write_op)
{
	IO_STATUS_BLOCK io;
	LARGE_INTEGER pos = off;
	ULONG part = count > 0x7fffffff ? 0x7fffffff : (ULONG)count;
	NTSTATUS st;
	io.Information = 0;
	if (write_op)
		st = NtWriteFile(h, 0, 0, 0, &io, buf, part, &pos, 0);
	else
		st = NtReadFile(h, 0, 0, 0, &io, buf, part, &pos, 0);
	if (st == STATUS_PENDING) {
		NtWaitForSingleObject(h, FALSE, NULL);
		st = io.Status;
	}
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return (ssize_t)io.Information;
}

/* The PEB lock is set up by the OS before any user code runs, so this
 * pair needs no creation step. */
void __plat_fast_lock(void) { RtlAcquirePebLock(); }
void __plat_fast_unlock(void) { RtlReleasePebLock(); }

// NOLINTEND(misc-include-cleaner)
