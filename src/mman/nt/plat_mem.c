/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of src/internal/plat_mem.h -- see that header for
 * the contract each function makes.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include "libc.h"
#include "plat_mem.h"

#define MMAP_PAGE 4096u
static size_t pground(size_t n) { return (n + MMAP_PAGE - 1) & ~(size_t)(MMAP_PAGE - 1); }

/* NtQueryVirtualMemory() describes page/region boundaries in the process's
 * flat virtual address space. A reported BaseAddress can precede the C
 * allocation containing the query pointer, so these are intentionally
 * integer address operations rather than same-array pointer operations
 * C's relational/subtraction operators require. */
static int addr_lt(const void *a, const void *b) { return (uintptr_t)a < (uintptr_t)b; }
static int addr_le(const void *a, const void *b) { return (uintptr_t)a <= (uintptr_t)b; }
static int addr_gt(const void *a, const void *b) { return (uintptr_t)a > (uintptr_t)b; }
static size_t addr_diff(const void *a, const void *b) { return (size_t)((uintptr_t)a - (uintptr_t)b); }

/* mmap.html "Protection Options" -> NT page protection.  PROT_WRITE
 * without PROT_READ has no NT spelling (there is no write-only page
 * protection), so it widens to read/write; POSIX permits that outright:
 * "an implementation may permit accesses other than those specified by
 * prot". */
static ULONG prot_to_page(int prot)
{
	if (prot & PROT_EXEC) {
		if (prot & PROT_WRITE) return PAGE_EXECUTE_READWRITE;
		if (prot & PROT_READ)  return PAGE_EXECUTE_READ;
		return PAGE_EXECUTE;
	}
	if (prot & PROT_WRITE) return PAGE_READWRITE;
	if (prot & PROT_READ)  return PAGE_READONLY;
	return PAGE_NOACCESS;
}

static size_t user_address_span(void)
{
	static size_t span;
	if (!span) {
		SYSTEM_BASIC_INFORMATION sbi;
		ULONG got = 0;
		NTSTATUS st = NtQuerySystemInformation(SystemBasicInformation,
		                                      &sbi, sizeof sbi, &got);
		if (NT_SUCCESS(st) &&
		    sbi.MaximumUserModeAddress >= sbi.MinimumUserModeAddress)
			span = (size_t)(sbi.MaximumUserModeAddress -
			                sbi.MinimumUserModeAddress) + 1;
		if (!span) span = (size_t)-1 >> 1;
	}
	return span;
}

/* Same table, but for a MAP_PRIVATE section view: mmap.html says a
 * MAP_PRIVATE write "shall be visible only to the calling process" and
 * "It is unspecified whether this change to the mapped file is visible
 * to other processes... or is carried through to the underlying object."
 * -- i.e. the write must not reach the file. NT's answer to that is
 * copy-on-write (PAGE_WRITECOPY/PAGE_EXECUTE_WRITECOPY): the first write
 * to a page forks it to a private, pagefile-backed copy instead of
 * dirtying the section. Win32's own FILE_MAP_COPY works against a
 * section created with PAGE_READONLY, so this needs no extra access
 * beyond what the file was opened with. */
static ULONG prot_to_view(int prot, int private) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	if (!private) return prot_to_page(prot);
	if (prot & PROT_EXEC) {
		if (prot & PROT_WRITE) return PAGE_EXECUTE_WRITECOPY;
		if (prot & PROT_READ)  return PAGE_EXECUTE_READ;
		return PAGE_EXECUTE;
	}
	if (prot & PROT_WRITE) return PAGE_WRITECOPY;
	if (prot & PROT_READ)  return PAGE_READONLY;
	return PAGE_NOACCESS;
}

int __plat_mem_reserve(void **base_inout, size_t len, int prot) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	PVOID base = *base_inout;
	SIZE_T size = len;
	ULONG type = MEM_RESERVE;
	MEMORY_BASIC_INFORMATION mbi;
	SIZE_T got = 0;
	if (prot != PROT_NONE) type |= MEM_COMMIT;
	/* Very large single reservations make Wine spend unbounded time
	 * searching its host VMAs. Use a generous per-call ceiling and let
	 * callers consume the address space with multiple mappings instead.
	 * This is a mapping-size limit, not a live-mapping-count limit.
	 *
	 * The ceiling itself is picked at preprocessing time rather than via
	 * `sizeof(size_t)` in the comparison below: on a target where
	 * size_t is always 32-bit (i386), a runtime `sizeof(size_t) > 4`
	 * guard is one GCC can prove always false (and its `== 4` twin
	 * always true), hence -Wtype-limits. SIZE_MAX resolves the same "is
	 * size_t wider than 32 bits" question at compile time instead, so
	 * each target ends up with exactly one constant and one ordinary
	 * comparison, matching the old runtime check's behavior exactly. */
#if SIZE_MAX > 0xFFFFFFFFu
	const size_t reserve_ceiling = 0x10000000000ULL;
#else
	const size_t reserve_ceiling = 0x40000000UL;
#endif
	if (len > reserve_ceiling) {
		errno = ENOMEM;
		return -1;
	}
	if (len > user_address_span()) { errno = ENOMEM; return -1; }
	NTSTATUS st = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size,
	                                      type, prot_to_page(prot));
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	/* Some Wine/NT combinations accept a near-SIZE_MAX request after
	 * internally truncating it. mmap() cannot describe a range whose end
	 * wraps the process address space, and must not record the truncated
	 * allocation as though the whole request existed. */
	memset(&mbi, 0, sizeof mbi);
	if (size < len || (uintptr_t)base > (uintptr_t)-1 - len ||
	    !NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(), base,
	        MemoryBasicInformation, &mbi, sizeof mbi, &got)) ||
	    mbi.BaseAddress != base || mbi.AllocationBase != base ||
	    mbi.RegionSize < len ||
	    (mbi.State != MEM_RESERVE && mbi.State != MEM_COMMIT)) {
		PVOID release = base;
		SIZE_T zero = 0;
		NtFreeVirtualMemory(NtCurrentProcess(), &release, &zero, MEM_RELEASE);
		errno = ENOMEM;
		return -1;
	}
	*base_inout = base;
	return 0;
}

int __plat_mem_commit_fixed(void *base, size_t len, int prot) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	PVOID p = base;
	SIZE_T z = len;
	NTSTATUS st;
	/* Decommit then commit, so the previous mapping's modifications are
	 * actually discarded rather than left in place by a bare commit
	 * over already-committed pages -- see mman.c's MAP_FIXED banner. */
	NtFreeVirtualMemory(NtCurrentProcess(), &p, &z, MEM_DECOMMIT);
	p = base;
	z = len;
	st = NtAllocateVirtualMemory(NtCurrentProcess(), &p, 0, &z, MEM_COMMIT, prot_to_page(prot));
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_mem_decommit(void *base, size_t len)
{
	PVOID p = base;
	SIZE_T z = len;
	NTSTATUS st = NtFreeVirtualMemory(NtCurrentProcess(), &p, &z, MEM_DECOMMIT);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_mem_release(void *base, size_t len)
{
	PVOID b = base;
	SIZE_T z = 0;
	NTSTATUS st;
	(void)len; /* MEM_RELEASE takes the whole reservation; see plat_mem.h */
	st = NtFreeVirtualMemory(NtCurrentProcess(), &b, &z, MEM_RELEASE);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_mem_protect(void *addr, size_t len, int prot) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	char *p = addr;
	char *end = p + len;
	while (addr_lt(p, end)) {
		MEMORY_BASIC_INFORMATION mbi;
		SIZE_T got = 0;
		char *region_end;
		SIZE_T z;
		PVOID q;
		NTSTATUS st = NtQueryVirtualMemory(NtCurrentProcess(), p,
			MemoryBasicInformation, &mbi, sizeof mbi, &got);
		if (!NT_SUCCESS(st) || !mbi.RegionSize || mbi.State == MEM_FREE) {
			errno = ENOMEM;
			return -1;
		}
		region_end = (char *)mbi.BaseAddress + mbi.RegionSize;
		if (addr_gt(region_end, end)) region_end = end;
		if (addr_le(region_end, p)) { errno = ENOMEM; return -1; }
		z = (SIZE_T)addr_diff(region_end, p);
		q = p;
		if (mbi.State == MEM_RESERVE) {
			if (prot != PROT_NONE) {
				if (!__mman_range_is_live(p, z)) {
					errno = ENOMEM;
					return -1;
				}
				st = NtAllocateVirtualMemory(NtCurrentProcess(), &q, 0, &z,
				                             MEM_COMMIT, prot_to_page(prot));
				if (!NT_SUCCESS(st)) return __set_errno_status(st);
			}
		} else {
			ULONG old = 0;
			st = NtProtectVirtualMemory(NtCurrentProcess(), &q, &z,
			                            prot_to_page(prot), &old);
			if (!NT_SUCCESS(st)) return __set_errno_status(st);
		}
		p = region_end;
	}
	return 0;
}

/* NtLockVirtualMemory() is allowed to fail for quota/privilege reasons before
 * it diagnoses an unmapped page.  POSIX is not: mlock()/munlock() require
 * ENOMEM when any page in the requested range is not mapped.  Query first so
 * the required address-range error cannot be hidden by the runner's working
 * set limit (Wine otherwise reported STATUS_ACCESS_DENIED for LONG_MAX). */
static int lock_range_is_mapped(void *addr, size_t len)
{
	char *p = addr;
	char *end;

	if (len > (size_t)-1 - (size_t)p) { errno = ENOMEM; return 0; }
	end = p + len;
	while (addr_lt(p, end)) {
		MEMORY_BASIC_INFORMATION mbi;
		SIZE_T got = 0;
		NTSTATUS st = NtQueryVirtualMemory(NtCurrentProcess(), p,
			MemoryBasicInformation, &mbi, sizeof mbi, &got);
		char *next;

		if (!NT_SUCCESS(st) || !mbi.RegionSize) {
			errno = ENOMEM;
			return 0;
		}
		next = (char *)mbi.BaseAddress + mbi.RegionSize;
		if (addr_gt(next, end)) next = end;
		if (mbi.State == MEM_RESERVE) {
			PVOID q = p;
			SIZE_T z = (SIZE_T)addr_diff(next, p);
			if (!__mman_range_is_live(p, z) ||
			    !NT_SUCCESS(NtAllocateVirtualMemory(NtCurrentProcess(), &q,
			        0, &z, MEM_COMMIT, PAGE_NOACCESS))) {
				errno = ENOMEM;
				return 0;
			}
		} else if (mbi.State != MEM_COMMIT) {
			errno = ENOMEM;
			return 0;
		}
		if (addr_le(next, p)) { errno = ENOMEM; return 0; }
		p = next;
	}
	return 1;
}

int __plat_mem_lock(void *addr, size_t len)
{
	PVOID p = addr;
	SIZE_T z = len;
	if (!lock_range_is_mapped(addr, len)) return -1;
	NTSTATUS st = NtLockVirtualMemory(NtCurrentProcess(), &p, &z, 1);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_mem_unlock(void *addr, size_t len)
{
	PVOID p = addr;
	SIZE_T z = len;
	if (!lock_range_is_mapped(addr, len)) return -1;
	NTSTATUS st = NtUnlockVirtualMemory(NtCurrentProcess(), &p, &z, 1);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

/* Create a section over `fh` and map a view of it at *base_inout (a hint,
 * or NULL to let NT choose). Tries the broadest section protection first,
 * and falls back to a read-only section on [STATUS_ACCESS_DENIED]: a
 * handle opened O_RDONLY cannot back a PAGE_READWRITE section, but
 * MAP_PRIVATE still works against a PAGE_READONLY one via copy-on-write. */
int __plat_mem_map_file(__plat_handle_t fh, int prot, int flags, off_t off, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
                        size_t viewbytes, void **base_inout)
{
	HANDLE section;
	IO_STATUS_BLOCK io;
	FILE_STANDARD_INFORMATION si;
	NTSTATUS st;
	LARGE_INTEGER secoff;
	SIZE_T viewsize;
	ULONG maxprot;
	PVOID base = *base_inout;
	int private = (flags & MAP_PRIVATE) != 0;
	long long eof = -1;

	/* Wine can retain writes made past EOF in the shared cache page even
	 * across close()+reopen()+NtCreateSection().  POSIX requires every
	 * mapping operation to zero-fill that partial page.  Capture the
	 * logical EOF before mapping so a writable shared view can restore
	 * the required zero tail below without extending the file. */
	if (!private && (prot & PROT_WRITE)) {
		st = NtQueryInformationFile(fh, &io, &si, sizeof si,
		                            FileStandardInformation);
		if (!NT_SUCCESS(st)) { errno = st == (NTSTATUS)STATUS_NO_MEMORY ? ENOMEM : ENOTSUP; return -1; }
		eof = si.EndOfFile;
	}

	maxprot = (prot & PROT_EXEC) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
	st = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL,
	                     maxprot, SEC_COMMIT, fh);
	if (st == (NTSTATUS)STATUS_ACCESS_DENIED) {
		maxprot = (prot & PROT_EXEC) ? PAGE_EXECUTE_READ : PAGE_READONLY;
		st = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL,
		                     maxprot, SEC_COMMIT, fh);
	}
	if (!NT_SUCCESS(st)) { errno = st == (NTSTATUS)STATUS_NO_MEMORY ? ENOMEM : ENOTSUP; return -1; }

	/* ViewSize=0 means "map from SectionOffset to the end of the section":
	 * NT rounds the accessible range up to the next page boundary and
	 * zero-fills the tail on its own (mmap.html's own requirement). An
	 * explicit ViewSize of the caller's rounded `len` was tried first and
	 * rejected with [STATUS_INVALID_VIEW_SIZE] whenever `len` rounds past
	 * the file's exact byte length -- the common case, not an edge one. */
	secoff = (LARGE_INTEGER)off;
	viewsize = 0;
	st = NtMapViewOfSection(section, NtCurrentProcess(), &base, 0, 0,
	                        &secoff, &viewsize, ViewShare, 0,
	                        prot_to_view(prot, private));
	NtClose(section);
	if (!NT_SUCCESS(st)) { errno = st == (NTSTATUS)STATUS_NO_MEMORY ? ENOMEM : ENOTSUP; return -1; }
	if (eof > off && (eof & (MMAP_PAGE - 1)) != 0 &&
	    (unsigned long long)(eof - off) < viewbytes) {
		size_t tail = (size_t)(eof - off);
		size_t end = pground(tail);
		size_t i;
		if (end > viewbytes) end = viewbytes;
		for (i = tail; i < end; i++) ((char *)base)[i] = 0;
	}
	*base_inout = base;
	return 0;
}

int __plat_mem_unmap_view(void *base, size_t len)
{
	NTSTATUS st;
	(void)len; /* a view knows its own extent; see plat_mem.h */
	st = NtUnmapViewOfSection(NtCurrentProcess(), base);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_mem_flush_view(void *addr, size_t len, __plat_handle_t writeback)
{
	const void *p = addr;
	SIZE_T z = len;
	IO_STATUS_BLOCK io;
	NTSTATUS st;
	FILE_BASIC_INFORMATION bi;
	LARGE_INTEGER now;

	st = NtFlushVirtualMemory(NtCurrentProcess(), &p, &z, &io);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	/* The section flush above writes data but does not consistently
	 * advance the file times.  Preserve the attributes explicitly:
	 * Wine clears FILE_ATTRIBUTE_READONLY when FileAttributes is zero,
	 * unlike real NT (the same quirk is documented in utimensat.c). */
	st = NtQueryInformationFile(writeback, &io, &bi, sizeof bi, FileBasicInformation);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	NtQuerySystemTime(&now);
	bi.CreationTime = bi.LastAccessTime = 0;
	bi.LastWriteTime = bi.ChangeTime = now;
	st = NtSetInformationFile(writeback, &io, &bi, sizeof bi, FileBasicInformation);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

// NOLINTEND(misc-include-cleaner)
