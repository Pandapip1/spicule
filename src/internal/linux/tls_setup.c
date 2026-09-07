/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * __spicule_linux_tls_block_create() -- one real aarch64 "variant I" TLS
 * block per call: a 16-byte {dtv;reserved} TCB header, a real DTV, and
 * an independent copy of the process's PT_TLS data immediately after
 * the header. Same shape crt/linux/crt1.c's own linux_setup_tls() used
 * to build inline for the initial thread only; factored out here (see
 * linux/tls.h) so src/thread/linux/plat_thread.c's __plat_thread_spawn()
 * can hand every CLONE_SETTLS'd thread an equally real block, built by
 * the exact same code path rather than a second, hand-copied one that
 * could silently drift out of sync.
 *
 * The compiler/linker bake `tp + 16 + <link-time offset>` into every
 * Local-Exec `__thread` access (R_AARCH64_TLSLE_* relocations); this
 * function's whole job is handing back a `tp` for which that address is
 * a correctly-initialized copy of PT_TLS's data. dtv[1] = tp additionally
 * satisfies the General-Dynamic path a dlopen()'d object's own TLS
 * access can take back into the main image (src/dlfcn/linux/
 * plat_dlfcn.c's own module-id scheme, module 1 reserved for this).
 *
 * Raw mmap(2) only, no malloc(): the initial-thread caller runs before
 * any allocator is initialized, and a later pthread_create() caller
 * must not depend on this library's own allocator being safe to call
 * while it may itself be constructing a brand new thread's bookkeeping.
 */

// NOLINTBEGIN(misc-include-cleaner)
#include "linux/tls.h"
#include "unsafe_pointer.h"

#if defined(__aarch64__)

struct spicule_linux_tls_layout __spicule_linux_tls_layout;

#define SYS_mmap 222 /* aarch64 only -- this whole file is aarch64-only,
                      * see linux/tls.h's own #if defined(__aarch64__) */
#define PROT_READ     0x1
#define PROT_WRITE    0x2
#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x20

static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6) // NOLINT(bugprone-easily-swappable-parameters) -- raw syscall ABI slots are positional and semantically distinct
{
	register long x8 __asm__("x8") = nr;
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = a3;
	register long x3 __asm__("x3") = a4;
	register long x4 __asm__("x4") = a5;
	register long x5 __asm__("x5") = a6;
	__asm__ volatile("svc #0"
		: "+r"(x0)
		: "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
		: "memory", "cc");
	return x0;
}

/* Must equal src/dlfcn/linux/plat_dlfcn.c's own TLS_DTV_INITIAL_CAPACITY
 * -- a numeric contract duplicated across the two files rather than
 * shared through a header, matching that file's own stated discipline
 * for this exact constant. Every DTV this function hands out -- the
 * initial thread's own (via crt1.c) or any later pthread_create()'d
 * thread's -- starts at this same capacity, so plat_dlfcn.c's
 * tls_dtv_ensure_capacity() growth logic (keyed off a THREAD's own tp)
 * behaves identically regardless of which thread it is growing. */
#define TLS_DTV_INITIAL_CAPACITY 8

void *__spicule_linux_tls_block_create(void)
{
	unsigned long tls_vaddr = __spicule_linux_tls_layout.vaddr;
	unsigned long tls_filesz = __spicule_linux_tls_layout.filesz;
	unsigned long tls_memsz = __spicule_linux_tls_layout.memsz;
	unsigned long data_align = __spicule_linux_tls_layout.align > 16
		? __spicule_linux_tls_layout.align : 16;
	unsigned long tcb_size = 16; /* dtv + reserved, fixed by the ABI */
	unsigned long alloc_size = tcb_size + tls_memsz + data_align; /* slack for alignment */
	long mm, dtv_mm;
	unsigned char *base, *data, *tp;
	void **dtv;
	unsigned long i;

	mm = raw_syscall(SYS_mmap, 0, (long)alloc_size, PROT_READ | PROT_WRITE,
	                 MAP_PRIVATE | MAP_ANONYMOUS, -1L, 0L);
	if ((unsigned long)mm >= (unsigned long)-4095L) return 0; /* allocation failed */
	/* mm is the raw mmap(2) syscall's own return-register value, just
	 * checked above (the `>= -4095` idiom this file's raw_syscall()
	 * ABI uses for "negative errno") to be a real success, not an
	 * encoded error. This aarch64 raw-syscall ABI's success contract is
	 * that the return register holds the mapped virtual address the
	 * kernel actually chose (we passed addr=0, i.e. MAP_ANONYMOUS
	 * let-the-kernel-choose) -- there is no pointer anywhere in this
	 * translation unit for that address to be derived from; the kernel
	 * mapping it is the entire reason it is valid. */
	base = unsafe_assume_valid_pointer((unsigned char *)mm);

	data = base + tcb_size;
	data = (unsigned char *)(((unsigned long)data + data_align - 1) & ~(data_align - 1));

	if (tls_filesz) {
		/* tls_vaddr == __spicule_linux_tls_layout.vaddr, the PT_TLS
		 * segment's own link-time virtual address as the kernel/loader
		 * mapped this executable -- crt1.c's linux_setup_tls() (already
		 * exempt below, same reasoning) populates
		 * __spicule_linux_tls_layout once from the real ELF program
		 * headers this process was loaded from, at a fixed load bias of
		 * 0 for a non-PIE static binary. Copying tls_filesz bytes from
		 * it below is exactly PT_TLS's own contract: the file-backed
		 * initializer image for every thread's TLS block. */
		const unsigned char *source =
		    unsafe_assume_valid_pointer((const unsigned char *)tls_vaddr);
		for (i = 0; i < tls_filesz; i++) data[i] = source[i];
	}
	for (i = tls_filesz; i < tls_memsz; i++) data[i] = 0;

	dtv_mm = raw_syscall(SYS_mmap, 0, (long)(TLS_DTV_INITIAL_CAPACITY * sizeof(void *)),
	                     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1L, 0L);
	if ((unsigned long)dtv_mm >= (unsigned long)-4095L) return 0; /* the `base` block above
	                                                                * is leaked here, matching
	                                                                * this function's own
	                                                                * predecessor's behavior in
	                                                                * crt1.c: a bootstrap-only,
	                                                                * essentially-never-hit path */
	/* dtv_mm is a second raw mmap(2) return value, same syscall-ABI
	 * success contract just justified for `mm` above (checked
	 * non-error immediately above this line). */
	dtv = unsafe_assume_valid_pointer((void **)dtv_mm);
	for (i = 0; i < TLS_DTV_INITIAL_CAPACITY; i++) dtv[i] = 0;

	tp = data - tcb_size;
	dtv[1] = tp; /* module 1 == the main image, see this file's own banner */
	((void **)tp)[0] = dtv;
	((void **)tp)[1] = 0; /* reserved */
	return tp;
}

#endif
// NOLINTEND(misc-include-cleaner)
