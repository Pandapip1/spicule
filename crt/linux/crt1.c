/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Program startup for a real, native Linux target -- the platform-axis
 * override of crt/crt1.c (Makefile's PLAT_GLOBS mechanism replaces the
 * NT crt1.o object wholesale for PLATFORM=linux).
 *
 * Unlike NT, the kernel places already-split argc/argv[]/envp[]/auxv[]
 * directly on the initial stack (System V ABI), so argv just aliases
 * the kernel-provided array -- no split_cmdline() equivalent exists.
 *
 * environ, by contrast, DOES need a real copy (linux_build_environ()
 * below): src/env/setenv.c's __putenv() free()s/realloc()s through this
 * library's allocator, so aliasing envp in place would eventually
 * free() a pointer into the kernel-provided stack block.
 *
 * TLS is the other thing NT's loader does for free that this file must
 * do by hand: a statically-linked, no-libc Linux ELF binary gets no TLS
 * block set up by the kernel at all (it doesn't even look at PT_TLS),
 * and errno itself is thread-local, so linux_setup_tls() below must run
 * before anything else, including __fd_init().
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include "libc.h"
#include "plat_exit.h"
#include "linux/tls.h"
#include "unsafe_pointer.h"

int main(int, char **, char **);

char **environ;
char **__argv;
int __argc;
char *__progname;
char *__progname_full;

/* This file's own raw syscall trampoline, not `extern long syscall(long,
 * ...)`: this file's link has no host libc to resolve that against.
 * Needed here only for the bootstrap mmap() the TLS block requires,
 * issued before __fd_init() and before any general allocator is safe to
 * assume -- deliberately not routed through __plat_mmap_anon(), which
 * would pull in the mman subsystem this early. */
#if defined(__aarch64__)
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6) // NOLINT(bugprone-easily-swappable-parameters) -- raw syscall ABI slots are positional and semantically distinct
{
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = a3;
	register long x3 __asm__("x3") = a4;
	register long x4 __asm__("x4") = a5;
	register long x5 __asm__("x5") = a6;
	register long x8 __asm__("x8") = nr;
	__asm__ volatile("svc #0"
	                 : "+r"(x0)
	                 : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
	                 : "memory", "cc");
	return x0;
}
#define SYS_mmap 222
#define SYS_write 64
#elif defined(__x86_64__)
/* System V AMD64 syscall convention: rax = number, rdi/rsi/rdx/r10/r8/
 * r9 = up to 6 arguments (r10, not rcx -- `syscall` itself clobbers
 * rcx with the return address), result in rax. rcx and r11 (clobbered
 * by `syscall` for the return address and saved rflags respectively)
 * must be declared clobbered even though nothing here reads them
 * afterward -- leaving them off would let the compiler assume they
 * still hold whatever it last put there. */
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long ret;
	register long r10 __asm__("r10") = a4;
	register long r8  __asm__("r8")  = a5;
	register long r9  __asm__("r9")  = a6;
	__asm__ volatile("syscall"
	                 : "=a"(ret)
	                 : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
	                 : "rcx", "r11", "memory");
	return ret;
}
#define SYS_mmap 9
#define SYS_write 1
#elif defined(__i386__)
/* i386 has no free register for a 6th syscall argument once
 * ebx/ecx/edx/esi/edi hold the first five -- only ebp is left, and
 * cdecl reserves that as the frame pointer. Fix: build an array of the
 * seven words (nr, a1..a6), point eax at it, load the other five
 * registers from memory through that pointer, then load eax itself
 * LAST (overwriting the pointer with the syscall number). ebx/ebp are
 * manually saved/restored since they're cdecl callee-saved and can't
 * appear in the clobber list. */
static long raw_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long args[7];
	long ret;
	args[0] = nr; args[1] = a1; args[2] = a2; args[3] = a3;
	args[4] = a4; args[5] = a5; args[6] = a6;
	__asm__ volatile(
		"pushl %%ebp\n\t"
		"pushl %%ebx\n\t"
		"movl 4(%%eax), %%ebx\n\t"
		"movl 8(%%eax), %%ecx\n\t"
		"movl 12(%%eax), %%edx\n\t"
		"movl 16(%%eax), %%esi\n\t"
		"movl 20(%%eax), %%edi\n\t"
		"movl 24(%%eax), %%ebp\n\t"
		"movl (%%eax), %%eax\n\t"
		"int $0x80\n\t"
		"popl %%ebx\n\t"
		"popl %%ebp"
		: "=a"(ret)
		: "a"(args)
		: "ecx", "edx", "esi", "edi", "memory", "cc");
	return ret;
}
/* SYS_mmap2, not the old single-struct-arg SYS_mmap (90): mmap2 takes
 * its six arguments in plain registers like every other syscall here,
 * at the cost of offset being in page units -- moot since every call
 * site passes offset 0. */
#define SYS_mmap 192
#define SYS_write 4
#else
#error "crt/linux/crt1.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

/* Minimal local ELF/auxv shapes -- this project ships no <elf.h> yet.
 * The program header struct is NOT arch-independent: ELFCLASS64's
 * Elf64_Phdr and ELFCLASS32's Elf32_Phdr differ in FIELD ORDER as well
 * as width (p_flags is 2nd in Elf64_Phdr, 2nd-to-last in Elf32_Phdr),
 * so i386 gets its own struct rather than a narrowed 64-bit one. */
#if defined(__i386__)
struct elf_phdr {
	unsigned int p_type;
	unsigned int p_offset;
	unsigned int p_vaddr;
	unsigned int p_paddr;
	unsigned int p_filesz;
	unsigned int p_memsz;
	unsigned int p_flags;
	unsigned int p_align;
};
#else
struct elf_phdr {
	unsigned int p_type;
	unsigned int p_flags;
	unsigned long p_offset;
	unsigned long p_vaddr;
	unsigned long p_paddr;
	unsigned long p_filesz;
	unsigned long p_memsz;
	unsigned long p_align;
};
#endif
#define PT_PHDR 6
#define PT_TLS 7

struct auxv_entry {
	unsigned long a_type;
	unsigned long a_val;
};
#define AT_NULL  0
#define AT_PHDR  3
#define AT_PHENT 4
#define AT_PHNUM 5

/* Walks auxv for AT_PHDR/AT_PHENT/AT_PHNUM, then the program header
 * table, looking for PT_TLS (and PT_PHDR, for *load_bias_out).
 *
 * *load_bias_out exists because AT_PHDR and a program header's p_vaddr
 * are not interchangeable: AT_PHDR is always the real, mapped runtime
 * address, but p_vaddr is a link-time address that only equals the
 * runtime address for a non-PIE ET_EXEC binary. For an ET_DYN PIE
 * binary the kernel picks a random load address, and every p_vaddr
 * needs that same bias added before it is dereferenceable.
 *
 * The bias is derived the standard way ELF loaders do: PT_PHDR's own
 * p_vaddr describes the program header table's link-time address, the
 * same table AT_PHDR gives the runtime address of, so
 * `AT_PHDR - PT_PHDR->p_vaddr` is the offset every other p_vaddr in
 * this image needs. No PT_PHDR (or no auxv) leaves *load_bias_out at
 * 0, correct for an ET_EXEC image. */
static struct elf_phdr *find_tls_phdr(long *auxv, unsigned long *load_bias_out)
    __attribute__((nonnull(1, 2)));
static struct elf_phdr *find_tls_phdr(long *auxv, unsigned long *load_bias_out)
{
	unsigned long phdr = 0, phent = 0, phnum = 0;
	unsigned long i;
	struct elf_phdr *tls = 0;

	*load_bias_out = 0;

	for (; auxv[0] != AT_NULL; auxv += 2) {
		if (auxv[0] == AT_PHDR) phdr = (unsigned long)auxv[1];
		else if (auxv[0] == AT_PHENT) phent = (unsigned long)auxv[1];
		else if (auxv[0] == AT_PHNUM) phnum = (unsigned long)auxv[1];
	}
	if (!phdr || !phent || !phnum) return 0; /* no auxv -- nothing to set up */

	/* ph is a local computed from phdr, guarded above by
	 * `if (!phdr || ...) return;` -- the kernel's ELF auxv contract
	 * guarantees AT_PHDR points to a real, mapped program header table
	 * whenever it's present at all. */
	for (i = 0; i < phnum; i++) {
		/* phdr is AT_PHDR, straight out of the kernel-populated auxv --
		 * the kernel's ELF auxv contract guarantees it points to a real,
		 * mapped program header table whenever it's present at all
		 * (checked above), not something this loop derives from a
		 * pointer anywhere in this translation unit. */
		struct elf_phdr *ph =
		    unsafe_assume_valid_pointer((struct elf_phdr *)(phdr + i * phent));
		if (ph->p_type == PT_TLS) tls = ph;
		else if (ph->p_type == PT_PHDR) *load_bias_out = phdr - (unsigned long)ph->p_vaddr;
	}
	return tls;
}

#if defined(__aarch64__)
/* aarch64's TLS layout (AAELF64 ABI "variant I"): TPIDR_EL0 addresses a
 * fixed 2-pointer TCB header (dtv slot, reserved), and the module's TLS
 * data begins right after it at tp + 16, rounded up to alignment. The
 * compiler/linker already bake `tp + 16 + <link-time offset>` into
 * every access (R_AARCH64_TLSLE_* relocations); this function's job is
 * making sure `tp + 16` lands on a correctly-initialized copy of
 * PT_TLS's data.
 *
 * The dtv slot is real: src/dlfcn/linux/plat_dlfcn.c builds per-
 * dlopen()'d-object TLS on top of it, with module 1 reserved for the
 * main image (dtv[1] = tp, set inside __ntlibc_linux_tls_block_create()
 * below).
 *
 * A TCB (with real DTV) is ALWAYS installed, even with no PT_TLS
 * segment: a later dlopen() of a PT_TLS-bearing object still needs a
 * real TPIDR_EL0/DTV to register into, and this is the only place that
 * runs before any dlopen() could. `tls` being NULL just means an empty
 * main-image TLS block.
 *
 * The actual block construction (raw mmap() of the TCB+DTV, copying
 * PT_TLS's data in) lives in src/internal/linux/tls_setup.c's
 * __ntlibc_linux_tls_block_create(), not here: src/thread/linux/
 * plat_thread.c's __plat_thread_spawn() needs to build the exact same
 * shape for every pthread_create()'d thread's own CLONE_SETTLS block,
 * and sharing the one real implementation rules out the two ever
 * silently drifting apart. This function's own job narrows to finding
 * PT_TLS (auxv is only ever available here, at process startup) and
 * publishing it through __ntlibc_linux_tls_layout for that shared
 * builder to read -- including from a later pthread_create() call, long
 * after auxv has gone out of scope. */
static void linux_setup_tls(long *auxv)
{
	unsigned long load_bias;
	struct elf_phdr *tls = find_tls_phdr(auxv, &load_bias);
	void *tp;

	__ntlibc_linux_tls_layout.vaddr = tls ? tls->p_vaddr + load_bias : 0;
	__ntlibc_linux_tls_layout.filesz = tls ? tls->p_filesz : 0;
	__ntlibc_linux_tls_layout.memsz = tls ? tls->p_memsz : 0;
	__ntlibc_linux_tls_layout.align = tls ? tls->p_align : 0;

	tp = __ntlibc_linux_tls_block_create();
	if (!tp) return; /* bootstrap alloc failed -- leave TPIDR_EL0 unset */

	__asm__ volatile("msr tpidr_el0, %0" : : "r"(tp) : "memory");
}
#elif defined(__x86_64__) || defined(__i386__)
/* x86_64/i386's TLS layout ("variant II", contrasted with aarch64's
 * variant I above): the module's TLS data sits BEFORE the thread
 * pointer, at negative offsets, and the TCB's first word is a
 * SELF-pointer (tp->self == tp), not a dtv slot. Under the Local Exec
 * model, a `__thread` access compiles to `%fs:(tpoff)` / `%gs:(tpoff)`
 * with tpoff a small negative link-time constant (R_X86_64_TPOFF32 /
 * R_386_TLS_TPOFF); this function's job is making sure `tp + tpoff`
 * for every such tpoff contains a correctly-initialized copy of
 * PT_TLS's data, with tp placed `round_up(p_memsz, p_align)` bytes
 * after the data begins.
 *
 * Setting the thread pointer register differs between the two: x86_64
 * has arch_prctl(2) for FS_BASE; i386 has no such syscall and must
 * install a GDT-style descriptor via set_thread_area(2) then load %gs
 * with the resulting selector.
 *
 * NOT extended with a DTV the way aarch64's sibling is: per-object TLS
 * (src/dlfcn/linux/plat_dlfcn.c) is aarch64-only, and variant II's own
 * psABI doesn't reserve a dtv word the way variant I's TCB header
 * does. */
static void linux_setup_tls(long *auxv)
{
	unsigned long load_bias;
	struct elf_phdr *tls = find_tls_phdr(auxv, &load_bias);
	unsigned long tls_size, data_align, tcb_size, alloc_size;
	long mm;
	unsigned char *base, *data, *tp;

	/* No PT_TLS segment: unlike aarch64, this is fine to leave as an
	 * early return, since per-object TLS is aarch64-only and nothing
	 * here needs FS_BASE/%gs set up for "no TLS at all". */
	if (!tls) return;

	/* data_align MUST be the segment's true p_align, not inflated the
	 * way aarch64's identical-looking data_align above safely is:
	 * variant II's tpoff is NEGATIVE, computed by the linker as exactly
	 * `offset - round_up(p_memsz, p_align)` using the segment's own
	 * declared p_align. Inflating it here would move tp away from
	 * where the data copy actually landed, silently reading the wrong
	 * memory for a fresh `__thread` variable. */
	data_align = tls->p_align ? tls->p_align : 1;
	tcb_size = sizeof(void *); /* just the self-pointer, unlike
	                            * aarch64's 2-pointer header -- no dtv
	                            * is ever read here */
	tls_size = (tls->p_memsz + data_align - 1) & ~(data_align - 1);
	alloc_size = tls_size + tcb_size + data_align; /* slack for alignment */

	mm = raw_syscall(SYS_mmap, 0, (long)alloc_size, PROT_READ | PROT_WRITE,
	                 MAP_PRIVATE | MAP_ANONYMOUS, -1L, 0L);
	if ((unsigned long)mm >= (unsigned long)-4095L) return; /* bootstrap alloc failed -- leave tp unset */
	base = (unsigned char *)mm;

	data = (unsigned char *)(((unsigned long)base + data_align - 1) & ~(data_align - 1));
	tp = data + tls_size; /* TCB starts immediately AFTER the TLS data
	                       * block -- the defining difference from
	                       * aarch64's layout above. */

	memcpy(data, (void *)(unsigned long)(tls->p_vaddr + load_bias), tls->p_filesz);
	memset(data + tls->p_filesz, 0, tls->p_memsz - tls->p_filesz);

	*(unsigned char **)tp = tp; /* TCB self-pointer: every variant II
	                             * ABI guarantees `mov %fs:0, %reg` can
	                             * read this back. */

#if defined(__x86_64__)
#define ARCH_SET_FS 0x1002
#define SYS_arch_prctl 158
	raw_syscall(SYS_arch_prctl, ARCH_SET_FS, (long)tp, 0, 0, 0, 0);
#else /* __i386__ */
	/* i386 has no arch_prctl(2): the thread pointer is the %gs segment
	 * register, which needs a real GDT-shaped descriptor behind it
	 * before it can be loaded (an unmatched selector just faults).
	 * set_thread_area(2) installs one into a free GDT slot the kernel
	 * picks (entry_number == -1 on entry, filled in on return);
	 * base_addr is where %gs:0 should point (tp itself), and the rest
	 * gives it a full 4 GiB flat span. Field layout matches the kernel
	 * UAPI's struct user_desc exactly. */
	struct user_desc {
		unsigned int entry_number;
		unsigned int base_addr;
		unsigned int limit;
		unsigned int seg_32bit : 1;
		unsigned int contents : 2;
		unsigned int read_exec_only : 1;
		unsigned int limit_in_pages : 1;
		unsigned int seg_not_present : 1;
		unsigned int useable : 1;
	} u;
	unsigned short gs_selector;
#define SYS_set_thread_area 243

	u.entry_number = (unsigned int)-1;
	u.base_addr = (unsigned int)(unsigned long)tp;
	u.limit = 0xfffff;
	u.seg_32bit = 1;
	u.contents = 0;         /* MODIFY_LDT_CONTENTS_DATA */
	u.read_exec_only = 0;
	u.limit_in_pages = 1;   /* limit is in 4 KiB pages -> a 4 GiB span */
	u.seg_not_present = 0;
	u.useable = 1;

	if ((unsigned long)raw_syscall(SYS_set_thread_area, (long)&u, 0, 0, 0, 0, 0) >= (unsigned long)-4095L)
		return; /* could not install the descriptor -- leave %gs unset */

	/* GDT selector: (index << 3) | RPL 3 | TI=0 (GDT, not LDT) --
	 * ordinary user-mode segment-selector encoding, the same shape
	 * every i386 segment register value follows. */
	gs_selector = (unsigned short)((u.entry_number << 3) | 3);
	__asm__ volatile("movw %w0, %%gs" : : "r"(gs_selector) : "memory");
#endif
}
#endif

/* Builds this library's own, independently-owned copy of the initial
 * environment (see this file's top banner for why aliasing envp in
 * place is a real, confirmed bug). __malloc()/__free(), not
 * malloc()/free(): this runs before __fd_init().
 *
 * count is the caller's own responsibility, exactly the way argc is for
 * every argc/argv-shaped utility entry point in src/internal/util.h --
 * the NUL-scan that discovers it happens once, at the call site, so
 * elements_withtok(null_terminated, count) below can name a parameter
 * the caller already proved, instead of a length this function would
 * otherwise have to discover on its own with no way to state the result. */
static char **linux_build_environ(
	char **envp elements_withtok(null_terminated, count), size_t count)
	__attribute__((nonnull(1)));
static char **linux_build_environ(
	char **envp elements_withtok(null_terminated, count), size_t count)
{
	size_t i, evbytes, added;
	char **ev;

	if (!__size_add_checked(count, 1, &added) ||
	    !__size_mul_checked(added, sizeof(char *), &evbytes)) return 0;
	ev = (char **)__malloc(evbytes);
	if (!ev) return 0;

	for (i = 0; i < count; i++) {
		size_t len = strlen(envp[i]);
		size_t bytes;
		char *s;
		if (!__size_add_checked(len, 1, &bytes)) {
			__free(ev);
			return 0;
		}
		s = (char *)__malloc(bytes);
		if (!s) {
			while (i > 0) __free(ev[--i]);
			__free(ev);
			return 0;
		}
		memcpy(s, envp[i], len + 1);
		ev[i] = s;
	}
	ev[count] = 0;
	return ev;
}

/* sp is the live initial stack pointer the kernel sets up per the
 * System V ABI process-startup contract; crt/linux/$(ARCH)/start.S's
 * _start passes it straight through (e.g. aarch64's `mov x0, sp`). */
_Noreturn void __linux_start_main(long *sp) // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision
    __attribute__((nonnull(1)));
_Noreturn void __linux_start_main(long *sp)
{
	static char empty_progname[] = "";
	long argc = sp[0];
	char **argv = (char **)(sp + 1);
	char **envp = argv + argc + 1;
	long *auxv = (long *)envp;
	size_t envc = 0;
	char *slash;
	int rc;

	/* Unlike the NT side, fd 2 needs no setup here: it is stderr from
	 * the kernel's own exec(2) contract before this program's first
	 * instruction runs, so this checks and reports as the literal first
	 * statement. Raw write(2), not stdio, which doesn't exist yet.
	 * Exit code 111 is a plain sentinel unlikely to be mistaken for a
	 * real exit(3) value or a signal-death encoding (128+n). */
	if (!__verify_ldbl_layout()) {
		static const char msg[] =
			"ntlibc: long double bit-layout assumption failed at startup\n";
		raw_syscall(SYS_write, 2, (long)msg, sizeof msg - 1, 0, 0, 0);
		__plat_terminate(111);
	}

	/* auxv is a local derived from sp by pointer arithmetic that stays
	 * within the same kernel-provided initial stack block. */
	while (*auxv) auxv++;
	auxv++; /* skip envp's own NULL terminator -- auxv starts right after */

	linux_setup_tls(auxv);

	__argc = (int)argc;
	__argv = argv;
	while (envp[envc]) envc++;
	environ = linux_build_environ(envp, envc);
	if (!environ) {
		static const char msg[] =
			"ntlibc: out of memory building environ at startup\n";
		raw_syscall(SYS_write, 2, (long)msg, sizeof msg - 1, 0, 0, 0);
		__plat_terminate(111);
	}
	__progname_full = argc > 0 ? argv[0] : empty_progname;
	slash = __progname_full;
	for (char *p = __progname_full; *p; p++)
		if (*p == '/') slash = p + 1;
	__progname = slash;

	__fd_init();
	/* After fd setup, before main(), mirroring crt/crt1.c's identical
	 * ordering on the NT side, so a fault anywhere in main() reaches
	 * real delivery instead of the kernel's unseen default action. */
	__signal_init();

	__fenv_init();

	/* environ, not envp: main()'s third argument should be the same
	 * array getenv()/setenv() operate on, not the raw kernel block it
	 * was built from. */
	rc = main((int)argc, argv, environ);
	/* exit(rc), not __plat_terminate(rc) directly: exit() flushes open
	 * stdio streams and runs atexit() handlers first. */
	exit(rc);
}

// NOLINTEND(misc-include-cleaner)
