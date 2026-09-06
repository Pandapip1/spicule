/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * src/internal/plat_dlfcn.h's Linux backend: a real, from-scratch ELF
 * dynamic loader for dlopen()/dlsym()/dlclose()/dlerror(),
 * linked directly into libc.a -- no separate ld.so, no PT_INTERP, no
 * mmap'd-off-disk loader spliced in later the way glibc's "static
 * dlopen" retrofit works (which is also the cause of glibc bug 20802,
 * getauxval() breaking after static dlopen). ntlibc's Linux port has
 * no PT_INTERP to begin with and no existing ld.so to reuse, so this
 * file just IS the loader: ordinary code in libc.a that mmaps a
 * caller-named .so, parses it, relocates it, and hands back an opaque
 * handle, using open()/pread()/close()/malloc() through the normal
 * public API (safe here since this file runs well after __fd_init()/
 * malloc init) -- except for its own raw mmap()/munmap()/mprotect()
 * syscall wrappers; see that section below for why the public
 * <sys/mman.h> front door doesn't fit this loader's needs.
 *
 * ============================================================
 * SCOPE: WHAT THIS LOADER SUPPORTS
 * ============================================================
 *
 * See test/posix-dl-linux.c for running proof of every "yes" below.
 *
 *   - ELFDATA2LSB, EM_AARCH64/EM_X86_64/EM_386. ELFCLASS64 on aarch64/
 *     x86_64, ELFCLASS32 on i386 -- a real class difference, not just a
 *     narrower ELFCLASS64: see this file's own "minimal local ELF32/
 *     ELF64 shapes" banner for the Elf_* generic-typedef scheme that
 *     covers the struct-shape half of that split, and apply_reloc_
 *     table()'s own banner for the SHT_REL-vs-SHT_RELA (implicit-vs-
 *     explicit addend) half.
 *   - ET_DYN (shared object) input only.
 *   - PT_LOAD segments mapped faithfully, including bss tail-zeroing.
 *   - PT_DYNAMIC: DT_HASH (an exact symbol count; DT_GNU_HASH is NOT
 *     supported), DT_SYMTAB/DT_STRTAB/DT_SYMENT, DT_RELA/DT_JMPREL on
 *     aarch64/x86_64 or DT_REL/DT_JMPREL on i386 (PLT relocations
 *     processed identically to DT_RELA/DT_REL -- this loader always
 *     binds eagerly, so RTLD_NOW vs. RTLD_LAZY is moot), DT_NEEDED,
 *     DT_INIT/DT_INIT_ARRAY.
 *   - Relocations: R_AARCH64_RELATIVE/ABS64/GLOB_DAT/JUMP_SLOT/
 *     IRELATIVE (GNU ifunc) and R_AARCH64_TLSDESC (aarch64), the
 *     equivalent R_X86_64_* set (x86_64), the equivalent R_386_* set
 *     minus an IRELATIVE-shaped TLS descriptor equivalent (i386 --
 *     PT_TLS is refused outright there, see below, so no i386 TLS
 *     relocation type is ever reached). Anything else is a clean, loud
 *     dlopen() failure (apply_one_reloc()'s `default:` case), never a
 *     silent mis-relocation.
 *   - PT_TLS: loaded for real on aarch64 (see "TLS / per-library
 *     thread descriptors" below). Refused cleanly, before anything is
 *     mapped, on every other architecture.
 *   - DT_NEEDED: chased recursively (load_object() loads each
 *     dependency, resolved relative to the referring object's own
 *     directory then as a bare name -- no DT_RPATH/DT_RUNPATH/
 *     LD_LIBRARY_PATH/ldconfig-cache search). An object's own
 *     undefined symbols are checked against its loaded dependencies
 *     before falling through to the static binary. See "NAMESPACE
 *     ISOLATION" below for how this interacts with dedup.
 *   - PT_GNU_RELRO: applied (mprotect(PROT_READ) after relocation and
 *     protection-narrowing, matching glibc's own _dl_protect_relro).
 *   - DT_INIT/DT_INIT_ARRAY: run once per dlopen(), in file order,
 *     after relocation/protection/RELRO are finished, and (for a
 *     DT_NEEDED dependency) before the object that depends on it runs
 *     its own -- load_object()'s depth-first order gives this for
 *     free.
 *
 * ============================================================
 * SYMBOL RESOLUTION AGAINST THE STATIC BINARY
 * ============================================================
 *
 * The static link into libc.a leaves no .dynsym at all -- nothing
 * shaped like a normal "shared object exports list" to search when a
 * dlopen()'d object's undefined symbols need to resolve against libc/
 * the main program.
 *
 * This file's answer: at symbol-resolution time, open /proc/self/exe
 * -- this same running binary's own file -- and read its ELF section
 * header table to find .symtab/.strtab, the way `nm`/`readelf` would
 * from outside the process (self_symtab_load() below). This needs no
 * build-system changes (no generated export table to keep in sync),
 * gets every symbol the linker kept rather than a hand-picked subset,
 * and is exactly the mechanism POSIX already wants dlopen(NULL, ...) +
 * dlsym() to provide -- MAIN_IMAGE_HANDLE's resolution path and a
 * dlopen()'d object's own undefined-symbol resolution are the same
 * function, resolve_main_symbol().
 *
 * The real cost: this depends on the running binary NOT being
 * stripped. A stripped binary has no .symtab -- self_symtab_load()
 * fails cleanly, and dlopen() then fails with a clear dlerror()
 * rather than resolving anything silently wrong. A production build
 * that strips its output would need a generated symbol table instead
 * (real deferred work, not a hidden gap).
 *
 * ============================================================
 * NAMESPACE ISOLATION / VERSION COEXISTENCE
 * ============================================================
 *
 * Requirement: if A dlopen()s one version of B and C dlopen()s a
 * different version of B, both must coexist correctly with no global
 * symbol-table collision -- as plain dlopen()'s DEFAULT behavior, not
 * an opt-in the way glibc's dlmopen() is (musl has no equivalent at
 * all).
 *
 * This file's answer: __plat_dlopen() NEVER deduplicates. Every call,
 * including two calls on the byte-identical path, mmaps a fresh,
 * independent copy at its own kernel-chosen address and gets its own
 * freshly-applied relocations. This is a deliberate, disclosed
 * deviation from dlopen.html's DESCRIPTION ("only a single copy...
 * shall be brought into the address space"): the pointer-identity and
 * no-double-mapping guarantees that sentence buys are exactly what
 * creates the version-collision hazard this design rules out. Because
 * there is no dedup, there is also no refcounting: dlclose()
 * unconditionally tears down exactly the one instance its handle
 * names.
 *
 * DT_NEEDED chasing preserves this property transitively: load_object()
 * never dedups a dependency against anything, not even an earlier
 * dependency loaded within the same top-level dlopen()'s own graph -- a
 * diamond dependency (A needs B and C, both need D) loads D twice, as
 * two fully independent objects. Real cost (extra mapping/relocation
 * work, no shared mutable state across the diamond), traded for one
 * uniform rule with no dependency-graph-shaped exception.
 *
 * ============================================================
 * TLS / PER-LIBRARY THREAD DESCRIPTORS
 * ============================================================
 *
 * Requirement: each loaded library's TLS block gets its OWN TD
 * (thread descriptor/TCB), not a slot carved out of one shared
 * per-thread TD the way glibc's dynamic-TLS extension does it.
 *
 * crt/linux/crt1.c's linux_setup_tls() sets TPIDR_EL0 to a block
 * shaped `{ dtv; reserved; <TLS data...> }` (AAELF64 "variant I").
 * This file's design: INDEX, never swap TPIDR_EL0. The real TCB gets
 * a real DTV (array of pointers; index 0 reserved, index 1 the main
 * image); module id N (>=2, assigned at dlopen() time to any object
 * with a PT_TLS segment) points at a SECOND, independently allocated
 * block shaped exactly like the real TCB -- satisfying "own TD per
 * library" literally, even though TPIDR_EL0 itself never moves. The
 * compiler-generated TLS access sequence for a dlopen()'d .so already
 * does this indexing for us (General-Dynamic model, R_AARCH64_TLSDESC
 * on this toolchain -- see that relocation's own #define comment): a
 * real resolver is just `dtv[module_id] + header + offset`, one array
 * index off the never-swapped TCB.
 *
 * Why not swap TPIDR_EL0 around calls into library code instead: (1)
 * "a call into library code" isn't a syntactically closed boundary --
 * dlsym() hands back a bare function pointer that can be invoked from
 * anywhere, including a signal handler or after a longjmp() past a
 * naive restore; only a compiler-generated thunk at every call site
 * could do this reliably, not something a loader retrofits. (2) it
 * would make TPIDR_EL0 invisible, dynamically-scoped global state --
 * two identical-looking `__thread` reads could mean different memory
 * depending on an ambient register neither reads nor writes. (3)
 * indexing needs zero call-site codegen changes: it's exactly where a
 * compiler already routes GD/LD-model TLS access on any ELF platform.
 *
 * What is built (aarch64 only): crt1.c's linux_setup_tls() installs a
 * real DTV; this file's module-id allocator (next_tls_module_id) and
 * DTV-growth function (tls_dtv_ensure_capacity()) hand every
 * PT_TLS-bearing object a fresh id and slot (setup_object_tls()); and
 * __ntlibc_tlsdesc_resolver (hand-written aarch64 asm, see its own
 * banner near apply_one_reloc()) is the runtime resolver R_AARCH64_
 * TLSDESC relocations are wired to. See test/posix-dl-linux.c's
 * test_pt_tls_per_object() for running proof.
 *
 * What is NOT built: x86_64/i386 still refuse any PT_TLS object
 * cleanly. Their "variant II" TCB (AAELF64's term: TLS data at
 * NEGATIVE tp offsets, first TCB word a self-pointer) has no dtv word
 * in its header at all, so adding one needs a genuinely separate
 * design, not a copy of aarch64's layout -- deferred, not merely
 * unstarted.
 *
 * ============================================================
 * PT_GNU_RELRO HARDENING
 * ============================================================
 *
 * See load_object()'s own PT_GNU_RELRO comment for the mechanism, and
 * test/posix-dl-linux.c's test_pt_gnu_relro_hardening() for running
 * proof: a fork()ed child's write through a RELRO-covered, load-time-
 * relocated `const` function pointer genuinely SIGSEGVs.
 *
 * ============================================================
 * THREAD SAFETY
 * ============================================================
 *
 * self_symtab_load()'s lazy init is race-free: it wraps the real work
 * in pthread_once() (src/thread/pthread_tsd.c) rather than a racy
 * plain "already ready?" flag check.
 *
 * What is NOT covered: dlopen()/dlclose() still do not serialize
 * against each other or against a concurrent dlopen()/dlclose() on
 * another thread. Each struct dlobj is its own independent allocation
 * (per "NAMESPACE ISOLATION" above), so two threads racing dlopen()/
 * dlclose() on independent objects do not corrupt each other's -- but
 * the module-id/DTV-growth state (next_tls_module_id, dtv_capacity,
 * the real TCB's own dtv array) is unsynchronized, and pthread_once()
 * cannot fix it (that state legitimately changes on every dlopen(), not
 * just the first). A real fix needs a mutex around load_object()/
 * teardown_obj() as a whole -- deferred, disclosed rather than hidden.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include "libc.h"
#include "plat_dlfcn.h"
#include "unsafe_pointer.h"

static int table_bytes(size_t count, size_t element_size, size_t *out)
{
	if (element_size && count > (size_t)-1 / element_size) return -1;
	*out = count * element_size;
	return 0;
}

/* The real kernel page size -- NOT hardcoded, and deliberately not
 * reused from this tree's existing src/mman/mman.c (`MMAP_PAGE 4096u`)
 * or src/unistd/sysconf.c (`_SC_PAGESIZE`/`getpagesize()`, both
 * hardcoded to 4096 too). Found empirically, not anticipated: this
 * loader's first working version assumed 4096 and got a real,
 * reproducible mmap() EINVAL mapping a genuine .so's second PT_LOAD
 * segment on this exact dev host -- `getconf PAGESIZE` on it reports
 * 16384, not 4096 (aarch64 Linux does not fix the page size at 4K the
 * way x86_64 does; 16K and 64K kernels are real and current, not
 * exotic). ELF segment-mapping correctness depends on matching the
 * kernel's ACTUAL page granularity exactly -- mmap()'s offset argument
 * must be a multiple of the real page size or the call fails outright,
 * so this loader cannot silently inherit the rest of this tree's
 * hardcoded assumption the way a less address-space-sensitive piece of
 * code might get away with. Not fixed in mman.c/sysconf.c themselves:
 * that is a separate, pre-existing bug there; this file simply does not
 * depend on it. The true value is read once from /proc/self/auxv's
 * AT_PAGESZ entry -- the same kind of "ask the kernel directly via
 * /proc" technique self_symtab_load() below already uses for a
 * different fact the rest of this tree has no reliable way to expose
 * yet -- and cached for the process's lifetime (it cannot change). */
static unsigned long cached_page_size;
#define AT_PAGESZ 6

static unsigned long real_page_size(void)
{
	int fd;
	unsigned long pair[2];

	if (cached_page_size) return cached_page_size;

	fd = open("/proc/self/auxv", O_RDONLY);
	if (fd >= 0) {
		while (read(fd, pair, sizeof pair) == (ssize_t)sizeof pair && pair[0] != 0) {
			if (pair[0] == AT_PAGESZ) { cached_page_size = pair[1]; break; }
		}
		(void)close(fd);
	}
	if (!cached_page_size) cached_page_size = 4096; /* conservative last resort */
	return cached_page_size;
}

static unsigned long pgdown(unsigned long v) { unsigned long p = real_page_size(); return v & ~(p - 1); }
static unsigned long pgup(unsigned long v) { unsigned long p = real_page_size(); return (v + p - 1) & ~(p - 1); }

/* ---- raw mmap()/munmap()/mprotect(), NOT the public <sys/mman.h> ones
 *
 * Found empirically, disclosed here rather than silently worked around:
 * this loader's address-space layout is exactly "reserve one big span,
 * then MAP_FIXED several independent file-backed sub-mappings inside
 * it, at exact addresses this file itself computes" -- and ntlibc's own
 * public mmap() front door (src/mman/mman.c) is NOT built to support
 * that pattern. Read in full once this broke: mman.c keeps its own
 * reservation-table bookkeeping, one reservation PER mmap() call, and
 * its own banner is explicit that "MAP_FIXED cannot replace part of a
 * file-backed mapping, only its entire current extent" -- a real,
 * deliberate restriction that makes sense for mman.c's own conforming-
 * partial-munmap() design goal, but is incompatible with a loader that
 * needs to punch several independent, exactly-placed file-backed
 * mappings into ONE anonymous reservation it made itself. Calling the
 * public mmap() for this was not a small mismatch: it silently mapped
 * fresh anonymous zero pages instead of the requested file content for
 * the second such sub-mapping in every case tested, with no error
 * returned -- exactly the kind of unobservable-until-it-matters
 * divergence mman.c's own banner warns partial-munmap() bookkeeping
 * can cause elsewhere, just hit here from a different angle.
 *
 * The fix is the same one crt/linux/crt1.c's own bootstrap TLS mmap()
 * already uses, for the same class of reason (see crt1.c's own
 * raw_syscall() banner: "needed here only for the crt's own one-time
 * internal bootstrap allocation... pulling in the mman subsystem this
 * early is exactly the kind of ordering hazard TLS setup itself already
 * had to avoid"): talk to the kernel directly, the same discipline
 * src/mman/linux/plat_mem.c's own backend already uses one layer down.
 * This is not a workaround bolted onto a bug -- it is the same
 * "portable POSIX front door vs. this file's own internal, lower-level
 * need" split every other src/internal/plat_*.h seam in this tree
 * already draws, just drawn here inside a single translation unit
 * instead of across a header boundary, because a full plat_dlfcn-level
 * mmap seam would be its own separate, larger piece of work for no
 * benefit this file needs today. */
/* One body per arch's own calling convention -- see crt/linux/crt1.c's
 * own raw_syscall() banner for the fuller per-arch rationale.
 * Duplicated here, not shared, per this tree's own "own syscall table
 * per file" discipline every src/.../linux/plat_*.c backend already
 * follows. */
#if defined(__aarch64__)
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
#define SYS_mmap     222
#define SYS_munmap   215
#define SYS_mprotect 226
#elif defined(__x86_64__)
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
#define SYS_mmap     9
#define SYS_munmap   11
#define SYS_mprotect 10
#elif defined(__i386__)
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
/* SYS_munmap/SYS_mprotect are ordinary direct syscalls, same shape as
 * every other arch above -- confirmed against this host's own /nix/store
 * linux-headers asm/unistd_32.h. SYS_mmap is deliberately the OLD,
 * `__NR_mmap`==90 entry (sys_old_mmap), not mmap2 (192): mmap2's own
 * pgoff argument is defined in fixed 4096-byte units regardless of the
 * real page size (Linux mmap2(2) itself documents this), a second,
 * independent unit this loader would have to convert pgdown(ph->p_offset)
 * into on top of real_page_size() above -- old mmap's single argument is
 * instead a pointer to a `{addr,len,prot,flags,fd,offset}` word array
 * with a plain BYTE offset (mm/mmap.c's sys_old_mmap()), the exact same
 * byte-offset contract raw_mmap() already hands every other architecture
 * here, so this arch's own trampoline (immediately below) is the only
 * i386-specific piece needed -- no separate pgoff-unit conversion
 * anywhere else in this file. */
#define SYS_mmap     90
#define SYS_munmap   91
#define SYS_mprotect 125
#else
#error "plat_dlfcn.c: unsupported architecture (expected __aarch64__, __x86_64__ or __i386__)"
#endif

static int is_sys_error(long ret) { return (unsigned long)ret >= (unsigned long)-4095L; }

#if defined(__i386__)
static void *raw_mmap(void *addr, size_t len, int prot, int flags, int fd, long off)
{
	long args[6];
	long ret;
	args[0] = (long)addr; args[1] = (long)len; args[2] = (long)prot;
	args[3] = (long)flags; args[4] = (long)fd; args[5] = off;
	ret = raw_syscall(SYS_mmap, (long)args, 0, 0, 0, 0, 0);
	if (is_sys_error(ret)) { errno = (int)-ret; return MAP_FAILED; }
	return (void *)ret;
}
#else
static void *raw_mmap(void *addr, size_t len, int prot, int flags, int fd, long off)
{
	long ret = raw_syscall(SYS_mmap, (long)addr, (long)len, (long)prot, (long)flags, (long)fd, off);
	if (is_sys_error(ret)) { errno = (int)-ret; return MAP_FAILED; }
	/* mmap(2) returns the mapped address in a signed machine-word
	 * syscall register; converting that ABI word to a pointer is the
	 * operation this function exists to perform. */
	return unsafe_assume_valid_pointer((void *)ret);
}
#endif
static int raw_munmap(void *addr, size_t len)
{
	long ret = raw_syscall(SYS_munmap, (long)addr, (long)len, 0, 0, 0, 0);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}
static int raw_mprotect(void *addr, size_t len, int prot)
{
	long ret = raw_syscall(SYS_mprotect, (long)addr, (long)len, (long)prot, 0, 0, 0);
	if (is_sys_error(ret)) { errno = (int)-ret; return -1; }
	return 0;
}

/* ---- minimal local ELF32/ELF64 shapes ---------------------------------
 *
 * This project ships no <elf.h> yet -- the same gap crt/linux/crt1.c's
 * own local `struct elf64_phdr` already lives with, for the same
 * reason (a real one is separate future work, and nothing outside one
 * file needs more than a fragment of the format today). This file
 * needs a much larger fragment than crt1.c's TLS bootstrap does
 * (section headers, the dynamic section, symbol/relocation tables, not
 * just program headers), so it keeps its own, deliberately NOT shared
 * with crt1.c's: merging them would mean either growing crt1.c's
 * minimal set for this file's sake or reaching into this file from
 * crt1.c's very early, allocator-free bootstrap context, and neither
 * is worth the coupling for what would still only be a handful of
 * struct definitions duplicated once. Field widths/order below are
 * each ELFCLASS's own, architecture-independent within a class (same
 * caveat crt1.c's own comment already states for its Phdr shape) --
 * confirmed field-for-field, including the real on-disk field ORDER
 * (which genuinely differs between the two classes -- see Elf32_Phdr's
 * own comment below), against this host's own /nix/store glibc-dev
 * <elf.h>.
 *
 * i386 is a real ELFCLASS32 target, not just a narrower ELFCLASS64:
 * Elf_Ehdr/Phdr/Shdr/Dyn/Sym below resolve to either width via the
 * Elf_* typedefs just past them, since every FIELD those five carry
 * has a straightforward same-name 32-vs-64-bit counterpart. Relocation
 * entries do not: i386's psABI uses SHT_REL (Elf32_Rel, no r_addend
 * field -- the addend is implicit, packed into the word already sitting
 * at the relocation target) where aarch64/x86_64 use SHT_RELA (Elf64_Rela,
 * an explicit r_addend field) -- a real format difference, not a width
 * difference, so Elf32_Rel/Elf64_Rela are kept as two genuinely separate
 * types with no shared Elf_Rel alias; apply_reloc_table()/apply_irelative_
 * table() below normalize both into one common `struct reloc` before
 * calling into the (fully shared) per-relocation appliers. */
typedef struct {
	unsigned char e_ident[16];
	uint16_t e_type, e_machine;
	uint32_t e_version;
	uint64_t e_entry, e_phoff, e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize, e_phentsize, e_phnum;
	uint16_t e_shentsize, e_shnum, e_shstrndx;
} Elf64_Ehdr;

typedef struct {
	uint32_t p_type, p_flags;
	uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} Elf64_Phdr;

typedef struct {
	uint32_t sh_name, sh_type;
	uint64_t sh_flags, sh_addr, sh_offset, sh_size;
	uint32_t sh_link, sh_info;
	uint64_t sh_addralign, sh_entsize;
} Elf64_Shdr;

typedef struct {
	int64_t d_tag;
	uint64_t d_val;
} Elf64_Dyn;

typedef struct {
	uint32_t st_name;
	unsigned char st_info, st_other;
	uint16_t st_shndx;
	uint64_t st_value, st_size;
} Elf64_Sym;

typedef struct {
	uint64_t r_offset, r_info;
	int64_t r_addend;
} Elf64_Rela;

typedef struct {
	unsigned char e_ident[16];
	uint16_t e_type, e_machine;
	uint32_t e_version;
	uint32_t e_entry, e_phoff, e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize, e_phentsize, e_phnum;
	uint16_t e_shentsize, e_shnum, e_shstrndx;
} Elf32_Ehdr;

/* Elf32_Phdr's own field ORDER genuinely differs from Elf64_Phdr's above
 * (p_flags sits right after p_type on ELFCLASS64, but after p_memsz on
 * ELFCLASS32) -- confirmed against the real header, not assumed; this
 * struct's field order below matches ELFCLASS32's real on-disk layout,
 * which is what makes a plain pread() into it correct. */
typedef struct {
	uint32_t p_type;
	uint32_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align;
} Elf32_Phdr;

typedef struct {
	uint32_t sh_name, sh_type;
	uint32_t sh_flags, sh_addr, sh_offset, sh_size;
	uint32_t sh_link, sh_info;
	uint32_t sh_addralign, sh_entsize;
} Elf32_Shdr;

typedef struct {
	int32_t d_tag;
	uint32_t d_val;
} Elf32_Dyn;

/* Elf32_Sym's field order differs from Elf64_Sym's above too (name,
 * value, size, info, other, shndx -- info/other/shndx move to the END
 * on ELFCLASS32, confirmed against the real header) -- same "order
 * matters for a raw pread()" reasoning as Elf32_Phdr just above. */
typedef struct {
	uint32_t st_name;
	uint32_t st_value, st_size;
	unsigned char st_info, st_other;
	uint16_t st_shndx;
} Elf32_Sym;

/* SHT_REL, not SHT_RELA -- see this section's own banner: i386's addend
 * is implicit (packed into the relocated word itself), so this struct,
 * unlike Elf64_Rela above, carries no r_addend field at all. */
typedef struct {
	uint32_t r_offset, r_info;
} Elf32_Rel;

#if defined(__i386__)
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Dyn  Elf_Dyn;
typedef Elf32_Sym  Elf_Sym;
#else
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Dyn  Elf_Dyn;
typedef Elf64_Sym  Elf_Sym;
#endif

#define EI_CLASS 4
#define EI_DATA  5
#define ELFCLASS32 1
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define EM_386     3
#define EM_X86_64  62
#define EM_AARCH64 183
#define ET_DYN 3

#if defined(__i386__)
#define ELF_CLASS ELFCLASS32
#else
#define ELF_CLASS ELFCLASS64
#endif

#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_TLS     7
/* A GNU/Linux extension segment type (in the OS-specific PT_LOOS..
 * PT_HIOS range, not the base ELF spec), the same class of extension
 * DT_GNU_HASH already is elsewhere in this file -- every glibc- and
 * musl-linked shared object this loader is likely to ever see emits
 * one. See "PT_GNU_RELRO hardening" at this file's own load_object()
 * for what load_object() does with it. */
#define PT_GNU_RELRO 0x6474e552

#define PF_X 1
#define PF_W 2
#define PF_R 4

#define SHT_SYMTAB 2

#define DT_NULL     0
#define DT_NEEDED   1
#define DT_PLTRELSZ 2
#define DT_HASH     4
#define DT_STRTAB   5
#define DT_SYMTAB   6
#define DT_RELA     7
#define DT_RELASZ   8
#define DT_RELAENT  9
#define DT_STRSZ    10
#define DT_SYMENT   11
#define DT_INIT     12
#define DT_REL      17
#define DT_RELSZ    18
#define DT_RELENT   19
#define DT_PLTREL   20
#define DT_JMPREL   23
#define DT_INIT_ARRAY   25
#define DT_INIT_ARRAYSZ 27

/* DT_REL/DT_RELSZ/DT_RELENT (i386, SHT_REL) vs. DT_RELA/DT_RELASZ/
 * DT_RELAENT (aarch64/x86_64, SHT_RELA) name the SAME three dynamic-
 * section facts -- "where is the main relocation table, how big is it,
 * how big is one entry" -- under genuinely different tags because the
 * two ELF classes use genuinely different on-disk relocation formats
 * (see this file's own "minimal local ELF32/ELF64 shapes" banner).
 * DT_PLTREL's own OWN value on a real object is one of these two tag
 * numbers too (it names which format the PLT's relocations use), which
 * is exactly why load_object()'s own DT_PLTREL check below compares
 * against this same macro rather than hardcoding DT_RELA. */
#if defined(__i386__)
#define DT_REL_TAG    DT_REL
#define DT_RELSZ_TAG  DT_RELSZ
#define DT_RELENT_TAG DT_RELENT
#else
#define DT_REL_TAG    DT_RELA
#define DT_RELSZ_TAG  DT_RELASZ
#define DT_RELENT_TAG DT_RELAENT
#endif

#define SHN_UNDEF 0

#define STB_LOCAL(info)  (((info) >> 4) == 0)
#define STV_VISIBILITY(other) ((other) & 0x3)
#define STV_DEFAULT 0
#define STV_PROTECTED 3

#define ELF64_R_SYM(i)  ((uint32_t)((i) >> 32))
#define ELF64_R_TYPE(i) ((uint32_t)((i) & 0xffffffffu))
/* Elf32_Rel's r_info packs sym/type differently from Elf64_Rela's above
 * (8 bits of type, not 32 -- confirmed against the real header): a real
 * format difference this loader's i386 relocation-table walk must use
 * instead of ELF64_R_SYM/TYPE, not a special case of them. */
#define ELF32_R_SYM(i)  ((uint32_t)((i) >> 8))
#define ELF32_R_TYPE(i) ((uint32_t)((i) & 0xffu))

#define R_AARCH64_ABS64      257
#define R_AARCH64_GLOB_DAT   1025
#define R_AARCH64_JUMP_SLOT  1026
#define R_AARCH64_RELATIVE   1027
/* The TLS-descriptor relocation -- confirmed empirically (not assumed)
 * to be the ONLY TLS relocation type this exact toolchain (clang 18,
 * this dev host) can even emit for aarch64 -fPIC shared-object code:
 * `-mtls-dialect=trad` (which would instead select the classic
 * __tls_get_addr()/R_AARCH64_TLS_DTPMOD64+DTPREL64 "general dynamic"
 * pair) is flatly rejected as an "unsupported option" for this target.
 * See this file's own "TLS / per-library thread descriptors" banner
 * and the __ntlibc_tlsdesc_resolver asm block further down for the
 * runtime side of what this relocation type needs. */
#define R_AARCH64_TLSDESC    1031
/* GNU indirect-function ("ifunc") relocation -- confirmed empirically
 * (not assumed) against a real fixture on this exact host/toolchain:
 * `__attribute__((ifunc("resolver"), visibility("hidden")))` compiled
 * with this dev host's own clang for aarch64 -fPIC/-shared emits
 * exactly one R_AARCH64_IRELATIVE entry in .rela.plt, with r_info's
 * symbol index 0 (no symbol at all -- unlike every other relocation
 * type this file handles) and r_addend holding the bias-relative vaddr
 * of the RESOLVER function itself, not of the eventual target. See
 * apply_one_reloc()'s own R_AARCH64_IRELATIVE case for what a loader
 * must do with that shape: CALL the resolver and store its return
 * value, not its address -- musl's dynlink.c (REL_IRELATIVE) takes the
 * identical approach, and it is the only correct one: the whole point
 * of an ifunc is that the real target address is not known until
 * runtime (typically CPU-feature dispatch), so there is no address to
 * simply relocate to the way R_AARCH64_RELATIVE's addend already names
 * one directly. */
#define R_AARCH64_IRELATIVE  1032

/* x86_64 psABI relocation type numbers -- confirmed against the real
 * x86-64 psABI spec, NOT assumed identical to aarch64's despite the
 * same conceptual role each plays (see apply_one_reloc()'s own banner
 * for exactly where these get used): R_X86_64_64 is the ABS64
 * equivalent (a full 64-bit symbol+addend store, the same job
 * R_AARCH64_ABS64 does), R_X86_64_GLOB_DAT/JUMP_SLOT resolve a GOT/PLT
 * slot to a symbol's address with no addend, and R_X86_64_RELATIVE is
 * a load-bias-only fixup needing no symbol at all -- same four
 * semantic roles as the aarch64 set above, different numeric values. */
#define R_X86_64_64          1
#define R_X86_64_GLOB_DAT    6
#define R_X86_64_JUMP_SLOT   7
#define R_X86_64_RELATIVE    8
/* R_AARCH64_IRELATIVE's own x86_64 counterpart -- same ifunc-dispatch
 * role, same "addend is the resolver's own vaddr, call it and store
 * the RETURN value" contract (see that constant's own comment for the
 * full derivation, confirmed empirically via a real aarch64 fixture on
 * this dev host). Value taken from the x86-64 psABI spec directly, the
 * same way this file's other R_X86_64_* values above were (this dev
 * host's own toolchain has no x86_64 target to cross-check a fixture
 * against -- see this file's own TLS banner for the identical caveat
 * already disclosed there for a different feature). */
#define R_X86_64_IRELATIVE   37

/* i386 psABI relocation type numbers -- confirmed against this host's
 * own /nix/store glibc-dev <elf.h>, not assumed. Same four semantic
 * roles as the aarch64/x86_64 sets above (R_386_32 is the ABS-equivalent
 * addend-adding store, R_386_GLOB_DAT/JUMP_SLOT are addend-less GOT/PLT
 * fixups, R_386_RELATIVE is a load-bias-only fixup) plus R_386_IRELATIVE,
 * the identical ifunc-dispatch relocation the aarch64/x86_64 comments
 * above already derive in full -- except that on i386 the addend for
 * EVERY one of these is never a struct field (see this file's own
 * "minimal local ELF32/ELF64 shapes" banner: i386 uses SHT_REL, not
 * SHT_RELA) -- it is always read out of the relocated word itself by
 * apply_reloc_table()'s own i386 branch before apply_one_reloc() ever
 * sees it. */
#define R_386_32          1
#define R_386_GLOB_DAT    6
#define R_386_JMP_SLOT    7
#define R_386_RELATIVE    8
#define R_386_IRELATIVE   42

/* ---- sticky error state, single instance for this whole backend ----- */
static char err_buf[256];
static unsigned long err_seq;

static void seterr(const char *fmt, ...)
{
	static const char fallback[] = "dynamic loader error";
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = vsnprintf(err_buf, sizeof err_buf, fmt, ap);
	va_end(ap);
	if (rc < 0) memcpy(err_buf, fallback, sizeof fallback);
	err_seq++;
}

const char *__plat_dlerror(void) { return err_seq ? err_buf : NULL; }
unsigned long __plat_dlerror_seq(void) { return err_seq; }

/* ---- dlopen(NULL, ...)'s distinguished handle ------------------------
 *
 * Any address unique to this file and never returned by mmap() works;
 * the address of a static object this translation unit alone owns is
 * the simplest such value, the same trick MAIN_IMAGE_HANDLE's NT-side
 * sibling (src/dlfcn/nt/plat_dlfcn.c) plays with __peb->ImageBaseAddress
 * -- just with no PEB to reuse here, so a dedicated sentinel object
 * instead. */
static const char main_handle_token;
#define MAIN_IMAGE_HANDLE ((void *)&main_handle_token)

/* ---- resolving a name against THIS running binary's own symbol table
 *
 * See this file's "SYMBOL RESOLUTION AGAINST THE STATIC BINARY" banner
 * above for why /proc/self/exe, not a generated table. Lazily loaded
 * once per process and kept resident for its lifetime (never freed --
 * a real loader's own symbol tables are resident for the same reason:
 * they may be needed again at any future dlopen()/dlsym() call). The
 * lazy init itself is genuinely once-only: self_symtab_load() below
 * wraps the real work (self_symtab_load_once()) in a real pthread_once()
 * (src/thread/pthread_tsd.c) rather than a plain, racy `if
 * (self_symtab_ready) return; ... self_symtab_ready = 1;` -- see the
 * "THREAD SAFETY" banner above for why pthread_once() specifically, not
 * a hand-rolled mutex. */
static int self_symtab_ready;      /* 0 = not attempted, 1 = ready, -1 = failed permanently */
static Elf_Sym *self_syms;
static char *self_strs;
static size_t self_nsyms;
static pthread_once_t self_symtab_once = PTHREAD_ONCE_INIT;

/* The pthread_once()-wrapped initializer itself: no early-return guard
 * needed here (pthread_once() itself is exactly that guard, and
 * guarantees this body runs to completion exactly once, with every
 * concurrent caller blocked until it does -- see pthread_once()'s own
 * contract), and no return value: self_symtab_load() below reads
 * self_symtab_ready back out after pthread_once() returns instead. */
static void self_symtab_load_once(void)
{
	int fd = -1;
	Elf_Ehdr eh;
	Elf_Shdr *shdrs = NULL;
	size_t shdr_bytes;
	size_t i;
	int symtab_idx = -1;

	fd = open("/proc/self/exe", O_RDONLY);
	if (fd < 0) {
		seterr("dlopen: cannot open /proc/self/exe to resolve symbols against the running binary: %s", strerror(errno));
		goto fail;
	}
	if (pread(fd, &eh, sizeof eh, 0) != (ssize_t)sizeof eh ||
	    eh.e_ident[EI_CLASS] != ELF_CLASS || eh.e_ident[EI_DATA] != ELFDATA2LSB ||
	    eh.e_shoff == 0 || eh.e_shnum == 0 || eh.e_shentsize != sizeof(Elf_Shdr)) {
		seterr("dlopen: /proc/self/exe has no usable ELF section header table");
		goto fail;
	}

	if (table_bytes((size_t)eh.e_shnum, sizeof *shdrs, &shdr_bytes) < 0) {
		seterr("dlopen: own section header table is too large"); goto fail;
	}
	shdrs = malloc(shdr_bytes);
	if (!shdrs) { seterr("dlopen: out of memory reading own section headers"); goto fail; }
	if (pread(fd, shdrs, shdr_bytes, (off_t)eh.e_shoff) != (ssize_t)shdr_bytes) {
		seterr("dlopen: short read on own section header table");
		goto fail;
	}

	for (i = 0; i < eh.e_shnum; i++) {
		if (shdrs[i].sh_type == SHT_SYMTAB) { symtab_idx = (int)i; break; }
	}
	if (symtab_idx < 0) {
		/* A stripped binary has no .symtab left -- see this file's own
		 * banner on why that is this design's one real, disclosed cost. */
		seterr("dlopen: running binary has no .symtab (stripped?) -- cannot resolve symbols against it");
		goto fail;
	}

	{
		Elf_Shdr *symtab_sh = &shdrs[symtab_idx];
		Elf_Shdr *strtab_sh = &shdrs[symtab_sh->sh_link];
		size_t nsyms = symtab_sh->sh_size / sizeof(Elf_Sym);
		Elf_Sym *syms = malloc(symtab_sh->sh_size);
		char *strs = malloc(strtab_sh->sh_size);

		if (!syms || !strs) {
			free(syms); free(strs);
			seterr("dlopen: out of memory reading own symbol/string table");
			goto fail;
		}
		if (pread(fd, syms, symtab_sh->sh_size, (off_t)symtab_sh->sh_offset) != (ssize_t)symtab_sh->sh_size ||
		    pread(fd, strs, strtab_sh->sh_size, (off_t)strtab_sh->sh_offset) != (ssize_t)strtab_sh->sh_size) {
			free(syms); free(strs);
			seterr("dlopen: short read on own symbol/string table");
			goto fail;
		}
		self_syms = syms;
		self_strs = strs;
		self_nsyms = nsyms;
	}

	free(shdrs);
	(void)close(fd);
	self_symtab_ready = 1;
	return;

fail:
	free(shdrs);
	if (fd >= 0) (void)close(fd);
	self_symtab_ready = -1;
}

static int self_symtab_load(void)
{
	pthread_once(&self_symtab_once, self_symtab_load_once);
	return self_symtab_ready == 1 ? 0 : -1;
}

/* Resolve `name` against the running binary's own symbol table.
 * Returns the address, or NULL if genuinely not found/unreadable --
 * does not itself set the sticky error on a plain "not found" (only
 * self_symtab_load()'s own I/O failures do), since the two call sites
 * below (dlsym(MAIN_IMAGE_HANDLE, ...) and a dlopen()'d object's own
 * undefined-symbol resolution) want different wording for that case. */
static void *resolve_main_symbol(const char *name)
{
	size_t i;
	if (self_symtab_load() != 0) return NULL;
	for (i = 0; i < self_nsyms; i++) {
		Elf_Sym *s = &self_syms[i];
		if (s->st_shndx == SHN_UNDEF) continue;
		if (s->st_name == 0) continue;
		/* st_value is an ELF symbol table entry's own numeric field, an
		 * already-absolute virtual address for a non-PIE main image --
		 * ELF defines symbol values as integer addresses, and
		 * reconstructing a pointer from one is this loader's own
		 * required ABI operation, not something derivable from a
		 * pointer anywhere in this translation unit. */
		if (strcmp(self_strs + s->st_name, name) == 0)
			return unsafe_assume_valid_pointer((void *)(uintptr_t)s->st_value); /* non-PIE: already absolute */
	}
	return NULL;
}

/* ---- a loaded object -------------------------------------------------
 *
 * See "NAMESPACE ISOLATION" above: one of these is created fresh by
 * every __plat_dlopen() call (and, now, by every DT_NEEDED dependency
 * load_object() chases on its behalf -- see load_object() below), never
 * shared or deduplicated. */
struct dlobj {
	void *map_base;   /* the whole reservation, for munmap() */
	size_t map_len;
	unsigned long bias; /* ADDR(v) == bias + v, see __plat_dlopen() */
	Elf_Sym *dynsym;
	char *dynstr;
	size_t dynsym_count;
	/* DT_NEEDED dependencies this object loaded, in DT_NEEDED order --
	 * this object's own array (realloc()'d by add_dep()), owned by it,
	 * torn down with it (see teardown_obj() below). Never deduplicated
	 * against anything, per this file's own "NAMESPACE ISOLATION"
	 * banner -- including against each other in a diamond-shaped
	 * dependency graph within this SAME load, a real, disclosed cost
	 * traded for never having to ask "has this exact file already been
	 * loaded, by whom, and can I actually reuse it safely". */
	struct dlobj **deps;
	size_t ndeps;
	/* Per-object TLS bookkeeping -- see this file's "TLS / per-library
	 * thread descriptors" banner. 0/NULL when this object has no
	 * PT_TLS segment (every non-aarch64 build, and any aarch64 object
	 * that simply has no __thread data at all). Present unconditionally
	 * (not #ifdef'd out on x86_64) purely so the rest of this file
	 * never needs an arch-guard just to read a field that is always
	 * zero-valued there -- negligible size cost, real readability win. */
	unsigned int tls_module_id;
	void *tls_block;
};

#define ADDR(obj, v) ((void *)((obj)->bias + (uint64_t)(v)))

static Elf_Dyn *find_dyn_ptr(Elf_Dyn *dyn, int64_t tag)
{
	for (; dyn->d_tag != DT_NULL; dyn++)
		if (dyn->d_tag == tag) return dyn;
	return NULL;
}

/* Does `obj` itself EXPORT `name`? The same test dlsym() applies to a
 * handle a caller passed in directly (see __plat_dlsym() below) --
 * factored out here so resolve_via_deps() below can apply the identical
 * STB_LOCAL/visibility filtering to a DEPENDENCY's own exports without a
 * second copy of those rules. Index 0 of .dynsym is always the reserved
 * all-zero null symbol (ELF spec) -- skipped, same as apply_reloc_
 * table()'s own `symidx == 0` rejection. Only STB_GLOBAL/STB_WEAK,
 * default/protected-visibility, defined symbols count as "exported":
 * present in .dynsym for this object's OWN relocations (resolve_symref()
 * below) to use is not the same thing as visible to an outside caller
 * (or a dependent object) through dlsym()/symbol resolution. */
static void *resolve_export(struct dlobj *obj, const char *name)
{
	size_t i;
	for (i = 1; i < obj->dynsym_count; i++) {
		Elf_Sym *s = &obj->dynsym[i];
		if (s->st_shndx == SHN_UNDEF) continue;
		if (STB_LOCAL(s->st_info)) continue;
		if (STV_VISIBILITY(s->st_other) != STV_DEFAULT &&
		    STV_VISIBILITY(s->st_other) != STV_PROTECTED) continue;
		/* ADDR() reconstructs a pointer from this object's real mapped
		 * load bias plus an ELF-symbol-value virtual address -- see
		 * apply_one_irelative() below for the full ADDR() reasoning,
		 * shared by every call site in this file. */
		if (strcmp(obj->dynstr + s->st_name, name) == 0)
			return unsafe_assume_valid_pointer(ADDR(obj, s->st_value));
	}
	return NULL;
}

/* Search `obj`'s own loaded DT_NEEDED dependency tree for `name` --
 * direct dependencies' own exports first, then their dependencies' (a
 * plain two-tier breadth order, not a strict flattened "global symbol
 * scope" a real ld.so's own default-namespace resolution builds --
 * sufficient for the dependency chains this file's own test fixtures
 * exercise, and disclosed as a real scope line rather than silently
 * assumed complete: a symbol satisfiable only through a GRANDCHILD
 * dependency while a nearer object also defines a same-named but
 * unrelated symbol could resolve differently than a real ld.so would).
 * depth is a plain recursion-depth cap, not a cycle detector -- no real
 * toolchain's own linker output comes remotely close to it; it exists
 * only so a hand-crafted or malformed circular DT_NEEDED chain fails
 * loudly (falls through to resolve_main_symbol()'s own "not found") in
 * stead of exhausting the stack. */
static void *resolve_via_deps(struct dlobj *obj, const char *name, int depth)
{
	size_t i;
	void *addr;
	if (depth > 32) return NULL;
	for (i = 0; i < obj->ndeps; i++) {
		addr = resolve_export(obj->deps[i], name);
		if (addr) return addr;
	}
	for (i = 0; i < obj->ndeps; i++) {
		addr = resolve_via_deps(obj->deps[i], name, depth + 1);
		if (addr) return addr;
	}
	return NULL;
}

/* Resolve one relocation's symbol reference, whether it is satisfied
 * by the SAME object's own definition (common: a .so taking its own
 * function's address through the GOT), by one of this object's own
 * DT_NEEDED dependencies (resolve_via_deps() above -- checked before
 * the static binary: a dlopen()'d object that depends on a second .so
 * expects ITS symbols to take precedence over any same-named symbol the
 * main program happens to also define, the same precedence a real
 * ld.so's own per-object dependency scope gives), or has to fall
 * through to the static binary (see resolve_main_symbol() above).
 * Returns 1 with *out filled on success, 0 on an unresolvable undefined
 * symbol (caller sets the sticky error with the symbol name for
 * context). */
static int resolve_symref(struct dlobj *obj, uint32_t symidx, uint64_t *out)
{
	Elf_Sym *sym;
	const char *name;
	void *addr;
	if (symidx == 0 || symidx >= obj->dynsym_count) return 0;
	sym = &obj->dynsym[symidx];
	if (sym->st_shndx != SHN_UNDEF) {
		*out = obj->bias + sym->st_value;
		return 1;
	}
	name = obj->dynstr + sym->st_name;
	addr = resolve_via_deps(obj, name, 0);
	if (!addr) addr = resolve_main_symbol(name);
	if (!addr) return 0;
	*out = (uint64_t)(uintptr_t)addr;
	return 1;
}

/* ---- TLS / per-library thread descriptors (aarch64 only) -------------
 *
 * See this file's own top "TLS / PER-LIBRARY THREAD DESCRIPTORS" banner
 * for the full design this section implements: INDEX, NEVER SWAP. The
 * real, TPIDR_EL0-addressed TCB (crt/linux/crt1.c's linux_setup_tls())
 * has a real DTV: dtv[0] is unused/reserved, dtv[1] is the main image's
 * own TLS block (crt1.c sets this up itself), and dtv[N] for N >= 2 is
 * this file's own doing: a small integer "TLS module id", allocated
 * below by setup_object_tls() to any dlopen()'d object with a PT_TLS
 * segment, pointing at a SECOND, independently malloc()'d block shaped
 * exactly like the real TCB itself (a 16-byte {dtv;reserved} header
 * immediately followed by that module's own TLS data) -- "own TD per
 * library", literally, even though TPIDR_EL0 itself is never repointed. */
#if defined(__aarch64__)
#define TLS_TCB_HEADER_SIZE 16 /* dtv + reserved, fixed by the AAELF64 ABI --
                                 * matches crt1.c's own aarch64 tcb_size
                                 * exactly; see this file's TLS banner. */

/* module id 0 is invalid (struct dlobj's own tls_module_id field uses 0
 * to mean "no PT_TLS"), module id 1 is the main image (crt1.c's own
 * dtv[1] = tp) -- the first id this loader ever hands out is 2. Never
 * reused across dlclose(): see setup_object_tls()'s own comment. */
static unsigned int next_tls_module_id = 2;

/* Must equal src/internal/linux/tls_setup.c's own
 * __ntlibc_linux_tls_block_create() initial DTV allocation size (the
 * real block builder crt/linux/crt1.c's linux_setup_tls() calls for the
 * initial thread, and src/thread/linux/plat_thread.c's
 * __plat_thread_spawn() calls for every later pthread_create()'d one)
 * -- a numeric contract duplicated across the two files rather than
 * shared through a header, the same discipline this tree already
 * applies to e.g. raw syscall numbers duplicated per translation unit
 * (see this file's own raw_syscall() banner). Tracked here (not re-read
 * from tls_setup.c, which has no way to report it back) purely so
 * tls_dtv_ensure_capacity() below knows when it must grow the array
 * rather than just index into it. */
#define TLS_DTV_INITIAL_CAPACITY 8
static size_t dtv_capacity = TLS_DTV_INITIAL_CAPACITY;

/* Grow the real TCB's own DTV array (malloc()+copy+repoint tp[0]) so
 * that dtv[module_id] is a valid slot to write into. Safe to call this
 * late (unlike crt1.c's own bootstrap allocation): malloc() is always
 * available by the time any dlopen() can run at all. */
static int tls_dtv_ensure_capacity(unsigned int module_id)
{
	void **tp = (void **)__builtin_thread_pointer();
	void **old_dtv = *(void ***)tp;
	void **new_dtv;
	size_t new_capacity, new_bytes;

	if ((size_t)module_id < dtv_capacity) return 0;
	if (!__array_next_capacity(dtv_capacity, (size_t)module_id, 1,
	    TLS_DTV_INITIAL_CAPACITY, sizeof(void *), &new_capacity)) return -1;

	new_bytes = new_capacity * sizeof(void *); /* proven <= SIZE_MAX by __array_next_capacity's own element_size bound above */
	new_dtv = malloc(new_bytes);
	if (!new_dtv) return -1;
	memcpy(new_dtv, old_dtv, dtv_capacity * sizeof(void *));
	memset(new_dtv + dtv_capacity, 0, (new_capacity - dtv_capacity) * sizeof(void *));

	/* Repoint tp[0] at the bigger array. old_dtv is intentionally never
	 * freed -- see this file's own "THREAD SAFETY" banner: dlopen()/
	 * dlclose() still take no lock against each other (only self_
	 * symtab_load()'s own race is fixed, via pthread_once() above), so a
	 * hypothetically concurrent reader could still be mid-read of the
	 * old array when this runs; freeing it out from under that read
	 * would turn a disclosed non-issue (a redundant read of consistent,
	 * unfreed data) into a real use-after-free. Same tradeoff self_
	 * symtab_load()'s own tables already make: resident for the
	 * process's lifetime. */
	*(void ***)tp = new_dtv;
	dtv_capacity = new_capacity;
	return 0;
}

/* The AArch64 TLS-descriptor runtime resolver. See this file's own
 * "TLS / per-library thread descriptors" banner and the R_AARCH64_
 * TLSDESC comment above for the full derivation; summarized here at the
 * point it is actually defined:
 *
 * A `__thread` access in dlopen()'d PIC code compiles to (confirmed by
 * disassembling this file's own test fixture on this exact host/clang):
 *
 *     adrp x0, :tlsdesc:sym              // x0 = page(&entry)
 *     ldr  x1, [x0, :tlsdesc_lo12:sym]   // x1 = entry.resolver
 *     add  x0, x0, :tlsdesc_lo12:sym     // x0 = &entry
 *     blr  x1                            // x0 = resolver(&entry) = tp-relative offset
 *     mrs  x2, tpidr_el0
 *     add  x0, x2, x0                    // x0 = absolute address
 *
 * `entry` is a two-word GOT slot: {resolver function pointer, opaque
 * argument}. This loader always binds eagerly (RTLD_NOW/LAZY are moot
 * here -- see this file's own top banner), so apply_one_reloc() below
 * writes a FINAL, fully-resolved entry at dlopen() time: word 0 always
 * points at this one function, and word 1 packs (module_id, offset)
 * into a single 8-byte argument -- module_id in the top 16 bits, offset
 * in the low 48 (real TLS blocks and real per-process module counts are
 * nowhere near either limit).
 *
 * The AAELF64 TLS-descriptor calling convention requires this function
 * to preserve every register except x0 (flags are not touched either,
 * though the convention does not require it -- every mnemonic below is
 * a plain, non-flag-setting form). x1-x4 are used as scratch and
 * explicitly saved/restored via the stack, rather than relying on the
 * x16/x17 pair AAPCS64 always permits a callee to clobber -- correctness
 * and readability over shaving two spilled registers in a function
 * called at most once per TLS access. On entry x0 = &entry (entry's
 * OWN address, i.e. the resolver-pointer word's address, per the
 * disassembly above -- not the argument word's address). On return
 * x0 = (accessed address) - tpidr_el0 (the caller's own `add x0, x2,
 * x0` adds tpidr_el0 back). */
extern void __ntlibc_tlsdesc_resolver(void);
__asm__(
"	.text\n"
"	.align	2\n"
"	.global	__ntlibc_tlsdesc_resolver\n"
"	.hidden	__ntlibc_tlsdesc_resolver\n"
"	.type	__ntlibc_tlsdesc_resolver, %function\n"
"__ntlibc_tlsdesc_resolver:\n"
"	stp	x1, x2, [sp, #-32]!\n"
"	stp	x3, x4, [sp, #16]\n"
"	ldr	x1, [x0, #8]\n"
"	lsr	x2, x1, #48\n"
"	and	x1, x1, #0xffffffffffff\n"
"	mrs	x3, tpidr_el0\n"
"	ldr	x4, [x3]\n"
"	ldr	x4, [x4, x2, lsl #3]\n"
"	add	x4, x4, x1\n"
"	add	x4, x4, #16\n"
"	sub	x0, x4, x3\n"
"	ldp	x3, x4, [sp, #16]\n"
"	ldp	x1, x2, [sp], #32\n"
"	ret\n"
"	.size	__ntlibc_tlsdesc_resolver, . - __ntlibc_tlsdesc_resolver\n"
);

/* Build this object's own per-module TLS block (this object's own
 * miniature TCB: a 16-byte {dtv;reserved} header identical in shape to
 * crt1.c's real one, immediately followed by a copy of PT_TLS's own
 * data), allocate it a module id, and register it in the real TCB's
 * DTV. Called from load_object() below once every PT_LOAD segment is
 * mapped (this needs to read PT_TLS's own initial data out of that
 * mapping) and before any relocation is applied (R_AARCH64_TLSDESC
 * relocations need obj->tls_module_id already assigned). Returns 0 on
 * success, -1 on failure (caller sets the sticky error). */
static int setup_object_tls(struct dlobj *obj, const Elf_Phdr *pt_tls)
{
	unsigned long data_align = pt_tls->p_align > 16 ? pt_tls->p_align : 16;
	unsigned long alloc_size = TLS_TCB_HEADER_SIZE + pt_tls->p_memsz + data_align;
	unsigned char *block, *data, *modtcb;
	void **tp, **dtv;
	unsigned int id;

	block = malloc(alloc_size);
	if (!block) return -1;

	data = block + TLS_TCB_HEADER_SIZE;
	data = (unsigned char *)(((uintptr_t)data + data_align - 1) & ~(uintptr_t)(data_align - 1));

	/* ADDR() reconstruction -- see apply_one_irelative() below. */
	memcpy(data, unsafe_assume_valid_pointer(ADDR(obj, pt_tls->p_vaddr)), pt_tls->p_filesz);
	memset(data + pt_tls->p_filesz, 0, pt_tls->p_memsz - pt_tls->p_filesz);

	modtcb = data - TLS_TCB_HEADER_SIZE; /* always >= block: data was rounded UP
	                                       * from block+16, so the slack this
	                                       * rounding consumed is exactly what
	                                       * keeps this subtraction in bounds --
	                                       * the same recipe crt1.c's own
	                                       * linux_setup_tls() uses. */
	((void **)modtcb)[0] = 0; /* this module's own dtv slot -- unused, exactly
	                           * like crt1.c's main-image TCB */
	((void **)modtcb)[1] = 0; /* reserved */

	/* Never reused: this loader never dedups (see "NAMESPACE ISOLATION"
	 * above) and gives every TLS-bearing object its own module id for
	 * the life of the process, even across a dlclose()+re-dlopen() of
	 * the byte-identical file -- reusing an id would risk a stale DTV
	 * read racing a fresh assignment with no synchronization to order
	 * them (see this file's own "THREAD SAFETY" banner: dlopen()/
	 * dlclose() are still not mutually serialized). Monotonic and
	 * simple beats reused-and-hazardous. */
	id = next_tls_module_id++;
	if (tls_dtv_ensure_capacity(id) != 0) { free(block); return -1; }

	tp = (void **)__builtin_thread_pointer();
	dtv = *(void ***)tp;
	dtv[id] = modtcb;

	obj->tls_module_id = id;
	obj->tls_block = modtcb;
	return 0;
}
#endif /* __aarch64__ */

/* A normalized relocation record: what apply_one_reloc()/apply_one_
 * irelative() below actually need, decoupled from which of the two
 * genuinely different on-disk relocation shapes it came from --
 * Elf64_Rela (r_addend an explicit struct field, aarch64/x86_64) or
 * Elf32_Rel (no r_addend field at all -- i386's addend is implicit,
 * packed into the word already sitting at the relocation target; see
 * this file's own "minimal local ELF32/ELF64 shapes" banner). apply_
 * reloc_table()/apply_irelative_table() below are what build one of
 * these per entry -- extracting r_addend explicitly for RELA, or
 * reading it out of *loc for REL -- so this pair of functions can stay
 * completely arch/format-agnostic about that split. */
struct reloc {
	uint64_t r_offset;
	uint32_t r_sym;
	uint32_t r_type;
	int64_t r_addend;
};

static int apply_one_reloc(struct dlobj *obj, const struct reloc *r,
                            unsigned long lo, unsigned long hi)
{
	unsigned long *loc;

	if (r->r_offset < lo || r->r_offset >= hi) {
		seterr("dlopen: relocation offset 0x%llx outside mapped object",
		       (unsigned long long)r->r_offset);
		return -1;
	}
	/* ADDR() reconstruction -- see apply_one_irelative() below. Bounds
	 * of r->r_offset are already proven inside [lo, hi) above. */
	loc = unsafe_assume_valid_pointer(ADDR(obj, r->r_offset));

	switch (r->r_type) {
#if defined(__aarch64__)
	case R_AARCH64_RELATIVE:
		*loc = obj->bias + (unsigned long)r->r_addend;
		return 0;
	case R_AARCH64_ABS64:
	case R_AARCH64_GLOB_DAT:
	case R_AARCH64_JUMP_SLOT: {
		uint64_t sym_addr;
		if (!resolve_symref(obj, r->r_sym, &sym_addr)) {
			const char *name = (r->r_sym && r->r_sym < obj->dynsym_count) ?
				obj->dynstr + obj->dynsym[r->r_sym].st_name : "?";
			seterr("dlopen: undefined symbol: %s", name);
			return -1;
		}
		*loc = (unsigned long)sym_addr + (r->r_type == R_AARCH64_ABS64 ? (unsigned long)r->r_addend : 0);
		return 0;
	}
	case R_AARCH64_TLSDESC: {
		/* See "TLS / per-library thread descriptors" (__ntlibc_tlsdesc_
		 * resolver's own banner, above) for the two-word GOT-entry
		 * shape and the (module_id, offset) packing this writes. */
		uint64_t module_id, offset;

		if (r->r_sym == 0) {
			/* No symbol: the addend directly gives the offset within
			 * THIS object's own PT_TLS segment -- the shape a `static
			 * __thread` variable accessed from within the same .so
			 * compiles to (confirmed empirically against this file's
			 * own test fixture). */
			if (!obj->tls_module_id) {
				seterr("dlopen: internal error: R_AARCH64_TLSDESC on an object with no PT_TLS module");
				return -1;
			}
			module_id = (uint64_t)obj->tls_module_id;
			offset = (uint64_t)r->r_addend;
		} else {
			Elf_Sym *sym;
			if (r->r_sym >= obj->dynsym_count) {
				seterr("dlopen: TLSDESC relocation references an out-of-range symbol index");
				return -1;
			}
			sym = &obj->dynsym[r->r_sym];
			if (sym->st_shndx == SHN_UNDEF) {
				/* A TLS symbol DEFINED in another object (a dependency,
				 * or the main image) -- cross-object TLS symbol
				 * resolution is not implemented (see this file's own
				 * TLS banner): loud, clean failure, not a silent
				 * mis-relocation. */
				seterr("dlopen: undefined TLS symbol: %s (TLS symbols defined in ANOTHER object are not yet resolved -- see plat_dlfcn.c's own TLS banner)",
				       obj->dynstr + sym->st_name);
				return -1;
			}
			if (!obj->tls_module_id) {
				seterr("dlopen: internal error: R_AARCH64_TLSDESC on an object with no PT_TLS module");
				return -1;
			}
			/* A defined STT_TLS symbol's st_value is already an offset
			 * within its own PT_TLS segment, per the ELF spec -- not a
			 * segment-relative vaddr the way an ordinary symbol's
			 * st_value is elsewhere in this file. */
			module_id = (uint64_t)obj->tls_module_id;
			offset = sym->st_value + (uint64_t)r->r_addend;
		}
		loc[0] = (unsigned long)(uintptr_t)(void *)&__ntlibc_tlsdesc_resolver;
		loc[1] = (unsigned long)((module_id << 48) | (offset & 0xffffffffffffULL));
		return 0;
	}
	case R_AARCH64_IRELATIVE:
		/* Deliberately NOT resolved here -- see apply_one_irelative()/
		 * apply_irelative_table() further down (and load_object()'s own
		 * "IRELATIVE resolution" pass, between protection-narrowing and
		 * PT_GNU_RELRO hardening) for why: this type's whole job (see
		 * its own #define comment) is to CALL a resolver function, and
		 * at the point apply_reloc_table() runs this object's own
		 * PT_LOAD segments are still mapped PROT_READ|PROT_WRITE only
		 * (see load_object()'s own comment on that first mapping pass)
		 * -- NOT yet PROT_EXEC, which only the later protection-
		 * narrowing pass restores. Confirmed empirically, not just
		 * reasoned: calling the resolver at this point genuinely
		 * SIGSEGVs (non-executable .text), caught by this file's own
		 * dlfix_ifunc.so test fixture. Returning 0 here (not an error)
		 * leaves the relocated slot untouched for now; apply_irelative_
		 * table() revisits this exact same table later and does the
		 * real work once .text is executable. */
		return 0;
#elif defined(__x86_64__)
	case R_X86_64_RELATIVE:
		*loc = obj->bias + (unsigned long)r->r_addend;
		return 0;
	case R_X86_64_64:
	case R_X86_64_GLOB_DAT:
	case R_X86_64_JUMP_SLOT: {
		uint64_t sym_addr;
		if (!resolve_symref(obj, r->r_sym, &sym_addr)) {
			const char *name = (r->r_sym && r->r_sym < obj->dynsym_count) ?
				obj->dynstr + obj->dynsym[r->r_sym].st_name : "?";
			seterr("dlopen: undefined symbol: %s", name);
			return -1;
		}
		/* Unlike aarch64's ABS64 vs. GLOB_DAT/JUMP_SLOT split above,
		 * x86_64's own psABI defines R_X86_64_GLOB_DAT/JUMP_SLOT as
		 * addend-less by CONVENTION (the addend field is simply always
		 * 0 for these two in practice), not by a rule this loader must
		 * itself enforce -- adding r_addend unconditionally here is
		 * therefore correct for all three types, not just R_X86_64_64,
		 * since it is 0 for the other two anyway on any real linker's
		 * output. */
		*loc = (unsigned long)sym_addr + (unsigned long)r->r_addend;
		return 0;
	}
	case R_X86_64_IRELATIVE:
		/* R_AARCH64_IRELATIVE's own x86_64 counterpart -- deferred for
		 * the identical reason (see that case's own comment just
		 * above, and apply_one_irelative()/apply_irelative_table()
		 * further down for where this actually gets applied). */
		return 0;
#elif defined(__i386__)
	case R_386_RELATIVE:
		*loc = obj->bias + (unsigned long)r->r_addend;
		return 0;
	case R_386_32:
	case R_386_GLOB_DAT:
	case R_386_JMP_SLOT: {
		uint64_t sym_addr;
		if (!resolve_symref(obj, r->r_sym, &sym_addr)) {
			const char *name = (r->r_sym && r->r_sym < obj->dynsym_count) ?
				obj->dynstr + obj->dynsym[r->r_sym].st_name : "?";
			seterr("dlopen: undefined symbol: %s", name);
			return -1;
		}
		/* Same ABS-vs-addend-less split as aarch64's ABS64 vs. GLOB_DAT/
		 * JUMP_SLOT above, not x86_64's "always add it, it's 0 anyway"
		 * convention: the i386 psABI defines R_386_GLOB_DAT/JMP_SLOT's
		 * own computation as plain "S" (the symbol's value, full stop),
		 * with no addend term at all -- only R_386_32 is "S + A". */
		*loc = (unsigned long)sym_addr + (r->r_type == R_386_32 ? (unsigned long)r->r_addend : 0);
		return 0;
	}
	case R_386_IRELATIVE:
		/* R_AARCH64_IRELATIVE's own i386 counterpart -- deferred for the
		 * identical reason (see that case's own comment above). */
		return 0;
#endif
	default:
		/* Includes every TLS relocation type -- see this file's own
		 * "TLS / per-library thread descriptors" banner: refusing a
		 * type we cannot correctly apply is the whole point of this
		 * being a `default:` fail rather than an ignored case. */
		seterr("dlopen: unsupported relocation type %u (offset 0x%llx) -- not yet implemented",
		       r->r_type, (unsigned long long)r->r_offset);
		return -1;
	}
}

static int apply_reloc_table(struct dlobj *obj, uint64_t tbl_vaddr, uint64_t tbl_size, // NOLINT(bugprone-easily-swappable-parameters) -- table address and size have distinct relocation roles
                              unsigned long lo, unsigned long hi)
{
#if defined(__i386__)
	Elf32_Rel *rels;
	size_t count, i;
	if (!tbl_vaddr || !tbl_size) return 0;
	rels = ADDR(obj, tbl_vaddr);
	count = tbl_size / sizeof(Elf32_Rel);
	for (i = 0; i < count; i++) {
		struct reloc rec;
		int32_t *loc;
		if (rels[i].r_offset < lo || rels[i].r_offset >= hi) {
			seterr("dlopen: relocation offset 0x%llx outside mapped object",
			       (unsigned long long)rels[i].r_offset);
			return -1;
		}
		loc = ADDR(obj, rels[i].r_offset);
		rec.r_offset = rels[i].r_offset;
		rec.r_sym = ELF32_R_SYM(rels[i].r_info);
		rec.r_type = ELF32_R_TYPE(rels[i].r_info);
		/* SHT_REL: the addend is implicit, already sitting in the word
		 * at the relocation target -- read BEFORE apply_one_reloc()
		 * below overwrites *loc with the relocated value (see this
		 * file's own "minimal local ELF32/ELF64 shapes" banner). */
		rec.r_addend = *loc;
		if (apply_one_reloc(obj, &rec, lo, hi) != 0) return -1;
	}
	return 0;
#else
	Elf64_Rela *relas;
	size_t count, i;
	if (!tbl_vaddr || !tbl_size) return 0;
	/* ADDR() reconstruction of the table base -- see
	 * apply_one_irelative() below. No independent extent to check
	 * beyond tbl_size, already required nonzero above and used only to
	 * bound the loop count. */
	relas = unsafe_assume_valid_pointer(ADDR(obj, tbl_vaddr));
	count = tbl_size / sizeof(Elf64_Rela);
	for (i = 0; i < count; i++) {
		struct reloc rec;
		rec.r_offset = relas[i].r_offset;
		rec.r_sym = ELF64_R_SYM(relas[i].r_info);
		rec.r_type = ELF64_R_TYPE(relas[i].r_info);
		rec.r_addend = relas[i].r_addend;
		if (apply_one_reloc(obj, &rec, lo, hi) != 0) return -1;
	}
	return 0;
#endif
}

/* The second half of R_AARCH64_IRELATIVE/R_X86_64_IRELATIVE handling --
 * see apply_one_reloc()'s own R_AARCH64_IRELATIVE case (which
 * deliberately does nothing) for why this has to be a SEPARATE later
 * pass over the identical relocation tables, not just another case in
 * that function's own switch: this must run after load_object()'s own
 * protection-narrowing pass has made this object's .text genuinely
 * executable (the resolver this calls lives there) and before its
 * PT_GNU_RELRO hardening pass (the GOT slot this writes into can fall
 * inside the RELRO-covered range on a real linker's output -- confirmed
 * against this file's own dlfix_ifunc.so fixture -- so writing it AFTER
 * RELRO already locked that range read-only would fault). Every
 * relocation type other than the platform's own IRELATIVE constant is
 * silently skipped here (not an error): apply_one_reloc() already
 * either applied it for real or already failed loudly on it during the
 * first pass, so a second, unrelated type showing up in the same table
 * is expected, not a new problem this pass needs to report again. */
static int apply_one_irelative(struct dlobj *obj, const struct reloc *r,
                                unsigned long lo, unsigned long hi)
{
	unsigned long *loc;
	unsigned long (*resolver)(void);

#if defined(__aarch64__)
	if (r->r_type != R_AARCH64_IRELATIVE) return 0;
#elif defined(__x86_64__)
	if (r->r_type != R_X86_64_IRELATIVE) return 0;
#elif defined(__i386__)
	if (r->r_type != R_386_IRELATIVE) return 0;
#else
	return 0;
#endif
	if (r->r_offset < lo || r->r_offset >= hi) {
		seterr("dlopen: relocation offset 0x%llx outside mapped object",
		       (unsigned long long)r->r_offset);
		return -1;
	}
	/* ADDR() reconstructs a pointer from this object's real mapped load
	 * bias (obj->bias, set once when load_object() mmap()'d the image)
	 * plus an ELF-relocation-computed virtual address; the same
	 * bias+vaddr reconstruction apply_one_reloc()/apply_reloc_table()
	 * already perform for every other relocation type (both marked the
	 * same way, below), IRELATIVE entries just reach it through this
	 * separate, later pass instead (see this function's own banner).
	 * r->r_offset -- the relocation SLOT this yields the address of --
	 * is proven inside [lo, hi) by the bounds check immediately above. */
	loc = unsafe_assume_valid_pointer(ADDR(obj, r->r_offset));
	/* Same ADDR() reconstruction as `loc` above, but keyed by a
	 * DIFFERENT field (r_addend, the resolver's own address) that has
	 * no equivalent bounds check available -- an ifunc resolver's
	 * target isn't range-limited to the relocated object the way a
	 * relocation slot is -- so this remains a human-justified ELF/ABI
	 * assumption (the relocation's own r_addend, by R_*_IRELATIVE's
	 * defined contract, holds resolver()'s runtime address), not a
	 * provable range like `loc` above. */
	resolver = unsafe_assume_valid_pointer(
	    (unsigned long (*)(void))ADDR(obj, (unsigned long)r->r_addend));
	*loc = resolver();
	return 0;
}

static int apply_irelative_table(struct dlobj *obj, uint64_t tbl_vaddr, uint64_t tbl_size, // NOLINT(bugprone-easily-swappable-parameters) -- table address and size have distinct relocation roles
                                  unsigned long lo, unsigned long hi)
{
#if defined(__i386__)
	Elf32_Rel *rels;
	size_t count, i;
	if (!tbl_vaddr || !tbl_size) return 0;
	rels = ADDR(obj, tbl_vaddr);
	count = tbl_size / sizeof(Elf32_Rel);
	for (i = 0; i < count; i++) {
		struct reloc rec;
		int32_t *loc;
		if (rels[i].r_offset < lo || rels[i].r_offset >= hi) {
			seterr("dlopen: relocation offset 0x%llx outside mapped object",
			       (unsigned long long)rels[i].r_offset);
			return -1;
		}
		loc = ADDR(obj, rels[i].r_offset);
		rec.r_offset = rels[i].r_offset;
		rec.r_sym = ELF32_R_SYM(rels[i].r_info);
		rec.r_type = ELF32_R_TYPE(rels[i].r_info);
		/* Still the original implicit addend for an R_386_IRELATIVE
		 * entry specifically -- apply_one_reloc()'s own R_386_IRELATIVE
		 * case (via apply_reloc_table() above) deliberately left THIS
		 * type's own slot untouched in the first pass, exactly as it
		 * does for R_AARCH64_IRELATIVE/R_X86_64_IRELATIVE (see that
		 * case's own comment). Every other type's slot already holds
		 * its real relocated value by now, not an addend at all -- but
		 * apply_one_irelative() below discards rec.r_addend unread for
		 * any type other than R_386_IRELATIVE, so that is harmless. */
		rec.r_addend = *loc;
		if (apply_one_irelative(obj, &rec, lo, hi) != 0) return -1;
	}
	return 0;
#else
	Elf64_Rela *relas;
	size_t count, i;
	if (!tbl_vaddr || !tbl_size) return 0;
	/* tbl_vaddr is DT_JMPREL/an irelative-table PT_DYNAMIC entry's own
	 * link-time virtual address; ADDR() reconstructs its runtime
	 * location the same way every other section/table address in this
	 * loader does, from obj->bias (this object's real, already-mapped
	 * load bias) plus that ELF-declared vaddr. Every element this table
	 * yields is separately bounds-checked against [lo, hi) inside the
	 * loop below (r->r_offset, see apply_one_irelative()) before use;
	 * the table base itself has no independent extent to check beyond
	 * tbl_size, already required nonzero above and used only to bound
	 * the loop count. */
	relas = unsafe_assume_valid_pointer(ADDR(obj, tbl_vaddr));
	count = tbl_size / sizeof(Elf64_Rela);
	for (i = 0; i < count; i++) {
		struct reloc rec;
		rec.r_offset = relas[i].r_offset;
		rec.r_sym = ELF64_R_SYM(relas[i].r_info);
		rec.r_type = ELF64_R_TYPE(relas[i].r_info);
		rec.r_addend = relas[i].r_addend;
		if (apply_one_irelative(obj, &rec, lo, hi) != 0) return -1;
	}
	return 0;
#endif
}

/* DT_INIT (if present), then every DT_INIT_ARRAY entry in file order --
 * exactly once per dlopen() call, run after this object (and, thanks to
 * load_object()'s own depth-first dependency loading, every dependency
 * beneath it, whose own load_object() call already ran ITS constructors
 * before returning) is fully relocated and protection-finalized. This
 * loader never dedups (see "NAMESPACE ISOLATION" above), so there is no
 * "did this already run" bookkeeping a deduping loader would need --
 * every struct dlobj this file ever creates gets its constructors run
 * exactly once, at the end of the one load_object() call that created
 * it. */
static void run_ctors(struct dlobj *obj, Elf_Dyn *dyn)
{
	Elf_Dyn *d_init = find_dyn_ptr(dyn, DT_INIT);
	Elf_Dyn *d_init_array = find_dyn_ptr(dyn, DT_INIT_ARRAY);
	Elf_Dyn *d_init_arraysz = find_dyn_ptr(dyn, DT_INIT_ARRAYSZ);

	if (d_init) {
		/* ADDR() reconstruction -- see apply_one_irelative() below. */
		void (*init_fn)(void) =
		    unsafe_assume_valid_pointer((void (*)(void))ADDR(obj, d_init->d_val));
		init_fn();
	}
	if (d_init_array && d_init_arraysz) {
		/* uintptr_t-sized entries, NOT hardcoded uint64_t: a real
		 * .init_array entry is one pointer-width word wide on its own
		 * architecture, which is 4 bytes on i386 -- the same "loc must
		 * track the target's own native word size, not a hardcoded 64
		 * bits" reasoning apply_one_reloc()'s own `unsigned long *loc`
		 * follows. ADDR() reconstruction of the array base itself --
		 * see apply_one_irelative() below. */
		uintptr_t *arr = unsafe_assume_valid_pointer(ADDR(obj, d_init_array->d_val));
		size_t count = d_init_arraysz->d_val / sizeof(uintptr_t);
		size_t i;
		for (i = 0; i < count; i++) {
			/* Each slot already holds an absolute, post-relocation
			 * function address by the time this runs: a -fPIC shared
			 * object's own .init_array lives in an ordinary writable
			 * PT_LOAD segment, and its entries get plain R_*_RELATIVE
			 * dynamic relocations at static-link time -- already
			 * applied by apply_reloc_table() above, like any other
			 * data pointer (confirmed against this file's own test
			 * fixture) -- NOT a link-time vaddr this function itself
			 * would need to re-bias through ADDR(). The relocation
			 * pass that established this ran in a DIFFERENT function
			 * (apply_reloc_table(), earlier in load_object()'s own
			 * sequence), an invariant this function's own body cannot
			 * see. */
			void (*fn)(void) =
			    unsafe_assume_valid_pointer((void (*)(void))(uintptr_t)arr[i]);
			fn();
		}
	}
}

/* ---- DT_NEEDED dependency-path resolution -----------------------------
 *
 * See this file's own "NAMESPACE ISOLATION" banner for the loading-and-
 * namespace side of DT_NEEDED chasing; this is just "where do we even
 * find the file". This loader has no ld.so, no ldconfig cache, no
 * DT_RPATH/DT_RUNPATH parsing, and reads no LD_LIBRARY_PATH -- real,
 * disclosed scope narrowing, not a hidden gap. What it actually does is
 * deliberately the simplest thing that lets a real multi-file dependency
 * chain work at all: look next to the object that NAMED the dependency
 * (that object's own directory -- a poor man's implicit "$ORIGIN"), then
 * fall back to the bare name exactly as passed to open() -- the same
 * "no search path of its own" contract __plat_dlopen()'s own top-level
 * `file` argument already has (a relative name resolves against the
 * CALLER's cwd, an absolute name is absolute). A real implementation
 * wanting DT_RPATH/DT_RUNPATH/LD_LIBRARY_PATH/an ldconfig-style cache
 * can build all of that on top of this same open_needed() call site
 * later; nothing above it needs to change. */
static void dirname_of(const char *path, char *buf, size_t bufsz)
{
	const char *slash = strrchr(path, '/');
	size_t len, i;
	if (!slash) { buf[0] = 0; return; }
	len = (size_t)(slash - path) + 1; /* keep the slash itself */
	if (len >= bufsz) len = bufsz - 1;
	for (i = 0; i < len; i++) buf[i] = path[i];
	buf[len] = 0;
}

static int open_needed(const char *dir, const char *name, char *pathbuf, size_t pathbuf_sz)
{
	int fd = -1;
	if (dir && dir[0] && strlen(dir) + strlen(name) < pathbuf_sz) {
		(void)snprintf(pathbuf, pathbuf_sz, "%s%s", dir, name);
		fd = open(pathbuf, O_RDONLY);
	}
	if (fd >= 0) return fd;
	if (strlen(name) >= pathbuf_sz) { errno = ENAMETOOLONG; return -1; }
	{
		size_t i, length = strlen(name);
		for (i = 0; i <= length; i++) pathbuf[i] = name[i];
	}
	return open(name, O_RDONLY);
}

/* ---- dependency-tree bookkeeping --------------------------------------
 *
 * Every struct dlobj this file ever creates for a DT_NEEDED dependency
 * is owned, transitively, by the top-level dlopen() call that pulled it
 * in -- see this file's own "NAMESPACE ISOLATION" banner: nothing here
 * is shared or reference-counted, so there is exactly one owner and
 * closing (or failing to fully build) it must tear down everything
 * underneath it too. */
static int add_dep(struct dlobj *obj, struct dlobj *dep)
{
	struct dlobj **grown;
	size_t ndeps;
	if (!__size_add_checked(obj->ndeps, 1, &ndeps)) return -1;
	grown = reallocarray(obj->deps, ndeps, sizeof *grown);
	if (!grown) return -1;
	grown[obj->ndeps] = dep;
	obj->deps = grown;
	obj->ndeps++;
	return 0;
}

/* Recursively tear down `obj` and everything it owns: its own DT_NEEDED
 * dependency subtree (deepest first), its own per-object TLS block (if
 * any -- aarch64 only, see this file's TLS banner), and finally its own
 * mapping. Used both by __plat_dlclose() below (a fully-built object)
 * and by load_object()'s own `fail:` path (a PARTIALLY built one --
 * some deps loaded, TLS maybe set up, relocations maybe not yet
 * applied) -- safe either way, since it only ever looks at fields that
 * are already valid the moment they are set (deps/ndeps are 0/NULL
 * until add_dep() succeeds; tls_module_id is 0 until setup_object_tls()
 * succeeds). obj may be NULL (nothing allocated yet); a no-op. */
static void teardown_obj(struct dlobj *obj)
{
	size_t i;
	if (!obj) return;
	for (i = 0; i < obj->ndeps; i++) teardown_obj(obj->deps[i]);
	free(obj->deps);
#if defined(__aarch64__)
	if (obj->tls_module_id) {
		void **tp = (void **)__builtin_thread_pointer();
		void **dtv = *(void ***)tp;
		/* Never reused (see setup_object_tls()'s own comment on module
		 * ids being monotonic) -- clearing the slot is defensive
		 * hygiene, not required for correctness, since this id will
		 * never be handed to a different object again. */
		if ((size_t)obj->tls_module_id < dtv_capacity) dtv[obj->tls_module_id] = 0;
		free(obj->tls_block);
	}
#endif
	if (obj->map_base != MAP_FAILED) raw_munmap(obj->map_base, obj->map_len);
	free(obj);
}

/* The real loader: genuinely recursive (DT_NEEDED chasing -- see below --
 * calls this again for each dependency), so `file` is not necessarily a
 * caller-given top-level path, and `depth` bounds that recursion (see
 * the check just below). __plat_dlopen() itself, further down, is a
 * thin wrapper: MAIN_IMAGE_HANDLE's special-casing and the RTLD_* `mode`
 * parameter both belong to the PUBLIC entry point, not to this internal
 * one. */
static struct dlobj *load_object(const char *file, int depth)
{
	int fd = -1;
	Elf_Ehdr eh;
	Elf_Phdr *phdrs = NULL;
	size_t phdr_bytes;
	Elf_Phdr *pt_dynamic = NULL;
	Elf_Phdr *pt_tls = NULL;
	Elf_Phdr *pt_relro = NULL;
	unsigned long lo = (unsigned long)-1, hi = 0;
	void *map_base = MAP_FAILED;
	size_t map_len = 0;
	struct dlobj *obj = NULL;
	unsigned int i;
	/* DT_RELA/DT_JMPREL's own location+size, captured here (rather than
	 * read again later) so the deferred IRELATIVE pass below -- which
	 * has to run after this function's own dynamic-section-parsing
	 * block has already gone out of scope, see that pass's own comment
	 * further down for exactly why -- can re-walk the identical two
	 * tables apply_reloc_table() already walked once, without a second
	 * DT_RELA/DT_JMPREL lookup. Zero-initialized: apply_irelative_table()
	 * already treats a zero vaddr/size as "no table", the same
	 * convention apply_reloc_table() itself already uses. */
	uint64_t rela_vaddr = 0, rela_size = 0, jmprel_vaddr = 0, jmprel_size = 0;

	if (depth > 32) {
		seterr("dlopen: %s: DT_NEEDED dependency chain too deep (>32 levels) -- likely a cycle", file);
		return NULL;
	}

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		seterr("dlopen: %s: %s", file, strerror(errno));
		return NULL;
	}

	if (pread(fd, &eh, sizeof eh, 0) != (ssize_t)sizeof eh ||
	    memcmp(eh.e_ident, "\x7f""ELF", 4) != 0 ||
	    eh.e_ident[EI_CLASS] != ELF_CLASS || eh.e_ident[EI_DATA] != ELFDATA2LSB) {
		seterr("dlopen: %s: not a recognizable ELF file for this architecture", file);
		errno = ENOEXEC;
		goto fail;
	}
#if defined(__aarch64__)
	if (eh.e_machine != EM_AARCH64) {
		seterr("dlopen: %s: wrong machine type (this build only supports EM_AARCH64=%d, see this file's own banner)", file, EM_AARCH64);
		errno = ENOEXEC;
		goto fail;
	}
#elif defined(__x86_64__)
	if (eh.e_machine != EM_X86_64) {
		seterr("dlopen: %s: wrong machine type (this build only supports EM_X86_64=%d, see this file's own banner)", file, EM_X86_64);
		errno = ENOEXEC;
		goto fail;
	}
#elif defined(__i386__)
	if (eh.e_machine != EM_386) {
		seterr("dlopen: %s: wrong machine type (this build only supports EM_386=%d, see this file's own banner)", file, EM_386);
		errno = ENOEXEC;
		goto fail;
	}
#endif
	if (eh.e_type != ET_DYN) {
		seterr("dlopen: %s: not ET_DYN (only shared objects are supported)", file);
		errno = ENOEXEC;
		goto fail;
	}
	if (eh.e_phnum == 0 || eh.e_phnum > 256 || eh.e_phentsize != sizeof(Elf_Phdr)) {
		seterr("dlopen: %s: unusable program header table", file);
		errno = ENOEXEC;
		goto fail;
	}

	if (table_bytes((size_t)eh.e_phnum, sizeof *phdrs, &phdr_bytes) < 0) {
		seterr("dlopen: %s: program header table is too large", file); errno = ENOEXEC; goto fail;
	}
	phdrs = malloc(phdr_bytes);
	if (!phdrs) { seterr("dlopen: out of memory"); errno = ENOMEM; goto fail; }
	if (pread(fd, phdrs, phdr_bytes, (off_t)eh.e_phoff) != (ssize_t)phdr_bytes) {
		seterr("dlopen: %s: short read on program header table", file);
		goto fail;
	}

	for (i = 0; i < eh.e_phnum; i++) {
		Elf_Phdr *ph = &phdrs[i];
		if (ph->p_type == PT_TLS) {
#if defined(__aarch64__)
			/* Per-object TLS is implemented for aarch64 -- see this
			 * file's own "TLS / per-library thread descriptors"
			 * banner. Just remember the phdr here; module-id
			 * allocation and the mini-TCB build (setup_object_tls())
			 * happen below, once every PT_LOAD segment is actually
			 * mapped -- that needs to read PT_TLS's own initial data
			 * out of the mapping. */
			pt_tls = ph;
#else
			/* See this file's own "TLS / per-library thread
			 * descriptors" banner: aarch64's variant-I TCB (dtv-headed)
			 * is implemented; x86_64/i386's variant-II TCB (self-
			 * pointer-headed, TLS data at NEGATIVE tp offsets) is a
			 * structurally different shape not implemented here --
			 * refused cleanly, before anything is mapped, rather than
			 * loaded with no working TLS story. */
			seterr("dlopen: %s: has a PT_TLS segment (__thread variables) -- per-object TLS is implemented for aarch64 only so far (x86_64's variant-II TCB shape needs separate follow-up work, see plat_dlfcn.c's own TLS banner), not on this architecture", file);
			goto fail;
#endif
		}
		if (ph->p_type == PT_GNU_RELRO) pt_relro = ph;
		if (ph->p_type == PT_DYNAMIC) pt_dynamic = ph;
		if (ph->p_type != PT_LOAD) continue;
		if (ph->p_vaddr < lo) lo = ph->p_vaddr;
		if (ph->p_vaddr + ph->p_memsz > hi) hi = ph->p_vaddr + ph->p_memsz;
	}
	if (hi == 0 || !pt_dynamic) {
		seterr("dlopen: %s: no PT_LOAD/PT_DYNAMIC segments", file);
		goto fail;
	}
	lo = pgdown(lo);
	hi = pgup(hi);
	map_len = hi - lo;

	map_base = raw_mmap(NULL, map_len, PROT_NONE, MAP_PRIVATE | __MAP_ANONYMOUS, -1, 0);
	if (map_base == MAP_FAILED) {
		int saved = errno;
		seterr("dlopen: %s: cannot reserve %zu bytes of address space: %s", file, map_len, strerror(saved));
		goto fail;
	}

	obj = malloc(sizeof *obj);
	if (!obj) { seterr("dlopen: out of memory"); goto fail; }
	obj->map_base = map_base;
	obj->map_len = map_len;
	obj->bias = (unsigned long)map_base - lo;
	obj->deps = NULL;
	obj->ndeps = 0;
	obj->tls_module_id = 0;
	obj->tls_block = NULL;

	/* Map every PT_LOAD segment. Mapped read-write initially regardless
	 * of the segment's own p_flags -- relocations below may need to
	 * write into it -- and narrowed down to its real declared
	 * protection in a second pass once every relocation (which may
	 * target any segment, not just the one currently being mapped) has
	 * been applied. See this file's own PT_GNU_RELRO note: this is
	 * NOT a relro-hardening pass, just restoring the object's own
	 * declared (non-relro) permissions. */
	for (i = 0; i < eh.e_phnum; i++) {
		Elf_Phdr *ph = &phdrs[i];
		unsigned long vstart, filelen, memend, alloclen;
		void *segbase;
		if (ph->p_type != PT_LOAD) continue;

		vstart = pgdown(ph->p_vaddr);
		filelen = pgup((ph->p_vaddr - vstart) + ph->p_filesz);
		memend = pgup((ph->p_vaddr - vstart) + ph->p_memsz);
		/* Same bias+vaddr reconstruction as ADDR() -- see
		 * apply_one_irelative() below -- just not spelled through that
		 * macro since vstart is already page-aligned, not a raw
		 * ELF-declared vaddr. */
		segbase = unsafe_assume_valid_pointer((void *)(obj->bias + vstart));

		if (ph->p_filesz > 0) {
			void *r = raw_mmap(segbase, filelen, PROT_READ | PROT_WRITE,
			               MAP_PRIVATE | MAP_FIXED, fd, (long)pgdown(ph->p_offset));
			if (r == MAP_FAILED) {
				int saved = errno;
				seterr("dlopen: %s: cannot map PT_LOAD segment %u: %s", file, i, strerror(saved));
				goto fail;
			}
			/* Zero the tail of the last file-backed page past p_filesz
			 * -- the ELF loading rule every real loader implements
			 * (System V ABI: "the bytes from the end of the file image
			 * to the end of the memory image are... initialized to
			 * zero"). The kernel already zero-fills the tail of a
			 * mapped page past the underlying file's own extent for a
			 * MAP_PRIVATE file mapping, but that guarantee stops at
			 * the file's real length, not at p_filesz specifically --
			 * writing it explicitly costs nothing and does not depend
			 * on that distinction lining up. */
			for (size_t tailoff = (size_t)((ph->p_vaddr - vstart) + ph->p_filesz);
			     tailoff < filelen; tailoff++)
				((char *)segbase)[tailoff] = 0;
		}
		alloclen = memend > filelen ? memend : filelen;
		if (alloclen > filelen) {
			void *r = raw_mmap((char *)segbase + filelen, alloclen - filelen, PROT_READ | PROT_WRITE,
				               MAP_PRIVATE | MAP_FIXED | __MAP_ANONYMOUS, -1, 0);
			if (r == MAP_FAILED) {
				int saved = errno;
				seterr("dlopen: %s: cannot map bss tail of segment %u: %s", file, i, strerror(saved));
				goto fail;
			}
		}
	}

#if defined(__aarch64__)
	/* Per-object TLS setup -- see setup_object_tls()'s own banner. Must
	 * run after every PT_LOAD segment above is mapped (it reads PT_TLS's
	 * own initial data out of that mapping) and before any relocation is
	 * applied below (R_AARCH64_TLSDESC relocations need obj->tls_
	 * module_id already assigned). */
	if (pt_tls && setup_object_tls(obj, pt_tls) != 0) {
		seterr("dlopen: %s: out of memory setting up per-object TLS", file);
		goto fail;
	}
#endif

	{
		/* ADDR() reconstruction -- see apply_one_irelative() below. */
		Elf_Dyn *dyn = unsafe_assume_valid_pointer(ADDR(obj, pt_dynamic->p_vaddr));
		Elf_Dyn *d_hash = find_dyn_ptr(dyn, DT_HASH);
		Elf_Dyn *d_symtab = find_dyn_ptr(dyn, DT_SYMTAB);
		Elf_Dyn *d_strtab = find_dyn_ptr(dyn, DT_STRTAB);
		Elf_Dyn *d_syment = find_dyn_ptr(dyn, DT_SYMENT);
		Elf_Dyn *d_rela = find_dyn_ptr(dyn, DT_REL_TAG);
		Elf_Dyn *d_relasz = find_dyn_ptr(dyn, DT_RELSZ_TAG);
		Elf_Dyn *d_relaent = find_dyn_ptr(dyn, DT_RELENT_TAG);
		Elf_Dyn *d_jmprel = find_dyn_ptr(dyn, DT_JMPREL);
		Elf_Dyn *d_pltrelsz = find_dyn_ptr(dyn, DT_PLTRELSZ);
		Elf_Dyn *d_pltrel = find_dyn_ptr(dyn, DT_PLTREL);

		if (!d_hash || !d_symtab || !d_strtab || !d_syment) {
			seterr("dlopen: %s: no DT_HASH/DT_SYMTAB/DT_STRTAB -- DT_GNU_HASH-only objects are not supported yet (see this file's own banner); relink with -Wl,--hash-style=sysv or =both", file);
			goto fail;
		}
		if (d_syment->d_val != sizeof(Elf_Sym)) {
			seterr("dlopen: %s: unexpected DT_SYMENT", file);
			goto fail;
		}
#if defined(__i386__)
		if (d_relaent && d_relaent->d_val != sizeof(Elf32_Rel)) {
			seterr("dlopen: %s: unexpected DT_RELENT", file);
			goto fail;
		}
#else
		if (d_relaent && d_relaent->d_val != sizeof(Elf64_Rela)) {
			seterr("dlopen: %s: unexpected DT_RELAENT", file);
			goto fail;
		}
#endif
		if (d_pltrel && d_pltrel->d_val != DT_REL_TAG) {
			seterr("dlopen: %s: DT_PLTREL does not match this object's own main relocation format", file);
			goto fail;
		}

		/* ADDR() reconstruction, twice -- see apply_one_irelative()
		 * below. */
		obj->dynsym = unsafe_assume_valid_pointer(ADDR(obj, d_symtab->d_val));
		obj->dynstr = unsafe_assume_valid_pointer(ADDR(obj, d_strtab->d_val));
		/* DT_HASH's header is { nbucket; nchain; ... } -- nchain equals
		 * the symbol table's own entry count by the SysV ELF hash
		 * table's own specification, giving an exact count with no
		 * GNU-hash bucket walk needed. Same bias+vaddr reconstruction
		 * as ADDR(), just not spelled through that macro since the
		 * result is immediately dereferenced rather than stored as a
		 * pointer. */
		obj->dynsym_count = unsafe_assume_valid_pointer(
		    (uint32_t *)(uintptr_t)(obj->bias + d_hash->d_val))[1];

		/* ---- DT_NEEDED: load every dependency fresh, within this
		 * object's own namespace -- see this file's "NAMESPACE
		 * ISOLATION" banner. Must happen BEFORE the relocation passes
		 * below: this object's own undefined symbols may need to
		 * resolve against a dependency (resolve_symref() above), and a
		 * dependency's own DT_INIT/DT_INIT_ARRAY (run_ctors(), inside
		 * the recursive load_object() call below) needs to run before
		 * THIS object's own constructors do. */
		{
			Elf_Dyn *walk;
			char dir[4096];
			dirname_of(file, dir, sizeof dir);
			for (walk = dyn; walk->d_tag != DT_NULL; walk++) {
				char pathbuf[4096];
				int nfd;
				struct dlobj *dep;
				const char *needed_name;
				if (walk->d_tag != DT_NEEDED) continue;
				needed_name = obj->dynstr + walk->d_val;
				nfd = open_needed(dir, needed_name, pathbuf, sizeof pathbuf);
				if (nfd < 0) {
					seterr("dlopen: %s: cannot find DT_NEEDED dependency \"%s\": %s (searched \"%s\" and the bare name -- no DT_RPATH/DT_RUNPATH/LD_LIBRARY_PATH support, see this file's own DT_NEEDED banner)",
					       file, needed_name, strerror(errno), dir[0] ? dir : "(no directory)");
					goto fail;
				}
				(void)close(nfd);
				dep = load_object(pathbuf, depth + 1);
				if (!dep) goto fail; /* seterr already set by the recursive call */
				if (add_dep(obj, dep) != 0) {
					teardown_obj(dep);
					seterr("dlopen: %s: out of memory recording dependency \"%s\"", file, needed_name);
					goto fail;
				}
			}
		}

		rela_vaddr = d_rela ? d_rela->d_val : 0;
		rela_size = d_relasz ? d_relasz->d_val : 0;
		jmprel_vaddr = d_jmprel ? d_jmprel->d_val : 0;
		jmprel_size = d_pltrelsz ? d_pltrelsz->d_val : 0;

		if (apply_reloc_table(obj, rela_vaddr, rela_size, lo, hi) != 0)
			goto fail;
		if (apply_reloc_table(obj, jmprel_vaddr, jmprel_size, lo, hi) != 0)
			goto fail;
	}

	/* Second pass: narrow each PT_LOAD segment down to its own declared
	 * protection now that every relocation, wherever it targeted, has
	 * been applied. */
	for (i = 0; i < eh.e_phnum; i++) {
		Elf_Phdr *ph = &phdrs[i];
		unsigned long vstart, memend;
		int prot;
		if (ph->p_type != PT_LOAD) continue;
		vstart = pgdown(ph->p_vaddr);
		memend = pgup((ph->p_vaddr - vstart) + ph->p_memsz);
		prot = (ph->p_flags & PF_R ? PROT_READ : 0) |
		       (ph->p_flags & PF_W ? PROT_WRITE : 0) |
		       (ph->p_flags & PF_X ? PROT_EXEC : 0);
		if (prot & PROT_WRITE) continue; /* already mapped read-write */
		/* Same bias+vaddr reconstruction as ADDR() -- see
		 * apply_one_irelative() below -- just not spelled through that
		 * macro since vstart is already page-aligned, not a raw
		 * ELF-declared vaddr. */
		if (raw_mprotect(unsafe_assume_valid_pointer((void *)(obj->bias + vstart)),
		                 memend, prot) != 0) {
			seterr("dlopen: %s: cannot finalize protection on segment %u: %s", file, i, strerror(errno));
			goto fail;
		}
	}

	/* R_AARCH64_IRELATIVE/R_X86_64_IRELATIVE ("ifunc") resolution -- see
	 * apply_one_irelative()'s own banner for the full reasoning; run
	 * exactly here, in exactly this position, for two real reasons at
	 * once, not one: (1) AFTER the protection-narrowing pass just
	 * above, because it calls a resolver FUNCTION that lives in this
	 * object's own .text, which that pass is what makes executable in
	 * the first place -- calling it any earlier genuinely SIGSEGVs
	 * (confirmed empirically against this file's own dlfix_ifunc.so
	 * fixture, not just reasoned about); (2) BEFORE PT_GNU_RELRO
	 * hardening just below, because the GOT slot an IRELATIVE
	 * relocation writes its resolved value into commonly falls inside
	 * RELRO's own covered range on a real linker's output -- writing it
	 * after RELRO already locked that range read-only would fault the
	 * other way instead. */
	if (apply_irelative_table(obj, rela_vaddr, rela_size, lo, hi) != 0)
		goto fail;
	if (apply_irelative_table(obj, jmprel_vaddr, jmprel_size, lo, hi) != 0)
		goto fail;

	/* PT_GNU_RELRO hardening. Applied LAST, after every relocation and
	 * after the ordinary protection-narrowing pass just above has
	 * already restored each segment's own declared (non-relro)
	 * permissions -- narrowing again here, for just the relro
	 * sub-range, down to read-only. Both bounds rounded DOWN to a real
	 * page boundary (not up): matches glibc's own reference algorithm
	 * (_dl_protect_relro), and for a real reason, not mere imitation --
	 * PT_GNU_RELRO's own p_memsz is not guaranteed page-aligned, and
	 * rounding the END up would risk marking read-only a partial page
	 * that ALSO holds non-relro, genuinely-still-written data (e.g. the
	 * start of .bss) sharing that same page past relro's own declared
	 * end. */
	if (pt_relro) {
		unsigned long relro_lo = pgdown(pt_relro->p_vaddr);
		unsigned long relro_hi = pgdown(pt_relro->p_vaddr + pt_relro->p_memsz);
		/* Same bias+vaddr reconstruction as segbase/raw_mprotect(vstart)
		 * above -- see apply_one_irelative() below. */
		if (relro_hi > relro_lo &&
		    raw_mprotect(unsafe_assume_valid_pointer((void *)(obj->bias + relro_lo)),
		                 relro_hi - relro_lo, PROT_READ) != 0) {
			seterr("dlopen: %s: cannot apply PT_GNU_RELRO protection: %s", file, strerror(errno));
			goto fail;
		}
	}

	/* DT_INIT/DT_INIT_ARRAY -- see run_ctors()'s own banner for exactly
	 * why this runs last, after every other step above has finished. */
	/* ADDR() reconstruction -- see apply_one_irelative() below. */
	run_ctors(obj, unsafe_assume_valid_pointer(ADDR(obj, pt_dynamic->p_vaddr)));

	free(phdrs);
	(void)close(fd);
	return obj;

fail:
	free(phdrs);
	if (fd >= 0) (void)close(fd);
	if (obj) {
		/* obj exists: it may already own dependencies (add_dep()'d
		 * above) and/or a TLS block (setup_object_tls()'d above) that
		 * must be torn down along with it -- teardown_obj() handles
		 * all of that (and obj->map_base, always valid by the time obj
		 * itself exists -- see load_object()'s own allocation order
		 * above). */
		teardown_obj(obj);
	} else if (map_base != MAP_FAILED) {
		/* Failed before obj was even allocated: the local map_base/
		 * map_len (not yet mirrored into any struct dlobj) are all
		 * there is to clean up. */
		raw_munmap(map_base, map_len);
	}
	return NULL;
}

void *__plat_dlopen(const char *file, int mode)
{
	(void)mode; /* every loaded object is already its own isolated
	             * namespace (see this file's own banner) and every
	             * relocation is already resolved eagerly -- RTLD_NOW/
	             * LAZY/GLOBAL/LOCAL have nothing left to select
	             * between, the same way they are moot on the NT
	             * backend for its own, different reasons. */

	if (!file) return MAIN_IMAGE_HANDLE;
	return load_object(file, 0);
}

void *__plat_dlsym(void *__restrict handle,
	const char *__restrict name withtok(null_terminated))
{
	void *addr;

	if (handle == MAIN_IMAGE_HANDLE) {
		addr = resolve_main_symbol(name);
		if (!addr) seterr("dlsym: symbol not found: %s", name);
		return addr;
	}

	addr = resolve_export(handle, name);
	if (!addr) seterr("dlsym: symbol not found: %s", name);
	return addr;
}

int __plat_dlclose(void *handle)
{
	if (handle == MAIN_IMAGE_HANDLE) return 0; /* see NT backend's identical rationale */
	teardown_obj(handle);
	return 0;
}

// NOLINTEND(misc-include-cleaner)
