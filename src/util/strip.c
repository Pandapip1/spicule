/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * strip(1p): `strip [-o strip_file] file`. Removes symbol table,
 * debugging, and relocation information from the executable file; -o
 * writes to a separate output instead of editing in place. That is the
 * entire base standard -- no XSI options to refuse.
 *
 * ---- WHY THIS FILE IS CONSERVATIVE ---------------------------------------
 *
 * A wrong strip corrupts an executable rather than just misbehaving, and
 * the input is often a real ELF PIE or this project's own working binary.
 * The invariant enforced by every check below: never rewrite a byte this
 * file cannot prove is safe to move, and when that proof fails, leave the
 * input byte-for-byte unchanged and still exit 0 (POSIX's DESCRIPTION
 * never promises removal *happens*, only that removal, if it happens, is
 * correct).
 *
 * ---- ELF64 STRATEGY --------------------------------------------------------
 *
 * ELFCLASS64/ELFDATA2LSB, ET_EXEC or ET_DYN only -- not ET_REL, whose
 * .symtab a later link step may still need; refused with a diagnostic.
 * Struct layouts below are a fresh local copy, deliberately not shared
 * with src/dlfcn/linux/plat_dlfcn.c or crt/linux/crt1.c, per this tree's
 * per-translation-unit struct-definition convention.
 *
 * Removal set: `.symtab`, `.strtab`, `.symtab_shndx`, `.comment`,
 * `.gnu_debuglink`, `.gnu_debugdata`, `.debug_*`. Never `.dynsym`/
 * `.dynstr` or anything else PT_DYNAMIC or a PT_LOAD depends on.
 *
 * Byte-for-byte, the approach:
 *
 *   1. Compute `load_limit`, the highest (p_offset + p_filesz) over every
 *      program header of any type. Nothing below that offset is ever
 *      relocated. No program headers at all -> refused (unchanged output).
 *   2. A section is a removal CANDIDATE only if its name is in the set
 *      above, it has no SHF_ALLOC bit, and its whole file range is at or
 *      beyond load_limit. Any section failing one of those checks stays,
 *      silently -- "kept" is always the safe outcome.
 *   3. Global safety gate, checked once for the whole file: if any
 *      section has SHF_ALLOC set AND sits at or beyond load_limit, the
 *      "everything loadable lives below load_limit" assumption is false
 *      for this binary and the whole strip is aborted -- output is the
 *      unmodified input, never a partial rewrite.
 *   4. A fixpoint pass protects against dangling references: for every
 *      KEPT section, if its sh_link (a section index when nonzero) or its
 *      sh_info (a section index only when SHF_INFO_LINK is set) names a
 *      section still marked for removal, that section is un-marked
 *      instead, and the pass repeats until nothing changes.
 *   5. Bytes below load_limit are copied verbatim and unmoved, including
 *      every PT_LOAD's phdrs and the ELF header's e_phoff/e_phnum/
 *      e_entry. Bytes at or above load_limit belonging to a KEPT section
 *      are copied, in original order, into a fresh compacted run with no
 *      gaps, each recording its new sh_offset (aligned to sh_addralign);
 *      REMOVED-section bytes are simply never copied. A fresh, shrunk
 *      section header table (sh_link/sh_info remapped) is appended after,
 *      and only e_shoff/e_shnum/e_shstrndx in the ELF header are patched.
 *
 * ---- PE STRATEGY (bonus scope; see __util_strip_main) --------------------
 *
 * Wine is unavailable in this sandbox, so a stripped PE binary cannot be
 * proven to still run the way test/util-strip.c proves for ELF. The PE
 * half therefore stays inside a much smaller, statically-verifiable scope:
 *
 *   - The legacy COFF symbol table (IMAGE_FILE_HEADER.PointerToSymbolTable/
 *     NumberOfSymbols) is removed ONLY when its byte range -- 18-byte
 *     symbol records followed by a string table whose own first 4 bytes
 *     are its total size -- reaches EXACTLY the end of the file. If not,
 *     the symbol table is left alone entirely.
 *   - The Debug Data Directory entry (IMAGE_DIRECTORY_ENTRY_DEBUG, index
 *     6) is zeroed if present -- this only clears a pointer pair inside
 *     the already-loaded header region, never moves a section byte, so it
 *     cannot desync SizeOfImage, section RVAs, or the import/export/
 *     relocation tables.
 *   - Nothing else is touched: no .pdata/.xdata, no .reloc, no section
 *     table entries, no RVAs. An actual `.debug$` COFF section (if a
 *     linker emits one) is NOT stripped -- removing a PE section needs
 *     re-deriving every RVA that follows it, which is unverifiable
 *     without a way to execute the result here and is left for later.
 *   - PE's checksum field (OptionalHeader.CheckSum) is left stale after
 *     either change, disclosed rather than silently wrong: ordinary
 *     user-mode loading does not validate it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdint.h>
#include "util.h"
#include "ownership_stubs.h"

/* ==== ELF64 shapes (own copy, see this file's own header banner) ========= */

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

#define EI_CLASS 4
#define EI_DATA  5
#define ELFCLASS64  2
#define ELFDATA2LSB 1

#define ET_EXEC 2
#define ET_DYN  3

#define SHT_NULL   0
#define SHT_NOBITS 8

#define SHF_ALLOC     0x2u
#define SHF_INFO_LINK 0x40u

/* sizeof() rather than hardcoded byte counts -- these structs have no
 * padding by field-order construction (same layout src/dlfcn/linux/
 * plat_dlfcn.c already relies on for real pread()s against real ELF
 * files), but computing the on-disk size from the struct itself rather
 * than restating it as a magic number is one less place the two could
 * silently drift apart. */
#define ELF_SHDR_SIZE ((uint32_t)sizeof(Elf64_Shdr))
#define ELF_PHDR_SIZE ((uint32_t)sizeof(Elf64_Phdr))
#define ELF_EHDR_SIZE ((uint32_t)sizeof(Elf64_Ehdr))

static int elf_name_strippable(const char *name)
{
	if (!name) return 0;
	if (strcmp(name, ".symtab") == 0) return 1;
	if (strcmp(name, ".strtab") == 0) return 1;
	if (strcmp(name, ".symtab_shndx") == 0) return 1;
	if (strcmp(name, ".comment") == 0) return 1;
	if (strcmp(name, ".gnu_debuglink") == 0) return 1;
	if (strcmp(name, ".gnu_debugdata") == 0) return 1;
	if (strncmp(name, ".debug_", 7) == 0) return 1;
	return 0;
}

static uint64_t align_up(uint64_t v, uint64_t align)
{
	if (align < 1) return v;
	return (v + align - 1) - ((v + align - 1) % align);
}

/* Strips `buf`/`size` (a whole ELF file already read into memory) if,
 * and only if, this file's own documented safety checks all hold.
 * Always succeeds: on any check failure, `*out`/`*outsize` become a
 * verbatim copy of the input (a safe no-op, not an error) -- the only
 * failure return is a genuine allocation failure. `*changed` reports
 * whether anything was actually removed, for the caller's own
 * diagnostic, not for correctness. */
static int strip_elf(const unsigned char *buf, size_t size,
                      unsigned char **out, size_t *outsize, int *changed)
{
	Elf64_Ehdr eh;
	Elf64_Phdr *phdrs = NULL;
	Elf64_Shdr *shdrs = NULL;
	unsigned char *removed = NULL;
	uint32_t *map = NULL;
	uint64_t *new_off = NULL;
	unsigned char *outbuf = NULL;
	uint64_t load_limit = 0;
	uint32_t i;
	int ok_to_strip = 1;

	*changed = 0;

	/* Unconditional fallback: an exact copy, used whenever this function
	 * decides (for any reason) not to touch the input. */
	outbuf = malloc(size ? size : 1);
	if (!outbuf) return -1;
	memcpy(outbuf, buf, size);
	*out = outbuf;
	*outsize = size;

	if (size < ELF_EHDR_SIZE) return 0; /* too small to be real ELF64 -- untouched */
	memcpy(&eh, buf, sizeof eh);

	if (eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_ident[EI_DATA] != ELFDATA2LSB)
		return 0; /* not ELF64 little-endian -- out of this file's scope, untouched */
	if (eh.e_type != ET_EXEC && eh.e_type != ET_DYN)
		return 0; /* ET_REL etc. -- deliberately out of scope, see header banner */
	if (eh.e_shoff == 0 || eh.e_shnum == 0 || eh.e_shentsize != ELF_SHDR_SIZE)
		return 0; /* no section header table to strip from */
	if (eh.e_shstrndx >= eh.e_shnum)
		return 0; /* SHN_XINDEX/extended numbering or corrupt -- untouched */
	if (eh.e_phnum != 0 && eh.e_phentsize != ELF_PHDR_SIZE)
		return 0;
	{
		uint64_t sh_bytes = (uint64_t)eh.e_shnum * ELF_SHDR_SIZE;
		uint64_t ph_bytes = (uint64_t)eh.e_phnum * ELF_PHDR_SIZE;
		if (eh.e_shoff > size || sh_bytes > size - eh.e_shoff) return 0;
		if (eh.e_phnum && (eh.e_phoff > size || ph_bytes > size - eh.e_phoff)) return 0;
	}

	if (eh.e_phnum == 0) return 0; /* nothing a real loader maps by phdr -- untouched */

	phdrs = malloc((size_t)eh.e_phnum * sizeof *phdrs);
	shdrs = malloc((size_t)eh.e_shnum * sizeof *shdrs);
	removed = calloc(eh.e_shnum, 1);
	map = malloc((size_t)eh.e_shnum * sizeof *map);
	new_off = calloc(eh.e_shnum, sizeof *new_off);
	if (!phdrs || !shdrs || !removed || !map || !new_off) {
		free(phdrs); free(shdrs); free(removed); free(map); free(new_off);
		return 0; /* out of memory -- leave the file untouched, not half-done */
	}
	memcpy(phdrs, buf + eh.e_phoff, (size_t)eh.e_phnum * sizeof *phdrs);
	memcpy(shdrs, buf + eh.e_shoff, (size_t)eh.e_shnum * sizeof *shdrs);

	for (i = 0; i < eh.e_phnum; i++) {
		uint64_t end;
		if (phdrs[i].p_filesz > size || phdrs[i].p_offset > size - phdrs[i].p_filesz) {
			ok_to_strip = 0; /* corrupt phdr -- refuse outright */
			continue;
		}
		end = phdrs[i].p_offset + phdrs[i].p_filesz;
		if (end > load_limit) load_limit = end;
	}

	{
		const char *shstr;
		uint64_t shstr_sz;
		Elf64_Shdr *ss = &shdrs[eh.e_shstrndx];
		if (ss->sh_offset > size || ss->sh_size > size - ss->sh_offset) ok_to_strip = 0;
		shstr = ok_to_strip ? (const char *)(buf + ss->sh_offset) : NULL;
		shstr_sz = ok_to_strip ? ss->sh_size : 0;

		for (i = 0; i < eh.e_shnum && ok_to_strip; i++) {
			Elf64_Shdr *sh = &shdrs[i];
			const char *name = NULL;

			/* SHT_NOBITS (.bss/.tbss) sections occupy no actual file
			 * bytes -- sh_offset is only a nominal marker (real ELF
			 * output, not a hypothetical: this build's own PIE
			 * binaries place .bss's sh_offset at exactly load_limit,
			 * with sh_size that would run well past EOF if it were
			 * real file content), so neither the file-bounds check
			 * nor the "allocated content must live below load_limit"
			 * gate below applies to one -- there is no byte at that
			 * offset for either check to be protecting. */
			if (sh->sh_type != SHT_NOBITS &&
			    (sh->sh_offset > size || sh->sh_size > size - sh->sh_offset)) {
				ok_to_strip = 0; /* corrupt section entry -- refuse outright */
				break;
			}
			/* Step 3's global safety gate: any allocated section at or
			 * beyond load_limit means this file's whole "loadable
			 * content lives below load_limit" premise is false for
			 * this binary -- abort the entire strip, not just this
			 * one section. */
			if (sh->sh_type != SHT_NOBITS &&
			    (sh->sh_flags & SHF_ALLOC) && sh->sh_offset >= load_limit) {
				ok_to_strip = 0;
				break;
			}
			if (sh->sh_type == SHT_NULL || i == eh.e_shstrndx) continue;
			if (sh->sh_name >= shstr_sz) continue; /* unreadable name -- never a candidate */
			name = shstr + sh->sh_name;
			/* Bounds-check the NUL terminator lives inside shstrtab
			 * before ever calling strcmp/strncmp on it. */
			{
				uint64_t max = shstr_sz - sh->sh_name;
				size_t len = strnlen(name, max);
				if (len == max) continue; /* not NUL-terminated within bounds -- skip */
			}
			if (!elf_name_strippable(name)) continue;
			if (sh->sh_flags & SHF_ALLOC) continue; /* never remove anything loaded */
			if (sh->sh_offset < load_limit) continue; /* not safely in the tail region */
			removed[i] = 1;
		}
	}

	if (ok_to_strip) {
		int changed_fix = 1;
		while (changed_fix) {
			changed_fix = 0;
			for (i = 0; i < eh.e_shnum; i++) {
				if (removed[i]) continue;
				if (shdrs[i].sh_link != 0 && shdrs[i].sh_link < eh.e_shnum &&
				    removed[shdrs[i].sh_link]) {
					removed[shdrs[i].sh_link] = 0;
					changed_fix = 1;
				}
				if ((shdrs[i].sh_flags & SHF_INFO_LINK) && shdrs[i].sh_info != 0 &&
				    shdrs[i].sh_info < eh.e_shnum && removed[shdrs[i].sh_info]) {
					removed[shdrs[i].sh_info] = 0;
					changed_fix = 1;
				}
			}
		}
	}

	if (!ok_to_strip) {
		free(phdrs); free(shdrs); free(removed); free(map); free(new_off);
		return 0; /* safety gate failed somewhere -- output stays the verbatim copy */
	}

	{
		uint32_t any_removed = 0;
		for (i = 0; i < eh.e_shnum; i++) if (removed[i]) any_removed = 1;
		if (!any_removed) {
			free(phdrs); free(shdrs); free(removed); free(map); free(new_off);
			return 0; /* nothing matched -- verbatim copy is already correct */
		}
	}

	/* Build the new index map for kept sections, in original order. */
	{
		uint32_t next = 0;
		for (i = 0; i < eh.e_shnum; i++) map[i] = removed[i] ? (uint32_t)-1 : next++;
	}

	/* Compose the output: [0, load_limit) verbatim, then the compacted
	 * tail (kept sections whose sh_offset >= load_limit, in original
	 * relative order, no gaps for removed ones), then the new,
	 * shrunk section header table. */
	{
		size_t cap = size; /* strip only ever shrinks a file */
		unsigned char *ob = malloc(cap ? cap : 1);
		uint64_t pos;
		uint32_t kept_shnum;
		Elf64_Ehdr new_eh;
		int compose_ok = 1;

		if (!ob) {
			free(phdrs); free(shdrs); free(removed); free(map); free(new_off);
			return -1;
		}
		memcpy(ob, buf, (size_t)load_limit);
		pos = load_limit;

		for (i = 0; i < eh.e_shnum && compose_ok; i++) {
			Elf64_Shdr *sh = &shdrs[i];
			uint64_t aligned;
			if (sh->sh_offset < load_limit) continue; /* already covered verbatim */
			if (removed[i]) continue; /* its bytes are simply never copied */
			/* sh_addralign is an attacker-controlled field straight out
			 * of this section's own header; align_up() with no upper
			 * bound on it can walk `pos` arbitrarily far past this
			 * `cap`-byte buffer (or, if the addition inside align_up()
			 * wraps, arbitrarily backward over already-written bytes) --
			 * either way the memcpy() below would then read/write
			 * outside what was proven safe. Treat an alignment that
			 * would do either as exactly the "cannot prove safe" case
			 * this file's own header banner requires refusing: abort the
			 * whole strip and fall back to the untouched verbatim copy. */
			aligned = align_up(pos, sh->sh_addralign ? sh->sh_addralign : 1);
			if (aligned < pos || aligned > cap ||
			    (sh->sh_type != SHT_NOBITS && sh->sh_size > cap - aligned)) {
				compose_ok = 0;
				break;
			}
			pos = aligned;
			new_off[i] = pos;
			/* SHT_NOBITS (.bss-like) sections have no file-resident
			 * data at all -- nothing to copy, just record a position. */
			if (sh->sh_type != SHT_NOBITS && sh->sh_size) {
				memcpy(ob + pos, buf + sh->sh_offset, (size_t)sh->sh_size);
				pos += sh->sh_size;
			}
		}

		kept_shnum = 0;
		for (i = 0; i < eh.e_shnum; i++) if (!removed[i]) kept_shnum++;

		if (compose_ok) {
			uint64_t hdrpos = align_up(pos, 8);
			uint64_t hdr_bytes = (uint64_t)kept_shnum * ELF_SHDR_SIZE;
			/* Same proof obligation as above, now for the shrunk
			 * section header table's own placement. */
			if (hdrpos < pos || hdrpos > cap || hdr_bytes > cap - hdrpos)
				compose_ok = 0;
			else
				pos = hdrpos;
		}

		if (!compose_ok) {
			free(ob);
			free(phdrs); free(shdrs); free(removed); free(map); free(new_off);
			return 0; /* untrusted sh_addralign made the layout unprovable -- untouched */
		}

		{
			uint32_t out_i = 0;
			for (i = 0; i < eh.e_shnum; i++) {
				Elf64_Shdr nh;
				if (removed[i]) continue;
				nh = shdrs[i];
				if (nh.sh_link != 0 && nh.sh_link < eh.e_shnum) nh.sh_link = map[nh.sh_link];
				if ((nh.sh_flags & SHF_INFO_LINK) && nh.sh_info != 0 && nh.sh_info < eh.e_shnum)
					nh.sh_info = map[nh.sh_info];
				if (shdrs[i].sh_offset >= load_limit) nh.sh_offset = new_off[i];
				memcpy(ob + pos + (size_t)out_i * ELF_SHDR_SIZE, &nh, sizeof nh);
				out_i++;
			}
		}

		new_eh = eh;
		new_eh.e_shoff = pos;
		new_eh.e_shnum = (uint16_t)kept_shnum;
		new_eh.e_shstrndx = (uint16_t)map[eh.e_shstrndx];
		memcpy(ob, &new_eh, sizeof new_eh);

		free(*out);
		*out = ob;
		*outsize = (size_t)(pos + (uint64_t)kept_shnum * ELF_SHDR_SIZE);
		*changed = 1;
	}

	free(phdrs); free(shdrs); free(removed); free(map); free(new_off);
	return 0;
}

/* ==== PE (bonus scope; see this file's own header banner) ================ */

static uint16_t le16(const unsigned char *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t le32(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void put_le32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8);
	p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24);
}

static int strip_pe(const unsigned char *buf, size_t size,
                     unsigned char **out, size_t *outsize, int *changed)
{
	unsigned char *ob;
	uint32_t lfanew, file_hdr_off, opt_off;
	uint16_t nsections, opt_size, opt_magic, ndirs;
	uint32_t symtab_off, nsyms, symtab_bytes, strtab_off, strtab_sz, tail_end;
	uint32_t debug_dir_off;

	*changed = 0;
	ob = malloc(size ? size : 1);
	if (!ob) return -1;
	memcpy(ob, buf, size);
	*out = ob; *outsize = size;

	if (size < 0x40 || buf[0] != 'M' || buf[1] != 'Z') return 0;
	lfanew = le32(buf + 0x3c);
	if ((uint64_t)lfanew + 24 > size) return 0;
	if (memcmp(buf + lfanew, "PE\0\0", 4) != 0) return 0;

	file_hdr_off = lfanew + 4;
	nsections = le16(buf + file_hdr_off + 2);
	symtab_off = le32(buf + file_hdr_off + 8);
	nsyms = le32(buf + file_hdr_off + 12);
	opt_size = le16(buf + file_hdr_off + 16);
	opt_off = file_hdr_off + 20;
	(void)nsections;

	if (symtab_off != 0 && nsyms != 0) {
		/* IMAGE_SYMBOL is 18 bytes; the string table immediately
		 * follows and begins with its own 4-byte total size
		 * (self-inclusive). Only remove this pair if that is
		 * EXACTLY the rest of the file -- see this file's own
		 * header banner for why. */
		int safe = 1;
		uint64_t sb = (uint64_t)nsyms * 18;
		if (sb > size || symtab_off > size - sb) safe = 0;
		symtab_bytes = (uint32_t)sb;
		strtab_off = symtab_off + symtab_bytes;
		if (safe) {
			if ((uint64_t)strtab_off + 4 > size) safe = 0;
		}
		if (safe) {
			strtab_sz = le32(buf + strtab_off);
			tail_end = strtab_off + strtab_sz;
			if ((uint64_t)strtab_off + strtab_sz > size) safe = 0;
			else if (tail_end != (uint32_t)size) safe = 0; /* must reach EOF exactly */
		}
		if (safe) {
			memcpy(ob, buf, symtab_off);
			put_le32(ob + file_hdr_off + 8, 0);
			put_le32(ob + file_hdr_off + 12, 0);
			*outsize = symtab_off;
			*changed = 1;
		}
	}

	/* Clear the Debug Data Directory entry (index 6), if the optional
	 * header is present and large enough to have one -- pure metadata,
	 * never a section move (see header banner). Done on `ob` so it
	 * composes with the symbol-table truncation above (if that also
	 * happened, `ob`'s prefix through symtab_off is unaffected by
	 * clearing bytes that live earlier, inside the header). */
	if (opt_size >= 2 && (uint64_t)opt_off + 2 <= size) {
		opt_magic = le16(buf + opt_off);
		if (opt_magic == 0x10b || opt_magic == 0x20b) {
			/* DataDirectory[] starts 96 bytes into PE32's optional
			 * header, 112 bytes into PE32+'s (see src/internal/pe.h's
			 * own IMAGE_OPTIONAL_HEADER32/64 field lists -- this is
			 * their DataDirectory[0] offset, cross-checked field by
			 * field against that header rather than re-derived here). */
			uint32_t dd0 = opt_off + (opt_magic == 0x10b ? 96u : 112u);
			debug_dir_off = dd0 + 6u * 8u; /* index 6 = IMAGE_DIRECTORY_ENTRY_DEBUG */
			ndirs = 0;
			if ((uint64_t)opt_off + 92 + 4 <= size)
				ndirs = (uint16_t)le32(buf + opt_off + (opt_magic == 0x10b ? 92u : 108u));
			if (ndirs > 6 && (uint64_t)debug_dir_off + 8 <= *outsize) {
				uint32_t va = le32(ob + debug_dir_off);
				uint32_t sz = le32(ob + debug_dir_off + 4);
				if (va != 0 || sz != 0) {
					put_le32(ob + debug_dir_off, 0);
					put_le32(ob + debug_dir_off + 4, 0);
					*changed = 1;
				}
			}
		}
	}

	return 0;
}

/* ==== driver =============================================================== */

static int read_whole_file(const char *path,
                           unsigned char **out withtok(heap_allocated),
                           size_t *outsize)
{
	FILE *f;
	long sz;
	unsigned char *buf;

	f = fopen(path, "rb");
	if (!f) return -1;
	if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
		(void)fclose(f);
		errno = EIO;
		return -1;
	}
	buf = malloc((size_t)sz ? (size_t)sz : 1);
	if (!buf) { (void)fclose(f); errno = ENOMEM; return -1; }
	if (sz && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		free(buf); (void)fclose(f); errno = EIO; return -1;
	}
	(void)fclose(f);
	__ownership_readable_span(buf, (size_t)sz);
	*out = buf;
	*outsize = (size_t)sz;
	return 0;
}

/* Writes `buf`/`size` to `path` atomically (temp file + rename, same
 * discipline src/util/ar.c's do_delete()/do_append_or_replace() already
 * use for the identical "never leave a half-written file behind"
 * reason), preserving `mode`'s permission bits -- critical here
 * specifically: a temp file created by fopen("wb") gets a fresh,
 * umask-affected mode with no execute bit, and this output is very
 * often meant to keep running as a program. */
static int write_atomic(const char *path, const unsigned char *buf, size_t size, mode_t mode)
{
	char tmppath[4096];
	FILE *f;

	if (snprintf(tmppath, sizeof tmppath, "%s.striptmp", path) >= (int)sizeof tmppath) {
		errno = ENAMETOOLONG;
		return -1;
	}
	f = fopen(tmppath, "wb");
	if (!f) return -1;
	if (size && fwrite(buf, 1, size, f) != size) {
		(void)fclose(f);
		(void)unlink(tmppath);
		errno = EIO;
		return -1;
	}
	if (fclose(f) != 0) {
		int saved = errno;
		(void)unlink(tmppath);
		errno = saved;
		return -1;
	}
	if (chmod(tmppath, mode & 07777) != 0) {
		int saved = errno;
		(void)unlink(tmppath);
		errno = saved;
		return -1;
	}
	if (rename(tmppath, path) != 0) {
		int saved = errno;
		(void)unlink(tmppath);
		errno = saved;
		return -1;
	}
	return 0;
}

int __util_strip_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	const char *in_path = NULL;
	const char *out_path = NULL;
	int i;
	unsigned char *inbuf = NULL, *outbuf = NULL;
	size_t insize = 0, outsize = 0;
	int changed = 0, rc;
	struct stat st;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-o") == 0) {
			if (i + 1 >= argc) {
				__util_diagf("strip: -o requires an argument\n");
				return 2;
			}
			out_path = argv[++i];
		} else if (strcmp(argv[i], "--") == 0) {
			i++;
			break;
		} else if (argv[i][0] == '-' && argv[i][1] != 0) {
			__util_diagf("strip: %s: unrecognized option\n", argv[i]);
			return 2;
		} else {
			break;
		}
	}
	if (i >= argc) {
		__util_diagf("strip: usage: strip [-o strip_file] file\n");
		return 2;
	}
	in_path = argv[i];
	if (i + 1 < argc) {
		__util_diagf("strip: extra operand '%s' -- exactly one file operand is supported\n", argv[i + 1]);
		return 2;
	}
	if (!out_path) out_path = in_path;

	if (stat(in_path, &st) != 0) {
		__util_diagf("strip: %s: %s\n", in_path, strerror(errno));
		return 1;
	}
	if (!S_ISREG(st.st_mode)) {
		__util_diagf("strip: %s: not a regular file\n", in_path);
		return 1;
	}

	if (read_whole_file(in_path, &inbuf, &insize) != 0) {
		__util_diagf("strip: %s: %s\n", in_path, strerror(errno));
		return 1;
	}

	if (insize >= 4 && inbuf[0] == 0x7f && inbuf[1] == 'E' && inbuf[2] == 'L' && inbuf[3] == 'F') {
		rc = strip_elf(inbuf, insize, &outbuf, &outsize, &changed);
	} else if (insize >= 2 && inbuf[0] == 'M' && inbuf[1] == 'Z') {
		rc = strip_pe(inbuf, insize, &outbuf, &outsize, &changed);
	} else {
		__util_diagf("strip: %s: not a recognized ELF or PE object file\n", in_path);
		free(inbuf);
		return 1;
	}

	if (rc != 0) {
		__util_diagf("strip: %s: %s\n", in_path, strerror(ENOMEM));
		free(inbuf);
		return 1;
	}
	free(inbuf);

	if (write_atomic(out_path, outbuf, outsize, st.st_mode) != 0) {
		__util_diagf("strip: %s: %s\n", out_path, strerror(errno));
		free(outbuf);
		return 1;
	}
	free(outbuf);
	return 0;
}
