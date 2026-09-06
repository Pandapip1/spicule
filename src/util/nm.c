/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * nm(1p): `nm [-g] [-p] [-u] [-v] [file...]`
 * Spec: https://pubs.opengroup.org/onlinepubs/9699919799/utilities/nm.html
 *
 * Scope: ELF64 (aarch64/x86_64) object files only, matching this build's
 * native-Linux target (src/dlfcn/linux/plat_dlfcn.c). PE is not attempted:
 * this project's PE parsing (src/internal/pe.c/pe.h) walks a *mapped
 * executable image's* export directory, a different on-disk structure
 * from a COFF *object file's* symbol table. A file not starting "\x7fELF"
 * is reported as unrecognized, never guessed at as PE. This project ships
 * no <elf.h>; this file keeps its own local Ehdr/Shdr/Sym copy,
 * cross-checked field-for-field against plat_dlfcn.c's.
 *
 * Archives: POSIX requires processing each object file inside an archive
 * operand. Walking this project's own ar(1p) "!<arch>\n" format to run
 * this file's ELF reader over each member is deferred out of this first
 * pass -- an archive operand is refused loudly rather than misread as a
 * malformed ELF file.
 *
 * Options implemented:
 *  -g  Only external (global/weak) symbols, i.e. bind != LOCAL.
 *  -u  Only undefined symbols (st_shndx == SHN_UNDEF).
 *  -p  Print in the object's own symbol-table order, not alphabetical.
 *  -v  Sort by symbol value (address) instead of by name.
 *
 * Not implemented, refused loudly: -A/-o (pathname prefix, only useful
 * once archive-member iteration exists), -f (this file's only format is
 * already the full one), -P (portable output format), -C/-r (demangling,
 * reverse sort -- cosmetic, GNU-only or not in the POSIX synopsis).
 *
 * Output: one symbol per line as `<value> <type> <name>`. <value> is 16
 * lowercase hex digits, zero-filled, or 16 spaces for an undefined
 * symbol. <type> is a single letter, uppercase for global/weak, lowercase
 * for local: 'A' absolute, 'B'/'b' bss, 'C' common, 'D'/'d' initialized
 * data, 'N' non-loaded (e.g. debug) section, 'R'/'r' read-only data,
 * 'T'/'t' text, 'U' undefined (always uppercase), 'W'/'w' weak, 'I'/'i'
 * GNU indirect function (STT_GNU_IFUNC -- an ABI extension both
 * aarch64/x86_64 toolchains emit, classified distinctly to match what a
 * real nm reports).
 *
 * Omitted by default: a symbol with no name, STT_FILE entries, and
 * AArch64/ARM mapping symbols ($x/$d/$a/$t, see is_mapping_symbol()
 * below) -- matching every real nm this project interoperates with.
 *
 * The default alphabetical sort is a plain byte-wise strcmp() on the raw
 * UTF-8 name, not locale-collated -- consistent with this project's own
 * "UTF-8 is the only encoding this library has ever supported" position
 * (src/util/wc.c).
 *
 * No file operand defaults to `a.out`. Exit status: diagnose-and-continue
 * across multiple file operands -- one bad operand doesn't stop the
 * rest, and the final exit status is nonzero if any failed.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "util.h"
#include "ownership_stubs.h"

/* Local ELF64 shapes -- see this file's header. Field widths/order are
 * ELFCLASS64's, architecture-independent. */
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
	uint32_t sh_name, sh_type;
	uint64_t sh_flags, sh_addr, sh_offset, sh_size;
	uint32_t sh_link, sh_info;
	uint64_t sh_addralign, sh_entsize;
} Elf64_Shdr;

typedef struct {
	uint32_t st_name;
	unsigned char st_info, st_other;
	uint16_t st_shndx;
	uint64_t st_value, st_size;
} Elf64_Sym;

#define EI_CLASS 4
#define EI_DATA  5
#define ELFCLASS64 2
#define ELFDATA2LSB 1

#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_NOBITS 8
#define SHT_DYNSYM 11

#define SHF_WRITE     0x1u
#define SHF_ALLOC     0x2u
#define SHF_EXECINSTR 0x4u

#define SHN_UNDEF  0
#define SHN_ABS    0xfff1u
#define SHN_COMMON 0xfff2u

#define ELF64_ST_BIND(info) ((unsigned)(info) >> 4)
#define ELF64_ST_TYPE(info) ((unsigned)(info) & 0xfu)

#define STB_LOCAL  0
#define STB_GLOBAL 1
#define STB_WEAK   2

#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_SECTION 3
#define STT_FILE    4
#define STT_COMMON  5
#define STT_GNU_IFUNC 10

/* AArch64 (and ARM) ELF object files carry "mapping symbols" -- local,
 * STT_NOTYPE entries named "$x"/"$d"/"$a"/"$t" (optionally followed by
 * ".<disambiguator>"), inserted by the assembler at every code/data
 * boundary (AAELF64 SS4.5.4). Every real nm hides them by default
 * (confirmed against `nix shell nixpkgs#binutils -c nm`: readelf -s
 * shows them, real nm does not). */
static int is_mapping_symbol(const char *name)
{
	if (name[0] != '$') return 0;
	if (name[1] != 'a' && name[1] != 'd' && name[1] != 't' && name[1] != 'x') return 0;
	return name[2] == 0 || name[2] == '.';
}

/* ==== one filtered/classified symbol, ready to print ===================== */

struct nm_sym {
	const char *name;
	uint64_t value;
	char type; /* already-cased type letter, see sym_type_letter() */
};

/* Classifies one symbol table entry per this file's header comment
 * ("Output" section). `shdrs`/`shnum` are the object's own section
 * header table, needed to classify a defined symbol by the section it
 * lives in. */
static char sym_type_letter(const Elf64_Sym *s, const Elf64_Shdr *shdrs, uint16_t shnum)
{
	unsigned bind = ELF64_ST_BIND(s->st_info);
	unsigned type = ELF64_ST_TYPE(s->st_info);
	char c;

	if (s->st_shndx == SHN_UNDEF) {
		c = 'U';
	} else if (s->st_shndx == SHN_ABS) {
		c = 'A';
	} else if (s->st_shndx == SHN_COMMON || type == STT_COMMON) {
		c = 'C';
	} else if (s->st_shndx < shnum) {
		const Elf64_Shdr *sh = &shdrs[s->st_shndx];
		if (sh->sh_type == SHT_NOBITS) c = 'B';
		else if (!(sh->sh_flags & SHF_ALLOC)) c = 'N';
		else if (sh->sh_flags & SHF_EXECINSTR) c = 'T';
		else if (sh->sh_flags & SHF_WRITE) c = 'D';
		else c = 'R';
	} else {
		c = '?'; /* out-of-range section index: corrupt, but reported, not crashed on */
	}

	if (type == STT_GNU_IFUNC) c = 'I';

	if (bind == STB_WEAK) {
		if (c == 'U') return 'w';
		return (type == STT_OBJECT) ? 'V' : 'W';
	}
	if (bind == STB_LOCAL && c != 'U') c = (char)tolower((unsigned char)c);
	return c;
}

/* ==== sort comparators ===================================================== */

static int cmp_by_name(const void *a, const void *b)
{
	const struct nm_sym *sa = a, *sb = b;
	return strcmp(sa->name, sb->name);
}

/* An undefined symbol's "value" is meaningless (printed as blank spaces,
 * not a real address), so -v's value sort treats "undefined" as its own
 * leading group rather than numerically tying it to whatever defined
 * symbol happens to also sit at address 0 -- confirmed against a real
 * `nm -v`, which puts every U symbol first regardless. */
static int cmp_by_value(const void *a, const void *b)
{
	const struct nm_sym *sa = a, *sb = b;
	int ua = sa->type == 'U' || sa->type == 'w';
	int ub = sb->type == 'U' || sb->type == 'w';
	if (ua != ub) return ua ? -1 : 1;
	if (sa->value < sb->value) return -1;
	if (sa->value > sb->value) return 1;
	return strcmp(sa->name, sb->name);
}

/* ==== reading one ELF64 object's symbol table into memory ================= */

/* Reads all of `fd` (already positioned at offset 0) into a freshly
 * malloc'd buffer of exactly its size. Returns the buffer (and sets
 * *out_size) on success, or NULL (errno set, no diagnostic printed --
 * the caller has the pathname for that) on a read/stat/allocation
 * failure. */
static unsigned char *read_whole_file(int fd, size_t *out_size)
{
	struct stat st;
	unsigned char *buf;
	size_t got = 0;

	if (fstat(fd, &st) < 0) return NULL;
	if (st.st_size < 0) { errno = EOVERFLOW; return NULL; }
	*out_size = (size_t)st.st_size;

	buf = malloc(*out_size ? *out_size : 1);
	if (!buf) return NULL;

	while (got < *out_size) {
		ssize_t n = read(fd, buf + got, *out_size - got);
		if (n < 0) {
			if (errno == EINTR) continue;
			free(buf);
			return NULL;
		}
		if (n == 0) break; /* file shrank/EOF early: treat as its real length */
		got += (size_t)n;
	}
	*out_size = got;
	__ownership_readable_span(buf, got);
	return buf;
}

/* Bounds-checks and locates the symbol table (SHT_SYMTAB, falling back
 * to SHT_DYNSYM if no SHT_SYMTAB section exists -- a stripped or
 * shared-object-shaped file may only have the latter) and its linked
 * string table within an already-validated ELF64 buffer. Returns 1 and
 * fills *symtab, *nsyms, *strtab, *strtab_size on success, or 0 (no
 * diagnostic -- the caller distinguishes "no symbols" from "corrupt"
 * for its own message) if neither section exists or either is
 * malformed. */
static int find_symtab(const unsigned char *buf, size_t size, const Elf64_Ehdr *eh,
                        const Elf64_Shdr *shdrs,
                        const Elf64_Shdr **symtab, size_t *nsyms,
                        const char **strtab, size_t *strtab_size)
{
	uint16_t i;
	int best = -1;

	for (i = 0; i < eh->e_shnum; i++) {
		if (shdrs[i].sh_type == SHT_SYMTAB) { best = i; break; }
		if (shdrs[i].sh_type == SHT_DYNSYM && best < 0) best = i;
	}
	if (best < 0) return 0;

	{
		const Elf64_Shdr *sy = &shdrs[best];
		const Elf64_Shdr *st;
		if (sy->sh_link >= eh->e_shnum) return 0;
		st = &shdrs[sy->sh_link];

		if (sy->sh_entsize != sizeof(Elf64_Sym)) return 0;
		if (sy->sh_offset > size || sy->sh_size > size - sy->sh_offset) return 0;
		if (st->sh_offset > size || st->sh_size > size - st->sh_offset) return 0;

		*symtab = sy;
		*nsyms = sy->sh_size / sizeof(Elf64_Sym);
		*strtab = (const char *)(buf + st->sh_offset);
		*strtab_size = st->sh_size;
	}
	return 1;
}

/* Returns a pointer to the NUL-terminated name at string-table offset
 * `off`, or NULL if `off` is out of range or the string is not
 * terminated before the table's own end (a corrupt/foreign file, not a
 * crash). */
static const char *strtab_name(const char *strtab, size_t strtab_size, uint32_t off)
{
	size_t i;
	if (off >= strtab_size) return NULL;
	for (i = off; i < strtab_size; i++)
		if (strtab[i] == 0) return strtab + off;
	return NULL;
}

/* ==== one file operand ====================================================== */

static int process_file(const char *path, int opt_g, int opt_u, int opt_p, int opt_v) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int fd;
	unsigned char *buf;
	size_t size;
	const Elf64_Ehdr *eh;
	const Elf64_Shdr *shdrs;
	const Elf64_Shdr *symtab;
	size_t nsyms, strtab_size, i;
	const char *strtab;
	struct nm_sym *out;
	size_t nout = 0;
	int rc = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		__util_diagf("nm: %s: %s\n", path, strerror(errno));
		return 1;
	}

	buf = read_whole_file(fd, &size);
	{
		/* close() on a freshly-read fd is cleanup, not the operation
		 * being diagnosed; if it fails, its own errno must not
		 * overwrite read_whole_file()'s already-set failure reason. */
		int saved_errno = errno;
		(void)close(fd);
		errno = saved_errno;
	}
	if (!buf) {
		__util_diagf("nm: %s: %s\n", path, strerror(errno));
		return 1;
	}

	if (size >= 8 && memcmp(buf, "!<arch>\n", 8) == 0) {
		__util_diagf("nm: %s: archive member listing is not implemented by this "
		                "build (see src/util/nm.c's own header comment)\n", path);
		free(buf);
		return 1;
	}

	if (size < sizeof(Elf64_Ehdr) || memcmp(buf, "\x7f" "ELF", 4) != 0) {
		__util_diagf("nm: %s: file format not recognized (not an ELF64 object)\n", path);
		free(buf);
		return 1;
	}
	eh = (const Elf64_Ehdr *)buf;
	if (eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_ident[EI_DATA] != ELFDATA2LSB) {
		__util_diagf("nm: %s: unsupported ELF class/byte order (this build reads "
		                "ELF64 little-endian only)\n", path);
		free(buf);
		return 1;
	}
	if (eh->e_shentsize != sizeof(Elf64_Shdr) || eh->e_shnum == 0) {
		__util_diagf("nm: %s: no section headers (nothing to read symbols from)\n", path);
		free(buf);
		return 1;
	}
	if (eh->e_shoff > size || (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) > size - eh->e_shoff) {
		__util_diagf("nm: %s: corrupt section header table\n", path);
		free(buf);
		return 1;
	}
	shdrs = (const Elf64_Shdr *)(buf + eh->e_shoff);
	__ownership_readable_span(shdrs, (size_t)eh->e_shnum * sizeof(Elf64_Shdr));

	if (!find_symtab(buf, size, eh, shdrs, &symtab, &nsyms, &strtab, &strtab_size)) {
		__util_diagf("nm: %s: no symbols\n", path);
		free(buf);
		return 1;
	}

	out = __util_mallocarray(nsyms ? nsyms : 1, sizeof *out);
	if (!out) {
		__util_diagf("nm: %s: %s\n", path, strerror(ENOMEM));
		free(buf);
		return 1;
	}

	{
		const Elf64_Sym *syms = (const Elf64_Sym *)(buf + symtab->sh_offset);
		__ownership_readable_span(syms, nsyms * sizeof(Elf64_Sym));

		for (i = 0; i < nsyms; i++) {
			const Elf64_Sym *s = &syms[i];
			const char *name;
			unsigned bind = ELF64_ST_BIND(s->st_info);
			unsigned type = ELF64_ST_TYPE(s->st_info);

			if (type == STT_FILE) continue;
			name = strtab_name(strtab, strtab_size, s->st_name);
			if (!name || !*name) continue;
			if (is_mapping_symbol(name)) continue;

			if (opt_g && bind == STB_LOCAL) continue;
			if (opt_u && s->st_shndx != SHN_UNDEF) continue;

			out[nout].name = name;
			out[nout].value = s->st_value;
			out[nout].type = sym_type_letter(s, shdrs, eh->e_shnum);
			nout++;
		}
	}

	if (!opt_p) qsort(out, nout, sizeof *out, opt_v ? cmp_by_value : cmp_by_name);

	for (i = 0; i < nout; i++) {
		if (out[i].type == 'U' || out[i].type == 'w')
			printf("                 %c %s\n", out[i].type, out[i].name);
		else
			printf("%016llx %c %s\n", (unsigned long long)out[i].value, out[i].type, out[i].name);
	}

	free(out);
	free(buf);
	return rc;
}

int __util_nm_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i;
	int opt_g = 0, opt_u = 0, opt_p = 0, opt_v = 0;
	int had_error = 0;
	int nfiles;

	for (i = 1; i < argc; i++) {
		char *a = argv[i];
		char *p;

		if (a[0] != '-' || a[1] == 0) break;
		if (!strcmp(a, "--")) { i++; break; }
		for (p = a + 1; *p; p++) {
			if (*p == 'g') { opt_g = 1; continue; }
			if (*p == 'u') { opt_u = 1; continue; }
			if (*p == 'p') { opt_p = 1; continue; }
			if (*p == 'v') { opt_v = 1; continue; }
			__util_diagf("nm: invalid option -- '%c'\n", *p);
			return 2;
		}
	}

	nfiles = argc - i;
	if (nfiles <= 0) {
		if (process_file("a.out", opt_g, opt_u, opt_p, opt_v) != 0) had_error = 1;
		return had_error ? 1 : 0;
	}

	for (; i < argc; i++) {
		if (nfiles > 1) printf("\n%s:\n", argv[i]);
		if (process_file(argv[i], opt_g, opt_u, opt_p, opt_v) != 0) had_error = 1;
	}

	return had_error ? 1 : 0;
}

// NOLINTEND(misc-include-cleaner)
