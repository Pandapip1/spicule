/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * pax(1p): the portable archive interchange utility, four modes selected
 * by -r/-w:
 *   (neither)   list mode:  `pax [-cv] [-f archive] [pattern...]`
 *   -r          read mode:  `pax -r [-cdkuv] [-f archive] [pattern...]`
 *   -w          write mode: `pax -w [-dv] [-f archive] [-x format] [file...]`
 *   -r -w       copy mode:  `pax -r -w [-dkuv] [file...] directory`
 *
 * ---- ARCHIVE FORMATS -------------------------------------------------------
 *
 * The spec requires cpio, ustar, and pax (extended-header) format
 * support. This build implements ustar and the "octet-oriented"
 * (ASCII/odc) cpio variant pax(1p) itself names as the supported one,
 * but not pax's own extended-header format (typeflag 'x'/'g' records
 * that carry keyword=value metadata for names/sizes/times too large for
 * ustar's plain fields). That is a deliberate narrowing: this build
 * diagnoses and refuses -- never silently truncates -- any member that
 * would need one (see ustar_split_name() and the fits_octal() checks).
 * `-x pax` is refused the same as any other unimplemented option.
 * Default write-mode output format is ustar; POSIX leaves this
 * implementation-defined.
 *
 * ---- OPTIONS implemented -------------------------------------------------
 *  -r / -w        select read / write / (both) copy mode, as above
 *  -f archive     archive pathname; default stdin (read/list) or
 *                 stdout (write)
 *  -x format      write-mode output format: "ustar" (default) or "cpio"
 *  -v             verbose: file-by-file names to stderr in read/write/
 *                 copy mode, or a long ls -l-style listing in list mode
 *  -d             match only the file itself for a directory named on
 *                 the command line (not recursed into); no archive-side
 *                 meaning in read/list mode, so accepted but only
 *                 meaningful for -w/-r -w
 *  -k             prevent overwriting existing files (read/copy mode)
 *  -u             skip restoring a member whose mtime is <= the
 *                 existing file's mtime (read/copy mode)
 *  -c             match all files except those matching pattern
 *                 operands (list/read mode)
 *
 * ---- NOT IMPLEMENTED, refused loudly (this project's standing
 * convention for an unimplemented option, e.g. src/util/cp.c's own
 * -p/-i/-H/-L/-P refusals) -----------------------------------------------
 *  -a, -b, -B     append to an existing archive; block/byte-count
 *                 limiting -- write mode always creates/truncates
 *  -i, -n         interactive rename; first-match-only pattern selection
 *  -l             hard-link (rather than copy) in copy mode
 *  -H, -L         symlink-following control -- this build always
 *                 behaves as if neither is given (symlinks archived/
 *                 copied as themselves), a valid but not adjustable
 *                 pax(1p) mode
 *  -o, -G, -U     pax-format keyword options, group/user restore -- tied
 *                 to formats/knobs this build does not implement
 *  -p string      file-characteristic preservation control -- see
 *                 MATERIALIZATION below for this build's fixed policy
 *  -s replstr     ed(1)-style name substitution
 *  -t             restore each read file's access time after reading
 *  -T, -Y, -Z     time-window/ctime-window member selection
 *  -X             stay-on-one-filesystem tree traversal restriction
 *
 * ---- MATERIALIZATION (read/copy mode): this build's fixed policy
 * standing in for -p's sub-options -------------------------------------
 *
 * Mode bits are passed through exactly as archived to open()/mkdir()/
 * mkfifo()/mknod() (umask applies normally -- the default, non-"-p p"
 * behaviour). Modification time IS restored via utime() after writing a
 * regular file's data (the default, non-"-p m" behaviour). Ownership
 * (uid/gid) is never touched: this platform has no real multi-user
 * ownership model (every stat() reports a fixed uid/gid; see
 * src/util/cp.c), so there is nothing "-p o" could preserve.
 *
 * ---- A safety addition beyond POSIX's literal text ------------------------
 *
 * On extract, a member pathname is refused (diagnostic, member skipped,
 * nonzero exit, other members continue) if it is absolute (either '/' or
 * '\\'-rooted, or drive-letter-rooted, e.g. "C:\\...") or contains a ".."
 * component (again on either separator). POSIX does not require this,
 * but silently honoring any of those would let a hostile or corrupt
 * archive write outside the extraction directory -- the same class of
 * refusal cp.c's symlink-in-tree guard and rm.c's own guards already
 * make. Both separators are checked unconditionally, not just when
 * building for NT, since a well-formed ustar/cpio name this file's own
 * writer produces never contains a backslash or drive letter in the
 * first place; see name_is_safe()'s own comment for why the NT target
 * specifically is what makes the backslash/drive-letter half of this
 * matter. A hardlink member's linkname gets the identical check (see
 * do_list_or_read()): unlike a symlink's target text, it is fed straight
 * to link() as the source to link *from*, so it is just as much a
 * traversal vector as the member's own name. A symlink member's target
 * text is deliberately left unrestricted (a real symlink pointing
 * anywhere is legitimate archive content), but ensure_parent_dirs()
 * refuses to walk *through* an already-extracted symlink sitting at an
 * intermediate path component of a later member, closing the other
 * direction of that same attack.
 *
 * ---- Hard links ------------------------------------------------------------
 *
 * This build never detects that two source files share an inode while
 * walking -w/-r -w operands (no dev/ino tracking), so every archived/
 * copied file is written as an independent full copy, regardless of its
 * real st_nlink. On the read side, an already-hard-link-encoded ustar
 * member (typeflag '1', with a linkname) is honored via link() against
 * its already-extracted linkname (subject to the same traversal check as
 * any other member's name -- see immediately above). cpio's own
 * hard-link convention (a repeated member sharing an earlier entry's
 * device/inode, with zero bytes of its own data) is not implemented
 * either direction; such a cpio archive round-trips as independent
 * copies instead -- legal, if link-count-losing.
 *
 * ---- FIFOs and device special files ----------------------------------------
 *
 * This tree's mkfifo()/mknod() (src/stat/chmod.c) are real ENOSYS/EPERM
 * stubs (NT has no backing for either; see src/util/mkfifo.c), so
 * extracting a fifo/char/block member reports the same real failure
 * every other utility does. On the write/copy-mode source-walking side,
 * a FIFO/char/block/socket file found while walking a tree is refused
 * with a diagnostic and skipped, matching src/util/cp.c's own -R policy.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <utime.h>
#include <fnmatch.h>
#include <ftw.h>
#include <sys/stat.h>
#include "ownership_stubs.h"
#include "util.h"

#define PAX_PATH_MAX 4096
#define USTAR_BLOCK 512

enum pax_type { PAX_REG, PAX_DIR, PAX_SYMLINK, PAX_HARDLINK, PAX_FIFO, PAX_CHR, PAX_BLK };
enum pax_format { PAX_FMT_USTAR, PAX_FMT_CPIO };

struct pax_member {
	char name[PAX_PATH_MAX];
	char linkname[PAX_PATH_MAX];
	unsigned long mode;
	unsigned long mtime;
	unsigned long size;
	enum pax_type type;
};

/* ==== small numeric helpers ============================================= */

/* True if `value` fits in `ndigits` octal digits (no sign, no NUL --
 * this is a pure magnitude check used before every fixed-width octal
 * field this file writes). */
static int fits_octal(unsigned long value, int ndigits __arith_range(1, 11))
{
	if (ndigits >= (int)(sizeof(unsigned long) * 8 / 3 + 1)) return 1;
	return value < (1UL << (3 * ndigits));
}

static unsigned long parse_octal_field(const char *field, size_t width)
{
	char buf[24];
	size_t n = width < sizeof buf - 1 ? width : sizeof buf - 1;
	memcpy(buf, field, n);
	buf[n] = 0;
	return strtoul(buf, NULL, 8);
}

/* ==== ustar codec ========================================================= */

static char pax_type_to_ustar_flag(enum pax_type t)
{
	switch (t) {
	case PAX_HARDLINK: return '1';
	case PAX_SYMLINK: return '2';
	case PAX_CHR: return '3';
	case PAX_BLK: return '4';
	case PAX_DIR: return '5';
	case PAX_FIFO: return '6';
	case PAX_REG: default: return '0';
	}
}

static enum pax_type ustar_flag_to_pax_type(char f)
{
	switch (f) {
	case '1': return PAX_HARDLINK;
	case '2': return PAX_SYMLINK;
	case '3': return PAX_CHR;
	case '4': return PAX_BLK;
	case '5': return PAX_DIR;
	case '6': return PAX_FIFO;
	case '0': case '7': case 0: default: return PAX_REG;
	}
}

/* Splits `path` into ustar's separate 155-byte prefix + 100-byte name
 * fields, choosing the rightmost '/' that lets both halves fit --
 * "no split works" (path over 255 bytes total, or no '/' in the right
 * place) is reported to the caller as -1, which write_ustar_header()
 * turns into the loud, documented refusal this file's header
 * describes rather than an extended-header fallback. */
static int ustar_split_name(const char *restrict path withtok(null_terminated),
	char *restrict prefix withtok(writable_span(prefixcap)), size_t prefixcap,
	char *restrict name withtok(writable_span(namecap)), size_t namecap)
	__attribute__((nonnull(1, 2, 4)));
static int ustar_split_name(const char *restrict path withtok(null_terminated),
	char *restrict prefix withtok(writable_span(prefixcap)), size_t prefixcap,
	char *restrict name withtok(writable_span(namecap)), size_t namecap)
{
	size_t len = strlen(path);
	size_t i;

	if (prefixcap == 0 || namecap == 0 || len == 0 ||
	    len > (namecap - 1) + (prefixcap - 1)) return -1;
	if (len < namecap) { strcpy(name, path); prefix[0] = 0; return 0; }

	for (i = len; i > 0; i--) {
		if (path[i - 1] != '/') continue;
		{
			size_t plen = i - 1;
			size_t nlen = len - i;
			if (plen < prefixcap && nlen > 0 && nlen < namecap) {
				memcpy(prefix, path, plen); prefix[plen] = 0;
				__ownership_readable_span(path + i, nlen);
				memcpy(name, path + i, nlen); name[nlen] = 0;
				return 0;
			}
		}
	}
	return -1;
}

__attribute__((nonnull(1)))
static void ustar_put_oct(unsigned char *field, int width, unsigned long value)
{
	char tmp[24];
	snprintf(tmp, sizeof tmp, "%0*lo", width - 1, value);
	__ownership_writable_span(field, (size_t)(width - 1));
	__ownership_readable_span(tmp, (size_t)(width - 1));
	{
		size_t i;
		for (i = 0; i < (size_t)(width - 1); i++) field[i] = tmp[i];
	}
	field[width - 1] = 0;
}

/* Writes one 512-byte ustar header for `m` to `out`. Returns 0, or -1
 * (diagnostic already printed) if the name doesn't fit or a numeric
 * field overflows its width -- see this file's header on why neither
 * case falls back to an extended header. */
__attribute__((nonnull(2)))
static int write_ustar_header(FILE *out, const struct pax_member *m)
{
	unsigned char block[USTAR_BLOCK];
	char prefix[156], name[101];
	char namebuf[PAX_PATH_MAX];
	const char *use_name = m->name;
	unsigned long sum;
	size_t i;

	/* m->name is a struct field, so null_terminated can't attach directly;
	 * every populator (parse_ustar_block(), read_cpio_header(),
	 * build_member_from_stat(), write_cpio_trailer()) NUL-terminates it
	 * via snprintf()/strcpy(). */
	__ownership_string_terminated(m->name);
	if (m->type == PAX_DIR) {
		size_t l = strlen(m->name);
		if (l == 0 || m->name[l - 1] != '/') {
			snprintf(namebuf, sizeof namebuf, "%s/", m->name);
			/* snprintf() isn't itself annotated to grant null_terminated,
			 * but it always NUL-terminates a nonzero-size buffer. */
			__ownership_string_terminated(namebuf);
			use_name = namebuf;
		}
	}
	if (ustar_split_name(use_name, prefix, sizeof prefix,
	    name, sizeof name) < 0) {
		__util_diagf("pax: %s: pathname too long for ustar format -- this build "
		                "does not implement pax extended-header long names "
		                "(see src/util/pax.c's header)\n", use_name);
		return -1;
	}
	/* ustar_split_name() always NUL-terminates both out-parameters on a
	 * 0 return; writable_span() only proves extent, not termination. */
	__ownership_string_terminated(prefix);
	__ownership_string_terminated(name);
	if (!fits_octal(m->mode & 07777, 7)) {
		__util_diagf("pax: %s: mode does not fit a ustar header\n", use_name);
		return -1;
	}
	if (!fits_octal(m->mtime, 11)) {
		__util_diagf("pax: %s: modification time too large for ustar format "
		                "(this build refuses rather than silently truncating it)\n", use_name);
		return -1;
	}
	if (!fits_octal(m->size, 11)) {
		__util_diagf("pax: %s: file too large for ustar format (>~8GB) -- "
		                "extended headers are not implemented (see this file's header)\n", use_name);
		return -1;
	}

	memset(block, 0, sizeof block);
	{
		size_t name_len = strlen(name);
		for (size_t j = 0; j < name_len; j++) block[j] = name[j];
	}
	ustar_put_oct(block + 100, 8, m->mode & 07777);
	ustar_put_oct(block + 108, 8, 0); /* uid */
	ustar_put_oct(block + 116, 8, 0); /* gid */
	ustar_put_oct(block + 124, 12, m->size);
	ustar_put_oct(block + 136, 12, m->mtime);
	memset(block + 148, ' ', 8);
	block[156] = pax_type_to_ustar_flag(m->type);
	if (m->type == PAX_SYMLINK || m->type == PAX_HARDLINK)
		strncpy((char *)block + 157, m->linkname, 100);
	memcpy(block + 257, "ustar", 6);
	memcpy(block + 263, "00", 2);
	{
		size_t prefix_len = strlen(prefix);
		for (size_t j = 0; j < prefix_len; j++)
			block[345 + j] = prefix[j];
	}

	sum = 0;
	for (i = 0; i < sizeof block; i++) sum += block[i];
	{
		char tmp[8];
		snprintf(tmp, sizeof tmp, "%06lo", sum & 0777777UL);
		memcpy(block + 148, tmp, 6);
		block[154] = 0;
		block[155] = ' ';
	}

	return fwrite(block, 1, sizeof block, out) == sizeof block ? 0 : -1;
}

/* Parses an in-memory 512-byte ustar block already read by the caller
 * (the top-level format-detection reader always has one in hand -- see
 * pax_reader_open() below). `*end` is set to 1 (member fields
 * untouched) if this block is the first of the two zero-filled
 * terminator blocks; this build accepts a single all-zero block as
 * end-of-archive on read (lenient) even though it always writes two. */
static void parse_ustar_block(const unsigned char block[USTAR_BLOCK], struct pax_member *m, int *end)
{
	size_t i;
	char prefix[156], name[101];

	*end = 1;
	for (i = 0; i < USTAR_BLOCK; i++) if (block[i] != 0) { *end = 0; break; }
	if (*end) return;

	memcpy(name, block, 100); name[100] = 0;
	memcpy(prefix, block + 345, 155); prefix[155] = 0;
	if (prefix[0]) snprintf(m->name, sizeof m->name, "%s/%s", prefix, name);
	else snprintf(m->name, sizeof m->name, "%s", name);

	m->mode = parse_octal_field((const char *)block + 100, 8);
	m->size = parse_octal_field((const char *)block + 124, 12);
	m->mtime = parse_octal_field((const char *)block + 136, 12);
	m->type = ustar_flag_to_pax_type((char)block[156]);
	m->linkname[0] = 0;
	if (m->type == PAX_SYMLINK || m->type == PAX_HARDLINK) {
		char ln[101];
		memcpy(ln, block + 157, 100); ln[100] = 0;
		snprintf(m->linkname, sizeof m->linkname, "%s", ln);
	}
	if (m->type != PAX_REG && m->type != PAX_HARDLINK) m->size = 0;
}

/* ==== cpio (octet-oriented / "odc") codec ================================ */

#define CPIO_HDR_LEN 76 /* magic..filesize, before the filename itself */

static enum pax_type mode_to_pax_type(unsigned long mode)
{
	switch (mode & 0170000UL) {
	case 0040000UL: return PAX_DIR;
	case 0120000UL: return PAX_SYMLINK;
	case 0020000UL: return PAX_CHR;
	case 0060000UL: return PAX_BLK;
	case 0010000UL: return PAX_FIFO;
	default: return PAX_REG;
	}
}

static unsigned long pax_type_to_ifmt(enum pax_type t)
{
	switch (t) {
	case PAX_DIR: return 0040000UL;
	case PAX_SYMLINK: return 0120000UL;
	case PAX_CHR: return 0020000UL;
	case PAX_BLK: return 0060000UL;
	case PAX_FIFO: return 0010000UL;
	case PAX_HARDLINK: case PAX_REG: default: return 0100000UL;
	}
}

__attribute__((nonnull(1)))
static int cpio_put_field(char *field, int width __arith_range(6, 11),
	unsigned long value, const char *ctxname, const char *what)
{
	char tmp[24];
	if (!fits_octal(value, width)) {
		__util_diagf("pax: %s: %s too large for cpio format\n", ctxname, what);
		return -1;
	}
	snprintf(tmp, sizeof tmp, "%0*lo", width, value);
	__ownership_writable_span(field, (size_t)width);
	/* width's __arith_range(6, 11) above is proven at every call site by
	 * the arithub lint stage, so this is never negative. */
	for (size_t i = 0; i < (size_t)width; i++) field[i] = tmp[i];
	return 0;
}

/* Writes one cpio (odc) header + filename for `m` to `out`. A symlink's
 * "size" for this format is the length of its target text, and the
 * target text itself is written in place of file data (odc has no
 * separate linkname field -- the target *is* the member's "data"). */
static int write_cpio_header(FILE *out, const struct pax_member *m, unsigned long *out_datasize)
{
	char hdr[CPIO_HDR_LEN];
	size_t namelen = strlen(m->name) + 1; /* cpio's namesize includes the NUL */
	unsigned long datasize = (m->type == PAX_SYMLINK) ? strlen(m->linkname) : m->size;

	memcpy(hdr, "070707", 6);
	if (cpio_put_field(hdr + 6, 6, 0, m->name, "device") < 0) return -1;
	if (cpio_put_field(hdr + 12, 6, 0, m->name, "inode") < 0) return -1;
	if (cpio_put_field(hdr + 18, 6, (pax_type_to_ifmt(m->type) | (m->mode & 07777)), m->name, "mode") < 0) return -1;
	if (cpio_put_field(hdr + 24, 6, 0, m->name, "uid") < 0) return -1;
	if (cpio_put_field(hdr + 30, 6, 0, m->name, "gid") < 0) return -1;
	if (cpio_put_field(hdr + 36, 6, 1, m->name, "nlink") < 0) return -1;
	if (cpio_put_field(hdr + 42, 6, 0, m->name, "rdev") < 0) return -1;
	if (cpio_put_field(hdr + 48, 11, m->mtime, m->name, "mtime") < 0) return -1;
	if (cpio_put_field(hdr + 59, 6, (unsigned long)namelen, m->name, "name length") < 0) return -1;
	if (cpio_put_field(hdr + 65, 11, datasize, m->name, "size") < 0) return -1;

	if (fwrite(hdr, 1, sizeof hdr, out) != sizeof hdr) return -1;
	if (fwrite(m->name, 1, namelen, out) != namelen) return -1;
	*out_datasize = datasize;
	return 0;
}

static int write_cpio_trailer(FILE *out)
{
	struct pax_member m;
	unsigned long ds;
	memset(&m, 0, sizeof m);
	strcpy(m.name, "TRAILER!!!");
	m.type = PAX_REG;
	if (write_cpio_header(out, &m, &ds) < 0) return -1;
	return 0;
}

/* Reads one cpio header (the 6-byte magic already consumed by the
 * caller for detection/format-check purposes) into `m`. `*end` is set
 * if this is the "TRAILER!!!" member. Returns 0 on success, -1 on a
 * malformed header (diagnostic already printed). */
static int read_cpio_header(FILE *in, struct pax_member *m, int *end)
{
	char hdr[CPIO_HDR_LEN - 6];
	unsigned long mode, namesize, filesize;
	char namebuf[PAX_PATH_MAX];

	*end = 0;
	if (fread(hdr, 1, sizeof hdr, in) != sizeof hdr) return -1;
	mode = parse_octal_field(hdr + 12, 6);
	namesize = parse_octal_field(hdr + 53, 6);
	filesize = parse_octal_field(hdr + 59, 11);
	if (namesize == 0 || namesize >= sizeof namebuf) return -1;
	if (fread(namebuf, 1, namesize, in) != namesize) return -1;
	namebuf[namesize - 1] = 0; /* namesize counts the trailing NUL already read */

	if (namesize >= sizeof "TRAILER!!!" &&
	    memcmp(namebuf, "TRAILER!!!", sizeof "TRAILER!!!") == 0) {
		*end = 1;
		return 0;
	}

	snprintf(m->name, sizeof m->name, "%s", namebuf);
	m->mode = mode & 07777;
	m->mtime = parse_octal_field(hdr + 42, 11);
	m->size = filesize;
	m->type = mode_to_pax_type(mode);
	m->linkname[0] = 0;
	if (m->type == PAX_SYMLINK) {
		unsigned long ll = filesize < sizeof m->linkname - 1 ? filesize : sizeof m->linkname - 1;
		if (fread(m->linkname, 1, ll, in) != ll) return -1;
		m->linkname[ll] = 0;
		if (filesize > ll) { /* discard any remainder past our buffer */
			char junk[256];
			unsigned long rem = filesize - ll;
			while (rem) {
				unsigned long want = rem < sizeof junk ? rem : sizeof junk;
				if (fread(junk, 1, want, in) != want) return -1;
				rem -= want;
			}
		}
		m->size = 0;
	}
	return 0;
}

/* ==== archive reader ====================================================== */

struct pax_reader {
	FILE *f;
	enum pax_format fmt;
	/* The very first member's header is unavoidably peeked at during
	 * format detection (see pax_reader_open() below) -- for ustar the
	 * whole 512-byte block is already in hand, and for cpio the
	 * 6-byte magic is already consumed straight from the stream.
	 * Either way, pax_reader_next()'s first call must consume that
	 * already-read data instead of reading fresh bytes; these two
	 * flags/buffer, kept on the reader itself rather than threaded
	 * through every call site, are exactly that "one pending member"
	 * state. */
	int have_first_block;
	unsigned char first_block[USTAR_BLOCK];
	int cpio_first_pending;
};

/* Opens `path` (or stdin if NULL) and detects its format by peeking
 * the first bytes -- see this file's header for why no generic
 * pushback buffer is needed: cpio's magic is exactly 6 bytes, and if
 * it doesn't match, those same 6 bytes are simply the start of what
 * must be (if anything) a ustar header, so the remaining 506 bytes are
 * read to complete that first 512-byte block, which is kept on `r`
 * (see struct pax_reader above) for pax_reader_next()'s first call. */
static int pax_reader_open(struct pax_reader *r, const char *path)
{
	unsigned char magic[6];
	size_t got;

	r->f = path ? fopen(path, "rb") : stdin;
	if (!r->f) {
		__util_diagf("pax: %s: %s\n", path, strerror(errno));
		return -1;
	}
	r->have_first_block = 0;
	r->cpio_first_pending = 0;

	got = fread(magic, 1, 6, r->f);
	if (got == 6 && memcmp(magic, "070707", 6) == 0) {
		r->fmt = PAX_FMT_CPIO;
		r->cpio_first_pending = 1;
		return 0;
	}
	if (got == 0) {
		__util_diagf("pax: %s: empty or unreadable archive\n", path ? path : "(stdin)");
		if (path) fclose(r->f);
		return -1;
	}
	{
		size_t i;
		for (i = 0; i < got; i++) r->first_block[i] = magic[i];
	}
	if (got < USTAR_BLOCK) {
		__ownership_writable_span(r->first_block + got, USTAR_BLOCK - got);
		size_t more = fread(r->first_block + got, 1, USTAR_BLOCK - got, r->f);
		got += more;
	}
	if (got != USTAR_BLOCK || memcmp(r->first_block + 257, "ustar", 5) != 0) {
		__util_diagf("pax: %s: unrecognized archive format (not cpio or ustar)\n", path ? path : "(stdin)");
		if (path) fclose(r->f);
		return -1;
	}
	r->fmt = PAX_FMT_USTAR;
	r->have_first_block = 1;
	return 0;
}

/* Reads the next member's header, transparently consuming the pending
 * first-member state pax_reader_open() left on `r` (see struct
 * pax_reader above) exactly once. Returns 1 on a member, 0 at
 * end-of-archive, -1 on a read/format error (diagnostic already
 * printed). Positions the stream at the start of the member's data on
 * a 1 return. */
static int pax_reader_next(struct pax_reader *r, struct pax_member *m)
{
	if (r->fmt == PAX_FMT_CPIO) {
		int end;
		if (!r->cpio_first_pending) {
			char magic[6];
			if (fread(magic, 1, 6, r->f) != 6) return 0;
			if (memcmp(magic, "070707", 6) != 0) {
				__util_diagf("pax: corrupt cpio archive (bad member magic)\n");
				return -1;
			}
		}
		r->cpio_first_pending = 0;
		if (read_cpio_header(r->f, m, &end) < 0) {
			__util_diagf("pax: corrupt cpio archive (bad member header)\n");
			return -1;
		}
		return end ? 0 : 1;
	} else {
		unsigned char block[USTAR_BLOCK];
		int end;
		if (r->have_first_block) {
			memcpy(block, r->first_block, USTAR_BLOCK);
			r->have_first_block = 0;
		} else {
			if (fread(block, 1, USTAR_BLOCK, r->f) != USTAR_BLOCK) return 0;
		}
		parse_ustar_block(block, m, &end);
		return end ? 0 : 1;
	}
}

/* Copies exactly `m->size` bytes of the current member's data from
 * the archive to `out` (a real fd, e.g. an extracted file), or just
 * discards them if `out < 0`. Consumes ustar's block padding too.
 * Returns 0, or -1 on a short read (diagnostic already printed). */
static int pax_reader_copy_data(struct pax_reader *r, const struct pax_member *m, int out)
{
	unsigned long remain = m->size;
	char buf[65536];

	while (remain) {
		size_t want = remain < sizeof buf ? remain : sizeof buf;
		size_t got = fread(buf, 1, want, r->f);
		if (got != want) {
			__util_diagf("pax: %s: truncated archive member data\n", m->name);
			return -1;
		}
		if (out >= 0) {
			ssize_t w;
			char *p = buf;
			size_t left = got;
			while (left) {
				w = write(out, p, left);
				if (w < 0) { __util_diagf("pax: %s: %s\n", m->name, strerror(errno)); return -1; }
				p += w; left -= (size_t)w;
			}
		}
		remain -= (unsigned long)got;
	}
	if (r->fmt == PAX_FMT_USTAR) {
		unsigned long pad = (USTAR_BLOCK - (m->size % USTAR_BLOCK)) % USTAR_BLOCK;
		if (pad && fseek(r->f, (long)pad, SEEK_CUR) != 0) return -1;
	}
	return 0;
}

/* ==== archive writer ====================================================== */

static int pax_write_data_from_fd(FILE *out, int fd, unsigned long size, enum pax_format fmt)
{
	char buf[65536];
	unsigned long remain = size;
	while (remain) {
		size_t want = remain < sizeof buf ? remain : sizeof buf;
		ssize_t got = read(fd, buf, want);
		if (got <= 0) { if (got < 0) return -1; break; }
		{
			ssize_t i;
			for (i = 0; i < got; i++)
				if (fputc((unsigned char)buf[i], out) == EOF) return -1;
		}
		remain -= (unsigned long)got;
	}
	if (remain) return -1; /* file shrank under us mid-archive */
	if (fmt == PAX_FMT_USTAR) {
		unsigned long pad = (USTAR_BLOCK - (size % USTAR_BLOCK)) % USTAR_BLOCK;
		char zero[USTAR_BLOCK];
		memset(zero, 0, sizeof zero);
		if (pad && fwrite(zero, 1, pad, out) != pad) return -1;
	}
	return 0;
}

/* Writes one archive member: header (+ symlink target for cpio, which
 * has no separate linkname field) and, for a regular file, its data
 * read from `srcfd` (ignored for every other type). Returns 0, or -1
 * on any I/O/format error. */
static int pax_write_member(FILE *out, enum pax_format fmt, const struct pax_member *m, int srcfd, int verbose)
{
	if (verbose) __util_diagf("%s\n", m->name);

	if (fmt == PAX_FMT_USTAR) {
		if (write_ustar_header(out, m) < 0) return -1;
		if (m->type == PAX_REG && m->size)
			return pax_write_data_from_fd(out, srcfd, m->size, fmt);
		return 0;
	} else {
		unsigned long datasize;
		if (write_cpio_header(out, m, &datasize) < 0) return -1;
		if (m->type == PAX_SYMLINK) {
			const char *linkname = m->linkname;
			__ownership_readable_span(linkname, datasize);
			return fwrite(linkname, 1, datasize, out) == datasize ? 0 : -1;
		}
		if (m->type == PAX_REG && datasize)
			return pax_write_data_from_fd(out, srcfd, datasize, fmt);
		return 0;
	}
}

static int pax_write_trailer(FILE *out, enum pax_format fmt)
{
	if (fmt == PAX_FMT_USTAR) {
		unsigned char zero[USTAR_BLOCK * 2];
		memset(zero, 0, sizeof zero);
		return fwrite(zero, 1, sizeof zero, out) == sizeof zero ? 0 : -1;
	}
	return write_cpio_trailer(out);
}

/* ==== pattern matching ==================================================== */

/* pax(1p)'s pattern operands use "the pattern matching notation" (shell
 * glob syntax); a pattern containing no glob metacharacter additionally
 * matches as a directory-prefix of a member name (e.g. pattern "usr"
 * selects both a member literally named "usr" and every member under
 * "usr/..."), which is the well-established behaviour every real pax/
 * tar shares for a plain non-wildcard pattern operand. */
static int is_plain_pattern(const char *pat)
{
	return strpbrk(pat, "*?[") == NULL;
}

static int pax_name_matches(const char *name withtok(null_terminated),
	char **patterns elements_withtok(null_terminated, npat), int npat, int complement)
{
	int i, matched;
	if (npat == 0) return 1;
	matched = 0;
	for (i = 0; i < npat; i++) {
		if (fnmatch(patterns[i], name, 0) == 0) { matched = 1; break; }
		if (is_plain_pattern(patterns[i])) {
			size_t plen = strlen(patterns[i]);
			if (strncmp(name, patterns[i], plen) == 0 && name[plen] == '/') { matched = 1; break; }
		}
	}
	return complement ? !matched : matched;
}

/* ==== safety: reject absolute / ".." member names on extract ============= */

/* An archive member name is untrusted: src/internal/rpath.c's
 * is_absolute() treats both "\\" and "X:" as absolute, since the NT
 * build's path resolution accepts either slash and drive letters. A
 * check that only recognised '/' would let a name like "..\\..\\evil"
 * or "C:\\evil" slip past this and reach mkdir()/open(), which do honor
 * backslashes and drive letters there. Both spellings are checked
 * unconditionally since a well-formed ustar/cpio name never contains
 * either. */
__attribute__((nonnull(1)))
static int name_is_safe(const char *name)
{
	const char *p;
	if (name[0] == '/' || name[0] == '\\' || name[0] == 0) return 0;
	if (((name[0] | 0x20) >= 'a' && (name[0] | 0x20) <= 'z') && name[1] == ':') return 0;
	for (p = name; *p; ) {
		const char *seg = p;
		size_t seglen = strcspn(p, "/\\");
		if (seglen == 2 && seg[0] == '.' && seg[1] == '.') return 0;
		p += seglen;
		if (*p) p++;
	}
	return 1;
}

/* ==== materialization (read mode extract, and copy mode) ================= */

struct materialize_opts { int keep_existing; int newer_only; int verbose; };

/* Creates every directory component of `path` but the last, refusing if
 * one already exists as something other than a directory. A prior member
 * (name_is_safe() only bars ".."/absolute names, not a symlink) could
 * leave a symlink at an intermediate component -- e.g. "trap" then
 * "trap/evil" -- and mkdir()'s EEXIST tolerance would otherwise walk
 * through it into wherever it points. lstat(), not stat(), so the
 * component itself is checked, not what it resolves to. */
static int ensure_parent_dirs(const char *path)
{
	char buf[PAX_PATH_MAX];
	char *p;
	snprintf(buf, sizeof buf, "%s", path);
	for (p = buf + 1; *p; p++) {
		struct stat st;
		if (*p != '/') continue;
		*p = 0;
		if (mkdir(buf, 0777) < 0 && errno != EEXIST) return -1;
		if (lstat(buf, &st) < 0) return -1;
		if (!S_ISDIR(st.st_mode)) { errno = ENOTDIR; return -1; }
		*p = '/';
	}
	return 0;
}

/* Drains `m`'s data from `reader` for a member materialize() decided not
 * to extract (a -k/-u skip, or a parent-directory failure), keeping the
 * archive stream positioned at the next member's header. Only PAX_REG
 * and PAX_HARDLINK carry data blocks of their own. `reader` is NULL in
 * copy mode, making this a no-op there. */
__attribute__((nonnull(2)))
static void materialize_skip_data(struct pax_reader *reader, const struct pax_member *m)
{
	if (reader && (m->type == PAX_REG || m->type == PAX_HARDLINK))
		pax_reader_copy_data(reader, m, -1);
}

/* Creates one filesystem entry for `m` at `destpath`, reading `size`
 * bytes of data (a regular file's contents) from `reader`/`srcfd`
 * (exactly one of which is non-NULL/non-negative, chosen by the
 * caller: the archive reader for -r, a real source fd for copy mode)
 * if `m->type == PAX_REG`. Returns 0 on success (including a
 * deliberate skip under -k/-u), or -1 on a real failure (diagnostic
 * already printed). */
__attribute__((nonnull(1, 2, 5)))
static int materialize(const struct pax_member *m, const char *destpath,
                         struct pax_reader *reader, int srcfd,
                         const struct materialize_opts *opts)
{
	struct stat existing;
	int exists = (lstat(destpath, &existing) == 0);

	if (exists && opts->keep_existing) {
		if (opts->verbose) __util_diagf("pax: %s: already exists, not overwritten (-k)\n", destpath);
		materialize_skip_data(reader, m);
		return 0;
	}
	if (exists && opts->newer_only && (unsigned long)existing.st_mtime >= m->mtime) {
		materialize_skip_data(reader, m);
		return 0;
	}

	if (ensure_parent_dirs(destpath) < 0) {
		__util_diagf("pax: %s: cannot create parent directories: %s\n", destpath, strerror(errno));
		materialize_skip_data(reader, m);
		return -1;
	}

	if (opts->verbose) __util_diagf("%s\n", destpath);

	/* Every non-PAX_REG entry has no data of its own by this writer's
	 * convention; draining whatever a foreign archive claims for such an
	 * entry's size here keeps the stream positioned correctly for later
	 * members. */
	if (reader && m->type != PAX_REG && m->size) pax_reader_copy_data(reader, m, -1);

	switch (m->type) {
	case PAX_DIR:
		if (mkdir(destpath, (mode_t)(m->mode & 07777)) < 0 && errno != EEXIST) {
			__util_diagf("pax: %s: %s\n", destpath, strerror(errno));
			return -1;
		}
		return 0;
	case PAX_SYMLINK:
		if (exists) (void)unlink(destpath);
		if (symlink(m->linkname, destpath) < 0) {
			__util_diagf("pax: %s: %s\n", destpath, strerror(errno));
			return -1;
		}
		return 0;
	case PAX_HARDLINK:
		if (exists) (void)unlink(destpath);
		if (link(m->linkname, destpath) < 0) {
			__util_diagf("pax: %s: %s\n", destpath, strerror(errno));
			return -1;
		}
		return 0;
	case PAX_FIFO:
		if (exists) (void)unlink(destpath);
		if (mkfifo(destpath, (mode_t)(m->mode & 07777)) < 0) {
			__util_diagf("pax: %s: %s\n", destpath, strerror(errno));
			return -1;
		}
		return 0;
	case PAX_CHR:
	case PAX_BLK:
		if (exists) (void)unlink(destpath);
		if (mknod(destpath, (mode_t)((m->mode & 07777) | (m->type == PAX_CHR ? S_IFCHR : S_IFBLK)), 0) < 0) {
			__util_diagf("pax: %s: %s\n", destpath, strerror(errno));
			return -1;
		}
		return 0;
	case PAX_REG:
	default: {
		int fd;
		if (exists) (void)unlink(destpath);
		/* O_EXCL, not O_TRUNC: the lstat() above is stale by now, so if
		 * a symlink has since appeared at destpath, O_TRUNC would
		 * follow it. O_EXCL fails instead; one unlink-and-retry covers
		 * ordinary re-extraction. */
		fd = open(destpath, O_WRONLY | O_CREAT | O_EXCL, (mode_t)(m->mode & 07777));
		if (fd < 0 && errno == EEXIST) {
			(void)unlink(destpath);
			fd = open(destpath, O_WRONLY | O_CREAT | O_EXCL, (mode_t)(m->mode & 07777));
		}
		if (fd < 0) {
			__util_diagf("pax: %s: %s\n", destpath, strerror(errno));
			if (reader) pax_reader_copy_data(reader, m, -1);
			return -1;
		}
		if (reader) {
			if (pax_reader_copy_data(reader, m, fd) < 0) { (void)close(fd); return -1; }
		} else if (srcfd >= 0) {
			char buf[65536];
			ssize_t n;
			while ((n = read(srcfd, buf, sizeof buf)) > 0) {
				char *p = buf; ssize_t left = n;
				while (left > 0) {
					__ownership_readable_span(p, (size_t)left);
					ssize_t w = write(fd, p, (size_t)left);
					if (w < 0) { __util_diagf("pax: %s: %s\n", destpath, strerror(errno)); (void)close(fd); return -1; }
					p += w; left -= w;
				}
			}
		}
		if (close(fd) < 0) {
			__util_diagf("pax: %s: %s\n", destpath, strerror(errno));
			return -1;
		}
		{
			struct utimbuf ub;
			ub.actime = ub.modtime = (time_t)m->mtime;
			utime(destpath, &ub);
		}
		return 0;
	}
	}
}

/* ==== write/copy mode: walking real file operands ========================= */

static void (*g_walk_emit)(const char *path, const struct stat *st, void *ud);
static void *g_walk_ud;
static int g_walk_failed;

static int walk_cb(const char *path, const struct stat *st, int type, struct FTW *ftwbuf)
{
	(void)ftwbuf;
	switch (type) {
	case FTW_F:
	case FTW_D:
	case FTW_SL:
		g_walk_emit(path, st, g_walk_ud);
		break;
	case FTW_DNR:
		__util_diagf("pax: %s: cannot read directory\n", path);
		g_walk_failed = 1;
		break;
	case FTW_NS:
		__util_diagf("pax: %s: cannot stat\n", path);
		g_walk_failed = 1;
		break;
	default:
		break;
	}
	return 0;
}

/* Walks each of `nfiles` operands (recursing into directories unless
 * `no_recurse`), calling `emit` once per real filesystem entry found
 * (symlinks reported as themselves, via lstat -- see this file's
 * header on -H/-L). Returns 0, or -1 if any operand failed (a
 * diagnostic for that operand was already printed either here or by
 * walk_cb() above). */
static int walk_operands(char **files, int nfiles, int no_recurse,
                           void (*emit)(const char *path, const struct stat *st, void *ud), void *ud)
{
	int i, failed = 0;

	g_walk_emit = emit;
	g_walk_ud = ud;

	for (i = 0; i < nfiles; i++) {
		struct stat st;
		if (lstat(files[i], &st) < 0) {
			__util_diagf("pax: %s: %s\n", files[i], strerror(errno));
			failed = 1;
			continue;
		}
		if (S_ISDIR(st.st_mode) && !no_recurse) {
			g_walk_failed = 0;
			if (nftw(files[i], walk_cb, 32, FTW_PHYS) < 0) {
				__util_diagf("pax: %s: %s\n", files[i], strerror(errno));
				failed = 1;
			}
			if (g_walk_failed) failed = 1;
		} else {
			emit(files[i], &st, ud);
		}
	}
	return failed ? -1 : 0;
}

/* ==== building a pax_member from a real stat()/lstat() result ============ */

__attribute__((nonnull(1, 2, 3)))
static int build_member_from_stat(const char *path, const struct stat *st, struct pax_member *m)
{
	memset(m, 0, sizeof *m);
	snprintf(m->name, sizeof m->name, "%s", path);
	m->mode = (unsigned long)(st->st_mode & 07777);
	m->mtime = (unsigned long)st->st_mtime;
	m->size = 0;

	if (S_ISREG(st->st_mode)) { m->type = PAX_REG; m->size = (unsigned long)st->st_size; return 0; }
	if (S_ISDIR(st->st_mode)) { m->type = PAX_DIR; return 0; }
	if (S_ISLNK(st->st_mode)) {
		char buf[PAX_PATH_MAX];
		ssize_t n = readlink(path, buf, sizeof buf - 1);
		if (n < 0) { __util_diagf("pax: %s: %s\n", path, strerror(errno)); return -1; }
		buf[n] = 0;
		m->type = PAX_SYMLINK;
		snprintf(m->linkname, sizeof m->linkname, "%s", buf);
		return 0;
	}
	__util_diagf("pax: %s: not a regular file, directory or symbolic link -- "
	                "FIFOs, device nodes and sockets found while walking a tree are "
	                "not supported by this build (see src/util/pax.c's header)\n", path);
	return -1;
}

/* ==== write mode ========================================================== */

struct write_ctx { FILE *out; enum pax_format fmt; int verbose; int failed; };

/* ud is always &ctx from do_write()'s own walk_operands(..., write_emit,
 * &ctx) call below -- the sole call site. */
__attribute__((nonnull(3)))
static void write_emit(const char *path, const struct stat *st, void *ud)
{
	struct write_ctx *ctx = ud;
	struct pax_member m;
	int fd = -1;

	if (build_member_from_stat(path, st, &m) < 0) { ctx->failed = 1; return; }
	if (m.type == PAX_REG) {
		fd = open(path, O_RDONLY);
		if (fd < 0) { __util_diagf("pax: %s: %s\n", path, strerror(errno)); ctx->failed = 1; return; }
	}
	if (pax_write_member(ctx->out, ctx->fmt, &m, fd, ctx->verbose) < 0) {
		__util_diagf("pax: %s: error writing archive member\n", path);
		ctx->failed = 1;
	}
	if (fd >= 0) (void)close(fd);
}

/* Reads one pathname per line from stdin ("[i]f no file operands are
 * specified, a list of files to copy, one per line, shall be read from
 * the standard input" -- pax(1p)). Returns a NULL-terminated, malloc'd
 * argv-style array the caller frees with free_stdin_list() below, or
 * NULL on allocation failure. */
static char **read_stdin_file_list(int *out_n)
{
	char **list = NULL;
	size_t cap = 0, n = 0;
	char line[PAX_PATH_MAX];

	while (fgets(line, sizeof line, stdin)) {
		size_t len;
		char *dup;
		/* fgets() NUL-terminates on success; stdio.h's declaration
		 * doesn't grant that fact, so restate it. */
		__ownership_string_terminated(line);
		len = strlen(line);
		if (len && line[len - 1] == '\n') line[--len] = 0;
		if (!len) continue;
		dup = strdup(line);
		if (!dup) break;
		if (n == cap) {
			size_t newcap;
			char **nl;
			if (!__util_array_capacity(cap, n, 1, 16, sizeof *list, &newcap)) { free(dup); break; }
			nl = __util_reallocarray(list, newcap, sizeof *list);
			if (!nl) { free(dup); break; }
			list = nl; cap = newcap;
		}
		list[n++] = dup;
	}
	*out_n = (int)n;
	return list;
}

static int do_write(const char *archive, enum pax_format fmt, char **files, int nfiles, int no_recurse, int verbose)
{
	FILE *out;
	struct write_ctx ctx;
	char **stdin_list = NULL;
	int stdin_n = 0;
	int rc;

	if (nfiles == 0) {
		stdin_list = read_stdin_file_list(&stdin_n);
		files = stdin_list;
		nfiles = stdin_n;
	}

	out = archive ? fopen(archive, "wb") : stdout;
	if (!out) {
		__util_diagf("pax: %s: %s\n", archive, strerror(errno));
		return 1;
	}

	ctx.out = out;
	ctx.fmt = fmt;
	ctx.verbose = verbose;
	ctx.failed = 0;

	rc = walk_operands(files, nfiles, no_recurse, write_emit, &ctx);
	if (rc < 0) ctx.failed = 1;
	if (pax_write_trailer(out, fmt) < 0) ctx.failed = 1;
	if (archive) { if (fclose(out) != 0) ctx.failed = 1; }
	else if (fflush(out) != 0) ctx.failed = 1;

	if (stdin_list) {
		int i;
		for (i = 0; i < stdin_n; i++) free(stdin_list[i]);
		free(stdin_list);
	}
	return ctx.failed ? 1 : 0;
}

/* ==== list / read mode ==================================================== */

static void print_listing(const struct pax_member *m, int verbose)
{
	if (!verbose) { printf("%s\n", m->name); return; }
	{
		char typec;
		char tbuf[32];
		time_t t = (time_t)m->mtime;
		struct tm *tm = gmtime(&t);
		switch (m->type) {
		case PAX_DIR: typec = 'd'; break;
		case PAX_SYMLINK: typec = 'l'; break;
		case PAX_HARDLINK: typec = 'h'; break;
		case PAX_FIFO: typec = 'p'; break;
		case PAX_CHR: typec = 'c'; break;
		case PAX_BLK: typec = 'b'; break;
		case PAX_REG: default: typec = '-'; break;
		}
		if (tm) strftime(tbuf, sizeof tbuf, "%b %e %H:%M %Y", tm);
		else snprintf(tbuf, sizeof tbuf, "%lu", m->mtime);
		if (m->type == PAX_SYMLINK)
			printf("%c%06lo %8lu %s %s -> %s\n", typec, m->mode, m->size, tbuf, m->name, m->linkname);
		else
			printf("%c%06lo %8lu %s %s\n", typec, m->mode, m->size, tbuf, m->name);
	}
}

/* Drains a member's data without extracting or printing it, for one
 * whose header was consumed but not materialized (unmatched pattern,
 * list mode, or a name-safety refusal) -- keeps the stream positioned at
 * the next header. Only PAX_REG/PAX_HARDLINK carry data of their own. */
static void reader_skip_data(struct pax_reader *r, const struct pax_member *m)
{
	if (m->type == PAX_REG || m->type == PAX_HARDLINK) pax_reader_copy_data(r, m, -1);
}

static int do_list_or_read(const char *archive,
	char **patterns elements_withtok(null_terminated, npat), int npat, int complement,
                             int do_extract, int no_recurse, int keep_existing, int newer_only, int verbose)
{
	struct pax_reader r;
	int failed = 0;

	(void)no_recurse; /* read/list mode has no hierarchy to skip recursing into */

	if (pax_reader_open(&r, archive) < 0) return 1;

	for (;;) {
		struct pax_member m;
		int rc = pax_reader_next(&r, &m);
		if (rc < 0) { failed = 1; break; }
		if (rc == 0) break;

		/* m.name/m.linkname are struct fields, so null_terminated can't
		 * attach directly; pax_reader_next() always populates both via
		 * snprintf()/an explicit NUL. */
		__ownership_string_terminated(m.name);
		__ownership_string_terminated(m.linkname);

		if (!pax_name_matches(m.name, patterns, npat, complement)) {
			reader_skip_data(&r, &m);
			continue;
		}

		if (!do_extract) {
			print_listing(&m, verbose);
			reader_skip_data(&r, &m);
			continue;
		}

		/* m.linkname is just as much untrusted archive input as m.name,
		 * and materialize() feeds it straight to link() as the OLDPATH
		 * -- unlike a symlink target, which is never dereferenced during
		 * extraction. A hostile hardlink member could alias any file the
		 * extracting user can reach, so it gets the same containment
		 * check as m.name. */
		if (!name_is_safe(m.name) ||
		    (m.type == PAX_HARDLINK && !name_is_safe(m.linkname))) {
			__util_diagf("pax: %s: refusing to extract an absolute path or a path "
			                "containing '..' (see src/util/pax.c's header)\n", m.name);
			reader_skip_data(&r, &m);
			failed = 1;
			continue;
		}

		{
			struct materialize_opts opts;
			opts.keep_existing = keep_existing;
			opts.newer_only = newer_only;
			opts.verbose = verbose;
			if (materialize(&m, m.name, &r, -1, &opts) < 0) failed = 1;
		}
	}

	if (archive) (void)fclose(r.f);
	return failed ? 1 : 0;
}

/* ==== copy mode (-r -w) ==================================================== */

struct copy_ctx { const char *destdir; int keep_existing; int newer_only; int verbose; int failed; };

/* ud is always &ctx from do_copy()'s own walk_operands(..., copy_emit, &ctx)
 * call below -- the sole call site, and the same "a real caller-supplied
 * accumulator, never optional" shape write_emit()'s own ctx has. */
__attribute__((nonnull(3)))
static void copy_emit(const char *path, const struct stat *st, void *ud)
{
	struct copy_ctx *ctx = ud;
	struct pax_member m;
	char destpath[PAX_PATH_MAX];
	struct materialize_opts opts;
	int fd = -1;

	if (build_member_from_stat(path, st, &m) < 0) { ctx->failed = 1; return; }
	snprintf(destpath, sizeof destpath, "%s/%s", ctx->destdir, path);

	if (m.type == PAX_REG) {
		fd = open(path, O_RDONLY);
		if (fd < 0) { __util_diagf("pax: %s: %s\n", path, strerror(errno)); ctx->failed = 1; return; }
	}
	opts.keep_existing = ctx->keep_existing;
	opts.newer_only = ctx->newer_only;
	opts.verbose = ctx->verbose;
	if (materialize(&m, destpath, NULL, fd, &opts) < 0) ctx->failed = 1;
	if (fd >= 0) (void)close(fd);
}

static int do_copy(char **files, int nfiles, const char *directory, int no_recurse,
                     int keep_existing, int newer_only, int verbose)
{
	struct stat dst;
	struct copy_ctx ctx;

	if (stat(directory, &dst) < 0 || !S_ISDIR(dst.st_mode)) {
		__util_diagf("pax: %s: not a directory\n", directory);
		return 1;
	}
	if (nfiles == 0) {
		__util_diagf("pax: copy mode: at least one file operand is required\n");
		return 1;
	}

	ctx.destdir = directory;
	ctx.keep_existing = keep_existing;
	ctx.newer_only = newer_only;
	ctx.verbose = verbose;
	ctx.failed = 0;

	if (walk_operands(files, nfiles, no_recurse, copy_emit, &ctx) < 0) ctx.failed = 1;
	return ctx.failed ? 1 : 0;
}

/* ==== option parsing / mode dispatch ====================================== */

int __util_pax_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i;
	int rflag = 0, wflag = 0;
	int cflag = 0, dflag = 0, kflag = 0, uflag = 0, vflag = 0;
	const char *archive = NULL;
	enum pax_format fmt = PAX_FMT_USTAR;

	for (i = 1; i < argc; i++) {
		char *a = argv[i];
		char *p;
		if (!strcmp(a, "--")) { i++; break; }
		if (a[0] != '-' || a[1] == 0) break;

		p = a + 1;
		while (*p) {
			switch (*p) {
			case 'r': rflag = 1; p++; break;
			case 'w': wflag = 1; p++; break;
			case 'c': cflag = 1; p++; break;
			case 'd': dflag = 1; p++; break;
			case 'k': kflag = 1; p++; break;
			case 'u': uflag = 1; p++; break;
			case 'v': vflag = 1; p++; break;
			case 'f':
				p++;
				if (*p) { archive = p; p += strlen(p); }
				else {
					if (++i >= argc) { __util_diagf("pax: -f: option requires an argument\n"); return 1; }
					archive = argv[i];
				}
				break;
			case 'x':
				p++;
				{
					const char *val;
					if (*p) { val = p; p += strlen(p); }
					else {
						if (++i >= argc) { __util_diagf("pax: -x: option requires an argument\n"); return 1; }
						val = argv[i];
					}
					if (!strcmp(val, "ustar")) fmt = PAX_FMT_USTAR;
					else if (!strcmp(val, "cpio")) fmt = PAX_FMT_CPIO;
					else if (!strcmp(val, "pax")) {
						__util_diagf("pax: -x pax: the pax extended-header format is not "
						                "implemented by this build -- see src/util/pax.c's header\n");
						return 1;
					} else {
						__util_diagf("pax: -x %s: unrecognized format\n", val);
						return 1;
					}
				}
				break;
			case 'a': case 'b': case 'B': case 'i': case 'n': case 'l':
			case 'H': case 'L': case 'o': case 'G': case 'U':
			case 's': case 't': case 'T': case 'Y': case 'Z': case 'X':
				__util_diagf("pax: -%c: not implemented by this build -- "
				                "see src/util/pax.c's header for what is and isn't\n", *p);
				return 1;
			case 'p':
				__util_diagf("pax: -p: file-characteristic preservation control is not "
				                "implemented -- this build has one fixed materialization "
				                "policy instead (see src/util/pax.c's header)\n");
				return 1;
			default:
				__util_diagf("pax: -%c: invalid option\n", *p);
				return 1;
			}
		}
	}

	if (rflag && wflag) {
		/* copy mode: file... directory */
		int nfiles = argc - i;
		if (nfiles < 1) { __util_diagf("pax: copy mode: missing directory operand\n"); return 1; }
		return do_copy(argv + i, nfiles - 1, argv[argc - 1], dflag, kflag, uflag, vflag);
	} else if (wflag) {
		return do_write(archive, fmt, argv + i, argc - i, dflag, vflag);
	} else {
		/* read mode (-r) or list mode (neither) */
		return do_list_or_read(archive, argv + i, argc - i, cflag, rflag, dflag, kflag, uflag, vflag);
	}
}
