/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ar(1p): `ar -d|-m|-p|-q|-r|-t|-x [-cuv] archive [file...]`
 *
 * ---- from-scratch vs. wrapping tcc's own `-ar` mode ---------------------
 *
 * A real system running ar.exe standalone has no tcc anywhere on it, so
 * wrapping tcc's `-ar` would not be a genuine standalone utility, just a
 * tcc frontend with an ar-shaped name -- this file is a real,
 * from-scratch reader/writer instead.  POSIX itself does not mandate a
 * specific on-disk archive format ("[a]rchives are files with
 * unspecified formats" -- ar(1p) EXTENDED DESCRIPTION is literally
 * "None."), so this file is free to pick one, and picks the classic
 * common format: the "!<arch>\n" 8-byte magic and 60-byte member header
 * (name[16] mtime[12] uid[6] gid[6] mode[8] size[10] fmag[2]="`\n",
 * data padded to an even length with a trailing '\n') every System V/
 * GNU/BSD ar agrees on -- the same layout tcc's own archiver writes for
 * lib/libc.a, verified directly against its own bytes.  This file's own
 * writer never emits a symbol table (see "NOT IMPLEMENTED" below).
 * Member names follow the GNU convention of a trailing '/' terminator
 * inside the 16-byte field (so a name may be at most 15 bytes), which
 * is what makes archives this utility writes readable by real ar
 * implementations too, not just by itself.
 *
 * ---- OPTIONS implemented -------------------------------------------------
 *  -d [-v]       delete
 *  -p [-v]       print (all members, or the named ones, in archive order)
 *  -q [-cv]      quick append, no duplicate-name check
 *  -r [-cuv]     replace-or-append ("Files that replace existing files
 *                 ... shall not change the order of the archive")
 *  -t [-v]       table of contents (-v: long/ls -l-style listing)
 *  -x [-v]       extract; "modification time of each file extracted
 *                 shall be set to the time the file is extracted" --
 *                 i.e. this build deliberately does NOT restore the
 *                 archived mtime, matching that sentence exactly (no
 *                 utime() call after writing the extracted file).
 *  -c            suppress the "creating archive" diagnostic (-q/-r)
 *  -u            with -r, replace only if file's mtime >= member's
 *  -v            verbose modifier for -d/-p/-r/-t/-x, per option above
 *
 * ---- NOT IMPLEMENTED, refused loudly rather than silently ignored -------
 *  -a/-b/-i posname   relative positioning (all three are XSI
 *                     extensions, not in the POSIX base standard --
 *                     verified against the real ar(1p) OPTIONS text,
 *                     each individually marked XSI there).  Without
 *                     them, -r/-m always append/move to the end.
 *  -m                 move (XSI); the operation itself is refused,
 *                     since without -a/-b/-i "move" degenerates to a
 *                     no-op this file would rather refuse than pretend
 *                     to perform.
 *  -s                 force symbol-table regeneration (XSI).  This
 *                     writer never builds a symbol table at all (doing
 *                     so needs a real object-file reader -- ELF/COFF/
 *                     PE symbol parsing -- which is an entirely
 *                     different, large project this batch does not
 *                     attempt), so -s is refused rather than accepted
 *                     as a silent no-op that implies a table exists.
 *  -C                 refuse to overwrite like-named files on extract
 *                     (XSI, paired with -T below).
 *  -T                 allow filename truncation on extract (XSI).  This
 *                     writer's own 15-byte name-field limit (above)
 *                     already refuses to *create* a member whose
 *                     basename does not fit, with a real diagnostic
 *                     and a nonzero exit for that operand, rather than
 *                     silently truncating a name into a colliding one
 *                     -- so there is nothing for a -T extraction-side
 *                     truncation policy to do with an archive this
 *                     utility itself wrote; refused for symmetry and
 *                     because reading a *foreign* long-name archive
 *                     (GNU's "//" long-name table extension) is also
 *                     not implemented (see below).
 *
 * GNU long-name ("//" member + "/N" back-references) and BSD
 * "#1/<len>" extended names are NOT implemented on read or write: a
 * from-scratch reader that only understands the classic <=15-byte
 * inline name is a real, useful, portable-enough ar for this batch's
 * purpose, and every name this writer itself produces fits by
 * construction (refused loudly at create time otherwise, above) -- so
 * this omission never bites an archive created by this same ar.exe,
 * only a much older/foreign one with long member names, which this
 * build declines to read (loud diagnostic, not silent misparsing).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include "util.h"
#include "ownership_stubs.h"

#define AR_MAGIC "!<arch>\n"
#define AR_MAGIC_LEN 8
#define AR_HDR_LEN 60
#define AR_NAME_MAX 15 /* + trailing '/' fills the 16-byte name field */

struct ar_member {
	char name[AR_NAME_MAX + 1];
	long mtime;
	long mode;
	long size; /* data length, not counting the odd-length pad byte */
};

/* ==== raw 60-byte header <-> struct ar_member ============================ */

static void put_field(char *field, size_t width, const char *fmt, long value)
{
	char tmp[32];
	size_t len;
	snprintf(tmp, sizeof tmp, fmt, value);
	__ownership_string_terminated(tmp);
	len = strlen(tmp);
	if (len > width) len = width; /* callers keep values in range */
	memset(field, ' ', width);
	memcpy(field, tmp, len);
}

/* Writes one 60-byte header to `out`. Returns 0, or -1 with errno set
 * on a write failure. */
static int write_header(FILE *out, const struct ar_member *m)
{
	char hdr[AR_HDR_LEN];
	size_t nl;
	/* m->name is always NUL-terminated: build_member()'s strcpy() from a
	 * basename already checked to fit, or parse_header()'s explicit
	 * m->name[AR_NAME_MAX] = 0. */
	__ownership_string_terminated(m->name);
	nl = strlen(m->name);

	memset(hdr, ' ', sizeof hdr);
	for (size_t i = 0; i < nl; i++) hdr[i] = m->name[i];
	hdr[nl] = '/';
	put_field(hdr + 16, 12, "%ld", m->mtime);
	put_field(hdr + 28, 6, "%ld", 0); /* uid: this platform has none real */
	put_field(hdr + 34, 6, "%ld", 0); /* gid: likewise */
	put_field(hdr + 40, 8, "%lo", m->mode & 07777);
	put_field(hdr + 48, 10, "%ld", m->size);
	hdr[58] = '`';
	hdr[59] = '\n';

	if (fwrite(hdr, 1, sizeof hdr, out) != sizeof hdr) return -1;
	return 0;
}

/* Parses one already-read 60-byte header. Returns 0 on a structurally
 * valid header (name may still be empty for a foreign long-name/symtab
 * member -- see below), or -1 if the magic is wrong, the name embeds a
 * path separator, or the size field over/underflows `long`.
 *
 * The name check blocks a "Zip Slip"-style path traversal: a crafted
 * name like "../../evil" fits the 15-byte field and would otherwise
 * reach fopen() unchecked in x_visit().
 *
 * The size check matters because the field is a 10-byte decimal string
 * that can claim up to 9999999999, past LONG_MAX on this project's
 * 32-bit-`long` Windows target; strtol() clamps rather than wraps, but
 * the caller's `m.size + (m.size & 1)` padding arithmetic can then
 * itself overflow. A leading '-' would also desync the walk by
 * "skipping" a negative amount. Rejecting both here is simpler than
 * making that arithmetic overflow-safe. */
static int parse_header(const char raw[AR_HDR_LEN], struct ar_member *m)
{
	char field[17];
	int i;

	if (raw[58] != '`' || raw[59] != '\n') return -1;

	memcpy(field, raw, 16);
	field[16] = 0;
	for (i = 15; i >= 0 && field[i] == ' '; i--) field[i] = 0;
	if (i >= 0 && field[i] == '/') field[i] = 0;
	strncpy(m->name, field, AR_NAME_MAX);
	m->name[AR_NAME_MAX] = 0;
	__ownership_string_terminated(m->name);
	if (strchr(m->name, '/') || strchr(m->name, '\\')) return -1;

	memcpy(field, raw + 16, 12); field[12] = 0; m->mtime = strtol(field, NULL, 10);
	memcpy(field, raw + 40, 8); field[8] = 0; m->mode = strtol(field, NULL, 8);
	memcpy(field, raw + 48, 10); field[10] = 0;
	errno = 0;
	m->size = strtol(field, NULL, 10);
	/* Reject LONG_MAX itself too: it's odd, so the caller's even-padding
	 * `+ (m.size & 1)` would overflow even for this in-range value. */
	if (m->size < 0 || errno == ERANGE || m->size >= LONG_MAX) return -1;
	return 0;
}

/* ==== archive iteration ================================================= */

typedef int (*ar_visit_fn)(FILE *ar, const struct ar_member *m, long data_off, void *ctx);

/* Opens `path`, checks the global "!<arch>\n" magic, and calls `visit`
 * once per member with the file positioned at the start of that
 * member's data (data_off is that same offset, for callers that need
 * to seek back to it after peeking ahead). `visit` must leave the file
 * positioned anywhere; this function always seeks to the next header
 * itself using m->size. Returns 0 if the whole archive was walked, -1
 * on an I/O/format error (diagnostic already printed), or whatever
 * nonzero `visit` returned (which stops the walk immediately). */
static int ar_foreach(const char *path, ar_visit_fn visit, void *ctx)
{
	FILE *ar;
	char magic[AR_MAGIC_LEN];
	int rc = 0;

	ar = fopen(path, "rb");
	if (!ar) {
		__util_diagf("ar: %s: %s\n", path, strerror(errno));
		return -1;
	}
	if (fread(magic, 1, AR_MAGIC_LEN, ar) != AR_MAGIC_LEN ||
	    memcmp(magic, AR_MAGIC, AR_MAGIC_LEN) != 0) {
		__util_diagf("ar: %s: not an archive (bad magic)\n", path);
		(void)fclose(ar);
		return -1;
	}

	for (;;) {
		char raw[AR_HDR_LEN];
		struct ar_member m;
		long data_off, skip;
		size_t got = fread(raw, 1, AR_HDR_LEN, ar);
		if (got == 0) break; /* clean EOF between members */
		if (got != AR_HDR_LEN) {
			__util_diagf("ar: %s: truncated archive header\n", path);
			rc = -1;
			break;
		}
		if (parse_header(raw, &m) < 0) {
			__util_diagf("ar: %s: corrupt member header\n", path);
			rc = -1;
			break;
		}
		data_off = ftell(ar);
		if (m.name[0] == 0) {
			/* Foreign special member (GNU "/" symtab, "//" long-name
			 * table, ...); skip rather than fail the whole archive. */
			(void)0;
		} else {
			rc = visit(ar, &m, data_off, ctx);
			if (rc != 0) break;
		}
		skip = m.size + (m.size & 1);
		if (fseek(ar, data_off + skip, SEEK_SET) != 0) break;
	}

	(void)fclose(ar);
	return rc;
}

/* ==== name-list matching (the `file...` operands) ======================= */

/* A tiny basename(): OPERANDS says "only the last component ... shall
 * be compared", and this project's own libgen.h basename() would
 * modify its argument in place -- avoided here since argv strings are
 * reused across multiple name_wanted() calls in the same run. */
static const char *basename_of(const char *path)
{
	const char *slash;
	/* path is always an argv-derived operand string. */
	__ownership_string_terminated(path);
	slash = strrchr(path, '/');
	const char *bslash = strrchr(path, '\\');
	if (bslash && (!slash || bslash > slash)) slash = bslash;
	return slash ? slash + 1 : path;
}

/* name is always a struct ar_member's own name[] field, never NULL. */
static int name_wanted(const char *name, char **files, int nfiles)
	__attribute__((nonnull(1, 2)));
static int name_wanted(const char *name, char **files, int nfiles)
{
	int i;
	__ownership_string_terminated(name);
	if (nfiles == 0) return 1;
	for (i = 0; i < nfiles; i++)
		if (files[i] && strcmp(basename_of(files[i]), name) == 0) return 1;
	return 0;
}

/* ==== -t: table of contents ============================================= */

struct t_ctx { char **files; int nfiles; int verbose; int any; };

/* m and ctxp are never NULL (ar_foreach() always passes &m and &ctx),
 * but reached only through the ar_visit_fn function pointer, so the
 * checker can't derive that by inlining -- must be asserted here. */
static int t_visit(FILE *ar, const struct ar_member *m, long data_off, void *ctxp)
	__attribute__((nonnull(2, 4)));
static int t_visit(FILE *ar, const struct ar_member *m, long data_off, void *ctxp)
{
	struct t_ctx *ctx = ctxp;
	(void)ar; (void)data_off;
	if (!name_wanted(m->name, ctx->files, ctx->nfiles)) return 0;
	ctx->any = 1;
	if (ctx->verbose) {
		time_t t = (time_t)m->mtime;
		char tbuf[32];
		struct tm *tm = gmtime(&t);
		if (tm) strftime(tbuf, sizeof tbuf, "%b %e %H:%M %Y", tm);
		else snprintf(tbuf, sizeof tbuf, "%ld", m->mtime);
		printf("%06lo %ld/%ld %6ld %s %s\n", m->mode & 07777, 0L, 0L, m->size, tbuf, m->name);
	} else {
		printf("%s\n", m->name);
	}
	return 0;
}

/* ==== -p: print contents ================================================ */

struct p_ctx { char **files; int nfiles; int verbose; };

/* m and ctxp are never NULL -- see t_visit()'s identical comment above for
 * why (same ar_foreach()/ar_visit_fn shape). */
static int p_visit(FILE *ar, const struct ar_member *m, long data_off, void *ctxp)
	__attribute__((nonnull(2, 4)));
static int p_visit(FILE *ar, const struct ar_member *m, long data_off, void *ctxp)
{
	struct p_ctx *ctx = ctxp;
	char buf[65536];
	long remain;

	if (!name_wanted(m->name, ctx->files, ctx->nfiles)) return 0;
	if (ctx->verbose) printf("\n<%s>\n\n", m->name);
	if (fseek(ar, data_off, SEEK_SET) != 0) return 0;
	remain = m->size;
	while (remain > 0) {
		size_t want = remain < (long)sizeof buf ? (size_t)remain : sizeof buf;
		size_t got = fread(buf, 1, want, ar);
		if (got == 0) break;
		__ownership_readable_span(buf, got);
		if (fwrite(buf, 1, got, stdout) != got) {
			__util_diagf("ar: error writing to standard output: %s\n", strerror(errno));
			return -1;
		}
		remain -= (long)got;
	}
	return 0;
}

/* ==== -x: extract ======================================================= */

struct x_ctx { char **files; int nfiles; int verbose; int failed; };

/* m and ctxp are never NULL -- see t_visit()'s identical comment above for
 * why (same ar_foreach()/ar_visit_fn shape). */
static int x_visit(FILE *ar, const struct ar_member *m, long data_off, void *ctxp)
	__attribute__((nonnull(2, 4)));
static int x_visit(FILE *ar, const struct ar_member *m, long data_off, void *ctxp)
{
	struct x_ctx *ctx = ctxp;
	FILE *out;
	char buf[65536];
	long remain;

	if (!name_wanted(m->name, ctx->files, ctx->nfiles)) return 0;
	if (fseek(ar, data_off, SEEK_SET) != 0) { ctx->failed = 1; return 0; }

	__ownership_string_terminated(m->name);
	out = fopen(m->name, "wb");
	if (!out) {
		__util_diagf("ar: cannot create '%s': %s\n", m->name, strerror(errno));
		ctx->failed = 1;
		return 0;
	}
	remain = m->size;
	while (remain > 0) {
		size_t want = remain < (long)sizeof buf ? (size_t)remain : sizeof buf;
		size_t got = fread(buf, 1, want, ar);
		if (got == 0) break;
		__ownership_readable_span(buf, got);
		if (fwrite(buf, 1, got, out) != got) {
			__util_diagf("ar: error writing '%s': %s\n", m->name, strerror(errno));
			ctx->failed = 1;
			break;
		}
		remain -= (long)got;
	}
	if (fclose(out) != 0) {
		__util_diagf("ar: error writing '%s': %s\n", m->name, strerror(errno));
		ctx->failed = 1;
	} else if (chmod(m->name, (mode_t)(m->mode & 07777)) != 0) {
		__util_diagf("ar: %s: chmod: %s\n", m->name, strerror(errno));
		ctx->failed = 1;
	}
	/* "The modification time of each file extracted shall be set to
	 * the time the file is extracted from the archive" -- i.e.
	 * deliberately NOT m->mtime; no utime() call here. */
	if (ctx->verbose) printf("x - %s\n", m->name);
	return 0;
}

/* ==== -d: delete ========================================================= */

struct rewrite_member { struct ar_member m; long data_off; };

/* Shared by -d and -r/-q: reads every existing member's header (not
 * its data) into memory so the caller can decide, per member, whether
 * to keep the original bytes, replace them, or drop them, then writes
 * a fresh archive to a temp file and renames it over the original --
 * the only way to change an archive member's size in place without a
 * hole-punching filesystem this build does not assume. */
static int read_all_headers(const char *path,
                            struct rewrite_member **out withtok(heap_allocated),
                            int *nout)
{
	FILE *ar;
	char magic[AR_MAGIC_LEN];
	struct rewrite_member *arr = NULL;
	size_t cap = 0, n = 0;

	ar = fopen(path, "rb");
	if (!ar) { *out = NULL; *nout = 0; return -1; }
	if (fread(magic, 1, AR_MAGIC_LEN, ar) != AR_MAGIC_LEN ||
	    memcmp(magic, AR_MAGIC, AR_MAGIC_LEN) != 0) {
		(void)fclose(ar);
		*out = NULL; *nout = 0;
		return -2;
	}
	for (;;) {
		char raw[AR_HDR_LEN];
		struct rewrite_member rm;
		long skip;
		size_t got = fread(raw, 1, AR_HDR_LEN, ar);
		if (got == 0) break;
		if (got != AR_HDR_LEN || parse_header(raw, &rm.m) < 0) { (void)fclose(ar); free(arr); *out = NULL; *nout = 0; return -3; }
		rm.data_off = ftell(ar);
		if (rm.m.name[0] != 0) {
			if (n == cap) {
				size_t newcap;
				struct rewrite_member *na;
				if (!__util_array_capacity(cap, n, 1, 16, sizeof *arr, &newcap)) { (void)fclose(ar); free(arr); return -4; }
				na = __util_reallocarray(arr, newcap, sizeof *arr);
				if (!na) { (void)fclose(ar); free(arr); return -4; }
				arr = na; cap = newcap;
			}
			arr[n++] = rm;
		}
		skip = rm.m.size + (rm.m.size & 1);
		if (fseek(ar, rm.data_off + skip, SEEK_SET) != 0) break;
	}
	(void)fclose(ar);
	*out = arr;
	*nout = (int)n;
	return 0;
}

static int copy_bytes(FILE *src, FILE *dst, long off, long len)
{
	char buf[65536];
	if (fseek(src, off, SEEK_SET) != 0) return -1;
	while (len > 0) {
		size_t want = len < (long)sizeof buf ? (size_t)len : sizeof buf;
		size_t got = fread(buf, 1, want, src);
		if (got == 0) return -1;
		__ownership_readable_span(buf, got);
		if (fwrite(buf, 1, got, dst) != got) return -1;
		len -= (long)got;
	}
	return 0;
}

/* Writes one member's header + data (data supplied either from an
 * already-open source `src_ar` at `off`, when `path` is NULL, or read
 * fresh from the real file `path`) to `out`, padding to an even
 * length. Returns 0, or -1 on any I/O error (diagnostic already
 * printed by the caller's context, not here). */
static int emit_member(FILE *out, const struct ar_member *m, FILE *src_ar, long off, const char *path)
{
	if (write_header(out, m) < 0) return -1;
	if (path) {
		FILE *in;
		__ownership_string_terminated(path);
		in = fopen(path, "rb");
		if (!in) return -1;
		if (copy_bytes(in, out, 0, m->size) < 0) { (void)fclose(in); return -1; }
		(void)fclose(in);
	} else {
		if (copy_bytes(src_ar, out, off, m->size) < 0) return -1;
	}
	if (m->size & 1) fputc('\n', out);
	return 0;
}

static int build_member(const char *filepath, struct ar_member *m)
{
	struct stat st;
	const char *bn = basename_of(filepath);
	__ownership_string_terminated(bn);
	if (strlen(bn) > AR_NAME_MAX) {
		__util_diagf("ar: %s: member name longer than %d bytes -- not supported "
		                "by this build's archive format (see src/util/ar.c's header)\n",
		                bn, AR_NAME_MAX);
		return -1;
	}
	if (stat(filepath, &st) < 0) {
		__util_diagf("ar: %s: %s\n", filepath, strerror(errno));
		return -1;
	}
	if (!S_ISREG(st.st_mode)) {
		__util_diagf("ar: %s: not a regular file\n", filepath);
		return -1;
	}
	strcpy(m->name, bn);
	m->mtime = (long)st.st_mtime;
	m->mode = (long)st.st_mode;
	m->size = (long)st.st_size;
	return 0;
}

/* -d: delete named members. files is never NULL: every real call site
 * (__util_ar_main() below) passes argv+3, a valid pointer into argv's own
 * storage regardless of nfiles' value. */
static int do_delete(const char *archive, char **files, int nfiles, int verbose)
	__attribute__((nonnull(2)));
static int do_delete(const char *archive, char **files, int nfiles, int verbose)
{
	struct rewrite_member *arr;
	int n, i, rc;
	FILE *src, *tmp;
	char tmppath[4096];

	rc = read_all_headers(archive, &arr, &n);
	if (rc < 0) {
		__util_diagf("ar: %s: %s\n", archive, rc == -1 ? strerror(errno) : "not a valid archive");
		return 1;
	}
	src = fopen(archive, "rb");
	if (!src) { free(arr); __util_diagf("ar: %s: %s\n", archive, strerror(errno)); return 1; }

	snprintf(tmppath, sizeof tmppath, "%s.artmp", archive);
	__ownership_string_terminated(tmppath);
	tmp = fopen(tmppath, "wb");
	if (!tmp) {
		/* fclose(src) is cleanup for the fopen(tmppath) failure just
		 * diagnosed; if it fails too, its own errno must not
		 * overwrite the real reason tmppath could not be opened. */
		int saved_errno = errno;
		(void)fclose(src);
		errno = saved_errno;
		free(arr);
		__util_diagf("ar: %s: %s\n", tmppath, strerror(errno));
		return 1;
	}
	fwrite(AR_MAGIC, 1, AR_MAGIC_LEN, tmp);

	/* read_all_headers() only ever sets *nout > 0 together with a
	 * checked-nonnull *out (every element is stored into arr right after
	 * a checked reallocarray(), the same 0-capacity-forces-first-growth
	 * pattern as this project's other growable arrays) -- so n > i here
	 * implies arr != NULL, a fact that does not survive that call's own
	 * out-parameter return. */
	if (n > 0) __ownership_pointer_nonnull(arr);
	for (i = 0; i < n; i++) {
		if (name_wanted(arr[i].m.name, files, nfiles)) {
			if (verbose) printf("d - %s\n", arr[i].m.name);
			continue;
		}
		emit_member(tmp, &arr[i].m, src, arr[i].data_off, NULL);
	}
	(void)fclose(src);
	if (fclose(tmp) != 0) {
		__util_diagf("ar: %s: %s\n", tmppath, strerror(errno));
		free(arr);
		return 1;
	}
	free(arr);
	if (rename(tmppath, archive) != 0) {
		__util_diagf("ar: cannot replace %s: %s\n", archive, strerror(errno));
		return 1;
	}
	return 0;
}

/* -q/-r: append or replace-or-append. files is never NULL -- see
 * do_delete()'s identical comment above for why. */
static int do_append_or_replace(const char *archive, char **files, int nfiles,
                                  int quick, int update, int suppress_diag, int verbose)
	__attribute__((nonnull(2)));
static int do_append_or_replace(const char *archive, char **files, int nfiles,
                                  int quick, int update, int suppress_diag, int verbose)
{
	struct rewrite_member *arr = NULL;
	int n = 0, rc, i, status = 0;
	FILE *tmp;
	char tmppath[4096];
	int *consumed;

	rc = read_all_headers(archive, &arr, &n);
	if (rc == -1) {
		/* Archive does not exist yet (or cannot be opened at all --
		 * treated the same, and reported below). */
		if (!suppress_diag)
			__util_diagf("ar: creating %s\n", archive);
	} else if (rc < 0) {
		__util_diagf("ar: %s: not a valid archive\n", archive);
		return 1;
	}

	consumed = calloc((size_t)(nfiles > 0 ? nfiles : 1), sizeof *consumed);
	if (!consumed) { free(arr); __util_diagf("ar: %s\n", strerror(ENOMEM)); return 1; }

	snprintf(tmppath, sizeof tmppath, "%s.artmp", archive);
	__ownership_string_terminated(tmppath);
	tmp = fopen(tmppath, "wb");
	if (!tmp) {
		free(arr); free(consumed);
		__util_diagf("ar: %s: %s\n", tmppath, strerror(errno));
		return 1;
	}
	fwrite(AR_MAGIC, 1, AR_MAGIC_LEN, tmp);

	if (arr) {
		FILE *src = fopen(archive, "rb");
		if (!src) {
			__util_diagf("ar: %s: %s\n", archive, strerror(errno));
			status = 1;
		}
		for (i = 0; i < n && src; i++) {
			int fi, replaced = 0;
			if (!quick) {
				for (fi = 0; fi < nfiles; fi++) {
					const char *bn = basename_of(files[fi]);
					__ownership_string_terminated(bn);
					__ownership_string_terminated(arr[i].m.name);
					if (strcmp(bn, arr[i].m.name) != 0) continue;
					struct ar_member nm;
					if (build_member(files[fi], &nm) < 0) { status = 1; consumed[fi] = 1; break; }
					if (update && nm.mtime < arr[i].m.mtime) { consumed[fi] = 1; break; }
					if (verbose) printf("r - %s\n", nm.name);
					if (emit_member(tmp, &nm, NULL, 0, files[fi]) < 0) status = 1;
					consumed[fi] = 1;
					replaced = 1;
					break;
				}
			}
			if (!replaced) {
				if (emit_member(tmp, &arr[i].m, src, arr[i].data_off, NULL) < 0) status = 1;
			}
		}
		if (src) (void)fclose(src);
	}

	for (i = 0; i < nfiles; i++) {
		struct ar_member nm;
		if (consumed[i]) continue;
		if (build_member(files[i], &nm) < 0) { status = 1; continue; }
		if (verbose) printf("%c - %s\n", quick ? 'q' : 'a', nm.name);
		if (emit_member(tmp, &nm, NULL, 0, files[i]) < 0) status = 1;
	}

	if (fclose(tmp) != 0) {
		__util_diagf("ar: %s: %s\n", tmppath, strerror(errno));
		free(arr);
		free(consumed);
		return 1;
	}
	free(arr);
	free(consumed);
	if (rename(tmppath, archive) != 0) {
		__util_diagf("ar: cannot replace %s: %s\n", archive, strerror(errno));
		return 1;
	}
	return status;
}

int __util_ar_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	char op = 0;
	int cflag = 0, uflag = 0, vflag = 0;
	char *archive;
	char **files;
	int nfiles;

	if (argc < 3) {
		__util_diagf("ar: usage: ar -dpqrtx [-cuv] archive [file...]\n");
		return 2;
	}

	{
		char *p = argv[1];
		/* argc >= 3 (checked above), so argv[1] is genuinely one of
		 * argv's own elements, never NULL by this function's own
		 * elements_withtok(null_terminated, argc) contract on argv --
		 * restated here the same way src/util/od.c's __util_od_main()
		 * restates its own analogous argv-slice fact. */
		__ownership_pointer_nonnull(p);
		if (*p == '-') p++;
		for (; *p; p++) {
			switch (*p) {
			case 'd': case 'p': case 'q': case 'r': case 't': case 'x':
				if (op) { __util_diagf("ar: only one of -dpqrtx may be given\n"); return 2; }
				op = *p;
				break;
			case 'c': cflag = 1; break;
			case 'u': uflag = 1; break;
			case 'v': vflag = 1; break;
			case 'a': case 'b': case 'i':
				__util_diagf("ar: -%c: relative positioning is an XSI extension "
				                "not implemented by this build\n", *p);
				return 2;
			case 'm':
				__util_diagf("ar: -m: move is an XSI extension not implemented "
				                "by this build (see src/util/ar.c's header)\n");
				return 2;
			case 's':
				__util_diagf("ar: -s: this build never generates a symbol table "
				                "-- see src/util/ar.c's header\n");
				return 2;
			case 'C':
			case 'T':
				__util_diagf("ar: -%c: XSI extension not implemented by this build\n", *p);
				return 2;
			default:
				__util_diagf("ar: -%c: invalid option\n", *p);
				return 2;
			}
		}
	}
	if (!op) {
		__util_diagf("ar: one of -dpqrtx must be given\n");
		return 2;
	}

	archive = argv[2];
	files = argv + 3;
	nfiles = argc - 3;

	switch (op) {
	case 't': {
		struct t_ctx ctx = { files, nfiles, vflag, 0 };
		if (ar_foreach(archive, t_visit, &ctx) < 0) return 1;
		return 0;
	}
	case 'p': {
		struct p_ctx ctx = { files, nfiles, vflag };
		if (ar_foreach(archive, p_visit, &ctx) < 0) return 1;
		return 0;
	}
	case 'x': {
		struct x_ctx ctx = { files, nfiles, vflag, 0 };
		if (ar_foreach(archive, x_visit, &ctx) < 0) return 1;
		return ctx.failed ? 1 : 0;
	}
	case 'd':
		if (nfiles == 0) { __util_diagf("ar: -d: at least one file operand is required\n"); return 2; }
		return do_delete(archive, files, nfiles, vflag);
	case 'q':
	case 'r':
		if (nfiles == 0) { __util_diagf("ar: -%c: at least one file operand is required\n", op); return 2; }
		return do_append_or_replace(archive, files, nfiles, op == 'q', uflag, cflag, vflag);
	default:
		return 2;
	}
}
