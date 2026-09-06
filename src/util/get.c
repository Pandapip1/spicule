/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * get(1p): retrieves the text delta(s) src/util/admin.c's s.file writer
 * put there.
 *
 * ---- round-trip scope decision (read this first) -----------------------
 *
 * POSIX admin.html on its own creates a real, complete s.file -- but
 * nothing in this project could ever prove that file's content is
 * correct without something able to read it back. get(1p) and
 * delta(1p) are admin's real POSIX-mandated counterparts (delta(1p)
 * commits a *new* delta to an existing s.file; get(1p) retrieves one).
 * This project's own task direction for this pair was explicit: if
 * admin(1p) alone cannot produce anything testable end-to-end, implement
 * the minimal real subset of get/delta needed to round-trip a test
 * (admin -i creates, get retrieves, compare). That minimal subset turns
 * out to be get(1p) alone, not both: admin -i's own initial delta *is*
 * SID 1.1, fully committed, the moment the file is created (real SCCS
 * has always worked this way -- admin -i is how the very first version
 * gets in, with no separate delta(1p) call needed for it). delta(1p)
 * only matters once a SECOND version needs committing, which requires
 * get -e (checkout for edit) and a real diff-based delta encoder against
 * an existing body -- genuinely more machinery than a round-trip test
 * needs. delta(1p) is therefore not implemented at all here, and this
 * file's own scope follows directly from that: every s.file this project
 * can ever produce (via admin.c) has exactly one delta, SID 1.1, so this
 * reader only ever has one delta to retrieve -- see get_body() below for
 * exactly what that narrows away (no ^AI/^AD/^AE serial-inclusion
 * evaluation across a real multi-delta history, because there is never
 * more than one delta to evaluate).
 *
 * ---- OPTIONS actually implemented (POSIX get.html, verified against
 * the live spec text before writing this file) --------------------------
 *
 *  -p       "Write the text retrieved from the SCCS file to the standard
 *            output. No g-file shall be created."
 *  -r SID   Retrieve a specific SID -- narrowed here to "must name the
 *            file's own sole delta, 1.1, or this is a real, diagnosed
 *            error", per this file's round-trip-scope note above.
 *
 * STDOUT (no -p): "%s\n%d lines\n", <SID>, <number of lines>, per
 * get.html's own STDOUT section, written after the g-file is created.
 * With -p, the retrieved text itself goes to stdout instead (real
 * historical get's own long-standing behaviour, so a caller can pipe
 * `get -p s.file | ...` without piping the status message too), and the
 * status line goes to standard error instead -- documented here as this
 * implementation's own concrete choice since get.html's fetched STDOUT
 * text does not spell out where the status line goes for -p specifically.
 *
 * -e (checkout for edit), -c/-i/-x (cutoff/include/exclude delta
 * selection), -b/-g/-k/-l/-L/-m/-n/-s (the rest of get.html's own
 * options), and reading a "-" operand as a list of filenames on stdin
 * are all real get(1p) features not implemented here -- every one of
 * them exists to support a multi-delta history or a build/edit workflow
 * this project has no delta(1p) to feed it. Given any of them, this
 * refuses loudly rather than silently ignoring (same rule admin.c's own
 * header comment cites).
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>
#include "util.h"
#include "ownership_stubs.h"

struct sfile {
	char *buf;   /* whole file, NUL-terminated */
	size_t len;
};

/* Streaming grow-as-you-read, not fseek(SEEK_END)+ftell(): the same
 * technique src/util/diff.c's read_whole_stream() uses, copied rather
 * than shared for the same reason that file's own sibling copies give
 * (each caller's error-handling/NUL-termination needs differ slightly),
 * and preferred here over a seek-to-find-the-size approach because it
 * works uniformly regardless of whether the underlying stream supports
 * seeking at all. */
static int read_whole_file(const char *path, struct sfile *out)
{
	FILE *f = fopen(path, "rb");
	size_t cap = 65536, len = 0;
	char *buf;

	if (!f) return -1;
	buf = malloc(cap);
	if (!buf) {
		/* fclose(f) is cleanup for the malloc() failure just diagnosed
		 * (errno == ENOMEM); if it fails too, its own errno must not
		 * overwrite that reason. */
		int saved_errno = errno;
		(void)fclose(f);
		errno = saved_errno;
		return -1;
	}
	for (;;) {
		size_t got;
		if (len + 1 >= cap) {
			size_t newcap;
			char *g;
			if (!__util_array_capacity(cap, cap, 1, 65536, 1, &newcap)) { free(buf); (void)fclose(f); return -1; }
			g = realloc(buf, newcap);
			if (!g) {
				int saved_errno = errno;
				(void)fclose(f);
				errno = saved_errno;
				free(buf);
				return -1;
			}
			buf = g; cap = newcap;
		}
		__ownership_writable_span(buf + len, cap - len - 1);
		got = fread(buf + len, 1, cap - len - 1, f);
		len += got;
		if (got == 0) break;
	}
	if (ferror(f)) {
		/* fclose(f) is cleanup for the fread() failure just diagnosed;
		 * if it fails too, its own errno must not overwrite the real
		 * read error. */
		int saved_errno = errno;
		free(buf);
		(void)fclose(f);
		errno = saved_errno;
		return -1;
	}
	(void)fclose(f);
	buf[len] = 0;
	out->buf = buf;
	out->len = len;
	return 0;
}

/* Everything after the checksum line's own trailing '\n' -- the exact
 * span src/util/admin.c's __util_sccs_checksum() was computed over when
 * this file was written (sccsfile(5): "the sum of all characters,
 * except those contained in the first line"). */
static int verify_checksum(const struct sfile *s, const char **rest_out, size_t *restlen_out)
{
	const char *nl;
	unsigned long expect;
	unsigned actual;
	char *end;

	if (s->len < 3 || s->buf[0] != '\001' || s->buf[1] != 'h') return -1;
	expect = strtoul(s->buf + 2, &end, 10);
	nl = strchr(s->buf, '\n');
	if (!nl || end == s->buf + 2 || end > nl) return -1;

	*rest_out = nl + 1;
	*restlen_out = s->len - (size_t)(nl + 1 - s->buf);
	actual = __util_sccs_checksum(*rest_out, *restlen_out);
	return actual == (unsigned)expect ? 0 : -1;
}

/* The '\001d D 1.1 ...' delta-table line -- its SID is the 3rd
 * whitespace-separated field (sccsfile(5): "type sid date time user
 * serial pred-serial"). Copies the SID into a caller-owned buffer
 * rather than returning a pointer into `rest` (the caller needs it
 * after `rest`'s own line-splitting below has overwritten '\n's). */
static int find_sid(const char *rest, size_t restlen, char *sidbuf, size_t sidbuflen)
{
	const char *p = rest, *end = rest + restlen;
	while (p < end) {
		const char *nl = memchr(p, '\n', (size_t)(end - p));
		size_t linelen = nl ? (size_t)(nl - p) : (size_t)(end - p);
		if (linelen > 4 && p[0] == '\001' && p[1] == 'd') {
			/* "\001d D <sid> ..." -- skip "\001d", the type field. */
			const char *q = p + 2;
			int field;
			for (field = 0; field < 2 && q < p + linelen; field++) {
				while (q < p + linelen && *q == ' ') q++;
				if (field == 1) {
					const char *sidstart = q;
					while (q < p + linelen && *q != ' ') q++;
					size_t sidlen = (size_t)(q - sidstart);
					if (sidlen >= sidbuflen || sidlen > INT_MAX) return -1;
					if (snprintf(sidbuf, sidbuflen, "%.*s",
					    (int)sidlen, sidstart) != (int)sidlen)
						return -1;
					return 0;
				}
				while (q < p + linelen && *q != ' ') q++;
			}
		}
		p = nl ? nl + 1 : end;
	}
	return -1;
}

struct line_ref {
	const char *p;
	size_t len;
};

/* This project's own s.files only ever have one delta, "\001I 1" ...
 * "\001E 1" wrapping the whole body (this file's own header comment) --
 * so this looks for exactly that bracket, not a general multi-delta
 * ^AI/^AD/^AE serial-inclusion evaluator. `out` receives an array of
 * pointers *into* `rest` (not copies) plus each line's length; the
 * caller must not use them past `rest`'s own lifetime. */
static int find_body(const char *rest, size_t restlen, struct line_ref **out, size_t *nout)
{
	const char *p = rest, *end = rest + restlen;
	int in_body = 0;
	struct line_ref *lines = 0;
	size_t n = 0, cap = 0;

	while (p < end) {
		const char *nl = memchr(p, '\n', (size_t)(end - p));
		size_t linelen = nl ? (size_t)(nl - p) : (size_t)(end - p);

		if (!in_body) {
		if (linelen == 4 && p[0] == '\001' && p[1] == 'I' &&
		    p[2] == ' ' && p[3] == '1') in_body = 1;
		} else {
		if (linelen == 4 && p[0] == '\001' && p[1] == 'E' &&
		    p[2] == ' ' && p[3] == '1') {
			p = nl ? nl + 1 : end;
			goto done;
		}
			if (n >= cap) {
				size_t newcap;
				struct line_ref *g;
				if (!__util_array_capacity(cap, n, 1, 32, sizeof *lines, &newcap)) { free(lines); return -1; }
				g = __util_reallocarray(lines, newcap, sizeof *lines);
				if (!g) { free(lines); return -1; }
				lines = g; cap = newcap;
			}
			lines[n].p = p;
			lines[n].len = linelen;
			n++;
		}
		p = nl ? nl + 1 : end;
	}
	free(lines);
	return -1; /* no matching "\001E 1" found -- not a file this reader understands */
done:
	*out = lines;
	*nout = n;
	return 0;
}

static int write_body(FILE *out, struct line_ref *lines, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		__ownership_readable_span(lines[i].p, lines[i].len);
		if (fwrite(lines[i].p, 1, lines[i].len, out) != lines[i].len) return -1;
		if (fputc('\n', out) == EOF) return -1;
	}
	return 0;
}

static int get_one(const char *path, int pflag, const char *rflag)
{
	struct sfile s;
	const char *rest;
	size_t restlen;
	char sid[64];
	struct line_ref *lines = 0;
	size_t nlines = 0;
	int rc = 0;

	if (read_whole_file(path, &s) != 0) {
		__util_diagf("get: %s: %s\n", path, strerror(errno));
		return 1;
	}
	if (verify_checksum(&s, &rest, &restlen) != 0) {
		__util_diagf("get: %s: not a valid SCCS file (checksum mismatch)\n", path);
		rc = 1;
		goto out;
	}
	if (find_sid(rest, restlen, sid, sizeof sid) != 0) {
		__util_diagf("get: %s: no delta-table entry found\n", path);
		rc = 1;
		goto out;
	}
	if (rflag && strcmp(rflag, sid) != 0) {
		__util_diagf("get: %s: no such delta: %s\n", path, rflag);
		rc = 1;
		goto out;
	}
	if (find_body(rest, restlen, &lines, &nlines) != 0) {
		__util_diagf("get: %s: could not locate delta 1.1's body\n", path);
		rc = 1;
		goto out;
	}

	if (pflag) {
		if (write_body(stdout, lines, nlines) != 0) rc = 1;
		fprintf(stderr, "%s\n%zu lines\n", sid, nlines);
	} else {
		char *dircopy = strdup(path), *basecopy = strdup(path);
		char gpath[4096];
		const char *dir, *base;
		FILE *g;

		if (!dircopy || !basecopy) { free(dircopy); free(basecopy); rc = 1; goto out; }
		dir = dirname(dircopy);
		base = basename(basecopy);
		/* has_sfile_name()'s counterpart in admin.c already enforces
		 * "s.*" on write; a file this reader is handed that lacks it
		 * is not one this project's own admin.c could have produced. */
		if (base[0] != 's' || base[1] != '.' || base[2] == 0) {
			__util_diagf("get: %s: not an SCCS file name (must be \"s.*\")\n", path);
			free(dircopy); free(basecopy);
			rc = 1;
			goto out;
		}
		if (strcmp(dir, ".") == 0) snprintf(gpath, sizeof gpath, "%s", base + 2);
		else snprintf(gpath, sizeof gpath, "%s/%s", dir, base + 2);
		free(dircopy); free(basecopy);

		g = fopen(gpath, "wb");
		if (!g) { __util_diagf("get: %s: %s\n", gpath, strerror(errno)); rc = 1; goto out; }
		/* fclose(g) must run whether or not write_body() failed --
		 * short-circuit || here used to skip it on a write failure,
		 * leaking g (caught by include/stdio.h's file_stream_open
		 * contract on fopen()/fclose()). errno is saved across the
		 * unconditional fclose() so a real write_body() failure is
		 * still what strerror() reports, the same convention
		 * read_whole_file() above already uses for this exact
		 * fclose-after-a-diagnosed-failure shape. */
		if (write_body(g, lines, nlines) != 0) {
			int saved_errno = errno;
			(void)fclose(g);
			errno = saved_errno;
			__util_diagf("get: %s: %s\n", gpath, strerror(errno));
			rc = 1;
		} else if (fclose(g) != 0) {
			__util_diagf("get: %s: %s\n", gpath, strerror(errno));
			rc = 1;
		}
		printf("%s\n%zu lines\n", sid, nlines);
	}

out:
	/* `lines` is still 0 (its initializer) for every early-exit above
	 * that never reached find_body(), so freeing it here unconditionally
	 * is always safe -- one exit path for every route through this
	 * function instead of a free(lines)/free(s.buf) pair repeated at
	 * each one. */
	free(lines);
	free(s.buf);
	return rc;
}

int __util_get_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int pflag = 0, i, status = 0, first_operand;
	const char *rflag = 0;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (a[0] != '-' || a[1] == 0) break;
		if (strcmp(a, "-p") == 0) pflag = 1;
		else if (strcmp(a, "-r") == 0) {
			if (i + 1 >= argc) { __util_diagf("get: -r: option requires an argument\n"); return 1; }
			rflag = argv[++i];
		} else if (strncmp(a, "-r", 2) == 0 && a[2]) {
			rflag = a + 2;
		} else {
			__util_diagf("get: %s: not implemented -- see src/util/get.c\n", a);
			return 1;
		}
	}
	first_operand = i;

	if (first_operand >= argc) {
		__util_diagf("get: missing operand\n");
		return 1;
	}

	for (i = first_operand; i < argc; i++)
		if (get_one(argv[i], pflag, rflag) != 0) status = 1;

	return status;
}

// NOLINTEND(misc-include-cleaner)
