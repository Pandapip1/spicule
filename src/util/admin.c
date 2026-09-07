/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * admin(1p): SCCS administration -- creates an s.file in the real
 * historical SCCS delta-encoding format (sccsfile(5)), not a fake
 * placeholder; the s.file this writes is byte-for-byte the shape a real
 * historical SCCS admin/get would produce, modulo the narrowing below.
 *
 * Implemented:
 *   admin -i[name] [-t[name]] [-y[comment]] newfile
 *   admin -n [-t[name]] [-y[comment]] newfile...
 *
 *  -i[name]  text for the new file, from `name`, or stdin if omitted.
 *  -n        create with control information but no file data.
 *  -t[name]  descriptive text file. Narrowed here: a name is always
 *            required -- the real, undocumented-by-POSIX behaviour of a
 *            bare -t (delete existing descriptive text on an
 *            already-existing file) doesn't apply to this create-only
 *            scope, so it's refused rather than guessed at.
 *  -y[comment]  comment for the initial delta. When omitted entirely
 *            (not just empty), defaults to the same text real historical
 *            SCCS admin always has: "date and time created
 *            YY/MM/DD HH:MM:SS by USER".
 *
 * Per POSIX: newfile's basename must start "s." and the created file is
 * chmod'd 0444 (both enforced below).
 *
 * Not implemented: the third SYNOPSIS form that modifies an
 * already-existing s.file (`-a`/`-d`/`-m`/`-r`/`-t`/`-y` file...), plus
 * `-h` (checksum audit) and `-z` (checksum recompute) -- this file only
 * ever creates a brand-new s.file. Given an existing operand, or neither
 * `-i` nor `-n`, this refuses with a diagnostic rather than silently
 * doing nothing (same "unsupported option must not look like it worked"
 * rule as src/util/dd.c/touch.c). `-a`/`-d`/`-e`/`-f`/`-m`/`-r` are
 * refused the same way. Every s.file this creates has the fixed initial
 * SID "1.1" (real admin's own default when `-r` is omitted, so a real
 * default, just with no override).
 *
 * This project has no delta(1p), so an s.file created here never grows a
 * second delta -- the user list (^Au/^AU) and flags (^At/^AT) that real
 * admin's maintenance form exists to edit are still written (a
 * structurally complete s.file), just always empty.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <libgen.h>
#include <sys/stat.h>
#include "util.h"

/* The real historical SCCS checksum (sccsfile(5)): sum of all bytes
 * except the first (^Ah) line, in an unsigned short so it wraps at
 * 65536 like historical SCCS. Shared with src/util/get.c's verification
 * of the same value on read. */
unsigned __util_sccs_checksum(const char *buf, size_t len)
{
	unsigned short sum = 0;
	size_t i;
	for (i = 0; i < len; i++) sum = (unsigned short)(sum + (unsigned char)buf[i]);
	return sum;
}

struct line_array {
	char **v;
	size_t n;
	size_t cap;
};

static int line_array_push(struct line_array *a, char *s)
{
	if (a->n >= a->cap) {
		size_t newcap;
		char **g;
		if (!__util_array_capacity(a->cap, a->n, 1, 16, sizeof *a->v, &newcap)) return 0;
		g = __util_reallocarray(a->v, newcap, sizeof *a->v);
		if (!g) return 0;
		a->v = g;
		a->cap = newcap;
	}
	a->v[a->n++] = s;
	return 1;
}

static void line_array_free(struct line_array *a)
{
	size_t i;
	for (i = 0; i < a->n; i++) free(a->v[i]);
	free(a->v);
}

/* Reads every line of `f` into `out` (freshly malloc'd copies, no
 * trailing '\n'). A final line with no trailing newline is still kept
 * -- getline() itself returns it, newline or not. */
static int read_lines(FILE *f, struct line_array *out)
{
	char *buf = 0;
	size_t bufcap = 0;
	ssize_t got;

	memset(out, 0, sizeof *out);
	while ((got = getline(&buf, &bufcap, f)) > 0) {
		size_t len = (size_t)got, bytes;
		char *copy;
		if (buf[len - 1] == '\n') len--;
		if (!__util_size_add(len, 1, &bytes)) { free(buf); line_array_free(out); return 0; }
		copy = malloc(bytes);
		if (!copy) { free(buf); line_array_free(out); return 0; }
		for (size_t i = 0; i < len; i++) copy[i] = buf[i];
		copy[len] = 0;
		if (!line_array_push(out, copy)) { free(copy); free(buf); line_array_free(out); return 0; }
	}
	free(buf);
	return 1;
}

/* newfile's own naming rule, quoted in this file's own header comment
 * above: "All SCCS files must follow the naming pattern s.filename". */
static int has_sfile_name(const char *path)
{
	char *copy = strdup(path);
	char *bn;
	int ok;
	if (!copy) return 0;
	bn = basename(copy);
	ok = bn[0] == 's' && bn[1] == '.' && bn[2] != 0;
	free(copy);
	return ok;
}

static void write_comment(FILE *rest, const char *comment)
{
	const char *p = comment;
	for (;;) {
		const char *nl = strchr(p, '\n');
		size_t seglen = nl ? (size_t)(nl - p) : strlen(p);
		fprintf(rest, "\001c %.*s\n", (int)seglen, p);
		if (!nl) break;
		p = nl + 1;
	}
}

/* Builds and writes one s.file: the checksum line, then everything
 * captured via open_memstream() below (delta table, empty user list,
 * descriptive text, and the input as one ^AI 1/^AE 1 body block). */
static int create_one(const char *path, const struct line_array *body,
	const struct line_array *text, const char *comment)
{
	char nowbuf[32], *username;
	struct passwd *pw;
	time_t now;
	struct tm tmv;
	char *buf = 0;
	size_t buflen = 0, i;
	unsigned sum;
	FILE *rest, *out;

	if (access(path, F_OK) == 0) {
		__util_diagf("admin: %s: file already exists\n", path);
		return 1;
	}

	now = time(0);
	if (!localtime_r(&now, &tmv)) { __util_diagf("admin: %s: localtime failed\n", path); return 1; }
	strftime(nowbuf, sizeof nowbuf, "%y/%m/%d %H:%M:%S", &tmv);

	pw = getpwuid(getuid());
	username = pw ? pw->pw_name : 0;

	rest = open_memstream(&buf, &buflen);
	if (!rest) { __util_diagf("admin: %s: %s\n", path, strerror(errno)); return 1; }

	fprintf(rest, "\001s %05zu/00000/00000\n", body->n);
	if (username) fprintf(rest, "\001d D 1.1 %s %s 1 0\n", nowbuf, username);
	else fprintf(rest, "\001d D 1.1 %s %lu 1 0\n", nowbuf, (unsigned long)getuid());
	write_comment(rest, comment);
	fprintf(rest, "\001e\n");
	fprintf(rest, "\001u\n\001U\n");
	fprintf(rest, "\001t\n");
	for (i = 0; i < text->n; i++) fprintf(rest, "%s\n", text->v[i]);
	fprintf(rest, "\001T\n");
	fprintf(rest, "\001I 1\n");
	for (i = 0; i < body->n; i++) fprintf(rest, "%s\n", body->v[i]);
	fprintf(rest, "\001E 1\n");

	if (fclose(rest) != 0) { free(buf); __util_diagf("admin: %s: %s\n", path, strerror(errno)); return 1; }

	sum = __util_sccs_checksum(buf, buflen);

	out = fopen(path, "wb");
	if (!out) { __util_diagf("admin: %s: %s\n", path, strerror(errno)); free(buf); return 1; }
	fprintf(out, "\001h%05u\n", sum);
	if (fwrite(buf, 1, buflen, out) != buflen) {
		__util_diagf("admin: %s: %s\n", path, strerror(errno));
		free(buf); (void)fclose(out); return 1;
	}
	free(buf);
	if (fclose(out) != 0) { __util_diagf("admin: %s: %s\n", path, strerror(errno)); return 1; }

	/* "New SCCS files shall be given read-only permission mode." */
	if (chmod(path, 0444) != 0) {
		__util_diagf("admin: %s: %s\n", path, strerror(errno));
		return 1;
	}
	return 0;
}

int __util_admin_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int have_i = 0, have_n = 0, have_t = 0, have_y = 0;
	const char *iname = 0, *tname = 0, *ycomment = 0;
	struct line_array body, text;
	char default_comment[64];
	const char *comment;
	int i, first_operand = 0, status = 0;

	memset(&body, 0, sizeof body);
	memset(&text, 0, sizeof text);

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (a[0] != '-' || a[1] == 0) break;
		if (strcmp(a, "-n") == 0) { have_n = 1; }
		else if (strncmp(a, "-i", 2) == 0) { have_i = 1; iname = a + 2; }
		else if (strncmp(a, "-t", 2) == 0) { have_t = 1; tname = a + 2; }
		else if (strncmp(a, "-y", 2) == 0) { have_y = 1; ycomment = a + 2; }
		else {
			__util_diagf("admin: %s: not implemented -- see src/util/admin.c\n", a);
			return 1;
		}
	}
	first_operand = i;

	if (!have_i && !have_n) {
		__util_diagf("admin: modifying an existing SCCS file is not implemented -- see src/util/admin.c\n");
		return 1;
	}
	if (first_operand >= argc) {
		__util_diagf("admin: missing operand\n");
		return 2;
	}
	if (have_i && argc - first_operand > 1) {
		__util_diagf("admin: -i: too many operands\n");
		return 2;
	}

	/* -i's body (or none, for a bare -n). */
	if (have_i) {
		/* use_stdin, not `f != stdin`, decides the fclose() below -- the
		 * checker can't prove opaque pointers unequal, so a direct
		 * comparison makes the fopen() allocation look conditionally
		 * leaked (same idiom as src/util/join.c's read_all()). */
		int use_stdin = !*iname;
		FILE *f = use_stdin ? stdin : fopen(iname, "r");
		if (!f) { __util_diagf("admin: %s: %s\n", iname, strerror(errno)); return 1; }
		if (!read_lines(f, &body)) {
			__util_diagf("admin: %s: %s\n", *iname ? iname : "(standard input)", strerror(errno));
			if (!use_stdin) (void)fclose(f);
			return 1;
		}
		if (!use_stdin) (void)fclose(f);
	}

	/* -t's descriptive text, if given (a name is always required here --
	 * see header). */
	if (have_t) {
		FILE *f;
		if (!*tname) {
			__util_diagf("admin: -t: file name required -- see src/util/admin.c\n");
			line_array_free(&body);
			return 1;
		}
		f = fopen(tname, "r");
		if (!f) {
			__util_diagf("admin: %s: %s\n", tname, strerror(errno));
			line_array_free(&body);
			return 1;
		}
		if (!read_lines(f, &text)) {
			__util_diagf("admin: %s: %s\n", tname, strerror(errno));
			(void)fclose(f); line_array_free(&body);
			return 1;
		}
		(void)fclose(f);
	}

	/* -y's comment, or the default synthesized below when -y is omitted
	 * entirely (see header). */
	if (have_y) {
		comment = ycomment;
	} else {
		time_t now = time(0);
		struct tm tmv;
		char nowbuf[32];
		struct passwd *pw;
		if (localtime_r(&now, &tmv)) strftime(nowbuf, sizeof nowbuf, "%y/%m/%d %H:%M:%S", &tmv);
		else nowbuf[0] = 0;
		pw = getpwuid(getuid());
		snprintf(default_comment, sizeof default_comment, "date and time created %s by %s",
			nowbuf, pw ? pw->pw_name : "unknown");
		comment = default_comment;
	}

	for (i = first_operand; i < argc; i++) {
		const char *path = argv[i];
		if (!has_sfile_name(path)) {
			__util_diagf("admin: %s: not an SCCS file name (must be \"s.*\")\n", path);
			status = 1;
			continue;
		}
		if (create_one(path, &body, &text, comment) != 0) status = 1;
	}

	line_array_free(&body);
	line_array_free(&text);
	return status;
}

// NOLINTEND(misc-include-cleaner)
