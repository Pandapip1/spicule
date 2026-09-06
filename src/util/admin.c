/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * admin(1p): SCCS (Source Code Control System) administration -- the
 * utility that creates an `s.file`.
 *
 * ---- why this exists at all --------------------------------------------
 *
 * admin(1p) is functionally obsolescent -- SCCS has been displaced by
 * every later version-control system for decades, and no real workflow
 * this project's own bootstrap use case needs touches it -- but is
 * implemented here anyway, as a well-specified, bounded XCU page worth
 * having.  Implemented here: real SCCS delta-encoding text format
 * (term(5)-equivalent: sccsfile(5)),
 * not a fake placeholder -- an `s.file` this writes is byte-for-byte the
 * same shape a real historical SCCS `admin`/`get` would produce for the
 * same input, modulo the deliberate feature narrowing documented below.
 *
 * ---- SYNOPSIS / OPTIONS actually implemented (POSIX admin.html,
 * verified against the live spec text before writing this file) --------
 *
 *   admin -i[name] [-t[name]] [-y[comment]] newfile
 *   admin -n [-t[name]] [-y[comment]] newfile...
 *
 *  -i[name]  "Specify the name of a file from which the text for a new
 *             SCCS file shall be taken... If the -i option is used, but
 *             the name option-argument is omitted, the text shall be
 *             obtained by reading the standard input."
 *  -n        "Create a new SCCS file. When -n is used without -i, the
 *             SCCS file shall be created with control information but
 *             without any file data."
 *  -t[name]  "Specify the name of a file from which descriptive text for
 *             the SCCS file shall be taken." Narrowed here: a name is
 *             always required (no bare -t) -- the real, undocumented-by-
 *             POSIX default behaviour of a bare -t is "delete existing
 *             descriptive text" on an already-existing file, which does
 *             not apply to this implementation's create-only scope
 *             below, so it is refused rather than guessed at.
 *  -y[comment]  "Insert the comment text into the SCCS file as a comment
 *             for the initial delta." When -y is omitted entirely (not
 *             just given empty), this implementation synthesizes the
 *             same default real historical SCCS admin has always used:
 *             "date and time created YY/MM/DD HH:MM:SS by USER".
 *
 * Per POSIX's own OPERANDS: "newfile: A pathname of an SCCS file to be
 * created," and DESCRIPTION: "All SCCS files must follow the naming
 * pattern s.filename" and "New SCCS files shall be given read-only
 * permission mode" -- both enforced below (basename must start "s.",
 * chmod 0444 after writing).
 *
 * ---- what is deliberately NOT implemented, and why ---------------------
 *
 * The admin.html SYNOPSIS also lists a third form -- `admin [-a login]
 * [-d flag] [-m mrlist] [-r rel] [-t[name]] [-y[comment]] file...`,
 * modifying parameters of an ALREADY-EXISTING s.file -- plus `-h`
 * (checksum audit) and `-z` (checksum recompute). None of that is
 * implemented: this file only ever creates a brand-new s.file (the
 * `-i`/`-n` forms above). Given an operand that already exists, or no
 * `-i`/`-n` at all, this refuses loudly with a diagnostic rather than
 * silently doing nothing -- this project's established "an unsupported
 * option must not look like it worked" rule (src/util/dd.c, src/util/
 * touch.c's own header comments make the same call). `-a`/`-d`/`-e`/
 * `-f`/`-m`/`-r` are refused the same way if given at all. `-r` in
 * particular means every s.file this creates has the same fixed initial
 * SID, "1.1" -- real admin's own default when `-r` is omitted, so this
 * is a real default, not a fabricated one, just with no override.
 *
 * Since there is no delta(1p) in this project (see this file's own
 * "round-trip scope" note below and src/util/get.c's header comment),
 * an s.file this creates never grows a second delta -- so the user list
 * (-a/-e) and flags (-f) that real admin's ongoing-maintenance form
 * exists to edit have nothing to matter for; the ^Au/^AU and ^At/^AT
 * brackets are still written (a structurally complete, real s.file),
 * just always empty/single-delta.
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

/* The real historical SCCS checksum: sccsfile(5), "the sum of all
 * characters [bytes], except those contained in the first [^Ah] line",
 * accumulated in a real unsigned short so it wraps at 65536 the same
 * way historical SCCS implementations (storing it in exactly that C
 * type) always did -- declared in src/internal/util.h, shared with
 * src/util/get.c's verification of the same value on read. */
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
 * captured through open_memstream() below (the delta table, empty user
 * list, descriptive text, and the whole input as one ^AI 1/^AE 1 body
 * block -- see this file's own header comment for the exact shape and
 * every section this omits). */
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
		FILE *f = *iname ? fopen(iname, "r") : stdin;
		if (!f) { __util_diagf("admin: %s: %s\n", iname, strerror(errno)); return 1; }
		if (!read_lines(f, &body)) {
			__util_diagf("admin: %s: %s\n", *iname ? iname : "(standard input)", strerror(errno));
			if (f != stdin) (void)fclose(f);
			return 1;
		}
		if (f != stdin) (void)fclose(f);
	}

	/* -t's descriptive text, if given -- required to name a real file
	 * in this implementation's narrowed scope (this file's own header
	 * comment). */
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

	/* -y's comment, or the same default real historical SCCS admin
	 * synthesizes when -y is omitted entirely (this file's own header
	 * comment). */
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
