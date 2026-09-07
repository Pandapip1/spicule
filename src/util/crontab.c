/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * crontab(1p): `crontab [file]` | `crontab [-e|-l|-r]`
 * https://pubs.opengroup.org/onlinepubs/9699919799/utilities/crontab.html
 *
 * No -u: this system has exactly one user (see pwd.c), so the
 * privileged `-u user` XSI extension (not in the base SYNOPSIS) has
 * no second user to name. Refused as an unrecognized option rather
 * than silently ignored (same rule as touch.c's -d). Every crontab
 * here is $HOME/.spicule/crontabs/crontab (spool.h).
 *
 * Every non-blank, non-comment line must parse as five crontab(5)
 * time fields (crontime.c) plus a command, validated eagerly at
 * install/edit time. A MAILTO=-style assignment line gets its own
 * diagnostic rather than the generic "bad line" one, since crontime.h
 * explains there's no mail transport to honour it with.
 *
 * -e picks $VISUAL then $EDITOR, falling back to this library's own
 * ed(1) (src/util/ed.c) rather than assuming vi exists. A bad edited
 * file aborts the install with the line number and leaves the edits
 * in the temp file (path printed) rather than looping back into the
 * editor automatically -- re-running `crontab -e` is one extra step.
 */
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/wait.h>
#include "util.h"
#include "spool.h"
#include "crontime.h"
#include "libc.h" /* __find_program()/__spawn() */
#include "ownership_stubs.h"

/* True if `line` (past leading blanks) is a crontab(5) env-assignment:
 * an identifier then optional blanks then '='. A real time field
 * never looks like this (digit, '*', or a bare month/dow name), so
 * this can't misfire on a schedule line. */
static int looks_like_assignment(const char *line)
{
	const char *p = line;
	if (!isalpha((unsigned char)*p) && *p != '_') return 0;
	while (isalnum((unsigned char)*p) || *p == '_') p++;
	while (*p == ' ' || *p == '\t') p++;
	return *p == '=';
}

static int split_field(const char **pp, char *out, size_t outsz)
{
	const char *p = *pp;
	size_t n;
	/* spicule.ValidPointer: open finding on this walk (cursor into a
	 * NUL-terminated fgets() buffer); unsafe_assume_string_terminated()
	 * doesn't close it (tried) -- crond.c's identical split_field() too. */
	while (*p == ' ' || *p == '\t') p++;
	n = strcspn(p, " \t\n");
	if (n == 0 || n >= outsz || n > INT_MAX) return -1;
	if (snprintf(out, outsz, "%.*s", (int)n, p) != (int)n) return -1;
	*pp = p + n;
	return 0;
}

/* Validates every non-blank, non-comment line of `f` as a real
 * crontab(5) entry. Returns 0 if the whole file is valid (rewinding
 * `f` back to the start when done), or -1 with *bad_line set to the
 * first offending 1-based line number. */
static int validate_crontab(FILE *f, long *bad_line)
{
	char line[2048];
	long lineno = 0;

	while (fgets(line, sizeof line, f)) {
		const char *p = line;
		char fields[5][256];
		struct crontime ct;
		int i;

		lineno++;
		while (*p == ' ' || *p == '\t') p++;
		if (*p == '\n' || *p == 0 || *p == '#') continue;

		if (looks_like_assignment(p)) {
			*bad_line = lineno;
			return -1;
		}
		for (i = 0; i < 5; i++) {
			if (split_field(&p, fields[i], sizeof fields[i]) < 0) { *bad_line = lineno; return -1; }
		}
		while (*p == ' ' || *p == '\t') p++;
		if (*p == '\n' || *p == 0) { *bad_line = lineno; return -1; } /* no command field */
		if (__crontime_parse(fields[0], fields[1], fields[2], fields[3], fields[4], &ct) < 0) {
			*bad_line = lineno;
			return -1;
		}
	}
	rewind(f);
	return 0;
}

static int do_list(void)
{
	char path[SPICULE_SPOOL_PATH_MAX];
	FILE *f withtok(file_stream_open);
	int c;

	if (!__spool_crontab_path(path, sizeof path)) { __util_diagf("crontab: cannot access crontab spool\n"); return 1; }
	unsafe_assume_string_terminated(path); /* __spool_crontab_path()'s own snprintf() contract */
	f = fopen(path, "r");
	if (!f) {
		__util_diagf("crontab: no crontab for current user\n");
		return 1;
	}
	while ((c = fgetc(f)) != EOF) if (fputc(c, stdout) == EOF) { (void)fclose(f); return 1; }
	(void)fclose(f);
	return fflush(stdout) == 0 ? 0 : 1;
}

static int do_remove(void)
{
	char path[SPICULE_SPOOL_PATH_MAX];

	if (!__spool_crontab_path(path, sizeof path)) { __util_diagf("crontab: cannot access crontab spool\n"); return 1; }
	if (unlink(path) < 0) {
		if (errno == ENOENT) { __util_diagf("crontab: no crontab for current user\n"); return 1; }
		__util_diagf("crontab: cannot remove crontab: %s\n", strerror(errno));
		return 1;
	}
	return 0;
}

/* Installs `src` (already open for reading, positioned at the start)
 * as the new crontab, after validating it. On success, publishes it
 * via spool.h's rename-over idiom and returns 0. On a validation
 * failure, returns -1 with *bad_line set and installs nothing. */
static int install_crontab(FILE *src, long *bad_line)
{
	char path[SPICULE_SPOOL_PATH_MAX], tmp[SPICULE_SPOOL_PATH_MAX];
	FILE *out withtok(file_stream_open);
	int c;

	if (validate_crontab(src, bad_line) < 0) return -1;
	if (!__spool_crontab_path(path, sizeof path)) { errno = ENOENT; return -1; }
	if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) { errno = ENAMETOOLONG; return -1; }

	unsafe_assume_string_terminated(tmp); /* the snprintf() length check above */
	out = fopen(tmp, "w");
	if (!out) return -1;
	while ((c = fgetc(src)) != EOF) {
		if (fputc(c, out) == EOF) {
			/* fclose()/unlink() below are cleanup for the fputc()
			 * failure just diagnosed; save/restore errno around
			 * them so a failure in either does not overwrite the
			 * real write error do_install_from() reports. */
			int saved_errno = errno;
			(void)fclose(out);
			(void)unlink(tmp);
			errno = saved_errno;
			return -1;
		}
	}
	if (fclose(out) != 0) {
		int saved_errno = errno;
		(void)unlink(tmp);
		errno = saved_errno;
		return -1;
	}
	if (rename(tmp, path) < 0) {
		int saved_errno = errno;
		(void)unlink(tmp);
		errno = saved_errno;
		return -1;
	}
	return 0;
}

static int do_install_from(FILE *src)
{
	long bad_line = 0;

	errno = 0;
	if (install_crontab(src, &bad_line) < 0) {
		if (bad_line) {
			__util_diagf("crontab: line %ld: bad crontab entry\n", bad_line);
		} else {
			__util_diagf("crontab: cannot install crontab: %s\n", strerror(errno));
		}
		return 1;
	}
	return 0;
}

static int do_edit(void)
{
	extern char **environ;
	char path[SPICULE_SPOOL_PATH_MAX];
	char tmpl[SPICULE_SPOOL_PATH_MAX];
	char dir[SPICULE_SPOOL_PATH_MAX];
	int fd;
	FILE *cur withtok(file_stream_open), *tf withtok(file_stream_open);
	const char *editor;
	char *resolved;
	char *argv2[3];
	pid_t pid;
	int status;
	long bad_line = 0;

	if (!__spool_crontab_path(path, sizeof path)) { __util_diagf("crontab: cannot access crontab spool\n"); return 1; }
	if (__spool_dir("crontabs", dir, sizeof dir) < 0) { __util_diagf("crontab: cannot access crontab spool\n"); return 1; }
	if (snprintf(tmpl, sizeof tmpl, "%s/crontab.edit.XXXXXX", dir) >= (int)sizeof tmpl) {
		__util_diagf("crontab: path too long\n");
		return 1;
	}
	fd = mkstemp(tmpl);
	if (fd < 0) { __util_diagf("crontab: cannot create temporary file: %s\n", strerror(errno)); return 1; }

	tf = fdopen(fd, "w");
	if (!tf) { (void)close(fd); (void)unlink(tmpl); return 1; }
	unsafe_assume_string_terminated(path); /* __spool_crontab_path()'s own snprintf() contract */
	cur = fopen(path, "r");
	if (cur) {
		int c;
		while ((c = fgetc(cur)) != EOF) fputc(c, tf);
		(void)fclose(cur);
	}
	if (fclose(tf) != 0) {
		__util_diagf("crontab: %s: %s\n", tmpl, strerror(errno));
		(void)unlink(tmpl);
		return 1;
	}

	editor = getenv("VISUAL");
	if (!editor || !*editor) editor = getenv("EDITOR");
	if (!editor || !*editor) editor = "ed";

	resolved = __find_program(editor, 1);
	if (!resolved) {
		__util_diagf("crontab: %s: not found\n", editor);
		(void)unlink(tmpl);
		return 1;
	}
	argv2[0] = resolved;
	argv2[1] = tmpl;
	argv2[2] = 0;
	pid = __spawn(resolved, argv2, environ);
	free(resolved);
	if (pid < 0) {
		__util_diagf("crontab: cannot run editor: %s\n", strerror(errno));
		(void)unlink(tmpl);
		return 1;
	}
	if (waitpid(pid, &status, 0) < 0) {
		__util_diagf("crontab: waitpid: %s\n", strerror(errno));
		(void)unlink(tmpl);
		return 1;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		__util_diagf("crontab: edits left in %s\n", tmpl);
		return 1;
	}

	unsafe_assume_string_terminated(tmpl); /* mkstemp() fills XXXXXX in place, length check above still holds */
	tf = fopen(tmpl, "r");
	if (!tf) { __util_diagf("crontab: cannot reopen %s: %s\n", tmpl, strerror(errno)); return 1; }
	if (install_crontab(tf, &bad_line) < 0) {
		(void)fclose(tf);
		__util_diagf("crontab: line %ld: bad crontab entry -- edits left in %s\n", bad_line, tmpl);
		return 1;
	}
	(void)fclose(tf);
	(void)unlink(tmpl);
	return 0;
}

int __util_crontab_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	if (argc == 2 && !strcmp(argv[1], "-l")) return do_list();
	if (argc == 2 && !strcmp(argv[1], "-r")) return do_remove();
	if (argc == 2 && !strcmp(argv[1], "-e")) return do_edit();
	if (argc == 2 && argv[1][0] != '-') {
		FILE *f = fopen(argv[1], "r");
		int rc;
		if (!f) { __util_diagf("crontab: %s: %s\n", argv[1], strerror(errno)); return 1; }
		rc = do_install_from(f);
		(void)fclose(f);
		return rc;
	}
	if (argc == 1) return do_install_from(stdin);

	__util_diagf("crontab: usage: crontab [file] | crontab [-e|-l|-r]\n");
	return 1;
}
