/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * at(1p):
 *
 *   at [-m] [-f file] [-q queuename] -t time_arg
 *   at [-m] [-f file] [-q queuename] timespec...
 *   at -r at_job_id...
 *   at -l -q queuename
 *   at -l [at_job_id...]
 *
 * Fetched and checked directly against
 * https://pubs.opengroup.org/onlinepubs/9699919799/utilities/at.html
 * before writing this file (SYNOPSIS/OPTIONS/OPERANDS quoted in the
 * banner above and in src/util/attime.h's own header). Submission
 * (`timespec...` or `-t time_arg`) writes a job to the spool via
 * src/util/atbatch.c's __atbatch_submit(); the job actually runs
 * later, out-of-process, when src/util/atd.c's daemon notices it is
 * due -- see that file's own header for the daemon side of this
 * split, and bin/atd.c/src/sh/builtin.c for why atd is a standalone
 * executable only, never a shell builtin.
 *
 * `-t time_arg`: "has the format as specified by the touch -t time
 * utility" -- touch(1p)'s own `[[CC]YY]MMDDhhmm[.SS]`, parsed here by
 * the identical two-digit-field logic src/util/touch.c's own
 * parse_touch_t() uses (re-implemented rather than shared: it is
 * ~30 lines, entirely self-contained, and touch.c's version is
 * static -- not worth a third header for something this small, the
 * same judgment call src/internal/util.h's own comment on cp/mv/rm's
 * *shared* helpers draws the line against for genuinely small,
 * non-duplicated logic).
 *
 * -m: accepted (mail-on-completion is real at(1p) SYNOPSIS, so a
 * script using it must not fail with "unknown option"), but every
 * job's output is captured to `<id>.out` regardless of whether -m was
 * given -- see src/util/atbatch.h's own header for why there is no
 * mail transport to make -m's mail-vs-discard distinction meaningful
 * here, and why "always capture" is the honest single behaviour.
 *
 * EXIT STATUS: at.html "0 ... successfully submitted, removed, or
 * listed a job or jobs. >0 An error occurred." -- this file uses 1 for
 * every error case, the same "1 within the >0 the standard leaves to
 * the implementation" convention src/util/util_time.c and others in
 * this tree already use.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include "util.h"
#include "spool.h"
#include "attime.h"
#include "atbatch.h"

static int read2(const char *s, int *out)
{
	if (s[0] < '0' || s[0] > '9' || s[1] < '0' || s[1] > '9') return -1;
	*out = (s[0] - '0') * 10 + (s[1] - '0');
	return 0;
}

/* touch(1p) -t: "[[CC]YY]MMDDhhmm[.SS]" -- see this file's own header
 * for why this is a self-contained re-implementation of
 * src/util/touch.c's parse_touch_t() rather than a shared function. */
static int parse_dash_t(const char *spec, time_t *out)
{
	size_t mainlen = strcspn(spec, ".");
	const char *dot = spec[mainlen] ? spec + mainlen : 0;
	int sec = 0, cc = -1, yy = -1, mm, dd, hh, mi;
	struct tm tmv;
	time_t t;

	if (dot) {
		if (!dot[1] || !dot[2] || dot[3] || read2(dot + 1, &sec) < 0 || sec > 60)
			return -1;
	}
	switch (mainlen) {
	case 8:
		if (read2(spec, &mm) < 0 || read2(spec + 2, &dd) < 0 ||
		    read2(spec + 4, &hh) < 0 || read2(spec + 6, &mi) < 0) return -1;
		break;
	case 10:
		if (read2(spec, &yy) < 0 || read2(spec + 2, &mm) < 0 ||
		    read2(spec + 4, &dd) < 0 || read2(spec + 6, &hh) < 0 ||
		    read2(spec + 8, &mi) < 0) return -1;
		break;
	case 12:
		if (read2(spec, &cc) < 0 || read2(spec + 2, &yy) < 0 ||
		    read2(spec + 4, &mm) < 0 || read2(spec + 6, &dd) < 0 ||
		    read2(spec + 8, &hh) < 0 || read2(spec + 10, &mi) < 0) return -1;
		break;
	default:
		return -1;
	}
	if (mm < 1 || mm > 12 || dd < 1 || dd > 31 || hh > 23 || mi > 59) return -1;

	memset(&tmv, 0, sizeof tmv);
	tmv.tm_mon = mm - 1;
	tmv.tm_mday = dd;
	tmv.tm_hour = hh;
	tmv.tm_min = mi;
	tmv.tm_sec = sec;
	tmv.tm_isdst = -1;
	if (cc >= 0) {
		tmv.tm_year = cc * 100 + yy - 1900;
	} else if (yy >= 0) {
		tmv.tm_year = (yy >= 69 ? 1900 + yy : 2000 + yy) - 1900;
	} else {
		time_t now = time(0);
		struct tm *cur = localtime(&now);
		if (!cur) return -1;
		tmv.tm_year = cur->tm_year;
	}
	t = mktime(&tmv);
	if (t == (time_t)-1) return -1;
	*out = t;
	return 0;
}

static int job_path(const char *dir, const char *id, const char *suffix, char *out, size_t outsz)
{
	int n = snprintf(out, outsz, "%s/%s.%s", dir, id, suffix);
	return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
}

static void print_job_line(FILE *out, const char *id, time_t run_at, const char *queue)
{
	char tbuf[32];
	char *c = ctime_r(&run_at, tbuf);
	size_t l = c ? strcspn(c, "\n") : 0;
	if (c) c[l] = 0;
	fprintf(out, "%s\t%s%s%s\n", id, c ? c : "?", *queue ? " " : "", queue);
}

static int do_list(const char *dir, const char *qfilter, char **ids, int nids)
{
	int status = 0;

	if (nids > 0) {
		int i;
		for (i = 0; i < nids; i++) {
			char path[NTLIBC_SPOOL_PATH_MAX];
			time_t run_at;
			char queue[32];
			if (job_path(dir, ids[i], "job", path, sizeof path) < 0 ||
			    __spool_job_header(path, &run_at, queue, sizeof queue) < 0) {
				__util_diagf("at: %s: no such job\n", ids[i]);
				status = 1;
				continue;
			}
			print_job_line(stdout, ids[i], run_at, queue);
		}
		return status;
	}

	{
		DIR *dp = opendir(dir);
		struct dirent *de;
		if (!dp) {
			/* No spool directory yet means no jobs at all -- not an
			 * error (this is the ordinary "nothing has been
			 * submitted yet" state, not a broken installation). */
			return errno == ENOENT ? 0 : 1;
		}
		while ((de = readdir(dp)) != 0) {
			size_t l = strlen(de->d_name);
			char path[NTLIBC_SPOOL_PATH_MAX];
			time_t run_at;
			char queue[32];
			char id[64];
			if (l <= 4 || strcmp(de->d_name + l - 4, ".job")) continue;
			if (l - 4 >= sizeof id) continue;
			memcpy(id, de->d_name, l - 4);
			id[l - 4] = 0;
			if (job_path(dir, id, "job", path, sizeof path) < 0 ||
			    __spool_job_header(path, &run_at, queue, sizeof queue) < 0)
				continue;
			if (qfilter && strcmp(queue, qfilter)) continue;
			print_job_line(stdout, id, run_at, queue);
		}
		(void)closedir(dp);
	}
	return status;
}

static int do_remove(const char *dir, char **ids, int nids)
{
	int status = 0;
	int i;

	for (i = 0; i < nids; i++) {
		char jpath[NTLIBC_SPOOL_PATH_MAX], opath[NTLIBC_SPOOL_PATH_MAX];
		int had = 0;
		if (job_path(dir, ids[i], "job", jpath, sizeof jpath) == 0 && unlink(jpath) == 0)
			had = 1;
		if (job_path(dir, ids[i], "out", opath, sizeof opath) == 0)
			(void)unlink(opath); /* fine if it never ran yet -- ENOENT is not an error here */
		if (!had) {
			__util_diagf("at: %s: no such job\n", ids[i]);
			status = 1;
		}
	}
	return status;
}

int __util_at_main(int argc, char **argv)
{
	int i = 1;
	int opt_l = 0, opt_r = 0;
	const char *opt_f = 0, *opt_q = 0, *opt_t = 0;
	char **rest;
	int nrest = 0;
	char dir[NTLIBC_SPOOL_PATH_MAX];

	rest = __util_mallocarray((size_t)argc + 1, sizeof(char *));
	if (!rest) { __util_diagf("at: out of memory\n"); return 1; }

	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!strcmp(a, "--")) { i++; break; }
		if (!strcmp(a, "-m")) continue;
		if (!strcmp(a, "-l")) { opt_l = 1; continue; }
		if (!strcmp(a, "-r")) { opt_r = 1; continue; }
		if (!strcmp(a, "-f")) {
			if (++i >= argc) { __util_diagf("at: -f: option requires an argument\n"); free(rest); return 1; }
			opt_f = argv[i];
			continue;
		}
		if (!strcmp(a, "-q")) {
			if (++i >= argc) { __util_diagf("at: -q: option requires an argument\n"); free(rest); return 1; }
			opt_q = argv[i];
			continue;
		}
		if (!strcmp(a, "-t")) {
			if (++i >= argc) { __util_diagf("at: -t: option requires an argument\n"); free(rest); return 1; }
			opt_t = argv[i];
			continue;
		}
		if (a[0] == '-' && a[1]) {
			__util_diagf("at: %s: invalid option\n", a);
			free(rest);
			return 1;
		}
		break;
	}
	for (; i < argc; i++) rest[nrest++] = argv[i];

	if (__spool_dir("atjobs", dir, sizeof dir) < 0) {
		__util_diagf("at: cannot access job spool: %s\n", strerror(errno));
		free(rest);
		return 1;
	}

	if (opt_r) {
		int status;
		if (nrest == 0) { __util_diagf("at: -r: at least one job identifier required\n"); free(rest); return 1; }
		status = do_remove(dir, rest, nrest);
		free(rest);
		return status;
	}
	if (opt_l) {
		int status = do_list(dir, opt_q, rest, nrest);
		free(rest);
		return status;
	}

	{
		time_t run_at;
		char id[64];
		char queue[2];

		queue[0] = opt_q && opt_q[0] ? opt_q[0] : 'a';
		queue[1] = 0;

		if (opt_t) {
			if (parse_dash_t(opt_t, &run_at) < 0) {
				__util_diagf("at: %s: invalid time\n", opt_t);
				free(rest);
				return 1;
			}
			if (nrest != 0) {
				__util_diagf("at: extra operands with -t\n");
				free(rest);
				return 1;
			}
		} else {
			int consumed;
			if (nrest == 0) {
				__util_diagf("at: missing time specification\n");
				free(rest);
				return 1;
			}
			consumed = __attime_parse(rest, nrest, time(0), &run_at);
			if (consumed < 0 || consumed != nrest) {
				__util_diagf("at: invalid time specification\n");
				free(rest);
				return 1;
			}
		}
		free(rest);

		if (__atbatch_submit(queue, run_at, opt_f, id, sizeof id) < 0) {
			__util_diagf("at: cannot submit job: %s\n", strerror(errno));
			return 1;
		}
		{
			char tbuf[32];
			char *c = ctime_r(&run_at, tbuf);
			if (c) c[strcspn(c, "\n")] = 0;
			fprintf(stderr, "job %s at %s\n", id, c ? c : "?");
		}
		return 0;
	}
}
