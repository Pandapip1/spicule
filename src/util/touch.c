/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * touch(1p): `touch [-acm] [-r ref_file|-t time] file...`
 *
 * OPTIONS:
 *  -a  "Change the access time of file.  Do not change the modification
 *       time unless -m is also specified."
 *  -c  "Do not create a specified file if it does not exist.  Do not
 *       write any diagnostic messages concerning this condition."
 *  -m  "Change the modification time of file.  Do not change the access
 *       time unless -a is also specified."
 *  -r ref_file  "Use the corresponding time of the file named by the
 *       pathname ref_file instead of the current time."
 *  -t time  "[[CC]YY]MMDDhhmm[.SS]" -- CC the century, YY the year within
 *       it, MM/DD/hh/mm/SS the usual calendar fields.
 *
 * "Neither -a nor -m" and "both -a and -m" are the same case per the two
 * quotes above (each says the *other* time is left alone only when its
 * own flag is absent) -- both times get updated.
 *
 * EXIT STATUS: "0 The utility executed successfully and all requested
 * changes were made." ">0 An error occurred." -- diagnose-and-continue,
 * same shape as this project's other utilities.
 *
 * -d date_time (ISO 8601, with optional fractional seconds and a
 * timezone offset) is a real touch(1p) option that is deliberately not
 * implemented -- refused loudly with a diagnostic and a nonzero exit,
 * per this project's "refuse rather than silently ignore" rule for
 * unsupported options (see bi_set's own comment on exactly this point),
 * rather than parsing only part of ISO 8601 and getting the unusual
 * cases (a timezone offset, a leap second, a truncated year) silently
 * wrong.  -t's fixed-width numeric format has no such open-ended
 * grammar and is implemented in full below.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "util.h"

/* Every numeric field in -t is exactly two decimal digits. */
static int read_two_digits(const char *s, int *out)
{
	if (s[0] < '0' || s[0] > '9' || s[1] < '0' || s[1] > '9') return -1;
	*out = (s[0] - '0') * 10 + (s[1] - '0');
	return 0;
}

/* touch(1p) -t: "[[CC]YY]MMDDhhmm[.SS]". out is never NULL at its one
 * call site (the address of a stack local). */
__attribute__((nonnull(2)))
static int parse_touch_t(const char *spec, struct timespec *out)
{
	size_t mainlen = strcspn(spec, ".");
	const char *dot = spec[mainlen] ? spec + mainlen : 0;
	int sec = 0, cc = -1, yy = -1, mm, dd, hh, mi;
	struct tm tmv;
	time_t t;

	if (dot) {
		if (!dot[1] || !dot[2] || dot[3] ||
		    read_two_digits(dot + 1, &sec) < 0 || sec > 60)
			return -1;
	}

	switch (mainlen) {
	case 8: /* MMDDhhmm */
		if (read_two_digits(spec, &mm) < 0 || read_two_digits(spec + 2, &dd) < 0 ||
		    read_two_digits(spec + 4, &hh) < 0 || read_two_digits(spec + 6, &mi) < 0)
			return -1;
		break;
	case 10: /* YYMMDDhhmm */
		if (read_two_digits(spec, &yy) < 0 || read_two_digits(spec + 2, &mm) < 0 ||
		    read_two_digits(spec + 4, &dd) < 0 || read_two_digits(spec + 6, &hh) < 0 ||
		    read_two_digits(spec + 8, &mi) < 0)
			return -1;
		break;
	case 12: /* CCYYMMDDhhmm */
		if (read_two_digits(spec, &cc) < 0 || read_two_digits(spec + 2, &yy) < 0 ||
		    read_two_digits(spec + 4, &mm) < 0 || read_two_digits(spec + 6, &dd) < 0 ||
		    read_two_digits(spec + 8, &hh) < 0 || read_two_digits(spec + 10, &mi) < 0)
			return -1;
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
		/* "If the YY subfield is in the range [69,99], the year
		 * shall be computed as 1900 + YY; ... if it is in the range
		 * [00,68], the year shall be computed as 2000 + YY." */
		tmv.tm_year = (yy >= 69 ? 1900 + yy : 2000 + yy) - 1900;
	} else {
		time_t now = time(0);
		struct tm *cur = localtime(&now);
		if (!cur) return -1;
		tmv.tm_year = cur->tm_year;
	}

	t = mktime(&tmv);
	if (t == (time_t)-1) return -1;
	out->tv_sec = t;
	out->tv_nsec = 0;
	return 0;
}

int __util_touch_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i, fail = 0;
	int opt_a = 0, opt_m = 0, opt_c = 0;
	const char *ref = 0;
	const char *tspec = 0;
	/* Keep the fallback value defined even if a future option path changes
	 * have_explicit without installing both timestamps. */
	struct timespec want[2] = {{0, 0}, {0, 0}};
	int have_explicit = 0;

	/* ntlibc.ValidPointer cannot prove argv[i][0] nonnull here: the
	 * dereference sits directly inside this loop's compound condition
	 * (see src/util/rmdir.c's identical, already-documented case for the
	 * same known checker gap, not a real bug -- argv[i] for i < argc is
	 * always live). */
	for (i = 1; i < argc && argv[i][0] == '-' && argv[i][1]; i++) {
		const char *a = argv[i];
		size_t option_len;
		if (!strcmp(a, "--")) { i++; break; }
		if (!strcmp(a, "-d")) {
			__util_diagf("touch: -d: not implemented -- see src/util/touch.c\n");
			return 1;
		}
		if (!strcmp(a, "-r")) {
			if (i + 1 >= argc) { __util_diagf("touch: -r: option requires an argument\n"); return 1; }
			ref = argv[++i];
			continue;
		}
		if (!strcmp(a, "-t")) {
			if (i + 1 >= argc) { __util_diagf("touch: -t: option requires an argument\n"); return 1; }
			tspec = argv[++i];
			continue;
		}
		option_len = strspn(a + 1, "acm");
		if (a[1] != 0 && a[option_len + 1] == 0) {
			if (strchr(a, 'a')) opt_a = 1;
			if (strchr(a, 'c')) opt_c = 1;
			if (strchr(a, 'm')) opt_m = 1;
			continue;
		}
		__util_diagf("touch: %s: invalid option\n", a);
		return 1;
	}
	if (i >= argc) {
		__util_diagf("touch: missing operand\n");
		return 1;
	}
	if (ref && tspec) {
		__util_diagf("touch: -r and -t are mutually exclusive\n");
		return 1;
	}

	if (ref) {
		struct stat st;
		if (stat(ref, &st) != 0) {
			__util_diagf("touch: %s: %s\n", ref, strerror(errno));
			return 1;
		}
		want[0] = st.st_atim;
		want[1] = st.st_mtim;
		have_explicit = 1;
	} else if (tspec) {
		struct timespec t;
		if (parse_touch_t(tspec, &t) < 0) {
			__util_diagf("touch: %s: invalid time\n", tspec);
			return 1;
		}
		want[0] = t;
		want[1] = t;
		have_explicit = 1;
	}

	for (; i < argc; i++) {
		struct timespec ts[2];
		int fd;

		if (access(argv[i], F_OK) != 0) {
			/* "-c ... Do not write any diagnostic messages
			 * concerning this condition" -- a missing file under
			 * -c is skipped entirely, not even counted as a
			 * failure. */
			if (opt_c) continue;
			fd = open(argv[i], O_CREAT | O_WRONLY, 0666);
			if (fd < 0) {
				__util_diagf("touch: %s: %s\n", argv[i], strerror(errno));
				fail = 1;
				continue;
			}
			if (close(fd) < 0) {
				__util_diagf("touch: %s: %s\n", argv[i], strerror(errno));
				fail = 1;
				continue;
			}
		}

		if (have_explicit) {
			ts[0] = want[0];
			ts[1] = want[1];
		} else {
			ts[0].tv_sec = 0; ts[0].tv_nsec = UTIME_NOW;
			ts[1].tv_sec = 0; ts[1].tv_nsec = UTIME_NOW;
		}
		if (opt_a && !opt_m) ts[1].tv_nsec = UTIME_OMIT;
		else if (opt_m && !opt_a) ts[0].tv_nsec = UTIME_OMIT;

		if (utimensat(AT_FDCWD, argv[i], ts, 0) != 0) {
			__util_diagf("touch: %s: %s\n", argv[i], strerror(errno));
			fail = 1;
		}
	}
	return fail;
}

// NOLINTEND(misc-include-cleaner)
