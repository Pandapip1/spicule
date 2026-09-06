/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <mntent.h>: not POSIX (see include/mntent.h's own banner for why it
 * is implemented here anyway).  The closest thing to a spec is the
 * Linux man-pages mntent(3)/getmntent(3) description, which this
 * follows: a struct mntent line is whitespace-separated fields
 * "fsname dir type opts freq passno", freq/passno are optional and
 * default to 0 when the line stops early, and lines that are blank or
 * start with '#' (after leading whitespace) are comments, skipped
 * rather than parsed.
 *
 * Every function below is pure stdio over the FILE * it is given --
 * see include/mntent.h's banner for why that makes this file portable
 * with no platform split, and third_party/libc-test/src/functional/
 * mntent.c for the corpus test this satisfies (it hands
 * getmntent()/getmntent_r() an fmemopen() buffer throughout, never a
 * real system path, which is exactly the part of this interface that
 * needs no OS-specific support).
 */
#include <mntent.h>
#include <string.h>
#include <stdlib.h>

withtok(file_stream_open)
FILE *setmntent(const char *file, const char *mode)
{
	return fopen(file, mode);
}

int endmntent(FILE *f)
{
	/* mntent(3): "endmntent() always returns 1." Errors closing a
	 * read-only mount table are not this caller's problem to react to
	 * differently -- there is nothing left to flush. */
	if (f) (void)fclose(f);
	return 1;
}

/* True for "" too (an empty options field), the same as a real ','-
 * joined options list with nothing before the first comma; getmntent_r
 * never hands back a NULL mnt_opts (a line short even a field for it
 * is rejected below), so callers relying on that per mntent(3) are
 * safe. */
char *hasmntopt(const struct mntent *mnt, const char *opt)
{
	char *s = mnt->mnt_opts;
	size_t len = strlen(opt);

	for (;;) {
		if (!strncmp(s, opt, len) && (s[len] == 0 || s[len] == ','))
			return s;
		s = strchr(s, ',');
		if (!s) return 0;
		s++;
	}
}

int addmntent(FILE *__restrict f, const struct mntent *__restrict mnt)
{
	/* mntent(3): "addmntent() returns 0 on success and 1 on failure." */
	if (fprintf(f, "%s %s %s %s %d %d\n", mnt->mnt_fsname, mnt->mnt_dir,
	    mnt->mnt_type, mnt->mnt_opts, mnt->mnt_freq, mnt->mnt_passno) < 0)
		return 1;
	return 0;
}

struct mntent *getmntent_r(FILE *__restrict f, struct mntent *__restrict mnt,
                            char *__restrict buf, int buflen)
{
	char *p, *save, *fsname, *dir, *type, *opts, *freq, *passno;

	if (!f || !mnt || !buf || buflen <= 0) return 0;

	for (;;) {
		if (!fgets(buf, buflen, f)) return 0;
		p = buf + strlen(buf);
		while (p > buf && (p[-1] == '\n' || p[-1] == '\r')) *--p = 0;
		p = buf;
		while (*p == ' ' || *p == '\t') p++;
		if (*p == 0 || *p == '#') continue;
		break;
	}

	fsname = strtok_r(buf, " \t", &save);
	dir    = fsname ? strtok_r(0, " \t", &save) : 0;
	type   = dir    ? strtok_r(0, " \t", &save) : 0;
	opts   = type   ? strtok_r(0, " \t", &save) : 0;
	if (!opts) return 0; /* fewer than the four mandatory fields */
	freq   = strtok_r(0, " \t", &save);
	passno = freq   ? strtok_r(0, " \t", &save) : 0;

	mnt->mnt_fsname = fsname;
	mnt->mnt_dir    = dir;
	mnt->mnt_type   = type;
	mnt->mnt_opts   = opts;
	mnt->mnt_freq   = freq   ? atoi(freq)   : 0;
	mnt->mnt_passno = passno ? atoi(passno) : 0;
	return mnt;
}

/* mntent(3): "the returned struct...may be overwritten by subsequent
 * calls" -- not thread-safe, same historical contract fgetgrent()/
 * fgetpwent() have (src/misc/grp.c, src/misc/pwd.c). */
struct mntent *getmntent(FILE *f)
{
	static struct mntent mnt;
	static char buf[8192];

	return getmntent_r(f, &mnt, buf, sizeof buf);
}
