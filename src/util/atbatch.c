/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * See src/util/atbatch.h for the job file format this writes and why.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include "spool.h"
#include "atbatch.h"
#include "ownership_stubs.h"

/* Identical escaping rule to src/sh/builtin.c's own write_quoted()
 * (bi_set's `set` output) -- see this header's own comment on why the
 * export lines below reuse it rather than a second implementation.
 *
 * ntlibc.ValidPointer: the `*v` walk below has an open "dereference
 * extent is not proven sufficient" finding at every caller (a cwd, an
 * environ entry, or a job command byte -- all genuinely NUL-terminated).
 * Declaring `v withtok(null_terminated)` closes it here but pushes new
 * findings onto every call site instead (tried; net regression), the
 * same open shape src/util/crontab.c's split_field() and
 * src/util/crond.c's identical one already document. */
static int write_quoted(FILE *f, const char *v)
{
	if (fputc('\'', f) == EOF) return -1;
	for (; *v; v++) {
		if (*v == '\'') {
			if (fputs("'\\''", f) < 0) return -1;
		} else if (fputc((unsigned char)*v, f) == EOF) return -1;
	}
	return fputc('\'', f) == EOF ? -1 : 0;
}

int __atbatch_submit(const char *queue, time_t run_at, const char *srcfile,
	char *id_out, size_t id_out_sz)
{
	extern char **environ;
	char dir[NTLIBC_SPOOL_PATH_MAX];
	char path[NTLIBC_SPOOL_PATH_MAX];
	char tmp[NTLIBC_SPOOL_PATH_MAX];
	FILE *f, *src withtok(file_stream_open);
	char *cwd;
	mode_t um;
	char **e;
	char buf[4096];
	size_t nrd;
	int saved_errno;

	src = NULL;
	if (__spool_dir("atjobs", dir, sizeof dir) < 0) return -1;
	f = __spool_new_job(dir, id_out, id_out_sz, path, sizeof path);
	if (!f) return -1;
	if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) {
		(void)fclose(f);
		errno = ENAMETOOLONG;
		return -1;
	}

	cwd = getcwd(0, 0);
	/* umask() has no "peek without changing" form -- set it to 0 and
	 * immediately restore the real value, the standard technique
	 * (there is no window where another thread could observe the
	 * temporary 0: this library has no threads, per every other
	 * "no threads" note elsewhere in this tree). */
	um = umask(0);
	umask(um);

	if (fprintf(f, "#!ntlibc-at-job 1\n#run_at %lld\n#submit_time %lld\n#queue %s\n",
	        (long long)run_at, (long long)time(0), queue) < 0)
		goto fail;
	if (fputs("cd ", f) == EOF) goto fail;
	if (write_quoted(f, cwd ? cwd : "/") < 0) goto fail;
	if (fprintf(f, " || exit 1\numask %04o\n", (unsigned)(um & 07777)) < 0) goto fail;

	for (e = environ; e && *e; e++) {
		size_t namelen = strcspn(*e, "=");
		if (!(*e)[namelen]) continue; /* malformed entry, no '=' -- nothing to export */
		if (fputs("export ", f) == EOF) goto fail;
		__ownership_readable_span(*e, namelen);
		if (fwrite(*e, 1, namelen, f) != namelen) goto fail;
		if (fputc('=', f) == EOF) goto fail;
		if (write_quoted(f, *e + namelen + 1) < 0) goto fail;
		if (fputc('\n', f) == EOF) goto fail;
	}

	if (srcfile) {
		__ownership_string_terminated(srcfile); /* an argv element (src/util/at.c's opt_f) */
		src = fopen(srcfile, "r");
		if (!src) goto fail;
	}
	for (;;) {
		nrd = fread(buf, 1, sizeof buf, srcfile ? src : stdin);
		if (nrd == 0) break;
		{
			size_t i;
			for (i = 0; i < nrd; i++)
				if (fputc((unsigned char)buf[i], f) == EOF) goto fail;
		}
	}
	if (ferror(srcfile ? src : stdin)) goto fail;

	if (src) (void)fclose(src);
	free(cwd);
	if (fclose(f) != 0) return -1;
	if (__spool_publish_job(path) < 0) return -1;
	return 0;

fail:
	saved_errno = errno;
	if (src) (void)fclose(src);
	free(cwd);
	(void)fclose(f);
	(void)unlink(tmp);
	errno = saved_errno;
	return -1;
}
