/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The job-submission logic genuinely shared by at(1p) (src/util/at.c)
 * and batch(1p) (src/util/batch.c) -- batch(1p)'s own DESCRIPTION
 * states it plainly: "It shall be the equivalent of the command: at
 * -q b -m now". Everything from "-t time_arg is really touch(1p)'s
 * own [[CC]YY]MMDDhhmm[.SS] grammar" down to "how a job file is
 * structured so atd (src/util/atd.c) can execute it later" belongs
 * here once, not duplicated in both files or force-fit into one
 * combined main() that would have to fake batch(1p)'s "no options"
 * SYNOPSIS on top of at(1p)'s real one.
 *
 * JOB FILE FORMAT
 * -----------------
 * A submitted job is a real, directly-executable `sh` script (see
 * src/internal/util.h: this library's own `sh` is what atd invokes
 * it with), so atd never needs a second interpreter or a hand-rolled
 * re-parse of the command text -- only its own three `#`-prefixed
 * header lines, which are simultaneously valid shell comments (so
 * `sh` skips them without any special-casing) and the one place atd
 * looks to answer "is this job due yet":
 *
 *   #!ntlibc-at-job 1
 *   #run_at <epoch seconds, decimal>
 *   #submit_time <epoch seconds, decimal>
 *   #queue <one letter>
 *   cd '<captured cwd>' || exit 1
 *   umask <captured umask, 4 octal digits>
 *   export 'NAME'='value'
 *   ... (one export line per captured environment variable)
 *   <the job body -- stdin's or -f file's bytes, verbatim>
 *
 * Environment values are single-quoted the same way src/sh/builtin.c's
 * bi_set() already quotes `set`'s own output ("suitable for reinput
 * to the shell", XCU 2.2.2) -- the identical escaping rule, reused
 * rather than reinvented, so a value containing a single quote, a
 * space or a `$` round-trips exactly.
 *
 * WHAT "MAIL ON COMPLETION" BECOMES HERE
 * -----------------------------------------
 * at(1p)'s -m and batch(1p)'s implicit -m both mean "mail the user
 * the job's stdout/stderr once it has run". mailx is explicitly out
 * of scope for this whole project pass (the task's own framing), so
 * there is no mail transport to hand that output to. The honest
 * fallback, used unconditionally (there is no non-mail, discard-
 * output mode to fall back to instead -- at(1p)'s own OPTIONS says
 * output is mailed "unless redirected elsewhere", and a plain job
 * with no redirection has nowhere else to go): atd captures the
 * job's combined stdout+stderr to `<id>.out` next to the job file
 * itself, and leaves it there for the user to read directly, rather
 * than silently discarding it or pretending mail was sent. See
 * src/util/atd.c's own header for exactly how.
 */
#ifndef _NTLIBC_UTIL_ATBATCH_H
#define _NTLIBC_UTIL_ATBATCH_H

#include <stddef.h>
#include <time.h>
#include <ownership.h>

/* Writes a new job to the atjobs spool (src/util/spool.h), scheduled
 * to run at `run_at` (an absolute time, already resolved by
 * src/util/attime.c or touch(1p)-shaped -t parsing -- this function
 * does no time parsing of its own), in queue `queue` (a single
 * letter; recorded and reported by `at -l`, otherwise inert -- see
 * this header's own note above and src/util/atd.c's for why every
 * queue runs the same way here). The job body is `srcfile`'s bytes if
 * non-NULL, else standard input's bytes read to EOF.
 *
 * Captures, at the moment of the call: the real environment
 * (`environ`), the current working directory, and the current umask
 * -- exactly what a real atd needs to reproduce this shell's
 * execution environment later, in a process that will not otherwise
 * inherit any of it (atd is a long-lived daemon, not a child of this
 * invocation).
 *
 * On success, returns 0 and writes the decimal job id into id_out
 * (id_out_sz bytes, NUL-terminated). On failure, returns -1 with
 * errno set to whatever the underlying spool/file/read operation
 * failed with; id_out is left untouched. */
/* tools/clang/ErrnoDisciplineChecker.cpp's ntlibc.ErrnoDiscipline: every
 * failure return of this file's own atbatch.c implementation sets
 * errno, via a real errno-setting call (__spool_dir/__spool_new_job/
 * fopen/fread/fwrite/fputc/fputs/fclose/__spool_publish_job) or its own
 * explicit ENAMETOOLONG assignment on the one path none of those
 * cover -- see this header's own doc comment above and the `fail:`
 * label's errno save/restore around cleanup in atbatch.c itself. */
grants_thread_token(errno_grounds)
int __atbatch_submit(const char *queue, time_t run_at, const char *srcfile,
	char *id_out, size_t id_out_sz);

#endif
