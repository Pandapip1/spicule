/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The on-disk job spool shared by at(1p)/batch(1p)/atd and
 * crontab(1p)/cron -- one real directory tree, one file-naming
 * convention, one "who am I" answer, used by all six translation
 * units (src/util/atbatch.c, src/util/atd.c, src/util/crontab.c,
 * src/util/crond.c) plus their two entry-point wrappers
 * (src/util/at.c, src/util/batch.c).
 *
 * WHERE THE SPOOL LIVES
 * ----------------------
 * src/misc/pwd.c's own header comment already settled "who is the
 * current user" for this library: there is exactly one, and its home
 * directory is %USERPROFILE% on NT, with getpwuid(getuid())->pw_dir
 * the honest place to read that back from. This file uses the exact
 * same source (getenv("HOME") first -- src/sh/builtin.c's bi_cd()
 * already treats that as the canonical shell-visible home directory --
 * falling back to getpwuid()->pw_dir when HOME is unset, never
 * fabricating a location neither names), so a spool path and `cd`'s
 * own idea of "home" can never disagree.
 *
 * Given that, the spool root is $HOME/.ntlibc/, with two
 * subdirectories:
 *
 *   $HOME/.ntlibc/atjobs/      one <id>.job (+ <id>.out once it has
 *                              run) per job at(1p)/batch(1p) submitted
 *   $HOME/.ntlibc/crontabs/    one file, "crontab", holding the single
 *                              real user's crontab (see src/util/
 *                              crontab.c's own header for why one file
 *                              is the whole of the multi-user question
 *                              here, not a narrowing this file invents)
 *
 * This mirrors XDG/cron convention (a per-user directory under the
 * home directory, not a system-wide /var/spool/{at,cron} this library
 * has no privileged install location for and no multi-user reason to
 * want) while staying inside the one directory this library already
 * treats as unambiguously "this user's own stuff".
 *
 * JOB IDENTITY AND ATOMICITY
 * ----------------------------
 * Every at(1p)/batch(1p) job gets a decimal job id, assigned by
 * __spool_new_job() below via a plain O_CREAT|O_EXCL loop seeded from
 * time(NULL): try that number, and if the file already exists (another
 * job submitted the same second, or a previous run left a lower-
 * numbered id behind), try the next integer up. No shared counter
 * file, no lock -- two at(1p) invocations racing each other can only
 * ever produce two *different* filenames, because O_EXCL is what NT's
 * CreateFile(..., CREATE_NEW, ...) and Linux's open(2) both guarantee
 * atomically, the same primitive src/stdlib/mktemp.c's own
 * mkostemps() already relies on for exactly this property.
 *
 * A job file is written to `<id>.job.tmp` first and rename()d to
 * `<id>.job` only once the whole thing -- header, captured
 * environment, captured script -- has been written and fflush()ed:
 * atd's poll loop (src/util/atd.c) only ever looks for `*.job`, so it
 * can never observe a job file mid-write. rename() replacing nothing
 * (the destination is guaranteed to not exist, since `<id>.job` was
 * never created directly) is an ordinary, single-syscall atomic
 * publish on both platforms.
 *
 * THE CRONTAB FILE
 * ------------------
 * Single-user, single-file, so there is no job-id allocation problem
 * to solve: crontab(1p)'s -e/-r write a new file to
 * crontabs/crontab.tmp and rename() it over crontabs/crontab, the
 * same publish-by-rename idiom as above. crond (src/util/crond.c)
 * notices a new crontab by stat()ing its mtime once per poll tick and
 * reparsing only when it has changed -- no lock needed there either,
 * for the same reason: it only ever sees a complete file.
 *
 * This internal header, like the public C library headers, must use the
 * implementation-reserved namespace for its guard and its own declarations
 * so they cannot collide with user code. */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#ifndef _NTLIBC_SPOOL_H
#define _NTLIBC_SPOOL_H

#include <stdio.h>
#include <stddef.h>
#include <time.h>
#include <ownership.h>

/* Longest path this file ever builds: $HOME + "/.ntlibc/crontabs/crontab.tmp".
 * 4096 comfortably covers any real NT or Linux path without a second,
 * dynamic-growth path to test. */
#define NTLIBC_SPOOL_PATH_MAX 4096

/* __spool_home(): fills buf (bufsz bytes) with the current user's home
 * directory -- getenv("HOME") if set and non-empty, else
 * getpwuid(getuid())->pw_dir (src/misc/pwd.c). Returns 0 on success,
 * -1 (errno untouched -- there is no failed syscall to blame, just an
 * unknowable answer, the same "not found" shape pwd.c's own
 * getpwuid() uses) if neither source has one. */
int __spool_home(char *buf, size_t bufsz);

/* __spool_dir(): fills buf with $HOME/.ntlibc/<sub> and ensures every
 * component of it exists as a directory (mkdir()ing $HOME/.ntlibc and
 * then $HOME/.ntlibc/<sub> in turn, tolerating EEXIST at each level --
 * $HOME itself is assumed to already exist and is never created).
 * Returns 0 on success, -1 with errno set (from mkdir() or from
 * __spool_home()'s "no home directory" case, reported as ENOENT since
 * there is no path to even attempt) on failure. */
int __spool_dir(const char *sub, char *buf, size_t bufsz);

/* __spool_new_job(): allocates a fresh job id under `dir` (already a
 * real, existing directory -- normally __spool_dir("atjobs", ...)'s
 * own output) and opens `<id>.job.tmp` for writing. On success, writes
 * the decimal id into id_out (id_out_sz bytes), the final `<id>.job`
 * path (not the .tmp path -- see __spool_publish_job()) into
 * path_out (path_out_sz bytes), and returns a FILE* open for writing;
 * the caller writes the job body to it, fclose()s it, and calls
 * __spool_publish_job() to make it visible to atd. Returns NULL with
 * errno set on failure (out of ids after a bounded number of
 * attempts, or a real open() failure). */
/* tools/clang/ErrnoDisciplineChecker.cpp's ntlibc.ErrnoDiscipline: see
 * this function's own doc comment above -- "Returns NULL with errno
 * set on failure". */
grants_thread_token(errno_grounds)
withtok(file_stream_open)
FILE *__spool_new_job(const char *dir, char *id_out, size_t id_out_sz,
	char *path_out, size_t path_out_sz);

/* __spool_publish_job(): rename()s `<path>.tmp` to `<path>`, making a
 * job written via __spool_new_job() visible to atd's poll loop for
 * the first time. Returns 0 on success, -1 with errno set on
 * failure (in which case the caller should unlink() the .tmp file
 * itself -- this function does not, since a caller may want to
 * inspect it first for diagnostics). */
/* tools/clang/ErrnoDisciplineChecker.cpp's ntlibc.ErrnoDiscipline: see
 * this function's own doc comment above -- "-1 with errno set on
 * failure". */
grants_thread_token(errno_grounds)
int __spool_publish_job(const char *path);

/* __spool_job_header(): reads a job file's "#run_at N" and
 * "#queue X" header lines (src/util/atbatch.h's own documented job
 * file format) WITHOUT executing it as a script -- both header lines
 * are near the top of the file and are also valid shell comments, so
 * `sh` skips them at execution time the same way this function skips
 * every other line while scanning. Shared between src/util/at.c
 * (`at -l`/`at -r` need to report a job's schedule without running
 * it) and src/util/atd.c (which needs the same answer to decide
 * whether a job is due) rather than the same ~15 lines written twice.
 *
 * Fills *run_at and queue (queue_sz bytes, NUL-terminated -- empty if
 * the file had no "#queue" line at all, which every job atbatch.c
 * itself writes always has, but a hand-edited or foreign file might
 * not). Returns 0 if a "#run_at" line was found, -1 (errno set from
 * fopen(), or ENOENT-shaped "no such line" if the file opened fine
 * but had none) otherwise. */
int __spool_job_header(const char *path, time_t *run_at, char *queue, size_t queue_sz);

/* __spool_crontab_path(): fills buf with the one real crontab file
 * this library ever has, $HOME/.ntlibc/crontabs/crontab (ensuring
 * the crontabs/ directory itself exists via __spool_dir()). Shared
 * between src/util/crontab.c (-e/-l/-r) and src/util/crond.c (which
 * needs the identical path to notice it has changed) rather than
 * the same three-line path build written twice. Returns buf on
 * success, or NULL with errno set if the directory could not be
 * ensured. */
const char *__spool_crontab_path(char *buf, size_t bufsz);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
