/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * paste(1p): `paste [-s] [-d list] file...`
 *
 * Default (no -s): "The paste utility shall concatenate the
 * corresponding lines of the given input files, replacing all but the
 * last file's newline characters with a single <tab>." Concretely: read
 * one line from every file for each output row, joined by delimiters,
 * one row per newline; once a file runs out of lines it contributes an
 * empty field for every remaining row (not a missing row -- the merge
 * keeps going, with that column blank, until every file has reached
 * EOF). merge_parallel() below implements exactly that: each file has
 * its own eof flag, a row is only skipped once *all* files are eof.
 *
 * -s ("serial"): "the lines of one file at a time shall be concatenated
 * together" -- concat_serial() below joins every line of a single file
 * onto one output row (delimiters between lines from that file), one
 * output row per input file, in argument order.
 *
 * -d list: "Use one or more of the characters in list, instead of the
 * default <tab>, to replace the newline of an input line ... used
 * circularly, that is, when list is exhausted, reuse it from the
 * beginning." parse_delim_list() decodes list's own small escape
 * grammar -- '\n' <newline>, '\t' <tab>, '\\' <backslash> -- into an
 * array of raw output bytes; any other backslash sequence is
 * undefined by the standard and refused here rather than guessed at,
 * same "refuse rather than guess an ambiguous ombination" rule this
 * project applies throughout (see src/util/tr.c's header for the same
 * reasoning applied to its own escape grammar).
 *
 * A file operand of "-" means standard input, same convention as
 * src/util/cut.c; a missing/unreadable operand is diagnosed and that
 * file is thereafter treated as permanently empty (paste keeps merging
 * the files that did open, rather than aborting the whole run), and the
 * exit status is still nonzero.
 *
 * EXIT STATUS: "0 Success. >0 An error occurred." -- 2 for a usage
 * error, 1 for a runtime one (a file that could not be opened), the
 * same split src/util/cut.c uses.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "util.h"
#include "ownership_stubs.h"

static int parse_delim_list(const char *spec, char **out withtok(heap_allocated),
                            size_t *out_n)
{
	char *buf;
	size_t n = 0;
	const char *p = spec;

	if (!*spec) return -1;
	buf = malloc(strlen(spec));
	if (!buf) return -1;

	while (*p) {
		if (*p == '\\') {
			p++;
			if (*p == 'n') { buf[n++] = '\n'; p++; }
			else if (*p == 't') { buf[n++] = '\t'; p++; }
			else if (*p == '\\') { buf[n++] = '\\'; p++; }
			else { free(buf); return -1; }
		} else {
			buf[n++] = *p++;
		}
	}
	if (n == 0) { free(buf); return -1; }
	*out = buf;
	*out_n = n;
	return 0;
}

static void merge_parallel(FILE **files, int nfiles, const char *delims, size_t ndelim)
{
	char **linebuf = calloc((size_t)nfiles, sizeof *linebuf);
	size_t *linecap = calloc((size_t)nfiles, sizeof *linecap);
	ssize_t *linelen = calloc((size_t)nfiles, sizeof *linelen);
	int *eof = calloc((size_t)nfiles, sizeof *eof);
	int j;

	if (!linebuf || !linecap || !linelen || !eof) {
		free(linebuf); free(linecap); free(linelen); free(eof); return;
	}
	for (j = 0; j < nfiles; j++) if (!files[j]) eof[j] = 1;

	for (;;) {
		/* Read this row's line from every file that isn't eof yet
		 * *before* printing anything. A file going eof mid-row still
		 * has to leave its column empty for this row (POSIX: a
		 * shorter file contributes an empty field, not a dropped
		 * row, until every file is exhausted) -- but the row after
		 * the true last line of the longest file must not be
		 * printed at all, since by then no file has anything left.
		 * any_data below is what tells those two cases apart: it is
		 * only set when some file actually produced a line this
		 * round, so a round where every file is already eof (or
		 * goes eof on this very read) breaks out before writing a
		 * spurious all-empty row of bare delimiters. */
		int any_data = 0;

		for (j = 0; j < nfiles; j++) {
			linelen[j] = -1;
			if (!eof[j]) {
				linelen[j] = getline(&linebuf[j], &linecap[j], files[j]);
				if (linelen[j] < 0) {
					eof[j] = 1;
				} else {
					if (linelen[j] > 0 && linebuf[j][linelen[j] - 1] == '\n')
						linebuf[j][--linelen[j]] = 0;
					any_data = 1;
				}
			}
		}
		if (!any_data) break;

		for (j = 0; j < nfiles; j++) {
			if (linelen[j] >= 0) fwrite(linebuf[j], 1, (size_t)linelen[j], stdout);
			if (j < nfiles - 1) fputc(delims[(size_t)j % ndelim], stdout);
			else fputc('\n', stdout);
		}
	}

	for (j = 0; j < nfiles; j++) free(linebuf[j]);
	free(linebuf);
	free(linecap);
	free(linelen);
	free(eof);
}

static void concat_serial(FILE *f, const char *delims, size_t ndelim)
{
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;
	size_t k = 0;
	int any = 0;

	if (!f) { fputc('\n', stdout); return; }

	while ((len = getline(&line, &cap, f)) >= 0) {
		if (len > 0 && line[len - 1] == '\n') line[--len] = 0;
		if (any) fputc(delims[k++ % ndelim], stdout);
		{
			ssize_t i;
			for (i = 0; i < len; i++) fputc((unsigned char)line[i], stdout);
		}
		any = 1;
	}
	free(line);
	fputc('\n', stdout);
}

int __util_paste_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int serial = 0;
	char *delims = NULL;
	size_t ndelim = 0;
	int i = 1;
	int nfiles, had_error = 0;
	FILE **files;
	static char default_delim[1] = { '\t' };

	for (; i < argc; i++) {
		char *a = argv[i];

		if (a[0] != '-' || a[1] == 0) break;
		if (!strcmp(a, "--")) { i++; break; }
		if (!strcmp(a, "-s")) { serial = 1; continue; }
		if (!strcmp(a, "-d") || (a[1] == 'd' && a[2])) {
			const char *spec = a[2] ? a + 2 : NULL;
			if (!spec) {
				if (i + 1 >= argc) {
					fprintf(stderr, "paste: -d: option requires an argument\n");
					free(delims); /* a prior -d may have already allocated one */
					return 2;
				}
				spec = argv[++i];
			}
			free(delims);
			delims = NULL; /* parse_delim_list() only writes *out on success */
			if (parse_delim_list(spec, &delims, &ndelim) < 0) {
				fprintf(stderr, "paste: %s: invalid delimiter list\n", spec);
				return 2;
			}
			continue;
		}
		fprintf(stderr, "paste: invalid option -- '%s'\n", a);
		free(delims);
		return 2;
	}

	if (i >= argc) {
		fprintf(stderr, "paste: missing operand\n");
		free(delims);
		return 2;
	}
	if (!delims) { delims = default_delim; ndelim = 1; }

	nfiles = argc - i;
	files = calloc((size_t)nfiles, sizeof *files); // NOLINT(bugprone-sizeof-expression) -- files is FILE**, *files is FILE*, the array holds pointers
	if (!files) { fprintf(stderr, "paste: %s\n", strerror(ENOMEM)); if (delims != default_delim) free(delims); return 1; }

	{
		int j;
		for (j = 0; j < nfiles; j++) {
			const char *path = argv[i + j];
			files[j] = !strcmp(path, "-") ? stdin : fopen(path, "r");
			if (!files[j]) {
				fprintf(stderr, "paste: %s: %s\n", path, strerror(errno));
				had_error = 1;
			}
		}
	}

	if (serial) {
		int j;
		for (j = 0; j < nfiles; j++) concat_serial(files[j], delims, ndelim);
	} else {
		merge_parallel(files, nfiles, delims, ndelim);
	}

	{
		int j;
		for (j = 0; j < nfiles; j++) if (files[j] && files[j] != stdin) (void)fclose(files[j]);
	}
	free(files);
	if (delims != default_delim) free(delims);
	return had_error ? 1 : 0;
}
