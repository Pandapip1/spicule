/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * xargs(1p): read whitespace/quote-delimited arguments from standard
 * input and invoke a utility with them, batched to fit a command-line
 * size limit. See
 * https://pubs.opengroup.org/onlinepubs/9699919799/utilities/xargs.html.
 *
 * Tokenizing (read_tokens()): bare text, "..." and '...' each build up
 * one token; a backslash outside any quote escapes the next character
 * literally. Backslash is NOT processed *inside* quotes -- the page's
 * Guideline grammar treats quoting and escaping as independent
 * mechanisms, unlike shell's nested quoting.
 *
 * Byte ceiling per invocation: min(-s value, or LINE_MAX if -s absent,
 * sysconf(_SC_ARG_MAX) - 2048 - current environ size).
 *
 * Not implemented, refused with a diagnostic and exit 2: -0/-d (a GNU
 * extension, not POSIX-mandatory). -E's eofstr matching is disabled by
 * default and only takes effect when -E is given -- the safer of the
 * two standard-permitted defaults, so an ordinary "_" token is never
 * silently swallowed. -I and -L both group the token stream by input
 * line (read_tokens() already tracks each token's line); -I's
 * substitution value for one invocation is that line's tokens rejoined
 * with single spaces rather than a second, separate per-line parse.
 *
 * All of standard input is read into memory (read_tokens()) before any
 * batch is built, trading unbounded-stdin streaming for simpler
 * batching logic below.
 *
 * -p implies trace mode (-t) plus a yes/no prompt read directly from
 * stdin, same convention as find(1)'s -ok (src/util/find.c).
 *
 * Exit status is the max of all candidate codes seen (note_status()):
 * 127 > 126 > 1 > 0, already plain numeric order.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include "util.h"
#include "libc.h" /* __find_program()/__spawn() -- src/process/, the same primitives sh's own execute.c uses */

struct tok { char *text; size_t line; };

struct buf { char *p withtok(readable_span(len)) withtok(writable_span(cap)); size_t len, cap; };

static int buf_putc(struct buf *b, int ch) __attribute__((nonnull(1)));
static int buf_putc(struct buf *b, int ch)
{
	if (b->len + 1 > b->cap) {
		size_t ncap;
		char *np;
		if (!__util_array_capacity(b->cap, b->len, 1, 64, 1, &ncap)) return -1;
		np = realloc(b->p, ncap);
		if (!np) return -1;
		b->p = np;
		b->cap = ncap;
	}
	b->p[b->len++] = (char)ch;
	return 0;
}

static int emit_token(struct tok **arrp, size_t *np, size_t *capp, struct buf *cur, size_t tokline)
    __attribute__((nonnull(1, 2, 3, 4)));
static int emit_token(struct tok **arrp, size_t *np, size_t *capp, struct buf *cur, size_t tokline)
{
	size_t ncap;
	char *restrict text;
	if (!__util_array_capacity(*capp, *np, 1, 16, sizeof(struct tok), &ncap)) return -1;
	if (ncap != *capp) {
		struct tok *grown = __util_reallocarray(*arrp, ncap, sizeof(struct tok));
		if (!grown) return -1;
		*arrp = grown;
		*capp = ncap;
	}
	{
		size_t bytes;
		if (!__util_size_add(cur->len, 1, &bytes)) return -1;
		text = malloc(bytes);
	}
	if (!text) return -1;
	for (size_t i = 0; i < cur->len; i++) text[i] = cur->p[i];
	text[cur->len] = 0;
	(*arrp)[*np].text = text;
	(*arrp)[*np].line = tokline;
	(*np)++;
	cur->len = 0;
	return 0;
}

/* On success, *outp and *np are a malloc()'d array of *np tokens (each
 * .text malloc()'d too). On failure (-1, diagnostic already written)
 * *outp and *np are untouched and everything allocated so far is
 * freed. */
static int read_tokens(FILE *in, struct tok **outp, size_t *np) __attribute__((nonnull(1, 2, 3)));
static int read_tokens(FILE *in, struct tok **outp, size_t *np)
{
	struct tok *arr = NULL;
	size_t n = 0, cap = 0;
	struct buf cur;
	int state = 0; /* 0 = between tokens, 1 = bare, 2 = "...", 3 = '...' */
	size_t line = 0, tokline = 0;
	int c;

	cur.p = NULL; cur.len = 0; cur.cap = 0;

	for (;;) {
		c = fgetc(in);
		if (state == 0) {
			if (c == EOF) break;
			if (c == ' ' || c == '\t') continue;
			if (c == '\n') { line++; continue; }
			tokline = line;
			state = 1;
			/* fall through: c is the token's first character */
		}
		if (c == EOF) {
			if (state == 2 || state == 3) {
				__util_diagf("xargs: unterminated quote\n");
				goto fail;
			}
			break; /* state == 1: final token emitted after the loop */
		}
		if (state == 1) {
			if (c == ' ' || c == '\t' || c == '\n') {
				if (c == '\n') line++;
				if (emit_token(&arr, &n, &cap, &cur, tokline) < 0) goto fail;
				state = 0;
				continue;
			}
			if (c == '\\') {
				int e = fgetc(in);
				if (e == EOF) { __util_diagf("xargs: unterminated backslash escape\n"); goto fail; }
				if (buf_putc(&cur, e) < 0) goto fail;
				if (e == '\n') line++;
				continue;
			}
			if (c == '"') { state = 2; continue; }
			if (c == '\'') { state = 3; continue; }
			if (buf_putc(&cur, c) < 0) goto fail;
			continue;
		}
		if (state == 2) {
			if (c == '"') { state = 1; continue; }
			if (buf_putc(&cur, c) < 0) goto fail;
			if (c == '\n') line++;
			continue;
		}
		/* state == 3 */
		if (c == '\'') { state = 1; continue; }
		if (buf_putc(&cur, c) < 0) goto fail;
		if (c == '\n') line++;
	}

	if (state == 1 && emit_token(&arr, &n, &cap, &cur, tokline) < 0) goto fail;

	free(cur.p);
	*outp = arr;
	*np = n;
	return 0;

fail:
	free(cur.p);
	{
		size_t i;
		for (i = 0; i < n; i++) free(arr[i].text);
	}
	free(arr);
	return -1;
}

/* Replace every occurrence of replstr within tmpl with value, for -I's
 * substitution.  A single allocation sized from a pre-count of
 * occurrences, not incremental realloc(). */
withtok(heap_allocated)
static char *subst(const char *tmpl, const char *replstr, const char *value)
    __attribute__((nonnull(1, 2, 3)));
withtok(heap_allocated)
static char *subst(const char *tmpl, const char *replstr, const char *value)
{
	size_t rlen = strlen(replstr), vlen = strlen(value), tlen = strlen(tmpl), occ = 0;
	const char *p;
	char *out;
	size_t opos;

	if (rlen == 0) {
		char *r;
		size_t bytes;
		if (!__util_size_add(tlen, 1, &bytes)) return NULL;
		r = malloc(bytes);
		if (r) for (size_t i = 0; i <= tlen; i++) r[i] = tmpl[i];
		return r;
	}
	for (p = tmpl; (p = strstr(p, replstr)) != NULL; p += rlen) occ++;
	{
		size_t bytes = tlen;
		if (vlen > rlen) {
			size_t grow;
			if (!__util_size_mul(vlen - rlen, occ, &grow) ||
			    !__util_size_add(bytes, grow, &bytes)) return NULL;
		}
		if (!__util_size_add(bytes, 1, &bytes)) return NULL;
		out = malloc(bytes);
	}
	if (!out) return NULL;
	opos = 0;
	p = tmpl;
	for (;;) {
		const char *hit = strstr(p, replstr);
		size_t chunk;
		if (!hit) { strcpy(out + opos, p); break; } // NOLINT(clang-analyzer-security.insecureAPI.strcpy) -- out was sized above to fit the remainder of tmpl plus every substitution
		chunk = (size_t)(hit - p);
		for (size_t i = 0; i < chunk; i++) out[opos + i] = p[i];
		opos += chunk;
		for (size_t i = 0; i < vlen; i++) out[opos + i] = value[i];
		opos += vlen;
		p = hit + rlen;
	}
	return out;
}

struct xopts {
	const char *eofstr;   /* NULL = disabled (this file's own documented default) */
	const char *replstr;  /* -I */
	long L, n, s;          /* 0 = not given */
	int p, t, x;
};

static void trace_line(char *const argv2[]) __attribute__((nonnull(1)));
static void trace_line(char *const argv2[])
{
	size_t i;
	for (i = 0; argv2[i]; i++) fprintf(stderr, "%s%s", i ? " " : "", argv2[i]);
	fputc('\n', stderr);
}

static int prompt_confirm(void)
{
	int c, first = -1;
	fputs("?...", stderr);
	(void)fflush(stderr);
	while ((c = getchar()) != EOF && c != '\n')
		if (first < 0 && c != ' ' && c != '\t') first = c;
	return first == 'y' || first == 'Y';
}

/* See header comment: priority already matches numeric order. */
static void note_status(int *xstatus, int candidate) __attribute__((nonnull(1)));
static void note_status(int *xstatus, int candidate)
{
	if (candidate > *xstatus) *xstatus = candidate;
}

static int spawn_and_wait(char *const argv2[], int *xstatus) __attribute__((nonnull(1, 2)));
static int spawn_and_wait(char *const argv2[], int *xstatus)
{
	char *resolved = __find_program(argv2[0], 1);
	int pid, status, rc;
	if (!resolved) {
		__util_diagf("xargs: %s: No such file or directory\n", argv2[0]);
		note_status(xstatus, 127);
		return -1;
	}
	pid = __spawn(resolved, argv2, environ);
	free(resolved);
	if (pid < 0) {
		__util_diagf("xargs: %s: %s\n", argv2[0], strerror(errno));
		note_status(xstatus, 126);
		return -1;
	}
	if (waitpid(pid, &status, 0) < 0) { note_status(xstatus, 1); return -1; }
	rc = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
	if (rc != 0) note_status(xstatus, 1);
	return rc;
}

static void run_one(char *const argv2[], const struct xopts *o, int *xstatus)
    __attribute__((nonnull(1, 2, 3)));
static void run_one(char *const argv2[], const struct xopts *o, int *xstatus)
{
	if (o->t || o->p) trace_line(argv2);
	if (o->p && !prompt_confirm()) return;
	(void)spawn_and_wait(argv2, xstatus);
}

static size_t argv_bytes(char *const *v, size_t n)
{
	size_t total = 0, i;
	for (i = 0; i < n; i++) total += strlen(v[i]) + 1;
	return total;
}

int __util_xargs_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	struct xopts o;
	int i;
	char **prog_argv;
	int prog_argc;
	static char *default_argv[] = { (char *)"echo", 0 };
	struct tok *toks = NULL;
	size_t ntok = 0, ntok_used, ti;
	long arg_max, line_max, envbytes = 0, ceiling, byte_limit;
	size_t base_bytes;
	int xstatus = 0;

	memset(&o, 0, sizeof o);

	for (i = 1; i < argc; i++) {
		char *a = argv[i];
		if (!strcmp(a, "--")) { i++; break; }
		if (a[0] != '-' || a[1] == 0) break;
		{
			char *p = a + 1;
			while (*p) {
				switch (*p) {
				case 'p': o.p = 1; p++; break;
				case 't': o.t = 1; p++; break;
				case 'x': o.x = 1; p++; break;
				case '0': case 'd':
					__util_diagf("xargs: -%c: not implemented (not a POSIX mandatory option) -- see src/util/xargs.c\n", *p);
					return 2;
				case 'E': case 'I': case 'L': case 'n': case 's': {
					char opt = *p;
					const char *val;
					p++;
					if (*p) { val = p; }
					else {
						if (++i >= argc) { __util_diagf("xargs: -%c: option requires an argument\n", opt); return 2; }
						val = argv[i];
					}
					if (opt == 'E') o.eofstr = val;
					else if (opt == 'I') o.replstr = val;
					else {
						char *end;
						long v = strtol(val, &end, 10);
						if (end == val || *end || v <= 0) { __util_diagf("xargs: -%c: invalid value\n", opt); return 2; }
						if (opt == 'L') o.L = v;
						else if (opt == 'n') o.n = v;
						else o.s = v;
					}
					p = (char *)"";
					break;
				}
				default:
					__util_diagf("xargs: -%c: invalid option\n", *p);
					return 2;
				}
			}
		}
	}
	if (o.replstr && o.L) {
		__util_diagf("xargs: -I and -L are mutually exclusive\n");
		return 2;
	}
	if (o.replstr) { o.L = 1; o.x = 1; } /* "-I ... enforces -x" */

	if (i < argc) { prog_argv = argv + i; prog_argc = argc - i; }
	else { prog_argv = default_argv; prog_argc = 1; }

	if (read_tokens(stdin, &toks, &ntok) < 0) return 1; /* read_tokens() already freed everything on failure */

	/* -E: stop at (and drop) the first token equal to eofstr -- disabled
	 * by default, see this file's header comment. */
	ntok_used = ntok;
	if (o.eofstr) {
		for (ti = 0; ti < ntok; ti++) {
			if (!strcmp(toks[ti].text, o.eofstr)) { ntok_used = ti; break; }
		}
	}

	arg_max = sysconf(_SC_ARG_MAX);
	line_max = sysconf(_SC_LINE_MAX);
	if (arg_max <= 0) arg_max = 131072;
	if (line_max <= 0) line_max = 4096;
	{
		char **e;
		for (e = environ; e && *e; e++) envbytes += (long)strlen(*e) + 1;
	}
	ceiling = arg_max - 2048 - envbytes;
	if (ceiling < 512) ceiling = 512; /* never so tight ordinary batching cannot proceed at all */
	byte_limit = o.s ? o.s : line_max;
	if (byte_limit > ceiling) byte_limit = ceiling;

	base_bytes = argv_bytes(prog_argv, (size_t)prog_argc);

	if (o.replstr) {
		/* -I: one invocation per input line, substituting replstr in
		 * every template argument with that line's tokens rejoined by
		 * single spaces (see header comment on this simplification). */
		ti = 0;
		while (ti < ntok_used) {
			size_t start, line, total_len = 1, k, vpos;
			char *value;
			char **argv2;
			if (xstatus >= 126) break;
			start = ti; line = toks[ti].line;
			while (ti < ntok_used && toks[ti].line == line) {
				total_len += strlen(toks[ti].text) + 1;
				ti++;
			}
			value = malloc(total_len);
			if (!value) { xstatus = 1; break; }
			vpos = 0;
			for (k = start; k < ti; k++) {
				size_t l = strlen(toks[k].text);
				if (k != start) value[vpos++] = ' ';
				for (size_t j = 0; j < l; j++) value[vpos + j] = toks[k].text[j];
				vpos += l;
			}
			value[vpos] = 0;

			argv2 = __util_mallocarray((size_t)prog_argc + 1, sizeof(char *));
			if (!argv2) { free(value); xstatus = 1; break; }
			{
				size_t built = 0, blen = 0;
				int ok = 1;
				for (k = 0; k < (size_t)prog_argc; k++) {
					char *sub = subst(prog_argv[k], o.replstr, value);
					if (!sub) { ok = 0; break; }
					argv2[built++] = sub;
					blen += strlen(sub) + 1;
				}
				argv2[built] = 0;
				if (!ok) { for (k = 0; k < built; k++) free(argv2[k]); free(argv2); free(value); xstatus = 1; break; }
				if (blen > (size_t)byte_limit) {
					__util_diagf("xargs: argument list too long\n");
					xstatus = 1;
					for (k = 0; k < built; k++) free(argv2[k]);
					free(argv2);
					free(value);
					break;
				}
				run_one(argv2, &o, &xstatus);
				for (k = 0; k < built; k++) free(argv2[k]);
				free(argv2);
			}
			free(value);
		}
	} else if (o.L) {
		/* -L: batch whole lines (not individual tokens) until L lines
		 * have been consumed, still bounded by byte_limit. */
		ti = 0;
		while (ti < ntok_used) {
			size_t start = ti, lines_seen = 0, last_line = toks[ti].line;
			size_t batch_bytes = base_bytes;
			while (ti < ntok_used) {
				size_t add = strlen(toks[ti].text) + 1;
				if (toks[ti].line != last_line) {
					lines_seen++;
					if (lines_seen >= (size_t)o.L) break;
					last_line = toks[ti].line;
				}
				if (batch_bytes + add > (size_t)byte_limit) {
					if (ti == start) { __util_diagf("xargs: argument list too long\n"); xstatus = 1; goto done; }
					break;
				}
				batch_bytes += add;
				ti++;
			}
			if (ti == start) break; /* nothing more fits */
			{
				char **argv2 = __util_mallocarray((size_t)prog_argc + (ti - start) + 1, sizeof(char *));
				size_t k;
				if (!argv2) { xstatus = 1; break; }
				for (k = 0; k < (size_t)prog_argc; k++) argv2[k] = prog_argv[k];
				for (k = 0; k < ti - start; k++) argv2[(size_t)prog_argc + k] = toks[start + k].text;
				argv2[(size_t)prog_argc + (ti - start)] = 0;
				run_one(argv2, &o, &xstatus);
				free(argv2);
			}
		}
	} else {
		/* Default / -n / -s: flat token-count and/or byte-size batching. */
		ti = 0;
		while (ti < ntok_used) {
			size_t start = ti, batch_bytes = base_bytes, count = 0;
			while (ti < ntok_used) {
				size_t add = strlen(toks[ti].text) + 1;
				if (o.n && count >= (size_t)o.n) break;
				if (batch_bytes + add > (size_t)byte_limit) {
					if (count == 0) { __util_diagf("xargs: argument list too long\n"); xstatus = 1; goto done; }
					break;
				}
				batch_bytes += add;
				count++;
				ti++;
			}
			if (o.x && o.n && count < (size_t)o.n && ti < ntok_used) {
				__util_diagf("xargs: argument list too long for -n %ld\n", o.n);
				xstatus = 1;
				break;
			}
			{
				char **argv2 = __util_mallocarray((size_t)prog_argc + count + 1, sizeof(char *));
				size_t k;
				if (!argv2) { xstatus = 1; break; }
				for (k = 0; k < (size_t)prog_argc; k++) argv2[k] = prog_argv[k];
				for (k = 0; k < count; k++) argv2[(size_t)prog_argc + k] = toks[start + k].text;
				argv2[(size_t)prog_argc + count] = 0;
				run_one(argv2, &o, &xstatus);
				free(argv2);
			}
			if (count == 0) break; /* defensive: avoid an infinite loop if nothing was consumed */
		}
	}

done:
	for (ti = 0; ti < ntok; ti++) free(toks[ti].text);
	free(toks);
	return xstatus;
}
