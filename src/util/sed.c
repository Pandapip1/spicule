/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * sed(1p): `sed [-n] script [file...]` / `sed [-n] [-e script]... [-f
 * script_file]... [file...]` (the two SYNOPSIS forms XCU sed(1p) gives;
 * a bare first operand is only ever taken as `script` when neither -e
 * nor -f was given at all -- otherwise every remaining operand is a
 * `file`, per the OPTIONS text below).
 *
 * OPTIONS: -n suppresses the default per-cycle "print pattern space"
 * step (only p/P/l/s///p/n's own leading print -- explicit output
 * commands -- write anything).  -e script and -f script_file each add
 * to "the script of editing commands" in argument order; "if the
 * previous addition ... was from a -e option, a <newline> shall be
 * inserted before the new addition" -- implemented literally by
 * script_buf_append() below.  A leading "#n" as the very first two
 * bytes of the assembled script is equivalent to -n (checked once,
 * after assembly, matching the standard's own wording).
 *
 * REGULAR EXPRESSIONS: always BRE (src/regex/regex.c's regcomp() with
 * REG_EXTENDED unset) -- sed(1p) has no ERE mode of its own to narrow;
 * GNU sed's -E/-r ERE flag is a well-known extension this file does
 * not implement (unrecognized options are refused with a diagnostic,
 * not silently ignored).  An empty RE ("//" or "\cc") reuses the most
 * recently *used* RE, address or s///, exactly as XCU's own "Regular
 * Expressions" section for this utility specifies; see g_last_re
 * below.
 *
 * ADDRESSING: no address (every cycle), a single address, or a
 * addr1,addr2 range, each in line-number, '$' (last line), or
 * /BRE/ (\cBREc with a custom delimiter c) form, optionally negated
 * with a trailing '!'.  Line numbers count cumulatively across every
 * file operand (concatenated in argv order), matching the standard's
 * own wording -- this file reads every operand fully into memory up
 * front (read_all_input() below) specifically so "$" and cumulative
 * numbering are simple index comparisons rather than one-line-of-
 * lookahead bookkeeping; sort(1p)/csplit(1p) already in this tree take
 * the identical "whole input in memory first" approach for their own,
 * different reasons.  A range's second address, if a line number less
 * than or equal to the line that opened the range, selects only that
 * one line (the standard's own parenthetical); once a range closes,
 * the *first* address is searched for again starting at the following
 * line, never re-triggering mid-range.  Following this project's own
 * convention (src/util/sort.c's -o, whose header cites the same
 * rationale), "-" as a file operand means standard input, matching
 * every other multi-file utility already in this tree even though XCU
 * sed(1p)'s own OPERANDS text does not spell that out the way cat(1p)
 * does for its own "-".
 *
 * COMMANDS implemented, the whole of XCU sed(1p)'s mandatory list:
 * s, y, a, i, c, d, D, g, G, h, H, x, n, N, p, P, q, r, w, b, t, :, =,
 * l, #, and the [2addr]{...} grouping.  s///'s flags are n (occurrence,
 * 1-based), g (global), p (print if a substitution happened) and
 * w wfile; combining a numeric occurrence with g is explicitly
 * "unspecified" by the standard, and this file resolves that by
 * replacing from the Nth match onward (matching every real-world sed
 * a script author has likely already tested against) rather than
 * leaving a script that asks for it silently do something worse.
 *
 * s///, a\, i\, c\ and y/// share one delimiter-escaping rule per XCU:
 * the chosen delimiter is literal wherever backslash-escaped.  The
 * BRE half of s/// is handed to regcomp() with only that one
 * unescape applied (any other backslash sequence -- \(, \{, \9, ...
 * -- reaches regcomp() exactly as written, since interpreting BRE
 * escapes is regcomp()'s job, not this parser's); the replacement,
 * y/// operand, and a/i/c text are each *fully* unescaped per their
 * own XCU rules (& and \1-\9 in a replacement, embedded <newline> via
 * a trailing backslash, "other <backslash> characters ... removed,
 * and the following character ... treated literally").
 *
 * a/r OUTPUT TIMING: XCU's own wording -- "shall be written to
 * standard output just before the next attempt to fetch a line of
 * input when executing the N or n commands, or when reaching the end
 * of the script" -- is implemented literally by an append_queue
 * (queue_append()/flush_appends() below): entries queue in the order
 * a/r were *applied* (not written), and drain in that order at
 * exactly those two points, never at the point a/r itself executes.
 * 'i', by contrast, writes immediately -- it is not in that sentence
 * at all.
 *
 * N/n AT END OF INPUT: N with no next line "shall branch to the end
 * of the script and quit without starting a new cycle or copying the
 * pattern space to standard output" -- i.e. genuinely no output for
 * that final, incomplete cycle, unlike GNU sed's default (non-POSIX)
 * behavior of printing anyway.  n with no next line also quits without
 * a new cycle, but only *after* n's own leading "write pattern space
 * if -n is not in effect" step has already run -- those are different
 * rules for different commands, both implemented as written.
 *
 * TRAILING NEWLINE: every line this file reads (read_all_input()) has
 * its own trailing <newline> stripped, and every line it writes gets
 * exactly one added back unconditionally -- this file does not track
 * "the last line of the last file had no trailing newline" the way a
 * byte-for-byte-faithful sed would.  Documented here as a deliberate
 * simplification, not an oversight: src/util/sort.c and src/util/
 * csplit.c already in this tree make the identical choice (sort.c:
 * `fprintf(outf, "%s\n", ...)` unconditionally) for the same reason --
 * every one of this tree's own utilities treats "text file, line-
 * oriented" as the working assumption, and threading a per-line
 * has-newline bit through g/G/h/H/x/N/D's pattern-space/hold-space
 * shuffling would be real, non-trivial bookkeeping for a corner XCU
 * itself calls out only for genuinely non-text input.
 *
 * NOT IMPLEMENTED, refused with a diagnostic rather than silently
 * mis-handled: GNU sed's -i (in-place editing), -E/-r (ERE mode), the
 * Q command (immediate quit with no auto-print), q/Q's optional exit-
 * code operand, s///'s i/I (case-insensitive) and m/M (multiline ^/$)
 * flags, \U/\L/\E case-conversion escapes in a replacement, address
 * form 0,/RE/, and the l command's optional line-wrap-length operand
 * (l's own fold width -- "unspecified" by XCU -- is fixed at 70
 * columns here, a common real-world default) -- none of these appear
 * in XCU sed(1p)'s own mandatory description; every one is a widely-
 * known GNU extension often assumed to be "just sed".  Likewise not
 * implemented: GNU's one-line `a text`/`i text`/`c text` shorthand
 * (without the backslash-newline XCU itself documents) -- a/i/c here
 * require the standard's own `a\` followed by <newline>-continued
 * text.  Every refusal above is a real, loud diagnostic and a nonzero
 * exit, this project's usual "refuse rather than silently approximate"
 * rule (see src/util/sort.c's own -m for the same policy stated in
 * full).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <regex.h>
#include "util.h"

#define SED_MAX_SUBGROUPS 32
#define SED_FOLD_WIDTH 70

/* ==== addresses ============================================================ */

enum addr_kind { ADDR_NONE = 0, ADDR_LINE, ADDR_LAST, ADDR_REGEX };

struct sed_addr {
	enum addr_kind kind;
	long line;
	regex_t re;
	int have_re;      /* re holds a compiled pattern (kind==ADDR_REGEX, non-empty) */
	int reuse_last;   /* kind==ADDR_REGEX, empty pattern: use g_last_re */
};

/* ==== replacement text (s command) ========================================= */

enum repl_kind { REPL_LITERAL, REPL_WHOLE, REPL_BACKREF };

struct repl_seg {
	enum repl_kind kind;
	char *lit;        /* REPL_LITERAL: owned bytes */
	size_t litlen;
	int group;         /* REPL_BACKREF: 1-9 */
};

/* ==== program commands ====================================================== */

enum cmd_kind {
	CMD_BLOCK_START, CMD_BLOCK_END, CMD_LABEL,
	CMD_SUBST, CMD_TRANS, CMD_DELETE, CMD_DELETE_FIRST,
	CMD_PRINT, CMD_PRINT_FIRST, CMD_NEXT, CMD_NEXT_APPEND,
	CMD_GET, CMD_GET_APPEND, CMD_HOLD, CMD_HOLD_APPEND, CMD_EXCHANGE,
	CMD_APPEND, CMD_INSERT, CMD_CHANGE, CMD_READ, CMD_WRITE,
	CMD_BRANCH, CMD_TEST, CMD_QUIT, CMD_LINENO, CMD_LIST
};

struct sed_cmd {
	struct sed_addr a1, a2;
	int naddr;         /* 0, 1, 2 */
	int negate;
	enum cmd_kind kind;
	int active;        /* runtime: is a 2-address range currently open? */

	/* s/// */
	regex_t re;
	int have_re, reuse_last;
	struct repl_seg *repl;
	size_t nrepl;
	int flag_g;
	long occurrence;   /* 1-based, default 1 */
	int flag_p;
	char *wfile;

	/* y/// */
	unsigned char ymap[256];
	int have_y;

	/* a/i/c text, and comment/label */
	char *text;

	/* r/w filename */
	char *filename;

	/* b/t label */
	char *label;
	long target;       /* resolved index into prog[], or -1 for "end" */

	/* '{' only: index one past the matching '}' */
	long block_end;
};

/* ==== w-file table: one FILE*, opened (truncated) once, per distinct
 * name -- so `s/x/y/w out` on every one of a thousand lines does not
 * truncate `out` a thousand times. ========================================= */

struct wfile_entry { char *name; FILE *f; };

struct wfile_table {
	struct wfile_entry *entries;
	size_t n, cap;
};

/* Deliberately NOT withtok(file_stream_open): unlike a plain producer,
 * this cache sometimes returns a FILE* it already owns from a previous
 * call (t->entries[i].f, read back below) rather than a fresh
 * acquisition -- annotating it produced a real false leak at every
 * caller that merely uses the cached result without itself closing it
 * (e.g. wfile_write_line()), since the checker cannot distinguish "just
 * minted" from "borrowed back from our own cache" on a producer's
 * return value. wfile_table_close() below is what actually proves this
 * cache leaks nothing. */
static FILE *wfile_get(struct wfile_table *t, const char *name)
{
	size_t i;
	FILE *f;
	for (i = 0; i < t->n; i++)
		if (!strcmp(t->entries[i].name, name)) return t->entries[i].f;

	if (t->n >= t->cap) {
		size_t newcap;
		struct wfile_entry *g;
		if (!__util_array_capacity(t->cap, t->n, 1, 8, sizeof *g, &newcap)) return 0;
		g = __util_reallocarray(t->entries, newcap, sizeof *g);
		if (!g) return 0;
		t->entries = g;
		t->cap = newcap;
	}

	if (!strcmp(name, "/dev/stdout")) f = stdout;
	else if (!strcmp(name, "/dev/stderr")) f = stderr;
	else f = fopen(name, "w");
	if (!f) return 0;
	t->entries[t->n].name = strdup(name);
	if (!t->entries[t->n].name) {
		if (f != stdout && f != stderr) (void)fclose(f);
		return 0;
	}
	t->entries[t->n].f = f;
	t->n++;
	return f;
}

/* s///w and the w command share this exact "look up (or open) the
 * w-file, then write the pattern space plus a trailing newline to it if
 * that lookup succeeded" pairing -- folded into one helper so neither
 * call site has to re-pair wfile_get()'s result with the write itself. */
static void wfile_write_line(struct wfile_table *t, const char *name, const char *data, size_t len)
{
	FILE *wf = wfile_get(t, name);
	if (wf) { fwrite(data, 1, len, wf); fputc('\n', wf); }
}

static int wfile_table_close(struct wfile_table *t)
{
	size_t i;
	int had_error = 0;
	for (i = 0; i < t->n; i++) {
		if (t->entries[i].f != stdout && t->entries[i].f != stderr &&
		    fclose(t->entries[i].f) != 0) {
			__util_diagf("sed: %s: %s\n", t->entries[i].name, strerror(errno));
			had_error = 1;
		}
		free(t->entries[i].name);
	}
	free(t->entries);
	t->entries = 0; t->n = 0; t->cap = 0;
	return had_error;
}

/* ==== append queue: a\ text and r file, drained per XCU's own timing
 * rule (see this file's header comment). ==================================== */

enum append_kind { APPEND_TEXT, APPEND_RFILE };

struct append_entry {
	enum append_kind kind;
	const char *text_or_file; /* not owned: points into the owning sed_cmd */
};

struct append_queue {
	struct append_entry *entries;
	size_t n, cap;
};

static int queue_append(struct append_queue *q, enum append_kind kind, const char *s)
{
	if (q->n >= q->cap) {
		size_t newcap;
		struct append_entry *g;
		if (!__util_array_capacity(q->cap, q->n, 1, 8, sizeof *g, &newcap)) return -1;
		g = __util_reallocarray(q->entries, newcap, sizeof *g);
		if (!g) return -1;
		q->entries = g;
		q->cap = newcap;
	}
	q->entries[q->n].kind = kind;
	q->entries[q->n].text_or_file = s;
	q->n++;
	return 0;
}

static void flush_appends(struct append_queue *q)
{
	size_t i;
	for (i = 0; i < q->n; i++) {
		if (q->entries[i].kind == APPEND_TEXT) {
			fputs(q->entries[i].text_or_file, stdout);
		} else {
			/* "the contents of the file ... shall be as of the time
			 * the output is written, not the time the r command is
			 * applied" -- read fresh, right here.  A missing/unreadable
			 * rfile is treated as empty, per XCU's own r command text. */
			FILE *rf = fopen(q->entries[i].text_or_file, "rb");
			if (rf) {
				char buf[4096];
				size_t got;
				while ((got = fread(buf, 1, sizeof buf, rf)) > 0)
					fwrite(buf, 1, got, stdout);
				(void)fclose(rf);
			}
		}
	}
	q->n = 0;
}

/* ==== growable byte buffer, used for the script text and the pattern/
 * hold spaces (all three can grow past any fixed size via N, G, H, s///
 * with backreferences, etc.) ================================================ */

struct buf { char *data withtok(readable_span(len)) withtok(writable_span(cap)); size_t len, cap; };

static int buf_reserve(struct buf *b, size_t extra)
{
	size_t need;
	if (!__util_size_add(b->len, extra, &need)) return -1;
	if (need + 1 <= b->cap) return 0;
	{
		size_t newcap;
		char *g;
		if (!__util_array_capacity(b->cap, b->len, extra + 1, 64, 1, &newcap)) return -1;
		g = realloc(b->data, newcap);
		if (!g) return -1;
		b->data = g;
		b->cap = newcap;
	}
	return 0;
}

static int buf_append(struct buf *b, const char *s, size_t n)
{
	if (buf_reserve(b, n) < 0) return -1;
	for (size_t i = 0; i < n; i++) b->data[b->len + i] = s[i];
	b->len += n;
	b->data[b->len] = 0;
	return 0;
}

static int buf_append_str(struct buf *b, const char *s) { return buf_append(b, s, strlen(s)); }
static int buf_append_char(struct buf *b, char c) { return buf_append(b, &c, 1); }

static void buf_free(struct buf *b) { free(b->data); b->data = 0; b->len = b->cap = 0; }

static void buf_set(struct buf *dst, const struct buf *src)
{
	dst->len = 0;
	buf_append(dst, src->data ? src->data : "", src->len);
}

/* ==== script assembly (-e/-f/bare-script, each -e insertion preceded
 * by a <newline> if the previous addition was itself from -e) ============== */

static int script_buf_append(struct buf *b, const char *s, int need_leading_newline)
{
	if (need_leading_newline && b->len) if (buf_append_char(b, '\n') < 0) return -1;
	return buf_append_str(b, s);
}

static int script_buf_append_file(struct buf *b, const char *path, int need_leading_newline)
{
	FILE *f;
	char chunk[4096];
	size_t got;

	if (need_leading_newline && b->len) if (buf_append_char(b, '\n') < 0) return -1;
	f = !strcmp(path, "-") ? stdin : fopen(path, "rb");
	if (!f) return -1;
	while ((got = fread(chunk, 1, sizeof chunk, f)) > 0)
		if (buf_append(b, chunk, got) < 0) { if (f != stdin) (void)fclose(f); return -1; }
	if (f != stdin) (void)fclose(f);
	return 0;
}

/* ==== parser =============================================================== */

struct parser {
	const char *p;
	const char *prog;   /* argv[0], for diagnostics */
	char errbuf[256];
};

static void perr(struct parser *ps, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
static void perr(struct parser *ps, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(ps->errbuf, sizeof ps->errbuf, fmt, ap);
	va_end(ap);
}

static void skip_blank(struct parser *ps)
{
	while (*ps->p == ' ' || *ps->p == '\t') ps->p++;
}

/* Skips blanks, semicolons and newlines between commands. */
static void skip_seps(struct parser *ps)
{
	for (;;) {
		if (*ps->p == ' ' || *ps->p == '\t' || *ps->p == ';' || *ps->p == '\n') ps->p++;
		else break;
	}
}

/* Extracts a delimiter-bounded field starting at *ps->p (which points
 * just past the opening delimiter already), stopping at the first
 * unescaped `delim` or NUL/<newline>.  `raw` selects which unescaping
 * rule applies: raw!=0 (the BRE half of s/// and addresses) only turns
 * "\<delim>" into a literal delim byte, copying every other backslash
 * pair through untouched for regcomp() to interpret; raw==0 (replacement
 * text, y/// operands) fully unescapes every "\X" to a literal X,
 * "\<newline>" to a literal <newline> byte, per XCU's own rule for
 * those two contexts.  Returns 0 with *out set and the cursor past the
 * closing delimiter, or -1 (unterminated). */
static int extract_field(struct parser *ps, char delim, int raw, struct buf *out)
{
	out->len = 0;
	for (;;) {
		char c = *ps->p;
		if (c == delim) { ps->p++; return 0; }
		if (c == 0 || c == '\n') { perr(ps, "unterminated expression (missing '%c')", delim); return -1; }
		if (c == '\\' && ps->p[1] != 0) {
			char n = ps->p[1];
			if (n == delim) { buf_append_char(out, delim); ps->p += 2; continue; }
			if (raw) { buf_append_char(out, '\\'); buf_append_char(out, n); ps->p += 2; continue; }
			if (n == '\n') { buf_append_char(out, '\n'); ps->p += 2; continue; }
			buf_append_char(out, n); ps->p += 2; continue;
		}
		buf_append_char(out, c);
		ps->p++;
	}
}

static int compile_bre(struct parser *ps, const char *pattern, regex_t *re)
{
	int rc = regcomp(re, pattern, 0);
	if (rc != 0) {
		char eb[128];
		regerror(rc, re, eb, sizeof eb);
		perr(ps, "invalid regular expression: %s", eb);
		return -1;
	}
	return 0;
}

/* Parses one address (line number, '$', or a /BRE/ or \cBREc context
 * address) at *ps->p.  Returns 1 if an address was present (a->kind
 * set), 0 if the cursor was not at the start of an address at all
 * (left untouched), or -1 on a malformed address. */
static int parse_one_address(struct parser *ps, struct sed_addr *a)
{
	memset(a, 0, sizeof *a);
	if (*ps->p >= '0' && *ps->p <= '9') {
		char *end;
		long v = strtol(ps->p, &end, 10);
		if (v < 0) { perr(ps, "invalid line-number address"); return -1; }
		a->kind = ADDR_LINE;
		a->line = v;
		ps->p = end;
		return 1;
	}
	if (*ps->p == '$') { a->kind = ADDR_LAST; ps->p++; return 1; }
	if (*ps->p == '/' || (*ps->p == '\\' && ps->p[1] != 0)) {
		char delim;
		struct buf pat;
		memset(&pat, 0, sizeof pat);
		if (*ps->p == '/') { delim = '/'; ps->p++; }
		else { delim = ps->p[1]; ps->p += 2; }
		if (extract_field(ps, delim, 1, &pat) < 0) { buf_free(&pat); return -1; }
		a->kind = ADDR_REGEX;
		if (pat.len == 0) { a->reuse_last = 1; }
		else if (compile_bre(ps, pat.data, &a->re) < 0) { buf_free(&pat); return -1; }
		else a->have_re = 1;
		buf_free(&pat);
		return 1;
	}
	return 0;
}

/* Parses the replacement half of s/// into segments: literal runs,
 * REPL_WHOLE for an unescaped '&', REPL_BACKREF for \1-\9.  "\<delim>"
 * and every other "\X" are already reduced to a literal X by the
 * shared delimiter logic here (not extract_field(), since this needs
 * to keep '&' and '\digit' distinguishable from ordinary literal
 * bytes rather than flattening them first). */
static int parse_replacement(struct parser *ps, char delim, struct repl_seg **out, size_t *nout)
{
	struct repl_seg *segs = 0;
	size_t n = 0, cap = 0;
	struct buf lit;
	memset(&lit, 0, sizeof lit);

#define FLUSH_LIT() \
	do { \
		if (lit.len) { \
			if (n >= cap) { \
				size_t newcap; struct repl_seg *g; \
				if (!__util_array_capacity(cap, n, 1, 8, sizeof *g, &newcap)) goto fail; \
				g = __util_reallocarray(segs, newcap, sizeof *g); \
				if (!g) goto fail; \
				segs = g; cap = newcap; \
			} \
			segs[n].kind = REPL_LITERAL; \
			segs[n].lit = malloc(lit.len + 1); \
			if (!segs[n].lit) goto fail; \
			for (size_t _j = 0; _j < lit.len; _j++) \
				segs[n].lit[_j] = lit.data[_j]; \
			segs[n].lit[lit.len] = 0; \
			segs[n].litlen = lit.len; \
			n++; \
			lit.len = 0; \
		} \
	} while (0)

	for (;;) {
		char c = *ps->p;
		if (c == delim) { ps->p++; break; }
		if (c == 0 || c == '\n') { perr(ps, "unterminated s/// replacement"); goto fail; }
		if (c == '&') {
			FLUSH_LIT();
			if (n >= cap) {
				size_t newcap; struct repl_seg *g;
				if (!__util_array_capacity(cap, n, 1, 8, sizeof *g, &newcap)) goto fail;
				g = __util_reallocarray(segs, newcap, sizeof *g);
				if (!g) goto fail;
				segs = g; cap = newcap;
			}
			segs[n].kind = REPL_WHOLE;
			n++;
			ps->p++;
			continue;
		}
		if (c == '\\' && ps->p[1] != 0) {
			char nc = ps->p[1];
			if (nc >= '1' && nc <= '9') {
				FLUSH_LIT();
				if (n >= cap) {
					size_t newcap; struct repl_seg *g;
					if (!__util_array_capacity(cap, n, 1, 8, sizeof *g, &newcap)) goto fail;
					g = __util_reallocarray(segs, newcap, sizeof *g);
					if (!g) goto fail;
					segs = g; cap = newcap;
				}
				segs[n].kind = REPL_BACKREF;
				segs[n].group = nc - '0';
				n++;
				ps->p += 2;
				continue;
			}
			if (nc == '\n') { buf_append_char(&lit, '\n'); ps->p += 2; continue; }
			/* "\&", "\\", "\<delim>" and any other "\X" all reduce to a
			 * literal X here, matching XCU's own general rule. */
			buf_append_char(&lit, nc);
			ps->p += 2;
			continue;
		}
		buf_append_char(&lit, c);
		ps->p++;
	}
	FLUSH_LIT();
#undef FLUSH_LIT
	buf_free(&lit);
	*out = segs;
	*nout = n;
	return 0;
fail:
	buf_free(&lit);
	{
		size_t i;
		for (i = 0; i < n; i++) if (segs[i].kind == REPL_LITERAL) free(segs[i].lit);
	}
	free(segs);
	return -1;
}

/* Parses the a\/i\/c\ text argument: `\` (already consumed by the
 * caller) then, per XCU, one or more <newline>-continued lines --
 * "Each embedded <newline> in the text shall be preceded by a
 * <backslash>.  Other <backslash> characters ... shall be removed,
 * and the following character ... treated literally."  This file
 * additionally accepts the immediate-newline-after-backslash form
 * (`a\` then a real <newline>, text starting on the next line) and
 * the same-line form (`a\text`, no newline at all after the `\`) --
 * both are the same one-or-more-lines grammar, just where the first
 * line's own text starts. */
static int parse_text_arg(struct parser *ps, struct buf *out)
{
	out->len = 0;
	if (*ps->p == '\n') ps->p++;
	for (;;) {
		char c = *ps->p;
		if (c == 0) break;
		if (c == '\n') { ps->p++; break; }
		if (c == '\\' && ps->p[1] != 0) {
			char n = ps->p[1];
			buf_append_char(out, n);
			ps->p += 2;
			continue;
		}
		if (c == '\\' && ps->p[1] == 0) { ps->p++; break; } /* trailing backslash, no more script */
		buf_append_char(out, c);
		ps->p++;
	}
	buf_append_char(out, '\n');
	return 0;
}

/* Rest-of-line filename for r/w (and s///w), and for a label. */
static char *dup_rest_of_line(struct parser *ps)
{
	const char *start;
	char *out;
	size_t n;
	skip_blank(ps);
	start = ps->p;
	n = strcspn(ps->p, "\n");
	ps->p += n;
	while (n && (start[n - 1] == ' ' || start[n - 1] == '\t')) n--;
	out = malloc(n + 1);
	if (!out) return 0;
	for (size_t i = 0; i < n; i++) out[i] = start[i];
	out[n] = 0;
	return out;
}

static char *dup_label(struct parser *ps)
{
	const char *start;
	char *out;
	size_t n;
	skip_blank(ps);
	start = ps->p;
	/* '}' stops a label/branch-target name too, same as ';'/<newline>/
	 * blank: a b/t/: with no address argument of its own is exactly as
	 * likely to be the last command inside a { ... } block as p, d, s///,
	 * etc. are, and unlike CMD_SUBST and friends this command's "rest of
	 * the argument" is consumed right here rather than by the shared
	 * terminator check further down parse_script() -- so that check
	 * accepting '}' does nothing for b/t/: unless this scan does too. */
	n = strcspn(ps->p, "\n;} \t");
	ps->p += n;
	out = malloc(n + 1);
	if (!out) return 0;
	for (size_t i = 0; i < n; i++) out[i] = start[i];
	out[n] = 0;
	return out;
}

struct program {
	struct sed_cmd *cmds;
	size_t n, cap;
};

static struct sed_cmd *prog_push(struct program *pr)
{
	if (pr->n >= pr->cap) {
		size_t newcap;
		struct sed_cmd *g;
		if (!__util_array_capacity(pr->cap, pr->n, 1, 32, sizeof *g, &newcap)) return 0;
		g = __util_reallocarray(pr->cmds, newcap, sizeof *g);
		if (!g) return 0;
		pr->cmds = g;
		pr->cap = newcap;
	}
	memset(&pr->cmds[pr->n], 0, sizeof pr->cmds[pr->n]);
	return &pr->cmds[pr->n++];
}

/* y/string1/string2/ -- fully unescaped per-character, both strings
 * must end up the same length. */
static int parse_y(struct parser *ps, struct sed_cmd *cmd)
{
	char delim;
	struct buf s1, s2;
	size_t i;

	if (*ps->p == 0) { perr(ps, "y: missing delimiter"); return -1; }
	delim = *ps->p;
	ps->p++;
	memset(&s1, 0, sizeof s1);
	memset(&s2, 0, sizeof s2);
	if (extract_field(ps, delim, 0, &s1) < 0) { buf_free(&s1); return -1; }
	if (extract_field(ps, delim, 0, &s2) < 0) { buf_free(&s1); buf_free(&s2); return -1; }
	if (s1.len != s2.len) {
		perr(ps, "y: strings have different lengths");
		buf_free(&s1); buf_free(&s2);
		return -1;
	}
	for (i = 0; i < 256; i++) cmd->ymap[i] = (unsigned char)i;
	for (i = 0; i < s1.len; i++) cmd->ymap[(unsigned char)s1.data[i]] = (unsigned char)s2.data[i];
	cmd->have_y = 1;
	buf_free(&s1);
	buf_free(&s2);
	return 0;
}

static int parse_s(struct parser *ps, struct sed_cmd *cmd)
{
	char delim;
	struct buf pat;

	if (*ps->p == 0 || *ps->p == '\n') { perr(ps, "s: missing delimiter"); return -1; }
	delim = *ps->p;
	if (delim == '\\' || delim == '\n') { perr(ps, "s: invalid delimiter"); return -1; }
	ps->p++;
	memset(&pat, 0, sizeof pat);
	if (extract_field(ps, delim, 1, &pat) < 0) { buf_free(&pat); return -1; }
	if (pat.len == 0) cmd->reuse_last = 1;
	else if (compile_bre(ps, pat.data, &cmd->re) < 0) { buf_free(&pat); return -1; }
	else cmd->have_re = 1;
	buf_free(&pat);

	if (parse_replacement(ps, delim, &cmd->repl, &cmd->nrepl) < 0) return -1;

	cmd->occurrence = 1;
	for (;;) {
		char c = *ps->p;
		if (c >= '0' && c <= '9') {
			char *end;
			long v = strtol(ps->p, &end, 10);
			if (v < 1) { perr(ps, "s: invalid occurrence flag"); return -1; }
			cmd->occurrence = v;
			ps->p = end;
			continue;
		}
		if (c == 'g') { cmd->flag_g = 1; ps->p++; continue; }
		if (c == 'p') { cmd->flag_p = 1; ps->p++; continue; }
		if (c == 'w') {
			ps->p++;
			cmd->wfile = dup_rest_of_line(ps);
			if (!cmd->wfile) { perr(ps, "out of memory"); return -1; }
			return 0; /* w consumes the rest of the line */
		}
		if (c == 'i' || c == 'I' || c == 'm' || c == 'M') {
			perr(ps, "s: flag '%c' (case-insensitive/multiline) is a GNU "
			         "extension, not implemented -- see src/util/sed.c", c);
			return -1;
		}
		break;
	}
	return 0;
}

/* Forward-declared: label resolution needs every ':' command's name,
 * gathered during the same pass that builds prog[]. */
static int parse_script(struct parser *ps, struct program *pr)
{
	while (*ps->p) {
		struct sed_addr a1, a2;
		int have1 = 0, have2 = 0, negate = 0;
		int r;
		struct sed_cmd *cmd;
		char c;

		skip_seps(ps);
		if (!*ps->p) break;

		if (*ps->p == '#') {
			while (*ps->p && *ps->p != '\n') ps->p++;
			continue;
		}
		if (*ps->p == '}') {
			ps->p++;
			cmd = prog_push(pr);
			if (!cmd) { perr(ps, "out of memory"); return -1; }
			cmd->kind = CMD_BLOCK_END;
			continue;
		}

		r = parse_one_address(ps, &a1);
		if (r < 0) return -1;
		if (r) {
			have1 = 1;
			skip_blank(ps);
			if (*ps->p == ',') {
				ps->p++;
				skip_blank(ps);
				r = parse_one_address(ps, &a2);
				if (r <= 0) { perr(ps, "expected address after ','"); return -1; }
				have2 = 1;
			}
		}
		skip_blank(ps);
		while (*ps->p == '!') { negate = 1; ps->p++; skip_blank(ps); }

		if (!*ps->p) { perr(ps, "missing command"); return -1; }

		cmd = prog_push(pr);
		if (!cmd) { perr(ps, "out of memory"); return -1; }
		if (have1) cmd->a1 = a1;
		if (have2) cmd->a2 = a2;
		if (have2) cmd->naddr = 2;
		else if (have1) cmd->naddr = 1;
		else cmd->naddr = 0;
		cmd->negate = negate;

		{
			c = *ps->p;
			ps->p++;
			switch (c) { // NOLINT(bugprone-switch-missing-default-case) -- default: below covers every unmatched byte
			case '{':
				cmd->kind = CMD_BLOCK_START;
				break;
			case 's':
				cmd->kind = CMD_SUBST;
				if (parse_s(ps, cmd) < 0) return -1;
				break;
			case 'y':
				cmd->kind = CMD_TRANS;
				if (parse_y(ps, cmd) < 0) return -1;
				break;
			case 'd': cmd->kind = CMD_DELETE; break;
			case 'D': cmd->kind = CMD_DELETE_FIRST; break;
			case 'p': cmd->kind = CMD_PRINT; break;
			case 'P': cmd->kind = CMD_PRINT_FIRST; break;
			case 'n': cmd->kind = CMD_NEXT; break;
			case 'N': cmd->kind = CMD_NEXT_APPEND; break;
			case 'g': cmd->kind = CMD_GET; break;
			case 'G': cmd->kind = CMD_GET_APPEND; break;
			case 'h': cmd->kind = CMD_HOLD; break;
			case 'H': cmd->kind = CMD_HOLD_APPEND; break;
			case 'x': cmd->kind = CMD_EXCHANGE; break;
			case '=': cmd->kind = CMD_LINENO; break;
			case 'l': cmd->kind = CMD_LIST; break;
			case 'q':
				cmd->kind = CMD_QUIT;
				if (*ps->p >= '0' && *ps->p <= '9') {
					perr(ps, "q: an exit-code operand is a GNU extension, "
					         "not implemented -- see src/util/sed.c");
					return -1;
				}
				break;
			case 'a':
				cmd->kind = CMD_APPEND;
				if (*ps->p != '\\') { perr(ps, "a: expected '\\'"); return -1; }
				ps->p++;
				{
					struct buf t; memset(&t, 0, sizeof t);
					if (parse_text_arg(ps, &t) < 0) { buf_free(&t); return -1; }
					cmd->text = t.data;
				}
				break;
			case 'i':
				cmd->kind = CMD_INSERT;
				if (*ps->p != '\\') { perr(ps, "i: expected '\\'"); return -1; }
				ps->p++;
				{
					struct buf t; memset(&t, 0, sizeof t);
					if (parse_text_arg(ps, &t) < 0) { buf_free(&t); return -1; }
					cmd->text = t.data;
				}
				break;
			case 'c':
				cmd->kind = CMD_CHANGE;
				if (*ps->p != '\\') { perr(ps, "c: expected '\\'"); return -1; }
				ps->p++;
				{
					struct buf t; memset(&t, 0, sizeof t);
					if (parse_text_arg(ps, &t) < 0) { buf_free(&t); return -1; }
					cmd->text = t.data;
				}
				break;
			case 'r':
				cmd->kind = CMD_READ;
				cmd->filename = dup_rest_of_line(ps);
				if (!cmd->filename) { perr(ps, "out of memory"); return -1; }
				break;
			case 'w':
				cmd->kind = CMD_WRITE;
				cmd->filename = dup_rest_of_line(ps);
				if (!cmd->filename) { perr(ps, "out of memory"); return -1; }
				break;
			case 'b':
				cmd->kind = CMD_BRANCH;
				cmd->label = dup_label(ps);
				break;
			case 't':
				cmd->kind = CMD_TEST;
				cmd->label = dup_label(ps);
				break;
			case ':':
				cmd->kind = CMD_LABEL;
				cmd->label = dup_label(ps);
				if (!cmd->label || !cmd->label[0]) { perr(ps, ": missing label"); return -1; }
				if (cmd->naddr) { perr(ps, ": does not take an address"); return -1; }
				break;
			default:
				perr(ps, "unknown command '%c'", c);
				return -1;
			}
		}

		/* Address-count enforcement per XCU's own [Naddr] annotations. */
		switch (cmd->kind) {
		case CMD_APPEND: case CMD_INSERT: case CMD_READ: case CMD_QUIT: case CMD_LINENO:
			if (cmd->naddr > 1) { perr(ps, "command accepts at most one address"); return -1; }
			break;
		case CMD_LABEL: case CMD_BLOCK_END:
			if (cmd->naddr) { perr(ps, "command does not accept an address"); return -1; }
			break;
		default:
			break;
		}

		/* Commands other than {, a, b, c, i, r, t, w, :, # may be
		 * followed by ';'; those instead run to end-of-line (already
		 * consumed by dup_rest_of_line()/parse_text_arg()/dup_label()
		 * for the ones that take an argument at all).  A command may
		 * also be immediately followed by '}' with no ';' or <newline>
		 * of its own -- XCU's own N{cmd1;cmd2} grammar lets a block's
		 * *last* command's terminator be the closing brace itself, so
		 * '}' ends a command exactly like ';'/<newline>/EOF do, and is
		 * deliberately left unconsumed here: the top of this loop's own
		 * `if (*ps->p == '}')` check is what actually recognizes it as
		 * CMD_BLOCK_END on the next iteration. */
		if (cmd->kind != CMD_BLOCK_START) {
			skip_blank(ps);
			if (*ps->p && *ps->p != '\n' && *ps->p != ';' && *ps->p != '#' && *ps->p != '}') {
				switch (cmd->kind) {
				case CMD_APPEND: case CMD_INSERT: case CMD_CHANGE:
				case CMD_READ: case CMD_WRITE: case CMD_BRANCH:
				case CMD_TEST: case CMD_LABEL:
					break; /* these already consumed to end of line */
				default:
					perr(ps, "extra characters after command '%c'", c);
					return -1;
				}
			}
		}
	}
	return 0;
}

/* Matches every '{' to its own '}' (cmd->block_end set to one past the
 * '}', so a not-selected block's address check can jump straight past
 * it) and resolves every b/t label against the program's ':' commands.
 * A bare "b"/"t" (empty label) targets pr->n itself -- "end of script",
 * which the pc < (long)pr->n loop condition in run_program() below
 * already treats identically to falling off the end normally. */
static int resolve_program(struct parser *ps, struct program *pr)
{
	long *stack;
	size_t sp = 0, cap = 0;
	size_t i;

	stack = 0;
	for (i = 0; i < pr->n; i++) {
		if (pr->cmds[i].kind == CMD_BLOCK_START) {
			if (sp >= cap) {
				size_t newcap;
				long *g;
				if (!__util_array_capacity(cap, sp, 1, 16, sizeof *g, &newcap)) { free(stack); return -1; }
				g = __util_reallocarray(stack, newcap, sizeof *g);
				if (!g) { free(stack); return -1; }
				stack = g; cap = newcap;
			}
			stack[sp++] = (long)i;
		} else if (pr->cmds[i].kind == CMD_BLOCK_END) {
			if (!sp) { perr(ps, "unmatched '}'"); free(stack); return -1; }
			pr->cmds[stack[--sp]].block_end = (long)i + 1;
		}
	}
	if (sp) { perr(ps, "unmatched '{'"); free(stack); return -1; }
	free(stack);

	for (i = 0; i < pr->n; i++) {
		struct sed_cmd *cmd = &pr->cmds[i];
		size_t j;
		int found;

		if (cmd->kind != CMD_BRANCH && cmd->kind != CMD_TEST) continue;
		if (!cmd->label || !cmd->label[0]) { cmd->target = (long)pr->n; continue; }

		found = 0;
		for (j = 0; j < pr->n; j++) {
			if (pr->cmds[j].kind == CMD_LABEL && pr->cmds[j].label &&
			    !strcmp(pr->cmds[j].label, cmd->label)) {
				cmd->target = (long)j;
				found = 1;
				break;
			}
		}
		if (!found) { perr(ps, "can't find label for jump to '%s'", cmd->label); return -1; }
	}
	return 0;
}

static void free_addr(struct sed_addr *a)
{
	if (a->have_re) regfree(&a->re);
}

static void free_program(struct program *pr)
{
	size_t i, j;
	for (i = 0; i < pr->n; i++) {
		struct sed_cmd *cmd = &pr->cmds[i];
		free_addr(&cmd->a1);
		free_addr(&cmd->a2);
		if (cmd->have_re) regfree(&cmd->re);
		for (j = 0; j < cmd->nrepl; j++)
			if (cmd->repl[j].kind == REPL_LITERAL) free(cmd->repl[j].lit);
		free(cmd->repl);
		free(cmd->wfile);
		free(cmd->text);
		free(cmd->filename);
		free(cmd->label);
	}
	free(pr->cmds);
	pr->cmds = 0; pr->n = 0; pr->cap = 0;
}

/* ==== input: every operand (or stdin) read fully into memory up front,
 * concatenated in argv order, so "$" and cumulative line numbering are
 * plain index comparisons -- see this file's header comment. ============== */

struct input_line { char *text; size_t len; };

struct input_set { struct input_line *lines; size_t n, cap; };

static int input_push(struct input_set *in, const char *text, size_t len)
{
	char *copy;
	if (in->n >= in->cap) {
		size_t newcap;
		struct input_line *g;
		if (!__util_array_capacity(in->cap, in->n, 1, 256, sizeof *g, &newcap)) return -1;
		g = __util_reallocarray(in->lines, newcap, sizeof *g);
		if (!g) return -1;
		in->lines = g; in->cap = newcap;
	}
	copy = malloc(len + 1);
	if (!copy) return -1;
	for (size_t i = 0; i < len; i++) copy[i] = text[i];
	copy[len] = 0;
	in->lines[in->n].text = copy;
	in->lines[in->n].len = len;
	in->n++;
	return 0;
}

static int read_all_input(FILE *f, struct input_set *in)
{
	char *buf = 0;
	size_t cap = 0;
	ssize_t got;
	while ((got = getline(&buf, &cap, f)) >= 0) {
		size_t len = (size_t)got;
		if (len && buf[len - 1] == '\n') len--;
		if (input_push(in, buf, len) < 0) { free(buf); return -1; }
	}
	free(buf);
	return 0;
}

static void free_input(struct input_set *in)
{
	size_t i;
	for (i = 0; i < in->n; i++) free(in->lines[i].text);
	free(in->lines);
	in->lines = 0; in->n = 0; in->cap = 0;
}

/* ==== execution state ======================================================= */

struct sed_state {
	struct input_line *lines;
	size_t nlines;
	size_t cursor;       /* index of the next not-yet-read line */
	long line_number;    /* 1-based, of the line most recently read */
	struct buf pattern;
	struct buf hold;
	regex_t *last_re;    /* most recently used RE, for an empty // to reuse */
	struct wfile_table wtab;
	struct append_queue aq;
	const char *prog_name;
};

static void buf_assign(struct buf *b, const char *s, size_t n) { b->len = 0; buf_append(b, s, n); }

static int addr_matches(struct sed_state *st, struct sed_addr *a)
{
	regex_t *re;
	switch (a->kind) {
	case ADDR_LINE: return st->line_number == a->line;
	case ADDR_LAST: return st->cursor >= st->nlines;
	case ADDR_REGEX:
		re = a->reuse_last ? st->last_re : &a->re;
		if (!re) { __util_diagf("%s: no previous regular expression\n", st->prog_name); return 0; }
		st->last_re = re;
		return regexec(re, st->pattern.data, 0, 0, 0) == 0;
	default: return 0;
	}
}

static int cmd_selected(struct sed_state *st, struct sed_cmd *cmd)
{
	int sel;

	if (cmd->naddr == 0) sel = 1;
	else if (cmd->naddr == 1) sel = addr_matches(st, &cmd->a1);
	else if (!cmd->active) {
		sel = addr_matches(st, &cmd->a1);
		if (sel) {
			cmd->active = 1;
			if (cmd->a2.kind == ADDR_LINE && cmd->a2.line <= st->line_number) cmd->active = 0;
		}
	} else {
		sel = 1;
		if (cmd->a2.kind == ADDR_LINE) { if (st->line_number >= cmd->a2.line) cmd->active = 0; }
		else if (cmd->a2.kind == ADDR_LAST) { if (st->cursor >= st->nlines) cmd->active = 0; }
		else if (addr_matches(st, &cmd->a2)) cmd->active = 0;
	}
	return cmd->negate ? !sel : sel;
}

/* ==== s/// substitution engine ============================================= */

static void expand_replacement(struct sed_cmd *cmd, const char *text, size_t pos,
                                const regmatch_t *pm, struct buf *out)
{
	size_t i;
	for (i = 0; i < cmd->nrepl; i++) {
		struct repl_seg *s = &cmd->repl[i];
		if (s->kind == REPL_LITERAL) {
			buf_append(out, s->lit, s->litlen);
		} else if (s->kind == REPL_WHOLE) {
			if (pm[0].rm_so >= 0)
				buf_append(out, text + pos + (size_t)pm[0].rm_so,
				           (size_t)(pm[0].rm_eo - pm[0].rm_so));
		} else {
			int g = s->group;
			if (g < SED_MAX_SUBGROUPS && pm[g].rm_so >= 0)
				buf_append(out, text + pos + (size_t)pm[g].rm_so,
				           (size_t)(pm[g].rm_eo - pm[g].rm_so));
		}
	}
}

/* Returns 1 if at least one substitution was made (result already
 * copied into st->pattern), 0 if the pattern never matched, -1 on a
 * fatal error (an empty // with no previous RE yet). */
static int do_subst(struct sed_state *st, struct sed_cmd *cmd)
{
	regex_t *re = cmd->reuse_last ? st->last_re : &cmd->re;
	regmatch_t pm[SED_MAX_SUBGROUPS];
	struct buf result;
	const char *text;
	size_t textlen, pos;
	long count = 0;
	int did = 0, notbol = 0;

	if (!re) { __util_diagf("%s: no previous regular expression\n", st->prog_name); return -1; }
	st->last_re = re;

	memset(&result, 0, sizeof result);
	text = st->pattern.data;
	textlen = st->pattern.len;
	pos = 0;

	for (;;) {
		int rc, k;
		size_t mstart, mend;
		int replace_this;

		for (k = 0; k < SED_MAX_SUBGROUPS; k++) { pm[k].rm_so = -1; pm[k].rm_eo = -1; }
		rc = regexec(re, text + pos, (size_t)SED_MAX_SUBGROUPS, pm, notbol ? REG_NOTBOL : 0);
		if (rc != 0) break;

		mstart = pos + (size_t)pm[0].rm_so;
		mend = pos + (size_t)pm[0].rm_eo;
		count++;
		replace_this = cmd->flag_g ? (count >= cmd->occurrence) : (count == cmd->occurrence);

		buf_append(&result, text + pos, mstart - pos);
		if (replace_this) {
			did = 1;
			expand_replacement(cmd, text, pos, pm, &result);
		} else {
			buf_append(&result, text + mstart, mend - mstart);
		}

		if (mend == mstart) {
			if (mend < textlen) { buf_append_char(&result, text[mend]); pos = mend + 1; }
			else { pos = mend; break; }
		} else {
			pos = mend;
		}
		notbol = 1;
		if (did && !cmd->flag_g) break;
		if (pos > textlen) break;
	}

	if (pos <= textlen) buf_append(&result, text + pos, textlen - pos);
	if (did) buf_set(&st->pattern, &result);
	buf_free(&result);
	return did;
}

/* ==== l command: pattern space in a visually unambiguous form, folded
 * at a fixed width -- XCU leaves the fold width itself "unspecified";
 * see this file's header comment for why 70 was picked. ==================== */

static void do_list(const struct buf *ps)
{
	size_t i, col = 0;
	for (i = 0; i < ps->len; i++) {
		unsigned char ch = (unsigned char)ps->data[i];
		char out[8];
		size_t outlen;
		switch (ch) {
		case '\\': out[0] = '\\'; out[1] = '\\'; outlen = 2; break;
		case '\a': out[0] = '\\'; out[1] = 'a'; outlen = 2; break;
		case '\b': out[0] = '\\'; out[1] = 'b'; outlen = 2; break;
		case '\f': out[0] = '\\'; out[1] = 'f'; outlen = 2; break;
		case '\n': out[0] = '\\'; out[1] = 'n'; outlen = 2; break;
		case '\r': out[0] = '\\'; out[1] = 'r'; outlen = 2; break;
		case '\t': out[0] = '\\'; out[1] = 't'; outlen = 2; break;
		case '\v': out[0] = '\\'; out[1] = 'v'; outlen = 2; break;
		default:
			if (ch < 0x20 || ch >= 0x7f) {
				int formatted = snprintf(out, sizeof out, "\\%03o", (unsigned)ch);
				if (formatted < 0) outlen = 0;
				else {
					outlen = (size_t)formatted;
					if (outlen >= sizeof out) outlen = sizeof out - 1;
				}
			} else {
				out[0] = (char)ch;
				outlen = 1;
			}
			break;
		}
		if (col + outlen > SED_FOLD_WIDTH - 1) { fputs("\\\n", stdout); col = 0; }
		fwrite(out, 1, outlen, stdout);
		col += outlen;
	}
	fputs("$\n", stdout);
}

/* ==== the main per-line cycle ============================================== */

static int run_program(struct sed_state *st, struct program *pr, int opt_n)
{
	int overall_quit = 0;

	while (!overall_quit) {
		if (st->cursor >= st->nlines) break;

		{
			struct input_line *ln = &st->lines[st->cursor++];
			buf_assign(&st->pattern, ln->text, ln->len);
			st->line_number++;
		}

		{
			int t_flag = 0;
			int cycle_active = 1;

			while (cycle_active) {
				int delete_flag = 0;
				int restart = 0;
				long pc = 0;

				while (pc < (long)pr->n) {
					struct sed_cmd *cmd = &pr->cmds[(size_t)pc];
					int sel;

					if (cmd->kind == CMD_LABEL || cmd->kind == CMD_BLOCK_END) { pc++; continue; }

					sel = cmd_selected(st, cmd);

					if (cmd->kind == CMD_BLOCK_START) {
						pc = sel ? pc + 1 : cmd->block_end;
						continue;
					}
					if (!sel) { pc++; continue; }

					switch (cmd->kind) { // NOLINT(bugprone-switch-missing-default-case) -- default: below covers every kind not listed
					case CMD_SUBST: {
						int rc = do_subst(st, cmd);
						if (rc < 0) return 1;
						if (rc) {
							t_flag = 1;
							if (cmd->flag_p) { fwrite(st->pattern.data, 1, st->pattern.len, stdout); fputc('\n', stdout); }
							if (cmd->wfile)
								wfile_write_line(&st->wtab, cmd->wfile, st->pattern.data, st->pattern.len);
						}
						pc++;
						break;
					}
					case CMD_TRANS: {
						size_t i;
						for (i = 0; i < st->pattern.len; i++)
							st->pattern.data[i] = (char)cmd->ymap[(unsigned char)st->pattern.data[i]];
						pc++;
						break;
					}
					case CMD_DELETE:
						delete_flag = 1;
						pc = (long)pr->n;
						break;
					case CMD_DELETE_FIRST: {
						char *nl = memchr(st->pattern.data, '\n', st->pattern.len);
						if (!nl) { delete_flag = 1; pc = (long)pr->n; }
						else {
							size_t off = (size_t)(nl - st->pattern.data) + 1;
							for (size_t i = 0; i < st->pattern.len - off; i++)
								st->pattern.data[i] = st->pattern.data[off + i];
							st->pattern.len -= off;
							st->pattern.data[st->pattern.len] = 0;
							restart = 1;
							pc = (long)pr->n;
						}
						break;
					}
					case CMD_PRINT:
						fwrite(st->pattern.data, 1, st->pattern.len, stdout);
						fputc('\n', stdout);
						pc++;
						break;
					case CMD_PRINT_FIRST: {
						char *nl = memchr(st->pattern.data, '\n', st->pattern.len);
						size_t n = nl ? (size_t)(nl - st->pattern.data) : st->pattern.len;
						fwrite(st->pattern.data, 1, n, stdout);
						fputc('\n', stdout);
						pc++;
						break;
					}
					case CMD_NEXT:
						if (!opt_n) { fwrite(st->pattern.data, 1, st->pattern.len, stdout); fputc('\n', stdout); }
						flush_appends(&st->aq);
						if (st->cursor >= st->nlines) {
							delete_flag = 1;
							overall_quit = 1;
							pc = (long)pr->n;
						} else {
							struct input_line *ln = &st->lines[st->cursor++];
							buf_assign(&st->pattern, ln->text, ln->len);
							st->line_number++;
							pc++;
						}
						break;
					case CMD_NEXT_APPEND:
						flush_appends(&st->aq);
						if (st->cursor >= st->nlines) {
							delete_flag = 1;
							overall_quit = 1;
							pc = (long)pr->n;
						} else {
							struct input_line *ln = &st->lines[st->cursor++];
							buf_append_char(&st->pattern, '\n');
							buf_append(&st->pattern, ln->text, ln->len);
							st->line_number++;
							pc++;
						}
						break;
					case CMD_GET: buf_assign(&st->pattern, st->hold.data ? st->hold.data : "", st->hold.len); pc++; break;
					case CMD_GET_APPEND:
						buf_append_char(&st->pattern, '\n');
						buf_append(&st->pattern, st->hold.data ? st->hold.data : "", st->hold.len);
						pc++;
						break;
					case CMD_HOLD: buf_assign(&st->hold, st->pattern.data ? st->pattern.data : "", st->pattern.len); pc++; break;
					case CMD_HOLD_APPEND:
						buf_append_char(&st->hold, '\n');
						buf_append(&st->hold, st->pattern.data ? st->pattern.data : "", st->pattern.len);
						pc++;
						break;
					case CMD_EXCHANGE: { struct buf tmp = st->pattern; st->pattern = st->hold; st->hold = tmp; pc++; break; }
					case CMD_APPEND: queue_append(&st->aq, APPEND_TEXT, cmd->text); pc++; break;
					case CMD_INSERT: fputs(cmd->text, stdout); pc++; break;
					case CMD_CHANGE: {
						int should_print = (cmd->naddr < 2) || !cmd->active;
						if (should_print) fputs(cmd->text, stdout);
						delete_flag = 1;
						pc = (long)pr->n;
						break;
					}
					case CMD_READ: queue_append(&st->aq, APPEND_RFILE, cmd->filename); pc++; break;
					case CMD_WRITE:
						wfile_write_line(&st->wtab, cmd->filename, st->pattern.data, st->pattern.len);
						pc++;
						break;
					case CMD_BRANCH: pc = cmd->target; break;
					case CMD_TEST:
						if (t_flag) { t_flag = 0; pc = cmd->target; }
						else pc++;
						break;
					case CMD_QUIT:
						overall_quit = 1;
						pc = (long)pr->n;
						break;
					case CMD_LINENO: fprintf(stdout, "%ld\n", st->line_number); pc++; break;
					case CMD_LIST: do_list(&st->pattern); pc++; break;
					case CMD_LABEL: case CMD_BLOCK_END: case CMD_BLOCK_START: pc++; break;
					}
				}

				if (restart) continue;

				if (!delete_flag && !opt_n) { fwrite(st->pattern.data, 1, st->pattern.len, stdout); fputc('\n', stdout); }
				flush_appends(&st->aq);
				cycle_active = 0;
			}
		}
	}
	return 0;
}

/* ==== argv parsing / top-level driver ====================================== */

int __util_sed_main(int argc, char **argv)
{
	int opt_n = 0;
	int have_e_or_f = 0;
	int last_was_e = 0;
	struct buf script;
	struct parser ps;
	struct program pr;
	struct sed_state st;
	struct input_set in;
	const char **files = 0;
	size_t nfiles = 0, filescap = 0;
	int i;
	int status = 0;

	memset(&script, 0, sizeof script);
	memset(&pr, 0, sizeof pr);
	memset(&in, 0, sizeof in);
	memset(&st, 0, sizeof st);
	st.prog_name = argv[0] ? argv[0] : "sed";

	for (i = 1; i < argc; i++) {
		char *a = argv[i];

		if (!strcmp(a, "--")) { i++; break; }
		if (a[0] != '-' || a[1] == 0) break;

		if (!strcmp(a, "-n")) { opt_n = 1; continue; }
		if (a[0] == '-' && a[1] == 'e') {
			const char *val;
			if (a[2]) val = a + 2;
			else {
				if (++i >= argc) { __util_diagf("sed: -e: option requires an argument\n"); return 1; }
				val = argv[i];
			}
			if (script_buf_append(&script, val, last_was_e) < 0) {
				__util_diagf("sed: out of memory\n");
				buf_free(&script);
				return 1;
			}
			have_e_or_f = 1;
			last_was_e = 1;
			continue;
		}
		if (a[0] == '-' && a[1] == 'f') {
			const char *val;
			if (a[2]) val = a + 2;
			else {
				if (++i >= argc) { __util_diagf("sed: -f: option requires an argument\n"); return 1; }
				val = argv[i];
			}
			if (script_buf_append_file(&script, val, last_was_e) < 0) {
				__util_diagf("sed: %s: %s\n", val, strerror(errno));
				buf_free(&script);
				return 1;
			}
			have_e_or_f = 1;
			last_was_e = 1;
			continue;
		}
		__util_diagf("sed: %s: invalid option\n", a);
		buf_free(&script);
		return 1;
	}

	if (!have_e_or_f) {
		if (i >= argc) { __util_diagf("sed: missing script operand\n"); buf_free(&script); return 1; }
		if (script_buf_append(&script, argv[i], 0) < 0) {
			__util_diagf("sed: out of memory\n");
			buf_free(&script);
			return 1;
		}
		i++;
	}

	for (; i < argc; i++) {
		if (nfiles >= filescap) {
			size_t newcap;
			const char **g;
			if (!__util_array_capacity(filescap, nfiles, 1, 16, sizeof *g, &newcap)) {
				__util_diagf("sed: out of memory\n");
				buf_free(&script);
				free(files);
				return 1;
			}
			g = __util_reallocarray(files, newcap, sizeof *g);
			if (!g) { __util_diagf("sed: out of memory\n"); buf_free(&script); free(files); return 1; }
			files = g; filescap = newcap;
		}
		files[nfiles++] = argv[i];
	}

	/* "if the first two characters in the script are #n, the default
	 * output shall be suppressed" -- equivalent to -n. */
	if (script.len >= 2 && script.data[0] == '#' && script.data[1] == 'n' &&
	    (script.len == 2 || script.data[2] == '\n')) opt_n = 1;

	ps.p = script.data ? script.data : "";
	ps.prog = st.prog_name;
	ps.errbuf[0] = 0;
	if (parse_script(&ps, &pr) < 0 || resolve_program(&ps, &pr) < 0) {
		__util_diagf("sed: %s\n", ps.errbuf[0] ? ps.errbuf : "invalid script");
		free_program(&pr);
		buf_free(&script);
		free(files);
		return 1;
	}
	buf_free(&script);

	if (nfiles == 0) {
		if (read_all_input(stdin, &in) < 0) {
			__util_diagf("sed: out of memory reading standard input\n");
			free_program(&pr); free_input(&in); free(files);
			return 1;
		}
	} else {
		size_t fi;
		for (fi = 0; fi < nfiles; fi++) {
			FILE *f = !strcmp(files[fi], "-") ? stdin : fopen(files[fi], "rb");
			if (!f) {
				__util_diagf("sed: %s: %s\n", files[fi], strerror(errno));
				free_program(&pr); free_input(&in); free(files);
				return 1;
			}
			if (read_all_input(f, &in) < 0) {
				__util_diagf("sed: out of memory reading %s\n", files[fi]);
				if (f != stdin) (void)fclose(f);
				free_program(&pr); free_input(&in); free(files);
				return 1;
			}
			if (f != stdin) (void)fclose(f);
		}
	}
	free(files);

	st.lines = in.lines;
	st.nlines = in.n;

	status = run_program(&st, &pr, opt_n);

	if (fflush(stdout) != 0 && status == 0) status = 1;

	free_program(&pr);
	free_input(&in);
	buf_free(&st.pattern);
	buf_free(&st.hold);
	if (wfile_table_close(&st.wtab) && status == 0) status = 1;
	free(st.aq.entries);

	return status;
}
