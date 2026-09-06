/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ed(1p): `ed [-p string] [-s] [file]` -- the POSIX line editor.
 *
 * Spec pages consulted (https://pubs.opengroup.org/onlinepubs/9699919799/):
 * utilities/ed.html.
 *
 * ---- SCOPE NARROWINGS, spelled out rather than left as silent gaps ------
 *
 *  - No `W` (append-write) command.  A careful re-read of the live spec
 *    page confirms POSIX ed(1p) has no `W` at all -- it is a GNU/BSD
 *    extension.  Not implemented here.
 *  - No `#` comment command either -- also absent from the POSIX page,
 *    also a common extension this file does not add.
 *  - No `%` address synonym for `1,$` -- POSIX's own address grammar
 *    (ADDRESSES, below "Command Descriptions") does not mention `%` at
 *    all, so this file does not invent it; use `1,$` or a bare `,`.
 *  - SIGHUP: real ed(1p) says "the editor shall write the buffer ... to
 *    a file named 'ed.hup' ... and exit" on SIGHUP.  Because
 *    __util_ed_main() can run in-process as a shell built-in with no
 *    fork/exec (src/sh/builtin.c's bi_ed()), a literal exit() would
 *    tear down the whole calling shell, not just this one command --
 *    exactly the mistake src/util/dd.c's own header comment documents
 *    avoiding for SIGINT.
 *    So SIGHUP here is adapted, not literal: a flag-poll (the same
 *    shape as SIGINT below) noticed between top-level command lines
 *    triggers a best-effort write of the whole buffer to ./ed.hup (if
 *    modified) and then a normal `return` from __util_ed_main(), as if
 *    `Q` had been typed -- never exit()/_exit().  Because the flag is
 *    only polled between top-level command lines (not inside a long
 *    global command or a blocked read the way SIGINT is), this is
 *    coarser-grained than SIGINT's own handling; that's an accepted,
 *    documented gap since SIGHUP has no realistic non-interactive test
 *    surface here anyway.
 *  - `s///` flag combination: an explicit occurrence count N together
 *    with `g` is implemented as "substitute the Nth match and every
 *    match after it on that line" (the traditional sed/ed reading),
 *    not merely "substitute only the Nth".  POSIX's own wording for the
 *    combination is not fully spelled out on the page; this is the
 *    common, expected behavior and is implemented, not narrowed away.
 *  - Undo (`u`) is a single level, exactly as POSIX permits ("shall
 *    undo the effect of the most recent command"; a full history is not
 *    required).  Implemented as a whole-buffer deep-copy swap between
 *    the live buffer and one "shadow" buffer, so a second `u` undoes
 *    the first `u` itself, matching the requirement.  `e`/`E`/`w`/`q`
 *    are deliberately NOT undo-able (POSIX's own undo wording, and this
 *    file, both scope `u` to a/c/d/g/i/j/m/r/s/t/u/v/G/V only) -- a
 *    whole g/v/G/V invocation is one undo unit, not one per line it
 *    touches.
 *  - Within a `g`/`v` command-list, when a sub-command (typically a
 *    range-taking `d`, `m`, or `s`) shifts or deletes OTHER lines still
 *    waiting in that invocation's own match snapshot, this file tracks
 *    that shift precisely for insertions and deletions (the snapshot's
 *    line numbers are kept accurate, and an entry whose line was
 *    deleted is dropped) but does NOT separately detect "this other
 *    marked line's *content* was rewritten in place by an unrelated
 *    substitution and should now be skipped" -- POSIX's own "lines a
 *    command modifies are unmarked" wording most plainly describes the
 *    delete/renumber case this file gets right; the narrower
 *    content-only case is a documented gap, not a silent one.
 *  - `l`'s line folding: POSIX explicitly leaves the fold width
 *    unspecified ("the length ... at which folding occurs is
 *    unspecified").  This file does not fold at all -- one input line
 *    is always one `l`-formatted output line, terminated with the
 *    unescaped `$` the format requires.  A conforming simplification,
 *    not a bug.
 *  - `H`/`h` explanatory text: POSIX does not specify the wording of
 *    these messages at all.  The strings used here are genuinely
 *    informative but are not a normative detail of this file.
 *  - A command that does not take an address (e, E, f, q, Q, u, H, h,
 *    P, and `!`) refuses -- loudly, with the usual `?` -- an address
 *    the caller supplied anyway, rather than silently ignoring it.
 *    `=` is the one deliberate exception: it is allowed to resolve to
 *    address 0 (an empty buffer's `$`) even though address 0 is
 *    otherwise reserved for a/i/m/t/r, because `=` only ever reports a
 *    number and never touches buffer content, so "print 0 for an empty
 *    buffer" is safe and useful rather than a real correctness risk.
 *  - `%` as an entire `s///` replacement text (reuse the previous
 *    replacement) and an empty `//`/`??` RE (reuse the last RE used by
 *    *any* search or substitute) are both implemented exactly as XCU
 *    describes, by keeping the last pattern/replacement as plain
 *    strings and recompiling on reuse -- never caching a live
 *    `regex_t` across calls, so there is no lifetime question about a
 *    stale compiled form.
 *
 * ---- THE BUILTIN-SAFETY SIGNAL DISCIPLINE (the load-bearing part) -------
 *
 * Exactly the shape src/util/dd.c's own header comment describes and
 * this file's own instructions insist on reusing rather than
 * reinventing: `static volatile sig_atomic_t` flags set from trivial
 * handlers (nothing else runs inside either handler -- no fprintf, no
 * exit()/_exit(), no cleanup), polled by the ordinary call stack
 * between logical steps (each top-level command line; each line of
 * text collected by a/i/c; each line of a `g`/`v` command-list
 * iteration; each `G`/`V` per-match step), and the previous SIGINT/
 * SIGHUP dispositions are restored via sigaction's `oldact` on every
 * return path out of __util_ed_main() -- including every error return,
 * not just the success path.  __util_ed_main() can run in-process as a
 * shell built-in with no fork/exec, sharing the calling shell's own
 * process; leaving a handler installed after `ed` returns would keep
 * intercepting signals for the rest of the shell's own life, and this
 * file never calls exit()/_exit() anywhere for exactly that reason --
 * `q`/`Q`/EOF-in-command-mode all `return` a real status from
 * __util_ed_main() instead.  No file-scope buffer state persists
 * either: the entire edit buffer, marks, undo shadow, and remembered
 * strings live in one on-stack `struct ed` local to __util_ed_main()
 * and are freed on every return path, so two sequential `ed` builtin
 * invocations in the same shell session never see each other's
 * leftover state.  The two `sig_atomic_t` flags below are the only
 * file-scope state, are reset to 0 at the top of every call, and carry
 * no buffer content of their own.
 */
// NOLINTBEGIN(misc-include-cleaner)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <regex.h>
#include <unistd.h>
#include "util.h"

/* ==== signal-safety plumbing (see the header comment above) ============= */

static volatile sig_atomic_t ed_interrupted;
static volatile sig_atomic_t ed_hup;

static void ed_sigint_handler(int sig)
{
	(void)sig;
	ed_interrupted = 1;
}

static void ed_sighup_handler(int sig)
{
	(void)sig;
	ed_hup = 1;
}

/* ==== core state ========================================================= */

struct ed {
	char **lines;		/* owned strings, lines[i] is 1-based line i+1 */
	size_t nlines, cap;
	long cur;		/* 0 only when the buffer is empty */

	long marks[26];		/* 'a'..'z', 0 == unset */

	char *filename;		/* remembered pathname, or NULL */
	int modified;		/* dirty since last full `w` of the whole buffer */
	int pending_quit;	/* 0, or 'e'/'q': which command's one-shot warn-then-allow latch is armed */

	char *last_re;		/* last BRE text used by any search or s/// */
	char *last_repl;	/* last s/// replacement text (for a lone '%') */
	char *last_bang;	/* last `!` command text, pre-%-expansion */

	int help_mode;		/* H */
	int prompt_mode;	/* P */
	const char *prompt;

	int suppress;		/* -s */
	int had_error;		/* sticky: any error at all during this run */
	const char *errmsg;	/* current H/h explanation */

	/* single-level undo shadow -- see the header comment's own account
	 * of why a swap, not a stack, is enough. */
	char **u_lines;
	size_t u_nlines;
	long u_cur;
	int u_valid;

	/* while a g/v/G/V invocation is iterating, points at that
	 * invocation's own snapshot of matched line numbers so buffer
	 * mutations (insert/delete) can keep it numerically accurate and
	 * drop entries whose line was deleted out from under it. */
	long *g_extra;
	size_t g_extra_n;
};

enum { ED_ERR = -1, ED_QUIT = -2, ED_INTR = -3 };
enum exec_ctx { CTX_TOP = 0, CTX_GLIST = 1, CTX_GVSINGLE = 2 };

/* ==== small dynamic string buffer, used throughout ======================= */

struct strbuf { char *data; size_t len, cap; };

static void strbuf_init(struct strbuf *s) { s->data = 0; s->len = 0; s->cap = 0; }

static void strbuf_free(struct strbuf *s)
{
	free(s->data);
	s->data = 0; s->len = 0; s->cap = 0;
}

static int strbuf_reserve(struct strbuf *s, size_t additional)
{
	size_t newcap, need;
	char *g;
	/* +1 for the NUL strbuf_append() always writes past s->len+n. */
	if (!__util_size_add(additional, 1, &need)) return 0;
	if (!__util_array_capacity(s->cap, s->len, need, 64, 1, &newcap)) return 0;
	if (newcap == s->cap) return 1;
	g = realloc(s->data, newcap);
	if (!g) return 0;
	s->data = g; s->cap = newcap;
	return 1;
}

static int strbuf_append(struct strbuf *s, const char *p, size_t n)
{
	if (!strbuf_reserve(s, n)) return 0;
	for (size_t i = 0; i < n; i++) s->data[s->len + i] = p[i];
	s->len += n;
	s->data[s->len] = 0;
	return 1;
}

static int strbuf_putc(struct strbuf *s, char c) { return strbuf_append(s, &c, 1); }
static int strbuf_puts(struct strbuf *s, const char *p) { return strbuf_append(s, p, strlen(p)); }

/* Detaches the buffer's storage to the caller, always returning a real
 * (possibly empty) NUL-terminated string rather than NULL, so callers
 * never need a NULL special case for "nothing was ever appended". */
static char *strbuf_take(struct strbuf *s)
{
	char *r = s->data;
	if (!r) r = strdup("");
	s->data = 0; s->len = 0; s->cap = 0;
	return r;
}

/* ==== misc small helpers ================================================= */

static void free_string_array(char **a, size_t n)
{
	size_t i;
	if (!a) return;
	for (i = 0; i < n; i++) free(a[i]);
	free(a);
}

static void skip_blanks(const char **pp)
{
	while (**pp == ' ' || **pp == '\t') (*pp)++;
}

static void ed_seterr(struct ed *ed, const char *msg)
{
	ed->errmsg = msg;
	ed->had_error = 1;
}

/* Every command-level failure funnels through here: sets the H/h
 * explanation, marks the whole run as having had an error (for the
 * final exit status), and writes the `?` ed(1p) itself requires --
 * this is a protocol response to the user, not a diagnostic, so it
 * goes to stdout like any other print command's output, not through
 * __util_diagf(). */
static int ed_fail(struct ed *ed, const char *msg)
{
	ed_seterr(ed, msg);
	fputs("?\n", stdout);
	if (ed->help_mode) fprintf(stdout, "%s\n", msg);
	return ED_ERR;
}

/* File-related failures (a real errno from open/fopen) are reported
 * with the OS's own strerror() text -- genuinely more useful than a
 * bare `?`, and what real ed implementations do. */
static int ed_fail_file(struct ed *ed, const char *path, int err)
{
	ed_seterr(ed, "file error");
	ed->had_error = 1;
	fprintf(stdout, "%s: %s\n", path, strerror(err));
	if (ed->help_mode) fprintf(stdout, "%s\n", ed->errmsg);
	return ED_ERR;
}

/* Returns 1 (and resets/consumes the flag) exactly once per real
 * interrupt, printing the `?\n` SIGINT requires; the caller is
 * responsible for unwinding to ED_INTR without any further printing. */
static int ed_check_interrupt(struct ed *ed)
{
	(void)ed;
	if (ed_interrupted) {
		ed_interrupted = 0;
		fputs("?\n", stdout);
		return 1;
	}
	return 0;
}

/* ==== buffer management =================================================== */

static int buf_reserve(struct ed *ed, size_t additional)
{
	size_t newcap;
	char **g;
	if (!additional) return 1;
	if (!__util_array_capacity(ed->cap, ed->nlines, additional, 16, sizeof *ed->lines, &newcap)) return 0;
	g = __util_reallocarray(ed->lines, newcap, sizeof *ed->lines);
	if (!g) return 0;
	ed->lines = g; ed->cap = newcap;
	return 1;
}

static void marks_shift_insert(struct ed *ed, long after_line, long count)
{
	int m;
	for (m = 0; m < 26; m++) if (ed->marks[m] > after_line) ed->marks[m] += count;
	if (ed->g_extra) {
		size_t i;
		for (i = 0; i < ed->g_extra_n; i++)
			if (ed->g_extra[i] > after_line) ed->g_extra[i] += count;
	}
}

static void marks_shift_delete(struct ed *ed, long from, long to)
{
	int m;
	long count = to - from + 1;
	for (m = 0; m < 26; m++) {
		long v = ed->marks[m];
		if (!v) continue;
		if (v >= from && v <= to) ed->marks[m] = 0;
		else if (v > to) ed->marks[m] -= count;
	}
	if (ed->g_extra) {
		size_t i;
		for (i = 0; i < ed->g_extra_n; i++) {
			long v = ed->g_extra[i];
			if (!v) continue;
			if (v >= from && v <= to) ed->g_extra[i] = 0;
			else if (v > to) ed->g_extra[i] -= count;
		}
	}
}

/* Inserts `count` already-heap-owned line pointers so they become
 * lines [after_line+1 .. after_line+count]; after_line may be 0. */
static int buf_insert_after(struct ed *ed, long after_line, char **newlines, size_t count)
{
	size_t at = (size_t)after_line, i;
	if (!count) return 1;
	if (!buf_reserve(ed, count)) return 0;
	for (i = ed->nlines; i > at; i--)
		ed->lines[i + count - 1] = ed->lines[i - 1];
	for (i = 0; i < count; i++) ed->lines[at + i] = newlines[i];
	ed->nlines += count;
	marks_shift_insert(ed, after_line, (long)count);
	return 1;
}

/* Removes lines [from,to] (1-based, inclusive) from the array WITHOUT
 * freeing their text -- used by `m`, whose moved lines are reinserted
 * elsewhere, not discarded. */
static void buf_remove_range_nofree(struct ed *ed, long from, long to)
{
	size_t at0 = (size_t)(from - 1), count = (size_t)(to - from + 1);
	for (size_t i = at0; i + count < ed->nlines; i++)
		ed->lines[i] = ed->lines[i + count];
	ed->nlines -= count;
	marks_shift_delete(ed, from, to);
}

static void buf_delete_range(struct ed *ed, long from, long to)
{
	long i;
	for (i = from; i <= to; i++) free(ed->lines[i - 1]);
	buf_remove_range_nofree(ed, from, to);
}

/* Cursor to leave current after a delete-without-replacement: `want`
 * (1-based, the old line just past the deleted range) if that line
 * still exists, else the new last line, else 0 if the buffer is now
 * empty. */
static long cur_after_delete(long want, long nlines)
{
	if (!nlines) return 0;
	return want <= nlines ? want : nlines;
}

/* ==== undo (single-level swap; see header comment) ======================= */

static int save_undo_snapshot(struct ed *ed)
{
	char **copy = 0;
	size_t i;
	if (ed->nlines) {
		copy = __util_mallocarray(ed->nlines, sizeof *copy);
		if (!copy) { ed->u_valid = 0; return 0; }
		for (i = 0; i < ed->nlines; i++) {
			copy[i] = strdup(ed->lines[i]);
			if (!copy[i]) { while (i-- > 0) free(copy[i]); free(copy); ed->u_valid = 0; return 0; }
		}
	}
	free_string_array(ed->u_lines, ed->u_nlines);
	ed->u_lines = copy;
	ed->u_nlines = ed->nlines;
	ed->u_cur = ed->cur;
	ed->u_valid = 1;
	return 1;
}

/* Returns 0 on success, -1 if there is nothing to undo, -2 on OOM. */
static int do_undo(struct ed *ed)
{
	char **tmp = 0;
	size_t tmp_n, i;
	long tmp_cur;

	if (!ed->u_valid) return -1;

	if (ed->nlines) {
		tmp = __util_mallocarray(ed->nlines, sizeof *tmp);
		if (!tmp) return -2;
		for (i = 0; i < ed->nlines; i++) {
			tmp[i] = strdup(ed->lines[i]);
			if (!tmp[i]) { while (i-- > 0) free(tmp[i]); free(tmp); return -2; }
		}
	}
	tmp_n = ed->nlines; tmp_cur = ed->cur;

	free_string_array(ed->lines, ed->nlines);
	ed->lines = ed->u_lines; ed->nlines = ed->u_nlines; ed->cap = ed->u_nlines;
	ed->cur = ed->u_cur;

	ed->u_lines = tmp; ed->u_nlines = tmp_n; ed->u_cur = tmp_cur;
	/* ed->u_valid stays 1: undoing an undo swaps back. */
	ed->modified = 1;
	return 0;
}

/* ==== line-source abstraction: unifies stdin, and a g/v command-list ===== */

struct linesrc {
	FILE *f;		/* non-NULL: read raw lines from here (stdin) */
	char **list;		/* non-NULL (f NULL): replay this fixed list */
	size_t n, i;
};

/* Reads one raw line from `f`, stripping exactly one trailing '\n' if
 * present (an unterminated final line is kept as-is -- POSIX leaves
 * that edge case unspecified; keeping it verbatim is the simplest
 * defensible choice).  Returns NULL on real EOF/error, or on being
 * interrupted mid-read (ed_interrupted is left set in that case so the
 * caller can tell the two apart). */
static char *read_line_stdin(FILE *f)
{
	char *buf = 0;
	size_t cap = 0;
	ssize_t got;

	for (;;) {
		got = getline(&buf, &cap, f);
		if (got >= 0) break;
		if (errno == EINTR) {
			if (ed_interrupted) { free(buf); return 0; }
			continue;
		}
		free(buf);
		return 0;
	}
	if (got > 0 && buf[got - 1] == '\n') buf[got - 1] = 0;
	return buf;
}

static char *linesrc_next(struct linesrc *ls)
{
	if (ls->f) return read_line_stdin(ls->f);
	if (ls->i >= ls->n) return 0;
	return strdup(ls->list[ls->i++]);
}

/* ==== text-input mode (a/i/c) ============================================ */

/* Collects lines until one containing exactly "." (not part of the
 * text), EOF, or an interrupt.  Returns 0 (out_lines/out_n valid,
 * possibly n==0), -1 on OOM, or ED_INTR if interrupted -- in the
 * ED_INTR case, everything collected so far is discarded, matching
 * "abort whatever's currently happening". */
static int read_text_lines(struct linesrc *src, char ***out_lines, size_t *out_n)
{
	char **lines = 0;
	size_t n = 0, cap = 0;
	char *ln;

	for (;;) {
		if (ed_check_interrupt(0)) { free_string_array(lines, n); *out_lines = 0; *out_n = 0; return ED_INTR; }
		ln = linesrc_next(src);
		if (!ln) {
			if (src->f && ed_interrupted) { free_string_array(lines, n); *out_lines = 0; *out_n = 0; return ED_INTR; }
			break; /* EOF ends input mode */
		}
		if (strcmp(ln, ".") == 0) { free(ln); break; }
		if (n >= cap) {
			size_t newcap;
			char **g;
			if (!__util_array_capacity(cap, n, 1, 16, sizeof *lines, &newcap)) { free(ln); free_string_array(lines, n); return -1; }
			g = __util_reallocarray(lines, newcap, sizeof *lines);
			if (!g) { free(ln); free_string_array(lines, n); return -1; }
			lines = g; cap = newcap;
		}
		lines[n++] = ln;
	}
	*out_lines = lines; *out_n = n;
	return 0;
}

/* ==== l-format ("unambiguous") printing =================================== */

static void print_l_format(FILE *out, const char *text)
{
	size_t len = strlen(text), i;
	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)text[i];
		switch (c) {
		case '\\': fputs("\\\\", out); break;
		case '\a': fputs("\\a", out); break;
		case '\b': fputs("\\b", out); break;
		case '\f': fputs("\\f", out); break;
		case '\r': fputs("\\r", out); break;
		case '\t': fputs("\\t", out); break;
		case '\v': fputs("\\v", out); break;
		case '$': fputs("\\$", out); break;
		default:
			if (isprint(c)) fputc((int)c, out);
			else fprintf(out, "\\%03o", c);
		}
	}
	fputs("$\n", out);
}

static void ed_print_range(struct ed *ed, long from, long to, int fmt)
{
	long i;
	for (i = from; i <= to; i++) {
		const char *text = ed->lines[i - 1];
		if (fmt == 'l') print_l_format(stdout, text);
		else if (fmt == 'n') fprintf(stdout, "%ld\t%s\n", i, text);
		else fprintf(stdout, "%s\n", text);
	}
	ed->cur = to;
}

/* ==== BRE search with wraparound ========================================== */

static int search_forward(struct ed *ed, const char *pat, long from, long *out)
{
	regex_t re;
	long i, n = ed->nlines;
	if (!n) return ed_fail(ed, "no match: buffer is empty");
	if (regcomp(&re, pat, REG_NOSUB) != 0) return ed_fail(ed, "invalid regular expression");
	for (i = 1; i <= n; i++) {
		long ln = from + i;
		while (ln > n) ln -= n;
		while (ln < 1) ln += n;
		if (regexec(&re, ed->lines[ln - 1], 0, 0, 0) == 0) { *out = ln; regfree(&re); return 0; }
	}
	regfree(&re);
	return ed_fail(ed, "no match");
}

static int search_backward(struct ed *ed, const char *pat, long from, long *out)
{
	regex_t re;
	long i, n = ed->nlines;
	if (!n) return ed_fail(ed, "no match: buffer is empty");
	if (regcomp(&re, pat, REG_NOSUB) != 0) return ed_fail(ed, "invalid regular expression");
	for (i = 1; i <= n; i++) {
		long ln = from - i;
		while (ln < 1) ln += n;
		while (ln > n) ln -= n;
		if (regexec(&re, ed->lines[ln - 1], 0, 0, 0) == 0) { *out = ln; regfree(&re); return 0; }
	}
	regfree(&re);
	return ed_fail(ed, "no match");
}

/* Copies chars up to (not including) an unescaped `delim`, turning
 * "\<delim>" into a literal delim; every other backslash sequence is
 * copied through untouched (regcomp() and the s/// replacement
 * expander below each give backslash its own further meaning).
 * Leaves *endp just past the consumed delimiter, or at the NUL if the
 * delimiter was omitted at end of line (both are valid per XCU). */
static int extract_delimited(const char *p, char delim, char **out, const char **endp)
{
	struct strbuf sb;
	strbuf_init(&sb);
	while (*p && *p != delim) {
		if (*p == '\\' && p[1] == delim) {
			if (!strbuf_putc(&sb, delim)) { strbuf_free(&sb); return 0; }
			p += 2;
			continue;
		}
		if (!strbuf_putc(&sb, *p)) { strbuf_free(&sb); return 0; }
		p++;
	}
	if (*p == delim) p++;
	*out = strbuf_take(&sb);
	*endp = p;
	return 1;
}

/* ==== address parsing ===================================================== */

static int parse_simple_addr(struct ed *ed, const char **pp, long eval_cur, long *out, int *had_base)
{
	const char *p = *pp;
	long v;

	*had_base = 1;
	if (*p == '.') { v = eval_cur; p++; }
	else if (*p == '$') { v = ed->nlines; p++; }
	else if (isdigit((unsigned char)*p)) {
		char *end;
		v = strtol(p, &end, 10);
		p = end;
	} else if (*p == '\'') {
		p++;
		if (*p < 'a' || *p > 'z') return ed_fail(ed, "invalid mark name");
		v = ed->marks[*p - 'a'];
		if (!v) return ed_fail(ed, "mark not set");
		p++;
	} else if (*p == '/' || *p == '?') {
		char delim = *p;
		char *pat = 0;
		const char *after;
		p++;
		if (!extract_delimited(p, delim, &pat, &after)) return ed_fail(ed, "out of memory");
		p = after;
		if (pat[0] == 0) {
			free(pat);
			if (!ed->last_re) return ed_fail(ed, "no previous regular expression");
			pat = strdup(ed->last_re);
			if (!pat) return ed_fail(ed, "out of memory");
		} else {
			char *save = strdup(pat);
			if (!save) { free(pat); return ed_fail(ed, "out of memory"); }
			free(ed->last_re); ed->last_re = save;
		}
		{
			long found;
			int rc = (delim == '/') ? search_forward(ed, pat, eval_cur, &found)
						 : search_backward(ed, pat, eval_cur, &found);
			free(pat);
			if (rc < 0) return ED_ERR;
			v = found;
		}
	} else {
		*had_base = 0;
		v = eval_cur;
	}

	for (;;) {
		const char *save = p;
		skip_blanks(&p);
		if (*p == '+') {
			p++; skip_blanks(&p);
			if (isdigit((unsigned char)*p)) { char *end; v += strtol(p, &end, 10); p = end; }
			else v += 1;
			*had_base = 1;
		} else if (*p == '-') {
			p++; skip_blanks(&p);
			if (isdigit((unsigned char)*p)) { char *end; v -= strtol(p, &end, 10); p = end; }
			else v -= 1;
			*had_base = 1;
		} else if (isdigit((unsigned char)*p)) {
			char *end;
			v += strtol(p, &end, 10);
			p = end;
			*had_base = 1;
		} else { p = save; break; }
	}
	*out = v;
	*pp = p;
	return 0;
}

struct range { int n; long a1, a2; };

static int parse_range(struct ed *ed, const char **pp, struct range *r)
{
	long eval_cur = ed->cur;
	long v1 = 0, v2 = 0;
	int had1, had2;
	const char *p = *pp;

	r->n = 0;
	skip_blanks(&p);
	if (parse_simple_addr(ed, &p, eval_cur, &v1, &had1) < 0) return ED_ERR;
	skip_blanks(&p);
	if (*p == ',' || *p == ';') {
		char sep = *p;
		long base1;
		p++;
		if (had1) base1 = v1;
		else if (sep == ',') base1 = 1;
		else base1 = eval_cur;
		if (sep == ';') eval_cur = base1;
		skip_blanks(&p);
		if (parse_simple_addr(ed, &p, eval_cur, &v2, &had2) < 0) return ED_ERR;
		if (!had1 && !had2) { v1 = base1; v2 = ed->nlines; }
		else if (had1 && !had2) { v2 = v1; }
		else if (!had1) { v1 = base1; }
		r->n = 2; r->a1 = v1; r->a2 = v2;
		*pp = p;
		return 0;
	}
	if (!had1) { r->n = 0; *pp = p; return 0; }
	r->n = 1; r->a1 = v1; r->a2 = v1;
	*pp = p;
	return 0;
}

static void resolve_default(const struct range *rg, long def_a, long def_b, long *from, long *to)
{
	if (rg->n == 0) { *from = def_a; *to = def_b; }
	else if (rg->n == 1) { *from = rg->a1; *to = rg->a1; }
	else { *from = rg->a1; *to = rg->a2; }
}

static int require_eol(struct ed *ed, const char *p)
{
	skip_blanks(&p);
	if (*p) return ed_fail(ed, "trailing garbage");
	return 0;
}

static int parse_trailing_suffix(struct ed *ed, const char *p, int *fmt)
{
	skip_blanks(&p);
	*fmt = 0;
	if (*p == 'p' || *p == 'l' || *p == 'n') { *fmt = *p; p++; }
	return require_eol(ed, p);
}

/* ==== s/// substitution ==================================================== */

static int expand_replacement(struct strbuf *out, const char *repl, const char *base, regmatch_t *pm)
{
	size_t i;
	for (i = 0; repl[i]; i++) {
		if (repl[i] == '&') {
			if (!strbuf_append(out, base + pm[0].rm_so, (size_t)(pm[0].rm_eo - pm[0].rm_so))) return 0;
		} else if (repl[i] == '\\' && repl[i + 1]) {
			char c = repl[i + 1];
			i++;
			if (c == '&') { if (!strbuf_putc(out, '&')) return 0; }
			else if (c >= '1' && c <= '9') {
				int g = c - '0';
				if (pm[g].rm_so >= 0 && !strbuf_append(out, base + pm[g].rm_so, (size_t)(pm[g].rm_eo - pm[g].rm_so))) return 0;
			} else {
				if (!strbuf_putc(out, c)) return 0;
			}
		} else {
			if (!strbuf_putc(out, repl[i])) return 0;
		}
	}
	return 1;
}

/* Builds and returns the (possibly unchanged) replacement text for one
 * line; *changed reports whether any substitution actually happened.
 * Returns NULL on OOM. */
static char *substitute_line(regex_t *re, const char *text, const char *repl, long nth, int global, int *changed)
{
	struct strbuf out;
	size_t len = strlen(text);
	size_t search_pos = 0, last_copy = 0;
	long match_index = 0;
	regmatch_t pm[10];

	*changed = 0;
	strbuf_init(&out);
	for (;;) {
		int eflags = search_pos > 0 ? REG_NOTBOL : 0;
		size_t so, eo;
		int do_this;

		if (search_pos > len) break;
		if (regexec(re, text + search_pos, 10, pm, eflags) != 0) break;

		so = search_pos + (size_t)pm[0].rm_so;
		eo = search_pos + (size_t)pm[0].rm_eo;
		match_index++;
		do_this = global ? (match_index >= nth) : (match_index == nth);

		if (do_this) {
			if (!strbuf_append(&out, text + last_copy, so - last_copy)) goto oom;
			if (!expand_replacement(&out, repl, text + search_pos, pm)) goto oom;
			*changed = 1;
			last_copy = eo;
		}
		if (eo == so) search_pos = eo + 1;
		else search_pos = eo;
		if (do_this && !global) break;
	}
	if (!strbuf_append(&out, text + last_copy, len - last_copy)) goto oom;
	return strbuf_take(&out);
oom:
	strbuf_free(&out);
	return 0;
}

static int cmd_s(struct ed *ed, long from, long to, const char *args)
{
	const char *p = args;
	char delim;
	char *pat = 0, *repl = 0;
	long nth = 1, i, last_changed = 0, changed_count = 0;
	int global = 0, print_fmt = 0;
	regex_t re;

	if (*p == 0 || *p == ' ' || *p == '\t') return ed_fail(ed, "missing pattern delimiter");
	delim = *p; p++;
	if (!extract_delimited(p, delim, &pat, &p)) return ed_fail(ed, "out of memory");
	if (!extract_delimited(p, delim, &repl, &p)) { free(pat); return ed_fail(ed, "out of memory"); }

	for (;;) {
		const char *save = p;
		skip_blanks(&p);
		if (*p >= '0' && *p <= '9') { char *end; nth = strtol(p, &end, 10); p = end; }
		else if (*p == 'g') { global = 1; p++; }
		else if (*p == 'p' || *p == 'l' || *p == 'n') { print_fmt = *p; p++; }
		else { p = save; break; }
	}
	if (nth < 1) nth = 1;
	if (require_eol(ed, p) < 0) { free(pat); free(repl); return ED_ERR; }

	if (pat[0] == 0) {
		free(pat);
		if (!ed->last_re) { free(repl); return ed_fail(ed, "no previous regular expression"); }
		pat = strdup(ed->last_re);
		if (!pat) { free(repl); return ed_fail(ed, "out of memory"); }
	} else {
		char *save = strdup(pat);
		if (!save) { free(pat); free(repl); return ed_fail(ed, "out of memory"); }
		free(ed->last_re); ed->last_re = save;
	}

	if (repl[0] == '%' && repl[1] == 0) {
		free(repl);
		if (!ed->last_repl) { free(pat); return ed_fail(ed, "no previous replacement text"); }
		repl = strdup(ed->last_repl);
		if (!repl) { free(pat); return ed_fail(ed, "out of memory"); }
	} else {
		char *save = strdup(repl);
		if (!save) { free(pat); free(repl); return ed_fail(ed, "out of memory"); }
		free(ed->last_repl); ed->last_repl = save;
	}

	if (regcomp(&re, pat, 0) != 0) { free(pat); free(repl); return ed_fail(ed, "invalid regular expression"); }
	free(pat);

	for (i = from; i <= to; i++) {
		int line_changed = 0;
		char *newtext = substitute_line(&re, ed->lines[i - 1], repl, nth, global, &line_changed);
		if (!newtext) { regfree(&re); free(repl); return ed_fail(ed, "out of memory"); }
		if (line_changed) {
			free(ed->lines[i - 1]);
			ed->lines[i - 1] = newtext;
			last_changed = i; changed_count++;
		} else {
			free(newtext);
		}
	}
	regfree(&re);
	free(repl);

	if (!changed_count) return ed_fail(ed, "no match");
	ed->cur = last_changed;
	ed->modified = 1;
	if (print_fmt) ed_print_range(ed, last_changed, last_changed, print_fmt);
	return 0;
}

/* ==== file I/O helpers (e/E/r/w and their "!command" forms) ============== */

static int read_lines_from_file(FILE *f, char ***out_lines, size_t *out_n, long *out_bytes)
{
	char *buf = 0;
	size_t bufcap = 0;
	ssize_t got;
	char **lines = 0;
	size_t n = 0, cap = 0;
	long bytes = 0;

	while ((got = getline(&buf, &bufcap, f)) >= 0) {
		size_t len = (size_t)got;
		char *text;
		bytes += (long)len;
		if (len && buf[len - 1] == '\n') len--;
		text = strndup(buf, len);
		if (!text) { free(buf); free_string_array(lines, n); return -1; }
		if (n >= cap) {
			size_t newcap;
			char **g;
			if (!__util_array_capacity(cap, n, 1, 32, sizeof *lines, &newcap)) { free(text); free(buf); free_string_array(lines, n); return -1; }
			g = __util_reallocarray(lines, newcap, sizeof *lines);
			if (!g) { free(text); free(buf); free_string_array(lines, n); return -1; }
			lines = g; cap = newcap;
		}
		lines[n++] = text;
	}
	free(buf);
	*out_lines = lines; *out_n = n; *out_bytes = bytes;
	return 0;
}

static long write_lines_to_file(FILE *f, char **lines, long from, long to)
{
	long bytes = 0, i;
	for (i = from; i <= to; i++) {
		size_t len = strlen(lines[i - 1]);
		if (fwrite(lines[i - 1], 1, len, f) != len) return -1;
		if (fputc('\n', f) == EOF) return -1;
		bytes += (long)len + 1;
	}
	return bytes;
}

/* `%` in a shell-command context (both the standalone `!` command and
 * the "!command" form e/r/w accept as their filename argument) expands
 * to the remembered pathname; `\%` is a literal `%`. */
static char *expand_percent(struct ed *ed, const char *text)
{
	struct strbuf sb;
	size_t i;
	strbuf_init(&sb);
	for (i = 0; text[i]; i++) {
		if (text[i] == '\\' && text[i + 1] == '%') { if (!strbuf_putc(&sb, '%')) { strbuf_free(&sb); return 0; } i++; }
		else if (text[i] == '%') {
			if (!ed->filename) { strbuf_free(&sb); return 0; }
			if (!strbuf_puts(&sb, ed->filename)) { strbuf_free(&sb); return 0; }
		} else {
			if (!strbuf_putc(&sb, text[i])) { strbuf_free(&sb); return 0; }
		}
	}
	return strbuf_take(&sb);
}

static int cmd_edit(struct ed *ed, const char *arg, int force, int is_startup)
{
	int is_bang = (arg[0] == '!');
	const char *path = arg;
	FILE *f;
	char **newlines = 0;
	size_t newn = 0;
	long bytes = 0;
	char *expanded = 0;

	if (!force && ed->modified) {
		if (ed->pending_quit != 'e') { ed->pending_quit = 'e'; return ed_fail(ed, "buffer modified since last write"); }
	}
	ed->pending_quit = 0;

	if (arg[0] == 0) {
		if (!ed->filename) return ed_fail(ed, "no current filename");
		path = ed->filename;
		is_bang = 0;
	}

	if (is_bang) {
		expanded = expand_percent(ed, arg + 1);
		if (!expanded) return ed_fail(ed, "no current filename");
		f = popen(expanded, "r");
		if (!f) { int e = errno, rc = ed_fail_file(ed, expanded, e); free(expanded); return rc; }
	} else {
		f = fopen(path, "r");
		if (!f) {
			int e = errno;
			if (is_startup && e == ENOENT) {
				free(ed->filename);
				ed->filename = strdup(path);
				/* Not a real error: starting on a not-yet-existing file
				 * is normal, so this must NOT feed into had_error / the
				 * final exit status -- set errmsg directly rather than
				 * through ed_seterr(), which would mark the whole run
				 * as having had an error. */
				ed->errmsg = "new file";
				return 0;
			}
			return ed_fail_file(ed, path, e);
		}
	}

	if (read_lines_from_file(f, &newlines, &newn, &bytes) < 0) {
		if (is_bang) pclose(f); else (void)fclose(f);
		free(expanded);
		return ed_fail(ed, "out of memory");
	}
	if (is_bang) pclose(f); else (void)fclose(f);

	free_string_array(ed->lines, ed->nlines);
	ed->lines = newlines; ed->nlines = newn; ed->cap = newn;
	ed->cur = ed->nlines;
	memset(ed->marks, 0, sizeof ed->marks);
	free_string_array(ed->u_lines, ed->u_nlines);
	ed->u_lines = 0; ed->u_nlines = 0; ed->u_valid = 0;
	ed->modified = 0;

	if (!is_bang) {
		/* `path` may alias ed->filename itself (a bare `e`/`E` with no
		 * argument reloads the remembered file) -- strdup() BEFORE
		 * free()ing the old string, never after, so this can't read
		 * through a just-freed pointer. */
		char *newfn = strdup(path);
		free(ed->filename);
		ed->filename = newfn;
	}
	free(expanded);

	if (!ed->suppress) fprintf(stdout, "%ld\n", bytes);
	return 0;
}

static int cmd_read(struct ed *ed, long after, const char *arg)
{
	int is_bang = (arg[0] == '!');
	const char *path = arg;
	FILE *f;
	char **newlines = 0;
	size_t newn = 0;
	long bytes = 0;
	char *expanded = 0;

	if (arg[0] == 0) {
		if (!ed->filename) return ed_fail(ed, "no current filename");
		path = ed->filename;
	}
	if (is_bang) {
		expanded = expand_percent(ed, arg + 1);
		if (!expanded) return ed_fail(ed, "no current filename");
		f = popen(expanded, "r");
		if (!f) { int e = errno, rc = ed_fail_file(ed, expanded, e); free(expanded); return rc; }
	} else {
		f = fopen(path, "r");
		if (!f) { int e = errno; return ed_fail_file(ed, path, e); }
	}

	if (read_lines_from_file(f, &newlines, &newn, &bytes) < 0) {
		if (is_bang) pclose(f); else (void)fclose(f);
		free(expanded);
		return ed_fail(ed, "out of memory");
	}
	if (is_bang) pclose(f); else (void)fclose(f);

	if (newn && !buf_insert_after(ed, after, newlines, newn)) {
		free_string_array(newlines, newn);
		free(expanded);
		return ed_fail(ed, "out of memory");
	}
	if (newn) { ed->cur = after + (long)newn; ed->modified = 1; }
	free(newlines); /* pointers now owned by ed->lines (or newn==0, nothing to free) */

	if (!is_bang && !ed->filename) ed->filename = strdup(path);
	free(expanded);

	if (!ed->suppress) fprintf(stdout, "%ld\n", bytes);
	return 0;
}

/* ed->nlines is a size_t because it sizes allocations (buf_reserve(),
 * mallocarray) alongside ed->cap, but every address the command grammar
 * deals in -- ed->cur, from/to/addr locals, marks -- is a signed `long`:
 * a not-yet-validated address can be negative mid-parse (e.g. `.-5` on
 * line 3), and the `< 0`/`< 1` checks throughout ed_exec_one() rely on
 * that sign surviving unpromoted. Comparing one of those longs straight
 * against ed->nlines makes the usual arithmetic conversions promote the
 * long to unsigned instead, which happens not to misfire today (the
 * negative case is always still caught by a neighboring `< 0`/`< 1`
 * clause in the same `||` chain) but is exactly the kind of thing that
 * silently stops being true the next time this code is touched. Convert
 * the count once, here, to the signed type every address comparison
 * already uses. This is exact, not merely convenient: a file's line
 * count can never approach LONG_MAX. Even at one byte per line plus one
 * pointer, a 32-bit process's whole 4GB address space could not hold
 * more than ~800M lines -- under 2^31-1 -- and a 64-bit nlines has the
 * same margin against 2^63-1. */
static long ed_nlines(const struct ed *ed)
{
	return (long)ed->nlines;
}

static int cmd_write(struct ed *ed, long from, long to, const char *arg)
{
	int is_bang = (arg[0] == '!');
	const char *path = arg;
	FILE *f;
	long bytes;
	char *expanded = 0;

	if (arg[0] == 0) {
		if (!ed->filename) return ed_fail(ed, "no current filename");
		path = ed->filename;
	}
	if (is_bang) {
		expanded = expand_percent(ed, arg + 1);
		if (!expanded) return ed_fail(ed, "no current filename");
		f = popen(expanded, "w");
		if (!f) { int e = errno, rc = ed_fail_file(ed, expanded, e); free(expanded); return rc; }
	} else {
		f = fopen(path, "w");
		if (!f) { int e = errno; return ed_fail_file(ed, path, e); }
	}

	bytes = (from <= to) ? write_lines_to_file(f, ed->lines, from, to) : 0;
	if (bytes < 0) {
		int e = errno, rc;
		if (is_bang) pclose(f); else (void)fclose(f);
		rc = ed_fail_file(ed, is_bang ? expanded : path, e);
		free(expanded);
		return rc;
	}
	if (is_bang) pclose(f); else (void)fclose(f);

	if (!is_bang && !ed->filename) ed->filename = strdup(path);
	/* Only a plain `w` of the whole buffer to a real pathname counts as
	 * "the buffer was written in full" for the modified/quit latch. */
	if (!is_bang && from == 1 && to == ed_nlines(ed)) { ed->modified = 0; ed->pending_quit = 0; }
	free(expanded);

	if (!ed->suppress) fprintf(stdout, "%ld\n", bytes);
	return 0;
}

static int cmd_bang(struct ed *ed, const char *arg)
{
	const char *raw;
	char *newlast, *expanded;

	if (arg[0] == 0) {
		if (!ed->last_bang) return ed_fail(ed, "no previous command");
		raw = ed->last_bang;
	} else {
		raw = arg;
	}
	newlast = strdup(raw);
	if (!newlast) return ed_fail(ed, "out of memory");
	expanded = expand_percent(ed, raw);
	if (!expanded) { free(newlast); return ed_fail(ed, "no current filename"); }
	free(ed->last_bang); ed->last_bang = newlast;

	(void)system(expanded);
	free(expanded);
	if (!ed->suppress) fputs("!\n", stdout);
	return 0;
}

/* ==== the single command executor ========================================= */

static int is_modifying_command(int c)
{
	return c == 'a' || c == 'c' || c == 'd' || c == 'g' || c == 'i' || c == 'j' ||
	       c == 'm' || c == 'r' || c == 's' || c == 't' || c == 'v' || c == 'G' || c == 'V';
}

static const char *help_text_default = "an ed(1p) command could not be carried out as written";

static int ed_exec_one(struct ed *ed, const char *cmdline, struct linesrc *textsrc, enum exec_ctx ctx)
{
	const char *p = cmdline;
	struct range rg;
	char cmd;
	long from, to;
	int fmt;

	if (ed_check_interrupt(ed)) return ED_INTR;

	if (parse_range(ed, &p, &rg) < 0) return ED_ERR;
	skip_blanks(&p);

	if (*p == 0) {
		/* null command: print the addressed line(s), default .+1 */
		if (rg.n) { from = rg.a1; to = rg.a2; }
		else { from = to = ed->cur + 1; }
		if (from < 1 || to > ed_nlines(ed) || from > to) return ed_fail(ed, "invalid address");
		ed_print_range(ed, from, to, 0);
		return 0;
	}
	cmd = *p++;

	if (is_modifying_command(cmd) && cmd != 'u' && ctx == CTX_TOP) save_undo_snapshot(ed);

	switch (cmd) {
	case 'a': {
		long addr; char **txt; size_t tn; int rc;
		if (ctx == CTX_GVSINGLE) return ed_fail(ed, "command not permitted here");
		if (rg.n == 2) return ed_fail(ed, "a single address, not a range, is expected here");
		addr = rg.n ? rg.a1 : ed->cur;
		if (require_eol(ed, p) < 0) return ED_ERR;
		if (addr < 0 || addr > ed_nlines(ed)) return ed_fail(ed, "address out of range");
		rc = read_text_lines(textsrc, &txt, &tn);
		if (rc == ED_INTR) return ED_INTR;
		if (rc < 0) return ed_fail(ed, "out of memory");
		if (tn) {
			if (!buf_insert_after(ed, addr, txt, tn)) { free_string_array(txt, tn); return ed_fail(ed, "out of memory"); }
			ed->cur = addr + (long)tn;
			ed->modified = 1;
			free(txt);
		}
		break;
	}
	case 'i': {
		long addr; char **txt; size_t tn; int rc;
		if (ctx == CTX_GVSINGLE) return ed_fail(ed, "command not permitted here");
		if (rg.n == 2) return ed_fail(ed, "a single address, not a range, is expected here");
		addr = rg.n ? rg.a1 : ed->cur;
		if (addr == 0) addr = 1;
		if (require_eol(ed, p) < 0) return ED_ERR;
		if (ed->nlines == 0) {
			if (addr != 1) return ed_fail(ed, "address out of range");
		} else if (addr < 1 || addr > ed_nlines(ed)) {
			return ed_fail(ed, "address out of range");
		}
		rc = read_text_lines(textsrc, &txt, &tn);
		if (rc == ED_INTR) return ED_INTR;
		if (rc < 0) return ed_fail(ed, "out of memory");
		if (tn) {
			if (!buf_insert_after(ed, addr - 1, txt, tn)) { free_string_array(txt, tn); return ed_fail(ed, "out of memory"); }
			ed->cur = addr - 1 + (long)tn;
			ed->modified = 1;
			free(txt);
		}
		break;
	}
	case 'c': {
		long f2, t2; char **txt; size_t tn; int rc;
		if (ctx == CTX_GVSINGLE) return ed_fail(ed, "command not permitted here");
		resolve_default(&rg, ed->cur, ed->cur, &f2, &t2);
		if (require_eol(ed, p) < 0) return ED_ERR;
		if (f2 < 1 || t2 > ed_nlines(ed) || f2 > t2) return ed_fail(ed, "invalid address");
		buf_delete_range(ed, f2, t2);
		rc = read_text_lines(textsrc, &txt, &tn);
		if (rc == ED_INTR) return ED_INTR;
		if (rc < 0) return ed_fail(ed, "out of memory");
		if (tn) {
			if (!buf_insert_after(ed, f2 - 1, txt, tn)) { free_string_array(txt, tn); return ed_fail(ed, "out of memory"); }
			ed->cur = f2 - 1 + (long)tn;
			free(txt);
		} else {
			ed->cur = cur_after_delete(f2, ed->nlines);
		}
		ed->modified = 1;
		break;
	}
	case 'd': {
		resolve_default(&rg, ed->cur, ed->cur, &from, &to);
		if (parse_trailing_suffix(ed, p, &fmt) < 0) return ED_ERR;
		if (from < 1 || to > ed_nlines(ed) || from > to) return ed_fail(ed, "invalid address");
		buf_delete_range(ed, from, to);
		ed->cur = cur_after_delete(from, ed->nlines);
		ed->modified = 1;
		if (fmt && ed->nlines) ed_print_range(ed, ed->cur, ed->cur, fmt);
		break;
	}
	case 'j': {
		long def_b;
		def_b = ed->cur + 1;
		if (def_b > ed_nlines(ed)) def_b = ed->nlines;
		resolve_default(&rg, ed->cur, def_b, &from, &to);
		if (parse_trailing_suffix(ed, p, &fmt) < 0) return ED_ERR;
		if (from < 1 || to > ed_nlines(ed) || from > to) return ed_fail(ed, "invalid address");
		if (to > from) {
			struct strbuf sb; long i2;
			char *joined;
			strbuf_init(&sb);
			for (i2 = from; i2 <= to; i2++) if (!strbuf_puts(&sb, ed->lines[i2 - 1])) { strbuf_free(&sb); return ed_fail(ed, "out of memory"); }
			joined = strbuf_take(&sb);
			free(ed->lines[from - 1]);
			ed->lines[from - 1] = joined;
			buf_delete_range(ed, from + 1, to);
			ed->modified = 1;
		}
		ed->cur = from;
		if (fmt) ed_print_range(ed, ed->cur, ed->cur, fmt);
		break;
	}
	case 'm': case 't': {
		long addr3; struct range r3; int is_move = (cmd == 'm');
		resolve_default(&rg, ed->cur, ed->cur, &from, &to);
		if (from < 1 || to > ed_nlines(ed) || from > to) return ed_fail(ed, "invalid address");
		if (parse_range(ed, &p, &r3) < 0) return ED_ERR;
		if (!r3.n) return ed_fail(ed, "missing destination address");
		addr3 = r3.a1;
		if (parse_trailing_suffix(ed, p, &fmt) < 0) return ED_ERR;
		if (addr3 < 0 || addr3 > ed_nlines(ed)) return ed_fail(ed, "address out of range");
		if (is_move && addr3 >= from && addr3 <= to) return ed_fail(ed, "destination falls inside the source range");
		{
			size_t count = (size_t)(to - from + 1);
			char **tmp = __util_mallocarray(count, sizeof *tmp);
			if (!tmp) return ed_fail(ed, "out of memory");
			if (is_move) {
				for (size_t i = 0; i < count; i++)
					tmp[i] = ed->lines[from - 1 + i];
				buf_remove_range_nofree(ed, from, to);
				if (addr3 > to) addr3 -= (long)count;
			} else {
				size_t k;
				for (k = 0; k < count; k++) {
					tmp[k] = strdup(ed->lines[from - 1 + k]);
					if (!tmp[k]) { while (k-- > 0) free(tmp[k]); free(tmp); return ed_fail(ed, "out of memory"); }
				}
			}
			if (!buf_insert_after(ed, addr3, tmp, count)) { free_string_array(tmp, count); return ed_fail(ed, "out of memory"); }
			free(tmp);
			ed->cur = addr3 + (long)count;
			ed->modified = 1;
		}
		if (fmt) ed_print_range(ed, ed->cur, ed->cur, fmt);
		break;
	}
	case 'p': case 'n': case 'l':
		resolve_default(&rg, ed->cur, ed->cur, &from, &to);
		if (require_eol(ed, p) < 0) return ED_ERR;
		if (from < 1 || to > ed_nlines(ed) || from > to) return ed_fail(ed, "invalid address");
		ed_print_range(ed, from, to, cmd);
		break;
	case '=': {
		long addr = rg.n ? rg.a1 : ed_nlines(ed);
		if (rg.n == 2) return ed_fail(ed, "a single address, not a range, is expected here");
		if (require_eol(ed, p) < 0) return ED_ERR;
		if (addr < 0 || addr > ed_nlines(ed)) return ed_fail(ed, "address out of range");
		fprintf(stdout, "%ld\n", addr);
		break;
	}
	case 's':
		resolve_default(&rg, ed->cur, ed->cur, &from, &to);
		if (from < 1 || to > ed_nlines(ed) || from > to) return ed_fail(ed, "invalid address");
		if (cmd_s(ed, from, to, p) < 0) return ED_ERR;
		break;
	case 'k': {
		long addr = rg.n ? rg.a1 : ed->cur;
		if (rg.n == 2) return ed_fail(ed, "a single address, not a range, is expected here");
		if (addr < 1 || addr > ed_nlines(ed)) return ed_fail(ed, "address out of range");
		skip_blanks(&p);
		if (*p < 'a' || *p > 'z') return ed_fail(ed, "invalid mark name");
		{
			char letter = *p++;
			if (require_eol(ed, p) < 0) return ED_ERR;
			ed->marks[letter - 'a'] = addr;
		}
		break;
	}
	case 'u':
		if (rg.n) return ed_fail(ed, "address not allowed here");
		if (require_eol(ed, p) < 0) return ED_ERR;
		{
			int rc = do_undo(ed);
			if (rc == -1) return ed_fail(ed, "nothing to undo");
			if (rc == -2) return ed_fail(ed, "out of memory");
		}
		break;
	case 'e': case 'E':
		if (ctx != CTX_TOP) return ed_fail(ed, "command not permitted here");
		if (rg.n) return ed_fail(ed, "address not allowed here");
		skip_blanks(&p);
		if (cmd_edit(ed, p, cmd == 'E', 0) < 0) return ED_ERR;
		break;
	case 'f':
		if (rg.n) return ed_fail(ed, "address not allowed here");
		skip_blanks(&p);
		if (*p) { free(ed->filename); ed->filename = strdup(p); }
		if (!ed->filename) return ed_fail(ed, "no current filename");
		fprintf(stdout, "%s\n", ed->filename);
		break;
	case 'r': {
		long addr = rg.n ? rg.a1 : ed_nlines(ed);
		if (rg.n == 2) return ed_fail(ed, "a single address, not a range, is expected here");
		if (addr < 0 || addr > ed_nlines(ed)) return ed_fail(ed, "address out of range");
		skip_blanks(&p);
		if (cmd_read(ed, addr, p) < 0) return ED_ERR;
		break;
	}
	case 'w': {
		resolve_default(&rg, 1, ed->nlines, &from, &to);
		skip_blanks(&p);
		if (from == 1 && to == 0 && ed->nlines == 0) { /* whole empty buffer: nothing to write, not an error */ }
		else if (from < 1 || to > ed_nlines(ed) || from > to) return ed_fail(ed, "invalid address");
		if (cmd_write(ed, from, to, p) < 0) return ED_ERR;
		break;
	}
	case '!':
		if (rg.n) return ed_fail(ed, "address not allowed here");
		if (cmd_bang(ed, p) < 0) return ED_ERR;
		break;
	case 'H':
		if (rg.n) return ed_fail(ed, "address not allowed here");
		if (require_eol(ed, p) < 0) return ED_ERR;
		ed->help_mode = !ed->help_mode;
		break;
	case 'h':
		if (rg.n) return ed_fail(ed, "address not allowed here");
		if (require_eol(ed, p) < 0) return ED_ERR;
		fprintf(stdout, "%s\n", ed->errmsg ? ed->errmsg : help_text_default);
		break;
	case 'P':
		if (rg.n) return ed_fail(ed, "address not allowed here");
		if (require_eol(ed, p) < 0) return ED_ERR;
		ed->prompt_mode = !ed->prompt_mode;
		break;
	case 'q': case 'Q':
		if (rg.n) return ed_fail(ed, "address not allowed here");
		if (require_eol(ed, p) < 0) return ED_ERR;
		/* The "warn once, then let a repeated q take effect" latch below
		 * exists purely so an interactive user gets a chance to save
		 * unsaved work before it is lost -- there is no user to give a
		 * second chance to when reading a fixed, non-interactive script
		 * (-s), and such a script has no way to "retype" q in response
		 * to a warning it never sees: its next line is whatever command
		 * comes next, not necessarily another q.  So -s runs the plain
		 * q it was given immediately, same as it already does for the
		 * unconditional Q. */
		if (cmd == 'q' && ed->modified && !ed->suppress) {
			if (ed->pending_quit != 'q') { ed->pending_quit = 'q'; return ed_fail(ed, "buffer modified since last write"); }
		}
		ed->pending_quit = 0;
		return ED_QUIT;
	case 'g': case 'v': case 'G': case 'V': {
		int invert = (cmd == 'v' || cmd == 'V');
		int interactive = (cmd == 'G' || cmd == 'V');
		char delim; char *pat = 0;
		regex_t re;
		long *matched = 0; size_t nmatched = 0, mcap = 0;
		long ln;
		int final = 0;

		if (ctx == CTX_GLIST) return ed_fail(ed, "g/v/G/V may not be nested in a command-list");
		if (ctx == CTX_GVSINGLE) return ed_fail(ed, "command not permitted here");

		resolve_default(&rg, 1, ed->nlines, &from, &to);
		if (from == 1 && to == 0 && ed->nlines == 0) { /* whole empty buffer: matches nothing, not an error */ }
		else if (from < 1 || to > ed_nlines(ed) || from > to) return ed_fail(ed, "invalid address");

		if (*p == 0 || *p == ' ' || *p == '\t') return ed_fail(ed, "missing pattern delimiter");
		delim = *p; p++;
		if (!extract_delimited(p, delim, &pat, &p)) return ed_fail(ed, "out of memory");
		if (pat[0] == 0) {
			free(pat);
			if (!ed->last_re) return ed_fail(ed, "no previous regular expression");
			pat = strdup(ed->last_re);
			if (!pat) return ed_fail(ed, "out of memory");
		} else {
			char *save = strdup(pat);
			if (!save) { free(pat); return ed_fail(ed, "out of memory"); }
			free(ed->last_re); ed->last_re = save;
		}
		if (regcomp(&re, pat, REG_NOSUB) != 0) { free(pat); return ed_fail(ed, "invalid regular expression"); }
		free(pat);

		for (ln = from; ln <= to; ln++) {
			int m = (regexec(&re, ed->lines[ln - 1], 0, 0, 0) == 0);
			if (invert) m = !m;
			if (m) {
				if (nmatched >= mcap) {
					size_t newcap; long *g;
					if (!__util_array_capacity(mcap, nmatched, 1, 32, sizeof *matched, &newcap)) { regfree(&re); free(matched); return ed_fail(ed, "out of memory"); }
					g = __util_reallocarray(matched, newcap, sizeof *matched);
					if (!g) { regfree(&re); free(matched); return ed_fail(ed, "out of memory"); }
					matched = g; mcap = newcap;
				}
				matched[nmatched++] = ln;
			}
		}
		regfree(&re);

		if (!interactive) {
			char **list = 0; size_t listn = 0, listcap = 0;
			size_t k;
			const char *chk = p;

			skip_blanks(&chk);
			if (*chk == 0) {
				/* "empty command-list defaults to p" -- a wholly blank
				 * tail (not merely an empty string reaching ed_exec_one
				 * as its own null command, which would default to .+1
				 * instead and be wrong here) becomes exactly one "p". */
				char *d = strdup("p");
				if (!d) { free(matched); return ed_fail(ed, "out of memory"); }
				list = __util_mallocarray(1, sizeof *list);
				if (!list) { free(d); free(matched); return ed_fail(ed, "out of memory"); }
				list[0] = d; listn = 1; listcap = 1;
			} else {
				char *cur = strdup(p);
				int cont;
				if (!cur) { free(matched); return ed_fail(ed, "out of memory"); }
				for (;;) {
					size_t L = strlen(cur);
					cont = (L > 0 && cur[L - 1] == '\\');
					if (cont) cur[L - 1] = 0;
					if (listn >= listcap) {
						size_t newcap; char **g;
						if (!__util_array_capacity(listcap, listn, 1, 16, sizeof *list, &newcap)) { free(cur); free_string_array(list, listn); free(matched); return ed_fail(ed, "out of memory"); }
						g = __util_reallocarray(list, newcap, sizeof *list);
						if (!g) { free(cur); free_string_array(list, listn); free(matched); return ed_fail(ed, "out of memory"); }
						list = g; listcap = newcap;
					}
					list[listn++] = cur;
					if (!cont) break;
					cur = linesrc_next(textsrc);
					if (!cur) break;
				}
			}

			ed->g_extra = matched; ed->g_extra_n = nmatched;
			for (k = 0; k < nmatched && final == 0; k++) {
				struct linesrc gls;
				char *cmdl;
				if (!matched[k]) continue;
				if (ed_check_interrupt(ed)) { final = ED_INTR; break; }
				ed->cur = matched[k];
				gls.f = 0; gls.list = list; gls.n = listn; gls.i = 0;
				while ((cmdl = linesrc_next(&gls)) != 0) {
					int r = ed_exec_one(ed, cmdl, &gls, CTX_GLIST);
					free(cmdl);
					if (r == ED_QUIT || r == ED_INTR || r == ED_ERR) { final = r; break; }
				}
			}
			ed->g_extra = 0; ed->g_extra_n = 0;
			free_string_array(list, listn);
			free(matched);
			if (final) return final;
		} else {
			char *last_cmd = 0;
			size_t k;
			if (require_eol(ed, p) < 0) { free(matched); return ED_ERR; }
			ed->g_extra = matched; ed->g_extra_n = nmatched;
			for (k = 0; k < nmatched && final == 0; k++) {
				char *cmdl;
				if (!matched[k]) continue;
				if (ed_check_interrupt(ed)) { final = ED_INTR; break; }
				ed->cur = matched[k];
				ed_print_range(ed, ed->cur, ed->cur, 0);
				cmdl = read_line_stdin(stdin);
				if (!cmdl) {
					if (ed_interrupted) { ed_interrupted = 0; fputs("?\n", stdout); final = ED_INTR; }
					break; /* real EOF: stop this G/V loop quietly */
				}
				if (cmdl[0] == 0) { free(cmdl); continue; }
				if (!strcmp(cmdl, "&")) {
					free(cmdl);
					if (!last_cmd) continue;
					cmdl = strdup(last_cmd);
					if (!cmdl) { final = ed_fail(ed, "out of memory"); break; }
				}
				{
					struct linesrc dummy;
					int r;
					dummy.f = stdin; dummy.list = 0; dummy.n = 0; dummy.i = 0;
					r = ed_exec_one(ed, cmdl, &dummy, CTX_GVSINGLE);
					if (r == 0) { free(last_cmd); last_cmd = strdup(cmdl); }
					free(cmdl);
					if (r == ED_QUIT || r == ED_INTR) { final = r; break; }
					/* a per-line ED_ERR does not abort the whole G/V run --
					 * it stays interactive/forgiving, matching the
					 * "print/read/execute" loop's own spirit; the ?
					 * has already been printed for this one line. */
				}
			}
			ed->g_extra = 0; ed->g_extra_n = 0;
			free(last_cmd);
			free(matched);
			if (final) return final;
		}
		break;
	}
	default:
		return ed_fail(ed, "unknown command");
	}
	return 0;
}

/* ==== SIGHUP best-effort save ============================================= */

static void ed_hup_save(struct ed *ed)
{
	FILE *f;
	if (!ed->modified || !ed->nlines) return;
	f = fopen("ed.hup", "w");
	if (!f) return; /* best-effort: nothing more useful to do here */
	(void)write_lines_to_file(f, ed->lines, 1, ed->nlines);
	(void)fclose(f);
}

/* ==== cleanup ============================================================== */

static void ed_free(struct ed *ed)
{
	free_string_array(ed->lines, ed->nlines);
	free_string_array(ed->u_lines, ed->u_nlines);
	free(ed->filename);
	free(ed->last_re);
	free(ed->last_repl);
	free(ed->last_bang);
}

/* ==== entry point ========================================================== */

int __util_ed_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	struct ed ed;
	struct sigaction sa, old_sa, sa_hup, old_sa_hup;
	int i, status;
	const char *prompt_arg = 0;
	int have_prompt_opt = 0;
	const char *initial_file = 0;
	struct linesrc topsrc;

	memset(&ed, 0, sizeof ed);
	ed_interrupted = 0;
	ed_hup = 0;

	for (i = 1; i < argc; i++) {
		char *a = argv[i];
		if (!strcmp(a, "--")) { i++; break; }
		if (a[0] != '-' || a[1] == 0) break;
		if (!strcmp(a, "-p")) {
			if (++i >= argc) { __util_diagf("ed: -p: option requires an argument\n"); return 2; }
			prompt_arg = argv[i]; have_prompt_opt = 1;
		} else if (a[1] == 'p' && a[2]) {
			prompt_arg = a + 2; have_prompt_opt = 1;
		} else if (!strcmp(a, "-s")) {
			ed.suppress = 1;
		} else {
			__util_diagf("ed: %s: invalid option\n", a);
			return 2;
		}
	}
	if (i < argc) { initial_file = argv[i]; i++; }
	if (i < argc) { __util_diagf("ed: %s: extra operand\n", argv[i]); return 2; }

	ed.prompt = have_prompt_opt ? prompt_arg : "*";
	ed.prompt_mode = have_prompt_opt;
	ed.cur = 0;

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = ed_sigint_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0; /* no SA_RESTART: a blocking read() must stay interruptible */
	sigaction(SIGINT, &sa, &old_sa);

	memset(&sa_hup, 0, sizeof sa_hup);
	sa_hup.sa_handler = ed_sighup_handler;
	sigemptyset(&sa_hup.sa_mask);
	sa_hup.sa_flags = 0;
	sigaction(SIGHUP, &sa_hup, &old_sa_hup);

	topsrc.f = stdin; topsrc.list = 0; topsrc.n = 0; topsrc.i = 0;

	if (initial_file) (void)cmd_edit(&ed, initial_file, 1, 1);

	for (;;) {
		char *line;
		int rc;

		if (ed_hup) {
			ed_hup = 0;
			ed_hup_save(&ed);
			break; /* treat like an unconditional Q -- see this file's header comment */
		}
		if (ed.prompt_mode) { fputs(ed.prompt, stdout); (void)fflush(stdout); }

		line = read_line_stdin(stdin);
		if (!line) {
			if (ed_interrupted) { ed_interrupted = 0; fputs("?\n", stdout); continue; }
			/* real EOF behaves like q, including (best-effort) the
			 * modified-buffer warning; there being no more input to
			 * retry with, this always actually quits. */
			if (ed.modified && ed.pending_quit != 'q') fputs("?\n", stdout);
			break;
		}
		rc = ed_exec_one(&ed, line, &topsrc, CTX_TOP);
		free(line);
		if (rc == ED_QUIT) break;
		/* ED_ERR and ED_INTR have already reported themselves; just
		 * loop back to the prompt. */
	}

	sigaction(SIGINT, &old_sa, 0);
	sigaction(SIGHUP, &old_sa_hup, 0);

	status = ed.had_error ? 1 : 0;
	ed_free(&ed);
	return status;
}
// NOLINTEND(misc-include-cleaner)
