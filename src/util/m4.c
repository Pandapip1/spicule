/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * m4(1p): `m4 [-s] [-D name[=val]]... [-U name]... [file...]`.
 *
 * Spec pages consulted (https://pubs.opengroup.org/onlinepubs/9699919799/):
 * utilities/m4.html.
 *
 * ==== THE SCANNING MODEL =====================================================
 *
 * scan() is the one recursive text scanner, used both for the top-level
 * input stream and for collecting each macro call's own arguments -- there
 * is no separate "raw argument text" pass. Both jobs copy comments through
 * verbatim, copy quoted regions through with delimiters stripped and their
 * content never scanned for macro names (m4.html: quoted text "shall not
 * be interpreted for macro names"), and invoke any recognized,
 * currently-defined macro name, pushing its expansion back onto the input
 * to be rescanned before continuing.
 *
 * Because argument collection runs through this same scanner, a macro
 * call's arguments ARE expanded as they are collected unless quoted --
 * real m4 semantics, and the reason idiomatic m4 quotes macro-name
 * arguments and definition bodies: `define(x,1)undefine(x)` undefines
 * "1", not "x", because x is already expanded before undefine's C code
 * runs. This file does not special-case any builtin's argument handling
 * to avoid it; doing so would deviate from real m4.
 *
 * A macro's expansion is pushed back onto the input rather than recursed
 * into, so a long CHAIN of macros expanding into one another costs no C
 * stack depth -- it's one loop reading whatever is on top of the
 * input-frame stack. Only genuinely NESTED calls in one argument list
 * (e.g. `foo(bar(baz(1)))`) use real C recursion, one level per open
 * paren.
 *
 * QUOTING is depth-counted: an inner left-quote inside an already-open
 * region increases a nesting counter and is kept as literal content; only
 * the depth-1-to-0 transition strips delimiters. This matches real m4
 * quote nesting and lets quoted text safely contain a stray quote
 * character.
 *
 * ==== BUILTINS IMPLEMENTED ===================================================
 *
 * All thirty-two: define, undefine, defn, pushdef, popdef, ifdef,
 * ifelse, shift, dnl, changequote, changecom, include, sinclude,
 * divert, undivert, divnum, len, index, substr, translit, dumpdef,
 * eval, incr, decr, syscmd, sysval, maketemp, mkstemp, m4exit, m4wrap,
 * traceon, traceoff.
 *
 * GNU-extension builtins that are NOT POSIX m4(1p) and are deliberately
 * NOT implemented: __file__, __line__, errprint, esyscmd, format,
 * patsubst, regexp, indir, builtin, and undivert's file-based (rather
 * than numeric) argument form.
 *
 * ---- shift() DOES quote its output -----------------------------------------
 * m4.html: shift's defining text is its arguments after the first, "each
 * ... quoted using the current quoting strings" -- so shift's output is
 * per-argument quoted like $@'s, not bare like $*'s.
 *
 * ---- syscmd does not capture output ----------------------------------------
 * m4.html both implies syscmd's result is the command's output AND states
 * "[n]o output redirection shall be performed" -- contradictory read
 * literally. Read against every real m4 (capturing output is esyscmd, the
 * GNU extension excluded above): syscmd(cmd) runs cmd via system(), leaves
 * stdout/stderr on the process's existing fds, expands to the empty
 * string, and records the exit status for sysval.
 *
 * ---- ifelse's 6+-argument recursion ----------------------------------------
 * m4.html, implemented exactly: with 6+ arguments and the first two
 * unequal, "the first three arguments shall be discarded and processing
 * shall restart with the remaining arguments" -- bi_ifelse() below is a
 * plain loop doing that.
 *
 * ---- defn of a builtin preserves builtin-ness ------------------------------
 * `define(new, defn(old))` must make NEW run old's real C logic, not
 * old's name as inert text. Since argument collection already expands
 * defn(old) before define() sees it, defn() cannot hand define() a raw
 * call to special-case; instead, for a builtin, defn() emits a short
 * control-character-prefixed sentinel (M4_BUILTIN_MAGIC + decimal id +
 * trailing 0x01), wrapped in the current quote strings so the rescan
 * between defn's return and define()'s argument strips the quotes but
 * leaves the sentinel (starting with 0x01, never a macro-name byte)
 * untouched. define()/pushdef() check their second argument against this
 * pattern (parse_builtin_sentinel()) before falling back to plain text.
 * Collision with genuine user text is accepted as astronomically
 * unlikely. A bare, non-defn-argument use of `defn(somebuiltin)` prints
 * this sentinel literally -- a narrow, cosmetic-only gap, since defn of a
 * builtin is only ever idiomatically used as define/pushdef's own second
 * argument.
 *
 * ---- eval(): 32-bit width, modular wraparound, C-style truncating division -
 * m4.html requires "signed integer arithmetic with at least 32-bit
 * precision"; this file uses int32_t/uint32_t explicitly, never `long`
 * (not guaranteed 32 bits on every host -- see src/wordexp/arith.c's note
 * on native-vs-target `long` width). Overflow wraps modulo 2^32 via
 * unsigned arithmetic, the same technique as arith.c's wrap_to_long()
 * (signed overflow is undefined by ISO C, POSIX doesn't mandate trapping
 * it, and wraparound is what users expect). Division/modulus truncate
 * toward zero (C99 6.5.5p6). A negative result renders as '-' plus the
 * magnitude's digits (never two's-complement bits); radix digits above 9
 * use lowercase 'a'..'z' (m4.html leaves case unspecified).
 *
 * ---- translit(): literal byte mapping only, no '-' range expansion --------
 * m4.html leaves duplicate-byte and '-'-range behavior in from/to
 * unspecified; this implements the simplest conforming reading -- every
 * byte of `from` maps one-for-one by index to the same-index byte of `to`
 * (deleted if `to` is shorter/absent), with no special '-' meaning.
 *
 * ---- foo() is one empty argument, not zero ---------------------------------
 * m4.html doesn't define an empty parenthesized call's argument count;
 * every real m4 treats `foo()` as one empty argument ($#==1, $1==""), and
 * this file matches that common convention.
 *
 * ---- changequote's single-argument form is refused, not guessed at --------
 * m4.html: "[t]he behavior is unspecified if there is a single argument
 * or either argument is null." Such a call is diagnosed to stderr and
 * left a no-op (quoting unchanged) -- loud refusal over guessing,
 * matching this project's house style (e.g. src/util/sort.c's -m).
 * Delimiter strings are capped at M4_MAXDELIM (32) bytes, diagnosed and
 * refused past that.
 *
 * ---- divert()/undivert(): in-memory buffers, only 1-9, n>9 refused --------
 * The nine numbered buffers m4.html specifies are growable in-memory byte
 * buffers (__util_mallocarray/__util_reallocarray/__util_array_capacity,
 * never a temp file). divert(n) for n>9 is diagnosed and refused (current
 * diversion unchanged); n<0 discards output, per m4.html. undivert() with
 * no arguments empties 1..9 in numeric order into whatever the CURRENT
 * diversion is, matching m4.html's "[b]uffers can be undiverted into
 * other temporary buffers". At end-of-input, any diversion still holding
 * data is auto-flushed straight to real stdout regardless of current
 * diversion (m4.html: "shall be written to standard output"), on every
 * return path out of __util_m4_main() including an early m4exit() --
 * discarding already-produced output would be a worse surprise than
 * honoring m4exit(). undivert()'s argument form only accepts numbers, per
 * m4.html; GNU's filename form is one of the extensions excluded above.
 *
 * ---- -s is accepted and ignored --------------------------------------------
 * `#line` output for a downstream c99 preprocessor phase has no consumer
 * here yet; -s is parsed (so scripts passing it don't fail) and does
 * nothing.
 *
 * ---- traceon/traceoff: minimal, functioning, not load-bearing -------------
 * m4.html leaves the trace format unspecified. This file tracks an on/off
 * set of traced names (or "trace everything") and prints one
 * "m4trace: name(args)" line per traced call to stderr.
 *
 * ---- mkstemp() is this library's own real mkstemp(), not reimplemented ----
 * include/stdlib.h / src/stdlib/mktemp.c already provide a real
 * O_CREAT|O_EXCL mkstemp(); the builtin is a thin wrapper (copy the
 * template to a mutable buffer, call it, close() the descriptor
 * immediately, expand to the resulting pathname). maketemp() is kept for
 * spec completeness only (m4.html: "should use mkstemp instead of the
 * obsolescent maketemp") and implemented as the simplest non-collision-
 * safe reading: trailing 'X' run replaced by decimal getpid().
 *
 * ---- text-only buffers: no embedded-NUL guarantee inside include() --------
 * Every string threaded through a macro's own C return value (a
 * builtin's result, a stored macro body, an argument value) is an
 * ordinary NUL-terminated C string. This narrows include(): file content
 * past an embedded NUL is lost. Top-level file/stdin operands are not
 * subject to this -- slurp() reads them with an explicit byte count and
 * pushes them onto the input stack with a real length, not through a
 * `char *` return.
 *
 * ---- exit() / _exit() are never called, and no state survives one call ----
 * __util_m4_main() can run in-process as a shell builtin
 * (src/sh/builtin.c's bi_m4()), sharing the calling shell's process --
 * see src/internal/util.h's Tier 4 comment and src/util/dd.c's header for
 * why calling exit()/_exit() from here would be a defect. m4exit() only
 * sets `st.exit_pending`/`st.exit_code` on the local `struct m4_state`;
 * every loop in scan()/collect_args() checks that flag each iteration and
 * unwinds cooperatively to an ordinary `return status;`. m4wrap() text is
 * scanned through the same loop, so an m4exit() reached while processing
 * wrap text stops promptly without calling exit(). Every byte of `struct
 * m4_state` (macro table, quote/comment strings, diversion buffers,
 * input-frame stack, wrap queue, trace set) is allocated on entry and
 * freed on every return path (m4_free()), so sequential invocations in
 * the same shell session never share state.
 *
 * ---- runaway expansion is bounded, and why that is not a correctness fix --
 * `define(a,a)a` loops forever by design -- real m4 implementations hang
 * on this input too, the same way `while true; do :; done` does. Nothing
 * here changes that expansion can run forever for a hostile or careless
 * script. What IS bounded is how long that can go on for code running
 * IN-PROCESS AS A SHELL BUILTIN, with no separate process to kill and no
 * signal-check to poll for interruption. Two independent caps, checked at
 * their one call site in dispatch_macro():
 *
 *   M4_MAX_EXPANSIONS bounds total macro invocations (the `define(a,a)a`
 *   shape -- a long flat chain, no extra C-stack depth per call);
 *
 *   M4_MAX_DEPTH bounds real C-stack recursion depth (the
 *   `len(len(len(...)))` shape -- genuinely nested calls, one C frame per
 *   level).
 *
 * Both unwind through the same cooperative path m4exit() uses
 * (st->exit_pending/st->exit_code) to an ordinary `return status;`, with
 * a nonzero status and one diagnostic line. A legitimate script is
 * expected to stay far under either limit.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include <sys/wait.h>
#include "util.h"
#include "ownership_stubs.h"

/* ==== builtin identity table ================================================ */

enum m4_builtin_id {
	BI_DEFINE, BI_UNDEFINE, BI_DEFN, BI_PUSHDEF, BI_POPDEF,
	BI_IFDEF, BI_IFELSE, BI_SHIFT, BI_DNL, BI_CHANGEQUOTE,
	BI_CHANGECOM, BI_INCLUDE, BI_SINCLUDE, BI_DIVERT, BI_UNDIVERT,
	BI_DIVNUM, BI_LEN, BI_INDEX, BI_SUBSTR, BI_TRANSLIT,
	BI_DUMPDEF, BI_EVAL, BI_INCR, BI_DECR, BI_SYSCMD,
	BI_SYSVAL, BI_MAKETEMP, BI_MKSTEMP, BI_M4EXIT, BI_M4WRAP,
	BI_TRACEON, BI_TRACEOFF,
	BI_COUNT
};

static const char *const m4_builtin_names[BI_COUNT] = {
	"define", "undefine", "defn", "pushdef", "popdef",
	"ifdef", "ifelse", "shift", "dnl", "changequote",
	"changecom", "include", "sinclude", "divert", "undivert",
	"divnum", "len", "index", "substr", "translit",
	"dumpdef", "eval", "incr", "decr", "syscmd",
	"sysval", "maketemp", "mkstemp", "m4exit", "m4wrap",
	"traceon", "traceoff",
};

#define M4_MAXDELIM 32
#define M4_BUILTIN_MAGIC "\x01M4BUILTIN:"

/* ---- M4_MAX_EXPANSIONS: a deliberate, harness-motivated safety net, NOT
 * a correctness fix -- see this file's header comment, "runaway
 * expansion is bounded, and why that is not a correctness fix," for the
 * reasoning in full.  Kept here, next to M4_MAXDELIM, because both are
 * "one number a caller might reasonably want to raise someday" rather
 * than load-bearing implementation detail. */
#define M4_MAX_EXPANSIONS 2000000UL

/* Real C-stack recursion depth, not total invocation count -- see the
 * comment at its one check site in dispatch_macro(). 5000 is well
 * inside any thread's default stack for this file's per-frame cost
 * (scan()'s wbuf[256] dominates it), and is many times deeper than any
 * legitimate, humanly-written m4 script's own macro-call nesting. */
#define M4_MAX_DEPTH 5000

/* eval()'s own recursive-descent parser (ev_primary()'s '(' handling
 * and ev_unary()'s unary-operator self-recursion, further below) is a
 * SEPARATE source of unbounded C-stack recursion from the
 * dispatch_macro()/collect_args()/scan() cycle M4_MAX_DEPTH guards --
 * it recurses once per '(' or per leading '+'/'-'/'~'/'!' character
 * inside a single eval() argument string, with no macro call and no
 * dispatch_macro() re-entry involved at all, so M4_MAX_DEPTH's check
 * never sees it. A single eval() call whose first argument is a few
 * hundred thousand nested parens (`eval(` + `(`*N + `1` + `)`*N + `)`)
 * crashed with a real stack overflow before this cap existed -- verified
 * with N=200000 against a real m4_state before this fix landed. Each
 * ev_*() frame here is small (no wbuf[256]-sized locals, unlike the
 * dispatch chain), so this can afford to be generous while still being
 * a hard, finite bound; legitimate eval() expressions nest nowhere near
 * this deep. */
#define M4_EVAL_MAX_DEPTH 2500

/* ==== growable byte buffer ================================================== */

struct m4_strbuf { char *data; size_t len, cap; };

static int strbuf_append(struct m4_strbuf *b, const char *data, size_t n)
{
	if (!n) {
		if (!b->data) {
			b->data = malloc(1);
			if (!b->data) return 0;
			b->data[0] = 0;
			b->cap = 1;
		}
		return 1;
	}
	/* b->len + n + 1, computed raw, wraps for an adversarial n and would
	 * then wrongly compare as "already fits", skipping the realloc
	 * below -- let __util_array_capacity's own overflow-checked test
	 * decide instead (src/util/man.c's mbuf_append() fix, same shape). */
	{
		size_t newcap;
		if (!__util_array_capacity(b->cap, b->len, n + 1, 64, 1, &newcap)) return 0;
		if (newcap != b->cap) {
			char *g = __util_reallocarray(b->data, newcap, 1);
			if (!g) return 0;
			b->data = g; b->cap = newcap;
		}
	}
	for (size_t i = 0; i < n; i++) b->data[b->len + i] = data[i];
	b->len += n;
	b->data[b->len] = 0;
	return 1;
}

/* Transfers ownership of b->data (or a fresh empty string, if nothing
 * was ever appended) to the caller.  b must not be reused afterward
 * without being reinitialized. */
static char *strbuf_finalize(struct m4_strbuf *b)
{
	if (!b->data) {
		char *e = malloc(1);
		if (e) e[0] = 0;
		return e;
	}
	return b->data;
}

/* ==== state structures ======================================================= */

struct m4_frame {
	char *buf;
	size_t len, pos;
	struct m4_frame *down;
};

struct m4_macro_def {
	int is_builtin;
	int builtin_id;
	char *text;			/* NULL when is_builtin */
	struct m4_macro_def *down;	/* the pushdef()'d definition beneath, if any */
};

struct m4_macro {
	char *name;
	struct m4_macro_def *top;	/* current (topmost) definition, or NULL */
	struct m4_macro *next;
};

struct m4_trace {
	char *name;
	struct m4_trace *next;
};

struct m4_state {
	struct m4_macro *macros;

	char lq[M4_MAXDELIM + 1], rq[M4_MAXDELIM + 1];
	int comment_on;
	char bc[M4_MAXDELIM + 1], ec[M4_MAXDELIM + 1];

	struct m4_strbuf div[10];	/* index 1..9 used; 0 unused */
	int cur_divert;

	struct m4_frame *top;

	char **wraps; size_t nwraps, wraps_cap, wrap_pos;

	int exit_pending, exit_code;
	int had_error;

	unsigned long expansions;	/* see M4_MAX_EXPANSIONS */
	int depth;			/* see M4_MAX_DEPTH */

	int sysval;

	int trace_all;
	struct m4_trace *traced;
};

/* ==== macro table ============================================================= */

static struct m4_macro *lookup(struct m4_state *st, const char *name)
{
	struct m4_macro *m;
	for (m = st->macros; m; m = m->next)
		if (!strcmp(m->name, name)) return m;
	return NULL;
}

/* is_builtin/builtin_id/text describe the new definition; push==1 keeps
 * the previous definition underneath (pushdef), push==0 replaces just
 * the top of the stack (define), matching m4.html's own wording for
 * each. */
static void define_macro(struct m4_state *st, const char *name,
	int is_builtin, int builtin_id, const char *text, int push)
{
	struct m4_macro *m = lookup(st, name);
	struct m4_macro_def *nd;

	if (!m) {
		m = malloc(sizeof *m);
		if (!m) { st->had_error = 1; return; }
		m->name = strdup(name);
		if (!m->name) { free(m); st->had_error = 1; return; }
		m->top = NULL;
		m->next = st->macros;
		st->macros = m;
	}

	nd = malloc(sizeof *nd);
	if (!nd) { st->had_error = 1; return; }
	nd->is_builtin = is_builtin;
	nd->builtin_id = builtin_id;
	nd->text = is_builtin ? NULL : strdup(text ? text : "");
	if (!is_builtin && !nd->text) { free(nd); st->had_error = 1; return; }

	if (push) {
		nd->down = m->top;
		m->top = nd;
	} else {
		struct m4_macro_def *old = m->top;
		nd->down = old ? old->down : NULL;
		m->top = nd;
		if (old) { free(old->text); free(old); }
	}
}

/* undefine(): removes the ENTIRE pushdef stack for name, not just the
 * top -- m4.html: "shall delete all definitions (including those
 * preserved using the pushdef macro)". */
static void remove_macro(struct m4_state *st, const char *name)
{
	struct m4_macro **pp = &st->macros;
	while (*pp) {
		if (!strcmp((*pp)->name, name)) {
			struct m4_macro *m = *pp;
			struct m4_macro_def *d = m->top;
			*pp = m->next;
			while (d) {
				struct m4_macro_def *dn = d->down;
				free(d->text); free(d);
				d = dn;
			}
			free(m->name); free(m);
			return;
		}
		pp = &(*pp)->next;
	}
}

/* popdef(): pops exactly one definition; if the stack becomes empty the
 * macro is fully removed, same end state as undefine() on a
 * single-definition name. */
static void pop_one(struct m4_state *st, const char *name)
{
	struct m4_macro *m = lookup(st, name);
	struct m4_macro_def *old;
	if (!m || !m->top) return;
	old = m->top;
	m->top = old->down;
	free(old->text); free(old);
	if (!m->top) remove_macro(st, name);
}

/* ==== input-frame stack and character pushback =============================== */

static void push_frame(struct m4_state *st, char *buf, size_t len)
{
	struct m4_frame *f;
	if (!len) { free(buf); return; }
	f = malloc(sizeof *f);
	if (!f) { free(buf); st->had_error = 1; return; }
	f->buf = buf; f->len = len; f->pos = 0;
	f->down = st->top;
	st->top = f;
}

static int getc_raw(struct m4_state *st)
{
	struct m4_frame *f;
	for (;;) {
		f = st->top;
		if (!f) return -1;
		if (f->pos < f->len) return (unsigned char)f->buf[f->pos++];
		st->top = f->down;
		free(f->buf); free(f);
	}
}

/* Pushes `c` back so the next getc_raw() returns it again, by pushing a
 * one-byte frame onto the SAME input-frame stack push_frame() uses --
 * deliberately not a separate pushback buffer.  A separate buffer that
 * getc_raw() always drained first (regardless of arrival order relative
 * to frames) would put a just-ungotten character ahead of a macro
 * expansion pushed by push_frame() AFTER it, even when the ungetc
 * logically happened first and the expansion belongs in between: e.g.
 * dispatch_macro() reads one lookahead byte to check for '(', ungets it
 * when absent, and only then pushes the macro's own expansion -- that
 * expansion must be read (and rescanned) before the lookahead byte, since
 * the byte lexically follows the macro call in the real input, while the
 * expansion replaces the call itself. Sharing one LIFO frame stack for
 * both makes "most recently pushed, whether by ungetc or by a macro
 * expansion, is read first" automatic instead of two competing
 * priorities. */
static void ungetc_raw(struct m4_state *st, int c)
{
	char *buf;
	if (c < 0) return;
	buf = malloc(1);
	if (!buf) { st->had_error = 1; return; }
	buf[0] = (char)c;
	push_frame(st, buf, 1);
}

/* Attempts to match `delim` starting at the current input position; on
 * a full match, consumes it and returns 1; on any mismatch, pushes
 * every character it had to read back (in the correct order) and
 * returns 0 having consumed nothing net.  getc_raw()/ungetc_raw() both
 * transparently cross input-frame boundaries (frames are popped as
 * they're exhausted, and pushback is itself just another frame on the
 * same stack), so this matches correctly even when `delim` straddles the
 * seam between a just-pushed macro expansion and the text beneath it. */
static int peek_match(struct m4_state *st, const char *delim)
{
	size_t n = strlen(delim);
	char got[M4_MAXDELIM];
	size_t i;
	for (i = 0; i < n; i++) {
		int c = getc_raw(st);
		if (c < 0 || (char)c != delim[i]) {
			if (c >= 0) ungetc_raw(st, c);
			while (i > 0) { i--; ungetc_raw(st, (unsigned char)got[i]); }
			return 0;
		}
		got[i] = (char)c;
	}
	return 1;
}

/* ==== output routing (stream/diversion) and the argument sink =============== */

static void emit_str(struct m4_state *st, const char *data, size_t len)
{
	if (!len) return;
	if (st->cur_divert < 0) return;			/* negative: discard */
	if (st->cur_divert == 0) {
		if (fwrite(data, 1, len, stdout) != len) st->had_error = 1;
		return;
	}
	if (!strbuf_append(&st->div[st->cur_divert], data, len)) st->had_error = 1;
}

/* buf==NULL routes through the current diversion (top-level/stream
 * context); buf!=NULL appends to the argument being collected. */
static void out_put(struct m4_state *st, struct m4_strbuf *buf, const char *data, size_t len)
{
	if (buf) { if (!strbuf_append(buf, data, len)) st->had_error = 1; }
	else emit_str(st, data, len);
}

/* ==== small parsing helpers =================================================== */

static const char *argn(char **args, int nargs, int i)
{
	return (i < nargs && args[i]) ? args[i] : "";
}

static void free_args(char **args, int nargs)
{
	int i;
	if (!args) return;
	for (i = 0; i < nargs; i++) free(args[i]);
	free(args);
}

/* Whole-string (surrounding whitespace tolerated) decimal integer --
 * used for every builtin's own plain numeric arguments (divert's n,
 * m4exit's code, incr/decr, substr's start/len, eval's radix/width).
 * eval()'s own EXPRESSION text uses a separate, C-literal-aware
 * tokenizer (ev_primary() below) since 0x/0-prefixed constants are
 * meaningful there. */
static int parse_long_strict(const char *s, long *out)
{
	char *end;
	long v;
	while (isspace((unsigned char)*s)) s++;
	if (!*s) return 0;
	v = strtol(s, &end, 10);
	while (isspace((unsigned char)*end)) end++;
	if (*end) return 0;
	*out = v;
	return 1;
}

/* Recognizes exactly "\x01M4BUILTIN:<digits>\x01" -- see this file's
 * header comment on defn()'s builtin-preserving mechanism. */
static int parse_builtin_sentinel(const char *s, int *id)
{
	size_t mlen = strlen(M4_BUILTIN_MAGIC);
	size_t slen = strlen(s);
	const char *p, *end_expect;
	char *endp;
	long v;

	if (slen < mlen + 1) return 0;
	for (size_t i = 0; i < mlen; i++)
		if (s[i] != M4_BUILTIN_MAGIC[i]) return 0;
	if (s[slen - 1] != '\x01') return 0;

	p = s + mlen;
	end_expect = s + slen - 1;
	if (p == end_expect) return 0;
	v = strtol(p, &endp, 10);
	if (endp != end_expect) return 0;
	if (v < 0 || v >= BI_COUNT) return 0;
	*id = (int)v;
	return 1;
}

/* ==== eval(): a hand-rolled recursive-descent, precedence-climbing
 * evaluator over m4's (assignment-free, variable-free) arithmetic
 * grammar -- see this file's header comment for the width/overflow
 * choices. */

struct m4_eval { const char *p; int err; int live; int depth; };

static void ev_fail(struct m4_eval *e) { if (e->live && !e->err) e->err = 1; }

/* Shared by ev_primary()'s '(' case and ev_unary()'s unary-operator
 * self-recursion below -- both are real C-stack recursion through this
 * one struct's `depth` counter, so a mix of the two (e.g.
 * `eval(-(-(-(...))))`) is bounded by their COMBINED depth, matching
 * how much C stack is actually in use. On hitting the cap this fails
 * the expression and returns 0 WITHOUT recursing further, so the
 * caller's own stack frames unwind normally instead of the cap being
 * just a diagnostic bolted onto an unbounded call. */
static int ev_depth_ok(struct m4_eval *e)
{
	if (++e->depth > M4_EVAL_MAX_DEPTH) {
		ev_fail(e);
		e->depth--;
		return 0;
	}
	return 1;
}

static void ev_ws(struct m4_eval *e) { while (*e->p == ' ' || *e->p == '\t' || *e->p == '\n') e->p++; }

static int32_t ev_wrap(uint32_t u)
{
	uint32_t half = 0x80000000u;
	if (u < half) return (int32_t)u;
	return (int32_t)(u - half) - (int32_t)(half - 1u) - 1;
}

static int32_t ev_negate(int32_t v) { return ev_wrap(0u - (uint32_t)v); }

static int32_t ev_lor(struct m4_eval *e);

static int32_t ev_primary(struct m4_eval *e)
{
	int32_t v;
	ev_ws(e);
	if (*e->p == '(') {
		e->p++;
		if (!ev_depth_ok(e)) return 0;
		v = ev_lor(e);
		e->depth--;
		ev_ws(e);
		if (*e->p == ')') e->p++;
		else ev_fail(e);
		return v;
	}
	if (isdigit((unsigned char)*e->p)) {
		char *end;
		long lv = strtol(e->p, &end, 0);
		e->p = end;
		return ev_wrap((uint32_t)(unsigned long)lv);
	}
	ev_fail(e);
	if (*e->p) e->p++;
	return 0;
}

static int32_t ev_unary(struct m4_eval *e)
{
	ev_ws(e);
	if (*e->p == '+' || *e->p == '-' || *e->p == '~' || *e->p == '!') {
		char op = *e->p;
		int32_t r;
		e->p++;
		if (!ev_depth_ok(e)) return 0;
		r = ev_unary(e);
		e->depth--;
		switch (op) {
		case '+': return r;
		case '-': return ev_negate(r);
		case '~': return ~r;
		default: return !r;
		}
	}
	return ev_primary(e);
}

static int32_t ev_mul(struct m4_eval *e)
{
	int32_t v = ev_unary(e);
	for (;;) {
		ev_ws(e);
		if (*e->p == '*') {
			e->p++;
			{
				int32_t r = ev_unary(e);
				v = ev_wrap((uint32_t)v * (uint32_t)r);
			}
		} else if (*e->p == '/') {
			e->p++;
			{
				int32_t r = ev_unary(e);
				if (r == 0) { ev_fail(e); v = 0; }
				else if (r == -1) v = ev_negate(v);
				else v = v / r;
			}
		} else if (*e->p == '%') {
			e->p++;
			{
				int32_t r = ev_unary(e);
				if (r == 0) { ev_fail(e); v = 0; }
				else if (r == -1) v = 0;
				else v = v % r;
			}
		} else return v;
	}
}

static int32_t ev_add(struct m4_eval *e)
{
	int32_t v = ev_mul(e);
	for (;;) {
		ev_ws(e);
		if (*e->p == '+') { e->p++; v = ev_wrap((uint32_t)v + (uint32_t)ev_mul(e)); }
		else if (*e->p == '-') { e->p++; v = ev_wrap((uint32_t)v - (uint32_t)ev_mul(e)); }
		else return v;
	}
}

static int32_t ev_shift(struct m4_eval *e)
{
	int32_t v = ev_add(e);
	for (;;) {
		ev_ws(e);
		if (e->p[0] == '<' && e->p[1] == '<') {
			e->p += 2;
			{
				int32_t r = ev_add(e);
				if (r < 0 || r >= 32) { ev_fail(e); v = 0; }
				else v = ev_wrap((uint32_t)v << r);
			}
		} else if (e->p[0] == '>' && e->p[1] == '>') {
			e->p += 2;
			{
				int32_t r = ev_add(e);
				if (r < 0 || r >= 32) { ev_fail(e); v = 0; }
				else v = v >> r;
			}
		} else return v;
	}
}

static int32_t ev_rel(struct m4_eval *e)
{
	int32_t v = ev_shift(e);
	for (;;) {
		ev_ws(e);
		if (e->p[0] == '<' && e->p[1] == '=') { e->p += 2; v = v <= ev_shift(e); }
		else if (e->p[0] == '>' && e->p[1] == '=') { e->p += 2; v = v >= ev_shift(e); }
		else if (e->p[0] == '<') { e->p += 1; v = v < ev_shift(e); }
		else if (e->p[0] == '>') { e->p += 1; v = v > ev_shift(e); }
		else return v;
	}
}

static int32_t ev_eq(struct m4_eval *e)
{
	int32_t v = ev_rel(e);
	for (;;) {
		ev_ws(e);
		if (e->p[0] == '=' && e->p[1] == '=') { e->p += 2; v = v == ev_rel(e); }
		else if (e->p[0] == '!' && e->p[1] == '=') { e->p += 2; v = v != ev_rel(e); }
		else return v;
	}
}

static int32_t ev_band(struct m4_eval *e)
{
	int32_t v = ev_eq(e);
	for (;;) {
		ev_ws(e);
		if (e->p[0] != '&' || e->p[1] == '&') return v;
		e->p++; v = v & ev_eq(e);
	}
}

static int32_t ev_bxor(struct m4_eval *e)
{
	int32_t v = ev_band(e);
	for (;;) {
		ev_ws(e);
		if (*e->p != '^') return v;
		e->p++; v = v ^ ev_band(e);
	}
}

static int32_t ev_bor(struct m4_eval *e)
{
	int32_t v = ev_bxor(e);
	for (;;) {
		ev_ws(e);
		if (e->p[0] != '|' || e->p[1] == '|') return v;
		e->p++; v = v | ev_bxor(e);
	}
}

static int32_t ev_land(struct m4_eval *e)
{
	int32_t v = ev_bor(e);
	for (;;) {
		int save; int32_t rhs;
		ev_ws(e);
		if (!(e->p[0] == '&' && e->p[1] == '&')) return v;
		e->p += 2;
		save = e->live;
		e->live = save && (v != 0);
		rhs = ev_bor(e);
		e->live = save;
		v = (v != 0) && (rhs != 0);
	}
}

static int32_t ev_lor(struct m4_eval *e)
{
	int32_t v = ev_land(e);
	for (;;) {
		int save; int32_t rhs;
		ev_ws(e);
		if (!(e->p[0] == '|' && e->p[1] == '|')) return v;
		e->p += 2;
		save = e->live;
		e->live = save && (v == 0);
		rhs = ev_land(e);
		e->live = save;
		v = (v != 0) || (rhs != 0);
	}
}

static char *format_radix(int32_t value, int radix __arith_range(2, 36),
	int width)
{
	char digits[40];
	int n = 0, i, neg = value < 0;
	uint32_t mag;
	struct m4_strbuf b;
	memset(&b, 0, sizeof b);

	if (value == INT32_MIN) mag = 0x80000000u;
	else mag = neg ? (uint32_t)(-value) : (uint32_t)value;

	if (mag == 0) digits[n++] = '0';
	while (mag && n < (int)sizeof digits) {
		int d = (int)(mag % (uint32_t)radix);
		digits[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
		mag /= (uint32_t)radix;
	}
	while (n < width && n < (int)sizeof digits) digits[n++] = '0';

	if (neg) strbuf_append(&b, "-", 1);
	for (i = n - 1; i >= 0; i--) strbuf_append(&b, &digits[i], 1);
	return strbuf_finalize(&b);
}

/* ==== tracing (minimal, see header comment) =================================== */

static int is_traced(struct m4_state *st, const char *name)
{
	struct m4_trace *t;
	if (st->trace_all) return 1;
	for (t = st->traced; t; t = t->next) if (!strcmp(t->name, name)) return 1;
	return 0;
}

static void trace_add(struct m4_state *st, const char *name)
{
	struct m4_trace *t = malloc(sizeof *t);
	if (!t) { st->had_error = 1; return; }
	t->name = strdup(name);
	if (!t->name) { free(t); st->had_error = 1; return; }
	t->next = st->traced; st->traced = t;
}

static void trace_remove_all(struct m4_state *st)
{
	while (st->traced) {
		struct m4_trace *n = st->traced->next;
		free(st->traced->name); free(st->traced);
		st->traced = n;
	}
}

static void trace_remove(struct m4_state *st, const char *name)
{
	struct m4_trace **pp = &st->traced;
	while (*pp) {
		if (!strcmp((*pp)->name, name)) {
			struct m4_trace *d = *pp;
			*pp = d->next;
			free(d->name); free(d);
			return;
		}
		pp = &(*pp)->next;
	}
}

static void trace_print(const char *name, char **args, int nargs)
{
	int i;
	fprintf(stderr, "m4trace: %s(", name);
	for (i = 0; i < nargs; i++) fprintf(stderr, "%s%s", i ? "," : "", args[i]);
	fprintf(stderr, ")\n");
}

/* ==== whole-file/stream slurp (for stdin/file operands and include()) ======== */

static int slurp(FILE *f, char **out, size_t *outlen)
{
	struct m4_strbuf b;
	char tmp[4096];
	size_t n;
	memset(&b, 0, sizeof b);
	while ((n = fread(tmp, 1, sizeof tmp, f)) > 0)
		if (!strbuf_append(&b, tmp, n)) { free(b.data); return -1; }
	if (ferror(f)) { free(b.data); return -1; }
	*outlen = b.len;
	*out = strbuf_finalize(&b);
	return *out ? 0 : -1;
}

/* ==== builtins ================================================================ */

static void install_definition(struct m4_state *st, const char *name, const char *rawtext, int push)
{
	int bid;
	if (parse_builtin_sentinel(rawtext, &bid))
		define_macro(st, name, 1, bid, NULL, push);
	else
		define_macro(st, name, 0, 0, rawtext, push);
}

static char *bi_define(struct m4_state *st, char **args, int nargs)
{
	const char *name = argn(args, nargs, 0);
	if (!name[0]) { __util_diagf("m4: define: missing macro name\n"); st->had_error = 1; return strdup(""); }
	install_definition(st, name, argn(args, nargs, 1), 0);
	return strdup("");
}

static char *bi_pushdef(struct m4_state *st, char **args, int nargs)
{
	const char *name = argn(args, nargs, 0);
	if (!name[0]) { __util_diagf("m4: pushdef: missing macro name\n"); st->had_error = 1; return strdup(""); }
	install_definition(st, name, argn(args, nargs, 1), 1);
	return strdup("");
}

static char *bi_undefine(struct m4_state *st, char **args, int nargs)
{
	int i;
	for (i = 0; i < nargs; i++) if (args[i][0]) remove_macro(st, args[i]);
	return strdup("");
}

static char *bi_popdef(struct m4_state *st, char **args, int nargs)
{
	int i;
	for (i = 0; i < nargs; i++) if (args[i][0]) pop_one(st, args[i]);
	return strdup("");
}

static char *bi_defn(struct m4_state *st, char **args, int nargs)
{
	struct m4_strbuf b;
	int i;
	memset(&b, 0, sizeof b);
	for (i = 0; i < nargs; i++) {
		struct m4_macro *m = lookup(st, args[i]);
		if (!m || !m->top) continue;
		strbuf_append(&b, st->lq, strlen(st->lq));
		if (m->top->is_builtin) {
			char sbuf[64];
			snprintf(sbuf, sizeof sbuf, "%s%d\x01", M4_BUILTIN_MAGIC, m->top->builtin_id);
			strbuf_append(&b, sbuf, strlen(sbuf));
		} else {
			strbuf_append(&b, m->top->text, strlen(m->top->text));
		}
		strbuf_append(&b, st->rq, strlen(st->rq));
	}
	return strbuf_finalize(&b);
}

static char *bi_ifdef(struct m4_state *st, char **args, int nargs)
{
	struct m4_macro *m = lookup(st, argn(args, nargs, 0));
	return strdup((m && m->top) ? argn(args, nargs, 1) : argn(args, nargs, 2));
}

static char *bi_ifelse(char **args, int nargs)
{
	for (;;) {
		if (nargs < 3) return strdup("");
		if (!strcmp(args[0], args[1])) return strdup(argn(args, nargs, 2));
		if (nargs == 3) return strdup("");
		if (nargs == 4 || nargs == 5) return strdup(argn(args, nargs, 3));
		args += 3; nargs -= 3;
	}
}

static char *bi_shift(struct m4_state *st, char **args, int nargs)
{
	struct m4_strbuf b;
	int i;
	memset(&b, 0, sizeof b);
	for (i = 1; i < nargs; i++) {
		if (i > 1) strbuf_append(&b, ",", 1);
		strbuf_append(&b, st->lq, strlen(st->lq));
		strbuf_append(&b, args[i], strlen(args[i]));
		strbuf_append(&b, st->rq, strlen(st->rq));
	}
	return strbuf_finalize(&b);
}

static char *bi_changequote(struct m4_state *st, char **args, int nargs)
{
	if (nargs == 0) { strcpy(st->lq, "`"); strcpy(st->rq, "'"); return strdup(""); }
	if (nargs == 1) { __util_diagf("m4: changequote: single-argument form is unspecified; ignoring\n"); return strdup(""); }
	if (!args[0][0] || !args[1][0]) { __util_diagf("m4: changequote: empty quote string is unspecified; ignoring\n"); return strdup(""); }
	if (strlen(args[0]) > M4_MAXDELIM || strlen(args[1]) > M4_MAXDELIM) {
		__util_diagf("m4: changequote: quote string longer than %d bytes\n", M4_MAXDELIM);
		st->had_error = 1;
		return strdup("");
	}
	strcpy(st->lq, args[0]); strcpy(st->rq, args[1]);
	return strdup("");
}

static char *bi_changecom(struct m4_state *st, char **args, int nargs)
{
	if (nargs == 0 || !args[0][0]) { st->comment_on = 0; return strdup(""); }
	if (strlen(args[0]) > M4_MAXDELIM) {
		__util_diagf("m4: changecom: comment string longer than %d bytes\n", M4_MAXDELIM);
		st->had_error = 1;
		return strdup("");
	}
	strcpy(st->bc, args[0]);
	if (nargs >= 2 && args[1][0]) {
		if (strlen(args[1]) > M4_MAXDELIM) {
			__util_diagf("m4: changecom: comment string longer than %d bytes\n", M4_MAXDELIM);
			st->had_error = 1;
			return strdup("");
		}
		strcpy(st->ec, args[1]);
	} else {
		strcpy(st->ec, "\n");
	}
	st->comment_on = 1;
	return strdup("");
}

static char *bi_include(struct m4_state *st, const char *path, int required)
{
	FILE *f = fopen(path, "rb");
	char *buf; size_t len;
	if (!f) {
		if (required) { __util_diagf("m4: include: %s: %s\n", path, strerror(errno)); st->had_error = 1; }
		return strdup("");
	}
	if (slurp(f, &buf, &len) < 0) {
		(void)fclose(f);
		if (required) { __util_diagf("m4: include: %s: read error\n", path); st->had_error = 1; }
		return strdup("");
	}
	(void)fclose(f);
	return buf;
}

static char *bi_divert(struct m4_state *st, char **args, int nargs)
{
	long n;
	if (nargs == 0 || !args[0][0]) { st->cur_divert = 0; return strdup(""); }
	if (!parse_long_strict(args[0], &n)) {
		__util_diagf("m4: divert: %s: not a valid integer\n", args[0]);
		st->had_error = 1;
		return strdup("");
	}
	if (n > 9) {
		__util_diagf("m4: divert: %ld: only diversions 0-9 are supported\n", n);
		st->had_error = 1;
		return strdup("");
	}
	st->cur_divert = (int)n;
	return strdup("");
}

static void undivert_one(struct m4_state *st, int n)
{
	if (n < 1 || n > 9 || !st->div[n].len) return;
	emit_str(st, st->div[n].data, st->div[n].len);
	st->div[n].len = 0;
	if (st->div[n].data) st->div[n].data[0] = 0;
}

static char *bi_undivert(struct m4_state *st, char **args, int nargs)
{
	if (nargs == 0) {
		int n;
		for (n = 1; n <= 9; n++) undivert_one(st, n);
	} else {
		int i;
		for (i = 0; i < nargs; i++) {
			long n;
			if (parse_long_strict(args[i], &n)) undivert_one(st, (int)n);
			else { __util_diagf("m4: undivert: %s: not a valid diversion number\n", args[i]); st->had_error = 1; }
		}
	}
	return strdup("");
}

static char *bi_index(const char *s, const char *sub)
{
	long pos = -1;
	size_t lsub = strlen(sub);
	char buf[24];
	if (lsub == 0) pos = 0;
	else { const char *f = strstr(s, sub); if (f) pos = (long)(f - s); }
	snprintf(buf, sizeof buf, "%ld", pos);
	return strdup(buf);
}

static char *bi_substr(struct m4_state *st, const char *s, const char *start_s, const char *len_s)
{
	long start, len = 0;
	size_t slen, avail, take;
	char *r;

	if (!parse_long_strict(start_s, &start) || start < 0) {
		__util_diagf("m4: substr: %s: invalid start\n", start_s);
		st->had_error = 1;
		return strdup("");
	}
	slen = strlen(s);
	if ((size_t)start >= slen) return strdup("");
	avail = slen - (size_t)start;
	take = avail;
	if (len_s) {
		if (!parse_long_strict(len_s, &len) || len < 0) {
			__util_diagf("m4: substr: %s: invalid length\n", len_s);
			st->had_error = 1;
			return strdup("");
		}
		take = (size_t)len < avail ? (size_t)len : avail;
	}
	r = malloc(take + 1);
	if (!r) { st->had_error = 1; return strdup(""); }
	for (size_t i = 0; i < take; i++) r[i] = s[start + i];
	r[take] = 0;
	return r;
}

static char *bi_translit(const char *s, const char *from, const char *to)
{
	size_t ls = strlen(s), lf = strlen(from), lt = strlen(to), i;
	struct m4_strbuf b;
	memset(&b, 0, sizeof b);
	for (i = 0; i < ls; i++) {
		char c = s[i];
		const char *pos = memchr(from, c, lf);
		if (!pos) { strbuf_append(&b, &c, 1); continue; }
		{
			size_t idx = (size_t)(pos - from);
			if (idx < lt) strbuf_append(&b, &to[idx], 1);
		}
	}
	return strbuf_finalize(&b);
}

static void dump_one(struct m4_macro *m)
{
	if (!m->top) return;
	if (m->top->is_builtin) fprintf(stderr, "%s:\t<builtin>\n", m->name);
	else fprintf(stderr, "%s:\t%s\n", m->name, m->top->text);
}

static char *bi_dumpdef(struct m4_state *st, char **args, int nargs)
{
	if (nargs == 0) {
		struct m4_macro *m;
		for (m = st->macros; m; m = m->next) dump_one(m);
	} else {
		int i;
		for (i = 0; i < nargs; i++) {
			struct m4_macro *m = lookup(st, args[i]);
			if (m) dump_one(m);
		}
	}
	return strdup("");
}

static char *bi_eval(struct m4_state *st, char **args, int nargs)
{
	const char *expr = argn(args, nargs, 0);
	const char *radix_s = argn(args, nargs, 1);
	const char *width_s = argn(args, nargs, 2);
	struct m4_eval e;
	long radix = 10, width = 0;
	int32_t v;

	e.p = expr; e.err = 0; e.live = 1; e.depth = 0;
	v = ev_lor(&e);
	if (!e.err) { ev_ws(&e); if (*e.p) e.err = 1; }
	if (radix_s[0] && !parse_long_strict(radix_s, &radix)) e.err = 1;
	if (width_s[0] && (!parse_long_strict(width_s, &width) || width < 0)) e.err = 1;
	if (radix < 2 || radix > 36) e.err = 1;

	if (e.err) {
		__util_diagf("m4: eval: %s: invalid expression or argument\n", expr);
		st->had_error = 1;
		return strdup("");
	}
	return format_radix(v, (int)radix, (int)width);
}

static char *bi_incr(struct m4_state *st, char **args, int nargs)
{
	long v; char buf[32];
	const char *s = argn(args, nargs, 0);
	if (!parse_long_strict(s, &v)) { __util_diagf("m4: incr: %s: not a valid integer\n", s); st->had_error = 1; return strdup(""); }
	snprintf(buf, sizeof buf, "%ld", v + 1);
	return strdup(buf);
}

static char *bi_decr(struct m4_state *st, char **args, int nargs)
{
	long v; char buf[32];
	const char *s = argn(args, nargs, 0);
	if (!parse_long_strict(s, &v)) { __util_diagf("m4: decr: %s: not a valid integer\n", s); st->had_error = 1; return strdup(""); }
	snprintf(buf, sizeof buf, "%ld", v - 1);
	return strdup(buf);
}

static char *bi_syscmd(struct m4_state *st, const char *cmd)
{
	int status = system(cmd);
	if (status == -1) {
		__util_diagf("m4: syscmd: %s\n", strerror(errno));
		st->had_error = 1;
		st->sysval = 127;
	} else if (WIFEXITED(status)) {
		st->sysval = WEXITSTATUS(status);
	} else if (WIFSIGNALED(status)) {
		st->sysval = 128 + WTERMSIG(status);
	} else {
		st->sysval = status;
	}
	return strdup("");
}

static char *bi_sysval(struct m4_state *st)
{
	char buf[16];
	snprintf(buf, sizeof buf, "%d", st->sysval);
	return strdup(buf);
}

static char *bi_maketemp(const char *tmpl)
{
	size_t n = strlen(tmpl), x = n, xrun;
	char pidbuf[32];
	int pl;
	struct m4_strbuf b;

	while (x > 0 && tmpl[x - 1] == 'X') x--;
	xrun = n - x;
	if (!xrun) return strdup(tmpl);

	pl = snprintf(pidbuf, sizeof pidbuf, "%ld", (long)getpid());
	memset(&b, 0, sizeof b);
	strbuf_append(&b, tmpl, x);
	strbuf_append(&b, pidbuf, (size_t)pl);
	return strbuf_finalize(&b);
}

static char *bi_mkstemp(struct m4_state *st, const char *tmpl)
{
	char buf[PATH_MAX];
	int fd;
	if (strlen(tmpl) >= sizeof buf) {
		__util_diagf("m4: mkstemp: template too long\n");
		st->had_error = 1;
		return strdup("");
	}
	strcpy(buf, tmpl);
	fd = mkstemp(buf);
	if (fd < 0) {
		__util_diagf("m4: mkstemp: %s: %s\n", tmpl, strerror(errno));
		st->had_error = 1;
		return strdup("");
	}
	(void)close(fd);
	return strdup(buf);
}

static char *bi_m4exit(struct m4_state *st, char **args, int nargs)
{
	long code;
	if (nargs >= 1 && args[0][0]) {
		if (!parse_long_strict(args[0], &code)) {
			__util_diagf("m4: m4exit: %s: not a valid integer\n", args[0]);
			st->had_error = 1;
			code = 1;
		}
	} else {
		code = st->had_error ? 1 : 0;
	}
	st->exit_pending = 1;
	st->exit_code = (int)code;
	return strdup("");
}

static char *bi_m4wrap(struct m4_state *st, char **args, int nargs)
{
	char *copy = strdup(argn(args, nargs, 0));
	if (!copy) { st->had_error = 1; return strdup(""); }
	if (st->nwraps >= st->wraps_cap) {
		size_t newcap;
		char **g;
		if (!__util_array_capacity(st->wraps_cap, st->nwraps, 1, 8, sizeof(char *), &newcap)) {
			free(copy); st->had_error = 1; return strdup("");
		}
		g = __util_reallocarray(st->wraps, newcap, sizeof(char *));
		if (!g) { free(copy); st->had_error = 1; return strdup(""); }
		st->wraps = g; st->wraps_cap = newcap;
	}
	st->wraps[st->nwraps++] = copy;
	return strdup("");
}

static char *bi_traceon(struct m4_state *st, char **args, int nargs)
{
	if (nargs == 0) { st->trace_all = 1; trace_remove_all(st); }
	else { int i; for (i = 0; i < nargs; i++) trace_add(st, args[i]); }
	return strdup("");
}

static char *bi_traceoff(struct m4_state *st, char **args, int nargs)
{
	if (nargs == 0) { st->trace_all = 0; trace_remove_all(st); }
	else { int i; for (i = 0; i < nargs; i++) trace_remove(st, args[i]); }
	return strdup("");
}

static char *call_builtin(struct m4_state *st, int id, char **args, int nargs)
{
	switch (id) {
	case BI_DEFINE: return bi_define(st, args, nargs);
	case BI_UNDEFINE: return bi_undefine(st, args, nargs);
	case BI_DEFN: return bi_defn(st, args, nargs);
	case BI_PUSHDEF: return bi_pushdef(st, args, nargs);
	case BI_POPDEF: return bi_popdef(st, args, nargs);
	case BI_IFDEF: return bi_ifdef(st, args, nargs);
	case BI_IFELSE: return bi_ifelse(args, nargs);
	case BI_SHIFT: return bi_shift(st, args, nargs);
	case BI_DNL: return strdup(""); /* dnl is intercepted before reaching here; kept for completeness */
	case BI_CHANGEQUOTE: return bi_changequote(st, args, nargs);
	case BI_CHANGECOM: return bi_changecom(st, args, nargs);
	case BI_INCLUDE: return bi_include(st, argn(args, nargs, 0), 1);
	case BI_SINCLUDE: return bi_include(st, argn(args, nargs, 0), 0);
	case BI_DIVERT: return bi_divert(st, args, nargs);
	case BI_UNDIVERT: return bi_undivert(st, args, nargs);
	case BI_DIVNUM: { char buf[16]; snprintf(buf, sizeof buf, "%d", st->cur_divert); return strdup(buf); }
	case BI_LEN: { char buf[24]; snprintf(buf, sizeof buf, "%zu", strlen(argn(args, nargs, 0))); return strdup(buf); }
	case BI_INDEX: return bi_index(argn(args, nargs, 0), argn(args, nargs, 1));
	case BI_SUBSTR: return bi_substr(st, argn(args, nargs, 0), argn(args, nargs, 1), nargs >= 3 ? args[2] : NULL);
	case BI_TRANSLIT: return bi_translit(argn(args, nargs, 0), argn(args, nargs, 1), argn(args, nargs, 2));
	case BI_DUMPDEF: return bi_dumpdef(st, args, nargs);
	case BI_EVAL: return bi_eval(st, args, nargs);
	case BI_INCR: return bi_incr(st, args, nargs);
	case BI_DECR: return bi_decr(st, args, nargs);
	case BI_SYSCMD: return bi_syscmd(st, argn(args, nargs, 0));
	case BI_SYSVAL: return bi_sysval(st);
	case BI_MAKETEMP: return bi_maketemp(argn(args, nargs, 0));
	case BI_MKSTEMP: return bi_mkstemp(st, argn(args, nargs, 0));
	case BI_M4EXIT: return bi_m4exit(st, args, nargs);
	case BI_M4WRAP: return bi_m4wrap(st, args, nargs);
	case BI_TRACEON: return bi_traceon(st, args, nargs);
	case BI_TRACEOFF: return bi_traceoff(st, args, nargs);
	default: return strdup("");
	}
}

/* ==== $0, $1-$9, $#, $star, $@ substitution into a user macro's stored body === */

static char *build_user_expansion(const char *name, const char *body, char **args, int nargs, struct m4_state *st)
{
	struct m4_strbuf out;
	size_t i = 0, blen = strlen(body);
	memset(&out, 0, sizeof out);

	while (i < blen) {
		if (body[i] == '$' && i + 1 < blen) {
			char n = body[i + 1];
			if (n == '0') {
				strbuf_append(&out, name, strlen(name)); i += 2;
			} else if (n >= '1' && n <= '9') {
				int idx = n - '0';
				if (idx <= nargs) strbuf_append(&out, args[idx - 1], strlen(args[idx - 1]));
				i += 2;
			} else if (n == '#') {
				char buf[16]; int L = snprintf(buf, sizeof buf, "%d", nargs);
				strbuf_append(&out, buf, (size_t)L); i += 2;
			} else if (n == '*') {
				int k;
				for (k = 0; k < nargs; k++) {
					if (k) strbuf_append(&out, ",", 1);
					strbuf_append(&out, args[k], strlen(args[k]));
				}
				i += 2;
			} else if (n == '@') {
				int k;
				for (k = 0; k < nargs; k++) {
					if (k) strbuf_append(&out, ",", 1);
					strbuf_append(&out, st->lq, strlen(st->lq));
					strbuf_append(&out, args[k], strlen(args[k]));
					strbuf_append(&out, st->rq, strlen(st->rq));
				}
				i += 2;
			} else {
				strbuf_append(&out, "$", 1); i += 1;
			}
		} else {
			strbuf_append(&out, &body[i], 1); i += 1;
		}
	}
	return strbuf_finalize(&out);
}

/* ==== the scanner, argument collector and macro dispatcher (mutually
 * recursive -- see this file's header comment for the overall model) === */

static int is_namestart(int c) { return isalpha((unsigned char)c) || c == '_'; }
static int is_namechar(int c) { return isalnum((unsigned char)c) || c == '_'; }

static int scan(struct m4_state *st, struct m4_strbuf *buf, int in_arg);
static char **collect_args(struct m4_state *st, int *out_nargs);
static void dispatch_macro(struct m4_state *st, struct m4_macro *m, const char *name);

static void skip_ws(struct m4_state *st)
{
	for (;;) {
		int c = getc_raw(st);
		if (c < 0) return;
		if (!isspace((unsigned char)c)) { ungetc_raw(st, c); return; }
	}
}

/* The opening left-quote has already been consumed by the caller
 * (via peek_match()).  Nesting is depth-counted: an inner left-quote
 * increases depth and is itself kept as literal content; only the
 * transition from depth 1 to 0 is the true, delimiter-stripped close. */
static void read_quoted_into(struct m4_state *st, struct m4_strbuf *buf)
{
	int depth = 1;
	for (;;) {
		if (st->exit_pending) return;
		if (peek_match(st, st->rq)) {
			depth--;
			if (!depth) return;
			out_put(st, buf, st->rq, strlen(st->rq));
			continue;
		}
		if (peek_match(st, st->lq)) {
			depth++;
			out_put(st, buf, st->lq, strlen(st->lq));
			continue;
		}
		{
			int c = getc_raw(st);
			char ch;
			if (c < 0) { __util_diagf("m4: unterminated quoted string\n"); st->had_error = 1; return; }
			ch = (char)c;
			out_put(st, buf, &ch, 1);
		}
	}
}

static int scan(struct m4_state *st, struct m4_strbuf *buf, int in_arg)
{
	int depth = 0;
	for (;;) {
		if (st->exit_pending) return 0;

		if (st->comment_on && peek_match(st, st->bc)) {
			out_put(st, buf, st->bc, strlen(st->bc));
			for (;;) {
				if (st->exit_pending) return 0;
				if (peek_match(st, st->ec)) { out_put(st, buf, st->ec, strlen(st->ec)); break; }
				{
					int c = getc_raw(st);
					char ch;
					if (c < 0) break;
					ch = (char)c;
					out_put(st, buf, &ch, 1);
				}
			}
			continue;
		}

		if (peek_match(st, st->lq)) {
			read_quoted_into(st, buf);
			continue;
		}

		{
			int c = getc_raw(st);
			if (c < 0) return 0;
			if (in_arg && !depth && c == ',') return ',';
			if (in_arg && !depth && c == ')') return ')';
			if (c == '(') { depth++; { char ch = (char)c; out_put(st, buf, &ch, 1); } continue; }
			if (c == ')') { depth--; { char ch = (char)c; out_put(st, buf, &ch, 1); } continue; }
			if (is_namestart(c)) {
				char wbuf[256];
				int wlen = 0;
				struct m4_macro *m;
				wbuf[wlen++] = (char)c;
				for (;;) {
					int c2 = getc_raw(st);
					if (c2 < 0) break;
					if (!is_namechar(c2)) { ungetc_raw(st, c2); break; }
					if (wlen < (int)sizeof(wbuf) - 1) wbuf[wlen++] = (char)c2;
				}
				wbuf[wlen] = 0;
				m = lookup(st, wbuf);
				if (m && m->top) dispatch_macro(st, m, wbuf);
				else out_put(st, buf, wbuf, (size_t)wlen);
				continue;
			}
			{ char ch = (char)c; out_put(st, buf, &ch, 1); }
		}
	}
}

static char **collect_args(struct m4_state *st, int *out_nargs)
{
	char **args = NULL;
	size_t cap = 0, n = 0;

	for (;;) {
		struct m4_strbuf b;
		int term;
		if (st->exit_pending) break;
		skip_ws(st);
		memset(&b, 0, sizeof b);
		term = scan(st, &b, 1);
		if (n >= cap) {
			size_t newcap;
			char **g;
			if (!__util_array_capacity(cap, n, 1, 8, sizeof(char *), &newcap)) { free(b.data); st->had_error = 1; break; }
			g = __util_reallocarray(args, newcap, sizeof(char *));
			if (!g) { free(b.data); st->had_error = 1; break; }
			args = g; cap = newcap;
		}
		args[n++] = strbuf_finalize(&b);
		if (term == ')' || term == 0 || st->exit_pending) break;
		/* term == ',': loop around to collect the next argument */
	}
	*out_nargs = (int)n;
	return args;
}

static void dispatch_macro(struct m4_state *st, struct m4_macro *m, const char *name)
{
	struct m4_macro_def *def = m->top;
	if (!def) return;

	/* M4_MAX_EXPANSIONS: every macro invocation -- builtin or
	 * user-defined, dnl included -- passes through here exactly once,
	 * so this is the one place a per-run cap on total macro
	 * invocations can live without threading a counter through
	 * scan()/collect_args() by hand.  See the file header, "runaway
	 * expansion is bounded, and why that is not a correctness fix."
	 * st->exit_pending is the SAME cooperative-unwind flag m4exit()
	 * uses (see the header's "exit() / _exit() are never called"
	 * section) -- every loop in scan()/collect_args() already checks
	 * it first thing on every iteration, so setting it here reaches
	 * an ordinary `return status;` at the bottom of
	 * __util_m4_main() exactly the way a real m4exit() would, with no
	 * new unwind path to get wrong. */
	if (++st->expansions > M4_MAX_EXPANSIONS) {
		if (!st->exit_pending)
			__util_diagf("m4: expansion limit exceeded (possible infinite recursion), aborting\n");
		st->had_error = 1;
		st->exit_pending = 1;
		st->exit_code = 1;
		return;
	}

	/* dnl(1p): "discard all input characters up to and including the
	 * next <newline>" -- unconditionally, with no argument-list
	 * syntax at all, so it must never go through collect_args(). */
	if (def->is_builtin && def->builtin_id == BI_DNL) {
		int c;
		if (is_traced(st, name)) trace_print(name, NULL, 0);
		while ((c = getc_raw(st)) >= 0 && c != '\n') { }
		return;
	}

	{
		int c = getc_raw(st);
		char **args = NULL;
		int nargs = 0;
		char *result;

		/* M4_MAX_DEPTH: the OTHER half of the header's "runaway
		 * expansion is bounded" note, and a different dimension from
		 * M4_MAX_EXPANSIONS above -- that counter bounds a LONG FLAT
		 * chain (any number of macro calls, one open at a time,
		 * costing no extra C stack per the file header's "one loop"
		 * description); this one bounds real C-stack depth, which
		 * only grows through THIS call: dispatch_macro() ->
		 * collect_args() -> scan() -> dispatch_macro() again, one
		 * level per open, unmatched '(' in a macro call's own
		 * argument list (`foo(bar(baz(...))))`).  Every one of
		 * POSIX's 32 builtins is predefined from m4_init() before a
		 * byte of input is read, so this recursion needs no prior
		 * define() to reach -- `len(len(len(...)))` alone drives it.
		 * Guarded here, not by a separate parameter threaded through
		 * collect_args()/scan(), so the two functions stay exactly
		 * as the header describes them; only the one call site that
		 * can actually recurse pays for the check. */
		if (c == '(') {
			if (++st->depth > M4_MAX_DEPTH) {
				if (!st->exit_pending)
					__util_diagf("m4: macro calls nested too deeply, aborting\n");
				st->had_error = 1;
				st->exit_pending = 1;
				st->exit_code = 1;
				st->depth--;
				return;
			}
			args = collect_args(st, &nargs);
			st->depth--;
		}
		else if (c >= 0) ungetc_raw(st, c);

		if (st->exit_pending) { free_args(args, nargs); return; }

		if (is_traced(st, name)) trace_print(name, args, nargs);

		if (def->is_builtin) result = call_builtin(st, def->builtin_id, args, nargs);
		else result = build_user_expansion(name, def->text, args, nargs, st);

		free_args(args, nargs);

		if (result) {
			size_t rl = strlen(result);
			if (rl) push_frame(st, result, rl);
			else free(result);
		}
	}
}

/* ==== setup / teardown ========================================================= */

static void m4_init(struct m4_state *st)
{
	int i;
	memset(st, 0, sizeof *st);
	strcpy(st->lq, "`"); strcpy(st->rq, "'");
	st->comment_on = 1;
	strcpy(st->bc, "#"); strcpy(st->ec, "\n");
	st->cur_divert = 0;
	for (i = 0; i < BI_COUNT; i++) define_macro(st, m4_builtin_names[i], 1, i, NULL, 0);
}

static void m4_free(struct m4_state *st)
{
	int i;
	while (st->macros) remove_macro(st, st->macros->name);
	while (st->top) {
		struct m4_frame *f = st->top;
		st->top = f->down;
		free(f->buf); free(f);
	}
	for (i = 1; i <= 9; i++) free(st->div[i].data);
	for (i = 0; i < (int)st->nwraps; i++) free(st->wraps[i]);
	free(st->wraps);
	trace_remove_all(st);
}

/* ==== entry point =============================================================== */

int __util_m4_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	struct m4_state st;
	const char *files[256];
	int nfiles = 0;
	int i;

	m4_init(&st);

	for (i = 1; i < argc; i++) {
		char *a = argv[i];
		if (!strcmp(a, "--")) { i++; break; }
		if (a[0] != '-' || a[1] == 0) break;

		if (a[1] == 's' && a[2] == 0) continue; /* accepted, ignored -- see header comment */

		if (a[1] == 'D') {
			const char *val, *eq;
			char namebuf[256];
			size_t namelen;
			if (a[2]) val = a + 2;
			else {
				if (++i >= argc) { __util_diagf("m4: -D: option requires an argument\n"); m4_free(&st); return 2; }
				val = argv[i];
			}
			eq = strchr(val, '=');
			namelen = eq ? (size_t)(eq - val) : strlen(val);
			if (!namelen || namelen >= sizeof namebuf) {
				__util_diagf("m4: -D: %s: invalid name\n", val);
				m4_free(&st); return 2;
			}
			for (size_t j = 0; j < namelen; j++) namebuf[j] = val[j];
			namebuf[namelen] = 0;
			define_macro(&st, namebuf, 0, 0, eq ? eq + 1 : "", 0);
			continue;
		}

		if (a[1] == 'U') {
			const char *val;
			if (a[2]) val = a + 2;
			else {
				if (++i >= argc) { __util_diagf("m4: -U: option requires an argument\n"); m4_free(&st); return 2; }
				val = argv[i];
			}
			remove_macro(&st, val);
			continue;
		}

		__util_diagf("m4: -%c: invalid option\n", a[1]);
		m4_free(&st);
		return 2;
	}

	for (; i < argc; i++) {
		if (nfiles >= (int)(sizeof files / sizeof files[0])) {
			__util_diagf("m4: too many file operands\n");
			m4_free(&st);
			return 2;
		}
		files[nfiles++] = argv[i];
	}

	if (!nfiles) {
		char *buf; size_t len;
		if (slurp(stdin, &buf, &len) < 0) { __util_diagf("m4: stdin: read error\n"); st.had_error = 1; }
		else push_frame(&st, buf, len);
	} else {
		char *bufs[256]; size_t lens[256];
		int fi;
		for (fi = 0; fi < nfiles; fi++) {
			FILE *f;
			int is_stdin = !strcmp(files[fi], "-");
			bufs[fi] = NULL; lens[fi] = 0;
			f = is_stdin ? stdin : fopen(files[fi], "rb");
			if (!f) {
				__util_diagf("m4: %s: %s\n", files[fi], strerror(errno));
				st.had_error = 1;
				continue;
			}
			if (slurp(f, &bufs[fi], &lens[fi]) < 0) {
				__util_diagf("m4: %s: read error\n", files[fi]);
				st.had_error = 1;
				bufs[fi] = NULL;
			}
			if (!is_stdin) (void)fclose(f);
		}
		for (fi = nfiles - 1; fi >= 0; fi--)
			if (bufs[fi]) push_frame(&st, bufs[fi], lens[fi]);
	}

	scan(&st, NULL, 0);

	/* m4wrap(): text saved by calls made anywhere during the run above
	 * is processed, in call order, once true end-of-input is reached;
	 * m4wrap() called while processing wrap text can append further
	 * text, which this loop picks up naturally by re-checking nwraps
	 * each iteration; an m4exit() reached in here stops promptly. */
	while (!st.exit_pending && st.wrap_pos < st.nwraps) {
		char *w = st.wraps[st.wrap_pos];
		st.wraps[st.wrap_pos] = NULL;
		st.wrap_pos++;
		push_frame(&st, w, strlen(w));
		scan(&st, NULL, 0);
	}

	/* End-of-input diversion flush: always to real stdout, always
	 * performed regardless of how this run ended -- see header comment. */
	for (i = 1; i <= 9; i++) {
		if (st.div[i].len) {
			__ownership_readable_span(st.div[i].data, st.div[i].len);
			if (fwrite(st.div[i].data, 1, st.div[i].len, stdout) != st.div[i].len) st.had_error = 1;
			st.div[i].len = 0;
		}
	}

	if (fflush(stdout) != 0) st.had_error = 1;

	{
		int code;
		if (st.exit_pending) code = st.exit_code;
		else if (st.had_error) code = 1;
		else code = 0;
		m4_free(&st);
		return code;
	}
}
