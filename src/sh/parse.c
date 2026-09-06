/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Lexer + recursive-descent parser for the Shell Command Language
 * subset this project implements (XCU chapter 2). No execution here --
 * this file only turns source text into the AST declared in sh.h. See
 * sh.h's header comment for the two deliberate lexical simplifications
 * this makes relative to strict POSIX:
 *
 *  - '|' '&' ';' '<' '>' '(' ')' '{' '}' are always lexed as operator
 *    tokens, never as ordinary word characters, matching
 *    src/wordexp/wordexp.c's existing WRDE_BADCHAR treatment of exactly
 *    this set. Only '!' is recognised as a reserved word by comparing
 *    a WORD token's text, and only in pipeline-start position.
 *  - Word text is kept raw (quotes and backslashes intact) rather than
 *    quote-removed here, so each sh_word.text is exactly the form
 *    wordexp()'s existing scanner already knows how to expand -- the
 *    expansion stage reuses that scanner per word instead of
 *    duplicating quote handling here.
 *
 * Grammar (informal, this project's subset of XCU 2.10.2):
 *   list       := [ NEWLINE... ] andor ( sep andor )* [ sep ]
 *   sep        := ';' | '&' | NEWLINE
 *   andor      := pipeline ( ('&&'|'||') NEWLINE... pipeline )*
 *   pipeline   := ['!'] command ( '|' NEWLINE... command )*
 *   command    := '(' list ')' redir*
 *              |  '{' list '}' redir*
 *              |  simple_command
 *   simple_command := ( assignment | redir )* WORD? ( WORD | redir )*
 *   redir      := [IONUMBER] ('<'|'>'|'>>'|'<&'|'>&'|'<>'|'>|'|'<<'|'<<-') WORD
 *
 * Here-documents (XCU 2.7.4): the body of a '<<'/'<<-' operand is not
 * available where the operator is parsed -- it is the text between the
 * next unescaped newline and a following line consisting solely of the
 * delimiter. The lexer therefore queues a "pending heredoc" per such
 * redirection as it is parsed and drains the queue (reading body lines
 * straight out of the source buffer) the moment it produces the
 * NEWLINE/EOF token that ends the current line, before that token is
 * returned to the parser -- the standard technique for hand-written
 * shell lexers.
 */
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>
#include "libc.h"
#include "sh.h"
#include "ownership_stubs.h"
#include "unsafe_pointer.h"

/* __sh_free_words()/__sh_free_redirs() live in free.c alongside
 * __sh_list_free() (which needs the same logic to free a whole parsed
 * list); declared in sh.h and reused here for cleanup on parse error. */

/* ---- growable buffers --------------------------------------------------- */
struct gbuf { char *d; size_t n, cap; };

static int gbuf_push(struct gbuf *b, char c) __attribute__((nonnull(1)));
static int gbuf_push(struct gbuf *b, char c)
{
	if (b->n == b->cap) {
		char *old = b->d;
		size_t nc, i;
		char *nd;
		if (b->cap) {
			if (!__size_mul_checked(b->cap, 2, &nc)) return -1;
		} else {
			nc = 32;
		}
		nd = __malloc(nc);
		if (!nd) return -1;
		if (old) {
			for (i = 0; i < b->n; i++) nd[i] = old[i];
		}
		__free(old);
		b->d = nd;
		b->cap = nc;
	}
	b->d[b->n++] = c;
	return 0;
}

static int gbuf_push_n(struct gbuf *b, const char *s, size_t n)
    __attribute__((nonnull(2)));
static int gbuf_push_n(struct gbuf *b, const char *s, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) if (gbuf_push(b, s[i])) return -1;
	return 0;
}

static char *xstrndup(const char *s, size_t n)
{
	size_t bytes;
	char *p = __size_add_checked(n, 1, &bytes) ? __malloc(bytes) : 0;
	if (p) {
		/* p's own dynamic extent is already bytes == n + 1 (just
		 * established by the allocation above), which already proves
		 * an n-byte writable span without restating it by hand -- the
		 * manual axiom here was redundant scaffolding. */
		__ownership_readable_span(s, n);
		memcpy(p, s, n);
		p[n] = 0;
	}
	return p;
}

static char *xstrdup(const char *s)
{
	size_t n;
	char *p;
	/* Every call site in this file passes a live WORD token's own
	 * ->text, established null-terminated by scan_word()'s trailing
	 * gbuf_push(&b, 0) -- restate that fact here since the checker
	 * cannot trace it through the struct token field it flows through
	 * (scan_word()'s return -> next_raw_token()'s local tok.text ->
	 * advance()'s p->cur.text) to here. */
	__ownership_string_terminated(s);
	n = strlen(s) + 1;
	p = __malloc(n);
	if (p) {
		memcpy(p, s, n);
	}
	return p;
}

/* ---- word-boundary handling for $(...), ${...} and `...` -------------
 *
 * '(' '{' '`' are otherwise always break/operator characters (see
 * scan_word below), which is wrong the moment they follow an unquoted
 * '$' (command substitution / parameter expansion) or stand alone
 * (old-form command substitution): 2.6.3/2.6.2 make the whole
 * delimited region part of the *word*, not a place token scanning
 * stops. These helpers copy such a region verbatim (still raw,
 * unexpanded -- actually running a substituted command is execute.c's
 * job) into the word buffer, balancing nested delimiters of the same
 * kind and skipping over quoted text inside so an embedded quote
 * containing '(' '{' '`' etc. can't desync the count. Known, accepted
 * gap: a *double*-quoted region inside one of these (e.g. the classic
 * "$(echo "hi")") is not specially handled, since scan_word's Q_DOUBLE
 * state has no matching awareness of command substitution either. */
static int copy_squoted(const char **pp, struct gbuf *b) __attribute__((nonnull(1)));
static int copy_squoted(const char **pp, struct gbuf *b)
{
	const char *p = *pp;
	if (gbuf_push(b, *p)) return -1;
	p++;
	while (*p && *p != '\'') { if (gbuf_push(b, *p)) return -1; p++; }
	if (!*p) return -1;
	if (gbuf_push(b, *p)) return -1;
	p++;
	*pp = p;
	return 0;
}

static int copy_dquoted(const char **pp, struct gbuf *b) __attribute__((nonnull(1)));
static int copy_dquoted(const char **pp, struct gbuf *b)
{
	const char *p = *pp;
	if (gbuf_push(b, *p)) return -1;
	p++;
	while (*p && *p != '"') {
		if (*p == '\\' && p[1]) { if (gbuf_push(b, *p) || gbuf_push(b, p[1])) return -1; p += 2; continue; }
		if (gbuf_push(b, *p)) return -1;
		p++;
	}
	if (!*p) return -1;
	if (gbuf_push(b, *p)) return -1;
	p++;
	*pp = p;
	return 0;
}

/* *pp points at `open` ('(' or '{'). Copies through the matching
 * `close`, tracking nesting depth and skipping quoted regions, into b
 * (both delimiters included). */
static int copy_balanced(const char **pp, struct gbuf *b, char open, char close)
    __attribute__((nonnull(1)));
static int copy_balanced(const char **pp, struct gbuf *b, char open, char close) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	const char *p = *pp;
	int depth = 1;
	if (gbuf_push(b, *p)) return -1;
	p++;
	while (depth > 0) {
		char c = *p;
		if (!c) return -1;
		if (c == '\\' && p[1]) { if (gbuf_push(b, c) || gbuf_push(b, p[1])) return -1; p += 2; continue; }
		if (c == '\'') { if (copy_squoted(&p, b)) return -1; continue; }
		if (c == '"') { if (copy_dquoted(&p, b)) return -1; continue; }
		if (c == open) depth++;
		else if (c == close) depth--;
		if (gbuf_push(b, c)) return -1;
		p++;
	}
	*pp = p;
	return 0;
}

/* *pp points at the opening '`'. Copies through the matching closing
 * '`' (old-form command substitution does not nest), into b. */
static int copy_backquoted(const char **pp, struct gbuf *b) __attribute__((nonnull(1)));
static int copy_backquoted(const char **pp, struct gbuf *b)
{
	const char *p = *pp;
	if (gbuf_push(b, *p)) return -1;
	p++;
	while (*p && *p != '`') {
		if (*p == '\\' && p[1]) { if (gbuf_push(b, *p) || gbuf_push(b, p[1])) return -1; p += 2; continue; }
		if (gbuf_push(b, *p)) return -1;
		p++;
	}
	if (!*p) return -1;
	if (gbuf_push(b, *p)) return -1;
	p++;
	*pp = p;
	return 0;
}

/* ---- tokens --------------------------------------------------------------*/
enum tok_type {
	T_WORD, T_IONUM,
	T_PIPE, T_AND, T_OR, T_SEMI, T_AMP,
	T_LPAREN, T_RPAREN, T_LBRACE, T_RBRACE,
	T_LESS, T_GREAT, T_DGREAT, T_LESSAND, T_GREATAND,
	T_LESSGREAT, T_CLOBBER, T_DLESS, T_DLESSDASH,
	T_NEWLINE, T_EOF, T_ERROR
};

struct token {
	enum tok_type type;
	char *text;   /* T_WORD: raw word text, __malloc'd, owned by caller */
	int ionum;    /* T_IONUM: the parsed value */
	/* Where this token begins in the source `__sh_parse()` was handed.
	 * Only function definitions need it -- func_text must be an exact
	 * substring of the program, delimited by the token *after* the body
	 * (which can be any of them), so every token records this. */
	const char *start;
};

static int is_redir_op(enum tok_type t)
{
	switch (t) {
	case T_LESS: case T_GREAT: case T_DGREAT: case T_LESSAND:
	case T_GREATAND: case T_LESSGREAT: case T_CLOBBER:
	case T_DLESS: case T_DLESSDASH:
		return 1;
	default:
		return 0;
	}
}

/* ---- lexer ---------------------------------------------------------------*/
struct pending_hd {
	struct sh_redir *redir;
	int dash;
	struct pending_hd *next;
};

struct lexer {
	const char *p;
	const char *tokstart;   /* where the token being returned began */
	struct pending_hd *pending_head, *pending_tail;
	/* Bumped once per "<<"/"<<-" redirection registered, never
	 * decremented (unlike pending_head/pending_tail). parse_funcdef()
	 * needs "did the body contain a here-document at all", which
	 * pending_head can't answer once drained by the newline ending the
	 * body's line. */
	unsigned long hd_seen;
	int err;
	char errbuf[256];
	size_t errbuflen;
};

static void format_parse_error(char *dst, size_t size, const char *fmt, va_list ap)
{
	static const char fallback[] = "could not format parse error";
	int n = vsnprintf(dst, size, fmt, ap);
	if (n < 0 && size) {
		size_t copy = sizeof fallback < size ? sizeof fallback : size;
		__ownership_writable_span(dst, copy - 1);
		memcpy(dst, fallback, copy - 1);
		dst[copy - 1] = 0;
	}
}

static void lex_errf(struct lexer *lx, const char *fmt, ...) __attribute__((nonnull(1)));
static void lex_errf(struct lexer *lx, const char *fmt, ...)
{
	va_list ap;
	if (!lx->err && lx->errbuflen) {
		va_start(ap, fmt);
		format_parse_error(lx->errbuf, lx->errbuflen, fmt, ap);
		va_end(ap);
	}
	lx->err = 1;
}

/* Quote-removes `raw` (a WORD token's raw text) for use as a heredoc
 * delimiter: strips the ' and " characters and backslash-escapes,
 * exactly the processing XCU 2.7.4 requires before comparing candidate
 * terminator lines. *quoted is set if any quoting/escaping was present
 * at all, which per 2.7.4 disables expansions within the body. */
static char *strip_delim(const char *raw, int *quoted) __attribute__((nonnull(1, 2)));
static char *strip_delim(const char *raw, int *quoted)
{
	struct gbuf b = {0, 0, 0};
	enum { Q_NONE, Q_SINGLE, Q_DOUBLE } q = Q_NONE;
	const char *p = raw;
	*quoted = 0;
	while (*p) {
		char c = *p;
		if (q == Q_NONE) {
			if (c == '\'') { q = Q_SINGLE; *quoted = 1; p++; continue; }
			if (c == '"') { q = Q_DOUBLE; *quoted = 1; p++; continue; }
			if (c == '\\' && p[1]) { *quoted = 1; if (gbuf_push(&b, p[1])) goto oom; p += 2; continue; }
			if (gbuf_push(&b, c)) goto oom;
			p++;
		} else if (q == Q_SINGLE) {
			if (c == '\'') { q = Q_NONE; p++; continue; }
			if (gbuf_push(&b, c)) goto oom;
			p++;
		} else {
			if (c == '"') { q = Q_NONE; p++; continue; }
			if (c == '\\' && p[1] && strchr("\"\\$`", p[1])) { if (gbuf_push(&b, p[1])) goto oom; p += 2; continue; }
			if (gbuf_push(&b, c)) goto oom;
			p++;
		}
	}
	if (gbuf_push(&b, 0)) goto oom;
	/* Restate the trailing NUL gbuf_push(&b, 0) just wrote, the same way
	 * scan_word() does for its own return value: drain_heredocs()'s
	 * immediate strlen(lit) on this exact return value is a separately
	 * analyzed function. */
	__ownership_string_terminated(b.d);
	return b.d;
oom:
	__free(b.d);
	return 0;
}

static int drain_heredocs(struct lexer *lx) __attribute__((nonnull(1)));
static int drain_heredocs(struct lexer *lx)
{
	struct pending_hd *h = lx->pending_head;
	lx->pending_head = lx->pending_tail = 0;
	while (h) {
		struct pending_hd *next = h->next;
		char *lit = strip_delim(h->redir->word, &h->redir->heredoc_quoted);
		size_t litlen;
		struct gbuf body = {0, 0, 0};
		if (!lit) { lex_errf(lx, "out of memory"); __free(h); h = next; continue; }
		/* strip_delim()'s own doc comment: a non-NULL return is a
		 * NUL-terminated delimiter -- restate here for the same reason
		 * scan_word()'s callers do. */
		__ownership_string_terminated(lit);
		litlen = strlen(lit);
		for (;;) {
			const char *line = lx->p;
			const char *eol = line;
			const char *cmp;
			size_t linelen, cmplen;
			while (*eol && *eol != '\n') eol++;
			linelen = (size_t)(eol - line);
			cmp = line; cmplen = linelen;
			if (h->dash) while (cmplen && *cmp == '\t') { cmp++; cmplen--; }
			if (cmplen == litlen) {
				__ownership_readable_span(cmp, litlen);
				__ownership_readable_span(lit, litlen);
				if (memcmp(cmp, lit, litlen) == 0) {
					lx->p = (*eol == '\n') ? eol + 1 : eol;
					break;
				}
			}
			if (!*eol) {
				lex_errf(lx, "unexpected EOF while looking for matching `%s'", lit);
				__free(lit);
				__free(body.d);
				__free(h);
				while (next) { struct pending_hd *n2 = next->next; __free(next); next = n2; }
				return -1;
			}
			if (gbuf_push_n(&body, h->dash ? cmp : line, h->dash ? cmplen : linelen) ||
			    gbuf_push(&body, '\n')) {
				lex_errf(lx, "out of memory");
				__free(lit); __free(body.d); __free(h);
				return -1;
			}
			lx->p = eol + 1;
		}
		if (gbuf_push(&body, 0)) { lex_errf(lx, "out of memory"); __free(lit); __free(body.d); __free(h); return -1; }
		h->redir->heredoc = body.d;
		h->redir->heredoc_delim = lit;
		__free(h);
		h = next;
	}
	return 0;
}

static void discard_heredocs(struct lexer *lx) __attribute__((nonnull(1)));
static void discard_heredocs(struct lexer *lx)
{
	struct pending_hd *h = lx->pending_head;
	while (h) {
		struct pending_hd *next = h->next;
		__free(h);
		h = next;
	}
	lx->pending_head = lx->pending_tail = 0;
}

/* Scans one WORD starting at lx->p (which must not currently be blank,
 * newline, EOF, comment-start or an operator character). Advances
 * lx->p past it. Returns the raw text (quotes/backslashes intact),
 * NUL-terminated, or NULL on OOM/unterminated-quote (lx->err is set
 * either way it fails). */
static char *scan_word(struct lexer *lx) __attribute__((nonnull(1)));
static char *scan_word(struct lexer *lx)
{
	struct gbuf b = {0, 0, 0};
	enum { Q_NONE, Q_SINGLE, Q_DOUBLE } q = Q_NONE;
	const char *p = lx->p;
	for (;;) {
		char c = *p;
		if (q == Q_NONE) {
			if (c == 0 || c == '\n' || c == ' ' || c == '\t' || strchr("|&;()<>{}", c)) break;
			if (c == '\\' && p[1] == '\n') { p += 2; continue; }
			if (c == '\\') {
				if (!p[1]) { lex_errf(lx, "backslash at end of input"); goto fail; }
				if (gbuf_push(&b, '\\') || gbuf_push(&b, p[1])) goto oom;
				p += 2;
				continue;
			}
			if (c == '\'') { if (gbuf_push(&b, c)) goto oom; q = Q_SINGLE; p++; continue; }
			if (c == '"') { if (gbuf_push(&b, c)) goto oom; q = Q_DOUBLE; p++; continue; }
			if (c == '$' && (p[1] == '(' || p[1] == '{')) {
				char open = p[1], close = (open == '(') ? ')' : '}';
				if (gbuf_push(&b, '$')) goto oom;
				p++;
				if (copy_balanced(&p, &b, open, close)) {
					lex_errf(lx, open == '(' ? "unterminated $(...)" : "unterminated ${...}");
					goto fail;
				}
				continue;
			}
			if (c == '`') {
				if (copy_backquoted(&p, &b)) { lex_errf(lx, "unterminated `...`"); goto fail; }
				continue;
			}
			if (gbuf_push(&b, c)) goto oom;
			p++;
		} else if (q == Q_SINGLE) {
			if (c == 0) { lex_errf(lx, "unterminated single-quoted string"); goto fail; }
			if (gbuf_push(&b, c)) goto oom;
			p++;
			if (c == '\'') q = Q_NONE;
		} else {
			if (c == 0) { lex_errf(lx, "unterminated double-quoted string"); goto fail; }
			if (c == '\\' && p[1] && strchr("\"\\$`\n", p[1])) {
				if (gbuf_push(&b, '\\') || gbuf_push(&b, p[1])) goto oom;
				p += 2;
				continue;
			}
			if (gbuf_push(&b, c)) goto oom;
			p++;
			if (c == '"') q = Q_NONE;
		}
	}
	lx->p = p;
	if (gbuf_push(&b, 0)) goto oom;
	/* The gbuf_push(&b, 0) just above wrote the trailing NUL this
	 * function's own doc comment promises ("NUL-terminated"); restate
	 * that here since next_raw_token()'s immediate strlen(w) on this
	 * same return value is a different function the checker analyzes
	 * separately. */
	__ownership_string_terminated(b.d);
	return b.d;
oom:
	lex_errf(lx, "out of memory");
fail:
	__free(b.d);
	return 0;
}

static struct token mktok(enum tok_type t) { struct token tok; tok.type = t; tok.text = 0; tok.ionum = 0; tok.start = 0; return tok; }

static struct token next_raw_token(struct lexer *lx) __attribute__((nonnull(1)));
static struct token next_raw_token(struct lexer *lx)
{
	for (;;) {
		char c = lx->p[0];
		if (c == ' ' || c == '\t') { lx->p++; continue; }
		if (c == '\\' && lx->p[1] == '\n') { lx->p += 2; continue; }
		if (c == '#') { while (*lx->p && *lx->p != '\n') lx->p++; continue; }
		/* Past every `continue` above, so lx->p is the first character of
		 * a real token. Recorded on the lexer instead of threaded through
		 * mktok()'s dozen call sites; advance() copies it onto the token. */
		lx->tokstart = lx->p;
		if (c == 0) {
			if (lx->pending_head && drain_heredocs(lx)) return mktok(T_ERROR);
			return mktok(T_EOF);
		}
		if (c == '\n') {
			lx->p++;
			if (lx->pending_head && drain_heredocs(lx)) return mktok(T_ERROR);
			return mktok(T_NEWLINE);
		}
#define OP2(a, b, tt) if (c == (a) && lx->p[1] == (b)) { lx->p += 2; return mktok(tt); }
#define OP3(a, b, cc, tt) if (c == (a) && lx->p[1] == (b) && lx->p[2] == (cc)) { lx->p += 3; return mktok(tt); }
		OP3('<', '<', '-', T_DLESSDASH)
		OP2('<', '<', T_DLESS)
		OP2('<', '&', T_LESSAND)
		OP2('<', '>', T_LESSGREAT)
		OP2('>', '>', T_DGREAT)
		OP2('>', '&', T_GREATAND)
		OP2('>', '|', T_CLOBBER)
		OP2('&', '&', T_AND)
		OP2('|', '|', T_OR)
#undef OP2
#undef OP3
		if (c == '<') { lx->p++; return mktok(T_LESS); }
		if (c == '>') { lx->p++; return mktok(T_GREAT); }
		if (c == '|') { lx->p++; return mktok(T_PIPE); }
		if (c == '&') { lx->p++; return mktok(T_AMP); }
		if (c == ';') { lx->p++; return mktok(T_SEMI); }
		if (c == '(') { lx->p++; return mktok(T_LPAREN); }
		if (c == ')') { lx->p++; return mktok(T_RPAREN); }
		if (c == '{') { lx->p++; return mktok(T_LBRACE); }
		if (c == '}') { lx->p++; return mktok(T_RBRACE); }
		{
			char *w = scan_word(lx);
			struct token tok;
			size_t i, len;
			int alldig;
			if (!w) return mktok(T_ERROR);
			/* scan_word()'s own doc comment: a non-NULL return is
			 * "NUL-terminated" -- restate that here since a fact
			 * established inside a separately analyzed callee's own
			 * body does not itself cross back into this function. */
			__ownership_string_terminated(w);
			len = strlen(w);
			alldig = len > 0;
			for (i = 0; i < len; i++) if (!isdigit((unsigned char)w[i])) { alldig = 0; break; }
			if (alldig && (*lx->p == '<' || *lx->p == '>')) {
				/* 2.10.1 puts no length limit on an IO_NUMBER, but the value
				 * has to fit a redirection's `fd`, an int. Accumulating it
				 * unchecked was signed overflow (UB); the multiply is
				 * guarded and an out-of-range digit string is diagnosed
				 * here rather than wrapped or demoted to a WORD (which
				 * would turn "2147483648<x" into a command *named*
				 * 2147483648, a different program). */
				int v = 0, ovf = 0;
				for (i = 0; i < len; i++) {
					int d = w[i] - '0';
					if (v > (INT_MAX - d) / 10) { ovf = 1; break; }
					v = v * 10 + d;
				}
				if (ovf) {
					lex_errf(lx, "file descriptor number too large: %s", w);
					__free(w);
					return mktok(T_ERROR);
				}
				__free(w);
				tok = mktok(T_IONUM);
				tok.ionum = v;
				return tok;
			}
			tok = mktok(T_WORD);
			tok.text = w;
			return tok;
		}
	}
}

/* ---- parser ----------------------------------------------------------- */
struct parser {
	struct lexer lx;
	struct token cur;
	int had_error;
};

static void advance(struct parser *p) __attribute__((nonnull(1)));
static void advance(struct parser *p)
{
	if (p->cur.type == T_WORD) { __free(p->cur.text); p->cur.text = 0; }
	if (p->had_error) {
		/* Leaving p->cur as a T_WORD whose text was just freed and NULLed
		 * would arm a null dereference for any caller (is_resword(),
		 * is_name(), xstrdup(), ...) that inspects the token before
		 * checking had_error. Handing back T_ERROR keeps that invariant
		 * true at the source instead of relying on every caller to check
		 * first. */
		p->cur = mktok(T_ERROR);
		return;
	}
	p->cur = next_raw_token(&p->lx);
	p->cur.start = p->lx.tokstart;
	if (p->cur.type == T_ERROR) p->had_error = 1;
}

/* p is required: `if (!p->had_error)` is this function's first
 * statement. fmt is left unmarked, same reasoning as lex_errf() above. */
static void perr(struct parser *p, const char *fmt, ...) __attribute__((nonnull(1)));
static void perr(struct parser *p, const char *fmt, ...)
{
	va_list ap;
	if (!p->had_error) {
		va_start(ap, fmt);
		format_parse_error(p->lx.errbuf, p->lx.errbuflen, fmt, ap);
		va_end(ap);
	}
	p->had_error = 1;
}

static void skip_newlines(struct parser *p) __attribute__((nonnull(1)));
static void skip_newlines(struct parser *p)
{
	while (!p->had_error && p->cur.type == T_NEWLINE) advance(p);
}

static int is_assignment_word(const char *s) __attribute__((nonnull(1)));
static int is_assignment_word(const char *s)
{
	const char *p = s;
	if (!(isalpha((unsigned char)*p) || *p == '_')) return 0;
	while (isalnum((unsigned char)*p) || *p == '_') p++;
	return p != s && *p == '=';
}

static struct sh_redir *parse_redir(struct parser *p) __attribute__((nonnull(1)));
static struct sh_redir *parse_redir(struct parser *p)
{
	struct sh_redir *r;
	enum sh_redir_op op;
	int fd = -1;

	if (p->cur.type == T_IONUM) { fd = p->cur.ionum; advance(p); }
	switch (p->cur.type) {
	case T_LESS: op = SH_R_LESS; break;
	case T_GREAT: op = SH_R_GREAT; break;
	case T_DGREAT: op = SH_R_DGREAT; break;
	case T_LESSAND: op = SH_R_LESSAND; break;
	case T_GREATAND: op = SH_R_GREATAND; break;
	case T_LESSGREAT: op = SH_R_LESSGREAT; break;
	case T_CLOBBER: op = SH_R_CLOBBER; break;
	case T_DLESS: op = SH_R_DLESS; break;
	case T_DLESSDASH: op = SH_R_DLESSDASH; break;
	default: perr(p, "expected a redirection operator"); return 0;
	}
	advance(p);
	if (p->had_error) return 0;
	if (p->cur.type != T_WORD) { perr(p, "expected a word after redirection operator"); return 0; }

	r = __malloc(sizeof *r);
	if (!r) { perr(p, "out of memory"); return 0; }
	r->op = op;
	r->fd = fd;
	r->word = xstrdup(p->cur.text);
	r->heredoc = 0;
	r->heredoc_delim = 0;
	r->heredoc_quoted = 0;
	r->next = 0;
	if (!r->word) { __free(r); perr(p, "out of memory"); return 0; }

	/* Registered *before* the advance() below: that call is what
	 * fetches the token after the delimiter word, and if that token
	 * is the newline ending this line, it is what triggers
	 * drain_heredocs() -- the queue has to already hold this entry
	 * when that happens, not be populated after the fact. */
	if (op == SH_R_DLESS || op == SH_R_DLESSDASH) {
		struct pending_hd *h = __malloc(sizeof *h);
		if (!h) { perr(p, "out of memory"); __free(r->word); __free(r); return 0; }
		h->redir = r;
		h->dash = (op == SH_R_DLESSDASH);
		h->next = 0;
		if (p->lx.pending_tail) p->lx.pending_tail->next = h; else p->lx.pending_head = h;
		p->lx.pending_tail = h;
		p->lx.hd_seen++;
	}
	advance(p);
	return r;
}

/* ---- compound commands (XCU 2.9.4) -----------------------------------
 *
 * `if`, `while`, `until` and `for` all have a reserved word/operator at
 * each end (2.9.4), so the machinery is built once: a set of reserved
 * words that end the compound-list currently being parsed, and one
 * parse_list() that stops on any of them. '(' ')' and '{' '}' become two
 * more bits of the same mask.
 *
 * Reserved words are recognised the same way `!`, `{` and `}` already
 * are: a bare, unquoted WORD token whose text is exactly the word, only
 * where the grammar expects one (XCU 2.10.1 rule 1). Since parse.c keeps
 * word text raw, `"fi"` is the token "\"fi\"" and simply isn't the word
 * `fi`, satisfying 2.10.1's "quoted strings cannot be recognized as
 * reserved words" for free. */
#define ST_RPAREN 0x01
#define ST_RBRACE 0x02
#define ST_THEN   0x04
#define ST_ELIF   0x08   /* `elif`, `else` and `fi` all end a then-part */
#define ST_FI     0x10
#define ST_DO     0x20
#define ST_DONE   0x40

static struct sh_list *parse_list(struct parser *p, unsigned stops);

/* A bare, unquoted WORD token whose text is exactly `w`. Every call site
 * in this file passes a string literal ("if", "then", "!", ...), the
 * same real contract string.h's own strcmp()/strcpy() parameters already
 * assert for a literal argument -- withtok(null_terminated) on `w`
 * states that explicitly instead of relying on each call site's literal
 * being recognised only when it appears directly in a strcmp() call. */
static int is_resword(struct parser *p, const char *w withtok(null_terminated))
    __attribute__((nonnull(1)));
static int is_resword(struct parser *p, const char *w withtok(null_terminated))
{
	if (p->cur.type != T_WORD) return 0;
	/* advance()'s own invariant comment: whenever p->cur.type == T_WORD,
	 * ->text is a live, non-freed WORD text established null-terminated
	 * by scan_word() -- restate that fact here since the checker cannot
	 * trace it through the struct token field it flows through. */
	__ownership_string_terminated(p->cur.text);
	return strcmp(p->cur.text, w) == 0;
}

/* Every call site in this file passes a string literal ("do", "done",
 * "then", "fi"), same as is_resword() itself, whose own withtok(...)
 * this forwards straight through to. */
static int expect_resword(struct parser *p, const char *w withtok(null_terminated))
    __attribute__((nonnull(1)));
static int expect_resword(struct parser *p, const char *w withtok(null_terminated))
{
	if (p->had_error) return -1;
	if (!is_resword(p, w)) {
		perr(p, "expected `%s'", w);
		return -1;
	}
	advance(p);
	return p->had_error ? -1 : 0;
}

static int at_group_stop(struct parser *p, unsigned stops) __attribute__((nonnull(1)));
static int at_group_stop(struct parser *p, unsigned stops)
{
	if (p->cur.type == T_EOF) return 1;
	if ((stops & ST_RPAREN) && p->cur.type == T_RPAREN) return 1;
	if ((stops & ST_RBRACE) && p->cur.type == T_RBRACE) return 1;
	if (p->cur.type != T_WORD) return 0;
	if ((stops & ST_THEN) && is_resword(p, "then")) return 1;
	if ((stops & ST_ELIF) &&
	    (is_resword(p, "elif") || is_resword(p, "else") || is_resword(p, "fi"))) return 1;
	if ((stops & ST_FI) && is_resword(p, "fi")) return 1;
	if ((stops & ST_DO) && is_resword(p, "do")) return 1;
	if ((stops & ST_DONE) && is_resword(p, "done")) return 1;
	return 0;
}

/* Reserved words that can only ever appear *inside* a construct, never at
 * the start of a command. Seeing one in command position (`fi` with no
 * `if`, a `then` already walked past) means the program is malformed --
 * XCU 2.10.1 rule 1 makes it a syntax error rather than a command named
 * "fi". Diagnosing it here keeps script.c's refuse-before-anything-runs
 * property intact for words that, being implemented, aren't on its
 * reserved-word refusal list.
 *
 * `case`/`esac` are deliberately absent: `case` isn't implemented yet, so
 * it still lexes as an ordinary WORD and script.c's preflight refuses it
 * by name instead. */
static const char *const misplaced_reswords[] = {
	"then", "else", "elif", "fi", "do", "done", "in", 0
};

/* Every sh_command allocation goes through here, zeroing the whole union
 * rather than field-by-field: whichever variant a later in-place
 * `c->kind = ...` (SUBSHELL/BRACE/FUNCDEF) switches to, its fields
 * already read as zero without this function needing to know about it. */
static struct sh_command *new_command(struct parser *p, enum sh_cmd_kind kind)
{
	struct sh_command *c = __malloc(sizeof *c);
	if (!c) { perr(p, "out of memory"); return 0; }
	c->kind = kind;
	memset(&c->u, 0, sizeof c->u);
	c->redirs = 0;
	return c;
}

static void free_command(struct sh_command *c)
{
	if (!c) return;
	__sh_free_command_contents(c);
	__free(c);
}

/* XBD Name: "a word consisting solely of underscores, digits, and
 * alphabetics from the portable character set, the first character of
 * which is not a digit" -- XCU 2.10.1's rule 5 ("NAME in for"). */
static int is_name(const char *s) __attribute__((nonnull(1)));
static int is_name(const char *s)
{
	const char *q = s;
	if (!(isalpha((unsigned char)*q) || *q == '_')) return 0;
	for (q++; *q; q++) if (!(isalnum((unsigned char)*q) || *q == '_')) return 0;
	return 1;
}

/* `do compound-list done`, shared by the for/while/until loops -- 2.9.4
 * spells the same two reserved words out for each of the three. */
// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested shell grammar
static struct sh_list *parse_do_group(struct parser *p)
{
	struct sh_list *body;
	skip_newlines(p);
	if (expect_resword(p, "do")) return 0;
	body = parse_list(p, ST_DONE);
	if (p->had_error) { __sh_list_free(body); return 0; }
	if (expect_resword(p, "done")) { __sh_list_free(body); return 0; }
	return body;
}

/* 2.9.4 "The if Conditional Construct":
 *
 *   if compound-list then compound-list
 *   [elif compound-list then compound-list]... [else compound-list] fi
 */
// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested shell grammar
static struct sh_command *parse_if(struct parser *p)
{
	struct sh_command *cmd = new_command(p, SH_CMD_IF);
	struct sh_ifarm *tail = 0;

	if (!cmd) return 0;
	advance(p); /* `if` */
	for (;;) {
		struct sh_ifarm *arm = __malloc(sizeof *arm);
		if (!arm) { perr(p, "out of memory"); goto fail; }
		arm->cond = 0;
		arm->body = 0;
		arm->next = 0;
		if (tail) tail->next = arm; else cmd->u.ifcmd.arms = arm;
		tail = arm;

		arm->cond = parse_list(p, ST_THEN);
		if (p->had_error) goto fail;
		if (expect_resword(p, "then")) goto fail;
		arm->body = parse_list(p, ST_ELIF);
		if (p->had_error) goto fail;

		if (!is_resword(p, "elif")) break;
		advance(p); /* `elif`: same shape as `if`, so loop */
	}
	if (is_resword(p, "else")) {
		advance(p);
		cmd->u.ifcmd.else_body = parse_list(p, ST_FI);
		if (p->had_error) goto fail;
	}
	if (expect_resword(p, "fi")) goto fail;
	return cmd;
fail:
	free_command(cmd);
	return 0;
}

/* 2.9.4 "The while Loop" / "The until Loop" -- identical grammar, and
 * the only difference is the sense of the test, which is one bit on the
 * node rather than a duplicated parser. */
// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested shell grammar
static struct sh_command *parse_loop(struct parser *p, int until)
{
	struct sh_command *cmd = new_command(p, SH_CMD_LOOP);
	if (!cmd) return 0;
	cmd->u.loop.until = until;
	advance(p); /* `while` / `until` */
	cmd->u.loop.cond = parse_list(p, ST_DO);
	if (p->had_error) { free_command(cmd); return 0; }
	cmd->u.loop.body = parse_do_group(p);
	if (p->had_error) { free_command(cmd); return 0; }
	return cmd;
}

/* 2.9.4 "The for Loop", via the 2.10.2 grammar's three for_clause
 * productions:
 *
 *   For name linebreak do_group
 *   For name linebreak in           sequential_sep do_group
 *   For name linebreak in wordlist  sequential_sep do_group
 *
 * The first is 2.9.4's "Omitting: in word ... shall be equivalent to:
 * in "$@"".  It is parsed here and executed by iterating this shell's
 * positional parameters -- see exec_for() in execute.c and
 * src/sh/param.c. */
// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested shell grammar
static struct sh_command *parse_for(struct parser *p)
{
	struct sh_command *cmd = new_command(p, SH_CMD_FOR);
	struct sh_word *wtail = 0;

	if (!cmd) return 0;
	advance(p); /* `for` */
	if (p->cur.type != T_WORD || !is_name(p->cur.text)) {
		perr(p, "expected a variable name after `for'");
		goto fail;
	}
	cmd->u.forloop.name = xstrdup(p->cur.text);
	if (!cmd->u.forloop.name) { perr(p, "out of memory"); goto fail; }
	advance(p);
	skip_newlines(p); /* `linebreak` */

	if (is_resword(p, "in")) {
		advance(p);
		cmd->u.forloop.have_in = 1;
		while (p->cur.type == T_WORD) {
			struct sh_word *w = __malloc(sizeof *w);
			if (!w) { perr(p, "out of memory"); goto fail; }
			w->text = xstrdup(p->cur.text);
			w->next = 0;
			if (!w->text) { __free(w); perr(p, "out of memory"); goto fail; }
			if (wtail) wtail->next = w; else cmd->u.forloop.words = w;
			wtail = w;
			advance(p);
		}
	}
	/* `sequential_sep`: ';' or a newline, either followed by more
	 * newlines.  Also accepted after a bare `for name`, which the
	 * grammar spells as plain `linebreak` but every shell in practice
	 * lets a ';' end. */
	if (p->cur.type == T_SEMI) advance(p);

	cmd->u.forloop.body = parse_do_group(p);
	if (p->had_error) goto fail;
	return cmd;
fail:
	free_command(cmd);
	return 0;
}

static struct sh_command *parse_command(struct parser *p);

/* XCU 2.9.5 "Function Definition Command":
 *
 *   fname ( ) compound-command [ io-redirect ... ]
 *
 * Called with `fname` already consumed and p->cur sitting on the '('.
 * `cmd` is the sh_command the caller already allocated as SH_CMD_SIMPLE;
 * this converts it in place, letting the caller fall through to the
 * ordinary simple-command loop when the lookahead turns out not to be a
 * definition.
 *
 * Two things are checked here rather than deferred:
 *  - fname must not be a special built-in: this has to be a *parse*
 *    error, since 2.9.1 runs special built-ins at step 1a and functions
 *    only at 1c, so an accepted `set() { ... }` could never be called.
 *    A *regular* built-in is fine: 1c beats 1d, so `test() { ... }`
 *    legitimately shadows this shell's `test`.
 *  - the body must be a compound command; 2.9.5's grammar admits nothing
 *    else.
 *
 * The body is captured as the source text between the starting and
 * following token (sh.h's func_text). It's parsed first purely to find
 * that extent, then the AST is thrown away: validating at definition
 * time keeps a syntax error inside a function from surfacing halfway
 * through a build script. */
// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested shell grammar
/* p is always live (every caller in this file threads a real parser
 * through); cmd is always the non-NULL SH_CMD_SIMPLE new_command() just
 * allocated at parse_command()'s only call site below (that site already
 * returns early on `!cmd`); fname is always the WORD text already proven
 * non-NULL by the `is_name(p->cur.text)` check that gated taking this
 * branch, stashed into a local so advance() doesn't free it out from
 * under the caller. */
static struct sh_command *parse_funcdef(struct parser *p, struct sh_command *cmd, char *fname)
    __attribute__((nonnull(1, 2, 3)));
static struct sh_command *parse_funcdef(struct parser *p, struct sh_command *cmd, char *fname)
{
	const struct sh_builtin *bi;
	struct sh_command *body;
	const char *start, *end;
	unsigned long hd0;

	/* Flipped here, before any u.funcdef field is written, since every
	 * `goto fail` between here and the end reaches free_command(), which
	 * must already see the variant whose (possibly still-zero) fields it
	 * will read. */
	cmd->kind = SH_CMD_FUNCDEF;

	advance(p);   /* '(' */
	if (p->cur.type != T_RPAREN) {
		perr(p, "expected `)' in the definition of function `%s'", fname);
		goto fail;
	}
	advance(p);
	skip_newlines(p);   /* 2.10.2's `linebreak` between ')' and the body */
	if (p->had_error) goto fail;

	bi = __sh_builtin_lookup(fname);
	if (bi && bi->special) {
		perr(p, "`%s' is a special built-in and cannot be a function name", fname);
		goto fail;
	}

	if (!(p->cur.type == T_LPAREN || p->cur.type == T_LBRACE ||
	      is_resword(p, "if") || is_resword(p, "while") ||
	      is_resword(p, "until") || is_resword(p, "for"))) {
		perr(p, "the body of function `%s' must be a compound command "
		        "(`{ ... ; }', `( ... )', if/while/until/for)", fname);
		goto fail;
	}

	start = p->cur.start;
	hd0 = p->lx.hd_seen;
	body = parse_command(p);
	if (!body) goto fail;      /* perr() already issued */

	/* The body was parsed to find its extent, and is normally thrown away
	 * here -- but not when it contains a here-document, for two
	 * independent reasons found by fuzz/fuzz_shparse.c that both need it
	 * kept alive:
	 *
	 * 1. Memory safety: a `<<` inside the body registers a pending_hd
	 *    holding a borrowed pointer to that redirection, drained at the
	 *    next <newline> or EOF, not at the end of the body. If the token
	 *    after the body is `|`/`&`/`&&`/`||` instead, the entry is still
	 *    live, and freeing the body here left drain_heredocs() reading
	 *    freed memory (`f()(<<E)&`).
	 * 2. Reprint correctness: when the token after the body IS that
	 *    <newline>/EOF, the peek that finds it also drains the heredoc
	 *    first, so print_command()'s FUNCDEF case reprints func_text
	 *    containing a bare "<<DELIM" with no body/terminator -- those live
	 *    only in the about-to-be-freed redir. Reparsing then swallows
	 *    whatever follows in the enclosing list as the phantom heredoc's
	 *    body (issues #4/#7).
	 *
	 * hd_seen (never decremented, unlike pending_head/pending_tail)
	 * answers "did the body register a here-document at all", which
	 * pending_head can't once case 2 has drained it. Keeping the body
	 * alive fixes both: drain_heredocs() writes into the redir sitting
	 * inside it, so print.c's queue_nested_heredocs_command() finds it
	 * either way. Unchanged in the common case (no here-document): the
	 * body lives in cmd->u.funcdef.func_body until the enclosing sh_list
	 * is freed. */
	if (p->lx.hd_seen != hd0) cmd->u.funcdef.func_body = body;
	else                      free_command(body);
	end = p->cur.start;        /* the token after the body -- T_EOF has
	                            * one too, pointing at the NUL, so there
	                            * is no end-of-input special case */
	/* start and end are both p->cur.start read at two different points
	 * while parsing the same function body (see start's own assignment
	 * above); the invariant that nothing changes what buffer `p`
	 * tokenizes between those two reads lives in the whole recursive-
	 * descent parser's shape, not in any one function's local
	 * reasoning. */
	if (unsafe_assume_shared_provenance(end < start)) end = start;
	while (unsafe_assume_shared_provenance(end > start) &&
	      isspace((unsigned char)end[-1])) end--;

	cmd->u.funcdef.name = fname;
	cmd->u.funcdef.func_text =
	    xstrndup(start, (size_t)unsafe_assume_shared_provenance(end - start));
	if (!cmd->u.funcdef.func_text) { cmd->u.funcdef.name = 0; perr(p, "out of memory"); goto fail; }
	return cmd;
fail:
	__free(fname);
	free_command(cmd);
	return 0;
}

static struct sh_command *parse_command(struct parser *p) __attribute__((nonnull(1)));
// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested shell grammar
static struct sh_command *parse_command(struct parser *p)
{
	struct sh_command *cmd;
	struct sh_redir *rtail = 0;

	/* XCU 2.9.1 decides between a compound command and a simple one on
	 * the *first* token, before any word is collected -- 2.10.1 rule 1:
	 * "when the TOKEN is exactly a reserved word, the token identifier
	 * for that reserved word shall result". */
	if (p->cur.type == T_WORD) {
		size_t i;
		if (is_resword(p, "if")) cmd = parse_if(p);
		else if (is_resword(p, "while")) cmd = parse_loop(p, 0);
		else if (is_resword(p, "until")) cmd = parse_loop(p, 1);
		else if (is_resword(p, "for")) cmd = parse_for(p);
		else {
			/* Same invariant is_resword() itself restates: p->cur.type
			 * == T_WORD here (this whole branch is gated on it above)
			 * means ->text is a live, null-terminated WORD text. */
			__ownership_string_terminated(p->cur.text);
			for (i = 0; misplaced_reswords[i]; i++) {
				/* misplaced_reswords[] is a fixed array of string
				 * literals, but the literal-ness the checker relies
				 * on elsewhere is lost once read back out through an
				 * array index rather than appearing directly in the
				 * call -- restate it the same way. */
				__ownership_string_terminated(misplaced_reswords[i]);
				if (strcmp(p->cur.text, misplaced_reswords[i]) == 0) {
					perr(p, "unexpected reserved word `%s'", misplaced_reswords[i]);
					return 0;
				}
			}
			goto not_compound;
		}
		if (!cmd) return 0;
		goto trailing_redirs;
	}
not_compound:

	cmd = new_command(p, SH_CMD_SIMPLE);
	if (!cmd) return 0;

	if (p->cur.type == T_LPAREN) {
		advance(p);
		/* Flipped before u.group.body is written, same reasoning as
		 * parse_funcdef()'s kind flip. */
		cmd->kind = SH_CMD_SUBSHELL;
		cmd->u.group.body = parse_list(p, ST_RPAREN);
		if (p->had_error) { free_command(cmd); return 0; }
		if (p->cur.type != T_RPAREN) { perr(p, "expected ')'"); free_command(cmd); return 0; }
		advance(p);
	} else if (p->cur.type == T_LBRACE) {
		advance(p);
		cmd->kind = SH_CMD_BRACE;
		cmd->u.group.body = parse_list(p, ST_RBRACE);
		if (p->had_error) { free_command(cmd); return 0; }
		if (p->cur.type != T_RBRACE) { perr(p, "expected '}'"); free_command(cmd); return 0; }
		advance(p);
	} else {
		struct sh_word *atail = 0, *wtail = 0;
		int seen_word = 0;

		/* XCU 2.9.5's one-token lookahead: a NAME followed by '(' at the
		 * start of a command is a function definition, anything else is
		 * that command's first word. No peek() in this parser, so the
		 * word is consumed and stashed (taking ownership of p->cur.text
		 * so advance() doesn't free it), then handed to parse_funcdef()
		 * or pushed onto the word list below. is_name() keeps `X=1 cmd`
		 * and `./cmd` out of this path. */
		if (p->cur.type == T_WORD && is_name(p->cur.text)) {
			char *fname = p->cur.text;
			struct sh_word *w;
			p->cur.text = 0;
			advance(p);
			if (p->had_error) { __free(fname); free_command(cmd); return 0; }
			if (p->cur.type == T_LPAREN)
				return parse_funcdef(p, cmd, fname);
			w = __malloc(sizeof *w);
			if (!w) { __free(fname); perr(p, "out of memory"); goto simple_fail; }
			w->text = fname;
			w->next = 0;
			cmd->u.simple.words = w;
			wtail = w;
			seen_word = 1;
		}

		for (;;) {
			if (p->cur.type == T_IONUM || is_redir_op(p->cur.type)) {
				struct sh_redir *r = parse_redir(p);
				if (!r) goto simple_fail;
				if (rtail) rtail->next = r; else cmd->redirs = r;
				rtail = r;
				continue;
			}
			if (p->cur.type == T_WORD) {
				struct sh_word *w;
				if (!seen_word && is_assignment_word(p->cur.text)) {
					w = __malloc(sizeof *w);
					if (!w) { perr(p, "out of memory"); goto simple_fail; }
					w->text = xstrdup(p->cur.text);
					w->next = 0;
					if (atail) atail->next = w; else cmd->u.simple.assigns = w;
					atail = w;
					advance(p);
					continue;
				}
				seen_word = 1;
				w = __malloc(sizeof *w);
				if (!w) { perr(p, "out of memory"); goto simple_fail; }
				w->text = xstrdup(p->cur.text);
				w->next = 0;
				if (wtail) wtail->next = w; else cmd->u.simple.words = w;
				wtail = w;
				advance(p);
				continue;
			}
			break;
		}
		if (!seen_word && !cmd->u.simple.assigns && !cmd->redirs) {
			perr(p, "expected a command");
			goto simple_fail;
		}
		return cmd;
simple_fail:
		free_command(cmd);
		return 0;
	}

trailing_redirs:
	/* 2.9.4: each construct can be followed by redirections on the same
	 * line as the terminator.
	 *
	 * The failure path frees the whole node through free_command(), not
	 * by hand: `cmd` owns a redirection list this loop is building, and
	 * is reached both from the '(' / '{' branches (group body hangs off
	 * cmd->u.group.body) and from if/while/until/for's `goto
	 * trailing_redirs` (hangs off cmd->u.ifcmd.arms/cmd->u.loop.cond
	 * instead) -- freeing anything narrower would have to enumerate
	 * fields and leak whichever one it missed. test/sh-engine.c's
	 * test_group_redir_leak() is the regression test, caught by
	 * LeakSanitizer under `make asan`. */
	while (p->cur.type == T_IONUM || is_redir_op(p->cur.type)) {
		struct sh_redir *r = parse_redir(p);
		if (!r) { free_command(cmd); return 0; }
		if (rtail) rtail->next = r; else cmd->redirs = r;
		rtail = r;
	}
	return cmd;
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested shell grammar
static int parse_pipeline(struct parser *p, struct sh_pipeline *out)
    __attribute__((nonnull(1, 2)));
// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested shell grammar
static int parse_pipeline(struct parser *p, struct sh_pipeline *out)
{
	struct sh_command *arr = 0;
	size_t n = 0, cap = 0;
	out->bang = 0;
	if (p->cur.type == T_WORD) {
		/* Same invariant is_resword() restates: a live T_WORD's ->text
		 * is null-terminated. */
		__ownership_string_terminated(p->cur.text);
		if (strcmp(p->cur.text, "!") == 0) { out->bang = 1; advance(p); }
	}
	for (;;) {
		struct sh_command *cmd = parse_command(p);
		if (!cmd) goto fail;
		if (n == cap) {
			size_t nc = 4, bytes;
			struct sh_command *na = 0;
			if (!cap || __size_mul_checked(cap, 2, &nc)) {
				na = __size_mul_checked(nc, sizeof *na, &bytes) ?
					__malloc(bytes) : 0;
			}
			if (!na) {
				perr(p, "out of memory");
				__sh_free_command_contents(cmd);
				__free(cmd);
				goto fail;
			}
			if (arr) {
				__ownership_writable_span(na, n * sizeof *na);
				__ownership_readable_span(arr, n * sizeof *na);
				memcpy(na, arr, n * sizeof *na);
			}
			__free(arr);
			arr = na; cap = nc;
		}
		arr[n++] = *cmd;
		__free(cmd);
		if (p->cur.type != T_PIPE) break;
		advance(p);
		skip_newlines(p);
	}
	out->commands = arr;
	out->ncommands = n;
	return 0;
fail:
	{
		size_t i;
		for (i = 0; i < n; i++) __sh_free_command_contents(&arr[i]);
	}
	__free(arr);
	return -1;
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested shell grammar
static struct sh_andor *parse_andor(struct parser *p)
{
	struct sh_andor *head, *tail;
	head = __malloc(sizeof *head);
	if (!head) { perr(p, "out of memory"); return 0; }
	head->op = SH_AO_NONE;
	head->next = 0;
	if (parse_pipeline(p, &head->pipeline)) { __free(head); return 0; }
	tail = head;
	for (;;) {
		enum sh_andor_op op;
		struct sh_andor *node;
		if (p->cur.type == T_AND) op = SH_AO_AND;
		else if (p->cur.type == T_OR) op = SH_AO_OR;
		else break;
		advance(p);
		skip_newlines(p);
		node = __malloc(sizeof *node);
		if (!node) { perr(p, "out of memory"); return head; }
		node->op = op;
		node->next = 0;
		if (parse_pipeline(p, &node->pipeline)) { __free(node); return head; }
		tail->next = node;
		tail = node;
	}
	return head;
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested shell grammar
static struct sh_list *parse_list(struct parser *p, unsigned stops)
{
	struct sh_list *list = __malloc(sizeof *list);
	struct sh_list_item *tail = 0;
	if (!list) { perr(p, "out of memory"); return 0; }
	list->items = 0;
	skip_newlines(p);
	while (!p->had_error && !at_group_stop(p, stops)) {
		struct sh_list_item *item = __malloc(sizeof *item);
		if (!item) { perr(p, "out of memory"); return list; }
		item->andor = parse_andor(p);
		item->next = 0;
		if (!item->andor) { __free(item); return list; }
		if (p->cur.type == T_SEMI || p->cur.type == T_NEWLINE) { item->sep = SH_SEP_SEQ; advance(p); }
		else if (p->cur.type == T_AMP) { item->sep = SH_SEP_AMP; advance(p); }
		else item->sep = SH_SEP_END;
		if (tail) tail->next = item; else list->items = item;
		tail = item;
		if (item->sep == SH_SEP_END) break;
		skip_newlines(p);
	}
	return list;
}

struct sh_list *__sh_parse(const char *src, char *errbuf, size_t errbuflen)
{
	struct parser p;
	struct sh_list *list;

	p.lx.p = src;
	p.lx.tokstart = src;
	p.lx.pending_head = p.lx.pending_tail = 0;
	p.lx.hd_seen = 0;
	p.lx.err = 0;
	p.lx.errbuf[0] = 0;
	p.lx.errbuflen = sizeof p.lx.errbuf;
	p.had_error = 0;
	p.cur = mktok(T_EOF);
	advance(&p);

	list = parse_list(&p, 0);

	if (!p.had_error && p.cur.type != T_EOF) {
		perr(&p, "unexpected token near '%s'", p.cur.type == T_WORD ? p.cur.text : "?");
	}
	if (p.cur.type == T_WORD) __free(p.cur.text);
	discard_heredocs(&p.lx);

	if (p.had_error) {
		if (errbuf && errbuflen) {
			size_t n = strnlen(p.lx.errbuf, sizeof p.lx.errbuf);
			if (n >= errbuflen) n = errbuflen - 1;
			__ownership_writable_span(errbuf, n);
			__ownership_readable_span(p.lx.errbuf, n);
			memcpy(errbuf, p.lx.errbuf, n);
			errbuf[n] = 0;
		}
		__sh_list_free(list);
		return 0;
	}
	return list;
}
