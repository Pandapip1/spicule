/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * awk's own lexer -- see src/util/awk_priv.h for the token/lexer types
 * and src/util/awk.c for the XCU awk(1p) citations this whole utility
 * follows.
 *
 * NEWLINE HANDLING: this lexer emits a real T_NEWLINE for every
 * physical newline outside a string/ERE literal (a backslash-newline
 * pair is a line continuation and produces no token at all -- XCU
 * awk(1p)'s own "a <backslash> character shall ... continue" rule).
 * Deciding which newlines terminate a statement and which are just
 * filler is the parser's job (its skip_newlines(), called at the
 * grammar's own `opt_nls` points) -- see awk_priv.h's own struct
 * awk_lexer comment for why that split is deliberate.
 *
 * NUMBER LITERALS: decimal only -- digits, an optional '.', more
 * digits, an optional exponent ([eE][+-]?digits). No hex float
 * literals (a from-scratch manual scan, not strtod() on the raw
 * remaining buffer, is exactly what keeps "0x1" from being consumed
 * as a C99 hex float the way glibc's strtod() would: this scanner
 * only ever recognizes the decimal grammar above, so "0x1" lexes as
 * NUMBER 0 followed by NAME "x1" -- see src/util/awk.c's header for
 * this recorded as a deliberate narrowing, not an oversight).
 *
 * STRING LITERAL ESCAPES: \\ \" \/ \a \b \f \n \r \t \v and \ddd (one
 * to three octal digits) -- XCU awk(1p)'s own table. An unrecognized
 * \X is left as both characters, literally, the same "don't silently
 * eat it" choice src/util/util_printf.c's format_escape() documents
 * for printf(1p)'s own \-table.
 *
 * ERE LITERAL SCANNING: reads up to an unescaped '/', treating a `\/`
 * as an escaped delimiter (unwrapped to a literal '/' in the ERE text
 * handed to regcomp() -- POSIX ERE itself has no meaning for `\/`, so
 * leaving the backslash in would just be a stray escape regcomp()
 * would have to tolerate) and otherwise copying every other `\X`
 * through untouched (those are real ERE escapes, e.g. `\.` `\(`,
 * regcomp()'s to interpret, not this lexer's). A `[...]` bracket
 * expression is tracked separately while scanning: '/' is never a
 * delimiter inside one (real ERE bracket expressions can contain a
 * literal '/'), and a ']' immediately after `[` or `[^` is the
 * bracket's own "first character is a literal ]" rule, not its close.
 */
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "awk_priv.h"
#include "ownership_stubs.h"
#include "util.h"

struct kw { const char *name; enum awk_toktype type; };
static const struct kw keywords[] = {
	{ "BEGIN", T_BEGIN }, { "END", T_END }, { "function", T_FUNCTION },
	{ "if", T_IF }, { "else", T_ELSE }, { "while", T_WHILE },
	{ "for", T_FOR }, { "do", T_DO }, { "break", T_BREAK },
	{ "continue", T_CONTINUE }, { "next", T_NEXT }, { "exit", T_EXIT },
	{ "return", T_RETURN }, { "delete", T_DELETE }, { "in", T_IN },
	{ "getline", T_GETLINE }, { "print", T_PRINT }, { "printf", T_PRINTF },
};

/* XCU awk(1p)'s BUILTIN_FUNC_NAME set: every mandatory built-in that is
 * called like a function (print/printf/getline are keywords instead,
 * handled by the table above -- and close/system, while ordinary
 * function-call syntax, are just ordinary names here too, indistinct
 * from a user function of the same name until the parser resolves a
 * call by looking one up first). tolower/toupper are XCU awk(1p)'s
 * own mandatory string functions, not an extension -- included here
 * on that basis, not as a bonus. */
static const char *const builtins[] = {
	"length", "substr", "index", "split", "sub", "gsub", "match",
	"sprintf", "sin", "cos", "atan2", "exp", "log", "sqrt", "int",
	"rand", "srand", "tolower", "toupper", "close", "system", NULL
};

int awk_is_builtin_name(const char *s)
{
	int i;
	for (i = 0; builtins[i]; i++) if (!strcmp(builtins[i], s)) return 1;
	return 0;
}

void awk_lex_init(struct awk_lexer *lx, const char *src)
{
	memset(lx, 0, sizeof *lx);
	lx->src = src;
	lx->len = strlen(src);
	lx->prevtype = T_NEWLINE; /* start-of-program: '/' means ERE, same as after any statement terminator */
}

static int peekc(struct awk_lexer *lx) { return lx->pos < lx->len ? (unsigned char)lx->src[lx->pos] : -1; }
static int peekc2(struct awk_lexer *lx) { return lx->pos + 1 < lx->len ? (unsigned char)lx->src[lx->pos + 1] : -1; }
static int getc_(struct awk_lexer *lx) { return lx->pos < lx->len ? (unsigned char)lx->src[lx->pos++] : -1; }

static void lex_err(struct awk_lexer *lx, const char *msg)
{
	lx->err = 1;
	snprintf(lx->errmsg, sizeof lx->errmsg, "%s", msg);
}

/* Skips spaces/tabs, comments (# to end of line), and backslash-
 * newline continuations. Stops at a real newline, EOF, or the start of
 * a token -- it does not consume the newline itself, since that is a
 * real token this lexer returns. */
static void skip_filler(struct awk_lexer *lx)
{
	for (;;) {
		int c = peekc(lx);
		if (c == ' ' || c == '\t' || c == '\r') { lx->pos++; continue; }
		if (c == '#') { while (peekc(lx) != -1 && peekc(lx) != '\n') lx->pos++; continue; }
		if (c == '\\' && peekc2(lx) == '\n') { lx->pos += 2; continue; }
		/* A backslash-CRLF continuation, for a program file with DOS
		 * line endings. */
		if (c == '\\' && peekc2(lx) == '\r' && lx->pos + 2 < lx->len && lx->src[lx->pos + 2] == '\n') { lx->pos += 3; continue; }
		break;
	}
}

static char *dupn(const char *s, size_t n)
{
	char *r;
	size_t bytes;
	if (!__util_size_add(n, 1, &bytes)) return NULL;
	r = malloc(bytes);
	if (!r) return NULL;
	__ownership_readable_span(s, n);
	memcpy(r, s, n);
	r[n] = 0;
	return r;
}

/* Grows *buf and *cap by at least one byte for *n to write into; returns 0
 * on allocation failure (buffer left usable, just not grown). */
static int growbuf(char **buf, size_t *cap, size_t n)
{
	{
		size_t need, newcap;
		char *g;
		if (!__util_size_add(n, 1, &need)) return 0;
		if (need <= *cap) return 1;
		newcap = *cap ? *cap : 32;
		while (newcap < need) {
			if (!__util_size_mul(newcap, 2, &newcap)) return 0;
		}
		g = realloc(*buf, newcap);
		if (!g) return 0;
		*buf = g;
		*cap = newcap;
	}
	return 1;
}

/* Appends one byte to *buf (growing it via growbuf() as needed),
 * setting a lexer error on allocation failure. Returns 1 on success, 0
 * on failure -- the caller's own job on failure is just to free(*buf)
 * and return 0, since growbuf() leaves *buf usable but un-grown rather
 * than freeing it itself. Folds the "grow, then on success write one
 * byte" pairing that scan_string()/scan_ere() below would otherwise
 * repeat at every one of their own append sites. */
static int scan_putc(struct awk_lexer *lx, char **buf, size_t *cap, size_t *n, char c)
{
	if (!growbuf(buf, cap, *n + 1)) { lex_err(lx, "awk: out of memory"); return 0; }
	(*buf)[(*n)++] = c;
	return 1;
}

static int scan_number(struct awk_lexer *lx, struct awk_token *out)
{
	size_t start = lx->pos;
	int saw_digit = 0;
	char small[64];
	size_t n;

	while (isdigit((unsigned char)peekc(lx))) { lx->pos++; saw_digit = 1; }
	if (peekc(lx) == '.') {
		lx->pos++;
		while (isdigit((unsigned char)peekc(lx))) { lx->pos++; saw_digit = 1; }
	}
	if (!saw_digit) { lx->pos = start; return 0; }
	if ((peekc(lx) == 'e' || peekc(lx) == 'E')) {
		size_t save = lx->pos;
		lx->pos++;
		if (peekc(lx) == '+' || peekc(lx) == '-') lx->pos++;
		if (isdigit((unsigned char)peekc(lx))) {
			while (isdigit((unsigned char)peekc(lx))) lx->pos++;
		} else {
			lx->pos = save; /* "1e" with no exponent digits: not part of the number */
		}
	}
	n = lx->pos - start;
	if (n >= sizeof small) n = sizeof small - 1;
	__ownership_writable_span(small, n);
	__ownership_readable_span(lx->src + start, n);
	memcpy(small, lx->src + start, n);
	small[n] = 0;
	out->type = T_NUMBER;
	out->num = strtod(small, NULL);
	out->text = NULL;
	return 1;
}

static int scan_string(struct awk_lexer *lx, struct awk_token *out)
{
	char *buf = NULL;
	size_t cap = 0, n = 0;

	lx->pos++; /* opening '"' */
	for (;;) {
		int c = getc_(lx);
		if (c == -1 || c == '\n') { lex_err(lx, "awk: unterminated string literal"); free(buf); return 0; }
		if (c == '"') break;
		if (c == '\\') {
			int e = getc_(lx);
			int val = -1;
			switch (e) {
			case '\\': val = '\\'; break;
			case '"': val = '"'; break;
			case '/': val = '/'; break;
			case 'a': val = '\a'; break;
			case 'b': val = '\b'; break;
			case 'f': val = '\f'; break;
			case 'n': val = '\n'; break;
			case 'r': val = '\r'; break;
			case 't': val = '\t'; break;
			case 'v': val = '\v'; break;
			default:
				if (e >= '0' && e <= '7') {
					int v = e - '0', k;
					for (k = 0; k < 2 && peekc(lx) >= '0' && peekc(lx) <= '7'; k++) v = v * 8 + (getc_(lx) - '0');
					val = v & 0xff;
				}
				break;
			}
			if (val < 0) {
				/* Unrecognized \X: leave both characters, literally. */
				if (!scan_putc(lx, &buf, &cap, &n, '\\')) { free(buf); return 0; }
				if (e == -1) { lex_err(lx, "awk: unterminated string literal"); free(buf); return 0; }
				if (!scan_putc(lx, &buf, &cap, &n, (char)e)) { free(buf); return 0; }
				continue;
			}
			if (!scan_putc(lx, &buf, &cap, &n, (char)val)) { free(buf); return 0; }
			continue;
		}
		if (!scan_putc(lx, &buf, &cap, &n, (char)c)) { free(buf); return 0; }
	}
	if (!growbuf(&buf, &cap, n)) { lex_err(lx, "awk: out of memory"); free(buf); return 0; }
	buf[n] = 0;
	out->type = T_STRING;
	out->text = buf;
	return 1;
}

static int scan_ere(struct awk_lexer *lx, struct awk_token *out)
{
	char *buf = NULL;
	size_t cap = 0, n = 0;
	int in_bracket = 0;

	lx->pos++; /* opening '/' */
	for (;;) {
		int c = getc_(lx);
		if (c == -1 || c == '\n') { lex_err(lx, "awk: unterminated regular expression"); free(buf); return 0; }
		if (c == '/' && !in_bracket) break;
		if (c == '\\') {
			int e = getc_(lx);
			if (e == -1) { lex_err(lx, "awk: unterminated regular expression"); free(buf); return 0; }
			if (e == '/') {
				if (!scan_putc(lx, &buf, &cap, &n, '/')) { free(buf); return 0; }
			} else {
				if (!scan_putc(lx, &buf, &cap, &n, '\\')) { free(buf); return 0; }
				if (!scan_putc(lx, &buf, &cap, &n, (char)e)) { free(buf); return 0; }
			}
			continue;
		}
		if (!in_bracket && c == '[') {
			in_bracket = 1;
			if (!scan_putc(lx, &buf, &cap, &n, (char)c)) { free(buf); return 0; }
			if (peekc(lx) == '^') { if (!scan_putc(lx, &buf, &cap, &n, (char)getc_(lx))) { free(buf); return 0; } }
			if (peekc(lx) == ']') { if (!scan_putc(lx, &buf, &cap, &n, (char)getc_(lx))) { free(buf); return 0; } }
			continue;
		}
		if (in_bracket && c == ']') { in_bracket = 0; }
		if (!scan_putc(lx, &buf, &cap, &n, (char)c)) { free(buf); return 0; }
	}
	if (!growbuf(&buf, &cap, n)) { lex_err(lx, "awk: out of memory"); free(buf); return 0; }
	buf[n] = 0;
	out->type = T_ERE;
	out->text = buf;
	return 1;
}

int awk_lex_next(struct awk_lexer *lx, struct awk_token *out)
{
	int c;

	memset(out, 0, sizeof *out);
	skip_filler(lx);

	c = peekc(lx);
	if (c == -1) { out->type = T_EOF; lx->prevtype = out->type; return 0; }

	if (c == '\n') {
		lx->pos++;
		out->type = T_NEWLINE;
		lx->prevtype = out->type;
		return 0;
	}

	if (isdigit((unsigned char)c) || (c == '.' && isdigit((unsigned char)peekc2(lx)))) {
		if (!scan_number(lx, out)) { lex_err(lx, "awk: malformed number"); return -1; }
		lx->prevtype = out->type;
		return 0;
	}

	if (c == '"') {
		if (!scan_string(lx, out)) return -1;
		lx->prevtype = out->type;
		return 0;
	}

	if (c == '/') {
		int div_ctx;
		switch (lx->prevtype) {
		case T_NUMBER: case T_STRING: case T_NAME: case T_BUILTIN_NAME:
		case T_RPAREN: case T_RBRACKET: case T_INCR: case T_DECR: case T_ERE:
			div_ctx = 1; break;
		default: div_ctx = 0; break;
		}
		if (!div_ctx) {
			if (!scan_ere(lx, out)) return -1;
			lx->prevtype = out->type;
			return 0;
		}
		lx->pos++;
		if (peekc(lx) == '=') { lx->pos++; out->type = T_DIV_ASSIGN; }
		else out->type = T_SLASH;
		lx->prevtype = out->type;
		return 0;
	}

	if (isalpha((unsigned char)c) || c == '_') {
		size_t start = lx->pos;
		size_t i;
		while (isalnum((unsigned char)peekc(lx)) || peekc(lx) == '_') lx->pos++;
		{
			char *name = dupn(lx->src + start, lx->pos - start);
			if (!name) { lex_err(lx, "awk: out of memory"); return -1; }
			for (i = 0; i < sizeof keywords / sizeof keywords[0]; i++) {
				if (!strcmp(keywords[i].name, name)) {
					out->type = keywords[i].type;
					free(name);
					lx->prevtype = out->type;
					return 0;
				}
			}
			if (awk_is_builtin_name(name)) {
				out->type = T_BUILTIN_NAME;
				out->text = name;
				out->adj_lparen = (peekc(lx) == '(');
				lx->prevtype = out->type;
				return 0;
			}
			out->adj_lparen = (peekc(lx) == '(');
			out->type = out->adj_lparen ? T_FUNC_NAME : T_NAME;
			out->text = name;
			lx->prevtype = T_NAME; /* a call/name either way ends a value for '/' purposes */
			return 0;
		}
	}

#define TWO(c1, c2, t) if (c == (c1) && peekc2(lx) == (c2)) { lx->pos += 2; out->type = (t); lx->prevtype = out->type; return 0; }
	TWO('=', '=', T_EQ)
	TWO('!', '=', T_NE)
	TWO('<', '=', T_LE)
	TWO('>', '=', T_GE)
	TWO('>', '>', T_APPEND)
	TWO('!', '~', T_NOMATCH)
	TWO('&', '&', T_AND)
	TWO('|', '|', T_OR)
	TWO('+', '+', T_INCR)
	TWO('-', '-', T_DECR)
	TWO('+', '=', T_ADD_ASSIGN)
	TWO('-', '=', T_SUB_ASSIGN)
	TWO('*', '=', T_MUL_ASSIGN)
	TWO('%', '=', T_MOD_ASSIGN)
	TWO('^', '=', T_POW_ASSIGN)
#undef TWO
	/* '*=' handled above; '**' (a non-POSIX power-operator spelling
	 * some awks accept) is deliberately not recognized -- '^' is the
	 * one XCU awk(1p) defines. */

	lx->pos++;
	switch (c) {
	case '{': out->type = T_LBRACE; break;
	case '}': out->type = T_RBRACE; break;
	case '(': out->type = T_LPAREN; break;
	case ')': out->type = T_RPAREN; break;
	case '[': out->type = T_LBRACKET; break;
	case ']': out->type = T_RBRACKET; break;
	case ';': out->type = T_SEMI; break;
	case ',': out->type = T_COMMA; break;
	case '+': out->type = T_PLUS; break;
	case '-': out->type = T_MINUS; break;
	case '*': out->type = T_STAR; break;
	case '%': out->type = T_PERCENT; break;
	case '^': out->type = T_CARET; break;
	case '=': out->type = T_ASSIGN; break;
	case '<': out->type = T_LT; break;
	case '>': out->type = T_GT; break;
	case '~': out->type = T_MATCH; break;
	case '!': out->type = T_NOT; break;
	case '$': out->type = T_DOLLAR; break;
	case '?': out->type = T_QUESTION; break;
	case ':': out->type = T_COLON; break;
	case '|': out->type = T_PIPE; break;
	default:
		lex_err(lx, "awk: unexpected character in program text");
		return -1;
	}
	lx->prevtype = out->type;
	return 0;
}
