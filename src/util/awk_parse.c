/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * awk's recursive-descent parser, one function per production of XCU
 * awk(1p)'s own grammar (see src/util/awk.c's header for full spec
 * citations). The operator-precedence chain, loosest to tightest, is
 * exactly the table that section's grammar encodes via layered
 * productions: assignment (right-assoc) > ?: (right-assoc) > || > &&
 * > `in` > `~`/`!~` (and, at the same tier, `| getline`) > relational
 * (non-assoc: XCU's grammar has no production chaining two relationals
 * without an explicit && between them, so this parser does not either)
 * > concatenation (a run of adjacent expressions with no operator
 * between them) > additive > multiplicative > unary +/-/! > `^`
 * (right-assoc) > pre/post ++/-- > `$` > primary.
 *
 * CONCATENATION AND UNARY +/-: concatenation's operand set does not
 * include a leading bare +/- (`"a" -1` is subtraction, not `"a"`
 * concatenated with `-1`) because +/- are already consumed one level
 * lower, inside parse_additive()'s own loop, by the time
 * parse_concat() would otherwise see them -- so this parser needs no
 * separate disambiguation rule for it; the precedence layering alone
 * produces the standard behavior every real awk implements.
 *
 * ALLOCATION FAILURE: treated as fatal here (a diagnostic and an unwind
 * via oom() below -- see awk_priv.h's "fatal-error unwind" header
 * comment for why that is awk_unwind_fatal(), not a raw exit(2): this
 * parser can run underneath a no-fork shell built-in via
 * __util_awk_main(), which must survive a fatal parse error, not die
 * with it) rather than threaded back through every one of this file's
 * ~40 mutually-recursive parse_*() functions as a NULL/error return.
 * Every other multi-stage parser in this tree (e.g. src/util/
 * modeparse.c) is small enough that propagating a NULL is cheap; a
 * recursive-descent parser building a whole program's AST is not, and
 * a partially-built tree has no well-defined owner to unwind it
 * through. A real awk program's source text is never so large that
 * this matters in practice.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "awk_priv.h"
#include "util.h"

static void oom(void)
{
	__util_diagf("awk: out of memory\n");
	awk_unwind_fatal();
}

static struct awk_node *mknode(enum awk_ntype type)
{
	struct awk_node *n = calloc(1, sizeof *n);
	if (!n) oom();
	n->type = type;
	return n;
}

static void addlist(struct awk_node ***list, int *n, struct awk_node *item)
{
	struct awk_node **g = __util_reallocarray(*list, (size_t)*n + 1, sizeof **list);
	if (!g) oom();
	*list = g;
	(*list)[*n] = item;
	(*n)++;
}

/* ==== token stream plumbing ============================================= */

static void free_tok_text(struct awk_token *t)
{
	switch (t->type) {
	case T_STRING: case T_ERE: case T_NAME: case T_FUNC_NAME: case T_BUILTIN_NAME:
		free(t->text);
		t->text = NULL;
		break;
	default: break;
	}
}

static void raw_next(struct awk_parser *p, struct awk_token *out)
{
	if (awk_lex_next(&p->lx, out) < 0) {
		if (!p->err) {
			p->err = 1;
			snprintf(p->errmsg, sizeof p->errmsg, "%s", p->lx.errmsg);
		}
		out->type = T_EOF;
	}
}

static void advance(struct awk_parser *p)
{
	free_tok_text(&p->tok);
	if (p->has_tok2) {
		p->tok = p->tok2;
		p->has_tok2 = 0;
	} else {
		raw_next(p, &p->tok);
	}
}

static enum awk_toktype peek2(struct awk_parser *p)
{
	if (!p->has_tok2) {
		raw_next(p, &p->tok2);
		p->has_tok2 = 1;
	}
	return p->tok2.type;
}

static void perr(struct awk_parser *p, const char *msg)
{
	if (p->err) return;
	p->err = 1;
	snprintf(p->errmsg, sizeof p->errmsg, "%s", msg);
}

static int at(struct awk_parser *p, enum awk_toktype t) { return p->tok.type == t; }

static int accept_tok(struct awk_parser *p, enum awk_toktype t)
{
	if (p->tok.type != t) return 0;
	advance(p);
	return 1;
}

static void expect(struct awk_parser *p, enum awk_toktype t, const char *what)
{
	if (p->err) return;
	if (p->tok.type != t) {
		char buf[256];
		snprintf(buf, sizeof buf, "awk: syntax error: expected %s", what);
		perr(p, buf);
		return;
	}
	advance(p);
}

/* `opt_nls` -- see awk_priv.h's struct awk_lexer comment. */
static void skip_newlines(struct awk_parser *p)
{
	while (at(p, T_NEWLINE)) advance(p);
}

static void skip_terminators(struct awk_parser *p)
{
	while (at(p, T_NEWLINE) || at(p, T_SEMI)) advance(p);
}

/* ==== recursion depth guard =============================================
 *
 * This parser has no depth limit on the awk program text itself: a
 * source file is fully attacker-controlled input (a script handed to
 * awk(1p)), and every one of parse_stmt()/parse_primary()/parse_pow()/
 * parse_ternary()/parse_assign() is mutually or directly self-recursive
 * with no base case other than running out of matching tokens. A
 * pathological-but-trivially-constructed program -- a run of N `(`
 * characters, N unary `-`/`!` operators, N `$` indirections, an N-deep
 * `a?a:a?a:...` ternary chain, an N-deep `a=a=...=1` assignment chain,
 * or N nested `{` blocks -- recurses this parser's own C stack N levels
 * deep with no other bound, which is a real stack-overflow crash (not a
 * clean parse error) for a large enough N. Every one of those five
 * shapes is a genuine, unbounded, attacker-reachable recursion vector:
 * XCU awk(1p) sets no nesting limit, but this implementation has to,
 * the same way any recursive-descent parser accepting untrusted text
 * does.
 *
 * AWK_PARSE_MAX_DEPTH is deliberately conservative (not tuned to any
 * one platform's default stack size): each of the five guarded
 * productions above is only ONE of several stack frames a single
 * nesting level actually costs (e.g. one `(` costs a frame in every
 * function between parse_primary() and parse_primary() again --
 * parse_paren_group(), parse_expr(), parse_assign(), parse_ternary(),
 * parse_or(), parse_and(), parse_in(), parse_match(), parse_rel(),
 * parse_concat(), parse_additive(), parse_mul(), parse_unary(),
 * parse_pow() -- most of which are NOT separately guarded because they
 * are not themselves recursive; guarding the five that ARE keeps this
 * count proportional to real stack depth without needing to instrument
 * every production). 200 levels is far beyond any awk program a person
 * would write or a code generator would sanely emit, while staying
 * comfortably inside even a constrained (e.g. 1 MiB) C stack at this
 * project's typical per-frame cost.
 *
 * p->depth is one shared counter, not five separate ones: these five
 * productions can recurse into EACH OTHER (an lvalue's own `(` opens a
 * fresh parse_ternary/parse_assign chain, etc.), so what actually needs
 * bounding is their combined live nesting, not any one production's
 * count in isolation. */
#define AWK_PARSE_MAX_DEPTH 200

/* Call at the top of a guarded production, before it does any of its
 * own (potentially self-recursive) parsing. Returns 1 and bumps
 * p->depth on success; on exceeding the limit, sets a parse error and
 * returns 0 -- callers must not recurse further in that case, just
 * return a harmless placeholder node so the C stack unwinds instead of
 * growing past the point that already tripped this guard. Paired with
 * parse_depth_leave(), called unconditionally on every return path
 * (including the guard's own reject case, which counts itself back out
 * before returning, so a caller that checks the return value need not). */
static int parse_depth_enter(struct awk_parser *p)
{
	if (++p->depth > AWK_PARSE_MAX_DEPTH) {
		p->depth--;
		perr(p, "awk: expression or statement nested too deeply");
		return 0;
	}
	return 1;
}

static void parse_depth_leave(struct awk_parser *p) { p->depth--; }

/* ==== expression grammar ================================================= */

static struct awk_node *parse_expr(struct awk_parser *p);
static struct awk_node *parse_assign(struct awk_parser *p);
static struct awk_node *parse_ternary(struct awk_parser *p);
static struct awk_node *parse_unary(struct awk_parser *p);
static struct awk_node *parse_concat(struct awk_parser *p);
static struct awk_node *parse_primary(struct awk_parser *p);
static struct awk_node *parse_lvalue_from_primary(struct awk_parser *p, struct awk_node *n);
static struct awk_node *parse_stmt(struct awk_parser *p);
static struct awk_node *parse_block(struct awk_parser *p);
static struct awk_node **parse_expr_list(struct awk_parser *p, int *n, int allow_empty);

static int is_lvalue(struct awk_node *n)
{
	return n->type == N_VAR || n->type == N_FIELD || n->type == N_ARRIDX;
}

/* '(' has already been consumed. Parses a comma-separated list; on a
 * single element, returns that element itself (no wrapping -- see the
 * N_ELIST comment in awk_priv.h); on 2+, returns an N_ELIST.
 *
 * suppress_gt (print's "bare '>' is redirection, not comparison" state
 * -- see parse_print_stmt()) is saved and cleared for the parens'
 * whole interior: `print (a > b)` must still parse `>` as a real
 * comparison once it is inside a nested grouping, the same way it
 * would inside a function call's argument list or an array
 * subscript's brackets (parse_expr_list() below does the same
 * save/clear/restore for those two). */
static struct awk_node *parse_paren_group(struct awk_parser *p)
{
	struct awk_node **list = NULL;
	int n = 0;
	struct awk_node *first;
	int saved_gt = p->suppress_gt;

	p->suppress_gt = 0;
	skip_newlines(p);
	first = parse_expr(p);
	addlist(&list, &n, first);
	while (accept_tok(p, T_COMMA)) {
		skip_newlines(p);
		addlist(&list, &n, parse_expr(p));
	}
	skip_newlines(p);
	expect(p, T_RPAREN, "')'");
	p->suppress_gt = saved_gt;
	if (n == 1) { free(list); return first; }
	{
		struct awk_node *e = mknode(N_ELIST);
		e->list = list; e->nlist = n;
		return e;
	}
}

static struct awk_node *parse_getline(struct awk_parser *p, struct awk_node *cmd_or_null, enum awk_getline_src src)
{
	struct awk_node *g = mknode(N_GETLINE);
	g->gl_src = src;
	g->b = cmd_or_null;
	advance(p); /* consume GETLINE */
	if (at(p, T_NAME) || at(p, T_DOLLAR)) {
		struct awk_node *prim = parse_primary(p);
		g->a = parse_lvalue_from_primary(p, prim);
		if (!is_lvalue(g->a)) perr(p, "awk: getline target must be a variable, field, or array element");
	}
	if (src != GL_CMD && at(p, T_LT)) {
		advance(p);
		g->gl_src = GL_FILE;
		g->b = parse_concat(p); /* a filename target may itself be a
		                         * concatenation, e.g. `getline < dir fname` */
	}
	return g;
}

/* file/command targets for `getline < expr` and redirection operands
 * accept concatenation (`"dir/" name`) but not relational/`in`/&&/||
 * -- i.e. the same "concat and tighter" tier used for print's own
 * redirection target. */
static struct awk_node *parse_primary_impl(struct awk_parser *p)
{
	struct awk_node *n;

	switch (p->tok.type) {
	case T_NUMBER:
		n = mknode(N_NUM);
		n->num = p->tok.num;
		advance(p);
		return n;
	case T_STRING:
		n = mknode(N_STR);
		n->str = p->tok.text; p->tok.text = NULL;
		advance(p);
		return n;
	case T_ERE: {
		regex_t *re = malloc(sizeof *re);
		if (!re) oom();
		n = mknode(N_REGEX);
		n->str = p->tok.text; p->tok.text = NULL;
		if (regcomp(re, n->str, REG_EXTENDED) != 0) {
			perr(p, "awk: invalid regular expression");
			free(re);
			n->re = NULL;
		} else {
			n->re = re;
		}
		advance(p);
		return n;
	}
	case T_DOLLAR: {
		struct awk_node *idx;
		advance(p);
		idx = parse_unary(p);
		n = mknode(N_FIELD);
		n->a = idx;
		goto postfix;
	}
	case T_INCR: case T_DECR: {
		int isincr = p->tok.type == T_INCR;
		advance(p);
		{
			struct awk_node *target = parse_unary(p);
			if (!is_lvalue(target)) perr(p, "awk: ++/-- requires a variable, field, or array element");
			n = mknode(isincr ? N_PREINCR : N_PREDECR);
			n->a = target;
			return n;
		}
	}
	case T_NOT: {
		advance(p);
		n = mknode(N_NOT);
		n->a = parse_unary(p);
		return n;
	}
	case T_MINUS: {
		advance(p);
		n = mknode(N_UMINUS);
		n->a = parse_unary(p);
		return n;
	}
	case T_PLUS: {
		advance(p);
		n = mknode(N_UPLUS);
		n->a = parse_unary(p);
		return n;
	}
	case T_LPAREN: {
		advance(p);
		n = parse_paren_group(p);
		/* `(list) in arr` is handled by parse_in(); a bare parenthesized
		 * group used anywhere else just carries on as this primary. */
		goto postfix;
	}
	case T_GETLINE:
		return parse_getline(p, NULL, GL_MAIN);
	case T_BUILTIN_NAME: {
		char *name = p->tok.text; p->tok.text = NULL;
		int had_lparen = p->tok.adj_lparen;
		advance(p);
		n = mknode(N_CALL);
		n->str = name;
		if (had_lparen) {
			advance(p); /* '(' */
			skip_newlines(p);
			if (!at(p, T_RPAREN)) {
				n->list = parse_expr_list(p, &n->nlist, 0);
			}
			skip_newlines(p);
			expect(p, T_RPAREN, "')'");
		} else if (strcmp(name, "length") != 0) {
			perr(p, "awk: built-in function requires '('");
		}
		return n;
	}
	case T_FUNC_NAME: {
		char *name = p->tok.text; p->tok.text = NULL;
		advance(p);
		expect(p, T_LPAREN, "'('");
		n = mknode(N_CALL);
		n->str = name;
		skip_newlines(p);
		if (!at(p, T_RPAREN)) n->list = parse_expr_list(p, &n->nlist, 0);
		skip_newlines(p);
		expect(p, T_RPAREN, "')'");
		return n;
	}
	case T_NAME: {
		char *name = p->tok.text; p->tok.text = NULL;
		advance(p);
		if (at(p, T_LBRACKET)) {
			advance(p);
			n = mknode(N_ARRIDX);
			n->str = name;
			n->list = parse_expr_list(p, &n->nlist, 0);
			expect(p, T_RBRACKET, "']'");
		} else {
			n = mknode(N_VAR);
			n->str = name;
		}
		goto postfix;
	}
	default:
		perr(p, "awk: syntax error: unexpected token");
		return mknode(N_NUM);
	}

postfix:
	if (at(p, T_INCR) || at(p, T_DECR)) {
		if (is_lvalue(n)) {
			int isincr = at(p, T_INCR);
			struct awk_node *w = mknode(isincr ? N_POSTINCR : N_POSTDECR);
			w->a = n;
			advance(p);
			return w;
		}
	}
	return n;
}

/* Guarded per this file's own "recursion depth guard" section above:
 * parse_primary_impl() is the one production every unbounded expression-
 * nesting shape (parens, prefix +/-/!/++/--, `$` chains, function-call/
 * subscript argument lists) recurses back through. */
static struct awk_node *parse_primary(struct awk_parser *p)
{
	struct awk_node *n;
	if (!parse_depth_enter(p)) return mknode(N_NUM);
	n = parse_primary_impl(p);
	parse_depth_leave(p);
	return n;
}

/* After parse_primary() has already produced `n` (used by getline's
 * optional lvalue target, which parses one primary and must reject a
 * non-lvalue result rather than re-deriving it). */
static struct awk_node *parse_lvalue_from_primary(struct awk_parser *p, struct awk_node *n)
{
	(void)p;
	return n;
}

static struct awk_node *parse_pow_impl(struct awk_parser *p)
{
	struct awk_node *l = parse_primary(p);
	if (at(p, T_CARET)) {
		advance(p);
		{
			struct awk_node *r = parse_unary(p); /* right-assoc, and unary binds tighter than ^ on the right: 2^-2 is valid */
			struct awk_node *b = mknode(N_BINOP);
			b->op = T_CARET; b->a = l; b->b = r;
			return b;
		}
	}
	return l;
}

/* Guarded: `^`'s own right-associativity makes parse_pow() indirectly
 * self-recursive (via parse_unary()) for a chain like `2^2^2^...` --
 * see this file's "recursion depth guard" section above. */
static struct awk_node *parse_pow(struct awk_parser *p)
{
	struct awk_node *n;
	if (!parse_depth_enter(p)) return mknode(N_NUM);
	n = parse_pow_impl(p);
	parse_depth_leave(p);
	return n;
}

static struct awk_node *parse_unary(struct awk_parser *p)
{
	/* Unary +/-/! are already parse_primary()'s own cases (so that
	 * `-2^2` parses as `-(2^2)`, matching every real awk: power binds
	 * tighter than a leading unary sign). This function exists as the
	 * named entry point parse_pow()/callers above use; it just defers. */
	return parse_pow(p);
}

static struct awk_node *parse_mul(struct awk_parser *p)
{
	struct awk_node *l = parse_unary(p);
	for (;;) {
		int op;
		if (at(p, T_STAR)) op = T_STAR;
		else if (at(p, T_SLASH)) op = T_SLASH;
		else if (at(p, T_PERCENT)) op = T_PERCENT;
		else break;
		advance(p);
		{
			struct awk_node *r = parse_unary(p);
			struct awk_node *b = mknode(N_BINOP);
			b->op = op; b->a = l; b->b = r;
			l = b;
		}
	}
	return l;
}

static struct awk_node *parse_additive(struct awk_parser *p)
{
	struct awk_node *l = parse_mul(p);
	for (;;) {
		int op;
		if (at(p, T_PLUS)) op = T_PLUS;
		else if (at(p, T_MINUS)) op = T_MINUS;
		else break;
		advance(p);
		{
			struct awk_node *r = parse_mul(p);
			struct awk_node *b = mknode(N_BINOP);
			b->op = op; b->a = l; b->b = r;
			l = b;
		}
	}
	return l;
}

static int starts_concat_operand(struct awk_parser *p)
{
	switch (p->tok.type) {
	case T_NUMBER: case T_STRING: case T_ERE: case T_NAME: case T_FUNC_NAME:
	case T_BUILTIN_NAME: case T_DOLLAR: case T_LPAREN: case T_NOT:
	case T_INCR: case T_DECR:
		return 1;
	default:
		return 0;
	}
}

static struct awk_node *parse_concat(struct awk_parser *p)
{
	struct awk_node *l = parse_additive(p);
	while (starts_concat_operand(p)) {
		struct awk_node *r = parse_additive(p);
		struct awk_node *c = mknode(N_CONCAT);
		c->a = l; c->b = r;
		l = c;
	}
	return l;
}

static struct awk_node *parse_rel(struct awk_parser *p)
{
	struct awk_node *l = parse_concat(p);
	int op = 0;

	if (at(p, T_LT)) op = T_LT;
	else if (at(p, T_LE)) op = T_LE;
	else if (at(p, T_NE)) op = T_NE;
	else if (at(p, T_EQ)) op = T_EQ;
	else if (at(p, T_GE)) op = T_GE;
	else if (at(p, T_GT) && !p->suppress_gt) op = T_GT;

	if (op) {
		struct awk_node *r, *b;
		advance(p);
		r = parse_concat(p);
		b = mknode(N_RELOP);
		b->op = op; b->a = l; b->b = r;
		return b;
	}

	/* `expr | getline [var]` -- same tier as relational per this
	 * parser's own layering (see this file's header). */
	if (at(p, T_PIPE) && !p->suppress_gt) {
		advance(p);
		if (!at(p, T_GETLINE)) { perr(p, "awk: expected 'getline' after '|'"); return l; }
		return parse_getline(p, l, GL_CMD);
	}
	return l;
}

static struct awk_node *parse_match(struct awk_parser *p)
{
	struct awk_node *l = parse_rel(p);
	while (at(p, T_MATCH) || at(p, T_NOMATCH)) {
		int neg = at(p, T_NOMATCH);
		struct awk_node *r, *m;
		advance(p);
		r = parse_rel(p);
		m = mknode(N_MATCH);
		m->op = neg; m->a = l; m->b = r;
		l = m;
	}
	return l;
}

static struct awk_node *parse_in(struct awk_parser *p)
{
	struct awk_node *l = parse_match(p);
	while (at(p, T_IN)) {
		struct awk_node *in;
		char *arrname;
		advance(p);
		if (!at(p, T_NAME)) { perr(p, "awk: expected array name after 'in'"); return l; }
		arrname = p->tok.text; p->tok.text = NULL;
		advance(p);
		in = mknode(N_IN);
		in->str = arrname;
		if (l->type == N_ELIST) { in->list = l->list; in->nlist = l->nlist; free(l); }
		else { in->list = malloc(sizeof *in->list); if (!in->list) oom(); in->list[0] = l; in->nlist = 1; }
		l = in;
	}
	return l;
}

static struct awk_node *parse_and(struct awk_parser *p)
{
	struct awk_node *l = parse_in(p);
	while (at(p, T_AND)) {
		struct awk_node *r, *b;
		advance(p);
		skip_newlines(p);
		r = parse_in(p);
		b = mknode(N_AND); b->a = l; b->b = r;
		l = b;
	}
	return l;
}

static struct awk_node *parse_or(struct awk_parser *p)
{
	struct awk_node *l = parse_and(p);
	while (at(p, T_OR)) {
		struct awk_node *r, *b;
		advance(p);
		skip_newlines(p);
		r = parse_and(p);
		b = mknode(N_OR); b->a = l; b->b = r;
		l = b;
	}
	return l;
}

static struct awk_node *parse_ternary_impl(struct awk_parser *p)
{
	struct awk_node *c = parse_or(p);
	if (at(p, T_QUESTION)) {
		struct awk_node *t, *f, *n;
		advance(p);
		skip_newlines(p);
		t = parse_ternary(p);
		skip_newlines(p);
		expect(p, T_COLON, "':'");
		skip_newlines(p);
		f = parse_ternary(p);
		n = mknode(N_TERNARY);
		n->a = c; n->b = t; n->c = f;
		return n;
	}
	return c;
}

/* Guarded: `?:`'s right-associativity makes this self-recursive (twice
 * over, for the true- and false-branches) for a chain like
 * `a?a?a?...:b:b:b` -- see this file's "recursion depth guard" section
 * above. */
static struct awk_node *parse_ternary(struct awk_parser *p)
{
	struct awk_node *n;
	if (!parse_depth_enter(p)) return mknode(N_NUM);
	n = parse_ternary_impl(p);
	parse_depth_leave(p);
	return n;
}

/* enum awk_toktype, not int: p->tok.type below is compared against these
 * entries directly, and the terminating 0 is T_EOF (never a real assign
 * operator), so the array's own element type should be the enum it holds. */
static const enum awk_toktype assign_ops[] = { T_ASSIGN, T_ADD_ASSIGN, T_SUB_ASSIGN, T_MUL_ASSIGN, T_DIV_ASSIGN, T_MOD_ASSIGN, T_POW_ASSIGN, T_EOF };

static struct awk_node *parse_assign_impl(struct awk_parser *p)
{
	struct awk_node *l = parse_ternary(p);
	int i, op = 0;

	for (i = 0; assign_ops[i]; i++) if (p->tok.type == assign_ops[i]) { op = assign_ops[i]; break; }
	if (op) {
		struct awk_node *r, *n;
		if (!is_lvalue(l)) { perr(p, "awk: assignment target must be a variable, field, or array element"); }
		advance(p);
		skip_newlines(p);
		r = parse_assign(p); /* right-associative */
		n = mknode(N_ASSIGN);
		n->op = op; n->a = l; n->b = r;
		return n;
	}
	return l;
}

/* Guarded: assignment's own right-associativity makes this self-
 * recursive for a chain like `a=a=a=...=1` -- see this file's
 * "recursion depth guard" section above. */
static struct awk_node *parse_assign(struct awk_parser *p)
{
	struct awk_node *n;
	if (!parse_depth_enter(p)) return mknode(N_NUM);
	n = parse_assign_impl(p);
	parse_depth_leave(p);
	return n;
}

static struct awk_node *parse_expr(struct awk_parser *p)
{
	return parse_assign(p);
}

/* Comma-separated expressions, e.g. call arguments and array
 * subscripts (multi-dimensional, SUBSEP-joined at evaluation time).
 * suppress_gt is saved/cleared/restored for the same reason
 * parse_paren_group() above does it: a bracketed/parenthesized
 * sub-list is never ambiguous with print's own redirection, even when
 * called from inside a print statement's own argument list (e.g.
 * `print f(a > b)`, `print arr[a > b]`). */
static struct awk_node **parse_expr_list(struct awk_parser *p, int *n, int allow_empty)
{
	struct awk_node **list = NULL;
	int saved_gt = p->suppress_gt;
	p->suppress_gt = 0;
	*n = 0;
	if (allow_empty && (at(p, T_RPAREN) || at(p, T_RBRACKET))) { p->suppress_gt = saved_gt; return NULL; }
	addlist(&list, n, parse_expr(p));
	while (accept_tok(p, T_COMMA)) {
		skip_newlines(p);
		addlist(&list, n, parse_expr(p));
	}
	p->suppress_gt = saved_gt;
	return list;
}

/* ==== print / printf ====================================================== */

static struct awk_node *parse_print_expr(struct awk_parser *p)
{
	struct awk_node *n;
	p->suppress_gt++;
	n = parse_expr(p);
	p->suppress_gt--;
	return n;
}

static struct awk_node *parse_print_stmt(struct awk_parser *p, int is_printf)
{
	struct awk_node *n = mknode(is_printf ? N_PRINTF : N_PRINT);
	struct awk_node **list = NULL;
	int cnt = 0;

	advance(p); /* PRINT / PRINTF */
	if (!at(p, T_SEMI) && !at(p, T_NEWLINE) && !at(p, T_RBRACE) && !at(p, T_EOF) &&
	    !at(p, T_GT) && !at(p, T_APPEND) && !at(p, T_PIPE)) {
		addlist(&list, &cnt, parse_print_expr(p));
		while (accept_tok(p, T_COMMA)) {
			skip_newlines(p);
			addlist(&list, &cnt, parse_print_expr(p));
		}
	}
	if (cnt == 1 && list[0]->type == N_ELIST) {
		struct awk_node *e = list[0];
		free(list);
		list = e->list; cnt = e->nlist;
		free(e);
	}
	n->list = list; n->nlist = cnt;

	if (at(p, T_GT)) { advance(p); n->redir = RD_FILE; n->a = parse_concat(p); }
	else if (at(p, T_APPEND)) { advance(p); n->redir = RD_APPEND; n->a = parse_concat(p); }
	else if (at(p, T_PIPE)) { advance(p); n->redir = RD_PIPE; n->a = parse_concat(p); }
	else n->redir = RD_NONE;

	return n;
}

/* ==== statements ========================================================== */

static struct awk_node *parse_simple_or_null(struct awk_parser *p)
{
	if (at(p, T_SEMI) || at(p, T_RPAREN)) return NULL;
	return parse_stmt(p);
}

static struct awk_node *parse_stmt_impl(struct awk_parser *p)
{
	if (p->err) return mknode(N_BLOCK);

	switch (p->tok.type) {
	case T_LBRACE:
		return parse_block(p);
	case T_IF: {
		struct awk_node *n = mknode(N_IF);
		advance(p);
		expect(p, T_LPAREN, "'('");
		n->a = parse_expr(p);
		expect(p, T_RPAREN, "')'");
		skip_newlines(p);
		n->b = parse_stmt(p);
		/* An ELSE may follow after any number of terminators (`if (x)
		 * y; else z` is common style). No lookahead/backtracking is
		 * needed to allow this: consuming every pending terminator
		 * here and finding no ELSE loses no information, because the
		 * enclosing statement-list's own skip_terminators() call
		 * (parse_block()'s loop) is idempotent on an empty run -- it
		 * simply finds nothing left to skip and proceeds straight to
		 * the next statement or '}'. */
		skip_terminators(p);
		if (at(p, T_ELSE)) {
			advance(p);
			skip_newlines(p);
			n->c = parse_stmt(p);
		}
		return n;
	}
	case T_WHILE: {
		struct awk_node *n = mknode(N_WHILE);
		advance(p);
		expect(p, T_LPAREN, "'('");
		n->a = parse_expr(p);
		expect(p, T_RPAREN, "')'");
		skip_newlines(p);
		n->b = parse_stmt(p);
		return n;
	}
	case T_DO: {
		struct awk_node *n = mknode(N_DOWHILE);
		advance(p);
		skip_newlines(p);
		n->a = parse_stmt(p);
		skip_terminators(p);
		expect(p, T_WHILE, "'while'");
		expect(p, T_LPAREN, "'('");
		n->b = parse_expr(p);
		expect(p, T_RPAREN, "')'");
		return n;
	}
	case T_FOR: {
		advance(p);
		expect(p, T_LPAREN, "'('");
		if (at(p, T_NAME) && peek2(p) == T_IN) {
			struct awk_node *n = mknode(N_FORIN);
			n->str = p->tok.text; p->tok.text = NULL;
			advance(p); /* NAME */
			advance(p); /* IN */
			if (!at(p, T_NAME)) { perr(p, "awk: expected array name"); return n; }
			n->str2 = p->tok.text; p->tok.text = NULL;
			advance(p);
			expect(p, T_RPAREN, "')'");
			skip_newlines(p);
			n->b = parse_stmt(p);
			return n;
		}
		{
			struct awk_node *n = mknode(N_FOR);
			n->a = parse_simple_or_null(p);
			expect(p, T_SEMI, "';'");
			if (!at(p, T_SEMI)) n->b = parse_expr(p);
			expect(p, T_SEMI, "';'");
			n->c = parse_simple_or_null(p);
			expect(p, T_RPAREN, "')'");
			skip_newlines(p);
			n->d = parse_stmt(p);
			return n;
		}
	}
	case T_BREAK: advance(p); return mknode(N_BREAK);
	case T_CONTINUE: advance(p); return mknode(N_CONTINUE);
	case T_NEXT: advance(p); return mknode(N_NEXT);
	case T_EXIT: {
		struct awk_node *n = mknode(N_EXIT);
		advance(p);
		if (!at(p, T_SEMI) && !at(p, T_NEWLINE) && !at(p, T_RBRACE) && !at(p, T_EOF)) n->a = parse_expr(p);
		return n;
	}
	case T_RETURN: {
		struct awk_node *n = mknode(N_RETURN);
		advance(p);
		if (!at(p, T_SEMI) && !at(p, T_NEWLINE) && !at(p, T_RBRACE) && !at(p, T_EOF)) n->a = parse_expr(p);
		return n;
	}
	case T_DELETE: {
		struct awk_node *n = mknode(N_DELETE);
		advance(p);
		if (!at(p, T_NAME)) { perr(p, "awk: expected array name after 'delete'"); return n; }
		n->str = p->tok.text; p->tok.text = NULL;
		advance(p);
		if (accept_tok(p, T_LBRACKET)) {
			n->list = parse_expr_list(p, &n->nlist, 0);
			expect(p, T_RBRACKET, "']'");
		}
		return n;
	}
	case T_PRINT: return parse_print_stmt(p, 0);
	case T_PRINTF: return parse_print_stmt(p, 1);
	case T_SEMI:
		return mknode(N_BLOCK); /* empty statement */
	default: {
		struct awk_node *n = mknode(N_EXPRSTMT);
		n->a = parse_expr(p);
		return n;
	}
	}
}

/* Guarded: statement nesting (if/while/for/do bodies, and -- the one
 * shape with no expression of its own to already be guarded via
 * parse_primary() -- a run of N bare `{` blocks, `{{{...}}}`) recurses
 * through parse_stmt() <-> parse_block() with no other bound. See this
 * file's "recursion depth guard" section above. */
static struct awk_node *parse_stmt(struct awk_parser *p)
{
	struct awk_node *n;
	if (!parse_depth_enter(p)) return mknode(N_BLOCK);
	n = parse_stmt_impl(p);
	parse_depth_leave(p);
	return n;
}

static struct awk_node *parse_block(struct awk_parser *p)
{
	struct awk_node *n = mknode(N_BLOCK);
	struct awk_node **list = NULL;
	int cnt = 0;

	expect(p, T_LBRACE, "'{'");
	skip_terminators(p);
	while (!at(p, T_RBRACE) && !at(p, T_EOF) && !p->err) {
		addlist(&list, &cnt, parse_stmt(p));
		skip_terminators(p);
	}
	expect(p, T_RBRACE, "'}'");
	n->list = list; n->nlist = cnt;
	return n;
}

/* ==== top level: functions and pattern-action rules ====================== */

static void parse_function_def(struct awk_parser *p)
{
	struct awk_func f;
	char **params = NULL;
	int nparams = 0;

	memset(&f, 0, sizeof f);
	advance(p); /* FUNCTION */
	if (!at(p, T_NAME) && !at(p, T_FUNC_NAME)) { perr(p, "awk: expected function name"); return; }
	f.name = p->tok.text; p->tok.text = NULL;
	advance(p);
	expect(p, T_LPAREN, "'('");
	if (!at(p, T_RPAREN)) {
		for (;;) {
			if (!at(p, T_NAME)) { perr(p, "awk: expected parameter name"); break; }
			{
				char **g = __util_reallocarray(params, (size_t)nparams + 1, sizeof *params);
				if (!g) oom();
				params = g;
				params[nparams++] = p->tok.text; p->tok.text = NULL;
			}
			advance(p);
			if (!accept_tok(p, T_COMMA)) break;
			skip_newlines(p);
		}
	}
	expect(p, T_RPAREN, "')'");
	f.params = params; f.nparams = nparams;
	skip_newlines(p);
	f.body = parse_block(p);

	{
		struct awk_func *g = __util_reallocarray(p->prog->funcs, (size_t)p->prog->nfuncs + 1, sizeof *g);
		if (!g) oom();
		p->prog->funcs = g;
		p->prog->funcs[p->prog->nfuncs++] = f;
	}
}

static void parse_rule(struct awk_parser *p)
{
	struct awk_rule r;
	memset(&r, 0, sizeof r);

	if (at(p, T_BEGIN)) {
		advance(p);
		skip_newlines(p);
		r.kind = RULE_BEGIN;
		r.action = parse_block(p);
	} else if (at(p, T_END)) {
		advance(p);
		skip_newlines(p);
		r.kind = RULE_END;
		r.action = parse_block(p);
	} else if (at(p, T_LBRACE)) {
		r.kind = RULE_ALWAYS;
		r.action = parse_block(p);
	} else {
		r.pat1 = parse_expr(p);
		if (accept_tok(p, T_COMMA)) {
			skip_newlines(p);
			r.pat2 = parse_expr(p);
			r.kind = RULE_RANGE;
		} else {
			r.kind = r.pat1->type == N_REGEX ? RULE_REGEX : RULE_EXPR;
		}
		if (at(p, T_LBRACE)) r.action = parse_block(p);
		else r.action = NULL; /* default action: print $0 */
	}

	{
		struct awk_rule *g = __util_reallocarray(p->prog->rules, (size_t)p->prog->nrules + 1, sizeof *g);
		if (!g) oom();
		p->prog->rules = g;
		p->prog->rules[p->prog->nrules++] = r;
	}
}

struct awk_program *awk_parse_program(const char *src)
{
	struct awk_parser p;
	struct awk_program *prog = calloc(1, sizeof *prog);

	if (!prog) oom();
	memset(&p, 0, sizeof p);
	p.prog = prog;
	awk_lex_init(&p.lx, src);
	raw_next(&p, &p.tok);

	skip_terminators(&p);
	while (!at(&p, T_EOF) && !p.err) {
		if (at(&p, T_FUNCTION)) parse_function_def(&p);
		else parse_rule(&p);
		skip_terminators(&p);
	}

	if (p.err) {
		__util_diagf("%s\n", p.errmsg);
		free_tok_text(&p.tok);
		free_tok_text(&p.tok2);
		free(prog->rules);
		free(prog->funcs);
		free(prog);
		return NULL;
	}
	free_tok_text(&p.tok);
	free_tok_text(&p.tok2);
	return prog;
}
