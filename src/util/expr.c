/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * expr(1p): evaluate an expression given as separate argv operands and
 * print the result.  Checked against
 * https://pubs.opengroup.org/onlinepubs/9699919799/utilities/expr.html.
 *
 * GRAMMAR (that page's OPERANDS table, "in order of decreasing
 * precedence, with equal-precedence operators grouped"; all binary
 * operators are left-associative):
 *
 *   expr1 '|' expr2
 *   expr1 '&' expr2
 *   expr1 { '=', '>', '>=', '<', '<=', '!=' } expr2
 *   expr1 { '+', '-' } expr2
 *   expr1 { '*', '/', '%' } expr2
 *   expr1 ':' expr2
 *   '(' expr1 ')'
 *
 * Each argv operand after argv[0] is already one token -- the shell (or
 * whatever invoked this utility) has already done the word-splitting
 * expr's own grammar needs, so this file's parser walks argv directly,
 * the same "recursive descent over an argv cursor" shape
 * src/util/test.c's t_oexpr()/t_aexpr()/t_nexpr() already use for
 * test(1p)'s not-unrelated `!`/`-a`/`-o` grammar (test(1p)'s own
 * comment explains why that shape fits an already-tokenized argv well).
 * expr(1p)'s grammar is a genuinely different operator set and
 * precedence table, though -- and unlike test(1p), a value here is
 * evaluated exactly once, so this parser builds and evaluates in one
 * pass (no separate AST) rather than parsing into a tree first.
 *
 * NUMERIC-VS-STRING COERCION: "An argument ... that consists only of an
 * optional unary minus followed by digits is a candidate for treatment
 * as an integer if it is used as the left argument to the '|' operator
 * or as either argument to any of the ... '&' '=' '>' '>=' '<' '<=' '!='
 * '+' '-' '*' '/' '%' [operators]. Otherwise, the argument is treated as
 * a string."  Implemented literally by is_num_candidate() below: for
 * '+'/'-'/'*'/'/'/'%' both operands must be candidates or the whole
 * expression is invalid (exit 2, "non-numeric argument"); for the
 * comparison operators, arithmetic comparison is used only when BOTH
 * operands are candidates, otherwise a plain byte/strcmp comparison is
 * used (this library's only locale is "C", src/misc/locale.c, so there
 * is no stronger collation to fall back to).
 *
 * '|' and '&' do NOT return a boolean the way shell/C's do: "'|': ...
 * evaluation of expr1 if it is neither null nor zero; otherwise ...
 * evaluation of expr2." / "'&': ... evaluation of expr1 if neither
 * expression evaluates to null or zero; otherwise ... zero." --
 * null_or_zero() below is exactly the "null or zero" test both operators
 * (and the final EXIT STATUS check) share: the empty string, or a
 * numeric candidate whose value is 0.
 *
 * ':' MATCH OPERATOR: "compare the string resulting from ... expr1 with
 * the regular expression pattern ... expr2. ... Basic Regular
 * Expressions ... except that all patterns are anchored to the
 * beginning of the string ... if the pattern contains at least one
 * ... subexpression \\(...\\), the string matched by the back-reference
 * expression \\1 shall be returned [or the null string if \\1 did not
 * match]; otherwise ... the number of characters matched ... or ... '0'
 * [if there was no match]."  Both operands of ':' are always treated as
 * strings, regardless of whether either looks numeric -- the table
 * above deliberately does not list ':' among the candidate-triggering
 * operators.  src/regex/regex.c's regcomp()/regexec() (default BRE,
 * REG_EXTENDED not passed) implement the pattern language; "anchored to
 * the beginning" is implemented by requiring pmatch[0].rm_so == 0 on a
 * successful match rather than by rewriting the pattern, since
 * regexec() here (like grep) finds the leftmost match anywhere in the
 * string unless told otherwise.
 *
 * EXIT STATUS (this file gets this exactly right, per the page's own
 * EXIT STATUS section): "0 The expression evaluates to neither null nor
 * zero. 1 The expression evaluates to null or zero. 2 The expression is
 * invalid. >2 An error occurred."  Every parse/evaluation problem below
 * (syntax error, non-numeric arithmetic operand, division by zero, a
 * malformed ':' pattern) is reported as 2, matching "the expression is
 * invalid" -- this file has no case that reaches >2, since none of its
 * own operations can fail for a reason other than the expression itself
 * being invalid (no file I/O, no allocation of a size an attacker
 * controls in a way that could plausibly exhaust memory on a real
 * expr(1p) invocation).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <regex.h>
#include "util.h"

/* parse_primary()'s '(' case is the only self-recursion this parser
 * does: it calls back into parse_or(), which walks straight back down
 * through parse_and()/parse_cmp()/parse_add()/parse_mul()/parse_match()/
 * parse_primary() -- six further C-stack frames -- for every level of
 * '(' nesting. Each argv operand this parser walks (struct expr_ctx's
 * `v`) is only bounded by the OS's exec() argument-list limit (ARG_MAX,
 * commonly a couple of MB on Linux), not by anything this file checks,
 * so a caller building argv directly (not through a shell's own command-
 * length limits) can pass on the order of 10^5-10^6 single-character
 * "(" operands and blow the C stack -- the same recursion-with-no-depth-
 * cap bug class already fixed in src/util/m4.c's eval() (ev_primary()/
 * ev_unary(), M4_EVAL_MAX_DEPTH) and src/util/awk_parse.c's parser.
 * Bound it the same way: a shared depth counter checked at the one
 * self-recursion site, failing the expression cleanly instead of
 * recursing further once the cap is hit. */
#define EXPR_MAX_DEPTH 2500

struct expr_ctx {
	char **v;
	size_t n;
	size_t i;
	int err;
	int depth;
};

static void xerr(struct expr_ctx *c, const char *msg) __attribute__((nonnull(1, 2)));
static void xerr(struct expr_ctx *c, const char *msg)
{
	if (c->err) return;
	c->err = 1;
	__util_diagf("expr: %s\n", msg);
}

static int is_num_candidate(const char *s) __attribute__((nonnull(1), __pure__));
static int is_num_candidate(const char *s)
{
	const char *p = s;
	if (*p == '-') p++;
	if (!*p) return 0;
	for (; *p; p++) if (*p < '0' || *p > '9') return 0;
	return 1;
}

/* "null or zero": the shared test '|', '&' and the final EXIT STATUS
 * decision all use, per this file's own header comment. */
static int null_or_zero(const char *v) __attribute__((nonnull(1), __pure__));
static int null_or_zero(const char *v)
{
	const char *p;
	if (!*v) return 1;
	if (!is_num_candidate(v)) return 0;
	p = *v == '-' ? v + 1 : v;
	for (; *p; p++) if (*p != '0') return 0;
	return 1;
}

static const char *peek(struct expr_ctx *c) __attribute__((nonnull(1)));
static const char *peek(struct expr_ctx *c)
{
	return c->i < c->n ? c->v[c->i] : NULL;
}

/* Allocation failure here does NOT call exit(): __util_expr_main() runs
 * in-process as a shell builtin with no fork (src/sh/builtin.c's
 * bi_expr()), and src/internal/util.h's own header says every
 * __util_<name>_main() "returns a real process exit status ... never a
 * raw errno or a boolean" for exactly that reason -- calling exit() from
 * here would tear down the whole shell process over one failed malloc()
 * in a single command, the same class of mistake src/util/dd.c's header
 * comment documents (and avoids) for its own SIGINT handling.
 *
 * c->err is set via xerr() instead, exactly like every other error in
 * this file, and __util_expr_main() checks it before ever printing a
 * result built from the sentinel dupstr()/numstr() return on failure.
 *
 * THE SENTINEL CANNOT BE NULL.  parse_and()/parse_or() below call
 * null_or_zero() on an operand as soon as they see a following '&'/'|'
 * token -- unconditionally, not gated on c->err first (see either
 * function).  A NULL value reaching there would be a null-pointer
 * dereference the first time an OOM'd sub-expression met '&' or '|'.  A
 * static one-byte buffer is dereferenceable -- null_or_zero() reads it
 * as the empty string, which is the correct "null or zero" answer for a
 * value this parser could not actually build -- without being a real
 * allocation.
 *
 * THAT IN TURN MEANS IT MUST NEVER REACH A REAL free().  Every value
 * this parser produces is eventually freed (do_arith()/do_cmp()/
 * do_match()'s consume(heap_allocated) parameters below, parse_and()/
 * parse_or()'s explicit free(), __util_expr_main()'s own free(result)),
 * and oom_sentinel is not a heap allocation -- free()ing it would be
 * undefined behaviour, freeing memory malloc() never returned.  Every
 * one of those sites therefore compares against oom_sentinel before
 * calling free(), the same shape as this codebase's ordinary
 * `if (p) free(p);` guard for an optional pointer, just against this
 * sentinel instead of NULL, so this value can flow anywhere a genuine
 * dupstr()/numstr() result can. */
static char oom_sentinel[1];

withtok(heap_allocated)
static char *dupstr(struct expr_ctx *c, const char *s) __attribute__((nonnull(1, 2)));
withtok(heap_allocated)
static char *dupstr(struct expr_ctx *c, const char *s)
{
	size_t n = strlen(s) + 1;
	char *p = malloc(n);
	if (!p) { xerr(c, "out of memory"); return oom_sentinel; }
	memcpy(p, s, n);
	return p;
}

withtok(heap_allocated)
static char *numstr(struct expr_ctx *c, long n) __attribute__((nonnull(1)));
withtok(heap_allocated)
static char *numstr(struct expr_ctx *c, long n)
{
	char buf[32];
	snprintf(buf, sizeof buf, "%ld", n);
	return dupstr(c, buf);
}

withtok(heap_allocated)
static char *parse_or(struct expr_ctx *c) __attribute__((nonnull(1)));
withtok(heap_allocated)
static char *parse_and(struct expr_ctx *c) __attribute__((nonnull(1)));
withtok(heap_allocated)
static char *parse_cmp(struct expr_ctx *c) __attribute__((nonnull(1)));
withtok(heap_allocated)
static char *parse_add(struct expr_ctx *c) __attribute__((nonnull(1)));
withtok(heap_allocated)
static char *parse_mul(struct expr_ctx *c) __attribute__((nonnull(1)));
withtok(heap_allocated)
static char *parse_match(struct expr_ctx *c) __attribute__((nonnull(1)));
withtok(heap_allocated)
static char *parse_primary(struct expr_ctx *c) __attribute__((nonnull(1)));

static int is_cmp_op(const char *s) __attribute__((nonnull(1), __pure__));
static int is_cmp_op(const char *s)
{
	return !strcmp(s, "=") || !strcmp(s, ">") || !strcmp(s, ">=") ||
	       !strcmp(s, "<") || !strcmp(s, "<=") || !strcmp(s, "!=");
}

/* p is required: every path dereferences it (strcmp against p is
 * unconditional).  c is left unmarked -- diagnostics go through xerr(),
 * which states its own contract. */
withtok(heap_allocated)
static char *do_arith(struct expr_ctx *c, char *a consume(heap_allocated), const char *op,
	char *b consume(heap_allocated)) __attribute__((nonnull(3)));
withtok(heap_allocated)
static char *do_arith(struct expr_ctx *c, char *a consume(heap_allocated), const char *op,
	char *b consume(heap_allocated)) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	long x, y, r;
	char *result;
	if (c->err) { result = dupstr(c, ""); goto done; }
	if (!is_num_candidate(a) || !is_num_candidate(b)) {
		xerr(c, "non-numeric argument");
		result = dupstr(c, "");
		goto done;
	}
	/* is_num_candidate() only requires "optional '-' then all digits" --
	 * it has no length limit, so a literal with more digits than `long`
	 * can hold (e.g. "99999999999999999999") reaches strtol() here.
	 * strtol() does not fail on that: it silently clamps to LONG_MIN/
	 * LONG_MAX and sets errno to ERANGE. Without checking errno, a huge
	 * literal like that would silently become LONG_MAX and every
	 * arithmetic op below would compute a plausible-looking but wrong
	 * answer from it instead of reporting the input could not actually
	 * be represented -- e.g. "expr 99999999999999999999 - 1" would
	 * silently print LONG_MAX-1. Treat the clamp as the same "overflow"
	 * error the operator-level checks below report. */
	errno = 0;
	x = strtol(a, NULL, 10);
	if (errno == ERANGE) { xerr(c, "overflow"); result = dupstr(c, ""); goto done; }
	errno = 0;
	y = strtol(b, NULL, 10);
	if (errno == ERANGE) { xerr(c, "overflow"); result = dupstr(c, ""); goto done; }
	/* x and y are each whatever a caller's argv put there, up to and
	 * including LONG_MIN/LONG_MAX -- "expr 9223372036854775807 + 1" on a
	 * 64-bit long reaches this line with exactly that x and y=1. Every
	 * operator below can overflow a real `long` on real input, and a
	 * plain +, -, or * on `long` operands is undefined behaviour right
	 * at overflow, not merely POSIX-unspecified; each arm below checks
	 * before computing rather than after, since the overflowing
	 * expression itself must never be evaluated. */
	if (!strcmp(op, "+")) {
		if ((y > 0 && x > LONG_MAX - y) || (y < 0 && x < LONG_MIN - y)) {
			xerr(c, "overflow"); result = dupstr(c, ""); goto done;
		}
		r = x + y;
	} else if (!strcmp(op, "-")) {
		if ((y < 0 && x > LONG_MAX + y) || (y > 0 && x < LONG_MIN + y)) {
			xerr(c, "overflow"); result = dupstr(c, ""); goto done;
		}
		r = x - y;
	} else if (!strcmp(op, "*")) {
		if (x > 0) {
			if (y > 0 ? x > LONG_MAX / y : y < LONG_MIN / x) {
				xerr(c, "overflow"); result = dupstr(c, ""); goto done;
			}
		} else if (x < 0) {
			if (y > 0 ? x < LONG_MIN / y : y < LONG_MAX / x) {
				xerr(c, "overflow"); result = dupstr(c, ""); goto done;
			}
		}
		r = x * y;
	} else {
		if (y == 0) { xerr(c, "division by zero"); result = dupstr(c, ""); goto done; }
		/* LONG_MIN / -1 (and the equivalent %) is the one division
		 * that overflows: its mathematical result, -LONG_MIN, is one
		 * past LONG_MAX. */
		if (x == LONG_MIN && y == -1) {
			xerr(c, "overflow"); result = dupstr(c, ""); goto done;
		}
		r = !strcmp(op, "/") ? x / y : x % y;
	}
	result = numstr(c, r);
done:
	if (a != oom_sentinel) free(a);
	if (b != oom_sentinel) free(b);
	return result;
}

withtok(heap_allocated)
static char *do_cmp(struct expr_ctx *c, char *a consume(heap_allocated), const char *op,
	char *b consume(heap_allocated)) __attribute__((nonnull(3)));
withtok(heap_allocated)
static char *do_cmp(struct expr_ctx *c, char *a consume(heap_allocated), const char *op,
	char *b consume(heap_allocated)) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int r;
	const char *value;
	char *result;
	if (c->err) { result = dupstr(c, ""); goto done; }
	if (is_num_candidate(a) && is_num_candidate(b)) {
		long x = strtol(a, NULL, 10), y = strtol(b, NULL, 10);
		if (x < y) r = -1;
		else if (x > y) r = 1;
		else r = 0;
	} else {
		int sr = strcmp(a, b);
		if (sr < 0) r = -1;
		else if (sr > 0) r = 1;
		else r = 0;
	}
	if (!strcmp(op, "=")) value = r == 0 ? "1" : "0";
	else if (!strcmp(op, "!=")) value = r != 0 ? "1" : "0";
	else if (!strcmp(op, "<")) value = r < 0 ? "1" : "0";
	else if (!strcmp(op, "<=")) value = r <= 0 ? "1" : "0";
	else if (!strcmp(op, ">")) value = r > 0 ? "1" : "0";
	else value = r >= 0 ? "1" : "0"; /* ">=" */
	result = dupstr(c, value);
done:
	if (a != oom_sentinel) free(a);
	if (b != oom_sentinel) free(b);
	return result;
}

withtok(heap_allocated)
static char *do_match(struct expr_ctx *c, char *a consume(heap_allocated),
	char *pat consume(heap_allocated)) __attribute__((nonnull(2, 3)));
withtok(heap_allocated)
static char *do_match(struct expr_ctx *c, char *a consume(heap_allocated),
	char *pat consume(heap_allocated))
{
	regex_t re;
	regmatch_t pm[2];
	int rc, matched;
	char *result;

	if (c->err) { result = dupstr(c, ""); goto done; }
	rc = regcomp(&re, pat, 0);
	if (rc) {
		xerr(c, "invalid regular expression");
		result = dupstr(c, "");
		goto done;
	}
	rc = regexec(&re, a, 2, pm, 0);
	matched = rc == 0 && pm[0].rm_so == 0;
	if (re.re_nsub >= 1) {
		if (matched && pm[1].rm_so >= 0) {
			regoff_t len = pm[1].rm_eo - pm[1].rm_so;
			result = malloc((size_t)len + 1);
			if (!result) { xerr(c, "out of memory"); result = dupstr(c, ""); }
			else {
				memcpy(result, a + pm[1].rm_so, (size_t)len);
				result[len] = 0;
			}
		} else {
			result = dupstr(c, "");
		}
	} else {
		result = matched ? numstr(c, pm[0].rm_eo - pm[0].rm_so) : dupstr(c, "0");
	}
	regfree(&re);
done:
	if (a != oom_sentinel) free(a);
	if (pat != oom_sentinel) free(pat);
	return result;
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested expr grouping and is depth-bounded by argc
withtok(heap_allocated)
static char *parse_primary(struct expr_ctx *c)
{
	const char *tok = peek(c);
	if (!tok) { xerr(c, "syntax error: unexpected end of expression"); return dupstr(c, ""); }
	if (!strcmp(tok, "(")) {
		char *v;
		c->i++;
		if (c->depth >= EXPR_MAX_DEPTH) {
			xerr(c, "expression too deeply nested");
			return dupstr(c, "");
		}
		c->depth++;
		v = parse_or(c);
		c->depth--;
		tok = peek(c);
		if (!tok || strcmp(tok, ")")) { xerr(c, "syntax error: expected ')'"); return v; } // NOLINT(bugprone-suspicious-string-compare) -- nonzero intentionally detects a missing/mismatched ')'
		c->i++;
		return v;
	}
	if (!strcmp(tok, ")")) { xerr(c, "syntax error: unexpected ')'"); return dupstr(c, ""); }
	c->i++;
	return dupstr(c, tok);
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested expr grouping and is depth-bounded by argc
withtok(heap_allocated)
static char *parse_match(struct expr_ctx *c)
{
	char *v = parse_primary(c);
	while (peek(c) && !strcmp(peek(c), ":")) {
		char *rhs;
		c->i++;
		rhs = parse_primary(c);
		v = do_match(c, v, rhs);
	}
	return v;
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested expr grouping and is depth-bounded by argc
withtok(heap_allocated)
static char *parse_mul(struct expr_ctx *c)
{
	char *v = parse_match(c);
	const char *tok;
	while ((tok = peek(c)) && (!strcmp(tok, "*") || !strcmp(tok, "/") || !strcmp(tok, "%"))) {
		char *rhs;
		c->i++;
		rhs = parse_match(c);
		v = do_arith(c, v, tok, rhs);
	}
	return v;
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested expr grouping and is depth-bounded by argc
withtok(heap_allocated)
static char *parse_add(struct expr_ctx *c)
{
	char *v = parse_mul(c);
	const char *tok;
	while ((tok = peek(c)) && (!strcmp(tok, "+") || !strcmp(tok, "-"))) {
		char *rhs;
		c->i++;
		rhs = parse_mul(c);
		v = do_arith(c, v, tok, rhs);
	}
	return v;
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested expr grouping and is depth-bounded by argc
withtok(heap_allocated)
static char *parse_cmp(struct expr_ctx *c)
{
	char *v = parse_add(c);
	while (peek(c) && is_cmp_op(peek(c))) {
		const char *op = peek(c);
		char *rhs;
		c->i++;
		rhs = parse_add(c);
		v = do_cmp(c, v, op, rhs);
	}
	return v;
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested expr grouping and is depth-bounded by argc
withtok(heap_allocated)
static char *parse_and(struct expr_ctx *c)
{
	char *v = parse_cmp(c);
	while (peek(c) && !strcmp(peek(c), "&")) {
		char *rhs;
		c->i++;
		rhs = parse_cmp(c);
		if (null_or_zero(v) || null_or_zero(rhs)) {
			if (v != oom_sentinel) free(v);
			if (rhs != oom_sentinel) free(rhs);
			v = dupstr(c, "0");
		} else {
			if (rhs != oom_sentinel) free(rhs);
		}
	}
	return v;
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested expr grouping and is depth-bounded by argc
withtok(heap_allocated)
static char *parse_or(struct expr_ctx *c)
{
	char *v = parse_and(c);
	while (peek(c) && !strcmp(peek(c), "|")) {
		char *rhs;
		c->i++;
		rhs = parse_and(c);
		if (null_or_zero(v)) {
			if (v != oom_sentinel) free(v);
			v = rhs;
		} else {
			if (rhs != oom_sentinel) free(rhs);
		}
	}
	return v;
}

int __util_expr_main(int argc, char **argv)
{
	struct expr_ctx c;
	char *result;
	int status;

	if (argc < 2) {
		__util_diagf("expr: missing operand\n");
		return 2;
	}

	c.v = argv + 1;
	c.n = (size_t)(argc - 1);
	c.i = 0;
	c.err = 0;
	c.depth = 0;

	result = parse_or(&c);
	if (!c.err && c.i != c.n) xerr(&c, "syntax error: unexpected argument");
	if (c.err) { if (result != oom_sentinel) free(result); return 2; }

	printf("%s\n", result);
	status = null_or_zero(result) ? 1 : 0;
	if (result != oom_sentinel) free(result);
	return status;
}
