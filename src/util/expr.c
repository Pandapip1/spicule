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
#include "ownership_stubs.h" /* __ownership_string_terminated(): struct expr_ctx's `v` (char **, sliced from argv+1) is byte-for-byte the same "struct holds an argv-derived char **" shape as src/util/test.c's struct texpr (commit 33438c1b) and src/util/find.c's struct find_ctx before it -- a checker-opaque struct field, so every strcmp()/strlen() against one of its elements looks like a missing null_terminated token even though it is true by construction (argv's own elements_withtok(null_terminated, argc) contract on __util_expr_main's own parameter). Restated at each point such an element or a heap-allocated (dupstr()/numstr()) result crosses into a plain const char *, the same idiom test.c/find.c already use. */

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
	const char *tok;
	if (c->i >= c->n) return NULL;
	/* tok is one of c->v's own elements -- an argv element, sliced from
	 * argv+1 by __util_expr_main() below -- restate the argv-wide
	 * null-terminated guarantee here, the single place this
	 * checker-opaque struct field crosses into a plain const char *, so
	 * every caller of peek() inherits the fact through its return value
	 * instead of each needing to restate it again. */
	tok = c->v[c->i];
	__ownership_string_terminated(tok);
	return tok;
}
/* Left open: ntlibc.ValidPointer/core.NullDereference still flag this
 * c->v[c->i] access itself as "not proven nonnull" -- no existing
 * ownership.h annotation establishes plain pointer nonnull-ness for a
 * struct field's own array (readable_elements/writable_elements
 * pairing was tried and does not help; __ownership_string_terminated()
 * does not establish nonnull-ness either). src/util/test.c's own
 * ownership-lint fixup (commit 33438c1b) hit and documented the same
 * unresolved gap for its byte-for-byte identical struct texpr.v. */

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
 * dupstr()/numstr() result can.
 *
 * Left open: this `if (x != oom_sentinel) free(x)` guard is exactly
 * why ntlibc.AllocationLifetime/ntlibc.Ownership still flag several
 * sites below ("dynamic allocation is not freed before function
 * exit", "consume function exits without releasing its argument",
 * "deallocator argument is not proven owned") along the symbolic path
 * where a withtok(heap_allocated) value equals oom_sentinel: the
 * checker's token model has no way to know oom_sentinel is a static
 * buffer masquerading as a heap_allocated value precisely so it need
 * not be freed on that path -- there is no existing ownership.h
 * vocabulary for "this value vacuously satisfies a linear token
 * without a real release call" the way zero_vacuous does for a
 * zero-length span. Confirmed via a real `tools/lint.sh ownership`
 * run rather than assumed; not fixable without either a new
 * annotation (out of scope for a per-file annotation pass) or
 * reworking this file's own OOM-signaling design (a real API change,
 * not a static-analysis fix). */
static char oom_sentinel[1];

withtok(heap_allocated)
static char *dupstr(struct expr_ctx *c, const char *s) __attribute__((nonnull(1, 2), returns_nonnull));
withtok(heap_allocated)
static char *dupstr(struct expr_ctx *c, const char *s)
{
	size_t n;
	char *p;
	/* s is always one of: a C string literal (every dupstr(c, "...")
	 * call site below), numstr()'s own snprintf()-terminated stack
	 * buffer, or one of c->v's argv elements passed through by
	 * parse_primary() -- every one of those is genuinely
	 * null-terminated, but that fact does not survive crossing this
	 * function's plain `const char *` parameter, the same reason
	 * peek()'s own struct-field read needs the axiom restated. Returns
	 * either a real malloc()'d copy or oom_sentinel (a valid static
	 * one-byte buffer), so the return is never NULL either -- see
	 * oom_sentinel's own comment above for why it must not be. */
	__ownership_string_terminated(s);
	n = strlen(s) + 1;
	p = malloc(n);
	if (!p) { xerr(c, "out of memory"); return oom_sentinel; }
	memcpy(p, s, n);
	return p;
}

withtok(heap_allocated)
static char *numstr(struct expr_ctx *c, long n) __attribute__((nonnull(1), returns_nonnull));
withtok(heap_allocated)
static char *numstr(struct expr_ctx *c, long n)
{
	char buf[32];
	snprintf(buf, sizeof buf, "%ld", n);
	return dupstr(c, buf);
}

withtok(heap_allocated)
static char *parse_or(struct expr_ctx *c) __attribute__((nonnull(1), returns_nonnull));
withtok(heap_allocated)
static char *parse_and(struct expr_ctx *c) __attribute__((nonnull(1), returns_nonnull));
withtok(heap_allocated)
static char *parse_cmp(struct expr_ctx *c) __attribute__((nonnull(1), returns_nonnull));
withtok(heap_allocated)
static char *parse_add(struct expr_ctx *c) __attribute__((nonnull(1), returns_nonnull));
withtok(heap_allocated)
static char *parse_mul(struct expr_ctx *c) __attribute__((nonnull(1), returns_nonnull));
withtok(heap_allocated)
static char *parse_match(struct expr_ctx *c) __attribute__((nonnull(1), returns_nonnull));
withtok(heap_allocated)
static char *parse_primary(struct expr_ctx *c) __attribute__((nonnull(1), returns_nonnull));

/* s is always one of peek()'s already-established argv elements
 * (every call site below is is_cmp_op(peek(c)) or is_cmp_op(tok) where
 * tok traces back to peek(c)) -- restate the axiom here too since
 * is_cmp_op is its own function boundary and peek()'s own established
 * fact does not automatically cross it. */
static int is_cmp_op(const char *s) __attribute__((nonnull(1), __pure__));
static int is_cmp_op(const char *s)
{
	__ownership_string_terminated(s);
	return !strcmp(s, "=") || !strcmp(s, ">") || !strcmp(s, ">=") ||
	       !strcmp(s, "<") || !strcmp(s, "<=") || !strcmp(s, "!=");
}

/* c is required: `if (c->err)` dereferences it unconditionally on
 * entry. op is required: every arm reached once c->err is false
 * dereferences it via strcmp(). a and b are left unmarked -- they are
 * consume(heap_allocated) values this function always frees exactly
 * once (possibly via the oom_sentinel comparison instead of a real
 * free()), whether or not they are ever read. */
withtok(heap_allocated)
static char *do_arith(struct expr_ctx *c, char *a consume(heap_allocated), const char *op,
	char *b consume(heap_allocated)) __attribute__((nonnull(1, 3), returns_nonnull));
withtok(heap_allocated)
static char *do_arith(struct expr_ctx *c, char *a consume(heap_allocated), const char *op,
	char *b consume(heap_allocated)) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	long x, y, r;
	char *result;
	if (c->err) { result = dupstr(c, ""); goto done; }
	/* op is always parse_mul()'s/parse_add()'s own peek()-derived
	 * token -- restate the axiom here since do_arith is its own
	 * function boundary. */
	__ownership_string_terminated(op);
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

/* c is required: `if (c->err)` dereferences it unconditionally on
 * entry, same as do_arith(). op is required for the same reason.  a
 * and b are left unmarked -- see do_arith()'s own comment; the
 * strcmp(a, b) fallback below is the one place this function reads
 * them, and only when neither is a numeric candidate. */
withtok(heap_allocated)
static char *do_cmp(struct expr_ctx *c, char *a consume(heap_allocated), const char *op,
	char *b consume(heap_allocated)) __attribute__((nonnull(1, 3), returns_nonnull));
withtok(heap_allocated)
static char *do_cmp(struct expr_ctx *c, char *a consume(heap_allocated), const char *op,
	char *b consume(heap_allocated)) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int r;
	const char *value;
	char *result;
	if (c->err) { result = dupstr(c, ""); goto done; }
	/* op is always parse_cmp()'s own peek()-derived token, same as
	 * do_arith()'s op. a and b are always a prior parse_add()'s
	 * withtok(heap_allocated) result -- genuinely null-terminated by
	 * construction (dupstr()'s memcpy() copies the source's own
	 * trailing NUL; numstr()'s snprintf() always terminates its
	 * buffer), but that fact does not survive the consume(heap_allocated)
	 * parameter crossing this function boundary either. */
	__ownership_string_terminated(op);
	__ownership_string_terminated(a);
	__ownership_string_terminated(b);
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

/* c is required: `if (c->err)` dereferences it unconditionally on
 * entry, same as do_arith()/do_cmp(). a and pat are required: rc =
 * regcomp(&re, pat, 0) and rc = regexec(&re, a, ...) each dereference
 * theirs unconditionally once c->err is false. */
withtok(heap_allocated)
static char *do_match(struct expr_ctx *c, char *a consume(heap_allocated),
	char *pat consume(heap_allocated)) __attribute__((nonnull(1, 2, 3), returns_nonnull));
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
			size_t bytes;
			if (!__util_size_add((size_t)len, 1, &bytes)) result = 0;
			else result = malloc(bytes);
			if (!result) { xerr(c, "out of memory"); result = dupstr(c, ""); }
			else {
				/* Safe by regexec()'s own postcondition: pm[1] is a
				 * sub-match of `a` itself, so
				 * 0 <= rm_so <= rm_eo <= strlen(a). Left as an
				 * ntlibc.MemoryContract finding rather than forcing an
				 * annotation -- this proof only became reachable once
				 * do_match()'s own nonnull(1,2,3)/returns_nonnull
				 * removed the spurious paths that previously kept the
				 * analyzer from exploring this deep, and closing it
				 * for real would mean giving src/regex/regex.c's
				 * regexec() a readable_span/extent_at_least contract
				 * tying pmatch[]'s offsets back to its subject
				 * string's own length -- shared regex.h
				 * infrastructure well outside this file's scope. */
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
	for (;;) {
		/* tok is peek(c)'s own already-established argv element --
		 * restated here too, the same reason parse_add()'s
		 * identically-restructured loop needs it restated rather
		 * than relying on peek(c) being inlined twice. */
		const char *tok = peek(c);
		char *rhs;
		if (!tok) break;
		__ownership_string_terminated(tok);
		if (strcmp(tok, ":")) break;
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
	for (;;) {
		/* tok is peek(c)'s own already-established argv element --
		 * restated here too since, unlike parse_mul()'s identically
		 * shaped loop, the analyzer's per-function exploration budget
		 * does not always carry peek()'s internal axiom this far by
		 * inlining alone. */
		const char *tok = peek(c);
		char *rhs;
		if (!tok) break;
		__ownership_string_terminated(tok);
		if (strcmp(tok, "+") && strcmp(tok, "-")) break;
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

int __util_expr_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
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
