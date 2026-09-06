/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * test(1p) / [(1p).  Moved here from src/sh/builtin.c's original bi_test()
 * (which implemented this inline against a struct sh_builtin_ctx) so the
 * same logic backs both the standalone obj/bin/test.exe and the shell
 * built-in -- see src/internal/util.h's header comment for why both exist,
 * and src/sh/builtin.c's for why `test`/`[` are built in at all.
 *
 * XCU test(1p).  Its OPERANDS section fixes the primaries, and its
 * EXTENDED DESCRIPTION fixes something subtler that a naive
 * "tokenise and evaluate" implementation gets wrong: *the meaning of an
 * argument depends on how many arguments there are*.  The standard
 * gives explicit rules for 0, 1, 2, 3 and 4 arguments and says results
 * are unspecified beyond that, which is why `test "(" = ")"` is a
 * string comparison (3 arguments: "$2 is a binary primary") and not a
 * parenthesised group, and why `test ! -n` is a 2-argument negation of
 * the string "-n" rather than a malformed unary primary.  eval_argc()
 * below implements those five cases literally, in the standard's own
 * order, and only falls through to the recursive-descent grammar for
 * the >4 case -- where the standard's XSI paragraph does describe a
 * precedence/associativity evaluation, and where every shell in
 * practice provides one.
 *
 * Exit status is test(1p)'s: 0 for a true expression, 1 for false or
 * null, ">1 An error occurred" -- 2 here, with a diagnostic, for a
 * malformed expression or a non-integer operand of an arithmetic
 * primary.  A silent "false" for a malformed expression would be the
 * same undiagnosable wrongness this project keeps refusing.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "util.h"
#include "ownership_stubs.h" /* __ownership_string_terminated(): restates argv's null-termination through struct texpr's char **v, which the checker can't trace on its own (same idiom as find.c) */

/* test(1p) EXIT STATUS: "0 expression evaluated to true", "1 expression
 * evaluated to false or expression was missing", ">1 An error
 * occurred". */
#define T_TRUE  0
#define T_FALSE 1
#define T_ERR   2

struct texpr {
	char **v;      /* the arguments being evaluated, v[0] is the first */
	size_t n;      /* how many there are */
	size_t i;      /* cursor for the >4-argument grammar */
	int err;       /* set once a diagnostic has been issued */
};

/* t and msg are required: every call site below dereferences t->err
 * unconditionally on entry, and msg is written through the "%s" of
 * both fprintf() branches with no NULL check. arg is deliberately left
 * unmarked -- it is genuinely optional (`terr(t, "argument expected", 0)`
 * in t_primary() below is a real, live NULL, guarded here by
 * `if (arg) fprintf(...)`). */
static void terr(struct texpr *t, const char *msg, const char *arg)
    __attribute__((nonnull(1, 2)));
static void terr(struct texpr *t, const char *msg, const char *arg)
{
	if (t->err) return;
	t->err = 1;
	if (arg) __util_diagf("test: %s: %s\n", arg, msg);
	else __util_diagf("test: %s\n", msg);
}

/* An integer operand of -eq/-ne/-lt/-le/-gt/-ge.  test(1p) calls these
 * operands "integers" with no allowance for anything else, so anything
 * strtol() does not consume in full is an error (status >1), not a
 * silently-zero comparison.  Surrounding blanks are tolerated because
 * field splitting routinely produces them and every historical
 * implementation accepts them. */
/* s and out are required: `while (*p == ...)` (p aliases s) dereferences
 * s unconditionally on entry, and every path that does not bail out
 * through terr() writes `*out` with no NULL check. t is left unmarked --
 * this function never touches it directly, only forwards it to terr(),
 * which already states its own contract. */
static int to_int(struct texpr *t, const char *s, long *out)
    __attribute__((nonnull(2, 3)));
static int to_int(struct texpr *t, const char *s, long *out)
{
	char *end;
	const char *p = s;
	while (*p == ' ' || *p == '\t' || *p == '\n') p++;
	if (!*p) { terr(t, "integer expression expected", s); return -1; }
	*out = strtol(p, &end, 10);
	if (end == p) { terr(t, "integer expression expected", s); return -1; }
	while (*end == ' ' || *end == '\t' || *end == '\n') end++;
	if (*end) { terr(t, "integer expression expected", s); return -1; }
	return 0;
}

static int is_binop(const char *s) __attribute__((nonnull(1), __pure__));
static int is_binop(const char *s)
{
	__ownership_string_terminated(s);
	return !strcmp(s, "=") || !strcmp(s, "!=") ||
	       !strcmp(s, "-eq") || !strcmp(s, "-ne") ||
	       !strcmp(s, "-lt") || !strcmp(s, "-le") ||
	       !strcmp(s, "-gt") || !strcmp(s, "-ge");
}

/* The unary primaries of test(1p)'s OPERANDS section.  -a is
 * deliberately absent: as a *unary* primary it is a non-standard
 * synonym for -e that some shells provide, and providing it would make
 * `test ! -a foo` ambiguous with the -a binary primary that the same
 * page does specify. */
static int is_unop(const char *s) __attribute__((nonnull(1), __pure__));
static int is_unop(const char *s)
{
	if (s[0] != '-' || s[1] == 0 || s[2] != 0) return 0;
	return strchr("bcdefghLnprSstuwxz", s[1]) != 0;
}

/* op and arg are required: `switch (op[1])` dereferences op
 * unconditionally on entry, and every case of that switch -- plus the
 * post-switch `stat(arg, &st)` fallback any op not matched by the first
 * group reaches -- dereferences arg, with no NULL check anywhere in
 * this function. t is left unmarked: never touched directly here, only
 * forwarded to terr(). */
static int do_unary(struct texpr *t, const char *op, const char *arg)
    __attribute__((nonnull(2, 3)));
static int do_unary(struct texpr *t, const char *op, const char *arg) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct stat st;

	switch (op[1]) {
	case 'n': return arg[0] != 0 ? T_TRUE : T_FALSE;
	case 'z': return arg[0] == 0 ? T_TRUE : T_FALSE;
	/* "True if file descriptor number file_descriptor is open and is
	 * associated with a terminal.  False if file_descriptor is not a
	 * valid file descriptor number" -- so a non-numeric operand is
	 * false, not an error. */
	case 't': {
		char *end;
		long fd = strtol(arg, &end, 10);
		if (end == arg || *end || fd < 0 || fd > 0x7fffffff) return T_FALSE;
		return isatty((int)fd) ? T_TRUE : T_FALSE;
	}
	case 'r': return access(arg, R_OK) == 0 ? T_TRUE : T_FALSE;
	case 'w': return access(arg, W_OK) == 0 ? T_TRUE : T_FALSE;
	case 'x': return access(arg, X_OK) == 0 ? T_TRUE : T_FALSE;
	/* "If the final component of pathname is a symbolic link, that
	 * symbolic link is not followed" -- -h and -L are the only two
	 * primaries that use lstat() rather than stat(). */
	case 'h': case 'L':
		if (lstat(arg, &st) < 0) return T_FALSE;
		return S_ISLNK(st.st_mode) ? T_TRUE : T_FALSE;
	default: break;
	}

	if (stat(arg, &st) < 0) return T_FALSE;
	switch (op[1]) {
	case 'e': return T_TRUE;                                     /* resolves at all */
	case 'f': return S_ISREG(st.st_mode) ? T_TRUE : T_FALSE;
	case 'd': return S_ISDIR(st.st_mode) ? T_TRUE : T_FALSE;
	case 'b': return S_ISBLK(st.st_mode) ? T_TRUE : T_FALSE;
	case 'c': return S_ISCHR(st.st_mode) ? T_TRUE : T_FALSE;
	case 'p': return S_ISFIFO(st.st_mode) ? T_TRUE : T_FALSE;
	case 'S': return S_ISSOCK(st.st_mode) ? T_TRUE : T_FALSE;
	case 's': return st.st_size > 0 ? T_TRUE : T_FALSE;
	case 'g': return (st.st_mode & S_ISGID) ? T_TRUE : T_FALSE;
	case 'u': return (st.st_mode & S_ISUID) ? T_TRUE : T_FALSE;
	default: break;
	}
	terr(t, "unknown unary operator", op);
	return T_ERR;
}

static int do_binary(struct texpr *t, const char *a, const char *op, const char *b) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	long x, y;
	__ownership_string_terminated(a);
	__ownership_string_terminated(op);
	__ownership_string_terminated(b);
	if (!strcmp(op, "=")) return strcmp(a, b) == 0 ? T_TRUE : T_FALSE;
	if (!strcmp(op, "!=")) return strcmp(a, b) != 0 ? T_TRUE : T_FALSE;
	if (to_int(t, a, &x) || to_int(t, b, &y)) return T_ERR;
	if (!strcmp(op, "-eq")) return x == y ? T_TRUE : T_FALSE;
	if (!strcmp(op, "-ne")) return x != y ? T_TRUE : T_FALSE;
	if (!strcmp(op, "-lt")) return x < y ? T_TRUE : T_FALSE;
	if (!strcmp(op, "-le")) return x <= y ? T_TRUE : T_FALSE;
	if (!strcmp(op, "-gt")) return x > y ? T_TRUE : T_FALSE;
	if (!strcmp(op, "-ge")) return x >= y ? T_TRUE : T_FALSE;
	terr(t, "unknown binary operator", op);
	return T_ERR;
}

/* ---- the >4-argument grammar ----------------------------------------
 *
 * test(1p): ">4 arguments: The results are unspecified", followed by
 * the XSI paragraph that does specify one -- "combinations of primaries
 * and operators shall be evaluated using the precedence and
 * associativity rules described previously.  In addition, the string
 * comparison binary primaries '=' and '!=' shall have a higher
 * precedence than any unary primary."  -a is left-associative and binds
 * tighter than -o, which is also left-associative.
 *
 * That last sentence is why t_primary() tests for a binary primary
 * *before* it tests for a unary one: with the checks the other way
 * round, `test -n = -n -o x` would consume "-n" as a unary primary and
 * never see the "=" it is the left operand of. */
static int t_oexpr(struct texpr *t);

static int t_primary(struct texpr *t) __attribute__((nonnull(1)));
// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested test-expression grammar
static int t_primary(struct texpr *t)
{
	const char *tok;

	if (t->i >= t->n) { terr(t, "argument expected", 0); return T_ERR; }
	tok = t->v[t->i];
	__ownership_string_terminated(tok);

	if (!strcmp(tok, "(")) {
		int r;
		t->i++;
		r = t_oexpr(t);
		if (t->err) return T_ERR;
		if (t->i < t->n) {
			const char *close = t->v[t->i];
			__ownership_string_terminated(close);
			if (strcmp(close, ")")) { terr(t, "')' expected", 0); return T_ERR; } // NOLINT(bugprone-suspicious-string-compare) -- nonzero intentionally detects a mismatched closing token
		} else {
			terr(t, "')' expected", 0); return T_ERR;
		}
		t->i++;
		return r;
	}
	/* higher precedence than any unary primary -- see above */
	if (t->i + 2 < t->n && is_binop(t->v[t->i + 1])) {
		int r = do_binary(t, t->v[t->i], t->v[t->i + 1], t->v[t->i + 2]);
		t->i += 3;
		return r;
	}
	if (is_unop(tok) && t->i + 1 < t->n) {
		int r = do_unary(t, tok, t->v[t->i + 1]);
		t->i += 2;
		return r;
	}
	/* "string: True if the string string is not the null string" */
	t->i++;
	return tok[0] != 0 ? T_TRUE : T_FALSE;
}

static int t_nexpr(struct texpr *t) __attribute__((nonnull(1)));
// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested test-expression grammar
static int t_nexpr(struct texpr *t)
{
	if (t->i < t->n) {
		const char *tok = t->v[t->i];
		__ownership_string_terminated(tok);
		if (!strcmp(tok, "!")) {
			int r;
			t->i++;
			r = t_nexpr(t);
			if (r == T_ERR || t->err) return T_ERR;
			return r == T_TRUE ? T_FALSE : T_TRUE;
		}
	}
	return t_primary(t);
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested test-expression grammar
static int t_aexpr(struct texpr *t)
{
	int r = t_nexpr(t);
	size_t remaining = t->i < t->n ? t->n - t->i : 0;
	while (remaining > 0 && !t->err && t->i < t->n) {
		const char *tok = t->v[t->i];
		__ownership_string_terminated(tok);
		if (strcmp(tok, "-a")) break;
		{
			int rhs;
			remaining--;
			t->i++;
			rhs = t_nexpr(t);
			/* Evaluated, not short-circuited: an error in either
			 * operand of -a is still an error (status >1), and
			 * skipping the right operand would hide a malformed
			 * one behind a false left. */
			if (r == T_ERR || rhs == T_ERR) r = T_ERR;
			else r = (r == T_TRUE && rhs == T_TRUE) ? T_TRUE : T_FALSE;
		}
	}
	return t->err ? T_ERR : r;
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested test-expression grammar
static int t_oexpr(struct texpr *t)
{
	int r = t_aexpr(t);
	size_t remaining = t->i < t->n ? t->n - t->i : 0;
	while (remaining > 0 && !t->err && t->i < t->n) {
		const char *tok = t->v[t->i];
		__ownership_string_terminated(tok);
		if (strcmp(tok, "-o")) break;
		{
			int rhs;
			remaining--;
			t->i++;
			rhs = t_aexpr(t);
			if (r == T_ERR || rhs == T_ERR) r = T_ERR;
			else r = (r == T_TRUE || rhs == T_TRUE) ? T_TRUE : T_FALSE;
		}
	}
	return t->err ? T_ERR : r;
}

/* test(1p) EXTENDED DESCRIPTION, taken literally and in its own order:
 * "The algorithm for determining the precedence of the operators and
 * the return value that shall be generated is based on the number of
 * arguments presented to test." */
static int eval_argc(struct texpr *t) __attribute__((nonnull(1)));
// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested test-expression grammar
static int eval_argc(struct texpr *t)
{
	char **v = t->v;
	size_t n = t->n;

	switch (n) {
	case 0:
		/* "0 arguments: Exit false (1)." */
		return T_FALSE;
	case 1:
		/* "1 argument: Exit true (0) if $1 is not null; otherwise,
		 * exit false." */
		__ownership_string_terminated(v[0]);
		return v[0][0] != 0 ? T_TRUE : T_FALSE;
	case 2:
		/* "If $1 is '!', exit true if $2 is null, false if $2 is not
		 * null." -- note this is a *string* test of $2, not a
		 * negated evaluation of it, so `test ! -n` is false: it is
		 * the negation of "-n" being a non-null string, not a
		 * malformed unary primary and not "not (-n)". */
		__ownership_string_terminated(v[0]);
		__ownership_string_terminated(v[1]);
		if (!strcmp(v[0], "!")) return v[1][0] == 0 ? T_TRUE : T_FALSE;
		if (is_unop(v[0])) return do_unary(t, v[0], v[1]);
		terr(t, "unary operator expected", v[0]);
		return T_ERR;
	case 3:
		/* "If $2 is a binary primary, perform the binary test of $1
		 * and $3." -- checked first, which is what makes
		 * `test "(" = ")"` a string comparison. */
		__ownership_string_terminated(v[0]);
		__ownership_string_terminated(v[1]);
		__ownership_string_terminated(v[2]);
		if (is_binop(v[1])) return do_binary(t, v[0], v[1], v[2]);
		if (!strcmp(v[0], "!")) {
			struct texpr sub = *t;
			int r;
			sub.v = v + 1; sub.n = 2; sub.i = 0;
			r = eval_argc(&sub);
			t->err = sub.err;
			if (r == T_ERR) return T_ERR;
			return r == T_TRUE ? T_FALSE : T_TRUE;
		}
		/* XSI: "If $1 is '(' and $3 is ')', perform the unary test
		 * of $2" -- i.e. the one-argument (non-null string) test. */
		if (!strcmp(v[0], "(") && !strcmp(v[2], ")")) return v[1][0] != 0 ? T_TRUE : T_FALSE;
		terr(t, "binary operator expected", v[1]);
		return T_ERR;
	case 4:
		/* "If $1 is '!', negate the three-argument test of $2, $3,
		 * and $4." */
		__ownership_string_terminated(v[0]);
		__ownership_string_terminated(v[3]);
		if (!strcmp(v[0], "!")) {
			struct texpr sub = *t;
			int r;
			sub.v = v + 1; sub.n = 3; sub.i = 0;
			r = eval_argc(&sub);
			t->err = sub.err;
			if (r == T_ERR) return T_ERR;
			return r == T_TRUE ? T_FALSE : T_TRUE;
		}
		/* XSI: "If $1 is '(' and $4 is ')', perform the two-argument
		 * test of $2 and $3." */
		if (!strcmp(v[0], "(") && !strcmp(v[3], ")")) {
			struct texpr sub = *t;
			int r;
			sub.v = v + 1; sub.n = 2; sub.i = 0;
			r = eval_argc(&sub);
			t->err = sub.err;
			return r;
		}
		/* fall through to the grammar: "Otherwise, the results are
		 * unspecified", and the XSI precedence rules are a more
		 * useful answer than a diagnostic for e.g.
		 * "-f a -o -f b". */
		break;
	default:
		break;
	}

	t->i = 0;
	{
		int r = t_oexpr(t);
		if (!t->err && t->i != t->n) { terr(t, "unexpected argument", t->v[t->i]); return T_ERR; }
		return t->err ? T_ERR : r;
	}
}

/* argv[0] is either "test" or "[" -- __find_program()'s resolved name for
 * the standalone .exe, or the literal source text for the shell built-in
 * (src/sh/builtin.c registers both names against the same bi_test()). */
int __util_test_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	struct texpr t;
	size_t n = (size_t)argc;
	if (n) n--;

	__ownership_string_terminated(argv[0]); /* argv[0] always exists (argc >= 1) */

	/* "In the second form of the utility, where the utility name used
	 * is [ rather than test, the application shall ensure that the
	 * closing square bracket is a separate argument."  Its absence is
	 * an error, and the bracket itself is "not ... counted in this
	 * algorithm". */
	if (!strcmp(argv[0], "[")) {
		const char *last;
		if (n < 1) { __util_diagf("[: missing `]'\n"); return T_ERR; }
		last = argv[n];
		__ownership_string_terminated(last);
		if (strcmp(last, "]")) { // NOLINT(bugprone-suspicious-string-compare) -- nonzero intentionally detects a mismatched closing bracket argument
			__util_diagf("[: missing `]'\n");
			return T_ERR;
		}
		n--;
	}

	t.v = argv + 1;
	t.n = n;
	t.i = 0;
	t.err = 0;
	return eval_argc(&t);
}

// NOLINTEND(misc-include-cleaner)
