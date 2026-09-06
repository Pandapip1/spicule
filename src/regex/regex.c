/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * regcomp/regexec/regerror/regfree: a small BRE/ERE compiler and a
 * recursive-backtracking matcher, in the mould of Rob Pike's/Russ
 * Cox's "backtrack" virtual machine (see Cox, "Regular Expression
 * Matching: the Virtual Machine Approach", swtch.com/~rsc/regexp/
 * regexp2.html): the pattern compiles to a flat array of instructions
 * (CHAR/ANY/SET/BOL/EOL/SAVE/JMP/SPLIT/MATCH) and regexec() walks it
 * recursively, backtracking through SPLIT/SAVE on failure.
 *
 * Scope, deliberately: anchors (^ $), alternation (|, ERE only),
 * grouping/capture (BRE "\(...\)" vs ERE "(...)"), the three simple
 * repeat operators plus bounded/unbounded intervals ({m,n}, \{m,n\}
 * in BRE), and bracket expressions with ranges, POSIX named classes
 * ([:alpha:] etc.), and negation. cflags: REG_EXTENDED, REG_ICASE,
 * REG_NOSUB, REG_NEWLINE. eflags: REG_NOTBOL, REG_NOTEOL. Subexpression
 * capture via regmatch_t, and regerror()'s size-query idiom.
 *
 * Not implemented -- a documented boundary, not a silent gap:
 *
 *   - Collating symbols ([.x.]) and equivalence classes ([=x=])
 *     beyond a single character. src/misc/locale.c: this library is
 *     C/POSIX-locale-only, and in the C locale every collating
 *     element and every equivalence class *is* just its one
 *     character (no multi-character collating elements, no locale-
 *     defined equivalences) -- so a single-character [.x.]/[=x=] is
 *     implemented (it is exactly the bracket-expression member 'x'),
 *     and anything longer is REG_ECOLLATE: this locale genuinely does
 *     not define one, not merely "not looked up".
 *
 * BRE backreferences compile to I_BACKREF and replay the earlier
 * capture at match time.  Matching explores every alternative at the
 * first viable start position and retains the longest whole match,
 * rather than accepting the first successful branch.
 *
 * BOUNDED MATCHING, AND WHAT regexec() REPORTS WHEN IT RUNS OUT.
 *
 * A backtracking VM has no polynomial bound on the work one match
 * attempt can take, so this one carries two explicit budgets -- see
 * MAX_STEPS and MAX_BACKTRACK below for the numbers and for why each
 * is where it is.  Exhausting either makes regexec() return
 * REG_ESPACE.
 *
 * That is a deliberate choice of code, not an invented one.  XBD
 * <regex.h> defines REG_ESPACE as "Out of memory", and XSH regcomp()
 * DESCRIPTION says of the matcher: "If regexec() finds a match, it
 * shall return zero; otherwise, it shall return non-zero indicating
 * either no match or an error."  So an error return from regexec() is
 * contemplated by the standard, and REG_ESPACE is the only code in the
 * header that means "a resource ran out" rather than "your pattern was
 * malformed" (those are all regcomp()'s).  The budgets ARE a resource;
 * a match attempt that hits one has not been shown not to match.
 *
 * Returning REG_NOMATCH instead would be worse than useless: it is a
 * definite, wrong answer where the implementation in fact has no
 * answer, and a caller cannot tell it from a real non-match.  Until
 * 2026-08 that is what MAX_STEPS did.
 *
 * The budgets are also the reason this matcher is iterative rather
 * than recursive.  It used to recurse once per SPLIT and once per
 * SAVE, so the real limit was the C stack -- unbounded and
 * unreportable: a repeat whose body can match the empty string
 * ("(a*)*b", "()*a", or a bracket expression that can match nothing)
 * compiles to a SPLIT/JMP loop that makes no input progress, and it
 * killed the process outright long before MAX_STEPS could count to
 * two million.  Found by fuzz/fuzz_regex.c.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <regex.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* ---- bytecode ---------------------------------------------------- */

enum { I_CHAR, I_ANY, I_SET, I_BOL, I_EOL, I_SAVE, I_BACKREF,
	I_JMP, I_SPLIT, I_MATCH };

struct inst {
	unsigned char op;
	int c;		/* I_CHAR */
	int set;	/* I_SET: index into rx->sets */
	int x, y;	/* I_JMP/I_SPLIT targets; I_SAVE: slot number in x */
};

struct bracket {
	unsigned char bits[32];	/* 256 bits, one per byte value */
};

struct rx {
	struct inst *prog;
	int nprog, capprog;
	struct bracket *sets;
	int nsets, capsets;
	int ncap;	/* re_nsub + 1 */
	int cflags;
};

/* bs required at every call site (always &ps->rx->sets[idx], a slot
 * newset() has already allocated within rx->sets, never NULL), and
 * dereferenced unconditionally here. */
static void setbit(struct bracket *bs, int c, int icase) __attribute__((nonnull(1)));
static void setbit(struct bracket *bs, int c, int icase) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	unsigned char cc = (unsigned char)c;
	if (icase) cc = (unsigned char)tolower(cc);
	bs->bits[cc >> 3] |= (unsigned char)(1u << (cc & 7));
}

static int testbit(const struct bracket *bs, int c, int icase) __attribute__((nonnull(1)));
static int testbit(const struct bracket *bs, int c, int icase) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	unsigned char cc = (unsigned char)c;
	if (icase) cc = (unsigned char)tolower(cc);
	return (bs->bits[cc >> 3] >> (cc & 7)) & 1;
}

/* ---- parser -------------------------------------------------------
 * ps->err, once set non-zero, is sticky: every emit helper below
 * checks it first and becomes a no-op, so a parse can keep "running"
 * (simplifying the recursive-descent control flow -- no need to check
 * a return code after every sub-call) without doing further real work
 * once something has failed. */
struct parser {
	const char *p;
	int ere;
	int icase;
	int err;
	struct rx *rx;
	int ngroup;	/* next capture group number, starts at 1 */
	unsigned closed;	/* closed BRE groups 1..9, valid backref targets */
};

/* Ceiling on the whole compiled program, in instructions -- the bound
 * DUP_MAX is not.
 *
 * DUP_MAX bounds each interval's count *individually*, and nothing
 * bounded their product: an interval's body is unrolled into real
 * instructions, so a repeat applied to a repeat multiplies. Found by
 * fuzz/fuzz_regex.c, which reached
 *
 *     ERROR: libFuzzer: out-of-memory (malloc(2684354560))
 *       ... realloc -> emit -> emit_reloc -> apply_repeat -> regcomp
 *
 * from a 24-byte ERE. Measured against this file before the bound:
 * "a{2}{202}{2024}" compiled to 817,696 instructions (58 MB RSS under
 * ASan) and "a{2}{202}{2024}?{2}{202}" was still allocating past 2 GB
 * when it was killed. There is no pattern length involved -- the
 * amplification is 2 x 202 x 2024 and then again -- so no cap on the
 * pattern could have caught it.
 *
 * 1M instructions is ~20 MB at the 20 bytes struct inst occupies. That
 * is deliberately generous rather than tight, so that the bound is a
 * backstop against amplification and not a new restriction on ordinary
 * patterns: it admits every single DUP_MAX interval whose body is up
 * to 32 instructions, and it agrees with glibc on all four nested
 * cases measured on the same day ("a{2}{202}{2024}" compiles in both;
 * "a{2}{202}{2024}?{2}{202}" and "a{1000}{1000}{1000}" are refused by
 * both).
 *
 * WHY REG_ESPACE AND NOT REG_BADBR. <regex.h> offers both readings and
 * they say different things to a caller: REG_BADBR is a statement
 * about the pattern ("your braces are wrong"), REG_ESPACE about a
 * resource ("there was no room"). REG_ESPACE, for three reasons.
 *
 * First, it is true and REG_BADBR is not: every individual brace in
 * "a{2}{202}{2024}?{2}{202}" is well-formed and within DUP_MAX. A
 * caller told REG_BADBR would go looking for a syntax error that is
 * not there. What is excessive is the size of the program the pattern
 * denotes, which is a fact about this compiler's expansion strategy --
 * an implementation that built a counted loop instead would compile
 * the same pattern without complaint.
 *
 * Second, it is what the reference implementation does: glibc returns
 * REG_ESPACE (12, "Memory exhausted") for exactly these nested-product
 * patterns, and reserves its brace codes for malformed braces.
 * Measured, same day, same programme as the DUP_MAX note above.
 *
 * Third, it is consistent with the rest of this file: regexec()'s
 * MAX_STEPS and MAX_BACKTRACK already report REG_ESPACE for "a budget
 * ran out", and this is the compile-time member of that family.
 *
 * The cost of the choice is that REG_ESPACE here is indistinguishable
 * from a genuine malloc() failure. That is the same trade POSIX itself
 * makes by having no "too big" code, and it is the direction that does
 * not require lying about the pattern. */
#define MAX_PROG (1 << 20)

/* ps is required throughout this file's whole recursive-descent parser
 * chain: every one of the parser functions below ultimately receives
 * it forwarded from regcomp()'s own `struct parser ps;` local (via
 * `&ps`), and none of them defensively checks it before touching
 * ps->p/ps->err/ps->rx/ps->icase/ps->ngroup/ps->ere/ps->closed. */
static int emit(struct parser *ps, int op, int c, int set, int x, int y)
    __attribute__((nonnull(1)));
static int emit(struct parser *ps, int op, int c, int set, int x, int y) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct rx *rx = ps->rx;
	if (ps->err) return -1;
	/* The ceiling, checked before the increment, so nprog is never
	 * greater than MAX_PROG and -- MAX_PROG being four orders of
	 * magnitude below INT_MAX -- can never overflow the int it is
	 * stored in.  That overflow was the second half of the defect this
	 * bound fixes: a large enough interval product wrapped nprog
	 * negative before any allocation was big enough to fail, so the
	 * "if (!n) REG_ESPACE" below could not have caught it.  See
	 * MAX_PROG. */
	if (rx->nprog >= MAX_PROG) { ps->err = REG_ESPACE; return -1; }
	if (rx->nprog == rx->capprog) {
		int ncap = rx->capprog ? rx->capprog * 2 : 32;
		struct inst *n;
		if (ncap > MAX_PROG) ncap = MAX_PROG;
		n = realloc(rx->prog, (size_t)ncap * sizeof *n);
		if (!n) { ps->err = REG_ESPACE; return -1; }
		rx->prog = n;
		rx->capprog = ncap;
	}
	rx->prog[rx->nprog].op = (unsigned char)op;
	rx->prog[rx->nprog].c = c;
	rx->prog[rx->nprog].set = set;
	rx->prog[rx->nprog].x = x;
	rx->prog[rx->nprog].y = y;
	return rx->nprog++;
}

static int newset(struct parser *ps) __attribute__((nonnull(1)));
static int newset(struct parser *ps)
{
	struct rx *rx = ps->rx;
	if (ps->err) return -1;
	if (rx->nsets == rx->capsets) {
		int ncap = rx->capsets ? rx->capsets * 2 : 8;
		struct bracket *n = realloc(rx->sets, (size_t)ncap * sizeof *n);
		if (!n) { ps->err = REG_ESPACE; return -1; }
		rx->sets = n;
		rx->capsets = ncap;
	}
	memset(&rx->sets[rx->nsets], 0, sizeof rx->sets[rx->nsets]);
	return rx->nsets++;
}

static const struct { const char *name; size_t len; int (*fn)(int); } classes[] = {
#define CLASS(name, fn) { name, sizeof name - 1, fn }
	CLASS("alpha", isalpha), CLASS("digit", isdigit), CLASS("alnum", isalnum),
	CLASS("upper", isupper), CLASS("lower", islower), CLASS("space", isspace),
	CLASS("blank", isblank), CLASS("punct", ispunct), CLASS("cntrl", iscntrl),
	CLASS("graph", isgraph), CLASS("print", isprint), CLASS("xdigit", isxdigit),
#undef CLASS
};

/* ps required, same as every parser function above. name is passed to
 * strncmp() unconditionally regardless of len (this tree's own
 * established mem/str doctrine, see 242ed40), so it is required too
 * -- every real call site passes a substring pointer straight out of
 * parse_bracket()'s own scan, never NULL. bs is left unmarked: forward-
 * only into setbit(), never dereferenced by emit_class() itself. */
static int emit_class(struct parser *ps, struct bracket *bs, const char *name, size_t len)
    __attribute__((nonnull(1, 3)));
static int emit_class(struct parser *ps, struct bracket *bs, const char *name, size_t len)
{
	size_t i;
	int c;
	for (i = 0; i < sizeof classes / sizeof *classes; i++)
		if (classes[i].len == len && !strncmp(classes[i].name, name, len)) {
			for (c = 0; c < 256; c++)
				if (classes[i].fn(c)) setbit(bs, c, ps->icase);
			return 0;
		}
	ps->err = REG_ECTYPE;
	return -1;
}

/* Parses a bracket expression; ps->p is positioned just after the
 * opening '['. Emits I_SET on success. */
static void parse_bracket(struct parser *ps) __attribute__((nonnull(1)));
static void parse_bracket(struct parser *ps)
{
	int idx = newset(ps);
	struct bracket *bs;
	int negate = 0, first = 1;

	if (idx < 0) return;
	bs = &ps->rx->sets[idx];

	if (*ps->p == '^') { negate = 1; ps->p++; }

	for (;;) {
		int c;

		if (*ps->p == '\0') { ps->err = REG_EBRACK; return; }
		if (*ps->p == ']' && !first) break;
		first = 0;

		if (ps->p[0] == '[' && ps->p[1] == ':') {
			const char *start = ps->p + 2;
			const char *q = strchr(start, ':');
			if (!q || q[1] != ']') { ps->err = REG_EBRACK; return; }
			if (emit_class(ps, bs, start, (size_t)(q - start)) < 0) return;
			ps->p = q + 2;
			continue;
		}
		if (ps->p[0] == '[' && (ps->p[1] == '.' || ps->p[1] == '=')) {
			char kind = ps->p[1];
			const char *start = ps->p + 2;
			const char *q = start;
			while (*q && !(*q == kind && q[1] == ']')) q++;
			if (!*q) { ps->err = REG_EBRACK; return; }
			if (q - start != 1) { ps->err = REG_ECOLLATE; return; }	/* see file header */
			setbit(bs, (unsigned char)*start, ps->icase);
			ps->p = q + 2;
			continue;
		}

		c = (unsigned char)*ps->p++;
		if (*ps->p == '-' && ps->p[1] != ']' && ps->p[1] != '\0') {
			int hi, k;
			ps->p++;
			hi = (unsigned char)*ps->p++;
			if (hi < c) { ps->err = REG_ERANGE; return; }
			for (k = c; k < hi + 1; k++) setbit(bs, k, ps->icase);
			continue;
		}
		setbit(bs, c, ps->icase);
	}
	ps->p++;	/* skip ']' */

	if (negate) {
		int i;
		for (i = 0; i < 32; i++) bs->bits[i] = (unsigned char)~bs->bits[i];
		/* "a non-matching list ... shall not match a <newline>"
		 * under REG_NEWLINE (regcomp.html DESCRIPTION). */
		if (ps->rx->cflags & REG_NEWLINE) bs->bits['\n' >> 3] &= (unsigned char)~(1u << ('\n' & 7));
	}
	emit(ps, I_SET, 0, idx, 0, 0);
}

/* Bound on a {m,n} or \{m,n\} interval's repeat count -- unrolled into
 * that many real instructions, so an unbounded count is a compile-
 * time and run-time size bomb. glibc's RE_DUP_MAX (a non-POSIX-
 * mandated but widely followed convention) is 32767; this
 * implementation uses the same number and reports REG_BADBR past it.
 *
 * (An earlier version of this comment said glibc reports REG_BADBR
 * too. Measured 2026-08-24 against glibc 2.39: regcomp("a{32768}",
 * REG_EXTENDED) returns 15, REG_ESIZE, "Regular expression too big" --
 * a GNU extension that is not in POSIX's <regex.h> and so not
 * available here. REG_BADBR stays: XBD <regex.h> defines it as
 * "Content of '\{\}' invalid: not a number, number too large, more
 * than two numbers, first larger than second", and a single count past
 * DUP_MAX is literally "number too large".) */
#define DUP_MAX 32767

/* Forward decls for the mutually-recursive ERE/BRE grammars. ps
 * required, same as every parser function in this file (see emit()'s
 * own comment above). */
static void ere_alt(struct parser *ps) __attribute__((nonnull(1)));
static void bre_branch(struct parser *ps) __attribute__((nonnull(1)));

/* Parses a {m,n} / {m,} / {m} interval body; ps->p is just after '{'.
 * *pm and *pn receive the bounds (*pn == -1 means unbounded). Leaves
 * ps->p just after the interval's own closing brace (ERE: '}'; BRE:
 * the caller consumes the trailing '\}'). */
static void parse_bound(struct parser *ps, int *pm, int *pn) __attribute__((nonnull(1)));
static void parse_bound(struct parser *ps, int *pm, int *pn)
{
	int m = 0, n = -1, any = 0;
	if (!isdigit((unsigned char)*ps->p)) { ps->err = REG_BADBR; return; }
	while (isdigit((unsigned char)*ps->p)) { m = m * 10 + (*ps->p++ - '0'); any = 1; if (m > DUP_MAX) { ps->err = REG_BADBR; return; } }
	(void)any;
	if (*ps->p == ',') {
		ps->p++;
		if (isdigit((unsigned char)*ps->p)) {
			n = 0;
			while (isdigit((unsigned char)*ps->p)) { n = n * 10 + (*ps->p++ - '0'); if (n > DUP_MAX) { ps->err = REG_BADBR; return; } }
		}
	} else {
		n = m;
	}
	if (n != -1 && n < m) { ps->err = REG_BADBR; return; }
	*pm = m; *pn = n;
}

/* Re-emits len instructions from saved[] (a verbatim copy of some
 * earlier [start, start+len) span) at the program's current position,
 * adjusting every JMP/SPLIT target by delta = (new base) - (old base
 * == the `start` saved[] was copied from). A JMP/SPLIT target inside
 * saved[] is always internal to that span (nothing compiled before
 * `start` can have needed to reference something at `start` or later,
 * since compilation only ever moves forward) -- SAVE's own "x" is a
 * capture-slot number, not an instruction index, and is copied as-is.
 * This is what makes it safe to relocate a saved atom that itself
 * contains a nested group or a nested repeat, not just a single plain
 * instruction. */
/* saved is required (subscripted unconditionally in the loop below,
 * `saved[i]`, for every one of the len iterations this is called
 * with); ps is deliberately NOT marked -- this function only ever
 * forwards it into emit(), never dereferencing it itself. */
static void emit_reloc(struct parser *ps, const struct inst *saved, int len, int delta)
    __attribute__((nonnull(2)));
static void emit_reloc(struct parser *ps, const struct inst *saved, int len, int delta) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int i;
	for (i = 0; i < len; i++) {
		int x = saved[i].x, y = saved[i].y;
		if (saved[i].op == I_JMP) x += delta;
		else if (saved[i].op == I_SPLIT) { x += delta; y += delta; }
		emit(ps, saved[i].op, saved[i].c, saved[i].set, x, y);
	}
}

/* Wraps the instructions from [start, ps->rx->nprog) -- the atom just
 * compiled -- in whichever repeat operator follows, if any. Reports
 * REG_BADRPT if a repeat operator appears with no preceding atom
 * (start == ps->rx->nprog, i.e. nothing was actually emitted). */
static void apply_repeat(struct parser *ps, int start, int had_atom) __attribute__((nonnull(1)));
static void apply_repeat(struct parser *ps, int start, int had_atom) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	for (;;) {
		char c = *ps->p;
		int is_star = (c == '*');
		/* POSIX BRE has no bare '+'/'?' repeat operator: only '*'
		 * and "\{m,n\}" are BRE repeat operators, and regcomp.html's
		 * ERE grammar is where '+'/'?' get their one-or-more/
		 * zero-or-one meaning -- in BRE proper a bare '+' or '?' is
		 * an ordinary character (regcomp.html DESCRIPTION, BRE
		 * "Ordinary Characters": "A <circumflex> ('^') ... and a
		 * <dollar-sign> ('$') ... are special ... All other
		 * characters ... are ordinary"; '+'/'?' are not given
		 * special meaning anywhere in the BRE grammar). Gating these
		 * on ps->ere, like is_brace already does two lines down, is
		 * the fix for that: an unguarded `c == '+'`/`c == '?'` here
		 * let ERE's quantifier meaning leak into BRE mode, so e.g.
		 * "a+b" under cflags 0 (BRE) wrongly matched "aaab"/"ab"
		 * instead of matching only the literal three characters
		 * "a+b". Found via test/util-grep.c's test_grep_bre_basic. */
		int is_plus = ps->ere && c == '+';
		int is_quest = ps->ere && c == '?';
		int is_brace = (ps->ere && c == '{') || (!ps->ere && c == '\\' && ps->p[1] == '{');
		int len = ps->rx->nprog - start;
		struct inst *restrict saved;

		if (!is_star && !is_plus && !is_quest && !is_brace) return;
		if (!had_atom) { ps->err = REG_BADRPT; return; }

		saved = malloc((size_t)(len > 0 ? len : 1) * sizeof *saved);
		if (!saved) { ps->err = REG_ESPACE; return; }
		for (int i = 0; i < len; i++) saved[i] = ps->rx->prog[start + i];
		ps->rx->nprog = start;	/* rewind: rebuild the atom inside the repeat wrapper */

		if (is_star || is_plus || is_quest) {
			int split;
			ps->p++;
			if (is_star) {
				split = emit(ps, I_SPLIT, 0, 0, 0, 0);
				emit_reloc(ps, saved, len, ps->rx->nprog - start);
				emit(ps, I_JMP, 0, 0, split, 0);
				if (split >= 0) { ps->rx->prog[split].x = split + 1; ps->rx->prog[split].y = ps->rx->nprog; }
			} else if (is_plus) {
				int body = ps->rx->nprog;
				emit_reloc(ps, saved, len, body - start);
				split = emit(ps, I_SPLIT, 0, 0, body, 0);
				if (split >= 0) ps->rx->prog[split].y = ps->rx->nprog;
			} else {	/* is_quest */
				split = emit(ps, I_SPLIT, 0, 0, 0, 0);
				emit_reloc(ps, saved, len, ps->rx->nprog - start);
				if (split >= 0) { ps->rx->prog[split].x = split + 1; ps->rx->prog[split].y = ps->rx->nprog; }
			}
		} else {
			/* {m,n} / \{m,n\} */
			int m, n, k;
			ps->p += ps->ere ? 1 : 2;	/* skip '{' or '\{' */
			parse_bound(ps, &m, &n);
			if (!ps->err) {
				if (ps->ere) {
					if (*ps->p != '}') ps->err = *ps->p ? REG_BADBR : REG_EBRACE;
					else ps->p++;
				} else {
					if (ps->p[0] != '\\' || ps->p[1] != '}')
						ps->err = *ps->p ? REG_BADBR : REG_EBRACE;
					else ps->p += 2;
				}
			}
			if (ps->err) { free(saved); return; }

			/* Refuse an expansion that would not fit BEFORE
			 * emitting any of it.  Two reasons it is here and not
			 * left to emit()'s own ceiling: the emit_reloc() loops
			 * below would otherwise spin m x len times with every
			 * call a no-op once ps->err is set (up to 32767 x
			 * MAX_PROG iterations doing nothing), and the caller
			 * gets the diagnosis from the operator responsible
			 * rather than from whichever instruction happened to
			 * be the one over the line.
			 *
			 * `copies` is the number of times the atom is unrolled:
			 * n for a bounded {m,n} (m mandatory plus n-m optional),
			 * m+1 for {m,} (m mandatory plus one repeatable tail).
			 * `per` adds the SPLIT each optional copy carries.  The
			 * test is a division rather than `copies * per >
			 * room`, because that product is what overflows: m and
			 * n reach DUP_MAX and len reaches MAX_PROG, so it does
			 * not fit in the 32-bit unsigned long this library
			 * targets. */
			{
				unsigned long copies = (n == -1) ? (unsigned long)m + 1UL
				                                 : (unsigned long)n;
				unsigned long per = (unsigned long)len + 1UL;
				unsigned long room = (unsigned long)(MAX_PROG - start);
				if (copies != 0UL && per > room / copies) {
					ps->err = REG_ESPACE;
					free(saved);
					return;
				}
			}

			if (m == 0 && n == -1) {
				/* {0,} === * */
				int split = emit(ps, I_SPLIT, 0, 0, 0, 0);
				emit_reloc(ps, saved, len, ps->rx->nprog - start);
				emit(ps, I_JMP, 0, 0, split, 0);
				if (split >= 0) { ps->rx->prog[split].x = split + 1; ps->rx->prog[split].y = ps->rx->nprog; }
			} else {
				for (k = 0; k < m; k++) emit_reloc(ps, saved, len, ps->rx->nprog - start);
				if (n == -1) {
					/* m mandatory copies followed by zero or more. */
					int split = emit(ps, I_SPLIT, 0, 0, 0, 0);
					emit_reloc(ps, saved, len, ps->rx->nprog - start);
					emit(ps, I_JMP, 0, 0, split, 0);
					if (split >= 0) {
						ps->rx->prog[split].x = split + 1;
						ps->rx->prog[split].y = ps->rx->nprog;
					}
				} else {
					/* (n - m) further optional copies, sequential
					 * (see file header on why flat "?  ?  ?" is
					 * equivalent to the fully nested form here). */
					for (k = 0; k < n - m; k++) {
						int split = emit(ps, I_SPLIT, 0, 0, 0, 0);
						emit_reloc(ps, saved, len, ps->rx->nprog - start);
						if (split >= 0) { ps->rx->prog[split].x = split + 1; ps->rx->prog[split].y = ps->rx->nprog; }
					}
				}
			}
		}
		/* POSIX leaves a stacked repeat ("a**") unspecified; looping
		 * back here just applies the next operator to the whole
		 * wrapped form, rather than rejecting it. */
		free(saved);
	}
}

/* A single escaped character's *literal* meaning, used by both
 * grammars for an escape this implementation does not give special
 * syntax to (see the file header: undefined escapes fall back to the
 * literal character, backslash dropped). */
static int esc_literal(struct parser *ps) __attribute__((nonnull(1)));
static int esc_literal(struct parser *ps)
{
	if (*ps->p == '\0') { ps->err = REG_EESCAPE; return -1; }
	return (unsigned char)*ps->p++;
}

/* ---- ERE ------------------------------------------------------------ */

static void ere_atom(struct parser *ps) __attribute__((nonnull(1)));
// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested regular-expression grammar
static void ere_atom(struct parser *ps)
{
	int c = (unsigned char)*ps->p;

	if (c == '(') {
		int g = ps->ngroup;
		if (g < 0 || g >= MAX_PROG / 2) { ps->err = REG_ESPACE; return; }
		ps->ngroup = g + 1;
		ps->p++;
		emit(ps, I_SAVE, 0, 0, 2 * g, 0);
		ere_alt(ps);
		/* Sticky error, as for the emit helpers above: a group whose
		 * body already failed has not been shown to be unbalanced --
		 * the parse simply stopped where it was. Without this,
		 * "(a\" reports the missing ')' this return then walks past
		 * rather than the REG_EESCAPE esc_literal() diagnosed. */
		if (ps->err) return;
		if (*ps->p != ')') { ps->err = REG_EPAREN; return; }
		ps->p++;
		emit(ps, I_SAVE, 0, 0, 2 * g + 1, 0);
		return;
	}
	if (c == '.') { ps->p++; emit(ps, I_ANY, 0, 0, 0, 0); return; }
	if (c == '^') { ps->p++; emit(ps, I_BOL, 0, 0, 0, 0); return; }
	if (c == '$') { ps->p++; emit(ps, I_EOL, 0, 0, 0, 0); return; }
	if (c == '[') { ps->p++; parse_bracket(ps); return; }
	if (c == '\\') { ps->p++; c = esc_literal(ps); if (ps->err) return; emit(ps, I_CHAR, ps->icase ? tolower(c) : c, 0, 0, 0); return; }
	ps->p++;
	emit(ps, I_CHAR, ps->icase ? tolower(c) : c, 0, 0, 0);
}

/* ps required, same as every parser function in this file -- though
 * its own flagged finding here (`*ps->p` at the top of the loop below)
 * is NOT actually about ps itself: the companion core.NullDereference
 * diagnostic at that exact line reads "Dereference of null pointer
 * (loaded from field 'p')", i.e. it is ps->p's own VALUE that is
 * unproven, not ps. That value is regcomp()'s own `pattern` argument,
 * unmodified (`ps.p = pattern;`, then straight into `bre_branch(&ps)`/
 * `ere_alt(&ps)` before ps.p is ever advanced) -- the real fix is
 * regcomp()'s own now-nonnull `pattern` parameter, not anything
 * expressible on ere_branch()'s own signature. Marked here anyway
 * because ps is still independently required for this function's own
 * other, ordinary field accesses. */
static void ere_branch(struct parser *ps) __attribute__((nonnull(1)));
// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested regular-expression grammar
static void ere_branch(struct parser *ps)
{
	int first = 1;
	for (;;) {
		int c = (unsigned char)*ps->p;
		int start;
		if (c == '\0' || c == '|' || c == ')') return;
		/* Unlike BRE's leading '*', ERE gives none of its repeat
		 * operators a "literal if first" carve-out (regcomp.html's
		 * ERE grammar has no production for a bare repeat operator
		 * starting a branch) -- ere_atom() below has no case for
		 * '*'/'+'/'?'/'{' either, so without this check it would
		 * fall through to their generic literal-character handling
		 * and this would never be reported as the BADRPT it is. */
		if (first && (c == '*' || c == '+' || c == '?' || c == '{')) { ps->err = REG_BADRPT; return; }
		start = ps->rx->nprog;
		ere_atom(ps);
		if (ps->err) return;
		apply_repeat(ps, start, 1);
		if (ps->err) return;
		first = 0;
	}
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested regular-expression grammar
static void ere_alt(struct parser *ps)
{
	int start = ps->rx->nprog;
	ere_branch(ps);
	if (ps->err) return;
	if (*ps->p == '|') {
		int len1 = ps->rx->nprog - start, split, jmp;
		struct inst *restrict saved = malloc((size_t)(len1 > 0 ? len1 : 1) * sizeof *saved);
		if (!saved) { ps->err = REG_ESPACE; return; }
		for (int i = 0; i < len1; i++) saved[i] = ps->rx->prog[start + i];
		ps->rx->nprog = start;

		split = emit(ps, I_SPLIT, 0, 0, 0, 0);
		emit_reloc(ps, saved, len1, ps->rx->nprog - start);
		free(saved);
		jmp = emit(ps, I_JMP, 0, 0, 0, 0);
		if (split >= 0) ps->rx->prog[split].x = split + 1;
		ps->p++;	/* '|' */
		if (split >= 0) ps->rx->prog[split].y = ps->rx->nprog;
		ere_alt(ps);	/* right-recursive: remaining branches */
		if (jmp >= 0) ps->rx->prog[jmp].x = ps->rx->nprog;
	}
}

/* ---- BRE -------------------------------------------------------------
 * No alternation, grouping is "\(...\)", '*' is the only simple repeat
 * operator (literal if it is the first character of the whole pattern
 * or of a "\(" subexpression), intervals are "\{m,n\}", and '^'/'$'
 * are anchors only at the very start/end of the whole pattern. */
static void bre_atom(struct parser *ps, int at_start) __attribute__((nonnull(1)));
// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested regular-expression grammar
static void bre_atom(struct parser *ps, int at_start)
{
	int c = (unsigned char)*ps->p;

	if (c == '\\' && ps->p[1] == '(') {
		int g = ps->ngroup;
		if (g < 0 || g >= MAX_PROG / 2) { ps->err = REG_ESPACE; return; }
		ps->ngroup = g + 1;
		ps->p += 2;
		emit(ps, I_SAVE, 0, 0, 2 * g, 0);
		bre_branch(ps);
		if (ps->err) return;	/* sticky, as in ere_atom() above */
		if (ps->p[0] != '\\' || ps->p[1] != ')') { ps->err = REG_EPAREN; return; }
		ps->p += 2;
		emit(ps, I_SAVE, 0, 0, 2 * g + 1, 0);
		if (g >= 0 && g <= 9) ps->closed |= 1u << g;
		return;
	}
	if (c == '\\' && ps->p[1] >= '1' && ps->p[1] <= '9') {
		int g = ps->p[1] - '0';
		if (!(ps->closed & (1u << g))) { ps->err = REG_ESUBREG; return; }
		ps->p += 2;
		emit(ps, I_BACKREF, g, 0, 0, 0);
		return;
	}
	if (c == '.') { ps->p++; emit(ps, I_ANY, 0, 0, 0, 0); return; }
	if (c == '^' && at_start) { ps->p++; emit(ps, I_BOL, 0, 0, 0, 0); return; }
	if (c == '$' && ps->p[1] == '\0') { ps->p++; emit(ps, I_EOL, 0, 0, 0, 0); return; }
	if (c == '$' && ps->p[1] == '\\' && ps->p[2] == ')') { ps->p++; emit(ps, I_EOL, 0, 0, 0, 0); return; }	/* end of a \(...\) */
	if (c == '[') { ps->p++; parse_bracket(ps); return; }
	if (c == '\\') { ps->p++; c = esc_literal(ps); if (ps->err) return; emit(ps, I_CHAR, ps->icase ? tolower(c) : c, 0, 0, 0); return; }
	ps->p++;
	emit(ps, I_CHAR, ps->icase ? tolower(c) : c, 0, 0, 0);
}

/* Same "ps required, but its own flagged finding (ps->p[0] in the loop
 * below) traces to regcomp()'s own pattern parameter instead" nuance
 * as ere_branch() above -- see that function's own comment. */
// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested regular-expression grammar
static void bre_branch(struct parser *ps)
{
	int first = 1;
	for (;;) {
		int c0 = (unsigned char)ps->p[0];
		int c1 = c0 ? (unsigned char)ps->p[1] : 0;	/* short-circuit: never index past a NUL */
		int start;
		/* A branch ends at the end of the pattern or at a "\)". A
		 * lone trailing backslash is NEITHER: it is the incomplete
		 * escape <regex.h>'s error table calls REG_EESCAPE, so it is
		 * handed to bre_atom() like any other backslash and
		 * esc_literal() finds the missing character. Ending the
		 * branch on it instead left it unconsumed, and regcomp()'s
		 * leftover-input check below then blamed it on an unbalanced
		 * "\(" -- the ERE path, which has never had such a carve-out,
		 * answered REG_EESCAPE for the same pattern. */
		int is_end = (c0 == '\0') || (c0 == '\\' && c1 == ')');
		if (is_end) return;

		/* A leading '*' is an ordinary character (regcomp.html
		 * DESCRIPTION: "The <asterisk> ... is an ordinary character
		 * if it is the first character of an entire BRE (after an
		 * initial '^', if any) or the first character of a
		 * subexpression"). apply_repeat() below only ever sees '*'
		 * after start != nprog once first==0, so it is never treated
		 * as a repeat here on the very first atom. */
		start = ps->rx->nprog;
		bre_atom(ps, first);
		if (ps->err) return;
		if (first && c0 == '^') continue;
		if (!first || (c0 != '*'))
			apply_repeat(ps, start, 1);
		first = 0;
	}
}

/* ---- compile / exec / error / free ------------------------------- */

int regcomp(regex_t *__restrict preg construct(regex_compiled), const char *__restrict pattern, int cflags)
{
	struct parser ps;
	struct rx *rx;

	rx = malloc(sizeof *rx);
	if (!rx) return REG_ESPACE;
	memset(rx, 0, sizeof *rx);
	rx->cflags = cflags;

	memset(&ps, 0, sizeof ps);
	ps.p = pattern;
	ps.ere = (cflags & REG_EXTENDED) != 0;
	ps.icase = (cflags & REG_ICASE) != 0;
	ps.rx = rx;
	ps.ngroup = 1;

	emit(&ps, I_SAVE, 0, 0, 0, 0);
	if (ps.ere) ere_alt(&ps);
	else bre_branch(&ps);
	/* Anything left unconsumed is a stray closing delimiter (ERE ')'
	 * with no opener, or a BRE '\)' with no opener). */
	if (!ps.err && *ps.p != '\0') ps.err = REG_EPAREN;
	if (!ps.err) emit(&ps, I_SAVE, 0, 0, 1, 0);
	if (!ps.err) emit(&ps, I_MATCH, 0, 0, 0, 0);

	if (ps.err) {
		free(rx->prog);
		free(rx->sets);
		free(rx);
		preg->__opaque = NULL;
		preg->re_nsub = 0;
		return ps.err;
	}

	rx->ncap = ps.ngroup;
	preg->__opaque = rx;
	preg->re_nsub = (size_t)(ps.ngroup - 1);
	return 0;
}

/* One entry on the matcher's explicit backtracking stack.  Two kinds,
 * because unwinding has to undo two different things:
 *
 *   BT_TRY   an alternative not taken yet: resume the VM at `pc` with
 *            the subject pointer `sp`.  Pushed by I_SPLIT.
 *   BT_UNDO  a capture slot's previous value, restored when unwinding
 *            past the I_SAVE that overwrote it.
 *
 * Popping applies every BT_UNDO it passes before it reaches a BT_TRY,
 * so the slots seen by the resumed alternative are exactly the ones
 * that were live at the I_SPLIT which pushed it -- which is what the
 * recursive version got for free from the C stack. */
enum { BT_TRY, BT_UNDO };

struct bt {
	unsigned char kind;
	int x;			/* BT_TRY: pc.  BT_UNDO: slot number */
	const char *sp;		/* BT_TRY */
	regoff_t old;		/* BT_UNDO */
};

struct mstate {
	const char *begin, *end;
	int cflags, eflags;
	regoff_t *slot;
	regoff_t *best;
	int nslot;
	struct rx *rx;
	regoff_t *progress;	/* last subject offset at each backward edge */
	struct bt *bt;		/* backtracking stack, grown on demand */
	int nbt, capbt;
};

/* Backtracking limit: caps pathological exponential blowup (see file
 * header on alternation not being leftmost-longest -- this is the
 * same "greedy backtracking" cost model every such VM has) so a
 * degenerate pattern fails the match rather than running forever. */
#define MAX_STEPS 2000000

/* Ceiling on the backtracking stack, in entries.  It cannot be reached
 * before MAX_STEPS by a pattern that makes progress -- every entry is
 * pushed by an instruction that also costs a step -- so it is a memory
 * bound, not a second work bound: 256K entries is ~6 MiB at the 24
 * bytes struct bt occupies on x86_64 (~4 MiB on i386), and it caps
 * what a single regexec() can ask the allocator for.  What it costs
 * is the length of subject a single unbounded repeat can consume:
 * "a*" pushes one entry per 'a', so a subject longer than this many
 * bytes reports REG_ESPACE rather than matching.
 * That is a real limit and is documented here deliberately; before
 * this it was a recursion depth of the same size, i.e. a process kill
 * at a few thousand. */
#define MAX_BACKTRACK 262144

/* Push, growing by doubling.  Returns 0 if the stack cannot grow --
 * out of memory, or MAX_BACKTRACK reached; both are REG_ESPACE to the
 * caller, which is what <regex.h> defines that code to mean ("Out of
 * memory"). */
/* ms required throughout the matcher: every function below ultimately
 * receives it forwarded from regexec()'s own `struct mstate ms;`
 * local, and none of them defensively checks it before touching
 * ms->capbt/ms->nbt/ms->bt/ms->rx/ms->end/etc. */
static int bt_grow(struct mstate *ms) __attribute__((nonnull(1)));
static int bt_grow(struct mstate *ms)
{
	int cap = ms->capbt ? ms->capbt * 2 : 64;
	struct bt *p;

	if (ms->capbt >= MAX_BACKTRACK) return 0;
	if (cap > MAX_BACKTRACK) cap = MAX_BACKTRACK;
	p = realloc(ms->bt, (size_t)cap * sizeof *p);
	if (!p) return 0;
	ms->bt = p;
	ms->capbt = cap;
	return 1;
}

static int bt_push_try(struct mstate *ms, int pc, const char *sp) __attribute__((nonnull(1)));
static int bt_push_try(struct mstate *ms, int pc, const char *sp)
{
	struct bt *e;
	if (ms->nbt == ms->capbt && !bt_grow(ms)) return 0;
	e = &ms->bt[ms->nbt++];
	e->kind = BT_TRY;
	e->x = pc;
	e->sp = sp;
	e->old = 0;
	return 1;
}

static int bt_push_undo(struct mstate *ms, int slot, regoff_t old) __attribute__((nonnull(1)));
static int bt_push_undo(struct mstate *ms, int slot, regoff_t old) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct bt *e;
	if (ms->nbt == ms->capbt && !bt_grow(ms)) return 0;
	e = &ms->bt[ms->nbt++];
	e->kind = BT_UNDO;
	e->x = slot;
	e->sp = 0;
	e->old = old;
	return 1;
}

/* Returns 1 on a match, 0 on no match, and -1 when the matcher ran out
 * of budget -- MAX_STEPS, MAX_BACKTRACK, or the allocator -- which
 * regexec() turns into REG_ESPACE.  -1 is deliberately NOT folded into
 * 0: "I gave up" and "this subject does not match" are different
 * answers, and reporting the second for the first is a wrong result
 * rather than a refusal.
 *
 * The VM is iterative.  It used to recurse once per I_SPLIT and once
 * per I_SAVE, which made the C stack the only bound on how far a match
 * attempt could go: MAX_STEPS counts steps, not depth, so a
 * progress-free SPLIT/JMP loop (any repeat whose body can match the
 * empty string) blew the stack long before the step counter tripped,
 * and even a well-behaved "a*" needed one C frame per character of
 * subject.  Both are gone: alternatives live on the heap stack above,
 * whose size is bounded and whose exhaustion is reportable. */
/* ms required, same as bt_grow()/bt_push_try()/bt_push_undo() above.
 * sp is also required: it is dereferenced directly (`c = (unsigned
 * char)*sp;` for I_CHAR/I_ANY, `sp[i]` for I_BACKREF) whenever the
 * bounds guard ahead of each of those cases lets control reach them,
 * and it is always derived from regexec()'s own `string + start`
 * (never NULL, since string is now required there too) or from a
 * previously-pushed bt_push_try() entry's own `sp` (recorded from the
 * same source). */
static int run(struct mstate *ms, int pc, const char *sp)
    __attribute__((nonnull(1, 3)));
static int run(struct mstate *ms, int pc, const char *sp)
{
	int found = 0;
	int steps_left = MAX_STEPS;
	while (steps_left-- > 0) {
		struct inst *in;

		if (pc < 0 || pc >= ms->rx->nprog) goto backtrack;
		in = &ms->rx->prog[pc];
		switch (in->op) {
		case I_CHAR: {
			int c;
			if (sp >= ms->end) goto backtrack;
			c = (unsigned char)*sp;
			if (ms->cflags & REG_ICASE) c = tolower(c);
			if (c != in->c) goto backtrack;
			sp++; pc++; continue;
		}
		case I_ANY:
			if (sp >= ms->end) goto backtrack;
			if ((ms->cflags & REG_NEWLINE) && *sp == '\n') goto backtrack;
			sp++; pc++; continue;
		case I_SET:
			if (sp >= ms->end) goto backtrack;
			if (!testbit(&ms->rx->sets[in->set], (unsigned char)*sp, ms->cflags & REG_ICASE)) goto backtrack;
			sp++; pc++; continue;
		case I_BOL:
			if (sp == ms->begin) {
				if (ms->eflags & REG_NOTBOL) goto backtrack;
				pc++; continue;
			}
			if ((ms->cflags & REG_NEWLINE) && sp[-1] == '\n') { pc++; continue; }
			goto backtrack;
		case I_EOL:
			if (sp == ms->end) {
				if (ms->eflags & REG_NOTEOL) goto backtrack;
				pc++; continue;
			}
			if ((ms->cflags & REG_NEWLINE) && *sp == '\n') { pc++; continue; }
			goto backtrack;
		case I_SAVE:
			/* Overwrite the slot now and record the old value, so
			 * that unwinding past this point restores it -- what
			 * the recursive version did in its `if (ok) ... else
			 * slot[x] = old` tail. */
			if (in->x < ms->nslot) {
				if (!bt_push_undo(ms, in->x, ms->slot[in->x])) return -1;
				ms->slot[in->x] = sp - ms->begin;
			}
			pc++;
			continue;
		case I_BACKREF: {
			size_t slot;
			regoff_t so, eo;
			regoff_t i, len;
			if (in->c < 0 || in->c >= ms->nslot / 2) goto backtrack;
			slot = (size_t)in->c * 2;
			so = ms->slot[slot];
			eo = ms->slot[slot + 1];
			if (so < 0 || eo < so) goto backtrack;
			len = eo - so;
			if (len > ms->end - sp) goto backtrack;
			for (i = 0; i < len; i++) {
				int a = (unsigned char)ms->begin[so + i];
				int b = (unsigned char)sp[i];
				if (ms->cflags & REG_ICASE) { a = tolower(a); b = tolower(b); }
				if (a != b) goto backtrack;
			}
			sp += len;
			pc++;
			continue;
		}
		case I_JMP:
			if (in->x <= pc) {
				regoff_t off = sp - ms->begin;
				if (off <= ms->progress[pc]) goto backtrack;
				ms->progress[pc] = off;
			}
			pc = in->x; continue;
		case I_SPLIT:
			/* Greedy: take x now, keep y for later.  Same order
			 * as `if (run(ms, in->x, sp)) return 1; pc = in->y;`. */
			if (in->x <= pc) {
				regoff_t off = sp - ms->begin;
				if (off <= ms->progress[pc]) { pc = in->y; continue; }
				ms->progress[pc] = off;
			}
			if (!bt_push_try(ms, in->y, sp)) return -1;
			pc = in->x;
			continue;
		case I_MATCH:
			if (!found || ms->slot[1] > ms->best[1]) {
				for (int i = 0; i < ms->nslot; i++) ms->best[i] = ms->slot[i];
				found = 1;
			}
			goto backtrack;
		default:
			goto backtrack;
		}

	backtrack:
		/* Backtrack: undo capture writes until an untaken
		 * alternative surfaces.  An empty stack means this start
		 * offset has no match. */
		for (;;) {
			struct bt *e;
			if (ms->nbt == 0) {
				if (found)
					for (int i = 0; i < ms->nslot; i++) ms->slot[i] = ms->best[i];
				return found;
			}
			e = &ms->bt[--ms->nbt];
			if (e->kind == BT_UNDO) { ms->slot[e->x] = e->old; continue; }
			pc = e->x;
			sp = e->sp;
			break;
		}
	}
	return -1;
}

int regexec(const regex_t *__restrict preg handle(regex_compiled), const char *__restrict string,
	    size_t nmatch, regmatch_t pmatch[__restrict], int eflags)
{
	struct rx *rx = preg->__opaque;
	struct mstate ms;
	regoff_t *slot;
	regoff_t *best;
	regoff_t *progress;
	int nslot = rx->ncap * 2;
	size_t len = strlen(string);
	size_t start;
	int matched = 0;

	slot = malloc((size_t)nslot * sizeof *slot);
	if (!slot) return REG_ESPACE;
	progress = malloc((size_t)rx->nprog * sizeof *progress);
	if (!progress) { free(slot); return REG_ESPACE; }
	best = malloc((size_t)nslot * sizeof *best);
	if (!best) { free(progress); free(slot); return REG_ESPACE; }

	ms.begin = string;
	ms.end = string + len;
	ms.cflags = rx->cflags;
	ms.eflags = eflags;
	ms.slot = slot;
	ms.best = best;
	ms.nslot = nslot;
	ms.rx = rx;
	ms.progress = progress;
	ms.bt = NULL;
	ms.nbt = ms.capbt = 0;

	for (start = 0; start <= len; start++) {
		int i, r;
		for (i = 0; i < nslot; i++) slot[i] = -1;
		for (i = 0; i < nslot; i++) best[i] = -1;
		for (i = 0; i < rx->nprog; i++) progress[i] = -1;
		ms.nbt = 0;		/* the buffer is reused; the contents are not */
		r = run(&ms, 0, string + start);
		if (r > 0) { matched = 1; break; }
		if (r < 0) {
			/* The matcher ran out of budget rather than
			 * out of subject.  <regex.h>: REG_ESPACE, "Out
			 * of memory" -- and regcomp.html's DESCRIPTION
			 * allows it: "If regexec() finds a match, it
			 * shall return zero; otherwise, it shall return
			 * non-zero indicating either no match or an
			 * error."  Reporting REG_NOMATCH here would be
			 * a wrong answer, not a refusal. */
			free(ms.bt);
			free(best);
			free(progress);
			free(slot);
			return REG_ESPACE;
		}
	}
	free(ms.bt);
	free(best);
	free(progress);

	if (matched && nmatch > 0 && pmatch && !(rx->cflags & REG_NOSUB)) {
		size_t i;
		for (i = 0; i < nmatch; i++) {
			if ((int)i * 2 + 1 < nslot && slot[i * 2] >= 0 && slot[i * 2 + 1] >= 0) {
				pmatch[i].rm_so = slot[i * 2];
				pmatch[i].rm_eo = slot[i * 2 + 1];
			} else {
				pmatch[i].rm_so = -1;
				pmatch[i].rm_eo = -1;
			}
		}
	}

	free(slot);
	return matched ? 0 : REG_NOMATCH;
}

#define NERRMSGS 14	/* index 0 (unused) through REG_BADRPT (13) */

struct errmsg {
	const char *text;
	size_t size;
};

#define ERRMSG(s) { s, sizeof s }

static const struct errmsg errmsgs[NERRMSGS] = {
	ERRMSG("unknown regex error"),	/* fallback: no code 0 in this header */
	ERRMSG("no match"),		/* REG_NOMATCH */
	ERRMSG("invalid regular expression"), /* REG_BADPAT */
	ERRMSG("invalid collating element"), /* REG_ECOLLATE */
	ERRMSG("invalid character class"), /* REG_ECTYPE */
	ERRMSG("trailing backslash"),	/* REG_EESCAPE */
	ERRMSG("invalid back reference"), /* REG_ESUBREG */
	ERRMSG("unmatched [ or [^"),	/* REG_EBRACK */
	ERRMSG("unmatched ( or \\("),	/* REG_EPAREN */
	ERRMSG("unmatched \\{"),		/* REG_EBRACE */
	ERRMSG("invalid interval"),	/* REG_BADBR */
	ERRMSG("invalid range end"),	/* REG_ERANGE */
	ERRMSG("out of memory"),		/* REG_ESPACE */
	ERRMSG("repetition operator with nothing to repeat"), /* REG_BADRPT */
};

#undef ERRMSG

size_t regerror(int errcode, const regex_t *__restrict preg,
	char *__restrict errbuf withtok(writable_span(errbuf_size)),
	size_t errbuf_size)
{
	const struct errmsg *msg = &errmsgs[0];
	(void)preg;

	if (errcode >= 1 && errcode < NERRMSGS) msg = &errmsgs[errcode];

	if (errbuf_size != 0) {
		size_t n = msg->size < errbuf_size ? msg->size : errbuf_size;
		for (size_t i = 0; i + 1 < n; i++) errbuf[i] = msg->text[i];
		errbuf[n - 1] = '\0';
	}
	return msg->size;
}

void regfree(regex_t *preg destroy(regex_compiled))
{
	struct rx *rx = preg->__opaque;
	if (!rx) return;
	free(rx->prog);
	free(rx->sets);
	free(rx);
	preg->__opaque = NULL;
	preg->re_nsub = 0;
}

// NOLINTEND(misc-include-cleaner)
