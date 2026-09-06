/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * awk(1p) -- XCU: `awk [-F sepstring] [-v assignment]... program
 * [argument...]` or `awk [-F sepstring] -f progfile [-f progfile]...
 * [-v assignment]... [argument...]`. __util_awk_main() below is just
 * command-line parsing and wiring; the real work is three sibling
 * translation units, each with its own header comment:
 *
 *  - src/util/awk_priv.h: shared token/AST/cell/interpreter types.
 *  - src/util/awk_lex.c: the lexer.
 *  - src/util/awk_parse.c: the recursive-descent parser.
 *  - src/util/awk_run.c: the tree-walking interpreter -- value/cell
 *    model, field splitting, comparisons, built-in functions, getline,
 *    and the BEGIN/main-loop/END driver.
 *
 * This file parses -F/-v/-f/--, assembles the program text, parses it,
 * builds the interpreter, seeds ENVIRON/ARGV/ARGC and any -v
 * assignments, runs it, and translates its EXIT STATUS section (syntax
 * error -> nonzero diagnostic exit; otherwise exit()'s argument, else 0)
 * into the process's own exit code.
 *
 * ---- OPTIONS -----------------------------------------------------------
 *
 *  -F sepstring   Sets FS before BEGIN runs -- seeds the same global a
 *                 -v assignment would, so awk_run.c's ordinary FS
 *                 classification (split_into()) applies to it
 *                 identically.
 *  -v assignment  `name=value`, applied before BEGIN runs, in
 *                 left-to-right command-line order (last repeat wins).
 *                 XCU is silent on -F/-v ordering when both name the
 *                 same variable; this implementation processes every
 *                 option in argv order, so whichever appears later
 *                 wins.
 *  -f progfile    May repeat; each file's text is concatenated (with an
 *                 inserted newline, in case one doesn't end in one) in
 *                 the order given. When at least one -f is given, the
 *                 first operand is NOT the program text -- it's the
 *                 first `argument`.
 *  --             Ends option parsing explicitly.
 *
 * OPERANDS: with no -f, the first non-option operand is the program
 * text. Every operand after that is a `file` or `var=value` assignment,
 * and a var=value operand takes effect exactly when the main input loop
 * *reaches* it in ARGV order, not all at once up front: `awk
 * '{print x}' file1 x=5 file2` prints an empty x for file1's lines and
 * "5" for file2's. This falls out naturally from awk_run.c's advance_
 * to_next_argv_file(), which applies a var=value ARGV element the
 * moment it's reached while walking ARGV for the next input file. -v
 * assignments are seeded here, before BEGIN, so BEGIN can see them.
 *
 * ---- DELIBERATE SCOPE NARROWINGS ---------------------------------------
 *
 *  - Numeric literals are decimal only -- XCU's own NUMBER grammar is
 *    decimal-only anyway; see awk_lex.c's header for what "0x1" lexes
 *    as instead (NUMBER 0 concatenated with NAME "x1").
 *  - Empty-string FS ("split into characters") is a common extension
 *    XCU doesn't define; this implementation's split_into() treats it
 *    as "no separator ever occurs" (the whole string is field 1), not
 *    the gawk-compatible behavior.
 *  - RS's value beyond its first character is never consulted (a
 *    multi-character or ERE RS is a gawk extension) -- XCU: "the first
 *    character of the value of RS should be used".
 *  - RS=="" (paragraph mode)'s "newline is always a field separator" is
 *    implemented for FS==" " (already true) and a single-character FS
 *    (unioned into the split), but not additionally unioned into a
 *    multi-character (ERE) FS -- an already-rare combination.
 *  - `nextfile` and `fflush()` are gawk/BWK extensions with no XCU
 *    awk(1p) citation, so neither is implemented. Every stream this
 *    implementation itself opens is still flushed at the right internal
 *    moments (before system()/`| getline`, and at normal exit).
 *  - printf/sprintf conversions carry no C length modifiers (h/hh/l/
 *    ll/L) -- meaningless since every awk value is already a double or
 *    a string, never a typed vararg.
 *  - substr()'s m<=0 / m+n past the string's end is XCU's own
 *    "unspecified" case; this implements the conventional clamping
 *    every real awk uses (a half-open [m, m+n) window over 1-based
 *    positions, clipped to what overlaps the string) -- see
 *    awk_run.c's comment.
 *  - `for (k in arr)` iteration order is XCU's own "unspecified" --
 *    it's whatever the hash table's bucket layout produces
 *    (awk_priv.h's struct awk_htab).
 *  - A user function's array-vs-scalar parameter binding is dynamic,
 *    not static: a bare-identifier argument whose cell is already an
 *    array or still uninitialized is bound *by reference*; the first
 *    scalar use inside the callee forks it into a private copy first.
 *    This gets scalars-by-value and arrays-by-reference right,
 *    including an uninitialized argument the callee treats as an array
 *    becoming a real array in the caller's scope -- see awk_priv.h's
 *    struct awk_cell and awk_run.c's call_user_func().
 *  - next/exit inside a user function unwind to the nearest enclosing
 *    record/program boundary via a persistent interpreter flag rather
 *    than setjmp/longjmp -- see awk_run.c's header for the mechanism
 *    and its one rough edge (a next/exit whose effect would need to be
 *    observed mid-expression instead lets any later argument of the
 *    same statement still evaluate before the statement bails).
 *  - Allocation failure anywhere in the parser or interpreter is fatal
 *    (a diagnostic plus an unwind back to here, not a raw exit(2):
 *    bi_awk() runs as a no-fork shell builtin, so exit()ing the process
 *    would be a defect -- see awk_priv.h's "fatal-error unwind"
 *    comment). The same unwind covers every other fatal runtime
 *    condition (division by zero, a scalar/array type clash, an
 *    undefined function call, an invalid dynamic ERE, a failed output
 *    redirect open).
 *
 * tolower()/toupper() ARE implemented -- they are XCU awk(1p)'s own
 * mandatory string functions, not an extension.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include "awk_priv.h"
#include "util.h"

struct vassign { char *name, *val; };

/* The one definition of the fatal-error unwind target awk_priv.h
 * declares extern -- see that header's own long comment for the full
 * design. Defined here because __util_awk_main() below is the only
 * function that ever calls setjmp() on it. */
jmp_buf awk_fatal_env;
static int awk_fatal_armed;

void awk_unwind_fatal(void)
{
	if (awk_fatal_armed) longjmp(awk_fatal_env, 1);
	/* No __util_awk_main() call is on the stack to catch this (e.g. a
	 * direct awk_parse_program() call, the way fuzz/fuzz_awk.c's own
	 * harness makes one to pre-check a program before deciding whether
	 * to run it) -- see awk_priv.h's own comment on awk_fatal_armed.
	 * Falling back to the historical diagnostic-plus-exit(2) behavior
	 * is still correct for that caller; only __util_awk_main() itself
	 * needs (and gets) the non-exiting path. */
	exit(2);
}

static void buf_grow_append(char **buf, size_t *len, size_t *cap, const char *s, size_t n)
{
	/* *len + n + 1, computed raw, wraps for an adversarial n (a huge
	 * -f program file) and would then wrongly compare as "already
	 * fits" against *cap -- same fix as this file's sibling
	 * awk_run.c's buf_append(). */
	size_t need;
	if (!__util_size_add(*len, n, &need) || !__util_size_add(need, 1, &need)) {
		__util_diagf("awk: out of memory\n"); awk_unwind_fatal();
	}
	if (need > *cap) {
		size_t newcap = *cap ? *cap : 256;
		while (newcap < need) {
			if (!__util_size_mul(newcap, 2, &newcap)) { __util_diagf("awk: out of memory\n"); awk_unwind_fatal(); }
		}
		*buf = realloc(*buf, newcap);
		if (!*buf) { __util_diagf("awk: out of memory\n"); awk_unwind_fatal(); }
		*cap = newcap;
	}
	for (size_t i = 0; i < n; i++) (*buf)[*len + i] = s[i];
	*len += n;
	(*buf)[*len] = 0;
}

static char *load_progfiles(char **files, int nfiles)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;
	int i;

	for (i = 0; i < nfiles; i++) {
		FILE *f = strcmp(files[i], "-") == 0 ? stdin : fopen(files[i], "r");
		char chunk[4096];
		size_t n;
		if (!f) {
			__util_diagf("awk: %s: %s\n", files[i], strerror(errno));
			free(buf);
			return NULL;
		}
		while ((n = fread(chunk, 1, sizeof chunk, f)) > 0)
			buf_grow_append(&buf, &len, &cap, chunk, n);
		if (f != stdin) (void)fclose(f);
		if (len == 0 || buf[len - 1] != '\n') buf_grow_append(&buf, &len, &cap, "\n", 1);
	}
	if (!buf) buf = strdup("");
	return buf;
}

/* `name=value`: name must look like a real awk identifier (letter/'_'
 * then alnum/'_') for the whole thing to be an assignment at all --
 * XCU's own grammar for both -v's operand and a var=value file
 * operand. Splits in place (writes a NUL over the '=') and returns 1
 * on success. */
static int split_assignment(char *s, char **name_out, char **val_out)
{
	char *eq = strchr(s, '=');
	char *p;
	if (!eq || eq == s) return 0;
	if (!(isalpha((unsigned char)s[0]) || s[0] == '_')) return 0;
	for (p = s + 1; p < eq; p++) if (!(isalnum((unsigned char)*p) || *p == '_')) return 0;
	*eq = 0;
	*name_out = s;
	*val_out = eq + 1;
	return 1;
}

/* -F/-v/-f all share the standard getopt(3)-style rule that an option's
 * argument is either attached (`-Fx`) or, when nothing is attached, the
 * next argv element (`-F x`). Returns that argument text, advancing
 * *argi past it in the "next argv element" case; on the missing-
 * argument case prints the diagnostic itself and returns NULL, which
 * the caller must treat as "return 2" (this function cannot do that
 * unwind itself: it runs before __util_awk_main()'s own setjmp() is
 * armed, so a plain return here is already exactly what every other
 * error in this same option loop does). */
static const char *opt_value(char **argv, int argc, int *argi, char opt, const char *arg)
{
	if (arg[2]) return arg + 2;
	if (++*argi >= argc) {
		__util_diagf("awk: -%c: option requires an argument\n", opt);
		return NULL;
	}
	return argv[*argi];
}

int __util_awk_main(int argc, char **argv)
{
	const char *fsarg = NULL;
	struct vassign *vassigns = NULL;
	int nvassigns = 0;
	char **progfiles = NULL;
	int nprogfiles = 0;
	int have_f = 0;
	int i;
	char *progtext;
	struct awk_program *prog;
	struct awk_interp ip;
	int status;

	for (i = 1; i < argc; i++) {
		char *arg = argv[i];
		const char *val;

		if (!strcmp(arg, "--")) { i++; break; }
		if (arg[0] != '-' || arg[1] == 0) break;

		switch (arg[1]) {
		case 'F':
			val = opt_value(argv, argc, &i, 'F', arg);
			if (!val) return 2;
			fsarg = val;
			break;
		case 'v': {
			char *name, *v2;
			char *dup;
			val = opt_value(argv, argc, &i, 'v', arg);
			if (!val) return 2;
			dup = strdup(val);
			if (!dup) { __util_diagf("awk: out of memory\n"); return 2; }
			if (!split_assignment(dup, &name, &v2)) {
				__util_diagf("awk: -v: %s: not a valid name=value assignment\n", val);
				free(dup);
				return 2;
			}
			{
				struct vassign *g = __util_reallocarray(vassigns, (size_t)nvassigns + 1, sizeof *g);
				if (!g) { __util_diagf("awk: out of memory\n"); return 2; }
				vassigns = g;
				vassigns[nvassigns].name = name;
				vassigns[nvassigns].val = v2;
				nvassigns++;
			}
			break;
		}
		case 'f':
			val = opt_value(argv, argc, &i, 'f', arg);
			if (!val) return 2;
			{
				char **g = __util_reallocarray(progfiles, (size_t)nprogfiles + 1, sizeof *g);
				if (!g) { __util_diagf("awk: out of memory\n"); return 2; }
				progfiles = g;
				progfiles[nprogfiles++] = (char *)val;
			}
			have_f = 1;
			break;
		default:
			__util_diagf("awk: -%c: invalid option\n", arg[1]);
			return 2;
		}
	}

	/* ---- fatal-error unwind: armed once here, covers every phase below
	 * (loading -f progfiles, parsing, running) without separate per-
	 * phase machinery -- see awk_priv.h's own long comment on
	 * awk_fatal_env/awk_unwind_fatal() for the full design, including
	 * why the catching branch below deliberately touches nothing but
	 * awk_fatal_armed and a hardcoded status (ip/prog/progtext are
	 * ordinary, non-volatile locals modified after this setjmp(), so
	 * touching them from here would itself be undefined behavior --
	 * see that same comment's point 3). */
	if (setjmp(awk_fatal_env)) {
		awk_fatal_armed = 0;
		return 2;
	}
	awk_fatal_armed = 1;

	if (have_f) {
		progtext = load_progfiles(progfiles, nprogfiles);
		if (!progtext) { awk_fatal_armed = 0; return 2; }
	} else {
		if (i >= argc) { __util_diagf("awk: missing program text\n"); awk_fatal_armed = 0; return 2; }
		progtext = argv[i];
		i++;
	}

	prog = awk_parse_program(progtext);
	/* progtext is heap-owned only in the -f path (load_progfiles());
	 * the bare-program-text path above points it at argv[i], which
	 * must not be freed. awk_parse_program() never retains src past
	 * its own return (its lexer just walks it; token text is copied
	 * separately), so it is safe to free here regardless of whether
	 * parsing succeeded. */
	if (have_f) free(progtext);
	if (!prog) { awk_fatal_armed = 0; return 2; }

	awk_interp_init(&ip, prog);
	awk_interp_setup_environ(&ip, environ);
	if (fsarg) awk_interp_set_str(&ip, "FS", fsarg);
	{
		int vi;
		for (vi = 0; vi < nvassigns; vi++)
			awk_interp_set_str(&ip, vassigns[vi].name, vassigns[vi].val);
	}
	awk_interp_setup_argv(&ip, argv[0], argc - i, argv + i);

	status = awk_interp_run(&ip);
	awk_interp_free(&ip);
	/* The parsed program (AST/lexer-owned strings/compiled literal
	 * EREs) is deliberately never freed -- this is a short-lived CLI
	 * process (or, as a shell built-in, one bi_awk() invocation), so
	 * the OS reclaims it at exit either way; see this file's own
	 * header for the same allocation-failure-handling philosophy
	 * (fatal rather than threaded through every call site) applied
	 * one step further, to a whole-of-run allocation nothing in this
	 * tree's other utilities needs to free piecemeal either (compare
	 * src/util/sort.c's own free_lines() -- sort frees because it may
	 * run again in the same process's loop in principle; awk's own
	 * program is parsed exactly once per process). */
	awk_fatal_armed = 0;
	return status;
}
