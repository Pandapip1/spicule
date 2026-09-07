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
#include "ownership_stubs.h" /* __ownership_string_terminated(), __ownership_pointer_nonnull() */

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
	/* No __util_awk_main() is on the stack to catch this (e.g. a direct
	 * awk_parse_program() call, as fuzz/fuzz_awk.c's harness makes) --
	 * see awk_priv.h's comment on awk_fatal_armed. Falling back to
	 * diagnostic-plus-exit(2) is still correct there; only
	 * __util_awk_main() gets the non-exiting path. */
	exit(2);
}

static void buf_grow_append(char **buf withtok(heap_allocated), size_t *len, size_t *cap, const char *s, size_t n)
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

withtok(heap_allocated)
static char *load_progfiles(char **files elements_withtok(null_terminated, nfiles), int nfiles)
{
	char *buf = NULL;
	size_t len = 0, cap = 0;
	int i;

	for (i = 0; i < nfiles; i++) {
		const char *fname = files[i];
		/* use_stdin, not `f != stdin`, decides the fclose() below -- the
		 * checker can't prove opaque pointers unequal, so a direct
		 * comparison makes this fopen() allocation look conditionally
		 * leaked (same idiom as src/util/join.c's read_all()). */
		int use_stdin = strcmp(fname, "-") == 0;
		FILE *f = use_stdin ? stdin : fopen(fname, "r");
		char chunk[4096];
		size_t n;

		__ownership_string_terminated(fname);
		if (!f) {
			__util_diagf("awk: %s: %s\n", fname, strerror(errno));
			free(buf);
			return NULL;
		}
		while ((n = fread(chunk, 1, sizeof chunk, f)) > 0)
			buf_grow_append(&buf, &len, &cap, chunk, n);
		if (!use_stdin) (void)fclose(f);
		if (len == 0) {
			buf_grow_append(&buf, &len, &cap, "\n", 1);
		} else {
			/* len only grows inside buf_grow_append(), whose growth
			 * branch always leaves *buf non-null before *len advances --
			 * a cross-call invariant this checker can't derive on its
			 * own. */
			__ownership_pointer_nonnull(buf);
			/* ValidPointer still can't prove buf's extent covers index
			 * len-1: the real extent buf_grow_append()'s realloc()
			 * establishes doesn't survive back out through its char**
			 * parameter. No annotation narrows extent state the way
			 * __ownership_pointer_nonnull() narrows nonnull state; left
			 * open. */
			if (buf[len - 1] != '\n') buf_grow_append(&buf, &len, &cap, "\n", 1);
		}
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

/* -F/-v/-f share the getopt(3)-style rule that an option's argument is
 * either attached (`-Fx`) or the next argv element (`-F x`). Returns
 * that text, advancing *argi in the "next element" case; on a missing
 * argument, prints the diagnostic and returns NULL, which the caller
 * must treat as "return 2" (this function can't unwind itself: it runs
 * before __util_awk_main()'s setjmp() is armed). */
withtok(null_terminated)
static const char *opt_value(char **argv elements_withtok(null_terminated, argc),
	int argc, int *argi, char opt, const char *arg withtok(null_terminated))
{
	if (arg[2]) return arg + 2;
	if (++*argi >= argc) {
		__util_diagf("awk: -%c: option requires an argument\n", opt);
		return NULL;
	}
	return argv[*argi];
}

int __util_awk_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	const char *fsarg = NULL;
	/* vassigns/progfiles and each -v's strdup() are freed once applied
	 * below, but only on the path that reaches that point -- every
	 * early usage-error return leaves them unfreed.
	 * ntlibc.AllocationLifetime flags those returns; left open rather
	 * than threading cleanup through every CLI usage error, same
	 * rationale as this file's tail comment on the parsed program. */
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

		__ownership_string_terminated(arg);
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
			__ownership_string_terminated(val);
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
	 * (loading -f progfiles, parsing, running) without per-phase
	 * machinery -- see awk_priv.h's comment on awk_fatal_env/
	 * awk_unwind_fatal() for the full design. The catching branch below
	 * deliberately touches nothing but awk_fatal_armed and a hardcoded
	 * status: ip/prog/progtext are ordinary non-volatile locals modified
	 * after this setjmp(), so touching them here would itself be UB. */
	if (setjmp(awk_fatal_env)) {
		awk_fatal_armed = 0;
		return 2;
	}
	awk_fatal_armed = 1;

	if (have_f) {
		progtext = load_progfiles(progfiles, nprogfiles);
		/* progfiles only ever borrows pointers into argv (see the -f
		 * case below); the array itself is never needed again once
		 * load_progfiles() has read every entry. */
		free(progfiles);
		if (!progtext) { awk_fatal_armed = 0; return 2; }
	} else {
		if (i >= argc) { __util_diagf("awk: missing program text\n"); awk_fatal_armed = 0; return 2; }
		progtext = argv[i];
		i++;
	}

	prog = awk_parse_program(progtext);
	/* progtext is heap-owned only in the -f path (load_progfiles()); the
	 * bare-program-text path points it at argv[i], which must not be
	 * freed. awk_parse_program() never retains src past its own return
	 * (its lexer just walks it), so freeing here is safe regardless of
	 * whether parsing succeeded. */
	if (have_f) free(progtext);
	if (!prog) { awk_fatal_armed = 0; return 2; }

	awk_interp_init(&ip, prog);
	awk_interp_setup_environ(&ip, environ);
	if (fsarg) awk_interp_set_str(&ip, "FS", fsarg);
	{
		int vi;
		for (vi = 0; vi < nvassigns; vi++) {
			awk_interp_set_str(&ip, vassigns[vi].name, vassigns[vi].val);
			/* vassigns[vi].name is the strdup() from the -v case
			 * below; .val just points partway into that same
			 * block, so freeing .name alone is enough. */
			free(vassigns[vi].name);
		}
		free(vassigns);
	}
	awk_interp_setup_argv(&ip, argv[0], argc - i, argv + i);

	status = awk_interp_run(&ip);
	awk_interp_free(&ip);
	/* The parsed program (AST/lexer-owned strings/compiled EREs) is
	 * deliberately never freed -- a short-lived CLI process (or one
	 * bi_awk() shell-builtin invocation), so the OS reclaims it at exit
	 * either way. Compare src/util/sort.c's free_lines(), which frees
	 * because it may run again in the same process's loop; awk's
	 * program is parsed exactly once per process. */
	awk_fatal_armed = 0;
	return status;
}
