/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The `sh` utility (XCU sh(1p)) as a *function*: option and operand
 * handling, the refusal preflight, and the run, over the shell engine
 * in the rest of src/sh/ (see sh.h for the AST and the __sh_exec_*()
 * contract).
 *
 * Two callers: sh/main.c (`return __sh_main(argc, argv)`), and
 * __sh_run_script() at the end of this file, which src/process/exec.c's
 * [ENOEXEC] fallback and XCU 2.9.1's command search call directly
 * in-process instead of spawning sh.exe as a second process.
 *
 * Nothing here may be named `main`: the Makefile archives a wildcard
 * over src/ into libc.a, so a main() here would collide with every
 * program that links it.
 *
 * ---- What this accepts (XCU sh(1p), "SYNOPSIS") ----------------------
 *
 *   sh -c command_string [command_name [argument...]]
 *   sh [-s] [command_file [argument...]]     (script file, or stdin)
 *
 * With no -c and no command_file, the program text is read from standard
 * input, exactly as `-s` asks for explicitly. `--` ends option parsing;
 * a lone `-` is the historical synonym for "no more options".
 *
 * Deliberate deviation: standard input is read *to EOF up front* and then
 * executed, rather than incrementally with the remainder left on fd 0.
 * Nothing in the supported subset can loop over its own input (no
 * while/read), so this is observable only to a command that deliberately
 * reads the rest of the script off fd 0.
 *
 * ---- What it refuses, and why refusing beats running -----------------
 *
 * The engine implements a documented subset (sh.h's banner). Two classes
 * of construct would otherwise be *silently misinterpreted* rather than
 * diagnosed, because they're syntactically indistinguishable from
 * something the engine does support:
 *
 *   - Reserved words and unimplemented built-ins. `case` and `unset`
 *     still lex as ordinary WORD tokens, so `case x in y) ;; esac` parses
 *     as simple commands and would run a nonexistent program called
 *     "case"; `unset X` fails with 127 while silently leaving X set.
 *     Function definitions, `if`/`while`/`until`/`for` are not in this
 *     class: they have real grammar, so a misplaced `fi`/`do`/`done` is a
 *     parse error, not a command name. A function body is re-parsed and
 *     checked at its definition (check_command() below), before any of
 *     the program runs.
 *   - Special parameters not yet implemented. wordexp() expands
 *     $NAME/${NAME} and the positional/`@`/`*`/`#`/`0` parameters; `$`
 *     followed by anything else (?, !, -, $) is left as a literal `$`,
 *     so `exit $?` would silently never see a status. `${#NAME}` (string
 *     length) is likewise refused rather than mistaken for `${#}`.
 *
 * preflight() below walks the AST and refuses the whole program, naming
 * what is unsupported, before running any of it -- a shell that already
 * ran half a build script before discovering it can't finish has done
 * real damage a diagnostic can't undo.
 *
 * Everything the *engine* declines at execution time reaches this file as
 * __sh_exec_list()'s -1 (sh.h: "cannot execute this AST node at all")
 * and is reported the same way: a stderr message and nonzero exit, never
 * a made-up status.
 *
 * ---- Exit status (XCU 2.8.2, sh(1p) "EXIT STATUS") -------------------
 *
 * An empty program (or comments only) runs no command and exits 0. A
 * syntax error, unsupported construct, or usage error exits 2 (bash/dash's
 * convention for these). A command_file that can't be opened or read
 * exits 127, matching sh(1p) and this project's exec.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libc.h"
#include "sh.h"

#define EX_USAGE 2       /* usage error, syntax error, unsupported construct */
#define EX_NOSCRIPT 127  /* command_file unopenable/unreadable */

static const char *progname = "sh";

/* Diagnostics go to stderr, prefixed with $0, ending in a newline (XCU
 * sh(1p) STDERR, 2.8.1). A macro so each call site keeps its own printf
 * arguments; a write failure here must not override the exit status already
 * chosen. */
#define diag(...) do { \
	(void)fprintf(stderr, "%s: ", progname); \
	(void)fprintf(stderr, __VA_ARGS__); \
	(void)fputc('\n', stderr); \
} while (0)

/* One message, three call sites (a word, a redirection target, a
 * here-document body), so the wording cannot drift between them. */
static void diag_bad_param(const char *what, const char *where)
{
	diag("%s: this special parameter ($!, $$, $-, ${#NAME}) is not "
	     "implemented%s", what, where);
}

/* ---- the refusal lists ----------------------------------------------
 *
 * Reserved words (XCU 2.4) that the grammar does not implement.
 *
 * Down to two: `if`/`while`/`for`/etc. are gone because parse.c now
 * builds those constructs and raises a syntax error on a misplaced `fi`
 * or `do` directly, which also catches it inside a "(...)" this list
 * never recursed into. `case`/`esac` stay: that construct isn't
 * implemented, so `case` still lexes as an ordinary WORD and would
 * otherwise run a nonexistent program called "case". */
static const char *const reserved[] = {
	"case", "esac",
	0
};

/* Utilities whose whole effect is on the shell's own execution environment
 * (XCU 2.12) and which therefore *cannot* be a program found on PATH.
 *
 * A name comes off this list exactly when builtin.c grows a real
 * implementation of it. `test`/`[`/`true`/`false` were never on it: on a
 * real POSIX system they're external utilities, but this platform has no
 * /bin, so builtin.c builds them in too (see its own header). */
static const char *const unimplemented_builtins[] = {
	".", "break", "continue", "eval", "exec",
	"times", "trap", "unset",
	"alias", "unalias", "bg", "fg", "jobs", "command", "getopts",
	"hash", "read", "ulimit", "wait",
	0
};

/* list is required: every real call site passes one of this file's own
 * static, always-populated arrays. */
static int in_list(const char *const *list, const char *s) __attribute__((nonnull(1)));
static int in_list(const char *const *list, const char *s)
{
	size_t i;
	for (i = 0; list[i]; i++) if (strcmp(list[i], s) == 0) return 1;
	return 0;
}

/* Scans one word's *raw* source text (quotes/backslashes still in place)
 * for a parameter expansion wordexp() would not perform. Returns the
 * offending text's leading characters in `what` (NUL-terminated, at most
 * 4 characters, so `what` needs 5 bytes) and 1, or 0 if clean.
 *
 * Minimal quoting state machine, not a second lexer: single quotes make
 * everything up to the next one literal (2.2.2), a backslash outside
 * single quotes escapes the next character, and double quotes don't
 * change whether `$` introduces an expansion (2.2.3), only field
 * splitting, which isn't relevant here. */
static int bad_expansion(const char *text, char *what)
{
	const char *p = text;
	int dq = 0;

	while (*p) {
		if (*p == '\'' && !dq) {
			for (p++; *p && *p != '\''; p++) ;
			if (*p) p++;
			continue;
		}
		if (*p == '\\' && p[1]) { p += 2; continue; }
		if (*p == '"') { dq = !dq; p++; continue; }
		if (*p == '$') {
			char c = p[1];
			const char *bad = 0;
			if (c == '{') {
				/* ${1}/${10}, ${@}/${*}/${#}, and ${NAME} are real
				 * expansions; ${#NAME} (string length) is not and must
				 * stay refused rather than be mistaken for ${#}. */
				const char *d = p + 2;
				if (*d >= '0' && *d <= '9') {
					while (*d >= '0' && *d <= '9') d++;
					if (*d != '}') bad = p;
				} else if ((*d == '@' || *d == '*' || *d == '#' || *d == '?') && d[1] == '}') {
					/* implemented */
				} else if (!((*d >= 'a' && *d <= 'z') || (*d >= 'A' && *d <= 'Z') || *d == '_')) {
					bad = p;
				}
			} else if (c == '!' || c == '-' || c == '$') {
				/* $!, $-, $$: still-unimplemented special parameters. */
				bad = p;
			}
			if (bad) {
				/* Quote back just the expansion's introducer ("$1", "${#"),
				 * not a fixed number of characters -- that would drag in
				 * whatever text follows and misrepresent it. */
				size_t n = 0;
				what[n++] = '$';
				if (bad[1]) what[n++] = bad[1];
				if (bad[1] == '{' && bad[2]) what[n++] = bad[2];
				what[n] = 0;
				return 1;
			}
		}
		p++;
	}
	return 0;
}

static int check_words(const struct sh_word *w)
{
	char what[8];
	for (; w; w = w->next) {
		if (bad_expansion(w->text, what)) {
			diag_bad_param(what, "");
			return -1;
		}
	}
	return 0;
}

static int check_redirs(const struct sh_redir *r)
{
	char what[8];
	for (; r; r = r->next) {
		if (r->word && bad_expansion(r->word, what)) {
			diag_bad_param(what, "");
			return -1;
		}
		/* A here-document body expands like a double-quoted word unless
		 * the delimiter was quoted (2.7.4), hence the same check. */
		if (r->heredoc && !r->heredoc_quoted &&
		    bad_expansion(r->heredoc, what)) {
			diag_bad_param(what, " (in a here-document body)");
			return -1;
		}
	}
	return 0;
}

static int check_list(const struct sh_list *list);

static int check_command(const struct sh_command *c) __attribute__((nonnull(1)));
// NOLINTNEXTLINE(misc-no-recursion) -- validation mirrors the nested shell-AST hierarchy
static int check_command(const struct sh_command *c)
{
	const char *name;
	const struct sh_ifarm *a;

	if (check_redirs(c->redirs)) return -1;

	/* Switched on kind rather than a generic "body" field: a `for` has
	 * both a word list and a body to check, and a single shared field
	 * would silently skip a loop's condition (a `while "$1"` test). */
	switch (c->kind) {
	case SH_CMD_SUBSHELL:
	case SH_CMD_BRACE:
		return check_list(c->u.group.body);
	case SH_CMD_IF:
		for (a = c->u.ifcmd.arms; a; a = a->next)
			if (check_list(a->cond) || check_list(a->body)) return -1;
		return check_list(c->u.ifcmd.else_body);
	case SH_CMD_LOOP:
		if (check_list(c->u.loop.cond)) return -1;
		return check_list(c->u.loop.body);
	case SH_CMD_FUNCDEF:
		/* The body is source text, not a subtree, so it must be re-parsed
		 * to check it. Checking here, at the definition, keeps the
		 * refuse-before-anything-runs property instead of blowing up
		 * later on the call. */
		{
			struct sh_list *body = __sh_parse(c->u.funcdef.func_text, 0, 0);
			int rc;
			if (!body) {
				diag("%s: cannot re-parse the function body", c->u.funcdef.name);
				return -1;
			}
			rc = check_list(body);
			__sh_list_free(body);
			return rc;
		}
	case SH_CMD_FOR:
		/* `for name` with no `in` list is equivalent to `in "$@"` (2.9.4)
		 * and this shell has positional parameters to iterate, so there's
		 * nothing more to refuse here. */
		if (check_words(c->u.forloop.words)) return -1;
		return check_list(c->u.forloop.body);
	default:
		break;
	}

	if (check_words(c->u.simple.assigns) || check_words(c->u.simple.words)) return -1;

	if (!c->u.simple.words || !c->u.simple.words->text) return 0;
	name = c->u.simple.words->text;
	if (in_list(reserved, name)) {
		diag("%s: the `case' construct is not implemented", name);
		return -1;
	}
	if (in_list(unimplemented_builtins, name)) {
		diag("%s: this shell has no `%s' built-in yet, and it cannot be an "
		     "external command", name, name);
		return -1;
	}
	return 0;
}

/* list is deliberately left unmarked nonnull: check_command()'s
 * SH_CMD_IF/LOOP/FOR arms pass a compound command's optional parts (e.g.
 * an else_body with no `else`) straight through as NULL. */
// NOLINTNEXTLINE(misc-no-recursion) -- validation mirrors the nested shell-AST hierarchy
static int check_list(const struct sh_list *list)
{
	const struct sh_list_item *it;
	const struct sh_andor *a;
	size_t i;

	if (!list) return 0;
	for (it = list->items; it; it = it->next) {
		if (it->sep == SH_SEP_AMP) {
			/* execute.c runs an async item synchronously instead --
			 * silently different behavior, not a detectable missing
			 * feature, so it's refused here instead. */
			diag("asynchronous lists (`&') are not implemented");
			return -1;
		}
		for (a = it->andor; a; a = a->next)
			for (i = 0; i < a->pipeline.ncommands; i++)
				if (check_command(&a->pipeline.commands[i])) return -1;
	}
	return 0;
}

/* Refuses the whole program if any part of it is something the engine
 * would misinterpret rather than diagnose. See this file's header. */
static int preflight(const struct sh_list *list)
{
	return check_list(list);
}

/* ---- reading the program text --------------------------------------- */

/* Reads all of `f` into a freshly malloc'd, NUL-terminated buffer.
 * Returns 0 on success (and never leaves *out set on failure). Grows the
 * buffer before each read so fread() is never called with zero room, and
 * stops on the first short read. */
static int slurp(FILE *f, char **out)
{
	size_t cap = 4096, len = 0;
	char *buf = malloc(cap);

	if (!buf) return -1;
	for (;;) {
		size_t room, n;

		if (cap - len < 2) {
			char *nb;
			size_t newcap;
			if (!__size_mul_checked(cap, 2, &newcap)) { free(buf); return -1; }
			nb = realloc(buf, newcap);
			if (!nb) { free(buf); return -1; }
			buf = nb;
			cap = newcap;
		}
		room = cap - len - 1;
		n = fread(buf + len, 1, room, f);
		if (n > room) { free(buf); return -1; }   /* cannot happen; keeps the bound checked, not assumed */
		len += n;
		if (n < room) break;                       /* EOF or error: nothing more is coming */
	}
	if (ferror(f)) { free(buf); return -1; }
	buf[len] = 0;
	*out = buf;
	return 0;
}

static void usage(void)
{
	/* usage() accompanies EX_USAGE and has no independent status channel. */
	(void)fprintf(stderr,
		"usage: %s -c command_string [command_name [argument...]]\n"
		"       %s [-s] [command_file [argument...]]\n",
		progname, progname);
}

int __sh_main(int argc, char **argv)
{
	const char *cmdstr = 0;
	const char *file = 0;
	int stdin_flag = 0;
	char *text = 0;
	char err[256];
	struct sh_list *list;
	int status = 0, i, pfirst;
	const char *zero;

	/* Reset rather than rely on the initialiser: __sh_run_script()
	 * below can call this more than once in one process. */
	progname = "sh";
	if (argc > 0 && argv[0] && *argv[0]) {
		const char *b = argv[0], *p;
		for (p = argv[0]; *p; p++) if (*p == '/' || *p == '\\') b = p + 1;
		if (*b) progname = b;
	}
	zero = progname;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (a[0] != '-' || a[1] == 0) break;   /* operand, or a lone "-" */
		if (strcmp(a, "--") == 0) { i++; break; }
		if (strcmp(a, "-c") == 0) {
			if (i + 1 >= argc) { diag("-c requires a command_string"); usage(); return EX_USAGE; }
			cmdstr = argv[++i];
			continue;
		}
		if (strcmp(a, "-s") == 0) { stdin_flag = 1; continue; }
		diag("unrecognized option `%s'", a);
		usage();
		return EX_USAGE;
	}
	if (i < argc && strcmp(argv[i], "-") == 0) i++;   /* historical "-" */

	/* sh(1p) OPERANDS. Which operand is $0 differs by form, and 2.5.2 is
	 * emphatic that $0 is not itself a positional parameter:
	 *
	 *  - `sh -c command_string [command_name [argument...]]`:
	 *    command_name is $0, arguments after it are $1 on.
	 *  - `sh command_file [argument...]`: command_file is $0.
	 *  - `sh [-s] [argument...]`: program comes from stdin, so every
	 *    operand is a positional parameter.
	 *
	 * `progname` deliberately does *not* follow $0 for command_file:
	 * "script.sh: script.sh: cannot open command_file" would read as a
	 * confused shell. It does follow $0 for -c, where a build system
	 * chooses a name precisely so diagnostics carry it. */
	pfirst = argc;
	if (cmdstr) {
		if (i < argc && *argv[i]) progname = argv[i];   /* command_name is $0 */
		if (i < argc) { zero = argv[i]; pfirst = i + 1; }
	} else if (!stdin_flag && i < argc) {
		file = argv[i];
		zero = argv[i];
		pfirst = i + 1;
	} else {
		pfirst = i;
	}
	if (__sh_param_set_zero(zero) < 0 ||
	    __sh_params_replace(argv + pfirst, argc - pfirst) < 0) {
		diag("out of memory");
		return EX_USAGE;
	}

	if (cmdstr) {
		size_t n = strlen(cmdstr) + 1;
		text = malloc(n);
		if (!text) { diag("out of memory"); return EX_USAGE; }
		memcpy(text, cmdstr, n);
	} else if (file) {
		FILE *f = fopen(file, "rb");
		if (!f) { diag("%s: cannot open command_file", file); return EX_NOSCRIPT; }
		if (slurp(f, &text)) { (void)fclose(f); diag("%s: read error", file); return EX_NOSCRIPT; }
		(void)fclose(f);
	} else {
		if (slurp(stdin, &text)) { diag("stdin: read error"); return EX_NOSCRIPT; }
	}

	list = __sh_parse(text, err, sizeof err);
	if (!list) {
		diag("syntax error: %s", err);
		free(text);
		return EX_USAGE;
	}
	if (preflight(list)) {
		__sh_list_free(list);
		free(text);
		return EX_USAGE;
	}
	if (__sh_exec_list(list, &status)) {
		/* -1 means "cannot execute this AST node at all", no status
		 * written (e.g. two adjacent compound commands in one pipeline,
		 * which exec.c refuses rather than deadlock without fork()). */
		diag("cannot execute: an unsupported construct");
		__sh_list_free(list);
		free(text);
		return EX_USAGE;
	}
	__sh_list_free(list);
	free(text);
	return status;
}

/* ---- the [ENOEXEC] interpreter --------------------------------------
 *
 * Runs `argv` -- { arg0, command_file, argument..., 0 } -- as one
 * invocation of the sh utility above, in this process, and returns its
 * exit status.
 *
 * Adds re-entrancy to __sh_main(): the calling shell's positional
 * parameters, $0, and function definitions must survive this nested
 * invocation, so they're saved/restored with the same move-out/move-in
 * pair a subshell or function call already uses (param.c, func.c).
 *
 * __sh_flow_clear() consumes any pending `exit` on the way out, so this
 * invocation's exit doesn't unwind the calling shell too -- the same
 * thing sh.h already specifies at a subshell boundary. */
int __sh_run_script(int argc, char *const argv[])
{
	struct sh_params psaved;
	struct sh_funcs fsaved;
	char *zsaved;
	int status;

	{
		const char *z = __sh_param_zero();   /* never NULL; "sh" if unset */
		size_t n = strlen(z) + 1;
		zsaved = malloc(n);
		if (!zsaved) { diag("out of memory"); return EX_USAGE; }
		memcpy(zsaved, z, n);
	}
	__sh_params_take(&psaved);
	__sh_funcs_take(&fsaved);

	status = __sh_main(argc, (char **)argv);

	__sh_flow_clear();
	__sh_funcs_install(&fsaved);
	__sh_params_install(&psaved);
	__sh_param_set_zero(zsaved);
	free(zsaved);
	return status;
}
