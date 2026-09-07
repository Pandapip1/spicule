/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal AST and entry points for the in-process POSIX shell (see
 * test/sh-design.md for why this exists and how it links).  Nothing in
 * here is a public interface: it is linked into libc.a and consumed by
 * the other files in this directory, the sh/ binary's main()
 * (sh/main.c), and -- as of stage 5, through the single __sh_cmdsub()
 * call-out declared in src/internal/libc.h -- wordexp()'s command
 * substitution.  system() and popen() still hand their command string
 * to an external shell process rather than to this in-process one --
 * %ComSpec%/cmd.exe on NT, a PATH-resolved "sh" on Linux (src/stdlib/
 * system.c, src/stdio/misc.c) -- and wiring them into __sh_main()/
 * __sh_run_script() instead is test/sh-design.md's item 5, not this
 * stage's.  All names begin with __sh_ or SH_.
 *
 * Grammar coverage is the subset test/sh-design.md scopes in: simple
 * commands (including leading NAME=value assignments), pipelines,
 * '&&'/'||'/';'/newline lists, '&' as an asynchronous separator,
 * subshells '( list )' and brace groups '{ list ; }', redirections
 * including here-documents, (stage 5) command substitution in both the
 * '$(...)' and the '`...`' form, and (stage 6b) the compound commands
 * 'if/then/elif/else/fi', 'while|until ... do ... done' and
 * 'for name [in words] do ... done' (XCU 2.9.4).
 *
 * Stage 7 adds the positional and special parameters of XCU 2.5.1 and
 * 2.5.2 -- $1..$9, ${10} and beyond, $@, $*, $#, $0 -- together with
 * the 'set' and 'shift' special built-ins that manipulate them.  The
 * expansion itself is not in this directory: it belongs to the one
 * left-to-right scan in src/wordexp/wordexp.c, reached through
 * __wordexp_sh() (src/internal/libc.h), because "$@" produces a
 * *number of fields* from one word and only that scan knows what is
 * quoted.  src/sh/param.c owns the list.  'for name' with no 'in' list
 * is consequently real now: 2.9.4 defines it as 'in "$@"', and there
 * is a "$@".
 *
 * Stage 7b adds XCU 2.9.5's function definitions -- 'fname ( )
 * compound-command' -- with the 'return' special built-in, and 2.5.2's
 * '?'.  A function is "a compound command with new positional
 * parameters", which is why it could only follow stage 7a: the body is
 * stored as raw source text (see sh_command.func_text below on why),
 * the call installs a new parameter list and restores the caller's, and
 * XCU 2.9.1's search order puts the lookup between the special and the
 * regular built-ins rather than before or after both.
 *
 * Still out of scope, and still WORD tokens here: 'case', aliases and
 * job control.  Because each of those lexes as an ordinary WORD, a
 * program using one would otherwise be *executed* as something else
 * entirely (an external command called "case");
 * sh/main.c refuses such a program up front, with a diagnostic naming
 * what is unsupported, rather than letting it run -- see that file's
 * header for the full list and why refusing beats a misleading
 * "command not found".  The special parameters $!, $$ and $- are
 * refused there for the same reason.
 *
 * '!' pipeline negation is parsed as a reserved word (a bare, unquoted
 * WORD token whose text is exactly "!"/"{"/"}"), as are the compound
 * commands' own reserved words, all by the same rule (XCU 2.10.1 rule
 * 1) and recognised only where the grammar expects them; a misplaced
 * one -- a bare 'fi', a stray 'do' -- is a syntax error rather than a
 * command of that name.  Every other operator -- | & ; < > ( ) { } --
 * is tokenised as a true lexer-level operator and can therefore never
 * appear inside an unquoted WORD; this matches src/wordexp/wordexp.c,
 * which already rejects all of these as WRDE_BADCHAR when unquoted, so
 * the two layers agree on what a "word" is.
 */
#ifndef SPICULE_SH_H
#define SPICULE_SH_H

#include <stddef.h>
#include <stdio.h>
#include <allocation_tokens.h>
#include <ownership.h>

tokdef child_environment_allocated
	dynamic_storage
	implemented_by(internal_heap_allocated);

/* ---- words --------------------------------------------------------------
 * `text` is the raw source text of the word: quotes and backslashes are
 * kept exactly as written.  Expansion (parameter/tilde/pathname) and
 * quote removal happen later, at execution time, via the shared
 * routines factored out of src/wordexp/wordexp.c (see __sh_expand.h) --
 * the parser's only job is to find word boundaries correctly. */
struct sh_word {
	char *text;
	struct sh_word *next;
};

enum sh_redir_op {
	SH_R_LESS,       /* <  */
	SH_R_GREAT,      /* >  */
	SH_R_DGREAT,     /* >> */
	SH_R_LESSAND,    /* <& */
	SH_R_GREATAND,   /* >& */
	SH_R_LESSGREAT,  /* <> */
	SH_R_CLOBBER,    /* >| */
	SH_R_DLESS,      /* << */
	SH_R_DLESSDASH   /* <<- */
};

struct sh_redir {
	enum sh_redir_op op;
	int fd;              /* explicit io_number, or -1 for the operator's default */
	char *word;           /* target word / heredoc delimiter, raw text */
	char *heredoc;         /* SH_R_DLESS(DASH) only: the literal body text */
	char *heredoc_delim;   /* SH_R_DLESS(DASH) only: quote-removed delimiter */
	int heredoc_quoted;     /* SH_R_DLESS(DASH) only: delimiter was quoted -> body gets no expansion */
	struct sh_redir *next;
};

enum sh_cmd_kind {
	SH_CMD_SIMPLE,
	SH_CMD_SUBSHELL,
	SH_CMD_BRACE,
	SH_CMD_IF,     /* if/elif/else/fi     (XCU 2.9.4 "The if Conditional Construct") */
	SH_CMD_LOOP,   /* while/until/do/done (XCU 2.9.4 "The while Loop"/"The until Loop") */
	SH_CMD_FOR,    /* for/in/do/done      (XCU 2.9.4 "The for Loop") */
	SH_CMD_FUNCDEF /* fname ( ) compound-command  (XCU 2.9.5) */
};

/* One arm of an if command: the `if`/`elif` condition and the
 * `then` compound-list it guards.  2.9.4 gives `elif` exactly the same
 * shape as `if` ("each elif compound-list shall be executed, in turn,
 * and if its exit status is zero, the then compound-list shall be
 * executed"), so they are one node type in a list rather than a
 * separate case -- the `else` part is the only genuinely different
 * thing, and it hangs off the command instead. */
struct sh_ifarm {
	struct sh_list *cond;
	struct sh_list *body;
	struct sh_ifarm *next;
};

struct sh_command {
	enum sh_cmd_kind kind;

	union {
		struct {
			struct sh_word *assigns;  /* leading NAME=value prefix words */
			struct sh_word *words;    /* command name + arguments */
		} simple;

		/* SUBSHELL and BRACE are one case in every switch that touches
		 * this struct -- '(' and '{' differ only in how they print and
		 * which closing token ends them -- so they share this shape too. */
		struct {
			struct sh_list *body;
		} group;

		struct {
			struct sh_ifarm *arms;      /* the if arm, then each elif arm */
			struct sh_list *else_body;  /* the `else` part, or NULL */
		} ifcmd;

		struct {
			struct sh_list *cond;   /* compound-list-1 */
			struct sh_list *body;   /* the `do ... done` compound-list-2 */
			int until;              /* 0: `while`, 1: `until` */
		} loop;

		struct {
			char *name;              /* the NAME between `for` and `in` */
			/* the `in` word list, raw and unexpanded -- 2.9.4 says "the
			 * list of words following in shall be expanded to generate a
			 * list of items", i.e. at execution time, exactly like a
			 * simple command's arguments. */
			struct sh_word *words;
			int have_in;             /* 0: `for name` with no `in` word list,
			                          * which 2.9.4 defines as `in "$@"` -- see
			                          * exec.c and sh/main.c on why that is
			                          * refused rather than approximated */
			struct sh_list *body;    /* the `do ... done` compound-list */
		} forloop;

		struct {
			char *name;              /* the fname being defined */
			/* the function body, kept as its *raw source text* -- the
			 * compound-command (and any trailing io-redirect) exactly as
			 * written, from src/sh/parse.c's captured extent.
			 *
			 * Source rather than an AST node, which is the one design
			 * decision in this construct worth arguing.  2.9.5 says the
			 * body is executed "whenever the function name is specified
			 * as the name of a simple command", which can be long after
			 * the sh_list it was defined in has been freed:
			 * `__sh_cmdsub()` parses, executes and frees a complete AST
			 * per substitution, and test/sh-engine.c runs one program
			 * per `run()` call.  A function table holding borrowed
			 * pointers into those trees would be reading freed memory on
			 * the next call.  The alternatives are a deep-copy walk of
			 * the whole AST -- ~100 lines that must be kept in sync with
			 * every field added here, exactly the hazard new_command()'s
			 * comment in parse.c warns about -- or keeping the text,
			 * which is what the shell was handed in the first place and
			 * cannot fall out of sync with anything.  Re-parsing per
			 * call is the cost; a call already costs an expansion of
			 * every word in the body. */
			char *func_text;

			/* the body's AST, kept ONLY when the body contained a
			 * here-document -- see parse_funcdef() in src/sh/parse.c,
			 * which is the only place this is ever set, via its own
			 * hd_seen/pending_head bookkeeping, not by re-walking the
			 * tree. Two independent things need it kept alive for that
			 * case: the `struct sh_redir` a `struct pending_hd` still
			 * points at must not be freed out from under a
			 * drain_heredocs() still to come, AND -- separately -- when
			 * the drain has *already* happened by the time
			 * parse_funcdef() looks, the canonical printer still needs
			 * to walk this to put the already-drained here-document's
			 * body and terminator back into its output after the
			 * definition's terminating newline, since func_text above
			 * carries only the bare "<<DELIM" operator text, never the
			 * body/terminator lines that follow it in the source.
			 *
			 * This does NOT reintroduce the hazard the comment above
			 * rules out. That one is about the *function table* holding
			 * a borrowed pointer into an AST that is freed before the
			 * function is called; the table still stores text, and this
			 * field lives and dies with the sh_list the definition was
			 * parsed into -- which is exactly the lifetime the pending
			 * queue needs, since the queue is always drained before
			 * __sh_parse() returns. */
			struct sh_command *func_body;
		} funcdef;
	} u;

	/* every kind: redirections attached directly to this command.
	 * 2.9.4: "each can be followed by redirections on the same line as
	 * the terminator.  Each redirection shall apply to all the commands
	 * within the compound command that do not explicitly override that
	 * redirection." */
	struct sh_redir *redirs;
};

struct sh_pipeline {
	int bang;                     /* leading '!' */
	struct sh_command *commands;  /* array of ncommands */
	size_t ncommands;
};

enum sh_andor_op { SH_AO_NONE, SH_AO_AND, SH_AO_OR };

/* One term of an and-or list, e.g. "a && b || c" is three sh_andor
 * nodes: {a,NONE} -> {b,AND} -> {c,OR}, each op naming the operator
 * that joined *this* pipeline to the one before it. */
struct sh_andor {
	struct sh_pipeline pipeline;
	enum sh_andor_op op;
	struct sh_andor *next;
};

enum sh_sep {
	SH_SEP_SEQ,   /* ';' or a bare newline: run sequentially */
	SH_SEP_AMP,   /* '&': run asynchronously */
	SH_SEP_END    /* no separator: end of the list */
};

struct sh_list_item {
	struct sh_andor *andor;   /* linked list of pipelines, see sh_andor */
	enum sh_sep sep;
	struct sh_list_item *next;
};

struct sh_list {
	struct sh_list_item *items;
};

/* Parses `src` (the whole program text, e.g. sh -c's operand) as a
 * complete_command (XCU Grammar). On success returns a freshly
 * __malloc'd AST (free with __sh_list_free). On a syntax error returns
 * NULL and, if errbuf is non-NULL, writes a NUL-terminated diagnostic
 * (truncated to fit) into errbuf[0..errbuflen). An empty or all-blank/
 * all-comment `src` is not an error: it returns a non-NULL list with a
 * NULL items pointer. */
struct sh_list *__sh_parse(const char *src, char *errbuf, size_t errbuflen);

void __sh_list_free(struct sh_list *list);

/* Shared by __sh_list_free() and parse.c's parse-error cleanup paths. */
void __sh_free_words(struct sh_word *w);
void __sh_free_redirs(struct sh_redir *r);
/* Frees everything a sh_command *owns* (words/assigns/redirs/body), but
 * not the struct itself -- callers that store sh_command by value in an
 * array (see sh_pipeline.commands) free the array separately. */
/* c is required, unlike __sh_free_words()/__sh_free_redirs() above: this
 * frees a command's own contents, not a linked-list node walk, so there
 * is no "NULL means empty list" reading available -- free.c's own body
 * dereferences c unconditionally on entry, and every real call site
 * passes a real struct (see free.c). */
void __sh_free_command_contents(struct sh_command *c) __attribute__((nonnull(1)));

/* Reprints `list` in a canonical, re-parseable form. Used by stage 1's
 * parse-and-print tests and (harmlessly) available to anything that
 * wants to log a parsed command. Returns 0 for a complete print, -1 for
 * an allocation or stream-write failure. */
int __sh_print_list(FILE *f, const struct sh_list *list);

/* ---- execution (stage 2 on -- see src/sh/execute.c) --------------------
 *
 * Each of these returns 0 and writes an exit status through `status`
 * on success, or -1 (status left untouched) for a construct this
 * stage's executor does not implement yet -- see exec.c's header
 * comment for exactly which. Callers must not treat -1 as "exit status
 * -1"; it means "cannot execute this AST node at all right now".
 *
 * The command-substitution entry point wordexp() calls is deliberately
 * NOT here: it is declared in src/internal/libc.h, which is where a
 * declaration shared between source directories belongs. See
 * __sh_cmdsub() there and its implementation in exec.c. */
/* ---- built-in utilities (XCU 1.6, 2.9.1, 2.14) ----------------------
 *
 * src/sh/builtin.c owns the table and every implementation; exec.c
 * consults it from the one place XCU 2.9.1 says a command name is
 * decided -- after the word expansions, on the expanded argv, before
 * any PATH search.  See builtin.c's header comment for why `test`,
 * `:`, `true`, `false` and `exit` are built in here rather than left to
 * an honest "command not found". */
struct sh_builtin_ctx {
	int argc;             /* expanded argv count, argv[0] is the name */
	char **argv;
	int env_mutate;       /* 0: this invocation's effect on the shell
	                       * execution environment (XCU 2.12) is going
	                       * to be discarded -- e.g. one stage of a
	                       * multi-command pipeline */
	int last_status;      /* the status of the last command executed,
	                       * i.e. what `exit` with no operand uses */
	int status;           /* out: the utility's exit status */
};

struct sh_builtin {
	const char *name;
	int special;          /* XCU 2.14 special built-in (2.8.1 hangs
	                       * error consequences off this) */
	int env_effect;       /* changes something XCU 2.12 lists as part
	                       * of the shell execution environment */
	int (*fn)(struct sh_builtin_ctx *ctx);
};

const struct sh_builtin *__sh_builtin_lookup(const char *name);

/* ---- shell functions (XCU 2.9.5) ------------------------------------
 *
 * src/sh/func.c owns the table.  A definition is a (name, body-source)
 * pair -- see sh_command.func_text above for why the body is text.
 *
 * XCU 2.9.1's "Command Search and Execution" fixes where a lookup goes
 * relative to the built-ins, and it is not "before" or "after" but
 * *between*: step 1a runs a special built-in, step 1c runs a function,
 * step 1d runs the regular built-ins of its own table (`cd`, `true`,
 * `false`, ...), step 1e searches PATH.  So a function named `test`
 * shadows this shell's `test` built-in -- `test` is not even in 1d's
 * table, it is an ordinary PATH utility -- while a function named `set`
 * does not shadow `set`, and 2.9.5 forbids defining one ("the
 * application shall ensure that ... it is not the name of a special
 * built-in utility"), which src/sh/parse.c enforces at definition. */
struct sh_fn;
struct sh_funcs { struct sh_fn *head; };

int __sh_func_define(const char *name, const char *body);
const char *__sh_func_lookup(const char *name);
/* out/src/in/f are each required: func.c's own body dereferences the
 * struct sh_funcs * directly and unconditionally on entry to every one
 * of these four (`out->head = table;`, `for (f = src->head; ...)`,
 * `table = in->head;`, `free_chain(f->head);`), and every real call site
 * -- execute.c's params_subshell_enter()/params_subshell_leave()/
 * __sh_cmdsub(), script.c's __sh_run_script() -- always passes the
 * address of a real local. */
void __sh_funcs_take(struct sh_funcs *out)      /* move out, leaving none */
    __attribute__((nonnull(1)));
int __sh_funcs_copy(const struct sh_funcs *src) /* install a duplicate of src */
    __attribute__((nonnull(1)));
void __sh_funcs_install(struct sh_funcs *in)    /* move in, freeing current */
    __attribute__((nonnull(1)));
void __sh_funcs_free(struct sh_funcs *f)        /* release a taken table */
    __attribute__((nonnull(1)));

/* ---- positional and special parameters (XCU 2.5.1, 2.5.2) -----------
 *
 * src/sh/param.c owns the list; see that file's header for why it is an
 * array here rather than entries in `environ` like every other variable
 * this shell has.  Expansion of "$1"/"$@"/"$*"/"$#" is not done here:
 * it happens inside the one left-to-right scan that already knows what
 * is quoted, i.e. src/wordexp/wordexp.c, reached through
 * __wordexp_sh() (src/internal/libc.h) -- "$@" has to produce several
 * *fields* from one word, which nothing bolted on after that scan can
 * express. */
struct sh_params {
	char **v;   /* v[k] is $(k+1); NULL iff n == 0 */
	int n;      /* $# */
};

const char *__sh_param_zero(void);
int __sh_param_set_zero(const char *s);
int __sh_param_count(void);
const char *__sh_param_get(int n);            /* 1-based; NULL if unset */
/* argv is deliberately left unmarked: param.c's own `for (i = 0; i < n;
 * i++) nv[i] = dup_str(argv[i]);` is gated by `if (n > 0)`, and a real
 * caller -- execute.c's params_subshell_enter(), `__sh_params_replace(
 * saved->v, saved->n)` -- genuinely passes NULL for argv when saved->n
 * is 0, matching this very struct's own "v[k] ... NULL iff n == 0"
 * comment above. */
int __sh_params_replace(char *const *argv, int n);
int __sh_params_shift(int n);                 /* -1 if n > $# */
/* out/in/p are each required: param.c's own body dereferences the
 * struct sh_params * directly and unconditionally on entry to every one
 * of these three (`out->v = pv;`, `pv = in->v;`, `free_vec(p->v, p->n);`),
 * and every real call site always passes the address of a real local
 * (execute.c's subshell/cmdsub save-restore pairs, script.c's
 * __sh_run_script(), test/sh-engine.c). */
void __sh_params_take(struct sh_params *out)      /* move out, leaving none */
    __attribute__((nonnull(1)));
void __sh_params_install(struct sh_params *in)    /* move in, freeing current */
    __attribute__((nonnull(1)));
void __sh_params_free(struct sh_params *p)
    __attribute__((nonnull(1)));

/* ---- the read-only attribute (XCU 2.14 readonly special built-in) ---
 *
 * src/sh/readonly.c owns the set; see that file's header for why a
 * name's read-only mark needs a store of its own rather than living in
 * `environ` alongside its value. name is required on all three: the
 * only real callers (src/sh/builtin.c's bi_readonly(),
 * src/sh/execute.c's exec_assignment_only()) always pass a NUL-terminated
 * name they already have in hand, never NULL. */
int __sh_readonly_is(const char *name)   /* 1 if name is marked, else 0 */
    __attribute__((nonnull(1)));
int __sh_readonly_mark(const char *name) /* idempotent; -1 only on OOM */
    __attribute__((nonnull(1)));
size_t __sh_readonly_count(void);
const char *__sh_readonly_name(size_t i); /* NULL if i is out of range */

/* ---- shell-wide control flow ----------------------------------------
 *
 * `exit` (XCU 2.14) has to unwind out of however many nested lists,
 * and-or terms and pipelines it is buried in, without any of them
 * mistaking the unwind for a command that failed.  A single pending
 * flag, checked by __sh_exec_list()/__sh_exec_andor() between items,
 * does that: they stop iterating and return normally with the status
 * already in *status.  A subshell environment (a "( list )", a command
 * substitution, or a pipeline stage) consumes the pending exit instead
 * of propagating it, because that is what exiting *that* subshell
 * means.  Implemented in exec.c, which is what drives execution. */
void __sh_flow_exit(int status);
int __sh_flow_pending(void);
void __sh_flow_clear(void);

/* `return` (XCU 2.14, return(1p)) unwinds to the nearest *function*
 * boundary instead of out of the shell, so it is a second pending flag
 * rather than a reuse of `exit`'s: the two differ in exactly one place,
 * which is who consumes them.  __sh_flow_pending() answers "is some
 * unwind in progress?" for both, so every list/and-or loop that already
 * checks it needs no change; __sh_flow_clear() clears both, which is
 * what makes "( return 3 )" exit that subshell and let the function
 * carry on, exactly as it makes "( exit 3 )" exit that subshell.  Only
 * a function call consumes a pending `return`. */
void __sh_flow_return(int status);
int __sh_flow_return_pending(void);
int __sh_flow_return_status(void);
void __sh_flow_return_clear(void);

/* Nonzero while a function body is executing.  return(1p) makes the
 * result of `return` outside a function unspecified; this shell
 * diagnoses it rather than guessing, and this is what it asks. */
int __sh_in_function(void);

/* The status of the last command executed (XCU 2.8.2), maintained by
 * exec.c and read by `exit` with no operand. */
int __sh_last_status(void);

/* cmd/pl/a are required in each case (see execute.c's own definitions
 * for exactly which unconditional dereference proves it); status is
 * required for __sh_exec_pipeline() and __sh_exec_andor(), which both
 * dereference it directly and not merely forward it, but deliberately
 * NOT for __sh_exec_command() (forward-only) or __sh_exec_list() (whose
 * OTHER parameter, list, is the one genuinely optional here -- NULL
 * means an empty compound-command body, e.g. an absent `else`, and
 * execute.c's own `if (!list) return 0;` is the real, working check for
 * it). */
int __sh_exec_command(const struct sh_command *cmd, int *status)
    __attribute__((nonnull(1)));
int __sh_exec_pipeline(const struct sh_pipeline *pl, int *status)
    __attribute__((nonnull(1, 2)));
int __sh_exec_andor(const struct sh_andor *a, int *status)
    __attribute__((nonnull(1, 2)));
int __sh_exec_list(const struct sh_list *list, int *status)
    __attribute__((nonnull(2)));

/* ---- the utility (src/sh/script.c) ----------------------------------
 *
 * __sh_main() is sh(1p) itself -- options, operands, the refusal
 * preflight, and the run -- as a function, so that sh/main.c and the
 * [ENOEXEC] interpreter reach the same code rather than one of them
 * spawning the other.  __sh_run_script() wraps it for a caller that may
 * already have a shell running in this process; it is the only one of
 * the two declared in src/internal/libc.h, because it is the only one
 * anything outside src/sh/ and sh/ calls. */
/* argv is required: `argv[0]` is indexed to decide `progname` in this
 * function's own preamble, and the `argc > 0` guard alongside it does
 * not by itself prove argv non-null to a static analyzer (nor, for that
 * matter, at runtime -- a caller could pass a positive argc with a NULL
 * argv). Both real callers -- sh/main.c's own main(), and
 * __sh_run_script() below -- always forward a real argv, matching the
 * standard C convention that argv is never NULL even when argc is 0. */
int __sh_main(int argc, char **argv) __attribute__((nonnull(2)));

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
