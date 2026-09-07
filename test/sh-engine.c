/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Conformance tests for the in-process shell *engine* -- see
 * test/sh-design.md for why this exists at all, and src/sh/sh.h for the
 * AST, the two deliberate lexical simplifications the lexer makes, and
 * the -1 "not implemented at this stage" convention __sh_exec_*() use.
 *
 * Named sh-engine.c, not sh.c, because the real shell binary
 * (sh/main.c -> obj/sh/sh.exe) already owns that name and CI's
 * real-Windows legs flatten every test executable into one directory.
 * The name also says what this file covers: the engine linked out of
 * libc.a, driven in-process through __sh_parse()/__sh_exec_*(), never a
 * second image. Black-box tests of the *program* -- argument handling,
 * exit status, diagnostics -- live in test/sh-main.c and spawn
 * obj/sh/sh.exe for real.
 *
 * Stage 1 (lexer/parser, no execution) tests inspect the parsed AST
 * directly or round-trip through __sh_print_list() and reparse. Stage 2
 * (simple commands) and stage 3 (redirections/pipelines) tests actually
 * run processes: they re-exec this binary as the command(s), matching
 * test/misc.c's test_abort_child() pattern -- argv[1] selects a role
 * (child_role() below) so redirection/pipeline tests don't depend on
 * any external program.
 *
 * The internal entry points (__sh_parse/__sh_print_list/__sh_list_free/
 * __sh_exec_*) aren't in any installed header -- src/sh/sh.h is reached
 * with a plain relative #include, like the rest of this suite declares
 * internal-but-linked symbols itself.
 *
 * Spec pages consulted (https://pubs.opengroup.org/onlinepubs/9699919799/
 * utilities/V3_chap02.html):
 *   2.2 Quoting  2.3 Token Recognition (comments: rule 9)
 *   2.7 Redirection  2.7.1 Redirecting Input  2.7.2 Redirecting Output
 *   2.7.3 Appending Redirected Output  2.7.4 Here-Document
 *   2.7.5/2.7.6 Duplicating an Input/Output File Descriptor
 *   2.7.7 Open File Descriptors for Reading and Writing
 *   2.8.1 Consequences of Shell Errors
 *   2.9.1 Simple Commands  2.9.2 Pipelines  2.9.3 Lists
 *   2.9.4 Compound Commands (Grouping Commands)
 *   2.10.2 Shell Grammar Rules
 *   2.2.2 Single-Quotes  2.2.3 Double-Quotes
 *   2.6.3 Command Substitution  2.6.5 Field Splitting
 *   2.12 Shell Execution Environment
 *   2.14 Special Built-In Utilities
 * and, for stage 6a's built-ins, the utility pages themselves:
 *   utilities/test.html (OPERANDS, EXTENDED DESCRIPTION, EXIT STATUS)
 *   utilities/true.html  utilities/false.html  utilities/cd.html
 */
/* fmemopen()/mkstemp()/strdup()/setenv()/unsetenv() are feature-test
 * gated in include/stdio.h and include/stdlib.h; same define most
 * other tests in test/ already carry for the same reason (see
 * test/posix-glob.c's comment on this exact define). */
#define _GNU_SOURCE
#include "test-policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include "../src/sh/sh.h"

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static struct sh_list *must_parse(const char *src)
{
	char err[256];
	struct sh_list *l = __sh_parse(src, err, sizeof err);
	if (!l) printf("  unexpected parse failure for %s: %s\n", src, err);
	CHECK(l != 0);
	return l;
}

static void must_reject(const char *src)
{
	char err[256];
	struct sh_list *l = __sh_parse(src, err, sizeof err);
	if (l) { printf("  unexpectedly accepted: %s\n", src); __sh_list_free(l); }
	CHECK(l == 0);
	CHECK(err[0] != 0); /* a diagnostic was actually written */
}

static struct sh_command *only_command(struct sh_list *l)
{
	CHECK(l->items != 0);
	if (!l->items) return 0;
	CHECK(l->items->next == 0);
	CHECK(l->items->andor != 0);
	CHECK(l->items->andor->next == 0);
	CHECK(l->items->andor->pipeline.ncommands == 1);
	return &l->items->andor->pipeline.commands[0];
}

/* ---- 2.9.1 Simple Commands ---------------------------------------------- */

static void test_simple_command_words(void)
{
	struct sh_list *l = must_parse("echo hello world");
	struct sh_command *c;
	struct sh_word *w;
	if (!l) return;
	c = only_command(l);
	CHECK(c && c->kind == SH_CMD_SIMPLE);
	CHECK(c && c->u.simple.assigns == 0);
	CHECK(c && c->redirs == 0);
	if (c) {
		w = c->u.simple.words;
		CHECK(w && strcmp(w->text, "echo") == 0); w = w ? w->next : 0;
		CHECK(w && strcmp(w->text, "hello") == 0); w = w ? w->next : 0;
		CHECK(w && strcmp(w->text, "world") == 0); w = w ? w->next : 0;
		CHECK(w == 0);
	}
	__sh_list_free(l);
}

/* 2.9.1: "variable assignments specified with any of the other command
 * types... shall affect only that command's execution environment" --
 * cmd_prefix's assignment words must be recognised and kept separate
 * from the command name/arguments, and only when they precede the
 * first ordinary word (a NAME=value *after* the command name is just
 * an argument, e.g. "echo FOO=bar"). */
static void test_assignment_prefix(void)
{
	struct sh_list *l = must_parse("FOO=bar BAZ=1 echo $FOO");
	struct sh_command *c;
	if (!l) return;
	c = only_command(l);
	CHECK(c && c->u.simple.assigns && strcmp(c->u.simple.assigns->text, "FOO=bar") == 0);
	CHECK(c && c->u.simple.assigns && c->u.simple.assigns->next && strcmp(c->u.simple.assigns->next->text, "BAZ=1") == 0);
	CHECK(c && c->u.simple.assigns && c->u.simple.assigns->next && c->u.simple.assigns->next->next == 0);
	CHECK(c && c->u.simple.words && strcmp(c->u.simple.words->text, "echo") == 0);
	CHECK(c && c->u.simple.words && c->u.simple.words->next && strcmp(c->u.simple.words->next->text, "$FOO") == 0);
	__sh_list_free(l);

	l = must_parse("echo FOO=bar");
	if (!l) return;
	c = only_command(l);
	CHECK(c && c->u.simple.assigns == 0);
	CHECK(c && c->u.simple.words && strcmp(c->u.simple.words->text, "echo") == 0);
	CHECK(c && c->u.simple.words && c->u.simple.words->next && strcmp(c->u.simple.words->next->text, "FOO=bar") == 0);
	__sh_list_free(l);
}

/* An all-assignment command (no cmd_word at all) is still a valid
 * simple_command per the grammar (cmd_prefix alone). */
static void test_assignment_only_command(void)
{
	struct sh_list *l = must_parse("FOO=bar");
	struct sh_command *c;
	if (!l) return;
	c = only_command(l);
	CHECK(c && c->u.simple.assigns && strcmp(c->u.simple.assigns->text, "FOO=bar") == 0);
	CHECK(c && c->u.simple.words == 0);
	__sh_list_free(l);
}

/* ---- 2.2 Quoting / 2.3 Token Recognition -------------------------------- */

/* An operator character loses its special meaning inside quotes, so
 * "a;b" is one word, not a command separator splitting the line. Word
 * text is kept raw (quotes intact) at this stage -- see sh.h. */
static void test_quoting_suppresses_operators(void)
{
	struct sh_list *l = must_parse("echo \"a;b\" 'c|d'");
	struct sh_command *c;
	if (!l) return;
	c = only_command(l);
	CHECK(c && c->u.simple.words && c->u.simple.words->next && strcmp(c->u.simple.words->next->text, "\"a;b\"") == 0);
	CHECK(c && c->u.simple.words && c->u.simple.words->next && c->u.simple.words->next->next &&
	      strcmp(c->u.simple.words->next->next->text, "'c|d'") == 0);
	__sh_list_free(l);
}

/* 2.6.3 Command Substitution / 2.6.2 Parameter Expansion: the '(' after
 * an unquoted "$(", the '{' after an unquoted "${", and the matching
 * old-form backtick pair are part of the *word*, not operator/break
 * characters -- even though '(' '{' '`' are otherwise always
 * lexer-level operators/word-enders in this implementation (see
 * sh.h). Actually running the substituted command is stage 5's job;
 * this only proves the word boundary comes out right, including
 * nested parens/braces and an embedded pipe/semicolon that must not
 * be mistaken for real operators. */
static void test_dollar_paren_and_brace_word_boundary(void)
{
	struct sh_list *l = must_parse("echo $(a | b; c) ${FOO} $((1+2))");
	struct sh_command *c;
	struct sh_word *w;
	if (!l) return;
	c = only_command(l);
	CHECK(c != 0);
	if (!c) { __sh_list_free(l); return; }
	w = c->u.simple.words;
	CHECK(w && strcmp(w->text, "echo") == 0); w = w ? w->next : 0;
	CHECK(w && strcmp(w->text, "$(a | b; c)") == 0); w = w ? w->next : 0;
	CHECK(w && strcmp(w->text, "${FOO}") == 0); w = w ? w->next : 0;
	CHECK(w && strcmp(w->text, "$((1+2))") == 0); w = w ? w->next : 0;
	CHECK(w == 0);
	__sh_list_free(l);
}

static void test_backtick_word_boundary(void)
{
	struct sh_list *l = must_parse("echo `a | b; c`suffix");
	struct sh_command *c;
	if (!l) return;
	c = only_command(l);
	CHECK(c && c->u.simple.words && c->u.simple.words->next && strcmp(c->u.simple.words->next->text, "`a | b; c`suffix") == 0);
	CHECK(c && c->u.simple.words && c->u.simple.words->next && c->u.simple.words->next->next == 0);
	__sh_list_free(l);
}

/* rule 9: '#' starts a comment only when it begins a new word, and it
 * runs to (not including) the next newline. */
static void test_comment(void)
{
	struct sh_list *l = must_parse("echo hi # this ; is && not | code\necho bye");
	struct sh_command *c;
	if (!l) return;
	CHECK(l->items && l->items->next && l->items->next->next == 0);
	c = &l->items->andor->pipeline.commands[0];
	CHECK(c->u.simple.words && c->u.simple.words->next && strcmp(c->u.simple.words->next->text, "hi") == 0);
	CHECK(c->u.simple.words && c->u.simple.words->next && c->u.simple.words->next->next == 0);
	c = &l->items->next->andor->pipeline.commands[0];
	CHECK(c->u.simple.words && strcmp(c->u.simple.words->text, "echo") == 0);
	__sh_list_free(l);

	l = must_parse("echo abc#def");
	if (!l) return;
	c = only_command(l);
	CHECK(c && c->u.simple.words && c->u.simple.words->next && strcmp(c->u.simple.words->next->text, "abc#def") == 0);
	__sh_list_free(l);
}

static void test_empty_and_comment_only(void)
{
	struct sh_list *l = must_parse("");
	CHECK(l && l->items == 0);
	__sh_list_free(l);

	l = must_parse("   \n\n  ");
	CHECK(l && l->items == 0);
	__sh_list_free(l);

	l = must_parse("# just a comment\n");
	CHECK(l && l->items == 0);
	__sh_list_free(l);
}

/* ---- 2.9.2 Pipelines ----------------------------------------------------- */

static void test_pipeline(void)
{
	struct sh_list *l = must_parse("a | b | c");
	struct sh_pipeline *pl;
	if (!l) return;
	pl = &l->items->andor->pipeline;
	CHECK(pl->ncommands == 3);
	CHECK(pl->bang == 0);
	CHECK(strcmp(pl->commands[0].u.simple.words->text, "a") == 0);
	CHECK(strcmp(pl->commands[1].u.simple.words->text, "b") == 0);
	CHECK(strcmp(pl->commands[2].u.simple.words->text, "c") == 0);
	__sh_list_free(l);
}

static void test_pipeline_bang(void)
{
	struct sh_list *l = must_parse("! false");
	struct sh_pipeline *pl;
	if (!l) return;
	pl = &l->items->andor->pipeline;
	CHECK(pl->bang == 1);
	CHECK(pl->ncommands == 1);
	CHECK(strcmp(pl->commands[0].u.simple.words->text, "false") == 0);
	__sh_list_free(l);
}

/* ---- 2.9.3 Lists ----------------------------------------------------------
 * "&&" and "||" are left-associative and have equal precedence; a
 * pipeline not preceded by one is unconditional (SH_AO_NONE here). */
static void test_andor(void)
{
	struct sh_list *l = must_parse("a && b || c");
	struct sh_andor *a;
	if (!l) return;
	a = l->items->andor;
	CHECK(a && a->op == SH_AO_NONE && strcmp(a->pipeline.commands[0].u.simple.words->text, "a") == 0);
	a = a ? a->next : 0;
	CHECK(a && a->op == SH_AO_AND && strcmp(a->pipeline.commands[0].u.simple.words->text, "b") == 0);
	a = a ? a->next : 0;
	CHECK(a && a->op == SH_AO_OR && strcmp(a->pipeline.commands[0].u.simple.words->text, "c") == 0);
	CHECK(a && a->next == 0);
	__sh_list_free(l);
}

/* ';' and '&' are both separators; '&' additionally marks the
 * preceding and-or list for asynchronous execution.  A trailing
 * separator (or none) both leave the final item's sep distinguishable
 * (SH_SEP_END here means "no separator was present"). */
static void test_list_separators(void)
{
	struct sh_list *l = must_parse("a; b & c");
	struct sh_list_item *it;
	if (!l) return;
	it = l->items;
	CHECK(it && it->sep == SH_SEP_SEQ && strcmp(it->andor->pipeline.commands[0].u.simple.words->text, "a") == 0);
	it = it ? it->next : 0;
	CHECK(it && it->sep == SH_SEP_AMP && strcmp(it->andor->pipeline.commands[0].u.simple.words->text, "b") == 0);
	it = it ? it->next : 0;
	CHECK(it && it->sep == SH_SEP_END && strcmp(it->andor->pipeline.commands[0].u.simple.words->text, "c") == 0);
	CHECK(it && it->next == 0);
	__sh_list_free(l);
}

/* ---- 2.9.4 Compound Commands (Grouping Commands) -------------------------- */

static void test_subshell(void)
{
	struct sh_list *l = must_parse("(a; b)");
	struct sh_command *c;
	if (!l) return;
	c = only_command(l);
	CHECK(c && c->kind == SH_CMD_SUBSHELL);
	CHECK(c && c->u.group.body && c->u.group.body->items && c->u.group.body->items->next && c->u.group.body->items->next->next == 0);
	CHECK(c && c->u.group.body && strcmp(c->u.group.body->items->andor->pipeline.commands[0].u.simple.words->text, "a") == 0);
	CHECK(c && c->u.group.body && strcmp(c->u.group.body->items->next->andor->pipeline.commands[0].u.simple.words->text, "b") == 0);
	__sh_list_free(l);
}

static void test_brace_group(void)
{
	struct sh_list *l = must_parse("{ a; b; }");
	struct sh_command *c;
	if (!l) return;
	c = only_command(l);
	CHECK(c && c->kind == SH_CMD_BRACE);
	CHECK(c && c->u.group.body && c->u.group.body->items && c->u.group.body->items->next && c->u.group.body->items->next->next == 0);
	__sh_list_free(l);
}

static void test_subshell_nested_and_redirected(void)
{
	struct sh_list *l = must_parse("(echo hi) > out");
	struct sh_command *c;
	if (!l) return;
	c = only_command(l);
	CHECK(c && c->kind == SH_CMD_SUBSHELL);
	CHECK(c && c->redirs && c->redirs->op == SH_R_GREAT && strcmp(c->redirs->word, "out") == 0);
	__sh_list_free(l);
}

/* ---- 2.7 Redirection ------------------------------------------------------ */

static void test_redirections(void)
{
	struct sh_list *l = must_parse("cmd > out 2>&1 < in 3<&4 >> app");
	struct sh_command *c;
	struct sh_redir *r;
	if (!l) return;
	c = only_command(l);
	CHECK(c != 0);
	if (!c) { __sh_list_free(l); return; }
	r = c->redirs;
	CHECK(r && r->op == SH_R_GREAT && r->fd == -1 && strcmp(r->word, "out") == 0); r = r ? r->next : 0;
	CHECK(r && r->op == SH_R_GREATAND && r->fd == 2 && strcmp(r->word, "1") == 0); r = r ? r->next : 0;
	CHECK(r && r->op == SH_R_LESS && r->fd == -1 && strcmp(r->word, "in") == 0); r = r ? r->next : 0;
	CHECK(r && r->op == SH_R_LESSAND && r->fd == 3 && strcmp(r->word, "4") == 0); r = r ? r->next : 0;
	CHECK(r && r->op == SH_R_DGREAT && r->fd == -1 && strcmp(r->word, "app") == 0); r = r ? r->next : 0;
	CHECK(r == 0);
	/* the io_number/redirect target words never became command args */
	CHECK(c->u.simple.words && c->u.simple.words->next == 0 && strcmp(c->u.simple.words->text, "cmd") == 0);
	__sh_list_free(l);
}

/* ---- 2.7.4 Here-Document --------------------------------------------------- */

static void test_heredoc_basic(void)
{
	struct sh_list *l = must_parse("cat <<EOF\nhello\nworld\nEOF\n");
	struct sh_command *c;
	if (!l) return;
	c = only_command(l);
	CHECK(c && c->redirs && c->redirs->op == SH_R_DLESS);
	CHECK(c && c->redirs && strcmp(c->redirs->word, "EOF") == 0);
	CHECK(c && c->redirs && !c->redirs->heredoc_quoted);
	CHECK(c && c->redirs && c->redirs->heredoc && strcmp(c->redirs->heredoc, "hello\nworld\n") == 0);
	__sh_list_free(l);
}

/* "<<-" strips leading <tab> characters from the body *and* the
 * delimiter line. */
static void test_heredoc_dash_strips_tabs(void)
{
	struct sh_list *l = must_parse("cat <<-END\n\t\thello\n\tEND\n");
	struct sh_command *c;
	if (!l) return;
	c = only_command(l);
	CHECK(c && c->redirs && c->redirs->op == SH_R_DLESSDASH);
	CHECK(c && c->redirs && c->redirs->heredoc && strcmp(c->redirs->heredoc, "hello\n") == 0);
	__sh_list_free(l);
}

/* A quoted delimiter ("shall be quoted" -> no expansions in the body)
 * is still matched against the *unquoted* terminator line, per 2.7.4's
 * "quote removal is performed on the delimiter". */
static void test_heredoc_quoted_delimiter(void)
{
	struct sh_list *l = must_parse("cat <<'EOF'\n$x literal\nEOF\n");
	struct sh_command *c;
	if (!l) return;
	c = only_command(l);
	CHECK(c && c->redirs && c->redirs->heredoc_quoted == 1);
	CHECK(c && c->redirs && c->redirs->heredoc && strcmp(c->redirs->heredoc, "$x literal\n") == 0);
	__sh_list_free(l);
}

static void test_heredoc_two_on_one_line(void)
{
	struct sh_list *l = must_parse("cat <<A <<B\nfirst\nA\nsecond\nB\n");
	struct sh_command *c;
	if (!l) return;
	c = only_command(l);
	CHECK(c && c->redirs && c->redirs->heredoc && strcmp(c->redirs->heredoc, "first\n") == 0);
	CHECK(c && c->redirs && c->redirs->next && c->redirs->next->heredoc &&
	      strcmp(c->redirs->next->heredoc, "second\n") == 0);
	__sh_list_free(l);
}

/* ---- 2.10.2 Shell Grammar Rules: malformed input must be rejected -------- */

static void test_rejects_malformed(void)
{
	must_reject("(a; b");                 /* unterminated subshell */
	must_reject("a)");                    /* stray ')' */
	must_reject("{ a; b");                /* unterminated brace group */
	must_reject("a &&");                  /* '&&' with no right operand */
	must_reject("a |");                   /* '|' with no right side */
	must_reject("| a");                   /* pipeline with no left side */
	must_reject("echo \"unterminated");   /* unterminated double quote */
	must_reject("echo 'unterminated");    /* unterminated single quote */
	must_reject("echo \\");               /* trailing backslash, nothing to escape */
	must_reject("cat <<EOF\nno terminator here\n"); /* here-doc delimiter never seen */
	must_reject(">");                     /* redirection operator with no target word */
	must_reject(";");                     /* separator with nothing before it */

	/* Stage 6b: XCU 2.10.1 rule 1 -- "when the TOKEN is exactly a
	 * reserved word, the token identifier for that reserved word shall
	 * result".  In command position, each of these can only be a
	 * misplaced terminator, so it is a syntax error and not a command
	 * of that name.  This is the assertion that keeps sh/main.c's
	 * refuse-before-anything-runs property after `if`/`for` came off
	 * its reserved-word list: without it they would go back to being
	 * an external command that exits 127 about a fiction. */
	must_reject("fi");
	must_reject("then");
	must_reject("else");
	must_reject("elif");
	must_reject("do");
	must_reject("done");
	must_reject("in");
	must_reject("echo hi; done");         /* misplaced anywhere, not just first */
	must_reject("if true; then a");       /* `then` part never terminated */
	must_reject("if true; a; fi");        /* no `then` at all */
	must_reject("while true; a; done");   /* no `do` */
	must_reject("while true; do a");      /* `do` never terminated */
	must_reject("for; do a; done");       /* no name */
	must_reject("for 9x in a; do b; done"); /* not a NAME (rule 5) */
	must_reject("for f in a b");          /* no do_group */

	/* "a <<E (" belongs here -- it is malformed and it is rejected --
	 * but it is in the fenced case below instead: it leaks, and
	 * test/ runs under `make asan` with leak detection on.  "()<a<"
	 * was fenced next to it for a different reason; it has its own
	 * test below now, where the leak-detection reasoning lives. */
}

/* 2.9.4 lets a subshell or brace group be followed by redirections, and
 * src/sh/parse.c collects them in a loop that attaches each one to the
 * command as it is parsed.  When a later redirection in that run fails
 * to parse, everything the loop has already attached is part of the
 * half-built command and has to go with it: parse.c hands the whole
 * node to free_command(), which frees cmd->redirs along with the group's
 * body, its words and the node itself.
 *
 * This case was fenced as a BUG -- "frees cmd->body and cmd but NOT
 * cmd->redirs", 42 bytes per redirection already collected (40 for the
 * struct sh_redir, plus the xstrdup of its target word), a leak whose
 * size the input chooses.  That was true when it was written: at
 * 821cd72, where src/sh/parse.c first appears, the group loop's failure
 * path is `{ __sh_list_free(cmd->body); __free(cmd); return 0; }` while
 * `simple_fail:` forty lines above does call __sh_free_redirs().  The
 * fence is stale rather than wrong -- 309cd94 ("stage 6b -- the
 * if/while/until/for compound commands") routed both labels through
 * free_command(), which reaches cmd->redirs unconditionally via free.c's
 * __sh_free_command_contents(), and closed the leak as a side effect of
 * a refactor whose message never mentions it.  Un-fenced on evidence
 * rather than on either prose: the fence's own reproducers leak nothing
 * under `make asan`, and a fuzz/fuzz_shparse.c run with its
 * group_redir_fence() deleted found none either.
 *
 * The test stays, because what it pins is worth pinning and nothing
 * else pinned it.  The group path is reached from two directions --
 * fallthrough from the '(' / '{' branches, and the `goto
 * trailing_redirs` the if/while/until/for parsers take -- and every
 * pre-existing redirection test redirects a *simple* command, so no
 * test covered a trailing redirection that fails to parse after
 * earlier ones succeeded.  Replacing that one free_command() call
 * with the hand-rolled free the fence describes makes this function
 * leak 1410 bytes in 31 allocations: that is what says the assertions
 * below are not passing vacuously, and it is also what rules out the
 * other reading of a clean run -- that leak detection was not on.
 *
 * There is no CHECK() spelling for "this allocation was freed", so what
 * the rejections below assert directly is only that each malformed
 * program is diagnosed rather than accepted.  The freeing is what
 * `make asan` checks: these cases run with detect_leaks=1, and their
 * redirection counts are graded 1/2/3 so a leak linear in that count
 * shows up as a report that grows rather than one fixed number.  Both
 * spellings of the errbuf argument are exercised, since a NULL errbuf
 * takes a different exit out of __sh_parse(). */
static void test_group_redir_leak(void)
{
	struct sh_list *l;
	struct sh_command *c;
	struct sh_redir *r;

	must_reject("()<a<");                  /* one already collected */
	must_reject("()<a<b<");                /* two */
	must_reject("(x)2>a 3>b 4>");          /* three, IO_NUMBER-prefixed */
	must_reject("{ x; }<a<");              /* brace group, same loop */
	must_reject("if x; then y; fi <a<");   /* reached via goto, not fallthrough */

	/* The errbuf-less call the fuzz harness makes, which leaves
	 * __sh_parse() by the branch that skips the copy-out. */
	CHECK(__sh_parse("()<a<b<", 0, 0) == 0);

	/* A trailing redirection list that parses is still collected, in
	 * order and with its IO numbers -- so none of the above can be
	 * satisfied by a parser that simply refuses to attach them. */
	l = must_parse("(x)2>a 3>b");
	if (!l) return;
	c = only_command(l);
	CHECK(c && c->kind == SH_CMD_SUBSHELL);
	CHECK(c && c->u.group.body != 0);
	r = c ? c->redirs : 0;
	CHECK(r && r->op == SH_R_GREAT && r->fd == 2 && strcmp(r->word, "a") == 0); r = r ? r->next : 0;
	CHECK(r && r->op == SH_R_GREAT && r->fd == 3 && strcmp(r->word, "b") == 0); r = r ? r->next : 0;
	CHECK(r == 0);
	__sh_list_free(l);
}

#if SPICULE_TEST(PASS, sh_engine_heredoc_queue_leak) /* A here-document that is queued and never drained releases
	 * its queue entry.  parse_redir() (src/sh/parse.c:524) pushes a
	 * `struct pending_hd` onto the lexer's pending list *before* the
	 * advance() that would reach the newline -- deliberately, and the
	 * comment above it explains why it has to be that order.  But
	 * drain_heredocs() is the only thing that ever frees those
	 * entries, and it runs only when that newline actually arrives.
	 * A parse that fails first unwinds through __sh_parse()'s error
	 * path, which frees the AST and returns; nothing walks
	 * p.lx.pending_head, which parse.c:725 initialised and no code
	 * tears down.  24 bytes per queued here-document, per failed
	 * parse.
	 *
	 * Found by fuzz/fuzz_shparse.c under LeakSanitizer and reduced by
	 * hand to the case below.  Note that "a <<E" on its own does NOT
	 * leak -- it parses, so the queue drains -- which is why no fixed
	 * test had reached this.  fuzz_shparse.c's heredoc_fence() keeps
	 * the harness off it; delete that function and its calls when
	 * this fence is lifted.
	 *
	 * There is no CHECK() spelling for "this allocation was not
	 * freed", so the case is written as the smallest program that
	 * reproduces it and is left unbuilt.  Run it under
	 * `make asan` with detect_leaks=1 to see the report. */
static void test_heredoc_queue_leak(void)
{
	CHECK(__sh_parse("a <<E (", 0, 0) == 0);   /* leaks 24 bytes */
}
#endif

/* 2.7 says a redirection may be preceded by an IO_NUMBER, and 2.10.1
 * defines IO_NUMBER as a token "made up solely of digits" immediately
 * followed by '<' or '>'.  The clause puts no length on that digit
 * string, but the value has to end up in a redirection's `fd`, an int,
 * so src/sh/parse.c guards the accumulation: a digit string that will
 * not fit is diagnosed, not wrapped.  (It used to accumulate with an
 * unchecked `v = v * 10 + (w[i] - '0')` into an int, so fifteen digits
 * were signed overflow -- undefined behaviour, found here by
 * fuzz/fuzz_shparse.c under UBSan -- and where that did not trap, the
 * redirection was left holding whatever the wrap produced, possibly a
 * negative fd.)
 *
 * Both halves are asserted, because a guard that refused every IO
 * number would satisfy the first half alone: the out-of-range strings
 * are rejected, and the in-range ones still lex as IO_NUMBERs and
 * arrive at the redirection carrying the value they name. */
static void test_ionum_overflow(void)
{
	struct sh_list *l;
	struct sh_command *c;
	struct sh_redir *r;

	/* Fifteen digits: what used to be undefined behaviour. */
	must_reject("877777777777777<x");
	/* One past INT_MAX: refused rather than silently wrapped. */
	must_reject("2147483648<x");
	/* Long enough to wrap an int several times over. */
	must_reject("99999999999999999999999999>x");

	/* Ordinary IO numbers are unaffected, value included. */
	l = must_parse("cmd 2>out 10<in");
	if (!l) return;
	c = only_command(l);
	CHECK(c != 0);
	if (!c) { __sh_list_free(l); return; }
	r = c->redirs;
	CHECK(r && r->op == SH_R_GREAT && r->fd == 2 && strcmp(r->word, "out") == 0); r = r ? r->next : 0;
	CHECK(r && r->op == SH_R_LESS && r->fd == 10 && strcmp(r->word, "in") == 0); r = r ? r->next : 0;
	CHECK(r == 0);
	__sh_list_free(l);

	/* INT_MAX is in range by exactly one, and reaches the redirection
	 * intact -- the boundary the two rejections above sit one past. */
	l = must_parse("2147483647<x");
	if (!l) return;
	c = only_command(l);
	CHECK(c && c->redirs && c->redirs->op == SH_R_LESS && c->redirs->fd == 2147483647);
	__sh_list_free(l);
}

/* ---- parse-and-print round trip: stage 1's other testability requirement */

static void check_roundtrip(const char *src)
{
	struct sh_list *l1, *l2;
	char buf1[1024], buf2[1024];
	FILE *f1, *f2;

	l1 = must_parse(src);
	if (!l1) return;
	f1 = fmemopen(buf1, sizeof buf1, "w");
	CHECK(f1 != 0);
	if (f1) {
		int printed = __sh_print_list(f1, l1);
		int closed = fclose(f1);
		CHECK(printed == 0 && closed == 0);
	}
	__sh_list_free(l1);
	if (!f1) return;

	l2 = must_parse(buf1);
	if (!l2) return;
	f2 = fmemopen(buf2, sizeof buf2, "w");
	CHECK(f2 != 0);
	if (f2) {
		int printed = __sh_print_list(f2, l2);
		int closed = fclose(f2);
		CHECK(printed == 0 && closed == 0);
	}
	__sh_list_free(l2);
	if (!f2) return;

	if (strcmp(buf1, buf2) != 0)
		printf("  roundtrip mismatch for %s:\n    1: %s    2: %s\n", src, buf1, buf2);
	CHECK(strcmp(buf1, buf2) == 0);
}

static void test_roundtrip(void)
{
	check_roundtrip("echo hello world");
	check_roundtrip("FOO=bar echo $FOO");
	check_roundtrip("a | b | c");
	check_roundtrip("! a | b");
	check_roundtrip("a && b || c; d & e");
	check_roundtrip("(a; b) | { c; }");
	check_roundtrip("cmd > out 2>&1 < in");
	check_roundtrip("cat <<EOF\nhello\nworld\nEOF\n");
	check_roundtrip("cat <<-END\n\thi\n\tEND\n");
	check_roundtrip("echo \"a;b\" 'c|d'");
	check_roundtrip("echo $(a | b; c) ${FOO} $((1+2))");
	check_roundtrip("echo `a | b; c`suffix");

	/* Stage 6b.  These are the fields print.c would otherwise have no
	 * reason to visit -- an if's arm chain, a loop's separate
	 * condition, a for's name/have_in -- and the round trip is the one
	 * check that a printed compound command reparses as *the same*
	 * compound command rather than as something that merely parses. */
	check_roundtrip("if a; then b; fi");
	check_roundtrip("if a; then b; else c; fi");
	check_roundtrip("if a; then b; elif c; then d; else e; fi");
	check_roundtrip("if a; then b; elif c; then d; elif e; then f; fi");
	check_roundtrip("while a; do b; done");
	check_roundtrip("until a; do b; done");
	check_roundtrip("for f in a b c; do d; done");
	check_roundtrip("for f in; do d; done");
	check_roundtrip("if a | b && c; then d | e; fi");
	check_roundtrip("while a; do if b; then c; fi; done");
	check_roundtrip("if a; then b; fi > out 2>&1");
	check_roundtrip("for f in *.c; do cat $f; done | wc");
	check_roundtrip("(if a; then b; fi); { while c; do d; done; }");

	/* Stage 7b.  A function definition reprints its body as the raw
	 * source text src/sh/parse.c captured (sh.h's func_text), so the
	 * round trip is what checks that captured extent is *exactly* the
	 * body: too short and the reprint does not reparse, too long and
	 * it swallows the next command and the second print differs. */
	check_roundtrip("f() { :; }");
	check_roundtrip("f() { a; b; }");
	check_roundtrip("f() ( a )");
	check_roundtrip("f() if a; then b; fi");
	check_roundtrip("f() while a; do b; done");
	check_roundtrip("f() for i in a b; do c; done");
	check_roundtrip("f() { a; } > out");
	check_roundtrip("f() { :; }; g() { :; }; f");
	check_roundtrip("f() { :; }\ng() { :; }");
}

/* A here-document inside a function-definition body, where the function
 * definition is followed by a list operator.  This was a
 * heap-use-after-free, found by fuzz/fuzz_shparse.c and fixed in
 * src/sh/parse.c's parse_funcdef():
 *
 * parse_funcdef() parses the body only to find its extent and then
 * throws the AST away, but a `<<` inside that body has registered a
 * `struct pending_hd` holding a borrowed pointer to its `struct
 * sh_redir`, and that queue is drained at the next <newline> or at EOF
 * -- not at the end of the body.  So when the token after the body is
 * one parse_command() leaves for its caller ('|', '&', '&&', '||'),
 * the entry was still live when the body was freed, and
 * drain_heredocs() then read `h->redir->word` out of freed memory.
 * `f()(<<E)&` is the ten-byte reduction; the programs below are the
 * same shapes written out with a real terminator line so that they
 * parse.  The fix keeps the body in sh_command.u.funcdef.func_body
 * whenever anything is pending.
 *
 * WHAT THE ASSERTIONS ARE FOR, since a use-after-free need not be
 * visible in a `make check` build with no sanitizer: `make asan`
 * (tools/asan-build.sh) compiles the src/sh/ sources natively and runs
 * this very file under ASan, which is what turns the first case into a hard
 * failure.  Under plain `make check` these two assertions still
 * discriminate, against the OTHER way this could have been "fixed":
 * each program must parse, and must parse to exactly ONE list item.
 * Dropping the pending entry instead of keeping its redirection alive
 * would leave the here-document body and its terminator to be read as
 * two more commands, and the count would be three. */
static void test_funcdef_heredoc_before_list_operator(void)
{
	static const char *const progs[] = {
		"f()( a <<E )|b\nx\nE\n",
		"f()( a <<E )&\nx\nE\n",
		"f(){ a <<E ;}|b\nx\nE\n",
		"f()( a <<E )&& b\nx\nE\n",
		"f()( a <<E )|| b\nx\nE\n"
	};
	size_t i;

	for (i = 0; i < sizeof progs / sizeof *progs; i++) {
		struct sh_list *l = must_parse(progs[i]);
		if (!l) continue;
		CHECK(l->items != 0);
		if (l->items) CHECK(l->items->next == 0);
		__sh_list_free(l);
	}

	/* The retained body is also the printer's only route to a pending
	 * here-document.  If it prints only func_text, the following `x'
	 * line becomes the empty-delimiter here-document body on reparse and
	 * disappears from the second print.  Reduced from a fuzz finding. */
	check_roundtrip("f()()<<\"\"&x&\ny\n");
}

/* A here-document inside a function-definition body, where the function
 * definition is followed by nothing at all -- <newline> or EOF, not one
 * of '|'/'&'/'&&'/'||' -- the exact complement of
 * test_funcdef_heredoc_before_list_operator() above.  Found by
 * fuzz/fuzz_shparse.c: an ordinary libFuzzer run and an AFL++ run both
 * found the same defect independently.
 *
 * <newline>/EOF is exactly the case parse_funcdef() drains the
 * here-document itself, as a side effect of peeking the token that ends
 * the body: next_raw_token() drains on producing T_NEWLINE or T_EOF (see
 * its own comment), and that peek is what parse_funcdef() reads `end`
 * from.  So by the time parse_funcdef() used to ask "is anything still
 * pending?", the queue this bug's sibling above depends on had already
 * answered "no" -- even though the body plainly had a here-document.
 * cmd->u.funcdef.func_body was then freed, along with the only place the drained
 * body and terminator lived, and print_command()'s FUNCDEF case had
 * nothing left to reprint but the bare "<<DELIM" operator text inside
 * func_text.
 *
 * Reparsing that output registers a *fresh* pending here-document for
 * the same "<<DELIM" text, and drains it against whatever the ENCLOSING
 * list put after the function definition -- silently swallowing a
 * following command into a heredoc body that, per the first print, does
 * not exist, or erroring outright if nothing ever matches the
 * delimiter.  Either way the fixed point print.c's banner promises
 * fails, and an entire trailing command can go missing rather than a
 * mismatched byte.
 *
 * The fix (see parse.c's struct lexer and parse_funcdef()) is to ask a
 * question draining cannot retroactively unanswer: hd_seen counts every
 * "<<"/"<<-" registered during the body's parse and is never
 * decremented, so it still says "yes" here where pending_head alone no
 * longer can. */
static void test_funcdef_heredoc_at_end_of_line_roundtrip(void)
{
	/* The same shape as the UAF sibling's `f()(<<E)&`, but with no
	 * operator at all after the body -- just the terminating <newline>
	 * that both defects turn on. */
	check_roundtrip("f()(:)<<X\nbody\nX\n");

	/* The same shape with a command after it on the enclosing list: the
	 * defect this test exists for is specifically that this trailing
	 * command used to vanish (or the reparse errored outright), not
	 * merely that a byte differed. */
	check_roundtrip("f() (:)<<X\nbody\nX\necho hi\n");

	/* '{ }' body, and a `<<-` (dash-strip) heredoc instead of `<<`,
	 * exercising the other compound-command form and the other
	 * heredoc-dash bit hd_seen has to catch regardless. */
	check_roundtrip("f() { :; }<<-X\n\tbody\n\tX\necho hi\n");

	/* An empty-body heredoc -- the terminator line matches immediately,
	 * so there is nothing to swallow into *except* the next command,
	 * which is exactly what the 14-byte fuzzer-minimized case reduces
	 * to (funcdef, empty subshell, a plain redirect, an empty-bodied
	 * heredoc, then a leftover word forming a second list item). */
	check_roundtrip("f()()<f<<E\nE\nnext\n");
}

#if SPICULE_TEST(PASS, sh_engine_heredoc_quoted_delim_roundtrip) /* The printer writes a here-document's quote-removed terminator.
	 * the delimiter word was WRITTEN, while the parser matches
	 * terminator lines against the delimiter with quote removal
	 * APPLIED.  A quoted delimiter's printed terminator therefore
	 * does not terminate its own here-document.
	 *
	 * src/sh/print.c:41 drain_heredocs() writes fputs(r->word), the
	 * raw source text.  src/sh/parse.c:273 drain_heredocs() compares
	 * each line against strip_delim(r->word) (parse.c:235), which
	 * strips the quotes and sets heredoc_quoted.  Nothing reconciles
	 * them, so the two agree only for an unquoted delimiter.
	 *
	 * VERIFIED with a probe that dumps the AST between the stages:
	 *
	 *     src    "a<<\"\""
	 *     parse1  r->word = "\"\"" ; r->heredoc = ""  (empty body)
	 *     print1  a << ""\n""\n
	 *     parse2  r->word = "\"\"" ; r->heredoc = "\"\"\n"
	 *     print2  a << ""\n""\n""\n
	 *
	 * The delimiter is the empty string after quote removal, so the
	 * parser is looking for an EMPTY line; the printer gave it the
	 * two-character line "" instead, which is swallowed as body.
	 * Every round trip adds one line, so this fixed point does not
	 * merely fail, it diverges.
	 *
	 * The empty delimiter is what exposes it in a one-line program:
	 * it is the only quoted delimiter whose here-document can
	 * terminate with no body at all.  "a<<X" and "a<<\"X\"" simply
	 * fail to parse, having no terminator anywhere.
	 *
	 * Found by fuzz/fuzz_shparse.c as "\x7f<<\t\"\"" and reduced by
	 * hand; "a<<''" is the same defect.  fuzz_shparse.c's
	 * hdquote_fence() keeps the harness off it -- delete that when
	 * this fence is lifted. */
static void test_heredoc_quoted_delim_roundtrip(void)
{
	check_roundtrip("a<<\"\"");
	check_roundtrip("a<<''");
}
#endif

#if SPICULE_TEST(PASS, sh_engine_bang_word_roundtrip) /* parse -> print -> parse -> print is a fixed point for
	 * a command word that is literally "!".  2.9.2 makes "!" a
	 * reserved word when it is the first word of a pipeline, and 2.4
	 * requires it to be quoted to be used as an ordinary word there;
	 * src/sh/print.c writes such a word out bare, so its own output
	 * reparses as a negation and the word is gone.
	 *
	 *     ">! !"   parses as { redirect > to the word "!" ; word "!" }
	 *              prints as "!  > !"
	 *              reparses as { negation ; redirect > to "!" }
	 *              prints as "! > !"
	 *
	 * This is the property print.c's own banner states and that
	 * check_roundtrip() above verifies by hand for a fixed set of
	 * programs; it is the first input to break it, and it took a
	 * fuzzer to find because no hand-written program uses "!" as a
	 * word.  Found by fuzz/fuzz_shparse.c, whose bang_fence() keeps
	 * the harness off it -- delete that when this fence is lifted. */
static void test_bang_word_roundtrip(void)
{
	check_roundtrip(">! !");
}
#endif

#if SPICULE_TEST(PASS, sh_engine_funcdef_list_operator_roundtrip) /* parse -> print -> parse -> print is a fixed point for a
	 * function definition followed by a list operator.  Every round
	 * trip inserts one more <blank> between the body and the operator,
	 * so like the here-document fence above this does not merely fail,
	 * it diverges:
	 *
	 *     "a()()&"   prints as   "a() () &"
	 *                REprints as "a() ()  &"
	 *                then        "a() ()   &"
	 *
	 * src/sh/parse.c:885-896 parse_funcdef() captures the body as the
	 * text from the body's first token to `end = p->cur.start` -- the
	 * START of the token that FOLLOWS the body.  The lexer has already
	 * skipped the <blank>s in between, so they are inside the captured
	 * extent: given "a() () &" the body is "() " and not "()".
	 * src/sh/print.c:148 writes func_text back verbatim, and
	 * print_list()/print_pipeline()/print_andor() then write the
	 * operator with a leading space of their own (print.c:183 " &",
	 * :163 " | ", :171 " && "/" || "), so one blank becomes two.
	 *
	 * WHY ONLY A LIST OPERATOR, which is what makes this survive the
	 * cases test_roundtrip() above already checks:
	 *
	 *   - a redirection does not expose it.  parse_command() consumes
	 *     the redirection into the BODY's redirection list, so it ends
	 *     up inside func_text and reprints exactly where it was --
	 *     "f() { a; } > out" is a fixed point and is checked live
	 *     above.
	 *   - ';' and <newline> do not expose it either.  print_list()
	 *     ends an item with a bare '\n' and writes no leading blank
	 *     for the next one, so the reprint has no blank to swallow --
	 *     "f() { :; }; g() { :; }; f" is checked live above too.
	 *
	 * That is the whole of the gap: stage 7b's round-trip cases put a
	 * function definition before ';', a <newline>, a redirection and
	 * end-of-input, and never before '&', '|', '&&' or '||'.
	 *
	 * Found by fuzz/fuzz_shparse.c as "\x01&A()()&" and, independently
	 * in the same run, inside a 256-byte pipeline as "___()()|"; both
	 * reduce to the four cases below.  fuzz_shparse.c's funcdef_fence()
	 * keeps the harness off it -- delete that when this fence is
	 * lifted. */
static void test_funcdef_before_list_operator_roundtrip(void)
{
	check_roundtrip("a()()&");
	check_roundtrip("a()()|b");
	check_roundtrip("a()()&&b");
	check_roundtrip("a()()||b");
	check_roundtrip("f() { a; }&");
}
#endif

/* ---- stage 2: execution of simple commands -----------------------------
 *
 * These re-exec this very binary (matching test/misc.c's
 * test_abort_child() pattern) as the command a parsed sh_list runs, so
 * a real __find_program()+__spawn()+waitpid() round trip happens --
 * argv[1] == "--exit-child" makes main() below exit(atoi(argv[2]))
 * immediately instead of running the test suite. `self` is wrapped in
 * single quotes in the source text since a Windows path's backslashes
 * must stay completely literal (single-quote quoting, not double, so
 * wordexp()'s expansion pass can't try to interpret one as an escape).
 */
static int run(const char *src, int *status)
{
	struct sh_list *l = must_parse(src);
	int rc;
	if (!l) return -1;
	rc = __sh_exec_list(l, status);
	__sh_list_free(l);
	return rc;
}

static void test_exec_simple_command_status(const char *self)
{
	char src[512];
	int status;
	snprintf(src, sizeof src, "'%s' --exit-child 7", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 7);

	snprintf(src, sizeof src, "'%s' --exit-child 0", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
}

/* command-not-found matches system()'s documented exit-127 clause
 * (src/stdlib/system.c), which stage 5 must not regress. */
static void test_exec_command_not_found(void)
{
	int status;
	CHECK(run("this-program-genuinely-does-not-exist-xyz", &status) == 0);
	CHECK(status == 127);
}

/* 2.9.2: "!" inverts the pipeline's exit status. */
static void test_exec_bang_negation(const char *self)
{
	char src[512];
	int status;
	snprintf(src, sizeof src, "! '%s' --exit-child 0", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 1);

	snprintf(src, sizeof src, "! '%s' --exit-child 5", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
}

/* 2.9.3: "&&"/"||" short-circuit on the previous command's status. */
static void test_exec_andor_short_circuit(const char *self)
{
	char src[512];
	int status;

	snprintf(src, sizeof src, "'%s' --exit-child 0 && '%s' --exit-child 9", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 9); /* left succeeded, right ran and its status wins */

	snprintf(src, sizeof src, "'%s' --exit-child 3 && '%s' --exit-child 9", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 3); /* left failed, right never ran -- status is still the left's */

	snprintf(src, sizeof src, "'%s' --exit-child 0 || '%s' --exit-child 9", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0); /* left succeeded, right never ran */
}

/* 2.9.1: an assignment-only simple command (no cmd_word) affects the
 * *current* execution environment, not a child's. */
static void test_exec_assignment_only_affects_shell_env(void)
{
	int status;
	unsetenv("SH_TEST_ASSIGN_ONLY");
	CHECK(run("SH_TEST_ASSIGN_ONLY=hello", &status) == 0);
	CHECK(status == 0);
	{
		const char *v = getenv("SH_TEST_ASSIGN_ONLY");
		CHECK(v && strcmp(v, "hello") == 0);
	}
	unsetenv("SH_TEST_ASSIGN_ONLY");
}

/* An assignment prefixed to a command with a cmd_word is scoped to
 * that command's own execution environment (build_child_envp() in
 * exec.c copies environ rather than mutating it) -- the shell's own
 * environment must come out unchanged, which is exactly what
 * test/sh-design.md means by "must never clobber the caller's ...
 * environ". */
static void test_exec_assignment_prefix_does_not_leak(const char *self)
{
	char src[512];
	int status;
	unsetenv("SH_TEST_ASSIGN_SCOPED");
	snprintf(src, sizeof src, "SH_TEST_ASSIGN_SCOPED=childonly '%s' --exit-child 0", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
	CHECK(getenv("SH_TEST_ASSIGN_SCOPED") == 0);
}

/* Proves word realization actually goes through wordexp() (rather than
 * some from-scratch reimplementation): an unquoted $VAR in a command
 * word is expanded before argv reaches __spawn(). */
static void test_exec_reuses_wordexp_param_expansion(const char *self)
{
	char src[512];
	int status;
	setenv("SH_TEST_EXIT_CODE", "42", 1);
	snprintf(src, sizeof src, "'%s' --exit-child $SH_TEST_EXIT_CODE", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 42);
	unsetenv("SH_TEST_EXIT_CODE");
}

/* Constructs no stage yet implements are reported as -1 ("cannot
 * execute this AST node yet"), never silently misexecuted -- see
 * sh.h's __sh_exec_*() comment.
 *
 * Command substitution in a redirection target word and in an unquoted
 * here-document body were stage 4's named, tested "not yet"; stage 5
 * implements them, so those three -1s became results, and they are
 * checked as results by test_exec_cmdsub_in_redirections() below. What
 * is left here is the convention itself, which is still live and still
 * needs a construct that genuinely reaches it: two directly adjacent
 * compound-command stages in one pipeline, which src/sh/execute.c refuses
 * up front rather than deadlock without a fork(). */
static void test_exec_reports_unimplemented_constructs(const char *self)
{
	char src[512];
	int status;

	snprintf(src, sizeof src, "('%s' --produce a) | { '%s' --cat; }", self, self);
	CHECK(run(src, &status) == -1);

	snprintf(src, sizeof src, "{ '%s' --produce a; } | ('%s' --cat)", self, self);
	CHECK(run(src, &status) == -1);
}

/* ---- stage 3: redirections and pipelines --------------------------------
 *
 * These reuse run()/must_parse() from stage 2 above, plus a handful of
 * new self-exec roles (child_role() below) that stand in for the
 * external `cat`/`true`/`echo` a Unix test suite could otherwise
 * assume: this platform has none of those as standalone programs, and
 * test/sh-design.md's whole point is that this shell must not depend
 * on one either.
 */

/* A fresh, empty temp file in the current directory -- the same
 * mkstemp()-in-cwd convention test/stdio.c's make_tmp() and
 * test/stdlib.c use. Returns a malloc'd path (already created) the
 * caller must remove()+free(), or NULL on failure. */
static char *make_tmp(void)
{
	char tmpl[] = "shtstXXXXXX";
	int fd = mkstemp(tmpl);
	if (fd < 0) return 0;
	close(fd);
	return strdup(tmpl);
}

/* Reads a whole (small) file into a malloc'd, NUL-terminated buffer,
 * or returns NULL if it cannot be opened. Used to inspect what a
 * redirected command actually wrote. */
static char *slurp(const char *path)
{
	FILE *f = fopen(path, "rb");
	char *buf;
	long len;
	if (!f) return 0;
	if (fseek(f, 0, SEEK_END)) { fclose(f); return 0; }
	len = ftell(f);
	if (len < 0 || fseek(f, 0, SEEK_SET)) { fclose(f); return 0; }
	buf = malloc((size_t)len + 1);
	if (!buf) { fclose(f); return 0; }
	if (len && fread(buf, 1, (size_t)len, f) != (size_t)len) { fclose(f); free(buf); return 0; }
	buf[len] = 0;
	fclose(f);
	return buf;
}

/* Whether a *spawned child* can actually observe any std-descriptor
 * redirection its parent process performed -- true on real Windows and
 * under Wine (this file's normal targets), but not under
 * tools/asan-build.sh's native ASan build: that harness's
 * RtlCreateUserProcess stub (fuzz/ntstubs.c) is a real host
 * fork()+execve() of a real host binary that never reads
 * pp->StandardInput/Output/Error at all, so a spawned child there
 * always gets the *harness's original* real host fd 0/1/2, no matter
 * what this process's own (correctly rewired) descriptor table says at
 * the moment of the call. This applies uniformly -- an open()'d file
 * (backed by that stub's in-memory-only vnode filesystem, with no real
 * host fd for a separate process to inherit either way), a
 * close()d/dup2()'d descriptor, and even a pipe (whose ends *are* real
 * host fds, but still never reach the child, precisely because nothing
 * ever copies them onto its fd 0/1/2) are all equally invisible to
 * anything this process spawns there. Detected once, at runtime, by
 * actually trying the simplest case (file redirection) rather than
 * assumed from a compile-time macro -- the same "find the environment
 * gap by checking, then skip only what it affects, with a note"
 * discipline test/posix-termios.c's /dev/tty checks already use, so
 * this keeps working unattended if that stub's process model ever
 * changes. Every test that needs a spawned child to observe some
 * redirection its parent made -- file-based, here-document, pipeline,
 * or close/dup -- gates on this; test_exec_redir_dup_closed_fd_fails()
 * is the one exception, since a redirection error keeps the command
 * from ever spawning at all and so does not depend on this. */
static int file_redir_supported(const char *self)
{
	static int cached = -1;
	char src[512], *tmp, *got;
	int status;

	if (cached >= 0) return cached;
	cached = 0;
	tmp = make_tmp();
	if (!tmp) return cached;
	snprintf(src, sizeof src, "'%s' --produce probe > %s", self, tmp);
	if (run(src, &status) == 0 && status == 0) {
		got = slurp(tmp);
		if (got && strcmp(got, "probe\n") == 0) cached = 1;
		free(got);
	}
	remove(tmp);
	free(tmp);
	if (!cached)
		printf("  note: a spawned child cannot see this process's file-based"
		       " redirections in this environment (native ASan stub?) --"
		       " skipping file/here-document redirection checks\n");
	return cached;
}

static void test_exec_redir_output_creates_and_truncates(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512], *tmp = make_tmp(), *got;
	CHECK(tmp != 0);
	if (!tmp) return;

	/* '>' creates (2.7.2) ... */
	snprintf(src, sizeof src, "'%s' --produce first > %s", self, tmp);
	{
		int status;
		CHECK(run(src, &status) == 0);
		CHECK(status == 0);
	}
	got = slurp(tmp);
	CHECK(got && strcmp(got, "first\n") == 0);
	free(got);

	/* ... and each subsequent '>' truncates rather than appending. */
	snprintf(src, sizeof src, "'%s' --produce second > %s", self, tmp);
	{
		int status;
		CHECK(run(src, &status) == 0);
		CHECK(status == 0);
	}
	got = slurp(tmp);
	CHECK(got && strcmp(got, "second\n") == 0);
	free(got);

	remove(tmp);
	free(tmp);
}

/* 2.7.3: '>>' appends instead of truncating. */
static void test_exec_redir_append(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512], *tmp = make_tmp(), *got;
	int status;
	CHECK(tmp != 0);
	if (!tmp) return;

	snprintf(src, sizeof src, "'%s' --produce one >> %s", self, tmp);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
	snprintf(src, sizeof src, "'%s' --produce two >> %s", self, tmp);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);

	got = slurp(tmp);
	CHECK(got && strcmp(got, "one\ntwo\n") == 0);
	free(got);
	remove(tmp);
	free(tmp);
}

/* '>|' is only documented (2.7.2) to differ from '>' when the shell's
 * noclobber option (set -C) is set; this shell has no `set` builtin at
 * all yet (test/sh-design.md's scope), so nothing ever refuses a plain
 * '>' in the first place and '>|' has nothing extra to override --
 * see apply_one_redir()'s SH_R_CLOBBER case in src/sh/execute.c for the
 * same point made where the behavior actually lives. This just checks
 * '>|' still *works* like '>', not that it is indistinguishable in
 * every hypothetical future (a `set -C` builtin would only need to
 * change the SH_R_GREAT case). */
static void test_exec_redir_clobber_like_great(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512], *tmp = make_tmp(), *got;
	int status;
	CHECK(tmp != 0);
	if (!tmp) return;
	snprintf(src, sizeof src, "'%s' --produce hi >| %s", self, tmp);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
	got = slurp(tmp);
	CHECK(got && strcmp(got, "hi\n") == 0);
	free(got);
	remove(tmp);
	free(tmp);
}

/* 2.7.1: '<' feeds a file to the command's stdin. */
static void test_exec_redir_input(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512], *tmp = make_tmp();
	int status;
	FILE *f;
	CHECK(tmp != 0);
	if (!tmp) return;
	f = fopen(tmp, "wb");
	CHECK(f != 0);
	if (f) { fputs("seed\n", f); fclose(f); }

	snprintf(src, sizeof src, "'%s' --stdin-eq seed < %s", self, tmp);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
	remove(tmp);
	free(tmp);
}

/* 2.7.7: '<>' opens for both reading and writing, without truncating
 * (unlike '<' + '>' or '>' alone) -- the seeded content must still be
 * there, and readable, afterward. */
static void test_exec_redir_lessgreat_no_truncate(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512], *tmp = make_tmp(), *got;
	int status;
	FILE *f;
	CHECK(tmp != 0);
	if (!tmp) return;
	f = fopen(tmp, "wb");
	CHECK(f != 0);
	if (f) { fputs("seed\n", f); fclose(f); }

	snprintf(src, sizeof src, "'%s' --stdin-eq seed <> %s", self, tmp);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);

	got = slurp(tmp);
	CHECK(got && strcmp(got, "seed\n") == 0); /* untouched -- no O_TRUNC */
	free(got);
	remove(tmp);
	free(tmp);
}

/* 2.7: "the order of evaluation is from beginning to end" -- so which
 * of two redirections targeting the *same* descriptor number wins is
 * whichever is written last. */
static void test_exec_redir_order_last_wins(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512], *t1 = make_tmp(), *t2 = make_tmp(), *got;
	int status;
	CHECK(t1 != 0 && t2 != 0);
	if (!t1 || !t2) { free(t1); free(t2); return; }

	snprintf(src, sizeof src, "'%s' --produce hi > %s > %s", self, t1, t2);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);

	got = slurp(t1);
	CHECK(got && got[0] == 0); /* opened (and truncated) but never written to */
	free(got);
	got = slurp(t2);
	CHECK(got && strcmp(got, "hi\n") == 0);
	free(got);

	remove(t1); free(t1);
	remove(t2); free(t2);
}

/* 2.7.6, and the classic ordering trap: "cmd >file 2>&1" sends both
 * streams to file (fd 2 is duplicated from fd 1 *after* fd 1 already
 * points at file), while "cmd 2>&1 >file" does not (fd 2 is duplicated
 * from the *old* fd 1 first, and only then does fd 1 move to file) --
 * this is exactly the ordering apply_redirs()/apply_one_redir() in
 * src/sh/execute.c process left to right, never as a batch. */
static void test_exec_redir_dup_output_ordering(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512], *t1 = make_tmp(), *t2 = make_tmp(), *got;
	int status;
	CHECK(t1 != 0 && t2 != 0);
	if (!t1 || !t2) { free(t1); free(t2); return; }

	/* stdout then stderr both land in t1: fd 2 follows fd 1 to it. */
	snprintf(src, sizeof src, "'%s' --produce-both OUT ERR > %s 2>&1", self, t1);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
	got = slurp(t1);
	CHECK(got && strcmp(got, "OUT\nERR\n") == 0);
	free(got);

	/* fd 2 is bound to the *old* stdout first; only stdout then moves
	 * to t2, so t2 must contain OUT but never ERR. */
	snprintf(src, sizeof src, "'%s' --produce-both OUT ERR 2>&1 > %s", self, t2);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
	got = slurp(t2);
	CHECK(got && strcmp(got, "OUT\n") == 0);
	free(got);

	remove(t1); free(t1);
	remove(t2); free(t2);
}

/* 2.7.6: "<&-"/">&-" close the descriptor instead of duplicating it. */
static void test_exec_redir_close(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512];
	int status;

	snprintf(src, sizeof src, "'%s' --fd-open 0", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 1); /* control: fd 0 is normally open */

	snprintf(src, sizeof src, "'%s' --fd-open 0 <&-", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0); /* closed */

	snprintf(src, sizeof src, "'%s' --fd-open 1 >&-", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0); /* closed */
}

/* 2.7.6: duplicating a closed/nonexistent descriptor is a redirection
 * error -- 2.8.1 says that "shall not exit" a non-interactive shell
 * for an ordinary utility, it just fails that one command. */
static void test_exec_redir_dup_closed_fd_fails(const char *self)
{
	char src[512];
	int status;
	snprintf(src, sizeof src, "'%s' --exit-child 0 <&9", self);
	CHECK(run(src, &status) == 0);  /* not "-1 unimplemented" */
	CHECK(status != 0);             /* the command failed to even start */
}

/* 2.8.1's "shall not exit" applies just as much to an outright open()
 * failure (no such directory) as to a bad fd -- and, in a pipeline,
 * only *that* stage is affected; the rest runs normally. */
static void test_exec_redir_open_failure_nonabort(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512];
	int status;

	snprintf(src, sizeof src, "'%s' --exit-child 0 > no-such-directory-xyz/file", self);
	CHECK(run(src, &status) == 0);
	CHECK(status != 0);

	snprintf(src, sizeof src, "'%s' --exit-child 0 > no-such-directory-xyz/file | '%s' --exit-child 7", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 7); /* pipeline status is still the *last* command's */
}

/* 2.7.4: an unquoted heredoc delimiter gets a plain (no here-document
 * syntax involved) round trip through the command's stdin. */
static void test_exec_heredoc_basic(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512];
	int status;
	snprintf(src, sizeof src, "'%s' --stdin-eq hello <<EOF\nhello\nEOF\n", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
}

/* 2.7.4: "<<-" strips leading tabs from every body line and the
 * delimiter line -- already done by the parser (parse.c's
 * drain_heredocs()), so this is really testing that exec.c passes the
 * already-stripped r->heredoc straight through unmolested. */
static void test_exec_heredoc_dash_strips_tabs(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512];
	int status;
	snprintf(src, sizeof src, "'%s' --stdin-eq hi <<-EOF\n\t\thi\n\tEOF\n", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
}

/* 2.7.4: "If no part of word is quoted, all lines ... shall be
 * expanded for parameter expansion" -- reusing wordexp() (see
 * expand_heredoc() in src/sh/execute.c) rather than a second from-scratch
 * expander. */
static void test_exec_heredoc_unquoted_expands(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512];
	int status;
	setenv("SH_TEST_HEREDOC_VAR", "expanded", 1);
	snprintf(src, sizeof src, "'%s' --stdin-eq expanded <<EOF\n$SH_TEST_HEREDOC_VAR\nEOF\n", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
	unsetenv("SH_TEST_HEREDOC_VAR");
}

/* 2.7.4: "If any part of word is quoted ... the here-document lines
 * shall not be expanded" -- a quoted delimiter turns expansion off
 * entirely, even though the body text looks exactly like the unquoted
 * case above. */
static void test_exec_heredoc_quoted_delimiter_no_expansion(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512];
	int status;
	setenv("SH_TEST_HEREDOC_VAR", "expanded", 1);
	/* --stdin-eq's own operand is single-quoted so *it* is not
	 * expanded either -- both sides stay the literal three characters
	 * '$', 'V', ... i.e. the same unexpanded text. */
	snprintf(src, sizeof src, "'%s' --stdin-eq '$SH_TEST_HEREDOC_VAR' <<'EOF'\n$SH_TEST_HEREDOC_VAR\nEOF\n", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
	unsetenv("SH_TEST_HEREDOC_VAR");
}

/* 2.9.2: connects each command's stdout to the next one's stdin. */
static void test_exec_pipeline_two_stage(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512];
	int status;
	snprintf(src, sizeof src, "'%s' --produce hi | '%s' --stdin-eq hi", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
}

/* A pipeline of more than two commands: proves this is a real loop
 * over ncommands, not a hand-special-cased two-stage pipe. */
static void test_exec_pipeline_three_stage(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512];
	int status;
	snprintf(src, sizeof src, "'%s' --produce hi | '%s' --cat | '%s' --stdin-eq hi", self, self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
}

/* 2.9.2: "the exit status shall be the exit status of the last command
 * specified in the pipeline" -- even though an earlier stage "fails". */
static void test_exec_pipeline_status_is_last(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512];
	int status;
	snprintf(src, sizeof src, "'%s' --exit-child 3 | '%s' --exit-child 0", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);

	snprintf(src, sizeof src, "'%s' --exit-child 0 | '%s' --exit-child 9", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 9);
}

/* 2.9.2: "!" negates the exit status of the whole pipeline (i.e. of
 * its last command), for a pipeline of more than one command too --
 * test_pipeline_bang() (stage 1, above) only checks parsing. */
static void test_exec_pipeline_bang(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512];
	int status;
	snprintf(src, sizeof src, "! '%s' --exit-child 0 | '%s' --exit-child 5", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0); /* last command's status (5) was nonzero -> negated to 0 */

	snprintf(src, sizeof src, "! '%s' --exit-child 5 | '%s' --exit-child 0", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 1); /* last command's status (0) was zero -> negated to 1 */
}

/* A command's own redirections apply on top of the pipe hookup (2.7's
 * left-to-right ordering, same rule as test_exec_redir_dup_output_ordering
 * above): redirecting the *first* stage's stdout away from the pipe
 * means the next stage reads nothing from it. */
static void test_exec_pipeline_stage_redir_overrides_pipe(const char *self)
{
	if (!file_redir_supported(self)) return;
	char src[512], *tmp = make_tmp(), *got;
	int status;
	CHECK(tmp != 0);
	if (!tmp) return;

	snprintf(src, sizeof src, "'%s' --produce hi > %s | '%s' --stdin-eq-raw ''", self, tmp, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0); /* second stage got EOF with nothing written -- empty stdin */

	got = slurp(tmp);
	CHECK(got && strcmp(got, "hi\n") == 0); /* first stage's real output went to the file */
	free(got);
	remove(tmp);
	free(tmp);
}

/* ---- stage 4: subshells and brace groups (XCU 2.9.4, 2.12) -------------
 *
 * These build on run()/must_parse()/file_redir_supported()/make_tmp()/
 * slurp() from stages 2/3 above, plus self-exec roles already defined
 * there (--exit-child/--produce/--stdin-eq). The environment and
 * working-directory checks below inspect *this test process's own*
 * getenv()/getcwd() directly, rather than needing a child role, because
 * run() executes the parsed AST in this very process (exec_group() in
 * src/sh/execute.c does not fork for a standalone group -- see its header
 * comment for why); a group used as a pipeline stage does fork, and
 * test_exec_group_pipeline_stage() below checks specifically that even
 * then nothing leaks back into this process.
 */

/* Returns a malloc'd copy of the current working directory (never
 * NULL on success), for a test to restore afterward -- every test
 * below that changes the working directory (proving a subshell's `cd`
 * does not survive it, or a brace group's does) must put it back, or
 * later tests using cwd-relative temp files (make_tmp()) would break. */
static char *save_cwd(void)
{
	char *p = getcwd(0, 0);
	CHECK(p != 0);
	return p;
}

static void restore_cwd(char *saved)
{
	if (saved) { CHECK(chdir(saved) == 0); free(saved); }
}

/* 2.9.4: "{ compound-list ; }" executes "in the current process
 * environment" -- both a variable assignment and a `cd` inside it must
 * still be visible afterward. */
static void test_exec_brace_persists_assignment_and_cd(void)
{
	char *saved = save_cwd();
	char *now;
	int status;

	CHECK(mkdir("shtst_brace_dir", 0755) == 0 || errno == EEXIST);
	unsetenv("SH_TEST_BRACE_VAR");

	CHECK(run("{ SH_TEST_BRACE_VAR=hello; cd shtst_brace_dir; }", &status) == 0);
	CHECK(status == 0);

	{
		const char *v = getenv("SH_TEST_BRACE_VAR");
		CHECK(v && strcmp(v, "hello") == 0);
	}
	now = getcwd(0, 0);
	CHECK(now && saved && strcmp(now, saved) != 0); /* cd actually moved us */
	free(now);

	unsetenv("SH_TEST_BRACE_VAR");
	restore_cwd(saved);
	rmdir("shtst_brace_dir");
}

/* 2.9.4/2.12: "( compound-list )" executes in a subshell environment
 * that is a duplicate of the shell's; "changes made to the subshell
 * environment shall not affect the shell environment" -- the same
 * assignment and `cd` that persisted through a brace group above must
 * both vanish once the subshell finishes. */
static void test_exec_subshell_does_not_persist_assignment_and_cd(void)
{
	char *saved = save_cwd();
	char *now;
	int status;

	CHECK(mkdir("shtst_sub_dir", 0755) == 0 || errno == EEXIST);
	unsetenv("SH_TEST_SUB_VAR");

	CHECK(run("(SH_TEST_SUB_VAR=hello; cd shtst_sub_dir)", &status) == 0);
	CHECK(status == 0);

	CHECK(getenv("SH_TEST_SUB_VAR") == 0);
	now = getcwd(0, 0);
	CHECK(now && saved && strcmp(now, saved) == 0); /* still where we started */
	free(now);

	restore_cwd(saved);
	rmdir("shtst_sub_dir");
}

/* 2.9.4 Exit Status: "The exit status of a grouping command shall be
 * the exit status of compound-list" -- i.e. of the last command run in
 * it, for both forms. */
static void test_exec_group_exit_status(const char *self)
{
	char src[512];
	int status;

	snprintf(src, sizeof src, "{ '%s' --exit-child 3; '%s' --exit-child 9; }", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 9);

	snprintf(src, sizeof src, "( '%s' --exit-child 3; '%s' --exit-child 9 )", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 9);
}

/* A group's exit status feeds "!" negation and "&&"/"||" short-circuit
 * exactly like a pipeline's does (2.9.2/2.9.3 apply uniformly to
 * whatever kind of command produced the status) -- this is what "$?
 * propagates correctly out of each form" means operationally, since
 * this shell has no $? parameter expansion yet (sh.h's banner): the
 * *status* __sh_exec_*() threads through by reference is the only
 * observable stand-in for it, and these are the constructs that
 * consume it. */
static void test_exec_group_bang_and_status_propagation(const char *self)
{
	char src[512];
	int status;

	snprintf(src, sizeof src, "! ( '%s' --exit-child 0 )", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 1);

	snprintf(src, sizeof src, "! { '%s' --exit-child 5; }", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);

	snprintf(src, sizeof src, "( '%s' --exit-child 0 ) && '%s' --exit-child 9", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 9); /* left (the subshell) succeeded, right ran */

	snprintf(src, sizeof src, "( '%s' --exit-child 3 ) && '%s' --exit-child 9", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 3); /* left failed, right never ran -- status is still the left's */

	snprintf(src, sizeof src, "{ '%s' --exit-child 0; } || '%s' --exit-child 9", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0); /* left succeeded, right never ran */
}

/* 2.9.4: "each [may be followed by] redirections ... shall apply to all
 * the commands within the compound command" -- a single "> file" after
 * the group affects every command inside it, not just the last one
 * (which would instead be what redirecting *that one command* looks
 * like). */
static void test_exec_group_redir_whole(const char *self)
{
	char src[512], *tmp, *got;
	int status;

	if (!file_redir_supported(self)) return;
	tmp = make_tmp();
	CHECK(tmp != 0);
	if (!tmp) return;

	snprintf(src, sizeof src, "{ '%s' --produce one; '%s' --produce two; } > %s", self, self, tmp);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
	got = slurp(tmp);
	CHECK(got && strcmp(got, "one\ntwo\n") == 0);
	free(got);

	snprintf(src, sizeof src, "( '%s' --produce three; '%s' --produce four ) > %s", self, self, tmp);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
	got = slurp(tmp);
	CHECK(got && strcmp(got, "three\nfour\n") == 0);
	free(got);

	remove(tmp);
	free(tmp);
}

/* Nesting: a brace group's assignment is visible inside a subshell that
 * contains it (it is still "the current process environment" as far as
 * that subshell's own copy is concerned) but the outer subshell still
 * discards it on the way out; a subshell nested inside a brace group
 * never lets its assignment escape even that innermost boundary. */
static void test_exec_group_nesting(const char *self)
{
	char src[512];
	int status;

	unsetenv("SH_TEST_NEST_VAR");

	snprintf(src, sizeof src, "( { SH_TEST_NEST_VAR=inner; '%s' --exit-child 4; } )", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 4);
	CHECK(getenv("SH_TEST_NEST_VAR") == 0);

	snprintf(src, sizeof src, "{ (SH_TEST_NEST_VAR=inner2); '%s' --exit-child 6; }", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 6);
	CHECK(getenv("SH_TEST_NEST_VAR") == 0);
}

/* A group used as one stage of a multi-command pipeline: its stdout
 * must reach the next stage exactly like a simple command's would
 * (src/sh/execute.c's fork_group_stage()), and -- per 2.12's "each command
 * of a multi-command pipeline is in a subshell environment", which
 * applies regardless of "(...)" vs "{...}" -- an assignment inside a
 * *brace* group used this way must still not leak into the real shell,
 * even though a standalone brace group (tested above) does not isolate
 * at all. */
static void test_exec_group_pipeline_stage(const char *self)
{
	char src[512];
	int status;

	if (!file_redir_supported(self)) return;

	snprintf(src, sizeof src, "( '%s' --produce hi ) | '%s' --stdin-eq hi", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);

	snprintf(src, sizeof src, "{ '%s' --produce hi; } | '%s' --stdin-eq hi", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);

	/* pipeline status is still the *last* stage's, whether that stage
	 * is a group or a simple command (2.9.2). */
	snprintf(src, sizeof src, "'%s' --produce hi | ( '%s' --stdin-eq hi; '%s' --exit-child 7 )", self, self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 7);

	unsetenv("SH_TEST_PIPE_VAR");
	snprintf(src, sizeof src, "{ SH_TEST_PIPE_VAR=leaked; '%s' --exit-child 0; } | '%s' --exit-child 0", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
	CHECK(getenv("SH_TEST_PIPE_VAR") == 0);
	unsetenv("SH_TEST_PIPE_VAR");
}

/* Reads every remaining byte of stdin into a growable buffer.
 * *out_len receives the byte count (never counting a NUL this doesn't
 * add). Returns a malloc'd buffer (possibly zero-length, never NULL on
 * success) or NULL on a real read error. */
/* ---- stage 5: command substitution (XCU 2.6.3) --------------------------
 *
 * https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html
 *   2.6.3 Command Substitution   2.6.5 Field Splitting
 *   2.9.1 Simple Commands (the "no command name" exit-status rule)
 *   2.12 Shell Execution Environment (the subshell environment 2.6.3 cites)
 *
 * Every one of these needs the substituted command's standard output to
 * actually reach the capture __sh_cmdsub() sets up, which is a
 * redirection of *this* process's fd 1 that a spawned child has to
 * observe -- exactly what file_redir_supported() above tests for, so
 * everything that inspects captured text gates on it. The three
 * exit-status tests do not: a status comes back through waitpid()
 * whatever the child's fd 1 was.
 *
 * Both substitution forms are covered case for case, not one covered
 * and the other spot-checked. The backquoted form is not the awkward
 * sibling here: an autoconf-generated `configure` -- the concrete thing
 * a working sh on this platform would be handed -- uses backquotes
 * about fourteen times as often as "$(...)", so its own rules (2.6.3's
 * "first unquoted non-escaped backquote" search, its backslash removal,
 * and nesting *through* that backslash removal rather than through
 * matching parentheses) are the ones most likely to be exercised in
 * anger. Note also that every backtick test below has this binary's own
 * Windows path -- backslashes and all -- inside the backquotes, in
 * single quotes: 2.6.3's backslash rule removes a backslash only before
 * '$', '`' or another backslash, so "Z:\tmp\...\sh.exe" survives it
 * intact, and a rule that over-removed would break these tests loudly.
 */

/* Runs "'self' --produce-join WORDS > tmp" and returns what the child
 * received as argv[2..], comma-joined -- i.e. exactly the fields WORDS
 * expanded to, in order. Returns a malloc'd string the caller frees, or
 * NULL if the command could not be run at all; *status gets the
 * command's exit status. */
static char *fields_of(const char *self, const char *words, int *status)
{
	char src[1024], *tmp = make_tmp(), *got;
	if (!tmp) return 0;
	snprintf(src, sizeof src, "'%s' --produce-join %s > %s", self, words, tmp);
	if (run(src, status) != 0) { remove(tmp); free(tmp); return 0; }
	got = slurp(tmp);
	remove(tmp);
	free(tmp);
	return got;
}

/* 2.6.3: "The shell shall expand the command substitution by executing
 * command in a subshell environment ... and replacing the command
 * substitution (the text of command plus the enclosing "$()" or
 * backquotes) with the standard output of the command, removing
 * sequences of one or more <newline> characters at the end of the
 * substitution." */
static void test_exec_cmdsub_basic(const char *self)
{
	char words[512], *got;
	int status;

	if (!file_redir_supported(self)) return;

	snprintf(words, sizeof words, "$('%s' --produce hi)", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "hi") == 0);	/* not "hi\n" */
	CHECK(status == 0);
	free(got);

	snprintf(words, sizeof words, "`'%s' --produce hi`", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "hi") == 0);
	CHECK(status == 0);
	free(got);

	/* "sequences of one or more" -- three trailing newlines all go. */
	snprintf(words, sizeof words, "$('%s' --produce-trailing hi)", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "hi") == 0);
	free(got);

	snprintf(words, sizeof words, "`'%s' --produce-trailing hi`", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "hi") == 0);
	free(got);

	/* A substitution is part of the word it appears in, not a word of
	 * its own: text either side of it concatenates, and two of them in
	 * one word still make one word. */
	snprintf(words, sizeof words, "x$('%s' --produce hi)y", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "xhiy") == 0);
	free(got);

	snprintf(words, sizeof words, "x`'%s' --produce hi`y", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "xhiy") == 0);
	free(got);

	snprintf(words, sizeof words, "$('%s' --produce a)`'%s' --produce b`", self, self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "ab") == 0);
	free(got);
}

/* 2.6.3: "Embedded <newline> characters before the end of the output
 * shall not be removed; however, they may be treated as field
 * delimiters and eliminated during field splitting" (2.6.5), and "If a
 * command substitution occurs inside double-quotes, field splitting and
 * pathname expansion shall not be performed on the results of the
 * substitution."  So the *same* two-line output is two fields unquoted
 * and one field (newline intact) quoted. */
static void test_exec_cmdsub_field_splitting(const char *self)
{
	char words[512], *got;
	int status;

	if (!file_redir_supported(self)) return;

	snprintf(words, sizeof words, "$('%s' --produce-embedded a b)", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "a,b") == 0);	/* two fields */
	free(got);

	snprintf(words, sizeof words, "\"$('%s' --produce-embedded a b)\"", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "a\nb") == 0);	/* one field, newline kept */
	free(got);

	snprintf(words, sizeof words, "`'%s' --produce-embedded a b`", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "a,b") == 0);
	free(got);

	snprintf(words, sizeof words, "\"`'%s' --produce-embedded a b`\"", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "a\nb") == 0);
	free(got);

	/* Spaces in the output split the same way newlines do, and a
	 * substitution that produces nothing at all produces no field --
	 * "x $(nothing) y" is two words, not three. */
	snprintf(words, sizeof words, "$('%s' --produce 'p q r')", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "p,q,r") == 0);
	free(got);

	snprintf(words, sizeof words, "x $('%s' --produce-join '') y", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "x,y") == 0);
	free(got);
}

/* 2.6.3, same clause: pathname expansion is performed on an unquoted
 * substitution's result and not on a double-quoted one. Needs a real
 * file to match, created here rather than assumed. */
static void test_exec_cmdsub_pathname_expansion(const char *self)
{
	char words[512], *got;
	int status;
	FILE *f;

	if (!file_redir_supported(self)) return;

	f = fopen("shcsA1", "wb");
	CHECK(f != 0);
	if (!f) return;
	fclose(f);

	snprintf(words, sizeof words, "$('%s' --produce-join 'shcsA*')", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "shcsA1") == 0);
	free(got);

	snprintf(words, sizeof words, "\"$('%s' --produce-join 'shcsA*')\"", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "shcsA*") == 0);
	free(got);

	remove("shcsA1");
}

/* 2.6.3: "The results of command substitution shall not be processed
 * for further tilde expansion, parameter expansion, command
 * substitution, or arithmetic expansion." A '$NAME' in the output stays
 * six literal bytes even with NAME set. */
static void test_exec_cmdsub_result_not_reexpanded(const char *self)
{
	char words[512], *got;
	int status;

	if (!file_redir_supported(self)) return;
	setenv("SH_TEST_CMDSUB_VAR", "expanded", 1);

	snprintf(words, sizeof words, "$('%s' --produce-join '$SH_TEST_CMDSUB_VAR')", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "$SH_TEST_CMDSUB_VAR") == 0);
	free(got);

	snprintf(words, sizeof words, "`'%s' --produce-join '$SH_TEST_CMDSUB_VAR'`", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "$SH_TEST_CMDSUB_VAR") == 0);
	free(got);

	unsetenv("SH_TEST_CMDSUB_VAR");
}

/* 2.6.3: "Command substitution can be nested."  For "$(...)" that is
 * just matching parentheses; for the backquoted form, "To specify
 * nesting within the backquoted version, the application shall precede
 * the inner backquotes with <backslash> characters" -- which works only
 * because the same clause's backslash rule turns the escaped inner
 * backquotes back into real ones in the command text.
 *
 * Also 2.6.3's own worked example of the "$((" ambiguity: "a command
 * substitution containing a single subshell could be written as
 * $( (command) )" -- with the space, so it is not read as an arithmetic
 * expansion. */
static void test_exec_cmdsub_nesting(const char *self)
{
	char words[512], *got;
	int status;

	if (!file_redir_supported(self)) return;

	snprintf(words, sizeof words, "$('%s' --produce-join $('%s' --produce inner))", self, self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "inner") == 0);
	free(got);

	snprintf(words, sizeof words, "`'%s' --produce-join \\`'%s' --produce inner\\``", self, self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "inner") == 0);
	free(got);

	/* Three deep, backquoted: the inner-inner pair needs its
	 * backslashes escaped in turn ("\\\\`" in C is \\` in the shell
	 * source), which is exactly the doubling real scripts write. */
	snprintf(words, sizeof words,
	         "`'%s' --produce-join \\`'%s' --produce-join \\\\\\`'%s' --produce deep\\\\\\`\\``",
	         self, self, self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "deep") == 0);
	free(got);

	/* Mixed: a backquoted substitution inside a "$(...)" one, and the
	 * reverse. Both nest without any escaping at all, since neither
	 * form's terminator can be confused for the other's. */
	snprintf(words, sizeof words, "$('%s' --produce-join `'%s' --produce mixed1`)", self, self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "mixed1") == 0);
	free(got);

	snprintf(words, sizeof words, "`'%s' --produce-join $('%s' --produce mixed2)`", self, self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "mixed2") == 0);
	free(got);

	/* $( (command) ) -- 2.6.3's prescribed spelling for a substitution
	 * whose command is a subshell. */
	snprintf(words, sizeof words, "$( ('%s' --produce sub) )", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "sub") == 0);
	free(got);
}

/* 2.6.3: "Within the backquoted style of command substitution,
 * <backslash> shall retain its literal meaning, except when followed
 * by: '$', '`', or <backslash>."  Each of the three exceptions is
 * checked by making the *unescaped* and the *not-unescaped* readings
 * produce visibly different output -- a test that passed either way
 * would be worth nothing. "$(...)" is checked alongside each, where the
 * same bytes mean something else entirely because its command text is
 * taken verbatim. */
static void test_exec_cmdsub_backquote_backslash(const char *self)
{
	char words[512], *got;
	int status;

	if (!file_redir_supported(self)) return;
	setenv("SH_TEST_CMDSUB_VAR", "expanded", 1);

	/* \$ -> $ : the command text gets a live '$', so the *inner*
	 * command's word is a parameter expansion. Without the unescaping
	 * the inner word would be "\$SH_TEST_CMDSUB_VAR", whose backslash
	 * makes the '$' literal. */
	snprintf(words, sizeof words, "`'%s' --produce-join \\$SH_TEST_CMDSUB_VAR`", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "expanded") == 0);
	free(got);

	/* The same bytes inside "$(...)", where nothing is unescaped: the
	 * inner word really is "\$SH_TEST_CMDSUB_VAR" and the '$' stays
	 * literal. */
	snprintf(words, sizeof words, "$('%s' --produce-join \\$SH_TEST_CMDSUB_VAR)", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "$SH_TEST_CMDSUB_VAR") == 0);
	free(got);

	/* \\ -> \ : the command text gets one backslash, which the inner
	 * word's own quote removal then consumes, so "a\\b" here reaches
	 * the child as "ab". Not unescaping would leave two backslashes,
	 * of which quote removal eats one, giving "a\b". */
	snprintf(words, sizeof words, "`'%s' --produce-join a\\\\b`", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "ab") == 0);
	free(got);

	snprintf(words, sizeof words, "$('%s' --produce-join a\\\\b)", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "a\\b") == 0);
	free(got);

	/* A backslash before anything else keeps "its literal meaning" --
	 * it is passed through to the command text as a backslash, still
	 * escaping the character after it there. */
	snprintf(words, sizeof words, "`'%s' --produce-join a\\qb`", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "aqb") == 0);
	free(got);

	unsetenv("SH_TEST_CMDSUB_VAR");
}

/* 2.2.3 Double-Quotes: "The backquote shall retain its special meaning
 * introducing the other form of command substitution", and inside
 * double-quotes <backslash> is special before '$', '`', '"', '\' and
 * <newline> -- so an escaped backquote there is a literal backquote,
 * not the start of a substitution. */
static void test_exec_cmdsub_in_double_quotes(const char *self)
{
	char words[512], *got;
	int status;

	if (!file_redir_supported(self)) return;

	snprintf(words, sizeof words, "\"pre `'%s' --produce mid` post\"", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "pre mid post") == 0);	/* one field */
	free(got);

	snprintf(words, sizeof words, "\"pre $('%s' --produce mid) post\"", self);
	got = fields_of(self, words, &status);
	CHECK(got && strcmp(got, "pre mid post") == 0);
	free(got);

	/* An escaped backquote inside double-quotes is data. */
	got = fields_of(self, "\"a\\`b\"", &status);
	CHECK(got && strcmp(got, "a`b") == 0);
	free(got);

	/* Single quotes make both forms inert (2.2.2: "each character
	 * within the single-quotes retains its literal value"). */
	got = fields_of(self, "'$(echo hi)' '`echo hi`'", &status);
	CHECK(got && strcmp(got, "$(echo hi),`echo hi`") == 0);
	free(got);
}

/* 2.9.1: "If there is a command name, execution shall continue as
 * described in Command Search and Execution. If there is no command
 * name, but the command contained a command substitution, the command
 * shall complete with the exit status of the last command substitution
 * performed. Otherwise, the command shall complete with a zero exit
 * status."
 *
 * No file_redir_supported() gate: a status comes back through
 * waitpid() regardless of where the child's output went. */
static void test_exec_cmdsub_exit_status(const char *self)
{
	char src[512];
	int status;

	/* No command name at all -- the whole command is one substitution
	 * that produces no output, so no field survives expansion. */
	snprintf(src, sizeof src, "$('%s' --exit-child 7)", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 7);

	snprintf(src, sizeof src, "`'%s' --exit-child 6`", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 6);

	/* "the *last* command substitution performed", not the first. */
	snprintf(src, sizeof src, "$('%s' --exit-child 3)$('%s' --exit-child 5)", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 5);

	/* A substitution in an assignment's value is one the command
	 * "contained" (2.9.1 step 4 expands assignment values for command
	 * substitution), and the assignment still takes effect. */
	snprintf(src, sizeof src, "SH_TEST_CMDSUB_ST=$('%s' --exit-child 4)", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 4);
	unsetenv("SH_TEST_CMDSUB_ST");

	/* With a command name, the *command's* status wins outright. */
	snprintf(src, sizeof src, "'%s' --exit-child 2 $('%s' --exit-child 9)", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 2);

	/* A substitution whose command cannot be found is not an error:
	 * it produces no output and exits 127, exactly like any other
	 * command not found (matching test_exec_command_not_found()). */
	CHECK(run("$(this-program-genuinely-does-not-exist-xyz)", &status) == 0);
	CHECK(status == 127);
}

/* 2.6.3: "executing command in a subshell environment (see Shell
 * Execution Environment)", i.e. 2.12's -- the same one "( list )" gets,
 * which src/sh/execute.c implements by reusing exec_group()'s own
 * save-and-restore rather than a second mechanism. So a substituted
 * command's assignment and its `cd` must both be gone afterwards, the
 * way test_exec_subshell_does_not_persist_assignment_and_cd() already
 * checks for the parenthesised form. */
static void test_exec_cmdsub_subshell_environment(const char *self)
{
	char src[512], *cwd_before, *cwd_after;
	int status;

	unsetenv("SH_TEST_CMDSUB_LEAK");
	CHECK(run("$(SH_TEST_CMDSUB_LEAK=leaked)", &status) == 0);
	CHECK(getenv("SH_TEST_CMDSUB_LEAK") == 0);

	CHECK(run("`SH_TEST_CMDSUB_LEAK=leaked`", &status) == 0);
	CHECK(getenv("SH_TEST_CMDSUB_LEAK") == 0);

	cwd_before = getcwd(0, 0);
	CHECK(cwd_before != 0);
	CHECK(run("$(cd ..)", &status) == 0);
	cwd_after = getcwd(0, 0);
	CHECK(cwd_before && cwd_after && strcmp(cwd_before, cwd_after) == 0);
	free(cwd_before);
	free(cwd_after);
	(void)self;
}

/* 2.7: "the word that follows the redirection operator shall be
 * subjected to tilde expansion, parameter expansion, command
 * substitution, arithmetic expansion, and quote removal" -- and 2.7.4,
 * for an unquoted here-document delimiter, "all lines of the
 * here-document shall be expanded for parameter expansion, command
 * substitution, and arithmetic expansion". Both of these were the
 * -1 "not implemented at this stage" cases stage 4's
 * test_exec_reports_unimplemented_constructs() asserted. */
static void test_exec_cmdsub_in_redirections(const char *self)
{
	char src[1024], *tmp, *got;
	int status;

	if (!file_redir_supported(self)) return;

	tmp = make_tmp();
	CHECK(tmp != 0);
	if (!tmp) return;

	/* The redirection target itself comes from a substitution. */
	snprintf(src, sizeof src, "'%s' --produce hi > $('%s' --produce-join %s)", self, self, tmp);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
	got = slurp(tmp);
	CHECK(got && strcmp(got, "hi\n") == 0);
	free(got);

	snprintf(src, sizeof src, "'%s' --produce ho > `'%s' --produce-join %s`", self, self, tmp);
	CHECK(run(src, &status) == 0);
	got = slurp(tmp);
	CHECK(got && strcmp(got, "ho\n") == 0);
	free(got);

	/* ... including when the redirection belongs to a compound command
	 * rather than a simple one. */
	snprintf(src, sizeof src, "('%s' --produce grp) > $('%s' --produce-join %s)", self, self, tmp);
	CHECK(run(src, &status) == 0);
	got = slurp(tmp);
	CHECK(got && strcmp(got, "grp\n") == 0);
	free(got);

	snprintf(src, sizeof src, "{ '%s' --produce brc > $('%s' --produce-join %s); }", self, self, tmp);
	CHECK(run(src, &status) == 0);
	got = slurp(tmp);
	CHECK(got && strcmp(got, "brc\n") == 0);
	free(got);

	remove(tmp);
	free(tmp);

	/* An unquoted here-document body expands substitutions (2.7.4) ... */
	snprintf(src, sizeof src, "'%s' --stdin-eq hi <<EOF\n$('%s' --produce hi)\nEOF\n", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);

	snprintf(src, sizeof src, "'%s' --stdin-eq hi <<EOF\n`'%s' --produce hi`\nEOF\n", self, self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);

	/* ... and a quoted delimiter suppresses them entirely, the body
	 * arriving as the literal source bytes. */
	snprintf(src, sizeof src, "'%s' --stdin-eq '$(x)' <<'EOF'\n$(x)\nEOF\n", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
}

/* The -1 "cannot execute this AST node at all" convention (sh.h)
 * survives stage 5: it now means the *substituted* list used a
 * construct this executor still refuses, not that substitution itself
 * is unimplemented. src/sh/execute.c refuses two directly adjacent
 * compound-command pipeline stages (it would deadlock without a
 * fork()), which makes a usable, stable example of one. */
static void test_exec_cmdsub_propagates_unimplemented(const char *self)
{
	char src[512];
	int status;

	snprintf(src, sizeof src, "'%s' --produce-join $( ('%s' --produce a) | { '%s' --cat; } )",
	         self, self, self);
	CHECK(run(src, &status) == -1);

	/* A syntax error inside the substitution is reported the same way
	 * (wordexp() turns it into WRDE_SYNTAX; exec.c cannot tell the two
	 * apart and does not need to). */
	CHECK(run("$( | )", &status) == -1);
	CHECK(run("` | `", &status) == -1);
}

static char *read_all_stdin(size_t *out_len)
{
	size_t cap = 256, len = 0;
	char *buf = malloc(cap);
	if (!buf) return 0;
	for (;;) {
		size_t n;
		if (len == cap) {
			char *nb = realloc(buf, cap *= 2);
			if (!nb) { free(buf); return 0; }
			buf = nb;
		}
		n = fread(buf + len, 1, cap - len, stdin);
		len += n;
		if (n == 0) break;
	}
	*out_len = len;
	return buf;
}


/* ---- stage 6a: the built-in dispatcher and its utilities --------------
 *
 * Spec pages: XCU 2.9.1 "Command Search and Execution", XCU 2.14
 * "Special Built-In Utilities", XCU test(1p) (OPERANDS + EXTENDED
 * DESCRIPTION + EXIT STATUS), XCU true(1p)/false(1p), XCU cd(1p).
 */

/* 2.9.1 step 1: the command name a built-in is matched against is the
 * one that exists *after* the word expansions, not the raw source text
 * -- which is precisely what src/sh/execute.c's old raw strcmp("cd") could
 * not express.  Both a quoted 'cd' and a $VAR expanding to "cd" have to
 * reach the built-in. */
static void test_builtin_dispatch_uses_expanded_name(void)
{
	char *saved = save_cwd();
	char *now;
	int status;

	CHECK(mkdir("shtst_disp_dir", 0755) == 0 || errno == EEXIST);

	CHECK(run("'cd' shtst_disp_dir", &status) == 0);
	CHECK(status == 0);
	now = getcwd(0, 0);
	CHECK(now && saved && strcmp(now, saved) != 0);
	free(now);
	CHECK(chdir(saved) == 0);

	CHECK(run("SHT_CDNAME=cd; $SHT_CDNAME shtst_disp_dir", &status) == 0);
	CHECK(status == 0);
	now = getcwd(0, 0);
	CHECK(now && saved && strcmp(now, saved) != 0);
	free(now);

	unsetenv("SHT_CDNAME");
	restore_cwd(saved);
	rmdir("shtst_disp_dir");
}

/* 2.14 ":" -- "This utility shall only expand command arguments... EXIT
 * STATUS: Zero."  true(1p): "shall return with exit code zero";
 * false(1p): "shall return with a non-zero exit code". */
static void test_builtin_colon_true_false(void)
{
	int status;

	CHECK(run(":", &status) == 0);
	CHECK(status == 0);
	CHECK(run(": ignored arguments here", &status) == 0);
	CHECK(status == 0);

	CHECK(run("true", &status) == 0);
	CHECK(status == 0);
	CHECK(run("false", &status) == 0);
	CHECK(status != 0);

	/* Regular utilities on a POSIX system, but there is no true.exe on
	 * this platform, so before stage 6a every one of these was a
	 * "command not found" 127 -- the value that must never come back. */
	CHECK(run("true", &status) == 0 && status != 127);
	CHECK(run("test x = x", &status) == 0 && status != 127);
}

/* 2.14 "exit [n]": "shall cause the shell to exit with the exit status
 * specified by the unsigned decimal integer n... If n is not specified,
 * the exit status shall be that of the last command executed."  The
 * "cause the shell to exit" half is observable here as the rest of the
 * list not running. */
static void test_builtin_exit(const char *self)
{
	char src[512];
	int status;

	CHECK(run("exit 7", &status) == 0);
	CHECK(status == 7);

	/* Everything after it must not run: the marker file would exist if
	 * the second list item had executed. */
	unlink("shtst_exit_marker.txt");
	snprintf(src, sizeof src, "exit 4; '%s' --produce x > shtst_exit_marker.txt", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 4);
	CHECK(access("shtst_exit_marker.txt", F_OK) != 0);

	/* ... including across "&&"/"||", where the status would otherwise
	 * have selected the next pipeline. */
	snprintf(src, sizeof src, "exit 0 && '%s' --produce x > shtst_exit_marker.txt", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);
	CHECK(access("shtst_exit_marker.txt", F_OK) != 0);

	/* "If n is not specified, the exit status shall be that of the
	 * last command executed" (2.14, and 2.8.2 for what that means). */
	snprintf(src, sizeof src, "'%s' --exit-child 6; exit", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 6);
	snprintf(src, sizeof src, "'%s' --exit-child 0; exit", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);

	/* 2.9.4/2.12: "( ... )" runs in a subshell environment, so an
	 * `exit` inside it exits that subshell only -- the list continues,
	 * and its status is the *later* command's. */
	snprintf(src, sizeof src, "( exit 3 ); '%s' --exit-child 5", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 5);

	/* And a command substitution is a subshell environment too
	 * (2.6.3), so "$(exit 3)" must not take the shell down with it. */
	snprintf(src, sizeof src, "SHT_X=$(exit 3); '%s' --exit-child 5", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 5);
	unsetenv("SHT_X");

	/* A brace group is *not* a subshell (2.9.4: "in the current
	 * process environment"), so this one really does end the program. */
	unlink("shtst_exit_marker.txt");
	snprintf(src, sizeof src, "{ exit 2; }; '%s' --produce x > shtst_exit_marker.txt", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 2);
	CHECK(access("shtst_exit_marker.txt", F_OK) != 0);

	/* The unwind must not latch: a second program in the same process
	 * has to run normally afterwards.  This has to be a *multi-item*
	 * list to mean anything.  __sh_exec_list() tests the pending flag
	 * between items, after running the first one, so a one-command
	 * program comes out right even with the flag stuck on -- it would
	 * report the same status either way, and the assertion would be
	 * vacuous.  With two items, a latched flag stops the list after
	 * `true` and leaves the status 0 instead of `false`'s 1. */
	CHECK(run("true", &status) == 0);
	CHECK(status == 0);
	CHECK(run("true; false", &status) == 0);
	CHECK(status == 1);
	CHECK(run("false; true", &status) == 0);
	CHECK(status == 0);
}

/* test(1p) EXTENDED DESCRIPTION: "The algorithm for determining the
 * precedence of the operators and the return value that shall be
 * generated is based on the number of arguments presented to test."
 * These are the 0-, 1-, 2-, 3- and 4-argument rules taken one at a
 * time; each is a case a "tokenise and evaluate" implementation gets
 * wrong. */
static void test_builtin_test_argc_rules(void)
{
	int status;

	/* "0 arguments: Exit false (1)." */
	CHECK(run("test", &status) == 0);
	CHECK(status == 1);

	/* "1 argument: Exit true (0) if $1 is not null; otherwise, exit
	 * false." -- note "-f" alone is a *string*, hence true. */
	CHECK(run("test x", &status) == 0);
	CHECK(status == 0);
	CHECK(run("test ''", &status) == 0);
	CHECK(status == 1);
	CHECK(run("test -f", &status) == 0);
	CHECK(status == 0);

	/* "2 arguments: If $1 is '!', exit true if $2 is null, false if $2
	 * is not null." -- a string test of $2, not a negated evaluation
	 * of it, so "! -f" is false because "-f" is a non-null string. */
	CHECK(run("test ! ''", &status) == 0);
	CHECK(status == 0);
	CHECK(run("test ! x", &status) == 0);
	CHECK(status == 1);
	CHECK(run("test ! -f", &status) == 0);
	CHECK(status == 1);
	/* "If $1 is a unary primary, exit true if the unary test is
	 * true" */
	CHECK(run("test -d .", &status) == 0);
	CHECK(status == 0);

	/* "3 arguments: If $2 is a binary primary, perform the binary test
	 * of $1 and $3." -- checked *before* the '('/')' rule, which is
	 * what makes this a string comparison rather than a group. */
	CHECK(run("test '(' = ')'", &status) == 0);
	CHECK(status == 1);
	CHECK(run("test '(' = '('", &status) == 0);
	CHECK(status == 0);
	/* "If $1 is '!', negate the two-argument test of $2 and $3." */
	CHECK(run("test ! -d .", &status) == 0);
	CHECK(status == 1);
	CHECK(run("test ! -d shtst_no_such_dir", &status) == 0);
	CHECK(status == 0);
	/* XSI: "If $1 is '(' and $3 is ')', perform the unary test of
	 * $2" -- i.e. the one-argument non-null-string test. */
	CHECK(run("test '(' x ')'", &status) == 0);
	CHECK(status == 0);
	CHECK(run("test '(' '' ')'", &status) == 0);
	CHECK(status == 1);

	/* "4 arguments: If $1 is '!', negate the three-argument test of
	 * $2, $3, and $4." */
	CHECK(run("test ! a = a", &status) == 0);
	CHECK(status == 1);
	CHECK(run("test ! a = b", &status) == 0);
	CHECK(status == 0);
	/* XSI: "If $1 is '(' and $4 is ')', perform the two-argument test
	 * of $2 and $3." */
	CHECK(run("test '(' -d . ')'", &status) == 0);
	CHECK(status == 0);
}

/* test(1p) OPERANDS, the file-system primaries. */
static void test_builtin_test_file_primaries(void)
{
	int status;
	FILE *f;

	unlink("shtst_t_file.txt");
	unlink("shtst_t_empty.txt");
	rmdir("shtst_t_dir");
	CHECK(mkdir("shtst_t_dir", 0755) == 0 || errno == EEXIST);
	f = fopen("shtst_t_file.txt", "wb");
	CHECK(f != 0);
	if (f) { fputs("data", f); fclose(f); }
	f = fopen("shtst_t_empty.txt", "wb");
	CHECK(f != 0);
	if (f) fclose(f);

	/* "-e pathname: True if pathname resolves to an existing directory
	 * entry.  False if pathname cannot be resolved." */
	CHECK(run("test -e shtst_t_file.txt", &status) == 0 && status == 0);
	CHECK(run("test -e shtst_t_dir", &status) == 0 && status == 0);
	CHECK(run("test -e shtst_t_nothing", &status) == 0 && status == 1);

	/* "-f ... for a regular file" / "-d ... for a directory" -- the
	 * two must disagree about the same two operands, which a
	 * -e-for-everything implementation would fail. */
	CHECK(run("test -f shtst_t_file.txt", &status) == 0 && status == 0);
	CHECK(run("test -f shtst_t_dir", &status) == 0 && status == 1);
	CHECK(run("test -d shtst_t_dir", &status) == 0 && status == 0);
	CHECK(run("test -d shtst_t_file.txt", &status) == 0 && status == 1);
	CHECK(run("test -f shtst_t_nothing", &status) == 0 && status == 1);
	CHECK(run("test -d shtst_t_nothing", &status) == 0 && status == 1);

	/* "-s ... a file that has a size greater than zero" */
	CHECK(run("test -s shtst_t_file.txt", &status) == 0 && status == 0);
	CHECK(run("test -s shtst_t_empty.txt", &status) == 0 && status == 1);
	CHECK(run("test -s shtst_t_nothing", &status) == 0 && status == 1);

	/* "-r ... permission to read from the file will be granted" /
	 * "-w ... permission to write" -- and both false for a pathname
	 * that "cannot be resolved". */
	CHECK(run("test -r shtst_t_file.txt", &status) == 0 && status == 0);
	CHECK(run("test -w shtst_t_file.txt", &status) == 0 && status == 0);
	CHECK(run("test -r shtst_t_nothing", &status) == 0 && status == 1);
	CHECK(run("test -w shtst_t_nothing", &status) == 0 && status == 1);

	/* "-x ... permission to execute the file (or search it, if it is a
	 * directory) will be granted" -- a directory this process just
	 * created and can chdir() into is searchable. */
	CHECK(run("test -x shtst_t_dir", &status) == 0 && status == 0);
	CHECK(run("test -x shtst_t_nothing", &status) == 0 && status == 1);

	/* "-z string: True if the length of string string is zero" /
	 * "-n string: True if the length of string is non-zero". */
	CHECK(run("test -z ''", &status) == 0 && status == 0);
	CHECK(run("test -z x", &status) == 0 && status == 1);
	CHECK(run("test -n ''", &status) == 0 && status == 1);
	CHECK(run("test -n x", &status) == 0 && status == 0);

	unlink("shtst_t_file.txt");
	unlink("shtst_t_empty.txt");
	rmdir("shtst_t_dir");
}

/* test(1p) OPERANDS: the string and arithmetic binary primaries, and
 * EXIT STATUS: ">1  An error occurred" for an operand of an arithmetic
 * primary that is not an integer.  A malformed expression must not
 * quietly become "false" -- 1 and 2 are different answers. */
static void test_builtin_test_binary_primaries(void)
{
	int status;

	CHECK(run("test abc = abc", &status) == 0 && status == 0);
	CHECK(run("test abc = abd", &status) == 0 && status == 1);
	CHECK(run("test abc != abd", &status) == 0 && status == 0);
	CHECK(run("test abc != abc", &status) == 0 && status == 1);

	CHECK(run("test 1 -eq 1", &status) == 0 && status == 0);
	CHECK(run("test 1 -eq 2", &status) == 0 && status == 1);
	CHECK(run("test 1 -ne 2", &status) == 0 && status == 0);
	CHECK(run("test 1 -lt 2", &status) == 0 && status == 0);
	CHECK(run("test 2 -lt 1", &status) == 0 && status == 1);
	CHECK(run("test 2 -le 2", &status) == 0 && status == 0);
	CHECK(run("test 2 -le 1", &status) == 0 && status == 1);
	CHECK(run("test 3 -gt 2", &status) == 0 && status == 0);
	CHECK(run("test 2 -gt 3", &status) == 0 && status == 1);
	CHECK(run("test 3 -ge 3", &status) == 0 && status == 0);
	CHECK(run("test 2 -ge 3", &status) == 0 && status == 1);
	/* The equal case of each strict comparison, which is the only
	 * input that separates "-lt" from "-le" and "-gt" from "-ge":
	 * without these, an off-by-one in either direction still gets
	 * every unequal pair above right.  ("-eq"/"-ne" are exact by
	 * construction and "-le"/"-ge" are pinned by the equal cases
	 * they already have.) */
	CHECK(run("test 2 -lt 2", &status) == 0 && status == 1);
	CHECK(run("test 2 -gt 2", &status) == 0 && status == 1);
	/* "algebraically" -- a negative integer is a valid operand, and a
	 * string comparison of "-1" and "1" would get this backwards. */
	CHECK(run("test -1 -lt 1", &status) == 0 && status == 0);

	/* An arithmetic primary whose operand is not an integer is an
	 * error (>1), not false.  The diagnostic goes to stderr, which is
	 * redirected here so a passing run stays quiet -- and doing that
	 * through the shell's own "2>" is one more thing being tested. */
	CHECK(run("test 1 -eq x 2>shtst_t_err.txt", &status) == 0);
	CHECK(status > 1);
	CHECK(run("test x -eq 1 2>shtst_t_err.txt", &status) == 0);
	CHECK(status > 1);
	/* A missing operator is equally an error, not false. */
	CHECK(run("test -d 2>shtst_t_err.txt", &status) == 0 && status == 0); /* 1 arg: non-null string */
	CHECK(run("test a b 2>shtst_t_err.txt", &status) == 0 && status > 1);
	unlink("shtst_t_err.txt");
}

/* test(1p) OPERANDS: "!", "-a", "-o" and "( expression )", plus the XSI
 * paragraph under ">4 arguments" that fixes their precedence -- "-a ...
 * has a higher precedence than -o", both left associative, and "the
 * string comparison binary primaries '=' and '!=' shall have a higher
 * precedence than any unary primary". */
static void test_builtin_test_grammar(void)
{
	int status;

	CHECK(run("test -n a -a -n b", &status) == 0 && status == 0);
	CHECK(run("test -n a -a -z b", &status) == 0 && status == 1);
	CHECK(run("test -z a -o -n b", &status) == 0 && status == 0);
	CHECK(run("test -z a -o -z b", &status) == 0 && status == 1);

	/* "-a ... has a higher precedence than -o": "false -a false -o
	 * true" is "(false -a false) -o true" = true.  Read the other way
	 * round it would be "false -a (false -o true)" = false. */
	CHECK(run("test -z a -a -z b -o -n c", &status) == 0 && status == 0);
	/* and "true -o true -a false" is "true -o (true -a false)" = true;
	 * left-to-right without precedence would give false. */
	CHECK(run("test -n a -o -n b -a -z c", &status) == 0 && status == 0);

	/* "( expression ): ... The parentheses can be used to alter the
	 * normal precedence and associativity." */
	CHECK(run("test '(' -z a -o -n b ')' -a -n c", &status) == 0 && status == 0);
	CHECK(run("test '(' -n a -o -n b ')' -a -z c", &status) == 0 && status == 1);

	/* "! expression: True if expression is false." */
	CHECK(run("test ! -n a -a -n b", &status) == 0 && status == 1);
	CHECK(run("test ! -z a -a -n b", &status) == 0 && status == 0);

	/* The XSI '='-binds-tighter-than-a-unary-primary rule: with the
	 * checks the other way round, "-n" would be taken as a unary
	 * primary applied to "=" and the "-n" on the right would never be
	 * seen as its operand. */
	CHECK(run("test -n = -n -o -z x", &status) == 0 && status == 0);
	CHECK(run("test -n = -z -o -z x", &status) == 0 && status == 1);

	/* An unbalanced group is an error (>1), not false. */
	CHECK(run("test '(' -n a -a -n b 2>shtst_t_err.txt", &status) == 0 && status > 1);
	unlink("shtst_t_err.txt");
}

/* test(1p) DESCRIPTION: "In the second form of the utility, where the
 * utility name used is [ rather than test, the application shall ensure
 * that the closing square bracket is a separate argument", and
 * EXTENDED DESCRIPTION: "when using the '[...]' form, the
 * <right-square-bracket> final argument shall not be counted in this
 * algorithm". */
static void test_builtin_bracket(void)
{
	int status;

	CHECK(run("[ -d . ]", &status) == 0 && status == 0);
	CHECK(run("[ -d shtst_no_such_dir ]", &status) == 0 && status == 1);
	CHECK(run("[ ]", &status) == 0 && status == 1);         /* 0 arguments after ']' is dropped */
	CHECK(run("[ x ]", &status) == 0 && status == 0);
	CHECK(run("[ '(' = ')' ]", &status) == 0 && status == 1); /* still the 3-argument rule */

	/* Missing ']' is an error, not a silent evaluation of the rest. */
	CHECK(run("[ -d . 2>shtst_t_err.txt", &status) == 0 && status > 1);
	unlink("shtst_t_err.txt");
}

/* 2.9.1: a built-in must be reachable from every place a command is,
 * not just as a whole program -- as a pipeline stage, inside a group,
 * and as an and-or term.  2.12 additionally puts each stage of a
 * multi-command pipeline in a subshell environment, so a `cd` there
 * must not move the *shell*. */
static void test_builtin_in_compound_contexts(const char *self)
{
	char src[512];
	char *saved = save_cwd();
	char *now;
	int status;

	CHECK(run("{ true; }", &status) == 0 && status == 0);
	CHECK(run("( false )", &status) == 0 && status == 1);
	CHECK(run("true && test 1 -eq 1", &status) == 0 && status == 0);
	CHECK(run("false || test 1 -eq 1", &status) == 0 && status == 0);
	CHECK(run("! true", &status) == 0 && status == 1);

	snprintf(src, sizeof src, "'%s' --produce hi | test -n x", self);
	CHECK(run(src, &status) == 0);
	CHECK(status == 0);

	CHECK(mkdir("shtst_pipe_dir", 0755) == 0 || errno == EEXIST);
	snprintf(src, sizeof src, "cd shtst_pipe_dir | '%s' --exit-child 0", self);
	CHECK(run(src, &status) == 0);
	now = getcwd(0, 0);
	CHECK(now && saved && strcmp(now, saved) == 0); /* the shell did not move */
	free(now);
	restore_cwd(saved);
	rmdir("shtst_pipe_dir");
}

/* Every self-exec role stage 2/3's tests use, dispatched on argv[1].
 * Returns the process's exit code for a recognised role, or -1 if
 * argv[1] is not one of them (so main() falls through to running the
 * actual test suite). */
static int child_role(int argc, char **argv)
{
	const char *role = argv[1];

	if (!strcmp(role, "--exit-child") && argc > 2)
		return atoi(argv[2]);

	/* Writes TEXT (argv[2]) plus a newline to stdout. Stands in for
	 * `echo` (not present as a standalone program on this platform --
	 * see this file's header comment). */
	if (!strcmp(role, "--produce") && argc > 2) {
		printf("%s\n", argv[2]);
		return 0;
	}

	/* Writes OUT (argv[2]) + "\n" to stdout and ERR (argv[3]) + "\n"
	 * to stderr, in that order -- for tests that need to distinguish
	 * which descriptor a byte went through (2>&1 ordering). */
	if (!strcmp(role, "--produce-both") && argc > 3) {
		fprintf(stdout, "%s\n", argv[2]);
		fflush(stdout);
		fprintf(stderr, "%s\n", argv[3]);
		fflush(stderr);
		return 0;
	}

	/* Writes its remaining arguments (argv[2..]) to stdout joined by
	 * <comma>, with NO trailing newline. Stage 5's workhorse: what a
	 * command substitution expanded to is a question about *fields*
	 * (how many, and which bytes in each), and an argv joined by a
	 * byte that neither IFS nor any expansion can produce answers it
	 * exactly, where "--produce hi" could only ever show one word's
	 * worth. The missing trailing newline is what makes the captured
	 * text an exact byte-for-byte assertion rather than one that
	 * silently tolerates 2.6.3's newline stripping being wrong. */
	if (!strcmp(role, "--produce-join") && argc > 2) {
		int i;
		for (i = 2; i < argc; i++) {
			if (i > 2) fputc(',', stdout);
			fputs(argv[i], stdout);
		}
		return 0;
	}

	/* Writes "N:" and then each remaining argument (argv[2..]) in
	 * square brackets.  --produce-join above cannot answer stage 7's
	 * central question: "$@" with no positional parameters must expand
	 * to ZERO fields, and an argv of zero words and an argv of one
	 * empty word both join to an empty capture.  Printing the count
	 * first tells them apart, and the brackets keep an empty field
	 * visible in the middle of a list.  Note the deliberately loose
	 * guard -- argc may be exactly 2 here, which is the whole point,
	 * where every other role needs an operand. */
	if (!strcmp(role, "--produce-fields")) {
		int i;
		printf("%d:", argc - 2);
		for (i = 2; i < argc; i++) printf("[%s]", argv[i]);
		return 0;
	}

	/* Writes TEXT (argv[2]) followed by three newlines -- 2.6.3 strips
	 * "sequences of one or more <newline> characters at the end of the
	 * substitution", and one newline cannot tell a correct
	 * implementation from one that strips exactly one. */
	if (!strcmp(role, "--produce-trailing") && argc > 2) {
		printf("%s\n\n\n", argv[2]);
		return 0;
	}

	/* Writes A (argv[2]), a newline, B (argv[3]), a newline: an
	 * *embedded* newline, which 2.6.3 says is not removed but may act
	 * as a field delimiter, plus a trailing one, which is removed. */
	if (!strcmp(role, "--produce-embedded") && argc > 3) {
		printf("%s\n%s\n", argv[2], argv[3]);
		return 0;
	}

	/* Byte-for-byte stdin -> stdout, unbuffered assumptions aside.
	 * Stands in for `cat`. */
	if (!strcmp(role, "--cat")) {
		char buf[4096];
		size_t n;
		while ((n = fread(buf, 1, sizeof buf, stdin)) > 0)
			fwrite(buf, 1, n, stdout);
		return 0;
	}

	/* Exits 0 iff stdin is exactly TEXT (argv[2]) followed by a single
	 * newline -- the shape every --produce output and every
	 * single-line here-document body (parse.c always appends '\n' per
	 * line) takes. */
	if (!strcmp(role, "--stdin-eq") && argc > 2) {
		size_t len, wantlen = strlen(argv[2]);
		char *got = read_all_stdin(&len);
		int ok;
		if (!got) return 5;
		ok = len == wantlen + 1 && memcmp(got, argv[2], wantlen) == 0 && got[wantlen] == '\n';
		if (!ok) fprintf(stderr, "child: stdin %.*s (%lu bytes), wanted %s\\n\n",
		                  (int)len, got, (unsigned long)len, argv[2]);
		free(got);
		return ok ? 0 : 4;
	}

	/* Like --stdin-eq but an exact byte-for-byte match, no implied
	 * trailing newline -- for asserting stdin is truly empty (0
	 * bytes), which "TEXT + '\\n'" can never express. */
	if (!strcmp(role, "--stdin-eq-raw") && argc > 2) {
		size_t len, wantlen = strlen(argv[2]);
		char *got = read_all_stdin(&len);
		int ok;
		if (!got) return 5;
		ok = len == wantlen && memcmp(got, argv[2], wantlen) == 0;
		free(got);
		return ok ? 0 : 4;
	}

	/* Exits 1 if fd N (argv[2]) is a currently-open descriptor, 0 if
	 * it is closed (EBADF) -- for "<&-"/">&-" tests, where the two
	 * exit codes read backwards from what a shell test usually wants
	 * is deliberate: 0 is easier to CHECK() against a specific
	 * "closed" expectation without a double negative in the caller. */
	if (!strcmp(role, "--fd-open") && argc > 2) {
		int fd = atoi(argv[2]);
		return fcntl(fd, F_GETFD) < 0 ? 0 : 1;
	}

	/* Reads NAME (argv[2]) from this process's own real environ and
	 * writes its value to stdout -- test/sh-main.c's own --print-env
	 * role, needed here too for the same reason it exists there: what a
	 * spawned child's envp actually contained (as opposed to what this
	 * same process's environ holds, which a bare getenv() here already
	 * answers for every other case in this file) is only observable by
	 * asking a real separate process. readonly(1p)'s "NAME=value cmd"
	 * prefix-assignment case is the one enforcement point where the two
	 * can disagree (build_child_envp() builds a private envp rather than
	 * calling setenv() on this process's own environ), so it is the one
	 * case in this file that needs it. */
	if (!strcmp(role, "--print-env") && argc > 2) {
		const char *v = getenv(argv[2]);
		if (v) fputs(v, stdout);
		return v ? 0 : 1;
	}

	return -1;
}



/* ---- stage 7: positional parameters (XCU 2.5.1, 2.5.2) ---------------
 *
 * Spec pages (https://pubs.opengroup.org/onlinepubs/9699919799/):
 *   utilities/V3_chap02.html 2.5.1 Positional Parameters
 *   utilities/V3_chap02.html 2.5.2 Special Parameters ('@', '*', '#', '0')
 *   utilities/V3_chap02.html 2.6 Word Expansions (the empty-field rule)
 *   utilities/set.html   utilities/shift.html
 *
 * Two interfaces are exercised deliberately, because they answer
 * different questions.  __sh_params_replace() installs a list directly,
 * which is how a *test* can set up a case with an embedded blank or an
 * empty parameter that no amount of shell source text could produce
 * unambiguously; the `set` built-in installs one through the language,
 * which is what a script actually does.  A suite with only the first
 * would pass with `set` unimplemented; one with only the second could
 * not distinguish "$@" from "$*" on a parameter containing a space.
 */

/* Runs "'self' --produce-fields WORDS > tmp" and returns the child's
 * report of exactly which fields WORDS expanded to: "N:[f1][f2]...".
 * Caller frees.  This is the assertion stage 6b's post-mortem asked
 * for -- the *bytes* produced, not merely a status, since a command
 * that received the wrong argv still exits 0. */
static char *param_fields(const char *self, const char *words)
{
	char src[1024], *tmp = make_tmp(), *got;
	int status;
	if (!tmp) return 0;
	snprintf(src, sizeof src, "'%s' --produce-fields %s > %s", self, words, tmp);
	if (run(src, &status) != 0) { remove(tmp); free(tmp); return 0; }
	got = slurp(tmp);
	remove(tmp);
	free(tmp);
	return got;
}

static void check_fields(const char *self, const char *words, const char *want)
{
	char *got = param_fields(self, words);
	if (!got) { fails++; printf("FAIL fields(%s): could not run\n", words); return; }
	if (strcmp(got, want) != 0) {
		fails++;
		printf("FAIL fields(%s): got \"%s\", want \"%s\"\n", words, got, want);
	}
	free(got);
}

/* 2.5.1: "A positional parameter is a parameter denoted by the decimal
 * value represented by one or more digits, other than the single digit
 * 0 ... When a positional parameter with more than one digit is
 * specified, the application shall enclose the digits in braces". */
static void test_positional_single_and_multi_digit(void)
{
	char *args[12];
	int status, i;

	for (i = 0; i < 12; i++) args[i] = 0;
	args[0] = (char *)"one";   args[1] = (char *)"two";   args[2] = (char *)"three";
	args[3] = (char *)"four";  args[4] = (char *)"five";  args[5] = (char *)"six";
	args[6] = (char *)"seven"; args[7] = (char *)"eight"; args[8] = (char *)"nine";
	args[9] = (char *)"ten";   args[10] = (char *)"eleven";
	CHECK(__sh_params_replace(args, 11) == 0);

	CHECK(run("test \"$1\" = one", &status) == 0 && status == 0);
	CHECK(run("test \"$9\" = nine", &status) == 0 && status == 0);
	CHECK(run("test \"${9}\" = nine", &status) == 0 && status == 0);

	/* The point of the braces: unbraced, "$10" is $1 followed by a
	 * literal '0', which is why 2.5.1 requires them past one digit.
	 * Asserting *both* spellings is what tells a correct
	 * implementation from one that helpfully reads all the digits. */
	CHECK(run("test \"$10\" = one0", &status) == 0 && status == 0);
	CHECK(run("test \"${10}\" = ten", &status) == 0 && status == 0);
	CHECK(run("test \"${11}\" = eleven", &status) == 0 && status == 0);

	/* "even if there is a leading zero" -- ${01} is $1. */
	CHECK(run("test \"${01}\" = one", &status) == 0 && status == 0);

	/* Out of range is unset, which expands to nothing at all. */
	CHECK(run("test \"${12}\" = ''", &status) == 0 && status == 0);
	CHECK(run("test \"${999}\" = ''", &status) == 0 && status == 0);

	CHECK(__sh_params_replace(args, 0) == 0);
}

/* 2.5.2 '#': "Expands to the decimal number of positional parameters.
 * The command name (parameter 0) shall not be counted in the number
 * given by '#' because it is a special parameter, not a positional
 * parameter." */
static void test_positional_count_and_zero(void)
{
	char *args[3];
	int status;

	args[0] = (char *)"a"; args[1] = (char *)"b"; args[2] = (char *)"c";

	CHECK(__sh_params_replace(args, 0) == 0);
	CHECK(run("test \"$#\" = 0", &status) == 0 && status == 0);
	CHECK(run("test \"${#}\" = 0", &status) == 0 && status == 0);
	CHECK(__sh_params_replace(args, 3) == 0);
	CHECK(run("test \"$#\" = 3", &status) == 0 && status == 0);
	CHECK(run("test \"${#}\" = 3", &status) == 0 && status == 0);

	/* $0 is not counted, is not $1, and `set`/`shift` never touch it. */
	CHECK(__sh_param_set_zero("myshell") == 0);
	CHECK(run("test \"$0\" = myshell", &status) == 0 && status == 0);
	CHECK(run("shift 3; test \"$0\" = myshell && test \"$#\" = 0", &status) == 0 && status == 0);
	CHECK(__sh_params_replace(args, 3) == 0);
	CHECK(run("set -- x; test \"$0\" = myshell && test \"$1\" = x", &status) == 0 && status == 0);
	CHECK(__sh_params_replace(args, 0) == 0);
}

/* 2.5.2 '@' and '*', which is where every implementation of this goes
 * wrong.  Each case below is asserted on the *fields* the command
 * received, because a status cannot see the difference between "passed
 * three arguments" and "passed one argument containing three words". */
static void test_at_and_star_fields(const char *self)
{
	char *args[3];

	if (!file_redir_supported(self)) return;

	/* No positional parameters: 2.5.2 -- "[i]f there are no positional
	 * parameters, the expansion of '@' shall generate zero fields,
	 * even when '@' is within double-quotes".  This is the assertion
	 * the whole feature turns on: `f "$@"` with nothing set must pass
	 * NO argument, not one empty one. */
	args[0] = 0; args[1] = 0; args[2] = 0;
	CHECK(__sh_params_replace(args, 0) == 0);
	check_fields(self, "\"$@\"", "0:");
	check_fields(self, "$@", "0:");
	/* "$*" is not the same thing: it is one field, which with no
	 * parameters is one *empty* field, not zero fields. */
	check_fields(self, "\"$*\"", "1:[]");
	check_fields(self, "$*", "0:");
	/* ... and the enclosing quotes of an unrelated empty pair still
	 * make a field, which is the clause 2.5.2 spells out: "if the
	 * expansion is embedded within a word which contains one or more
	 * other parts that expand to a quoted null string, these null
	 * string(s) shall still produce an empty field". */
	check_fields(self, "\"\"$@\"\"", "1:[]");
	/* Embedded in a word with real text: nothing to splice, so the
	 * two halves join into one field. */
	check_fields(self, "x\"$@\"y", "1:[xy]");
	/* ... and the two one-sided forms, which are the only ones that can
	 * see whether the field was alive *before* the quote opened: with
	 * trailing text after the closing quote, text pushed afterwards
	 * revives the field and hides the mistake. */
	check_fields(self, "x\"$@\"", "1:[x]");
	check_fields(self, "\"$@\"y", "1:[y]");

	/* Several parameters, one containing a blank -- the case that
	 * separates "$@" from "$*" and from an unquoted expansion. */
	args[0] = (char *)"a b"; args[1] = (char *)"c";
	CHECK(__sh_params_replace(args, 2) == 0);
	check_fields(self, "\"$@\"", "2:[a b][c]");
	check_fields(self, "\"${@}\"", "2:[a b][c]");
	/* 2.5.2 for '*' in a non-splitting context: "the initial fields
	 * shall be joined to form a single field with the value of each
	 * parameter separated by the first character of the IFS variable
	 * ... or separated by a <space> if IFS is unset".  This shell
	 * never consults IFS (see <wordexp.h>), so it is always the
	 * <space> that clause names. */
	check_fields(self, "\"$*\"", "1:[a b c]");
	check_fields(self, "\"${*}\"", "1:[a b c]");
	/* Unquoted, '*' is the *splitting* context of the same clause --
	 * "initially producing one field for each positional parameter" --
	 * so it is not the joined form.  Asserting this is what tells the
	 * two halves of 2.5.2's '*' apart; the joined form alone passes
	 * whether or not the quoting is consulted. */
	check_fields(self, "$*", "2:[a b][c]");
	check_fields(self, "$@", "2:[a b][c]");

	/* 2.5.2's "except that if the parameter being expanded was
	 * embedded within a word, the first field shall be joined with the
	 * beginning part of the original word and the last field shall be
	 * joined with the end part". */
	check_fields(self, "x\"$@\"y", "2:[xa b][cy]");

	/* An empty parameter in the middle: quoted, a null field is still
	 * a field (2.6's "unless the original word contained ...
	 * double-quote characters"); unquoted, 2.5.2 allows it to be
	 * discarded and this implementation discards it, which is what
	 * keeps `f $1` with nothing set from passing an empty argument. */
	args[0] = (char *)"a"; args[1] = (char *)""; args[2] = (char *)"b";
	CHECK(__sh_params_replace(args, 3) == 0);
	check_fields(self, "\"$@\"", "3:[a][][b]");
	check_fields(self, "$@", "2:[a][b]");

	/* One parameter that is entirely empty. */
	args[0] = (char *)"";
	CHECK(__sh_params_replace(args, 1) == 0);
	check_fields(self, "\"$@\"", "1:[]");
	check_fields(self, "$@", "0:");
	check_fields(self, "\"$1\"", "1:[]");
	check_fields(self, "$1", "0:");

	CHECK(__sh_params_replace(args, 0) == 0);
}

/* Braced spellings must not be mistaken for the special parameters they
 * begin with.  ${#NAME} is string length, not ${#}; ${@...} and
 * ${*...} are parameter-operator forms, not ${@} and ${*}. */
static void test_brace_form_disambiguation(void)
{
	char *args[3];
	int status;

	args[0] = (char *)"a"; args[1] = (char *)"b"; args[2] = (char *)"c";
	CHECK(__sh_params_replace(args, 3) == 0);

	/* Not the parameter count: with three parameters set, an unset x has
	 * length zero.  Also exercise a nonempty value. */
	unsetenv("x");
	CHECK(run("test \"${#x}\" = 0", &status) == 0 && status == 0);
	CHECK(setenv("x", "four", 1) == 0);
	CHECK(run("test \"${#x}\" = 4", &status) == 0 && status == 0);
	unsetenv("x");

	/* Not "$@": a ${@x} that expanded like ${@} would start with "a". */
	CHECK(run("test \"${@x}\" = '${@x}'", &status) == 0 && status == 0);
	CHECK(run("test \"${*x}\" = '${*x}'", &status) == 0 && status == 0);

	CHECK(__sh_params_replace(args, 0) == 0);
}

/* 2.6: "If the complete expansion appropriate for a word results in an
 * empty field, that empty field shall be deleted from the list of
 * fields ... unless the original word contained single-quote or
 * double-quote characters."  Stage 7 closed this gap for every
 * parameter expansion, not only the positional ones, because "$@"
 * cannot be right while "$1" is wrong -- so the environment-variable
 * case is asserted here too. */
static void test_empty_field_deletion(const char *self)
{
	if (!file_redir_supported(self)) return;
	unsetenv("SHT_P7_EMPTY");
	check_fields(self, "$SHT_P7_EMPTY", "0:");
	check_fields(self, "\"$SHT_P7_EMPTY\"", "1:[]");
	check_fields(self, "''", "1:[]");
	check_fields(self, "a$SHT_P7_EMPTY", "1:[a]");
}

/* set(1p): "The remaining arguments shall be assigned in order to the
 * positional parameters ... All positional parameters shall be unset
 * before any new values are assigned", and "[t]he command set --
 * without argument shall unset all positional parameters and set the
 * special parameter '#' to zero." */
static void test_builtin_set(const char *self)
{
	int status;

	CHECK(run("set -- a b c; test \"$#\" = 3", &status) == 0 && status == 0);
	CHECK(run("set -- a b c; test \"$3\" = c", &status) == 0 && status == 0);
	/* "All positional parameters shall be unset before any new values
	 * are assigned": a shorter second list must not leave $3 behind. */
	CHECK(run("set -- a b c; set -- x; test \"$#\" = 1 && test \"${3}\" = ''",
	          &status) == 0 && status == 0);
	CHECK(run("set -- a b c; set --; test \"$#\" = 0", &status) == 0 && status == 0);
	/* Without "--", ordinary operands still become the parameters --
	 * set(1p)'s own example, "set c a b". */
	CHECK(run("set c a b; test \"$1\" = c && test \"$#\" = 3", &status) == 0 && status == 0);
	/* "set -- \"$x\"": a value beginning with '-' reaches the list
	 * intact rather than being read as an option. */
	CHECK(run("set -- -x; test \"$1\" = -x && test \"$#\" = 1", &status) == 0 && status == 0);

	/* Options are refused, loudly, rather than silently ignored: a
	 * `set -e` that did nothing would change the meaning of every
	 * later failure without the script being able to notice.
	 * set(1p) EXIT STATUS: ">0  An invalid option was specified". */
	CHECK(run("set -e", &status) == 0 && status > 0);
	CHECK(run("set +x", &status) == 0 && status > 0);
	/* And a refused `set` must not have half-assigned anything. */
	CHECK(run("set -- a b; set -e; test \"$#\" = 2", &status) == 0 && status == 0);

	/* No operands: the variable listing.  Asserted on the bytes, since
	 * "printed nothing" and "printed the right thing" are both exit 0
	 * -- and on the quoting, which is the half set(1p) calls out
	 * ("suitable for reinput to the shell") and the half a naive
	 * implementation gets wrong. */
	if (file_redir_supported(self)) {
		char src[512], *tmp = make_tmp(), *got;
		if (tmp) {
			setenv("SHT_P7_LIST", "has space and 'quote'", 1);
			snprintf(src, sizeof src, "set > %s", tmp);
			CHECK(run(src, &status) == 0 && status == 0);
			got = slurp(tmp);
			CHECK(got != 0);
			if (got) {
				CHECK(strstr(got, "SHT_P7_LIST='has space and '\\''quote'\\'''\n") != 0);
				free(got);
			}
			remove(tmp);
			free(tmp);
			unsetenv("SHT_P7_LIST");
		}
	}
}

/* export(1p): "The shell shall give the export attribute to the
 * variables corresponding to the specified names, which shall cause
 * them to be in the environment of subsequently executed commands."
 * bi_export()'s own header comment (src/sh/builtin.c) explains why this
 * shell needs no separate exported/unexported bookkeeping to get that
 * right: every shell variable already lives in the real environ, which
 * is exactly what these assertions check directly -- run() executes the
 * engine in this same process (unlike test/sh-main.c's spawn of a whole
 * second sh.exe), so a bare getenv()/setenv() here is the ground truth. */
static void test_builtin_export(const char *self)
{
	int status;
	char *v;

	unsetenv("SHT_EXPORT_A");
	CHECK(run("export SHT_EXPORT_A=bar", &status) == 0 && status == 0);
	v = getenv("SHT_EXPORT_A");
	CHECK(v && strcmp(v, "bar") == 0);
	unsetenv("SHT_EXPORT_A");

	/* `export NAME` on an already-set variable leaves its value alone. */
	setenv("SHT_EXPORT_B", "baz", 1);
	CHECK(run("export SHT_EXPORT_B", &status) == 0 && status == 0);
	v = getenv("SHT_EXPORT_B");
	CHECK(v && strcmp(v, "baz") == 0);
	unsetenv("SHT_EXPORT_B");

	/* -p takes no further operands (export(1p) SYNOPSIS: "export -p"
	 * and "export name[=word]..." are the two forms, not a mix). */
	CHECK(run("export -p x", &status) == 0 && status > 0);

	/* An invalid identifier is a real, diagnosed error, and an operand
	 * that follows a bad one is still processed rather than the whole
	 * command being abandoned. */
	unsetenv("SHT_EXPORT_E");
	CHECK(run("export 1BAD=x SHT_EXPORT_E=ok", &status) == 0 && status != 0);
	v = getenv("SHT_EXPORT_E");
	CHECK(v && strcmp(v, "ok") == 0);
	unsetenv("SHT_EXPORT_E");

	/* A pipeline stage is a subshell environment (XCU 2.12): an
	 * `export`'s setenv() there must not leak into the shell that ran
	 * the pipeline once that stage's subshell environment is discarded
	 * -- the same rule test_builtin_set()/test_builtin_shift() already
	 * check for `set`/`shift`, applied here to bi_export(). */
	unsetenv("SHT_EXPORT_F");
	CHECK(run("export SHT_EXPORT_F=leaked | true", &status) == 0 && status == 0);
	CHECK(getenv("SHT_EXPORT_F") == 0);

	/* A subshell *inherits* an exported variable (XCU 2.12 duplicates
	 * the shell execution environment for "(...)"), the complementary
	 * half of the pipeline check just above. */
	setenv("SHT_EXPORT_G", "seen", 1);
	CHECK(run("( test \"$SHT_EXPORT_G\" = seen )", &status) == 0 && status == 0);
	unsetenv("SHT_EXPORT_G");

	/* No operands, and -p: the variable listing, asserted on the bytes
	 * for the same reason test_builtin_set()'s own listing check is --
	 * "printed nothing" and "printed the right thing" are both exit 0,
	 * and the quoting (export(1p): "suitable for reinput") is the half
	 * a naive implementation gets wrong. bi_export() shares
	 * list_variables() with bi_set(), so this is the same check with an
	 * "export " prefix on each line. */
	if (file_redir_supported(self)) {
		char src[512], *tmp = make_tmp(), *got;
		if (tmp) {
			setenv("SHT_EXPORT_LIST", "has space and 'quote'", 1);
			snprintf(src, sizeof src, "export > %s", tmp);
			CHECK(run(src, &status) == 0 && status == 0);
			got = slurp(tmp);
			CHECK(got != 0);
			if (got) {
				CHECK(strstr(got, "export SHT_EXPORT_LIST='has space and '\\''quote'\\'''\n") != 0);
				free(got);
			}
			remove(tmp);
			free(tmp);
			unsetenv("SHT_EXPORT_LIST");
		}
	}
}

/* readonly(1p): "It shall be an error for [a name given the read-only
 * attribute] to appear as a name in a subsequent readonly command, or
 * to appear as one of the names in a variable assignment." Unlike
 * export, this really is enforcement rather than bookkeeping --
 * bi_readonly()'s own header comment (src/sh/builtin.c) points at
 * exec_assignment_only() (src/sh/execute.c) as the one place it is
 * checked. run() executes the engine in this same process, so a bare
 * getenv() after a rejected assignment is the ground truth that the
 * value never changed, the same way test_builtin_export() uses it to
 * confirm a value did.
 *
 * Every name here is unique to this function and never reused
 * elsewhere in this file: src/sh/readonly.c's side-table has no
 * unmark (this shell has no `unset` yet -- see that file's own header),
 * so a name marked read-only here would stay unassignable for the rest
 * of this process if some other test picked the same name. */
static void test_builtin_readonly(const char *self)
{
	int status;
	char *v;

	/* `readonly NAME=value` sets it and marks it; a later plain
	 * assignment is rejected and the value is left untouched. */
	unsetenv("SHT_RO_A");
	CHECK(run("readonly SHT_RO_A=bar", &status) == 0 && status == 0);
	v = getenv("SHT_RO_A");
	CHECK(v && strcmp(v, "bar") == 0);
	CHECK(run("SHT_RO_A=baz", &status) == 0 && status != 0);
	v = getenv("SHT_RO_A");
	CHECK(v && strcmp(v, "bar") == 0);

	/* `readonly NAME` on an already-set variable marks it without
	 * touching the value, and a later assignment is rejected exactly as
	 * if the value had been given to `readonly` itself. */
	setenv("SHT_RO_B", "baz", 1);
	CHECK(run("readonly SHT_RO_B", &status) == 0 && status == 0);
	CHECK(run("SHT_RO_B=qux", &status) == 0 && status != 0);
	v = getenv("SHT_RO_B");
	CHECK(v && strcmp(v, "baz") == 0);

	/* Re-declaring an already read-only name through `readonly` itself
	 * is rejected too, even when the value matches; the bare, valueless
	 * form re-marking an already-marked name is the genuine no-op
	 * bi_export()'s own bare-NAME form is. */
	unsetenv("SHT_RO_C");
	CHECK(run("readonly SHT_RO_C=x", &status) == 0 && status == 0);
	CHECK(run("readonly SHT_RO_C=x", &status) == 0 && status != 0);
	CHECK(run("readonly SHT_RO_C", &status) == 0 && status == 0);

	/* A name marked read-only before it is ever assigned a value is
	 * still enforced on the first real assignment -- src/sh/readonly.c
	 * tracks names, not environ entries, so there is nothing that needs
	 * SHT_RO_D to already be set first. */
	unsetenv("SHT_RO_D");
	CHECK(run("readonly SHT_RO_D", &status) == 0 && status == 0);
	CHECK(run("SHT_RO_D=nope", &status) == 0 && status != 0);
	CHECK(getenv("SHT_RO_D") == 0);

	/* -p takes no further operands, matching export -p's own SYNOPSIS
	 * shape (bi_export()'s own check, mirrored here). */
	CHECK(run("readonly -p x", &status) == 0 && status > 0);

	/* An invalid identifier is a real, diagnosed error, and an operand
	 * that follows a bad one is still processed. */
	unsetenv("SHT_RO_E");
	CHECK(run("readonly 1BAD=x SHT_RO_E=ok", &status) == 0 && status != 0);
	v = getenv("SHT_RO_E");
	CHECK(v && strcmp(v, "ok") == 0);

	/* A pipeline stage is a subshell environment (XCU 2.12): a
	 * `readonly` there must not leave the name marked once that stage's
	 * subshell environment is discarded -- the same rule
	 * test_builtin_export() already checks, applied here. */
	unsetenv("SHT_RO_F");
	CHECK(run("readonly SHT_RO_F=x | true", &status) == 0 && status == 0);
	CHECK(run("SHT_RO_F=y", &status) == 0 && status == 0);
	v = getenv("SHT_RO_F");
	CHECK(v && strcmp(v, "y") == 0);
	unsetenv("SHT_RO_F");

	/* No operands, and -p: readonly(1p)'s own "readonly name=value"
	 * format, and a name with no value at all listing with no '=' --
	 * both checked on the bytes for the same reason
	 * test_builtin_export()'s own listing check is. */
	if (file_redir_supported(self)) {
		char src[512], *tmp = make_tmp(), *got;
		if (tmp) {
			unsetenv("SHT_RO_G");
			unsetenv("SHT_RO_H");
			CHECK(run("readonly SHT_RO_G='has space'", &status) == 0 && status == 0);
			CHECK(run("readonly SHT_RO_H", &status) == 0 && status == 0);
			snprintf(src, sizeof src, "readonly > %s", tmp);
			CHECK(run(src, &status) == 0 && status == 0);
			got = slurp(tmp);
			CHECK(got != 0);
			if (got) {
				CHECK(strstr(got, "readonly SHT_RO_G='has space'\n") != 0);
				CHECK(strstr(got, "readonly SHT_RO_H\n") != 0);
				free(got);
			}
			remove(tmp);
			free(tmp);
		}
	}

	/* `NAME=value cmd`: the command-prefix form (2.9.1) is a real
	 * assignment too, so a read-only NAME is rejected there exactly as
	 * it is in the plain form -- but there is a real command here, and
	 * it still runs (build_child_envp()'s own header comment, src/sh/
	 * execute.c): only that one override is dropped, not the whole
	 * command. This process's own getenv() cannot tell the difference,
	 * since build_child_envp() never touches this process's real
	 * environ either way (that is the property
	 * test_exec_assignment_prefix_does_not_leak() above already checks)
	 * -- what a spawned child's envp actually contained is only
	 * observable by asking a real separate process, hence --print-env. */
	if (file_redir_supported(self)) {
		char src[512], *tmp = make_tmp(), *got;
		if (tmp) {
			unsetenv("SHT_RO_I");
			CHECK(run("readonly SHT_RO_I=bar", &status) == 0 && status == 0);
			snprintf(src, sizeof src, "SHT_RO_I=baz '%s' --print-env SHT_RO_I > %s", self, tmp);
			CHECK(run(src, &status) == 0 && status == 0);
			got = slurp(tmp);
			CHECK(got != 0);
			if (got) { CHECK(strcmp(got, "bar") == 0); free(got); }
			remove(tmp);
			free(tmp);
		}
	}

	/* `for NAME in ...`: the loop variable is (re)assigned every
	 * iteration, and it is the *same* name each time, so a read-only
	 * NAME is rejected before the very first iteration -- diagnosed,
	 * nonzero status, and the body never runs at all (SHT_RO_LOOP_HIT
	 * stays unset), matching bash/dash's "the whole for aborts" rather
	 * than skipping just that one iteration and continuing with the
	 * rest. */
	unsetenv("SHT_RO_LOOP");
	unsetenv("SHT_RO_LOOP_HIT");
	CHECK(run("readonly SHT_RO_LOOP", &status) == 0 && status == 0);
	CHECK(run("for SHT_RO_LOOP in a b c; do SHT_RO_LOOP_HIT=1; done", &status) == 0 && status != 0);
	CHECK(getenv("SHT_RO_LOOP_HIT") == 0);
}

/* shift(1p): "Positional parameter 1 shall be assigned the value of
 * parameter (1+n) ... If n is not given, it shall be assumed to be 1.
 * If n is 0, the positional and special parameters are not changed."
 * EXIT STATUS: "[i]f the n operand is invalid or is greater than
 * "$#" ... a non-zero exit status shall be returned." */
static void test_builtin_shift(void)
{
	int status;

	/* shift(1p)'s own EXAMPLES: "set a b c d e; shift 2" leaves c d e. */
	CHECK(run("set -- a b c d e; shift 2; test \"$#\" = 3 && test \"$1\" = c",
	          &status) == 0 && status == 0);
	CHECK(run("set -- a b c; shift; test \"$#\" = 2 && test \"$1\" = b",
	          &status) == 0 && status == 0);
	/* "If n is 0, the positional and special parameters are not
	 * changed" -- and it is not an error. */
	CHECK(run("set -- a b c; shift 0; test \"$#\" = 3 && test \"$1\" = a",
	          &status) == 0 && status == 0);
	/* ... and `shift 0` itself succeeds.  Asserting only the trailing
	 * `test` above cannot see a `shift 0` that returned an error
	 * status, because the `;` list takes its status from the last
	 * command either way. */
	CHECK(run("set -- a b c; shift 0", &status) == 0 && status == 0);
	CHECK(run("set --; shift 0", &status) == 0 && status == 0);
	/* Shifting exactly $# is legal and empties the list. */
	CHECK(run("set -- a b; shift 2; test \"$#\" = 0", &status) == 0 && status == 0);

	/* Greater than $#: nonzero status, and -- the part a status alone
	 * does not pin -- the parameters must be left alone rather than
	 * partly shifted. */
	CHECK(run("set -- a b; shift 3", &status) == 0 && status > 0);
	CHECK(run("set -- a b; shift 3; test \"$#\" = 2 && test \"$1\" = a",
	          &status) == 0 && status == 0);
	CHECK(run("set --; shift", &status) == 0 && status > 0);

	/* "an unsigned decimal integer": not a negative, not a word, not a
	 * number with trailing text. */
	CHECK(run("set -- a b; shift -1", &status) == 0 && status > 0);
	CHECK(run("set -- a b; shift x", &status) == 0 && status > 0);
	CHECK(run("set -- a b; shift 1x", &status) == 0 && status > 0);
	CHECK(run("set -- a b; shift 1 2", &status) == 0 && status > 0);
}

/* XCU 2.12: a subshell environment's changes "shall not affect the
 * shell execution environment", which covers the positional parameters
 * as much as it covers the working directory -- exec.c already
 * snapshots environ and cwd for "( ... )" and for a command
 * substitution, and stage 7 puts the parameter list in the same
 * bracket. */
static void test_params_are_subshell_scoped(void)
{
	int status;

	CHECK(run("set -- a b c; ( set -- x ); test \"$#\" = 3 && test \"$1\" = a",
	          &status) == 0 && status == 0);
	CHECK(run("set -- a b c; ( shift 2; test \"$#\" = 1 ); test \"$#\" = 3",
	          &status) == 0 && status == 0);
	/* A subshell *inherits* them, which is the other half: a snapshot
	 * that cleared the list instead of copying it would pass the two
	 * assertions above and fail this one. */
	CHECK(run("set -- a b c; ( test \"$2\" = b )", &status) == 0 && status == 0);
	/* A brace group runs "in the current process environment" (2.9.4),
	 * so it does *not* get the isolation. */
	CHECK(run("set -- a b c; { set -- x ; }; test \"$#\" = 1", &status) == 0 && status == 0);
}

/* The parameters are the shell's, not the environment's: XCU 2.5.1's
 * list is not exported, so a child must not see a variable named "1",
 * and a stray environment entry of that name must not be mistaken for
 * a positional parameter. */
static void test_params_are_not_environment_variables(void)
{
	int status;

	setenv("1", "from-environ", 1);
	CHECK(__sh_params_replace(0, 0) == 0);
	CHECK(run("test \"$1\" = ''", &status) == 0 && status == 0);
	CHECK(run("set -- real; test \"$1\" = real", &status) == 0 && status == 0);
	unsetenv("1");
	CHECK(__sh_params_replace(0, 0) == 0);
}

/* ---- stage 6b: the compound commands (XCU 2.9.4) ---------------------
 *
 * Spec page: XCU 2.9.4 "Compound Commands" -- "The if Conditional
 * Construct", "The while Loop", "The until Loop", "The for Loop", plus
 * 2.10.1's rule 1 and rule 5 for how their reserved words and the for
 * loop's NAME are recognised.
 */

/* "the body produced exactly this" -- the assertion a status alone cannot
 * make.  Several stage-6b mutations survived a suite that checked only
 * exit status: a pipeline stage that never ran its body at all still
 * reports 0, because an empty compound-list is a successful one.  Reading
 * the bytes back is what tells those two apart. */
static void check_file_is(const char *path, const char *want)
{
	char buf[256];
	size_t n = 0;
	FILE *f = fopen(path, "rb");
	CHECK(f != 0);
	if (!f) return;
	n = fread(buf, 1, sizeof buf - 1, f);
	buf[n] = 0;
	fclose(f);
	if (strcmp(buf, want) != 0) {
		printf("FAIL %s: got \"%s\", want \"%s\"\n", path, buf, want);
		fails++;
	}
}

/* 2.9.4 "The if Conditional Construct": "The if compound-list shall be
 * executed; if its exit status is zero, the then compound-list shall be
 * executed and the command shall complete.  Otherwise, each elif
 * compound-list shall be executed, in turn, and if its exit status is
 * zero, the then compound-list shall be executed and the command shall
 * complete.  Otherwise, the else compound-list shall be executed." */
static void test_if_branches(const char *self)
{
	char src[768];
	int status;

	snprintf(src, sizeof src, "if true; then '%s' --exit-child 3; fi", self);
	CHECK(run(src, &status) == 0 && status == 3);

	/* The false branch must not run its body at all, not merely report
	 * a different status: a marker file is the only way to tell those
	 * two apart from out here. */
	unlink("shtst_if_marker.txt");
	snprintf(src, sizeof src, "if false; then '%s' --produce x > shtst_if_marker.txt; fi", self);
	CHECK(run(src, &status) == 0);
	CHECK(access("shtst_if_marker.txt", F_OK) != 0);

	snprintf(src, sizeof src, "if false; then '%s' --exit-child 3; else '%s' --exit-child 4; fi", self, self);
	CHECK(run(src, &status) == 0 && status == 4);

	/* elif: taken in order, first zero condition wins, and a later
	 * elif whose condition is also true must not run. */
	snprintf(src, sizeof src, "if false; then '%s' --exit-child 3; elif true; then '%s' --exit-child 5; else '%s' --exit-child 4; fi", self, self, self);
	CHECK(run(src, &status) == 0 && status == 5);
	snprintf(src, sizeof src, "if false; then '%s' --exit-child 3; elif false; then '%s' --exit-child 5; else '%s' --exit-child 4; fi", self, self, self);
	CHECK(run(src, &status) == 0 && status == 4);
	snprintf(src, sizeof src, "if true; then '%s' --exit-child 2; elif true; then '%s' --exit-child 5; fi", self, self);
	CHECK(run(src, &status) == 0 && status == 2);
	snprintf(src, sizeof src, "if false; then '%s' --exit-child 2; elif false; then '%s' --exit-child 5; elif true; then '%s' --exit-child 6; fi", self, self, self);
	CHECK(run(src, &status) == 0 && status == 6);

	unlink("shtst_if_marker.txt");
}

/* 2.9.4, if EXIT STATUS: "the exit status of the then or else
 * compound-list that was executed, or zero, if none was executed."
 *
 * The "zero, if none was executed" half is the one an implementation
 * gets wrong by letting the condition's status fall through -- and the
 * condition of a taken-nothing `if` is *always* non-zero by
 * construction, so a fall-through implementation reports 1 here every
 * time.  Preceding it with a failing command as well pins that the
 * status is reset rather than merely inherited from further back. */
static void test_if_status_when_nothing_ran(void)
{
	int status;

	CHECK(run("if false; then :; fi", &status) == 0 && status == 0);
	CHECK(run("false; if false; then :; fi", &status) == 0 && status == 0);
	CHECK(run("true; if false; then :; fi", &status) == 0 && status == 0);
	/* An `if` whose condition is a *pipeline* still uses that
	 * pipeline's status, i.e. the last stage's (2.9.2). */
	CHECK(run("if false | true; then :; fi", &status) == 0 && status == 0);
	CHECK(run("if true | false; then exit 3; fi", &status) == 0 && status == 0);
	/* "! cond" is a pipeline negation, so it inverts which branch runs. */
	CHECK(run("if ! false; then exit 3; fi", &status) == 0 && status == 3);
}

/* 2.9.4 "The while Loop": "compound-list-1 shall be executed, and if it
 * has a non-zero exit status, the while command shall complete.
 * Otherwise, the compound-list-2 shall be executed, and the process
 * shall repeat."  EXIT STATUS: "the exit status of the last
 * compound-list-2 executed, or zero if none was executed."
 *
 * Every loop here has a body that makes its own condition false, so a
 * bug that never re-evaluates the condition hangs rather than passes --
 * which is the failure mode worth having, and why none of them is
 * `while true`. */
static void test_while_until(void)
{
	int status;

	/* Runs zero times: status 0, and the body must not run. */
	CHECK(run("while false; do exit 9; done", &status) == 0 && status == 0);
	CHECK(run("until true; do exit 9; done", &status) == 0 && status == 0);
	/* ... and 0 even when the last thing before it failed. */
	CHECK(run("false; while false; do exit 9; done", &status) == 0 && status == 0);
	CHECK(run("false; until true; do exit 9; done", &status) == 0 && status == 0);

	/* Runs until the body falsifies the condition.  `until` is the
	 * same loop with the test inverted, so it needs the mirror-image
	 * condition to terminate -- if the two shared a sense, one of
	 * these two would spin forever. */
	unsetenv("SHT_N");
	CHECK(run("SHT_N=a; while test \"$SHT_N\" = a; do SHT_N=b; done; test \"$SHT_N\" = b", &status) == 0);
	CHECK(status == 0);
	unsetenv("SHT_N");
	CHECK(run("SHT_N=a; until test \"$SHT_N\" = b; do SHT_N=b; done; test \"$SHT_N\" = b", &status) == 0);
	CHECK(status == 0);
	unsetenv("SHT_N");

	/* "the exit status of the last compound-list-2 executed": the
	 * *body*'s, never the condition's -- and the condition's final
	 * evaluation is by definition the one that ended the loop, so an
	 * implementation that lets it through reports the wrong number
	 * every single time a loop terminates normally. */
	unsetenv("SHT_N");
	CHECK(run("SHT_N=a; while test \"$SHT_N\" = a; do SHT_N=b; false; done", &status) == 0);
	CHECK(status == 1);
	unsetenv("SHT_N");
}

/* 2.9.4 "The for Loop": "the list of words following in shall be
 * expanded to generate a list of items.  Then, the variable name shall
 * be set to each item, in turn, and the compound-list executed each
 * time.  If no items result from the expansion, the compound-list shall
 * not be executed."  EXIT STATUS: "the exit status of the last command
 * that executes.  If there are no items, the exit status shall be
 * zero." */
static void test_for_loop(const char *self)
{
	char src[768];
	int status;
	FILE *f;
	char buf[128];

	/* Iterates in order, and `name` really is set to each item: the
	 * body appends $f to a file, so the file contents are the item
	 * sequence rather than a count. */
	/* Redirection-dependent, so it carries the same capability guard the
	 * stage-3 redirection tests use: a spawned child cannot see this
	 * process's file redirections under the native ASan stub. */
	if (file_redir_supported(self)) {
		unlink("shtst_for_out.txt");
		snprintf(src, sizeof src,
			"for f in a b c; do '%s' --produce \"$f\" >> shtst_for_out.txt; done", self);
		CHECK(run(src, &status) == 0);
		buf[0] = 0;
		f = fopen("shtst_for_out.txt", "rb");
		CHECK(f != 0);
		if (f) { size_t n = fread(buf, 1, sizeof buf - 1, f); buf[n] = 0; fclose(f); }
		CHECK(strcmp(buf, "a\nb\nc\n") == 0); /* --produce writes its operand plus a newline */
		unlink("shtst_for_out.txt");
	}

	/* "the exit status of the last command that executes" -- the last
	 * iteration's, not the first's and not an aggregate. */
	CHECK(run("for f in a b c; do test \"$f\" = c; done", &status) == 0 && status == 0);
	CHECK(run("for f in a b c; do test \"$f\" = a; done", &status) == 0 && status == 1);

	/* "If no items result from the expansion, the compound-list shall
	 * not be executed" and "if there are no items, the exit status
	 * shall be zero" -- both halves, since a body that ran once and
	 * happened to exit 0 would satisfy only the second. */
	CHECK(run("for f in ; do exit 9; done", &status) == 0 && status == 0);
	CHECK(run("false; for f in ; do exit 9; done", &status) == 0 && status == 0);

	/* "shall be expanded" is the ordinary word expansion, so one source
	 * word can become several items and several source words can be one
	 * item each -- exec_for() does not tokenise the list itself. */
	CHECK(run("for f in a 'b c' d; do test \"$f\" = d; done", &status) == 0 && status == 0);
	CHECK(run("for f in a 'b c' d; do test \"$f\" = 'b c'; done", &status) == 0 && status == 1);
	unsetenv("SHT_LIST");
	CHECK(run("SHT_LIST='p q r'; for f in \"$SHT_LIST\"; do test \"$f\" = 'p q r'; done", &status) == 0);
	CHECK(status == 0);
	unsetenv("SHT_LIST");

	/* ---- inherited wordexp() behavior -------------------------------
	 *
	 * Parameter-expansion results are field-split unless quoted, and the
	 * shell shares wordexp()'s implementation of that rule. */
	unsetenv("SHT_LIST");
	CHECK(run("SHT_LIST='p q r'; for f in $SHT_LIST; do test \"$f\" = r; done", &status) == 0);
	CHECK(status == 0);
	CHECK(run("SHT_LIST='p q r'; for f in $SHT_LIST; do test \"$f\" = 'p q r'; done", &status) == 0);
	CHECK(status == 1);
	unsetenv("SHT_LIST");

	/* (b) XCU 2.6: "If the complete expansion appropriate for a word
	 *     results in an empty field, that empty field shall be deleted
	 *     from the list of fields ... unless the original word
	 *     contained single-quote or double-quote characters."  This
	 *     was the second pinned gap: wordexp() used to *keep* the empty
	 *     field, so an unset variable was one empty item and the body
	 *     ran once with the loop variable set to "".  Stage 7 closed
	 *     it -- "$@" needs it, since `f $1` with no positional
	 *     parameters passing one empty argument instead of none is the
	 *     same defect wearing a different name -- so this assertion is
	 *     inverted rather than deleted: 2.9.4's "if no items result
	 *     from the expansion, the compound-list shall not be executed"
	 *     now reaches this case. */
	unsetenv("SHT_EMPTY");
	CHECK(run("for f in $SHT_EMPTY; do exit 9; done", &status) == 0);
	CHECK(status == 0); /* the body did not run */
	/* And the quoted form still produces a field, which is the half of
	 * 2.6's sentence that is easy to lose while implementing the other:
	 * "unless the original word contained ... double-quote
	 * characters". */
	CHECK(run("for f in \"$SHT_EMPTY\"; do exit 9; done", &status) == 0);
	CHECK(status == 9);

	/* The loop variable survives the loop -- it is an ordinary
	 * assignment into the one variable store this shell has. */
	unsetenv("SHT_V");
	CHECK(run("for SHT_V in a b; do :; done; test \"$SHT_V\" = b", &status) == 0);
	CHECK(status == 0);
	unsetenv("SHT_V");
}

/* 2.9.4's opening paragraph: "each can be followed by redirections on
 * the same line as the terminator.  Each redirection shall apply to all
 * the commands within the compound command that do not explicitly
 * override that redirection." */
static void test_compound_redirection(const char *self)
{
	char src[768];
	int status;
	char buf[128];
	FILE *f;

	/* Every assertion in here is about a redirection reaching a spawned
	 * child, which the native ASan stub cannot model -- tools/asan-build.sh
	 * compiles all of src/ against fuzz/ntstubs.c, whose RtlCreateUserProcess
	 * execve()s a real host binary instead of copying NT process
	 * parameters.  file_redir_supported() is the probe the stage-3
	 * redirection tests already use for exactly this, and it prints a note
	 * saying what was skipped rather than passing vacuously.  Covered for
	 * real by `make check` under Wine and by the real-Windows CI leg. */
	if (!file_redir_supported(self)) return;

	unlink("shtst_cr_out.txt");
	snprintf(src, sizeof src,
		"for f in a b; do '%s' --produce \"$f\"; done > shtst_cr_out.txt", self);
	CHECK(run(src, &status) == 0);
	buf[0] = 0;
	f = fopen("shtst_cr_out.txt", "rb");
	CHECK(f != 0);
	if (f) { size_t n = fread(buf, 1, sizeof buf - 1, f); buf[n] = 0; fclose(f); }
	CHECK(strcmp(buf, "a\nb\n") == 0);

	unlink("shtst_cr_out.txt");
	snprintf(src, sizeof src,
		"if true; then '%s' --produce inner; fi > shtst_cr_out.txt", self);
	CHECK(run(src, &status) == 0);
	buf[0] = 0;
	f = fopen("shtst_cr_out.txt", "rb");
	CHECK(f != 0);
	if (f) { size_t n = fread(buf, 1, sizeof buf - 1, f); buf[n] = 0; fclose(f); }
	CHECK(strcmp(buf, "inner\n") == 0);
	unlink("shtst_cr_out.txt");
}

/* 2.12: a subshell environment is what "( list )" asks for; the
 * control-flow constructs are not on that list, so their bodies run in
 * the shell's own environment and their side effects outlive them.
 * Getting this backwards is not a status bug -- every status above
 * still comes out right -- so it needs its own assertions. */
static void test_compound_runs_in_current_environment(void)
{
	char *saved = save_cwd();
	char *now;
	int status;

	unsetenv("SHT_ENV");
	CHECK(run("if true; then SHT_ENV=set; fi; test \"$SHT_ENV\" = set", &status) == 0);
	CHECK(status == 0);
	unsetenv("SHT_ENV");
	CHECK(run("for f in a; do SHT_ENV=set; done; test \"$SHT_ENV\" = set", &status) == 0);
	CHECK(status == 0);
	unsetenv("SHT_ENV");

	/* ... and a "( ... )" around the same thing still scopes it,
	 * which is the control that makes the two assertions above mean
	 * "not a subshell" rather than "environ happens to persist". */
	CHECK(run("( SHT_ENV=set ); test \"$SHT_ENV\" = set", &status) == 0);
	CHECK(status == 1);
	unsetenv("SHT_ENV");

	CHECK(mkdir("shtst_cmp_dir", 0755) == 0 || errno == EEXIST);
	CHECK(run("for f in a; do cd shtst_cmp_dir; done", &status) == 0);
	now = getcwd(0, 0);
	CHECK(now && saved && strcmp(now, saved) != 0); /* the shell really moved */
	free(now);
	restore_cwd(saved);
	rmdir("shtst_cmp_dir");
}

/* 2.14 `exit` from inside a compound command: sh.h's control-flow
 * comment says the unwind has to get out of "however many nested lists,
 * and-or terms and pipelines it is buried in", and a loop is the one
 * construct where failing to notice does not merely report a wrong
 * status -- `while` asks its condition again and spins forever.  Each
 * of these therefore has a body that would never terminate the loop on
 * its own. */
static void test_exit_unwinds_compound(const char *self)
{
	char src[768];
	int status;

	CHECK(run("while true; do exit 4; done", &status) == 0 && status == 4);
	CHECK(run("until false; do exit 5; done", &status) == 0 && status == 5);
	CHECK(run("if true; then exit 6; fi", &status) == 0 && status == 6);
	CHECK(run("for f in a b c; do exit 7; done", &status) == 0 && status == 7);
	/* ... and the body must run ONCE, not once per item.  The status above
	 * cannot see the difference: re-running `exit 7` for every remaining
	 * item produces the same 7.  Only a side effect per iteration shows
	 * that the loop kept going after the unwind began -- 2.9.4's loop does
	 * not get to run its body again once `exit` is pending. */
	/* redirection-dependent: see file_redir_supported() */
	if (file_redir_supported(self)) {
		unlink("shtst_fx_marker.txt");
		snprintf(src, sizeof src,
			"for f in a b c; do '%s' --produce \"$f\" >> shtst_fx_marker.txt; exit 7; done", self);
		CHECK(run(src, &status) == 0 && status == 7);
		check_file_is("shtst_fx_marker.txt", "a\n");
		unlink("shtst_fx_marker.txt");
	}

	/* Nothing after it in the same program runs. */
	unlink("shtst_cx_marker.txt");
	snprintf(src, sizeof src,
		"while true; do exit 2; done; '%s' --produce x > shtst_cx_marker.txt", self);
	CHECK(run(src, &status) == 0 && status == 2);
	CHECK(access("shtst_cx_marker.txt", F_OK) != 0);

	/* An `exit` in a *condition* stops the loop too, and its status is
	 * the program's -- otherwise the condition's status would be read
	 * as "keep going" and the loop would run its body once more. */
	CHECK(run("while exit 8; do :; done", &status) == 0 && status == 8);
	CHECK(run("if exit 9; then :; fi", &status) == 0 && status == 9);

	/* A subshell around it still consumes the unwind (2.9.4/2.12), so
	 * the rest of the program runs and reports its own status. */
	snprintf(src, sizeof src, "( while true; do exit 3; done ); '%s' --exit-child 5", self);
	CHECK(run(src, &status) == 0 && status == 5);

	unlink("shtst_cx_marker.txt");
}

/* A compound command is a pipeline stage like any other (2.9.2), and
 * 2.12 puts every stage of a multi-command pipeline in a subshell
 * environment -- so a `cd` in a looping stage must not move the shell,
 * exactly as it must not from a "{ ...; }" stage. */
static void test_compound_as_pipeline_stage(const char *self)
{
	char src[768];
	char *saved = save_cwd();
	char *now;
	int status;

	/* Redirected to a file rather than left on this process's stdout:
	 * a suite that prints the output of the programs it runs makes a
	 * real failure line harder to see, and the pipeline's own plumbing
	 * is what is under test, not where its last stage lands. */
	/* The CONTENT, not just the status.  An `if` stage whose body never
	 * ran still exits 0 (an empty compound-list succeeds), so a status-only
	 * assertion here passes even when the stage executed nothing at all --
	 * which is exactly what happens if this path reads u.group.body
	 * directly instead of dispatching on the kind: SH_CMD_IF keeps its
	 * branches in u.ifcmd.arms, a different union member entirely. */
	/* redirection-dependent: see file_redir_supported() */
	if (file_redir_supported(self)) {
		unlink("shtst_cps_out.txt");
		snprintf(src, sizeof src,
			"'%s' --produce hi | if true; then '%s' --cat; fi > shtst_cps_out.txt", self, self);
		CHECK(run(src, &status) == 0 && status == 0);
		check_file_is("shtst_cps_out.txt", "hi\n");

		/* Same for a `for` stage, which fails differently and so needs its own
		 * assertion: u.forloop.body IS the do-group there, so a bypassing path
		 * runs the body once with the loop variable never set, rather than not
		 * at all. */
		unlink("shtst_cps_out.txt");
		snprintf(src, sizeof src,
			"for f in a b; do '%s' --produce \"$f\"; done | '%s' --cat > shtst_cps_out.txt", self, self);
		CHECK(run(src, &status) == 0 && status == 0);
		check_file_is("shtst_cps_out.txt", "a\nb\n");
		unlink("shtst_cps_out.txt");
	}

	CHECK(mkdir("shtst_cps_dir", 0755) == 0 || errno == EEXIST);
	snprintf(src, sizeof src, "while false; do :; done | '%s' --exit-child 0", self);
	CHECK(run(src, &status) == 0);
	snprintf(src, sizeof src, "for f in a; do cd shtst_cps_dir; done | '%s' --exit-child 0", self);
	CHECK(run(src, &status) == 0);
	now = getcwd(0, 0);
	CHECK(now && saved && strcmp(now, saved) == 0); /* the shell did not move */
	free(now);
	restore_cwd(saved);
	rmdir("shtst_cps_dir");
}

/* 2.9.4: "Omitting: in word ... shall be equivalent to: in "$@"".
 * Stage 6b parsed this and refused it at execution (-1, "cannot execute
 * this node") because there were no positional parameters; stage 7 has
 * them, so the equivalence is delivered for real. */
static void test_for_without_in_iterates_positional_parameters(void)
{
	int status;
	char *args[4];

	args[0] = (char *)"a"; args[1] = (char *)"b"; args[2] = (char *)"c";

	/* It still parses -- that never changed. */
	{
		struct sh_list *l = __sh_parse("for f; do :; done", 0, 0);
		CHECK(l != 0);
		__sh_list_free(l);
	}

	/* "in \"$@\"" means the *fields* of "$@": one iteration per
	 * parameter, each getting the whole parameter even when it
	 * contains a blank.  SHT_ACC accumulates them so the assertion is
	 * about what the body saw, not just how many times it ran -- a
	 * loop that ran three times over the wrong values exits 0 exactly
	 * like one that ran over the right ones. */
	CHECK(__sh_params_replace(args, 3) == 0);
	unsetenv("SHT_ACC");
	CHECK(run("SHT_ACC=; for f; do SHT_ACC=\"$SHT_ACC-$f\"; done", &status) == 0);
	CHECK(status == 0);
	CHECK(getenv("SHT_ACC") && strcmp(getenv("SHT_ACC"), "-a-b-c") == 0);

	args[0] = (char *)"p q"; args[1] = (char *)"r";
	CHECK(__sh_params_replace(args, 2) == 0);
	unsetenv("SHT_ACC");
	CHECK(run("SHT_ACC=; for f; do SHT_ACC=\"$SHT_ACC[$f]\"; done", &status) == 0);
	CHECK(getenv("SHT_ACC") && strcmp(getenv("SHT_ACC"), "[p q][r]") == 0);

	/* No positional parameters: 2.9.4's "if no items result from the
	 * expansion, the compound-list shall not be executed", and "if
	 * there are no items, the exit status shall be zero". */
	CHECK(__sh_params_replace(args, 0) == 0);
	CHECK(run("for f; do exit 9; done", &status) == 0);
	CHECK(status == 0);
	CHECK(run("false; for f; do exit 9; done", &status) == 0);
	CHECK(status == 0);

	unsetenv("SHT_ACC");
	CHECK(__sh_params_replace(args, 0) == 0);
}


/* ---- stage 7b: shell functions (XCU 2.9.5) and $? (2.5.2) ------------
 *
 * Spec pages (https://pubs.opengroup.org/onlinepubs/9699919799/):
 *   utilities/V3_chap02.html 2.9.5 Function Definition Command
 *   utilities/V3_chap02.html 2.9.1 Command Search and Execution
 *   utilities/V3_chap02.html 2.5.2 Special Parameters ('?')
 *   utilities/V3_chap02.html 2.12 Shell Execution Environment
 *   utilities/return.html
 *
 * Several of these accumulate into an environment variable and assert
 * the accumulated *string* rather than an exit status.  That is not
 * ceremony: a function that ran the wrong number of times, or nested in
 * the wrong order, or saw the wrong positional parameters, still exits
 * 0 if its last command happened to succeed -- and an empty
 * compound-list exits 0 too, so "did nothing" and "did the right thing"
 * are the same status.  The accumulated string is the only thing that
 * tells them apart.
 */

/* Every program below is meant to be an independent one, the way each
 * `sh -c` invocation is a fresh process.  Variables already get that
 * treatment here by hand (the unsetenv() calls throughout this file);
 * functions need the same, because src/sh/func.c's table is
 * process-global and a `true()` defined by one assertion would
 * otherwise shadow the built-in for every assertion after it -- which
 * is exactly how three of these tests first failed. */
static void reset_functions(void)
{
	struct sh_funcs f;
	__sh_funcs_take(&f);
	__sh_funcs_free(&f);
}

/* 2.9.5's shape: "fname ( ) compound-command [io-redirect...]", with
 * the body kept as the raw source text src/sh/sh.h describes -- so the
 * AST assertion is about the exact substring captured, which is what a
 * later __sh_parse() of it depends on. */
static void test_funcdef_parse(void)
{
	reset_functions();
	struct sh_list *l;
	struct sh_command *c;

	l = must_parse("f() { :; }");
	if (l) {
		c = only_command(l);
		if (c) {
			CHECK(c->kind == SH_CMD_FUNCDEF);
			CHECK(c->u.funcdef.name && strcmp(c->u.funcdef.name, "f") == 0);
			CHECK(c->u.funcdef.func_text && strcmp(c->u.funcdef.func_text, "{ :; }") == 0);
		}
		__sh_list_free(l);
	}

	/* No space before '(' is the usual spelling and must lex the same:
	 * '(' is a lexer-level operator, so "f()" is three tokens. */
	l = must_parse("f ( ) ( : )");
	if (l) {
		c = only_command(l);
		if (c) {
			CHECK(c->kind == SH_CMD_FUNCDEF);
			CHECK(c->u.funcdef.func_text && strcmp(c->u.funcdef.func_text, "( : )") == 0);
		}
		__sh_list_free(l);
	}

	/* The captured extent stops at the token *after* the body, so a
	 * following command is not swallowed into it. */
	l = must_parse("f() { :; }; g() { :; }");
	if (l) {
		CHECK(l->items != 0);
		if (l->items) {
			struct sh_command *first = &l->items->andor->pipeline.commands[0];
			CHECK(first->kind == SH_CMD_FUNCDEF);
			CHECK(first->u.funcdef.func_text && strcmp(first->u.funcdef.func_text, "{ :; }") == 0);
			CHECK(l->items->next != 0);
		}
		__sh_list_free(l);
	}

	/* 2.9.5's grammar admits only a compound command as the body. */
	must_reject("f() echo hi");
	must_reject("f() ");
	must_reject("f( { :; }");
	/* The minimal input that separates "checks for ')'" from "skips a
	 * token and hopes": here the token after '(' is not ')', and a
	 * parser that did not check would land on a perfectly good body
	 * and accept the whole thing as `f() { :; }`.  2.9.5's grammar has
	 * the two parentheses adjacent. */
	must_reject("f(x { :; }");
	/* "the application shall ensure that ... it is not the name of a
	 * special built-in utility" -- and it has to be refused at parse
	 * time, because 2.9.1 runs special built-ins at step 1a and
	 * functions only at 1c, so an accepted definition could never be
	 * called. */
	must_reject("set() { :; }");
	must_reject("shift() { :; }");
	must_reject("return() { :; }");
	must_reject(":() { :; }");
	must_reject("exit() { :; }");
	/* A *regular* built-in is fine: 1c beats 1d. */
	{
		struct sh_list *ok = __sh_parse("cd() { :; }", 0, 0);
		CHECK(ok != 0);
		__sh_list_free(ok);
	}
}

/* 2.9.5: "The operands to the command temporarily shall become the
 * positional parameters during the execution of the compound-command;
 * the special parameter '#' also shall be changed to reflect the number
 * of operands.  The special parameter 0 shall be unchanged.  When the
 * function completes, the values of the positional parameters and the
 * special parameter '#' shall be restored to the values they had before
 * the function was executed." */
static void test_function_positional_parameters(void)
{
	reset_functions();
	int status;

	CHECK(__sh_param_set_zero("myshell") == 0);

	/* New parameters inside; the caller's restored after -- both
	 * halves, since a call that never installed any would satisfy the
	 * restore assertion alone. */
	CHECK(run("set -- x y z; f() { test \"$1\" = a && test \"$#\" = 2; }; f a b",
	          &status) == 0 && status == 0);
	CHECK(run("set -- x y z; f() { :; }; f a b; test \"$1\" = x && test \"$#\" = 3",
	          &status) == 0 && status == 0);
	/* A call with no operands makes $# zero inside, not "unchanged". */
	CHECK(run("set -- x y; f() { test \"$#\" = 0; }; f", &status) == 0 && status == 0);
	/* "The special parameter 0 shall be unchanged." */
	CHECK(run("f() { test \"$0\" = myshell; }; f a b", &status) == 0 && status == 0);

	/* Nesting restores each frame's own list, not the outermost one:
	 * the inner call must not leave the outer function looking at its
	 * arguments.  Asserted on the accumulated sequence so that the
	 * order of restoration is pinned, not just the final value. */
	unsetenv("SHT_FN");
	CHECK(run("SHT_FN=; inner() { SHT_FN=\"$SHT_FN[i:$1]\"; }; "
	          "outer() { SHT_FN=\"$SHT_FN[o:$1]\"; inner deep; "
	          "SHT_FN=\"$SHT_FN[o:$1]\"; }; outer top", &status) == 0);
	CHECK(getenv("SHT_FN") && strcmp(getenv("SHT_FN"), "[o:top][i:deep][o:top]") == 0);

	/* Recursion: each frame owns its own list all the way down and
	 * back.  `shift` inside the recursion is what makes the lists
	 * genuinely different per frame rather than three copies of one.
	 *
	 * The trace is "$1 on the way down" for each frame, then "$1 on
	 * the way back up" -- and the way-up value is *this frame's* $1
	 * after its own shift, not the value it was called with: a b c
	 * going down, then the empty $1 the innermost caller was left
	 * holding, then c, then b.  "abccb", not the "abccba" that reading
	 * the source too quickly suggests; VERIFIED against bash and dash,
	 * which both print exactly this.  It is the right assertion for
	 * the wrong-looking reason, so: an implementation that shared one
	 * parameter list between frames would print "abc" and then three
	 * empty strings, and one that restored the *caller's* list instead
	 * of this frame's would print "abc" then "cba". */
	unsetenv("SHT_FN");
	CHECK(run("SHT_FN=; r() { if test \"$#\" = 0; then return 0; fi; "
	          "SHT_FN=\"$SHT_FN$1\"; shift; r \"$@\"; SHT_FN=\"$SHT_FN$1\"; }; "
	          "r a b c", &status) == 0 && status == 0);
	CHECK(getenv("SHT_FN") && strcmp(getenv("SHT_FN"), "abccb") == 0);
	unsetenv("SHT_FN");

	/* "$@" inside a function is the function's arguments, including
	 * the zero-argument case that must forward nothing. */
	CHECK(run("f() { g \"$@\"; }; g() { test \"$#\" = 0; }; f", &status) == 0 && status == 0);
	CHECK(run("f() { g \"$@\"; }; g() { test \"$#\" = 2 && test \"$2\" = 'b c'; }; "
	          "f a 'b c'", &status) == 0 && status == 0);

	CHECK(__sh_params_replace(0, 0) == 0);
}

/* 2.9.5 Exit Status: "The exit status of a function definition shall be
 * zero ... The exit status of a function invocation shall be the exit
 * status of the last command executed by the function." */
static void test_function_exit_status(void)
{
	reset_functions();
	int status;

	CHECK(run("f() { :; }", &status) == 0 && status == 0);
	CHECK(run("false; f() { :; }; test \"$?\" = 0", &status) == 0 && status == 0);
	CHECK(run("f() { true; false; }; f", &status) == 0 && status == 1);
	CHECK(run("f() { false; true; }; f", &status) == 0 && status == 0);
	/* An empty body runs no command, so there is no "last command":
	 * zero, like any other empty compound-list. */
	CHECK(run("f() { :; }; f", &status) == 0 && status == 0);
	/* A function is an ordinary simple command in every other respect:
	 * it takes part in and-or lists and in `!`. */
	CHECK(run("f() { false; }; f || true", &status) == 0 && status == 0);
	CHECK(run("f() { false; }; ! f", &status) == 0 && status == 0);
}

/* return(1p): "The return utility shall cause the shell to stop
 * executing the current function ... The value of the special parameter
 * '?' shall be set to n ... or to the exit status of the last command
 * executed if n is not specified." */
static void test_builtin_return(void)
{
	reset_functions();
	int status;

	CHECK(run("f() { return 3; }; f", &status) == 0 && status == 3);
	/* It really *stops*: a command after the return must not run.  A
	 * status assertion alone cannot see this -- `return 3` and
	 * `return 3; false` both end at 3 only if the return worked, but a
	 * body whose trailing command sets the same status would hide it,
	 * so the side effect is asserted instead. */
	unsetenv("SHT_RET");
	CHECK(run("f() { return 3; SHT_RET=ran; }; f", &status) == 0 && status == 3);
	CHECK(getenv("SHT_RET") == 0);
	/* ... including out of a nested compound command. */
	CHECK(run("f() { if true; then return 4; fi; SHT_RET=ran; }; f",
	          &status) == 0 && status == 4);
	CHECK(getenv("SHT_RET") == 0);
	CHECK(run("f() { while true; do return 5; done; SHT_RET=ran; }; f",
	          &status) == 0 && status == 5);
	CHECK(getenv("SHT_RET") == 0);
	/* ... and out of an and-or list, which needs data chosen so the
	 * short-circuit would otherwise let the next term run: after
	 * `return 0` the status is 0, so "&&" *would* run the marker, and
	 * only the pending unwind stops it.  `return 1 || marker` is the
	 * mirror.  A test using "return 1 && marker" proves nothing --
	 * the short-circuit alone skips the marker there. */
	unsetenv("SHT_RET");
	CHECK(run("f() { return 0 && SHT_RET=ran; }; f", &status) == 0 && status == 0);
	CHECK(getenv("SHT_RET") == 0);
	CHECK(run("f() { return 1 || SHT_RET=ran; }; f", &status) == 0 && status == 1);
	CHECK(getenv("SHT_RET") == 0);

	/* ... and it must not keep unwinding past the call. */
	CHECK(run("f() { return 3; }; f; SHT_RET=after", &status) == 0);
	CHECK(getenv("SHT_RET") && strcmp(getenv("SHT_RET"), "after") == 0);
	unsetenv("SHT_RET");

	/* No operand: "the exit status of the last command executed". */
	CHECK(run("f() { false; return; }; f", &status) == 0 && status == 1);
	CHECK(run("f() { true; return; }; f", &status) == 0 && status == 0);

	/* Nested calls return one level, not all of them. */
	CHECK(run("g() { return 2; }; f() { g; return 7; }; f", &status) == 0 && status == 7);

	/* "an unsigned decimal integer": anything else is an error, not a
	 * salvaged number. */
	CHECK(run("f() { return x; }; f", &status) == 0 && status == 2);
	CHECK(run("f() { return -1; }; f", &status) == 0 && status == 2);
	CHECK(run("f() { return 1 2; }; f", &status) == 0 && status == 2);

	/* return(1p) leaves `return` outside a function unspecified; this
	 * shell diagnoses it with a nonzero status (2.14) rather than
	 * quietly exiting the whole shell, and -- the part that matters --
	 * does not unwind, so the rest of the program still runs. */
	unsetenv("SHT_RET");
	CHECK(run("return; SHT_RET=after", &status) == 0);
	CHECK(getenv("SHT_RET") && strcmp(getenv("SHT_RET"), "after") == 0);
	unsetenv("SHT_RET");

	/* `exit` inside a function is still the *shell* exiting, which is
	 * the one behavioural difference between the two unwinds. */
	CHECK(run("f() { exit 9; }; f; SHT_RET=after", &status) == 0 && status == 9);
	CHECK(getenv("SHT_RET") == 0);

	/* A subshell consumes either unwind, so "( return 3 )" leaves the
	 * function running -- exactly as "( exit 3 )" does. */
	CHECK(run("f() { ( return 3 ); return 6; }; f", &status) == 0 && status == 6);
	unsetenv("SHT_RET");
}

/* 2.9.1 "Command Search and Execution": step 1a special built-in, step
 * 1c function, step 1d the regular built-ins of its own table, step 1e
 * PATH.  So the answer is not "built-ins win" or "functions win": it
 * depends on which kind of built-in, and getting it backwards makes
 * exactly one of these two assertions fail. */
static void test_function_search_order(void)
{
	reset_functions();
	int status;

	/* `test` is not in 1d's table at all -- it is an ordinary utility
	 * this shell happens to provide -- so a function shadows it.
	 * `test 1 -eq 2` is false; if the function ran, the status is 0. */
	CHECK(run("test 1 -eq 2", &status) == 0 && status == 1);   /* the built-in */
	CHECK(run("test() { return 0; }; test 1 -eq 2", &status) == 0 && status == 0);
	reset_functions();   /* ... and it really was the definition that
	                      * changed the answer, not the assertion order:
	                      * with the definition dropped, the built-in is
	                      * back. */
	CHECK(run("test 1 -eq 2", &status) == 0 && status == 1);
	/* `true` and `false` ARE in 1d's table, and 1c still beats 1d. */
	CHECK(run("true", &status) == 0 && status == 0);
	CHECK(run("true() { return 5; }; true", &status) == 0 && status == 5);
	reset_functions();
	CHECK(run("false", &status) == 0 && status == 1);
	CHECK(run("false() { return 0; }; false", &status) == 0 && status == 0);
	reset_functions();
	/* A special built-in (1a) is *not* shadowed.  2.9.5 forbids writing
	 * such a definition and src/sh/parse.c refuses it (pinned by
	 * test_funcdef_parse() above), so the only way to ask the
	 * *executor* this question is to install one behind the parser's
	 * back -- which is exactly why it is worth asking.  The two guards
	 * are independent: a suite that only tested the parser's would
	 * pass with the executor's step-1a-before-step-1c ordering
	 * removed, because nothing could ever reach it. */
	CHECK(run("f() { :; }; :", &status) == 0 && status == 0);
	CHECK(__sh_func_define(":", "{ return 9; }") == 0);
	CHECK(run(":", &status) == 0 && status == 0);          /* the built-in, not 9 */
	CHECK(__sh_func_define("exit", "{ return 9; }") == 0);
	CHECK(run("exit 4", &status) == 0 && status == 4);     /* the built-in, not 9 */
	reset_functions();
}

/* 2.9.5: "When the function is declared, none of the expansions in
 * wordexp shall be performed on the text in compound-command or
 * io-redirect; all expansions shall be performed as normal each time
 * the function is called." */
static void test_function_body_expanded_at_call_time(void)
{
	reset_functions();
	int status;

	unsetenv("SHT_FX");
	CHECK(run("SHT_FX=one; f() { test \"$SHT_FX\" = two; }; SHT_FX=two; f",
	          &status) == 0 && status == 0);
	/* Two calls, different values, same definition. */
	unsetenv("SHT_FN");
	CHECK(run("SHT_FN=; f() { SHT_FN=\"$SHT_FN[$SHT_FX]\"; }; "
	          "SHT_FX=a; f; SHT_FX=b; f", &status) == 0);
	CHECK(getenv("SHT_FN") && strcmp(getenv("SHT_FN"), "[a][b]") == 0);
	unsetenv("SHT_FN");
	unsetenv("SHT_FX");

	/* Redefinition replaces. */
	CHECK(run("f() { return 1; }; f() { return 2; }; f", &status) == 0 && status == 2);
}

/* 2.12: a subshell environment's changes "shall not affect the shell
 * execution environment" -- a function defined in one does not survive
 * it, and one defined outside is still visible inside. */
static void test_functions_are_subshell_scoped(void)
{
	reset_functions();
	int status;

	CHECK(run("( f() { return 3; } ); f", &status) == 0 && status == 127);
	CHECK(run("f() { return 3; }; ( f )", &status) == 0 && status == 3);
	/* Redefining inside a subshell does not leak out either. */
	CHECK(run("f() { return 3; }; ( f() { return 4; }; f ); f",
	          &status) == 0 && status == 3);
	/* A brace group runs "in the current process environment" (2.9.4),
	 * so it is not scoped. */
	CHECK(run("{ f() { return 3; } ; }; f", &status) == 0 && status == 3);
}

/* 2.9.5's body may be any compound command, and 2.9.4's "each can be
 * followed by redirections" carries into the definition's
 * [io-redirect...]. */
static void test_function_body_forms(const char *self)
{
	reset_functions();
	int status;

	CHECK(run("f() ( return 3 ); f", &status) == 0 && status == 3);
	CHECK(run("f() { return 3; }; f", &status) == 0 && status == 3);
	CHECK(run("f() if true; then return 3; fi; f", &status) == 0 && status == 3);
	CHECK(run("f() while true; do return 3; done; f", &status) == 0 && status == 3);
	CHECK(run("f() for i in a; do return 3; done; f", &status) == 0 && status == 3);
	/* `for` with no `in` inside a function iterates the *function's*
	 * arguments, which is 2.9.4's "in \"$@\"" meeting 2.9.5's "the
	 * operands ... temporarily shall become the positional
	 * parameters". */
	unsetenv("SHT_FN");
	CHECK(run("SHT_FN=; f() { for i; do SHT_FN=\"$SHT_FN[$i]\"; done; }; f p q",
	          &status) == 0);
	CHECK(getenv("SHT_FN") && strcmp(getenv("SHT_FN"), "[p][q]") == 0);
	unsetenv("SHT_FN");

	/* A here-document inside a function body: the captured extent has
	 * to reach past the body lines the lexer drained, which is the one
	 * way the source-text capture could be subtly short. */
	if (file_redir_supported(self)) {
		char src[768], *tmp = make_tmp(), *got;
		if (tmp) {
			snprintf(src, sizeof src,
				"f() { '%s' --cat > %s <<EOF\nbody $1\nEOF\n}\nf ARG", self, tmp);
			CHECK(run(src, &status) == 0 && status == 0);
			got = slurp(tmp);
			CHECK(got != 0);
			if (got) {
				if (strcmp(got, "body ARG\n") != 0) {
					fails++;
					printf("FAIL heredoc in function: got \"%s\"\n", got);
				}
				free(got);
			}
			remove(tmp);
			free(tmp);
		}
	}
}

/* 2.5.2 '?': "Expands to the decimal exit status of the most recent
 * pipeline." */
static void test_dollar_question(void)
{
	reset_functions();
	int status;

	CHECK(run("true; test \"$?\" = 0", &status) == 0 && status == 0);
	CHECK(run("false; test \"$?\" = 1", &status) == 0 && status == 0);
	CHECK(run("false; test \"${?}\" = 1", &status) == 0 && status == 0);
	/* "the most recent pipeline", so a pipeline's status is the last
	 * stage's -- and a `!` negation is part of the pipeline. */
	CHECK(run("! true; test \"$?\" = 1", &status) == 0 && status == 0);
	/* A command not found is 127 and $? can see it. */
	CHECK(run("no-such-utility-xyzzy; test \"$?\" = 127", &status) == 0 && status == 0);
	/* A function invocation is a command like any other. */
	CHECK(run("f() { return 4; }; f; test \"$?\" = 4", &status) == 0 && status == 0);
	/* $? and command substitution.  The status of a command containing
	 * one still reaches $? through 2.9.1's "no command name, but the
	 * command contained a command substitution" rule -- this is the
	 * case a `configure` writes constantly. */
	CHECK(run("x=$(false); test \"$?\" = 1", &status) == 0 && status == 0);
	CHECK(run("x=$(true); test \"$?\" = 0", &status) == 0 && status == 0);

	/* Whether a substitution's *own* commands change $? for the rest
	 * of the same command is NOT settled by the standard, and the
	 * shells disagree: XCU 2.12 lists what a shell execution
	 * environment consists of and $? is not on that list, so "changes
	 * made to the subshell environment shall not affect the shell
	 * environment" does not reach it.  VERIFIED on this machine:
	 * `false; x="$(true)$?"` gives 1 under dash and busybox ash, and 0
	 * under bash.  This shell restores, i.e. takes the dash reading,
	 * because it makes $? mean "the status of the last command this
	 * shell completed" with no exception carved out for the middle of
	 * a word.  The assertion below exists to pin that choice, not to
	 * claim the standard requires it.
	 *
	 * Note the data: `false; x=$(true); ...` cannot see this at all,
	 * because the substitution's status and the caller's $? are both
	 * 0.  They have to differ on the axis being tested. */
	CHECK(run("false; x=\"$(true)$?\"; test \"$x\" = 1", &status) == 0 && status == 0);
	CHECK(run("true; x=\"$(false)$?\"; test \"$x\" = 0", &status) == 0 && status == 0);
	CHECK(run("false; :; test \"$?\" = 0", &status) == 0 && status == 0);
	/* ${#NAME} is a different expansion and stays unimplemented, so it
	 * must not be confused with ${?} or ${#}. */
	CHECK(run("test \"${?x}\" = '${?x}'", &status) == 0 && status == 0);
}

int main(int argc, char **argv)
{
	if (argc > 1) { int r = child_role(argc, argv); if (r >= 0) return r; }

	test_simple_command_words();
	test_assignment_prefix();
	test_assignment_only_command();

	test_quoting_suppresses_operators();
	test_dollar_paren_and_brace_word_boundary();
	test_backtick_word_boundary();
	test_comment();
	test_empty_and_comment_only();

	test_pipeline();
	test_pipeline_bang();

	test_andor();
	test_list_separators();

	test_subshell();
	test_brace_group();
	test_subshell_nested_and_redirected();

	test_redirections();
	test_ionum_overflow();

	test_heredoc_basic();
	test_heredoc_dash_strips_tabs();
	test_heredoc_quoted_delimiter();
	test_heredoc_two_on_one_line();

	test_rejects_malformed();
	test_group_redir_leak();

	test_roundtrip();
	test_funcdef_heredoc_before_list_operator();
	test_funcdef_heredoc_at_end_of_line_roundtrip();

	test_exec_simple_command_status(argv[0]);
	test_exec_command_not_found();
	test_exec_bang_negation(argv[0]);
	test_exec_andor_short_circuit(argv[0]);
	test_exec_assignment_only_affects_shell_env();
	test_exec_assignment_prefix_does_not_leak(argv[0]);
	test_exec_reuses_wordexp_param_expansion(argv[0]);
	test_exec_reports_unimplemented_constructs(argv[0]);

	test_exec_redir_output_creates_and_truncates(argv[0]);
	test_exec_redir_append(argv[0]);
	test_exec_redir_clobber_like_great(argv[0]);
	test_exec_redir_input(argv[0]);
	test_exec_redir_lessgreat_no_truncate(argv[0]);
	test_exec_redir_order_last_wins(argv[0]);
	test_exec_redir_dup_output_ordering(argv[0]);
	test_exec_redir_close(argv[0]);
	test_exec_redir_dup_closed_fd_fails(argv[0]);
	test_exec_redir_open_failure_nonabort(argv[0]);

	test_exec_heredoc_basic(argv[0]);
	test_exec_heredoc_dash_strips_tabs(argv[0]);
	test_exec_heredoc_unquoted_expands(argv[0]);
	test_exec_heredoc_quoted_delimiter_no_expansion(argv[0]);

	test_exec_pipeline_two_stage(argv[0]);
	test_exec_pipeline_three_stage(argv[0]);
	test_exec_pipeline_status_is_last(argv[0]);
	test_exec_pipeline_bang(argv[0]);
	test_exec_pipeline_stage_redir_overrides_pipe(argv[0]);

	test_exec_brace_persists_assignment_and_cd();
	test_exec_subshell_does_not_persist_assignment_and_cd();
	test_exec_group_exit_status(argv[0]);
	test_exec_group_bang_and_status_propagation(argv[0]);
	test_exec_group_redir_whole(argv[0]);
	test_exec_group_nesting(argv[0]);
	test_exec_group_pipeline_stage(argv[0]);

	test_exec_cmdsub_basic(argv[0]);
	test_exec_cmdsub_field_splitting(argv[0]);
	test_exec_cmdsub_pathname_expansion(argv[0]);
	test_exec_cmdsub_result_not_reexpanded(argv[0]);
	test_exec_cmdsub_nesting(argv[0]);
	test_exec_cmdsub_backquote_backslash(argv[0]);
	test_exec_cmdsub_in_double_quotes(argv[0]);
	test_exec_cmdsub_exit_status(argv[0]);
	test_exec_cmdsub_subshell_environment(argv[0]);
	test_exec_cmdsub_in_redirections(argv[0]);
	test_exec_cmdsub_propagates_unimplemented(argv[0]);

	test_builtin_dispatch_uses_expanded_name();
	test_builtin_colon_true_false();
	test_builtin_exit(argv[0]);
	test_builtin_test_argc_rules();
	test_builtin_test_file_primaries();
	test_builtin_test_binary_primaries();
	test_builtin_test_grammar();
	test_builtin_bracket();
	test_builtin_in_compound_contexts(argv[0]);

	test_if_branches(argv[0]);
	test_if_status_when_nothing_ran();
	test_while_until();
	test_for_loop(argv[0]);
	test_compound_redirection(argv[0]);
	test_compound_runs_in_current_environment();
	test_exit_unwinds_compound(argv[0]);
	test_compound_as_pipeline_stage(argv[0]);
	test_for_without_in_iterates_positional_parameters();

	test_positional_single_and_multi_digit();
	test_positional_count_and_zero();
	test_at_and_star_fields(argv[0]);
	test_brace_form_disambiguation();
	test_empty_field_deletion(argv[0]);
	test_builtin_set(argv[0]);
	test_builtin_export(argv[0]);
	test_builtin_readonly(argv[0]);
	test_builtin_shift();
	test_params_are_subshell_scoped();
	test_params_are_not_environment_variables();

	test_funcdef_parse();
	test_function_positional_parameters();
	test_function_exit_status();
	test_builtin_return();
	test_function_search_order();
	test_function_body_expanded_at_call_time();
	test_functions_are_subshell_scoped();
	test_function_body_forms(argv[0]);
	test_dollar_question();

	if (fails) { printf("sh: failures: %d\n", fails); return 1; }
	printf("sh: all ok (stage 6b: lexer + parser + execution of simple commands, redirections, pipelines, subshells and brace groups, command substitution, the built-in dispatcher with test/[/:/true/false/exit/cd, and the if/while/until/for compound commands)\n");
	return 0;
}
