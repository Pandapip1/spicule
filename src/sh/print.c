/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Canonical reprint of the AST sh.h declares. Exists so the parser is
 * testable on its own, via parse-and-print -- test/sh-engine.c
 * round-trips parse() -> print() -> parse() -> print() and checks the
 * second print is a fixed point, which exercises every AST field
 * without needing a second, hand-written AST-equality walk.
 *
 * Separators are canonicalised: every list item ends with a real
 * newline (a bare newline is exactly as valid a separator as ';' --
 * XCU Grammar's `separator`), which is also what lets a here-document
 * body be reprinted immediately after it, mirroring how parse.c's
 * lexer drains pending here-documents on the newline that ends the
 * line containing '<<'/'<<-'.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include "libc.h"
#include "sh.h"
#include "ownership_stubs.h"

struct hdq {
	const struct sh_redir *r;
	struct hdq *next withtok(internal_heap_allocated);
};

struct pctx {
	FILE *f;
	struct hdq *head withtok(internal_heap_allocated), *tail;
	int failed;
};

static void emit_char(struct pctx *c, int ch)
{
	if (!c->failed && fputc(ch, c->f) == EOF) c->failed = 1;
}

static void emit_string(struct pctx *c, const char *s)
{
	if (!c->failed && fputs(s, c->f) < 0) c->failed = 1;
}

static void emit_fd(struct pctx *c, int fd)
{
	if (!c->failed && fprintf(c->f, "%d", fd) < 0) c->failed = 1;
}

static void queue_heredoc(struct pctx *c, const struct sh_redir *r) __attribute__((nonnull(1)));
static void queue_heredoc(struct pctx *c, const struct sh_redir *r)
{
	struct hdq *n = __malloc(sizeof *n);
	if (!n) { c->failed = 1; return; }
	n->r = r;
	n->next = 0;
	if (c->tail) c->tail->next = n; else c->head = n;
	c->tail = n;
}

static void queue_nested_heredocs_list(struct pctx *, const struct sh_list *);

/* Function definitions are printed from func_text, but parse.c may retain
 * their body AST when a here-document was still pending at the definition's
 * end. Walk that retained tree in source order so the bodies are emitted
 * after the definition's terminating newline like any other queued heredoc. */
// NOLINTNEXTLINE(misc-no-recursion) -- formatting and heredoc traversal mirror the nested shell-AST hierarchy
static void queue_nested_heredocs_command(struct pctx *c,
		const struct sh_command *cmd) __attribute__((nonnull(2)));
// NOLINTNEXTLINE(misc-no-recursion) -- formatting and heredoc traversal mirror the nested shell-AST hierarchy
static void queue_nested_heredocs_command(struct pctx *c,
		const struct sh_command *cmd)
{
	const struct sh_ifarm *arm;
	const struct sh_redir *r;

	switch (cmd->kind) {
	case SH_CMD_SUBSHELL:
	case SH_CMD_BRACE:
		queue_nested_heredocs_list(c, cmd->u.group.body);
		break;
	case SH_CMD_IF:
		for (arm = cmd->u.ifcmd.arms; arm; arm = arm->next) {
			queue_nested_heredocs_list(c, arm->cond);
			queue_nested_heredocs_list(c, arm->body);
		}
		queue_nested_heredocs_list(c, cmd->u.ifcmd.else_body);
		break;
	case SH_CMD_LOOP:
		queue_nested_heredocs_list(c, cmd->u.loop.cond);
		queue_nested_heredocs_list(c, cmd->u.loop.body);
		break;
	case SH_CMD_FOR:
		queue_nested_heredocs_list(c, cmd->u.forloop.body);
		break;
	case SH_CMD_FUNCDEF:
		if (cmd->u.funcdef.func_body)
			queue_nested_heredocs_command(c, cmd->u.funcdef.func_body);
		break;
	default:
		break;
	}
	for (r = cmd->redirs; r; r = r->next)
		if (r->op == SH_R_DLESS || r->op == SH_R_DLESSDASH)
			queue_heredoc(c, r);
}

/* list is genuinely optional: a compound command's optional part (e.g.
 * an `if` with no `else`) is absent as NULL here. */
// NOLINTNEXTLINE(misc-no-recursion) -- formatting and heredoc traversal mirror the nested shell-AST hierarchy
static void queue_nested_heredocs_list(struct pctx *c,
		const struct sh_list *list)
{
	const struct sh_list_item *item;
	const struct sh_andor *andor;
	size_t i;

	if (!list) return;
	for (item = list->items; item; item = item->next)
		for (andor = item->andor; andor; andor = andor->next)
			for (i = 0; i < andor->pipeline.ncommands; i++)
				queue_nested_heredocs_command(c,
				    &andor->pipeline.commands[i]);
}

static void drain_heredocs(struct pctx *c) __attribute__((nonnull(1)));
static void drain_heredocs(struct pctx *c)
{
	struct hdq *h = c->head;
	c->head = c->tail = 0;
	while (h) {
		struct hdq *n = h->next;
		if (h->r->heredoc) emit_string(c, h->r->heredoc);
		emit_string(c, h->r->heredoc_delim ? h->r->heredoc_delim : h->r->word);
		emit_char(c, '\n');
		__free(h);
		h = n;
	}
}

static void print_redir(struct pctx *c, const struct sh_redir *r)
    __attribute__((nonnull(1, 2)));
static void print_redir(struct pctx *c, const struct sh_redir *r)
{
	static const char *const opstr[] = {
		"<", ">", ">>", "<&", ">&", "<>", ">|", "<<", "<<-"
	};
	emit_char(c, ' ');
	if (r->fd >= 0) emit_fd(c, r->fd);
	emit_string(c, opstr[r->op]);
	emit_char(c, ' ');
	emit_string(c, r->word);
	if (r->op == SH_R_DLESS || r->op == SH_R_DLESSDASH) queue_heredoc(c, r);
}

static void print_redirs(struct pctx *c, const struct sh_redir *r)
{
	for (; r; r = r->next) print_redir(c, r);
}

/* w may be NULL: an assignment-only simple command has no words. */
static void print_words(struct pctx *c, const struct sh_word *w, int leading_space)
    __attribute__((nonnull(1)));
static void print_words(struct pctx *c, const struct sh_word *w, int leading_space)
{
	for (; w; w = w->next) {
		if (leading_space) emit_char(c, ' ');
		leading_space = 1;
		/* w->text is always the raw source text of a scanned WORD (see
		 * sh.h's struct sh_word comment) -- scan_word() null-terminates
		 * it before any sh_word is ever built, but that fact does not
		 * survive the struct field the checker cannot trace back to
		 * scan_word()'s own separately analyzed body, the same reason
		 * parse.c restates it on p->cur.text. */
		__ownership_string_terminated(w->text);
		if (!strcmp(w->text, "!")) emit_string(c, "'!'");
		else emit_string(c, w->text);
	}
}

static void print_list(struct pctx *c, const struct sh_list *list);

// NOLINTNEXTLINE(misc-no-recursion) -- formatting and heredoc traversal mirror the nested shell-AST hierarchy
static void print_command(struct pctx *c, const struct sh_command *cmd)
    __attribute__((nonnull(1, 2)));
// NOLINTNEXTLINE(misc-no-recursion) -- formatting and heredoc traversal mirror the nested shell-AST hierarchy
static void print_command(struct pctx *c, const struct sh_command *cmd)
{
	switch (cmd->kind) {
	case SH_CMD_SUBSHELL:
		emit_char(c, '(');
		print_list(c, cmd->u.group.body);
		emit_char(c, ')');
		break;
	case SH_CMD_BRACE:
		emit_string(c, "{ ");
		print_list(c, cmd->u.group.body);
		emit_string(c, "}");
		break;
	/* Compound commands are reprinted with a real <newline> before each
	 * terminator reserved word rather than "; ": parse.c only recognizes
	 * a reserved word in command position, so "cmd; fi" would reparse `fi`
	 * as an argument and break the round-trip. */
	case SH_CMD_IF: {
		const struct sh_ifarm *a;
		for (a = cmd->u.ifcmd.arms; a; a = a->next) {
			emit_string(c, a == cmd->u.ifcmd.arms ? "if " : "elif ");
			print_list(c, a->cond);
			emit_string(c, "then\n");
			print_list(c, a->body);
		}
		if (cmd->u.ifcmd.else_body) {
			emit_string(c, "else\n");
			print_list(c, cmd->u.ifcmd.else_body);
		}
		emit_string(c, "fi");
		break;
	}
	case SH_CMD_LOOP:
		emit_string(c, cmd->u.loop.until ? "until " : "while ");
		print_list(c, cmd->u.loop.cond);
		emit_string(c, "do\n");
		print_list(c, cmd->u.loop.body);
		emit_string(c, "done");
		break;
	case SH_CMD_FOR:
		emit_string(c, "for ");
		emit_string(c, cmd->u.forloop.name);
		if (cmd->u.forloop.have_in) {
			emit_string(c, " in");
			print_words(c, cmd->u.forloop.words, 1);
		}
		emit_string(c, "\ndo\n");
		print_list(c, cmd->u.forloop.body);
		emit_string(c, "done");
		break;
	/* Reprinted from func_text, the raw source the parser captured, not
	 * re-derived from the AST: re-parsing it yields the identical
	 * substring, making the round-trip a fixed point. */
	case SH_CMD_FUNCDEF:
		emit_string(c, cmd->u.funcdef.name);
		emit_string(c, "() ");
		emit_string(c, cmd->u.funcdef.func_text);
		if (cmd->u.funcdef.func_body)
			queue_nested_heredocs_command(c, cmd->u.funcdef.func_body);
		break;
	default:
		print_words(c, cmd->u.simple.assigns, 0);
		print_words(c, cmd->u.simple.words, cmd->u.simple.assigns != 0);
		break;
	}
	print_redirs(c, cmd->redirs);
}

// NOLINTNEXTLINE(misc-no-recursion) -- formatting and heredoc traversal mirror the nested shell-AST hierarchy
static void print_pipeline(struct pctx *c, const struct sh_pipeline *pl)
    __attribute__((nonnull(1, 2)));
// NOLINTNEXTLINE(misc-no-recursion) -- formatting and heredoc traversal mirror the nested shell-AST hierarchy
static void print_pipeline(struct pctx *c, const struct sh_pipeline *pl)
{
	size_t i;
	if (pl->bang) emit_string(c, "! ");
	for (i = 0; i < pl->ncommands; i++) {
		if (i) emit_string(c, " | ");
		print_command(c, &pl->commands[i]);
	}
}

// NOLINTNEXTLINE(misc-no-recursion) -- formatting and heredoc traversal mirror the nested shell-AST hierarchy
static void print_andor(struct pctx *c, const struct sh_andor *a)
{
	for (; a; a = a->next) {
		if (a->op == SH_AO_AND) emit_string(c, " && ");
		else if (a->op == SH_AO_OR) emit_string(c, " || ");
		print_pipeline(c, &a->pipeline);
	}
}

// NOLINTNEXTLINE(misc-no-recursion) -- formatting and heredoc traversal mirror the nested shell-AST hierarchy
static void print_list(struct pctx *c, const struct sh_list *list)
{
	const struct sh_list_item *it;
	if (!list) return;
	for (it = list->items; it; it = it->next) {
		print_andor(c, it->andor);
		if (it->sep == SH_SEP_AMP) emit_string(c, " &");
		emit_char(c, '\n');
		drain_heredocs(c);
	}
}

int __sh_print_list(FILE *f, const struct sh_list *list)
{
	struct pctx c;
	c.f = f;
	c.head = c.tail = 0;
	c.failed = 0;
	print_list(&c, list);
	return c.failed ? -1 : 0;
}

// NOLINTEND(misc-include-cleaner)
