/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Freeing the AST sh.h declares. parse.c's error-recovery paths reuse
 * these per-node-kind helpers directly instead of duplicating them.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include "libc.h"
#include "sh.h"

void __sh_free_words(struct sh_word *w)
{
	while (w) {
		struct sh_word *n = w->next;
		__free(w->text);
		__free(w);
		w = n;
	}
}

void __sh_free_redirs(struct sh_redir *r)
{
	while (r) {
		struct sh_redir *n = r->next;
		__free(r->word);
		__free(r->heredoc);
		__free(r->heredoc_delim);
		__free(r);
		r = n;
	}
}

/* `if` and `elif` arms share the same node type, so this one chain covers both. */
// NOLINTNEXTLINE(misc-no-recursion) -- the destructor mirrors the owned shell-AST hierarchy
static void free_ifarms(struct sh_ifarm *a)
{
	while (a) {
		struct sh_ifarm *n = a->next;
		__sh_list_free(a->cond);
		__sh_list_free(a->body);
		__free(a);
		a = n;
	}
}

/* Must switch on c->kind rather than freeing every field unconditionally:
 * only the active union variant's pointers are meaningful. new_command()
 * zeroes the whole union, and parse.c always sets kind before writing any
 * field of a new variant, so this is safe even on a node abandoned mid-parse.
 * Unlike its free_*() siblings, c is required: this frees a command's
 * contents, not a list node, so there's no "NULL means empty" convention. */
// NOLINTNEXTLINE(misc-no-recursion) -- the destructor mirrors the owned shell-AST hierarchy
void __sh_free_command_contents(struct sh_command *c)
{
	__sh_free_redirs(c->redirs);
	switch (c->kind) {
	case SH_CMD_SIMPLE:
		__sh_free_words(c->u.simple.assigns);
		__sh_free_words(c->u.simple.words);
		break;
	case SH_CMD_SUBSHELL:
	case SH_CMD_BRACE:
		__sh_list_free(c->u.group.body);
		break;
	case SH_CMD_IF:
		free_ifarms(c->u.ifcmd.arms);
		__sh_list_free(c->u.ifcmd.else_body);
		break;
	case SH_CMD_LOOP:
		__sh_list_free(c->u.loop.cond);
		__sh_list_free(c->u.loop.body);
		break;
	case SH_CMD_FOR:
		__free(c->u.forloop.name);
		__sh_free_words(c->u.forloop.words);
		__sh_list_free(c->u.forloop.body);
		break;
	case SH_CMD_FUNCDEF:
		__free(c->u.funcdef.name);
		__free(c->u.funcdef.func_text);
		/* func_body is a bare sh_command, not a list, so no __sh_list_free(). */
		if (c->u.funcdef.func_body) {
			__sh_free_command_contents(c->u.funcdef.func_body);
			__free(c->u.funcdef.func_body);
		}
		break;
	}
}

static void free_pipeline_contents(struct sh_pipeline *pl) __attribute__((nonnull(1)));
// NOLINTNEXTLINE(misc-no-recursion) -- the destructor mirrors the owned shell-AST hierarchy
static void free_pipeline_contents(struct sh_pipeline *pl)
{
	size_t i;
	for (i = 0; i < pl->ncommands; i++) __sh_free_command_contents(&pl->commands[i]);
	__free(pl->commands);
}

// NOLINTNEXTLINE(misc-no-recursion) -- the destructor mirrors the owned shell-AST hierarchy
static void free_andor(struct sh_andor *a)
{
	while (a) {
		struct sh_andor *n = a->next;
		free_pipeline_contents(&a->pipeline);
		__free(a);
		a = n;
	}
}

// NOLINTNEXTLINE(misc-no-recursion) -- the destructor mirrors the owned shell-AST hierarchy
void __sh_list_free(struct sh_list *list)
{
	struct sh_list_item *it;
	if (!list) return;
	it = list->items;
	while (it) {
		struct sh_list_item *n = it->next;
		free_andor(it->andor);
		__free(it);
		it = n;
	}
	__free(list);
}

// NOLINTEND(misc-include-cleaner)
