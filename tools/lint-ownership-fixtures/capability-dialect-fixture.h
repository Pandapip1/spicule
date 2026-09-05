/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#include "../../include/ownership.h"

typedef __SIZE_TYPE__ size_t;

tokdef dialect_mutex_unlocked;
tokdef dialect_mutex_locked l_unlimited;
tokdef dialect_terminated l_unlimited implicit_drop string_literal;
tokdef dialect_span l_unlimited implicit_drop;
tokdef dialect_disjoint l_unlimited implicit_drop;

typedef struct { void *opaque[8]; } dialect_mutex_t;

void dialect_mutex_init(dialect_mutex_t *mutex
	construct(dialect_mutex) grant(dialect_mutex_unlocked));
void dialect_mutex_lock(dialect_mutex_t *mutex
	handle(dialect_mutex) consume(dialect_mutex_unlocked)
	grant(dialect_mutex_locked));
void dialect_mutex_share_unlock(dialect_mutex_t *mutex
	handle(dialect_mutex) withtok(dialect_mutex_locked)
	grant(dialect_mutex_locked));
void dialect_mutex_unlock(dialect_mutex_t *mutex
	handle(dialect_mutex) consume(dialect_mutex_locked)
	grant(dialect_mutex_unlocked));
void dialect_mutex_destroy(dialect_mutex_t *mutex
	destroy(dialect_mutex) consume(dialect_mutex_unlocked));
void dialect_mark_terminated(char *text grant(dialect_terminated));
void dialect_invalidate_string(char *text drop(dialect_terminated));
void dialect_use_string(const char *text withtok(dialect_terminated));
void dialect_use_string_vector(
	int count,
	char **values elements_withtok(dialect_terminated, count))
	__attribute__((nonnull(2)));
/* Same shape as dialect_use_string_vector, but the extent parameter is a
 * genuinely distinct 64-bit type from int/long -- "unsigned long long"
 * is never the same canonical type as "unsigned long" even though both
 * are 64 bits wide on this target, the same way this project's own
 * size_t (`unsigned _Addr`, with _Addr = "long long" on aarch64/x86_64;
 * see arch/*'s bits/alltypes.h.gen) is. Exercises
 * AggregateElementTokenChecker's extent/index type compatibility check
 * against a real, same-width-but-different-type pairing. */
void dialect_use_wide_vector(
	unsigned long long count,
	char **values elements_withtok(dialect_terminated, count))
	__attribute__((nonnull(2)));
void dialect_clear_string(char *text drop(dialect_terminated));
void dialect_bad_clear_string(char *text drop(dialect_terminated));
char *dialect_copy_string(char *text grant(dialect_terminated));
void dialect_mark_span(void *data grant(dialect_span(length)), size_t length);
void dialect_use_span(const void *data withtok(dialect_span(length)),
	size_t length);
void dialect_invalidate_span(void *data drop(dialect_span(length)),
	size_t length);
void dialect_clear_span(void *data drop(dialect_span(length)), size_t length);
void dialect_bad_clear_span(void *data drop(dialect_span(length)),
	size_t length);
void dialect_mark_disjoint(
	void *left grant(dialect_disjoint(right, length)), const void *right,
	size_t length);
void dialect_use_disjoint(
	const void *left withtok(dialect_disjoint(right, length)),
	const void *right, size_t length);
