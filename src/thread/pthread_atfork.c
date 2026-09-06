/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include "pthread_impl.h"
#include "plat_thread.h"

struct atfork_handler {
	void (*prepare)(void);
	void (*parent)(void);
	void (*child)(void);
};

static struct atfork_handler *handlers;
static size_t handler_count;
static size_t handler_capacity;
static __thread size_t active_count;

int pthread_atfork(void (*prepare)(void), void (*parent)(void), // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
	void (*child)(void))
{
	struct atfork_handler *new_handlers;
	size_t capacity;
	__plat_fast_lock();
	if (handler_count == handler_capacity) {
		if (!__array_next_capacity(handler_capacity, handler_count, 1, 8,
		    sizeof *handlers, &capacity)) {
			__plat_fast_unlock();
			return ENOMEM;
		}
		{
			size_t bytes = capacity * sizeof *handlers; /* proven <= SIZE_MAX by __array_next_capacity's own element_size bound above */
			new_handlers = realloc(handlers, bytes);
		}
		if (!new_handlers) {
			__plat_fast_unlock();
			return ENOMEM;
		}
		handlers = new_handlers;
		handler_capacity = capacity;
	}
	handlers[handler_count].prepare = prepare;
	handlers[handler_count].parent = parent;
	handlers[handler_count].child = child;
	handler_count++;
	__plat_fast_unlock();
	return 0;
}

void __pthread_atfork_prepare(void)
{
	size_t i;
	__plat_fast_lock();
	active_count = handler_count;
	__plat_fast_unlock();
	for (i = active_count; i; i--)
		if (handlers[i - 1].prepare) handlers[i - 1].prepare();
}

void __pthread_atfork_parent(void)
{
	size_t i, count = active_count;
	active_count = 0;
	for (i = 0; i < count; i++)
		if (handlers[i].parent) handlers[i].parent();
}

void __pthread_atfork_child(void)
{
	size_t i, count = active_count;
	active_count = 0;
	for (i = 0; i < count; i++)
		if (handlers[i].child) handlers[i].child();
}

// NOLINTEND(misc-include-cleaner)
