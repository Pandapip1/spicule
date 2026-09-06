/* SPDX-FileCopyrightText: (C) 2026 Gavin John */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "../../include/ownership.h"

typedef void (*handler_t)(int);
async_signal_safe
handler_t signal(int, handler_t);
void *malloc(unsigned long);

static int observed;

static void unsafe_handler(int number) {
  observed = number; /* signal-safety-expect */
  malloc(16); /* signal-safety-expect */
}

void install_unsafe(void) { signal(1, unsafe_handler); }
