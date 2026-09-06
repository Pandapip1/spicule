/* SPDX-FileCopyrightText: (C) 2026 Gavin John */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "../../include/ownership.h"

fallible
int close(int);
fallible
long read(int, void *, unsigned long);

int propagated_close(int fd) { return close(fd); }

int checked_close(int fd) {
  if (close(fd) < 0)
    return -1;
  return 0;
}

void deliberately_discarded_close(int fd) { (void)close(fd); }

void deliberately_discarded_unbraced_if(int cond, int fd) {
  if (cond)
    (void)close(fd);
}

int for_condition_uses_result(int fd, char *buf, unsigned long n) {
  int seen = 0;
  for (; read(fd, buf, n);)
    seen = 1;
  return seen;
}
