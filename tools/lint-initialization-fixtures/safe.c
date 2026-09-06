/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

int initialized_local(void) {
  int value;
  value = 7;
  return value;
}

int initialized_field(void) {
  struct pair {
    int first;
    int second;
  } value = {1, 2};
  return value.second;
}

/* This tree's own Linux platform backend raw syscall trampolines take
 * every argument as a bare `long`, including ones that are really
 * `&local_buffer` or a local array decaying to a pointer -- the real
 * Linux syscall ABI, six untyped general-purpose registers. A local
 * array or struct passed this way genuinely is filled by the syscall
 * (e.g. src/socket/linux/plat_socket.c's SYS_socketpair `int sv[2]`,
 * or src/unistd/linux/plat_unistd.c's SYS_uname `struct new_utsname`),
 * but nothing about the call site's own types looks like it could
 * write through that argument, so this checker must recognise the
 * idiom by name rather than by Clang's own default pointer-argument
 * invalidation. */
static long raw_syscall(long nr, long a1, long a2, long a3, long a4,
                        long a5, long a6);

int reads_array_filled_by_raw_syscall(void) {
  int sv[2];
  long ret = raw_syscall(1, 0, 0, 0, (long)sv, 0, 0);
  if (ret < 0) return -1;
  return sv[0] + sv[1];
}

int reads_struct_filled_by_raw_syscall(void) {
  struct { int a; int b; } raw;
  long ret = raw_syscall(2, (long)&raw, 0, 0, 0, 0, 0);
  if (ret < 0) return -1;
  return raw.a + raw.b;
}
