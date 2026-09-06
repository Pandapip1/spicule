/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#include "../../include/ownership.h"

typedef struct {
  int len, cap;
  void *actions;
} posix_spawn_file_actions_t;

int posix_spawn_file_actions_init(
    posix_spawn_file_actions_t *fa construct(spawn_file_actions));
int posix_spawn_file_actions_destroy(
    posix_spawn_file_actions_t *fa destroy(spawn_file_actions));
int posix_spawn_file_actions_addopen(
    posix_spawn_file_actions_t *fa handle(spawn_file_actions), int,
    const char *, int, unsigned);
int posix_spawn_file_actions_addclose(
    posix_spawn_file_actions_t *fa handle(spawn_file_actions), int);
int posix_spawn_file_actions_adddup2(
    posix_spawn_file_actions_t *fa handle(spawn_file_actions), int, int);
int posix_spawn(int *, const char *, const posix_spawn_file_actions_t *,
                const void *, char *const *, char *const *);

/* src/util/crond.c's/atd.c's own shape: init, record a few real actions,
 * spawn, then destroy exactly once regardless of which branch of
 * posix_spawn()'s result is taken. */
void spawn_with_redirected_stdio(void) {
  posix_spawn_file_actions_t fa;
  int pid;
  if (posix_spawn_file_actions_init(&fa) != 0)
    return;
  posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", 0, 0);
  posix_spawn_file_actions_addopen(&fa, 1, "/tmp/out", 0, 0600);
  posix_spawn_file_actions_adddup2(&fa, 1, 2);
  posix_spawn(&pid, "/bin/sh", &fa, 0, 0, 0);
  posix_spawn_file_actions_destroy(&fa);
}

/* posix_spawn()'s own file_actions parameter is deliberately
 * unannotated (see spawn.h's own comment): a null file_actions is
 * POSIX-legal, so passing one here must not be flagged as a use of an
 * uninitialized object. */
void spawn_without_file_actions(void) {
  int pid;
  posix_spawn(&pid, "/bin/sh", 0, 0, 0, 0);
}

/* A posix_spawn_file_actions_t received as a borrowed, already-live
 * pointer -- the same shape construct-safe.c's lock_via_borrowed_pointer
 * trusts for mutex_t and regex-safe.c's match_via_borrowed_pointer
 * trusts for regex_t, since this per-function analysis cannot see the
 * other translation unit's own init() call that established it. */
void inspect_via_borrowed_pointer(posix_spawn_file_actions_t *fa) {
  posix_spawn_file_actions_addclose(fa, 3);
}

/* Reusing the same object for a second spawn is safe once the prior
 * use was actually destroyed first -- unlike construct-unsafe.c's
 * initialize_twice, there is no double-construct here because destroy()
 * discharges the lifecycle before the second init(). The first
 * destroy()'s own result is checked (unlike regfree(), destroy() here
 * returns int and can fail): on the path where it fails the object is
 * still live, so reconstructing it would be a real double-construct,
 * and this function correctly bails out before reaching the second
 * init() on that path. */
void reinitialize_after_destroy(void) {
  posix_spawn_file_actions_t fa;
  if (posix_spawn_file_actions_init(&fa) != 0)
    return;
  if (posix_spawn_file_actions_destroy(&fa) != 0)
    return;
  if (posix_spawn_file_actions_init(&fa) != 0)
    return;
  posix_spawn_file_actions_destroy(&fa);
}
