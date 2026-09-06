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
int posix_spawn_file_actions_addclose(
    posix_spawn_file_actions_t *fa handle(spawn_file_actions), int);

/* A genuinely never-initialized, on-stack file_actions object -- real,
 * checkable evidence (see construct-unsafe.c's own use_uninitialized
 * for the identical shape on mutex_t). */
void record_action_never_initialized(void) {
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_addclose(&fa, 3); /* ownership-expect: construct-uninitialized */
}

/* Initializing the same object twice without an intervening destroy() --
 * the leak-shaped bug this coverage exists for: a caller that forgets
 * destroy() on an earlier use and comes back around to init() again. */
void initialize_twice(void) {
  posix_spawn_file_actions_t fa;
  if (posix_spawn_file_actions_init(&fa) == 0)
    posix_spawn_file_actions_init(&fa); /* ownership-expect: construct-twice */
}

/* Recording an action against a destroyed object. */
void record_action_after_destroy(void) {
  posix_spawn_file_actions_t fa;
  if (posix_spawn_file_actions_init(&fa) != 0)
    return;
  posix_spawn_file_actions_destroy(&fa);
  posix_spawn_file_actions_addclose(&fa, 3); /* ownership-expect: construct-use-destroyed */
}

/* Destroying the same object twice. */
void destroy_twice(void) {
  posix_spawn_file_actions_t fa;
  if (posix_spawn_file_actions_init(&fa) != 0)
    return;
  posix_spawn_file_actions_destroy(&fa);
  posix_spawn_file_actions_destroy(&fa); /* ownership-expect: construct-destroyed */
}
