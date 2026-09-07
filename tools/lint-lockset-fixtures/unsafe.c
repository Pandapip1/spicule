/* SPDX-FileCopyrightText: (C) 2026 Gavin John */
/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A clear violation for tools/lint.sh's `lockset` stage: the guarded
 * global is touched with the lock that guards it never acquired at all.
 * Self-contained -- its own local attribute macros, no spicule headers --
 * so this is a fixture on Clang's -Wthread-safety feature itself, not on
 * src/internal/thread_annotations.h.
 */
#define CAPABILITY(x) __attribute__((capability(x)))
#define GUARDED_BY(x) __attribute__((guarded_by(x)))
#define ACQUIRE(...) __attribute__((acquire_capability(__VA_ARGS__)))
#define RELEASE(...) __attribute__((release_capability(__VA_ARGS__)))

typedef struct CAPABILITY("mutex") mutex { int locked; } mutex_t;

void mutex_lock(mutex_t *m) ACQUIRE(m);
void mutex_unlock(mutex_t *m) RELEASE(m);

static mutex_t g_lock;
static int g_counter GUARDED_BY(g_lock);

/* No mutex_lock()/mutex_unlock() anywhere in sight: -Wthread-safety must
 * report this write as unguarded. */
void increment_without_locking(void)
{
	g_counter++;
}
