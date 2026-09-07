/* SPDX-FileCopyrightText: (C) 2026 Gavin John */
/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A clean "correctly guarded" case for tools/lint.sh's `lockset` stage:
 * every touch of the guarded global happens while the lock that guards it
 * is held.  Self-contained -- its own local attribute macros, no spicule
 * headers -- so this is a fixture on Clang's -Wthread-safety feature
 * itself, not on src/internal/thread_annotations.h.
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

void increment(void)
{
	mutex_lock(&g_lock);
	g_counter++;
	mutex_unlock(&g_lock);
}

int read_counter(void)
{
	int v;
	mutex_lock(&g_lock);
	v = g_counter;
	mutex_unlock(&g_lock);
	return v;
}
