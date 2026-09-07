/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The process's PT_TLS layout, plus the block builder that turns it into
 * a real per-thread aarch64 TCB -- promoted out of crt/linux/crt1.c
 * (where the whole thing started as a private, file-scoped routine for
 * the INITIAL thread only) so src/thread/linux/plat_thread.c's
 * __plat_thread_spawn() can give every CLONE_SETTLS'd thread the exact
 * same real, independent TLS block rather than reimplementing (and
 * risking silently diverging from) the same ABI-critical layout a
 * second time. See src/internal/linux/tls_setup.c for the
 * implementation and the full derivation of the block shape.
 *
 * __spicule_linux_tls_layout is written exactly once, by crt1.c's
 * linux_setup_tls() during process startup (before any thread but the
 * initial one exists) -- every later reader, including every
 * pthread_create() call for the rest of the process's life, only reads
 * it. vaddr == 0 means "no PT_TLS segment"; the other three fields are
 * only meaningful when vaddr is nonzero.
 */
#ifndef _SPICULE_LINUX_TLS_H
#define _SPICULE_LINUX_TLS_H

#if defined(__aarch64__)
struct spicule_linux_tls_layout {
	unsigned long vaddr;
	unsigned long filesz;
	unsigned long memsz;
	unsigned long align;
};
extern struct spicule_linux_tls_layout __spicule_linux_tls_layout;

/* Builds one fresh TCB (see tls_setup.c for the exact shape) and
 * returns the new thread pointer (TPIDR_EL0 value) it should be
 * created with, or 0 if the bootstrap mmap() failed -- a caller MUST
 * treat 0 as a hard allocation failure, never as "run with no TLS": an
 * aarch64 `__thread` access always dereferences tp + 16 + offset
 * unconditionally, so a thread actually started with TPIDR_EL0 == 0
 * would fault on its first such access. */
void *__spicule_linux_tls_block_create(void);
#endif

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
