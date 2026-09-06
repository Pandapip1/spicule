/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Terminal identification shared, verbatim, between mesg(1p) and
 * write(1p) (src/util/mesg.c, src/util/util_write.c): both need to
 * answer "which of my own descriptors is really a terminal, and what,
 * if anything, can this library reach to gate or write messages to
 * it?" -- the same question, asked by two different utilities, so it
 * lives here once rather than being copied (the bar src/util/tablist.h
 * and src/util/modeparse.h both already document for a header of their
 * own instead of src/internal/util.h's flat function list).
 *
 * What "really a terminal" means here, concretely, differs by
 * platform, and neither half is a fabrication:
 *
 *  - NT: isatty()'s __FD_CONSOLE gate (src/unistd/isatty.c) is the
 *    real, correct answer -- but a console has no filesystem path this
 *    library can chmod(): src/stat/chmod.c's fchmodat() returns EROFS
 *    off the synthetic /dev/console object (src/internal/vfs.c's
 *    __vfs_stat() -- a fixed S_IFCHR|0666 with no writable backing
 *    store at all), and fchmod() on a non-regular-file/directory fd is
 *    a silent success no-op (src/stat/chmod.c:21) that touches
 *    nothing. So an NT console is real and identifiable, but this
 *    library has no real permission bit to read back or flip for it --
 *    see mesg.c's own header comment for what that honestly means for
 *    its y/n state.  `opaque` is set for this case.
 *
 *  - Linux: a real tty (a pty slave, most commonly) is a real
 *    character-device node with a real path, and this library's own
 *    chmod()/fchmodat() are real syscalls against it
 *    (src/stat/linux/plat_stat.c). isatty() (src/unistd/linux/
 *    plat_isatty.c) is real here too now, but answers a wider question
 *    than this file needs: it also succeeds on a Unix98 pty MASTER fd
 *    (/dev/ptmx), which is not a nameable per-session device this file
 *    could chmod() or write(1p) a message into. So this file finds a
 *    real Linux tty its own way instead: fstat() + S_ISCHR(), then
 *    resolve the actual device node path via
 *    readlink("/proc/self/fd/<fd>") and check it is shaped like a real
 *    tty (src/util/termident.c's own path_looks_like_tty(), which is
 *    what filters the ptmx master case out). isatty() is only a
 *    fallback, for a path this route could not resolve.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#ifndef _NTLIBC_UTIL_TERMIDENT_H
#define _NTLIBC_UTIL_TERMIDENT_H

/* path/shortname are always NUL-terminated once __util_find_terminal()
 * returns >= 0.  shortname is the "who"/write(1p)-style short form
 * (the real path with a leading "/dev/" stripped, or ttyname()'s fixed
 * "CON" for an opaque NT console) that write(1p)'s tty operand and
 * banner both compare against / print. */
struct term_ident {
	char path[1024];
	char shortname[64];
	int opaque; /* 1: a real terminal with no writable permission-bit
	             * backing this library can reach (NT); 0: `path` is a
	             * real device node this library resolved for real
	             * (Linux). */
};

/* Searches fd 0, then 1, then 2 -- mesg(1p)/write(1p)'s own shared rule
 * (each utility's own DESCRIPTION: the affected terminal is identified
 * by successively checking standard input, then output, then error)
 * -- for the first one that is really a terminal, and fills *out
 * describing it.  Returns the fd found (0, 1, or 2), or -1 (out
 * untouched) if none of the three is a terminal at all. */
int __util_find_terminal(struct term_ident *out) __attribute__((nonnull(1)));

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
