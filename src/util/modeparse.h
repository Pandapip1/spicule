/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A single mode-operand parser shared by src/util/mkdir_util.c, src/util/mkfifo.c
 * and src/util/chmod_util.c -- all three XCU pages define their `mode` operand
 * (or mkdir/mkfifo's `-m mode`) as "the same as the mode operand defined
 * for the chmod utility", so this is genuinely one piece of logic used
 * three times, not three coincidentally similar ones.
 *
 * chmod(1p)'s OPERANDS section defines two forms:
 *
 *  - An octal number, "formed by OR-ing together" the desired bits.
 *  - A `symbolic_mode` string: comma-separated clauses, each
 *    `[who...] (op [perm...])+` where who is any combination of
 *    u/g/o/a (a == ugo, the default when who is omitted), op is one of
 *    +/-/=, and perm is the permissions op applies.
 *
 * That grammar's full perm alphabet is r/w/x/X/s/t plus permcopy (perm
 * itself being another who letter, to copy that class's current bits).
 * Only r/w/x are implemented here -- X (conditional execute), s
 * (setuid/setgid), t (sticky) and permcopy are a documented, deliberate
 * gap: their conditional-on-current-state or copy-from-another-class
 * semantics add real complexity for primaries this project's own callers
 * (mkdir -m, mkfifo -m, chmod's own common case) rarely need, and a
 * missing feature that is refused outright (see below) is far safer than
 * one that is silently approximated. Octal mode remains the exact,
 * complete way to reach setuid/setgid/sticky bits.
 *
 * chmod(1p) DESCRIPTION also fixes what happens when who is omitted:
 * "the file mode bits represented by perm for the owner, group, and
 * other permissions, except for those with corresponding bits in the
 * file mode creation mask of the invoking process, shall be set" -- i.e.
 * a bare `+x` (no u/g/o/a) is umask-filtered per class, but an explicit
 * `a+x` is not.  __util_parse_mode() implements exactly that distinction
 * via its own `umask_bits` argument; it is the caller's job to decide
 * what to pass (mkdir(1p)/mkfifo(1p)'s -m callers still hand this
 * function's result to this tree's own mkdir()/mkfifo(), whose NT
 * backend applies the process umask a second time unconditionally --
 * see src/util/mkdir_util.c's own comment on that interaction).
 */
#ifndef _SPICULE_UTIL_MODEPARSE_H
#define _SPICULE_UTIL_MODEPARSE_H

#include <sys/stat.h>

/* prog, spec and out are required: every path through this function's
 * body either writes *out unconditionally or calls fprintf() with prog
 * and spec already substituted in, with no NULL check on any of the
 * three anywhere in modeparse.c. base and umask_bits are plain mode_t
 * values, left unmarked. Returns 0 with *out set to the resulting mode
 * (masked to 07777) on success, or -1 with a "prog: invalid mode:
 * 'spec'" diagnostic already written to stderr. */
int __util_parse_mode(const char *prog, const char *spec, mode_t base,
                       mode_t umask_bits, mode_t *out)
    __attribute__((nonnull(1, 2, 5)));

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
