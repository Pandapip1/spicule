/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The platform interface src/dlfcn/dlfcn.c's POSIX-facing front door
 * (dlopen()/dlsym()/dlclose()/dlerror()) calls into instead of talking
 * to a platform loader directly.  See src/dlfcn/nt/plat_dlfcn.c (built
 * on ntdll's LdrLoadDll()/LdrGetProcedureAddress()/LdrUnloadDll() via
 * include/spicule/rpath.h) and src/dlfcn/linux/plat_dlfcn.c (a real,
 * from-scratch ELF64 loader -- see that file's own banner for the
 * design) for the two implementations these declare.  Same shape as
 * src/internal/plat_stat.h/plat_fcntl.h/plat_mem.h: one POSIX-facing
 * API, multiple OS backends, selected by PLAT_GLOBS (Makefile) at
 * build time with no per-call dispatch.
 *
 * Every function here takes exactly the POSIX-shaped arguments and
 * returns exactly the POSIX-shaped result dlopen.html/dlsym.html/
 * dlclose.html/dlerror.html specify for the matching public function --
 * unlike plat_stat.h/plat_fcntl.h's __plat_* functions, which trade a
 * resolved OS handle for POSIX-shaped fields, there is no narrower
 * "raw platform result" to translate here: a dlopen() handle is
 * already exactly as opaque on every backend as POSIX itself requires
 * it to be (dlopen.html: "the value of this handle should not be
 * interpreted in any way"), so __plat_dlopen() returning that opaque
 * value straight through IS the POSIX-shaped result already, not a
 * layer this header narrows.
 *
 * ---- dlerror(): sticky backend, single-shot front door ---------------
 *
 * dlerror.html's contract is single-shot: "a subsequent call to
 * dlerror() ... shall return NULL" immediately after a prior call
 * already reported the same failure. Both backends instead keep their
 * error state STICKY (the NT backend inherits this from
 * spicule_rpath_error(), which stays sticky because other, older callers
 * of that API already depend on it; the Linux backend below matches it
 * deliberately, for the same reason src/dlfcn/dlfcn.c's own dlerror()
 * banner gives: a sticky backend behind a single-shot front door is
 * strictly more information, never less, and the reconciliation needs
 * only one extra piece of state (a monotonic sequence number) rather
 * than changing what the backend remembers).
 *
 * __plat_dlerror() returns the most recent failure's message (valid
 * until the next __plat_dl*() call on this backend touches it -- the
 * same lifetime dlerror.html itself specifies), or NULL if nothing has
 * ever failed. __plat_dlerror_seq() is a monotonic counter, 0 until the
 * first-ever failure and bumped exactly once per failure recorded by
 * __plat_dlopen()/_dlsym()/_dlclose() -- letting the front door
 * distinguish "the same failure already reported through dlerror()"
 * from "a new one happened since" without either backend needing to
 * implement single-shot semantics itself. src/dlfcn/dlfcn.c's dlerror()
 * is the only caller of either.
 */
#ifndef _SPICULE_PLAT_DLFCN_H
#define _SPICULE_PLAT_DLFCN_H

/* dlopen(): load `file` (or, if NULL, return a handle for the global/
 * main-image symbol set -- dlopen.html DESCRIPTION) with mode `mode`
 * (RTLD_LAZY/RTLD_NOW/RTLD_GLOBAL/RTLD_LOCAL, <dlfcn.h>). NULL and
 * __plat_dlerror() describes why on failure. */
void *__plat_dlopen(const char *file, int mode);

/* dlsym(): resolve `name` against `handle` (a value __plat_dlopen()
 * returned). NULL and __plat_dlerror() describes why on failure --
 * ambiguous only when the object genuinely defines `name` as NULL,
 * which dlsym.html itself says to resolve with dlerror(), the same
 * ambiguity every backend here inherits rather than resolves
 * differently. */
void *__plat_dlsym(void *__restrict handle,
                   const char *__restrict name withtok(null_terminated));

/* dlclose(): release `handle`. 0 on success; nonzero and
 * __plat_dlerror() describes why on failure. */
int __plat_dlclose(void *handle);

/* See this header's own banner above. */
const char *__plat_dlerror(void);
unsigned long __plat_dlerror_seq(void);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
