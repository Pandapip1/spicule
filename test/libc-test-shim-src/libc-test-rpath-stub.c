/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * tools/libc-test.sh's companion translation unit for the handful of
 * upstream corpus sources that call dlopen(): include/spicule/rpath.h
 * documents __rpath as an extern array the CALLING PROGRAM defines, not
 * something libc itself provides -- the same way libc never defines
 * main(). tools/linkcheck.sh's linkcheck_exception() hits the identical
 * "resolves __rpath ... not a libc symbol" story for the library's own
 * dlopen()/dlsym()/dlclose()/dlerror() entry points, for the same
 * reason: a generated single-call TU that only calls the function is
 * always missing that array too.
 *
 * musl's libc-test corpus has zero spicule awareness and so never
 * defines __rpath itself; this is the minimal definition a real
 * consumer with no extra search directories would supply (see
 * test/rpath.c for the non-empty, real-search-path shape). Linked in
 * only for the corpus sources that reference dlopen() -- see
 * build_one()'s detection in tools/libc-test.sh.
 */
const char *const __rpath[] = { 0 };
