/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Entry points for ntlibc's own POSIX.1-2017 (XCU) standard utilities.
 * Each `__util_<name>_main()` is the whole of utility <name>'s logic,
 * implemented once in src/util/<name>.c (mkdir, chmod, printf and time
 * are the four exceptions -- src/util/mkdir_util.c, src/util/chmod_util.c,
 * src/util/util_printf.c and src/util/util_time.c, to avoid colliding with
 * the ar member names src/stat/mkdir.c, src/stat/chmod.c, and, for printf
 * and time, this library's own src/stdio/printf.c and src/time/time.c
 * already own (tcc's `ar` truncates archive member names to basename
 * only, so two time.c anywhere in src/ silently collide in lib/libc.a --
 * confirmed real, not theoretical, before choosing the name); see each
 * file's own header comment) and shared by two callers:
 *
 *  - bin/<name>.c, a thin main() building the standalone obj/bin/<name>.exe
 *    -- the same "entry point out here, logic in the library" split
 *    sh/main.c already uses for __sh_main() (src/sh/script.c).
 *  - src/sh/builtin.c's bi_<name>() wrapper, which registers the same
 *    utility as a shell built-in that runs in-process, with no fork/exec
 *    (and so no dependency on __find_program()/__spawn() succeeding) --
 *    see that file's own header comment for why this matters for early
 *    bootstrap, not just convenience.
 *
 * (Tier 2's six -- cut/paste/tr/expand/unexpand/fold -- have no ar
 * member-name collision of their own: `find src -name '<name>.c'` turns
 * up nothing else named cut.c, paste.c, tr.c, expand.c, unexpand.c or
 * fold.c anywhere in this tree, so all six live at the plain
 * src/util/<name>.c this comment describes as the default.)
 *
 * Every __util_<name>_main() takes the same shape argc/argv `main()`
 * does (argv[0] is the utility's own name, matching XCU 2.9.1's "first
 * word" and this platform's PATH-search convention) and returns a real
 * process exit status -- 0 for success, matching each utility's own
 * XCU page's EXIT STATUS section otherwise -- never a raw errno or a
 * boolean.  Neither caller above interprets the return value any
 * further: bin/<name>.c hands it straight to the OS as its own exit
 * code, and bi_<name>() assigns it straight to ctx->status.
 */
#ifndef _NTLIBC_UTIL_H
#define _NTLIBC_UTIL_H

#include <stdlib.h>

/* Arithmetic contracts are analysis-only: normal compilers see no source
 * attribute, while the arithub checker both enforces them at every direct
 * call and assumes them at the separately-analyzed callee entry. */
#ifdef NTLIBC_ARITHMETIC_ANALYSIS
#define __arith_range(minimum, maximum) \
	__attribute__((annotate("ntlibc_arith_range:" #minimum ":" #maximum)))
#define __arith_nonzero_field_on_success(argument, field) \
	__attribute__((annotate("ntlibc_arith_nonzero_field_on_success:" \
		#argument ":" #field)))
#else
#define __arith_range(minimum, maximum)
#define __arith_nonzero_field_on_success(argument, field)
#endif

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/* Diagnostics are always secondary to an error status the utility is
 * already returning.  Check the write, but preserve the primary errno and
 * outcome because a diagnostic failure has no more useful status to report. */
static inline void __util_diagf(const char *fmt, ...)
	__attribute__((format(printf, 1, 2), nonnull(1)));
static inline void __util_diagf(const char *fmt, ...)
{
	int saved_errno = errno;
	va_list ap;
	va_start(ap, fmt);
	if (vfprintf(stderr, fmt, ap) < 0) {
		/* The utility's primary failure remains authoritative. */
	}
	va_end(ap);
	errno = saved_errno;
}

/* Shared checked sizing for the utility implementations below.  Keep the
 * arithmetic out of malloc/realloc arguments so an untrusted input length
 * cannot wrap into a small allocation. */
static inline int __util_size_add(size_t a, size_t b, size_t *out)
{
	if (b > (size_t)-1 - a) return 0;
	*out = a + b;
	return 1;
}

static inline int __util_size_mul(size_t a, size_t b, size_t *out)
{
	if (b && a > (size_t)-1 / b) return 0;
	*out = a * b;
	return 1;
}

/* Both wrappers' own writable_span contract is `count * element_size`, not
 * `bytes`: the checked local is invisible outside this function body, so
 * MemoryContractChecker's declaredReturnSpanExtent (which only ever reads
 * a withtok(...) expression against the FUNCTION's own parameters) has to
 * be given the same product its callers already compute their own
 * capacity from. Without this, every caller's later write to the paired
 * count/cap field these allocations back (src/util/patch.c's
 * `struct linebuf`, src/glob/glob.c's `struct pv`/`struct comp`,
 * src/wordexp/wordexp.c's `struct pv`/`struct fbuf`) is unprovable by
 * construction -- not because the write is wrong, but because nothing
 * ever recorded how big the buffer actually is -- which is exactly the
 * gap that made MemoryContractChecker's new field-span enforcement
 * (checkEndFunction's TouchedRecordSpan flush) unusably noisy against
 * this tree until this was added. */
/* Both wrappers set errno = ENOMEM on the overflow path below, not just
 * on malloc()/realloc()'s own failure: real reallocarray(3) (OpenBSD's
 * original, and glibc's own since 2.26) is specified to fail exactly
 * this way -- "if an overflow ... errno is set to ENOMEM, and a NULL
 * pointer is returned" -- and every one of this tree's own callers
 * (src/util/grep.c pl_add(), and the same shape across ar.c, sed.c,
 * m4.c, mailx.c, pax.c, csplit.c, diff.c, ed.c, tsort.c, admin.c,
 * man.c, patch.c, sort.c, find.c, join.c, xargs.c, get.c, ls.c) already
 * trusts errno unconditionally after either of these returns NULL,
 * matching that same real-world contract, not a narrower "only on the
 * underlying allocator's own failure" one. */
withtok(heap_allocated)
withtok(writable_span(count * element_size))
static inline void *__util_mallocarray(size_t count, size_t element_size)
{
	size_t bytes;
	if (!__util_size_mul(count, element_size, &bytes)) { errno = ENOMEM; return NULL; }
	return malloc(bytes);
}

withtok(heap_allocated)
withtok(writable_span(count * element_size))
static inline void *__util_reallocarray(
	void *ptr consume_if_nonnull_return(heap_allocated), size_t count,
	size_t element_size)
{
	size_t bytes;
	if (!__util_size_mul(count, element_size, &bytes)) { errno = ENOMEM; return NULL; }
	return realloc(ptr, bytes);
}

/* Every real call site (src/util/{admin,ar,get,grep,tsort,...}.c and
 * more) uses this exactly the way __util_mallocarray()/
 * __util_reallocarray() above are used -- "grow this array, and if you
 * can't, fail the whole operation the same way an allocator failure
 * would" -- so a `0` return here sets errno = ENOMEM for the identical
 * reason those two do: overflowing the size arithmetic means this much
 * cannot be represented/allocated, which is what ENOMEM already means
 * to every caller that (like every one of the callers in this tree)
 * already trusts errno unconditionally afterward. */
static inline int __util_array_capacity(size_t current, size_t used, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
	size_t additional, size_t initial, size_t element_size, size_t *out)
{
	size_t minimum, maximum, capacity;
	if (!initial || !element_size ||
	    !__util_size_add(used, additional, &minimum)) { errno = ENOMEM; return 0; }
	maximum = (size_t)-1 / element_size;
	if (minimum > maximum || current > maximum) { errno = ENOMEM; return 0; }
	capacity = current < initial ? initial : current;
	while (capacity < minimum) {
		if (capacity > maximum / 2) { capacity = minimum; break; }
		capacity *= 2;
	}
	*out = capacity;
	return 1;
}

/* Tier 1: pathname utilities (XCU basename(1p), dirname(1p), pathchk(1p),
 * pwd(1p)), plus readlink and realpath -- both real GNU/BSD utilities this
 * project's own POSIX-utilities plan folds into this tier even though
 * neither has an XCU page of its own (see src/util/readlink.c and
 * src/util/realpath.c for the caveat spelled out in full).  None of the
 * six is __pure__: pwd and realpath read the real filesystem, basename/
 * dirname/pathchk/readlink still touch errno or stat() a path, so a
 * repeated call with the same argv is not guaranteed to answer the same
 * way twice -- unlike true(1p)/false(1p) below. */
int __util_basename_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_dirname_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_pathchk_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_pwd_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_readlink_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_realpath_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* rm(1p), cp(1p) and mv(1p) do real, potentially destructive filesystem
 * work, so none of them are __pure__ -- unlike true/false below, or
 * test(1p) which never affects the filesystem it inspects. */
int __util_cp_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_mv_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_rm_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Alphabetical.  All six below do real filesystem I/O -- creating,
 * removing, linking or restamping something -- so none is __pure__ the
 * way true/false are; each still gets nonnull(2) because each
 * unconditionally reads argv[0] or argv[1] before any argc check could
 * matter (a usage-error path taken with argc==1 still formats argv[0]
 * into its own diagnostic, or -- test's own reasoning, restated here --
 * simply because a real argv from a real caller is never NULL and this
 * says so). */
int __util_chmod_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
/* Both ignore their arguments entirely and return a fixed status, so
 * both are genuinely side-effect-free regardless of what is passed --
 * pure in the strict __attribute__ sense, not just in the true(1p)/
 * false(1p) naming sense. */
int __util_false_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((__pure__));
int __util_ln_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_mkdir_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_mkfifo_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_rmdir_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_test_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_touch_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_true_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((__pure__));

/* Tier 2: text I/O utilities (XCU cat(1p), echo(1p), tee(1p), wc(1p),
 * head(1p), tail(1p)) -- the first batch of the tier after Tier 1's
 * pathname/filesystem utilities above.  Every one of these reads
 * standard input, a file, or both and writes to standard output, so
 * none is __pure__ the way true/false are; each still gets nonnull(2)
 * for the same reason the Tier-1 filesystem utilities above do -- a
 * real argv from a real caller is never NULL, and each formats argv[0]
 * or an operand from argv into a diagnostic on at least one path. */
int __util_cat_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_echo_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_head_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_tail_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_tee_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_wc_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Tier 2 continued: the data-copying/reporting tier (dd(1p), df(1p),
 * du(1p), cksum(1p)) plus the two uuencoding utilities (uuencode(1p),
 * uudecode(1p)) -- see each src/util/<name>.c for its own XCU citations
 * and documented scope narrowings (df's "no operands" case, dd's conv=
 * coverage, du's -r reading).  None is __pure__: dd/uuencode/uudecode
 * read real files (or stdin) and dd/uudecode write them, df/du query
 * and walk the real filesystem, and cksum reads real files -- every one
 * genuinely depends on outside state a repeated call could see change.
 * Each still gets nonnull(2) for the same reason the Tier 1 block above
 * does: a real argv from a real caller is never NULL, and a usage-error
 * path taken with argc==1 still needs argv[0] for its own diagnostic. */
int __util_cksum_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_dd_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_df_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_du_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_uudecode_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_uuencode_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Tier 2 continued: text-formatting/file-splitting utilities (XCU
 * printf(1p), od(1p), pr(1p), tabs(1p), split(1p), csplit(1p)).
 * Alphabetical, same as the tiers above.  None is __pure__:
 * printf/od/pr/tabs write to stdout unconditionally as their whole
 * purpose, and split/csplit do real filesystem I/O creating the piece
 * files.  Each gets nonnull(2) for the same reason as the tiers above:
 * a real argv from a real caller is never NULL, and each function's
 * own usage-error path formats argv[0] into a diagnostic before any
 * argc check could matter. */
int __util_csplit_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_od_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_pr_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_printf_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_split_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_tabs_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Tier 2 continued: sorting/set-operation utilities (XCU sort(1p),
 * uniq(1p), comm(1p), join(1p), tsort(1p)) -- none is __pure__: all
 * read a real file or stdin (or, for sort -o/uniq's second operand,
 * write one), so a repeated call with the same argv is not guaranteed
 * to answer the same way twice (a changed input file, a different
 * stdin stream). Each has its whole logic in src/util/<name>.c, no
 * basename collision with any existing src/ file (checked before
 * naming these -- see this header's own comment above for why that
 * check matters). */
int __util_comm_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_join_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_sort_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_tsort_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_uniq_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Tier 2 continued: text-formatting utilities (XCU cut(1p), paste(1p),
 * tr(1p), expand(1p), unexpand(1p), fold(1p)).  None is __pure__: all
 * six read standard input or a file operand and write to standard
 * output, so a repeated call is not guaranteed to see the same bytes
 * twice (a pipe, a file another process is still writing, etc.) even
 * though none of them ever writes anything back to the filesystem the
 * way the mkdir/rmdir/mkfifo/ln/chmod/touch block above does. */
int __util_cut_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_expand_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_fold_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_paste_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_tr_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_unexpand_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Tier 4: "bigger engine" utilities -- real parsers, not just option
 * loops over stdio.  patch(1p) is the first: it reads a diff(1)-style
 * difference report (normal, copied-context, unified-context, or ed
 * script -- see src/util/patch.c's own header comment for exactly which
 * of each format's behaviour is implemented, and the real, cited scope
 * narrowings against XCU patch(1p) taken along the way) and applies it
 * to a file.  Not __pure__: it reads (and, absent -o, writes) real
 * files.  nonnull(2) for the same reason as every other utility above:
 * argv is never NULL from a real caller, and a usage-error path taken
 * with argc==1 still needs argv[0] for its own diagnostic. */
int __util_patch_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Tier 4 continued: sed(1p) -- its whole script parser, BRE-driven
 * address/substitution engine, and pattern-space/hold-space cycle live
 * in src/util/sed.c (see that file's own header comment for the
 * mandatory-command coverage and the deliberate GNU-extension
 * exclusions).  Not __pure__: it reads a real file or stdin, and its
 * w/s///w commands and 'i'/'a' output are real I/O with externally
 * visible side effects -- so, like every other utility in this header,
 * a repeated call with the same argv is not guaranteed to answer the
 * same way twice. */
int __util_sed_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Tier 4 continued: grep(1p) -- a real regex-driven line filter,
 * sharing src/regex/regex.c's regcomp()/regexec() (already used
 * internally by src/util/csplit.c) rather than a second regex
 * implementation.  Not __pure__: it reads a real file or stdin, so a
 * repeated call with the same argv is not guaranteed to answer the
 * same way twice. */
int __util_grep_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Tier 4 continued: real archive/content-format parsers, rather than
 * line/field-oriented text tools (XCU pax(1p), ar(1p), file(1p)).
 * Each has its whole logic in src/util/<name>.c EXCEPT file(1p),
 * whose implementation is src/util/util_file.c -- not src/util/file.c
 * -- specifically to avoid colliding with this library's own,
 * unrelated src/stdio/file.c: tcc's `-ar` archiver (this project's own
 * $(AR)) truncates every archive member to its basename, so two
 * different file.c anywhere under src/ would become the same
 * "file.o" member in lib/libc.a (see this header's own comment above,
 * and src/util/util_file.c's, for the full story).  pax.c and ar.c
 * have no such collision (checked with `find src -name 'pax.c'`/
 * `find src -name 'ar.c'` before adding them).  None of the three is
 * __pure__: pax and ar both do real archive/filesystem I/O by design,
 * and file(1p) at minimum stat()s (and, for a regular file, opens and
 * reads a peek of) every operand. */
int __util_ar_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_file_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_pax_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Tier 4 continued: find(1p), xargs(1p), expr(1p), ls(1p) -- real
 * expression grammars and a real recursive traversal, not just a
 * straight-line pass over stdin/argv the way most of Tiers 0-3 are.
 * Each has its own real, deliberate scope narrowing documented at
 * length in its own src/util/<name>.c header comment (find: -H/-L,
 * XSI-only -perm symbolic-mode grammar, -xdev/-nouser/-nogroup;
 * xargs: -0/-d, -E's default-enabled state; ls: -H/-L, the two
 * XSI-shaded -g/-o long-format variants) rather than being silently
 * approximated -- read each file's own comment before assuming a
 * missing flag was an oversight.  None of the four is __pure__: find
 * and ls both walk the real filesystem (and find's -exec/-ok, like
 * xargs's whole reason to exist, spawn real child processes via this
 * project's own __find_program()/__spawn(), src/process/), and expr,
 * though it touches no filesystem itself, still isn't marked __pure__
 * because it writes its result to stdout as its entire purpose (the
 * same reasoning src/util/printf.c's own entry doesn't claim __pure__
 * either). */
int __util_expr_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_find_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_ls_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_xargs_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Tier 4 continued: ed(1p), m4(1p) -- real parsers, not line-oriented
 * filters.  Both are genuinely interactive/stateful by design (ed's
 * in-memory edit buffer and current line/mark/undo state, m4's macro
 * table, quote/comment characters, and diversion buffers), so both
 * take real, documented care to stay safe when run in-process as a
 * shell built-in rather than as their own process: neither ever calls
 * exit()/_exit() internally (a `q`/`Q` or `m4exit` unwinds back to an
 * ordinary `return` from the _main() function instead, the same
 * reasoning src/util/dd.c's own header comment gives for why its
 * SIGINT handler never does either), and neither keeps any static or
 * global mutable state that could leak between one builtin invocation
 * and the next in the same shell session -- see each file's own header
 * comment for the rest of its documented scope (ed: no non-mandatory
 * `W`/`#`, best-effort SIGINT/SIGHUP discipline; m4: which GNU
 * extensions -- __file__, __line__, errprint, esyscmd, and others --
 * are deliberately not implemented because they are not XCU-mandatory).
 * Neither is __pure__: ed touches real files via e/E/r/w/!  and m4 via
 * include/sinclude/mkstemp/syscmd, so a repeated call is not guaranteed
 * to answer the same way twice. */
int __util_ed_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_m4_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Tier 4 continued: diff(1p), cmp(1p) -- real parsers, real
 * algorithms, not just line-oriented text filters.  Neither is
 * __pure__: both read real files (or stdin) whose contents can change
 * between calls.  Each has its whole logic in src/util/<name>.c, no
 * basename collision with any existing src/ file (checked before
 * naming these -- see this header's own comment above for why that
 * check matters). */
int __util_cmp_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_diff_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Tier 7 (this project's own POSIX-utilities plan's "Software
 * Development option tier", the plan's final, explicitly follow-on
 * tier): nm(1p) -- a real ELF64 object-file symbol-table reader, from
 * scratch, sharing no code with src/dlfcn/linux/plat_dlfcn.c's own ELF
 * loader (each keeps its own minimal local Elf64_* structures, the
 * established per-file convention that file's own header comment
 * documents) or with src/internal/pe.c's PE *image* export-directory
 * walker (a different on-disk structure entirely from a COFF object
 * file's symbol table -- see src/util/nm.c's own header for why PE
 * object files are out of scope for this first pass). `strip`/`ctags`/
 * `make`, this tier's other three named utilities, are not yet
 * implemented -- see this project's own plan document for the rest of
 * this tier. Not __pure__: it reads real files. nonnull(2) for the
 * same reason as every other utility above: a real argv from a real
 * caller is never NULL, and a usage-error path taken with argc==1
 * still needs argv[0] for its own diagnostic (or, with argc==1, simply
 * defaults its one implicit operand to "a.out" per XCU nm(1p)'s own
 * OPERANDS text -- either way argv itself is never NULL). */
int __util_nm_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* ---- plumbing shared between src/util/cp.c, src/util/mv.c and
 * src/util/rm.c -----------------------------------------------------
 *
 * mv(1p)'s cross-filesystem fallback (rename() failing EXDEV) is a
 * copy-then-remove-source, so it needs cp's file/tree copy and rm's
 * tree removal; cp's own target_dir form and mv's target_dir form need
 * the identical "target/basename(source)" path construction.  Declared
 * here rather than duplicated three times or left static-and-copied,
 * per this project's "genuine duplication is worth avoiding" rule.
 *
 * `force`, where present, is -f's meaning in cp(1p): "If a file
 * descriptor for dest_file cannot be obtained ... unlink dest_file and
 * proceed" -- retry once after unlinking the destination rather than
 * failing outright.  None of the four are __pure__: all touch the
 * filesystem. */
int __util_copy_regular_file(const char *src, const char *dst, int force) __attribute__((nonnull(1, 2)));
int __util_copy_tree(const char *src withtok(null_terminated), const char *dst withtok(null_terminated), int force) __attribute__((nonnull(1, 2)));
int __util_remove_tree(const char *path) __attribute__((nonnull(1)));
withtok(heap_allocated) withtok(null_terminated) __attribute__((nonnull(1, 2)))
char *__util_join_basename(const char *dir withtok(null_terminated), const char *src withtok(null_terminated));

/* Tier 4: "bigger engines" -- real parsers, budget real time.  awk(1p)
 * is the whole of this tier: the single biggest POSIX utility there
 * is, a real pattern-action language with its own lexer, recursive-
 * descent parser and tree-walking interpreter (src/util/awk_lex.c,
 * awk_parse.c, awk_run.c, with shared types in src/util/awk_priv.h).
 * See src/util/awk.c's own header for the full XCU awk(1p) citations
 * and every deliberate scope narrowing, spelled out the same honest
 * way src/util/dd.c documents its conv= coverage. Not __pure__: awk
 * reads real files/stdin, writes real output, and can run arbitrary
 * commands via system()/getline/print redirection. */
int __util_awk_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Tier 5: process/environment utilities.  time(1p) runs a utility and
 * reports its real/user/system elapsed time; timeout(1) -- not an XCU
 * utility at all (checked against the real alphabetical XCU utility
 * index before writing either file: no timeout(1p) page exists), but
 * named in this project's own POSIX-utilities plan for this tier
 * anyway, implemented per the common GNU-heritage semantics every
 * `timeout` agrees on -- runs a utility and signals it if it outlives
 * a deadline.  See each file's own header comment for the exact
 * spec/manual wording cited and every deliberate scope narrowing.
 * Neither is __pure__: both spawn and wait on a real child process,
 * whose very existence and behaviour differ call to call. */
int __util_time_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_timeout_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Terminal-control utilities: stty(1p), tty(1p) -- both real against
 * src/termios/termios.c's genuine tcgetattr()/tcsetattr() and
 * src/unistd/ttyname.c's ttyname(), not a terminal database (that is
 * tput's job, out of scope for this project entirely; see each file's
 * own header comment for the exact XCU stty.html/tty.html coverage and
 * every deliberate, cited scope narrowing). Neither is __pure__: both
 * read (and stty, absent -a/-g, writes) the real terminal state behind
 * file descriptor 0, so a repeated call is not guaranteed to answer
 * the same way twice. */
int __util_stty_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_tty_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Tier 8 (this project's own POSIX-utilities plan originally deferred
 * both of the utilities below as needing infrastructure the plan
 * didn't build -- "a terminal database" for tput, real termios/pty
 * support that had not landed yet for stty/tty; the user has since
 * explicitly decided to implement both anyway.  tput(1p): real XCU
 * OPERANDS are narrow (clear/init/reset only) plus a deliberately
 * bounded, clearly-labeled capname extension over a built-in five-
 * terminal-type table -- see src/util/tput.c's own header comment for
 * the full citation and every scope narrowing (no real terminfo
 * database reader, no general tparm() parameter-string interpreter,
 * no termcap short names).  Not __pure__: it reads $TERM/argv, queries
 * the real terminal size via ioctl(TIOCGWINSZ) when one is attached,
 * and writes to stdout as its entire purpose -- a repeated call is not
 * guaranteed to answer the same way twice. */
int __util_tput_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Tier 9: SCCS (Source Code Control System) tooling -- admin(1p), and
 * enough of get(1p) to retrieve what admin(1p) creates.  This project's
 * own POSIX-utilities plan (luminous-orbiting-biscuit.md) called admin
 * "functionally obsolescent... low priority regardless" and deprioritized
 * it rather than ruling it out; the user has since explicitly decided to
 * implement it anyway.  Both share the real, documented SCCS `s.file`
 * delta-encoding text format (SOH-prefixed control lines: ^Ah checksum,
 * ^Ad delta-table entry, ^Au/^AU user list, ^At/^AT descriptive text,
 * ^AI/^AE body brackets) -- see src/util/admin.c's own header comment
 * for the full citation and the real, deliberate scope narrowing (no
 * delta(1p) at all, so no second delta ever exists to retrieve; no
 * branches, MR validation, flags, or user-list editing).  Neither is
 * __pure__: both do real filesystem I/O by design. */
int __util_admin_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_get_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* ---- plumbing shared between src/util/admin.c and src/util/get.c ----
 *
 * The SCCS checksum (sccsfile(5): "the sum of all characters [bytes],
 * except those contained in the first [checksum] line", stored as a
 * real historical unsigned short so it wraps at 65536) is computed by
 * admin(1p) when writing a new s.file and re-verified by get(1p) when
 * reading one back -- the identical algorithm, so it lives once here
 * rather than being copied into both files and risking the two silently
 * drifting apart (this project's own "genuine duplication is worth
 * avoiding" rule, restated from the cp/mv/rm plumbing block above). */
unsigned __util_sccs_checksum(const char *buf, size_t len) __attribute__((nonnull(1)));

/* Tier 6: terminal messaging.  write(1p)/mesg(1p) -- the plan's own
 * "explicitly deferred / out of scope" tier, revisited: see
 * src/util/mesg.c and src/util/util_write.c's own header comments for
 * the full argument on what is real here given ntlibc's one-real-user
 * model (src/misc/pwd.c), and src/util/termident.h for the terminal-
 * identification mechanism both share.  __util_write_main() lives in
 * util_write.c, not write.c, to avoid the same ar member-name
 * collision src/util/util_basename.c's header explains in full (this
 * time against src/unistd/write.c, the write(2) syscall). */
int __util_mesg_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_write_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* at(1p)/batch(1p)/crontab(1p), plus the two standalone-only daemons
 * behind them (atd, crond -- not POSIX utilities themselves, no XCU
 * page for either, the same "real infrastructure, no spec page to
 * cite" status src/util/timeout.c already has). This is the one place
 * in this header where two of the five entries below have no bi_*()
 * twin in src/sh/builtin.c at all: __util_atd_main() and
 * __util_crond_main() are each called only from their own
 * bin/atd.c/bin/crond.c, never registered as a shell builtin --
 * src/util/atd.c's and src/util/crond.c's own header comments explain
 * why a long-lived daemon is a deliberate exception to this header's
 * usual "shared by two callers" shape. at(1p)/batch(1p)/crontab(1p)
 * themselves keep the ordinary two-caller shape: they only ever
 * submit/list/edit a job and return immediately, so they are exactly
 * as builtin-shaped as every other entry above.
 *
 * None of the five are __pure__: all five read and write real files
 * in the job spool (src/util/spool.h), and the two daemons spawn and
 * wait on real child processes besides. */
int __util_at_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_batch_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_crontab_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_atd_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));
int __util_crond_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* mailx(1p): originally listed in this project's own POSIX-utilities
 * plan as needing "infrastructure this plan doesn't build" (an MTA, a
 * mail spool) and deferred -- since built for real: a genuine
 * mbox-format reader/writer plus flock()-based advisory locking for
 * concurrent-append safety, with delivery deliberately scoped to
 * *local* delivery only (this platform has no MTA, and this library's
 * own single-real-uid model per src/misc/pwd.c means there is exactly
 * one real local user to deliver to/from anyway -- see
 * src/util/mailx.c's own header for the full scope writeup, including
 * exactly which of mailx.html's interactive commands are implemented
 * and which are deliberately deferred). Not __pure__: reads real
 * mailbox files, writes/appends to them, and reads stdin/a terminal. */
int __util_mailx_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* man(1p): finds a manual page by name/section across $MANPATH and
 * formats it -- a real parser/formatter for the `man`-macro-package
 * troff subset real-world pages overwhelmingly use (.TH, .SH/.SS,
 * .TP/.IP, .PP/.LP, the B/I family, .RS/.RE, .nf/.fi), NOT a general
 * troff/groff engine (out of scope by design -- see src/util/man.c's
 * own header comment for the exact, cited boundary: which macros are
 * supported, which degrade gracefully, and why gzip-compressed pages
 * and real tbl/eqn content are unsupported rather than silently
 * mis-rendered). Not __pure__: it reads real files under $MANPATH,
 * queries the real terminal size, and may spawn a real pager. */
int __util_man_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

/* Tier 7 (Software Development option tier, follow-on work per this
 * project's own POSIX-utilities plan): strip(1p) -- removes the symbol
 * table and debugging information from an ELF64 executable/shared
 * object (ET_EXEC/ET_DYN only) or, in a deliberately narrower bonus
 * scope, a PE image's legacy COFF symbol table and Debug Data
 * Directory entry -- see src/util/strip.c's own header banner for the
 * full, cited safety design (why this utility, uniquely among this
 * batch, is built around "never touch a byte this file cannot prove is
 * safe to move" rather than "strip everything a real GNU strip would").
 * Not __pure__: it reads a real file and, absent -o, overwrites it. */
int __util_strip_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
	__attribute__((nonnull(2)));

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
