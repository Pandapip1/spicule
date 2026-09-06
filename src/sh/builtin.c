/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A real built-in *dispatcher*, and the built-in utilities the
 * compound-command grammar needs to be usable at all.
 *
 * A raw strcmp() on a command's *unexpanded* first word is the naive way
 * to add a built-in, and execute.c's dispatcher deliberately doesn't work
 * that way: XCU 2.9.1 names a command *after* word expansion runs, so
 * this file is consulted from exec.c's spawn path with the already-
 * expanded argv; and 2.14's special/regular built-in distinction plus
 * 2.12's shell-execution-environment rules need a column each, which a
 * strcmp() chain has no room for -- hence a table.
 *
 * `test`/`[`/`true`/`false` also exist as standalone executables
 * (src/util/test.c and friends) but stay registered here too, on
 * purpose: a builtin runs in this process unconditionally, without
 * depending on __find_program()/__spawn() succeeding, which matters at
 * an early bootstrap point before fork/exec or PATH are proven to work.
 * `:`, `exit`, `cd`, `set`, `shift`, `return` and `umask` have no
 * standalone form and never could: they are 2.14 special built-ins (or
 * `cd`/`umask`) whose entire effect is on the shell's own execution
 * environment, which a subprocess could never affect.
 *
 * `test` is used 5488 times across five real autoconf `configure`
 * scripts, 229x more often than the `[ ... ]` spelling -- why `test` is
 * not an afterthought to a bracket implementation. What it implements
 * (XCU test(1p)) is documented in src/util/test.c.
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "libc.h"
#include "sh.h"
#include "util.h"
#include "ownership_stubs.h"


/* Every bi_*() below is reached only through builtins[].fn with the address
 * of a real, on-stack sh_builtin_ctx (execute.c's spawn_stage()), hence the
 * unqualified nonnull(1) on all of them. */

/* test(1p)/[(1p): the expression engine lives in src/util/test.c as
 * __util_test_main(), shared with the standalone obj/bin/test.exe. */
static int bi_test(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_test(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_test_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== Tier 1: pathname utilities (basename, dirname, pathchk, pwd,
 * readlink, realpath) -- env_effect 0, same as bi_test() above. ==== */
static int bi_basename(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_basename(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_basename_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_dirname(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_dirname(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_dirname_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_pathchk(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_pathchk(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_pathchk_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_pwd(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_pwd(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_pwd_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_readlink(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_readlink(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_readlink_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_realpath(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_realpath(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_realpath_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== the trivial four ================================================== */

/* XCU 2.14: ": [argument...] -- This utility shall only expand command
 * arguments.  It is used when a command is needed, as in the then
 * condition of an if command, but nothing is to be done by the
 * command.  EXIT STATUS: Zero."  The expansion has already happened by
 * the time this runs (exec.c calls the dispatcher with expanded argv),
 * which is exactly the specified behaviour. */
static int bi_colon(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_colon(struct sh_builtin_ctx *ctx)
{
	ctx->status = 0;
	return 0;
}

/* XCU true(1p) / false(1p): "shall return with exit code zero" /
 * "shall return with a non-zero exit code".  Regular utilities, not
 * 2.14 special built-ins -- they are built in here only because this
 * platform has no true.exe/false.exe for __find_program() to find (see
 * this file's header). */
static int bi_true(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_true(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_true_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_false(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_false(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_false_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== rm / cp / mv (XCU rm(1p), cp(1p), mv(1p)) -- env_effect 0. ==== */
static int bi_rm(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_rm(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_rm_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_cp(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_cp(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_cp_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_mv(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_mv(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_mv_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== the Tier-1 filesystem utilities (mkdir, rmdir, mkfifo, ln, chmod,
 * touch) -- env_effect 0. ==== */
static int bi_mkdir(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_mkdir(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_mkdir_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_rmdir(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_rmdir(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_rmdir_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_mkfifo(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_mkfifo(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_mkfifo_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_ln(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_ln(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_ln_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_chmod(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_chmod(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_chmod_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_touch(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_touch(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_touch_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== Tier 2: text I/O utilities (cat, echo, tee, wc, head, tail) --
 * env_effect 0. ==== */
static int bi_cat(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_cat(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_cat_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_echo(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_echo(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_echo_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_tee(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_tee(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_tee_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_wc(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_wc(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_wc_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_head(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_head(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_head_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_tail(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_tail(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_tail_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== the data-copying/reporting tier (dd, df, du, cksum, uuencode,
 * uudecode) -- env_effect 0. dd(1p)'s SIGINT handler (src/util/dd.c)
 * only sets a flag its copy loop polls and restores the previous
 * disposition before returning, so it's safe to run in-process here. */
static int bi_dd(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_dd(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_dd_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_df(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_df(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_df_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_du(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_du(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_du_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_cksum(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_cksum(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_cksum_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_uuencode(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_uuencode(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_uuencode_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_uudecode(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_uudecode(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_uudecode_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== Tier 2: text-formatting/file-splitting utilities (printf, od, pr,
 * tabs, split, csplit) -- env_effect 0. printf's __util_printf_main()
 * lives in util_printf.c to dodge an ar member-name collision. */
static int bi_printf(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_printf(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_printf_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_od(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_od(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_od_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_pr(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_pr(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_pr_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_tabs(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_tabs(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_tabs_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_split(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_split(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_split_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_csplit(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_csplit(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_csplit_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== Tier 2: sorting/set-operation utilities (sort, uniq, comm, join,
 * tsort) -- env_effect 0. ==== */
static int bi_sort(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_sort(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_sort_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_uniq(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_uniq(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_uniq_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_comm(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_comm(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_comm_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_join(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_join(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_join_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_tsort(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_tsort(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_tsort_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== Tier 2: text-formatting utilities (cut, paste, tr, expand,
 * unexpand, fold) -- env_effect 0. ==== */
static int bi_cut(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_cut(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_cut_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_paste(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_paste(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_paste_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_tr(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_tr(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_tr_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_expand(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_expand(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_expand_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_unexpand(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_unexpand(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_unexpand_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_fold(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_fold(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_fold_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== Tier 4: "bigger engine" utilities -- patch(1p), env_effect 0. ==== */
static int bi_patch(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_patch(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_patch_main(ctx->argc, ctx->argv);
	return 0;
}

/* Tier 4 continued: sed(1p), env_effect 0. */
static int bi_sed(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_sed(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_sed_main(ctx->argc, ctx->argv);
	return 0;
}

/* Tier 4 continued: grep(1p), env_effect 0. */
static int bi_grep(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_grep(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_grep_main(ctx->argc, ctx->argv);
	return 0;
}

/* Tier 4 continued: pax(1p), ar(1p), file(1p) -- env_effect 0. file's
 * __util_file_main() lives in util_file.c to dodge an ar member-name
 * collision with this library's own src/stdio/file.c. */
static int bi_pax(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_pax(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_pax_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_ar(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_ar(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_ar_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_file(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_file(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_file_main(ctx->argc, ctx->argv);
	return 0;
}

/* Tier 7: nm(1p), a from-scratch ELF64-only symbol-table reader (see
 * src/util/nm.c for scope). env_effect 0. */
static int bi_nm(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_nm(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_nm_main(ctx->argc, ctx->argv);
	return 0;
}

/* Tier 4 continued: find(1p), xargs(1p), expr(1p), ls(1p) -- env_effect 0.
 * Being registered here matters more than usual for find -exec/xargs,
 * since they themselves depend on __find_program()/__spawn() to run
 * whatever they invoke; running them in-process needs none of that. */
static int bi_find(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_find(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_find_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_xargs(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_xargs(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_xargs_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_expr(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_expr(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_expr_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_ls(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_ls(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_ls_main(ctx->argc, ctx->argv);
	return 0;
}

/* Tier 4 continued: awk(1p), env_effect 0. */
static int bi_awk(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_awk(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_awk_main(ctx->argc, ctx->argv);
	return 0;
}

/* Tier 4 continued: diff(1p), cmp(1p), env_effect 0. */
static int bi_diff(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_diff(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_diff_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_cmp(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_cmp(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_cmp_main(ctx->argc, ctx->argv);
	return 0;
}

/* XCU 2.14 exit(1p): n defaults to the last command's status, else is
 * taken mod 256.
 *
 * env_mutate == 0 means this command's effect on the shell execution
 * environment is discarded anyway (a pipeline stage, in its own subshell
 * environment per 2.12), so `exit` there exits *that* subshell instead of
 * starting a shell-wide unwind. `( exit 3 )` is handled one level up, by
 * exec_group() consuming the pending exit. */
static int bi_exit(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_exit(struct sh_builtin_ctx *ctx)
{
	int st;

	if (ctx->argc > 1) {
		char *end;
		long v = strtol(ctx->argv[1], &end, 10);
		if (end == ctx->argv[1] || *end) {
			/* 2.8.1: "an error in a special built-in utility ...
			 * shall cause a non-interactive shell to exit"; the
			 * status is implementation-defined and 2 is what
			 * bash/dash use for a numeric-argument error here. */
			(void)fprintf(stderr, "exit: %s: numeric argument required\n", ctx->argv[1]);
			st = 2;
		} else {
			st = (int)(v & 0xff);
		}
	} else {
		st = ctx->last_status;
	}
	ctx->status = st;
	if (ctx->env_mutate) __sh_flow_exit(st);
	return 0;
}

/* XCU cd(1p): the working directory is part of the shell execution
 * environment (2.12), so this can only ever run in the shell's own
 * process -- there is no cd.exe.
 *
 * Deliberately incomplete: no CDPATH search, no -L/-P, no "cd -" to
 * OLDPWD. PWD and OLDPWD are updated so a later $PWD read isn't stale. */
static int bi_cd(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_cd(struct sh_builtin_ctx *ctx)
{
	const char *target = ctx->argc > 1 ? ctx->argv[1] : getenv("HOME");
	char *oldcwd, *newcwd;

	if (!target || !*target) {
		/* cd(1p): "If ... HOME is unset or null, the results are
		 * unspecified" -- failing the command is a conforming
		 * choice. */
		ctx->status = 1;
		return 0;
	}
	oldcwd = getcwd(0, 0);
	if (chdir(target) < 0) {
		free(oldcwd);
		ctx->status = 1;
		return 0;
	}
	newcwd = getcwd(0, 0);
	if (oldcwd) setenv("OLDPWD", oldcwd, 1);
	if (newcwd) setenv("PWD", newcwd, 1);
	free(oldcwd);
	free(newcwd);
	ctx->status = 0;
	return 0;
}

/* XCU umask(1p): like `cd`, the file creation mask is part of the shell
 * execution environment (2.12), so this can only usefully run in the
 * shell's own process -- a standalone umask.exe would set only its own
 * mask and exit with nothing left to observe the change, so unlike
 * test/true/false there is no src/util/umask.c.
 *
 * Also the fix for a real bug: src/util/atbatch.c's generated job bodies
 * re-emit the submitting shell's umask as a plain `umask NNNN` line, so a
 * shell with no `umask` builtin refused every at/batch job on its first line.
 *
 * SYNOPSIS: "umask [-S] [mask]". Only an octal mask is implemented; a
 * symbolic one (`umask u+rwx`) is refused with a diagnostic rather than
 * silently misparsed as octal -- a tracked gap, since nothing this
 * project generates ever needs it. -S prints the mask in symbolic form;
 * otherwise only an omitted mask operand prints anything at all. */
static void print_umask_symbolic(unsigned mask)
{
	static const char classes[3] = { 'u', 'g', 'o' };
	int i;

	for (i = 0; i < 3; i++) {
		unsigned bits = (~mask >> ((2 - i) * 3)) & 07u;
		if (i) putchar(',');
		putchar(classes[i]);
		putchar('=');
		if (bits & 4u) putchar('r');
		if (bits & 2u) putchar('w');
		if (bits & 1u) putchar('x');
	}
	putchar('\n');
}

static int bi_umask(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_umask(struct sh_builtin_ctx *ctx)
{
	int argi = 1;
	int symbolic = 0;
	const char *s;
	char *end;
	unsigned long v = 0;
	int bad;

	if (ctx->argc > 1 && !strcmp(ctx->argv[1], "-S")) {
		symbolic = 1;
		argi = 2;
	}

	if (argi >= ctx->argc) {
		if (symbolic) print_umask_symbolic(__umask_get());
		else printf("%04o\n", __umask_get());
		ctx->status = 0;
		return 0;
	}
	if (ctx->argc > argi + 1) {
		(void)fprintf(stderr, "umask: too many operands\n");
		ctx->status = 1;
		return 0;
	}

	s = ctx->argv[argi];
	bad = !*s || *s < '0' || *s > '7';
	if (!bad) {
		v = strtoul(s, &end, 8);
		bad = *end != 0 || v > 07777;
	}
	if (bad) {
		(void)fprintf(stderr,
			"umask: %s: not an octal mode -- symbolic mode operands are not implemented\n", s);
		ctx->status = 1;
		return 0;
	}
	umask((mode_t)v);
	if (symbolic) print_umask_symbolic(__umask_get());
	ctx->status = 0;
	return 0;
}

/* ==== set / shift: the positional parameters (XCU 2.5.1) =============== */

/* set(1p) with no arguments must write output "suitable for reinput to
 * the shell" -- a naive `printf("%s\n", e)` breaks silently the moment a
 * value has a space, '$', or quote. So each value is single-quoted (XCU
 * 2.2.2), with the one character that can't appear inside single quotes
 * escaped via the standard '\'' close/escape/reopen splice.
 *
 * Deviation: this shell's only variable store is the real `environ`
 * (execute.c), so what's listed is the environment, not a separate set
 * of unexported shell variables, and there's no collation-order sort. */
static int write_quoted(const char *v)
{
	if (fputc('\'', stdout) == EOF) return -1;
	for (; *v; v++) {
		if (*v == '\'') {
			if (fputs("'\\''", stdout) < 0) return -1;
		} else if (fputc(*v, stdout) == EOF) return -1;
	}
	return fputc('\'', stdout) == EOF ? -1 : 0;
}

/* Shared by bi_set() (prefix "", set(1p)'s own "%s=%s\n") and bi_export()
 * (prefix "export ", export(1p)'s "the format 'export name=value'") --
 * both are this same environ walk with the same reinput-safe quoting,
 * differing only in what precedes each line. */
static int list_variables(const char *prefix)
{
	extern char **environ;
	char **e;

	for (e = environ; e && *e; e++) {
		size_t name_length = strcspn(*e, "=");
		if (fputs(prefix, stdout) < 0) return -1;
		if (!(*e)[name_length]) {
			if (fputs(*e, stdout) < 0 || fputc('\n', stdout) == EOF) return -1;
			continue;
		}
		__ownership_readable_span(*e, name_length);
		if (fwrite(*e, 1, name_length, stdout) != name_length ||
		    fputc('=', stdout) == EOF || write_quoted(*e + name_length + 1) < 0 ||
		    fputc('\n', stdout) == EOF) return -1;
	}
	return fflush(stdout) == 0 ? 0 : -1;
}

/* set(1p): non-option arguments replace the positional parameters;
 * `set --` with no further arguments unsets them all.
 *
 * Options are refused rather than silently no-opped: `set -e` doing
 * nothing would change the meaning of every later failure without the
 * script being able to tell (set(1p)'s ">0 An invalid option..." covers it).
 *
 * env_effect is 0, not 1: the no-operand form writes to stdout ("set | ...")
 * and must still run in a pipeline stage, so the mutating half checks
 * ctx->env_mutate itself. */
static int bi_set(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_set(struct sh_builtin_ctx *ctx)
{
	int first = 1;

	if (ctx->argc == 1) {
		ctx->status = list_variables("") == 0 ? 0 : 1;
		return 0;
	}
	if (strcmp(ctx->argv[1], "--") == 0) {
		first = 2;
	} else if (ctx->argv[1][0] == '-' || ctx->argv[1][0] == '+') {
		(void)fprintf(stderr, "set: %s: options are not implemented\n",
		              ctx->argv[1]);
		ctx->status = 2;
		return 0;
	}
	/* A pipeline stage's env_mutate is 0: renumbering the real shell's
	 * parameters from there would leak out of a subshell meant to be
	 * discarded (2.12). */
	if (!ctx->env_mutate) { ctx->status = 0; return 0; }
	if (__sh_params_replace(ctx->argv + first, ctx->argc - first) < 0) {
		(void)fprintf(stderr, "set: out of memory\n");
		ctx->status = 2;
		return 0;
	}
	ctx->status = 0;
	return 0;
}

/* shift(1p): n defaults to 1, must be an unsigned decimal integer <= $#.
 * "Unsigned decimal integer" is taken literally -- a leading '-'/'+' or
 * trailing text is invalid rather than salvaged, since `shift $x` with a
 * malformed $x is exactly the case where guessing produces a
 * wrong-but-plausible argument list further down the script. */
static int bi_shift(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_shift(struct sh_builtin_ctx *ctx)
{
	long n = 1;

	if (ctx->argc > 2) {
		(void)fprintf(stderr, "shift: too many operands\n");
		ctx->status = 2;
		return 0;
	}
	if (ctx->argc == 2) {
		const char *a = ctx->argv[1];
		char *end;
		if (!*a || !(*a >= '0' && *a <= '9')) {
			(void)fprintf(stderr, "shift: %s: not an unsigned decimal integer\n", a);
			ctx->status = 2;
			return 0;
		}
		n = strtol(a, &end, 10);
		if (*end) {
			(void)fprintf(stderr, "shift: %s: not an unsigned decimal integer\n", a);
			ctx->status = 2;
			return 0;
		}
	}
	if (n > __sh_param_count()) {
		(void)fprintf(stderr, "shift: can only shift %d positional parameter%s\n",
			__sh_param_count(), __sh_param_count() == 1 ? "" : "s");
		ctx->status = 2;
		return 0;
	}
	/* Same subshell reasoning as bi_set() above. */
	if (!ctx->env_mutate) { ctx->status = 0; return 0; }
	if (__sh_params_shift((int)n) < 0) { ctx->status = 2; return 0; }
	ctx->status = 0;
	return 0;
}

/* ==== export (XCU 2.14 special built-in, export(1p)) ===================
 *
 * This shell's only variable store is the real `environ` (execute.c), so
 * every "NAME=value" assignment already calls setenv() regardless of
 * `export`, and there's no separate exported/unexported distinction to
 * maintain: `export NAME=value` performs the setenv() a bare assignment
 * already would, and `export NAME` alone is a genuine no-op (a later
 * plain assignment to NAME calls setenv() unconditionally anyway).
 *
 * What this builtin actually adds is the `export`/`export -p` listing
 * form (reusing list_variables() above) -- src/util/atbatch.c emits
 * `export NAME=value` at the top of every generated job body, so a
 * shell with no `export` built in refused every at/batch job outright.
 *
 * env_effect is 0, same as bi_set()'s and for the same reason: the
 * no-operand/-p form must still run and print in a pipeline stage. */
static int is_valid_name(const char *s) __attribute__((nonnull(1)));
static int is_valid_name(const char *s)
{
	size_t i;

	if (!s[0] || (s[0] >= '0' && s[0] <= '9')) return 0;
	for (i = 0; s[i]; i++) {
		char c = s[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '_')) return 0;
	}
	return 1;
}

static int bi_export(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_export(struct sh_builtin_ctx *ctx)
{
	int i;
	int status = 0;

	if (ctx->argc == 1 || strcmp(ctx->argv[1], "-p") == 0) {
		if (ctx->argc > 2) {
			(void)fprintf(stderr, "export: -p: too many operands\n");
			ctx->status = 2;
			return 0;
		}
		ctx->status = list_variables("export ") == 0 ? 0 : 1;
		return 0;
	}

	/* Same subshell reasoning as bi_set()/bi_shift() above. */
	if (!ctx->env_mutate) { ctx->status = 0; return 0; }

	for (i = 1; i < ctx->argc; i++) {
		const char *arg = ctx->argv[i];
		size_t namelen = strcspn(arg, "="), namebytes;
		char *name = __size_add_checked(namelen, 1, &namebytes) ?
			__malloc(namebytes) : 0;

		if (!name) {
			(void)fprintf(stderr, "export: out of memory\n");
			ctx->status = 2;
			return 0;
		}
		__ownership_writable_span(name, namelen);
		__ownership_readable_span(arg, namelen);
		memcpy(name, arg, namelen);
		name[namelen] = 0;
		if (!is_valid_name(name)) {
			(void)fprintf(stderr, "export: %s: not a valid identifier\n", name);
			status = 1;
			__free(name);
			continue;
		}
		/* A bare NAME with no '=' needs no state change at all -- see
		 * this function's own header comment. */
		if (arg[namelen] == '=') setenv(name, arg + namelen + 1, 1);
		__free(name);
	}
	ctx->status = status;
	return 0;
}

/* ==== readonly (XCU 2.14 special built-in, readonly(1p)) ===============
 *
 * Unlike export, this needs real enforcement: readonly(1p) requires a
 * read-only name to error on any later assignment. The mark lives in
 * readonly.c's side-table, and exec_assignment_only() (execute.c)
 * consults it for a plain "NAME=value" command before calling setenv().
 *
 * `readonly NAME=value` sets and marks NAME (rejected if already marked);
 * `readonly NAME` alone marks an existing or not-yet-existing NAME.
 *
 * Stated gap: an assignment *prefix* on another command ("NAME=value
 * cmd") and a `for NAME in ...` loop variable are separate setenv() call
 * sites (execute.c) that don't consult __sh_readonly_is(), so a
 * read-only NAME can still be shadowed or driven by a `for` loop.
 *
 * special is 1 (readonly is on XCU 2.14's own list); env_effect is 0,
 * same as export's and for the same reason. */
static int list_readonly_variables(void)
{
	size_t i, n = __sh_readonly_count();

	for (i = 0; i < n; i++) {
		const char *name = __sh_readonly_name(i);
		const char *val = getenv(name);
		if (fputs("readonly ", stdout) < 0 || fputs(name, stdout) < 0) return -1;
		if (val && (fputc('=', stdout) == EOF || write_quoted(val) < 0)) return -1;
		if (fputc('\n', stdout) == EOF) return -1;
	}
	return fflush(stdout) == 0 ? 0 : -1;
}

static int bi_readonly(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_readonly(struct sh_builtin_ctx *ctx)
{
	int i;
	int status = 0;

	if (ctx->argc == 1 || strcmp(ctx->argv[1], "-p") == 0) {
		if (ctx->argc > 2) {
			(void)fprintf(stderr, "readonly: -p: too many operands\n");
			ctx->status = 2;
			return 0;
		}
		ctx->status = list_readonly_variables() == 0 ? 0 : 1;
		return 0;
	}

	/* Same subshell reasoning as bi_set()/bi_export() above. */
	if (!ctx->env_mutate) { ctx->status = 0; return 0; }

	for (i = 1; i < ctx->argc; i++) {
		const char *arg = ctx->argv[i];
		size_t namelen = strcspn(arg, "="), namebytes;
		char *name = __size_add_checked(namelen, 1, &namebytes) ?
			__malloc(namebytes) : 0;

		if (!name) {
			(void)fprintf(stderr, "readonly: out of memory\n");
			ctx->status = 2;
			return 0;
		}
		__ownership_writable_span(name, namelen);
		__ownership_readable_span(arg, namelen);
		memcpy(name, arg, namelen);
		name[namelen] = 0;
		if (!is_valid_name(name)) {
			(void)fprintf(stderr, "readonly: %s: not a valid identifier\n", name);
			status = 1;
			__free(name);
			continue;
		}
		if (arg[namelen] == '=') {
			if (__sh_readonly_is(name)) {
				(void)fprintf(stderr, "readonly: %s: readonly variable\n", name);
				status = 1;
				__free(name);
				continue;
			}
			setenv(name, arg + namelen + 1, 1);
		}
		if (__sh_readonly_mark(name) < 0) {
			(void)fprintf(stderr, "readonly: out of memory\n");
			ctx->status = 2;
			__free(name);
			return 0;
		}
		__free(name);
	}
	ctx->status = status;
	return 0;
}

/* ==== return (XCU 2.9.5, return(1p)) =================================== */

/* return(1p) outside a function is "unspecified"; this resolves it as a
 * diagnosed error (the System V reading) rather than as an alias for
 * `exit` (the KornShell reading) -- a top-level `return` has almost
 * certainly lost track of where it is, and quietly exiting the whole
 * shell is exactly the silent behavior this shell keeps refusing. */
static int bi_return(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_return(struct sh_builtin_ctx *ctx)
{
	int st = ctx->last_status;

	if (ctx->argc > 2) {
		(void)fprintf(stderr, "return: too many operands\n");
		ctx->status = 2;
		return 0;
	}
	if (ctx->argc == 2) {
		const char *a = ctx->argv[1];
		char *end;
		long v;
		if (!*a || !(*a >= '0' && *a <= '9')) {
			(void)fprintf(stderr, "return: %s: not an unsigned decimal integer\n", a);
			ctx->status = 2;
			return 0;
		}
		v = strtol(a, &end, 10);
		if (*end) {
			(void)fprintf(stderr, "return: %s: not an unsigned decimal integer\n", a);
			ctx->status = 2;
			return 0;
		}
		/* "If n is not an unsigned decimal integer, or is greater than
		 * 255, the results are unspecified" -- the same 8-bit
		 * truncation `exit` already applies here, since that is what a
		 * wait status can carry. */
		st = (int)(v & 0xff);
	}
	if (!__sh_in_function()) {
		(void)fprintf(stderr, "return: not currently executing a function\n");
		ctx->status = 2;
		return 0;
	}
	ctx->status = st;
	if (ctx->env_mutate) __sh_flow_return(st);
	return 0;
}

/* ==== Tier 4: "bigger engines" -- ed(1p), m4(1p) -- env_effect 0. Both
 * are more stateful than most utilities here (ed's edit buffer, m4's
 * macro table), so both take care in their own src/util/<name>.c to
 * never call exit()/_exit() and to leave no state that could leak into
 * a later command in this shell session. */
static int bi_ed(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_ed(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_ed_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_m4(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_m4(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_m4_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== Tier 5: process/environment utilities (time, timeout) --
 * env_effect 0; both only spawn and wait on a child of their own.
 * timeout is not even an XCU-mandatory utility (see its own header). */
static int bi_time(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_time(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_time_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_timeout(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_timeout(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_timeout_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== stty(1p), tty(1p) -- env_effect 0; both only read (stty, absent
 * -a/-g, writes) real terminal state on fd 0. ==== */
static int bi_stty(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_stty(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_stty_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_tty(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_tty(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_tty_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== Tier 8: tput(1p) -- env_effect 0; only reads $TERM and writes
 * to stdout. ==== */
static int bi_tput(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_tput(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_tput_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== Tier 9: SCCS tooling -- admin(1p), get(1p) -- env_effect 0. ==== */
static int bi_admin(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_admin(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_admin_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_get(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_get(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_get_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== Tier 6: terminal messaging -- write(1p)/mesg(1p) -- env_effect 0.
 * See src/util/mesg.c/util_write.c for what's real given ntlibc's
 * one-real-user model. ==== */
static int bi_mesg(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_mesg(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_mesg_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_write(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_write(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_write_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== at(1p)/batch(1p)/crontab(1p): deferred and scheduled jobs =========
 *
 * atd and crond -- the daemons that actually run a submitted job or
 * crontab entry once due -- are deliberately NOT registered here: a
 * long-lived background process is the one shape a shell builtin can't
 * honestly be (see src/util/atd.c/crond.c). bin/atd.c and bin/crond.c
 * are their only callers. */
static int bi_at(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_at(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_at_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_batch(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_batch(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_batch_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_crontab(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_crontab(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_crontab_main(ctx->argc, ctx->argv);
	return 0;
}

static int bi_mailx(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_mailx(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_mailx_main(ctx->argc, ctx->argv);
	return 0;
}

/* man(1p) wraps a troff-macro-subset formatter (src/util/man.c).
 * env_effect is 0: it only reads $MANPATH pages and writes to a pager. */
static int bi_man(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_man(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_man_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== Tier 7 (Software Development option tier): strip(1p) --
 * env_effect 0; only rewrites the file named by its own operand. ==== */
static int bi_strip(struct sh_builtin_ctx *ctx) __attribute__((nonnull(1)));
static int bi_strip(struct sh_builtin_ctx *ctx)
{
	ctx->status = __util_strip_main(ctx->argc, ctx->argv);
	return 0;
}

/* ==== the dispatcher ==================================================== */

/* `special` is XCU 2.14's distinction, recorded because 2.8.1 hangs
 * consequences off it; `env_effect` says the utility changes something
 * 2.12 lists as part of the shell execution environment, so exec.c must
 * not run it in-process when the invocation's effect is scoped to a
 * subshell environment that is about to be discarded. */
static const struct sh_builtin builtins[] = {
	{ ":",     1, 0, bi_colon },
	/* exit/return's env_effect is 0 on purpose: their effect in a subshell
	 * environment *is* the exit status, produced either way, so each
	 * consults ctx->env_mutate itself to decide whether to start an unwind. */
	{ "exit",  1, 0, bi_exit },
	/* set/shift/export/readonly: env_effect 0 (see each's header comment)
	 * -- each has an output half that must run in a pipeline stage and a
	 * mutating half that must not, so each checks ctx->env_mutate itself. */
	{ "set",   1, 0, bi_set },
	{ "shift", 1, 0, bi_shift },
	{ "export", 1, 0, bi_export },
	{ "readonly", 1, 0, bi_readonly },
	{ "return", 1, 0, bi_return },
	{ "cd",    0, 1, bi_cd },
	/* env_effect 1, same as `cd`: umask is XCU 2.12's file creation mask,
	 * so a pipeline stage's own invocation must not actually change it. */
	{ "umask", 0, 1, bi_umask },
	{ "test",  0, 0, bi_test },
	{ "[",     0, 0, bi_test },
	{ "true",  0, 0, bi_true },
	{ "false", 0, 0, bi_false },
	{ "basename", 0, 0, bi_basename },
	{ "dirname",  0, 0, bi_dirname },
	{ "pathchk",  0, 0, bi_pathchk },
	{ "pwd",      0, 0, bi_pwd },
	{ "readlink", 0, 0, bi_readlink },
	{ "realpath", 0, 0, bi_realpath },
	{ "rm",    0, 0, bi_rm },
	{ "cp",    0, 0, bi_cp },
	{ "mv",    0, 0, bi_mv },
	{ "mkdir",  0, 0, bi_mkdir },
	{ "rmdir",  0, 0, bi_rmdir },
	{ "mkfifo", 0, 0, bi_mkfifo },
	{ "ln",     0, 0, bi_ln },
	{ "chmod",  0, 0, bi_chmod },
	{ "touch",  0, 0, bi_touch },
	{ "cat",    0, 0, bi_cat },
	{ "echo",   0, 0, bi_echo },
	{ "tee",    0, 0, bi_tee },
	{ "wc",     0, 0, bi_wc },
	{ "head",   0, 0, bi_head },
	{ "tail",   0, 0, bi_tail },
	{ "dd",       0, 0, bi_dd },
	{ "df",       0, 0, bi_df },
	{ "du",       0, 0, bi_du },
	{ "cksum",    0, 0, bi_cksum },
	{ "uuencode", 0, 0, bi_uuencode },
	{ "uudecode", 0, 0, bi_uudecode },
	{ "printf", 0, 0, bi_printf },
	{ "od",     0, 0, bi_od },
	{ "pr",     0, 0, bi_pr },
	{ "tabs",   0, 0, bi_tabs },
	{ "split",  0, 0, bi_split },
	{ "csplit", 0, 0, bi_csplit },
	{ "sort",  0, 0, bi_sort },
	{ "uniq",  0, 0, bi_uniq },
	{ "comm",  0, 0, bi_comm },
	{ "join",  0, 0, bi_join },
	{ "tsort", 0, 0, bi_tsort },
	{ "cut",      0, 0, bi_cut },
	{ "paste",    0, 0, bi_paste },
	{ "tr",       0, 0, bi_tr },
	{ "expand",   0, 0, bi_expand },
	{ "unexpand", 0, 0, bi_unexpand },
	{ "fold",     0, 0, bi_fold },
	{ "patch", 0, 0, bi_patch },
	{ "sed",   0, 0, bi_sed },
	{ "grep",  0, 0, bi_grep },
	{ "pax",  0, 0, bi_pax },
	{ "ar",   0, 0, bi_ar },
	{ "file", 0, 0, bi_file },
	{ "nm",   0, 0, bi_nm },
	{ "find",  0, 0, bi_find },
	{ "xargs", 0, 0, bi_xargs },
	{ "expr",  0, 0, bi_expr },
	{ "ls",    0, 0, bi_ls },
	{ "awk",   0, 0, bi_awk },
	{ "ed",    0, 0, bi_ed },
	{ "m4",    0, 0, bi_m4 },
	{ "diff",  0, 0, bi_diff },
	{ "cmp",   0, 0, bi_cmp },
	{ "time",    0, 0, bi_time },
	{ "timeout", 0, 0, bi_timeout },
	{ "stty",    0, 0, bi_stty },
	{ "tty",     0, 0, bi_tty },
	{ "tput",    0, 0, bi_tput },
	{ "admin",   0, 0, bi_admin },
	{ "get",     0, 0, bi_get },
	{ "mesg",    0, 0, bi_mesg },
	{ "write",   0, 0, bi_write },
	{ "at",      0, 0, bi_at },
	{ "batch",   0, 0, bi_batch },
	{ "crontab", 0, 0, bi_crontab },
	{ "mailx",   0, 0, bi_mailx },
	{ "man",     0, 0, bi_man },
	{ "strip",   0, 0, bi_strip },
	{ 0, 0, 0, 0 }
};

const struct sh_builtin *__sh_builtin_lookup(const char *name)
{
	size_t i;
	for (i = 0; builtins[i].name; i++)
		if (strcmp(builtins[i].name, name) == 0) return &builtins[i];
	return 0;
}
