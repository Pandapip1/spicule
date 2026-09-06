/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * find(1p): walk one or more file hierarchies evaluating a predicate
 * expression against every entry. Checked against
 * https://pubs.opengroup.org/onlinepubs/9699919799/utilities/find.html.
 *
 * SYNOPSIS split: "find [-H|-L] path... [operand_expression...]". Path
 * operands are everything before the first token that looks like the
 * start of an expression ("(", "!", or anything starting with '-'); no
 * path operand defaults to ".".
 *
 * ---- SCOPE NARROWING ------------------------------------------------------
 *
 *  - -H/-L are not implemented; this file always walks physically
 *    (nftw()'s FTW_PHYS, src/ftw/ftw.c), which is the default behavior
 *    when neither flag is given, so the common case is exact; only the
 *    two explicit flags are missing, refused with exit 2.
 *  - -perm accepts only an octal mode operand, not chmod's full symbolic
 *    clause grammar (src/util/modeparse.c) -- that grammar expresses a
 *    *relative modification* of a base mode, the wrong shape for "does
 *    this file's mode satisfy X" testing. Octal names any exact
 *    permission combination.
 *  - -xdev, -nouser, -nogroup, -depth are refused, not silently ignored:
 *    -nouser/-nogroup would be a near-universal match against this
 *    platform's single synthesized passwd/group entry (src/misc/pwd.c,
 *    src/misc/grp.c), not a useful one, and none add power this
 *    project's bootstrap/test scripts need.
 *  - Every other primary (-atime/-ctime/-mtime/-newer/-links/-size/
 *    -perm/-user/-group) is mandatory in the base standard and fully
 *    implemented.
 *
 * ---- PRECEDENCE ---------------------------------------------------------
 *
 * `!` binds tighter than `-a`, which binds tighter than `-o`; adjacent
 * primaries with no explicit operator behave as `-a`. Implemented as the
 * same recursive-descent shape as test(1p) (src/util/test.c's
 * t_oexpr()/t_aexpr()/t_nexpr()): parse_or() -> parse_and() ->
 * parse_not() -> parse_primary(). Unlike expr(1p)'s parser, the
 * expression here is parsed into an AST once and evaluated once per
 * visited file, since find(1p) evaluates the same expression repeatedly.
 *
 * DEFAULT ACTION: an expression containing no -exec/-ok/-print (checked
 * by has_action() below) is wrapped in a top-level AND with a
 * synthesized -print node; a wholly absent expression skips parsing and
 * becomes a bare -print node.
 *
 * ---- -prune, and why it is not a direct nftw() return --------------------
 *
 * POSIX's ftw()/nftw() give the callback exactly one way to affect the
 * walk: return non-zero, which stops the ENTIRE walk. There is no
 * fts()-style FTS_SKIP that skips just one subtree. So preventing
 * descent into one pruned directory while continuing to walk its
 * siblings isn't expressible as an nftw() return code at all.
 *
 * The fix: every entry nftw() reports is checked against a "pruned
 * prefixes" list (g_find.pruned) *before* the expression is evaluated
 * against it; a directory added to that list by a live -prune causes
 * every subsequent report of its descendants to be skipped outright.
 * The one real cost versus a true skip-the-subtree walker: nftw() has
 * already opendir()'d/readdir()'d into the pruned directory by the time
 * -prune fires (report() happens before descent, and the descent itself
 * can't be cancelled), so a pruned subtree's directory-read I/O is not
 * saved -- but no action ever fires on anything under the prefix, so
 * this is a cost, not a correctness gap.
 *
 * ---- -exec/-ok "{} +" batching --------------------------------------------
 *
 * The "+" form's pathnames are accumulated per -exec/-ok node
 * (node->acc) across the entire walk and flushed once at the end, in
 * size-bounded batches (flush_plus() below), rather than per-directory.
 * Both are conforming; deferring to the end is simpler against this
 * project's single-pass nftw() driver. One observable consequence:
 * "+"-batched invocations do not begin running until the whole walk has
 * finished, unlike an "as you go" streaming find.
 *
 * -ok's confirmation is read from standard input with getchar(), not
 * specifically /dev/tty, so a piped stdin is consulted for the answer --
 * POSIX's wording ("read a response from standard input") is silent on
 * /dev/tty and this file follows it literally.
 *
 * EXIT STATUS: 0 all path operands traversed successfully; >0 an error
 * occurred. g_find.exit_status starts 0 and is set to 1 by any
 * per-entry error; a malformed expression is a distinct, immediate exit
 * 2 before any walk begins, matching this project's "invalid invocation
 * is 2, a runtime error is something else" convention (src/util/test.c).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ftw.h>
#include <fnmatch.h>
#include <pwd.h>
#include <grp.h>
#include "util.h"
#include "find.h"
#include "libc.h" /* __find_program()/__spawn() -- src/process/, the same primitives sh's own execute.c uses */

enum ntype {
	N_NOT, N_AND, N_OR,
	P_NAME, P_PATH, P_TYPE, P_PERM, P_USER, P_GROUP, P_SIZE, P_LINKS,
	P_MTIME, P_ATIME, P_CTIME, P_NEWER, P_PRUNE, P_PRINT, P_EXEC, P_OK
};

struct node {
	enum ntype type;
	struct node *a withtok(find_expression_allocated);
	struct node *b withtok(find_expression_allocated);

	const char *pat;        /* -name / -path */
	int type_char;          /* -type */
	int perm_prefix;        /* -perm: 1 => "-mode" (superset match) */
	mode_t perm_val;
	uid_t uid;               /* -user */
	gid_t gid;               /* -group */
	long num;                /* -links / -size / -mtime / -atime / -ctime */
	int cmp;                 /* -1 less, 0 exact, +1 more -- shared numeric-arg convention */
	int size_bytes;           /* -size ...c */
	time_t newer_time;        /* -newer */

	const char **exec_argv;   /* -exec / -ok: slice of the original argv, not owned */
	size_t exec_argc;
	int exec_plus;             /* "{} +" form vs. "{} ;" */
	int is_ok;                 /* -ok vs -exec */
	char **acc withtok(heap_allocated); /* "{} +": accumulated matched pathnames */
	size_t acc_n, acc_cap;
};

struct find_ctx {
	char **v;
	size_t n, i;
	int err;
};

struct find_global {
	int exit_status;
	int fatal;
	time_t now;
	char **pruned withtok(heap_allocated);
	size_t pruned_n, pruned_cap;
};

static struct find_global g_find;

/* ==== parsing ============================================================ */

withtok(find_expression_allocated)
static struct node *alloc_node(enum ntype t)
{
	struct node *n = calloc(1, sizeof *n);
	if (!n) { __util_diagf("find: out of memory\n"); exit(2); }
	n->type = t;
	return n;
}

// NOLINTNEXTLINE(misc-no-recursion) -- ownership follows the argc-bounded expression tree
static void free_node(struct node *n consume(find_expression_allocated))
{
	size_t i;
	if (!n) return;
	free_node(n->a);
	free_node(n->b);
	for (i = 0; i < n->acc_n; i++) free(n->acc[i]);
	free(n->acc);
	free(n);
}

static void ferr(struct find_ctx *c, const char *msg) __attribute__((nonnull(1, 2)));
static void ferr(struct find_ctx *c, const char *msg)
{
	if (c->err) return;
	c->err = 1;
	__util_diagf("find: %s\n", msg);
}

static const char *peek(struct find_ctx *c) __attribute__((nonnull(1)));
static const char *peek(struct find_ctx *c)
{
	return c->i < c->n ? c->v[c->i] : NULL;
}

static const char *consume_arg(struct find_ctx *c, const char *name) __attribute__((nonnull(1, 2)));
static const char *consume_arg(struct find_ctx *c, const char *name)
{
	char msg[64];
	if (c->i >= c->n) {
		snprintf(msg, sizeof msg, "%.40s: argument expected", name);
		ferr(c, msg);
		return "";
	}
	return c->v[c->i++];
}

/* Shared "[+-]N" numeric-argument convention: "+n More than n... -n
 * Less than n... n Exactly n." (find(1p) NUMBER OF n, cited once here
 * for -links/-size/-mtime/-atime/-ctime, all of which share it). */
static int parse_num(const char *tok, long *out, int *cmp) __attribute__((nonnull(1, 2, 3)));
static int parse_num(const char *tok, long *out, int *cmp)
{
	const char *p = tok;
	int m = 0;
	if (*p == '+') { m = 1; p++; }
	else if (*p == '-') { m = -1; p++; }
	if (!*p) return -1;
	{
		const char *q;
		for (q = p; *q; q++) if (*q < '0' || *q > '9') return -1;
	}
	*out = strtol(p, NULL, 10);
	*cmp = m;
	return 0;
}

withtok(find_expression_allocated)
static struct node *parse_or(struct find_ctx *c) __attribute__((nonnull(1)));
withtok(find_expression_allocated)
static struct node *parse_and(struct find_ctx *c) __attribute__((nonnull(1)));
withtok(find_expression_allocated)
static struct node *parse_not(struct find_ctx *c) __attribute__((nonnull(1)));
withtok(find_expression_allocated)
static struct node *parse_primary(struct find_ctx *c) __attribute__((nonnull(1)));

// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested find-expression grouping and is argc-bounded
withtok(find_expression_allocated)
static struct node *parse_primary(struct find_ctx *c)
{
	const char *t;

	if (c->i >= c->n) { ferr(c, "expression expected"); return alloc_node(P_PRINT); }
	t = c->v[c->i];

	if (!strcmp(t, "(")) {
		struct node *inner;
		c->i++;
		inner = parse_or(c);
		if (c->err) return inner;
		if (!peek(c) || strcmp(peek(c), ")")) { ferr(c, "expected ')'"); return inner; } // NOLINT(bugprone-suspicious-string-compare) -- nonzero intentionally detects a missing/mismatched ')'
		c->i++;
		return inner;
	}

	if (!strcmp(t, "-name") || !strcmp(t, "-path")) {
		struct node *n = alloc_node(!strcmp(t, "-name") ? P_NAME : P_PATH);
		c->i++;
		n->pat = consume_arg(c, t);
		return n;
	}
	if (!strcmp(t, "-type")) {
		struct node *n = alloc_node(P_TYPE);
		const char *arg;
		c->i++;
		arg = consume_arg(c, t);
		if (c->err) return n;
		if (strlen(arg) != 1 || !strchr("bcdlpfs", arg[0])) { ferr(c, "-type: unknown type"); return n; }
		n->type_char = arg[0];
		return n;
	}
	if (!strcmp(t, "-perm")) {
		struct node *n = alloc_node(P_PERM);
		const char *arg;
		char *end;
		long v;
		c->i++;
		arg = consume_arg(c, t);
		if (c->err) return n;
		if (*arg == '-') { n->perm_prefix = 1; arg++; }
		v = strtol(arg, &end, 8);
		if (end == arg || *end || v < 0 || v > 07777) { ferr(c, "-perm: invalid mode"); return n; }
		n->perm_val = (mode_t)v;
		return n;
	}
	if (!strcmp(t, "-user")) {
		struct node *n = alloc_node(P_USER);
		const char *arg;
		struct passwd *pw;
		c->i++;
		arg = consume_arg(c, t);
		if (c->err) return n;
		pw = getpwnam(arg);
		if (pw) { n->uid = pw->pw_uid; return n; }
		{
			char *end;
			long v = strtol(arg, &end, 10);
			if (end == arg || *end) { ferr(c, "-user: unknown user"); return n; }
			n->uid = (uid_t)v;
		}
		return n;
	}
	if (!strcmp(t, "-group")) {
		struct node *n = alloc_node(P_GROUP);
		const char *arg;
		struct group *gr;
		c->i++;
		arg = consume_arg(c, t);
		if (c->err) return n;
		gr = getgrnam(arg);
		if (gr) { n->gid = gr->gr_gid; return n; }
		{
			char *end;
			long v = strtol(arg, &end, 10);
			if (end == arg || *end) { ferr(c, "-group: unknown group"); return n; }
			n->gid = (gid_t)v;
		}
		return n;
	}
	if (!strcmp(t, "-size")) {
		struct node *n = alloc_node(P_SIZE);
		const char *arg;
		char buf[64];
		size_t len;
		c->i++;
		arg = consume_arg(c, t);
		if (c->err) return n;
		len = strlen(arg);
		if (len > 0 && arg[len - 1] == 'c') { n->size_bytes = 1; len--; }
		if (len == 0 || len >= sizeof buf) { ferr(c, "-size: invalid value"); return n; }
		memcpy(buf, arg, len);
		buf[len] = 0;
		if (parse_num(buf, &n->num, &n->cmp) < 0) { ferr(c, "-size: invalid value"); return n; }
		return n;
	}
	if (!strcmp(t, "-links") || !strcmp(t, "-mtime") || !strcmp(t, "-atime") || !strcmp(t, "-ctime")) {
		struct node *n = alloc_node(!strcmp(t, "-links") ? P_LINKS :
		                             !strcmp(t, "-mtime") ? P_MTIME :
		                             !strcmp(t, "-atime") ? P_ATIME : P_CTIME);
		const char *arg;
		c->i++;
		arg = consume_arg(c, t);
		if (c->err) return n;
		if (parse_num(arg, &n->num, &n->cmp) < 0) {
			char msg[64];
			snprintf(msg, sizeof msg, "%.40s: invalid value", t);
			ferr(c, msg);
		}
		return n;
	}
	if (!strcmp(t, "-newer")) {
		struct node *n = alloc_node(P_NEWER);
		const char *arg;
		struct stat st;
		c->i++;
		arg = consume_arg(c, t);
		if (c->err) return n;
		if (stat(arg, &st) < 0) {
			__util_diagf("find: %s: %s\n", arg, strerror(errno));
			c->err = 1;
			return n;
		}
		n->newer_time = st.st_mtime;
		return n;
	}
	if (!strcmp(t, "-prune")) { c->i++; return alloc_node(P_PRUNE); }
	if (!strcmp(t, "-print")) { c->i++; return alloc_node(P_PRINT); }
	if (!strcmp(t, "-exec") || !strcmp(t, "-ok")) {
		int is_ok = !strcmp(t, "-ok");
		struct node *n = alloc_node(is_ok ? P_OK : P_EXEC);
		size_t start;
		c->i++;
		start = c->i;
		while (c->i < c->n && strcmp(c->v[c->i], ";") && strcmp(c->v[c->i], "+")) c->i++;
		if (c->i >= c->n) { ferr(c, "-exec/-ok: missing terminating ';' or '+'"); return n; }
		if (c->i == start) { ferr(c, "-exec/-ok: missing utility"); return n; }
		n->exec_argc = c->i - start;
		n->exec_argv = (const char **)&c->v[start];
		if (!strcmp(c->v[c->i], "+")) {
			if (strcmp(n->exec_argv[n->exec_argc - 1], "{}")) { // NOLINT(bugprone-suspicious-string-compare) -- nonzero intentionally detects a missing "{}" marker
				ferr(c, "-exec/-ok ... {} +: '{}' must be the last argument before '+'");
				c->i++;
				return n;
			}
			n->exec_plus = 1;
		}
		n->is_ok = is_ok;
		c->i++; /* consume ';' or '+' */
		return n;
	}

	{
		char msg[80];
		snprintf(msg, sizeof msg, "%.60s: unknown predicate", t);
		ferr(c, msg);
	}
	c->i++;
	return alloc_node(P_PRINT);
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested find-expression grouping and is argc-bounded
withtok(find_expression_allocated)
static struct node *parse_not(struct find_ctx *c)
{
	if (peek(c) && !strcmp(peek(c), "!")) {
		struct node *n = alloc_node(N_NOT);
		c->i++;
		n->a = parse_not(c);
		return n;
	}
	return parse_primary(c);
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested find-expression grouping and is argc-bounded
withtok(find_expression_allocated)
static struct node *parse_and(struct find_ctx *c)
{
	struct node *l = parse_not(c);
	for (;;) {
		const char *t;
		if (c->err) break;
		t = peek(c);
		if (!t || !strcmp(t, ")") || !strcmp(t, "-o")) break;
		if (!strcmp(t, "-a")) c->i++; /* explicit -a; otherwise implicit juxtaposition */
		{
			struct node *n = alloc_node(N_AND);
			n->a = l;
			n->b = parse_not(c);
			l = n;
		}
	}
	return l;
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursive descent mirrors nested find-expression grouping and is argc-bounded
withtok(find_expression_allocated)
static struct node *parse_or(struct find_ctx *c)
{
	struct node *l = parse_and(c);
	while (!c->err && peek(c) && !strcmp(peek(c), "-o")) {
		struct node *n = alloc_node(N_OR);
		c->i++;
		n->a = l;
		n->b = parse_and(c);
		l = n;
	}
	return l;
}

static int has_action(const struct node *n)
{
	if (!n) return 0;
	if (n->type == P_PRINT || n->type == P_EXEC || n->type == P_OK) return 1;
	return has_action(n->a) || has_action(n->b);
}

/* ==== evaluation ========================================================== */

static int type_matches(int ch, mode_t mode)
{
	switch (ch) {
	case 'b': return S_ISBLK(mode);
	case 'c': return S_ISCHR(mode);
	case 'd': return S_ISDIR(mode);
	case 'l': return S_ISLNK(mode);
	case 'p': return S_ISFIFO(mode);
	case 'f': return S_ISREG(mode);
	case 's': return S_ISSOCK(mode);
	default: return 0;
	}
}

static int match_num(long val, long n, int cmp)
{
	if (cmp < 0) return val < n;
	if (cmp > 0) return val > n;
	return val == n;
}

static long days_since(time_t then)
{
	long diff = (long)(g_find.now - then);
	return diff / 86400;
}

static const char *basename_of(const char *path) __attribute__((nonnull(1), __pure__));
static const char *basename_of(const char *path)
{
	const char *s = strrchr(path, '/');
	return s ? s + 1 : path;
}

static void add_pruned(const char *path) __attribute__((nonnull(1)));
static void add_pruned(const char *path)
{
	size_t cap;
	if (!__util_array_capacity(g_find.pruned_cap, g_find.pruned_n, 1, 8,
	                            sizeof(char *), &cap)) {
		g_find.fatal = 1;
		return;
	}
	if (cap != g_find.pruned_cap) {
		char **grown = __util_reallocarray(g_find.pruned, cap, sizeof(char *));
		if (!grown) { g_find.fatal = 1; return; }
		g_find.pruned = grown;
		g_find.pruned_cap = cap;
	}
	{
		size_t len = strlen(path) + 1;
		char *copy = malloc(len);
		if (!copy) { g_find.fatal = 1; return; }
		memcpy(copy, path, len);
		g_find.pruned[g_find.pruned_n++] = copy;
	}
}

static int under_pruned(const char *path) __attribute__((nonnull(1)));
static int under_pruned(const char *path)
{
	size_t i;
	for (i = 0; i < g_find.pruned_n; i++) {
		size_t pl = strlen(g_find.pruned[i]);
		if (!strncmp(path, g_find.pruned[i], pl) && path[pl] == '/') return 1;
	}
	return 0;
}

static void clear_pruned_from(size_t first)
{
	while (g_find.pruned_n > first)
		free(g_find.pruned[--g_find.pruned_n]);
}

static void free_find_global(void)
{
	clear_pruned_from(0);
	free(g_find.pruned);
	g_find.pruned = NULL;
	g_find.pruned_cap = 0;
}

static int spawn_and_wait(char *const argv2[]) __attribute__((nonnull(1)));
static int spawn_and_wait(char *const argv2[])
{
	char *resolved = __find_program(argv2[0], 1);
	int pid, status;
	if (!resolved) {
		__util_diagf("find: %s: command not found\n", argv2[0]);
		g_find.exit_status = 1;
		return -1;
	}
	pid = __spawn(resolved, argv2, environ);
	free(resolved);
	if (pid < 0) {
		__util_diagf("find: %s: %s\n", argv2[0], strerror(errno));
		g_find.exit_status = 1;
		return -1;
	}
	if (waitpid(pid, &status, 0) < 0) { g_find.exit_status = 1; return -1; }
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

/* "read a response from standard input" (find(1p) -ok, EXTENDED
 * DESCRIPTION) -- see this file's header comment on why this reads
 * stdin directly rather than /dev/tty. */
static int confirm(void)
{
	int c, first = -1;
	while ((c = getchar()) != EOF && c != '\n')
		if (first < 0 && c != ' ' && c != '\t') first = c;
	return first == 'y' || first == 'Y';
}

static int confirm_exec(char *const argv2[]) __attribute__((nonnull(1)));
static int confirm_exec(char *const argv2[])
{
	size_t i;
	for (i = 0; argv2[i]; i++) fprintf(stderr, "%s ", argv2[i]);
	fprintf(stderr, "? ");
	(void)fflush(stderr);
	return confirm();
}

static int do_exec_semi(struct node *n, const char *path) __attribute__((nonnull(1, 2)));
static int do_exec_semi(struct node *n, const char *path)
{
	char **argv2 = malloc((n->exec_argc + 1) * sizeof(char *));
	size_t i;
	int rc;
	if (!argv2) { g_find.exit_status = 1; return 0; }
	for (i = 0; i < n->exec_argc; i++)
		argv2[i] = !strcmp(n->exec_argv[i], "{}") ? (char *)path : (char *)n->exec_argv[i];
	argv2[n->exec_argc] = 0;
	if (n->is_ok && !confirm_exec(argv2)) { free(argv2); return 0; }
	rc = spawn_and_wait(argv2);
	free(argv2);
	return rc == 0;
}

static int do_exec_plus_accumulate(struct node *n, const char *path) __attribute__((nonnull(1, 2)));
static int do_exec_plus_accumulate(struct node *n, const char *path)
{
	size_t cap;
	if (!__util_array_capacity(n->acc_cap, n->acc_n, 1, 16, sizeof(char *), &cap)) {
		g_find.fatal = 1;
		return 1;
	}
	if (cap != n->acc_cap) {
		char **grown = __util_reallocarray(n->acc, cap, sizeof(char *));
		if (!grown) { g_find.fatal = 1; return 1; }
		n->acc = grown;
		n->acc_cap = cap;
	}
	{
		size_t len = strlen(path) + 1;
		char *copy = malloc(len);
		if (!copy) { g_find.fatal = 1; return 1; }
		memcpy(copy, path, len);
		n->acc[n->acc_n++] = copy;
	}
	return 1; /* "{} +" always evaluates true */
}

static int do_exec(struct node *n, const char *path) __attribute__((nonnull(1, 2)));
static int do_exec(struct node *n, const char *path)
{
	return n->exec_plus ? do_exec_plus_accumulate(n, path) : do_exec_semi(n, path);
}

// NOLINTNEXTLINE(misc-no-recursion) -- expression evaluation mirrors the parsed AST and is expression-depth bounded
static int eval(struct node *n, const char *path, const struct stat *st, int is_dir)
{
	switch (n->type) {
	case N_NOT: return !eval(n->a, path, st, is_dir);
	case N_AND: return eval(n->a, path, st, is_dir) && eval(n->b, path, st, is_dir);
	case N_OR:  return eval(n->a, path, st, is_dir) || eval(n->b, path, st, is_dir);
	case P_NAME: return fnmatch(n->pat, basename_of(path), 0) == 0;
	case P_PATH: return fnmatch(n->pat, path, 0) == 0;
	case P_TYPE: return type_matches(n->type_char, st->st_mode);
	case P_PERM: {
		mode_t bits = st->st_mode & 07777;
		return n->perm_prefix ? (bits & n->perm_val) == n->perm_val : bits == n->perm_val;
	}
	case P_USER: return st->st_uid == n->uid;
	case P_GROUP: return st->st_gid == n->gid;
	case P_SIZE: {
		long v = n->size_bytes ? (long)st->st_size : (long)((st->st_size + 511) / 512);
		return match_num(v, n->num, n->cmp);
	}
	case P_LINKS: return match_num((long)st->st_nlink, n->num, n->cmp);
	case P_MTIME: return match_num(days_since(st->st_mtime), n->num, n->cmp);
	case P_ATIME: return match_num(days_since(st->st_atime), n->num, n->cmp);
	case P_CTIME: return match_num(days_since(st->st_ctime), n->num, n->cmp);
	case P_NEWER: return st->st_mtime > n->newer_time;
	case P_PRUNE: if (is_dir) add_pruned(path); return 1;
	case P_PRINT: printf("%s\n", path); return 1;
	case P_EXEC: case P_OK: return do_exec(n, path);
	default: return 0;
	}
}

static struct node *g_root;

static int find_cb(const char *path, const struct stat *st, int typeflag, struct FTW *ftwbuf)
{
	(void)ftwbuf;
	if (g_find.fatal) return -1;
	if (under_pruned(path)) return 0;
	if (typeflag == FTW_DNR) {
		__util_diagf("find: %s: cannot read directory\n", path);
		g_find.exit_status = 1;
		return 0;
	}
	if (typeflag == FTW_NS) {
		__util_diagf("find: %s: cannot stat\n", path);
		g_find.exit_status = 1;
		return 0;
	}
	(void)eval(g_root, path, st, typeflag == FTW_D);
	return g_find.fatal ? -1 : 0;
}

/* Flush every "{} +" -exec/-ok node's accumulated batch, in size-bounded
 * chunks -- see this file's header comment on why flushing is deferred
 * to the end of the whole walk rather than streamed. */
// NOLINTNEXTLINE(misc-no-recursion) -- mirrors the parsed AST's own bounded nesting
static void flush_plus(struct node *n)
{
	if (!n) return;
	if ((n->type == P_EXEC || n->type == P_OK) && n->exec_plus && n->acc_n > 0) {
		size_t fixed_argc = n->exec_argc - 1; /* excludes the trailing "{}" marker */
		size_t i = 0;
		while (i < n->acc_n) {
			size_t j = i, bytes = 0, k;
			char **argv2;
			while (j < n->acc_n && (j - i) < 1000 && bytes < 131072) {
				bytes += strlen(n->acc[j]) + 1;
				j++;
			}
			argv2 = malloc((fixed_argc + (j - i) + 1) * sizeof(char *));
			if (!argv2) { g_find.exit_status = 1; return; }
			for (k = 0; k < fixed_argc; k++) argv2[k] = (char *)n->exec_argv[k];
			for (k = 0; k < j - i; k++) argv2[fixed_argc + k] = n->acc[i + k];
			argv2[fixed_argc + (j - i)] = 0;
			if (!n->is_ok || confirm_exec(argv2)) (void)spawn_and_wait(argv2);
			free(argv2);
			i = j;
		}
	}
	flush_plus(n->a);
	flush_plus(n->b);
}

int __util_find_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	const char *paths[128];
	int npaths = 0, i = 1, pi;
	struct find_ctx c;
	struct node *root;

	while (i < argc) {
		const char *a = argv[i];
		if (a[0] == '-' || !strcmp(a, "(") || !strcmp(a, "!")) break;
		if (npaths >= (int)(sizeof paths / sizeof paths[0])) {
			__util_diagf("find: too many path operands\n");
			return 2;
		}
		paths[npaths++] = a;
		i++;
	}
	if (npaths == 0) paths[npaths++] = ".";

	c.v = argv;
	c.n = (size_t)argc;
	c.i = (size_t)i;
	c.err = 0;

	if (c.i >= c.n) {
		root = alloc_node(P_PRINT);
	} else {
		root = parse_or(&c);
		if (!c.err && c.i != c.n) ferr(&c, "unexpected argument");
		if (c.err) { free_node(root); return 2; }
		if (!has_action(root)) {
			struct node *print = alloc_node(P_PRINT);
			struct node *and_ = alloc_node(N_AND);
			and_->a = root;
			and_->b = print;
			root = and_;
		}
	}

	memset(&g_find, 0, sizeof g_find);
	g_find.now = time(NULL);
	g_root = root;

	for (pi = 0; pi < npaths; pi++) {
		size_t saved_pruned;
		if (g_find.fatal) break;
		saved_pruned = g_find.pruned_n; /* pruning is scoped to one path operand's walk */
		if (nftw(paths[pi], find_cb, 15, FTW_PHYS) < 0 && !g_find.fatal) {
			__util_diagf("find: %s: %s\n", paths[pi], strerror(errno));
			g_find.exit_status = 1;
		}
		clear_pruned_from(saved_pruned);
	}
	if (g_find.fatal) {
		__util_diagf("find: out of memory\n");
		g_root = NULL;
		free_find_global();
		free_node(root);
		return 1;
	}

	flush_plus(root);
	{
		int status = g_find.exit_status;
		g_root = NULL;
		free_find_global();
		free_node(root);
		return status;
	}
}
