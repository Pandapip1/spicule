/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * (This file is execute.c, not the exec.c it was until 2026-08: tcc's
 * built-in -ar truncates `ar` member names to 15 characters, so this
 * file and src/process/exec.c's exec()/execve() family both landed in
 * lib/libc.a as a single member, `exec.o`, silently shadowing one
 * another in `ar x`/`ar p` despite the archive's symbol index still
 * resolving fine. tools/linkcheck.sh now asserts per arch that
 * lib/libc.a's member count equals its unique-member-name count, so a
 * future collision fails the build instead of sitting unnoticed.)
 *
 * This file executes redirections and multi-command pipelines on top of
 * simple-command execution; subshells "( list )" and brace groups
 * "{ list; }" (exec_group()'s header comment further down); and command
 * substitution (__sh_cmdsub()'s header comment further down), which is
 * what lets wordexp() stop refusing "$(...)"/"`...`" with WRDE_CMDSUB.
 * PATH lookup goes through __find_program(); starting a process goes
 * through __spawn()/waitpid().
 *
 * Word realization reuses the public wordexp() rather than
 * reimplementing quote removal/parameter/pathname expansion here: each
 * sh_word.text is, by construction, already in the form wordexp() expects
 * as one input word. That reuse is bidirectional: a word containing
 * command substitution makes wordexp() call back into this file's
 * __sh_cmdsub(), so a substituted command runs through this same
 * executor, in the same process, with no second interpreter anywhere.
 *
 * ---- Redirections (XCU 2.7) -----------------------------------------
 *
 * Redirection operators are evaluated left to right (2.7), so
 * apply_redirs() walks the sh_redir list once in order, applying each to
 * *this process's own* descriptor table before the next -- observably:
 * "cmd >a 2>&1" sends both fd 1 and fd 2 to "a", but "cmd 2>&1 >a" sends
 * only fd 1 to "a" and leaves fd 2 at the old stdout.
 *
 * Redirections never need a fork(): a "process" here is either (a)
 * nothing at all (an assignment-only command, where 2.7's side effects
 * like a bare "> file" truncation are produced by applying the redirect
 * to the shell's own table and immediately reverting it), or (b) a
 * __spawn() that already gets a private copy of this process's
 * descriptor table at the moment of the call. So redirecting a command
 * is: rewire this process's own fds, spawn (or don't), then restore
 * them exactly. save_fd()/restore_fds() below is that pair; every
 * redirection and every pipe hookup goes through it.
 *
 * ---- Pipelines (XCU 2.9.2) -------------------------------------------
 *
 * The same no-fork reasoning extends to pipelines: connecting one
 * command's stdout to the next's stdin is just another temporary
 * redirection pair applied before each __spawn(). __sh_exec_pipeline()
 * creates ncommands-1 real OS pipes, then loops wiring each stage's fds
 * (with that stage's own redirections applied after, per 2.7's ordering
 * rule -- why "cmd1 2>&1 | cmd2" merges cmd1's stderr into the pipe),
 * spawning as it goes, and waits on all of them only after every command
 * is already running concurrently.
 *
 * Descriptor hygiene is the whole difficulty: this process's own copy of
 * a pipe's read end must close the moment the reading command is
 * spawned, and the write end the moment the writing command is spawned
 * -- a write end left open anywhere is an EOF a downstream reader will
 * never see, i.e. an unkillable hang. Pipe fds are created O_CLOEXEC
 * (pipe2(), not pipe()) so only the fd-0/fd-1 *copies* this file
 * explicitly dup2()s onto the standard descriptors cross into a child.
 *
 * ---- Here-documents (XCU 2.7.4) ---------------------------------------
 *
 * parse.c already captured the literal body text and whether the
 * delimiter was quoted; this file's job is to turn that into an open,
 * readable fd. Deliberately a real temporary file (tmpfile()), not a
 * pipe: a heredoc body larger than one pipe buffer (65536 bytes) written
 * before the reading command exists would block this process forever
 * with nobody draining it. A seekable file has no such limit.
 *
 * ---- Deliberately NOT implemented yet -------------------------------
 *   - `case` and aliases: no grammar exists for either, so a word like
 *     "case" is an ordinary WORD token looked up on PATH; script.c's
 *     preflight refuses both by name before a program ever runs.
 *   - '&' actually backgrounding rather than running synchronously
 *     (job control is out of scope entirely, but *not waiting* for an
 *     async list item is still future work, tracked here).
 * __sh_exec_pipeline()/__sh_exec_command() return -1 (no status written)
 * for a construct that reaches this file despite the above and still
 * cannot be executed; __sh_exec_list()/__sh_exec_andor() propagate it
 * rather than guessing at a status.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <wordexp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include "libc.h"
#include "ownership_stubs.h"
#include "sh.h"

static char *xstrdup(const char *s)
{
	size_t n = strlen(s) + 1;
	char *p = __malloc(n);
	if (p) memcpy(p, s, n);
	return p;
}

/* The "last command substitution performed" 2.9.1 needs: its exit status,
 * plus a monotonically increasing counter so a caller can tell "ran and
 * exited 0" from "no substitution ran" without either masquerading as
 * the other. File-scope because the substitution happens *inside*
 * wordexp(), several frames below any expansion helper, with no
 * wordexp_t field to carry it back out. */
static int cmdsub_status;
static unsigned long cmdsub_generation;

/* ---- shell-wide control flow, and $? ---------------------------------
 *
 * XCU 2.8.2: "the exit status of the last command executed". Every
 * status funnels through __sh_exec_pipeline(), so recording it there is
 * enough to give `exit` with no operand the value 2.14 requires.
 *
 * `flow_exit_pending` is the unwind sh.h documents: `exit` sets it, and
 * every list/and-or loop stops iterating while it's set. Deliberately
 * *not* a longjmp: the redirection/environ/cwd save-and-restore this
 * file is built around live in ordinary function epilogues, and jumping
 * past them would leave the shell's fd table and environ permanently
 * wrong on the way out -- which for `sh -c` is the path that flushes
 * stdout. */
static int sh_last_status;
static int flow_exit_pending;

/* `return` unwinds the same way `exit` does, differing only in who stops
 * it. A separate flag, not a reused one, because the status must survive
 * independently -- `f() { return 3; }; f` must give the call status 3
 * while sh_last_status still tracks 2.8.2's "last command executed" --
 * and a returning function must not look like an exiting shell to any
 * caller in between. */
static int flow_return_pending;
static int flow_return_status;

/* How many function bodies are currently executing. Read by `return`
 * through __sh_in_function() to diagnose a top-level `return`, and used
 * by call_function() below as a recursion bound. */
static int func_depth;

void __sh_flow_exit(int status)
{
	flow_exit_pending = 1;
	sh_last_status = status;
}

int __sh_flow_pending(void)
{
	return flow_exit_pending || flow_return_pending;
}

/* Clears *both*: every caller is a subshell environment consuming an
 * unwind that belongs to it -- "( exit 3 )" exits the subshell, and so
 * does "( return 3 )", which is why a `return` inside a subshell inside
 * a function does not return from the function. */
void __sh_flow_clear(void)
{
	flow_exit_pending = 0;
	flow_return_pending = 0;
}

void __sh_flow_return(int status)
{
	flow_return_pending = 1;
	flow_return_status = status;
}

int __sh_flow_return_pending(void)
{
	return flow_return_pending;
}

int __sh_flow_return_status(void)
{
	return flow_return_status;
}

void __sh_flow_return_clear(void)
{
	flow_return_pending = 0;
}

int __sh_in_function(void)
{
	return func_depth > 0;
}

int __sh_last_status(void)
{
	return sh_last_status;
}

static void free_strv(
	char **v consume(child_environment_allocated), size_t n)
{
	size_t i;
	if (!v) return;
	for (i = 0; i < n; i++) __free(v[i]);
	__free((void *)v);
}

/* Splits an assignment word's raw text ("NAME=value...", guaranteed by
 * parse.c's is_assignment_word() to have an unquoted '=' after an
 * unquoted NAME) and expands the value half via wordexp(). Per 2.9.1,
 * only tilde/parameter expansion and quote removal apply to an
 * assignment's value -- no field splitting, no pathname expansion --
 * but wordexp() doesn't expose that narrower mode, so this takes its
 * first resulting word, accepting the rare over-permissiveness of an
 * unquoted glob/multi-word $var expanding more than strictly correct.
 * Command substitution does run (2.9.1 step 4) and its status feeds the
 * "no command name" rule (cmdsub_status_rule() below). If expansion
 * fails outright, the value falls back to its literal raw text rather
 * than the assignment being silently dropped. On success, *name and
 * *val are __malloc'd and owned by the caller; returns 0, or -1 on a
 * malformed assignment word or OOM. */
static int split_assignment(const char *raw, char **name, char **val)
    __attribute__((nonnull(2, 3)));
static int split_assignment(const char *raw, char **name, char **val) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	const char *eq = strchr(raw, '=');
	size_t nlen;
	wordexp_t we;
	int have_we = 0;
	int rc = 0;

	if (!eq) return -1;
	nlen = (size_t)(eq - raw);
	{
		size_t namebytes;
		char *allocated_name = __size_add_checked(nlen, 1, &namebytes) ?
			__malloc(namebytes) : 0;
		if (!allocated_name) return -1;
		__ownership_writable_span(allocated_name, nlen);
		__ownership_readable_span(raw, nlen);
		memcpy(allocated_name, raw, nlen);
		allocated_name[nlen] = 0;
		*name = allocated_name;
	}

	if (eq[1] && __wordexp_sh(eq + 1, &we, 0) == 0) {
		have_we = 1;
		*val = xstrdup(we.we_wordc ? we.we_wordv[0] : "");
	} else {
		*val = xstrdup(eq[1] ? eq + 1 : "");
	}
	if (!*val) { __free(*name); rc = -1; }
	if (have_we) wordfree(&we);
	return rc;
}

/* Replaces an existing "name=" entry in *vp (freeing the old string),
 * or appends a new one, growing *vp and *cap as needed. Takes
 * ownership of `entry` either way. */
static int env_set(char ***vp, size_t *n, size_t *cap, char *entry, size_t namelen)
{
	char **v = *vp;
	size_t i;
	for (i = 0; i < *n; i++) {
		if (strncmp(v[i], entry, namelen) == 0 && v[i][namelen] == '=') {
			__free(v[i]);
			v[i] = entry;
			return 0;
		}
	}
	if (*n + 1 >= *cap) {
		size_t nc, slots, bytes;
		char **nv;
		if (*cap) {
			if (!__size_mul_checked(*cap, 2, &nc)) { __free(entry); return -1; }
		} else {
			nc = 16;
		}
		if (!__size_add_checked(nc, 1, &slots) ||
		    !__size_mul_checked(slots, sizeof *nv, &bytes)) { __free(entry); return -1; }
		nv = (char **)__malloc(bytes);
		if (!nv) { __free(entry); return -1; }
		memcpy((void *)nv, (const void *)v, *n * sizeof *nv);
		__free((void *)v);
		v = *vp = nv;
		*cap = nc;
	}
	v[(*n)++] = entry;
	v[*n] = 0;
	return 0;
}

/* Builds a private envp for a command with an assignment prefix: a full
 * copy of the current environment (never the shell's own `environ`
 * directly -- a substituted/run command must never clobber the caller's
 * environ) with each assignment applied on top. *out_n receives the
 * entry count (excluding the NULL terminator); returns NULL on OOM.
 *
 * A prefix assignment to a read-only name is rejected with a diagnostic
 * and that one name's override is skipped while the rest of the prefix
 * -- and the command itself -- proceeds. There's no *status here to
 * force nonzero the way exec_assignment_only() does, and there
 * shouldn't be: real shells run `FOO=bar cmd` after rejecting a
 * read-only FOO override, with the command's exit status untouched. */
withtok(child_environment_allocated)
static char **build_child_envp(const struct sh_word *assigns, size_t *out_n)
    __attribute__((nonnull(2)));
withtok(child_environment_allocated)
static char **build_child_envp(const struct sh_word *assigns, size_t *out_n)
{
	size_t n = 0, cap, slots, bytes, i;
	char **v;
	const struct sh_word *a;

	for (n = 0; __environ && __environ[n]; n++) continue;
	if (!__size_add_checked(n, 8, &cap) ||
	    !__size_add_checked(cap, 1, &slots) ||
	    !__size_mul_checked(slots, sizeof *v, &bytes)) return 0;
	v = (char **)__malloc(bytes);
	if (!v) return 0;
	for (i = 0; i < n; i++) {
		v[i] = xstrdup(__environ[i]);
		if (!v[i]) { free_strv(v, i); return 0; }
	}
	v[n] = 0;

	for (a = assigns; a; a = a->next) {
		char *name, *val, *entry;
		size_t nlen, vlen;
		if (split_assignment(a->text, &name, &val)) { free_strv(v, n); return 0; }
		if (__sh_readonly_is(name)) {
			(void)fprintf(stderr, "%s: readonly variable\n", name);
			__free(name);
			__free(val);
			continue;
		}
		{
			size_t entrybytes;
			nlen = strlen(name);
			vlen = strlen(val);
			if (!__size_add_checked(nlen, 1, &entrybytes) ||
			    !__size_add_checked(entrybytes, vlen, &entrybytes) ||
			    !__size_add_checked(entrybytes, 1, &entrybytes)) {
				__free(name); __free(val); free_strv(v, n); return 0;
			}
			entry = __malloc(entrybytes);
		}
		if (!entry) { __free(name); __free(val); free_strv(v, n); return 0; }
		__ownership_writable_span(entry, nlen);
		memcpy(entry, name, nlen);
		entry[nlen] = '=';
		__ownership_writable_span(entry + nlen + 1, vlen + 1);
		memcpy(entry + nlen + 1, val, vlen + 1);
		__free(name);
		__free(val);
		if (env_set(&v, &n, &cap, entry, nlen)) { free_strv(v, n); return 0; }
	}
	*out_n = n;
	return v;
}

/* 2.9.1: a simple command with no cmd_word at all -- only variable
 * assignments -- is still valid, and those assignments affect the
 * *current* execution environment, not a child's. Succeeds (status 0)
 * unless a name is marked read-only: this is the one place a plain
 * "NAME=value" command's assignment is actually performed, so it's
 * readonly.c's enforcement point. The caller may still overwrite a 0
 * here with the status of a command substitution in one of the values
 * (cmdsub_status_rule() below); a read-only rejection takes priority
 * over both that and the "always succeeds" default. */
static int exec_assignment_only(const struct sh_command *cmd, int *status)
    __attribute__((nonnull(1, 2)));
static int exec_assignment_only(const struct sh_command *cmd, int *status)
{
	const struct sh_word *a;
	int ok = 1;
	for (a = cmd->u.simple.assigns; a; a = a->next) {
		char *name, *val;
		if (split_assignment(a->text, &name, &val)) continue;
		if (__sh_readonly_is(name)) {
			(void)fprintf(stderr, "%s: readonly variable\n", name);
			ok = 0;
		} else {
			setenv(name, val, 1);
		}
		__free(name);
		__free(val);
	}
	*status = ok ? 0 : 1;
	return 0;
}

/* ==== Redirections (XCU 2.7) ============================================ */

/* One entry of a redir_state: how to put fd `fd` back the way it was
 * before some redirection touched it. `have` is 0 when `fd` wasn't open
 * beforehand, in which case "restore" means close it; otherwise `dup` is
 * an F_DUPFD_CLOEXEC duplicate of the original handle, so this saved
 * copy is never itself handed to the spawned child. */
struct redir_save {
	int fd;
	int have;
	int dup;
};

struct redir_state {
	struct redir_save *saves;
	size_t n, cap;
};

/* Records fd's current state so it can be restored later, unless already
 * recorded (a command touching the same fd number twice -- "cmd >a >b"
 * -- must restore to what fd 1 was *before either* redirection).
 * Returns -1 only on OOM; "fd was not open" is recorded as `have = 0`,
 * not an error. */
static int save_fd(struct redir_state *rs, int fd) __attribute__((nonnull(1)));
static int save_fd(struct redir_state *rs, int fd)
{
	size_t i;
	for (i = 0; i < rs->n; i++) if (rs->saves[i].fd == fd) return 0;
	if (rs->n == rs->cap) {
		size_t nc, bytes;
		struct redir_save *ns;
		if (rs->cap) {
			if (!__size_mul_checked(rs->cap, 2, &nc)) return -1;
		} else {
			nc = 4;
		}
		if (!__size_mul_checked(nc, sizeof *ns, &bytes)) return -1;
		ns = __malloc(bytes);
		if (!ns) return -1;
		if (rs->saves) { memcpy(ns, rs->saves, rs->n * sizeof *ns); __free(rs->saves); }
		rs->saves = ns;
		rs->cap = nc;
	}
	rs->saves[rs->n].fd = fd;
	rs->saves[rs->n].dup = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	rs->saves[rs->n].have = rs->saves[rs->n].dup >= 0;
	rs->n++;
	return 0;
}

/* Undoes every save_fd() since the matching {0} initialization, in no
 * particular order (each entry names a distinct fd, so they are
 * independent), and frees the bookkeeping array. Safe to call on an
 * all-zero (never touched) redir_state. */
static void restore_fds(struct redir_state *rs) __attribute__((nonnull(1)));
static void restore_fds(struct redir_state *rs)
{
	size_t i;
	for (i = 0; i < rs->n; i++) {
		if (rs->saves[i].have) {
			(void)dup2(rs->saves[i].dup, rs->saves[i].fd);
			(void)close(rs->saves[i].dup);
		} else {
			(void)close(rs->saves[i].fd);
		}
	}
	__free(rs->saves);
	rs->saves = 0;
	rs->n = rs->cap = 0;
}

/* The fd a redirection operator applies to when the syntax didn't name
 * one explicitly (sh_redir.fd is -1): 0 for input-flavoured operators,
 * 1 for output-flavoured ones. */
static int default_redir_fd(enum sh_redir_op op)
{
	switch (op) {
	case SH_R_GREAT:
	case SH_R_DGREAT:
	case SH_R_GREATAND:
	case SH_R_CLOBBER:
		return 1;
	default:
		return 0;
	}
}

/* Expands a redirection target word (2.7: tilde/parameter/command/
 * arithmetic expansion and quote removal, no pathname expansion).
 * wordexp() doesn't expose a "no field splitting, no globbing" mode, so
 * -- like split_assignment() above -- this takes its first resulting
 * word and accepts the same rare over-permissiveness. Returns NULL and
 * sets *unsupported on a wordexp() failure (WRDE_CMDSUB, most commonly)
 * or OOM; the caller propagates that as this file's usual -1. */
static char *expand_redir_word(const char *raw, int *unsupported)
    __attribute__((nonnull(2)));
static char *expand_redir_word(const char *raw, int *unsupported)
{
	wordexp_t we;
	char *r;
	if (__wordexp_sh(raw, &we, 0)) { *unsupported = 1; return 0; }
	r = xstrdup(we.we_wordc ? we.we_wordv[0] : "");
	wordfree(&we);
	if (!r) *unsupported = 1;
	return r;
}

/* 2.7.4: an unquoted-delimiter heredoc body gets the same expansions and
 * backslash rule as an unquoted "..." word, but wordexp() only
 * understands real shell syntax and a heredoc body is literal (a bare
 * '"' is just a data byte). This synthesizes a double-quoted WORD
 * wordexp() can parse instead of reimplementing double-quote expansion:
 * wrap the body in '"', escaping only '"' bytes not already escaped by
 * an odd-length backslash run (the only bytes that would otherwise end
 * the synthetic quoted word prematurely) -- everything else, backslash
 * runs included, passes through unchanged. Returns NULL and sets
 * *unsupported on failure. */
static char *expand_heredoc(const char *body, int *unsupported)
    __attribute__((nonnull(1, 2)));
static char *expand_heredoc(const char *body, int *unsupported)
{
	size_t n = strlen(body), i, synbytes;
	char *syn;
	size_t o = 0;

	int run = 0;
	wordexp_t we;
	char *r;

	if (!__size_mul_checked(n, 2, &synbytes) ||
	    !__size_add_checked(synbytes, 3, &synbytes)) { *unsupported = 1; return 0; }
	syn = __malloc(synbytes);
	if (!syn) { *unsupported = 1; return 0; }
	syn[o++] = '"';
	for (i = 0; i < n; i++) {
		if (body[i] == '\\') {
			run++;
		} else {
			if (body[i] == '"' && (run % 2) == 0) syn[o++] = '\\';
			run = 0;
		}
		syn[o++] = body[i];
	}
	syn[o++] = '"';
	syn[o] = 0;

	if (__wordexp_sh(syn, &we, 0)) { __free(syn); *unsupported = 1; return 0; }
	__free(syn);
	r = xstrdup(we.we_wordc ? we.we_wordv[0] : "");
	wordfree(&we);
	if (!r) *unsupported = 1;
	return r;
}

/* Materializes a here-document body as a real seekable file (see this
 * file's header comment for why a pipe would risk a self-inflicted
 * hang). tmpfile() creates-then-unlinks so the data is gone once every
 * handle closes; F_DUPFD_CLOEXEC gets an independent descriptor that
 * survives this function's own fclose() while staying close-on-exec --
 * the caller dup2()s it onto the command's real target fd, and that's
 * what actually becomes visible to the child. Returns a read-only fd
 * positioned at the start of the body, or -1 on failure. */
static int heredoc_open(const char *text)
{
	FILE *f = tmpfile();
	size_t len;
	int fd, dfd;

	if (!f) return -1;
	len = strlen(text);
	if (len && fwrite(text, 1, len, f) != len) { (void)fclose(f); return -1; }
	if (fflush(f)) { (void)fclose(f); return -1; }
	fd = fileno(f);
	if (fd < 0 || lseek(fd, 0, SEEK_SET) < 0) { (void)fclose(f); return -1; }
	dfd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	(void)fclose(f);
	return dfd;
}

/* Applies one redirection to this process's own descriptor table
 * (already save_fd()-protected by the caller, so every branch here is
 * free to dup2()/close() fd outright). Returns 0 on success, -1 with
 * *unsupported set for "cannot execute this yet" (command substitution
 * in the target word or heredoc body), or 1 for a genuine redirection
 * failure that the caller reports as the *command's* exit status per
 * 2.8.1, not as this file's -1. */
static int apply_one_redir(const struct sh_redir *r, int fd, int *unsupported)
    __attribute__((nonnull(1)));
static int apply_one_redir(const struct sh_redir *r, int fd, int *unsupported)
{
	char *word;
	int newfd = -1;

	switch (r->op) {
	case SH_R_LESS:
		word = expand_redir_word(r->word, unsupported);
		if (!word) return *unsupported ? -1 : 1;
		newfd = open(word, O_RDONLY);
		__free(word);
		break;

	case SH_R_GREAT:
	case SH_R_CLOBBER:
		/* set -C ("noclobber") is not implemented -- this shell has no
		 * `set` builtin at all yet -- so plain '>' never refuses an
		 * existing file in the first place, which makes '>|' (whose
		 * only documented job, 2.7.2, is overriding noclobber) behave
		 * identically to '>' here. That is a real, deliberate gap,
		 * not the two operators being silently treated as the same
		 * thing: the day `set -C` exists, only '>' needs to grow the
		 * "refuse an existing regular file" check. */
		word = expand_redir_word(r->word, unsupported);
		if (!word) return *unsupported ? -1 : 1;
		newfd = open(word, O_WRONLY | O_CREAT | O_TRUNC, 0666);
		__free(word);
		break;

	case SH_R_DGREAT:
		word = expand_redir_word(r->word, unsupported);
		if (!word) return *unsupported ? -1 : 1;
		newfd = open(word, O_WRONLY | O_CREAT | O_APPEND, 0666);
		__free(word);
		break;

	case SH_R_LESSGREAT:
		/* 2.7.7: opened for both reading and writing; created if it
		 * does not exist; deliberately no O_TRUNC. */
		word = expand_redir_word(r->word, unsupported);
		if (!word) return *unsupported ? -1 : 1;
		newfd = open(word, O_RDWR | O_CREAT, 0666);
		__free(word);
		break;

	case SH_R_LESSAND:
	case SH_R_GREATAND: {
		char *end;
		long n;
		word = expand_redir_word(r->word, unsupported);
		if (!word) return *unsupported ? -1 : 1;
		if (strcmp(word, "-") == 0) {
			/* 2.7.6: "file descriptor n ... shall be closed." Closing
			 * an fd that was not even open is not treated as a
			 * failure -- there is nothing left to do either way. */
			__free(word);
			(void)close(fd);
			return 0;
		}
		n = strtol(word, &end, 10);
		if (word[0] && !*end && n >= 0 && n < FD_MAX) {
			int ok = dup2((int)n, fd) >= 0;
			__free(word);
			return ok ? 0 : 1; /* EBADF: duplicating a closed fd */
		}
		/* 2.7.6: "If word evaluates to something else, the behavior
		 * is unspecified" -- treated as a redirection error rather
		 * than silently ignored. */
		__free(word);
		return 1;
	}

	case SH_R_DLESS:
	case SH_R_DLESSDASH: {
		const char *body = r->heredoc ? r->heredoc : "";
		char *expanded = 0;
		if (!r->heredoc_quoted) {
			expanded = expand_heredoc(body, unsupported);
			if (!expanded) return -1;
			body = expanded;
		}
		newfd = heredoc_open(body);
		__free(expanded);
		break;
	}

	default:
		return 1;
	}

	if (newfd < 0) return 1;
	if (newfd != fd) {
		if (dup2(newfd, fd) < 0) { (void)close(newfd); return 1; }
		(void)close(newfd);
	}
	return 0;
}

/* Walks `redirs` left to right (2.7), save_fd()-protecting each target
 * fd the first time it's touched and applying the redirection. Stops at
 * the first -1 (unsupported) or failure -- there's no reason to keep
 * evaluating redirections for a command that is about to fail. Returns
 * -1 (caller propagates as "cannot execute this yet") or 0 with *failed
 * telling the caller whether the command should actually run. */
static int apply_redirs(const struct sh_redir *redirs, struct redir_state *rs, int *failed)
    __attribute__((nonnull(3)));
static int apply_redirs(const struct sh_redir *redirs, struct redir_state *rs, int *failed)
{
	const struct sh_redir *r;
	int unsupported = 0;

	*failed = 0;
	for (r = redirs; r; r = r->next) {
		int fd = r->fd >= 0 ? r->fd : default_redir_fd(r->op);
		int rc;
		if (save_fd(rs, fd)) return -1; /* OOM */
		rc = apply_one_redir(r, fd, &unsupported);
		if (unsupported) return -1;
		if (rc) { *failed = 1; return 0; }
	}
	return 0;
}

/* ==== Shell functions (XCU 2.9.5) ====================================== */

/* 2.9.5: calling a function makes its operands the positional
 * parameters for the duration and restores the caller's afterward; $0 is
 * unchanged (param.c keeps it outside the array so there's nothing to do
 * here). Nesting and recursion fall out of __sh_params_take() being a
 * *move*: each frame owns the list it took, so a recursive call can't
 * alias its caller's.
 *
 * The body is re-parsed per call (sh.h's func_text explains why it's
 * text, not an AST); a parse failure here can't happen for a body
 * already parsed once at definition, but is still reported rather than
 * assumed away.
 *
 * `depth` bounds accidental infinite recursion so it doesn't exhaust the
 * real stack; 2.8.1 lets a non-interactive shell diagnose this as an
 * error rather than crash.
 *
 * Exit status: __sh_exec_list() already wrote 2.9.5's "last command
 * executed by the function" into *status, unless `return` ran. */
#define SH_FUNC_DEPTH_MAX 128

static int call_function(const char *name, const char *body,
                         char **argv, int argc, int *status)
    __attribute__((nonnull(5)));
// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int call_function(const char *name, const char *body, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
                         char **argv, int argc, int *status)
{
	struct sh_params saved;
	struct sh_list *list;
	int rc;

	if (func_depth >= SH_FUNC_DEPTH_MAX) {
		(void)fprintf(stderr, "%s: function calls nested more than %d deep\n",
			name, SH_FUNC_DEPTH_MAX);
		*status = 1;
		return 0;
	}

	list = __sh_parse(body, 0, 0);
	if (!list) return -1;

	__sh_params_take(&saved);
	if (__sh_params_replace(argv + 1, argc - 1) < 0) {
		__sh_params_install(&saved);
		__sh_list_free(list);
		return -1;
	}

	func_depth++;
	*status = 0;
	rc = __sh_exec_list(list, status);
	func_depth--;

	/* Consume a pending `return` -- and *only* a pending return.  A
	 * pending `exit` belongs to the shell and must keep unwinding
	 * straight through this frame, which is the one behavioural
	 * difference between the two flags. */
	if (__sh_flow_return_pending()) {
		*status = __sh_flow_return_status();
		__sh_flow_return_clear();
	}

	__sh_params_install(&saved);
	__sh_list_free(list);
	return rc;
}

/* ==== Spawning one already-redirected simple command ==================== */

typedef struct stage_variant_result {
	int kind;    /* 0: normal holds a pid; nonzero: special holds a status */
	pid_t normal;
	int special;
	int had_name; /* 2.9.1 step 2 actually produced a command name (so the
	               * "no command name, but the command contained a command
	               * substitution" status rule below does not apply) */
} stage_result_t;

/* ==== Built-in utilities: dispatch, not a strcmp chain =================
 *
 * builtin.c owns the built-in table (`cd` included) and every
 * implementation; this file consults it from spawn_stage() below --
 * after wordexp() has produced the argv, which is the only string XCU
 * 2.9.1 ever names as the command name. So `c=cd; $c /tmp` and
 * `'cd' /tmp` are both a `cd`, as 2.9.1 requires and a raw strcmp() on
 * the unexpanded first word could not express.
 *
 * `env_mutate` gates the same thing for every built-in via the table's
 * `env_effect` column: a built-in that changes the shell execution
 * environment (2.12) must not actually do so when this invocation is
 * one stage of a multi-command pipeline, which 2.12 places in a
 * subshell environment. See run_stage()'s comment below.
 */

/* Finds and starts the program named by cmd->u.simple.words (non-NULL --
 * the assignment-only case is handled by the caller, run_stage() below),
 * but does not wait for it: a pipeline needs every stage spawned before
 * waiting on any (this file's header), and a lone command's caller waits
 * immediately afterward instead. Returns -1 ("cannot execute this yet")
 * for a word needing command substitution or on OOM; otherwise 0 with
 * *out filled in. */
/* XCU 2.9.1's [ENOEXEC] fallback: when execl() fails with ENOEXEC, the
 * shell runs a shell invoked with the resolved pathname (or, for a
 * <slash> command name, the command name itself) as its first operand
 * plus the remaining arguments. Both cases are the same call site here:
 * __find_program() copies a name with a directory part through verbatim,
 * so "the pathname resulting from the search" and "the command name"
 * are the same string whenever a slash is involved (the case that
 * matters most on this platform, since `./configure` names itself with
 * a slash).
 *
 * Why [ENOEXEC] at all on NT: nothing here can execute a script image.
 * RtlCreateUserProcess returns STATUS_INVALID_IMAGE_NOT_MZ/_FORMAT,
 * which spawn.c maps to ENOEXEC, so this fallback is the only route by
 * which this shell can run a shell script (XRAT C.2.9.1: the clause
 * exists so a shell can run scripts even without #! support).
 *
 * The interpreter is this shell itself, called rather than spawned:
 * __sh_run_script() (script.c) is the whole sh(1p) utility, re-entered
 * with the calling shell's own $0, positional parameters and functions
 * saved around it.
 *
 * Redirections need nothing special: spawn_stage() has already rewired
 * this process's descriptors to what the command should see, and the
 * in-process interpreter reads exactly those.
 *
 * argv is { arg0, resolved, args... }: 2.9.1 permits, but doesn't
 * require, setting $0 to the command name instead of the pathname, and
 * this takes the pathname (script.c's __sh_main() takes command_file as $0).
 *
 * Not taken: 2.9.1's "may bypass ... if not a text file" -- that's a
 * "may", and exercising it means a second, fallible sniff of the file to
 * suppress a case the interpreter will diagnose anyway.
 *
 * Returns 0 with *status set (the command already ran, so there's no
 * pid to wait on) or -1 with the caller's 126 to follow. */
static int run_interpreted(const char *resolved, const wordexp_t *we, int *status)
    __attribute__((nonnull(2, 3)));
static int run_interpreted(const char *resolved, const wordexp_t *we, int *status)
{
	char **av;
	size_t n = we->we_wordc, i, navs, bytes;
	int argc;

	if (!__size_add_checked(n, 3, &navs) ||
	    !__size_mul_checked(navs, sizeof *av, &bytes)) return -1;
	av = (char **)malloc(bytes);
	if (!av) return -1;
	av[0] = n ? we->we_wordv[0] : (char *)"sh";
	av[1] = (char *)resolved;
	for (i = 1; i < n; i++) av[i + 1] = we->we_wordv[i];
	argc = (int)(n ? n : 1) + 1;
	av[argc] = 0;

	/* An interpreted command's assignments (`FOO=bar ./script`) are already
	 * in the envp spawn_stage() built for the process that never started;
	 * applying them to this shell's own environment and taking them back
	 * would be a transaction this clause doesn't need to run. Not
	 * implemented rather than half-implemented. */
	*status = __sh_run_script(argc, av);
	free((void *)av);
	return 0;
}

// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int spawn_stage(const struct sh_command *cmd, stage_result_t *out, int env_mutate)
    __attribute__((nonnull(1, 2)));
// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int spawn_stage(const struct sh_command *cmd, stage_result_t *out, int env_mutate)
{
	wordexp_t we;
	const struct sh_word *w;
	int first = 1, rc, ran = 0;
	char *resolved;
	char **envp = 0;
	size_t envn = 0;
	pid_t pid;
	const struct sh_builtin *bi;

	out->kind = 1;
	out->had_name = 0;

	/* run_stage() never calls this with cmd->u.simple.words == NULL (the
	 * assignment-only case it handles itself), but a static analyzer
	 * can't see across the call boundary and flags `we` as possibly
	 * read uninitialized below, so this makes the invariant explicit. */
	if (!cmd->u.simple.words) { out->special = 0; return 0; }

	for (w = cmd->u.simple.words; w; w = w->next) {
		rc = __wordexp_sh(w->text, &we, first ? 0 : WRDE_APPEND);
		if (rc) {
			if (!first) wordfree(&we);
			return -1;
		}
		first = 0;
	}
	if (we.we_wordc == 0) { wordfree(&we); out->special = 0; return 0; } /* every word expanded away -- 2.9.1: "no command name results" */
	out->had_name = 1;

	/* 2.9.1 steps 1a/1e: a special built-in, then a regular one, both
	 * *before* any PATH search, so this lookup goes above
	 * __find_program(), not beside it.
	 *
	 * An assignment prefix on a built-in/function is not applied: 2.9.1
	 * scopes such assignments to the utility, and this shell's only
	 * variable store is the real `environ`, so applying it would leak
	 * into the shell with no way to undo it. Refusing (-1) is the honest
	 * answer, since silently not applying it is worse.
	 *
	 * 2.9.1's search order is a sequence with the function step (1c)
	 * between the two kinds of built-in (1a, 1d), not before or after
	 * both: `test` isn't in 1d's table at all (an ordinary PATH utility
	 * this shell happens to provide), so a `test()` function shadows it,
	 * while `set` is 1a and a `set()` function could never run -- which
	 * is why parse.c refuses to define one. */
	bi = __sh_builtin_lookup(we.we_wordv[0]);
	if (!bi || !bi->special) {
		const char *body = __sh_func_lookup(we.we_wordv[0]);
		if (body) {
			if (cmd->u.simple.assigns) { wordfree(&we); return -1; }
			if (!env_mutate) {
				/* A pipeline stage is a subshell environment (2.12) this
				 * shell does not fork for; a function body may `cd` or
				 * assign, so running it here would leak. */
				out->special = 0;
				wordfree(&we);
				return 0;
			}
			rc = call_function(we.we_wordv[0], body,
			                   we.we_wordv, (int)we.we_wordc, &out->special);
			wordfree(&we);
			return rc;
		}
	}
	if (bi) {
		struct sh_builtin_ctx ctx;
		if (cmd->u.simple.assigns) { wordfree(&we); return -1; }
		if (!env_mutate && bi->env_effect) {
			/* A pipeline stage's `cd` would change this process's working
			 * directory with nothing to put it back, so not doing it is
			 * indistinguishable from doing it in a discarded subshell. */
			out->special = 0;
			wordfree(&we);
			return 0;
		}
		ctx.argc = (int)we.we_wordc;
		ctx.argv = we.we_wordv;
		ctx.env_mutate = env_mutate;
		ctx.last_status = sh_last_status;
		ctx.status = 0;
		rc = bi->fn(&ctx);
		out->special = ctx.status;
		wordfree(&we);
		return rc;
	}

	if (cmd->u.simple.assigns) {
		envp = build_child_envp(cmd->u.simple.assigns, &envn);
		if (!envp) { wordfree(&we); return -1; }
	}

	resolved = __find_program(we.we_wordv[0], 1);
	if (!resolved) {
		out->special = 127; /* command not found -- matches system()'s exit-127 clause */
		wordfree(&we);
		free_strv(envp, envn);
		return 0;
	}

	pid = __spawn(resolved, we.we_wordv, envp);
	/* errno is read here, before __free()/wordfree()/free_strv() can write
	 * it. The interpreter runs in this process, so on success there's no
	 * pid: `ran` says out->special is already final and must not be
	 * overwritten with 126 below. */
	if (pid < 0 && errno == ENOEXEC &&
	    run_interpreted(resolved, &we, &out->special) == 0)
		ran = 1;
	free(resolved);
	wordfree(&we);
	free_strv(envp, envn);
	if (pid < 0) {
		out->kind = 1;
		if (!ran) out->special = 126; /* found but could not execute */
	} else {
		out->kind = 0;
		out->normal = pid;
	}
	return 0;
}

/* Runs one simple command's non-redirection half: either the
 * assignment-only case (2.9.1) or a real spawn_stage(). `env_mutate`
 * distinguishes an assignment-only command as the whole of a one-command
 * "pipeline" (where 2.9.1 says the assignment affects this shell's own
 * environment -- exec_assignment_only() does that) from one stage of a
 * multi-command pipeline. This implementation spawns a separate process
 * per stage that has a program to run, but an assignment-only stage has
 * none, so setenv()-ing it here would leak into the real shell's
 * process. Treating it as a no-op is indistinguishable from doing it in
 * a discarded subshell, and keeps this file's "no fork()" pipeline
 * design correct. */
// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int run_stage(const struct sh_command *cmd, stage_result_t *out, int env_mutate)
    __attribute__((nonnull(1, 2)));
// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int run_stage(const struct sh_command *cmd, stage_result_t *out, int env_mutate)
{
	if (!cmd->u.simple.words) {
		out->kind = 1;
		out->had_name = 0;
		if (env_mutate) exec_assignment_only(cmd, &out->special);
		else out->special = 0;
		return 0;
	}
	return spawn_stage(cmd, out, env_mutate);
}

static int wait_status(pid_t pid)
{
	int wstatus;
	if (waitpid(pid, &wstatus, 0) < 0) return -1;
	return WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : 128 + WTERMSIG(wstatus);
}

/* ==== A single simple command, including its own redirections ========== */

/* XCU 2.9.1: with no command name, a command that contained a command
 * substitution completes with that substitution's exit status; otherwise 0.
 *
 * `gen0` is cmdsub_generation as it stood *before* any of this command's
 * expansions ran -- including the redirection words ("> $(...)" has no
 * command name but did contain a substitution), so every caller samples
 * it before its own apply_redirs(), not just before run_stage(). */
static int cmdsub_status_rule(const stage_result_t *sr, unsigned long gen0)
    __attribute__((nonnull(1)));
static int cmdsub_status_rule(const stage_result_t *sr, unsigned long gen0)
{
	if (!sr->kind) return 0;
	if (!sr->had_name && cmdsub_generation != gen0) return cmdsub_status;
	return sr->special;
}

// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int exec_simple(const struct sh_command *cmd, int *status)
    __attribute__((nonnull(1, 2)));
// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int exec_simple(const struct sh_command *cmd, int *status)
{
	struct redir_state rs;
	int failed = 0;
	stage_result_t sr;
	int st;
	unsigned long gen0 = cmdsub_generation;

	rs.saves = 0; rs.n = rs.cap = 0;

	if (apply_redirs(cmd->redirs, &rs, &failed)) { restore_fds(&rs); return -1; } /* unsupported */
	if (failed) {
		/* 2.8.1: a redirection error for an ordinary (non-special-
		 * built-in) utility "shall not exit" a non-interactive shell
		 * -- it fails only this command. The exact nonzero value is
		 * implementation-defined; 1 matches common practice (bash,
		 * dash). */
		restore_fds(&rs);
		*status = 1;
		return 0;
	}

	if (run_stage(cmd, &sr, 1)) { restore_fds(&rs); return -1; }
	restore_fds(&rs);

	if (sr.kind) { *status = cmdsub_status_rule(&sr, gen0); return 0; }
	st = wait_status(sr.normal);
	if (st < 0) return -1;
	*status = st;
	return 0;
}

/* ==== Subshells and brace groups (XCU 2.9.4, XCU 2.12) =================
 *
 * "( list )" executes in a subshell environment (2.12): a duplicate whose
 * changes don't affect the caller. "{ list; }" executes in the current
 * process environment, changes and all. Of the objects 2.12 lists as
 * part of that environment, this shell can actually change four: shell
 * parameters (all in `environ`, via assignment), the working directory
 * (`cd`), open files, and the file creation mask (`umask`). Traps,
 * ulimit and aliases aren't implemented, so there's nothing to isolate there.
 *
 * ---- Standalone: save-and-restore, not fork() ---------------------------
 *
 * A brace group's own redirections and body run without fork() exactly
 * like exec_simple() (apply_redirs()/restore_fds() bracket a plain
 * __sh_exec_list()), needing no isolation since a brace group's changes
 * are supposed to persist.
 *
 * A standalone subshell needs the same redirection bracketing plus real
 * isolation of variables and cwd. fork() is deliberately not used:
 *  1. Nothing in this shell's supported subset needs the *process*
 *     boundary fork() buys, only the *state* isolation 2.12 asks for --
 *     there's no job control, no real backgrounding, and no concurrent
 *     reader of a subshell's output (command substitution captures to a
 *     seekable temp file and only reads after __sh_exec_list() returns).
 *     So nothing else in this process ever needs to run *while* the
 *     subshell body runs.
 *  2. fork()'s cost on this platform is real: src/process/fork.c's
 *     RtlCloneUserProcess wrapper has already needed a fix for a cloexec
 *     handle surviving a clone while its fd-table entry didn't, freezing
 *     a handle NT then silently reissued elsewhere. Avoiding fork() here
 *     keeps one fewer path through that wrapper to get right.
 *
 * What's saved, precisely, per 2.12's list intersected with what this
 * shell can change:
 *   - Shell parameters: every name=value in `environ`, via setenv()/
 *     unsetenv() only (env_snapshot_restore() below), never by swapping
 *     __environ's storage directly -- setenv.c privately tracks which
 *     entries came from putenv() (and must never be freed) in a table
 *     this file can't see or replicate.
 *   - Working directory: getcwd()/chdir() (the only way `cd` changes it).
 *   - File creation mask: __umask_get()/umask() (the only way `umask`
 *     changes it) -- a plain read-and-restore, no allocation involved.
 *   - Open files: apply_redirs()/restore_fds(), reused unchanged, bracket
 *     the subshell's own redirections the same way a simple command's are.
 * $? is not separately saved: it's never a shell variable, only the
 * out-parameter every __sh_exec_*() threads by reference, so not writing
 * through `status` until the subshell's final status is known already
 * gives the right answer for free.
 *
 * ---- As one stage of a multi-command pipeline: still no fork() ---------
 *
 * Every other pipeline stage is a real concurrently-running process
 * connected through a real 64KiB-buffered pipe. Running a compound-
 * command stage's body *in this process* while the rest of the pipeline
 * is still being wired up would risk the same self-inflicted hang this
 * file's header warns a heredoc-via-pipe would risk, and fork() would
 * sidestep it -- but on this platform fork() means RtlCloneUserProcess,
 * which stock Wine (the CI `test` legs run under) does not implement at
 * all: an unimplemented-function abort that takes the whole process
 * down. sh.exe is therefore never expected to fork.
 *
 * So __sh_exec_pipeline() spawns every real (SH_CMD_SIMPLE) stage first,
 * and only afterward -- once every real process already exists and is
 * concurrently draining/filling its own pipe ends -- runs each compound-
 * command stage's body in this process, left to right
 * (exec_group_stage_inline() below). By the time any deferred stage's
 * body runs, whichever neighbor produces its input or consumes its
 * output is either a real spawned process already running concurrently,
 * or a deferred stage strictly to its left that has already finished and
 * closed its end. So no fixed-size pipe buffer can wedge this process
 * against itself.
 *
 * The one hole: two (or more) compound-command stages *directly
 * adjacent*, with no real spawned stage between them (e.g.
 * "{ a; } | { b; }"). Neither side runs concurrently with the other, so
 * whichever runs first can block forever writing/reading past one pipe
 * buffer with nothing on the other end to unblock it -- silently, with
 * no trap to report it. Genuine concurrency is the only fix, and this
 * file has none available here, so __sh_exec_pipeline() detects two
 * adjacent non-simple stages up front and refuses the whole pipeline via
 * the usual -1 convention rather than risk the hang. "( a ) | { b; }"
 * and its permutations are therefore not yet supported; any other
 * placement, including any number of "(...)"/"{...}" separated by at
 * least one ordinary command, works.
 *
 * 2.12's subshell-environment rule for pipeline stages is not qualified
 * by "(...)" vs "{...}", so a deferred brace-group stage still needs the
 * same environ/cwd save-and-restore as a standalone subshell --
 * exec_group_stage_inline() applies it unconditionally (unlike
 * exec_group()'s is_subshell-gated version). See
 * test_exec_group_pipeline_stage() in test/sh-engine.c.
 */

/* A subshell environment (2.12) gets its own copy of the positional
 * parameters: "( set -- x )" must not renumber the caller's, any more
 * than "( cd / )" moves it.
 *
 * take-then-replace rather than a dedicated copy routine: the take
 * leaves the live list empty and hands this frame the only pointer to
 * the caller's array, and __sh_params_replace() builds the subshell's
 * own copy from it -- one owner per array at every moment, which makes
 * nesting safe. Returns -1 on OOM with the caller's list already
 * restored. */
static int params_subshell_enter(struct sh_params *saved, struct sh_funcs *fsaved)
    __attribute__((nonnull(1)));
static int params_subshell_enter(struct sh_params *saved, struct sh_funcs *fsaved)
{
	__sh_params_take(saved);
	if (__sh_params_replace(saved->v, saved->n) < 0) {
		__sh_params_install(saved);
		return -1;
	}
	/* 2.9.5's functions are subshell-scoped for the same reason: a
	 * "( f() { ...; } )" must not define f in the caller, and the
	 * subshell must still see the functions the caller had. */
	__sh_funcs_take(fsaved);
	if (__sh_funcs_copy(fsaved) < 0) {
		__sh_funcs_install(fsaved);
		__sh_params_install(saved);
		return -1;
	}
	return 0;
}

static void params_subshell_leave(struct sh_params *saved, struct sh_funcs *fsaved)
{
	__sh_funcs_install(fsaved);
	__sh_params_install(saved);
}

struct env_snapshot {
	char **names;
	char **vals;
	size_t n;
};

static void free_env_snapshot(struct env_snapshot *es) __attribute__((nonnull(1)));
static void free_env_snapshot(struct env_snapshot *es)
{
	size_t i;
	for (i = 0; i < es->n; i++) { __free(es->names[i]); __free(es->vals[i]); }
	__free((void *)es->names);
	__free((void *)es->vals);
	es->names = 0; es->vals = 0; es->n = 0;
}

/* Returns 0 on success, -1 on OOM (nothing left half-allocated either way). */
static int env_snapshot_take(struct env_snapshot *es) __attribute__((nonnull(1)));
static int env_snapshot_take(struct env_snapshot *es)
{
	size_t n, i, namesbytes, valsbytes;
	es->names = 0; es->vals = 0; es->n = 0;
	for (n = 0; __environ && __environ[n]; n++) continue;
	if (!n) return 0;
	if (!__size_mul_checked(n, sizeof *es->names, &namesbytes) ||
	    !__size_mul_checked(n, sizeof *es->vals, &valsbytes)) return -1;
	es->names = (char **)__malloc(namesbytes);
	es->vals = (char **)__malloc(valsbytes);
	if (!es->names || !es->vals) { __free((void *)es->names); __free((void *)es->vals); es->names = 0; es->vals = 0; return -1; }
	for (i = 0; i < n; i++) {
		const char *e = __environ[i];
		const char *eq = strchr(e, '=');
		size_t nlen = eq ? (size_t)(eq - e) : strlen(e);
		size_t namebytes;
		char *name = __size_add_checked(nlen, 1, &namebytes) ?
			__malloc(namebytes) : 0;
		if (name) {
			__ownership_writable_span(name, nlen);
			__ownership_readable_span(e, nlen);
			memcpy(name, e, nlen);
			name[nlen] = 0;
		}
		es->names[i] = name;
		es->vals[i] = xstrdup(eq ? eq + 1 : "");
		if (!es->names[i] || !es->vals[i]) { es->n = i + 1; free_env_snapshot(es); return -1; }
	}
	es->n = n;
	return 0;
}

static int name_in_snapshot(const struct env_snapshot *es, const char *name)
    __attribute__((nonnull(1)));
static int name_in_snapshot(const struct env_snapshot *es, const char *name)
{
	size_t i;
	for (i = 0; i < es->n; i++) if (strcmp(es->names[i], name) == 0) return 1;
	return 0;
}

/* Restores `environ` to exactly the state `es` recorded: every name the
 * body added gets unsetenv()'d, every name/value `es` remembers gets
 * setenv(..., 1)'d back -- driven entirely through the public API so
 * setenv.c's putenv()-ownership bookkeeping stays correct. */
static void env_snapshot_restore(const struct env_snapshot *es)
    __attribute__((nonnull(1)));
static void env_snapshot_restore(const struct env_snapshot *es)
{
	size_t n, i, curbytes;
	char **cur;

	for (n = 0; __environ && __environ[n]; n++) continue;
	cur = (n && __size_mul_checked(n, sizeof *cur, &curbytes)) ?
		(char **)__malloc(curbytes) : 0;
	if (n && cur) {
		for (i = 0; i < n; i++) {
			const char *e = __environ[i];
			const char *eq = strchr(e, '=');
			size_t nlen = eq ? (size_t)(eq - e) : strlen(e);
			size_t nmbytes;
			char *nm = __size_add_checked(nlen, 1, &nmbytes) ?
				__malloc(nmbytes) : 0;
			if (nm) {
				__ownership_writable_span(nm, nlen);
				__ownership_readable_span(e, nlen);
				memcpy(nm, e, nlen);
				nm[nlen] = 0;
			}
			cur[i] = nm;
		}
		for (i = 0; i < n; i++)
			if (cur[i] && !name_in_snapshot(es, cur[i])) unsetenv(cur[i]);
		for (i = 0; i < n; i++) __free(cur[i]);
		__free((void *)cur);
	}
	/* n && !cur is OOM listing what to remove: best effort continues
	 * below and still gets every remembered value put back, even though
	 * a variable the body added with no snapshot counterpart cannot be
	 * removed in that case. */
	for (i = 0; i < es->n; i++) setenv(es->names[i], es->vals[i], 1);
}

/* Runs `cmd`'s own redirections bracketing its body, and -- for
 * SH_CMD_SUBSHELL only -- environ/cwd save-and-restore around that.
 * Same -1/0 convention as every other __sh_exec_*() helper. */

/* ==== Compound commands (XCU 2.9.4) ====================================
 *
 * `if`, `while`, `until`, `for` and function definitions are implemented
 * below. `case` alone is not: it still lexes as an ordinary WORD, so
 * script.c's preflight refuses it by name before this file ever sees it.
 *
 * Three properties are shared by all four:
 *
 *  - **They run in this process, with no subshell.** 2.12's subshell
 *    scope doesn't include control-flow constructs, so a `cd` inside a
 *    `for` body moves the shell, and an assignment in an `if` branch
 *    survives the `fi`. exec_group() supplies the "( ... )" subshell
 *    semantics and is deliberately not reused here.
 *  - **The condition's status is not the construct's status.** An `if`
 *    with no branch taken, a `while` whose body never runs, and a `for`
 *    over an empty word list are all 0. Each keeps the condition's
 *    status in a local and only ever writes *status from a body --
 *    letting the condition fall through would make `if false; then
 *    ...; fi` wrongly report 1.
 *  - **A pending `exit` has to get out.** These are loops and branches
 *    around __sh_exec_list(), so each checks __sh_flow_pending() at
 *    every point it would otherwise iterate again or evaluate another
 *    condition -- without that, `while true; do exit 0; done` never
 *    terminates.
 */

/* 2.9.4: an `if` with no branch taken, or a `while`/`for` whose body
 * never runs, exits 0 -- why *status starts at 0 and is only ever
 * written by a body. */
// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int exec_if(const struct sh_command *cmd, int *status)
    __attribute__((nonnull(1, 2)));
// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int exec_if(const struct sh_command *cmd, int *status)
{
	const struct sh_ifarm *a;

	*status = 0;
	for (a = cmd->u.ifcmd.arms; a; a = a->next) {
		int cond_status;
		int rc = __sh_exec_list(a->cond, &cond_status);
		if (rc) return rc;
		if (__sh_flow_pending()) { *status = cond_status; return 0; }
		if (cond_status == 0) return __sh_exec_list(a->body, status);
	}
	if (cmd->u.ifcmd.else_body) return __sh_exec_list(cmd->u.ifcmd.else_body, status);
	return 0;
}

/* `until` is `while` with the test inverted (`cmd->u.loop.until`). */
// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int exec_loop(const struct sh_command *cmd, int *status)
    __attribute__((nonnull(1, 2)));
// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int exec_loop(const struct sh_command *cmd, int *status)
{
	*status = 0;
	for (;;) {
		int cond_status, rc;

		rc = __sh_exec_list(cmd->u.loop.cond, &cond_status);
		if (rc) return rc;
		if (__sh_flow_pending()) { *status = cond_status; return 0; }
		if (cmd->u.loop.until ? (cond_status == 0) : (cond_status != 0)) return 0;

		rc = __sh_exec_list(cmd->u.loop.body, status);
		if (rc) return rc;
		if (__sh_flow_pending()) return 0;
	}
}

/* 2.9.4 "The for Loop": "the list of words following in shall be
 * expanded to generate a list of items.  Then, the variable name shall
 * be set to each item, in turn, and the compound-list executed each
 * time; zero items runs it zero times, exit status 0.
 *
 * The words are expanded exactly the way a simple command's arguments
 * are -- one wordexp() per source word with WRDE_APPEND -- so "for f in
 * *.c" iterates the matched files without being a special case here.
 * One XCU 2.6 rule this consequently does *not* deliver (belongs to
 * wordexp.c, which states it): a parameter expansion's result is not
 * field-split, so "for f in $LIST" is one item, not $LIST's fields --
 * matching what `cmd $LIST` already does, deliberately not special-cased
 * here. test/sh-engine.c pins it. (Empty-field deletion does work,
 * though: "for f in $UNSET" runs zero times, not once with an empty item.)
 *
 * Setting `name` is setenv(), the only variable store this shell has, so
 * the loop variable is *exported* to children -- the same pre-existing
 * deviation `X=1; cmd` already has, not a new one.
 *
 * Each setenv() gets the same read-only check exec_assignment_only()
 * uses. Since `name` doesn't change between iterations, marking it
 * read-only rejects the very first assignment and the whole `for`
 * completes immediately with *status nonzero and its body never entered
 * -- matching bash/dash. An empty item list still exits 0 with no
 * diagnostic: the check only fires where an item would actually be
 * assigned. */
// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int exec_for(const struct sh_command *cmd, int *status)
    __attribute__((nonnull(1, 2)));
// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int exec_for(const struct sh_command *cmd, int *status)
{
	wordexp_t we;
	const struct sh_word *w;
	int first = 1, rc = 0;
	size_t i;

	*status = 0;

	/* 2.9.4: "Omitting: in word" is equivalent to "in \"$@\"". Reads
	 * param.c's list directly rather than expanding the literal text
	 * "\"$@\"" through __wordexp_sh(), so a `for f; do` doesn't depend on
	 * the quoting of a string this file would have to synthesize. */
	if (!cmd->u.forloop.have_in) {
		int n = __sh_param_count(), k;
		for (k = 1; k <= n; k++) {
			if (__sh_readonly_is(cmd->u.forloop.name)) {
				(void)fprintf(stderr, "%s: readonly variable\n", cmd->u.forloop.name);
				*status = 1;
				break;
			}
			if (setenv(cmd->u.forloop.name, __sh_param_get(k), 1) < 0) return -1;
			rc = __sh_exec_list(cmd->u.forloop.body, status);
			if (rc) break;
			if (__sh_flow_pending()) break;
		}
		return rc;
	}

	if (!cmd->u.forloop.words) return 0; /* `for f in ; do` -- no items, exit 0 */

	for (w = cmd->u.forloop.words; w; w = w->next) {
		if (__wordexp_sh(w->text, &we, first ? 0 : WRDE_APPEND)) {
			if (!first) wordfree(&we);
			return -1; /* same meaning as in spawn_stage() */
		}
		first = 0;
	}

	for (i = 0; i < we.we_wordc; i++) {
		if (__sh_readonly_is(cmd->u.forloop.name)) {
			(void)fprintf(stderr, "%s: readonly variable\n", cmd->u.forloop.name);
			*status = 1;
			break;
		}
		if (setenv(cmd->u.forloop.name, we.we_wordv[i], 1) < 0) { rc = -1; break; }
		rc = __sh_exec_list(cmd->u.forloop.body, status);
		if (rc) break;
		if (__sh_flow_pending()) break;
	}
	wordfree(&we);
	return rc;
}

/* The body of any compound command, run in this process. Both callers --
 * exec_group() for a standalone "(...)"/"{...}"/if/while/for, and
 * exec_group_stage_inline() for one as a pipeline stage -- route through
 * one dispatcher rather than reading cmd->u.group.body directly, so a
 * kind added later can't be wired into one path and silently forgotten
 * in the other; the default arm reports -1 rather than silently running
 * an empty list. */
/* 2.9.5: a function definition exits 0 if declared successfully. Nothing
 * is expanded here -- storing the raw source text is exactly what
 * "expansions happen each time the function is called" requires. */
static int exec_funcdef(const struct sh_command *cmd, int *status)
    __attribute__((nonnull(1, 2)));
static int exec_funcdef(const struct sh_command *cmd, int *status)
{
	if (__sh_func_define(cmd->u.funcdef.name, cmd->u.funcdef.func_text) < 0) {
		(void)fprintf(stderr, "%s: cannot define function\n", cmd->u.funcdef.name);
		*status = 1;
		return 0;
	}
	*status = 0;
	return 0;
}

// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int exec_compound(const struct sh_command *cmd, int *status)
    __attribute__((nonnull(1)));
// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int exec_compound(const struct sh_command *cmd, int *status)
{
	switch (cmd->kind) {
	case SH_CMD_FUNCDEF:
		return exec_funcdef(cmd, status);
	case SH_CMD_SUBSHELL:
	case SH_CMD_BRACE:
		return __sh_exec_list(cmd->u.group.body, status);
	case SH_CMD_IF:
		return exec_if(cmd, status);
	case SH_CMD_LOOP:
		return exec_loop(cmd, status);
	case SH_CMD_FOR:
		return exec_for(cmd, status);
	default:
		return -1;
	}
}

/* cmd is required: `int is_subshell = cmd->kind == SH_CMD_SUBSHELL;` is
 * this function's first real statement, unconditional. status is
 * required too -- `*status = 1;` in the `if (failed)` branch is a real,
 * reachable direct dereference, and no real caller of this function
 * (exec_group_stage_inline() aside, which is a separate function with
 * its own contract) ever passes it a NULL status. */
// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int exec_group(const struct sh_command *cmd, int *status)
    __attribute__((nonnull(1, 2)));
// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int exec_group(const struct sh_command *cmd, int *status)
{
	struct redir_state rs;
	int failed = 0;
	int rc;
	struct env_snapshot es;
	struct sh_params ps;
	struct sh_funcs fs;
	char *oldcwd = 0;
	unsigned oldumask = 0;
	int is_subshell = cmd->kind == SH_CMD_SUBSHELL;

	rs.saves = 0; rs.n = rs.cap = 0;
	if (apply_redirs(cmd->redirs, &rs, &failed)) { restore_fds(&rs); return -1; }
	if (failed) { restore_fds(&rs); *status = 1; return 0; }

	if (is_subshell) {
		oldcwd = getcwd(0, 0);
		oldumask = __umask_get();
		if (env_snapshot_take(&es)) { free(oldcwd); restore_fds(&rs); return -1; }
		if (params_subshell_enter(&ps, &fs)) {
			env_snapshot_restore(&es);
			free_env_snapshot(&es);
			free(oldcwd);
			restore_fds(&rs);
			return -1;
		}
	}

	rc = exec_compound(cmd, status);

	if (is_subshell) {
		/* "( exit 3 )" exits *the subshell*, not the shell; consuming the
		 * pending unwind here keeps the rest of the caller's program
		 * running. A brace group deliberately doesn't do this, since
		 * "{ exit 3; }" runs in the current process environment and
		 * really is the shell exiting. */
		if (__sh_flow_pending()) __sh_flow_clear();
		params_subshell_leave(&ps, &fs);
		env_snapshot_restore(&es);
		free_env_snapshot(&es);
		if (oldcwd) { chdir(oldcwd); free(oldcwd); }
		umask((mode_t)oldumask);
	}
	restore_fds(&rs);
	return rc;
}

/* ==== Command substitution (XCU 2.6.3) =================================
 *
 * 2.6.3: run command in a subshell environment and replace the
 * substitution with its standard output, trailing newlines stripped.
 *
 * "Subshell environment" reuses exec_group()'s environ/cwd
 * snapshot-and-restore plus redir_state bracketing unchanged, rather
 * than growing a second notion of isolation. The genuinely new piece is
 * "standard output of the command": the list's stdout has to end up
 * somewhere this process can read back.
 *
 * ---- Why a temporary file and not a pipe -----------------------------
 *
 * __sh_exec_list() runs to completion *in this process* before this
 * function regains control, so nobody could drain a pipe while the
 * substituted commands fill it -- a substitution producing more than one
 * pipe buffer (65536 bytes) would wedge this process against itself
 * silently. Draining concurrently needs a thread or a fork(), and this
 * file deliberately uses neither (see the "still no fork()" discussion
 * above).
 *
 * tmpfile() has neither problem: seekable, so writers finish before the
 * read happens, with no size limit beyond the filesystem's; and
 * created-then-unlinked, so the capture is gone once the last handle
 * closes even if this process dies mid-substitution. Trade-off: the
 * output makes a round trip through %TEMP% instead of staying in
 * memory, and isn't visible until the whole list finishes -- which costs
 * nothing, since 2.6.3's result is the complete output anyway.
 *
 * fd 2 is deliberately left alone: only stdout is captured, so a
 * substituted command's stderr passes through to the shell's own, which
 * is what makes a failing "$(...)" say why.
 */

/* Reads everything left in `fd` into a freshly __malloc'd,
 * NUL-terminated buffer, storing the exact captured byte count in
 * `out_len`. Returns NULL on OOM or a read error. A capture containing
 * null bytes reads truncated at the first one to any string caller --
 * 2.6.3 leaves that behavior unspecified. */
static char *slurp_fd(int fd, size_t *out_len)
{
	char *buf = 0;
	size_t len = 0, cap = 0;

	for (;;) {
		ssize_t n;
		size_t need;
		if (!__size_add_checked(len, 4096 + 1, &need)) { __free(buf); return 0; }
		if (need > cap) {
			size_t nc;
			char *nb;
			if (cap) {
				if (!__size_mul_checked(cap, 2, &nc)) { __free(buf); return 0; }
			} else {
				nc = 8192;
			}
			while (need > nc) {
				if (!__size_mul_checked(nc, 2, &nc)) { __free(buf); return 0; }
			}
			nb = __malloc(nc);
			if (!nb) { __free(buf); return 0; }
			if (buf) {
				size_t i;
				for (i = 0; i < len; i++) nb[i] = buf[i];
			}
			__free(buf);
			buf = nb;
			cap = nc;
		}
		__ownership_writable_span(buf + len, 4096);
		n = read(fd, buf + len, 4096);
		if (n < 0) { __free(buf); return 0; }
		if (n == 0) break;
		len += (size_t)n;
	}
	if (!buf) { buf = __malloc(1); if (!buf) return 0; }
	buf[len] = 0;
	*out_len = len;
	return buf;
}

/* libc.h's documented contract: *out NULL and *status untouched on
 * failure; *out a __malloc'd capture and *status the exit status on
 * success. */
int __sh_cmdsub(const char *program, char **out, int *status)
{
	struct sh_list *list;
	struct redir_state rs;
	struct env_snapshot es;
	struct sh_params ps;
	struct sh_funcs fs;
	char *oldcwd;
	unsigned oldumask;
	char *buf;
	int saved_last;
	FILE *tf;
	int tfd, rc, st = 0;
	size_t len = 0;

	*out = 0;
	list = __sh_parse(program, 0, 0);
	if (!list) return -1;

	tf = tmpfile();
	if (!tf) { __sh_list_free(list); return -1; }
	tfd = fileno(tf);
	if (tfd < 0) { (void)fclose(tf); __sh_list_free(list); return -1; }

	/* Anything this process has buffered for its own stdout belongs on
	 * the *real* stdout, not in the capture -- fd 1 is about to point
	 * somewhere else, and stdio's buffer does not know that. */
	if (fflush(stdout)) {
		(void)fclose(tf);
		__sh_list_free(list);
		return -1;
	}

	rs.saves = 0; rs.n = rs.cap = 0;
	if (save_fd(&rs, 1) || dup2(tfd, 1) < 0) {
		restore_fds(&rs);
		(void)fclose(tf);
		__sh_list_free(list);
		return -1;
	}

	oldcwd = getcwd(0, 0);
	oldumask = __umask_get();
	if (env_snapshot_take(&es)) {
		free(oldcwd);
		restore_fds(&rs);
		(void)fclose(tf);
		__sh_list_free(list);
		return -1;
	}
	if (params_subshell_enter(&ps, &fs)) {
		env_snapshot_restore(&es);
		free_env_snapshot(&es);
		free(oldcwd);
		restore_fds(&rs);
		(void)fclose(tf);
		__sh_list_free(list);
		return -1;
	}

	saved_last = sh_last_status;
	rc = __sh_exec_list(list, &st);

	/* 2.6.3's subshell environment: "$(exit 3)" is a substitution whose
	 * status is 3, never the calling shell exiting. */
	if (__sh_flow_pending()) __sh_flow_clear();
	/* That subshell environment includes $?: `false; echo "$(true)$?"`
	 * must print 1, not the substitution's own last status. The
	 * substitution's status still reaches 2.9.1's "no command name"
	 * rule through cmdsub_status above, not through this variable. */
	sh_last_status = saved_last;
	params_subshell_leave(&ps, &fs);
	env_snapshot_restore(&es);
	free_env_snapshot(&es);
	if (oldcwd) { chdir(oldcwd); free(oldcwd); }
	umask((mode_t)oldumask);
	if (fflush(stdout)) rc = -1; /* while fd 1 is still the capture */
	restore_fds(&rs);
	__sh_list_free(list);

	if (rc) { (void)fclose(tf); return -1; }

	if (lseek(tfd, 0, SEEK_SET) < 0) { (void)fclose(tf); return -1; }
	buf = slurp_fd(tfd, &len);
	(void)fclose(tf);
	if (!buf) return -1;

	/* 2.6.3: "removing sequences of one or more <newline> characters at
	 * the end of the substitution. Embedded <newline> characters before
	 * the end of the output shall not be removed". */
	len = strnlen(buf, len);
	while (len && buf[len - 1] == '\n') len--;
	buf[len] = 0;

	*out = buf;
	*status = st;
	cmdsub_status = st;
	cmdsub_generation++;
	return 0;
}

// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
int __sh_exec_command(const struct sh_command *cmd, int *status)
{
	if (cmd->kind == SH_CMD_SIMPLE) return exec_simple(cmd, status);
	return exec_group(cmd, status);
}

/* ==== Pipelines of any length (XCU 2.9.2) =============================== */

/* Runs a compound-command pipeline stage's body in this process, once
 * every real (SH_CMD_SIMPLE) stage in the pipeline has already been
 * spawned (see exec_group()'s "still no fork()" discussion above for why
 * that ordering makes this safe in-process). The caller has already
 * dup2()'d this stage's pipe ends onto fd 0/1; this function applies
 * `cmd`'s own redirections on top, runs the body with environ/cwd
 * save-and-restore around it (2.12 applies subshell semantics to every
 * pipeline stage, unlike the standalone case), and restores fds/environ/
 * cwd before returning, since there's no child process to discard them
 * for free. Returns 0 with *status set, or -1 if redirections fail to
 * apply or the body hits something this shell can't execute. */
// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int exec_group_stage_inline(const struct sh_command *cmd, int *status)
    __attribute__((nonnull(1, 2)));
// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
static int exec_group_stage_inline(const struct sh_command *cmd, int *status)
{
	struct redir_state rs;
	int failed = 0;
	struct env_snapshot es;
	struct sh_params ps;
	struct sh_funcs fs;
	char *oldcwd;
	unsigned oldumask;
	int rc;

	rs.saves = 0; rs.n = rs.cap = 0;
	if (apply_redirs(cmd->redirs, &rs, &failed)) { restore_fds(&rs); return -1; }
	if (failed) { restore_fds(&rs); *status = 1; return 0; }

	oldcwd = getcwd(0, 0);
	oldumask = __umask_get();
	if (env_snapshot_take(&es)) { free(oldcwd); restore_fds(&rs); return -1; }
	if (params_subshell_enter(&ps, &fs)) {
		env_snapshot_restore(&es);
		free_env_snapshot(&es);
		free(oldcwd);
		restore_fds(&rs);
		return -1;
	}

	rc = exec_compound(cmd, status);

	/* 2.12 puts every pipeline stage in a subshell environment regardless
	 * of "(...)" vs "{...}", so an `exit` here exits that subshell only --
	 * unlike the standalone brace group exec_group() lets through. */
	if (__sh_flow_pending()) __sh_flow_clear();
	params_subshell_leave(&ps, &fs);
	env_snapshot_restore(&es);
	free_env_snapshot(&es);
	if (oldcwd) { chdir(oldcwd); free(oldcwd); }
	umask((mode_t)oldumask);
	restore_fds(&rs);
	return rc;
}

/* Wires this stage's fd 0/1 onto its neighboring pipe ends as 2.9.2
 * requires, save_fd()-protected so the caller's restore_fds() undoes
 * just this. Returns -1 on OOM, 0 otherwise. Split out because pass 1
 * (a SH_CMD_SIMPLE stage, wired and spawned immediately) and pass 2 (a
 * deferred compound-command stage, wired again once it's its turn) need
 * identical wiring at different times. */
static int wire_stage_stdio(struct redir_state *rs, int (*pipes)[2], size_t n, size_t i)
    __attribute__((nonnull(1, 2)));
static int wire_stage_stdio(struct redir_state *rs, int (*pipes)[2], size_t n, size_t i)
{
	if (i > 0) {
		if (save_fd(rs, 0)) return -1;
		if (dup2(pipes[i - 1][0], 0) < 0) return -1;
	}
	if (i + 1 < n) {
		if (save_fd(rs, 1)) return -1;
		if (dup2(pipes[i][1], 1) < 0) return -1;
	}
	return 0;
}

// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
int __sh_exec_pipeline(const struct sh_pipeline *pl, int *status)
{
	size_t n = pl->ncommands, i;
	int (*pipes)[2] = 0;
	pid_t *pids = 0;
	int *statuses = 0;
	unsigned char *deferred = 0; /* 1 iff commands[i] is a compound
	                                command still waiting for pass 2 */
	int abort_unsupported = 0;
	int rc;

	/* The grammar never produces an empty pipeline, but this is checked
	 * explicitly rather than left an unstated invariant: every allocation
	 * and index below is sized off n or n-1, and an unchecked n==0 would
	 * underflow n-1 to SIZE_MAX. */
	if (n == 0) return -1;

	if (n == 1) {
		/* Routes back through __sh_exec_command so a lone subshell or
		 * brace group still reports its own -1 rather than this file
		 * assuming SH_CMD_SIMPLE. */
		rc = __sh_exec_command(&pl->commands[0], status);
		if (rc) return rc;
		if (pl->bang) *status = (*status == 0);
		sh_last_status = *status;
		return 0;
	}

	/* Two compound-command stages directly adjacent, with no real spawned
	 * stage between them, is the one case the "still no fork()" design
	 * above can't make safe (see that discussion): refused up front,
	 * before anything is allocated or spawned, via the usual -1
	 * convention rather than risk a silent hang. */
	for (i = 0; i + 1 < n; i++) {
		if (pl->commands[i].kind != SH_CMD_SIMPLE && pl->commands[i + 1].kind != SH_CMD_SIMPLE)
			return -1;
	}

	{
		size_t pidsbytes, statusesbytes, pipesbytes, deferredbytes;
		if (!__size_mul_checked(n, sizeof *pids, &pidsbytes) ||
		    !__size_mul_checked(n, sizeof *statuses, &statusesbytes) ||
		    !__size_mul_checked(n - 1, sizeof *pipes, &pipesbytes) ||
		    !__size_mul_checked(n, sizeof *deferred, &deferredbytes)) return -1;
		pids = __malloc(pidsbytes);
		statuses = __malloc(statusesbytes);
		pipes = __malloc(pipesbytes);
		deferred = __malloc(deferredbytes);
		if (!pids || !statuses || !pipes || !deferred) {
			__free(pids); __free(statuses); __free(pipes); __free(deferred);
			return -1;
		}
		memset(deferred, 0, deferredbytes);
	}

	/* Every pipe is created up front, O_CLOEXEC: if creation fails partway
	 * through, only the ones already made need cleaning up -- nothing has
	 * been spawned yet. */
	for (i = 0; i + 1 < n; i++) {
		if (pipe2(pipes[i], O_CLOEXEC) < 0) {
			size_t j;
			for (j = 0; j < i; j++) { (void)close(pipes[j][0]); (void)close(pipes[j][1]); }
			__free(pids); __free(statuses); __free(pipes); __free(deferred);
			return -1;
		}
	}

	/* Pass 1: spawn every real (SH_CMD_SIMPLE) stage, in order, so that by
	 * the time pass 2 runs any compound-command stage's body, every stage
	 * that could be on the other end of one of its pipes already exists
	 * and is running concurrently. A compound-command stage is left
	 * entirely untouched here; pass 2 handles it once it's its turn. */
	for (i = 0; i < n; i++) {
		struct redir_state rs;
		stage_result_t sr;
		int failed = 0;
		int unsupported;
		unsigned long gen0 = cmdsub_generation;

		sr.kind = 1;
		sr.special = 0;
		sr.had_name = 1;

		if (pl->commands[i].kind != SH_CMD_SIMPLE) {
			deferred[i] = 1;
			continue;
		}

		rs.saves = 0; rs.n = rs.cap = 0;
		if (!abort_unsupported) {
			/* 2.9.2's pipe hookup applied *before* the command's own
			 * redirs list, so e.g. "cmd 2>&1 | next" merges cmd's stderr
			 * into the pipe (2.7's left-to-right ordering then applies
			 * the explicit "2>&1" on top). */
			unsupported = wire_stage_stdio(&rs, pipes, n, i) ||
			              apply_redirs(pl->commands[i].redirs, &rs, &failed);
			if (!unsupported && !failed)
				unsupported = run_stage(&pl->commands[i], &sr, 0);
			if (unsupported) {
				abort_unsupported = 1;
			} else if (failed) {
				/* 2.8.1: this stage fails without running; the rest of
				 * the pipeline still runs normally (its reader just sees
				 * immediate EOF from this stage's never-written end). */
				sr.special = 1;
			}
			restore_fds(&rs);
		}

		/* Close this process's own copies of the pipe ends handed off to
		 * a spawned child, unconditionally -- an aborted or failed stage
		 * must free these exactly like a successful one, or the pipeline
		 * hangs or leaks regardless. A deferred stage's neighboring ends
		 * are left open (skipped via the `continue` above); pass 2 still
		 * needs them. */
		if (i > 0) (void)close(pipes[i - 1][0]);
		if (i + 1 < n) (void)close(pipes[i][1]);

		pids[i] = sr.kind ? -1 : sr.normal;
		statuses[i] = sr.kind ? cmdsub_status_rule(&sr, gen0) : 0;
	}

	/* Pass 2: run every compound-command stage's body, left to right, now
	 * that pass 1 has spawned every real stage. Whichever neighbor
	 * produces a deferred stage's input or consumes its output is by now
	 * either a real, already-running process, or an earlier deferred
	 * stage that has already finished and closed its end. */
	for (i = 0; i < n; i++) {
		struct redir_state rs;
		int st = 0;

		if (!deferred[i]) continue;

		if (!abort_unsupported) {
			rs.saves = 0; rs.n = rs.cap = 0;
			if (wire_stage_stdio(&rs, pipes, n, i) ||
			    exec_group_stage_inline(&pl->commands[i], &st)) {
				abort_unsupported = 1;
			}
			restore_fds(&rs);
		}

		if (i > 0) (void)close(pipes[i - 1][0]);
		if (i + 1 < n) (void)close(pipes[i][1]);

		pids[i] = -1;
		statuses[i] = st;
	}

	/* Every pipe end in this process has been closed by the two passes
	 * above; what remains open is only each spawned child's own inherited
	 * copy, letting a downstream reader see EOF once its writers finish. */
	for (i = 0; i < n; i++) {
		if (pids[i] < 0) continue;
		rc = wait_status(pids[i]);
		statuses[i] = rc; /* an unexpected waitpid() failure here propagates
		                   * rather than fabricating a fake success */
	}

	rc = statuses[n - 1];
	__free(pids);
	__free(statuses);
	__free(pipes);
	__free(deferred);

	if (abort_unsupported) return -1; /* *status left untouched, per this file's convention */

	*status = pl->bang ? (rc == 0) : rc;
	sh_last_status = *status;
	return 0;
}

/* a is required: `__sh_exec_pipeline(&a->pipeline, status)` is this
 * function's first statement. status is required too: `*status != 0`/
 * `*status == 0` in the and/or short-circuit tests further down are
 * real, directly-reachable dereferences of this function's own, not
 * merely forwarded ones, and __sh_exec_list() below always passes a
 * real status. */
// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
int __sh_exec_andor(const struct sh_andor *a, int *status)
{
	int rc = __sh_exec_pipeline(&a->pipeline, status);
	if (rc) return rc;
	for (a = a->next; a; a = a->next) {
		/* An `exit` or `return` anywhere in the and-or list ends it,
		 * whatever the status would have selected next. Checked before
		 * the short-circuit tests so "exit 0 && cmd" runs no cmd. */
		if (__sh_flow_pending()) return 0;
		if (a->op == SH_AO_AND && *status != 0) continue;
		if (a->op == SH_AO_OR && *status == 0) continue;
		rc = __sh_exec_pipeline(&a->pipeline, status);
		if (rc) return rc;
	}
	return 0;
}

/* Nesting depth of __sh_exec_list(). A pending `exit` must survive every
 * *inner* return but must not survive the outermost one, or the next
 * program this process runs would find the flag still set and execute
 * nothing, silently. Clearing it exactly where the unwind has nowhere
 * left to go is what makes the flag a control-flow signal, not a latch. */
static unsigned exec_list_depth;

// NOLINTNEXTLINE(misc-no-recursion) -- shell execution recursively evaluates the parsed AST and is command-nesting bounded
int __sh_exec_list(const struct sh_list *list, int *status)
{
	const struct sh_list_item *it;
	int rc = 0;
	*status = 0;
	if (!list) return 0;
	exec_list_depth++;
	for (it = list->items; it; it = it->next) {
		rc = __sh_exec_andor(it->andor, status);
		if (rc) break;
		if (__sh_flow_pending()) break;
		/* SH_SEP_AMP: true backgrounding is future work, so an async item
		 * still just runs synchronously, like SH_SEP_SEQ/SH_SEP_END. */
	}
	/* Back at the outermost list: no frame above can consume an unwind,
	 * so neither flag may survive into whatever runs next in this
	 * process. A `return` reaching here had no function to return from
	 * and was already diagnosed by the built-in; dropping it stops it
	 * from silently truncating an unrelated later program. */
	if (--exec_list_depth == 0) { flow_exit_pending = 0; flow_return_pending = 0; }
	return rc;
}
