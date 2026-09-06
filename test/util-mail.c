/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for `mailx` (XCU mailx(1p), src/util/mailx.c) -- the
 * one utility this project's own POSIX-utilities plan originally
 * deferred ("infrastructure this plan doesn't build") and later built
 * for real. Same shape as test/util-fileops.c/test/sh-main.c (see their
 * headers): obj/bin/mailx.exe is spawned as a real process via
 * __spawn()+waitpid(), and the shell built-in is exercised too through
 * `obj/sh/sh.exe -c`, confirming both callers of __util_mailx_main()
 * (src/internal/util.h) agree.
 *
 * Every fixture lives inside one scratch directory named with this
 * process's own pid, cleaned up (best-effort, independent of mailx
 * itself) on the way out -- same reasoning as util-fileops.c's own
 * raw_rmtree() comment.
 *
 * The core claim this file is here to prove, not merely assert: two
 * mailx processes appending to the *same* mbox file at the same real
 * time (real concurrency -- spawned back to back with no wait in
 * between, exactly the technique test/sh-main.c uses to avoid fork(),
 * which Wine cannot run) never corrupt it. concurrent_append_test()
 * below spawns several children, waits for all of them, then
 * independently re-parses the raw file (its own from-scratch boundary
 * scan, not by calling back into mailx -- the same "don't verify a
 * utility using itself" discipline util-fileops.c's raw_rmtree() uses)
 * and checks every message survived exactly once, in one piece.
 *
 * Spec pages consulted (https://pubs.opengroup.org/onlinepubs/9699919799/):
 *   utilities/mailx.html
 */
/* setenv()/unsetenv() below are gated behind _POSIX_SOURCE/
 * _POSIX_C_SOURCE/_XOPEN_SOURCE/_GNU_SOURCE/_BSD_SOURCE in ntlibc's own
 * include/stdlib.h, none of which a plain -std=c99 build defines on its
 * own. Same fix, same reasoning, as test/posix-stdlib.c's own
 * top-of-file _GNU_SOURCE define. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>

extern char **environ;
int __spawn(const char *path, char *const argv[], char *const envp[]);

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* ---- the one local user mailx will ever deliver to ---------------------
 * src/util/mailx.c's current_user() is getpwuid(getuid()), and every send
 * below has to name that same user as its recipient or it is refused as
 * "user unknown" (mailx.c's addr_is_current_user()). The two <pwd.h>
 * backends disagree on what that resolves to (src/misc/nt/pwd.c vs.
 * src/misc/linux/pwd.c, same split test/pwd.c already audits): NT
 * synthesizes pw_name from %USERNAME%/%USER%, so this file can pick any
 * name it likes and export it; Linux reads the real /etc/passwd via
 * getuid() and ignores USERNAME entirely, so the only name that will ever
 * work there is whatever getpwuid(getuid())->pw_name already is on this
 * host. test_user is set up once in main() accordingly. */
#ifdef __linux__
static char test_user[256];
#else
static const char *test_user = "mtestuser";
#endif

/* ---- locating obj/bin/mailx.exe and obj/sh/sh.exe ---------------------
 * Same walk-up-from-argv[0] technique as test/util-fileops.c's
 * find_obj_root()/path_for(). */
static char obj_root[1024];

/* Strips the trailing "/last-component" (or "\...") off `path` in
 * place. Returns 0 on success, -1 if `path` has no separator left to
 * strip at. */
static int strip_last_component(char *path)
{
	size_t i;

	for (i = strlen(path); i > 0; i--)
		if (path[i - 1] == '/' || path[i - 1] == '\\') break;
	if (i == 0) return -1;
	path[i - 1] = 0;
	return 0;
}

static int find_obj_root(const char *argv0)
{
	if (!argv0 || !*argv0) return -1;
	if (strlen(argv0) >= sizeof obj_root) return -1;
	strcpy(obj_root, argv0);

	if (strip_last_component(obj_root) != 0) return -1; /* strip "/util-mail.exe" */
	if (strip_last_component(obj_root) != 0) return -1; /* strip "/test" */

	return 0;
}

static void path_for(char *out, size_t outlen, const char *rel)
{
	char sep = strchr(obj_root, '\\') ? '\\' : '/';
	char relcopy[256];
	size_t i;

	strncpy(relcopy, rel, sizeof relcopy - 1);
	relcopy[sizeof relcopy - 1] = 0;
	if (sep == '\\')
		for (i = 0; relcopy[i]; i++)
			if (relcopy[i] == '/') relcopy[i] = '\\';
	snprintf(out, outlen, "%s%c%s", obj_root, sep, relcopy);
}

static char mailx_path[1024], sh_path[1024];
static char scratch[128];

static void mkpath(char *out, size_t outsz, const char *rel)
{
	snprintf(out, outsz, "%s/%s", scratch, rel);
}

/* Independent teardown of the scratch tree -- its own opendir()/
 * readdir()/unlink()/rmdir() walk, never mailx itself, so cleanup never
 * depends on the correctness of the thing under test (same reasoning
 * as test/util-fileops.c's own raw_rmtree()). */
static void raw_rmtree(const char *path)
{
	struct stat st;
	DIR *d;
	struct dirent *de;

	if (lstat(path, &st) < 0) return;
	if (S_ISDIR(st.st_mode)) {
		d = opendir(path);
		if (d) {
			while ((de = readdir(d)) != NULL) {
				char child[600];
				if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
				snprintf(child, sizeof child, "%s/%s", path, de->d_name);
				raw_rmtree(child);
			}
			closedir(d);
		}
		rmdir(path);
	} else {
		unlink(path);
	}
}

/* ---- spawning with stdin from a file and stdout/stderr captured ------- */

static int run_prog(const char *prog, char *const *args, const char *infile,
	const char *outfile, const char *errfile)
{
	int in = -1, out, err;
	int s0 = -1, s1, s2, pid, status;

	out = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	err = open(errfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (out < 0 || err < 0) { if (out >= 0) close(out); if (err >= 0) close(err); return -1; }
	if (infile) {
		in = open(infile, O_RDONLY);
		if (in < 0) { close(out); close(err); return -1; }
	}

	s1 = dup(1); s2 = dup(2);
	if (in >= 0) s0 = dup(0);
	if (in >= 0) dup2(in, 0);
	dup2(out, 1);
	dup2(err, 2);
	close(out); close(err);
	if (in >= 0) close(in);

	pid = __spawn(prog, args, environ);

	if (s0 >= 0) { dup2(s0, 0); close(s0); }
	dup2(s1, 1); close(s1);
	dup2(s2, 2); close(s2);

	if (pid < 0) return -1;
	if (waitpid(pid, &status, 0) != pid) return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static int slurp_into(const char *path, char *buf, size_t buflen)
{
	FILE *f = fopen(path, "rb");
	size_t n;
	if (!f) { buf[0] = 0; return -1; }
	n = fread(buf, 1, buflen - 1, f);
	buf[n] = 0;
	fclose(f);
	return 0;
}

static void write_file(const char *path, const char *text)
{
	FILE *f = fopen(path, "wb");
	if (!f) { fails++; printf("FAIL: cannot write %s\n", path); return; }
	fputs(text, f);
	fclose(f);
}

/* Reads a whole file into a malloc'd buffer (not NUL-safe-required,
 * mbox content is text); returns NULL on failure. Independent of
 * mailx's own slurp_fd() -- this is the verification path. */
static char *slurp_alloc(const char *path, size_t *outlen)
{
	FILE *f = fopen(path, "rb");
	char *buf;
	long sz;
	if (!f) return 0;
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (sz < 0) { fclose(f); return 0; }
	buf = malloc((size_t)sz + 1);
	if (!buf) { fclose(f); return 0; }
	*outlen = fread(buf, 1, (size_t)sz, f);
	buf[*outlen] = 0;
	fclose(f);
	return buf;
}

/* Independent re-implementation of mbox's own "From " boundary rule
 * (mailx.html MBOX FORMAT), deliberately not sharing code with
 * src/util/mailx.c's parse_mbox() -- this is the check, not the thing
 * under test. Returns the number of boundaries found. */
static int count_boundaries(const char *buf, size_t len)
{
	size_t i = 0;
	int prev_blank = 1, n = 0;
	while (i < len) {
		size_t ls = i, j = i;
		while (j < len && buf[j] != '\n') j++;
		if (prev_blank && j - ls >= 5 && memcmp(buf + ls, "From ", 5) == 0) n++;
		prev_blank = (j == ls);
		i = (j < len) ? j + 1 : j;
	}
	return n;
}

/* Counts non-overlapping occurrences of `needle` in buf[0,len). Used by
 * concurrent_append_test() below to check each child's marker appears the
 * exact number of times its own body actually wrote it -- not once: each
 * marker leads all NLINES_PER_CHILD lines a child writes (see that loop),
 * so it legitimately recurs within one child's own message, and only a
 * count above or below that expected total points at real cross-writer
 * corruption. */
static int count_occurrences(const char *buf, size_t len, const char *needle)
{
	size_t needlelen = strlen(needle);
	size_t i = 0;
	int n = 0;
	if (needlelen == 0 || needlelen > len) return 0;
	while (i + needlelen <= len) {
		if (memcmp(buf + i, needle, needlelen) == 0) { n++; i += needlelen; }
		else i++;
	}
	return n;
}

/* ---- single-shot send/receive round-trip test -------------------------- */

static void roundtrip_test(void)
{
	char mbox[256], bodyfile[256], out[256], err[256];
	char *args[8];
	int rc;
	char buf[8192];

	mkpath(mbox, sizeof mbox, "rt-mbox");
	mkpath(bodyfile, sizeof bodyfile, "rt-body.txt");
	mkpath(out, sizeof out, "rt-out.txt");
	mkpath(err, sizeof err, "rt-err.txt");

	setenv("MAIL", mbox, 1);
#ifndef __linux__
	setenv("USERNAME", "mtestuser", 1);
#endif

	/* A body containing a literal "From " line, to exercise the
	 * mboxo-style escaping this file's own header comment documents. */
	write_file(bodyfile, "Hello there\nFrom the deep past\nGoodbye\n");

	args[0] = mailx_path; args[1] = (char *)"-s"; args[2] = (char *)"Round Trip";
	args[3] = (char *)test_user; args[4] = 0;
	rc = run_prog(mailx_path, args, bodyfile, out, err);
	CHECK(rc == 0);

	/* Raw on-disk form: the body's own "From " line must have been
	 * escaped with a leading '>' so it is never mistaken for a real
	 * message boundary. */
	{
		size_t rawlen = 0;
		char *raw = slurp_alloc(mbox, &rawlen);
		char hdrbuf[300];
		CHECK(raw != 0);
		if (raw) {
			CHECK(strstr(raw, "\n>From the deep past\n") != 0);
			CHECK(strstr(raw, "Subject: Round Trip\n") != 0);
			snprintf(hdrbuf, sizeof hdrbuf, "To: %s\n", test_user);
			CHECK(strstr(raw, hdrbuf) != 0);
			snprintf(hdrbuf, sizeof hdrbuf, "From: %s\n", test_user);
			CHECK(strstr(raw, hdrbuf) != 0);
			free(raw);
		}
	}

	/* -e: mail is present now. */
	{
		char *eargs[3];
		eargs[0] = mailx_path; eargs[1] = (char *)"-e"; eargs[2] = 0;
		rc = run_prog(mailx_path, eargs, 0, out, err);
		CHECK(rc == 0);
	}

	/* Receive Mode: headers-only first. */
	{
		char *hargs[3];
		hargs[0] = mailx_path; hargs[1] = (char *)"-H"; hargs[2] = 0;
		rc = run_prog(mailx_path, hargs, 0, out, err);
		CHECK(rc == 0);
		slurp_into(out, buf, sizeof buf);
		CHECK(strstr(buf, "1 message") != 0);
		CHECK(strstr(buf, "Round Trip") != 0);
	}

	/* Interactive: print message 1 (escaped line stays escaped -- the
	 * documented, deliberate mboxo-style lossy behavior), then delete
	 * and quit; the mailbox must end up empty. */
	{
		char cmdfile[256];
		char *rargs[2];
		mkpath(cmdfile, sizeof cmdfile, "rt-cmds.txt");
		write_file(cmdfile, "p 1\nd 1\nq\n");
		rargs[0] = mailx_path; rargs[1] = 0;
		rc = run_prog(mailx_path, rargs, cmdfile, out, err);
		CHECK(rc == 0);
		slurp_into(out, buf, sizeof buf);
		CHECK(strstr(buf, "Hello there") != 0);
		CHECK(strstr(buf, ">From the deep past") != 0);
		CHECK(strstr(buf, "Goodbye") != 0);
	}
	{
		size_t len = 0;
		char *raw = slurp_alloc(mbox, &len);
		CHECK(raw != 0 && len == 0);
		free(raw);
	}

	/* Undelete: send two, delete one, undelete it, quit -- both must
	 * still be present. */
	{
		char *args2[5];
		write_file(bodyfile, "msg one\n");
		args2[0] = mailx_path; args2[1] = (char *)"-s"; args2[2] = (char *)"One";
		args2[3] = (char *)test_user; args2[4] = 0;
		CHECK(run_prog(mailx_path, args2, bodyfile, out, err) == 0);

		write_file(bodyfile, "msg two\n");
		args2[2] = (char *)"Two";
		CHECK(run_prog(mailx_path, args2, bodyfile, out, err) == 0);

		{
			char cmdfile[256], *rargs[2];
			mkpath(cmdfile, sizeof cmdfile, "rt-cmds2.txt");
			write_file(cmdfile, "d 1\nu 1\nq\n");
			rargs[0] = mailx_path; rargs[1] = 0;
			CHECK(run_prog(mailx_path, rargs, cmdfile, out, err) == 0);
		}
		{
			size_t len = 0;
			char *raw = slurp_alloc(mbox, &len);
			CHECK(raw != 0);
			if (raw) { CHECK(count_boundaries(raw, len) == 2); free(raw); }
		}
	}

	/* Unknown recipient: refused, mailbox untouched. */
	{
		char *bargs[5];
		size_t before_len = 0, after_len = 0;
		char *before = slurp_alloc(mbox, &before_len);
		write_file(bodyfile, "should not be delivered\n");
		bargs[0] = mailx_path; bargs[1] = (char *)"-s"; bargs[2] = (char *)"Nope";
		bargs[3] = (char *)"somebodyelse"; bargs[4] = 0;
		rc = run_prog(mailx_path, bargs, bodyfile, out, err);
		CHECK(rc != 0);
		slurp_into(err, buf, sizeof buf);
		CHECK(strstr(buf, "user unknown") != 0);
		{
			char *after = slurp_alloc(mbox, &after_len);
			CHECK(before && after && before_len == after_len && memcmp(before, after, before_len) == 0);
			free(after);
		}
		free(before);
	}
}

/* ---- header-injection refusal ------------------------------------------
 * A `-s subject` or recipient address carrying a raw embedded newline
 * must never reach deliver_message()'s single snprintf() unescaped: that
 * would let it forge extra header lines, or even a blank-line-preceded
 * fake "From " boundary (mbox format's own message-boundary rule) inside
 * the delivered message, which reads back on the next receive as a
 * second, fully forged message. src/util/mailx.c's has_header_injection()
 * is what is supposed to catch this before deliver_message() ever runs;
 * these checks prove both injection points (subject, recipient) are
 * refused outright, and that the mailbox is left byte-for-byte untouched
 * when they are. */
static void header_injection_test(void)
{
	char mbox[256], bodyfile[256], out[256], err[256];
	char *args[5];
	char buf[8192];
	int rc;

	mkpath(mbox, sizeof mbox, "hi-mbox");
	mkpath(bodyfile, sizeof bodyfile, "hi-body.txt");
	mkpath(out, sizeof out, "hi-out.txt");
	mkpath(err, sizeof err, "hi-err.txt");
	setenv("MAIL", mbox, 1);
#ifndef __linux__
	setenv("USERNAME", "mtestuser", 1);
#endif
	write_file(bodyfile, "should not be delivered\n");

	/* A subject that tries to smuggle in a forged boundary + a second,
	 * fully forged message. */
	{
		char evil_subject[128];
		size_t before_len = 0, after_len = 0;
		char *before, *after;

		snprintf(evil_subject, sizeof evil_subject,
			"innocuous\n\nFrom forged@evil Thu Jan  1 00:00:00 1970\nSubject: forged");
		before = slurp_alloc(mbox, &before_len); /* mbox does not exist yet -- NULL is expected */

		args[0] = mailx_path; args[1] = (char *)"-s"; args[2] = evil_subject;
		args[3] = (char *)test_user; args[4] = 0;
		rc = run_prog(mailx_path, args, bodyfile, out, err);
		CHECK(rc != 0);
		slurp_into(err, buf, sizeof buf);
		CHECK(strstr(buf, "newline") != 0);

		after = slurp_alloc(mbox, &after_len);
		/* Refused before ever opening/appending to the mailbox: it must
		 * still not exist (same as `before`), never a corrupt partial
		 * file. */
		CHECK(before == 0 && after == 0);
		(void)before_len; (void)after_len;
		free(before); free(after);
	}

	/* A recipient address whose part before '@' still matches the one
	 * real local user (so addr_is_current_user() alone would accept it)
	 * but which smuggles a newline in after the '@'. */
	{
		char evil_rcpt[128];
		size_t after_len = 0;
		char *after;

		snprintf(evil_rcpt, sizeof evil_rcpt, "%s@host\nBcc: attacker@evil.example", test_user);
		args[0] = mailx_path; args[1] = (char *)"-s"; args[2] = (char *)"fine";
		args[3] = evil_rcpt; args[4] = 0;
		rc = run_prog(mailx_path, args, bodyfile, out, err);
		CHECK(rc != 0);
		slurp_into(err, buf, sizeof buf);
		CHECK(strstr(buf, "newline") != 0);

		after = slurp_alloc(mbox, &after_len);
		CHECK(after == 0);
		free(after);
	}
}

/* ---- shell built-in agreement ------------------------------------------ */

static void builtin_agreement_test(void)
{
	char mbox[256], bodyfile[256], out[256], err[256], cmd[512];
	char *args[5];
	int rc;

	mkpath(mbox, sizeof mbox, "bi-mbox");
	mkpath(bodyfile, sizeof bodyfile, "bi-body.txt");
	setenv("MAIL", mbox, 1);
#ifndef __linux__
	setenv("USERNAME", "mtestuser", 1);
#endif

	write_file(bodyfile, "builtin body\n");
	snprintf(cmd, sizeof cmd, "mailx -s BuiltinSubj %s < %s", test_user, bodyfile);
	args[0] = sh_path; args[1] = (char *)"-c"; args[2] = cmd; args[3] = 0;
	mkpath(out, sizeof out, "bi-out.txt");
	mkpath(err, sizeof err, "bi-err.txt");
	rc = run_prog(sh_path, args, 0, out, err);
	CHECK(rc == 0);

	{
		size_t len = 0;
		char *raw = slurp_alloc(mbox, &len);
		CHECK(raw != 0);
		if (raw) {
			CHECK(strstr(raw, "Subject: BuiltinSubj\n") != 0);
			CHECK(strstr(raw, "builtin body\n") != 0);
			free(raw);
		}
	}
}

/* ---- concurrent-append lock-safety test -------------------------------- */

#define NCHILD 6
#define NLINES_PER_CHILD 20

static void concurrent_append_test(void)
{
	char mbox[256];
	char bodyfiles[NCHILD][256];
	char outfiles[NCHILD][256];
	char errfiles[NCHILD][256];
	char markers[NCHILD][64];
	int pids[NCHILD];
	int i;

	mkpath(mbox, sizeof mbox, "conc-mbox");
	setenv("MAIL", mbox, 1);
#ifndef __linux__
	setenv("USERNAME", "mtestuser", 1);
#endif

	for (i = 0; i < NCHILD; i++) {
		char rel[64];
		/* 20 lines at up to ~56 bytes each (a marker's own 64-byte
		 * budget plus " line NN filler filler filler\n") is up to
		 * ~1120 bytes -- 512 was short by more than half and let
		 * strcat() below run this same stack frame's other locals
		 * over, which is exactly the mechanism behind the real
		 * segfault this size was found chasing. */
		char body[2048];
		int line;

		snprintf(markers[i], sizeof markers[i], "UNIQUE-MARKER-%d-abcdefgh", i);
		snprintf(rel, sizeof rel, "conc-body-%d.txt", i);
		mkpath(bodyfiles[i], sizeof bodyfiles[i], rel);
		snprintf(rel, sizeof rel, "conc-out-%d.txt", i);
		mkpath(outfiles[i], sizeof outfiles[i], rel);
		snprintf(rel, sizeof rel, "conc-err-%d.txt", i);
		mkpath(errfiles[i], sizeof errfiles[i], rel);

		body[0] = 0;
		for (line = 0; line < NLINES_PER_CHILD; line++) {
			char oneline[80];
			snprintf(oneline, sizeof oneline, "%s line %02d filler filler filler\n", markers[i], line);
			strcat(body, oneline);
		}
		write_file(bodyfiles[i], body);
	}

	/* Spawn all NCHILD children back to back, with no wait in between
	 * -- real concurrency, the same technique test/sh-main.c's own
	 * comment explains is used instead of fork() (Wine has no
	 * RtlCloneUserProcess). Each child gets its own dup2'd stdin/
	 * stdout/stderr at spawn time; __spawn() snapshots the handle
	 * table then, so redirecting again for the next child does not
	 * disturb one already spawned. */
	for (i = 0; i < NCHILD; i++) {
		char subj[32];
		char *args[5];
		int in, out, err;
		int s0, s1, s2;

		snprintf(subj, sizeof subj, "Conc%d", i);
		args[0] = mailx_path; args[1] = (char *)"-s"; args[2] = subj;
		args[3] = (char *)test_user; args[4] = 0;

		in = open(bodyfiles[i], O_RDONLY);
		out = open(outfiles[i], O_WRONLY | O_CREAT | O_TRUNC, 0600);
		err = open(errfiles[i], O_WRONLY | O_CREAT | O_TRUNC, 0600);
		CHECK(in >= 0 && out >= 0 && err >= 0);

		s0 = dup(0); s1 = dup(1); s2 = dup(2);
		dup2(in, 0); dup2(out, 1); dup2(err, 2);
		close(in); close(out); close(err);

		pids[i] = __spawn(mailx_path, args, environ);

		dup2(s0, 0); dup2(s1, 1); dup2(s2, 2);
		close(s0); close(s1); close(s2);

		CHECK(pids[i] >= 0);
	}

	for (i = 0; i < NCHILD; i++) {
		int status;
		if (pids[i] < 0) continue;
		CHECK(waitpid(pids[i], &status, 0) == pids[i]);
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}

	{
		size_t len = 0;
		char *raw = slurp_alloc(mbox, &len);
		CHECK(raw != 0);
		if (raw) {
			CHECK(count_boundaries(raw, len) == NCHILD);
			for (i = 0; i < NCHILD; i++) {
				const char *p = strstr(raw, markers[i]);
				CHECK(p != 0);
				/* Exactly NLINES_PER_CHILD occurrences of this child's
				 * marker in the whole file -- one per line its own body
				 * wrote (see the body-generation loop above), never
				 * more or fewer: if two writers had interleaved, a
				 * marker's lines could show up duplicated (split into,
				 * or replayed into, another message) or missing
				 * (clobbered). */
				CHECK(count_occurrences(raw, len, markers[i]) == NLINES_PER_CHILD);
			}
			free(raw);
		}
	}
}

int main(int argc, char **argv)
{
	if (argc < 1 || find_obj_root(argv[0]) < 0) {
		printf("FAIL: could not locate obj/ from argv[0]\n");
		return 1;
	}
	path_for(mailx_path, sizeof mailx_path, "bin/mailx.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

#ifdef __linux__
	{
		struct passwd *pw = getpwuid(getuid());
		if (!pw) {
			printf("FAIL: getpwuid(getuid()) found no entry for this host's real user -- "
				"mailx has no other user it could ever deliver to (see src/misc/linux/pwd.c)\n");
			return 1;
		}
		strncpy(test_user, pw->pw_name, sizeof test_user - 1);
		test_user[sizeof test_user - 1] = 0;
	}
#endif

	snprintf(scratch, sizeof scratch, "mailx-scratch-%d", (int)getpid());
	mkdir(scratch, 0700);

	roundtrip_test();
	header_injection_test();
	builtin_agreement_test();
	concurrent_append_test();

	unsetenv("MAIL");
	unsetenv("USERNAME");
	raw_rmtree(scratch);

	if (fails) { printf("%d check(s) failed\n", fails); return 1; }
	printf("ok\n");
	return 0;
}
