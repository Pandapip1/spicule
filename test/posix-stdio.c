/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit for <stdio.h>, cross-checked
 * against https://pubs.opengroup.org/onlinepubs/9699919799/functions/
 * <name>.html.  test/stdio.c already has ~430 broad sanity checks for
 * nearly every function here (see test/posix-coverage/stdio.md for the
 * function-by-function map of what it covers); this file adds the
 * clauses that file's checks do not exercise, with a citation on every
 * assertion. Run headless under Wine, same as test/stdio.c.
 */
/* strdup()/mkstemp()/fileno()/fmemopen()/open_memstream()/fseeko()/
 * ftello() are feature-test gated in include/string.h, include/stdlib.h
 * and include/stdio.h; same define most other tests in test/ already carry
 * for the same reason (see test/posix-glob.c's comment on this exact
 * define). */
#define _GNU_SOURCE
#include "test-policy.h"
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdint.h>
#include <limits.h>
#include <wchar.h>
#include <signal.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static char *make_tmp(const char *tmpl)
{
	char *t = strdup(tmpl);
	int fd = mkstemp(t);
	if (fd < 0) { free(t); return 0; }
	close(fd);
	return t;
}

/* fflush.html DESCRIPTION: "For a stream open for reading with an
 * underlying file description, if the file is not already at EOF, and
 * the file is one capable of seeking, the file offset of the underlying
 * open file description shall be set to the file position of the
 * stream, and any characters pushed back onto the stream by ungetc()
 * ... that have not subsequently been read from the stream shall be
 * discarded (without further changing the file offset)."  This applies
 * to any readable stream backed by a real fd, not just update ("+")
 * streams. */
static void test_fflush_read_stream(const char *name)
{
	FILE *f;
	int c, raw;
	char rawbuf[8];

	f = fopen(name, "wb");
	CHECK(f != 0);
	if (!f) return;
	CHECK(fputs("abcdefgh", f) == 0);
	CHECK(fclose(f) == 0);

	/* Part 1: fflush() must discard an unread pushed-back byte. */
	f = fopen(name, "rb");
	CHECK(f != 0);
	if (f) {
		CHECK((c = fgetc(f)) == 'a');
		CHECK((c = fgetc(f)) == 'b');
		CHECK(ungetc(c, f) == 'b');
		CHECK(fflush(f) == 0);
		CHECK((c = fgetc(f)) == 'c');
		CHECK(fclose(f) == 0);
	}

	/* Part 2: fflush() must resync the underlying fd's offset to the
	 * stream's position, so a raw read() on fileno(f) right after
	 * continues where the stream left off, not wherever read-ahead
	 * buffering left the fd. */
	f = fopen(name, "rb");
	CHECK(f != 0);
	if (f) {
		CHECK(setvbuf(f, 0, _IOFBF, 4096) == 0); /* force read-ahead beyond 2 bytes */
		CHECK((c = fgetc(f)) == 'a');
		CHECK((c = fgetc(f)) == 'b');
		CHECK(fflush(f) == 0);
		raw = read(fileno(f), rawbuf, 1);
		CHECK(raw == 1 && rawbuf[0] == 'c');
		CHECK(fclose(f) == 0);
	}
}

#if SPICULE_TEST(PASS, posix_stdio_fflush_nonseekable_read_stream) /* fflush() accepts a readable stream whose fd cannot seek.
	 * fflush.html DESCRIPTION states the read-stream action with an
	 * explicit seekability condition: "For a stream open for reading
	 * with an underlying file description, if the file is not already
	 * at EOF, and the file is one capable of seeking, the file offset
	 * of the underlying open file description shall be set to the file
	 * position of the stream, and any characters pushed back onto the
	 * stream by ungetc() or ungetwc() that have not subsequently been
	 * read from the stream shall be discarded (without further changing
	 * the file offset)."  A pipe, FIFO or console is not capable of
	 * seeking, so there is no offset to move and nothing has failed --
	 * which leaves only RETURN VALUE's success arm: "Upon successful
	 * completion, fflush() shall return 0; otherwise, it shall set the
	 * error indicator for the stream, return EOF, and set errno to
	 * indicate the error."
	 *
	 * Mechanism: src/stdio/buf.c's __fflush_locked() exempts memory
	 * streams from the resync and nothing else -- `if (ahead &&
	 * !f->is_mem)`.  A pipe-backed stream with read-ahead therefore
	 * still calls __file_seek(), which reaches src/unistd/lseek.c:18,
	 * `if (f->type != __FD_FILE) { errno = ESPIPE; return -1; }`.
	 * __fflush_locked() then latches f->err and returns -1, so fflush()
	 * returns EOF on a stream where nothing was wrong, ferror() reports
	 * an error that never happened, and fclose() -- which returns
	 * fflush()'s result (src/stdio/file.c:150) -- reports EOF for a
	 * stream that closed perfectly well.
	 *
	 * The condition to test is seekability, not is_mem: the fix is to
	 * treat an ESPIPE from the resync seek as "nothing to resync"
	 * rather than as a failure, the way the read-ahead distance is
	 * already ignored for a memory stream.  This is source-derived --
	 * it is spicule's own lseek() refusing a non-__FD_FILE fd, not an
	 * emulator artefact -- so it holds on Wine and on real NT alike.
	 * Re-enable when fflush() stops failing here. */
static void test_fflush_nonseekable_read_stream(void)
{
	int fds[2];
	FILE *f;

	CHECK(pipe(fds) == 0);
	CHECK(write(fds[1], "abcdefgh", 8) == 8);
	CHECK(close(fds[1]) == 0);

	f = fdopen(fds[0], "rb");
	CHECK(f != 0);
	if (!f) { close(fds[0]); return; }

	/* One byte consumed, seven sitting in the buffer: the read-ahead
	 * distance __fflush_locked() would try to seek back over. */
	CHECK(fgetc(f) == 'a');

	CHECK(fflush(f) == 0);		/* not seekable: nothing to resync */
	CHECK(ferror(f) == 0);		/* and so nothing to report */
	CHECK(fgetc(f) == 'b');		/* the stream is left undisturbed */
	CHECK(fclose(f) == 0);
}
#endif

/* fopen.html DESCRIPTION: on a stream open for update ("+"), "output is
 * not directly followed by input without an intervening call to
 * fflush() or to a file positioning function..., and input is not
 * directly followed by output without an intervening call to a file
 * positioning function, unless the input operation encounters
 * end-of-file." spicule's __toread/__towrite (src/stdio/buf.c) apply the
 * fflush/seek automatically on every direction switch, which is a
 * strict superset of what the standard requires (it makes the "shall
 * be preceded by" cases work too, not just leaves them as UB) -- so
 * this exercises exactly the sequences the clause calls out and expects
 * them to behave as if the intervening call had been made explicitly. */
static void test_update_stream_rule(const char *name)
{
	FILE *f;
	char buf[16];

	f = fopen(name, "wb+");
	CHECK(f != 0);
	if (!f) return;
	CHECK(fputs("0123456789", f) == 0);
	/* write directly followed by read: no explicit fflush/fseek */
	rewind(f);
	memset(buf, 0, sizeof buf);
	CHECK(fread(buf, 1, 5, f) == 5);
	CHECK(memcmp(buf, "01234", 5) == 0);
	/* read directly followed by write, mid-stream (not at EOF) */
	CHECK(fputs("XY", f) == 0);
	rewind(f);
	memset(buf, 0, sizeof buf);
	CHECK(fread(buf, 1, 10, f) == 10);
	CHECK(memcmp(buf, "01234XY789", 10) == 0);
	/* read to EOF directly followed by write (explicitly permitted by
	 * the "unless the input operation encounters end-of-file" clause) */
	fseek(f, 0, SEEK_END);
	CHECK(fgetc(f) == EOF);
	CHECK(fputs("!", f) == 0);
	rewind(f);
	memset(buf, 0, sizeof buf);
	CHECK(fread(buf, 1, 11, f) == 11);
	CHECK(memcmp(buf, "01234XY789!", 11) == 0);
	CHECK(fclose(f) == 0);
}

/* fread()/fwrite() describe the transfer as size*nmemb bytes.  That
 * product is caller-controlled and must be rejected before it wraps to a
 * smaller operation.  These streams are deliberately valid for the
 * requested direction; the failure is the unrepresentable byte count,
 * which is reported through both errno and the stream error indicator. */
static void test_block_io_size_overflow(void)
{
	unsigned char mem[2] = { 'x', 0 }, byte = 0;
	FILE *f;

	f = fmemopen(mem, sizeof mem, "r");
	CHECK(f != 0);
	if (f) {
		errno = 0;
		CHECK(fread(&byte, SIZE_MAX, 2, f) == 0);
		CHECK(errno == EOVERFLOW);
		CHECK(ferror(f));
		CHECK(fclose(f) == 0);
	}

	f = fmemopen(mem, sizeof mem, "w");
	CHECK(f != 0);
	if (f) {
		errno = 0;
		CHECK(fwrite(&byte, 2, SIZE_MAX, f) == 0);
		CHECK(errno == EOVERFLOW);
		CHECK(ferror(f));
		CHECK(fclose(f) == 0);
	}
}

/* Memory streams calculate a requested position from their current
 * position, buffered read-ahead, and buffered writes.  Each term can be
 * individually representable while their signed sum is not.  Exercise
 * all three arithmetic boundaries and require failure before the stream
 * position is changed. */
static void test_memory_stream_position_overflow(void)
{
	char mem[4] = "abc";
	char *out = 0;
	size_t outsz = 0;
	FILE *f;

	f = fmemopen(mem, sizeof mem, "r");
	CHECK(f != 0);
	if (f) {
		CHECK(fseeko(f, 1, SEEK_SET) == 0);
		errno = 0;
		CHECK(fseeko(f, (off_t)LLONG_MAX, SEEK_CUR) == -1);
		CHECK(errno == EOVERFLOW);
		CHECK(ftello(f) == 1);

		CHECK(fseeko(f, 0, SEEK_SET) == 0);
		CHECK(fgetc(f) == 'a');
		errno = 0;
		CHECK(fseeko(f, (off_t)LLONG_MIN, SEEK_CUR) == -1);
		CHECK(errno == EOVERFLOW);
		CHECK(ftello(f) == 1);
		CHECK(fclose(f) == 0);
	}

	f = open_memstream(&out, &outsz);
	CHECK(f != 0);
	if (f) {
		/* The logical endpoint still fits in off_t (off_t is 64-bit on
		 * every target here), but the extra byte needed for the mandatory
		 * terminator exceeds spicule's object-size range, PTRDIFF_MAX --
		 * see __file_write()'s own comment on that ceiling. PTRDIFF_MAX
		 * is the portable spelling of this boundary: it equals LLONG_MAX
		 * on a target where ptrdiff_t is 64-bit (x86_64, aarch64), so
		 * this is the same test there it always was, and it stays
		 * meaningful on i386, where ptrdiff_t is 32-bit. */
		CHECK(fseeko(f, (off_t)PTRDIFF_MAX - 1, SEEK_SET) == 0);
		CHECK(fputc('x', f) == 'x');
		CHECK(ftello(f) == (off_t)PTRDIFF_MAX);
		errno = 0;
		CHECK(fflush(f) == EOF);
		CHECK(errno == ENOMEM);

#if SIZE_MAX >= LLONG_MAX
		/* size_t covers off_t's whole range here, so a memory stream can
		 * actually be positioned at LLONG_MAX; what then overflows is
		 * ftello()'s own 64-bit off_t arithmetic. */
		CHECK(fseeko(f, (off_t)LLONG_MAX, SEEK_SET) == 0);
		CHECK(fputc('x', f) == 'x');
		errno = 0;
		CHECK(ftello(f) == (off_t)-1);
		CHECK(errno == EOVERFLOW);
		errno = 0;
		CHECK(fflush(f) == EOF);
		CHECK(errno == EOVERFLOW);
#else
		/* size_t (32-bit here) cannot hold a position anywhere near
		 * LLONG_MAX at all: mem_pos, which backs a memory stream's
		 * position, is a size_t byte offset into a heap buffer, and no
		 * heap object can span 2^63 bytes on this target regardless of
		 * off_t's own width. __file_seek() (src/stdio/buf.c) rejects the
		 * seek itself with EOVERFLOW rather than deferring to a later
		 * off_t-arithmetic overflow that a stream at this position could
		 * never actually reach. */
		errno = 0;
		CHECK(fseeko(f, (off_t)LLONG_MAX, SEEK_SET) == -1);
		CHECK(errno == EOVERFLOW);
		/* "Unmoved" means unmoved from the position the failed fflush()
		 * above actually left behind, not from the PTRDIFF_MAX seen at
		 * the ftello() before it: that fflush() failed inside
		 * __file_write() before mem_pos ever moved, so __fflush_locked()
		 * (src/stdio/buf.c) took its write-error path and discarded the
		 * buffered 'x' via f->wpos = 0 without ever writing it out. The
		 * byte is gone and mem_pos is still PTRDIFF_MAX - 1, so that is
		 * the position this rejected seek must have left in place. */
		CHECK(ftello(f) == (off_t)PTRDIFF_MAX - 1); /* seek failed: unmoved */
#endif
		/* Closing retries the intentionally impossible flush and may fail;
		 * its only purpose here is releasing the FILE object. */
		(void)fclose(f);
		free(out);
	}
}

/* setvbuf.html DESCRIPTION: "may be used after the stream ... is
 * associated with an open file but before any other operation ... is
 * performed on the stream." setvbuf.html RETURN VALUE: 0 on success,
 * non-zero if type is invalid or the request cannot be honored. */
static void test_setvbuf(const char *name)
{
	FILE *f;

	f = fopen(name, "w");
	CHECK(f != 0);
	if (!f) return;
	/* the very first operation on the stream: must succeed */
	CHECK(setvbuf(f, 0, _IOFBF, 1024) == 0);
	CHECK(fputs("hi", f) == 0);
	CHECK(fclose(f) == 0);

	/* an invalid mode is rejected */
	f = fopen(name, "w");
	CHECK(f != 0);
	if (f) {
		CHECK(setvbuf(f, 0, 12345, 0) != 0);
		CHECK(fclose(f) == 0);
	}

	/* setbuf(f, NULL) is equivalent to setvbuf(f, NULL, _IONBF, BUFSIZ):
	 * every byte written lands immediately, observable without an
	 * explicit fflush(). */
	f = fopen(name, "w");
	CHECK(f != 0);
	if (f) {
		FILE *g;
		setbuf(f, 0);
		CHECK(fputc('Z', f) == 'Z');
		g = fopen(name, "r");
		CHECK(g != 0);
		if (g) {
			CHECK(fgetc(g) == 'Z');
			CHECK(fclose(g) == 0);
		}
		CHECK(fclose(f) == 0);
	}

	/* setlinebuf(3) (BSD, not POSIX -- src/stdio/buf.c's own comment:
	 * "BSD's void wrapper" over setvbuf()): "equivalent to
	 * setvbuf(stream, NULL, _IOLBF, 0)".  Checked the same observable
	 * way test/stdio.c checks _IOLBF directly a few lines above this
	 * test's own file: a complete line lands without an explicit
	 * fflush(), while a trailing partial line does not, until one is
	 * given. */
	f = fopen(name, "w");
	CHECK(f != 0);
	if (f) {
		FILE *g;
		char buf[32];

		setlinebuf(f);
		CHECK(fputs("one\ntwo", f) == 0);

		g = fopen(name, "r");
		CHECK(g != 0);
		if (g) {
			memset(buf, 0, sizeof buf);
			CHECK(fread(buf, 1, sizeof buf, g) >= 4);
			CHECK(strncmp(buf, "one\n", 4) == 0);
			CHECK(fclose(g) == 0);
		}

		CHECK(fflush(f) == 0);
		g = fopen(name, "r");
		CHECK(g != 0);
		if (g) {
			memset(buf, 0, sizeof buf);
			CHECK(fread(buf, 1, sizeof buf, g) == 7);
			CHECK(strcmp(buf, "one\ntwo") == 0);
			CHECK(fclose(g) == 0);
		}
		CHECK(fclose(f) == 0);
	}
}

/* ungetc.html RETURN VALUE: "Otherwise, it shall return EOF" -- e.g. for
 * c == EOF (tested in test/stdio.c already) or a non-readable stream. */
static void test_ungetc_errors(const char *name)
{
	FILE *f = fopen(name, "w");
	CHECK(f != 0);
	if (!f) return;
	CHECK(ungetc('x', f) == EOF); /* stream not open for reading */
	CHECK(fclose(f) == 0);
}

/* fprintf.html RETURN VALUE: "Upon successful completion ... shall
 * return the number of bytes transmitted." (checked here against a
 * real FILE*, not just the sprintf/snprintf path test/stdio.c already
 * exercises heavily.) */
static void test_fprintf_return(const char *name)
{
	FILE *f = fopen(name, "w");
	CHECK(f != 0);
	if (!f) return;
	CHECK(fprintf(f, "%d-%s", 12, "ab") == 5);
	CHECK(fclose(f) == 0);
}

/* clearerr.html DESCRIPTION: "clears the end-of-file and error
 * indicators for the stream pointed to by stream." Both, independently
 * of each other -- test/stdio.c exercises feof/ferror but not a stream
 * that has both indicators set at once, cleared by one call. */
static void test_clearerr_both(const char *name)
{
	FILE *f = fopen(name, "rb");
	CHECK(f != 0);
	if (!f) return;
	CHECK(fseek(f, 0, SEEK_END) == 0);
	CHECK(fgetc(f) == EOF);          /* sets the EOF indicator */
	CHECK(feof(f));
	CHECK(fputc('z', f) == EOF);     /* not writable: sets the error indicator too */
	CHECK(ferror(f));
	CHECK(feof(f) && ferror(f));     /* both set at once */
	clearerr(f);
	CHECK(!feof(f));
	CHECK(!ferror(f));
	CHECK(fclose(f) == 0);
}

/* perror.html DESCRIPTION: "First (if s is not a null pointer and the
 * character pointed to by s is not the null byte), the string pointed
 * to by s followed by a <colon> and a <space>. Then an error message
 * string followed by a <newline>." "The error messages ... shall be
 * the same as those returned by strerror()." "The perror() function
 * shall not change the orientation of the standard error stream" (not
 * meaningfully testable here -- spicule's stderr is always byte
 * oriented, there is no wide-orientation mode to switch into) and,
 * from the "Error Checking" application-usage note (implicit in the
 * DESCRIPTION's silence about errno), a successful perror() call must
 * not itself change errno -- captured by comparing errno before/after.
 * Output is captured through a real pipe on fd 2, the same technique
 * test/posix-strings.c's test_assert_message_and_death() uses for the
 * same reason (a named file isn't guaranteed visible the way an
 * inherited/duplicated fd is, and this also works under the native
 * ASan harness). No child process is needed here since perror() does
 * not abort -- the redirect/restore happens in this process. */
static void capture_stderr(void (*fn)(void), char *out, size_t outsz)
{
	int p[2], saved;
	ssize_t n;

	CHECK(pipe(p) == 0);
	saved = dup(2);
	CHECK(saved >= 0);
	CHECK(dup2(p[1], 2) == 2);
	close(p[1]);

	fn();

	dup2(saved, 2);
	close(saved);
	n = read(p[0], out, outsz - 1);
	close(p[0]);
	out[n > 0 ? n : 0] = 0;
}

static void perror_prefixed(void) { errno = ENOENT; perror("myprefix"); }
static void perror_noprefix_null(void) { errno = EACCES; perror(0); }
static void perror_noprefix_empty(void) { errno = EACCES; perror(""); }

#if SPICULE_TEST(PASS, posix_stdio_fflush_null_covers_stderr) /* fflush(NULL) includes stderr and stdin.
	 * on the list it walks.  fflush.html DESCRIPTION: "If stream is a
	 * null pointer, fflush() shall perform this flushing action on all
	 * streams for which the behavior is defined above."  stderr is such
	 * a stream: it is open for writing with an underlying file
	 * description, which is exactly the case the paragraph above it
	 * defines.
	 *
	 * Mechanism: src/stdio/file.c gives the three standard streams as
	 * file-scope statics (stdin_f/stdout_f/stderr_f) with no ->next,
	 * and only __file_new() ever pushes a FILE onto the __stdio_files
	 * list -- so none of the three is ever on it.  src/stdio/buf.c's
	 * fflush(NULL) walks that list plus stdout, by name, and nothing
	 * else:
	 *
	 *     if (__fflush_locked(stdout) < 0) r = EOF;
	 *     for (p = __stdio_files; p; p = p->next) ...
	 *
	 * stderr and stdin are simply missing.  That the omission is an
	 * oversight rather than a decision is visible two files away:
	 * __stdio_exit() flushes stdout AND stderr before walking the same
	 * list, because whoever wrote it knew the list does not contain
	 * them.
	 *
	 * stderr is unbuffered by default here (bufmode = _IONBF), so
	 * nothing is normally pending on it and the gap stays invisible --
	 * until a caller does what POSIX explicitly permits and gives
	 * stderr a buffer with setvbuf().  Then output that fflush(NULL)
	 * was told to push out sits in the buffer instead.
	 *
	 * The same omission has a second, input-side face: fflush(NULL)
	 * does not apply the read-stream action to stdin either, so an
	 * outstanding ungetc() pushback on a seekable stdin survives a call
	 * that POSIX says discards it.  Only the stderr half is asserted
	 * below, because it needs no assumption about what stdin is
	 * connected to when the suite runs.
	 *
	 * Re-enable when fflush(NULL) covers all three standard streams. */
static void test_fflush_null_covers_stderr(void)
{
	static char ebuf[BUFSIZ];
	char got[64];
	int p[2], saved;
	ssize_t n;

	CHECK(pipe(p) == 0);
	saved = dup(2);
	CHECK(saved >= 0);
	CHECK(dup2(p[1], 2) == 2);
	close(p[1]);

	/* POSIX lets a caller buffer stderr; "the standard error stream
	 * ... shall not be fully buffered" only constrains the default. */
	CHECK(setvbuf(stderr, ebuf, _IOLBF, sizeof ebuf) == 0);
	CHECK(fputs("hello", stderr) >= 0);	/* no newline: still buffered */

	CHECK(fflush(NULL) == 0);		/* must reach fd 2 now */

	dup2(saved, 2);
	close(saved);
	setvbuf(stderr, 0, _IONBF, 0);		/* put stderr back */

	n = read(p[0], got, sizeof got - 1);
	close(p[0]);
	got[n > 0 ? n : 0] = 0;
	CHECK(n == 5 && !strcmp(got, "hello"));
}
#endif

static void test_perror(void)
{
	char buf[256];
	int e;

	/* "s followed by a <colon> and a <space>. Then an error message
	 * string ... followed by a <newline>." and "shall be the same as
	 * those returned by strerror()". */
	capture_stderr(perror_prefixed, buf, sizeof buf);
	{
		char want[256];
		strcpy(want, "myprefix: ");
		strcat(want, strerror(ENOENT));
		strcat(want, "\n");
		CHECK(strcmp(buf, want) == 0);
	}

	/* "if s is not a null pointer and the character pointed to by s is
	 * not the null byte" -- s == NULL: no prefix/colon/space at all. */
	capture_stderr(perror_noprefix_null, buf, sizeof buf);
	{
		char want[256];
		strcpy(want, strerror(EACCES));
		strcat(want, "\n");
		CHECK(strcmp(buf, want) == 0);
	}

	/* s == "" (not null, but *s == '\0'): same "no prefix" case. */
	capture_stderr(perror_noprefix_empty, buf, sizeof buf);
	{
		char want[256];
		strcpy(want, strerror(EACCES));
		strcat(want, "\n");
		CHECK(strcmp(buf, want) == 0);
	}

	/* perror() itself must not change errno on success (the
	 * "Error Checking" note only makes sense if a successful call
	 * leaves errno as the caller set it -- otherwise the "clearerr()
	 * then check errno" recipe it describes couldn't distinguish a
	 * write failure from perror() clobbering errno on its own). */
	e = ENOENT;
	errno = e;
	capture_stderr(perror_prefixed, buf, sizeof buf);
	CHECK(errno == ENOENT);
	(void)e;
}

/* popen.html/pclose.html: on NT, src/stdio/misc.c's own header comment
 * documents that popen() hands the command to cmd.exe /c rather than a
 * POSIX shell, since there is no /bin/sh there -- that divergence is
 * real and not tested here (the *string* handed to the interpreter is
 * cmd syntax, not sh syntax).  On Linux there is no such divergence:
 * misc.c's popen() resolves a real "sh" and hands it "-c", so the
 * commands below run as genuine sh(1p) syntax; they were kept to forms
 * ("echo hello", "exit N") that happen to mean the same thing in both,
 * so nothing here needed to change to cover both platforms for real.
 * Everything else the spec promises about the *stream* and
 * *pclose()*'s return, though, is plain fd/process plumbing that does
 * not depend on which interpreter runs the command, and
 * src/stdio/misc.c implements all of it -- so it is asserted for real
 * below rather than waved off as "no POSIX shell". */
/* popen() spawns a real child process: cmd.exe (via %ComSpec%) on NT,
 * "sh" (via PATH) on Linux -- both per src/stdio/misc.c. Under Wine
 * (the normal `make check` target) cmd.exe is a real, present binary,
 * and a real --platform=linux build always has a real "sh" on PATH, so
 * both reach every assertion below for real. Under this project's
 * native-ASan harness, a distinct build from either of those, there is
 * no cmd.exe at all -- __spawn's ability to reach *this test binary*
 * again under a special-cased argv (as test/posix-strings.c's spawn
 * helper does) does not extend to an arbitrary Windows executable path,
 * so popen() legitimately fails to spawn there. That is an environment
 * limitation, not a popen()/pclose() bug, so each block below degrades
 * to a note instead of a hard failure when popen() itself returns NULL;
 * every assertion still runs for real wherever a real shell is
 * actually reachable. */
static void test_popen(void)
{
	FILE *f;
	int st;
	char buf[256];

	/* popen.html DESCRIPTION, mode 'r': "the file descriptor
	 * fileno(stream) in the calling process ... shall be the readable
	 * end of the pipe" -- reading actually returns the child's output,
	 * and writing to it fails (not the writable end). */
	f = popen("echo hello", "r");
	if (!f) {
		printf("note: popen() could not spawn a command interpreter in this environment (errno %d); popen/pclose \"r\" checks skipped\n", errno);
	} else {
		CHECK(fgets(buf, sizeof buf, f) != 0);
		CHECK(strstr(buf, "hello") != 0);
		errno = 0;
		CHECK(fputc('x', f) == EOF && errno == EBADF);
		/* pclose.html RETURN VALUE: "Upon successful return, pclose()
		 * shall return the termination status of the command language
		 * interpreter" -- cmd.exe /c "echo hello" exits 0. */
		st = pclose(f);
		CHECK(st != -1);
		CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
	}

	/* mode 'w': "STDIN_FILENO shall be the readable end of the pipe,
	 * and ... fileno(stream) in the calling process ... shall be the
	 * writable end" -- writing succeeds, reading fails.  cmd.exe /c
	 * "exit 7" doesn't touch stdin at all, so what it does with the
	 * bytes written is unobserved here; what IS observed is that
	 * pclose() reports the exact exit status the interpreter used,
	 * which is the concrete, checkable form of "termination status of
	 * the command language interpreter" for this mode. */
	f = popen("exit 7", "w");
	if (!f) {
		printf("note: popen() could not spawn a command interpreter in this environment (errno %d); popen/pclose \"w\" checks skipped\n", errno);
	} else {
		CHECK(fputs("ignored\n", f) >= 0);
		errno = 0;
		CHECK(fgetc(f) == EOF && errno == EBADF);
		st = pclose(f);
		CHECK(st != -1);
		CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 7);
	}

	/* popen.html ERRORS ("may fail"): "[EINVAL] The mode argument is
	 * invalid." src/stdio/misc.c rejects any mode[0] other than 'r'/
	 * 'w' outright, before ever trying to spawn anything, so this one
	 * holds regardless of whether cmd.exe is reachable. */
	errno = 0;
	CHECK(popen("echo hi", "x") == 0 && errno == EINVAL);

	/* pclose.html ERRORS: "[ECHILD] The status of the child process
	 * could not be obtained" -- a legitimate way this happens without
	 * touching any spicule-internal state: the application itself reaps
	 * the popen'd child (e.g. via a wait()/waitpid(-1, ...) loop that
	 * doesn't know or care it came from popen(), which POSIX permits),
	 * so by the time pclose() calls waitpid() on that same pid there is
	 * nothing left to wait for. */
	f = popen("exit 0", "w");
	if (!f) {
		printf("note: popen() could not spawn a command interpreter in this environment (errno %d); pclose() ECHILD check skipped\n", errno);
	} else {
		CHECK(waitpid(-1, &st, 0) > 0); /* reaps popen()'s own child first */
		errno = 0;
		CHECK(pclose(f) == -1 && errno == ECHILD);
	}
}

#if SPICULE_TEST(PASS, posix_stdio_popen_emfile) /* PASS: popen.html ERRORS "shall fail" clause: "[EMFILE]
       * {STREAM_MAX} streams are currently open in the calling
       * process."  Was N/A; the tag was wrong, and this is a
       * correction of the tag rather than of the decision.
       *
       * The reason recorded here has always been a test-economy
       * judgement, not a platform fact: driving the process to
       * STREAM_MAX purely to watch one more popen() fail is not a
       * popen()-specific behaviour -- every fopen()-family function
       * hits the same wall the same way, spicule has no
       * STREAM_MAX-specific logic in popen() to distinguish from the
       * generic "out of fd table / out of memory" paths fopen()
       * already exercises, and repeating it here would be an
       * expensive duplicate under a different function name.  That may
       * well be the right call.  But N/A asserts the clause is
       * *inapplicable on this platform*, and this one is perfectly
       * applicable: __fd_alloc() (src/internal/fd.c) returns EMFILE on
       * a full __fds[FD_MAX] table, and popen() reaches it like every
       * other stream constructor.  Nothing about NT makes the clause
       * meaningless.  A clause we chose not to exercise is UNIMPL.
       * The independent probe is inexpensive enough in practice and passes;
       * keep it as real coverage instead of a test-economy exception. */
static void test_popen_emfile(void)
{
	FILE *fs[8192];
	int i, n = 0;

	for (i = 0; i < 8192; i++) {
		fs[i] = popen("exit 0", "r");
		if (!fs[i]) break;
		n++;
	}
	CHECK(fs[n] == 0 && errno == EMFILE);
	for (i = 0; i < n; i++) pclose(fs[i]);
}
#endif

/* Everything below exists in src/ and links, but was named by no
 * assertion anywhere in the test/ tree before this (see
 * test/POSIX-GAP-ACCOUNTING.md's "implemented, but no assertion
 * anywhere in the test/ tree" list, which this closes for <stdio.h>).  These
 * are deliberately the cheap RETURN VALUE / DESCRIPTION clauses, not a
 * clause-by-clause audit -- the ledger's stdio.h section stays the
 * authority for that.  They run on real Windows in CI too, which is the
 * only authority for real-NT behaviour; nothing here depends on any
 * Wine-specific behaviour. */

/* putc.html RETURN VALUE: "shall return the value written"; putc() and
 * fputc() are equivalent except that putc() may be a macro evaluating
 * its stream argument more than once.  putc_unlocked.html: "versions of
 * ... putc() ... that ... may be safely used only within a scope
 * protected by flockfile()"; behaviour is otherwise identical. */
static void test_putc_family(const char *name)
{
	FILE *f;
	char buf[8];
	size_t n;

	f = fopen(name, "wb");
	CHECK(f != 0);
	if (!f) return;
	CHECK(putc('a', f) == 'a');
	CHECK(putc_unlocked('b', f) == 'b');
	/* putc.html: the value is written "as an unsigned char converted
	 * to an int", so a byte above 0x7f comes back positive, not
	 * sign-extended. */
	CHECK(putc((int)(unsigned char)0xfe, f) == 0xfe);
	CHECK(fclose(f) == 0);

	f = fopen(name, "rb");
	CHECK(f != 0);
	if (!f) return;
	n = fread(buf, 1, sizeof buf, f);
	CHECK(n == 3);
	CHECK(buf[0] == 'a');
	CHECK(buf[1] == 'b');
	CHECK((unsigned char)buf[2] == 0xfe);
	CHECK(fclose(f) == 0);
}

/* putchar.html: "equivalent to putc(c, stdout)", RETURN VALUE "the
 * value written".  Asserted without redirecting stdout: the only
 * observable effect is one extra newline in this test's own output,
 * which no harness parses. */
static void test_putchar_return(void)
{
	CHECK(putchar('\n') == '\n');
	CHECK(putchar_unlocked('\n') == '\n');
}

/* getchar.html: "equivalent to getc(stdin)"; RETURN VALUE "the next
 * byte ... as an unsigned char converted to an int", or EOF at
 * end-of-file.  stdin is repointed at a known file rather than trusted
 * to be anything in particular -- the gate runs with stdin from
 * /dev/null, CI on real Windows does not necessarily. */
static void test_getchar(const char *name)
{
	FILE *f;

	f = fopen(name, "wb");
	CHECK(f != 0);
	if (!f) return;
	CHECK(fputc('X', f) == 'X');
	CHECK(fputc((int)(unsigned char)0x80, f) == 0x80);
	CHECK(fclose(f) == 0);

	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	CHECK(getchar() == 'X');
	/* unsigned-char conversion, not sign extension */
	CHECK(getchar_unlocked() == 0x80);
	CHECK(getchar() == EOF);
	CHECK(feof(stdin));
}

/* ftell.html/fseek.html, off_t forms: "ftello() ... shall obtain the
 * current value of the file-position indicator"; fseeko() returns 0 on
 * success.  Same contract as ftell()/fseek(), which test/stdio.c
 * already covers -- what is new here is only that the off_t-typed
 * spellings exist and agree with them. */
static void test_fseeko_ftello(const char *name)
{
	FILE *f;
	off_t pos;

	f = fopen(name, "wb");
	CHECK(f != 0);
	if (!f) return;
	CHECK(fwrite("0123456789", 1, 10, f) == 10);
	pos = ftello(f);
	CHECK(pos == (off_t)10);
	CHECK(fseeko(f, (off_t)3, SEEK_SET) == 0);
	CHECK(ftello(f) == (off_t)3);
	CHECK(fseeko(f, (off_t)2, SEEK_CUR) == 0);
	CHECK(ftello(f) == (off_t)5);
	CHECK(fseeko(f, (off_t)0, SEEK_END) == 0);
	CHECK(ftello(f) == (off_t)10);
	CHECK(ftell(f) == 10L);
	CHECK(fclose(f) == 0);
}

/* flockfile.html: ftrylockfile() "shall return zero for success", and
 * the lock is recursive ("the lock count ... shall be incremented"), so
 * a nested acquisition must also succeed and needs a matching
 * funlockfile().  spicule is single-threaded today and src/stdio/file.c
 * implements all three as no-ops; the clause these assert is the
 * RETURN VALUE, which a no-op still has to get right. */
static void test_flockfile(const char *name)
{
	FILE *f = fopen(name, "wb");
	CHECK(f != 0);
	if (!f) return;
	flockfile(f);
	CHECK(ftrylockfile(f) == 0);
	funlockfile(f);
	funlockfile(f);
	CHECK(fclose(f) == 0);
}

/* vfprintf.html: the v-forms are "equivalent to ... with the variable
 * argument list replaced by arg", and return the same byte count.
 * Wrapped here so each one is reached through a real va_list. */
static int via_vfprintf(FILE *f, const char *fmt, ...)
{
	int r;
	va_list ap;
	va_start(ap, fmt);
	r = vfprintf(f, fmt, ap);
	va_end(ap);
	return r;
}

static int via_vsnprintf(char *b, size_t n, const char *fmt, ...)
{
	int r;
	va_list ap;
	va_start(ap, fmt);
	r = vsnprintf(b, n, fmt, ap);
	va_end(ap);
	return r;
}

static int via_vsprintf(char *b, const char *fmt, ...)
{
	int r;
	va_list ap;
	va_start(ap, fmt);
	r = vsprintf(b, fmt, ap);
	va_end(ap);
	return r;
}

static int via_vsscanf(const char *src, const char *fmt, ...)
{
	int r;
	va_list ap;
	va_start(ap, fmt);
	r = vsscanf(src, fmt, ap);
	va_end(ap);
	return r;
}

static int via_vfscanf(FILE *f, const char *fmt, ...)
{
	int r;
	va_list ap;
	va_start(ap, fmt);
	r = vfscanf(f, fmt, ap);
	va_end(ap);
	return r;
}

static int via_vdprintf(int fd, const char *fmt, ...)
{
	int r;
	va_list ap;
	va_start(ap, fmt);
	r = vdprintf(fd, fmt, ap);
	va_end(ap);
	return r;
}

/* vasprintf(3) (glibc/BSD, not POSIX -- asprintf()'s v-form, same
 * relationship vfprintf() has to fprintf()): allocates and returns the
 * formatted string itself, sized exactly, rather than writing into a
 * caller-supplied buffer. */
static int via_vasprintf(char **s, const char *fmt, ...)
{
	int r;
	va_list ap;
	va_start(ap, fmt);
	r = vasprintf(s, fmt, ap);
	va_end(ap);
	return r;
}

static void test_v_forms(const char *name)
{
	FILE *f;
	char buf[64];
	int fd, got;

	CHECK(via_vsnprintf(buf, sizeof buf, "%s-%d", "ab", 7) == 4);
	CHECK(strcmp(buf, "ab-7") == 0);
	/* vsnprintf.html RETURN VALUE: "the number of bytes that would
	 * have been written ... had n been sufficiently large", not the
	 * number actually written. */
	CHECK(via_vsnprintf(buf, 3, "%s-%d", "ab", 7) == 4);
	CHECK(strcmp(buf, "ab") == 0);

	memset(buf, 0, sizeof buf);
	CHECK(via_vsprintf(buf, "%d/%c", 42, 'z') == 4);
	CHECK(strcmp(buf, "42/z") == 0);

	got = 0;
	CHECK(via_vsscanf("  91x", "%d", &got) == 1);
	CHECK(got == 91);

	f = fopen(name, "wb");
	CHECK(f != 0);
	if (!f) return;
	CHECK(via_vfprintf(f, "%s=%d\n", "k", 5) == 4);
	CHECK(fclose(f) == 0);

	f = fopen(name, "rb");
	CHECK(f != 0);
	if (!f) return;
	got = 0;
	CHECK(via_vfscanf(f, "k=%d", &got) == 1);
	CHECK(got == 5);
	CHECK(fclose(f) == 0);

	/* dprintf.html: "equivalent to fprintf(), except that dprintf()
	 * shall write output to the file associated with the file
	 * descriptor fildes rather than ... a stream". */
	fd = open(name, O_WRONLY | O_TRUNC);
	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(dprintf(fd, "%s", "abcd") == 4);
	CHECK(via_vdprintf(fd, "%d", 12345) == 5);
	CHECK(close(fd) == 0);

	f = fopen(name, "rb");
	CHECK(f != 0);
	if (!f) return;
	memset(buf, 0, sizeof buf);
	CHECK(fread(buf, 1, sizeof buf - 1, f) == 9);
	CHECK(strcmp(buf, "abcd12345") == 0);
	CHECK(fclose(f) == 0);

	/* vasprintf.html-equivalent (see asprintf(3)): the returned byte
	 * count matches strlen() of the allocated string, mirroring
	 * test/stdio.c's own asprintf() coverage but reached through a
	 * real va_list, the same distinction every other via_v*() helper
	 * in this function makes for its non-v sibling. */
	{
		char *out = 0;
		got = via_vasprintf(&out, "%s=%d", "va", 99);
		CHECK(got == 5);
		CHECK(out && strcmp(out, "va=99") == 0);
		free(out);
	}
}

/* getc_unlocked.html.  DESCRIPTION: the _unlocked forms "shall be
 * functionally equivalent to the original versions, with the exception
 * that they are not required to be implemented in a fully thread-safe
 * manner", and "shall be thread-safe when used within a scope protected
 * by flockfile() ... and funlockfile()".  RETURN VALUE and ERRORS both
 * defer to getc()/getchar()/putc()/putchar().
 *
 * test_putc_family() and test_getchar() above already reach
 * putc_unlocked, putchar_unlocked and getchar_unlocked; getc_unlocked
 * was the one name in the family nothing in the tree had ever called
 * (test/POSIX-GAP-ACCOUNTING.md's <stdio.h> pair).  Asserted against
 * getc() on the same stream, inside a flockfile()/funlockfile() scope as
 * the page prescribes.  Pure library behaviour: Wine is a sound oracle.
 *
 * N/A, with the reason: the thread-safety clause itself.  spicule has no
 * threading to speak of (src/signal/signal.c's banner and the FILE
 * locking in src/stdio/file.c say as much), so "not required to be
 * thread-safe" and "thread-safe under flockfile()" have no observable
 * difference to test between. */
static void test_getc_unlocked(const char *name)
{
	FILE *f = fopen(name, "wb");
	int c;

	CHECK(f != 0);
	if (!f) return;
	CHECK(fwrite("Ab\200", 1, 3, f) == 3);
	CHECK(fclose(f) == 0);

	f = fopen(name, "rb");
	CHECK(f != 0);
	if (!f) return;
	flockfile(f);
	CHECK(getc_unlocked(f) == 'A');
	/* functionally equivalent to getc(): same stream, same position */
	CHECK(getc(f) == 'b');
	/* unsigned-char conversion, not sign extension */
	CHECK(getc_unlocked(f) == 0x80);
	c = getc_unlocked(f);
	CHECK(c == EOF);
	CHECK(feof(f));
	funlockfile(f);
	CHECK(fclose(f) == 0);
}

/* tmpnam.html (obsolescent).  DESCRIPTION: "The tmpnam() function shall
 * generate a string that is a valid pathname that does not name an
 * existing file"; RETURN VALUE: the internal-buffer form (a null
 * argument) has to answer the same way as the caller-buffer form.
 *
 * The clause is only worth as much as what it is for: the caller goes on
 * to create the file, and O_CREAT|O_EXCL is the only safe way to use a
 * name this function produces, so that create is asserted here rather
 * than the absence of a stat alone.
 *
 * This was a fenced BUG.  src/stdio/misc.c's tmpnam() called mkstemp()
 * on a "tmpnam_XXXXXX" template and handed back the name of the file
 * mkstemp had just created, so the exclusive create got [EEXIST] every
 * time and every call left a zero-byte tmpnam_* file in the current
 * directory; it generates the name with mktemp() now, which checks for
 * non-existence instead of creating.  (That function's comment records
 * why tempnam()'s create-then-unlink was not the route taken.)
 *
 * Filesystem-adjacent (it names, and the caller then creates, a path in
 * the current directory), so real-Windows CI is the authority; Wine
 * agreeing is weak evidence. */
static void test_tmpnam_does_not_create(void)
{
	char buf[L_tmpnam];
	char *a, *b;
	struct stat st;
	int fd;

	a = tmpnam(buf);
	CHECK(a == buf);
	if (!a) return;

	/* "a valid pathname that does not name an existing file" */
	CHECK(stat(a, &st) == -1);

	/* which is what makes the documented use -- an exclusive create on
	 * the returned name -- work rather than collide with itself. */
	fd = open(a, O_CREAT | O_EXCL | O_WRONLY, 0600);
	CHECK(fd >= 0);
	if (fd >= 0) { CHECK(close(fd) == 0); CHECK(remove(a) == 0); }

	/* and the internal-buffer form must behave the same way */
	b = tmpnam(NULL);
	CHECK(b != 0);
	if (b) CHECK(stat(b, &st) == -1);
}

/* tempnam.html (XSI, obsolescent).  DESCRIPTION: "shall generate a
 * pathname that may be used for a temporary file"; if dir "is a null
 * pointer or points to a string which is not a pathname for an
 * appropriate directory, the path prefix defined as P_tmpdir in the
 * <stdio.h> header shall be used"; pfx is "a string of up to five bytes
 * to be used as the beginning of the filename".  RETURN VALUE: "Upon
 * successful completion, tempnam() shall allocate space for a string,
 * put the generated pathname in that space, and return a pointer to it.
 * The pointer shall be suitable for use in a subsequent call to
 * free()."  ERRORS: "[ENOMEM] Insufficient storage space is available."
 *
 * That the result must be free()-able is the clause with teeth here, and
 * it is checked for real: tools/asan-build.sh runs every test under
 * LeakSanitizer, so a returned pointer that is not a live malloc block
 * fails the asan gate rather than passing quietly.  This is the same
 * mechanism that caught the vdprintf() leak the last never-asserted
 * sweep turned up.
 *
 * N/A, with the reason: [ENOMEM].  Reaching it needs allocator
 * exhaustion, which this suite has no way to induce -- the ledger
 * already treats malloc-exhaustion paths that way throughout.
 *
 * Filesystem-adjacent (it names a path under the temp directory and
 * src/stdio/misc.c reaches mkstemp() to pick one), so real-Windows CI
 * is the authority; Wine agreeing is weak evidence. */
static void test_tempnam(void)
{
	char *a, *b;
	struct stat st;

	a = tempnam(".", "tn");
	CHECK(a != 0);
	if (a) {
		/* honours dir and pfx */
		CHECK(!strncmp(a, "./tn", 4));
		/* "a pathname that may be used for a temporary file": the name
		 * must not already be taken, or the caller's create races. */
		CHECK(stat(a, &st) == -1);
		/* usable as promised */
		{
			FILE *f = fopen(a, "wb");
			CHECK(f != 0);
			if (f) {
				CHECK(fputs("x", f) != EOF);
				CHECK(fclose(f) == 0);
				CHECK(stat(a, &st) == 0);
				CHECK(remove(a) == 0);
			}
		}
	}

	b = tempnam(".", "tn");
	CHECK(b != 0);
	/* two calls must not hand out the same name */
	if (a && b) CHECK(strcmp(a, b) != 0);
	if (b) CHECK(stat(b, &st) == -1);

	/* a null dir falls back to P_tmpdir (or an implementation-defined
	 * directory); only that a pathname comes back at all is portable. */
	free(a);
	free(b);
	a = tempnam(NULL, "tn");
	CHECK(a != 0);
	if (a) {
		CHECK(strlen(a) > 0);
		CHECK(stat(a, &st) == -1);
	}
	/* "suitable for use in a subsequent call to free()" -- and under
	 * tools/asan-build.sh's LeakSanitizer, not freeing would fail. */
	free(a);

	/* a null pfx is allowed too */
	b = tempnam(".", NULL);
	CHECK(b != 0);
	if (b) CHECK(stat(b, &st) == -1);
	free(b);
}

/* vprintf.html / vscanf.html, and the <stdarg.h> machinery they are
 * defined in terms of:
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/vprintf.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/vscanf.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/va_arg.html
 *
 * vprintf.html DESCRIPTION: the v-forms "shall be equivalent to
 * printf() ... respectively, except that instead of being called with a
 * variable number of arguments, they are called with an argument list";
 * RETURN VALUE: "the number of bytes transmitted".  vscanf.html: the
 * same equivalence to scanf(), returning "the number of successfully
 * matched and assigned input items".  va_arg.html DESCRIPTION: va_copy
 * "initializes dest as a copy of src, as if the va_start() macro had
 * been applied to dest followed by the same sequence of uses of the
 * va_arg() macro as had previously been used to reach the present state
 * of src".
 *
 * test_v_forms() above already reaches vfprintf/vsnprintf/vsprintf/
 * vsscanf/vfscanf/vdprintf and, through them, va_start/va_end.  vprintf,
 * vscanf, va_arg and va_copy were the four names left with no assertion
 * anywhere (test/POSIX-GAP-ACCOUNTING.md's <stdarg.h> group).  vprintf
 * and vscanf are the stdout/stdin forms, so they need those two streams
 * redirected -- fd-level for stdout (dup/dup2 around the call, so the
 * stream object survives), freopen() for stdin, the same way
 * test_getchar() does it.
 *
 * Pure C library over a redirected fd: Wine is a sound oracle. */
static int via_vprintf(const char *fmt, ...)
{
	int r;
	va_list ap;
	va_start(ap, fmt);
	r = vprintf(fmt, ap);
	va_end(ap);
	return r;
}

static int via_vscanf(const char *fmt, ...)
{
	int r;
	va_list ap;
	va_start(ap, fmt);
	r = vscanf(fmt, ap);
	va_end(ap);
	return r;
}

/* Walks ap with va_arg, then walks a va_copy of it from the same point
 * and checks the copy yields the identical sequence -- the whole of what
 * va_copy promises.  The original is consumed first so that, if va_copy
 * silently aliased rather than copied, the second walk would read past
 * the end instead of repeating. */
static int va_copy_sees_same(int n, ...)
{
	va_list ap, ap2;
	int first[8], second[8], i, ok = 1;

	if (n > 8) return 0;
	va_start(ap, n);
	va_copy(ap2, ap);
	for (i = 0; i < n; i++) first[i] = va_arg(ap, int);
	va_end(ap);
	for (i = 0; i < n; i++) second[i] = va_arg(ap2, int);
	va_end(ap2);
	for (i = 0; i < n; i++) if (first[i] != second[i]) ok = 0;
	for (i = 0; i < n; i++) if (first[i] != i * 11 + 1) ok = 0;
	return ok;
}

static void test_vprintf_vscanf(const char *name)
{
	char buf[64];
	int saved, fd, got = 0, r;
	FILE *f;

	/* va_arg/va_copy first: no I/O involved. */
	CHECK(va_copy_sees_same(5, 1, 12, 23, 34, 45));
	CHECK(va_copy_sees_same(1, 1));
	CHECK(va_copy_sees_same(0));

	/* vprintf: redirect fd 1 at the temp file for the duration. */
	saved = dup(1);
	CHECK(saved >= 0);
	fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (saved < 0 || fd < 0) return;
	CHECK(fflush(stdout) == 0);
	CHECK(dup2(fd, 1) == 1);
	CHECK(close(fd) == 0);
	r = via_vprintf("%s=%d\n", "vp", 17);
	CHECK(fflush(stdout) == 0);
	CHECK(dup2(saved, 1) == 1);
	CHECK(close(saved) == 0);
	/* "the number of bytes transmitted": "vp=17\n" */
	CHECK(r == 6);

	f = fopen(name, "rb");
	CHECK(f != 0);
	if (f) {
		memset(buf, 0, sizeof buf);
		CHECK(fread(buf, 1, sizeof buf - 1, f) == 6);
		CHECK(!strcmp(buf, "vp=17\n"));
		CHECK(fclose(f) == 0);
	}

	/* vscanf: same file, now as stdin. */
	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }
	CHECK(via_vscanf("vp=%d", &got) == 1);
	CHECK(got == 17);
	/* "the number of successfully matched and assigned input items" is
	 * EOF once the input is exhausted before any conversion. */
	CHECK(via_vscanf("%d", &got) == EOF);
}

/* ------------------------------------------------------------------ *
 * Clause audit of the <stdio.h> (16) and <stdarg.h> (12) rows of
 * test/POSIX-GAP-ACCOUNTING.md's "Implemented, not clause-audited"
 * table.  Everything below cites
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/<name>.html
 * (or basedefs/stdarg.h.html) by section.
 * ------------------------------------------------------------------ */

/* fprintf.html DESCRIPTION: "The snprintf() function shall be
 * equivalent to sprintf(), with the addition of the n argument which
 * states the size of the buffer referred to by s.  If n is zero,
 * nothing shall be written and s may be a null pointer.  Otherwise,
 * output bytes beyond the n-1st shall be discarded instead of being
 * written to the array, and a null byte is written at the end of the
 * bytes actually written into the array."
 *
 * fprintf.html RETURN VALUE: "Upon successful completion, the
 * snprintf() function shall return the number of bytes that would be
 * written to s had n been sufficiently large excluding the terminating
 * null byte", and "If the value of n is zero on a call to snprintf(),
 * nothing shall be written, the number of bytes that would have been
 * written had n been sufficiently large excluding the terminating null
 * shall be returned, and s may be a null pointer."
 *
 * fprintf.html RETURN VALUE, sprintf: "the number of bytes written to
 * s, excluding the terminating null byte"; DESCRIPTION: sprintf "shall
 * place output followed by the null byte".
 *
 * The exact-fit / one-short / one-byte / zero-byte cases are walked
 * individually, and each writes a sentinel past the buffer end first so
 * that a formatter that scribbled one byte too far would be caught here
 * rather than only under asan.  Pure library code over memory: Wine is
 * a sound oracle. */
static void test_snprintf_boundaries(void)
{
	char b[16];
	int r;

	/* exact fit: n == strlen + 1 */
	memset(b, '#', sizeof b);
	r = snprintf(b, 5, "abcd");
	CHECK(r == 4);
	CHECK(!strcmp(b, "abcd"));
	CHECK(b[5] == '#');          /* nothing past the n-1st byte's NUL */

	/* one short: the 4th byte is discarded, a NUL goes at b[3] */
	memset(b, '#', sizeof b);
	r = snprintf(b, 4, "abcd");
	CHECK(r == 4);               /* what *would* have been written */
	CHECK(!strcmp(b, "abc"));
	CHECK(b[4] == '#');

	/* n == 1: only the null byte fits */
	memset(b, '#', sizeof b);
	r = snprintf(b, 1, "abcd");
	CHECK(r == 4);
	CHECK(b[0] == 0);
	CHECK(b[1] == '#');

	/* n == 0: "nothing shall be written" -- not even the NUL */
	memset(b, '#', sizeof b);
	r = snprintf(b, 0, "abcd");
	CHECK(r == 4);
	CHECK(b[0] == '#');

	/* n == 0 and "s may be a null pointer" */
	CHECK(snprintf(NULL, 0, "abcd%d", 7) == 5);

	/* the same three shapes through the v-form (vfprintf.html:
	 * "equivalent to ... snprintf()") */
	memset(b, '#', sizeof b);
	CHECK(via_vsnprintf(b, 5, "abcd") == 4);
	CHECK(!strcmp(b, "abcd") && b[5] == '#');
	memset(b, '#', sizeof b);
	CHECK(via_vsnprintf(b, 4, "abcd") == 4);
	CHECK(!strcmp(b, "abc") && b[4] == '#');
	CHECK(via_vsnprintf(NULL, 0, "abcd") == 4);

	/* sprintf: bytes written excluding the NUL, and the NUL is there */
	memset(b, '#', sizeof b);
	r = sprintf(b, "%s%d", "x", 42);
	CHECK(r == 3);
	CHECK(!strcmp(b, "x42"));
	CHECK(b[4] == '#');
	memset(b, '#', sizeof b);
	CHECK(via_vsprintf(b, "%s%d", "x", 42) == 3);
	CHECK(!strcmp(b, "x42"));

	/* DESCRIPTION: "If the format is exhausted while arguments remain,
	 * the excess arguments shall be evaluated but are otherwise
	 * ignored." */
	memset(b, '#', sizeof b);
	CHECK(snprintf(b, sizeof b, "x", 1, 2) == 1);
	CHECK(!strcmp(b, "x"));
}

/* fprintf.html ERRORS: "The snprintf() function shall fail if:
 * [EOVERFLOW] The value of n is greater than {INT_MAX}."  Note the
 * "shall": unlike the [EBADF] under dprintf() this is not a "may fail",
 * so a conforming snprintf() has to reject the call, return a negative
 * value (RETURN VALUE: "If an output error was encountered, these
 * functions shall return a negative value and set errno") and never
 * touch s.
 *
 * Why POSIX makes it a shall-fail rather than leaving it alone: the
 * return type is int, and the return value is defined as the number of
 * bytes that *would* have been written had n been sufficiently large.
 * For n > INT_MAX that promised value is not representable in the
 * return type at all, so the standard makes the call fail up front
 * instead of returning something that cannot be right.
 *
 * vsnprintf() is asserted alongside it because vfprintf.html makes it
 * "equivalent to ... snprintf()" and refers its ERRORS to fprintf(), so
 * the ceiling has to sit where both entry points pass through it rather
 * than in snprintf()'s own variadic wrapper.  The sentinel byte is the
 * half that says the call was refused BEFORE formatting: an
 * implementation that formatted first and reported the error afterwards
 * would satisfy the return value and errno and still have written to a
 * buffer POSIX says it may not touch. */
static void test_snprintf_eoverflow(void)
{
	char b[8];
	int r;

	memset(b, '#', sizeof b);
	errno = 0;
	r = snprintf(b, (size_t)INT_MAX + 1, "z");
	CHECK(r < 0);
	CHECK(errno == EOVERFLOW);
	CHECK(b[0] == '#');

	memset(b, '#', sizeof b);
	errno = 0;
	r = via_vsnprintf(b, (size_t)INT_MAX + 1, "z");
	CHECK(r < 0);
	CHECK(errno == EOVERFLOW);
	CHECK(b[0] == '#');

	/* The boundary itself is not an error: n == {INT_MAX} is "greater
	 * than" nothing, so it formats normally. */
	memset(b, '#', sizeof b);
	CHECK(snprintf(b, (size_t)INT_MAX, "z") == 1);
	CHECK(!strcmp(b, "z"));
}

/* An L"..." literal follows the compiler host's wchar_t width.  The
 * native sanitizer build uses a 4-byte host wchar_t while spicule's public
 * type, matching NT, is 2 bytes, so construct wide test strings in the
 * library's actual type.  Four rotating slots also make two stdio_w()
 * calls in one expression independent of argument evaluation order. */
static const wchar_t *stdio_w(const char *s)
{
	static wchar_t pool[4][64];
	static int slot;
	wchar_t *b = pool[slot++ % 4];
	size_t i;
	for (i = 0; s[i] && i < 63; i++) b[i] = (wchar_t)(unsigned char)s[i];
	b[i] = 0;
	return b;
}

/* fprintf.html: a negative '*' width is a '-' flag followed by its
 * positive magnitude.  INT_MIN's magnitude is INT_MAX+1, so the required
 * output count cannot fit the return type and [EOVERFLOW] is the defined
 * failure.  Evaluating `-width` first is signed-overflow UB; cover both
 * ordinary and numbered argument paths because they fetch independently
 * before converging on the same normalization. */
static void test_printf_int_min_width_no_overflow(void)
{
	char b[8];
	wchar_t wb[8];
	int n;

	errno = 0;
	CHECK(snprintf(b, sizeof b, "%*d", INT_MIN, 7) == -1);
	CHECK(errno == EOVERFLOW);

	errno = 0;
	CHECK(snprintf(b, sizeof b, "%1$*2$d", 7, INT_MIN) == -1);
	CHECK(errno == EOVERFLOW);

	/* Literal width and precision digit runs are caller-controlled too.
	 * The byte and wide formatters share one parser, and the byte and wide
	 * scanners share the other, so exercise both strides at the endpoint. */
	errno = 0;
	CHECK(snprintf(b, sizeof b, "%999999999999999999d", 7) == -1);
	CHECK(errno == EOVERFLOW);
	errno = 0;
	CHECK(swprintf(wb, sizeof wb / sizeof *wb,
	               stdio_w("%999999999999999999d"), 7) == -1);
	CHECK(errno == EOVERFLOW);
	/* The parser boundary itself is valid, but two individually valid
	 * conversions can make the aggregate return value unrepresentable.
	 * Fixed-buffer padding is deliberately bounded, so these exercise the
	 * sink's count check without doing billions of writes. */
	CHECK(snprintf(b, sizeof b, "%2147483647d", 7) == INT_MAX);
	errno = 0;
	CHECK(snprintf(b, sizeof b, "%1073741824d%1073741824d", 1, 2) == -1);
	CHECK(errno == EOVERFLOW);
	errno = 0;
	CHECK(swprintf(wb, sizeof wb / sizeof *wb,
	               stdio_w("%1073741824d%1073741824d"), 1, 2) == -1);
	CHECK(errno == EOVERFLOW);
	CHECK(snprintf(b, sizeof b, "%.999999999999999999s", "x") == 1);
	CHECK(!strcmp(b, "x"));
	CHECK(swprintf(wb, sizeof wb / sizeof *wb,
	               stdio_w("%.999999999999999999ls"), stdio_w("x")) == 1);
	CHECK(wb[0] == (wchar_t)'x' && wb[1] == 0);

	n = -1;
	CHECK(sscanf("abc", "%*999999999999999999s%n", &n) == 0);
	CHECK(n == 3);
	n = -1;
	CHECK(swscanf(stdio_w("abc"), stdio_w("%*999999999999999999s%n"), &n) == 0);
	CHECK(n == 3);
}

/* fprintf.html, the length modifiers: "z  Specifies that a following
 * d, i, o, u, x, or X conversion specifier applies to a size_t or the
 * corresponding signed integer type argument; or that a following n
 * conversion specifier applies to a pointer to a signed integer type
 * corresponding to a size_t argument."  t says the same for ptrdiff_t.
 *
 * src/stdio/printf.c USED TO read both with va_arg(ap, long) at three
 * sites -- two value conversions and %n.  On this target long is 32
 * bits and size_t is 64 (LLP64), so the type was simply wrong.  The %n
 * case was the worst of the three: it stored through *(long *), writing
 * four bytes into the caller's eight-byte object and leaving the other
 * four whatever they were.  Fixed in c200c7f; this test is the fence
 * that was opened by that commit, and it stays live so the defect
 * cannot come back silently.  tools/lint-widthmod.sh guards the same
 * property statically, over every LM_z/LM_t site in the tree.
 *
 * The tree already contained the correct pattern, in the file that
 * implements the same grammar: src/stdio/scanf.c pairs LM_z with size_t
 * and LM_t with ptrdiff_t, and has no instance of this bug.  printf.c
 * was the only offender.
 *
 * Found by musl's libc-test (printf-fmt-n), not by this file's own
 * clause audit, which read these pages closely enough to fence the
 * <apostrophe> flag and [EOVERFLOW] and walked past this. */
/* fprintf.html, the c and s conversions:
 *
 *   c  "If an l (ell) qualifier is present, the wint_t argument shall
 *       be converted as if by an ls conversion specification with no
 *       precision and an argument that points to a two-element array of
 *       type wchar_t, the first element containing the wint_t argument
 *       ... and the second a null wide character."
 *
 *   s  "If an l (ell) qualifier is present, the argument shall be a
 *       pointer to an array of type wchar_t.  Wide characters from the
 *       array shall be converted to characters (each as if by a call to
 *       the wcrtomb() function ...) up to and including a terminating
 *       null wide character.  ...  If a precision is specified, no more
 *       than that many bytes shall be written ... and a partial
 *       character shall not be written."
 *
 * This library's only encoding is UTF-8 (src/stdlib/mbrtowc.c), so
 * U+00E9 is two bytes and U+1234 is three, and the byte count the
 * conversion reports and the field width it pads to are both byte
 * counts.
 *
 * WHY THIS TEST EXISTS AS ITS OWN THING: two of the cases below pass
 * against an implementation that ignores the l qualifier entirely, and
 * they are the two a casual test would have written.  %lc of an ASCII
 * character is right by accident, because the low byte of the wint_t IS
 * the character; and %ls of a one-character ASCII wide string is right
 * by accident, because the second byte of that wchar_t is the NUL that
 * stops a char* walk.  The cases that bite are a non-ASCII character,
 * and an ASCII wide string of length two or more. */
static void test_printf_l_modifier(void)
{
	static const wchar_t w_eb[3]  = { 0xe9, L'b', 0 };   /* U+00E9 'b' */
	static const wchar_t w_ab[3]  = { L'a', L'b', 0 };   /* "ab" */
	static const wchar_t w_hi[3]  = { 0x1234, L'z', 0 }; /* U+1234 'z' */
	static const wchar_t w_empty[1] = { 0 };
	char b[64];
	int n;

	/* %ls: the whole multibyte form of every wide character. */
	memset(b, 0, sizeof b);
	n = snprintf(b, sizeof b, "%ls", w_eb);
	CHECK(n == 3);
	CHECK(!memcmp(b, "\xc3\xa9" "b", 4));

	/* The trap: an ASCII wide string longer than one character.  An
	 * implementation that reads the wchar_t array as a char* stops at
	 * the first unit's zero high byte and prints "a". */
	memset(b, 0, sizeof b);
	n = snprintf(b, sizeof b, "%ls", w_ab);
	CHECK(n == 2);
	CHECK(!strcmp(b, "ab"));

	/* three-byte character */
	memset(b, 0, sizeof b);
	n = snprintf(b, sizeof b, "%ls", w_hi);
	CHECK(n == 4);
	CHECK(!memcmp(b, "\xe1\x88\xb4" "z", 5));

	/* empty wide string writes nothing */
	memset(b, 'Z', sizeof b);
	n = snprintf(b, sizeof b, "%ls", w_empty);
	CHECK(n == 0);
	CHECK(b[0] == 0);

	/* "If a precision is specified, no more than that many bytes shall
	 * be written ... and a partial character shall not be written."
	 * U+00E9 is two bytes, so a precision of 1 writes NOTHING: there is
	 * no way to write one byte of it. */
	memset(b, 0, sizeof b);
	n = snprintf(b, sizeof b, "%.1ls", w_eb);
	CHECK(n == 0);
	memset(b, 0, sizeof b);
	n = snprintf(b, sizeof b, "%.2ls", w_eb);
	CHECK(n == 2);
	CHECK(!memcmp(b, "\xc3\xa9", 2));
	/* three bytes admits the whole first character and the 'b' */
	memset(b, 0, sizeof b);
	n = snprintf(b, sizeof b, "%.3ls", w_eb);
	CHECK(n == 3);
	CHECK(!memcmp(b, "\xc3\xa9" "b", 3));

	/* The field width is a BYTE count too, and is computed from the
	 * converted length -- so an implementation that measured the
	 * argument as a char* pads by the wrong amount even when the
	 * characters themselves are ASCII. */
	memset(b, 0, sizeof b);
	n = snprintf(b, sizeof b, "[%6ls]", w_ab);
	CHECK(n == 8);
	CHECK(!strcmp(b, "[    ab]"));
	memset(b, 0, sizeof b);
	n = snprintf(b, sizeof b, "[%-6ls]", w_ab);
	CHECK(n == 8);
	CHECK(!strcmp(b, "[ab    ]"));
	/* padding counts the BYTES of a non-ASCII character, not its
	 * characters: U+00E9 'b' is three bytes, so %6ls pads three */
	memset(b, 0, sizeof b);
	n = snprintf(b, sizeof b, "[%6ls]", w_eb);
	CHECK(n == 8);
	CHECK(!memcmp(b, "[   \xc3\xa9" "b]", 8));

	/* %lc: the wint_t argument, as its whole multibyte form. */
	memset(b, 0, sizeof b);
	n = snprintf(b, sizeof b, "%lc", (wint_t)0xe9);
	CHECK(n == 2);
	CHECK(!memcmp(b, "\xc3\xa9", 2));
	memset(b, 0, sizeof b);
	n = snprintf(b, sizeof b, "%lc", (wint_t)0x1234);
	CHECK(n == 3);
	CHECK(!memcmp(b, "\xe1\x88\xb4", 3));
	/* the accidental case, asserted so the real ones are not the only
	 * evidence that anything happens at all */
	memset(b, 0, sizeof b);
	n = snprintf(b, sizeof b, "%lc", (wint_t)L'Z');
	CHECK(n == 1);
	CHECK(!strcmp(b, "Z"));
	/* width pads to the byte count */
	memset(b, 0, sizeof b);
	n = snprintf(b, sizeof b, "[%4lc]", (wint_t)0xe9);
	CHECK(n == 6);
	CHECK(!memcmp(b, "[  \xc3\xa9]", 6));

	/* A supplementary character is TWO wchar_t on this target (a UTF-16
	 * surrogate pair) and ONE four-byte sequence on the way out, so the
	 * conversion state has to carry the high surrogate from one unit to
	 * the next. */
	{
		static const wchar_t pair[3] = { 0xd83d, 0xde00, 0 };  /* U+1F600 */
		memset(b, 0, sizeof b);
		n = snprintf(b, sizeof b, "%ls", pair);
		CHECK(n == 4);
		CHECK(!memcmp(b, "\xf0\x9f\x98\x80", 4));
	}
}
/* fprintf.html DESCRIPTION, conversion specifications: "Conversions can
 * be applied to the nth argument after the format in the argument list,
 * rather than to the next unused argument.  In this case, the conversion
 * specifier character % (see below) is replaced by the sequence "%n$",
 * where n is a decimal integer in the range [1,{NL_ARGMAX}] ... The
 * format can contain either numbered argument conversion specifications
 * (that is, "%n$" and "*m$"), or unnumbered argument conversion
 * specifications (that is, % and *), but not both."
 */
static void test_printf_positional_arguments(void)
{
	char b[64];

	/* the n'th argument, out of order */
	CHECK(snprintf(b, sizeof b, "%2$s %1$s", "world", "hello") == 11);
	CHECK(!strcmp(b, "hello world"));

	/* the same argument twice -- the thing unnumbered specs cannot do */
	CHECK(snprintf(b, sizeof b, "%1$d %1$d", 7) == 3);
	CHECK(!strcmp(b, "7 7"));

	/* "*m$" for a width taken from the m'th argument */
	CHECK(snprintf(b, sizeof b, "%2$*1$d", 5, 42) == 5);
	CHECK(!strcmp(b, "   42"));

	/* n is "in the range [1,{NL_ARGMAX}]", so the upper end must work */
	CHECK(snprintf(b, sizeof b, "%9$d", 1, 2, 3, 4, 5, 6, 7, 8, 99) == 2);
	CHECK(!strcmp(b, "99"));

	/* "... but not both".  A format that writes both forms is
	 * undefined, so what follows pins spicule's choice rather than the
	 * standard's, and pins it because the alternative to a diagnosed
	 * refusal is not a slightly wrong answer: it is every argument
	 * after the offending specification read at an offset nobody
	 * stated.  The refusal is the negative return RETURN VALUE already
	 * defines, with the [EINVAL] fprintf.html ERRORS names for "There
	 * are insufficient arguments".  Same treatment for an n outside
	 * "[1,{NL_ARGMAX}]", which has no argument to name at all. */
	errno = 0;
	CHECK(snprintf(b, sizeof b, "%1$d %d", 1, 2) < 0);
	CHECK(errno == EINVAL);
	errno = 0;
	CHECK(snprintf(b, sizeof b, "%d %1$d", 1, 2) < 0);
	CHECK(errno == EINVAL);
	errno = 0;                                   /* "*" against "*m$" */
	CHECK(snprintf(b, sizeof b, "%1$*d", 4, 2) < 0);
	CHECK(errno == EINVAL);
	errno = 0;
	CHECK(snprintf(b, sizeof b, "%10$d", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10) < 0);
	CHECK(errno == EINVAL);
}

static void test_printf_z_modifier_width(void)
{
	/* size_t, ssize_t and ptrdiff_t are 64 bits on the LLP64 target
	 * this defect lived on and 32 bits on i386, so both the values and
	 * the decimals they must print are per-arch.  Selected with
	 * sizeof() rather than #if because spicule's <stdint.h> defines no
	 * SIZE_MAX to test against (INT64_MAX and friends are there; the
	 * pointer-width limits are not), and a runtime select compiles and
	 * type-checks both arms on both arches.
	 *
	 * On i386 long, size_t and ptrdiff_t are all 32 bits and occupy the
	 * same argument slot, so va_arg(ap, long) and va_arg(ap, size_t)
	 * fetch identical bytes and the original defect is NOT observable
	 * here -- which is exactly why it survived: the fence has to run on
	 * the LLP64 arch to bite.  The i386 arm is still worth running: it
	 * holds the %z/%t grammar itself (accepted, not misparsed as a
	 * stray modifier) and %zn's store to the whole object. */
	int wide = sizeof(size_t) > 4;
	size_t big = wide ? (size_t)(0xdeadbeefULL << 32) : (size_t)0xdeadbeefUL;
	const char *big_text = wide ? "16045690981097406464" : "3735928559";
	/* The signed value must be one a 32-bit long CANNOT hold, or the
	 * assertion proves nothing: -1 sign-extends to the same bits either
	 * way, and mutation-testing confirmed that a -1-only check passes
	 * with the defect restored.  0xdeadbeef is above 2^31, so read
	 * through a 32-bit long it comes back negative -- that is the
	 * discriminating value, and it is only representable in a 64-bit
	 * ssize_t.  On i386 no such value exists (see above), so that arm
	 * uses the same bit pattern read as a 32-bit signed quantity, which
	 * still round-trips %zd and %td against %lld. */
	long long sval = wide ? 0xdeadbeefLL : -559038737LL;
	size_t n = (size_t)-1;
	ptrdiff_t t = -1;
	char b[64], ref[64];

	/* Checked TWO ways on purpose.  The fence's version asserted only a
	 * hand-written decimal literal, and that literal was WRONG:
	 * 0xdeadbeef << 32 is 16045690981097406464, but it said
	 * ...537536, i.e. 0xdeadbeef00020000.  A correct fix therefore still
	 * failed the test, which invites "fixing" the library until the
	 * wrong constant is produced.  Comparing against "%llu" of the same
	 * value is the check that cannot be typo'd out of agreement; the
	 * literal is kept as well, corrected, so that a bug shared by both
	 * conversions could still be caught. */
	snprintf(ref, sizeof ref, "%llu", (unsigned long long)big);
	snprintf(b, sizeof b, "%zu", big);
	CHECK(strcmp(b, ref) == 0);
	CHECK(strcmp(b, big_text) == 0);

	/* Signed, and t as well as z. */
	snprintf(ref, sizeof ref, "%lld", sval);
	snprintf(b, sizeof b, "%zd", (ssize_t)sval);
	CHECK(strcmp(b, ref) == 0);
	snprintf(b, sizeof b, "%td", (ptrdiff_t)sval);
	CHECK(strcmp(b, ref) == 0);
	/* and -1 still round-trips, so the fix is not "always widen wrongly" */
	snprintf(ref, sizeof ref, "%lld", -1LL);
	snprintf(b, sizeof b, "%zd", (ssize_t)-1);
	CHECK(strcmp(b, ref) == 0);
	/* %zn must write all of a size_t, not its low half -- the worst of
	 * the three, because it corrupts an object the caller owns rather
	 * than merely printing a wrong number.  Pre-set to all-ones so a
	 * four-byte store leaves the upper half visibly wrong. */
	n = (size_t)-1;
	snprintf(b, sizeof b, "ab%zn", &n);
	CHECK(n == 2);
	t = -1;
	snprintf(b, sizeof b, "abc%tn", &t);
	CHECK(t == 3);
}

/* fprintf.html, the flag characters: "'  [CX] (The <apostrophe>.)  The
 * integer portion of the result of a decimal conversion ( %i, %d, %u,
 * %f, %F, %g, or %G ) shall be formatted with thousands' grouping
 * characters.  ...  The non-monetary grouping character is used."
 *
 * This is a [CX] flag, i.e. base POSIX, not XSI.  In the POSIX locale
 * the non-monetary grouping is empty (XBD 7.3.4 LC_NUMERIC: the POSIX
 * locale's `grouping` is unspecified-length/no grouping, and
 * localeconv()'s POSIX-locale `grouping` is ""), so a conforming
 * implementation must accept the flag and produce exactly what the
 * unflagged conversion produces.  spicule's flag loop in
 * src/stdio/printf.c recognises only '-', '+', ' ', '0' and '#', so a
 * <apostrophe> ends the flag scan and then falls out of the conversion
 * switch's default arm, which emits the two bytes literally.  Measured:
 * snprintf("%'d", 1234567) yields "%'d", 3 bytes.
 *
 * SEVERITY -- read this before filing it as cosmetic.  The default arm
 * emits the bytes and does *not* consume an argument, so the failure is
 * not "the number comes out unformatted": it is a silent
 * argument-stream desync for the whole rest of the format string.
 * Every conversion after the %' reads the argument meant for the one
 * before it.  In
 *
 *     printf("%'d %s\n", total, name);
 *
 * the %s is handed `total` and dereferences an integer as a char * --
 * a crash, or a garbage string, in code that reads as obviously
 * correct, with the %'d as the only clue anything is wrong.
 *
 * The POSIX locale makes this worse rather than better.  There is no
 * thousands grouping in that locale, so the *correct* output for %'d
 * is byte-for-byte the output of %d: an author who tries %'d, sees no
 * separators, and concludes "not supported here, harmless" has no
 * reason to suspect that the rest of their format is now misaligned.
 * The one visible symptom is the one that looks least alarming. */
static void test_printf_apostrophe_flag(void)
{
	char grouped[64], plain[64];

	/* In the POSIX locale the non-monetary grouping is empty, so the
	 * flagged conversion must produce byte-for-byte what the unflagged
	 * one produces -- for every conversion the flag table names. */
	CHECK(snprintf(plain, sizeof plain, "%d", 1234567) == 7);
	CHECK(snprintf(grouped, sizeof grouped, "%'d", 1234567) == 7);
	CHECK(!strcmp(grouped, plain));

	CHECK(snprintf(plain, sizeof plain, "%i", -1234567) == 8);
	CHECK(snprintf(grouped, sizeof grouped, "%'i", -1234567) == 8);
	CHECK(!strcmp(grouped, plain));

	CHECK(snprintf(plain, sizeof plain, "%u", 4000000000u) == 10);
	CHECK(snprintf(grouped, sizeof grouped, "%'u", 4000000000u) == 10);
	CHECK(!strcmp(grouped, plain));

	snprintf(plain, sizeof plain, "%f", 1234567.5);
	snprintf(grouped, sizeof grouped, "%'f", 1234567.5);
	CHECK(!strcmp(grouped, plain));

	snprintf(plain, sizeof plain, "%g", 1234567.5);
	snprintf(grouped, sizeof grouped, "%'g", 1234567.5);
	CHECK(!strcmp(grouped, plain));

	/* the flag combines with width, precision and the other flags */
	CHECK(snprintf(plain, sizeof plain, "%+08.3d", 42) ==
	      snprintf(grouped, sizeof grouped, "%+'08.3d", 42));
	CHECK(!strcmp(grouped, plain));

	/* THE ARGUMENT-STREAM ASSERTION, which is the whole severity of this
	 * defect and which comparing one conversion's output cannot detect.
	 * When the flag was unrecognised the bytes were emitted literally and
	 * NO argument was consumed, so the next conversion read the previous
	 * conversion's argument and everything after it was misaligned.
	 * Two integer conversions are used rather than the "%'d %s" shape
	 * from the fence text: that shape is the dangerous one in real code
	 * (%s is handed an int and dereferences it), but it is undefined
	 * behaviour to provoke here, and this pins the same desync safely --
	 * with the flag unrecognised the second conversion prints 111. */
	CHECK(snprintf(grouped, sizeof grouped, "%'d %d", 111, 222) == 7);
	CHECK(!strcmp(grouped, "111 222"));
	CHECK(snprintf(grouped, sizeof grouped, "%'d%'d%'d", 1, 2, 3) == 3);
	CHECK(!strcmp(grouped, "123"));
}

/* fprintf.html DESCRIPTION, field width and precision: "A negative
 * field width is taken as a '-' flag followed by a positive field
 * width.  A negative precision is taken as if the precision were
 * omitted."  Also the flag table's '#', '+' and <space> entries, the
 * "null digit string is treated as zero" precision rule, and the
 * length modifiers.
 *
 * The wide-field/wide-precision cases exist because this formatter
 * sizes nothing from the caller's precision on purpose (see PREC_MAX
 * and BODYMAX in src/stdio/printf.c) and a fixed-size body buffer here
 * has been a real defect before: every one of these writes far more
 * bytes than any internal buffer, and runs under asan in
 * tools/asan-build.sh. */
static void test_printf_width_precision(void)
{
	static char big[8192];
	char b[64];

	/* "A negative precision is taken as if the precision were omitted" */
	CHECK(snprintf(b, sizeof b, "%.*d", -3, 42) == 2);
	CHECK(!strcmp(b, "42"));
	/* "A negative field width is taken as a '-' flag followed by a
	 * positive field width" */
	CHECK(snprintf(b, sizeof b, "%*d|", -5, 42) == 6);
	CHECK(!strcmp(b, "42   |"));
	/* '#' for o and x; '+' and <space> for signed conversions; '#' for
	 * f ("the result shall always contain a radix character") */
	CHECK(snprintf(b, sizeof b, "%#o|%#x|%+d|% d|%#.0f", 8, 255, 3, 3, 1.0) == 17);
	CHECK(!strcmp(b, "010|0xff|+3| 3|1."));
	/* precision 0 with a zero d value prints nothing: "The result of
	 * converting a zero value with a precision of 0 shall be no
	 * characters." */
	CHECK(snprintf(b, sizeof b, "[%.0d][%.0d]", 0, 5) == 5);
	CHECK(!strcmp(b, "[][5]"));
	/* length modifiers narrow the argument before conversion */
	CHECK(snprintf(b, sizeof b, "%hhd|%hd", 300, 70000) == 7);
	CHECK(!strcmp(b, "44|4464"));

	/* widths and precisions far past any internal buffer */
	CHECK(snprintf(big, sizeof big, "%5000d", 7) == 5000);
	CHECK(strlen(big) == 5000);
	CHECK(big[4999] == '7' && big[0] == ' ');
	CHECK(snprintf(big, sizeof big, "%.5000d", 7) == 5000);
	CHECK(strlen(big) == 5000);
	CHECK(snprintf(big, sizeof big, "%.5000f", 1.0 / 3.0) == 5002);
	CHECK(strlen(big) == 5002);
	CHECK(!strncmp(big, "0.3333333333", 12));
	CHECK(snprintf(big, sizeof big, "%.5000e", 1.0 / 3.0) == 5006);
	CHECK(strlen(big) == 5006);
	/* "%g: the maximum number of significant digits" -- trailing zeros
	 * are removed, so a huge precision does not make a huge result */
	CHECK(snprintf(big, sizeof big, "%.5000g", 1.0 / 3.0) == 56);
	/* "the number of digits to appear after the radix character for the
	 * a, A, e, E, f, and F conversion specifiers" -- every one of them,
	 * exactly, out to the last place a double has: the smallest
	 * subnormal is 2^-1074, so its exact expansion's last non-zero
	 * fractional digit is the 1074th and it is a '5' (the whole tail is
	 * "...265625", 2^-1074 being 5^1074 * 10^-1074).  A formatter that
	 * clamped its internal expansion short would still get the length
	 * right and the leading digits right, and only this would catch it. */
	CHECK(snprintf(big, sizeof big, "%.1074f", 4.9406564584124654e-324) == 1076);
	CHECK(strlen(big) == 1076);
	CHECK(!strcmp(big + 1070, "265625"));

	/* "the maximum number of bytes to be printed from a string" */
	CHECK(snprintf(big, sizeof big, "%.5000s", "abc") == 3);
	CHECK(snprintf(big, sizeof big, "%.3s", "abcdef") == 3);
	CHECK(!strcmp(big, "abc"));
}

/* fprintf.html RETURN VALUE: "If an output error was encountered, these
 * functions shall return a negative value and set errno to indicate the
 * error", and ERRORS: "For the conditions under which dprintf(),
 * fprintf(), and printf() fail and may fail, refer to fputc" --
 * fputc.html ERRORS lists [EBADF] "The file descriptor underlying
 * stream is not a valid file descriptor open for writing" and [EPIPE]
 * "An attempt is made to write to a pipe or FIFO that is not open for
 * reading by any process.  A SIGPIPE signal shall also be sent to the
 * thread."
 *
 * fputc.html also requires the stream's error indicator to be set
 * ("shall set the error indicator for the stream"), which ferror()
 * observes.  The EPIPE case ignores SIGPIPE first, precisely because
 * the signal is the default outcome: without the SIG_IGN the process
 * dies of it, which is itself the clause's other half and is what this
 * measured before adding the ignore.
 *
 * Wine is a sound oracle for the EBADF path (pure fd bookkeeping);
 * the EPIPE path goes through NT named pipes, so real-Windows CI is
 * the authority there. */
static void test_printf_output_error(const char *name)
{
	FILE *f;
	int fds[2], r;

	f = fopen(name, "wb");
	CHECK(f != 0);
	if (!f) return;
	CHECK(setvbuf(f, 0, _IONBF, 0) == 0);
	CHECK(close(fileno(f)) == 0);
	errno = 0;
	r = fprintf(f, "hello");
	CHECK(r < 0);
	CHECK(errno == EBADF);
	CHECK(ferror(f) != 0);
	clearerr(f);
	fclose(f);

	/* dprintf.html/fprintf.html ERRORS: "[EBADF] The fildes argument is
	 * not a valid file descriptor" (a "may fail" for dprintf, but the
	 * write is an output error either way, so the negative return and
	 * the errno are required by RETURN VALUE). */
	errno = 0;
	CHECK(dprintf(-1, "x") < 0);
	CHECK(errno == EBADF);
	errno = 0;
	CHECK(via_vdprintf(-1, "x") < 0);
	CHECK(errno == EBADF);

	signal(SIGPIPE, SIG_IGN);
	if (pipe(fds) == 0) {
		CHECK(close(fds[0]) == 0);
		f = fdopen(fds[1], "wb");
		CHECK(f != 0);
		if (f) {
			CHECK(setvbuf(f, 0, _IONBF, 0) == 0);
			errno = 0;
			r = fprintf(f, "hello");
			CHECK(r < 0);
			CHECK(errno == EPIPE);
			CHECK(ferror(f) != 0);
			clearerr(f);
			fclose(f);
		} else {
			close(fds[1]);
		}
	} else {
		CHECK(0);
	}
	signal(SIGPIPE, SIG_DFL);
}

/* fprintf.html DESCRIPTION: "The dprintf() function shall be equivalent
 * to the fprintf() function, except that dprintf() shall write output
 * to the file associated with the file descriptor specified by the
 * fildes argument rather than place output on a stream."
 *
 * "The file associated with the file descriptor" means the open file
 * description, offset and all: a dprintf() has to land where the fd is
 * positioned and leave the fd advanced past what it wrote, so that a
 * raw write() in between interleaves rather than overwrites.  That is
 * the half of the clause a FILE*-shaped implementation could get wrong,
 * and src/stdio/printf.c's vdprintf() does wrap the raw fd in a stack
 * FILE -- so this checks that the wrapper writes through rather than
 * buffering somewhere of its own.  Filesystem-adjacent, so real-Windows
 * CI is the authority. */
static void test_dprintf_fd_path(const char *name)
{
	FILE *f;
	char buf[32];
	int fd;

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK(fd >= 0);
	if (fd < 0) return;
	CHECK(dprintf(fd, "%s", "AA") == 2);
	CHECK(write(fd, "-", 1) == 1);
	CHECK(via_vdprintf(fd, "%s", "BB") == 2);
	CHECK(lseek(fd, 0, SEEK_CUR) == (off_t)5);
	CHECK(close(fd) == 0);

	f = fopen(name, "rb");
	CHECK(f != 0);
	if (!f) return;
	memset(buf, 0, sizeof buf);
	CHECK(fread(buf, 1, sizeof buf - 1, f) == 5);
	CHECK(!strcmp(buf, "AA-BB"));
	CHECK(fclose(f) == 0);
}

/* fscanf.html RETURN VALUE: "these functions shall return the number of
 * successfully matched and assigned input items; this number can be
 * zero in the event of an early matching failure.  If the input ends
 * before the first conversion (if any) has completed, and without a
 * matching failure having occurred, EOF shall be returned."
 *
 * DESCRIPTION: "A directive composed of one or more white-space
 * characters shall be executed by reading input until no more valid
 * input can be read, or up to the first byte which is not a white-space
 * character"; "A directive that is an ordinary character shall be
 * executed as follows: the next byte shall be read from the input and
 * compared with the byte that comprises the directive; if the
 * comparison shows that they are not equivalent, the directive shall
 * fail, and the differing and subsequent bytes shall remain unread";
 * "An input item shall be defined as the longest sequence of input
 * bytes (up to any specified maximum field width) which is an initial
 * subsequence of a matching sequence"; and the %n rule that the count
 * "shall not be counted" toward the return value.
 *
 * The long-field cases are deliberate: a fixed-size staging buffer for
 * a numeric field has been a real defect in this tree before, and a
 * 400-digit fraction is far past any of them.  Pure library code over a
 * memory FILE: Wine is a sound oracle. */
static void test_sscanf_clauses(void)
{
	char s1[64], fb[600];
	int a, b, n, i, k, r;
	double d;

	/* "this number can be zero in the event of an early matching
	 * failure" */
	a = -1;
	CHECK(sscanf("xyz", "%d", &a) == 0);
	CHECK(a == -1);
	/* "If the input ends before the first conversion (if any) has
	 * completed ... EOF shall be returned" */
	CHECK(sscanf("", "%d", &a) == EOF);
	CHECK(sscanf("   ", "%d", &a) == EOF);
	/* ... but input ending *after* a completed conversion is not EOF */
	a = 0; b = -1;
	CHECK(sscanf("12", "%d %d", &a, &b) == 1);
	CHECK(a == 12 && b == -1);

	/* an ordinary-character mismatch is a plain return, not EOF */
	CHECK(sscanf("aXc", "abc") == 0);
	/* %% matches one literal '%' */
	a = 0;
	CHECK(sscanf("%5", "%%%d", &a) == 1);
	CHECK(a == 5);
	/* a white-space directive matches zero white-space characters too */
	a = 0; b = 0;
	CHECK(sscanf("1x2", "%d x %d", &a, &b) == 2);
	CHECK(a == 1 && b == 2);
	/* maximum field width bounds the item */
	a = 0; b = 0;
	CHECK(sscanf("56789", "%2d%d", &a, &b) == 2);
	CHECK(a == 56 && b == 789);
	CHECK(sscanf("hello world", "%5s", s1) == 1);
	CHECK(!strcmp(s1, "hello"));
	/* the fscanf.html EXAMPLES scanset case, verbatim */
	CHECK(sscanf("56a72", "%[0123456789]", s1) == 1);
	CHECK(!strcmp(s1, "56"));
	/* "%*": assignment suppression, and the item is still consumed */
	a = 0;
	CHECK(sscanf("1 2", "%*d %d", &a) == 1);
	CHECK(a == 2);
	/* %n is not counted toward the return value */
	a = 0; n = -1;
	CHECK(sscanf("42", "%d%n", &a, &n) == 1);
	CHECK(a == 42 && n == 2);

	/* a numeric field far longer than any staging buffer */
	k = 0;
	fb[k++] = '1'; fb[k++] = '.';
	for (i = 0; i < 400; i++) fb[k++] = '3';
	fb[k++] = 'e'; fb[k++] = '1'; fb[k] = 0;
	d = -1;
	CHECK(sscanf(fb, "%lf", &d) == 1);
	CHECK(d > 13.3333333333 && d < 13.3333333334);
	CHECK(via_vsscanf(fb, "%lf", &d) == 1);
	CHECK(d > 13.3333333333 && d < 13.3333333334);

	/* the fscanf.html EXAMPLES worked example, verbatim: "assigns 56 to
	 * i, 789.0 to x, skips 0123, and places the string "56\0" in
	 * name" */
	{
		int ii = 0; float x = 0;
		memset(s1, 0, sizeof s1);
		r = sscanf("56789 0123 56a72", "%2d%f%*d %[0123456789]", &ii, &x, s1);
		CHECK(r == 3);
		CHECK(ii == 56);
		CHECK(x > 788.9f && x < 789.1f);
		CHECK(!strcmp(s1, "56"));
	}
}

/* fscanf.html DESCRIPTION: "if the comparison shows that they are not
 * equivalent, the directive shall fail, and the differing and
 * subsequent bytes shall remain unread."  Only a real stream can show
 * this: sscanf() has no observable read position afterwards.  Also
 * RETURN VALUE: "If an error occurs before the first conversion (if
 * any) has completed, and without a matching failure having occurred,
 * EOF shall be returned and errno shall be set to indicate the error.
 * If a read error occurs, the error indicator for the stream shall be
 * set."  The read error is manufactured by scanning a stream that is
 * not open for reading (fgetc.html [EBADF]). */
static void test_fscanf_stream_clauses(const char *name)
{
	FILE *f;
	int a, r;

	f = fopen(name, "wb");
	CHECK(f != 0);
	if (!f) return;
	CHECK(fputs("abZq", f) == 0);
	CHECK(fclose(f) == 0);

	f = fopen(name, "rb");
	CHECK(f != 0);
	if (!f) return;
	CHECK(fscanf(f, "abc") == 0);
	CHECK(fgetc(f) == 'Z');      /* the differing byte remained unread */
	CHECK(fgetc(f) == 'q');
	CHECK(fclose(f) == 0);

	f = fopen(name, "rb");
	CHECK(f != 0);
	if (!f) return;
	a = 0;
	CHECK(via_vfscanf(f, "abc") == 0);
	CHECK(fgetc(f) == 'Z');
	CHECK(fclose(f) == 0);
	(void)a;

	/* read error before the first conversion completes */
	f = fopen(name, "wb");
	CHECK(f != 0);
	if (!f) return;
	errno = 0;
	r = fscanf(f, "%d", &a);
	CHECK(r == EOF);
	CHECK(errno == EBADF);
	CHECK(ferror(f) != 0);
	clearerr(f);
	CHECK(fclose(f) == 0);
}

/* fscanf.html DESCRIPTION, the [CX] assignment-allocation character:
 * "The %c, %s, and %[ conversion specifiers shall accept an optional
 * assignment-allocation character 'm', which shall cause a memory
 * buffer to be allocated to hold the string converted including a
 * terminating null character.  In such a case, the argument
 * corresponding to the conversion specifier should be a reference to a
 * pointer variable that will receive a pointer to the allocated
 * buffer."
 *
 * Asserted through sscanf() here, and through scanf() on a real stream
 * in test/posix-unreferenced.c's test_scanf_enomem(), which is where the
 * failure paths and the [ENOMEM] the page makes a shall-fail live.  The
 * two are worth having separately: sscanf() reaches the parser through a
 * memory FILE, and the allocating conversions read through the same
 * cursor as everything else, so a buffer sized from the wrong stream is
 * a mistake only one of the two would show. */
static void test_scanf_m_modifier(void)
{
	char *p = 0;
	char *q = 0;
	wchar_t *w = 0;

	CHECK(sscanf("abc", "%ms", &p) == 1);
	CHECK(p != 0);
	if (p) {
		CHECK(!strcmp(p, "abc"));
		free(p);
		p = 0;
	}

	/* all three conversions, and the l qualifier's wchar_t ** form */
	CHECK(sscanf("  hi 007", "%ms %m[0-9]", &p, &q) == 2);
	CHECK(p != 0 && !strcmp(p, "hi"));
	CHECK(q != 0 && !strcmp(q, "007"));
	free(p); free(q); p = q = 0;

	CHECK(sscanf("\xc3\xa9z", "%mls", &w) == 1);
	CHECK(w != 0 && w[0] == 0x00e9 && w[1] == L'z' && w[2] == 0);
	free(w); w = 0;

	CHECK(sscanf("wx", "%2mc", &p) == 1);
	CHECK(p != 0 && !memcmp(p, "wx", 2));
	free(p); p = 0;

	/* a matching failure hands over nothing */
	CHECK(sscanf("abc", "%m[0-9]", &p) == 0);
	CHECK(p == 0);
}

/* gets.html.  DESCRIPTION: "shall read bytes from the standard input
 * stream, stdin, into the array pointed to by s, until a <newline> is
 * read or an end-of-file condition is encountered.  Any <newline> shall
 * be discarded and a null byte shall be placed immediately after the
 * last byte read into the array."  RETURN VALUE: "Upon successful
 * completion, gets() shall return s.  If the end-of-file indicator for
 * the stream is set, or if the stream is at end-of-file, the end-of-file
 * indicator for the stream shall be set and gets() shall return a null
 * pointer.  If a read error occurs, the error indicator for the stream
 * shall be set, gets() shall return a null pointer, and set errno to
 * indicate the error."  ERRORS: "Refer to fgetc."
 *
 * Status, stated rather than editorialised: gets() was removed from the
 * C standard by C11 and POSIX.1-2017 marks it [OB] (obsolescent), with
 * a RATIONALE saying so and a FUTURE DIRECTIONS saying it "may be
 * removed in a future version" -- but it is still normatively specified
 * in the edition this audit is against, so it is audited.  spicule does
 * implement it: src/stdio/rw.c guards the definition with
 * `#if __STDC_VERSION__ < 201112L`, and this tree builds at -std=c99
 * (configure's CFLAGS_C99FSE), so the guard is satisfied and the symbol
 * is in lib/libc.a; include/stdio.h declares it unconditionally.
 *
 * The buffer here is far larger than any line the test itself writes,
 * so the APPLICATION USAGE hazard ("Reading a line that overflows the
 * array pointed to by s results in undefined behavior") is not
 * exercised -- there is no conforming way to exercise it. */
static void test_gets(const char *name)
{
	FILE *f;
	char g[64];
	char *p;

	f = fopen(name, "wb");
	CHECK(f != 0);
	if (!f) return;
	CHECK(fputs("line1\nline2", f) == 0);
	CHECK(fclose(f) == 0);

	if (!freopen(name, "rb", stdin)) { CHECK(0); return; }

	/* a newline-terminated line: the <newline> is discarded */
	memset(g, '#', sizeof g);
	p = gets(g);
	CHECK(p == g);
	CHECK(!strcmp(g, "line1"));
	CHECK(g[6] == '#');          /* the NUL went immediately after */

	/* the last line, ended by end-of-file rather than a <newline> */
	memset(g, '#', sizeof g);
	p = gets(g);
	CHECK(p == g);
	CHECK(!strcmp(g, "line2"));

	/* "if the stream is at end-of-file, the end-of-file indicator for
	 * the stream shall be set and gets() shall return a null pointer" */
	memset(g, '#', sizeof g);
	p = gets(g);
	CHECK(p == 0);
	CHECK(feof(stdin) != 0);
	/* "If the end-of-file indicator for the stream is set" -- a second
	 * call with the indicator already set is a null pointer too */
	CHECK(gets(g) == 0);

	/* "If a read error occurs, the error indicator for the stream shall
	 * be set, gets() shall return a null pointer, and set errno":
	 * fgetc.html [EBADF], reached by pointing stdin at a stream that is
	 * not open for reading. */
	if (!freopen(name, "wb", stdin)) { CHECK(0); return; }
	errno = 0;
	memset(g, '#', sizeof g);
	p = gets(g);
	CHECK(p == 0);
	CHECK(errno == EBADF);
	CHECK(ferror(stdin) != 0);
	clearerr(stdin);
}

/* ctermid.html.  DESCRIPTION: "shall generate a string that, when used
 * as a pathname, refers to the current controlling terminal for the
 * current process.  If ctermid() returns a pathname, access to the file
 * is not guaranteed."  RETURN VALUE: "If s is a null pointer, the
 * string shall be generated in an area that may be static, the address
 * of which shall be returned.  ...  If s is not a null pointer, s is
 * assumed to point to a character array of at least L_ctermid bytes;
 * the string is placed in this array and the value of s shall be
 * returned.  The symbolic constant L_ctermid is defined in <stdio.h>,
 * and shall have a value greater than 0.  The ctermid() function shall
 * return an empty string if the pathname that would refer to the
 * controlling terminal cannot be determined, or if the function is
 * unsuccessful."  ERRORS: "No errors are defined."
 *
 * Every one of those is checkable here.  Note what is deliberately not
 * asserted: that the returned pathname can be opened.  The DESCRIPTION
 * says outright that "access to the file is not guaranteed", so
 * spicule's fixed "/dev/tty" (src/stdio/misc.c) is conforming on a
 * platform with no such path -- the clause it would violate is the
 * empty-string one, and only if the pathname "cannot be determined",
 * which is a statement about the implementation's own knowledge, not
 * about whether open() would succeed.  The two branches are asserted to
 * agree with each other, which is the strongest portable statement
 * available.
 *
 * "The application shall not modify the string returned" is a
 * constraint on the caller, so there is nothing to assert; it is why
 * the NULL-argument result is only read here.  L_ctermid is 20 in
 * include/stdio.h, comfortably above the 9 bytes the implementation
 * copies -- checked below rather than assumed, since a too-small
 * L_ctermid with a strcpy() behind it is a buffer overflow in the
 * caller's array. */
static void test_ctermid(void)
{
	char t[L_ctermid];
	char *p, *q;

	/* "shall have a value greater than 0" */
	CHECK(L_ctermid > 0);

	memset(t, '#', sizeof t);
	p = ctermid(t);
	/* "the string is placed in this array and the value of s shall be
	 * returned" */
	CHECK(p == t);
	/* it must fit in the L_ctermid bytes the caller was told to supply */
	CHECK(strnlen(t, sizeof t) < sizeof t);

	/* "If s is a null pointer, the string shall be generated in an area
	 * that may be static, the address of which shall be returned." */
	q = ctermid(NULL);
	CHECK(q != 0);
	/* the two forms must describe the same terminal */
	CHECK(q != 0 && !strcmp(q, t));

	/* "shall return an empty string if the pathname ... cannot be
	 * determined": spicule always determines one, so the complement is
	 * what holds here.  Either outcome is conforming; asserting the
	 * measured one pins the behaviour. */
	CHECK(strlen(t) > 0);
}

/* flockfile.html, the whole page, and the verdict this audit reaches on
 * it.
 *
 * DESCRIPTION: "The functions shall behave as if there is a lock count
 * associated with each (FILE *) object.  This count is implicitly
 * initialized to zero when the (FILE *) object is created.  The (FILE
 * *) object is unlocked when the count is zero.  When the count is
 * positive, a single thread owns the (FILE *) object.  When the
 * flockfile() function is called, if the count is zero or if the count
 * is positive and the caller owns the (FILE *) object, the count shall
 * be incremented.  Otherwise, the calling thread shall be suspended,
 * waiting for the count to return to zero.  Each call to funlockfile()
 * shall decrement the count."  RETURN VALUE: "None for flockfile() and
 * funlockfile().  The ftrylockfile() function shall return zero for
 * success and non-zero to indicate that the lock cannot be acquired."
 * ERRORS: "No errors are defined."
 *
 * N/A, with the mechanism named, for every clause that distinguishes a
 * real lock from a no-op -- the suspension rule, the "a single thread
 * owns" rule, and ftrylockfile()'s non-zero return.  spicule has no
 * threads at all: there is no <pthread.h> in include/ (POSIX-GAP-
 * ACCOUNTING.md lists all 102 pthread interfaces as Absent), and
 * lib/libpthread.a is an 8-byte empty archive -- the "!<arch>\n"
 * magic and nothing else -- built purely so that `-lpthread` links.
 * With exactly one thread of control, the lock count can only ever be
 * incremented by its owner, so the "Otherwise, the calling thread shall
 * be suspended" branch is unreachable, ftrylockfile() can never fail,
 * and src/stdio/file.c's no-ops are indistinguishable from a correct
 * recursive mutex by any conforming program.  That is N/A by mechanism,
 * not UNIMPL: nothing was declined, the distinguishing observation does
 * not exist on this platform.
 *
 * What remains and is asserted: ftrylockfile()'s success return, that
 * nesting is permitted, and that the intervening stdio calls the page
 * requires to work inside a held lock ("All functions that reference
 * (FILE *) objects, except those with names ending in _unlocked, shall
 * behave as if they use flockfile() and funlockfile() internally")
 * really do -- a no-op that had accidentally become a self-deadlocking
 * real lock would hang exactly here, and a hang is a CI job timeout
 * rather than a clean failure.
 *
 * EXPIRY CONDITION, written down because this N/A can stop being one.
 * Every clause marked N/A above is N/A *only* for as long as
 * lib/libpthread.a stays an empty archive and include/ has no
 * <pthread.h>.  This is a no-op that is correct today and would be
 * wrong the day a second thread of control exists.  If <pthread.h>
 * ever lands, all of those clauses become reachable at once and
 * src/stdio/file.c's three functions become BUGs without a single line
 * of them changing -- which is exactly the kind of regression nobody
 * goes looking for, because no diff introduces it.  Whoever adds
 * threading to this libc has to come back here.  The same condition is
 * recorded in test/POSIX-COVERAGE.md's group K rows, so it is not
 * carried by this comment alone. */
static void test_flockfile_nesting(const char *name)
{
	FILE *f;
	int c;

	f = fopen(name, "wb");
	CHECK(f != 0);
	if (!f) return;
	/* "shall return zero for success" on an unlocked stream */
	CHECK(ftrylockfile(f) == 0);
	/* "if the count is positive and the caller owns the (FILE *)
	 * object, the count shall be incremented" -- nested acquisition by
	 * the owner, by both spellings */
	flockfile(f);
	CHECK(ftrylockfile(f) == 0);
	/* a locked stream still serves ordinary (locking) stdio calls to
	 * its owner */
	CHECK(fputs("ab", f) == 0);
	CHECK(fflush(f) == 0);
	/* "Each call to funlockfile() shall decrement the count" */
	funlockfile(f);
	funlockfile(f);
	funlockfile(f);
	CHECK(fclose(f) == 0);

	/* getc_unlocked.html: the _unlocked forms are "functionally
	 * equivalent to the original versions" and are the reason the
	 * flockfile() scope exists at all ("The only case where the use of
	 * flockfile() and funlockfile() is required is to provide a scope
	 * protecting uses of the *_unlocked functions/macros" --
	 * flockfile.html RATIONALE). */
	f = fopen(name, "rb");
	CHECK(f != 0);
	if (!f) return;
	flockfile(f);
	c = getc_unlocked(f);
	CHECK(c == 'a');
	CHECK(getc(f) == 'b');
	CHECK(getc_unlocked(f) == EOF);
	funlockfile(f);
	CHECK(fclose(f) == 0);
}

/* XBD <stdarg.h> (basedefs/stdarg.h.html), the whole DESCRIPTION.
 *
 * "The va_start() macro is invoked to initialize ap to the beginning of
 * the list before any calls to va_arg()."  "The va_arg() macro shall
 * return the next argument in the list pointed to by ap.  Each
 * invocation of va_arg() modifies ap so that the values of successive
 * arguments are returned in turn."  "Different types can be mixed, but
 * it is up to the routine to know what type of argument is expected."
 * "The va_end() macro is used to clean up; it invalidates ap for use
 * (unless va_start() or va_copy() is invoked again)."  "Multiple
 * traversals, each bracketed by va_start() ... va_end(), are possible."
 *
 * And the two explicitly-permitted type mismatches, which are clauses in
 * their own right and are the reason a naive implementation can look
 * correct on a narrower test:
 *   "One type is a signed integer type, the other type is the
 *    corresponding unsigned integer type, and the value is
 *    representable in both types."
 *   "One type is a pointer to void and the other is a pointer to a
 *    character type."
 *
 * va_copy is already covered by va_copy_sees_same() above; what is new
 * here is the mixed-type walk (which exercises the x86-64 register/
 * stack hand-off that a same-width walk never leaves), the two
 * permitted mismatches, and the repeat traversal. */
static int stdarg_mixed(int n, ...)
{
	va_list ap;
	int i, ok = 1;
	double d;
	char *s;
	long long ll;
	unsigned u;
	void *v;

	(void)n;
	va_start(ap, n);
	i = va_arg(ap, int);
	d = va_arg(ap, double);
	s = va_arg(ap, char *);
	ll = va_arg(ap, long long);
	/* signed passed, unsigned read: "the value is representable in
	 * both types" */
	u = va_arg(ap, unsigned);
	/* char * passed, void * read */
	v = va_arg(ap, void *);
	va_end(ap);

	if (i != 7) ok = 0;
	if (!(d > 2.49 && d < 2.51)) ok = 0;
	if (!s || strcmp(s, "str")) ok = 0;
	if (ll != 1234567890123LL) ok = 0;
	if (u != 99u) ok = 0;
	if (!v || strcmp((char *)v, "vp")) ok = 0;

	/* "Multiple traversals, each bracketed by va_start() ... va_end(),
	 * are possible." */
	va_start(ap, n);
	if (va_arg(ap, int) != 7) ok = 0;
	va_end(ap);
	return ok;
}

/* XBD <stdarg.h>: "The object ap may be passed as an argument to another
 * function; if that function invokes the va_arg() macro with parameter
 * ap, the value of ap in the calling function is unspecified and shall
 * be passed to the va_end() macro prior to any further reference to ap."
 *
 * That is exactly the contract every v-form relies on, and vfprintf.html
 * spells out the other half of it: "These functions shall not invoke the
 * va_end macro.  As these functions invoke the va_arg macro, the value
 * of ap after the return is unspecified."  So the testable statement is
 * that a *partially consumed* ap handed to a v-form continues from where
 * the caller left off -- not from the beginning -- and that the caller
 * may then va_end() it. */
static int stdarg_handoff(char *out, size_t outsz, const char *fmt, ...)
{
	va_list ap;
	int first, r;

	va_start(ap, fmt);
	first = va_arg(ap, int);
	r = vsnprintf(out, outsz, fmt, ap);
	va_end(ap);
	return first == 11 ? r : -1;
}

static void test_stdarg(void)
{
	char b[64];

	CHECK(stdarg_mixed(6, 7, 2.5, "str", 1234567890123LL, 99, (void *)"vp"));

	memset(b, 0, sizeof b);
	CHECK(stdarg_handoff(b, sizeof b, "%d-%s", 11, 22, "zz") == 5);
	CHECK(!strcmp(b, "22-zz"));
}

int main(void)
{
	char *name = make_tmp("posix-stdio-XXXXXX");
	CHECK(name != 0);
	if (name) {
		test_fflush_read_stream(name);
		test_update_stream_rule(name);
		test_setvbuf(name);
		test_ungetc_errors(name);
		test_fprintf_return(name);
		test_clearerr_both(name);
		remove(name);
		free(name);
	}
	test_perror();
	test_popen();

	test_snprintf_boundaries();
	test_snprintf_eoverflow();
	test_block_io_size_overflow();
	test_memory_stream_position_overflow();
	test_printf_int_min_width_no_overflow();
	test_printf_z_modifier_width();
	test_printf_l_modifier();
	test_printf_positional_arguments();
	test_printf_apostrophe_flag();
	test_printf_width_precision();
	test_sscanf_clauses();
	test_ctermid();
	test_stdarg();

	name = make_tmp("posix-stdio2-XXXXXX");
	CHECK(name != 0);
	if (name) {
		test_putc_family(name);
		test_fseeko_ftello(name);
		test_flockfile(name);
		test_flockfile_nesting(name);
		test_v_forms(name);
		test_getc_unlocked(name);
		test_tmpnam_does_not_create();
		test_tempnam();
		test_printf_output_error(name);
		test_dprintf_fd_path(name);
		test_fscanf_stream_clauses(name);
		test_scanf_m_modifier();
		/* these three repoint stdin at the temp file and leave it there */
		test_vprintf_vscanf(name);
		test_getchar(name);
		test_gets(name);
		remove(name);
		free(name);
	}
	test_putchar_return();

	if (fails) printf("%d check(s) failed\n", fails);
	else printf("all checks passed\n");
	return fails != 0;
}
