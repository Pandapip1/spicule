/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * tail(1p): `tail [-f] [-c number|-n number] [file...]`
 *
 * DESCRIPTION: "The tail utility shall copy its input file to standard
 * output beginning at a designated place."  "number" (for either -c or
 * -n) is a decimal integer, optionally signed:
 *  - "+": relative to the beginning of the file -- number must be
 *    non-zero, and counts from 1 ("-c +1" is the first byte, "-n +1"
 *    the first line).
 *  - "-" or no sign: relative to the end of the file -- the number of
 *    trailing bytes/lines to copy.
 * "If neither -c nor -n is specified, -n 10 shall be assumed."
 *
 * ---- Reading the whole input before writing anything ------------------
 *
 * "Relative to the end of the file" cannot be answered without knowing
 * where the end is, and unlike head(1p) there is no way to stream this
 * and still support the from-end form for input that is not seekable --
 * a real pathname operand could still be a pipe or a FIFO on this
 * platform.  Rather than special-case seekable-vs-not, read_all() below
 * always reads the whole input into one growable buffer first, then
 * both -c and -n (and both signs of each) are answered as an index into
 * that buffer -- see the byte-offset arithmetic in __util_tail_main()
 * below.  The cost is memory proportional to the whole input rather
 * than to `number`; for the sizes this project handles that trade is
 * simpler and correct, over a seek-and-scan-backward optimization this
 * file does not attempt.
 *
 * -f ("do not terminate after the last line ... read the appended data")
 * has no natural exit, so after the initial tail is written it hands
 * off to tail_follow() below, which polls fstat()'s st_size rather than
 * blocking a single read() forever: this platform has no filesystem-
 * change-notification primitive (no inotify equivalent; see src/select/,
 * src/thread/).  fstat() never blocks, which is what makes size-polling
 * safe to round-robin across several regular-file operands at once (see
 * tail_follow()); a single non-regular operand (a pipe/FIFO, or "-"/
 * no-operand stdin fed from one) instead gets a plain blocking read()
 * loop, since a true EOF there (writer closed) really is the end, unlike
 * a regular file which can always grow again.  SIGINT (Ctrl-C) ends the
 * loop the normal way -- its default disposition is process termination,
 * so nothing here installs a handler.
 *
 * The multi-operand `==> file <==` banner extends past XCU's own
 * single-`[file]` SYNOPSIS the same way multiple operands are, for
 * symmetry with every other utility in this tier.
 *
 * EXIT STATUS: "0 Successful completion." ">0 An error occurred." --
 * diagnose-and-continue across operands.
 *
 * Spec consulted: https://pubs.opengroup.org/onlinepubs/9699919799/utilities/tail.html
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include "util.h"
#include "ownership_stubs.h"

/* -f's poll interval.  200ms: frequent enough that an interactive
 * `tail -f` reads as "instant" the way GNU tail's 1s default does not,
 * cheap enough (five fstat()s a second per followed file) not to matter
 * against any real workload. */
#define TAIL_FOLLOW_POLL_NS 200000000L

enum tail_mode { TAIL_LINES, TAIL_BYTES };

static int write_all(const char *buf withtok(readable_span(len)), size_t len)
{
	size_t off = 0;
	while (off < len) {
		__ownership_readable_span(buf + off, len - off);
		ssize_t w = write(STDOUT_FILENO, buf + off, len - off);
		if (w < 0) return -1;
		if (!w || (size_t)w > len - off) { errno = EIO; return -1; }
		off += (size_t)w;
	}
	return 0;
}

/* Reads the whole of `fd` into a malloc()'d buffer, growing it as
 * needed.  *out is set regardless of success (freeing it is always the
 * caller's job on a non-NULL result); returns the number of bytes read,
 * or (size_t)-1 on a read failure. */
static size_t read_all(int fd, char **out withtok(heap_allocated))
{
	size_t cap = 65536, len = 0;
	char *buf = malloc(cap);
	ssize_t r;

	if (!buf) { *out = 0; return (size_t)-1; }

	for (;;) {
		if (len == cap) {
			char *nb;
			size_t newcap;
			if (!__util_array_capacity(cap, len, 1, 65536, 1, &newcap)) {
				free(buf); *out = 0; return (size_t)-1;
			}
			nb = realloc(buf, newcap);
			if (!nb) { free(buf); *out = 0; return (size_t)-1; }
			buf = nb;
			cap = newcap;
		}
		__ownership_writable_span(buf + len, cap - len);
		r = read(fd, buf + len, cap - len);
		if (r < 0) { free(buf); *out = 0; return (size_t)-1; }
		if (r == 0) break;
		len += (size_t)r;
	}
	*out = buf;
	return len;
}

/* Finds the start offset of the `index`-th line (0-based) in `buf`
 * (length `len`), where a "line" is a maximal run up to and including
 * its terminating '\n', except possibly the last, which may run to
 * end-of-buffer instead.  *nlines is set to the total line count.
 * `index >= *nlines` is the caller's responsibility to check first. */
static size_t nth_line_offset(const char *buf, size_t len, size_t index, size_t *nlines) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	size_t i, n = 0, want_offset = 0;
	int found = 0;

	if (len == 0) { *nlines = 0; return 0; }
	if (index == 0) want_offset = 0, found = 1;

	for (i = 0; i < len; i++) {
		if (buf[i] != '\n') continue;
		if (i + 1 >= len) continue;   /* trailing newline: no new line starts after it */
		n++;
		if (!found && n == index) { want_offset = i + 1; found = 1; }
	}
	*nlines = n + 1; /* the n newlines seen mid-buffer, plus the final line itself */
	return want_offset;
}

static int tail_one(int fd, enum tail_mode mode, int from_end, long long number, const char *label) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	char *buf;
	size_t len;
	size_t start;
	int rc = 0;

	len = read_all(fd, &buf);
	if (len == (size_t)-1) {
		int saved = errno;
		__util_diagf("tail: %s: %s\n", label, strerror(saved));
		return -1;
	}

	/* Clamp to len+1 (the largest value that can change the outcome:
	 * "at least the whole file") before any (size_t) cast below -- a
	 * huge -c/-n argument must behave like "the whole file", not wrap
	 * around through size_t's narrower range on an ILP32 build. */
	if (sizeof len < sizeof number || len < (size_t)LLONG_MAX) {
		long long limit = (long long)len + 1;
		if (number > limit) number = limit;
	}

	if (mode == TAIL_BYTES) {
		if (from_end) {
			if (number <= 0) start = len;
			else if ((size_t)number >= len) start = 0;
			else start = len - (size_t)number;
		} else {
			/* number is 1-based; "+1" is the first byte. */
			size_t k = (size_t)(number - 1);
			start = (k >= len) ? len : k;
		}
	} else {
		size_t nlines;
		if (from_end) {
			if (number <= 0) {
				start = len; /* "-n 0" (or "-n -0"): nothing to print */
			} else {
				(void)nth_line_offset(buf, len, 0, &nlines); /* just to get nlines */
				if ((size_t)number >= nlines) start = 0;
				else start = nth_line_offset(buf, len, nlines - (size_t)number, &nlines);
			}
		} else {
			/* "+K": start at the K-th line, 1-based. */
			size_t k = (size_t)(number - 1);
			(void)nth_line_offset(buf, len, 0, &nlines);
			start = (k >= nlines) ? len : nth_line_offset(buf, len, k, &nlines);
		}
	}

	__ownership_readable_span(buf + start, len - start);
	if (write_all(buf + start, len - start) < 0) {
		int saved = errno;
		__util_diagf("tail: %s: %s\n", label, strerror(saved));
		rc = -1;
	}
	free(buf);
	return rc;
}

/* One -f target: an already-open, already-tailed descriptor.  `pos` is
 * only meaningful for a regular file (`is_regular`); it starts out
 * wherever read_all() left the file position -- exactly end-of-file at
 * the moment the initial tail was read -- and only ever advances. */
struct tail_follow_target {
	int fd;
	const char *label;
	int is_regular;
	off_t pos;
};

/* Drains whatever of `t`'s regular file lies between t->pos and
 * `new_size` (a size already observed to be greater), writing it to
 * stdout and advancing t->pos to match.  Returns 0, or -1 on a read/
 * write failure (diagnostic already printed). read() on a regular file
 * never blocks waiting for more bytes than are already there, so this
 * cannot stall a round-robin poll across several targets the way a
 * blocking read() on a pipe could. */
static int tail_follow_drain(struct tail_follow_target *t, off_t new_size)
{
	char buf[65536];

	while (t->pos < new_size) {
		off_t want = new_size - t->pos;
		size_t chunk = want > (off_t)sizeof buf ? sizeof buf : (size_t)want;
		ssize_t r = read(t->fd, buf, chunk);

		if (r < 0) {
			if (errno == EINTR) continue;
			__util_diagf("tail: %s: %s\n", t->label, strerror(errno));
			return -1;
		}
		if (r == 0) break;   /* raced with a truncation; next poll catches up */
		__ownership_readable_span(buf, (size_t)r);
		if (write_all(buf, (size_t)r) < 0) {
			__util_diagf("tail: %s: %s\n", t->label, strerror(errno));
			return -1;
		}
		t->pos += r;
	}
	return 0;
}

/* -f's main loop, entered once every operand has printed its initial
 * tail.  Runs until a read/write failure (diagnostic already printed,
 * -1 returned) or -- the common case -- until SIGINT/Ctrl-C kills the
 * process outright (see this file's header comment); there is no other
 * exit for a regular-file target, since a regular file can always grow
 * again no matter how long it has sat still. */
static int tail_follow(struct tail_follow_target *targets, int ntargets)
{
	/* Not 0: the caller's own initial-dump loop over the operands (in
	 * argv order, same order targets[] was built in) always finishes on
	 * the last one, so that is the last banner a multi-operand run has
	 * actually shown -- starting this loop's own idea of "last shown"
	 * from scratch would reprint that same file's banner the moment it
	 * is also the first one to grow, even though nothing has switched
	 * files from the reader's point of view yet. */
	const char *last_label = ntargets > 1 ? targets[ntargets - 1].label : 0;

	/* Exactly one target, and it is not a regular file: a pipe/FIFO (or
	 * character-device stdin) has no "size" to poll, and read() already
	 * blocks until either more data arrives or the writer closes --
	 * which, unlike a regular file, really is the end, since nothing
	 * will ever make a closed pipe grow again. */
	if (ntargets == 1 && !targets[0].is_regular) {
		char buf[65536];
		for (;;) {
			ssize_t r = read(targets[0].fd, buf, sizeof buf);
			if (r < 0) {
				if (errno == EINTR) continue;
				__util_diagf("tail: %s: %s\n", targets[0].label, strerror(errno));
				return -1;
			}
			if (r == 0) return 0;   /* writer closed: input exhausted */
			__ownership_readable_span(buf, (size_t)r);
			if (write_all(buf, (size_t)r) < 0) {
				__util_diagf("tail: %s: %s\n", targets[0].label, strerror(errno));
				return -1;
			}
		}
	}

	/* One or more regular-file targets (a lone non-regular target took
	 * the branch above; a non-regular target mixed in among several
	 * operands is skipped below -- fstat()'s st_size means nothing for
	 * a pipe, and blocking read() on one would stall every other
	 * target's polling, so it only ever gets its initial tail). */
	for (;;) {
		int i;

		for (i = 0; i < ntargets; i++) {
			struct stat st;

			if (!targets[i].is_regular) continue;
			if (fstat(targets[i].fd, &st) < 0) continue;   /* transient; retry next tick */
			if (st.st_size < targets[i].pos) targets[i].pos = st.st_size; /* truncated */
			if (st.st_size <= targets[i].pos) continue;

			if (ntargets > 1 && last_label != targets[i].label) {
				printf("\n==> %s <==\n", targets[i].label);
				last_label = targets[i].label;
				if (fflush(stdout) < 0) {
					__util_diagf("tail: %s: %s\n", targets[i].label, strerror(errno));
					return -1;
				}
			}
			if (tail_follow_drain(&targets[i], st.st_size) < 0) return -1;
		}
		{
			struct timespec nap = { 0, TAIL_FOLLOW_POLL_NS };
			(void)nanosleep(&nap, 0);
		}
	}
}

/* Parses "[+|-]number" per tail(1p)'s -c/-n option-argument grammar.
 * *from_end is 1 for '-' or no sign, 0 for '+'.  Returns 0 on success,
 * -1 on anything that is not that grammar (including "+0", which the
 * spec singles out as invalid: "If the '+' ... is used, number shall be
 * non-zero"). */
static int parse_signed_number(const char *s, int *from_end, long long *number)
{
	char *end;
	long long v;
	int sign_plus = 0;

	if (*s == '+') { sign_plus = 1; s++; }
	else if (*s == '-') { s++; }
	if (!*s) return -1;
	v = strtoll(s, &end, 10);
	if (*end || v < 0) return -1;
	if (sign_plus && v == 0) return -1;
	*from_end = !sign_plus;
	*number = v;
	return 0;
}

int __util_tail_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i;
	enum tail_mode mode = TAIL_LINES;
	int from_end = 1;
	long long number = 10;
	int mode_given = 0;
	int had_error = 0;
	int first_banner = 1;
	int follow = 0;

	for (i = 1; i < argc; i++) {
		char *a = argv[i];

		if (!strcmp(a, "--")) { i++; break; }
		if (!strcmp(a, "-f")) { follow = 1; continue; }
		if (!strcmp(a, "-c") || !strcmp(a, "-n")) {
			enum tail_mode m = (a[1] == 'c') ? TAIL_BYTES : TAIL_LINES;
			int fe;
			long long num;

			if (i + 1 >= argc) {
				__util_diagf("tail: %s: option requires an argument\n", a);
				return 1;
			}
			if (parse_signed_number(argv[++i], &fe, &num) < 0) {
				__util_diagf("tail: %s: invalid number\n", argv[i]);
				return 1;
			}
			mode = m; from_end = fe; number = num; mode_given = 1;
			continue;
		}
		if (a[0] == '-' && a[1] != 0) {
			__util_diagf("tail: invalid option -- '%s'\n", a);
			return 1;
		}
		break;
	}
	(void)mode_given;

	if (i >= argc) {
		int rc = tail_one(STDIN_FILENO, mode, from_end, number, "standard input");

		if (rc < 0) return 1;
		if (follow) {
			struct tail_follow_target t;
			struct stat st;

			t.fd = STDIN_FILENO;
			t.label = "standard input";
			t.is_regular = fstat(STDIN_FILENO, &st) == 0 && S_ISREG(st.st_mode);
			t.pos = 0;
			if (t.is_regular) {
				off_t p = lseek(STDIN_FILENO, 0, SEEK_CUR);
				t.pos = (p < 0) ? st.st_size : p;
			}
			return tail_follow(&t, 1) < 0 ? 1 : 0;
		}
		return 0;
	}

	{
		int noperands = argc - i;
		struct tail_follow_target *targets = 0;
		int ntargets = 0;

		if (follow) {
			targets = malloc((size_t)noperands * sizeof *targets);
			if (!targets) {
				__util_diagf("tail: %s\n", strerror(ENOMEM));
				return 1;
			}
		}

		for (; i < argc; i++) {
			const char *path = argv[i];
			int is_stdin = !strcmp(path, "-");
			int fd;
			int rc;

			if (noperands > 1) {
				printf("%s==> %s <==\n", first_banner ? "" : "\n", path);
				first_banner = 0;
				if (fflush(stdout) < 0) had_error = 1;
			}

			fd = is_stdin ? STDIN_FILENO : open(path, O_RDONLY);
			if (fd < 0) {
				__util_diagf("tail: %s: %s\n", path, strerror(errno));
				had_error = 1;
				continue;
			}

			rc = tail_one(fd, mode, from_end, number, path);
			if (rc < 0) had_error = 1;

			/* A target that followed successfully stays open across
			 * the follow loop below (and past it, until the process
			 * exits) -- only a failed or non-followed operand's fd
			 * gets closed here. */
			if (follow && rc == 0) {
				struct tail_follow_target *t = &targets[ntargets++];
				struct stat st;

				t->fd = fd;
				t->label = path;
				t->is_regular = fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
				t->pos = 0;
				if (t->is_regular) {
					off_t p = lseek(fd, 0, SEEK_CUR);
					t->pos = (p < 0) ? st.st_size : p;
				}
			} else if (!is_stdin) {
				(void)close(fd);
			}
		}

		if (follow && ntargets > 0 && tail_follow(targets, ntargets) < 0)
			had_error = 1;
		free(targets);
	}

	return had_error ? 1 : 0;
}
