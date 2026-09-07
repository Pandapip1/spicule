/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Fuzzes glob()/globfree() (src/glob/glob.c). Unlike fnmatch, glob()
 * walks a real directory tree, so this harness builds one once (under
 * fuzz/ntstubs.c's simulated volume) at first call and roots every
 * pattern at it -- names chosen to straddle glob's special cases:
 * leading dots, metacharacters as literal filenames (testing
 * GLOB_NOESCAPE and the no-metacharacter-means-no-pattern path), and two
 * directory levels for multi-component patterns and GLOB_MARK. The
 * pattern is the whole fuzz input, rooted unless byte 0 says otherwise,
 * so absolute patterns, "//", and the empty pattern get exercised too.
 *
 * This is a memory-safety and self-consistency net, not a differential
 * oracle (no fuzzer can see a semantic disagreement with a POSIX clause
 * without a reference glob -- see test/verification-coverage-accounting.md
 * section 1): return value is one of the four documented codes;
 * gl_pathv is NULL-terminated at gl_pathc with every entry before it
 * readable (read in full, so ASan catches an over-claimed count);
 * GLOB_DOOFFS's leading slots are NULL; without GLOB_NOSORT each call's
 * own run is in strcmp order -- per run, not across a GLOB_APPEND
 * boundary, since glob.html says an appended run is not sorted together
 * with the previous one (asserting across it was GitHub issue #2, a
 * harness bug, not a glob() one -- pinned by
 * test_glob_fuzz_append_same_pattern_runs); GLOB_MARK only ever adds
 * '/' to a real directory; globfree() runs on every outcome and a
 * second call is a no-op, covering (with ASan/LeakSanitizer) glob()'s
 * ownership-transfer paths, GLOB_APPEND's four-ways-back included.
 *
 * GLOB_APPEND is driven for real -- a second glob() onto the first
 * result -- since that's where pointers move between owners and a
 * double-free would live.
 */
#include <glob.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

extern void oracle_mismatch_i(const char *, const char *, long long, long long);
extern void oracle_mismatch_s(const char *, const char *, const char *, const char *);

#define ROOT "/tmp/g"

static void touch(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd >= 0) { (void)write(fd, "x", 1); close(fd); }
}

/* Built once -- a per-input rebuild would dominate run time and mean no
 * reproducer actually reproduces.
 *
 * ROOT "/back\\slash" silently fails to be created (touch() ignores a
 * failed open(), and fuzz/ntstubs.c's simulated volume rejects this
 * name): the list below names fourteen files but only thirteen exist,
 * so the "literal backslash in a filename" coverage this fixture claims
 * is one name short. A gap in ntstubs.c's volume, not this file's own. */
static void fixture(void)
{
	static int done;
	static const char *const files[] = {
		ROOT "/a", ROOT "/ab", ROOT "/abc", ROOT "/b",
		ROOT "/.hidden", ROOT "/.h2",
		ROOT "/[x]", ROOT "/a*b", ROOT "/a?c", ROOT "/back\\slash",
		ROOT "/d/a", ROOT "/d/ab", ROOT "/d/.h", ROOT "/d/e/f"
	};
	size_t i;

	if (done) return;
	done = 1;
	mkdir(ROOT, 0755);
	mkdir(ROOT "/d", 0755);
	mkdir(ROOT "/d/e", 0755);
	for (i = 0; i < sizeof files / sizeof *files; i++) touch(files[i]);
}

/* __real_stat, not stat: every harness is linked with -Wl,--wrap=stat so
 * a plain `stat` call resolves to __wrap_stat, which answers in the
 * *host's* struct stat layout (for libFuzzer's own use) rather than
 * spicule's smaller one -- calling it here overflows the caller's buffer.
 * Confirmed: the first version of this file called stat() and ASan
 * reported a stack-buffer-overflow within four inputs. */
extern int __real_stat(const char *, struct stat *);

static int is_dir(const char *path)
{
	struct stat st;
	return __real_stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* `base`: entries already in *g before this call (0, or the previous
 * call's gl_pathc for GLOB_APPEND) -- collating order is a per-call
 * property, not a whole-vector one (glob.html: an appended run is "not
 * sorted together with the previous pathnames"). Only the single
 * comparison straddling that boundary is skipped; both runs are still
 * checked in full. See header for the GitHub issue #2 this fixed. */
static void check(const char *pat, int flags, int rc, size_t base, glob_t *g)
{
	size_t i, offs = (flags & GLOB_DOOFFS) ? g->gl_offs : 0;

	if (rc != 0 && rc != GLOB_NOMATCH && rc != GLOB_NOSPACE && rc != GLOB_ABORTED)
		oracle_mismatch_i("glob returned a code not in <glob.h>", pat, rc, 0);
	if (rc != 0) return;

	if (!g->gl_pathv) {
		oracle_mismatch_i("glob returned 0 with a NULL gl_pathv", pat, 0, 1);
		return;
	}
	if (g->gl_pathv[offs + g->gl_pathc] != NULL)
		oracle_mismatch_i("gl_pathv is not NULL-terminated at gl_pathc", pat,
		                  (long long)g->gl_pathc, 0);
	for (i = 0; i < offs; i++)
		if (g->gl_pathv[i] != NULL)
			oracle_mismatch_i("GLOB_DOOFFS leading slot is not NULL", pat,
			                  (long long)i, 0);

	for (i = 0; i < g->gl_pathc; i++) {
		const char *s = g->gl_pathv[offs + i];
		size_t len;
		if (!s) {
			oracle_mismatch_i("NULL inside the gl_pathc entries", pat, (long long)i, 0);
			continue;
		}
		len = strlen(s);                        /* ASan sees an unterminated one here */
		if (i > base && !(flags & GLOB_NOSORT) &&
		    strcmp(g->gl_pathv[offs + i - 1], s) > 0)
			oracle_mismatch_s("glob result is not in collating order", pat,
			                  g->gl_pathv[offs + i - 1], s);
		/* GLOB_MARK, one direction only: a marked name must really be
		 * a directory (the converse doesn't hold -- glob("") and
		 * GLOB_NOCHECK can legitimately return unmarked non-matches).
		 * The strcmp(s, pat) exclusion is GLOB_NOCHECK's verbatim
		 * pattern copy, which a real match can't be byte-equal to
		 * since GLOB_MARK always appends '/' to those. */
		if ((flags & GLOB_MARK) && len > 1 && s[len - 1] == '/' &&
		    strcmp(s, pat) != 0) {
			char tmp[1024];
			if (len < sizeof tmp) {
				memcpy(tmp, s, len);
				tmp[len - 1] = 0;
				if (!is_dir(tmp))
					oracle_mismatch_s("GLOB_MARK marked a non-directory", pat, s, tmp);
			}
		}
	}
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	char pat[512];
	size_t n;
	int flags, rooted, rc;
	glob_t g;

	if (size < 2) return 0;
	fixture();

	/* Only the seven defined bits: an undefined bit in glob's flags is
	 * not a documented input, and feeding one would let the fuzzer
	 * chase behaviour no clause describes. */
	flags = data[0] & 0x07f;
	rooted = (data[1] & 1) != 0;
	data += 2; size -= 2;

	n = size;
	if (n > sizeof pat - sizeof ROOT - 2) n = sizeof pat - sizeof ROOT - 2;
	if (rooted) {
		memcpy(pat, ROOT "/", sizeof ROOT);
		memcpy(pat + sizeof ROOT, data, n);
		pat[sizeof ROOT + n] = 0;
	} else {
		memcpy(pat, data, n);
		pat[n] = 0;
	}
	if (memchr(pat, 0, rooted ? sizeof ROOT + n : n)) return 0;

	memset(&g, 0, sizeof g);
	if (flags & GLOB_DOOFFS) g.gl_offs = 2;

	rc = glob(pat, flags & ~GLOB_APPEND, NULL, &g);
	check(pat, flags & ~GLOB_APPEND, rc, 0, &g);

	/* Only legal after a successful call, per glob.html. */
	if (rc == 0) {
		/* Captured before the call: gl_pathc covers both runs after. */
		size_t carried = g.gl_pathc;
		int rc2 = glob(pat, flags | GLOB_APPEND, NULL, &g);
		check(pat, flags | GLOB_APPEND, rc2, carried, &g);
	}

	globfree(&g);
	globfree(&g);                   /* must be a no-op, not a double free */
	return 0;
}
