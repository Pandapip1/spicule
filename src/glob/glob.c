/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * glob(): pattern matching against ntlibc's own working opendir/
 * readdir/stat layer (src/dirent/, src/unistd/stat.c), one '/'-
 * separated pattern component at a time, using fnmatch() (src/fnmatch/
 * fnmatch.c) to test each component against directory entries.  A
 * component with no unescaped '*', '?' or '[' is a literal: it is
 * unescaped and looked up directly with stat(), the same as the shell
 * never bothers to opendir() a directory just to find one name it
 * already knows.
 *
 * Hidden files: a directory entry whose name starts with '.' is only
 * matched when the pattern component itself starts with a literal '.',
 * the same convention every historical shell glob (and glibc's glob())
 * uses; "." and ".." are never matched, even then. Neither is required
 * by POSIX base glob(), which says nothing about dot-files at all, but
 * omitting it would make "*.txt" match a stray ".txt" hidden file in
 * a way no glob(1) call anyone has ever used actually behaves, so it
 * is implemented as the reasonable default a real caller expects.
 *
 * Tilde expansion is NOT here -- see include/glob.h's header comment.
 */
#include <glob.h>
#include <fnmatch.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "libc.h"
#include "ownership_stubs.h"

/* v carries internal_heap_allocated (the backing array itself, __malloc()'d
 * below) AND elements_withtok(internal_heap_allocated, n) (every element up
 * to n is itself a separate xstrdup()/unescape() heap allocation, never a
 * string literal or a borrowed pointer) -- src/wordexp/wordexp.c's own
 * struct pv, "same shape ... not shared", carries the identical pair for
 * the identical reason; see that file's own comment on both, including its
 * already-confirmed finding that the elements_withtok half does NOT make
 * AllocationLifetimeChecker recognize a pv_push(out, xstrdup(...))-style
 * per-element transfer (MemoryContractChecker's extent proofs read
 * elements_withtok; AllocationLifetimeChecker's escape recognition does
 * not) -- do_glob()'s own xstrdup() results handed to pv_push() below are
 * exactly that shape, and are not expected to stop being reported by it. */
struct pv {
	char **v withtok(internal_heap_allocated)
		elements_withtok(internal_heap_allocated, n)
		withtok(readable_elements(n)) withtok(writable_elements(cap));
	size_t n, cap;
};

/* s is genuinely null-terminated at every real call site: a string
 * literal ("/", ".", ""), prefix/newprefix (both maintained NUL-terminated
 * throughout do_glob() via join()'s own snprintf, but neither one itself
 * withtok(null_terminated) -- do_glob()'s own comment on prefix explains
 * why it is deliberately not given a parameter-level contract), tmp
 * (explicitly NUL-terminated two lines above its own xstrdup() call), or
 * pattern/pat (glob()'s own withtok(null_terminated) parameter). Tried
 * marking s withtok(null_terminated) here to resolve this function's own
 * "strlen(s)" finding below and reverted: xstrdup(prefix)/xstrdup(newprefix)
 * in do_glob() have no comparable fact to offer once xstrdup() itself
 * demands one, so the requirement simply relocates to those call sites as
 * new findings there (measured via a real tools/lint.sh ownership run) --
 * a strictly larger backlog than the one finding this was meant to close.
 * Left unannotated and the finding left open. */
withtok(internal_heap_allocated)
static char *xstrdup(const char *s)
{
	size_t n = strlen(s) + 1;
	char *p = __malloc(n);
	if (p) {
		memcpy(p, s, n);
	}
	return p;
}

/* -1 on allocation failure (frees s either way it owns it).
 *
 * p is required: p->n/p->cap are read unconditionally below, and every
 * real call site passes &out, the address of a caller's own local
 * struct pv, never NULL. s is deliberately NOT required -- the
 * `if (!s) return -1;` right below is real and load-bearing: every
 * caller passes an xstrdup()/unescape() result that can genuinely be
 * NULL on allocation failure (see xstrdup's/unescape's own `if (!p)
 * return 0;`), and this is how that OOM propagates as an ordinary
 * GLOB_NOSPACE rather than a crash. */
static int pv_push(struct pv *p, char *s) __attribute__((nonnull(1)));
static int pv_push(struct pv *p, char *s)
{
	if (!s) return -1;
	if (p->n == p->cap) {
		char **old = p->v;
		size_t nc, bytes, oldbytes;
		if (!__array_next_capacity(p->cap, p->n, 1, 16,
		    sizeof *p->v, &nc)) { __free(s); errno = ENOMEM; return -1; }
		bytes = nc * sizeof *p->v;
		oldbytes = p->n * sizeof *p->v;
		if (oldbytes > bytes) { __free(s); errno = ENOMEM; return -1; }
		char **nv = (char **)__malloc(bytes);
		size_t i;
		if (!nv) { __free(s); return -1; }
		if (old) {
			for (i = 0; i < p->n; i++) nv[i] = p->v[i];
		}
		__free((void *)old);
		p->v = nv;
		p->cap = nc;
	}
	/* p->v is non-NULL here either way, by the same shape as
	 * src/process/spawn_file_actions.c's own fa_push() comment on
	 * fa->__actions: either the growth branch above just set it, or
	 * p->n != p->cap already meant p->cap > 0, which by this function's
	 * own invariant only holds after an earlier successful growth
	 * already set p->v. Not expressible via nonnull on p itself (already
	 * marked above) -- a fact about one of p's FIELDS, not p, and a
	 * local proof the checker cannot follow through the conditional
	 * reassignment. */
	p->v[p->n++] = s;
	return 0;
}

/* p required: p->n is read unconditionally by the loop condition below,
 * and every real call site (do_glob()'s/glob()'s own &out) passes the
 * address of a local struct pv, never NULL. */
static void pv_free_from(struct pv *p, size_t from) __attribute__((nonnull(1)));
static void pv_free_from(struct pv *p, size_t from)
{
	size_t i;
	for (i = from; i < p->n; i++) __free(p->v[i]);
	__free((void *)p->v);
	p->v = 0;
	p->n = p->cap = 0;
}

/* p required: `*p` is read unconditionally at the loop's own entry, and
 * its one real call site (do_glob()) passes pat, itself required (see
 * do_glob()'s own comment below), never NULL. */
/* p is a genuine null-terminated C string at every real call site (both
 * do_glob()'s own pat and split_components()'s own p, each themselves
 * withtok(null_terminated)) -- marking p and the return here the same way
 * would resolve this function's own "strlen(p)" capability-token finding
 * below, matching string.h's strchr() for the identical returned-pointer
 * shape. Tried and reverted: doing so requires the checker to carry the
 * fact across `p += 2` (a plain compound-assignment reassignment, not the
 * `for (...; s++)`-shaped loop increment string.h's own strlen()/strchr()
 * use), which it does not -- and the resulting "ownership destination
 * token state is not proven"/"source ownership token has already moved"
 * findings on that reassignment, PLUS the loss of the fact at every
 * caller across a real function-call boundary (do_glob()'s own
 * strlen(slash), split_components()'s own slash = find_slash(...)),
 * measured strictly more findings than the one this was meant to fix
 * (confirmed via a real tools/lint.sh ownership run, not just this file).
 * Left unannotated and the finding left open. */
static const char *find_slash(const char *p, int flags) __attribute__((nonnull(1)));
static const char *find_slash(const char *p, int flags)
{
	/* Every pass consumes at least one byte, or two for an escaped byte.
	 * The original string extent is therefore an independent exact upper
	 * bound on the number of iterations. */
	size_t remaining = strlen(p);

	while (remaining > 0 && *p) {
		remaining--;
		if (!(flags & GLOB_NOESCAPE) && *p == '\\' && p[1]) { p += 2; continue; }
		if (*p == '/') return p;
		p++;
	}
	return 0;
}

/* s required: subscripted unconditionally (`s[i]`) whenever len >= 1,
 * and its one real call site (do_glob()) passes pat, itself required,
 * never NULL. */
static int has_meta(const char *s, size_t len, int flags) __attribute__((nonnull(1)));
static int has_meta(const char *s, size_t len, int flags)
{
	size_t i, steps;
	for (i = 0, steps = 0; i < len && steps < len; steps++) {
		if (!(flags & GLOB_NOESCAPE) && s[i] == '\\' && i + 1 < len) {
			i += 2;
			continue;
		}
		if (s[i] == '*' || s[i] == '?' || s[i] == '[') return 1;
		i++;
	}
	return 0;
}

/* s required: subscripted unconditionally (`s[i]`) whenever len >= 1,
 * and its one real call site (do_glob()) passes pat, itself required,
 * never NULL. */
withtok(internal_heap_allocated)
withtok(writable_span(len))
static char *unescape(const char *s, size_t len, int flags)
    __attribute__((nonnull(1)));
withtok(internal_heap_allocated)
withtok(writable_span(len))
static char *unescape(const char *s, size_t len, int flags)
{
	char *buf;
	size_t i = 0, j = 0, remaining = len, bytes;
	if (!__size_add_checked(len, 1, &bytes)) return 0;
	buf = __malloc(bytes);
	if (!buf) return 0;
	while (remaining > 0) {
		if (!(flags & GLOB_NOESCAPE) && s[i] == '\\' && remaining > 1) {
			i++;
			remaining--;
		}
		buf[j++] = s[i++];
		remaining--;
	}
	buf[j] = 0;
	return buf;
}

/* a/b required: this is qsort()'s own comparator, called (src/stdlib/
 * qsort.c's sift()/qsort_r()) only as cmp(base + i*sz, base + j*sz, ...)
 * for i, j inside [0, n) of the real array being sorted -- an internal
 * heapsort never invents an out-of-range index or a NULL element
 * address, so both arguments are always the address of a real char* in
 * out.v, never NULL, whenever this is actually reached. */
static int cmpstrp(const void *a, const void *b) __attribute__((nonnull(1, 2)));
static int cmpstrp(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Join prefix (preflen bytes, already ending in '/' unless empty) with
 * name (namelen bytes) into out, appending a trailing '/' if
 * want_slash.  On success outlen receives the joined byte length.
 * Returns 0, or -1 if it would not fit in PATH_MAX. */
static int join(char *out withtok(writable_span(outcap)), size_t outcap,
                const char *prefix withtok(readable_span(preflen)),
                size_t preflen,
                const char *name withtok(readable_span(namelen)),
                size_t namelen, int want_slash, size_t *outlen);
static int join(char *out withtok(writable_span(outcap)), size_t outcap,
                const char *prefix withtok(readable_span(preflen)),
                size_t preflen,
                const char *name withtok(readable_span(namelen)),
                size_t namelen, int want_slash, size_t *outlen)
{
	size_t need, remaining;

	/* Reserve the terminator first, then admit each component before
	 * forming the corresponding sum.  Besides ordinary overlong paths,
	 * this rejects wrapped attacker-sized lengths as the same no-match. */
	if (outcap == 0 || preflen >= outcap) return -1;
	remaining = outcap - preflen;
	if (namelen >= remaining) return -1;
	need = preflen + namelen;
	if (want_slash) {
		if (need >= outcap - 1) return -1;
		need++;
	}
	if (need > INT_MAX) return -1;
	if (snprintf(out, outcap, "%s%s%s", prefix, name,
	    want_slash ? "/" : "") != (int)need)
		return -1;
	*outlen = need;
	return 0;
}

/* Total do_glob() invocations (this call plus every recursive one)
 * that one top-level glob() call will perform before giving up as
 * though it had run out of memory. Recursion depth here is already
 * bounded by the pattern's own component count (the NOLINT below), but
 * depth is not the axis that matters: a pattern shaped like repeated
 * wildcard/../wildcard/../wildcard/../.. components (a wildcard
 * immediately undone by a literal "..", repeated) revisits the SAME
 * directory at the SAME depth every
 * time, and each visit re-multiplies by however many entries that
 * directory has, so the number of do_glob() CALLS is exponential in the
 * number of repeats even though the directory tree involved is tiny and
 * shallow -- two entries and one level was enough for
 * fuzz/fuzz_wordexp.c to find a wordexp() call that ran for 26 seconds
 * (test/posix-glob.c's test_wordexp_glob_alternation_bound reproduces
 * it directly against do_glob()). The literal ".." arm costs one stat()
 * and does not itself recurse into the meta branch's readdir loop, so
 * it is not what is exponential; the repeated wildcard re-matches are.
 *
 * glibc's own glob() carries an equivalent GLOB_LIMIT protection for
 * the identical reason -- a short, unremarkable-looking pattern must
 * not be able to cost unbounded wall time against a real filesystem --
 * and, like this one, reports it as GLOB_NOSPACE/ENOMEM rather than
 * inventing a new failure mode: "out of budget" and "out of memory" are
 * both just "this call cannot be completed with the resources this
 * implementation is willing to spend on it", and wordexp.h has no
 * WRDE_* code that means anything more specific than WRDE_NOSPACE
 * either (emit_field()'s own comment on its glob() call records that).
 *
 * The ceiling is generous by the standard of any pattern a real caller
 * writes by hand -- even a pattern that is nothing but wildcard
 * components, several deep, against a wide, multi-level real tree
 * stays several orders of magnitude below it -- while still keeping
 * the worst case a small fraction of a second rather than tens of
 * seconds. */
#define GLOB_STEP_LIMIT ((size_t)1 << 14)

/* Returns 0 (call handled, possibly zero matches added), 1 (GLOB_ABORTED
 * -- stop the whole scan), or -1 (GLOB_NOSPACE, also returned once
 * *steps exceeds GLOB_STEP_LIMIT -- see the constant's own comment).
 *
 * pat required: `*pat` is read unconditionally at entry (the leading-
 * slash skip loop). Every real call site agrees: glob()'s own initial
 * call passes pat, advanced from pattern (required there -- see glob()'s
 * own comment -- and never past its own NUL, so never NULL), and both
 * recursive calls pass rest, which is only ever reached from inside an
 * `if (rest)` guard, so rest is always a live pointer into pat's own
 * string, not the 0 find_slash()/the `rest = slash ? slash + 1 : 0;`
 * assignment can otherwise produce. pat is also withtok(null_terminated)
 * for the same reason: glob()'s own pattern parameter carries it (see
 * include/glob.h), rest is find_slash()'s own withtok(null_terminated)
 * return (or one past it, still inside the same terminated string), and
 * collapse_dotdot()'s replacement pattern is always a fresh xstrdup()
 * result of a real C string it built itself. prefix/out are not marked here: out
 * is already required by pv_push()/finish() at its own real dereference
 * sites, and prefix, though written through in several branches, is
 * only read back conditionally per-branch (never unconditionally at
 * entry the way pat is), so there is no single unconditional dereference
 * this attribute could describe for it. steps IS marked: `++*steps` at
 * the top of the function dereferences it unconditionally, on every
 * call, and both recursive call sites and glob()'s own initial call
 * (its own comment) agree in passing the address of a real counter,
 * never NULL. */
// NOLINTNEXTLINE(misc-no-recursion) -- component expansion mirrors the pathname hierarchy and is pattern/path-depth bounded; total call count is separately bounded by GLOB_STEP_LIMIT
static int do_glob(char *prefix withtok(readable_span(prefixcap)),
                    size_t prefixcap, size_t preflen,
                    const char *pat withtok(null_terminated), int flags,
                    int (*errfunc)(const char *, int), struct pv *out, size_t *steps)
    __attribute__((nonnull(4, 8)));
// NOLINTNEXTLINE(misc-no-recursion) -- component expansion mirrors the pathname hierarchy and is pattern/path-depth bounded; total call count is separately bounded by GLOB_STEP_LIMIT
static int do_glob(char *prefix withtok(readable_span(prefixcap)),
                    size_t prefixcap, size_t preflen,
                    const char *pat withtok(null_terminated), int flags,
                    int (*errfunc)(const char *, int), struct pv *out, size_t *steps)
{
	const char *slash, *rest;
	size_t seglen, newlen;
	int meta, want_slash;
	char newprefix[PATH_MAX];
	if (preflen > prefixcap) return -1;

	if (++*steps > GLOB_STEP_LIMIT) { errno = ENOMEM; return -1; }

	while (*pat == '/') pat++;
	if (!*pat) {
		/* Pattern exhausted mid-recursion only happens after a caller
		 * already confirmed prefix names a directory (the literal and
		 * wildcard branches below both stat() before descending), so
		 * this is always a real, existing path. */
		char *m;
		if (preflen == 1 && prefix[0] == '/') m = xstrdup("/");
		else if (preflen) {
			/* A pattern ending in a slash yields a pathname ending in
			 * a slash -- ALWAYS, not only under GLOB_MARK.
			 *
			 * This branch is where a trailing-slash pattern lands, and
			 * it used to strip the slash: glob("subdir/", ...) returned
			 * "subdir" whatever the flags.  The generated pathname is
			 * supposed to be the one that matched, and the pattern's
			 * own trailing slash is part of it; GLOB_MARK is then
			 * simply redundant for this shape rather than the thing
			 * that enables it.  Confirmed against glibc, which returns
			 * "subdir/" for both glob("subdir/", 0) and
			 * glob("subdir/", GLOB_MARK) -- and "subdir" for
			 * glob("subdir", 0), where there is no slash to keep.
			 *
			 * (An earlier version of this fix made keeping the slash
			 * conditional on GLOB_MARK, which the fence's wording
			 * suggested.  Mutation-testing said the unconditional form
			 * was indistinguishable, and measuring glibc showed why:
			 * the unconditional form is the correct one.)
			 *
			 * Nothing needs to be re-stat()ed to know this is a
			 * directory: reaching here means a caller matched a
			 * component with a trailing slash and confirmed it with
			 * stat() before descending (see the literal and wildcard
			 * branches), so prefix already ends in '/' and names a
			 * directory. */
			m = xstrdup(prefix);
		} else if (preflen == 0) m = xstrdup(".");
		else {
			char tmp[PATH_MAX];
			__ownership_writable_span(tmp, preflen - 1);
			__ownership_readable_span(prefix, preflen - 1);
			memcpy(tmp, prefix, preflen - 1);
			tmp[preflen - 1] = 0;
			m = xstrdup(tmp);
		}
		return pv_push(out, m) ? -1 : 0;
	}

	slash = find_slash(pat, flags);
	seglen = strlen(pat);
	if (slash) {
		size_t suffix_len = strlen(slash);
		if (suffix_len > seglen) {
			errno = EINVAL;
			return -1;
		}
		seglen -= suffix_len;
	}
	rest = slash ? slash + 1 : 0;
	meta = has_meta(pat, seglen, flags);
	want_slash = rest != 0;

	if (!meta) {
		size_t namelen;
		char *name = unescape(pat, seglen, flags);
		struct stat st;
		int isdir;

		if (!name) return -1;
		/* unescape()'s declared contract is writable_span(len) only, not
		 * null_terminated (see classify()'s own comment on why that is
		 * deliberate) -- but its body, read by hand, always leaves a real
		 * NUL at buf[j] for some j <= len before returning, which is
		 * exactly what strlen() below needs and a raw loop here cannot
		 * syntactically prove from the type alone. */
		__ownership_string_terminated(name);
		namelen = strlen(name);
		if (join(newprefix, sizeof newprefix, prefix, preflen, name, namelen, want_slash,
		         &newlen)) {
			__free(name);
			return 0; /* too long to ever exist; not a match, not an error */
		}
		__free(name);

		if (rest) {
			if (stat(newprefix, &st) != 0 || !S_ISDIR(st.st_mode)) return 0;
			return do_glob(newprefix, sizeof newprefix, newlen, rest, flags,
			               errfunc, out, steps);
		}
		if (stat(newprefix, &st) != 0) return 0;
		isdir = S_ISDIR(st.st_mode);
		if ((flags & GLOB_MARK) && isdir) {
			if (newlen + 1 < PATH_MAX) {
				newprefix[newlen++] = '/';
				newprefix[newlen] = 0;
			}
		}
		return pv_push(out, xstrdup(newprefix)) ? -1 : 0;
	} else {
		const char *dirpath = preflen ? prefix : ".";
		char *segbuf;
		int dot_ok;
		DIR *dp;
		struct dirent *d;
		int rc = 0;

		size_t segbytes;
		if (seglen > INT_MAX || !__size_add_checked(seglen, 1, &segbytes)) {
			errno = ENOMEM;
			return -1;
		}
		segbuf = __malloc(segbytes);
		if (!segbuf) return -1;
		if (snprintf(segbuf, segbytes, "%.*s", (int)seglen, pat) !=
		    (int)seglen) {
			__free(segbuf);
			errno = ENOMEM;
			return -1;
		}
		dot_ok = seglen > 0 && (pat[0] == '.' ||
			(!(flags & GLOB_NOESCAPE) && pat[0] == '\\' && seglen > 1 && pat[1] == '.'));

		dp = opendir(dirpath);
		if (!dp) {
			int e = errno;
			__free(segbuf);
			if ((errfunc && errfunc(dirpath, e)) || (flags & GLOB_ERR)) return 1;
			return 0;
		}

		errno = 0;
		while ((d = readdir(dp))) {
			size_t namelen;
			struct stat st;

			/* Validate the producer's fixed-size name member before any
			 * string traversal or copy can leave that live object. */
			namelen = strnlen(d->d_name, sizeof d->d_name);
			if (namelen == sizeof d->d_name) { errno = EIO; break; }
			if ((namelen == 1 && d->d_name[0] == '.') ||
			    (namelen == 2 && d->d_name[0] == '.' && d->d_name[1] == '.'))
				continue;
			if (d->d_name[0] == '.' && !dot_ok) continue;
			if (fnmatch(segbuf, d->d_name, (flags & GLOB_NOESCAPE) ? FNM_NOESCAPE : 0) != 0)
				continue;

			if (join(newprefix, sizeof newprefix, prefix, preflen, d->d_name, namelen,
			         want_slash, &newlen))
				continue;

			if (rest) {
				if (stat(newprefix, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
				rc = do_glob(newprefix, sizeof newprefix, newlen, rest, flags,
				             errfunc, out, steps);
				if (rc) break;
			} else {
				int isdir = 0;
				if ((flags & GLOB_MARK) && stat(newprefix, &st) == 0) isdir = S_ISDIR(st.st_mode);
				if (isdir) {
					if (newlen + 1 < PATH_MAX) {
						/* newprefix is a concrete PATH_MAX-sized local
						 * array, and the guard just proved newlen+1 is a
						 * valid index into it -- but this write is inside
						 * a readdir() loop, and ValidPointer still reports
						 * "dereference extent is not proven sufficient"
						 * here (the byte-for-byte identical guarded pair
						 * in this function's own literal branch above,
						 * reached only once per call, is never reported,
						 * so this looks like the analyzer's own loop
						 * widening forgetting the per-iteration bound
						 * across the back-edge). Tried restating it by
						 * hand with __ownership_writable_span(newprefix +
						 * newlen, 2), the same idiom the pattern-exhausted
						 * branch's own memcpy() above uses, and reverted:
						 * MemoryContractChecker's own manual-proof-axiom
						 * pass reports that call as "can be narrowed" (its
						 * span is already provable at that program point
						 * without it) while the ORIGINAL finding on the
						 * write itself is untouched either way -- a net
						 * increase in findings for no proof gained. Left
						 * as-is and the finding left open. */
						newprefix[newlen++] = '/';
						newprefix[newlen] = 0;
					}
				}
				if (pv_push(out, xstrdup(newprefix))) { rc = -1; break; }
			}
			errno = 0;
		}
		if (!rc && errno) {
			int e = errno;
			if ((errfunc && errfunc(dirpath, e)) || (flags & GLOB_ERR)) rc = 1;
		}
		__free(segbuf);
		(void)closedir(dp);
		return rc;
	}
}

/* out/pglob both required: out->n is read unconditionally in the loop
 * bound just below, and pglob->gl_pathv/gl_pathc are written
 * unconditionally further down (both the success path and the nospace:
 * label's own reset) -- no branch of this function leaves pglob
 * untouched. Every real call site (glob(), three of them) passes &out
 * and its own pglob parameter straight through, and glob()'s own pglob
 * is itself required (see glob()'s comment) -- never NULL either way. */
static int finish(struct pv *out, int flags, glob_t *pglob) __attribute__((nonnull(1, 3)));
static int finish(struct pv *out, int flags, glob_t *pglob)
{
	size_t offs = (flags & GLOB_DOOFFS) ? pglob->gl_offs : 0;
	size_t i, total;
	char **v;

	/* gl_offs is caller-controlled.  Check both the element count and
	 * its conversion to bytes before either can wrap into a small
	 * allocation followed by an out-of-bounds NULL-fill loop. */
	if (out->n == (size_t)-1 || offs > (size_t)-1 - out->n - 1) goto nospace;
	total = offs + out->n + 1;
	if (total > (size_t)-1 / sizeof *v) goto nospace;
	{
		size_t bytes = total * sizeof *v; /* proven <= SIZE_MAX just above */
		v = (char **)__malloc(bytes);
	}
	if (!v) goto nospace;
	for (i = 0; i < offs; i++) v[i] = 0;
	for (i = 0; i < out->n; i++) v[offs + i] = out->v[i];
	v[offs + out->n] = 0;
	__free((void *)out->v);

	/* Unlike src/wordexp/wordexp.c's pv_pack() -- which needs its own
	 * withtok(internal_heap_allocated) so its char** return survives the
	 * call into the separate function (expand_impl()) that performs the
	 * field write -- this function both allocates v AND stores it into
	 * gl_pathv in the same frame. v already carries a fresh
	 * internal_heap_allocated fact straight from __malloc()'s own
	 * withtok'd return (src/internal/libc.h), so
	 * AllocationLifetimeChecker's checkPostStmt recognizes this store into
	 * gl_pathv's own withtok(internal_heap_allocated) (include/glob.h)
	 * without any annotation on finish() itself -- and one would do
	 * nothing anyway, since finish() returns int, and checkPostCall/
	 * checkEndFunction only ever act on a pointer-typed return value.
	 * Confirmed against tools/lint.sh ownership: annotating the field
	 * alone made this line's previously-reported "dynamic allocation is
	 * not freed before function exit" finding disappear, with no change
	 * to this function. */
	pglob->gl_pathv = v;
	pglob->gl_pathc = out->n;
	if (!(flags & GLOB_DOOFFS) && !(flags & GLOB_APPEND)) pglob->gl_offs = offs;
	/* out->v was just freed above (its contents copied into v, now
	 * owned by pglob->gl_pathv instead); out itself is *out, the
	 * caller's own local struct pv, which every real call site abandons
	 * right after this call returns, but MemoryContractChecker's
	 * deferred paired-field proof still requires out->n/out->cap to stay
	 * within out->v's real extent at every one of those callers' own
	 * return points (see split_components()'s own comment on this exact
	 * mechanism). Zero all three fields together, the same shape
	 * pv_free_from() already uses. */
	out->v = 0; out->n = out->cap = 0;
	return 0;

nospace:
	pv_free_from(out, 0);
	/* GLOB_APPEND has already released the old wrapper, and every entry
	 * it owned is now freed above.  An empty result also gives ordinary
	 * callers a safe globfree()-able state after this failure. */
	pglob->gl_pathv = 0;
	pglob->gl_pathc = 0;
	errno = ENOMEM;
	return GLOB_NOSPACE;
}

/* --------------------------------------------------------------------
 * Pattern-level ".." collapsing -- see also GLOB_STEP_LIMIT above.
 *
 * GLOB_STEP_LIMIT is a defensive CAP: it stops a pathological pattern
 * from running forever, but it does so by giving up (GLOB_NOSPACE) on
 * exactly the patterns a real caller is most likely to write by hand --
 * repeated wildcard/../wildcard/../wildcard/../foo components is not
 * an exotic adversarial input, it looks
 * like the kind of thing a generated or templated path ends up as. The
 * cap alone still does all the wasted enumeration work up to the
 * ceiling before giving up.
 *
 * collapse_dotdot(), below, removes the waste at its source: BEFORE
 * do_glob() is ever called, it rewrites the PATTERN TEXT itself,
 * canceling "component/../" pairs the same way a shell's logical
 * ("cd -L" / $PWD-tracking) pathname handling does -- algebraically, by
 * inspecting the pattern's own component list, never by asking the
 * filesystem what "component" resolves to. But glob() is not a shell's
 * $PWD bookkeeping: it exists specifically to report which pathnames
 * are REAL, and XBD 4.13 "Pathname Resolution" is explicit that a real
 * ".." names the parent of its predecessor DIRECTORY and that
 * "[p]athname resolution shall fail" if a predecessor cannot itself be
 * located -- so a purely textual rewrite that never checked anything
 * would be able to turn glob("nonexistent/../foo", ...) into a match
 * for "foo" even though "nonexistent" does not exist, which is wrong.
 * This rewrite therefore treats two shapes of "component" differently:
 *
 * - A WILDCARD component (an unescaped '*', '?' or '[' in it) is
 *   collapsed against a following ".." UNCONDITIONALLY, with no
 *   filesystem check at all. This is what actually matters for
 *   GLOB_STEP_LIMIT's own reproducer: do_glob()'s wildcard branch only
 *   ever recurses past a matched entry after confirming, via readdir()
 *   + stat(), that the entry is a real, existing directory, so by the
 *   time do_glob() would reach the ".." that follows a wildcard match,
 *   the thing being canceled was ALREADY guaranteed to exist -- the
 *   existence check this rewrite skips was never in question. What IS
 *   given up is exact multiplicity: do_glob(), uncollapsed, produces
 *   one textually distinct result PER matching entry ("wxab-1/.." and
 *   "wxab-2/.." are two separate results for glob("wxab-?/.."), not
 *   one -- confirmed directly against bash's own glob()), and a pattern
 *   with N repeats of a wildcard matching K entries genuinely has K**N
 *   distinct such spellings, every one naming the exact same file.
 *   Enumerating that entire set is what was exponential, not any
 *   accidental inefficiency in how do_glob() walked it -- glibc's own
 *   GLOB_LIMIT exists for the identical reason. Collapsing intentionally
 *   reports each such family of same-target, differently-spelled matches
 *   ONCE rather than K**N times, which is what turns an inherently
 *   exponential expansion into O(pattern length) work.
 *
 * - A LITERAL (meta-free) component is collapsed against a following
 *   ".." only when this rewrite can ITSELF confirm, with one stat(),
 *   that the component names a real, accessible directory -- exactly
 *   the check do_glob()'s own literal branch would have performed
 *   anyway, just performed here, once, up front, instead of once per
 *   occurrence during the recursion. This is never the exponential
 *   shape (a literal component costs one stat() and never fans out --
 *   see GLOB_STEP_LIMIT's own comment above), so there is no
 *   performance reason to skip the check the way the wildcard case
 *   does, and skipping it would be a real correctness bug (the
 *   "nonexistent/../foo" case above). That verification is only
 *   possible while the accumulated path up to and including the
 *   candidate is itself made of nothing but literal/"."/survived-".."
 *   components with no unresolved wildcard anywhere in it (a
 *   wildcard's real location is not knowable without a filesystem walk,
 *   which is exactly the per-repeat cost this pass exists to avoid);
 *   once any wildcard appears, every literal component after it is left
 *   completely alone and falls through to do_glob()'s own unmodified,
 *   already-correct per-component handling.
 *
 * Either way, a leading ".." (nothing precedes it) and a "." component
 * are never cancelable AGAINST: ".." cannot cancel another ".."
 * ("../../" must stay exactly two levels), and "./.." is NOT the same
 * as "..", either -- entering "." changes nothing, so "./.." must still
 * walk up one real level, and collapsing "./../" straight to nothing
 * would be wrong (it would turn "./../x" into "x" instead of "../x").
 * Both are simply pushed onto the surviving component stack like any
 * other component that fails to cancel.
 *
 * The single left-to-right stack pass below reaches the same fixed
 * point a repeated linear-scan-until-no-change approach would ("a/b/
 * ../../c" needs two cancellations to reach "c", and the stack performs
 * both in the one pass: "b" cancels against the first "..", then "a" --
 * now the new top of stack -- cancels against the second).
 *
 * GLOB_STEP_LIMIT remains in place after this pass purely as
 * belt-and-suspenders: it is no longer the primary defense against the
 * "* /../" repeat shape (this rewrite removes that shape's fan-out
 * before do_glob() ever sees it), but it still protects every OTHER
 * pattern shape that is exponential in do_glob()'s recursion without
 * matching this pass's narrow "component immediately undone by '..'"
 * trigger -- e.g. plain nested wildcards several levels deep against a
 * wide tree, which cost real, unavoidable enumeration work this pass
 * has no opinion about.
 * -------------------------------------------------------------------- */

enum comp_kind { CK_LIT, CK_WILD, CK_DOT, CK_DOTDOT };

struct comp {
	const char *start withtok(readable_span(len));
	size_t len;
	enum comp_kind kind;
};

/* v carries internal_heap_allocated for the backing array itself
 * (comp_push()'s own __malloc(bytes), matching struct pv's identical
 * field above) -- but NOT elements_withtok: unlike struct pv's char*
 * elements (each a separate xstrdup()/unescape() heap allocation), a
 * struct comp's own `start` field is always a borrowed pointer INTO the
 * original pattern text (see struct comp's own comment below), never a
 * heap allocation in its own right, so there is no per-element ownership
 * fact to state here. */
struct comp_list {
	struct comp *v withtok(internal_heap_allocated)
		withtok(readable_elements(n)) withtok(writable_elements(cap));
	size_t n, cap;
	int trailing_slash;
};

static int comp_push(struct comp_list *cl, const char *start, size_t len,
                      enum comp_kind kind) __attribute__((nonnull(1)));
static int comp_push(struct comp_list *cl, const char *start, size_t len,
                      enum comp_kind kind)
{
	if (cl->n == cl->cap) {
		size_t nc, bytes, oldbytes;
		struct comp *nv;
		if (!__array_next_capacity(cl->cap, cl->n, 1, 16, sizeof *cl->v, &nc)) {
			errno = ENOMEM;
			return -1;
		}
		bytes = nc * sizeof *nv;
		oldbytes = cl->n * sizeof *nv;
		if (oldbytes > bytes) { errno = ENOMEM; return -1; }
		nv = (struct comp *)__malloc(bytes);
		if (!nv) return -1;
		if (cl->v) memcpy((void *)nv, (const void *)cl->v,
		    cl->n * sizeof *cl->v);
		__free((void *)cl->v);
		cl->v = nv;
		cl->cap = nc;
	}
	cl->v[cl->n].start = start;
	cl->v[cl->n].len = len;
	cl->v[cl->n].kind = kind;
	cl->n++;
	return 0;
}

/* Classifies one already-bounded component (start, len bytes, no '/' in
 * it -- the caller already split on find_slash()'s own escape-aware
 * boundaries). A component containing any unescaped wildcard
 * metacharacter is CK_WILD without needing to unescape it at all: it
 * can never BE "." or ".." textually once matched, since do_glob()'s
 * own dirent-skip check (its wildcard branch) refuses "." and ".." as
 * readdir() results before fnmatch() ever runs on them. Otherwise the
 * component is unescaped (GLOB_NOESCAPE-aware, the same as do_glob()'s
 * own literal branch) and compared against the real strings "." and
 * ".." -- so an ESCAPED dot (e.g. "\." under ordinary escaping rules)
 * is judged by what it actually names once unescaped, not by its raw
 * spelling, while GLOB_NOESCAPE correctly turns "\.\." into four
 * ordinary literal bytes that are neither. */
static int classify(const char *s, size_t len, int flags, enum comp_kind *kind)
    __attribute__((nonnull(1, 4)));
static int classify(const char *s, size_t len, int flags, enum comp_kind *kind)
{
	char *u;
	size_t ul;

	if (has_meta(s, len, flags)) {
		*kind = CK_WILD;
		return 0;
	}
	u = unescape(s, len, flags);
	if (!u) return -1;
	/* unescape()'s own declared span is `writable_span(len)` -- exactly
	 * len bytes -- even though its real allocation is len+1 and it
	 * always leaves a NUL at buf[j] for some j <= len (unescaping only
	 * ever removes bytes, never adds them). Indexing u[1]/u[2] looking
	 * for that NUL, the way this used to, reads u[len] whenever j == len
	 * (no backslash in this component at all -- an ordinary "." or ".."
	 * path segment), one byte past what the callee's own contract
	 * promises: the same shape of bug struct pline's `text` field had in
	 * src/util/patch.c before it was fixed to stop trusting an implicit
	 * terminator that isn't part of the type's contract. strnlen(u, len)
	 * gets the real content length without ever dereferencing u[len]. */
	ul = strnlen(u, len);
	if (ul == 1 && u[0] == '.') *kind = CK_DOT;
	else if (ul == 2 && u[0] == '.' && u[1] == '.') *kind = CK_DOTDOT;
	else *kind = CK_LIT;
	__free(u);
	return 0;
}

/* Splits pat into its '/'-delimited components, mirroring do_glob()'s
 * own "while (*pat == '/') pat++" run-of-slashes skip at the top of its
 * loop -- so, exactly as do_glob() already treats them, a run of two or
 * more '/' never produces an empty component here either. pat is
 * guaranteed not to start with '/' by glob()'s own leading-slash
 * handling before this is ever called, so there is no leading empty
 * component to represent either. pat is withtok(null_terminated): its one
 * real call site (collapse_dotdot()) passes its own pat parameter, itself
 * required there -- see collapse_dotdot()'s own comment -- unchanged. */
static int split_components(const char *pat withtok(null_terminated), int flags,
                             struct comp_list *cl)
    __attribute__((nonnull(1, 3)));
static int split_components(const char *pat withtok(null_terminated), int flags,
                             struct comp_list *cl)
{
	const char *p = pat;

	cl->v = 0;
	cl->n = cl->cap = 0;
	cl->trailing_slash = 0;

	for (;;) {
		const char *slash;
		size_t seglen;
		enum comp_kind kind;

		while (*p == '/') p++;
		if (!*p) break;

		slash = find_slash(p, flags);
		seglen = slash ? (size_t)(slash - p) : strlen(p);
		if (classify(p, seglen, flags, &kind) || comp_push(cl, p, seglen, kind)) {
			/* cl is discarded by every real caller on this path (the
			 * function returns -1 without leaving cl in play) -- but
			 * MemoryContractChecker's deferred paired-field proof
			 * (checkEndFunction, see MemoryContractChecker.cpp's own
			 * TouchedRecordSpan comment, which cites this exact
			 * function's caller chain) still requires cl->n/cl->cap to
			 * stay within cl->v's real extent at every path's end, and a
			 * freed cl->v has none. Zero the paired fields the same way
			 * pv_free_from() already does for struct pv, so a freed
			 * pointer is always paired with n == cap == 0 --
			 * zero_vacuous (include/memory_tokens.h) makes that
			 * combination valid with no storage proof at all. */
			__free((void *)cl->v);
			cl->v = 0;
			cl->n = cl->cap = 0;
			return -1;
		}
		if (!slash) break;
		p = slash + 1;
		if (!*p) { cl->trailing_slash = 1; break; }
	}
	return 0;
}

/* Confirms, with exactly one stat(), that the LITERAL path named by
 * joining base_prefix with every currently-kept component in stk (in
 * order, unescaped) is a real, existing, accessible directory -- i.e.
 * that canceling stk's own top entry against a following ".." is
 * something do_glob() itself would also have confirmed, had it walked
 * there the slow way. Returns 1 (confirmed, safe to cancel), 0 (not
 * confirmed -- either a CK_WILD entry anywhere in stk makes the real
 * location unknowable without a filesystem walk this pass is not
 * willing to perform, or the stat() itself failed), or -1 on allocation
 * failure. */
static int literal_prefix_exists(const struct comp_list *stk, int flags,
                                  const char *base_prefix
                                      withtok(readable_span(base_preflen)),
                                  size_t base_preflen)
    __attribute__((nonnull(1, 3)));
static int literal_prefix_exists(const struct comp_list *stk, int flags,
                                  const char *base_prefix
                                      withtok(readable_span(base_preflen)),
                                  size_t base_preflen)
{
	char path[PATH_MAX];
	size_t len, i;
	struct stat st;

	if (base_preflen >= sizeof path) return 0;
	if (base_preflen > INT_MAX ||
	    snprintf(path, sizeof path, "%.*s", (int)base_preflen,
	    base_prefix) != (int)base_preflen)
		return 0;
	len = base_preflen;

	for (i = 0; i < stk->n; i++) {
		const struct comp *c = &stk->v[i];
		char *name;
		size_t namelen;

		if (c->kind == CK_WILD) return 0;
		name = unescape(c->start, c->len, flags);
		if (!name) return -1;
		/* Same fact, same reason, as do_glob()'s own identical
		 * unescape()-then-strlen() pair in its literal branch: the
		 * writable_span(len) contract alone does not say so, but the
		 * body always leaves a real NUL within it. */
		__ownership_string_terminated(name);
		namelen = strlen(name);
		if (namelen >= sizeof path - len) { __free(name); return 0; }
		if (snprintf(path + len, sizeof path - len, "%s", name) !=
		    (int)namelen) { __free(name); return 0; }
		len += namelen;
		__free(name);
		if (len >= sizeof path - 1) return 0;
		path[len++] = '/';
	}
	path[len] = 0;

	return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* The rewrite pass itself -- see the banner comment above. pat is the
 * pattern with any leading '/' already stripped and stored in
 * base_prefix/base_preflen by glob() (see glob()'s own call site), and is
 * withtok(null_terminated) for the same reason: it is glob()'s own
 * withtok(null_terminated) pattern parameter (see include/glob.h),
 * advanced past a leading '/' by ordinary pointer arithmetic, which does
 * not change its terminator. Returns a newly heap-allocated replacement
 * for pat, or NULL on allocation failure. */
withtok(internal_heap_allocated)
static char *collapse_dotdot(const char *pat withtok(null_terminated), int flags,
                              const char *base_prefix, size_t base_preflen)
    __attribute__((nonnull(1, 3)));
withtok(internal_heap_allocated)
static char *collapse_dotdot(const char *pat withtok(null_terminated), int flags,
                              const char *base_prefix, size_t base_preflen)
{
	struct comp_list src, stk;
	size_t i, total, pos;
	char *out;
	int ok = 1;

	/* A fast, deliberately conservative pre-filter: if the byte pair
	 * ".." does not appear ANYWHERE in the raw pattern text, no
	 * component can unescape to the special ".." token either --
	 * unescaping only ever REMOVES backslash bytes, it never
	 * manufactures two adjacent literal dots out of bytes that were
	 * not already adjacent -- except for the one case where an escape
	 * backslash sits BETWEEN the two dots (e.g. ".\." unescaping to
	 * ".."), which this heuristic deliberately does not chase down.
	 * Skipping the pass there is always SAFE, never wrong: do_glob()'s
	 * own unmodified per-component recursion still produces the
	 * correct result either way, just without this pass's speedup, and
	 * GLOB_STEP_LIMIT remains the backstop against any pattern shaped
	 * to specifically dodge this prefilter. */
	if (!strstr(pat, "..")) return xstrdup(pat);

	if (split_components(pat, flags, &src)) return 0;

	stk.v = 0;
	stk.n = stk.cap = 0;
	stk.trailing_slash = src.trailing_slash;

	for (i = 0; i < src.n && ok; i++) {
		struct comp c = src.v[i];
		int canceled = 0;

		if (c.kind == CK_DOTDOT && stk.n > 0) {
			struct comp *top = &stk.v[stk.n - 1];
			if (top->kind == CK_WILD) {
				stk.n--;
				canceled = 1;
			} else if (top->kind == CK_LIT) {
				int r = literal_prefix_exists(&stk, flags, base_prefix, base_preflen);
				if (r < 0) { ok = 0; break; }
				if (r) { stk.n--; canceled = 1; }
			}
		}
		if (!canceled && comp_push(&stk, c.start, c.len, c.kind)) ok = 0;
	}
	/* src/stk are both about to go out of scope on every path below, so
	 * none of these resets change runtime behavior -- but
	 * MemoryContractChecker's deferred paired-field proof (see
	 * split_components()'s own comment on this same mechanism, and
	 * MemoryContractChecker.cpp's own TouchedRecordSpan comment, which
	 * names this file's glob() by example) still requires each struct's
	 * n/cap to stay within its v's real extent at every path's end, and a
	 * freed v has none. Zeroing all three fields together, the same way
	 * pv_free_from() already does for struct pv, keeps every freed
	 * pointer paired with n == cap == 0, which zero_vacuous
	 * (include/memory_tokens.h) makes valid with no storage proof at
	 * all. */
	__free((void *)src.v);
	src.v = 0; src.n = src.cap = 0;
	if (!ok) { __free((void *)stk.v); stk.v = 0; stk.n = stk.cap = 0; return 0; }

	if (stk.n == 0) {
		/* Every real component canceled away: what remains names
		 * exactly base_prefix itself (e.g. "a/.." with "a" confirmed
		 * a real directory collapses to "", which do_glob()'s own
		 * pattern-exhausted branch already turns into the correct
		 * pathname for an empty remaining pattern -- see its own
		 * comment on that branch). */
		__free((void *)stk.v);
		stk.v = 0; stk.cap = 0;
		return xstrdup("");
	}

	for (i = 0, total = 1; i < stk.n; i++) total += stk.v[i].len + 1;
	out = __malloc(total);
	if (!out) { __free((void *)stk.v); stk.v = 0; stk.n = stk.cap = 0; return 0; }
	for (i = 0, pos = 0; i < stk.n; i++) {
		if (stk.v[i].len > INT_MAX ||
		    snprintf(out + pos, total - pos, "%.*s", (int)stk.v[i].len,
		    stk.v[i].start) != (int)stk.v[i].len) {
			__free(out);
			__free((void *)stk.v);
			stk.v = 0; stk.n = stk.cap = 0;
			return 0;
		}
		pos += stk.v[i].len;
		if (i + 1 < stk.n) out[pos++] = '/';
	}
	if (stk.trailing_slash) out[pos++] = '/';
	out[pos] = 0;
	__free((void *)stk.v);
	stk.v = 0; stk.n = stk.cap = 0;
	return out;
}

int glob(const char *pattern withtok(null_terminated), int flags,
         int (*errfunc)(const char *, int), glob_t *pglob)
{
	struct pv out;
	char prefix[PATH_MAX];
	size_t preflen = 0, base, steps = 0;
	const char *pat = pattern;
	int rc;

	out.v = 0;
	out.n = out.cap = 0;

	if (flags & GLOB_APPEND) {
		out.n = out.cap = pglob->gl_pathc;
		if (out.n) {
			char *const *old = pglob->gl_pathv + pglob->gl_offs;
			size_t bytes;
			/* out.n/out.cap were just set from pglob->gl_pathc above,
			 * ahead of out.v itself (the opposite order from pv_push()'s
			 * own careful v-then-cap sequencing, and unavoidable here:
			 * bytes, needed to allocate out.v, is derived from out.n).
			 * Both early returns below leave that window open --
			 * out.n/out.cap nonzero, out.v still its initial 0 -- which
			 * MemoryContractChecker.cpp's own TouchedRecordSpan comment
			 * names this exact statement as the motivating case for
			 * deferring its paired-field proof to checkEndFunction rather
			 * than checking eagerly at every store. Reset out.n/out.cap
			 * back to 0 on both paths, the same zero_vacuous-valid state
			 * pv_free_from() leaves behind, so the pair stays consistent
			 * at this function's own return. */
			if (!__size_mul_checked(out.n, sizeof *out.v, &bytes)) {
				out.n = out.cap = 0;
				errno = ENOMEM;
				return GLOB_NOSPACE;
			}
			out.v = (char **)__malloc(bytes);
			if (!out.v) { out.n = out.cap = 0; errno = ENOMEM; return GLOB_NOSPACE; }
			__ownership_readable_span(old, bytes);
			memcpy((void *)out.v, (const void *)old, bytes);
		}
		__free((void *)pglob->gl_pathv);
	}
	base = out.n;

	if (*pat == '/') {
		prefix[0] = '/';
		preflen = 1;
		pat++;
		while (*pat == '/') pat++;
	}
	prefix[preflen] = 0;

	/* An EMPTY pattern names no pathname, so it matches nothing --
	 * glob.html RETURN VALUE, "[GLOB_NOMATCH] The pattern does not match
	 * any existing pathname, and GLOB_NOCHECK was not set".
	 *
	 * do_glob() cannot be asked this question.  Its pattern-exhausted
	 * branch assumes it was reached part-way through a recursion, after
	 * a caller had already confirmed the prefix names a directory (its
	 * own comment says so), and synthesises "." when the prefix is
	 * empty.  Reached with an empty pattern from HERE that assumption is
	 * false, and glob("", 0, ...) returned 0 with gl_pathv[0] == "." --
	 * a pathname the caller never asked about, handed back as a
	 * successful match.
	 *
	 * Guarded at the call rather than inside do_glob() because the
	 * assumption the branch makes is correct for every recursive entry;
	 * only the initial one can violate it.  Note "/" is NOT empty and
	 * must still work: pat has already advanced past the leading slash
	 * by this point, leaving preflen == 1 and an empty pat, which is the
	 * legitimate exhausted case naming the root.  So the test is on the
	 * caller's original pattern, not on pat. */
	if (*pattern) {
		/* collapse_dotdot() rewrites pat into an equivalent, shorter
		 * pattern with "component/../" pairs already canceled -- see
		 * its own banner comment above -- BEFORE do_glob() ever
		 * starts recursing, so the recursion below never has to
		 * redo the same directory listing once per repeat of a
		 * "wildcard undone by '..'" pattern. A NULL result here is
		 * an allocation failure, handled by falling into the exact
		 * same GLOB_NOSPACE path an out-of-memory do_glob() return
		 * already takes below, rather than duplicating that cleanup. */
		char *collapsed = collapse_dotdot(pat, flags, prefix, preflen);
		rc = collapsed ? do_glob(prefix, sizeof prefix, preflen, collapsed, flags,
		                         errfunc, &out, &steps) : -1;
		__free(collapsed);
	} else {
		rc = 0;
	}

	if (rc == -1) {
		/* Frees everything in out, including any entries kept alive
		 * from a previous GLOB_APPEND call: those pointers were moved
		 * out of pglob->gl_pathv (already freed above) into out.v, so
		 * this is the only remaining owner of them. */
		pv_free_from(&out, 0);
		/* A GLOB_APPEND call already freed pglob's old gl_pathv above;
		 * leaving gl_pathc/gl_pathv pointing at that freed block would
		 * be a dangling pointer, so put pglob back in a safe, empty,
		 * globfree()-is-a-no-op state. A non-APPEND call never touched
		 * pglob at all, so it is left as the caller had it. */
		if (flags & GLOB_APPEND) { pglob->gl_pathc = 0; pglob->gl_pathv = 0; }
		errno = ENOMEM;
		return GLOB_NOSPACE;
	}
	if (rc == 1) {
		int frc = finish(&out, flags, pglob);
		return frc ? frc : GLOB_ABORTED;
	}

	if (out.n == base) {
		if (flags & GLOB_NOCHECK) {
			if (pv_push(&out, xstrdup(pattern))) {
				pv_free_from(&out, 0);
				if (flags & GLOB_APPEND) { pglob->gl_pathc = 0; pglob->gl_pathv = 0; }
				errno = ENOMEM;
				return GLOB_NOSPACE;
			}
		}
	} else if (!(flags & GLOB_NOSORT)) {
		/* Sort only what THIS call added -- from `base`, the count
		 * carried over from a previous GLOB_APPEND, onwards.
		 *
		 * glob.html APPLICATION USAGE: "The new pathnames generated by
		 * a subsequent call with GLOB_APPEND are not sorted together
		 * with the previous pathnames."  Sorting the whole vector
		 * re-sorted the predecessor's results into this call's, so
		 * glob("*.log", 0) followed by glob("*.txt", GLOB_APPEND) gave
		 * "a.txt b.txt d.log" where POSIX requires "d.log a.txt
		 * b.txt".  Each call's results stay in their own sorted run.
		 *
		 * base is 0 for a non-GLOB_APPEND call, so this is the same
		 * whole-vector sort as before in the ordinary case. */
		qsort((void *)(out.v + base), out.n - base, sizeof *out.v, cmpstrp);
	}

	if (out.n == base && !(flags & GLOB_NOCHECK)) {
		/* GLOB_NOMATCH: nothing matched, and there is nothing else to
		 * allocate for it -- except under GLOB_APPEND, where the old
		 * pglob->gl_pathv was already freed above and must be replaced
		 * with *something* freeable, even if empty, so a subsequent
		 * globfree() stays well-defined. A plain (non-APPEND) call
		 * just leaves pglob's pathv/pathc at a safe, already-empty
		 * state: nothing was ever allocated for this call, so nothing
		 * needs freeing, and globfree() on a NULL gl_pathv is already
		 * a no-op (see below). */
		if (flags & GLOB_APPEND) {
			int frc = finish(&out, flags, pglob);
			if (frc) return frc;
		}
		else { pv_free_from(&out, 0); pglob->gl_pathc = 0; pglob->gl_pathv = 0; }
		return GLOB_NOMATCH;
	}
	return finish(&out, flags, pglob);
}

void globfree(glob_t *pglob)
{
	size_t i, offs;

	if (!pglob || !pglob->gl_pathv) return;
	offs = pglob->gl_offs;
	for (i = 0; i < pglob->gl_pathc; i++) __free(pglob->gl_pathv[offs + i]);
	__free((void *)pglob->gl_pathv);
	pglob->gl_pathv = 0;
	pglob->gl_pathc = 0;
}
