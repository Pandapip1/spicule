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

/* v's elements are each a separate heap allocation (xstrdup()/unescape()
 * results), never string literals or borrowed pointers -- same shape as
 * src/wordexp/wordexp.c's own struct pv, not shared between the two. */
struct pv {
	char **v withtok(internal_heap_allocated)
		elements_withtok(internal_heap_allocated, n)
		withtok(readable_elements(n)) withtok(writable_elements(cap));
	size_t n, cap;
};

/* s is null-terminated at every real call site, but marking it
 * withtok(null_terminated) just relocates the lint finding to callers
 * that have no comparable fact to offer (measured) -- left unannotated. */
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

/* -1 on allocation failure (frees s either way it owns it). s may be
 * NULL (OOM in the caller's xstrdup()/unescape()); that's how OOM
 * propagates here as GLOB_NOSPACE instead of a crash. */
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
	p->v[p->n++] = s;
	return 0;
}

static void pv_free_from(struct pv *p, size_t from) __attribute__((nonnull(1)));
static void pv_free_from(struct pv *p, size_t from)
{
	size_t i;
	for (i = from; i < p->n; i++) __free(p->v[i]);
	__free((void *)p->v);
	p->v = 0;
	p->n = p->cap = 0;
}

/* p is null-terminated at every call site, but marking it
 * withtok(null_terminated) doesn't survive the `p += 2` reassignment
 * below and produces more findings than it resolves (measured) -- left
 * unannotated. */
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

/* Total do_glob() invocations one top-level glob() call will perform
 * before giving up with GLOB_NOSPACE. A pattern like repeated
 * "wildcard/../wildcard/../..." revisits the same directory at the
 * same depth on every repeat, so the call count is exponential in the
 * number of repeats even though the tree involved is tiny (two entries,
 * one level, was enough for a 26-second wordexp() call -- see
 * test/posix-glob.c's test_wordexp_glob_alternation_bound). glibc's own
 * glob() carries an equivalent GLOB_LIMIT for the same reason. The
 * ceiling is generous for any hand-written pattern. */
#define GLOB_STEP_LIMIT ((size_t)1 << 14)

/* Returns 0 (call handled, possibly zero matches added), 1 (GLOB_ABORTED
 * -- stop the whole scan), or -1 (GLOB_NOSPACE, also returned once
 * *steps exceeds GLOB_STEP_LIMIT -- see the constant's own comment). */
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
		 * already confirmed prefix names a directory, so this is
		 * always a real, existing path. */
		char *m;
		if (preflen == 1 && prefix[0] == '/') m = xstrdup("/");
		else if (preflen) {
			/* A pattern ending in a slash yields a pathname ending in
			 * a slash ALWAYS, not only under GLOB_MARK: the trailing
			 * slash is part of what matched. Confirmed against glibc,
			 * which returns "subdir/" for glob("subdir/", 0) too. */
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
		/* unescape()'s contract is writable_span(len), not
		 * null_terminated, but its body always leaves a real NUL. */
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
						/* The guard proves newlen+1 is valid here, but
						 * inside this readdir() loop the checker's loop
						 * widening forgets the per-iteration bound across
						 * the back-edge; a manual span axiom doesn't help
						 * (measured). Left open. */
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
	pglob->gl_pathv = v;
	pglob->gl_pathc = out->n;
	if (!(flags & GLOB_DOOFFS) && !(flags & GLOB_APPEND)) pglob->gl_offs = offs;
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
 * collapse_dotdot(), below, rewrites the pattern text before do_glob()
 * ever runs, canceling "component/../" pairs algebraically instead of
 * enumerating them. Two component shapes are treated differently:
 *
 * - A WILDCARD component collapses against a following ".."
 *   unconditionally, no filesystem check needed: do_glob() only
 *   recurses past a wildcard match after confirming via readdir()+stat()
 *   that the entry is a real directory, so the thing being canceled was
 *   already guaranteed to exist. This is what defeats GLOB_STEP_LIMIT's
 *   exponential case: uncollapsed, a wildcard matching K entries repeated
 *   N times produces K**N distinct (but same-target) result spellings;
 *   collapsing reports the family once instead of K**N times.
 *
 * - A LITERAL component collapses against a following ".." only when
 *   this pass can itself confirm with one stat() that it names a real
 *   directory (the same check do_glob()'s literal branch would have
 *   made anyway, just hoisted up front). Skipping that check would be a
 *   correctness bug: glob("nonexistent/../foo", ...) must not match
 *   "foo" (XBD 4.13). Once any wildcard appears in the accumulated
 *   prefix, its real location is unknowable without a filesystem walk,
 *   so every literal component after it is left alone.
 *
 * A leading ".." and a "." component are never cancelable against:
 * "../../" must stay two levels, and "./.." must still walk up one real
 * level ("./../x" is not "x"). Both are just pushed onto the stack.
 *
 * The single left-to-right stack pass reaches the same fixed point a
 * repeated rescan would ("a/b/../../c" cancels "b" against the first
 * "..", then "a" against the second, in one pass).
 *
 * GLOB_STEP_LIMIT stays in place as belt-and-suspenders for exponential
 * shapes this pass doesn't target, e.g. plain nested wildcards several
 * levels deep against a wide tree.
 * -------------------------------------------------------------------- */

enum comp_kind { CK_LIT, CK_WILD, CK_DOT, CK_DOTDOT };

struct comp {
	const char *start withtok(readable_span(len));
	size_t len;
	enum comp_kind kind;
};

/* Unlike struct pv, v's elements carry no elements_withtok: a struct
 * comp's `start` is a borrowed pointer into the original pattern text,
 * never its own heap allocation. */
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

/* Classifies one already-bounded component (start, len bytes, no '/').
 * A wildcard component is CK_WILD without unescaping: do_glob()'s own
 * dirent-skip already refuses "." and ".." as readdir() results before
 * fnmatch() runs, so a wildcard can never textually BE one. Otherwise
 * the component is unescaped and compared against "." and ".." -- an
 * escaped dot is judged by what it names once unescaped, not its raw
 * spelling. */
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
	/* unescape()'s declared span is writable_span(len), not len+1;
	 * indexing for a NUL past that would be the same out-of-bounds bug
	 * struct pline's `text` field had in src/util/patch.c. strnlen(u, len)
	 * gets the content length without reading u[len]. */
	ul = strnlen(u, len);
	if (ul == 1 && u[0] == '.') *kind = CK_DOT;
	else if (ul == 2 && u[0] == '.' && u[1] == '.') *kind = CK_DOTDOT;
	else *kind = CK_LIT;
	__free(u);
	return 0;
}

/* Splits pat into its '/'-delimited components, mirroring do_glob()'s
 * own run-of-slashes skip, so a run of two or more '/' never produces
 * an empty component here either. */
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
			/* Zero n/cap along with v (zero_vacuous, include/memory_tokens.h)
			 * so a freed pointer never has a stale nonzero paired count. */
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

/* Confirms, with one stat(), that the literal path named by joining
 * base_prefix with every currently-kept component in stk is a real,
 * existing directory -- i.e. that canceling stk's top entry against a
 * following ".." is safe. Returns 1 (safe to cancel), 0 (a CK_WILD entry
 * makes the location unknowable, or the stat() failed), or -1 on OOM. */
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

/* The rewrite pass itself -- see the banner comment above. pat has any
 * leading '/' already stripped and stored in base_prefix/base_preflen by
 * glob(). Returns a newly heap-allocated replacement for pat, or NULL on
 * allocation failure. */
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

	/* Conservative pre-filter: unescaping only removes bytes, so if ".."
	 * doesn't appear in the raw text, no component can unescape to it
	 * either (the ".\." edge case is deliberately not chased down --
	 * skipping the pass is always safe, just slower, and GLOB_STEP_LIMIT
	 * backstops it). */
	if (!strstr(pat, "..")) return xstrdup(pat);

	if (split_components(pat, flags, &src)) return 0;

	stk.v = 0;
	stk.n = stk.cap = 0;
	stk.trailing_slash = src.trailing_slash;

	for (i = 0; i < src.n; i++) {
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
		if (!canceled && comp_push(&stk, c.start, c.len, c.kind)) { ok = 0; break; }
	}
	/* Zero n/cap along with v (zero_vacuous) so a freed pointer never
	 * has a stale nonzero paired count. */
	__free((void *)src.v);
	src.v = 0; src.n = src.cap = 0;
	if (!ok) { __free((void *)stk.v); stk.v = 0; stk.n = stk.cap = 0; return 0; }

	if (stk.n == 0) {
		/* Every component canceled away: what remains names exactly
		 * base_prefix itself (e.g. "a/.." collapses to ""). */
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
			/* out.n/out.cap are set from gl_pathc before out.v exists
			 * (bytes, needed to allocate it, is derived from out.n);
			 * reset them to 0 on the early-return paths so a still-NULL
			 * out.v is never paired with a nonzero count. */
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

	/* An empty pattern matches nothing (glob.html RETURN VALUE). do_glob()
	 * can't be asked this: its pattern-exhausted branch assumes it was
	 * reached mid-recursion with the prefix already confirmed a directory,
	 * and would synthesize "." for an empty prefix -- wrong for a
	 * top-level empty pattern. Guarded here instead of in do_glob() since
	 * only the initial call can violate that assumption. Note "/" is not
	 * empty: pat has already advanced past the leading slash, so the test
	 * is on the caller's original pattern, not pat. */
	if (*pattern) {
		/* NULL here is an allocation failure, falling into the same
		 * GLOB_NOSPACE path an out-of-memory do_glob() return takes below. */
		char *collapsed = collapse_dotdot(pat, flags, prefix, preflen);
		rc = collapsed ? do_glob(prefix, sizeof prefix, preflen, collapsed, flags,
		                         errfunc, &out, &steps) : -1;
		__free(collapsed);
	} else {
		rc = 0;
	}

	if (rc == -1) {
		/* out.v owns any entries carried over from a previous
		 * GLOB_APPEND too, since gl_pathv was already freed above. */
		pv_free_from(&out, 0);
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
		/* Sort only what this call added (from `base` onwards): per
		 * glob.html APPLICATION USAGE, a GLOB_APPEND call's new pathnames
		 * are not sorted together with the previous ones. base is 0 for
		 * a non-APPEND call, so this is an ordinary whole-vector sort
		 * there. */
		qsort((void *)(out.v + base), out.n - base, sizeof *out.v, cmpstrp);
	}

	if (out.n == base && !(flags & GLOB_NOCHECK)) {
		/* GLOB_NOMATCH. Under GLOB_APPEND the old gl_pathv was already
		 * freed above and must be replaced with something freeable. */
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
