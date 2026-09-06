/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * wordexp(): XCU Word Expansions -- see include/wordexp.h's header
 * comment for which pieces are implemented and which are not.
 * Arithmetic expansion ($((expr))) is implemented for real
 * (src/wordexp/arith.c, called from expand_arith() below); see that
 * file's header for the evaluator itself.
 *
 * Command substitution used to be the one construct refused outright,
 * for want of a POSIX shell on this platform. There is one now
 * (src/sh/, see test/sh-design.md), linked into the same libc.a rather
 * than spawned as a separate interpreter image, so "$(...)" and
 * "`...`" are performed for real via the __sh_cmdsub() call-out
 * declared in src/internal/libc.h -- see run_cmdsub() below and its
 * neighbours for the extent-finding and quoting rules, which stay
 * here because they are part of this file's own left-to-right scan.
 * WRDE_NOCMD, which previously had no observable effect, is now what
 * makes wordexp() refuse one with WRDE_CMDSUB.
 *
 * One left-to-right scan of `words` does almost everything at once,
 * because the pieces are not actually separable: whether a character
 * is "quoted" has to be known before deciding whether it can start a
 * parameter expansion, end a field, or become a live glob
 * metacharacter, and that quote state can only be tracked by walking
 * the string in order. Per *raw* field (split on unquoted IFS
 * whitespace -- see include/wordexp.h on why that part of field
 * splitting is in scope), the scan builds two parallel arrays of the
 * same length: the literal bytes the field expands to, and a same-
 * length "was this byte quoted/escaped" flag.  A byte with that flag
 * clear is live: it came from outside any quotes, unescaped, so if it
 * is '*', '?' or '[' it is a real glob metacharacter, and if the
 * field contains any such byte at all, the field is handed to glob()
 * for pathname expansion; a field with none is used exactly as
 * scanned (that is quote removal). Parameter expansion ($VAR/${VAR})
 * substitutes environ text as *live* bytes (matching real shells: an
 * unquoted $VAR's value is itself eligible for pathname expansion);
 * tilde expansion substitutes the home directory as *quoted* bytes
 * (matching real shells: the result of ~ expansion is never re-glob-
 * scanned).
 */
#include <wordexp.h>
#include <fnmatch.h>
#include <glob.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include "internal.h"
#include "libc.h"
#include "ownership_stubs.h"

/* ---- growable byte buffer: the field being built, plus a parallel
 * "quoted/escaped" flag per byte --------------------------------------- */
struct fbuf {
	char *data withtok(internal_heap_allocated)
		withtok(readable_span(n)) withtok(writable_span(cap));
	unsigned char *lit withtok(internal_heap_allocated)
		withtok(readable_span(n)) withtok(writable_span(cap));
	size_t n, cap;
};

/* b->data[b->n]/b->lit[b->n] below still report "pointer dereference
 * is not proven nonnull": nothing in this file's annotation vocabulary
 * ties cap > 0 to data/lit being non-null for a per-call analysis
 * (src/glob/glob.c's struct pv has the same open finding). */
static int fbuf_push(struct fbuf *b, char c, int literal)
    __attribute__((nonnull(1)));
static int fbuf_push(struct fbuf *b, char c, int literal) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	if (b->n == b->cap) {
		size_t nc;
		if (!__array_next_capacity(b->cap, b->n, 1, 64, 1, &nc)) return -1;
		if (b->n > nc) return -1;
		char *nd = __malloc(nc);
		unsigned char *nl = __malloc(nc);
		if (!nd || !nl) { __free(nd); __free(nl); return -1; }
		if (b->data) {
			memcpy(nd, b->data, b->n);
			memcpy(nl, b->lit, b->n);
		}
		__free(b->data);
		__free(b->lit);
		b->data = nd;
		b->lit = nl;
		b->cap = nc;
	}
	b->data[b->n] = c;
	b->lit[b->n] = (unsigned char)literal;
	b->n++;
	return 0;
}

static void fbuf_free(struct fbuf *b) __attribute__((nonnull(1)));
static void fbuf_free(struct fbuf *b)
{
	__free(b->data);
	__free(b->lit);
	b->data = 0;
	b->lit = 0;
	b->n = b->cap = 0;
}

static int fbuf_push_str(struct fbuf *b, const char *s, int literal)
    __attribute__((nonnull(2)));
static int fbuf_push_str(struct fbuf *b, const char *s, int literal)
{
	for (; *s; s++)
		if (fbuf_push(b, *s, literal)) return -1;
	return 0;
}

/* ---- growable word-pointer vector, same shape as src/glob/glob.c's
 * private one (not shared: neither module is meant to depend on the
 * other's internals) ----------------------------------------------------- */
struct pv {
	char **v withtok(internal_heap_allocated)
		elements_withtok(internal_heap_allocated, n)
		withtok(readable_elements(n)) withtok(writable_elements(cap));
	size_t n, cap;
};

/* s can legitimately be NULL here (an OOM result from a caller's
 * xstrdup()/malloc()); the check below is real, not decoration. */
static int pv_push(struct pv *p, char *s) __attribute__((nonnull(1)));
static int pv_push(struct pv *p, char *s)
{
	if (!s) return -1;
	if (p->n == p->cap) {
		char **old = p->v;
		size_t nc, bytes, oldbytes;
		if (!__array_next_capacity(p->cap, p->n, 1, 16,
		    sizeof *p->v, &nc)) { __free(s); return -1; }
		bytes = nc * sizeof *p->v;
		oldbytes = p->n * sizeof *p->v;
		if (oldbytes > bytes) { __free(s); return -1; }
		char **nv = (char **)__malloc(bytes);
		if (!nv) { __free(s); return -1; }
		if (old) {
			memcpy((void *)nv, (const void *)p->v,
			    p->n * sizeof *p->v);
		}
		__free((void *)old);
		p->v = nv;
		p->cap = nc;
	}
	p->v[p->n++] = s;
	return 0;
}

/* No real call site in this tree -- every cleanup path uses
 * pv_free_from() instead -- so this is dead code, kept annotated
 * since the fact costs nothing to state. */
static void pv_free_all(struct pv *p) __attribute__((nonnull(1)));
static void pv_free_all(struct pv *p)
{
	size_t i;
	for (i = 0; i < p->n; i++) __free(p->v[i]);
	__free((void *)p->v);
	p->v = 0;
	p->n = p->cap = 0;
}

/* Frees only the entries [from, n) (words *this* call itself added --
 * used when [0, from) still belongs to a WRDE_APPEND caller's
 * untouched pwordexp), plus the array wrapper itself, which is always
 * this call's own allocation regardless of from. */
static void pv_free_from(struct pv *p, size_t from) __attribute__((nonnull(1)));
static void pv_free_from(struct pv *p, size_t from)
{
	size_t i;
	for (i = from; i < p->n; i++) __free(p->v[i]);
	__free((void *)p->v);
	p->v = 0;
	p->n = p->cap = 0;
}

/* Allocate the caller-visible pointer vector and transfer the pointer
 * entries into it.  offs is caller-controlled under WRDE_DOOFFS, so
 * validate both additions and the final conversion to bytes before
 * allocating or filling the reserved slots. */
withtok(internal_heap_allocated)
static char **pv_pack(struct pv *p, size_t offs) __attribute__((nonnull(1)));
withtok(internal_heap_allocated)
static char **pv_pack(struct pv *p, size_t offs)
{
	size_t i, total;
	char **v;

	if (p->n == (size_t)-1 || offs > (size_t)-1 - p->n - 1) return 0;
	total = offs + p->n + 1;
	if (total > (size_t)-1 / sizeof *v) return 0;
	{
		size_t bytes = total * sizeof *v; /* proven <= SIZE_MAX just above */
		v = (char **)__malloc(bytes);
	}
	if (!v) return 0;
	for (i = 0; i < offs; i++) v[i] = 0;
	for (i = 0; i < p->n; i++) v[offs + i] = p->v[i];
	v[offs + p->n] = 0;
	__free((void *)p->v);
	p->v = 0;
	return v;
}

withtok(internal_heap_allocated)
withtok(null_terminated)
static char *xstrdup(const char *s withtok(null_terminated)) __attribute__((nonnull(1)));
withtok(internal_heap_allocated)
withtok(null_terminated)
static char *xstrdup(const char *s withtok(null_terminated))
{
	size_t n = strlen(s) + 1;
	char *p = __malloc(n);
	if (!p) return 0;
	memcpy(p, s, n);
	__ownership_string_terminated(p);
	return p;
}

static int is_ifs(char c) { return c == ' ' || c == '\t' || c == '\n'; }
static int is_split_char(char c)
{
	const char *ifs = getenv("IFS");
	if (!ifs) ifs = " \t\n";
	/* Both branches are real C strings, but the checker's string-literal
	 * recognition only fires on a literal initializer at declaration,
	 * not a later reassignment. */
	__ownership_string_terminated(ifs);
	return strchr(ifs, c) != 0;
}
static int is_namestart(char c) { return isalpha((unsigned char)c) || c == '_'; }
static int is_namechar(char c) __attribute__((pure));
static int is_namechar(char c) { return isalnum((unsigned char)c) || c == '_'; }

static int fbuf_push_long(struct fbuf *b, long v);

struct assignment {
	char *name withtok(internal_heap_allocated) withtok(null_terminated);
	char *old withtok(internal_heap_allocated);
	int had_old;
	struct assignment *next;
};

struct assign_ctx { struct assignment *head withtok(internal_heap_allocated); };

static int expand_impl(const char *, wordexp_t *, int, int, struct assign_ctx *)
    __attribute__((nonnull(1, 2)));
static int expand_trim_pattern(const char *, size_t, int, int,
                               struct assign_ctx *, char **)
    __attribute__((nonnull(1, 6)));

static int assign_param(struct assign_ctx *ctx, const char *name withtok(null_terminated), const char *value)
    __attribute__((nonnull(1, 2)));
static int assign_param(struct assign_ctx *ctx, const char *name withtok(null_terminated), const char *value)
{
	struct assignment *a;
	const char *old;

	for (a = ctx->head; a; a = a->next) {
		/* a->name is xstrdup()'d below on an earlier call; not
		 * visible to a per-call analysis. */
		__ownership_string_terminated(a->name);
		if (!strcmp(a->name, name)) return setenv(name, value, 1) < 0 ? WRDE_NOSPACE : 0;
	}
	a = __malloc(sizeof *a);
	if (!a) return WRDE_NOSPACE;
	/* a->name's null_terminated fact doesn't propagate through this
	 * manual grant for a per-call proof; left open. xstrdup() still
	 * makes it a real C string. */
	a->name = xstrdup(name);
	old = getenv(name);
	if (old) __ownership_string_terminated(old);
	a->had_old = old != 0;
	a->old = old ? xstrdup(old) : 0;
	if (!a->name || (old && !a->old)) {
		__free(a->name); __free(a->old); __free(a);
		return WRDE_NOSPACE;
	}
	a->next = ctx->head;
	ctx->head = a;
	return setenv(name, value, 1) < 0 ? WRDE_NOSPACE : 0;
}

static void finish_assignments(struct assign_ctx *ctx, int restore)
{
	struct assignment *a, *next;

	for (a = ctx->head; a; a = next) {
		next = a->next;
		if (restore) {
			if (a->had_old) setenv(a->name, a->old, 1);
			else unsetenv(a->name);
		}
		__free(a->name);
		__free(a->old);
		__free(a);
	}
}

/* Find the closing brace of a ${parameter-word} expansion.  Nested
 * parameter expansions belong to word and therefore do not close the
 * outer expansion.  Escaped braces and braces in quotes are data. */
static const char *param_word_end(const char *p) __attribute__((nonnull(1)));
static const char *param_word_end(const char *p)
{
	int depth = 0;

	for (; *p; p++) {
		if (*p == '\\' && p[1]) { p++; continue; }
		if (p[0] == '$' && p[1] == '\'') {
			p += 2;
			while (*p && *p != '\'') {
				if (*p == '\\' && p[1]) p++;
				p++;
			}
			if (!*p) return 0;
			continue;
		}
		if (*p == '\'') {
			p++;
			while (*p && *p != '\'') p++;
			if (!*p) return 0;
			continue;
		}
		if (*p == '"') {
			p++;
			while (*p && *p != '"') {
				if (*p == '\\' && p[1]) p++;
				p++;
			}
			if (!*p) return 0;
			continue;
		}
		if (p[0] == '$' && p[1] == '{') { depth++; p++; continue; }
		if (*p == '}') {
			if (!depth) return p;
			depth--;
		}
	}
	return 0;
}

/* Expand an operator's word with the same engine, then turn its fields
 * back into the single replacement string on which the surrounding
 * parameter expansion operates.  A multi-field result is joined with
 * the first IFS byte, as shell "$*" is; the caller performs the final
 * field splitting when the outer expansion is unquoted. */
static int expand_param_word(const char *start withtok(readable_span(input_len)),
                             size_t input_len, int flags,
                             int sh, int quoted, struct assign_ctx *ctx,
                             char **result) __attribute__((nonnull(1, 7)));
// NOLINTNEXTLINE(misc-no-recursion) -- parameter and arithmetic expansion mirror nested shell-word syntax
static int expand_param_word(const char *start withtok(readable_span(input_len)), // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
                             size_t input_len, int flags,
                             int sh, int quoted, struct assign_ctx *ctx, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
                             char **result)
{
	wordexp_t we;
	char *text, *s;
	const char *ifs;
	size_t i, n = 0, prefix = 0;
	int rc;

	*result = 0;
	/* Tilde expansion is suppressed by surrounding double-quotes.  The
	 * recursive scanner cannot otherwise see those outer quotes, so
	 * protect a leading tilde exactly as an input backslash would. */
	if (quoted && input_len && *start == '~') prefix = 1;
	{
		size_t bytes;
		if (input_len > INT_MAX ||
		    !__size_add_checked(input_len, prefix, &bytes) ||
		    !__size_add_checked(bytes, 1, &bytes)) return WRDE_NOSPACE;
		text = __malloc(bytes);
	}
	if (!text) return WRDE_NOSPACE;
	if (prefix) text[0] = '\\';
	if (snprintf(text + prefix, input_len + 1, "%.*s",
	    (int)input_len, start) != (int)input_len) {
		__free(text);
		return WRDE_NOSPACE;
	}
	memset(&we, 0, sizeof we);
	rc = expand_impl(text, &we, flags & (WRDE_NOCMD | WRDE_SHOWERR | WRDE_UNDEF), sh, ctx);
	__free(text);
	if (rc) return rc;

	ifs = getenv("IFS");
	if (!ifs) ifs = " ";
	for (i = 0; i < we.we_wordc; i++) {
		/* Every we.we_wordv[] entry is a real C string (built by
		 * pv_pack()/xstrdup()), but that fact doesn't survive the
		 * wordexp_t out-parameter boundary for a per-call analysis. */
		__ownership_string_terminated(we.we_wordv[i]);
		n += strlen(we.we_wordv[i]);
	}
	if (we.we_wordc > 1 && *ifs) n += we.we_wordc - 1;
	/* A trailing unquoted IFS byte is a field terminator even though it
	 * contributes no field of its own.  Preserve one so the caller's
	 * final split does not concatenate following literal text. */
	if (!quoted && input_len && is_split_char(start[input_len - 1])) n++;
	{
		size_t bytes;
		if (!__size_add_checked(n, 1, &bytes)) { wordfree(&we); return WRDE_NOSPACE; }
		s = __malloc(bytes);
	}
	if (!s) { wordfree(&we); return WRDE_NOSPACE; }
	n = 0;
	for (i = 0; i < we.we_wordc; i++) {
		size_t z;
		__ownership_string_terminated(we.we_wordv[i]);
		z = strlen(we.we_wordv[i]);
		if (i && *ifs) s[n++] = *ifs;
		if (z > INT_MAX ||
		    snprintf(s + n, z + 1, "%s", we.we_wordv[i]) != (int)z) {
			__free(s);
			wordfree(&we);
			return WRDE_NOSPACE;
		}
		n += z;
	}
	if (!quoted && input_len && is_split_char(start[input_len - 1])) s[n++] = start[input_len - 1];
	/* n is rebuilt here by re-summing the same lengths `bytes` was
	 * sized from above, so it's still < bytes, but no annotation in
	 * this vocabulary lets the checker re-derive that. Left unannotated. */
	s[n] = 0;
	wordfree(&we);
	/* *result = s is a store through a `T **` out-parameter, which
	 * AllocationLifetimeChecker's escape recognition doesn't follow
	 * (unlike a producer's own pointer return). */
	*result = s;
	return 0;
}

/* Reads a parameter expansion starting at *pp (which points at the
 * '$'). Advances *pp past it. Appends the value to b -- as literal
 * bytes when `quoted` (inside double-quotes the result is not a glob
 * pattern, XCU 2.6 "quote removal"), as live bytes otherwise, matching
 * every shell: an unquoted $VAR's value *is* eligible for pathname
 * expansion.  Returns 0, or a WRDE_* error code.
 *
 * `sh` is __wordexp_sh()'s "expand as a shell would" (src/internal/
 * libc.h): with it, XCU 2.5.1's positional parameters ($1..$9, and
 * ${10} and beyond, which 2.5.1 requires the braces for -- "when a
 * positional parameter with more than one digit is specified, the
 * application shall enclose the digits in braces") and 2.5.2's '#'
 * expand against src/sh/param.c's list.  Without it -- the public
 * wordexp(), called from a program that has no positional parameters
 * -- a '$' before a digit stays the literal character it always was.
 * 2.5.2's '?' is here too, for the same reason '#' is: it expands to a
 * single field of decimal digits and nothing about it depends on
 * quoting.  2.5.2's '@' and '*' are NOT here: they can produce more
 * than one field, which only the caller's scan can express. */
// NOLINTNEXTLINE(misc-no-recursion) -- parameter and arithmetic expansion mirror nested shell-word syntax
static int expand_param(const char **pp, struct fbuf *b, int flags, int sh,
                        int quoted, struct assign_ctx *ctx)
    __attribute__((nonnull(1)));
// NOLINTNEXTLINE(misc-no-recursion) -- parameter and arithmetic expansion mirror nested shell-word syntax
static int expand_param(const char **pp, struct fbuf *b, int flags, int sh,
                        int quoted, struct assign_ctx *ctx)
{
	const char *p = *pp + 1;
	const char *start;
	char name[256];
	size_t len;
	const char *val;
	int braced = 0;

	if (*p == '{') {
		braced = 1;
		p++;
	}
	start = p;

	if (braced && *p == '#' && is_namestart(p[1])) {
		p++;
		start = p;
		while (is_namechar(*p)) p++;
		len = (size_t)(p - start);
		if (*p != '}' || len >= sizeof name) return WRDE_SYNTAX;
		if (snprintf(name, sizeof name, "%.*s", (int)len, start) !=
		    (int)len)
			return WRDE_SYNTAX;
		__ownership_string_terminated(name);
		*pp = p + 1;
		val = getenv(name);
		if (!val && (flags & WRDE_UNDEF)) return WRDE_BADVAL;
		if (val) __ownership_string_terminated(val);
		return fbuf_push_long(b, val ? (long)strlen(val) : 0) ? WRDE_NOSPACE : 0;
	}

	if (*p >= '0' && *p <= '9') {
		/* 2.5.1: "The digits denoting the positional parameters shall
		 * always be interpreted as a decimal value, even if there is a
		 * leading zero."  Unbraced, exactly one digit is consumed --
		 * "$12" is $1 followed by a literal '2', which is why ${12}
		 * exists.  The cap keeps a pathological "${99999999999}" from
		 * overflowing; it is far above any real argument list and the
		 * answer for it is "unset" either way. */
		long idx = 0;
		if (braced) {
			while (*p >= '0' && *p <= '9') {
				if (idx < 1000000) idx = idx * 10 + (*p - '0');
				p++;
			}
			if (*p != '}') return WRDE_SYNTAX;
			p++;
		} else {
			idx = *p - '0';
			p++;
		}
		*pp = p;
		/* 2.5.2: '0' "[e]xpands to the name of the shell or shell
		 * script" -- a special parameter, never a positional one, so it
		 * cannot be unset and does not go through __sh_param_get(). */
		/* wordexp() has no positional-parameter context.  Its parameters
		 * are therefore all unset; the private shell entry point supplies
		 * the real list (and $0) instead. */
		val = sh ? (idx == 0 ? __sh_param_zero() : __sh_param_get((int)idx)) : 0;
		if (!val) {
			if (flags & WRDE_UNDEF) return WRDE_BADVAL;
			return 0;
		}
		return fbuf_push_str(b, val, quoted) ? WRDE_NOSPACE : 0;
	}
	if (sh && *p == '?' && (!braced || p[1] == '}')) {
		/* 2.5.2 '?': "Expands to the decimal exit status of the most
		 * recent pipeline."  Not ${?word} or any other form -- the
		 * '}' has to come straight after, for the same reason ${#}
		 * below is not ${#NAME}. */
		p += braced ? 2 : 1;
		*pp = p;
		return fbuf_push_long(b, (long)__sh_last_status()) ? WRDE_NOSPACE : 0;
	}
	if (*p == '#' && (!braced || p[1] == '}')) {
		/* 2.5.2 '#': "Expands to the decimal number of positional
		 * parameters."  ${#NAME} is string length, a different
		 * expansion this does not implement, and is excluded by
		 * requiring the '}' to come straight after the '#'. */
		p += braced ? 2 : 1;
		*pp = p;
		return fbuf_push_long(b, sh ? (long)__sh_param_count() : 0) ? WRDE_NOSPACE : 0;
	}

	if (!is_namestart(*p)) {
		/* "$" not followed by a name: not a parameter expansion this
		 * implementation supports (see include/wordexp.h -- only bare
		 * $VAR/${VAR}, not the special parameters). Treat '$' as a
		 * literal character rather than fail the whole expansion. */
		*pp = *pp + 1;
		return fbuf_push(b, '$', 0) ? WRDE_NOSPACE : 0;
	}
	while (is_namechar(*p)) p++;
	len = (size_t)(p - start);
	if (len >= sizeof name) return WRDE_SYNTAX;
	if (snprintf(name, sizeof name, "%.*s", (int)len, start) != (int)len)
		return WRDE_SYNTAX;
	__ownership_string_terminated(name);
	val = getenv(name);
	if (val) __ownership_string_terminated(val);
	if (braced && *p != '}') {
		const char *word, *end;
		char op, *replacement;
		int colon = 0, use_word, rc;
		int longest = 0;

		if (*p == '#' || *p == '%') {
			size_t i, cut = 0, vlen;
			char *pattern, *candidate;

			op = *p++;
			if (*p == op) { longest = 1; p++; }
			word = p;
			end = param_word_end(word);
			if (!end) return WRDE_SYNTAX;
			*pp = end + 1;
			if (!val) {
				if (flags & WRDE_UNDEF) return WRDE_BADVAL;
				return 0;
			}
			rc = expand_trim_pattern(word, (size_t)(end - word), flags, sh, ctx, &pattern);
			if (rc) return rc;
			vlen = strlen(val);
			candidate = xstrdup(val);
			if (!candidate) { __free(pattern); return WRDE_NOSPACE; }
			if (op == '#') {
				if (longest) {
					for (i = vlen + 1; i-- > 0;) {
						candidate[i] = 0;
						if (fnmatch(pattern, candidate, 0) == 0) { cut = i; break; }
					}
				} else {
					for (i = 0; i < vlen + 1; i++) {
						candidate[i] = 0;
						if (fnmatch(pattern, candidate, 0) == 0) { cut = i; break; }
						candidate[i] = val[i];
					}
				}
				rc = fbuf_push_str(b, val + cut, quoted) ? WRDE_NOSPACE : 0;
			} else {
				cut = vlen;
				if (longest) {
					for (i = 0; i < vlen + 1; i++)
						if (fnmatch(pattern, val + i, 0) == 0) { cut = i; break; }
				} else {
					for (i = vlen + 1; i-- > 0;)
						if (fnmatch(pattern, val + i, 0) == 0) { cut = i; break; }
				}
				for (i = 0; i < cut; i++)
					if (fbuf_push(b, val[i], quoted)) { rc = WRDE_NOSPACE; break; }
			}
			__free(candidate);
			__free(pattern);
			return rc;
		}

		if (*p == ':' && p[1] && strchr("-+=?", p[1])) { colon = 1; op = p[1]; word = p + 2; }
		else if (*p && strchr("-+=?", *p)) { op = *p; word = p + 1; }
		else return WRDE_SYNTAX;
		end = param_word_end(word);
		if (!end) return WRDE_SYNTAX;
		*pp = end + 1;
		use_word = !val || (colon && !*val);

		if (op == '+') use_word = !use_word;
		if (!use_word) {
			if (op == '+') return 0;
			return fbuf_push_str(b, val, quoted) ? WRDE_NOSPACE : 0;
		}
		rc = expand_param_word(word, (size_t)(end - word), flags, sh, quoted, ctx, &replacement);
		if (rc) return rc;
		if (op == '?') {
			if (flags & WRDE_SHOWERR) {
				const char *message = *replacement ? replacement : "parameter is unset";
				__ownership_string_terminated(message);
				(void)write(2, message, strlen(message));
				(void)write(2, "\n", 1);
			}
			__free(replacement);
			return WRDE_SYNTAX;
		}
		if (op == '=') {
			rc = assign_param(ctx, name, replacement);
			if (rc) {
				__free(replacement);
				return rc;
			}
		}
		rc = fbuf_push_str(b, replacement, quoted) ? WRDE_NOSPACE : 0;
		__free(replacement);
		return rc;
	}
	if (braced) p++;
	*pp = p;

	if (!val) {
		if (flags & WRDE_UNDEF) return WRDE_BADVAL;
		return 0;
	}
	return fbuf_push_str(b, val, quoted) ? WRDE_NOSPACE : 0;
}

/* Expand a removal operator's word into an fnmatch pattern.  This is
 * deliberately not expand_param_word(): pathname expansion is the
 * following word-expansion phase and must not turn the pattern into a
 * list of files before it is matched against the parameter value. */
// NOLINTNEXTLINE(misc-no-recursion) -- parameter and arithmetic expansion mirror nested shell-word syntax
static int expand_trim_pattern(const char *start, size_t len, int flags, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
                               int sh, struct assign_ctx *ctx, char **result)
{
	struct fbuf b = { 0 };
	char *text, *p, *pattern;
	enum { T_NONE, T_SINGLE, T_DOUBLE } q = T_NONE;
	size_t i, n = 0;
	int rc = 0;

	*result = 0;
	{
		size_t bytes;
		if (!__size_add_checked(len, 1, &bytes)) return WRDE_NOSPACE;
		text = __malloc(bytes);
	}
	if (!text) return WRDE_NOSPACE;
	__ownership_readable_span(start, len);
	memcpy(text, start, len);
	text[len] = 0;
	for (p = text; *p;) {
		char c = *p;
		if (q == T_NONE) {
			if (c == '\'') { q = T_SINGLE; p++; continue; }
			if (c == '"') { q = T_DOUBLE; p++; continue; }
			if (c == '\\' && p[1]) {
				if (fbuf_push(&b, p[1], 1)) { rc = WRDE_NOSPACE; break; }
				p += 2; continue;
			}
			if (c == '$') {
				const char *scan = p;
				rc = expand_param(&scan, &b, flags, sh, 0, ctx);
				if (rc) break;
				p = (char *)scan;
				continue;
			}
			if (fbuf_push(&b, c, 0)) { rc = WRDE_NOSPACE; break; }
			p++;
		} else if (q == T_SINGLE) {
			if (c == '\'') { q = T_NONE; p++; continue; }
			if (fbuf_push(&b, c, 1)) { rc = WRDE_NOSPACE; break; }
			p++;
		} else {
			if (c == '"') { q = T_NONE; p++; continue; }
			if (c == '\\' && p[1] && strchr("\\\"$`", p[1])) {
				if (fbuf_push(&b, p[1], 1)) { rc = WRDE_NOSPACE; break; }
				p += 2; continue;
			}
			if (c == '$') {
				const char *scan = p;
				rc = expand_param(&scan, &b, flags, sh, 1, ctx);
				if (rc) break;
				p = (char *)scan;
				continue;
			}
			if (fbuf_push(&b, c, 1)) { rc = WRDE_NOSPACE; break; }
			p++;
		}
	}
	__free(text);
	if (!rc && q != T_NONE) rc = WRDE_SYNTAX;
	if (rc) { fbuf_free(&b); return rc; }
	{
		size_t bytes;
		if (!__size_mul_checked(b.n, 2, &bytes) ||
		    !__size_add_checked(bytes, 1, &bytes)) { fbuf_free(&b); return WRDE_NOSPACE; }
		pattern = __malloc(bytes);
	}
	if (!pattern) { fbuf_free(&b); return WRDE_NOSPACE; }
	for (i = 0; i < b.n; i++) {
		if (b.lit[i] && strchr("*?[\\", b.data[i])) pattern[n++] = '\\';
		pattern[n++] = b.data[i];
	}
	pattern[n] = 0;
	fbuf_free(&b);
	*result = pattern;
	return 0;
}

/* Reads ~ or ~user starting at *pp (pointing at '~'), only valid when
 * called at the very start of a field. Advances *pp past it. Appends
 * the home directory (as quoted/literal bytes -- tilde-expansion
 * results are not re-scanned for pathname expansion) to b. If the
 * user is unknown, '~'/"~user" is left unexpanded, matching every
 * shell's fallback. */
static int expand_tilde(const char **pp, struct fbuf *b)
    __attribute__((nonnull(1)));
static int expand_tilde(const char **pp, struct fbuf *b)
{
	const char *p = *pp + 1;
	const char *start = p;
	char name[256];
	size_t len;
	const char *home = 0;

	while (*p && *p != '/' && *p != ' ' && *p != '\t' && *p != '\n' &&
	       *p != '"' && *p != '\'')
		p++;
	len = (size_t)(p - start);

	if (len == 0) {
		home = getenv("HOME");
	} else if (len < sizeof name) {
		struct passwd *pw;
		__ownership_readable_span(start, len);
		memcpy(name, start, len);
		name[len] = 0;
		pw = getpwnam(name);
		if (pw) home = pw->pw_dir;
	}

	if (!home) {
		/* Unknown user, or bare ~ with no $HOME: leave the '~' itself
		 * literal and do not consume the rest of the candidate name --
		 * a later '$' etc. in it still gets its own expansion. */
		*pp = *pp + 1;
		return fbuf_push(b, '~', 1) ? WRDE_NOSPACE : 0;
	}
	*pp = p;
	return fbuf_push_str(b, home, 1) ? WRDE_NOSPACE : 0;
}

/* Pushes v's decimal representation onto b as live bytes (unquoted,
 * matching expand_param()'s treatment of a substituted $VAR value --
 * see this file's own header comment on why live vs. quoted never
 * actually matters here: a decimal integer never contains a glob
 * metacharacter or IFS whitespace). */
static int fbuf_push_long(struct fbuf *b, long v)
{
	char buf[32];	/* sign + up to 20 digits (64-bit LONG_MIN) + NUL */
	int n = 0, i;
	unsigned long u = v < 0 ? (unsigned long)(-(v + 1)) + 1UL : (unsigned long)v;

	if (u == 0) buf[n++] = '0';
	while (u) { buf[n++] = (char)('0' + (u % 10)); u /= 10; }
	if (v < 0) buf[n++] = '-';
	for (i = 0; i < n / 2; i++) {
		char t = buf[i];
		buf[i] = buf[n - 1 - i];
		buf[n - 1 - i] = t;
	}
	buf[n] = 0;
	return fbuf_push_str(b, buf, 0);
}

/* POSIX.1-2024 dollar-single-quotes.  The result is quoted data, so
 * neither field splitting nor pathname expansion sees these bytes. */
static int expand_dollar_single(const char **pp, struct fbuf *b)
    __attribute__((nonnull(1)));
static int expand_dollar_single(const char **pp, struct fbuf *b)
{
	const char *p = *pp + 2;

	while (*p && *p != '\'') {
		unsigned char c = (unsigned char)*p++;
		if (c == '\\') {
			unsigned value = 0;
			int digits = 0;
			if (!*p) return WRDE_SYNTAX;
			c = (unsigned char)*p++;
			switch (c) {
			case 'a': c = '\a'; break;
			case 'b': c = '\b'; break;
			case 'e': c = 27; break;
			case 'f': c = '\f'; break;
			case 'n': c = '\n'; break;
			case 'r': c = '\r'; break;
			case 't': c = '\t'; break;
			case 'v': c = '\v'; break;
			case '\\': case '\'': case '"': case '?': break;
			case '\n': continue;
			case '0':
				while (digits < 3 && *p >= '0' && *p <= '7') {
					value = value * 8 + (unsigned)(*p++ - '0');
					digits++;
				}
				c = (unsigned char)value;
				break;
			default:
				/* An unspecified escape keeps the backslash. */
				if (fbuf_push(b, '\\', 1)) return WRDE_NOSPACE;
				break;
			}
		}
		if (fbuf_push(b, (char)c, 1)) return WRDE_NOSPACE;
	}
	if (*p != '\'') return WRDE_SYNTAX;
	*pp = p + 1;
	return 0;
}

/* Reads $((expr)) starting at *pp (pointing at the '$'; callers have
 * already confirmed p[1]=='(' && p[2]=='('). Advances *pp past the
 * matching "))". Appends the decimal result to b. Returns 0, or a
 * WRDE_* error code.
 *
 * Finding the matching "))": the expression's own parentheses (from
 * grouping, e.g. "$((1+(2*3)))") must balance out to net zero before
 * the terminating "))" is recognized -- tracked here with a simple
 * depth counter over '('/')' bytes, not quote-aware (arithmetic
 * expressions have no quoting construct of their own; see
 * src/wordexp/arith.c's header for what this grammar does and does
 * not include). This is XBD 2.6.4's own documented ambiguity ("$((" is
 * also a valid start of a command substitution beginning with a
 * subshell) resolved the way 2.6.4 says every conforming shell must:
 * "the shell shall first determine whether it can parse the expansion
 * as an arithmetic expansion" -- arithmetic wins whenever the text
 * parses as one, which is exactly what wordexp.c's caller already
 * guarantees by only reaching here when p[1]/p[2] are both '('. */
// NOLINTNEXTLINE(misc-no-recursion) -- parameter and arithmetic expansion mirror nested shell-word syntax
static int expand_arith(const char **pp, struct fbuf *b, int flags, int sh,
                        struct assign_ctx *ctx) __attribute__((nonnull(1)));
// NOLINTNEXTLINE(misc-no-recursion) -- parameter and arithmetic expansion mirror nested shell-word syntax
static int expand_arith(const char **pp, struct fbuf *b, int flags, int sh,
                        struct assign_ctx *ctx)
{
	const char *p = *pp + 3;
	const char *start = p;
	const char *end;
	int depth = 0;
	char *expr;
	struct fbuf expanded = { 0 };
	size_t len;
	long result;
	int rc;

	for (;;) {
		if (!*p) return WRDE_SYNTAX;	/* unterminated $(( */
		if (*p == '\\' && p[1]) { p += 2; continue; }
		if (p[0] == '$' && p[1] == '{') {
			const char *close = param_word_end(p + 2);
			if (!close) return WRDE_SYNTAX;
			p = close + 1;
			continue;
		}
		if (*p == '(') { depth++; p++; continue; }
		if (*p == ')') {
			if (depth > 0) { depth--; p++; continue; }
			if (p[1] == ')') { end = p; p += 2; break; }
			return WRDE_SYNTAX;	/* a single ')' where "))" was expected */
		}
		p++;
	}

	len = (size_t)(end - start);
	{
		size_t bytes;
		if (len > INT_MAX || !__size_add_checked(len, 1, &bytes)) return WRDE_NOSPACE;
		expr = __malloc(bytes);
	}
	if (!expr) return WRDE_NOSPACE;
	if (snprintf(expr, len + 1, "%.*s", (int)len, start) != (int)len) {
		__free(expr);
		return WRDE_NOSPACE;
	}

	/* XBD 2.6.4 performs parameter expansion and nested arithmetic
	 * expansion on the expression before evaluating it. */
	{
		const char *s = expr;
		while (*s) {
			if (s[0] == '$' && s[1] == '(' && s[2] == '(') {
				rc = expand_arith(&s, &expanded, flags, sh, ctx);
				if (rc) goto arithmetic_done;
				continue;
			}
			if (*s == '$') {
				rc = expand_param(&s, &expanded, flags, sh, 1, ctx);
				if (rc) goto arithmetic_done;
				continue;
			}
			if (fbuf_push(&expanded, *s++, 1)) {
				rc = WRDE_NOSPACE;
				goto arithmetic_done;
			}
		}
		if (fbuf_push(&expanded, 0, 1)) {
			rc = WRDE_NOSPACE;
			goto arithmetic_done;
		}
	}
	rc = __wordexp_arith(expanded.data, &result, flags);
arithmetic_done:
	fbuf_free(&expanded);
	__free(expr);
	if (rc) return rc;

	*pp = p;
	return fbuf_push_long(b, result) ? WRDE_NOSPACE : 0;
}

/* ---- command substitution (XCU 2.6.3) --------------------------------
 *
 * The extent-finding half lives here rather than in src/sh/: deciding
 * where a "$(...)" or "`...`" *ends* is part of the same left-to-right,
 * quote-state-aware scan this file already performs (it is what lets
 * the scan resume at the right byte afterwards), and src/sh/parse.c's
 * lexer already has its own copy of the same rules for the same reason
 * -- it must find the end to know where the *word* ends. The
 * *execution* half is the shell's, reached through the single
 * __sh_cmdsub() call-out declared in src/internal/libc.h.
 *
 * The two forms are genuinely different languages here, not one with a
 * spelling variant, and the backquoted one is not the lesser case: it
 * is what autoconf-generated `configure` scripts overwhelmingly use.
 *
 *   "$(command)": "all characters following the open parenthesis to the
 *   matching closing parenthesis constitute the command" (2.6.3) -- the
 *   text is the command *verbatim*, nothing is unescaped, and nesting
 *   falls out of matching parentheses. Quoted regions inside are
 *   skipped while matching so a ')' inside 'a)b' cannot close it.
 *
 *   "`command`": "The search for the matching backquote shall be
 *   satisfied by the first unquoted non-escaped backquote" (2.6.3), and
 *   "<backslash> shall retain its literal meaning, except when followed
 *   by: '$', '`', or <backslash>" -- so the delimited text is *not* the
 *   command: it has to have exactly those three escapes removed first,
 *   and every other backslash left standing. That is also the entire
 *   mechanism by which the backquoted form nests: 2.6.3, "To specify
 *   nesting within the backquoted version, the application shall
 *   precede the inner backquotes with <backslash> characters" -- an
 *   inner \` survives the outer scan as an escaped byte and becomes a
 *   real ` in the command text, which the shell's own lexer then reads
 *   as a nested substitution. Nesting therefore needs no special case
 *   at all beyond getting the unescaping exactly right.
 */

/* *pp points at the '$' of "$(". Advances it past the matching ')' and
 * returns the command text between them, freshly __malloc'd, or NULL on
 * an unterminated substitution or OOM (*syntax distinguishes the two).
 */
withtok(internal_heap_allocated)
static char *cmdsub_dollar_text(const char **pp, int *syntax)
    __attribute__((nonnull(1, 2)));
withtok(internal_heap_allocated)
static char *cmdsub_dollar_text(const char **pp, int *syntax)
{
	const char *p = *pp + 2;
	const char *start = p;
	int depth = 1;
	char *r;
	size_t len;

	*syntax = 0;
	while (depth > 0) {
		char c = *p;
		if (!c) { *syntax = 1; return 0; }
		if (c == '\\' && p[1]) { p += 2; continue; }
		if (c == '\'') {
			p++;
			while (*p && *p != '\'') p++;
			if (!*p) { *syntax = 1; return 0; }
			p++;
			continue;
		}
		if (c == '"') {
			p++;
			while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; }
			if (!*p) { *syntax = 1; return 0; }
			p++;
			continue;
		}
		if (c == '(') depth++;
		else if (c == ')') { depth--; if (!depth) break; }
		p++;
	}
	len = (size_t)(p - start);
	{
		size_t bytes;
		if (len > INT_MAX || !__size_add_checked(len, 1, &bytes)) return 0;
		r = __malloc(bytes);
	}
	if (!r) return 0;
	if (snprintf(r, len + 1, "%.*s", (int)len, start) != (int)len) {
		__free(r);
		return 0;
	}
	*pp = p + 1;	/* past the ')' */
	return r;
}

/* *pp points at the opening '`'. Advances it past the matching closing
 * '`' and returns the command text with 2.6.3's backquote escapes
 * removed (\$ -> $, \` -> `, \\ -> \; every other backslash kept, and
 * kept together with the character it precedes), freshly __malloc'd, or
 * NULL on an unterminated substitution or OOM (*syntax distinguishes
 * the two). */
withtok(internal_heap_allocated)
static char *cmdsub_backquote_text(const char **pp, int *syntax)
    __attribute__((nonnull(1, 2)));
withtok(internal_heap_allocated)
static char *cmdsub_backquote_text(const char **pp, int *syntax)
{
	const char *p = *pp + 1;
	const char *start = p;
	char *r;
	size_t o = 0;

	*syntax = 0;
	while (*p && *p != '`') {
		if (*p == '\\' && p[1]) { p += 2; continue; }
		p++;
	}
	if (!*p) { *syntax = 1; return 0; }

	{
		size_t bytes;
		if (!__size_add_checked((size_t)(p - start), 1, &bytes)) return 0;
		r = __malloc(bytes);
	}
	if (!r) return 0;
	for (; start < p; start++) {
		if (*start == '\\' && start + 1 < p &&
		    (start[1] == '$' || start[1] == '`' || start[1] == '\\')) {
			r[o++] = start[1];
			start++;
			continue;
		}
		r[o++] = *start;
	}
	r[o] = 0;
	*pp = p + 1;	/* past the closing '`' */
	return r;
}

/* Runs the command substitution starting at *pp (pointing at the '$' of
 * "$(" or at a '`'), advancing *pp past it, and hands back its captured
 * standard output (trailing newlines already stripped by __sh_cmdsub()
 * per 2.6.3) in *out, __malloc'd and owned by the caller. Returns 0, or
 * a WRDE_* code. */
static int run_cmdsub(const char **pp, int flags, char **out)
    __attribute__((nonnull(1, 3)));
static int run_cmdsub(const char **pp, int flags, char **out)
{
	char *program;
	int syntax = 0, status = 0;

	*out = 0;
	/* WRDE_NOCMD is finally load-bearing: "[f]ail if command
	 * substitution is requested" (wordexp.html) is now a refusal of
	 * something this implementation could otherwise do, rather than a
	 * flag with no observable effect. */
	if (flags & WRDE_NOCMD) return WRDE_CMDSUB;

	program = (**pp == '`') ? cmdsub_backquote_text(pp, &syntax)
	                        : cmdsub_dollar_text(pp, &syntax);
	if (!program) return syntax ? WRDE_SYNTAX : WRDE_NOSPACE;

	if (__sh_cmdsub(program, out, &status)) {
		__free(program);
		/* No WRDE_* code means "the embedded command was bad", and
		 * WRDE_CMDSUB would be a lie (not refused/unsupported), so
		 * WRDE_SYNTAX does double duty here, as in arith.c. */
		return WRDE_SYNTAX;
	}
	__free(program);
	return 0;
}

/* Check lexical errors before performing any expansion.  Besides being
 * cheaper than unwinding a partial result, this gives shell syntax and
 * WRDE_NOCMD the precedence required over WRDE_UNDEF when a malformed
 * construct occurs later in the input.
 *
 * The `while (*p)`/`*p` below (and its siblings in expand_impl(),
 * expand_arith(), expand_trim_pattern(), and expand_param()) report an
 * open "pointer dereference is not proven nonnull": passing &p to the
 * cursor-advancing helpers (cmdsub_dollar_text() etc.) means Clang's
 * core engine can no longer treat a later *pp read as the same
 * proven-in-bounds value, even though it only ever advances within the
 * original buffer. Neither returns_nonnull nor a manual
 * __ownership_readable_span() axiom after the call fixes this. Left open. */
static int validate_words(const char *words, int flags)
    __attribute__((nonnull(1)));
static int validate_words(const char *words, int flags)
{
	const char *p = words;
	enum { V_NONE, V_SINGLE, V_DOUBLE } q = V_NONE;

	while (*p) {
		char c = *p;
		if (q == V_SINGLE) {
			if (c == '\'') q = V_NONE;
			p++;
			continue;
		}
		if (q == V_DOUBLE && c == '"') { q = V_NONE; p++; continue; }
		if (c == '\\') {
			if (!p[1]) return WRDE_SYNTAX;
			p += 2;
			continue;
		}
		if (q == V_NONE && c == '\'') { q = V_SINGLE; p++; continue; }
		if (q == V_NONE && c == '"') { q = V_DOUBLE; p++; continue; }
		if (q == V_NONE && c == '#' &&
		    (p == words || p[-1] == ' ' || p[-1] == '\t' || p[-1] == '\n')) {
			while (*p && *p != '\n') p++;
			return *p == '\n' ? WRDE_BADCHAR : 0;
		}
		if (c == '$' && p[1] == '{') {
			const char *end = param_word_end(p + 2);
			if (!end) return WRDE_SYNTAX;
			p = end + 1;
			continue;
		}
		if (q == V_NONE && c == '$' && p[1] == '\'') {
			p += 2;
			while (*p && *p != '\'') {
				if (*p == '\\' && p[1]) p++;
				p++;
			}
			if (!*p) return WRDE_SYNTAX;
			p++;
			continue;
		}
		if (c == '$' && p[1] == '(' && p[2] == '(') {
			const char *a = p + 3;
			int depth = 0;
			for (;;) {
				if (!*a) return (flags & WRDE_NOCMD) ? WRDE_CMDSUB : WRDE_SYNTAX;
				if (a[0] == '$' && a[1] == '{') {
					const char *end = param_word_end(a + 2);
					if (!end) return WRDE_SYNTAX;
					a = end + 1;
					continue;
				}
				if (*a == '(') { depth++; a++; continue; }
				if (*a == ')') {
					if (depth) { depth--; a++; continue; }
					if (a[1] == ')') { p = a + 2; break; }
					return (flags & WRDE_NOCMD) ? WRDE_CMDSUB : WRDE_SYNTAX;
				}
				a++;
			}
			continue;
		}
		if ((c == '$' && p[1] == '(' && p[2] != '(') || c == '`') {
			char *text;
			int syntax = 0;
			if (flags & WRDE_NOCMD) return WRDE_CMDSUB;
			text = c == '`' ? cmdsub_backquote_text(&p, &syntax)
			                  : cmdsub_dollar_text(&p, &syntax);
			if (!text) return syntax ? WRDE_SYNTAX : WRDE_NOSPACE;
			__free(text);
			continue;
		}
		if (q == V_NONE) {
			if (c == '(' || c == ')') return WRDE_BADCHAR;
			if (c == '\n') return WRDE_BADCHAR;
		}
		p++;
	}
	return q == V_NONE ? 0 : WRDE_SYNTAX;
}

/* Turns one already-expanded field (b->data[0..n), with b->lit[i] true
 * for bytes that must stay literal) into one or more output words,
 * pushing them onto out. Live '*'/'?'/'[' bytes trigger glob(); no live
 * metacharacters means the field is used exactly as scanned. */
static int emit_field(struct fbuf *b, struct pv *out) __attribute__((nonnull(1)));
static int emit_field(struct fbuf *b, struct pv *out)
{
	size_t i;
	int has_meta = 0;
	char *plain;
	struct fbuf pat;

	/* Same open "pointer dereference is not proven nonnull" as
	 * fbuf_push()'s b->lit[b->n] -- see that function's comment. */
	for (i = 0; i < b->n; i++)
		if (!b->lit[i] && (b->data[i] == '*' || b->data[i] == '?' || b->data[i] == '['))
			{ has_meta = 1; break; }

	{
		size_t bytes;
		if (!__size_add_checked(b->n, 1, &bytes)) return WRDE_NOSPACE;
		plain = __malloc(bytes);
	}
	if (!plain) return WRDE_NOSPACE;
	if (b->n) {
		memcpy(plain, b->data, b->n);
	}
	plain[b->n] = 0;

	/* pv_push(out, plain)'s transfer into out->v[] is the same open
	 * "dynamic allocation is not freed before function exit" as below:
	 * AllocationLifetimeChecker's escape recognition doesn't read
	 * struct pv's elements_withtok(internal_heap_allocated, n). */
	if (!has_meta) return pv_push(out, plain) ? WRDE_NOSPACE : 0;

	pat.data = 0; pat.lit = 0; pat.n = pat.cap = 0;
	for (i = 0; i < b->n; i++) {
		char c = b->data[i];
		if (b->lit[i] && (c == '*' || c == '?' || c == '[' || c == '\\')) {
			if (fbuf_push(&pat, '\\', 0)) goto nospace;
		}
		if (fbuf_push(&pat, c, 0)) goto nospace;
	}
	if (fbuf_push(&pat, 0, 0)) goto nospace;

	{
		glob_t g;
		int rc = glob(pat.data, 0, 0, &g);
		fbuf_free(&pat);
		if (rc == 0) {
			size_t j;
			for (j = 0; j < g.gl_pathc; j++) {
				/* glob(3)'s contract: gl_pathv[0..gl_pathc) are real,
				 * NUL-terminated pathnames; <glob.h>'s gl_pathv field
				 * has no per-element contract of its own. */
				__ownership_string_terminated(g.gl_pathv[j]);
				char *w = xstrdup(g.gl_pathv[j]);
				if (!w || pv_push(out, w)) { globfree(&g); __free(plain); return WRDE_NOSPACE; }
			}
			globfree(&g);
			__free(plain);
			return 0;
		}
		if (rc == GLOB_NOMATCH) return pv_push(out, plain) ? WRDE_NOSPACE : 0;
		__free(plain);
		return WRDE_NOSPACE; /* GLOB_ABORTED can't happen: no errfunc, no GLOB_ERR */
	}
nospace:
	fbuf_free(&pat);
	__free(plain);
	return WRDE_NOSPACE;
}

/* Field-split the live bytes appended by an unquoted expansion.  Input
 * syntax whitespace is handled by the main scanner; IFS applies here,
 * to expansion results. */
static int split_appended(struct fbuf *b, struct pv *out, int *active,
                          size_t before) __attribute__((nonnull(1)));
static int split_appended(struct fbuf *b, struct pv *out, int *active,
                          size_t before)
{
	size_t i, n = b->n - before;
	char *text;
	int rc;

	if (!n) return 0;
	text = __malloc(n);
	if (!text) return WRDE_NOSPACE;
	__ownership_readable_span(b->data + before, n);
	memcpy(text, b->data + before, n);
	b->n = before;
	for (i = 0; i < n; i++) {
		if (is_split_char(text[i])) {
			if (*active) {
				rc = emit_field(b, out);
				fbuf_free(b);
				*active = 0;
				if (rc) { __free(text); return rc; }
			}
		} else {
			if (fbuf_push(b, text[i], 0)) {
				__free(text);
				return WRDE_NOSPACE;
			}
			*active = 1;
		}
	}
	__free(text);
	return 0;
}

/* If `p` (pointing at a '$') introduces "$@"/"${@}" or "$*"/"${*}",
 * returns '@' or '*' and sets *end past the whole expansion; otherwise
 * returns 0 and leaves *end alone.  Only the bare and fully-braced
 * spellings: "${@:-x}" and friends are other expansions this does not
 * implement, and must not be mistaken for this one. */
static int at_or_star(const char *p, const char **end) __attribute__((nonnull(1)));
static int at_or_star(const char *p, const char **end)
{
	const char *q = p + 1;

	if (*q == '{') {
		if ((q[1] == '@' || q[1] == '*') && q[2] == '}') { *end = q + 3; return q[1]; }
		return 0;
	}
	if (*q == '@' || *q == '*') { *end = q + 1; return *q; }
	return 0;
}

/* XCU 2.5.2's '@' and '*': "Expands to the positional parameters,
 * starting from one, initially producing one field for each positional
 * parameter that is set."
 *
 * This is the one expansion that cannot be a string: it produces a
 * *number* of fields, so it splices directly into the caller's scan --
 * emitting the field built so far, then starting the next one -- rather
 * than returning text.  That is also why it takes `out` and `active`:
 * it is doing the same thing the caller's FLUSH does, at a point only
 * it knows about.
 *
 *  - `star && quoted` is 2.5.2's other half for '*': "[w]hen the
 *    expansion occurs in a context where field splitting will not be
 *    performed, the initial fields shall be joined to form a single
 *    field with the value of each parameter separated by the first
 *    character of the IFS variable ... or separated by a <space> if
 *    IFS is unset".  This implementation never consults IFS at all
 *    (see <wordexp.h>), so the separator is always the <space> that
 *    clause names for an unset IFS.
 *  - Everything else produces one field per parameter.  For unquoted
 *    '@' and '*' that is 2.5.2's "initially producing one field for
 *    each positional parameter", with field splitting then applying to
 *    each; for "$@" it is the retained-as-separate-fields case.
 *  - Zero parameters contributes nothing at all -- 2.5.2: "[i]f there
 *    are no positional parameters, the expansion of '@' shall generate
 *    zero fields, even when '@' is within double-quotes".  The
 *    caller's `dq` bookkeeping is what stops the enclosing quotes from
 *    manufacturing an empty field in that case.
 *
 * An empty parameter mid-list is kept as an empty field when quoted (a
 * quoted null is a field, 2.6) and dropped when not (2.5.2: "any empty
 * fields may be discarded"), which is what `quoted ||` below says. */
static int push_params(struct fbuf *b, struct pv *out, int *active, int star, int quoted)
    __attribute__((nonnull(1, 3)));
static int push_params(struct fbuf *b, struct pv *out, int *active, int star, int quoted)
{
	int n = __sh_param_count(), i, rc;

	if (star && quoted) {
		for (i = 1; i <= n; i++) {
			if (i > 1 && fbuf_push(b, ' ', 1)) return WRDE_NOSPACE;
			if (fbuf_push_str(b, __sh_param_get(i), 1)) return WRDE_NOSPACE;
		}
		return 0;
	}
	for (i = 1; i <= n; i++) {
		size_t before;
		if (i > 1) {
			if (*active) {
				rc = emit_field(b, out);
				fbuf_free(b);
				if (rc) return rc;
			}
			*active = 0;
		}
		before = b->n;
		if (fbuf_push_str(b, __sh_param_get(i), quoted)) return WRDE_NOSPACE;
		if (quoted || b->n != before) *active = 1;
	}
	return 0;
}

/* The one scan both wordexp() and __wordexp_sh() run; `sh` is the only
 * difference between them (see src/internal/libc.h on __wordexp_sh()
 * for why it is a parameter rather than a second implementation). */
// NOLINTNEXTLINE(misc-no-recursion) -- parameter and arithmetic expansion mirror nested shell-word syntax
static int expand_impl(const char *words, wordexp_t *pwordexp, int flags, int sh,
                       struct assign_ctx *ctx)
{
	struct pv out;
	struct fbuf field;
	const char *p = words;
	enum { Q_NONE, Q_SINGLE, Q_DOUBLE } q = Q_NONE;
	int active = 0;	/* current field has at least one byte, or was opened by a quote */
	int rc;
	size_t base = 0;
	int pack_failed = 0;
	/* State for the one case where a double-quote must *not* keep the
	 * field alive: 2.5.2 says "$@" with no positional parameters
	 * generates zero fields "even when '@' is within double-quotes",
	 * while "" plainly generates one empty field.  The three below
	 * distinguish them: `dq_prev` is whether the field was already
	 * alive before this quote opened, `dq_mark` how long it was, and
	 * `dq_null_at` whether an empty "$@" happened inside.  Only when
	 * all three say "these quotes contributed nothing but the empty
	 * $@" is the quote's own activation undone.  That is exactly the
	 * clause 2.5.2 leaves unspecified -- "if the other parts are all
	 * within the same double-quotes as the '@', it is unspecified
	 * whether the result is zero fields or one empty field" -- resolved
	 * the way bash and dash both resolve it, since `f "$@"` passing one
	 * empty argument instead of none is the classic script-breaking
	 * form of getting this wrong. */
	int dq_prev = 0, dq_null_at = 0;
	size_t dq_mark = 0;

	if (flags & WRDE_REUSE) wordfree(pwordexp);

	out.v = 0; out.n = out.cap = 0;
	if (flags & WRDE_APPEND) {
		/* pwordexp->we_wordv is not freed here even though its pointers
		 * are copied into out.v: RETURN VALUE requires it stay valid on
		 * a non-WRDE_NOSPACE error, so it's freed only once a path below
		 * commits to replacing it. */
		size_t count = pwordexp->we_wordc;
		if (count) {
			char *const *old = pwordexp->we_wordv + pwordexp->we_offs;
			size_t bytes;
			if (!__size_mul_checked(count, sizeof *out.v, &bytes)) {
				errno = ENOMEM;
				return WRDE_NOSPACE;
			}
			out.v = (char **)__malloc(bytes);
			if (!out.v) { errno = ENOMEM; return WRDE_NOSPACE; }
			__ownership_readable_span(old, bytes);
			memcpy((void *)out.v, (const void *)old, bytes);
			out.n = out.cap = count;
		}
		base = count;
	}

	field.data = 0; field.lit = 0; field.n = field.cap = 0;
#define FLUSH() do { \
		if (active) { \
			rc = emit_field(&field, &out); \
			fbuf_free(&field); \
			active = 0; \
			if (rc) goto fail; \
		} \
	} while (0)

	while (*p) {
		char c = *p;
		if (q == Q_NONE) {
			if (c == '#' &&
			    (p == words || p[-1] == ' ' || p[-1] == '\t' || p[-1] == '\n')) {
				while (*p && *p != '\n') p++;
				continue;
			}
			if (is_ifs(c)) { FLUSH(); p++; continue; }
			if (c == '\'') { q = Q_SINGLE; active = 1; p++; continue; }
			if (c == '"') {
				q = Q_DOUBLE;
				dq_prev = active;
				dq_mark = field.n;
				dq_null_at = 0;
				active = 1;
				p++;
				continue;
			}
			if (c == '\\') {
				if (!p[1]) { rc = WRDE_SYNTAX; goto fail; }
				if (p[1] == '\n') { p += 2; continue; }
				if (fbuf_push(&field, p[1], 1)) { rc = WRDE_NOSPACE; goto fail; }
				active = 1;
				p += 2;
				continue;
			}
			if (c == '$' && p[1] == '\'') {
				active = 1;
				rc = expand_dollar_single(&p, &field);
				if (rc) goto fail;
				continue;
			}
			if (c == '$' && p[1] == '(' && p[2] == '(') {
				active = 1;
				rc = expand_arith(&p, &field, flags, sh, ctx);
				if (rc) goto fail;
				continue;
			}
			if ((c == '$' && p[1] == '(') || c == '`') {
				/* 2.6.3 unquoted: the result *is* subject to field
				 * splitting and pathname expansion (only the
				 * double-quoted case below is exempted), so each byte
				 * goes in live and an IFS byte ends the field right
				 * here -- this is field splitting of a substitution
				 * result, tracked through the same scan that produced
				 * it, which is precisely what cannot be done by a
				 * splitter bolted on afterwards. */
				char *o;
				size_t i;
				rc = run_cmdsub(&p, flags, &o);
				if (rc) goto fail;
				for (i = 0; o[i]; i++) {
					if (is_split_char(o[i])) {
						if (active) {
							rc = emit_field(&field, &out);
							fbuf_free(&field);
							active = 0;
							if (rc) { __free(o); goto fail; }
						}
						continue;
					}
					if (fbuf_push(&field, o[i], 0)) { __free(o); rc = WRDE_NOSPACE; goto fail; }
					active = 1;
				}
				__free(o);
				continue;
			}
			if (c == '$') {
				const char *end;
				int k = at_or_star(p, &end);
				size_t before;
				if (k) {
					if (sh) {
						rc = push_params(&field, &out, &active, k == '*', 0);
						if (rc) goto fail;
					}
					p = end;
					continue;
				}
				/* Not `active = 1` up front any more: XCU 2.6 says
				 * "[i]f the complete expansion appropriate for a word
				 * results in an empty field, that empty field shall be
				 * deleted ... unless the original word contained
				 * single-quote or double-quote characters", so an
				 * unquoted expansion that produces no bytes must
				 * produce no field either.  Deciding it on whether
				 * anything was actually appended is what makes
				 * `f $1` with no parameters pass nothing rather than
				 * one empty argument. */
				before = field.n;
				rc = expand_param(&p, &field, flags, sh, 0, ctx);
				if (rc) goto fail;
				rc = split_appended(&field, &out, &active, before);
				if (rc) goto fail;
				continue;
			}
			if (c == '~' && !active) {
				active = 1;
				rc = expand_tilde(&p, &field);
				if (rc) goto fail;
				continue;
			}
			if (c == '|' || c == '&' || c == ';' || c == '<' || c == '>' ||
			    c == '(' || c == ')' || c == '{' || c == '}') {
				rc = WRDE_BADCHAR;
				goto fail;
			}
			if (fbuf_push(&field, c, 0)) { rc = WRDE_NOSPACE; goto fail; }
			active = 1;
			p++;
		} else if (q == Q_SINGLE) {
			if (c == '\'') { q = Q_NONE; p++; continue; }
			if (fbuf_push(&field, c, 1)) { rc = WRDE_NOSPACE; goto fail; }
			p++;
		} else { /* Q_DOUBLE */
			if (c == '"') {
				q = Q_NONE;
				if (dq_null_at && !dq_prev && field.n == dq_mark) active = 0;
				p++;
				continue;
			}
			if (c == '\\' && p[1] && strchr("\"\\$`\n", p[1])) {
				if (p[1] == '\n') { p += 2; continue; }
				if (fbuf_push(&field, p[1], 1)) { rc = WRDE_NOSPACE; goto fail; }
				p += 2;
				continue;
			}
			if (c == '$' && p[1] == '(' && p[2] == '(') {
				rc = expand_arith(&p, &field, flags, sh, ctx);
				if (rc) goto fail;
				continue;
			}
			if ((c == '$' && p[1] == '(') || c == '`') {
				/* 2.6.3: "If a command substitution occurs inside
				 * double-quotes, field splitting and pathname
				 * expansion shall not be performed on the results of
				 * the substitution" -- so the whole capture goes in as
				 * one run of quoted bytes: no FLUSH on an IFS byte, and
				 * a '*' in the output stays a literal '*'. */
				char *o;
				rc = run_cmdsub(&p, flags, &o);
				if (rc) goto fail;
				rc = fbuf_push_str(&field, o, 1) ? WRDE_NOSPACE : 0;
				__free(o);
				if (rc) goto fail;
				continue;
			}
			if (c == '$') {
				const char *end;
				int k = at_or_star(p, &end);
				if (k) {
					if (k == '@' && (!sh || __sh_param_count() == 0)) dq_null_at = 1;
					if (sh) {
						rc = push_params(&field, &out, &active, k == '*', 1);
						if (rc) goto fail;
					}
					p = end;
					continue;
				}
				rc = expand_param(&p, &field, flags, sh, 1, ctx);
				if (rc) goto fail;
				continue;
			}
			if (fbuf_push(&field, c, 1)) { rc = WRDE_NOSPACE; goto fail; }
			p++;
		}
	}
	if (q != Q_NONE) { rc = WRDE_SYNTAX; goto fail; }
	FLUSH();
#undef FLUSH

	{
		size_t offs = (flags & WRDE_DOOFFS) ? pwordexp->we_offs : 0;
		char **v = pv_pack(&out, offs);
		if (!v) { rc = WRDE_NOSPACE; pack_failed = 1; goto fail; }
		if (flags & WRDE_APPEND) __free((void *)pwordexp->we_wordv);
		pwordexp->we_wordv = v;
		pwordexp->we_wordc = out.n;
		if (!(flags & WRDE_DOOFFS) && !(flags & WRDE_APPEND)) pwordexp->we_offs = offs;
	}
	return 0;

fail:
	fbuf_free(&field);
	if (rc == WRDE_NOSPACE) {
		/* RETURN VALUE: on WRDE_NOSPACE, we_wordc/we_wordv are updated
		 * to reflect the words successfully expanded so far. */
		size_t offs = (flags & WRDE_DOOFFS) ? pwordexp->we_offs : 0;
		char **v = pack_failed ? 0 : pv_pack(&out, offs);
		if (v) {
			if (flags & WRDE_APPEND) __free((void *)pwordexp->we_wordv);
			pwordexp->we_wordv = v;
			pwordexp->we_wordc = out.n;
		} else {
			/* Couldn't even allocate room to report partial success:
			 * leave pwordexp as it was, freeing only what this call added. */
			pv_free_from(&out, base);
			if (!(flags & WRDE_APPEND)) {
				pwordexp->we_wordc = 0;
				pwordexp->we_wordv = 0;
			}
		}
	} else {
		/* RETURN VALUE: "on other errors ... these fields remain
		 * unmodified" -- so free only the words *this* call added
		 * (out.v[base..n)), not the carried-over ones out.v[0..base). */
		pv_free_from(&out, base);
		if (!(flags & WRDE_APPEND)) {
			pwordexp->we_wordc = 0;
			pwordexp->we_wordv = 0;
		}
	}
	if (rc == WRDE_NOSPACE) errno = ENOMEM;
	return rc;
}

int wordexp(const char *words, wordexp_t *pwordexp, int flags)
{
	struct assign_ctx ctx = { 0 };
	int rc;

	if (flags & WRDE_REUSE) wordfree(pwordexp);
	rc = validate_words(words, flags);
	if (!rc) rc = expand_impl(words, pwordexp, flags & ~WRDE_REUSE, 0, &ctx);
	else if (!(flags & WRDE_APPEND)) {
		pwordexp->we_wordc = 0;
		pwordexp->we_wordv = 0;
	}
	finish_assignments(&ctx, 1);
	return rc;
}

int __wordexp_sh(const char *words, wordexp_t *pwordexp, int flags)
{
	struct assign_ctx ctx = { 0 };
	int rc = expand_impl(words, pwordexp, flags, 1, &ctx);
	finish_assignments(&ctx, 0);
	return rc;
}

void wordfree(wordexp_t *pwordexp)
{
	size_t i, offs;

	if (!pwordexp || !pwordexp->we_wordv) return;
	offs = pwordexp->we_offs;
	/* we_wordv[offs+i]'s open "dereference extent is not proven
	 * sufficient" is <wordexp.h>'s documented limit: its
	 * withtok(internal_heap_allocated) proves no leak/double-free, not
	 * that we_wordc elements are really there for an arbitrary caller. */
	for (i = 0; i < pwordexp->we_wordc; i++) __free(pwordexp->we_wordv[offs + i]);
	__free((void *)pwordexp->we_wordv);
	pwordexp->we_wordv = 0;
	pwordexp->we_wordc = 0;
}
