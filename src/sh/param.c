/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The shell's positional parameters (XCU 2.5.1) and the special
 * parameter 0, which is *not* one of them.
 *
 * Unlike every other piece of shell state (which lives in the real
 * `environ`, see execute.c), positional parameters get their own array:
 * they're an ordered list `shift` renumbers atomically, "$@" needs a
 * known length a stray inherited `1=...` can't corrupt, 2.9.5 requires
 * a function to save/restore the whole list cheaply, and critically,
 * XCU 2.5.1's list is not exported -- storing it in environ would leak
 * $1 into a child process. The array holds $1 at index 0; `n` is `$#`.
 *
 * $0 is a *special* parameter, not a positional one (2.5.1 excludes the
 * digit 0), so it lives in its own variable: `shift` never touches it,
 * `$#` never counts it, `set` never replaces it, and a function call
 * leaves it unchanged (2.9.5), all by construction.
 */
#include <string.h>
#include "libc.h"
#include "sh.h"

/* $1..$n, as a NULL-free array of __malloc'd strings: v[k] is $(k+1). */
static char **pv;
static int pn;

/* $0. NULL means "never set" (engine linked without sh/main.c, e.g. a test
 * binary or wordexp()'s command substitution); __sh_param_zero() then falls
 * back to "sh", per sh(1p) making $0 the shell or script name. */
static char *pzero;

static char *dup_str(const char *s)
{
	size_t n = strlen(s) + 1;
	char *p = __malloc(n);
	if (p) memcpy(p, s, n);
	return p;
}

static void free_vec(char **v, int n)
{
	int i;
	if (!v) return;
	for (i = 0; i < n; i++) __free(v[i]);
	__free((void *)v);
}

const char *__sh_param_zero(void)
{
	return pzero ? pzero : "sh";
}

int __sh_param_set_zero(const char *s)
{
	char *d = dup_str(s);
	if (!d) return -1;
	__free(pzero);
	pzero = d;
	return 0;
}

int __sh_param_count(void)
{
	return pn;
}

/* $n, 1-based; NULL for out-of-range. Callers must not pass 0 -- that's
 * $0, which comes from __sh_param_zero() instead. */
const char *__sh_param_get(int n)
{
	if (n < 1 || n > pn) return 0;
	return pv[n - 1];
}

/* Replaces the whole list with a copy of argv[0..n).  This is `set`'s
 * "All positional parameters shall be unset before any new values are
 * assigned", and a function call's "[t]he operands to the command
 * temporarily shall become the positional parameters" (2.9.5).
 *
 * The new array is built *before* the old one is released, so a failure
 * partway through leaves the shell's parameters exactly as they were
 * rather than half-assigned. */
int __sh_params_replace(char *const *argv, int n)
{
	char **nv = 0;
	int i;

	if (n < 0) n = 0;
	if (n > 0) {
		size_t bytes;
		if (!__size_mul_checked((size_t)n, sizeof *nv, &bytes)) return -1;
		nv = (char **)__malloc(bytes);
		if (!nv) return -1;
		for (i = 0; i < n; i++) {
			nv[i] = dup_str(argv[i]);
			if (!nv[i]) { free_vec(nv, i); return -1; }
		}
	}
	free_vec(pv, pn);
	pv = nv;
	pn = n;
	return 0;
}

/* shift(1p): n must be <= $#; n == 0 leaves the parameters unchanged.
 * Returns -1 without touching anything for an out-of-range n. */
int __sh_params_shift(int n)
{
	int i;

	if (n < 0 || n > pn) return -1;
	if (n == 0) return 0;
	for (i = 0; i < n; i++) __free(pv[i]);
	for (i = n; i < pn; i++)
		pv[i - n] = pv[i];
	pn -= n;
	return 0;
}

/* ---- save/restore, for 2.9.5 and for subshell environments ------------
 *
 * A *move*, not a copy: each frame owns the list it took, so recursion
 * can't alias a parent's array. $0 is not part of the saved state --
 * 2.9.5 leaves it unchanged across a function call, so there's nothing
 * to restore. */
void __sh_params_take(struct sh_params *out)
{
	out->v = pv;
	out->n = pn;
	pv = 0;
	pn = 0;
}

void __sh_params_install(struct sh_params *in)
{
	free_vec(pv, pn);
	pv = in->v;
	pn = in->n;
	in->v = 0;
	in->n = 0;
}

void __sh_params_free(struct sh_params *p)
{
	free_vec(p->v, p->n);
	p->v = 0;
	p->n = 0;
}
