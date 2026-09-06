/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * awk's tree-walking interpreter. See src/util/awk.c's header for the
 * XCU awk(1p) citations and the full, honest list of what this whole
 * utility narrows or omits; this file's own header covers only the
 * implementation techniques specific to it.
 *
 * CONTROL FLOW: exec_stmt() returns an `enum awk_sig` (awk_priv.h)
 * instead of using setjmp/longjmp. break/continue/next/exit/return are
 * each caught by whichever C stack frame already corresponds to their
 * target (a loop's own exec_stmt call, the per-record dispatch loop,
 * or call_user_func()), so an ordinary return value threads the signal
 * exactly as far as it needs to go, with no extra machinery, for every
 * case except one: next/exit executed from *inside a user-defined
 * function* need to unwind past eval()'s call to call_user_func(),
 * and eval() only returns a value, with no room for a signal. That one
 * case uses ip->unwind, a persistent flag next/exit's own exec_stmt
 * cases set in addition to their normal SIG_NEXT/SIG_EXIT return; every
 * statement that evaluates a sub-expression checks it immediately
 * afterward and bails the same way it would from an ordinary
 * SIG_NEXT/SIG_EXIT if set. A next/exit whose only observable effect
 * would be mid-expression (as one operand still being combined with
 * others after the call returns) instead leaves a harmless dummy value
 * for the rest of that one expression -- discarded anyway, since the
 * enclosing statement bails right after.
 *
 * NUMERIC STRING / VALUE-KIND MODEL: see awk_priv.h's struct awk_cell
 * comment (enum awk_valkind) for the full design and why it is kept
 * separate from num/str lazy-caching.
 *
 * ALLOCATION FAILURE: fatal here too, the same policy and reasoning as
 * awk_parse.c's own header explains for the parser -- and, as of this
 * file's oom()/fatal() below, the same "unwind via awk_unwind_fatal(),
 * never a raw exit()" requirement too: awk_run.c is where every OTHER
 * fatal runtime condition also lives (division by zero, a scalar/array
 * type clash, an undefined function call, an invalid dynamic ERE, a
 * failed output redirect open), every one of them reachable from
 * ordinary, easily-triggered awk source, and __util_awk_main() can be
 * running as a no-fork src/sh/builtin.c built-in when any of them
 * fires -- see awk_priv.h's "fatal-error unwind" header comment for
 * the full design and its two disclosed tradeoffs (why setjmp/longjmp
 * over threading real error returns, and why memory/FDs are not
 * unwound-and-freed on that path).
 *
 * DOUBLE -> INTEGER CONVERSIONS THAT FEED AN ARRAY INDEX/ALLOCATION
 * SIZE: funneled through d2long()/d2int() below rather than a bare
 * (long)/(int) cast. A cast of a double outside the target type's
 * range is undefined behavior in C (C11 6.3.1.4p1), not just "some
 * implementation-defined large number" -- and this was a real, fuzzer-
 * found bug, not a theoretical one: an absurd field reference like
 * $111111111111111111111 (a huge decimal literal well outside `long`,
 * let alone `int`, range) used to reach set_field() with idx already
 * UB from the (long) cast at its call site, which set_field() then
 * cast AGAIN, to (int), to size fields_reserve()'s allocation -- while
 * a second, un-truncated use of the same `long idx` a few lines later
 * walked the loop bound past that (int)-sized allocation, a genuine
 * out-of-bounds heap write. d2long()/d2int() saturate instead: NaN
 * maps to 0, anything outside the target range clamps to that range's
 * nearest endpoint, so every later comparison/cast is over a value
 * already inside a well-defined range -- no wraparound, no UB, and
 * (paired with AWK_MAX_FIELD below) no more truncate-then-use-the-
 * untruncated-value mismatch.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <sys/wait.h>
#include "awk_priv.h"
#include "ownership_stubs.h"
#include "util.h"

/* A field index or NF assignment past this is refused with a clean
 * diagnostic (via fatal(), same as any other fatal runtime condition
 * here) rather than attempted at all -- defense in depth alongside
 * d2long()/d2int() below: even a legitimate-looking huge index that
 * DOES fit in a long (unlike the UB case those two guard against)
 * would otherwise size a real multi-hundred-megabyte-or-more
 * fields_reserve() allocation for one `$N=` or `NF=` assignment. No
 * real awk program legitimately needs anywhere near this many fields;
 * 1,000,000 keeps the worst case (~8 bytes/pointer slot, plus one
 * empty-string allocation per padded field) in the tens-of-megabytes
 * range instead of unbounded. */
#define AWK_MAX_FIELD 1000000L

/* See this file's header comment ("DOUBLE -> INTEGER CONVERSIONS")
 * above for why a bare (long) cast is not safe here. */
static long d2long(double d)
{
	if (d != d) return 0; /* NaN: no ordering to saturate toward */
	if (d >= (double)LONG_MAX) return LONG_MAX;
	if (d <= (double)LONG_MIN) return LONG_MIN;
	return (long)d;
}

static int d2int(double d)
{
	long l = d2long(d);
	if (l > INT_MAX) return INT_MAX;
	if (l < INT_MIN) return INT_MIN;
	return (int)l;
}

/* printf's %d/%o/%u/%x/%X/%c conversions format via `long long`/
 * `unsigned long long` rather than `long` (awk_format() below), so the
 * saturating conversion for those needs its own long-long-range
 * version rather than reusing d2long() -- LONG_MAX/LLONG_MAX are equal
 * on this project's own targets in practice, but this is the correct
 * one to reach for regardless of that. */
static long long d2ll(double d)
{
	if (d != d) return 0;
	if (d >= (double)LLONG_MAX) return LLONG_MAX;
	if (d <= (double)LLONG_MIN) return LLONG_MIN;
	return (long long)d;
}

static void oom(void)
{
	__util_diagf("awk: out of memory\n");
	awk_unwind_fatal();
}

static void fatal(const char *msg)
{
	__util_diagf("awk: %s\n", msg);
	awk_unwind_fatal();
}

/* Not also declared withtok(heap_allocated): almost every caller hands
 * the result to v_str_init()/assign_value_to_cell(), whose own str
 * fields deliberately don't carry that family either. Verified
 * empirically: adding the grant here turned 4 pre-existing findings
 * into 36. */
withtok(null_terminated)
static char *xstrdup(const char *s withtok(null_terminated))
{
	size_t n = strlen(s) + 1;
	char *r = malloc(n);
	if (!r) oom();
	for (size_t i = 0; i < n; i++) r[i] = s[i];
	/* Copies s's terminating NUL too, so r is null-terminated by
	 * construction -- just not through a shape the checker can see. */
	__ownership_string_terminated(r);
	return r;
}

/* Not declared withtok(heap_allocated) either, same empirically-verified
 * reason as xstrdup() above. */
static void *xrealloc(void *p, size_t n)
{
	void *r = realloc(p, n);
	if (!r) oom();
	return r;
}

withtok(null_terminated)
static char *dupn_local(const char *s, size_t n)
{
	char *r;
	size_t bytes;
	if (!__util_size_add(n, 1, &bytes)) oom();
	r = malloc(bytes);
	if (!r) oom();
	for (size_t i = 0; i < n; i++) r[i] = s[i];
	r[n] = 0;
	__ownership_string_terminated(r); /* r[n]=0 just above, by hand */
	return r;
}

/* Forward declarations for the handful of mutually-recursive pieces
 * that would otherwise force an unnatural file order: exec_stmt() is
 * reached from call_user_func() (a builtin-call helper defined well
 * before exec_stmt() itself), and v_num_p() is a small convenience
 * used inside call_builtin() before its own later definition. (struct
 * awk_value is this translation unit's own transient-value type,
 * defined below -- an opaque forward declaration is all a pointer
 * parameter here needs.) */
struct awk_value;
static enum awk_sig exec_stmt(struct awk_interp *ip, struct awk_node *n, struct awk_value *retval);
static double v_num_p(struct awk_interp *ip, struct awk_node *n);

/* ==== numeric-string classification, XCU awk(1p)'s own term ============= */

static int looks_numeric(const char *s)
{
	const char *p = s, *q, *end;
	while (*p == ' ' || *p == '\t' || *p == '\n') p++;
	if (!*p) return 0;
	q = p;
	if (*q == '+' || *q == '-') q++;
	/* Reject strtod()'s C99 "nan"/"inf"/"infinity" spellings: a field
	 * that literally contains that text is not what XCU awk(1p) means
	 * by a numeric string. */
	if (!((*q >= '0' && *q <= '9') || (*q == '.' && q[1] >= '0' && q[1] <= '9')))
		return 0;
	end = p;
	(void)strtod(p, (char **)&end);
	if (end == p) return 0;
	while (*end == ' ' || *end == '\t' || *end == '\n') end++;
	return *end == 0;
}

/* Number -> string, per CONVFMT/OFMT's own rule: an integral value
 * (finite, exactly representable, in a plain-decimal-worth range)
 * always converts as a plain integer regardless of fmt; anything else
 * uses fmt (a printf %-conversion, typically "%.6g"). */
withtok(null_terminated)
static char *num_to_str_fmt(double n, const char *fmt)
{
	char buf[512];
	int is_int = 0;

	if (isfinite(n) && n > -1e18 && n < 1e18) {
		long long ll = (long long)n;
		is_int = ((double)ll == n);
		if (is_int) {
			snprintf(buf, sizeof buf, "%lld", ll);
			/* snprintf() guarantees NUL-termination within a nonzero
			 * buffer size (C11 7.21.6.5p2), not visible through this
			 * opaque variadic call. */
			__ownership_string_terminated(buf);
			return xstrdup(buf);
		}
	}
	if (snprintf(buf, sizeof buf, fmt, n) < 0) buf[0] = 0; /* explicit NUL on the one error path */
	__ownership_string_terminated(buf); /* same C11 guarantee as above on the success path */
	return xstrdup(buf);
}

/* ==== transient evaluation value ========================================= */

struct awk_value {
	double num;
	/* NUL-terminated whenever non-NULL, same deliberate omission of
	 * heap_allocated as struct awk_cell.str (awk_priv.h): do_getline()
	 * moves a getdelim()-sourced buffer straight into this field, and
	 * getdelim()'s own declaration grants no dynamic_storage family. */
	char *str withtok(null_terminated);   /* owned iff strcached */
	unsigned char kind;
	unsigned char numcached, strcached;
};

static void v_num_init(struct awk_value *v, double n) { v->num = n; v->str = NULL; v->kind = VK_NUM; v->numcached = 1; v->strcached = 0; }
/* Takes ownership of s, always NUL-terminated (a literal, an xstrdup()/
 * dupn_local() result, or another already-terminated buffer); asserted
 * once here rather than at each call site. */
static void v_str_init(struct awk_value *v, char *s, unsigned char kind)
{
	__ownership_string_terminated(s);
	v->num = 0; v->str = s; v->kind = kind; v->numcached = 0; v->strcached = 1;
}
static void v_uninit_init(struct awk_value *v) { v->num = 0; v->str = NULL; v->kind = VK_UNINIT; v->numcached = 1; v->strcached = 0; }
static void v_free(struct awk_value *v) { free(v->str); v->str = NULL; }

static double v_num(struct awk_value *v)
{
	if (!v->numcached) {
		v->num = v->str ? strtod(v->str, NULL) : 0.0;
		v->numcached = 1;
	}
	return v->num;
}

withtok(null_terminated)
static const char *v_str(struct awk_value *v, const char *fmt)
{
	const char *result;
	if (!v->strcached) {
		v->str = (v->kind == VK_UNINIT) ? xstrdup("") : num_to_str_fmt(v->num, fmt);
		v->strcached = 1;
	}
	result = v->str;
	/* Re-asserted here: v->str's capability doesn't reliably survive the
	 * intervening strcached=1 sibling-field write, across this
	 * checker's path-sensitive tracking. */
	__ownership_string_terminated(result);
	return result;
}

static int v_numeric_ctx(struct awk_value *v) { return v->kind != VK_STR; }

/* print's own number->string conversion uses OFMT rather than CONVFMT
 * (XCU awk(1p)); caches into v->str exactly like v_str() does (so it
 * is freed the same way, by the caller's later v_free()) rather than
 * returning a separately-allocated string the caller would have to
 * remember to free on its own. */
withtok(null_terminated)
static const char *output_str(const char *ofmt, struct awk_value *v)
{
	const char *result;
	if (v->kind == VK_NUM && !v->strcached) {
		v->str = num_to_str_fmt(v->num, ofmt);
		v->strcached = 1;
	}
	result = v_str(v, ofmt);
	__ownership_string_terminated(result); /* v_str()'s own declared contract, re-asserted on a fresh local copy right before the return */
	return result;
}
static int v_truth(struct awk_value *v)
{
	/* "A string value shall be considered ... true if ... non-null...
	 * A numeric value ... true if ... non-zero." A numeric string (a
	 * field etc. that looks numeric) is judged numerically, matching
	 * every other numeric-string rule in this file. */
	if (v->kind == VK_STR) return v_str(v, "%.6g")[0] != 0;
	return v_num(v) != 0.0;
}

/* ==== global interpreter singleton needed by CONVFMT/OFMT lookups ======= */
/* awk_run.c's functions are all interpreter-method style, taking `ip`
 * explicitly; CONVFMT/OFMT are looked up through it, not a global. */

static struct awk_cell *lookup_cell(struct awk_interp *ip, const char *name);
withtok(null_terminated)
static const char *cell_str(struct awk_interp *ip, struct awk_cell *c);

withtok(null_terminated)
static const char *convfmt_str(struct awk_interp *ip)
{
	struct awk_cell *c = lookup_cell(ip, "CONVFMT");
	/* Only recurse into the general (CONVFMT-using) formatter when c
	 * is not itself the thing that formatter would need CONVFMT for --
	 * i.e. only when c's string form is already authoritative. This
	 * sidesteps infinite recursion in the (contrived) case of a script
	 * assigning CONVFMT a bare number. */
	if ((c->kind == VK_STR || c->kind == VK_STRNUM) && c->strcached) {
		__ownership_string_terminated(c->str); /* see cell_str()'s own comment on why this is re-asserted right at the read */
		return c->str;
	}
	return "%.6g";
}

withtok(null_terminated)
static const char *ofmt_str(struct awk_interp *ip)
{
	struct awk_cell *c = lookup_cell(ip, "OFMT");
	if ((c->kind == VK_STR || c->kind == VK_STRNUM) && c->strcached) {
		__ownership_string_terminated(c->str); /* see cell_str()'s own comment on why this is re-asserted right at the read */
		return c->str;
	}
	return "%.6g";
}

/* ==== cells =============================================================== */

/* Not declared withtok(heap_allocated): its result is stored into a
 * generic void* hash-table slot or a local cells[] array, neither a
 * typed destination this file can attach a contract to -- same
 * empirically-verified reason as xstrdup()'s own comment above. */
static struct awk_cell *new_cell(void)
{
	struct awk_cell *c = calloc(1, sizeof *c);
	if (!c) oom();
	c->kind = VK_UNINIT;
	c->numcached = 1;
	return c;
}

static void free_cell_scalar_storage(struct awk_cell *c)
{
	free(c->str);
	c->str = NULL;
	c->strcached = 0;
}

static void free_cell_val(void *p);

static void free_cell_contents(struct awk_cell *c)
{
	if (c->is_array) {
		awk_htab_free(c->arr, free_cell_val);
		free(c->arr);
		c->arr = NULL;
		c->is_array = 0;
	} else {
		free_cell_scalar_storage(c);
	}
	c->kind = VK_UNINIT;
	c->numcached = 1;
	c->num = 0;
}

static void free_cell_val(void *p)
{
	struct awk_cell *c = p;
	free_cell_contents(c);
	free(c);
}

withtok(null_terminated)
static const char *cell_str(struct awk_interp *ip, struct awk_cell *c)
{
	const char *result;
	if (!c->strcached) {
		c->str = (c->kind == VK_UNINIT) ? xstrdup("") : num_to_str_fmt(c->num, convfmt_str(ip));
		c->strcached = 1;
	}
	result = c->str;
	/* Re-asserted here: same path-sensitivity limitation as v_str()'s
	 * identical comment above. */
	__ownership_string_terminated(result);
	return result;
}

static double cell_num(struct awk_cell *c)
{
	if (!c->numcached) {
		c->num = c->str ? strtod(c->str, NULL) : 0.0;
		c->numcached = 1;
	}
	return c->num;
}

static struct awk_value cell_to_value(struct awk_interp *ip, struct awk_cell *c)
{
	struct awk_value v;
	v.kind = c->kind;
	v.num = c->num;
	v.numcached = c->numcached;
	v.strcached = c->strcached;
	if (c->strcached) {
		const char *cs = cell_str(ip, c);
		__ownership_string_terminated(cs); /* cell_str()'s own declared contract, re-asserted right at this use */
		v.str = xstrdup(cs);
	} else {
		v.str = NULL;
	}
	if (!v.numcached) { (void)cell_num(c); v.num = c->num; v.numcached = 1; } /* cheap to just resolve now too */
	return v;
}

/* Moves *v's string ownership into c; caller must not use *v again
 * except to let it go out of scope (v->str is nulled). */
static void assign_value_to_cell(struct awk_cell *c, struct awk_value *v)
{
	free_cell_scalar_storage(c);
	c->kind = v->kind;
	c->num = v->num;
	c->numcached = v->numcached;
	c->strcached = v->strcached;
	{
		char *moved = v->str;
		__ownership_string_terminated(moved); /* re-asserted on a fresh local copy right at the move (harmless when NULL); see cell_str()'s own comment on why this checker needs it re-established this close to the use */
		c->str = moved;
	}
	v->str = NULL;
}

static void promote_to_array(struct awk_cell *c)
{
	if (c->is_array) return;
	if (c->kind != VK_UNINIT) fatal("can't use a scalar value as an array");
	c->is_array = 1;
	c->arr = malloc(sizeof *c->arr);
	if (!c->arr) oom();
	awk_htab_init(c->arr);
}

/* Returns the cell stored under key in t, creating a fresh VK_UNINIT
 * one first if key was absent -- the "look it up, and if that's not
 * there make it" step both array_elem() (an array's own element table)
 * and lookup_cell() below (the globals table) need identically. */
static struct awk_cell *htab_get_or_create_cell(struct awk_htab *t, const char *key)
{
	void **slot = awk_htab_getp(t, key);
	if (!slot) oom();
	if (!*slot) *slot = new_cell();
	return *slot;
}

static struct awk_cell *array_elem(struct awk_cell *arrcell, const char *key)
{
	return htab_get_or_create_cell(arrcell->arr, key);
}

/* ==== variable resolution ================================================= */

/* name always traces back to a string literal or a parser-owned
 * awk_node identifier, both NUL-terminated; asserted once here rather
 * than on struct awk_node's own shared field. */
static struct awk_cell *lookup_cell(struct awk_interp *ip, const char *name)
{
	__ownership_string_terminated(name);
	if (ip->frame) {
		int i;
		for (i = 0; i < ip->frame->nparams; i++) {
			__ownership_string_terminated(ip->frame->names[i]);
			if (!strcmp(ip->frame->names[i], name)) return ip->frame->cells[i];
		}
	}
	return htab_get_or_create_cell(&ip->globals, name);
}

static void set_global_str(struct awk_interp *ip, const char *name, const char *val)
{
	struct awk_cell *c = lookup_cell(ip, name);
	struct awk_value v;
	__ownership_string_terminated(val); /* every caller passes a literal or an already-NUL-terminated cell/field string */
	v_str_init(&v, xstrdup(val), VK_STR);
	assign_value_to_cell(c, &v);
	v_free(&v);
}

static void set_global_num(struct awk_interp *ip, const char *name, double n)
{
	struct awk_cell *c = lookup_cell(ip, name);
	struct awk_value v;
	v_num_init(&v, n);
	assign_value_to_cell(c, &v);
	v_free(&v);
}

/* ==== SUBSEP-joined subscript keys ======================================== */

static struct awk_value eval(struct awk_interp *ip, struct awk_node *n);

static char *build_subsep_key(struct awk_interp *ip, struct awk_node **subs, int n)
{
	char *key = NULL;
	size_t len = 0;
	int i;
	const char *subsep_cell_str = cell_str(ip, lookup_cell(ip, "SUBSEP"));
	char *subsep;
	size_t subsep_len;
	__ownership_string_terminated(subsep_cell_str); /* cell_str()'s own declared contract, re-asserted right at this use -- see cell_str()'s own comment */
	subsep = xstrdup(subsep_cell_str);
	__ownership_string_terminated(subsep); /* xstrdup()'s own declared contract, re-asserted right at this use */
	subsep_len = strlen(subsep);

	for (i = 0; i < n; i++) {
		struct awk_value v = eval(ip, subs[i]);
		const char *s = v_str(&v, convfmt_str(ip));
		size_t slen;
		__ownership_string_terminated(s); /* v_str()'s own declared contract, re-asserted right at this use */
		slen = strlen(s);
		size_t addlen = slen + (i ? subsep_len : 0);
		key = xrealloc(key, len + addlen + 1);
		if (i) {
			for (size_t j = 0; j < subsep_len; j++) key[len + j] = subsep[j];
			len += subsep_len;
		}
		for (size_t j = 0; j < slen; j++) key[len + j] = s[j];
		len += slen;
		v_free(&v);
	}
	if (!key) key = xstrdup("");
	key[len] = 0;
	free(subsep);
	return key;
}

/* ==== comparisons ========================================================= */

static int compare_values(struct awk_value *a, struct awk_value *b, const char *fmt)
{
	if (v_numeric_ctx(a) && v_numeric_ctx(b)) {
		double x = v_num(a), y = v_num(b);
		if (x < y) return -1;
		if (x > y) return 1;
		return 0;
	}
	return strcmp(v_str(a, fmt), v_str(b, fmt));
}

/* ==== fields / $0 ========================================================= */

static void free_fields(struct awk_interp *ip)
{
	int i;
	for (i = 0; i < ip->nf; i++) free(ip->flds[i]);
	ip->nf = 0;
}

static void fields_reserve(struct awk_interp *ip, int n)
{
	if (n <= ip->fcap) return;
	{
		size_t newcap = ip->fcap ? (size_t)ip->fcap : 16;
		if (ip->fcap && !__util_size_mul((size_t)ip->fcap, 2, &newcap)) oom();
		while (newcap < (size_t)n) {
			if (!__util_size_mul(newcap, 2, &newcap)) oom();
		}
		ip->flds = xrealloc(ip->flds, newcap * sizeof *ip->flds);
		ip->fcap = (int)newcap;
	}
}

/* Splits `s` (length len) per `fs`'s XCU-defined field-splitting rules
 * (used for both $0's own splitting and split()'s built-in), appending
 * results as owned strings into *outv and *outn (grown with xrealloc).
 * extra_nl_sep additionally treats '\n' as a separator even when fs is
 * not the default whitespace form -- RS=="" paragraph mode's own rule
 * ("the <newline> character shall always be a field separator, no
 * matter what field-splitting value is used") -- for the single-
 * character-FS case; see this file's header/src/util/awk.c's header
 * for this being narrowed to not extend the same union into a
 * multi-character (ERE) FS in paragraph mode, a rare combination. */
static void split_into(const char *s, size_t len, const char *fs, int extra_nl_sep, char ***outv, int *outn)
{
	char **out = NULL;
	int n = 0;

	if (fs[0] == ' ' && fs[1] == 0) {
		size_t i = 0;
		while (i < len) {
			while (i < len && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n')) i++;
			if (i >= len) break;
			{
				size_t start = i;
				while (i < len && !(s[i] == ' ' || s[i] == '\t' || s[i] == '\n')) i++;
				out = xrealloc(out, (size_t)(n + 1) * sizeof *out);
				out[n++] = dupn_local(s + start, i - start);
			}
		}
	} else if (fs[0] == 0) {
		/* Empty FS: not defined by XCU awk(1p) (see src/util/awk.c's
		 * header) -- the whole string is field 1 (as if no separator
		 * ever occurred), rather than splitting into characters. */
		if (len) {
			out = xrealloc(out, sizeof *out);
			out[0] = dupn_local(s, len);
			n = 1;
		}
	} else if (fs[1] == 0 && !extra_nl_sep) {
		char sep = fs[0];
		size_t start = 0, i;
		for (i = 0; i <= len; i++) {
			if (i == len || s[i] == sep) {
				out = xrealloc(out, (size_t)(n + 1) * sizeof *out);
				out[n++] = dupn_local(s + start, i - start);
				start = i + 1;
			}
		}
	} else if (fs[1] == 0 && extra_nl_sep) {
		char sep = fs[0];
		size_t start = 0, i;
		for (i = 0; i <= len; i++) {
			if (i == len || s[i] == sep || s[i] == '\n') {
				out = xrealloc(out, (size_t)(n + 1) * sizeof *out);
				out[n++] = dupn_local(s + start, i - start);
				start = i + 1;
			}
		}
	} else {
		/* FS is an ERE (2+ characters). */
		regex_t re;
		if (regcomp(&re, fs, REG_EXTENDED) != 0) {
			out = xrealloc(out, sizeof *out);
			out[0] = dupn_local(s, len);
			n = 1;
		} else {
			size_t start = 0, pos = 0;
			char *tmp = dupn_local(s, len);
			while (pos <= len) {
				regmatch_t m;
				int eflags = pos ? REG_NOTBOL : 0;
				if (pos == len || regexec(&re, tmp + pos, 1, &m, eflags) != 0 || (size_t)m.rm_so + pos >= len) break;
				if (m.rm_so == m.rm_eo) { pos++; continue; } /* avoid a zero-width infinite loop */
				out = xrealloc(out, (size_t)(n + 1) * sizeof *out);
				out[n++] = dupn_local(s + start, (pos + (size_t)m.rm_so) - start);
				pos = start = pos + (size_t)m.rm_eo;
			}
			out = xrealloc(out, (size_t)(n + 1) * sizeof *out);
			out[n++] = dupn_local(s + start, len - start);
			free(tmp);
			regfree(&re);
		}
	}
	*outv = out;
	*outn = n;
}

static void split_record(struct awk_interp *ip)
{
	const char *fs = cell_str(ip, lookup_cell(ip, "FS"));
	const char *rs = cell_str(ip, lookup_cell(ip, "RS"));
	char **out;
	int n, i;

	free_fields(ip);
	__ownership_string_terminated(ip->rec); /* re-asserted right at the read; see cell_str()'s own comment on why this checker needs it re-established this close to the use */
	split_into(ip->rec, strlen(ip->rec), fs, rs[0] == 0, &out, &n);
	fields_reserve(ip, n);
	for (i = 0; i < n; i++) ip->flds[i] = out[i];
	free(out);
	ip->nf = n;
	set_global_num(ip, "NF", ip->nf);
}

static void rebuild_record(struct awk_interp *ip)
{
	const char *ofs = cell_str(ip, lookup_cell(ip, "OFS"));
	size_t ofslen;
	size_t len = 0, bytes;
	int i;
	char *rec;

	__ownership_string_terminated(ofs); /* cell_str()'s own declared contract, re-asserted right at this use */
	ofslen = strlen(ofs);
	for (i = 0; i < ip->nf; i++) {
		__ownership_string_terminated(ip->flds[i]); /* ip->flds's own comment (awk_priv.h), re-asserted right at this use */
		len += strlen(ip->flds[i]) + (i ? ofslen : 0);
	}
	if (!__util_size_add(len, 1, &bytes)) oom();
	rec = malloc(bytes);
	if (!rec) oom();
	len = 0;
	for (i = 0; i < ip->nf; i++) {
		size_t flen;
		const char *field = ip->flds[i];
		if (i) {
			for (size_t j = 0; j < ofslen; j++) rec[len + j] = ofs[j];
			len += ofslen;
		}
		__ownership_string_terminated(field); /* ip->flds's own comment, re-asserted right at this use */
		flen = strlen(field);
		for (size_t j = 0; j < flen; j++) rec[len + j] = field[j];
		len += flen;
	}
	rec[len] = 0;
	__ownership_string_terminated(rec); /* rec[len]=0 just above, by hand */
	free(ip->rec);
	ip->rec = rec;
}

/* Takes ownership of `rec`. Every caller passes either an xstrdup()
 * result or a getdelim()-sourced record buffer (read_delim_record()/
 * read_paragraph_record(), both of which manually NUL-terminate their
 * own result) -- established once here rather than at each call site. */
static void set_record(struct awk_interp *ip, char *rec)
{
	__ownership_string_terminated(rec);
	free(ip->rec);
	ip->rec = rec;
	split_record(ip);
}

static struct awk_value get_field(struct awk_interp *ip, long idx)
{
	struct awk_value v;
	const char *s;
	if (idx == 0) s = ip->rec ? ip->rec : "";
	else if (idx >= 1 && idx <= ip->nf) s = ip->flds[idx - 1];
	else s = "";
	__ownership_string_terminated(s); /* ip->rec/ip->flds[]'s own comments (awk_priv.h), re-asserted right at this use */
	v_str_init(&v, xstrdup(s), looks_numeric(s) ? VK_STRNUM : VK_STR);
	return v;
}

static void set_field(struct awk_interp *ip, long idx, struct awk_value *val)
{
	const char *s = v_str(val, convfmt_str(ip));
	__ownership_string_terminated(s); /* v_str()'s own declared contract, re-asserted right at this use */
	if (idx == 0) {
		set_record(ip, xstrdup(s));
		return;
	}
	if (idx < 1) return; /* $(-1)="x": no defined effect; ignored rather than corrupting storage */
	/* See AWK_MAX_FIELD's own comment above: refused cleanly here,
	 * BEFORE idx is ever truncated to (int) below, so the fields_
	 * reserve() allocation size and the loop bound that walks it are
	 * guaranteed to agree -- see this file's header comment ("DOUBLE ->
	 * INTEGER CONVERSIONS") for the out-of-bounds write this closes. */
	if (idx > AWK_MAX_FIELD) fatal("field index too large");
	if (idx > ip->nf) {
		/* Fields between the old NF and this new one are filled with
		 * "" (fully initialized, up to but NOT including idx-1's own
		 * slot -- that one is about to be set unconditionally below,
		 * and must NOT be free()d first: it was never allocated, so
		 * freeing it here would free a garbage pointer out of freshly
		 * grown, uninitialized storage). */
		int i;
		fields_reserve(ip, (int)idx);
		for (i = ip->nf; i < idx - 1; i++) ip->flds[i] = xstrdup("");
		ip->nf = (int)idx;
		set_global_num(ip, "NF", ip->nf);
	} else {
		free(ip->flds[idx - 1]);
	}
	__ownership_string_terminated(s); /* v_str()'s own declared contract, re-asserted right at this (second) use */
	ip->flds[idx - 1] = xstrdup(s);
	rebuild_record(ip);
}

/* NF assigned directly: truncate or pad the field array to match,
 * then rebuild $0 -- XCU awk(1p): "the setting of NF ... shall cause
 * the record to be recompiled". */
static void set_nf(struct awk_interp *ip, long newnf)
{
	int i;
	if (newnf < 0) newnf = 0;
	if (newnf > AWK_MAX_FIELD) fatal("NF assignment too large"); /* see AWK_MAX_FIELD's own comment */
	if (newnf < ip->nf) {
		for (i = (int)newnf; i < ip->nf; i++) { free(ip->flds[i]); ip->flds[i] = NULL; }
		ip->nf = (int)newnf;
	} else if (newnf > ip->nf) {
		fields_reserve(ip, (int)newnf);
		for (i = ip->nf; i < newnf; i++) ip->flds[i] = xstrdup("");
		ip->nf = (int)newnf;
	}
	rebuild_record(ip);
}

/* ==== dynamic-regex resolution ============================================ */

static regex_t *resolve_ere(struct awk_interp *ip, struct awk_node *node)
{
	if (node->type == N_REGEX) return node->re;
	{
		struct awk_value v = eval(ip, node);
		const char *pat = v_str(&v, convfmt_str(ip));
		void **slot = awk_htab_getp(&ip->recmp, pat);
		regex_t *re;
		if (!slot) oom();
		if (*slot) { v_free(&v); return *slot; }
		re = malloc(sizeof *re);
		if (!re) oom();
		if (regcomp(re, pat, REG_EXTENDED) != 0) {
			free(re);
			__util_diagf("awk: invalid dynamic regular expression: %s\n", pat);
			v_free(&v);
			awk_unwind_fatal();
		}
		*slot = re;
		v_free(&v);
		return re;
	}
}

/* ==== output/input stream table (redirection + getline + close) ========= */

static void free_stream_val(void *p)
{
	struct awk_stream *st = p;
	if (st->is_pipe) (void)pclose(st->f); else (void)fclose(st->f);
	free(st);
}

static FILE *get_output_stream(struct awk_interp *ip, const char *target withtok(null_terminated), enum awk_redir redir)
{
	void **slot = awk_htab_getp(&ip->streams, target);
	struct awk_stream *st;
	if (!slot) oom();
	if (*slot) return ((struct awk_stream *)*slot)->f;
	st = malloc(sizeof *st);
	if (!st) oom();
	st->is_input = 0;
	if (redir == RD_PIPE) {
		st->is_pipe = 1;
		st->f = popen(target, "w");
	} else {
		st->is_pipe = 0;
		/* Split into two bare-literal fopen() calls rather than one with
		 * a `redir == RD_APPEND ? "a" : "w"` ternary: the checker's
		 * string-literal recognition doesn't look through a
		 * ConditionalOperator to either arm. */
		if (redir == RD_APPEND) st->f = fopen(target, "a");
		else st->f = fopen(target, "w");
	}
	if (!st->f) { free(st); *slot = NULL; awk_htab_del(&ip->streams, target, NULL); return NULL; }
	*slot = st;
	return st->f;
}

static FILE *get_input_stream(struct awk_interp *ip, const char *target withtok(null_terminated), int is_pipe)
{
	void **slot = awk_htab_getp(&ip->streams, target);
	struct awk_stream *st;
	if (!slot) oom();
	if (*slot) return ((struct awk_stream *)*slot)->f;
	st = malloc(sizeof *st);
	if (!st) oom();
	st->is_input = 1;
	st->is_pipe = is_pipe;
	if (is_pipe) st->f = popen(target, "r");
	else st->f = !strcmp(target, "-") ? stdin : fopen(target, "r");
	if (!st->f) { free(st); awk_htab_del(&ip->streams, target, NULL); return NULL; }
	*slot = st;
	return st->f;
}

static void flush_all_streams(struct awk_interp *ip)
{
	struct awk_hiter it;
	struct awk_hnode *n;
	if (fflush(stdout) != 0) {
		__util_diagf("awk: write error\n");
		ip->exit_status = 2;
	}
	awk_hiter_init(&it, &ip->streams);
	while ((n = awk_hiter_next(&it))) {
		struct awk_stream *st = n->val;
		if (!st->is_input && fflush(st->f) != 0) {
			__util_diagf("awk: write error\n");
			ip->exit_status = 2;
		}
	}
}

/* ==== record reading (main input, and getline's <file/|cmd/plain forms) = */

static char *read_delim_record(FILE *f, char sep, int *got)
{
	char *buf = NULL;
	size_t cap = 0;
	ssize_t n = getdelim(&buf, &cap, (unsigned char)sep, f);
	if (n < 0) { free(buf); *got = 0; return NULL; }
	if (n > 0 && buf[n - 1] == sep) buf[n - 1] = 0;
	*got = 1;
	return buf;
}

static char *read_paragraph_record(FILE *f, int *got)
{
	char *rec = NULL;
	size_t reclen = 0;
	int have_any = 0;

	for (;;) {
		char *buf = NULL;
		size_t cap = 0;
		ssize_t n = getdelim(&buf, &cap, '\n', f);
		size_t linelen;
		if (n < 0) { free(buf); break; }
		linelen = (size_t)n;
		if (linelen > 0 && buf[linelen - 1] == '\n') linelen--;
		if (linelen == 0) {
			free(buf);
			if (!have_any) continue; /* leading blank line: skip */
			break; /* blank line ends the paragraph */
		}
		rec = xrealloc(rec, reclen + (have_any ? 1 : 0) + linelen + 1);
		if (have_any) rec[reclen++] = '\n';
		for (size_t j = 0; j < linelen; j++) rec[reclen + j] = buf[j];
		reclen += linelen;
		rec[reclen] = 0;
		have_any = 1;
		free(buf);
	}
	*got = have_any;
	if (!have_any) { free(rec); return NULL; }
	return rec;
}

static char *read_record_rs(struct awk_interp *ip, FILE *f, int *got)
{
	const char *rs = cell_str(ip, lookup_cell(ip, "RS"));
	if (rs[0] == 0) return read_paragraph_record(f, got);
	return read_delim_record(f, rs[0], got);
}

static int is_awk_name_prefix(const char *s, const char *eq)
{
	const char *p = s;
	if (p == eq) return 0;
	if (!(isalpha((unsigned char)*p) || *p == '_')) return 0;
	for (p++; p < eq; p++) if (!(isalnum((unsigned char)*p) || *p == '_')) return 0;
	return 1;
}

static int advance_to_next_argv_file(struct awk_interp *ip)
{
	struct awk_cell *argv_cell = lookup_cell(ip, "ARGV");
	struct awk_cell *argc_cell = lookup_cell(ip, "ARGC");

	for (;;) {
		long argc = d2long(cell_num(argc_cell)); /* ARGC is user-assignable */
		char key[32];
		void *slot;
		const char *s;

		if (ip->argi >= argc) {
			if (!ip->any_input_used) {
				ip->curfile = stdin;
				ip->curfile_is_stdin = 1;
				ip->any_input_used = 1;
				set_global_num(ip, "FNR", 0);
				return 1;
			}
			return 0;
		}
		snprintf(key, sizeof key, "%ld", (long)ip->argi);
		ip->argi++;
		slot = argv_cell->is_array ? awk_htab_get(argv_cell->arr, key) : NULL;
		s = slot ? cell_str(ip, slot) : "";
		if (!*s) continue;
		{
			const char *eq = strchr(s, '=');
			if (eq && is_awk_name_prefix(s, eq)) {
				char *name = dupn_local(s, (size_t)(eq - s));
				awk_interp_set_str(ip, name, eq + 1);
				free(name);
				continue;
			}
		}
		ip->curfile_is_stdin = !strcmp(s, "-");
		ip->curfile = ip->curfile_is_stdin ? stdin : fopen(s, "r");
		if (!ip->curfile) {
			__util_diagf("awk: can't open file %s\n", s);
			ip->exit_status = 2;
			continue;
		}
		set_global_str(ip, "FILENAME", s);
		set_global_num(ip, "FNR", 0);
		ip->any_input_used = 1;
		return 1;
	}
}

static int read_next_main_record(struct awk_interp *ip, char **out)
{
	for (;;) {
		int got;
		char *rec;
		if (!ip->curfile && !advance_to_next_argv_file(ip)) return 0;
		rec = read_record_rs(ip, ip->curfile, &got);
		if (got) { *out = rec; return 1; }
		if (!ip->curfile_is_stdin) (void)fclose(ip->curfile);
		ip->curfile = NULL;
	}
}

/* ==== getline (all six XCU forms) ========================================= */

static struct awk_value eval_lvalue_read(struct awk_interp *ip, struct awk_node *lv);
static void assign_lvalue(struct awk_interp *ip, struct awk_node *lv, struct awk_value *val);

static double do_getline(struct awk_interp *ip, struct awk_node *node)
{
	FILE *f = NULL;
	char *rec = NULL;
	int got = 0;
	int upd_nr = 0, upd_fnr = 0, upd_rec = (node->a == NULL);

	switch (node->gl_src) {
	case GL_MAIN:
		upd_nr = upd_fnr = 1;
		if (!read_next_main_record(ip, &rec)) return 0;
		got = 1;
		break;
	case GL_FILE: {
		struct awk_value fv = eval(ip, node->b);
		const char *fname = v_str(&fv, convfmt_str(ip));
		__ownership_string_terminated(fname); /* v_str()'s own declared contract, re-asserted right at this use */
		f = get_input_stream(ip, fname, 0);
		v_free(&fv);
		if (!f) return -1;
		rec = read_record_rs(ip, f, &got);
		break;
	}
	case GL_CMD: {
		struct awk_value cv = eval(ip, node->b);
		const char *cmd = v_str(&cv, convfmt_str(ip));
		__ownership_string_terminated(cmd); /* v_str()'s own declared contract, re-asserted right at this use */
		upd_nr = 1;
		flush_all_streams(ip);
		f = get_input_stream(ip, cmd, 1);
		v_free(&cv);
		if (!f) return -1;
		rec = read_record_rs(ip, f, &got);
		break;
	}
	}
	if (!got) return 0;

	if (upd_nr) set_global_num(ip, "NR", cell_num(lookup_cell(ip, "NR")) + 1);
	if (upd_fnr) set_global_num(ip, "FNR", cell_num(lookup_cell(ip, "FNR")) + 1);

	if (upd_rec) {
		set_record(ip, rec);
	} else {
		struct awk_value v;
		v_str_init(&v, rec, looks_numeric(rec) ? VK_STRNUM : VK_STR);
		assign_lvalue(ip, node->a, &v);
		v_free(&v);
	}
	return 1;
}

/* ==== awk's own printf/sprintf formatter ================================= */

static void buf_append(char **buf, size_t *len, size_t *cap, const char *s, size_t n)
{
	/* *len + n + 1, computed raw, wraps for an adversarial n and would
	 * then wrongly compare as "already fits" against *cap -- check it
	 * the same overflow-safe way __util_mallocarray()'s callers do. */
	size_t need;
	if (!__util_size_add(*len, n, &need) || !__util_size_add(need, 1, &need))
		fatal("output too large");
	if (need > *cap) {
		size_t oldcap = *cap;
		size_t newcap = *cap ? *cap : 64;
		while (newcap < need) {
			if (!__util_size_mul(newcap, 2, &newcap)) fatal("output too large");
		}
		*buf = xrealloc(*buf, newcap);
		/* realloc() leaves the grown tail's bytes unspecified; a later
		 * buf_append() call could otherwise read that indeterminate
		 * tail past *len+n. */
		memset(*buf + oldcap, 0, newcap - oldcap);
		*cap = newcap;
	}
	{
		char *dst = *buf + *len;
		for (size_t i = 0; i < n; i++) dst[i] = s[i];
	}
	*len += n;
	(*buf)[*len] = 0;
}

/* Builds `printf`'s/`sprintf()`'s whole formatted output. Every
 * directive is resolved by synthesizing a single-conversion C format
 * string (flags/width/precision baked in as literal digits, `*`
 * resolved from args first) and calling this library's own snprintf()
 * once per directive -- the same "let the real printf() do the exact
 * float/integer work" trick src/util/util_printf.c's format_float()
 * already uses, applied here to every conversion rather than just the
 * float ones, since every argument here is already a typed
 * struct awk_value rather than printf(1p)'s raw argv text. Unlike
 * printf(1p) (src/util/util_printf.c), the format string is NOT
 * reused/cycled once arguments run out -- XCU awk(1p)'s own printf
 * consumes argument_list exactly once, left to right; a directive
 * beyond the argument list's end is treated as an exhausted argument
 * (0 or ""), never a wraparound reuse. */
withtok(null_terminated)
static char *awk_format(struct awk_interp *ip, const char *fmt, struct awk_value *args, int nargs)
{
	char *out = NULL;
	size_t len = 0, cap = 0;
	int ai = 0;
	const char *p = fmt;

	while (*p) {
		if (*p != '%') { buf_append(&out, &len, &cap, p, 1); p++; continue; }
		if (p[1] == '%') { buf_append(&out, &len, &cap, "%", 1); p += 2; continue; }
		{
			char flags[8]; int nflags = 0;
			int width = -1, prec = -1;
			char conv;
			const char *start = p;
			p++;
			while (*p == '-' || *p == '+' || *p == ' ' || *p == '0' || *p == '#') {
				if (nflags < (int)sizeof flags - 1) flags[nflags++] = *p;
				p++;
			}
			flags[nflags] = 0;
			if (*p == '*') { width = (ai < nargs) ? d2int(v_num(&args[ai++])) : 0; p++; }
			else while (isdigit((unsigned char)*p)) { width = (width < 0 ? 0 : width) * 10 + (*p++ - '0'); }
			if (*p == '.') {
				p++;
				if (*p == '*') { prec = (ai < nargs) ? d2int(v_num(&args[ai++])) : 0; p++; }
				else { prec = 0; while (isdigit((unsigned char)*p)) prec = prec * 10 + (*p++ - '0'); }
			}
			conv = *p;
			if (!conv) { buf_append(&out, &len, &cap, start, (size_t)(p - start)); break; }
			p++;
			if (conv == 'i') conv = 'd';

			/* Every conversion is resolved by synthesizing a single-
			 * directive C format string (flags/width/precision baked
			 * in as literal digits -- '*' was already resolved from
			 * args above) and calling this library's own snprintf()
			 * exactly twice: once with a NULL buffer to size the
			 * result (the portable, always-correct way to size an
			 * arbitrarily wide/precise conversion -- no fixed-size
			 * scratch buffer to overflow or silently truncate into),
			 * then once for real into an exactly-sized allocation. */
			{
				char subfmt[64];
				char wbuf[24] = "", pbuf[24] = "";
				char cbuf[2] = { 0, 0 };
				enum { AT_LL, AT_ULL, AT_DBL, AT_STR } atype = AT_STR;
				long long llv = 0;
				unsigned long long ullv = 0;
				double dv = 0;
				const char *sv = "";
				int skip = 0, need;
				struct awk_value dummy;
				struct awk_value *arg;

				if (ai < nargs) { arg = &args[ai++]; }
				else { v_uninit_init(&dummy); arg = &dummy; }
				if (width >= 0) snprintf(wbuf, sizeof wbuf, "%d", width);
				if (prec >= 0) snprintf(pbuf, sizeof pbuf, ".%d", prec);

				switch (conv) {
				case 'd':
					atype = AT_LL; llv = d2ll(v_num(arg));
					snprintf(subfmt, sizeof subfmt, "%%%s%s%sll%c", flags, wbuf, pbuf, conv);
					break;
				case 'o': case 'u': case 'x': case 'X':
					atype = AT_ULL; ullv = (unsigned long long)d2ll(v_num(arg));
					snprintf(subfmt, sizeof subfmt, "%%%s%s%sll%c", flags, wbuf, pbuf, conv);
					break;
				case 'e': case 'E': case 'f': case 'F': case 'g': case 'G':
					atype = AT_DBL; dv = v_num(arg);
					snprintf(subfmt, sizeof subfmt, "%%%s%s%s%c", flags, wbuf, pbuf, conv);
					break;
				case 'c':
					if (v_numeric_ctx(arg)) cbuf[0] = (char)d2long(v_num(arg));
					else { const char *s = v_str(arg, convfmt_str(ip)); cbuf[0] = s[0]; }
					if (!cbuf[0]) { skip = 1; break; }
					atype = AT_STR; sv = cbuf;
					snprintf(subfmt, sizeof subfmt, "%%%s%ss", flags, wbuf);
					break;
				case 's':
					atype = AT_STR; sv = v_str(arg, convfmt_str(ip));
					snprintf(subfmt, sizeof subfmt, "%%%s%s%ss", flags, wbuf, pbuf);
					break;
				default:
					/* Unrecognized conversion: leave the directive's own
					 * source text visible rather than silently dropping
					 * it or guessing -- same "don't paper over" choice
					 * src/util/util_printf.c makes for printf(1p). */
					buf_append(&out, &len, &cap, start, (size_t)(p - start));
					skip = 1;
					break;
				}
				/* dummy must be freed AFTER sv's last use below, not
				 * before: for an exhausted-argument %s/%c conversion,
				 * sv points straight into dummy.str. */
				if (!skip) {
					switch (atype) {
					case AT_LL: need = snprintf(NULL, 0, subfmt, llv); break;
					case AT_ULL: need = snprintf(NULL, 0, subfmt, ullv); break;
					case AT_DBL: need = snprintf(NULL, 0, subfmt, dv); break;
					default: need = snprintf(NULL, 0, subfmt, sv); break;
					}
					if (need > 0) {
						char *buf = xrealloc(NULL, (size_t)need + 1);
						switch (atype) {
						case AT_LL: snprintf(buf, (size_t)need + 1, subfmt, llv); break;
						case AT_ULL: snprintf(buf, (size_t)need + 1, subfmt, ullv); break;
						case AT_DBL: snprintf(buf, (size_t)need + 1, subfmt, dv); break;
						default: snprintf(buf, (size_t)need + 1, subfmt, sv); break;
						}
						buf_append(&out, &len, &cap, buf, (size_t)need);
						free(buf);
					}
				}
				if (arg == &dummy) v_free(&dummy);
			}
		}
	}
	if (!out) out = xstrdup("");
	__ownership_string_terminated(out); /* buf_append() always maintains a trailing NUL, see its own comment */
	return out;
}

/* ==== built-in and user function calls ==================================== */

static struct awk_value call_user_func(struct awk_interp *ip, struct awk_func *fn, struct awk_node **argnodes, int nargs);
static struct awk_value call_builtin(struct awk_interp *ip, struct awk_node *call);

/* ==== sub/gsub replacement-text expansion (& and \& per XCU) ============= */

withtok(null_terminated)
static char *expand_replacement(const char *repl, const char *matched, size_t mlen)
{
	char *out = NULL;
	size_t len = 0, cap = 0;
	const char *p = repl;
	while (*p) {
		if (*p == '\\' && (p[1] == '&' || p[1] == '\\')) {
			char c = p[1];
			buf_append(&out, &len, &cap, &c, 1);
			p += 2;
		} else if (*p == '&') {
			buf_append(&out, &len, &cap, matched, mlen);
			p++;
		} else {
			buf_append(&out, &len, &cap, p, 1);
			p++;
		}
	}
	if (!out) out = xstrdup("");
	__ownership_string_terminated(out); /* buf_append() always maintains a trailing NUL, see its own comment */
	return out;
}

/* Runs one (sub) or every (gsub) non-overlapping match of `re` in
 * `text`, replacing each with `repl`'s &/\&-expansion. Returns the
 * count of substitutions and, via *outp, the resulting owned string
 * (always set, even for zero substitutions -- a copy of `text`). */
static int do_sub(regex_t *re, const char *text withtok(null_terminated), const char *repl, int global, char **outp)
{
	char *out = NULL;
	size_t len = 0, cap = 0;
	size_t pos = 0, tlen = strlen(text);
	int count = 0;

	for (;;) {
		regmatch_t m;
		int eflags = pos ? REG_NOTBOL : 0;
		if (regexec(re, text + pos, 1, &m, eflags) != 0) break;
		buf_append(&out, &len, &cap, text + pos, (size_t)m.rm_so);
		{
			char *r = expand_replacement(repl, text + pos + m.rm_so, (size_t)(m.rm_eo - m.rm_so));
			__ownership_string_terminated(r); /* expand_replacement()'s own declared contract, re-asserted right at this use */
			buf_append(&out, &len, &cap, r, strlen(r));
			free(r);
		}
		count++;
		if (m.rm_so == m.rm_eo) {
			/* Zero-width match: emit one byte verbatim and advance, or
			 * we would loop forever re-matching the same empty spot. */
			if (pos + (size_t)m.rm_eo < tlen) buf_append(&out, &len, &cap, text + pos + m.rm_eo, 1);
			pos += (size_t)m.rm_eo + 1;
		} else {
			pos += (size_t)m.rm_eo;
		}
		if (!global || pos > tlen) break;
	}
	if (pos <= tlen) buf_append(&out, &len, &cap, text + pos, tlen - pos);
	if (!out) out = xstrdup("");
	__ownership_string_terminated(out); /* buf_append() always maintains a trailing NUL, see its own comment */
	*outp = out;
	return count;
}

/* ==== printf/print's shared argument-evaluation + redirection ============ */

static FILE *resolve_redir_stream(struct awk_interp *ip, struct awk_node *n)
{
	if (n->redir == RD_NONE) return stdout;
	{
		struct awk_value v = eval(ip, n->a);
		const char *target = v_str(&v, convfmt_str(ip));
		FILE *f;
		__ownership_string_terminated(target); /* v_str()'s own declared contract, re-asserted right at this use */
		f = get_output_stream(ip, target, n->redir);
		if (!f) { __util_diagf("awk: can't open output %s\n", target); v_free(&v); awk_unwind_fatal(); }
		v_free(&v);
		return f;
	}
}

/* ==== main expression evaluator =========================================== */

static struct awk_value do_incrdecr(struct awk_interp *ip, struct awk_node *n, int delta, int is_pre)
{
	struct awk_value cur = eval_lvalue_read(ip, n->a);
	double oldnum = v_num(&cur);
	struct awk_value nv;
	v_free(&cur);
	v_num_init(&nv, oldnum + delta);
	{
		struct awk_value store = nv; /* assign_lvalue moves; keep a readable copy for pre/post result */
		struct awk_value result;
		if (is_pre) { v_num_init(&result, oldnum + delta); }
		else { v_num_init(&result, oldnum); }
		assign_lvalue(ip, n->a, &store);
		return result;
	}
}

/* Resolves an N_ARRIDX node to its backing cell: promotes the base
 * variable to an array on first use, then looks up (creating if
 * absent) the SUBSEP-joined subscript's own element cell -- the shared
 * first half of both eval_lvalue_read()'s and assign_lvalue()'s own
 * N_ARRIDX cases below. */
static struct awk_cell *resolve_arridx_cell(struct awk_interp *ip, struct awk_node *lv)
{
	struct awk_cell *c = lookup_cell(ip, lv->str);
	char *key;
	struct awk_cell *e;
	promote_to_array(c);
	key = build_subsep_key(ip, lv->list, lv->nlist);
	e = array_elem(c, key);
	free(key);
	return e;
}

static struct awk_value eval_lvalue_read(struct awk_interp *ip, struct awk_node *lv)
{
	switch (lv->type) {
	case N_VAR: {
		struct awk_cell *c = lookup_cell(ip, lv->str);
		if (c->is_array) fatal("can't read an array as a scalar");
		return cell_to_value(ip, c);
	}
	case N_FIELD: {
		struct awk_value idxv = eval(ip, lv->a);
		long idx = d2long(v_num(&idxv));
		v_free(&idxv);
		return get_field(ip, idx);
	}
	case N_ARRIDX:
		return cell_to_value(ip, resolve_arridx_cell(ip, lv));
	default: {
		struct awk_value v; v_uninit_init(&v); return v;
	}
	}
}

static void assign_lvalue(struct awk_interp *ip, struct awk_node *lv, struct awk_value *val)
{
	switch (lv->type) {
	case N_VAR: {
		struct awk_cell *c = lookup_cell(ip, lv->str);
		assign_value_to_cell(c, val);
		__ownership_string_terminated(lv->str); /* same reasoning as lookup_cell()'s own comment above */
		if (!strcmp(lv->str, "NF")) set_nf(ip, d2long(cell_num(c)));
		return;
	}
	case N_FIELD: {
		struct awk_value idxv = eval(ip, lv->a);
		long idx = d2long(v_num(&idxv));
		v_free(&idxv);
		set_field(ip, idx, val);
		return;
	}
	case N_ARRIDX:
		assign_value_to_cell(resolve_arridx_cell(ip, lv), val);
		return;
	default:
		return;
	}
}

static double arith(int op, double a, double b)
{
	switch (op) {
	case T_PLUS: return a + b;
	case T_MINUS: return a - b;
	case T_STAR: return a * b;
	case T_SLASH:
		if (b == 0.0) fatal("division by zero");
		return a / b;
	case T_PERCENT:
		if (b == 0.0) fatal("division by zero in %");
		return fmod(a, b);
	case T_CARET: return pow(a, b);
	default: return 0;
	}
}

static struct awk_value eval(struct awk_interp *ip, struct awk_node *n)
{
	struct awk_value v;

	switch (n->type) {
	case N_NUM: v_num_init(&v, n->num); return v;
	case N_STR:
		__ownership_string_terminated(n->str); /* same provenance as lookup_cell()'s own comment above */
		v_str_init(&v, xstrdup(n->str), VK_STR);
		return v;
	case N_REGEX: {
		int m = regexec(n->re, ip->rec ? ip->rec : "", 0, NULL, 0) == 0;
		v_num_init(&v, m ? 1 : 0);
		return v;
	}
	case N_VAR: case N_FIELD: case N_ARRIDX:
		return eval_lvalue_read(ip, n);
	case N_ASSIGN: {
		struct awk_value rhs = eval(ip, n->b);
		if (n->op != T_ASSIGN) {
			struct awk_value cur = eval_lvalue_read(ip, n->a);
			int arith_op;
			double result;
			switch (n->op) {
			case T_ADD_ASSIGN: arith_op = T_PLUS; break;
			case T_SUB_ASSIGN: arith_op = T_MINUS; break;
			case T_MUL_ASSIGN: arith_op = T_STAR; break;
			case T_DIV_ASSIGN: arith_op = T_SLASH; break;
			case T_MOD_ASSIGN: arith_op = T_PERCENT; break;
			default: arith_op = T_CARET; break; /* T_POW_ASSIGN */
			}
			result = arith(arith_op, v_num(&cur), v_num(&rhs));
			v_free(&cur);
			v_free(&rhs);
			v_num_init(&rhs, result);
		}
		assign_lvalue(ip, n->a, &rhs);
		v_free(&rhs);
		return eval_lvalue_read(ip, n->a);
	}
	case N_TERNARY: {
		struct awk_value c = eval(ip, n->a);
		int truth = v_truth(&c);
		v_free(&c);
		return eval(ip, truth ? n->b : n->c);
	}
	case N_OR: {
		struct awk_value a = eval(ip, n->a);
		int t = v_truth(&a);
		v_free(&a);
		if (t) { v_num_init(&v, 1); return v; }
		{
			struct awk_value b = eval(ip, n->b);
			int tb = v_truth(&b);
			v_free(&b);
			v_num_init(&v, tb ? 1 : 0);
			return v;
		}
	}
	case N_AND: {
		struct awk_value a = eval(ip, n->a);
		int t = v_truth(&a);
		v_free(&a);
		if (!t) { v_num_init(&v, 0); return v; }
		{
			struct awk_value b = eval(ip, n->b);
			int tb = v_truth(&b);
			v_free(&b);
			v_num_init(&v, tb ? 1 : 0);
			return v;
		}
	}
	case N_NOT: {
		struct awk_value a = eval(ip, n->a);
		int t = v_truth(&a);
		v_free(&a);
		v_num_init(&v, t ? 0 : 1);
		return v;
	}
	case N_IN: {
		struct awk_cell *c = lookup_cell(ip, n->str);
		char *key = build_subsep_key(ip, n->list, n->nlist);
		int found;
		promote_to_array(c);
		found = awk_htab_get(c->arr, key) != NULL;
		free(key);
		v_num_init(&v, found ? 1 : 0);
		return v;
	}
	case N_MATCH: {
		struct awk_value s = eval(ip, n->a);
		regex_t *re = resolve_ere(ip, n->b);
		int m = regexec(re, v_str(&s, convfmt_str(ip)), 0, NULL, 0) == 0;
		int matched;
		v_free(&s);
		matched = n->op ? !m : m; /* n->op is the T_NOMATCH ("!~") negation flag */
		v_num_init(&v, matched ? 1 : 0);
		return v;
	}
	case N_RELOP: {
		struct awk_value a = eval(ip, n->a), b = eval(ip, n->b);
		int c = compare_values(&a, &b, convfmt_str(ip));
		v_free(&a); v_free(&b);
		{
			int r;
			switch (n->op) {
			case T_LT: r = c < 0; break;
			case T_LE: r = c <= 0; break;
			case T_GT: r = c > 0; break;
			case T_GE: r = c >= 0; break;
			case T_EQ: r = c == 0; break;
			default: r = c != 0; break;
			}
			v_num_init(&v, r ? 1 : 0);
			return v;
		}
	}
	case N_CONCAT: {
		struct awk_value a = eval(ip, n->a), b = eval(ip, n->b);
		const char *sa = v_str(&a, convfmt_str(ip)), *sb = v_str(&b, convfmt_str(ip));
		size_t la, lb, bytes;
		__ownership_string_terminated(sa); /* v_str()'s own declared contract, re-asserted right at this use */
		__ownership_string_terminated(sb);
		la = strlen(sa); lb = strlen(sb);
		char *s;
		if (!__util_size_add(la, lb, &bytes) || !__util_size_add(bytes, 1, &bytes)) oom();
		s = malloc(bytes);
		if (!s) oom();
		for (size_t i = 0; i < la; i++) s[i] = sa[i];
		for (size_t i = 0; i < lb; i++) s[la + i] = sb[i];
		s[la + lb] = 0;
		v_free(&a); v_free(&b);
		v_str_init(&v, s, VK_STR);
		return v;
	}
	case N_BINOP: {
		struct awk_value a = eval(ip, n->a), b = eval(ip, n->b);
		double r = arith(n->op, v_num(&a), v_num(&b));
		v_free(&a); v_free(&b);
		v_num_init(&v, r);
		return v;
	}
	case N_UMINUS: { struct awk_value a = eval(ip, n->a); double r = -v_num(&a); v_free(&a); v_num_init(&v, r); return v; }
	case N_UPLUS: { struct awk_value a = eval(ip, n->a); double r = v_num(&a); v_free(&a); v_num_init(&v, r); return v; }
	case N_PREINCR: return do_incrdecr(ip, n, 1, 1);
	case N_PREDECR: return do_incrdecr(ip, n, -1, 1);
	case N_POSTINCR: return do_incrdecr(ip, n, 1, 0);
	case N_POSTDECR: return do_incrdecr(ip, n, -1, 0);
	case N_GETLINE: {
		double r = do_getline(ip, n);
		v_num_init(&v, r);
		return v;
	}
	case N_CALL: return call_builtin(ip, n);
	case N_ELIST:
		if (n->nlist) return eval(ip, n->list[0]);
		v_uninit_init(&v);
		return v;
	default:
		v_uninit_init(&v);
		return v;
	}
}

/* Converts a wait(2)-style status (as pclose()/system() below both
 * return it) into the plain exit-code integer close()'s and system()'s
 * own awk(1p) return value is: -1 if pclose()/system() itself failed
 * to obtain a status at all, the command's own exit code if it exited
 * normally, or the raw status back unchanged for any other case (e.g.
 * a signal-termination encoding) -- shared by both builtins below
 * rather than duplicated. */
static int wait_status_to_exit_code(int status)
{
	if (status < 0) return -1;
	if (WIFEXITED(status)) return WEXITSTATUS(status);
	return status;
}

/* ==== built-in function dispatch ========================================== */

static struct awk_value call_builtin(struct awk_interp *ip, struct awk_node *call)
{
	struct awk_value v;
	const char *name = call->str;
	struct awk_node **a = call->list;
	int na = call->nlist;

	/* call->str is an N_CALL awk_node's own function-name text -- the
	 * parser only ever fills it from a NUL-terminated token, same
	 * provenance as lookup_cell()'s own comment above. */
	__ownership_string_terminated(name);

	if (!strcmp(name, "length")) {
		if (na == 0) {
			const char *rec0 = ip->rec ? ip->rec : "";
			__ownership_string_terminated(rec0); /* ip->rec's own comment (awk_priv.h), or the "" literal */
			v_num_init(&v, (double)strlen(rec0));
			return v;
		}
		if (a[0]->type == N_VAR) {
			struct awk_cell *c = lookup_cell(ip, a[0]->str);
			if (c->is_array) { v_num_init(&v, (double)c->arr->count); return v; }
		}
		{
			struct awk_value s = eval(ip, a[0]);
			const char *str = v_str(&s, convfmt_str(ip));
			__ownership_string_terminated(str); /* v_str()'s own declared contract, re-asserted right at this use */
			v_num_init(&v, (double)strlen(str));
			v_free(&s);
			return v;
		}
	}
	if (!strcmp(name, "substr")) {
		/* XCU awk(1p) leaves m<=0 or m+n past the string's end
		 * unspecified; this implements the well-known clamping
		 * algorithm every real awk uses (see src/util/awk.c's header):
		 * treat [m, m+n) as a half-open character range over 1-based
		 * positions, shrink it to whatever actually overlaps [1, len],
		 * and take that overlap -- so `substr("hello", -2, 5)` (the 5
		 * characters at positions -2,-1,0,1,2) yields "he" (the two of
		 * those five positions, 1 and 2, that actually exist in the
		 * string), not an error or the whole string. */
		struct awk_value s = eval(ip, a[0]);
		const char *str = v_str(&s, convfmt_str(ip));
		__ownership_string_terminated(str); /* v_str()'s own declared contract, re-asserted right at this use */
		double slen = (double)strlen(str);
		double m = na > 1 ? v_num_p(ip, a[1]) : 1;
		double end = na > 2 ? m + v_num_p(ip, a[2]) : slen + 1; /* exclusive */
		double start = m;
		/* m/n can be ANY string's numeric value, including strtod()'s
		 * own "nan" spelling (v_num()'s unconditional strtod() call,
		 * not gated by looks_numeric()'s VK_STRNUM classification --
		 * e.g. substr("hello","nan",2)) -- NaN compares false against
		 * everything, so the < clamps just below would silently leave
		 * start/end as NaN instead of catching them; d2long() below
		 * maps that case to 0 rather than letting a NaN reach a bare
		 * (long) cast (undefined behavior). */
		if (!(start >= 1)) start = 1;
		if (!(end <= slen + 1)) end = slen + 1;
		if (!(end >= start)) end = start;
		{
			long is = d2long(start) - 1, ie = d2long(end) - 1;
			if (is < 0) is = 0;
			if (ie < is) ie = is;
			if (ie > (long)slen) ie = (long)slen;
			v_str_init(&v, dupn_local(str + is, (size_t)(ie - is)), VK_STR);
		}
		v_free(&s);
		return v;
	}
	if (!strcmp(name, "index")) {
		struct awk_value s = eval(ip, a[0]), t = eval(ip, a[1]);
		const char *p = strstr(v_str(&s, convfmt_str(ip)), v_str(&t, convfmt_str(ip)));
		v_num_init(&v, p ? (double)(p - v_str(&s, convfmt_str(ip))) + 1 : 0);
		v_free(&s); v_free(&t);
		return v;
	}
	if (!strcmp(name, "split")) {
		struct awk_value s = eval(ip, a[0]);
		const char *str = v_str(&s, convfmt_str(ip));
		__ownership_string_terminated(str); /* v_str()'s own declared contract, re-asserted right at this use */
		struct awk_cell *arrc = lookup_cell(ip, a[1]->str);
		char **out; int n, i;
		char fsbuf[2] = { ' ', 0 };
		const char *fs = fsbuf;
		char *dynfs = NULL;
		regex_t *dynre = NULL;

		if (arrc->is_array) { awk_htab_free(arrc->arr, free_cell_val); awk_htab_init(arrc->arr); }
		else { arrc->is_array = 1; arrc->arr = malloc(sizeof *arrc->arr); if (!arrc->arr) oom(); awk_htab_init(arrc->arr); }

		if (na > 2) {
			if (a[2]->type == N_REGEX) { dynre = a[2]->re; }
			else {
				struct awk_value fsv = eval(ip, a[2]);
				const char *fsv_str = v_str(&fsv, convfmt_str(ip));
				__ownership_string_terminated(fsv_str); /* v_str()'s own declared contract, re-asserted right at this use */
				dynfs = xstrdup(fsv_str);
				v_free(&fsv);
				fs = dynfs;
			}
		} else {
			fs = cell_str(ip, lookup_cell(ip, "FS"));
		}

		if (dynre) {
			size_t pos = 0, start = 0, len = strlen(str);
			out = NULL; n = 0;
			for (;;) {
				regmatch_t m;
				int eflags = pos ? REG_NOTBOL : 0;
				if (pos == len || regexec(dynre, str + pos, 1, &m, eflags) != 0) break;
				if (m.rm_so == m.rm_eo) { pos++; continue; }
				out = xrealloc(out, (size_t)(n + 1) * sizeof *out);
				out[n++] = dupn_local(str + start, (pos + (size_t)m.rm_so) - start);
				pos = start = pos + (size_t)m.rm_eo;
			}
			out = xrealloc(out, (size_t)(n + 1) * sizeof *out);
			out[n++] = dupn_local(str + start, len - start);
			if (n == 1 && out[0][0] == 0 && len == 0) { free(out[0]); free(out); out = NULL; n = 0; }
		} else {
			split_into(str, strlen(str), fs, 0, &out, &n);
		}
		free(dynfs);
		for (i = 0; i < n; i++) {
			char key[32];
			struct awk_cell *e;
			snprintf(key, sizeof key, "%d", i + 1);
			e = array_elem(arrc, key);
			{
				struct awk_value fv;
				v_str_init(&fv, out[i], looks_numeric(out[i]) ? VK_STRNUM : VK_STR);
				assign_value_to_cell(e, &fv);
				v_free(&fv);
			}
		}
		free(out);
		v_free(&s);
		v_num_init(&v, n);
		return v;
	}
	if (!strcmp(name, "sub") || !strcmp(name, "gsub")) {
		regex_t *re = resolve_ere(ip, a[0]);
		struct awk_value replv = eval(ip, a[1]);
		const char *repl = v_str(&replv, convfmt_str(ip));
		struct awk_node *target = na > 2 ? a[2] : NULL;
		struct awk_value cur;
		char *result;
		int count;
		if (target) {
			cur = eval_lvalue_read(ip, target);
		} else {
			const char *rec0 = ip->rec ? ip->rec : "";
			__ownership_string_terminated(rec0); /* ip->rec's own comment (awk_priv.h), or the "" literal */
			v_str_init(&cur, xstrdup(rec0), VK_STR);
		}
		{
			const char *cur_str = v_str(&cur, convfmt_str(ip));
			__ownership_string_terminated(cur_str); /* v_str()'s own declared contract, re-asserted right at this use */
			count = do_sub(re, cur_str, repl, !strcmp(name, "gsub"), &result);
		}
		v_free(&cur);
		v_free(&replv);
		if (count) {
			struct awk_value nv;
			v_str_init(&nv, result, VK_STR);
			if (target) assign_lvalue(ip, target, &nv);
			else set_record(ip, xstrdup(nv.str));
			v_free(&nv);
		} else {
			free(result);
		}
		v_num_init(&v, count);
		return v;
	}
	if (!strcmp(name, "match")) {
		struct awk_value s = eval(ip, a[0]);
		regex_t *re = resolve_ere(ip, a[1]);
		regmatch_t m;
		const char *str = v_str(&s, convfmt_str(ip));
		__ownership_string_terminated(str); /* v_str()'s own declared contract, re-asserted right at this use */
		if (regexec(re, str, 1, &m, 0) == 0) {
			set_global_num(ip, "RSTART", m.rm_so + 1);
			set_global_num(ip, "RLENGTH", m.rm_eo - m.rm_so);
			v_num_init(&v, m.rm_so + 1);
		} else {
			set_global_num(ip, "RSTART", 0);
			set_global_num(ip, "RLENGTH", -1);
			v_num_init(&v, 0);
		}
		v_free(&s);
		return v;
	}
	if (!strcmp(name, "sprintf")) {
		struct awk_value *args = na > 1 ? xrealloc(NULL, (size_t)(na - 1) * sizeof *args) : NULL;
		struct awk_value fmtv = eval(ip, a[0]);
		int i;
		char *s;
		for (i = 1; i < na; i++) args[i - 1] = eval(ip, a[i]);
		s = awk_format(ip, v_str(&fmtv, convfmt_str(ip)), args, na - 1);
		v_free(&fmtv);
		for (i = 0; i < na - 1; i++) v_free(&args[i]);
		free(args);
		v_str_init(&v, s, VK_STR);
		return v;
	}
	if (!strcmp(name, "sin") || !strcmp(name, "cos") || !strcmp(name, "exp") ||
	    !strcmp(name, "log") || !strcmp(name, "sqrt") || !strcmp(name, "int")) {
		struct awk_value s = eval(ip, a[0]);
		double x = v_num(&s), r;
		v_free(&s);
		if (!strcmp(name, "sin")) r = sin(x);
		else if (!strcmp(name, "cos")) r = cos(x);
		else if (!strcmp(name, "exp")) r = exp(x);
		else if (!strcmp(name, "log")) r = log(x);
		else if (!strcmp(name, "sqrt")) r = sqrt(x);
		else r = x < 0 ? ceil(x) : floor(x);
		v_num_init(&v, r);
		return v;
	}
	if (!strcmp(name, "atan2")) {
		struct awk_value s1 = eval(ip, a[0]), s2 = eval(ip, a[1]);
		double r = atan2(v_num(&s1), v_num(&s2));
		v_free(&s1); v_free(&s2);
		v_num_init(&v, r);
		return v;
	}
	if (!strcmp(name, "rand")) {
		ip->rand_state = ip->rand_state * 1103515245u + 12345u;
		v_num_init(&v, (double)((ip->rand_state >> 16) & 0x7fffffff) / 2147483648.0);
		return v;
	}
	if (!strcmp(name, "srand")) {
		double prev = ip->rand_prev_seed;
		double seed = na > 0 ? v_num_p(ip, a[0]) : (double)time(NULL);
		ip->rand_prev_seed = seed;
		ip->rand_state = (unsigned long)seed;
		v_num_init(&v, prev);
		return v;
	}
	if (!strcmp(name, "tolower") || !strcmp(name, "toupper")) {
		struct awk_value s = eval(ip, a[0]);
		const char *str = v_str(&s, convfmt_str(ip));
		__ownership_string_terminated(str); /* v_str()'s own declared contract, re-asserted right at this use */
		size_t len = strlen(str), i, bytes;
		char *r;
		if (!__util_size_add(len, 1, &bytes)) oom();
		r = malloc(bytes);
		if (!r) oom();
		for (i = 0; i < len; i++) r[i] = (char)(name[2] == 'l' ? tolower((unsigned char)str[i]) : toupper((unsigned char)str[i]));
		r[len] = 0;
		v_free(&s);
		v_str_init(&v, r, VK_STR);
		return v;
	}
	if (!strcmp(name, "close")) {
		struct awk_value s = eval(ip, a[0]);
		const char *target = v_str(&s, convfmt_str(ip));
		void *found = awk_htab_get(&ip->streams, target);
		int result = -1;
		if (found) {
			struct awk_stream *st = found;
			if (st->is_pipe) {
				result = wait_status_to_exit_code(pclose(st->f));
			} else {
				result = fclose(st->f);
			}
			free(st);
			awk_htab_del(&ip->streams, target, NULL); /* already freed above; avoid double free */
		}
		v_free(&s);
		v_num_init(&v, result);
		return v;
	}
	if (!strcmp(name, "system")) {
		struct awk_value s = eval(ip, a[0]);
		int status;
		flush_all_streams(ip);
		status = system(v_str(&s, convfmt_str(ip)));
		v_free(&s);
		v_num_init(&v, wait_status_to_exit_code(status));
		return v;
	}
	{
		int i;
		for (i = 0; i < ip->prog->nfuncs; i++) {
			__ownership_string_terminated(ip->prog->funcs[i].name); /* parser-owned identifier text, same as name above */
			if (!strcmp(ip->prog->funcs[i].name, name))
				return call_user_func(ip, &ip->prog->funcs[i], a, na);
		}
	}
	{
		char msg[256];
		snprintf(msg, sizeof msg, "call to undefined function %s", name);
		fatal(msg);
	}
	v_uninit_init(&v);
	return v;
}

static double v_num_p(struct awk_interp *ip, struct awk_node *n)
{
	struct awk_value v = eval(ip, n);
	double r = v_num(&v);
	v_free(&v);
	(void)ip;
	return r;
}

/* ==== user-defined function calls (arg binding -- see this file's own
 * and awk_priv.h's struct awk_frame comments for the alias/copy rule) */

static struct awk_value call_user_func(struct awk_interp *ip, struct awk_func *fn, struct awk_node **argnodes, int nargs)
{
	struct awk_cell **cells = fn->nparams ? xrealloc(NULL, (size_t)fn->nparams * sizeof *cells) : NULL; // NOLINT(bugprone-sizeof-expression) -- cells is awk_cell**, *cells is awk_cell*, the array holds pointers
	unsigned char *isalias = fn->nparams ? xrealloc(NULL, (size_t)fn->nparams * sizeof *isalias) : NULL;
	struct awk_frame frame, *prev_frame = ip->frame;
	struct awk_value ret;
	enum awk_sig sig;
	int i;

	if (++ip->depth > 1000) fatal("function call nesting too deep");

	for (i = 0; i < fn->nparams; i++) {
		if (i < nargs) {
			struct awk_node *an = argnodes[i];
			if (an->type == N_VAR) {
				struct awk_cell *src = lookup_cell(ip, an->str);
				if (src->is_array || src->kind == VK_UNINIT) {
					cells[i] = src;
					isalias[i] = 1;
				} else {
					struct awk_value sv = cell_to_value(ip, src);
					cells[i] = new_cell();
					assign_value_to_cell(cells[i], &sv);
					v_free(&sv);
					isalias[i] = 0;
				}
			} else {
				struct awk_value av = eval(ip, an);
				cells[i] = new_cell();
				assign_value_to_cell(cells[i], &av);
				v_free(&av);
				isalias[i] = 0;
			}
		} else {
			cells[i] = new_cell();
			isalias[i] = 0;
		}
	}

	frame.names = fn->params;
	frame.cells = cells;
	frame.is_alias = isalias;
	frame.nparams = fn->nparams;
	ip->frame = &frame;
	v_uninit_init(&ret);
	sig = exec_stmt(ip, fn->body, &ret);
	ip->frame = prev_frame;
	ip->depth--;

	for (i = 0; i < fn->nparams; i++) {
		if (!isalias[i]) { free_cell_contents(cells[i]); free(cells[i]); }
	}
	free(cells);
	free(isalias);

	if (sig != SIG_RETURN) { v_free(&ret); v_uninit_init(&ret); }
	return ret;
}

/* ==== statement execution ================================================= */

static enum awk_sig exec_block(struct awk_interp *ip, struct awk_node *n, struct awk_value *retval)
{
	int i;
	for (i = 0; i < n->nlist; i++) {
		enum awk_sig s = exec_stmt(ip, n->list[i], retval);
		if (s != SIG_NONE) return s;
		if (ip->unwind != SIG_NONE) return ip->unwind;
	}
	return SIG_NONE;
}

static enum awk_sig exec_stmt(struct awk_interp *ip, struct awk_node *n, struct awk_value *retval)
{
	switch (n->type) {
	case N_BLOCK: return exec_block(ip, n, retval);
	case N_EXPRSTMT: { struct awk_value v = eval(ip, n->a); v_free(&v); return ip->unwind; }
	case N_PRINT: case N_PRINTF: {
		FILE *f = resolve_redir_stream(ip, n);
		if (n->type == N_PRINT) {
			int i;
			const char *ofs = cell_str(ip, lookup_cell(ip, "OFS"));
			const char *ors = cell_str(ip, lookup_cell(ip, "ORS"));
			if (n->nlist == 0) {
				fputs(ip->rec ? ip->rec : "", f);
			} else {
				for (i = 0; i < n->nlist; i++) {
					struct awk_value v = eval(ip, n->list[i]);
					if (i) fputs(ofs, f);
					fputs(output_str(ofmt_str(ip), &v), f);
					v_free(&v);
				}
			}
			fputs(ors, f);
		} else {
			struct awk_value *args = n->nlist > 1 ? xrealloc(NULL, (size_t)(n->nlist - 1) * sizeof *args) : NULL;
			struct awk_value fmtv;
			int i;
			char *s;
			if (n->nlist == 0) { v_str_init(&fmtv, xstrdup(""), VK_STR); }
			else fmtv = eval(ip, n->list[0]);
			for (i = 1; i < n->nlist; i++) args[i - 1] = eval(ip, n->list[i]);
			s = awk_format(ip, v_str(&fmtv, convfmt_str(ip)), args, n->nlist > 0 ? n->nlist - 1 : 0);
			fputs(s, f);
			free(s);
			v_free(&fmtv);
			for (i = 0; i < n->nlist - 1; i++) v_free(&args[i]);
			free(args);
		}
		return ip->unwind;
	}
	case N_IF: {
		struct awk_value c = eval(ip, n->a);
		int t = v_truth(&c);
		v_free(&c);
		if (ip->unwind != SIG_NONE) return ip->unwind;
		if (t) return exec_stmt(ip, n->b, retval);
		if (n->c) return exec_stmt(ip, n->c, retval);
		return SIG_NONE;
	}
	case N_WHILE: {
		for (;;) {
			struct awk_value c = eval(ip, n->a);
			int t = v_truth(&c);
			v_free(&c);
			if (ip->unwind != SIG_NONE) return ip->unwind;
			if (!t) break;
			{
				enum awk_sig s = exec_stmt(ip, n->b, retval);
				if (s == SIG_BREAK) break;
				if (s == SIG_NEXT || s == SIG_EXIT || s == SIG_RETURN) return s;
			}
		}
		return SIG_NONE;
	}
	case N_DOWHILE: {
		for (;;) {
			enum awk_sig s = exec_stmt(ip, n->a, retval);
			if (s == SIG_NEXT || s == SIG_EXIT || s == SIG_RETURN) return s;
			if (s != SIG_BREAK) {
				struct awk_value c = eval(ip, n->b);
				int t = v_truth(&c);
				v_free(&c);
				if (ip->unwind != SIG_NONE) return ip->unwind;
				if (!t) break;
			} else break;
		}
		return SIG_NONE;
	}
	case N_FOR: {
		if (n->a) { enum awk_sig s = exec_stmt(ip, n->a, retval); if (s != SIG_NONE) return s; if (ip->unwind) return ip->unwind; }
		for (;;) {
			if (n->b) {
				struct awk_value c = eval(ip, n->b);
				int t = v_truth(&c);
				v_free(&c);
				if (ip->unwind != SIG_NONE) return ip->unwind;
				if (!t) break;
			}
			{
				enum awk_sig s = exec_stmt(ip, n->d, retval);
				if (s == SIG_BREAK) break;
				if (s == SIG_NEXT || s == SIG_EXIT || s == SIG_RETURN) return s;
			}
			if (n->c) { enum awk_sig s = exec_stmt(ip, n->c, retval); if (s != SIG_NONE) return s; if (ip->unwind) return ip->unwind; }
		}
		return SIG_NONE;
	}
	case N_FORIN: {
		struct awk_cell *arrc = lookup_cell(ip, n->str2);
		struct awk_cell *var = lookup_cell(ip, n->str);
		struct awk_hiter it;
		struct awk_hnode *node;
		promote_to_array(arrc);
		awk_hiter_init(&it, arrc->arr);
		while ((node = awk_hiter_next(&it))) {
			struct awk_value kv;
			enum awk_sig s;
			__ownership_string_terminated(node->key); /* awk_htab.c always strcpy()'s a NUL-terminated key here */
			v_str_init(&kv, xstrdup(node->key), looks_numeric(node->key) ? VK_STRNUM : VK_STR);
			assign_value_to_cell(var, &kv);
			v_free(&kv);
			s = exec_stmt(ip, n->b, retval);
			if (s == SIG_BREAK) break;
			if (s == SIG_NEXT || s == SIG_EXIT || s == SIG_RETURN) return s;
		}
		return SIG_NONE;
	}
	case N_BREAK: return SIG_BREAK;
	case N_CONTINUE: return SIG_CONTINUE;
	case N_NEXT: ip->unwind = SIG_NEXT; return SIG_NEXT;
	case N_EXIT: {
		if (n->a) { struct awk_value v = eval(ip, n->a); ip->exit_status = d2int(v_num(&v)); v_free(&v); }
		ip->exiting = 1;
		ip->unwind = SIG_EXIT;
		return SIG_EXIT;
	}
	case N_RETURN: {
		if (n->a) { v_free(retval); *retval = eval(ip, n->a); }
		return SIG_RETURN;
	}
	case N_DELETE: {
		struct awk_cell *c = lookup_cell(ip, n->str);
		promote_to_array(c);
		if (n->nlist == 0) {
			awk_htab_free(c->arr, free_cell_val);
			awk_htab_init(c->arr);
		} else {
			char *key = build_subsep_key(ip, n->list, n->nlist);
			awk_htab_del(c->arr, key, free_cell_val);
			free(key);
		}
		return SIG_NONE;
	}
	default:
		return SIG_NONE;
	}
}

/* ==== program-level setup and driver ====================================== */

static void awk_interp_seed_defaults(struct awk_interp *ip)
{
	set_global_str(ip, "FS", " ");
	set_global_str(ip, "OFS", " ");
	set_global_str(ip, "ORS", "\n");
	set_global_str(ip, "RS", "\n");
	set_global_str(ip, "SUBSEP", "\034");
	set_global_str(ip, "CONVFMT", "%.6g");
	set_global_str(ip, "OFMT", "%.6g");
	set_global_str(ip, "FILENAME", "");
	set_global_num(ip, "NR", 0);
	set_global_num(ip, "NF", 0);
	set_global_num(ip, "FNR", 0);
	set_global_num(ip, "RSTART", 0);
	set_global_num(ip, "RLENGTH", -1);
}

void awk_interp_init(struct awk_interp *ip, struct awk_program *prog)
{
	memset(ip, 0, sizeof *ip);
	ip->prog = prog;
	awk_htab_init(&ip->globals);
	awk_htab_init(&ip->streams);
	awk_htab_init(&ip->recmp);
	ip->rand_state = 1;
	ip->rand_prev_seed = 1;
	ip->diag_prefix = "awk";
	awk_interp_seed_defaults(ip);
}

void awk_interp_set_str(struct awk_interp *ip, const char *name, const char *val)
{
	struct awk_cell *c = lookup_cell(ip, name);
	struct awk_value v;
	/* Both parameters come from a -v assignment or var=value operand
	 * (awk.c) or a fixed name this file passes itself (e.g. "NF"
	 * elsewhere) -- always a plain, already NUL-terminated C string. */
	__ownership_string_terminated(name);
	__ownership_string_terminated(val);
	v_str_init(&v, xstrdup(val), looks_numeric(val) ? VK_STRNUM : VK_STR);
	assign_value_to_cell(c, &v);
	v_free(&v);
	if (!strcmp(name, "NF")) set_nf(ip, d2long(cell_num(c)));
}

void awk_interp_setup_argv(struct awk_interp *ip, const char *prog_name, int nargs, char **args)
{
	struct awk_cell *argv_cell = lookup_cell(ip, "ARGV");
	int i;
	char key[32];

	__ownership_string_terminated(prog_name); /* argv[0], always NUL-terminated per exec()'s own contract */
	promote_to_array(argv_cell);
	{
		struct awk_cell *e = array_elem(argv_cell, "0");
		struct awk_value v;
		v_str_init(&v, xstrdup(prog_name), VK_STR);
		assign_value_to_cell(e, &v);
		v_free(&v);
	}
	for (i = 0; i < nargs; i++) {
		struct awk_cell *e;
		struct awk_value v;
		snprintf(key, sizeof key, "%d", i + 1);
		e = array_elem(argv_cell, key);
		__ownership_string_terminated(args[i]); /* an argv[] element, same as prog_name above */
		v_str_init(&v, xstrdup(args[i]), looks_numeric(args[i]) ? VK_STRNUM : VK_STR);
		assign_value_to_cell(e, &v);
		v_free(&v);
	}
	set_global_num(ip, "ARGC", nargs + 1);
	ip->argi = 1;
}

void awk_interp_setup_environ(struct awk_interp *ip, char **envp)
{
	struct awk_cell *ec = lookup_cell(ip, "ENVIRON");
	int i;
	promote_to_array(ec);
	for (i = 0; envp && envp[i]; i++) {
		__ownership_string_terminated(envp[i]); /* POSIX envp: every element up to the NULL terminator is itself a NUL-terminated "NAME=value" string */
		const char *eq = strchr(envp[i], '=');
		if (!eq) continue;
		{
			char *name = dupn_local(envp[i], (size_t)(eq - envp[i]));
			struct awk_cell *e = array_elem(ec, name);
			struct awk_value v;
			v_str_init(&v, xstrdup(eq + 1), looks_numeric(eq + 1) ? VK_STRNUM : VK_STR);
			assign_value_to_cell(e, &v);
			v_free(&v);
			free(name);
		}
	}
}

static int rule_matches(struct awk_interp *ip, struct awk_rule *r)
{
	switch (r->kind) {
	case RULE_ALWAYS: return 1;
	case RULE_EXPR: case RULE_REGEX: {
		struct awk_value v = eval(ip, r->pat1);
		int t = v_truth(&v);
		v_free(&v);
		return t;
	}
	case RULE_RANGE: {
		if (!r->range_active) {
			struct awk_value v = eval(ip, r->pat1);
			int t = v_truth(&v);
			v_free(&v);
			if (!t) return 0;
			r->range_active = 1;
		}
		{
			struct awk_value v = eval(ip, r->pat2);
			int t = v_truth(&v);
			v_free(&v);
			if (t) r->range_active = 0;
		}
		return 1;
	}
	default: return 0;
	}
}

static void run_default_or_action(struct awk_interp *ip, struct awk_rule *r, struct awk_value *dummy_ret)
{
	if (r->action) {
		exec_stmt(ip, r->action, dummy_ret);
	} else {
		fputs(ip->rec ? ip->rec : "", stdout);
		fputs(cell_str(ip, lookup_cell(ip, "ORS")), stdout);
	}
}

int awk_interp_run(struct awk_interp *ip)
{
	int i, need_input = 0;
	struct awk_value dummy;

	v_uninit_init(&dummy);
	for (i = 0; i < ip->prog->nrules; i++)
		if (ip->prog->rules[i].kind != RULE_BEGIN) { need_input = 1; break; }

	for (i = 0; i < ip->prog->nrules && !ip->exiting; i++) {
		if (ip->prog->rules[i].kind == RULE_BEGIN) exec_stmt(ip, ip->prog->rules[i].action, &dummy);
	}

	if (need_input && !ip->exiting) {
		char *rec;
		while (!ip->exiting && read_next_main_record(ip, &rec)) {
			set_global_num(ip, "NR", cell_num(lookup_cell(ip, "NR")) + 1);
			set_global_num(ip, "FNR", cell_num(lookup_cell(ip, "FNR")) + 1);
			set_record(ip, rec);
			for (i = 0; i < ip->prog->nrules; i++) {
				struct awk_rule *r = &ip->prog->rules[i];
				enum awk_sig s;
				if (r->kind == RULE_BEGIN || r->kind == RULE_END) continue;
				if (!rule_matches(ip, r)) continue;
				run_default_or_action(ip, r, &dummy);
				s = ip->unwind;
				if (s == SIG_NEXT) { ip->unwind = SIG_NONE; break; }
				if (s == SIG_EXIT) break;
			}
		}
	}

	ip->unwind = SIG_NONE;
	for (i = 0; i < ip->prog->nrules; i++) {
		if (ip->prog->rules[i].kind == RULE_END) exec_stmt(ip, ip->prog->rules[i].action, &dummy);
		if (ip->unwind == SIG_EXIT) break;
	}

	flush_all_streams(ip);
	return ip->exit_status;
}

void awk_interp_free(struct awk_interp *ip)
{
	int i;
	if (ip->curfile && !ip->curfile_is_stdin) (void)fclose(ip->curfile);
	awk_htab_free(&ip->globals, free_cell_val);
	awk_htab_free(&ip->streams, free_stream_val);
	for (i = 0; i < (int)ip->recmp.nbuckets; i++) {
		struct awk_hnode *n = ip->recmp.buckets[i];
		while (n) { regfree(n->val); free(n->val); n = n->next; }
	}
	awk_htab_free(&ip->recmp, NULL);
	free_fields(ip);
	free(ip->flds);
	free(ip->rec);
}
