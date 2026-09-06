/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * __vfscanf: the one parser every scanf/fscanf/sscanf variant calls
 * into.  sscanf/vsscanf hand it a throwaway read-only memory FILE (see
 * mem.c/fmemopen) instead of duplicating the logic against a string.
 *
 * An input item is "the longest sequence of input bytes ... which is an
 * initial subsequence of a matching sequence" (C99 7.19.6.2p12); a
 * matching failure consumes it in full.  Note *initial subsequence*: a
 * half-spelled "infi", a bare "0x" or a "1e" with no exponent are all
 * consumed whole as matching failures.  Only the single offending byte
 * that could not extend the item is left unread.
 *
 * %f has no length limit worth naming, so the float conversions walk
 * the strtod grammar a character at a time, staging the field's text in
 * a buffer that starts in this frame and moves to the heap when it
 * outgrows it, then hand a matching-sequence field to strtof/strtod/
 * strtold for exact rounding.  Integer conversions need no buffer: they
 * accumulate as they read and saturate rather than wrap on overflow.
 *
 * The look-ahead is one byte everywhere, normally the stream's own
 * ungetc -- which C99 only promises for a single character and can
 * still refuse -- so struct sc keeps a small stack behind it (see unrd
 * below) and seeks back whatever is left over at the end.
 *
 * %[...] scansets and POSIX's [CX] 'm' assignment-allocation character
 * (see struct abuf) are implemented; positional arguments and
 * vector-of-float %a/%A input conversions are not, since nothing in
 * this tree needs them.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- GNU feature-test macro has its specified reserved spelling
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <wchar.h>
#include "stdio_impl.h"
#include "unsafe_pointer.h"

enum { LM_NONE, LM_hh, LM_h, LM_l, LM_ll, LM_j, LM_z, LM_t, LM_L };

/* Input cursor: every character taken from the stream bumps nread, and
 * every pushed-back one takes it off again, so nread is exactly what %n
 * reports.  A pushed-back character normally goes to the stream's own
 * ungetc, but that is only guaranteed for one character, so unrd falls
 * back to a stack that rd drains first; anything left on it at the end
 * is returned to the stream by seeking. */
/* One pushed-back unit.  `nb` is how many BYTES of the stream it came
 * from -- 1 for a byte, 1..4 for a UTF-8-decoded wide character,
 * sizeof(wchar_t) for a wmemstream read -- since sc_done() hands the
 * look-ahead back by seeking a byte offset, not recoverable from the
 * unit itself once a variable-width encoding is in play. */
struct pbent {
	wchar_t wc;
	unsigned char nb;
};

struct sc {
	FILE *f;
	int nread;
	int wide;               /* read wide characters, not bytes */
	int ilseq;              /* a wide read hit an invalid sequence */
	int lastnb;             /* bytes consumed by the most recent rd() */
	struct pbent *pb;       /* pb[npb-1] is the next unit to hand back */
	int npb, pbcap;
	struct pbent pbinit[32];
};

/* The text of one numeric field.  Starts in the caller's frame and
 * grows on the heap; oom is sticky, and the caller turns it into the
 * [ENOMEM] fscanf.html makes a shall-fail. */
struct nbuf {
	char *p;
	int len, cap, oom;
	char init[128];
};

/* The destination of an 'm'-qualified %s, %c or %[: POSIX's [CX]
 * assignment-allocation character allocates a buffer sized to the
 * converted string plus a terminating null, and hands it back through
 * a caller-owned pointer variable (fscanf.html).
 *
 * cap counts ELEMENTS, not bytes -- the destination is wchar_t for an
 * l-qualified conversion, char otherwise, and store_unit() indexes it
 * in elements either way; esz says which.  The caller's pointer is
 * written only on success, so a matching failure, encoding error or
 * allocation failure all leave it untouched and free what was built. */
struct abuf {
	void *p;
	int cap;                /* elements allocated */
	int esz;                /* bytes per element */
};

/* A width-limited view of the cursor: %20lf may take twenty characters
 * and no more, and a character given back is available to the field
 * again.  left < 0 means no width was given. */
struct fld {
	struct sc *sc;
	int left;
};

static void sc_init(struct sc *sc, FILE *f, int wide)
{
	sc->f = f;
	sc->nread = 0;
	sc->wide = wide;
	sc->ilseq = 0;
	sc->lastnb = 1;
	sc->pb = sc->pbinit;
	sc->npb = 0;
	sc->pbcap = (int)(sizeof sc->pbinit / sizeof sc->pbinit[0]);
}

/* One input unit: a byte for fscanf(), a wide character for fwscanf().
 * nread counts UNITS, not bytes: the field width and %n are byte counts
 * under fscanf.html and wide-character counts under fwscanf.html, and a
 * unit is the right thing in each mode -- falls out of counting here
 * rather than being special-cased at ~15 call sites. */
/* sc is nonnull: every function below dereferences it unconditionally,
 * always the caller's own struct sc on the stack. */
static int rd(struct sc *sc) __attribute__((nonnull(1)));
static int rd(struct sc *sc)
{
	int c;
	if (sc->npb) {
		struct pbent e = sc->pb[--sc->npb];
		sc->nread++;
		sc->lastnb = e.nb;
		return (int)e.wc;
	}
	if (!sc->wide) {
		c = __fgetc(sc->f);
		if (c != EOF) { sc->nread++; sc->lastnb = 1; }
		return c;
	}
	{
		int nb = 0;
		wint_t w = __fgetwc_n(sc->f, &nb);
		if (w == WEOF) {
			/* Distinguish "no more input" from "not a character": the
			 * stream's error indicator is set only for the latter, by
			 * src/stdio/wide.c. */
			if (ferror(sc->f)) sc->ilseq = 1;
			return EOF;
		}
		sc->nread++;
		sc->lastnb = nb ? nb : 1;
		return (int)w;
	}
}

static void unrd(struct sc *sc, int c) __attribute__((nonnull(1)));
static void unrd(struct sc *sc, int c)
{
	if (c == EOF) return;
	/* The stream's own pushback first, and only in byte mode.  Wide mode
	 * always uses this stack instead, so sc_done() below knows the exact
	 * byte length still owed to the stream -- ungetwc() would take the
	 * character but not say how many bytes it stood for. */
	if (!sc->wide && sc->npb == 0 && c >= 0 && c <= UCHAR_MAX &&
	    ungetc(c, sc->f) != EOF) { sc->nread--; return; }
	if (sc->npb >= sc->pbcap) {
		struct pbent *q;
		size_t newcap, bytes;
		if (!__size_mul_checked((size_t)sc->pbcap, 2, &newcap) ||
		    newcap > (size_t)INT_MAX ||
		    !__size_mul_checked(newcap, sizeof *q, &bytes)) return;
		q = sc->pb == sc->pbinit ? malloc(bytes) : realloc(sc->pb, bytes);
		/* Nowhere to put it or report it: the character is lost. */
		if (!q) return;
		if (sc->pb == sc->pbinit) memcpy(q, sc->pbinit, (size_t)sc->npb * sizeof *q);
		sc->pb = q;
		sc->pbcap = (int)newcap;
	}
	sc->pb[sc->npb].wc = (wchar_t)c;
	sc->pb[sc->npb].nb = (unsigned char)sc->lastnb;
	sc->npb++;
	sc->nread--;
}

/* Hand back whatever look-ahead the stream's own pushback could not
 * take, and drop the stack.  A stream that cannot seek cannot be given
 * it back at all -- the pre-existing cost of over-reading. */
static void sc_done(struct sc *sc) __attribute__((nonnull(1)));
static void sc_done(struct sc *sc)
{
	if (sc->npb) {
		/* A failed seek is not this call's failure to report, so it
		 * does not get to leave errno behind either.  The offset is
		 * BYTES, not unit count, which matters once wide mode is in
		 * play. */
		int e = errno, i;
		long bytes = 0;
		for (i = 0; i < sc->npb; i++) bytes += sc->pb[i].nb;
		if (fseek(sc->f, -bytes, SEEK_CUR) == 0) sc->npb = 0;
		errno = e;
	}
	if (sc->pb != sc->pbinit) free(sc->pb);
	sc->pb = sc->pbinit;
	sc->npb = 0;
	sc->pbcap = (int)(sizeof sc->pbinit / sizeof sc->pbinit[0]);
}

static int skipspace(struct sc *sc)
{
	int c;
	while ((c = rd(sc)) != EOF && isspace(c)) ;
	return c;
}

/* b is nonnull the same way sc is above: unconditional first-statement
 * dereference, always a real local's address. */
static void nb_init(struct nbuf *b) __attribute__((nonnull(1)));
static void nb_init(struct nbuf *b)
{
	b->p = b->init;
	b->len = 0;
	b->cap = (int)sizeof b->init;
	b->oom = 0;
}

static void nb_done(struct nbuf *b) __attribute__((nonnull(1)));
static void nb_done(struct nbuf *b)
{
	if (b->p != b->init) free(b->p);
	b->p = b->init;
	b->cap = (int)sizeof b->init;
}

/* Append one character, keeping room for the terminator.  0 (and a
 * sticky oom) if the field cannot be staged. */
static int nb_put(struct nbuf *b, int c) __attribute__((nonnull(1)));
static int nb_put(struct nbuf *b, int c)
{
	if (b->len + 1 >= b->cap) {
		char *q;
		size_t newcap;
		if (!__size_mul_checked((size_t)b->cap, 2, &newcap) ||
		    newcap > (size_t)INT_MAX) { b->oom = 1; return 0; }
		q = b->p == b->init ? malloc(newcap)
		                    : realloc(b->p, newcap);
		if (!q) { b->oom = 1; return 0; }
		if (b->p == b->init) memcpy(q, b->init, (size_t)b->len);
		b->p = q;
		b->cap = (int)newcap;
	}
	b->p[b->len++] = (char)c;
	return 1;
}

static void ab_init(struct abuf *b, int esz) __attribute__((nonnull(1)));
static void ab_init(struct abuf *b, int esz)
{
	b->p = 0;
	b->cap = 0;
	b->esz = esz;
}

/* Drop a buffer the conversion is not going to hand over.  Every exit
 * from an 'm' conversion that is not a success goes through here, which
 * is what keeps a matching failure or an [EILSEQ] from leaking the part
 * of the field that had already been built. */
static void ab_free(struct abuf *b) __attribute__((nonnull(1)));
static void ab_free(struct abuf *b)
{
	free(b->p);
	b->p = 0;
	b->cap = 0;
}

/* Room for `need` elements.  Doubling rather than growing by the field
 * width, which may be far larger than the input (%1000000ms on a
 * three-byte field should cost three bytes).  0 is out of memory,
 * which the caller turns into [ENOMEM]. */
static int ab_room(struct abuf *b, int need) __attribute__((nonnull(1)));
static int ab_room(struct abuf *b, int need)
{
	void *q;
	size_t cap = (size_t)b->cap, bytes;

	if (need <= b->cap) return 1;
	if (cap < 32) cap = 32;
	while (cap < (size_t)need) {
		if (!__size_mul_checked(cap, 2, &cap) || cap > (size_t)INT_MAX) return 0;
	}
	if (!__size_mul_checked(cap, (size_t)b->esz, &bytes)) return 0;
	q = realloc(b->p, bytes);
	if (!q) return 0;
	b->p = q;
	b->cap = (int)cap;
	return 1;
}

/* Hand the finished buffer to the caller.  `n` is the element count to
 * keep -- including the terminator for %s/%[, none for %c, which
 * fscanf.html does not terminate -- shrinking the block from whatever
 * the doubling above landed on.  A failed shrink is not a failure: the
 * oversized block is just as usable, and realloc leaves it untouched.
 *
 * The store is through void ** for the same reason the conversions
 * fetch their argument as a bare void *: char ** without the l
 * qualifier, wchar_t ** with it, same representation either way. */
static void ab_give(struct abuf *b, void *arg, int n) __attribute__((nonnull(1, 2)));
static void ab_give(struct abuf *b, void *arg, int n)
{
	void *q = 0;
	size_t bytes;
	if (__size_mul_checked((size_t)(n > 0 ? n : 1), (size_t)b->esz, &bytes))
		q = realloc(b->p, bytes);
	if (q) b->p = q;
	*(void **)arg = b->p;
	b->p = 0;
	b->cap = 0;
}

/* fl is nonnull: unconditional first-statement dereference, always the
 * address of a real local `struct fld fl;` in vfscanf_st(). */
static int fld_get(struct fld *fl) __attribute__((nonnull(1)));
static int fld_get(struct fld *fl)
{
	int c;
	if (fl->left == 0) return EOF;
	c = rd(fl->sc);
	if (c != EOF && fl->left > 0) fl->left--;
	return c;
}

static void fld_unget(struct fld *fl, int c) __attribute__((nonnull(1)));
static void fld_unget(struct fld *fl, int c)
{
	if (c == EOF) return;
	unrd(fl->sc, c);
	if (fl->left >= 0) fl->left++;
}

static int hexval(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Match one of the spellings of a named value, case-insensitively:
 * `least` characters make the short spelling ("inf"), the whole word
 * the long one ("infinity").  A spelling that stops in between ("infi")
 * is still consumed in full and is a matching failure.  1 if matched, 0
 * if not, -1 out of memory.  c is the first character, already read. */
static int scanword(struct fld *fl, struct nbuf *b, const char *word, int least, int c) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	int i = 0, ok = 0;
	for (;;) {
		if (c == EOF || tolower(c) != word[i]) break;
		if (!nb_put(b, c)) return -1;
		i++;
		ok = i == least || !word[i];
		if (!word[i]) { c = EOF; break; }
		c = fld_get(fl);
	}
	fld_unget(fl, c);
	return ok;
}

/* "nan", optionally followed by a parenthesised character sequence.
 * "nan(" and everything after it is an initial subsequence of a
 * "nan(n-char-sequence)", so an unterminated one is consumed in full
 * and is a matching failure rather than a bare "nan". */
static int scannan(struct fld *fl, struct nbuf *b, int c)
{
	int r = scanword(fl, b, "nan", 3, c);
	if (r <= 0) return r;
	c = fld_get(fl);
	if (c != '(') { fld_unget(fl, c); return 1; }
	if (!nb_put(b, c)) return -1;
	for (;;) {
		c = fld_get(fl);
		if (c == ')') return nb_put(b, c) ? 1 : -1;
		if (c == EOF || !(isalnum(c) || c == '_')) break;
		if (!nb_put(b, c)) return -1;
	}
	fld_unget(fl, c);
	return 0;
}

/* The digits of a mantissa, decimal or hexadecimal, with at most one
 * radix point.  Leading zeros are consumed but not staged: they say
 * nothing about the value, and a hundred of them should not cost a
 * hundred bytes.  Returns the terminating character in *cp, 0 if there
 * was no digit at all, -1 out of memory. */
static int scandigits(struct fld *fl, struct nbuf *b, int base, int *cp) __attribute__((nonnull(4)));
static int scandigits(struct fld *fl, struct nbuf *b, int base, int *cp)
{
	int c = *cp, any = 0, dot = 0, lead = 1, nd = 0;
	for (; ; c = fld_get(fl)) {
		if (c != EOF && (base == 16 ? hexval(c) >= 0 : isdigit(c))) {
			any = 1;
			if (c == '0' && lead && !dot) continue;
			if (c != '0') lead = 0;
			if (!nb_put(b, c)) return -1;
			nd++;
		} else if (c == '.' && !dot) {
			dot = 1;
			if (!nb_put(b, c)) return -1;
		} else {
			break;
		}
	}
	*cp = c;
	/* Every digit was a dropped leading zero: the value is zero, and
	 * the staged text still has to say so. */
	if (any && !nd && !nb_put(b, '0')) return -1;
	return any;
}

/* An exponent, if one is there in full: "e" or "p", an optional sign,
 * and at least one decimal digit.  A half-written one ("1.5e+") stays
 * consumed and makes the whole item a matching failure.  1 for a
 * complete exponent, 0 for a half-written one, -1 out of memory; the
 * terminating character comes back in *cp. */
static int scanexp(struct fld *fl, struct nbuf *b, int *cp) __attribute__((nonnull(2, 3)));
static int scanexp(struct fld *fl, struct nbuf *b, int *cp)
{
	int c = *cp, ok = 0;
	if (!nb_put(b, c)) return -1;
	c = fld_get(fl);
	if (c == '+' || c == '-') {
		if (!nb_put(b, c)) return -1;
		c = fld_get(fl);
	}
	while (c != EOF && isdigit(c)) {
		ok = 1;
		if (!nb_put(b, c)) return -1;
		c = fld_get(fl);
	}
	*cp = c;
	return ok;
}

/* One floating-point field.  Consumes the whole input item (capped by
 * the field width) and returns 1 if it is a strtod subject sequence,
 * staged in b ready to convert; 0 for a matching failure with the
 * item's bytes already spent; -1 out of memory.  The one character
 * handed back is the offending input that ended the item. */
static int scanfloat(struct fld *fl, struct nbuf *b)
{
	int c, ok, any;

	c = fld_get(fl);
	if (c == '+' || c == '-') {
		if (!nb_put(b, c)) return -1;
		c = fld_get(fl);
	}
	if (c == 'i' || c == 'I') return scanword(fl, b, "infinity", 3, c);
	if (c == 'n' || c == 'N') return scannan(fl, b, c);

	if (c == '0') {
		int c2 = fld_get(fl);
		if (c2 == 'x' || c2 == 'X') {
			/* A "0x" with no hex digit behind it is still an initial
			 * subsequence of "0x1" -- the whole "0x" is the item and a
			 * matching failure, not a "0" with the "x" handed back. */
			if (!nb_put(b, c)) return -1;
			if (!nb_put(b, c2)) return -1;
			c = fld_get(fl);
			any = scandigits(fl, b, 16, &c);
			if (any < 0) return -1;
			ok = any != 0;
			if (ok && (c == 'p' || c == 'P')) {
				ok = scanexp(fl, b, &c);
				if (ok < 0) return -1;
			}
			fld_unget(fl, c);
			return ok;
		}
		fld_unget(fl, c2);
	}

	any = scandigits(fl, b, 10, &c);
	if (any < 0) return -1;
	/* A lone sign or radix point stays consumed; if nothing at all was
	 * staged, nothing was consumed either. */
	if (!any) { fld_unget(fl, c); return 0; }
	ok = 1;
	if (c == 'e' || c == 'E') {
		ok = scanexp(fl, b, &c);
		if (ok < 0) return -1;
	}
	fld_unget(fl, c);
	return ok;
}

/* Out of memory staging a field.  The failure itself is reported as the
 * [ENOMEM] fscanf.html makes a shall-fail; the field is drained first so
 * that the stream stops where the input item ended rather than in the
 * middle of it, which is where a caller inspecting the stream after the
 * error would expect to find it. */
static void scandrain(struct fld *fl)
{
	int c;
	while ((c = fld_get(fl)) != EOF &&
	       (isalnum(c) || c == '.' || c == '+' || c == '-' ||
	        c == '(' || c == ')' || c == '_')) ;
	fld_unget(fl, c);
}

/* One input byte through mbrtowc(), for the l-modified %s, %c and %[
 * (fscanf.html: input "begins in the initial shift state" and is
 * converted "as if by a call to the mbrtowc() function").  Fed one byte
 * at a time, since a partial sequence lives in the mbstate_t between
 * calls (mbrtowc's (size_t)-2).
 *
 * SURROGATE PAIRS ARE THE SUBTLE PART.  wchar_t is 16-bit UTF-16 here,
 * so a character above the BMP is TWO wchar_t from ONE multibyte
 * character: src/stdlib/mbrtowc.c returns the high surrogate and holds
 * the low one in state, delivered by a later zero-length call as
 * (size_t)-3.  A loop assuming one wide character per call silently
 * drops it; the n == 0 call here drains it (mbrtowc checks pending
 * state before n, which is what makes n == 0 work).
 *
 * Returns 0, or -1 for an encoding error ([EILSEQ]). */
static int wide_put(int c, wchar_t *ws, int *nn, mbstate_t *st, int assign) __attribute__((nonnull(3)));
static int wide_put(int c, wchar_t *ws, int *nn, mbstate_t *st, int assign)
{
	char ch = (char)c;
	wchar_t wc;
	size_t r = mbrtowc(&wc, &ch, 1, st);

	if (r == (size_t)-1) return -1;
	if (r == (size_t)-2) return 0;          /* incomplete; more bytes needed */
	if (assign) ws[*nn] = wc;
	(*nn)++;
	/* mbrtowc holds at most one queued low surrogate: one check drains
	 * it, the second observes the now-empty state. */
	for (unsigned checks_left = 2; checks_left > 0; checks_left--) {
		if (mbrtowc(&wc, &ch, 0, st) != (size_t)-3) break;
		if (assign) ws[*nn] = wc;
		(*nn)++;
	}
	return 0;
}

/* ------------------------------------------------------------------
 * FORMAT CURSOR
 *
 * gf() reads through the cursor and steps by `st` bytes so one scanner
 * serves both fscanf() (byte format) and fwscanf() (wide format).
 * Every character a specification can contain is ASCII, and the
 * <ctype.h> functions here are range tests false above 0x7f
 * (src/ctype/isspace.c), so a wide format unit needs no special
 * classification.
 *
 * Named `fp`, not `p`: a stale dereference of the old name is then a
 * compile error instead of a silent one-byte misread of a wide unit.
 *
 * `st` is a size_t, not an int (same reason as src/stdlib/strtod.c's
 * own cursor): as an int, the %[ range scanner's `fp += 2 * st` widened
 * to ptrdiff_t only after computing the step in int (clang-tidy
 * bugprone-implicit-widening-of-multiplication-result on 64-bit
 * targets).  Nothing truncated, but the declared type of `st` is what
 * makes the arithmetic right rather than a cast at one site.
 * ------------------------------------------------------------------ */
/* A macro, not a function: tcc does no inlining, and a function-call
 * fetch measured 17% slower (300000 iterations of eight sscanf()
 * calls). */
#define gf(q, s) ((s) == 1 ? (unsigned)(unsigned char)*(q) \
	                           : (unsigned)*(const wchar_t *)(q))
/* MEASURED: the `s == 1` branch above costs ~3.8% of scanner time.
 * Removing it would mean compiling this scanner twice from a template,
 * one instantiation per stride -- considered and declined as not worth
 * the structure. */

/* One input unit into the caller's array, for %s, %c and %[.
 *
 * Four combinations, since BOTH sides vary -- input bytes or wide
 * characters, destination char or wchar_t (l-qualified):
 *
 *   bytes  -> char     copy      (fscanf  "%s")
 *   bytes  -> wchar_t  mbrtowc   (fscanf  "%ls", wide_put above)
 *   wide   -> wchar_t  copy      (fwscanf "%ls")
 *   wide   -> char     wcrtomb   (fwscanf "%s")
 *
 * *nn counts ELEMENTS STORED, not units read: one wide character can be
 * four bytes, one multibyte character two wchar_t (a surrogate pair
 * here).  The field width counts units read, kept separately.
 *
 * Returns 0, or -1 for an encoding error ([EILSEQ]). */
/* dst is deliberately not marked nonnull: every store through it is
 * behind `if (assign)`, and assign == 0 is fscanf.html's own '*'
 * assignment-suppression convention, not an omitted check. */
static int store_unit(int wide_in, int c, void *dst, int *nn, mbstate_t *mbs,
                      int assign, int wide_out) __attribute__((nonnull(4)));
static int store_unit(int wide_in, int c, void *dst, int *nn, mbstate_t *mbs, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
                      int assign, int wide_out) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	if (!wide_in) {
		if (wide_out) return wide_put(c, (wchar_t *)dst, nn, mbs, assign);
		if (assign) ((char *)dst)[*nn] = (char)c;
		(*nn)++;
		return 0;
	}
	if (wide_out) {
		if (assign) ((wchar_t *)dst)[*nn] = (wchar_t)c;
		(*nn)++;
		return 0;
	}
	{
		char buf[MB_LEN_MAX];
		size_t r = wcrtomb(buf, (wchar_t)c, mbs);
		if (r == (size_t)-1) return -1;
		/* r == 0: a high surrogate held for its partner; mbsinit()
		 * reports the debt if the field ends here. */
		if (assign && r)
			for (size_t i = 0; i < r; i++) ((char *)dst)[*nn + i] = buf[i];
		*nn += (int)r;
		return 0;
	}
}

/* How many elements an allocating destination must have room for before
 * the next store_unit(), given that nn are already in it.  One INPUT
 * unit is not one stored element -- wide -> char emits up to
 * MB_LEN_MAX bytes, bytes -> wchar_t up to two wchar_t (a surrogate
 * pair) -- so the headroom is a whole unit's worth plus the terminator
 * %s and %[ still owe. */
#define ALLOC_HEAD(nn) ((nn) + MB_LEN_MAX + 1)

/* The null that terminates %s and %[ (never %c), in the width the
 * destination actually has.  Unlike store_unit(), dst here is
 * dereferenced unconditionally -- both branches write through it. */
static void store_term(void *dst, int nn, int wide_out) __attribute__((nonnull(1)));
static void store_term(void *dst, int nn, int wide_out) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	if (wide_out) ((wchar_t *)dst)[nn] = 0;
	else ((char *)dst)[nn] = 0;
}

/* Membership for a %[ scanset member the 256-entry table cannot hold.
 * Only reachable from a wide format, where a scanset may name
 * characters above 0xff; the table still answers everything below.
 * The range rule mirrors this file's own: a '-' that is neither first
 * nor immediately before the closing ']' makes a range of the
 * characters either side of it.
 *
 * Takes the scanset's length rather than an end pointer -- computed
 * once by the caller as `setend - setstart`, positions of the same
 * cursor `fp` -- so this function's body is a locally traceable
 * derivation rather than trusting that a `b`/`e` pair shares an
 * object. */
/* b is nonnull: `e = b + blen;` needs a real pointer value even at
 * blen == 0 (ISO 7.24.1p2's "still valid at n == 0" convention). */
static int wset_has(const char *b, size_t blen, size_t st, unsigned c) __attribute__((nonnull(1)));
static int wset_has(const char *b, size_t blen, size_t st, unsigned c) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	const char *q, *e = b + blen;
	for (q = b; q < e; q += st) {
		unsigned x = gf(q, st);
		if (x == '-' && q != b && q + st < e) {
			unsigned lo = gf(q - st, st), hi = gf(q + st, st);
			if (c >= lo && c <= hi) return 1;
			q += st;
			continue;
		}
		if (x == c) return 1;
	}
	return 0;
}

/* fmt is nonnull (dereferenced by the main loop's own gf()); f is left
 * unmarked -- this function only stores it via sc_init(), never
 * dereferences it directly. */
static int vfscanf_st(FILE *f, const char *fmt, va_list ap, size_t st) __attribute__((nonnull(2)));
static int vfscanf_st(FILE *f, const char *fmt, va_list ap, size_t st)
{
	int nmatched = 0, gotEOF = 0, ilseq = 0, oom = 0;
	const char *fp = fmt;
	int c = 0;
	struct sc sc;

	sc_init(&sc, f, st != 1);
	for (; gf(fp, st); fp += st) {
		if (isspace((int)gf(fp, st))) {
			c = skipspace(&sc);
			unrd(&sc, c);
			continue;
		}
		if (gf(fp, st) != '%') {
			c = rd(&sc);
			if (c == EOF) { gotEOF = 1; goto done; }
			if ((unsigned)c != gf(fp, st)) { unrd(&sc, c); goto done; }
			continue;
		}
		fp += st;
		if (gf(fp, st) == '%') {
			c = rd(&sc);
			if (c == EOF) { gotEOF = 1; goto done; }
			if (c != '%') { unrd(&sc, c); goto done; }
			continue;
		}

		{
			int assign = 1, width = -1, lm = LM_NONE, alloc = 0;
			if (gf(fp, st) == '*') { assign = 0; fp += st; }
			while (gf(fp, st) >= '0' && gf(fp, st) <= '9') {
				int digit = (int)(gf(fp, st) - '0');
				if (width < 0) width = 0;
				if (width > (INT_MAX - digit) / 10) width = INT_MAX;
				else width = width * 10 + digit;
				fp += st;
			}
			/* 'm' (fscanf.html's assignment-allocation character) sits
			 * between the field width and length modifier; scanning it
			 * in the same loop as the modifiers also accepts "%lms" for
			 * the "%mls" the page spells out.  It means something only
			 * to s/c/[; other conversions ignore it rather than
			 * inventing a diagnostic for what the page leaves
			 * undefined. */
			for (;;) {
				if (gf(fp, st) == 'm') { alloc = 1; fp += st; }
				else if (gf(fp, st) == 'h') { lm = lm == LM_h ? LM_hh : LM_h; fp += st; }
				else if (gf(fp, st) == 'l') { lm = lm == LM_l ? LM_ll : LM_l; fp += st; }
				else if (gf(fp, st) == 'j') { lm = LM_j; fp += st; }
				else if (gf(fp, st) == 'z') { lm = LM_z; fp += st; }
				else if (gf(fp, st) == 't') { lm = LM_t; fp += st; }
				else if (gf(fp, st) == 'L') { lm = LM_L; fp += st; }
				else break;
			}

			switch ((int)gf(fp, st)) {
			case 'd': case 'i': case 'u': case 'o': case 'x': case 'X': {
				int base = (gf(fp, st) == 'o') ? 8 : (gf(fp, st) == 'x' || gf(fp, st) == 'X') ? 16 : 10;
				int autodetect = gf(fp, st) == 'i';
				int issigned = gf(fp, st) == 'd' || gf(fp, st) == 'i';
				int neg = 0, any = 0, ovf = 0;
				unsigned long long uv = 0;
				struct fld fl;

				c = skipspace(&sc);
				if (c == EOF) { gotEOF = 1; goto done; }
				unrd(&sc, c);
				/* The field width counts every character of the
				 * item, the sign and any "0x" included. */
				fl.sc = &sc;
				fl.left = width;
				c = fld_get(&fl);
				if (c == '+' || c == '-') { neg = c == '-'; c = fld_get(&fl); }
				if ((autodetect || base == 16) && c == '0') {
					int c2 = fld_get(&fl);
					if (c2 == 'x' || c2 == 'X') {
						int c3 = fld_get(&fl);
						/* "0x" with no hex digit behind it is the
						 * whole item and a matching failure, not a
						 * "0" with the "x" handed back. */
						if (hexval(c3) < 0) { fld_unget(&fl, c3); goto done; }
						base = 16;
						c = c3;
					} else {
						any = 1;   /* the "0" is already a complete item */
						if (autodetect) base = 8;
						c = c2;
					}
				}
				if (autodetect && base != 16 && base != 8) base = 10;
				for (; c != EOF; c = fld_get(&fl)) {
					unsigned d;
					if (c >= '0' && c <= '9') d = (unsigned)(c - '0');
					else if (c >= 'a' && c <= 'z') d = (unsigned)(c - 'a' + 10);
					else if (c >= 'A' && c <= 'Z') d = (unsigned)(c - 'A' + 10);
					else break;
					if (d >= (unsigned)base) break;
					/* Every digit of the item is consumed, however
					 * many there are; a value too wide for the
					 * widest type saturates the way strtoull would
					 * rather than quietly wrapping. */
					if (uv > (ULLONG_MAX - d) / (unsigned)base) ovf = 1;
					else uv = uv * (unsigned)base + d;
					any = 1;
				}
				fld_unget(&fl, c);
				if (!any) goto done;
				if (ovf)
					uv = issigned ? (neg ? (unsigned long long)LLONG_MIN
					                     : (unsigned long long)LLONG_MAX)
					              : ULLONG_MAX;
				/* Negation is on the unsigned value: -(long long)uv is
				 * undefined for LLONG_MIN, while unsigned negation
				 * wraps modulo 2**64 (C99 6.2.5p9) as wanted. */
				else if (neg) uv = __neg_mag(uv);
				if (assign) {
					switch (lm) {
					case LM_hh: *(unsigned char *)va_arg(ap, void *) = (unsigned char)uv; break;
					case LM_h:  *(unsigned short *)va_arg(ap, void *) = (unsigned short)uv; break;
					case LM_l:  *(unsigned long *)va_arg(ap, void *) = (unsigned long)uv; break;
					case LM_ll: case LM_j: *(unsigned long long *)va_arg(ap, void *) = uv; break;
					case LM_z: *(size_t *)va_arg(ap, void *) = (size_t)uv; break;
					case LM_t: *(ptrdiff_t *)va_arg(ap, void *) = (ptrdiff_t)uv; break;
					default: *(unsigned int *)va_arg(ap, void *) = (unsigned int)uv; break;
					}
					nmatched++;
				}
				break;
			}
			case 'f': case 'e': case 'E': case 'g': case 'G': case 'a': case 'A': {
				struct fld fl;
				struct nbuf nb;
				int r;

				c = skipspace(&sc);
				if (c == EOF) { gotEOF = 1; goto done; }
				unrd(&sc, c);
				fl.sc = &sc;
				fl.left = width;
				nb_init(&nb);
				r = scanfloat(&fl, &nb);
				if (r <= 0) {
					/* r < 0 is out of memory staging the field,
					 * not a matching failure: the item may well
					 * have matched and there is no way to know. */
					if (r < 0) { scandrain(&fl); oom = 1; }
					nb_done(&nb);
					goto done;
				}
				nb.p[nb.len] = 0;
				if (assign) {
					/* The staged text is a complete subject
					 * sequence, so each of these converts all of
					 * it, in the destination's own precision. */
					if (lm == LM_L) *(long double *)va_arg(ap, void *) = strtold(nb.p, 0);
					else if (lm == LM_l) *(double *)va_arg(ap, void *) = strtod(nb.p, 0);
					else *(float *)va_arg(ap, void *) = strtof(nb.p, 0);
					nmatched++;
				}
				nb_done(&nb);
				break;
			}
			case 's': {
				/* One va_arg for both widths (char * / wchar_t *, same
				 * representation here).  With 'm' the argument is one
				 * indirection further out (char ** / wchar_t **),
				 * naming where to leave the allocated buffer -- so
				 * `arg` and `dst` differ from here on. */
				void *arg = assign ? va_arg(ap, void *) : 0;
				int wout = lm == LM_l;
				int alc = alloc && assign;
				struct abuf ab;
				void *dst = alc ? 0 : arg;
				mbstate_t mbs;
				int nn = 0, nu = 0;   /* elements stored; units read */
				ab_init(&ab, wout ? (int)sizeof(wchar_t) : 1);
				memset(&mbs, 0, sizeof mbs);
				c = skipspace(&sc);
				if (c == EOF) { gotEOF = 1; goto done; }
				for (; c != EOF && !isspace(c) && (width < 0 || nu < width); c = rd(&sc)) {
					if (alc) {
						if (!ab_room(&ab, ALLOC_HEAD(nn))) { oom = 1; ab_free(&ab); goto done; }
						dst = ab.p;   /* re-read: growing may have moved it */
					}
					if (store_unit(sc.wide, c, dst, &nn, &mbs, assign, wout) < 0) { ilseq = 1; ab_free(&ab); goto done; }
					nu++;
				}
				unrd(&sc, c);
				/* a sequence left half-finished is an encoding error
				 * too: there are no more units that could complete it */
				if (!mbsinit(&mbs)) { ilseq = 1; ab_free(&ab); goto done; }
				if (nu == 0) { ab_free(&ab); goto done; }
				if (alc) { store_term(ab.p, nn, wout); ab_give(&ab, arg, nn + 1); nmatched++; }
				else if (assign) { store_term(dst, nn, wout); nmatched++; }
				break;
			}
			case 'c': {
				/* fscanf.html/fwscanf.html: the field width counts INPUT
				 * UNITS (bytes or wide characters) in both, and the l
				 * qualifier changes what is stored, not what the width
				 * counts.  (C99 is arguably read the other way for %lc;
				 * this suite audits against POSIX.)  No null is added,
				 * so an 'm' buffer is sized to exactly what was stored. */
				void *arg = assign ? va_arg(ap, void *) : 0;
				int wout = lm == LM_l;
				int alc = alloc && assign;
				struct abuf ab;
				void *dst = alc ? 0 : arg;
				mbstate_t mbs;
				int w = width < 0 ? 1 : width, nu, nn = 0;
				ab_init(&ab, wout ? (int)sizeof(wchar_t) : 1);
				memset(&mbs, 0, sizeof mbs);
				for (nu = 0; nu < w; nu++) {
					c = rd(&sc);
					if (c == EOF) break;
					if (alc) {
						if (!ab_room(&ab, ALLOC_HEAD(nn))) { oom = 1; ab_free(&ab); goto done; }
						dst = ab.p;   /* re-read: growing may have moved it */
					}
					if (store_unit(sc.wide, c, dst, &nn, &mbs, assign, wout) < 0) { ilseq = 1; ab_free(&ab); goto done; }
				}
				if (nu == 0) { gotEOF = 1; ab_free(&ab); goto done; }
				if (!mbsinit(&mbs)) { ilseq = 1; ab_free(&ab); goto done; }
				if (nu < w) { gotEOF = 1; ab_free(&ab); goto done; }
				if (alc) ab_give(&ab, arg, nn);
				if (assign) nmatched++;
				break;
			}
			case '[': {
				unsigned char set[256] = {0};
				/* One va_arg for both widths (char * or wchar_t *, same
				 * representation here), fetched once and cast at the
				 * point of use, with a further indirection when 'm' is
				 * present. */
				void *arg = assign ? va_arg(ap, void *) : 0;
				int wout = lm == LM_l;
				int alc = alloc && assign;
				struct abuf ab;
				void *dst = alc ? 0 : arg;
				mbstate_t mbs;
				int neg = 0, nn = 0, nu = 0, anyhigh = 0;
				const char *setstart, *setend;
				ab_init(&ab, wout ? (int)sizeof(wchar_t) : 1);
				fp += st;
				if (gf(fp, st) == '^') { neg = 1; fp += st; }
				setstart = fp;
				{
					const char *start = fp;
					do {
						if (gf(fp, st) == '-' && gf(fp + st, st) && gf(fp + st, st) != ']' && fp != start) {
							unsigned a = gf(fp - st, st), b = gf(fp + st, st), k;
							if (a < 256 && b < 256) for (k = a; k < b + 1; k++) set[k] = 1;
							else anyhigh = 1;
							fp += 2 * st;
						} else {
							if (gf(fp, st) < 256) set[gf(fp, st)] = 1;
							else anyhigh = 1;
							fp += st;
						}
					} while (gf(fp, st) && gf(fp, st) != ']');
					/* fp now at the closing ']'; the outer loop steps past it */
				}
				setend = fp;
				memset(&mbs, 0, sizeof mbs);
				c = rd(&sc);
				while (c != EOF
				       && (((unsigned)c < 256 ? set[c] != 0
				            : anyhigh && wset_has(setstart, (size_t)(setend - setstart), st, (unsigned)c)) != neg)
				       && (width < 0 || nu < width)) {
					if (alc) {
						if (!ab_room(&ab, ALLOC_HEAD(nn))) { oom = 1; ab_free(&ab); goto done; }
						dst = ab.p;   /* re-read: growing may have moved it */
					}
					if (store_unit(sc.wide, c, dst, &nn, &mbs, assign, wout) < 0) { ilseq = 1; ab_free(&ab); goto done; }
					nu++;
					c = rd(&sc);
				}
				unrd(&sc, c);
				if (!mbsinit(&mbs)) { ilseq = 1; ab_free(&ab); goto done; }
				if (nu == 0) { ab_free(&ab); if (c == EOF) gotEOF = 1; goto done; }
				if (alc) { store_term(ab.p, nn, wout); ab_give(&ab, arg, nn + 1); nmatched++; }
				else if (assign) { store_term(dst, nn, wout); nmatched++; }
				break;
			}
			case 'p': {
				void **pp = assign ? va_arg(ap, void **) : 0;
				unsigned long long uv = 0; int any = 0;
				c = skipspace(&sc);
				if (c == EOF) { gotEOF = 1; goto done; }
				if (c == '0') { int c2 = rd(&sc); if (c2 == 'x' || c2 == 'X') c = rd(&sc); else unrd(&sc, c2); }
				for (; c != EOF; c = rd(&sc)) {
					int d;
					if (c >= '0' && c <= '9') d = c - '0';
					else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
					else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
					else break;
					uv = uv * 16 + (unsigned)d; any = 1;
				}
				unrd(&sc, c);
				if (!any) goto done;
				/* %p's whole contract (C11 7.21.6.2p12) is turning text
				 * back into a pointer; no compile-time provenance is
				 * possible for the conversion specifier itself. */
				if (assign) {
					*pp = unsafe_assume_valid_pointer((void *)(uintptr_t)uv);
					nmatched++;
				}
				break;
			}
			case 'n':
				if (assign) {
					/* %n never counts toward the return value */
					switch (lm) {
					case LM_hh: *(signed char *)va_arg(ap, void *) = (signed char)sc.nread; break;
					case LM_h: *(short *)va_arg(ap, void *) = (short)sc.nread; break;
					case LM_l: *(long *)va_arg(ap, void *) = sc.nread; break;
					case LM_ll: case LM_j: *(long long *)va_arg(ap, void *) = sc.nread; break;
					case LM_z: *(size_t *)va_arg(ap, void *) = (size_t)sc.nread; break;
					case LM_t: *(ptrdiff_t *)va_arg(ap, void *) = sc.nread; break;
					default: *(int *)va_arg(ap, void *) = sc.nread; break;
					}
				}
				break;
			default:
				break;
			}
		}
	}
done:
	if (sc.ilseq) ilseq = 1;
	sc_done(&sc);
	/* [EILSEQ] is a READ error, not a matching failure: the stream's
	 * error indicator must be set so ferror() can tell it apart from
	 * plain end-of-file. */
	if (ilseq) { f->err = 1; errno = EILSEQ; return EOF; }
	/* [ENOMEM]: the 'm' assignment-allocation character or the numeric
	 * staging buffer failed to allocate.  Unlike [EILSEQ], the stream's
	 * error indicator is NOT set -- nothing went wrong reading it, only
	 * with this function's own allocation. */
	if (oom) { errno = ENOMEM; return EOF; }
	return (nmatched == 0 && gotEOF) ? EOF : nmatched;
}

int __vfscanf(FILE *f, const char *fmt, va_list ap)
{
	return vfscanf_st(f, fmt, ap, 1);
}

int vfscanf(FILE *__restrict f, const char *__restrict fmt, __isoc_va_list ap)
{
	return __vfscanf(f, fmt, ap);
}
int vscanf(const char *__restrict fmt, __isoc_va_list ap)
{
	return __vfscanf(stdin, fmt, ap);
}

/* s is nonnull (`mf.mem_len = strlen(s);`). */
static int vsscanf_impl(const char *s, const char *fmt, va_list ap) __attribute__((nonnull(1, 2)));
static int vsscanf_impl(const char *s, const char *fmt, va_list ap) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	FILE mf; // NOLINT(cert-fio38-c,misc-non-copyable-objects) -- implementation-owned transient memory-stream adapter is constructed from scratch, not copied
	int r;
	memset(&mf, 0, sizeof mf);
	mf.fd = -1;
	mf.pid = -1;
	mf.is_mem = 1;
	mf.readable = 1;
	mf.mem_buf = (unsigned char *)s;
	mf.mem_len = strlen(s);
	mf.mem_size = mf.mem_len;
	r = __vfscanf(&mf, fmt, ap);
	/* __fill gives even a memory FILE a read buffer, and this local one
	 * never sees fclose, so freeing it is ours to do. */
	free(mf.buf);
	return r;
}

int vsscanf(const char *__restrict s, const char *__restrict fmt, __isoc_va_list ap)
{
	return vsscanf_impl(s, fmt, ap);
}

int fscanf(FILE *__restrict f, const char *__restrict fmt, ...)
{
	va_list ap; int r;
	va_start(ap, fmt);
	r = __vfscanf(f, fmt, ap);
	va_end(ap);
	return r;
}
int scanf(const char *__restrict fmt, ...)
{
	va_list ap; int r;
	va_start(ap, fmt);
	r = __vfscanf(stdin, fmt, ap);
	va_end(ap);
	return r;
}
int sscanf(const char *__restrict s, const char *__restrict fmt, ...)
{
	va_list ap; int r;
	va_start(ap, fmt);
	r = vsscanf_impl(s, fmt, ap);
	va_end(ap);
	return r;
}

/* ------------------------------------------------------------------
 * The wide family: fwscanf.html.  Same scanner, stride sizeof(wchar_t),
 * struct sc reading wide characters instead of bytes.
 * ------------------------------------------------------------------ */

int __vfwscanf(FILE *f, const wchar_t *fmt, va_list ap)
{
	return vfscanf_st(f, (const char *)fmt, ap, (int)sizeof(wchar_t));
}

/* swscanf() reads a wchar_t array IN PLACE: the memory FILE points
 * straight at the caller's string with the wmem flag set, so
 * src/stdio/wide.c's reader takes whole wchar_t out of it rather than
 * decoding bytes -- no copy or allocation for a buffer sized by the
 * caller's input.  The cast away from const is safe the same way
 * fmemopen()'s read-only mode is: mf.writable is 0. */
static int vswscanf_impl(const wchar_t *s, const wchar_t *fmt, va_list ap) __attribute__((nonnull(1, 2)));
static int vswscanf_impl(const wchar_t *s, const wchar_t *fmt, va_list ap) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	FILE mf; // NOLINT(cert-fio38-c,misc-non-copyable-objects) -- implementation-owned transient wide memory-stream adapter is constructed from scratch, not copied
	int r;
	memset(&mf, 0, sizeof mf);
	mf.fd = -1;
	mf.pid = -1;
	mf.is_mem = 1;
	mf.wmem = 1;
	mf.wide = 1;
	mf.readable = 1;
	mf.mem_buf = (unsigned char *)(uintptr_t)s;
	mf.mem_len = wcslen(s) * sizeof(wchar_t);
	mf.mem_size = mf.mem_len;
	r = vfscanf_st(&mf, (const char *)fmt, ap, (int)sizeof(wchar_t));
	/* Same as vsscanf_impl: __fill gives even a memory FILE a read
	 * buffer, and this one never sees fclose. */
	free(mf.buf);
	return r;
}

int vfwscanf(FILE *__restrict f, const wchar_t *__restrict fmt, __isoc_va_list ap)
{
	return __vfwscanf(f, fmt, ap);
}
int vwscanf(const wchar_t *__restrict fmt, __isoc_va_list ap)
{
	return __vfwscanf(stdin, fmt, ap);
}
int vswscanf(const wchar_t *__restrict s, const wchar_t *__restrict fmt, __isoc_va_list ap)
{
	return vswscanf_impl(s, fmt, ap);
}

int fwscanf(FILE *__restrict f, const wchar_t *__restrict fmt, ...)
{
	va_list ap; int r;
	va_start(ap, fmt);
	r = __vfwscanf(f, fmt, ap);
	va_end(ap);
	return r;
}
int wscanf(const wchar_t *__restrict fmt, ...)
{
	va_list ap; int r;
	va_start(ap, fmt);
	r = __vfwscanf(stdin, fmt, ap);
	va_end(ap);
	return r;
}
int swscanf(const wchar_t *__restrict s, const wchar_t *__restrict fmt, ...)
{
	va_list ap; int r;
	va_start(ap, fmt);
	r = vswscanf_impl(s, fmt, ap);
	va_end(ap);
	return r;
}

// NOLINTEND(misc-include-cleaner)
