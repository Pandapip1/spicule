/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Named util_printf.c, not printf.c like src/internal/util.h's own
 * "src/util/<name>.c" convention would suggest: this tree already has a
 * src/stdio/printf.c (the C library's own, unrelated printf() family --
 * include/stdio.h), and `ar`'s member names are truncated basenames with
 * no directory component (src/util/mkdir_util.c's own comment says the
 * same about src/stat/mkdir.c), so two different objects both named
 * printf.o would silently shadow each other inside lib/libc.a -- whoever
 * lost would be invisible until something called the wrong one.
 * src/internal/util.h's own header comment lists this alongside
 * mkdir_util.c/chmod_util.c as the established way out.
 *
 * ---- What this implements: XCU printf(1p), not C's printf() ----------
 *
 * `printf format [argument...]` -- these are two genuinely different
 * things that happen to share a name and a conversion vocabulary.  C's
 * printf() takes typed varargs the compiler already knows the types of;
 * this printf(1p) is a shell utility where *every* argument is text
 * (argv is char*[]), so a "%d" here has to parse its argument string
 * into a number itself, and a malformed one is a real, specified error
 * (see arg_signed()/arg_unsigned()/arg_double() below), not undefined
 * behavior the way passing the wrong vararg type to C's printf() is.
 * printf(1p) also reuses `format` over the whole argument list rather
 * than consuming it once (see run_printf() below), and has its own %b
 * directive with its own escape table, distinct from \-escapes in
 * `format` itself.  None of that is expressible by handing `format` to
 * this library's own vprintf()/vsnprintf() -- so this file is a real,
 * standalone format-string interpreter, not a wrapper around one.
 *
 * The one deliberate exception: format_float() below still calls this
 * library's own snprintf() to turn one already-parsed `double` into
 * decimal digits for %f/%e/%g.  That is not the part that differs
 * between C's printf() and this one -- src/stdio/printf.c's own header
 * says its float conversions "are exact", and reimplementing a second,
 * probably-worse binary-to-decimal converter here to avoid one internal
 * call would not make this a more faithful printf(1p); it would just be
 * duplicated dtoa logic.  Every other conversion (the integer types,
 * %s, %c, %b, and the argument-cycling/escape-table logic around all of
 * them) is this file's own, for the reasons above.
 *
 * OPTIONS: none (printf(1p) OPTIONS: "None.").
 *
 * OPERANDS / ARGUMENT-CYCLING (printf(1p)):  "The format operand shall
 * be used as the format string described in ... except that ... The
 * format operand shall be reused as often as necessary to satisfy the
 * argument operands.  Any extra c or s conversion specifications shall
 * be evaluated ... as if a null string argument were supplied; other
 * extra conversion specifications shall be evaluated ... as if a zero
 * argument were supplied.  If the format operand contains no conversion
 * specifications and argument operands are still present, ... undefined."
 * run_printf() below resolves that last "undefined" case the same way
 * every other real implementation does: if a whole pass over `format`
 * consumes zero arguments while arguments remain, stop rather than
 * looping forever.
 *
 * FORMAT escape table (for \-sequences written directly in `format`,
 * distinct from %b's own table below): \\ \a \b \f \n \r \t \v, and
 * \ddd (one to three octal digits).  An unrecognized \X is undefined by
 * the standard; this leaves the backslash in the output rather than
 * silently eating it, so a typo is visible instead of vanishing.
 *
 * %b (printf(1p)-specific, distinct from %s): expands backslash escapes
 * *within the corresponding argument* using the same table as above,
 * plus \0ddd (zero to three octal digits, where plain \ddd is NOT
 * recognized inside a %b argument -- only \0ddd is, per printf(1p)'s
 * own table) and \c, which "shall be used to indicate that the
 * remaining arguments and portions of format are to remain unprocessed
 * and this utility exits" -- expand_b_arg() below returns 1 to request
 * exactly that immediate, whole-invocation stop.
 *
 * ARGUMENTS, numeric conversions (%d/%i/%o/%u/%x/%X/%f/%e/%g): "If the
 * leading character is a <quotation-mark> or <apostrophe>, the value
 * shall be the numeric value in the underlying codeset of the character
 * following the <quotation-mark> or <apostrophe>."  Otherwise the
 * argument "shall be evaluated as if it were the operand of a C
 * language integer constant expression" -- so "010" is octal 8 and
 * "0x10" is hex 16, matched here by parsing with strtol()/strtoul()
 * base 0.  An argument that is neither is a genuine, diagnosed error
 * (arg_signed()/arg_unsigned()/arg_double(): a message to stderr, the
 * value treated as 0 so the rest of the line still prints something
 * coherent, and the process's own exit status forced nonzero) -- never
 * a silent 0.  An *exhausted* argument (ran out because format was
 * reused more times than there were arguments) is NOT an error: that
 * one is the standard's own "treated as 0" case quoted above.
 *
 * Supported conversions: d, i, o, u, x, X, c, s, b, f, e, g, %, with the
 * usual flags (-, 0, +, space, #), a decimal field width and a
 * .precision -- enough to cover real printf(1p) usage (field-formatted
 * numbers and strings) without reimplementing every corner of C's own
 * conversion grammar (no *-width or *-precision from an argument, no
 * length modifiers -- meaningless here since every argument is already
 * text, not a typed vararg).  Any other conversion letter, or `%` not
 * followed by a recognized one, is a diagnosed error: XCU 1.4 lets a
 * standard utility diagnose anything the standard does not itself
 * define, and a silently-dropped or silently-literal "%q" would be a
 * wrong-looking-right answer instead.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "util.h"

/* ---- argument cursor ---------------------------------------------- */

struct argcur {
	char **argv;   /* argument operands, argv[0]..argv[n-1] */
	int n;
	int i;         /* next unconsumed index */
	int any_this_pass;
};

/* printf(1p): "extra c or s ... a null string ... other extra ...
 * zero" -- and, symmetrically, this project's own reading that a
 * *missing* argument (format reused past the end of the list) is the
 * same "as if" case, not a diagnosed error.  Returns 0 (meaning
 * "already exhausted, use the standard fallback") when nothing is
 * left, 1 with *out set when a real argument was consumed. */
static int arg_take(struct argcur *a, const char **out)
{
	if (a->i >= a->n) { *out = ""; return 0; }
	*out = a->argv[a->i++];
	a->any_this_pass = 1;
	return 1;
}

/* ---- numeric argument parsing (shared quote-char + C-constant rule) - */

static int g_status; /* sticky: any per-conversion error makes the whole run fail */

/* Every arg_signed()/arg_unsigned()/arg_double() call below is followed,
 * at its one call site, by exactly this same action on failure -- folded
 * in here so a genuine parse error can never be diagnosed once and
 * missed at another call site (see arg_signed()/arg_unsigned()/
 * arg_double() themselves for where this is invoked). */
static void numeric_error(const char *arg)
{
	__util_diagf("printf: %s: expected a numeric value\n", arg);
	g_status = 1;
}

static int leading_quote_char(const char *s, long *out)
{
	if ((s[0] == '\'' || s[0] == '"') && s[1] != 0) {
		*out = (long)(unsigned char)s[1];
		return 1;
	}
	return 0;
}

static int arg_signed(const char *s, long *out)
{
	char *end;
	long v;

	if (!*s) { *out = 0; return 0; } /* exhausted argument: standard's "0" case */
	if (leading_quote_char(s, &v)) { *out = v; return 0; }
	errno = 0;
	v = strtol(s, &end, 0);
	if (end == s || *end != 0) { *out = 0; numeric_error(s); return -1; }
	*out = v;
	return 0;
}

static int arg_unsigned(const char *s, unsigned long *out)
{
	char *end;
	long qv;
	unsigned long v;

	if (!*s) { *out = 0; return 0; }
	if (leading_quote_char(s, &qv)) { *out = (unsigned long)qv; return 0; }
	errno = 0;
	/* A leading '-' is accepted by strtoul() as wraparound, which is
	 * not what a shell script means by `printf %x -1` -- reject it
	 * explicitly rather than silently printing a huge unsigned value. */
	{
		const char *p = s;
		if (*p == '-') { *out = 0; numeric_error(s); return -1; }
	}
	v = strtoul(s, &end, 0);
	if (end == s || *end != 0) { *out = 0; numeric_error(s); return -1; }
	*out = v;
	return 0;
}

static int arg_double(const char *s, double *out)
{
	char *end;
	long qv;
	double v;

	if (!*s) { *out = 0.0; return 0; }
	if (leading_quote_char(s, &qv)) { *out = (double)qv; return 0; }
	errno = 0;
	v = strtod(s, &end);
	if (end == s || *end != 0) { *out = 0.0; numeric_error(s); return -1; }
	*out = v;
	return 0;
}

/* ---- format string's own \-escape table (not %b's) ------------------ */

static const char *format_escape(const char *s)
{
	/* s[0] == '\\' */
	switch (s[1]) {
	case '\\': putchar('\\'); return s + 2;
	case 'a': putchar('\a'); return s + 2;
	case 'b': putchar('\b'); return s + 2;
	case 'f': putchar('\f'); return s + 2;
	case 'n': putchar('\n'); return s + 2;
	case 'r': putchar('\r'); return s + 2;
	case 't': putchar('\t'); return s + 2;
	case 'v': putchar('\v'); return s + 2;
	default:
		if (s[1] >= '0' && s[1] <= '7') {
			int v = 0, n = 0;
			const char *p = s + 1;
			while (n < 3 && *p >= '0' && *p <= '7') { v = v * 8 + (*p - '0'); p++; n++; }
			putchar(v & 0xff);
			return p;
		}
		/* Undefined by the standard: keep the backslash visible
		 * rather than silently dropping it (see this file's header). */
		putchar('\\');
		return s + 1;
	}
}

/* ---- %b's own escape table (distinct from format_escape() above) ---- */

/* Returns 1 if \c was hit (the whole invocation must stop now). */
static int expand_b_arg(const char *s)
{
	for (; *s; s++) {
		if (*s != '\\') { putchar((unsigned char)*s); continue; }
		switch (s[1]) {
		case '\\': putchar('\\'); s++; break;
		case 'a': putchar('\a'); s++; break;
		case 'b': putchar('\b'); s++; break;
		case 'f': putchar('\f'); s++; break;
		case 'n': putchar('\n'); s++; break;
		case 'r': putchar('\r'); s++; break;
		case 't': putchar('\t'); s++; break;
		case 'v': putchar('\v'); s++; break;
		case 'c': return 1;
		case '0': {
			int v = 0, n = 0;
			const char *p = s + 2;
			while (n < 3 && *p >= '0' && *p <= '7') { v = v * 8 + (*p - '0'); p++; n++; }
			putchar(v & 0xff);
			s = p - 1;
			break;
		}
		default:
			/* Same "leave it visible" choice as format_escape(). */
			putchar('\\');
			break;
		}
	}
	return 0;
}

/* ---- one %-directive: flags/width/precision/conversion --------------- */

struct spec {
	int left, zero, plus, space, alt;
	int width;  /* -1 = absent */
	int prec;   /* -1 = absent */
	char conv;
};

static const char *parse_spec(const char *p, struct spec *sp)
{
	memset(sp, 0, sizeof *sp);
	sp->width = -1;
	sp->prec = -1;
	for (;;) {
		if (*p == '-') { sp->left = 1; p++; }
		else if (*p == '0') { sp->zero = 1; p++; }
		else if (*p == '+') { sp->plus = 1; p++; }
		else if (*p == ' ') { sp->space = 1; p++; }
		else if (*p == '#') { sp->alt = 1; p++; }
		else break;
	}
	/* Width/precision are clamped, not just parsed, for two reasons: an
	 * unbounded run of digits (`%99999999999999999999d`) would
	 * overflow `int` while accumulating (undefined behavior), and
	 * format_signed()/format_unsigned() below zero-pad a digit buffer
	 * out to `prec` characters in a fixed-size stack array -- an
	 * unclamped precision from attacker- or typo-controlled input would
	 * be a real stack buffer overflow, not just a cosmetic wraparound.
	 * SPEC_MAX is comfortably above any width/precision a real
	 * conversion ever needs (a double's longest %f rendering is a few
	 * hundred characters) and comfortably below where the digit buffers
	 * below stop being safe to write into. */
#define SPEC_MAX 1000
	if (*p >= '0' && *p <= '9') {
		int w = 0;
		while (*p >= '0' && *p <= '9') {
			int digit = *p - '0';
			if (w <= (SPEC_MAX - digit) / 10)
				w = w * 10 + digit;
			else
				w = SPEC_MAX;
			p++;
		}
		sp->width = w;
	}
	if (*p == '.') {
		int pr = 0;
		p++;
		while (*p >= '0' && *p <= '9') {
			int digit = *p - '0';
			if (pr <= (SPEC_MAX - digit) / 10)
				pr = pr * 10 + digit;
			else
				pr = SPEC_MAX;
			p++;
		}
		sp->prec = pr;
	}
	sp->conv = *p;
	if (*p) p++;
	return p;
}

/* sign/body padding shared by every conversion below. zero_ok gates
 * whether the '0' flag applies (it never does for %s/%c/%b, and it is
 * suppressed for numeric conversions whose precision was given -- the
 * same C rule src/stdio/printf.c's own formatter follows). */
static void emit_padded(const char *sign, const char *body, const struct spec *sp, int zero_ok)
{
	size_t slen = sign ? strlen(sign) : 0;
	size_t blen = strlen(body);
	size_t total = slen + blen;
	size_t pad = sp->width > 0 && (size_t)sp->width > total ?
		(size_t)sp->width - total : 0;

	if (sp->left) {
		if (sign && fputs(sign, stdout) < 0) g_status = 1;
		if (fputs(body, stdout) < 0) g_status = 1;
		while (pad > 0) { putchar(' '); pad--; }
	} else if (zero_ok && sp->zero) {
		if (sign && fputs(sign, stdout) < 0) g_status = 1;
		while (pad > 0) { putchar('0'); pad--; }
		if (fputs(body, stdout) < 0) g_status = 1;
	} else {
		while (pad > 0) { putchar(' '); pad--; }
		if (sign && fputs(sign, stdout) < 0) g_status = 1;
		if (fputs(body, stdout) < 0) g_status = 1;
	}
}

/* Sized for SPEC_MAX (parse_spec()'s clamp): a precision up to
 * SPEC_MAX zero-pads the digit buffer out to that many characters, so
 * the buffer has to be at least that big, not just big enough for a
 * 64-bit value's own ~20 digits. */
#define DIGBUF_MAX (SPEC_MAX + 32)

static void format_signed(const char *arg, const struct spec *sp)
{
	long v;
	unsigned long uv;
	char digs[DIGBUF_MAX];
	int n = 0;
	const char *sign = "";

	(void)arg_signed(arg, &v); /* on failure: diagnosed already, v left 0 */
	uv = v < 0 ? (unsigned long)(-(v + 1)) + 1UL : (unsigned long)v;
	if (v < 0) sign = "-";
	else if (sp->plus) sign = "+";
	else if (sp->space) sign = " ";

	if (uv == 0 && sp->prec == 0) {
		digs[0] = 0;
	} else {
		char tmp[DIGBUF_MAX];
		int t = 0;
		do { tmp[t++] = (char)('0' + uv % 10); uv /= 10; } while (uv);
		while (sp->prec > t) tmp[t++] = '0';
		while (t > 0) digs[n++] = tmp[--t];
		digs[n] = 0;
	}
	emit_padded(sign, digs, sp, sp->prec < 0);
}

static void format_unsigned(const char *arg, const struct spec *sp, int base, int upper) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	unsigned long v, orig;
	char tmp[DIGBUF_MAX], digs[DIGBUF_MAX];
	int t = 0, n = 0;
	const char *hex = upper ? "0123456789ABCDEF" : "0123456789abcdef";
	const char *prefix = "";

	(void)arg_unsigned(arg, &v); /* on failure: diagnosed already, v left 0 */
	orig = v;

	if (v == 0 && sp->prec == 0) {
		digs[0] = 0;
	} else {
		/* All callers use base 8, 10, or 16, so a nonzero value reaches
		 * zero well before this one-pass-per-value-bit guard. */
		unsigned bits_left = (unsigned)(sizeof v * CHAR_BIT);
		do {
			tmp[t++] = hex[v % (unsigned)base];
			v /= (unsigned)base;
			bits_left--;
		} while (v && bits_left > 0);
		while (sp->prec > t) tmp[t++] = '0';
		while (t > 0) digs[n++] = tmp[--t];
		digs[n] = 0;
	}
	/* alt flag (#): octal gets a leading zero unless the result
	 * already has one (a bare "0" already does, so it is left alone);
	 * hex gets an "0x"/"0X" prefix, but only for a genuinely nonzero
	 * value -- C99 7.19.6.1p6 and every real printf() agree a zero
	 * value never gets the 0x/0X prefix even under '#'. */
	if (sp->alt) {
		if (base == 8 && digs[0] != '0') prefix = "0"; /* digs[0]==0 (empty) also takes this branch: fine, an empty result plus "0" is exactly the one digit octal wants */
		else if (base == 16 && orig != 0) prefix = upper ? "0X" : "0x";
	}
	{
		/* +4: room for the longest prefix ("0x"/"0X") plus the NUL;
		 * snprintf() would truncate silently otherwise if digs ever
		 * grew to fill DIGBUF_MAX (a large -- but SPEC_MAX-clamped,
		 * so still bounded -- precision). */
		char withpfx[DIGBUF_MAX + 4];
		int wrote = snprintf(withpfx, sizeof withpfx, "%s%s", prefix, digs);
		if (wrote < 0 || (size_t)wrote >= sizeof withpfx) {
			withpfx[0] = 0;
			g_status = 1;
		}
		emit_padded("", withpfx, sp, sp->prec < 0);
	}
}

/* Not routed through emit_padded(): %s's argument can be arbitrarily
 * long and only a precision-bounded *prefix* of it is ever wanted, so
 * this writes directly from `arg` (length-bounded) instead of building
 * a NUL-terminated copy just to hand it to a strlen()-based helper. */
static void format_str(const char *arg, const struct spec *sp)
{
	size_t len = strlen(arg);
	size_t pad;

	if (sp->prec >= 0 && (size_t)sp->prec < len) len = (size_t)sp->prec;
	pad = sp->width > 0 && (size_t)sp->width > len ?
		(size_t)sp->width - len : 0;
	if (sp->left) {
		if (fwrite(arg, 1, len, stdout) != len) g_status = 1;
		while (pad > 0) { putchar(' '); pad--; }
	} else {
		while (pad > 0) { putchar(' '); pad--; }
		if (fwrite(arg, 1, len, stdout) != len) g_status = 1;
	}
}

static void format_char(const char *arg, const struct spec *sp)
{
	char c[2];
	if (!arg[0]) { /* exhausted argument: empty, per the standard's "null string" case */
		emit_padded(0, "", sp, 0);
		return;
	}
	c[0] = arg[0];
	c[1] = 0;
	emit_padded(0, c, sp, 0);
}

/* %f/%e/%g: the one place this file borrows this library's own,
 * already-exact float-to-decimal conversion -- see this file's header
 * for why that is not the same thing as wrapping the whole utility
 * around vprintf(). */
static void format_float(const char *arg, const struct spec *sp, char conv)
{
	double v;
	char subfmt[16];
	/* DBL_MAX has ~309 integer digits at %f; +SPEC_MAX covers the
	 * clamped worst-case fractional precision, +16 is slop for the
	 * point/sign/exponent/NUL. snprintf() below is memory-safe either
	 * way, but this keeps a pathological-but-valid `%.900f` from being
	 * silently truncated instead of merely bounded. */
	char buf[320 + SPEC_MAX + 16];
	int prec = sp->prec < 0 ? 6 : sp->prec;
	const char *sign = "";
	const char *body = buf;
	int n;

	(void)arg_double(arg, &v); /* on failure: diagnosed already, v left 0 */

	if (v < 0.0 || (v == 0.0 && 1.0 / v < 0.0)) { sign = "-"; v = -v; }
	else if (sp->plus) sign = "+";
	else if (sp->space) sign = " ";

	n = snprintf(subfmt, sizeof subfmt, "%%.%d%c", prec, conv);
	if (n < 0 || (size_t)n >= sizeof subfmt) {
		buf[0] = 0;
		g_status = 1;
	} else {
		n = snprintf(buf, sizeof buf, subfmt, v);
		if (n < 0 || (size_t)n >= sizeof buf) {
			buf[0] = 0;
			g_status = 1;
		}
	}
	emit_padded(sign, body, sp, sp->prec >= 0 ? 0 : 1);
}

/* ---- one pass over `format`, consuming arguments from `a` ----------- */

static int run_one_pass(const char *format, struct argcur *a)
{
	const char *p = format;

	a->any_this_pass = 0;
	while (*p) {
		if (*p == '\\') { p = format_escape(p); continue; }
		if (*p != '%') { putchar((unsigned char)*p); p++; continue; }
		if (p[1] == '%') { putchar('%'); p += 2; continue; }
		{
			struct spec sp;
			const char *arg;
			p = parse_spec(p + 1, &sp);
			switch (sp.conv) {
			case 'd': case 'i':
				arg_take(a, &arg);
				format_signed(arg, &sp);
				break;
			case 'o':
				arg_take(a, &arg);
				format_unsigned(arg, &sp, 8, 0);
				break;
			case 'u':
				arg_take(a, &arg);
				format_unsigned(arg, &sp, 10, 0);
				break;
			case 'x':
				arg_take(a, &arg);
				format_unsigned(arg, &sp, 16, 0);
				break;
			case 'X':
				arg_take(a, &arg);
				format_unsigned(arg, &sp, 16, 1);
				break;
			case 'c':
				arg_take(a, &arg);
				format_char(arg, &sp);
				break;
			case 's':
				arg_take(a, &arg);
				format_str(arg, &sp);
				break;
			case 'f': case 'e': case 'g':
				arg_take(a, &arg);
				format_float(arg, &sp, sp.conv);
				break;
			case 'b':
				arg_take(a, &arg);
				if (expand_b_arg(arg)) return 1; /* \c: stop everything */
				break;
			default:
				__util_diagf("printf: %%%c: invalid conversion\n",
					sp.conv ? sp.conv : '?');
				g_status = 1;
				return 1; /* malformed format: stop rather than guess */
			}
		}
	}
	return 0;
}

int __util_printf_main(int argc, char **argv)
{
	struct argcur a;
	const char *format;

	if (argc < 2) {
		__util_diagf("printf: missing operand\n");
		return 1;
	}
	format = argv[1];
	a.argv = argv + 2;
	a.n = argc - 2;
	a.i = 0;
	g_status = 0;

	/* printf(1p): reuse `format` until the argument list is exhausted;
	 * a pass that consumes nothing (no conversion in `format` at all,
	 * or every conversion is %%) still has to run exactly once even
	 * with zero arguments, but must not be allowed to loop forever if
	 * arguments remain and none of them are ever consumed. */
	do {
		if (run_one_pass(format, &a)) break;
	} while (a.i < a.n && a.any_this_pass);

	if (fflush(stdout) != 0) g_status = 1;
	return g_status;
}
