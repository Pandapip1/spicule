/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Covers the conversion specifiers programs actually use in practice
 * (%Y %m %d %H %M %S %A %a %B %b %j %p %Z %z %% plus the common
 * composites %c %x %X %D %F %T %R %r, the odds and ends %C %e %I %n %s %t
 * %u %w %y, and the week-number family %U %W %V %G %g -- the last three
 * of those are ISO 8601 week-based year/week, computed by
 * time_impl.h's __iso_week()/__iso_weeks_in_year()).  The numeric year
 * conversions consume the '+' and '0' flags and field widths used by
 * POSIX for extended years.  The locale-alternate %E/%O modifiers need
 * no separate data -- this target has only
 * the "C" locale, and %E/%O are defined to fall back to their
 * non-alternate form in the C locale anyway, so there is nothing an
 * alternate form could do here that the base specifier doesn't already.
 * An unrecognized %<letter> is passed through literally, which is what
 * several other libcs do rather than silently eating input.
 *
 * POSIX strftime returns 0 (buffer contents unspecified) if the result
 * including the NUL wouldn't fit in max bytes, rather than truncating
 * like snprintf; PUT_CH below detects that and bails to `done` with
 * overflow set.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <time.h>
#include <string.h>
#include <limits.h>
#include "time_impl.h"

/* out is required: `out[n++] = ...`/`out[n] = 0;` are unconditional
 * whenever the computed digit count fits (`needed < out_size`), with no
 * NULL check of out itself, and every one of this file's own call sites
 * passes `s + pos` where s is do_strftime()'s own (now-required) buffer
 * -- never NULL, since pointer arithmetic on a non-null pointer stays
 * non-null. */
static int format_number(char *out, size_t out_size, long long value,
	int width, int plus, int automatic_plus) __attribute__((nonnull(1)));
static int format_number(char *out, size_t out_size, long long value, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
	int width, int plus, int automatic_plus)
{
	char rev[32];
	unsigned long long mag = value < 0
		? (unsigned long long)(-(value + 1)) + 1 : (unsigned long long)value;
	int digits = 0, sign, zeroes, needed, n = 0;

	do { rev[digits++] = (char)('0' + mag % 10); mag /= 10; } while (mag);
	sign = value < 0 || (plus && digits < width)
		|| (value >= 0 && automatic_plus && digits > automatic_plus);
	zeroes = width - digits - sign;
	if (zeroes < 0) zeroes = 0;
	needed = sign + zeroes + digits;
	if ((size_t)needed >= out_size) return -1;
	if (sign) out[n++] = value < 0 ? '-' : '+';
	while (zeroes--) out[n++] = '0';
	while (digits > 0) {
		digits--;
		out[n++] = rev[digits];
	}
	out[n] = 0;
	return n;
}

/* s/f/tm are all required. f is dereferenced unconditionally by the
 * main loop's own condition (`for (; *f; f++)`) as soon as this
 * function is called at all. s is written unconditionally at `done`
 * (`s[pos] = 0;`) on every non-overflow return, and directly by PUT_CH
 * whenever anything is emitted -- strftime() (this function's only real
 * caller) already refuses to call it at all when max == 0, so there is
 * always room for at least the check that decides overflow. tm is
 * dereferenced unconditionally near the top of the loop body
 * (`tm->tm_wday`/`tm->tm_mon`, computing wday/mon for every conversion
 * that follows) whenever the format string is non-empty; no caller in
 * this tree ever passes a NULL tm together with a non-empty format
 * (test/time.c and friends always pass a real `struct tm`).
 *
 * Marking s/f/tm here lets the checker explore deeper into this
 * function's own body than before, surfacing PUT_STR's own `*_s`
 * (`const char *_s = (str); while (*_s) PUT_CH(*_s++);`) as a new
 * finding at each of its call sites (%a/%A/%h/%b/%B/%p/%r). Not a
 * parameter of this function at all -- _s is PUT_STR's own macro-local,
 * always one of __spicule_day_name[_abbr]/__spicule_month_name[_abbr]'s
 * fixed, non-null string-literal elements (time_impl.h's own extern
 * arrays, populated by names.c) or the literal "AM"/"PM" -- sound by
 * hand, left as a residual rather than force-fit. */
static size_t do_strftime(char *restrict s, size_t max, const char *restrict f, const struct tm *restrict tm)
    __attribute__((nonnull(1, 3, 4)));
static size_t do_strftime(char *restrict s, size_t max, const char *restrict f, const struct tm *restrict tm)
{
	size_t pos = 0;
	int overflow = 0;

#define PUT_CH(c) do { if (pos + 1 >= max) { overflow = 1; goto done; } s[pos++] = (char)(c); } while (0)
#define PUT_STR(str) do { const char *_s = (str); while (*_s) PUT_CH(*_s++); } while (0)
#define PUT_NUM(v, w, pad) do { \
		long long _v = (long long)(v); \
		unsigned long _mag = _v < 0 \
			? (unsigned long)(-(_v + 1)) + 1 : (unsigned long)_v; \
		char _tmp[24]; int _n; \
		if (_v < 0) PUT_CH('-'); \
		_n = __num_digits(_tmp, (int)sizeof _tmp, _mag, (w), (pad)); \
		for (int _i = 0; _i < _n; _i++) PUT_CH(_tmp[_i]); \
	} while (0)

	for (; *f; f++) {
		int wday, mon, plus = 0, explicit_width = 0, width = 0;
		if (*f != '%') { PUT_CH(*f); continue; }
		f++;
		if (!*f) break;
		if (*f == '+') { plus = 1; f++; }
		if (*f == '0') f++;
		while (*f >= '0' && *f <= '9') {
			int digit = *f++ - '0';
			explicit_width = 1;
			if (width > (INT_MAX - digit) / 10) width = INT_MAX;
			else width = width * 10 + digit;
		}
		if (!*f) break;

		/* strftime.html: "If the alternative format or specification
		 * does not exist for the current locale (see ERA in XBD
		 * LC_TIME), the behavior shall be as if the unmodified
		 * conversion specification were used."  The POSIX/C locale
		 * defines no ERA, so every %E<x> and %O<x> falls back to
		 * plain %<x> here -- this target has only the C locale (this
		 * file's banner), so the fallback is unconditional rather
		 * than locale-dependent.  Consuming the E/O and re-dispatching
		 * on the following character is the whole fix: previously
		 * 'E'/'O' matched no case, so the switch below's `default`
		 * passed "%E"/"%O" through literally and left the base
		 * specifier that followed (e.g. the 'C' in "%EC") to be
		 * emitted as an unrelated, unescaped literal character. */
		if ((*f == 'E' || *f == 'O') && f[1]) f++;

		wday = (unsigned)tm->tm_wday < 7 ? tm->tm_wday : 0;
		mon = (unsigned)tm->tm_mon < 12 ? tm->tm_mon : 0;

		switch (*f) {
		case 'a': PUT_STR(__spicule_day_name_abbr[wday]); break;
		case 'A': PUT_STR(__spicule_day_name[wday]); break;
		case 'h': case 'b': PUT_STR(__spicule_month_name_abbr[mon]); break;
		case 'B': PUT_STR(__spicule_month_name[mon]); break;
		case 'c': {
			long long year = (long long)tm->tm_year + 1900;
			int n;
			PUT_STR(__spicule_day_name_abbr[wday]); PUT_CH(' ');
			PUT_STR(__spicule_month_name_abbr[mon]); PUT_CH(' ');
			PUT_NUM(tm->tm_mday, 2, ' '); PUT_CH(' ');
			PUT_NUM(tm->tm_hour, 2, '0'); PUT_CH(':');
			PUT_NUM(tm->tm_min, 2, '0'); PUT_CH(':');
			PUT_NUM(tm->tm_sec, 2, '0'); PUT_CH(' ');
			n = format_number(s + pos, max - pos, year, 4, 0, 4);
			if (n < 0) { overflow = 1; goto done; }
			pos += (size_t)n;
			break;
		}
		case 'C': {
			long long year = (long long)tm->tm_year + 1900;
			int n = format_number(s + pos, max - pos, __floordiv(year, 100),
				explicit_width ? width : 2, plus, 0);
			if (n < 0) { overflow = 1; goto done; }
			pos += (size_t)n;
			break;
		}
		case 'd': PUT_NUM(tm->tm_mday, 2, '0'); break;
		case 'D':
			PUT_NUM((long long)tm->tm_mon + 1, 2, '0'); PUT_CH('/');
			PUT_NUM(tm->tm_mday, 2, '0'); PUT_CH('/');
			PUT_NUM(((long long)tm->tm_year + 1900) % 100, 2, '0');
			break;
		case 'e': PUT_NUM(tm->tm_mday, 2, ' '); break;
		case 'F': {
			long long year = (long long)tm->tm_year + 1900;
			int yw = explicit_width ? (width > 6 ? width - 6 : 1) : 4;
			int n = format_number(s + pos, max - pos, year, yw, plus,
				explicit_width ? 0 : 4);
			if (n < 0) { overflow = 1; goto done; }
			pos += (size_t)n;
			PUT_CH('-');
			PUT_NUM((long long)tm->tm_mon + 1, 2, '0'); PUT_CH('-');
			PUT_NUM(tm->tm_mday, 2, '0');
			break;
		}
		case 'H': PUT_NUM(tm->tm_hour, 2, '0'); break;
		case 'I': { int h = tm->tm_hour % 12; PUT_NUM(h ? h : 12, 2, '0'); break; }
		case 'j': PUT_NUM((long long)tm->tm_yday + 1, 3, '0'); break;
		case 'm': PUT_NUM((long long)tm->tm_mon + 1, 2, '0'); break;
		case 'M': PUT_NUM(tm->tm_min, 2, '0'); break;
		case 'n': PUT_CH('\n'); break;
		case 'p': PUT_STR(tm->tm_hour < 12 ? "AM" : "PM"); break;
		case 'r':
			{ int h = tm->tm_hour % 12; PUT_NUM(h ? h : 12, 2, '0'); }
			PUT_CH(':'); PUT_NUM(tm->tm_min, 2, '0');
			PUT_CH(':'); PUT_NUM(tm->tm_sec, 2, '0');
			PUT_CH(' '); PUT_STR(tm->tm_hour < 12 ? "AM" : "PM");
			break;
		case 'R': PUT_NUM(tm->tm_hour, 2, '0'); PUT_CH(':'); PUT_NUM(tm->tm_min, 2, '0'); break;
		case 'S': PUT_NUM(tm->tm_sec, 2, '0'); break;
		case 't': PUT_CH('\t'); break;
		case 'T':
			PUT_NUM(tm->tm_hour, 2, '0'); PUT_CH(':');
			PUT_NUM(tm->tm_min, 2, '0'); PUT_CH(':');
			PUT_NUM(tm->tm_sec, 2, '0');
			break;
		case 'u': PUT_NUM(wday ? wday : 7, 1, '0'); break;
		case 'U': PUT_NUM(((long long)tm->tm_yday + 7 - wday) / 7, 2, '0'); break;
		case 'V': case 'G': case 'g': {
			long long iso_year;
			int iso_week;
			__iso_week((long long)tm->tm_year + 1900, tm->tm_yday, wday, &iso_year, &iso_week);
			if (*f == 'V') PUT_NUM(iso_week, 2, '0');
			else if (*f == 'G') {
				int n = format_number(s + pos, max - pos, iso_year,
					explicit_width ? width : 4, plus, explicit_width ? 0 : 4);
				if (n < 0) { overflow = 1; goto done; }
				pos += (size_t)n;
			}
			else PUT_NUM(__floormod(iso_year, 100), 2, '0');
			break;
		}
		case 'w': PUT_NUM(wday, 1, '0'); break;
		case 'W': PUT_NUM(((long long)tm->tm_yday + 7 - (wday ? wday - 1 : 6)) / 7, 2, '0'); break;
		case 'x':
			PUT_NUM((long long)tm->tm_mon + 1, 2, '0'); PUT_CH('/');
			PUT_NUM(tm->tm_mday, 2, '0'); PUT_CH('/');
			PUT_NUM(((long long)tm->tm_year + 1900) % 100, 2, '0');
			break;
		case 'X':
			PUT_NUM(tm->tm_hour, 2, '0'); PUT_CH(':');
			PUT_NUM(tm->tm_min, 2, '0'); PUT_CH(':');
			PUT_NUM(tm->tm_sec, 2, '0');
			break;
		case 'y': PUT_NUM(__floormod((long long)tm->tm_year + 1900, 100), 2, '0'); break;
		case 'Y': {
			int n = format_number(s + pos, max - pos,
				(long long)tm->tm_year + 1900, explicit_width ? width : 4,
				plus, explicit_width ? 0 : 4);
			if (n < 0) { overflow = 1; goto done; }
			pos += (size_t)n;
			break;
		}
		case 's': {
			struct tm copy = *tm;
			int n = format_number(s + pos, max - pos,
				(long long)mktime(&copy), 1, 0, 0);
			if (n < 0) { overflow = 1; goto done; }
			pos += (size_t)n;
			break;
		}
		case 'z': {
			long long off = tm->__tm_gmtoff;
			PUT_CH(off < 0 ? '-' : '+');
			if (off < 0) off = -off;
			PUT_NUM(off / 3600, 2, '0');
			PUT_NUM(off % 3600 / 60, 2, '0');
			break;
		}
		case 'Z': PUT_STR(tm->__tm_zone ? tm->__tm_zone : "UTC"); break;
		case '%': PUT_CH('%'); break;
		default: PUT_CH('%'); PUT_CH(*f); break;
		}
	}
done:
	if (overflow) return 0;
	s[pos] = 0;
	return pos;

#undef PUT_CH
#undef PUT_STR
#undef PUT_NUM
}

/* s/f/tm are deliberately NOT marked here, unlike do_strftime() above:
 * strftime()'s own body never dereferences any of the three itself, only
 * checks max and forwards all three unchanged, so there is nothing in
 * ITS OWN body for the attribute to describe -- the same "forwarded,
 * callee already owns the contract" shape as time.h's own ctime_r()/
 * clock_gettime() comments. */
size_t strftime(char *restrict s, size_t max, const char *restrict f, const struct tm *restrict tm)
{
	if (!max) return 0;
	return do_strftime(s, max, f, tm);
}

size_t strftime_l(char *restrict s, size_t max, const char *restrict f, const struct tm *restrict tm, locale_t loc)
{
	(void)loc;
	return strftime(s, max, f, tm);
}

// NOLINTEND(misc-include-cleaner)
