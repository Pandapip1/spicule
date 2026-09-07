/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * strfmon() and strfmon_l(), whose conversion grammar was added after
 * the original fuzzing inventory.  As with fuzz_printf.c, raw bytes are
 * not used as a variadic format: a format that asks for an argument the
 * harness did not pass has undefined behaviour in the caller.  Instead
 * the input drives one fully defined monetary conversion -- flags, fill,
 * width, left/right precision and national/international form -- and the
 * harness passes the corresponding double.
 *
 * Guard bytes enforce maxsize even in UBSan-only mode.  The locale form
 * must agree byte-for-byte with the ordinary form because spicule has one
 * immutable locale, and a successful return must name the complete,
 * NUL-terminated result inside the advertised buffer.
 */
#include <monetary.h>
#include <locale.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

extern void oracle_mismatch_i(const char *, const char *, long long, long long);
extern void oracle_mismatch_s(const char *, const char *, const char *, const char *);

#define CAP   256
#define PAD   16
#define GUARD 0xc3

struct rd { const unsigned char *p; size_t n, i; };
static unsigned char u8(struct rd *r) { return r->i < r->n ? r->p[r->i++] : 0; }
static uint64_t u64(struct rd *r)
{
	uint64_t v = 0;
	int i;
	for (i = 0; i < 8; i++) v = (v << 8) | u8(r);
	return v;
}

static size_t put_u64(char *p, uint64_t v)
{
	char rev[24];
	size_t n = 0, i = 0;
	do { rev[n++] = (char)('0' + v % 10); v /= 10; } while (v);
	while (n) p[i++] = rev[--n];
	return i;
}

struct outbuf { unsigned char mem[PAD + CAP + PAD]; };

static char *prepare(struct outbuf *b)
{
	memset(b->mem, GUARD, sizeof b->mem);
	return (char *)b->mem + PAD;
}

static void check(const char *what, const char *fmt, const struct outbuf *b,
	              size_t cap, ssize_t rc)
{
	size_t i;
	const char *out = (const char *)b->mem + PAD;

	for (i = 0; i < PAD; i++)
		if (b->mem[i] != GUARD)
			oracle_mismatch_i(what, fmt, (long long)i, GUARD);
	for (i = PAD + cap; i < sizeof b->mem; i++)
		if (b->mem[i] != GUARD)
			oracle_mismatch_i(what, fmt, (long long)(i - PAD - cap), GUARD);
	if (rc >= 0) {
		if ((size_t)rc >= cap)
			oracle_mismatch_i("strfmon success exceeds maxsize", fmt, rc,
			                  (long long)cap);
		else if (out[rc] != 0 || strlen(out) != (size_t)rc)
			oracle_mismatch_i("strfmon return does not describe its string",
			                  fmt, rc, (long long)strlen(out));
	}
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	struct rd r = { data, size, 0 };
	struct outbuf a, b;
	char fmt[160], *ao, *bo;
	size_t k = 0, cap;
	unsigned char flags, shape;
	uint64_t bits;
	double value;
	ssize_t ar, br;
	int ae, be;
	locale_t loc;

	if (size < 4) return 0;
	cap = u8(&r) % (CAP + 1);
	flags = u8(&r);
	shape = u8(&r);

	if (shape & 1) fmt[k++] = (char)('a' + u8(&r) % 26);
	fmt[k++] = '%';
	if (flags & 1) { fmt[k++] = '='; fmt[k++] = (char)(33 + u8(&r) % 94); }
	if (flags & 2) fmt[k++] = '^';
	if (flags & 4) fmt[k++] = (flags & 8) ? '(' : '+';
	if (flags & 16) fmt[k++] = '!';
	if (flags & 32) fmt[k++] = '-';
	if (shape & 2) k += put_u64(fmt + k, (shape & 4) ? u64(&r) : u8(&r));
	if (shape & 8) {
		fmt[k++] = '#';
		k += put_u64(fmt + k, (shape & 16) ? u64(&r) : u8(&r));
	}
	if (shape & 32) {
		fmt[k++] = '.';
		k += put_u64(fmt + k, (shape & 64) ? u64(&r) : u8(&r));
	}
	fmt[k++] = (flags & 64) ? 'i' : 'n';
	if (flags & 128) { fmt[k++] = '%'; fmt[k++] = '%'; }
	if (shape & 128) fmt[k++] = (char)('A' + u8(&r) % 26);
	fmt[k] = 0;

	bits = u64(&r);
	memcpy(&value, &bits, sizeof value);
	ao = prepare(&a);
	bo = prepare(&b);

	errno = 0;
	ar = strfmon(ao, cap, fmt, value);
	ae = errno;
	check("strfmon wrote outside maxsize", fmt, &a, cap, ar);

	loc = newlocale(LC_ALL_MASK, "C", (locale_t)0);
	if (!loc) return 0;
	errno = 0;
	br = strfmon_l(bo, cap, loc, fmt, value);
	be = errno;
	check("strfmon_l wrote outside maxsize", fmt, &b, cap, br);
	freelocale(loc);

	if (ar != br)
		oracle_mismatch_i("strfmon_l return differs in the C locale", fmt, ar, br);
	if (ar >= 0 && memcmp(ao, bo, (size_t)ar + 1) != 0)
		oracle_mismatch_s("strfmon_l output differs in the C locale", fmt, ao, bo);
	if (ar < 0 && (ae != E2BIG || be != E2BIG))
		oracle_mismatch_i("defined strfmon format failed without E2BIG",
		                  fmt, ae, E2BIG);
	return 0;
}
