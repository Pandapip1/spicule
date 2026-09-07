/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The oracle: the host C library's answer to the same question, for the
 * harnesses that check spicule for *wrong results* rather than only for
 * memory errors.  strtod("1e442") returning NaN is not something a
 * sanitizer can see; a differential check is.
 *
 * This is the one file in fuzz/ compiled against the *host* headers, so
 * it cannot include anything of spicule's.  It also cannot just call
 * strtod(): spicule's strtod is linked into the same executable and would
 * win, and the oracle would be comparing spicule against itself.  dlsym on
 * libc.so.6 gets the real one -- spicule's definitions are built hidden, so
 * they are not in the dynamic symbol table and cannot be found this way.
 *
 * Reporting lives here too, and deliberately so: a harness must not format
 * a mismatch with spicule's own snprintf, which is itself under test.
 *
 * errno itself needs the same treatment as strtod: `errno` is
 * `*__errno_location()`, and spicule's harnesses link this file's object
 * directly against spicule's *.o (see Makefile), which defines its own
 * __errno_location.  The plain `errno` macro from <errno.h> would therefore
 * resolve, at static link time, straight to spicule's thread-local errno
 * rather than glibc's -- there is no dynamic symbol lookup involved for a
 * call to a symbol the static linker can already see defined in the same
 * executable, so RTLD-level tricks (LD_PRELOAD, RTLD_NEXT) do not even
 * enter into it.  spicule's __errno_location is hidden-visibility, so it is
 * absent from the dynamic symbol table; going through dlsym() on the
 * explicit libc.so.6 handle above (same as strtod et al.) reaches glibc's
 * real __errno_location and cannot see spicule's hidden one at all.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

typedef double (*strtod_fn)(const char *, char **);
typedef float (*strtof_fn)(const char *, char **);
typedef long long (*strtoll_fn)(const char *, char **, int);
typedef unsigned long long (*strtoull_fn)(const char *, char **, int);
typedef int *(*errno_loc_fn)(void);

static void *libc(void)
{
	static void *h;
	if (!h) {
		h = dlopen("libc.so.6", RTLD_LAZY | RTLD_LOCAL);
		if (!h) { fprintf(stderr, "oracle: %s\n", dlerror()); abort(); }
	}
	return h;
}

static void *sym(const char *n)
{
	void *p = dlsym(libc(), n);
	if (!p) { fprintf(stderr, "oracle: no %s\n", n); abort(); }
	return p;
}

/* glibc's real errno, not spicule's -- see the comment at the top of the
 * file for why the plain `errno` macro cannot be used here. */
static int *host_errno_loc(void)
{
	static errno_loc_fn f;
	if (!f) f = (errno_loc_fn)sym("__errno_location");
	return f();
}

double host_strtod(const char *s, size_t *endoff, int *err)
{
	static strtod_fn f;
	char *e;
	double r;
	if (!f) f = (strtod_fn)sym("strtod");
	*host_errno_loc() = 0;
	r = f(s, &e);
	*err = *host_errno_loc();
	*endoff = (size_t)(e - s);
	return r;
}

float host_strtof(const char *s, size_t *endoff, int *err)
{
	static strtof_fn f;
	char *e;
	float r;
	if (!f) f = (strtof_fn)sym("strtof");
	*host_errno_loc() = 0;
	r = f(s, &e);
	*err = *host_errno_loc();
	*endoff = (size_t)(e - s);
	return r;
}

long long host_strtoll(const char *s, size_t *endoff, int base, int *err)
{
	static strtoll_fn f;
	char *e;
	long long r;
	if (!f) f = (strtoll_fn)sym("strtoll");
	*host_errno_loc() = 0;
	r = f(s, &e, base);
	*err = *host_errno_loc();
	*endoff = (size_t)(e - s);
	return r;
}

unsigned long long host_strtoull(const char *s, size_t *endoff, int base, int *err)
{
	static strtoull_fn f;
	char *e;
	unsigned long long r;
	if (!f) f = (strtoull_fn)sym("strtoull");
	*host_errno_loc() = 0;
	r = f(s, &e, base);
	*err = *host_errno_loc();
	*endoff = (size_t)(e - s);
	return r;
}

/* The printf harness's oracle: glibc's snprintf, one argument at a time. */
/* inet_pton(AF_INET/AF_INET6), the host's.  A differential oracle is only worth
 * having where the two implementations are answering the same question,
 * and here they are: inet_pton.html specifies the strict dotted-quad
 * grammar with no short forms and no octal or hex parts, and glibc and
 * src/socket/inet.c both implement exactly that.  (inet_addr is
 * deliberately NOT oracled -- spicule's goes through strtoul with base 0,
 * which accepts leading whitespace and a sign that glibc's own parser
 * does not, so the comparison would be a stream of disagreements about
 * an under-specified corner rather than about defects.)
 *
 * Returns the host's return value; on success *out receives the four
 * network-order bytes. */
typedef int (*inet_pton_fn)(int, const char *, void *);
int host_inet_pton4(const char *s, unsigned char out[4])
{
	static inet_pton_fn f;
	if (!f) f = (inet_pton_fn)sym("inet_pton");
	return f(2 /* AF_INET, and it is 2 on both sides */, s, out);
}

int host_inet_pton6(const char *s, unsigned char out[16])
{
	static inet_pton_fn f;
	if (!f) f = (inet_pton_fn)sym("inet_pton");
	return f(10 /* Linux AF_INET6; spicule's Windows value is 23 */, s, out);
}

/* The time harness's oracle: glibc's timegm() and gmtime_r().
 *
 * These two are worth oracling and the rest of <time.h> is not, and the
 * reason is that they are the two whose answer does not depend on
 * anything outside their arguments.  timegm() and gmtime_r() are pure
 * proleptic-Gregorian arithmetic on UTC in both libraries -- no zone
 * database, no TZ, no "now" -- so a disagreement is a calendar bug in
 * one of them and nothing else.  mktime()/localtime() are deliberately
 * NOT oracled: glibc consults /usr/share/zoneinfo and implements POSIX
 * DST rules, while src/time/tzset.c documents that this target has
 * neither, so the two are answering different questions and every
 * "mismatch" would be that documented difference rather than a defect.
 *
 * <time.h> here is the host's, so `struct tm` is the host's layout --
 * which is exactly why the seam is a flat array of ints rather than a
 * struct: the harness is compiled against spicule's headers and the two
 * layouts are not required to agree.
 *
 * glibc's timegm reports out-of-range results as (time_t)-1 with errno
 * EOVERFLOW; *ok distinguishes that from the legitimate instant
 * 1969-12-31T23:59:59Z, which is also -1.  The caller must not compare
 * when *ok is 0 -- not because spicule is then excused, but because the
 * two libraries have made different (and both defensible) choices about
 * a case POSIX leaves as "shall return (time_t)-1 ... [EOVERFLOW]".
 */
#include <time.h>
typedef time_t (*timegm_fn)(struct tm *);
typedef struct tm *(*gmtime_r_fn)(const time_t *, struct tm *);

long long host_timegm(const int in[6], int *ok)
{
	static timegm_fn f;
	struct tm tm;
	time_t r;
	if (!f) f = (timegm_fn)sym("timegm");
	memset(&tm, 0, sizeof tm);
	tm.tm_year = in[0];
	tm.tm_mon  = in[1];
	tm.tm_mday = in[2];
	tm.tm_hour = in[3];
	tm.tm_min  = in[4];
	tm.tm_sec  = in[5];
	tm.tm_isdst = 0;
	*host_errno_loc() = 0;
	r = f(&tm);
	*ok = !(r == (time_t)-1 && *host_errno_loc() != 0);
	return (long long)r;
}

/* out[] = year, mon, mday, hour, min, sec, wday, yday.  Returns 0 if
 * glibc declined the instant (its own year range), 1 on success. */
int host_gmtime(long long t, int out[8])
{
	static gmtime_r_fn f;
	struct tm tm;
	time_t tt = (time_t)t;
	if (!f) f = (gmtime_r_fn)sym("gmtime_r");
	memset(&tm, 0, sizeof tm);
	if (!f(&tt, &tm)) return 0;
	out[0] = tm.tm_year; out[1] = tm.tm_mon;  out[2] = tm.tm_mday;
	out[3] = tm.tm_hour; out[4] = tm.tm_min;  out[5] = tm.tm_sec;
	out[6] = tm.tm_wday; out[7] = tm.tm_yday;
	return 1;
}

typedef int (*snprintf_fn)(char *, size_t, const char *, ...);
static snprintf_fn hsnp(void)
{
	static snprintf_fn f;
	if (!f) f = (snprintf_fn)sym("snprintf");
	return f;
}
int host_snprintf_1d(char *b, size_t n, const char *f, double v)      { return hsnp()(b, n, f, v); }
int host_snprintf_1ll(char *b, size_t n, const char *f, long long v)  { return hsnp()(b, n, f, v); }
int host_snprintf_1s(char *b, size_t n, const char *f, const char *v) { return hsnp()(b, n, f, v); }
int host_snprintf_1p(char *b, size_t n, const char *f, void *v)       { return hsnp()(b, n, f, v); }
int host_snprintf_0(char *b, size_t n, const char *f)                 { return hsnp()(b, n, f); }

/* ---------------------------------------------------------- reporting */

/*
 * Formatted with the host's snprintf and written with write(2).  Not
 * fprintf: in this executable `fprintf` is spicule's (it is the definition
 * the linker sees), so an oracle that reported through it would be
 * printing the numbers with the very code it is meant to be checking --
 * and spicule's printf does not implement %a, which is exactly the format
 * a bit-level float difference has to be shown in.
 */
static char rbuf[4096];
static size_t rlen;

static void emit(void)
{
	ssize_t ignored = write(2, rbuf, rlen);
	(void)ignored;
	rlen = 0;
}

static void addf(const char *fmt, ...)
{
	va_list ap;
	int n;
	va_start(ap, fmt);
	n = ((int (*)(char *, size_t, const char *, va_list))sym("vsnprintf"))
	      (rbuf + rlen, sizeof rbuf - rlen, fmt, ap);
	va_end(ap);
	if (n > 0) rlen += (size_t)n < sizeof rbuf - rlen ? (size_t)n : sizeof rbuf - rlen - 1;
}

static void addq(const char *s)
{
	addf("\"");
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		if (c == '"' || c == '\\') addf("\\%c", c);
		else if (c >= 0x20 && c < 0x7f) addf("%c", c);
		else addf("\\x%02x", c);
	}
	addf("\"");
}

/*
 * The host's abort(), not spicule's.  spicule's abort goes through its own
 * raise(), which on a native build has no real signal to deliver -- the
 * process would just stop, and libFuzzer would neither print a report nor
 * name the reproducing input.  A genuine SIGABRT is what its crash
 * handler is waiting for.
 */
static void host_abort(void)
{
	static void (*f)(void);
	if (!f) f = (void (*)(void))sym("abort");
	f();
	_exit(70);
}

void oracle_mismatch_d(const char *what, const char *in, double got, double want)
{
	addf("MISMATCH %s\n  input : ", what); addq(in);
	addf("\n  spicule: %.17g (%a)\n  glibc : %.17g (%a)\n", got, got, want, want);
	emit();
	host_abort();
}

void oracle_mismatch_i(const char *what, const char *in, long long got, long long want)
{
	addf("MISMATCH %s\n  input : ", what); addq(in);
	addf("\n  spicule: %lld\n  glibc : %lld\n", got, want);
	emit();
	host_abort();
}

void oracle_mismatch_s(const char *what, const char *in, const char *got, const char *want)
{
	addf("MISMATCH %s\n  input : ", what); addq(in);
	addf("\n  spicule: "); addq(got);
	addf("\n  glibc : "); addq(want);
	addf("\n");
	emit();
	host_abort();
}

/* ------------------------------------------------- the struct stat seam
 *
 * See fuzz/statshim.h for why this is here.  This file is the only one in
 * fuzz/ compiled against the host headers, so it is the only one that can
 * write a host `struct stat` without transcribing its layout by hand.
 */
#include <sys/stat.h>
#include "statshim.h"

unsigned long __ntfuzz_host_stat_size(void) { return (unsigned long)sizeof(struct stat); }

void __ntfuzz_pack_stat(void *hostbuf, const struct ntfuzz_stat *s)
{
	struct stat *st = (struct stat *)hostbuf;
	memset(st, 0, sizeof *st);
	st->st_dev     = (dev_t)s->dev;
	st->st_ino     = (ino_t)s->ino;
	st->st_rdev    = (dev_t)s->rdev;
	st->st_nlink   = (nlink_t)s->nlink;
	st->st_mode    = (mode_t)s->mode;
	st->st_uid     = (uid_t)s->uid;
	st->st_gid     = (gid_t)s->gid;
	st->st_size    = (off_t)s->size;
	st->st_blksize = (blksize_t)s->blksize;
	st->st_blocks  = (blkcnt_t)s->blocks;
	st->st_atim.tv_sec  = (time_t)s->atim_sec;  st->st_atim.tv_nsec = (long)s->atim_nsec;
	st->st_mtim.tv_sec  = (time_t)s->mtim_sec;  st->st_mtim.tv_nsec = (long)s->mtim_nsec;
	st->st_ctim.tv_sec  = (time_t)s->ctim_sec;  st->st_ctim.tv_nsec = (long)s->ctim_nsec;
}
