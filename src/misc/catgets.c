/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * catopen(), catgets(), catclose() -- catopen.html, catgets.html,
 * catclose.html.  <nl_types.h> carries the type and constant half.
 *
 * WHAT THIS DOES AND DOES NOT DO, first, because a message-catalogue
 * interface is easy to fake and a fake one is worse than none.
 *
 * It does: resolve NLSPATH exactly as XBD 8.2 specifies, open the
 * resulting pathname, read a catalogue in the byte format described
 * below, validate it, and answer catgets() out of it.  A catalogue
 * built by musl's gencat works here unchanged.
 *
 * It does not: build a catalogue.  There is no gencat in this tree, so
 * on a machine where nobody has put one there, catopen() finds no file
 * and fails.  That is not a stub result: every entry in catopen.html's
 * ERRORS list is under "The catopen() function may fail if:", including
 * "[ENOENT] The message catalog does not exist or the name argument
 * points to an empty string.", so failing is a specified outcome and a
 * caller is written for it.  catgets.html then keeps that caller
 * correct: "The s argument points to a default message string which
 * shall be returned by catgets() if it cannot retrieve the identified
 * message."  What is NOT done is the dishonest version -- returning a
 * descriptor that opened nothing, so that catgets() could hand back s
 * while pretending a catalogue was consulted.
 *
 * THE FILE FORMAT.  POSIX standardises gencat's *source* format and
 * says nothing about the compiled catalogue's bytes, so a reader has to
 * pick one.  This picks musl's, so that catalogues are portable between
 * the two libcs rather than to a format only this file can produce:
 *
 *   byte  0..3   magic, 0xff88ff89, big-endian
 *   byte  4..7   number of set records
 *   byte  8..11  size of everything after this 20-byte header
 *   byte 12..15  offset of the message-record table, from byte 20
 *   byte 16..19  offset of the string pool, from byte 20
 *   then the set records, 12 bytes each: set_id, message count,
 *        index of this set's first message record
 *   then the message records, 12 bytes each: msg_id, string length,
 *        offset of the string within the pool
 *   then the string pool
 *
 * Every 32-bit field is big-endian and is read a byte at a time by V()
 * below, so this needs no <endian.h>, no alignment assumption, and
 * behaves the same on either arch.  Set and message records are sorted
 * ascending by id, which is what makes the binary searches in catgets()
 * legitimate; ordering is verified at open, not assumed.
 *
 * WHY THE WHOLE FILE IS READ AT OPEN.  catopen.html: "If a file
 * descriptor is used to implement message catalog descriptors, the
 * FD_CLOEXEC flag shall be set".  This keeps no descriptor at all --
 * the file is read into one malloc'd block and closed before catopen()
 * returns -- so the clause is satisfied by having nothing to leak, and
 * catclose.html's "If a file descriptor is used to implement the type
 * nl_catd, that file descriptor shall be closed" is likewise vacuous
 * here.  O_CLOEXEC is set on the transient descriptor anyway, so that a
 * fork()/exec() racing the read cannot inherit it.
 *
 * VALIDATION.  A corrupt catalogue must not be able to walk this
 * process off the end of the block, and catgets.html gives the error to
 * report if one is found: "[EINVAL] The message catalog identified by
 * catd is corrupted."  Every offset and count is range-checked once at
 * open (check_catalog() below), and the last byte of the file is
 * required to be NUL so that any in-range string offset names a
 * terminated string.  A file that fails any of it is not opened at all,
 * so catgets() never has to defend itself against one -- which matters,
 * because catgets.html makes the results undefined for a descriptor
 * catopen() did not return and so catgets() cannot re-check anything.
 *
 * ONE CLAUSE DELIBERATELY NOT IMPLEMENTED, said plainly rather than
 * left to be discovered: "if NLSPATH exists in the environment when the
 * process starts, then if the process has appropriate privileges, the
 * behavior of catopen() is undefined."  Implementations use that
 * licence to ignore NLSPATH in a set-user-ID process.  ntlibc has no
 * set-user-ID and no notion of a process that started with more
 * privilege than its caller, so there is no flag to test; NLSPATH is
 * honoured unconditionally.  If such a notion is ever added, this is
 * the function that has to consult it.
 *
 * "A change in the setting of the LC_MESSAGES category may invalidate
 * existing open catalogs."  It does not here, and need not: "may".
 */
#include <nl_types.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include "libc.h"
#include "ownership_stubs.h"

#define CAT_MAGIC 0xff88ff89u
#define CAT_HDRSZ 20
#define CAT_RECSZ 12

/* A catalogue is a naked block of bytes; nl_catd is the block. p is
 * required: dereferenced unconditionally (p[0..3]) with no guard of
 * its own. Every real call site in this file passes a pointer already
 * proven nonnull by its own caller before V() is ever reached --
 * catgets()'s own m, checked by a real `if (!m || m == -1) ...`
 * BEFORE any V(m+...) call; check_catalog()'s own m, itself required
 * below and always catopen()'s just-null-checked malloc() result. */
static uint32_t V(const unsigned char *p) __attribute__((nonnull(1)));
static uint32_t V(const unsigned char *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

/* Range-check the whole structure once, so catgets() can walk it
 * without a bounds test on every step.  Returns 1 if usable. m is
 * required: V(m)/m[size - 1] are unconditional on real, reachable
 * paths with no NULL check, and its one real call site (catopen())
 * passes buf, already checked non-NULL right after its own malloc(). */
static int check_catalog(const unsigned char *m, size_t size)
    __attribute__((nonnull(1)));
static int check_catalog(const unsigned char *m, size_t size)
{
	uint32_t nsets, msgoff, stroff, body;
	uint32_t i, prev_set;
	size_t after;

	if (size < CAT_HDRSZ + 1) return 0;
	if (V(m) != CAT_MAGIC) return 0;

	body = V(m + 8);
	if ((size_t)body + CAT_HDRSZ != size) return 0;

	nsets = V(m + 4);
	msgoff = V(m + 12);
	stroff = V(m + 16);
	if (msgoff > body || stroff > body || msgoff > stroff) return 0;

	/* The set table lives between the header and the message table. */
	if ((size_t)nsets > (size_t)(msgoff / CAT_RECSZ)) return 0;

	/* Strings are only safe to hand out as C strings if the block ends
	 * in a NUL: then any offset inside the pool is terminated. */
	if (m[size - 1] != 0) return 0;

	after = CAT_HDRSZ;
	prev_set = 0;
	for (i = 0; i < nsets; i++) {
		const unsigned char *set = m + after + (size_t)i * CAT_RECSZ;
		uint32_t set_id = V(set), nmsgs = V(set + 4), first = V(set + 8);
		uint32_t j, prev_msg = 0;
		const unsigned char *msgs;

		/* Ascending and distinct: the binary search depends on it. */
		if (i && set_id <= prev_set) return 0;
		prev_set = set_id;

		if (first > (stroff - msgoff) / CAT_RECSZ) return 0;
		if (nmsgs > (stroff - msgoff) / CAT_RECSZ - first) return 0;

		msgs = m + CAT_HDRSZ + msgoff + (size_t)first * CAT_RECSZ;
		for (j = 0; j < nmsgs; j++) {
			const unsigned char *msg = msgs + (size_t)j * CAT_RECSZ;
			uint32_t msg_id = V(msg), soff = V(msg + 8);

			if (j && msg_id <= prev_msg) return 0;
			prev_msg = msg_id;
			if (soff >= body - stroff) return 0;
		}
	}
	return 1;
}

/* Read a whole file into one block.  Not mmap: this tree's mmap is a
 * section-object wrapper with page granularity and no advantage here,
 * and catclose() then has nothing to remember but the pointer. */
withtok(catalog_opened)
static nl_catd read_catalog(const char *path)
{
	unsigned char *buf = 0, *nbuf;
	size_t cap = 4096, len = 0;
	int fd, saved;
	ssize_t n;

	if (!*path) { errno = ENOENT; return (nl_catd)-1; }

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return (nl_catd)-1;   /* open() already set errno */

	buf = malloc(cap);
	if (!buf) { saved = ENOMEM; goto fail; }

	for (;;) {
		if (len == cap) {
			size_t newcap;
			if (!__size_mul_checked(cap, 2, &newcap)) { saved = ENOMEM; goto fail; }
			nbuf = realloc(buf, newcap);
			if (!nbuf) { saved = ENOMEM; goto fail; }
			buf = nbuf;
			cap = newcap;
		}
		__ownership_writable_span(buf + len, cap - len);
		n = read(fd, buf + len, cap - len);
		if (n < 0) {
			/* catopen.html lists no [EINTR], but read() can
			 * report one; retry rather than invent a failure. */
			if (errno == EINTR) continue;
			saved = errno;
			goto fail;
		}
		if (n == 0) break;
		len += (size_t)n;
	}
	(void)close(fd);

	if (!check_catalog(buf, len)) {
		free(buf);
		errno = ENOENT;   /* not a catalogue -> keep looking */
		return (nl_catd)-1;
	}
	return (nl_catd)buf;

fail:
	saved = saved ? saved : ENOMEM;
	(void)close(fd);
	free(buf);
	errno = saved;
	return (nl_catd)-1;
}

/* XBD 8.2 NLSPATH: "Conversion specifications consist of a '%' symbol,
 * followed by a single-letter keyword.", %N %L %l %t %c %%, and "An
 * empty string is substituted if the specified value is not currently
 * defined. The separators <underscore> ( '_' ) and <period> ( '.' ) are
 * not included in the %t and %c conversion specifications."
 *
 * Expands one template into buf; returns its length, or (size_t)-1 if
 * it does not fit or uses an undefined keyword (in which case the
 * template is skipped, not treated as a literal).
 *
 * Takes the template's length rather than an end pointer so that `end`
 * is computed here, locally, from `tmpl` -- both callers already have a
 * length or an equally-local same-object end pointer at hand (see
 * catopen() below), and a length crossing the call as a plain size_t
 * carries no pointer-provenance obligation at all, unlike an end
 * pointer, which a static analyzer checking this function on its own
 * (as tools/lint.sh's provenance stage does) has no way to know shares
 * `tmpl`'s object -- that invariant lived only in catopen()'s two call
 * sites, not in anything expand() itself could see. */
static size_t expand(char *buf, size_t bufsz, const char *tmpl,
                     size_t tmpllen, const char *name, const char *lang) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	size_t i = 0;
	const char *p, *end = tmpl + tmpllen;

	for (p = tmpl; p < end; p++) {
		const char *v;
		size_t l;

		if (*p != '%') { v = p; l = 1; }
		else if (++p >= end) return (size_t)-1;
		else switch (*p) {
		case 'N': v = name; l = strlen(v); break;
		case 'L': v = lang; l = strlen(v); break;
		case 'l': v = lang; l = strcspn(v, "_.@"); break;
		case 't':
			v = lang + strcspn(lang, "_");
			if (*v) v++;              /* drop the '_' itself */
			l = strcspn(v, ".@");
			break;
		case 'c':
			v = lang + strcspn(lang, ".");
			if (*v) v++;              /* drop the '.' itself */
			l = strcspn(v, "@");
			break;
		case '%': v = "%"; l = 1; break;
		default: return (size_t)-1;
		}
		if (l >= bufsz - i) return (size_t)-1;
		{
			size_t j;
			for (j = 0; j < l; j++) buf[i + j] = v[j];
		}
		i += l;
	}
	buf[i] = 0;
	return i;
}

withtok(catalog_opened)
nl_catd catopen(const char *name withtok(null_terminated), int oflag)
{
	/* A named array rather than a second "%N" literal purely so
	 * `sizeof dflt - 1` names its length without a magic 2: expand()
	 * takes a length now (see its own comment), not an end pointer, so
	 * the historical reason this had to be one array -- two identical
	 * string literals are not guaranteed to be one object, and the old
	 * `expand(..., "%N", "%N" + 2, ...)` shape relied on comparing
	 * pointers into what would otherwise have been potentially distinct
	 * arrays -- no longer applies, but there is still no reason to
	 * spell the template twice. */
	static const char dflt[] = "%N";
	char buf[PATH_MAX];
	const char *path, *lang, *p;
	nl_catd cd;

	if (!name || !*name) { errno = ENOENT; return (nl_catd)-1; }

	/* "If name contains a '/', then name specifies a pathname for the
	 * message catalog." */
	if (strchr(name, '/')) return read_catalog(name);

	/* "If the value of the oflag argument is 0, the LANG environment
	 * variable is used to locate the catalog without regard to the
	 * LC_MESSAGES category. If the oflag argument is NL_CAT_LOCALE,
	 * the LC_MESSAGES category is used to locate the message
	 * catalog".  setlocale(LC_MESSAGES, NULL) is that category's
	 * current value; here it is always "C", but reading it rather
	 * than hard-coding "C" is what makes this follow the category
	 * rather than merely agree with it today. */
	lang = oflag == NL_CAT_LOCALE ? setlocale(LC_MESSAGES, 0)
	                              : getenv("LANG");
	if (!lang) lang = "";

	/* "If NLSPATH does not exist in the environment, or if a message
	 * catalog cannot be found in any of the components specified by
	 * NLSPATH, then an implementation-defined default path shall be
	 * used."  ntlibc's default is "%N:%N.cat": the name as given,
	 * then the name with the .cat suffix XBD's own example uses.
	 * There is no system message-catalogue directory on this platform
	 * to name, and inventing one would send every lookup somewhere
	 * nothing will ever be installed. */
	path = getenv("NLSPATH");
	if (!path || !*path) path = "%N:%N.cat";

	p = path;
	for (;;) {
		size_t n, template_len;

		template_len = strcspn(p, ":");

		/* "A leading or two adjacent <colon> characters ( "::" ) is
		 * equivalent to specifying %N." */
		n = template_len == 0 ? expand(buf, sizeof buf, dflt,
		                                 sizeof dflt - 1, name, lang)
		                        : expand(buf, sizeof buf, p, template_len,
		                                 name, lang);
		if (n != (size_t)-1) {
			cd = read_catalog(buf);
			if (cd != (nl_catd)-1) return cd;
		}
		p += template_len;
		if (!*p) break;
		p++;
	}

	errno = ENOENT;
	return (nl_catd)-1;
}

char *catgets(nl_catd catd withtok(catalog_opened), int set_id, int msg_id, const char *s) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	const unsigned char *m = (const unsigned char *)catd;
	const unsigned char *sets, *msgs, *strings;
	uint32_t lo, hi, nsets, nmsgs;

	/* "The results are undefined if catd is not a value returned by
	 * catopen() for a message catalog still open in the process."  A
	 * null is the one shape of that which is cheap to survive; it is
	 * caught because a caller that ignored catopen()'s return value
	 * should get its default string back rather than a fault, not
	 * because the standard asks for a check. */
	if (!m || m == (const unsigned char *)-1) {
		errno = EBADF;
		return (char *)s;
	}

	nsets = V(m + 4);
	sets = m + CAT_HDRSZ;
	msgs = m + CAT_HDRSZ + V(m + 12);
	strings = m + CAT_HDRSZ + V(m + 16);

	for (lo = 0, hi = nsets; lo < hi; ) {
		uint32_t mid = lo + (hi - lo) / 2;
		uint32_t id = V(sets + (size_t)mid * CAT_RECSZ);

		if ((uint32_t)set_id == id) {
			nmsgs = V(sets + (size_t)mid * CAT_RECSZ + 4);
			msgs += (size_t)V(sets + (size_t)mid * CAT_RECSZ + 8)
			        * CAT_RECSZ;
			for (lo = 0, hi = nmsgs; lo < hi; ) {
				uint32_t k = lo + (hi - lo) / 2;
				uint32_t mid_id = V(msgs + (size_t)k * CAT_RECSZ);

				if ((uint32_t)msg_id == mid_id)
					return (char *)strings +
					       V(msgs + (size_t)k * CAT_RECSZ + 8);
				if ((uint32_t)msg_id < mid_id) hi = k;
				else lo = k + 1;
			}
			break;
		}
		if ((uint32_t)set_id < id) hi = mid;
		else lo = mid + 1;
	}

	/* "[ENOMSG] The message identified by set_id and msg_id is not in
	 * the message catalog." -- a *shall fail*, and "If the call is
	 * unsuccessful for any reason, s shall be returned": the pointer
	 * the caller gave, not a copy of it. */
	errno = ENOMSG;
	return (char *)s;
}

int catclose(nl_catd catd consume(catalog_opened))
{
	/* "[EBADF] The catalog descriptor is not valid." is a *may fail*;
	 * a descriptor this implementation handed out is a malloc'd block
	 * and there is nothing that can go wrong closing it, so the only
	 * failure reported is the one that is free to detect. */
	if (!catd || catd == (nl_catd)-1) {
		errno = EBADF;
		return -1;
	}
	free(catd);
	return 0;
}
