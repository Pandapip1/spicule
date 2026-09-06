/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * gethostbyname()/h_errno: a legacy/XSI extension outside this edition
 * of POSIX, kept as a real, disclosed addition -- see include/netdb.h's
 * own banner for why herror()/hstrerror() are not included alongside it.
 *
 * A second, thinner front door onto the same __hosts_resolve() walk
 * getaddrinfo() (addrinfo.c) already uses -- not a second resolver or
 * nsswitch order decision.
 *
 * Non-reentrant, growable shared static storage, the same pattern
 * src/misc/pwd.c's fill_shared() uses for an unbounded real answer
 * with no caller-supplied buffer to size. h_name, h_addr_list (NUL-
 * pointer-terminated per <netdb.h>) and their backing bytes live in
 * one packed buffer; h_aliases is a separate static {NULL} array,
 * since this file tracks no alias list (see hosts.c's banner) but the
 * member must still be a valid non-NULL terminated array.
 */
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "netdb_internal.h"
#include "nss_paths.h"

int h_errno;

#define MAX_RESULT_ADDRS 32

static struct hostent g_he;
static char *g_hebuf;
static size_t g_hebufsz;
static char *g_he_aliases[1]; /* always {NULL}; see this file's banner */

/* Packs gethostbyname()'s answer for `name` into buf (bufsz bytes).
 * Returns 1 on success, 0 on a clean failure (h_errno set), or ERANGE
 * if buf is too small (*needp set, h_errno untouched -- not yet a
 * real failure): gethostbyname()'s own first probing call
 * legitimately passes bufsz == 0. */
static int fill_he(const char *name, char *buf, size_t bufsz, size_t *needp)
    __attribute__((nonnull(1)));
static int fill_he(const char *name, char *buf, size_t bufsz, size_t *needp)
{
	struct in_addr addrs[MAX_RESULT_ADDRS];
	char canon[256];
	int eai = 0;
	int n = __hosts_resolve(name, addrs, MAX_RESULT_ADDRS, canon, sizeof canon, &eai);
	const char *hname;
	size_t namelen, pad, ptrbytes, databytes, need;
	char *p;
	char **addrlist;
	int i;

	if (n < 0) {
		h_errno = (eai == EAI_AGAIN) ? TRY_AGAIN : NO_RECOVERY;
		return 0;
	}
	if (n == 0) {
		h_errno = HOST_NOT_FOUND;
		return 0;
	}

	hname = canon[0] ? canon : name;
	namelen = strlen(hname) + 1;
	pad = (sizeof(char *) - ((uintptr_t)(buf + namelen) % sizeof(char *))) % sizeof(char *);
	ptrbytes = (size_t)(n + 1) * sizeof(char *);
	databytes = (size_t)n * 4;
	need = namelen + pad + ptrbytes + databytes;
	if (need > bufsz) { if (needp) *needp = need; return ERANGE; }

	p = buf;
	{
		size_t j;
		for (j = 0; j < namelen; j++) p[j] = hname[j];
	}
	g_he.h_name = p;
	p += namelen + pad;

	addrlist = (char **)(void *)p;
	p += ptrbytes;
	for (i = 0; i < n; i++) {
		size_t j;
		const unsigned char *source = (const unsigned char *)&addrs[i];
		for (j = 0; j < 4; j++) p[j] = (char)source[j];
		addrlist[i] = p;
		p += 4;
	}
	addrlist[n] = NULL;

	g_he.h_aliases = g_he_aliases;
	g_he.h_addrtype = AF_INET;
	g_he.h_length = 4;
	g_he.h_addr_list = addrlist;
	return 1;
}

struct hostent *gethostbyname(const char *name)
{
	size_t need = 0;
	int r = fill_he(name, g_hebuf, g_hebufsz, &need);
	char *nb;

	if (r == ERANGE) {
		nb = realloc(g_hebuf, need);
		if (!nb) { h_errno = TRY_AGAIN; return NULL; }
		g_hebuf = nb;
		g_hebufsz = need;
		r = fill_he(name, g_hebuf, g_hebufsz, &need);
		if (r == ERANGE) { h_errno = TRY_AGAIN; return NULL; }
	}
	if (r != 1) return NULL;
	h_errno = 0;
	return &g_he;
}

/* sethostent()/gethostent()/endhostent(): sequential host-database
 * walk, one struct hostent per line of the same /etc/hosts this
 * file's gethostbyname() and hosts.c's __hosts_lookup() read, via
 * __hosts_read_entry() (hosts.c). One address per entry, h_addrtype/
 * h_length always AF_INET/4 (no IPv6 line is ever parsed -- see
 * hosts.c's banner), and up to GHE_MAX_ALIASES trailing name tokens
 * as h_aliases -- real per-line aliases, unlike gethostbyname()'s own
 * g_he_aliases (always {NULL}).
 *
 * Non-reentrant static storage, same house style as fill_he()/g_he
 * above. */
#define GHE_MAX_ALIASES 16
#define GHE_ALIASBUF_SZ 512

static FILE *g_hostf withtok(file_stream_open);

static struct hostent g_ghe;
static char g_ghe_name[256];
static char g_ghe_aliasbuf[GHE_ALIASBUF_SZ];
static char *g_ghe_aliases[GHE_MAX_ALIASES + 1];
static struct in_addr g_ghe_addr;
static char *g_ghe_addrlist[2];

void sethostent(int stayopen)
{
	(void)stayopen; /* this implementation always keeps the connection
	                  * open across calls (endhostent() is the only
	                  * thing that closes it) -- stayopen only relaxes
	                  * that in the other direction, so honoring it is
	                  * a no-op here, not a gap. */
	if (g_hostf) rewind(g_hostf);
	else g_hostf = fopen(__NSS_HOSTS_PATH(), "r");
}

struct hostent *gethostent(void)
{
	int naliases;

	if (!g_hostf) {
		g_hostf = fopen(__NSS_HOSTS_PATH(), "r");
		if (!g_hostf) return NULL; /* no database: a clean, immediate
		                             * end-of-database, same as the
		                             * file existing but being empty */
	}

	if (!__hosts_read_entry(g_hostf, &g_ghe_addr, g_ghe_name, sizeof g_ghe_name,
	                         g_ghe_aliasbuf, sizeof g_ghe_aliasbuf,
	                         g_ghe_aliases, GHE_MAX_ALIASES, &naliases))
		return NULL;

	/* g_ghe_aliases[0..naliases-1] already point into g_ghe_aliasbuf,
	 * filled in by __hosts_read_entry() itself. */
	g_ghe_aliases[naliases] = NULL;

	g_ghe_addrlist[0] = (char *)&g_ghe_addr;
	g_ghe_addrlist[1] = NULL;

	g_ghe.h_name = g_ghe_name;
	g_ghe.h_aliases = g_ghe_aliases;
	g_ghe.h_addrtype = AF_INET;
	g_ghe.h_length = 4;
	g_ghe.h_addr_list = g_ghe_addrlist;
	return &g_ghe;
}

void endhostent(void)
{
	if (g_hostf) { (void)fclose(g_hostf); g_hostf = NULL; }
}
