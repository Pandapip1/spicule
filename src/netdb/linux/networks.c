/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * setnetent()/getnetent()/endnetent()/getnetbyname()/getnetbyaddr():
 * a real /etc/networks(5) parser, same shape as hosts.c/services.c/
 * protocols.c. /etc/networks is routinely absent on a real machine (no
 * IANA-style assignment list for it, unlike /etc/services and
 * /etc/protocols) -- a missing file is this database's normal empty
 * state, not an error.
 *
 * Line shape: "name net-number [alias...] [# comment]". net-number is
 * parsed with inet_addr() + ntohl(), NOT the classic BSD
 * inet_network() this tree does not have -- the two differ for a
 * genuinely abbreviated non-zero short form ("128.10" meaning network
 * 128.10.0.0 under inet_network(), but host 128.0.0.10 under
 * inet_addr(), confirmed against this tree's own inet_addr()). Real
 * /etc/networks entries are near-universally full or trailing-zero
 * dotted form ("127.0.0.0", "0.0.0.0"), where the two functions agree,
 * so this reuse is correct in practice; a genuinely abbreviated
 * non-zero short form is a real, disclosed gap, not a silently wrong
 * answer.
 */
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include "nss_paths.h"

#define NET_LINE_MAX 512
#define NET_MAX_ALIASES 16
#define NET_ALIASBUF_SZ 256

static struct netent g_ne;
static char g_ne_name[128];
static char g_ne_aliasbuf[NET_ALIASBUF_SZ];
static char *g_ne_aliases[NET_MAX_ALIASES + 1];

/* Fills g_ne from one raw /etc/networks line. Returns 1 on a real
 * entry, 0 for a line with nothing to say (blank, comment-only, or an
 * unparsable net-number). inet_addr()'s failure value, INADDR_NONE
 * (0xffffffff), is indistinguishable from a real "255.255.255.255"
 * network, but an all-ones network (no host bits at all) can never be
 * a legitimate network number either way, so treating it as
 * unparsable is correct regardless. */
static int parse_net_line(char *line)
{
	char *hash = strchr(line, '#');
	char *p = line, *nametok, *numtok;
	in_addr_t parsed;
	size_t n;
	int naliases = 0, off = 0;

	if (hash) *hash = '\0';

	while (*p == ' ' || *p == '\t') p++;
	nametok = p;
	while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
	if (p == nametok) return 0;
	if (*p) *p++ = '\0';

	while (*p == ' ' || *p == '\t') p++;
	numtok = p;
	while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
	if (p == numtok) return 0;
	if (*p) *p++ = '\0';

	parsed = inet_addr(numtok);
	if (parsed == (in_addr_t)-1) return 0;

	n = strlen(nametok);
	if (n >= sizeof g_ne_name) n = sizeof g_ne_name - 1;
	memcpy(g_ne_name, nametok, n);
	g_ne_name[n] = '\0';

	for (;;) {
		char *tok;
		size_t toklen;

		while (*p == ' ' || *p == '\t') p++;
		if (*p == '\0' || *p == '\n') break;
		tok = p;
		while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
		toklen = (size_t)(p - tok);
		if (*p) *p++ = '\0';

		if (naliases < NET_MAX_ALIASES &&
		    (size_t)off + toklen + 1 <= sizeof g_ne_aliasbuf) {
			memcpy(g_ne_aliasbuf + off, tok, toklen);
			g_ne_aliasbuf[off + (int)toklen] = '\0';
			g_ne_aliases[naliases++] = g_ne_aliasbuf + off;
			off += (int)toklen + 1;
		}
	}
	g_ne_aliases[naliases] = NULL;

	g_ne.n_name = g_ne_name;
	g_ne.n_aliases = g_ne_aliases;
	g_ne.n_addrtype = AF_INET;
	g_ne.n_net = ntohl(parsed);
	return 1;
}

struct netent *getnetbyname(const char *name)
{
	FILE *f = fopen(__NSS_NETWORKS_PATH(), "r");
	char line[NET_LINE_MAX];

	if (!f) return NULL;
	while (fgets(line, sizeof line, f) != NULL) {
		if (!parse_net_line(line)) continue;
		if (strcmp(g_ne_name, name) != 0) continue;
		(void)fclose(f);
		return &g_ne;
	}
	(void)fclose(f);
	return NULL;
}

struct netent *getnetbyaddr(uint32_t net, int type)
{
	FILE *f;
	char line[NET_LINE_MAX];

	if (type != AF_INET) return NULL; /* the only network address type
	                                    * this database's own parser
	                                    * ever produces -- see this
	                                    * file's banner. */
	f = fopen(__NSS_NETWORKS_PATH(), "r");
	if (!f) return NULL;
	while (fgets(line, sizeof line, f) != NULL) {
		if (!parse_net_line(line)) continue;
		if (g_ne.n_net != net) continue;
		(void)fclose(f);
		return &g_ne;
	}
	(void)fclose(f);
	return NULL;
}

static FILE *g_netf withtok(file_stream_open);

void setnetent(int stayopen)
{
	(void)stayopen; /* see services.c's setservent() identical note */
	if (g_netf) rewind(g_netf);
	else g_netf = fopen(__NSS_NETWORKS_PATH(), "r");
}

struct netent *getnetent(void)
{
	char line[NET_LINE_MAX];

	if (!g_netf) {
		g_netf = fopen(__NSS_NETWORKS_PATH(), "r");
		if (!g_netf) return NULL; /* no database: a clean, immediate
		                            * end-of-database -- see this
		                            * file's banner. */
	}
	while (fgets(line, sizeof line, g_netf) != NULL)
		if (parse_net_line(line)) return &g_ne;
	return NULL;
}

void endnetent(void)
{
	if (g_netf) { (void)fclose(g_netf); g_netf = NULL; }
}
