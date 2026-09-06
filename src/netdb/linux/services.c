/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * getservbyname()/getservbyport()/setservent()/getservent()/endservent():
 * a real /etc/services(5) parser, same "real-database-or-honestly-
 * empty" shape as hosts.c -- endservent.html's own DESCRIPTION says
 * the database's storage "is unspecified", so a flat-file parser
 * reading the one real system database every Linux distribution ships
 * is squarely inside that latitude.
 *
 * Line shape: "name port/proto [alias...] [# comment]" -- the '#' cut
 * happens before any tokenizing (same as every other parser here), so
 * a trailing comment on the same line as an alias is never swallowed
 * into a bogus extra alias.
 *
 * s_port stores the port already in network byte order (htons()'d at
 * parse time), matching endservent.html's own member description and
 * test/posix-netdb.c's assertion.
 *
 * Non-reentrant static storage, same house style as hostent.c's g_he.
 */
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nss_paths.h"

#define SERV_LINE_MAX 512
#define SERV_MAX_ALIASES 16
#define SERV_ALIASBUF_SZ 256

static struct servent g_se;
static char g_se_name[128];
static char g_se_proto[32];
static char g_se_aliasbuf[SERV_ALIASBUF_SZ];
static char *g_se_aliases[SERV_MAX_ALIASES + 1];

/* parse_serv_line(): fills g_se (and its backing static buffers) from
 * one raw /etc/services line. Returns 1 on a real entry, 0 for a line
 * this parser has nothing to say about (blank, comment-only, or
 * malformed -- e.g. no '/proto' suffix, or a non-numeric/out-of-range
 * port) -- every caller's per-line loop just continues past a 0. */
static int parse_serv_line(char *line)
{
	char *hash = strchr(line, '#');
	char *p = line, *nametok, *portproto, *proto, *slash, *end;
	long port;
	size_t n;
	int naliases = 0, off = 0;

	if (hash) *hash = '\0';

	while (*p == ' ' || *p == '\t') p++;
	nametok = p;
	while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
	if (p == nametok) return 0;
	if (*p) *p++ = '\0';

	while (*p == ' ' || *p == '\t') p++;
	portproto = p;
	while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
	if (p == portproto) return 0;
	if (*p) *p++ = '\0';

	slash = strchr(portproto, '/');
	if (!slash) return 0;
	*slash = '\0';
	proto = slash + 1;
	if (*proto == '\0') return 0;

	port = strtol(portproto, &end, 10);
	if (*end != '\0' || port < 0 || port > 65535) return 0;

	n = strlen(nametok);
	if (n >= sizeof g_se_name) n = sizeof g_se_name - 1;
	memcpy(g_se_name, nametok, n);
	g_se_name[n] = '\0';

	n = strlen(proto);
	if (n >= sizeof g_se_proto) n = sizeof g_se_proto - 1;
	{
		size_t i;
		for (i = 0; i < n; i++) g_se_proto[i] = proto[i];
	}
	g_se_proto[n] = '\0';

	for (;;) {
		char *tok;
		size_t toklen;

		while (*p == ' ' || *p == '\t') p++;
		if (*p == '\0' || *p == '\n') break;
		tok = p;
		while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
		toklen = (size_t)(p - tok);
		if (*p) *p++ = '\0';

		if (naliases < SERV_MAX_ALIASES &&
		    (size_t)off + toklen + 1 <= sizeof g_se_aliasbuf) {
			memcpy(g_se_aliasbuf + off, tok, toklen);
			g_se_aliasbuf[off + (int)toklen] = '\0';
			g_se_aliases[naliases++] = g_se_aliasbuf + off;
			off += (int)toklen + 1;
		}
	}
	g_se_aliases[naliases] = NULL;

	g_se.s_name = g_se_name;
	g_se.s_aliases = g_se_aliases;
	g_se.s_port = (int)htons((unsigned short)port);
	g_se.s_proto = g_se_proto;
	return 1;
}

struct servent *getservbyname(const char *name, const char *proto)
{
	FILE *f = fopen(__NSS_SERVICES_PATH(), "r");
	char line[SERV_LINE_MAX];

	if (!f) return NULL;
	while (fgets(line, sizeof line, f) != NULL) {
		if (!parse_serv_line(line)) continue;
		if (strcmp(g_se_name, name) != 0) continue;
		if (proto && strcmp(g_se_proto, proto) != 0) continue;
		(void)fclose(f);
		return &g_se;
	}
	(void)fclose(f);
	return NULL;
}

struct servent *getservbyport(int port, const char *proto)
{
	FILE *f = fopen(__NSS_SERVICES_PATH(), "r");
	char line[SERV_LINE_MAX];

	if (!f) return NULL;
	while (fgets(line, sizeof line, f) != NULL) {
		if (!parse_serv_line(line)) continue;
		if (g_se.s_port != port) continue;
		if (proto && strcmp(g_se_proto, proto) != 0) continue;
		(void)fclose(f);
		return &g_se;
	}
	(void)fclose(f);
	return NULL;
}

static FILE *g_servf withtok(file_stream_open);

void setservent(int stayopen)
{
	(void)stayopen; /* see sethostent()'s identical note (src/netdb/
	                  * linux/hostent.c): this implementation always
	                  * keeps the connection open until endservent(),
	                  * so stayopen has nothing to relax. */
	if (g_servf) rewind(g_servf);
	else g_servf = fopen(__NSS_SERVICES_PATH(), "r");
}

struct servent *getservent(void)
{
	char line[SERV_LINE_MAX];

	if (!g_servf) {
		g_servf = fopen(__NSS_SERVICES_PATH(), "r");
		if (!g_servf) return NULL;
	}
	while (fgets(line, sizeof line, g_servf) != NULL)
		if (parse_serv_line(line)) return &g_se;
	return NULL;
}

void endservent(void)
{
	if (g_servf) { (void)fclose(g_servf); g_servf = NULL; }
}
