/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * getprotobyname()/getprotobynumber()/setprotoent()/getprotoent()/
 * endprotoent(): https://pubs.opengroup.org/onlinepubs/9699919799/
 * functions/endprotoent.html. A real /etc/protocols(5) parser --
 * same shape and same reasoning as this directory's services.c
 * (endprotoent.html's own DESCRIPTION says only that the database "is
 * considered to be stored ... in an unspecified format", so parsing the
 * one real flat file every Linux distribution ships is squarely inside
 * that, not a deviation from it).
 *
 * Line shape: "name number [alias...] [# comment]" -- e.g. real
 * /etc/protocols entries look like "tcp  6  TCP  # Transmission Control
 * Protocol". p_proto is a plain host-order int (unlike services.c's
 * s_port, nothing here is ever put on the wire in a fixed byte order --
 * endprotoent.html's own member description for p_proto says only "The
 * protocol number", no byte-order clause at all).
 */
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nss_paths.h"

#define PROTO_LINE_MAX 512
#define PROTO_MAX_ALIASES 16
#define PROTO_ALIASBUF_SZ 256

static struct protoent g_pe;
static char g_pe_name[64];
static char g_pe_aliasbuf[PROTO_ALIASBUF_SZ];
static char *g_pe_aliases[PROTO_MAX_ALIASES + 1];

/* parse_proto_line(): fills g_pe from one raw /etc/protocols line.
 * Returns 1 on a real entry, 0 for a line this parser has nothing to
 * say about (blank, comment-only, or a non-numeric protocol number). */
static int parse_proto_line(char *line)
{
	char *hash = strchr(line, '#');
	char *p = line, *nametok, *numtok, *end;
	long num;
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

	num = strtol(numtok, &end, 10);
	if (*end != '\0') return 0;

	n = strlen(nametok);
	if (n >= sizeof g_pe_name) n = sizeof g_pe_name - 1;
	memcpy(g_pe_name, nametok, n);
	g_pe_name[n] = '\0';

	for (;;) {
		char *tok;
		size_t toklen;

		while (*p == ' ' || *p == '\t') p++;
		if (*p == '\0' || *p == '\n') break;
		tok = p;
		while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
		toklen = (size_t)(p - tok);
		if (*p) *p++ = '\0';

		if (naliases < PROTO_MAX_ALIASES &&
		    (size_t)off + toklen + 1 <= sizeof g_pe_aliasbuf) {
			memcpy(g_pe_aliasbuf + off, tok, toklen);
			g_pe_aliasbuf[off + (int)toklen] = '\0';
			g_pe_aliases[naliases++] = g_pe_aliasbuf + off;
			off += (int)toklen + 1;
		}
	}
	g_pe_aliases[naliases] = NULL;

	g_pe.p_name = g_pe_name;
	g_pe.p_aliases = g_pe_aliases;
	g_pe.p_proto = (int)num;
	return 1;
}

struct protoent *getprotobyname(const char *name)
{
	FILE *f = fopen(__NSS_PROTOCOLS_PATH(), "r");
	char line[PROTO_LINE_MAX];

	if (!f) return NULL;
	while (fgets(line, sizeof line, f) != NULL) {
		if (!parse_proto_line(line)) continue;
		if (strcmp(g_pe_name, name) != 0) continue;
		(void)fclose(f);
		return &g_pe;
	}
	(void)fclose(f);
	return NULL;
}

struct protoent *getprotobynumber(int proto)
{
	FILE *f = fopen(__NSS_PROTOCOLS_PATH(), "r");
	char line[PROTO_LINE_MAX];

	if (!f) return NULL;
	while (fgets(line, sizeof line, f) != NULL) {
		if (!parse_proto_line(line)) continue;
		if (g_pe.p_proto != proto) continue;
		(void)fclose(f);
		return &g_pe;
	}
	(void)fclose(f);
	return NULL;
}

static FILE *g_protof withtok(file_stream_open);

void setprotoent(int stayopen)
{
	(void)stayopen; /* see services.c's setservent() identical note */
	if (g_protof) rewind(g_protof);
	else g_protof = fopen(__NSS_PROTOCOLS_PATH(), "r");
}

struct protoent *getprotoent(void)
{
	char line[PROTO_LINE_MAX];

	if (!g_protof) {
		g_protof = fopen(__NSS_PROTOCOLS_PATH(), "r");
		if (!g_protof) return NULL;
	}
	while (fgets(line, sizeof line, g_protof) != NULL)
		if (parse_proto_line(line)) return &g_pe;
	return NULL;
}

void endprotoent(void)
{
	if (g_protof) { (void)fclose(g_protof); g_protof = NULL; }
}
