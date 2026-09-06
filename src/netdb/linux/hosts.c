/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * __hosts_lookup(): the "files" service for the "hosts" NSS database
 * -- a real /etc/hosts(5) parser. See src/netdb/linux/netdb_internal.h
 * for this function's exact contract.
 *
 * getnameinfo() (src/netdb/linux/getnameinfo.c) and gethostent()
 * (src/netdb/linux/hostent.c) also need the reverse (address -> name)
 * and sequential walks this file provides -- both built below as
 * small additions on top of the forward scan, sharing its line-shape
 * rules (parse_hosts_addr()) rather than re-deriving them.
 */
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include "nss_paths.h"
#include "netdb_internal.h"

#define HOSTS_LINE_MAX 512

/* True if `tok` (a NUL-terminated whitespace-delimited field already
 * split out of the line) is a real IPv6 literal this file does not
 * parse -- detected the cheap, sufficient way: a dotted-quad IPv4
 * address never contains ':', and nothing else legitimately appears
 * in /etc/hosts's address column. */
static int looks_like_v6(const char *tok)
{
	return strchr(tok, ':') != NULL;
}

/* Shared first half of every /etc/hosts(5) line parse in this file:
 * splits off the leading address field (mutating `line` in place),
 * skips a real IPv6 literal or an unparsable address, and returns a
 * pointer to the remainder (the name-tokens portion, possibly empty).
 * Returns NULL for a line with nothing to say (blank, IPv6, or a bad
 * address); callers just continue past that. Does NOT strip a
 * trailing '#' comment -- callers do that first, before any field is
 * split out. */
static char *parse_hosts_addr(char *line, struct in_addr *out)
{
	char *p = line;
	char *addrtok;

	while (*p == ' ' || *p == '\t') p++;
	addrtok = p;
	while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
	if (p == addrtok) return NULL; /* blank/comment-only line */
	if (*p) *p++ = '\0';

	if (looks_like_v6(addrtok)) return NULL;
	if (inet_pton(AF_INET, addrtok, out) != 1) return NULL;
	return p;
}

int __hosts_lookup(const char *name, struct in_addr *addrs, int maxaddrs,
                    char *canon, size_t canonsz)
{
	FILE *f;
	char line[HOSTS_LINE_MAX];
	int found = 0;

	f = fopen(__NSS_HOSTS_PATH(), "r");
	if (!f) return 0;

	while (fgets(line, sizeof line, f) != NULL) {
		char *p = line;
		char *hash = strchr(line, '#');
		char *addrtok, *nametok;
		struct in_addr a;
		int matched;

		if (hash) *hash = '\0';

		while (*p == ' ' || *p == '\t') p++;
		addrtok = p;
		while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
		if (p == addrtok) continue; /* blank/comment-only line */
		if (*p) *p++ = '\0';

		if (looks_like_v6(addrtok)) continue;
		if (inet_pton(AF_INET, addrtok, &a) != 1) continue;

		/* Remaining whitespace-separated fields: canonical name
		 * first, then zero or more aliases -- hosts(5)'s own
		 * documented layout. `name` matches any of them. */
		matched = 0;
		nametok = NULL;
		for (;;) {
			char *tok;
			while (*p == ' ' || *p == '\t') p++;
			if (*p == '\0' || *p == '\n') break;
			tok = p;
			while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
			if (*p) *p++ = '\0';
			if (!nametok) nametok = tok;
			if (strcasecmp(tok, name) == 0) matched = 1;
		}
		if (!matched || !nametok) continue;

		if (found == 0 && canon && canonsz > 0) {
			size_t n = strlen(nametok);
			if (n >= canonsz) n = canonsz - 1;
			{
				size_t i;
				for (i = 0; i < n; i++) canon[i] = nametok[i];
			}
			canon[n] = '\0';
		}
		if (found < maxaddrs) addrs[found] = a;
		found++;
	}

	(void)fclose(f);
	return found;
}

int __hosts_lookup_reverse(const struct in_addr *addr, char *name, size_t namesz)
{
	FILE *f;
	char line[HOSTS_LINE_MAX];
	int found = 0;

	f = fopen(__NSS_HOSTS_PATH(), "r");
	if (!f) return 0;

	while (fgets(line, sizeof line, f) != NULL) {
		char *hash = strchr(line, '#');
		struct in_addr a;
		char *rest, *nametok;

		if (hash) *hash = '\0';
		rest = parse_hosts_addr(line, &a);
		if (!rest) continue;
		if (a.s_addr != addr->s_addr) continue;

		while (*rest == ' ' || *rest == '\t') rest++;
		if (*rest == '\0' || *rest == '\n') continue; /* address, no name: malformed */
		nametok = rest;
		while (*rest && *rest != ' ' && *rest != '\t' && *rest != '\n') rest++;
		*rest = '\0';

		if (namesz > 0) {
			size_t n = strlen(nametok);
			if (n >= namesz) n = namesz - 1;
			{
				size_t i;
				for (i = 0; i < n; i++) name[i] = nametok[i];
			}
			name[n] = '\0';
		}
		found = 1;
		break;
	}

	(void)fclose(f);
	return found;
}

int __hosts_read_entry(FILE *f, struct in_addr *addr,
                        char *name, size_t namesz,
                        char *aliasbuf, size_t aliasbufsz,
                        char **aliases, int maxaliases, int *naliases)
{
	char line[HOSTS_LINE_MAX];

	*naliases = 0;
	while (fgets(line, sizeof line, f) != NULL) {
		char *hash = strchr(line, '#');
		char *rest, *canontok;
		size_t off = 0;
		int n = 0;

		if (hash) *hash = '\0';
		rest = parse_hosts_addr(line, addr);
		if (!rest) continue;

		while (*rest == ' ' || *rest == '\t') rest++;
		if (*rest == '\0' || *rest == '\n') continue; /* address, no name: malformed */
		canontok = rest;
		while (*rest && *rest != ' ' && *rest != '\t' && *rest != '\n') rest++;
		if (*rest) *rest++ = '\0';

		if (namesz > 0) {
			size_t l = strlen(canontok);
			if (l >= namesz) l = namesz - 1;
			{
				size_t i;
				for (i = 0; i < l; i++) name[i] = canontok[i];
			}
			name[l] = '\0';
		}

		for (;;) {
			char *tok;
			size_t toklen;

			while (*rest == ' ' || *rest == '\t') rest++;
			if (*rest == '\0' || *rest == '\n') break;
			tok = rest;
			while (*rest && *rest != ' ' && *rest != '\t' && *rest != '\n') rest++;
			toklen = (size_t)(rest - tok);
			if (*rest) *rest++ = '\0';

			if (n < maxaliases && off + toklen + 1 <= aliasbufsz) {
				{
					size_t i;
					for (i = 0; i < toklen; i++) aliasbuf[off + i] = tok[i];
				}
				aliasbuf[off + toklen] = '\0';
				aliases[n++] = aliasbuf + off;
				off += toklen + 1;
			}
		}
		*naliases = n;
		return 1;
	}
	return 0;
}
