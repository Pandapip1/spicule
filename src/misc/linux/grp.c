/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux's real <grp.h> backend -- the "group" database's "files" service,
 * mirroring src/misc/linux/pwd.c exactly. See that file's header for the
 * reasoning this one does not repeat, and src/misc/nt/grp.c for the NT
 * sibling.
 *
 * The one real structural difference from pwd.c: gr_mem is a
 * variable-length NULL-terminated array of member-name strings, so
 * fill_from_fields() below packs a pointer array plus its pointed-to
 * strings into the buffer, generalizing src/misc/nt/grp.c's
 * fill_current()/fill_current_r() layout to however many members one
 * real /etc/group line lists.
 */
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include "nsswitch.h"
#include "nss_paths.h"

struct grp_fields {
	char *name;
	char *gid_s;
	char *members; /* comma-separated, possibly empty; not yet split */
};

/* split_group_line(): mirrors src/misc/linux/pwd.c's
 * split_passwd_line() exactly, for /etc/group's 4-field record shape
 * (name:passwd:gid:member,member,...). line/f required, same
 * reasoning as that file's identical function. */
static int split_group_line(char *line, struct grp_fields *f)
    __attribute__((nonnull(1, 2)));
static int split_group_line(char *line, struct grp_fields *f)
{
	char *fields[4];
	char *p = line;
	int i;

	for (i = 0; i < 4; i++) {
		fields[i] = p;
		if (i < 3) {
			char *c = strchr(p, ':');
			if (!c) return 0;
			*c = '\0';
			p = c + 1;
		} else {
			char *nl = strchr(p, '\n');
			if (nl) *nl = '\0';
		}
	}
	f->name = fields[0];
	f->gid_s = fields[2];
	f->members = fields[3];
	return 1;
}

/* fill_from_fields(): packs gr_name, gr_mem's pointer array, and gr_mem's
 * pointed-to member strings into buf (bufsz bytes) -- ERANGE/needp
 * contract identical to src/misc/linux/pwd.c's own function of the same
 * name. Layout: name string, then pointer-aligned (nmem+1) char* array,
 * then each member's own NUL-terminated copy (the comma-separated
 * `members` field re-split into buf, not mutated in its original
 * getline() buffer, which getgrent() reuses across calls). */
static int fill_from_fields(struct group *gr, const struct grp_fields *f,
                             char *buf, size_t bufsz, size_t *needp)
    __attribute__((nonnull(1, 2)));
static int fill_from_fields(struct group *gr, const struct grp_fields *f,
                             char *buf, size_t bufsz, size_t *needp)
{
	size_t namelen = strlen(f->name) + 1;
	size_t pad, need, memberbytes;
	int nmem = 0;
	const char *p;
	char **mem;
	char *out;

	if (*f->members) {
		nmem = 1;
		for (p = f->members; *p; p++) if (*p == ',') nmem++;
	}
	memberbytes = strlen(f->members) + 1;

	pad = (sizeof(char *) - ((uintptr_t)(buf + namelen) % sizeof(char *))) % sizeof(char *);
	need = namelen + pad + (size_t)(nmem + 1) * sizeof(char *) + memberbytes;
	if (need > bufsz) { if (needp) *needp = need; return ERANGE; }

	out = buf;
	memcpy(out, f->name, namelen);
	gr->gr_name = out;
	out += namelen + pad;

	mem = (char **)(void *)out;
	out += (size_t)(nmem + 1) * sizeof(char *);

	memcpy(out, f->members, memberbytes);
	if (nmem > 0) {
		int idx = 0;
		char *q = out;

		mem[idx++] = q;
		for (; *q; q++) {
			if (*q == ',') {
				*q = '\0';
				mem[idx++] = q + 1;
			}
		}
	}
	mem[nmem] = NULL;

	gr->gr_gid = (gid_t)strtoul(f->gid_s, NULL, 10);
	gr->gr_mem = mem;
	return 1;
}

static int group_files_enabled(void)
{
	enum __nss_service order[4];
	int n = __nsswitch_order("group", order, 4);
	int i;

	for (i = 0; i < n; i++) if (order[i] == __NSS_SVC_FILES) return 1;
	return 0;
}

enum match_kind { MATCH_NAME, MATCH_GID };

static int scan_group(enum match_kind kind, const char *name, gid_t gid,
                       struct group *gr, char *buf, size_t bufsz, size_t *needp)
    __attribute__((nonnull(4)));
static int scan_group(enum match_kind kind, const char *name, gid_t gid,
                       struct group *gr, char *buf, size_t bufsz, size_t *needp)
{
	FILE *f;
	char *line = NULL;
	size_t linesz = 0;
	int result = 0;

	if (!group_files_enabled()) return 0;
	f = fopen(__NSS_GROUP_PATH(), "r");
	if (!f) return 0;

	while (getline(&line, &linesz, f) != -1) {
		struct grp_fields fl;

		if (!split_group_line(line, &fl)) continue;
		if (kind == MATCH_NAME) {
			if (strcmp(fl.name, name) != 0) continue;
		} else {
			if ((gid_t)strtoul(fl.gid_s, NULL, 10) != gid) continue;
		}
		result = fill_from_fields(gr, &fl, buf, bufsz, needp);
		break;
	}

	free(line);
	(void)fclose(f);
	return result;
}

static struct group g_gr;
static char *g_grbuf;
static size_t g_grbufsz;

static int fill_shared(enum match_kind kind, const char *name, gid_t gid)
{
	size_t need = 0;
	int r = scan_group(kind, name, gid, &g_gr, g_grbuf, g_grbufsz, &need);
	char *nb;

	if (r != ERANGE) return r;
	nb = realloc(g_grbuf, need);
	if (!nb) return 0;
	g_grbuf = nb;
	g_grbufsz = need;
	r = scan_group(kind, name, gid, &g_gr, g_grbuf, g_grbufsz, &need);
	return r == ERANGE ? 0 : r;
}

/* errno save/restore on the not-found path: same reasoning as
 * src/misc/linux/pwd.c's identical getpwnam()/getpwuid(). */
struct group *getgrnam(const char *name)
{
	int saved_errno = errno;

	if (!name) return 0;
	if (!fill_shared(MATCH_NAME, name, 0)) { errno = saved_errno; return 0; }
	return &g_gr;
}

struct group *getgrgid(gid_t gid)
{
	int saved_errno = errno;

	if (!fill_shared(MATCH_GID, NULL, gid)) { errno = saved_errno; return 0; }
	return &g_gr;
}

int getgrnam_r(const char *name, struct group *grp, char *buffer,
    size_t bufsize, struct group **result)
{
	int r;

	*result = 0;
	if (!name) return 0;
	r = scan_group(MATCH_NAME, name, 0, grp, buffer, bufsize, 0);
	if (r == ERANGE) return ERANGE;
	if (r == 0) return 0;
	*result = grp;
	return 0;
}

int getgrgid_r(gid_t gid, struct group *grp, char *buffer,
    size_t bufsize, struct group **result)
{
	int r;

	*result = 0;
	r = scan_group(MATCH_GID, NULL, gid, grp, buffer, bufsize, 0);
	if (r == ERANGE) return ERANGE;
	if (r == 0) return 0;
	*result = grp;
	return 0;
}

/* getgrent()/setgrent()/endgrent(): real sequential enumeration,
 * mirroring src/misc/linux/pwd.c's getpwent() exactly -- see that
 * file's own comment for why g_grent_line/g_grent_linesz persist
 * across calls while g_grent_f/g_grent_open_tried are reset together. */
static FILE *g_grent_f withtok(file_stream_open);
static int g_grent_open_tried;
static char *g_grent_line;
static size_t g_grent_linesz;

void setgrent(void)
{
	if (g_grent_f) { (void)fclose(g_grent_f); g_grent_f = 0; }
	g_grent_open_tried = 0;
}

void endgrent(void)
{
	setgrent();
}

/* errno save/restore on every "return 0" path: same reasoning as
 * src/misc/linux/pwd.c's identical getpwent(). */
struct group *getgrent(void)
{
	int saved_errno = errno;

	if (!g_grent_open_tried) {
		g_grent_open_tried = 1;
		if (group_files_enabled()) g_grent_f = fopen(__NSS_GROUP_PATH(), "r");
	}
	if (!g_grent_f) { errno = saved_errno; return 0; }

	while (getline(&g_grent_line, &g_grent_linesz, g_grent_f) != -1) {
		struct grp_fields fl;
		size_t need = 0;
		int r;

		if (!split_group_line(g_grent_line, &fl)) continue;
		r = fill_from_fields(&g_gr, &fl, g_grbuf, g_grbufsz, &need);
		if (r == ERANGE) {
			char *nb = realloc(g_grbuf, need);
			if (!nb) { errno = saved_errno; return 0; }
			g_grbuf = nb;
			g_grbufsz = need;
			r = fill_from_fields(&g_gr, &fl, g_grbuf, g_grbufsz, &need);
		}
		if (r != 1) { errno = saved_errno; return 0; }
		return &g_gr;
	}
	errno = saved_errno;
	return 0;
}
