/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Linux's real <pwd.h> backend -- the "passwd" NSS database's "files"
 * service: a genuine /etc/passwd(5) parser, gated by a real
 * /etc/nsswitch.conf lookup (src/internal/nsswitch.h). src/misc/nt/pwd.c
 * is the NT sibling (NT has no /etc/passwd at all).
 *
 * There is exactly one recognized service for "passwd" in this file
 * ("files"; no LDAP/NIS/systemd-userdb backend is built). If an admin's
 * nsswitch.conf explicitly configures passwd with a service this library
 * does not implement (or an empty list), every lookup below honestly
 * reports "not found".
 *
 * Buffer-packing shape (fill_from_fields()) mirrors src/misc/nt/pwd.c's
 * fill_current()/fill_shared(): name/pw_dir/pw_shell packed back-to-back
 * into one buffer, ERANGE only ever reported to the _r forms.
 * getpwent()/setpwent()/endpwent() enumerate the REAL file sequentially,
 * unlike the NT file's honest one-entry version of the same functions.
 */
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include "nsswitch.h"
#include "nss_paths.h"
#include "ownership_stubs.h"

struct pwd_fields {
	char *name;
	char *uid_s;
	char *gid_s;
	char *home;
	char *shell;
};

/* split_passwd_line(): splits `line` (one /etc/passwd record from
 * getline(), still carrying its trailing '\n') in place on ':', the real
 * /etc/passwd(5) field separator. Returns 0 (a malformed/short line)
 * without touching *f, so callers skip it and read the next line rather
 * than fabricate a record from a corrupt one. */
static int split_passwd_line(char *line, struct pwd_fields *f)
    __attribute__((nonnull(1, 2)));
static int split_passwd_line(char *line, struct pwd_fields *f)
{
	char *fields[7];
	char *p = line;
	int i;

	for (i = 0; i < 7; i++) {
		fields[i] = p;
		if (i < 6) {
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
	f->uid_s = fields[2];
	f->gid_s = fields[3];
	f->home = fields[5];
	f->shell = fields[6];
	return 1;
}

/* fill_from_fields(): packs pw_name/pw_dir/pw_shell into buf (bufsz
 * bytes) -- see src/misc/nt/pwd.c's identical fill_current() for the
 * ERANGE/needp contract this mirrors exactly. */
static int fill_from_fields(struct passwd *pw, const struct pwd_fields *f,
                             char *buf, size_t bufsz, size_t *needp)
    __attribute__((nonnull(1, 2)));
static int fill_from_fields(struct passwd *pw, const struct pwd_fields *f,
                             char *buf, size_t bufsz, size_t *needp)
{
	size_t nl = strlen(f->name) + 1;
	size_t dl = strlen(f->home) + 1;
	size_t sl = strlen(f->shell) + 1;
	size_t need = nl + dl + sl;
	size_t i;

	if (need > bufsz) { if (needp) *needp = need; return ERANGE; }

	for (i = 0; i < nl; i++) buf[i] = f->name[i];
	pw->pw_name = buf;
	buf += nl;
	for (i = 0; i < dl; i++) buf[i] = f->home[i];
	pw->pw_dir = buf;
	buf += dl;
	for (i = 0; i < sl; i++) buf[i] = f->shell[i];
	pw->pw_shell = buf;

	pw->pw_uid = (uid_t)strtoul(f->uid_s, NULL, 10);
	pw->pw_gid = (gid_t)strtoul(f->gid_s, NULL, 10);
	return 1;
}

static int passwd_files_enabled(void)
{
	enum __nss_service order[4];
	int n = __nsswitch_order("passwd", order, 4);
	int i;

	for (i = 0; i < n; i++) if (order[i] == __NSS_SVC_FILES) return 1;
	return 0;
}

enum match_kind { MATCH_NAME, MATCH_UID };

/* scan_passwd(): one full pass over /etc/passwd (or its test-fixture
 * override), first-match-wins -- the same simplicity real nss_files uses
 * (no index, no cache), acceptable since this is a config file, not a
 * hot-path database. Returns 0 (not found / "files" service disabled), 1
 * (found), or ERANGE (found, buf too small, *needp set). */
static int scan_passwd(enum match_kind kind, const char *name, uid_t uid,
                        struct passwd *pw, char *buf, size_t bufsz, size_t *needp)
    __attribute__((nonnull(4)));
static int scan_passwd(enum match_kind kind, const char *name, uid_t uid,
                        struct passwd *pw, char *buf, size_t bufsz, size_t *needp)
{
	FILE *f;
	char *line = NULL;
	size_t linesz = 0;
	int result = 0;

	if (!passwd_files_enabled()) return 0;
	f = fopen(__NSS_PASSWD_PATH(), "r");
	if (!f) return 0;

	while (getline(&line, &linesz, f) != -1) {
		struct pwd_fields fl;

		if (!split_passwd_line(line, &fl)) continue;
		if (kind == MATCH_NAME) {
			if (strcmp(fl.name, name) != 0) continue;
		} else {
			if ((uid_t)strtoul(fl.uid_s, NULL, 10) != uid) continue;
		}
		result = fill_from_fields(pw, &fl, buf, bufsz, needp);
		break;
	}

	free(line);
	(void)fclose(f);
	return result;
}

static struct passwd g_pw;
static char *g_pwbuf;
static size_t g_pwbufsz;

static int fill_shared(enum match_kind kind, const char *name, uid_t uid)
{
	size_t need = 0;
	int r = scan_passwd(kind, name, uid, &g_pw, g_pwbuf, g_pwbufsz, &need);
	char *nb;

	if (r != ERANGE) return r;
	nb = realloc(g_pwbuf, need);
	if (!nb) return 0;
	g_pwbuf = nb;
	g_pwbufsz = need;
	r = scan_passwd(kind, name, uid, &g_pw, g_pwbuf, g_pwbufsz, &need);
	return r == ERANGE ? 0 : r;
}

/* getpwnam.html: errno must not change when not found. Unlike
 * src/misc/nt/pwd.c's getenv()-only functions, this backend does real
 * file I/O -- a successful syscall can set errno as an ordinary side
 * effect of succeeding -- so a genuine "not found" here must explicitly
 * restore the errno the caller had on entry. */
struct passwd *getpwnam(const char *name)
{
	int saved_errno = errno;

	if (!name) return 0;
	if (!fill_shared(MATCH_NAME, name, 0)) { errno = saved_errno; return 0; }
	return &g_pw;
}

struct passwd *getpwuid(uid_t uid)
{
	int saved_errno = errno;

	if (!fill_shared(MATCH_UID, NULL, uid)) { errno = saved_errno; return 0; }
	return &g_pw;
}

int getpwnam_r(const char *name, struct passwd *pwd, char *buffer,
    size_t bufsize, struct passwd **result)
{
	int r;

	*result = 0;
	if (!name) return 0;
	r = scan_passwd(MATCH_NAME, name, 0, pwd, buffer, bufsize, 0);
	if (r == ERANGE) return ERANGE;
	if (r == 0) return 0;
	*result = pwd;
	return 0;
}

int getpwuid_r(uid_t uid, struct passwd *pwd, char *buffer,
    size_t bufsize, struct passwd **result)
{
	int r;

	*result = 0;
	r = scan_passwd(MATCH_UID, NULL, uid, pwd, buffer, bufsize, 0);
	if (r == ERANGE) return ERANGE;
	if (r == 0) return 0;
	*result = pwd;
	return 0;
}

/* getpwent()/setpwent()/endpwent(): real sequential enumeration of
 * /etc/passwd. g_pwent_f/g_pwent_open_tried are reset together by
 * setpwent()/endpwent(); g_pwent_line/g_pwent_linesz are getline()'s
 * own persistent scratch buffer, deliberately NOT reset by either --
 * reusing it avoids reallocating on every line of a long /etc/passwd. */
static FILE *g_pwent_f withtok(file_stream_open);
static int g_pwent_open_tried;
static char *g_pwent_line;
static size_t g_pwent_linesz;

void setpwent(void)
{
	if (g_pwent_f) { (void)fclose(g_pwent_f); g_pwent_f = 0; }
	g_pwent_open_tried = 0;
}

void endpwent(void)
{
	setpwent();
}

/* getpwent.html: errno unchanged at end-of-file. Same real-file-I/O
 * reasoning as getpwnam()/getpwuid() above: every "return 0" path here
 * restores the errno this call started with. */
struct passwd *getpwent(void)
{
	int saved_errno = errno;

	if (!g_pwent_open_tried) {
		g_pwent_open_tried = 1;
		if (passwd_files_enabled()) g_pwent_f = fopen(__NSS_PASSWD_PATH(), "r");
	}
	if (!g_pwent_f) { errno = saved_errno; return 0; }

	while (getline(&g_pwent_line, &g_pwent_linesz, g_pwent_f) != -1) {
		struct pwd_fields fl;
		size_t need = 0;
		int r;

		if (!split_passwd_line(g_pwent_line, &fl)) continue;
		r = fill_from_fields(&g_pw, &fl, g_pwbuf, g_pwbufsz, &need);
		if (r == ERANGE) {
			char *nb = realloc(g_pwbuf, need);
			if (!nb) { errno = saved_errno; return 0; }
			g_pwbuf = nb;
			g_pwbufsz = need;
			/* `fl`'s pointers are unaffected by growing g_pwbuf (a
			 * separate allocation) and still reference g_pwent_line. */
			r = fill_from_fields(&g_pw, &fl, g_pwbuf, g_pwbufsz, &need);
		}
		if (r != 1) { errno = saved_errno; return 0; }
		return &g_pw;
	}
	errno = saved_errno;
	return 0;
}
