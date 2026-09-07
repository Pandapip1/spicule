/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT's <grp.h> backend -- see src/misc/nt/pwd.c's banner for the same
 * reasoning applied to <pwd.h>; src/misc/linux/grp.c is Linux's real,
 * file-backed sibling.
 *
 * NT has no /etc/group, but this library has exactly one gid (getgid()
 * always reports 1000), so "the current group" is the only group this
 * library can ever be asked about honestly:
 *
 *   gr_name -- the same %USERNAME%-then-%USER% lookup src/misc/pwd.c's
 *              current_name() uses. NT has no group-name database this
 *              library can query without LSA, so naming the group after
 *              the user matches the "user private group" convention
 *              several real Unix systems use (Fedora/RHEL's useradd
 *              default, for one).
 *   gr_gid  -- getgid(), not a separate constant.
 *   gr_mem  -- {gr_name, NULL}: the current user genuinely is the only
 *              member of this group, so there's no primary-vs-
 *              supplementary distinction to draw.
 *
 * Any *other* name or gid is refused cleanly (NULL, errno untouched) --
 * there is no database to enumerate a second entry out of.
 */
#include <grp.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

/* Non-reentrant getgrnam()/getgrgid()/getgrent() share this static
 * storage; none of these functions are required to be thread-safe. */
static struct group g_gr;
static char *g_grmem[2];
/* Grown on demand rather than fixed, for the reason spelled out in
 * src/misc/pwd.c beside g_pwbuf: [ERANGE] is only defined for
 * getgrnam_r()/getgrgid_r(), so the non-_r forms have no way to report
 * that this internal buffer was too small. See fill_shared(). */
static char *g_grbuf;
static size_t g_grbufsz;

/* current_name(): identical lookup to src/misc/pwd.c's -- kept as a
 * separate static so this file has no link-time dependency on pwd.c. */
static const char *current_name(void)
{
	const char *n = getenv("USERNAME");
	if (!n || !*n) n = getenv("USER");
	if (n && !*n) n = 0;
	return n;
}

/* fill_current(): pack the current group's record into buf (bufsz
 * bytes): the name once, plus a two-element gr_mem pointer array
 * (gr_mem[0] aliases the same stored name; gr_mem is not a second
 * copy). Returns 1 on success, 0 if the name is unknowable (treated as
 * "not found" by every caller), or ERANGE if buf is too small, in which
 * case *needp is set to the size that would do. */
static int fill_current(struct group *gr, char **mem, char *buf, size_t bufsz, size_t *needp)
    __attribute__((nonnull(1, 2)));
static int fill_current(struct group *gr, char **mem, char *buf, size_t bufsz, size_t *needp)
{
	const char *name = current_name();
	size_t nl;

	if (!name) return 0;

	nl = strlen(name) + 1;
	if (nl > bufsz) { if (needp) *needp = nl; return ERANGE; }

	strcpy(buf, name);
	gr->gr_name = buf;
	gr->gr_gid = getgid();
	mem[0] = buf;
	mem[1] = 0;
	gr->gr_mem = mem;
	return 1;
}

/* getgrnam_r()/getgrgid_r() need their own two-element gr_mem array per
 * call (the caller-supplied buffer has no room set aside for pointers),
 * so each _r call carves one out of its own buffer: enough leading
 * padding to bring buf up to pointer alignment (a caller-supplied char[]
 * buffer carries no alignment guarantee beyond char, and mem[0]/mem[1]
 * are accessed as char* here), then the two pointers, then the name. */
static int fill_current_r(struct group *gr, char *buf, size_t bufsz)
    __attribute__((nonnull(1)));
static int fill_current_r(struct group *gr, char *buf, size_t bufsz)
{
	size_t pad, need;
	char **mem;

	/* "Not found" (no current_name()) must win over ERANGE regardless of
	 * how small buf is -- same ordering as src/misc/pwd.c's fill_current(). */
	if (!current_name()) return 0;

	pad = (sizeof(char *) - ((uintptr_t)buf % sizeof(char *))) % sizeof(char *);
	need = pad + sizeof(char *) * 2;
	if (bufsz < need) return ERANGE;
	mem = (char **)(buf + pad);
	buf += need;
	bufsz -= need;
	return fill_current(gr, mem, buf, bufsz, 0);
}

/* fill_current() into the shared buffer, growing it if it does not fit.
 * Returns 1 on success, 0 for "not found", never ERANGE -- same rationale
 * and allocation-failure policy as src/misc/pwd.c's fill_shared(). */
static int fill_shared(void)
{
	size_t need = 0;
	int r = fill_current(&g_gr, g_grmem, g_grbuf, g_grbufsz, &need);
	char *nb;

	if (r != ERANGE) return r;
	nb = realloc(g_grbuf, need);
	if (!nb) return 0;
	g_grbuf = nb;
	g_grbufsz = need;
	r = fill_current(&g_gr, g_grmem, g_grbuf, g_grbufsz, &need);
	return r == ERANGE ? 0 : r;
}

struct group *getgrnam(const char *name)
{
	const char *cur = current_name();
	int r;

	if (!name || !cur || strcmp(name, cur) != 0) return 0;
	r = fill_shared();
	if (r == 0) return 0;
	return &g_gr;
}

struct group *getgrgid(gid_t gid)
{
	int r;

	if (gid != getgid()) return 0;
	r = fill_shared();
	if (r == 0) return 0;
	return &g_gr;
}

/* getgrnam_r()/getgrgid_r() (Thread-Safe Functions option; spicule has
 * no feature-test gate for it, same as the rest of this library's _r
 * functions).  Return value is the error number itself (0 on success
 * or clean not-found), never routed through errno; *result is set to
 * NULL in both the error and not-found cases. */
int getgrnam_r(const char *name, struct group *grp, char *buffer,
    size_t bufsize, struct group **result)
{
	const char *cur;
	int r;

	*result = 0;
	if (!name) return 0;
	cur = current_name();
	if (!cur || strcmp(name, cur) != 0) return 0;
	r = fill_current_r(grp, buffer, bufsize);
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
	if (gid != getgid()) return 0;
	r = fill_current_r(grp, buffer, bufsize);
	if (r == ERANGE) return ERANGE;
	if (r == 0) return 0;
	*result = grp;
	return 0;
}

/* getgrent()/setgrent()/endgrent(): the one-entry "database" this
 * library actually has, mirroring src/misc/pwd.c's getpwent() family. */
static int g_grent_done;

void setgrent(void)
{
	g_grent_done = 0;
}

void endgrent(void)
{
	g_grent_done = 0;
}

/* getgrent.html RETURN VALUE: "the null pointer" at end-of-file,
 * without disturbing errno -- exactly what happens once the one entry
 * has been given out, and also (indistinguishably, but honestly) if
 * the current user's name could not be determined at all. */
struct group *getgrent(void)
{
	if (g_grent_done) return 0;
	g_grent_done = 1;
	return getgrgid(getgid());
}
