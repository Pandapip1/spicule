/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT's <pwd.h> backend. src/misc/linux/pwd.c (the NSS pass) is Linux's
 * real, file-backed sibling.
 *
 * NT has no /etc/passwd, but this library has exactly one current uid, so
 * "the current user" is the only user this library can ever be asked
 * about honestly:
 *
 *   pw_name  -- %USERNAME%, falling back to %USER%, the same lookup
 *               getlogin() (src/unistd/ids.c) uses, so the two agree.
 *   pw_uid / pw_gid -- getuid()/getgid(), not a separate constant.
 *   pw_dir   -- %USERPROFILE%, NT's real analogue of a home directory.
 *   pw_shell -- %ComSpec%, the same value src/stdlib/system.c's
 *               find_shell() treats as "the shell" on this OS. Unlike
 *               find_shell(), not re-validated with access(X_OK):
 *               pw_shell is documented metadata, not a runnability
 *               promise, and POSIX does not require that check.
 *
 * Any *other* name or uid is refused cleanly (NULL, errno untouched, per
 * getpwnam.html's "not found" case) -- there is no database to enumerate
 * a second entry out of.
 *
 * getpwent()/setpwent()/endpwent(): implemented, not stubbed. spicule's
 * user database genuinely contains exactly one entry, so "rewind, yield
 * that one entry, then EOF" is the honest enumeration of it.
 */
#include <pwd.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "ownership_stubs.h"

/* Non-reentrant getpwnam()/getpwuid()/getpwent() share this static
 * storage; none of these functions are required to be thread-safe.
 * Grown on demand rather than fixed, because POSIX gives the non-_r forms
 * NO WAY to report that this buffer was too small -- [ERANGE] is only
 * defined for getpwnam_r()/getpwuid_r(). See fill_shared(). */
static struct passwd g_pw;
static char *g_pwbuf;
static size_t g_pwbufsz;

/* current_name(): the same %USERNAME%-then-%USER% lookup getlogin()
 * (src/unistd/ids.c) uses, so getpwnam(getlogin()) and
 * getpwuid(getuid())->pw_name round-trip through the identical
 * source.  Returns NULL if genuinely unknowable. */
static const char *current_name(void)
{
	const char *n = getenv("USERNAME");
	if (!n || !*n) n = getenv("USER");
	if (n && !*n) n = 0;
	return n;
}

/* fill_current(): pack the current user's record into buf (bufsz bytes).
 * Returns 1 on success, 0 if the user's name is unknowable (treated as
 * "not found" by every caller), or ERANGE if buf is too small, in which
 * case *needp is set to the size that would do. Never touches the global
 * errno -- callers decide whether the return travels through errno
 * (getpwnam(), getpwuid()) or is returned directly (the _r variants). */
static int fill_current(struct passwd *pw, char *buf, size_t bufsz, size_t *needp)
    __attribute__((nonnull(1)));
static int fill_current(struct passwd *pw, char *buf, size_t bufsz, size_t *needp)
{
	const char *name = current_name();
	const char *dir, *shell;
	size_t nl, dl, sl, need;

	if (!name) return 0;

	dir = getenv("USERPROFILE");
	if (!dir || !*dir) dir = "/";
	shell = getenv("ComSpec");
	if (!shell || !*shell) shell = "cmd.exe";

	nl = strlen(name) + 1;
	dl = strlen(dir) + 1;
	sl = strlen(shell) + 1;
	need = nl + dl + sl;
	if (need > bufsz) { if (needp) *needp = need; return ERANGE; }

	__ownership_writable_span(buf, nl);
	memmove(buf, name, nl);
	pw->pw_name = buf;
	buf += nl;
	__ownership_writable_span(buf, dl);
	memmove(buf, dir, dl);
	pw->pw_dir = buf;
	buf += dl;
	__ownership_writable_span(buf, sl);
	memmove(buf, shell, sl);
	pw->pw_shell = buf;

	pw->pw_uid = getuid();
	pw->pw_gid = getgid();
	return 1;
}

/* fill_current() into the shared buffer, growing it if it does not fit.
 * Returns 1 on success, 0 for "not found". Never reports ERANGE, unlike a
 * fixed-size buffer would: [ERANGE] is not in getpwnam()/getpwuid()'s
 * ERRORS list, and a long enough %USERNAME%/%USERPROFILE%/%ComSpec% could
 * reach it. An allocation failure is likewise reported as "not found"
 * with errno left alone, since [ENOMEM] isn't in the ERRORS list either.
 * The returned strings point into this buffer, which a later call may
 * reallocate -- getpwnam.html permits exactly that. */
static int fill_shared(void)
{
	size_t need = 0;
	int r = fill_current(&g_pw, g_pwbuf, g_pwbufsz, &need);
	char *nb;

	if (r != ERANGE) return r;
	nb = realloc(g_pwbuf, need);
	if (!nb) return 0;
	g_pwbuf = nb;
	g_pwbufsz = need;
	r = fill_current(&g_pw, g_pwbuf, g_pwbufsz, &need);
	return r == ERANGE ? 0 : r;
}

/* getpwnam.html RETURN VALUE: "If the requested entry was not found,
 * errno shall not be changed."  These functions now never set errno at
 * all: the only errno they ever set was the [ERANGE] that is not in
 * their ERRORS list, and fill_shared() removes that case. */
struct passwd *getpwnam(const char *name)
{
	const char *cur = current_name();
	int r;

	if (!name || !cur || strcmp(name, cur) != 0) return 0;
	r = fill_shared();
	if (r == 0) return 0;
	return &g_pw;
}

struct passwd *getpwuid(uid_t uid)
{
	int r;

	if (uid != getuid()) return 0;
	r = fill_shared();
	if (r == 0) return 0;
	return &g_pw;
}

/* getpwnam_r()/getpwuid_r() (Thread-Safe Functions option; spicule has
 * no feature-test gate for it, same as the rest of this library's
 * _r functions).  Return value is the error number itself (0 on
 * success or clean not-found), never routed through errno; *result
 * is set to NULL in both the error and not-found cases. */
int getpwnam_r(const char *name, struct passwd *pwd, char *buffer,
    size_t bufsize, struct passwd **result)
{
	const char *cur;
	int r;

	*result = 0;
	if (!name) return 0;
	cur = current_name();
	if (!cur || strcmp(name, cur) != 0) return 0;
	r = fill_current(pwd, buffer, bufsize, 0);
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
	if (uid != getuid()) return 0;
	r = fill_current(pwd, buffer, bufsize, 0);
	if (r == ERANGE) return ERANGE;
	if (r == 0) return 0;
	*result = pwd;
	return 0;
}

/* getpwent()/setpwent()/endpwent(): the one-entry "database" this
 * library actually has.  g_pwent_done tracks whether the single entry
 * has already been handed out this pass; setpwent() rewinds it,
 * endpwent() "closes" it the same way (there is nothing else to
 * release). */
static int g_pwent_done;

void setpwent(void)
{
	g_pwent_done = 0;
}

void endpwent(void)
{
	g_pwent_done = 0;
}

/* getpwent.html RETURN VALUE: "On end-of-file, getpwent() shall
 * return a null pointer and shall not change the setting of errno."
 * That is exactly what happens once the one entry has been given out,
 * and also (indistinguishably, but honestly -- there genuinely is
 * nothing further to enumerate) if the current user's name could not
 * be determined at all. */
struct passwd *getpwent(void)
{
	if (g_pwent_done) return 0;
	g_pwent_done = 1;
	return getpwuid(getuid());
}
