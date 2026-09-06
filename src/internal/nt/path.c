/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * __ntpath()/__ntpath_at() and their supporting machinery: turning a
 * POSIX path into an NT one is inherently NT's own object-manager
 * encoding (UNICODE_STRING, OBJECT_ATTRIBUTES, RtlDosPathNameToNtPathName_U's
 * DOS->NT conversion), not a POSIX-shaped interface with an NT body, so
 * this file has no Linux counterpart -- every caller already lives under
 * nt/ itself.
 *
 * A program hands in UTF-8 with either kind of slash, relative or
 * absolute, possibly with a drive letter and possibly not; ntdll wants
 * UTF-16 in the \??\C:\... form, inside a UNICODE_STRING, inside an
 * OBJECT_ATTRIBUTES. RtlDosPathNameToNtPathName_U does the hard part
 * (resolving relative paths against the current directory, . and ..,
 * per-drive current directories, UNC names); this file does the rest.
 *
 * A rooted path with no drive ("/usr/bin/sh") is taken relative to the
 * root of the current drive, the same thing Windows itself does with
 * "\usr\bin\sh". Fixed POSIX objects are resolved before this layer;
 * native paths that win that resolution are passed through unchanged.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include "libc.h"
#include "ownership_stubs.h"

/* XBD <limits.h> {NAME_MAX}: BYTES, not characters. This is NOT the
 * [ENAMETOOLONG] this library already had for the whole-path
 * __US_MAX_WCHARS bound (~32k code units) -- that bound says nothing
 * about a 300-byte component sitting inside a short path. This function
 * implements the per-component shall-fail clause, boilerplate on
 * open/stat/unlink/mkdir/link/rename/chmod/chdir/utimensat/opendir/etc.
 *
 * MEASURED: NTFS bounds a component at 255 UTF-16 code units;
 * {NAME_MAX} bounds it at 255 bytes. They part company on multi-byte
 * UTF-8: 100 CJK characters are 300 bytes but only 100 code units, and
 * before this check open()/openat()/mkdir() created such a name
 * successfully; they now refuse it, matching glibc measured on ext4
 * (same 255-byte limit).
 *
 * Zero-length pieces (a doubled separator, the empty piece before a
 * leading slash) are not components and are not measured. Both
 * separators are recognised since dos_from_posix() has not yet run. */
int __name_too_long(const char *path)
{
	const char *p = path;
	size_t component = 0;

	while (*p) {
		if (*p == '/' || *p == '\\') {
			if (component > NAME_MAX) return 1;
			component = 0;
		} else {
			component++;
		}
		p++;
	}
	return component > NAME_MAX;
}

withtok(internal_heap_allocated)
static WCHAR *dos_from_posix(const char *path, size_t *wlen, int *trailing)
{
	WCHAR *w;
	size_t i, n;

	if (__name_too_long(path)) { errno = ENAMETOOLONG; return 0; }
	w = __utf8_to_utf16(path, &n);
	if (!w) return 0;
	for (i = 0; i < n; i++)
		if (w[i] == '/') w[i] = '\\';
	/* Strip a trailing slash: "dir/" must mean "dir" to NtCreateFile --
	 * but remember it was there ("root" paths like "/" or "C:\" do not
	 * count: they can only ever name a directory) so the caller can
	 * still reject the name if what it resolves to is not one. */
	if (trailing) *trailing = n > 1 && w[n-1] == '\\' && !(n == 3 && w[1] == ':');
	while (n > 1 && w[n-1] == '\\' && !(n == 3 && w[1] == ':')) w[--n] = 0;
	if (wlen) *wlen = n;
	return w;
}

/* access.html ERRORS ENOTDIR / open.html DESCRIPTION: a trailing slash
 * requires the resolved name to be a directory. The slash itself is
 * already stripped from *out (NtCreateFile does not accept one), so this
 * re-checks the object type with a handle-less attribute query. Only
 * rejects a trailing slash on something that positively exists and is
 * not a directory; leaves everything else to the real operation. */
static int reject_if_not_dir(struct __ntpath *out)
{
	FILE_BASIC_INFORMATION bi;
	NTSTATUS st = NtQueryAttributesFile(&out->oa, &bi);
	if (NT_SUCCESS(st) && !(bi.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
		__ntpath_free(out);
		errno = ENOTDIR;
		return -1;
	}
	return 0;
}

/* Where __nt_prefix_not_dir() may start truncating an NT path. A drive
 * path ("\??\C:\...") may lose everything below "\??\C:\"; a name that is
 * not of that shape ("\??\NUL", a UNC name) has no prefix this can say
 * anything about, and is reported as having none. Every access below is
 * guarded by `n < 7` first. */
static size_t nt_prefix_root(const UNICODE_STRING *nt)
{
	const WCHAR *b = nt->Buffer;
	size_t n = nt->Length / sizeof(WCHAR);

	if (n < 7 || b[0] != '\\' || b[1] != '?' || b[2] != '?' || b[3] != '\\') return n;
	if (!__nt_is_drive_letter(b[4]) || b[5] != ':' || b[6] != '\\') return n;
	return 7;
}

/* open.html (and stat, access, unlink, mkdir, utime, ... -- boilerplate
 * across the filesystem surface) ERRORS [ENOTDIR]: "A component of the
 * path prefix names an existing file that is neither a directory nor a
 * symbolic link to a directory."
 *
 * NT gives no way to tell that apart from a prefix that simply is not
 * there: the object manager answers both with STATUS_OBJECT_PATH_NOT_FOUND,
 * which maps to ENOENT (right for "not there", wrong for "exists but not
 * a directory"). So the prefix is checked here, the same way
 * reject_if_not_dir() checks the last component: a handle-less attribute
 * query, verdict only when the answer is positive.
 *
 * The walk runs from the nearest ancestor outwards, so the first one that
 * exists decides: if it is a directory the whole prefix is a directory
 * chain; if not, that is the ENOTDIR case. Cost is one query for a path
 * that has a prefix at all; deeper ancestors are only checked once a
 * nearer one comes back missing, on a path that was going to fail
 * regardless.
 *
 * Exposed rather than kept private to __ntpath() because chdir() needs
 * the same verdict but hand-builds its own UNICODE_STRING for
 * RtlSetCurrentDirectory_U() rather than going through this file's
 * builder, so the arguments are the NT path and the RootDirectory handle
 * it is relative to (0 for absolute) rather than a struct __ntpath. Where
 * truncation may start follows from that handle: an absolute NT path
 * keeps everything up to and including the drive's backslash, while every
 * component of a RootDirectory-relative name may be cut.
 *
 * Returns 1 when a component of the path prefix positively exists and is
 * not a directory, 0 otherwise; errno is not touched.
 *
 * Caveat for testing under Wine rather than real NT: Wine's
 * NtQueryAttributesFile resolves a RootDirectory-relative query against
 * the *process* working directory instead of the root handle, so it can
 * answer about the wrong file entirely (and, symmetrically, does not
 * reject openat(dirfd, "file/", ...) the way real NT does). The
 * dirfd-relative half of both checks is a real-Windows question, not a
 * Wine-testable one. */
int __nt_prefix_not_dir(const UNICODE_STRING *nt, HANDLE root)
{
	FILE_BASIC_INFORMATION bi;
	UNICODE_STRING cut = *nt;
	OBJECT_ATTRIBUTES oa;
	size_t floor = root ? 0 : nt_prefix_root(nt);
	size_t i = nt->Length / sizeof(WCHAR);

	if (i > 0xffffu / sizeof(WCHAR)) return 0;
	InitializeObjectAttributes(&oa, &cut, OBJ_CASE_INSENSITIVE, root, 0);
	while (i > floor) {
		NTSTATUS st;
		if (nt->Buffer[--i] != '\\') continue;
		/* `i` starts at nt->Length / sizeof(WCHAR) and only decreases. */
		cut.Length = (USHORT)(i * sizeof(WCHAR));
		st = NtQueryAttributesFile(&oa, &bi);
		if (NT_SUCCESS(st))
			return !(bi.FileAttributes & FILE_ATTRIBUTE_DIRECTORY);
		if (st != STATUS_OBJECT_NAME_NOT_FOUND && st != STATUS_OBJECT_PATH_NOT_FOUND)
			return 0;
	}
	return 0;
}

/* The __ntpath-side wrapper: the same verdict, but freeing the path and
 * reporting it the way the rest of this file reports a failure. */
static int reject_if_prefix_not_dir(struct __ntpath *out, HANDLE root)
{
	if (!__nt_prefix_not_dir(&out->nt, root)) return 0;
	__ntpath_free(out);
	errno = ENOTDIR;
	return -1;
}

/* Defined below, next to normalize_rel(), which it uses. */
static int nt_path_over_max_path(const WCHAR *dos, size_t n, int *trailing,
                                 struct __ntpath *out, ULONG attributes);

static int ntpath_impl(const char *path, struct __ntpath *out, ULONG attributes, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
                       int overlay)
{
	int vfs;
	WCHAR *dos;
	size_t n;
	int trailing;
	NTSTATUS st;

	if (!path) { errno = EFAULT; return -1; }
	if (!*path) { errno = ENOENT; return -1; }
	if (overlay) {
		vfs = __vfs_resolve_at(AT_FDCWD, path);
		if (vfs < 0) return -1;
		if (vfs != __VFS_NONE && !(vfs & __VFS_NATIVE)) {
			errno = vfs == __VFS_MISSING ? ENOENT : EROFS;
			return -1;
		}
	}

	dos = dos_from_posix(path, &n, &trailing);
	if (!dos) return -1;

	/* Same ceiling as the hand-built UNICODE_STRING in __ntpath_at() below:
	 * a name past __US_MAX_WCHARS code units cannot be described by one at
	 * all. Reported here rather than falling into the catch-all ENOENT
	 * below, agreeing with chdir()'s own check of its hand-built string. */
	if (n > __US_MAX_WCHARS) { __free(dos); errno = ENAMETOOLONG; return -1; }

	memset(out, 0, sizeof *out);
	st = RtlDosPathNameToNtPathName_U_WithStatus(dos, &out->nt, 0, 0);
	if (NT_SUCCESS(st)) {
		out->buf = out->nt.Buffer;
		out->dos = dos;
		InitializeObjectAttributes(&out->oa, &out->nt, attributes, 0, 0);
	} else if (st == STATUS_NAME_TOO_LONG &&
	           !nt_path_over_max_path(dos, n, &trailing, out, attributes)) {
		/* The Rtl refused a name real NT can perfectly well open; the
		 * NT path was built here instead.  See that function. */
		__free(dos);
	} else {
		__free(dos);
		/* A relative name that fits on its own can still overflow once it
		 * is resolved against the current directory; the Rtl says so with
		 * STATUS_NAME_TOO_LONG, which is the same ENAMETOOLONG case. */
		errno = st == STATUS_NO_MEMORY ? ENOMEM :
			st == STATUS_NAME_TOO_LONG ? ENAMETOOLONG : ENOENT;
		return -1;
	}
	if (trailing && reject_if_not_dir(out)) return -1;
	if (reject_if_prefix_not_dir(out, 0)) return -1;
	return 0;
}

int __ntpath(const char *path, struct __ntpath *out, ULONG attributes)
{
	return ntpath_impl(path, out, attributes, 1);
}

int __ntpath_native(const char *path, struct __ntpath *out, ULONG attributes)
{
	return ntpath_impl(path, out, attributes, 0);
}

/* Lexical resolution of "." and ".." in a RootDirectory-relative name.
 * The NT object manager does not implement XBD 4.13 pathname resolution
 * in a name resolved against a RootDirectory handle -- it takes the name
 * as a literal sequence of components -- so without this pass
 * openat(dfd, "./f", ...) failed with ENOENT while openat(dfd, "f", ...)
 * on the same file succeeded, and no spelling of ".." could reach a
 * parent at all.
 *
 * Resolving ".." by string surgery is not strictly what XBD 4.13 asks
 * for (a preceding symlink component's target parent isn't the lexical
 * parent), but this is what the REST OF THIS LIBRARY already does: the
 * AT_FDCWD/absolute branch resolves through RtlDosPathNameToNtPathName_U,
 * Windows path normalisation performed before the filesystem is
 * consulted. Measured: stat("d/nonexistent/../f") and
 * stat("d/regularfile/../f") both return 0 through that branch, so this
 * pass agrees with it rather than being independently "more correct" and
 * inconsistent. The gap is fenced in test/posix-unreferenced.c,
 * test_pathres_dotdot_over_nondir().
 *
 * Operates in place -- the result is never longer than the input.
 * Returns 0 with *np and *trailing updated, or 1 if the name escapes
 * above the RootDirectory (a leading ".." with nothing to pop), which a
 * RootDirectory-relative name cannot express. */
static int normalize_rel(WCHAR *w, size_t *np, int *trailing)
{
	size_t n = *np, out = 0, i = 0;
	int lastdot = 0;

	while (i < n) {
		size_t j = i, len;
		while (j < n && w[j] != '\\') j++;
		len = j - i;
		if (len == 0) {
			/* a doubled separator: no component at all */
		} else if (len == 1 && w[i] == '.') {
			lastdot = 1;
		} else if (len == 2 && w[i] == '.' && w[i+1] == '.') {
			if (out == 0) return 1;               /* above the root */
			while (out > 0 && w[out-1] != '\\') out--;
			if (out > 0) out--;                   /* and its separator */
			lastdot = 1;
		} else {
			/* out < i whenever out > 0 (each emitted component is at
			 * least as short as its source and i has passed a
			 * separator), so this never overwrites the source. */
			if (out) w[out++] = '\\';
			{
				size_t k;
				for (k = 0; k < len; k++) w[out + k] = w[i + k];
			}
			out += len;
			lastdot = 0;
		}
		i = j < n ? j + 1 : j;
	}
	w[out] = 0;
	*np = out;
	/* A name whose last component was "." or ".." names a directory by
	 * construction, and dos_from_posix computed `trailing` from the
	 * ORIGINAL string -- so "sub/." would otherwise stop requiring sub
	 * to be a directory once the "." is gone.  An empty result is the
	 * RootDirectory itself, which the caller has already established is
	 * a directory. */
	if (lastdot) *trailing = 1;
	if (out == 0) *trailing = 0;
	return 0;
}

/* THE {MAX_PATH} CEILING THE Rtl PUTS ON EVERY DOS NAME, AND WHY THIS
 * FUNCTION EXISTS.
 *
 * MEASURED ON REAL WINDOWS (GitHub windows-latest / Server 2025), from a
 * working directory of "D:\a\ntlibc\ntlibc":
 *
 *   open("chm.d/<255 bytes>")               -> -1, [ENAMETOOLONG]  (280)
 *   open("chm.d/<254 bytes>")               -> -1, [ENAMETOOLONG]  (279)
 *   open("<255 bytes>")                     -> -1, [ENAMETOOLONG]  (274)
 *   chdir("chm.d"); open("<255 bytes>")     -> -1, [ENAMETOOLONG]  (280)
 *   openat(dirfd_of_chm.d, "<255 bytes>")   ->  ok
 *   open("\\?\D:\a\ntlibc\ntlibc\chm.d\<255 bytes>") -> ok
 *
 * The last two identify the culprit: NTFS and NtCreateFile are both happy
 * with the *same file*, created successfully, when the NT path is handed
 * over ready-made. The only step that differs is RtlDosPathNameToNtPathName_U's
 * DOS->NT conversion: the Rtl applies the Win32 {MAX_PATH} = 260 ceiling
 * to any name it has to normalise, and the "\\?\" local-device prefix --
 * copied through verbatim rather than normalised -- is the documented way
 * past it.
 *
 * That ceiling is not this library's to keep: PATH_MAX is 4096, so a
 * caller is entitled to a 4000-byte path. NONE OF THIS IS VISIBLE UNDER
 * WINE: Wine's RtlDosPathNameToNtPathName_U has no such ceiling, so all
 * six lines above succeed there, which is why the gap survived until a
 * test built a path past 260.
 *
 * Rather than route every name through a hand-built NT path, this runs
 * ONLY as a fallback after the Rtl has refused with STATUS_NAME_TOO_LONG
 * -- a name that works today takes exactly the path it took before.
 *
 * What it handles is narrow: a drive-absolute name ("X:\..."), a
 * drive-rooted one ("\...", taking the drive from the current directory)
 * and a plain relative one (joined onto the current directory).
 * Drive-relative "X:rel", and a name whose ".." climbs above the drive
 * root, are declined -- the caller then reports the Rtl's [ENAMETOOLONG]
 * as before. "." and ".." are resolved lexically by normalize_rel(), same
 * as the __ntpath_at() branch below.
 *
 * Returns 0 with *out built (and *trailing possibly updated), or -1
 * without touching errno meaningfully -- the caller reports the Rtl's own
 * verdict in that case. */
static int nt_path_over_max_path(const WCHAR *dos, size_t n, int *trailing,
                                 struct __ntpath *out, ULONG attributes)
{
	WCHAR cur[4096];
	WCHAR *w = 0, *joined = 0;
	const WCHAR *body;      /* what follows "X:"; always starts with '\' */
	WCHAR letter;
	size_t bodyn, curn = 0, bn, len;
	ULONG got;

	if (n >= 3 && __nt_is_drive_letter(dos[0]) && dos[1] == ':' && dos[2] == '\\') {
		letter = dos[0];
		body = dos + 2;
		bodyn = n - 2;
	} else if (n >= 2 && dos[1] == ':') {
		return -1;              /* drive-relative "X:rel": declined */
	} else {
		got = RtlGetCurrentDirectory_U(sizeof cur, cur);
		if (!got || got > sizeof cur) return -1;
		curn = got / sizeof(WCHAR);
		if (curn < 2 || !__nt_is_drive_letter(cur[0]) || cur[1] != ':') return -1;
		letter = cur[0];
		if (dos[0] == '\\') {
			body = dos;
			bodyn = n;
		} else {
			/* "X:\a\b" + "\" + the relative name.  The current
			 * directory's own trailing separator (present only at a
			 * drive root) is dropped so the join never doubles it --
			 * normalize_rel() would swallow a doubled one anyway, but
			 * the arithmetic below is easier to check without it. */
			size_t wchars, joined_bytes;
			while (curn > 2 && cur[curn-1] == '\\') curn--;
			if (!__size_add_checked(curn - 2, 1, &wchars) ||
			    !__size_add_checked(wchars, n, &wchars) ||
			    !__size_add_checked(wchars, 1, &wchars) ||
			    !__size_mul_checked(wchars, sizeof(WCHAR), &joined_bytes)) return -1;
			joined = __malloc(joined_bytes);
			if (!joined) return -1;
			{
				size_t i;
				for (i = 0; i < curn - 2; i++) joined[i] = cur[2 + i];
			}
			joined[curn - 2] = '\\';
			{
				size_t i;
				for (i = 0; i < n; i++) joined[curn - 1 + i] = dos[i];
			}
			bodyn = curn - 1 + n;
			joined[bodyn] = 0;
			body = joined;
		}
	}

	/* "\??\" + "X:" + "\" + the normalised body, which normalize_rel()
	 * writes without a leading separator.  It only ever shortens, so the
	 * allocation below is an upper bound. */
	{
		size_t wchars, wbytes;
		if (!__size_add_checked(bodyn, 4 + 3 + 1, &wchars) ||
		    !__size_mul_checked(wchars, sizeof(WCHAR), &wbytes)) { __free(joined); return -1; }
		w = __malloc(wbytes);
	}
	if (!w) { __free(joined); return -1; }
	w[0] = '\\'; w[1] = '?'; w[2] = '?'; w[3] = '\\';
	w[4] = letter; w[5] = ':'; w[6] = '\\';
	bn = bodyn - 1;                 /* body[0] is the separator at w[6] */
	{
		size_t i;
		for (i = 0; i < bn; i++) w[7 + i] = body[1 + i];
	}
	__free(joined);
	if (normalize_rel(w + 7, &bn, trailing)) { __free(w); return -1; }
	len = 7 + bn;
	w[len] = 0;

	/* The same UNICODE_STRING ceiling the rest of this file applies. */
	if (len > __US_MAX_WCHARS) { __free(w); return -1; }

	memset(out, 0, sizeof *out);
	out->nt.Buffer = w;
	out->nt.Length = (USHORT)(len * sizeof(WCHAR));
	out->nt.MaximumLength = (USHORT)(out->nt.Length + sizeof(WCHAR));
	out->buf = 0;                   /* w is freed as ->dos */
	out->dos = w;
	InitializeObjectAttributes(&out->oa, &out->nt, attributes, 0, 0);
	return 0;
}

static int ntpath_at_impl(int dirfd, const char *path, struct __ntpath *out,
                          ULONG attributes, int overlay)
{
	int absolute;

	int vfs;
	if (!path) { errno = EFAULT; return -1; }
	/* "path is an empty string" is [ENOENT] on every page that specifies
	 * an *at() function, and no page's *at()-specific ERRORS subsection
	 * carves out an exception.
	 *
	 * DO NOT "SIMPLIFY" THIS AWAY on the grounds that the object manager
	 * copes with an empty name perfectly well. It does, and that is
	 * precisely the problem: an empty UNICODE_STRING names the
	 * RootDirectory handle itself, so without this guard every *at()
	 * function silently operated on the descriptor's own directory --
	 * fchmodat(dfd, "", 0644, 0) changed that directory's mode and
	 * returned 0. The empty NT name is correct as an ENCODING (the branch
	 * below deliberately produces one for ".") and wrong as a POLICY for
	 * caller input; keep the two apart.
	 *
	 * This is not the AT_EMPTY_PATH case either: that flag is a Linux
	 * extension not in POSIX.1-2017, and this library neither defines it
	 * nor has any caller that asks for it. A caller meaning "the
	 * directory itself" spells it ".". */
	if (!*path) { errno = ENOENT; return -1; }
	if (overlay) {
		vfs = __vfs_resolve_at(dirfd, path);
		if (vfs < 0) return -1;
		if (vfs != __VFS_NONE && !(vfs & __VFS_NATIVE)) {
			errno = vfs == __VFS_MISSING ? ENOENT : EROFS;
			return -1;
		}
	}
	absolute = path[0] == '/' || path[0] == '\\' ||
		(__nt_is_drive_letter((unsigned char)path[0]) && path[1] == ':');
	if (dirfd == AT_FDCWD || absolute) return ntpath_impl(path, out, attributes, overlay);

	/* Relative to a directory handle: the object manager resolves a
	 * relative name against RootDirectory, so the name is given as-is,
	 * with slashes fixed and without the DOS->NT conversion. "." becomes
	 * the empty NT name, how the object manager spells "the RootDirectory
	 * itself" -- this encoding's legitimate use, unlike a caller's own
	 * empty path, rejected as [ENOENT] above. */
	{
		struct __fd *f = __fd_get(dirfd);
		WCHAR *w;
		size_t n;
		int trailing;
		if (!f) return -1;
		if (f->type != __FD_DIR) { errno = ENOTDIR; return -1; }
		int esc;
		w = dos_from_posix(path, &n, &trailing);
		if (!w) return -1;
		esc = normalize_rel(w, &n, &trailing);
		if (esc) {
			/* The name reaches above the descriptor's directory, which a
			 * RootDirectory-relative name has no way to say. Resolve the
			 * descriptor to an absolute path and hand the whole thing to
			 * __ntpath(), the same answer the AT_FDCWD branch would give
			 * -- only in this case, since resolving by path for every
			 * relative name would throw away what the *at() family
			 * exists for: pinning the directory even if renamed. */
			char *dir, *joined;
			size_t dl, pl, joined_bytes;
			int rc;
			__free(w);
			dir = __handle_path(f->h);
			if (!dir) return -1;
			dl = strlen(dir);
			pl = strlen(path);
			if (!__size_add_checked(dl, 1, &joined_bytes) ||
			    !__size_add_checked(joined_bytes, pl, &joined_bytes) ||
			    !__size_add_checked(joined_bytes, 1, &joined_bytes)) {
				__free(dir);
				errno = ENOMEM;
				return -1;
			}
			joined = __malloc(joined_bytes);
			if (!joined) { __free(dir); errno = ENOMEM; return -1; }
			{
				size_t i;
				for (i = 0; i < dl; i++) joined[i] = dir[i];
			}
			/* "C:\\" already ends in one */
			if (dl && dir[dl-1] != '\\' && dir[dl-1] != '/') joined[dl++] = '\\';
			__ownership_writable_span(joined + dl, pl + 1);
			memcpy(joined + dl, path, pl + 1);
			__free(dir);
			rc = ntpath_impl(joined, out, attributes, overlay);
			__free(joined);
			return rc;
		}
		/* UNICODE_STRING.Length is a USHORT count of bytes and
		 * MaximumLength has to hold one more code unit, so a name past
		 * 32766 code units cannot be described -- and narrowing it would
		 * wrap rather than truncate, naming some prefix of the caller's
		 * path instead of failing. */
		if (n > __US_MAX_WCHARS) {
			__free(w);
			errno = ENAMETOOLONG;
			return -1;
		}
		memset(out, 0, sizeof *out);
		out->nt.Buffer = w;
		out->nt.Length = (USHORT)(n * sizeof(WCHAR));
		out->nt.MaximumLength = (USHORT)(out->nt.Length + sizeof(WCHAR));
		out->buf = 0;      /* w is freed as dos */
		out->dos = w;
		InitializeObjectAttributes(&out->oa, &out->nt, attributes, f->h, 0);
		if (trailing && reject_if_not_dir(out)) return -1;
		/* Relative to RootDirectory: every component of this name is a
		 * path prefix component, so the walk may truncate anywhere. */
		if (reject_if_prefix_not_dir(out, f->h)) return -1;
		return 0;
	}
}

int __ntpath_at(int dirfd, const char *path, struct __ntpath *out, ULONG attributes)
{
	return ntpath_at_impl(dirfd, path, out, attributes, 1);
}

int __ntpath_at_native(int dirfd, const char *path, struct __ntpath *out, ULONG attributes)
{
	return ntpath_at_impl(dirfd, path, out, attributes, 0);
}

void __ntpath_free(struct __ntpath *p)
{
	if (p->buf) RtlFreeHeap(__process_heap(), 0, p->buf);
	if (p->dos) __free(p->dos);
	p->buf = 0; p->dos = 0;
}

// NOLINTEND(misc-include-cleaner)
