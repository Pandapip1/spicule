/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of src/internal/plat_stdio.h -- see that header for
 * the contract __plat_rename() makes. Everything here was, until this
 * file existed, split between src/stdio/misc.c's renameat() front door
 * (path resolution, isdir_attrs()/ntpath_is_ancestor(), the directory-
 * type-mismatch check) and three separate interface functions
 * (__plat_rename_open_old()/__plat_query_new_attrs()/__plat_rename_set())
 * this file used to declare; nothing changed in substance, only
 * location -- __plat_rename() below is the identical sequence
 * renameat() used to run inline plus what those three functions did,
 * now one function, verified line for line against the pre-refactor
 * version (commit ce4763c did the same relocation for open()).
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <errno.h>
#include <string.h>
#include "libc.h"
#include "plat_fd.h"
#include "plat_stdio.h"
#include "plat_unistd.h"

/* POSIX classifies a symbolic link as a non-directory file whatever it
 * points at; NT gives a directory symlink FILE_ATTRIBUTE_DIRECTORY on
 * the link itself.  Same predicate as src/stat/stat.c's
 * mode_from_attrs(), so __plat_rename() and lstat() agree on what a
 * link is. */
static int isdir_attrs(ULONG attrs, ULONG tag)
{
	if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) &&
	    (tag == IO_REPARSE_TAG_SYMLINK || tag == IO_REPARSE_TAG_MOUNT_POINT || tag == IO_REPARSE_TAG_LX_SYMLINK))
		return 0;
	return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

/* Refuses to rename a directory into its own descendant -- rename.html
 * ERRORS: [EINVAL] "The old argument names an ancestor directory of
 * the new argument". NT has no native check for this (FILE_RENAME_
 * INFORMATION happily renames a directory into its own subdirectory,
 * producing an unreachable/orphaned tree), so it is done here, on the
 * resolved NT paths, before ever calling NtSetInformationFile. Compares
 * old's full NT path against new's leading prefix (case-insensitively,
 * '/' and '\\' unified, matching NT's own path-separator tolerance),
 * requiring identical RootDirectory handles (a newdirfd-relative
 * comparison only makes sense against an old resolved against the same
 * base) and a full path-COMPONENT prefix match (new's next character
 * past old's length must itself be a separator, not just any
 * character, so "/a/bb" is not mistaken for a descendant of "/a/b"). */
/* old/new are both dereferenced unconditionally, first statement
 * (`old->nt.Length`/`new->nt.Length`); this function's one real call
 * site always passes the address of a real local (`&op, &np`), never a
 * value that could legitimately be null. */
static int ntpath_is_ancestor(const struct __ntpath *old,
		const struct __ntpath *new) __attribute__((nonnull(1, 2)));
static int ntpath_is_ancestor(const struct __ntpath *old,
		const struct __ntpath *new)
{
	size_t i, on = old->nt.Length / sizeof(WCHAR);
	size_t nn = new->nt.Length / sizeof(WCHAR);
	if (old->oa.RootDirectory != new->oa.RootDirectory || on >= nn)
		return 0;
	for (i = 0; i < on; i++) {
		WCHAR a = old->nt.Buffer[i], b = new->nt.Buffer[i];
		if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
		if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
		if (a == '/') a = '\\';
		if (b == '/') b = '\\';
		if (a != b) return 0;
	}
	return new->nt.Buffer[on] == '\\' || new->nt.Buffer[on] == '/';
}

/* Open `old`'s already-resolved NT path (op) with DELETE|FILE_READ_
 * ATTRIBUTES|SYNCHRONIZE -- the eventual FILE_RENAME_INFORMATION[Ex]
 * set's own handle, kept open across the rest of this function.
	 * *attrs and *tag are FileAttributeTagInformation's two fields, needed by
 * isdir_attrs() to decide whether `old` is a directory; a failed query
 * (rather than a failed open) leaves them 0, which reads as "not a
 * reparse point, not a directory" either way -- not a behavior change
 * from before this file's functions were merged into one.  0/-1(errno)
 * via return -- only the OPEN's own failure is reported; the attribute
 * query's failure is absorbed as above. */
static int rename_open_old(struct __ntpath *op, __plat_handle_t *h_out,
                           unsigned long *attrs, unsigned long *tag) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	IO_STATUS_BLOCK io;
	HANDLE h;
	NTSTATUS st;
	FILE_ATTRIBUTE_TAG_INFORMATION oti;

	/* FILE_READ_ATTRIBUTES is requested alongside DELETE because the
	 * type check below queries FileBasicInformation on this same handle
	 * to learn whether old is a directory. DELETE alone is enough for
	 * the rename itself (FileRenameInformation's IopSetOperationAccess
	 * entry is DELETE), so adding FILE_READ_ATTRIBUTES here is purely
	 * additive and cannot newly deny the open. */
	st = NtOpenFile(&h, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &op->oa, &io,
	                FILE_SHARE_VALID_FLAGS,
	                FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);

	*attrs = 0; *tag = 0;
	if (NT_SUCCESS(NtQueryInformationFile(h, &io, &oti, sizeof oti, FileAttributeTagInformation))) {
		*attrs = oti.FileAttributes;
		*tag = oti.ReparseTag;
	}
	*h_out = h;
	return 0;
}

/* Best-effort probe of `new`'s NT path: does it exist, and if so, what
 * are its FileAttributeTagInformation fields?  *exists is always
	 * written; *attrs and *tag only when *exists is set.  No handle is kept --
 * new is never opened again after this call -- and no failure is
 * reported outward: an unreadable `new` is exactly like a nonexistent
 * one here. */
static void query_new_attrs(struct __ntpath *np, int *exists,
                            unsigned long *attrs, unsigned long *tag) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	IO_STATUS_BLOCK io;
	HANDLE nh;
	NTSTATUS st;
	FILE_ATTRIBUTE_TAG_INFORMATION nti;

	st = NtOpenFile(&nh, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &np->oa, &io, FILE_SHARE_VALID_FLAGS,
	                FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT);
	*exists = NT_SUCCESS(st);
	*attrs = 0; *tag = 0;
	if (*exists) {
		if (NT_SUCCESS(NtQueryInformationFile(nh, &io, &nti, sizeof nti, FileAttributeTagInformation))) {
			*attrs = nti.FileAttributes;
			*tag = nti.ReparseTag;
		}
		NtClose(nh);
	}
}

/* Apply the rename: FILE_RENAME_INFORMATION[Ex] with FILE_RENAME_
 * REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS tried first via the
 * Ex info class, falling back to the plain info class and flag on
 * [STATUS_INVALID_PARAMETER]/[STATUS_INVALID_INFO_CLASS]/
 * [STATUS_NOT_SUPPORTED]/[STATUS_NOT_IMPLEMENTED] (an NT that does not
 * know the newer class/flag).  `h` (from rename_open_old()) is closed
 * before this returns, on every path.  0 on success; on failure,
 * [EXDEV] for STATUS_NOT_SAME_DEVICE, [ENOTEMPTY]/[EISDIR] (chosen by
 * `old_isdir`) when NT's STATUS_ACCESS_DENIED is standing in for a
 * directory-shaped refusal rather than a real permission failure, and
 * the generic mapping for everything else. */
static int rename_set(__plat_handle_t h, struct __ntpath *np, int old_isdir, int new_isdir) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	IO_STATUS_BLOCK io;
	FILE_RENAME_INFORMATION *ri;
	NTSTATUS st;
	size_t bufsz = sizeof(FILE_RENAME_INFORMATION) + np->nt.Length;
	size_t i;

	ri = __malloc(bufsz);
	if (!ri) { NtClose(h); errno = ENOMEM; return -1; }
	ri->Flags = FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS;
	/* np->oa.RootDirectory is the "resolve FileName against this
	 * directory" handle __ntpath_at() put there for a newdirfd-relative
	 * destination -- FILE_RENAME_INFORMATION's RootDirectory is the
	 * same mechanism as OBJECT_ATTRIBUTES'.  0 for an absolute path or
	 * AT_FDCWD, where np->nt is already a full NT path. */
	ri->RootDirectory = np->oa.RootDirectory;
	ri->FileNameLength = np->nt.Length;
	for (i = 0; i < np->nt.Length / sizeof(WCHAR); i++)
		ri->FileName[i] = np->nt.Buffer[i];

	st = NtSetInformationFile(h, &io, ri, (ULONG)bufsz, FileRenameInformationEx);
	if (st == STATUS_INVALID_PARAMETER || st == STATUS_INVALID_INFO_CLASS ||
	    st == STATUS_NOT_SUPPORTED || st == STATUS_NOT_IMPLEMENTED) {
		ri->Flags = FILE_RENAME_REPLACE_IF_EXISTS;
		st = NtSetInformationFile(h, &io, ri, (ULONG)bufsz, FileRenameInformation);
	}
	__free(ri);

	/* rename.html ERRORS: STATUS_ACCESS_DENIED is what NT answers both
	 * when new names a directory and old does not (should be EISDIR) and
	 * when new names a non-empty directory (should be EEXIST/ENOTEMPTY);
	 * the generic map in __set_errno_status turns both into plain
	 * EACCES, which is right for genuine permission failures but wrong
	 * here.  Disambiguate by type, using the types established before
	 * the set was attempted. */
	if (st == STATUS_ACCESS_DENIED && new_isdir) {
		NtClose(h);
		errno = old_isdir ? ENOTEMPTY : EISDIR;
		return -1;
	}

	NtClose(h);
	if (st == STATUS_NOT_SAME_DEVICE) { errno = EXDEV; return -1; }
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_rename(int olddirfd, const char *old, int newdirfd, const char *new)
{
	struct __ntpath op, np;
	__plat_handle_t h = 0;
	unsigned long old_attrs = 0, old_tag = 0, new_attrs = 0, new_tag = 0;
	int old_isdir, new_exists, new_isdir;

	if (__ntpath_at(olddirfd, old, &op, OBJ_CASE_INSENSITIVE) < 0) return -1;
	if (__ntpath_at(newdirfd, new, &np, OBJ_CASE_INSENSITIVE) < 0) { __ntpath_free(&op); return -1; }
	if (ntpath_is_ancestor(&op, &np)) {
		__ntpath_free(&op);
		__ntpath_free(&np);
		errno = EINVAL;
		return -1;
	}

	if (rename_open_old(&op, &h, &old_attrs, &old_tag) < 0) {
		__ntpath_free(&op);
		__ntpath_free(&np);
		return -1;
	}
	__ntpath_free(&op);

	/* rename.html ERRORS: "the old argument names a directory and the new
	 * argument names a non-directory file" is [ENOTDIR], and RETURN VALUE
	 * requires that on failure "neither the file named by old nor the file
	 * named by new shall be changed or created".  NT honours neither:
	 * FileRenameInformation[Ex] with FILE_RENAME_REPLACE_IF_EXISTS will
	 * rename a directory straight over an existing regular file, unlink
	 * the victim and report success.  The check therefore has to happen
	 * HERE, before the set -- once NT has run, the file is already gone
	 * and there is nothing left to diagnose.
	 *
	 * old's type comes from the handle already open on it (which is why
	 * rename_open_old() asks for FILE_READ_ATTRIBUTES); new's from a
	 * handle-less attribute query, since new is never opened.  Both are
	 * reused by the STATUS_ACCESS_DENIED disambiguation inside
	 * rename_set(), which used to make these same two queries for
	 * itself after the fact. */
	old_isdir = isdir_attrs(old_attrs, old_tag);
	query_new_attrs(&np, &new_exists, &new_attrs, &new_tag);
	new_isdir = new_exists && isdir_attrs(new_attrs, new_tag);

	if (old_isdir && new_exists && !new_isdir) {
		__plat_close(h);
		__ntpath_free(&np);
		errno = ENOTDIR;
		return -1;
	}

	/* renameat.html DESCRIPTION: "If new is a relative path, the file is
	 * located relative to the directory associated with the file
	 * descriptor newfd instead of the current working directory."
	 * __ntpath_at() expresses exactly that by putting newfd's handle in
	 * np.oa.RootDirectory and leaving np.nt unqualified; rename_set()
	 * carries that RootDirectory into the rename request itself, exactly
	 * the way FILE_RENAME_INFORMATION's own RootDirectory field expects. */
	{
		int r = rename_set(h, &np, old_isdir, new_isdir);

		/* rename.html DESCRIPTION, the directory case: "If the
		 * directory named by the new argument exists, it shall be
		 * removed and old renamed to new... The new argument shall
		 * not name any directory other than an empty directory."
		 * NT's FileRenameInformation[Ex] refuses outright to replace
		 * an existing directory, empty or not -- measured,
		 * FILE_RENAME_REPLACE_IF_EXISTS|FILE_RENAME_POSIX_SEMANTICS
		 * included -- always STATUS_ACCESS_DENIED, which rename_set()
		 * above already turned into ENOTEMPTY via its old_isdir &&
		 * new_isdir disambiguation.  That disambiguation answers
		 * "which type mismatch is this", not "is new empty", so it
		 * cannot by itself tell a genuinely non-empty new (which
		 * really must fail ENOTEMPTY) from an empty one (which must
		 * succeed) -- both reach it as the identical status.
		 *
		 * The two ARE distinguishable, just not from the status NT
		 * handed back for the rename itself: NT's own directory-
		 * delete path (FILE_DISPOSITION_INFORMATION[Ex], the same
		 * mechanism rmdir()/__plat_unlink() already use) independently
		 * refuses a non-empty directory with
		 * STATUS_DIRECTORY_NOT_EMPTY.  Asking it is exactly the
		 * emptiness test this clause needs, and reuses the existing,
		 * already-correct rmdir() logic rather than hand-rolling a
		 * second one here.
		 *
		 * So: if the rename failed as ENOTEMPTY *and* both sides are
		 * really directories (the only case rename_set() maps to
		 * ENOTEMPTY this way), try to remove new exactly as rmdir()
		 * would.  If new was genuinely empty, that succeeds, new is
		 * gone, and old's rename -- freshly resolved, since
		 * rename_set() always closes the handle it was given, even on
		 * failure -- lands on a name that no longer exists: an
		 * ordinary, unqualified rename.  If new was not empty, the
		 * delete attempt fails with the same ENOTEMPTY rename_set()
		 * already reported, and that is restored explicitly below
		 * rather than trusted to survive incidentally, in case the
		 * delete attempt failed for some unrelated reason instead
		 * (e.g. a permission problem on new itself) and left a
		 * different errno behind. */
		if (r == -1 && errno == ENOTEMPTY && old_isdir && new_isdir) {
			if (__plat_unlink(newdirfd, new, 1) == 0) {
				struct __ntpath op2;
				__plat_handle_t h2 = 0;
				unsigned long oa2 = 0, ot2 = 0;

				if (__ntpath_at(olddirfd, old, &op2, OBJ_CASE_INSENSITIVE) < 0) {
					__ntpath_free(&np);
					return -1;
				}
				if (rename_open_old(&op2, &h2, &oa2, &ot2) < 0) {
					__ntpath_free(&op2);
					__ntpath_free(&np);
					return -1;
				}
				__ntpath_free(&op2);
				r = rename_set(h2, &np, old_isdir, 0);
				__ntpath_free(&np);
				return r;
			}
			errno = ENOTEMPTY;
		}

		__ntpath_free(&np);
		return r;
	}
}

// NOLINTEND(misc-include-cleaner)
