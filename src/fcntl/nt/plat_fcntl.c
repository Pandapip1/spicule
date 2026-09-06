/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of src/internal/plat_fcntl.h -- see that header for
 * the contract each function makes. __plat_open() owns the ENTIRE
 * NT-specific path-to-handle journey (VFS-overlay resolution,
 * __ntpath_at(), the $LXMOD extended-attribute buffer), not just the
 * NtCreateFile call at the end of it.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include "libc.h"
#include "plat_fcntl.h"

int __plat_open(int dirfd, const char *path, int flags, unsigned mode, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
                __plat_handle_t *out, int *typeout, int *vfsout, int *vfsnativeout) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __ntpath np;
	unsigned char mode_ea[32];
	void *ea = 0;
	unsigned ea_len = 0;
	int vfs, native;
	IO_STATUS_BLOCK io;
	ACCESS_MASK access;
	ULONG disposition, options, attrs;
	NTSTATUS st;
	HANDLE h;

	vfs = __vfs_resolve_at(dirfd, path);
	if (vfs < 0) return -1;
	native = (vfs & __VFS_NATIVE) != 0;
	if (native) {
		*vfsout = __VFS_KIND(vfs);
		*vfsnativeout = 1;
		vfs = __VFS_NONE;
	}
	if (vfs == __VFS_MISSING) {
		errno = flags & O_CREAT ? EROFS : ENOENT;
		return -1;
	}
	if (vfs == __VFS_ROOT || vfs == __VFS_DEV) {
		if ((flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) { errno = EEXIST; return -1; }
		if ((flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC)) { errno = EISDIR; return -1; }
		if (__vfs_open_dir(vfs, flags & O_CLOEXEC, out) < 0) return -1;
		*typeout = __FD_DIR;
		*vfsout = vfs;
		return 0;
	}
	if (vfs == __VFS_CONSOLE || vfs == __VFS_NULL || vfs == __VFS_TTY) {
		if ((flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) { errno = EEXIST; return -1; }
		if (flags & O_DIRECTORY) { errno = ENOTDIR; return -1; }
		path = vfs == __VFS_NULL ? "NUL" : "CON";
		dirfd = AT_FDCWD;
		*vfsout = vfs;
	}

	if (__ntpath_at(dirfd, path, &np, OBJ_CASE_INSENSITIVE | (flags & O_CLOEXEC ? 0 : OBJ_INHERIT)) < 0)
		return -1;

	/* open.html DESCRIPTION: mode is ANDed with the complement of umask.
	 * The $LXMOD extended-attribute buffer is this library's own POSIX-
	 * mode-persistence strategy (see src/stat/lxmod.c). */
	if (flags & O_CREAT) {
		mode = mode & ~__umask_get() & 07777;
		ea_len = __lxmod_create_buffer(mode_ea, S_IFREG | mode);
		ea = mode_ea;
	}

	access = SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_READ_EA;
	switch (flags & O_ACCMODE) {
	case O_RDONLY: access |= FILE_GENERIC_READ; break;
	case O_WRONLY: access |= FILE_GENERIC_WRITE; break;
	case O_RDWR:   access |= FILE_GENERIC_READ | FILE_GENERIC_WRITE; break; // NOLINT(misc-redundant-expression) -- both masks include SYNCHRONIZE, harmless ORed twice
	/* The fourth access mode, 03, is O_EXEC and O_SEARCH -- equal values.
	 * Refused, not served: each asks for a handle that can do LESS than a
	 * read handle, so quietly widening to O_RDONLY would grant more access
	 * than requested. Serving them for real needs FILE_EXECUTE/
	 * FILE_TRAVERSE and matching fd-table checks; not done here. */
	default: __ntpath_free(&np); errno = EINVAL; return -1;
	}
	if (flags & O_APPEND) access = (access & ~FILE_WRITE_DATA) | FILE_APPEND_DATA;
	if (flags & O_TRUNC) access |= FILE_WRITE_DATA;   /* overwrite needs it */
	if (flags & O_PATH) access = SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_READ_EA;

	switch (flags & (O_CREAT | O_EXCL | O_TRUNC)) {
	case 0:
	case O_EXCL:                  disposition = FILE_OPEN; break;
	case O_CREAT:                 disposition = FILE_OPEN_IF; break;
	case O_CREAT | O_EXCL:
	case O_CREAT | O_EXCL | O_TRUNC: disposition = FILE_CREATE; break;
	case O_TRUNC:
	case O_TRUNC | O_EXCL:        disposition = FILE_OVERWRITE; break;
	case O_CREAT | O_TRUNC:       disposition = FILE_OVERWRITE_IF; break;
	default: disposition = FILE_OPEN; break;
	}

	options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT;
	if (flags & O_DIRECTORY) options |= FILE_DIRECTORY_FILE;
	else if (disposition != FILE_OPEN && disposition != FILE_OPEN_IF) options |= FILE_NON_DIRECTORY_FILE;
	if (flags & O_NOFOLLOW) options |= FILE_OPEN_REPARSE_POINT;
	if (flags & (O_SYNC | O_DSYNC)) options |= FILE_WRITE_THROUGH;
	if (flags & O_DIRECT) options |= FILE_NO_INTERMEDIATE_BUFFERING;

	attrs = FILE_ATTRIBUTE_NORMAL;
	/* open.html DESCRIPTION: mode is ANDed with the complement of umask.
	 * NtCreateFile only applies its EA buffer when it creates the object,
	 * so O_CREAT on an existing file cannot overwrite that file's mode. */
	if (flags & O_CREAT) {
		if (!(mode & 0222)) attrs = FILE_ATTRIBUTE_READONLY;
	}

	st = NtCreateFile(&h, access, &np.oa, &io, 0, attrs, FILE_SHARE_VALID_FLAGS,
	                  disposition, options, ea, ea_len);

	/* A directory opened without O_DIRECTORY for reading: allowed by
	 * POSIX (reads then fail with EISDIR); NT refuses FILE_NON_DIRECTORY
	 * only when we asked for it, and refuses data access on directories
	 * with STATUS_FILE_IS_A_DIRECTORY, so retry as a directory. */
	if (st == STATUS_FILE_IS_A_DIRECTORY && (flags & O_ACCMODE) == O_RDONLY && !(flags & O_CREAT)) {
		options |= FILE_DIRECTORY_FILE;
		access = SYNCHRONIZE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES |
		         FILE_READ_EA | FILE_TRAVERSE;
		st = NtCreateFile(&h, access, &np.oa, &io, 0, attrs, FILE_SHARE_VALID_FLAGS, FILE_OPEN, options, 0, 0);
	}
	__ntpath_free(&np);
	/* Writing to a directory is EISDIR, not EACCES. */
	if (st == STATUS_FILE_IS_A_DIRECTORY) { errno = EISDIR; return -1; }
	if (!NT_SUCCESS(st)) {
		/* FILE_CREATE on an existing directory, etc. */
		if (st == STATUS_OBJECT_NAME_COLLISION) errno = EEXIST;
		else __set_errno_status(st);
		return -1;
	}

	*typeout = (options & FILE_DIRECTORY_FILE) ? __FD_DIR : 0;
	*out = h;
	return 0;
}

int __plat_lock_probe(__plat_handle_t h, long long off, long long len, int exclusive, int *conflicting) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	IO_STATUS_BLOCK io;
	LARGE_INTEGER o = off, l = len;
	NTSTATUS st;

	*conflicting = 0;
	/* IoStatusBlock: try the real-NT-correct &io first, and retry with
	 * NULL only if that specific call hard-fails STATUS_NOT_IMPLEMENTED
	 * -- Wine's NtLockFile (dlls/ntdll/unix/file.c) does exactly that
	 * whenever given a non-NULL IoStatusBlock ("Unimplemented yet
	 * parameter"), which is why an earlier version of this function
	 * passed NULL unconditionally. That traded one platform's bug for
	 * another's: windows-test's posix-unistd.exe and
	 * posix-fcntl-lock-crossproc.exe both then failed F_SETLK/F_GETLK
	 * on real Windows, which requires a real IoStatusBlock on
	 * NtLockFile. Trying &io first means real Windows takes the
	 * correct path directly and Wine still falls back to the NULL call
	 * it always needed. NtUnlockFile below always dereferences its
	 * IoStatusBlock unconditionally on every platform, so it keeps
	 * &io either way. */
	st = NtLockFile(h, 0, 0, 0, &io, &o, &l, 0, 1, exclusive);
	if (st == STATUS_NOT_IMPLEMENTED)
		st = NtLockFile(h, 0, 0, 0, 0, &o, &l, 0, 1, exclusive);
	if (NT_SUCCESS(st)) {
		st = NtUnlockFile(h, &io, &o, &l, 0);
		if (!NT_SUCCESS(st)) return __set_errno_status(st);
		return 0;
	}
	/* NT does not expose the owning process for a byte-range lock. */
	if (st == STATUS_FILE_LOCK_CONFLICT || st == STATUS_LOCK_NOT_GRANTED) {
		*conflicting = 1;
		return 0;
	}
	return __set_errno_status(st);
}

int __plat_lock_set(__plat_handle_t h, long long off, long long len, int exclusive, int wait) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	IO_STATUS_BLOCK io;
	LARGE_INTEGER o = off, l = len;
	/* See __plat_lock_probe() above for why &io is tried first, with a
	 * NULL retry only on Wine's STATUS_NOT_IMPLEMENTED. */
	NTSTATUS st = NtLockFile(h, 0, 0, 0, &io, &o, &l, 0, wait ? 0 : 1, exclusive);
	if (st == STATUS_NOT_IMPLEMENTED)
		st = NtLockFile(h, 0, 0, 0, 0, &o, &l, 0, wait ? 0 : 1, exclusive);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_lock_clear(__plat_handle_t h, long long off, long long len) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	IO_STATUS_BLOCK io;
	LARGE_INTEGER o = off, l = len;
	NTSTATUS st = NtUnlockFile(h, &io, &o, &l, 0);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

/* See fadvise.c's posix_fallocate() for the full derivation and the two
 * Microsoft Learn pages that disagree about it -- this is Microsoft's
 * own rule (cluster_size * (2^32-1)), not a guess, and reproduces the
 * "NTFS overview" support-for-large-volumes table exactly. */
long long __plat_volume_max_file_size(__plat_handle_t h)
{
	IO_STATUS_BLOCK io;
	FILE_FS_SIZE_INFORMATION fsi;
	unsigned long long cluster, lim;

	if (!NT_SUCCESS(NtQueryVolumeInformationFile(h, &io, &fsi, sizeof fsi, FileFsSizeInformation)))
		return LLONG_MAX;
	cluster = (unsigned long long)fsi.SectorsPerAllocationUnit * fsi.BytesPerSector;
	if (!cluster) return LLONG_MAX;
	lim = cluster * 4294967295ULL;
	return lim > (unsigned long long)LLONG_MAX ? LLONG_MAX : (long long)lim;
}

int __plat_file_extent(__plat_handle_t h, long long *alloc_size, long long *eof) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	IO_STATUS_BLOCK io;
	FILE_STANDARD_INFORMATION si;
	NTSTATUS st = NtQueryInformationFile(h, &io, &si, sizeof si, FileStandardInformation);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	*alloc_size = si.AllocationSize;
	*eof = si.EndOfFile;
	return 0;
}

/* Wine versions without FileAllocationInformation can still honour the
 * useful, non-destructive part of an extending posix_fallocate() request:
 * every byte from the old EOF to the requested end already reads as zero,
 * so writing zeroes there changes no file data while forcing the host
 * filesystem to back the new tail with storage. Positioned I/O, so the
 * caller's file offset is left alone. Not used for an extent wholly
 * inside the file: rewriting that range would need read access a valid
 * write-only descriptor need not have. */
static int materialize_zero_tail(HANDLE h, long long from, long long to)
{
	static const unsigned char zeroes[64 * 1024];
	IO_STATUS_BLOCK io;
	LARGE_INTEGER pos;
	NTSTATUS st;
	ULONG part;

	while (from < to) {
		part = to - from > (long long)sizeof zeroes
		     ? (ULONG)sizeof zeroes : (ULONG)(to - from);
		pos = from;
		io.Status = 0;
		io.Information = 0;
		st = NtWriteFile(h, 0, 0, 0, &io, zeroes, part, &pos, 0);
		if (st == STATUS_PENDING) {
			NtWaitForSingleObject(h, 0, 0);
			st = io.Status;
		}
		if (!NT_SUCCESS(st)) return __errno_from_status(st);
		if (!io.Information) return EIO;
		from += (long long)io.Information;
	}
	return 0;
}

/* `grow_alloc` decides whether the AllocationSize step below runs at all
 * -- the front door computes it as `want > alloc_size && want >= eof`,
 * and BOTH conjuncts are load-bearing:
 *
 * ZwSetInformationFile(FileAllocationInformation) automatically adjusts
 * EndOfFile down to match a requested AllocationSize below it, and the
 * requested size is rounded up to the cluster size first. `want >
 * alloc_size` alone is only safe while alloc_size >= eof -- exactly what
 * a sparse or compressed file breaks (its allocation is deliberately
 * smaller than its size), so without the second conjunct a small
 * posix_fallocate() request on such a file could truncate it. POSIX
 * never shrinks a file.
 *
 * Skipping the call (rather than clamping the request up to eof) avoids
 * de-sparsifying the whole file: clamping a 1-byte request against a
 * terabyte-sized sparse file would request a terabyte of clusters.
 *
 * DO NOT DELETE THE SECOND CONJUNCT AS REDUNDANT: on real NTFS, `want >
 * alloc_size` already implies `want > eof` when alloc_size >= eof, but
 * under Wine (which implements extension via ftruncate(), producing a
 * hole) AllocationSize reads 0 for an ORDINARY file too -- measured on
 * Windows 11 22621: a non-sparse EndOfFile-16384 file reports
 * AllocationSize 16384 on NTFS and 0 under Wine. The second conjunct is
 * the only thing preventing truncation there. */
int __plat_fallocate(__plat_handle_t h, long long want, long long eof, int grow_alloc) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	IO_STATUS_BLOCK io;
	FILE_ALLOCATION_INFORMATION ai;
	FILE_END_OF_FILE_INFORMATION eofi;
	NTSTATUS st;
	int missing_allocation_api = 0;

	if (grow_alloc) {
		ai.AllocationSize = want;
		st = NtSetInformationFile(h, &io, &ai, sizeof ai, FileAllocationInformation);
		/* Real Windows honours this; older Wine ntdll does not implement
		 * FileAllocationInformation at all. An unsupported class takes
		 * materialize_zero_tail() below instead.
		 *
		 * Branch on the *status*, not on __errno_from_status(): that
		 * mapping is a lossy projection that folds many distinct statuses
		 * onto one value. Concretely, Wine reports the same missing
		 * set-info case as STATUS_NOT_IMPLEMENTED natively but as
		 * STATUS_INVALID_INFO_CLASS under WOW64 -- an ENOSYS test on the
		 * mapped errno would tolerate the gap on x86_64 and reject it on
		 * i386. Whenever the status is in hand, decide from it. */
		if (!NT_SUCCESS(st)) {
			missing_allocation_api = st == STATUS_NOT_IMPLEMENTED
			                      || st == STATUS_NOT_SUPPORTED
			                      || st == STATUS_INVALID_DEVICE_REQUEST
			                      || st == STATUS_INVALID_INFO_CLASS;
			if (!missing_allocation_api) return __errno_from_status(st);
		}
	}
	if (missing_allocation_api && want > eof) {
		int error = materialize_zero_tail(h, eof, want);
		if (error) return error;
		eof = want;
	}
	if (want > eof) {
		eofi.EndOfFile = want;
		st = NtSetInformationFile(h, &io, &eofi, sizeof eofi, FileEndOfFileInformation);
		if (!NT_SUCCESS(st)) return __errno_from_status(st);
	}
	return 0;
}

// NOLINTEND(misc-include-cleaner)
