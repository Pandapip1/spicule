/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT implementation of src/internal/plat_stat.h -- see that header for
 * the contract each function makes. __plat_chmodat()/__plat_mkdir()/
 * __plat_fstatat()/__plat_statvfs_path()/__plat_set_times_at() own the
 * ENTIRE NT-specific path-to-handle journey for each call, including the
 * __vfs_resolve_at() overlay check and __ntpath_at()/__ntpath() path
 * resolution, not just the tail that runs once a handle is already open.
 * __vfs_resolve_at()/__vfs_open_dir() themselves stay in
 * src/internal/vfs.c; only their call sites moved here.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "libc.h"
#include "plat_stat.h"

/* ---- $LXMOD (src/stat/lxmod.c's __lxmod_get/__lxmod_set) -------------- */

#define LXMOD_NAME "$LXMOD"
#define LXMOD_NAME_LEN 6u
#define LXMOD_VALUE_LEN 4u
#define LXMOD_EA_LEN (8u + LXMOD_NAME_LEN + 1u + LXMOD_VALUE_LEN)

static unsigned getle32(const unsigned char *p)
{
	return (unsigned)p[0] | (unsigned)p[1] << 8 |
	       (unsigned)p[2] << 16 | (unsigned)p[3] << 24;
}

int __plat_lxmod_get(__plat_handle_t h, unsigned *mode)
{
	unsigned char request[12] = { 0 };
	unsigned char reply[32] = { 0 };
	__NT_FILE_GET_EA_INFORMATION *get = (__NT_FILE_GET_EA_INFORMATION *)request;
	__NT_FILE_FULL_EA_INFORMATION *ea = (__NT_FILE_FULL_EA_INFORMATION *)reply;
	IO_STATUS_BLOCK io;
	NTSTATUS st;

	get->EaNameLength = LXMOD_NAME_LEN;
	memcpy(get->EaName, LXMOD_NAME, LXMOD_NAME_LEN + 1);
	st = NtQueryEaFile(h, &io, reply, sizeof reply, 1, request, sizeof request,
	                   0, 1);
	if (!NT_SUCCESS(st) || io.Information < LXMOD_EA_LEN ||
	    ea->EaNameLength != LXMOD_NAME_LEN ||
	    ea->EaValueLength != LXMOD_VALUE_LEN ||
	    memcmp(ea->EaName, LXMOD_NAME, LXMOD_NAME_LEN)) // NOLINT(bugprone-suspicious-string-compare) -- any nonzero result intentionally rejects a mismatched EA name
		return 0;
	*mode = getle32((unsigned char *)ea->EaName + LXMOD_NAME_LEN + 1);
	return 1;
}

int __plat_lxmod_set(__plat_handle_t h, unsigned mode)
{
	/* __lxmod_create_buffer() below already memsets the whole buffer
	 * before filling it field by field, but that happens inside the
	 * callee, one translation unit away from this declaration -- proving
	 * it here too costs nothing and does not depend on tracing into
	 * another function's body. */
	unsigned char buffer[LXMOD_EA_LEN] = {0};
	IO_STATUS_BLOCK io;
	NTSTATUS st;
	unsigned len = __lxmod_create_buffer(buffer, mode);
	st = NtSetEaFile(h, &io, buffer, len);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

/* ---- chmod (src/stat/chmod.c) ------------------------------------------ */

int __plat_chmod(__plat_handle_t h, mode_t mode)
{
	IO_STATUS_BLOCK io;
	FILE_BASIC_INFORMATION bi, set;
	struct stat before;
	NTSTATUS st;
	unsigned lxmode;
	int making_readonly;
	int have_before = __plat_fstat(h, __FD_FILE, &before) == 0;
	st = NtQueryInformationFile(h, &io, &bi, sizeof bi, FileBasicInformation);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	lxmode = (bi.FileAttributes & FILE_ATTRIBUTE_DIRECTORY ? S_IFDIR : S_IFREG) |
	         (mode & 07777);
	/* Unlike `bi` above, `set` is a fresh local this function fills itself:
	 * FILE_BASIC_INFORMATION's trailing 4-byte ULONG after four 8-byte
	 * LARGE_INTEGERs leaves real uninitialized padding bytes on a target
	 * that aligns the struct to 8 bytes. */
	memset(&set, 0, sizeof set);
	set.CreationTime = set.LastAccessTime = set.LastWriteTime = set.ChangeTime = 0;
	set.FileAttributes = bi.FileAttributes;
	if (mode & 0222) set.FileAttributes &= ~FILE_ATTRIBUTE_READONLY;
	else set.FileAttributes |= FILE_ATTRIBUTE_READONLY;
	/* FILE_ATTRIBUTE_NORMAL is valid only by itself: adding READONLY without
	 * removing NORMAL asks NT to ignore the transition chmod() is making,
	 * and clearing READONLY from an archived file must leave ARCHIVE alone
	 * rather than manufacture the invalid ARCHIVE|NORMAL pair. */
	if (set.FileAttributes & ~FILE_ATTRIBUTE_NORMAL)
		set.FileAttributes &= ~FILE_ATTRIBUTE_NORMAL;
	else
		set.FileAttributes = FILE_ATTRIBUTE_NORMAL;
	making_readonly = !(bi.FileAttributes & FILE_ATTRIBUTE_READONLY) &&
	                  (set.FileAttributes & FILE_ATTRIBUTE_READONLY);
	/* Wine refuses NtSetEaFile once FILE_ATTRIBUTE_READONLY is set on the
	 * object, even with FILE_WRITE_EA granted. Persist the exact POSIX mode
	 * before making that one-way transition; the old order made
	 * chmod(0700 -> 0500) report success via the fallback below while
	 * stat() kept seeing the stale 0700 $LXMOD record. The inverse
	 * transition must retain the old order: clearing READONLY first is
	 * what makes the EA writable again. */
	if (making_readonly) {
		if (__plat_lxmod_set(h, lxmode) == 0) {
			st = NtSetInformationFile(h, &io, &set, sizeof set,
			                          FileBasicInformation);
			if (NT_SUCCESS(st)) return 0;
			/* Best-effort observable rollback; a handle on which fstat
			 * failed cannot supply an old mode. */
			if (have_before)
				__plat_lxmod_set(h,
				    (bi.FileAttributes & FILE_ATTRIBUTE_DIRECTORY ? S_IFDIR : S_IFREG) |
				    (before.st_mode & 07777));
			return __set_errno_status(st);
		}
		/* Wine versions without writable EAs can still represent a
		 * write-bit-only change with FILE_ATTRIBUTE_READONLY. */
		if (!have_before || (mode & 0111) != (before.st_mode & 0111))
			return -1;
		st = NtSetInformationFile(h, &io, &set, sizeof set,
		                          FileBasicInformation);
		if (!NT_SUCCESS(st)) return __set_errno_status(st);
		return 0;
	}
	if (set.FileAttributes != bi.FileAttributes) {
		st = NtSetInformationFile(h, &io, &set, sizeof set, FileBasicInformation);
		if (!NT_SUCCESS(st)) return __set_errno_status(st);
	}
	if (__plat_lxmod_set(h, lxmode) < 0) {
		/* Wine through 10.x stubs NtSetEaFile as ACCESS_DENIED. Preserve
		 * the historical readonly-only chmod when the requested execute
		 * bits already match; an actual execute-bit change still fails
		 * honestly. */
		if (have_before && (mode & 0111) == (before.st_mode & 0111))
			return 0;
		/* Do not leave the Windows read-only state changed after a mode
		 * metadata failure. The old $LXMOD value, if any, was untouched
		 * because NtSetEaFile replaces its single entry atomically. */
		if (set.FileAttributes != bi.FileAttributes)
			NtSetInformationFile(h, &io, &bi, sizeof bi, FileBasicInformation);
		return -1;
	}
	return 0;
}

int __plat_chmodat(int dirfd, const char *path, int flags, mode_t mode) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __ntpath np;
	IO_STATUS_BLOCK io;
	HANDLE h;
	NTSTATUS st;
	ULONG options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT |
	                (flags & AT_SYMLINK_NOFOLLOW ? FILE_OPEN_REPARSE_POINT : 0);
	int r;

	if (__ntpath_at(dirfd, path, &np, OBJ_CASE_INSENSITIVE) < 0) return -1;
	st = NtOpenFile(&h, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES |
	               FILE_READ_EA | FILE_WRITE_EA | SYNCHRONIZE,
	               &np.oa, &io, FILE_SHARE_VALID_FLAGS, options);
	if (st == STATUS_ACCESS_DENIED) {
		/* chmod.html: a file's own mode must never itself forbid chmod().
		 * Wine's server denies a FILE_WRITE_ATTRIBUTES open outright when
		 * the file already carries FILE_ATTRIBUTE_READONLY (real NT does
		 * not), which would otherwise make a 0444 file permanently
		 * un-chmod-able by path. Fall back to a read-attributes-only
		 * handle: Wine's NtSetInformationFile does not itself require
		 * FILE_WRITE_ATTRIBUTES on the handle. */
		st = NtOpenFile(&h, FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE,
		                &np.oa, &io, FILE_SHARE_VALID_FLAGS, options);
	}
	__ntpath_free(&np);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	r = __plat_chmod(h, mode);
	NtClose(h);
	return r;
}

/* NT has no OS-level umask concept of its own to push `m` out to: masking
 * already happens once, in userspace, via __umask_get() at every NT front
 * door that needs it. A documented no-op, not a stub. */
void __plat_umask_apply(mode_t m)
{
	(void)m;
}

/* ---- mkdir (src/stat/mkdir.c) ------------------------------------------ */

int __plat_mkdir(int dirfd, const char *path, mode_t mode)
{
	struct __ntpath np;
	IO_STATUS_BLOCK io;
	HANDLE h;
	NTSTATUS st;
	unsigned char mode_ea[32];
	unsigned ea_len;
	int vfs = __vfs_resolve_at(dirfd, path);
	if (vfs < 0) return -1;
	if (vfs & __VFS_NATIVE) vfs = __VFS_NONE;
	if (vfs != __VFS_NONE) {
		errno = vfs == __VFS_MISSING ? EROFS : EEXIST;
		return -1;
	}

	mode = mode & ~__umask_get() & 07777;
	ea_len = __lxmod_create_buffer(mode_ea, S_IFDIR | mode);

	if (__ntpath_at(dirfd, path, &np, OBJ_CASE_INSENSITIVE) < 0) return -1;
	/* Wine only consumes NtCreateFile's EA buffer when the requested access
	 * includes FILE_WRITE_EA.  Without it mkdir() succeeded but silently
	 * discarded the requested POSIX mode, so stat() fell back to 0755. */
	st = NtCreateFile(&h, FILE_LIST_DIRECTORY | FILE_WRITE_EA | SYNCHRONIZE,
	                          &np.oa, &io, 0,
	                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_VALID_FLAGS, FILE_CREATE,
	                          FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT,
	                          mode_ea, ea_len);
	/* mkdir.html requires [EEXIST] when the named file exists, whatever kind
	 * of file it is -- reached here through NT's *collision* status, not a
	 * type mismatch. The call pairs FILE_CREATE with FILE_DIRECTORY_FILE,
	 * so an existing plain file at `path` is both a name collision and a
	 * create-option mismatch. Measured on Windows 11 Pro 22621 NTFS: NT
	 * reports the collision (0xc0000035), NOT STATUS_NOT_A_DIRECTORY.
	 *
	 * NT is asymmetric here: the mirror case (FILE_NON_DIRECTORY_FILE
	 * against an existing directory, src/unistd/link.c's symlinkat())
	 * reports the *mismatch* first (0xc00000ba) instead. Do not
	 * "simplify" by assuming the two call sites share one status arm, or
	 * add a STATUS_NOT_A_DIRECTORY case here on the theory that NT is
	 * consistent about which it reports. */
	__ntpath_free(&np);
	if (st == STATUS_OBJECT_NAME_COLLISION) { errno = EEXIST; return -1; }
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	/* Wine 11 accepts the create-time EA buffer above but does not attach it
	 * to a newly-created directory. Repeat the write on the returned
	 * handle, best-effort like the create-time EA itself. */
	{
		int saved_errno = errno;
		__plat_lxmod_set(h, S_IFDIR | mode);
		errno = saved_errno;
	}
	NtClose(h);
	return 0;
}

/* ---- mkfifo/mknod (src/stat/chmod.c) ------------------------------------ */

/* NT has no filesystem node type either mkfifo() or mknod() maps onto
 * (named pipes are real NTDLL objects, but nobody has mapped POSIX FIFO
 * semantics onto them, and NTFS has no device-node concept at all), so
 * this is an unconditional stub: dirfd/path/dev are validated by nothing
 * and nothing is created. Which errno depends only on the requested type:
 * S_IFIFO gets mkfifo()'s historical ENOSYS; anything else gets mknod()'s
 * EPERM, POSIX's real answer for a non-FIFO type the caller lacks
 * privilege for. */
int __plat_mknod(int dirfd, const char *path, mode_t mode, dev_t dev) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; mode and dev have distinct roles
{
	(void)dirfd; (void)path; (void)dev;
	errno = (mode & S_IFMT) == S_IFIFO ? ENOSYS : EPERM;
	return -1;
}

/* ---- stat/fstat (src/stat/stat.c) --------------------------------------- */

/* A real st_dev is always vi.VolumeSerialNumber, a plain ULONG assigned
 * into the 64-bit dev_t, so its top 32 bits are always zero. Setting all
 * of ours gives values no real volume serial number can equal, while
 * keeping the two distinct from each other. */
#define __STAT_DEV_PIPE ((dev_t)0xFFFFFFFF00000001ULL) // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision
#define __STAT_DEV_CHAR ((dev_t)0xFFFFFFFF00000002ULL) // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision

/* FNV-1a, a well-known 64-bit hash, used below to fold a variable-length
 * NT object name into a fixed 64-bit st_ino. */
static ino_t fnv1a64(const void *data, size_t n) __attribute__((nonnull(1)));
static ino_t fnv1a64(const void *data, size_t n)
{
	const unsigned char *p = data;
	ino_t h = 0xcbf29ce484222325ULL;
	size_t i;
	for (i = 0; i < n; i++) { h ^= p[i]; h *= 0x100000001b3ULL; }
	return h;
}

/* The identity source for a pipe/console/char/unknown handle, in order of
 * preference -- each candidate was checked, not assumed:
 *
 * 1. FileInternalInformation, the same NTFS-style file reference number
 *    the regular-file path below uses. NPFS (the named-pipe filesystem)
 *    does not support it (confirmed under Wine: STATUS_NOT_IMPLEMENTED),
 *    but a real ConDrv console handle answers with a real, distinct-
 *    per-handle value, so it is tried first.
 *
 * 2. NtQueryObject's ObjectNameInformation, hashed. A console handle has
 *    no name, but a pipe does -- and for this library's own pipe2(), the
 *    read and write ends of the *same* pipe are opens of the *same* NT
 *    path, so they hash to the same st_ino, reporting the two ends of one
 *    pipe as "the same file" by the st_dev/st_ino test. Defensible: the
 *    alternative (handle value) would make even the *same* end of the
 *    same pipe stop matching itself across dup(), the worse failure mode.
 *
 * 3. The handle value itself, when neither of the above produced
 *    anything: unique within this process and stable for the handle's own
 *    lifetime, but NOT stable across dup(). */
static ino_t __fstat_synthetic_ino(HANDLE h) // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision
{
	IO_STATUS_BLOCK io;
	FILE_INTERNAL_INFORMATION ii;
	NTSTATUS s;

	s = NtQueryInformationFile(h, &io, &ii, sizeof ii, FileInternalInformation);
	if (NT_SUCCESS(s) && ii.IndexNumber != 0) return (ino_t)ii.IndexNumber;

	{
		char buf[512] = { 0 };
		ULONG ret = 0;
		OBJECT_NAME_INFORMATION *ni = (OBJECT_NAME_INFORMATION *)buf;
		s = NtQueryObject(h, ObjectNameInformation, buf, sizeof buf, &ret);
		if (NT_SUCCESS(s) && ni->Name.Length > 0)
			return fnv1a64(ni->Name.Buffer, ni->Name.Length);
	}

	return (ino_t)(ULONG_PTR)h;
}

static unsigned getle16(const unsigned char *p)
{
	return (unsigned)p[0] | (unsigned)p[1] << 8;
}

static int read_at(HANDLE h, void *buffer, unsigned length, long long offset) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	IO_STATUS_BLOCK io;
	LARGE_INTEGER position = offset;
	NTSTATUS status;

	io.Information = 0;
	status = NtReadFile(h, 0, 0, 0, &io, buffer, length, &position, 0);
	if (status == STATUS_PENDING) {
		NtWaitForSingleObject(h, 0, 0);
		status = io.Status;
	}
	return NT_SUCCESS(status) && io.Information == length;
}

/* Offsets/values from the on-disk PE/COFF format (Microsoft, "PE Format"):
 * IMAGE_DOS_HEADER::e_lfanew, then IMAGE_FILE_HEADER::{SizeOfOptional
 * Header,Characteristics} and IMAGE_OPTIONAL_HEADER{32,64}::Magic
 * immediately following the "PE\0\0" signature. */
#define PE_DOS_E_LFANEW 0x3c
#define PE_COFF_SIZE_OF_OPTIONAL_HEADER 20
#define PE_COFF_CHARACTERISTICS 22
#define PE_OPTIONAL_MAGIC 24
#define PE_MAGIC_PE32 0x10b
#define PE_MAGIC_PE32PLUS 0x20b
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_DLL 0x2000

/* Validate enough of the on-disk PE header to distinguish an executable
 * image from a DOS file, DLL, text file with an executable-looking suffix,
 * or an arbitrary file beginning with MZ.  Both PE32 and PE32+ are Windows
 * executable formats; IMAGE_FILE_EXECUTABLE_IMAGE must be set and the DLL
 * characteristic must be clear. */
static int pe_executable(HANDLE h, long long size)
{
	unsigned char dos[64], nt[26];
	unsigned long peoff;
	unsigned characteristics, optional_size, optional_magic;
	long long saved;
	int result = 0;

	if (size < (long long)sizeof dos || __fd_pos_save(h, &saved) < 0)
		return 0;
	if (!read_at(h, dos, sizeof dos, 0) || dos[0] != 'M' || dos[1] != 'Z')
		goto done;
	peoff = getle32(dos + PE_DOS_E_LFANEW);
	if ((long long)peoff > size - (long long)sizeof nt ||
	    !read_at(h, nt, sizeof nt, peoff))
		goto done;
	if (nt[0] != 'P' || nt[1] != 'E' || nt[2] || nt[3]) goto done;
	optional_size = getle16(nt + PE_COFF_SIZE_OF_OPTIONAL_HEADER);
	characteristics = getle16(nt + PE_COFF_CHARACTERISTICS);
	optional_magic = getle16(nt + PE_OPTIONAL_MAGIC);
	if (optional_size >= 2 &&
	    (optional_magic == PE_MAGIC_PE32 || optional_magic == PE_MAGIC_PE32PLUS) &&
	    (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) &&
	    !(characteristics & IMAGE_FILE_DLL))
		result = 1;
done:
	__fd_pos_restore(h, saved);
	return result;
}

static mode_t mode_from_attrs(ULONG attrs, ULONG tag, int exe, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
                              int have_lxmod, unsigned lxmod)
{
	mode_t m;
	if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) &&
	    (tag == IO_REPARSE_TAG_SYMLINK || tag == IO_REPARSE_TAG_MOUNT_POINT || tag == IO_REPARSE_TAG_LX_SYMLINK))
		m = S_IFLNK;
	else if (attrs & FILE_ATTRIBUTE_DIRECTORY) m = S_IFDIR;
	else if (attrs & FILE_ATTRIBUTE_DEVICE) m = S_IFCHR;
	else m = S_IFREG;
	if (S_ISLNK(m)) m |= 0777;
	else if (S_ISDIR(m)) m |= 0755;
	else if (S_ISCHR(m)) m |= 0666;
	else m |= exe ? 0755 : 0644;
	/* $LXMOD is the POSIX mode record, not merely an execute-bit sidecar.
	 * Keep the type derived from the live NT object, but report every
	 * permission and special bit from the metadata.  Files without the EA
	 * use the validated-PE compatibility fallback. */
	if (have_lxmod) m = (m & S_IFMT) | (lxmod & 07777);
	/* The native readonly attribute is independently authoritative.  It may
	 * have been changed by a Windows program, or an EA query may return an
	 * older $LXMOD value immediately after the attribute transition. */
	if (attrs & FILE_ATTRIBUTE_READONLY) m &= ~0222;
	return m;
}

int __plat_fstat(__plat_handle_t h, int type, struct stat *st)
{
	IO_STATUS_BLOCK io;
	FILE_BASIC_INFORMATION bi;
	FILE_STANDARD_INFORMATION si;
	FILE_INTERNAL_INFORMATION ii;
	FILE_ATTRIBUTE_TAG_INFORMATION ti;
	FILE_FS_VOLUME_INFORMATION vi;
	long long blocks;
	NTSTATUS s;
	unsigned lxmod = 0;
	int have_lxmod, exe = 0;

	memset(st, 0, sizeof *st);
	if (type == __FD_PIPE) {
		st->st_dev = __STAT_DEV_PIPE;
		st->st_ino = __fstat_synthetic_ino(h);
		st->st_mode = S_IFIFO | 0600; st->st_nlink = 1; st->st_blksize = 4096; return 0;
	}
	if (type == __FD_CONSOLE || type == __FD_CHAR || type == __FD_UNKNOWN) {
		st->st_dev = __STAT_DEV_CHAR;
		st->st_ino = __fstat_synthetic_ino(h);
		st->st_mode = S_IFCHR | 0600; st->st_nlink = 1; st->st_blksize = 4096; return 0;
	}

	s = NtQueryInformationFile(h, &io, &bi, sizeof bi, FileBasicInformation);
	if (!NT_SUCCESS(s)) return __set_errno_status(s);
	s = NtQueryInformationFile(h, &io, &si, sizeof si, FileStandardInformation);
	if (!NT_SUCCESS(s)) return __set_errno_status(s);
	if (si.EndOfFile < 0 ||
	    !__file_allocation_blocks(si.AllocationSize, &blocks)) {
		errno = EOVERFLOW;
		return -1;
	}
	if (!NT_SUCCESS(NtQueryInformationFile(h, &io, &ii, sizeof ii, FileInternalInformation))) ii.IndexNumber = 0;
	if (!NT_SUCCESS(NtQueryInformationFile(h, &io, &ti, sizeof ti, FileAttributeTagInformation))) ti.ReparseTag = 0;
	if (NT_SUCCESS(NtQueryVolumeInformationFile(h, &io, &vi, sizeof vi, FileFsVolumeInformation)) ||
	    io.Information >= offsetof(FILE_FS_VOLUME_INFORMATION, VolumeLabel))
		st->st_dev = vi.VolumeSerialNumber;
	have_lxmod = __plat_lxmod_get(h, &lxmod);

	if (!have_lxmod && !(bi.FileAttributes &
	    (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE))) {
		int saved = errno;
		exe = pe_executable(h, si.EndOfFile);
		errno = saved;
	}

	st->st_ino = (ino_t)ii.IndexNumber;
	st->st_mode = mode_from_attrs(bi.FileAttributes, ti.ReparseTag,
	                              exe, have_lxmod, lxmod);
	st->st_nlink = si.NumberOfLinks ? si.NumberOfLinks : 1;
	st->st_uid = getuid();
	st->st_gid = getgid();
	st->st_size = S_ISDIR(st->st_mode) ? 0 : si.EndOfFile;
	st->st_blksize = 4096;
	st->st_blocks = (blkcnt_t)blocks;
	st->st_atim.tv_sec = __ticks_to_unix_sec(bi.LastAccessTime);
	st->st_atim.tv_nsec = __ticks_to_unix_nsec(bi.LastAccessTime);
	st->st_mtim.tv_sec = __ticks_to_unix_sec(bi.LastWriteTime);
	st->st_mtim.tv_nsec = __ticks_to_unix_nsec(bi.LastWriteTime);
	st->st_ctim.tv_sec = __ticks_to_unix_sec(bi.ChangeTime);
	st->st_ctim.tv_nsec = __ticks_to_unix_nsec(bi.ChangeTime);
	return 0;
}

int __plat_fstatat(int dirfd, const char *path, int flags, struct stat *st)
{
	struct __ntpath np;
	IO_STATUS_BLOCK io;
	HANDLE h;
	NTSTATUS s;
	int r, vfs;

	vfs = __vfs_resolve_at(dirfd, path);
	if (vfs < 0) return -1;
	if (vfs & __VFS_NATIVE) vfs = __VFS_NONE;
	if (vfs == __VFS_MISSING) { errno = ENOENT; return -1; }
	if (vfs != __VFS_NONE) return __vfs_stat(vfs, st);

	if (__ntpath_at(dirfd, path, &np, OBJ_CASE_INSENSITIVE) < 0) return -1;
	s = NtOpenFile(&h, FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA |
	               SYNCHRONIZE, &np.oa, &io, FILE_SHARE_VALID_FLAGS,
	               FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT |
	               (flags & AT_SYMLINK_NOFOLLOW ? FILE_OPEN_REPARSE_POINT : 0));
	/* stat() must not require permission to read file data. Reading is only
	 * needed for the metadata-free PE default, so retain the ordinary
	 * attribute-only result when that extra access is denied. */
	if (!NT_SUCCESS(s) && s != STATUS_IO_REPARSE_TAG_NOT_HANDLED)
		s = NtOpenFile(&h, FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE,
		               &np.oa, &io, FILE_SHARE_VALID_FLAGS,
		               FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT |
		               (flags & AT_SYMLINK_NOFOLLOW ? FILE_OPEN_REPARSE_POINT : 0));
	if (s == STATUS_IO_REPARSE_TAG_NOT_HANDLED && !(flags & AT_SYMLINK_NOFOLLOW)) {
		/* A reparse point of a kind nothing resolves (WSL links): report it as is. */
		s = NtOpenFile(&h, FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA |
		               SYNCHRONIZE, &np.oa, &io, FILE_SHARE_VALID_FLAGS,
		               FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT);
		if (!NT_SUCCESS(s))
			s = NtOpenFile(&h, FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE,
			               &np.oa, &io, FILE_SHARE_VALID_FLAGS,
			               FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT |
			               FILE_OPEN_REPARSE_POINT);
	}
	__ntpath_free(&np);
	if (!NT_SUCCESS(s)) return __set_errno_status(s);
	r = __plat_fstat(h, __FD_FILE, st);
	NtClose(h);
	return r;
}

/* ---- statvfs/fstatvfs (src/stat/statvfs.c) ------------------------------ */

int __plat_statvfs(__plat_handle_t h, struct statvfs *buf)
{
	IO_STATUS_BLOCK io;
	FILE_FS_FULL_SIZE_INFORMATION fsi;
	FILE_FS_SIZE_INFORMATION si;
	FILE_FS_DEVICE_INFORMATION di;
	/* FileSystemName/VolumeLabel are variable-length; over-allocate so
	 * the fixed head is never truncated by a long name.  Only the
	 * fixed members are read. */
	union { FILE_FS_ATTRIBUTE_INFORMATION a; char pad[sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + 256 * sizeof(WCHAR)]; } ab;
	union { FILE_FS_VOLUME_INFORMATION v; char pad[sizeof(FILE_FS_VOLUME_INFORMATION) + 256 * sizeof(WCHAR)]; } vb;
	NTSTATUS s;
	unsigned long long cluster;

	memset(buf, 0, sizeof *buf);

	s = NtQueryVolumeInformationFile(h, &io, &fsi, sizeof fsi, FileFsFullSizeInformation);
	if (NT_SUCCESS(s)) {
		cluster = (unsigned long long)fsi.SectorsPerAllocationUnit * fsi.BytesPerSector;
		buf->f_blocks = (fsblkcnt_t)fsi.TotalAllocationUnits;
		buf->f_bfree = (fsblkcnt_t)fsi.ActualAvailableAllocationUnits;
		buf->f_bavail = (fsblkcnt_t)fsi.CallerAvailableAllocationUnits;
	} else {
		s = NtQueryVolumeInformationFile(h, &io, &si, sizeof si, FileFsSizeInformation);
		if (!NT_SUCCESS(s)) return __set_errno_status(s);
		cluster = (unsigned long long)si.SectorsPerAllocationUnit * si.BytesPerSector;
		buf->f_blocks = (fsblkcnt_t)si.TotalAllocationUnits;
		/* This class reports only the caller-visible free count; with
		 * no second figure to distinguish them, f_bfree is that same
		 * number rather than a guess at what quota is hiding. */
		buf->f_bavail = buf->f_bfree = (fsblkcnt_t)si.AvailableAllocationUnits;
	}

	/* fstatvfs.html ERRORS: [EOVERFLOW] "One of the values to be
	 * returned cannot be represented correctly in the structure
	 * pointed to by buf."  f_bsize/f_frsize are `unsigned long`, which
	 * is 32-bit under this target's LLP64 model on both arches, while
	 * the cluster size is computed from two ULONGs and could in
	 * principle exceed it.  The block *counts* cannot overflow:
	 * fsblkcnt_t is unsigned 64-bit and the NT counters are signed
	 * 64-bit LARGE_INTEGERs. */
	if (cluster > (unsigned long)-1) { errno = EOVERFLOW; return -1; }
	buf->f_bsize = buf->f_frsize = (unsigned long)cluster;

	/* f_files/f_ffree/f_favail stay 0 from the memset above -- see
	 * statvfs.c's own banner.  NT exposes no file-serial-number pool. */

	buf->f_flag = ST_NOSUID;

	s = NtQueryVolumeInformationFile(h, &io, &ab, sizeof ab, FileFsAttributeInformation);
	if (NT_SUCCESS(s)) {
		if (ab.a.FileSystemAttributes & FILE_READ_ONLY_VOLUME) buf->f_flag |= ST_RDONLY;
		if (ab.a.MaximumComponentNameLength > 0) buf->f_namemax = (unsigned long)ab.a.MaximumComponentNameLength;
	}

	s = NtQueryVolumeInformationFile(h, &io, &di, sizeof di, FileFsDeviceInformation);
	if (NT_SUCCESS(s) && (di.Characteristics & FILE_READ_ONLY_DEVICE)) buf->f_flag |= ST_RDONLY;

	s = NtQueryVolumeInformationFile(h, &io, &vb, sizeof vb, FileFsVolumeInformation);
	if (NT_SUCCESS(s)) buf->f_fsid = vb.v.VolumeSerialNumber;

	return 0;
}

int __plat_statvfs_path(const char *path, struct statvfs *buf)
{
	struct __ntpath np;
	IO_STATUS_BLOCK io;
	HANDLE h;
	NTSTATUS s;
	int r, vfs;

	vfs = __vfs_resolve_at(AT_FDCWD, path);
	if (vfs < 0) return -1;
	if (vfs & __VFS_NATIVE) vfs = __VFS_NONE;
	if (vfs == __VFS_MISSING) { errno = ENOENT; return -1; }
	if (vfs != __VFS_NONE) {
		memset(buf, 0, sizeof *buf);
		buf->f_bsize = buf->f_frsize = 4096;
		buf->f_fsid = 0xffffffffu;
		buf->f_flag = ST_RDONLY | ST_NOSUID;
		buf->f_namemax = 255;
		return 0;
	}
	/* "Read, write, or execute permission of the named file is not
	 * required" (DESCRIPTION) -- FILE_READ_ATTRIBUTES is the NT access
	 * mask that asks for none of the three. */
	if (__ntpath(path, &np, OBJ_CASE_INSENSITIVE) < 0) return -1;
	s = NtOpenFile(&h, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &np.oa, &io, FILE_SHARE_VALID_FLAGS,
	               FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT);
	__ntpath_free(&np);
	if (!NT_SUCCESS(s)) return __set_errno_status(s);
	r = __plat_statvfs(h, buf);
	NtClose(h);
	return r;
}

/* ---- utimensat (src/stat/utimensat.c) ----------------------------------- */

int __plat_set_times(__plat_handle_t h, const struct timespec ts[2])
{
	IO_STATUS_BLOCK io;
	FILE_BASIC_INFORMATION bi;
	LARGE_INTEGER now;
	LARGE_INTEGER converted[2] = { 0, 0 };
	NTSTATUS st;
	int i;

	if (ts) {
		for (i = 0; i < 2; i++) {
			if (ts[i].tv_nsec == UTIME_NOW || ts[i].tv_nsec == UTIME_OMIT)
				continue;
			if (ts[i].tv_nsec < 0 || ts[i].tv_nsec >= 1000000000L) {
				errno = EINVAL;
				return -1;
			}
			if (!__unix_to_ticks(ts[i].tv_sec, ts[i].tv_nsec,
			    &converted[i])) {
				errno = EOVERFLOW;
				return -1;
			}
		}
	}

	/* utime.html: only the access/modification times change, the mode must
	 * survive untouched. FILE_BASIC_INFORMATION documents FileAttributes==0
	 * as "leave the attributes alone", and real NT honors that -- but stock
	 * Wine's NtSetInformationFile silently clears FILE_ATTRIBUTE_READONLY on
	 * every timestamp-only call regardless. So always query the current
	 * attributes and pass them back explicitly, on every Wine and on real
	 * NT alike. This round-trip needs FILE_READ_ATTRIBUTES on the handle,
	 * which __plat_set_times_at()'s primary open below requests
	 * specifically for this. */
	st = NtQueryInformationFile(h, &io, &bi, sizeof bi, FileBasicInformation);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	bi.CreationTime = bi.LastAccessTime = bi.LastWriteTime = bi.ChangeTime = 0;
	NtQuerySystemTime(&now);
	if (!ts) { bi.LastAccessTime = bi.LastWriteTime = now; }
	else {
		if (ts[0].tv_nsec == UTIME_NOW) bi.LastAccessTime = now;
		else if (ts[0].tv_nsec != UTIME_OMIT) bi.LastAccessTime = converted[0];
		if (ts[1].tv_nsec == UTIME_NOW) bi.LastWriteTime = now;
		else if (ts[1].tv_nsec != UTIME_OMIT) bi.LastWriteTime = converted[1];
	}
	st = NtSetInformationFile(h, &io, &bi, sizeof bi, FileBasicInformation);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	return 0;
}

int __plat_set_times_at(int dirfd, const char *path, int flags, const struct timespec ts[2])
{
	struct __ntpath np;
	IO_STATUS_BLOCK io;
	HANDLE h;
	NTSTATUS st;
	ULONG options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT |
	                (flags & AT_SYMLINK_NOFOLLOW ? FILE_OPEN_REPARSE_POINT : 0);
	int r;

	if (__ntpath_at(dirfd, path, &np, OBJ_CASE_INSENSITIVE) < 0) return -1;
	/* FILE_READ_ATTRIBUTES is requested alongside FILE_WRITE_ATTRIBUTES
	 * because __plat_set_times() above round-trips the current attributes
	 * through NtQueryInformationFile before writing them back, which
	 * requires FILE_READ_ATTRIBUTES on real NT (Wine doesn't enforce that
	 * check). Omitting it here is exactly what turned every ordinary
	 * utimensat() into STATUS_ACCESS_DENIED on real Windows before. */
	st = NtOpenFile(&h, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE, &np.oa, &io, FILE_SHARE_VALID_FLAGS, options);
	if (st == STATUS_ACCESS_DENIED) {
		/* Wine's server denies a FILE_WRITE_ATTRIBUTES open outright when
		 * the file already carries FILE_ATTRIBUTE_READONLY (real NT does
		 * not, so real NT never falls back to this handle). The fallback
		 * keeps FILE_READ_ATTRIBUTES, all __plat_set_times()'s query
		 * needs. */
		st = NtOpenFile(&h, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &np.oa, &io, FILE_SHARE_VALID_FLAGS, options);
	}
	__ntpath_free(&np);
	if (!NT_SUCCESS(st)) return __set_errno_status(st);
	r = __plat_set_times(h, ts);
	NtClose(h);
	return r;
}

// NOLINTEND(misc-include-cleaner)
