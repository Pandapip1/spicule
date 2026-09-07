/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NT's __handle_type()/__fd_init()/__fd_runtime_data() -- moved out of
 * src/internal/fd.c (which keeps only the genuinely portable fd-table
 * bookkeeping) so PLATFORM=linux's own src/internal/linux/plat_fd_init.c
 * can supply its own __handle_type()/__fd_init() without colliding at
 * link time.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include "libc.h"

/* msvcrt's _osfile bits */
#define FOPEN      0x01
#define FEOFLAG    0x02
#define FCRLF      0x04
#define FPIPE      0x08
#define FNOINHERIT 0x10
#define FAPPEND    0x20
#define FDEV       0x40
#define FTEXT      0x80

#define VFS_RUNTIME_MAGIC 0x32534656u /* "VFS2", little-endian */
#define VFS_RUNTIME_CWD_NATIVE 0x80

/* An spicule-specific trailer riding the same RuntimeData blob, past both
 * the fixed osfile/osfhnd table and the optional VFS trailer. Carries
 * POSIX_SPAWN_SETSIGMASK's non-empty mask (src/process/posix_spawn.c) to
 * a child that has not run its own first instruction yet, so cannot be
 * handed data any other way. Self-describing (own magic+length),
 * independent of whether the VFS trailer is present. */
#define SIG_RUNTIME_MAGIC 0x4D474953u /* "SIGM", little-endian */

int __handle_type(HANDLE h)
{
	IO_STATUS_BLOCK io;
	FILE_FS_DEVICE_INFORMATION dev;
	NTSTATUS st;

	if (!h || h == (HANDLE)(LONG_PTR)-1) return __FD_UNKNOWN;
	st = NtQueryVolumeInformationFile(h, &io, &dev, sizeof dev, FileFsDeviceInformation);
	if (!NT_SUCCESS(st)) return __FD_UNKNOWN;
	switch (dev.DeviceType) {
	case FILE_DEVICE_DISK:
	case FILE_DEVICE_DISK_FILE_SYSTEM:
	case FILE_DEVICE_NETWORK_FILE_SYSTEM:
	case FILE_DEVICE_CD_ROM:
	case FILE_DEVICE_CD_ROM_FILE_SYSTEM:
	case FILE_DEVICE_VIRTUAL_DISK:
	case FILE_DEVICE_FILE_SYSTEM:
	case FILE_DEVICE_TAPE_FILE_SYSTEM: {
		FILE_STANDARD_INFORMATION si;
		if (NT_SUCCESS(NtQueryInformationFile(h, &io, &si, sizeof si, FileStandardInformation)) && si.Directory)
			return __FD_DIR;
		return __FD_FILE;
	}
	case FILE_DEVICE_CONSOLE:
	case FILE_DEVICE_SCREEN:
		return __FD_CONSOLE;
	case FILE_DEVICE_NAMED_PIPE:
	case FILE_DEVICE_MAILSLOT:
		return __FD_PIPE;
	case FILE_DEVICE_NULL:
	case FILE_DEVICE_SERIAL_PORT:
	default:
		return __FD_CHAR;
	}
}

/* The access mode of a handle this process did not open.
 *
 * The RuntimeData block a parent leaves for its child is msvcrt's
 * _osfile format, byte for byte -- what lets an spicule program and an
 * msvcrt program inherit each other's descriptors. That format has no
 * access-mode bit (all eight are spoken for), so the mode cannot be
 * recovered from the block, and adding a ninth bit would make the
 * payload a private extension rather than the interop format it is.
 *
 * The handle itself knows instead: NtQueryObject(ObjectBasicInformation)
 * reports GrantedAccess, the actual mask the kernel checks a read or
 * write against.
 *
 * Measured (Wine, x86_64), GrantedAccess for handles this library opens:
 *   O_RDONLY          0x00120089  READ_DATA, no WRITE_DATA
 *   O_WRONLY          0x00120196  WRITE_DATA, no READ_DATA
 *   O_RDWR            0x0012019f  both
 *   O_WRONLY|O_APPEND 0x00120194  APPEND_DATA only, no WRITE_DATA
 * -- the last because open() maps O_APPEND by trading FILE_WRITE_DATA for
 * FILE_APPEND_DATA, so "writable" here has to mean either bit.
 *
 * `fallback` is used only if the query fails, which is not expected. It
 * is O_RDWR for an inherited descriptor, deliberately NOT the O_RDONLY
 * that used to be assumed: guessing too permissive is corrected by the
 * kernel refusing the operation; guessing too restrictive is corrected
 * by nobody, since this library refuses before the kernel is ever asked. */
static unsigned accmode_of(HANDLE h, unsigned fallback)
{
	OBJECT_BASIC_INFORMATION obi;
	ULONG len = 0;
	int r, w;

	if (!NT_SUCCESS(NtQueryObject(h, ObjectBasicInformation, &obi, sizeof obi, &len)))
		return fallback;
	r = (obi.GrantedAccess & FILE_READ_DATA) != 0;
	w = (obi.GrantedAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;
	if (r && w) return O_RDWR;
	if (w) return O_WRONLY;
	if (r) return O_RDONLY;
	return fallback;
}

/* Descriptors 0-2, from the process parameters the creator left behind.
 *
 * A parent cannot reliably say "this one is closed" by writing 0 or -1
 * here: on real Windows both were measured to arrive as a live, open
 * handle instead. Which actor rewrites the field is not known, but it is
 * value-blind, so the only thing the receiving side can do is check what
 * actually turned up -- __handle_type() here: whatever cannot be
 * identified as a file, console or pipe is not installed, covering a
 * dead-but-inheritable handle, a duplicated pseudohandle, and the
 * deliberate placeholder __spawn writes for a closed descriptor. */
static void install_std(int fd, HANDLE h)
{
	if (!h || h == (HANDLE)(LONG_PTR)-1) return;
	if (__handle_type(h) == __FD_UNKNOWN) return;
	__fd_install_at(fd, h, fd == 0 ? O_RDONLY : O_WRONLY, 0);
}

/* pp = __peb->ProcessParameters is populated by the NT loader before any
 * user-mode instruction runs, so its dereferences below are sound. */
void __fd_init(void)
{
	PRTL_USER_PROCESS_PARAMETERS pp = __peb->ProcessParameters;
	install_std(0, pp->StandardInput);
	install_std(1, pp->StandardOutput);
	install_std(2, pp->StandardError);

	if (pp->RuntimeData.Buffer && pp->RuntimeData.Length >= sizeof(int)) {
		const unsigned char *p = (const unsigned char *)pp->RuntimeData.Buffer;
		const unsigned char *vfs = 0;
		const unsigned char *vfs_native = 0, *vseen = 0, *vnext = 0;
		size_t base;
		int count, i;
		memcpy(&count, p, sizeof count);
		if (count > FD_MAX) count = FD_MAX;
		base = sizeof(int) + count * (1 + sizeof(HANDLE));
		if ((size_t)pp->RuntimeData.Length >= base) {
			const unsigned char *osfile = p + sizeof(int);
			const unsigned char *osfhnd = osfile + count;
			if ((size_t)pp->RuntimeData.Length >= base + 9 + 4 * (size_t)count) {
				unsigned magic, trailer_count;
				memcpy(&magic, p + base, sizeof magic);
				memcpy(&trailer_count, p + base + 4, sizeof trailer_count);
				if (magic == VFS_RUNTIME_MAGIC && trailer_count == (unsigned)count) {
					vfs = p + base + 8;
					vfs_native = vfs + count;
					vseen = vfs_native + count;
					vnext = vseen + count;
					int cwd = vnext[count];
					if (cwd & VFS_RUNTIME_CWD_NATIVE)
						cwd = __VFS_NATIVE | (cwd & ~VFS_RUNTIME_CWD_NATIVE);
					__vfs_cwd_set(cwd);
				}
			}
			/* The sigmask trailer, if any, rides immediately after
			 * whichever of the two trailers above did or did not appear --
			 * its own magic makes it self-describing regardless, see this
			 * file's own comment on SIG_RUNTIME_MAGIC above. */
			{
				size_t sig_pos = base + (vfs ? (size_t)(9 + 4 * count) : 0);
				if ((size_t)pp->RuntimeData.Length >= sig_pos + 4 + sizeof(sigset_t)) {
					unsigned smagic;
					memcpy(&smagic, p + sig_pos, sizeof smagic);
					if (smagic == SIG_RUNTIME_MAGIC) {
						sigset_t mask;
						memcpy(&mask, p + sig_pos + 4, sizeof mask);
						__sig_current_mask_install(&mask);
					}
				}
			}
			for (i = 0; i < count; i++) {
				HANDLE h;
				int vk = vfs ? vfs[i] : __VFS_NONE;
				memcpy((void *)&h, osfhnd + i * sizeof(HANDLE), sizeof h);
				if (!(osfile[i] & FOPEN) || !h || h == (HANDLE)(LONG_PTR)-1) continue;
				if (i < 3 && __fds[i].h) {
					if (vk) {
						__fds[i].vfs = (unsigned char)vk;
						__fds[i].vfs_native = vfs_native[i];
						__fds[i].vseen = vseen[i];
						__fds[i].vnext = vnext[i];
						if (vk == __VFS_ROOT || vk == __VFS_DEV) __fds[i].type = __FD_DIR;
					}
					continue;   /* the PEB's std handles win */
				}
				if (!vk && __handle_type(h) == __FD_UNKNOWN) continue;
				/* The access mode is NOT in osfile[i] -- see
				 * accmode_of(). Without it every inherited descriptor
				 * read back as O_RDONLY (O_RDONLY is 0), so
				 * write()/pwrite() refused an inherited writable
				 * descriptor with EBADF while ftruncate()/
				 * posix_fallocate() on the same descriptor succeeded,
				 * since they ask the kernel instead of this field. */
				__fd_install_at(i, h, (osfile[i] & FAPPEND ? O_APPEND : 0) |
				                      (vk == __VFS_ROOT || vk == __VFS_DEV ? O_RDONLY : accmode_of(h, O_RDWR)),
				                vk == __VFS_ROOT || vk == __VFS_DEV ? __FD_DIR : 0);
				__fds[i].vfs = (unsigned char)vk;
				if (vk) {
					__fds[i].vfs_native = vfs_native[i];
					__fds[i].vseen = vseen[i];
					__fds[i].vnext = vnext[i];
				}
			}
		}
	}
}

/* Build the RuntimeData block describing the descriptors a child should
 * inherit: everything open and not close-on-exec. Handles are made
 * inheritable as a side effect (NtCreateUserProcess copies only those). */
void *__fd_runtime_data(size_t *len, __plat_handle_t std[3])
{
	int count = 0, i, have_vfs = __vfs_cwd_get() != __VFS_NONE;
	const sigset_t *sigmask = __spawn_pending_sigmask();
	unsigned char *blk, *osfile, *osfhnd;

	for (i = 0; i < FD_MAX; i++) {
		if (__fds[i].h && !(__fds[i].flags & O_CLOEXEC)) {
			count = i + 1;
			if (__fds[i].vfs) have_vfs = 1;
		}
	}
	/* A pending sigmask is worth a block of its own even when nothing
	 * else here is: a caller with no inheritable descriptors and no VFS
	 * mount can still have asked for POSIX_SPAWN_SETSIGMASK. */
	if (count <= 3 && !have_vfs && !sigmask) { *len = 0; return 0; }

	*len = sizeof(int) + count * (1 + sizeof(HANDLE)) + (have_vfs ? 9 + 4 * count : 0) +
	       (sigmask ? 4 + sizeof(sigset_t) : 0);
	blk = __malloc(*len);
	if (!blk) { *len = 0; return 0; }
	memcpy(blk, &count, sizeof count);
	osfile = blk + sizeof(int);
	osfhnd = osfile + count;
	for (i = 0; i < count; i++) {
		HANDLE h = 0;
		unsigned char fl = 0;
		if (__fds[i].h && !(__fds[i].flags & O_CLOEXEC)) {
			HANDLE dup, old;
			int j;
			fl = FOPEN;
			if (__fds[i].flags & O_APPEND) fl |= FAPPEND;
			if (__fds[i].type == __FD_PIPE) fl |= FPIPE;
			if (__fds[i].type == __FD_CONSOLE || __fds[i].type == __FD_CHAR) fl |= FDEV;
			/* Make the handle itself inheritable, in place. The process
			 * backend has already resolved descriptors 0-2 into `std`, so
			 * keep that snapshot in step when this invalidates the old
			 * HANDLE value. */
			old = __fds[i].h;
			if (NT_SUCCESS(NtDuplicateObject(NtCurrentProcess(), old, NtCurrentProcess(), &dup,
			                                 0, OBJ_INHERIT, DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES))) {
				NtClose(old);
				__fds[i].h = dup;
				for (j = 0; j < 3; j++)
					if (std[j] == old) std[j] = dup;
			}
			h = __fds[i].h;
		}
		osfile[i] = fl;
		memcpy(osfhnd + i * sizeof(HANDLE), (const void *)&h, sizeof h);
	}
	if (have_vfs) {
		unsigned magic = VFS_RUNTIME_MAGIC, trailer_count = (unsigned)count;
		int cwd = __vfs_cwd_get();
		unsigned char *trailer = osfhnd + count * sizeof(HANDLE);
		memcpy(trailer, &magic, sizeof magic);
		memcpy(trailer + 4, &trailer_count, sizeof trailer_count);
		for (i = 0; i < count; i++) trailer[8 + i] = __fds[i].vfs;
		for (i = 0; i < count; i++) trailer[8 + count + i] = __fds[i].vfs_native;
		for (i = 0; i < count; i++) trailer[8 + 2 * count + i] = __fds[i].vseen;
		for (i = 0; i < count; i++) trailer[8 + 3 * count + i] = __fds[i].vnext;
		trailer[8 + 4 * count] = (unsigned char)(__VFS_KIND(cwd) |
			((cwd & __VFS_NATIVE) ? VFS_RUNTIME_CWD_NATIVE : 0));
	}
	if (sigmask) {
		unsigned magic = SIG_RUNTIME_MAGIC;
		unsigned char *trailer = osfhnd + count * sizeof(HANDLE) + (have_vfs ? 9 + 4 * (size_t)count : 0);
		memcpy(trailer, &magic, sizeof magic);
		memcpy(trailer + 4, sigmask, sizeof *sigmask);
	}
	return blk;
}

// NOLINTEND(misc-include-cleaner)
