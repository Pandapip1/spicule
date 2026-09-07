/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * statvfs/fstatvfs: everything comes from NtQueryVolumeInformationFile,
 * which works on any open handle on the volume, so both entry points
 * share one filler and differ only in how they get a handle.
 *
 * f_bsize == f_frsize always, since NT's allocation unit is the only
 * block size it reports. f_files/f_ffree/f_favail are always 0: NTFS's
 * MFT grows on demand and exposes no inode-pool count, so a nonzero
 * value would be fabricated. f_fsid is the same VolumeSerialNumber
 * stat.c uses for st_dev. ST_NOSUID is set unconditionally since no NT
 * file system honors setuid/setgid bits and spicule never produces them.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include "libc.h"
#include "plat_stat.h"

int fstatvfs(int fd, struct statvfs *buf)
{
	struct __fd *f = __fd_get(fd);
	if (!f) return -1;   /* __fd_get sets EBADF */
	if (!buf) { errno = EFAULT; return -1; }
	if (f->vfs && !f->vfs_native) {
		memset(buf, 0, sizeof *buf);
		buf->f_bsize = buf->f_frsize = 4096;
		buf->f_fsid = 0xffffffffu;
		buf->f_flag = ST_RDONLY | ST_NOSUID;
		buf->f_namemax = 255;
		return 0;
	}
	return __plat_statvfs(f->h, buf);
}

int statvfs(const char *__restrict path, struct statvfs *__restrict buf)
{
	if (!buf) { errno = EFAULT; return -1; }
	return __plat_statvfs_path(path, buf);
}

// NOLINTEND(misc-include-cleaner)
