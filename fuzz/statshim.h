/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A layout-neutral struct stat, and the one seam that translates between
 * spicule's `struct stat` and the host's.
 *
 * Why it has to exist.  libFuzzer is part of the compiler runtime: it was
 * compiled long ago against the *host* headers, and it calls stat() to
 * decide whether the corpus path it was given is a directory
 * (ValidateDirectoryExists -> IsDirectory -> S_ISDIR).  The stat() it
 * reaches is spicule's, because spicule's objects are linked into the same
 * executable.  The two `struct stat`s do not agree:
 *
 *     field       spicule offset   glibc/x86_64 offset
 *     st_mode          16                 24
 *     st_nlink         24                 16
 *     st_uid           32                 28
 *     st_gid           36                 32
 *
 * (measured, not assumed: a host-headers probe reading spicule's answer
 * for a directory saw st_mode = 01, which is st_nlink.)  So S_ISDIR is
 * false for every directory, and libFuzzer rejects any corpus directory
 * with `ERROR: The required directory "..." does not exist` -- even one
 * that is really there.  spicule uses the generic POSIX field order that
 * musl uses on architectures with no Linux ABI to match; glibc and musl
 * on x86_64 both use the kernel's order.  Neither is wrong; they are just
 * different, and a native build puts both in one address space.
 *
 * The seam: fuzz/Makefile runs objcopy over the *library* objects,
 * renaming `stat` to __real_stat -- the definition in src/stat/stat.o and
 * every internal reference to it move together, so spicule's own callers
 * reach spicule's stat() with spicule's struct stat and nothing comes
 * between them.  The name `stat` is then left to ntstubs.c, which
 * answers in the host's layout by asking __real_stat and handing the
 * result to __ntfuzz_pack_stat (host_oracle.c, the one file here built
 * against the host headers).  Neither file has to hand-transcribe the
 * other's struct; this one, which uses no libc types at all, is what
 * they share.
 *
 * It was -Wl,--wrap=stat until fuzz_glob was written.  --wrap is a
 * LINK-WIDE rename, so spicule's six internal stat() call sites
 * (src/glob/glob.c ×4, src/ftw/ftw.c, src/stdlib/mktemp.c) were each
 * being handed a 144-byte host struct stat in their 120-byte spicule
 * one.  A 24-byte overrun, and st_mode read out of st_nlink's slot, so
 * glob() stopped recognising directories.  Nothing noticed because no
 * harness had ever reached an internal stat() call.
 *
 * A harness is not in the renamed set, so a plain stat() call from
 * fuzz_*.c still reaches the host-layout definition.  Harnesses must
 * call __real_stat(); fuzz/fuzz_glob.c declares it and explains why.
 *
 * Confined to fuzz/ on purpose.  Reordering spicule's own struct stat to
 * match glibc's would fix this and several latent siblings, but it is a
 * public header used by every build and every test, and this problem is
 * only ever visible in a native sanitizer build.  It is recorded as a
 * finding rather than fixed here.
 */
#ifndef NTFUZZ_STATSHIM_H
#define NTFUZZ_STATSHIM_H

struct ntfuzz_stat {
	unsigned long long dev, ino, rdev, nlink;
	unsigned int mode, uid, gid;
	long long size, blksize, blocks;
	long long atim_sec, atim_nsec;
	long long mtim_sec, mtim_nsec;
	long long ctim_sec, ctim_nsec;
};

/* Writes *s into `hostbuf`, which must be a host `struct stat`. */
void __ntfuzz_pack_stat(void *hostbuf, const struct ntfuzz_stat *s);
/* sizeof(struct stat) as the host sees it, so the wrapper can zero it. */
unsigned long __ntfuzz_host_stat_size(void);

#endif
