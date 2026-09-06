/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ioctl(): NOT a POSIX interface -- POSIX specifies termios(3) instead,
 * precisely because ioctl request numbers and semantics are not
 * standardized. This header exists anyway as a de-facto-universal BSD/
 * SVR4 extension a large amount of portable-in-practice code assumes
 * exists alongside termios.h. Implemented in src/ioctl/ioctl.c, which
 * documents the small set of requests given a real answer.
 *
 * Request numbers match Linux's (asm-generic/ioctls.h) rather than
 * inventing new ones, since a lot of existing source hardcodes them.
 */
#ifndef _SYS_IOCTL_H
#define _SYS_IOCTL_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <ownership.h>

/* TIOCGWINSZ: terminal window size (src/ioctl/ioctl.c, backed by
 * kernel32's GetConsoleScreenBufferInfo() -- NTLIBC_USE_KERNEL32 only,
 * same reason as termios.h's ISIG/ICANON/ECHO). */
struct winsize {
	unsigned short ws_row;
	unsigned short ws_col;
	unsigned short ws_xpixel;
	unsigned short ws_ypixel;
};
#define TIOCGWINSZ 0x5413

/* FIONREAD: bytes immediately readable without blocking. Real for a pipe
 * and for a regular file (bytes remaining until EOF); not supported for
 * anything else -- see src/ioctl/ioctl.c. */
#define FIONREAD 0x541B

/* FIONBIO: toggle O_NONBLOCK. See src/ioctl/ioctl.c for exactly what
 * O_NONBLOCK does and does not change in this library today. */
#define FIONBIO 0x5421

io_operation
int ioctl(int, unsigned long, ...);

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
