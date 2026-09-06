/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Two backends: src/termios/termios.c against an NT console (only
 * ISIG/ICANON/ECHO are real, via GetConsoleMode()/SetConsoleMode();
 * everything serial-line-shaped -- baud/parity/stop-bit/flow-control,
 * tcsendbreak() -- is honestly N/A, not faked), and
 * src/termios/linux/plat_termios.c against a real tty/pty via
 * ioctl(2), where every clause is real.
 */
#ifndef _TERMIOS_H
#define _TERMIOS_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <ownership.h>

#define __NEED_pid_t
#include <bits/alltypes.h>

typedef unsigned long tcflag_t;
typedef unsigned char cc_t;
typedef unsigned int speed_t;

/* None of these are independently settable on an NT console (VINTR's
 * Ctrl-C and VEOF's Ctrl-Z are fixed keys it recognises on its own);
 * all 16 still round-trip through tcgetattr()/tcsetattr() as plain
 * stored bytes. */
#define VINTR    0
#define VQUIT    1
#define VERASE   2
#define VKILL    3
#define VEOF     4
#define VTIME    5
#define VMIN     6
#define VSTART   7
#define VSTOP    8
#define VSUSP    9
#define VEOL     10
#define VREPRINT 11
#define VDISCARD 12
#define VWERASE  13
#define VLNEXT   14
#define VEOL2    15
#define NCCS     16

struct termios {
	tcflag_t c_iflag;
	tcflag_t c_oflag;
	tcflag_t c_cflag;
	tcflag_t c_lflag;
	cc_t c_cc[NCCS];
	/* Not POSIX-mandated; added *BSD-style as storage for
	 * cfsetispeed() et al, since nothing here ever reads it back. */
	speed_t c_ispeed;
	speed_t c_ospeed;
};

/* c_iflag: on NT, accepted and stored but never applied -- ReadConsole()
 * runs no line discipline these could hook. */
#define IGNBRK  0000001
#define BRKINT  0000002
#define IGNPAR  0000004
#define PARMRK  0000010
#define INPCK   0000020
#define ISTRIP  0000040
#define INLCR   0000100
#define IGNCR   0000200
#define ICRNL   0000400
#define IXON    0002000
#define IXANY   0004000
#define IXOFF   0010000

/* c_oflag: same status as c_iflag above. */
#define OPOST   0000001
#define ONLCR   0000004
#define OCRNL   0000010
#define ONOCR   0000020
#define ONLRET  0000040
#define OFILL   0000100
#define OFDEL   0000200

/* c_oflag delay masks. Each name is a field mask, not a single flag
 * bit; NL0/CR0/TAB0/BS0/VT0/FF0 are zero because "no delay" is the
 * field being clear. Never applied on NT: a console write is finished
 * by the time WriteConsole() returns, so these are accepted and stored
 * only, same status as ONLCR/OFILL above. */
#define NLDLY   0000400
#define NL0     0000000
#define NL1     0000400
#define CRDLY   0003000
#define CR0     0000000
#define CR1     0001000
#define CR2     0002000
#define CR3     0003000
#define TABDLY  0014000
#define TAB0    0000000
#define TAB1    0004000
#define TAB2    0010000
#define TAB3    0014000
#define BSDLY   0020000
#define BS0     0000000
#define BS1     0020000
#define VTDLY   0040000
#define VT0     0000000
#define VT1     0040000
#define FFDLY   0100000
#define FF0     0000000
#define FF1     0100000

/* c_cflag: hardware control (wire encoding, RTS/CTS). Genuinely N/A on
 * a console, not merely unimplemented -- accepted and stored like
 * c_iflag/c_oflag. */
#define CSIZE   0000060
#define CS5     0000000
#define CS6     0000020
#define CS7     0000040
#define CS8     0000060
#define CSTOPB  0000100
#define CREAD   0000200
#define PARENB  0000400
#define PARODD  0001000
#define HUPCL   0002000
#define CLOCAL  0004000
#define CRTSCTS 020000000000

/* c_lflag: ISIG/ICANON/ECHO are the real, load-bearing three, mapped
 * onto GetConsoleMode()/SetConsoleMode() (NTLIBC_USE_KERNEL32 only --
 * no ntdll path to console mode exists). The rest are accepted and
 * stored only, same as c_iflag/c_oflag. */
#define ISIG    0000001
#define ICANON  0000002
#define ECHO    0000010
#define ECHOE   0000020
#define ECHOK   0000040
#define ECHONL  0000100
#define NOFLSH  0000200
#define TOSTOP  0000400
#define IEXTEN  0100000

/* tcsetattr() optional_actions (tcsetattr.html DESCRIPTION). */
#define TCSANOW   0
#define TCSADRAIN 1
#define TCSAFLUSH 2

/* tcflush() queue_selector (tcflush.html DESCRIPTION). */
#define TCIFLUSH  0
#define TCOFLUSH  1
#define TCIOFLUSH 2

/* tcflow() action (tcflow.html DESCRIPTION). */
#define TCOOFF 0
#define TCOON  1
#define TCIOFF 2
#define TCION  3

/* POSIX leaves the B* encoding unspecified; these are just the bps
 * number itself, since ntlibc has no real serial line to encode a rate
 * for. */
#define B0        0
#define B50       50
#define B75       75
#define B110      110
#define B134      134
#define B150      150
#define B200      200
#define B300      300
#define B600      600
#define B1200     1200
#define B1800     1800
#define B2400     2400
#define B4800     4800
#define B9600     9600
#define B19200    19200
#define B38400    38400

/* tools/clang/ErrnoDisciplineChecker.cpp's ntlibc.ErrnoDiscipline:
 * src/termios/termios.c's tcgetattr()/tcsetattr() set errno on every
 * failure return, via get_console() (__fd_get()'s own EBADF, or an
 * explicit ENOTTY) or tcsetattr()'s own explicit EINVAL. */
grants_thread_token(errno_grounds)
async_signal_safe
int tcgetattr(int, struct termios *) __attribute__((nonnull(2)));
grants_thread_token(errno_grounds)
async_signal_safe
int tcsetattr(int, int, const struct termios *) __attribute__((nonnull(3)));
speed_t cfgetispeed(const struct termios *) __attribute__((nonnull(1)));
speed_t cfgetospeed(const struct termios *) __attribute__((nonnull(1)));
int cfsetispeed(struct termios *, speed_t) __attribute__((nonnull(1)));
int cfsetospeed(struct termios *, speed_t) __attribute__((nonnull(1)));
async_signal_safe
int tcflush(int, int);
async_signal_safe
int tcdrain(int);
async_signal_safe
int tcflow(int, int);
async_signal_safe
int tcsendbreak(int, int);
pid_t tcgetsid(int);

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
