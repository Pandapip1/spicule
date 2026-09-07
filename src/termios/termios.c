/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * termios(3) against an NT console (the only "terminal" the NT backend
 * has -- __FD_CONSOLE, see src/internal/libc.h and src/unistd/isatty.c,
 * which already gates every one of these the same way a real
 * tcgetattr() would: termios.html ERRORS "[ENOTTY] The file associated
 * with fildes is not a terminal."). NT-only: this whole file's body is
 * wrapped in `#ifndef __linux__` below, compiling to nothing on Linux.
 * Linux has a genuine tty/pty layer instead, where every one of these
 * eleven functions is real (real ioctl(2) against the underlying fd,
 * no console-shadow, no SPICULE_USE_KERNEL32 gate) -- see
 * src/termios/linux/plat_termios.c, which implements the identical
 * public symbols this file does. The two never coexist in one build
 * (the Makefile's own PLATFORM axis selects exactly one of NT or
 * Linux -- see its own banner comment), so the guard below exists
 * purely to keep this TU's definitions out of the way on the platform
 * where the OTHER file supplies them for real, not to select between
 * two simultaneously valid implementations.
 *
 * What is real on NT, clause by clause:
 *
 *   - c_lflag's ISIG/ICANON/ECHO: real, direct console-mode bits.
 *     ENABLE_PROCESSED_INPUT (ISIG: does Ctrl-C/Ctrl-Break generate a
 *     signal at all -- src/signal/signal.c's ctrl_handler() is exactly
 *     what this gates), ENABLE_LINE_INPUT (ICANON: does a read wait for
 *     a full line or return per-keystroke), ENABLE_ECHO_INPUT (ECHO:
 *     are typed characters echoed) are reached through the console
 *     driver directly (ConsolepGetMode/ConsolepSetMode over
 *     NtDeviceIoControlFile, src/internal/condrv.h), with kernel32's
 *     GetConsoleMode()/SetConsoleMode() kept only as the
 *     SPICULE_USE_KERNEL32 fallback for a host that does not speak that
 *     protocol.
 *   - tcflush()'s input side (TCIFLUSH/TCIOFLUSH): real, via the same
 *     transport's ConsolepFlushInputBuffer (kernel32's
 *     FlushConsoleInputBuffer() as the fallback) -- tcflush.html
 *     DESCRIPTION "discard[s] data received but not read" is exactly
 *     what that call does.
 *   - tcgetsid(): real in the same sense src/unistd/ttyname.c's
 *     tcgetpgrp() is -- the console is the only terminal a process here
 *     can have and the caller is the only user of it this library can
 *     name, so "the session associated with the terminal" is the
 *     caller's own session, which src/unistd/ids.c keeps as real
 *     per-process state that setsid() moves.  tcgetsid() follows it
 *     rather than answering a constant, gated by the same ENOTTY check
 *     as everything else here.  What is *not* modelled is which
 *     terminal is "controlling": nothing here distinguishes one, so
 *     setsid()'s "shall have no controlling terminal" leaves these two
 *     answering for the console as before (src/unistd/ids.c).
 *
 * What is honestly accepted-and-stored, never applied (round-trips
 * through tcgetattr()/tcsetattr() correctly, changes nothing real):
 * c_iflag and c_oflag in full (no line discipline sits between
 * ReadConsole()/WriteConsole() and the screen buffer for INLCR/OPOST/
 * etc. to hook), and c_lflag's ECHOE/ECHOK/ECHONL/NOFLSH/TOSTOP/IEXTEN
 * (no per-feature console-mode bit for any of these -- only
 * ISIG/ICANON/ECHO, above, have one). c_cc[]: none of the 16 slots are
 * independently reprogrammable through any console API -- VINTR's
 * Ctrl-C and VEOF's Ctrl-Z are fixed keys the console recognises on its
 * own (ENABLE_PROCESSED_INPUT only turns Ctrl-C handling on or off
 * wholesale, and canonical-mode Ctrl-Z-as-EOF is likewise not
 * retargetable), and the rest (VQUIT, VERASE, VKILL, VEOL, VEOL2,
 * VMIN, VTIME, VSTART, VSTOP, VSUSP, VREPRINT, VDISCARD, VWERASE,
 * VLNEXT) have no console concept whatsoever -- so the whole array is
 * stored-only, same as c_iflag/c_oflag.
 *
 * What is genuinely N/A, not merely unimplemented -- a console has no
 * serial line under it for these to describe, so they are honest
 * no-ops rather than faked:
 *
 *   - c_cflag in full (CSIZE/CS5-8, PARENB/PARODD, CSTOPB, CRTSCTS):
 *     wire-encoding properties of a physical line. Stored, never
 *     applied.
 *   - cfgetispeed()/cfsetispeed()/cfgetospeed()/cfsetospeed(): baud
 *     rate is a serial clocking property; a console session has none.
 *     These round-trip a value through struct termios's c_ispeed/
 *     c_ospeed (added the *BSD way, since POSIX itself does not
 *     mandate the storage shape -- termios.h.html) and nothing else on
 *     this platform ever reads it.
 *   - tcflush()'s output side (TCOFLUSH, and the output half of
 *     TCIOFLUSH): "discard[s] data written ... but not transmitted"
 *     (tcflush.html) presumes a transmit queue sitting between the
 *     write and the wire; WriteConsole() completes only once the
 *     characters are already in the screen buffer, so there is nothing
 *     to discard. Legal no-op.
 *   - tcdrain(): "wait until all output written ... has been
 *     transmitted" (tcdrain.html) -- same reasoning: a console write is
 *     synchronously complete by the time it returns, so there is never
 *     anything still in flight to wait out. Legal no-op that returns
 *     immediately.
 *   - tcflow(): TCOOFF/TCOON/TCIOFF/TCION (tcflow.html) all describe
 *     suspending/resuming a serial data stream, or sending XOFF/XON
 *     characters "to the terminal device" -- no such stream or wire
 *     exists for a console. Legal no-op (POSIX default is "neither
 *     input nor output is suspended"; this platform can never make
 *     either true).
 *   - tcsendbreak(): "If the terminal is not using asynchronous serial
 *     data transmission, it is implementation-defined whether
 *     tcsendbreak() sends data ... or returns without taking any
 *     action" (tcsendbreak.html) -- a console is squarely that case.
 *     Legal, spec-permitted no-op.
 *
 * Storage for the accepted-but-not-applied fields is a single
 * process-global shadow, not per-fd: spicule has exactly one console
 * session reachable at a time in practice (no multi-console support
 * anywhere else in this library either -- see src/unistd/ttyname.c's
 * fixed "CON" answer), so a global is the honest amount of state to
 * keep, not an arbitrary simplification hiding a real per-fd need.
 */
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "libc.h"
#ifndef __linux__
#include "condrv.h"
#include "conin.h"
#endif
#ifdef SPICULE_USE_KERNEL32
#include "kernel32.h"
#endif

#ifndef __linux__
/* Everything below is the NT backend proper -- see this file's own
 * banner above for why the Linux build never reaches this point at
 * all (src/termios/linux/plat_termios.c supplies these same eleven
 * symbols there instead). */

/* ---- the shadow: c_iflag/c_oflag/c_cflag/c_cc[]/speeds, plus c_lflag
 * as the last-known value ISIG/ICANON/ECHO fall back to when no real
 * console mode can be reached. */
static struct {
	int inited;
	tcflag_t iflag, oflag, cflag, lflag;
	cc_t cc[NCCS];
	speed_t ispeed, ospeed;
} shadow;

static void shadow_init(void)
{
	if (shadow.inited) return;
	shadow.inited = 1;
	shadow.iflag = ICRNL | IXON;
	shadow.oflag = OPOST | ONLCR;
	shadow.cflag = CS8 | CREAD | HUPCL;
	shadow.lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK | IEXTEN;
	/* Conventional POSIX defaults (the values stty -a shows on most
	 * systems); nothing on this platform enforces them, they are
	 * simply sane data for tcgetattr() to hand back before any
	 * tcsetattr() call. */
	shadow.cc[VINTR] = 3;    /* ^C */
	shadow.cc[VQUIT] = 28;   /* ^\ */
	shadow.cc[VERASE] = 127;
	shadow.cc[VKILL] = 21;   /* ^U */
	shadow.cc[VEOF] = 4;     /* ^D */
	shadow.cc[VTIME] = 0;
	shadow.cc[VMIN] = 1;
	shadow.cc[VSTART] = 17;  /* ^Q */
	shadow.cc[VSTOP] = 19;   /* ^S */
	shadow.cc[VSUSP] = 26;   /* ^Z */
	shadow.cc[VEOL] = 0;
	shadow.cc[VREPRINT] = 18; /* ^R */
	shadow.cc[VDISCARD] = 15; /* ^O */
	shadow.cc[VWERASE] = 23;  /* ^W */
	shadow.cc[VLNEXT] = 22;   /* ^V */
	shadow.cc[VEOL2] = 0;
}

/* termios.html ERRORS / isatty.html: gate every function here the same
 * way src/unistd/isatty.c already gates isatty() itself. */
static struct __fd *get_console(int fd)
{
	struct __fd *f = __fd_get(fd);
	if (!f) return 0;               /* EBADF, already set */
	if (f->type != __FD_CONSOLE) { errno = ENOTTY; return 0; }
	return f;
}

#ifdef SPICULE_USE_KERNEL32
/* Same LdrLoadDll()/LdrGetProcedureAddress() dance as
 * src/signal/signal.c's install_ctrl_handler(), generalised to more
 * than one proc and cached across calls (a console-heavy program may
 * call tcgetattr()/tcsetattr() often; there is no reason to repeat the
 * loader work every time). */
static PVOID k32_dll(void)
{
	static PVOID dll;
	static int tried;
	UNICODE_STRING dllname;

	if (tried) return dll;
	tried = 1;
	RtlInitUnicodeString(&dllname, L"kernel32.dll");
	if (!NT_SUCCESS(LdrLoadDll(0, 0, &dllname, &dll))) dll = 0;
	return dll;
}

static PVOID k32_proc(const char *name)
{
	PVOID dll = k32_dll(), proc;
	ANSI_STRING procname;
	size_t len;

	if (!dll) return 0;
	len = strlen(name);
	if (len > 0xffffu) return 0;
	procname.Buffer = (char *)name;
	procname.Length = procname.MaximumLength = (USHORT)len;
	if (!NT_SUCCESS(LdrGetProcedureAddress(dll, &procname, 0, &proc))) return 0;
	return proc;
}

typedef BOOL (NTAPI *fn_GetConsoleMode)(HANDLE, ULONG *);
typedef BOOL (NTAPI *fn_SetConsoleMode)(HANDLE, ULONG);
typedef BOOL (NTAPI *fn_FlushConsoleInputBuffer)(HANDLE);
#endif

/* ---- the three real console operations, ntdll first.
 *
 * Each drives the console driver directly (src/internal/condrv.h) and
 * only falls back to kernel32 when that fails -- which it does on a
 * console whose host does not speak this protocol, Wine's being the one
 * that matters in practice (see condrv.h's banner). CONTRIBUTING.md's
 * ordering, not a preference: ntdll where ntdll can do it, kernel32 as
 * the guarded fallback. Each returns 0 on success and -1 when neither
 * transport could act, leaving errno alone; the callers below decide
 * what an unreachable console mode means for their own contract. */

static int console_mode_get(HANDLE h, ULONG *mode)
{
	CONSOLE_MODE_MSG body;

	body.Mode = 0;
	if (__condrv_call(h, ConsolepGetMode, &body, sizeof body) == 0) {
		*mode = body.Mode;
		return 0;
	}
#ifdef SPICULE_USE_KERNEL32
	{
		fn_GetConsoleMode fn = (fn_GetConsoleMode)k32_proc("GetConsoleMode");
		if (fn && fn(h, mode)) return 0;
	}
#endif
	return -1;
}

static int console_mode_set(HANDLE h, ULONG mode)
{
	CONSOLE_MODE_MSG body;

	body.Mode = mode;
	if (__condrv_call(h, ConsolepSetMode, &body, sizeof body) == 0) return 0;
#ifdef SPICULE_USE_KERNEL32
	{
		fn_SetConsoleMode fn = (fn_SetConsoleMode)k32_proc("SetConsoleMode");
		if (fn && fn(h, mode)) return 0;
	}
#endif
	return -1;
}

/* ConsolepFlushInputBuffer takes no descriptor at all (conhost's
 * ApiSorter.cpp lists it as CONSOLE_API_NO_PARAMETER), so the message
 * is the bare header and there is no output buffer. */
static int console_flush_input(HANDLE h)
{
	if (__condrv_call(h, ConsolepFlushInputBuffer, 0, 0) == 0) return 0;
#ifdef SPICULE_USE_KERNEL32
	{
		fn_FlushConsoleInputBuffer fn = (fn_FlushConsoleInputBuffer)k32_proc("FlushConsoleInputBuffer");
		if (fn && fn(h)) return 0;
	}
#endif
	return -1;
}

/* Non-canonical mode is where a POSIX program expects the interrupt
 * character to act the moment it is typed, and it is the only mode this
 * library can honestly serve: with ENABLE_LINE_INPUT set, conhost holds
 * the line in its own editor and would hand Ctrl-C over a whole line
 * late (see src/internal/nt/conin.c's banner). So leaving canonical
 * mode -- and only that -- hands the discipline to the reader thread:
 * ENABLE_PROCESSED_INPUT comes off with ENABLE_LINE_INPUT so Ctrl-C
 * arrives as a 0x03 byte, and the thread turns it into SIGINT itself
 * whenever termios still says ISIG.
 *
 * *mode is left exactly as the caller computed it if the thread cannot
 * be started: an unowned console must keep conhost's own Ctrl-C
 * handling rather than lose it to a discipline that is not running. */
static void take_over_line_discipline(HANDLE h, ULONG *mode, int want_isig)
{
	if (*mode & ENABLE_LINE_INPUT) {
		/* Canonical mode, or back to it: the console keeps the job. */
		if (__conin_owns(h)) __conin_set_isig(0);
		return;
	}
	if (__conin_takeover(h) < 0) return;
	*mode &= ~(ULONG)ENABLE_PROCESSED_INPUT;
	__conin_set_isig(want_isig);
}

int tcgetattr(int fd, struct termios *t)
{
	struct __fd *f = get_console(fd);
	if (!f) return -1;
	shadow_init();
	t->c_iflag = shadow.iflag;
	t->c_oflag = shadow.oflag;
	t->c_cflag = shadow.cflag;
	t->c_lflag = shadow.lflag;
	memcpy(t->c_cc, shadow.cc, sizeof shadow.cc);
	t->c_ispeed = shadow.ispeed;
	t->c_ospeed = shadow.ospeed;
	{
		ULONG mode;
		if (console_mode_get(f->h, &mode) == 0) {
			t->c_lflag = (shadow.lflag & ~(ISIG | ICANON | ECHO))
				| (mode & ENABLE_PROCESSED_INPUT ? ISIG : 0)
				| (mode & ENABLE_LINE_INPUT ? ICANON : 0)
				| (mode & ENABLE_ECHO_INPUT ? ECHO : 0);
			/* Once the reader thread owns the handle,
			 * ENABLE_PROCESSED_INPUT is off by construction and
			 * no longer describes ISIG -- the shadow does, and
			 * it is what the thread was told to honour. */
			if (__conin_owns(f->h))
				t->c_lflag = (t->c_lflag & ~(tcflag_t)ISIG) | (shadow.lflag & ISIG);
		}
		/* Neither transport could read the mode (no real console
		 * under this process, as under `make check`'s Wine runner --
		 * see test/posix-termios.c): fall back to the shadow's own
		 * c_lflag. Not an error -- ENOTTY was already the honest
		 * answer for "no terminal at all" and get_console() already
		 * ruled that out; this is "a terminal exists but its mode is
		 * unreadable", which the shadow's last-known/default value
		 * covers. */
	}
	return 0;
}

int tcsetattr(int fd, int act, const struct termios *t) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __fd *f = get_console(fd);
	if (!f) return -1;
	if (act != TCSANOW && act != TCSADRAIN && act != TCSAFLUSH) { errno = EINVAL; return -1; }
	shadow_init();

	{
		ULONG mode;
		if (console_mode_get(f->h, &mode) == 0) {
			mode = (mode & ~(ULONG)(ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT))
				| (t->c_lflag & ISIG ? ENABLE_PROCESSED_INPUT : 0)
				| (t->c_lflag & ICANON ? ENABLE_LINE_INPUT : 0)
				| (t->c_lflag & ECHO ? ENABLE_ECHO_INPUT : 0);
			take_over_line_discipline(f->h, &mode, !!(t->c_lflag & ISIG));
			/* TCSAFLUSH: "all input so far received but not read
			 * shall be discarded" (tcsetattr.html) -- do this before
			 * installing the new mode, same ordering a real
			 * implementation uses. TCSADRAIN differs from TCSANOW
			 * only in output-drain timing, which is a no-op here
			 * anyway (tcdrain() below) -- both are treated as
			 * TCSANOW. */
			if (act == TCSAFLUSH) console_flush_input(f->h);
			console_mode_set(f->h, mode);
			/* Whether or not the mode change actually landed,
			 * tcsetattr() "shall return successful completion if
			 * ... able to perform any of the requested actions"
			 * (tcsetattr.html) -- the shadow update below always
			 * happens, so the store side of the contract is always
			 * honoured even when this environment cannot reach a
			 * real console mode to change. */
		}
	}
	shadow.iflag = t->c_iflag;
	shadow.oflag = t->c_oflag;
	shadow.cflag = t->c_cflag;
	shadow.lflag = t->c_lflag;
	memcpy(shadow.cc, t->c_cc, sizeof shadow.cc);
	shadow.ispeed = t->c_ispeed;
	shadow.ospeed = t->c_ospeed;
	return 0;
}

speed_t cfgetispeed(const struct termios *t) { return t->c_ispeed; }
speed_t cfgetospeed(const struct termios *t) { return t->c_ospeed; }

int cfsetispeed(struct termios *t, speed_t s) { t->c_ispeed = s; return 0; }
int cfsetospeed(struct termios *t, speed_t s) { t->c_ospeed = s; return 0; }

int tcflush(int fd, int queue) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __fd *f = get_console(fd);
	if (!f) return -1;
	if (queue != TCIFLUSH && queue != TCOFLUSH && queue != TCIOFLUSH) { errno = EINVAL; return -1; }
	if (queue == TCOFLUSH) return 0;   /* N/A: no transmit queue, see file banner */
	console_flush_input(f->h);
	/* If neither transport could reach the console: honest no-op, not
	 * a fabricated success. Still returns 0: tcflush() has no
	 * ENOTSUP-shaped error for "I accepted the request but could not
	 * act on it", and returning -1 here would be indistinguishable
	 * from the genuine failures (EBADF/EINVAL/ENOTTY) already checked
	 * above. */
	return 0;
}

int tcdrain(int fd)
{
	struct __fd *f = get_console(fd);
	if (!f) return -1;
	return 0;   /* N/A: no transmit queue to wait out, see file banner */
}

int tcflow(int fd, int action) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __fd *f = get_console(fd);
	if (!f) return -1;
	if (action != TCOOFF && action != TCOON && action != TCIOFF && action != TCION) { errno = EINVAL; return -1; }
	return 0;   /* N/A: no serial data stream to suspend/resume, see file banner */
}

int tcsendbreak(int fd, int duration) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct __fd *f = get_console(fd);
	(void)duration;
	if (!f) return -1;
	return 0;   /* spec-permitted no-op for a terminal with no break condition, see file banner */
}

pid_t tcgetsid(int fd)
{
	struct __fd *f = get_console(fd);
	if (!f) return -1;
	/* The console is the only terminal here and the caller is the only
	 * user of it this library can name, so the session associated with
	 * it is the caller's own -- src/unistd/ids.c keeps that as real
	 * per-process state now, and this follows it rather than answering
	 * a constant, exactly as src/unistd/ttyname.c's tcgetpgrp() does
	 * for the process-group equivalent. */
	return getsid(0);
}

#endif /* !__linux__ */
