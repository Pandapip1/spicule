/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Declarations for the handful of kernel32 (and csrss-via-kernel32) APIs
 * that have no ntdll equivalent at all.  Kept out of nt.h on purpose: nt.h
 * is the ntdll-only surface this library is built on, and every symbol
 * declared here is only ever used inside an `#ifdef NTLIBC_USE_KERNEL32`
 * block (see CONTRIBUTING.md).  A file that only ever gets included from
 * behind that guard makes "does this build depend on kernel32" a single
 * grep away, instead of a needle hidden in nt.h.
 *
 * Only ever include this from within an NTLIBC_USE_KERNEL32 guard.
 */
#ifndef _NTLIBC_KERNEL32_H
#define _NTLIBC_KERNEL32_H

#include "nt.h"

typedef int BOOL;
typedef unsigned long DWORD;

/* Console control handler routine, as registered with
 * SetConsoleCtrlHandler().  kernel32 calls it on a separate thread that
 * it creates for the purpose -- not the thread that called
 * SetConsoleCtrlHandler(), and not the process's main thread.  Returning
 * TRUE tells kernel32 the event was handled and stops it from passing
 * the event down the chain to the next-registered handler / the default
 * handler; returning FALSE lets it fall through. */
typedef BOOL (NTAPI *PHANDLER_ROUTINE)(DWORD CtrlType);

#define CTRL_C_EVENT        0
#define CTRL_BREAK_EVENT    1
#define CTRL_CLOSE_EVENT    2
#define CTRL_LOGOFF_EVENT   5
#define CTRL_SHUTDOWN_EVENT 6

/* SetConsoleCtrlHandler() itself is not declared here: it is reached at
 * runtime through LdrLoadDll()/LdrGetProcedureAddress() (see
 * src/signal/signal.c) rather than linked against kernel32's import
 * library, so no extern prototype for it is needed. */

/* The console input mode bits GetConsoleMode()/SetConsoleMode() take
 * are not declared here: they are the same values the console driver's
 * own CONSOLE_MODE_MSG carries, so src/internal/condrv.h owns them and
 * both transports share one definition. */

/* GetConsoleScreenBufferInfo() output, used by src/ioctl/ioctl.c for
 * TIOCGWINSZ.  Layout is the documented Win32 one (wincon.h); declared
 * here rather than pulled from windows.h for the same reason as
 * everything else in this file -- see the file banner. */
typedef struct _COORD { short X, Y; } COORD;
typedef struct _SMALL_RECT { short Left, Top, Right, Bottom; } SMALL_RECT;
typedef struct _CONSOLE_SCREEN_BUFFER_INFO {
	COORD dwSize;
	COORD dwCursorPosition;
	unsigned short wAttributes;
	SMALL_RECT srWindow;
	COORD dwMaximumWindowSize;
} CONSOLE_SCREEN_BUFFER_INFO;

/* GetConsoleMode()/SetConsoleMode()/FlushConsoleInputBuffer()/
 * GetConsoleScreenBufferInfo() themselves are not declared here, same
 * reasoning as SetConsoleCtrlHandler() above: each is reached at
 * runtime through LdrLoadDll()/LdrGetProcedureAddress() by the .c file
 * that needs it. */

#endif
