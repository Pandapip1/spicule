/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The `\Device\ConDrv` wire protocol: the one ioctl a console client
 * issues, the request structure it carries, and the three console API
 * messages this library needs, driven directly through
 * NtDeviceIoControlFile the same way src/internal/afd.h drives AFD.
 *
 * A console client does not talk to conhost.  It sends
 * IOCTL_CONDRV_ISSUE_USER_IO to the console driver on the handle in
 * PEB->ProcessParameters->ConsoleHandle -- the session's
 * `\Device\ConDrv\Connect` handle, not any of the standard handles --
 * naming the console object it
 * means (a standard-handle-shaped `Client`) and handing the driver two
 * lists of user-mode buffers.  The driver relays them to whichever
 * server is hosting the session.
 *
 * Microsoft does not document this.  It is cross-checked against three
 * sources that agree on it:
 *
 *   - Microsoft's own conhost, open-sourced as microsoft/terminal: the
 *     driver/server-shared headers dep/Console/condrv.h (CONSOLE_IO_*
 *     function codes, CD_IO_BUFFER, CD_USER_DEFINED_IO, and the
 *     IOCTL_CONDRV_* CTL_CODE definitions) and dep/Console/conmsgl1.h
 *     and conmsgl2.h (CONSOLE_MSG_HEADER, CONSOLE_MODE_MSG,
 *     CONSOLE_SCREENBUFFERINFO_MSG, and the CONSOLE_API_NUMBER_L1/L2
 *     enums whose ordinals the API numbers below are).  This is the
 *     primary source: real, compilable, currently-shipping code, and
 *     the half of the protocol Microsoft actually publishes.  It does
 *     not, however, contain a client -- nothing in that repository ever
 *     uses CD_USER_DEFINED_IO -- so the layout of the two buffer lists
 *     is pinned by src/server/ApiSorter.cpp instead, which is where the
 *     server states its own view of them:
 *
 *         Message->Complete.Write.Data  = &Message->u;
 *         Message->Complete.Write.Size  = ApiDescriptorSize;
 *         Message->State.WriteOffset    = ApiDescriptorSize;
 *         Message->State.ReadOffset     = ApiDescriptorSize + sizeof(CONSOLE_MSG_HEADER);
 *
 *     i.e. the input list begins with the header followed by the API
 *     descriptor, and the output list begins with the API descriptor
 *     alone; any further payload follows at those offsets.  Its
 *     argument validation (`ApiDescriptorSize > InputSize -
 *     sizeof(CONSOLE_MSG_HEADER)`) says the same thing a second way.
 *   - Yori's lib/condrv.c (malxau/yori, MIT), a working client: it
 *     calls SetConsoleDisplayMode by hand for exactly the reason this
 *     file exists, and independently states the three facts the server
 *     source cannot -- that the ioctl goes to
 *     PEB->ProcessParameters->ConsoleHandle ("this is not the same as
 *     the condrv handle (which is where this IOCTL is sent)"), that
 *     `Client` is the console object handle, and that InputCount ==
 *     OutputCount == 1 with the input buffer covering header+descriptor
 *     and the output buffer covering the descriptor alone.  It also
 *     spells out the 64-bit padding in CD_IO_BUFFER that natural C
 *     alignment already produces here.
 *   - PSBits' Misc/AliasWithIoctl.c (gtworek/PSBits), a second,
 *     independent working client, and the closer of the two to this
 *     one: it calls NtDeviceIoControlFile directly rather than
 *     DeviceIoControl, reads the same PEB field, uses the same
 *     Buffers[0] = {header, sizeof(CONSOLE_MSG_HEADER) + descriptor}
 *     shape with three further input buffers after it, and hardcodes
 *     the ioctl as the bare number 0x500016 -- which is what the
 *     CTL_CODE arithmetic below evaluates to, confirming it a third
 *     way, the way test/networking-audit.md confirmed AFD's codes
 *     against Wine's numbers.
 *
 * Two further reverse-engineering lineages, neither working from
 * Microsoft's headers, recovered the same layout blind and agree:
 * dlunch/NewConsole (a conhost replacement) names the fields
 * `requestHandle/data1..4/requestDataPtr` and dispatches on
 * `requestCode` 0x1000001 GetConsoleMode / 0x1000002 SetConsoleMode /
 * 0x2000007 GetConsoleScreenBufferInfo, and mrexodia/dumpulator parses
 * the x64 request as handle(8), two counts(4+4), then {size(4), pad(4),
 * pointer(8)} pairs -- which is exactly the padding the layout
 * assertions below check for.  fortra/No-Consolation's source/console.c
 * is a separate lineage again, pairing ApiNumber 0x1000001 and
 * 0x1000002 with descriptor size 4, i.e. confirming both the numbers
 * and sizeof(CONSOLE_MODE_MSG) without reference to conmsgl1.h at all.
 *
 * Wine is deliberately not cited for any of this, unlike in afd.h:
 * Wine's `\Device\ConDrv` (include/wine/condrv.h) borrows the name and
 * nothing else -- one flat METHOD_BUFFERED ioctl per console API, no
 * ISSUE_USER_IO, no message header, and an ioctl-value set with an
 * empty intersection with Microsoft's.  It is a different protocol, so
 * agreement with it would have measured nothing.
 *
 * The API-number derivation is confirmed the same way.  Both clients
 * hardcode an L3 number computed from the conmsgl3.h enum's ordinal --
 * Yori's `((3<<24) | 13)` is ConsolepSetDisplayMode, the 14th entry,
 * and PSBits' 50331666 is 0x03000012, ConsolepAddAlias, the 19th --
 * so `(layer << 24) | index-within-layer` is the rule, and the numbers
 * below are read off conmsgl1.h and conmsgl2.h with it.
 *
 * Version floor: none of this exists before the console driver did.
 * Yori refuses to try below 6.3 because "the current condrv
 * architecture was in flux until Windows 8.1"; this library does not
 * need a version test, because __handle_type() (src/internal/nt/
 * plat_fd_init.c) only ever answers __FD_CONSOLE for a handle whose
 * FILE_FS_DEVICE_INFORMATION says FILE_DEVICE_CONSOLE, which a
 * pre-driver CSRSS console pseudo-handle cannot, and every caller here
 * is behind that check.  A failed ioctl is reported to the caller
 * rather than translated to errno, so an older or foreign console --
 * Wine's, whose driver is a separate design with its own incompatible
 * ioctl codes and does not answer this one -- falls back cleanly.
 */
#ifndef _NTLIBC_CONDRV_H
#define _NTLIBC_CONDRV_H

#include "nt.h"

/* condrv.h: CTL_CODE(FILE_DEVICE_CONSOLE, 5, METHOD_OUT_DIRECT,
 * FILE_ANY_ACCESS).  FILE_DEVICE_CONSOLE is 0x50 (nt.h) and
 * METHOD_OUT_DIRECT is 2, so this is 0x500016. */
#define CONDRV_METHOD_OUT_DIRECT 2u
#define IOCTL_CONDRV_ISSUE_USER_IO \
	(((ULONG)FILE_DEVICE_CONSOLE << 16) | (5u << 2) | CONDRV_METHOD_OUT_DIRECT)

/* CONSOLE_FIRST_API_NUMBER(Layer) is (Layer << 24) and each layer's
 * enum counts up from there; see this file's banner for how the two
 * independent clients confirm the rule. */
#define CONSOLE_API_NUMBER(layer, index) (((ULONG)(layer) << 24) | (ULONG)(index))

#define ConsolepGetMode             CONSOLE_API_NUMBER(1, 1)
#define ConsolepSetMode             CONSOLE_API_NUMBER(1, 2)
#define ConsolepFlushInputBuffer    CONSOLE_API_NUMBER(2, 3)
#define ConsolepGetScreenBufferInfo CONSOLE_API_NUMBER(2, 7)

/* Console input mode bits, as carried in CONSOLE_MODE_MSG::Mode.  These
 * are the same values SetConsoleMode() documents
 * (https://learn.microsoft.com/en-us/windows/console/setconsolemode,
 * input-mode table); src/termios/termios.c backs c_lflag's
 * ISIG/ICANON/ECHO with them over either transport. */
#define ENABLE_PROCESSED_INPUT 0x0001
#define ENABLE_LINE_INPUT      0x0002
#define ENABLE_ECHO_INPUT      0x0004

typedef struct _CD_IO_BUFFER {
	ULONG Size;
	PVOID Buffer;
} CD_IO_BUFFER;

/* condrv.h declares Buffers[ANYSIZE_ARRAY]; two is all this library
 * ever sends (one input list entry, one output list entry), and a fixed
 * bound keeps the request on the stack. */
typedef struct _CD_USER_DEFINED_IO {
	HANDLE Client;
	ULONG InputCount;
	ULONG OutputCount;
	CD_IO_BUFFER Buffers[2];
} CD_USER_DEFINED_IO;

typedef struct _CONSOLE_MSG_HEADER {
	ULONG ApiNumber;
	ULONG ApiDescriptorSize;
} CONSOLE_MSG_HEADER;

typedef struct _CONSOLE_MODE_MSG {
	ULONG Mode;
} CONSOLE_MODE_MSG;

/* conmsgl2.h's CONSOLE_SCREENBUFFERINFO_MSG, with its COORD pairs
 * written out as the X,Y short pairs they are: COORD itself lives in
 * kernel32.h, which only exists behind NTLIBC_USE_KERNEL32, and this
 * message has to be reachable without it.  Every field is IN OUT there;
 * only the window size is read here.
 *
 * ScrollPosition and CurrentWindowSize are what Win32 presents as
 * CONSOLE_SCREEN_BUFFER_INFO::srWindow, and CurrentWindowSize is a
 * count of columns and rows, not a right/bottom edge -- the one field
 * here it would be easy to get off by one, so it is sourced twice.
 * conhost fills it from an *exclusive* rect (src/host/getset.cpp does
 * `srWindow.right += 1` on its own inclusive one, saying in as many
 * words that "callers of this function expect to receive an exclusive
 * rect", and src/server/ApiDispatchers.cpp then stores `srWindow.Right
 * - srWindow.Left`), so the value is the width.  ReactOS's own
 * clean-room client of the older CSRSS-era protocol, whose message
 * carries the same pair under the names ViewOrigin and ViewSize,
 * reconstructs the Win32 rect as `srWindow.Right = ViewOrigin.X +
 * ViewSize.X - 1` (dll/win32/kernel32/client/console/console.c) --
 * which says the same thing from the other side. So TIOCGWINSZ's
 * (Right - Left + 1) is CurrentWindowSize as it stands. */
typedef struct _CONSOLE_SCREENBUFFERINFO_MSG {
	short SizeX, SizeY;
	short CursorPositionX, CursorPositionY;
	short ScrollPositionX, ScrollPositionY;
	USHORT Attributes;
	short CurrentWindowSizeX, CurrentWindowSizeY;
	short MaximumWindowSizeX, MaximumWindowSizeY;
	USHORT PopupAttributes;
	BOOLEAN FullscreenSupported;
	ULONG ColorTable[16];
} CONSOLE_SCREENBUFFERINFO_MSG;

NT_LAYOUT_SIZE(CD_IO_BUFFER, 2*NT_PTR);
NT_LAYOUT_OFFSET(CD_USER_DEFINED_IO, Buffers, NT_PTR + 8);
NT_LAYOUT_SIZE(CONSOLE_MSG_HEADER, 8);
NT_LAYOUT_SIZE(CONSOLE_MODE_MSG, 4);
NT_LAYOUT_SIZE(CONSOLE_SCREENBUFFERINFO_MSG, 92);

/* The largest API descriptor this library sends -- 92 bytes for
 * CONSOLE_SCREENBUFFERINFO_MSG, the biggest of the four. */
#define CONDRV_MAX_DESCRIPTOR 128

/* Issue one console API call on `client`, an __FD_CONSOLE handle.
 *
 * `body` is the API descriptor: `body_size` bytes copied into the
 * request and, since every descriptor here is IN OUT, copied back out
 * over the same object on success.  The header the driver needs around
 * it is built here, so a caller never has to get that adjacency right.
 *
 * Returns 0 on success and -1 on any failure, without touching errno --
 * "this console did not answer" is a fallback decision for the caller,
 * not an error to report to the application. */
int __condrv_call(HANDLE client, ULONG api, void *body, ULONG body_size);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
