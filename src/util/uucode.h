/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The uuencoding character-mapping logic shared by src/util/uuencode.c
 * and src/util/uudecode.c -- same "one piece of logic, two callers"
 * shape as src/util/modeparse.h's relationship to mkdir_util.c/
 * mkfifo.c/chmod_util.c.
 *
 * The classic (non-Base64) uuencoding scheme maps each 6-bit value
 * 0..63 to a printable character by adding 0x20 (space) -- except that
 * a 6-bit value of 0 maps to '`' (backtick, 0x60) rather than to a
 * literal space, so a line of all-zero data (or a zero-length final
 * line) never ends in trailing whitespace that a mail transport or
 * editor might strip.  Both directions of that one exception are here:
 * UUENC() for encoding, UUDEC() for decoding.  Every real uuencoded
 * stream in the wild (BSD, GNU sharutils, this one) uses this exact
 * mapping.
 */
#ifndef _SPICULE_UTIL_UUCODE_H
#define _SPICULE_UTIL_UUCODE_H

/* 0..63 -> the printable character uuencode(1p) writes for it. */
#define UUENC(c) ((c) ? (char)(((c) & 0x3f) + ' ') : '`')

/* The printable character -> 0..63, the inverse of UUENC(). Callers must
 * validate the input character is in ['\x20','\x60'] first (see
 * uu_valid_char() below) -- this macro does not range-check. */
#define UUDEC(ch) ((((ch) - ' ') & 0x3f))

/* Is `ch` a character UUDEC() can legitimately decode -- i.e. is it one
 * UUENC() could actually have produced?  Anything outside ' '..'`'
 * (0x20..0x60) is not: a genuinely uuencoded stream never contains one,
 * so this is exactly the check that turns a truncated/corrupted input
 * into a diagnosed error instead of UUDEC() silently wrapping garbage
 * into some in-range-looking byte value. */
static inline int uu_valid_char(char ch)
{
	return ch >= ' ' && ch <= '`';
}

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
