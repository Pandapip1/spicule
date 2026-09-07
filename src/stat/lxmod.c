/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The WSL mode stored on NTFS as the $LXMOD extended attribute.
 *
 * Microsoft documents $LXMOD as the file-mode member of WSL's NTFS
 * metadata, and Linux ntfs3 stores it as one little-endian 32-bit word.
 * Deliberately do not create $LXUID or $LXGID here: those are literal IDs
 * in a Linux distribution's user namespace, while spicule's getuid() is a
 * Windows-SID-derived process identity and is not a WSL UID mapping.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include "libc.h"
#include "ownership_stubs.h"

#define LXMOD_NAME "$LXMOD"
#define LXMOD_NAME_LEN 6u
#define LXMOD_VALUE_LEN 4u
#define LXMOD_EA_LEN (8u + LXMOD_NAME_LEN + 1u + LXMOD_VALUE_LEN)

static void putle32(unsigned char *p, unsigned v)
{
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
	p[2] = (unsigned char)(v >> 16);
	p[3] = (unsigned char)(v >> 24);
}

/* Builds the raw $LXMOD extended-attribute buffer NtCreateFile's EA
 * parameter and __plat_lxmod_set() (src/stat/nt/plat_stat.c) both need. */
unsigned __lxmod_create_buffer(
    void *buffer withtok(writable_span(19)), unsigned mode)
{
	unsigned char *b = buffer;
	__NT_FILE_FULL_EA_INFORMATION *ea = (__NT_FILE_FULL_EA_INFORMATION *)b;
	__ownership_writable_span(b, LXMOD_EA_LEN);
	memset(b, 0, LXMOD_EA_LEN);
	ea->EaNameLength = LXMOD_NAME_LEN;
	ea->EaValueLength = LXMOD_VALUE_LEN;
	__ownership_writable_span(ea->EaName, LXMOD_NAME_LEN + 1);
	memcpy(ea->EaName, LXMOD_NAME, LXMOD_NAME_LEN + 1);
	putle32((unsigned char *)ea->EaName + LXMOD_NAME_LEN + 1, mode);
	return LXMOD_EA_LEN;
}

// NOLINTEND(misc-include-cleaner)
