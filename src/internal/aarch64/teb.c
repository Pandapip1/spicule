/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * aarch64's counterpart to src/internal/{x86_64,i386}/teb.c: those read
 * the current TEB out of the segment base NT points GS (x86_64)/FS
 * (i386) at; ARM64 Windows has no segment registers at all, so the
 * loader/OS instead reserves a general-purpose register for exactly
 * this -- x18, the "platform register" in Microsoft's own ARM64
 * addendum to AAPCS64 (Arm64ECABI/the win32 ABI docs both call it out
 * by name: "reserved for OS use... points to the TEB on Windows").
 * That is a real, documented Windows-specific reservation, not a base
 * AAPCS64 rule: plain AAPCS64 (what Linux/aarch64 uses) leaves x18
 * as an ordinary temporary register, so this file's asm is only
 * semantically meaningful under PLATFORM=nt. It still compiles cleanly
 * under the Linux/aarch64 build too (this file lives under the
 * arch-keyed, not platform-keyed, src/internal/aarch64/ -- see the
 * Makefile's ARCH_GLOBS comment -- so both platforms build it): the
 * instruction itself is valid AArch64 on either OS, __teb() is simply
 * never called from Linux code (nothing under any module's linux/
 * backend references it), so an unused symbol reading x18 there is
 * harmless dead code, not a correctness issue.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)

#include "libc.h"
PTEB __teb(void)
{
	PTEB t;
	__asm__ __volatile__("mov %0, x18" : "=r"(t));
	return t;
}

// NOLINTEND(misc-include-cleaner)
