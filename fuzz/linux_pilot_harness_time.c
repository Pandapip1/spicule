/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Test-harness scaffolding for the Linux platform pilot's time
 * extension -- NOT part of spicule, exactly like
 * fuzz/linux_pilot_harness.c (the mman/unistd pilot's own harness,
 * which this file is the sibling of) and fuzz/ntstubs.c before it.
 *
 * Unlike the mman/unistd pilot, the time front doors this build links
 * (src/time/{time,clock,stime,timespec_get,clock_gettime}.c plus
 * src/time/linux/plat_time.c) call nothing outside src/internal/libc.h's
 * static-inline helpers, src/internal/plat_time.h, and
 * src/internal/errno.c's __errno_location() -- no fd table, no signal
 * queue, no other subsystem's __plat_* interface. This file exists to
 * satisfy tools/linux-build-time.sh's naming convention and as the
 * documented place a stub would go if a future addition to this test
 * needs one, not because anything here is load-bearing today.
 */
