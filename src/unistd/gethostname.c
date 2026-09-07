/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "plat_unistd.h"
#include "ownership_stubs.h"

int gethostname(char *name withtok(writable_span(len)), size_t len)
{
	/* NT's COMPUTERNAME or Linux's real uname(2) nodename, via
	 * __plat_hostname(); the two must agree with uname()'s own nodename.
	 * 256 matches struct utsname's field width (include/sys/utsname.h). */
	char h[256];
	size_t n;
	__plat_hostname(h, sizeof h);
	/* __plat_hostname() always NUL-terminates h (see its own contract in
	 * plat_unistd.h); the checker can't see across the backend call. */
	unsafe_assume_string_terminated(h);
	n = strlen(h);
	if (n >= len) {
		if (len) memmove(name, h, len);
		return 0;
	}
	if (snprintf(name, len, "%s", h) != (int)n) return -1;
	return 0;
}

// NOLINTEND(misc-include-cleaner)
