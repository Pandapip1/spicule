/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

#include "test-policy.h"

/* POSIX specifies <stropts.h> as ioctl()'s header. Keep this in its own
 * translation unit: including the missing header is the test, so UNIMPL is
 * correct only while compilation fails. Pedantic catches the day it appears. */
#if SPICULE_TEST(UNIMPL, posix_stropts_stropts_header_exists)
#include <stropts.h>
#endif

int main(void)
{
	return 0;
}
