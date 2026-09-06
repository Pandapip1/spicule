/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * tabs(1p): `tabs [-n] [-T type]` and `tabs [-T type] n[[sep[+]n]...]`
 * -- sets a terminal's hardware tab stops by writing the right escape
 * sequence to standard output.
 *
 * SCOPE.  tabs(1p) is fundamentally a termcap/terminfo-database lookup:
 * `-T type` selects a terminal type whose database entry defines the
 * escape sequence to use. This tree has no termcap/terminfo database
 * (see src/termios/, which is I/O *mode* control -- raw/cooked, echo,
 * baud -- not terminal *capability* escape sequences), so `-T type` is
 * refused rather than silently guessing a database entry that isn't
 * there.
 *
 * What IS implemented: `tabs -N` (uniform interval of N columns), or
 * bare `tabs` with no operands (tabs(1p) defines this as "equivalent to
 * tabs -8") -- the one case needing no database, since the sequence is
 * the same ANSI X3.64/VT100 convention every real terminal emulator
 * implements:
 *
 *   1. TBC (Tabulation Clear), Ps=3: "\033[3g" -- clear every existing
 *      hardware tab stop, so old stops don't linger.
 *   2. <CR> to return to column 1.
 *   3. For each stop position (N, 2N, 3N, ... up to MAX_COLUMN below):
 *      emit enough <space> characters to reach that column, then HTS
 *      (Horizontal Tab Set), "\033H" -- set a stop at the cursor.
 *   4. <CR> again, to leave the cursor at column 1 rather than wherever
 *      the last stop landed.
 *
 * MAX_COLUMN is a fixed, generous bound (not read from the real
 * terminal's width, which this build has no portable way to query) --
 * see this file's own comment at its definition.
 *
 * `-a`/`-c`/`-c2`/`-c3`/`-f`/`-p`/`-s`/`-u` (named presets for specific
 * historical languages/editors) and the explicit tab-stop-list form
 * (`tabs 1,10 +8` etc.) are real tabs(1p) but not implemented: refused
 * loudly rather than guessing a plausible-looking but wrong column
 * list.
 *
 * EXIT STATUS: "0 Successful completion." ">0 An error occurred."
 */
#include <stdio.h>
#include <string.h>
#include "util.h"

/* No way to query the attached terminal's actual width (see this
 * file's header) -- 132 columns is the widest standard terminal
 * geometry (VT100's own 80/132-column modes), so tab stops are set out
 * this far regardless; a real terminal simply ignores an HTS sent past
 * its own last column. */
#define MAX_COLUMN 132

static int emit_uniform_tabs(int n)
{
	int col;

	if (fputs("\033[3g", stdout) < 0 || fputc('\r', stdout) == EOF) return -1;
	for (col = 0; col < MAX_COLUMN / n; col++) {
		int i;
		for (i = 0; i < n; i++) if (fputc(' ', stdout) == EOF) return -1;
		if (fputs("\033H", stdout) < 0) return -1; /* HTS: set a stop at the cursor's column */
	}
	if (fputc('\r', stdout) == EOF) return -1;
	return fflush(stdout) == 0 ? 0 : -1;
}

int __util_tabs_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i;
	int interval = 8; /* tabs(1p): no operands "shall be equivalent to tabs -8" */

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (a[0] == '-' && a[1] >= '0' && a[1] <= '9' && a[2] == 0) {
			interval = a[1] - '0';
			if (interval == 0) {
				__util_diagf("tabs: -0: clearing tab stops without setting new "
				                "ones is not implemented\n");
				return 1;
			}
			continue;
		}
		if (!strcmp(a, "-T")) {
			__util_diagf("tabs: -T: terminal-type database lookups are not "
			                "supported by this build -- see src/util/tabs.c\n");
			return 1;
		}
		if (a[0] == '-' && a[1] != 0) {
			__util_diagf("tabs: %s: not implemented -- this build only supports "
			                "the uniform-interval form (`tabs` or `tabs -N`); see "
			                "src/util/tabs.c\n", a);
			return 1;
		}
		__util_diagf("tabs: %s: the explicit tab-stop-list form is not "
		                "implemented -- see src/util/tabs.c\n", a);
		return 1;
	}

	return emit_uniform_tabs(interval) == 0 ? 0 : 1;
}
