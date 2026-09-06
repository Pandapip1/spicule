/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * tabs(1p): `tabs [-n] [-T type]` and `tabs [-T type] n[[sep[+]n]...]`
 * -- sets a terminal's hardware tab stops by writing the right escape
 * sequence to standard output.
 *
 * SCOPE.  tabs(1p) is fundamentally a termcap/terminfo-database lookup:
 * `-T type` selects a terminal type, and the standard's own escape
 * sequence is *whatever that terminal type's database entry says* --
 * "the appropriate sequence to clear and set the tab stops may be
 * written to standard output in an unspecified format" (od(1p)'s
 * sibling page, quoted here because tabs(1p) says the same thing about
 * its own output).  This tree has no termcap/terminfo database (see
 * src/termios/, which is I/O *mode* control -- raw/cooked, echo, baud --
 * not terminal *capability* escape sequences), so `-T type` cannot be
 * honored for any type this build doesn't hard-code, and is refused
 * loudly rather than silently guessing a database entry that isn't
 * there.
 *
 * What IS implemented: the one case that needs no database at all
 * because the sequence is the same widely-implemented ANSI X3.64/VT100
 * convention on effectively every real terminal emulator (xterm,
 * gnome-terminal, Windows Terminal, ...) -- `tabs -N`, a uniform
 * interval of N column positions, or bare `tabs` with no operands at
 * all, which tabs(1p) itself defines as "equivalent to tabs -8":
 *
 *   1. TBC (Tabulation Clear), Ps=3: "\033[3g" -- clear every existing
 *      hardware tab stop, so old stops from a previous `tabs` call (or
 *      the terminal's own power-on default) don't linger.
 *   2. <CR> to return to column 1.
 *   3. For each stop position (N, 2N, 3N, ... up to MAX_COLUMN below):
 *      emit enough <space> characters to advance the cursor to that
 *      column, then HTS (Horizontal Tab Set), "\033H" -- set a stop at
 *      the cursor's current column.
 *   4. <CR> again, to leave the cursor back at column 1 rather than
 *      wherever the last stop landed -- matching every real
 *      implementation of this exact technique.
 *
 * MAX_COLUMN is a fixed, generous bound (not read from the real
 * terminal's width, which this build has no portable way to query) --
 * see this file's own comment at its definition.
 *
 * `-a`/`-c`/`-c2`/`-c3`/`-f`/`-p`/`-s`/`-u` (tabs(1p)'s named presets for
 * specific historical languages/editors) and the explicit tab-stop-list
 * form (`tabs 1,10 +8` etc.) are real tabs(1p) but not implemented:
 * refused loudly rather than guessing a plausible-looking but wrong
 * column list.
 *
 * EXIT STATUS: "0 Successful completion." ">0 An error occurred."
 */
#include <stdio.h>
#include <string.h>
#include "util.h"

/* No real way to query the attached terminal's actual width from this
 * build (see this file's header) -- 132 columns is the widest standard
 * terminal geometry (VT100's own 80/132-column modes), comfortably past
 * the common 80, so tab stops are set out to it regardless of the
 * terminal's real width; a real terminal simply ignores an HTS sent
 * past its own last column. */
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
