/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * setusershell()/getusershell()/endusershell(): real, from-scratch
 * /etc/shells enumeration for native Linux. NT has no such file or
 * concept, so that reasoning stays NT-only; Linux has a real, simple,
 * line-oriented /etc/shells this backend can just read.
 *
 * Ordinary FILE*-based line reading, not a raw syscall: getusershell() has
 * no fd-table-shaped contract to honor and no reason to avoid this
 * library's own stdio.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define SHELL_LINE_MAX 256

static FILE *shells_fp withtok(file_stream_open);
static char shells_line[SHELL_LINE_MAX];

void setusershell(void)
{
	if (shells_fp) rewind(shells_fp);
	else shells_fp = fopen("/etc/shells", "r");
}

void endusershell(void)
{
	if (shells_fp) { (void)fclose(shells_fp); shells_fp = 0; }
}

/* getusershell.html: "shall return successive lines" -- comment lines
 * (leading '#') and blank lines are conventionally skipped by every
 * real /etc/shells reader (glibc, musl, *BSD); nothing on the page
 * requires it, but a "shell path" that is empty or starts with '#' is
 * not a real answer either implementation would want a caller to see. */
char *getusershell(void)
{
	size_t n;
	if (!shells_fp) setusershell();
	if (!shells_fp) return 0;
	for (;;) {
		if (!fgets(shells_line, sizeof shells_line, shells_fp)) return 0;
		n = strlen(shells_line);
		while (n && (shells_line[n - 1] == '\n' || shells_line[n - 1] == '\r')) shells_line[--n] = 0;
		if (n == 0 || shells_line[0] == '#') continue;
		return shells_line;
	}
}

// NOLINTEND(misc-include-cleaner)
