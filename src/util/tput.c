/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * tput(1p): `tput [-T type] operand`
 *
 * ---- what POSIX actually mandates ----------------------------------------
 *
 * The XCU OPERANDS section is narrow: only `clear`, `init`, and `reset`
 * are required operands (each may be a no-op if the terminal doesn't
 * support it -- not an error). DESCRIPTION: with -T absent and TERM
 * unset or null, "an unspecified default terminal type shall be used";
 * this implementation's choice is "dumb" (TERM_DEFAULT below), a real
 * named type with no capabilities, rather than one that pretends to
 * know more than nothing was specified. -T takes precedence over TERM
 * when both are given.
 *
 * EXIT STATUS mapping onto the spec's five buckets: 0 success; 1 a
 * *recognised* capname the selected terminal type's entry doesn't
 * define (POSIX leaves "1" implementation-defined, and this is the same
 * "lacks this capability" use real tput makes of it); 2 a missing
 * operand, a `-T` with no argument, or a parameterized capname given
 * the wrong number of parameters; 3 `-T`/`$TERM` names a type outside
 * this file's built-in table; 4 the operand is neither
 * `clear`/`init`/`reset` nor a name in TERM_CAPNAMES below.
 *
 * ---- the capname extension beyond strict POSIX ----------------------------
 *
 * Every real-world `tput` additionally accepts a terminfo/termcap
 * capability name as the operand (`tput cols`, `tput bold`, `tput cup 5
 * 10`, ...); POSIX doesn't mandate this, but it's universal practice
 * and what this project's own task direction asked for by name.
 * Implemented as a fixed ten-name table (cols, lines, bold, smso, rmso,
 * smul, rmul, rev, sgr0, cup) rather than a general capname-lookup
 * mechanism. `clear` is shared between the POSIX operand and the
 * capname table -- same escape sequence, one field. Long (terminfo)
 * names only; two-letter termcap aliases are not added, to keep one
 * name per capability.
 *
 * ---- why a built-in table, not a real terminfo database reader -----------
 *
 * This dev host has a real terminfo database (NixOS's
 * /run/current-system/sw/share/terminfo), but that's an artifact of
 * this machine, not something a shipped binary could rely on: Windows
 * NT has no terminal database at all, and this project's native-Linux
 * target is a from-scratch bootstrap environment (see boot/kaem/)
 * that cannot assume ncurses-data/terminfo is installed either. So the
 * table is fixed: five terminal types (xterm, xterm-256color, vt100,
 * ansi, dumb) with capability strings hand-copied from `infocmp`
 * against the real system database, minus `$<N>` padding/delay
 * notations (e.g. vt100's `bold=\E[1m$<2>`) -- that syntax exists for
 * hardware terminals with real transmission timing constraints neither
 * an NT console nor a modern pty has, so every modern terminfo/termcap
 * library treats it as a no-op too. An unrecognised `-T`/`$TERM` fails
 * cleanly (exit 3) rather than fabricating capabilities.
 *
 * `cols`/`lines` try one real, live answer first -- ioctl(1, TIOCGWINSZ)
 * (src/ioctl/ioctl.c) -- before falling back to the table's static
 * value. No COLUMNS/LINES env override is implemented: that's a
 * separate layer real implementations add on top, not a substitute, and
 * this project's bootstrap use case doesn't need it yet.
 *
 * `cup`'s row/col parameters are taken 0-based (curses' own
 * convention), then written out incremented by one, matching the real
 * `%i%p1%d;%p2%dH` terminfo string every terminal in this table has
 * (`%i` increments both parameters; ANSI CUP is 1-based). No general
 * terminfo parameter-string interpreter is implemented -- cup is the
 * only parameterized capability this table carries and all entries
 * share the identical CSI-row;col-H shape, so it's hand-written once
 * (print_cup() below).
 *
 * `init`/`reset` succeed (exit 0) and write nothing for every covered
 * terminal -- this table defines no is1/is2/is3/rs1/rs2/rs3-equivalent
 * sequence, matching the real terminfo entries, and the spec allows
 * this. `longname` is not implemented: real historical tput practice,
 * not a POSIX operand, and this table has no long-description field
 * for it.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "util.h"

/* This implementation's own "unspecified default" (this file's header
 * comment, DESCRIPTION quote) when -T is absent and $TERM is unset or
 * null. */
#define TERM_DEFAULT "dumb"

struct term_entry {
	const char *name;
	int cols;    /* -1: capability not defined for this terminal */
	int lines;   /* -1: capability not defined for this terminal */
	const char *bold, *smso, *rmso, *smul, *rmul, *rev, *sgr0, *clear;
	int has_cup; /* cursor addressing (cup): all covered terminals but
	              * "dumb" share the identical \E[%i%p1%d;%p2%dH shape,
	              * so only whether it exists needs recording. */
};

/* Capability strings below are the real escape sequences these five
 * terminal types actually use (verified against `infocmp` reading this
 * dev host's own system terminfo database -- see this file's header
 * comment for exactly what was, and was not, carried over). */
static const struct term_entry term_table[] = {
	{ "xterm",          80, 24, "\033[1m", "\033[7m", "\033[27m", "\033[4m", "\033[24m", "\033[7m", "\033(B\033[m", "\033[H\033[2J", 1 },
	{ "xterm-256color", 80, 24, "\033[1m", "\033[7m", "\033[27m", "\033[4m", "\033[24m", "\033[7m", "\033(B\033[m", "\033[H\033[2J", 1 },
	{ "vt100",          80, 24, "\033[1m", "\033[7m", "\033[m",   "\033[4m", "\033[m",   "\033[7m", "\033[m\017",  "\033[H\033[J",  1 },
	{ "ansi",           80, 24, "\033[1m", "\033[7m", "\033[m",   "\033[4m", "\033[m",   "\033[7m", "\033[0;10m", "\033[H\033[J",  1 },
	{ "dumb",           80, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};
#define TERM_TABLE_N (sizeof term_table / sizeof term_table[0])

static const struct term_entry *lookup_term(const char *name)
{
	size_t i;
	for (i = 0; i < TERM_TABLE_N; i++)
		if (strcmp(term_table[i].name, name) == 0) return &term_table[i];
	return 0;
}

/* Live terminal size via TIOCGWINSZ (src/ioctl/ioctl.c), falling back
 * to the table's static value on any failure (not a tty, no console,
 * wrong platform) -- see this file's header comment for the real
 * "ask the terminal, then the database" ordering this follows. */
static int live_dimension(int want_cols)
{
	struct winsize ws;
	if (!isatty(1)) return -1;
	if (ioctl(1, TIOCGWINSZ, &ws) < 0) return -1;
	return want_cols ? (int)ws.ws_col : (int)ws.ws_row;
}

static int print_numeric(int table_value, int want_cols)
{
	int live = live_dimension(want_cols);
	int v = live >= 0 ? live : table_value;
	if (v < 0) return 1; /* not defined for this terminal: "unspecified" */
	printf("%d", v);
	return 0;
}

static int print_string(const char *s)
{
	if (!s) return 1; /* not defined for this terminal: "unspecified" */
	if (fputs(s, stdout) == EOF) return 5; /* real I/O failure: ">4 An error occurred" */
	return 0;
}

/* cup row col: 0-based on input (this file's header comment), written
 * out as the real \E[%i%p1%d;%p2%dH shape (1-based, CSI row;col H)
 * every covered non-dumb terminal actually has. */
static int print_cup(const struct term_entry *t, const char *rowarg, const char *colarg)
{
	char *end1, *end2;
	long row, col;

	/* OPEN LINT FINDING (ntlibc.ValidPointer, "*rowarg" not proven
	 * nonnull): rowarg/colarg are always argv[i+1]/argv[i+2] from this
	 * file's one call site, which checks i + 2 < argc first, so both are
	 * always live, null-terminated argv elements. Tried adding
	 * withtok(null_terminated) to this function's own parameters
	 * instead of leaving this open, but verified (tools/lint.sh
	 * ownership) that it is a net regression: the *rowarg finding stays
	 * (the fact still doesn't reach a raw `!*rowarg` in a compound
	 * condition, the same shape src/util/rmdir.c's argv[i][0] gap
	 * documents) and it adds two new findings at the call site instead
	 * (argv[i + 1]/argv[i + 2]'s offset subscript doesn't hand off the
	 * elements_withtok(null_terminated, argc) token the way a bare
	 * argv[i] read does), so left open here rather than kept. */
	if (!t->has_cup) return 1; /* not defined for this terminal */
	row = strtol(rowarg, &end1, 10);
	col = strtol(colarg, &end2, 10);
	if (*end1 || *end2 || !*rowarg || !*colarg || row < 0 || col < 0)
		return 2; /* usage error: not valid non-negative integers */
	if (printf("\033[%ld;%ldH", row + 1, col + 1) < 0) return 5;
	return 0;
}

int __util_tput_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	const char *type = 0, *op;
	const struct term_entry *t;
	int i = 1;

	if (argc >= 3 && strcmp(argv[1], "-T") == 0) {
		type = argv[2];
		i = 3;
	} else if (argc >= 2 && strncmp(argv[1], "-T", 2) == 0 && argv[1][2]) {
		type = argv[1] + 2;
		i = 2;
	} else if (argc >= 2 && strcmp(argv[1], "-T") == 0) {
		__util_diagf("tput: -T: option requires an argument\n");
		return 2;
	}

	if (!type) {
		type = getenv("TERM");
		if (!type || !*type) type = TERM_DEFAULT;
	}

	if (i >= argc) {
		__util_diagf("tput: missing operand\n");
		return 2;
	}
	op = argv[i];

	t = lookup_term(type);
	if (!t) {
		__util_diagf("tput: %s: unknown terminal type\n", type);
		return 3;
	}

	if (strcmp(op, "clear") == 0) return print_string(t->clear);
	if (strcmp(op, "init") == 0 || strcmp(op, "reset") == 0) return 0;
	if (strcmp(op, "cols") == 0) return print_numeric(t->cols, 1);
	if (strcmp(op, "lines") == 0) return print_numeric(t->lines, 0);
	if (strcmp(op, "bold") == 0) return print_string(t->bold);
	if (strcmp(op, "smso") == 0) return print_string(t->smso);
	if (strcmp(op, "rmso") == 0) return print_string(t->rmso);
	if (strcmp(op, "smul") == 0) return print_string(t->smul);
	if (strcmp(op, "rmul") == 0) return print_string(t->rmul);
	if (strcmp(op, "rev") == 0) return print_string(t->rev);
	if (strcmp(op, "sgr0") == 0) return print_string(t->sgr0);
	if (strcmp(op, "cup") == 0) {
		if (i + 2 >= argc) {
			__util_diagf("tput: cup: requires row and column operands\n");
			return 2;
		}
		return print_cup(t, argv[i + 1], argv[i + 2]);
	}

	__util_diagf("tput: %s: invalid operand\n", op);
	return 4;
}

// NOLINTEND(misc-include-cleaner)
