/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * stty(1p): "set or report on terminal I/O characteristics for the
 * device that is its standard input" (stty.html DESCRIPTION -- always
 * fd 0, never an operand of its own, matching the spec's own RATIONALE
 * for why: "usage of standard input is required by this volume of
 * POSIX.1-2017").  Built against src/termios/termios.c's real
 * tcgetattr()/tcsetattr(), not a terminal database (that is tput's
 * job, explicitly out of scope for this project).
 *
 * SYNOPSIS (stty.html): two mutually-exclusive forms --
 *   stty [-a|-g]
 *   stty operand...
 * -- so -a/-g may never appear alongside another operand, and this
 * file rejects that combination loudly rather than picking one to
 * honor silently.
 *
 * OPERANDS implemented -- every one of stty.html's OPERANDS section,
 * grouped exactly as that page groups them (Control/Input/Output/
 * Local Modes, Special Control Character Assignments, Combination
 * Modes).  Output Modes are [XSI]-only per the spec, and in scope here
 * because this whole tree compiles -D_XOPEN_SOURCE=700 (same
 * reasoning test/posix-termios.c's own header comment gives for
 * checking OPOST/ONLCR/etc. unconditionally).  Nothing here is
 * silently dropped: an operand this file does not recognize is a
 * loud, documented, nonzero-exit refusal (parse_operand() below),
 * never a no-op -- this project's usual "an unsupported option must
 * not look like it worked" rule (src/sh/builtin.c's bi_set(),
 * src/util/touch.c's -d, src/util/dd.c's conv=).
 *
 * Every mandatory operand maps onto a bit or field include/termios.h
 * already defines and src/termios/termios.c already round-trips
 * through tcgetattr()/tcsetattr() successfully -- including the
 * fields that file's own header comment documents as "accepted and
 * stored, never applied" (c_iflag/c_oflag in full; c_cflag's
 * CSIZE/PARENB/PARODD/CSTOPB; the delay masks) or "genuinely N/A"
 * (baud rate itself, on a platform with no serial line under it).
 * That is a legitimate, spec-permitted outcome documented at length in
 * that file's banner, not a "this platform doesn't support it" case
 * this file needs a separate refusal path for: stty.html says outright
 * "It is unspecified whether stty shall report an error if an attempt
 * to set a Control Mode fails", and every other group has no such
 * disclaimer at all because tcsetattr() here never fails for any of
 * them.  There is, in short, no termios flag this platform's own
 * <termios.h> defines that this file has to reject as unsupported --
 * every failure path below is a real one (ENOTTY: stdin is not a
 * console; a malformed operand).
 *
 * NOT implemented (real, deliberate scope narrowing, not oversights):
 * every BSD/GNU-only operand include/termios.h happens to also define
 * a bit for (CRTSCTS -- crtscts/rtsdtr in real BSD stty(1) -- has no
 * stty.html operand name at all, so it is left out the same way this
 * tree leaves out every other non-mandatory long-option spelling
 * elsewhere); anything from a real BSD/GNU stty(1) man page that is
 * not also in the actual XCU stty.html OPERANDS section (checked
 * directly against the real spec text before writing this file, not
 * reconstructed from a general-purpose stty(1) man page, several of
 * which mix in dozens of non-POSIX extras -- mdmbuf, dec, litout,
 * oxtabs, kerninfo, and the like).
 *
 * DOCUMENTED, DELIBERATE READINGS OF UNDERSPECIFIED CORNERS (each
 * cited against the real spec text, not guessed):
 *
 *   - raw's defining line in stty.html literally reads "... -eol ^-
 *     \-post -inpck" (the actual published Issue 7 text, confirmed
 *     directly against pubs.opengroup.org, not a transcription slip
 *     introduced here) where every other line in that same table cell
 *     spells output-mode names in full ("opost", never "post"); this
 *     file reads "-post" as the evident "-opost" it must mean (no
 *     other termios field is named "post", and clearing output
 *     post-processing is exactly what every other raw-mode
 *     definition -- cfmakeraw() included -- also does).
 *   - "-raw"/"cooked" has no operand-by-operand inverse spelled out
 *     the way every boolean pair above it does ("(disable)" is all
 *     stty.html says); this file's own inverse is narrow and
 *     reversible only in the two bitwise-boolean fields raw itself
 *     flips (opost, inpck) -- it does not try to restore the
 *     character size or the six control characters raw clears, since
 *     nothing recorded what they were before.
 *   - "-g"'s save/restore format is explicitly "an unspecified form"
 *     (stty.html OPTIONS) with the one hard requirement that it
 *     "shall not contain any characters that would require quoting to
 *     avoid word expansion by the shell" (STDOUT); this file's own
 *     choice is a single ':'-joined run of hex fields (iflag:oflag:
 *     cflag:lflag:cc[0..15]:ispeed:ospeed, 22 fields, exactly this
 *     process's own struct termios) -- one shell word, no quoting
 *     concerns, and (Combination Modes' "saved settings" entry) is
 *     recognized back on a subsequent invocation only when it is the
 *     *sole* operand, matching stty.html's own APPLICATION USAGE
 *     example verbatim: `stty $saveterm`, never combined with anything
 *     else.
 *   - "sane"'s reset target and "ek"'s ERASE/KILL defaults are the
 *     same "conventional POSIX defaults" src/termios/termios.c's own
 *     shadow_init() already documents and ships (cc_defaults[] below
 *     is a deliberate, cited duplicate of those same 16 values -- that
 *     table is private to termios.c's own translation unit, so there
 *     is nothing to share it from).
 *
 * Like every other __util_<name>_main(), never calls exit()/_exit():
 * it also runs in-process as the `stty` shell built-in (src/sh/
 * builtin.c's bi_stty()) -- see src/internal/util.h's own header
 * comment and src/util/dd.c's for the established reasoning.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>	/* _POSIX_VDISABLE */
#include <termios.h>
#include "util.h"
#include "ownership_stubs.h" /* __ownership_string_terminated() */

/* ---- accumulated, not-yet-applied operand state -------------------
 *
 * Every operand is folded into this single struct as the argv loop
 * walks left to right, and applied to a real struct termios only once
 * -- immediately before tcsetattr() -- rather than as an argv-ordered
 * list of actions.  Ordering still comes out right for a repeated or
 * conflicting operand ("echo -echo", "cs7 sane"): every field below is
 * either a plain last-write-wins scalar (have_csize/csize_val, each
 * cc_have[i]/cc_val[i], ...) or a set/clear bitmask pair that a later
 * mark_group() call for the same bit always overwrites in both
 * directions (see mark_group() below) -- so whichever operand is
 * parsed last always wins, the same as it would with a strict
 * apply-in-order action list, without needing one.
 */
struct pending {
	tcflag_t iflag_set, iflag_clr;
	tcflag_t oflag_set, oflag_clr;
	tcflag_t cflag_set, cflag_clr;
	tcflag_t lflag_set, lflag_clr;

	int have_csize;  tcflag_t csize_val;
	int have_crdly;  tcflag_t crdly_val;
	int have_nldly;  tcflag_t nldly_val;
	int have_tabdly; tcflag_t tabdly_val;
	int have_bsdly;  tcflag_t bsdly_val;
	int have_ffdly;  tcflag_t ffdly_val;
	int have_vtdly;  tcflag_t vtdly_val;

	int have_baud;   speed_t baud_val;
	int have_ispeed; speed_t ispeed_val;
	int have_ospeed; speed_t ospeed_val;

	int cc_have[NCCS];
	unsigned char cc_val[NCCS];
};

/* Same 16 "conventional POSIX defaults" values src/termios/termios.c's
 * shadow_init() ships, positionally by c_cc[] subscript (VINTR==0 ...
 * VEOL2==15, include/termios.h) -- see this file's own header comment
 * for why this is a deliberate, cited duplicate rather than a shared
 * table. */
static const unsigned char cc_defaults[NCCS] = {
	3, 28, 127, 21, 4, 0, 1, 17, 19, 26, 0, 18, 15, 23, 22, 0
};

enum { G_IFLAG, G_OFLAG, G_CFLAG, G_LFLAG };

struct boolflag { const char *name; int group; tcflag_t bit; int def_on; };

/* stty.html's Control/Input/Output/Local Modes groups, minus the
 * non-boolean members of each (CSIZE and the delay masks -- handled
 * separately below, since a field select is not a bit toggle).
 * Output Modes are [XSI]; in scope, see this file's own header
 * comment. def_on is termios.c's shadow_init() default for that bit,
 * used by print_flags()'s default-output "differs from defaults"
 * filter and by apply_sane() below. */
static const struct boolflag boolflags[] = {
	/* Control Modes */
	{ "parenb", G_CFLAG, PARENB, 0 },
	{ "parodd", G_CFLAG, PARODD, 0 },
	{ "hupcl",  G_CFLAG, HUPCL,  1 },
	{ "cstopb", G_CFLAG, CSTOPB, 0 },
	{ "cread",  G_CFLAG, CREAD,  1 },
	{ "clocal", G_CFLAG, CLOCAL, 0 },
	/* Input Modes */
	{ "ignbrk", G_IFLAG, IGNBRK, 0 },
	{ "brkint", G_IFLAG, BRKINT, 0 },
	{ "ignpar", G_IFLAG, IGNPAR, 0 },
	{ "parmrk", G_IFLAG, PARMRK, 0 },
	{ "inpck",  G_IFLAG, INPCK,  0 },
	{ "istrip", G_IFLAG, ISTRIP, 0 },
	{ "inlcr",  G_IFLAG, INLCR,  0 },
	{ "igncr",  G_IFLAG, IGNCR,  0 },
	{ "icrnl",  G_IFLAG, ICRNL,  1 },
	{ "ixon",   G_IFLAG, IXON,   1 },
	{ "ixany",  G_IFLAG, IXANY,  0 },
	{ "ixoff",  G_IFLAG, IXOFF,  0 },
	/* Output Modes [XSI] */
	{ "opost",  G_OFLAG, OPOST,  1 },
	{ "onlcr",  G_OFLAG, ONLCR,  1 },
	{ "ocrnl",  G_OFLAG, OCRNL,  0 },
	{ "onocr",  G_OFLAG, ONOCR,  0 },
	{ "onlret", G_OFLAG, ONLRET, 0 },
	{ "ofill",  G_OFLAG, OFILL,  0 },
	{ "ofdel",  G_OFLAG, OFDEL,  0 },
	/* Local Modes */
	{ "isig",   G_LFLAG, ISIG,   1 },
	{ "icanon", G_LFLAG, ICANON, 1 },
	{ "iexten", G_LFLAG, IEXTEN, 1 },
	{ "echo",   G_LFLAG, ECHO,   1 },
	{ "echoe",  G_LFLAG, ECHOE,  1 },
	{ "echok",  G_LFLAG, ECHOK,  1 },
	{ "echonl", G_LFLAG, ECHONL, 0 },
	{ "noflsh", G_LFLAG, NOFLSH, 0 },
	{ "tostop", G_LFLAG, TOSTOP, 0 },
};
#define NBOOLFLAGS (int)(sizeof boolflags / sizeof *boolflags)

struct delaymode { const char *name; tcflag_t mask; tcflag_t val; };

/* [XSI] Output Modes delay masks (stty.html); "tabs" is the spec's own
 * documented synonym for tab3 ("tabs (-tabs) -- Synonym for tab0
 * (tab3)"), so it shares tab3's entry here rather than needing a
 * second lookup path. -tabs (tab0) is handled as a special case in
 * parse_operand() since, uniquely among this group, it has a defined
 * '-' form. */
static const struct delaymode delaymodes[] = {
	{ "cr0", CRDLY, CR0 }, { "cr1", CRDLY, CR1 },
	{ "cr2", CRDLY, CR2 }, { "cr3", CRDLY, CR3 },
	{ "nl0", NLDLY, NL0 }, { "nl1", NLDLY, NL1 },
	{ "tab0", TABDLY, TAB0 }, { "tab1", TABDLY, TAB1 },
	{ "tab2", TABDLY, TAB2 }, { "tab3", TABDLY, TAB3 },
	{ "tabs", TABDLY, TAB3 },
	{ "bs0", BSDLY, BS0 }, { "bs1", BSDLY, BS1 },
	{ "ff0", FFDLY, FF0 }, { "ff1", FFDLY, FF1 },
	{ "vt0", VTDLY, VT0 }, { "vt1", VTDLY, VT1 },
};
#define NDELAYMODES (int)(sizeof delaymodes / sizeof *delaymodes)

struct ccname { const char *name; int idx; };

/* Special Control Character Assignments (stty.html's own table) --
 * exactly the nine POSIX names, deliberately not the five extra
 * VREPRINT/VDISCARD/VWERASE/VLNEXT/VEOL2 slots include/termios.h also
 * defines as common extensions: stty.html's own table lists only
 * these nine, so only these nine get an operand keyword. */
static const struct ccname ccnames[] = {
	{ "intr", VINTR }, { "quit", VQUIT }, { "erase", VERASE },
	{ "kill", VKILL }, { "eof", VEOF }, { "eol", VEOL },
	{ "start", VSTART }, { "stop", VSTOP }, { "susp", VSUSP },
};
#define NCCNAMES (int)(sizeof ccnames / sizeof *ccnames)

/* p is always &p in __util_stty_main's own local -- never NULL along any
 * of this file's call chains. */
__attribute__((nonnull(1)))
static void mark_group(struct pending *p, int group, tcflag_t bit, int enable)
{
	tcflag_t *setm, *clrm;
	switch (group) {
	case G_IFLAG: setm = &p->iflag_set; clrm = &p->iflag_clr; break;
	case G_OFLAG: setm = &p->oflag_set; clrm = &p->oflag_clr; break;
	case G_CFLAG: setm = &p->cflag_set; clrm = &p->cflag_clr; break;
	default:      setm = &p->lflag_set; clrm = &p->lflag_clr; break;
	}
	if (enable) { *setm |= bit; *clrm &= ~bit; }
	else        { *clrm |= bit; *setm &= ~bit; }
}

/* p is always &p in __util_stty_main's own local -- see mark_group's
 * identical note. */
__attribute__((nonnull(1)))
static void set_delay(struct pending *p, tcflag_t mask, tcflag_t val)
{
	switch (mask) {
	case CRDLY:  p->have_crdly = 1;  p->crdly_val = val;  break;
	case NLDLY:  p->have_nldly = 1;  p->nldly_val = val;  break;
	case TABDLY: p->have_tabdly = 1; p->tabdly_val = val; break;
	case BSDLY:  p->have_bsdly = 1;  p->bsdly_val = val;  break;
	case FFDLY:  p->have_ffdly = 1;  p->ffdly_val = val;  break;
	default:     p->have_vtdly = 1;  p->vtdly_val = val;  break; /* VTDLY */
	}
}

/* "sane" (Combination Modes: "Reset all modes to some reasonable,
 * unspecified, values") and "ek" (Special Control Character
 * Assignments' sibling entry: "Reset ERASE and KILL characters back to
 * system defaults") both reset to the exact same conventional values,
 * so ek's own reset is just the two-entry slice of this. Every field
 * touched is a last-write-wins scalar or set/clear pair (this file's
 * own header comment), so calling this mid-sequence and then applying
 * more operands afterward still lets those later operands win. */
static void apply_sane(struct pending *p)
{
	int i;
	for (i = 0; i < NBOOLFLAGS; i++)
		mark_group(p, boolflags[i].group, boolflags[i].bit, boolflags[i].def_on);
	p->have_csize = 1;  p->csize_val = CS8;
	p->have_crdly = 1;  p->crdly_val = CR0;
	p->have_nldly = 1;  p->nldly_val = NL0;
	p->have_tabdly = 1; p->tabdly_val = TAB0;
	p->have_bsdly = 1;  p->bsdly_val = BS0;
	p->have_ffdly = 1;  p->ffdly_val = FF0;
	p->have_vtdly = 1;  p->vtdly_val = VT0;
	for (i = 0; i < NCCS; i++) { p->cc_have[i] = 1; p->cc_val[i] = cc_defaults[i]; }
}

/* p is always &p in __util_stty_main's own local -- see mark_group's
 * identical note. */
__attribute__((nonnull(1)))
static void apply_ek(struct pending *p)
{
	p->cc_have[VERASE] = 1; p->cc_val[VERASE] = cc_defaults[VERASE];
	p->cc_have[VKILL] = 1;  p->cc_val[VKILL] = cc_defaults[VKILL];
}

/* Raw mode's defining line (stty.html, quoted and explained in this
 * file's own header comment): cs8, six control characters disabled,
 * output post-processing off, input parity checking off. */
/* p is always &p in __util_stty_main's own local -- see mark_group's
 * identical note. */
__attribute__((nonnull(1)))
static void apply_raw(struct pending *p)
{
	static const int disabled[] = { VERASE, VKILL, VINTR, VQUIT, VEOF, VEOL };
	size_t i;
	p->have_csize = 1; p->csize_val = CS8;
	for (i = 0; i < sizeof disabled / sizeof *disabled; i++) {
		p->cc_have[disabled[i]] = 1;
		p->cc_val[disabled[i]] = (unsigned char)_POSIX_VDISABLE;
	}
	mark_group(p, G_OFLAG, OPOST, 0);
	mark_group(p, G_IFLAG, INPCK, 0);
}

/* -raw/cooked's narrow, documented inverse -- see this file's own
 * header comment for why it is only these two bits. */
static void apply_cooked(struct pending *p)
{
	mark_group(p, G_OFLAG, OPOST, 1);
	mark_group(p, G_IFLAG, INPCK, 1);
}

/* "<control>-character string" (stty.html's table): a literal single
 * character, "^-"/"undef" for _POSIX_VDISABLE, or a "^c" pair from the
 * POSIX-locale circumflex table -- which is exactly the conventional
 * ASCII control-character encoding (A=SOH=1 ... Z=SUB=26, plus the six
 * punctuation specials), so this computes it rather than transcribing
 * stty.html's own three-column table by hand. Returns 1 and sets *out
 * on success, 0 on a string this file does not recognize. */
/* Both call sites pass an argv element (already null-terminated) and the
 * address of a stack local for out. */
__attribute__((nonnull(1, 2)))
static int parse_ctrl_char(const char *s withtok(null_terminated), unsigned char *out)
{
	if (!strcmp(s, "undef") || !strcmp(s, "^-")) {
		*out = (unsigned char)_POSIX_VDISABLE;
		return 1;
	}
	if (s[0] == '^' && s[1] && !s[2]) {
		unsigned char c = (unsigned char)s[1];
		if (c >= 'a' && c <= 'z') c = (unsigned char)(c - 'a' + 'A');
		if (c >= 'A' && c <= 'Z') { *out = (unsigned char)(c - 'A' + 1); return 1; }
		switch (c) {
		case '[':  *out = 27;  return 1;
		case '\\': *out = 28;  return 1;
		case ']':  *out = 29;  return 1;
		case '^':  *out = 30;  return 1;
		case '_':  *out = 31;  return 1;
		case '?':  *out = 127; return 1;
		default: return 0;
		}
	}
	if (s[0] && !s[1]) { *out = (unsigned char)s[0]; return 1; }
	return 0;
}

/* Plain decimal, fully consumed, fits in an unsigned long -- used for
 * the bare baud "number" operand, ispeed/ospeed's, and min/time's.
 * Rejects empty strings, leading '-'/'+', hex/octal forms, and any
 * trailing garbage -- stty.html's "number" is a plain decimal integer,
 * never one of those. */
static int parse_uint(const char *s withtok(null_terminated), unsigned long *out)
{
	char *end;
	/* OPEN LINT FINDING (ntlibc.ValidPointer, "s[0]" not proven
	 * nonnull): withtok(null_terminated) above establishes s at
	 * function entry, but a raw subscript directly inside this
	 * compound `if` condition is the same shape src/util/rmdir.c's
	 * argv[i][0] gap documents -- the fact does not reach a bare
	 * subscript in a condition, only a subscript in a body statement. */
	if (!s[0] || !isdigit((unsigned char)s[0])) return 0;
	*out = strtoul(s, &end, 10);
	return *end == 0;
}

/* This file's own '-g' save/restore encoding -- see this file's own
 * header comment for the format and why it was chosen. Exactly 22
 * ':'-joined hex fields (iflag, oflag, cflag, lflag, cc[0..NCCS-1],
 * ispeed, ospeed); anything else is "not a saved-settings token",
 * which parse_saved()'s only caller treats as an ordinary (and here,
 * invalid) operand rather than an error of its own. */
#define NSAVEDFIELDS (4 + NCCS + 2)

static int parse_saved(const char *s, struct termios *out)
{
	unsigned long vals[NSAVEDFIELDS];
	const char *p = s;
	char *end;
	int i;

	for (i = 0; i < NSAVEDFIELDS; i++) {
		if (!isxdigit((unsigned char)*p)) return 0;
		vals[i] = strtoul(p, &end, 16);
		if (end == p) return 0;
		p = end;
		if (i + 1 < NSAVEDFIELDS) {
			if (*p != ':') return 0;
			p++;
		}
	}
	if (*p) return 0; /* trailing garbage past the 22nd field */

	out->c_iflag = (tcflag_t)vals[0];
	out->c_oflag = (tcflag_t)vals[1];
	out->c_cflag = (tcflag_t)vals[2];
	out->c_lflag = (tcflag_t)vals[3];
	for (i = 0; i < NCCS; i++) out->c_cc[i] = (cc_t)vals[4 + i];
	out->c_ispeed = (speed_t)vals[4 + NCCS];
	out->c_ospeed = (speed_t)vals[4 + NCCS + 1];
	return 1;
}

static void print_saved(const struct termios *t)
{
	int i;
	printf("%lx:%lx:%lx:%lx", (unsigned long)t->c_iflag, (unsigned long)t->c_oflag,
		(unsigned long)t->c_cflag, (unsigned long)t->c_lflag);
	for (i = 0; i < NCCS; i++) printf(":%lx", (unsigned long)t->c_cc[i]);
	printf(":%lx:%lx\n", (unsigned long)t->c_ispeed, (unsigned long)t->c_ospeed);
}

/* stty.html STDOUT, the mandatory speed-line wording, verbatim:
 * "speed %d baud;" when input and output speed agree, otherwise
 * "ispeed %d baud; ospeed %d baud;". */
static void print_speed(const struct termios *t)
{
	if (t->c_ispeed == t->c_ospeed)
		printf("speed %u baud;\n", (unsigned int)t->c_ispeed);
	else
		printf("ispeed %u baud; ospeed %u baud;\n",
			(unsigned int)t->c_ispeed, (unsigned int)t->c_ospeed);
}

/* stty.html STDOUT's control-character wording, verbatim: "%s = %s;",
 * <name>, <value> where value is the character, a visual (caret)
 * representation, or "undef" if disabled. */
static const char *caret_repr(unsigned char v, char buf[4])
{
	if (v == (unsigned char)_POSIX_VDISABLE) return "undef";
	if (v == 127) { buf[0] = '^'; buf[1] = '?'; buf[2] = 0; return buf; }
	if (v < 32) { buf[0] = '^'; buf[1] = (char)(v + '@'); buf[2] = 0; return buf; }
	if (v < 127) { buf[0] = (char)v; buf[1] = 0; return buf; }
	snprintf(buf, 4, "\\%03o", v);
	return buf;
}

static void print_cc(const struct termios *t, int all)
{
	char buf[4];
	int i;
	for (i = 0; i < NCCNAMES; i++) {
		int idx = ccnames[i].idx;
		/* OPEN LINT FINDING (ntlibc.ValidPointer, "dereference extent is
		 * not proven sufficient"): every ccnames[].idx value is one of
		 * the VINTR..VSUSP constants, all < NCCS, so t->c_cc[idx] and
		 * cc_defaults[idx] below are always in bounds. The checker
		 * can't correlate an index loaded from one const table's field
		 * against the fixed size of an unrelated array; no existing
		 * ownership.h annotation expresses that relation (same shape as
		 * src/util/sort.c's key_start_off()/key_end_off() open findings
		 * on fields[f-1].end), so this is left open rather than papered
		 * over. */
		unsigned char v = t->c_cc[idx];
		if (!all && v == cc_defaults[idx]) continue;
		printf("%s = %s; ", ccnames[i].name, caret_repr(v, buf));
	}
	if (all || t->c_cc[VMIN] != cc_defaults[VMIN])
		printf("min = %d; ", t->c_cc[VMIN]);
	if (all || t->c_cc[VTIME] != cc_defaults[VTIME])
		printf("time = %d; ", t->c_cc[VTIME]);
	printf("\n");
}

static void print_flags(const struct termios *t, int all)
{
	int i;
	for (i = 0; i < NBOOLFLAGS; i++) {
		tcflag_t field;
		int on;
		switch (boolflags[i].group) {
		case G_IFLAG: field = t->c_iflag; break;
		case G_OFLAG: field = t->c_oflag; break;
		case G_CFLAG: field = t->c_cflag; break;
		default:      field = t->c_lflag; break;
		}
		on = (field & boolflags[i].bit) != 0;
		if (!all && on == boolflags[i].def_on) continue;
		printf("%s%s ", on ? "" : "-", boolflags[i].name);
	}
	{
		tcflag_t csize = t->c_cflag & (tcflag_t)CSIZE;
		if (all || csize != CS8) {
			const char *name;
			if (csize == CS5) name = "cs5";
			else if (csize == CS6) name = "cs6";
			else if (csize == CS7) name = "cs7";
			else name = "cs8";
			printf("%s ", name);
		}
	}
	printf("\n");
}

static int report_mode(int which) /* 0: bare default subset, 'a', 'g' */
{
	struct termios t;
	if (tcgetattr(0, &t) < 0) {
		__util_diagf("stty: standard input: %s\n", strerror(errno));
		return 1;
	}
	if (which == 'g') { print_saved(&t); return 0; }
	print_speed(&t);
	print_cc(&t, which == 'a');
	print_flags(&t, which == 'a');
	return 0;
}

/* Parses argv[*ip] (and, for a value-taking operand, argv[*ip + 1]
 * too), folding it into *p and advancing *ip past what it consumed.
 * Returns 1 on success, 0 on an operand this file does not recognize
 * or a malformed value -- having already printed the diagnostic, so
 * the caller's only job on failure is to stop and return a nonzero
 * status. */
static int parse_operand(int argc, char **argv, int *ip, struct pending *p)
{
	char *a = argv[*ip];
	const char *name = a;
	int enable = 1;
	int i;

	if (a[0] == '-' && a[1]) { enable = 0; name = a + 1; }
	/* name is either a itself (an argv element, already null-terminated
	 * via __util_stty_main's own elements_withtok(null_terminated, argc))
	 * or a + 1 (a[1] was just proven non-NUL above, so a + 1 is still a
	 * null-terminated suffix of the same buffer) -- the pointer
	 * arithmetic loses the token this checker tracks even though the
	 * fact stays true, so restated here. */
	__ownership_string_terminated(name);

	for (i = 0; i < NBOOLFLAGS; i++) {
		if (!strcmp(name, boolflags[i].name)) {
			mark_group(p, boolflags[i].group, boolflags[i].bit, enable);
			(*ip)++;
			return 1;
		}
	}

	if (enable) {
		if (!strcmp(name, "cs5")) { p->have_csize = 1; p->csize_val = CS5; (*ip)++; return 1; }
		if (!strcmp(name, "cs6")) { p->have_csize = 1; p->csize_val = CS6; (*ip)++; return 1; }
		if (!strcmp(name, "cs7")) { p->have_csize = 1; p->csize_val = CS7; (*ip)++; return 1; }
		if (!strcmp(name, "cs8")) { p->have_csize = 1; p->csize_val = CS8; (*ip)++; return 1; }

		for (i = 0; i < NDELAYMODES; i++) {
			if (!strcmp(name, delaymodes[i].name)) {
				set_delay(p, delaymodes[i].mask, delaymodes[i].val);
				(*ip)++;
				return 1;
			}
		}

		if (!strcmp(name, "ispeed") || !strcmp(name, "ospeed")) {
			unsigned long v;
			if (*ip + 1 >= argc) {
				__util_diagf("stty: %s: option requires an argument\n", a);
				return 0;
			}
			if (!parse_uint(argv[*ip + 1], &v) || v > (unsigned long)(speed_t)-1) {
				__util_diagf("stty: %s: %s: invalid speed\n", a, argv[*ip + 1]);
				return 0;
			}
			if (name[0] == 'i') { p->have_ispeed = 1; p->ispeed_val = (speed_t)v; }
			else { p->have_ospeed = 1; p->ospeed_val = (speed_t)v; }
			*ip += 2;
			return 1;
		}

		if (!strcmp(name, "min") || !strcmp(name, "time")) {
			unsigned long v;
			int idx = name[0] == 'm' ? VMIN : VTIME;
			if (*ip + 1 >= argc) {
				__util_diagf("stty: %s: option requires an argument\n", a);
				return 0;
			}
			if (!parse_uint(argv[*ip + 1], &v) || v > 255) {
				__util_diagf("stty: %s: %s: invalid value\n", a, argv[*ip + 1]);
				return 0;
			}
			p->cc_have[idx] = 1; p->cc_val[idx] = (unsigned char)v;
			*ip += 2;
			return 1;
		}

		for (i = 0; i < NCCNAMES; i++) {
			unsigned char v;
			if (strcmp(name, ccnames[i].name)) continue;
			if (*ip + 1 >= argc) {
				__util_diagf("stty: %s: option requires an argument\n", a);
				return 0;
			}
			if (!parse_ctrl_char(argv[*ip + 1], &v)) {
				__util_diagf("stty: %s: %s: invalid control character\n", a, argv[*ip + 1]);
				return 0;
			}
			p->cc_have[ccnames[i].idx] = 1;
			p->cc_val[ccnames[i].idx] = v;
			*ip += 2;
			return 1;
		}

		{
			unsigned long v;
			if (parse_uint(name, &v) && v <= (unsigned long)(speed_t)-1) {
				p->have_baud = 1; p->baud_val = (speed_t)v;
				(*ip)++;
				return 1;
			}
		}
	}

	if (!strcmp(a, "-tabs")) { set_delay(p, TABDLY, TAB0); (*ip)++; return 1; }
	if (!strcmp(a, "evenp") || !strcmp(a, "parity")) {
		mark_group(p, G_CFLAG, PARENB, 1);
		p->have_csize = 1; p->csize_val = CS7;
		mark_group(p, G_CFLAG, PARODD, 0);
		(*ip)++; return 1;
	}
	if (!strcmp(a, "oddp")) {
		mark_group(p, G_CFLAG, PARENB, 1);
		p->have_csize = 1; p->csize_val = CS7;
		mark_group(p, G_CFLAG, PARODD, 1);
		(*ip)++; return 1;
	}
	if (!strcmp(a, "-parity") || !strcmp(a, "-evenp") || !strcmp(a, "-oddp")) {
		mark_group(p, G_CFLAG, PARENB, 0);
		p->have_csize = 1; p->csize_val = CS8;
		(*ip)++; return 1;
	}
	if (!strcmp(a, "raw")) { apply_raw(p); (*ip)++; return 1; }
	if (!strcmp(a, "-raw") || !strcmp(a, "cooked")) { apply_cooked(p); (*ip)++; return 1; }
	if (!strcmp(a, "nl")) { mark_group(p, G_IFLAG, ICRNL, 0); (*ip)++; return 1; }
	if (!strcmp(a, "-nl")) {
		mark_group(p, G_IFLAG, ICRNL, 1);
		mark_group(p, G_IFLAG, INLCR, 0);
		mark_group(p, G_IFLAG, IGNCR, 0);
		(*ip)++; return 1;
	}
	if (!strcmp(a, "ek")) { apply_ek(p); (*ip)++; return 1; }
	if (!strcmp(a, "sane")) { apply_sane(p); (*ip)++; return 1; }

	__util_diagf("stty: %s: invalid argument\n", a);
	return 0;
}

static void apply_pending(const struct pending *p, struct termios *t)
{
	int i;

	t->c_iflag = (t->c_iflag & ~p->iflag_clr) | p->iflag_set;
	t->c_oflag = (t->c_oflag & ~p->oflag_clr) | p->oflag_set;
	t->c_cflag = (t->c_cflag & ~p->cflag_clr) | p->cflag_set;
	t->c_lflag = (t->c_lflag & ~p->lflag_clr) | p->lflag_set;

	if (p->have_csize)  t->c_cflag = (t->c_cflag & ~(tcflag_t)CSIZE) | p->csize_val;
	if (p->have_crdly)  t->c_oflag = (t->c_oflag & ~(tcflag_t)CRDLY) | p->crdly_val;
	if (p->have_nldly)  t->c_oflag = (t->c_oflag & ~(tcflag_t)NLDLY) | p->nldly_val;
	if (p->have_tabdly) t->c_oflag = (t->c_oflag & ~(tcflag_t)TABDLY) | p->tabdly_val;
	if (p->have_bsdly)  t->c_oflag = (t->c_oflag & ~(tcflag_t)BSDLY) | p->bsdly_val;
	if (p->have_ffdly)  t->c_oflag = (t->c_oflag & ~(tcflag_t)FFDLY) | p->ffdly_val;
	if (p->have_vtdly)  t->c_oflag = (t->c_oflag & ~(tcflag_t)VTDLY) | p->vtdly_val;

	for (i = 0; i < NCCS; i++)
		if (p->cc_have[i]) t->c_cc[i] = p->cc_val[i];

	/* Precedence when both a bare baud number and an explicit ispeed/
	 * ospeed are given together (an unusual combination XCU does not
	 * define an interleaved order for): the specific override always
	 * wins over the general one, applied in that fixed order -- not
	 * argv order -- documented here rather than left implicit. */
	if (p->have_baud)   { t->c_ispeed = p->baud_val; t->c_ospeed = p->baud_val; }
	if (p->have_ispeed) t->c_ispeed = p->ispeed_val;
	if (p->have_ospeed) t->c_ospeed = p->ospeed_val;
}

int __util_stty_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	struct pending p;
	struct termios t;
	int i;

	if (argc == 1) return report_mode(0);
	if (argc == 2 && !strcmp(argv[1], "-a")) return report_mode('a');
	if (argc == 2 && !strcmp(argv[1], "-g")) return report_mode('g');

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-a") || !strcmp(argv[i], "-g")) {
			__util_diagf("stty: %s: may not be combined with other operands\n", argv[i]);
			return 1;
		}
	}

	/* "saved settings" (Combination Modes): recognized only as the
	 * sole operand -- see this file's own header comment. */
	if (argc == 2) {
		struct termios saved;
		if (parse_saved(argv[1], &saved)) {
			if (tcsetattr(0, TCSANOW, &saved) < 0) {
				__util_diagf("stty: standard input: %s\n", strerror(errno));
				return 1;
			}
			return 0;
		}
	}

	memset(&p, 0, sizeof p);
	i = 1;
	while (i < argc)
		if (!parse_operand(argc, argv, &i, &p)) return 1;

	if (tcgetattr(0, &t) < 0) {
		__util_diagf("stty: standard input: %s\n", strerror(errno));
		return 1;
	}
	apply_pending(&p, &t);
	if (tcsetattr(0, TCSANOW, &t) < 0) {
		__util_diagf("stty: standard input: %s\n", strerror(errno));
		return 1;
	}
	return 0;
}
