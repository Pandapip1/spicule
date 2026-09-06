/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * crontab(5)'s five time fields -- minute, hour, day-of-month, month,
 * day-of-week -- shared between src/util/crontab.c (which only needs
 * to *validate* a line while editing) and src/util/crond.c (which
 * needs to *evaluate* one, once a real minute, forever). Declared here
 * rather than folded into src/internal/util.h for the same reason
 * src/util/tablist.h gives for expand(1p)/unexpand(1p)'s shared -t
 * grammar: struct crontime itself, not just a function over plain
 * types, is what both callers need.
 *
 * GRAMMAR IMPLEMENTED
 * ---------------------
 * POSIX crontab(1p)'s own INPUT FILES section states only "an
 * <asterisk>, an element, or a list of elements separated by commas
 * [...] An element shall be either a number or two numbers separated
 * by a hyphen (meaning an inclusive range)" -- no step values, no
 * names. Real-world cron -- checked directly against the actual
 * crontab(5) manual page every Vixie-derived cron (the version every
 * Linux distribution and *BSD actually ships) agrees on, not
 * reconstructed from memory -- adds two things on top of that POSIX
 * minimum, both implemented here because "the real crontab(5)
 * grammar" is this project's own explicit brief for this pass:
 *
 *   - step values: "*" followed by "/N" (every Nth value starting at
 *     the field's own minimum) and "a-b/N" (every Nth value within the range,
 *     inclusive of a).
 *   - names: the month field accepts "jan".."dec" and the day-of-week
 *     field accepts "sun".."sat", matched case-insensitively against
 *     the first three letters (crontab(5)'s own documented rule:
 *     "the specification of days can be made ... by name, using the
 *     first three letters of the particular day").
 *
 * Both day-of-month and day-of-week accept a comma-separated list of
 * any of the above, mixed freely (e.g. "1,15" and a step -- an
 * asterisk immediately followed by "/5" -- combined with a comma).
 *
 * Field ranges (all inclusive): minute 0-59, hour 0-23, day-of-month
 * 1-31, month 1-12, day-of-week 0-7 with both 0 and 7 meaning Sunday
 * (crontab(1p)'s own OPERANDS: "Day of week ... [0,6] (0 = Sunday)"
 * -- Vixie cron additionally accepts 7 for Sunday too, folded into
 * bit 0 here since nothing downstream needs to distinguish them).
 *
 * NOT implemented: "@reboot"/"@daily"/... nicknames (a pure syntactic
 * shorthand for a fixed 5-field pattern each; omitted here rather
 * than silently mapped, since "@reboot" specifically has no honest
 * mapping onto a periodic 5-field schedule at all -- see
 * src/util/crond.c's own header for why re-running it "on every
 * crond start" would be a real behavioural claim this pass does not
 * want to make), and environment-variable assignment lines
 * ("MAILTO=...", a real crontab(5) feature) -- crond has no mail
 * subsystem to route to (mailx is explicitly out of scope for this
 * whole project pass; see the task's own framing), so accepting the
 * syntax and doing nothing with it would be exactly the kind of
 * silent misrepresentation this project's house style refuses.
 * src/util/crontab.c's own header documents the same point for -e/-l.
 *
 * This internal header, like the public C library headers, must use the
 * implementation-reserved namespace for its guard and its own declarations
 * so they cannot collide with user code.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#ifndef _NTLIBC_UTIL_CRONTIME_H
#define _NTLIBC_UTIL_CRONTIME_H

#include <time.h>

struct crontime {
	unsigned char minute[60];   /* [0,59] */
	unsigned char hour[24];     /* [0,23] */
	unsigned char dom[32];      /* [1,31], index 0 unused */
	unsigned char month[13];    /* [1,12], index 0 unused */
	unsigned char dow[7];       /* [0,6], 0 = Sunday (7 folds into 0) */
	/* crontab(1p)/crontab(5)'s day-matching special case: "if both
	 * month and day of month are specified as an asterisk, but day
	 * of week is an element or list, then only the specified days
	 * of the week match" -- i.e. dom and dow are OR'd, not AND'd,
	 * whenever dom was literally "*". Recorded here (rather than
	 * re-derived from `dom` being all-1s, which a literal "1-31"
	 * would also produce without meaning the same thing) because
	 * it is genuinely "was the character '*' present", not a fact
	 * about which values the field matches. */
	int dom_is_star;
};

/* Parses one crontab(5) field (`text`) into `out[lo..hi]` (1 = this
 * value matches), for the given inclusive [lo,hi] range. `names`, if
 * non-NULL, is a NULL-terminated array of exactly (hi-lo+1) three-
 * letter lowercase names (out[lo+i] may also be spelled names[i]);
 * pass NULL for minute/hour/day-of-month, which have none. Returns 0
 * on success, -1 on a malformed field (out is left in an unspecified
 * state on failure -- callers always treat -1 as "reject the whole
 * line", never patch up a partial result). */
int __crontime_parse_field(const char *text, int lo, int hi,
	const char *const *names, unsigned char *out);

/* Parses all five whitespace-separated fields (already split by the
 * caller -- src/util/crontab.c's line reader and src/util/crond.c's
 * both tokenize on <blank> first, matching crontab(1p)'s own "fields
 * separated by <blank> characters") into `out`. Returns 0 on success,
 * -1 if any field is malformed or out of range. */
int __crontime_parse(const char *min, const char *hour, const char *dom,
	const char *mon, const char *dow, struct crontime *out);

/* True if `t` (an already-normalized broken-down local time -- tm_min/
 * tm_hour/tm_mday/tm_mon (0-11)/tm_wday (0-6) all need to be live,
 * exactly what localtime_r() itself produces) falls on a minute this
 * schedule fires. Implements the dom_is_star OR-vs-AND rule above. */
int __crontime_matches(const struct crontime *e, const struct tm *t);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
