/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include "libc.h"
#include "ownership_stubs.h"

char *optarg;
int optind = 1, opterr = 1, optopt, optreset;

/* The position within the current argv element, for clustered
 * short options (-abc). */
int __optpos; // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision

extern char *__progname;

static void writestr(const char *s withtok(null_terminated))
{
	(void)write(2, s, strlen(s));
}

/* "prog: msg: -c\n", or "prog: msg: --name\n" for getopt_long. */
void __getopt_msg(const char *msg withtok(null_terminated),
    const char *optname, size_t l) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	const char *p = __progname ? __progname : "";
	/* __progname is argv[0] (or "" before it is set), always a real
	 * NUL-terminated C string -- the checker can't see across the
	 * ternary assignment (same shape src/unistd/getcwd.c's own
	 * ternary-of-literals uses). */
	unsafe_assume_string_terminated(p);
	writestr(p);
	writestr(": ");
	writestr(msg);
	writestr(": ");
	(void)write(2, optname, l);
	(void)write(2, "\n", 1);
}

/* Checker gap (spicule.ValidPointer): every argv[optind] access below is
 * guarded by an "optind < argc" check earlier on the same path (elements_
 * withtok(null_terminated, argc) above already proves each in-bounds
 * element itself null-terminated), but the generic dereference-extent
 * proof does not carry that guard across a persistent global index the
 * way it does for a local loop counter -- left open rather than
 * restructured to help the checker prove an already-true fact. */
int getopt(int argc, char *const argv[] elements_withtok(null_terminated, argc), const char *optstring)
{
	int c, d;
	char optchar[3];
	const char *p;

	if (!optind || optreset) {
		__optpos = 0;
		optind = 1;
		optreset = 0;
	}

	if (optind >= argc || !argv[optind])
		return -1;

	if (argv[optind][0] != '-') {
		if (optstring[0] == '-') {
			optarg = argv[optind++];
			return 1;
		}
		return -1;
	}

	if (!argv[optind][1])
		return -1;

	if (argv[optind][1] == '-' && !argv[optind][2])
		return optind++, -1;

	if (!__optpos) __optpos++;
	c = (unsigned char)argv[optind][__optpos];
	__optpos++;

	if (!argv[optind][__optpos]) {
		optind++;
		__optpos = 0;
	}

	if (optstring[0] == '-' || optstring[0] == '+')
		optstring++;

	for (p = optstring; *p; p++) {
		d = (unsigned char)*p;
		if (d == c && c != ':') break;
	}

	if (!*p || c == ':') {
		optopt = c;
		if (optstring[0] != ':' && opterr) {
			optchar[0] = '-'; optchar[1] = (char)c; optchar[2] = 0;
			__getopt_msg("unrecognized option", optchar, 2);
		}
		return '?';
	}
	if (p[1] == ':') {
		optarg = 0;
		if (__optpos) {
			/* The argument is the rest of this element (-ofoo). */
			optarg = argv[optind++] + __optpos;
			__optpos = 0;
		} else if (p[2] != ':') {
			/* Required: the next element. */
			if (optind < argc && argv[optind]) {
				optarg = argv[optind++];
			} else {
				optopt = c;
				if (optstring[0] == ':') return ':';
				if (opterr) {
					optchar[0] = '-'; optchar[1] = (char)c; optchar[2] = 0;
					__getopt_msg("option requires an argument", optchar, 2);
				}
				return '?';
			}
		}
	}
	return c;
}
