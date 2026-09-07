/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- GNU feature-test macro has its specified reserved spelling
#include <string.h>
#include <getopt.h>
#include "libc.h"
#include "ownership_stubs.h"

extern int __optpos; // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision

/* argv required: `av[src]` is dereferenced unconditionally at entry
 * with no guard; its one real call site (__getopt_long() below) always
 * passes its own now-required argv. dest/src are real, in-bounds indices
 * there (0 <= dest <= src < argc), but permute() has no argc parameter
 * of its own to state that against -- checker gap (spicule.ValidPointer),
 * left open rather than adding an unused parameter just to carry a
 * bound. */
static void permute(char *const *argv, int dest, int src) __attribute__((nonnull(1)));
static void permute(char *const *argv, int dest, int src) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	char **av = (char **)argv;
	char *tmp = av[src];
	int i;
	for (i = src; i > dest; i--)
		av[i] = av[i-1];
	av[dest] = tmp;
}

/* argv/optstring required: reached either directly
 * (`argv[optind][0]`/optstring's own indexing on the longopts-taken
 * path) or forwarded, unguarded, into the now-required getopt() at
 * the fallthrough return. longopts/idx are deliberately NOT marked --
 * see include/getopt.h's own comment on getopt_long()/
 * getopt_long_only() for why. Every argv[optind]/argv[i] access below
 * carries the same open checker gap as src/misc/getopt.c's own
 * getopt() -- see that function's comment. */
static int __getopt_long_core(int argc, char *const *argv elements_withtok(null_terminated, argc), const char *optstring, const struct option *longopts, int *idx, int longonly) // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision
    __attribute__((nonnull(2, 3)));
static int __getopt_long_core(int argc, char *const *argv elements_withtok(null_terminated, argc), const char *optstring, const struct option *longopts, int *idx, int longonly)
{
	optarg = 0;
	if (longopts && argv[optind][0] == '-' &&
		((longonly && argv[optind][1] && argv[optind][1] != '-') ||
		 (argv[optind][1] == '-' && argv[optind][2])))
	{
		int colon = optstring[optstring[0] == '+' || optstring[0] == '-'] == ':';
		int i, cnt, match = -1;
		char *arg = 0, *opt, *start = argv[optind] + 1;
		for (cnt = i = 0; longopts[i].name; i++) {
			const char *name = longopts[i].name;
			opt = start;
			if (*opt == '-') opt++;
			while (*opt && *opt != '=' && *opt == *name)
				name++, opt++;
			if (*opt && *opt != '=') continue;
			arg = opt;
			match = i;
			if (!*name) {
				cnt = 1;
				break;
			}
			cnt++;
		}
		if (cnt == 1 && longonly && arg - start == 1) {
			/* A one-character name in long-only mode that is
			 * also a short option is treated as the short one. */
			for (i = 0; optstring[i]; i++) {
				if (optstring[i] == start[0] && start[0] != ':') {
					cnt++;
					break;
				}
			}
		}
		if (cnt == 1) {
			i = match;
			opt = arg;
			optind++;
			if (*opt == '=') {
				if (!longopts[i].has_arg) {
					optopt = longopts[i].val;
					if (colon || !opterr)
						return '?';
					__getopt_msg("option does not take an argument", argv[optind-1], strlen(argv[optind-1]));
					return '?';
				}
					optarg = opt + 1;
				} else if (longopts[i].has_arg == required_argument) {
					optarg = argv[optind];
					if (!optarg) {
					optopt = longopts[i].val;
					if (colon) return ':';
					if (!opterr) return '?';
					__getopt_msg("option requires an argument", argv[optind-1], strlen(argv[optind-1]));
					return '?';
				}
				optind++;
			}
			if (idx) *idx = i;
			if (longopts[i].flag) {
				*longopts[i].flag = longopts[i].val;
				return 0;
			}
			return longopts[i].val;
		}
		if (argv[optind][1] == '-') {
			optopt = 0;
			if (!colon && opterr) {
				const char *reason = cnt ? "option is ambiguous" : "unrecognized option";
				/* Both arms are string literals; the checker's literal
				 * recognition doesn't reach through the ternary when it
				 * feeds a call argument directly (same shape src/unistd/
				 * getcwd.c's own ternary-into-assignment uses). */
				unsafe_assume_string_terminated(reason);
				__getopt_msg(reason, argv[optind], strlen(argv[optind]));
			}
			optind++;
			return '?';
		}
	}
	return getopt(argc, argv, optstring);
}

/* argv/optstring required, same evidence as __getopt_long_core()
 * above: `argv[optind]`/`optstring[0]` are both dereferenced
 * unconditionally past the `optind >= argc` bound check, which says
 * nothing about either pointer's own nullness. */
static int __getopt_long(int argc, char *const *argv elements_withtok(null_terminated, argc), const char *optstring, const struct option *longopts, int *idx, int longonly) // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) -- libc-internal name is intentionally reserved against application collision
    __attribute__((nonnull(2, 3)));
static int __getopt_long(int argc, char *const *argv elements_withtok(null_terminated, argc), const char *optstring, const struct option *longopts, int *idx, int longonly)
{
	int ret, skipped, resumed;
	if (!optind || optreset) {
		__optpos = 0;
		optind = 1;
		optreset = 0;
	}
	if (optind >= argc || !argv[optind]) return -1;
	skipped = optind;
	if (optstring[0] != '+' && optstring[0] != '-') {
		int i;
		for (i = optind; i < argc; i++) {
			if (!argv[i]) return -1;
			if (argv[i][0] == '-' && argv[i][1]) break;
		}
		if (i >= argc) return -1;
		optind = i;
	}
	resumed = optind;
	ret = __getopt_long_core(argc, argv, optstring, longopts, idx, longonly);
	if (resumed > skipped) {
		int i, cnt = optind - resumed;
		for (i = 0; i < cnt; i++)
			permute(argv, skipped, optind - 1);
		optind = skipped + cnt;
	}
	return ret;
}

int getopt_long(int argc, char *const *argv elements_withtok(null_terminated, argc), const char *optstring, const struct option *longopts, int *idx)
{
	return __getopt_long(argc, argv, optstring, longopts, idx, 0);
}

int getopt_long_only(int argc, char *const *argv elements_withtok(null_terminated, argc), const char *optstring, const struct option *longopts, int *idx)
{
	return __getopt_long(argc, argv, optstring, longopts, idx, 1);
}
