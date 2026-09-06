/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * batch(1p): "The batch utility shall read commands from standard
 * input and schedule them for execution in a batch queue. It shall
 * be the equivalent of the command: at -q b -m now" -- fetched and
 * checked directly against
 * https://pubs.opengroup.org/onlinepubs/9699919799/utilities/batch.html
 * before writing this file. No options, no operands (both sections
 * say "None" outright), so this is the smallest possible caller of
 * src/util/atbatch.c's __atbatch_submit(): queue "b", run_at "now"
 * (time(0) -- literally now, not "when submitted plus some delay"),
 * job body read from stdin.
 *
 * "Run by the system using algorithms, based on unspecified factors,
 * that may vary with each invocation" is this implementation's real
 * load-average check -- see src/util/atd.c's own header for exactly
 * what atd does differently for a queue-b job versus every other
 * queue, and what "unspecified factors" honestly reduces to on NT,
 * which has no load-average concept at all.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "util.h"
#include "atbatch.h"

int __util_batch_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	time_t run_at = time(0);
	char id[64];

	if (argc > 1) {
		__util_diagf("batch: %s: unexpected operand\n", argv[1]);
		return 1;
	}
	if (__atbatch_submit("b", run_at, 0, id, sizeof id) < 0) {
		__util_diagf("batch: cannot submit job: %s\n", strerror(errno));
		return 1;
	}
	{
		char tbuf[32];
		char *c = ctime_r(&run_at, tbuf);
		if (c) c[strcspn(c, "\n")] = 0;
		fprintf(stderr, "job %s at %s\n", id, c ? c : "?");
	}
	return 0;
}
