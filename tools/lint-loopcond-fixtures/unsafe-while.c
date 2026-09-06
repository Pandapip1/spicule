/* SPDX-FileCopyrightText: (C) 2026 Gavin John */
/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Each `while` loop below folds a secondary, incidental safety-cap
 * condition into its own header via `&&`, alongside the loop's real
 * data-dependent driver -- the mirror image of unsafe-for.c's pattern,
 * and just as real: the fix is to keep the data-dependent condition as
 * the while-loop's own header and move the attempt-count check into an
 * explicit `if (...) break;` inside the loop body. */

int try_connect(void);

/* 1. The real driver is `!success`; `attempts < max_attempts` is an
 * incidental safety cap folded into the same header via `&&`. */
int retry_until_success_capped(int (*attempt)(void), int max_attempts)
{
	int success = 0;
	int attempts = 0;
	while (!success && attempts < max_attempts) { /* loopcond-expect */
		success = attempt();
		attempts++;
	}
	return success;
}

/* 2. Same shape, but the data-dependent leaf is a bare function-call
 * result rather than a flag variable. */
int connect_with_retry_limit(int max_attempts)
{
	int attempts = 0;
	while (attempts < max_attempts && !try_connect()) { /* loopcond-expect */
		attempts++;
	}
	return attempts < max_attempts;
}
