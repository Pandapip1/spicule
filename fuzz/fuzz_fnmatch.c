/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * fnmatch() -- src/fnmatch/fnmatch.c: a recursive-descent matcher with
 * backtracking on '*', plus a bracket scanner that walks `pattern`
 * looking for the closing ']'.
 *
 * That scanner is why this harness exists. test/posix-glob.c:999 fences
 * an unterminated '[': the scanner's loop condition is
 * `*p && (first || *p != ']')`, and every `p++` inside it is guarded,
 * but the *callers* of bracket_match advance past what it consumed -- so
 * a pattern ending mid-bracket is exactly the shape that walks off the
 * end of a string in this family of code.
 *
 * Byte 0 is the flag word (only the low three bits are defined flags;
 * the rest are fed in deliberately, because fnmatch() must not misbehave
 * on flags it does not know). Byte 1 is the split point: the pattern is
 * the next `data[1] % (size-2)` bytes and the string is the remainder.
 * Both are NUL-terminated copies, and an input containing an embedded
 * NUL in either half is rejected -- such an input does not describe two
 * C strings.
 *
 * Pattern length is capped at CAP_PAT (64). fnmatch backtracking is
 * exponential in the number of '*'s against a non-matching subject in
 * every implementation, spicule's included -- "*a*a*a*a*a*a*a*a*a*b"
 * against 40 a's is the documented cost of the grammar, not a defect.
 * Without the cap libFuzzer converges on exactly that and reports a
 * timeout that says nothing about correctness.
 *
 * No differential oracle: glibc's fnmatch implements GNU extensions this
 * one deliberately does not (FNM_EXTMATCH, FNM_CASEFOLD, multibyte
 * collation for ranges), so a byte-for-byte comparison would mostly be
 * disagreements that are choices, not defects. Checked positively
 * instead, per fnmatch.html:
 *
 *   - the return value is 0 or FNM_NOMATCH and nothing else;
 *   - a pattern containing no special character ('*', '?', '[', and --
 *     unless FNM_NOESCAPE -- '\\') matches itself exactly, whatever the
 *     flags are, because none of the flags alter literal matching.
 *
 * Everything else is left to ASan/UBSan, which is what the fence at
 * posix-glob.c:999 would have been caught by.
 */
#include <fnmatch.h>
#include <string.h>

extern void oracle_mismatch_i(const char *, const char *, long long, long long);

#define CAP_PAT 64
#define CAP_STR 256

/* Does `p` consist only of characters that fnmatch must treat as
 * literals?  '\\' counts as special only when FNM_NOESCAPE is clear. */
static int all_literal(const char *p, int flags)
{
	for (; *p; p++) {
		if (*p == '*' || *p == '?' || *p == '[') return 0;
		if (*p == '\\' && !(flags & FNM_NOESCAPE)) return 0;
	}
	return 1;
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	char pat[CAP_PAT + 1], str[CAP_STR + 1];
	size_t split, plen, slen;
	int flags, r;

	if (size < 3) return 0;
	flags = data[0];
	split = data[1] % (size - 2);
	data += 2; size -= 2;

	plen = split < CAP_PAT ? split : CAP_PAT;
	slen = size - split;
	if (slen > CAP_STR) slen = CAP_STR;

	memcpy(pat, data, plen); pat[plen] = 0;
	memcpy(str, data + split, slen); str[slen] = 0;
	if (memchr(pat, 0, plen) || memchr(str, 0, slen)) return 0;

	r = fnmatch(pat, str, flags);
	if (r != 0 && r != FNM_NOMATCH)
		oracle_mismatch_i("fnmatch returned neither 0 nor FNM_NOMATCH",
		                  pat, r, FNM_NOMATCH);

	/* A literal pattern matches itself.  Under FNM_PATHNAME and
	 * FNM_PERIOD alike: neither flag restricts an explicit literal in
	 * the pattern (src/fnmatch/fnmatch.c's file banner says so, and
	 * fnmatch.html restricts only '*', '?' and bracket expressions). */
	if (all_literal(pat, flags) && fnmatch(pat, pat, flags) != 0)
		oracle_mismatch_i("literal pattern does not match itself", pat,
		                  fnmatch(pat, pat, flags), 0);

	/* The same call with the two strings swapped: no property is
	 * asserted about the answer, this simply doubles the number of
	 * distinct (pattern, subject) shapes each input reaches, and the
	 * subject side of the matcher gets to be the long one too. */
	{
		char p2[CAP_STR + 1];
		memcpy(p2, str, slen); p2[slen] = 0;
		if (slen <= CAP_PAT) (void)fnmatch(p2, pat, flags);
	}
	return 0;
}
