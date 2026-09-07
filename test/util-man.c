/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Black-box tests for man(1p) (src/util/man.c, obj/bin/man.exe,
 * src/sh/builtin.c's bi_man()). Same shape as test/util-textio.c (see
 * its own header): each standalone obj/bin/man.exe is spawned as a
 * real process, and the shell built-in is exercised too through
 * obj/sh/sh.exe -c, confirming both callers of __util_man_main()
 * agree.
 *
 * Two kinds of fixture page live under one scratch $MANPATH this file
 * builds itself (write_file(), same "private scratch dir torn down on
 * the way out" idiom test/util-fileops.c's own header explains):
 *
 *  - FROBNICATE_1: hand-written troff source exercising every macro
 *    src/util/man.c's own header comment lists as supported (.TH,
 *    .SH/.SS, .TP/.IP, .PP/.LP, .B/.I, the alternating-font pairs,
 *    .RS/.RE, .nf/.fi, .br, .ds/.nr/.rn and \* / \n interpolation)
 *    plus the common escape subset.
 *  - GREP1_EXCERPT: a REAL, unmodified 210-line prefix of GNU grep's
 *    own grep.1 (from a real Linux system's /nix/store, gzip -dc'd by
 *    hand once to produce this literal text -- not paraphrased, not
 *    hand-simplified), proving this formatter against troff nobody
 *    wrote for this project. It opens with real .de/.ie/.ds/.nr
 *    boilerplate: the .de-body and .ie-guarded lines are still spans
 *    this project's man(1p) deliberately never executes (see src/
 *    util/man.c's own header, "WHAT IS DELIBERATELY NOT IMPLEMENTED"),
 *    but the bare, top-level `.ds`/`.nr` lines among them (e.g. `.ds mC
 *    CW`) ARE now real definitions -- before reaching real NAME/
 *    SYNOPSIS/DESCRIPTION/OPTIONS content that uses the supported
 *    macro subset, exactly the boundary this project's man(1p) is
 *    scoped to.
 *
 * A third fixture, GREP1_EXCERPT_GZ (Tier 4: src/util/man_gz.c's own
 * gzip/DEFLATE decompression), is GREP1_EXCERPT's exact same bytes run
 * through a real `gzip -9` once by hand -- not a hand-crafted DEFLATE
 * stream, so decompressing it exercises this project's own inflate
 * against a real compressor's real dynamic-Huffman output, then
 * reuses check_grep1_rendered_correctly() to prove the decompressed
 * result renders byte-for-byte the same page GREP1_EXCERPT does.
 *
 * Spec pages consulted (https://pubs.opengroup.org/onlinepubs/9699919799/):
 *   utilities/man.html (SYNOPSIS, OPTIONS, OPERANDS, EXIT STATUS)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>

extern char **environ;
int __spawn(const char *path, char *const argv[], char *const envp[]);

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* ---- locating obj/bin/man.exe and obj/sh/sh.exe -- same walk-up-from-
 * argv[0] technique as test/util-textio.c's find_obj_root()/path_for(). */
static char obj_root[1024];

static int find_obj_root(const char *argv0)
{
	size_t n;
	char *p;

	if (!argv0 || !*argv0) return -1;
	n = strlen(argv0);
	if (n >= sizeof obj_root) return -1;
	strcpy(obj_root, argv0);

	for (p = obj_root + n; p > obj_root; p--)
		if (p[-1] == '/' || p[-1] == '\\') break;
	if (p == obj_root) return -1;
	p[-1] = 0;                       /* strip "/util-man.exe" */

	for (p = obj_root + strlen(obj_root); p > obj_root; p--)
		if (p[-1] == '/' || p[-1] == '\\') break;
	if (p == obj_root) return -1;
	p[-1] = 0;                       /* strip "/test" */

	return 0;
}

static void path_for(char *out, size_t outlen, const char *rel)
{
	char sep = strchr(obj_root, '\\') ? '\\' : '/';
	char relcopy[256], *p;

	strncpy(relcopy, rel, sizeof relcopy - 1);
	relcopy[sizeof relcopy - 1] = 0;
	if (sep == '\\')
		for (p = relcopy; *p; p++) if (*p == '/') *p = '\\';
	snprintf(out, outlen, "%s%c%s", obj_root, sep, relcopy);
}

static char man_path[1024], sh_path[1024];

/* ---- the scratch directory, doubling as $MANPATH's one entry ---------- */

static char scratch[128];
static char man1dir[256];

static void raw_rmtree(const char *path)
{
	struct stat st;
	DIR *d;
	struct dirent *de;

	if (lstat(path, &st) < 0) return;
	if (S_ISDIR(st.st_mode)) {
		d = opendir(path);
		if (d) {
			while ((de = readdir(d)) != NULL) {
				char child[600];
				if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
				snprintf(child, sizeof child, "%s/%s", path, de->d_name);
				raw_rmtree(child);
			}
			closedir(d);
		}
		rmdir(path);
	} else {
		unlink(path);
	}
}

static void write_file(const char *path, const char *text)
{
	FILE *f = fopen(path, "wb");
	if (!f) { fails++; printf("FAIL: cannot write %s\n", path); return; }
	fputs(text, f);
	fclose(f);
}

/* ---- spawning and capturing -------------------------------------------- */

static char outfile[700], errfile[700];

/* $MANPATH for every spawned child: built once (see main()) as
 * `environ` plus one extra "MANPATH=..." entry, rather than mutating
 * this process's own environment via setenv()/putenv() -- both are
 * declared in include/stdlib.h only behind _XOPEN_SOURCE/_BSD_SOURCE/
 * _GNU_SOURCE (see that header's own guards), none of which this
 * project's test build line defines under -std=c99 (which predefines
 * __STRICT_ANSI__, so include/features.h's own "define them by
 * default" fallback does not fire either -- see include/sys/wait.h's
 * own comment for the identical situation). Passing a custom envp
 * straight to __spawn() sidesteps the question entirely. */
static char **test_envp;

static int run(const char *path, char *const *args)
{
	int out, err;
	int s1, s2, pid, status;

	out = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	err = open(errfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (out < 0 || err < 0) { if (out >= 0) close(out); if (err >= 0) close(err); return -1; }

	s1 = dup(1); s2 = dup(2);
	dup2(out, 1);
	dup2(err, 2);
	close(out); close(err);

	pid = __spawn(path, args, test_envp);

	dup2(s1, 1); close(s1);
	dup2(s2, 2); close(s2);

	if (pid < 0) return -1;
	if (waitpid(pid, &status, 0) != pid) return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static int run_sh_c(const char *cmd)
{
	char *argv[4];
	argv[0] = (char *)"sh"; argv[1] = (char *)"-c"; argv[2] = (char *)cmd; argv[3] = 0;
	return run(sh_path, argv);
}

static int slurp_into(const char *path, char *buf, size_t buflen)
{
	FILE *f = fopen(path, "rb");
	size_t n;
	if (!f) { buf[0] = 0; return -1; }
	n = fread(buf, 1, buflen - 1, f);
	buf[n] = 0;
	fclose(f);
	return 0;
}

static char outbuf[16384], errbuf[16384];

/* De-overstrike, the same collapse `col -b` does: a bold or italic
 * glyph is always exactly `X\bY` (see src/util/man.c's own
 * man_render_write() -- OVERSTRIKE mode writes the shadow character,
 * a backspace, then the real one), so replacing every such triple
 * with just Y recovers the plain text underneath. Content assertions
 * below check plainbuf, not outbuf directly, precisely BECAUSE most
 * of FROBNICATE_1's/grep.1's interesting text is bold/italic and
 * would never literally appear byte-for-byte in the overstruck raw
 * output -- a couple of assertions check outbuf directly instead,
 * specifically to prove the overstrike encoding itself is present. */
static char plainbuf[16384];

static void strip_overstrike(const char *in, char *out, size_t outsz)
{
	size_t i = 0, o = 0, n = strlen(in);
	while (i < n && o + 1 < outsz) {
		if (i + 2 < n && in[i + 1] == '\b') { out[o++] = in[i + 2]; i += 3; }
		else { out[o++] = in[i++]; }
	}
	out[o] = 0;
}

static void slurp_both(void)
{
	slurp_into(outfile, outbuf, sizeof outbuf);
	slurp_into(errfile, errbuf, sizeof errbuf);
	strip_overstrike(outbuf, plainbuf, sizeof plainbuf);
}

static int out_contains(const char *needle) { return strstr(outbuf, needle) != 0; }
static int plain_contains(const char *needle) { return strstr(plainbuf, needle) != 0; }
static int err_contains(const char *needle) { return strstr(errbuf, needle) != 0; }

/* ==== fixture page 1: exercises every supported macro/escape ============ */

static const char FROBNICATE_1[] =
	".TH FROBNICATE 1 \"2026\" \"spicule test\" \"spicule Test Suite\"\n"
	".SH NAME\n"
	"frobnicate \\- exercise every supported macro\n"
	".SH SYNOPSIS\n"
	".B frobnicate\n"
	".RB [ \\-x ]\n"
	".I target\n"
	".br\n"
	".B frobnicate\n"
	".B \\-\\-help\n"
	".SH DESCRIPTION\n"
	"Plain text with\n"
	".B bold\n"
	"and\n"
	".I italic\n"
	"words, plus alternating\n"
	".BR bold , roman\n"
	"and a glyph\n"
	".RB ( \\(bu )\n"
	"bullet and a copyright\n"
	".RB ( \\(co )\n"
	"sign and an undefined string register\n"
	".RB ( \\*(xx )\n"
	"that must vanish silently.\n"
	".SS Subsection Heading\n"
	"Body text under a subsection.\n"
	".TP\n"
	".B \\-x\n"
	"A short tag.\n"
	".TP\n"
	".B \\-\\-a-very-long-option-name-that-does-not-fit-the-tag-column\n"
	"A description that must start on its own line because the tag itself is too long to share it.\n"
	".IP \\(bu 2\n"
	"A bulleted item using .IP with an explicit width.\n"
	".RS\n"
	".IP \\(bu 2\n"
	"A nested item, one .RS level deeper.\n"
	".RE\n"
	".nf\n"
	"literal   line    one\n"
	"    literal line two, indented\n"
	".fi\n"
	"Back to normal filled text after .fi.\n"
	".SH REGISTERS\n"
	".ds GREETING hello register world\n"
	".nr COUNT 5\n"
	"String register:\n"
	".B \\*[GREETING]\n"
	".br\n"
	"Number register:\n"
	".B \\n[COUNT]\n"
	".br\n"
	".nr COUNT +3\n"
	"Relative increment:\n"
	".B \\n[COUNT]\n"
	".br\n"
	".rn COUNT KOUNT\n"
	"Renamed register:\n"
	".B \\n[KOUNT]\n"
	".br\n"
	"Old name after rename:\n"
	".B \\n[COUNT]\n"
	".br\n"
	"Undefined number register:\n"
	".B \\n(zz\n"
	".br\n"
	"Groff detection register:\n"
	".B \\n(.g\n"
	".SH SEE ALSO\n"
	".BR true (1)\n";

/* ==== fixture page 1b: exercises Tier 2 user-defined macros (.de/.de1/
 * .am/.am1/.ig, invocation, $0/$1-$9/$* argument substitution, .rm/.rn/
 * .als) plus the two formatter fidelity fixes (.RB per-word alternation,
 * \c join suppression). Each result sits on its own line via .br, same
 * "never split across a word-wrap boundary" reasoning FROBNICATE_1's own
 * REGISTERS section already documents. */
static const char MACROTEST_1[] =
	".TH MACROTEST 1 \"2026\" \"spicule test\" \"spicule Test Suite\"\n"
	".SH NAME\n"
	"macrotest \\- exercise user-defined macros\n"
	".SH MACROS\n"
	".de greet\n"
	"Hello, \\$1! Args: \\$*\n"
	"..\n"
	".greet World extra\n"
	".br\n"
	".de1 greet2\n"
	".B \\$0 says hi to \\$1\n"
	"..\n"
	".greet2 Bob\n"
	".br\n"
	".am greet\n"
	"More appended text for \\$1.\n"
	"..\n"
	".greet Carol\n"
	".br\n"
	".ig\n"
	"This should never appear in rendered output.\n"
	"..\n"
	".rm greet2\n"
	".greet2 ShouldBeSkipped\n"
	".als aliasgreet greet\n"
	".rn greet renamedgreet\n"
	".renamedgreet Dave\n"
	".br\n"
	".aliasgreet Eve\n"
	".SH FIDELITY\n"
	".RB \"wordone wordtwo\" \"wordthree\"\n"
	".br\n"
	".B contfoo\\c\n"
	".I contbar\n"
	".br\n"
	".B nofoo\n"
	".I nobar\n";

/* ==== fixture page 1c: exercises Tier 3 conditionals (.if/.ie/.el) --
 * numeric comparisons (including parenthesized arithmetic), string
 * equality, negation, the n/t/o/e device/page-parity tests, .ie/.el
 * if/else chaining, and \{ ... \} multi-line blocks including one
 * nested block -- see src/util/man.c's own "CONDITIONALS" header
 * comment for the exact grammar and the documented n/t/o/e answers. */
static const char CONDTEST_1[] =
	".TH CONDTEST 1 \"2026\" \"spicule test\" \"spicule Test Suite\"\n"
	".SH NAME\n"
	"condtest \\- exercise conditional evaluation\n"
	".SH CONDITIONALS\n"
	".nr xx 10\n"
	".if \\n(xx>5 .ds cmp1 numeric-gt-true\n"
	".if \\n(xx>50 .ds cmp1b numeric-gt-false\n"
	"Numeric greater-than:\n"
	".B \\*[cmp1]\n"
	".B \\*[cmp1b]\n"
	".br\n"
	".if (\\n(xx-5)>4 .ds cmpparen paren-arith-true\n"
	"Parenthesized arithmetic:\n"
	".B \\*[cmpparen]\n"
	".br\n"
	".if \\n(xx=10 .ds cmpeq numeric-eq-true\n"
	".if \\n(xx=11 .ds cmpeqb numeric-eq-false\n"
	"Numeric equal:\n"
	".B \\*[cmpeq]\n"
	".B \\*[cmpeqb]\n"
	".br\n"
	".if 'abc'abc' .ds cmp2 string-eq-true\n"
	".if 'abc'xyz' .ds cmp2b string-eq-false\n"
	"String equality:\n"
	".B \\*[cmp2]\n"
	".B \\*[cmp2b]\n"
	".br\n"
	".if !'abc'xyz' .ds cmp3 negated-neq-true\n"
	"Negated inequality:\n"
	".B \\*[cmp3]\n"
	".br\n"
	".if n .ds nt nroff-true\n"
	".if t .ds tt troff-true\n"
	"Device tests:\n"
	".B \\*[nt]\n"
	".B \\*[tt]\n"
	".br\n"
	".if o .ds oddp odd-page-true\n"
	".if e .ds evenp even-page-true\n"
	"Page parity tests:\n"
	".B \\*[oddp]\n"
	".B \\*[evenp]\n"
	".br\n"
	".ie \\n(xx=10 .ds iebranch ie-true-branch\n"
	".el .ds iebranch el-branch\n"
	"IE chain when true:\n"
	".B \\*[iebranch]\n"
	".br\n"
	".ie \\n(xx=99 .ds iebranch2 ie-alt-branch\n"
	".el .ds iebranch2 el-alt-branch\n"
	"IE chain when false:\n"
	".B \\*[iebranch2]\n"
	".br\n"
	".if \\n(xx>5 \\{\n"
	".ds block1 block-line-one\n"
	".ds block2 block-line-two\n"
	".\\}\n"
	"Block form:\n"
	".B \\*[block1]\n"
	".B \\*[block2]\n"
	".br\n"
	".if \\n(xx>500 \\{\n"
	".ds neverblock should-not-appear\n"
	".\\}\n"
	"Block form false:\n"
	".B \\*[neverblock]\n"
	".br\n"
	".ie \\n(xx>5 \\{\n"
	".ds nestbranch nest-true-outer\n"
	".if \\n(xx>0 \\{\n"
	".ds nestinner nest-true-inner\n"
	".\\}\n"
	".\\}\n"
	".el \\{\n"
	".ds nestbranch nest-false-outer\n"
	".\\}\n"
	"Nested block:\n"
	".B \\*[nestbranch]\n"
	".B \\*[nestinner]\n";

/* ==== fixture page 1d: exercises Tier 5 tables (.TS/.TE) -- see src/
 * util/man.c's own "TABLES" header comment for the exact grammar.
 * Hand-written (a genuine .TS-using real-world man page excerpt was
 * not easy to source at this fixture's small size without pulling in
 * a much larger real page), but matching real troff tbl syntax
 * exactly -- same rigor as CONDTEST_1/MACROTEST_1 above.
 *
 * Three tables:
 *  - A boxed table whose FIRST format line ("c s s") spans a title
 *    across the row (columns 2/3 are `s`, consuming no data field),
 *    while every following row uses the SECOND ("l l n") format line
 *    -- exactly real tbl's "last format line repeats" rule, and this
 *    file's own "alignment/width is taken from the last format line"
 *    documented simplification (see header comment). The final row
 *    (after a `_` single-rule row) leaves its middle field empty
 *    (two adjacent tabs) to exercise a genuinely missing cell, and
 *    its numeric field has a fractional part to prove real decimal-
 *    point column alignment against the other numeric cells.
 *  - A second, boxless table (no options line at all) proving plain
 *    (non-`box`) rendering uses no border characters.
 *  - A third table combining `allbox` with a custom `tab(:)` field
 *    separator on one options line, proving multiple option keywords
 *    parse together and the custom separator is honoured instead of
 *    a literal tab. */
static const char TBLTEST_1[] =
	".TH TBLTEST 1 \"2026\" \"spicule test\" \"spicule Test Suite\"\n"
	".SH NAME\n"
	"tbltest \\- exercise tbl table rendering\n"
	".SH TABLES\n"
	".TS\n"
	"box;\n"
	"c s s\n"
	"l l n.\n"
	"Element Summary\n"
	"Name\tKind\tBytes\n"
	"Alpha\tint\t1\n"
	"Beta\tlong\t42\n"
	"Gamma\tdouble\t3.5\n"
	"_\n"
	"Total\t\t46.5\n"
	".TE\n"
	"Text after the boxed table must still render normally.\n"
	".TS\n"
	"l l\n"
	"l l.\n"
	"Plain\tNoBox\n"
	"one\t1\n"
	"two\t2\n"
	".TE\n"
	"Text after the second, box-less table.\n"
	".TS\n"
	"allbox tab(:);\n"
	"c c\n"
	"l l.\n"
	"Col1:Col2\n"
	"xray:yankee\n"
	"papa:quebec\n"
	".TE\n"
	"Text after the third, allbox/custom-separator table.\n";

/* ==== fixture page 1e: exercises Tier 6 eqn (.EQ/.EN) -- see src/
 * util/man.c's own "EQN" header comment for the exact grammar and its
 * linear-approximation rendering choices. Hand-written for the same
 * reason TBLTEST_1 above is (a small real-world .EQ-using page wasn't
 * easy to source at fixture size), but the quadratic-formula equation
 * is eqn's own textbook-canonical example (see e.g. the original "Typ-
 * esetting Mathematics" eqn tutorial): `x = { -b +- sqrt{b sup 2 -
 * 4ac} } over {2a}`, chosen specifically because it's the standard
 * proof that `over` binds to the bracketed numerator group ALONE and
 * not to the whole "x =" prefix before it -- exactly the tight-vs-loose
 * precedence this file's own man_eqn_parse_over() header comment
 * documents getting right. Also exercises: a `delim` directive line
 * (must produce no visible output of its own), Greek-letter lookup
 * (lowercase `alpha`, uppercase `GAMMA`) alongside `sub`, a left-
 * associative chained `over`, `sqrt` on a bare primary, `sub`/`sup`
 * combining onto one primary, and a `"quoted"` literal staying literal
 * text beside the same bare word looked up as a Greek letter. */
static const char EQNTEST_1[] =
	".TH EQNTEST 1 \"2026\" \"spicule test\" \"spicule Test Suite\"\n"
	".SH NAME\n"
	"eqntest \\- exercise eqn equation rendering\n"
	".SH EQUATIONS\n"
	".EQ\n"
	"delim $$\n"
	".EN\n"
	"The quadratic formula:\n"
	".EQ\n"
	"x = { -b +- sqrt{ b sup 2 - 4 ac } } over {2 a}\n"
	".EN\n"
	"Greek letters and a subscript:\n"
	".EQ\n"
	"alpha sub i + GAMMA\n"
	".EN\n"
	"A left-associative chained fraction:\n"
	".EQ\n"
	"a over b over c\n"
	".EN\n"
	"A square root:\n"
	".EQ\n"
	"sqrt x\n"
	".EN\n"
	"Sub and sup combine onto one primary regardless of order:\n"
	".EQ\n"
	"x sup 2 sub i\n"
	".EN\n"
	"A quoted literal stays literal beside the same bare name looked up:\n"
	".EQ\n"
	"\"pi\" + pi\n"
	".EN\n"
	"Text after the equations must still render normally.\n";

/* ==== fixture page 1f: exercises Tier 7 fill-and-adjust (.ad/.na) --
 * see src/util/man.c's own "ADJUSTMENT" header comment. Two paragraphs,
 * each nine words of the SAME 11-column length (differing only in a
 * B/N prefix so find_line() below can tell them apart), one under
 * `.ad b` (real justification) and the other under `.na` (ragged
 * right, this file's own long-standing default) -- since both share
 * the same word length/count/indent/terminal width, they wrap at the
 * identical word boundary, so any rendered-length difference between
 * them can only come from adjustment padding, not a different break.
 * Hand-verified arithmetic at this file's documented 80-column
 * default width (no $COLUMNS in this test's own environment) and
 * MAN_BASE_INDENT of 7: 73 columns available, 6 words of 11 columns
 * plus 5 mandatory single spaces = 71, a 7th word would need 83 -- so
 * the break falls after the 6th word, leaving 2 columns of slack for
 * `.ad b` to distribute across the resulting 5 gaps, and 3 words (35
 * columns, nowhere near 73) on the final, never-stretched line. */
static const char ADJUSTTEST_1[] =
	".TH ADJUSTTEST 1 \"2026\" \"spicule test\" \"spicule Test Suite\"\n"
	".SH NAME\n"
	"adjusttest \\- exercise fill-and-adjust rendering\n"
	".SH ADJUSTMENT\n"
	".ad b\n"
	"AdjustBXXX1 AdjustBXXX2 AdjustBXXX3 AdjustBXXX4 AdjustBXXX5 AdjustBXXX6 "
	"AdjustBXXX7 AdjustBXXX8 AdjustBXXX9\n"
	".PP\n"
	".na\n"
	"AdjustNXXX1 AdjustNXXX2 AdjustNXXX3 AdjustNXXX4 AdjustNXXX5 AdjustNXXX6 "
	"AdjustNXXX7 AdjustNXXX8 AdjustNXXX9\n";

/* ==== fixture page 1g: exercises Tier 7 hyphenation (.hy/.nh) -- see
 * src/util/man.c's own "HYPHENATION" header comment. Five paragraphs, all
 * at this file's documented 80-column default width (no $COLUMNS in this
 * test's own environment) and MAN_BASE_INDENT of 7 (73 columns
 * available), the same arithmetic ADJUSTTEST_1 above hand-verifies:
 *
 *  - P1 (.hy on): six 10-column filler words (60 cols + 5 mandatory
 *    spaces = 65) leave only 8 columns before "understanding" (13
 *    columns) -- it cannot fit whole (65+1+13 > 73), but man_hyph_
 *    best_split() finds this file's own ".under3" prefix pattern's
 *    break point (5 columns) fits the 6 columns left after reserving one
 *    for the hyphen, so the line ends "...under-" and the very next line
 *    starts with the remainder, "standing".
 *  - P2 (.nh): the identical filler+word shape, hyphenation off --
 *    "understanding" cannot split, so it is deferred whole to the next
 *    line exactly as this file always did before this tier, proving
 *    `.nh` actually suppresses the P1 behaviour rather than P1 being
 *    coincidental.
 *  - P3 (.hy on, but "understanding" is this paragraph's OWN LAST WORD):
 *    proves this file's documented "never hyphenate a paragraph's last
 *    word" rule -- despite `.hy` being on and the identical overflow
 *    shape, the word is deferred whole, exactly like P2.
 *  - P4 (.hy on, "understanding" placed where it comfortably fits):
 *    proves hyphenation is only ever attempted when a word doesn't fit
 *    -- the word must render intact, unsplit, on one line.
 *  - P5 (.hy on, same filler shape as P1, but the word being split is
 *    exactly MAN_HYPH_MAX_WORD - 2 == 54 ASCII letters -- the longest
 *    word man_hyph_word_ok() ever accepts, where man_hyph_find_points()'s
 *    own dotted-word length (wlen + 2) reaches MAN_HYPH_MAX_WORD exactly.
 *    A real, execution-based regression case for a fixed off-by-one that
 *    wrote one int past the end of that function's own `vals[]` stack
 *    array at precisely this boundary -- not merely reasoned about.
 *    "under" + "standing" x6 + "s" (5 + 48 + 1 == 54) still carries this
 *    file's own recognised ".under3" prefix, so the same "under-" split
 *    point P1 exercises is still the expected, correct result here. */
static const char HYPHTEST_1[] =
	".TH HYPHTEST 1 \"2026\" \"spicule test\" \"spicule Test Suite\"\n"
	".SH NAME\n"
	"hyphtest \\- exercise hyphenation rendering\n"
	".SH HYPHENATION\n"
	".hy\n"
	"P1FillerAA P1FillerBB P1FillerCC P1FillerDD P1FillerEE P1FillerFF "
	"understanding continues afterward\n"
	".PP\n"
	".nh\n"
	"P2FillerAA P2FillerBB P2FillerCC P2FillerDD P2FillerEE P2FillerFF "
	"understanding continues afterward\n"
	".PP\n"
	".hy\n"
	"P3FillerAA P3FillerBB P3FillerCC P3FillerDD P3FillerEE P3FillerFF "
	"understanding\n"
	".PP\n"
	".hy\n"
	"A short line with the word understanding placed early enough to fit.\n"
	".PP\n"
	".hy\n"
	"P5FillerAA P5FillerBB P5FillerCC P5FillerDD P5FillerEE P5FillerFF "
	"understandingstandingstandingstandingstandingstandings afterward\n";

/* ==== fixture page 2: a real, unmodified 210-line prefix of GNU grep's
 * own grep.1 (gzip -dc'd by hand from a real Linux system's
 * /nix/store copy of gnugrep-3.12) -- see this file's own header. */
static const char *const GREP1_EXCERPT[] = {
	".\\\" GNU grep man page\n",
	".de dT\n",
	".ds Dt \\\\$2\n",
	"..\n",
	".dT Time-stamp: \"2025-03-21\"\n",
	".\\\" Update the above date whenever a change to either this file or\n",
	".\\\" grep.c's 'usage' function results in a nontrivial change to the man page.\n",
	".\\\" In Emacs, you can update the date by running 'M-x time-stamp'\n",
	".\\\" after you make a change that you decide is nontrivial.\n",
	".\\\" It is no big deal to forget to update the date.\n",
	".\n",
	".TH GREP 1 \\*(Dt \"GNU grep 3.12\" \"User Commands\"\n",
	".\n",
	".ie \\n(.g .ds ' \\(aq\n",
	".el .ds ' '\n",
	".if !\\w@\\*(lq@ \\{\\\n",
	".\\\" Recent-enough groff an.tmac does not seem to be in use,\n",
	".\\\" so define the strings lq and rq.\n",
	".\tie \\n(.g \\{\\\n",
	".\t\tds lq \\(lq\\\"\n",
	".\t\tds rq \\(rq\\\"\n",
	".\t\\}\n",
	".\tel \\{\\\n",
	".\t\tds lq ``\n",
	".\t\tds rq ''\n",
	".\t\\}\n",
	".\\}\n",
	".\n",
	".as mC\n",
	".if !\\w@\\*(mC@ \\{\\\n",
	".\\\" groff an-ext.tmac does not seem to be in use, so define the parts of\n",
	".\\\" it that are used below, taken from groff 1.23.0.  For a copy, please see:\n",
	".\\\" https://git.savannah.gnu.org/cgit/groff.git/plain/tmac/an-ext.tmac?id=1.23.0\n",
	".nr mG \\n(.g-1\n",
	".\\\" --- Start of lines taken from groff an-ext.tmac,\n",
	".\\\" except with \"nr mH 14\" replaced by \"nr mH 0\"\n",
	".\\\" and with mS, SY, YS definitions omitted.\n",
	".\n",
	".\\\" Define this to your implementation's constant-width typeface.\n",
	".ds mC CW\n",
	".if n .ds mC R\n",
	".\n",
	".\\\" Save the automatic hyphenation mode.\n",
	".\\\"\n",
	".\\\" In AT&T troff, there was no register exposing the hyphenation mode,\n",
	".\\\" and no way to save and restore it.  Set `mH` to a reasonable value\n",
	".\\\" for your implementation and preference.\n",
	".de mY\n",
	".  ie !\\\\n(.g \\\n",
	".    nr mH 0\n",
	".  el \\\n",
	".    do nr mH \\\\n[.hy] \\\" groff extension register\n",
	"..\n",
	".\n",
	".nr mE 0 \\\" in an example (EX/EE)?\n",
	".\n",
	".\\\" Prepare link text for mail/web hyperlinks.  `MT` and `UR` call this.\n",
	".de mV\n",
	".  ds m1 \\\\$1\\\"\n",
	"..\n",
	".\n",
	".\\\" IP address, no domain name, for a `mailto:` or other URI.\n",
	".de mX\n",
	".  ie \\\\n(.$-1 \\{\\\n",
	".    as m1 \\e \\\\$2\n",
	".  \\}\n",
	".  el \\{\\\n",
	".    as m1 \\e \\\\*(m1\n",
	".  \\}\n",
	"..\n",
	".\n",
	".\\\" Set the link text and target for `MT`, `UR`.\n",
	".de mZ\n",
	".  ds m2 \\\\$1\\\"\n",
	"..\n",
	".\n",
	".\\\" Hyperlink using an explicit target, if given, or link text otherwise\n",
	".\\\" (encoded per RFC 3986, except a fragment is not yet supported).\n",
	".de UR\n",
	".  ds m1 \\\\$1\\\"\n",
	"..\n",
	".de UE\n",
	".  br\n",
	"..\n",
	".de MT\n",
	".  ds m1 mailto:\\\\$1\\\"\n",
	"..\n",
	".de ME\n",
	".  br\n",
	"..\n",
	".\n",
	".\\\" Start example.\n",
	".de EX\n",
	".  nr mP \\\\n(PD\n",
	".  nr PD 0\n",
	".  nf\n",
	".  ft \\\\n(mC\n",
	".  nr mE 1\n",
	"..\n",
	".\n",
	".\\\" End example.\n",
	".if \\\\n(.g-\\\\n(mG \\{\\\n",
	".de EE\n",
	".  br\n",
	".  if \\\\n(mE \\{\\\n",
	".    ft \\\\n(mF\n",
	".    nr PD \\\\n(mP\n",
	".    fi\n",
	".    nr mE 0\n",
	".  \\}\n",
	"..\n",
	".\\}\n",
	".\\\" --- End of lines taken from groff an-ext.tmac\n",
	".\\}\n",
	".\n",
	".hy 0\n",
	".\n",
	".SH NAME\n",
	"grep \\- print lines that match patterns\n",
	".\n",
	".SH SYNOPSIS\n",
	".B grep\n",
	".RI [ OPTION ].\\|.\\|.\\&\n",
	".I PATTERNS\n",
	".RI [ FILE ].\\|.\\|.\n",
	".br\n",
	".B grep\n",
	".RI [ OPTION ].\\|.\\|.\\&\n",
	".B \\-e\n",
	".I PATTERNS\n",
	"\\&.\\|.\\|.\\&\n",
	".RI [ FILE ].\\|.\\|.\n",
	".br\n",
	".B grep\n",
	".RI [ OPTION ].\\|.\\|.\\&\n",
	".B \\-f\n",
	".I PATTERN_FILE\n",
	"\\&.\\|.\\|.\\&\n",
	".RI [ FILE ].\\|.\\|.\n",
	".\n",
	".SH DESCRIPTION\n",
	".B grep\n",
	"searches for patterns in each\n",
	".IR FILE .\n",
	"In the synopsis's first form, which is used if no\n",
	".B \\-e\n",
	"or\n",
	".B \\-f\n",
	"options are present, the first operand\n",
	".I PATTERNS\n",
	"is one or more patterns separated by newline characters, and\n",
	".B grep\n",
	"prints each line that matches a pattern.\n",
	"Typically\n",
	".I PATTERNS\n",
	"should be quoted when\n",
	".B grep\n",
	"is used in a shell command.\n",
	".PP\n",
	"A\n",
	".I FILE\n",
	"of\n",
	".RB \"\\*(lq\" \\- \"\\*(rq\"\n",
	"stands for standard input.\n",
	"If no\n",
	".I FILE\n",
	"is given, recursive searches examine the working directory,\n",
	"and nonrecursive searches read standard input.\n",
	".\n",
	".SH OPTIONS\n",
	".SS \"Generic Program Information\"\n",
	".TP\n",
	".B \\-\\^\\-help\n",
	"Output a usage message and exit.\n",
	".TP\n",
	".BR \\-V \", \" \\-\\^\\-version\n",
	"Output the version number of\n",
	".B grep\n",
	"and exit.\n",
	".SS \"Pattern Syntax\"\n",
	".TP\n",
	".BR \\-E \", \" \\-\\^\\-extended\\-regexp\n",
	"Interpret\n",
	".I PATTERNS\n",
	"as extended regular expressions (EREs, see below).\n",
	".TP\n",
	".BR \\-F \", \" \\-\\^\\-fixed\\-strings\n",
	"Interpret\n",
	".I PATTERNS\n",
	"as fixed strings, not regular expressions.\n",
	".TP\n",
	".BR \\-G \", \" \\-\\^\\-basic\\-regexp\n",
	"Interpret\n",
	".I PATTERNS\n",
	"as basic regular expressions (BREs, see below).\n",
	"This is the default.\n",
	".TP\n",
	".BR \\-P \", \" \\-\\^\\-perl\\-regexp\n",
	"Interpret\n",
	".I PATTERNS\n",
	0
};

static void write_grep1_excerpt(const char *path)
{
	FILE *f = fopen(path, "wb");
	size_t i;
	if (!f) { fails++; printf("FAIL: cannot write %s\n", path); return; }
	for (i = 0; GREP1_EXCERPT[i]; i++) fputs(GREP1_EXCERPT[i], f);
	fclose(f);
}

/* ==== fixture page 3: the SAME real, unmodified GREP1_EXCERPT bytes above,
 * genuinely gzip-compressed (Tier 4 -- src/util/man_gz.c) ================ */

/* `gzip -9 -n` (real gzip(1), -n so the header carries no filename/mtime,
 * for a deterministic fixture) run once, by hand, over the exact same
 * 3901 bytes write_grep1_excerpt() writes above -- not a separately
 * hand-crafted DEFLATE stream, so this exercises this project's own
 * man_gunzip() (src/util/man_gz.c) against a real compressor's real
 * output on real troff content, the same "proof against data nobody
 * wrote for this project" reasoning GREP1_EXCERPT's own comment gives.
 * 1796 compressed bytes for grep1.raw's 3901 uncompressed -- comfortably
 * exercises dynamic Huffman blocks (real gzip -9 never emits stored or
 * fixed-Huffman blocks for text this size), not just the trivial paths. */
static const unsigned char GREP1_EXCERPT_GZ[] = {
	31, 139, 8, 0, 0, 0, 0, 0, 2, 3, 165, 87,
	109, 111, 219, 200, 17, 254, 28, 254, 138, 57, 225, 16,
	57, 133, 68, 91, 78, 91, 180, 1, 138, 187, 196, 166,
	109, 1, 23, 71, 144, 228, 235, 165, 199, 107, 181, 34,
	87, 210, 34, 226, 46, 205, 93, 90, 22, 218, 254, 247,
	62, 179, 75, 74, 116, 226, 194, 5, 10, 248, 133, 47,
	179, 207, 204, 60, 243, 202, 56, 237, 209, 245, 237, 29,
	173, 43, 89, 82, 33, 52, 149, 98, 45, 163, 56, 151,
	148, 207, 241, 207, 210, 165, 163, 52, 253, 254, 60, 138,
	99, 220, 206, 105, 174, 10, 57, 180, 78, 20, 229, 59,
	234, 157, 159, 157, 255, 97, 120, 246, 118, 120, 62, 234,
	69, 49, 128, 238, 202, 92, 56, 73, 110, 35, 73, 44,
	205, 3, 48, 248, 118, 183, 145, 90, 62, 200, 138, 4,
	101, 27, 161, 215, 16, 48, 36, 21, 164, 42, 136, 42,
	75, 43, 181, 149, 100, 42, 15, 193, 118, 196, 89, 223,
	82, 191, 182, 176, 164, 79, 171, 90, 103, 78, 25, 77,
	149, 180, 245, 214, 89, 82, 26, 64, 218, 104, 87, 169,
	7, 37, 182, 29, 76, 214, 219, 186, 16, 123, 180, 177,
	166, 164, 16, 153, 29, 208, 222, 212, 148, 225, 93, 125,
	52, 209, 95, 44, 247, 84, 213, 90, 43, 189, 166, 254,
	199, 225, 35, 185, 131, 127, 125, 143, 32, 86, 14, 102,
	242, 233, 66, 124, 145, 29, 23, 54, 194, 249, 199, 185,
	204, 20, 216, 130, 27, 71, 155, 26, 229, 46, 60, 165,
	165, 90, 67, 12, 166, 194, 198, 149, 169, 214, 210, 241,
	213, 87, 150, 224, 76, 20, 207, 111, 232, 122, 154, 76,
	104, 68, 233, 239, 78, 192, 124, 239, 16, 154, 183, 241,
	232, 188, 71, 189, 59, 11, 107, 46, 76, 1, 55, 115,
	219, 227, 35, 74, 82, 170, 79, 226, 53, 113, 176, 250,
	148, 158, 136, 251, 40, 150, 219, 230, 22, 78, 168, 21,
	125, 151, 238, 126, 4, 224, 246, 254, 71, 74, 255, 153,
	122, 227, 166, 50, 147, 218, 13, 165, 54, 245, 122, 3,
	21, 102, 181, 34, 161, 99, 7, 182, 40, 55, 146, 237,
	118, 100, 165, 44, 216, 212, 165, 100, 214, 107, 43, 7,
	254, 172, 53, 112, 103, 165, 116, 48, 222, 194, 105, 189,
	182, 180, 189, 7, 64, 78, 213, 61, 140, 122, 117, 176,
	202, 235, 123, 245, 42, 247, 239, 83, 152, 144, 246, 154,
	251, 138, 239, 171, 112, 159, 254, 27, 127, 96, 244, 19,
	233, 197, 226, 40, 217, 239, 55, 82, 252, 27, 197, 194,
	82, 113, 209, 117, 173, 184, 56, 186, 214, 58, 51, 148,
	143, 238, 69, 135, 190, 114, 166, 20, 21, 82, 204, 172,
	60, 144, 114, 33, 204, 162, 146, 44, 155, 227, 216, 214,
	236, 6, 228, 144, 9, 154, 86, 149, 41, 26, 93, 163,
	248, 252, 109, 124, 22, 19, 93, 25, 159, 229, 166, 220,
	15, 168, 220, 74, 97, 37, 171, 124, 231, 209, 54, 206,
	149, 246, 221, 233, 233, 90, 185, 216, 138, 7, 161, 181,
	216, 196, 107, 93, 199, 200, 136, 211, 12, 79, 79, 61,
	88, 204, 87, 229, 86, 40, 125, 202, 182, 159, 118, 252,
	248, 65, 229, 127, 9, 170, 162, 88, 87, 84, 92, 7,
	142, 135, 35, 143, 63, 28, 14, 105, 230, 96, 63, 204,
	167, 45, 28, 178, 223, 26, 218, 1, 11, 161, 148, 143,
	153, 44, 29, 237, 80, 141, 212, 99, 204, 27, 26, 253,
	190, 135, 90, 131, 5, 25, 123, 188, 111, 31, 159, 133,
	18, 231, 16, 123, 233, 98, 54, 160, 217, 231, 1, 125,
	158, 5, 254, 20, 23, 41, 168, 43, 148, 115, 50, 247,
	217, 12, 241, 203, 150, 90, 84, 2, 120, 71, 193, 84,
	164, 10, 80, 83, 32, 251, 4, 31, 65, 169, 103, 56,
	232, 4, 178, 113, 167, 114, 32, 187, 125, 41, 87, 208,
	30, 251, 254, 83, 92, 208, 197, 95, 125, 168, 53, 53,
	247, 211, 6, 124, 38, 30, 154, 102, 83, 59, 83, 0,
	45, 163, 205, 190, 68, 183, 241, 192, 84, 152, 60, 180,
	129, 182, 21, 188, 159, 191, 158, 147, 99, 34, 6, 124,
	12, 81, 221, 9, 95, 160, 149, 92, 43, 203, 117, 46,
	31, 75, 99, 185, 23, 48, 234, 215, 88, 131, 3, 1,
	56, 178, 19, 123, 118, 200, 178, 9, 62, 237, 165, 117,
	6, 136, 8, 46, 209, 12, 21, 190, 40, 110, 22, 44,
	33, 240, 74, 88, 163, 197, 18, 77, 238, 65, 108, 107,
	233, 97, 208, 7, 158, 99, 195, 99, 149, 149, 92, 193,
	58, 29, 40, 64, 79, 251, 28, 1, 20, 37, 245, 93,
	218, 20, 21, 223, 19, 53, 129, 225, 27, 174, 157, 240,
	48, 55, 205, 115, 200, 254, 26, 111, 246, 191, 209, 161,
	36, 16, 122, 169, 109, 232, 165, 193, 97, 223, 213, 67,
	50, 37, 116, 198, 146, 220, 93, 53, 36, 5, 155, 69,
	39, 201, 47, 167, 73, 242, 230, 135, 134, 240, 9, 242,
	130, 139, 1, 217, 245, 133, 28, 224, 188, 27, 133, 80,
	219, 211, 157, 92, 50, 97, 178, 226, 119, 22, 150, 44,
	62, 206, 23, 222, 155, 197, 221, 116, 129, 214, 187, 221,
	250, 44, 104, 60, 250, 153, 141, 229, 104, 142, 120, 186,
	140, 56, 70, 109, 202, 140, 39, 36, 242, 28, 124, 162,
	107, 131, 232, 28, 145, 133, 81, 90, 20, 40, 214, 149,
	175, 175, 5, 107, 116, 230, 221, 2, 67, 131, 140, 159,
	35, 119, 211, 113, 131, 252, 75, 195, 149, 167, 234, 251,
	225, 40, 180, 5, 102, 70, 4, 117, 178, 153, 103, 68,
	220, 75, 2, 117, 207, 136, 160, 167, 140, 90, 161, 214,
	52, 142, 43, 103, 198, 209, 127, 118, 16, 53, 199, 45,
	157, 109, 99, 167, 7, 222, 227, 198, 154, 191, 181, 126,
	158, 127, 227, 231, 77, 203, 22, 122, 11, 167, 156, 167,
	189, 220, 170, 140, 219, 142, 135, 28, 16, 178, 126, 173,
	30, 164, 30, 176, 167, 71, 173, 222, 231, 157, 178, 33,
	149, 78, 144, 41, 72, 79, 228, 13, 136, 152, 94, 93,
	208, 219, 63, 255, 233, 143, 131, 182, 180, 5, 234, 95,
	172, 57, 193, 194, 52, 194, 212, 130, 177, 182, 46, 75,
	83, 161, 80, 223, 4, 67, 239, 166, 207, 6, 132, 223,
	36, 252, 102, 89, 181, 247, 31, 231, 71, 201, 38, 14,
	79, 15, 124, 236, 30, 8, 180, 249, 174, 212, 228, 84,
	16, 74, 124, 152, 56, 239, 38, 62, 82, 147, 203, 230,
	126, 114, 25, 18, 90, 175, 248, 239, 202, 249, 183, 220,
	235, 131, 116, 66, 163, 35, 110, 2, 242, 143, 168, 224,
	42, 148, 199, 208, 31, 185, 14, 81, 101, 93, 7, 131,
	136, 26, 33, 224, 28, 98, 222, 234, 184, 58, 20, 21,
	108, 240, 79, 38, 141, 128, 58, 150, 91, 18, 172, 107,
	146, 194, 15, 164, 208, 121, 217, 150, 255, 169, 239, 182,
	35, 108, 179, 103, 168, 40, 158, 221, 208, 237, 123, 112,
	230, 167, 124, 58, 68, 241, 43, 132, 170, 193, 225, 233,
	131, 198, 150, 109, 48, 152, 208, 86, 43, 109, 155, 35,
	179, 207, 183, 159, 38, 179, 241, 44, 138, 63, 248, 253,
	32, 138, 167, 99, 250, 149, 62, 77, 230, 227, 79, 183,
	244, 91, 156, 254, 203, 255, 188, 142, 226, 49, 77, 222,
	207, 231, 201, 244, 118, 214, 200, 92, 141, 127, 74, 14,
	18, 81, 204, 188, 188, 132, 241, 1, 134, 201, 39, 80,
	233, 235, 206, 235, 255, 7, 118, 213, 129, 253, 7, 99,
	188, 12, 237, 9, 184, 76, 102, 23, 211, 177, 199, 60,
	40, 178, 82, 84, 217, 6, 188, 113, 41, 182, 132, 113,
	71, 147, 34, 219, 64, 207, 52, 32, 197, 17, 102, 129,
	223, 92, 246, 218, 148, 86, 217, 62, 175, 160, 149, 245,
	37, 92, 12, 176, 175, 42, 16, 142, 98, 241, 51, 159,
	7, 143, 105, 41, 48, 85, 107, 181, 41, 195, 188, 227,
	118, 136, 126, 109, 81, 95, 126, 168, 52, 72, 6, 181,
	136, 222, 240, 132, 51, 32, 26, 205, 139, 46, 166, 9,
	159, 106, 13, 180, 220, 84, 177, 1, 250, 105, 171, 229,
	142, 99, 207, 107, 102, 37, 50, 8, 160, 11, 122, 160,
	198, 71, 159, 30, 214, 123, 228, 147, 164, 147, 35, 112,
	92, 180, 168, 113, 52, 223, 151, 138, 187, 238, 254, 137,
	13, 118, 99, 234, 45, 47, 50, 116, 95, 27, 86, 201,
	203, 249, 1, 252, 224, 51, 175, 216, 118, 35, 209, 179,
	179, 176, 107, 130, 244, 201, 36, 122, 207, 88, 62, 72,
	188, 33, 77, 63, 80, 207, 111, 149, 61, 206, 91, 190,
	172, 238, 123, 17, 79, 242, 60, 132, 192, 95, 138, 138,
	241, 202, 218, 129, 246, 64, 101, 3, 1, 101, 77, 111,
	171, 100, 86, 87, 22, 215, 116, 136, 32, 151, 117, 187,
	147, 237, 76, 245, 133, 27, 100, 174, 32, 136, 33, 187,
	31, 68, 97, 8, 235, 103, 14, 98, 216, 230, 223, 40,
	14, 41, 19, 50, 16, 101, 48, 155, 97, 177, 198, 55,
	73, 133, 133, 97, 82, 153, 117, 37, 10, 172, 7, 28,
	124, 63, 131, 209, 201, 230, 147, 16, 231, 244, 239, 233,
	16, 52, 148, 209, 167, 218, 1, 9, 172, 248, 175, 18,
	42, 48, 157, 248, 191, 240, 29, 72, 177, 10, 127, 100,
	138, 51, 63, 83, 111, 64, 189, 230, 48, 62, 123, 120,
	224, 182, 231, 217, 157, 230, 17, 233, 186, 88, 162, 97,
	51, 147, 13, 253, 29, 52, 54, 113, 18, 66, 73, 179,
	61, 150, 131, 199, 94, 71, 69, 210, 85, 225, 167, 58,
	218, 127, 58, 196, 84, 199, 4, 65, 118, 227, 24, 114,
	210, 61, 137, 188, 176, 212, 74, 242, 248, 175, 183, 194,
	175, 59, 60, 103, 125, 34, 159, 36, 211, 4, 185, 134,
	117, 53, 172, 185, 111, 186, 62, 93, 117, 21, 174, 212,
	35, 107, 107, 246, 254, 255, 174, 206, 203, 181, 159, 7,
	3, 63, 122, 158, 81, 220, 85, 115, 221, 85, 179, 20,
	86, 101, 47, 59, 229, 197, 158, 247, 232, 195, 55, 30,
	205, 121, 15, 229, 85, 148, 63, 186, 176, 100, 226, 131,
	178, 171, 127, 210, 213, 207, 211, 249, 5, 245, 255, 1,
	245, 155, 11, 110, 61, 15, 0, 0,
};

static void write_file_bin(const char *path, const unsigned char *data, size_t len)
{
	FILE *f = fopen(path, "wb");
	if (!f) { fails++; printf("FAIL: cannot write %s\n", path); return; }
	fwrite(data, 1, len, f);
	fclose(f);
}

/* ==== tests =============================================================== */

static void test_finds_and_formats_frobnicate(void)
{
	char *argv[3];
	argv[0] = (char *)"man"; argv[1] = (char *)"frobnicate"; argv[2] = 0;
	CHECK(run(man_path, argv) == 0);
	slurp_both();

	/* Header/footer from .TH. */
	CHECK(out_contains("FROBNICATE(1)"));
	CHECK(out_contains("spicule Test Suite"));

	/* .SH/.SS headings and body text reach the page at all.
	 * "Subsection Heading" is bold (every .SS heading is), so it is
	 * checked against plainbuf (de-overstruck), not the raw bytes --
	 * see plainbuf's own comment for why. */
	CHECK(out_contains("exercise every supported macro"));
	CHECK(plain_contains("Subsection Heading"));
	CHECK(out_contains("Body text under a subsection."));

	/* .B/.I/.BR: bold text renders as overstrike (X\bX) since stdout
	 * here is a captured file, not a terminal -- see src/util/man.c's
	 * own header comment ("RENDERING") for why that's the correct
	 * choice, not a bug. "bold" -> "b\bbo\bo...", checked against the
	 * RAW bytes specifically to prove the overstrike encoding itself
	 * is really being produced. */
	CHECK(out_contains("b\bbo\bol\bld\bd"));
	/* .I italic -> underline-style overstrike, shadow character
	 * FIRST: "italic" -> "_\bi_\bt...". */
	CHECK(out_contains("_\bi"));

	/* \(bu / \(co glyphs decoded to real UTF-8 bytes -- both are bold
	 * here (`.RB ( \(bu )` alternates roman/BOLD/roman), so each
	 * glyph's individual bytes are themselves overstruck; check
	 * plainbuf, where the collapse reassembles the clean UTF-8
	 * sequence. */
	CHECK(plain_contains("\xE2\x80\xA2")); /* bullet */
	CHECK(plain_contains("\xC2\xA9"));     /* copyright sign */

	/* \*(xx (unsupported string register) vanished without leaving
	 * raw escape syntax in the output. */
	CHECK(!out_contains("\\*(xx"));
	CHECK(out_contains("that must vanish silently."));

	/* .TP: a short tag shares the body's first output line; a too-
	 * long tag gets its own line, with the body starting fresh below
	 * it -- both cases' tag text must appear. The tag itself is bold
	 * (`.B ...`). */
	CHECK(out_contains("A short tag."));
	CHECK(plain_contains("-a-very-long-option-name-that-does-not-fit-the-tag-column"));
	CHECK(out_contains("must start on its own line"));

	/* .IP with \(bu bullets, including one nested inside .RS/.RE. */
	CHECK(out_contains("A bulleted item using"));
	CHECK(out_contains("A nested item, one"));

	/* .nf/.fi: internal multiple spaces preserved verbatim (fill mode
	 * would have collapsed them to one). */
	CHECK(out_contains("literal   line    one"));
	CHECK(out_contains("    literal line two, indented"));
	/* Immediately after .fi, ordinary fill-mode wrapping resumes. */
	CHECK(out_contains("Back to normal filled text after .fi."));

	/* .br kept the two SYNOPSIS forms on separate lines rather than
	 * flowing "target frobnicate --help" together. Both are styled
	 * (.I target, .B --help). */
	CHECK(plain_contains("target"));
	CHECK(plain_contains("--help"));
}

/* .ds/.nr/.rn and \* / \n interpolation, real end-to-end -- see
 * FROBNICATE_1's own "REGISTERS" section. Each label:value pair sits
 * on its own line via .br, so a value never lands split across a
 * word-wrap boundary. */
static void test_registers(void)
{
	char *argv[3];
	argv[0] = (char *)"man"; argv[1] = (char *)"frobnicate"; argv[2] = 0;
	CHECK(run(man_path, argv) == 0);
	slurp_both();

	/* .ds GREETING hello register world, then \*[GREETING] -- the
	 * bracket name form, since GREETING is longer than the two
	 * characters the \*(xx paren form reads. */
	CHECK(plain_contains("String register: hello register world"));

	/* .nr COUNT 5, then \n[COUNT]. */
	CHECK(plain_contains("Number register: 5"));

	/* .nr COUNT +3 (relative add onto the current value 5), then
	 * \n[COUNT] again -- proves the register was actually updated, not
	 * just re-set to 3. */
	CHECK(plain_contains("Relative increment: 8"));

	/* .rn COUNT KOUNT, then \n[KOUNT] reads the renamed register's
	 * value, and \n[COUNT] (the old name) is undefined again -- 0,
	 * exactly as if COUNT had never been defined at all. */
	CHECK(plain_contains("Renamed register: 8"));
	CHECK(plain_contains("Old name after rename: 0"));

	/* A number register that was never defined at all: 0, not an
	 * error and not the raw escape syntax. */
	CHECK(plain_contains("Undefined number register: 0"));

	/* \n(.g: the built-in "is this groff" register -- see src/util/
	 * man.c's own header comment ("REGISTERS") for why this file
	 * answers 1. */
	CHECK(plain_contains("Groff detection register: 1"));
}

/* Real .de/.de1/.am/.am1/.ig, macro invocation, $0/$1-$9/$* argument
 * substitution, .rm/.rn/.als, and the two formatter fidelity fixes
 * (.RB per-word alternation, \c join suppression) -- see MACROTEST_1's
 * own header comment. */
static void test_macros(void)
{
	char *argv[3];
	argv[0] = (char *)"man"; argv[1] = (char *)"macrotest"; argv[2] = 0;
	CHECK(run(man_path, argv) == 0);
	slurp_both();

	/* .de greet + .greet World extra: $1 and $* both substitute the
	 * invoking line's own raw arguments. */
	CHECK(plain_contains("Hello, World! Args: World extra"));

	/* .de1 greet2 + .greet2 Bob: $0 is the name the macro was invoked
	 * as, $1 the first argument; .de1 behaves exactly like .de here
	 * (see src/util/man.c's own header comment, "MACROS"). Bold, so
	 * checked de-overstruck. */
	CHECK(plain_contains("greet2 says hi to Bob"));

	/* .am greet appends a second body line onto the existing one
	 * without discarding it: .greet Carol must show BOTH the original
	 * template (with Carol substituted) and the newly appended one. */
	CHECK(plain_contains("Hello, Carol! Args: Carol"));
	CHECK(plain_contains("More appended text for Carol."));

	/* .ig discards its body for real: never stored, never invokable,
	 * and its literal text never leaks into output either. */
	CHECK(!out_contains("This should never appear"));

	/* .rm greet2, then invoking it again: unknown macro, silently
	 * skipped like any other unrecognised request -- its argument
	 * text must not appear anywhere (the line is never processed as
	 * an invocation, since there is nothing left to invoke). */
	CHECK(!out_contains("ShouldBeSkipped"));

	/* .als aliasgreet greet takes an INDEPENDENT COPY of greet's
	 * current (already-.am-appended) body; .rn greet renamedgreet
	 * then renames the original away entirely. Both the renamed
	 * macro and the alias must still work afterward, and both must
	 * still carry the appended second line -- proving the alias
	 * really copied, rather than merely referencing, OLD's body. */
	CHECK(plain_contains("Hello, Dave! Args: Dave"));
	CHECK(plain_contains("More appended text for Dave."));
	CHECK(plain_contains("Hello, Eve! Args: Eve"));
	CHECK(plain_contains("More appended text for Eve."));

	/* Fidelity fix 1: .RB "wordone wordtwo" "wordthree" alternates
	 * roman/bold PER WORD across the whole call, not per argv[]
	 * token -- wordtwo (the second word, still inside the first
	 * quoted argument) is bold, and wordthree (a whole separate
	 * argument) continues the same cycle back to roman with NO
	 * separator at that argument boundary, while the real space
	 * between wordone/wordtwo (from inside one quoted argument) is
	 * still preserved. The de-overstruck plain text alone proves
	 * both halves: the space survives, the arg-boundary concatenation
	 * doesn't gain one. */
	CHECK(plain_contains("wordone wordtwowordthree"));
	/* And the raw bytes prove wordtwo specifically carries bold
	 * overstrike (its own d->t letter boundary), the same style this
	 * file's own existing "bold" assertion already relies on. */
	CHECK(out_contains("d\bdt\bt"));

	/* Fidelity fix 2: \c at the end of one macro call's decoded text
	 * suppresses the join-space before the NEXT accumulated content --
	 * .B contfoo\c immediately followed by .I contbar must render as
	 * one unbroken "contfoocontbar", while the same shape without \c
	 * (.B nofoo / .I nobar) keeps its normal single join-space. */
	CHECK(plain_contains("contfoocontbar"));
	CHECK(plain_contains("nofoo nobar"));
}

/* Real .if/.ie/.el evaluation -- see CONDTEST_1's own header comment
 * for exactly what each pair exercises. Each label:value pair sits on
 * its own line via .br, same "never split across a word-wrap boundary"
 * reasoning FROBNICATE_1's own REGISTERS section already documents;
 * a register that a FALSE condition never defines resolves to empty
 * (Tier 1's own undefined-string-register behaviour), so its absence
 * from the output IS the assertion for the "false" half of every pair. */
static void test_conditionals(void)
{
	char *argv[3];
	argv[0] = (char *)"man"; argv[1] = (char *)"condtest"; argv[2] = 0;
	CHECK(run(man_path, argv) == 0);
	slurp_both();

	/* .if \n(x>5 (10>5, true) vs .if \n(x>50 (false): only the true
	 * branch's .ds ever runs. */
	CHECK(plain_contains("numeric-gt-true"));
	CHECK(!out_contains("numeric-gt-false"));

	/* .if (\n(x-5)>4 -- parenthesized arithmetic (10-5=5, 5>4 true),
	 * proving the numeric evaluator's grammar, not just bare compares. */
	CHECK(plain_contains("paren-arith-true"));

	/* .if \n(x=10 (true) vs .if \n(x=11 (false). */
	CHECK(plain_contains("numeric-eq-true"));
	CHECK(!out_contains("numeric-eq-false"));

	/* .if 'abc'abc' (true) vs .if 'abc'xyz' (false): quoted-delimiter
	 * string equality. */
	CHECK(plain_contains("string-eq-true"));
	CHECK(!out_contains("string-eq-false"));

	/* .if !'abc'xyz' -- ! negates a false string comparison to true. */
	CHECK(plain_contains("negated-neq-true"));

	/* .if n (true: this file only ever emits nroff-style output) vs
	 * .if t (always false -- never real typeset troff output). */
	CHECK(plain_contains("nroff-true"));
	CHECK(!out_contains("troff-true"));

	/* .if o (true: page 1 is odd, this file's own stable documented
	 * answer) vs .if e (false, the exact complement). */
	CHECK(plain_contains("odd-page-true"));
	CHECK(!out_contains("even-page-true"));

	/* .ie \n(x=10 .ds iebranch ie-true-branch / .el ... el-branch: the
	 * .ie branch (true) runs, NOT the paired .el. */
	CHECK(plain_contains("ie-true-branch"));
	CHECK(!out_contains("el-branch"));

	/* .ie \n(xx=99 (false) / .el ...: this time the PAIRED .el runs
	 * instead, proving .el really does track its own .ie's outcome
	 * rather than always running or never running. Distinct label text
	 * from the pair above (not "ie-true-branch2"/"el-branch2") so
	 * neither substring-collides with "ie-true-branch"/"el-branch". */
	CHECK(!out_contains("ie-alt-branch"));
	CHECK(plain_contains("el-alt-branch"));

	/* .if \n(x>5 \{ ... \}: a true multi-line block runs both of its
	 * lines. */
	CHECK(plain_contains("block-line-one"));
	CHECK(plain_contains("block-line-two"));

	/* .if \n(x>500 \{ ... \}: a false multi-line block runs neither --
	 * its own .ds never executes, so the register stays undefined. */
	CHECK(!out_contains("should-not-appear"));

	/* .ie \n(x>5 \{ ... nested .if \n(x>0 \{ ... \} ... \} .el \{ ... \}:
	 * the outer .ie's TRUE branch runs (nest-true-outer, not
	 * nest-false-outer from the paired .el, which must not run at all),
	 * and the block nested inside it ALSO evaluates for real
	 * (nest-true-inner) -- proving nested \{ \} depth-tracking during
	 * both collection and replay, not just a single flat level. */
	CHECK(plain_contains("nest-true-outer"));
	CHECK(!out_contains("nest-false-outer"));
	CHECK(plain_contains("nest-true-inner"));
}

/* ---- small layout-inspection helpers for test_tables() below ----------
 * Table rendering is column-positional in a way plain_contains()/
 * out_contains() can't check (e.g. "these two numbers' decimal points
 * land in the same output column", "this specific line has no box
 * characters on it") -- these walk `buf` line by line the same way
 * strip_overstrike() above already does. */

/* Returns a pointer to the start of the first line in `buf` containing
 * `needle`, or NULL. */
static const char *find_line(const char *buf, const char *needle)
{
	const char *p = buf;
	size_t nlen = strlen(needle);
	while (*p) {
		const char *nl = strchr(p, '\n');
		size_t linelen = nl ? (size_t)(nl - p) : strlen(p);
		size_t k;
		for (k = 0; k + nlen <= linelen; k++)
			if (!memcmp(p + k, needle, nlen)) return p;
		if (!nl) break;
		p = nl + 1;
	}
	return 0;
}

/* Offset of the first '.' within the line starting at `line_start`
 * (not searching past its own '\n'), or -1 if that line has none. */
static long dot_offset(const char *line_start)
{
	const char *nl = strchr(line_start, '\n');
	size_t linelen = nl ? (size_t)(nl - line_start) : strlen(line_start);
	size_t i;
	for (i = 0; i < linelen; i++) if (line_start[i] == '.') return (long)i;
	return -1;
}

/* True if the line starting at `line_start` contains `ch` before its
 * own '\n' -- used to prove a box-less table's rows carry no stray
 * '|'/'+' box-drawing characters. */
static int line_has_char(const char *line_start, char ch)
{
	const char *nl = strchr(line_start, '\n');
	size_t linelen = nl ? (size_t)(nl - line_start) : strlen(line_start);
	size_t i;
	for (i = 0; i < linelen; i++) if (line_start[i] == ch) return 1;
	return 0;
}

/* True if the line starting at `line_start` contains `needle` before
 * its own '\n' -- a line-bounded strstr(), not memmem() (this test
 * file's own default `make check` build has no _XOPEN_SOURCE/
 * _GNU_SOURCE feature-test macro defined -- see this file's own
 * top-of-file comment on test_envp -- so memmem() isn't declared
 * there). */
static int line_has_substr(const char *line_start, const char *needle)
{
	const char *nl = strchr(line_start, '\n');
	size_t linelen = nl ? (size_t)(nl - line_start) : strlen(line_start);
	size_t nlen = strlen(needle);
	size_t k;
	for (k = 0; k + nlen <= linelen; k++)
		if (!memcmp(line_start + k, needle, nlen)) return 1;
	return 0;
}

/* Length of the line starting at `line_start`, up to (not including)
 * its own '\n' -- used to prove real fill-and-adjust justification
 * pads a line out to an exact column count, not merely "somewhere". */
static size_t line_len(const char *line_start)
{
	const char *nl = strchr(line_start, '\n');
	return nl ? (size_t)(nl - line_start) : strlen(line_start);
}

/* Counts lines in `buf` whose first non-space character is `ch` --
 * every man_tbl_emit_border() line (top/bottom border, `_`/`=` rule
 * row, and each allbox inter-row separator) starts with '+', so this
 * counts exactly how many border/rule lines a table rendered. */
static int count_lines_starting_with(const char *buf, char ch)
{
	int count = 0;
	const char *p = buf;
	while (*p) {
		const char *q = p;
		while (*q == ' ') q++;
		if (*q == ch) count++;
		{
			const char *nl = strchr(p, '\n');
			if (!nl) break;
			p = nl + 1;
		}
	}
	return count;
}

static void test_tables(void)
{
	const char *gamma_line, *total_line, *one_line;
	char *argv[3];
	argv[0] = (char *)"man"; argv[1] = (char *)"tbltest"; argv[2] = 0;
	CHECK(run(man_path, argv) == 0);
	slurp_both();

	/* Table 1 (boxed): the "c s s" title row's own single field
	 * ("Element Summary") must render whole -- the `s` columns beside
	 * it consume no data field of their own (see src/util/man.c's own
	 * "TABLES" header comment) -- and every later row's real content
	 * must appear, proving field-to-column assignment survived a
	 * format line with spans in it. */
	CHECK(plain_contains("Element Summary"));
	CHECK(plain_contains("Name") && plain_contains("Kind") && plain_contains("Bytes"));
	CHECK(plain_contains("Alpha") && plain_contains("int"));
	CHECK(plain_contains("Beta") && plain_contains("long"));
	CHECK(plain_contains("Gamma") && plain_contains("double"));
	CHECK(plain_contains("Total"));

	CHECK(out_contains("|"));

	/* Real decimal-point column alignment: Gamma's "3.5" and the
	 * final row's "46.5" are both real (non-span, non-blank) cells in
	 * the same numeric column, so their '.' must land in the exact
	 * same output column -- not just "both present somewhere". */
	gamma_line = find_line(plainbuf, "Gamma");
	total_line = find_line(plainbuf, "46.5");
	CHECK(gamma_line != 0 && total_line != 0);
	if (gamma_line && total_line) {
		long gdot = dot_offset(gamma_line), tdot = dot_offset(total_line);
		CHECK(gdot > 0 && gdot == tdot);
	}

	/* Table 1's final row ("Total\t\t46.5") has a genuinely EMPTY
	 * middle field (two adjacent tabs) -- Total's own Kind column must
	 * be blank, not "double" or "long" leaking down from an earlier
	 * row. */
	total_line = find_line(plainbuf, "Total");
	CHECK(total_line != 0);
	if (total_line) CHECK(!line_has_substr(total_line, "double") && !line_has_substr(total_line, "long"));

	CHECK(plain_contains("Text after the boxed table must still render normally."));

	/* Table 2: no options line at all -- plain rendering must carry
	 * NO box-drawing characters on its own data rows. */
	CHECK(plain_contains("Plain") && plain_contains("NoBox"));
	one_line = find_line(plainbuf, "one");
	CHECK(one_line != 0);
	if (one_line) CHECK(!line_has_char(one_line, '|') && !line_has_char(one_line, '+'));
	CHECK(plain_contains("two"));
	CHECK(plain_contains("Text after the second, box-less table."));

	/* Table 3: `allbox tab(:);` -- two option keywords on one options
	 * line, AND a custom `:` field separator instead of a literal tab
	 * (proving man_render_table() actually switched its split
	 * character, not just parsed and ignored `tab(:)`). */
	CHECK(plain_contains("Col1") && plain_contains("Col2"));
	CHECK(plain_contains("xray") && plain_contains("yankee"));
	CHECK(plain_contains("papa") && plain_contains("quebec"));
	CHECK(plain_contains("Text after the third, allbox/custom-separator table."));

	/* Every man_tbl_emit_border() line (top/bottom borders, `_`/`=`
	 * rule rows, allbox inter-row separators) starts with '+' -- a
	 * page-wide count proves both boxed tables drew exactly the
	 * border/rule lines this fixture's own shape calls for, and that
	 * table 2 (no box option at all) drew none of its own: table 1
	 * contributes 3 (top border, the `_` rule row, bottom border);
	 * table 2 contributes 0; table 3 (`allbox`, 3 data rows, no rule
	 * rows) contributes 4 (top border, one separator after each of
	 * its first two rows, bottom border). */
	CHECK(count_lines_starting_with(plainbuf, '+') == 3 + 0 + 4);
}

static void test_eqn(void)
{
	char *argv[3];
	argv[0] = (char *)"man"; argv[1] = (char *)"eqntest"; argv[2] = 0;
	CHECK(run(man_path, argv) == 0);
	slurp_both();

	/* The canonical quadratic-formula example, proof that `over` binds
	 * to the bracketed numerator group alone -- "x =" must stay OUTSIDE
	 * the fraction, not get pulled inside it -- see src/util/man.c's own
	 * man_eqn_parse_over() header comment. */
	CHECK(plain_contains("x = (-b +- sqrt(b^2 - 4 ac))/(2 a)"));

	/* Greek-letter lookup (lowercase `alpha`, uppercase `GAMMA`,
	 * rendered as real UTF-8 codepoints -- see man_eqn_greek[]) beside
	 * a real subscript. */
	CHECK(plain_contains("\xCE\xB1_i + \xCE\x93"));

	/* Left-associative chained `over`: `a over b over c` -> "(a/b)/c",
	 * not "a/(b/c)". */
	CHECK(plain_contains("(a/b)/c"));

	/* `sqrt` on a bare primary. */
	CHECK(plain_contains("sqrt(x)"));

	/* `sub`/`sup` combine onto the SAME primary regardless of which one
	 * appears first in the source. */
	CHECK(plain_contains("x_i^2"));

	/* A `"quoted"` literal is exempt from Greek-letter lookup (stays
	 * the literal word "pi"), while the same BARE word beside it is
	 * looked up as the letter. */
	CHECK(plain_contains("pi + \xCF\x80"));

	/* `delim $$` is a recognised-and-consumed mode-setting directive --
	 * see "EQN" in src/util/man.c's own header comment -- and must
	 * produce no visible output of its own anywhere on the page. */
	CHECK(!plain_contains("delim"));

	CHECK(plain_contains("Text after the equations must still render normally."));
}

static void test_adjustment(void)
{
	const char *b1, *b2, *n1, *n2;
	char *argv[3];
	argv[0] = (char *)"man"; argv[1] = (char *)"adjusttest"; argv[2] = 0;
	CHECK(run(man_path, argv) == 0);
	slurp_both();

	b1 = find_line(plainbuf, "AdjustBXXX1");
	b2 = find_line(plainbuf, "AdjustBXXX7");
	n1 = find_line(plainbuf, "AdjustNXXX1");
	n2 = find_line(plainbuf, "AdjustNXXX7");
	CHECK(b1 != 0 && b2 != 0 && n1 != 0 && n2 != 0);
	if (b1 && b2 && n1 && n2) {
		/* `.ad b`'s own first (non-last) output line is real
		 * justification: padded flush to this file's default
		 * 80-column terminal width -- indent(7) + cols(73), an exact
		 * right margin, not merely "some extra space appeared". */
		CHECK(line_len(b1) == 80);
		/* `.na`'s own first line -- the SAME six words, at the SAME
		 * indent and column budget -- stays ragged (this file's
		 * long-standing pre-Tier-7 default): 2 columns short of the
		 * full width, exactly the slack `.ad b` above distributed as
		 * real inter-word padding instead. */
		CHECK(line_len(n1) == 78);
		CHECK(line_len(b1) - line_len(n1) == 2);
		/* A justified line's slack shows up as an inter-word gap
		 * wider than one space -- proof it was actually distributed
		 * as padding, not just that the line happens to be 80
		 * columns some other way. */
		CHECK(line_has_substr(b1, "  "));
		/* Real troff never stretches a fill span's own LAST line to
		 * the right margin, even under `.ad b` -- both variants'
		 * final line (3 words, nowhere near the 73-column budget)
		 * must come out byte-for-byte the same length. */
		CHECK(line_len(b2) == line_len(n2));
		CHECK(line_len(b2) < 80);
	}
}

static void test_hyphenation(void)
{
	const char *p1, *p1n, *p2, *p2n, *p3, *p3n, *p4, *p5, *p5n;
	char *argv[3];
	argv[0] = (char *)"man"; argv[1] = (char *)"hyphtest"; argv[2] = 0;
	CHECK(run(man_path, argv) == 0);
	slurp_both();

	p1 = find_line(plainbuf, "P1FillerFF");
	CHECK(p1 != 0);
	if (p1) {
		p1n = p1 + line_len(p1) + 1;
		/* `.hy`'s own real Knuth-Liang split: this file's own ".under3"
		 * prefix pattern breaks "understanding" as "under-"/"standing"
		 * -- see HYPHTEST_1's own comment for the column arithmetic
		 * that forces this exact split point. */
		CHECK(line_has_substr(p1, "under-"));
		CHECK(!line_has_substr(p1, "understanding"));
		CHECK(line_has_substr(p1n, "standing"));
	}

	p2 = find_line(plainbuf, "P2FillerFF");
	CHECK(p2 != 0);
	if (p2) {
		p2n = p2 + line_len(p2) + 1;
		/* `.nh`: the identical overflow shape as P1, but hyphenation
		 * off -- the whole word is deferred to the next line, never
		 * split, proving `.nh` actually suppresses P1's behaviour
		 * rather than P1's split being some unrelated coincidence. */
		CHECK(!line_has_substr(p2, "under-"));
		CHECK(line_has_substr(p2n, "understanding"));
	}

	p3 = find_line(plainbuf, "P3FillerFF");
	CHECK(p3 != 0);
	if (p3) {
		p3n = p3 + line_len(p3) + 1;
		/* `.hy` is on and the overflow shape is identical to P1, but
		 * "understanding" is this paragraph's own LAST word -- this
		 * file's documented "never hyphenate a paragraph's last word"
		 * rule means it is deferred whole, exactly like P2 above. */
		CHECK(!line_has_substr(p3, "under-"));
		CHECK(line_has_substr(p3n, "understanding"));
	}

	p4 = find_line(plainbuf, "with the word");
	CHECK(p4 != 0);
	if (p4) {
		/* A word that already fits the line is never hyphenated, even
		 * with `.hy` on -- hyphenation only ever answers "how do I
		 * place a word that doesn't fit". */
		CHECK(line_has_substr(p4, "understanding"));
		CHECK(!line_has_substr(p4, "under-"));
	}

	p5 = find_line(plainbuf, "P5FillerFF");
	CHECK(p5 != 0);
	if (p5) {
		p5n = p5 + line_len(p5) + 1;
		/* Regression case for a fixed stack-buffer overflow: the word
		 * being split here is exactly 54 ASCII letters -- the longest
		 * man_hyph_word_ok() ever accepts -- which makes man_hyph_
		 * find_points()'s own dotted-word length (wlen + 2) land on
		 * exactly MAN_HYPH_MAX_WORD, one past the end of that
		 * function's un-fixed `vals[]`. The correct result is still
		 * the same "under-" split point P1 above exercises. */
		CHECK(line_has_substr(p5, "under-"));
		CHECK(!line_has_substr(p5, "understandingstanding"));
		CHECK(line_has_substr(p5n, "standingstanding"));
	}
}

static void test_section_operand_restricts_search(void)
{
	char *argv[4];
	argv[0] = (char *)"man"; argv[1] = (char *)"1"; argv[2] = (char *)"frobnicate"; argv[3] = 0;
	CHECK(run(man_path, argv) == 0);
	slurp_both();
	CHECK(out_contains("FROBNICATE(1)"));
}

static void test_no_such_page(void)
{
	char *argv[3];
	argv[0] = (char *)"man"; argv[1] = (char *)"this-utility-does-not-exist"; argv[2] = 0;
	CHECK(run(man_path, argv) != 0);
	slurp_both();
	CHECK(err_contains("No manual entry"));
}

static void test_apropos_dash_k(void)
{
	char *argv[4];
	argv[0] = (char *)"man"; argv[1] = (char *)"-k"; argv[2] = (char *)"exercise"; argv[3] = 0;
	CHECK(run(man_path, argv) == 0);
	slurp_both();
	CHECK(out_contains("frobnicate(1)"));
}

/* Content is irrelevant here on purpose: this ".1.gz" page exists (so
 * man_find_one() finds it, Tier 4's own man_find_page() no longer
 * refuses a ".gz"-only page the way it used to) but is not real gzip
 * data, so man_gunzip() must reject it -- a bad magic number, since
 * the file is empty and even the 10-byte fixed header doesn't fit.
 * Proves a corrupt/malformed gzip page is diagnosed and treated like
 * any other unreadable file (nonzero exit, one diagnostic mentioning
 * "gzip"), not a crash and not silently-wrong output reaching the
 * troff parser. */
static void test_corrupt_gzip_page_diagnosed(void)
{
	char gzpath[400];
	char *argv[3];
	snprintf(gzpath, sizeof gzpath, "%s/compressed-only.1.gz", man1dir);
	write_file(gzpath, "");

	argv[0] = (char *)"man"; argv[1] = (char *)"compressed-only"; argv[2] = 0;
	CHECK(run(man_path, argv) != 0);
	slurp_both();
	CHECK(err_contains("gzip"));
}

/* Shared assertions for GREP1_EXCERPT's real content, run after a
 * successful `man <name>` -- used both for the plain grep.1 fixture
 * and (Tier 4) its real gzip-compressed sibling below, so both prove
 * the exact same rendered output reaches the reader either way. */
static void check_grep1_rendered_correctly(void)
{
	/* Real header/footer, real NAME/SYNOPSIS/DESCRIPTION/OPTIONS
	 * content reaches the page despite the heavy .de/.ie/.ds/.nr
	 * boilerplate this file opens with. */
	CHECK(out_contains("GREP(1)"));
	CHECK(out_contains("print lines that match patterns"));
	CHECK(plain_contains("PATTERNS")); /* .I PATTERNS: italic throughout */
	CHECK(out_contains("extended regular expressions"));
	CHECK(out_contains("fixed strings, not regular expressions"));

	/* .TP tags from real .BR alternating-font option lists -- bold. */
	CHECK(plain_contains("--help"));
	CHECK(plain_contains("--version"));

	/* No raw troff syntax leaked into the rendered output: none of
	 * the unsupported .de/.ds/.nr/.ie machinery's own literal source
	 * text (which would look like corruption to a reader) appears. */
	CHECK(!out_contains(".de "));
	CHECK(!out_contains(".ds "));
	CHECK(!out_contains(".nr "));
	CHECK(!out_contains(".ie "));
	CHECK(!out_contains("\\\\$"));
	CHECK(!out_contains("mailto:"));

	/* Tier 2 proof against this same real, unmodified fixture: its own
	 * opening boilerplate defines `.de dT` (body: `.ds Dt \\$2`) then
	 * immediately invokes it as `.dT Time-stamp: "2025-03-21"` -- a
	 * real .de + macro invocation + $2 argument substitution + .ds
	 * chain that only runs end-to-end now that user macros are real.
	 * `.TH GREP 1 \*(Dt ...` then interpolates the date this set,
	 * landing it in the rendered footer. Before Tier 2, \*(Dt was an
	 * always-undefined string register (empty), so this date never
	 * appeared at all. */
	CHECK(out_contains("2025-03-21"));
}

static void test_real_grep1_excerpt(void)
{
	char *argv[3];
	argv[0] = (char *)"man"; argv[1] = (char *)"grep"; argv[2] = 0;
	CHECK(run(man_path, argv) == 0);
	slurp_both();
	check_grep1_rendered_correctly();
}

/* Tier 4: the exact same real content as test_real_grep1_excerpt()
 * above, but stored as GREP1_EXCERPT_GZ -- real gzip -9 output, a
 * different on-disk name ("grepz.1.gz", so man_find_one() cannot
 * accidentally resolve this to the plain "grep.1" fixture instead and
 * skip decompression entirely) -- proving man_gunzip() decompresses a
 * real compressor's real dynamic-Huffman-coded output correctly, all
 * the way through to identical rendered troff output. */
static void test_gzip_compressed_grep1_excerpt(void)
{
	char gzpath[400];
	char *argv[3];
	snprintf(gzpath, sizeof gzpath, "%s/grepz.1.gz", man1dir);
	write_file_bin(gzpath, GREP1_EXCERPT_GZ, sizeof GREP1_EXCERPT_GZ);

	argv[0] = (char *)"man"; argv[1] = (char *)"grepz"; argv[2] = 0;
	CHECK(run(man_path, argv) == 0);
	slurp_both();
	check_grep1_rendered_correctly();
}

/* Tier 4's other detection path: the SAME real gzip bytes, but stored
 * under a name with no ".gz" suffix at all ("grepnogz.1") -- man.c's
 * own header comment documents that a compressed page need not be
 * named ".gz" to be treated as one, matching real gzip(1)'s own
 * magic-number-first behaviour. man_find_one() finds this file
 * directly (it IS the plain expected path, no ".gz" fallback
 * involved) and man_read_page() must still recognise and decompress
 * it purely from its first two bytes. */
static void test_gzip_magic_detected_without_gz_suffix(void)
{
	char path[400];
	char *argv[3];
	snprintf(path, sizeof path, "%s/grepnogz.1", man1dir);
	write_file_bin(path, GREP1_EXCERPT_GZ, sizeof GREP1_EXCERPT_GZ);

	argv[0] = (char *)"man"; argv[1] = (char *)"grepnogz"; argv[2] = 0;
	CHECK(run(man_path, argv) == 0);
	slurp_both();
	check_grep1_rendered_correctly();
}

static void test_builtin_agrees_with_standalone(void)
{
	/* $MANPATH reaches sh.exe -c via test_envp, the same custom envp
	 * every run() call already uses -- no inline "MANPATH=... man ..."
	 * shell prefix needed. */
	CHECK(run_sh_c("man frobnicate") == 0);
	slurp_both();
	CHECK(out_contains("FROBNICATE(1)"));
	CHECK(out_contains("exercise every supported macro"));
}

/* ==== main ================================================================ */

static char manpath_entry[300];

int main(int argc, char **argv)
{
	(void)argc;

	if (find_obj_root(argv[0]) != 0) {
		printf("SKIP util-man: cannot locate obj/ from argv[0] \"%s\"\n",
			argv[0] ? argv[0] : "(null)");
		return 77;
	}
	path_for(man_path, sizeof man_path, "bin/man.exe");
	path_for(sh_path, sizeof sh_path, "sh/sh.exe");

	if (access(man_path, R_OK) != 0 || access(sh_path, R_OK) != 0) {
		printf("SKIP util-man: obj/bin/man.exe or obj/sh/sh.exe is missing\n");
		return 77;
	}

	snprintf(scratch, sizeof scratch, "man-scratch-%ld", (long)getpid());
	raw_rmtree(scratch);   /* in case a previous crashed run left one behind */
	if (mkdir(scratch, 0700) != 0) {
		printf("SKIP util-man: cannot create scratch directory \"%s\"\n", scratch);
		return 77;
	}
	snprintf(man1dir, sizeof man1dir, "%s/man1", scratch);
	if (mkdir(man1dir, 0700) != 0) {
		printf("SKIP util-man: cannot create \"%s\"\n", man1dir);
		raw_rmtree(scratch);
		return 77;
	}
	snprintf(outfile, sizeof outfile, "%s/out.txt", scratch);
	snprintf(errfile, sizeof errfile, "%s/err.txt", scratch);

	{
		char frobpath[400];
		snprintf(frobpath, sizeof frobpath, "%s/frobnicate.1", man1dir);
		write_file(frobpath, FROBNICATE_1);
	}
	{
		char macropath[400];
		snprintf(macropath, sizeof macropath, "%s/macrotest.1", man1dir);
		write_file(macropath, MACROTEST_1);
	}
	{
		char condpath[400];
		snprintf(condpath, sizeof condpath, "%s/condtest.1", man1dir);
		write_file(condpath, CONDTEST_1);
	}
	{
		char tblpath[400];
		snprintf(tblpath, sizeof tblpath, "%s/tbltest.1", man1dir);
		write_file(tblpath, TBLTEST_1);
	}
	{
		char eqnpath[400];
		snprintf(eqnpath, sizeof eqnpath, "%s/eqntest.1", man1dir);
		write_file(eqnpath, EQNTEST_1);
	}
	{
		char adjpath[400];
		snprintf(adjpath, sizeof adjpath, "%s/adjusttest.1", man1dir);
		write_file(adjpath, ADJUSTTEST_1);
	}
	{
		char hyphpath[400];
		snprintf(hyphpath, sizeof hyphpath, "%s/hyphtest.1", man1dir);
		write_file(hyphpath, HYPHTEST_1);
	}
	{
		char greppath[400];
		snprintf(greppath, sizeof greppath, "%s/grep.1", man1dir);
		write_grep1_excerpt(greppath);
	}

	/* Builds test_envp = environ + one extra "MANPATH=<scratch>" entry
	 * -- see test_envp's own comment above for why this is passed
	 * directly to __spawn() rather than mutating this process's
	 * environment via setenv()/putenv(). */
	{
		size_t n = 0, i;
		char **envp;
		while (environ && environ[n]) n++;
		envp = malloc((n + 2) * sizeof *envp);
		if (!envp) {
			printf("SKIP util-man: out of memory building envp\n");
			raw_rmtree(scratch);
			return 77;
		}
		for (i = 0; i < n; i++) envp[i] = environ[i];
		snprintf(manpath_entry, sizeof manpath_entry, "MANPATH=%s", scratch);
		envp[n] = manpath_entry;
		envp[n + 1] = 0;
		test_envp = envp;
	}

	test_finds_and_formats_frobnicate();
	test_registers();
	test_macros();
	test_conditionals();
	test_tables();
	test_eqn();
	test_adjustment();
	test_hyphenation();
	test_section_operand_restricts_search();
	test_no_such_page();
	test_apropos_dash_k();
	test_corrupt_gzip_page_diagnosed();
	test_real_grep1_excerpt();
	test_gzip_compressed_grep1_excerpt();
	test_gzip_magic_detected_without_gz_suffix();
	test_builtin_agrees_with_standalone();

	raw_rmtree(scratch);

	if (fails) { printf("%d check(s) failed\n", fails); return 1; }
	printf("ok\n");
	return 0;
}
