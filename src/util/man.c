/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * man(1p): find a manual page by name (and, as a near-universal
 * historical extension POSIX itself does not specify, by section) and
 * format it for the terminal.
 *
 * ============================================================
 * WHAT THIS IS, AND WHY IT IS SHAPED THIS WAY
 * ============================================================
 *
 * A real `man` has two separate jobs: FIND the right page, and FORMAT
 * it. Formatting means running a troff/groff interpreter over `man`-
 * or `mdoc`-macro-package source; a general troff engine is its own
 * enormous project and out of scope. In scope is a real parser and
 * formatter for the macro subset the overwhelming majority of real-
 * world man pages use: .TH, .SH/.SS, .TP/.IP, .PP/.LP, .B/.I and all
 * six alternating-font pairs (.BI/.BR/.IR/.IB/.RB/.RI, one shared
 * helper), .RS/.RE, .nf/.fi, .br (real pages routinely need it to keep
 * alternate SYNOPSIS forms on separate lines), .ad/.na (fill-and-adjust
 * justification -- see "ADJUSTMENT" below), .hy/.nh (hyphenation, a
 * documented Knuth-Liang-algorithm subset -- see "HYPHENATION" below),
 * .ds/.nr/.rn (string/number registers -- see "REGISTERS" below), .de/
 * .de1/.am/.am1/.ig/.rm/.als (user-defined macros -- see "MACROS"
 * below), .if/.ie/.el (conditionals -- see "CONDITIONALS" below), .TS/
 * .TE (tbl tables -- see "TABLES" below), .EQ/.EN (eqn equations, a
 * documented linear-approximation subset -- see "EQN" below), and a
 * common subset of escape sequences. This file IS that engine, not a
 * wrapper around a real one.
 *
 * ---- WHAT IS DELIBERATELY NOT IMPLEMENTED, AND WHY --------------------
 *
 *  - \k (mark register) and \s (point-size change): recognised and
 *    consumed only -- no horizontal-motion tracking or point-size
 *    concept exists here for them to act on.
 *
 * ---- UNKNOWN-MACRO DEGRADATION ------------------------------------------
 *
 * Any `.xx` request this file doesn't implement is silently skipped:
 * one line consumed, nothing emitted, no following lines swallowed.
 * This matches real troff's own behaviour for a macro with no defined
 * body (a no-op, not an error) -- .de/.am/.ig/.if/.ie/.el above are the
 * deliberate exceptions, because only they can corrupt output
 * otherwise (a `\{ ... \}` conditional span left untracked would leak
 * its guarded lines into the page regardless of the condition's real
 * outcome). Passing the raw request line through as text was rejected
 * on purpose: a stray ".TS" line printed into the middle of a
 * paragraph is more confusing than a silent no-op.
 *
 * ============================================================
 * MACROS: .de/.de1/.am/.am1/.ig, INVOCATION, AND $1.. ARGUMENTS
 * ============================================================
 *
 * A second name -> body table (struct man_mactab below), separate from
 * the register table above (real troff also keeps macros/strings in a
 * different name space than number registers; see "REGISTERS" for why
 * this file already merges strings+numbers together but keeps macros
 * apart, since a macro body is a list of LINES, not one scalar value).
 *
 * `.de NAME [END]` stores every following raw source line, verbatim
 * and unprocessed, up to a line matching END (or the literal `..` if
 * END is omitted -- real troff's own default), replacing NAME's
 * previous body if it had one. `.am NAME [END]` is identical except it
 * APPENDS to NAME's existing body (creating NAME empty first if it had
 * none yet), also matching real troff. `.de1`/`.am1` behave exactly
 * like `.de`/`.am` here: real troff's own distinction is a
 * compatibility-mode toggle this file has no concept of (it never
 * emulates AT&T troff's stricter register-name/backslash rules), so
 * there is nothing for `1` to actually change. `.ig [END]` still never
 * stores anything -- its lines are scanned with the exact same
 * termination logic and discarded, matching real troff's own "define
 * nothing, just skip" semantics.
 *
 * A line encountered later whose request name matches a stored macro
 * (checked only after every built-in request above it -- a page
 * cannot shadow a built-in by defining a same-named macro) EXECUTES
 * that macro: each stored body line, after $-argument substitution
 * (below), is fed back through the exact same line-processing
 * function top-level source lines go through, so a macro body can
 * itself use any real macro/register/request, including defining or
 * invoking further macros. Recursion (a macro invoking itself, or a
 * cycle) is bounded by MAN_MAX_MACRO_DEPTH, the same "documented
 * finite bound, loud failure not silent hang" discipline
 * MAN_MAX_RS_DEPTH already gives `.RS` nesting.
 *
 * $-argument substitution is a textual pre-pass over each RAW stored
 * body line (before that line is tokenized/decoded like any other
 * source line): a literal `\$1`..`\$9` is replaced with the invoking
 * line's corresponding argument (raw, undecoded text -- decoded
 * normally once the substituted line is processed like any other),
 * `\$0` with the name the macro was invoked as, and `\$*`/`\$@` with
 * every argument space-joined (real troff's `\$@` individually
 * double-quotes each argument for safe re-passing to another macro
 * call; this file's own tokenizer has no matching escaped-quote
 * support to reconstruct that form, so `\$@` is a documented
 * simplification, identical to `\$*` here). An argument index beyond
 * how many were actually given substitutes nothing, matching real
 * troff.
 *
 * `.rm NAME` deletes a macro; `.als NEW OLD` makes NEW an independent
 * copy of OLD's current body (a real troff alias is a copy taken at
 * alias time, not a live link -- redefining OLD afterward does not
 * change NEW); `.rn OLD NEW` (see "REGISTERS" for its register
 * behaviour) also renames a macro when OLD names one instead of a
 * register. All three are silent no-ops when OLD/NAME doesn't exist,
 * matching real troff's own forgiving behaviour for these requests.
 *
 * ============================================================
 * REGISTERS: .ds/.nr/.rn, AND \* / \n INTERPOLATION
 * ============================================================
 *
 * One name -> value table (struct man_regtab below) holds both STRING
 * registers (`.ds NAME text`, read with `\*(xx`/`\*x`/`\*[...]`) and
 * NUMBER registers (`.nr NAME value [increment]`, read with
 * `\n(xx`/`\nx`/`\n[...]`, or auto-incremented/-decremented by the
 * register's own INCREMENT step with `\n+xx`/`\n-xx`). Real troff
 * keeps strings and number registers in two separate name spaces; this
 * file merges them into one, a deliberate simplification -- looking a
 * name up under the wrong kind behaves exactly like looking up a name
 * that was never defined (empty / 0), which no real page distinguishes
 * from in practice.
 *
 * `.nr NAME VALUE` sets NAME outright; a leading `+`/`-` on VALUE
 * instead adds/subtracts from NAME's current value (0 if undefined),
 * matching real troff's absolute-vs-relative `.nr` syntax. VALUE and
 * INCREMENT are register-interpolated first, then must be a plain
 * signed decimal integer -- NOT a general arithmetic expression (real
 * troff's `.nr`/`.if` share one numeric-expression evaluator; that's
 * Tier 3 of this project's own troff-engine plan, not duplicated
 * here). A VALUE that isn't plain once interpolated (e.g. GNU grep's
 * own grep.1 fixture has `.nr mG \n(.g-1`, which decodes to the
 * expression "1-1") leaves the register untouched, the same honest-
 * no-op precedent as "UNKNOWN-MACRO DEGRADATION" above.
 *
 * `.rn OLD NEW` renames whichever register OLD names to NEW; OLD not
 * existing is a no-op, NEW already existing is silently overwritten --
 * both match real troff. (Real troff's own `.rn` only ever covered
 * macros/strings, never number registers, because of the name-space
 * split above; merging the two name spaces here means `.rn` naturally
 * covers both kinds too.)
 *
 * An interpolated register that was never defined resolves to an
 * empty string (`\*`) or `0` (`\n`), matching real troff.
 *
 * A small set of READ-ONLY built-in number registers, checked ahead of
 * the user table so a page can never shadow them via `.nr`: `\n(.g` is
 * always 1 (real groff defines it as 1, AT&T troff leaves it 0; pages
 * use it to detect "is this groff" before using a groff extension --
 * answering 1 is the honest choice for an engine that targets groff-
 * era pages and doesn't implement every groff extension, since any
 * specific one it lacks still degrades cleanly on its own). `\n(mo`/
 * `\n(dy`/`\n(yr` are the current month/day-of-month/year -- `yr`
 * deliberately keeps troff's own wart of year MINUS 1900 (126 in 2026,
 * not "26"), since pages that check it at all expect that exact
 * convention. `\n(.s`/`\n(.f` (point size / current font) are fixed
 * dummy values (10, 1): this file has no real point-size concept and
 * only a depth-1 font "stack" (see \fP below), so there's nothing real
 * to report.
 *
 * ============================================================
 * CONDITIONALS: .if/.ie/.el
 * ============================================================
 *
 * A real recursive-descent evaluator for troff's condition-expression
 * grammar (see man_eval_condition() and the numeric-expression parsers
 * above it), not a stub that always shows or always hides the guarded
 * text. `.if COND anything` runs `anything` (itself processed exactly
 * like any other source line, so it may be a further request, another
 * `.if`, or plain text) when COND is true, and discards it silently
 * when false. `.ie COND anything` is identical but additionally
 * remembers COND's outcome for the NEXT `.el`, which runs its own
 * `anything` exactly when that remembered outcome was false -- matching
 * real troff's own if/else-if/else chaining. Unlike real troff, only
 * the SINGLE most recently seen `.ie` outcome is remembered (no nesting
 * stack); a page whose `.el` pairs with something other than the
 * innermost preceding `.ie` -- vanishingly rare in practice -- would
 * see the wrong branch, a documented simplification.
 *
 * `COND` is one of:
 *  - `!COND`: negates whatever COND (recursively, same grammar) says.
 *  - `n`/`t`/`o`/`e`: the four built-in device/page-parity tests. `n`
 *    (is this nroff, i.e. terminal/non-typeset output) is always true
 *    and `t` (is this troff, i.e. real typeset output) always false --
 *    this file only ever produces nroff-style output, never real
 *    typesetting. `o`/`e` (odd/even page) have no real pagination to
 *    answer from, so this file gives a stable, documented answer: page
 *    1 is treated as odd (`o` true, `e` false), matching what a real
 *    single-page nroff run would report.
 *  - `Dstr1Dstr2D` (D = whatever single, non-alphanumeric character
 *    immediately follows -- almost always `'` in practice, per the
 *    plan's own `'a'b'` example, but any character works, matching
 *    real troff): true if str1 equals str2 after both are escape-
 *    decoded the same way any other text is (so `\*(xx`/`\(xx`/etc all
 *    interpolate inside a comparison operand).
 *  - a numeric expression, optionally followed by one relational
 *    operator (`<`/`>`/`<=`/`>=`/`=`/`==`) and a second numeric
 *    expression: true if the comparison holds, or (no relop) if the
 *    expression alone is nonzero. Numeric expressions support the
 *    standard arithmetic grammar (`+ - * / %`, unary minus, parens)
 *    plus `\n` register interpolation -- the "shared .nr/.if numeric
 *    evaluator" man_parse_plain_number()'s own comment named as this
 *    tier's own future work (`.nr` itself still only accepts a plain
 *    literal or a register-interpolated one, unchanged -- widening it
 *    to share this same arithmetic grammar is easy but out of THIS
 *    tier's own named scope, .if/.ie/.el). `\w`/`\k`/`\s`/`\h`/`\v`/
 *    `\x`/`\X`/`\H`/`\V` inside a numeric expression evaluate to 0 --
 *    same "recognised and consumed only" precedent as everywhere else
 *    in this file those escapes appear (see "ESCAPE SEQUENCES
 *    IMPLEMENTED" below); a string register used numerically (`\*(xx`)
 *    is likewise always 0, since this file has no numeric-parse-a-
 *    string fallback.
 *
 * `.if`/`.ie`'s own condition is parsed directly off the RAW source
 * line (never man_tokenize()'d -- a quoted string-comparison operand
 * with an embedded space would otherwise get split in two) and, unlike
 * everywhere else escapes are decoded, register interpolation happens
 * INLINE as each numeric atom is scanned rather than via one up-front
 * decode_text() pass -- decoding first would already have turned a
 * literal `\{`/`\}` block marker into plain `{`/`}`, indistinguishable
 * from ordinary text, before this code ever got a chance to recognise
 * it as one.
 *
 * A condition (or, for `.el`, no condition at all) can be followed
 * either by a single-line action (everything remaining on that line,
 * run/discarded exactly once) or by `\{ ... \}`: a multi-line true-
 * branch block, collected verbatim (c->cond_active/cond_body, the same
 * "verbatim raw-line collection, terminator recognised at the very top
 * of man_process_line() before normal dispatch" shape .de's own
 * c->def_active collection already uses) up to a matching `\}`, tracked
 * with a nesting-depth counter (c->cond_depth) since `\{ ... \}` blocks
 * nest in real pages (this project's own GREP1_EXCERPT test fixture
 * included) -- only a `\}` at depth 0 is OUR terminator; any `\{`/`\}`
 * pair seen while collecting just adjusts the depth and is stored
 * verbatim like any other body line, to be re-parsed for real (with its
 * own fresh c->cond_active collection) when this block's own lines are
 * replayed through man_process_line() after the fact, if COND was true.
 * A `\}` is only ever recognised as a WHOLE (trimmed, optionally `.`-
 * prefixed) line by itself, never embedded elsewhere -- matching every
 * real page this file has been tested against, and a documented
 * simplification of troff's fully general "anywhere in the input"
 * rule.
 *
 * ============================================================
 * TABLES: .TS/.TE (tbl)
 * ============================================================
 *
 * A real subset parser/renderer for tbl's own mini-language (see
 * man_render_table() and its helpers), not a stub that drops the
 * table. `.TS [H]` begins collecting every following raw source line
 * verbatim, up to a line matching `.TE`, the exact same "verbatim
 * raw-line collection, terminator recognised at the very top of
 * man_process_line() before normal dispatch" shape .de's own
 * c->def_active collection uses (c->tbl_active/tbl_body here). The `H`
 * argument (real troff: repeat the heading rows across page breaks) is
 * ignored -- this file has no real pagination for it to act on, the
 * same reasoning \n(mo/\n(dy's neighbours give elsewhere. Once `.TE`
 * closes the block, the collected lines are parsed and rendered as one
 * unit into c->doc at the current c->rs_indent, exactly where a `.nf`
 * block's raw lines would land.
 *
 * The collected block has three parts, in order:
 *
 *  1. AN OPTIONAL OPTIONS LINE: present only when the very first
 *     collected (non-blank) line ends in `;`. Recognised keywords:
 *     `box`/`frame` and `allframe` (draw a bordered table -- see
 *     "box-drawing" below), `allbox` (bordered AND ruled between every
 *     row/column), `doublebox`/`allframe` (real troff draws a double-
 *     line outer border; this file degrades that to the same single-
 *     line ASCII box `box` draws -- a real, documented simplification,
 *     the same spirit as the `\fP` depth-1 font-stack one), `tab(x)`
 *     (use `x` instead of a literal tab as the cell-data field
 *     separator), and `center`/`centre` (center the whole table
 *     between the current indent and the terminal width). `expand`
 *     (stretch columns to fill the full line width),
 *     `linesize(N)`/`delim(xx)`/`nospaces`/`nowarn`/`nokeep`/
 *     `nocenter`: recognised and consumed so their syntax doesn't leak
 *     into the table, but not applied -- this file always sizes
 *     columns from real cell content and never changes delimiter/
 *     spacing behaviour for them.
 *
 *  2. ONE OR MORE FORMAT-SPECIFICATION LINES: each physical line lists
 *     that line's own column descriptors (whitespace- or comma-
 *     separated), ending when a line's last token is a lone `.`
 *     (attached to the previous token or standing alone, both real
 *     troff forms). If there are more DATA rows than format lines, the
 *     LAST format line's descriptors are reused for every remaining
 *     row -- real troff's own rule, and the reason a table's steady-
 *     state column alignment/width is always taken from that last
 *     format line (man_render_table()'s `disp[]`), not the first (a
 *     real page's FIRST format line is very often instead a `c s s`-
 *     style spanning title row -- see point 3 below). Each column
 *     descriptor is one alignment letter -- `l`/`L` left, `c`/`C`
 *     center, `r`/`R` right, `n`/`N` numeric (aligned on the decimal
 *     point, see below), `s`/`S` "this column's data is spanned from
 *     the previous column, consume no field here", `^` "this column's
 *     data is spanned from the row above, consume no field here", and
 *     `a`/`A`/`e`/`E` (real troff: alphabetic top-alignment / equal-
 *     width column grouping -- this file has no multi-line-cell or
 *     column-grouping concept for either to act on, so both degrade to
 *     plain left alignment, per this tier's own plan note that the
 *     rarer variants may be ignored if genuinely uncommon) -- followed
 *     by any number of modifier letters: `b`/`B` bold and `i`/`I`/
 *     `u`/`U` italic (this file has no underline marker, `u` degrades
 *     to italic) set that column's font for EVERY cell in it (if a
 *     descriptor sets both, bold wins, matching the single-active-
 *     marker model \fB/\fI already use elsewhere in this file); a `(`
 *     up to its matching `)` (covers `w(N)` explicit width, `f(name)`
 *     font-name selectors, and similar) and any other single modifier
 *     letter or digit (point-size numbers, the `e`-as-modifier equal-
 *     width flag, `t`/`p`/`v`/`z` vertical-fill/point-size/font
 *     letters) are recognised and consumed, never applied -- see point
 *     1 above, this file always computes real widths from content.
 *
 *  3. DATA ROWS: every remaining line up to the block's own `.TE`. A
 *     line that is exactly `_` (optionally surrounded by whitespace)
 *     is a single-rule row; exactly `=` is a double-rule row -- both
 *     span the whole table width instead of holding cells, and do NOT
 *     consume a format-line slot (rule rows aren't data). Any other
 *     line is a normal data row: split on the option line's separator
 *     (a literal tab by default) into fields, assigned in order to
 *     that row's own format line's columns that are NOT `s`/`^`
 *     (which instead render blank -- see "box-drawing" below for why
 *     that, not a real merge, is this tier's one honest layout
 *     degradation). Fewer fields than slots leaves the remaining cells
 *     blank; extra fields are dropped -- both match this file's
 *     established "forgiving, no crash, honest no-op" precedent for
 *     request arguments elsewhere (e.g. \$1..\$9 beyond argc). A
 *     single field that is exactly `_`/`=` (after trimming) renders as
 *     a rule filling just that cell's own column width, the common
 *     real-world way to underline one column's header without ruling
 *     the whole row. Every other field is register-interpolated and
 *     escape-decoded through the same decode_text() every other piece
 *     of text in this file goes through, so `\*(xx`/`\n(xx`/named
 *     glyphs all work inside table cells.
 *
 * ---- COLUMN WIDTH AND ALIGNMENT ------------------------------------------
 *
 * Each column's width is the widest cell content actually measured in
 * it (man_vislen(), the same UTF-8/marker-aware column counter word-
 * wrapping uses) -- rule/span cells don't contribute, so an all-
 * spanned column can be zero-width. A NUMERIC column instead tracks,
 * per cell, the visible width to the LEFT of its first `.` and the
 * visible width FROM that `.` onward (man_tbl_decimal_split()); the
 * column's width is the sum of each side's own maximum, and every
 * cell is padded so every row's decimal point lines up in the same
 * output column -- real decimal-point alignment, not a right-justify
 * approximation. A cell with no `.` is treated as all-integer-part,
 * which naturally right-justifies it against cells that do have a
 * fraction. One simplification: a column's alignment/width-computation
 * KIND is taken once from the table's steady-state (last) format
 * line's descriptor at that column position (see point 2 above) and
 * applied to every row at that position, even though real troff
 * technically lets a table's non-last format lines declare a
 * DIFFERENT alignment letter for the same column index (vanishingly
 * rare in real pages -- this tier's own research pass found none;
 * per-row SPAN/rule behaviour above is still read from each row's own
 * format line regardless of this simplification, since that's what
 * actually determines which field goes where).
 *
 * ---- BOX-DRAWING --------------------------------------------------------
 *
 * `box`/`frame`: a plain ASCII border (`+`/`-`/`|`) around the whole
 * table, drawn once at the top and bottom. `allbox`: the same border
 * PLUS a ruled line between every data row (not duplicated next to a
 * `_`/`=` rule row, which already draws one). No box option at all:
 * columns are simply separated by MAN_TBL_COL_GAP spaces, no border
 * characters -- matching plain (non-boxed) real tbl output. `center`
 * adds left padding, computed once from the table's own total rendered
 * width against the terminal width, ahead of every line -- an honest
 * approximation of real troff's page-relative centering, since this
 * file has no page-width concept distinct from the terminal.
 *
 * The one real, deliberate layout degradation named above: `s`
 * (horizontal span) and `^` (vertical span) columns render as BLANK
 * space filling their own column's width, rather than real troff's
 * visual merge (the owning cell's content stretching across the
 * combined width of every column it spans, or repeating the cell
 * above for `^`). The DATA is never lost or misassigned by this --
 * every field still reads into the correct owning column, see point 3
 * above -- only the visual presentation of a spanned cell is
 * simplified, the same "the data must render correctly and
 * completely, box/line drawing may degrade" spirit this tier's own
 * plan names for double-line boxes.
 *
 * ============================================================
 * EQN: .EQ/.EN
 * ============================================================
 *
 * A real subset parser/renderer for eqn's own in-line mathematical
 * notation (see man_render_eqn() and its helpers), not a stub that
 * drops the equation. `.EQ [label]` begins collecting every following
 * raw source line verbatim, up to a line matching `.EN`, the same
 * "verbatim raw-line collection, terminator recognised at the very top
 * of man_process_line() before normal dispatch" shape `.TS`'s own
 * c->tbl_active collection uses (c->eqn_active/eqn_body here). Real
 * troff's optional arguments here -- a cross-reference label, and/or a
 * one-letter display-position override (`L`/`I`/`C`/`R`) -- are both
 * ignored: this file always centers a displayed equation (see below),
 * the same "recognised argument, no real per-page effect" precedent
 * `.TS [H]`'s own `H` argument sets.
 *
 * There is no real 2-D typeset math in a terminal regardless of how
 * much of eqn's grammar gets implemented -- stacked fractions, a
 * radical sign actually drawn over its argument, a superscript
 * genuinely raised half a line, are not things plain terminal text can
 * represent. Real groff itself falls back to a readable LINEAR ASCII
 * approximation for its own `-Tascii`/`-Tutf8` output devices (`a over
 * b` becomes text meaning "a divided by b", not a drawn fraction bar);
 * this file matches that existing real-world precedent rather than
 * inventing a new one. Each collected `.EQ`/`.EN` line is register-
 * interpolated and escape-decoded (decode_text(), the same pass every
 * other piece of text in this file goes through -- `\*(xx`/`\n(xx`/
 * named glyphs all work inside an equation too) and then parsed and
 * rendered as ONE COMPLETE, INDEPENDENT equation of its own. Unlike
 * real eqn, an expression cannot span multiple physical source lines
 * here -- a page that deliberately hard-wraps one long equation's
 * source across several lines (this tier's own research pass found
 * none doing so) would see it rendered as several smaller, unrelated-
 * looking pieces instead of one, a documented, honest degradation, not
 * a silently wrong answer.
 *
 * The implemented grammar (man_eqn_parse_expr() and the functions
 * below it, in precedence order, tightest first):
 *
 *  - A PRIMARY is a bare word (rendered literally, unless it's one of
 *    the Greek-letter names below), a `"quoted string"` (rendered
 *    literally, and -- matching real eqn -- exempt from being read as
 *    a keyword or a Greek-letter name, since quoting is exactly how a
 *    real page would spell out the literal word "sub" or "pi"), a
 *    `{ expr }` group (pure grouping -- see below), or `sqrt PRIMARY`
 *    (its own argument, itself a primary, so `sqrt` binds to exactly
 *    the next atom or group and no further).
 *  - `sub`/`sup` are POSTFIX operators on the immediately preceding
 *    primary: `x sub i sup 2` and `x sup 2 sub i` both mean the same
 *    thing (subscript i, superscript 2) -- either order is accepted,
 *    each keyword recognised at most once per primary. A second `sub`
 *    or `sup` on the same primary without an intervening `{ }` group
 *    falls outside this tier's documented scope (a real page needing
 *    that nests explicitly instead, `x sub {i sub j}`, which the
 *    grouping rule below already handles); it is read back as a
 *    literal word by the next primary, the same "malformed input
 *    degrades to something reasonable, never crashes" precedent
 *    "UNKNOWN-MACRO DEGRADATION" documents elsewhere in this file.
 *  - `over` binds just as TIGHTLY as `sub`/`sup`: to the single
 *    (possibly already sub/sup-combined) unit immediately to its left
 *    and right, never to an entire concatenated run -- this is what
 *    makes eqn's own canonical quadratic-formula example, `x = { -b +-
 *    sqrt{b sup 2 - 4ac} } over {2a}`, render correctly as `x = (-b +-
 *    sqrt(b^2 - 4ac))/(2a)`: `over`'s left operand is exactly the `{
 *    -b +- sqrt{...} }` group (one unit), never pulling the preceding
 *    `x =` into the fraction. Chained `over`s are left-associative (`a
 *    over b over c` -> `(a/b)/c`), each intermediate division
 *    parenthesized when it becomes the next numerator -- exactly the
 *    disambiguation a human writing plain-text math by hand would add.
 *  - Units (a primary, with or without sub/sup/over already applied)
 *    written next to each other with no keyword between them
 *    CONCATENATE (eqn's own loosest-binding juxtaposition rule),
 *    rejoined here with a single space for readability.
 *  - `{ expr }` is TRANSPARENT grouping only: its own parsed value
 *    (text and all) is used exactly as if the braces were never there
 *    -- they exist purely to scope what an outer sub/sup/over/sqrt
 *    applies to (`{a + b} over c` -> `(a + b)/c`), never to add visible
 *    output of their own, matching real eqn.
 *
 * A parsed value only gets wrapped in an extra delimiter when embedded
 * as a sub/sup/over/sqrt operand IF it represents more than one
 * concatenated unit or is itself an `over` division (man_eqn_wrap(),
 * keyed off each value's own `compound` flag) -- so `x sub i` reads
 * "x_i", not the noisier "x_{i}", while `x sub {i+1}` correctly reads
 * "x_{i+1}". Sub/sup use `{ }` as that delimiter (the common
 * plain-text-math convention for a multi-character subscript); `over`
 * and `sqrt` use `( )` (`sqrt{a + b}` -> "sqrt(a + b)"; `a over {b +
 * c}` -> "a/(b + c)"). A subscripted/superscripted primary is itself
 * treated as atomic (never re-wrapped) once built: `x sub i over y`
 * reads "x_i/y", since a subscripted quantity already reads as one
 * visual unit without an extra delimiter.
 *
 * Greek-letter names (man_eqn_greek[]): the full 24-letter lowercase
 * alphabet (`alpha` .. `omega`), plus the 11 uppercase names whose
 * glyph actually differs from a plain Latin letter (`GAMMA`, `DELTA`,
 * `THETA`, `LAMBDA`, `XI`, `PI`, `SIGMA`, `UPSILON`, `PHI`, `PSI`,
 * `OMEGA` -- real eqn has no separate uppercase name for e.g. ALPHA or
 * BETA, since their Greek capitals are visually identical to Latin A
 * and B, so neither does this table), rendered as their real UTF-8
 * Greek codepoints. This deliberately does NOT match groff -Tascii's
 * own fallback (which, confined to 7-bit ASCII, spells the name out as
 * plain text, e.g. literal "pi") -- it instead matches THIS file's own
 * pre-existing precedent of emitting real UTF-8 for named glyphs it
 * can represent exactly (see man_specials[] above, e.g. \(co -> the
 * real copyright sign, not the string "(C)"), which reads better on
 * any UTF-8 terminal without losing honesty about what's a real glyph
 * versus an approximation.
 *
 * A line whose first word is `delim` or `define` -- real eqn's own
 * mode-setting directives (respectively: switch on/off a pair of
 * characters that trigger inline math mode inside ordinary paragraph
 * text elsewhere on the page, outside any `.EQ`/`.EN` pair; and define
 * a reusable text macro for later equations to reference) -- is
 * recognised and consumed rather than parsed as math, so its keyword
 * and argument don't render as meaningless literal text. NEITHER
 * directive's actual effect is implemented: in particular, the `delim`
 * inline-math-in-running-text feature (`.EQ` / `delim $$` / `.EN`
 * followed later by `$x sup 2$` inside a plain paragraph line) is out
 * of this tier's scope entirely -- only real `.EQ`...`.EN` BLOCK
 * equations are recognised; an inline delimited expression is left as
 * plain literal text, the same "not hooked in, not silently mangled"
 * choice \k/\s make elsewhere in this file.
 *
 * NOT implemented, and left as literal text if encountered: matrices
 * and piles (`matrix`, `pile`, `lpile`, `rpile`, `cpile`, column
 * layout); summation/integral/product bounds (`from`/`to`, e.g. `sum
 * from i=0 to n`); sized delimiters (`left`/`right`, e.g. `left (
 * x over y right )` growing the parens to fit); font/size changes
 * (`roman`, `italic`, `bold`, `fat`, `size`); accent marks (`dot`,
 * `dotdot`, `hat`, `tilde`, `vec`, `dyad`, `bar`, `under`); explicit
 * spacing tokens (bare `~`/`^` as full-/half-space, distinct from `^`
 * as this file's OWN superscript-rendering character in its output);
 * and `mark`/`lineup` multi-equation column alignment. Every one of
 * these is a real, named eqn construct outside the plan's own
 * documented subset (sub/sup, over, sqrt, Greek letters, `{ }`
 * grouping) -- a page using one sees that construct's own keyword and
 * operands rendered as literal words side by side, not a crash and not
 * silently dropped text.
 *
 * Recursion (nested `{ }` groups) is bounded by MAN_EQN_MAX_DEPTH, the
 * same "documented finite bound, loud degrade not silent hang"
 * discipline MAN_MAX_RS_DEPTH/MAN_MAX_MACRO_DEPTH already give `.RS`
 * nesting and macro invocation.
 *
 * Each rendered equation line is emitted as its own display, indented
 * from c->rs_indent and then centered within the remaining line width
 * (room split evenly left/right, man_vislen()'s own UTF-8-aware column
 * counter, so a Greek letter's multi-byte UTF-8 encoding still counts
 * as one column) -- a deliberate, fixed choice (see the `.EQ` argument
 * paragraph above), not real per-page position-argument handling. A
 * malformed/empty equation (nothing left after trimming and stripping
 * directive lines) renders nothing, the same honest no-op precedent
 * "UNKNOWN-MACRO DEGRADATION" documents elsewhere in this file, rather
 * than an empty display line.
 *
 * ============================================================
 * GZIP-COMPRESSED (.gz) PAGES
 * ============================================================
 *
 * Real `/usr/share/man` is almost entirely `.gz` pages. man_read_page()
 * (below man_read_file()) transparently decompresses one: tried
 * whenever the path itself ends in ".gz" OR (independent of the name)
 * the file's own first two bytes are gzip's magic number -- real
 * gzip(1) itself only ever looks at the magic, a page can be
 * compressed without ".gz" in its name too. src/util/man_gz.c is a
 * real, from-scratch RFC 1951 DEFLATE decompressor plus the RFC 1952
 * gzip container around it (no zlib/libz anywhere in this tree, by
 * design -- see that file's own header comment for the algorithm and
 * every simplification it documents, e.g. only the FIRST gzip member
 * of a multi-member stream is decompressed). A malformed/corrupt/
 * truncated gzip page is diagnosed by name and treated exactly like
 * any other unreadable file (had_error set, that one operand skipped,
 * the rest of the command line still processed) -- never a crash, never
 * silently-wrong output handed to the troff parser below.
 *
 * ============================================================
 * ESCAPE SEQUENCES IMPLEMENTED
 * ============================================================
 *
 * See decode_text() for the exhaustive switch. Summary: \- \_ \& \e
 * \% \(space) \0 \| \^ \' \` \. \\ (literal-character/spacing
 * escapes), \c (interrupt output right here and suppress the usual
 * join-space/break before whatever comes next -- real troff's own
 * meaning; tracked via man_ctx's own suppress_join flag, consulted
 * everywhere this file would otherwise insert a join space between
 * consecutive accumulated fragments), \" (comment to end of line, also
 * a whole-line `.\"` request), \fX \f(XX \f[...] (font change: B/I are
 * real; everything else -- R, P, numbered/named fonts -- maps to
 * roman/reset, since
 * this file keeps no font *stack* and every real page tested only ever
 * nests one level deep, where \fP's "previous font" distinction never
 * arises), \(xx (a built-in table of the commonest named glyphs;
 * unrecognised names are dropped, not guessed at), \*(xx/\*x/\*[...]
 * and \n(xx/\nx/\n[...]/\n+xx/\n-xx (register interpolation -- real,
 * see "REGISTERS" above), and \s... \k... \h... \v... \w... \x... \X...
 * \H... \V... (point-size/mark/motion/size requests: recognised and
 * consumed so their syntax never leaks into output, but resolve to
 * nothing -- nothing here tracks point size or horizontal motion). Any
 * other \X falls back to printing X literally, troff's own "protect
 * this character" meaning for an unknown escape.
 *
 * ============================================================
 * ADJUSTMENT: .ad/.na, AND REAL FILL-AND-ADJUST JUSTIFICATION
 * ============================================================
 *
 * Real troff's own default rendering fills AND adjusts: a paragraph's
 * text is greedily packed onto each line (fill, which this file has
 * always done) and the leftover slack on every line but the last is
 * then spread back out across that line's own inter-word gaps
 * (adjust), so both margins land flush -- the classic "extra spaces
 * between words" look of old troff/nroff output. This file's own
 * default instead stays ragged-right (single space between words, no
 * stretching) even after this tier, a deliberate divergence from real
 * troff's own default, NOT an unfinished feature: `.ad`/`.na` are real,
 * troff-compatible REQUESTS here (they toggle c->adjust, one of the
 * MAN_ADJ_* modes below) and produce real, complete justification the
 * moment a page actually asks for it -- but a page that never mentions
 * either request (the overwhelming majority; real troff already has
 * adjustment on by default, so most real pages never need to ask)
 * keeps rendering exactly the way every earlier tier of this file
 * already did and every existing test already assumes. Defaulting to
 * real troff's own "adjust on" instead would have silently reformatted
 * every already-passing test and every real page this file has ever
 * been verified against, for a purely cosmetic difference (inter-word
 * spacing) nothing downstream actually depends on -- a deliberate,
 * disclosed judgement call, not a correctness gap.
 *
 * `.ad [c|l|r|b|n]`: `l` ragged right (this file's own default, see
 * above), `r` ragged LEFT (each line's right edge flush, left edge
 * shifted over by that line's own slack), `c` each line centred (slack
 * split, remainder to the left), `b`/`n` real both-margins
 * justification, and a bare `.ad` with no argument also sets `b`/`n` --
 * real troff instead restores whichever specific mode was last active
 * before an intervening `.na`, a remembered-mode distinction this file
 * does not separately track (c->adjust just holds the current mode, not
 * a history of it); real pages essentially always use bare `.ad`/`.na`
 * as a simple on/off pair without an `.ad r`/`.ad c` in between, so the
 * two behave identically in every case that matters in practice, a
 * documented simplification. An unrecognised argument is a no-op,
 * matching this file's own "malformed value leaves the setting
 * untouched" precedent `.nr` already established. `.na`: ragged right,
 * unconditionally (real troff's own `.na` takes no argument).
 *
 * Both requests flush the current paragraph accumulator first, exactly
 * like `.nf`/`.fi` already do, for the same reason: c->acc buffers an
 * entire paragraph's raw text and only word-wraps it as one unit when
 * the paragraph ends (man_flush_paragraph() -> man_wrap_emit()), so a
 * mode change mid-paragraph could otherwise only ever apply uniformly
 * to the WHOLE buffered block regardless of exactly where in the
 * source it appeared -- flushing first turns that into an explicit,
 * honest boundary instead of a silently backdated one.
 *
 * The actual justification math (man_wrap_flush_line()): once a line's
 * full word list is known (greedy packing is unchanged from before this
 * tier -- adjustment only changes INTER-WORD SPACING, never where a
 * line breaks), MAN_ADJ_BOTH distributes `cols - content_width` extra
 * columns across the line's own (word_count - 1) gaps as evenly as
 * integer division allows, any remainder going to the LEFTMOST gaps
 * first -- classic troff's own left-to-right distribution, and why a
 * justified line with non-uniform word lengths still often shows one
 * gap slightly wider than its neighbours rather than a perfectly even
 * split. A single-word line has no gap to stretch and a fill span's own
 * LAST line is never stretched at all (both real troff behaviours,
 * carried via man_wrap_emit()'s own `is_last` bookkeeping -- see its
 * header comment) -- both fall back to plain single-space rendering
 * even under MAN_ADJ_BOTH.
 *
 * ============================================================
 * HYPHENATION: .hy/.nh
 * ============================================================
 *
 * Off by default -- same reasoning as ADJUSTMENT's own default above:
 * this file never split a word before this tier existed at all, so
 * defaulting hyphenation ON would silently reformat every page and every
 * existing test that has never once mentioned `.hy`, for a purely
 * cosmetic difference nothing downstream depends on. `.hy [N]` turns it
 * on (any numeric argument, or none, all mean the same thing here -- see
 * below); `.nh` turns it off. Both flush the current paragraph
 * accumulator first, the identical reasoning `.ad`/`.na` give above.
 *
 * The algorithm (man_hyph_best_split()/man_hyph_find_points(), just
 * above man_block_start() in this file) is the REAL Knuth-Liang pattern-
 * matching algorithm -- the same mechanism TeX and real troff/groff use:
 * digit-weighted letter patterns matched as substrings of the word (with
 * `.` boundary anchors), one weight per inter-letter gap taken as the
 * MAX over every pattern that matches there, and a gap is a legal break
 * point exactly when that weight is ODD -- not a fixed-column or prose-
 * guessing heuristic. What's genuinely scoped down from a real troff is
 * the PATTERN TABLE itself (man_hyph_patterns[]): a small, hand-written
 * set of common English prefixes, suffixes, doubled-consonant splits,
 * and digraph/cluster deny rules (see that table's own header comment
 * for the exact list), not the ~4500-pattern table real TeX/groff
 * hyphenation data ships (machine-derived from a large pronouncing
 * dictionary via Liang's own training algorithm -- a separate, much
 * larger undertaking than hand-authoring rules, and this project's own
 * troff-engine plan, .claude/plans/man-troff-engine.md's Tier 7 text,
 * explicitly named the choice between the two as this pass's own open
 * question). The chosen bias is precision over recall: this table
 * deliberately has no general vowel-consonant-vowel fallback rule (the
 * part of a real trained pattern set that covers a word with no
 * recognised affix), so it finds real, defensible breaks for words
 * carrying a recognised prefix/suffix/doubled-consonant and simply finds
 * NONE for a long word it doesn't recognise -- an honest under-
 * hyphenation, never a wrong break.
 *
 * MAN_HYPH_LEFT_MIN (2) / MAN_HYPH_RIGHT_MIN (3) bound every break to
 * leave at least that many letters on each side, matching TeX's own
 * \lefthyphenmin=2 \righthyphenmin=3 convention for US English patterns
 * -- a word shorter than their sum can never be split at all.
 *
 * Only a PLAIN word is ever offered to the pattern matcher
 * (man_hyph_word_ok()): ASCII letters only, no digits, punctuation,
 * apostrophes, embedded MAN_M_BOLD/MAN_M_ITAL/MAN_M_ROMAN font markers,
 * or multi-byte UTF-8 -- a word carrying any of those is never
 * hyphenated, a documented simplification (splitting mid-marker or mid-
 * multi-byte-sequence would risk corrupting the styled text stream
 * man_wrap_emit() decodes; a styled/foreign-alphabet word is rare enough
 * in the specific position "doesn't fit AND would otherwise overflow"
 * that simply not hyphenating it is the honest, safe choice over adding
 * that complexity here).
 *
 * man_wrap_emit() only ever ATTEMPTS a split when a word doesn't fit the
 * remaining space on a line that already holds another word, AND more
 * text follows it -- never the paragraph's own last word (real troff's
 * own avoidance of leaving a hyphenated stub as the very last thing in a
 * paragraph, where hyphenating it could not even save a line: there is
 * no following word left to pull up), and never a word that already
 * fits (hyphenation only ever answers "how do I place a word that
 * doesn't fit", never "should I reformat one that does"). At most ONE
 * split is attempted per word instance: if the leftover remainder still
 * doesn't fit a whole fresh line (only possible at a pathologically
 * narrow width), it falls through to this file's pre-existing "any_word
 * first-word-always-placed" overflow carve-out unhyphenated, rather than
 * this file attempting to chain multiple hyphenation splits across more
 * than two lines -- a documented, deliberately narrow scope boundary,
 * not an oversight.
 *
 * ============================================================
 * RENDERING: WHERE BOLD/ITALIC COME FROM, AND HOW WIDTH IS CHOSEN
 * ============================================================
 *
 * Font state is carried through word-wrapping as three zero-width
 * marker bytes (MAN_M_BOLD/MAN_M_ITAL/MAN_M_ROMAN -- control codes no
 * real troff source uses, and stripped from raw input on the way in so
 * a hostile page can't forge them) embedded in the styled text stream.
 * Wrapping measures width by codepoint, skipping UTF-8 continuation
 * bytes and marker bytes, so multi-byte \(xx glyphs still count as one
 * column each.
 *
 * The marker bytes' actual output depends on the destination, chosen
 * once in man_display() below:
 *
 *   - Direct to a terminal, or this file's own "--More--" pager: real
 *     ANSI SGR (`\033[1m` bold, `\033[4m` italic/underline, `\033[0m`
 *     reset) -- this file fully controls what interprets the bytes
 *     either way.
 *   - An external $PAGER, or non-terminal stdout: classic nroff
 *     overstrike (`X\bX` bold, `_\bX` italic/underline) instead --
 *     safer specifically because it's external: this file can't know
 *     whether an arbitrary $PAGER honours ANSI SGR (`less` needs an
 *     explicit -R), but both `less` and `more` have understood
 *     backspace-overstrike by default since long before either
 *     supported color.
 *
 * Terminal width: ioctl(TIOCGWINSZ) first, then $COLUMNS if positive,
 * then a fixed 80 -- src/util/ls.c's own fallback chain, ioctl moved
 * first since laying out text for the terminal is man's whole job.
 * Height follows the same chain against ws_row/$LINES/24.
 *
 * ============================================================
 * PAGING
 * ============================================================
 *
 * Not a terminal: no paging, formatted text goes straight to stdout.
 * A terminal: $PAGER (split on whitespace only, no shell-quoting) is
 * spawned via __find_program()/__spawn() against a real mkstemp() file
 * holding the formatted output -- a pipe was rejected, since it would
 * need either a drainer thread or risk deadlock if the pager doesn't
 * read until EOF. If $PAGER is unset, a minimal built-in "--More--"
 * pager runs instead, necessarily Enter-terminated rather than single-
 * keystroke: this project's termios(3) only has real raw-mode control
 * on its NT backend, not native-Linux yet.
 *
 * ============================================================
 * FINDING A PAGE
 * ============================================================
 *
 * `$MANPATH`, colon-separated, each entry a directory of man1/, man2/,
 * ... subdirectories. Unset/empty falls back to "/usr/share/man:/usr/
 * local/share/man". `$MANSECT` (also colon-separated) overrides the
 * default section search order "1:2:...:9" when no section operand is
 * given. POSIX's own man(1p) SYNOPSIS has no section operand at all,
 * but every real `man` also accepts a leading bare section (`man 3
 * printf`): implemented here as "if >=2 operands are given and the
 * first matches ^[0-9][A-Za-z0-9]*$, it restricts every name that
 * follows."
 *
 * -k: no prebuilt whatis database exists here (that's its own
 * subsystem, `makewhatis`), so -k walks MANPATH, reads every page's
 * `.SH NAME` line, and substring-matches (case-insensitively) each
 * keyword against it -- exactly the "slow method" real `man -k` itself
 * falls back to without a cached database.
 *
 * ---- THIS REPOSITORY'S OWN man/man1/ PAGES -------------------------------
 *
 * man/man1/ (true.1, false.1, cat.1, echo.1, mkdir.1, man.1) is not
 * installed by the build -- there's no existing $(prefix)-relative
 * default-search-path precedent to extend the way $(bindir)/
 * $(libdir)/$(includedir) have. These pages exist to prove the macro
 * subset above against real, useful content ($MANPATH pointed at man/
 * in a checkout, `man true` works today), alongside test/util-man.c's
 * embedded real GNU grep.1 excerpt, which proves this formatter
 * against troff nobody wrote by hand for this project.
 *
 * Never calls exit()/_exit(): __util_man_main() can run in-process as
 * a shell built-in (src/sh/builtin.c) like every other src/util/
 * utility -- see src/util/dd.c's own header comment for why.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <limits.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include "util.h"
#include "libc.h" /* __find_program()/__spawn() -- src/process/, the same primitives sh's own execute.c uses */
#include "man_gz.h" /* man_gunzip()/man_looks_gzipped() -- Tier 4, see that file's own header comment */

/* A whole page this large would be pathological (real man pages are a
 * few KB to a few hundred KB) -- this is a safety net against reading
 * an unbounded amount of an arbitrary file into memory, the same
 * "bound it, document why, move on" discipline src/util/m4.c's own
 * M4_MAX_EXPANSIONS comment describes, not a real limit any honest
 * page would hit. */
#define MAN_MAX_PAGE_SIZE (16 * 1024 * 1024)

/* Nesting nowhere near this deep occurs in real pages; bounding
 * .RS/.RE stack depth turns a pathological/malformed page's unbounded
 * `.RS` run into a loud "too deeply nested" skip instead of unbounded
 * growth. */
#define MAN_MAX_RS_DEPTH 64

/* A user macro invoking itself (directly or through a cycle) would
 * otherwise recurse without limit; bounding it the same way as
 * MAN_MAX_RS_DEPTH turns that into a loud diagnostic instead of an
 * unbounded stack. */
#define MAN_MAX_MACRO_DEPTH 64

/* A pathological/malformed `.EQ`...`.EN` expression with an unbounded
 * run of nested `{` groups would otherwise recurse the eqn expression
 * parser without limit; bounded the same "documented finite bound,
 * loud degrade not silent hang" way as MAN_MAX_RS_DEPTH -- see
 * man_eqn_parse_primary(). */
#define MAN_EQN_MAX_DEPTH 64

#define MAN_BASE_INDENT 7  /* classic troff `an.tmac` .nr IN default */
#define MAN_SS_COL      3

/* ==== zero-width font-state markers embedded in styled text ============ */
#define MAN_M_BOLD  '\x01'
#define MAN_M_ITAL  '\x02'
#define MAN_M_ROMAN '\x03'

/* ==== `.ad`/`.na` adjustment modes -- see this file's header comment
 * ("ADJUSTMENT") -- and man_wrap_emit()'s own use of them. */
#define MAN_ADJ_LEFT   0  /* ragged right, this file's own long-standing default */
#define MAN_ADJ_RIGHT  1
#define MAN_ADJ_CENTER 2
#define MAN_ADJ_BOTH   3  /* real justification: both margins flush */

/* ==== `.hy`/`.nh` hyphenation -- see "HYPHENATION" in this file's header
 * comment. Standard English left/right hyphenation minimums (matching
 * TeX's own \lefthyphenmin=2 \righthyphenmin=3 for US English patterns):
 * a break must leave at least this many letters on each side. */
#define MAN_HYPH_LEFT_MIN  2
#define MAN_HYPH_RIGHT_MIN 3
#define MAN_HYPH_MAX_WORD  56  /* no real English word this file will ever
                                 * see is anywhere near this long; a longer
                                 * "word" (run-together text, a path, ...)
                                 * is simply never offered to the pattern
                                 * matcher -- see man_hyph_best_split(). */

/* ==== growable byte buffer (src/util/m4.c's strbuf_append() idiom) ===== */

struct man_buf { char *data withtok(heap_allocated); size_t len, cap; };

static int mbuf_append(struct man_buf *restrict b,
	const char *restrict data, size_t n)
{
	if (!n) {
		if (!b->data) {
			b->data = malloc(1);
			if (!b->data) return 0;
			b->data[0] = 0;
			b->cap = 1;
		}
		return 1;
	}
	/* __util_array_capacity() folds the overflow-checked "is b->cap
	 * already big enough?" test into its own return -- unlike the raw
	 * `b->len + n + 1 > b->cap` comparison this replaced, which could
	 * wrap around for an adversarial n and wrongly skip growing b->data
	 * (still NULL for a never-appended-to b). */
	{
		size_t newcap;
		if (!__util_array_capacity(b->cap, b->len, n + 1, 256, 1, &newcap)) return 0;
		if (newcap != b->cap) {
			char *g = __util_reallocarray(b->data, newcap, 1);
			if (!g) return 0;
			b->data = g; b->cap = newcap;
		}
	}
	for (size_t i = 0; i < n; i++) b->data[b->len + i] = data[i];
	b->len += n;
	b->data[b->len] = 0;
	return 1;
}

static int mbuf_appendc(struct man_buf *b, char c) { return mbuf_append(b, &c, 1); }
static int mbuf_appendstr(struct man_buf *b, const char *s) { return mbuf_append(b, s, strlen(s)); }
static int mbuf_appendn(struct man_buf *b, int n, char c)
{
	while (n-- > 0) if (!mbuf_appendc(b, c)) return 0;
	return 1;
}
static void mbuf_free(struct man_buf *b) { free(b->data); b->data = 0; b->len = b->cap = 0; }
static void mbuf_reset(struct man_buf *b) { b->len = 0; if (b->data) b->data[0] = 0; }

/* ==== \(xx named-glyph table: the commonest subset, ASCII source only == */

static const struct { char name[2]; const char *rep; } man_specials[] = {
	{ { 'c', 'o' }, "\xC2\xA9" },         /* copyright sign */
	{ { 'r', 'g' }, "\xC2\xAE" },         /* registered sign */
	{ { 't', 'm' }, "\xE2\x84\xA2" },     /* trade mark sign */
	{ { 'b', 'u' }, "\xE2\x80\xA2" },     /* bullet */
	{ { 'e', 'm' }, "\xE2\x80\x94" },     /* em dash */
	{ { 'e', 'n' }, "\xE2\x80\x93" },     /* en dash */
	{ { 'd', 'g' }, "\xE2\x80\xA0" },     /* dagger */
	{ { 'l', 'q' }, "\xE2\x80\x9C" },     /* left curly double quote */
	{ { 'r', 'q' }, "\xE2\x80\x9D" },     /* right curly double quote */
	{ { 'o', 'q' }, "\xE2\x80\x98" },     /* left curly single quote */
	{ { 'c', 'q' }, "\xE2\x80\x99" },     /* right curly single quote */
	{ { 'a', 'q' }, "'" },                /* apostrophe */
	{ { 'd', 'q' }, "\"" },               /* double quote */
	{ { 's', 'q' }, "'" },                /* apostrophe (alt name) */
	{ { 'g', 'a' }, "`" },                /* grave accent */
	{ { 'a', 'a' }, "'" },                /* acute accent */
	{ { 'h', 'a' }, "^" },                /* circumflex */
	{ { 't', 'i' }, "~" },                /* tilde */
};

static const char *man_lookup_special(char c1, char c2)
{
	size_t i;
	for (i = 0; i < sizeof man_specials / sizeof *man_specials; i++)
		if (man_specials[i].name[0] == c1 && man_specials[i].name[1] == c2)
			return man_specials[i].rep;
	return 0;
}

/* Consume a `'...'`- or `[...]`-delimited argument (the shape \h, \v,
 * \w, \x, \X, \H, \V all take) and produce no output -- see this
 * file's own header comment ("motion/size requests") for why these
 * are recognised-and-dropped rather than implemented. Returns the new
 * index. */
static size_t man_skip_delim_arg(const char *s, size_t n, size_t i)
{
	if (i < n && s[i] == '\'') {
		i++;
		while (i < n && s[i] != '\'') i++;
		if (i < n) i++;
	} else if (i < n && s[i] == '[') {
		i++;
		while (i < n && s[i] != ']') i++;
		if (i < n) i++;
	}
	return i;
}

/* ==== register table: .ds/.nr/.rn and \* / \n interpolation =========== *
 * See this file's own header comment ("REGISTERS: .ds/.nr/.rn, AND
 * \* / \n INTERPOLATION") for the full design rationale -- summary: one
 * table holds both string and number registers (a documented
 * simplification of real troff's two separate name spaces), looked
 * up by name, with a small set of read-only built-in number registers
 * checked ahead of it. */

enum man_reg_kind { MAN_REG_STRING, MAN_REG_NUMBER };

struct man_reg {
	char *name withtok(heap_allocated);             /* malloc'd */
	enum man_reg_kind kind;
	char *str withtok(heap_allocated);               /* MAN_REG_STRING: malloc'd value */
	long num;                /* MAN_REG_NUMBER: current value */
	long incr;                /* MAN_REG_NUMBER: \n+xx/\n-xx step, from .nr's optional third argument */
};

struct man_regtab { struct man_reg *v withtok(heap_allocated); size_t n, cap; };

static void man_regtab_free(struct man_regtab *t)
{
	size_t i;
	for (i = 0; i < t->n; i++) { free(t->v[i].name); free(t->v[i].str); }
	free(t->v);
	t->v = 0; t->n = t->cap = 0;
}

static struct man_reg *man_reg_find(struct man_regtab *t, const char *name)
{
	size_t i;
	for (i = 0; i < t->n; i++)
		if (!strcmp(t->v[i].name, name)) return &t->v[i];
	return 0;
}

/* Finds `name`'s existing slot, or grows the table and creates a
 * fresh (zeroed) one. Returns NULL only on allocation failure. */
static struct man_reg *man_reg_get_or_create(struct man_regtab *t, const char *name)
{
	struct man_reg *r = man_reg_find(t, name);
	char *dup;

	if (r) return r;

	if (t->n + 1 > t->cap) {
		size_t newcap;
		struct man_reg *g;
		if (!__util_array_capacity(t->cap, t->n, 1, 8, sizeof *t->v, &newcap)) return 0;
		g = __util_reallocarray(t->v, newcap, sizeof *t->v);
		if (!g) return 0;
		t->v = g; t->cap = newcap;
	}
	dup = strdup(name);
	if (!dup) return 0;
	r = &t->v[t->n++];
	memset(r, 0, sizeof *r);
	r->name = dup;
	return r;
}

static int man_reg_set_string(struct man_regtab *t, const char *name, const char *value)
{
	struct man_reg *r = man_reg_get_or_create(t, name);
	char *dup;
	if (!r) return 0;
	dup = strdup(value);
	if (!dup) return 0;
	free(r->str);
	r->str = dup;
	r->kind = MAN_REG_STRING;
	return 1;
}

/* set_incr false leaves an existing register's auto-increment step
 * untouched (real troff's own .nr: the increment argument is
 * optional, and omitting it does not reset a previously-set step). */
static int man_reg_set_number(struct man_regtab *t, const char *name, long value, long incr, int set_incr)
{
	struct man_reg *r = man_reg_get_or_create(t, name);
	if (!r) return 0;
	if (r->kind == MAN_REG_STRING) { free(r->str); r->str = 0; }
	r->kind = MAN_REG_NUMBER;
	r->num = value;
	if (set_incr) r->incr = incr;
	return 1;
}

/* Removes the register named `name`, if any (silent no-op if not
 * found) -- used by man_do_rn() so renaming onto an existing name
 * overwrites it, matching real troff's own .rn behaviour. */
static void man_reg_remove(struct man_regtab *t, const char *name)
{
	size_t i, j;
	for (i = 0; i < t->n; i++) {
		if (strcmp(t->v[i].name, name) != 0) continue;
		free(t->v[i].name);
		free(t->v[i].str);
		for (j = i; j + 1 < t->n; j++) t->v[j] = t->v[j + 1];
		t->n--;
		return;
	}
}

/* Built-in read-only number registers real pages actually probe --
 * see this file's own header comment for exactly which ones and why
 * each value was chosen. Returns 1 and sets *out if `name` is one of
 * them, 0 otherwise (falls through to the user-defined table). */
static int man_builtin_number(const char *name, long *out)
{
	if (!strcmp(name, ".g")) { *out = 1; return 1; }
	if (!strcmp(name, ".s")) { *out = 10; return 1; }
	if (!strcmp(name, ".f")) { *out = 1; return 1; }
	if (!strcmp(name, "mo") || !strcmp(name, "dy") || !strcmp(name, "yr")) {
		time_t now = time(0);
		struct tm tmv;
		if (!localtime_r(&now, &tmv)) { *out = 0; return 1; }
		if (!strcmp(name, "mo")) *out = tmv.tm_mon + 1;
		else if (!strcmp(name, "dy")) *out = tmv.tm_mday;
		else *out = tmv.tm_year; /* real troff wart: year MINUS 1900, see header comment */
		return 1;
	}
	return 0;
}

static long man_lookup_number(struct man_regtab *t, const char *name)
{
	long v;
	struct man_reg *r;
	if (man_builtin_number(name, &v)) return v;
	r = man_reg_find(t, name);
	if (!r || r->kind != MAN_REG_NUMBER) return 0; /* undefined, or defined as the other kind: 0, same as real troff's undefined-register default */
	return r->num;
}

static const char *man_lookup_string(struct man_regtab *t, const char *name)
{
	struct man_reg *r = man_reg_find(t, name);
	if (!r || r->kind != MAN_REG_STRING) return 0; /* undefined, or defined as the other kind: empty, same as real troff's undefined-register default */
	return r->str;
}

/* Extracts a register name from one of the three name-syntaxes a
 * register-interpolation escape (`\*`/`\n`) can use, starting at
 * s[i]: `(xx` (exactly two characters), `[...]` (bracket-delimited,
 * any length, truncated to namesz-1 if longer -- real register names
 * this long do not occur in practice), or a single bare character.
 * Writes the NUL-terminated name into `name` and returns the new
 * index. */
static size_t man_read_reg_name(const char *s, size_t n, size_t i, char *name, size_t namesz)
{
	size_t k = 0;

	if (i < n && s[i] == '(') {
		i++;
		if (i < n) { if (k + 1 < namesz) name[k++] = s[i]; i++; }
		if (i < n) { if (k + 1 < namesz) name[k++] = s[i]; i++; }
	} else if (i < n && s[i] == '[') {
		i++;
		while (i < n && s[i] != ']') { if (k + 1 < namesz) name[k++] = s[i]; i++; }
		if (i < n) i++;
	} else if (i < n) {
		if (k + 1 < namesz) name[k++] = s[i];
		i++;
	}
	name[k] = 0;
	return i;
}

/* ==== macro table: .de/.de1/.am/.am1/.ig, .rm/.als ===================== *
 * See this file's own header comment ("MACROS") for the full design
 * rationale -- summary: a separate name -> body table (a macro body is
 * a list of raw source lines, not one scalar value, so it doesn't fit
 * man_regtab above), looked up only after every built-in request name
 * so a page can never shadow a built-in by defining a same-named
 * macro. */

struct man_macro {
	char *name withtok(heap_allocated);   /* malloc'd */
	char **lines withtok(heap_allocated); /* malloc'd array of malloc'd raw body lines */
	size_t n, cap;
};

struct man_mactab { struct man_macro *v withtok(heap_allocated); size_t n, cap; };

static void man_macro_free_lines(struct man_macro *m)
{
	size_t i;
	for (i = 0; i < m->n; i++) free(m->lines[i]);
	free(m->lines);
	m->lines = 0; m->n = m->cap = 0;
}

static void man_mactab_free(struct man_mactab *t)
{
	size_t i;
	for (i = 0; i < t->n; i++) { free(t->v[i].name); man_macro_free_lines(&t->v[i]); }
	free(t->v);
	t->v = 0; t->n = t->cap = 0;
}

static struct man_macro *man_mac_find(struct man_mactab *t, const char *name)
{
	size_t i;
	for (i = 0; i < t->n; i++)
		if (!strcmp(t->v[i].name, name)) return &t->v[i];
	return 0;
}

/* Finds `name`'s existing macro slot, or grows the table and creates a
 * fresh (empty-bodied) one. Returns NULL only on allocation failure. */
static struct man_macro *man_mac_get_or_create(struct man_mactab *t, const char *name)
{
	struct man_macro *m = man_mac_find(t, name);
	char *dup;

	if (m) return m;

	if (t->n + 1 > t->cap) {
		size_t newcap;
		struct man_macro *g;
		if (!__util_array_capacity(t->cap, t->n, 1, 8, sizeof *t->v, &newcap)) return 0;
		g = __util_reallocarray(t->v, newcap, sizeof *t->v);
		if (!g) return 0;
		t->v = g; t->cap = newcap;
	}
	dup = strdup(name);
	if (!dup) return 0;
	m = &t->v[t->n++];
	memset(m, 0, sizeof *m);
	m->name = dup;
	return m;
}

static int man_macro_add_line(struct man_macro *m, const char *line)
{
	char *dup;
	if (m->n + 1 > m->cap) {
		size_t newcap;
		char **g;
		if (!__util_array_capacity(m->cap, m->n, 1, 16, sizeof *m->lines, &newcap)) return 0;
		g = __util_reallocarray(m->lines, newcap, sizeof *m->lines);
		if (!g) return 0;
		m->lines = g; m->cap = newcap;
	}
	dup = strdup(line);
	if (!dup) return 0;
	m->lines[m->n++] = dup;
	return 1;
}

/* Removes the macro named `name`, if any (silent no-op if not found) --
 * used by man_do_rm() and man_do_rn()'s own macro-rename overwrite,
 * same shape as man_reg_remove() above. */
static void man_mac_remove(struct man_mactab *t, const char *name)
{
	size_t i, j;
	for (i = 0; i < t->n; i++) {
		if (strcmp(t->v[i].name, name) != 0) continue;
		free(t->v[i].name);
		man_macro_free_lines(&t->v[i]);
		for (j = i; j + 1 < t->n; j++) t->v[j] = t->v[j + 1];
		t->n--;
		return;
	}
}

/* Signed `long` arithmetic that might overflow, defined by widening
 * through the unsigned wraparound C99 6.2.5p9 guarantees rather than
 * ever evaluating the signed +, -, or unary - that would overflow.
 * troff number registers and \n(x/.if expressions have no overflow
 * diagnostic of their own -- a register set to a huge value, or
 * auto-incremented past LONG_MAX, is just a huge or wrapped register
 * value in real troff, not a fatal error -- so these keep that
 * silent-wraparound behaviour without going through the signed UB
 * that reached it before. */
static long man_wrap_neg(long v) { return (long)-(unsigned long)v; }
static long man_wrap_add(long a, long b) { return (long)((unsigned long)a + (unsigned long)b); }
static long man_wrap_sub(long a, long b) { return (long)((unsigned long)a - (unsigned long)b); }
static long man_wrap_mul(long a, long b) { return (long)((unsigned long)a * (unsigned long)b); }

/* Escape/glyph decoder: appends the rendering of one chunk of raw
 * troff text (a whole text line, or one macro argument) to `out`,
 * expanding the escapes this file's own header comment documents.
 * See that comment for the exact, exhaustive list. `regs` is the
 * register table \* / \n interpolation escapes read (and, indirectly
 * through man_do_ds()/man_do_nr(), write). `trailing_c`, if non-NULL,
 * is set to 1 when this chunk ended in \c (see "ESCAPE SEQUENCES
 * IMPLEMENTED" in this file's own header comment) and left untouched
 * otherwise -- callers that thread join-space suppression across
 * consecutive accumulated fragments pass a real pointer; callers that
 * don't care (register values, headings, and the like never
 * participate in that join logic) pass NULL. */
static int decode_text(struct man_regtab *regs, struct man_buf *out, const char *s, size_t n, int *trailing_c)
{
	size_t i = 0;

	while (i < n) {
		unsigned char c = (unsigned char)s[i];

		/* Defensive: strip any of the three internal marker bytes a
		 * malformed/hostile page might contain literally, so the
		 * marker channel word-wrap and rendering rely on can never
		 * be forged by input -- see this file's own header comment. */
		if (c == (unsigned char)MAN_M_BOLD || c == (unsigned char)MAN_M_ITAL ||
		    c == (unsigned char)MAN_M_ROMAN) { i++; continue; }

		if (c != '\\') { if (!mbuf_appendc(out, (char)c)) return 0; i++; continue; }
		i++;
		if (i >= n) { if (!mbuf_appendc(out, '\\')) return 0; break; }
		c = (unsigned char)s[i];

		switch (c) {
		case '-': case '_': case '\'': case '`': case '.': case '\\':
			if (!mbuf_appendc(out, (char)c)) return 0;
			i++;
			break;
		case ' ': case '0':
			if (!mbuf_appendc(out, ' ')) return 0;
			i++;
			break;
		case 'e':
			if (!mbuf_appendc(out, '\\')) return 0;
			i++;
			break;
		case '&': case '%': case '|': case '^':
			i++; /* zero-width / spacing / no-break hints: dropped */
			break;
		case 'c':
			/* \c: interrupt processing right here -- anything after
			 * it in this same chunk is real troff's own "not part of
			 * this output" territory, so stop rather than keep
			 * decoding. Reported to the caller via trailing_c so it
			 * can suppress the join-space it would otherwise insert
			 * before whatever gets accumulated next. */
			if (trailing_c) *trailing_c = 1;
			i = n;
			break;
		case '"':
			i = n; /* comment to end of line */
			break;
		case '(': {
			char c1 = 0, c2 = 0;
			const char *rep;
			i++;
			if (i < n) { c1 = s[i]; i++; }
			if (i < n) { c2 = s[i]; i++; }
			rep = man_lookup_special(c1, c2);
			if (rep && !mbuf_appendstr(out, rep)) return 0;
			break;
		}
		case '*': { /* string register interpolation: \*(xx / \*x / \*[...] */
			char regname[64];
			const char *val;
			i++;
			i = man_read_reg_name(s, n, i, regname, sizeof regname);
			val = man_lookup_string(regs, regname);
			if (val && !mbuf_appendstr(out, val)) return 0;
			break;
		}
		case 'n': { /* number register interpolation: \n(xx / \nx / \n[...] / \n+xx / \n-xx */
			char regname[64];
			char numbuf[24];
			int autoincr = 0, decr = 0;
			long v;
			i++;
			if (i < n && (s[i] == '+' || s[i] == '-')) { autoincr = 1; decr = (s[i] == '-'); i++; }
			i = man_read_reg_name(s, n, i, regname, sizeof regname);
			if (autoincr) {
				struct man_reg *r = man_reg_find(regs, regname);
				/* Auto-incrementing an undefined (or wrong-kind)
				 * register: real troff treats it as starting at 0
				 * with a 0 step, so the result is 0 either way. */
				if (r && r->kind == MAN_REG_NUMBER) {
					r->num = decr ? man_wrap_sub(r->num, r->incr)
					              : man_wrap_add(r->num, r->incr);
					v = r->num;
				} else {
					v = 0;
				}
			} else {
				v = man_lookup_number(regs, regname);
			}
			snprintf(numbuf, sizeof numbuf, "%ld", v);
			if (!mbuf_appendstr(out, numbuf)) return 0;
			break;
		}
		case 'k': /* mark register: unsupported */
			i++;
			if (i < n && s[i] == '(') { i++; if (i < n) i++; if (i < n) i++; }
			else if (i < n) { i++; }
			break;
		case 's': /* point-size change: unsupported */
			i++;
			if (i < n && (s[i] == '+' || s[i] == '-')) i++;
			if (i < n && (s[i] == '\'' || s[i] == '[')) {
				i = man_skip_delim_arg(s, n, i);
			} else {
				while (i < n && s[i] >= '0' && s[i] <= '9') i++;
			}
			break;
		case 'h': case 'v': case 'w': case 'x': case 'X': case 'H': case 'V':
			i++;
			i = man_skip_delim_arg(s, n, i);
			break;
		case 'f': {
			i++;
			if (i < n && s[i] == '(') {
				i++;
				if (i < n) i++;
				if (i < n) i++;
				if (!mbuf_appendc(out, MAN_M_ROMAN)) return 0;
			} else if (i < n && s[i] == '[') {
				i++;
				while (i < n && s[i] != ']') i++;
				if (i < n) i++;
				if (!mbuf_appendc(out, MAN_M_ROMAN)) return 0;
			} else if (i < n) {
				char fc = s[i];
				i++;
				if (fc == 'B') { if (!mbuf_appendc(out, MAN_M_BOLD)) return 0; }
				else if (fc == 'I') { if (!mbuf_appendc(out, MAN_M_ITAL)) return 0; }
				else { if (!mbuf_appendc(out, MAN_M_ROMAN)) return 0; }
			}
			break;
		}
		default:
			/* Unknown escape: troff's own fallback is "the escaped
			 * character, literally" (this is how `\.` protects a
			 * dot from control-character interpretation, etc). */
			if (!mbuf_appendc(out, (char)c)) return 0;
			i++;
			break;
		}
	}
	return 1;
}

/* ==== conditional evaluator: .if/.ie/.el's condition syntax =========== *
 * See this file's own header comment ("CONDITIONALS") for the full
 * design rationale -- summary: a real recursive-descent evaluator for
 * troff's `.if`/`.ie` condition grammar, operating directly on RAW
 * (undecoded) source text rather than pre-decoded text, since decoding
 * ahead of time would already have turned a literal `\{`/`\}` block
 * marker into `{`/`}` and made it indistinguishable from ordinary text
 * -- the block marker has to be recognised before any decoding happens.
 * Register interpolation (`\n(xx` etc.) is instead performed inline, as
 * each numeric atom is scanned, by calling the same man_lookup_number()/
 * man_reg_find() this file's \n escape-decoding already uses. */

static size_t man_cond_skip_ws(const char *s, size_t n, size_t i)
{
	while (i < n && (s[i] == ' ' || s[i] == '\t')) i++;
	return i;
}

/* Skips a `\w`/`\k`/`\s`/`\h`/`\v`/`\x`/`\X`/`\H`/`\V`-style delimited
 * argument starting at s[i] (the delimiter itself), for the numeric
 * evaluator below -- these escapes are documented (this file's own
 * header comment, "ESCAPE SEQUENCES IMPLEMENTED") as recognised-and-
 * consumed only, so their numeric value is always 0, but the argument
 * still has to be skipped correctly to keep parsing in sync. Unlike
 * man_skip_delim_arg() above (used by decode_text(), `'`/`[` only),
 * troff condition syntax lets these take ANY single character as their
 * own delimiter (`\w@...@` is exactly what real groff tmac sources use
 * -- see GREP1_EXCERPT's own `\w@\*(lq@` in test/util-man.c), so this
 * is a separate, more general helper rather than reusing that one. */
static size_t man_cond_skip_delim(const char *s, size_t n, size_t i)
{
	char delim, close;
	if (i >= n) return i;
	delim = s[i]; i++;
	close = (delim == '[') ? ']' : delim;
	while (i < n && s[i] != close) i++;
	if (i < n) i++;
	return i;
}

static long man_cond_parse_expr(struct man_regtab *regs, const char *s, size_t n, size_t *i);

/* One numeric primary: a parenthesized sub-expression, `\n` register
 * interpolation (including the `\n+xx`/`\n-xx` auto-increment forms,
 * same semantics as decode_text()'s own `\n` case), an unsupported
 * escape contributing 0 (see man_cond_skip_delim()'s own comment), or a
 * plain signed decimal literal. */
static long man_cond_parse_atom(struct man_regtab *regs, const char *s, size_t n, size_t *i)
{
	size_t k = man_cond_skip_ws(s, n, *i);

	if (k < n && s[k] == '(') {
		long v;
		k++;
		v = man_cond_parse_expr(regs, s, n, &k);
		k = man_cond_skip_ws(s, n, k);
		if (k < n && s[k] == ')') k++;
		*i = k;
		return v;
	}

	if (k < n && s[k] == '\\' && k + 1 < n) {
		char ec = s[k + 1];
		if (ec == '\\') {
			/* `\\` is troff's own "one literal backslash" escape --
			 * real macro packages routinely write `\\n(xx` inside a
			 * `.if` expression (this project's own GREP1_EXCERPT test
			 * fixture's `.if \\n(.g-\\n(mG \{\` included) so that the
			 * SECOND backslash is what the expression scanner actually
			 * sees as a fresh, real `\n` escape -- collapsing one level
			 * and re-scanning from there is what makes that idiom
			 * resolve to a real register value instead of the generic
			 * unrecognised-escape fallback below. */
			k++;
			*i = k;
			return man_cond_parse_atom(regs, s, n, i);
		}
		if (ec == 'n') {
			char regname[64];
			int autoincr = 0, decr = 0;
			long v;
			k += 2;
			if (k < n && (s[k] == '+' || s[k] == '-')) { autoincr = 1; decr = (s[k] == '-'); k++; }
			k = man_read_reg_name(s, n, k, regname, sizeof regname);
			if (autoincr) {
				struct man_reg *r = man_reg_find(regs, regname);
				if (r && r->kind == MAN_REG_NUMBER) {
					r->num = decr ? man_wrap_sub(r->num, r->incr)
					              : man_wrap_add(r->num, r->incr);
					v = r->num;
				} else v = 0;
			} else {
				v = man_lookup_number(regs, regname);
			}
			*i = k;
			return v;
		}
		if (ec == '*') { /* string register in numeric context: not a real number, 0 */
			char regname[64];
			k += 2;
			k = man_read_reg_name(s, n, k, regname, sizeof regname);
			*i = k;
			return 0;
		}
		if (ec == 'w' || ec == 'k' || ec == 's' || ec == 'h' ||
		    ec == 'v' || ec == 'x' || ec == 'X' || ec == 'H' || ec == 'V') {
			k += 2;
			k = man_cond_skip_delim(s, n, k);
			*i = k;
			return 0;
		}
		if (ec == '(') { /* \(xx glyph name: not numeric, 0 */
			k += 2;
			if (k < n) k++;
			if (k < n) k++;
			*i = k;
			return 0;
		}
		/* Any other unrecognised escape: consume it, contribute 0 --
		 * the same "protect this character" fallback decode_text()'s
		 * own default case documents, adapted to a numeric context. */
		k += 2;
		*i = k;
		return 0;
	}

	{
		char *end;
		long v = strtol(s + k, &end, 10);
		if (end == s + k) { *i = k; return 0; } /* unparseable: honest 0, not a guess */
		*i = k + (size_t)(end - (s + k));
		return v;
	}
}

/* Unary +/- wraps the atom above; real troff numeric expressions allow
 * a sign before a parenthesized sub-expression too (`-(\n(x+1)`), not
 * just before a bare literal, so this is its own grammar level rather
 * than folded into strtol()'s own sign handling. */
static long man_cond_parse_factor(struct man_regtab *regs, const char *s, size_t n, size_t *i)
{
	size_t k = man_cond_skip_ws(s, n, *i);
	if (k < n && (s[k] == '+' || s[k] == '-')) {
		int neg = (s[k] == '-');
		long v;
		k++;
		*i = k;
		v = man_cond_parse_factor(regs, s, n, i);
		return neg ? man_wrap_neg(v) : v;
	}
	*i = k;
	return man_cond_parse_atom(regs, s, n, i);
}

static long man_cond_parse_term(struct man_regtab *regs, const char *s, size_t n, size_t *i)
{
	long v = man_cond_parse_factor(regs, s, n, i);
	for (;;) {
		size_t k = man_cond_skip_ws(s, n, *i);
		if (k < n && (s[k] == '*' || s[k] == '/' || s[k] == '%')) {
			char op = s[k];
			long rhs;
			k++;
			*i = k;
			rhs = man_cond_parse_factor(regs, s, n, i);
			if (op == '*') {
				v = man_wrap_mul(v, rhs);
			} else if (rhs == 0) {
				v = 0; /* division/modulo by zero: honest 0, not a crash */
			} else if (v == LONG_MIN && rhs == -1) {
				/* The one division whose mathematical quotient
				 * (-LONG_MIN) does not fit back in a long; two's
				 * complement wraps that to LONG_MIN itself, so
				 * man_wrap_neg gives the same answer a plain
				 * `v / rhs` would be undefined behaviour reaching
				 * for here. The matching remainder is exactly 0. */
				v = (op == '/') ? man_wrap_neg(v) : 0;
			} else {
				v = (op == '/') ? v / rhs : v % rhs;
			}
		} else break;
	}
	return v;
}

static long man_cond_parse_expr(struct man_regtab *regs, const char *s, size_t n, size_t *i)
{
	long v = man_cond_parse_term(regs, s, n, i);
	for (;;) {
		size_t k = man_cond_skip_ws(s, n, *i);
		if (k < n && (s[k] == '+' || s[k] == '-')) {
			char op = s[k];
			long rhs;
			k++;
			*i = k;
			rhs = man_cond_parse_term(regs, s, n, i);
			v = (op == '+') ? man_wrap_add(v, rhs) : man_wrap_sub(v, rhs);
		} else break;
	}
	return v;
}

/* A numeric expression, optionally followed by one relational operator
 * and a second numeric expression -- true if the comparison holds, or
 * (no relop present) if the expression alone is nonzero. */
static int man_cond_parse_relation(struct man_regtab *regs, const char *s, size_t n, size_t *i)
{
	long lhs = man_cond_parse_expr(regs, s, n, i);
	size_t k = man_cond_skip_ws(s, n, *i);

	if (k < n && (s[k] == '<' || s[k] == '>' || s[k] == '=')) {
		char op = s[k];
		int op_eq = 0;
		long rhs;
		k++;
		if (k < n && s[k] == '=') { op_eq = 1; k++; }
		*i = k;
		rhs = man_cond_parse_expr(regs, s, n, i);
		if (op == '=') return lhs == rhs;
		if (op == '<') return op_eq ? lhs <= rhs : lhs < rhs;
		return op_eq ? lhs >= rhs : lhs > rhs; /* op == '>' */
	}
	*i = k;
	return lhs != 0;
}

/* Top-level condition grammar: `!` negation, the four built-in device/
 * page-parity tests, a delimiter-quoted string-equality test, or (the
 * default) a numeric relation. See this file's own header comment
 * ("CONDITIONALS") for why n/t/o/e answer the way they do. */
static int man_eval_condition(struct man_regtab *regs, const char *s, size_t n, size_t *i)
{
	size_t k = man_cond_skip_ws(s, n, *i);

	if (k < n && s[k] == '!') {
		int r;
		k++;
		r = man_eval_condition(regs, s, n, &k);
		*i = k;
		return !r;
	}

	if (k < n && (s[k] == 'n' || s[k] == 't' || s[k] == 'o' || s[k] == 'e') &&
	    (k + 1 >= n || s[k + 1] == ' ' || s[k + 1] == '\t' || s[k + 1] == '\\')) {
		int result = 0;
		switch (s[k]) {
		case 'n': result = 1; break; /* this file only ever produces nroff/terminal-style output */
		case 't': result = 0; break; /* never real typeset troff output */
		case 'o': result = 1; break; /* no real pagination: a stable "page 1, odd" answer */
		case 'e': result = 0; break; /* the exact complement of 'o' above */
		}
		*i = k + 1;
		return result;
	}

	if (k < n && !isalnum((unsigned char)s[k]) && s[k] != '\\' && s[k] != '(' &&
	    s[k] != '!' && s[k] != '+' && s[k] != '-') {
		char delim = s[k];
		struct man_buf s1, s2;
		size_t start;
		int result;
		k++;
		memset(&s1, 0, sizeof s1); memset(&s2, 0, sizeof s2);
		start = k;
		while (k < n && s[k] != delim) k++;
		decode_text(regs, &s1, s + start, k - start, 0);
		if (k < n) k++;
		start = k;
		while (k < n && s[k] != delim) k++;
		decode_text(regs, &s2, s + start, k - start, 0);
		if (k < n) k++;
		result = !strcmp(s1.data ? s1.data : "", s2.data ? s2.data : "");
		mbuf_free(&s1); mbuf_free(&s2);
		*i = k;
		return result;
	}

	*i = k;
	return man_cond_parse_relation(regs, s, n, i);
}

/* Does `s` (already comment-stripped, and for the .if/.ie/.el dispatch
 * itself already past the parsed condition) end in a `\{ ... \}`
 * multi-line-block opener -- `\{` alone, or `\{\` (the trailing
 * backslash is troff's own line-continuation escape; this file never
 * joins lines across a physical newline anywhere, so it is treated
 * identically to the plain `\{` form, a documented simplification). */
static int man_line_ends_block_open(const char *s, size_t n)
{
	if (n >= 3 && s[n - 3] == '\\' && s[n - 2] == '{' && s[n - 1] == '\\') return 1;
	if (n >= 2 && s[n - 2] == '\\' && s[n - 1] == '{') return 1;
	return 0;
}

/* Does raw line `line` close a `\{ ... \}` block -- real troff lets
 * `\}` appear anywhere, but real-world macro packages (this project's
 * own GREP1_EXCERPT test fixture included) always give it a line of
 * its own, optionally indented and/or preceded by a null `.` control
 * character; requiring the whole (trimmed) line to be exactly `\}` is
 * an honest, documented simplification of that general rule. */
static int man_line_is_block_close(const char *line)
{
	const char *p = line;
	while (*p == ' ' || *p == '\t') p++;
	if (*p == '.') { p++; while (*p == ' ' || *p == '\t') p++; }
	return p[0] == '\\' && p[1] == '}' && p[2] == 0;
}

/* ==== macro-argument tokenizer: whitespace-separated, "quoted strings" == */

struct man_argv { char **v withtok(heap_allocated); size_t n, cap; };

static void man_argv_free(struct man_argv *a)
{
	size_t i;
	for (i = 0; i < a->n; i++) free(a->v[i]);
	free(a->v);
	a->v = 0; a->n = a->cap = 0;
}

static int man_argv_push(struct man_argv *a, const char *tok, size_t len)
{
	char *dup;
	if (a->n + 1 > a->cap) {
		size_t newcap;
		char **g;
		if (!__util_array_capacity(a->cap, a->n, 1, 8, sizeof *a->v, &newcap)) return 0;
		g = __util_reallocarray(a->v, newcap, sizeof *a->v);
		if (!g) return 0;
		a->v = g; a->cap = newcap;
	}
	{
		size_t bytes;
		if (!__util_size_add(len, 1, &bytes)) return 0;
		dup = malloc(bytes);
	}
	if (!dup) return 0;
	for (size_t i = 0; i < len; i++) dup[i] = tok[i];
	dup[len] = 0;
	a->v[a->n++] = dup;
	return 1;
}

/* Splits a request line's argument text into raw (not escape-decoded --
 * callers decode each token themselves once they know what font, if
 * any, applies) tokens. A token beginning with `"` runs to the next
 * `"` or end of line -- doubled `""`-inside-a-quote escaping is not
 * implemented, a small, honest simplification. */
static int man_tokenize(const char *s, struct man_argv *out)
{
	size_t i = 0, n = strlen(s);
	memset(out, 0, sizeof *out);
	while (i < n) {
		size_t start;
		while (i < n && (s[i] == ' ' || s[i] == '\t')) i++;
		if (i >= n) break;
		if (s[i] == '"') {
			i++;
			start = i;
			while (i < n && s[i] != '"') i++;
			if (!man_argv_push(out, s + start, i - start)) { man_argv_free(out); return 0; }
			if (i < n) i++;
		} else {
			start = i;
			/* A `\` always protects whatever byte follows it from
			 * ending the token here -- most importantly `\ `
			 * (escaped space), real troff's own way to embed a
			 * literal space inside an unquoted macro argument
			 * without splitting it in two (this project's own
			 * man/man1/mkdir.1 fixture uses exactly this, in
			 * `.BI \-m\ mode`). Escape decoding itself still happens
			 * later in decode_text(); this only keeps tokenizing from
			 * cutting an escape sequence in half. */
			while (i < n && s[i] != ' ' && s[i] != '\t') {
				if (s[i] == '\\' && i + 1 < n) i += 2;
				else i++;
			}
			if (!man_argv_push(out, s + start, i - start)) { man_argv_free(out); return 0; }
		}
	}
	return 1;
}

/* ==== visible-column counting (UTF-8-codepoint-aware, marker-aware) ==== */

static size_t man_vislen(const char *s, size_t n)
{
	size_t i, cols = 0;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c == (unsigned char)MAN_M_BOLD || c == (unsigned char)MAN_M_ITAL ||
		    c == (unsigned char)MAN_M_ROMAN) continue;
		if ((c & 0xC0) == 0x80) continue; /* UTF-8 continuation byte */
		cols++;
	}
	return cols;
}

/* ==== rendering context ================================================ */

struct man_ctx {
	struct man_buf doc;     /* the final formatted document, styled */
	struct man_buf acc;     /* paragraph/tag accumulator, styled */
	int width;
	int fill;               /* 1 = fill (wrap) mode, 0 = .nf no-fill mode */
	int adjust;              /* MAN_ADJ_* -- .ad/.na, only meaningful while fill is on --
	                            * see "ADJUSTMENT" in this file's header comment */
	int hyphenate;           /* .hy/.nh -- see "HYPHENATION" in this file's header comment */
	int nf_started;         /* has this .nf block emitted its first line yet */
	int rs_indent;          /* current body indent, from base + RS/RE stack */
	int rs_stack[MAN_MAX_RS_DEPTH];
	int rs_depth;
	int extra_indent;       /* active .TP/.IP tag-body indent bump */
	int pending_tag;        /* next content chunk becomes a .TP tag */
	int tag_width;
	char *pending_prefix withtok(heap_allocated);   /* deferred short-tag first-line prefix, styled */
	int just_emitted_tag;   /* suppress the next flush's leading blank line
	                          * -- set after a .TP/.IP tag (its body is a
	                          * continuation, not a new block), after .br
	                          * (same reasoning), and after a .SH/.SS
	                          * heading (its own first paragraph sits
	                          * flush against it, no blank -- see each
	                          * case's own comment) */
	int had_output;         /* has anything at all been written to doc yet */
	struct man_regtab regs; /* .ds/.nr/.rn register table -- see decode_text() */
	struct man_mactab macros; /* .de/.am/.ig/.rm/.als macro table -- see "MACROS" */
	int def_active;          /* collecting a .de/.am/.ig body right now */
	int def_discard;         /* def_active's body is .ig's: discard, don't store */
	char *def_end withtok(heap_allocated);            /* malloc'd custom end-macro name, or NULL for the default ".." */
	struct man_macro *def_target; /* macro def_active is writing lines into (NULL if def_discard) */
	int macro_depth;         /* current user-macro invocation nesting, bounded by MAN_MAX_MACRO_DEPTH */
	int suppress_join;       /* \c seen: skip the next join-space between accumulated fragments */
	int cond_active;          /* collecting a .if/.ie \{ ... \} block body right now */
	int cond_depth;            /* nested \{ \} opens seen while collecting, below our own -- see "CONDITIONALS" */
	int cond_result;           /* the block's already-evaluated condition, applied once collection finishes */
	struct man_macro cond_body; /* raw lines collected for that block (struct man_macro reused as a plain growable line list -- .name is never set) */
	int last_ie_result;        /* most recent .ie's outcome, for a following .el -- see "CONDITIONALS" */
	int have_last_ie;          /* 0 until the first .ie runs, and after each .el consumes it */
	int tbl_active;             /* collecting a .TS/.TE table body right now -- see "TABLES" */
	struct man_macro tbl_body;  /* raw lines collected for that table (struct man_macro reused as a plain growable line list, same as cond_body above) */
	int eqn_active;             /* collecting a .EQ/.EN equation body right now -- see "EQN" */
	struct man_macro eqn_body;  /* raw lines collected for that equation (struct man_macro reused as a plain growable line list, same as tbl_body above) */
};

static int man_ctx_init(struct man_ctx *c, int width)
{
	memset(c, 0, sizeof *c);
	c->width = width;
	c->fill = 1;
	c->adjust = MAN_ADJ_LEFT;
	c->rs_indent = MAN_BASE_INDENT;
	return 1;
}

static void man_ctx_free(struct man_ctx *c)
{
	mbuf_free(&c->doc);
	mbuf_free(&c->acc);
	free(c->pending_prefix);
	man_regtab_free(&c->regs);
	man_mactab_free(&c->macros);
	free(c->def_end);
	man_macro_free_lines(&c->cond_body);
	man_macro_free_lines(&c->tbl_body);
	man_macro_free_lines(&c->eqn_body);
}

/* ==== HYPHENATION: a small, hand-curated Knuth-Liang pattern table =====
 *
 * See "HYPHENATION" in this file's own header comment for the full
 * disclosure of what this subset covers and doesn't. Short version: this
 * is the REAL Knuth-Liang pattern-matching algorithm (the same mechanism
 * TeX/troff use -- digit-weighted letter patterns, matched as substrings,
 * combined by taking the MAX weight at each inter-letter position, odd =
 * legal break point), not a fixed-column or prose-guessing heuristic --
 * but the pattern TABLE itself is a small, hand-written set of common
 * English prefixes, suffixes, doubled-consonant splits, and digraph/
 * cluster deny rules, not the full ~4500-pattern table a real TeX
 * us-english hyphen.tex ships (that table is machine-derived from a
 * large pronouncing dictionary via Liang's own training algorithm, a
 * separate and much larger undertaking than hand-authoring rules).
 *
 * Pattern syntax (Liang's own notation): a pattern is letters and `.`
 * (word-boundary anchor, matches only at the true start/end of the
 * dotted word) with decimal digits inserted BETWEEN letters. A digit is
 * the weight for the gap it appears in; an omitted gap defaults to 0. An
 * ODD weight at a gap means "a hyphen may legally go here"; EVEN means
 * "never break here", and when multiple patterns disagree about one gap
 * the LARGEST weight wins (the standard Knuth-Liang combine rule) -- so
 * an even, high-weight "never split this cluster" pattern (e.g. the "ck"
 * entry below) reliably overrides a lower-weight odd pattern that would
 * otherwise cut through it.
 *
 * This table deliberately never encodes a general vowel-consonant-vowel
 * rule (the part of a real trained pattern set that covers arbitrary
 * words with no recognised prefix/suffix) -- authoring that safely by
 * hand, without a training corpus to validate it against, risks
 * confidently-wrong breaks. The chosen bias is precision over recall:
 * this table finds real, defensible break points for words carrying a
 * recognised affix or a doubled consonant, and simply finds NONE for a
 * long word it doesn't recognise (falling back to this file's pre-
 * existing whole-word-deferred-to-next-line behaviour) rather than
 * guessing. */
static const char *const man_hyph_patterns[] = {
	/* Digraphs/clusters that must never be split (even weight, wins
	 * over any conflicting odd weight below regardless of match order). */
	"c4k", "t4h", "s4h", "c4h", "p4h", "w4h", "q4u", "n4g", "g4h", "t4c4h",
	/* A doubled consonant splits down the middle (run-ning, sum-mer,
	 * hap-pen, mid-dle, sil-ly, traf-fic) -- a real, common English
	 * hyphenation convention, not specific to any one suffix. */
	"b3b", "d3d", "f3f", "g3g", "l3l", "m3m", "n3n",
	"p3p", "r3r", "s3s", "t3t", "z3z",
	/* Common prefixes: break right after the prefix. */
	".con3", ".com3", ".dis3", ".pre3", ".pro3", ".sub3", ".trans3",
	".super3", ".over3", ".under3", ".out3", ".non3", ".inter3",
	".intra3", ".auto3", ".multi3", ".semi3", ".micro3", ".ex3",
	".de3", ".re3", ".un3", ".in3",
	/* Common suffixes: break right before the suffix. */
	"3tion.", "3sion.", "3ation.", "3ment.", "3ness.", "3ful.", "3less.",
	"3able.", "3ible.", "3ize.", "3ise.", "3ism.", "3ist.", "3ity.",
	"3ous.", "3ive.", "3hood.", "3ship.", "3ward.", "3wise.", "3ing.",
	"3er.", "3ed.", "3ly.", "3al.", "3ic.", "3ical.",
	0
};

/* Parses one man_hyph_patterns[] entry into its letter skeleton
 * (`letters`, `.` included literally) and the digit weight BEFORE each
 * letter and one final weight AFTER the last letter (`vals[0..nletters]`,
 * `vals[k]` is the gap immediately before `letters[k]`, `vals[nletters]`
 * the gap after the last letter) -- see this table's own header comment
 * above for the notation. Both output arrays must hold at least
 * strlen(pat)+1 entries (a pattern with a leading digit still has that
 * many letters at most). */
static void man_hyph_parse_pattern(const char *pat, char *letters, int *vals, int *nletters)
{
	int li = 0;
	vals[0] = 0;
	for (; *pat; pat++) {
		if (*pat >= '0' && *pat <= '9') {
			vals[li] = *pat - '0';
		} else {
			letters[li++] = *pat;
			vals[li] = 0;
		}
	}
	*nletters = li;
}

/* True if `word` (wlen bytes) is eligible for hyphenation at all: plain
 * ASCII letters only (no digits, punctuation, apostrophes, embedded
 * MAN_M_BOLD/MAN_M_ITAL/MAN_M_ROMAN font markers, or multi-byte UTF-8 --
 * see "HYPHENATION" in this file's header comment for why a styled or
 * non-ASCII word is simply never split rather than risking a break
 * inside a marker or a multi-byte sequence) and long enough that SOME
 * break satisfying MAN_HYPH_LEFT_MIN/MAN_HYPH_RIGHT_MIN could even exist. */
static int man_hyph_word_ok(const char *word, size_t wlen)
{
	size_t i;
	if (wlen < (size_t)(MAN_HYPH_LEFT_MIN + MAN_HYPH_RIGHT_MIN)) return 0;
	if (wlen > MAN_HYPH_MAX_WORD - 2) return 0;
	for (i = 0; i < wlen; i++) {
		unsigned char ch = (unsigned char)word[i];
		if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'))) return 0;
	}
	return 1;
}

/* Finds every legal Knuth-Liang break point in `word` (wlen bytes,
 * already confirmed man_hyph_word_ok()), honouring MAN_HYPH_LEFT_MIN/
 * MAN_HYPH_RIGHT_MIN. Each returned point is a byte offset `p` such that
 * breaking between word[p-1] and word[p] (prefix word[0..p), suffix
 * word[p..wlen)) is legal -- ascending order, up to `max_points` of
 * them, actual count returned. */
static int man_hyph_find_points(const char *word, size_t wlen, int *points, int max_points)
{
	char dotted[MAN_HYPH_MAX_WORD];
	int vals[MAN_HYPH_MAX_WORD + 1]; /* one gap-weight slot per dotted-word
	                                    * BYTE POSITION, 0..dlen inclusive
	                                    * (dlen == wlen+2 can reach
	                                    * MAN_HYPH_MAX_WORD exactly at the
	                                    * longest word man_hyph_word_ok()
	                                    * allows) -- one wider than
	                                    * `dotted` itself, which only ever
	                                    * needs indices 0..dlen-1. */
	size_t dlen, i, p;
	int n = 0;

	dotted[0] = '.';
	for (i = 0; i < wlen; i++) {
		char ch = word[i];
		if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 'a');
		dotted[1 + i] = ch;
	}
	dotted[1 + wlen] = '.';
	dlen = wlen + 2;
	for (i = 0; i <= dlen; i++) vals[i] = 0;

	for (p = 0; man_hyph_patterns[p]; p++) {
		char letters[MAN_HYPH_MAX_WORD];
		int pvals[MAN_HYPH_MAX_WORD];
		int nletters;
		size_t s;

		man_hyph_parse_pattern(man_hyph_patterns[p], letters, pvals, &nletters);
		if ((size_t)nletters > dlen) continue;
		for (s = 0; s + (size_t)nletters <= dlen; s++) {
			int k;
			if (memcmp(dotted + s, letters, (size_t)nletters) != 0) continue;
			for (k = 0; k <= nletters; k++)
				if (pvals[k] > vals[s + (size_t)k]) vals[s + (size_t)k] = pvals[k];
		}
	}

	for (i = MAN_HYPH_LEFT_MIN; i + MAN_HYPH_RIGHT_MIN <= wlen; i++) {
		size_t gap = i + 1; /* dotted[0] is the leading '.', so word[i] == dotted[i+1] */
		if ((vals[gap] % 2) == 1) {
			if (n < max_points) points[n++] = (int)i;
		}
	}
	return n;
}

/* The single hyphenation decision man_wrap_emit() actually needs: the
 * largest legal break point in `word` (wlen bytes) whose prefix is no
 * wider than `max_prefix` columns (the caller has already reserved room
 * for the hyphen itself), or 0 if the word isn't eligible or no legal
 * break fits. */
static int man_hyph_best_split(const char *word, size_t wlen, int max_prefix)
{
	int points[MAN_HYPH_MAX_WORD];
	int n, i, best = 0;

	if (max_prefix < MAN_HYPH_LEFT_MIN) return 0;
	if (!man_hyph_word_ok(word, wlen)) return 0;
	n = man_hyph_find_points(word, wlen, points, MAN_HYPH_MAX_WORD);
	for (i = 0; i < n; i++)
		if (points[i] <= max_prefix && points[i] > best) best = points[i];
	return best;
}

/* Blank-line-before-a-new-block bookkeeping: exactly one blank line
 * between consecutive blocks (headings, paragraphs, .TP items), none
 * before the very first block, and none between a .TP/.IP tag and its
 * own immediately-following body -- see this file's header comment's
 * "just_emitted_tag" discussion for why that last case matters. */
static int man_block_start(struct man_ctx *c)
{
	if (c->had_output && !c->just_emitted_tag) {
		if (!mbuf_appendc(&c->doc, '\n')) return 0;
	}
	c->just_emitted_tag = 0;
	c->had_output = 1;
	return 1;
}

/* One word already located within a man_wrap_emit() call's `styled`
 * buffer -- start/len index into it directly rather than copying, wcols
 * is its pre-measured man_vislen() width. `hyphen` marks a word that is
 * actually just the PREFIX of a longer word man_wrap_emit() split at a
 * legal hyphenation point (see "HYPHENATION" in this file's header
 * comment) -- man_wrap_flush_line() appends a literal '-' after it;
 * `wcols` already includes that extra column so line-width/adjustment
 * math needs no separate case for it. */
struct man_wrapword { size_t start, len; int wcols; int hyphen; };

static int man_wrapword_push(struct man_wrapword **v, size_t *n, size_t *cap,
                              size_t start, size_t len, int wcols, int hyphen)
{
	if (*n + 1 > *cap) {
		size_t newcap;
		struct man_wrapword *g;
		if (!__util_array_capacity(*cap, *n, 1, 16, sizeof **v, &newcap)) return 0;
		g = __util_reallocarray(*v, newcap, sizeof **v);
		if (!g) return 0;
		*v = g; *cap = newcap;
	}
	(*v)[*n].start = start; (*v)[*n].len = len; (*v)[*n].wcols = wcols;
	(*v)[*n].hyphen = hyphen;
	(*n)++;
	return 1;
}

/* Emits one already-line-broken word list (see man_wrap_emit() below)
 * as one physical output line: `indent` plain spaces, or `prefix`
 * verbatim if non-NULL (already padded to `indent` visible columns --
 * the ".TP tag short enough to share the body's first line" case), then
 * the words themselves. `is_last` marks the final physical line this
 * man_wrap_emit() call will produce -- real troff never stretches a
 * fill span's own last line to the right margin even under `.ad`, so
 * MAN_ADJ_BOTH only distributes slack when `!is_last`. MAN_ADJ_RIGHT/
 * MAN_ADJ_CENTER apply to every line, `is_last` included, since neither
 * one has troff's "last line stays ragged" carve-out (there is nothing
 * to stretch, only to shift). */
static int man_wrap_flush_line(struct man_ctx *c, const char *styled,
                                const struct man_wrapword *words, size_t wn,
                                int indent, int cols, int is_last, int adjust,
                                const char *prefix)
{
	size_t i;
	int content_cols;
	int gap_base = 1, gap_extra = 0;

	if (wn == 0) {
		if (prefix) {
			size_t l = strlen(prefix);
			while (l > 0 && prefix[l - 1] == ' ') l--;
			if (!mbuf_append(&c->doc, prefix, l)) return 0;
		} else {
			if (!mbuf_appendn(&c->doc, indent, ' ')) return 0;
		}
		return mbuf_appendc(&c->doc, '\n');
	}

	content_cols = (int)wn - 1;
	for (i = 0; i < wn; i++) content_cols += words[i].wcols;

	if (prefix) { if (!mbuf_appendstr(&c->doc, prefix)) return 0; }
	else { if (!mbuf_appendn(&c->doc, indent, ' ')) return 0; }

	if (adjust == MAN_ADJ_RIGHT || adjust == MAN_ADJ_CENTER) {
		int pad = cols - content_cols;
		if (pad < 0) pad = 0;
		if (!mbuf_appendn(&c->doc, adjust == MAN_ADJ_CENTER ? pad / 2 : pad, ' ')) return 0;
	} else if (adjust == MAN_ADJ_BOTH && !is_last && wn > 1) {
		int slack = cols - content_cols;
		int gaps = (int)wn - 1;
		if (slack < 0) slack = 0;
		gap_base = 1 + slack / gaps;
		gap_extra = slack % gaps;
	}

	for (i = 0; i < wn; i++) {
		if (i > 0) {
			int spaces = gap_base + (((int)i - 1) < gap_extra ? 1 : 0);
			if (!mbuf_appendn(&c->doc, spaces, ' ')) return 0;
		}
		if (!mbuf_append(&c->doc, styled + words[i].start, words[i].len)) return 0;
		if (words[i].hyphen) { if (!mbuf_appendc(&c->doc, '-')) return 0; }
	}
	return mbuf_appendc(&c->doc, '\n');
}

/* Word-wrap of `styled` (marker-embedded) into c->doc at the given
 * indent, honouring c->adjust (MAN_ADJ_* -- see "ADJUSTMENT" in this
 * file's header comment). If first_prefix is non-NULL it is used
 * verbatim as the FIRST output line's own left margin instead of
 * `indent` plain spaces, the ".TP tag short enough to share the body's
 * first line" case.
 *
 * Single pass: words are greedily assigned to the current line exactly
 * as before Tier 7; the difference is that a completed line's words are
 * buffered (man_wrapword) rather than emitted immediately, because
 * MAN_ADJ_BOTH's inter-word spacing for that line can only be computed
 * once every word that belongs on it is known. A line is known-complete
 * either when the next word doesn't fit (more text follows -- `is_last`
 * false) or when the input runs out (this IS the last line).
 *
 * HYPHENATION (c->hyphenate, `.hy`/`.nh` -- see "HYPHENATION" in this
 * file's header comment): when a word doesn't fit the remaining space on
 * a line that already holds at least one word, and more text follows it
 * (so it is NOT the very last word of this whole span -- real troff's
 * own "don't hyphenate a paragraph's last word" avoidance), and it is a
 * plain, unstyled ASCII word man_hyph_best_split() can find a legal
 * break in that fits: the prefix (plus a trailing '-') is emitted as
 * that line's own final word, and the suffix takes the prefix's place as
 * `wstart`/`wlen` -- one iteration through the exact same fit check,
 * now against a freshly emptied line, as if it had been read fresh.
 * Splitting more than once per word instance is out of scope (see the
 * header comment): a leftover remainder that still doesn't fit a whole
 * fresh line just falls through to the pre-existing "any_word first-
 * word-always-placed" overflow carve-out below, unhyphenated. */
static int man_wrap_emit(struct man_ctx *c, const char *styled, int indent, const char *first_prefix)
{
	size_t n = strlen(styled);
	size_t i = 0;
	int cols = c->width - indent;
	int line_cols = 0;
	int any_word = 0;
	int first_line = 1;
	struct man_wrapword *words = 0;
	size_t wn = 0, wcap = 0;
	int result = 1;

	if (cols < 20) cols = 20;

	while (i < n) {
		size_t wstart, wlen, wcols;

		while (i < n && styled[i] == ' ') i++;
		if (i >= n) break;
		wstart = i;
		while (i < n && styled[i] != ' ') i++;
		wlen = i - wstart;
		wcols = man_vislen(styled + wstart, wlen);

		{
			int sep = any_word ? 1 : 0;

			if (any_word && (size_t)(line_cols + sep) + wcols > (size_t)cols) {
				int p = 0;
				if (c->hyphenate && i < n) {
					int avail = cols - line_cols - sep - 1; /* -1 reserves the '-' column */
					if (avail > 0) p = man_hyph_best_split(styled + wstart, wlen, avail);
				}
				if (p > 0) {
					if (!man_wrapword_push(&words, &wn, &wcap, wstart, (size_t)p, p + 1, 1)) {
						result = 0; break;
					}
					if (!man_wrap_flush_line(c, styled, words, wn, indent, cols, 0,
					                          c->adjust, first_line ? first_prefix : 0)) {
						result = 0; break;
					}
					first_line = 0;
					wn = 0;
					line_cols = 0;
					any_word = 0;
					sep = 0;
					wstart += (size_t)p;
					wlen -= (size_t)p;
					wcols = wlen; /* man_hyph_best_split() only accepts plain ASCII letters */
				} else {
					if (!man_wrap_flush_line(c, styled, words, wn, indent, cols, 0,
					                          c->adjust, first_line ? first_prefix : 0)) {
						result = 0; break;
					}
					first_line = 0;
					wn = 0;
					line_cols = 0;
					any_word = 0;
					sep = 0;
				}
			}
			if (!man_wrapword_push(&words, &wn, &wcap, wstart, wlen, (int)wcols, 0)) { result = 0; break; }
			line_cols += sep + (int)wcols;
			any_word = 1;
		}
	}
	if (result && (wn > 0 || first_line)) {
		result = man_wrap_flush_line(c, styled, words, wn, indent, cols, 1,
		                              c->adjust, first_line ? first_prefix : 0);
	}
	free(words);
	return result;
}

/* Ends the current paragraph/tag-body accumulator, if any, or an
 * outstanding deferred short tag with no body at all. Always safe to
 * call with nothing pending (no-op). */
static int man_flush_paragraph(struct man_ctx *c)
{
	if (c->acc.len == 0 && !c->pending_prefix) return 1;

	if (!c->just_emitted_tag) { if (!man_block_start(c)) return 0; }
	else { c->just_emitted_tag = 0; c->had_output = 1; }

	if (c->acc.len == 0) {
		/* Deferred tag, never followed by a body: emit it alone. */
		char *p = c->pending_prefix;
		size_t l = strlen(p);
		while (l > 0 && p[l - 1] == ' ') l--;
		if (!mbuf_append(&c->doc, p, l)) return 0;
		if (!mbuf_appendc(&c->doc, '\n')) return 0;
	} else {
		int indent = c->rs_indent + c->extra_indent;
		if (!man_wrap_emit(c, c->acc.data, indent, c->pending_prefix)) return 0;
	}
	free(c->pending_prefix);
	c->pending_prefix = 0;
	mbuf_reset(&c->acc);
	return 1;
}

/* Turns the current accumulator into a .TP/.IP tag: either deferred
 * (short enough to share the body's first output line -- resolved by
 * man_flush_paragraph() once the body text is known) or emitted
 * immediately on its own line (too long to share). */
static int man_flush_as_tag(struct man_ctx *c, int width)
{
	size_t tag_vis;
	if (!man_block_start(c)) return 0;

	tag_vis = man_vislen(c->acc.data, c->acc.len);
	if ((int)tag_vis + 1 <= width) {
		struct man_buf p;
		memset(&p, 0, sizeof p);
		if (!mbuf_appendn(&p, c->rs_indent, ' ')) { mbuf_free(&p); return 0; }
		if (!mbuf_append(&p, c->acc.data, c->acc.len)) { mbuf_free(&p); return 0; }
		if (!mbuf_appendn(&p, width - (int)tag_vis, ' ')) { mbuf_free(&p); return 0; }
		free(c->pending_prefix);
		c->pending_prefix = p.data; /* transfer ownership */
	} else {
		if (!mbuf_appendn(&c->doc, c->rs_indent, ' ')) return 0;
		if (!mbuf_append(&c->doc, c->acc.data, c->acc.len)) return 0;
		if (!mbuf_appendc(&c->doc, '\n')) return 0;
	}
	mbuf_reset(&c->acc);
	c->just_emitted_tag = 1;
	return 1;
}

/* Appends `text` (raw, not yet escape-decoded) to the accumulator in
 * font `font` (0 = current/roman, MAN_M_BOLD, MAN_M_ITAL), inserting a
 * single space first if the accumulator is non-empty -- the .B/.I
 * (single-font, space-joined-with-args) shape. A trailing \c in `text`
 * (real troff's own "no break here" escape) suppresses that join-space
 * for whatever gets appended next instead, via c->suppress_join. */
static int man_acc_add_font(struct man_ctx *c, const char *text, int font)
{
	int had_c = 0;
	if (c->acc.len > 0 && !c->suppress_join) { if (!mbuf_appendc(&c->acc, ' ')) return 0; }
	if (font) { if (!mbuf_appendc(&c->acc, (char)font)) return 0; }
	if (!decode_text(&c->regs, &c->acc, text, strlen(text), &had_c)) return 0;
	if (font) { if (!mbuf_appendc(&c->acc, MAN_M_ROMAN)) return 0; }
	c->suppress_join = had_c;
	return 1;
}

/* If a .TP tag is pending, whatever content the caller just appended
 * to the (until-now-empty) accumulator becomes that tag. Call after
 * any content-appending line (text, .B/.I/.BI/.BR/.IR/.IB/.RB/.RI). */
static int man_maybe_consume_tag(struct man_ctx *c)
{
	if (!c->pending_tag) return 1;
	c->pending_tag = 0;
	if (c->acc.len == 0) return 1;
	return man_flush_as_tag(c, c->tag_width);
}

/* Maps one letter of a .BI/.IB/.BR/.RB/.IR/.RI macro NAME to the font it
 * selects: 'B' bold, 'I' italic, anything else (always 'R' in practice --
 * the letter is one of the six macro names' own two characters) roman. */
static int man_font_for_letter(char c)
{
	if (c == 'B') return MAN_M_BOLD;
	if (c == 'I') return MAN_M_ITAL;
	return MAN_M_ROMAN;
}

/* ==== macro dispatch ==================================================== */

struct man_render {
	struct man_buf title, section, date, source, manual;
};

static void man_th(struct man_ctx *c, struct man_argv *a,
                    struct man_buf *title, struct man_buf *section,
                    struct man_buf *date, struct man_buf *source, struct man_buf *manual)
{
	size_t i;
	struct man_buf *slots[5];
	slots[0] = title; slots[1] = section; slots[2] = date; slots[3] = source; slots[4] = manual;

	c->rs_depth = 0;
	c->rs_indent = MAN_BASE_INDENT;
	c->extra_indent = 0;
	c->pending_tag = 0;
	c->fill = 1;

	for (i = 0; i < 5; i++) mbuf_reset(slots[i]);
	for (i = 0; i < a->n && i < 5; i++)
		if (!decode_text(&c->regs, slots[i], a->v[i], strlen(a->v[i]), 0)) return;
}

static int man_center3(struct man_buf *doc, int width, const char *l, const char *ctr, const char *r)
{
	int ll = (int)strlen(l), cl = (int)strlen(ctr), rl = (int)strlen(r);
	int pad1, pad2;

	pad1 = (width - ll - cl - rl) / 2;
	if (pad1 < 1) pad1 = 1;
	pad2 = width - ll - cl - rl - pad1;
	if (pad2 < 1) pad2 = 1;

	if (!mbuf_appendstr(doc, l)) return 0;
	if (!mbuf_appendn(doc, pad1, ' ')) return 0;
	if (!mbuf_appendstr(doc, ctr)) return 0;
	if (!mbuf_appendn(doc, pad2, ' ')) return 0;
	if (!mbuf_appendstr(doc, r)) return 0;
	if (!mbuf_appendc(doc, '\n')) return 0;
	return 1;
}

/* Splits one physical input line into a (possibly empty) macro name
 * and the raw remainder, for lines whose first byte is '.'. */
static void man_split_request(const char *line, char *name, size_t namesz, const char **rest)
{
	size_t i = 1, k = 0;
	while (line[i] && line[i] != ' ' && line[i] != '\t' && k + 1 < namesz)
		name[k++] = line[i++];
	name[k] = 0;
	while (line[i] == ' ' || line[i] == '\t') i++;
	*rest = line + i;
}

/* Truncates `line` (in place) at the first unescaped `\"` sequence
 * (troff's "comment to end of line", valid anywhere, not just at the
 * start of a `.\"` request line). */
static void man_strip_comment(char *line)
{
	char *p = line;
	while ((p = strchr(p, '\\')) != 0) {
		if (p[1] == '"') { *p = 0; return; }
		if (p[1] == 0) return;
		p += 2;
	}
}

/* .ds NAME STRING...: defines/redefines a string register. STRING is
 * every remaining token, escape-decoded and rejoined with a single
 * space -- the same "join what man_tokenize split, add a single space
 * back" approach the .SH/.SS heading construction above already
 * uses. */
static int man_do_ds(struct man_ctx *c, struct man_argv *a)
{
	struct man_buf val;
	size_t i;
	int ok = 1;

	if (a->n < 1) return 1; /* ".ds" with no name: nothing to define */

	memset(&val, 0, sizeof val);
	for (i = 1; i < a->n; i++) {
		if (!ok) break;
		if (i > 1 && !mbuf_appendc(&val, ' ')) ok = 0;
		if (ok && !decode_text(&c->regs, &val, a->v[i], strlen(a->v[i]), 0)) ok = 0;
	}
	if (ok) ok = man_reg_set_string(&c->regs, a->v[0], val.data ? val.data : "");
	mbuf_free(&val);
	return ok;
}

/* Parses one decode_text()'d, plain (non-arithmetic) troff numeric
 * expression -- an optional leading `+`/`-` followed by decimal
 * digits, and nothing else. Real troff's `.nr` numeric expressions
 * also allow full arithmetic (`\n(.g-1`, `+`/`-`/`*`/`/` and more);
 * that shared evaluator is out of scope here (see this file's header
 * comment, "REGISTERS"), so an expression this simple form can't
 * parse is rejected rather than guessed at. */
static int man_parse_plain_number(const char *s, long *out)
{
	char *end;
	long v;
	if (!s || !*s) return 0;
	v = strtol(s, &end, 10);
	if (end == s || *end != 0) return 0;
	*out = v;
	return 1;
}

/* .nr NAME VALUE [INCR]: defines/redefines a number register. VALUE
 * and INCR are register-interpolated first (so `.nr x \n(y` works),
 * then each must be a plain signed integer per man_parse_plain_
 * number() -- a VALUE that isn't (e.g. an arithmetic expression) is
 * an honest no-op, register left untouched. A leading `+`/`-` on
 * VALUE means "add/subtract from NAME's current value" rather than
 * setting it outright, real troff's own distinction; the sign is read
 * straight off the decoded text, so no separate relative/absolute
 * flag is needed. */
static int man_do_nr(struct man_ctx *c, struct man_argv *a)
{
	struct man_buf val, incrbuf;
	long parsed, incr = 0;
	int have_incr = 0;
	int ok;

	if (a->n < 2) return 1; /* ".nr NAME" with no value: nothing to set */

	memset(&val, 0, sizeof val);
	memset(&incrbuf, 0, sizeof incrbuf);
	ok = decode_text(&c->regs, &val, a->v[1], strlen(a->v[1]), 0);
	if (ok && a->n >= 3) ok = decode_text(&c->regs, &incrbuf, a->v[2], strlen(a->v[2]), 0);
	if (ok && a->n >= 3) have_incr = man_parse_plain_number(incrbuf.data, &incr);

	if (ok && man_parse_plain_number(val.data, &parsed)) {
		struct man_reg *existing = man_reg_find(&c->regs, a->v[0]);
		long current = (existing && existing->kind == MAN_REG_NUMBER) ? existing->num : 0;
		int relative = val.data[0] == '+' || val.data[0] == '-';
		long newval = relative ? man_wrap_add(current, parsed) : parsed;
		ok = man_reg_set_number(&c->regs, a->v[0], newval, incr, have_incr);
	}

	mbuf_free(&val);
	mbuf_free(&incrbuf);
	return ok;
}

/* .rn OLD NEW: renames whichever thing OLD names -- a register (string
 * or number, whichever is defined -- see this file's header comment
 * for why this table doesn't separate string/number name spaces the
 * way real troff technically does), tried first, or otherwise a macro
 * (real troff's own `.rn` covers macros/strings, never number
 * registers, because of that name-space split -- checking the
 * register table first and falling back to the macro table gives the
 * same practical result: whichever thing OLD actually names gets
 * renamed). OLD not existing as either is a silent no-op; NEW already
 * existing is silently overwritten; both match real troff's own .rn
 * behaviour. */
static int man_do_rn(struct man_ctx *c, struct man_argv *a)
{
	struct man_reg *old;
	struct man_macro *oldm;
	char *newname;

	if (a->n < 2 || !strcmp(a->v[0], a->v[1])) return 1;

	if (man_reg_find(&c->regs, a->v[0])) {
		/* Overwrite any existing NEW first, then re-find OLD by name --
		 * man_reg_remove() can shift the table, invalidating any
		 * pointer taken before it ran. */
		man_reg_remove(&c->regs, a->v[1]);
		old = man_reg_find(&c->regs, a->v[0]);
		newname = strdup(a->v[1]);
		if (!newname) return 0;
		free(old->name);
		old->name = newname;
		return 1;
	}

	oldm = man_mac_find(&c->macros, a->v[0]);
	if (oldm) {
		man_mac_remove(&c->macros, a->v[1]);
		oldm = man_mac_find(&c->macros, a->v[0]);
		newname = strdup(a->v[1]);
		if (!newname) return 0;
		free(oldm->name);
		oldm->name = newname;
		return 1;
	}

	return 1; /* OLD doesn't exist as either kind: nothing to rename */
}

/* .rm NAME: deletes macro NAME; not existing is a silent no-op,
 * matching real troff's own .rm behaviour. */
static int man_do_rm(struct man_ctx *c, struct man_argv *a)
{
	if (a->n < 1) return 1;
	man_mac_remove(&c->macros, a->v[0]);
	return 1;
}

/* .als NEW OLD: makes NEW an independent copy of OLD's current body --
 * a real troff alias is a copy taken at alias time, not a live link,
 * so redefining OLD afterward does not change NEW. OLD not existing is
 * a silent no-op, the same honest-no-op precedent this file's other
 * register/macro-management requests already follow for a missing
 * source name. */
static int man_do_als(struct man_ctx *c, struct man_argv *a)
{
	struct man_macro *old, *new;
	size_t i;

	if (a->n < 2) return 1;
	old = man_mac_find(&c->macros, a->v[1]);
	if (!old) return 1;
	new = man_mac_get_or_create(&c->macros, a->v[0]);
	if (!new) return 0;
	man_macro_free_lines(new);
	for (i = 0; i < old->n; i++)
		if (!man_macro_add_line(new, old->lines[i])) return 0;
	return 1;
}

/* Argument-substitution escapes real troff recognises inside a macro
 * body -- see this file's own header comment ("MACROS") for the full
 * design rationale. Textual, over the RAW stored body line, before
 * that line is tokenized/decoded like any other source line -- \$1
 * substitutes with `args`' raw (undecoded) text, decoded normally once
 * the whole substituted line is processed downstream. */
static int man_macro_subst_args(const char *body, const char *macroname,
    struct man_argv *args, struct man_buf *out)
{
	size_t n = strlen(body);
	size_t i = 0;

	while (i < n) {
		if (body[i] == '\\' && i + 2 < n && body[i + 1] == '$') {
			char sel = body[i + 2];
			if (sel >= '1' && sel <= '9') {
				size_t idx = (size_t)(sel - '1');
				if (idx < args->n && !mbuf_appendstr(out, args->v[idx])) return 0;
				i += 3;
				continue;
			}
			if (sel == '0') {
				if (!mbuf_appendstr(out, macroname)) return 0;
				i += 3;
				continue;
			}
			if (sel == '*' || sel == '@') {
				size_t k;
				for (k = 0; k < args->n; k++) {
					if (k && !mbuf_appendc(out, ' ')) return 0;
					if (!mbuf_appendstr(out, args->v[k])) return 0;
				}
				i += 3;
				continue;
			}
		}
		if (!mbuf_appendc(out, body[i])) return 0;
		i++;
	}
	return 1;
}

/* .de/.de1/.am/.am1/.ig: begins collecting body lines into c->def_*
 * state -- see this file's own header comment ("MACROS") for the
 * default-vs-custom end-marker syntax. `.de`/`.am` replace/append to a
 * macro named by argv[0]; `.ig` has no macro-name argument at all
 * (argv[0], if present, is instead the custom end-marker). */
static int man_begin_macro_def(struct man_ctx *c, const char *directive, struct man_argv *a)
{
	int append = !strcmp(directive, "am") || !strcmp(directive, "am1");
	int discard = !strcmp(directive, "ig");

	free(c->def_end);
	c->def_end = 0;
	c->def_target = 0;

	if (discard) {
		if (a->n > 0) { c->def_end = strdup(a->v[0]); if (!c->def_end) return 0; }
	} else {
		if (a->n < 1) return 1; /* .de/.am with no name: real troff errors; honest no-op here */
		c->def_target = man_mac_get_or_create(&c->macros, a->v[0]);
		if (!c->def_target) return 0;
		if (!append) man_macro_free_lines(c->def_target);
		if (a->n > 1) { c->def_end = strdup(a->v[1]); if (!c->def_end) return 0; }
	}

	c->def_discard = discard;
	c->def_active = 1;
	return 1;
}

/* ==== TABLES: .TS/.TE (tbl) -- see this file's own header comment
 * ("TABLES") for the full design writeup; everything below is the
 * mechanical implementation of that design. ==== */

#define MAN_TBL_COL_GAP 3   /* inter-column spacing for a non-boxed table */
#define MAN_TBL_MAX_COLS 64 /* bound against a pathological/malformed format line, same discipline as MAN_MAX_RS_DEPTH */

enum man_tbl_align { MAN_TBL_LEFT, MAN_TBL_CENTER, MAN_TBL_RIGHT, MAN_TBL_NUMERIC, MAN_TBL_SPAN, MAN_TBL_VSPAN };

struct man_tbl_colspec { enum man_tbl_align align; int bold, ital; };

struct man_tbl_fmtrow { struct man_tbl_colspec *v withtok(heap_allocated); size_t n, cap; };

struct man_tbl_fmt { struct man_tbl_fmtrow *v withtok(heap_allocated); size_t n, cap; };

/* kind: 0 = real text (cell.text is the decoded/styled content), 1 =
 * horizontal span (`s`: no field consumed, blank filler), 2 = vertical
 * span (`^`: no field consumed, blank filler), 3 = single-rule field
 * (`_`: fill this cell's own column width with `-`), 4 = double-rule
 * field (`=`: fill with `=`). */
struct man_tbl_cell { int kind; char *text withtok(heap_allocated); };

/* full_rule: 0 = an ordinary row of `cells`, 1 = a whole-table `_`
 * single-rule row, 2 = a whole-table `=` double-rule row (neither of
 * which has any cells, and neither of which consumes a format-line
 * slot -- see this file's header comment). */
struct man_tbl_row { int full_rule; struct man_tbl_cell *cells withtok(heap_allocated); size_t ncells; };

struct man_tbl_rows { struct man_tbl_row *v withtok(heap_allocated); size_t n, cap; };

static void man_tbl_fmtrow_free(struct man_tbl_fmtrow *r) { free(r->v); r->v = 0; r->n = r->cap = 0; }

static int man_tbl_fmtrow_push(struct man_tbl_fmtrow *r, struct man_tbl_colspec cs)
{
	if (r->n + 1 > r->cap) {
		size_t newcap;
		struct man_tbl_colspec *g;
		if (!__util_array_capacity(r->cap, r->n, 1, 8, sizeof *r->v, &newcap)) return 0;
		g = __util_reallocarray(r->v, newcap, sizeof *r->v);
		if (!g) return 0;
		r->v = g; r->cap = newcap;
	}
	r->v[r->n++] = cs;
	return 1;
}

static void man_tbl_fmt_free(struct man_tbl_fmt *f)
{
	size_t i;
	for (i = 0; i < f->n; i++) man_tbl_fmtrow_free(&f->v[i]);
	free(f->v); f->v = 0; f->n = f->cap = 0;
}

static struct man_tbl_fmtrow *man_tbl_fmt_new_row(struct man_tbl_fmt *f)
{
	if (f->n + 1 > f->cap) {
		size_t newcap;
		struct man_tbl_fmtrow *g;
		if (!__util_array_capacity(f->cap, f->n, 1, 4, sizeof *f->v, &newcap)) return 0;
		g = __util_reallocarray(f->v, newcap, sizeof *f->v);
		if (!g) return 0;
		f->v = g; f->cap = newcap;
	}
	memset(&f->v[f->n], 0, sizeof f->v[f->n]);
	return &f->v[f->n++];
}

static void man_tbl_row_free(struct man_tbl_row *row)
{
	size_t i;
	for (i = 0; i < row->ncells; i++) free(row->cells[i].text);
	free(row->cells);
	row->cells = 0; row->ncells = 0;
}

static void man_tbl_rows_free(struct man_tbl_rows *rs)
{
	size_t i;
	for (i = 0; i < rs->n; i++) man_tbl_row_free(&rs->v[i]);
	free(rs->v); rs->v = 0; rs->n = rs->cap = 0;
}

static struct man_tbl_row *man_tbl_rows_new(struct man_tbl_rows *rs)
{
	if (rs->n + 1 > rs->cap) {
		size_t newcap;
		struct man_tbl_row *g;
		if (!__util_array_capacity(rs->cap, rs->n, 1, 8, sizeof *rs->v, &newcap)) return 0;
		g = __util_reallocarray(rs->v, newcap, sizeof *rs->v);
		if (!g) return 0;
		rs->v = g; rs->cap = newcap;
	}
	memset(&rs->v[rs->n], 0, sizeof rs->v[rs->n]);
	return &rs->v[rs->n++];
}

/* Splits a tbl option/format-spec line on whitespace and commas (real
 * tbl accepts either between column descriptors) into raw tokens.
 * Deliberately not man_tokenize(): that splitter is shaped for troff
 * REQUEST ARGUMENTS (`"quoted strings"`, `\`-escaped spaces), neither
 * of which tbl's own option/format mini-language uses. Reuses struct
 * man_argv purely as a generic growable char* array, the same way
 * struct man_macro is reused as a plain line list for cond_body/
 * tbl_body above. */
static int man_tbl_split(const char *s, struct man_argv *out)
{
	size_t i = 0, n = strlen(s);
	memset(out, 0, sizeof *out);
	while (i < n) {
		size_t start;
		while (i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == ',')) i++;
		if (i >= n) break;
		start = i;
		while (i < n && s[i] != ' ' && s[i] != '\t' && s[i] != ',') i++;
		if (!man_argv_push(out, s + start, i - start)) { man_argv_free(out); return 0; }
	}
	return 1;
}

/* Trims leading/trailing spaces/tabs (and a trailing '\r', for a page
 * with CRLF line endings) from `s`, returning the trimmed span as a
 * start offset + length rather than a copy -- every caller already
 * holds `s` alive for at least as long as it needs the span. */
static void man_tbl_trim_span(const char *s, size_t *start, size_t *len)
{
	size_t n = strlen(s), a = 0, b = n;
	while (a < b && (s[a] == ' ' || s[a] == '\t')) a++;
	while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r')) b--;
	*start = a; *len = b - a;
}

/* One column descriptor token (`l`, `cb`, `n`, `s`, `^`, `lw(10)`, ...)
 * -- see this file's own header comment ("TABLES", point 2) for
 * exactly which modifier letters are recognised-and-applied (b/i) vs
 * recognised-and-consumed-only (everything else, including `(...)`
 * groups like `w(N)`). */
static void man_tbl_parse_colspec(const char *tok, struct man_tbl_colspec *out)
{
	size_t i, n = strlen(tok);
	memset(out, 0, sizeof *out);
	if (n == 0) { out->align = MAN_TBL_LEFT; return; }
	switch (tok[0]) {
	case 'c': case 'C': out->align = MAN_TBL_CENTER; break;
	case 'r': case 'R': out->align = MAN_TBL_RIGHT; break;
	case 'n': case 'N': out->align = MAN_TBL_NUMERIC; break;
	case 's': case 'S': out->align = MAN_TBL_SPAN; break;
	case '^': out->align = MAN_TBL_VSPAN; break;
	default: out->align = MAN_TBL_LEFT; break; /* l/L, and a/A/e/E degraded to left -- see header comment */
	}
	for (i = 1; i < n; i++) {
		char m = tok[i];
		if (m == 'b' || m == 'B') out->bold = 1;
		else if (m == 'i' || m == 'I' || m == 'u' || m == 'U') out->ital = 1;
		else if (m == '(') { i++; while (i < n && tok[i] != ')') i++; }
		/* else: a width/point-size digit or another modifier letter
		 * (f/t/p/v/z/e) -- recognised, not applied, see header comment. */
	}
}

/* Splits `s` into the visible-column width to the LEFT of its first
 * `.` and the visible-column width FROM that `.` onward (the `.`
 * itself counted on the right side) -- man_vislen()'s own UTF-8/
 * marker-skipping logic, just tallied into two buckets instead of one.
 * A cell with no `.` is all left-side, matching plain-integer numeric
 * alignment. See this file's header comment ("TABLES", "COLUMN WIDTH
 * AND ALIGNMENT"). */
static void man_tbl_decimal_split(const char *s, size_t *leftvis, size_t *rightvis)
{
	size_t i, n = strlen(s), dot = n;
	*leftvis = 0; *rightvis = 0;
	for (i = 0; i < n; i++) if (s[i] == '.') { dot = i; break; }
	for (i = 0; i < n; i++) {
		unsigned char ch = (unsigned char)s[i];
		if (ch == (unsigned char)MAN_M_BOLD || ch == (unsigned char)MAN_M_ITAL ||
		    ch == (unsigned char)MAN_M_ROMAN) continue;
		if ((ch & 0xC0) == 0x80) continue;
		if (i < dot) (*leftvis)++; else (*rightvis)++;
	}
}

/* Emits one full-width box border/rule line -- `+---+----+` when
 * `boxed`, or a bare run of `ch` spanning the same total content width
 * otherwise. Shared by the table's own top/bottom/allbox borders and
 * by a `_`/`=` whole-table rule row (see this file's header comment,
 * "TABLES"): a rule row IS exactly a border line, just with `ch`
 * chosen by which rule character the page used. */
static int man_tbl_emit_border(struct man_buf *doc, int indent, const int *width, size_t ncols, char ch, int boxed)
{
	size_t j;
	if (!mbuf_appendn(doc, indent, ' ')) return 0;
	if (!boxed) {
		int total = 0;
		for (j = 0; j < ncols; j++) total += width[j] + (j ? MAN_TBL_COL_GAP : 0);
		if (!mbuf_appendn(doc, total, ch)) return 0;
		return mbuf_appendc(doc, '\n');
	}
	if (!mbuf_appendc(doc, '+')) return 0;
	for (j = 0; j < ncols; j++) {
		if (!mbuf_appendn(doc, width[j] + 2, ch)) return 0;
		if (!mbuf_appendc(doc, '+')) return 0;
	}
	return mbuf_appendc(doc, '\n');
}

/* Pads and appends one cell's rendering into `doc`, per its own kind
 * and (for real text) the column's alignment -- see this file's header
 * comment ("TABLES", "COLUMN WIDTH AND ALIGNMENT") for the numeric
 * decimal-point math `numleft` feeds. */
static int man_tbl_emit_cell(struct man_buf *doc, const struct man_tbl_cell *cell,
    enum man_tbl_align align, int width, int numleft)
{
	const char *text;
	size_t vv;
	int pad;

	if (cell->kind == 1 || cell->kind == 2) return mbuf_appendn(doc, width, ' ');
	if (cell->kind == 3) return mbuf_appendn(doc, width, '-');
	if (cell->kind == 4) return mbuf_appendn(doc, width, '=');

	text = cell->text ? cell->text : "";
	vv = man_vislen(text, strlen(text));
	pad = width - (int)vv;
	if (pad < 0) pad = 0;

	if (align == MAN_TBL_RIGHT) {
		if (!mbuf_appendn(doc, pad, ' ')) return 0;
		return mbuf_append(doc, text, strlen(text));
	}
	if (align == MAN_TBL_CENTER) {
		int lp = pad / 2, rp = pad - lp;
		if (!mbuf_appendn(doc, lp, ' ')) return 0;
		if (!mbuf_append(doc, text, strlen(text))) return 0;
		return mbuf_appendn(doc, rp, ' ');
	}
	if (align == MAN_TBL_NUMERIC) {
		size_t lv, rv;
		int lp, rp;
		man_tbl_decimal_split(text, &lv, &rv);
		lp = numleft - (int)lv;
		if (lp < 0) lp = 0;
		if (!mbuf_appendn(doc, lp, ' ')) return 0;
		if (!mbuf_append(doc, text, strlen(text))) return 0;
		rp = width - lp - (int)vv;
		if (rp < 0) rp = 0;
		return mbuf_appendn(doc, rp, ' ');
	}
	/* LEFT (and the SPAN/VSPAN/rule kinds handled above never reach here). */
	if (!mbuf_append(doc, text, strlen(text))) return 0;
	return mbuf_appendn(doc, pad, ' ');
}

/* Parses and renders one already-collected `.TS`...`.TE` block (`body`
 * -- struct man_macro reused as a plain raw-line list, c->tbl_body's
 * own shape) into c->doc. See this file's own header comment
 * ("TABLES") for the full three-part grammar this walks: an optional
 * `;`-terminated options line, one or more format-spec lines ending in
 * a lone `.`, then data rows up to the block's own end. A malformed
 * table with no recognisable format-spec line is an honest no-op --
 * the same "silently skipped, rest of the page still renders"
 * precedent "UNKNOWN-MACRO DEGRADATION" documents elsewhere in this
 * file -- rather than a hard failure. */
static int man_render_table(struct man_ctx *c, struct man_macro *body)
{
	size_t li = 0, i;
	int have_box = 0, have_allbox = 0, have_center = 0;
	char tabch = '\t';
	struct man_tbl_fmt fmt;
	struct man_tbl_rows rows;
	struct man_tbl_colspec *disp = 0;
	size_t ncols = 0;
	int *width = 0, *numleft = 0, *numright = 0;
	int ok = 1;

	memset(&fmt, 0, sizeof fmt);
	memset(&rows, 0, sizeof rows);

	while (li < body->n) {
		size_t start, len;
		man_tbl_trim_span(body->lines[li], &start, &len);
		if (len > 0) break;
		li++;
	}

	if (li < body->n) {
		size_t start, len;
		man_tbl_trim_span(body->lines[li], &start, &len);
		if (len > 0 && body->lines[li][start + len - 1] == ';') {
			struct man_argv opts;
			char optline[512];
			size_t copylen = len - 1;
			size_t k;
			if (copylen >= sizeof optline) copylen = sizeof optline - 1;
			for (k = 0; k < copylen; k++) optline[k] = body->lines[li][start + k];
			optline[copylen] = 0;
			if (!man_tbl_split(optline, &opts)) return 0;
			for (i = 0; i < opts.n; i++) {
				const char *kw = opts.v[i];
				if (!strncasecmp(kw, "tab(", 4) && strlen(kw) >= 6) tabch = kw[4];
				else if (!strcasecmp(kw, "box") || !strcasecmp(kw, "frame")) have_box = 1;
				else if (!strcasecmp(kw, "allbox")) { have_box = 1; have_allbox = 1; }
				else if (!strcasecmp(kw, "doublebox") || !strcasecmp(kw, "allframe")) have_box = 1;
				else if (!strcasecmp(kw, "center") || !strcasecmp(kw, "centre")) have_center = 1;
				/* expand/linesize(N)/delim(xx)/nospaces/nowarn/nokeep/nocenter: see header comment */
			}
			man_argv_free(&opts);
			li++;
		}
	}

	while (li < body->n) {
		size_t start, len, llen;
		struct man_argv toks;
		struct man_tbl_fmtrow *row;
		int done_here = 0;
		char tmp[512];
		size_t clen;

		man_tbl_trim_span(body->lines[li], &start, &len);
		if (len == 0) { li++; continue; }

		llen = len;
		if (body->lines[li][start + llen - 1] == '.') {
			done_here = 1;
			llen--;
			while (llen > 0 && (body->lines[li][start + llen - 1] == ' ' ||
			    body->lines[li][start + llen - 1] == '\t')) llen--;
		}

		clen = llen;
		if (clen >= sizeof tmp) clen = sizeof tmp - 1;
		{
			size_t k;
			for (k = 0; k < clen; k++) tmp[k] = body->lines[li][start + k];
		}
		tmp[clen] = 0;
		if (!man_tbl_split(tmp, &toks)) { man_tbl_fmt_free(&fmt); return 0; }

		row = man_tbl_fmt_new_row(&fmt);
		if (!row) { man_argv_free(&toks); man_tbl_fmt_free(&fmt); return 0; }
		for (i = 0; i < toks.n && i < MAN_TBL_MAX_COLS; i++) {
			struct man_tbl_colspec cs;
			man_tbl_parse_colspec(toks.v[i], &cs);
			if (!man_tbl_fmtrow_push(row, cs)) { man_argv_free(&toks); man_tbl_fmt_free(&fmt); return 0; }
		}
		if (row->n > ncols) ncols = row->n;
		man_argv_free(&toks);
		li++;
		if (done_here) break;
	}

	if (fmt.n == 0 || ncols == 0) { man_tbl_fmt_free(&fmt); return 1; }
	if (ncols > MAN_TBL_MAX_COLS) ncols = MAN_TBL_MAX_COLS;

	disp = calloc(ncols, sizeof *disp);
	if (!disp) { man_tbl_fmt_free(&fmt); return 0; }
	{
		struct man_tbl_fmtrow *last = &fmt.v[fmt.n - 1];
		for (i = 0; i < ncols; i++) {
			if (i < last->n) disp[i] = last->v[i];
			else { disp[i].align = MAN_TBL_LEFT; disp[i].bold = 0; disp[i].ital = 0; }
		}
	}

	{
		size_t data_idx = 0;
		for (; li < body->n; li++) {
			size_t start, len;
			if (!ok) break;
			man_tbl_trim_span(body->lines[li], &start, &len);
			if (len == 1 && body->lines[li][start] == '_') {
				struct man_tbl_row *rw = man_tbl_rows_new(&rows);
				if (!rw) { ok = 0; break; }
				rw->full_rule = 1;
				continue;
			}
			if (len == 1 && body->lines[li][start] == '=') {
				struct man_tbl_row *rw = man_tbl_rows_new(&rows);
				if (!rw) { ok = 0; break; }
				rw->full_rule = 2;
				continue;
			}
			if (len == 0) continue;

			{
				struct man_tbl_fmtrow *frow = &fmt.v[data_idx < fmt.n ? data_idx : fmt.n - 1];
				struct man_tbl_row *rw = man_tbl_rows_new(&rows);
				const char *raw = body->lines[li];
				size_t rn = strlen(raw), p = 0;

				if (!rw) { ok = 0; break; }
				rw->cells = calloc(ncols, sizeof *rw->cells);
				if (!rw->cells) { ok = 0; break; }
				rw->ncells = ncols;

				for (i = 0; i < ncols; i++) {
					struct man_tbl_colspec cs = (i < frow->n) ? frow->v[i] : disp[i];

					if (!ok) break;
					if (cs.align == MAN_TBL_SPAN || cs.align == MAN_TBL_VSPAN) {
						rw->cells[i].kind = (cs.align == MAN_TBL_SPAN) ? 1 : 2;
						continue;
					}
					if (p > rn) {
						rw->cells[i].text = strdup("");
						if (!rw->cells[i].text) ok = 0;
						continue;
					}
					{
						size_t fs = p, fe, tstart, tlen;
						while (p < rn && raw[p] != tabch) p++;
						fe = p;
						p = (p < rn) ? p + 1 : rn + 1;
						tstart = fs; tlen = fe - fs;
						while (tlen > 0 && (raw[tstart] == ' ' || raw[tstart] == '\t')) { tstart++; tlen--; }
						while (tlen > 0 && (raw[tstart + tlen - 1] == ' ' || raw[tstart + tlen - 1] == '\t')) tlen--;
						if (tlen == 1 && raw[tstart] == '_') rw->cells[i].kind = 3;
						else if (tlen == 1 && raw[tstart] == '=') rw->cells[i].kind = 4;
						else {
							struct man_buf cell;
							int font = cs.bold ? MAN_M_BOLD : (cs.ital ? MAN_M_ITAL : 0);
							memset(&cell, 0, sizeof cell);
							if (font && !mbuf_appendc(&cell, (char)font)) ok = 0;
							if (ok && !decode_text(&c->regs, &cell, raw + tstart, tlen, 0)) ok = 0;
							if (ok && font && !mbuf_appendc(&cell, MAN_M_ROMAN)) ok = 0;
							if (ok) {
								rw->cells[i].text = strdup(cell.data ? cell.data : "");
								if (!rw->cells[i].text) ok = 0;
							}
							mbuf_free(&cell);
						}
					}
				}
				data_idx++;
			}
		}
	}

	if (ok) {
		width = calloc(ncols, sizeof *width);
		numleft = calloc(ncols, sizeof *numleft);
		numright = calloc(ncols, sizeof *numright);
		if (!width || !numleft || !numright) ok = 0;
	}
	if (ok) {
		size_t j, ri;
		for (j = 0; j < ncols; j++) {
			for (ri = 0; ri < rows.n; ri++) {
				struct man_tbl_row *rw = &rows.v[ri];
				struct man_tbl_cell *cell;
				if (rw->full_rule || j >= rw->ncells) continue;
				cell = &rw->cells[j];
				if (cell->kind != 0) continue;
				if (disp[j].align == MAN_TBL_NUMERIC) {
					size_t lv, rv;
					man_tbl_decimal_split(cell->text ? cell->text : "", &lv, &rv);
					if ((int)lv > numleft[j]) numleft[j] = (int)lv;
					if ((int)rv > numright[j]) numright[j] = (int)rv;
				} else {
					size_t vv = man_vislen(cell->text ? cell->text : "", strlen(cell->text ? cell->text : ""));
					if ((int)vv > width[j]) width[j] = (int)vv;
				}
			}
			if (disp[j].align == MAN_TBL_NUMERIC) width[j] = numleft[j] + numright[j];
		}
	}

	if (ok) ok = man_flush_paragraph(c);
	if (ok) { c->extra_indent = 0; c->pending_tag = 0; }
	if (ok) {
		int indent = c->rs_indent + c->extra_indent;
		int total = 0;
		size_t j, ri;

		for (j = 0; j < ncols; j++) total += width[j] + (j ? MAN_TBL_COL_GAP : 0);
		if (have_box) { total = 1; for (j = 0; j < ncols; j++) total += width[j] + 3; }
		if (have_center) {
			int room = c->width - indent - total;
			if (room > 0) indent += room / 2;
		}

		ok = man_block_start(c);
		if (ok && have_box) ok = man_tbl_emit_border(&c->doc, indent, width, ncols, '-', 1);
		for (ri = 0; ri < rows.n; ri++) {
			struct man_tbl_row *rw = &rows.v[ri];
			if (!ok) break;
			if (rw->full_rule) {
				ok = man_tbl_emit_border(&c->doc, indent, width, ncols, rw->full_rule == 2 ? '=' : '-', have_box);
				continue;
			}
			ok = mbuf_appendn(&c->doc, indent, ' ');
			if (ok && have_box) ok = mbuf_appendstr(&c->doc, "| ");
			for (j = 0; j < ncols; j++) {
				if (!ok) break;
				ok = man_tbl_emit_cell(&c->doc, &rw->cells[j], disp[j].align, width[j], numleft[j]);
				if (ok) {
					if (j + 1 < ncols) ok = have_box ? mbuf_appendstr(&c->doc, " | ") : mbuf_appendn(&c->doc, MAN_TBL_COL_GAP, ' ');
					else if (have_box) ok = mbuf_appendstr(&c->doc, " |");
				}
			}
			if (ok) ok = mbuf_appendc(&c->doc, '\n');
			if (ok && have_allbox && ri + 1 < rows.n && !rows.v[ri + 1].full_rule)
				ok = man_tbl_emit_border(&c->doc, indent, width, ncols, '-', 1);
		}
		if (ok && have_box) ok = man_tbl_emit_border(&c->doc, indent, width, ncols, '-', 1);
		if (ok) c->had_output = 1;
	}

	free(disp);
	free(width);
	free(numleft);
	free(numright);
	man_tbl_fmt_free(&fmt);
	man_tbl_rows_free(&rows);
	return ok;
}

/* ==== EQN: .EQ/.EN -- see this file's own header comment ("EQN") for
 * the full design writeup; everything below is the mechanical
 * implementation of that design. ==== */

/* `\(*a`-style Greek-LETTER-NAME lookup for eqn's own bare (unquoted)
 * word tokens -- see this file's header comment ("EQN") for exactly
 * which names are covered: the full 24-letter lowercase alphabet, plus
 * the 11 uppercase names whose glyph actually differs from a plain
 * Latin letter (real troff/eqn has no separate uppercase name for
 * ALPHA/BETA/EPSILON/... since they'd be visually identical to A/B/E/
 * ..., so neither does this table). */
static const struct { const char *name; const char *rep; } man_eqn_greek[] = {
	{ "alpha", "\xCE\xB1" }, { "beta", "\xCE\xB2" }, { "gamma", "\xCE\xB3" },
	{ "delta", "\xCE\xB4" }, { "epsilon", "\xCE\xB5" }, { "zeta", "\xCE\xB6" },
	{ "eta", "\xCE\xB7" }, { "theta", "\xCE\xB8" }, { "iota", "\xCE\xB9" },
	{ "kappa", "\xCE\xBA" }, { "lambda", "\xCE\xBB" }, { "mu", "\xCE\xBC" },
	{ "nu", "\xCE\xBD" }, { "xi", "\xCE\xBE" }, { "omicron", "\xCE\xBF" },
	{ "pi", "\xCF\x80" }, { "rho", "\xCF\x81" }, { "sigma", "\xCF\x83" },
	{ "tau", "\xCF\x84" }, { "upsilon", "\xCF\x85" }, { "phi", "\xCF\x86" },
	{ "chi", "\xCF\x87" }, { "psi", "\xCF\x88" }, { "omega", "\xCF\x89" },
	{ "GAMMA", "\xCE\x93" }, { "DELTA", "\xCE\x94" }, { "THETA", "\xCE\x98" },
	{ "LAMBDA", "\xCE\x9B" }, { "XI", "\xCE\x9E" }, { "PI", "\xCE\xA0" },
	{ "SIGMA", "\xCE\xA3" }, { "UPSILON", "\xCE\xA5" }, { "PHI", "\xCE\xA6" },
	{ "PSI", "\xCE\xA8" }, { "OMEGA", "\xCE\xA9" },
};

static const char *man_eqn_lookup_greek(const char *name)
{
	size_t i;
	for (i = 0; i < sizeof man_eqn_greek / sizeof *man_eqn_greek; i++)
		if (!strcmp(man_eqn_greek[i].name, name)) return man_eqn_greek[i].rep;
	return 0;
}

/* One eqn source token: `{`/`}` are always their own token regardless
 * of surrounding whitespace (real eqn's own rule); a `"..."` span is
 * one literal token with `quoted` set, exempting it from keyword
 * (`sub`/`sup`/`over`/`sqrt`) and Greek-letter-name recognition --
 * matching real eqn, where only a BARE word is ever looked up as a
 * keyword or a named letter. */
struct man_eqn_tok { char *text withtok(heap_allocated); int quoted; };
struct man_eqn_toks { struct man_eqn_tok *v withtok(heap_allocated); size_t n, cap; };

static void man_eqn_toks_free(struct man_eqn_toks *t)
{
	size_t i;
	for (i = 0; i < t->n; i++) free(t->v[i].text);
	free(t->v);
	t->v = 0; t->n = t->cap = 0;
}

static int man_eqn_toks_push(struct man_eqn_toks *t, const char *s, size_t n, int quoted)
{
	char *dup;
	if (t->n + 1 > t->cap) {
		size_t newcap;
		struct man_eqn_tok *g;
		if (!__util_array_capacity(t->cap, t->n, 1, 16, sizeof *t->v, &newcap)) return 0;
		g = __util_reallocarray(t->v, newcap, sizeof *t->v);
		if (!g) return 0;
		t->v = g; t->cap = newcap;
	}
	{
		size_t bytes;
		if (!__util_size_add(n, 1, &bytes)) return 0;
		dup = malloc(bytes);
	}
	if (!dup) return 0;
	memcpy(dup, s, n);
	dup[n] = 0;
	t->v[t->n].text = dup;
	t->v[t->n].quoted = quoted;
	t->n++;
	return 1;
}

static int man_eqn_tokenize(const char *s, struct man_eqn_toks *out)
{
	size_t i = 0, n = strlen(s);
	memset(out, 0, sizeof *out);
	while (i < n) {
		while (i < n && (s[i] == ' ' || s[i] == '\t')) i++;
		if (i >= n) break;
		if (s[i] == '{' || s[i] == '}') {
			if (!man_eqn_toks_push(out, s + i, 1, 0)) { man_eqn_toks_free(out); return 0; }
			i++;
			continue;
		}
		if (s[i] == '"') {
			size_t start = ++i;
			while (i < n && s[i] != '"') i++;
			if (!man_eqn_toks_push(out, s + start, i - start, 1)) { man_eqn_toks_free(out); return 0; }
			if (i < n) i++;
			continue;
		}
		{
			size_t start = i;
			while (i < n && s[i] != ' ' && s[i] != '\t' && s[i] != '{' && s[i] != '}' && s[i] != '"') i++;
			if (!man_eqn_toks_push(out, s + start, i - start, 0)) { man_eqn_toks_free(out); return 0; }
		}
	}
	return 1;
}

/* One parsed eqn value: `text` is its rendered linear-approximation
 * string; `compound` marks whether it represents MORE than one
 * juxtaposed primary (a concatenation, or an `over` division result)
 * -- see man_eqn_wrap() and this file's header comment ("EQN") for why
 * that distinction is what decides whether embedding this value as a
 * sub/sup/over operand needs an extra disambiguating delimiter around
 * it, instead of always adding one (`x sub i` should read "x_i", not
 * the noisier "x_{i}"). */
struct man_eqn_val { char *text withtok(heap_allocated); int compound; };

static void man_eqn_val_free(struct man_eqn_val *v) { free(v->text); v->text = 0; }

static int man_eqn_val_set(struct man_eqn_val *v, const char *text, int compound)
{
	v->text = strdup(text);
	v->compound = compound;
	return v->text != 0;
}

/* Wraps `v` in `open`/`close` only if v->compound -- an atomic value
 * (a single word, a single Greek letter, an already-self-delimited
 * `sqrt(...)`) is returned unwrapped. */
static int man_eqn_wrap(const struct man_eqn_val *v, char open, char close, char **out)
{
	size_t n;
	char *s;
	if (!v->compound) { *out = strdup(v->text ? v->text : ""); return *out != 0; }
	n = strlen(v->text);
	{
		size_t bytes;
		if (!__util_size_add(n, 3, &bytes)) return 0;
		s = malloc(bytes);
	}
	if (!s) return 0;
	s[0] = open;
	memcpy(s + 1, v->text, n);
	s[1 + n] = close;
	s[2 + n] = 0;
	*out = s;
	return 1;
}

struct man_eqn_parser { struct man_eqn_toks *toks; size_t pos; int depth; };

static const struct man_eqn_tok *man_eqn_peek(struct man_eqn_parser *p)
{
	return p->pos < p->toks->n ? &p->toks->v[p->pos] : 0;
}

static const struct man_eqn_tok *man_eqn_advance(struct man_eqn_parser *p)
{
	return p->pos < p->toks->n ? &p->toks->v[p->pos++] : 0;
}

static int man_eqn_is_kw(const struct man_eqn_tok *t, const char *kw)
{
	return t && !t->quoted && !strcmp(t->text, kw);
}

static int man_eqn_parse_expr(struct man_eqn_parser *p, struct man_eqn_val *out);

/* primary := WORD | QUOTED-STRING | '{' expr '}' | 'sqrt' primary
 *
 * A `{...}` group is transparent grouping only -- its own parsed value
 * (text AND compound flag) is returned as-is, exactly as if the braces
 * were never there; braces exist purely to scope what an outer sub/
 * sup/over/sqrt applies to, never to add visible output of their own
 * (matching real eqn). A `sqrt` with no following primary, or a bare
 * `sub`/`sup`/`over` keyword with no valid preceding operand (caught
 * by the callers below, not here), falls back to being treated as
 * ordinary literal text -- the same forgiving "malformed input degrades
 * honestly, never crashes" precedent this file gives elsewhere (see
 * e.g. "UNKNOWN-MACRO DEGRADATION" in this file's own header comment). */
static int man_eqn_parse_primary(struct man_eqn_parser *p, struct man_eqn_val *out)
{
	const struct man_eqn_tok *t = man_eqn_peek(p);

	if (!t) return man_eqn_val_set(out, "", 0);

	if (man_eqn_is_kw(t, "{")) {
		struct man_eqn_val inner;
		int ok;
		man_eqn_advance(p);
		if (p->depth >= MAN_EQN_MAX_DEPTH) {
			/* Bounded recursion: stop descending into this group (skip
			 * to its matching close, best-effort) rather than growing
			 * the parse stack without limit -- see MAN_EQN_MAX_DEPTH. */
			while ((t = man_eqn_peek(p)) != 0 && !man_eqn_is_kw(t, "}")) man_eqn_advance(p);
			if (t) man_eqn_advance(p);
			return man_eqn_val_set(out, "", 0);
		}
		p->depth++;
		ok = man_eqn_parse_expr(p, &inner);
		p->depth--;
		if (!ok) return 0;
		t = man_eqn_peek(p);
		if (man_eqn_is_kw(t, "}")) man_eqn_advance(p);
		*out = inner;
		return 1;
	}

	if (man_eqn_is_kw(t, "}")) return man_eqn_val_set(out, "", 0); /* stray close: empty, don't consume */

	if (man_eqn_is_kw(t, "sqrt")) {
		struct man_eqn_val operand;
		struct man_buf b;
		man_eqn_advance(p);
		if (!man_eqn_parse_primary(p, &operand)) return 0;
		memset(&b, 0, sizeof b);
		if (!mbuf_appendstr(&b, "sqrt(") || !mbuf_appendstr(&b, operand.text ? operand.text : "") ||
		    !mbuf_appendc(&b, ')')) { mbuf_free(&b); man_eqn_val_free(&operand); return 0; }
		man_eqn_val_free(&operand);
		out->text = b.data ? b.data : strdup("");
		out->compound = 0;
		return out->text != 0;
	}

	{
		const char *rep = t->quoted ? 0 : man_eqn_lookup_greek(t->text);
		int ok = man_eqn_val_set(out, rep ? rep : t->text, 0);
		man_eqn_advance(p);
		return ok;
	}
}

/* postfix := primary ('sub' primary)? ('sup' primary)?
 *          | primary ('sup' primary)? ('sub' primary)?
 *
 * Real eqn allows either order (`x sub i sup 2` and `x sup 2 sub i`
 * both place `i` as the subscript and `2` as the superscript); this
 * loop accepts either, bounded to (at most) one of each -- a repeated
 * second `sub` or `sup` on the same primary is not this file's
 * documented scope (real pages needing that nest with braces instead,
 * `x sub {i sub j}`, which the grouping above already handles), so it
 * falls through and is read as a literal word by the next primary()
 * call instead, the same "malformed input degrades to something
 * reasonable" precedent as above. The combined result is treated as
 * ATOMIC (compound = 0): `x sub i over y` should read "x_i/y", not the
 * noisier "{x_i}/y" -- a subscripted/superscripted quantity already
 * reads as one visual unit without an extra delimiter. */
static int man_eqn_parse_postfix(struct man_eqn_parser *p, struct man_eqn_val *out)
{
	struct man_eqn_val base, subv, supv;
	int have_sub = 0, have_sup = 0, tries;

	if (!man_eqn_parse_primary(p, &base)) return 0;

	for (tries = 0; tries < 2; tries++) {
		const struct man_eqn_tok *t = man_eqn_peek(p);
		if (!have_sub && man_eqn_is_kw(t, "sub")) {
			man_eqn_advance(p);
			if (!man_eqn_parse_primary(p, &subv)) { man_eqn_val_free(&base); return 0; }
			have_sub = 1;
		} else if (!have_sup && man_eqn_is_kw(t, "sup")) {
			man_eqn_advance(p);
			if (!man_eqn_parse_primary(p, &supv)) {
				man_eqn_val_free(&base);
				if (have_sub) man_eqn_val_free(&subv);
				return 0;
			}
			have_sup = 1;
		} else break;
	}

	if (!have_sub && !have_sup) { *out = base; return 1; }

	{
		struct man_buf b;
		int ok;
		char *piece;
		memset(&b, 0, sizeof b);
		ok = mbuf_appendstr(&b, base.text ? base.text : "");
		if (ok && have_sub) {
			ok = man_eqn_wrap(&subv, '{', '}', &piece);
			if (ok) { ok = mbuf_appendc(&b, '_') && mbuf_appendstr(&b, piece); free(piece); }
		}
		if (ok && have_sup) {
			ok = man_eqn_wrap(&supv, '{', '}', &piece);
			if (ok) { ok = mbuf_appendc(&b, '^') && mbuf_appendstr(&b, piece); free(piece); }
		}
		man_eqn_val_free(&base);
		if (have_sub) man_eqn_val_free(&subv);
		if (have_sup) man_eqn_val_free(&supv);
		if (!ok) { mbuf_free(&b); return 0; }
		out->text = b.data ? b.data : strdup("");
		out->compound = 0;
		return out->text != 0;
	}
}

/* term := postfix ('over' postfix)* -- `over`, like `sub`/`sup`, binds
 * TIGHTLY: to the single immediately-adjacent postfix unit on each
 * side, not to an entire concatenated run. This matters for correctly
 * reading eqn's own canonical quadratic-formula example, `x = { -b +-
 * sqrt{b sup 2 - 4ac} } over {2a}`: `over` must take ONLY the `{ -b +-
 * sqrt{...} }` group as its numerator (a single postfix unit, a `{ }`
 * group) and `{2a}` as its denominator, leaving `x =` outside the
 * fraction entirely -- a looser-binding `over` that grabbed everything
 * concatenated since the start of the expression (as an earlier
 * version of this parser incorrectly did) would wrongly pull `x =`
 * inside the numerator. Left-associative, so `a over b over c` reads
 * as `(a/b)/c` -- each intermediate division is itself compound, so
 * man_eqn_wrap() parenthesizes it when it becomes the next numerator,
 * exactly the disambiguation a human writing plain-text math by hand
 * would add. */
static int man_eqn_parse_over(struct man_eqn_parser *p, struct man_eqn_val *out)
{
	struct man_eqn_val val;
	if (!man_eqn_parse_postfix(p, &val)) return 0;

	for (;;) {
		const struct man_eqn_tok *t = man_eqn_peek(p);
		struct man_eqn_val rhs;
		struct man_buf b;
		char *lp = 0, *rp = 0;
		int ok;

		if (!man_eqn_is_kw(t, "over")) break;
		man_eqn_advance(p);
		if (!man_eqn_parse_postfix(p, &rhs)) { man_eqn_val_free(&val); return 0; }

		ok = man_eqn_wrap(&val, '(', ')', &lp);
		if (ok) ok = man_eqn_wrap(&rhs, '(', ')', &rp);
		memset(&b, 0, sizeof b);
		if (ok) ok = mbuf_appendstr(&b, lp) && mbuf_appendc(&b, '/') && mbuf_appendstr(&b, rp);
		free(lp);
		free(rp);
		man_eqn_val_free(&val);
		man_eqn_val_free(&rhs);
		if (!ok) { mbuf_free(&b); return 0; }

		val.text = b.data ? b.data : strdup("");
		val.compound = 1;
		if (!val.text) return 0;
	}

	*out = val;
	return 1;
}

/* expr := term* (stops at `}` or end of input) -- eqn's own
 * juxtaposition rule: terms written next to each other with no
 * operator between them are simply concatenated, rejoined here with a
 * single space so the linear rendering stays readable ("a + b", not
 * "a+b"). `compound` is set whenever more than one term was read
 * (definitely needs a delimiter if this whole run becomes an over/sub/
 * sup operand later); when EXACTLY one term was read, that term's OWN
 * compound flag is carried through unchanged rather than forced to
 * false -- a lone term can already be compound itself (a `{a+b}` group
 * standing alone as this whole expr, or an `over` division result, for
 * instance), and losing that flag here would drop the delimiter
 * man_eqn_wrap() needs to add around it later (`x sub {2 a}` must still
 * render "x_{2 a}", not the ambiguous "x_2 a"). */
static int man_eqn_parse_expr(struct man_eqn_parser *p, struct man_eqn_val *out)
{
	struct man_buf b;
	size_t count = 0;
	int ok = 1, last_compound = 0;
	memset(&b, 0, sizeof b);
	for (;;) {
		const struct man_eqn_tok *t = man_eqn_peek(p);
		struct man_eqn_val piece;
		if (!t || man_eqn_is_kw(t, "}")) break;
		if (!man_eqn_parse_over(p, &piece)) { ok = 0; break; }
		if (count && !mbuf_appendc(&b, ' ')) { man_eqn_val_free(&piece); ok = 0; break; }
		if (!mbuf_appendstr(&b, piece.text ? piece.text : "")) { man_eqn_val_free(&piece); ok = 0; break; }
		last_compound = piece.compound;
		man_eqn_val_free(&piece);
		count++;
	}
	if (!ok) { mbuf_free(&b); return 0; }
	out->text = b.data ? b.data : strdup("");
	out->compound = count > 1 ? 1 : (count == 1 && last_compound);
	return out->text != 0;
}

/* Renders one already-decoded, already-trimmed eqn source line to its
 * linear-approximation text (malloc'd, caller frees). See this file's
 * own header comment ("EQN") for the grammar this implements and every
 * construct it does NOT. */
static int man_eqn_render_line(const char *s, char **out)
{
	struct man_eqn_toks toks;
	struct man_eqn_parser parser;
	struct man_eqn_val result;
	int ok;

	if (!man_eqn_tokenize(s, &toks)) return 0;
	memset(&parser, 0, sizeof parser);
	parser.toks = &toks;
	ok = man_eqn_parse_expr(&parser, &result);
	man_eqn_toks_free(&toks);
	if (!ok) return 0;
	*out = result.text;
	return 1;
}

/* Parses and renders one already-collected `.EQ`...`.EN` block (`body`
 * -- struct man_macro reused as a plain raw-line list, c->eqn_body's
 * own shape, same convention man_render_table() above documents for
 * c->tbl_body) into c->doc. Unlike a `.TS` table, there is no shared
 * multi-line grammar to assemble first: each collected raw line is
 * register-interpolated/escape-decoded (decode_text(), the same pass
 * every other piece of text in this file goes through, so `\*(xx`/
 * `\n(xx`/named glyphs all work inside an equation too) and then parsed
 * as ONE COMPLETE, INDEPENDENT equation of its own -- see this file's
 * header comment ("EQN") for why a single equation deliberately cannot
 * span multiple physical source lines here, a real, honest
 * simplification of eqn's fully general free-form line-wrapping. A
 * line whose first word is `delim` or `define` (real eqn's own mode-
 * setting directives, covered under "EQN" in the header comment as
 * NOT implemented) is recognised and consumed rather than parsed as
 * math -- otherwise its keyword and argument would render as
 * meaningless literal text, worse than a clean skip. */
static int man_render_eqn(struct man_ctx *c, struct man_macro *body)
{
	size_t li;
	int ok = 1, started = 0;

	for (li = 0; li < body->n; li++) {
		size_t start, len;
		char *rendered;

		if (!ok) break;
		man_tbl_trim_span(body->lines[li], &start, &len); /* generic trim helper, not table-specific despite the name */
		if (len == 0) continue;

		{
			char *decoded_src;
			struct man_buf decoded;
			int is_directive;

			{
				size_t bytes;
				if (!__util_size_add(len, 1, &bytes)) { ok = 0; break; }
				decoded_src = malloc(bytes);
			}
			if (!decoded_src) { ok = 0; break; }
			memcpy(decoded_src, body->lines[li] + start, len);
			decoded_src[len] = 0;

			is_directive =
			    (!strncmp(decoded_src, "delim", 5) && (decoded_src[5] == 0 || decoded_src[5] == ' ' || decoded_src[5] == '\t')) ||
			    (!strncmp(decoded_src, "define", 6) && (decoded_src[6] == 0 || decoded_src[6] == ' ' || decoded_src[6] == '\t'));
			if (is_directive) { free(decoded_src); continue; }

			memset(&decoded, 0, sizeof decoded);
			if (!decode_text(&c->regs, &decoded, decoded_src, len, 0)) { mbuf_free(&decoded); free(decoded_src); ok = 0; break; }
			free(decoded_src);
			ok = man_eqn_render_line(decoded.data ? decoded.data : "", &rendered);
			mbuf_free(&decoded);
			if (!ok) break;
		}

		if (rendered[0] == 0) { free(rendered); continue; }

		if (!started) {
			ok = man_flush_paragraph(c);
			if (ok) { c->extra_indent = 0; c->pending_tag = 0; }
			if (ok) ok = man_block_start(c);
			if (!ok) { free(rendered); break; }
			started = 1;
		}

		{
			size_t vis = man_vislen(rendered, strlen(rendered));
			int indent = c->rs_indent + c->extra_indent;
			int room = c->width - indent - (int)vis;
			if (room > 0) indent += room / 2;
			ok = mbuf_appendn(&c->doc, indent, ' ');
			if (ok) ok = mbuf_appendstr(&c->doc, rendered);
			if (ok) ok = mbuf_appendc(&c->doc, '\n');
		}
		free(rendered);
	}
	if (ok && started) c->had_output = 1;
	return ok;
}

/* Forward declaration: a macro body line is fed back through the same
 * line-processing function top-level source lines go through -- see
 * this file's own header comment ("MACROS") -- so man_invoke_macro()
 * below needs to call it before its own later definition. */
static int man_process_line(struct man_ctx *c, struct man_render *r, char *line);

static int man_invoke_macro(struct man_ctx *c, struct man_render *r,
    struct man_macro *m, const char *macroname, struct man_argv *args)
{
	size_t i;
	int ok = 1;

	if (c->macro_depth >= MAN_MAX_MACRO_DEPTH) {
		__util_diagf("man: macro '%s' nested too deeply (>%d), aborting expansion\n",
		    macroname, MAN_MAX_MACRO_DEPTH);
		return 1; /* loud diagnostic, not a hard failure -- MAN_MAX_RS_DEPTH's own precedent */
	}

	c->macro_depth++;
	for (i = 0; i < m->n; i++) {
		struct man_buf expanded;
		char *lc;
		if (!ok) break;
		memset(&expanded, 0, sizeof expanded);
		ok = man_macro_subst_args(m->lines[i], macroname, args, &expanded);
		if (ok) {
			lc = strdup(expanded.data ? expanded.data : "");
			if (!lc) { ok = 0; }
			else {
				ok = man_process_line(c, r, lc);
				free(lc);
			}
		}
		mbuf_free(&expanded);
	}
	c->macro_depth--;
	return ok;
}

static int man_process_line(struct man_ctx *c, struct man_render *r, char *line)
{
	man_strip_comment(line);

	if (c->def_active) {
		const char *p = line;
		int terminated = 0;
		while (*p == ' ' || *p == '\t') p++;
		if (p[0] == '.') {
			if (c->def_end) {
				char ename[16] = { 0 };
				const char *erest;
				man_split_request(p, ename, sizeof ename, &erest);
				terminated = !strcmp(ename, c->def_end);
			} else {
				terminated = p[1] == '.' && (p[2] == 0 || p[2] == ' ' || p[2] == '\t');
			}
		}
		if (terminated) {
			c->def_active = 0;
			free(c->def_end);
			c->def_end = 0;
			c->def_target = 0;
			return 1;
		}
		if (!c->def_discard && c->def_target && !man_macro_add_line(c->def_target, line)) return 0;
		return 1;
	}

	if (c->cond_active) {
		int opens = man_line_ends_block_open(line, strlen(line));
		int closes = man_line_is_block_close(line);

		if (closes && c->cond_depth == 0) {
			/* Move c->cond_body out to a local copy before replaying:
			 * a NESTED `.if ... \{` among these very lines (this
			 * project's own GREP1_EXCERPT test fixture has exactly
			 * this shape) re-enters this same dispatch during replay
			 * and reuses c->cond_body for ITS OWN collection -- iterating
			 * the shared field directly here would have that nested
			 * collection's man_macro_free_lines() clear the array out
			 * from under this loop mid-replay, truncating it. */
			struct man_macro body = c->cond_body;
			int result = c->cond_result;
			int ok = 1;
			memset(&c->cond_body, 0, sizeof c->cond_body);
			c->cond_active = 0;
			if (result) {
				size_t i;
				for (i = 0; i < body.n; i++) {
					char *lc;
					if (!ok) break;
					lc = strdup(body.lines[i]);
					if (!lc) { ok = 0; break; }
					ok = man_process_line(c, r, lc);
					free(lc);
				}
			}
			man_macro_free_lines(&body);
			return ok;
		}
		if (closes) c->cond_depth--;
		else if (opens) c->cond_depth++;
		if (!man_macro_add_line(&c->cond_body, line)) return 0;
		return 1;
	}

	if (c->tbl_active) {
		/* Same shape as c->def_active's own custom-end-marker check
		 * above -- `.TE` (unlike `.de`'s `..`) is always the literal
		 * terminator, never page-customisable, so there is no
		 * equivalent of c->def_end here. */
		const char *p = line;
		int terminated;
		while (*p == ' ' || *p == '\t') p++;
		terminated = 0;
		if (p[0] == '.') {
			char ename[16] = { 0 };
			const char *erest;
			man_split_request(p, ename, sizeof ename, &erest);
			terminated = !strcmp(ename, "TE");
		}
		if (terminated) {
			struct man_macro tbody = c->tbl_body;
			int ok;
			memset(&c->tbl_body, 0, sizeof c->tbl_body);
			c->tbl_active = 0;
			ok = man_render_table(c, &tbody);
			man_macro_free_lines(&tbody);
			return ok;
		}
		if (!man_macro_add_line(&c->tbl_body, line)) return 0;
		return 1;
	}

	if (c->eqn_active) {
		/* Same shape as c->tbl_active's own collection above -- `.EN`
		 * is likewise always the literal terminator, never page-
		 * customisable. */
		const char *p = line;
		int terminated;
		while (*p == ' ' || *p == '\t') p++;
		terminated = 0;
		if (p[0] == '.') {
			char ename[16] = { 0 };
			const char *erest;
			man_split_request(p, ename, sizeof ename, &erest);
			terminated = !strcmp(ename, "EN");
		}
		if (terminated) {
			struct man_macro ebody = c->eqn_body;
			int ok;
			memset(&c->eqn_body, 0, sizeof c->eqn_body);
			c->eqn_active = 0;
			ok = man_render_eqn(c, &ebody);
			man_macro_free_lines(&ebody);
			return ok;
		}
		if (!man_macro_add_line(&c->eqn_body, line)) return 0;
		return 1;
	}

	if (line[0] != '.') {
		/* Plain text line. */
		if (!c->fill) {
			struct man_buf tmp;
			int ok = 1;
			memset(&tmp, 0, sizeof tmp);
			if (!decode_text(&c->regs, &tmp, line, strlen(line), 0)) { mbuf_free(&tmp); return 0; }
			if (tmp.len == 0) {
				ok = mbuf_appendc(&c->doc, '\n');
			} else {
				if (!c->nf_started) {
					ok = man_block_start(c);
					c->nf_started = 1;
				}
				if (ok) ok = mbuf_appendn(&c->doc, c->rs_indent + c->extra_indent, ' ');
				if (ok) ok = mbuf_append(&c->doc, tmp.data, tmp.len);
				if (ok) ok = mbuf_appendc(&c->doc, '\n');
			}
			mbuf_free(&tmp);
			return ok;
		}
		{
			size_t k = 0;
			while (line[k] == ' ' || line[k] == '\t') k++;
			if (line[k] == 0) return man_flush_paragraph(c);
		}
		if (!man_acc_add_font(c, line, 0)) return 0;
		return man_maybe_consume_tag(c);
	}

	{
		/* Zero-initialized defensively: man_split_request() always
		 * NUL-terminates within bounds, so every byte the code below
		 * actually reads is real, but a static analyzer cannot always
		 * correlate "name[1] is read only once !strcmp(name,\"BI\")
		 * (etc, all exactly 2 bytes) has already succeeded" with
		 * name's true length -- zero-initializing removes the
		 * ambiguity for free rather than arguing with the tool. */
		char name[16] = { 0 };
		const char *rest;
		struct man_argv a;
		int ok = 1;

		man_split_request(line, name, sizeof name, &rest);

		if (!strcmp(name, "de") || !strcmp(name, "de1") ||
		    !strcmp(name, "am") || !strcmp(name, "am1") || !strcmp(name, "ig")) {
			struct man_argv da;
			if (!man_tokenize(rest, &da)) return 0;
			ok = man_begin_macro_def(c, name, &da);
			man_argv_free(&da);
			return ok;
		}

		if (!strcmp(name, "if") || !strcmp(name, "ie") || !strcmp(name, "el")) {
			/* See this file's own header comment ("CONDITIONALS") --
			 * operates on raw `rest` directly, never man_tokenize()'d:
			 * a condition/action can contain quoting and spacing
			 * man_tokenize()'s whitespace/quote splitting would
			 * corrupt (a string-equality operand with an embedded
			 * space, for one). */
			int is_el = !strcmp(name, "el");
			int result;
			size_t rn = strlen(rest);
			size_t pos = man_cond_skip_ws(rest, rn, 0);

			if (is_el) {
				result = c->have_last_ie ? !c->last_ie_result : 0;
				c->have_last_ie = 0;
			} else {
				result = man_eval_condition(&c->regs, rest, rn, &pos);
				if (!strcmp(name, "ie")) { c->last_ie_result = result; c->have_last_ie = 1; }
				pos = man_cond_skip_ws(rest, rn, pos);
			}

			if (man_line_ends_block_open(rest + pos, rn - pos)) {
				c->cond_active = 1;
				c->cond_depth = 0;
				c->cond_result = result;
				man_macro_free_lines(&c->cond_body);
				return 1;
			}

			if (result && pos < rn) {
				char *action = strdup(rest + pos);
				if (!action) return 0;
				ok = man_process_line(c, r, action);
				free(action);
			}
			return ok;
		}

		if (!strcmp(name, "TS")) {
			/* Begins collecting a `.TS`...`.TE` table body verbatim --
			 * see this file's own header comment ("TABLES") and the
			 * c->tbl_active check above. Real troff's only argument
			 * here is `H` (repeat the heading rows across page
			 * breaks); ignored, same as \n(mo's neighbours -- no real
			 * pagination exists here for it to act on. */
			c->tbl_active = 1;
			man_macro_free_lines(&c->tbl_body);
			return 1;
		}

		if (!strcmp(name, "EQ")) {
			/* Begins collecting a `.EQ`...`.EN` equation body verbatim --
			 * see this file's own header comment ("EQN") and the
			 * c->eqn_active check above. Real troff's own optional
			 * arguments here are a cross-reference label and/or a one-
			 * letter display-position override (L/I/C/R); both ignored
			 * (this file always centers, see "EQN"), same "recognised
			 * argument, no real per-page effect" precedent `.TS`'s own
			 * `H` argument sets above. */
			c->eqn_active = 1;
			man_macro_free_lines(&c->eqn_body);
			return 1;
		}

		if (!man_tokenize(rest, &a)) return 0;

		if (!strcmp(name, "TH")) {
			man_th(c, &a, &r->title, &r->section, &r->date, &r->source, &r->manual);
		} else if (!strcmp(name, "SH") || !strcmp(name, "SS")) {
			struct man_buf heading;
			size_t i;
			memset(&heading, 0, sizeof heading);
			if (!man_flush_paragraph(c)) { man_argv_free(&a); return 0; }
			for (i = 0; i < a.n; i++) {
				if (!ok) break;
				if (i && !mbuf_appendc(&heading, ' ')) ok = 0;
				if (ok && !decode_text(&c->regs, &heading, a.v[i], strlen(a.v[i]), 0)) ok = 0;
			}
			if (ok) {
				int is_sh = !strcmp(name, "SH");
				ok = man_block_start(c);
				if (ok) ok = mbuf_appendn(&c->doc, is_sh ? 0 : MAN_SS_COL, ' ');
				if (ok) ok = mbuf_appendc(&c->doc, MAN_M_BOLD);
				if (ok) ok = mbuf_append(&c->doc, heading.data, heading.len);
				if (ok) ok = mbuf_appendc(&c->doc, MAN_M_ROMAN);
				if (ok) ok = mbuf_appendc(&c->doc, '\n');
				/* A heading's own immediately-following paragraph sits
				 * flush against it, no blank line -- real troff's an.
				 * tmac SH/SS macros put the blank line BEFORE a
				 * heading (man_block_start() above), never after;
				 * confirmed against a real system man page's actual
				 * rendered output, not assumed. Reuses the same
				 * suppress-next-leading-blank flag .TP/.IP tags and
				 * .br already rely on. */
				if (ok) c->just_emitted_tag = 1;
			}
			mbuf_free(&heading);
			if (!strcmp(name, "SH")) {
				c->rs_depth = 0;
				c->rs_indent = MAN_BASE_INDENT;
			}
			c->extra_indent = 0;
			c->pending_tag = 0;
		} else if (!strcmp(name, "PP") || !strcmp(name, "LP")) {
			ok = man_flush_paragraph(c);
			c->extra_indent = 0;
			c->pending_tag = 0;
		} else if (!strcmp(name, "TP")) {
			long w = MAN_BASE_INDENT;
			if (a.n > 0) { char *end; long v = strtol(a.v[0], &end, 10); if (*end == 0 && v > 0) w = v; }
			ok = man_flush_paragraph(c);
			c->extra_indent = 0;
			c->pending_tag = 1;
			c->tag_width = (int)w;
		} else if (!strcmp(name, "IP")) {
			long w = MAN_BASE_INDENT;
			size_t tagn = a.n;
			if (tagn > 0) {
				char *end;
				long v = strtol(a.v[tagn - 1], &end, 10);
				if (*end == 0 && v > 0 && tagn > 1) { w = v; tagn--; }
			}
			ok = man_flush_paragraph(c);
			if (ok) {
				c->extra_indent = 0;
				c->pending_tag = 0;
				{
					size_t i;
					for (i = 0; i < tagn; i++) {
						if (!ok) break;
						ok = man_acc_add_font(c, a.v[i], 0);
					}
				}
				if (ok) ok = man_flush_as_tag(c, (int)w);
			}
			c->extra_indent = (int)w;
		} else if (!strcmp(name, "RS")) {
			long v = MAN_BASE_INDENT;
			if (a.n > 0) { char *end; long vv = strtol(a.v[0], &end, 10); if (*end == 0 && vv > 0) v = vv; }
			ok = man_flush_paragraph(c);
			c->extra_indent = 0;
			c->pending_tag = 0;
			if (ok && c->rs_depth < MAN_MAX_RS_DEPTH) {
				c->rs_stack[c->rs_depth++] = c->rs_indent;
				c->rs_indent += (int)v;
			}
		} else if (!strcmp(name, "RE")) {
			int level = 0;
			if (a.n > 0) { char *end; long v = strtol(a.v[0], &end, 10); if (*end == 0 && v > 0) level = (int)v; }
			ok = man_flush_paragraph(c);
			c->extra_indent = 0;
			c->pending_tag = 0;
			if (ok) {
				if (level > 0) {
					while (c->rs_depth >= level && c->rs_depth > 0) c->rs_indent = c->rs_stack[--c->rs_depth];
				} else if (c->rs_depth > 0) {
					c->rs_indent = c->rs_stack[--c->rs_depth];
				}
			}
		} else if (!strcmp(name, "nf")) {
			ok = man_flush_paragraph(c);
			c->fill = 0;
			c->nf_started = 0;
		} else if (!strcmp(name, "fi")) {
			c->fill = 1;
			c->nf_started = 0;
		} else if (!strcmp(name, "ad")) {
			/* `.ad [c|l|r|b|n]` -- see "ADJUSTMENT" in this file's
			 * header comment. Flushed first, same as .nf/.fi above:
			 * c->acc buffers a whole paragraph before man_wrap_emit()
			 * ever runs, so a mode change mid-paragraph could otherwise
			 * only ever apply uniformly to that whole buffered block
			 * anyway (whichever mode is active when it's finally
			 * flushed) -- flushing first makes that boundary explicit
			 * instead of silently backdating the new mode onto text
			 * already accumulated under the old one. An unrecognised
			 * argument is a no-op, the same "malformed value leaves the
			 * setting untouched" precedent `.nr` already documents. */
			ok = man_flush_paragraph(c);
			if (ok && a.n == 0) c->adjust = MAN_ADJ_BOTH;
			else if (ok && a.n > 0 && a.v[0][0] && !a.v[0][1]) {
				switch (a.v[0][0]) {
				case 'l': c->adjust = MAN_ADJ_LEFT; break;
				case 'r': c->adjust = MAN_ADJ_RIGHT; break;
				case 'c': c->adjust = MAN_ADJ_CENTER; break;
				case 'b': case 'n': c->adjust = MAN_ADJ_BOTH; break;
				default: break;
				}
			}
		} else if (!strcmp(name, "na")) {
			ok = man_flush_paragraph(c);
			c->adjust = MAN_ADJ_LEFT;
		} else if (!strcmp(name, "hy")) {
			/* `.hy [N]` -- see "HYPHENATION" in this file's header
			 * comment. Real troff's optional numeric argument selects
			 * finer-grained hyphenation-mode BITS (e.g. suppress
			 * hyphenating the last word on a line, or within two
			 * characters of a word's own start/end); this file has
			 * exactly one on/off mode, so any argument (or none) just
			 * turns hyphenation ON, the same "recognised, simplified,
			 * disclosed" precedent `.ad`'s own bare-argument case sets
			 * above. Flushed first, same reasoning as `.ad`/`.na`: a
			 * mode change mid-paragraph must not backdate onto text
			 * already accumulated under the old mode. */
			ok = man_flush_paragraph(c);
			c->hyphenate = 1;
		} else if (!strcmp(name, "nh")) {
			ok = man_flush_paragraph(c);
			c->hyphenate = 0;
		} else if (!strcmp(name, "br")) {
			/* .br: force a line break WITHOUT starting a new block --
			 * no blank line, no indent/tag-state reset, unlike .PP.
			 * Added beyond the task's originally-named macro set: a
			 * real-world necessity, not scope creep -- both this
			 * project's own man/man1/ fixtures' multi-form
			 * SYNOPSIS sections and the real GNU grep.1 excerpt this
			 * file is tested against use `.br` between alternative
			 * invocation forms, and without it those forms would
			 * wrongly run together into one flowed line. */
			if (c->acc.len > 0) {
				int indent = c->rs_indent + c->extra_indent;
				ok = man_wrap_emit(c, c->acc.data, indent, c->pending_prefix);
				free(c->pending_prefix);
				c->pending_prefix = 0;
				mbuf_reset(&c->acc);
				c->had_output = 1;
				/* Reuses the exact "don't insert a blank line before
				 * the next flush" suppression man_flush_as_tag() uses
				 * for a tag's own body continuation -- semantically
				 * the same situation: whatever comes next is this
				 * line's continuation, not a new block, so the next
				 * man_flush_paragraph() (e.g. the one .SH triggers
				 * when this section ends) must not treat it as one. */
				c->just_emitted_tag = 1;
			}
		} else if (!strcmp(name, "B") || !strcmp(name, "I")) {
			int font = !strcmp(name, "B") ? MAN_M_BOLD : MAN_M_ITAL;
			size_t i;
			if (!c->fill) {
				struct man_buf tmp;
				memset(&tmp, 0, sizeof tmp);
				ok = mbuf_appendc(&tmp, (char)font);
				for (i = 0; i < a.n; i++) {
					if (!ok) break;
					if (i && !mbuf_appendc(&tmp, ' ')) { ok = 0; break; }
					ok = decode_text(&c->regs, &tmp, a.v[i], strlen(a.v[i]), 0);
				}
				if (ok) ok = mbuf_appendc(&tmp, MAN_M_ROMAN);
				if (ok && tmp.len > 0) {
					if (!c->nf_started) { ok = man_block_start(c); c->nf_started = 1; }
					if (ok) ok = mbuf_appendn(&c->doc, c->rs_indent + c->extra_indent, ' ');
					if (ok) ok = mbuf_append(&c->doc, tmp.data, tmp.len);
					if (ok) ok = mbuf_appendc(&c->doc, '\n');
				}
				mbuf_free(&tmp);
			} else {
				for (i = 0; i < a.n; i++) {
					if (!ok) break;
					ok = man_acc_add_font(c, a.v[i], font);
				}
				if (ok) ok = man_maybe_consume_tag(c);
			}
		} else if (!strcmp(name, "BI") || !strcmp(name, "IB") || !strcmp(name, "BR") ||
		           !strcmp(name, "RB") || !strcmp(name, "IR") || !strcmp(name, "RI")) {
			/* Alternating-font macros: real troff alternates font1/
			 * font2/font1/... per space-separated WORD across the
			 * whole argument list, not per raw argv[] token -- a
			 * quoted multi-word argument like .RB "word1 word2"
			 * "word3" still alternates at the word1/word2 boundary,
			 * continuing the same cycle into the next argument's own
			 * words. Args supply their own spacing in real troff (no
			 * separator is added AT AN ARGUMENT BOUNDARY); a space
			 * WITHIN one argument is real source text and is copied
			 * through verbatim between that argument's own words, so
			 * `.RB [ \-x ]` still renders tight as "[-x]" (three
			 * single-word args, nothing between them) while
			 * "word1 word2" still keeps its own internal space. */
			int f1 = man_font_for_letter(name[0]);
			int f2 = man_font_for_letter(name[1]);
			size_t i;
			int windex = 0;
			int had_c = 0;
			if (c->acc.len > 0 && !c->suppress_join) { if (!mbuf_appendc(&c->acc, ' ')) ok = 0; }
			for (i = 0; i < a.n; i++) {
				const char *s = a.v[i];
				size_t si = 0, sn = strlen(s);
				if (!ok) break;
				while (si < sn) {
					size_t wstart;
					if (!ok) break;
					while (si < sn && (s[si] == ' ' || s[si] == '\t')) {
						if (!mbuf_appendc(&c->acc, s[si])) { ok = 0; break; }
						si++;
					}
					if (!ok || si >= sn) break;
					wstart = si;
					while (si < sn && s[si] != ' ' && s[si] != '\t') si++;
					{
						int font = (windex % 2 == 0) ? f1 : f2;
						had_c = 0;
						if (!mbuf_appendc(&c->acc, (char)font)) { ok = 0; break; }
						if (!decode_text(&c->regs, &c->acc, s + wstart, si - wstart, &had_c)) { ok = 0; break; }
						if (!mbuf_appendc(&c->acc, MAN_M_ROMAN)) { ok = 0; break; }
						windex++;
					}
				}
			}
			if (ok) c->suppress_join = had_c;
			if (ok) ok = man_maybe_consume_tag(c);
		} else if (!strcmp(name, "ds")) {
			ok = man_do_ds(c, &a);
		} else if (!strcmp(name, "nr")) {
			ok = man_do_nr(c, &a);
		} else if (!strcmp(name, "rn")) {
			ok = man_do_rn(c, &a);
		} else if (!strcmp(name, "rm")) {
			ok = man_do_rm(c, &a);
		} else if (!strcmp(name, "als")) {
			ok = man_do_als(c, &a);
		} else {
			struct man_macro *m = man_mac_find(&c->macros, name); // NOLINT(misc-confusable-identifiers) -- flags "m" against the *string literal* "rn" used in an earlier strcmp() in this same function, not against any other identifier in scope
			/* Checked only here, after every built-in request name
			 * above -- a page can never shadow a built-in by defining
			 * a same-named macro. Anything still unmatched (.sp, .ce,
			 * .in, .ll, ...): unimplemented, silently skipped -- see
			 * this file's own "UNKNOWN-MACRO DEGRADATION" header
			 * comment. (.EQ/.TS are handled earlier, before this
			 * dispatch even runs -- see c->eqn_active/c->tbl_active
			 * above; .ad/.na/.hy/.nh are handled above too.) */
			if (m) ok = man_invoke_macro(c, r, m, name, &a);
		}
		man_argv_free(&a);
		return ok;
	}
}

/* Builds the .TH header line -- see this file's own header comment
 * ("the well-known three-field header/footer layout") -- into `out`
 * (a fresh buffer, NOT c->doc: c->doc already holds the whole
 * formatted body by the time this runs, and the header line belongs
 * *before* that, so man_format() below prepends this rather than
 * appending it). A page with no .TH (unusual but not fatal) leaves
 * `out` empty. */
static int man_emit_header(struct man_buf *out, int width, struct man_render *r)
{
	struct man_buf left;
	int ok;

	if (r->title.len == 0) return 1;

	memset(&left, 0, sizeof left);
	ok = mbuf_appendstr(&left, r->title.data);
	if (ok && r->section.len) { ok = mbuf_appendc(&left, '('); if (ok) ok = mbuf_appendstr(&left, r->section.data); if (ok) ok = mbuf_appendc(&left, ')'); }
	if (ok) {
		const char *ctr;
		if (r->manual.len) ctr = r->manual.data;
		else if (r->source.len) ctr = r->source.data;
		else ctr = "";
		ok = man_center3(out, width, left.data, ctr, left.data);
	}
	mbuf_free(&left);
	return ok;
}

static int man_emit_footer(struct man_ctx *c, struct man_render *r)
{
	struct man_buf left;
	int ok;

	if (r->title.len == 0) return 1;

	memset(&left, 0, sizeof left);
	ok = mbuf_appendstr(&left, r->title.data);
	if (ok && r->section.len) { ok = mbuf_appendc(&left, '('); if (ok) ok = mbuf_appendstr(&left, r->section.data); if (ok) ok = mbuf_appendc(&left, ')'); }
	if (ok) ok = mbuf_appendc(&c->doc, '\n');
	if (ok) {
		const char *l = r->date.len ? r->date.data : "";
		const char *ctr = r->source.len ? r->source.data : "";
		ok = man_center3(&c->doc, c->width, l, ctr, left.data);
	}
	mbuf_free(&left);
	return ok;
}

/* ==== top-level: format one already-read page's text into c->doc ======= */

static int man_format(const char *text, size_t len, int width, struct man_buf *out)
{
	struct man_ctx c;
	struct man_render r;
	char *copy;
	char *line;
	int ok = 1;

	if (!man_ctx_init(&c, width)) return 0;
	memset(&r, 0, sizeof r);

	{
		size_t bytes;
		if (!__util_size_add(len, 1, &bytes)) { man_ctx_free(&c); return 0; }
		copy = malloc(bytes);
	}
	if (!copy) { man_ctx_free(&c); return 0; }
	for (size_t i = 0; i < len; i++) copy[i] = text[i];
	copy[len] = 0;

	line = copy;
	while (line) {
		char *nl;
		if (!ok) break;
		nl = strchr(line, '\n');
		if (nl) *nl = 0;
		ok = man_process_line(&c, &r, line);
		line = nl ? nl + 1 : 0;
	}
	if (ok) ok = man_flush_paragraph(&c);

	if (ok) {
		struct man_buf full;
		/* c.doc.len is only ever nonzero once c.doc.data has been
		 * allocated (every writer is mbuf_append() or a sibling that
		 * grows data before advancing len), but pairing the fallback
		 * "" literal with the real length regardless would read past
		 * that literal's single byte if the two ever came apart --
		 * tie doc_len to the same null check instead of trusting the
		 * invariant to hold at this one distant call site. */
		const char *doc_data = c.doc.data;
		size_t doc_len = doc_data ? c.doc.len : 0;
		memset(&full, 0, sizeof full);
		ok = man_emit_header(&full, width, &r) &&
		     mbuf_append(&full, doc_data ? doc_data : "", doc_len);
		if (ok) {
			mbuf_free(&c.doc);
			c.doc = full;
			c.had_output = 1;
			full.data = 0;
		} else {
			mbuf_free(&full);
		}
	}
	if (ok) ok = man_emit_footer(&c, &r);

	if (ok) { out->data = c.doc.data; out->len = c.doc.len; out->cap = c.doc.cap; c.doc.data = 0; }

	free(copy);
	mbuf_free(&r.title); mbuf_free(&r.section); mbuf_free(&r.date);
	mbuf_free(&r.source); mbuf_free(&r.manual);
	man_ctx_free(&c);
	return ok;
}

/* ==== terminal geometry ================================================ */

static int man_env_positive(const char *name, int fallback)
{
	const char *v = getenv(name);
	char *end;
	long n;
	if (!v || !*v) return fallback;
	n = strtol(v, &end, 10);
	if (*end || end == v || n <= 0 || n > 100000) return fallback;
	return (int)n;
}

static int man_term_width(void)
{
	struct winsize ws;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) return ws.ws_col;
	return man_env_positive("COLUMNS", 80);
}

static int man_term_height(void)
{
	struct winsize ws;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0) return ws.ws_row;
	return man_env_positive("LINES", 24);
}

/* ==== rendering: marker bytes -> real terminal bytes ==================== */

enum man_render_mode { MAN_RENDER_ANSI, MAN_RENDER_OVERSTRIKE };

static int man_render_write(FILE *out, const char *styled, size_t len, enum man_render_mode mode)
{
	size_t i;
	int font = 0; /* 0 = roman, MAN_M_BOLD, MAN_M_ITAL */

	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)styled[i];

		if (c == (unsigned char)MAN_M_BOLD || c == (unsigned char)MAN_M_ITAL ||
		    c == (unsigned char)MAN_M_ROMAN) {
			if (mode == MAN_RENDER_ANSI) {
				if (c == (unsigned char)MAN_M_BOLD) { if (fputs("\033[1m", out) < 0) return -1; }
				else if (c == (unsigned char)MAN_M_ITAL) { if (fputs("\033[4m", out) < 0) return -1; }
				else { if (fputs("\033[0m", out) < 0) return -1; }
			}
			font = (c == (unsigned char)MAN_M_ROMAN) ? 0 : (int)c;
			continue;
		}

		if (mode == MAN_RENDER_OVERSTRIKE && font && c != ' ' && c != '\n') {
			int uc = (font == MAN_M_BOLD) ? c : '_';
			if (fputc(uc, out) == EOF) return -1;
			if (fputc('\b', out) == EOF) return -1;
		}
		if (fputc(c, out) == EOF) return -1;
	}
	if (mode == MAN_RENDER_ANSI) { if (fputs("\033[0m", out) < 0) return -1; }
	return 0;
}

/* ==== built-in "--More--" pager ========================================= */

static int man_builtin_pager(const char *styled, size_t len, int height)
{
	const char *p = styled, *end = styled + len;
	int rows = 0;
	int page_rows = height > 2 ? height - 1 : 1;

	while (p < end) {
		const char *nl = memchr(p, '\n', (size_t)(end - p));
		size_t linelen = nl ? (size_t)(nl - p) : (size_t)(end - p);

		if (man_render_write(stdout, p, linelen, MAN_RENDER_ANSI) < 0) return -1;
		if (fputc('\n', stdout) == EOF) return -1;
		rows++;
		p = nl ? nl + 1 : end;

		if (rows >= page_rows && p < end) {
			char resp[64];
			if (fflush(stdout) < 0) return -1;
			fputs("\033[1m--More--\033[0m", stderr);
			(void)fflush(stderr);
			if (!fgets(resp, sizeof resp, stdin)) { fputc('\n', stderr); break; }
			fputc('\r', stderr);
			if (resp[0] == 'q' || resp[0] == 'Q') break;
			rows = 0;
		}
	}
	return 0;
}

/* ==== external $PAGER via a real temp file ============================= */

static const char *man_tmpdir(void)
{
	const char *d = getenv("TMPDIR");
	if (!d || !*d) d = getenv("TMP");
	if (!d || !*d) d = getenv("TEMP");
	if (!d || !*d) d = ".";
	return d;
}

static int man_run_external_pager(const char *pager, const char *styled, size_t len)
{
	const char *dir = man_tmpdir();
	char *tmpl;
	size_t dn = strlen(dir);
	int fd;
	FILE *f;
	int rc = -1;
	char *argv[64];
	int argc = 0;
	char *pcopy, *tok, *save = 0;
	char *resolved;
	int pid, status;

	{
		size_t tmplbytes;
		if (!__util_size_add(dn, sizeof "/ntlibc-manXXXXXX", &tmplbytes)) return -1;
		tmpl = malloc(tmplbytes);
		if (!tmpl) return -1;
		snprintf(tmpl, tmplbytes, "%s/ntlibc-manXXXXXX", dir);
	}
	fd = mkstemp(tmpl);
	if (fd < 0) { free(tmpl); return -1; }
	f = fdopen(fd, "wb");
	if (!f) { (void)close(fd); (void)unlink(tmpl); free(tmpl); return -1; }
	if (man_render_write(f, styled, len, MAN_RENDER_OVERSTRIKE) < 0) { (void)fclose(f); (void)unlink(tmpl); free(tmpl); return -1; }
	if (fclose(f) != 0) { (void)unlink(tmpl); free(tmpl); return -1; }

	pcopy = strdup(pager);
	if (!pcopy) { (void)unlink(tmpl); free(tmpl); return -1; }
	/* Split $PAGER on whitespace only -- no shell-quoting support, a
	 * deliberate, documented limit (see this file's own header
	 * comment). */
	for (tok = strtok_r(pcopy, " \t", &save); tok && argc < 62; tok = strtok_r(0, " \t", &save))
		argv[argc++] = tok;
	if (argc == 0) { free(pcopy); (void)unlink(tmpl); free(tmpl); return -1; }
	argv[argc++] = tmpl;
	argv[argc] = 0;

	resolved = __find_program(argv[0], 1);
	if (resolved) {
		pid = __spawn(resolved, argv, environ);
		free(resolved);
		if (pid >= 0 && waitpid(pid, &status, 0) >= 0) rc = 0;
	}

	free(pcopy);
	(void)unlink(tmpl);
	free(tmpl);
	return rc;
}

/* Shows one already-formatted page, choosing direct/external-pager/
 * built-in-pager per this file's own header comment ("PAGING"). */
static void man_display(struct man_buf *formatted)
{
	int tty = isatty(STDOUT_FILENO);
	const char *pager = tty ? getenv("PAGER") : 0;

	if (!tty) {
		(void)man_render_write(stdout, formatted->data ? formatted->data : "", formatted->len, MAN_RENDER_OVERSTRIKE);
		return;
	}
	if (pager && *pager) {
		if (man_run_external_pager(pager, formatted->data ? formatted->data : "", formatted->len) == 0) return;
		/* $PAGER failed to run at all: fall back to the built-in one
		 * rather than losing the page entirely. */
	}
	(void)man_builtin_pager(formatted->data ? formatted->data : "", formatted->len, man_term_height());
}

/* ==== finding a page on MANPATH ========================================= */

#define MAN_DEFAULT_MANPATH "/usr/share/man:/usr/local/share/man"
#define MAN_DEFAULT_SECTIONS "1:2:3:4:5:6:7:8:9"

static int man_looks_like_section(const char *s)
{
	if (!isdigit((unsigned char)s[0])) return 0;
	for (s++; *s; s++) if (!isalnum((unsigned char)*s)) return 0;
	return 1;
}

/* Splits a colon-separated string into a NULL-terminated, malloc'd
 * array of malloc'd component strings. */
static char **man_split_colon(const char *s)
{
	struct man_argv a;
	size_t i = 0, n = strlen(s);
	memset(&a, 0, sizeof a);
	while (i <= n) {
		size_t start = i;
		while (i < n && s[i] != ':') i++;
		if (i > start) { if (!man_argv_push(&a, s + start, i - start)) { man_argv_free(&a); return 0; } }
		if (i >= n) break;
		i++;
	}
	if (!man_argv_push(&a, "", 0)) { man_argv_free(&a); return 0; } /* NULL terminator slot */
	free(a.v[a.n - 1]);
	a.v[a.n - 1] = 0;
	return a.v;
}

static void man_free_strv(char **v)
{
	size_t i;
	if (!v) return;
	for (i = 0; v[i]; i++) free(v[i]);
	free(v);
}

/* Looks for <dir>/man<section>/<name>.<section> under every directory
 * in `manpath`, preferring an uncompressed page but falling back to
 * its ".gz" sibling (man_read_page() below transparently decompresses
 * it, Tier 4 -- see this file's own header comment, "GZIP-COMPRESSED
 * (.gz) PAGES"). Returns a malloc'd path naming whichever one exists,
 * or NULL if neither does. */
withtok(heap_allocated)
static char *man_find_one(char **manpath, const char *section, const char *name)
{
	size_t i;
	for (i = 0; manpath[i]; i++) {
		char path[4096];
		int n = snprintf(path, sizeof path, "%s/man%s/%s.%s", manpath[i], section, name, section);
		struct stat st;
		if (n < 0 || (size_t)n >= sizeof path) continue;
		if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) return strdup(path);
		{
			char gzpath[4096 + 3];
			int gn = snprintf(gzpath, sizeof gzpath, "%s.gz", path);
			if (gn > 0 && (size_t)gn < sizeof gzpath && stat(gzpath, &st) == 0 && S_ISREG(st.st_mode))
				return strdup(gzpath);
		}
	}
	return 0;
}

withtok(heap_allocated)
static char *man_find_page(char **manpath, char **sections, const char *name, char **out_section)
{
	size_t i;

	for (i = 0; sections[i]; i++) {
		char *p = man_find_one(manpath, sections[i], name);
		if (p) { *out_section = sections[i]; return p; }
	}
	return 0;
}

/* Reads a whole file into a malloc'd buffer (bounded, see
 * MAN_MAX_PAGE_SIZE). Returns 1/0; out and outlen are both valid on
 * success. */
static int man_read_file(const char *path, char **out, size_t *outlen)
{
	FILE *f = fopen(path, "rb");
	struct man_buf b;
	char chunk[65536];
	size_t r;

	if (!f) return 0;
	memset(&b, 0, sizeof b);
	while ((r = fread(chunk, 1, sizeof chunk, f)) > 0) {
		if (b.len + r > MAN_MAX_PAGE_SIZE) { // NOLINT(bugprone-implicit-widening-of-multiplication-result) -- MAN_MAX_PAGE_SIZE is a compile-time constant, 16777216, far inside int range before the widen to size_t
			__util_diagf("man: %s: page too large, truncating at %d bytes\n", path, MAN_MAX_PAGE_SIZE);
			break;
		}
		if (!mbuf_append(&b, chunk, r)) {
			/* fclose(f) is cleanup for the mbuf_append() failure just
			 * diagnosed (errno == ENOMEM on the realloc paths); if it
			 * fails too, its own errno must not overwrite that reason. */
			int saved_errno = errno;
			mbuf_free(&b);
			(void)fclose(f);
			errno = saved_errno;
			return 0;
		}
	}
	(void)fclose(f);
	*out = b.data ? b.data : strdup("");
	*outlen = b.len;
	return *out != 0;
}

/* True iff `path` itself ends in ".gz" (case-sensitive, matching real
 * gzip(1)'s own default suffix -- the only one this project's own
 * man_find_one() ever appends). */
static int man_path_has_gz_suffix(const char *path)
{
	size_t n = strlen(path);
	return n >= 3 && !strcmp(path + n - 3, ".gz");
}

/* man_read_file() plus transparent gzip decompression (Tier 4 -- see
 * this file's own header comment, "GZIP-COMPRESSED (.gz) PAGES"):
 * decompression is attempted whenever `path` itself ends in ".gz" OR
 * (independent of the name) the bytes just read start with gzip's own
 * magic number, so a page compressed under a non-".gz" name is still
 * caught. Unlike man_read_file() (which leaves diagnosing a failure to
 * its own caller, since a bare "cannot read" needs strerror(errno)
 * for a real reason), this function prints its own diagnostic on
 * EITHER failure and simply returns 0 -- a corrupt/truncated gzip
 * stream has no meaningful errno of its own to report, so folding
 * both outcomes into one "diagnose here, caller just checks the
 * return" contract avoids the caller needing to know which kind of
 * failure it was. */
static int man_read_page(const char *path, char **out, size_t *outlen)
{
	char *raw;
	size_t rawlen;

	if (!man_read_file(path, &raw, &rawlen)) {
		__util_diagf("man: %s: %s\n", path, strerror(errno));
		return 0;
	}

	if (man_path_has_gz_suffix(path) || man_looks_gzipped(raw, rawlen)) {
		char *dec;
		size_t declen;
		const char *err = 0;
		int ok = man_gunzip(raw, rawlen, &dec, &declen, &err);
		free(raw);
		if (!ok) {
			__util_diagf("man: %s: gzip: %s\n", path, err ? err : "corrupt data");
			return 0;
		}
		*out = dec;
		*outlen = declen;
		return 1;
	}

	*out = raw;
	*outlen = rawlen;
	return 1;
}

/* ==== -k: apropos-style NAME-line scan (see this file's own header ====
 * comment for why this is a real, honest degrade rather than a real
 * whatis database). */

/* A NAME line reads "<name>[, <name>...] \- <description>" (troff
 * source) or, once decode_text() has expanded its escapes, "<name> -
 * <description>" -- so the first " - " (space, hyphen, space) in the
 * decoded text is the separator between the redundant name repeat and
 * the actual description. Points *out and *out_len at the description; on
 * a malformed or nonstandard NAME line with no such separator, leaves
 * them pointing at the whole decoded line unchanged -- printing the
 * raw line is still more useful than reporting no description at all. */
static void man_apropos_split_description(
	const char *text, size_t len, const char **out, size_t *out_len)
{
	size_t i;

	for (i = 1; i + 1 < len; i++) {
		if (text[i] == '-' && text[i - 1] == ' ' && text[i + 1] == ' ') {
			*out = text + i + 2;
			*out_len = len - (i + 2);
			return;
		}
	}
	*out = text;
	*out_len = len;
}

/* Finds `.SH NAME`'s following line inside `text` (one whole, raw page
 * buffer), decodes its troff escapes via this file's own decode_text()
 * -- the same decoder the real formatting path uses, so apropos output
 * never re-implements a second, parallel escape decoder -- and strips
 * the leading "<name> - " repeat down to just the description. Appends
 * the result to `out` (left empty, meaning "no match", if the page has
 * no NAME section at all). */
static void man_apropos_name_description(const char *text, size_t tlen, struct man_buf *out)
{
	const char *end = text + tlen;
	const char *p = text;
	const char *namehit = 0;
	const char *line, *lineend;
	struct man_buf decoded;
	struct man_regtab no_regs;
	const char *desc;
	size_t desclen, i;

	memset(&no_regs, 0, sizeof no_regs);

	while (p < end) {
		const char *nl = memchr(p, '\n', (size_t)(end - p));
		size_t linelen = nl ? (size_t)(nl - p) : (size_t)(end - p);
		if (linelen == 8 && !strncmp(p, ".SH NAME", 8)) { namehit = p; break; }
		p = nl ? nl + 1 : end;
	}
	if (!namehit) return; /* no NAME section: not a match, not an error */

	line = memchr(namehit, '\n', (size_t)(end - namehit));
	line = line ? line + 1 : end;
	lineend = memchr(line, '\n', (size_t)(end - line));
	if (!lineend) lineend = end;

	memset(&decoded, 0, sizeof decoded);
	if (!decode_text(&no_regs, &decoded, line, (size_t)(lineend - line), 0)) { mbuf_free(&decoded); return; }

	man_apropos_split_description(decoded.data ? decoded.data : "", decoded.len, &desc, &desclen);

	/* decode_text() can still emit its own \fB/\fI font-change marker
	 * bytes into `decoded` (it only strips markers already present in
	 * its *input*); apropos output goes straight to printf(), with no
	 * renderer downstream to turn those markers into real terminal
	 * bytes, so drop them here rather than let them show up as raw
	 * control characters. */
	for (i = 0; i < desclen; i++) {
		char c = desc[i];
		if (c == MAN_M_BOLD || c == MAN_M_ITAL || c == MAN_M_ROMAN) continue;
		if (!mbuf_appendc(out, c)) break;
	}
	mbuf_free(&decoded);
}

static int man_apropos(char **manpath, char **keywords, size_t nkeywords)
{
	size_t mi;
	int any = 0;

	for (mi = 0; manpath[mi]; mi++) {
		char secdir[4096];
		int sec;
		for (sec = 1; sec <= 9; sec++) {
			DIR *dp;
			struct dirent *de;
			int n = snprintf(secdir, sizeof secdir, "%s/man%d", manpath[mi], sec);
			if (n < 0 || (size_t)n >= sizeof secdir) continue;
			dp = opendir(secdir);
			if (!dp) continue;
			while ((de = readdir(dp)) != 0) {
				char path[4096 + 256];
				char *text; size_t tlen;
				size_t nl = strlen(de->d_name);
				size_t k;
				struct man_buf desc;
				if (nl < 3 || de->d_name[nl - 2] != '.') continue; /* need "<base>.<digit>" */
				n = snprintf(path, sizeof path, "%s/%s", secdir, de->d_name);
				if (n < 0 || (size_t)n >= sizeof path) continue;
				if (!man_read_file(path, &text, &tlen)) continue;

				memset(&desc, 0, sizeof desc);
				man_apropos_name_description(text, tlen, &desc);
				free(text);

				for (k = 0; k < nkeywords; k++) {
					size_t x, klen = strlen(keywords[k]);
					int hit = 0;
					for (x = 0; klen > 0 && x + klen <= desc.len; x++) {
						if (strncasecmp(desc.data + x, keywords[k], klen) == 0) { hit = 1; break; }
					}
					if (hit) {
						char base[256];
						size_t bn = nl - 2;
						size_t bi;
						if (bn >= sizeof base) bn = sizeof base - 1;
						for (bi = 0; bi < bn; bi++) base[bi] = de->d_name[bi];
						base[bn] = 0;
						printf("%s(%d) - %.*s\n", base, sec, (int)desc.len, desc.data ? desc.data : "");
						any = 1;
					}
				}
				mbuf_free(&desc);
			}
			(void)closedir(dp);
		}
	}
	return any;
}

/* ==== entry point ======================================================= */

int __util_man_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	int i;
	int opt_k = 0;
	int width;
	char **manpath = 0;
	char **sections = 0;
	const char *forced_section = 0;
	int had_error = 0;
	int shown_any = 0;
	struct man_argv names;
	size_t ni;

	memset(&names, 0, sizeof names);

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--")) { i++; break; }
		if (!strcmp(argv[i], "-k")) { opt_k = 1; continue; }
		if (argv[i][0] == '-' && argv[i][1] != 0) {
			__util_diagf("man: invalid option -- '%s'\n", argv[i]);
			return 1;
		}
		break;
	}

	if (!opt_k && i < argc && (argc - i) >= 2 && man_looks_like_section(argv[i]))
		forced_section = argv[i++];

	for (; i < argc; i++)
		if (!man_argv_push(&names, argv[i], strlen(argv[i]))) { man_argv_free(&names); return 1; }

	if (names.n == 0) {
		__util_diagf("man: what manual page do you want?\n");
		man_argv_free(&names);
		return 1;
	}

	{
		const char *mp = getenv("MANPATH");
		manpath = man_split_colon(mp && *mp ? mp : MAN_DEFAULT_MANPATH);
	}
	{
		const char *ms = getenv("MANSECT");
		sections = forced_section ? 0 : man_split_colon(ms && *ms ? ms : MAN_DEFAULT_SECTIONS);
	}
	if (!manpath || (!forced_section && !sections)) {
		__util_diagf("man: out of memory\n");
		man_free_strv(manpath); man_free_strv(sections); man_argv_free(&names);
		return 1;
	}

	width = man_term_width();

	if (opt_k) {
		if (!man_apropos(manpath, names.v, names.n)) {
			__util_diagf("man: nothing appropriate\n");
			had_error = 1;
		}
		man_free_strv(manpath); man_free_strv(sections); man_argv_free(&names);
		return had_error ? 1 : 0;
	}

	{
		char *forced_arr[2];
		char **use_sections = sections;
		if (forced_section) { forced_arr[0] = (char *)forced_section; forced_arr[1] = 0; use_sections = forced_arr; }

		for (ni = 0; ni < names.n; ni++) {
			char *found_section = 0;
			char *path = man_find_page(manpath, use_sections, names.v[ni], &found_section);
			char *text; size_t tlen;
			struct man_buf formatted;

			if (!path) {
				__util_diagf("man: No manual entry for %s\n", names.v[ni]);
				had_error = 1;
				continue;
			}
			if (!man_read_page(path, &text, &tlen)) {
				free(path);
				had_error = 1;
				continue;
			}
			free(path);

			memset(&formatted, 0, sizeof formatted);
			if (!man_format(text, tlen, width, &formatted)) {
				__util_diagf("man: %s: formatting failed (out of memory)\n", names.v[ni]);
				free(text);
				had_error = 1;
				continue;
			}
			free(text);
			man_display(&formatted);
			mbuf_free(&formatted);
			shown_any = 1;
		}
	}

	man_free_strv(manpath);
	man_free_strv(sections);
	man_argv_free(&names);
	return (had_error || !shown_any) ? 1 : 0;
}

// NOLINTEND(misc-include-cleaner)
