#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# linkcheck.sh -- prove that a user can actually link a call to every
# function spicule declares in a public header, for the arch this tree is
# currently configured for.
#
# The bug class: a header can declare a function that no program can
# actually link against.  include/alloca.h used to do exactly this --
# `#define alloca __builtin_alloca` unconditionally, which tcc (having no
# such builtin) turned into `unresolved reference to '__builtin_alloca'`
# at link time for every caller, silently defeating arch/*/src/alloca.S,
# which exists precisely so tcc can call alloca as an ordinary function.
# It shipped because nothing in test/ ever called alloca.
#
# tools/lint-undefined.sh already catches the *textual* half of this (a
# prototype with no matching definition anywhere in src/arch/crt), but it
# cannot see the alloca shape at all: alloca(3) *is* defined, by
# arch/*/src/alloca.S, so lint-undefined.sh's declared-vs-defined name
# match is satisfied and it never notices that a macro at the call site
# silently retargeted every caller to a name that isn't.  Nothing short
# of actually compiling and linking a real call through the header, the
# same way a user's own TU would, catches that -- which is the entire
# reason this script exists.
#
# Method (see "why a real call, not just &func" below):
#
#   1. Mechanically extract every function declared in include/**/*.h
#      (plus obj/include's generated headers) with a real clang AST walk
#      (tools/clang/DeclScanner.cpp -- see its own header comment for the
#      full contract), which also captures each declaration's fixed
#      argument count and any `undefined-ok:` marker.  Never hand-listed:
#      add a header, add a prototype, and the next run sees it with no
#      change to this script.
#
#   2. For every declared name not covered by an `undefined-ok:` marker
#      (see tools/lint-undefined.sh's header for that convention -- this
#      script reuses the exact same markers as its exception list rather
#      than keeping a second, parallel one that could drift from the
#      first: setrlimit and select carry theirs today), emit a tiny
#      translation unit:
#
#          #include <the header that declared it>
#          void __linkcheck_NAME(void) { (void)NAME(0, 0, ...); }
#
#      with as many zero arguments as the prototype's fixed parameter
#      count (variadic functions get just the fixed ones; tcc does not
#      require more).  Every such TU is compiled and linked, individually,
#      against this arch's freshly built lib/crt1.o + lib/libc.a +
#      lib/ntdll.def -- the exact recipe the Makefile's obj/test/%.exe
#      rule uses for a real test binary -- with $(CC), never a host
#      compiler, so this sees precisely what a user's own build would.
#
#   3. Every failure (compile or link -- both mean "cannot use this
#      symbol") is collected and reported together, grouped, instead of
#      the run dying at the first one.
#
# Why a real call and not just `(void)&NAME`: taking the address does
# catch alloca's exact bug (an *object-like* macro rename: `#define
# alloca __builtin_alloca` turns `&alloca` into `&__builtin_alloca`,
# which fails), but it does NOT catch a *function-like* macro overriding
# a declared name (`#define foo(x) __foo(x)`) -- the preprocessor only
# expands a function-like macro when the name is followed by `(`, so a
# bare `&foo` silently refers to the un-expanded literal `foo` and can
# pass even when every real call would not.  A real call `foo(0)`
# triggers expansion either way and reproduces the historical failure
# faithfully: reverting the alloca.h fix locally and running this script
# reports the identical `tcc: error: unresolved reference to
# '__builtin_alloca'` the original bug report described (see the commit
# that introduced this script for a transcript).  No function-like macro
# shadows a declared prototype's name anywhere in include/ today (checked
# by hand at the time this was written), so the fixed-arity-zero-argument
# call this script generates is exact for every symbol currently declared;
# if one is ever added with a *different* arity than its own prototype,
# preprocessing that call would fail loudly (a macro/prototype arity
# mismatch), which is itself a finding worth seeing, not a false pass.
#
# Categories this does not, and cannot mechanically, cover:
#   - object-like macros that are never declared as a prototype at all
#     (assert, isdigit-the-macro-that-doesn't-exist-here, WIFEXITED,
#     FD_SET, va_start, ...) never appear in the "declared" list in the
#     first place, because they have no `RET NAME(...);` line to scan --
#     nothing to except, nothing to check.
#   - `static inline`/`static __inline` functions defined with a body in
#     the header itself (__bswap16/32/64 in endian.h): the scanner's decl
#     mode treats the body's `{` as opening an opaque nested block and
#     never emits a top-level declarator for it, exactly like
#     lint-undefined.sh -- correctly: nothing to link, the definition is
#     right there in every including TU.
#   - a symbol legitimately declared-and-unimplemented is not a failure
#     of this script; it must carry an `undefined-ok:` marker (checked by
#     lint-undefined.sh too) or this script reports it same as any other
#     unlinkable symbol.
#
# Usage: tools/linkcheck.sh
#   Requires the tree to already be `./configure`d and `make`d for the
#   arch to check (reads config.mak via the Makefile's own `linkcheck`
#   target, which passes CC/ARCH/flags in).  Run once per arch -- see
#   `make linkcheck`'s own comment for why this cannot check both arches
#   in one invocation: arch/ is not shared, so lib/crt1.o and lib/libc.a
#   are only ever built for whichever arch config.mak currently names.
#
# Environment (all normally supplied by `make linkcheck`):
#   CC, ARCH, CFLAGS_C99FSE, CFLAGS_AUTO   as in config.mak
#   LINKCHECK_STRICT=0   always exit 0 (report only)
#   LINKCHECK_JOBS=N     how many symbols to compile and link at once
#                        (default: nproc).  1 restores the fully serial
#                        behaviour, and is also the safe fallback when
#                        neither nproc nor getconf exists.  The report is
#                        byte-identical at any value -- see phase 1's
#                        comment on why.

set -u

# shellcheck disable=SC1007
srcdir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$srcdir" || exit 1

: "${CC:?linkcheck.sh needs CC set (run via 'make linkcheck', not directly)}"
: "${ARCH:?linkcheck.sh needs ARCH set (run via 'make linkcheck', not directly)}"
: "${CFLAGS_C99FSE:=-std=c99 -nostdinc -fno-builtin}"
: "${CFLAGS_AUTO:=}"
: "${LINKCHECK_STRICT:=1}"

for f in lib/crt1.o lib/libc.a lib/ntdll.def; do
	[ -f "$f" ] || { echo "linkcheck: $f missing -- run 'make' first" >&2; exit 1; }
done

# ---------------------------------------------------------------------
# lib/libc.a's member names must be unique.
#
# An `ar' member is named by the *basename* of the file handed to ar.
# Every archiver strips the directory (GNU ar, llvm-ar and tcc's
# built-in -ar alike) and none of them offers a way to ask for anything
# else, so a mirrored object tree -- obj/src/process/exec.o and
# obj/src/sh/exec.o -- collapses into one flat archive namespace whether
# the build system means it to or not.
#
# tcc's ar, which is this project's $(AR) on platform=nt (`AR = $(CC)
# -ar', and nt's boot/kaem bootstrap leg has no other archiver at all --
# unlike platform=linux's leg, which uses a real `ar' with no such
# limitation; see tools/gen-kaem.sh's own note on why clang needs one),
# goes one step further: it truncates that basename to 15 characters.
# This check itself is unconditional (ARCH-scoped, not PLATFORM-aware --
# see the Makefile's `linkcheck:' recipe), so it still runs under
# platform=linux, just against an archiver that does not actually have
# this bug; a false positive here is not impossible, just not yet seen.
# tcctools.c's
# tcc_tool_ar() clamps `istrlen' to `sizeof(arhdro.ar_name) - 1' and
# writes the '/' terminator at that offset, and it emits no SysV `//'
# long-name table to escape to.  So `spawn_file_actions.o' is really
# stored as `spawn_file_acti', and any two sources anywhere under src/
# whose basenames agree in their first 15 characters are one member
# name -- not merely two sources with the identical basename.
#
# That 15-character cap is also why this is a check rather than a naming
# scheme: no injective encoding of a source path exists inside 15
# characters, so member names cannot be made unique *by construction*
# without hashing them into illegibility.  What can be guaranteed is
# that a collision never lands silently, which is this check's whole
# job.
#
# The collision is not hypothetical.  src/process/exec.c (the
# exec()/execve() family) and src/sh/exec.c (the shell executor, renamed
# to src/sh/execute.c when this was found) both landed as `exec.o':
# 308 members under 307 distinct names on x86_64, 310/309 on i386.
# Nothing had broken -- the archive symbol index still resolved every
# symbol in both objects, and both tcc's linker and GNU ld linked
# against it fine -- which is exactly why it sat there unnoticed until
# an outside consumer counted members.  But `ar x'/`ar p' can only ever
# reach the first of the two, and any consumer resolving by member name
# rather than by symbol gets whichever one the archive order hands it.
#
# This check exists because that was invisible from inside the tree:
# nothing failed, nothing warned, and the only reason it was ever found
# is that somebody outside counted.  A count is cheap and it cannot be
# fooled by "it links fine here".
#
# It lives in linkcheck, rather than in the Makefile, for two reasons.
# linkcheck is already a per-arch gate stage over the *built* lib/libc.a
# (linkcheck-i386 and linkcheck-x86_64 are separate stages in
# tools/gate.sh), and reading the archive back is what makes the
# 15-character truncation visible at all -- a check over the Makefile's
# object list would only ever see untruncated names and would miss that
# entire class.  Putting it in the `lib/libc.a' recipe was the other
# candidate and is deliberately rejected: tools/gen-kaem.sh rewrites
# that recipe's dry run into boot/kaem/build-*.kaem and fails on any
# command it cannot classify, so a check there would have to be taught
# to the bootstrap generator too, for no gain.
#
# Like the missing-file check above, and unlike a symbol finding, this
# is a structural defect in the artefact rather than a report about the
# library's contents, so it is not subject to LINKCHECK_STRICT=0.
#
# $CC is a command name possibly carrying flags, exactly as at the
# compile and link sites further down, and must word-split.
# shellcheck disable=SC2086
ar_names=$($CC -ar t lib/libc.a 2>&1) || {
	echo "linkcheck [$ARCH]: FAILED -- could not list lib/libc.a's members with" >&2
	echo "linkcheck [$ARCH]: '$CC -ar t':" >&2
	printf '%s\n' "$ar_names" | sed 's/^/linkcheck: /' >&2
	exit 1
}

ar_total=$(printf '%s\n' "$ar_names" | grep -c '.')
ar_uniq=$(printf '%s\n' "$ar_names" | sort | uniq | grep -c '.')

# A floor, so an `ar t' that silently produced nothing (or a handful of
# lines) cannot pass this check by making 0 equal 0.  The library has
# had 300-odd objects for a long time and only ever grows; 100 is far
# below any plausible real value and far above any accident.
if [ "$ar_total" -lt 100 ]; then
	echo "linkcheck [$ARCH]: FAILED -- lib/libc.a lists only $ar_total member(s)." >&2
	echo "linkcheck [$ARCH]: That is too few to be a real build of this library, so the" >&2
	echo "linkcheck [$ARCH]: member-name uniqueness check below would be vacuous.  Either" >&2
	echo "linkcheck [$ARCH]: the archive is truncated, or '$CC -ar t' does not list members" >&2
	echo "linkcheck [$ARCH]: one per line the way this check assumes." >&2
	exit 1
fi

if [ "$ar_total" -ne "$ar_uniq" ]; then
	echo "linkcheck [$ARCH]: FAILED -- lib/libc.a has $ar_total member(s) under only" >&2
	echo "linkcheck [$ARCH]: $ar_uniq distinct name(s).  An ar member name is the object's" >&2
	echo "linkcheck [$ARCH]: basename truncated to 15 characters (tcc's ar -- see the comment" >&2
	echo "linkcheck [$ARCH]: above this check), so two sources in different directories, or" >&2
	echo "linkcheck [$ARCH]: two long names in the same one, can shadow each other in the" >&2
	echo "linkcheck [$ARCH]: archive even though their paths differ." >&2
	echo "linkcheck [$ARCH]: Colliding member name(s), with the sources that produce them:" >&2
	printf '%s\n' "$ar_names" | sort | uniq -d | while IFS= read -r dup; do
		echo "linkcheck [$ARCH]:   $dup" >&2
		find src arch crt -name '*.c' -o -name '*.S' -o -name '*.s' 2>/dev/null |
		sort | while IFS= read -r f; do
			b=${f##*/}
			b=${b%.*}.o
			case $(printf '%.15s' "$b") in
				"$dup") echo "linkcheck [$ARCH]:     $f" >&2 ;;
			esac
		done
	done
	echo "linkcheck [$ARCH]: Rename one of them so the first 15 characters of the object" >&2
	echo "linkcheck [$ARCH]: basename differ, then run 'make generated' to regenerate the" >&2
	echo "linkcheck [$ARCH]: boot/kaem bootstrap scripts." >&2
	exit 1
fi

echo "linkcheck [$ARCH]: lib/libc.a: $ar_total member(s), $ar_uniq distinct name(s) -- no collisions"

builddir=obj/linkcheck
rm -rf "$builddir"
mkdir -p "$builddir" || exit 1

INC="-I$srcdir/arch/$ARCH -I$srcdir/arch/generic -Iobj/include -I$srcdir/include"
CFLAGS="$CFLAGS_C99FSE $CFLAGS_AUTO -D_XOPEN_SOURCE=700 -D_ALL_SOURCE $INC"

# The scanner below is clang-18, but the real target for every arch this
# project builds (x86_64-win32-tcc, i386-win32-tcc, arm64-win32-tcc) is
# tcc -- and tcc predefines __TINYC__ itself, automatically, with no
# CFLAGS involvement at all, the same way any compiler predefines its
# own identifying macro. clang has no way to know to simulate that
# unless told, so without this, the scanner sees a header exactly as
# clang itself would parse it -- not as the real target compiler would
# -- silently defeating this whole function's own header comment above
# ("a declaration hidden behind an #ifdef this arch's flags do not
# satisfy is correctly invisible here too, the same as it would be to a
# real caller"). Found real: include/complex.h's `#ifdef __TINYC__ /
# #define __STDC_NO_COMPLEX__ 1 #else <66 declarations> #endif` is
# exactly this shape, and every one of those 66 was a false-positive
# "unlinkable" finding here before this fix -- correctly undeclared
# under a real tcc compile (src/complex/*.c's own bodies compile to
# empty translation units there, by the same #ifdef), but visible to
# this scanner's clang-only view. Guarded on $CC naming tcc specifically
# rather than defined unconditionally, so a future non-tcc target
# (nothing in this tree today, but ARCH/CC are config.mak-driven) is not
# silently told it is tcc when it is not.
case "$CC" in
*tcc*) CFLAGS="$CFLAGS -D__TINYC__" ;;
esac

# ---------------------------------------------------------------------
# The scanner: tools/clang/DeclScanner.cpp, a real clang AST walk (see
# that file's own header comment for the full contract).  It replaced a
# hand-rolled awk scanner that did character-at-a-time comment/string
# stripping and treated "the first identifier immediately followed by
# '('" as a declarator name -- a heuristic that broke on two patterns
# that now appear throughout include/*.h: `// NOLINTBEGIN(...)` /
# `// NOLINTEND(...)` clang-tidy suppression comments (the awk only ever
# stripped /* */ comments, never // ones), and ownership.h's `withtok()`
# used as a *prefix* attribute before a declaration's return type (the
# awk's leftmost-identifier-before-"(" match landed on `withtok(` itself,
# and silently swallowed the real declaration that followed -- not just
# malloc()/calloc()/realloc()/etc. in stdlib.h, but every declaration
# between that swallowed span and the next semicolon).
#
# Built once, right below, the same way tools/lint.sh builds its own
# PluginASTAction/CheckerRegistry clang plugins (see e.g. that script's
# stage_totality()): clang++-18 against llvm-config-18's own flags, plus
# libclang-cpp.so.18* found under llvm-config-18's libdir, which
# FrontendPluginRegistry-based plugins need and llvm-config's own
# --libs/--system-libs do not provide.
#
# Run once per header, in the same C mode ($CFLAGS, built above) every
# real spicule-consuming program compiles against -- so, unlike the old
# awk's blind text scan, a declaration hidden behind an #ifdef this
# arch's flags do not satisfy is correctly invisible here too, the same
# as it would be to a real caller.
#
# Output contract unchanged from the old scan(): one line per declared
# function, tab-separated: name  header  fixed_argc  undefined_ok(0/1).
# ---------------------------------------------------------------------
declscan_plugin="$builddir/spicule-declscan.so"
for declscan_tool in clang-18 clang++-18 llvm-config-18; do
	command -v "$declscan_tool" >/dev/null 2>&1 || {
		echo "linkcheck: FAILED -- '$declscan_tool' not found on PATH." >&2
		echo "linkcheck: the declaration scanner (tools/clang/DeclScanner.cpp) is a real" >&2
		echo "linkcheck: clang AST walk, built and run the same way tools/lint.sh builds its" >&2
		echo "linkcheck: own clang plugins -- see that script's require_tool()/stage_totality()" >&2
		echo "linkcheck: for what to install (CI: clang-18 libclang-18-dev llvm-18-dev)." >&2
		exit 1
	}
done
declscan_libdir=$(llvm-config-18 --libdir) || {
	echo "linkcheck: FAILED -- 'llvm-config-18 --libdir' failed." >&2
	exit 1
}
declscan_clang_cpp=$(find "$declscan_libdir" -maxdepth 1 -name 'libclang-cpp.so.18*' \
	-print 2>/dev/null | sort | head -n 1)
if [ -z "$declscan_clang_cpp" ]; then
	echo "linkcheck: FAILED -- Clang 18 development libraries (libclang-cpp.so.18*) not" >&2
	echo "linkcheck: found under '$declscan_libdir'.  Install them the same way CI does" >&2
	echo "linkcheck: (libclang-18-dev) -- see tools/lint.sh's stage_totality() for the" >&2
	echo "linkcheck: equivalent build." >&2
	exit 1
fi
# llvm-config deliberately returns shell words, not one argument.
# shellcheck disable=SC2046
clang++-18 -fPIC -shared $(llvm-config-18 --cxxflags) \
	tools/clang/DeclScanner.cpp -o "$declscan_plugin" "$declscan_clang_cpp" \
	$(llvm-config-18 --ldflags --libs --system-libs) || {
	echo "linkcheck: FAILED -- could not build tools/clang/DeclScanner.cpp into a clang" >&2
	echo "linkcheck: plugin." >&2
	exit 1
}

scan() {
	scan_rc=0
	for scan_hdr in "$@"; do
		# shellcheck disable=SC2086
		clang-18 -std=c99 -fsyntax-only $CFLAGS \
			-Xclang -load -Xclang "$declscan_plugin" \
			-Xclang -add-plugin -Xclang spicule-declscan \
			-Xclang -plugin-arg-spicule-declscan -Xclang "$scan_hdr" \
			"$scan_hdr" 2>> "$builddir/declscan.err" || scan_rc=1
	done
	return $scan_rc
}

headers=$(find include obj/include -type f -name '*.h' 2>/dev/null | sort)
nheaders=$(printf '%s\n' "$headers" | grep -c . || true)

declfile="$builddir/declared"
# An empty $headers is checked *before* scan(), not after, so a truly
# empty header list is reported plainly rather than as a mysteriously
# empty $declfile below.
if [ -z "$headers" ]; then
	echo "linkcheck: FAILED -- no headers found under include/ or obj/include/." >&2
	echo "linkcheck: there is nothing to check, so this run cannot report success." >&2
	echo "linkcheck: (obj/include/ is generated -- run 'make' first.)" >&2
	exit 1
fi
: > "$builddir/declscan.err"
# $headers is a list of file names and must word-split.
# shellcheck disable=SC2086
scan $headers > "$declfile" </dev/null || {
	echo "linkcheck: FAILED -- the header scanner (clang-18 + tools/clang/DeclScanner.cpp)" >&2
	echo "linkcheck: exited nonzero on at least one header; the declared-symbol list is" >&2
	echo "linkcheck: incomplete or empty, so nothing below can be trusted.  Diagnostics:" >&2
	echo "linkcheck: $builddir/declscan.err" >&2
	sed 's/^/linkcheck: /' "$builddir/declscan.err" >&2
	exit 1
}
if [ ! -s "$declfile" ]; then
	echo "linkcheck: FAILED -- no declared symbols were found in any header." >&2
	echo "linkcheck: $nheaders header(s) were scanned; either the find above" >&2
	echo "linkcheck: matched nothing (run 'make' first, so obj/include exists) or scan()" >&2
	echo "linkcheck: stopped recognising declarations.  Either way this run checked" >&2
	echo "linkcheck: nothing." >&2
	exit 1
fi

# undefined-ok reason, for the report: the marker's own comment line(s),
# collapsed to one line.  Mirrors tools/lint-undefined.sh's own
# markednames pass, but this script only needs the free text, not a
# name list -- names come straight from column 4 of $declfile above.
reason_for() {
	nm=$1 hdr=$2
	awk -v NM="$nm" '
		index($0, NM) && index($0, "undefined-ok:") {
			line = $0
			sub(/^.*undefined-ok:[ \t]*/, "", line)
			gsub(/\*\//, "", line)
			gsub(/^[ \t]+|[ \t]+$/, "", line)
			# The reason often starts on the *next* line ("undefined-ok:"
			# with nothing else on its own line) -- pull it in too, so the
			# report is never just a bare "undefined-ok:" with no text.
			if (line == "" && (getline nextline) > 0) {
				sub(/^[ \t]*\*?[ \t]*/, "", nextline)
				gsub(/\*\//, "", nextline)
				gsub(/^[ \t]+|[ \t]+$/, "", nextline)
				line = nextline
			}
			print line; exit
		}
	' "$hdr"
}

# A second, small exception list, in the same shape as
# tools/asan-build.sh's not_native(): symbols that are genuinely defined
# in the library (so `undefined-ok:` above does not apply, and
# lint-undefined.sh correctly reports nothing) but that cannot link from
# a standalone TU like the ones this script generates, because their
# *contract* requires the calling program itself to supply another
# symbol.  Found by running this script once and reading the failures:
# every spicule_rpath_*/spicule_delayLoadHelper2 entry point resolves
# `__rpath` (include/spicule/rpath.h) as an extern array the *executable*
# is documented to define (see test/rpath.c for a real definition) --
# libc.a deliberately does not carry one, the same way it does not carry
# a definition of `main`. A generated TU that only calls the function,
# the way every other symbol here is checked, would always be missing
# that array and would misreport a real, working library entry point as
# broken.
#
# dlopen()/dlsym()/dlclose()/dlerror() (include/dlfcn.h, src/dlfcn/
# dlfcn.c) and spicule_rpath_unload()/spicule_rpath_error_seq()
# (include/spicule/rpath.h, src/internal/rpath.c) join the list for the
# same reason at one remove: dlopen()/dlsym()/dlclose() call straight
# into spicule_rpath_load()/_sym()/_unload(), and dlerror() into
# spicule_rpath_error_seq() (which shares rpath.c's one translation unit
# and so pulls in the same unresolved `__rpath`, even though it does
# not read that array itself) -- a generated single-call TU for any of
# these six hits the identical missing-`__rpath` link failure, for a
# reason that has nothing to do with whether the function itself works.
#
# hsearch() (include/search.h, src/search/hsearch.c) is a different
# shape of the same "the generator, not the symbol, is the problem"
# story: basedefs/search.h.html's ENTRY is passed *by value*
# (`ENTRY hsearch(ENTRY item, ACTION action)` -- ACTION is an enum, so
# its own `0` argument is fine), and this script's call-site generator
# (see "method" above) always fills every argument slot with the
# literal `0`. `0` does not implicitly convert to a struct type in C,
# so the generated `hsearch(0, 0)` fails to compile -- not because
# hsearch is unlinkable (test/posix-glob.c calls it with a real ENTRY
# literal and it works), but because a bare `0` can never stand in for
# a byval struct argument no matter what the callee does with it.
#
# inet_ntoa() (include/arpa/inet.h, src/socket/inet.c) is the identical
# by-value-struct shape: `char *inet_ntoa(struct in_addr)` takes its
# only argument by value, so the generated `inet_ntoa(0)` hits the same
# "0 cannot convert to a struct type" compile failure, not a real link
# problem (test/posix-socket.c calls it with a real struct in_addr and
# it works).
#
# sigqueue() (include/signal.h, src/signal/signal.c) is the same shape
# again, one argument at a different position: `int sigqueue(pid_t, int,
# union sigval)` takes its third argument by value, so the generated
# `sigqueue(0, 0, 0)` hits the same "0 cannot convert to a
# struct/union type" compile failure -- not a real link problem
# (test/posix-signal.c calls it with a real union sigval and it works).
# The old hand-rolled awk scanner never reached this one: include/signal.h
# is one of the headers carrying a `// NOLINTBEGIN(...)` suppression
# comment near its top, and the awk's failure to strip `//` comments (see
# tools/clang/DeclScanner.cpp's own header comment) swallowed an
# unpredictable span of the file's real declarations into one bogus
# "NOLINTBEGIN" entry -- sigqueue's declaration was silently among the
# casualties, so this exception was never needed until the scanner
# started seeing the whole header correctly.
linkcheck_exception() {
	case $1 in
	spicule_rpath_load|spicule_rpath_sym|spicule_rpath_error|spicule_rpath_fail|spicule_delayLoadHelper2|spicule_rpath_unload|spicule_rpath_error_seq|dlopen|dlsym|dlclose|dlerror)
		echo "resolves __rpath (include/spicule/rpath.h), an extern array the *calling program* is documented to define (see test/rpath.c) -- not a libc symbol, so no standalone TU can supply it" ;;
	hsearch)
		echo "takes ENTRY by value (basedefs/search.h.html); this script's generated call site fills every argument with a literal 0, which cannot convert to a struct type -- a generator limitation, not an unlinkable symbol (see test/posix-glob.c's real ENTRY-literal call)" ;;
	inet_ntoa)
		echo "takes struct in_addr by value (include/arpa/inet.h); this script's generated call site fills every argument with a literal 0, which cannot convert to a struct type -- a generator limitation, not an unlinkable symbol (see test/posix-socket.c's real struct in_addr call)" ;;
	sigqueue)
		echo "takes union sigval by value (include/signal.h); this script's generated call site fills every argument with a literal 0, which cannot convert to a struct/union type -- a generator limitation, not an unlinkable symbol (see test/posix-signal.c's real union sigval call)" ;;
	*) echo "" ;;
	esac
}

# ---------------------------------------------------------------------
# PE header sanity check.
#
# Wine's PE loader and the real Windows NT loader disagree about which
# header fields they actually enforce -- measured directly on real
# Windows 11 Pro 22621 by building header variants of the same program
# and launching each on the true NT loader (see the commit that added
# this check for the full transcript):
#
#   - SectionAlignment below the page size (0x1000), *even with
#     FileAlignment set to match it* -- a combination the PE/COFF spec
#     (section "Optional Header Windows-Specific Fields", the
#     SectionAlignment entry) explicitly permits -- makes the real NT
#     loader reject the image outright with ERROR_BAD_EXE_FORMAT (193),
#     "is not a valid Win32 application". Wine loads the identical image
#     without complaint.
#   - SectionAlignment == 0x1000 loads and runs on real Windows even
#     when SizeOfRawData is not a multiple of FileAlignment, which the
#     spec says it MUST be -- ReactOS's ntoskrnl/mm/section.c documents
#     deliberately disabling that exact check, with a comment noting
#     real-world images violate it and the loader copes. So that field
#     is a confirmed non-hazard on the "spec MUST but nobody enforces
#     it" side and is deliberately NOT asserted here.
#
# Every test this project runs, runs under Wine (tools/run-tests.py);
# none of them would ever notice a SectionAlignment regression. This
# check exists so a static header inspection catches it instead, on
# every .exe tools/linkcheck.sh builds.
#
# Read with `od`, not objdump/readelf or a PE-parsing library: this
# script has no dependency today beyond awk/sh/the target $CC, od is a
# POSIX utility (IEEE Std 1003.1-2017), and the three fields needed
# (Magic, SectionAlignment, FileAlignment) sit at fixed byte offsets
# from e_lfanew, so a handful of `od -j/-N` reads is simpler and more
# portable than adding a new tool dependency for three integers this
# script's own build-and-link recipe already produced. PE headers are
# nt-specific in the first place (linux's real ELF output has no MZ/PE
# structure for this check to read at all), and this stays out of nt's
# boot/kaem/ bootstrap leg entirely regardless -- that leg never invokes
# `make linkcheck`, only tcc + mkdir/cp/catm (see gen-kaem.sh).
#
# Bytes are combined explicitly as little-endian (PE's byte order,
# always) rather than via `od`'s native-endian numeric types, so this
# is correct even run on a big-endian host.
#
# Standard fields before the Windows-specific fields are 28 bytes long
# in a PE32 optional header (through BaseOfData) and 24 bytes in PE32+
# (no BaseOfData), but ImageBase is 4 bytes in PE32 and 8 in PE32+, so
# the two differences exactly cancel: SectionAlignment lands at
# optional-header offset 32, and FileAlignment at offset 36, in both
# PE32 and PE32+ alike.
# ---------------------------------------------------------------------
pe_u8_list() {
	# pe_u8_list FILE OFFSET COUNT -- COUNT decimal byte values, one per line.
	od -An -tu1 -j "$2" -N "$3" "$1" | tr -s ' \t' '\n' | sed '/^$/d'
}

pe_le() {
	# pe_le FILE OFFSET COUNT -- little-endian unsigned integer built
	# from COUNT bytes (COUNT <= 4) read at OFFSET in FILE.
	pe_le_val=0 pe_le_mul=1
	for pe_le_byte in $(pe_u8_list "$1" "$2" "$3"); do
		pe_le_val=$((pe_le_val + pe_le_byte * pe_le_mul))
		pe_le_mul=$((pe_le_mul * 256))
	done
	echo "$pe_le_val"
}

pe_header_check() {
	# pe_header_check EXE -- prints nothing and returns 0 if EXE's PE
	# header passes every check above; otherwise prints one line per
	# violation (to stdout -- callers redirect) and returns nonzero.
	img=$1
	case $ARCH in
	x86_64) pe_want_magic=$((0x20b)); pe_want_name="PE32+" ;;
	i386)   pe_want_magic=$((0x10b)); pe_want_name="PE32" ;;
	*)
		echo "linkcheck: ARCH='$ARCH' has no known expected PE Magic -- add it to pe_header_check() in tools/linkcheck.sh"
		return 1 ;;
	esac

	# shellcheck disable=SC2046
	set -- $(pe_u8_list "$img" 0 2)
	if [ "${1:-0}" -ne 77 ] || [ "${2:-0}" -ne 90 ]; then
		echo "$img: no MZ signature at offset 0 -- not a PE image"
		return 1
	fi

	pe_off=$(pe_le "$img" 60 4)
	# shellcheck disable=SC2046
	set -- $(pe_u8_list "$img" "$pe_off" 4)
	if [ "${1:-0}" -ne 80 ] || [ "${2:-0}" -ne 69 ] || [ "${3:-0}" -ne 0 ] || [ "${4:-0}" -ne 0 ]; then
		echo "$img: no PE signature at e_lfanew offset $pe_off"
		return 1
	fi

	opt_off=$((pe_off + 4 + 20))
	pe_magic=$(pe_le "$img" "$opt_off" 2)
	pe_sec_align=$(pe_le "$img" $((opt_off + 32)) 4)
	pe_file_align=$(pe_le "$img" $((opt_off + 36)) 4)

	pe_ok=1
	if [ "$pe_magic" -ne "$pe_want_magic" ]; then
		printf '%s: Magic 0x%x, expected 0x%x (%s, for ARCH=%s)\n' \
			"$img" "$pe_magic" "$pe_want_magic" "$pe_want_name" "$ARCH"
		pe_ok=0
	fi
	if [ "$pe_sec_align" -lt 4096 ]; then
		printf '%s: SectionAlignment 0x%x is below the page size (0x1000). The real NT loader rejects this outright with ERROR_BAD_EXE_FORMAT (193), "is not a valid Win32 application" -- even when FileAlignment is set to match it, which the PE/COFF spec explicitly permits. Measured on real Windows 11 Pro 22621; Wine loads such an image fine, so this project'"'"'s Wine-based test suite can never catch it (see the comment above pe_header_check() in tools/linkcheck.sh).\n' \
			"$img" "$pe_sec_align"
		pe_ok=0
	fi
	if [ "$pe_sec_align" -lt "$pe_file_align" ]; then
		printf '%s: SectionAlignment 0x%x is less than FileAlignment 0x%x; the PE/COFF spec requires SectionAlignment >= FileAlignment unconditionally.\n' \
			"$img" "$pe_sec_align" "$pe_file_align"
		pe_ok=0
	fi
	[ "$pe_ok" -eq 1 ]
}

total=0 checked=0 excepted=0 failed=0
: > "$builddir/failures"
: > "$builddir/exceptions"
: > "$builddir/pe-seen"

# ---------------------------------------------------------------------
# Phase 1, serial: split the declared list into "excepted" (reported and
# skipped) and a worklist of symbols that really get compiled and linked.
# Cheap -- no processes -- and it has to be serial anyway, because both
# exception paths carry a written reason that is reported in declaration
# order.
#
# The worklist line is "index<TAB>name<TAB>header<TAB>argc"; the index is
# what makes the parallel phase below reproducible.  Two runs of this
# script produce byte-identical reports regardless of how the workers
# were scheduled, because nothing is appended to a shared file by a
# worker: each writes its own result file named by that index, and the
# merge reads them back in index order.
# ---------------------------------------------------------------------
worklist="$builddir/worklist"
: > "$worklist"
while IFS="$(printf '\t')" read -r nm hdr argc marked; do
	[ -z "$nm" ] && continue
	total=$((total + 1))
	if [ "$marked" = 1 ]; then
		excepted=$((excepted + 1))
		printf '%s (%s): %s\n' "$nm" "$hdr" "$(reason_for "$nm" "$hdr")" >> "$builddir/exceptions"
		continue
	fi
	why=$(linkcheck_exception "$nm")
	if [ -n "$why" ]; then
		excepted=$((excepted + 1))
		printf '%s (%s): %s\n' "$nm" "$hdr" "$why" >> "$builddir/exceptions"
		continue
	fi
	checked=$((checked + 1))
	printf '%06d\t%s\t%s\t%s\n' "$checked" "$nm" "$hdr" "$argc" >> "$worklist"
done < "$declfile"

# ---------------------------------------------------------------------
# Phase 2, parallel: two $CC invocations and a handful of `od` reads per
# symbol, several hundred symbols.  Every one is independent -- it reads
# the source tree and lib/, and writes only files named after its own
# symbol -- so this is embarrassingly parallel, and it was the dominant
# cost of `make linkcheck`.
#
# Sharded across LINKCHECK_JOBS subshells of *this* shell, rather than
# the worker pattern in tools/lint.sh and tools/run-tests.py
# use.  The reason is specific and not a preference: the per-symbol work
# calls pe_header_check(), which calls pe_le(), which calls
# pe_u8_list().  A `sh -c` child does not inherit shell functions, so the
# xargs shape would need those three either duplicated into a generated
# helper or re-derived in the child -- a second copy of the PE-header
# rules, which is exactly the hazard tools/lint-decls.awk was extracted
# to remove.  A subshell inherits them.  The cost of the choice is static
# round-robin instead of xargs's dynamic scheduling; the per-symbol cost
# here is near-uniform (the same two compiles of a three-line TU), so the
# imbalance is negligible.
#
# check_one INDEX NAME HEADER ARGC -- writes $pardir/INDEX.out, whose
# first line is "OK", or "FAIL COMPILE"/"FAIL LINK"/"FAIL PE" followed by
# the detail.  ALWAYS writes the file, including on success: the merge
# below counts them, so a worker that dies without reporting is a
# failure rather than a symbol that quietly stops being checked.  That is
# the failure mode of this rewrite -- losing a child's non-zero exit
# turns the whole stage into a vacuous pass -- and it is the one thing
# here that is guarded rather than reasoned about.
check_one() {
	co_idx=$1 co_nm=$2 co_hdr=$3 co_argc=$4
	co_args=""
	co_i=0
	while [ "$co_i" -lt "$co_argc" ]; do
		co_args="$co_args${co_args:+, }0"
		co_i=$((co_i + 1))
	done

	co_src="$builddir/$co_nm.c"
	co_obj="$builddir/$co_nm.o"
	co_exe="$builddir/$co_nm.exe"
	co_out="$pardir/$co_idx.out"
	{
		printf '#include <%s>\n' "${co_hdr#include/}"
		printf 'void __linkcheck_%s(void) { (void)%s(%s); }\n' "$co_nm" "$co_nm" "$co_args"
		printf 'int main(void) { return 0; }\n'
	} > "$co_src"

	# shellcheck disable=SC2086
	if ! $CC $CFLAGS -c -o "$co_obj" "$co_src" 2> "$co_obj.err"; then
		{ echo "FAIL COMPILE"; sed 's/^/    /' "$co_obj.err"; } > "$co_out"
		return 0
	fi
	# shellcheck disable=SC2086
	if ! $CC $CFLAGS -nostdlib -o "$co_exe" lib/crt1.o "$co_obj" -Llib -lc -lntdll 2> "$co_exe.err"; then
		{ echo "FAIL LINK"; sed 's/^/    /' "$co_exe.err"; } > "$co_out"
		return 0
	fi
	if ! co_pe=$(pe_header_check "$co_exe" 2>&1); then
		{ echo "FAIL PE"; printf '%s\n' "$co_pe"; } > "$co_out"
		return 0
	fi
	echo OK > "$co_out"
}

: "${LINKCHECK_JOBS:=}"
if [ -z "$LINKCHECK_JOBS" ]; then
	LINKCHECK_JOBS=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
fi
pardir="$builddir/par"
mkdir -p "$pardir" || exit 1

shard=0
while [ "$shard" -lt "$LINKCHECK_JOBS" ]; do
	(
		awk -v n="$LINKCHECK_JOBS" -v k="$shard" 'NR % n == k' "$worklist" \
		| while IFS="$(printf '\t')" read -r idx nm hdr argc; do
			[ -z "$idx" ] && continue
			check_one "$idx" "$nm" "$hdr" "$argc"
		done
	) &
	shard=$((shard + 1))
done
wait

# ---------------------------------------------------------------------
# Phase 3, serial: merge the per-symbol results back in declaration
# order.  The PE-header de-duplication lives here rather than in the
# worker, which is not merely convenient: a shared "have I already
# printed this reason" file written from N concurrent workers would make
# which instance got the full paragraph depend on scheduling, and the
# report would differ run to run for an unchanged tree.
# ---------------------------------------------------------------------
nreported=0
while IFS="$(printf '\t')" read -r idx nm hdr argc; do
	[ -z "$idx" ] && continue
	res="$pardir/$idx.out"
	if [ ! -f "$res" ]; then
		# See check_one's comment: this is the vacuous-pass hole this
		# rewrite could have opened, so it is a hard failure rather
		# than a symbol silently dropped from the count.
		failed=$((failed + 1))
		printf '%s (%s, %s args) -- NO RESULT: the worker for this symbol never wrote one, so it was never checked.\n' \
			"$nm" "$hdr" "$argc" >> "$builddir/failures"
		continue
	fi
	nreported=$((nreported + 1))
	kind=$(head -n 1 "$res")
	case $kind in
	OK) continue ;;
	"FAIL COMPILE")
		failed=$((failed + 1))
		{
			printf '%s (%s, %s args) -- COMPILE FAILED:\n' "$nm" "$hdr" "$argc"
			tail -n +2 "$res"
		} >> "$builddir/failures" ;;
	"FAIL LINK")
		failed=$((failed + 1))
		{
			printf '%s (%s, %s args) -- LINK FAILED:\n' "$nm" "$hdr" "$argc"
			tail -n +2 "$res"
		} >> "$builddir/failures" ;;
	"FAIL PE")
		failed=$((failed + 1))
		exe="$builddir/$nm.exe"
		pehdr=$(tail -n +2 "$res")
		# Every .exe built this run shares the same $CC/$CFLAGS/link
		# recipe, so a PE header regression is not per-symbol -- it is
		# the same header field, wrong the same way, in every failing
		# .exe. Print the full reason once per distinct message (keyed
		# on the text with this file's own path stripped out) and fold
		# repeats into a one-line pointer, so a real regression's
		# report stays readable instead of repeating the same
		# paragraph once per declared symbol (hundreds of times).
		pe_key=$(printf '%s\n' "$pehdr" | sed "s#$exe#<exe>#g")
		if grep -qxF "$pe_key" "$builddir/pe-seen" 2>/dev/null; then
			printf '%s (%s, %s args) -- PE HEADER CHECK FAILED: %s (same reason as the first instance above; see %s)\n' \
				"$nm" "$hdr" "$argc" "$(printf '%s\n' "$pehdr" | head -1)" "$exe" >> "$builddir/failures"
		else
			printf '%s\n' "$pe_key" >> "$builddir/pe-seen"
			{
				printf '%s (%s, %s args) -- PE HEADER CHECK FAILED:\n' "$nm" "$hdr" "$argc"
				printf '%s\n' "$pehdr" | sed 's/^/    /'
			} >> "$builddir/failures"
		fi ;;
	*)
		failed=$((failed + 1))
		printf '%s (%s, %s args) -- UNPARSEABLE RESULT: %s\n' \
			"$nm" "$hdr" "$argc" "$kind" >> "$builddir/failures" ;;
	esac
done < "$worklist"

# The floor on the parallel phase itself, counted rather than inferred.
# $failed already rose once per missing result above; this says how many,
# in one line, so a scheduling or fork failure that lost a whole shard is
# legible instead of appearing as a wall of individual NO RESULT lines.
if [ "$nreported" -ne "$checked" ]; then
	echo "" >&2
	echo "linkcheck [$ARCH]: FAILED -- $nreported of $checked symbol(s) reported a result." >&2
	echo "linkcheck [$ARCH]: $((checked - nreported)) worker result(s) are missing, so those symbols" >&2
	echo "linkcheck [$ARCH]: were never compiled or linked.  A parallel phase that loses work must" >&2
	echo "linkcheck [$ARCH]: fail, not report a smaller number of checks as a pass." >&2
	# $failed already rose once per missing result in the loop above, so
	# the exit status is already non-zero; this block exists to say how
	# many in one line rather than to change the verdict.
fi

echo "linkcheck [$ARCH]: $checked symbol(s) checked, $excepted excepted (undefined-ok), $failed unlinkable, out of $total declared"

# ---- did this run check anything at all? ---------------------------------
#
# The exit status below is a function of $failed alone, and $failed can
# only rise for a symbol that was actually compiled and linked -- so a run
# that checked zero symbols reports "no findings" and exits 0.  Same shape
# as tools/asan-build.sh's `0 = 0` (855fdb2): the printed line is honest,
# nothing consumed it.
#
# The floor goes on $checked, not on $total, and that placement is the
# point.  Every declared name is either checked or excepted, and
# excepting is the *deliberate* path: linkcheck_exception() and the
# `undefined-ok:` header marker both carry a written reason, and both are
# reported above.  A run in which every symbol took that path would still
# have verified nothing linkable, which is why the floor is on the
# symbols that were really compiled and linked rather than on the size of
# the input.
if [ "$checked" -eq 0 ]; then
	echo "" >&2
	echo "linkcheck [$ARCH]: FAILED -- 0 symbols were actually compiled and linked" >&2
	echo "linkcheck [$ARCH]: ($total declared, $excepted excepted).  This run verified nothing." >&2
	echo "linkcheck [$ARCH]: a symbol that genuinely cannot be call-site-generated belongs in" >&2
	echo "linkcheck [$ARCH]: linkcheck_exception() or behind an 'undefined-ok:' marker, with a" >&2
	echo "linkcheck [$ARCH]: reason -- not dropped from the run." >&2
	exit 1
fi

if [ "$excepted" -gt 0 ]; then
	echo ""
	echo "excepted (declared, deliberately unimplemented, see the header for the full reason):"
	sort -u "$builddir/exceptions" | sed 's/^/  /'
fi

if [ "$failed" -eq 0 ]; then
	echo "linkcheck [$ARCH]: no findings"
	exit 0
fi

echo ""
echo "unlinkable symbols -- declared in a public header, but a program cannot link a call to them:"
cat "$builddir/failures"
echo "linkcheck [$ARCH]: $failed finding(s); full logs under $builddir/"
[ "$LINKCHECK_STRICT" = 0 ] && exit 0
exit 1
