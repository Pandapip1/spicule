#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# install-check.sh -- prove that `make install` produces something an
# outside program can actually build and run against.
#
# Every other gate in this tree (`make check`, `make asan`, `tools/lint.sh`)
# builds straight out of the source tree, with -I./include -I./arch/$(ARCH)
# -Iobj/include and -Llib hand-assembled by the Makefile. That is not how a
# real consumer uses spicule: they install it to a prefix and reach it
# through the installed layout, ideally through tools/spicule-tcc's
# installed wrapper (the "compile and link a program against spicule" entry
# point the wrapper's own header comment describes, the same role
# musl-gcc plays for musl). A full-source bootstrap building Make against
# spicule once found two gaps nothing in-tree could see this way: a
# generated include/alloca.h that #define'd alloca to a builtin tcc does
# not have (every call failed to link), and a missing header. Neither
# in-tree gate could ever have caught either, because neither gate ever
# consumes spicule the way that bootstrap did.
#
# This script:
#
#   1. Configures and builds spicule *out of tree*, in a scratch build
#      directory that is not this source tree, using the srcdir= support
#      configure and the Makefile already have (see configure's --srcdir
#      and the Makefile's own srcdir variable) -- the same mechanism a
#      normal autotools-style out-of-tree build uses.
#   2. Installs it with a plain `make install` into a temporary prefix
#      (mktemp -d), never the real one and never DESTDIR-staged under a
#      path that still needs moving: the wrapper bakes an absolute
#      @PREFIX@/@INCDIR@/@LIBDIR@ into itself at build time (see
#      tools/spicule-tcc.in), so the tree has to be *configured* with the
#      temporary prefix, not just DESTDIR-installed under it, or the
#      wrapper it produces points at the wrong (real) prefix and this
#      whole gate would silently test nothing.
#   3. Compiles and links test programs against *only* that prefix, in a
#      scratch working directory that is neither the source tree nor the
#      build directory, using nothing but the installed
#      $PREFIX/bin/spicule-tcc wrapper -- no -I or -L of our own pointing
#      anywhere. That is the whole point: if a source-tree path leaked
#      into the compile line, this would prove nothing. The wrapper is
#      invoked by absolute path from a working directory unrelated to
#      both trees, so nothing about "where we happen to be" can matter
#      either.
#   4. Runs the resulting PE binaries under Wine, not merely links them.
#   5. Cross-checks the installed header set against the same glob the
#      Makefile's own ALL_INCLUDES uses, so a header that make install
#      silently drops (nested dirs included) is caught here rather than
#      by a downstream consumer.
#
# Usage:
#   tools/install-check.sh
#
# Requires an already-run ./configure in the source tree (same as `make
# check`): CC, the target triple and KERNEL32 are read back out of the
# existing config.mak and reused for the out-of-tree configure, so this
# tests whatever arch/configuration the tree is currently set up for.
# Run it again after reconfiguring for the other arch to cover both, the
# same way `make check` itself is run once per arch.

set -u

# `CDPATH=` is an assignment prefixing the `cd`, not a botched assignment.
# shellcheck disable=SC1007
srcdir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

configmak="$srcdir/config.mak"
if [ ! -f "$configmak" ]; then
	echo "install-check.sh: $configmak not found -- run ./configure first" >&2
	exit 1
fi

getvar() {
	sed -n "s/^$1 = //p" "$configmak" | tail -n 1
}

cc=$(getvar CC)
target=$(getvar TARGET)
kernel32=$(getvar KERNEL32)
wine=$(getvar WINE)

if [ -z "$cc" ] || [ -z "$target" ]; then
	echo "install-check.sh: could not read CC/TARGET out of $configmak" >&2
	exit 1
fi

prefix=
build=
work=
# Only ever invoked indirectly, via the trap below -- shellcheck 0.9
# (SC2317, "unreachable") and newer shellcheck (SC2329, "never invoked")
# both flag a trap-only function as dead code.
# shellcheck disable=SC2329,SC2317
cleanup() {
	rc=$?
	[ -n "$prefix" ] && rm -rf "$prefix"
	[ -n "$build" ] && rm -rf "$build"
	[ -n "$work" ] && rm -rf "$work"
	exit "$rc"
}
trap cleanup EXIT INT HUP TERM

prefix=$(mktemp -d) || exit 1
build=$(mktemp -d) || exit 1
work=$(mktemp -d) || exit 1

fail=0
note() { printf '%s\n' "$*"; }
hdr() { printf '\n=== %s ===\n' "$*"; }

hdr "configuring out-of-tree build (srcdir=$srcdir)"
kflag=--disable-kernel32
[ "$kernel32" = yes ] && kflag=--enable-kernel32
if ! ( cd "$build" && "$srcdir/configure" --srcdir="$srcdir" \
		--host="$target" CC="$cc" --prefix="$prefix" \
		--enable-wrapper "$kflag" ); then
	note "FAIL: configure"
	exit 1
fi

hdr "make install (into $prefix)"
njobs=1
command -v nproc >/dev/null 2>&1 && njobs=$(nproc)
if ! ( cd "$build" && make -j"$njobs" install ); then
	note "FAIL: make install"
	exit 1
fi

# --- header completeness: does the prefix have everything the Makefile's
# own ALL_INCLUDES glob says it should? Reimplements that glob (see the
# Makefile's INCLUDES/ARCH_INCLUDES/GENERIC_INCLUDES/GENH) against the
# *source* tree, then checks each expected path exists under $prefix.
arch=$(getvar ARCH)
hdr "header completeness ($arch)"
expected=$(
	cd "$srcdir" && {
		find include -maxdepth 1 -name '*.h'
		find include -mindepth 2 -name '*.h'
		find "arch/$arch/bits" -maxdepth 1 -name '*.h' 2>/dev/null \
			| sed "s#^arch/$arch/bits/#include/bits/#"
		find arch/generic/bits -maxdepth 1 -name '*.h' 2>/dev/null \
			| sed 's#^arch/generic/bits/#include/bits/#'
		echo include/bits/alltypes.h
	} | sort -u
)
missing_hdrs=0
for h in $expected; do
	if [ ! -f "$prefix/$h" ]; then
		note "MISSING: $h not installed"
		missing_hdrs=1
	fi
done
[ "$missing_hdrs" -eq 0 ] && note "all $(printf '%s\n' "$expected" | wc -l) expected headers present"
[ "$missing_hdrs" -ne 0 ] && fail=1

# --- installed libs/tools completeness: everything the wrapper's own
# generated command line (tools/spicule-tcc.in) references by path.
hdr "installed libs/tools"
for f in lib/crt1.o lib/libc.a lib/ntdll.def lib/libm.a lib/librt.a \
	lib/libpthread.a lib/libcrypt.a lib/libutil.a lib/libxnet.a \
	lib/libresolv.a lib/libdl.a bin/spicule-tcc; do
	if [ ! -f "$prefix/$f" ]; then
		note "MISSING: $f not installed"
		fail=1
	fi
done
delay_all=$(getvar DELAY_ALL)
if [ "$delay_all" = yes ] && [ ! -f "$prefix/lib/delayload2.o" ]; then
	note "MISSING: lib/delayload2.o not installed (DELAY_ALL=yes)"
	fail=1
fi
[ "$fail" -eq 0 ] && note "lib/crt1.o, libc.a, ntdll.def, the empty stub libs and bin/spicule-tcc are all present"

wrapper="$prefix/bin/spicule-tcc"
if [ ! -x "$wrapper" ]; then
	note "FAIL: $wrapper missing or not executable, cannot continue"
	exit 1
fi

# --- header-spread compile: every installed *public* header (i.e.
# everything a consumer would #include directly -- not bits/*.h, which
# are private and only ever reached indirectly, through their public
# header's own #include <bits/...>; trying to include e.g. <bits/stdint.h>
# a second time on its own does not use the same __NEED_* protocol its
# public header uses and is not a real usage pattern), in one TU, compiled
# through the wrapper alone (-c, no linking needed to prove the headers
# are self-contained and mutually compatible). Generated from what is
# actually installed under $prefix/include, not from the source tree, so
# an extra or missing public header shows up here too.
hdr "compiling a program that includes every installed public header"
allheaders="$work/allheaders.c"
: > "$allheaders"
( cd "$prefix/include" && find . -name '*.h' -not -path './bits/*' | sed 's#^\./##' | sort ) |
while read -r h; do echo "#include <$h>"; done >> "$allheaders"
echo 'int all_headers_compiled(void) { return 0; }' >> "$allheaders"

rundir="$work/rundir"
mkdir -p "$rundir"
if ! ( cd "$rundir" && "$wrapper" -c -o allheaders.o "$allheaders" ); then
	note "FAIL: compiling all installed headers together"
	fail=1
else
	note "OK: $(grep -c '^#include' "$allheaders") headers compile together"
fi

# --- broad API-surface program: stdio, string, stdlib conversions, time,
# a directory read, alloca, malloc/free, qsort. Breadth is the point --
# depth is already test/'s job. Built and *run*, not just linked, under
# Wine, invoked from $rundir (neither $srcdir nor $build) using the
# wrapper's absolute path, with no -I/-L of our own: everything the
# compile needs comes from the wrapper alone.
broad="$work/broad.c"
cat > "$broad" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <alloca.h>

static int intcmp(const void *a, const void *b)
{
	int ia = *(const int *)a, ib = *(const int *)b;
	return (ia > ib) - (ia < ib);
}

int main(void)
{
	char *stackbuf = alloca(64);
	int nums[6] = { 6, 2, 9, 1, 5, 3 };
	char *heapbuf;
	time_t now;
	struct tm *tm;
	char timebuf[64];
	DIR *d;
	int i, ok = 1;

	strcpy(stackbuf, "install-check");
	if (strcmp(stackbuf, "install-check") != 0)
		ok = 0;

	if (atoi("123") != 123 || strtol("456", NULL, 10) != 456)
		ok = 0;
	if (strtod("1.5", NULL) != 1.5)
		ok = 0;

	qsort(nums, 6, sizeof(nums[0]), intcmp);
	for (i = 1; i < 6; i++)
		if (nums[i - 1] > nums[i])
			ok = 0;

	heapbuf = malloc(32);
	if (!heapbuf)
		ok = 0;
	else {
		strcpy(heapbuf, "heap");
		if (strcmp(heapbuf, "heap") != 0)
			ok = 0;
		free(heapbuf);
	}

	now = time(NULL);
	if (now == (time_t)-1)
		ok = 0;
	tm = localtime(&now);
	if (!tm || strftime(timebuf, sizeof(timebuf), "%Y", tm) == 0)
		ok = 0;

	d = opendir(".");
	if (!d)
		ok = 0;
	else {
		while (readdir(d))
			;
		closedir(d);
	}

	printf("install-check: %s\n", ok ? "PASS" : "FAIL");
	return ok ? 0 : 1;
}
EOF

hdr "compiling + linking the broad API-surface program"
if ! ( cd "$rundir" && "$wrapper" -o broad.exe "$broad" ); then
	note "FAIL: compiling/linking broad.c"
	fail=1
else
	note "OK: link succeeded"

	# Defense in depth: nothing about the compile above should ever have
	# been able to see $srcdir or $build (the wrapper's own command line
	# never mentions them -- see tools/spicule-tcc.in), but confirm it,
	# rather than merely asserting it in a comment.
	if command -v strings >/dev/null 2>&1 &&
		strings "$rundir/broad.exe" | grep -qF -e "$srcdir" -e "$build"; then
		note "FAIL: source-tree or build-dir path leaked into broad.exe"
		fail=1
	fi

	if [ -z "$wine" ]; then
		note "SKIP: no wine configured, cannot run broad.exe"
	else
		hdr "running broad.exe under Wine"
		out=$(cd "$rundir" && WINEDEBUG=-all WINEDLLOVERRIDES=winedbg.exe=d \
			"$wine" ./broad.exe 2>&1 </dev/null)
		rc=$?
		printf '%s\n' "$out" | sed 's/^/    /'
		if [ "$rc" -eq 0 ]; then
			note "PASS broad.exe"
		else
			note "FAIL broad.exe (rc=$rc)"
			fail=1
		fi
	fi
fi

# --- the wrapper must work from a directory other than the one it was
# invoked from above, too: exercise it again from $prefix itself (a third,
# distinct directory from $srcdir/$build/$rundir).
hdr "wrapper from a third, unrelated working directory"
if ! ( cd "$prefix" && "$wrapper" -c -o "$work/fromelsewhere.o" "$broad" ); then
	note "FAIL: wrapper did not work when invoked from \$prefix"
	fail=1
else
	note "OK: wrapper works from another directory"
fi

hdr "summary"
if [ "$fail" -eq 0 ]; then
	note "install-check: all checks passed ($arch, $target, $cc)"
else
	note "install-check: FAILURES ABOVE ($arch, $target, $cc)"
fi
exit $fail
