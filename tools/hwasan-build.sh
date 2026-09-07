#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# hwasan-build.sh -- opt-in HWAddressSanitizer build for spicule, staged for
# a future arch/aarch64 target.
#
# HWASan is a memory-error *detector* -- tagged-pointer use-after-free and
# out-of-bounds, the same class ASan finds, at lower overhead -- so unlike
# a pure mitigation it belongs in this tooling on the same "does it find
# bugs" test as ASan/UBSan/CFI.  Its instrumentation is not x86_64-specific
# (clang has shipped an x86_64 "aliasing mode" since clang 9, and this
# script does build src/*.c under it below), but its *runtime* categorically
# needs a kernel that hands out tagged pointers: Linux's tagged-address ABI,
# which is arm64-only (see Documentation/arch/arm64/tagged-address-abi.rst
# in the kernel tree). Every process built this way dies at startup on any
# other architecture and on an arm64 kernel that has not opted in, with
# libclang_rt.hwasan's own message:
#
#   FATAL: HWAddressSanitizer requires a kernel with tagged address ABI.
#
# So this script does not gate on `uname -m`: it builds for real (the
# mechanical file-selection is worth keeping current even though it cannot
# run yet) and then *probes* with one small link+run before spending time
# on the rest. If the probe dies with exactly that message, there is
# nothing this host can tell us, and the script says so plainly and stops
# -- it must never print PASS/FAIL for tests it could not actually run.
# If the probe dies any other way, or a real run reports something, that
# is treated as a genuine result (see the end of this script).
#
# This is not `make asan` with a different -fsanitize=: HWASan does not
# coexist with ASan (both claim the same shadow-memory/interception
# machinery), so it is its own native build from the same mechanical file
# selection as tools/asan-build.sh, not a mode of it.
#
# Usage: tools/hwasan-build.sh
# Env:   SPICULE_CC (default clang), SPICULE_HWASAN_OBJ (default obj/hwasan),
#        SPICULE_ARCH (default x86_64)

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)
CC=${SPICULE_CC:-clang}
OBJ=${SPICULE_HWASAN_OBJ:-$srcdir/obj/hwasan}
ARCH=${SPICULE_ARCH:-x86_64}

if [ ! -f "$srcdir/obj/include/bits/alltypes.h" ]; then
	echo "hwasan: obj/include/bits/alltypes.h missing -- run 'make' first" >&2
	exit 1
fi

# HWASan needs a shared runtime for the same reason ASan does in
# tools/asan-build.sh: with the static runtime, the sanitizer's own
# start-up calls bind to spicule's own definitions (malloc/sysconf/...)
# before spicule is initialised.
SAN="-fsanitize=hwaddress -shared-libsan"
SAN_RT=libclang_rt.hwasan-$ARCH.so
RT=$($CC -print-file-name="$SAN_RT")
case $RT in
*/libclang_rt.hwasan-*.so) ;;
*)	echo "hwasan: $CC has no dynamic HWASan runtime ($SAN_RT);" >&2
	echo "        cannot even build the probe -- treating as not applicable." >&2
	exit 0 ;;
esac
RTDIR=$(dirname "$RT")
# --no-relax: HWASan's tag checks are patched in by the linker at fixed
# offsets from relocations it recognises; a relaxed (converted to a
# shorter form) relocation can move the instruction HWASan expected to
# patch, silently under-instrumenting the binary rather than failing the
# build. See the prior measurement referenced in CONTRIBUTING.md.
LINKFLAGS="-Wl,-rpath,$RTDIR -Wl,--no-relax"

INC="-I$srcdir/src/internal -I$srcdir/obj/include -I$srcdir/include \
     -I$srcdir/arch/$ARCH -I$srcdir/arch/generic"
CFLAGS="$SAN -g -O1 -std=c99 -nostdinc -fno-builtin -fvisibility=hidden \
        -D_XOPEN_SOURCE=700 -D_SPICULE_INTERNAL -D_SPICULE_NATIVE_BUILD $INC"

rm -rf "$OBJ"
mkdir -p "$OBJ/obj" "$OBJ/test"

# Same mechanical file selection as tools/asan-build.sh: kept identical on
# purpose so the two never drift into disagreeing about which src/*.c a
# native build covers.
: > "$OBJ/compiled.txt"
: > "$OBJ/skipped.txt"
for f in $(cd "$srcdir" && find src -name '*.c' | sort); do
	sub=$(echo "$f" | awk -F/ 'NF==4{print $3}')
	if [ -n "$sub" ] && [ "$sub" != "$ARCH" ]; then
		echo "$f  (other architecture)" >> "$OBJ/skipped.txt"
		continue
	fi
	case $f in
	*/teb.c) echo "$f  (reads gs:0x30; __teb() comes from ntstubs.c)" >> "$OBJ/skipped.txt"
	         continue ;;
	esac
	o="$OBJ/obj/$(echo "$f" | tr / _).o"
	# $CFLAGS is a flag list and must word-split.
	# shellcheck disable=SC2086
	if $CC -c $CFLAGS -w "$srcdir/$f" -o "$o" 2> "$o.err"; then
		echo "$f" >> "$OBJ/compiled.txt"
	else
		echo "$f  (see $o.err)" >> "$OBJ/skipped.txt"
		rm -f "$o"
	fi
done
# $CFLAGS is a flag list and must word-split.
# shellcheck disable=SC2086
$CC -c $CFLAGS -w "$srcdir/fuzz/ntstubs.c" -o "$OBJ/ntstubs.o"
# See tools/hwasan-interceptor-shim.c: libclang_rt.hwasan does not export
# the two-underscore __interceptor_{malloc,free,realloc} ntstubs.c calls
# by name (only the mangled three-underscore form), unlike ASan's runtime.
# $CFLAGS is a flag list and must word-split.
# shellcheck disable=SC2086
$CC -c $CFLAGS -w "$srcdir/tools/hwasan-interceptor-shim.c" -o "$OBJ/shim.o"

nsrc=$(wc -l < "$OBJ/compiled.txt")
nskip=$(wc -l < "$OBJ/skipped.txt")
echo "hwasan: $nsrc of $((nsrc + nskip)) src/*.c compiled natively ($nskip skipped, see $OBJ/skipped.txt)"

# Objects, not an archive, and hidden -- same reason as tools/asan-build.sh.
LIBOBJS=$(echo "$OBJ"/obj/*.o)

TINC="-I$srcdir/obj/include -I$srcdir/include -I$srcdir/arch/$ARCH -I$srcdir/arch/generic"

# ---- probe: is the tagged-address ABI even available here? -----------------
#
# test/malloc is small and touches the allocator, which is the part HWASan
# instruments most -- a representative canary without paying for all 11
# tests before knowing whether any of them can run at all.
probe_src="$srcdir/test/malloc.c"
probe_exe="$OBJ/test/probe"
# $SAN/$TINC/$LINKFLAGS/$LIBOBJS are flag and object lists: word-split.
# shellcheck disable=SC2086
if ! $CC $SAN -g -O1 -std=c99 -nostdinc -fno-builtin -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -w \
     $TINC $LINKFLAGS "$probe_src" "$OBJ/ntstubs.o" "$OBJ/shim.o" $LIBOBJS -o "$probe_exe" \
     2> "$OBJ/probe.link.err"; then
	echo "hwasan: probe failed to link -- see $OBJ/probe.link.err" >&2
	exit 1
fi

probe_out=$("$probe_exe" 2>&1) && probe_status=0 || probe_status=$?
if [ "$probe_status" != 0 ] && \
   echo "$probe_out" | grep -q 'FATAL: HWAddressSanitizer requires a kernel with tagged address ABI'; then
	echo "hwasan: NOT APPLICABLE on this architecture/kernel ($ARCH)."
	echo "        $(echo "$probe_out" | grep 'FATAL: HWAddressSanitizer')"
	echo "        HWAddressSanitizer needs Linux's arm64 tagged-address ABI; the"
	echo "        library objects above compiled cleanly ($nsrc of $((nsrc + nskip)))"
	echo "        and are staged for a real run once an arch/aarch64 target with"
	echo "        that ABI exists.  This is not a pass: no test ran."
	exit 0
fi

# The probe did NOT die with the "no tagged address ABI" signature: either
# it is genuinely usable here (a real arm64 kernel with the ABI enabled) or
# something else is wrong.  Either way this is a real result now, not an
# arch gate, so run the rest of the applicable tests and report normally.
echo "hwasan: tagged address ABI available -- running the full applicable suite"

not_native()
{
	case $1 in
	exec)          echo "the simulated file system does not cross execve (fuzz/ntstubs.c)" ;;
	waitpid-overflow) echo "a host wait status carries 8 bits of exit code" ;;
	fork-win|fork-handles-win|process-win) echo "needs NT process cloning: RtlCloneUserProcess is a stub" ;;
	math)          echo "long double is 64-bit on the NT target and 80-bit here" ;;
	strto)         echo "asserts sizeof(long)==4 (LLP64); a native long is 8" ;;
	*)             echo "" ;;
	esac
}

ran=0 passed=0 nolink=0 skipped=0
for t in $(cd "$srcdir" && echo test/*.c); do
	n=$(basename "$t" .c)
	exe="$OBJ/test/$n"
	why=$(not_native "$n")
	if [ -n "$why" ]; then
		skipped=$((skipped + 1))
		echo "  SKIP $n  ($why)"
		continue
	fi
	# $SAN/$TINC/$LINKFLAGS/$LIBOBJS are flag and object lists: word-split.
	# shellcheck disable=SC2086
	if $CC $SAN -g -O1 -std=c99 -nostdinc -fno-builtin -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -w \
	     $TINC $LINKFLAGS "$srcdir/$t" "$OBJ/ntstubs.o" "$OBJ/shim.o" $LIBOBJS -o "$exe" \
	     2> "$exe.link.err"; then
		ran=$((ran + 1))
		if timeout 120 "$exe" > "$exe.out" 2>&1 < /dev/null; then
			passed=$((passed + 1))
			echo "  PASS $n"
		else
			echo "  FAIL $n  (output in $exe.out)"
			sed -n '1,25p' "$exe.out" | sed 's/^/        /'
		fi
	else
		nolink=$((nolink + 1))
		echo "$n: link failed, see $exe.link.err"
	fi
done

echo "hwasan: $passed/$ran tests passed, $skipped not applicable natively, $nolink unlinkable"
[ "$passed" = "$ran" ]
