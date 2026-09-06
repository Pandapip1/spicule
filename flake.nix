# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
{
  description = "ntlibc build and lint tooling";

  # This flake exists to replace tribal knowledge, not to add to it: every
  # package here was pulled directly from the `nix shell nixpkgs#... --command
  # ...` combinations that tools/lint.sh, .github/workflows/ci.yml, and
  # tools/gate.sh already document/require, not guessed at. See the comment
  # above `versionedLlvm18` below for the one nontrivial wrinkle (Debian-style
  # `clang-18`-shaped binary names that nixpkgs does not itself provide), and
  # the comment above `tcc` for the one package with no nixpkgs equivalent at
  # all -- its derivation reproduces .github/actions/setup-tinycc's own
  # clone/patch/build steps instead of an existing nixpkgs combination.

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];

      perSystem = { pkgs, ... }:
        let
          llvm18 = pkgs.llvmPackages_18;

          # The NT/win32 build's actual compiler, reproduced through Nix
          # instead of .github/actions/setup-tinycc's `git clone`/`git
          # apply`/`./configure`/`make` sequence. nixpkgs' own `tinycc`
          # package (pkgs/by-name/ti/tinycc) is NOT a substitute: it pins
          # upstream tinycc.git (repo.or.cz) at f6385c05, 238 commits
          # behind this project's own fork/pin below, and that gap is
          # exactly where upstream grew arm64-win32 support (grischka's
          # "arm64-win32 review: fix problems and pass tests" and Benjamin
          # Oldenburg's "arm64-win32 support: configure & Makefiles", both
          # after f6385c05) -- so nixpkgs' build has no arm64-win32-tcc
          # target at all (only i386-win32-tcc and x86_64-win32-tcc come
          # out of it). It also predates this project's own 5 fork commits
          # implementing -Wl,--delay-all (f1a1e131..89d513f0, PE
          # delay-load imports) and the extra patch below that fixes a bug
          # in that feature -- both of which test/delayall.c (Makefile's
          # delayall.exe target, run across every arch in CI) actually
          # depends on. Confirmed empirically: `nix build nixpkgs#tinycc`
          # succeeds and its i386-win32-tcc/x86_64-win32-tcc do run, but
          # neither the arm64 target nor --delay-all support exists in
          # what it produces.
          tcc = pkgs.stdenv.mkDerivation {
            pname = "ntlibc-tcc";
            # Matches .github/workflows/ci.yml's TINYCC_SHA. Keep this,
            # the `rev`/`hash` below, and the patch below in sync with
            # that file and .github/actions/setup-tinycc/action.yml by
            # hand -- there is no automated link between a GitHub Actions
            # env var and a Nix derivation.
            version = "69eed4d3";

            src = pkgs.fetchFromGitHub {
              owner = "Pandapip1";
              repo = "tinycc";
              rev = "69eed4d346f31dea12d61b99f60298d2f59f66be";
              hash = "sha256-fCfxxlGwvZ6UzWReC+7saiH9lGC6trG5bgETFwiiHlY=";
            };

            # Identical to the heredoc setup-tinycc/action.yml applies at
            # CI time: the pinned delay-import change calls its
            # unsupported-target stub unconditionally, which rejects
            # every ordinary arm64 PE link even when --delay-all was not
            # requested. Keep the rejection for an actual unsupported
            # request, but leave normal arm64 imports alone.
            patches = [
              (pkgs.writeText "tcc-delay-all-arm64.patch" ''
                diff --git a/tccpe.c b/tccpe.c
                --- a/tccpe.c
                +++ b/tccpe.c
                @@ -1307,6 +1307,7 @@ static void pe_build_delay_imports(struct pe_info *pe)
                 static void pe_build_delay_imports(struct pe_info *pe)
                 {
                     TCCState *s1 = pe->s1;
                -    tcc_error_noabort("--delay-all is only supported for the i386 and x86_64 targets");
                +    if (s1->pe_all_delay)
                +        tcc_error_noabort("--delay-all is only supported for the i386 and x86_64 targets");
                 }
                 #endif
              '')
            ];

            # perl (texi2pod.pl) and texinfo (makeinfo) build tcc.1/
            # tcc-doc.html/tcc-doc.info -- part of `make`'s default `all`
            # target (TCCDOCS) alongside the actual cross compilers, and
            # `which` is tinycc's own configure-time tool probe. Mirrors
            # nixpkgs' own tinycc package's nativeBuildInputs, which
            # needs them for the same reason.
            nativeBuildInputs = [ pkgs.perl pkgs.texinfo pkgs.which ];

            postPatch = ''
              patchShebangs texi2pod.pl
            '';

            # tinycc's ./configure is a hand-rolled script, not autoconf
            # -- it does not understand genericBuild's usual
            # --bindir=/--mandir=/etc. injection, so this reproduces
            # setup-tinycc's own `./configure --enable-cross
            # --prefix=...` by hand instead of relying on mkDerivation's
            # default configure flags.
            #
            # The three extra flags below are NOT part of setup-tinycc's
            # own invocation -- CI's ubuntu-24.04 runner has a real
            # /usr/include and a real dynamic linker at a fixed path, so
            # plain `./configure --enable-cross --prefix=...` there
            # already finds both. Nix's non-FHS layout has neither, and
            # without these `make`'s default target fails past every
            # win32 cross target (those already build fine, self-hosted
            # off their own -B../win32/-I../include, same as on CI) once
            # it reaches the *native* Linux `tcc`'s own libtcc1.a: `tcov.c
            # error: include file 'stdio.h' not found`. nixpkgs' own
            # tinycc package (see the comment above this derivation)
            # carries the equivalent of these same three flags for
            # exactly this reason.
            configurePhase = ''
              runHook preConfigure
              ./configure --enable-cross --prefix="$out" \
                --crtprefix="${pkgs.lib.getLib pkgs.stdenv.cc.libc}/lib" \
                --sysincludepaths="{B}/include:${pkgs.lib.getDev pkgs.stdenv.cc.libc}/include" \
                --elfinterp="$(cat "$NIX_CC/nix-support/dynamic-linker")"
              runHook postConfigure
            '';

            enableParallelBuilding = true;

            # No `make test`/`make check`: setup-tinycc doesn't run one
            # either, and ntlibc's own gate.sh/CI matrix is what actually
            # exercises these cross compilers (against real ntlibc
            # sources), not tinycc's own bundled test suite.
            doCheck = false;

            meta = {
              description = "ntlibc's pinned tinycc cross toolchain (i386/x86_64/arm64 win32), built via Nix instead of setup-tinycc's git clone+patch+make";
              mainProgram = "x86_64-win32-tcc";
            };
          };

          # tools/lint.sh's Z3-backed stages (sizearith, totality, arithub,
          # ownership, initproof, fallible, provenance, locks, lockset,
          # abizeroinit, reentrancy, variadic, signals, errno, purity,
          # undefined, unreferenced) all `require_tool clang-18` /
          # `clang++-18` / `llvm-config-18`, and CI's own `analyze` leg
          # pins CLANG_TIDY=clang-tidy-18 (.github/workflows/ci.yml's
          # `lint` job matrix installs exactly those Debian package names
          # from ubuntu-24.04's apt, where llvm-18-dev and libclang-18-dev
          # share one /usr/lib/llvm-18 prefix). Nixpkgs does not name its
          # LLVM 18 binaries that way, and keeps LLVM's and Clang's
          # headers/shared libraries in separate per-package dev/lib
          # outputs rather than one shared prefix -- so besides the name
          # mismatch, `clang++-18 $(llvm-config-18 --cxxflags) ...` as
          # tools/lint.sh writes it can't otherwise find clang/AST/Expr.h,
          # and `find "$(llvm-config-18 --libdir)" -name
          # 'libclang-cpp.so.18*'` (also tools/lint.sh, verbatim) can't find
          # the shared library the built plugin loads into. This lets
          # lint.sh stay exactly as written: a small symlink farm supplies
          # the missing names, clang-unwrapped.dev goes on CPATH for the
          # missing headers below, and this wrapper answers --libdir with
          # clang-unwrapped.lib's directory (where libclang-cpp.so.18
          # actually lives) instead of llvm-config's own.
          #
          # llvmPackages_18.clang (aliased nixpkgs#clang_18), not
          # .clang-unwrapped, is the source for clang-18/clang++-18: it is
          # cc-wrapper-mediated, so -resource-dir and the C/C++ standard
          # library header search path it needs to compile
          # tools/clang/*.cpp (an ordinary hosted C++ program, unlike the
          # -nostdinc freestanding ntlibc sources cppflags_for() feeds it)
          # are already handled the same way they would be by a Debian
          # clang-18 package -- clang-unwrapped on its own knows neither.
          versionedLlvm18 = pkgs.runCommand "llvm18-versioned-names" { } ''
            mkdir -p "$out/bin"
            ln -s ${llvm18.clang}/bin/clang "$out/bin/clang-18"
            ln -s ${llvm18.clang}/bin/clang++ "$out/bin/clang++-18"
            # clang-tidy itself, not clang-tidy-unwrapped's caller wrapper:
            # that wrapper script re-derives its own target name from
            # "$(basename $0)-unwrapped", so invoking it under a symlink
            # named clang-tidy-18 makes it look for a nonexistent
            # clang-tidy-18-unwrapped. The wrapper's only job is injecting
            # Nix's libc/libc++ header search paths, which tools/lint.sh
            # never needs -- cppflags_for() in that script always passes
            # -nostdinc and its own explicit -I set, so going straight to
            # the unwrapped binary changes nothing this project's lint
            # stages rely on.
            ln -s ${llvm18.clang-tools}/bin/clang-tidy-unwrapped "$out/bin/clang-tidy-18"

            cat > "$out/bin/llvm-config-18" <<EOF
#!/bin/sh
# See versionedLlvm18's comment in flake.nix for why --libdir is
# special-cased instead of just symlinking straight to llvm-config.
if [ "\$#" = 1 ] && [ "\$1" = --libdir ]; then
	echo "${llvm18.clang-unwrapped.lib}/lib"
	exit 0
fi
exec ${llvm18.llvm.dev}/bin/llvm-config "\$@"
EOF
            chmod +x "$out/bin/llvm-config-18"
          '';
        in
        {
          devShells.default = pkgs.mkShell {
            packages = [
              # Linux/aarch64 build (tools/lint.sh's own arch table) and the
              # NT/tcc build: both need GNU make.
              pkgs.gnumake

              # The NT/win32 build's actual compiler (i386-win32-tcc,
              # x86_64-win32-tcc, arm64-win32-tcc) -- built by the `tcc`
              # derivation above from this project's own pinned fork, not
              # nixpkgs' `tinycc` package (see that derivation's comment
              # for why that one isn't a substitute). Verified to produce
              # byte-identical .exe/.a output to the hand-built
              # ~/tinycc-install this project's dev machines used before
              # this existed.
              tcc

              # A plain, unversioned clang: stage_warn's pick_cc() falls
              # back to bare `clang`/`gcc` per-arch, the native aarch64
              # Linux build uses it directly, and it is what
              # .github/workflows/ci.yml's `linux-builds` and `asan` jobs
              # install. lld and qemu-user round out cross-build
              # verification (tools/linux-build-*-cross.sh: clang
              # --target=..., -fuse-ld=lld, then run the cross binary under
              # qemu-x86_64/qemu-i386).
              pkgs.clang
              pkgs.lld
              pkgs.qemu-user

              # binutils' `nm` is what tools/lint-unreferenced.sh reads
              # (`nm --undefined-only`) to find which declared/defined
              # functions no test/*.c references; ar/objcopy/etc. ride
              # along in the same closure.
              pkgs.binutils

              # The Z3-backed analyzer-plugin lint stages: a real clang 18 +
              # LLVM 18 (headers/libs, for building tools/clang/*.cpp as
              # analyzer plugins), clang-tidy 18 (the `analyze` stage), and
              # Z3's library and development headers (pkg-config discovers
              # them via z3.pc, which z3.dev carries). clang-unwrapped.dev
              # and .lib supply clang's own AST/Analysis headers and
              # libclang-cpp.so.18, on top of the versioned names from
              # versionedLlvm18 above -- see its comment for why both are
              # needed.
              llvm18.clang-unwrapped.dev
              llvm18.clang-unwrapped.lib
              llvm18.llvm.dev
              llvm18.clang-tools
              versionedLlvm18
              pkgs.pkg-config
              pkgs.z3
              pkgs.z3.dev

              # tools/lint-*.py (every Z3-backed stage's Python-side proof
              # checker) and the pre-commit hook (.githooks/pre-commit,
              # which shells out to tools/test-policy.py and
              # tools/gen-alltypes.sh) both need python3 on PATH; make is
              # already covered above.
              pkgs.python3

              # tools/lint.sh's remaining stages: cppcheck and shellcheck.
              pkgs.cppcheck
              pkgs.shellcheck

              # Pushing changes up.
              pkgs.gh
            ];

            # clang-unwrapped.dev carries clang/AST/Expr.h and friends --
            # the plugin API tools/clang/*.cpp is written against -- which
            # is project-specific and no cc-wrapper adds on its own.
            # clang-unwrapped.lib carries libclang-cpp.so.18, which the
            # built plugins link against and clang-18 dlopen()s at analysis
            # time; it needs to be findable at runtime, not just link time.
            shellHook = ''
              export CPATH="${llvm18.clang-unwrapped.dev}/include''${CPATH:+:$CPATH}"
              export LD_LIBRARY_PATH="${llvm18.clang-unwrapped.lib}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
              echo "ntlibc dev shell: gnumake, tcc (i386/x86_64/arm64-win32-tcc), clang/lld/qemu-user, the clang-18/llvm-18/z3 lint toolchain, python3, cppcheck, shellcheck, gh." >&2
            '';
          };

          packages.tcc = tcc;
        };
    };
}
