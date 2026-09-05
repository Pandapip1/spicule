<!--
SPDX-FileCopyrightText: (C) 2026 Gavin John
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Safe Platform-Independent Complete Unix-Like Environment

A from-scratch C library and POSIX-ish userland that talks to the
operating system directly, with nothing underneath it. On Windows NT
that means ntdll — never kernel32 or any other DLL layered on top of it.
On Linux it means raw syscalls, with no host libc underneath at all. One
source tree covers both.

[![CI](https://github.com/Pandapip1/ebue/actions/workflows/ci.yml/badge.svg)](https://github.com/Pandapip1/ebue/actions/workflows/ci.yml)

## Supported platforms

| Platform | Architectures | Compiler | Coverage |
| --- | --- | --- | --- |
| Windows NT | i386, x86_64, aarch64 | tcc (`{i386,x86_64,arm64}-win32-tcc`) | full: libc, CRT, shell, the whole utility set below; CI runs both architectures under Wine and on real Windows (including Windows-on-ARM for aarch64) |
| Linux | aarch64 | clang | full: libc, CRT, shell, the whole utility set below; CI builds and runs the library's own per-subsystem native suites (`tools/linux-build-*.sh`) |
| Linux | x86_64 | clang | partial: CRT builds and runs, plus the ELF loader (`dlopen`/`dlsym`, `src/dlfcn/linux/plat_dlfcn.c`) under a native proof |
| Linux | i386 | clang | partial: CRT builds and runs |

`./configure --host=<arch>-win32 CC=<arch>-win32-tcc` selects a Windows
build; `./configure --platform=linux CC=clang` selects Linux, with the
architecture guessed from the compiler or set explicitly via
`--host=<arch>-linux`. See `./configure --help` and
[CONTRIBUTING.md](CONTRIBUTING.md) for the full build and test loop.

## Supported Windows versions

<!-- ntlibc-min-ntdll: 6.0 -->
**Windows Vista / Server 2008 (NTDLL 6.0) or newer, for i386, x86_64 and
aarch64 alike.** (aarch64 additionally requires an ARM64 build of
Windows, which did not exist before Windows 10 — that is a fact about
when Microsoft shipped Windows for that architecture at all, not a
separate ntdll floor; the 6.0 figure below is computed the same way,
from the same import list, for all three architectures.)

This is a floor, not a preference. ntlibc imports from `ntdll.dll` and
nothing else, and a static import of a name the running ntdll does not
export is not a call that fails at runtime — the loader refuses the whole
image before any of its code runs. So the minimum supported version is
the maximum, over every import, of the version that first exported it.

Today four imports set it, all used by `fork`/`exec`
(`src/process/nt/plat_process.c`):

| Import | First exported by NTDLL | Reference |
| --- | --- | --- |
| `NtCreateThreadEx` | 6.0 (Vista) | [names60.htm](https://www.geoffchappell.com/studies/windows/win32/ntdll/history/names60.htm) |
| `RtlCloneUserProcess` | 6.0 (Vista) | [names60.htm](https://www.geoffchappell.com/studies/windows/win32/ntdll/history/names60.htm) |
| `RtlCreateProcessParametersEx` | 6.0 (Vista) | [names60.htm](https://www.geoffchappell.com/studies/windows/win32/ntdll/history/names60.htm) |
| `RtlExitUserProcess` | 6.0 (Vista) | [names60.htm](https://www.geoffchappell.com/studies/windows/win32/ntdll/history/names60.htm) |

Until this changed, the floor was Windows 7 (NTDLL 6.1), imposed by
`RtlUTF8ToUnicodeN`/`RtlUnicodeToUTF8N` — the UTF-8 ↔ UTF-16 conversion
every path-taking and string-taking function goes through
(`src/internal/utf.c`), which the great majority of the PE executables
this tree builds — the 80 utilities under `bin/` plus `sh/main.c` — import
directly. `utf.c` converts in-tree now, so it imports neither name, and
the floor dropped to whatever the next-highest import required.

Below Vista the next floor down is Server 2003 SP1
(`RtlDosPathNameToNtPathName_U_WithStatus`, and on i386 the `NtWow64*`
pair), then XP. Replacing the four `fork`/`exec` imports above with
something Server-2003-compatible is not on the table the way the UTF-8
conversions were: `RtlCloneUserProcess` and `NtCreateThreadEx` are the
documented way to create a process/thread from a running one at all, with
no in-tree substitute to hand-roll — so 6.0 is where this floor stays
absent a real replacement for process/thread creation itself.

Every export in [`tools/ntdll.def`](tools/ntdll.def) carries the NTDLL
version it was first exported from, with the sources cited in that
file's header. `tools/lint-minver.sh` (`make minver`) fails if any export
is unannotated, or if the highest annotation stops matching the version
in the marker above — so this section cannot go stale with respect to
what the library actually imports.

Note on NT *behaviour* versus NT *exports*: a few call sites do ask for
things newer than 6.0 (`FileDispositionInformationEx`,
`FileRenameInformationEx`; both Windows 10). Those are not load-time
failures — NT rejects the request and the call site falls back to the
pre-`Ex` information class — so they do not raise the floor.

## Utilities and shell

`bin/` builds 80 standalone command-line programs against the library,
covering most of POSIX's XCU utility set plus a handful of common
non-POSIX ones: text tools (`awk`, `sed`, `ed`, `grep`, `diff`, `patch`,
`m4`, `sort`, `uniq`, `cut`, `paste`, `join`, `tr`, `fold`,
`expand`/`unexpand`, `csplit`, `comm`, `pr`, `wc`, `od`, `cksum`),
filesystem tools (`ls`, `cp`, `mv`, `rm`, `ln`, `find`, `xargs`, `du`,
`df`, `chmod`, `mkdir`, `mkfifo`, `readlink`, `realpath`, `pathchk`,
`dd`, `cmp`, `file`, `pax`, `ar`, `nm`, `strip`), job control (`at`,
`atd`, `batch`, `crond`, `crontab`, `time`, `timeout`), and `mailx`,
`tty`/`stty`/`tput`, `write`/`mesg`, and `man`. `man` is backed by a real
in-tree troff/mdoc formatting engine (`src/util/man.c`, close to 5,000
lines) that interprets man- and mdoc-macro-package source directly,
rather than shelling out to groff.

`src/sh/` is a POSIX shell language engine compiled into the library
itself, not a wrapper around a separate shell: `system()`, `popen()` and
`wordexp()` need shell-language behavior that `cmd.exe` cannot provide,
so the shell has to be part of libc. `sh/main.c` is a thin executable
(`obj/sh/sh.exe`) over that same engine.

## Testing

`test/*.c` (134 files) is the in-tree suite. Every case carries a
disposition — `PASS`, `BUG`, `UNIMPL`, `NA` or `FLAKY` — from one shared
vocabulary, checked in three modes: `make check` (normal), `make
check-pedantic` (fails on a stale disposition) and `make check-strict`
(additionally forbids any remaining `BUG`/`UNIMPL`, and requires every
`FLAKY` case to pass). `tools/test-policy.py` and
`test/test-profiles.tsv` resolve per-case overrides by suite, stable case
name, and selectors on runtime/architecture/capability, so a new
platform starts every case unannotated instead of silently inheriting
another platform's results.

Two external corpora run through that same policy machinery, as pinned
submodules: musl's **libc-test** (`third_party/libc-test`; `make
libc-test`, `-pedantic`, `-strict`) and the **Open POSIX Test Suite**,
vendored inside the pinned **LTP** submodule (`third_party/ltp`; `make
posix-optsrun`). `test/posix-opts-expected.txt` records the Open POSIX
suite's known-bad cases; a case it does not mention is expected to pass.

Beyond functional testing: `make asan` builds the OS-independent source
natively under ASan+UBSan; `make cfi` does the same plus
`-fsanitize=cfi-icall` and LTO; `make hwasan` builds under
HWAddressSanitizer (needs an aarch64 tagged-address ABI, reports N/A
elsewhere); `make tsan` is an opt-in ThreadSanitizer probe. `make fuzz`
runs the libFuzzer harnesses under `fuzz/`; the same harnesses also run,
unmodified, under AFL++ (`tools/afl-fuzz.sh`, `ENGINE=afl` in
`fuzz/Makefile`) as a second, independent fuzzing engine with its own
corpus.

## Static analysis

`tools/lint.sh` runs source-level policy checks as clang analyzer
plugins: 14 checkers under `tools/clang/*Checker.cpp`, covering
allocation/ownership lifetime, pointer provenance, memory-safety
contracts, arithmetic overflow, lock discipline (including lockset race
detection), signal safety, reentrancy, purity, errno discipline,
discarded fallible results, ABI zero-initialization, and totality
(switch/enum exhaustiveness). The ownership/memory-contract checker
backs its extent-bounds and no-wrap side conditions with a real Z3 SMT
query rather than a heuristic, and it requires Z3 to run at all; the
totality and arithmetic-overflow checkers are built the same way but are
not yet part of the default gate below. The project's direction is to
keep migrating the rest of the hand-rolled arithmetic checks onto that
same Z3-backed algebra as it proves out.

`tools/lint.sh` implements 22 such stages in total (the checkers above,
plus compiler warnings, `clang-tidy`, `cppcheck`, `shellcheck`, and a few
source-level policy scripts), each run in its own subshell to its own
log so they execute concurrently. `make lint` runs 18 of them
(`LINT_REQUIRED_STAGES` in the Makefile, kept in sync with
`tools/lint.sh`'s own default set); CI runs that same set as one job per
stage. Four stages are opt-in only, invoked directly
(`tools/lint.sh sizearith totality arithub provenance`) rather than
through `make lint` or CI: `sizearith`, `totality` and `arithub` because
their findings still need triage against the codebase, and `provenance`
because removing `PointerProvenanceChecker.cpp`'s exemption table
surfaced real findings at previously-exempted call sites, moving it to
the same opt-in status until those are triaged too.

## Generated files, the pre-push gate, and dependency updates

See [CONTRIBUTING.md](CONTRIBUTING.md): the platform rules for adding an
ntdll import, `make generated`/`make kaem` and the committed
`*.h.gen`/`boot/kaem/*.kaem` files, `tools/gate.sh`'s pre-push
verification stages, and the Renovate-tracked toolchain pins.
