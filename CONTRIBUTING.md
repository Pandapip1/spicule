<!--
SPDX-FileCopyrightText: (C) 2026 Gavin John
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Contributing to ntlibc

## Platform rules

ntlibc talks to Windows NT through ntdll's `Nt*` and `Rtl*` interfaces.
Use ntdll whenever it can provide the behavior. Calls into kernel32 or any
other higher-level DLL require both:

- an `#ifdef NTLIBC_USE_KERNEL32` guard; and
- a usable ntdll-only fallback.

The default configuration is `--disable-kernel32`. The guarded build exists
for the few facilities with no ntdll equivalent, such as console control
handlers, and is covered by the x86_64 kernel32 CI leg. It also carries the
fallbacks for facilities that do have an ntdll path but not on every host:
console mode and screen-buffer size go through the console driver directly
(`src/internal/condrv.h`) and reach for kernel32 only when that protocol is
not answered.

The shell under `src/sh/` is part of libc because `system()`, `popen()` and
`wordexp()` require shell-language behavior that `cmd.exe` cannot provide.
`sh/main.c` is a thin executable wrapper over the same in-process engine.

## Adding an ntdll import raises the minimum Windows version

`tools/ntdll.def` is the complete list of what ntlibc asks of the
operating system — ntdll is the only DLL a default build imports from at
all (see the section above). It is therefore also the complete statement
of which Windows versions ntlibc can run on, and adding a line to it is
not a free action.

The reason is that these are *static* imports. A static import of a name
the running ntdll does not export does not produce a call that fails: the
loader refuses the whole image, before any of its code runs. One import
that is newer than the machine bricks every program built against the
library, whether or not it ever calls the function. So the minimum
supported version is the **maximum**, over every import, of the version
that first exported it — and one careless line here raises it for
everyone.

That is why every export in `tools/ntdll.def` carries the NTDLL version
it was first exported from, sourced to Geoff Chappell's per-release
"exports added for NTDLL x.y" lists (cited page-by-page in that file's
own header). When you add an import:

1. Look the name up on those pages and annotate it. Do not guess from the
   name, and do not infer from the fact that it exists in Wine or in
   ReactOS — neither is evidence about Microsoft's ntdll. (Wine's ntdll
   has no version gates at all, which is exactly why the Windows 7 floor
   went unnoticed in this tree for as long as it did.)
2. Run `make minver`. It fails if the annotation is missing, or if the
   new maximum no longer matches the floor declared in `README.md`.
3. If it does raise the floor, that is a decision, not a build error.
   Either use an older equivalent (`RtlCreateProcessParameters` rather
   than the Vista `...Ex`, say), or raise the README floor deliberately
   and update the prose there.

Requesting something newer than the floor at *runtime* is a different
matter and is fine, because it can fail softly: `src/unistd/unlink.c`
asks for `FileDispositionInformationEx` (Windows 10) and falls back to
`FileDispositionInformation` on `STATUS_INVALID_PARAMETER` /
`STATUS_NOT_SUPPORTED`; `src/stdio/misc.c` does the same for
`FileRenameInformationEx`. An information class, an FSCTL or an
`NtCreateFile` flag can be probed that way. An import cannot, which is
the whole distinction.

### Probe, do not ask the version

When behavior differs between NT releases, **call the thing and read the
failure status**. A probe stays correct on platforms nobody here has heard
of; a version test is only as good as the table of versions behind it, and
it silently mis-serves anything not in that table.

Branching on `PEB.OSMajorVersion` is reserved for divergences with all
three of these properties:

1. two releases read the *same* request buffer with different layouts;
2. the buffer carries **no discriminator** — no version field, no length,
   nothing in the bytes that says which layout is meant; and
3. handing either side the wrong layout **succeeds**, so there is no
   failure for a probe to learn from.

(3) is the binding condition. If the wrong guess returns an error, probe.

The one instance today is AFD's socket-creation extended attribute — NT
4/5's 12-byte `AFD_CREATE_PACKET` against NT 6+'s 24-byte
`AFD_OPEN_PACKET`. See `src/internal/ntversion.c` for the mechanism and
`src/internal/afd.h`'s socket-creation banner for that case in full.

Use `__nt_version_at_least(major, minor)` from `src/internal/libc.h`; do
not read the PEB fields at a call site. It is cached — the PEB's copy does
not change for the life of the process.

This is **not** a statement about the minimum supported Windows version.
That floor is set by the ntdll imports in `tools/ntdll.def`; a platform can
satisfy it while reporting an older
kernel version (ReactOS does, exporting `RtlUTF8ToUnicodeN` and
`RtlUnicodeToUTF8N` while reporting 5.2).

## Source conventions

- Add an SPDX copyright and licence header to every new file. CI runs
  [REUSE](https://reuse.software/).
- Comments should explain platform constraints, observed behavior or a
  non-obvious tradeoff, rather than narrating the code.
- Keep public headers independently usable. `make hygiene` checks every
  header for both supported architectures.
- Generated `*.h.gen` and `boot/kaem/*.kaem` files are committed. Run
  `make generated` after changing their inputs.
- Attribute LLM assistance with `Assisted-by:`, never `Co-authored-by:`.
  This is a deliberate override, not a typo: the Claude Code harness tells
  every session to use `Co-Authored-By:`, so the wrong trailer is the one
  an agent writes without deciding to. Leave it alone if you see it —
  correcting it back is the failure this note exists to prevent.

## Build and test

The normal x86_64 loop is:

```sh
./configure --host=x86_64-win32 CC=x86_64-win32-tcc
make -j4
make -j4 check
```

Test dispositions have one vocabulary everywhere:

| disposition | normal | pedantic | strict |
|---|---|---|---|
| `PASS` | must compile and pass | same | same |
| `BUG` | skipped | must compile and fail | disallowed (after the same probe) |
| `UNIMPL` | skipped | must fail compilation or linking | disallowed (after the same probe) |
| `NA` | skipped for its recorded reason | same | same |
| `FLAKY` | run; pass or failure is recorded | same | must pass |

Pedantic mode is a ratchet: it fails when a disposition has gone stale, not
merely because a known bug exists. Strict mode includes every pedantic check
and additionally requires that no `BUG` or `UNIMPL` disposition remain and
that every `FLAKY` case pass. Source-level cases use
`NTLIBC_TEST(DISPOSITION, stable_case_name)` and are generated as independent
translation units when probed, so one case cannot hide another compile result.

```sh
make check-pedantic
make check-strict
python3 tools/test-policy.py list
```

The same mode suffixes apply to imported suites, for example
`make libc-test-pedantic` and `make libc-test-strict`. Profile-specific
overrides live in `test/test-profiles.tsv`; they are keyed by suite and stable
case name, so libc-test and Open POSIX use the same resolver as in-tree cases.
Selectors may constrain `runtime`, `target_arch`, `host_arch`, `wow64`,
`kernel32`, or a named `capability.*`. The most-specific matching rule wins;
equal-specificity matches are rejected as ambiguous. Imported baselines claim
only the profile in which they were measured, so a new platform fails as
unannotated instead of inheriting Wine/x86_64 results by accident.
Pass runner capabilities as whitespace-separated selectors when needed. The
same `TEST_PROFILE` reaches the in-tree, libc-test, and Open POSIX policy
resolvers; for example `make check-pedantic TEST_PROFILE="capability.symlink=no
capability.console=no"` describes the stock headless Wine CI environment.

Use `--host=i386-win32 CC=i386-win32-tcc` for i386. If guarded kernel32
code changed, run `make check-kernel32`; it cleans and rebuilds before and
after the kernel32-enabled check so configuration-dependent objects cannot
be reused accidentally.

Useful focused checks are:

```sh
make lint          # warnings, analyzers and source-level policy checks
make hygiene       # public-header isolation
make linkcheck     # declarations, definitions and PE import/header checks
make asan          # native AddressSanitizer and UBSan suite
make cfi           # ASan/UBSan plus indirect-call CFI and LTO
make hwasan        # HWASan build; N/A without the tagged-address ABI
make tsan          # opt-in native data-race probe
make fuzz          # native libFuzzer harnesses, 60 seconds each
make libc-test     # musl libc-test corpus under Wine
make posix-optsrun # Open POSIX suite through the shared policy
make install-check # build and run against an installed prefix only
```

No suite writes a generated report. Every runner prints its per-case
result to stdout, so the run log is the record; there is nothing to
commit, diff, regenerate in a hook, or keep a merge driver for.

## The pre-push gate

`tools/gate.sh` runs the complete local verification set with independent
stages in isolated copies of the working tree:

```sh
tools/gate.sh
tools/gate.sh check-x86_64 lint-plain
tools/gate.sh --list
```

Each stage writes a separate log and result file. A requested stage that
does not report is a failure, so a killed worker cannot disappear into a
green summary.

Concurrency is bounded by two settings:

| variable | default | meaning |
|---|---:|---|
| `GATE_STAGE_CONCURRENCY` | 4 | stages allowed to run at once (`0` is unlimited) |
| `GATE_MAKE_JOBS` | 3 | workers allowed inside each stage |

The gate passes the second value to the subordinate runners as well as to
`make`; this keeps the actual bound close to their product. Override either
setting for a dedicated build machine. `GATE_WINE` selects an alternate
Wine binary for the two project-suite stages.

## Verifying a measurement

A gate is only worth its reputation if a pass means what it appears to. These
rules exist because each has been violated here, and each time the result was
a green check that measured something other than what it claimed.

**Oracles and stimuli are orthogonal axes.** Adding a third environment buys
nothing on a stimulus that cannot discriminate. Before reaching for another
oracle, ask whether the probe you have could express the disagreement at all:
a one-element array cannot exercise a stride, and a device-free test emits the
same bytes whether or not the device would have agreed. A dead stimulus need
not look degenerate: a reproducer in the Wine fork-emulation work reportedly
delivered 382,791 `SIGUSR1`s while meeting the `INVALID_PARAMETER` condition
it was hunting zero times, and hung at 1/1 — a large, busy, wholly plausible
number measuring something other than the thing under test, which would have
been filed as a successful run had its exit code been trusted. That count is
recorded from the Wine tree, not reproduced here. Vary the stimulus first; it
is usually the cheaper axis and always the one that decides whether the other
is worth anything.

**Agreement between non-independent sources measures the sharing, not the
fact.** Two consumers of one header agree at any value it defines. A stub
written to return what the code under test asserts confirms only that both
were written by the same hand. An expected value derived from the
implementation cannot contradict it. Say what would make your sources
disagree; if nothing would, you have one measurement wearing several hats —
and cross-oracle agreement on an under-powered stimulus is *worse* than a
single measurement, because it retires the question.

**Measure expected values; never derive them.** A fence whose expectation was
computed from the code it fences will certify whatever that code does,
including breaking it. If the apparatus cannot carry the evidence — a spawned
child's file that never reaches the parent, a runner with no console — measure
*that* first and skip honestly, rather than letting a zero stand for both "no
effect" and "no channel".

**The same applies to the reason you were given for the work.** A premise that
arrives as the justification for a task is the one least likely to be audited,
because auditing it questions whether the task exists. Two instances from a
single evening, both stated confidently and both false: a stride was briefed
as a live `select()` defect when the shipped code issues one handle per ioctl
and could not reach it; and a rewrite was briefed against a document, by line
number, that had been deleted six hours earlier. Neither survived one command.
Check the premise before the work, not after it fails.

**Number your checks and print the total.** Emit one line per check with an
incrementing index, and a final `CHECKS EXECUTED=n PASSED=n FAILED=n`. A case
that silently did not run then shows up twice — as a gap in the numbering and
as a lower total — instead of as silence. `tools/run-tests.py` prints stdout
only for non-`PASS` outcomes, so a passing probe's numbers are otherwise never
seen. Prefer expectations computed from the run itself (a handle this process
opened) over frozen constants: a test that would still pass with its
expectations stale is not testing what it names.

**A zero result cannot tell "all failed" from "never ran".** `make asan`
reports `0/74 passed` on this machine: no test ran at all. Every ASan binary
aborts at startup with `AddressSanitizer failed to allocate 0xdfff0001000
bytes ... ReserveShadowMemoryRange failed (errno: 12)`, because Linux's
`do_mmap()` honours `MAP_NORESERVE` only when `sysctl_overcommit_memory !=
OVERCOMMIT_NEVER`; under `vm.overcommit_memory=2` — permanent here, a
maintainer's decision rather than a transient fault — the ~15 TB shadow
reservation is charged against `CommitLimit` and refused. That was read as 74
failures during a review, and the misreading costs in a specific direction:
"N failures" sends you to debug the code, "the harness never started" sends
you to fix the harness. `make lint` exits 2 for a different cause with the
same shape — clang-tidy, cppcheck and shellcheck are absent here — and also
means unknown, not fail. CI's runners use default overcommit, so ASan does run
there and remains the authority for memory-safety findings; a local `make
asan` licenses no claim about a heap overflow either way. `CHECKS EXECUTED=0`
is what separates the two readings, which is why the previous rule's total is
worth emitting unconditionally rather than only where a skip is anticipated: a
check that passes without testing anything and a suite that never starts are
one phenomenon — the harness reporting on itself rather than on its subject —
and three instances turned up across three projects in one day.

**Ask "true on which version?"** before recording a platform fact. Wine
implements the shapes it implements; absence there is not evidence about NT,
and a behaviour shared by both may be true only of one era. The three
`windows-test` legs are one Windows build wearing three labels — they vary the
artifact architecture, not the operating system — so agreement across them is
one observation, not three.

**Verify the stimulus actually varied.** A parameter silently rounded or
ignored looks like success while repeating the run you already had. Check that
the thing you changed reached the thing you were testing.

**A result taken under load is not evidence — re-measure quiet.** When the
machine is oversubscribed the suites report contention as `TIMEOUT`, which is
indistinguishable from a hang. Record the load average alongside any gate
result; re-run a red stage individually before believing it; and verify an
artifact by content (hash it) rather than assuming it survived. A rule that
only tells you to doubt produces paralysis — the recovery action is the rule.

## Sanitizers and fuzzing

`make asan` and `make fuzz` build the OS-independent library code natively
with clang. They complement rather than replace the PE/Wine and real-Windows
tests: native stubs cannot validate ntdll, WOW64 or console behavior.

The fuzz corpus defaults to `obj/fuzzcorpus/<harness>/`. Common commands:

```sh
make fuzz FUZZ_TIME=300
FUZZ_JOBS=4 tools/fuzz.sh 60
tools/fuzz.sh 60 strtod printf
tools/fuzz.sh --repro /absolute/path/to/crash-input strtod
```

`FUZZ_JOBS` shards harnesses across workers. The default is one for a
developer invocation; CI sets it to the runner's CPU count. A finding exits
non-zero and leaves its input under the harness's `crashes/` directory.
Promote durable reproducers into the matching `test/*.c` file.

The same `fuzz/fuzz_*.c` harnesses also run under AFL++, a second and
independent fuzzing engine (`ENGINE=afl` in `fuzz/Makefile`, driven by
`tools/afl-fuzz.sh`) -- no harness source changes needed, since every one
already defines only `LLVMFuzzerTestOneInput()`. Requires `afl++`
(`apt-get install afl++` on Debian/Ubuntu; CI installs it the same way).
AFL++'s own runtime collides with several of ntlibc's own strong symbols
the same way `stat()` used to for libFuzzer -- see `fuzz/aflshim.c` for
which ones and why. Common commands mirror the libFuzzer ones above:

```sh
make -C fuzz ENGINE=afl
FUZZ_JOBS=4 tools/afl-fuzz.sh 60
tools/afl-fuzz.sh 60 strtod printf
tools/afl-fuzz.sh --repro /absolute/path/to/crash-input strtod
```

Its corpus defaults to `obj/aflcorpus/<harness>/default/`, in afl-fuzz's
own layout, and is a separate tree from libFuzzer's: the two engines find
different things at different rates, and neither corpus is a subset of
the other's format.

Three additional opt-in detectors sit beyond the default loop. `make cfi`
adds clang's `cfi-icall` check and LTO to the ASan/UBSan build; it is separate
because LTO materially increases every test link. `make hwasan` builds the
native sources under HWAddressSanitizer and reports N/A unless the host has
the tagged-address ABI its runtime requires. `make tsan` drives selected
library calls from two host threads and fails on unsuppressed races. These
are detectors, not shipping hardening flags; SafeStack and ShadowCallStack
remain out of scope because they mitigate corruption without reporting it.

## CI structure

The workflows deliberately keep different schedules and meanings separate:

- `ci.yml` runs deterministic push/PR gates: both architectures under Wine,
  the x86_64 kernel32 configuration, the same binaries on real Windows,
  libc-test, the Open POSIX suite, linkcheck, header hygiene, lint,
  sanitizers and REUSE.
- `fuzz.yml` runs a short corpus-backed net on pushes to main and a longer
  corpus-writing scheduled search, as two jobs (`fuzz` for libFuzzer,
  `afl-fuzz` for AFL++) over the same harnesses with separate corpora.
- `ltp-pin-drift.yml` reports how far the pinned LTP submodule has drifted
  from upstream. It builds nothing: the suite itself is adjudicated on every
  push by `ci.yml`, and drift is the one thing a per-push job cannot see.

`.github/actions/setup-tinycc/action.yml` is the single implementation of
the pinned toolchain cache/restore/build setup shared by CI workflows. The
toolchain revision remains explicit in each workflow using it so Renovate
can update and review the pin. `.github/actions/setup-wine/action.yml` is
the same idea for the jobs that execute PE files: one definition rather
than a copy per job, so the Wine-executing legs cannot drift apart in what
they install.

Wine and real Windows both execute the PE files through `tools/run-tests.py`.
It checks the artifact layout, refuses a zero-test run, isolates working
directories, serializes process-sensitive cases, and reports exit 77 as `NA`
rather than treating an environment-limited test as a pass.

## Generated build files

`tools/gen-alltypes.sh` expands the small `*.h.in` type descriptions into
the committed `*.h.gen` files. `tools/gen-kaem.sh` derives the kaem
bootstrap recipes from the Makefile's source lists -- one per platform+arch
pair it knows how to generate for (today: `nt` x `{i386,x86_64,aarch64}`,
named `boot/kaem/build-nt-{i386,x86_64,aarch64}.kaem`, and `linux` x
`{aarch64}`, named `boot/kaem/build-linux-aarch64.kaem`; see its own header
for why the filename carries both axes, and for the real, disclosed
differences between the two platforms' recipes -- a different compiler and
archiver, a second crt object for the real ELF entry point, and the real
`-fno-stack-protector -mno-outline-atomics` flags). `make kaem`/`make
generated` regenerate every platform+arch pair, not just the default
(`nt`). Use:

```sh
make generated
git diff -- 'arch/*/bits/*.h.gen' 'include/*.h.gen' boot/kaem/
```

`./configure` installs `.githooks/pre-commit`, which checks both generated
families plus staged conflict markers. It also registers the
`ntlibc-kaem` merge driver for every kaem file. If configure has not run
in a checkout, install these manually:

```sh
git config core.hooksPath .githooks
git config merge.ntlibc-kaem.driver 'tools/merge-kaem.sh %O %A %B %P'
```

The merge driver handles independent source-list insertions and archive
member additions. It leaves unfamiliar conflicts for a human; after any
manual resolution, run `make kaem` and stage every generated file.

## Dependency updates

Renovate tracks GitHub Actions and the pinned tinycc commit. Nothing is
auto-merged. When tinycc moves, validate both architectures, generated-file
drift and the real-Windows jobs before merging. Keep every workflow's
`TINYCC_SHA` identical so they share one cache entry and one compiler claim.
