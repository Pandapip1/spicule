#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check that every manual pointer proof axiom is still load-bearing.

Parses tools/clang/OwnershipChecker.cpp's RedundantPointerAxiomChecker
(spicule.RedundantPointerAxiom) diagnostic output -- the opt-in self-audit of
src/internal/ownership_stubs.h's __ownership_pointer_nonnull() and
__ownership_string_terminated() leaf axioms, the direct counterpart of the
"manual memory proof axiom is redundant / can be narrowed" audit
spicule.MemoryContract already performs on the span axioms.

spicule.ValidPointer must be enabled alongside spicule.RedundantPointerAxiom
in the same clang -analyzer-checker= invocation: every nonnull constraint the
audit reads is one ValidPointerChecker's own checkBeginFunction/checkPostCall/
checkPostStmt narrowed, so run alone it has nothing to work from.

Two verdicts, exactly as in the memory-contract audit:

  redundant     the fact is established on every path into the call by the
                argument's own declaration or expression shape, so the axiom
                proves nothing and the call is dead scaffolding.
  narrowable    the fact holds on the path reaching the call, but only
                because of a guard or other path constraint, which says
                nothing about the paths that do not reach it -- worth a look,
                not automatically removable.

Shares tools/lint-ownership-fixtures/pointer-safe.c with
tools/lint-ownership.py -- this script's fixture gate only expects the lines
tagged `ownership-expect: pointer-axiom-redundant` and
`ownership-expect: pointer-axiom-narrowable`, the two shapes specific to this
checker; every other `ownership-expect:` tag in those files belongs to
tools/lint-ownership.py's own gate instead.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tools/lint-ownership-fixtures"
DIAGNOSTIC = re.compile(
    r"^(.*?):(\d+):(\d+): warning: "
    r"manual pointer proof axiom (is redundant|can be narrowed); "
    r"origin '(.*)'; context '(.*)'; "
    r"expression '(.*)'; site '(.*)' "
    r"\[spicule\.RedundantPointerAxiom\]$"
)
VERDICT = {"is redundant": "redundant", "can be narrowed": "narrowable"}


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    verdict: str
    context: str
    expression: str
    site: str

    @property
    def key(self) -> tuple[str, str, str, str]:
        return self.path, self.context, self.expression, self.site


def relative(name: str) -> str:
    path = pathlib.Path(name)
    if path.is_absolute():
        try:
            return path.relative_to(ROOT).as_posix()
        except ValueError:
            pass
    return path.as_posix()


def parse(path: pathlib.Path) -> list[Finding]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if "PLEASE submit a bug report" in text or "clang frontend command failed" in text:
        raise SystemExit(f"lint-pointer-axiom: analyzer crashed; see {path}")
    result = []
    for line in text.splitlines():
        match = DIAGNOSTIC.match(line)
        if match:
            result.append(Finding(relative(match.group(5)), int(match.group(2)),
                                  VERDICT[match.group(4)], match.group(6),
                                  match.group(7), match.group(8)))
    return result


def fixture_test(path: pathlib.Path) -> None:
    expected = set()
    for source in FIXTURES.glob("*.c"):
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            for verdict in VERDICT.values():
                if f"ownership-expect: pointer-axiom-{verdict}" in line:
                    expected.add((source.relative_to(ROOT).as_posix(), number,
                                  verdict))
    actual = {(finding.path, finding.line, finding.verdict)
              for finding in parse(path)}
    if actual != expected:
        print("lint-pointer-axiom: fixture self-test failed", file=sys.stderr)
        print(f"  expected: {sorted(expected)}", file=sys.stderr)
        print(f"  actual:   {sorted(actual)}", file=sys.stderr)
        raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", required=True, type=pathlib.Path)
    parser.add_argument("logs", nargs="*", type=pathlib.Path)
    args = parser.parse_args()
    fixture_test(args.fixtures)

    findings = {finding.key: finding for log in args.logs for finding in parse(log)}
    for finding in sorted(findings.values()):
        wording = ("is redundant" if finding.verdict == "redundant"
                   else "can be narrowed")
        print(f"{finding.path}:{finding.line}: manual pointer proof axiom "
              f"{wording} in {finding.context}: {finding.expression}")
    if findings:
        redundant = sum(finding.verdict == "redundant"
                        for finding in findings.values())
        print(f"lint-pointer-axiom: {redundant} redundant and "
              f"{len(findings) - redundant} narrowable manual pointer proof "
              f"axiom(s)")
        return 1
    print("lint-pointer-axiom: no findings (fixtures passed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
