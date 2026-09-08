#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check for a manual pointer proof axiom restating its own function's parameter.

Parses tools/clang/OwnershipChecker.cpp's OwnParameterAxiomChecker
(spicule.OwnParameterAxiom) diagnostic output -- the opt-in, standing version
of the manual, tree-wide re-audit landed in commit 52522078 ("re-audit of
unsafe_assume_string_terminated() vs withtok()"): a manual
unsafe_assume_pointer_nonnull()/unsafe_assume_string_terminated() axiom whose
argument names the enclosing function's own, unescaped parameter directly is
always a candidate to push out to a withtok(null_terminated)/nonnull
parameter contract instead, regardless of whether spicule.RedundantPointerAxiom
can currently prove the axiom redundant -- that is a separate, path-sensitive
question this script's own sibling (tools/lint-pointer-axiom.py) asks.

This is a suggestion, not a proof that the rewrite is safe: converting a real
call site can cascade into new findings at callers that are not yet proven to
satisfy the stronger, caller-visible contract (src/util/mktemp.c's own
once-attempted, reverted conversion is the standing example). Finding zero
occurrences of this shape is not required for the always-on ownership stage
or the opt-in pointeraxiom stage to pass -- this stage is independent of
both, and is itself opt-in until its own backlog is triaged down.

Shares tools/lint-ownership-fixtures/pointer-safe.c with tools/lint-ownership.py
and tools/lint-pointer-axiom.py -- this script's fixture gate only expects the
lines tagged `ownership-expect: own-parameter-axiom`; every other
`ownership-expect:` tag in those files belongs to one of the other two
scripts' own gates instead.
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
    r"manual axiom restates this function's own parameter; "
    r"consider (.*?) instead; verify no cascade regression before "
    r"converting; origin '(.*)'; context '(.*)'; expression '(.*)'; "
    r"site '(.*)' \[spicule\.OwnParameterAxiom\]$"
)
TAG = "ownership-expect: own-parameter-axiom"


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    suggestion: str
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
        raise SystemExit(f"lint-own-parameter-axiom: analyzer crashed; see {path}")
    result = []
    for line in text.splitlines():
        match = DIAGNOSTIC.match(line)
        if match:
            result.append(Finding(relative(match.group(5)), int(match.group(2)),
                                  match.group(4), match.group(6),
                                  match.group(7), match.group(8)))
    return result


def fixture_test(path: pathlib.Path) -> None:
    expected = set()
    for source in FIXTURES.glob("*.c"):
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            if TAG in line:
                expected.add((source.relative_to(ROOT).as_posix(), number))
    actual = {(finding.path, finding.line) for finding in parse(path)}
    if actual != expected:
        print("lint-own-parameter-axiom: fixture self-test failed", file=sys.stderr)
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
        print(f"{finding.path}:{finding.line}: manual axiom restates this "
              f"function's own parameter in {finding.context}: "
              f"{finding.expression} -- consider {finding.suggestion} instead "
              f"(verify no cascade regression before converting)")
    if findings:
        print(f"lint-own-parameter-axiom: {len(findings)} manual axiom(s) "
              f"restating their own function's parameter")
        return 1
    print("lint-own-parameter-axiom: no findings (fixtures passed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
