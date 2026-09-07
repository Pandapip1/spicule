#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check proofs for division, shifts, and representable signed arithmetic."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tools/lint-arithmetic-ub-fixtures"
DIAGNOSTIC = re.compile(
    r"^(.*?):(\d+):(\d+): warning: "
    r"(divisor is not proven nonzero|shift count is not proven in range \[0, \d+\)|"
    r"signed arithmetic result is not proven representable|"
    r"arithmetic contract is not proven: .*); "
    r"origin '(.*)'; context '(.*)'; expression '(.*)'; site '(.*)' "
    r"\[spicule\.(Divisor|ShiftCount|SignedArithmetic|ArithmeticContract)\]$"
)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    checker: str
    context: str
    expression: str
    site: str
    line: int

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return self.path, self.checker, self.context, self.expression, self.site


def relative(name: str) -> str:
    path = pathlib.Path(name)
    if path.is_absolute():
        try:
            return path.relative_to(ROOT).as_posix()
        except ValueError:
            return path.as_posix()
    return path.as_posix()


def parse_log(path: pathlib.Path) -> list[Finding]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if "PLEASE submit a bug report" in text or "clang frontend command failed" in text:
        raise SystemExit(f"lint-arithmetic-ub: analyzer crashed; see {path}")
    findings = []
    for line in text.splitlines():
        match = DIAGNOSTIC.match(line)
        if match:
            findings.append(Finding(relative(match.group(5)), match.group(9),
                                    match.group(6), match.group(7),
                                    f"{match.group(8)} @column {match.group(3)}",
                                    int(match.group(2))))
    return findings


def fixture_test(path: pathlib.Path) -> None:
    expected = set()
    for source in FIXTURES.glob("*.c"):
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            if "arithmetic-ub-expect" in line:
                expected.add((source.relative_to(ROOT).as_posix(), number))
    actual = {(finding.path, finding.line) for finding in parse_log(path)}
    if actual != expected:
        print("lint-arithmetic-ub: fixture self-test failed", file=sys.stderr)
        print(f"  expected: {sorted(expected)}", file=sys.stderr)
        print(f"  actual:   {sorted(actual)}", file=sys.stderr)
        raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", required=True, type=pathlib.Path)
    parser.add_argument("logs", nargs="*", type=pathlib.Path)
    arguments = parser.parse_args()
    fixture_test(arguments.fixtures)

    findings = {finding.key: finding
                for log in arguments.logs for finding in parse_log(log)}
    for finding in sorted(findings.values()):
        obligation = ("nonzero divisor" if finding.checker == "Divisor"
                      else "shift count range" if finding.checker == "ShiftCount"
                      else "declared arithmetic contract" if finding.checker == "ArithmeticContract"
                      else "signed arithmetic range")
        print(f"{finding.path}:{finding.line}: unproved {obligation} in "
              f"{finding.context}: {finding.expression}")
    if findings:
        divisors = sum(finding.checker == "Divisor" for finding in findings.values())
        shifts = sum(finding.checker == "ShiftCount" for finding in findings.values())
        contracts = sum(finding.checker == "ArithmeticContract" for finding in findings.values())
        arithmetic = len(findings) - divisors - shifts - contracts
        print(f"lint-arithmetic-ub: {divisors} unproved divisor(s), "
              f"{shifts} unproved shift count(s), "
              f"{arithmetic} unproved signed arithmetic result(s), "
              f"{contracts} unproved arithmetic contract(s)")
        return 1
    print("lint-arithmetic-ub: no findings (fixtures passed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
