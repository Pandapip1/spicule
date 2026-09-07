#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check __attribute__((pure)) eligibility and disprove false pure claims.

Two directions, reported separately: a "false claim" finding is a real
correctness bug against a function already marked __attribute__((pure)) in
this tree today -- a wrong pure claim licenses the compiler to eliminate,
reorder, or coalesce calls the program actually depends on. A "candidate"
finding is a function that is not marked pure but structurally qualifies;
these are reported for a human to spot-check, not applied automatically and
are advisory rather than a failed proof.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tools/lint-purity-fixtures"
DIAGNOSTIC = re.compile(
    r"^(.*?):(\d+):(\d+): warning: "
    r"(already-declared pure function touches errno|"
    r"already-declared pure function writes through a pointer|"
    r"already-declared pure function writes to global or static state|"
    r"already-declared pure function reads mutable global or static state|"
    r"already-declared pure function reads through a pointer of unproven provenance|"
    r"already-declared pure function performs I/O or a syscall|"
    r"already-declared pure function acquires or releases a lock|"
    r"already-declared pure function calls .+, which is not proven pure \(.*\)|"
    r"already-declared pure function calls through an unresolved function pointer|"
    r"already-declared pure function accesses volatile state|"
    r"already-declared pure function contains inline assembly|"
    r"already-declared pure function has no definition visible in this translation unit|"
    r"function has no proven side effects and could be declared __attribute__\(\(pure\)\)); "
    r"origin '(.*)'; context '(.*)'; expression '(.*)' \[spicule\.Purity\]$"
)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    kind: str
    reason: str
    context: str
    expression: str
    line: int

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return self.path, self.kind, self.reason, self.context, self.expression


def relative(name: str) -> str:
    path = pathlib.Path(name)
    if path.is_absolute():
        try:
            return path.relative_to(ROOT).as_posix()
        except ValueError:
            pass
    return path.as_posix()


def classify(reason: str) -> str:
    return "false-claim" if reason.startswith("already-declared pure function") else "candidate"


def parse(path: pathlib.Path) -> list[Finding]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if "PLEASE submit a bug report" in text or "clang frontend command failed" in text:
        raise SystemExit(f"lint-purity: analyzer crashed; see {path}")
    result = []
    for line in text.splitlines():
        match = DIAGNOSTIC.match(line)
        if match:
            reason = match.group(4)
            result.append(Finding(relative(match.group(5)), classify(reason), reason,
                                  match.group(6), match.group(7), int(match.group(2))))
    return result


def check_fixtures(path: pathlib.Path) -> None:
    expected = {(source.relative_to(ROOT).as_posix(), number)
                for source in FIXTURES.glob("*.c")
                for number, line in enumerate(source.read_text().splitlines(), 1)
                if "purity-expect" in line}
    actual = {(finding.path, finding.line) for finding in parse(path)}
    if expected != actual:
        print(f"lint-purity: fixture mismatch\n  expected: {sorted(expected)}\n"
              f"  actual:   {sorted(actual)}", file=sys.stderr)
        raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", required=True, type=pathlib.Path)
    parser.add_argument("logs", nargs="*", type=pathlib.Path)
    args = parser.parse_args()
    check_fixtures(args.fixtures)

    findings = {finding.key: finding for log in args.logs for finding in parse(log)}
    for finding in sorted(findings.values()):
        print(f"{finding.path}:{finding.line}: [{finding.kind}] {finding.reason} in "
              f"{finding.context}: {finding.expression}")
    if findings:
        false_claims = sum(f.kind == "false-claim" for f in findings.values())
        candidates = sum(f.kind == "candidate" for f in findings.values())
        if false_claims:
            print(f"lint-purity: {false_claims} false pure claim(s), "
                  f"{candidates} advisory pure candidate(s)")
            return 1
        print(f"lint-purity: no false pure claims; {candidates} advisory pure "
              "candidate(s) (fixtures passed)")
        return 0
    print("lint-purity: no findings (fixtures passed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
