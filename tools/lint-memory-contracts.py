#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check memory-operation spans and overlap."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tools/lint-memory-contract-fixtures"
DIAGNOSTIC = re.compile(
    r"^(.*?):(\d+):(\d+): warning: "
    r"(memory operation span is not proven valid|memcpy ranges are not proven nonoverlapping|"
    r"declared memory token addition is not proven by function body|"
    r"manual memory proof axiom is redundant|"
    r"manual memory proof axiom can be narrowed|"
    r"paired length field is not proven within its pointer field's real "
    r"allocation extent|"
    r"struct argument passed to a fields_established parameter is not "
    r"proven to already satisfy its own paired-field extent invariant "
    r"before this call); "
    r"origin '(.*)'; context '(.*)'; expression '(.*)'; site '(.*)' "
    r"\[spicule\.MemoryContract\]$"
)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    reason: str
    context: str
    expression: str
    site: str
    line: int

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return self.path, self.reason, self.context, self.expression, self.site


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
        raise SystemExit(f"lint-memory-contracts: analyzer crashed; see {path}")
    result = []
    for line in text.splitlines():
        match = DIAGNOSTIC.match(line)
        if match:
            result.append(Finding(relative(match.group(5)), match.group(4),
                                  match.group(6), match.group(7),
                                  f"{match.group(8)} @column {match.group(3)}",
                                  int(match.group(2))))
    return result


def check_fixtures(path: pathlib.Path) -> None:
    expected = {(source.relative_to(ROOT).as_posix(), number)
                for source in FIXTURES.glob("*.c")
                for number, line in enumerate(source.read_text().splitlines(), 1)
                if "memory-contract-expect" in line}
    actual = {(finding.path, finding.line) for finding in parse(path)}
    if expected != actual:
        print(f"lint-memory-contracts: fixture mismatch\n  expected: {sorted(expected)}\n"
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
        print(f"{finding.path}:{finding.line}: {finding.reason} in "
              f"{finding.context}: {finding.expression}")
    if findings:
        spans = sum(f.reason.startswith("memory operation span") for f in findings.values())
        overlaps = sum(f.reason.startswith("memcpy ranges") for f in findings.values())
        tokens = sum(f.reason.startswith("declared memory token") for f in findings.values())
        redundant = sum(f.reason.startswith("manual memory proof") for f in findings.values())
        movable = sum(f.reason.endswith("can be narrowed") for f in findings.values())
        redundant -= movable
        print(f"lint-memory-contracts: {spans} unproved span(s), "
              f"{overlaps} unproved overlap(s), {tokens} unproved token contract(s), "
              f"{redundant} redundant manual axiom(s), "
              f"{movable} movable manual axiom(s)")
        return 1
    print("lint-memory-contracts: no findings (fixtures passed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
