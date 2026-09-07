#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check path-sensitive reentrant-static-storage pointer staleness."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tools/lint-reentrancy-fixtures"
DIAGNOSTIC = re.compile(
    r"^(.*?):(\d+):(\d+): warning: "
    r"read of a pointer returned by an earlier '(\w+)' call after a later "
    r"'\4' call may observe overwritten internal static storage; "
    r"origin '(.*)'; context '(.*)'; expression '(.*)' \[spicule\.Reentrancy\]$"
)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    family: str
    context: str
    expression: str
    line: int

    @property
    def key(self) -> tuple[str, str, str, str]:
        return self.path, self.family, self.context, self.expression


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
        raise SystemExit(f"lint-reentrancy: analyzer crashed; see {path}")
    result = []
    for line in text.splitlines():
        match = DIAGNOSTIC.match(line)
        if match:
            result.append(Finding(relative(match.group(5)), match.group(4),
                                  match.group(6), match.group(7),
                                  int(match.group(2))))
    return result


def check_fixtures(path: pathlib.Path) -> None:
    expected = {(source.relative_to(ROOT).as_posix(), number)
                for source in FIXTURES.glob("*.c")
                for number, line in enumerate(source.read_text().splitlines(), 1)
                if "reentrancy-expect" in line}
    actual = {(finding.path, finding.line) for finding in parse(path)}
    if expected != actual:
        print(f"lint-reentrancy: fixture mismatch\n  expected: {sorted(expected)}\n"
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
        print(f"{finding.path}:{finding.line}: stale '{finding.family}' pointer read in "
              f"{finding.context}: {finding.expression}")
    if findings:
        print(f"lint-reentrancy: {len(findings)} stale reentrant-storage read(s)")
        return 1
    print("lint-reentrancy: no findings (fixtures passed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
