#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the Clang integer-sentinel checker's fixtures and live findings."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tools/lint-integer-sentinel-fixtures"
DIAGNOSTIC = re.compile(
    r"^(.*?):(\d+):(\d+): warning: value from (.*?) carries excluded sentinel "
    r"(-?\d+) not proven ruled out before (.*?); origin '(.*?)'; "
    r"context '(.*?)'; use '(.*?)' \[ntlibc\.IntegerSentinel\]$"
)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    context: str
    use: str
    origin_symbol: str
    sentinel: str
    kind: str
    line: int

    @property
    def key(self) -> tuple[str, str, str, str, str, str]:
        return (self.path, self.context, self.use, self.origin_symbol,
                self.sentinel, self.kind)


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
        raise SystemExit(f"lint-integer-sentinel: analyzer crashed; see {path}")
    findings = []
    for line in text.splitlines():
        match = DIAGNOSTIC.match(line)
        if match:
            findings.append(Finding(relative(match.group(7)), match.group(8),
                                    match.group(9), match.group(4),
                                    match.group(5), match.group(6),
                                    int(match.group(2))))
    return findings


def fixture_test(path: pathlib.Path) -> None:
    expected = set()
    for source in FIXTURES.glob("*.c"):
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            if "integer-sentinel-expect" in line:
                expected.add((source.relative_to(ROOT).as_posix(), number))
    actual = {(finding.path, finding.line) for finding in parse_log(path)}
    if actual != expected:
        print("lint-integer-sentinel: fixture self-test failed", file=sys.stderr)
        print(f"  expected: {sorted(expected)}", file=sys.stderr)
        print(f"  actual:   {sorted(actual)}", file=sys.stderr)
        raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", required=True, type=pathlib.Path)
    parser.add_argument("logs", nargs="*", type=pathlib.Path)
    arguments = parser.parse_args()
    fixture_test(arguments.fixtures)

    findings = {finding.key: finding for log in arguments.logs for finding in parse_log(log)}
    for finding in sorted(findings.values()):
        print(f"{finding.path}:{finding.line}: unproven integer sentinel in "
              f"{finding.context}: '{finding.use}' from '{finding.origin_symbol}' "
              f"(excludes {finding.sentinel}) before {finding.kind}")
        print("  add a dominating check ruling the sentinel out first")
    if findings:
        print(f"lint-integer-sentinel: {len(findings)} finding(s)")
        return 1
    print("lint-integer-sentinel: no findings (fixtures passed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
