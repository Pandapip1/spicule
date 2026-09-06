#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check for/while/do headers that compound a bound with a data-dependent flag.

Parses tools/clang/LoopConditionChecker.cpp's diagnostic output (real AST
analysis, not text matching -- see that file's own header for the
classification it applies) and reports every loop header whose condition
mixes, via `&&`/`||`, a structural bound (a range, a count, a cursor-vs-
NULL/sentinel test) with a distinct, apparently incidental data-dependent
condition (a found/success/error flag, or an unrelated function-call
result). The fix in every case is the same: keep the primary condition in
the loop header, and move the other one into an explicit
`if (condition) break;` statement in the loop body -- never to change what
the checker itself does.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tools/lint-loopcond-fixtures"
DIAGNOSTIC = re.compile(
    r"^(.*?):(\d+):(\d+): warning: .*; kind 'compound-header'; loop_kind '(.*?)'; "
    r"origin '(.*)'; context '(.*)'; bound '(.*)'; flag '(.*)'; expression '(.*)' "
    r"\[ntlibc\.LoopCondition\]$"
)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    loop_kind: str
    context: str
    bound: str
    flag: str
    expression: str

    @property
    def key(self) -> tuple[str, str, str, str, str, str]:
        return self.path, self.loop_kind, self.context, self.bound, self.flag, self.expression


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
        raise SystemExit(f"lint-loopcond: analyzer crashed; see {path}")
    result = []
    for line in text.splitlines():
        match = DIAGNOSTIC.match(line)
        if match:
            result.append(Finding(relative(match.group(5)), int(match.group(2)), match.group(4),
                                  match.group(6), match.group(7), match.group(8), match.group(9)))
    return result


def check_fixtures(path: pathlib.Path) -> None:
    expected = {(source.relative_to(ROOT).as_posix(), number)
                for source in FIXTURES.glob("*.c")
                for number, line in enumerate(source.read_text().splitlines(), 1)
                if "loopcond-expect" in line}
    actual = {(finding.path, finding.line) for finding in parse(path)}
    if expected != actual:
        print(f"lint-loopcond: fixture mismatch\n  expected: {sorted(expected)}\n"
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
        print(f"{finding.path}:{finding.line}: `{finding.loop_kind}` loop in {finding.context} "
              f"compounds bound '{finding.bound}' with data-dependent '{finding.flag}' via &&/||")
        print(f"  move the data-dependent part into an `if (...) break;` in the loop body: "
              f"{finding.expression}")
    if findings:
        print(f"lint-loopcond: {len(findings)} finding(s)")
        return 1
    print("lint-loopcond: no findings (fixtures passed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
