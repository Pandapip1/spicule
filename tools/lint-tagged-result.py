#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check tagged-result selection proofs and their analyzer fixtures."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tools/lint-tagged-result-fixtures"
DIAGNOSTIC = re.compile(
    r"^(.*?):(\d+):(\d+): warning: tagged result field '(normal|special)' "
    r"is not proven selected; origin '(.*)'; context '(.*)'; access '(.*)' "
    r"\[spicule\.TaggedResult\]$"
)


def relative(name: str) -> str:
    path = pathlib.Path(name)
    if path.is_absolute():
        try:
            return path.relative_to(ROOT).as_posix()
        except ValueError:
            return path.as_posix()
    return path.as_posix()


def parse_log(path: pathlib.Path) -> list[tuple[str, int, str, str, str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if "PLEASE submit a bug report" in text or "clang frontend command failed" in text:
        raise SystemExit(f"lint-tagged-result: analyzer crashed; see {path}")
    findings = []
    for line in text.splitlines():
        match = DIAGNOSTIC.match(line)
        if match:
            findings.append((relative(match.group(5)), int(match.group(2)),
                             match.group(4), match.group(6), match.group(7)))
    return findings


def fixture_test(path: pathlib.Path) -> None:
    expected = set()
    for source in FIXTURES.glob("*.c"):
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            if "tagged-result-expect" in line:
                expected.add((source.relative_to(ROOT).as_posix(), number))
    actual = {(finding[0], finding[1]) for finding in parse_log(path)}
    if actual != expected:
        print("lint-tagged-result: fixture self-test failed", file=sys.stderr)
        print(f"  expected: {sorted(expected)}", file=sys.stderr)
        print(f"  actual:   {sorted(actual)}", file=sys.stderr)
        raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", required=True, type=pathlib.Path)
    parser.add_argument("logs", nargs="*", type=pathlib.Path)
    arguments = parser.parse_args()
    fixture_test(arguments.fixtures)

    findings = [finding for log in arguments.logs for finding in parse_log(log)]
    for path, line, field, context, access in findings:
        print(f"{path}:{line}: {context} reads tagged {field} arm without proving it: {access}")
        print("  branch on kind first (kind == 0 selects normal; kind != 0 selects special)")
    if findings:
        print(f"lint-tagged-result: {len(findings)} unproven tagged-result read(s)")
        return 1
    print("lint-tagged-result: no findings (fixtures passed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
