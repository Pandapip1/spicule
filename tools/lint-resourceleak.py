#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check that every tracked resource is proven released before function exit.

Parses tools/clang/OwnershipChecker.cpp's ResourceLeakChecker (ntlibc.
ResourceLeak) diagnostic output -- the opt-in leak-at-exit half of
ResourceLifecycleChecker's (ntlibc.Resource, always-on) acquire/use/release
proof. ntlibc.Resource must be enabled alongside ntlibc.ResourceLeak in the
same clang -analyzer-checker= invocation: ResourceLeakChecker only reads the
ResourceMap/ResourceOrigin/ResourceFrame program-state facts
ResourceLifecycleChecker's own track() writes, so run alone it has nothing
to work from.

Shares tools/lint-ownership-fixtures/resource-safe.c and resource-unsafe.c
with tools/lint-ownership.py -- this script's own fixture gate only expects
the lines tagged `ownership-expect: resource-leak`, the one shape specific
to this checker; every other `ownership-expect:` tag in those files belongs
to tools/lint-ownership.py's own gate instead.
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
    r"(resource is not proven released before function exit); "
    r"origin '(.*)'; context '(.*)'; "
    r"expression '(.*)'; site '(.*)' "
    r"\[ntlibc\.ResourceLeak\]$"
)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
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
        raise SystemExit(f"lint-resourceleak: analyzer crashed; see {path}")
    result = []
    for line in text.splitlines():
        match = DIAGNOSTIC.match(line)
        if match:
            result.append(Finding(relative(match.group(5)), int(match.group(2)),
                                  match.group(6), match.group(7), match.group(8)))
    return result


def fixture_test(path: pathlib.Path) -> None:
    expected = {(source.relative_to(ROOT).as_posix(), number)
                for source in FIXTURES.glob("*.c")
                for number, line in enumerate(source.read_text().splitlines(), 1)
                if "ownership-expect: resource-leak" in line}
    actual = {(finding.path, finding.line) for finding in parse(path)}
    if actual != expected:
        print("lint-resourceleak: fixture self-test failed", file=sys.stderr)
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
        print(f"{finding.path}:{finding.line}: resource is not proven released "
              f"before function exit in {finding.context}: {finding.expression}")
    if findings:
        print(f"lint-resourceleak: {len(findings)} resource(s) not proven "
              f"released before function exit")
        return 1
    print("lint-resourceleak: no findings (fixtures passed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
