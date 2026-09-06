#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check heap ownership, construct lifecycles, and pointer validity proofs."""

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
    r"(deallocator argument is not proven owned|reallocator argument is not proven owned|"
    r"ownership is already consumed|"
    r"borrow accesses a consumed owner|owned construct is not proven initialized|"
    r"owned construct is already initialized|owned construct is already destroyed|"
    r"operation accesses a destroyed owned construct|"
    r"owned construct ownership class does not match operation|"
    r"required ownership capability token is not held|"
    r"none of the required ownership capability tokens is held|"
    r"linear ownership capability token would be duplicated|"
    r"ownership capability token duplication class does not match|"
    r"operation is blocked while ownership capability token is held|"
    r"pointer operation is blocked while unchecked ownership token is held|"
    r"source ownership type does not provide destination token bundle|"
    r"source ownership token has already moved|"
    r"ownership destination already holds a token|"
    r"ownership destination token state is not proven|"
    r"ownership token duplication class does not match|"
    r"ownership token is not implicitly droppable|"
    r"declared ownership token drop is not proven by function body|"
    r"declared ownership token addition is not proven by function body|"
    r"pointer dereference is not proven nonnull|"
    r"pointer target is not proven live storage|"
    r"dereference extent is not proven sufficient|"
    r"dereference alignment is not proven valid|"
    r"dereference accesses consumed storage|resource is not proven live|"
    r"resource is already released|operation uses a released resource|"
    r"resource family does not match operation); "
    r"origin '(.*)'; context '(.*)'; "
    r"expression '(.*)'; site '(.*)' "
    r"\[ntlibc\.(Ownership|OwnedConstruct|CapabilityToken|OwnershipType|ValidPointer|Resource)\]$"
)
CONTRACT = re.compile(
    r"^ownership-contract: "
    r"(header-declaration|source-declaration|definition-explicit|"
    r"definition-inherited|definition)\t([^\t]+)\t([^\t]+)\t(.*)$"
)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    checker: str
    reason: str
    context: str
    expression: str
    site: str
    line: int

    @property
    def key(self) -> tuple[str, str, str, str, str, str]:
        return (self.path, self.checker, self.reason, self.context,
                self.expression, self.site)


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
        raise SystemExit(f"lint-ownership: analyzer crashed; see {path}")
    findings = []
    for line in text.splitlines():
        match = DIAGNOSTIC.match(line)
        if match:
            findings.append(Finding(relative(match.group(5)), match.group(9),
                                    match.group(4), match.group(6), match.group(7),
                                    f"{match.group(8)} @column {match.group(3)}",
                                    int(match.group(2))))
    return findings


def parse_contracts(path: pathlib.Path) -> set[tuple[str, str, str]]:
    contracts = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = CONTRACT.match(line)
        if match:
            kind, contract, function, _rest = match.groups()
            contracts.add((kind, contract, function))
    return contracts


def validate_contracts(
        contracts: set[tuple[str, str, str]]) -> list[str]:
    declared: dict[str, set[str]] = {}
    explicit: dict[str, set[str]] = {}
    inherited: dict[str, set[str]] = {}
    definitions = {function for kind, _contract, function in contracts
                   if kind == "definition"}
    for kind, contract, function in contracts:
        if kind == "header-declaration":
            declared.setdefault(function, set()).add(contract)
        elif kind == "definition-explicit":
            explicit.setdefault(function, set()).add(contract)
        elif kind == "definition-inherited":
            inherited.setdefault(function, set()).add(contract)
    errors = []
    for function in sorted(definitions):
        required = declared.get(function, set()) | inherited.get(function, set())
        for contract in sorted(required - explicit.get(function, set())):
            errors.append(
                f"definition of '{function}' does not explicitly repeat "
                f"header contract '{contract}'"
            )
    return errors


def fixture_test(path: pathlib.Path) -> None:
    expected = set()
    for source in FIXTURES.glob("*.c"):
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            # "ownership-expect: resource-leak" belongs to the opt-in
            # ntlibc.ResourceLeak checker's own tools/lint-resourceleak.py
            # gate (tools/lint.sh's resourceleak stage) -- ntlibc.Resource
            # alone (this script's own DIAGNOSTIC) no longer emits that
            # message, so it must not be in this gate's expected set.
            if "ownership-expect" in line and "ownership-expect: resource-leak" not in line:
                expected.add((source.relative_to(ROOT).as_posix(), number))
    actual = {(finding.path, finding.line) for finding in parse_log(path)}
    errors = validate_contracts(parse_contracts(path))
    expected_contract_errors = sum(
        "ownership-contract-expect" in line
        for source in FIXTURES.glob("*.c")
        for line in source.read_text(encoding="utf-8").splitlines()
    )
    if actual != expected or len(errors) != expected_contract_errors:
        print("lint-ownership: fixture self-test failed", file=sys.stderr)
        print(f"  expected: {sorted(expected)}", file=sys.stderr)
        print(f"  actual:   {sorted(actual)}", file=sys.stderr)
        print(f"  expected contract errors: {expected_contract_errors}",
              file=sys.stderr)
        for error in errors:
            print(f"  contract: {error}", file=sys.stderr)
        raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", required=True, type=pathlib.Path)
    parser.add_argument("logs", nargs="*", type=pathlib.Path)
    arguments = parser.parse_args()
    fixture_test(arguments.fixtures)

    findings = {finding.key: finding
                for log in arguments.logs for finding in parse_log(log)}
    contracts = {contract for log in arguments.logs
                 for contract in parse_contracts(log)}
    errors = validate_contracts(contracts)
    for finding in sorted(findings.values()):
        print(f"{finding.path}:{finding.line}: {finding.reason} in "
              f"{finding.context}: {finding.expression}")
    for error in errors:
        print(f"ownership-contract: {error}")
    if findings or errors:
        releases = sum(finding.reason.endswith("argument is not proven owned")
                       for finding in findings.values())
        repeats = sum(finding.reason == "ownership is already consumed"
                      for finding in findings.values())
        borrows = sum(finding.reason == "borrow accesses a consumed owner"
                      for finding in findings.values())
        constructs = sum(finding.checker == "OwnedConstruct"
                         for finding in findings.values())
        capabilities = sum(finding.checker == "CapabilityToken"
                           for finding in findings.values())
        ownership_types = sum(finding.checker == "OwnershipType"
                              for finding in findings.values())
        pointers = sum(finding.checker == "ValidPointer"
                       for finding in findings.values())
        resources = sum(finding.checker == "Resource"
                        for finding in findings.values())
        print(f"lint-ownership: {releases} unproved release(s), "
              f"{repeats} repeated consumption(s), "
              f"{borrows} expired borrow access(es), "
              f"{constructs} construct lifecycle obligation(s), "
              f"{capabilities} capability token obligation(s), "
              f"{ownership_types} ownership type mismatch(es), "
              f"{pointers} pointer validity obligation(s), "
              f"{resources} resource lifecycle obligation(s), "
              f"{len(errors)} contract mismatch(es)")
        return 1
    print("lint-ownership: no findings (fixtures passed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
