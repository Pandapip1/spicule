#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate path-sensitive allocation lifetime and producer/freer contracts."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tools/lint-allocation-lifetime-fixtures"
DIAGNOSTIC = re.compile(
    r"^(.*?):(\d+):(\d+): warning: "
    r"(dynamic allocation is not freed before function exit|"
    r"returned allocation has no dynamic-storage token contract|"
    r"consume function exits without releasing its argument|"
    r"allocation lifecycle state is not proven|"
    r"allocation is not proven live|"
    r"allocation result overwrites a live allocation|"
    r"allocation is already released|"
    r"allocation family does not match operation|"
    r"allocation family morphism is not proven|"
    r"allocation family morphism does not match operation); "
    r"context '(.*)'; allocation '(.*)' \[spicule\.AllocationLifetime\]$"
)
CONTRACT = re.compile(
    r"^spicule-allocation-contract: "
    r"(returns-declaration|returns-definition-explicit|"
    r"returns-definition-inherited|definition|takes-declaration|"
    r"takes-definition-explicit|takes-definition-inherited|"
    r"implementation-valid|implementation-malformed|"
    r"implementation-unknown-family|implementation-conflicting|"
    r"implementation-self|implementation-cyclic|"
    r"implementation-unsupported)"
    r"\t([^\t]+)\t([^\t]+)\t(.*)$"
)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    reason: str
    context: str
    allocation: str


def relative(name: str) -> str:
    path = pathlib.Path(name)
    if path.is_absolute():
        try:
            return path.relative_to(ROOT).as_posix()
        except ValueError:
            pass
    return path.as_posix()


def parse(path: pathlib.Path) -> tuple[list[Finding], set[tuple[str, str, str]]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if "PLEASE submit a bug report" in text or "clang frontend command failed" in text:
        raise SystemExit(f"lint-allocation-lifetime: analyzer crashed; see {path}")
    findings: list[Finding] = []
    contracts: set[tuple[str, str, str]] = set()
    for line in text.splitlines():
        match = DIAGNOSTIC.match(line)
        if match:
            findings.append(Finding(relative(match.group(1)), int(match.group(2)),
                                    match.group(4), match.group(5), match.group(6)))
            continue
        match = CONTRACT.match(line)
        if match:
            kind, family, function, _rest = match.groups()
            contracts.add((kind, family, function))
    return findings, contracts


def validate_contracts(contracts: set[tuple[str, str, str]], fixture: bool) -> list[str]:
    producers: dict[str, set[str]] = {}
    producer_explicit: dict[str, set[str]] = {}
    producer_inherited: dict[str, set[str]] = {}
    declared: dict[str, set[str]] = {}
    explicit: dict[str, set[str]] = {}
    inherited: dict[str, set[str]] = {}
    definitions = {function for kind, _family, function in contracts
                   if kind == "definition"}
    for kind, family, function in contracts:
        if kind.startswith("returns-"):
            producers.setdefault(family, set()).add(function)
            if kind == "returns-definition-explicit":
                producer_explicit.setdefault(family, set()).add(function)
            elif kind == "returns-definition-inherited":
                producer_inherited.setdefault(family, set()).add(function)
        elif kind == "takes-declaration":
            declared.setdefault(family, set()).add(function)
        elif kind == "takes-definition-explicit":
            explicit.setdefault(family, set()).add(function)
        elif kind == "takes-definition-inherited":
            inherited.setdefault(family, set()).add(function)
    errors = []
    for kind, external, internal in sorted(contracts):
        if kind.startswith("implementation-") and kind != "implementation-valid":
            errors.append(
                f"token family '{external}' has rejected implementation "
                f"mapping '{internal}' ({kind.removeprefix('implementation-')})"
            )
    for family, functions in sorted(producer_inherited.items()):
        for producer in sorted(functions - producer_explicit.get(family, set())):
            errors.append(
                f"producer '{producer}' for family '{family}' has an in-tree "
                "definition but that definition does not repeat "
                "withtok explicitly (the header annotation was only "
                "inherited)"
            )
    for family, functions in sorted(producers.items()):
        # A same-family consume+return function is an ownership transformer,
        # not a terminal freer: it replaces or forwards one live generation
        # while preserving the caller's obligation in its return value.
        # It therefore cannot satisfy the requirement for an independently
        # callable terminal release operation, and must not make the real
        # freer look ambiguous merely because it also consumes its inputs.
        linked = (declared.get(family, set()) |
                  explicit.get(family, set())) - functions
        if len(linked) != 1:
            errors.append(f"family '{family}' returned by {sorted(functions)} has "
                          f"{len(linked)} freer(s), expected exactly one: {sorted(linked)}")
    for family in sorted(set(declared) | set(explicit)):
        linked = ((declared.get(family, set()) |
                   explicit.get(family, set())) -
                  producers.get(family, set()))
        for freer in sorted(linked):
            if freer in definitions and freer not in explicit.get(family, set()):
                inherited_here = freer in inherited.get(family, set())
                errors.append(
                    f"freer '{freer}' for family '{family}' has an in-tree definition "
                    f"but that definition does not repeat consume explicitly"
                    + (" (the header annotation was only inherited)" if inherited_here else "")
                )
    if not fixture:
        all_freer_families = set(declared) | set(explicit)
        for family in sorted(all_freer_families - set(producers)):
            functions = declared.get(family, set()) | explicit.get(family, set())
            errors.append(f"family '{family}' freed by {sorted(functions)} has no producer")
    return errors


def fixture_test(path: pathlib.Path) -> None:
    findings, contracts = parse(path)
    expected = {(source.relative_to(ROOT).as_posix(), number)
                for source in FIXTURES.glob("*.c")
                for number, line in enumerate(source.read_text().splitlines(), 1)
                if "allocation-lifetime-expect" in line}
    actual = {(finding.path, finding.line) for finding in findings}
    errors = validate_contracts(contracts, True)
    expected_contract_errors = sum(
        "allocation-contract-expect" in line
        for source in FIXTURES.glob("*.c")
        for line in source.read_text().splitlines()
    )
    if actual != expected or len(errors) != expected_contract_errors:
        print("lint-allocation-lifetime: fixture self-test failed", file=sys.stderr)
        print(f"  expected: {sorted(expected)}", file=sys.stderr)
        print(f"  actual:   {sorted(actual)}", file=sys.stderr)
        print(f"  expected contract errors: {expected_contract_errors}", file=sys.stderr)
        for error in errors:
            print(f"  contract: {error}", file=sys.stderr)
        raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", required=True, type=pathlib.Path)
    parser.add_argument("logs", nargs="*", type=pathlib.Path)
    args = parser.parse_args()
    fixture_test(args.fixtures)

    findings: dict[tuple[str, int, str, str], Finding] = {}
    contracts: set[tuple[str, str, str]] = set()
    for log in args.logs:
        parsed, found_contracts = parse(log)
        contracts.update(found_contracts)
        for finding in parsed:
            findings[(finding.path, finding.line, finding.reason,
                      finding.context)] = finding
    errors = validate_contracts(contracts, False)
    for finding in sorted(findings.values()):
        print(f"{finding.path}:{finding.line}: {finding.reason} in "
              f"{finding.context}: {finding.allocation}")
    for error in errors:
        print(f"allocation-contract: {error}")
    if findings or errors:
        print(f"lint-allocation-lifetime: {len(findings)} lifetime finding(s), "
              f"{len(errors)} contract error(s)")
        return 1
    print("lint-allocation-lifetime: no findings (fixtures and contracts passed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
