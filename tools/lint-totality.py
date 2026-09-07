#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prove spicule loops and recursive call-graph components terminating."""

from __future__ import annotations

import argparse
import collections
import pathlib
import sys
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tools/lint-totality-fixtures"
LOOP_KINDS = {"for", "while", "do"}
LOOP_PROOFS = {"constant-false", "finite-state-transition",
               "reachable-cycle-absence",
               "strict-scalar-rank", "paired-scalar-rank",
               "sentinel-distance-rank", "unproved"}


@dataclass(frozen=True)
class Edge:
    caller: str
    callee: str
    path: str
    line: int
    relations: tuple[tuple[int, int, bool], ...]


@dataclass(frozen=True)
class Loop:
    function: str
    path: str
    line: int
    kind: str
    proof: str
    text: str


def relative(name: str) -> str:
    path = pathlib.Path(name)
    if path.is_absolute():
        try:
            return path.relative_to(ROOT).as_posix()
        except ValueError:
            return path.as_posix()
    return path.as_posix()


def parse_relations(raw: str) -> tuple[tuple[int, int, bool], ...]:
    if raw == "-":
        return ()
    result = []
    for item in raw.split(","):
        destination, source, relation = item.split(":")
        if relation not in {"=", "<"}:
            raise ValueError(f"unknown size relation {relation!r}")
        result.append((int(destination), int(source), relation == "<"))
    return tuple(sorted(result))


def parse(logs: list[pathlib.Path]) -> tuple[dict[str, int], list[Edge], list[Edge], list[Loop]]:
    functions = {}
    direct = []
    indirect = []
    loops = []
    for log in logs:
        for number, raw in enumerate(log.read_text(encoding="utf-8").splitlines(), 1):
            fields = raw.split("\t")
            if not fields or not fields[0]:
                continue
            try:
                if fields[0] == "F" and len(fields) == 6:
                    parameters = int(fields[5])
                    if fields[1] in functions and functions[fields[1]] != parameters:
                        raise ValueError(f"conflicting declarations of {fields[1]}")
                    functions[fields[1]] = parameters
                elif fields[0] in {"C", "I"} and len(fields) == 6:
                    edge = Edge(fields[1], fields[2], relative(fields[3]), int(fields[4]),
                                parse_relations(fields[5]))
                    (direct if fields[0] == "C" else indirect).append(edge)
                elif fields[0] == "L" and len(fields) == 7:
                    if fields[4] not in LOOP_KINDS:
                        raise ValueError(f"unknown loop kind {fields[4]!r}")
                    if fields[5] not in LOOP_PROOFS:
                        raise ValueError(f"unknown loop proof {fields[5]!r}")
                    loops.append(Loop(fields[1], relative(fields[2]), int(fields[3]),
                                      fields[4], fields[5], fields[6]))
                else:
                    raise ValueError("unknown record")
            except ValueError as error:
                raise SystemExit(f"{log}:{number}: malformed totality record: {error}") from error
    for edge in direct:
        if edge.caller not in functions:
            raise SystemExit(f"{edge.path}:{edge.line}: call has unknown caller {edge.caller}")
        for destination, source, _ in edge.relations:
            if source >= functions[edge.caller] or source < 0:
                raise SystemExit(f"{edge.path}:{edge.line}: source parameter index out of range")
            if edge.callee in functions and (destination >= functions[edge.callee] or
                                             destination < 0):
                raise SystemExit(f"{edge.path}:{edge.line}: destination parameter index out of range")
    if logs and not functions:
        raise SystemExit("lint-totality: extractor produced no function records")
    return functions, direct, indirect, loops


def findings(functions: dict[str, int], direct: list[Edge],
             loops: list[Loop]) -> tuple[list[Edge], list[Loop]]:
    components = recursive_components(functions, direct)
    failed = [component for component in components
              if not size_change_proves(component, direct)]
    recursion = sorted((edge for component in failed for edge in direct
                        if edge.caller in component and edge.callee in component),
                       key=lambda edge: (edge.path, edge.line,
                                         edge.caller, edge.callee))
    unproved_loops = sorted((loop for loop in loops if loop.proof == "unproved"),
                            key=lambda loop: (loop.path, loop.line,
                                              loop.function))
    return recursion, unproved_loops


def fixture_test(log: pathlib.Path) -> None:
    expected = set()
    for source in FIXTURES.glob("*.c"):
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            if "totality-expect" in line:
                expected.add((source.relative_to(ROOT).as_posix(), number))
    functions, direct, _, loops = parse([log])
    recursion, unproved_loops = findings(functions, direct, loops)
    actual = {(edge.path, edge.line) for edge in recursion}
    actual.update((loop.path, loop.line) for loop in unproved_loops)
    if actual != expected:
        print("lint-totality: fixture self-test failed", file=sys.stderr)
        print(f"  expected: {sorted(expected)}", file=sys.stderr)
        print(f"  actual:   {sorted(actual)}", file=sys.stderr)
        raise SystemExit(1)


def recursive_components(functions: dict[str, int], edges: list[Edge]) -> list[set[str]]:
    graph: dict[str, list[str]] = collections.defaultdict(list)
    for edge in edges:
        if edge.callee in functions:
            graph[edge.caller].append(edge.callee)

    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack = set()
    components: list[set[str]] = []
    next_index = 0

    def visit(function: str) -> None:
        nonlocal next_index
        index[function] = low[function] = next_index
        next_index += 1
        stack.append(function)
        on_stack.add(function)
        for callee in graph[function]:
            if callee not in index:
                visit(callee)
                low[function] = min(low[function], low[callee])
            elif callee in on_stack:
                low[function] = min(low[function], index[callee])
        if low[function] == index[function]:
            component = set()
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.add(member)
                if member == function:
                    break
            if len(component) > 1 or function in graph[function]:
                components.append(component)

    for function in sorted(functions):
        if function not in index:
            visit(function)

    return components


Matrix = tuple[tuple[int, int, bool], ...]


def compose(first: Matrix, second: Matrix) -> Matrix:
    """Compose A->B first with B->C second, producing A->C."""
    result: dict[tuple[int, int], bool] = {}
    for middle1, source, strict1 in first:
        for destination, middle2, strict2 in second:
            if middle1 != middle2:
                continue
            key = destination, source
            result[key] = result.get(key, False) or strict1 or strict2
    return tuple((destination, source, strict)
                 for (destination, source), strict in sorted(result.items()))


def size_change_proves(component: set[str], edges: list[Edge]) -> bool:
    paths: dict[tuple[str, str], set[Matrix]] = collections.defaultdict(set)
    for edge in edges:
        if edge.caller in component and edge.callee in component:
            paths[edge.caller, edge.callee].add(edge.relations)

    changed = True
    while changed:
        changed = False
        snapshot = [(pair, matrix) for pair, matrices in paths.items()
                    for matrix in matrices]
        for (source, middle), first in snapshot:
            for (middle2, destination), second in snapshot:
                if middle != middle2:
                    continue
                matrix = compose(first, second)
                bucket = paths[source, destination]
                if matrix not in bucket:
                    bucket.add(matrix)
                    changed = True

    idempotents = []
    for function in component:
        for matrix in paths[function, function]:
            if compose(matrix, matrix) == matrix:
                idempotents.append(matrix)
    return bool(idempotents) and all(
        any(destination == source and strict
            for destination, source, strict in matrix)
        for matrix in idempotents
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=pathlib.Path)
    parser.add_argument("logs", nargs="*", type=pathlib.Path)
    arguments = parser.parse_args()
    if arguments.fixtures:
        fixture_test(arguments.fixtures)
    if not arguments.logs:
        print("lint-totality: fixtures passed")
        return 0
    functions, direct, indirect, loops = parse(arguments.logs)
    recursion, unproved_loops = findings(functions, direct, loops)

    for edge in recursion:
        print(f"{edge.path}:{edge.line}: recursion lacks a size-change proof: "
              f"{edge.caller} -> {edge.callee}")
    for loop in unproved_loops:
        print(f"{loop.path}:{loop.line}: loop has no inferred well-founded rank "
              f"in {loop.function}: {loop.text[:160]}")
    for edge in sorted(indirect, key=lambda edge: (edge.path, edge.line,
                                                    edge.caller, edge.callee)):
        print(f"{edge.path}:{edge.line}: indirect call prevents a closed call-graph proof "
              f"in {edge.caller}: {edge.callee}")
    if recursion or unproved_loops or indirect:
        print(f"lint-totality: {len(recursion)} edge(s) in unproved recursive component(s); "
              f"{len(unproved_loops)} of {len(loops)} loop(s) unproved; "
              f"{len(indirect)} indirect call(s) unproved")
        return 1
    print(f"lint-totality: recursive call graph passes size-change termination; "
          f"all {len(loops)} loop(s) have ranks; no indirect calls")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
