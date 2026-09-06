#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject unchecked allocation arithmetic and capacity growth.

This is a deliberately small C lexer, not a regular-expression grep.  It
keeps source positions while masking comments and literals, balances call
parentheses, and examines the actual size argument of the allocators used by
this tree.  Every site found is reported live, every run.

Integer casts are handled separately by the Clang path-sensitive checker;
this lexer does not guess from type, variable, or limit names.  Checked
arithmetic should normally be expressed through src/internal/libc.h's
__size_* and __array_next_capacity helpers.  Escape comments are rejected.
"""

from __future__ import annotations

import collections
import os
import pathlib
import re
import sys
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tools/lint-sizearith-fixtures"
ALLOC_SIZE_ARGS = {
    "malloc": (0,),
    "__malloc": (0,),
    "realloc": (1,),
    "__realloc": (1,),
    "calloc": (0, 1),
    "reallocarray": (1, 2),
    "RtlAllocateHeap": (2,),
    "RtlReAllocateHeap": (3,),
}
TOKEN = re.compile(
    r"[A-Za-z_]\w*|0[xX][0-9A-Fa-f]+|\d+|<<=|>>=|\*=|\+=|-=|"
    r"<<|>>|->|\+\+|--|&&|\|\||==|!=|<=|>=|[^\s]"
)
GROWTH_NAME = re.compile(r"(?:^|_)(?:cap|capacity|newcap|new_cap|nc)$|cap", re.I)


@dataclass(frozen=True)
class Tok:
    text: str
    start: int
    end: int
    line: int


@dataclass(frozen=True)
class Site:
    rule: str
    path: str
    line: int
    snippet: str


def mask_noncode(source: str) -> str:
    out = list(source)
    state = "code"
    i = 0
    while i < len(source):
        c = source[i]
        n = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if c == "/" and n == "/":
                out[i] = out[i + 1] = " "
                state = "line"
                i += 2
                continue
            if c == "/" and n == "*":
                out[i] = out[i + 1] = " "
                state = "block"
                i += 2
                continue
            if c == '"':
                out[i] = " "
                state = "string"
            elif c == "'":
                out[i] = " "
                state = "char"
        elif state == "line":
            if c == "\n":
                state = "code"
            else:
                out[i] = " "
        elif state == "block":
            if c == "*" and n == "/":
                out[i] = out[i + 1] = " "
                state = "code"
                i += 2
                continue
            if c != "\n":
                out[i] = " "
        else:
            out[i] = " "
            if c == "\\" and i + 1 < len(source):
                if source[i + 1] != "\n":
                    out[i + 1] = " "
                i += 2
                continue
            if (state == "string" and c == '"') or (state == "char" and c == "'"):
                state = "code"
        i += 1
    return "".join(out)


def lex(masked: str) -> list[Tok]:
    starts = [0]
    for m in re.finditer("\n", masked):
        starts.append(m.end())
    toks = []
    line = 0
    for m in TOKEN.finditer(masked):
        while line + 1 < len(starts) and starts[line + 1] <= m.start():
            line += 1
        toks.append(Tok(m.group(), m.start(), m.end(), line + 1))
    return toks


def pairs(toks: list[Tok], left: str, right: str) -> dict[int, int]:
    stack: list[int] = []
    result: dict[int, int] = {}
    for i, tok in enumerate(toks):
        if tok.text == left:
            stack.append(i)
        elif tok.text == right and stack:
            j = stack.pop()
            result[j] = i
    return result


def split_args(toks: list[Tok], begin: int, end: int) -> list[tuple[int, int]]:
    result = []
    start = begin
    depth = 0
    for i in range(begin, end):
        if toks[i].text in ("(", "[", "{"):
            depth += 1
        elif toks[i].text in (")", "]", "}"):
            depth -= 1
        elif toks[i].text == "," and depth == 0:
            result.append((start, i))
            start = i + 1
    result.append((start, end))
    return result


def sizeof_ignored(toks: list[Tok], parens: dict[int, int]) -> set[int]:
    ignored: set[int] = set()
    i = 0
    while i < len(toks):
        if toks[i].text != "sizeof":
            i += 1
            continue
        ignored.add(i)
        j = i + 1
        if j < len(toks) and toks[j].text == "(" and j in parens:
            k = parens[j]
            ignored.update(range(j, k + 1))
            i = k + 1
            continue
        if j < len(toks) and toks[j].text == "*":
            ignored.add(j)
            j += 1
        if j < len(toks):
            ignored.add(j)
        i = j + 1
    return ignored


def has_arithmetic(toks: list[Tok], begin: int, end: int, ignored: set[int]) -> bool:
    have_operand = False
    for i in range(begin, end):
        if i in ignored:
            if toks[i].text == "sizeof":
                have_operand = True
            continue
        text = toks[i].text
        if text in ("+", "-", "*", "<<", ">>"):
            if have_operand:
                return True
            continue
        if text in ("?", ":"):
            # A ternary's '?' and ':' each start a fresh sub-expression:
            # a '*' (or unary '-') immediately following one is a pointer
            # dereference or sign, not this operand's continuation, so an
            # operand seen before the ternary must not carry across it.
            have_operand = False
            continue
        if text not in ("(", "[", "{", ",", "="):
            have_operand = True
    return False


def normalise(source: str, begin: int, end: int) -> str:
    return " ".join(source[begin:end].split()).replace("\t", " ")


def growth_guarded(toks: list[Tok], variable: int, factor: str, operation: int,
                   parens: dict[int, int], braces: dict[int, int]) -> bool:
    """Recognise an immediately dominating overflow guard with an exit."""
    name = toks[variable].text
    containing = [begin for begin, end in braces.items() if begin < operation < end]
    if not containing:
        return False
    body = min(containing)
    for i in range(body + 1, operation):
        if toks[i].text != "if" or i + 1 >= len(toks) or toks[i + 1].text != "(":
            continue
        cond_open = i + 1
        cond_close = parens.get(cond_open)
        if cond_close is None or cond_close >= operation:
            continue
        cond = [tok.text for tok in toks[cond_open + 1:cond_close]]
        try:
            variable_at = cond.index(name)
            greater_at = cond.index(">", variable_at + 1)
            divide_at = cond.index("/", greater_at + 1)
            factor_at = cond.index(factor, divide_at + 1)
        except ValueError:
            continue
        if not (variable_at < greater_at < divide_at < factor_at):
            continue
        statement = cond_close + 1
        if statement >= len(toks) or toks[statement].text != "{":
            continue
        statement_end = braces.get(statement)
        if statement_end is None or statement_end >= operation:
            continue
        if not any(tok.text in ("break", "return")
                   for tok in toks[statement + 1:statement_end]):
            continue
        between = [tok.text for tok in toks[statement_end + 1:operation]]
        if all(tok in ("return",) for tok in between):
            return True
    return False


def scan(path: pathlib.Path) -> list[Site]:
    source = path.read_text(encoding="utf-8")
    lines = source.splitlines()
    toks = lex(mask_noncode(source))
    parens = pairs(toks, "(", ")")
    braces = pairs(toks, "{", "}")
    ignored = sizeof_ignored(toks, parens)
    rel = path.relative_to(ROOT).as_posix()
    sites: list[Site] = []
    allocation_spans: list[tuple[int, int]] = []

    for number, line in enumerate(lines, 1):
        if "sizearith-safe:" in line:
            sites.append(Site("forbidden-escape", rel, number, line.strip()))

    for i, tok in enumerate(toks[:-1]):
        argnos = ALLOC_SIZE_ARGS.get(tok.text)
        if argnos is None or toks[i + 1].text != "(" or i + 1 not in parens:
            continue
        close = parens[i + 1]
        args = split_args(toks, i + 2, close)
        bad = False
        for argno in argnos:
            if argno < len(args):
                begin, end = args[argno]
                bad = bad or (begin < end and has_arithmetic(toks, begin, end, ignored))
        if not bad:
            continue
        line = tok.line
        sites.append(Site("allocation-arithmetic", rel, line,
                          normalise(source, tok.start, toks[close].end)))
        allocation_spans.append((i, close))

    def inside_allocation(index: int) -> bool:
        return any(a <= index <= b for a, b in allocation_spans)

    for i, tok in enumerate(toks):
        if inside_allocation(i):
            continue
        found = False
        end = i
        variable = i
        factor = ""
        guarded_multiply = False
        if GROWTH_NAME.search(tok.text):
            if i + 1 < len(toks) and toks[i + 1].text in ("*=", "+=", "<<="):
                found, end = True, min(i + 2, len(toks) - 1)
                factor = toks[end].text
                guarded_multiply = toks[i + 1].text == "*="
            elif (i + 2 < len(toks) and toks[i + 1].text == "*" and
                  i + 1 not in ignored and re.fullmatch(r"(?:0[xX][0-9A-Fa-f]+|\d+)",
                                                        toks[i + 2].text)):
                found, end = True, i + 2
                factor = toks[end].text
                guarded_multiply = True
            elif (i + 2 < len(toks) and toks[i + 1].text == "<<" and
                  toks[i + 2].text == "1"):
                found, end = True, i + 2
                factor = "2"
        elif (re.fullmatch(r"(?:0[xX][0-9A-Fa-f]+|\d+)", tok.text) and
              i + 2 < len(toks) and toks[i + 1].text == "*" and
              i + 1 not in ignored and GROWTH_NAME.search(toks[i + 2].text)):
            found, end = True, i + 2
            variable, factor = i + 2, tok.text
            guarded_multiply = True
        if found:
            line = tok.line
            if (guarded_multiply and factor and
                    growth_guarded(toks, variable, factor, i, parens, braces)):
                continue
            else:
                sites.append(Site("unchecked-growth", rel, line,
                                  normalise(source, tok.start, toks[end].end)))

    # Repeated tokens in one expression can make the growth matcher report
    # the same site twice.  Preserve source order while collapsing them.
    return list(dict.fromkeys(sites))


def fixture_test() -> None:
    expected: collections.Counter[tuple[str, str, int]] = collections.Counter()
    actual: collections.Counter[tuple[str, str, int]] = collections.Counter()
    files = sorted(FIXTURES.glob("*.c"))
    if not files:
        raise SystemExit("lint-sizearith: fixture floor failed: no fixture .c files")
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = re.search(r"sizearith-expect:\s*([a-z-]+)", line)
            if match:
                expected[(path.name, match.group(1), number)] += 1
        for site in scan(path):
            actual[(path.name, site.rule, site.line)] += 1
    if actual != expected:
        print("lint-sizearith: fixture self-test failed", file=sys.stderr)
        print(f"  expected: {sorted(expected.elements())}", file=sys.stderr)
        print(f"  actual:   {sorted(actual.elements())}", file=sys.stderr)
        raise SystemExit(1)


def source_files(arguments: list[str]) -> list[pathlib.Path]:
    roots = arguments or ["src", "crt", "sh", "arch"]
    result: list[pathlib.Path] = []
    for name in roots:
        path = (ROOT / name).resolve()
        if path.is_file() and path.suffix in (".c", ".h"):
            result.append(path)
        elif path.is_dir():
            result.extend(p for p in sorted(path.rglob("*"))
                          if p.is_file() and p.suffix in (".c", ".h"))
    return sorted(set(result))


def main() -> int:
    fixture_test()
    arguments = sys.argv[1:]
    files = source_files(arguments)
    if not files:
        print("lint-sizearith: FAILED -- no .c files scanned", file=sys.stderr)
        return 1
    sites = [site for path in files for site in scan(path)]
    for site in sites:
        print(f"{site.path}:{site.line}: {site.rule}: {site.snippet}")
        print("  use checked size/growth conversion or a mechanically visible bound")
    if sites:
        print(f"lint-sizearith: {len(sites)} finding(s) in {len(files)} file(s)")
        if os.environ.get("LINT_STRICT", "1") != "0":
            return 1
        return 0
    print(f"lint-sizearith: no findings ({len(files)} file(s) scanned; fixtures passed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
