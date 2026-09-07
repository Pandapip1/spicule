#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate src/internal/unicode_tables.c from the real Unicode Character
Database (UCD).

spicule's wchar_t is one 16-bit UTF-16 code unit (arch/*/bits/alltypes.h.in:
"TYPEDEF unsigned short wchar_t;" -- see include/wctype.h's banner comment),
so every classification/case-mapping/width table this script emits only
ever needs entries for U+0000..U+FFFF (the Basic Multilingual Plane): a
single wchar_t cannot hold a higher code point, only one half of a
surrogate pair, and a lone surrogate half is never a member of any real
Unicode property.

This is the one-time (well: "one Unicode-version-bump at a time") generator
that turns the raw, official UCD text files into the compact C range
tables checked in at src/internal/unicode_tables.c.  Nothing in that
generated file is hand-transcribed: every table is a straight, mechanical
range-compression of a real Unicode property, traceable back through this
script to the exact upstream file and field it came from.  Re-run this
script (no arguments needed -- it fetches its own inputs) to regenerate
that file, e.g. after a Unicode version bump edit UCD_VERSION below.

Inputs (fetched from https://www.unicode.org/Public/<UCD_VERSION>/ucd/,
cached in a temp directory so re-runs during development do not re-fetch):
  UnicodeData.txt          -- General_Category (per code point, including
                               the "<..., First>"/"<..., Last>" range
                               pseudo-entries) and the Simple_Uppercase/
                               Simple_Lowercase_Mapping fields (12 and 13,
                               0-indexed) used for towupper()/towlower().
  DerivedCoreProperties.txt -- Alphabetic, Uppercase, Lowercase: these are
                               the real "is this a letter" properties
                               (broader than the Lu/Ll/Lt/Lm/Lo general
                               categories alone -- e.g. Alphabetic also
                               picks up Nl and a handful of marks that are
                               letters in their scripts).
  PropList.txt              -- White_Space, Hex_Digit: two more
                               already-curated derived properties, no
                               reason to reconstruct either from the
                               general category data by hand.
  EastAsianWidth.txt        -- East_Asian_Width: Wide/Fullwidth code
                               points get column width 2 in wcwidth().

======================= what each generated table means =====================

iswalpha  -> Alphabetic property (DerivedCoreProperties.txt)
iswupper  -> Uppercase property (DerivedCoreProperties.txt)
iswlower  -> Lowercase property (DerivedCoreProperties.txt)
iswdigit  -> General_Category Nd ("decimal digit", every script's own
             contiguous 0-9 block, not just ASCII)
iswspace  -> White_Space property (PropList.txt)
iswcntrl  -> General_Category Cc (the C0 controls, DEL, and the C1
             controls -- Cc is closed and small: nothing else is ever in
             it)
iswxdigit -> Hex_Digit property (PropList.txt): ASCII 0-9/A-F/a-f plus
             their fullwidth (U+FF10-FF46) forms
iswprint  -> the complement of Cc + Cf + Cs + Co + Cn(unassigned) + Zl +
             Zp -- i.e. "has a real glyph or is at least a normal space",
             the standard definition used by e.g. Rust's
             char::is_control()'s complement and glibc's wide iswprint()
iswblank  -> General_Category Zs (space separators) union U+0009 TAB --
             the same "space-like but doesn't start a new line" set most
             libcs use
iswgraph, iswpunct, iswalnum -- NOT separate tables; composed from the
             above at the C level exactly the way this tree's narrow
             ctype already composes them (src/ctype/isalnum.c: alpha ||
             digit; src/ctype/ispunct.c: graph && !alnum) --
             graph = print && !space, alnum = alpha || digit,
             punct = graph && !alnum.
towupper/towlower -> UnicodeData.txt's own Simple_Uppercase_Mapping /
             Simple_Lowercase_Mapping fields. This is deliberately the
             POSIX-mandatory bar and no more: a 1:1, context-free,
             locale-blind code point mapping. Real *case folding* --
             locale-sensitive special casing such as Turkish dotless
             i/dotted I, or one-to-many mappings such as German sharp s
             (ß) case-folding to "SS" -- is explicitly out of scope; a
             simple mapping table structurally cannot represent a 1:N
             mapping, and the Turkish case needs locale data this tree's
             single C/POSIX locale has no slot for. towupper(0x00DF) i.e.
             towupper('ß') is therefore 0x00DF unchanged (no simple
             uppercase mapping exists for it), which is the correct,
             conforming answer for "simple" mapping.
wcwidth combining (0-width) set -> General_Category Mn (Nonspacing_Mark)
             union Me (Enclosing_Mark). This is real, data-derived, and
             covers the overwhelming majority of real-world combining
             diacritics (e.g. U+0301 COMBINING ACUTE ACCENT). Deliberately
             NOT included: Cf (Format) code points such as ZERO WIDTH
             JOINER/NON-JOINER (U+200C/200D) or the BOM (U+FEFF), which
             the widely-used Markus Kuhn reference wcwidth.c also treats
             as zero-width. spicule's wcwidth() reports width 1 for those
             instead -- a deliberate, documented simplification (they are
             a much smaller, more irregular set than Mn/Me, and getting
             them right needs the same kind of curated exception list
             Kuhn's own implementation carries, e.g. excluding U+00AD
             SOFT HYPHEN from an otherwise Cf-inclusive set -- exactly
             the "hand-picked ranges" this generator exists to avoid).
wcwidth wide (2-column) set -> East_Asian_Width Wide (W) or Fullwidth (F)
             (EastAsianWidth.txt). Ambiguous-width (A) code points are
             deliberately treated as narrow (1 column) here, matching
             the East Asian Width UAX #11 recommendation for a
             non-CJK-legacy context and most terminal emulators' default.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import urllib.request
from pathlib import Path

UCD_VERSION = "15.0.0"
UCD_BASE = f"https://www.unicode.org/Public/{UCD_VERSION}/ucd/"
BMP_MAX = 0xFFFF

ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = ROOT / "src" / "internal" / "unicode_tables.c"

FILES = ["UnicodeData.txt", "DerivedCoreProperties.txt", "PropList.txt",
         "EastAsianWidth.txt"]


def fetch(cache_dir: Path) -> dict[str, Path]:
    paths = {}
    for name in FILES:
        dest = cache_dir / name
        if not dest.exists() or dest.stat().st_size == 0:
            url = UCD_BASE + name
            print(f"fetching {url}", file=sys.stderr)
            with urllib.request.urlopen(url, timeout=30) as resp:
                dest.write_bytes(resp.read())
        paths[name] = dest
    return paths


# ---------------------------------------------------------------------
# Range helpers
# ---------------------------------------------------------------------

Range = tuple[int, int]


def coalesce(ranges: list[Range]) -> list[Range]:
    """Sort and merge adjacent/overlapping (lo, hi) pairs."""
    ordered = sorted(ranges)
    merged: list[Range] = []
    for lo, hi in ordered:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def clip_to_bmp(ranges: list[Range]) -> list[Range]:
    out = []
    for lo, hi in ranges:
        if lo > BMP_MAX:
            continue
        out.append((lo, min(hi, BMP_MAX)))
    return out


def complement(ranges: list[Range], lo_bound: int, hi_bound: int) -> list[Range]:
    ranges = coalesce(ranges)
    out = []
    cur = lo_bound
    for lo, hi in ranges:
        if lo > cur:
            out.append((cur, lo - 1))
        cur = max(cur, hi + 1)
    if cur <= hi_bound:
        out.append((cur, hi_bound))
    return out


# ---------------------------------------------------------------------
# UnicodeData.txt
# ---------------------------------------------------------------------

def parse_unicode_data(path: Path):
    """Returns (assigned_ranges, category -> ranges dict,
    upper_pairs, lower_pairs)."""
    assigned: list[Range] = []
    by_cat: dict[str, list[Range]] = {}
    upper_pairs: list[tuple[int, int]] = []
    lower_pairs: list[tuple[int, int]] = []

    pending_first: tuple[int, str] | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        f = line.split(";")
        cp = int(f[0], 16)
        name = f[1]
        cat = f[2]

        if name.endswith(", First>"):
            pending_first = (cp, cat)
            continue
        if name.endswith(", Last>"):
            lo, lo_cat = pending_first
            pending_first = None
            assigned.append((lo, cp))
            by_cat.setdefault(lo_cat, []).append((lo, cp))
            continue

        assigned.append((cp, cp))
        by_cat.setdefault(cat, []).append((cp, cp))

        if cp <= BMP_MAX:
            upper = f[12].strip()
            lower = f[13].strip()
            if upper:
                u = int(upper, 16)
                if u <= BMP_MAX:
                    upper_pairs.append((cp, u))
            if lower:
                l = int(lower, 16)
                if l <= BMP_MAX:
                    lower_pairs.append((cp, l))

    return assigned, by_cat, upper_pairs, lower_pairs


# ---------------------------------------------------------------------
# DerivedCoreProperties.txt / PropList.txt (shared "prop list" format)
# ---------------------------------------------------------------------

PROP_LINE_RE = re.compile(
    r"^([0-9A-Fa-f]{4,6})(?:\.\.([0-9A-Fa-f]{4,6}))?\s*;\s*(\S+)")


def parse_prop_file(path: Path) -> dict[str, list[Range]]:
    out: dict[str, list[Range]] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = PROP_LINE_RE.match(line)
        if not m:
            continue
        lo = int(m.group(1), 16)
        hi = int(m.group(2), 16) if m.group(2) else lo
        prop = m.group(3)
        out.setdefault(prop, []).append((lo, hi))
    return out


# ---------------------------------------------------------------------
# EastAsianWidth.txt
# ---------------------------------------------------------------------

def parse_east_asian_width(path: Path) -> list[Range]:
    wide: list[Range] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = PROP_LINE_RE.match(line)
        if not m:
            continue
        lo = int(m.group(1), 16)
        hi = int(m.group(2), 16) if m.group(2) else lo
        width = m.group(3)
        if width in ("W", "F"):
            wide.append((lo, hi))
    return wide


# ---------------------------------------------------------------------
# C emission
# ---------------------------------------------------------------------

def emit_range_table(out: list[str], c_name: str, ranges: list[Range]) -> None:
    ranges = clip_to_bmp(coalesce(ranges))
    out.append(f"const struct unicode_range {c_name}[] = {{")
    per_line = 4
    for i in range(0, len(ranges), per_line):
        chunk = ranges[i:i + per_line]
        row = " ".join(f"{{0x{lo:04x},0x{hi:04x}}}," for lo, hi in chunk)
        out.append("\t" + row)
    out.append("};")
    out.append(f"const size_t {c_name}_count = "
                f"sizeof({c_name})/sizeof({c_name}[0]);")
    out.append("")


def emit_pair_table(out: list[str], c_name: str,
                     pairs: list[tuple[int, int]]) -> None:
    # Drop no-op mappings, de-duplicate by source, sort by source.
    dedup: dict[int, int] = {}
    for src, dst in pairs:
        if src == dst:
            continue
        dedup[src] = dst
    ordered = sorted(dedup.items())
    out.append(f"const struct unicode_casepair {c_name}[] = {{")
    per_line = 4
    for i in range(0, len(ordered), per_line):
        chunk = ordered[i:i + per_line]
        row = " ".join(f"{{0x{a:04x},0x{b:04x}}}," for a, b in chunk)
        out.append("\t" + row)
    out.append("};")
    out.append(f"const size_t {c_name}_count = "
                f"sizeof({c_name})/sizeof({c_name}[0]);")
    out.append("")


def main() -> None:
    cache_dir = Path(os.environ.get("SPICULE_UCD_CACHE",
                                     tempfile.gettempdir() + "/spicule-ucd-" + UCD_VERSION))
    cache_dir.mkdir(parents=True, exist_ok=True)
    paths = fetch(cache_dir)

    assigned, by_cat, upper_pairs, lower_pairs = parse_unicode_data(
        paths["UnicodeData.txt"])
    derived = parse_prop_file(paths["DerivedCoreProperties.txt"])
    proplist = parse_prop_file(paths["PropList.txt"])
    wide = parse_east_asian_width(paths["EastAsianWidth.txt"])

    alpha = derived["Alphabetic"]
    upper_prop = derived["Uppercase"]
    lower_prop = derived["Lowercase"]
    white_space = proplist["White_Space"]
    hex_digit = proplist["Hex_Digit"]

    digit = by_cat.get("Nd", [])
    cntrl = by_cat.get("Cc", [])
    zs = by_cat.get("Zs", [])
    blank = coalesce(zs + [(0x09, 0x09)])

    notprint_cats = (by_cat.get("Cc", []) + by_cat.get("Cf", []) +
                      by_cat.get("Cs", []) + by_cat.get("Co", []) +
                      by_cat.get("Zl", []) + by_cat.get("Zp", []))
    unassigned = complement(clip_to_bmp(assigned), 0, BMP_MAX)
    notprint = coalesce(clip_to_bmp(notprint_cats) + unassigned)

    combining = coalesce(clip_to_bmp(by_cat.get("Mn", []) + by_cat.get("Me", [])))

    lines: list[str] = []
    lines.append("/* SPDX-FileCopyrightText: (C) 2026 Gavin John")
    lines.append(" * SPDX-License-Identifier: GPL-3.0-or-later")
    lines.append(" *")
    lines.append(f" * GENERATED by tools/gen-unicode-tables.py from Unicode "
                 f"{UCD_VERSION} UCD data")
    lines.append(" * (UnicodeData.txt, DerivedCoreProperties.txt, PropList.txt,")
    lines.append(" * EastAsianWidth.txt, all from "
                 f"https://www.unicode.org/Public/{UCD_VERSION}/ucd/).")
    lines.append(" * DO NOT EDIT BY HAND -- re-run the generator instead. See")
    lines.append(" * that script's own module docstring for exactly which")
    lines.append(" * Unicode property backs each table below and why.")
    lines.append(" *")
    lines.append(" * Every table is restricted to U+0000..U+FFFF (the Basic")
    lines.append(" * Multilingual Plane) because spicule's wchar_t is a single")
    lines.append(" * 16-bit UTF-16 code unit -- see include/wctype.h.")
    lines.append(" */")
    lines.append("")
    lines.append('#include "unicode_tables.h"')
    lines.append("")

    emit_range_table(lines, "unicode_alpha_ranges", alpha)
    emit_range_table(lines, "unicode_upper_ranges", upper_prop)
    emit_range_table(lines, "unicode_lower_ranges", lower_prop)
    emit_range_table(lines, "unicode_digit_ranges", digit)
    emit_range_table(lines, "unicode_space_ranges", white_space)
    emit_range_table(lines, "unicode_cntrl_ranges", cntrl)
    emit_range_table(lines, "unicode_xdigit_ranges", hex_digit)
    emit_range_table(lines, "unicode_blank_ranges", blank)
    emit_range_table(lines, "unicode_notprint_ranges", notprint)
    emit_range_table(lines, "unicode_combining_ranges", combining)
    emit_range_table(lines, "unicode_wide_ranges", wide)
    emit_pair_table(lines, "unicode_toupper_pairs", upper_pairs)
    emit_pair_table(lines, "unicode_tolower_pairs", lower_pairs)

    OUT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT_PATH}", file=sys.stderr)


if __name__ == "__main__":
    main()
