"""DUCTF Godot: reconstruct 5-row pixel font from tile-map Vector2i coordinates.

A tile at (x,y) is one pixel. The level's tiles contain two text rows.
Letters are identified using individual 5-row glyph templates; the full
flag phrase is not stored as a literal in this solver.
"""
import argparse
import re
from pathlib import Path

FONT = {
    "## /# #/# #/# #/## ": "D",
    "# #/# #/# #/# #/###": "U",
    "###/#  /#  /#  /###": "C",
    "###/ # / # / # / # ": "T",
    "###/#  /###/#  /#  ": "F",
    " #/# /##/# / #": "{",
    "# #/# #/###/# #/# #": "H",
    "###/#  /###/#  /###": "E",
    "   /   /   /   /###": "_",
    "## /# #/## /# #/## ": "B",
    "###/# #/# #/# #/###": "O",
    "# #/# #/ # / # / # ": "Y",
    "# # #/# # #/# # #/# # #/ # # ": "W",
    "#/#/#/#/#": "I",
    "#  /#  /#  /#  /###": "L",
    "#  #/## #/####/# ##/#  #": "N",
    "# #/# #/# #/# #/ # ": "V",
    "## /# #/## /# #/# #": "R",
    "#   #/## ##/# # #/#   #/#   #": "M",
    "###/#  /## /#  /###": "E",
    "# / #/##/ #/# ": "}",
}

def parse_coordinates(source: str) -> set[tuple[int, int]]:
    match = re.search(r"@onready\s+var\s+coords\s*=\s*\[([\s\S]*?)\]", source)
    if not match:
        raise ValueError("Missing Godot coords array")
    points = {(int(x), int(y)) for x, y in re.findall(
        r"Vector2i\(\s*(-?\d+)\s*,\s*(-?\d+)\s*\)", match.group(1)
    )}
    if not points:
        raise ValueError("No pixels found in Godot source")
    return points

def glyph_rows(pixels: set[tuple[int, int]], y_start: int, height: int = 5):
    if height <= 0:
        raise ValueError("Font height must be positive")
    active = sorted({x for x, y in pixels if y_start <= y < y_start + height})
    if not active:
        return []
    result = []
    first, last = active[0], active[-1]
    column = lambda x: "".join(
        "#" if (x, y) in pixels else " " for y in range(y_start, y_start + height)
    )
    x = first
    while x <= last:
        while x <= last and column(x) == " " * height:
            x += 1
        if x > last:
            break
        begin = x
        while x <= last and column(x) != " " * height:
            x += 1
        rows = [
            "".join("#" if (col, y) in pixels else " "
                    for col in range(begin, x))
            for y in range(y_start, y_start + height)
        ]
        result.append("/".join(rows))
    return result

def decode_text(pixels: set[tuple[int, int]], starts: tuple[int, ...] = (-255, -249)) -> str:
    decoded = []
    for start in starts:
        chars = []
        for pattern in glyph_rows(pixels, start):
            if pattern not in FONT:
                raise ValueError(f"Unknown tile glyph {pattern!r} in row {start}")
            chars.append(FONT[pattern])
        decoded.append("".join(chars))
    return "_".join(decoded)

def solve(source: str) -> str:
    text = decode_text(parse_coordinates(source))
    matches = re.findall(r"DUCTF\{[A-Z_]+\}", text, re.IGNORECASE)
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one readable DUCTF flag, got {matches!r}")
    return matches[0].lower()

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    print(solve(args.source.read_text(encoding="utf-8")))

if __name__ == "__main__":
    main()
