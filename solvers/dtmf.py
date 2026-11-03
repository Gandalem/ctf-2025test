"""DUCTF 2025 DTMF frequency-sums and keypad multi-tap decoder."""
import argparse
from pathlib import Path

ROWS = (697, 770, 852, 941)
COLS = (1209, 1336, 1477, 1633)
LAYOUT = ("123A", "456B", "789C", "*0#D")
SUM_TO_KEY = {
    str(low + high): LAYOUT[i][j]
    for i, low in enumerate(ROWS)
    for j, high in enumerate(COLS)
}
MULTITAP = {
    "0": " 0", "1": ".,?!1-@_+#", "2": "abc2ABC",
    "3": "def3DEF", "4": "ghi4GHI", "5": "jkl5JKL",
    "6": "mno6MNO", "7": "pqrs7PQRS",
    "8": "tuv8TUV", "9": "wxyz9WXYZ",
}

def decode_dtmf(text: str) -> str:
    stream = "".join(text.split())
    if not stream or len(stream) % 4:
        raise ValueError("Expected nonempty 4-digit frequency-sum groups")
    keys = []
    for pos in range(0, len(stream), 4):
        code = stream[pos:pos+4]
        if code not in SUM_TO_KEY:
            raise ValueError(f"Invalid frequency sum {code!r} at position {pos}")
        keys.append(SUM_TO_KEY[code])
    return "".join(keys)

def decode_multitap(keys: str) -> str:
    result = []
    i = 0
    while i < len(keys):
        key = keys[i]
        if key == "#":
            i += 1
            continue
        if key not in MULTITAP:
            raise ValueError(f"Invalid multi-tap key: {key!r}")
        j = i + 1
        while j < len(keys) and keys[j] == key:
            j += 1
        choices = MULTITAP[key]
        result.append(choices[(j - i - 1) % len(choices)])
        i = j
    return "".join(result)

def solve(text: str) -> str:
    return "DUCTF{" + decode_multitap(decode_dtmf(text)) + "}"

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    print(solve(args.input.read_text(encoding="utf-8")))

if __name__ == "__main__":
    main()
