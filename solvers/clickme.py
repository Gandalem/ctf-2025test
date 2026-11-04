"""DUCTF 2025 ClickMe: statically decode bytes from Swift's disabled Flag button."""
import argparse
import re
from pathlib import Path

def parse_encoded_flag(swift_source: str) -> bytes:
    button = re.search(r'Button\("Flag"\)\s*\{([\s\S]*?)\}\s*\.disabled\(\)', swift_source)
    if not button:
        raise ValueError("Original disabled Flag button not found")
    code = button.group(1)
    array = re.search(r'let\s+a\s*:\s*\[UInt8\]\s*=\s*\[([^\]]+)\]', code)
    if not array:
        raise ValueError("Flag byte array not found")
    numbers = [int(s) for s in re.findall(r'\d+', array.group(1))]
    if not numbers or any(x > 255 for x in numbers):
        raise ValueError("Invalid encoded bytes")
    if not re.search(r'38\s*\*\s*i\s*\+\s*17', code):
        raise ValueError("Unrecognized index-dependent XOR formula")
    return bytes(numbers)

def solve(swift_source: str) -> str:
    encoded = parse_encoded_flag(swift_source)
    decoded = bytes(x ^ ((38 * i + 17) & 255) for i, x in enumerate(encoded))
    try:
        message = decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Decoded flag is not valid UTF-8") from exc
    if re.fullmatch(r'DUCTF\{[ -~]{1,200}\}', message) is None:
        raise ValueError("Decoded text does not match DUCTF format")
    return message

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("swift_source", type=Path)
    args = parser.parse_args()
    print(solve(args.swift_source.read_text(encoding="utf-8")))

if __name__ == "__main__":
    main()
