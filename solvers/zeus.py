"""Solve DUCTF 2025 Zeus from its original C-language challenge fixture.

The challenge uses repeated-key XOR. Parse the actual encoded byte array and
key from the original C file, rather than copying the known flag into solver.
"""
import argparse
import re
from pathlib import Path

def parse_source(source: str) -> tuple[bytes, bytes]:
    key_match = re.search(r'const\s+char\s*\*\s*key\s*=\s*"([^"]+)"', source)
    data_match = re.search(
        r'uint8_t\s+encrypted_flag\s*\[\s*\]\s*=\s*\{([^}]+)\}', source, re.S
    )
    if not key_match or not data_match:
        raise ValueError("Could not locate Zeus XOR key or encrypted bytes")
    key = key_match.group(1).encode("ascii")
    values = re.findall(r"0x([0-9a-fA-F]{1,2})\b", data_match.group(1))
    if not key or not values:
        raise ValueError("Invalid XOR key or encrypted payload")
    return bytes(int(value, 16) for value in values), key

def repeated_key_xor(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("XOR key must not be empty")
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))

def solve(source: str) -> str:
    encrypted, key = parse_source(source)
    result = repeated_key_xor(encrypted, key).decode("utf-8")
    if not re.fullmatch(r"DUCTF\{[ -~]+\}", result):
        raise ValueError("Recovered text does not match DUCTF flag format")
    return result

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Original Zeus C source fixture")
    args = parser.parse_args()
    print(solve(args.source.read_text(encoding="utf-8")))

if __name__ == "__main__":
    main()
