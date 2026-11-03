"""Recover the leaked API key in the original DUCTF mini-me source map.

This is static analysis of a local CTF fixture, not an HTTP exploit.  A real
running server's flag endpoint is intentionally not accessed by this solver.
"""
import argparse
import json
import re
from pathlib import Path

DEFINITIONS = re.compile(
    r'\b([A-Za-z_$][\w$]*)\s*=\s*\[\s*["\x27](\d+)["\x27]\s*\]'
)
ARRAY = re.compile(r'\bconst\s+dhgyvu\s*=\s*\[([\s\S]*?)\];')
REFERENCE = re.compile(r'\b([A-Za-z_$][\w$]*)\s*\[\s*0\s*\]')

def extract_key(source_map: str) -> str:
    payload = json.loads(source_map)
    sources = payload.get("sourcesContent")
    if not isinstance(sources, list):
        raise ValueError("No sourcesContent in source map")
    for source in sources:
        if not isinstance(source, str):
            continue
        match = ARRAY.search(source)
        if not match:
            continue
        numbers = dict((name, int(num)) for name, num in DEFINITIONS.findall(source))
        references = REFERENCE.findall(match.group(1))
        if not references:
            raise ValueError("Source map contains no key components")
        if any(name not in numbers for name in references):
            raise ValueError("Missing obfuscated key components")
        # Exact inversion of JS source: fromCharCode(Number(x) ^ (index + 1) ^ 0)
        return "".join(chr(numbers[name] ^ (i + 1)) for i, name in enumerate(references))
    raise ValueError("Source map contains no known obfuscated key array")

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_map", type=Path)
    args = parser.parse_args()
    print("Recovered X-API-Key:", extract_key(args.source_map.read_text(encoding="utf-8")))
    print("Flag requires a local running challenge endpoint; no flag is inferred from the key.")

if __name__ == "__main__":
    main()
