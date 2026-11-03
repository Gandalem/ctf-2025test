"""Rocky (DUCTF 2025): wordlist-driven MD5 preimage + AES-CBC decrypt.

Uses original challenge C arrays as input. This solver does NOT hard-code
the known password: it searches caller-supplied wordlist candidates. Only
small demo wordlists are included; a real attack requires an appropriate
dictionary such as rockyou.txt.
"""
import argparse
import hashlib
import re
import subprocess
from pathlib import Path


def parse_c_bytes(source: str, variable: str) -> bytes:
    match = re.search(
        rf"\buint8_t\s+{re.escape(variable)}\s*\[\s*\]\s*=\s*\{{([^}}]+)\}}",
        source,
        flags=re.DOTALL,
    )
    if match is None:
        raise ValueError(f"Missing C byte array {variable}")
    hexes = re.findall(r"0x([0-9a-fA-F]{1,2})\b", match.group(1))
    if not hexes:
        raise ValueError(f"Empty C byte array {variable}")
    return bytes(int(s, 16) for s in hexes)


def find_password(md5_digest: bytes, candidates: list[str]) -> str:
    if len(md5_digest) != 16:
        raise ValueError("MD5 digest must have 16 bytes")
    for candidate in candidates:
        candidate = candidate.rstrip("\r\n")
        if hashlib.md5(candidate.encode("utf-8")).digest() == md5_digest:
            if len(candidate.encode("utf-8")) != 16:
                raise ValueError("Matching password is not an AES-128 key")
            return candidate
    raise ValueError("No candidate matches the supplied MD5 digest")


def decrypt_cbc(ciphertext: bytes, password: str) -> bytes:
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError("Ciphertext must be a nonempty multiple of 16 bytes")
    key = password.encode("utf-8")
    if len(key) != 16:
        raise ValueError("Rocky needs a 16-byte AES-128 key")
    iv = key[::-1]
    result = subprocess.run(
        ["openssl", "enc", "-aes-128-cbc", "-d", "-nosalt", "-nopad",
         "-K", key.hex(), "-iv", iv.hex()],
        input=ciphertext,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15,
    )
    if result.returncode:
        raise ValueError("OpenSSL failed: " + result.stderr.decode(errors="replace"))
    return result.stdout


def solve(source: str, candidates: list[str]) -> str:
    md5_digest = parse_c_bytes(source, "hash")
    ciphertext = parse_c_bytes(source, "precomputed")
    password = find_password(md5_digest, candidates)
    plaintext = decrypt_cbc(ciphertext, password)
    found = re.search(rb"DUCTF\{[ -~]{1,300}?\}", plaintext)
    if not found:
        raise ValueError("Decryption did not contain a valid DUCTF flag")
    return found.group(0).decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Original Rocky C source fixture")
    parser.add_argument("wordlist", type=Path, help="UTF-8 candidate password list")
    args = parser.parse_args()
    candidates = args.wordlist.read_text(encoding="utf-8").splitlines()
    print(solve(args.source.read_text(encoding="utf-8"), candidates))


if __name__ == "__main__":
    main()
