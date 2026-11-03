"""Statically decrypt DUCTF 2025 Skippy without executing the crashing binary.

Reads original C fixture for ciphertext, obfuscated key, and IV. The source
contains an intentional null-pointer dereference before the de-obfuscation,
but we can model the post-dereference right-shift and use OpenSSL AES-CBC.
"""
import argparse
import re
import shutil
import subprocess
from pathlib import Path

def c_array(source: str, name: str) -> bytes:
    match = re.search(
        rf"uint8_t\s+{re.escape(name)}\s*\[\s*\]\s*=\s*\{{([^}}]+)\}}",
        source, re.S,
    )
    if not match:
        raise ValueError(f"Missing {name} C byte array")
    raw = match.group(1)
    numbers = re.findall(r"0x([0-9a-fA-F]{1,2})\b", raw)
    if not numbers:
        raise ValueError(f"No hex bytes in {name}")
    return bytes(int(x, 16) for x in numbers)

def recover_material(encoded: bytes) -> bytes:
    if len(encoded) < 16:
        raise ValueError("Encoded key or IV must contain 16 bytes")
    # C decryptor shifts only the first 16 elements; extra terminator ignored.
    return bytes(x >> 1 for x in encoded[:16])

def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if not shutil.which("openssl"):
        raise RuntimeError("OpenSSL CLI is required to decrypt Skippy")
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("AES-128-CBC requires a 16-byte key and IV")
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError("Ciphertext must be a non-empty multiple of 16 bytes")
    result = subprocess.run(
        ["openssl", "enc", "-aes-128-cbc", "-d", "-nosalt", "-nopad",
         "-K", key.hex(), "-iv", iv.hex()],
        input=ciphertext, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=10,
    )
    if result.returncode:
        raise ValueError("AES decryption failed: " + result.stderr.decode(errors="replace"))
    return result.stdout

def solve(source: str) -> str:
    ciphertext = c_array(source, "precomputed")
    key = recover_material(c_array(source, "key"))
    iv = recover_material(c_array(source, "iv"))
    plaintext = decrypt_aes_cbc(ciphertext, key, iv)
    # Input is AES-CBC decrypted plaintext with padding/trailing nulls.
    match = re.search(rb"DUCTF\{[ -~]{1,500}?\}", plaintext)
    if not match:
        raise ValueError("No DUCTF flag found in decrypted plaintext")
    return match.group(0).decode("ascii")

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Original Skippy C source fixture")
    args = parser.parse_args()
    print(solve(args.source.read_text(encoding="utf-8")))

if __name__ == "__main__":
    main()
