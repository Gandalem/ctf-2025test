"""SwiftPasswordManager: LoadMe -- decode original SPM1 + AES-256-GCM file.

The master password is provided in the public CTF prompt ("DUCTF2025!").
The scheme is reconstructed from upstream Swift CryptoHelper/FileManager
and BinaryEncoder; authentication uses AES-GCM, not a plaintext search.
"""
import argparse
import base64
import hashlib
import re
import struct
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, size: int) -> bytes:
        if size < 0 or size > len(self.data) - self.offset:
            raise ValueError("Unexpected end of SPM data")
        result = self.data[self.offset:self.offset + size]
        self.offset += size
        return result

    def number(self, fmt: str) -> int:
        return struct.unpack("<" + fmt, self.take(struct.calcsize("<" + fmt)))[0]

    def string(self) -> str:
        size = self.number("I")
        return self.take(size).decode("utf-8")


def load_file(raw: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    reader = Reader(raw)
    if reader.take(4) != b"SPM1":
        raise ValueError("Invalid SPM file magic")
    if reader.number("H") != 1:
        raise ValueError("Unsupported SPM file version")
    reader.number("H")  # Reserved flags.
    salt = reader.take(reader.number("H"))
    nonce = reader.take(reader.number("H"))
    tag = reader.take(reader.number("H"))
    ciphertext = reader.take(reader.number("I"))
    if reader.offset != len(raw):
        raise ValueError("Unexpected trailing data in SPM file")
    if len(salt) != 32 or len(nonce) != 12 or len(tag) != 16:
        raise ValueError("Unexpected AES-GCM salt, nonce, or tag length")
    return salt, nonce, tag, ciphertext


def derive_key(password: str, salt: bytes) -> bytes:
    value = password.encode("utf-8")
    for _ in range(0xAAAA):
        value = hashlib.sha256(value + salt).digest()
    return value


def decode_entries(plaintext: bytes) -> list[dict[str, object]]:
    reader = Reader(plaintext)
    count = reader.number("I")
    if count > 10000:
        raise ValueError("SPM entry count is unreasonably large")
    entries = []
    for _ in range(count):
        identifier = str(uuid.UUID(bytes=reader.take(16)))
        entries.append({
            "id": identifier,
            "title": reader.string(),
            "username": reader.string(),
            "password": reader.string(),
            "notes": reader.string(),
            "created_at": reader.number("q"),
            "modified_at": reader.number("q"),
        })
    if reader.offset != len(plaintext):
        raise ValueError("SPM plaintext contains trailing data")
    return entries


def solve(file_bytes: bytes, master_password: str) -> list[dict[str, object]]:
    salt, nonce, tag, ciphertext = load_file(file_bytes)
    key = derive_key(master_password, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext + tag, None)
    return decode_entries(plaintext)


def flags_in(entries: list[dict[str, object]]) -> list[str]:
    flags: set[str] = set()
    for entry in entries:
        for field in ("title", "username", "password", "notes"):
            value = entry[field]
            if isinstance(value, str):
                flags.update(re.findall(r"DUCTF\{[^{}\r\n]{1,200}\}", value))
    return sorted(flags)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path, help="Original SPM fixture in base64 text")
    parser.add_argument("--password", default="DUCTF2025!", help="CTF prompt master password")
    args = parser.parse_args()
    data = base64.b64decode(args.fixture.read_text(encoding="ascii"), validate=False)
    entries = solve(data, args.password)
    print(f"Recovered {len(entries)} login entries")
    for index, entry in enumerate(entries, 1):
        print(f"[{index}] title={entry['title']!r}, username={entry['username']!r}, "
              f"password={entry['password']!r}")
    found = flags_in(entries)
    if found:
        for flag in found:
            print(flag)
    else:
        print("No DUCTF flag found in decoded login fields.")


if __name__ == "__main__":
    main()
