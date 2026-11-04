"""ECB-a-tron 9000: chosen-plaintext byte-at-a-time suffix recovery.

The algorithm needs only an encryption oracle implementing AES-ECB of
attacker-controlled bytes || unknown secret. No assumed secret, key or flag
is stored in the solver. The provided CLI uses a synthetic local oracle.
"""
import argparse
import re
from pathlib import Path
from typing import Callable

BLOCK_SIZE = 16


def secret_length(oracle: Callable[[bytes], bytes]) -> int:
    initial = len(oracle(b""))
    if initial == 0 or initial % BLOCK_SIZE:
        raise ValueError("Unexpected ciphertext size or block size")
    for pad_count in range(1, BLOCK_SIZE + 1):
        encrypted_len = len(oracle(b"A" * pad_count))
        if encrypted_len > initial:
            return initial - pad_count
    raise ValueError("Unable to determine unknown suffix length")


def recover_secret(
    oracle: Callable[[bytes], bytes],
    batch_oracle: Callable[[list[bytes]], list[bytes]] | None = None,
    max_length: int = 512,
) -> bytes:
    """Recover the secret, even if it ends in spaces or binary bytes."""
    n = secret_length(oracle)
    if n > max_length:
        raise ValueError("Secret exceeds configured search bound")
    result = bytearray()
    for i in range(n):
        pad = b"A" * (BLOCK_SIZE - 1 - (i % BLOCK_SIZE))
        block_number = i // BLOCK_SIZE
        target = oracle(pad)[block_number * BLOCK_SIZE:(block_number + 1) * BLOCK_SIZE]
        probes = [pad + result + bytes([candidate]) for candidate in range(256)]
        ciphertexts = batch_oracle(probes) if batch_oracle is not None else [oracle(p) for p in probes]
        if len(ciphertexts) != len(probes):
            raise ValueError("Batch oracle returned incorrect number of results")
        matches = [
            candidate
            for candidate, ciphertext in enumerate(ciphertexts)
            if ciphertext[block_number * BLOCK_SIZE:(block_number + 1) * BLOCK_SIZE] == target
        ]
        if len(matches) != 1:
            raise ValueError(f"Unable to identify byte {i}; matches={len(matches)}")
        result.append(matches[0])
    return bytes(result)


def validate_source(source: str) -> None:
    """Guard against accidentally testing a different encryption protocol."""
    required = [
        r"KEY\s*=\s*secrets\.token_bytes\(16\)",
        r'SECRET\s*=\s*os\.getenv\("SECRET"\)\.encode\(\)',
        r"full_pt\s*=\s*pt\s*\+\s*SECRET",
        r"AES\.new\(KEY,\s*AES\.MODE_ECB\)",
        r'pad_len\s*=\s*16\s*-\s*len\(msg\)\s*%\s*16',
    ]
    for pattern in required:
        if not re.search(pattern, source):
            raise ValueError(f"Original ECB oracle property missing: {pattern}")


def local_oracle(secret: bytes, key: bytes):
    """Equivalent of the original backend's ECB encrypt and space padding."""
    from Crypto.Cipher import AES
    if len(key) != BLOCK_SIZE:
        raise ValueError("AES-128 key must be 16 bytes")

    def encrypt(probe: bytes) -> bytes:
        plaintext = probe + secret
        padding = BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE)
        return AES.new(key, AES.MODE_ECB).encrypt(plaintext + b" " * padding)

    def batch(probes: list[bytes]) -> list[bytes]:
        if len(probes) > 256:
            raise ValueError("Original batch endpoint supports at most 256")
        return [encrypt(value) for value in probes]

    return encrypt, batch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original_backend", type=Path)
    parser.add_argument("--fixture-secret", default="DUCTF{SYNTHETIC_ECB_DEMO}")
    args = parser.parse_args()
    validate_source(args.original_backend.read_text(encoding="utf-8"))
    oracle, batch = local_oracle(args.fixture_secret.encode(), bytes(range(16)))
    recovered = recover_secret(oracle, batch)
    print("Recovered synthetic local suffix:", recovered.decode("utf-8"))
    print("The original hosted challenge's secret has NOT been retrieved.")


if __name__ == "__main__":
    main()
