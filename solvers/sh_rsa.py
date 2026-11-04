"""DUCTF 2025 SH-RSA: short-hash multiplicative RSA signature analysis.

The original verifier compares just the first eight big-endian bytes of
pow(signature, e, N), with SHAKE128(N || message, 8). RSA is multiplicative:
the product of signatures verifies the product of their hash integers when
their product has the target byte prefix. The author used 92 signatures and
an accelerated subset-product search. This module provides the actual
short-hash primitive, RSA arithmetic and a bounded exact MITM helper on
small local fixtures; it does NOT claim to solve the 64-bit 92-item subset
problem or recover the hosted challenge flag.
"""
import argparse
import hashlib
import math
import re
from pathlib import Path


def int_bytes(number: int) -> bytes:
    if number < 0:
        raise ValueError("Negative unsigned integer")
    return number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")


def H(modulus: int, message: bytes) -> bytes:
    return hashlib.shake_128(int_bytes(modulus) + message).digest(8)


def sign(modulus: int, private_exponent: int, message: bytes) -> int:
    return pow(int.from_bytes(H(modulus, message), "big"), private_exponent, modulus)


def recovered_prefix(modulus: int, exponent: int, signature: int,
                     length: int = 8) -> bytes:
    if modulus <= 1 or exponent < 1 or not 0 <= signature < modulus:
        raise ValueError("Invalid RSA public key or signature")
    if not 1 <= length <= 64:
        raise ValueError("Unsupported comparison byte width")
    return int_bytes(pow(signature, exponent, modulus))[:length]


def verify(modulus: int, exponent: int, message: bytes, signature: int) -> bool:
    """Mirror the published original verify() exactly, including the flaw."""
    return recovered_prefix(modulus, exponent, signature) == H(modulus, message)


def multiply_signed_subset(modulus: int, signatures: list[int],
                           indices: list[int]) -> int:
    if not indices or len(set(indices)) != len(indices):
        raise ValueError("Select distinct signatures")
    value = 1
    for index in indices:
        if not 0 <= index < len(signatures):
            raise IndexError("Signature index outside input")
        value = value * signatures[index] % modulus
    return value


def subset_product_exact(values: list[int], target: int,
                         limit: int = 20) -> list[int] | None:
    """Exact subset-product MITM on at most 20 *synthetic* factors.

    This helper documents the subset combinatorics, not the author's
    probabilistic large-scale 92-factor approximate prefix solver.
    Excludes empty subset and rejects zero/negative factors.
    """
    if len(values) > limit or limit > 24 or limit < 1:
        raise ValueError("Bounded demo only")
    if target < 1 or any(v < 1 for v in values):
        raise ValueError("Products must be positive integers")
    mid = len(values) // 2
    left, right = values[:mid], values[mid:]
    table = {1: 0}
    for mask in range(1, 1 << len(left)):
        value = math.prod(v for i, v in enumerate(left) if mask >> i & 1)
        table[value] = mask
    for mask in range(1 << len(right)):
        product = math.prod(v for i, v in enumerate(right) if mask >> i & 1)
        if target % product:
            continue
        remain = target // product
        if remain not in table:
            continue
        left_mask = table[remain]
        if not left_mask and not mask:
            continue
        indices = ([i for i in range(len(left)) if left_mask >> i & 1]
                   + [mid + i for i in range(len(right)) if mask >> i & 1])
        if math.prod(values[i] for i in indices) == target:
            return indices
    return None


def validate_source(source: str) -> None:
    required = (
        "shake_128(long_to_bytes(N) + m).digest(8)",
        "pow(s, e, N))[:8] == H(N, m)",
        "for i in range(92):",
        "b'challenge'",
        "signal.alarm(46)",
    )
    if not all(needle in source for needle in required):
        raise ValueError("Original SH-RSA challenge contract changed")


def local_demo(source: str) -> dict:
    validate_source(source)
    # Small synthetic RSA private key, original unmodified H/sign/verify
    # formula; no original hosted challenge secrets.
    p, q, exponent = 32416190071, 32416187567, 65537
    n = p * q
    d = pow(exponent, -1, (p - 1) * (q - 1))
    message = b"offline-test"
    signature = sign(n, d, message)
    if not verify(n, exponent, message, signature):
        raise ValueError("RSA synthetic signing regression failed")
    factors = [3, 5, 7, 11, 13, 17, 19, 23]
    target = 5 * 11 * 19
    found = subset_product_exact(factors, target)
    if found is None or math.prod(factors[i] for i in found) != target:
        raise ValueError("Subset-product MITM regression failed")
    return {"synthetic_signature_valid": True,
            "subset_product": target,
            "subset_indices": found,
            "full_challenge_forged": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original_source", type=Path)
    args = parser.parse_args()
    print(local_demo(args.original_source.read_text(encoding="utf-8")))


if __name__ == "__main__":
    main()
