"""DUCTF 2025 cheap logs: bounded discrete-log / heap-overlap analysis.

The original C challenge uses GMP mpz_roinit_n to point the private key's
limbs at malloc'd storage, then frees that backing buffer. Later public-key
printing reuses that heap memory, partly replacing the private exponent.
The author's attack reduces the unknown exponent to two ASLR slices and
one byte, then solves their multiplicative-group equation via a meet-in-
the-middle table.

Here a generic MITM solves an exact *small synthetic* affine exponent
whose variables represent those two slices and byte. This verifies the
math and the original source contract; it does NOT corrupt a real GMP
heap, deduce a live 36-bit ASLR secret or retrieve the hosted Flag.
"""
import argparse
import math
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Model:
    prime: int
    generator: int
    constant: int
    aslr_coefficient: int
    byte_coefficient: int
    low_bits: int
    high_bits: int
    byte_bits: int

    def validate(self) -> None:
        if self.prime <= 3 or not 1 < self.generator < self.prime:
            raise ValueError("Invalid finite-field parameters")
        if any(b < 1 or b > 12 for b in
               (self.low_bits, self.high_bits, self.byte_bits)):
            raise ValueError("Demo bounds must be <= 12 bits per variable")
        if (1 << (self.low_bits + self.byte_bits)) > 65536:
            raise ValueError("Demo MITM lookup would be too large")


def exponent(model: Model, low: int, high: int, byte: int) -> int:
    model.validate()
    for value, bits in ((low, model.low_bits),
                        (high, model.high_bits), (byte, model.byte_bits)):
        if not 0 <= value < 1 << bits:
            raise ValueError("Unknown variable out of declared range")
    return (model.constant +
            model.aslr_coefficient * (low + (high << model.low_bits)) +
            model.byte_coefficient * byte)


def observed_public(model: Model, low: int, high: int, byte: int) -> int:
    return pow(model.generator, exponent(model, low, high, byte), model.prime)


def recover_bounded(
    model: Model, public: int,
) -> tuple[int, int, int]:
    """Meet-in-the-middle: table for low ASLR bits & byte, scan high bits.

    public * g^(-constant - coefficient*low - byte_coefficient*byte)
         = (g^(coefficient*2^low_bits))^high.
    All computations occur modulo the field prime. Collision candidates
    are verified against the original public value, and ambiguous inputs
    are rejected rather than making an arbitrary guess.
    """
    model.validate()
    if not 0 < public < model.prime:
        raise ValueError("Invalid public key")
    p, g = model.prime, model.generator
    table = {}
    base_inv = pow(pow(g, model.constant, p), -1, p)
    low_base_inv = pow(pow(g, model.aslr_coefficient, p), -1, p)
    byte_base_inv = pow(pow(g, model.byte_coefficient, p), -1, p)
    byte_factor = 1
    for byte in range(1 << model.byte_bits):
        low_factor = 1
        for low in range(1 << model.low_bits):
            target = public * base_inv * low_factor * byte_factor % p
            table.setdefault(target, []).append((low, byte))
            low_factor = low_factor * low_base_inv % p
        byte_factor = byte_factor * byte_base_inv % p
    giant = pow(g, model.aslr_coefficient << model.low_bits, p)
    rhs = 1
    matches = []
    for high in range(1 << model.high_bits):
        for low, byte in table.get(rhs, []):
            if observed_public(model, low, high, byte) == public:
                matches.append((low, high, byte))
                if len(matches) > 1:
                    raise ValueError("Ambiguous bounded discrete-log solution")
        rhs = rhs * giant % p
    if not matches:
        raise ValueError("No bounded discrete-log solution")
    return matches[0]


def validate_original_source(original: str, author: str) -> None:
    challenge_checks = (
        "mpz_roinit_n(priv, buf, nb / sizeof(mp_limb_t))",
        "free(buf);",
        "mpz_powm_sec(pub, g, priv, p);",
        "mpz_inp_str(guess, stdin, 16);",
        "PRIVKEY_SIZE 2184",
    )
    author_checks = (
        "PolynomialRing(ZZ",
        "L1, L2, B",
        "rhs_mem",
        "2**18",
    )
    if any(needle not in original for needle in challenge_checks):
        raise ValueError("Original GMP backing-buffer vulnerability changed")
    if any(needle not in author for needle in author_checks):
        raise ValueError("Original author's MITM variable model changed")


def original_modulus(original: str) -> int:
    # Extract only contiguous hex chunks passed to mpz_set_str(p,...,16).
    match = re.search(r'mpz_set_str\(\s*p,\s*((?:"[0-9A-Fa-f]+"\s*)+),\s*16\)', original)
    if not match:
        raise ValueError("Original public modulus not found")
    return int("".join(re.findall(r'"([0-9A-Fa-f]+)"', match.group(1))), 16)


def local_demo(original: str, author: str) -> dict:
    validate_original_source(original, author)
    published_p = original_modulus(original)
    if published_p.bit_length() < 900:
        raise ValueError("Unexpected small published modulus")
    # Deliberately different tiny local field; the original field does not
    # contain a known discrete log. Recover the three synthetic unknowns.
    model = Model(
        prime=2305843009213693951, generator=37, constant=1234567,
        aslr_coefficient=104729, byte_coefficient=65537,
        low_bits=5, high_bits=6, byte_bits=4,
    )
    expected = (21, 37, 11)
    public = observed_public(model, *expected)
    recovered = recover_bounded(model, public)
    if recovered != expected:
        raise ValueError("Synthetic exponent recovery failed")
    return {
        "published_modulus_bits": published_p.bit_length(),
        "synthetic_unknowns": recovered,
        "original_heap_exploited": False,
        "hosted_flag_recovered": False,
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("original_challenge", type=Path)
    p.add_argument("original_solver", type=Path)
    a = p.parse_args()
    print(local_demo(a.original_challenge.read_text(encoding="utf-8"),
                     a.original_solver.read_text(encoding="utf-8")))


if __name__ == "__main__":
    main()
