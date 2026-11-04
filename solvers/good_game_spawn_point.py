"""Good Game Spawn Point: bounded Paillier / P-256 quotient leakage.

Given published (p,q), an attacker-chosen Paillier encryption of k and the
server's MTA response and beta_pub, derive the EC point

   H = (k*B + beta*G - alpha*G) / n = floor((k*secret+beta)/n) * G

where alpha is the decrypted Paillier response. Recover a *bounded*
discrete logarithm with BSGS; each observation narrows the secret interval.
This is reusable cryptanalytic machinery, not the full 256-bit DUCTF attack:
the local integration demo uses a deliberately small secret and bounded
search. It never returns a known Flag or connects to remote targets.
"""
import argparse
import importlib.util
import math
import re
from dataclasses import dataclass
from pathlib import Path

from Crypto.PublicKey import ECC
from Crypto.Util.number import getPrime

ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GENERATOR = ECC._curves["P-256"].G


def validate_source(source: str) -> None:
    required = (
        r"def mta_response\(ciphertext, n, secret\):",
        r"def zk_schnorr\(beta\):",
        r"mta_response = pow\(ciphertext, secret, nsq\)",
        r"beta = secrets.randbelow\(n\)",
        r"beta_pub",
        r'print\("paillier key:", \{"p": p, "q": q\}\)',
    )
    if any(re.search(expr, source) is None for expr in required):
        raise ValueError("Original GGSP challenge source changed")


def paillier_encrypt(k: int, n: int) -> int:
    """Valid Paillier ciphertext for attacker-controlled plaintext, r=1."""
    if not 0 <= k < n:
        raise ValueError("Plaintext outside Paillier modulus")
    return pow(n + 1, k, n * n)


def paillier_decrypt(cipher: int, p: int, q: int) -> int:
    n = p * q
    if not 0 <= cipher < n * n:
        raise ValueError("Invalid Paillier ciphertext")
    lam = (p - 1) * (q - 1)
    l_value = (pow(cipher, lam, n * n) - 1) // n
    return l_value * pow(lam, -1, n) % n


def point_key(point) -> tuple[int, int]:
    return int(point.x), int(point.y)


def bounded_log(point, limit: int) -> int | None:
    """Memory O(sqrt(limit)), work O(sqrt(limit)), not 2^256 capable."""
    if limit < 0 or limit > 10_000_000:
        raise ValueError("Bounded-log limit must be in 0..10 million")
    if point.is_point_at_infinity():
        return 0
    step = math.isqrt(limit + 1) + 1
    baby = {}
    cur = GENERATOR * 0
    for j in range(step):
        baby.setdefault(point_key(cur) if not cur.is_point_at_infinity()
                        else None, j)
        cur = cur + GENERATOR
    giant_step = -(GENERATOR * step)
    candidate = point
    for i in range(step + 1):
        key = None if candidate.is_point_at_infinity() else point_key(candidate)
        j = baby.get(key)
        if j is not None:
            result = i * step + j
            if result <= limit and GENERATOR * result == point:
                return result
        candidate = candidate + giant_step
    return None


@dataclass(frozen=True)
class Observation:
    lower: int
    upper: int
    quotient: int


def decrypt_observation(k: int, p: int, q: int, public_point,
                        mta_cipher: int, beta_point,
                        max_quotient: int) -> Observation:
    n = p * q
    if not 0 < k < n or n % ORDER == 0:
        raise ValueError("Invalid scalar or modulus")
    alpha = paillier_decrypt(mta_cipher, p, q)
    numerator = public_point * (k % ORDER) + beta_point - GENERATOR * (alpha % ORDER)
    target = numerator * pow(n, -1, ORDER)
    quotient = bounded_log(target, max_quotient)
    if quotient is None:
        raise ValueError("Quotient outside supplied bounded-log range")
    # beta is uniformly 0 <= beta < n, so qn <= ks+beta < (q+1)n
    # implies ((q-1)n < ks < (q+1)n) as a conservative interval.
    lower = max(0, ((quotient - 1) * n) // k)
    upper = ((quotient + 1) * n) // k + 1
    return Observation(lower, upper, quotient)


def recover_small_secret(observations: list[Observation],
                         public_point, max_brute: int = 4096) -> int:
    if not observations:
        raise ValueError("No observations")
    lo = max(o.lower for o in observations)
    hi = min(o.upper for o in observations)
    if hi < lo or hi - lo + 1 > max_brute:
        raise ValueError("Final interval not small enough for controlled test")
    matches = [v for v in range(lo, hi + 1) if GENERATOR * v == public_point]
    if len(matches) != 1:
        raise ValueError("No unique scalar in bounded interval")
    return matches[0]


def original_local_demo(source_file: Path, secret: int = 12345) -> int:
    source = source_file.read_text(encoding="utf-8")
    validate_source(source)
    if not 1 <= secret < (1 << 16):
        raise ValueError("Demo secret must be 16-bit (not a full-sized key)")
    spec = importlib.util.spec_from_file_location("_ductf_ggsp", source_file)
    if spec is None or spec.loader is None:
        raise ValueError("Cannot load original public CTF fixture")
    import sys
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    p, q = getPrime(384), getPrime(384)
    n = p * q
    pub = GENERATOR * secret
    observations = []
    # Two valid attacker ciphertext queries with different bucket widths.
    for divisor in (32, 128):
        k = n // divisor
        response, beta = module.mta_response(paillier_encrypt(k, n), n, secret)
        proof = module.zk_schnorr(beta)
        bp = proof["beta_pub"]
        beta_point = ECC.EccPoint(bp["x"], bp["y"], curve="P-256")
        observations.append(decrypt_observation(
            k, p, q, pub, response, beta_point,
            max_quotient=(1 << 16) // divisor + 3,
        ))
    return recover_small_secret(observations, pub)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    print("Recovered small synthetic EC secret:", original_local_demo(args.source))
    print("The full 256-bit contest key and hosted Flag are NOT recovered.")


if __name__ == "__main__":
    main()
