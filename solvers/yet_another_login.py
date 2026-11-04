"""yet another login: Paillier verification oracle + SHA-256 length extension.

Offline CTF solution. Uses an oracle callback for authenticated-token
verification. Does NOT know or recover the server's random 16-byte key.
Requires the original public Paillier modulus and a registered user token.
"""
import argparse
import hashlib
import re
import struct
from pathlib import Path
from typing import Callable

MASK = (1 << 32) - 1
K = (
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
)
INIT = (0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)

def sha_padding(message_length: int) -> bytes:
    if message_length < 0:
        raise ValueError("Invalid original length")
    zero_bytes = (56 - (message_length + 1) % 64) % 64
    return b"\x80" + b"\x00" * zero_bytes + struct.pack(">Q", message_length * 8)

def rotr(value: int, shift: int) -> int:
    return ((value >> shift) | (value << (32 - shift))) & MASK

def compress(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    if len(state) != 8 or len(block) != 64:
        raise ValueError("SHA256 requires 8 state words and 64-byte block")
    words = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        x, y = words[i - 15], words[i - 2]
        s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
        s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >> 10)
        words.append((words[i - 16] + s0 + words[i - 7] + s1) & MASK)
    a,b,c,d,e,f,g,h = state
    for i in range(64):
        s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        temp1 = (h + s1 + ch + K[i] + words[i]) & MASK
        s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (s0 + maj) & MASK
        a,b,c,d,e,f,g,h = (temp1 + temp2) & MASK,a,b,c,(d + temp1) & MASK,e,f,g
    return tuple((s + x) & MASK for s,x in zip(state,(a,b,c,d,e,f,g,h)))

def sha256_extend(digest: bytes, total_original_len: int, suffix: bytes) -> tuple[bytes, bytes]:
    """Get SHA256(secret || msg || glue || suffix) without knowing secret."""
    if len(digest) != 32:
        raise ValueError("Expected 32-byte SHA256 digest")
    glue = sha_padding(total_original_len)
    state = struct.unpack(">8I", digest)
    prefix_len = total_original_len + len(glue)
    message = suffix + sha_padding(prefix_len + len(suffix))
    for pos in range(0, len(message), 64):
        state = compress(state, message[pos:pos + 64])
    return glue, struct.pack(">8I", *state)

def as_bytes(number: int) -> bytes:
    if number < 0:
        raise ValueError("Negative token")
    return number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")

def homomorphic_add(ciphertext: int, value: int, n: int) -> int:
    """Paillier public-key addition E(m+value) = E(m) * (n+1)^value."""
    n_squared = n * n
    return ciphertext * pow(n + 1, value % n, n_squared) % n_squared

def recover_mac_hash(
    n: int, registered_ciphertext: int, message: bytes,
    verify: Callable[[bytes, int], bool], bits: int = 256,
) -> bytes:
    """Obtain a 256-bit MAC using only the flawed byte-truncated verify oracle.

    Verifier accepts iff the decrypted integer's trailing 32 bytes
    equal the correct SHA256 digest. Before a bit is learned, scaling
    (digest - recovered_low_bits) by 2^(255 - bit) moves the first unknown
    low bit into a detectable position while the server modulus is large
    enough not to wrap this 512-bit probe.
    """
    if bits != 256:
        raise ValueError("This service uses a 256-bit SHA256 MAC")
    if n.bit_length() < 513:
        raise ValueError("Need modulus >512 bits to avoid Paillier wrap during probes")
    n_squared = n * n
    g = n + 1
    known = 0
    for bit in range(bits):
        offset = homomorphic_add(registered_ciphertext, -known, n)
        candidate = registered_ciphertext * pow(offset, 1 << (255-bit), n_squared) % n_squared
        if not verify(message, candidate):
            known |= 1 << bit
    digest = known.to_bytes(32, "big")
    return digest

def forge_admin_token(
    n: int, original_message: bytes, recovered_digest: bytes,
    secret_length: int = 16, suffix: bytes = b"user=admin",
) -> bytes:
    glue, digest = sha256_extend(
        recovered_digest, secret_length + len(original_message), suffix
    )
    forged_message = original_message + glue + suffix
    # r=1 yields valid Paillier encryption of the forged MAC, which is
    # enough for TokenService.verify; ciphertext randomization is not checked.
    forged_cipher = pow(n + 1, int.from_bytes(digest, "big"), n * n)
    return forged_message + b"|" + as_bytes(forged_cipher)

def validate_source(source: str) -> None:
    patterns = (
        r"self\.secret\s*=\s*os\.urandom\(16\)",
        r"sha256\(self\.secret\s*\+\s*msg\)",
        r"self\.g\s*=\s*self\.n\s*\+\s*1",
        r"return h == w\[-32:\]",
        r"msg,\s*_,\s*mac\s*=\s*token\.partition\(b'\|'\)",
        r"msg\.rpartition\(b'user='\)\[2\]",
    )
    if any(re.search(p, source) is None for p in patterns):
        raise ValueError("Source differs from intended original CTF service")

def local_demo(source: str) -> tuple[bytes, bytes]:
    """Use the *original* TokenService class in a local test namespace."""
    validate_source(source)
    scope = {"__name__": "_ctf_fixture_"}
    # Only execute a trusted original DUCTF Python source fixture.
    exec(compile(source, "<original-DUCTF-chall>", "exec"), scope)
    service = scope["TokenService"]()
    original_message = b"user=user"
    full_token = original_message + b"|" + service.generate(original_message)
    _, _, registered_mac = full_token.partition(b"|")
    ciphertext = int.from_bytes(registered_mac, "big")
    recovered = recover_mac_hash(
        service.n, ciphertext, original_message,
        lambda message, encrypted: service.verify(message, as_bytes(encrypted))
    )
    forged = forge_admin_token(service.n, original_message, recovered)
    msg, _, mac = forged.partition(b"|")
    if not service.verify(msg, mac) or msg.rpartition(b"user=")[2] != b"admin":
        raise ValueError("Forged local admin token was rejected")
    return recovered, forged

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Trusted original DUCTF chall.py")
    args = parser.parse_args()
    digest, token = local_demo(args.source.read_text(encoding="utf-8"))
    print("Recovered local hidden-key SHA256:", digest.hex())
    print("Local forged admin token accepted; token bytes:", len(token))
    print("This is a local reproduction; no hosted server Flag is claimed.")

if __name__ == "__main__":
    main()
