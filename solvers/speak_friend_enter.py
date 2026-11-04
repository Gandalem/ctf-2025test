"""DUCTF 2025 Speak Friend, and Enter: AES-CMAC chosen-message forgery.

The server accepts any 2048-bit RSA modulus whose CMAC equals a *fixed*
value. Because the public AES-CMAC key is NIST's Appendix D.1 example key,
a last block can be chosen to match that CMAC for an arbitrary prefix.

This module proves bypass of the original key-authentication CMAC check.
It does NOT claim to factor the forged 2048-bit modulus or sign the challenge
without a private key. The hosted Flag is not retrieved.
"""
import argparse
import re
import secrets
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import CMAC, SHA512
from Crypto.PublicKey import RSA

# NIST SP 800-38B Appendix D.1 publicly published AES test key.
# This is the known fixed MAC key imported as cryptosecrets in handout.
NIST_CMAC_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


def parse_target_mac(source: str) -> bytes:
    m = re.search(
        r"server_cmac_publickey\s*=\s*unhexlify\(['\"]([0-9a-fA-F]{32})['\"]\)",
        source,
    )
    if not m:
        raise ValueError("Original server fixed public-key MAC not found")
    return bytes.fromhex(m.group(1))


def check_source(source: str) -> None:
    required = (
        r"CMAC\.new\(NIST_SP_800_38B_Appendix_D1_K,\s*ciphermod=AES\)",
        r"mac\s*!=\s*server_cmac_publickey",
        r"public_key\.bit_length\(\)\s*!=\s*2048",
        r"pow\(signature,\s*65537,\s*r\.n\)\s*==\s*s",
    )
    for regex in required:
        if not re.search(regex, source):
            raise ValueError("Original RSA/CMAC verification assumption changed")


def cmac(data: bytes, key: bytes = NIST_CMAC_KEY) -> bytes:
    return CMAC.new(key, ciphermod=AES).update(data).digest()


def double_subkey(block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("CMAC requires 16-byte blocks")
    x = int.from_bytes(block, "big")
    return (((x << 1) & ((1 << 128) - 1)) ^ (0x87 if block[0] & 0x80 else 0)).to_bytes(16, "big")


def forge_cmac_message(prefix: bytes, target: bytes,
                       key: bytes = NIST_CMAC_KEY) -> bytes:
    """Append a 16-byte last block so CMAC(prefix+last)==target.

    Prefix must comprise whole 16-byte blocks. For a completed final
    block, CMAC encrypts CBC_state ^ last_block ^ K1. Solve for last_block.
    """
    if not prefix or len(prefix) % 16 or len(target) != 16:
        raise ValueError("CMAC prefix must be nonempty full blocks, target 16 bytes")
    if len(key) not in (16, 24, 32):
        raise ValueError("Invalid AES key size")
    aes = AES.new(key, AES.MODE_ECB)
    intermediate = bytes(16)
    for offset in range(0, len(prefix), 16):
        block = prefix[offset:offset+16]
        intermediate = aes.encrypt(bytes(x ^ y for x, y in zip(intermediate, block)))
    k1 = double_subkey(aes.encrypt(bytes(16)))
    backward = aes.decrypt(target)
    final = bytes(x ^ y ^ z for x, y, z in zip(backward, intermediate, k1))
    full = prefix + final
    if cmac(full, key) != target:
        raise AssertionError("Derived CMAC forgery did not validate")
    return full


def forge_public_modulus(source: str, prefix: bytes | None = None) -> int:
    check_source(source)
    target = parse_target_mac(source)
    if prefix is None:
        # 240 original bytes + 16 controllable final block = 2048 bits.
        prefix = bytes([0xFF]) + secrets.token_bytes(239)
    if len(prefix) != 240 or not (prefix[0] & 0x80):
        raise ValueError("Need 240-byte high-bit-set prefix for 2048-bit modulus")
    candidate = int.from_bytes(forge_cmac_message(prefix, target), "big")
    if candidate.bit_length() != 2048:
        raise ValueError("Forged candidate must be 2048-bit RSA modulus")
    return candidate


def verify_key_gate(source: str, public_modulus: int) -> bool:
    check_source(source)
    if public_modulus.bit_length() != 2048:
        return False
    encoded = public_modulus.to_bytes(256, "big")
    return cmac(encoded) == parse_target_mac(source)


def verify_signature(public_modulus: int, challenge: bytes, signature: int) -> bool:
    if public_modulus < 2 or signature < 0:
        return False
    try:
        rsa_pub = RSA.construct((public_modulus, 65537))
    except ValueError:
        return False
    digest_int = int.from_bytes(SHA512.new(challenge).digest(), "big")
    return pow(signature, 65537, rsa_pub.n) == digest_int


def local_demo(source: str) -> int:
    candidate = forge_public_modulus(source)
    if not verify_key_gate(source, candidate):
        raise ValueError("Forged modulus did not pass original MAC/length checks")
    return candidate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    candidate = local_demo(args.source.read_text(encoding="utf-8"))
    print("Forged 2048-bit public key accepted by original CMAC/bitlength checks")
    print("Forged key bit length:", candidate.bit_length())
    print("RSA signing for this modulus is NOT solved; hosted Flag not retrieved.")


if __name__ == "__main__":
    main()
