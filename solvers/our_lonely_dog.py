"""DUCTF 2025 Our Lonely Dog: extract the flag from an email *header*.

The original public write-up says to email e-dog@downunderctf.com and
inspect the returned message's custom X-FLAG header. This module reads
a saved RFC 5322/MIME response only. It never sends an email, connects
to an SMTP server or imports the published expected flag as a solution.
"""
import argparse
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path

FLAG = re.compile(r"DUCTF\{[^\s{}\r\n]{1,200}\}")
ADDRESS = "e-dog@downunderctf.com"
MAX_EMAIL_BYTES = 5_000_000


def validate_original_writeup(writeup: str) -> None:
    required = ("e-dog@downunderctf.com", "auto-reply", "X-FLAG")
    if not all(token in writeup for token in required):
        raise ValueError("Original Our Lonely Dog write-up has changed")


def extract_flag(raw: bytes) -> str:
    """Parse only headers, including headers inside nested RFC 822 emails."""
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_EMAIL_BYTES:
        raise ValueError("Invalid or oversized email message")
    message = BytesParser(policy=policy.default).parsebytes(raw)
    if message.defects:
        raise ValueError("Malformed email header: " + str(message.defects[0]))
    flags = set()
    for part in message.walk():
        for value in part.get_all("X-FLAG", []):
            # Header folding is handled by the email parser. No body search.
            flags.update(FLAG.findall(str(value)))
    if len(flags) != 1:
        raise ValueError("Expected exactly one unique X-FLAG value")
    return flags.pop()


def solve(raw: bytes, original_writeup: str) -> str:
    validate_original_writeup(original_writeup)
    return extract_flag(raw)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("saved_autoreply", type=Path, help="Raw saved .eml message")
    p.add_argument("--writeup", type=Path,
                   default=Path("data/our_lonely_dog/original_writeup.md"))
    args = p.parse_args()
    print(solve(args.saved_autoreply.read_bytes(),
                args.writeup.read_text(encoding="utf-8")))


if __name__ == "__main__":
    main()
