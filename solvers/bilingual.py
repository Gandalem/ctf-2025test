"""Static DUCTF bilingual solver: recover the password and RC4-decrypt the flag.

Sources: the distributed Python file and the helper's C validation logic.
Avoids executing the embedded native DLL or trusting its eval callbacks.
"""
import argparse
import base64
import re
from pathlib import Path


def rc4(key: bytes, ciphertext: bytes) -> bytes:
    if not key:
        raise ValueError("RC4 key must not be empty")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) % 256
        state[i], state[j] = state[j], state[i]
    i = j = 0
    output = bytearray()
    for value in ciphertext:
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        output.append(value ^ state[(state[i] + state[j]) % 256])
    return bytes(output)


def source_value(source: str, variable: str) -> str:
    match = re.search(
        rf"(?m)^{re.escape(variable)}\s*=\s*['\"]([^'\"]+)['\"]", source
    )
    if not match:
        raise ValueError(f"Missing source variable {variable}")
    return match.group(1)


def c_array(source: str, variable: str) -> bytes:
    match = re.search(
        rf"\bconst\s+uint8_t\s+{re.escape(variable)}\s*\[\s*\]\s*=\s*\{{([^}}]+)\}}",
        source, re.S,
    )
    if not match:
        raise ValueError(f"Missing C array {variable}")
    values = re.findall(r"0x([0-9a-fA-F]{1,2})\b", match.group(1))
    if not values:
        raise ValueError(f"Empty C array {variable}")
    return bytes(int(value, 16) for value in values)


def candidate_passwords(helper_source: str, challenge_key: str):
    """Recover positional constraints from Check1/2/3/4 and RC4 expression.

    First character: (byte ^ 0x43) == 11.
    Fifth character: ASCII digit '0', because Check3 evaluates digit-0.
    Sixth/seventh: Check2 callback returns character +3.
    Eighth/ninth: matching digits 1-8, 11th char: digit +2.
    Remaining alphabetic positions 1-3 are determined by RC4 crib:
    encrypted callback expression is 'ord(PASSWORD[9])'.
    """
    p0 = 11 ^ 0x43
    state0 = p0 | 0x72
    p5 = (9 ^ state0) - 3
    p6 = (116 - 9) - 3
    state1 = (~(116 + 30)) & 255
    first = int(challenge_key[:4], 10)
    state3 = ((first >> 3) & 255) ^ 0x36

    encrypted = c_array(helper_source, "get_password_nine_encrypted")
    crib = "ord(PASSWORD[9])".encode("utf-16le")
    if len(crib) != len(encrypted):
        raise ValueError("Unexpected encrypted expression length")

    p9 = int(challenge_key[11:13], 10) ^ (first & 100)
    p10 = int(challenge_key[:2], 16) - 7

    for x in range(ord("a"), ord("z") + 1):
        for y in range(ord("a"), ord("z") + 1):
            for z in range(ord("a"), ord("z") + 1):
                state = bytes([
                    state0, state1, 0xCC, state3,
                    x, y, x ^ y ^ z ^ 0x10, 0xCC
                ])
                if rc4(state, encrypted) != crib:
                    continue
                for digit in range(ord("1"), ord("9")):
                    # Password positions 0..11; indexing aligns with C.
                    password = bytes([
                        p0, x, y, z, ord("0"), p5, p6,
                        digit, digit, p9, p10, digit + 2
                    ])
                    yield password.decode("ascii")


def solve(published_python: str, helper_source: str) -> tuple[str, str]:
    challenge_key = source_value(published_python, "KEY")
    cipher = base64.b64decode(source_value(published_python, "FLAG"), validate=True)
    matches = []
    for password in candidate_passwords(helper_source, challenge_key):
        plaintext = rc4(password.encode(), cipher)
        try:
            message = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if re.fullmatch(r"[a-z][a-z_]{10,150}", message):
            matches.append((password, f"DUCTF{{{message}}}"))
    if len(matches) != 1:
        raise ValueError(f"Expected one deciphered candidate; got {len(matches)}")
    return matches[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("python", type=Path, help="Original published bilingual.py")
    parser.add_argument("helper", type=Path, help="Original helper.cpp")
    args = parser.parse_args()
    password, flag = solve(
        args.python.read_text(encoding="utf-8"),
        args.helper.read_text(encoding="utf-8"),
    )
    print(f"Recovered password: {password}")
    print(flag)


if __name__ == "__main__":
    main()
