"""DUCTF 2025 Trusted: reconstruct Gemini input challenge from the write-up.

Reuses the existing Horoscopes Gemini URL/response implementation. The
original Trusted admin capsule is a continuation of Horoscopes; the public
2025 instance is not contacted. Test fixtures contain synthetic Gemini
status 11, real published challenge wording and a synthetic success flag.

The write-up includes an anomalous raw '1111 ...' header; parse that
separately rather than silently claiming it is a normal Gemini response.
"""
import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from solvers import horoscopes

FLAG = re.compile(r"DUCTF\{[^{}\r\n]{1,200}\}")
EXPECTED_LOGIN = "password_protected.gmi"


@dataclass(frozen=True)
class ChallengeInfo:
    port: int
    phrase: str
    response: str
    login_path: str


def parse_writeup(original: str) -> ChallengeInfo:
    port_match = re.search(r"\bport is (\d{2,5})\b", original)
    phrase_match = re.search(r'Today.s authentication phrase:\s*"([^"\r\n]+)"', original)
    answer_match = re.search(r'(?m)^Response:\s*"([^"\r\n]+)"\s*$', original)
    route = re.search(r"=>\s+(password_protected\.gmi)\s+Login", original)
    if not all((port_match, phrase_match, answer_match, route)):
        raise ValueError("Original Trusted public write-up changed")
    port = int(port_match.group(1))
    if not 1 <= port <= 65535:
        raise ValueError("Invalid original admin port")
    return ChallengeInfo(port, phrase_match.group(1),
                         answer_match.group(1), "/" + route.group(1))


def input_prompt(raw: bytes, expected_phrase: str) -> str:
    """Check Gemini 11 input status; support documented malformed 1111 variant."""
    if not isinstance(raw, bytes):
        raise ValueError("Input prompt must be bytes")
    if raw.startswith(b"11 "):
        status, meta, _ = horoscopes.parse_response(raw)
        if status != 11:
            raise ValueError("Expected Gemini input status 11")
        prompt = meta
    elif raw.startswith(b"1111 "):
        # This is an anomalous archival response, NOT standards-valid Gemini.
        # The writeup's raw hex depicts 1111 followed by the prompt.
        first = raw.split(b"\r\n", 1)[0]
        prompt = first[5:].decode("utf-8").strip().rstrip(":")
    else:
        raise ValueError("Expected Gemini input status 11 or archived 1111")
    if expected_phrase not in prompt:
        raise ValueError("Unexpected Gemini authentication question")
    return prompt


def build_request(hostname: str, info: ChallengeInfo, input_data: bytes) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9.-]+", hostname) or hostname.startswith("-"):
        raise ValueError("Invalid Gemini hostname")
    input_prompt(input_data, info.phrase)
    # Quote '+' as %2B, '=' as %3D, '%' as %25; use quote_plus for
    # the historical form-encoded space '+', as in the public write-up.
    from urllib.parse import quote_plus
    encoded = quote_plus(info.response, safe="")
    url = f"gemini://{hostname}:{info.port}{info.login_path}?{encoded}"
    return horoscopes.gemini_request(url)


def verify_response(raw: bytes) -> str:
    status, _meta, body = horoscopes.parse_response(raw)
    if status != 20:
        raise ValueError(f"Gemini authentication failed ({status})")
    candidates = set(FLAG.findall(body))
    if len(candidates) != 1:
        raise ValueError("Expected exactly one successful Gemini flag")
    return candidates.pop()


def solve_offline(original_writeup: str, prompt: bytes, response: bytes,
                  hostname: str = "chal.2025.ductf.net") -> tuple[int, bytes, str]:
    info = parse_writeup(original_writeup)
    request = build_request(hostname, info, prompt)
    return info.port, request, verify_response(response)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("original_writeup", type=Path)
    p.add_argument("saved_gemini_input", type=Path)
    p.add_argument("saved_gemini_response", type=Path)
    args = p.parse_args()
    port, request, flag = solve_offline(
        args.original_writeup.read_text(encoding="utf-8"),
        args.saved_gemini_input.read_bytes(),
        args.saved_gemini_response.read_bytes(),
    )
    print("Admin TCP port:", port)
    print("Reconstructed Gemini request:", request.decode().strip())
    print("Saved response flag:", flag)
    print("No public contest Gemini service contacted.")


if __name__ == "__main__":
    main()
