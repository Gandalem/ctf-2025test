"""Horoscopes (DUCTF 2025): parse Gemini protocol and crawl a local capsule.

The challenge is hosted on Gemini (TCP/TLS port 1965), not HTTP. This
standalone solver reads original public .gmi handouts via an offline
Gemini-style response callback. It can also parse real Gemini responses.
"""
import argparse
import re
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, urlparse

FLAG = re.compile(r"DUCTF\{[^{}\r\n]{1,200}\}")
LINK = re.compile(r"(?m)^=>\s+(\S+)(?:\s+([^\r\n]+))?$")

def gemini_request(url: str) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme != "gemini" or not parsed.hostname:
        raise ValueError("Gemini URL must contain a host and gemini:// scheme")
    if "\r" in url or "\n" in url:
        raise ValueError("No line breaks allowed in request URL")
    return url.encode("utf-8") + b"\r\n"

def parse_response(raw: bytes) -> tuple[int, str, str]:
    header, sep, body = raw.partition(b"\r\n")
    if not sep or len(header) < 3 or not header[:2].isdigit() or header[2:3] != b" ":
        raise ValueError("Invalid Gemini header")
    status = int(header[:2])
    if not 10 <= status <= 69:
        raise ValueError("Invalid Gemini status")
    meta = header[3:].decode("utf-8")
    if len(header) > 1024:
        raise ValueError("Gemini response header too long")
    return status, meta, body.decode("utf-8")

def links(body: str, current_url: str) -> list[str]:
    return [urljoin(current_url, item.group(1)) for item in LINK.finditer(body)]

def crawl(start_url: str, request: Callable[[str], bytes], limit: int = 25) -> list[str]:
    """Breadth-first traversal of Gemini text/gemini pages on same host."""
    if limit <= 0:
        raise ValueError("Crawl limit must be positive")
    start = urlparse(start_url)
    if start.scheme != "gemini" or not start.hostname:
        raise ValueError("Invalid start URL")
    pending = [start_url]
    visited: set[str] = set()
    found: set[str] = set()
    while pending and len(visited) < limit:
        current = pending.pop(0)
        if current in visited:
            continue
        visited.add(current)
        status, meta, body = parse_response(request(current))
        if status != 20 or not meta.startswith("text/gemini"):
            continue
        found.update(FLAG.findall(body))
        for link in links(body, current):
            parsed = urlparse(link)
            if parsed.scheme == "gemini" and parsed.hostname == start.hostname and link not in visited:
                if link not in pending:
                    pending.append(link)
    return sorted(found)

def local_capsule(root: Path) -> Callable[[str], bytes]:
    """Serve only existing .gmi files in original public challenge fixture."""
    if not (root / "index.gmi").is_file():
        raise ValueError("Missing original Gemini index.gmi")
    def request(url: str) -> bytes:
        gemini_request(url)
        parsed = urlparse(url)
        relative = parsed.path.lstrip("/") or "index.gmi"
        file = (root / relative).resolve()
        if root.resolve() not in file.parents or file.suffix != ".gmi":
            return b"51 NOT FOUND\r\n"
        if not file.is_file():
            return b"51 NOT FOUND\r\n"
        return b"20 text/gemini\r\n" + file.read_bytes()
    return request

def solve(root: Path) -> list[str]:
    return crawl("gemini://local-ctf.invalid/", local_capsule(root))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture_directory", type=Path)
    args = parser.parse_args()
    found = solve(args.fixture_directory)
    if not found:
        raise SystemExit("No DUCTF flag found in supplied Gemini capsule")
    for flag in found:
        print(flag)
    print("Original local Gemini handout inspected; no live server queried.")

if __name__ == "__main__":
    main()
