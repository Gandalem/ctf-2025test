"""Offline Gemini protocol graph crawler for DUCTF 2025 Wiki.

The original Go solve/main.go walks gemini:// links and looks for "DUCTF".
This implementation preserves Gemini status/header semantics, joins relative
links, prevents cycles, limits scope to one origin and exposes an injectable
fetch function for deterministic local integration. A real fetcher supports
Gemini over TLS with certificate verification (no insecure TLS defaults).

No challenge-hosted Wiki server is available in the public archive, so the
tests construct a fake capsule and recover a SYNTHETIC marker. A published
challenge.yaml flag is not used by the solver.
"""
import argparse
import re
import socket
import ssl
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, urlsplit, urldefrag

FLAG_PATTERN = re.compile(r"DUCTF\{[^\s{}]{1,160}\}")


@dataclass(frozen=True)
class Page:
    url: str
    status: int
    meta: str
    body: str


def parse_gemini_response(url: str, raw: bytes) -> Page:
    """Parse status+meta terminated by CRLF; accept only 2x content bodies."""
    if len(raw) > 1_000_000:
        raise ValueError("Gemini response exceeds configured safety limit")
    header, sep, body = raw.partition(b"\r\n")
    if not sep or len(header) < 3 or len(header) > 1024:
        raise ValueError("Invalid Gemini header")
    status = header[:2]
    if not status.isdigit() or header[2:3] != b" ":
        raise ValueError("Malformed Gemini status line")
    code = int(status)
    if code < 10 or code > 69:
        raise ValueError("Invalid Gemini response status")
    meta = header[3:].decode("utf-8", errors="replace")
    return Page(url, code, meta, body.decode("utf-8", errors="replace") if 20 <= code < 30 else "")


def canonical_url(url: str) -> str:
    url, _ = urldefrag(url)
    parts = urlsplit(url)
    if parts.scheme.lower() != "gemini" or not parts.hostname:
        raise ValueError("Only gemini:// URLs are supported")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Credentials in Gemini URLs are unsupported")
    port = parts.port or 1965
    path = parts.path or "/"
    return f"gemini://{parts.hostname.lower()}:{port}{path}" + (f"?{parts.query}" if parts.query else "")


def links_from_gemtext(text: str, base_url: str) -> list[str]:
    result = []
    for line in text.splitlines():
        match = re.match(r"^\s*=>\s+(\S+)(?:\s+.*)?$", line)
        if not match:
            continue
        raw = match.group(1)
        try:
            result.append(canonical_url(urljoin(base_url, raw)))
        except ValueError:
            # Ignore unsupported links to HTTP, mailto, malformed addresses.
            pass
    return result


def crawl(start: str, fetch: Callable[[str], bytes], max_pages: int = 256) -> dict[str, list[str]]:
    """Visit only the starting Gemini host:port and return matched pages.

    Uses breadth-first search, a visited set, size bounds and a request
    budget so cyclic, malicious or unexpectedly large capsules terminate.
    """
    if not 1 <= max_pages <= 10_000:
        raise ValueError("max_pages must be in 1..10000")
    first = canonical_url(start)
    root = urlsplit(first)
    queue = deque([first])
    visited = set()
    results = {}
    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        page = parse_gemini_response(url, fetch(url))
        if not 20 <= page.status < 30:
            continue
        found = FLAG_PATTERN.findall(page.body)
        if found:
            results[url] = sorted(set(found))
        if not page.meta.lower().startswith("text/gemini"):
            continue
        for link in links_from_gemtext(page.body, url):
            parts = urlsplit(link)
            if (parts.hostname, parts.port) == (root.hostname, root.port) and link not in visited:
                queue.append(link)
    return results


def verified_tls_fetch(url: str) -> bytes:
    """Optional real TLS Gemini client with verified system certificate."""
    parsed = urlsplit(canonical_url(url))
    hostname, port = parsed.hostname, parsed.port
    request = url + "\r\n"
    if len(request.encode("utf-8")) > 1024:
        raise ValueError("Gemini request exceeds 1024 bytes")
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=4) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls:
            tls.settimeout(5)
            tls.sendall(request.encode("utf-8"))
            chunks = []
            size = 0
            while True:
                data = tls.recv(min(65536, 1_000_001 - size))
                if not data:
                    break
                size += len(data)
                if size > 1_000_000:
                    raise ValueError("Gemini response too large")
                chunks.append(data)
    return b"".join(chunks)


def validate_original_source(source: str) -> None:
    required = ("go crawl(client, startingURL)", 'const searchString = "DUCTF"',
                "strings.HasPrefix(resp.Meta", "strings.HasPrefix(line", "url.Parse")
    if not all(part in source for part in required):
        raise ValueError("Original Wiki Go crawler has changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Authorized Gemini capsule root")
    parser.add_argument("--max-pages", type=int, default=100)
    args = parser.parse_args()
    for page, matches in crawl(args.url, verified_tls_fetch, args.max_pages).items():
        print(page, *matches)


if __name__ == "__main__":
    main()
