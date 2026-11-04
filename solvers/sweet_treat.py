"""Sweet Treat (Tomcat 9): local legacy cookie-sandwich parser model.

The original DUCTF 2025 JSP application has two independent flaws:
the admin review page displays a user's aboutMe markup without HTML
encoding, and index.jsp copies the legacy language cookie value into
the HTML lang attribute. RFC2109 compatibility can permit an
attacker-controlled quoted cookie to consume later HttpOnly cookies.

OFFLINE cookie-header parser model, not actual Tomcat execution. Only
synthetic mock values; no bot visit, remote callback or hosted Flag.
"""
import argparse
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Cookie:
    name: str
    value: str
    path: str = "/"
    created: int = 0
    http_only: bool = False


def validate_source(index_jsp: str, admin_jsp: str,
                    profile_jsp: str, dockerfile: str) -> None:
    conditions = [
        ('FROM tomcat:9.0-jdk11', dockerfile),
        ('"language".equals(c.getName())', index_jsp),
        ('<html lang="<%= lang %>">', index_jsp),
        ('"language".equals(c.getName())', admin_jsp),
        ('<%= (aboutMe != null && !aboutMe.isEmpty()) ? aboutMe', admin_jsp),
        ('pstmt.setString(1, newAboutMe)', profile_jsp),
        ('request.getParameter("reportProfile")', profile_jsp),
        ('flag.setHttpOnly(true)', admin_jsp),
    ]
    for needle, text in conditions:
        if needle not in text:
            raise ValueError("Original Sweet Treat source no longer matches model")


def cookie_header(cookies: list[Cookie], path: str) -> str:
    """Browser-like same-host cookie sorting by path length and creation time."""
    if not path.startswith("/"):
        raise ValueError("Request path must be absolute")
    relevant = [c for c in cookies
                if (path == c.path or
                    (path.startswith(c.path) and
                     (c.path.endswith("/") or path[len(c.path):].startswith("/"))))]
    relevant.sort(key=lambda c: (-len(c.path), c.created))
    for c in relevant:
        if not re.fullmatch(r"[$A-Za-z0-9_-]+", c.name) or "\r" in c.value or "\n" in c.value:
            raise ValueError("Unsafe cookie header name/value")
    return "; ".join(f"{c.name}={c.value}" for c in relevant)


def parse_legacy_cookies(header: str) -> list[tuple[str, str]]:
    """Minimal RFC2109 quoted-value simulation for a local CTF regression."""
    cookies = []
    position = 0
    versioned = header.startswith("$Version=1")
    while position < len(header):
        while position < len(header) and header[position] in " ;":
            position += 1
        if position >= len(header):
            break
        eq = header.find("=", position)
        if eq < 0:
            break
        name = header[position:eq].strip()
        position = eq + 1
        if versioned and position < len(header) and header[position] == '"':
            position += 1
            end = header.find('"', position)
            if end < 0:
                break
            value = header[position:end]
            position = end + 1
        else:
            end = header.find(";", position)
            if end < 0:
                end = len(header)
            value = header[position:end].strip()
            position = end
        if name and not name.startswith("$"):
            cookies.append((name, value))
    return cookies


def synthetic_sandwich(marker: str = "SYNTHETIC_TEST_VALUE") -> tuple[str, dict[str, str]]:
    if not re.fullmatch(r"[A-Z0-9_]{8,80}", marker):
        raise ValueError("Only fixed local synthetic markers are supported")
    cookies = [
        Cookie("$Version", "1", "/index.jsp", created=0),
        Cookie("language", '"start', "/index.jsp", created=1),
        Cookie("JSESSIONID", "LOCAL_SESSION", "/", created=2, http_only=True),
        Cookie("flag", "DUCTF{" + marker + "}", "/", created=3, http_only=True),
        Cookie("end", '"', "/", created=4),
    ]
    header = cookie_header(cookies, "/index.jsp")
    values = dict(parse_legacy_cookies(header))
    if "language" not in values:
        raise ValueError("Legacy parser produced no language value")
    return header, values


def local_html_language(language: str) -> str:
    return '<!doctype html><html lang="' + language + '"><body>Local demo</body></html>'


def analyse(index: str, admin: str, profile: str, docker: str) -> dict:
    validate_source(index, admin, profile, docker)
    header, cookies = synthetic_sandwich()
    language = cookies["language"]
    marker = "DUCTF{SYNTHETIC_TEST_VALUE}"
    if marker not in language or marker not in local_html_language(language):
        raise ValueError("Synthetic marker not included in quoted language")
    return {
        "cookie_header": header,
        "language": language,
        "reflected_html": local_html_language(language),
        "synthetic_marker_reflected": True,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("index_jsp", type=Path)
    p.add_argument("admin_review_jsp", type=Path)
    p.add_argument("edit_profile_jsp", type=Path)
    p.add_argument("original_dockerfile", type=Path)
    a = p.parse_args()
    result = analyse(a.index_jsp.read_text(encoding="utf-8"),
                     a.admin_review_jsp.read_text(encoding="utf-8"),
                     a.edit_profile_jsp.read_text(encoding="utf-8"),
                     a.original_dockerfile.read_text(encoding="utf-8"))
    print("Offline cookie model reflects synthetic HttpOnly marker:",
          result["synthetic_marker_reflected"])
    print("No Tomcat container, admin bot, or hosted Flag accessed.")


if __name__ == "__main__":
    main()
